"""
witnessd.py — one witness process for MANY logs, and the monthly report (deliverable 4: monthly verification).
===============================================================================================================
A witness remembers, per log, the last checkpoint it verified. Before it cosigns a newer one it demands an RFC 9162
consistency proof that the old tree is a prefix of the new one. If history was rewritten or truncated no valid proof
exists, the witness refuses, and records an ALERT. (Protocol logic is tlog.Witness, ported from v1 and tested there.)

What changed from the v1 script:
  • many logs, one config: every customer's log is a line in witness.json (their /public/<tenant>/ URL and the log key
    you were given out of band — pinned, never trusted on first use unless a log entry says "tofu": true)
  • the witness PRIVATE key lives in its own file (witness.key, 0600), not in the state file next to its memory
  • every check is appended to a history, which is what makes the MONTHLY REPORT possible:
    checks done, refusals, how far each log grew, the longest gap with no successful check

Two ways to feed it (same checks, same history, same report):
  PULL   the witness fetches /public/<tenant>/checkpoint from the log (needs the log's public endpoint reachable)
  PUSH   the log sends its checkpoint to the witness's own server (witness serve) and gets the cosignature back. Only
         the log makes an outbound connection, which is what customers behind a firewall accept. A cosignature says:
         "I saw, at time T, a checkpoint of this log (size N, root R) signed by its pinned key, and it extends the one I
         saw before." It does not say the records are correct or complete.

Who runs it: someone who is not the log's operator (the customer's audit/security person, an auditor, the party that
asks for the proof). If YOU run it for a customer, say so plainly: it is independent of their administrators, not of you.

  python -m omnios witness init   --out witness-dir --name witness-1
  python -m omnios witness run    --config witness-dir/witness.json [--once]
  python -m omnios witness report --config witness-dir/witness.json --month 2026-10 --out reports/

Exit codes: 0 all logs verified · 2 at least one ALERT · 4 a log could not be reached.
"""
from __future__ import annotations

import base64
import calendar
import html
import json
import os
import time
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import tlog

_MAX_HISTORY = 20000


class AddBody(BaseModel):
    """What a log sends to PUSH a checkpoint. Bounded, so a stranger cannot make the witness chew on a huge request."""
    origin: str = Field(min_length=3, max_length=120)
    old_size: int = Field(ge=0)
    proof: list[str] = Field(default_factory=list, max_length=128)
    note: str = Field(min_length=10, max_length=4000)


def _origin(entry: dict) -> str:
    return entry.get("origin") or f"omnios/{entry['tenant']}"


def _label(entry: dict) -> str:
    return entry.get("tenant") or _origin(entry)


def _http_get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "omnios-witnessd/2"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode("utf-8"))


def _http_post(url: str, body: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "omnios-witnessd/2"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode("utf-8"))


def init_witness(out_dir: str, name: str = "witness-1") -> dict:
    """Create a witness key and a config skeleton. Returns {name, public_key, config_path}."""
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    key_path = d / "witness.key"
    if key_path.exists():
        priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(key_path.read_text().strip()))
    else:
        priv = Ed25519PrivateKey.generate()
        seed = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # private from the first byte (no effect on Windows)
        with os.fdopen(fd, "w") as f:
            f.write(base64.b64encode(seed).decode("ascii") + "\n")
    pub = base64.b64encode(tlog.public_bytes(priv.public_key())).decode("ascii")
    cfg_path = d / "witness.json"
    if not cfg_path.exists():
        cfg_path.write_text(json.dumps({
            "name": name, "key_file": "witness.key", "state_file": "witness_state.json", "format": "v1",
            "interval": 300, "max_gap_seconds": 3600,
            "logs": [{"name": "example", "url": "https://omnios.example.com", "tenant": "example",
                      "log_key": "<base64 log public key, obtained from the customer by another route>", "post_cosign": True}]},
            # for PUSH only (no "url"): {"name": "...", "origin": "omnios/<tenant>", "log_key": "<base64>"}
            indent=2), encoding="utf-8")
    return {"name": name, "public_key": pub, "config_path": str(cfg_path)}


class WitnessDaemon:
    def __init__(self, config_path: str, *, get: Callable[[str], dict] = _http_get,
                 post: Callable[[str, dict], dict] = _http_post, clock: Callable[[], float] = time.time) -> None:
        self.config_path = Path(config_path)
        self.base = self.config_path.parent
        self.cfg: dict = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.name: str = self.cfg["name"]
        self._get, self._post, self._clock = get, post, clock
        self.priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode((self.base / self.cfg.get("key_file", "witness.key")).read_text().strip()))
        self.public_key = base64.b64encode(tlog.public_bytes(self.priv.public_key())).decode("ascii")
        self.state_path = self.base / self.cfg.get("state_file", "witness_state.json")
        self.state: dict = json.loads(self.state_path.read_text()) if self.state_path.exists() else {"logs": {}, "history": []}
        self._lock = threading.RLock()

    def _save(self) -> None:
        self.state["history"] = self.state["history"][-_MAX_HISTORY:]
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state), encoding="utf-8")
        os.replace(tmp, self.state_path)

    def _note(self, log: str, ok: bool, frm: int, to: int, detail: str = "") -> None:
        self.state["history"].append({"at": round(self._clock(), 3), "log": log, "ok": ok, "from": frm, "to": to, "detail": detail})

    def check_log(self, entry: dict) -> tuple[int, str]:
        """One poll of one log. Returns (exit code, message)."""
        if not entry.get("url"):
            return 0, f"{entry['name']}: push-only (waiting for the log to send its checkpoint)"
        lname, base, tenant = entry["name"], entry["url"].rstrip("/"), entry["tenant"]
        try:
            cp = self._get(f"{base}/public/{tenant}/checkpoint")
        except (urllib.error.URLError, OSError, ValueError) as e:
            self._note(lname, False, 0, 0, f"unreachable: {type(e).__name__}")
            self._save()
            return 4, f"{lname}: NETWORK ERROR: cannot read the checkpoint ({e})"
        pinned = entry.get("log_key")
        if not pinned or pinned.startswith("<"):
            if not entry.get("tofu"):
                return 3, f"{lname}: TRUST ERROR: no pinned log_key in the config (the server claims {cp.get('log_public_key')})"
            pinned = cp["log_public_key"]
        origin, key_name = cp["origin"], cp["key_name"]
        w = tlog.Witness(self.name, self.priv, {origin: (key_name, base64.b64decode(pinned))}, self.state["logs"])
        known, size, proof = w.known_size(origin), int(cp["size"]), []
        if known and size > known:
            try:
                c = self._get(f"{base}/public/{tenant}/consistency?first={known}&second={size}")
                proof = [base64.b64decode(p) for p in c["proof"]]
            except urllib.error.HTTPError as e:
                if 400 <= e.code < 500:
                    # the log answered, signed a bigger tree, and will not (or cannot) prove it extends the old one
                    self._note(lname, False, known, size, f"REFUSED: the log did not provide a consistency proof (HTTP {e.code})")
                    self._save()
                    return 2, (f"{lname}: ALERT — the log claims size {size} but refuses to prove it extends size {known} "
                               f"(HTTP {e.code}; state NOT updated)")
                self._note(lname, False, known, size, f"consistency proof unreachable: HTTP {e.code}")
                self._save()
                return 4, f"{lname}: NETWORK ERROR: cannot read the consistency proof (HTTP {e.code})"
            except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
                self._note(lname, False, known, size, f"consistency proof unreachable: {type(e).__name__}")
                self._save()
                return 4, f"{lname}: NETWORK ERROR: cannot read the consistency proof ({e})"
        try:
            line = w.cosign(cp["note"], proof, fmt=self.cfg.get("format", "v1"))
        except tlog.WitnessRefusal as e:
            self._note(lname, False, known, size, f"REFUSED: {e}")
            self._save()
            return 2, f"{lname}: ALERT — {e} (last seen size {known}; state NOT updated)"
        self._note(lname, True, known, size)
        self._save()
        msg = f"{lname}: OK size {known} -> {size}"
        if entry.get("post_cosign", True):
            try:
                r = self._post(f"{base}/public/{tenant}/cosign", {"size": size, "line": line})
                msg += f" (cosignature stored: {r.get('witness')})"
            except urllib.error.HTTPError as e:
                msg += f" (cosignature NOT stored: HTTP {e.code}; is '{self.name}' registered by the tenant?)"
            except (urllib.error.URLError, OSError, ValueError) as e:
                msg += f" (cosignature NOT sent: {e})"
        return 0, msg

    def poll_once(self) -> int:
        worst = 0
        for entry in self.cfg["logs"]:
            code, msg = self.check_log(entry)
            print(msg)
            if code == 2 or (code == 4 and worst != 2) or (code == 3 and worst == 0):
                worst = code
        return worst

    def run(self, once: bool = False) -> int:
        print(f"witness '{self.name}'  public key: {self.public_key}")
        print(f"  (the tenant registers it:  python -m omnios tenant witness --id <tenant> --name {self.name} --key {self.public_key})")
        while True:
            code = self.poll_once()
            interval = int(self.cfg.get("interval", 0))
            if once or interval <= 0 or code == 2:
                return code
            time.sleep(interval)

    # ───────────────────── PUSH: the log sends its checkpoint here ─────────────────────
    def add_checkpoint(self, origin: str, old_size: int, proof_b64: list, note: str) -> tuple[int, dict]:
        """Returns (http status, body). 200 cosignature · 403 unknown log or not signed by its pinned key ·
        409 the log must restart from the size this witness holds · 422 the log refused to be consistent (ALERT)."""
        with self._lock:
            entry = next((e for e in self.cfg["logs"] if _origin(e) == origin), None)
            if entry is None:
                return 403, {"error": "unknown_log"}
            pinned = entry.get("log_key")
            if not pinned or pinned.startswith("<"):
                return 403, {"error": "log_key_not_pinned"}
            key_name = entry.get("key_name") or origin
            try:
                _, signers = tlog.verify_note(note, {key_name: base64.b64decode(pinned)})
                _, size, _ = tlog.parse_checkpoint(tlog.split_note(note)[0])
            except Exception:
                return 403, {"error": "unreadable_checkpoint"}
            if key_name not in signers:
                return 403, {"error": "not_signed_by_the_pinned_log_key"}        # a stranger's forgery: not a log fault, not recorded
            w = tlog.Witness(self.name, self.priv, {origin: (key_name, base64.b64decode(pinned))}, self.state["logs"])
            known = w.known_size(origin)
            if old_size != known:
                return 409, {"known_size": known}
            try:
                proof = [base64.b64decode(p) for p in proof_b64]
                line = w.cosign(note, proof, fmt=self.cfg.get("format", "v1"))
            except (tlog.WitnessRefusal, ValueError) as e:
                self._note(entry["name"], False, known, size, f"REFUSED: {e}")
                self._save()
                return 422, {"error": "refused", "detail": str(e)}
            self._note(entry["name"], True, known, size)
            self._save()
            return 200, {"cosignature": line, "size": size, "witness": self.name}

    def app(self):
        """The witness's own HTTP service:  python -m omnios witness serve --config witness.json"""
        from fastapi import FastAPI
        from fastapi.responses import JSONResponse

        api = FastAPI(title=f"OmniOS witness {self.name}", version="2.0-draft")

        @api.get("/witness/v1/info")
        def info() -> dict:
            return {"name": self.name, "public_key": self.public_key, "logs": [_origin(e) for e in self.cfg["logs"]]}

        @api.post("/witness/v1/add-checkpoint")
        def add(body: AddBody) -> JSONResponse:
            status, out = self.add_checkpoint(body.origin, body.old_size, body.proof, body.note)
            return JSONResponse(out, status_code=status)

        return api

    def serve(self, host: str = "127.0.0.1", port: int = 8100) -> int:
        import uvicorn
        print(f"witness '{self.name}'  public key: {self.public_key}")
        print(f"  logs it accepts: {', '.join(_origin(e) for e in self.cfg['logs'])}")
        print(f"  (a customer registers it:  python -m omnios tenant witness --id <tenant> --name {self.name} "
              f"--key {self.public_key} --url http://<this host>:{port})")
        uvicorn.run(self.app(), host=host, port=port, log_level="warning")
        return 0

    # ───────────────────── the monthly report ─────────────────────
    def monthly_report(self, month: str) -> dict:
        """`month` = 'YYYY-MM' (UTC). Summarises the history of every configured log for that month."""
        t0 = calendar.timegm(time.strptime(month + "-01", "%Y-%m-%d"))
        y, m = int(month[:4]), int(month[5:7])
        t1 = calendar.timegm(time.strptime(f"{y + (m == 12)}-{1 if m == 12 else m + 1:02d}-01", "%Y-%m-%d"))
        gap_limit = int(self.cfg.get("max_gap_seconds", 3600))
        out_logs = []
        for entry in self.cfg["logs"]:
            rows = [h for h in self.state["history"] if h["log"] == entry["name"] and t0 <= h["at"] < t1]
            good = [h for h in rows if h["ok"]]
            alerts = [h for h in rows if not h["ok"] and h["detail"].startswith("REFUSED")]
            unreachable = [h for h in rows if not h["ok"] and not h["detail"].startswith("REFUSED")]
            times = sorted(h["at"] for h in good)
            marks = [t0] + times + [t1]
            max_gap = max((b - a for a, b in zip(marks, marks[1:])), default=0)
            sizes = [h["to"] for h in good]
            verdict = ("ALERT" if alerts else "NO COVERAGE" if not good else "GAPS" if max_gap > gap_limit else "CLEAN")
            out_logs.append({"log": entry["name"], "tenant": _label(entry), "checks": len(rows), "verified": len(good),
                             "refusals": len(alerts), "unreachable": len(unreachable),
                             "first_size": good[0]["from"] if good else None, "last_size": max(sizes) if sizes else None,
                             "longest_gap_seconds": int(max_gap), "gap_limit_seconds": gap_limit, "verdict": verdict,
                             "alerts": [{"at": a["at"], "detail": a["detail"]} for a in alerts]})
        return {"witness": self.name, "witness_public_key": self.public_key, "month": month,
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self._clock())), "logs": out_logs}


_REPORT_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>OmniOS witness report {month}</title>
<style>body{{font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:32px auto;padding:0 16px;color:#0e1a2b}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #d8dde6;padding:8px 10px;text-align:left}}th{{background:#edf0f5}}
.CLEAN{{color:#17693f;font-weight:600}}.ALERT{{color:#9b2226;font-weight:700}}.GAPS,.NOCOVERAGE{{color:#8a4700;font-weight:600}}
code{{background:#edf0f5;padding:1px 5px;border-radius:4px}}small{{color:#5b6472}}</style></head><body>
<h1>Witness report, {month}</h1>
<p>Witness <b>{witness}</b> &middot; public key <code>{pub}</code><br><small>Generated {generated}</small></p>
<table><tr><th>Log</th><th>Checks</th><th>Verified</th><th>Refusals</th><th>Grew from &rarr; to</th><th>Longest gap</th><th>Verdict</th></tr>
{rows}</table>
<h2>What this says, and what it does not</h2>
<p>For each log, this witness fetched the signed checkpoint and a proof that the previous tree it had seen is a prefix of
the new one, and cosigned only when the proof held. A <b>refusal</b> means history was rewritten, truncated or forked, or the
log was not signed by the pinned key. <b>Gaps</b> are stretches with no successful check: during a gap this witness could
not have noticed a rewrite.</p>
<p>It does <b>not</b> say that the records are correct or complete, or that every action was logged. It says the log
did not change what this witness had already seen. This witness is independent of the log's administrators only if it is
run by someone who is not one of them.</p></body></html>"""


def write_report(rep: dict, out_dir: str) -> dict:
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    rows = ""
    for r in rep["logs"]:
        v = r["verdict"]
        rows += (f"<tr><td>{html.escape(r['log'])}</td><td>{r['checks']}</td><td>{r['verified']}</td><td>{r['refusals']}</td>"
                 f"<td>{r['first_size']} &rarr; {r['last_size']}</td><td>{r['longest_gap_seconds'] // 60} min</td>"
                 f"<td class=\"{v.replace(' ', '')}\">{v}</td></tr>")
        for a in r["alerts"]:
            rows += f"<tr><td colspan=7><small>ALERT {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(a['at']))}: {html.escape(a['detail'])}</small></td></tr>"
    h = _REPORT_HTML.format(month=rep["month"], witness=html.escape(rep["witness"]), pub=rep["witness_public_key"],
                            generated=rep["generated_at"], rows=rows)
    jp, hp = d / f"witness-report-{rep['month']}.json", d / f"witness-report-{rep['month']}.html"
    jp.write_text(json.dumps(rep, indent=2), encoding="utf-8")
    hp.write_text(h, encoding="utf-8")
    return {"json": str(jp), "html": str(hp)}
