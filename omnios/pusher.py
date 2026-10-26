"""
pusher.py — the log side of PUSH witnessing: send the signed checkpoint OUT to each registered witness.
=========================================================================================================
The customer's installation makes an outbound HTTPS call only; nothing has to be reachable from outside. For each witness
registered with a URL (`python -m omnios tenant witness --id T --name W --key K --url https://witness.example`):

    1. take the log's current signed checkpoint (size N)
    2. tell the witness the size it last accepted (`old_size`) and prove, with an RFC 9162 consistency proof, that the
       tree it saw is a prefix of this one
    3. if the witness holds a different size it answers 409 with that size: send the proof from THERE (this is also how a
       log recovers after losing its own progress note)
    4. the witness answers with a cosignature; it is stored only if it verifies against the witness key registered for this
       tenant (a witness cannot be impersonated by whoever controls the URL)

If the witness is AHEAD of this log (it has seen a bigger tree than the one we now hold) we still send our checkpoint with
its size: the witness refuses ("log shrank") and records an ALERT. That is the signal that a backup was restored or history
was cut, and it must be visible on the witness side, not only here.

Run it inside the server (`python -m omnios serve --push-interval 300`) or once from a scheduler (`python -m omnios push`).
Do not leave a second long-running process next to `serve`: it would hold a stale copy of the log.
"""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from typing import Callable, Optional

from .errors import OmniError

_NS = "witness_push"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def post_json(url: str, body: dict, timeout: float = 20.0) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "omnios-pusher/2"})
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            raw, status = r.read(1_000_000), r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(1_000_000), e.code
    try:
        return status, json.loads(raw.decode("utf-8")) if raw else {}
    except (ValueError, UnicodeDecodeError):
        return status, {}


def push_one(rt, name: str, base_url: str, post: Callable[[str, dict], tuple] = post_json) -> dict:
    """One push to one witness. Returns {tenant, witness, ok, size, detail}. Never raises on network trouble."""
    led = rt.ledger
    url = base_url.rstrip("/") + "/witness/v1/add-checkpoint"
    result = {"tenant": rt.id, "witness": name, "ok": False, "size": 0, "detail": ""}
    prog = rt.kv.get(_NS, name) or {"size": 0}
    known = int(prog["size"])
    cp = led.checkpoint()
    size = cp["size"]
    result["size"] = size
    for _ in range(3):
        proof = []
        if 0 < known < size:
            proof = led.consistency(known, size)["proof"]
        try:
            status, body = post(url, {"origin": led.origin, "old_size": known, "proof": proof, "note": cp["note"]})
        except (urllib.error.URLError, OSError, TimeoutError, ValueError) as e:
            result["detail"] = f"witness unreachable: {type(e).__name__}"
            return result
        if status == 409:
            known = int(body.get("known_size", 0))
            continue
        if status == 200:
            try:
                led.add_cosignature(size, body["cosignature"], rt.witness_keys())
            except (OmniError, KeyError) as e:
                result["detail"] = f"cosignature not accepted: {getattr(e, 'code', e)} (is the witness key registered for this tenant under the same name?)"
                return result
            rt.kv.put(_NS, name, {"size": size, "at": rt._clock()})
            result.update(ok=True, detail="cosigned")
            return result
        if status == 422:
            result["detail"] = f"ALERT, witness refused: {body.get('detail') or body.get('error')}"
            return result
        result["detail"] = f"witness answered HTTP {status}: {body.get('error', '')}"
        return result
    result["detail"] = "witness and log could not agree on a starting size"
    return result


def push_tenant(rt, post: Callable[[str, dict], tuple] = post_json) -> list[dict]:
    return [push_one(rt, n, u, post) for n, u in sorted((rt.cfg.get("witness_endpoints") or {}).items())]


def push_all(registry, post: Callable[[str, dict], tuple] = post_json, only: Optional[str] = None) -> list[dict]:
    out: list[dict] = []
    for tid in registry.ids():
        if only and tid != only:
            continue
        rt = registry.get(tid)
        if rt.suspended:
            continue
        out.extend(push_tenant(rt, post))
    return out


def start_background(registry, interval: float, post: Callable[[str, dict], tuple] = post_json,
                     log: Callable[[str], None] = print) -> threading.Event:
    """Push every `interval` seconds from a daemon thread inside the server. Returns an Event; set it to stop."""
    stop = threading.Event()

    def loop() -> None:
        while not stop.is_set():
            try:
                for r in push_all(registry, post):
                    if not r["ok"]:
                        log(f"push {r['tenant']} -> {r['witness']}: {r['detail']}")
            except Exception as e:                     # a failing witness must never take the server down
                log(f"push loop error: {type(e).__name__}: {e}")
            stop.wait(interval)

    threading.Thread(target=loop, name="omnios-pusher", daemon=True).start()
    return stop
