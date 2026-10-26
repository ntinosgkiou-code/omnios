#!/usr/bin/env python3
"""
verify.py — check an OmniOS evidence bundle with nothing but Python 3.9+.   (stand-alone: no OmniOS code needed)

    python verify.py bundle.zip --log-key <base64 public key of the log>  [--witness name=<base64 key> ...] [--json]

--log-key is the log's public key AS YOU OBTAINED IT FROM THE CUSTOMER BY ANOTHER ROUTE (a call, a signed contract), not
only from this file: a bundle that vouches for its own key proves nothing. Without --log-key the check still runs but is
reported as UNPINNED. Witness keys work the same way.

What is checked (every item is reported, none is skipped silently):
  1. the bundle's own files match the hashes in manifest.json
  2. the checkpoint is signed by the pinned log key, and says what size / root the log claims
  3. every record: its text hashes to its leaf, the leaf is in that tree (inclusion proof, RFC 9162), the text is
     canonical JSON, and consecutive records are chained by `prev`
  4. witness cosignatures: which trusted witnesses signed which size, and when; and whether the checkpoint extends the
     witnessed one (consistency proof)
  5. the RULES were followed, per action: enough DISTINCT approvers, none of them the agent, approver groups respected,
     the policy named by each decision really was activated, no execution without approval, no dangling execution; and
     every change to rules or keys had the other admins' approvals it needed

What it cannot tell you: that a record is TRUE (only that it was committed and not rewritten), or that actions were not
omitted before being logged. A witness limits rewriting to what it had already seen.
Exit code: 0 all good · 2 something failed · 3 usage / unreadable bundle.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import time
import zipfile
from typing import Any, Optional

_EM = "—"
GENESIS = "0" * 64


# ───────────────────────── hashing and Merkle (RFC 9162) ─────────────────────────
def _sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def leaf_hash(data: bytes) -> bytes:
    return _sha(b"\x00" + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _sha(b"\x01" + left + right)


def verify_inclusion(leaf: bytes, index: int, size: int, proof: list, root: bytes) -> bool:
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes, proof: list) -> bool:
    if first < 0 or first > second:
        return False
    if first == second:
        return not proof and first_root == second_root
    if first == 0:
        return not proof
    if not proof:
        return False
    path = list(proof)
    if first & (first - 1) == 0:
        path = [first_root] + path
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0


# ───────────────────────── Ed25519 verification ─────────────────────────
_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _padd(p: tuple, q: tuple) -> tuple:
    a, b = (p[1] - p[0]) * (q[1] - q[0]) % _P, (p[1] + p[0]) * (q[1] + q[0]) % _P
    c, d = 2 * p[3] * q[3] * _D % _P, 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _pmul(s: int, p: tuple) -> tuple:
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _padd(q, p)
        p = _padd(p, p)
        s >>= 1
    return q


def _peq(p: tuple, q: tuple) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _recover_x(y: int, sign: int):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _ed25519_pure(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    a, r = _decompress(public), _decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _Q
    return _peq(_pmul(s, _G), _padd(r, _pmul(h, a)))


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> tuple[bool, str]:
    """(valid, implementation used). Uses the `cryptography` package when present, pure Python otherwise."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
            return True, "cryptography"
        except InvalidSignature:
            return False, "cryptography"
        except ValueError:
            return False, "cryptography"
    except ImportError:
        return _ed25519_pure(public, message, signature), "pure-python"


# ───────────────────────── signed notes (C2SP) ─────────────────────────
def _key_id(name: str, pub: bytes, sig_type: bytes = b"\x01") -> bytes:
    return _sha(name.encode("utf-8") + b"\n" + sig_type + pub)[:4]


def split_note(note: str) -> tuple[str, list]:
    idx = note.rfind("\n\n")
    if idx < 0:
        raise ValueError("no signature block")
    text, sigs = note[:idx + 1], note[idx + 2:]
    out = []
    for line in sigs.split("\n"):
        if not line:
            continue
        m = re.fullmatch(_EM + r" (\S+) (\S+)", line)
        if not m:
            raise ValueError("malformed signature line")
        out.append((m.group(1), base64.b64decode(m.group(2), validate=True), line))
    return text, out


def parse_checkpoint(body: str) -> tuple[str, int, bytes]:
    lines = body.split("\n")
    if len(lines) < 4 or lines[-1] != "":
        raise ValueError("malformed checkpoint")
    root = base64.b64decode(lines[2], validate=True)
    if len(root) != 32 or not re.fullmatch(r"0|[1-9][0-9]*", lines[1]):
        raise ValueError("malformed checkpoint")
    return lines[0], int(lines[1]), root


def check_log_signature(note: str, name: str, pub: bytes) -> tuple[bool, str]:
    body, sigs = split_note(note)
    impl = "n/a"
    for n, payload, _ in sigs:
        if n == name and len(payload) >= 5 and payload[:4] == _key_id(name, pub):
            ok, impl = ed25519_verify(pub, body.encode("utf-8"), payload[4:])
            if ok:
                return True, impl
    return False, impl


def check_cosignature(line: str, body: str, trusted: dict) -> Optional[tuple]:
    """(witness name, timestamp or None) if `line` is a valid cosignature by a TRUSTED witness over checkpoint `body`."""
    m = re.fullmatch(_EM + r" (\S+) (\S+)", line.rstrip("\n"))
    if not m or m.group(1) not in trusted:
        return None
    name, pub = m.group(1), trusted[m.group(1)]
    try:
        payload = base64.b64decode(m.group(2), validate=True)
    except ValueError:
        return None
    if len(payload) == 4 + 8 + 64 and payload[:4] == _key_id(name, pub, b"\x04"):           # cosignature/v1
        ts = int.from_bytes(payload[4:12], "big")
        ok, _ = ed25519_verify(pub, f"cosignature/v1\ntime {ts}\n{body}".encode("utf-8"), payload[12:])
        return (name, ts) if ok else None
    if len(payload) >= 5 and payload[:4] == _key_id(name, pub):                              # plain signed-note line
        ok, _ = ed25519_verify(pub, body.encode("utf-8"), payload[4:])
        return (name, None) if ok else None
    return None


# ───────────────────────── the bundle check ─────────────────────────
def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def _policy_hash(doc: dict) -> str:
    return hashlib.sha256(_canon(doc).encode("utf-8")).hexdigest()


def verify_bundle(path: str, log_key_b64: Optional[str] = None, witnesses: Optional[dict] = None, *,
                  min_witnesses: Optional[int] = None, max_age: Optional[float] = None, now: Optional[float] = None) -> dict:
    """Returns a report dict. `report["ok"]` is True only if every cryptographic check passed AND no rule violation was
    found. Warnings (unpinned key, partial witness coverage, dangling execution) do not flip `ok` but are listed.

    Witness policy (optional, set by the person who asks for the proof):
      min_witnesses  at least this many DISTINCT trusted witnesses must hold a valid cosignature on a checkpoint that
                     this log provably extends (the bundle fails otherwise)
      max_age        seconds: a witness only counts if its latest cosignature is at most this old (needs the cosignature/v1
                     timestamp; a plain signed-note cosignature has none and does not count). Implies min_witnesses >= 1.
      now            the clock, for tests."""
    rep: dict = {"ok": True, "pinned": log_key_b64 is not None, "problems": [], "warnings": [], "info": {}, "actions": {}}

    def problem(msg: str) -> None:
        rep["ok"] = False
        rep["problems"].append(msg)

    try:
        z = zipfile.ZipFile(path)
        manifest = json.loads(z.read("manifest.json").decode("utf-8"))
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as e:
        return {"ok": False, "problems": [f"cannot read the bundle: {e}"], "warnings": [], "info": {}, "actions": {}, "pinned": False}

    if manifest.get("format") != "omnios-evidence-bundle" or manifest.get("version") != 1:
        return {"ok": False, "pinned": log_key_b64 is not None, "warnings": [], "info": {}, "actions": {},
                "problems": [f"unsupported bundle: format={manifest.get('format')!r} version={manifest.get('version')!r} "
                             "(this verifier reads omnios-evidence-bundle version 1)"]}

    # 1. file integrity
    for fname, want in (manifest.get("files") or {}).items():
        try:
            if hashlib.sha256(z.read(fname)).hexdigest() != want:
                problem(f"file {fname} does not match manifest.json")
        except KeyError:
            problem(f"file {fname} listed in manifest.json is missing")

    # 2. the checkpoint
    if log_key_b64 is None:
        rep["warnings"].append("UNPINNED: no --log-key given. The key inside the bundle was used, which proves nothing about who holds the log.")
    log_key = base64.b64decode(log_key_b64 or manifest.get("log_public_key", ""))
    if log_key_b64 and manifest.get("log_public_key") and manifest["log_public_key"] != log_key_b64:
        problem("the bundle claims a different log key than the one you pinned")
    key_name, origin = manifest.get("key_name"), manifest.get("origin")
    cps = json.loads(z.read("checkpoints.json").decode("utf-8"))
    main = cps["main"]
    try:
        body, _ = split_note(main["note"])
        c_origin, size, root = parse_checkpoint(body)
    except ValueError as e:
        problem(f"checkpoint unreadable: {e}")
        return rep
    ok, impl = check_log_signature(main["note"], key_name, log_key)
    rep["info"]["ed25519"] = impl
    if not ok:
        problem("the checkpoint is NOT signed by the log key")
    if c_origin != origin or size != manifest.get("size"):
        problem("checkpoint origin/size do not match the manifest")
    rep["info"].update({"tenant": manifest.get("tenant"), "origin": origin, "size": size, "profile": manifest.get("profile"),
                        "admin_quorum": manifest.get("admin_quorum"), "scope": manifest.get("scope"),
                        "root": base64.b64encode(root).decode("ascii")})

    # 3. records
    records = [json.loads(line) for line in z.read("records.jsonl").decode("utf-8").splitlines() if line.strip()]
    parsed: dict[int, dict] = {}
    rhashes: dict[int, str] = {}
    for r in records:
        raw = r["body"].encode("utf-8")
        seq = r["seq"]
        if leaf_hash(raw).hex() != r["leaf"]:
            problem(f"record {seq}: text does not hash to its leaf")
            continue
        if not verify_inclusion(bytes.fromhex(r["leaf"]), seq, size, [bytes.fromhex(p) for p in r["proof"]], root):
            problem(f"record {seq}: NOT in the checkpointed tree")
            continue
        try:
            rec = json.loads(r["body"])
        except ValueError:
            problem(f"record {seq}: not JSON")
            continue
        if _canon(rec) != r["body"]:
            problem(f"record {seq}: text is not canonical JSON")
        if rec.get("seq") != seq or rec.get("tenant") != manifest.get("tenant"):
            problem(f"record {seq}: sequence or tenant does not match")
        parsed[seq] = rec
        rhashes[seq] = hashlib.sha256(raw).hexdigest()
    for seq, rec in parsed.items():
        if seq == 0:
            if rec["prev"] != GENESIS:
                problem("record 0 does not start from the genesis hash")
        elif seq - 1 in rhashes and rec["prev"] != rhashes[seq - 1]:
            problem(f"record {seq}: chain link does not match record {seq - 1}")
    if (manifest.get("scope") or {}).get("kind") == "all" and len(parsed) != size:
        problem(f"scope 'all' promised {size} records, {len(parsed)} verified")
    rep["info"]["records_verified"] = len(parsed)

    # 4. witnesses
    trusted = {n: base64.b64decode(k) for n, k in (witnesses or {}).items()}
    seen: list = []
    best: dict = {}            # witness -> {"size": largest cosigned size proven to be a prefix of this log, "timestamp": ts or None}
    for entry in cps.get("witnessed", []):
        try:
            wbody, sigs = split_note(entry["note"])
            _, wsize, wroot = parse_checkpoint(wbody)
        except ValueError:
            problem("a witnessed checkpoint is unreadable")
            continue
        if not check_log_signature(entry["note"], key_name, log_key)[0]:
            problem(f"witnessed checkpoint at size {wsize} is not signed by the log key")
            continue
        for _, _, line in sigs:
            hit = check_cosignature(line, wbody, trusted)
            if not hit:
                continue
            wname, wts = hit
            seen.append({"witness": wname, "size": wsize, "timestamp": wts})
            ext = entry.get("consistency")
            if wsize == size and wroot == root:
                extends = True
            else:
                extends = bool(ext) and wsize <= size and verify_consistency(wsize, size, wroot, root, [base64.b64decode(p) for p in ext])
            if not extends:
                problem(f"the checkpoint does NOT extend the one witness '{wname}' cosigned at size {wsize}")
                continue
            cur = best.get(wname)
            if cur is None or wsize > cur["size"] or (wsize == cur["size"] and (wts or 0) > (cur["timestamp"] or 0)):
                best[wname] = {"size": wsize, "timestamp": wts}
    covered = max([b["size"] for b in best.values()], default=0)
    rep["info"]["witness_cosignatures"] = seen
    rep["info"]["witnessed_up_to"] = covered

    need = min_witnesses if min_witnesses is not None else (1 if max_age is not None else None)
    clock = time.time() if now is None else now
    table, counted, uncounted = [], [], []
    for wname, b in sorted(best.items()):
        age = (clock - b["timestamp"]) if b["timestamp"] else None
        table.append({"witness": wname, "size": b["size"], "timestamp": b["timestamp"], "age_seconds": None if age is None else int(age)})
        if max_age is not None and (age is None or age > max_age):
            uncounted.append(f"{wname} ({'no timestamp' if age is None else f'last cosigned {int(age) // 3600} h ago'})")
        else:
            counted.append(b["size"])
    rep["info"]["witnesses"] = table
    rep["info"]["policy"] = {"min_witnesses": need, "max_age_seconds": max_age}
    counted.sort(reverse=True)
    by_k = counted[need - 1] if need and len(counted) >= need else 0
    rep["info"]["witnessed_by_required_up_to"] = by_k
    if need is not None:
        if not trusted:
            problem(f"{need} trusted witness(es) required but no witness keys were given (--witness NAME=KEY)")
        elif len(counted) < need:
            extra = f"; not counted: {', '.join(uncounted)}" if uncounted else ""
            problem(f"witness policy NOT met: {len(counted)} of the {need} required trusted witnesses"
                    f"{' with a cosignature at most ' + str(int(max_age)) + ' s old' if max_age is not None else ''}{extra}")
        elif by_k < size:
            rep["warnings"].append(f"records {by_k}..{size - 1} are not yet witnessed by {need} witness(es)")
    elif not trusted:
        rep["warnings"].append("no --witness keys given: witness cosignatures were not checked")
    elif covered == 0:
        rep["warnings"].append("no trusted witness cosigned this log: nothing stops the operator from rewriting history unnoticed")
    elif covered < size:
        rep["warnings"].append(f"witnesses cover records 0..{covered - 1}; records {covered}..{size - 1} are not yet witnessed")

    # 5. the rules
    _check_rules(parsed, rep)
    return rep


def _check_rules(parsed: dict, rep: dict) -> None:
    def violation(msg: str) -> None:
        rep["ok"] = False
        rep["problems"].append("RULE: " + msg)

    policies: dict[str, dict] = {}
    changes: dict[str, dict] = {}
    acts: dict[str, list] = {}
    obs: dict[str, int] = {}
    for seq in sorted(parsed):
        rec = parsed[seq]
        t, d = rec["type"], rec["data"]
        if t == "policy.activated":
            if _policy_hash(d["policy"]) != d["policy_hash"]:
                violation(f"record {seq}: the policy text does not match its hash")
            policies[d["policy_hash"]] = d["policy"]
        elif t.startswith("change."):
            c = changes.setdefault(d["id"], {"proposed": None, "approvals": [], "applied": False})
            if t == "change.proposed":
                c["proposed"] = d
            elif t == "change.approved":
                c["approvals"].append(d["by"])
            elif t == "change.applied":
                c["applied"] = True
        elif t == "action.observed":
            # observe mode: a dry-run verdict about something the customer's system reported. Nothing was decided,
            # approved or executed, so none of the action rules below apply; it is only counted.
            obs[d.get("decision", "?")] = obs.get(d.get("decision", "?"), 0) + 1
        elif t.startswith("action."):
            acts.setdefault(d["id"], []).append((seq, t, d))
    if obs:
        rep.setdefault("info", {})["observed"] = {"total": sum(obs.values()), **obs}
    for cid, c in changes.items():
        if c["applied"] and c["proposed"]:
            need = max(0, c["proposed"]["quorum"] - 1)
            others = {a for a in c["approvals"] if a != c["proposed"]["by"]}
            if len(others) < need:
                violation(f"change {cid} was applied with {len(others)} approval(s) from other admins, quorum needs {need}")
    for aid, evs in acts.items():
        types = [t for _, t, _ in evs]
        prop = next((d for _, t, d in evs if t in ("action.proposed", "action.denied")), None)
        rep["actions"][aid] = {"events": [t for t in types]}
        if prop is None:
            violation(f"action {aid}: records exist but no proposal/decision record was included")
            continue
        denied = any(t == "action.denied" for t in types)
        approvals = [d for _, t, d in evs if t == "action.approved"]
        approvers = [d["by"] for d in approvals]
        rep["actions"][aid].update({"tool": prop.get("tool"), "agent": prop.get("agent"), "approvers": approvers})
        if len(set(approvers)) != len(approvers):
            violation(f"action {aid}: the same approver approved more than once")
        if prop.get("agent") in approvers:
            violation(f"action {aid}: the agent approved its own action")
        pol = policies.get(prop.get("policy_hash"))
        if pol is None:
            rep["warnings"].append(f"action {aid}: the policy {str(prop.get('policy_hash'))[:12]} is not among the included records")
        else:
            groups = ((pol.get("tools", {}).get(prop.get("tool")) or {}).get("approvals") or {}).get("groups") or []
            if groups:
                for ap in approvals:
                    if not set(groups) & set(ap.get("groups") or []):
                        violation(f"action {aid}: approver {ap['by']} is not in a required group ({', '.join(groups)})")
        ex = [(s, d) for s, t, d in evs if t in ("action.executing", "action.executed")]
        if ex and denied:
            violation(f"action {aid}: executed although the rules denied it")
        for s, t, d in evs:
            if t in ("action.executing",) or (t == "action.executed" and d.get("attestation") == "agent_report"):
                required = max([prop.get("approvals_required", 0)] + [a.get("of", 0) for a in approvals])
                before = {a["by"] for sq, tt, a in evs if tt == "action.approved" and sq < s}
                if len(before) < required:
                    violation(f"action {aid}: record {s} ({t}) happened with {len(before)} approval(s), the rules required {required}")
        if "action.executing" in types and not any(t in ("action.executed", "action.failed") for t in types):
            rep["warnings"].append(f"action {aid}: an execution started and no outcome was recorded (dangling)")


# ───────────────────────── command line ─────────────────────────
def render(rep: dict) -> str:
    i = rep.get("info", {})
    out = ["OmniOS evidence bundle", "=" * 60]
    if i:
        out += [f"tenant           {i.get('tenant')}   (profile {i.get('profile')}, admin quorum {i.get('admin_quorum')})",
                f"log              {i.get('origin')}   size {i.get('size')}",
                f"scope            {(i.get('scope') or {}).get('kind')}",
                f"log key pinned   {'YES' if rep.get('pinned') else 'NO (UNPINNED)'}",
                f"records checked  {i.get('records_verified')}   (signature check: {i.get('ed25519')})"]
        w = i.get("witness_cosignatures") or []
        cov = i.get("witnessed_up_to") or 0
        out.append("witnesses        " + (", ".join(sorted({f"{x['witness']}@{x['size']}" for x in w})) if w else "none verified")
                   + (f"   (covers records 0..{cov - 1})" if cov else ""))
        pol = i.get("policy") or {}
        if pol.get("min_witnesses"):
            kk = i.get("witnessed_by_required_up_to") or 0
            out.append(f"witness policy   at least {pol['min_witnesses']}"
                       + (f", each at most {int(pol['max_age_seconds'])} s old" if pol.get("max_age_seconds") is not None else "")
                       + f"   (records 0..{kk - 1} are covered)" if kk else f"witness policy   at least {pol['min_witnesses']}   (no record is covered yet)")
    ob = i.get("observed")
    if ob:
        out.append(f"observed (dry run) {ob['total']} reported actions: {ob.get('allow', 0)} would pass, "
                   f"{ob.get('pending', 0)} would need approval, {ob.get('deny', 0)} would be refused; nothing was executed or stopped")
    for aid, a in rep.get("actions", {}).items():
        out.append(f"  {aid}: {a.get('tool')} by {a.get('agent')}; approvers {a.get('approvers')}; {' > '.join(e.split('.')[-1] for e in a['events'])}")
    for w in rep.get("warnings", []):
        out.append("WARNING  " + w)
    for p in rep.get("problems", []):
        out.append("PROBLEM  " + p)
    out.append("=" * 60)
    out.append("RESULT: " + ("VERIFIED" if rep.get("ok") else "FAILED") + ("  (with warnings)" if rep.get("ok") and rep.get("warnings") else ""))
    return "\n".join(out)


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="Verify an OmniOS evidence bundle offline")
    ap.add_argument("bundle")
    ap.add_argument("--log-key", help="base64 public key of the log, obtained out of band")
    ap.add_argument("--witness", action="append", default=[], metavar="NAME=KEY", help="a trusted witness public key (repeatable)")
    ap.add_argument("--min-witnesses", type=int, metavar="K", help="require at least K distinct trusted witnesses")
    ap.add_argument("--max-age", metavar="AGE", help="a witness counts only if its latest cosignature is this recent, e.g. 36h, 7d, 3600")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    age = None
    if a.max_age:
        m = re.fullmatch(r"(\d+(?:\.\d+)?)([smhd]?)", a.max_age.strip())
        if not m:
            print("--max-age: a number with an optional s, m, h or d (e.g. 36h)", file=sys.stderr)
            return 3
        age = float(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    wit = {}
    for w in a.witness:
        if "=" not in w:
            print("--witness needs NAME=BASE64KEY", file=sys.stderr)
            return 3
        n, k = w.split("=", 1)
        wit[n] = k
    rep = verify_bundle(a.bundle, a.log_key, wit, min_witnesses=a.min_witnesses, max_age=age)
    if "tenant" not in rep.get("info", {}) and not rep["ok"] and not rep.get("info"):
        print(render(rep) if not a.json else json.dumps(rep, indent=2), file=sys.stderr)
        return 3
    print(json.dumps(rep, indent=2) if a.json else render(rep))
    return 0 if rep["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
