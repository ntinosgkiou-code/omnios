"""
evidence.py — the evidence bundle (deliverable 3): one zip an auditor, insurer or customer can check offline.
=============================================================================================================
Layout (format "omnios-evidence-bundle", version 1; full spec in docs/EVIDENCE-BUNDLE-SPEC.md):

    manifest.json     tenant, log origin, the log's public key, size, scope, profile, admin quorum, sha256 of every other file
    checkpoints.json  {"main": {note}, "witnessed": [{note (log-signed + cosignature lines), consistency proof to main}]}
    records.jsonl     one line per record: {"seq", "body" (the exact canonical JSON text), "leaf", "proof" (inclusion, hex)}
    README.txt        how to verify, in plain words
    verify.py         the stand-alone verifier (stdlib only; uses `cryptography` if installed, pure Python otherwise)

Scopes:  all      every record (the whole ledger up to the checkpoint)
         action   the records of one action (--id act-00007) plus the policy versions and admin changes they rely on
         changes  the governance of the system itself: policy versions, key changes, approvals of both, tenant events

The bundle never contains raw parameters, comments or credentials: the ledger holds identifiers, digests and the rule-generated reasons for each decision (a reason can quote a number, such as a daily total).
The log key inside the bundle is for convenience; the verifier asks you to PIN the key you got another way.
"""
from __future__ import annotations

import hashlib
import io
import json
import time
import zipfile
from pathlib import Path
from typing import Optional

from .errors import OmniError
from .tenant import TenantRuntime

FORMAT = "omnios-evidence-bundle"
_README = """OmniOS evidence bundle
======================
Tenant: {tenant}     Log: {origin}     Records: {size}     Scope: {scope}     Generated: {when}

HOW TO CHECK IT (Python 3.9 or newer, nothing to install):

    python verify.py bundle.zip --log-key <the log's public key, obtained from the customer by another route> \\
                                --witness <name>=<that witness's public key>

* The log key in manifest.json is only a convenience. If you do not pin the key you obtained separately, the check is
  reported as UNPINNED and proves nothing about who runs the log.
* A witness is a program run by someone other than the operator. If a trusted witness cosigned this log, the operator
  could not have rewritten the part it saw without being caught. Without a witness the operator can rewrite history.
* verify.py inside this zip was produced by the same party as the zip. For a real check, use a copy of the verifier you obtained
  separately (and compare its sha256 with the one the vendor publishes).
* "VERIFIED" means: the records are exactly what was committed, they sit in the checkpointed tree, and the rules recorded
  in the ledger (distinct approvers, none of them the agent, enough approvals before execution) were followed.
  It does NOT mean the decisions were right, or that nothing was left out before being logged.
"""


def build_bundle(rt: TenantRuntime, scope: str = "all", ref: Optional[str] = None) -> bytes:
    led = rt.ledger
    size = led.size()
    if scope not in ("all", "action", "changes"):
        raise OmniError(422, "invalid_scope", "one of all | action | changes")
    if scope == "all":
        recs = list(led.iter_records(0)) if size else []
    elif scope == "changes":
        recs = led.by_type("tenant.", "policy.", "change.", "principal.", "witness.")
    else:
        if not ref:
            raise OmniError(422, "id_required", "scope 'action' needs the action id")
        recs = led.by_ref(ref)
        if not recs:
            raise OmniError(404, "no_records_for_id", ref)
        want_hash = {json.loads(r["body"])["data"].get("policy_hash") for r in recs}
        by_seq = {r["seq"]: r for r in recs}
        for p in led.by_type("policy."):
            d = json.loads(p["body"])["data"]
            if d.get("policy_hash") in want_hash:
                by_seq[p["seq"]] = p
                via = d.get("via", "")
                if via.startswith("chg-"):
                    for c in led.by_ref(via):
                        by_seq[c["seq"]] = c
        recs = [by_seq[s] for s in sorted(by_seq)]
    cp = led.checkpoint()
    lines = []
    for r in recs:
        inc = led.inclusion(r["seq"], size)
        lines.append(json.dumps({"seq": r["seq"], "body": r["body"], "leaf": r["leaf"], "proof": inc["proof"]}, ensure_ascii=False))
    witnessed = []
    wsizes = sorted({s for s in led.latest_cosig_sizes().values() if s <= size}, reverse=True)[:8]   # each witness's latest
    for w in wsizes:
        cons = led.consistency(w, size)["proof"] if w <= size else []
        witnessed.append({"note": led.note_with_cosignatures(w), "consistency": cons})
    checkpoints = {"main": {"note": led.note_for_size(size)}, "witnessed": witnessed}
    when = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    scope_info = {"kind": scope, **({"id": ref} if ref else {})}
    files = {
        "checkpoints.json": json.dumps(checkpoints, indent=1).encode("utf-8"),
        "records.jsonl": ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8"),
        "README.txt": _README.format(tenant=rt.id, origin=led.origin, size=size, scope=scope, when=when).encode("utf-8"),
        "verify.py": (Path(__file__).parent / "verifier.py").read_bytes(),
    }
    manifest = {"format": FORMAT, "version": 1, "tenant": rt.id, "name": rt.cfg.get("name"), "origin": led.origin,
                "key_name": led.origin, "log_public_key": cp["log_public_key"], "size": size, "scope": scope_info,
                "profile": rt.cfg.get("profile"), "admin_quorum": rt.cfg.get("admin_quorum"), "generated_at": when,
                "witnesses_registered": sorted((rt.cfg.get("witnesses") or {}).keys()),
                "files": {n: hashlib.sha256(b).hexdigest() for n, b in files.items()}}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, indent=1))
        for n, b in files.items():
            z.writestr(n, b)
    return buf.getvalue()
