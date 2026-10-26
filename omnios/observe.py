"""
observe.py — the shadow report: what the customer's own agent did, and what the rules WOULD have said.
=========================================================================================================
Observe mode is the low-risk way to start. The customer's system tells OmniOS what its agent does (a few identifiers and
the fields the rules need), nothing is blocked, nothing is executed, no credentials are involved. Every event is judged
against the tenant's rules as a dry run, written to the signed ledger (so the observation itself can be witnessed and
verified) and counted here.

The report says, in plain words, how many actions would have been allowed, would have needed N approvals, or would have
been refused, which tools are outside the rules, and which cases to look at first.

Honest limits, printed in every report: it covers only what the customer's system reported (an agent that is not reported
is not seen); the verdicts are simulated under the rules in force and nothing was actually stopped; the rules may be a
first draft; it says nothing about whether the actions were right.
"""
from __future__ import annotations

import html
import re
import time
from collections import Counter, defaultdict
from typing import Optional

_NUM = re.compile(r"\d[\d.,]*")
VERDICT = {"allow": "would have been allowed", "pending": "would have needed approval", "deny": "would have been refused"}


def _at(o: dict) -> float:
    return o.get("occurred_at") or o["created_at"]


def _unmapped(o: dict) -> bool:
    return o["decision"] != "allow" and any("is not in the policy" in r for r in o.get("reasons", []))


def summarize(obs: list[dict], attention: int = 25) -> dict:
    total = len(obs)
    dec = Counter(o["decision"] for o in obs)
    by_tool: dict = defaultdict(lambda: {"total": 0, "allow": 0, "pending": 0, "deny": 0})
    reasons: Counter = Counter()
    approvals = Counter()
    unmapped = Counter()
    unknown_input = 0
    for o in obs:
        t = by_tool[o["tool"]]
        t["total"] += 1
        t[o["decision"]] += 1
        if o["decision"] == "pending":
            approvals[o["approvals_required"]] += 1
        if _unmapped(o):
            unmapped[o["tool"]] += 1
        for r in o.get("reasons", []):
            if "could not be" in r or "missing or non-numeric" in r:
                unknown_input += 1
                break
        if o["decision"] != "allow":
            for r in o.get("reasons", [])[:2]:
                reasons[_NUM.sub("N", r)] += 1
    ordered = sorted((o for o in obs if o["decision"] != "allow"), key=lambda o: (0 if o["decision"] == "deny" else 1, -_at(o)))
    times = [_at(o) for o in obs]
    return {
        "total": total, "allow": dec.get("allow", 0), "pending": dec.get("pending", 0), "deny": dec.get("deny", 0),
        "needs_review_share": round((dec.get("pending", 0) + dec.get("deny", 0)) / total, 3) if total else 0,
        "by_tool": {k: v for k, v in sorted(by_tool.items(), key=lambda kv: -kv[1]["total"])},
        "pending_by_approvals": {str(k): v for k, v in sorted(approvals.items())},
        "unmapped_tools": dict(unmapped.most_common()),
        "unreadable_input": unknown_input,
        "top_reasons": [{"reason": r, "count": c} for r, c in reasons.most_common(8)],
        "attention": [{"id": o["id"], "tool": o["tool"], "decision": o["decision"], "approvals_required": o["approvals_required"],
                       "at": _at(o), "reasons": o.get("reasons", [])[:3], "params_digest": o["params_digest"][:16]} for o in ordered[:attention]],
        "agents": sorted({o["agent"] for o in obs}),
        "policy_hashes": sorted({o["policy_hash"][:12] for o in obs}),
        "first_at": min(times) if times else None, "last_at": max(times) if times else None,
    }


_CSS = """:root{--bg:#f4f6f9;--sf:#fff;--ink:#0e1a2b;--mu:#5b6472;--ln:#d8dde6;--ok:#17693f;--oks:#e3f4ea;--wn:#8a4700;--wns:#fcefdc;--er:#9b2226;--ers:#fbe7e8}
@media(prefers-color-scheme:dark){:root{--bg:#0a111d;--sf:#111b2c;--ink:#e7ecf6;--mu:#93a0b6;--ln:#243350;--ok:#6fd39d;--oks:#13301f;--wn:#f0b35e;--wns:#33250f;--er:#f29a9d;--ers:#3a1517}}
body{background:var(--bg);color:var(--ink);font:15px/1.6 system-ui,'Segoe UI',sans-serif;margin:0;padding:24px 16px}main{max-width:920px;margin:0 auto}
h1{font-size:28px;margin:0 0 4px}h2{font-size:19px;margin:30px 0 8px}.mu{color:var(--mu)}
.k{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin:14px 0}.k div{background:var(--sf);border:1px solid var(--ln);border-radius:10px;padding:12px 14px}.k b{display:block;font-size:28px}
.ok b{color:var(--ok)}.wn b{color:var(--wn)}.er b{color:var(--er)}

.tw{overflow-x:auto}table{border-collapse:collapse;width:100%;background:var(--sf);font-size:14px}th,td{border:1px solid var(--ln);padding:7px 9px;text-align:left;vertical-align:top}th{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--mu)}
.box{background:var(--sf);border:1px solid var(--ln);border-radius:10px;padding:12px 16px;margin:14px 0}.warn{background:var(--wns);border-color:var(--wn)}code{font-family:ui-monospace,Consolas,monospace;font-size:.9em}"""


def render_html(summary: dict, tenant_name: str, generated: Optional[float] = None, banner: Optional[str] = None) -> str:
    e = html.escape
    s = summary
    when = lambda t: time.strftime("%Y-%m-%d", time.gmtime(t)) if t else "-"
    gen = time.strftime("%Y-%m-%d", time.gmtime(generated if generated is not None else time.time()))
    rows = "".join(f"<tr><td>{e(t)}</td><td>{v['total']}</td><td>{v['allow']}</td><td>{v['pending']}</td><td>{v['deny']}</td></tr>" for t, v in s["by_tool"].items()) \
        or "<tr><td colspan=5>-</td></tr>"
    att = "".join(f"<tr><td><code>{e(a['id'])}</code></td><td>{e(a['tool'])}</td><td>{e(VERDICT[a['decision']])}"
                  f"{' (' + str(a['approvals_required']) + ' approvers)' if a['decision'] == 'pending' else ''}</td><td>{e(when(a['at']))}</td>"
                  f"<td>{e('; '.join(a['reasons']))}</td></tr>" for a in s["attention"]) or "<tr><td colspan=5>-</td></tr>"
    rsn = "".join(f"<li>{e(r['reason'])} <span class='mu'>({r['count']})</span></li>" for r in s["top_reasons"]) or "<li>-</li>"
    um = "".join(f"<li><code>{e(t)}</code>: {n}</li>" for t, n in s["unmapped_tools"].items())
    pct = round(100 * s["needs_review_share"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Shadow report: {e(tenant_name)}</title><style>{_CSS}</style></head><body><main>
<p class="mu">OmniOS &middot; observe mode &middot; generated {e(gen)}</p>
<h1>Shadow report: {e(tenant_name)}</h1>
{'<div class="box warn"><b>' + e(banner) + '</b></div>' if banner else ''}
<p class="mu">Period {e(when(s['first_at']))} to {e(when(s['last_at']))} &middot; agents: {e(', '.join(s['agents']) or '-')} &middot; rules in force: {e(', '.join(s['policy_hashes']) or '-')}</p>
<div class="k"><div><b>{s['total']}</b><span class="mu">actions reported</span></div>
<div class="ok"><b>{s['allow']}</b><span class="mu">would have been allowed</span></div>
<div class="wn"><b>{s['pending']}</b><span class="mu">would have needed approval</span></div>
<div class="er"><b>{s['deny']}</b><span class="mu">would have been refused</span></div></div>
<p><b>{pct}%</b> of the reported actions would not have gone through automatically under these rules.
{'<b>' + str(len(s['unmapped_tools'])) + ' tool(s) used by the agent are not in the rules at all.</b>' if s['unmapped_tools'] else ''}
{'<b>' + str(s['unreadable_input']) + ' action(s) had a field the rules needed that was missing or not a clean number</b>; those are sent to a human.' if s['unreadable_input'] else ''}</p>
{'<h2>Tools outside the rules</h2><ul>' + um + '</ul>' if um else ''}
<h2>By tool</h2><div class="tw"><table><thead><tr><th>Tool</th><th>Total</th><th>Allowed</th><th>Approval</th><th>Refused</th></tr></thead><tbody>{rows}</tbody></table></div>
<h2>Why actions did not pass</h2><ul>{rsn}</ul>
<h2>Look at these first</h2><div class="tw"><table><thead><tr><th>Id</th><th>Tool</th><th>Verdict</th><th>When</th><th>Reason</th></tr></thead><tbody>{att}</tbody></table></div>
<div class="box warn"><b>What this report is, and is not.</b> It is based only on what the customer's own system reported: an agent that is not reported is not seen.
The verdicts are a simulation under the rules in force (which may be a first draft); nothing was stopped and nothing was executed. It says
nothing about whether the actions were right. Every event is also written to a signed, append-only ledger (identifiers, digests and the reasons for each verdict, no raw parameters); once an
outside witness has recorded its checkpoint, a later change to this history can be detected, and until then it cannot. It is not a certification,
a penetration test or legal advice.</div>
</main></body></html>"""


# ───────────────────────── importing an export (the no-integration way to start) ─────────────────────────
_RESERVED = {"tool", "params", "external_id", "occurred_at"}


def _parse_time(v):
    """A number of seconds, a numeric string, or an ISO-8601 date/time (UTC when no zone is given). Returns None for empty."""
    import datetime as _dt
    if v is None or (isinstance(v, str) and not v.strip()):
        return None
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    s = str(v).strip()
    try:
        return float(s)
    except ValueError:
        pass
    try:
        d = _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"cannot read the time {s!r}: use seconds since 1970 or an ISO date such as 2026-10-01T09:30:00")
    if d.tzinfo is None:
        d = d.replace(tzinfo=_dt.timezone.utc)
    return d.timestamp()


def load_events(path: str) -> list:
    """Read a .jsonl or .csv export into observe events. Columns/keys: tool (required), external_id, occurred_at; in JSONL an
    optional "params" object, otherwise every other key is a parameter; in CSV every other column is a parameter (empty cells
    are left out; values stay text, which the rules read as numbers when they are plain decimals)."""
    import csv
    import json as _json
    from pathlib import Path
    p = Path(path)
    rows: list = []
    if p.suffix.lower() == ".csv":
        with p.open(newline="", encoding="utf-8-sig") as f:
            for n, r in enumerate(csv.DictReader(f), start=2):
                rows.append((n, {k.strip(): v for k, v in r.items() if k and v is not None and str(v).strip() != ""}))
    else:
        with p.open(encoding="utf-8-sig") as f:
            for n, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                try:
                    obj = _json.loads(line)
                except ValueError:
                    raise ValueError(f"line {n}: not valid JSON")
                if not isinstance(obj, dict):
                    raise ValueError(f"line {n}: each line must be a JSON object")
                rows.append((n, obj))
    out = []
    for n, r in rows:
        tool = r.get("tool")
        if not isinstance(tool, str) or not tool.strip():
            raise ValueError(f"row {n}: the 'tool' column is required")
        params = r["params"] if isinstance(r.get("params"), dict) else {k: v for k, v in r.items() if k not in _RESERVED}
        ev = {"tool": tool.strip(), "params": params}
        if r.get("external_id") not in (None, ""):
            ev["external_id"] = str(r["external_id"])
        try:
            t = _parse_time(r.get("occurred_at"))
        except ValueError as e:
            raise ValueError(f"row {n}: {e}")
        if t is not None:
            ev["occurred_at"] = t
        out.append(ev)
    if not out:
        raise ValueError("the file has no events")
    # shadow limits count what happened before an event, so the order must be chronological
    out.sort(key=lambda e: e.get("occurred_at") if e.get("occurred_at") is not None else float("inf"))
    return out


def import_events(rt, agent: str, events: list, batch: int = 200) -> dict:
    """Feed events to a tenant's engine in batches as `agent`. Returns {"imported", "decisions"}."""
    from .errors import OmniError
    pr = rt.identity.get(agent)
    if pr is None or pr["role"] != "agent":
        raise OmniError(404, "no_such_agent", f"'{agent}' is not an agent of this tenant")
    done: list = []
    for i in range(0, len(events), batch):
        done += rt.engine.observe(agent, pr.get("permissions"), events[i:i + batch])
    c = Counter(o["decision"] for o in done)
    return {"imported": len(done), "decisions": {k: c.get(k, 0) for k in ("allow", "pending", "deny")}}
