"""
assess.py — the Agent Control Check kit (deliverable 1): answers file in, findings + recommended rules + report out.
====================================================================================================================
A consultant fills `answers.yaml` WITH the client (60-90 minutes). `analyse` scores every tool the agents can use,
finds the control gaps, maps them to OWASP's agentic risks, and drafts the rules (policy) that would close them.
`render_report` writes a self-contained HTML report. Everything is deterministic and documented here, so two people
filling the same answers get the same report, and the client can see WHY each finding exists.

Scoring (per tool):  irreversible +3, partly reversible +2 | moves money +3 | personal data +2 | reaches outside the
company +2 | value over 10,000 EUR +3, over 1,000 +2, over 100 +1.   High >= 6, Medium 3-5, Low < 3.

Honest limits, printed in every report: this check is based on the answers given and one demonstration. It is not a
penetration test, a certification or legal advice, and the OWASP / regulatory pointers say what a gap is RELEVANT to,
never that the client is or is not compliant. The recommended rules are a first draft for the client to review.
"""
from __future__ import annotations

import html
import json
import re
import time
from pathlib import Path
from typing import Any

import yaml

from .policy import validate_policy

_DATA = Path(__file__).parent / "assess_data"
_TF = {"yes": 0, "partly": 2, "no": 3}

# control catalogue: what closes the gap, and what it is RELEVANT to (never "compliant with")
CATALOGUE = {
    "C-APPROVAL": ("A human approves risky actions before they run", "ASI02 Tool Misuse & Exploitation",
                   "Rules per tool decide which actions need a human; the agent cannot approve itself."),
    "C-SOD": ("Two different people for money and irreversible actions", "ASI02 Tool Misuse; EU AI Act Art. 14 (human oversight)",
              "Require N distinct approvers by value; the same key cannot approve twice."),
    "C-LIMITS": ("Hard limits enforced outside the agent", "ASI02 Tool Misuse & Exploitation",
                 "Per-action ceilings and per-day totals in the rules; a limit that cannot be checked goes to a human."),
    "C-CRED": ("The agent never holds the credentials", "ASI03 Identity & Privilege Abuse",
               "Proxy mode: the platform holds the credentials and makes the approved call itself."),
    "C-LOG": ("A record that shows if it was edited", "ASI10 Rogue Agents; EU AI Act Art. 12 (record-keeping)",
              "A hash-chained, signed ledger holding identifiers, digests and decision reasons, never raw parameters."),
    "C-INDEP": ("Someone outside the team can verify the record", "ASI10 Rogue Agents",
                "A witness run by a party that is not the log's administrator, and an offline-verifiable evidence bundle."),
    "C-KILL": ("A kill switch within minutes", "ASI10 Rogue Agents", "Revoke the agent's key; with proxy mode nothing runs without the platform."),
    "C-INCIDENT": ("A written incident process", "ASI10 Rogue Agents", "Out of scope for the software: a one-page runbook with named owners."),
    "C-KEYS": ("Keys are rotated and revocable", "ASI03 Identity & Privilege Abuse", "Per-person keys, revocable at once, changes need a second admin."),
}


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-") or "tool"


def tool_id(name: str, taken: set) -> str:
    """A policy-legal tool name (letters, digits and _ . : -, at most 80 characters) that is unique in this draft."""
    base = re.sub(r"[^A-Za-z0-9_.:-]+", "-", str(name)).strip("-")[:76] or "tool"
    cand, n = base, 2
    while cand in taken:
        cand, n = f"{base}-{n}", n + 1
    taken.add(cand)
    return cand


def _bool(v: Any) -> bool:
    return v is True or str(v).strip().lower() in ("true", "yes", "1")


def score_tool(t: dict) -> dict:
    pts, why = 0, []
    rev = str(t.get("reversible", "no")).lower()
    if rev in ("no", "partly"):
        pts += 3 if rev == "no" else 2
        why.append("cannot be fully undone" if rev == "no" else "only partly reversible")
    if _bool(t.get("money")):
        pts += 3
        why.append("moves money")
    if _bool(t.get("personal_data")):
        pts += 2
        why.append("touches personal data")
    if _bool(t.get("external_effect")):
        pts += 2
        why.append("reaches outside the company")
    try:
        v = float(t.get("max_value_eur") or 0)
    except (TypeError, ValueError):
        v = 0
    if v > 10000:
        pts += 3
        why.append("values above 10,000 EUR")
    elif v > 1000:
        pts += 2
        why.append("values above 1,000 EUR")
    elif v > 100:
        pts += 1
    return {"points": pts, "level": "High" if pts >= 6 else "Medium" if pts >= 3 else "Low", "why": why}


def _finding(sev: str, ctl: str, where: str, text: str) -> dict:
    return {"severity": sev, "control": ctl, "where": where, "text": text,
            "title": CATALOGUE[ctl][0], "relevant_to": CATALOGUE[ctl][1], "closes_with": CATALOGUE[ctl][2]}


def analyse(a: dict) -> dict:
    findings: list[dict] = []
    tools_out: list[dict] = []
    for ag in a.get("agents") or []:
        an = ag.get("name", "agent")
        holds = _bool(ag.get("credentials_held_by_agent"))
        for t in ag.get("tools") or []:
            sc = score_tool(t)
            tn = t.get("name", "tool")
            where = f"{an} / {tn}"
            hi = sc["level"] == "High"
            med_up = sc["level"] in ("High", "Medium")
            appr = str(t.get("human_approval_today", "none")).lower()
            rec = {"agent": an, "tool": tn, "system": t.get("system", ""), **sc, "approval_today": appr}
            tools_out.append(rec)
            if med_up and appr == "none":
                findings.append(_finding("High" if hi else "Medium", "C-APPROVAL", where,
                                         f"Runs with no human approval ({', '.join(sc['why']) or 'moderate impact'})."))
            if appr == "native-hook":
                findings.append(_finding("Medium", "C-LOG", where,
                                         "Approval exists inside the agent framework, but a framework hook does not by itself give "
                                         "separation of duties or a record that shows edits."))
            try:
                val = float(t.get("max_value_eur") or 0)
            except (TypeError, ValueError):
                val = 0
            if (_bool(t.get("money")) or (hi and rev_bad(t))) and not _bool(t.get("approvers_distinct")) and (val > 1000 or hi):
                findings.append(_finding("High" if hi else "Medium", "C-SOD", where,
                                         "One person (or nobody) can authorise this; a second, different person is not required."))
            if holds and (_bool(t.get("money")) or rev_bad(t)):
                findings.append(_finding("High", "C-CRED", where,
                                         "The agent's process holds the credentials, so it can call the system directly and skip any approval."))
            if med_up and not _bool(t.get("log_tamper_evident")):
                findings.append(_finding("Medium", "C-LOG", where,
                                         f"Recorded in: {t.get('logged_where') or 'unknown'}. Nobody outside the team can tell if it was edited."))
        if str(ag.get("autonomy", "")).lower() == "fully-autonomous" and any(score_tool(t)["level"] == "High" for t in ag.get("tools") or []):
            findings.append(_finding("High", "C-APPROVAL", an, "Fully autonomous agent with at least one high-impact tool."))
    ctl = a.get("controls") or {}
    for key, cid in (("separation_of_duties", "C-SOD"), ("spend_limits", "C-LIMITS"), ("kill_switch", "C-KILL"),
                     ("incident_process", "C-INCIDENT"), ("key_rotation", "C-KEYS"), ("independent_log_verification", "C-INDEP")):
        v = str(ctl.get(key, "no")).lower()
        if v != "yes":
            findings.append(_finding("Medium" if v == "partial" else "High" if cid in ("C-SOD", "C-LIMITS", "C-INDEP") else "Medium",
                                     cid, "organisation", f"{key.replace('_', ' ').capitalize()}: {v}."))
    ev = a.get("evidence_asked") or {}
    asked = ev.get("asked_by") or []
    out_ev = {"asked_by": asked, "what_was_shown": ev.get("what_was_shown", ""), "outcome": ev.get("outcome", ""),
              "pressure": bool(asked)}
    order = {"High": 0, "Medium": 1, "Low": 2}
    findings.sort(key=lambda f: (order[f["severity"]], f["control"]))
    summary = {"agents": len(a.get("agents") or []), "tools": len(tools_out),
               "high_impact_tools": sum(1 for t in tools_out if t["level"] == "High"),
               "findings": {s: sum(1 for f in findings if f["severity"] == s) for s in ("High", "Medium", "Low")}}
    return {"client": a.get("client") or {}, "tools": tools_out, "findings": findings, "evidence_asked": out_ev,
            "summary": summary, "policy": recommend_policy(a), "controls_today": ctl, "notes": a.get("notes", "")}


def rev_bad(t: dict) -> bool:
    return str(t.get("reversible", "no")).lower() in ("no", "partly")


def recommend_policy(a: dict) -> dict:
    """A FIRST DRAFT of the rules that would close the findings. It always validates; the client must review the numbers."""
    tools: dict[str, dict] = {}
    taken: set = set()
    for ag in a.get("agents") or []:
        for t in ag.get("tools") or []:
            sc = score_tool(t)
            original = str(t.get("name", "tool"))
            name = tool_id(original, taken)
            rev = str(t.get("reversible", "no")).lower()
            reversibility = {"yes": "two_way", "partly": "one_way_recoverable"}.get(rev, "one_way_consequential")
            risk = "low" if (sc["level"] == "Low" and reversibility == "two_way") else "high"
            entry: dict[str, Any] = {"description": f"{t.get('system', '')}: {', '.join(sc['why']) or 'low impact'}".strip(": "),
                                     "permission": slug(original), "reversibility": reversibility, "risk": risk,
                                     "x_review": "DRAFT: confirm every number with the client"
                                                 + ("" if name == original else f" (the client calls this tool '{original}'; agents must use the id '{name}')")}
            try:
                val = float(t.get("max_value_eur") or 0)
            except (TypeError, ValueError):
                val = 0
            field = t.get("value_field")
            if risk == "high":
                ap: dict[str, Any] = {"required": 1}
                if _bool(t.get("money")) and field:
                    if val > 0:
                        entry["deny"] = [{"when": {"field": field, "op": ">", "value": val},
                                          "reason": f"Above the agreed ceiling of {val:g} per action"}]
                        entry["limits"] = [{"field": field, "per": "day", "max": round(val * 3, 2), "on_exceed": "deny"}]
                    ap["extra"] = [{"when": {"field": field, "op": ">", "value": 1000}, "required": 2}]
                elif sc["level"] == "High":
                    ap["required"] = 2
                entry["approvals"] = ap
            tools[name] = entry
    doc = {"version": 1, "default_unknown_tool": "deny", "tools": tools}
    errs = validate_policy(doc)
    if errs:                                    # never hand out a draft that would not load
        raise ValueError("recommended policy is invalid: " + "; ".join(errs))
    return doc


def init_answers(out_path: str, client: str) -> str:
    text = (_DATA / "answers-template.yaml").read_text(encoding="utf-8").replace('"CLIENT NAME"', json.dumps(client, ensure_ascii=False))
    Path(out_path).write_text(text, encoding="utf-8")
    return out_path


def load_answers(path: str) -> dict:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not data.get("agents"):
        raise ValueError("answers file needs at least one agent under 'agents'")
    return data


_CSS = """:root{--bg:#f4f6f9;--sf:#fff;--ink:#0e1a2b;--mu:#5b6472;--ln:#d8dde6;--ac:#2347a8;--hi:#9b2226;--md:#8a4700;--lo:#17693f}
@media(prefers-color-scheme:dark){:root{--bg:#0a111d;--sf:#111b2c;--ink:#e7ecf6;--mu:#93a0b6;--ln:#243350;--ac:#a9c0ff;--hi:#f29a9d;--md:#f0b35e;--lo:#6fd39d}}
body{background:var(--bg);color:var(--ink);font:15px/1.6 system-ui,'Segoe UI',sans-serif;margin:0;padding:24px 16px}
main{max-width:900px;margin:0 auto}h1{font-size:30px;margin:0 0 6px}h2{font-size:20px;margin:32px 0 10px}
table{border-collapse:collapse;width:100%;background:var(--sf);font-size:14px}th,td{border:1px solid var(--ln);padding:8px 10px;text-align:left;vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--mu)}
.High{color:var(--hi);font-weight:700}.Medium{color:var(--md);font-weight:600}.Low{color:var(--lo);font-weight:600}
.box{background:var(--sf);border:1px solid var(--ln);border-radius:10px;padding:12px 16px;margin:14px 0}
pre{background:#0f1b2e;color:#dce6fa;padding:14px;border-radius:10px;overflow:auto;font-size:13px}small,.mu{color:var(--mu)}
.kpi{display:inline-block;margin:0 22px 8px 0}.kpi b{display:block;font-size:26px}"""


def render_report(res: dict) -> str:
    e = html.escape
    c, s = res["client"], res["summary"]
    rows_t = "".join(f"<tr><td>{e(t['agent'])}</td><td>{e(t['tool'])}</td><td>{e(str(t['system']))}</td>"
                     f"<td class=\"{t['level']}\">{t['level']}</td><td>{e(', '.join(t['why']))}</td><td>{e(t['approval_today'])}</td></tr>"
                     for t in res["tools"])
    rows_f = "".join(f"<tr><td class=\"{f['severity']}\">{f['severity']}</td><td>{e(f['where'])}</td><td>{e(f['text'])}</td>"
                     f"<td>{e(f['title'])}<br><small>{e(f['closes_with'])}</small></td><td><small>{e(f['relevant_to'])}</small></td></tr>"
                     for f in res["findings"]) or "<tr><td colspan=5>No findings.</td></tr>"
    top = "".join(f"<li><b>{e(f['where'])}</b>: {e(f['text'])}</li>" for f in res["findings"][:5])
    ev = res["evidence_asked"]
    pressure = (f"<p><b>Someone has already asked</b> ({e(', '.join(ev['asked_by']))}). What was shown: "
                f"{e(ev['what_was_shown'] or 'nothing recorded')}. Outcome: {e(ev['outcome'] or 'not recorded')}.</p>"
                if ev["pressure"] else "<p class=\"mu\">Nobody has asked the client for proof yet.</p>")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent Control Check: {e(str(c.get('name', '')))}</title><style>{_CSS}</style></head><body><main>
<p class="mu">OmniOS &middot; Agent Control Check &middot; {e(str(c.get('date') or time.strftime('%Y-%m-%d')))}</p>
<h1>{e(str(c.get('name', 'Client')))}</h1>
<p class="mu">{e(str(c.get('industry', '')))} &middot; trigger: {e(str(c.get('trigger') or 'none stated'))} {e(str(c.get('deadline') or ''))}</p>
<div class="box"><span class="kpi"><b>{s['agents']}</b>agents</span><span class="kpi"><b>{s['tools']}</b>tools</span>
<span class="kpi"><b>{s['high_impact_tools']}</b>high-impact tools</span>
<span class="kpi"><b class="High">{s['findings']['High']}</b>high findings</span><span class="kpi"><b class="Medium">{s['findings']['Medium']}</b>medium findings</span></div>
<h2>The five things to fix first</h2><ol>{top or '<li>Nothing urgent found.</li>'}</ol>
<h2>What a third party will ask</h2>{pressure}
<ol><li>Who approved this action, and could the same person have done it alone?</li><li>Which rules applied that day, and who changed them?</li>
<li>Can I check that this record was not edited after the fact, without trusting you?</li><li>What happens if the agent is wrong or deceived?</li></ol>
<h2>Inventory and impact</h2><table><tr><th>Agent</th><th>Tool</th><th>System</th><th>Impact</th><th>Why</th><th>Approval today</th></tr>{rows_t}</table>
<h2>Findings</h2><table><tr><th>Severity</th><th>Where</th><th>Finding</th><th>What closes it</th><th>Relevant to</th></tr>{rows_f}</table>
<h2>Draft rules</h2><p class="mu">A first draft that would close the findings above. It loads as it stands; review every number with the client.</p>
<pre>{e(json.dumps(res['policy'], indent=2, ensure_ascii=False))}</pre>
<h2>What this check is, and is not</h2><div class="box"><p>It is based on the answers given and one demonstration. It is not a penetration test, a
certification or legal advice. The OWASP and regulatory pointers say what a gap is <i>relevant to</i>; they never say the client is,
or is not, compliant. Findings about records and independent verification describe what can be proven to a third party, not whether
anything went wrong.</p></div></main></body></html>"""


def run_report(answers_path: str, out_dir: str) -> dict:
    res = analyse(load_answers(answers_path))
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    (d / "report.html").write_text(render_report(res), encoding="utf-8")
    (d / "findings.json").write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    (d / "draft-policy.json").write_text(json.dumps(res["policy"], indent=2, ensure_ascii=False), encoding="utf-8")
    return {"report": str(d / "report.html"), "findings": str(d / "findings.json"), "policy": str(d / "draft-policy.json"),
            "summary": res["summary"]}
