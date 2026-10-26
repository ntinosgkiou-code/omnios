"""
policy.py — rules as data: evaluation, strict validation, hashing and a versioned history.
=========================================================================================
Ported from the v1 gateway (same rule language, so every v1 policy still validates) with three changes:

  • credentials in a proxy tool's headers are written ${SECRET:NAME} and resolved PER TENANT. v1 used ${ENV:NAME} from
    the process environment, which in a multi-customer process would let customer A's policy name customer B's secret.
  • approvals may be restricted to groups:  "approvals": {"required": 2, "groups": ["finance"]}   (who may approve what)
  • every activated policy is stored as a numbered version, and its full text goes into the ledger, so an auditor can
    see exactly which rules were in force for any decision (the decision records carry the policy hash).

Fail-closed everywhere: a condition that cannot be evaluated (field missing, not a number) is "unknown", and the engine
sends unknown to a human. A policy that cannot be understood is refused whole, never partly applied.
"""
from __future__ import annotations

import re
import urllib.parse
from decimal import Decimal, InvalidOperation
from typing import Any, Optional

from .canonical import digest

REVERSIBILITY = ("two_way", "one_way_recoverable", "one_way_consequential", "one_way_terminal")
IRREVERSIBLE = {"one_way_consequential", "one_way_terminal"}
PERIOD_SECONDS = {"hour": 3600, "day": 86400, "week": 7 * 86400, "month": 30 * 86400}
OPS = {">", ">=", "<", "<=", "==", "!=", "in", "not_in", "contains", "exists", "missing"}
EMPTY_POLICY: dict = {"version": 1, "default_unknown_tool": "deny", "tools": {}}
_NS = "policy"


# ───────────────────────────────── conditions (tri-state, fail-closed) ─────────────────────────────────
_PLAIN_NUMBER = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]{1,3})?")


def num(v: Any) -> Optional[Decimal]:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        try:
            d = Decimal(str(v))
        except InvalidOperation:
            return None
    elif isinstance(v, str):
        # plain ASCII decimal notation only: Python's Decimal also accepts "1_000" and non-ASCII digits, which other
        # systems read differently, so the gate and the system behind it could disagree about the amount
        if not _PLAIN_NUMBER.fullmatch(v.strip()):
            return None
        try:
            d = Decimal(v.strip())
        except InvalidOperation:
            return None
    else:
        return None
    return d if d.is_finite() and abs(d.adjusted()) < 40 else None


def get_path(params: Any, path: str) -> tuple[bool, Any]:
    cur = params
    for part in str(path).split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False, None
    return True, cur


def _loose_eq(a: Any, b: Any) -> bool:
    na, nb = num(a), num(b)
    if na is not None and nb is not None and not isinstance(a, bool) and not isinstance(b, bool):
        return na == nb
    return a == b


def _eval_leaf(c: dict, params: dict) -> Optional[bool]:
    op = c["op"]
    found, val = get_path(params, c["field"])
    present = found and val is not None
    if op == "exists":
        return present
    if op == "missing":
        return not present
    if not present:
        return None                                   # cannot evaluate: the caller decides (always: escalate)
    if op in (">", ">=", "<", "<="):
        a, b = num(val), num(c["value"])
        if a is None or b is None:
            return None
        return {">": a > b, ">=": a >= b, "<": a < b, "<=": a <= b}[op]
    if op in ("==", "!="):
        res = _loose_eq(val, c["value"])
        return res if op == "==" else not res
    if op in ("in", "not_in"):
        res = any(_loose_eq(val, x) for x in c["value"])
        return res if op == "in" else not res
    if op == "contains":
        if not isinstance(val, str):
            return None
        return str(c["value"]).lower() in val.lower()
    return None


def eval_cond(c: dict, params: dict) -> Optional[bool]:
    """True / False / None (= cannot be evaluated). Composites: {"all":[…]}, {"any":[…]}, {"not":c}."""
    if "all" in c:
        rs = [eval_cond(x, params) for x in c["all"]]
        if any(r is False for r in rs):
            return False
        return None if any(r is None for r in rs) else True
    if "any" in c:
        rs = [eval_cond(x, params) for x in c["any"]]
        if any(r is True for r in rs):
            return True
        return None if any(r is None for r in rs) else False
    if "not" in c:
        r = eval_cond(c["not"], params)
        return None if r is None else (not r)
    return _eval_leaf(c, params)


# ───────────────────────────────── validation ─────────────────────────────────
def _validate_cond(c: Any, where: str, errs: list[str], depth: int = 0) -> None:
    if depth > 6:
        errs.append(f"{where}: condition nested too deeply")
        return
    if not isinstance(c, dict):
        errs.append(f"{where}: a condition must be an object")
        return
    for k in ("all", "any"):
        if k in c:
            if not isinstance(c[k], list) or not c[k]:
                errs.append(f"{where}.{k}: needs a non-empty list")
            else:
                for i, x in enumerate(c[k]):
                    _validate_cond(x, f"{where}.{k}[{i}]", errs, depth + 1)
            return
    if "not" in c:
        _validate_cond(c["not"], f"{where}.not", errs, depth + 1)
        return
    if not isinstance(c.get("field"), str) or not c.get("field"):
        errs.append(f"{where}: 'field' (string) is required")
    op = c.get("op")
    if op not in OPS:
        errs.append(f"{where}: unknown op {op!r} (allowed: {sorted(OPS)})")
    elif op in ("in", "not_in") and not isinstance(c.get("value"), list):
        errs.append(f"{where}: op {op} needs a list 'value'")
    elif op not in ("exists", "missing", "in", "not_in") and "value" not in c:
        errs.append(f"{where}: op {op} needs a 'value'")


def _validate_upstream(u: dict, allow_insecure_localhost: bool) -> list[str]:
    errs: list[str] = []
    url = u.get("url")
    if not isinstance(url, str):
        return ["'url' is required"]
    p = urllib.parse.urlparse(url)
    local = p.hostname in ("127.0.0.1", "localhost", "::1")
    if p.scheme != "https" and not (p.scheme == "http" and local and allow_insecure_localhost):
        errs.append("url must be https (plain http is accepted only for localhost in test mode)")
    if p.username or p.password:
        errs.append("credentials do not belong in the url; use headers with ${SECRET:NAME}")
    if u.get("method", "POST") not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        errs.append("method must be GET, POST, PUT, PATCH or DELETE")
    hdrs = u.get("headers", {})
    if not isinstance(hdrs, dict) or not all(isinstance(v, str) for v in hdrs.values()):
        errs.append("headers must be an object of strings")
    else:
        for k, v in hdrs.items():
            if "${ENV:" in v:
                errs.append(f"header {k}: ${{ENV:…}} is not allowed in the multi-customer platform; use ${{SECRET:NAME}}")
    t = u.get("timeout", 15)
    if not isinstance(t, (int, float)) or isinstance(t, bool) or not 0 < t <= 60:
        errs.append("timeout must be a number of seconds, 0 < t <= 60")
    return errs


def validate_policy(doc: Any, allow_insecure_localhost: bool = False) -> list[str]:
    """Human-readable errors (empty list = valid). Strict on purpose."""
    errs: list[str] = []
    if not isinstance(doc, dict):
        return ["policy must be a JSON object"]
    if doc.get("version") != 1:
        errs.append("version must be 1")
    if doc.get("default_unknown_tool", "deny") not in ("deny", "pending"):
        errs.append("default_unknown_tool must be 'deny' or 'pending'")
    tools = doc.get("tools")
    if not isinstance(tools, dict):
        return errs + ["'tools' must be an object (it may be empty)"]
    for name, t in tools.items():
        w = f"tools.{name}"
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", str(name)):
            errs.append(f"{w}: tool names use letters, digits and _ . : - (max 80)")
        if not isinstance(t, dict):
            errs.append(f"{w}: must be an object")
            continue
        if t.get("reversibility") not in REVERSIBILITY:
            errs.append(f"{w}.reversibility is REQUIRED, one of {list(REVERSIBILITY)}")
        risk = t.get("risk", "high")
        if risk not in ("low", "high"):
            errs.append(f"{w}.risk must be 'low' or 'high'")
        if t.get("reversibility") in IRREVERSIBLE and risk != "high":
            errs.append(f"{w}: an irreversible tool can never be risk 'low' (it must always wait for a human)")
        if "permission" in t and not isinstance(t["permission"], str):
            errs.append(f"{w}.permission must be a string")
        for kind in ("escalate", "deny"):
            for i, r in enumerate(t.get(kind, [])):
                if not isinstance(r, dict) or "when" not in r:
                    errs.append(f"{w}.{kind}[{i}]: needs a 'when' condition")
                else:
                    _validate_cond(r["when"], f"{w}.{kind}[{i}].when", errs)
        for i, lim in enumerate(t.get("limits", [])):
            lw = f"{w}.limits[{i}]"
            if not isinstance(lim, dict) or not isinstance(lim.get("field"), str):
                errs.append(f"{lw}: needs a 'field'")
                continue
            if lim.get("per") not in PERIOD_SECONDS:
                errs.append(f"{lw}.per must be one of {sorted(PERIOD_SECONDS)}")
            m = num(lim.get("max"))
            if m is None or m <= 0:
                errs.append(f"{lw}.max must be a number > 0")
            if lim.get("on_exceed", "deny") not in ("deny", "escalate"):
                errs.append(f"{lw}.on_exceed must be 'deny' or 'escalate'")
            if lim.get("scope", "tool") not in ("tool", "agent"):
                errs.append(f"{lw}.scope must be 'tool' or 'agent'")
        ap = t.get("approvals", {})
        if not isinstance(ap, dict):
            errs.append(f"{w}.approvals must be an object")
        else:
            req = ap.get("required", 1)
            if not isinstance(req, int) or isinstance(req, bool) or not 1 <= req <= 5:
                errs.append(f"{w}.approvals.required must be an integer 1..5")
            groups = ap.get("groups", [])
            if not isinstance(groups, list) or not all(isinstance(g, str) and g for g in groups):
                errs.append(f"{w}.approvals.groups must be a list of group names")
            for i, x in enumerate(ap.get("extra", [])):
                if not isinstance(x, dict) or "when" not in x or not isinstance(x.get("required"), int) \
                        or isinstance(x.get("required"), bool) or not 1 <= x["required"] <= 5:
                    errs.append(f"{w}.approvals.extra[{i}]: needs 'when' and an integer 'required' 1..5")
                else:
                    _validate_cond(x["when"], f"{w}.approvals.extra[{i}].when", errs)
        for i, ek in enumerate(t.get("effect_key", [])):
            if not isinstance(ek, dict) or not isinstance(ek.get("field"), str) or not isinstance(ek.get("as"), str) \
                    or ek.get("norm", "raw") not in ("text", "cents", "int", "raw"):
                errs.append(f"{w}.effect_key[{i}]: needs 'field', 'as' and norm in text|cents|int|raw")
        ex = t.get("execution", {"mode": "agent"})
        if not isinstance(ex, dict) or ex.get("mode", "agent") not in ("agent", "proxy"):
            errs.append(f"{w}.execution.mode must be 'agent' or 'proxy'")
        elif ex.get("mode") == "proxy":
            errs += [f"{w}.execution: {e}" for e in _validate_upstream(ex, allow_insecure_localhost)]
            comp = ex.get("compensate")
            if comp is not None:
                errs += [f"{w}.execution.compensate: {e}" for e in _validate_upstream(comp, allow_insecure_localhost)]
            elif t.get("reversibility") in ("two_way", "one_way_recoverable"):
                errs.append(f"{w}: a reversible proxy tool must define execution.compensate")
    return errs


def policy_hash(doc: dict) -> str:
    return digest(doc)


# ───────────────────────────────── versioned history ─────────────────────────────────
class PolicyStore:
    """Numbered versions of a tenant's policy. `activate` validates, stores version n+1 and makes it current."""

    def __init__(self, kv: Any, allow_insecure_localhost: bool = False) -> None:
        self._kv = kv
        self._allow_local = allow_insecure_localhost

    def current(self) -> dict:
        cur = self._kv.get(_NS, "current")
        if cur is None:
            return {"n": 0, "hash": policy_hash(EMPTY_POLICY), "doc": EMPTY_POLICY, "by": "system", "at": 0}
        return self._kv.get(_NS, f"v{cur['n']}")

    def activate(self, doc: dict, by: str, now: float) -> dict:
        errs = validate_policy(doc, self._allow_local)
        if errs:
            raise ValueError("; ".join(errs))
        cur = self._kv.get(_NS, "current") or {"n": 0}
        n = int(cur["n"]) + 1
        rec = {"n": n, "hash": policy_hash(doc), "doc": doc, "by": by, "at": now}
        self._kv.put(_NS, f"v{n}", rec)
        self._kv.put(_NS, "current", {"n": n})
        return rec

    def history(self) -> list[dict]:
        out = []
        for k, v in self._kv.all(_NS).items():
            if k.startswith("v"):
                out.append({"n": v["n"], "hash": v["hash"], "by": v["by"], "at": v["at"]})
        return sorted(out, key=lambda x: x["n"])
