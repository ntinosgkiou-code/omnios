"""
engine.py — the action workflow for ONE tenant: propose -> approve -> execute, and admin changes under the same rule.
====================================================================================================================
Ported from the v1 gateway (same decisions, same fail-closed behaviour) with these structural changes:

  • No globals. The engine is handed its tenant's key-value store, ledger, policy store, identity store and forwarder.
    Two engines in one process share nothing, which is what makes many customers safe.
  • EVERYTHING that changes what the system will allow is an action under the same four-eyes rule: replacing the
    policy and creating or revoking a key are "changes" proposed by an admin and applied only once enough OTHER admins
    approve (tenant setting `admin_quorum`; 1 means the proposer alone, and that setting is part of the evidence).
    v1 let one admin do both alone (register gap A7).
  • Write-ahead evidence: a record "action.executing" is written BEFORE a proxy call leaves the building, and the
    outcome after it. If the ledger cannot be written the action does not happen (no evidence, no action). An
    "executing" with no outcome is visible to every verifier as a dangling execution.
  • Records carry identifiers, digests and the rule-generated reasons for each decision (a reason can quote a number, for
    example a daily total over a limit). Raw parameters, comments and credentials stay in the tenant's own store; the
    ledger keeps their digest, so the evidence can be bound to them without publishing them.

Honest limits: the engine enforces what the policy says and records it. It cannot judge whether a decision is RIGHT,
and in decision mode an agent that never asks is invisible (proxy mode and reconciliation exist for that).
"""
from __future__ import annotations

import threading
import time
from decimal import Decimal
from typing import Any, Callable, Optional

from .canonical import canon, digest
from .errors import OmniError
from .forwarder import Forwarder
from .identity import IdentityStore
from .ledger import Ledger
from .policy import (EMPTY_POLICY, IRREVERSIBLE, PERIOD_SECONDS, PolicyStore, eval_cond, get_path, num,
                     policy_hash, validate_policy)

_COUNTED = {"APPROVED", "EXECUTING", "EXECUTED", "REPORTED_SUCCESS"}      # statuses that consumed a limit
_NS_ACT, _NS_IDEM, _NS_META, _NS_CHG = "act", "idem", "meta", "chg"
_NS_OBS, _NS_OBS_IDEM = "obs", "obsidem"             # observe mode: events reported by the customer's own system
MAX_OBSERVE_BATCH = 200
CHANGE_KINDS = ("policy.replace", "principal.create", "principal.revoke")


class Engine:
    def __init__(self, tenant: str, kv: Any, ledger: Ledger, policies: PolicyStore, identity: IdentityStore,
                 forwarder: Forwarder, *, clock: Callable[[], float] = time.time, approval_ttl: int = 86400,
                 admin_quorum: int = 1, allow_insecure_localhost: bool = False) -> None:
        if admin_quorum < 1:
            raise ValueError("admin_quorum must be at least 1")
        self.tenant, self._kv, self.ledger = tenant, kv, ledger
        self._policies, self._identity, self._fwd = policies, identity, forwarder
        self._clock, self._ttl, self.admin_quorum = clock, approval_ttl, admin_quorum
        self._allow_local = allow_insecure_localhost
        self._lock = threading.RLock()

    # ───────────────────────── policy ─────────────────────────
    def policy(self) -> dict:
        return self._policies.current()["doc"]

    def policy_hash(self) -> str:
        return self._policies.current()["hash"]

    def policy_version(self) -> dict:
        cur = self._policies.current()
        return {"n": cur["n"], "hash": cur["hash"], "by": cur["by"], "at": cur["at"]}

    def bootstrap(self, doc: Optional[dict] = None, by: str = "system:provision") -> dict:
        """First activation of a tenant's policy (an operator action). Recorded in the ledger like any other."""
        return self._activate_policy(doc if doc is not None else EMPTY_POLICY, by, via="provision")

    def _activate_policy(self, doc: dict, by: str, via: str) -> dict:
        prev = self._policies.current()
        try:
            rec = self._policies.activate(doc, by, self._clock())
        except ValueError as e:
            raise OmniError(422, "invalid_policy", str(e))
        self._log("policy.activated", {"policy_hash": rec["hash"], "n": rec["n"], "previous_hash": prev["hash"] if prev["n"] else None,
                                       "by": by, "via": via, "policy": doc})
        return rec

    # ───────────────────────── helpers ─────────────────────────
    def _log(self, rtype: str, data: dict) -> dict:
        return self.ledger.append(rtype, data, at=self._clock())

    def _next(self, prefix: str, width: int) -> str:
        meta = self._kv.get(_NS_META, prefix) or {"n": 0}
        n = int(meta["n"]) + 1
        self._kv.put(_NS_META, prefix, {"n": n})
        return f"{prefix}-{n:0{width}d}"

    def _save(self, a: dict) -> None:
        self._kv.put(_NS_ACT, a["id"], a)

    @staticmethod
    def _view(a: dict) -> dict:
        import json
        return json.loads(json.dumps(a))

    def _tool(self, name: str) -> Optional[dict]:
        return self.policy()["tools"].get(name)

    def _base(self, a: dict) -> dict:
        return {"id": a["id"], "tool": a["tool"], "agent": a["agent"], "params_digest": a["params_digest"],
                "policy_hash": a["policy_hash"], "reversibility": a["reversibility"], "execution_mode": a["execution_mode"]}

    def _effect_key(self, tool: dict, params: dict) -> Optional[str]:
        spec = tool.get("effect_key")
        if not spec:
            return None
        out: dict[str, Any] = {}
        for item in spec:
            found, v = get_path(params, item["field"])
            if not found or v is None:
                return None
            norm = item.get("norm", "raw")
            try:
                if norm == "text":
                    v = str(v).strip().lower()
                elif norm == "cents":
                    n = num(v)
                    if n is None:
                        return None
                    v = int((n * 100).to_integral_value())
                elif norm == "int":
                    n = num(v)
                    if n is None:
                        return None
                    v = int(n)
            except (ValueError, ArithmeticError):
                return None
            out[item["as"]] = v
        return digest(out)

    def _used(self, tool_name: str, field: str, window: int, scope: str, agent: str, now: float, exclude: str,
              shadow: bool = False) -> Decimal:
        total = Decimal(0)
        if shadow:                    # observe mode: everything the customer reported actually happened, so it all counts
            for o in self._kv.all(_NS_OBS).values():
                if o["tool"] != tool_name or o["id"] == exclude or (scope == "agent" and o["agent"] != agent):
                    continue
                at = o.get("occurred_at") or o["created_at"]
                if at < now - window or at > now:
                    continue
                found, v = get_path(o["params"], field)
                n = num(v) if found else None
                if n is not None:
                    total += n
            return total
        for a in self._kv.all(_NS_ACT).values():
            if a["tool"] != tool_name or a["id"] == exclude or a["status"] not in _COUNTED:
                continue
            if scope == "agent" and a["agent"] != agent:
                continue
            if a["created_at"] < now - window:
                continue
            found, v = get_path(a["params"], field)
            n = num(v) if found else None
            if n is not None:
                total += n
        return total

    # ───────────────────────── the decision (pure) ─────────────────────────
    def _decide(self, agent: str, permissions: set, tool_name: str, params: dict, now: float, exclude: str = "",
                shadow: bool = False) -> dict:
        pol = self.policy()
        tool = pol["tools"].get(tool_name)
        if tool is None:
            if pol.get("default_unknown_tool", "deny") == "pending":
                return {"decision": "pending", "risk": "high", "approvals_required": 1,
                        "reasons": [f"tool '{tool_name}' is not in the policy: a human decides"]}
            return {"decision": "deny", "risk": "high", "approvals_required": 0, "reasons": [f"tool '{tool_name}' is not in the policy"]}
        reasons: list[str] = []
        need = tool.get("permission")
        if need and need not in permissions:
            return {"decision": "deny", "risk": "high", "approvals_required": 0, "reasons": [f"agent lacks permission '{need}'"]}
        risk = tool.get("risk", "high")
        if risk == "high":
            reasons.append("tool is classified high risk")
        for i, r in enumerate(tool.get("deny", [])):
            res = eval_cond(r["when"], params)
            if res is True:
                return {"decision": "deny", "risk": "high", "approvals_required": 0, "reasons": [r.get("reason", f"deny rule {i} matched")]}
            if res is None:
                risk = "high"
                reasons.append(f"deny rule {i} could not be evaluated (missing or non-numeric field): escalated to a human")
        for i, r in enumerate(tool.get("escalate", [])):
            res = eval_cond(r["when"], params)
            if res is True or res is None:
                risk = "high"
                why = r.get("reason", f"escalation rule {i}")
                reasons.append(why if res else f"{why} (could not be evaluated: escalated)")
        for lim in tool.get("limits", []):
            found, v = get_path(params, lim["field"])
            n = num(v) if found else None
            if n is None:
                risk = "high"
                reasons.append(f"limit on '{lim['field']}' could not be checked (missing or non-numeric): escalated to a human")
                continue
            used = self._used(tool_name, lim["field"], PERIOD_SECONDS[lim["per"]], lim.get("scope", "tool"), agent, now, exclude, shadow)
            if used + n > num(lim["max"]):
                msg = f"limit exceeded: {lim['field']} {used + n} would pass {lim['max']} per {lim['per']}"
                if lim.get("on_exceed", "deny") == "deny":
                    return {"decision": "deny", "risk": "high", "approvals_required": 0, "reasons": [msg]}
                risk = "high"
                reasons.append(msg + " (escalated)")
        required = 0
        if risk == "high":
            ap = tool.get("approvals", {})
            required = int(ap.get("required", 1))
            for x in ap.get("extra", []):
                res = eval_cond(x["when"], params)
                if res is True or res is None:
                    required = max(required, int(x["required"]))
                    reasons.append(f"{x['required']} distinct approvers required" + ("" if res else " (condition could not be evaluated)"))
        return {"decision": "pending" if risk == "high" else "allow", "risk": risk, "reasons": reasons, "approvals_required": required}

    def _expire(self, a: dict) -> dict:
        if a["status"] == "PENDING_APPROVAL" and self._clock() > a["created_at"] + self._ttl:
            self._log("action.expired", {"id": a["id"], "tool": a["tool"], "policy_hash": self.policy_hash()})
            a["status"] = "EXPIRED"
            a.setdefault("history", []).append({"at": self._clock(), "event": "expired"})
            self._save(a)
        return a

    def _load(self, action_id: str) -> dict:
        a = self._kv.get(_NS_ACT, action_id)
        if a is None:
            raise OmniError(404, "no_such_action", action_id)
        return self._expire(a)

    # ───────────────────────── actions ─────────────────────────
    def propose(self, agent: str, tool: str, params: dict, *, permissions: Any = (), idempotency_key: Optional[str] = None,
                context: Optional[dict] = None) -> dict:
        if not agent or not isinstance(agent, str):
            raise OmniError(400, "agent_required")
        if not isinstance(params, dict):
            raise OmniError(400, "params_must_be_an_object")
        try:
            canon(params)
            import json
            json.dumps(params)
        except (TypeError, ValueError):
            raise OmniError(400, "params_not_json_serializable")
        perms = set(permissions or ())
        with self._lock:
            if idempotency_key:
                existing = self._kv.get(_NS_IDEM, f"{agent}:{idempotency_key}")
                if existing:
                    return self._view(self._load(existing["id"]))
            now = self._clock()
            dec = self._decide(agent, perms, tool, params, now)
            cfg = self._tool(tool) or {}
            ex = cfg.get("execution", {"mode": "agent"})
            a = {"id": self._next("act", 5), "tool": tool, "agent": agent, "agent_permissions": sorted(perms), "params": params,
                 "params_digest": digest(params), "context": context or {}, "risk": dec["risk"], "reasons": dec["reasons"],
                 "approvals_required": dec["approvals_required"], "approvals": [], "execution_mode": ex.get("mode", "agent"),
                 "reversibility": cfg.get("reversibility", "one_way_consequential"), "policy_hash": self.policy_hash(),
                 "created_at": now, "status": "", "effect_key": self._effect_key(cfg, params) if cfg else None,
                 "idempotency_key": idempotency_key, "history": []}
            denied = dec["decision"] == "deny"
            a["status"] = "DENIED" if denied else ("PENDING_APPROVAL" if dec["decision"] == "pending" else "APPROVED")
            # evidence first: if the ledger cannot take the record, the action is not created
            self._log("action.denied" if denied else "action.proposed",
                      {**self._base(a), "risk": a["risk"], "approvals_required": a["approvals_required"],
                       "reasons": a["reasons"][:6], "effect_key": a["effect_key"]})
            self._save(a)
            if idempotency_key:
                self._kv.put(_NS_IDEM, f"{agent}:{idempotency_key}", {"id": a["id"]})
            if a["status"] == "APPROVED" and a["execution_mode"] == "proxy":
                self._execute_proxy(a, approvers=[])
            return self._view(a)

    def approve(self, action_id: str, approver: str, comment: str = "", approver_groups: Any = ()) -> dict:
        if not approver or not isinstance(approver, str):
            raise OmniError(400, "approver_required")
        with self._lock:
            a = self._load(action_id)
            if a["status"] != "PENDING_APPROVAL":
                raise OmniError(409, "not_pending", a["status"])
            if approver == a["agent"]:
                raise OmniError(403, "agent_cannot_approve_its_own_action")
            if any(x["by"] == approver for x in a["approvals"]):
                raise OmniError(409, "already_approved_by_you")
            need_groups = ((self._tool(a["tool"]) or {}).get("approvals") or {}).get("groups") or []
            if need_groups and not set(need_groups) & set(approver_groups or ()):
                raise OmniError(403, "approver_not_in_required_group", "needs one of: " + ", ".join(need_groups))
            # re-evaluate under the CURRENT policy and CURRENT limits: an old pending request must not slip through
            dec = self._decide(a["agent"], set(a["agent_permissions"]), a["tool"], a["params"], self._clock(), exclude=a["id"])
            if dec["decision"] == "deny":
                self._log("action.denied", {**self._base(a), "reasons": dec["reasons"][:6], "on": "re-evaluation at approval"})
                a["status"], a["reasons"] = "DENIED", dec["reasons"]
                a["history"].append({"at": self._clock(), "event": "denied_on_reevaluation"})
                self._save(a)
                raise OmniError(409, "denied_on_reevaluation", "; ".join(dec["reasons"]))
            required = max(a["approvals_required"], dec["approvals_required"]) if dec["decision"] == "pending" else a["approvals_required"]
            n = len(a["approvals"]) + 1
            self._log("action.approved", {"id": a["id"], "tool": a["tool"], "by": approver, "n": n, "of": required,
                                          "groups": sorted(set(approver_groups or ())), "policy_hash": self.policy_hash(),
                                          "comment_digest": digest(comment) if comment else None})
            a["approvals_required"] = required
            a["approvals"].append({"by": approver, "at": self._clock(), "comment": str(comment)[:300]})
            if n >= required:
                a["status"] = "APPROVED"
                a["history"].append({"at": self._clock(), "event": "approved"})
                self._save(a)
                if a["execution_mode"] == "proxy":
                    self._execute_proxy(a, approvers=[x["by"] for x in a["approvals"]])
            else:
                self._save(a)
            return self._view(a)

    def reject(self, action_id: str, approver: str, reason: str = "") -> dict:
        if not approver:
            raise OmniError(400, "approver_required")
        with self._lock:
            a = self._load(action_id)
            if a["status"] != "PENDING_APPROVAL":
                raise OmniError(409, "not_pending", a["status"])
            self._log("action.rejected", {"id": a["id"], "tool": a["tool"], "by": approver, "policy_hash": self.policy_hash(),
                                          "reason_digest": digest(reason) if reason else None})
            a["status"] = "REJECTED"
            a["history"].append({"at": self._clock(), "event": "rejected", "by": approver, "reason": str(reason)[:300]})
            self._save(a)
            return self._view(a)

    def report(self, action_id: str, agent: str, ok: bool, response: Any = None, note: str = "", kind: str = "execution") -> dict:
        """Decision mode: the agent that proposed the action reports what happened (an attestation by the agent)."""
        if kind not in ("execution", "compensation"):
            raise OmniError(400, "kind_must_be_execution_or_compensation")
        with self._lock:
            a = self._load(action_id)
            if a["agent"] != agent:
                raise OmniError(403, "only_the_proposing_agent_may_report")
            if a["execution_mode"] != "agent":
                raise OmniError(409, "proxy_actions_are_executed_by_the_platform")
            approvers = [x["by"] for x in a["approvals"]]
            if kind == "execution":
                if a["status"] != "APPROVED":
                    raise OmniError(409, "not_approved_or_already_reported", a["status"])
                rd = digest(response) if response is not None else None
                if ok:
                    self._log("action.executed", {"id": a["id"], "tool": a["tool"], "approvers": approvers, "attestation": "agent_report",
                                                  "result_digest": rd, "effect_key": a["effect_key"], "policy_hash": a["policy_hash"]})
                else:
                    self._log("action.failed", {"id": a["id"], "tool": a["tool"], "approvers": approvers, "attestation": "agent_report",
                                                "error": "agent_reported_failure", "policy_hash": a["policy_hash"]})
                a["status"] = "REPORTED_SUCCESS" if ok else "REPORTED_FAILURE"
                a["response_digest"], a["report_note"] = rd, str(note)[:300]
                a["history"].append({"at": self._clock(), "event": "reported_success" if ok else "reported_failure"})
                self._save(a)
                return self._view(a)
            if a["reversibility"] in IRREVERSIBLE:
                raise OmniError(409, "tool_is_declared_irreversible")
            if a["status"] != "REPORTED_SUCCESS":
                raise OmniError(409, "nothing_to_compensate", a["status"])
            if ok:
                self._log("action.compensated", {"id": a["id"], "tool": a["tool"], "by": agent, "attestation": "agent_report",
                                                 "policy_hash": a["policy_hash"]})
                a["status"] = "COMPENSATED"
                a["history"].append({"at": self._clock(), "event": "compensated_by_agent_report"})
                self._save(a)
            return self._view(a)

    def compensate(self, action_id: str, actor: str) -> dict:
        """Proxy mode: undo through the configured upstream compensation call."""
        with self._lock:
            a = self._load(action_id)
            comp = ((self._tool(a["tool"]) or {}).get("execution") or {}).get("compensate")
            if a["execution_mode"] != "proxy" or not comp:
                raise OmniError(409, "no_compensation_configured")
            if a["reversibility"] in IRREVERSIBLE:
                raise OmniError(409, "tool_is_declared_irreversible")
            if a["status"] != "EXECUTED":
                raise OmniError(409, "nothing_to_compensate", a["status"])
            body = None
            if comp.get("body_from_response"):
                resp = a.get("response")
                body = {}
                for k, path in comp["body_from_response"].items():
                    found, v = get_path(resp if isinstance(resp, dict) else {}, path)
                    if not found:
                        raise OmniError(502, "compensation_input_missing", path)
                    body[k] = v
            self._log("action.compensating", {"id": a["id"], "tool": a["tool"], "by": actor, "policy_hash": a["policy_hash"]})
            status, _ = self._fwd.call(comp, body)
            if not 200 <= status < 300:
                a["history"].append({"at": self._clock(), "event": "compensation_failed", "http_status": status})
                self._save(a)
                self._log("action.failed", {"id": a["id"], "tool": a["tool"], "error": f"compensation_http_{status}",
                                            "attestation": "gate_executed", "policy_hash": a["policy_hash"]})
                raise OmniError(502, "compensation_failed", f"upstream returned {status}")
            self._log("action.compensated", {"id": a["id"], "tool": a["tool"], "by": actor, "attestation": "gate_executed",
                                             "policy_hash": a["policy_hash"]})
            a["status"] = "COMPENSATED"
            a["history"].append({"at": self._clock(), "event": "compensated", "by": actor})
            self._save(a)
            return self._view(a)

    def _execute_proxy(self, a: dict, approvers: list[str]) -> None:
        """Called with the lock held. APPROVED -> EXECUTING -> EXECUTED / FAILED, at most once."""
        cfg = (self._tool(a["tool"]) or {}).get("execution", {})
        self._log("action.executing", {"id": a["id"], "tool": a["tool"], "approvers": approvers, "policy_hash": a["policy_hash"]})
        a["status"] = "EXECUTING"
        self._save(a)
        try:
            status, resp = self._fwd.call(cfg, a["params"] if cfg.get("body", "params") == "params" else None)
        except OmniError as e:
            self._log("action.failed", {"id": a["id"], "tool": a["tool"], "approvers": approvers, "error": e.code,
                                        "attestation": "gate_executed", "policy_hash": a["policy_hash"]})
            a["status"] = "FAILED"
            a["history"].append({"at": self._clock(), "event": "execution_failed", "error": e.code})
            self._save(a)
            return
        if 200 <= status < 300:
            rd = digest(resp)
            self._log("action.executed", {"id": a["id"], "tool": a["tool"], "approvers": approvers, "attestation": "gate_executed",
                                          "result_digest": rd, "http_status": status, "effect_key": a["effect_key"],
                                          "policy_hash": a["policy_hash"]})
            a["status"], a["response"], a["response_digest"] = "EXECUTED", resp, rd
            a["history"].append({"at": self._clock(), "event": "executed", "http_status": status})
        else:
            self._log("action.failed", {"id": a["id"], "tool": a["tool"], "approvers": approvers, "error": f"upstream_http_{status}",
                                        "attestation": "gate_executed", "policy_hash": a["policy_hash"]})
            a["status"], a["response"] = "FAILED", resp
            a["history"].append({"at": self._clock(), "event": "execution_failed", "http_status": status})
        self._save(a)

    # ───────────────────────── observe mode (shadow) ─────────────────────────
    def observe(self, agent: str, permissions: Any, events: list) -> list[dict]:
        """Record what the customer's own system says its agent did (or is doing), WITHOUT gating anything.

        Each event is judged against the current rules as a dry run ("would this have needed approval? been refused?"),
        written to the ledger as `action.observed` (identifiers, digests and the reasons for the verdict; no raw parameters) and kept for the shadow report. Nothing
        is blocked, nothing is executed, no credentials are involved. What the agent never reports is not seen."""
        if not isinstance(events, list) or not events:
            raise OmniError(400, "events_required")
        if len(events) > MAX_OBSERVE_BATCH:
            raise OmniError(413, "too_many_events", f"at most {MAX_OBSERVE_BATCH} per call")
        perms = set(permissions or ())
        with self._lock:
            checked = [self._observe_check(ev) for ev in events]        # all-or-nothing: nothing is recorded if one event is malformed
            return [self._observe_one(agent, perms, *c) for c in checked]

    def _observe_check(self, ev: Any) -> tuple:
        import json
        if not isinstance(ev, dict):
            raise OmniError(400, "event_must_be_an_object")
        tool, params = ev.get("tool"), ev.get("params")
        if params is None:
            params = {}
        if not isinstance(tool, str) or not 1 <= len(tool) <= 80:
            raise OmniError(422, "invalid_tool")
        if not isinstance(params, dict):
            raise OmniError(400, "params_must_be_an_object")
        try:
            canon(params)
            too_big = len(json.dumps(params)) > 20_000
        except (TypeError, ValueError):
            raise OmniError(400, "params_not_json_serializable")
        if too_big:
            raise OmniError(413, "params_too_large")
        ext = ev.get("external_id")
        if ext is not None and (not isinstance(ext, str) or len(ext) > 120):
            raise OmniError(422, "invalid_external_id")
        occurred = ev.get("occurred_at")
        if occurred is not None:
            if isinstance(occurred, bool) or not isinstance(occurred, (int, float)) or not 1_577_836_800 <= occurred <= self._clock() + 86400:
                raise OmniError(422, "invalid_occurred_at", "seconds since 1970, between 2020-01-01 and tomorrow")
            occurred = float(occurred)
        return tool, params, ext or None, occurred

    def _observe_one(self, agent: str, perms: set, tool: str, params: dict, ext: Optional[str], occurred: Optional[float]) -> dict:
        if ext:
            seen = self._kv.get(_NS_OBS_IDEM, f"{agent}:{ext}")
            if seen:
                return self._obs_view(self._kv.get(_NS_OBS, seen["id"]))
        now = occurred if occurred is not None else self._clock()
        oid = self._next("obs", 5)
        dec = self._decide(agent, perms, tool, params, now, exclude=oid, shadow=True)
        rec = {"id": oid, "tool": tool, "agent": agent, "params": params, "params_digest": digest(params), "decision": dec["decision"],
               "risk": dec["risk"], "approvals_required": dec["approvals_required"], "reasons": dec["reasons"],
               "policy_hash": self.policy_hash(), "created_at": self._clock(), "occurred_at": occurred, "external_id": ext}
        self._log("action.observed", {"id": oid, "tool": tool, "agent": agent, "params_digest": rec["params_digest"], "decision": rec["decision"],
                                      "risk": rec["risk"], "approvals_required": rec["approvals_required"], "reasons": rec["reasons"][:6],
                                      "policy_hash": rec["policy_hash"], "claimed_at": occurred,
                                      "external_digest": digest(ext) if ext else None})
        self._kv.put(_NS_OBS, oid, rec)
        if ext:
            self._kv.put(_NS_OBS_IDEM, f"{agent}:{ext}", {"id": oid})
        return self._obs_view(rec)

    @staticmethod
    def _obs_view(o: dict) -> dict:
        import json
        return json.loads(json.dumps(o))

    def observations(self, decision: Optional[str] = None, agent: Optional[str] = None, limit: int = 100,
                     since: Optional[float] = None, until: Optional[float] = None) -> list[dict]:
        with self._lock:
            rows = list(self._kv.all(_NS_OBS).values())
        out = []
        for o in rows:
            at = o.get("occurred_at") or o["created_at"]
            if ((decision and o["decision"] != decision) or (agent and o["agent"] != agent)
                    or (since is not None and at < since) or (until is not None and at > until)):
                continue
            out.append(o)
        out.sort(key=lambda o: o.get("occurred_at") or o["created_at"], reverse=True)
        return [self._obs_view(o) for o in out[:max(1, min(limit, 5000))]]

    # ───────────────────────── reading ─────────────────────────
    def get(self, action_id: str) -> dict:
        with self._lock:
            return self._view(self._load(action_id))

    def list(self, status: Optional[str] = None, agent: Optional[str] = None, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = [self._expire(a) for a in self._kv.all(_NS_ACT).values()]
        rows = [a for a in rows if (status is None or a["status"] == status) and (agent is None or a["agent"] == agent)]
        rows.sort(key=lambda a: a["created_at"], reverse=True)
        return [self._view(a) for a in rows[:max(1, min(limit, 500))]]

    def counts(self) -> dict:
        out: dict[str, int] = {}
        with self._lock:
            for a in self._kv.all(_NS_ACT).values():
                st = self._expire(a)["status"]
                out[st] = out.get(st, 0) + 1
        return out

    # ───────────────────────── admin changes (four-eyes on the system itself) ─────────────────────────
    def propose_change(self, kind: str, payload: dict, by: str) -> dict:
        """An admin proposes a change. It is applied at once if admin_quorum is 1, otherwise when admin_quorum-1 OTHER
        admins have approved. Creating a key returns the key HERE, once, to the proposer; it stays inactive until applied."""
        if kind not in CHANGE_KINDS:
            raise OmniError(400, "unknown_change_kind", f"one of {list(CHANGE_KINDS)}")
        if not isinstance(payload, dict):
            raise OmniError(400, "payload_must_be_an_object")
        with self._lock:
            secret_key: Optional[str] = None
            stored: dict
            if kind == "policy.replace":
                doc = payload.get("doc")
                errs = validate_policy(doc, self._allow_local)
                if errs:
                    raise OmniError(422, "invalid_policy", "; ".join(errs))
                stored = {"doc": doc}
                summary = {"policy_hash": policy_hash(doc)}
            elif kind == "principal.create":
                try:
                    rec, secret_key = self._identity.prepare(str(payload.get("name", "")), str(payload.get("role", "")),
                                                             payload.get("permissions"), payload.get("groups"))
                except ValueError as e:
                    raise OmniError(422, "invalid_principal", str(e))
                existing = self._identity.get(rec["name"])
                if existing and existing["role"] != rec["role"]:
                    raise OmniError(409, "name_in_use_with_another_role", "revoke it first; a name keeps its role")
                stored = {"record": rec}
                summary = {"name": rec["name"], "role": rec["role"], "groups": rec["groups"], "permissions": rec["permissions"],
                           "replaces_existing_key": bool(existing)}
            else:
                name = str(payload.get("name", ""))
                target = self._identity.get(name)
                if target is None:
                    raise OmniError(404, "no_such_principal", name)
                if name == by:
                    raise OmniError(400, "cannot_revoke_yourself")
                if target["role"] == "admin" and self._identity.counts()["admin"] - 1 < self.admin_quorum:
                    raise OmniError(409, "would_leave_too_few_admins", f"quorum is {self.admin_quorum}")
                stored = {"name": name}
                summary = {"name": name, "role": target["role"]}
            c = {"id": self._next("chg", 4), "kind": kind, "by": by, "payload": stored, "approvals": [], "status": "PENDING",
                 "quorum": self.admin_quorum, "created_at": self._clock(), "summary": summary}
            self._log("change.proposed", {"id": c["id"], "kind": kind, "by": by, "quorum": self.admin_quorum, "summary": summary})
            self._kv.put(_NS_CHG, c["id"], c)
            if self.admin_quorum == 1:
                self._apply_change(c)
            out = self._change_view(c)
            if secret_key:
                out["key"] = secret_key
                out["note"] = "Shown once. The key stays inactive until the change is applied."
            return out

    def approve_change(self, change_id: str, by: str) -> dict:
        with self._lock:
            c = self._kv.get(_NS_CHG, change_id)
            if c is None:
                raise OmniError(404, "no_such_change", change_id)
            if c["status"] != "PENDING":
                raise OmniError(409, "change_not_pending", c["status"])
            if by == c["by"]:
                raise OmniError(403, "proposer_cannot_approve_own_change", "another admin must approve")
            if any(x["by"] == by for x in c["approvals"]):
                raise OmniError(409, "already_approved_by_you")
            self._log("change.approved", {"id": c["id"], "kind": c["kind"], "by": by, "n": len(c["approvals"]) + 1,
                                          "of": c["quorum"] - 1})
            c["approvals"].append({"by": by, "at": self._clock()})
            self._kv.put(_NS_CHG, c["id"], c)
            if len(c["approvals"]) >= c["quorum"] - 1:
                self._apply_change(c)
            return self._change_view(c)

    def reject_change(self, change_id: str, by: str) -> dict:
        with self._lock:
            c = self._kv.get(_NS_CHG, change_id)
            if c is None:
                raise OmniError(404, "no_such_change", change_id)
            if c["status"] != "PENDING":
                raise OmniError(409, "change_not_pending", c["status"])
            self._log("change.rejected", {"id": c["id"], "kind": c["kind"], "by": by})
            c["status"] = "REJECTED"
            self._kv.put(_NS_CHG, c["id"], c)
            return self._change_view(c)

    def _apply_change(self, c: dict) -> None:
        kind, payload = c["kind"], c["payload"]
        if kind == "policy.replace":
            self._activate_policy(payload["doc"], c["by"], via=c["id"])
        elif kind == "principal.create":
            rec = payload["record"]
            replaced = self._identity.get(rec["name"]) is not None
            self._identity.activate(rec)
            self._log("principal.changed", {"id": c["id"], "change": "rotated" if replaced else "created", "name": rec["name"], "role": rec["role"],
                                            "groups": rec["groups"], "permissions": rec["permissions"], "by": c["by"],
                                            "approvers": [x["by"] for x in c["approvals"]]})
        else:
            self._identity.revoke(payload["name"])
            self._log("principal.changed", {"id": c["id"], "change": "revoked", "name": payload["name"], "by": c["by"],
                                            "approvers": [x["by"] for x in c["approvals"]]})
        self._log("change.applied", {"id": c["id"], "kind": kind})
        c["status"] = "APPLIED"
        c["applied_at"] = self._clock()
        self._kv.put(_NS_CHG, c["id"], c)

    @staticmethod
    def _change_view(c: dict) -> dict:
        return {"id": c["id"], "kind": c["kind"], "by": c["by"], "status": c["status"], "quorum": c["quorum"],
                "approvals": c["approvals"], "summary": c["summary"], "created_at": c["created_at"]}

    def changes(self, status: Optional[str] = None) -> list[dict]:
        rows = [self._change_view(c) for c in self._kv.all(_NS_CHG).values()]
        return [c for c in rows if status is None or c["status"] == status]
