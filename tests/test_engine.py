import copy
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import _util
from _util import Env, FakeClock, POLICY
from omnios.errors import OmniError

AGENT = "ops-agent"
PERMS = ["finance:pay", "refund:issue", "data:delete", "notes:write"]


def propose(env, tool, params, **kw):
    return env.rt.engine.propose(AGENT, tool, params, permissions=PERMS, **kw)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.eng = self.env.rt.engine

    def tearDown(self):
        self.env.close()

    def types(self):
        return [r["type"] for r in self.env.rt.ledger.records(0, 1000)]

    # ---------- decisions ----------
    def test_low_risk_is_allowed_and_logged(self):
        a = propose(self.env, "note.add", {"text": "hi"})
        self.assertEqual(a["status"], "APPROVED")
        self.assertIn("action.proposed", self.types())

    def test_unknown_tool_and_missing_permission_are_denied(self):
        self.assertEqual(propose(self.env, "wire.everything", {})["status"], "DENIED")
        a = self.eng.propose(AGENT, "payments.send", {"amount_eur": 5, "vendor": "x"}, permissions=[])
        self.assertEqual(a["status"], "DENIED")
        self.assertIn("action.denied", self.types())

    def test_deny_rule_and_limit(self):
        self.assertEqual(propose(self.env, "payments.send", {"amount_eur": 10001, "vendor": "v"})["status"], "DENIED")
        a = propose(self.env, "payments.send", {"amount_eur": 600, "vendor": "v"})
        self.eng.approve(a["id"], "alice")
        b = propose(self.env, "payments.send", {"amount_eur": 9000, "vendor": "w"})
        self.assertEqual(b["status"], "PENDING_APPROVAL")
        c = propose(self.env, "payments.send", {"amount_eur": 6000, "vendor": "w"})
        self.assertEqual(c["status"], "PENDING_APPROVAL")  # pending requests do not consume the limit...
        self.eng.approve(b["id"], "alice")
        self.eng.approve(b["id"], "bob")                    # ...approved ones do: 600 + 9000 = 9600
        with self.assertRaises(OmniError) as cm:
            self.eng.approve(c["id"], "alice")              # 9600 + 6000 > 15000, caught at approval
        self.assertEqual(cm.exception.code, "denied_on_reevaluation")
        self.assertEqual(propose(self.env, "payments.send", {"amount_eur": 6000, "vendor": "z"})["status"], "DENIED")

    def test_missing_or_non_numeric_amount_escalates_never_allows(self):
        for params in ({"vendor": "x"}, {"vendor": "x", "amount_eur": "lots"}, {"vendor": "x", "amount_eur": None}):
            a = propose(self.env, "payments.send", params)
            self.assertEqual(a["status"], "PENDING_APPROVAL", params)
            self.assertTrue(a["approvals_required"] >= 2, params)  # extra rule cannot be evaluated -> strictest
        a = propose(self.env, "refunds.issue", {"customer": "c"})
        self.assertEqual(a["status"], "PENDING_APPROVAL")

    # ---------- approvals ----------
    def test_two_distinct_approvers_for_large_payment(self):
        a = propose(self.env, "payments.send", {"amount_eur": 4000, "vendor": "Acme"})
        self.assertEqual((a["status"], a["approvals_required"]), ("PENDING_APPROVAL", 2))
        a = self.eng.approve(a["id"], "alice")
        self.assertEqual(a["status"], "PENDING_APPROVAL")
        with self.assertRaises(OmniError) as cm:
            self.eng.approve(a["id"], "alice")
        self.assertEqual(cm.exception.code, "already_approved_by_you")
        a = self.eng.approve(a["id"], "bob")
        self.assertEqual(a["status"], "APPROVED")

    def test_agent_cannot_approve_its_own_action(self):
        a = propose(self.env, "payments.send", {"amount_eur": 50, "vendor": "x"})
        with self.assertRaises(OmniError) as cm:
            self.eng.approve(a["id"], AGENT)
        self.assertEqual(cm.exception.status, 403)

    def test_required_group(self):
        a = propose(self.env, "data.delete", {"subject": "u1"})
        with self.assertRaises(OmniError) as cm:
            self.eng.approve(a["id"], "alice", approver_groups=[])
        self.assertEqual(cm.exception.code, "approver_not_in_required_group")
        self.eng.approve(a["id"], "carol", approver_groups=["privacy"])
        a = self.eng.approve(a["id"], "dave", approver_groups=["privacy"])
        self.assertEqual(a["status"], "APPROVED")

    def test_reject_and_expiry(self):
        a = propose(self.env, "payments.send", {"amount_eur": 50, "vendor": "x"})
        self.assertEqual(self.eng.reject(a["id"], "bob", "no")["status"], "REJECTED")
        with self.assertRaises(OmniError):
            self.eng.approve(a["id"], "alice")
        b = propose(self.env, "payments.send", {"amount_eur": 60, "vendor": "x"})
        self.env.clock.advance(86400 + 5)
        self.assertEqual(self.eng.get(b["id"])["status"], "EXPIRED")
        with self.assertRaises(OmniError):
            self.eng.approve(b["id"], "alice")
        self.assertIn("action.expired", self.types())

    def test_reevaluation_at_approval_uses_current_policy(self):
        a = propose(self.env, "payments.send", {"amount_eur": 500, "vendor": "x"})
        tight = copy.deepcopy(POLICY)
        tight["tools"]["payments.send"]["deny"] = [{"when": {"field": "amount_eur", "op": ">", "value": 100}, "reason": "tightened"}]
        self.eng.propose_change("policy.replace", {"doc": tight}, "admin-1")
        self.eng.approve_change(self.eng.changes("PENDING")[0]["id"], "admin-2")
        with self.assertRaises(OmniError) as cm:
            self.eng.approve(a["id"], "alice")
        self.assertEqual(cm.exception.code, "denied_on_reevaluation")
        self.assertEqual(self.eng.get(a["id"])["status"], "DENIED")

    def test_idempotency(self):
        a = propose(self.env, "note.add", {"text": "x"}, idempotency_key="k1")
        b = propose(self.env, "note.add", {"text": "x"}, idempotency_key="k1")
        self.assertEqual(a["id"], b["id"])
        self.assertEqual(self.types().count("action.proposed"), 1)

    # ---------- decision mode: the agent reports ----------
    def test_report_and_compensation_rules(self):
        a = propose(self.env, "payments.send", {"amount_eur": 50, "vendor": "x"})
        with self.assertRaises(OmniError):
            self.eng.report(a["id"], AGENT, True)  # not approved yet
        self.eng.approve(a["id"], "alice")
        with self.assertRaises(OmniError):
            self.eng.report(a["id"], "someone-else", True)
        r = self.eng.report(a["id"], AGENT, True, {"tx": 1})
        self.assertEqual(r["status"], "REPORTED_SUCCESS")
        self.assertEqual(self.eng.report(a["id"], AGENT, True, kind="compensation")["status"], "COMPENSATED")  # recoverable
        d = propose(self.env, "data.delete", {"subject": "u1"})
        self.eng.approve(d["id"], "carol", approver_groups=["privacy"])
        self.eng.approve(d["id"], "dave", approver_groups=["privacy"])
        self.eng.report(d["id"], AGENT, True)
        with self.assertRaises(OmniError) as cm:
            self.eng.report(d["id"], AGENT, True, kind="compensation")
        self.assertEqual(cm.exception.code, "tool_is_declared_irreversible")  # one_way_terminal
        n = propose(self.env, "note.add", {"text": "x"})
        self.eng.report(n["id"], AGENT, True)
        self.assertEqual(self.eng.report(n["id"], AGENT, True, kind="compensation")["status"], "COMPENSATED")

    def test_ledger_failure_means_no_action(self):
        class Boom:
            def append(self, *a, **k):
                raise RuntimeError("disk full")

        real = self.eng.ledger
        self.eng.ledger = Boom()
        try:
            with self.assertRaises(Exception):
                propose(self.env, "note.add", {"text": "x"})
        finally:
            self.eng.ledger = real
        self.assertEqual(self.eng.list(), [])

    # ---------- four-eyes on the system itself ----------
    def test_policy_change_needs_a_second_admin(self):
        new = copy.deepcopy(POLICY)
        new["tools"]["note.add"]["risk"] = "high"
        c = self.eng.propose_change("policy.replace", {"doc": new}, "admin-1")
        self.assertEqual(c["status"], "PENDING")
        self.assertEqual(self.eng.policy()["tools"]["note.add"]["risk"], "low")
        with self.assertRaises(OmniError) as cm:
            self.eng.approve_change(c["id"], "admin-1")
        self.assertEqual(cm.exception.code, "proposer_cannot_approve_own_change")
        self.assertEqual(self.eng.approve_change(c["id"], "admin-2")["status"], "APPLIED")
        self.assertEqual(self.eng.policy()["tools"]["note.add"]["risk"], "high")
        self.assertIn("policy.activated", self.types())

    def test_invalid_policy_is_refused(self):
        with self.assertRaises(OmniError) as cm:
            self.eng.propose_change("policy.replace", {"doc": {"version": 1, "tools": {"x": {}}}}, "admin-1")
        self.assertEqual(cm.exception.status, 422)

    def test_new_key_is_inactive_until_applied(self):
        c = self.eng.propose_change("principal.create", {"name": "erin", "role": "approver"}, "admin-1")
        key = c["key"]
        self.assertIsNone(self.env.rt.identity.authenticate(key))
        self.eng.approve_change(c["id"], "admin-2")
        p = self.env.rt.identity.authenticate(key)
        self.assertEqual((p.name, p.role), ("erin", "approver"))

    def test_rotating_a_key_replaces_it_and_a_name_keeps_its_role(self):
        old_key = self.env.key["bob"]
        with self.assertRaises(OmniError) as cm:
            self.eng.propose_change("principal.create", {"name": "bob", "role": "admin"}, "admin-1")
        self.assertEqual(cm.exception.code, "name_in_use_with_another_role")
        c = self.eng.propose_change("principal.create", {"name": "bob", "role": "approver"}, "admin-1")
        self.assertTrue(c["summary"]["replaces_existing_key"])
        self.assertIsNotNone(self.env.rt.identity.authenticate(old_key))     # still the old key until applied
        self.eng.approve_change(c["id"], "admin-2")
        self.assertIsNone(self.env.rt.identity.authenticate(old_key))
        self.assertEqual(self.env.rt.identity.authenticate(c["key"]).name, "bob")
        last = [r for r in self.env.rt.ledger.records(0, 1000) if r["type"] == "principal.changed"][-1]
        self.assertEqual(json.loads(last["body"])["data"]["change"], "rotated")

    def test_lockout_protection(self):
        with self.assertRaises(OmniError) as cm:
            self.eng.propose_change("principal.revoke", {"name": "admin-1"}, "admin-1")
        self.assertEqual(cm.exception.code, "cannot_revoke_yourself")
        with self.assertRaises(OmniError) as cm:
            self.eng.propose_change("principal.revoke", {"name": "admin-2"}, "admin-1")
        self.assertEqual(cm.exception.code, "would_leave_too_few_admins")
        c = self.eng.propose_change("principal.revoke", {"name": "bob"}, "admin-1")
        self.eng.approve_change(c["id"], "admin-2")
        self.assertIsNone(self.env.rt.identity.authenticate(self.env.key["bob"]))

    def test_pilot_profile_applies_at_once(self):
        e2 = Env(profile="pilot")
        try:
            c = e2.rt.engine.propose_change("principal.create", {"name": "zed", "role": "auditor"}, "admin-1")
            self.assertEqual(c["status"], "APPLIED")
        finally:
            e2.close()

    def test_ledger_stays_valid_after_everything(self):
        a = propose(self.env, "payments.send", {"amount_eur": 4000, "vendor": "Acme"})
        self.eng.approve(a["id"], "alice")
        self.eng.approve(a["id"], "bob")
        self.eng.report(a["id"], AGENT, True)
        self.assertTrue(self.env.rt.ledger.verify_integrity()["ok"])


class _Upstream(BaseHTTPRequestHandler):
    calls = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        _Upstream.calls.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
        code = 500 if self.path == "/boom" else 200
        out = json.dumps({"ok": code == 200, "payment_id": "p-1"}).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


class ProxyTests(unittest.TestCase):
    def setUp(self):
        _Upstream.calls = []
        self.srv = HTTPServer(("127.0.0.1", 0), _Upstream)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        import tempfile
        from omnios.tenant import TenantRegistry
        self.dir = tempfile.mkdtemp()
        self.reg = TenantRegistry(self.dir)
        pol = {"version": 1, "tools": {
            "pay": {"permission": "p", "reversibility": "one_way_consequential", "risk": "high",
                    "approvals": {"required": 2},
                    "execution": {"mode": "proxy", "url": f"http://127.0.0.1:{self.port}/pay",
                                  "headers": {"Authorization": "Bearer ${SECRET:BANK}"}}},
            "bad": {"permission": "p", "reversibility": "one_way_consequential", "risk": "high",
                    "execution": {"mode": "proxy", "url": f"http://127.0.0.1:{self.port}/boom"}},
            "undo": {"permission": "p", "reversibility": "two_way", "risk": "high",
                     "execution": {"mode": "proxy", "url": f"http://127.0.0.1:{self.port}/do",
                                   "compensate": {"url": f"http://127.0.0.1:{self.port}/undo", "body_from_response": {"payment_id": "payment_id"}}}}}}
        self.rt, _ = self.reg.create("pxy", "Proxy Co", policy=pol, profile="pilot", approvers=["a1", "a2"],
                                     agents=[{"name": "ag", "permissions": ["p"]}], allow_private_upstreams=True)
        (self.rt.dir / "secrets.json").write_text(json.dumps({"BANK": "sekret-123"}))
        self.eng = self.rt.engine

    def tearDown(self):
        self.srv.shutdown()
        self.reg.close()

    def test_proxy_executes_only_after_quorum_with_the_tenants_secret(self):
        a = self.eng.propose("ag", "pay", {"amount": 5}, permissions=["p"])
        self.assertEqual(a["status"], "PENDING_APPROVAL")
        self.assertEqual(_Upstream.calls, [])
        self.eng.approve(a["id"], "a1")
        self.assertEqual(_Upstream.calls, [])
        a = self.eng.approve(a["id"], "a2")
        self.assertEqual(a["status"], "EXECUTED")
        self.assertEqual(len(_Upstream.calls), 1)
        self.assertEqual(_Upstream.calls[0]["auth"], "Bearer sekret-123")
        self.assertEqual(_Upstream.calls[0]["body"], {"amount": 5})
        types = [r["type"] for r in self.rt.ledger.records(0, 100)]
        self.assertLess(types.index("action.executing"), types.index("action.executed"))
        self.assertNotIn("sekret-123", json.dumps(self.rt.ledger.records(0, 100)))

    def test_upstream_error_is_a_failed_action(self):
        a = self.eng.propose("ag", "bad", {"x": 1}, permissions=["p"])
        a = self.eng.approve(a["id"], "a1")
        self.assertEqual(a["status"], "FAILED")

    def test_missing_secret_fails_closed(self):
        (self.rt.dir / "secrets.json").write_text("{}")
        a = self.eng.propose("ag", "pay", {"amount": 5}, permissions=["p"])
        self.eng.approve(a["id"], "a1")
        a = self.eng.approve(a["id"], "a2")
        self.assertEqual(a["status"], "FAILED")
        self.assertEqual(_Upstream.calls, [])

    def test_compensation_uses_response_fields(self):
        a = self.eng.propose("ag", "undo", {"x": 1}, permissions=["p"])
        a = self.eng.approve(a["id"], "a1")
        self.assertEqual(a["status"], "EXECUTED")
        a = self.eng.compensate(a["id"], "a1")
        self.assertEqual(a["status"], "COMPENSATED")
        self.assertEqual(_Upstream.calls[-1]["path"], "/undo")
        self.assertEqual(_Upstream.calls[-1]["body"], {"payment_id": "p-1"})

    def test_private_upstream_refused_when_not_allowed(self):
        from omnios.forwarder import Forwarder
        with self.assertRaises(OmniError) as cm:
            Forwarder(lambda n: None).call({"url": f"http://127.0.0.1:{self.port}/pay"}, {})
        self.assertEqual(cm.exception.code, "upstream_address_not_allowed")


if __name__ == "__main__":
    unittest.main()
