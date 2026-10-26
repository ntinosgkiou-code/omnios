"""Observe mode: the customer's system reports what its agent does; every event is judged as a dry run, nothing is gated."""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
import zipfile

import _util
from _util import POLICY, Env
from fastapi.testclient import TestClient
from omnios import cli, verifier
from omnios.api import create_app
from omnios.errors import OmniError
from omnios.observe import render_html, summarize

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sdk"))
import omnios_sdk  # noqa: E402

PERMS = ["finance:pay", "refund:issue", "notes:write"]          # no data:delete on purpose
T0 = 1_760_000_000.0


class ObserveEngineTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.eng = self.env.rt.engine

    def tearDown(self):
        self.env.close()

    def obs(self, *events, perms=PERMS):
        return self.eng.observe("ops-agent", perms, list(events))

    def test_three_verdicts_and_nothing_is_gated(self):
        out = self.obs({"tool": "note.add", "params": {"x": 1}},
                       {"tool": "payments.send", "params": {"amount_eur": 4000, "vendor": "V"}},
                       {"tool": "payments.send", "params": {"amount_eur": 20000, "vendor": "V"}})
        self.assertEqual([o["decision"] for o in out], ["allow", "pending", "deny"])
        self.assertEqual(out[1]["approvals_required"], 2)
        self.assertTrue(all(o["id"].startswith("obs-") for o in out))
        # nothing entered the real action flow
        self.assertEqual(self.eng.list(), [])
        self.assertEqual(self.eng.counts(), {})

    def test_ledger_record_has_digests_not_values(self):
        o = self.obs({"tool": "payments.send", "params": {"amount_eur": 4000, "vendor": "Secret-Vendor-9921"}, "external_id": "inv-77"})[0]
        recs = self.env.rt.ledger.by_ref(o["id"])
        self.assertEqual([r["type"] for r in recs], ["action.observed"])
        text = json.dumps(recs)
        self.assertNotIn("Secret-Vendor-9921", text)
        self.assertNotIn("inv-77", text)
        data = json.loads(recs[0]["body"])["data"]
        self.assertEqual(data["params_digest"], o["params_digest"])
        self.assertEqual(data["decision"], "pending")

    def test_missing_permission_and_unknown_tool(self):
        o = self.obs({"tool": "data.delete", "params": {"subject": "u1"}}, {"tool": "calendar.invite", "params": {}})
        self.assertEqual([x["decision"] for x in o], ["deny", "deny"])
        self.assertIn("lacks permission", o[0]["reasons"][0])
        self.assertIn("is not in the policy", o[1]["reasons"][0])

    def test_unreadable_amount_goes_to_a_human(self):
        o = self.obs({"tool": "payments.send", "params": {"amount_eur": "1_000", "vendor": "V"}},
                     {"tool": "payments.send", "params": {"vendor": "V"}})
        self.assertEqual([x["decision"] for x in o], ["pending", "pending"])
        self.assertTrue(any("could not be" in r for r in o[0]["reasons"]))

    def test_shadow_limit_counts_reported_events_in_their_own_window(self):
        day = 86400
        self.env.clock.advance(5 * day)          # "now" must be later than the claimed times below
        # three payments of 6000 on the same (claimed) day: 6000 -> 12000 -> 18000 passes the 15000/day limit
        a = self.obs({"tool": "payments.send", "params": {"amount_eur": 6000, "vendor": "V"}, "occurred_at": T0})[0]
        b = self.obs({"tool": "payments.send", "params": {"amount_eur": 6000, "vendor": "V"}, "occurred_at": T0 + 600})[0]
        c = self.obs({"tool": "payments.send", "params": {"amount_eur": 6000, "vendor": "V"}, "occurred_at": T0 + 1200})[0]
        self.assertEqual((a["decision"], b["decision"], c["decision"]), ("pending", "pending", "deny"))
        self.assertIn("limit exceeded", c["reasons"][0])
        # the same amount two days later is a fresh window
        d = self.obs({"tool": "payments.send", "params": {"amount_eur": 6000, "vendor": "V"}, "occurred_at": T0 + 2 * day})[0]
        self.assertEqual(d["decision"], "pending")

    def test_real_limits_are_not_polluted_by_observations(self):
        for i in range(3):
            self.obs({"tool": "payments.send", "params": {"amount_eur": 9000, "vendor": "V"}, "occurred_at": T0 - 100 + i})
        r = self.eng.propose("ops-agent", "payments.send", {"amount_eur": 9000, "vendor": "V"}, permissions=PERMS)
        self.assertEqual(r["status"], "PENDING_APPROVAL")                     # not denied by the 27000 that was only observed

    def test_idempotent_by_external_id(self):
        ev = {"tool": "payments.send", "params": {"amount_eur": 4000, "vendor": "V"}, "external_id": "inv-1"}
        a = self.obs(ev)[0]
        b = self.obs(ev)[0]
        self.assertEqual(a["id"], b["id"])
        self.assertEqual(len(self.eng.observations()), 1)
        self.assertEqual(len(self.env.rt.ledger.by_ref(a["id"])), 1)

    def test_whole_batch_is_rejected_if_one_event_is_bad(self):
        size = self.env.rt.ledger.size()
        with self.assertRaises(OmniError) as cm:
            self.obs({"tool": "note.add", "params": {}}, {"tool": "", "params": {}})
        self.assertEqual(cm.exception.code, "invalid_tool")
        self.assertEqual(self.env.rt.ledger.size(), size)
        self.assertEqual(self.eng.observations(), [])

    def test_validation(self):
        bad = [({"tool": "note.add", "params": []}, "params_must_be_an_object"),
               ({"tool": "note.add", "params": {}, "occurred_at": "yesterday"}, "invalid_occurred_at"),
               ({"tool": "note.add", "params": {}, "occurred_at": 5}, "invalid_occurred_at"),
               ({"tool": "note.add", "params": {}, "occurred_at": T0 + 10 * 86400}, "invalid_occurred_at"),
               ({"tool": "note.add", "params": {}, "occurred_at": True}, "invalid_occurred_at"),
               ({"tool": "note.add", "params": {}, "external_id": "x" * 121}, "invalid_external_id"),
               ({"tool": "note.add", "params": {"blob": "x" * 25000}}, "params_too_large"),
               ("not an object", "event_must_be_an_object")]
        for ev, code in bad:
            with self.assertRaises(OmniError, msg=str(ev)[:40]) as cm:
                self.obs(ev)
            self.assertEqual(cm.exception.code, code)
        with self.assertRaises(OmniError) as cm:
            self.eng.observe("ops-agent", PERMS, [])
        self.assertEqual(cm.exception.code, "events_required")
        with self.assertRaises(OmniError) as cm:
            self.eng.observe("ops-agent", PERMS, [{"tool": "note.add"}] * 201)
        self.assertEqual(cm.exception.status, 413)

    def test_filters_and_order(self):
        self.obs({"tool": "note.add", "params": {}, "occurred_at": T0 + 10},
                 {"tool": "payments.send", "params": {"amount_eur": 4000, "vendor": "V"}, "occurred_at": T0 + 20},
                 {"tool": "note.add", "params": {}, "occurred_at": T0 + 5})
        rows = self.eng.observations()
        self.assertEqual([r["tool"] for r in rows], ["payments.send", "note.add", "note.add"])      # newest first by claimed time
        self.assertEqual(len(self.eng.observations(decision="pending")), 1)
        self.assertEqual(len(self.eng.observations(since=T0 + 8)), 2)
        self.assertEqual(len(self.eng.observations(until=T0 + 8)), 1)
        self.assertEqual(self.eng.observations(agent="someone-else"), [])

    def test_bundle_with_observations_verifies(self):
        from omnios.evidence import build_bundle
        self.obs({"tool": "payments.send", "params": {"amount_eur": 4000, "vendor": "V"}}, {"tool": "note.add", "params": {}})
        self.eng.propose("ops-agent", "note.add", {"k": 1}, permissions=PERMS)
        data = build_bundle(self.env.rt, scope="all")
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            self.assertTrue(any("action.observed" in l for l in z.read("records.jsonl").decode().splitlines()))
        path = os.path.join(self.env.dir, "obs-bundle.zip")
        with open(path, "wb") as f:
            f.write(data)
        rep = verifier.verify_bundle(path, self.env.rt.public_info()["log_public_key"])
        self.assertTrue(rep["ok"], rep["problems"])
        self.assertEqual(rep["info"]["observed"], {"total": 2, "pending": 1, "allow": 1})
        self.assertIn("observed (dry run) 2", verifier.render(rep))


class ObserveSummaryTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.eng = self.env.rt.engine

    def tearDown(self):
        self.env.close()

    def test_summary_and_report(self):
        self.eng.observe("ops-agent", PERMS, [
            {"tool": "note.add", "params": {}, "occurred_at": T0},
            {"tool": "note.add", "params": {}, "occurred_at": T0 + 1},
            {"tool": "payments.send", "params": {"amount_eur": 4000, "vendor": "<b>V</b>"}, "occurred_at": T0 + 2},
            {"tool": "payments.send", "params": {"amount_eur": 20000, "vendor": "V"}, "occurred_at": T0 + 3},
            {"tool": "calendar.invite<script>", "params": {}, "occurred_at": T0 + 4},
            {"tool": "payments.send", "params": {"vendor": "V"}, "occurred_at": T0 + 5}])
        s = summarize(self.eng.observations())
        self.assertEqual((s["total"], s["allow"], s["pending"], s["deny"]), (6, 2, 2, 2))
        self.assertEqual(s["needs_review_share"], 0.667)
        self.assertEqual(s["by_tool"]["payments.send"], {"total": 3, "allow": 0, "pending": 2, "deny": 1})
        self.assertEqual(list(s["unmapped_tools"]), ["calendar.invite<script>"])
        self.assertEqual(s["unreadable_input"], 1)
        self.assertEqual(s["attention"][0]["decision"], "deny")                 # refused cases first
        self.assertEqual(len(s["attention"]), 4)
        page = render_html(s, "Acme <Ltd>")
        self.assertNotIn("<script>", page)
        self.assertNotIn("<Ltd>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("nothing was stopped", page)
        self.assertIn("not seen", page)

    def test_empty(self):
        s = summarize([])
        self.assertEqual((s["total"], s["needs_review_share"]), (0, 0))
        self.assertIn("0", render_html(s, "Empty"))


class ObserveApiTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.c = TestClient(create_app(self.env.reg, platform_key="op-key-123"))
        self.k = self.env.key

    def tearDown(self):
        self.c.close()
        self.env.close()

    def h(self, who):
        return {"X-API-Key": self.k[who]}

    def post(self, events, who="ops-agent"):
        return self.c.post("/v1/observe", headers=self.h(who), json={"events": events})

    def test_roles(self):
        ev = [{"tool": "note.add", "params": {}}]
        self.assertEqual(self.post(ev).status_code, 200)
        for who in ("alice", "aud-1", "admin-1"):
            self.assertEqual(self.post(ev, who).status_code, 403, who)
        self.assertEqual(self.c.post("/v1/observe", json={"events": ev}).status_code, 401)
        self.assertEqual(self.c.get("/v1/observe/report", headers=self.h("ops-agent")).status_code, 403)
        for who in ("aud-1", "admin-1", "alice"):
            self.assertEqual(self.c.get("/v1/observe/report", headers=self.h(who)).status_code, 200, who)

    def test_post_and_read_back(self):
        r = self.post([{"tool": "payments.send", "params": {"amount_eur": 4000, "vendor": "V"}, "external_id": "inv-1"},
                       {"tool": "note.add", "params": {}}])
        body = r.json()
        self.assertEqual([o["decision"] for o in body["observed"]], ["pending", "allow"])
        self.assertEqual(body["mode"], "observe")
        mine = self.c.get("/v1/observe", headers=self.h("ops-agent")).json()["observed"]
        self.assertEqual(len(mine), 2)
        self.assertEqual(len(self.c.get("/v1/observe?decision=pending", headers=self.h("aud-1")).json()["observed"]), 1)
        self.assertEqual(self.c.get("/v1/observe?decision=bogus", headers=self.h("aud-1")).status_code, 422)
        self.assertEqual(self.c.get("/v1/actions", headers=self.h("aud-1")).json()["actions"], [])

    def test_batch_limits_and_shape(self):
        self.assertEqual(self.post([]).status_code, 422)
        self.assertEqual(self.post([{"tool": "note.add"}] * 201).status_code, 422)
        self.assertEqual(self.post([{"tool": "note.add", "occurred_at": 5}]).status_code, 422)
        self.assertEqual(self.c.post("/v1/observe", headers=self.h("ops-agent"), json={"events": [{"params": {}}]}).status_code, 422)
        self.assertEqual(self.c.get("/v1/observe", headers=self.h("aud-1")).json()["observed"], [])

    def test_report_json_and_html(self):
        self.post([{"tool": "payments.send", "params": {"amount_eur": 4000, "vendor": "V"}},
                   {"tool": "payments.send", "params": {"amount_eur": 99999, "vendor": "V"}}, {"tool": "note.add", "params": {}}])
        j = self.c.get("/v1/observe/report", headers=self.h("aud-1")).json()
        self.assertEqual((j["total"], j["allow"], j["pending"], j["deny"]), (3, 1, 1, 1))
        r = self.c.get("/v1/observe/report.html", headers=self.h("aud-1"))
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/html", r.headers["content-type"])
        self.assertIn("default-src 'none'", r.headers["content-security-policy"])
        self.assertIn("Acme Ltd", r.text)

    def test_agent_sees_only_its_own(self):
        self.post([{"tool": "note.add", "params": {}}])
        self.env.rt.engine.observe("other-agent", ["notes:write"], [{"tool": "note.add", "params": {}}])
        self.assertEqual(len(self.c.get("/v1/observe", headers=self.h("ops-agent")).json()["observed"]), 1)
        self.assertEqual(len(self.c.get("/v1/observe", headers=self.h("aud-1")).json()["observed"]), 2)


class ObserveSdkTests(unittest.TestCase):
    def setUp(self):
        self.env = Env(clock=_util.FakeClock(time.time()))
        self.client = TestClient(create_app(self.env.reg))
        self.k = self.env.key
        self.down = False

    def tearDown(self):
        self.client.close()
        self.env.close()

    def transport(self, method, url, headers, body):
        if self.down:
            raise OSError("connection refused")
        r = self.client.request(method, url.replace("http://testserver", ""), headers=headers, content=body)
        return r.status_code, r.content

    def gw(self, who="ops-agent"):
        return omnios_sdk.OmniOS("http://testserver", self.k[who], transport=self.transport)

    def test_observed_function_always_runs_and_is_reported_in_the_background(self):
        gw, calls = self.gw(), []

        @gw.observed("payments.send", external_id=lambda a: "inv-" + a["vendor"])
        def pay(vendor, amount_eur):
            calls.append(vendor)
            return "paid"

        self.assertEqual(pay("Acme", 4000), "paid")
        self.assertEqual(pay("Bolt", 20000), "paid")                 # would be refused; observe mode does not stop it
        self.assertTrue(gw.flush(5))
        self.assertEqual(calls, ["Acme", "Bolt"])
        rows = self.env.rt.engine.observations()
        self.assertEqual(sorted((r["decision"], r["external_id"]) for r in rows), [("deny", "inv-Bolt"), ("pending", "inv-Acme")])
        self.assertEqual(gw.observe_stats()["sent"], 2)

    def test_fail_open_when_the_gateway_is_down(self):
        gw = self.gw()
        self.down = True

        @gw.observed("note.add")
        def note(text):
            return text.upper()

        self.assertEqual(note("hello"), "HELLO")                      # the agent is unaffected
        self.assertTrue(gw.flush(5))
        st = gw.observe_stats()
        self.assertEqual((st["sent"], st["failed"]), (0, 1))
        self.assertIn("OSError", st["last_error"] or "")
        self.down = False
        self.assertEqual(note("again"), "AGAIN")
        self.assertTrue(gw.flush(5))
        self.assertEqual(gw.observe_stats()["sent"], 1)

    def test_unserializable_arguments_do_not_break_the_function(self):
        gw = self.gw()

        @gw.observed("note.add")
        def note(obj):
            return "ok"

        self.assertEqual(note(object()), "ok")
        self.assertEqual(gw.observe_stats()["dropped"], 1)

    def test_direct_calls(self):
        gw = self.gw()
        v = gw.observe("payments.send", {"amount_eur": 4000, "vendor": "V"}, external_id="x1")
        self.assertEqual((v["decision"], v["approvals_required"]), ("pending", 2))
        with self.assertRaises(omnios_sdk.OmniOSError):
            self.gw("alice").observe("note.add", {})                   # an approver key cannot report actions


class DemoSeedTests(unittest.TestCase):
    def test_the_ui_demo_data_is_valid_and_tells_a_story(self):
        import runpy
        from omnios.provision import create_tenant
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        demo = runpy.run_path(os.path.join(here, "scripts", "ui_demo.py"), run_name="omnios_ui_demo_test")
        env = Env(clock=_util.FakeClock(time.time()))
        try:
            rt, _, _ = create_tenant(env.reg, "demo-acme", "Demo Acme Ltd", template="finance-ap-payments", profile="production",
                                     admins=["a1", "a2", "a3"], approvers=["alice", "bob"], auditors=["au"],
                                     agents=[{"name": "ap-agent", "permissions": ["finance:pay", "finance:vendor-admin", "finance:books"]}])
            demo["seed_observed"](rt, now=env.clock())
            s = summarize(rt.engine.observations(limit=5000))
            self.assertGreater(s["total"], 40)
            self.assertTrue(s["allow"] and s["pending"] and s["deny"])
            self.assertIn("contracts.sign", s["unmapped_tools"])
            self.assertGreaterEqual(s["unreadable_input"], 2)
            self.assertTrue(any("limit exceeded" in r["reason"] for r in s["top_reasons"]))
        finally:
            env.close()


class ObserveCliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def p(self, name):
        return os.path.join(self.dir, name)

    def test_import_csv_then_report(self):
        with open(self.p("rules.json"), "w", encoding="utf-8") as f:
            json.dump(POLICY, f)
        root = self.p("data")
        code, out, err = self.run_cli("tenant", "create", "--root", root, "--id", "pilot1", "--name", "Pilot One", "--policy", self.p("rules.json"),
                                      "--agents", "ops-agent:finance:pay|notes:write")
        self.assertEqual(code, 0, err)
        with open(self.p("export.csv"), "w", encoding="utf-8", newline="") as f:
            f.write("tool,external_id,occurred_at,amount_eur,vendor\n"
                    "payments.send,i3,2026-10-03T09:00:00,6000,V\n"
                    "payments.send,i1,2026-10-01T09:00:00,6000,V\n"
                    "payments.send,i2,2026-10-01T10:00:00,6000,V\n"
                    "note.add,n1,2026-10-01T11:00:00,,\n"
                    "ghost.tool,g1,2026-10-01T12:00:00,,\n")
        code, out, err = self.run_cli("observe", "import", "--root", root, "--tenant", "pilot1", "--agent", "ops-agent", "--file", self.p("export.csv"))
        self.assertEqual(code, 0, err)
        # sorted by time before judging: i1 6000, i2 12000 (both need approval), i3 two days later is a fresh window; one unknown tool, one note
        self.assertIn("imported 5 events: 1 would pass, 3 would need approval, 1 would be refused", out)
        again = self.run_cli("observe", "import", "--root", root, "--tenant", "pilot1", "--agent", "ops-agent", "--file", self.p("export.csv"))
        self.assertEqual(again[0], 0)
        code, out, err = self.run_cli("observe", "report", "--root", root, "--tenant", "pilot1", "--out", self.p("report.html"))
        self.assertEqual(code, 0, err)
        with open(self.p("report.html"), encoding="utf-8") as f:
            html = f.read()
        self.assertIn("Pilot One", html)
        self.assertIn("ghost.tool", html)
        code, out, err = self.run_cli("observe", "report", "--root", root, "--tenant", "pilot1", "--out", self.p("report.json"))
        with open(self.p("report.json"), encoding="utf-8") as f:
            self.assertEqual(json.load(f)["total"], 5)                 # importing the same file twice adds nothing (external ids)

    def test_import_errors_are_readable(self):
        root = self.p("data")
        self.assertEqual(self.run_cli("tenant", "create", "--root", root, "--id", "pilot2", "--name", "Pilot Two", "--agents", "bot:notes:write")[0], 0)
        with open(self.p("bad.csv"), "w", encoding="utf-8") as f:
            f.write("tool,occurred_at\nnote.add,yesterday-ish\n")
        code, out, err = self.run_cli("observe", "import", "--root", root, "--tenant", "pilot2", "--agent", "bot", "--file", self.p("bad.csv"))
        self.assertEqual(code, 1)
        self.assertIn("row 2", err)
        with open(self.p("ok.jsonl"), "w", encoding="utf-8") as f:
            f.write('{"tool": "note.add"}\n')
        self.assertEqual(self.run_cli("observe", "import", "--root", root, "--tenant", "pilot2", "--agent", "nobody", "--file", self.p("ok.jsonl"))[0], 1)
        self.assertEqual(self.run_cli("observe", "import", "--root", root, "--tenant", "pilot2", "--agent", "bot", "--file", self.p("ok.jsonl"))[0], 0)
        with open(self.p("empty.jsonl"), "w", encoding="utf-8") as f:
            f.write("\n")
        self.assertEqual(self.run_cli("observe", "import", "--root", root, "--tenant", "pilot2", "--agent", "bot", "--file", self.p("empty.jsonl"))[0], 1)


if __name__ == "__main__":
    unittest.main()
