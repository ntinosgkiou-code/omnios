"""The four deliverables as a consultant uses them: assess kit, provisioning/handover, SDK against the real API, CLI."""
import base64
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
import zipfile

import _util
from _util import Env
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from omnios import assess, cli, provision, tlog
from omnios.api import create_app
from omnios.errors import OmniError
from omnios.policy import validate_policy
from omnios.tenant import TenantRegistry

sys_path_sdk = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sdk")
import sys  # noqa: E402

sys.path.insert(0, sys_path_sdk)
import omnios_sdk  # noqa: E402


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class AssessTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def answers(self, **over):
        path = os.path.join(self.dir, "a.yaml")
        assess.init_answers(path, 'Acme "Quoted" <b>SA</b>')
        data = assess.load_answers(path)
        data.update(over)
        return data

    def test_scoring_boundaries(self):
        s = assess.score_tool
        self.assertEqual(s({"reversible": "yes"})["level"], "Low")
        self.assertEqual(s({"reversible": "no"})["points"], 3)
        self.assertEqual(s({"reversible": "no", "personal_data": True})["level"], "Medium")
        self.assertEqual(s({"reversible": "no", "money": True})["level"], "High")
        self.assertEqual(s({"reversible": "yes", "money": True, "external_effect": True})["points"], 5)
        self.assertEqual(s({"reversible": "yes", "max_value_eur": 150})["points"], 1)
        self.assertEqual(s({"reversible": "yes", "max_value_eur": 1500})["points"], 2)
        self.assertEqual(s({"reversible": "yes", "max_value_eur": 15000})["points"], 3)
        self.assertEqual(s({"reversible": "yes", "max_value_eur": "garbage"})["points"], 0)
        self.assertEqual(s({})["level"], "Medium")  # unknown is scored as "no": irreversible

    def test_template_is_a_realistic_bad_case(self):
        res = assess.analyse(self.answers())
        self.assertEqual(res["tools"][0]["level"], "High")
        controls = {f["control"] for f in res["findings"]}
        self.assertTrue({"C-APPROVAL", "C-SOD", "C-CRED", "C-LOG", "C-LIMITS", "C-INDEP", "C-KILL", "C-INCIDENT", "C-KEYS"} <= controls)
        sev = [f["severity"] for f in res["findings"]]
        self.assertEqual(sev, sorted(sev, key={"High": 0, "Medium": 1, "Low": 2}.get))
        self.assertEqual(res["summary"]["high_impact_tools"], 1)

    def test_a_well_controlled_client_has_no_findings(self):
        a = self.answers()
        t = a["agents"][0]["tools"][0]
        t.update({"human_approval_today": "separate-system", "approvers_distinct": True, "log_tamper_evident": True})
        a["agents"][0]["credentials_held_by_agent"] = False
        a["agents"][0]["autonomy"] = "asks-first"
        a["controls"] = {k: "yes" for k in a["controls"]}
        res = assess.analyse(a)
        self.assertEqual(res["findings"], [], res["findings"])

    def test_native_hook_is_called_out_without_overclaiming(self):
        a = self.answers()
        a["agents"][0]["tools"][0]["human_approval_today"] = "native-hook"
        res = assess.analyse(a)
        f = next(f for f in res["findings"] if "framework hook" in f["text"])
        self.assertEqual(f["control"], "C-LOG")
        self.assertNotIn("insecure", f["text"].lower())

    def test_pressure_is_reported(self):
        a = self.answers()
        a["evidence_asked"] = {"asked_by": ["insurer"], "what_was_shown": "screenshots", "outcome": "asked for more"}
        html = assess.render_report(assess.analyse(a))
        self.assertIn("Someone has already asked", html)
        self.assertIn("insurer", html)

    def test_draft_policy_always_validates_and_loads(self):
        cases = [
            self.answers(),
            self.answers(agents=[{"name": "a", "tools": [{"name": "crm.note", "reversible": "yes"}]}]),
            self.answers(agents=[{"name": "a", "tools": [{"name": "Delete Customer!", "reversible": "no", "personal_data": True}]}]),
            self.answers(agents=[{"name": "a", "tools": [{"name": "pay", "reversible": "partly", "money": True, "value_field": "amt", "max_value_eur": 800}]}]),
            self.answers(agents=[{"name": "a", "tools": [{"name": "pay2", "reversible": "no", "money": True, "max_value_eur": "n/a"}]}]),
        ]
        for a in cases:
            pol = assess.recommend_policy(a)
            self.assertEqual(validate_policy(pol), [], pol)
            env = Env()
            try:
                env.reg.create("drafted", "Drafted", policy=pol, profile="pilot")
            finally:
                env.close()
        pol = assess.recommend_policy(cases[0])
        t = pol["tools"]["payments.send"]
        self.assertEqual(t["deny"][0]["when"]["value"], 5000)
        self.assertEqual(t["limits"][0]["max"], 15000)
        self.assertEqual(t["approvals"]["extra"][0]["required"], 2)
        self.assertIn("DRAFT", t["x_review"])

    def test_same_tool_name_on_two_agents_gets_distinct_ids(self):
        a = self.answers(agents=[{"name": "x", "tools": [{"name": "send mail", "reversible": "no"}]},
                                 {"name": "y", "tools": [{"name": "send mail", "reversible": "no"}]}])
        pol = assess.recommend_policy(a)
        self.assertEqual(sorted(pol["tools"]), ["send-mail", "send-mail-2"])
        self.assertIn("agents must use the id", pol["tools"]["send-mail"]["x_review"])

    def test_report_is_escaped_and_honest(self):
        html = assess.render_report(assess.analyse(self.answers()))
        self.assertNotIn("<b>SA</b>", html)
        self.assertIn("&lt;b&gt;SA&lt;/b&gt;", html)
        self.assertIn("not a penetration test", html)
        self.assertIn("never say the client is,", html)
        self.assertNotIn("ISO 27001", html)

    def test_run_report_writes_three_files(self):
        path = os.path.join(self.dir, "a.yaml")
        assess.init_answers(path, "Acme")
        out = assess.run_report(path, os.path.join(self.dir, "out"))
        for k in ("report", "findings", "policy"):
            self.assertTrue(os.path.getsize(out[k]) > 100)
        self.assertEqual(json.load(open(out["policy"], encoding="utf-8"))["version"], 1)

    def test_answers_need_an_agent(self):
        path = os.path.join(self.dir, "empty.yaml")
        open(path, "w").write("client: {name: x}\nagents: []\n")
        with self.assertRaises(ValueError):
            assess.load_answers(path)


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.reg = TenantRegistry(os.path.join(self.dir, "data"))

    def tearDown(self):
        self.reg.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_every_template_validates_and_creates_a_production_tenant(self):
        names = provision.template_names()
        self.assertEqual(set(names), {"finance-ap-payments", "finance-ar-collections", "support-refunds", "generic-starter"})
        for n in names:
            self.assertEqual(validate_policy(provision.load_template(n)), [], n)
            rt, keys, _ = provision.create_tenant(self.reg, "t-" + n[:20].replace("_", "-"), n, template=n, profile="production",
                                                  approvers=["a1", "a2"], agents=[{"name": "bot", "permissions": ["x"]}])
            self.assertEqual(rt.cfg["admin_quorum"], 2)
        with self.assertRaises(OmniError):
            provision.load_template("nope")

    def test_templates_carry_review_notes_and_no_secrets(self):
        for n in provision.template_names():
            raw = json.dumps(provision.load_template(n))
            self.assertIn("x_review", raw, n)
            self.assertNotIn("${ENV:", raw)

    def test_parse_agents(self):
        self.assertEqual(provision.parse_agents("ops:finance:pay|refund:issue,bot:crm:write"),
                         [{"name": "ops", "permissions": ["finance:pay", "refund:issue"]}, {"name": "bot", "permissions": ["crm:write"]}])
        self.assertEqual(provision.parse_agents(""), [])

    def test_handover_folder(self):
        out = os.path.join(self.dir, "handover")
        rt, keys, path = provision.create_tenant(self.reg, "client-one", "Client One SA", template="finance-ap-payments", profile="pilot",
                                                 approvers=["maria", "nikos"], auditors=["audit-1"],
                                                 agents=[{"name": "ap-bot", "permissions": ["finance:pay"]}], handover_dir=out)
        files = set(os.listdir(out))
        self.assertEqual(files, {"HANDOVER.md", "tenant-public.json", "witness-entry.json", "docker-compose.yml", ".env.example"})
        everything = "".join(open(os.path.join(out, f), encoding="utf-8").read() for f in files)
        for k in keys:
            self.assertNotIn(k["key"], everything)
        self.assertIn("maria", open(os.path.join(out, "HANDOVER.md"), encoding="utf-8").read())
        pub = json.load(open(os.path.join(out, "tenant-public.json"), encoding="utf-8"))
        self.assertEqual(pub["log_public_key"], rt.public_info()["log_public_key"])
        seed = open(rt.dir / "log.key").read().strip()
        self.assertNotIn(seed, everything)
        entry = json.load(open(os.path.join(out, "witness-entry.json"), encoding="utf-8"))
        self.assertEqual((entry["tenant"], entry["log_key"]), ("client-one", pub["log_public_key"]))
        out2 = os.path.join(self.dir, "handover2")
        rt2, keys2, _ = provision.create_tenant(self.reg, "client-two", "Two", template="generic-starter", handover_dir=out2, write_keys=True)
        txt = open(os.path.join(out2, "keys.txt"), encoding="utf-8").read()
        self.assertTrue(all(k["key"] in txt for k in keys2))

    def test_finance_template_behaves_as_described(self):
        rt, keys, _ = provision.create_tenant(self.reg, "ap-test", "AP", template="finance-ap-payments", profile="production",
                                              approvers=["a1", "a2", "a3"], agents=[{"name": "bot", "permissions": ["finance:pay"]}])
        pol = rt.engine.policy()
        tool = next(iter(pol["tools"]))
        perm = pol["tools"][tool]["permission"]
        a = rt.engine.propose("bot", tool, {"amount_eur": 2500, "vendor": "V", "iban": "GR0000"}, permissions=[perm])
        self.assertEqual(a["status"], "PENDING_APPROVAL")
        self.assertGreaterEqual(a["approvals_required"], 2)


class SdkAgainstTheRealApi(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.client = TestClient(create_app(self.env.reg))
        self.k = self.env.key
        self.calls = []
        self.on_poll = None

    def tearDown(self):
        self.client.close()
        self.env.close()

    def transport(self, method, url, headers, body):
        if getattr(self, "down", False):
            raise OSError("connection refused")
        path = url.replace("http://testserver", "")
        if method == "GET" and self.on_poll:
            fn, self.on_poll = self.on_poll, None
            fn()
        r = self.client.request(method, path, headers=headers, content=body)
        return r.status_code, r.content

    def gw(self):
        return omnios_sdk.OmniOS("http://testserver", self.k["ops-agent"], poll_seconds=0.001, wait_seconds=5, transport=self.transport)

    def approve_all(self, *who):
        for a in self.client.get("/v1/actions?status=PENDING_APPROVAL", headers={"X-API-Key": self.k["alice"]}).json()["actions"]:
            for w in who:
                self.client.post(f"/v1/actions/{a['id']}/approve", headers={"X-API-Key": self.k[w]})

    def test_function_runs_only_after_two_approvers_and_outcome_is_reported(self):
        gw = self.gw()

        @gw.governed("payments.send")
        def pay(vendor, amount_eur):
            self.calls.append((vendor, amount_eur))
            return {"tx": "t-1"}

        self.on_poll = lambda: (self.assertEqual(self.calls, []), self.approve_all("alice", "bob"))
        self.assertEqual(pay("Acme", 4000), {"tx": "t-1"})
        self.assertEqual(self.calls, [("Acme", 4000)])
        a = self.client.get("/v1/actions/act-00001", headers={"X-API-Key": self.k["alice"]}).json()
        self.assertEqual(a["status"], "REPORTED_SUCCESS")
        self.assertEqual([x["by"] for x in a["approvals"]], ["alice", "bob"])

    def test_denied_and_rejected_never_run(self):
        gw = self.gw()

        @gw.governed("payments.send")
        def pay(vendor, amount_eur):
            self.calls.append(1)

        with self.assertRaises(omnios_sdk.Denied):
            pay("Acme", 99999)
        self.on_poll = lambda: [self.client.post(f"/v1/actions/{a['id']}/reject", headers={"X-API-Key": self.k["bob"]})
                                for a in self.client.get("/v1/actions?status=PENDING_APPROVAL", headers={"X-API-Key": self.k["bob"]}).json()["actions"]]
        with self.assertRaises(omnios_sdk.Rejected):
            pay("Acme", 50)
        self.assertEqual(self.calls, [])

    def test_unreachable_platform_fails_closed(self):
        gw = self.gw()

        @gw.governed("note.add")
        def note(text):
            self.calls.append(text)

        self.down = True
        with self.assertRaises(omnios_sdk.GatewayUnavailable):
            note("x")
        self.assertEqual(self.calls, [])

    def test_agent_failure_is_reported(self):
        gw = self.gw()

        @gw.governed("note.add")
        def note(text):
            raise RuntimeError("boom")

        with self.assertRaises(RuntimeError):
            note("x")
        a = self.client.get("/v1/actions/act-00001", headers={"X-API-Key": self.k["alice"]}).json()
        self.assertEqual(a["status"], "REPORTED_FAILURE")

    def test_an_approver_key_cannot_be_used_as_an_agent(self):
        gw = omnios_sdk.OmniOS("http://testserver", self.k["alice"], transport=self.transport)
        with self.assertRaises(omnios_sdk.OmniOSError):
            gw.propose("note.add", {})


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.root = os.path.join(self.dir, "data")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_demo_runs_end_to_end(self):
        import subprocess
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        r = subprocess.run([sys.executable, "-m", "omnios", "demo"], capture_output=True, text=True, cwd=root,
                           env={**os.environ, "PYTHONUTF8": "1"}, timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout[-1500:] + r.stderr[-1500:])
        self.assertIn("Demo finished", r.stdout)
        self.assertIn("ALERT, witness refused", r.stdout)
        self.assertIn("witness policy NOT met", r.stdout)
        self.assertIn("RESULT: FAILED", r.stdout)

    def test_the_whole_consultant_path(self):
        a = os.path.join(self.dir, "answers.yaml")
        self.assertEqual(run_cli("assess", "init", "--client", "Acme", "--out", a)[0], 0)
        code, out, _ = run_cli("assess", "report", "--answers", a, "--out", os.path.join(self.dir, "report"))
        self.assertEqual(code, 0)
        self.assertIn("high_impact_tools", out)
        self.assertTrue(os.path.exists(os.path.join(self.dir, "report", "report.html")))

        ho = os.path.join(self.dir, "handover")
        code, out, err = run_cli("tenant", "create", "--root", self.root, "--id", "acme", "--name", "Acme", "--template", "finance-ap-payments",
                                 "--profile", "production", "--approvers", "maria,nikos", "--auditors", "aud",
                                 "--agents", "ap-bot:finance:pay", "--handover", ho)
        self.assertEqual(code, 0, err)
        self.assertIn("KEYS (shown once", out)
        self.assertIn("admin-1", out)
        self.assertFalse(os.path.exists(os.path.join(ho, "keys.txt")))
        code, out, _ = run_cli("tenant", "list", "--root", self.root)
        self.assertIn("acme", out)
        self.assertEqual(run_cli("tenant", "create", "--root", self.root, "--id", "acme", "--name", "again")[0], 1)

        wdir = os.path.join(self.dir, "witness")
        code, out, _ = run_cli("witness", "init", "--out", wdir, "--name", "w1")
        self.assertEqual(code, 0)
        wpub = out.split("public key:")[1].split()[0]
        self.assertEqual(run_cli("tenant", "witness", "--root", self.root, "--id", "acme", "--name", "w1", "--key", wpub)[0], 0)
        self.assertEqual(run_cli("tenant", "witness", "--root", self.root, "--id", "acme", "--name", "bad", "--key", base64.b64encode(b"x").decode())[0], 1)

        bundle = os.path.join(self.dir, "b.zip")
        self.assertEqual(run_cli("bundle", "export", "--root", self.root, "--tenant", "acme", "--out", bundle)[0], 0)
        key = json.load(open(os.path.join(ho, "tenant-public.json"), encoding="utf-8"))["log_public_key"]
        code, out, _ = run_cli("verify", bundle, "--log-key", key)
        self.assertEqual(code, 0, out)
        self.assertIn("RESULT: VERIFIED", out)
        code, out, _ = run_cli("verify", bundle)
        self.assertIn("UNPINNED", out)

        self.assertEqual(run_cli("tenant", "suspend", "--root", self.root, "--id", "acme")[0], 0)
        self.assertEqual(run_cli("tenant", "suspend", "--root", self.root, "--id", "acme", "--resume")[0], 0)

        code, out, _ = run_cli("witness", "report", "--config", os.path.join(wdir, "witness.json"), "--month", "2026-10", "--out", os.path.join(self.dir, "rep"))
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(os.path.join(self.dir, "rep", "witness-report-2026-10.html")))


if __name__ == "__main__":
    unittest.main()
