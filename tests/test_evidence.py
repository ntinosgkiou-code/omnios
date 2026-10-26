import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
import zipfile

import _util
from _util import POLICY, Env
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from omnios import tlog, verifier
from omnios.errors import OmniError
from omnios.evidence import build_bundle
from omnios.ledger import Ledger

AGENT, PERMS = "ops-agent", ["finance:pay", "refund:issue", "data:delete", "notes:write"]


def scenario(env):
    """A payment with two approvers, a denied one, a rejected one, and a policy change by two admins."""
    eng = env.rt.engine
    ids = {}
    a = eng.propose(AGENT, "payments.send", {"amount_eur": 4000, "vendor": "Acme"}, permissions=PERMS)
    eng.approve(a["id"], "alice")
    eng.approve(a["id"], "bob")
    eng.report(a["id"], AGENT, True, {"tx": "t1"})
    ids["paid"] = a["id"]
    ids["denied"] = eng.propose(AGENT, "payments.send", {"amount_eur": 99999, "vendor": "Acme"}, permissions=PERMS)["id"]
    r = eng.propose(AGENT, "refunds.issue", {"amount_eur": 500}, permissions=PERMS)
    eng.reject(r["id"], "carol", "no")
    ids["rejected"] = r["id"]
    new = json.loads(json.dumps(POLICY))
    new["tools"]["note.add"]["description"] = "v2"
    c = eng.propose_change("policy.replace", {"doc": new}, "admin-1")
    eng.approve_change(c["id"], "admin-2")
    ids["change"] = c["id"]
    return ids


def rewrite(data, records=None, manifest=None, checkpoints=None, fix_manifest=True):
    """Return a modified copy of a bundle. `records` edits the list of record dicts."""
    z = zipfile.ZipFile(io.BytesIO(data))
    files = {n: z.read(n) for n in z.namelist()}
    if records:
        lines = [json.loads(x) for x in files["records.jsonl"].decode().splitlines() if x.strip()]
        lines = records(lines)
        files["records.jsonl"] = ("\n".join(json.dumps(x, ensure_ascii=False) for x in lines) + "\n").encode()
    if checkpoints:
        cps = json.loads(files["checkpoints.json"])
        checkpoints(cps)
        files["checkpoints.json"] = json.dumps(cps).encode()
    m = json.loads(files["manifest.json"])
    if manifest:
        manifest(m)
    if fix_manifest:
        m["files"] = {n: hashlib.sha256(b).hexdigest() for n, b in files.items() if n != "manifest.json"}
    files["manifest.json"] = json.dumps(m).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as out:
        for n, b in files.items():
            out.writestr(n, b)
    return buf.getvalue()


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.ids = scenario(self.env)
        self.key = self.env.rt.public_info()["log_public_key"]
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        self.env.close()

    def verify(self, data, key="pinned", witnesses=None):
        path = os.path.join(self.dir, "b.zip")
        open(path, "wb").write(data)
        return verifier.verify_bundle(path, self.key if key == "pinned" else key, witnesses)

    def bundle(self, **kw):
        return build_bundle(self.env.rt, **kw)

    # ---------- honest bundles ----------
    def test_full_bundle_verifies_when_pinned(self):
        rep = self.verify(self.bundle())
        self.assertTrue(rep["ok"], rep["problems"])
        self.assertEqual(rep["info"]["records_verified"], self.env.rt.ledger.size())
        self.assertTrue(rep["pinned"])
        a = rep["actions"][self.ids["paid"]]
        self.assertEqual(a["approvers"], ["alice", "bob"])
        self.assertEqual(rep["actions"][self.ids["denied"]]["events"], ["action.denied"])
        text = verifier.render(rep)
        self.assertIn("RESULT: VERIFIED", text)

    def test_unpinned_is_flagged(self):
        rep = self.verify(self.bundle(), key=None)
        self.assertTrue(rep["ok"])
        self.assertTrue(any("UNPINNED" in w for w in rep["warnings"]))
        self.assertIn("UNPINNED", verifier.render(rep))

    def test_wrong_pinned_key_fails(self):
        other = base64.b64encode(tlog.public_bytes(Ed25519PrivateKey.generate().public_key())).decode()
        rep = self.verify(self.bundle(), key=other)
        self.assertFalse(rep["ok"])

    def test_scopes(self):
        rep = self.verify(self.bundle(scope="action", ref=self.ids["paid"]))
        self.assertTrue(rep["ok"], rep["problems"])
        self.assertLess(rep["info"]["records_verified"], self.env.rt.ledger.size())
        self.assertEqual(list(rep["actions"]), [self.ids["paid"]])
        self.assertFalse([w for w in rep["warnings"] if "policy" in w])  # the rules the action relied on are included
        rep = self.verify(self.bundle(scope="changes"))
        self.assertTrue(rep["ok"], rep["problems"])
        self.assertEqual(rep["actions"], {})
        with self.assertRaises(OmniError):
            self.bundle(scope="action")
        with self.assertRaises(OmniError):
            self.bundle(scope="action", ref="act-77777")
        with self.assertRaises(OmniError):
            self.bundle(scope="everything")

    def test_bundle_contains_no_parameters(self):
        z = zipfile.ZipFile(io.BytesIO(self.bundle()))
        blob = b"".join(z.read(n) for n in z.namelist() if n != "verify.py")
        self.assertNotIn(b"Acme", blob.replace(b"Acme Ltd", b""))

    def test_standalone_verify_py_runs_without_the_package(self):
        data = self.bundle()
        z = zipfile.ZipFile(io.BytesIO(data))
        d = tempfile.mkdtemp()
        open(os.path.join(d, "verify.py"), "wb").write(z.read("verify.py"))
        open(os.path.join(d, "b.zip"), "wb").write(data)
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["PYTHONUTF8"] = "1"
        r = subprocess.run([sys.executable, os.path.join(d, "verify.py"), os.path.join(d, "b.zip"), "--log-key", self.key],
                           capture_output=True, text=True, cwd=d, env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("VERIFIED", r.stdout)
        bad = rewrite(data, records=lambda L: [dict(L[0], body=L[0]["body"].replace("tenant.created", "tenant.deleted"))] + L[1:])
        open(os.path.join(d, "bad.zip"), "wb").write(bad)
        r = subprocess.run([sys.executable, os.path.join(d, "verify.py"), os.path.join(d, "bad.zip"), "--log-key", self.key],
                           capture_output=True, text=True, cwd=d, env=env)
        self.assertEqual(r.returncode, 2)
        self.assertIn("FAILED", r.stdout)
        r = subprocess.run([sys.executable, os.path.join(d, "verify.py"), os.path.join(d, "nope.zip")], capture_output=True, text=True, cwd=d, env=env)
        self.assertEqual(r.returncode, 3)

    # ---------- tampering ----------
    def test_edit_without_fixing_manifest(self):
        def edit(L):
            i = next(k for k, x in enumerate(L) if '"alice"' in x["body"])
            L[i] = dict(L[i], body=L[i]["body"].replace("alice", "mallory"))
            return L
        bad = rewrite(self.bundle(), records=edit, fix_manifest=False)
        rep = self.verify(bad)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("manifest" in p for p in rep["problems"]))

    def test_edit_record_text_with_manifest_fixed(self):
        def edit(L):
            i = next(k for k, x in enumerate(L) if '"alice"' in x["body"])
            L[i] = dict(L[i], body=L[i]["body"].replace("alice", "mallory"))
            return L
        rep = self.verify(rewrite(self.bundle(), records=edit))
        self.assertFalse(rep["ok"])
        self.assertTrue(any("does not hash to its leaf" in p for p in rep["problems"]))

    def test_edit_record_and_recompute_leaf_is_not_in_the_signed_tree(self):
        def edit(L):
            i = next(k for k, x in enumerate(L) if '"alice"' in x["body"])
            body = L[i]["body"].replace("alice", "mallory")
            L[i] = dict(L[i], body=body, leaf=tlog.leaf_hash(body.encode()).hex())
            return L
        rep = self.verify(rewrite(self.bundle(), records=edit))
        self.assertFalse(rep["ok"])
        self.assertTrue(any("NOT in the checkpointed tree" in p for p in rep["problems"]))

    def test_deleting_a_record_is_detected(self):
        rep = self.verify(rewrite(self.bundle(), records=lambda L: L[:3] + L[4:]))
        self.assertFalse(rep["ok"])
        self.assertTrue(any("promised" in p for p in rep["problems"]))

    def test_checkpoint_swapped_for_another_log(self):
        other = Env()
        try:
            scenario(other)
            theirs = build_bundle(other.rt)
            rep = self.verify(theirs)  # pinned to OUR key
            self.assertFalse(rep["ok"])
            self.assertTrue(any("different log key" in p or "NOT signed" in p for p in rep["problems"]))
        finally:
            other.close()

    def test_rewritten_history_with_the_real_key_breaks_the_witnessed_prefix(self):
        """The operator holds the log key and rebuilds a ledger with one record changed. The witness cosigned the
        original at size 6, so the new history cannot be shown to extend it."""
        led = self.env.rt.ledger
        wk = Ed25519PrivateKey.generate()
        wpub = tlog.public_bytes(wk.public_key())
        n = led.size()
        text, _ = tlog.split_note(led.note_for_size(n))
        led.add_cosignature(n, tlog.sign_cosignature_v1(text, "wit", wk, timestamp=1_760_000_000), {"wit": wpub})
        honest = self.bundle()
        rep = self.verify(honest, witnesses={"wit": base64.b64encode(wpub).decode()})
        self.assertTrue(rep["ok"], rep["problems"])
        self.assertEqual(rep["info"]["witnessed_up_to"], n)
        self.assertFalse([w for w in rep["warnings"] if "witness" in w])
        # rebuild with the same key and a different 3rd record
        path = os.path.join(self.dir, "alt.db")
        alt = Ledger(path, "acme", self.env.rt.log_key)
        for r in led.records(0, 1000):
            body = json.loads(r["body"])
            data = body["data"]
            if r["seq"] == 3:
                data = dict(data, by="mallory")
            alt.append(body["type"], data, at=body["at"])
        fake_rt = types.SimpleNamespace(ledger=alt, id="acme", cfg=self.env.rt.cfg)
        forged = build_bundle(fake_rt)
        old = json.loads(zipfile.ZipFile(io.BytesIO(honest)).read("checkpoints.json"))["witnessed"]
        forged = rewrite(forged, checkpoints=lambda c: c.update({"witnessed": old}))
        rep = self.verify(forged, witnesses={"wit": base64.b64encode(wpub).decode()})
        self.assertFalse(rep["ok"])
        self.assertTrue(any("does NOT extend" in p for p in rep["problems"]), rep["problems"])

    def test_unknown_format_or_version_is_refused_not_guessed(self):
        for change in ({"version": 2}, {"format": "something-else"}):
            rep = self.verify(rewrite(self.bundle(), manifest=lambda m, c=change: m.update(c)))
            self.assertFalse(rep["ok"])
            self.assertTrue(any("unsupported bundle" in p for p in rep["problems"]))

    def test_partial_witness_coverage_is_a_warning(self):
        led = self.env.rt.ledger
        wk = Ed25519PrivateKey.generate()
        wpub = tlog.public_bytes(wk.public_key())
        n = led.size()
        text, _ = tlog.split_note(led.note_for_size(n))
        led.add_cosignature(n, tlog.sign_cosignature_v1(text, "wit", wk, timestamp=1_760_000_000), {"wit": wpub})
        self.env.rt.engine.propose(AGENT, "note.add", {"t": 1}, permissions=PERMS)
        rep = self.verify(self.bundle(), witnesses={"wit": base64.b64encode(wpub).decode()})
        self.assertTrue(rep["ok"], rep["problems"])
        self.assertEqual(rep["info"]["witnessed_up_to"], n)
        self.assertTrue(any("not yet witnessed" in w for w in rep["warnings"]))

    def test_no_witness_keys_given_is_a_warning(self):
        rep = self.verify(self.bundle())
        self.assertTrue(any("witness" in w for w in rep["warnings"]))


class WitnessPolicyTests(unittest.TestCase):
    """The person who asks for the proof sets the bar: how many witnesses, and how recent."""
    T0 = 1_760_000_000

    def setUp(self):
        self.env = Env()
        self.eng = self.env.rt.engine
        for i in range(3):
            self.eng.propose(AGENT, "note.add", {"i": i}, permissions=PERMS)
        self.led = self.env.rt.ledger
        self.key = self.env.rt.public_info()["log_public_key"]
        self.dir = tempfile.mkdtemp()
        self.w = {n: Ed25519PrivateKey.generate() for n in ("w-audit", "w-vendor", "w-insurer")}
        self.pub = {n: tlog.public_bytes(k.public_key()) for n, k in self.w.items()}
        self.b64 = {n: base64.b64encode(p).decode() for n, p in self.pub.items()}

    def tearDown(self):
        self.env.close()

    def cosign(self, name, ts=None, size=None, plain=False):
        size = size or self.led.size()
        text, _ = tlog.split_note(self.led.note_for_size(size))
        line = tlog.sign_line(text, name, self.w[name]) if plain else tlog.sign_cosignature_v1(text, name, self.w[name], timestamp=ts or self.T0)
        self.led.add_cosignature(size, line, {name: self.pub[name]})

    def check(self, names, **kw):
        path = os.path.join(self.dir, "b.zip")
        open(path, "wb").write(build_bundle(self.env.rt))
        kw.setdefault("now", self.T0 + 100)
        return verifier.verify_bundle(path, self.key, {n: self.b64[n] for n in names}, **kw)

    def test_two_of_two(self):
        self.cosign("w-audit")
        self.cosign("w-vendor")
        rep = self.check(["w-audit", "w-vendor"], min_witnesses=2)
        self.assertTrue(rep["ok"], rep["problems"])
        self.assertEqual(rep["info"]["witnessed_by_required_up_to"], self.led.size())
        self.assertEqual({w["witness"] for w in rep["info"]["witnesses"]}, {"w-audit", "w-vendor"})
        self.assertIn("witness policy   at least 2", verifier.render(rep))

    def test_one_of_two_fails(self):
        self.cosign("w-audit")
        rep = self.check(["w-audit", "w-vendor"], min_witnesses=2)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("1 of the 2 required" in p for p in rep["problems"]), rep["problems"])

    def test_a_witness_you_did_not_pin_does_not_count(self):
        self.cosign("w-audit")
        self.cosign("w-vendor")
        rep = self.check(["w-audit"], min_witnesses=2)
        self.assertFalse(rep["ok"])

    def test_no_keys_given_but_a_policy_asked_for(self):
        self.cosign("w-audit")
        rep = self.check([], min_witnesses=1)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("no witness keys were given" in p for p in rep["problems"]))

    def test_stale_cosignature_does_not_count(self):
        self.cosign("w-audit", ts=self.T0)
        fresh = self.check(["w-audit"], max_age=3600)
        self.assertTrue(fresh["ok"], fresh["problems"])
        stale = self.check(["w-audit"], max_age=3600, now=self.T0 + 10 * 86400)
        self.assertFalse(stale["ok"])
        self.assertTrue(any("last cosigned 240 h ago" in p for p in stale["problems"]), stale["problems"])

    def test_plain_note_cosignature_has_no_timestamp_so_it_cannot_prove_freshness(self):
        self.cosign("w-audit", plain=True)
        self.assertTrue(self.check(["w-audit"], min_witnesses=1)["ok"])
        rep = self.check(["w-audit"], max_age=3600)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("no timestamp" in p for p in rep["problems"]))

    def test_each_witness_is_represented_by_its_latest_and_lag_is_a_warning(self):
        self.cosign("w-vendor")
        old = self.led.size()
        self.eng.propose(AGENT, "note.add", {"i": 99}, permissions=PERMS)
        self.cosign("w-audit")
        rep = self.check(["w-audit", "w-vendor"], min_witnesses=2)
        self.assertTrue(rep["ok"], rep["problems"])
        self.assertEqual(rep["info"]["witnessed_by_required_up_to"], old)
        self.assertEqual(rep["info"]["witnessed_up_to"], self.led.size())
        self.assertTrue(any("not yet witnessed by 2" in w for w in rep["warnings"]), rep["warnings"])

    def test_a_witness_that_saw_another_history_breaks_the_policy_even_with_the_real_key(self):
        self.cosign("w-audit")
        honest = build_bundle(self.env.rt)
        alt = Ledger(os.path.join(self.dir, "alt.db"), "acme", self.env.rt.log_key)
        for r in self.led.records(0, 1000):
            body = json.loads(r["body"])
            alt.append(body["type"], dict(body["data"], x="rewritten") if r["seq"] == 2 else body["data"], at=body["at"])
        alt.append("note", {"id": "filler"}, at=1.0)
        forged = build_bundle(types.SimpleNamespace(ledger=alt, id="acme", cfg=self.env.rt.cfg))
        old = json.loads(zipfile.ZipFile(io.BytesIO(honest)).read("checkpoints.json"))["witnessed"]
        forged = rewrite(forged, checkpoints=lambda c: c.update({"witnessed": old}))
        path = os.path.join(self.dir, "f.zip")
        open(path, "wb").write(forged)
        rep = verifier.verify_bundle(path, self.key, {"w-audit": self.b64["w-audit"]}, min_witnesses=1, now=self.T0 + 100)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("does NOT extend" in p for p in rep["problems"]))

    def test_command_line_flags(self):
        self.cosign("w-audit")
        path = os.path.join(self.dir, "b.zip")
        open(path, "wb").write(build_bundle(self.env.rt))
        base = [path, "--log-key", self.key, "--witness", f"w-audit={self.b64['w-audit']}"]
        out = io.StringIO()
        import contextlib
        with contextlib.redirect_stdout(out):
            self.assertEqual(verifier.main(base + ["--min-witnesses", "1"]), 0)
            self.assertEqual(verifier.main(base + ["--min-witnesses", "2"]), 2)
            self.assertEqual(verifier.main(base + ["--max-age", "1s"]), 2)       # cosigned in 2025, now is later
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(verifier.main(base + ["--max-age", "soon"]), 3)
        self.assertIn("witness policy NOT met", out.getvalue())


class LargeLedgerTests(unittest.TestCase):
    def test_bundle_of_more_records_than_one_read_returns(self):
        """`Ledger.records` caps a single call at 5,000; a bundle of 'all' must still contain every record."""
        d = tempfile.mkdtemp()
        led = Ledger(os.path.join(d, "l.db"), "acme", Ed25519PrivateKey.generate())
        for i in range(5100):
            led.append("note", {"id": f"n{i}"}, at=1.0)
        self.assertEqual(len(list(led.iter_records(0, page=700))), 5100)
        rt = types.SimpleNamespace(ledger=led, id="acme", cfg={"profile": "pilot", "admin_quorum": 1, "name": "x"})
        path = os.path.join(d, "b.zip")
        open(path, "wb").write(build_bundle(rt))
        rep = verifier.verify_bundle(path)
        self.assertTrue(rep["ok"], rep["problems"][:3])
        self.assertEqual(rep["info"]["records_verified"], 5100)


class RuleTests(unittest.TestCase):
    """The log is cryptographically fine, but what it records breaks the rules: the verifier must still say FAILED."""

    def setUp(self):
        self.env = Env()
        self.dir = tempfile.mkdtemp()
        self.eng = self.env.rt.engine
        self.key = self.env.rt.public_info()["log_public_key"]

    def tearDown(self):
        self.env.close()

    def verify(self):
        path = os.path.join(self.dir, "b.zip")
        open(path, "wb").write(build_bundle(self.env.rt))
        return verifier.verify_bundle(path, self.key)

    def problems(self, rep):
        return " | ".join(rep["problems"])

    def pending(self):
        a = self.eng.propose(AGENT, "payments.send", {"amount_eur": 4000, "vendor": "x"}, permissions=PERMS)
        self.assertEqual(a["status"], "PENDING_APPROVAL")
        return a

    def log(self, rtype, **data):
        self.env.rt.ledger.append(rtype, data, at=self.env.clock())

    def test_agent_approving_itself(self):
        a = self.pending()
        self.log("action.approved", id=a["id"], tool="payments.send", by=AGENT, n=1, of=2, groups=[], policy_hash=a["policy_hash"])
        rep = self.verify()
        self.assertFalse(rep["ok"])
        self.assertIn("agent approved its own action", self.problems(rep))

    def test_same_approver_twice(self):
        a = self.pending()
        for n in (1, 2):
            self.log("action.approved", id=a["id"], tool="payments.send", by="alice", n=n, of=2, groups=[], policy_hash=a["policy_hash"])
        self.assertIn("same approver approved more than once", self.problems(self.verify()))

    def test_execution_without_enough_approvals(self):
        a = self.pending()
        self.log("action.approved", id=a["id"], tool="payments.send", by="alice", n=1, of=2, groups=[], policy_hash=a["policy_hash"])
        self.log("action.executed", id=a["id"], tool="payments.send", approvers=["alice"], attestation="agent_report", policy_hash=a["policy_hash"])
        rep = self.verify()
        self.assertFalse(rep["ok"])
        self.assertIn("rules required 2", self.problems(rep))

    def test_execution_of_a_denied_action(self):
        a = self.eng.propose(AGENT, "payments.send", {"amount_eur": 99999, "vendor": "x"}, permissions=PERMS)
        self.assertEqual(a["status"], "DENIED")
        self.log("action.executing", id=a["id"], tool="payments.send", approvers=[], policy_hash=a["policy_hash"])
        self.assertIn("executed although the rules denied it", self.problems(self.verify()))

    def test_required_group_is_checked_from_the_logged_policy(self):
        a = self.eng.propose(AGENT, "data.delete", {"subject": "u"}, permissions=PERMS)
        for who in ("alice", "bob"):
            self.log("action.approved", id=a["id"], tool="data.delete", by=who, n=1, of=2, groups=[], policy_hash=a["policy_hash"])
        self.assertIn("not in a required group", self.problems(self.verify()))

    def test_dangling_execution_is_a_warning(self):
        a = self.pending()
        for who in ("alice", "bob"):
            self.log("action.approved", id=a["id"], tool="payments.send", by=who, n=1, of=2, groups=[], policy_hash=a["policy_hash"])
        self.log("action.executing", id=a["id"], tool="payments.send", approvers=["alice", "bob"], policy_hash=a["policy_hash"])
        rep = self.verify()
        self.assertTrue(rep["ok"], rep["problems"])
        self.assertTrue(any("dangling" in w for w in rep["warnings"]))

    def test_admin_change_applied_below_quorum(self):
        self.log("change.proposed", id="chg-9001", kind="policy.replace", by="admin-1", quorum=2, summary={})
        self.log("change.applied", id="chg-9001", kind="policy.replace")
        self.assertIn("quorum needs 1", self.problems(self.verify()))

    def test_policy_text_must_match_its_hash(self):
        self.log("policy.activated", policy_hash="0" * 64, n=9, by="admin-1", via="x", policy={"version": 1, "tools": {}})
        self.assertIn("policy text does not match its hash", self.problems(self.verify()))

    def test_honest_run_passes_the_same_rules(self):
        a = self.pending()
        self.eng.approve(a["id"], "alice")
        self.eng.approve(a["id"], "bob")
        self.eng.report(a["id"], AGENT, True)
        rep = self.verify()
        self.assertTrue(rep["ok"], rep["problems"])


if __name__ == "__main__":
    unittest.main()
