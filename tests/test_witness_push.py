"""PUSH witnessing: the customer's installation sends its checkpoint OUT; the witness (a separate service) answers."""
import base64
import json
import os
import shutil
import tempfile
import unittest

import _util
from _util import Env
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from omnios import pusher, tlog, witnessd
from omnios.errors import OmniError
from omnios.ledger import Ledger

PERMS = ["notes:write"]
URL = "http://witness.test"


class PushTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.rt = self.env.rt
        self.wdir = tempfile.mkdtemp()
        info = witnessd.init_witness(self.wdir, "w-audit")
        self.wpub = info["public_key"]
        self.cfg_path = info["config_path"]
        self.key = self.rt.public_info()["log_public_key"]
        self.set_cfg(logs=[{"name": "acme", "origin": "omnios/acme", "log_key": self.key}])   # push-only: no url
        self.boot()
        self.env.reg.set_witnesses("acme", {"w-audit": self.wpub}, {"w-audit": URL})

    def boot(self):
        self.daemon = witnessd.WitnessDaemon(self.cfg_path)
        self.client = TestClient(self.daemon.app())

    def tearDown(self):
        self.env.close()
        shutil.rmtree(self.wdir, ignore_errors=True)

    def set_cfg(self, **kw):
        cfg = json.load(open(self.cfg_path, encoding="utf-8"))
        cfg.update(kw)
        json.dump(cfg, open(self.cfg_path, "w", encoding="utf-8"))

    def post(self, url, body):
        r = self.client.post(url.replace(URL, ""), json=body)
        return r.status_code, r.json()

    def push(self):
        return pusher.push_tenant(self.rt, self.post)[0]

    def grow(self, n=2):
        for i in range(n):
            self.rt.engine.propose("ops-agent", "note.add", {"i": i}, permissions=PERMS)

    # ---------- the happy path ----------
    def test_first_push_then_growth(self):
        r = self.push()
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.rt.ledger.witnessed(), (self.rt.ledger.size(), ["w-audit"]))
        self.grow()
        r = self.push()
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.rt.ledger.witnessed()[0], self.rt.ledger.size())
        self.assertEqual(self.daemon.state["logs"]["omnios/acme"]["size"], self.rt.ledger.size())
        self.assertTrue(self.push()["ok"])   # nothing new: idempotent

    def test_what_crosses_the_wire_is_a_signed_checkpoint_and_proof_only(self):
        seen = []

        def spy(url, body):
            seen.append(body)
            return self.post(url, body)
        self.grow()
        pusher.push_tenant(self.rt, spy)
        self.assertEqual(set(seen[0]), {"origin", "old_size", "proof", "note"})
        blob = json.dumps(seen)
        self.assertNotIn("ops-agent", blob)
        self.assertNotIn("notes:write", blob)

    def test_witness_info_and_validation(self):
        info = self.client.get("/witness/v1/info").json()
        self.assertEqual((info["name"], info["public_key"], info["logs"]), ("w-audit", self.wpub, ["omnios/acme"]))
        r = self.client.post("/witness/v1/add-checkpoint", json={"origin": "omnios/acme", "old_size": 0, "proof": ["x"] * 500, "note": "n" * 50})
        self.assertEqual(r.status_code, 422)

    # ---------- refusals ----------
    def test_unknown_log_and_forged_checkpoint_are_rejected_without_polluting_the_history(self):
        stranger = Env()
        try:
            cp = stranger.rt.ledger.checkpoint()
            for origin in ("omnios/not-a-customer", "omnios/acme"):
                status, body = self.post(URL + "/witness/v1/add-checkpoint", {"origin": origin, "old_size": 0, "proof": [], "note": cp["note"]})
                self.assertEqual(status, 403, body)
        finally:
            stranger.close()
        self.assertEqual(self.daemon.state["history"], [])      # a stranger cannot make a customer's report say ALERT

    def test_the_witness_must_be_registered_for_the_tenant_or_its_cosignature_is_not_stored(self):
        other = Ed25519PrivateKey.generate()
        self.env.reg.set_witnesses("acme", {"w-audit": base64.b64encode(tlog.public_bytes(other.public_key())).decode()})
        r = self.push()
        self.assertFalse(r["ok"])
        self.assertIn("cosignature not accepted", r["detail"])
        self.assertEqual(self.rt.ledger.witnessed(), (0, []))

    def test_unreachable_witness(self):
        def down(url, body):
            raise OSError("connection refused")
        r = pusher.push_tenant(self.rt, down)[0]
        self.assertFalse(r["ok"])
        self.assertIn("unreachable", r["detail"])

    def test_log_that_lost_its_progress_note_recovers_through_409(self):
        self.push()
        self.grow()
        self.rt.kv.delete("witness_push", "w-audit")
        r = self.push()
        self.assertTrue(r["ok"], r)

    # ---------- the point of it all ----------
    def rebuild_with_one_record_changed(self):
        alt = Ledger(os.path.join(self.wdir, "alt.db"), "acme", self.rt.log_key)
        for rec in self.rt.ledger.records(0, 1000):
            body = json.loads(rec["body"])
            alt.append(body["type"], dict(body["data"], x="rewritten") if rec["seq"] == 2 else body["data"], at=body["at"])
        for i in range(3):
            alt.append("note", {"id": f"f{i}"}, at=1.0)
        return alt

    def test_rewritten_history_is_refused_and_recorded_as_an_alert(self):
        self.grow(3)
        self.assertTrue(self.push()["ok"])
        known = self.daemon.state["logs"]["omnios/acme"]["size"]
        alt = self.rebuild_with_one_record_changed()
        status, body = self.post(URL + "/witness/v1/add-checkpoint", {
            "origin": "omnios/acme", "old_size": known, "proof": alt.consistency(known, alt.size())["proof"], "note": alt.checkpoint()["note"]})
        self.assertEqual(status, 422, body)
        self.assertIn("INCONSISTENT", body["detail"])
        self.assertEqual(self.daemon.state["logs"]["omnios/acme"]["size"], known)
        self.assertTrue(self.daemon.state["history"][-1]["detail"].startswith("REFUSED"))
        # and the real log is still accepted afterwards
        self.grow()
        self.assertTrue(self.push()["ok"])

    def test_the_same_size_but_a_different_tree_is_a_fork(self):
        self.grow(3)
        self.assertTrue(self.push()["ok"])
        known = self.daemon.state["logs"]["omnios/acme"]["size"]
        alt = Ledger(os.path.join(self.wdir, "fork.db"), "acme", self.rt.log_key)
        for rec in self.rt.ledger.records(0, 1000):
            body = json.loads(rec["body"])
            alt.append(body["type"], dict(body["data"], x="y") if rec["seq"] == 1 else body["data"], at=body["at"])
        self.assertEqual(alt.size(), known)
        status, body = self.post(URL + "/witness/v1/add-checkpoint", {"origin": "omnios/acme", "old_size": known, "proof": [], "note": alt.checkpoint()["note"]})
        self.assertEqual(status, 422)

    def test_a_restored_backup_makes_the_log_shorter_than_the_witness_remembers(self):
        self.grow(4)
        self.assertTrue(self.push()["ok"])
        seen = self.daemon.state["logs"]["omnios/acme"]["size"]
        self.rt.kv.put("witness_push", "w-audit", {"size": 3})           # what a restored, older state would believe
        shorter = Ledger(os.path.join(self.wdir, "short.db"), "acme", self.rt.log_key)
        for rec in self.rt.ledger.records(0, seen - 2):
            body = json.loads(rec["body"])
            shorter.append(body["type"], body["data"], at=body["at"])
        class FakeRT:                       # the restored installation: same identity, shorter ledger
            id, ledger, kv = self.rt.id, shorter, self.rt.kv
            _clock = staticmethod(self.rt._clock)
            def witness_keys(s): return self.rt.witness_keys()
            cfg = self.rt.cfg
        r = pusher.push_one(FakeRT(), "w-audit", URL, self.post)
        self.assertFalse(r["ok"])
        self.assertIn("ALERT", r["detail"])
        self.assertIn("SHRANK", r["detail"])
        self.assertEqual(self.daemon.state["logs"]["omnios/acme"]["size"], seen)
        self.assertEqual(self.daemon.monthly_report(__import__("time").strftime("%Y-%m"))["logs"][0]["refusals"], 1)

    # ---------- from push to the proof an auditor checks ----------
    def test_cosigned_log_verifies_offline_with_a_witness_policy(self):
        from omnios import verifier
        from omnios.evidence import build_bundle
        self.grow()
        self.assertTrue(self.push()["ok"])
        path = os.path.join(self.wdir, "b.zip")
        open(path, "wb").write(build_bundle(self.rt))
        rep = verifier.verify_bundle(path, self.key, {"w-audit": self.wpub}, min_witnesses=1, max_age=3600, now=self.rt._clock() + 60)
        self.assertTrue(rep["ok"], rep["problems"])
        self.assertEqual(rep["info"]["witnessed_by_required_up_to"], self.rt.ledger.size())

    def test_monthly_report_covers_a_push_only_log(self):
        self.push()
        rep = self.daemon.monthly_report(__import__("time").strftime("%Y-%m"))
        self.assertEqual((rep["logs"][0]["tenant"], rep["logs"][0]["verified"]), ("omnios/acme", 1))
        self.assertEqual(self.daemon.poll_once(), 0)                  # pull ignores push-only entries

    # ---------- registration ----------
    def test_registering_a_witness_url(self):
        reg = self.env.reg
        with self.assertRaises(OmniError):
            reg.set_witnesses("acme", {}, {"nobody": "https://x.example"})
        with self.assertRaises(OmniError):
            reg.set_witnesses("acme", {}, {"w-audit": "javascript:alert(1)"})
        reg.set_witnesses("acme", {}, {"w-audit": "https://witness.example:8443/prefix"})
        self.assertEqual(self.rt.cfg["witness_endpoints"]["w-audit"], "https://witness.example:8443/prefix")
        last = [r for r in self.rt.ledger.records(0, 1000) if r["type"] == "witness.registered"][-1]
        self.assertIn("https://witness.example:8443/prefix", last["body"])

    def test_suspended_tenants_are_not_pushed(self):
        self.env.reg.suspend("acme")
        self.assertEqual(pusher.push_all(self.env.reg, self.post), [])


if __name__ == "__main__":
    unittest.main()
