import json
import os
import shutil
import tempfile
import unittest

import _util
from _util import POLICY, Env
from omnios.errors import OmniError
from omnios.identity import key_tenant
from omnios.tenant import TenantRegistry


class TenantIsolationTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.reg = TenantRegistry(self.dir)
        self.a, self.ka = self.reg.create("alpha", "Alpha SA", policy=POLICY, profile="pilot", approvers=["ann"],
                                          agents=[{"name": "bot", "permissions": ["notes:write"]}])
        self.b, self.kb = self.reg.create("bravo", "Bravo SA", policy=POLICY, profile="pilot", approvers=["ann"],
                                          agents=[{"name": "bot", "permissions": ["notes:write"]}])
        self.key = lambda ks, n: next(k["key"] for k in ks if k["name"] == n)

    def tearDown(self):
        self.reg.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_keys_carry_their_tenant_and_only_work_there(self):
        ka = self.key(self.ka, "ann")
        self.assertEqual(key_tenant(ka), "alpha")
        self.assertIsNotNone(self.a.identity.authenticate(ka))
        self.assertIsNone(self.b.identity.authenticate(ka))

    def test_separate_files_keys_and_sequences(self):
        self.assertNotEqual(self.a.dir, self.b.dir)
        for f in ("state.db", "ledger.db", "log.key", "tenant.json"):
            self.assertTrue((self.a.dir / f).exists() and (self.b.dir / f).exists())
        self.assertNotEqual(self.a.public_info()["log_public_key"], self.b.public_info()["log_public_key"])
        self.assertNotEqual(self.a.ledger.origin, self.b.ledger.origin)
        x = self.a.engine.propose("bot", "note.add", {"t": 1}, permissions=["notes:write"])
        y = self.b.engine.propose("bot", "note.add", {"t": 1}, permissions=["notes:write"])
        self.assertEqual(x["id"], y["id"])  # each customer counts from its own 1
        self.a.engine.propose("bot", "note.add", {"t": 2}, permissions=["notes:write"])
        self.assertEqual(self.b.engine.counts(), {"APPROVED": 1})
        self.assertEqual(self.a.engine.counts(), {"APPROVED": 2})
        self.assertNotEqual(self.a.ledger.checkpoint()["root"], self.b.ledger.checkpoint()["root"])

    def test_secrets_are_per_tenant(self):
        (self.a.dir / "secrets.json").write_text(json.dumps({"BANK": "alpha-secret"}))
        self.assertEqual(self.a.secret("BANK"), "alpha-secret")
        self.assertIsNone(self.b.secret("BANK"))
        os.environ["OMNIOS_SECRET__BRAVO__BANK"] = "bravo-env"
        try:
            self.assertEqual(self.b.secret("BANK"), "bravo-env")
            self.assertEqual(self.a.secret("BANK"), "alpha-secret")
        finally:
            del os.environ["OMNIOS_SECRET__BRAVO__BANK"]

    def test_log_key_file_is_not_world_readable_on_posix(self):
        if os.name != "posix":
            self.skipTest("POSIX permission bits")
        self.assertEqual(oct((self.a.dir / "log.key").stat().st_mode & 0o777), "0o600")

    def test_data_survives_reopening_the_registry(self):
        self.a.engine.propose("bot", "note.add", {"t": 1}, permissions=["notes:write"])
        pub = self.a.public_info()["log_public_key"]
        self.reg.close()
        reg2 = TenantRegistry(self.dir)
        try:
            a2 = reg2.get("alpha")
            self.assertEqual(a2.public_info()["log_public_key"], pub)
            self.assertEqual(a2.engine.counts(), {"APPROVED": 1})
            self.assertTrue(a2.ledger.verify_integrity()["ok"])
            self.assertIsNotNone(a2.identity.authenticate(self.key(self.ka, "ann")))
        finally:
            reg2.close()
            self.reg = TenantRegistry(self.dir)

    def test_provisioning_rules(self):
        with self.assertRaises(OmniError) as cm:
            self.reg.create("alpha", "dup", profile="pilot")
        self.assertEqual(cm.exception.code, "tenant_exists")
        with self.assertRaises(OmniError):
            self.reg.create("Bad Name!", "x")
        with self.assertRaises(OmniError) as cm:
            self.reg.create("prod-one", "x", profile="production", admins=["only-one"])
        self.assertEqual(cm.exception.code, "not_enough_admins")
        with self.assertRaises(OmniError) as cm:
            self.reg.create("prod-two", "x", profile="production", admin_quorum=1, admins=["a"])
        self.assertEqual(cm.exception.code, "production_needs_four_eyes")
        rt, keys = self.reg.create("prod-ok", "x", profile="production")
        self.assertEqual(rt.cfg["admin_quorum"], 2)
        self.assertEqual([k["name"] for k in keys if k["role"] == "admin"], ["admin-1", "admin-2"])

    def test_keys_are_stored_hashed_only(self):
        k = self.key(self.ka, "ann")
        raw = open(self.a.dir / "state.db", "rb").read() + open(self.a.dir / "ledger.db", "rb").read()
        self.assertNotIn(k.encode(), raw)

    def test_witness_registration_is_logged(self):
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from omnios import tlog
        pub = base64.b64encode(tlog.public_bytes(Ed25519PrivateKey.generate().public_key())).decode()
        self.reg.set_witnesses("alpha", {"w-one": pub})
        self.assertEqual(self.a.witness_keys()["w-one"], base64.b64decode(pub))
        self.assertIn("witness.registered", [r["type"] for r in self.a.ledger.records(0, 100)])
        with self.assertRaises(OmniError):
            self.reg.set_witnesses("alpha", {"bad": base64.b64encode(b"short").decode()})

    def test_public_registry_has_no_secrets(self):
        txt = json.dumps(self.reg.public_registry())
        self.assertIn("alpha", txt)
        self.assertNotIn(self.key(self.ka, "ann"), txt)


if __name__ == "__main__":
    unittest.main()
