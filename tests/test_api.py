import base64
import io
import json
import unittest
import zipfile

import _util
from _util import POLICY, Env
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from omnios import tlog
from omnios.api import create_app

SECRET_VENDOR = "Zephyr-Quasar-Vendor-4471"


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.app = create_app(self.env.reg, platform_key="op-key-123")
        self.c = TestClient(self.app)
        self.k = self.env.key

    def tearDown(self):
        self.c.close()
        self.env.close()

    def h(self, who):
        return {"X-API-Key": self.k[who]}

    def propose(self, tool="payments.send", params=None):
        r = self.c.post("/v1/actions", headers=self.h("ops-agent"),
                        json={"tool": tool, "params": params or {"amount_eur": 4000, "vendor": SECRET_VENDOR}})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    # ---------- authentication ----------
    def test_keys(self):
        self.assertEqual(self.c.get("/v1/me").status_code, 401)
        self.assertEqual(self.c.get("/v1/me", headers={"X-API-Key": "nonsense"}).status_code, 401)
        self.assertEqual(self.c.get("/v1/me", headers={"X-API-Key": "ogk_ghost_abcdef"}).status_code, 401)
        self.assertEqual(self.c.get("/v1/me", headers={"X-API-Key": self.k["alice"] + "x"}).status_code, 401)
        me = self.c.get("/v1/me", headers=self.h("alice")).json()
        self.assertEqual((me["name"], me["role"], me["tenant"]), ("alice", "approver", "acme"))

    def test_error_shape(self):
        r = self.c.post("/v1/actions/act-99999/approve", headers=self.h("alice"))
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.json()["detail"]["code"], "no_such_action")

    # ---------- roles ----------
    def test_roles(self):
        a = self.propose()
        aid = a["id"]
        self.assertEqual(self.c.post(f"/v1/actions/{aid}/approve", headers=self.h("ops-agent")).status_code, 403)
        self.assertEqual(self.c.post(f"/v1/actions/{aid}/approve", headers=self.h("admin-1")).status_code, 403)
        self.assertEqual(self.c.post(f"/v1/actions/{aid}/approve", headers=self.h("aud-1")).status_code, 403)
        self.assertEqual(self.c.post("/v1/actions", headers=self.h("alice"), json={"tool": "note.add"}).status_code, 403)
        self.assertEqual(self.c.post("/v1/changes", headers=self.h("aud-1"), json={"kind": "policy.replace", "payload": {}}).status_code, 403)
        self.assertEqual(self.c.post("/v1/changes", headers=self.h("alice"), json={"kind": "policy.replace", "payload": {}}).status_code, 403)
        self.assertEqual(self.c.get("/v1/principals", headers=self.h("alice")).status_code, 403)
        self.assertEqual(self.c.get("/v1/audit/integrity", headers=self.h("alice")).status_code, 403)
        self.assertEqual(self.c.get("/v1/audit/integrity", headers=self.h("aud-1")).status_code, 200)

    def test_full_payment_flow(self):
        a = self.propose()
        self.assertEqual((a["status"], a["approvals_required"]), ("PENDING_APPROVAL", 2))
        r = self.c.post(f"/v1/actions/{a['id']}/approve", headers=self.h("alice"), json={"comment": "ok by finance"})
        self.assertEqual(r.json()["status"], "PENDING_APPROVAL")
        self.assertEqual(self.c.post(f"/v1/actions/{a['id']}/approve", headers=self.h("alice")).status_code, 409)
        r = self.c.post(f"/v1/actions/{a['id']}/approve", headers=self.h("bob"))
        self.assertEqual(r.json()["status"], "APPROVED")
        r = self.c.post(f"/v1/actions/{a['id']}/report", headers=self.h("ops-agent"), json={"ok": True, "response": {"tx": "t1"}})
        self.assertEqual(r.json()["status"], "REPORTED_SUCCESS")
        ev = self.c.get(f"/v1/audit/evidence/{a['id']}", headers=self.h("aud-1")).json()
        self.assertEqual([x["type"] for x in ev["records"]], ["action.proposed", "action.approved", "action.approved", "action.executed"])

    def test_groups_come_from_the_key_not_from_the_request(self):
        a = self.propose("data.delete", {"subject": "u1"})
        self.assertEqual(self.c.post(f"/v1/actions/{a['id']}/approve", headers=self.h("alice"), json={"groups": ["privacy"]}).status_code, 403)
        self.assertEqual(self.c.post(f"/v1/actions/{a['id']}/approve", headers=self.h("carol")).status_code, 200)
        self.assertEqual(self.c.post(f"/v1/actions/{a['id']}/approve", headers=self.h("dave")).json()["status"], "APPROVED")

    # ---------- changes ----------
    def test_new_approver_key_via_two_admins(self):
        r = self.c.post("/v1/changes", headers=self.h("admin-1"), json={"kind": "principal.create", "payload": {"name": "erin", "role": "approver"}})
        self.assertEqual(r.status_code, 200, r.text)
        ch = r.json()
        key = ch["key"]
        self.assertEqual(self.c.get("/v1/me", headers={"X-API-Key": key}).status_code, 401)
        self.assertEqual(self.c.post(f"/v1/changes/{ch['id']}/approve", headers=self.h("admin-1")).status_code, 403)
        r = self.c.post(f"/v1/changes/{ch['id']}/approve", headers=self.h("admin-2"))
        self.assertEqual(r.json()["status"], "APPLIED")
        self.assertEqual(self.c.get("/v1/me", headers={"X-API-Key": key}).json()["name"], "erin")
        self.assertNotIn(key, self.c.get("/v1/changes", headers=self.h("aud-1")).text)   # the key is shown once, to the proposer
        self.assertNotIn(key, self.c.get("/v1/audit/records?limit=500", headers=self.h("aud-1")).text)

    def test_policy_validate_endpoint(self):
        r = self.c.post("/v1/policy/validate", headers=self.h("admin-1"), json={"version": 1, "tools": {"x": {}}})
        self.assertTrue(r.json()["errors"])
        r = self.c.post("/v1/policy/validate", headers=self.h("admin-1"), json=POLICY)
        self.assertEqual(r.json()["errors"], [])

    # ---------- isolation between customers ----------
    def test_other_tenants_cannot_see_acme(self):
        rt2, keys2 = self.env.reg.create("beta", "Beta", policy=POLICY, profile="pilot", approvers=["bea"],
                                         agents=[{"name": "beta-bot", "permissions": ["finance:pay"]}])
        kb = {k["name"]: k["key"] for k in keys2}
        a = self.propose()
        r = self.c.get(f"/v1/actions/{a['id']}", headers={"X-API-Key": kb["bea"]})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(self.c.get("/v1/actions", headers={"X-API-Key": kb["bea"]}).json(), {"actions": []})
        self.assertEqual(self.c.get(f"/v1/audit/evidence/{a['id']}", headers={"X-API-Key": kb["bea"]}).status_code, 404)
        self.assertNotIn(SECRET_VENDOR, self.c.get("/v1/audit/records", headers={"X-API-Key": kb["bea"]}).text)
        # the same action id exists independently in beta
        b = self.c.post("/v1/actions", headers={"X-API-Key": kb["beta-bot"]}, json={"tool": "payments.send", "params": {"amount_eur": 5, "vendor": "v"}}).json()
        self.assertEqual(b["id"], a["id"])
        self.assertEqual(self.c.get(f"/v1/actions/{b['id']}", headers={"X-API-Key": kb["bea"]}).json()["agent"], "beta-bot")
        # acme's keys do not work as beta's: the prefix routes to acme
        self.assertEqual(self.c.get("/v1/me", headers=self.h("alice")).json()["tenant"], "acme")

    def test_agents_only_see_their_own_actions(self):
        self.env.rt.engine._identity.create("other-bot", "agent", ["finance:pay"])
        key2 = self.env.rt.engine._identity.create("other-bot-2", "agent", ["finance:pay"])
        a = self.propose()
        self.assertEqual(self.c.get(f"/v1/actions/{a['id']}", headers={"X-API-Key": key2}).status_code, 404)
        self.assertEqual(self.c.get("/v1/actions", headers={"X-API-Key": key2}).json()["actions"], [])
        self.assertEqual(self.c.get(f"/v1/audit/evidence/{a['id']}", headers={"X-API-Key": key2}).status_code, 404)

    def test_suspended_tenant(self):
        self.env.reg.suspend("acme")
        self.assertEqual(self.c.get("/v1/me", headers=self.h("alice")).status_code, 423)
        self.assertEqual(self.c.get("/public/acme/checkpoint").status_code, 200)
        self.env.reg.suspend("acme", False)
        self.assertEqual(self.c.get("/v1/me", headers=self.h("alice")).status_code, 200)

    # ---------- evidence ----------
    def test_records_hold_digests_not_content(self):
        a = self.propose()
        self.c.post(f"/v1/actions/{a['id']}/approve", headers=self.h("alice"), json={"comment": "private-comment-text"})
        for url, hdr in (("/v1/audit/records?limit=500", self.h("aud-1")), ("/public/acme/checkpoint", {})):
            self.assertNotIn(SECRET_VENDOR, self.c.get(url, headers=hdr).text)
            self.assertNotIn("private-comment-text", self.c.get(url, headers=hdr).text)

    def test_bundle_download_and_scopes(self):
        a = self.propose()
        r = self.c.get("/v1/audit/bundle", headers=self.h("aud-1"))
        self.assertEqual(r.status_code, 200)
        z = zipfile.ZipFile(io.BytesIO(r.content))
        self.assertTrue({"manifest.json", "checkpoints.json", "records.jsonl", "README.txt", "verify.py"} <= set(z.namelist()))
        r = self.c.get(f"/v1/audit/bundle?scope=action&id={a['id']}", headers=self.h("aud-1"))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.c.get("/v1/audit/bundle", headers=self.h("alice")).status_code, 403)
        r = self.c.get("/v1/audit/bundle?scope=bogus", headers=self.h("aud-1"))
        self.assertIn(r.status_code, (400, 422))
        r = self.c.get("/v1/audit/bundle?scope=action", headers=self.h("aud-1"))
        self.assertIn(r.status_code, (400, 422))

    # ---------- public surface ----------
    def test_public_endpoints_and_cosign(self):
        for i in range(6):
            self.propose("note.add", {"text": str(i)})
        cp = self.c.get("/public/acme/checkpoint").json()
        self.assertEqual(cp["tenant"] if "tenant" in cp else "acme", "acme")
        size = cp["size"]
        inc = self.c.get(f"/public/acme/inclusion/2?size={size}").json()
        root = base64.b64decode(cp["root"])
        self.assertTrue(tlog.verify_inclusion(bytes.fromhex(inc["leaf"]), 2, size, [bytes.fromhex(p) for p in inc["proof"]], root))
        cons = self.c.get("/public/acme/consistency?first=3").json()
        self.assertEqual(cons["second"], size)
        self.assertEqual(self.c.get("/public/ghost/checkpoint").status_code, 404)
        wk = Ed25519PrivateKey.generate()
        line = tlog.sign_cosignature_v1(tlog.split_note(cp["note"])[0], "w-x", wk, timestamp=1_760_000_000)
        r = self.c.post("/public/acme/cosign", json={"size": size, "line": line})
        self.assertEqual(r.status_code, 403)  # not a registered witness
        self.env.reg.set_witnesses("acme", {"w-x": base64.b64encode(tlog.public_bytes(wk.public_key())).decode()})
        r = self.c.post("/public/acme/cosign", json={"size": size, "line": line})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.c.get("/public/acme/checkpoint").json()["witnessed"], {"size": size, "witnesses": ["w-x"]})

    # ---------- operator ----------
    def test_platform_surface(self):
        plain = TestClient(create_app(self.env.reg))  # no platform key configured
        self.assertEqual(plain.get("/platform/tenants", headers={"X-Platform-Key": "op-key-123"}).status_code, 404)
        self.assertEqual(self.c.get("/platform/tenants").status_code, 401)
        self.assertEqual(self.c.get("/platform/tenants", headers={"X-Platform-Key": "wrong"}).status_code, 401)
        r = self.c.get("/platform/tenants", headers={"X-Platform-Key": "op-key-123"})
        self.assertEqual([t["tenant"] for t in r.json()["tenants"]], ["acme"])
        body = {"id": "gamma", "name": "Gamma", "profile": "pilot", "approvers": ["g1"], "agents": [{"name": "gb", "permissions": ["x"]}]}
        r = self.c.post("/platform/tenants", headers={"X-Platform-Key": "op-key-123"}, json=body)
        self.assertEqual(r.status_code, 200, r.text)
        keys = {k["name"]: k["key"] for k in r.json()["keys"]}
        self.assertEqual(self.c.get("/v1/me", headers={"X-API-Key": keys["g1"]}).json()["tenant"], "gamma")
        self.assertEqual(self.c.post("/platform/tenants", headers={"X-Platform-Key": "op-key-123"}, json=body).status_code, 409)
        self.assertEqual(self.c.get("/health").json()["tenants"], 2)


if __name__ == "__main__":
    unittest.main()
