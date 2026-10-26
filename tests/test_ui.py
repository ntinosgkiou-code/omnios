import re
import unittest

import _util
from _util import Env
from fastapi.testclient import TestClient
from omnios.api import create_app


class UiTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()

    def tearDown(self):
        self.env.close()

    def test_ui_is_served_with_safe_headers_and_no_external_resources(self):
        c = TestClient(create_app(self.env.reg))
        r = c.get("/ui")
        self.assertEqual(r.status_code, 200)
        self.assertIn("OmniOS", r.text)
        self.assertIn("default-src 'self'", r.headers["content-security-policy"])
        self.assertEqual(r.headers["cache-control"], "no-store")
        self.assertEqual(re.findall(r'(?:src|href)=["\']https?://', r.text), [])          # nothing loaded from outside
        self.assertNotIn("cdn.", r.text)

    def test_every_text_exists_in_both_languages_and_the_observe_tab_is_wired(self):
        html = TestClient(create_app(self.env.reg)).get("/ui").text
        el_block = html[html.index("el: {"):html.index("en: {")]
        en_block = html[html.index("en: {"):html.index("const STATUS")]
        keys = lambda block: set(re.findall(r'(?:^ |, ?)([a-z][a-z0-9_]*):"', block, re.M))
        self.assertEqual(keys(el_block) ^ keys(en_block), set(), "a text is missing in one language")
        self.assertIn("t_obs", keys(el_block))
        self.assertIn('["obs","t_obs"]', html)
        for fn in ("vObs", "loadObs", "openObsReport", "sendObs"):
            self.assertIn("function " + fn if fn != "sendObs" else "async function sendObs", html)
        for key in set(re.findall(r'\bt\("([a-z][a-z0-9_]*)"\)', html)):
            self.assertIn(key, keys(el_block), f"t('{key}') has no text")

    def test_demo_keys_exist_only_when_the_launcher_asks(self):
        self.assertEqual(TestClient(create_app(self.env.reg)).get("/ui/demo-keys").status_code, 404)
        c = TestClient(create_app(self.env.reg, demo_keys=[{"name": "x", "role": "agent", "key": "k", "label": "x"}]))
        self.assertEqual(c.get("/ui/demo-keys").json()["keys"][0]["name"], "x")

    def test_evidence_response_carries_the_size_the_proofs_refer_to(self):
        c = TestClient(create_app(self.env.reg))
        a = c.post("/v1/actions", headers={"X-API-Key": self.env.key["ops-agent"]}, json={"tool": "note.add", "params": {"t": 1}}).json()
        ev = c.get(f"/v1/audit/evidence/{a['id']}", headers={"X-API-Key": self.env.key["aud-1"]}).json()
        self.assertEqual(ev["size"], ev["checkpoint"]["size"])
        self.assertTrue(ev["records"][0]["inclusion"] is not None)


if __name__ == "__main__":
    unittest.main()
