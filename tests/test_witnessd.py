import calendar
import json
import os
import shutil
import tempfile
import unittest
import urllib.error
from urllib.parse import urlparse

import _util
from _util import Env, FakeClock
from fastapi.testclient import TestClient
from omnios import witnessd
from omnios.api import create_app
from omnios.ledger import Ledger

PERMS = ["notes:write"]


def at(y, m, d, h=12):
    return float(calendar.timegm((y, m, d, h, 0, 0)))


class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.client = TestClient(create_app(self.env.reg))
        self.wdir = tempfile.mkdtemp()
        info = witnessd.init_witness(self.wdir, "witness-1")
        self.wpub = info["public_key"]
        self.cfg_path = info["config_path"]
        self.key = self.env.rt.public_info()["log_public_key"]
        self.set_cfg(logs=[{"name": "acme", "url": "http://testserver", "tenant": "acme", "log_key": self.key, "post_cosign": True}])
        self.env.reg.set_witnesses("acme", {"witness-1": self.wpub})
        self.override = None          # a function(path) -> dict to serve something other than the real log
        self.clock = FakeClock(at(2025, 10, 5))

    def tearDown(self):
        self.client.close()
        self.env.close()
        shutil.rmtree(self.wdir, ignore_errors=True)

    def set_cfg(self, **kw):
        cfg = json.load(open(self.cfg_path, encoding="utf-8"))
        cfg.update(kw)
        json.dump(cfg, open(self.cfg_path, "w", encoding="utf-8"))

    def get(self, url):
        p = urlparse(url)
        path = p.path + ("?" + p.query if p.query else "")
        if self.override:
            out = self.override(path)
            if out is not None:
                return out
        r = self.client.get(path)
        if r.status_code != 200:
            raise urllib.error.HTTPError(url, r.status_code, "x", {}, None)
        return r.json()

    def post(self, url, body):
        r = self.client.post(urlparse(url).path, json=body)
        if r.status_code != 200:
            raise urllib.error.HTTPError(url, r.status_code, "x", {}, None)
        return r.json()

    def daemon(self):
        return witnessd.WitnessDaemon(self.cfg_path, get=self.get, post=self.post, clock=self.clock)

    def grow(self, n=3):
        for i in range(n):
            self.env.rt.engine.propose("ops-agent", "note.add", {"i": i}, permissions=PERMS)

    # ---------- setup ----------
    def test_init_is_idempotent_and_keeps_the_private_key_out_of_state(self):
        again = witnessd.init_witness(self.wdir, "witness-1")
        self.assertEqual(again["public_key"], self.wpub)
        d = self.daemon()
        d.check_log(d.cfg["logs"][0])
        self.assertNotIn(open(os.path.join(self.wdir, "witness.key")).read().strip(), open(os.path.join(self.wdir, "witness_state.json")).read())

    # ---------- checking ----------
    def test_first_check_then_growth_and_cosignature_stored(self):
        d = self.daemon()
        code, msg = d.check_log(d.cfg["logs"][0])
        self.assertEqual(code, 0, msg)
        self.assertIn("cosignature stored", msg)
        self.assertEqual(self.env.rt.ledger.witnessed()[1], ["witness-1"])
        self.grow()
        code, msg = d.check_log(d.cfg["logs"][0])
        self.assertEqual(code, 0, msg)
        self.assertEqual(self.env.rt.ledger.witnessed()[0], self.env.rt.ledger.size())
        code, msg = d.check_log(d.cfg["logs"][0])   # nothing new: same size, same root
        self.assertEqual(code, 0, msg)

    def test_state_survives_a_restart(self):
        d = self.daemon()
        d.check_log(d.cfg["logs"][0])
        known = d.state["logs"]["omnios/acme"]["size"]
        d2 = self.daemon()
        self.assertEqual(d2.state["logs"]["omnios/acme"]["size"], known)

    def test_unregistered_witness_is_told_so(self):
        self.env.rt.cfg["witnesses"] = {}
        d = self.daemon()
        code, msg = d.check_log(d.cfg["logs"][0])
        self.assertEqual(code, 0)
        self.assertIn("NOT stored", msg)

    def test_rewritten_history_is_refused_and_the_state_is_not_advanced(self):
        self.grow(4)
        d = self.daemon()
        self.assertEqual(d.check_log(d.cfg["logs"][0])[0], 0)
        known = d.state["logs"]["omnios/acme"]["size"]
        # the operator rebuilds the log with the real key and one record changed, then adds more
        alt = Ledger(os.path.join(self.wdir, "alt.db"), "acme", self.env.rt.log_key)
        for r in self.env.rt.ledger.records(0, 1000):
            body = json.loads(r["body"])
            data = dict(body["data"], x="rewritten") if r["seq"] == 2 else body["data"]
            alt.append(body["type"], data, at=body["at"])
        for i in range(3):
            alt.append("note", {"id": f"n{i}"}, at=1.0)
        cp = alt.checkpoint()
        cons_cache = {}

        def serve(path):
            if path.endswith("/checkpoint"):
                return cp
            if "/consistency" in path:
                return alt.consistency(known, alt.size())
            return None
        self.override = serve
        code, msg = d.check_log(d.cfg["logs"][0])
        self.assertEqual(code, 2, msg)
        self.assertIn("INCONSISTENT", msg)
        self.assertEqual(d.state["logs"]["omnios/acme"]["size"], known)
        self.assertTrue(d.state["history"][-1]["detail"].startswith("REFUSED"))
        # the honest log is still accepted afterwards
        self.override = None
        self.grow(2)
        self.assertEqual(d.check_log(d.cfg["logs"][0])[0], 0)

    def test_truncated_log_is_refused(self):
        self.grow(5)
        d = self.daemon()
        d.check_log(d.cfg["logs"][0])
        size = self.env.rt.ledger.size()
        cp = dict(self.env.rt.ledger.checkpoint())
        cp["note"] = self.env.rt.ledger.note_for_size(size - 3)
        cp["size"] = size - 3
        self.override = lambda p: cp if p.endswith("/checkpoint") else None
        code, msg = d.check_log(d.cfg["logs"][0])
        self.assertEqual(code, 2)
        self.assertIn("SHRANK", msg)

    def test_log_signed_by_another_key_is_refused(self):
        other = Env()
        try:
            other.rt.engine.propose("ops-agent", "note.add", {"i": 1}, permissions=PERMS)
            cp = other.rt.ledger.checkpoint()
            self.override = lambda p: cp if p.endswith("/checkpoint") else None
            d = self.daemon()
            code, msg = d.check_log(d.cfg["logs"][0])
            self.assertEqual(code, 2, msg)
            self.assertIn("not signed by the pinned log key", msg)
        finally:
            other.close()

    def test_unpinned_log_needs_explicit_tofu(self):
        self.set_cfg(logs=[{"name": "acme", "url": "http://testserver", "tenant": "acme", "log_key": "<fill in>"}])
        code, msg = self.daemon().check_log(self.daemon().cfg["logs"][0])
        self.assertEqual(code, 3)
        self.assertIn("TRUST ERROR", msg)
        self.set_cfg(logs=[{"name": "acme", "url": "http://testserver", "tenant": "acme", "log_key": "<fill in>", "tofu": True}])
        self.assertEqual(self.daemon().check_log(self.daemon().cfg["logs"][0])[0], 0)

    def test_unreachable_log(self):
        def down(path):
            raise urllib.error.URLError("connection refused")
        self.override = down
        d = self.daemon()
        code, msg = d.check_log(d.cfg["logs"][0])
        self.assertEqual(code, 4)
        self.assertFalse(d.state["history"][-1]["ok"])

    def test_poll_once_reports_the_worst_exit_code(self):
        self.set_cfg(logs=[
            {"name": "acme", "url": "http://testserver", "tenant": "acme", "log_key": self.key},
            {"name": "ghost", "url": "http://testserver", "tenant": "ghost", "log_key": self.key}])
        self.assertEqual(self.daemon().poll_once(), 4)

    # ---------- the monthly report ----------
    def run_checks(self, d, days, month_day_hour=(2025, 10)):
        for day in days:
            self.clock.t = at(month_day_hour[0], month_day_hour[1], day)
            self.assertEqual(d.check_log(d.cfg["logs"][0])[0], 0)
            self.grow(1)

    def test_report_clean_gaps_alert_and_no_coverage(self):
        self.set_cfg(max_gap_seconds=5 * 86400)
        d = self.daemon()
        self.run_checks(d, range(1, 31, 2))
        rep = d.monthly_report("2025-10")
        row = rep["logs"][0]
        self.assertEqual(row["verdict"], "CLEAN", row)
        self.assertEqual((row["refusals"], row["verified"]), (0, 15))
        self.assertGreater(row["last_size"], row["first_size"])
        self.assertEqual(d.monthly_report("2025-09")["logs"][0]["verdict"], "NO COVERAGE")

        d = self.daemon()
        d.state["history"] = []
        self.run_checks(d, [1, 2, 3, 20, 21])
        self.assertEqual(d.monthly_report("2025-10")["logs"][0]["verdict"], "GAPS")

        self.clock.t = at(2025, 10, 25)
        self.override = lambda p: {"note": "garbage", "size": 99, "origin": "omnios/acme", "key_name": "omnios/acme", "log_public_key": self.key} if p.endswith("/checkpoint") else None
        self.assertEqual(d.check_log(d.cfg["logs"][0])[0], 2)
        row = d.monthly_report("2025-10")["logs"][0]
        self.assertEqual((row["verdict"], row["refusals"]), ("ALERT", 1))

    def test_a_log_that_will_not_prove_growth_is_an_alert_but_an_outage_is_not(self):
        d = self.daemon()
        d.check_log(d.cfg["logs"][0])
        known = d.state["logs"]["omnios/acme"]["size"]
        self.grow(2)

        def broken(code):
            def serve(path):
                if "/consistency" in path:
                    raise urllib.error.HTTPError(path, code, "x", {}, None)
                return None
            return serve
        self.override = broken(404)
        code, msg = d.check_log(d.cfg["logs"][0])
        self.assertEqual(code, 2, msg)
        self.assertEqual(d.state["logs"]["omnios/acme"]["size"], known)
        self.override = broken(503)
        self.assertEqual(d.check_log(d.cfg["logs"][0])[0], 4)
        self.override = None
        self.assertEqual(d.check_log(d.cfg["logs"][0])[0], 0)

    def test_december_rolls_into_the_next_year(self):
        d = self.daemon()
        self.clock.t = at(2025, 12, 31, 23)
        d.check_log(d.cfg["logs"][0])
        self.assertEqual(d.monthly_report("2025-12")["logs"][0]["verified"], 1)
        self.assertEqual(d.monthly_report("2026-01")["logs"][0]["verified"], 0)

    def test_report_files(self):
        d = self.daemon()
        d.check_log(d.cfg["logs"][0])
        rep = d.monthly_report("2025-10")
        rep["logs"][0]["alerts"] = [{"at": at(2025, 10, 6), "detail": "REFUSED: <script>alert(1)</script>"}]
        out = witnessd.write_report(rep, os.path.join(self.wdir, "reports"))
        html = open(out["html"], encoding="utf-8").read()
        self.assertNotIn("<script>", html)
        self.assertIn("does <b>not</b> say that the records are correct", html)
        self.assertEqual(json.load(open(out["json"], encoding="utf-8"))["month"], "2025-10")


if __name__ == "__main__":
    unittest.main()
