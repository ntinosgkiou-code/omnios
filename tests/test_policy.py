import copy
import unittest

import _util
from omnios.kv import MemoryKV
from omnios.policy import PolicyStore, eval_cond, policy_hash, validate_policy


class PolicyTests(unittest.TestCase):
    def test_the_test_policy_is_valid(self):
        self.assertEqual(validate_policy(_util.POLICY), [])

    def test_strictness(self):
        bad = copy.deepcopy(_util.POLICY)
        del bad["tools"]["payments.send"]["reversibility"]
        self.assertTrue(any("reversibility" in e for e in validate_policy(bad)))
        bad = copy.deepcopy(_util.POLICY)
        bad["tools"]["data.delete"]["risk"] = "low"
        self.assertTrue(any("irreversible" in e for e in validate_policy(bad)))
        bad = copy.deepcopy(_util.POLICY)
        bad["tools"]["payments.send"]["approvals"]["required"] = 9
        self.assertTrue(validate_policy(bad))
        bad = copy.deepcopy(_util.POLICY)
        bad["tools"]["payments.send"]["approvals"]["groups"] = "finance"
        self.assertTrue(any("groups" in e for e in validate_policy(bad)))

    def test_proxy_credentials_use_secret_not_env(self):
        base = {"version": 1, "tools": {"p": {"reversibility": "one_way_consequential", "risk": "high",
                                              "execution": {"mode": "proxy", "url": "https://bank.example/pay",
                                                            "headers": {"Authorization": "Bearer ${ENV:TOKEN}"}}}}}
        self.assertTrue(any("SECRET" in e for e in validate_policy(base)))
        base["tools"]["p"]["execution"]["headers"]["Authorization"] = "Bearer ${SECRET:TOKEN}"
        self.assertEqual(validate_policy(base), [])
        base["tools"]["p"]["execution"]["url"] = "http://bank.example/pay"
        self.assertTrue(any("https" in e for e in validate_policy(base)))

    def test_conditions_are_tri_state(self):
        gt = {"field": "amount_eur", "op": ">", "value": 100}
        self.assertTrue(eval_cond(gt, {"amount_eur": 250}))
        self.assertFalse(eval_cond(gt, {"amount_eur": "50"}))
        self.assertIsNone(eval_cond(gt, {}))
        self.assertIsNone(eval_cond(gt, {"amount_eur": "lots"}))
        self.assertIsNone(eval_cond(gt, {"amount_eur": True}))
        self.assertTrue(eval_cond({"any": [gt, {"field": "x", "op": "exists"}]}, {"x": 1}))
        self.assertFalse(eval_cond({"all": [gt, {"field": "x", "op": "exists"}]}, {"amount_eur": 1, "x": 1}))

    def test_numbers_are_read_strictly(self):
        from omnios.policy import num
        for ok in ("12", " 12.50 ", "-3", "+4", "1e3", ".5", "7."):
            self.assertIsNotNone(num(ok), ok)
        for bad in ("1_000", "١٢٣", "1,5", "NaN", "Infinity", "0x10", "1e999999", "", "  ", "12abc", "1e", True, float("inf"), 10 ** 60):
            self.assertIsNone(num(bad), bad)
        self.assertEqual(num(12.5), num("12.5"))

    def test_versions_and_hash(self):
        ps = PolicyStore(MemoryKV())
        self.assertEqual(ps.current()["n"], 0)
        a = ps.activate(_util.POLICY, "me", 1.0)
        changed = copy.deepcopy(_util.POLICY)
        changed["tools"]["note.add"]["description"] = "x"
        b = ps.activate(changed, "you", 2.0)
        self.assertEqual((a["n"], b["n"]), (1, 2))
        self.assertNotEqual(a["hash"], b["hash"])
        self.assertEqual(ps.current()["hash"], b["hash"])
        self.assertEqual([h["n"] for h in ps.history()], [1, 2])
        self.assertEqual(policy_hash(_util.POLICY), a["hash"])
        with self.assertRaises(ValueError):
            ps.activate({"version": 2, "tools": {}}, "me", 3.0)


if __name__ == "__main__":
    unittest.main()
