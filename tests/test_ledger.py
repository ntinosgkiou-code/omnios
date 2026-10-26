import base64
import os
import sqlite3
import tempfile
import unittest

import _util  # noqa: F401
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from omnios import ed25519_pure, tlog, verifier
from omnios.errors import OmniError
from omnios.ledger import Ledger


def _ledger(path=":memory:", key=None):
    return Ledger(path, "acme", key or Ed25519PrivateKey.generate())


class LedgerTests(unittest.TestCase):
    def test_leaf_is_the_record_text_so_a_third_party_can_check_it(self):
        led = _ledger()
        rec = led.append("action.proposed", {"id": "act-00001", "by": "alice"})
        row = led.records(0, 1)[0]
        self.assertEqual(tlog.leaf_hash(row["body"].encode("utf-8")).hex(), row["leaf"])
        inc = led.inclusion(0)
        root = base64.b64decode(led.checkpoint()["root"])
        self.assertTrue(tlog.verify_inclusion(bytes.fromhex(inc["leaf"]), 0, 1, [bytes.fromhex(p) for p in inc["proof"]], root))
        self.assertEqual(rec["rhash"], row["rhash"])

    def test_chain_inclusion_and_consistency_for_many_sizes(self):
        led = _ledger()
        roots = {}
        for i in range(1, 40):
            led.append("note", {"id": f"n{i}", "i": i})
            roots[led.size()] = base64.b64decode(led.checkpoint()["root"])
        n = led.size()
        for idx in (0, 1, 7, 8, 20, n - 1):
            inc = led.inclusion(idx)
            self.assertTrue(tlog.verify_inclusion(bytes.fromhex(inc["leaf"]), idx, n, [bytes.fromhex(p) for p in inc["proof"]], roots[n]))
        for first in (1, 2, 5, 8, 16, 25):
            c = led.consistency(first, n)
            self.assertTrue(tlog.verify_consistency(first, n, roots[first], roots[n], [base64.b64decode(p) for p in c["proof"]]))
        self.assertTrue(led.verify_integrity()["ok"])

    def test_checkpoint_is_a_valid_signed_note(self):
        key = Ed25519PrivateKey.generate()
        led = _ledger(key=key)
        led.append("a", {"id": "x"})
        cp = led.checkpoint()
        text, signers = tlog.verify_note(cp["note"], {cp["key_name"]: base64.b64decode(cp["log_public_key"])})
        self.assertEqual(signers, {cp["key_name"]})
        self.assertEqual(tlog.parse_checkpoint(text)[1], 1)

    def test_editing_the_database_is_detected(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "l.db")
        led = _ledger(path)
        for i in range(5):
            led.append("note", {"id": f"n{i}", "who": "alice"})
        led.checkpoint()
        self.assertTrue(led.verify_integrity()["ok"])
        con = sqlite3.connect(path)
        body = con.execute("SELECT body FROM records WHERE seq=2").fetchone()[0]
        con.execute("UPDATE records SET body=? WHERE seq=2", (body.replace("alice", "mallory"),))
        con.commit()
        con.close()
        res = Ledger(path, "acme", Ed25519PrivateKey.generate()).verify_integrity()
        self.assertFalse(res["ok"])
        self.assertTrue(any("record 2" in p for p in res["problems"]))

    def test_reopening_keeps_history_and_chain(self):
        d = tempfile.mkdtemp()
        path, key = os.path.join(d, "l.db"), Ed25519PrivateKey.generate()
        a = Ledger(path, "acme", key)
        a.append("one", {"id": "1"})
        a.append("two", {"id": "2"})
        b = Ledger(path, "acme", key)
        b.append("three", {"id": "3"})
        self.assertEqual(b.size(), 3)
        self.assertTrue(b.verify_integrity()["ok"])

    def test_a_second_writer_on_the_same_file_fails_closed_instead_of_forking(self):
        d = tempfile.mkdtemp()
        path, key = os.path.join(d, "l.db"), Ed25519PrivateKey.generate()
        a, b = Ledger(path, "acme", key), Ledger(path, "acme", key)
        a.append("one", {"id": "1"})
        with self.assertRaises(OmniError) as cm:
            b.append("other", {"id": "2"})       # b still believes the log is empty
        self.assertEqual((cm.exception.status, cm.exception.code), (503, "ledger_unavailable"))
        self.assertEqual(a.size(), 1)
        self.assertTrue(Ledger(path, "acme", key).verify_integrity()["ok"])

    def test_cosignature_only_from_a_trusted_witness(self):
        led = _ledger()
        led.append("a", {"id": "x"})
        led.append("b", {"id": "y"})
        wk = Ed25519PrivateKey.generate()
        wpub = tlog.public_bytes(wk.public_key())
        text, _ = tlog.split_note(led.note_for_size(2))
        line = tlog.sign_cosignature_v1(text, "w1", wk, timestamp=1_760_000_000)
        r = led.add_cosignature(2, line, {"w1": wpub})
        self.assertEqual(r["witness"], "w1")
        self.assertEqual(led.witnessed(), (2, ["w1"]))
        with self.assertRaises(OmniError) as cm:
            led.add_cosignature(2, line, {"other": wpub})
        self.assertEqual(cm.exception.status, 403)
        stranger = tlog.sign_cosignature_v1(text, "w1", Ed25519PrivateKey.generate())
        with self.assertRaises(OmniError):
            led.add_cosignature(2, stranger, {"w1": wpub})

    def test_pure_python_ed25519_agrees_with_cryptography(self):
        for i in range(5):
            k = Ed25519PrivateKey.generate()
            pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            msg = os.urandom(40 + i)
            sig = k.sign(msg)
            for fn in (ed25519_pure.verify, verifier._ed25519_pure):
                self.assertTrue(fn(pub, msg, sig))
                self.assertFalse(fn(pub, msg + b"x", sig))
                bad = bytearray(sig)
                bad[3] ^= 1
                self.assertFalse(fn(pub, msg, bytes(bad)))

    def test_standalone_verifier_functions_match_tlog(self):
        led = _ledger()
        for i in range(13):
            led.append("n", {"id": str(i)})
        n = led.size()
        root = base64.b64decode(led.checkpoint()["root"])
        inc = led.inclusion(6)
        self.assertTrue(verifier.verify_inclusion(bytes.fromhex(inc["leaf"]), 6, n, [bytes.fromhex(p) for p in inc["proof"]], root))
        self.assertFalse(verifier.verify_inclusion(bytes.fromhex(inc["leaf"]), 5, n, [bytes.fromhex(p) for p in inc["proof"]], root))


if __name__ == "__main__":
    unittest.main()
