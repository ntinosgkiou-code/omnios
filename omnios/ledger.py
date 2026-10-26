"""
ledger.py — a tenant's append-only evidence ledger.
====================================================
THE design change from v1: the Merkle leaf is the RECORD ITSELF (SHA-256 over its canonical JSON bytes), not an HMAC
output only the operator can reproduce. So a third party who is shipped a record can check three things with no secret:

    1. the record text hashes to the leaf the tree contains            (what it SAYS is what was committed)
    2. the leaf is in the tree whose root a signed checkpoint states    (inclusion proof, RFC 9162)
    3. the checkpoint was signed by the log key, and cosigned by witnesses who verified it only ever grew

Each record also carries `prev`, the hash of the previous record, so the chain is publicly checkable too. Records hold
identifiers and DIGESTS (never raw parameters), which is why records can be given to an auditor.

One ledger = one customer. Its own SQLite file, its own Ed25519 signing key, its own checkpoints and witnesses.
Honest limits: the operator can still rewrite the whole file; what stops it from doing so UNNOTICED is a witness that
already saw an earlier checkpoint. If the ledger cannot write, nothing proceeds (no evidence, no action).
"""
from __future__ import annotations

import base64
import json
import sqlite3
import threading
import time
from typing import Callable, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import tlog
from .canonical import canon, sha256_hex
from .errors import OmniError

GENESIS = "0" * 64
FORMAT_VERSION = 1


class Ledger:
    def __init__(self, path: str, tenant: str, signing_key: Ed25519PrivateKey, *,
                 clock: Callable[[], float] = time.time) -> None:
        self.tenant = tenant
        self.origin = f"omnios/{tenant}"
        tlog._check_name(self.origin)
        self._key = signing_key
        self.public_key = tlog.public_bytes(signing_key.public_key())
        self._clock = clock
        self._lock = threading.RLock()
        self._con = sqlite3.connect(path, check_same_thread=False)
        if path != ":memory:":
            self._con.execute("PRAGMA journal_mode=WAL")
            self._con.execute("PRAGMA busy_timeout=5000")
        with self._lock:
            self._con.executescript("""
                CREATE TABLE IF NOT EXISTS records (seq INTEGER PRIMARY KEY, type TEXT NOT NULL, body TEXT NOT NULL,
                                                    rhash TEXT NOT NULL, leaf BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS refs (ref TEXT NOT NULL, seq INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS refs_ref ON refs(ref);
                CREATE TABLE IF NOT EXISTS checkpoints (size INTEGER PRIMARY KEY, root BLOB NOT NULL, note TEXT NOT NULL,
                                                        created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS cosigs (size INTEGER NOT NULL, witness TEXT NOT NULL, line TEXT NOT NULL,
                                                   ts INTEGER NOT NULL, PRIMARY KEY(size, witness));
            """)
            self._con.commit()
            rows = self._con.execute("SELECT leaf, rhash FROM records ORDER BY seq").fetchall()
        self._view = tlog.LogView([bytes(r[0]) for r in rows])
        self._last_rhash = rows[-1][1] if rows else GENESIS

    def close(self) -> None:
        with self._lock:
            self._con.close()

    # ---- writing ----
    def append(self, rtype: str, data: dict, at: Optional[float] = None) -> dict:
        """Add one record. Raises OmniError(503) if it cannot be written: callers must stop, never carry on unlogged."""
        with self._lock:
            seq = len(self._view)
            rec = {"v": FORMAT_VERSION, "seq": seq, "tenant": self.tenant, "type": rtype,
                   "at": round(self._clock() if at is None else at, 3), "prev": self._last_rhash, "data": data}
            body = canon(rec)
            raw = body.encode("utf-8")
            rhash, leaf = sha256_hex(raw), tlog.leaf_hash(raw)
            try:
                self._con.execute("INSERT INTO records(seq,type,body,rhash,leaf) VALUES(?,?,?,?,?)",
                                  (seq, rtype, body, rhash, leaf))
                ref = data.get("id") if isinstance(data, dict) else None
                if isinstance(ref, str):
                    self._con.execute("INSERT INTO refs(ref,seq) VALUES(?,?)", (ref, seq))
                self._con.commit()
            except sqlite3.Error as exc:
                self._con.rollback()
                raise OmniError(503, "ledger_unavailable", type(exc).__name__) from exc
            self._view.extend([leaf])
            self._last_rhash = rhash
            return {**rec, "rhash": rhash}

    # ---- reading ----
    def size(self) -> int:
        with self._lock:
            return len(self._view)

    def records(self, start: int = 0, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._con.execute("SELECT seq,type,body,rhash,leaf FROM records WHERE seq>=? ORDER BY seq LIMIT ?",
                                     (max(0, start), max(1, min(limit, 5000)))).fetchall()
        return [{"seq": s, "type": t, "body": b, "rhash": h, "leaf": bytes(lf).hex()} for s, t, b, h, lf in rows]

    def iter_records(self, start: int = 0, page: int = 1000):
        """Every record from `start` to the end, in order, a page at a time (`records` caps one call at 5,000)."""
        while True:
            rows = self.records(start, page)
            if not rows:
                return
            yield from rows
            start = rows[-1]["seq"] + 1

    def by_ref(self, ref: str) -> list[dict]:
        """All records about one action / change (the records whose data.id is `ref`), in order."""
        with self._lock:
            seqs = [r[0] for r in self._con.execute("SELECT seq FROM refs WHERE ref=? ORDER BY seq", (ref,))]
            out = []
            for s in seqs:
                row = self._con.execute("SELECT seq,type,body,rhash,leaf FROM records WHERE seq=?", (s,)).fetchone()
                out.append({"seq": row[0], "type": row[1], "body": row[2], "rhash": row[3], "leaf": bytes(row[4]).hex()})
        return out

    def by_type(self, *prefixes: str) -> list[dict]:
        """All records whose type starts with one of `prefixes` (e.g. "policy.", "change."), in order."""
        with self._lock:
            rows = self._con.execute("SELECT seq,type,body,rhash,leaf FROM records ORDER BY seq").fetchall()
        return [{"seq": s, "type": t, "body": b, "rhash": h, "leaf": bytes(lf).hex()}
                for s, t, b, h, lf in rows if any(t.startswith(p) for p in prefixes)]

    def witnessed_sizes(self) -> list[int]:
        with self._lock:
            return [r[0] for r in self._con.execute("SELECT DISTINCT size FROM cosigs ORDER BY size")]

    def latest_cosig_sizes(self) -> dict:
        """{witness: the largest checkpoint size that witness has cosigned}."""
        with self._lock:
            return {w: int(s) for w, s in self._con.execute("SELECT witness, MAX(size) FROM cosigs GROUP BY witness")}

    # ---- checkpoints and proofs ----
    def note_for_size(self, size: int) -> str:
        """The signed checkpoint (a C2SP signed note) for the tree of the first `size` records."""
        with self._lock:
            if not 0 <= size <= len(self._view):
                raise OmniError(404, "size_out_of_range", f"0..{len(self._view)}")
            row = self._con.execute("SELECT note FROM checkpoints WHERE size=?", (size,)).fetchone()
            if row:
                return row[0]
            root = self._view.root(size)
            note = tlog.sign_note(tlog.checkpoint_text(self.origin, size, root), self.origin, self._key)
            self._con.execute("INSERT OR IGNORE INTO checkpoints(size,root,note,created) VALUES(?,?,?,?)",
                              (size, root, note, self._clock()))
            self._con.commit()
            return self._con.execute("SELECT note FROM checkpoints WHERE size=?", (size,)).fetchone()[0]

    def checkpoint(self) -> dict:
        with self._lock:
            size = len(self._view)
            note = self.note_for_size(size)
            wsize, wnames = self.witnessed()
            return {"tenant": self.tenant, "origin": self.origin, "key_name": self.origin, "size": size,
                    "root": base64.b64encode(self._view.root()).decode("ascii"), "note": note,
                    "log_public_key": base64.b64encode(self.public_key).decode("ascii"),
                    "witnessed": {"size": wsize, "witnesses": wnames} if wsize else None}

    def inclusion(self, index: int, size: Optional[int] = None) -> dict:
        with self._lock:
            size = len(self._view) if size is None else size
            if not 0 <= index < size <= len(self._view):
                raise OmniError(404, "index_or_size_out_of_range")
            proof = self._view.inclusion_proof(index, size)
            return {"index": index, "size": size, "leaf": self._view.leaves[index].hex(),
                    "proof": [p.hex() for p in proof], "note": self.note_for_size(size)}

    def consistency(self, first: int, second: Optional[int] = None) -> dict:
        with self._lock:
            second = len(self._view) if second is None else second
            if not 0 <= first <= second <= len(self._view):
                raise OmniError(404, "sizes_out_of_range")
            return {"first": first, "second": second, "proof": [base64.b64encode(p).decode("ascii")
                                                               for p in self._view.consistency_proof(first, second)]}

    # ---- witnesses ----
    def add_cosignature(self, size: int, line: str, trusted: dict[str, bytes]) -> dict:
        """Store a witness cosignature for the checkpoint at `size`, only if a TRUSTED witness key really signed it."""
        if size < 1:
            raise OmniError(422, "size_must_be_positive")
        with self._lock:
            text, _ = tlog.split_note(self.note_for_size(size))
            hit = tlog.verify_cosignature_v1(line, text, trusted)
            if hit:
                name, ts = hit
            else:
                _, ok = tlog.verify_note(text + "\n" + line, trusted)
                name, ts = (sorted(ok)[0], int(self._clock())) if ok else (None, 0)
            if not name:
                raise OmniError(403, "cosignature_not_accepted", "unknown witness key or bad signature")
            self._con.execute("INSERT INTO cosigs(size,witness,line,ts) VALUES(?,?,?,?) "
                              "ON CONFLICT(size,witness) DO UPDATE SET line=excluded.line, ts=excluded.ts",
                              (size, name, line.rstrip("\n") + "\n", ts))
            self._con.commit()
            return {"witness": name, "size": size, "timestamp": ts}

    def cosignatures(self, size: int) -> list[dict]:
        with self._lock:
            rows = self._con.execute("SELECT witness,line,ts FROM cosigs WHERE size=? ORDER BY witness", (size,)).fetchall()
        return [{"witness": w, "line": ln, "timestamp": ts} for w, ln, ts in rows]

    def witnessed(self) -> tuple[int, list[str]]:
        """(largest size any witness has cosigned, the witnesses who cosigned that size)."""
        with self._lock:
            row = self._con.execute("SELECT MAX(size) FROM cosigs").fetchone()
            if not row or row[0] is None:
                return 0, []
            names = [r[0] for r in self._con.execute("SELECT witness FROM cosigs WHERE size=? ORDER BY witness", (row[0],))]
        return int(row[0]), names

    def note_with_cosignatures(self, size: int) -> str:
        note = self.note_for_size(size)
        for c in self.cosignatures(size):
            note = tlog.add_signature(note, c["line"])
        return note

    # ---- self-check ----
    def verify_integrity(self) -> dict:
        """Re-derive everything from the stored text: canonical form, chain, leaves, and every stored checkpoint root.
        Detects an edit of the database file by anyone who did not also redo all of it."""
        problems: list[str] = []
        with self._lock:
            rows = self._con.execute("SELECT seq,body,rhash,leaf FROM records ORDER BY seq").fetchall()
            cps = self._con.execute("SELECT size,root FROM checkpoints ORDER BY size").fetchall()
        prev, leaves = GENESIS, []
        for i, (seq, body, rhash, leaf) in enumerate(rows):
            raw = body.encode("utf-8")
            try:
                rec = json.loads(body)
            except ValueError:
                problems.append(f"record {i}: not JSON")
                break
            if seq != i or rec.get("seq") != i:
                problems.append(f"record {i}: sequence is {seq}/{rec.get('seq')}")
            if canon(rec) != body:
                problems.append(f"record {i}: text is not canonical")
            if rec.get("prev") != prev:
                problems.append(f"record {i}: chain link (prev) does not match the previous record")
            if sha256_hex(raw) != rhash:
                problems.append(f"record {i}: stored hash differs from the text")
            lf = tlog.leaf_hash(raw)
            if lf != bytes(leaf):
                problems.append(f"record {i}: stored leaf differs from the text")
            leaves.append(lf)
            prev = rhash
        view = tlog.LogView(leaves)
        for size, root in cps:
            if size > len(view) or view.root(size) != bytes(root):
                problems.append(f"checkpoint at size {size} does not match the records")
        return {"ok": not problems, "records": len(rows), "checkpoints": len(cps), "problems": problems[:20]}
