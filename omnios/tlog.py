"""
tlog.py — witnessed transparency log primitives: an audit history an operator cannot quietly rewrite.
=====================================================================================================
Ported unchanged from the v1 gateway (core/tlog.py); in this platform ledger.py builds one log per customer on top of it,
witnessd.py is the witness, and verifier.py re-implements the verifying half with the standard library only.

  1. Every record becomes a leaf of an RFC 6962 / RFC 9162 Merkle tree (leaf = H(0x00 || data), node = H(0x01 || l || r)).
     In THIS platform the data is the record's canonical JSON text itself, so anyone holding a record can recompute its leaf.
  2. The log signs a CHECKPOINT (origin, tree size, root): a C2SP `tlog-checkpoint` body wrapped in a C2SP `signed-note`
     with an Ed25519 signature.
  3. A WITNESS (a separate process, run by someone other than the log's administrators) remembers the last checkpoint it saw.
     Before it countersigns a newer one it demands an RFC 9162 CONSISTENCY PROOF that the old tree is a prefix of the new one.
     If history was rewritten no valid proof exists, the witness refuses, and the rewrite is exposed.

Honest limits (state them, don't hide them):
  • A witness only proves the log did not fork or rewrite what the witness already saw. It does not prove each record was
    correct or complete, or that actions were not left out before logging.
  • A witness run by the log's own administrator proves nothing about that administrator.
  • Witness cosignatures come in two formats: a plain Ed25519 signed-note line, and the C2SP `tlog-cosignature`
    `cosignature/v1` format (signature type 0x04, signed message "cosignature/v1
time <t>
" + checkpoint body, 76-byte
    payload). The second is implemented from the published spec and tested against our own implementation only: it has NOT
    been tested against a third-party C2SP witness — do not claim interoperability yet.

Prior art — never claim novelty: Certificate Transparency (RFC 6962 / RFC 9162), Sigstore Rekor, transparency.dev / C2SP,
Crosby & Wallach (USENIX Security 2009).

Dependencies: stdlib + `cryptography`.
"""
from __future__ import annotations

import base64
import hashlib
import re
import time
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_EM_DASH = "—"
SIG_TYPE_ED25519 = b"\x01"
SIG_TYPE_COSIGNATURE_V1 = b"\x04"          # C2SP tlog-cosignature: timestamped Ed25519 cosignature


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(data: bytes) -> bytes:
    """RFC 6962 §2.1: MTH({d}) = SHA-256(0x00 || d)."""
    return _h(b"\x00" + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 §2.1: SHA-256(0x01 || left || right)."""
    return _h(b"\x01" + left + right)


EMPTY_ROOT = _h(b"")


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


_MEMO_MIN = 64      # memoize only PERFECT aligned subtrees of at least this many leaves (~n/32 entries)


class LogView:
    """View of an append-only log, given its already-hashed leaves (see `leaf_hash`).

    Long-lived views are cheap to keep current: `extend` appends new leaves, and the hash of any
    perfect aligned subtree is computed once and remembered. That is sound only because the log is
    append-only — a leaf already in the view must never change. A fresh process rebuilds from the
    stored log, so an in-place rewrite of storage is picked up on restart, not mid-run."""

    def __init__(self, leaves: list[bytes]) -> None:
        self.leaves = list(leaves)
        self._memo: dict[tuple[int, int], bytes] = {}

    def __len__(self) -> int:
        return len(self.leaves)

    def extend(self, leaves: list[bytes]) -> None:
        self.leaves.extend(leaves)

    def _mth(self, lo: int, hi: int) -> bytes:
        n = hi - lo
        if n == 0:
            return EMPTY_ROOT
        if n == 1:
            return self.leaves[lo]
        perfect = n >= _MEMO_MIN and n & (n - 1) == 0 and lo % n == 0
        if perfect:
            hit = self._memo.get((lo, n))
            if hit is not None:
                return hit
        k = _split(n)
        h = node_hash(self._mth(lo, lo + k), self._mth(lo + k, hi))
        if perfect:
            self._memo[(lo, n)] = h
        return h

    def root(self, size: Optional[int] = None) -> bytes:
        size = len(self.leaves) if size is None else size
        if not 0 <= size <= len(self.leaves):
            raise ValueError(f"size {size} out of range 0..{len(self.leaves)}")
        return self._mth(0, size)

    def inclusion_proof(self, index: int, size: Optional[int] = None) -> list[bytes]:
        """RFC 9162 §2.1.3.1 audit path for leaf `index` in the tree of the first `size` leaves."""
        size = len(self.leaves) if size is None else size
        if not 0 <= index < size <= len(self.leaves):
            raise ValueError(f"index {index} / size {size} out of range")

        def path(m: int, lo: int, hi: int) -> list[bytes]:
            n = hi - lo
            if n == 1:
                return []
            k = _split(n)
            if m < k:
                return path(m, lo, lo + k) + [self._mth(lo + k, hi)]
            return path(m - k, lo + k, hi) + [self._mth(lo, lo + k)]

        return path(index, 0, size)

    def consistency_proof(self, first: int, second: Optional[int] = None) -> list[bytes]:
        """RFC 9162 §2.1.4.1: proof that the tree of size `first` is a prefix of the tree of size
        `second`. Empty when first == second (or first == 0)."""
        second = len(self.leaves) if second is None else second
        if not 0 <= first <= second <= len(self.leaves):
            raise ValueError(f"need 0 <= first({first}) <= second({second}) <= {len(self.leaves)}")
        if first == 0 or first == second:
            return []

        def sub(m: int, lo: int, hi: int, complete: bool) -> list[bytes]:
            n = hi - lo
            if m == n:
                return [] if complete else [self._mth(lo, hi)]
            k = _split(n)
            if m <= k:
                return sub(m, lo, lo + k, complete) + [self._mth(lo + k, hi)]
            return sub(m - k, lo + k, hi, False) + [self._mth(lo, lo + k)]

        return sub(first, 0, second, True)


def verify_inclusion(leaf: bytes, index: int, size: int, proof: list[bytes], root: bytes) -> bool:
    """RFC 9162 §2.1.3.2. `leaf` is the already-hashed leaf."""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes,
                       proof: list[bytes]) -> bool:
    """RFC 9162 §2.1.4.2: is the tree (first, first_root) a prefix of (second, second_root)?"""
    if first < 0 or first > second:
        return False
    if first == second:
        return not proof and first_root == second_root
    if first == 0:                       # everything extends the empty tree
        return not proof
    if not proof:
        return False
    path = list(proof)
    if first & (first - 1) == 0:         # first is an exact power of two
        path = [first_root] + path
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0


# ───────────────────────── C2SP signed-note + tlog-checkpoint ─────────────────────────
def public_bytes(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(name: str, pub: bytes) -> bytes:
    """C2SP signed-note: SHA-256(name || 0x0A || 0x01 || 32-byte Ed25519 pubkey)[:4]."""
    return _h(name.encode("utf-8") + b"\n" + SIG_TYPE_ED25519 + pub)[:4]


def cosig_key_id(name: str, pub: bytes) -> bytes:
    """C2SP tlog-cosignature: SHA-256(name || 0x0A || 0x04 || 32-byte Ed25519 pubkey)[:4]."""
    return _h(name.encode("utf-8") + b"\n" + SIG_TYPE_COSIGNATURE_V1 + pub)[:4]


def cosig_v1_message(checkpoint_body: str, timestamp: int) -> bytes:
    """The exact bytes a cosigner signs: 'cosignature/v1\ntime <decimal t>\n' + the checkpoint body
    (origin, size, root — every line newline-terminated, no signature lines)."""
    return f"cosignature/v1\ntime {timestamp}\n{checkpoint_body}".encode("utf-8")


def _check_name(name: str) -> None:
    if not name or re.search(r"[\s+]", name):
        raise ValueError("key/origin names must be non-empty and contain no spaces or '+'")


def checkpoint_text(origin: str, size: int, root: bytes) -> str:
    """C2SP tlog-checkpoint body: origin / decimal size / base64 root, each line ending in \\n."""
    _check_name(origin)
    return f"{origin}\n{size}\n{base64.b64encode(root).decode('ascii')}\n"


def parse_checkpoint(text: str) -> tuple[str, int, bytes]:
    lines = text.split("\n")
    if len(lines) < 4 or lines[-1] != "" or not lines[0] or not lines[1] or not lines[2]:
        raise ValueError("malformed checkpoint")
    if not re.fullmatch(r"0|[1-9][0-9]*", lines[1]):
        raise ValueError("tree size must be decimal without leading zeroes")
    root = base64.b64decode(lines[2], validate=True)
    if len(root) != 32:
        raise ValueError("root hash must be 32 bytes")
    return lines[0], int(lines[1]), root


def sign_line(text: str, name: str, priv: Ed25519PrivateKey) -> str:
    """One signed-note signature line: '— <name> <base64(keyid || signature)>\\n'."""
    _check_name(name)
    pub = public_bytes(priv.public_key())
    payload = key_id(name, pub) + priv.sign(text.encode("utf-8"))
    return f"{_EM_DASH} {name} {base64.b64encode(payload).decode('ascii')}\n"


def sign_cosignature_v1(text: str, name: str, priv: Ed25519PrivateKey,
                        timestamp: Optional[int] = None) -> str:
    """A C2SP cosignature/v1 signature line: '— <name> <base64(keyid(4) || timestamp(8, big-endian) ||
    ed25519 signature(64))>\n'."""
    _check_name(name)
    ts = int(time.time()) if timestamp is None else int(timestamp)
    if not 0 <= ts < 2 ** 63:
        raise ValueError("timestamp out of range")
    pub = public_bytes(priv.public_key())
    sig = priv.sign(cosig_v1_message(text, ts))
    payload = cosig_key_id(name, pub) + ts.to_bytes(8, "big") + sig
    return f"{_EM_DASH} {name} {base64.b64encode(payload).decode('ascii')}\n"


def verify_cosignature_v1(line: str, text: str, trusted: dict[str, bytes]) -> Optional[tuple[str, int]]:
    """Verify one cosignature/v1 line over checkpoint body `text` against TRUSTED {name: pubkey}.
    Returns (name, timestamp) on success, None otherwise (unknown signer, wrong key id, bad length,
    bad signature)."""
    m = re.fullmatch(_EM_DASH + r" (\S+) (\S+)", line.rstrip("\n"))
    if not m:
        return None
    name = m.group(1)
    try:
        payload = base64.b64decode(m.group(2), validate=True)
    except ValueError:
        return None
    pub = trusted.get(name)
    if pub is None or len(payload) != 4 + 8 + 64 or payload[:4] != cosig_key_id(name, pub):
        return None
    ts = int.from_bytes(payload[4:12], "big")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(payload[12:], cosig_v1_message(text, ts))
    except InvalidSignature:
        return None
    return name, ts


def sign_note(text: str, name: str, priv: Ed25519PrivateKey) -> str:
    if not text.endswith("\n"):
        raise ValueError("note text must end with a newline")
    return text + "\n" + sign_line(text, name, priv)


def add_signature(note: str, line: str) -> str:
    return note if line in note else note + line


def split_note(note: str) -> tuple[str, list[tuple[str, bytes]]]:
    """Return (text, [(name, base64-decoded signature payload), ...])."""
    idx = note.rfind("\n\n")
    if idx < 0:
        raise ValueError("no signature block")
    text, sigs = note[:idx + 1], note[idx + 2:]
    out: list[tuple[str, bytes]] = []
    for line in sigs.split("\n"):
        if not line:
            continue
        m = re.fullmatch(_EM_DASH + r" (\S+) (\S+)", line)
        if not m:
            raise ValueError("malformed signature line")
        out.append((m.group(1), base64.b64decode(m.group(2), validate=True)))
    if not out:
        raise ValueError("no signatures")
    return text, out


def verify_note(note: str, trusted: dict[str, bytes]) -> tuple[str, set[str]]:
    """Verify a signed note against TRUSTED keys {name: raw 32-byte Ed25519 pubkey}. Returns
    (text, names whose signature verified). Signatures by unknown names/keys are ignored."""
    text, sigs = split_note(note)
    ok: set[str] = set()
    for name, payload in sigs:
        pub = trusted.get(name)
        if pub is None or len(payload) < 5 or payload[:4] != key_id(name, pub):
            continue
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(payload[4:], text.encode("utf-8"))
            ok.add(name)
        except InvalidSignature:
            continue
    return text, ok


# ───────────────────────────────── witness ─────────────────────────────────
class WitnessRefusal(Exception):
    """The witness will not cosign: the log is inconsistent, shrank, forked, or is untrusted."""


class Witness:
    """Remembers, per log origin, the latest checkpoint it verified. Pure logic, no I/O: the CLI
    (`witness.py`) persists `state` and does the HTTP."""

    def __init__(self, name: str, priv: Ed25519PrivateKey,
                 trusted_logs: dict[str, tuple[str, bytes]],
                 state: Optional[dict[str, dict]] = None) -> None:
        _check_name(name)
        self.name, self.priv = name, priv
        self.trusted_logs = trusted_logs          # origin -> (log key name, log public key bytes)
        self.state: dict[str, dict] = state if state is not None else {}

    def cosign(self, note: str, proof: list[bytes], fmt: str = "note") -> str:
        """Verify the log's signed checkpoint and its consistency with what we last saw; on
        success remember it and return our signature line (`fmt` = "note" for the original plain
        signed-note signature, "v1" for a C2SP cosignature/v1). Raises WitnessRefusal otherwise."""
        if fmt not in ("note", "v1"):
            raise ValueError("fmt must be 'note' or 'v1'")
        try:
            text, _ = split_note(note)
            origin, size, root = parse_checkpoint(text)
        except (ValueError, Exception) as exc:
            raise WitnessRefusal(f"unparseable checkpoint: {exc}") from exc
        trust = self.trusted_logs.get(origin)
        if trust is None:
            raise WitnessRefusal(f"unknown log origin {origin!r}")
        key_name, pub = trust
        _, signers = verify_note(note, {key_name: pub})
        if key_name not in signers:
            raise WitnessRefusal("checkpoint is not signed by the pinned log key")
        prev = self.state.get(origin)
        if prev is not None:
            old_size, old_root = prev["size"], base64.b64decode(prev["root"])
            if size < old_size:
                raise WitnessRefusal(f"log SHRANK: was {old_size}, now {size} — history was truncated")
            if not verify_consistency(old_size, size, old_root, root, proof):
                raise WitnessRefusal(
                    f"INCONSISTENT: the tree we saw at size {old_size} is NOT a prefix of the tree "
                    f"at size {size} — history was rewritten or the log forked")
        self.state[origin] = {"size": size, "root": base64.b64encode(root).decode("ascii")}
        if fmt == "v1":
            return sign_cosignature_v1(text, self.name, self.priv)
        return sign_line(text, self.name, self.priv)

    def known_size(self, origin: str) -> int:
        return self.state.get(origin, {}).get("size", 0)
