"""
canonical.py — the ONE definition of "canonical JSON" and "digest" for the whole platform.
=========================================================================================
A ledger record is hashed over the exact bytes of its canonical JSON. Anyone who is shipped those bytes can
recompute the hash with any language (SHA-256 of the UTF-8 bytes); Python's own canonical form is only needed to
CHECK that shipped text is canonical. Keep this module tiny and dependency-free: the stand-alone verifier mirrors it.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canon(obj: Any) -> str:
    """Sorted keys, no whitespace, UTF-8 characters kept as they are."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def canon_bytes(obj: Any) -> bytes:
    return canon(obj).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj: Any) -> str:
    """SHA-256 (hex) of the canonical JSON of `obj`. Records carry DIGESTS of parameters and results, so the evidence
    can be bound to the real request without the ledger holding its content."""
    return sha256_hex(canon_bytes(obj))
