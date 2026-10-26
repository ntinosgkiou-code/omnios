"""
identity.py — who may talk to a tenant, and as what.
====================================================
Roles:  agent     proposes actions and reports what it did            (cannot approve anything)
        approver  approves / rejects / undoes actions                  (a human; N distinct approvers can be required)
        admin     proposes changes to rules and keys                   (changes need other admins: see engine.py)
        auditor   read-only: records, evidence, bundles                (cannot change or approve anything)

A key looks like  ogk_<tenant>_<random>.  The tenant is IN the key, so a request is routed to the right customer before
anything is looked up, and a key issued for one tenant can never be presented to another (it is rejected on its prefix,
and would not be found in the other tenant's database anyway). Only a SHA-256 of each key is stored.

Identity (who proposed, who approved) always comes from here, never from a request body. Honest limit: keys are bearer
secrets with no SSO or MFA yet (register item A4); the `Principal` object is the seam where an OIDC login plugs in.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import threading
import time
from typing import Any, Optional

ROLES = ("agent", "approver", "admin", "auditor")
NAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$")
KEY_RE = re.compile(r"^ogk_([a-z0-9][a-z0-9-]{1,30}[a-z0-9])_[A-Za-z0-9_-]{20,}$")
_NS, _NS_HASH = "principals", "principal_by_hash"


class Principal:
    __slots__ = ("name", "role", "permissions", "groups", "tenant")

    def __init__(self, tenant: str, name: str, role: str, permissions: Any = (), groups: Any = ()) -> None:
        self.tenant, self.name, self.role = tenant, name, role
        self.permissions, self.groups = sorted(set(permissions or ())), sorted(set(groups or ()))

    def public(self) -> dict:
        return {"tenant": self.tenant, "name": self.name, "role": self.role,
                "permissions": self.permissions, "groups": self.groups}


def key_tenant(key: Optional[str]) -> Optional[str]:
    """The tenant a key claims to belong to (None if it is not shaped like a key)."""
    m = KEY_RE.match(key or "")
    return m.group(1) if m else None


def _sha(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class IdentityStore:
    def __init__(self, kv: Any, tenant: str, clock: Any = time.time) -> None:
        self._kv, self.tenant, self._clock = kv, tenant, clock
        self._lock = threading.Lock()

    def prepare(self, name: str, role: str, permissions: Any = (), groups: Any = ()) -> tuple[dict, str]:
        """Validate and mint a key WITHOUT activating it. Returns (record, key); the key is shown once to its holder."""
        if not NAME_RE.match(name or ""):
            raise ValueError("name: letters, digits and _ . @ - only (max 64)")
        if role not in ROLES:
            raise ValueError(f"role must be one of {list(ROLES)}")
        for g in groups or ():
            if not isinstance(g, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", g):
                raise ValueError("groups: letters, digits and _ . - only (max 40)")
        key = f"ogk_{self.tenant}_{secrets.token_urlsafe(24)}"
        rec = {"name": name, "role": role, "permissions": sorted(set(permissions or ())),
               "groups": sorted(set(groups or ())), "key_sha256": _sha(key), "created": self._clock()}
        return rec, key

    def activate(self, rec: dict) -> None:
        with self._lock:
            old = self._kv.get(_NS, rec["name"])
            if old:
                self._kv.delete(_NS_HASH, old["key_sha256"])
            self._kv.put(_NS, rec["name"], rec)
            self._kv.put(_NS_HASH, rec["key_sha256"], {"name": rec["name"]})

    def create(self, name: str, role: str, permissions: Any = (), groups: Any = ()) -> str:
        """Prepare + activate in one step. Used by provisioning (an operator action, recorded by the caller)."""
        rec, key = self.prepare(name, role, permissions, groups)
        self.activate(rec)
        return key

    def authenticate(self, key: Optional[str]) -> Optional[Principal]:
        if not key or key_tenant(key) != self.tenant:
            return None
        hit = self._kv.get(_NS_HASH, _sha(key))
        if not hit:
            return None
        rec = self._kv.get(_NS, hit["name"])
        if not rec or rec["key_sha256"] != _sha(key):
            return None
        return Principal(self.tenant, rec["name"], rec["role"], rec.get("permissions"), rec.get("groups"))

    def get(self, name: str) -> Optional[dict]:
        return self._kv.get(_NS, name)

    def list(self) -> list[dict]:
        return [{"name": n, "role": r["role"], "permissions": r.get("permissions", []), "groups": r.get("groups", []),
                 "created": r.get("created")} for n, r in self._kv.all(_NS).items()]

    def revoke(self, name: str) -> bool:
        with self._lock:
            rec = self._kv.get(_NS, name)
            if rec is None:
                return False
            self._kv.delete(_NS_HASH, rec["key_sha256"])
            self._kv.delete(_NS, name)
            return True

    def counts(self) -> dict:
        out = {r: 0 for r in ROLES}
        for rec in self._kv.all(_NS).values():
            out[rec["role"]] = out.get(rec["role"], 0) + 1
        return out
