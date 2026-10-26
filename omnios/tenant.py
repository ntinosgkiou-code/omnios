"""
tenant.py — isolation by construction: one customer = one directory = its own database pair, signing key and secrets.
=====================================================================================================================
    <root>/tenants/<id>/tenant.json   public settings (profile, admin quorum, TTL, trusted witness keys)
                        state.db      actions, changes, principals, policy versions        (SqliteKV)
                        ledger.db     the evidence ledger                                  (Ledger)
                        log.key       the tenant's Ed25519 log-signing seed (0600; BACK IT UP, and never share it)
                        secrets.json  optional {"NAME": "value"} for proxy-mode credentials, edited by the operator only

Nothing is shared between tenants: no table, no counter, no key, no secret namespace. A tenant can run alone in a
process (a customer-hosted install: the registry just holds one tenant) or next to others (a pilot host, a partner who
manages several clients) with the same code. Profiles:  "pilot"       admin_quorum 1, fine for a trial
                                                         "production"  admin_quorum >= 2: no admin can change rules or
                                                                       keys alone (needs at least two admins)
"""
from __future__ import annotations

import base64
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import tlog
from .engine import Engine
from .errors import OmniError
from .forwarder import Forwarder
from .identity import ROLES, TENANT_RE, IdentityStore
from .kv import SqliteKV
from .ledger import Ledger
from .policy import EMPTY_POLICY, PolicyStore, validate_policy

PROFILES = ("pilot", "production")


def _load_or_create_key(path: Path) -> Ed25519PrivateKey:
    if path.exists():
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(path.read_text().strip()))
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)      # private from the first byte (no effect on Windows)
    with os.fdopen(fd, "w") as f:
        f.write(base64.b64encode(seed).decode("ascii") + "\n")
    return key


class TenantRuntime:
    def __init__(self, directory: Path, clock: Callable[[], float] = time.time) -> None:
        self.dir = directory
        self.cfg: dict = json.loads((directory / "tenant.json").read_text(encoding="utf-8"))
        self.id: str = self.cfg["id"]
        self._clock = clock
        self.kv = SqliteKV(str(directory / "state.db"))
        self.log_key = _load_or_create_key(directory / "log.key")
        self.ledger = Ledger(str(directory / "ledger.db"), self.id, self.log_key, clock=clock)
        self.identity = IdentityStore(self.kv, self.id, clock)
        allow_local = bool(self.cfg.get("allow_private_upstreams", False))
        self.policies = PolicyStore(self.kv, allow_local)
        self.forwarder = Forwarder(self.secret, allow_private=allow_local)
        self.engine = Engine(self.id, self.kv, self.ledger, self.policies, self.identity, self.forwarder, clock=clock,
                             approval_ttl=int(self.cfg.get("approval_ttl", 86400)),
                             admin_quorum=int(self.cfg.get("admin_quorum", 1)), allow_insecure_localhost=allow_local)

    # ---- secrets for proxy mode: resolved per tenant, never from another tenant's namespace ----
    def secret(self, name: str) -> Optional[str]:
        env = os.environ.get(f"OMNIOS_SECRET__{self.id.upper().replace('-', '_')}__{name}")
        if env is not None:
            return env
        f = self.dir / "secrets.json"
        if f.exists():
            try:
                return json.loads(f.read_text(encoding="utf-8")).get(name)
            except (ValueError, OSError):
                return None
        return None

    def witness_keys(self) -> dict[str, bytes]:
        return {n: base64.b64decode(k) for n, k in (self.cfg.get("witnesses") or {}).items()}

    @property
    def suspended(self) -> bool:
        return bool(self.cfg.get("suspended"))

    def public_info(self) -> dict:
        return {"tenant": self.id, "name": self.cfg.get("name"), "origin": self.ledger.origin, "key_name": self.ledger.origin,
                "log_public_key": base64.b64encode(self.ledger.public_key).decode("ascii"),
                "profile": self.cfg.get("profile"), "admin_quorum": self.cfg.get("admin_quorum")}

    def save_cfg(self) -> None:
        (self.dir / "tenant.json").write_text(json.dumps(self.cfg, indent=2, ensure_ascii=False), encoding="utf-8")

    def close(self) -> None:
        self.kv.close()
        self.ledger.close()


class TenantRegistry:
    def __init__(self, root: str, clock: Callable[[], float] = time.time) -> None:
        self.root = Path(root)
        self._tenants_dir = self.root / "tenants"
        self._tenants_dir.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._cache: dict[str, TenantRuntime] = {}
        self._lock = threading.RLock()

    # ---- lookup ----
    def exists(self, tenant_id: str) -> bool:
        return bool(TENANT_RE.match(tenant_id or "")) and (self._tenants_dir / tenant_id / "tenant.json").exists()

    def get(self, tenant_id: str) -> TenantRuntime:
        if not self.exists(tenant_id):
            raise OmniError(404, "no_such_tenant")
        with self._lock:
            rt = self._cache.get(tenant_id)
            if rt is None:
                rt = self._cache[tenant_id] = TenantRuntime(self._tenants_dir / tenant_id, self._clock)
            return rt

    def ids(self) -> list[str]:
        return sorted(p.name for p in self._tenants_dir.iterdir() if (p / "tenant.json").exists())

    def public_registry(self) -> list[dict]:
        return [self.get(i).public_info() for i in self.ids()]

    # ---- provisioning ----
    def create(self, tenant_id: str, name: str, *, policy: Optional[dict] = None, profile: str = "pilot",
               admin_quorum: Optional[int] = None, admins: Optional[list] = None, approvers: Optional[list] = None,
               agents: Optional[list] = None, auditors: Optional[list] = None, witnesses: Optional[dict] = None,
               approval_ttl: int = 86400, allow_private_upstreams: bool = False) -> tuple[TenantRuntime, list[dict]]:
        """Create a customer. `admins`, `approvers`, `auditors` are names or {name, groups}; `agents` are
        {name, permissions}. Returns (runtime, keys) — the keys are shown ONCE and only their hashes are stored."""
        if not TENANT_RE.match(tenant_id or ""):
            raise OmniError(422, "invalid_tenant_id", "3-32 characters: lowercase letters, digits and hyphens")
        if profile not in PROFILES:
            raise OmniError(422, "invalid_profile", f"one of {list(PROFILES)}")
        quorum = admin_quorum if admin_quorum is not None else (2 if profile == "production" else 1)
        admins = admins or (["admin-1", "admin-2"] if quorum >= 2 else ["admin-1"])
        if len(admins) < quorum:
            raise OmniError(422, "not_enough_admins", f"admin_quorum {quorum} needs at least {quorum} admins")
        if profile == "production" and quorum < 2:
            raise OmniError(422, "production_needs_four_eyes", "a production tenant needs admin_quorum >= 2")
        doc = policy if policy is not None else EMPTY_POLICY
        errs = validate_policy(doc, allow_private_upstreams)
        if errs:
            raise OmniError(422, "invalid_policy", "; ".join(errs))
        d = self._tenants_dir / tenant_id
        with self._lock:
            if (d / "tenant.json").exists():
                raise OmniError(409, "tenant_exists")
            d.mkdir(parents=True, exist_ok=True)
            cfg = {"id": tenant_id, "name": name, "profile": profile, "admin_quorum": quorum, "approval_ttl": approval_ttl,
                   "witnesses": witnesses or {}, "allow_private_upstreams": allow_private_upstreams,
                   "created": self._clock(), "suspended": False}
            (d / "tenant.json").write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
            rt = TenantRuntime(d, self._clock)
            self._cache[tenant_id] = rt
        rt.ledger.append("tenant.created", {"id": tenant_id, "name": name, "profile": profile, "admin_quorum": quorum,
                                            "approval_ttl": approval_ttl, "log_public_key": base64.b64encode(rt.ledger.public_key).decode("ascii"),
                                            "witnesses": sorted((witnesses or {}).keys())}, at=self._clock())
        rt.engine.bootstrap(doc, by="system:provision")
        keys: list[dict] = []

        def issue(entry: Any, role: str) -> None:
            nm = entry if isinstance(entry, str) else entry["name"]
            perms = [] if isinstance(entry, str) else entry.get("permissions", [])
            groups = [] if isinstance(entry, str) else entry.get("groups", [])
            try:
                key = rt.identity.create(nm, role, perms, groups)
            except ValueError as e:
                raise OmniError(422, "invalid_principal", str(e))
            rt.ledger.append("principal.changed", {"id": f"provision-{nm}", "change": "created", "name": nm, "role": role,
                                                   "groups": sorted(groups), "permissions": sorted(perms),
                                                   "by": "system:provision", "approvers": []}, at=self._clock())
            keys.append({"name": nm, "role": role, "permissions": sorted(perms), "groups": sorted(groups), "key": key})

        for e in admins:
            issue(e, "admin")
        for e in approvers or []:
            issue(e, "approver")
        for e in agents or []:
            issue(e, "agent")
        for e in auditors or []:
            issue(e, "auditor")
        return rt, keys

    def set_witnesses(self, tenant_id: str, witnesses: dict[str, str], urls: Optional[dict[str, str]] = None) -> None:
        """Trusted witness public keys {name: base64}, and optionally where each one listens ({name: https URL}) so this
        installation can PUSH its checkpoints to it. An operator action; recorded in the ledger (names and URLs, never keys' secrets)."""
        rt = self.get(tenant_id)
        for n, k in witnesses.items():
            try:
                ok = len(base64.b64decode(k, validate=True)) == 32
            except ValueError:
                ok = False
            if not ok or not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", n):
                raise OmniError(422, "invalid_witness", n)
        for n, u in (urls or {}).items():
            if n not in {**(rt.cfg.get("witnesses") or {}), **witnesses}:
                raise OmniError(422, "url_for_an_unregistered_witness", n)
            if not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d+)?(/[A-Za-z0-9._~/-]*)?", u or ""):
                raise OmniError(422, "invalid_witness_url", u)
        rt.cfg["witnesses"] = {**(rt.cfg.get("witnesses") or {}), **witnesses}
        if urls:
            rt.cfg["witness_endpoints"] = {**(rt.cfg.get("witness_endpoints") or {}), **urls}
        rt.save_cfg()
        rt.ledger.append("witness.registered", {"id": f"witness-{int(self._clock())}", "witnesses": sorted(witnesses),
                                                "endpoints": dict(sorted((urls or {}).items()))}, at=self._clock())

    def suspend(self, tenant_id: str, suspended: bool = True) -> None:
        rt = self.get(tenant_id)
        rt.cfg["suspended"] = suspended
        rt.save_cfg()
        rt.ledger.append("tenant.suspended" if suspended else "tenant.resumed", {"id": f"suspend-{int(self._clock())}"}, at=self._clock())

    def close(self) -> None:
        with self._lock:
            for rt in self._cache.values():
                rt.close()
            self._cache.clear()
