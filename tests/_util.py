"""Shared test helpers: a throwaway registry, a fake clock, and a small finance policy."""
from __future__ import annotations

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from omnios.tenant import TenantRegistry  # noqa: E402

POLICY = {
    "version": 1, "default_unknown_tool": "deny",
    "tools": {
        "payments.send": {
            "permission": "finance:pay", "reversibility": "one_way_recoverable", "risk": "high",
            "deny": [{"when": {"field": "amount_eur", "op": ">", "value": 10000}, "reason": "ceiling"}],
            "limits": [{"field": "amount_eur", "per": "day", "max": 15000, "on_exceed": "deny"}],
            "approvals": {"required": 1, "extra": [{"when": {"field": "amount_eur", "op": ">", "value": 1000}, "required": 2}]},
            "effect_key": [{"field": "vendor", "as": "vendor", "norm": "text"}, {"field": "amount_eur", "as": "amount_cents", "norm": "cents"}]},
        "refunds.issue": {
            "permission": "refund:issue", "reversibility": "two_way", "risk": "low",
            "escalate": [{"when": {"field": "amount_eur", "op": ">", "value": 100}, "reason": "needs a human"}]},
        "data.delete": {"permission": "data:delete", "reversibility": "one_way_terminal", "risk": "high",
                        "approvals": {"required": 2, "groups": ["privacy"]}},
        "note.add": {"permission": "notes:write", "reversibility": "two_way", "risk": "low"},
    },
}


class FakeClock:
    def __init__(self, t: float = 1_760_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


class Env:
    """A registry in a temp directory with one production tenant 'acme' (people: alice, bob, carol(privacy), ops-agent, aud-1)."""

    def __init__(self, clock: FakeClock = None, profile: str = "production") -> None:
        self.dir = tempfile.mkdtemp(prefix="omnios-test-")
        self.clock = clock or FakeClock()
        self.reg = TenantRegistry(self.dir, clock=self.clock)
        self.rt, self.keys = self.reg.create(
            "acme", "Acme Ltd", policy=POLICY, profile=profile,
            approvers=["alice", "bob", {"name": "carol", "groups": ["privacy"]}, {"name": "dave", "groups": ["privacy"]}],
            agents=[{"name": "ops-agent", "permissions": ["finance:pay", "refund:issue", "data:delete", "notes:write"]}],
            auditors=["aud-1"])
        self.key = {k["name"]: k["key"] for k in self.keys}

    def close(self) -> None:
        self.reg.close()
        shutil.rmtree(self.dir, ignore_errors=True)
