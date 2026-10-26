"""
errors.py — one error type that maps to an HTTP status. `.status` and `.code` are stable and safe to show people.
"""
from __future__ import annotations


class OmniError(Exception):
    def __init__(self, status: int, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.status, self.code, self.detail = status, code, detail
