"""
kv.py — the small storage interface the platform needs: namespaced JSON documents.
==================================================================================
Two implementations with the same four methods (put / get / all / delete): MemoryKV for tests and SqliteKV for a
tenant's state file. A tenant gets its OWN SqliteKV file, so there is no shared table in which one customer's rows
could meet another's. Moving to Postgres later means writing a third class with these four methods, nothing else.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any, Optional


class MemoryKV:
    def __init__(self) -> None:
        self._d: dict[str, dict[str, str]] = {}
        self._lock = threading.RLock()

    def put(self, ns: str, key: str, value: dict) -> None:
        with self._lock:
            self._d.setdefault(ns, {})[key] = json.dumps(value, ensure_ascii=False)

    def get(self, ns: str, key: str) -> Optional[dict]:
        with self._lock:
            v = self._d.get(ns, {}).get(key)
        return json.loads(v) if v is not None else None

    def all(self, ns: str) -> dict[str, dict]:
        with self._lock:
            return {k: json.loads(v) for k, v in self._d.get(ns, {}).items()}

    def delete(self, ns: str, key: str) -> None:
        with self._lock:
            self._d.get(ns, {}).pop(key, None)

    def close(self) -> None:
        pass


class SqliteKV:
    def __init__(self, path: str) -> None:
        self._con = sqlite3.connect(path, check_same_thread=False)
        if path != ":memory:":
            self._con.execute("PRAGMA journal_mode=WAL")
            self._con.execute("PRAGMA busy_timeout=5000")
        self._lock = threading.RLock()
        with self._lock:
            self._con.execute("CREATE TABLE IF NOT EXISTS kv (ns TEXT, key TEXT, value TEXT, PRIMARY KEY(ns, key))")
            self._con.commit()

    def put(self, ns: str, key: str, value: dict) -> None:
        with self._lock:
            self._con.execute("INSERT INTO kv(ns,key,value) VALUES(?,?,?) "
                              "ON CONFLICT(ns,key) DO UPDATE SET value=excluded.value",
                              (ns, key, json.dumps(value, ensure_ascii=False)))
            self._con.commit()

    def get(self, ns: str, key: str) -> Optional[dict]:
        with self._lock:
            row = self._con.execute("SELECT value FROM kv WHERE ns=? AND key=?", (ns, key)).fetchone()
        return json.loads(row[0]) if row else None

    def all(self, ns: str) -> dict[str, dict]:
        with self._lock:
            rows = self._con.execute("SELECT key,value FROM kv WHERE ns=? ORDER BY rowid", (ns,)).fetchall()
        return {k: json.loads(v) for k, v in rows}

    def delete(self, ns: str, key: str) -> None:
        with self._lock:
            self._con.execute("DELETE FROM kv WHERE ns=? AND key=?", (ns, key))
            self._con.commit()

    def close(self) -> None:
        with self._lock:
            self._con.close()


def open_kv(path: Optional[str]) -> Any:
    return MemoryKV() if path in (None, ":memory:") else SqliteKV(path)
