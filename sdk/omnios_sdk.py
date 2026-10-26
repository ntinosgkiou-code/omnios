"""
omnios_sdk.py — connect any Python agent or function to the OmniOS gateway (v1 DRAFT).
One file, standard library only. Copy it next to your agent.

    from omnios_sdk import OmniOS
    gw = OmniOS("http://127.0.0.1:8010", api_key="ogk_...")        # a key with the "agent" role

    @gw.governed("refunds.issue")              # from now on this function does not run without the gateway's yes
    def refund(customer, amount_eur, reason):
        return billing_api.refund(customer, amount_eur)

    refund("C-2001", 250, "wrong item")        # stops and waits for a human if the rules say so

What the decorator does, in order:
  1. sends the call's arguments (JSON) to the gateway: "may I?"
  2. denied            -> raises Denied, the function never runs
     needs a human     -> waits (polling) until approved / rejected / expired
     approved          -> runs your function, then REPORTS success or failure to the gateway
     proxy-mode tool   -> the GATEWAY performs the action with its own credentials; your function body is not run
                          and the gateway's response is returned (the agent never holds the keys)
  3. FAIL-CLOSED: if the gateway cannot be reached, or a reply is not understood, the function does NOT run.

The arguments are what the log keeps a digest of, so keep secrets out of them.

OBSERVE MODE (the safe first step: nothing is blocked, nothing changes for the agent):

    @gw.observed("refunds.issue")              # the function runs exactly as before; the gateway only watches
    def refund(customer, amount_eur, reason): ...

    gw.flush()                                 # before the process exits, to send what is still queued

Fail-OPEN by design: if the gateway is unreachable the agent carries on and those events are not observed
(`gw.observe_stats()` counts them). Only what the code reports is seen.
"""
from __future__ import annotations

import functools
import inspect
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Optional


class OmniOSError(Exception):
    """Base class: anything that stops the governed function from running."""


class GatewayUnavailable(OmniOSError):
    """The gateway could not be reached or answered nonsense. The function did NOT run (fail-closed)."""


class Denied(OmniOSError):
    def __init__(self, action: dict) -> None:
        self.action = action
        super().__init__("denied by the rules: " + "; ".join(action.get("reasons") or ["no reason given"]))


class Rejected(OmniOSError):
    def __init__(self, action: dict) -> None:
        self.action = action
        super().__init__("rejected by a human")


class Expired(OmniOSError):
    def __init__(self, action: dict) -> None:
        self.action = action
        super().__init__("no human answered in time; the request expired")


Transport = Callable[[str, str, dict, Optional[bytes]], "tuple[int, bytes]"]


def _urllib_transport(timeout: float) -> Transport:
    def send(method: str, url: str, headers: dict, body: Optional[bytes]) -> "tuple[int, bytes]":
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
    return send


class OmniOS:
    def __init__(self, base_url: str, api_key: str, *, wait_seconds: float = 3600.0, poll_seconds: float = 1.0,
                 timeout: float = 15.0, transport: Optional[Transport] = None) -> None:
        if not api_key:
            raise ValueError("an API key with the agent role is required")
        self.base_url = base_url.rstrip("/")
        self.api_key, self.wait_seconds, self.poll_seconds = api_key, wait_seconds, poll_seconds
        self._send = transport or _urllib_transport(timeout)
        import threading
        self._obs_q = None
        self._obs_lock = threading.Lock()
        self._obs_stats: dict = {"sent": 0, "dropped": 0, "failed": 0, "last_error": None}

    @classmethod
    def from_env(cls, **kw: Any) -> "OmniOS":
        return cls(os.environ["OMNIOS_URL"], os.environ["OMNIOS_API_KEY"], **kw)

    # ---- plumbing ----
    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        headers = {"X-API-Key": self.api_key, "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            status, raw = self._send(method, self.base_url + path, headers, data)
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise GatewayUnavailable(f"cannot reach the gateway ({type(e).__name__})") from e
        try:
            doc = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError) as e:
            raise GatewayUnavailable(f"the gateway answered something that is not JSON (HTTP {status})") from e
        if status >= 400:
            d = doc.get("detail") if isinstance(doc, dict) else None
            code = d.get("code") if isinstance(d, dict) else str(d)
            raise OmniOSError(f"gateway refused: HTTP {status} {code}")
        if not isinstance(doc, dict):
            raise GatewayUnavailable("unexpected reply shape")
        return doc

    # ---- the protocol ----
    def propose(self, tool: str, params: dict, *, idempotency_key: Optional[str] = None, context: Optional[dict] = None) -> dict:
        body: dict = {"tool": tool, "params": params}
        if idempotency_key:
            body["idempotency_key"] = idempotency_key
        if context:
            body["context"] = context
        return self._request("POST", "/v1/actions", body)

    def get(self, action_id: str) -> dict:
        return self._request("GET", f"/v1/actions/{action_id}")

    def wait(self, action: dict) -> dict:
        """Block until the action is allowed to proceed. Returns the action (APPROVED or EXECUTED) or raises."""
        deadline = time.monotonic() + self.wait_seconds
        while True:
            st = action.get("status")
            if st in ("APPROVED", "EXECUTED"):
                return action
            if st == "DENIED":
                raise Denied(action)
            if st == "REJECTED":
                raise Rejected(action)
            if st == "EXPIRED":
                raise Expired(action)
            if st != "PENDING_APPROVAL":
                raise OmniOSError(f"unexpected status {st!r}; not running the function")
            if time.monotonic() > deadline:
                raise OmniOSError("gave up waiting for a human; not running the function")
            time.sleep(self.poll_seconds)
            action = self.get(action["id"])

    def report(self, action_id: str, ok: bool, response: Any = None, note: str = "") -> dict:
        return self._request("POST", f"/v1/actions/{action_id}/report", {"ok": ok, "response": _safe(response), "note": note[:300]})

    # ---- the one-line integration ----
    def governed(self, tool: str, *, params: Optional[Callable[[dict], dict]] = None) -> Callable:
        """Decorator. `params(bound_arguments) -> dict` lets you choose which arguments are sent (default: all)."""
        def deco(fn: Callable) -> Callable:
            sig = inspect.signature(fn)

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                payload = params(dict(bound.arguments)) if params else dict(bound.arguments)
                try:
                    json.dumps(payload)
                except (TypeError, ValueError) as e:
                    raise OmniOSError("the arguments must be JSON-serializable") from e
                action = self.wait(self.propose(tool, payload))
                if action.get("execution_mode") == "proxy":
                    return action.get("response")          # the gateway did it, with its own keys
                try:
                    result = fn(*args, **kwargs)
                except Exception as e:
                    try:
                        self.report(action["id"], False, note=type(e).__name__)
                    finally:
                        raise
                self.report(action["id"], True, response=result)
                return result

            wrapper.omnios_tool = tool        # type: ignore[attr-defined]
            return wrapper
        return deco


    # ---- observe mode: report what the agent does, block nothing ----
    def observe(self, tool: str, params: Optional[dict] = None, *, external_id: Optional[str] = None,
                occurred_at: Optional[float] = None) -> dict:
        """Tell the gateway about one action (synchronously). Returns its dry-run verdict; raises if the gateway refuses."""
        return self.observe_many([_event(tool, params, external_id, occurred_at)])[0]

    def observe_many(self, events: "list[dict]") -> "list[dict]":
        """At most 200 events per call. Each: {"tool", "params", "external_id"?, "occurred_at"?}."""
        return self._request("POST", "/v1/observe", {"events": events})["observed"]

    def observed(self, tool: str, *, params: Optional[Callable[[dict], dict]] = None,
                 external_id: Optional[Callable[[dict], Optional[str]]] = None) -> Callable:
        """Decorator for OBSERVE MODE. The function ALWAYS runs, exactly as before and at the same speed: the call's arguments are
        queued and sent to the gateway in the background, and the gateway says what the rules WOULD have decided (see the shadow
        report). It is deliberately fail-OPEN: if the gateway is down or slow, the agent is not affected, and that event is
        simply not observed (count it with `observe_stats()`). Use `governed` when you want the function to be gated."""
        def deco(fn: Callable) -> Callable:
            sig = inspect.signature(fn)

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    bound = sig.bind(*args, **kwargs)
                    bound.apply_defaults()
                    allargs = dict(bound.arguments)
                    payload = params(allargs) if params else allargs
                    json.dumps(payload)
                    ext = external_id(allargs) if external_id else None
                    self._enqueue(_event(tool, payload, ext, time.time()))
                except Exception:                       # never let the observer break the observed
                    self._obs_stats["dropped"] += 1
                return fn(*args, **kwargs)

            wrapper.omnios_tool = tool        # type: ignore[attr-defined]
            return wrapper
        return deco

    def observe_stats(self) -> dict:
        """{"sent", "dropped", "failed", "last_error"}: how many reported events reached the gateway, and how many did not."""
        return dict(self._obs_stats)

    def flush(self, timeout: float = 10.0) -> bool:
        """Wait until queued events have been sent (call before the process exits). False if the time ran out."""
        if self._obs_q is None:
            return True
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self._obs_q.unfinished_tasks == 0:
                return True
            time.sleep(0.01)
        return self._obs_q.unfinished_tasks == 0

    def _enqueue(self, ev: dict) -> None:
        import queue
        import threading
        with self._obs_lock:
            if self._obs_q is None:
                self._obs_q = queue.Queue(maxsize=2000)
                threading.Thread(target=self._obs_worker, name="omnios-observe", daemon=True).start()
        try:
            self._obs_q.put_nowait(ev)
        except queue.Full:
            self._obs_stats["dropped"] += 1

    def _obs_worker(self) -> None:
        import queue
        q = self._obs_q
        while True:
            batch = [q.get()]
            while len(batch) < 100:
                try:
                    batch.append(q.get_nowait())
                except queue.Empty:
                    break
            try:
                self.observe_many(batch)
                self._obs_stats["sent"] += len(batch)
            except Exception as e:                      # fail-open: record it, drop the batch, carry on
                self._obs_stats["failed"] += len(batch)
                self._obs_stats["last_error"] = f"{type(e).__name__}: {e}"[:200]
            finally:
                for _ in batch:
                    q.task_done()


def _event(tool: str, params: Optional[dict], external_id: Optional[str], occurred_at: Optional[float]) -> dict:
    ev: dict = {"tool": tool, "params": params or {}}
    if external_id:
        ev["external_id"] = external_id
    if occurred_at is not None:
        ev["occurred_at"] = occurred_at
    return ev


def _safe(x: Any) -> Any:
    try:
        json.dumps(x)
        return x
    except (TypeError, ValueError):
        return {"repr": repr(x)[:200]}
