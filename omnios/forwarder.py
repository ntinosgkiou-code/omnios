"""
forwarder.py — proxy mode: the platform performs the approved call itself, with the tenant's own credentials.
============================================================================================================
The URL, method and headers come ONLY from the (admin-approved) policy; the agent can influence only the JSON body.
Credentials are written ${SECRET:NAME} and resolved through the TENANT's secret resolver, so one customer's policy can
never read another customer's secret. Redirects are not followed, response size and time are capped, and private
addresses are refused unless the operator allows them (tests and local demos only).

Known limit: the host name is resolved here and again when connecting, so a DNS-rebinding attacker who controls the
upstream's DNS is not fully stopped; put the platform behind an egress allow-list for that.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Optional

from .errors import OmniError

_SECRET_REF = re.compile(r"\$\{SECRET:([A-Za-z_][A-Za-z0-9_]*)\}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _address_allowed(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return False
    return bool(infos)


class Forwarder:
    MAX_BYTES = 1_000_000

    def __init__(self, secret_resolver: Callable[[str], Optional[str]], allow_private: bool = False) -> None:
        self._secret = secret_resolver
        self.allow_private = allow_private
        self._opener = urllib.request.build_opener(_NoRedirect)

    def _interpolate(self, s: str) -> str:
        def sub(m: re.Match) -> str:
            v = self._secret(m.group(1))
            if v is None:
                raise OmniError(502, "upstream_credential_missing", f"secret {m.group(1)} is not set for this customer")
            return v
        return _SECRET_REF.sub(sub, s)

    def call(self, cfg: dict, body: Optional[dict]) -> tuple[int, Any]:
        host = urllib.parse.urlparse(cfg["url"]).hostname or ""
        if not self.allow_private and not _address_allowed(host):
            raise OmniError(502, "upstream_address_not_allowed", host)
        headers = {k: self._interpolate(v) for k, v in (cfg.get("headers") or {}).items()}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(cfg["url"], data=data, headers=headers, method=cfg.get("method", "POST"))
        try:
            with self._opener.open(req, timeout=float(cfg.get("timeout", 15))) as r:
                raw, status = r.read(self.MAX_BYTES), r.status
        except urllib.error.HTTPError as e:
            raw, status = e.read(self.MAX_BYTES), e.code
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise OmniError(502, "upstream_unreachable", type(e).__name__)
        try:
            return status, json.loads(raw.decode("utf-8")) if raw else None
        except (ValueError, UnicodeDecodeError):
            return status, raw.decode("utf-8", "replace")[:4000]
