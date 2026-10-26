"""
api.py — the HTTP surface. Three audiences, three prefixes, one rule: WHO is talking comes from the API key.
===========================================================================================================
  /v1/...            a tenant's agents, approvers, admins and auditors. The key carries the tenant (ogk_<tenant>_...),
                     so the request is routed to the right customer before anything is looked up.
                     (The action routes keep the v1 shapes, so the v1 SDK works unchanged.)
  /public/<tenant>/  anyone: the signed checkpoint, consistency and inclusion proofs. Hash-only, by design: this is
                     what a witness or a verifier polls. POST .../cosign accepts a witness's signature, but only if
                     it is made with a key the tenant has registered.
  /platform/...      the operator who runs this process (X-Platform-Key). Absent unless OMNIOS_PLATFORM_KEY is set,
                     so a customer-hosted install exposes no provisioning surface at all.

Roles:  agent -> propose, report | approver -> approve, reject, compensate | admin -> propose/approve CHANGES to rules
and keys (never approves actions) | auditor -> read-only: records, evidence, bundles, integrity.
"""
from __future__ import annotations

import hmac
import json
from pathlib import Path
from typing import Any, Callable, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .errors import OmniError
from .identity import Principal, key_tenant
from .policy import validate_policy
from .tenant import TenantRegistry, TenantRuntime

_MAX_PARAMS_BYTES = 20_000


class Ctx:
    __slots__ = ("rt", "p")

    def __init__(self, rt: TenantRuntime, p: Principal) -> None:
        self.rt, self.p = rt, p


class ProposeBody(BaseModel):
    tool: str = Field(min_length=1, max_length=80)
    params: dict = Field(default_factory=dict)
    idempotency_key: Optional[str] = Field(default=None, max_length=120)
    context: Optional[dict] = None


class ObserveItem(BaseModel):
    tool: str = Field(min_length=1, max_length=80)
    params: dict = Field(default_factory=dict)
    external_id: Optional[str] = Field(default=None, max_length=120)
    occurred_at: Optional[float] = None


class ObserveBody(BaseModel):
    events: list[ObserveItem] = Field(min_length=1, max_length=200)


class DecisionBody(BaseModel):
    comment: str = Field(default="", max_length=300)


class ReportBody(BaseModel):
    ok: bool
    response: Any = None
    note: str = Field(default="", max_length=300)
    kind: str = "execution"


class ChangeBody(BaseModel):
    kind: str
    payload: dict = Field(default_factory=dict)


class CosignBody(BaseModel):
    size: int = Field(ge=1)
    line: str = Field(min_length=10, max_length=600)


class TenantBody(BaseModel):
    id: str
    name: str = Field(min_length=1, max_length=120)
    profile: str = "pilot"
    policy: Optional[dict] = None
    admin_quorum: Optional[int] = None
    admins: list = Field(default_factory=list)
    approvers: list = Field(default_factory=list)
    agents: list = Field(default_factory=list)
    auditors: list = Field(default_factory=list)
    witnesses: dict = Field(default_factory=dict)


def create_app(registry: TenantRegistry, *, platform_key: Optional[str] = None, demo_keys: Optional[list] = None) -> FastAPI:
    app = FastAPI(title="OmniOS trust platform", version="2.0-draft")

    @app.exception_handler(OmniError)
    async def omni_error(_: Request, e: OmniError) -> Response:
        body = json.dumps({"detail": {"code": e.code, "detail": e.detail}})
        return Response(content=body, status_code=e.status, media_type="application/json")

    # ───────────── authentication ─────────────
    def ctx(x_api_key: Optional[str] = Header(default=None)) -> Ctx:
        tenant = key_tenant(x_api_key)
        if not tenant or not registry.exists(tenant):
            raise HTTPException(status_code=401, detail={"code": "invalid_or_missing_api_key"})
        rt = registry.get(tenant)
        if rt.suspended:
            raise HTTPException(status_code=423, detail={"code": "tenant_suspended"})
        p = rt.identity.authenticate(x_api_key)
        if p is None:
            raise HTTPException(status_code=401, detail={"code": "invalid_or_missing_api_key"})
        return Ctx(rt, p)

    def need(*roles: str) -> Callable:
        def dep(c: Ctx = Depends(ctx)) -> Ctx:
            if c.p.role not in roles:
                raise HTTPException(status_code=403, detail={
                    "code": "role_not_allowed", "detail": f"role '{c.p.role}' cannot do this (needs: {', '.join(roles)})"})
            return c
        return dep

    def own_or_staff(c: Ctx, action: dict) -> None:
        if c.p.role == "agent" and action["agent"] != c.p.name:
            raise HTTPException(status_code=404, detail={"code": "no_such_action"})

    def platform(x_platform_key: Optional[str] = Header(default=None)) -> None:
        if not platform_key:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        if not x_platform_key or not hmac.compare_digest(x_platform_key, platform_key):
            raise HTTPException(status_code=401, detail={"code": "invalid_platform_key"})

    # ───────────── the browser UI (one static page; it talks to the same API as everything else) ─────────────
    @app.get("/ui", response_class=HTMLResponse)
    def ui_page() -> HTMLResponse:
        html = (Path(__file__).parent / "ui" / "index.html").read_text(encoding="utf-8")
        return HTMLResponse(html, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                                           "Referrer-Policy": "no-referrer", "Content-Security-Policy": (
                                               "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                                               "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")})

    @app.get("/ui/demo-keys")
    def ui_demo_keys() -> dict:
        """Only present when the server was started by the local demo launcher (it hands out throw-away demo keys)."""
        if not demo_keys:
            raise HTTPException(status_code=404, detail={"code": "not_found"})
        return {"keys": demo_keys}

    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "tenants": len(registry.ids())}

    # ───────────── who am I ─────────────
    @app.get("/v1/me")
    def me(c: Ctx = Depends(ctx)) -> dict:
        return {**c.p.public(), "profile": c.rt.cfg.get("profile"), "admin_quorum": c.rt.cfg.get("admin_quorum")}

    # ───────────── actions (v1-compatible shapes) ─────────────
    @app.post("/v1/actions")
    def propose(body: ProposeBody, c: Ctx = Depends(need("agent"))) -> dict:
        if len(json.dumps(body.params)) > _MAX_PARAMS_BYTES:
            raise HTTPException(status_code=413, detail={"code": "params_too_large"})
        return c.rt.engine.propose(c.p.name, body.tool, body.params, permissions=c.p.permissions,
                                   idempotency_key=body.idempotency_key, context=body.context)

    @app.get("/v1/actions")
    def list_actions(status: Optional[str] = None, limit: int = 100, c: Ctx = Depends(ctx)) -> dict:
        return {"actions": c.rt.engine.list(status=status, agent=c.p.name if c.p.role == "agent" else None, limit=limit)}

    @app.get("/v1/actions/{aid}")
    def get_action(aid: str, c: Ctx = Depends(ctx)) -> dict:
        a = c.rt.engine.get(aid)
        own_or_staff(c, a)
        return a

    @app.post("/v1/actions/{aid}/approve")
    def approve(aid: str, body: Optional[DecisionBody] = None, c: Ctx = Depends(need("approver"))) -> dict:
        return c.rt.engine.approve(aid, c.p.name, body.comment if body else "", approver_groups=c.p.groups)

    @app.post("/v1/actions/{aid}/reject")
    def reject(aid: str, body: Optional[DecisionBody] = None, c: Ctx = Depends(need("approver"))) -> dict:
        return c.rt.engine.reject(aid, c.p.name, body.comment if body else "")

    @app.post("/v1/actions/{aid}/report")
    def report(aid: str, body: ReportBody, c: Ctx = Depends(need("agent"))) -> dict:
        return c.rt.engine.report(aid, c.p.name, body.ok, body.response, body.note, body.kind)

    @app.post("/v1/actions/{aid}/compensate")
    def compensate(aid: str, c: Ctx = Depends(need("approver"))) -> dict:
        return c.rt.engine.compensate(aid, c.p.name)

    # ───────────── observe mode: the customer's system reports what its agent does; nothing is gated ─────────────
    @app.post("/v1/observe")
    def observe(body: ObserveBody, c: Ctx = Depends(need("agent"))) -> dict:
        events = [e.model_dump(exclude_none=True) for e in body.events]
        return {"observed": c.rt.engine.observe(c.p.name, c.p.permissions, events), "mode": "observe",
                "note": "dry run: nothing was blocked or executed"}

    def _obs_query(c: Ctx, decision: Optional[str], limit: int, since: Optional[float], until: Optional[float]) -> list:
        if decision not in (None, "allow", "pending", "deny"):
            raise HTTPException(status_code=422, detail={"code": "invalid_decision"})
        return c.rt.engine.observations(decision=decision, agent=c.p.name if c.p.role == "agent" else None,
                                        limit=limit, since=since, until=until)

    @app.get("/v1/observe")
    def list_observed(decision: Optional[str] = None, limit: int = 100, since: Optional[float] = None, until: Optional[float] = None,
                      c: Ctx = Depends(ctx)) -> dict:
        return {"observed": _obs_query(c, decision, limit, since, until)}

    @app.get("/v1/observe/report")
    def observe_report(since: Optional[float] = None, until: Optional[float] = None,
                       c: Ctx = Depends(need("admin", "auditor", "approver"))) -> dict:
        from .observe import summarize
        return summarize(_obs_query(c, None, 5000, since, until))

    @app.get("/v1/observe/report.html", response_class=HTMLResponse)
    def observe_report_html(since: Optional[float] = None, until: Optional[float] = None,
                            c: Ctx = Depends(need("admin", "auditor", "approver"))) -> HTMLResponse:
        from .observe import render_html, summarize
        page = render_html(summarize(_obs_query(c, None, 5000, since, until)), c.rt.cfg.get("name") or c.rt.id)
        return HTMLResponse(page, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                                           "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"})

    # ───────────── rules, keys, and changes (four-eyes on the system itself) ─────────────
    @app.get("/v1/policy")
    def get_policy(c: Ctx = Depends(ctx)) -> dict:
        return {"policy": c.rt.engine.policy(), "policy_hash": c.rt.engine.policy_hash(), "version": c.rt.engine.policy_version()}

    @app.post("/v1/policy/validate")
    def check_policy(doc: dict, c: Ctx = Depends(need("admin"))) -> dict:
        return {"errors": validate_policy(doc, bool(c.rt.cfg.get("allow_private_upstreams")))}

    @app.get("/v1/principals")
    def list_principals(c: Ctx = Depends(need("admin", "auditor"))) -> dict:
        return {"principals": c.rt.identity.list()}

    @app.post("/v1/changes")
    def propose_change(body: ChangeBody, c: Ctx = Depends(need("admin"))) -> dict:
        return c.rt.engine.propose_change(body.kind, body.payload, c.p.name)

    @app.get("/v1/changes")
    def list_changes(status: Optional[str] = None, c: Ctx = Depends(need("admin", "auditor"))) -> dict:
        return {"changes": c.rt.engine.changes(status)}

    @app.post("/v1/changes/{cid}/approve")
    def approve_change(cid: str, c: Ctx = Depends(need("admin"))) -> dict:
        return c.rt.engine.approve_change(cid, c.p.name)

    @app.post("/v1/changes/{cid}/reject")
    def reject_change(cid: str, c: Ctx = Depends(need("admin"))) -> dict:
        return c.rt.engine.reject_change(cid, c.p.name)

    # ───────────── read-only audit surface ─────────────
    @app.get("/v1/overview")
    def overview(c: Ctx = Depends(ctx)) -> dict:
        cp = c.rt.ledger.checkpoint()
        return {"me": c.p.public(), "tenant": c.rt.public_info(), "policy": c.rt.engine.policy_version(),
                "tools": len(c.rt.engine.policy()["tools"]), "principals": c.rt.identity.counts(),
                "counts": c.rt.engine.counts(), "pending_changes": len(c.rt.engine.changes("PENDING")),
                "ledger": {"records": cp["size"], "root": cp["root"], "witnessed": cp["witnessed"]}}

    @app.get("/v1/audit/records")
    def audit_records(start: int = 0, limit: int = 100, c: Ctx = Depends(need("approver", "admin", "auditor"))) -> dict:
        return {"records": c.rt.ledger.records(start, limit), "size": c.rt.ledger.size()}

    @app.get("/v1/audit/evidence/{aid}")
    def audit_evidence(aid: str, c: Ctx = Depends(ctx)) -> dict:
        if c.p.role == "agent":
            own_or_staff(c, c.rt.engine.get(aid))
        recs = c.rt.ledger.by_ref(aid)
        if not recs:
            raise HTTPException(status_code=404, detail={"code": "no_records_for_id"})
        cp = c.rt.ledger.checkpoint()
        size = cp["size"]                      # proofs and checkpoint refer to the same tree size
        return {"id": aid, "size": size, "records": [{**r, "inclusion": c.rt.ledger.inclusion(r["seq"], size)["proof"]} for r in recs],
                "checkpoint": cp}

    @app.get("/v1/audit/integrity")
    def integrity(c: Ctx = Depends(need("admin", "auditor"))) -> dict:
        return c.rt.ledger.verify_integrity()

    @app.get("/v1/audit/bundle")
    def bundle(scope: str = "all", id: Optional[str] = None, c: Ctx = Depends(need("admin", "auditor"))) -> Response:
        from .evidence import build_bundle
        data = build_bundle(c.rt, scope=scope, ref=id)
        return Response(content=data, media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="omnios-evidence-{c.rt.id}.zip"'})

    # ───────────── public, hash-only: what witnesses and verifiers poll ─────────────
    def pub(tenant: str) -> TenantRuntime:
        if not registry.exists(tenant):
            raise HTTPException(status_code=404, detail={"code": "no_such_tenant"})
        return registry.get(tenant)

    @app.get("/public/{tenant}/checkpoint")
    def public_checkpoint(tenant: str) -> dict:
        return pub(tenant).ledger.checkpoint()

    @app.get("/public/{tenant}/consistency")
    def public_consistency(tenant: str, first: int, second: Optional[int] = None) -> dict:
        return pub(tenant).ledger.consistency(first, second)

    @app.get("/public/{tenant}/inclusion/{index}")
    def public_inclusion(tenant: str, index: int, size: Optional[int] = None) -> dict:
        return pub(tenant).ledger.inclusion(index, size)

    @app.post("/public/{tenant}/cosign")
    def public_cosign(tenant: str, body: CosignBody) -> dict:
        rt = pub(tenant)
        return rt.ledger.add_cosignature(body.size, body.line, rt.witness_keys())

    # ───────────── operator surface (only if OMNIOS_PLATFORM_KEY is set) ─────────────
    @app.post("/platform/tenants")
    def platform_create(body: TenantBody, _: None = Depends(platform)) -> dict:
        rt, keys = registry.create(body.id, body.name, policy=body.policy, profile=body.profile, admin_quorum=body.admin_quorum,
                                   admins=body.admins or None, approvers=body.approvers, agents=body.agents,
                                   auditors=body.auditors, witnesses=body.witnesses)
        return {"tenant": rt.public_info(), "keys": keys, "note": "The keys are shown once. Only their hashes are stored."}

    @app.get("/platform/tenants")
    def platform_list(_: None = Depends(platform)) -> dict:
        return {"tenants": registry.public_registry()}

    return app
