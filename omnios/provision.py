"""
provision.py — set a customer up (deliverable 2) and hand the install over.
===========================================================================
`create_tenant` = a TenantRegistry.create with a policy TEMPLATE, plus the handover folder the customer actually gets:

    HANDOVER.md              who holds which key, how to connect an agent, what to do every month, what is NOT covered
    tenant-public.json       tenant id, log origin and the log's PUBLIC key. Give this to the witness BY ANOTHER ROUTE.
    witness-entry.json       the line the witness adds to its witness.json
    docker-compose.yml       one container, one volume (the volume IS the customer's data and keys: back it up)
    .env.example             where the proxy-mode secrets go
    keys.txt                 ONLY with --write-keys: the one-time keys. Default: shown once on screen, never written.

Deployment models this supports with the same code (see docs/OPERATIONS.md):
  A. customer-hosted    the registry holds ONE tenant, inside the customer's boundary (recommended for money)
  B. partner-managed    one process, several tenants, run by an integrator or MSP for its own clients
  C. pilot host         one process, several tenants, run by us, clearly labelled non-production
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Optional

from .errors import OmniError
from .tenant import TenantRegistry, TenantRuntime

_TEMPLATES = Path(__file__).parent / "templates"


def template_names() -> list[str]:
    return sorted(p.stem for p in _TEMPLATES.glob("*.json"))


def load_template(name: str) -> dict:
    p = _TEMPLATES / f"{name}.json"
    if not p.exists():
        raise OmniError(404, "no_such_template", f"one of {template_names()}")
    return json.loads(p.read_text(encoding="utf-8"))


def parse_agents(spec: str) -> list[dict]:
    """'ops-agent:finance:pay|refund:issue,intern-bot:crm:write' -> [{name, permissions}]. Permissions are split on '|'."""
    out = []
    for part in [s for s in (spec or "").split(",") if s.strip()]:
        name, _, perms = part.strip().partition(":")
        out.append({"name": name, "permissions": [p for p in perms.split("|") if p]})
    return out


def create_tenant(reg: TenantRegistry, tenant_id: str, name: str, *, template: str = "generic-starter", profile: str = "pilot",
                  admins: Optional[list] = None, approvers: Optional[list] = None, agents: Optional[list] = None,
                  auditors: Optional[list] = None, policy: Optional[dict] = None, handover_dir: Optional[str] = None,
                  write_keys: bool = False, public_url: str = "https://omnios.example.com") -> tuple[TenantRuntime, list[dict], Optional[str]]:
    rt, keys = reg.create(tenant_id, name, policy=policy if policy is not None else load_template(template), profile=profile,
                          admins=admins, approvers=approvers, agents=agents, auditors=auditors)
    out = write_handover(rt, keys, handover_dir, write_keys, public_url) if handover_dir else None
    return rt, keys, out


def write_handover(rt: TenantRuntime, keys: list[dict], out_dir: str, write_keys: bool, public_url: str) -> str:
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    info = rt.public_info()
    (d / "tenant-public.json").write_text(json.dumps({**info, "public_url": public_url,
                                                      "checkpoint_url": f"{public_url}/public/{rt.id}/checkpoint"}, indent=2), encoding="utf-8")
    (d / "witness-entry.json").write_text(json.dumps({"name": rt.id, "origin": info["origin"], "url": public_url, "tenant": rt.id,
                                                      "log_key": info["log_public_key"], "post_cosign": True,
                                                      "_note": "Delete \"url\" for a push-only witness (the log sends its checkpoints out)."}, indent=2), encoding="utf-8")
    (d / ".env.example").write_text(
        f"# Proxy-mode credentials for {rt.id}. Names are used in the rules as ${{SECRET:NAME}}.\n"
        f"# Either set environment variables like this, or put {{\"NAME\": \"value\"}} in tenants/{rt.id}/secrets.json.\n"
        f"OMNIOS_SECRET__{rt.id.upper().replace('-', '_')}__BANK_TOKEN=\n", encoding="utf-8")
    (d / "docker-compose.yml").write_text(
        "services:\n  omnios:\n    build: .\n    command: python -m omnios serve --root /data --host 0.0.0.0 --port 8000\n"
        "    ports: [\"8000:8000\"]\n    volumes: [\"./data:/data\"]\n    env_file: [.env]\n    restart: unless-stopped\n"
        "# ./data holds the database, the signing key and the secrets. Back it up. Lose log.key and the history cannot be extended.\n",
        encoding="utf-8")
    roles: dict[str, list] = {}
    for k in keys:
        roles.setdefault(k["role"], []).append(k["name"])
    people = "\n".join(f"- **{r}**: {', '.join(n)}" for r, n in roles.items())
    (d / "HANDOVER.md").write_text(_HANDOVER.format(
        tenant=rt.id, name=rt.cfg.get("name"), profile=rt.cfg.get("profile"), quorum=rt.cfg.get("admin_quorum"), people=people,
        origin=info["origin"], pub=info["log_public_key"], url=public_url), encoding="utf-8")
    if write_keys:
        (d / "keys.txt").write_text("ONE-TIME KEYS. Hand each to its holder, then delete this file.\n\n" +
                                    "\n".join(f"{k['name']:<20} {k['role']:<9} {k['key']}" for k in keys) + "\n", encoding="utf-8")
    return str(d)


_HANDOVER = """# OmniOS handover: {name}

Tenant `{tenant}` · profile **{profile}** · admin quorum **{quorum}** (changes to rules and keys need {quorum} admin(s))

## Who holds what
{people}

Keys were shown once at creation; only their hashes are stored. A lost key is replaced by a change (another admin approves),
not recovered.

## Connect an agent (one line per function)
```python
from omnios_sdk import OmniOS
gw = OmniOS("{url}", api_key="<the agent's key>")

@gw.governed("payments.send")
def pay(vendor, amount_eur): ...
```
The agent stops until the rules allow it. If the platform is unreachable the function does NOT run (fail-closed).

## Independent verification (the part that is worth the most)
1. Give the **witness** the file `tenant-public.json` BY ANOTHER ROUTE than this server (a call, a signed email). It holds the
   log's public key `{pub}`.
2. The witness adds `witness-entry.json` to its `witness.json`, runs `python -m omnios witness serve --config witness.json`
   (behind TLS), and gives YOU its public key and URL. Register it, then let this installation push to it:
   `python -m omnios tenant witness --id {tenant} --name <witness> --key <its key> --url <its URL>` and start the server with
   `python -m omnios serve --push-interval 300`. Only this installation makes outbound calls; nothing needs to be reachable
   from outside. Two or three witnesses from different organisations are stronger than one.
3. The witness should be someone who is NOT an administrator of this installation (internal audit, security, the customer's
   auditor, or the party that asked for the proof). A witness run by an administrator proves nothing.

## Every month
- The witness produces `python -m omnios witness report --month YYYY-MM` (checks done, refusals, gaps).
- You export the evidence: `python -m omnios bundle export --tenant {tenant} --scope all --out bundle.zip` and give it,
  with the report, to whoever asked. They check it with `verify.py` inside the bundle, pinning the log key above.
- Review pending changes to rules and keys; review who still holds a key.

## What this does NOT cover
Whether decisions were right; actions the agent took without asking (use proxy mode for money and anything irreversible);
single sign-on or MFA for approvers (keys are bearer secrets); an external security review of this software; legal advice.
"""
