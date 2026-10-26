# OmniOS platform: architecture

Draft v2.0 · 2026-10-10 · nothing here is deployed, committed or sold yet. Written so that the next change is an addition, not a rewrite.

## 1. What the platform is for

An AI agent proposes an action (pay an invoice, refund a customer, delete a record). The platform decides under the customer's own rules whether it runs, waits for N different people, or is refused. Every step goes into a signed, append-only ledger. A third party who does not trust the operator can check that ledger from one file and one public key.

It is sold as four deliverables. They are four *views* of one core, not four products:

| # | Deliverable | What the customer gets | Code that serves it |
|---|---|---|---|
| 1 | **Agent Control Check** (5 days) | A report: inventory of agent tools, scored impact, control gaps mapped to OWASP agentic risks, a draft of the rules that would close them | `assess.py` + `assess_data/` |
| 2 | **Setup of one flow** | A running tenant with a policy from a template, keys for each person and agent, a handover folder | `provision.py`, `templates/`, `tenant.py` |
| 3 | **Evidence pack** | One zip that an auditor, insurer or customer checks offline | `evidence.py`, `verifier.py` |
| 4 | **Monthly verification** | A witness that checks the log only ever grew, and a monthly report | `witnessd.py` |

## 2. Needs analysis: what the first design (v1) got wrong for this

v1 was built as a single-customer demo for one conversation. Selling the four deliverables to many customers exposed these structural problems (numbers refer to the v1 trust-gap register):

| v1 | Why it blocks the four deliverables | v2 |
|---|---|---|
| One customer per installation; policy, keys and log in global state | A second customer means a second deployment, or customers sharing a ledger | **Tenant = directory.** Same code runs one tenant (customer-hosted) or many (partner-managed) |
| Merkle leaf = HMAC output only the operator can reproduce (C8) | A third party cannot check that the text they are shown is what was committed, so "who approved" cannot be verified | **Leaf = SHA-256 of the record's own canonical JSON.** Anyone holding a record recomputes it |
| A second log (SCITT) with its own key and no witness (C9) | Two things to run, explain and witness | **One ledger.** A SCITT export, if ever needed, is a view over it |
| Admin could create approvers and change rules alone (A7) | The control the customer is paying for can be switched off by one person | **Everything is an action:** rule changes and key changes are proposed by an admin and applied after `admin_quorum − 1` other admins approve |
| Any approver could approve anything (A5) | "Only finance approves payments" cannot be expressed | **Approver groups** per tool, taken from the approver's key |
| No evidence export (H3), no read-only role (H4) | Deliverables 3 and 4 had no product | **Evidence bundle**, **auditor role** |
| Witness private key stored inside its state file (C10); one log per witness | Cannot run monthly verification for several customers | **witnessd**: many logs, key in its own file, history for the monthly report |
| Proxy credentials from process environment variables | One customer's rules could name another customer's secret | `${SECRET:NAME}` resolved per tenant; `${ENV:` is rejected at validation |
| Clinic code and gateway in one application (C7) | Every install carried a medical product | Gateway only |
| Events listed by scanning memory (D6) | Fine for a demo | `refs` index in the ledger; bundles are paged |

What did **not** change on purpose: the action routes (`/v1/actions…`) and the SDK, so everything built against v1 keeps working; the policy language; the transparency-log primitives (`tlog.py`, copied unchanged).

## 3. Principles

1. **One customer, one directory.** `state.db`, `ledger.db`, `log.key`, `secrets.json`, `tenant.json`. Nothing is shared between customers: not a table, not a key, not an id counter. Isolation is by construction, not by a `WHERE tenant = ?` that someone can forget.
2. **No evidence, no action.** The ledger record is written *before* the state changes and before an upstream call is made. If the ledger cannot write, the call fails with 503 and nothing happens.
3. **The ledger holds identifiers, digests and decision reasons, never raw content.** A reason is rule-generated text and can quote a number (for example a daily total over a limit). Parameters, comments and credentials stay in `state.db` (or the customer's own systems). A ledger can therefore be handed to an auditor.
4. **Verification needs nothing from the operator except a file and a public key obtained another way.** The verifier is stdlib-only (pure-Python Ed25519 fallback) and ships inside every bundle.
5. **Fail closed.** Missing or non-numeric fields that a rule needs go to a human; an unknown tool is denied; an irreversible tool can never be low risk; limits are re-checked at approval time.
6. **Identity comes from the key, never from the request.** A key is `ogk_<tenant>_<random>`; the tenant routes the request before anything is looked up; only the SHA-256 of a key is stored.
7. **Say what a thing proves, and what it does not.** Every report, README and CLI output carries its own limits.

## 4. Component map

```
                 agents (SDK / HTTP)         approvers / admins / auditors (HTTP)       witness (anyone)
                         │                              │                                    │
                         ▼                              ▼                                    ▼
                ┌────────────────────── api.py (FastAPI) ───────────────────────┐   /public/<tenant>/…  (hash-only)
                │ /v1/…  key → tenant → role check     /platform/… (operator)   │──────────────────────────────┘
                └───────────────────────────────┬───────────────────────────────┘
                                                ▼
                                  tenant.py  TenantRegistry ──► one TenantRuntime per customer directory
                                                │
        ┌───────────────┬───────────────┬───────┴────────┬──────────────┬────────────────┐
        ▼               ▼               ▼                ▼              ▼                ▼
   identity.py      policy.py       engine.py        forwarder.py    ledger.py        kv.py
   keys (hashed)    rules, hash,    decide, approve,  proxy mode:     append-only,     SQLite state
   roles, groups    versions        changes, report   tenant secrets  signed, proofs   (actions, keys,
                                                                                         rules, counters)
                                                          ledger.py ──► tlog.py (RFC 9162, C2SP notes)

   ui/index.html (one static page, same API)   served at /ui
   evidence.py ──► zip ──► verifier.py (also inside the zip as verify.py)          witnessd.py (separate process)
   assess.py, provision.py, templates/, cli.py: the consultant's tooling around the same core
```

Module sizes are small on purpose (`omnios/*.py` ≈ 3,800 lines in total; tests and the demo ≈ 2,200).

## 5. Data model

Per tenant directory:

| File | Contents | Sensitivity |
|---|---|---|
| `tenant.json` | id, name, profile, admin quorum, approval TTL, registered witness keys, suspended flag | low |
| `state.db` | actions with full parameters, principals (SHA-256 of keys), policy versions, change proposals, id counters | **high**: back up, encrypt at rest |
| `ledger.db` | records, `refs` index, checkpoints, witness cosignatures | evidence: back up, keep forever |
| `log.key` | Ed25519 seed (0600). Lose it and the history cannot be extended under the same identity | **critical** |
| `secrets.json` | proxy-mode credentials, or use `OMNIOS_SECRET__<TENANT>__<NAME>` | **critical** |

Ledger record types (all `data` carries an `id`, indexed in `refs`):

| Type | Written when | Key fields |
|---|---|---|
| `tenant.created`, `tenant.suspended/resumed`, `witness.registered` | operator actions | profile, quorum, log public key |
| `policy.activated` | provisioning or an applied rule change | **the full policy**, its hash, previous hash, who, via which change |
| `principal.changed` | key created / rotated / revoked | name, role, groups, permissions, who, approvers |
| `change.proposed/approved/rejected/applied` | admin changes | kind, proposer, quorum, summary, approvers |
| `action.proposed` / `action.denied` | an agent proposes | tool, agent, `params_digest`, policy hash, risk, approvals required, reasons, effect key |
| `action.approved` / `action.rejected` | an approver decides | approver, n of N, groups, comment digest |
| `action.executing` → `action.executed` / `action.failed` | proxy mode: before and after the upstream call | approvers, attestation `gate_executed`, result digest, HTTP status |
| `action.executed` (attestation `agent_report`) | decision mode: the agent reports | approvers, result digest |
| `action.compensating/compensated`, `action.expired` | undo and timeout | |
| `action.observed` | observe mode: the customer's system reports something its agent did | tool, agent, `params_digest`, **dry-run verdict** (allow / pending / deny), approvals it would have needed, reasons, policy hash, claimed time, digest of the customer's own id. Never approved, executed or counted against real limits |

Record format and bundle format are versioned (`"v": 1`, `"version": 1`) so they can evolve without breaking old bundles. See `EVIDENCE-BUNDLE-SPEC.md`.

## 6. The flows

**An action.** `POST /v1/actions` → key → tenant → role `agent` → engine decides (permission, deny rules, escalate rules, limits, approvals) → *ledger* → state. Low risk is allowed at once. High risk waits. Each approval re-evaluates the rules and limits as they are *now*. When the last approval arrives: in decision mode the agent may proceed (and later reports); in proxy mode the platform logs `action.executing`, makes the call with the tenant's own secret, and logs the outcome. `idempotency_key` makes a retry return the same action.

**Observe mode (the low-risk way in).** `POST /v1/observe` (agent key, up to 200 events per call) or `python -m omnios observe import --file export.csv|.jsonl`, or the SDK's `@gw.observed(...)`. Each event is judged against the current rules as a **dry run** by the same `_decide` function that gates real actions, with one difference: limits are counted from the *observed* events inside their own claimed time window (`occurred_at`), because everything the customer reports actually happened. The verdict is written to the ledger as `action.observed` and kept in `state.db` (namespace `obs`, with the parameters) for the report. Nothing is blocked, executed, approved, or counted against the real limits of gated actions. A batch is validated as a whole before anything is written, and `external_id` makes a retry or a repeated import idempotent. `GET /v1/observe/report` (JSON) and `/report.html` (a page to hand over) summarize: would pass / would need approval / would be refused, by tool, why, tools missing from the rules, the cases to look at first. Limits that the report prints about itself: it sees only what is reported; the verdicts are a simulation under the rules in force; it says nothing about whether the actions were right. The SDK's `observed` decorator is deliberately **fail-open** (the opposite of `governed`): the function always runs, events are sent from a background thread, a lost event is counted in `observe_stats()`.

**A change.** An admin proposes `policy.replace`, `principal.create` (a new key, or a rotation of an existing name with the same role) or `principal.revoke`. The record `change.proposed` is written. With `admin_quorum = 1` (pilot profile) it applies at once; with 2 (production profile) a *different* admin approves first. A new key is shown once to the proposer and stays inactive until applied. Lock-out is prevented: you cannot revoke yourself or leave fewer admins than the quorum.

**Evidence.** `GET /v1/audit/bundle?scope=all|action|changes` (admin or auditor) → a zip. The auditor runs `verify.py bundle.zip --log-key <pinned> --witness name=<pinned>`.

**Monthly verification.** A witness is its own service (`witness serve`) on someone else's machine. The customer's installation *pushes* its signed checkpoint and a consistency proof to each registered witness (outbound calls only; `serve --push-interval`), and stores the cosignature that comes back. The witness cosigns only if the checkpoint extends the last one it accepted; a log that was rewritten, cut back or forked is refused and an ALERT is recorded. A pull mode (the witness fetches `/public/<tenant>/checkpoint`) remains for logs reachable from outside. `witness report --month` turns the history into CLEAN / GAPS / NO COVERAGE / ALERT per log. The person asking for proof then sets the bar when verifying: `--min-witnesses K --max-age 36h`. Full description: `WITNESS.md`.

## 7. Trust model: who must be trusted for what

| Party | Can do | Cannot do (without being caught) |
|---|---|---|
| **Operator** (whoever runs the process and holds `log.key`) | Read all state; refuse service; append records | Rewrite or delete history a witness has already seen; make a bundle verify that breaks the recorded rules |
| **Customer admin** | Propose rule/key changes | Apply them alone (production profile); approve actions |
| **Approver** | Approve/reject | Approve their own agent's action; approve twice; approve outside their group |
| **Agent** | Propose; report | Approve anything; see other agents' actions |
| **Auditor** | Read, export bundles | Change anything |
| **Witness** (must NOT be an admin of the installation; ideally 2+ from different organisations) | Refuse to cosign | Vouch for correctness; it only attests: "I saw this checkpoint and it extends the one before" |

The honest hole, stated first: **approvals are attested by the platform, not signed by the approver's own key.** An operator who holds the log key could append a false "alice approved" record *at the time of an action* (it would not rewrite history, so a witness would not object). It is visible to alice if she reviews her approvals, and the model "customer hosts it" removes the operator/customer split, but a skeptical CISO will find it. The designed fix is approver-signed approvals (section 9). See `KNOWN-LIMITS.md`.

## 8. Decisions and the alternatives rejected

| Decision | Alternative | Why |
|---|---|---|
| SQLite file per tenant | One Postgres, `tenant_id` column | Isolation is a property of the file, not of every query. Backup/restore/delete/export of one customer is a directory. One customer's integrity check never touches another's rows. Scale-out is "put different directories on different hosts", routed by the tenant in the key. Postgres can come later *behind* `kv.py`; the ledger is the part that must stay per-tenant |
| Leaf = hash of the record text | HMAC leaf (v1); SCITT statements | Verifiable by anyone with no secret; one mechanism instead of two |
| `prev` hash *and* a Merkle tree | Tree only | The chain makes "which record came right before" checkable record by record; the tree gives compact proofs and witnessing. Costs one field |
| Policy document stored **in** the ledger (`policy.activated`) | Only its hash | A bundle can prove which rules applied without asking the operator |
| Admin changes as ledger-recorded actions with a quorum | Role checks only | The control must not be removable by one person |
| `pilot` / `production` profiles | One mode | Honest labelling: pilot (quorum 1) is for trials and can be run by us; production needs ≥ 2 admins |
| Verifier = stdlib + inline Ed25519 fallback | Require `pip install` | An auditor must be able to run it on a locked-down laptop |
| Bearer API keys with the tenant in the prefix | OAuth/OIDC now | Fast to deploy for a first customer; `Principal` is the seam where OIDC plugs in (A4) |
| Decision mode **and** proxy mode | Proxy only | Decision mode is a one-line integration (agent asks, then acts); proxy mode (platform holds credentials) is the only way to *enforce*. Records say which attestation applies (`agent_report` vs `gate_executed`) |
| Draft policy generated from the assessment | Hand-written | The deliverables connect: report → rules → tenant. The draft always validates and is marked `x_review` |
| No UI in this draft | Port the v1 UI | The four deliverables are operated by a consultant with a CLI first; approvers can use the API/SDK. UI is an addition, not a dependency |

## 9. Extension points (each is an addition, none needs a re-architecture)

| Need | Where it plugs in | What stays unchanged |
|---|---|---|
| **Approver-signed approvals** (closes the hole in section 7) | `principal.create` already stores a record: add a public key. `approve` accepts a signature over `{action id, params digest, policy hash, decision}`; the record gets `data.sig`; the verifier checks it against the key in the `principal.changed` record | Record format (`v` stays 1, a field is added), ledger, tree, witness |
| **SSO / MFA** | `identity.Principal` is built from the key today; build it from an OIDC session instead | Engine, ledger, API roles |
| **Postgres / sharding** | `kv.open_kv` returns a store with put/get/all/delete; `TenantRegistry` maps tenant → runtime. A router on the key prefix sends a tenant to its host | Per-tenant ledger |
| **KMS/HSM for the log key** | `Ledger` needs an object with `sign(bytes)` and `public_key()`; pass a KMS-backed one | Everything |
| **Framework adapters** (MCP, LangChain, OpenAI Agents, n8n) | They are thin callers of `POST /v1/actions` + `report`; the Python SDK shows the shape | The API |
| **Notifications** (email/Slack for pending approvals) | `Engine._log` is the single choke point for events; a hook there | Engine logic |
| **Reconcile with the system of record** (find actions the agent took without asking) | A read-only connector per customer system comparing its log to `action.executed`/`gate_executed` | The ledger; this is the answer to "agent that never asks" |
| **More rule conditions** | `policy._validate_cond` + `eval_cond` | Stored policies (they are versioned documents) |
| **New bundle scopes or formats** | `evidence.build_bundle`, bump manifest `version` | Old bundles still verify (the verifier reads `format` and `version`) |
| **Retention and archiving** | Checkpoints and cosignatures make a prefix of the ledger archivable; proofs from the archive to the live tree are consistency proofs | Witnesses |

## 10. Known limits (the short list; details in `KNOWN-LIMITS.md`)

- **One writer process per tenant directory.** A second process gets a 503 (the primary-key collision fails closed); it does not fork the chain. To scale, shard tenants across processes, not workers across one tenant.
- **State and ledger are two SQLite files.** The ledger is written first, so a crash can leave a record without its state change, never the reverse. A reconcile-on-start routine is not built. The ledger is not an event store: it deliberately lacks the parameters, so state cannot be rebuilt from it.
- `Ledger.records` reads are paged (5,000 per call); a bundle of 6,000 records builds in ~4 s and verifies in ~1 s. Not measured beyond that.
- No rate limiting on the public and witness endpoints; the witness push protocol is our own JSON format, not wire-compatible with third-party witnesses. No time-stamping authority: record times are the operator's clock.
- Proxy-mode forwarder does not follow redirects and refuses private addresses, but DNS rebinding and an egress allow-list are open.
- Never run against a real agent, a real bank or a real customer. The Dockerfile has not been built.

## 11. Relation to v1

`mit-demo-v1-draft` and the Railway deployment are untouched. The `/v1/actions…` routes and `sdk/omnios_sdk.py` are compatible, so a demo built on v1 can point at v2. v1 data is not migrated (it is simulation data); v1's UI is not ported.
