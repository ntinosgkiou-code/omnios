# Known limits

Published first, on purpose: this is what OmniOS does **not** do or has **not** been shown to do. Read it before you rely on any of it.

**What "checked" means here:** 175 automated tests (`python run_tests.py`) and one full rehearsal (`python -m omnios demo`). It has **never been run with a real agent, bank or customer**, and it has had **no external security review**.

**Legend:** ✅ covered by tests or code · 🔧 partly addressed · ❌ open · ⚠️ not verified.

## Open gaps

| # | Gap | Severity | Status | Mitigation / next step |
|---|---|---|---|---|
| **G1** | **Approvals are attested by the platform; they are not signed by the approver's own key.** An operator who holds the log key could append a false "alice approved" record *at the time of an action*. It does not rewrite history, so a witness does not object. Alice sees it only if she reviews her approvals. When the customer runs the system themselves the operator and the customer are the same party, which shrinks the gap, but a careful security reviewer will find it | High | ❌ | Designed, not built: an approver public key in `principal.created`, a signature over `{action, params digest, policy hash, decision}`, checked by the verifier. A new field, not an architecture change (`ARCHITECTURE.md` section 9) |
| **G2** | With **exactly two admins** in `production`, a lost admin key blocks every change (the proposer cannot approve their own). There is no recorded break-glass command | Medium | ❌ | Run with three admins. A recovery command that writes `tenant.recovery` to the ledger is not built |
| **G3** | State and ledger are two SQLite files. The ledger is written first, so a crash leaves a record without a state change, never the reverse. In that window an approver who retries can create a second approval record and the verifier can report a false "same approver twice". No reconcile on start | Medium | ❌ | A reconcile step comparing the last records with the state. The ledger alone cannot rebuild state (it deliberately does not keep parameters) |
| **G4** | One writer process per tenant. A second process gets 503 (the chain is not broken), but there is no multi-worker mode and no high availability | Medium | ✅ tested | Shard by tenant, not by workers per tenant |
| **G5** | No rate limiting. `/public/<tenant>/cosign` is open (it rejects anything not signed by a registered witness). No egress allow-list | Medium | ❌ | Reverse proxy with limits; egress allow-list |
| **G6** | Never run with a real agent, customer or bank. `cosignature/v1` was only tested against our own code | High | ❌ | The first design partner. The Docker image is built and smoke-tested in CI (see `.github/workflows/docker.yml`) |
| **G7** | Witness independence. A witness you run yourself for a log you also host proves nothing about you. The `verify.py` inside a bundle is made by whoever makes the bundle. The auditor can now require at least K witnesses from different organisations and a fresh signature, but the auditor states that rule; we do not enforce it | High | ✅ documented (`docs/WITNESS.md`) | The witness should be the auditor, insurer or the customer's internal audit (two or three of them). Keep a separate copy of the verifier with a published hash. Do not call a witness independent if you run it |
| **G8** | Scale: a 6,000-record bundle builds in about 4 s and verifies in about 1 s; not measured above that. No retention or archiving policy | Low | ⚠️ | Measure at 100,000 records before promising volume |
| **G9** | Times are the operator's clock; there is no timestamping authority. Witness cosignatures give an upper bound | Medium | ❌ | RFC 3161 later |
| **G10** | On disk: `secrets.json` and `state.db` (which holds parameters) are not encrypted; `log.key` is mode 0600 on POSIX but not checked on Windows; no KMS | Medium | ❌ | Disk or volume encryption now; a KMS later (the `Ledger` accepts any signer) |
| **G11** | No external security review, no dependency pinning, no penetration test | High | ❌ | A penetration test before real money |
| **G12** | The scoring in the Agent Control Check (weights such as +3/+2) is the author's judgement, not validated against real incidents. The OWASP and EU AI Act mappings are "relevant to", not compliance | Medium | ✅ stated in the report | Do not present it as a risk score beyond the classification you make together with the customer |
| **G13** | A basic browser UI exists (requests, evidence, rules and changes, observe mode). No SSO or MFA, no notifications | Medium | ❌ | Approvers can use the API or SDK. SSO and alerts when a design partner asks |
| **G14** | If the operator hosts a tenant, its parameters (possibly personal data) live in the operator's `state.db`: a data processing agreement, sub-processors and region apply | High | ⚠️ legal | Prefer the customer-hosted model. Get a lawyer for the agreement |
| **G15** | **License.** No license is granted: all rights reserved, source published for reading and evaluation. This was a deliberate choice, because granting a license cannot be undone and the commercial terms are not settled | n/a | decision recorded | See `LICENSE`. The verifier, witness and rules language are open under Apache-2.0 in [agentdryrun](https://github.com/ntinosgkiou-code/agentdryrun) |
| **G16** | The witness push protocol is our own JSON, not compatible with C2SP witnesses; no rate limiting, no HA, one state file; a registered witness key cannot yet be removed from a tenant; no automatic key rotation | Medium | ❌ | Reverse proxy with limits; a remove/rotate command; test with a third-party witness before promising interoperability |
| **G17** | **Observe mode** sees only what the customer reports. An agent that is not reported, or reported partly, is invisible. `occurred_at` is claimed by the customer (only checked to be between 2020 and tomorrow). The verdicts are a simulation, not proof the actions were right. Parameters are stored in `state.db` as for normal actions | Medium | ⚠️ stated in every report | Send only the fields the rules need. For money, the next step is gated or proxy mode, not observation |

## What can truthfully be said today

- "A third party can check offline, from one file and a public key obtained elsewhere, that the data was not changed, that a witness did not see a rewritten history, and that the rules written in the log itself were followed."
- "A witness on another server, with its own key, remembers the log. If someone rewrites the past, the witness refuses, and an auditor who requires at least two witnesses sees FAILED." (tested over real HTTP in the rehearsal)
- "Changes to rules and keys need a second admin in `production`."
- "Each customer has its own folder, key, log and counters."
- "175 automated tests pass, plus one full rehearsal that shows an attack on a bundle and a rewritten history."
- "In observe mode it shows where your rules would have stopped what your agent already does, without blocking anything." (with G17 next to it)

## What this project does not claim

- That a witness certifies the history is correct. It only certifies that it saw this checkpoint and that it extends the previous one.
- That a witness is independent when the operator runs it. That it makes anyone compliant, certified or "SOC 2".
- That approvals are signed by the humans themselves (G1).
- That it has run with a real agent, bank or customer, or that it is deployed anywhere.
- That an agent that never asks is controlled: for money and anything irreversible, use proxy mode.
- That it stops prompt injection. The Gateway limits what a fooled agent can do *through it*, and leaves evidence of what it did.

## Order of work (not a promise to build)

1. G6: a first design partner with a real agent. Everything built without one is a guess.
2. G1: signed approvals.
3. G2 and G3: recovery and reconcile.
4. G11: a penetration test before real money.
5. G13: SSO, alerts, a small admin UI.
