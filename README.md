# agentdryrun Gateway (codename OmniOS)

![status](https://img.shields.io/badge/status-draft%2C%20never%20used%20with%20a%20real%20customer-orange)
[![tests](https://github.com/ntinosgkiou-code/omnios/actions/workflows/tests.yml/badge.svg)](https://github.com/ntinosgkiou-code/omnios/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)
![license](https://img.shields.io/badge/license-all%20rights%20reserved-lightgrey)

**Make AI agents ask before they act, and keep a record nobody can quietly edit.**

*Think four-eyes approval for software agents, plus a black box that a third party can check without trusting you.*

When an AI agent moves money, changes a customer record or deletes data, sooner or later someone asks:
*who approved this? can you show the record was not changed afterwards? what stops it doing that again?*
The Gateway answers all three. It sits between the agent and the systems it acts on, applies **your** rules, waits for **named humans** when the rules say so, and writes every step to a signed, append-only log that an auditor can verify **offline**.

![Terminal output of python -m omnios demo, shortened: a payment that needs two different approvers, the agent unable to approve its own payment, a payment over the ceiling refused, a rule change that needs a second admin, an edited evidence pack that fails verification, and witnesses refusing a rewritten log](docs/assets/demo.png)

*Real output of one command (`python -m omnios demo`), shortened. All data is invented.*

> **Status: draft. Source published for reading, evaluation and review; never run with a real agent, bank or customer.** 175 automated tests pass and a full rehearsal runs end to end, but nothing is deployed and nothing has had an external security review. Read [`docs/KNOWN-LIMITS.md`](docs/KNOWN-LIMITS.md) before you say anything about this to anyone: it lists what is **not** proven.

---

## Where it fits

| | **agentdryrun** (free, open) | **Gateway** (this repository, source-available) |
|---|---|---|
| What it does | **Looks back.** Reads what an agent did and shows what your rules *would* have stopped. Read-only. | **Acts.** Refuses, waits for humans, executes through a proxy, writes the signed log. |
| Changes anything? | No. A dry run. | Yes: it is the gate the agent goes through. |
| Typical first step | `python -m agentdryrun scan` on your own Claude Code history | **Observe mode** (below): the same dry run, kept as evidence, before anything is enforced |
| The part you must trust | Nothing: it is local and you can read it | Nothing it asserts, because the verifier and the witness are open |

The split is deliberate: **the part you have to trust is the part you can read.** The Gateway *produces* evidence; the open verifier, the witness service and the rules language (all in the public [agentdryrun](https://github.com/ntinosgkiou-code/agentdryrun) repository) *check* it. You do not have to take the Gateway's word, only the signed file and the public key you got another way.

---

## What you get

| | |
|---|---|
| **Rules that decide** | One JSON rules file per customer: what is allowed at once, what needs N different people (optionally from a named group), what is refused, with limits per day, week or month. Missing or unreadable inputs go to a human, never to "allowed". |
| **Approvals the agent cannot fake** | The agent cannot approve its own action; the same person cannot approve twice; approver groups come from the approver's key, not from the request. |
| **A signed, append-only log** | Every step is a record written *before* the action happens: proposal, each approval, execution. A Merkle tree with a signed checkpoint, per customer. |
| **Evidence packs** | One zip that an auditor, insurer or customer checks offline with a single stdlib-only Python file and a public key obtained another way. Edited, removed or reordered records fail. |
| **Witnesses** | Separate services with their own keys that remember checkpoints and **refuse** any that rewrite the past. The auditor chooses how many witnesses and how recent. |
| **Observe mode** | The low-risk first step: nothing is blocked; reported actions are judged against the rules and you get a report of what *would* have been refused or sent for approval. |
| **Many customers, one codebase** | Each customer has its own folder, key, rules, log and counters. Nothing is shared: not a table, not a key, not an id counter. |
| **Browser UI and SDK** | Approvers see requests and approve or reject; admins propose rule changes; auditors export evidence. Python SDK: `@gw.governed("payments.send")`. |

---

## Try it (about two minutes)

Tested on Python 3.11 and 3.12, on Linux and Windows (see the badge and `.github/workflows/tests.yml`).

```bash
pip install -r requirements.txt          # fastapi, uvicorn, cryptography, pydantic, pyyaml
python run_tests.py                      # 175 tests, about a minute (Windows: the runner sets PYTHONUTF8=1 for you)
python -m omnios demo                    # two customers, approvals, an edited pack, a rewritten log, witnesses
python -m omnios ui-demo                 # the browser UI with a ready-made demo customer (http://127.0.0.1:8765/ui)
```

The demo walks through, in one run: two customers on one platform; a 4,000 EUR payment that needs two different people; a 25,000 EUR payment refused for being over the ceiling; customer B unable to see customer A; a rule change that needs a second admin; an evidence pack verified offline; the same pack with one name edited, which fails; two witnesses on their own servers; and an operator who rewrites history, which both witnesses refuse. It finishes by telling you what it did **not** show: a real agent, a real bank, single sign-on, or an external security review.

### The four deliverables

```bash
# 1. Agent Control Check: an answers file in, findings + draft rules + report out
python -m omnios assess init   --client "Acme" --out answers.yaml
python -m omnios assess report --answers answers.yaml --out report

# 2. Setup of one flow: a tenant with its own rules, keys, signed log and a handover folder
python -m omnios tenant create --root data --id acme --name "Acme" --template finance-ap-payments --profile production \
       --approvers maria,nikos --auditors audit --agents "ap-agent:finance:pay" --handover handover/acme
python -m omnios serve --root data

# 3. Evidence pack: one zip, checked offline against a pinned key
python -m omnios bundle export --root data --tenant acme --out acme.zip
python -m omnios verify acme.zip --log-key <pinned key>

# 4. Monthly verification: a witness that checks the log only ever grew, and a monthly report
python -m omnios witness init  --out witness --name witness-1
python -m omnios witness serve --config witness/witness.json
python -m omnios tenant witness --root data --id acme --name witness-1 --key <key> --url https://witness.example
python -m omnios serve --root data --push-interval 300          # the customer pushes checkpoints outward
python -m omnios verify acme.zip --log-key <key> --witness witness-1=<key> --min-witnesses 2 --max-age 36h
python -m omnios witness report --config witness/witness.json --month 2026-10
```

Agents connect with the SDK in [`sdk/omnios_sdk.py`](sdk/omnios_sdk.py):

```python
@gw.governed("payments.send")
def send_payment(supplier, amount_eur): ...
```

### Observe mode: start without blocking anything

```bash
python -m omnios tenant create --root data --id acme --name "Acme" --policy rules.json --agents "ap-agent:finance:pay"
python -m omnios observe import --root data --tenant acme --agent ap-agent --file export.csv     # or @gw.observed("payments.send") in the agent
python -m omnios observe report --root data --tenant acme --out shadow-report.html
```

Nothing is blocked and nothing is executed. The report shows what the rules *would* have said (would pass, would need approval, would be refused) and which tools no rule covers. It sees **only what you report**: an agent that is not reported is not seen. The same dry-run engine runs locally and for free in [agentdryrun](https://github.com/ntinosgkiou-code/agentdryrun).

---

## How it works

```text
 AI agent ──► GATEWAY ──────────────► append-only log, one per customer
              rules, limits,           every step is a record
              named approvers          leaf = SHA-256(0x00 | record)
              (refuse / wait / run)    Merkle tree (RFC 9162), signed checkpoint
                                               │
                                               ▼  outbound only
                                     WITNESSES (other servers, other keys)
                                     cosign a checkpoint only if it extends the
                                     last one they saw; otherwise refuse and alert
                                               │
                                               ▼
                              evidence bundle (.zip) ──► verify.py  (offline, any machine)
```

1. **No evidence, no action.** The record is written before the state changes and before any upstream call. If the log cannot be written, the call fails and nothing happens.
2. **Records hold identifiers, digests and the rule-generated reason for each decision**, never raw credentials. A reason can quote a number (for example a daily total over a limit); parameters are kept in the customer's own state database.
3. **Decisions follow a fixed order:** unknown tool, missing permission, high-risk classification, deny rules, escalation rules, limits, then the number of distinct approvers. Anything that cannot be evaluated goes to a human.
4. **Fail closed.** An unknown tool is refused; an irreversible tool can never be marked low risk; limits are re-checked at approval time.
5. **Identity comes from the key, never from the request.** Only the SHA-256 of a key is stored. Changes to rules and keys are themselves actions: in a `production` customer they need a second admin.
6. **The verifier needs only a file and a public key** and ships inside every evidence pack. **Use your own copy**, never the one inside the pack: whoever made the pack wrote that one.

Full design: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Bundle format: [`docs/EVIDENCE-BUNDLE-SPEC.md`](docs/EVIDENCE-BUNDLE-SPEC.md). Witness protocol and independence levels: [`docs/WITNESS.md`](docs/WITNESS.md). Running it step by step: [`docs/OPERATIONS.md`](docs/OPERATIONS.md).

---

## Who it is for, and who it is not

**For** a team that runs AI agents with real tool access (payments, customer records, deployments) and has to answer an insurer, an auditor or a customer: *how do you prove what the agent did, and who approved it?* The first conversation is observe mode on the agent's own log, because it needs no change to the agent and blocks nothing.

**Not for** you if write-once storage plus a separate security team already satisfies your auditor: object lock stops deletion, but says nothing about order, completeness or whether the approval rules were followed. This is for the case where a **third party must be able to check without trusting you or us.**

It does **not** stop prompt injection, it does not make you compliant with any regulation, and it is not a certification.

---

## What it does not do (read before relying on it)

The complete list, with severity and what to do about each, is [`docs/KNOWN-LIMITS.md`](docs/KNOWN-LIMITS.md). The ones that matter most:

- **Never run with a real agent, customer or bank.** Everything above is tests and one rehearsal. The Docker image is built and smoke-tested in CI, nothing more.
- **Approvals are attested by the platform, not signed by the humans themselves (G1).** An operator who holds the log key could add a false "alice approved" record *at the time of the action*. A witness catches a rewritten past, not a false present. The fix (approver-held keys signing each approval) is designed, not built.
- **A witness only proves it saw a checkpoint** that extends the previous one. It does not say the history is correct or complete, and a witness you run yourself for a log you also run proves nothing about you (G7).
- **An agent that never asks is invisible.** Evidence covers actions that pass through the Gateway, or that you report in observe mode.
- **No single sign-on, no alerts, no high availability, no rate limiting, no external security review, no dependency pinning** (G5, G11, G13). Recovery from a lost admin key is not built (G2).
- **Observe mode sees only what is reported**, the time of an event is the one the customer claims, and the verdicts are a simulation (G17).
- **The Agent Control Check scoring is my own judgement**, not validated against real incidents, and its mapping to OWASP and EU AI Act items is "relevant to", never "compliant with" (G12).

---

## FAQ

**Is this a blockchain?** No. It is a transparency log (the design behind Certificate Transparency), with witnesses instead of consensus.

**Why not just write logs to write-once storage?** See above: it does not prove order, completeness or that the approval rules were followed, and you still trust the cloud account.

**Why is it not open source?** The source is published so it can be read, evaluated and reviewed. No license is granted yet: that is an irreversible decision and the commercial terms are not settled. The parts you must be able to trust are open under Apache-2.0 in [agentdryrun](https://github.com/ntinosgkiou-code/agentdryrun): the verifier, the witness, the rules language and the local dry run. See [`LICENSE`](LICENSE).

**What is "OmniOS"?** The first name of this project. The free tool was renamed **agentdryrun** because OmniOS is also the name of an unrelated, actively released operating system (omnios.org). The Python package and the CLI of this repository are still called `omnios`; the evidence-bundle format identifier `omnios-evidence-bundle` and the `omnios/<tenant>` log origin stay as they are on purpose, because changing them would break signed bundles.

**Which standards?** RFC 9162 (Merkle trees and proofs), C2SP signed-note and tlog-checkpoint layouts (implemented from the published text, not yet cross-checked against another implementation), Ed25519 (RFC 8032). The witness push protocol is our own JSON and is **not** wire-compatible with the C2SP witness protocol yet.

---

## Roadmap

In this order, and only as a first design partner makes each one real:

1. A first design partner with a real agent (everything built without one is a guess).
2. Approver-signed approvals (passkeys or Ed25519) so a record carries the human's own signature (G1).
3. Recovery of a lost admin key and reconciliation after a crash (G2, G3).
4. An external security review before real money (G11).
5. Single sign-on, alerts, and a small admin UI (G13).

## Repository map

```text
omnios/                the platform: ledger, rules engine, tenants, API, UI, evidence, verifier, witness, push, assessment, provisioning, CLI
omnios/templates/      rule templates              omnios/assess_data/   the Agent Control Check answers file
sdk/                   Python SDK                  scripts/demo_platform.py   the end-to-end demo
tests/                 175 tests, no network       docs/                 architecture, bundle spec, witness, operations, trust gaps
docs/assets/demo.png   made by scripts/make_readme_assets.py from the real demo output
LICENSE, SECURITY.md, CONTRIBUTING.md, CHANGELOG.md, ROADMAP.md   how it is governed and built, in public
Dockerfile, pyproject.toml, .github/   container, packaging and CI
```

## Work with me

I am looking for **two or three design partners**: teams that run AI agents on money, customer or data flows and are willing to try observe mode on their own agent's log. You report what the agent does, you get the report and, if you want, a signed record. To talk, open an issue titled `design partner` in this repository (no personal details needed).

## License

All rights reserved: the source is published for reading, evaluation and security review, and no license to use, copy, modify or distribute it is granted yet (see [`LICENSE`](LICENSE)). The open parts live in [agentdryrun](https://github.com/ntinosgkiou-code/agentdryrun) under Apache-2.0. Security reports: [`SECURITY.md`](SECURITY.md).
