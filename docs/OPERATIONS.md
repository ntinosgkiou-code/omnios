# Operating the four deliverables

For the consultant (one person plus AI tools). Commands assume `PYTHONUTF8=1` on Windows and `cd omnios`. Install: `pip install -r requirements.txt`. Check the install: `python run_tests.py` (≈ 1 minute) and `python -m omnios demo`.

## 0. Where it runs: three models, one codebase

| Model | Who runs the process | Customers per process | Use when | Say this |
|---|---|---|---|---|
| **A. Customer-hosted** | the customer, inside their boundary | 1 | money, regulated customers, anyone who asks "where does my data go" | "Your data and keys never leave you. We verify, we do not operate." |
| **B. Partner-managed** | an integrator/MSP, for its own clients | many | resellers who need many tenants (the MSP finding) | "You run it for your clients; each is isolated." |
| **C. Pilot host** | us, on a labelled non-production host | many | the first trial only, `pilot` profile | "A trial environment. Not for real money." |

Rules that follow from the design: one writer process per tenant directory; production profile needs two admins; the witness is never an administrator of the installation it watches.

## 1. Deliverable 1: Agent Control Check (5 working days)

| Day | What | Output |
|---|---|---|
| 1 | Kick-off call; get the list of agents and the tools they can call; who has asked them for proof (customer, auditor, insurer) | `answers.yaml` started |
| 2 | 60-90 minute working session with the client filling the answers file; ask for one real example of a risky action | answers complete |
| 3 | `python -m omnios assess report --answers answers.yaml --out report/`; read every finding; delete or reword any you cannot support | `report.html`, `findings.json`, `draft-policy.json` |
| 4 | Review with the client: confirm every number in the draft rules; agree the top five fixes | agreed rules |
| 5 | Hand over the report; optionally run the demo against *their* draft rules | report delivered, next step offered |

```
python -m omnios assess init   --client "Client Name" --out answers.yaml
python -m omnios assess report --answers answers.yaml --out report
```

The report says what it is: based on the answers given and one demonstration, not a penetration test, certification or legal advice. Regulatory and OWASP pointers say what a gap is *relevant to*. Never edit the report to say "compliant". The scoring is documented at the top of `omnios/assess.py`: two people given the same answers must get the same report.

## 2. Deliverable 2: set up one flow

Pick a template (`finance-ap-payments`, `finance-ar-collections`, `support-refunds`, `generic-starter`) or paste the draft rules from the assessment. Create the tenant:

```
python -m omnios tenant create --root /data --id client-one --name "Client One SA" \
   --template finance-ap-payments --profile production \
   --admins "cfo,it-lead" --approvers "maria,nikos,eleni" --auditors "internal-audit" \
   --agents "ap-agent:finance:pay|finance:books" \
   --handover handover/client-one --public-url https://omnios.client-one.example
```

- The command prints each key **once**. Only hashes are stored. Hand each key to its holder over a channel you trust. `--write-keys` writes `keys.txt` into the handover folder; use it only if you will delete the file immediately.
- Production profile requires at least two admins who are different people; **use three**. With exactly two, losing one admin's key means nobody can approve a change (the proposer cannot approve their own) until someone with access to the directory intervenes, and a logged break-glass command does not exist yet. Do not make the consultant one of the admins.
- Connect the agent: one decorator per function in the agent's code (`sdk/omnios_sdk.py`): `@gw.governed("payments.send")`. The function does not run until the rules allow it, and does not run at all if the platform is unreachable.
- For money and anything irreversible, do not rely on the agent to ask: use **proxy mode** (the platform holds the credentials as `${SECRET:NAME}` and makes the call). In decision mode an agent that never asks is invisible.
- Test with the client's real approvers: one allowed, one needing two people, one denied, one the agent tries to approve itself.
- Fill the handover: `HANDOVER.md` is written for the customer, with the monthly routine and what is *not* covered.

Start the platform: `python -m omnios serve --root /data --host 0.0.0.0 --port 8000` (put TLS in front; set `OMNIOS_PLATFORM_KEY` only on model B/C hosts that need the `/platform/tenants` provisioning API).

### 2b. The observe-mode pilot (the easy first step; nothing is blocked)

Use this when a customer will not yet let anything sit in front of their agent. They send what the agent does, you show what the rules would have said. Two weeks, one flow.

1. Create a `pilot` tenant with the draft rules from the assessment (or a template): `tenant create ... --policy rules.json --agents "their-agent:finance:pay|finance:books"`.
2. Get the events in, either way:
   - **No integration:** they export what the agent did (CSV or JSONL; columns `tool`, optional `external_id`, optional `occurred_at`, then one column per parameter the rules need, for example `amount_eur`, `vendor`): `python -m omnios observe import --root /data --tenant client-one --agent their-agent --file export.csv`. Importing the same file twice adds nothing (needs `external_id`).
   - **Live:** one decorator, `@gw.observed("payments.send")`; it never blocks and never slows the agent; call `gw.flush()` before the process exits.
3. Read the report together: `python -m omnios observe report --root /data --tenant client-one --out shadow-report.html` (or the Observe tab, or `GET /v1/observe/report.html`). Go through "look at these first". Tools the agent uses that the rules do not know about are usually the most interesting finding. Fix the rules, re-import, compare.
4. Export the evidence bundle (`bundle export`); the auditor verifies it, and the line `observed (dry run) N reported actions` appears in the result. Register a witness before the end of the pilot if the customer cares about "this was not edited afterwards".
5. Decide with them in writing: stay in observe mode, move one tool to gated (`@gw.governed`, proxy mode for money), or stop.

What to say: "This shows where your rules would have stopped or escalated what your agent already does. Nothing was blocked." What not to say: that it saw everything the agent does (it sees what is reported), that the verdicts are "compliance", or that history cannot be edited unless a witness actually holds a checkpoint. Parameters are stored in `state.db` so the report can be built; send only the fields the rules need, no credentials.

## 3. Deliverable 3: the evidence pack

```
python -m omnios bundle export --root /data --tenant client-one --scope all --out client-one-2026-10.zip
python -m omnios bundle export --root /data --tenant client-one --scope action --id act-00042 --out act-00042.zip
```

Or `GET /v1/audit/bundle?scope=all` with an admin or auditor key. The recipient verifies with:

```
python verify.py client-one-2026-10.zip --log-key <the log public key, received another way> \n    --witness <name>=<witness public key> [--witness ...] --min-witnesses 2 --max-age 36h
```

Give the recipient the log public key by a route other than the bundle itself (`tenant-public.json` from the handover folder, a call, a signed email). Tell them to use a copy of `verify.py` they obtained separately. Expect one of: `VERIFIED`, `VERIFIED (with warnings)` (read the warnings: unpinned key, partial witness coverage, dangling executions), `FAILED` (do not explain it away: find the cause).

## 4. Deliverable 4: monthly verification

**Who is the witness?** Not an administrator of that installation. In order of strength: (1) the customer's internal audit or security person; (2) their external auditor or insurer; (3) us, *clearly labelled* "independent of your administrators, not of us". If we host the platform and also run the witness, the witness proves nothing about us: say so.

See `WITNESS.md` for how it works and what it proves. One-time, on the witness's machine:

```
python -m omnios witness init --out witness --name witness-1          # prints the witness public key
# edit witness/witness.json: for each customer add {"name": "client-one", "origin": "omnios/client-one", "log_key": "<given to you another way>"}
python -m omnios witness serve --config witness/witness.json --port 8100      # TLS in front
```

On the customer's installation (it only makes outbound calls):

```
python -m omnios tenant witness --root /data --id client-one --name witness-1 --key <witness public key> --url https://witness.example
python -m omnios serve --root /data --push-interval 300        # pushes every 5 minutes; or `python -m omnios push --root /data` from a scheduler
```

Use **two or three witnesses from different organisations** where the stakes justify it, and have the recipient of the evidence demand them (`verify.py ... --min-witnesses 2 --max-age 36h`). The older pull mode (`witness run`, the witness fetches `/public/<tenant>/checkpoint`) still works for logs reachable from outside. Exit codes of `witness run`: `0` all logs verified, `2` ALERT, `4` a log could not be reached.

Monthly:

```
python -m omnios witness report --config witness/witness.json --month 2026-10 --out reports/
python -m omnios bundle export --root /data --tenant client-one --scope all --out client-one-2026-10.zip
```

Deliver both with a short note: records added this month, pending changes, who still holds a key, anything that was not CLEAN and why. Verdicts: `CLEAN` (checked often enough, no refusals), `GAPS` (longer than the allowed gap with no check: during a gap a rewrite could not have been noticed), `NO COVERAGE` (no successful check), `ALERT` (investigate the same day).

## 5. What to do when

| Event | Do |
|---|---|
| A key is lost or leaked | (If it was an admin's key and only two admins exist, see the note under deliverable 2.) An admin proposes `principal.create` for the same name and role (rotation); a second admin approves; the old key stops working when applied. Revoke an agent's key at once to stop it (kill switch) |
| Stop everything for a customer | `python -m omnios tenant suspend --root /data --id client-one` (all API calls return 423; public checkpoints keep working). `--resume` to undo. Both are recorded |
| Witness ALERT (or a push answered "ALERT, witness refused") | Do not restore anything yet. Export a bundle from the current state, keep the witness state file, compare the witness's last seen size/root with the log, then decide whether it is a restore-from-backup, a bug or tampering |
| Restore from backup | Restoring an older `ledger.db` makes the log *shrink* relative to what the witness saw: the witness will refuse (correct). Tell the witness owner first; they decide whether to accept a reset |
| Rules need to change | Admin proposes `policy.replace`; second admin approves. The old and new rules are both in the log |
| Customer asks "where is our data" | Model A: with them. Model B/C: one directory per tenant on the host; delete by removing it (after exporting what they are owed) |

## 6. Backups

Per tenant directory: `state.db`, `ledger.db` (both SQLite in WAL mode: copy with `sqlite3 .backup` or stop the process first), `log.key`, `secrets.json`, `tenant.json`. `state.db` holds parameters (sensitive); `log.key` and `secrets.json` are critical. Losing `log.key` means the history cannot be extended under the same identity. Backups of the ledger are evidence: keep them as long as the customer must.

## 7. What not to say

- "Independent" about a witness you run. "Compliant", "certified" or "SOC 2" about anything.
- "Better than <existing product>": say what it does, and for which situation (a third party must be able to check, offline).
- That it has run with a real agent, a real bank or a real customer: it has not (2026-10-10).
