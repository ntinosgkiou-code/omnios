# The independent witness: how it works, what it proves, what it does not

The idea in one line: **whoever runs the system cannot quietly rewrite its past, because someone else already remembers it.**
The operator still *writes* the log. What it cannot do, without being caught, is change what a witness has already seen.

## 1. The parties

| Party | Holds | Does |
|---|---|---|
| **The log** (the customer's OmniOS installation) | the ledger and its signing key | writes records; signs a *checkpoint* (size N, root hash R) |
| **A witness** (a separate service on someone else's machine, with its own key) | the log's *public* key (given to it another way), and the last checkpoint it accepted | checks that each new checkpoint extends the previous one, and cosigns only if it does |
| **The auditor / insurer / customer** | the log's public key and the witnesses' public keys (each obtained another way) | checks an evidence bundle offline and sets the bar: *how many witnesses, how recent* |

A checkpoint contains no data: only the size, a root hash and signatures. The witness never sees parameters, names, amounts or credentials.

## 2. The push flow (the one customers accept: only the log makes an outbound call)

```
 customer's installation                                  witness (its own server, its own key)
 ───────────────────────                                  ──────────────────────────────────────
 ledger grows to size N
 signs checkpoint (N, R)
 POST /witness/v1/add-checkpoint ─────────────────────►   1. is this log known, and is the checkpoint signed by the
   { origin, old_size, proof, note }                          log key I was given? (no → 403, nothing recorded)
                                                          2. is old_size what I hold? (no → 409 + my size; the log retries)
                                                          3. does the proof show my last tree is a prefix of this one?
                                                             no → 422 REFUSED, ALERT recorded, nothing cosigned
                                                             yes → remember (N, R), sign
 stores the cosignature  ◄───────────────────────────────  { cosignature }
 (only if it verifies against the witness key
  registered for this tenant)
```

`python -m omnios serve --push-interval 300` does this every five minutes for every witness registered with a URL. The older **pull** mode (the witness fetches `/public/<tenant>/checkpoint`) still exists for logs that can be reached from outside; both modes share one history and one report.

## 3. What a cosignature says, in exact words

> "At time T, I received a checkpoint of log L (size N, root R), signed by the key I was given for L, and it extends the checkpoint I accepted before."

It does **not** say the records are correct or complete, that every action was logged, or that the people named really approved.

## 4. What it catches and what it does not

| Catches | Does not catch |
|---|---|
| An old record edited, deleted or reordered (the new tree does not extend the old one) | A false record *added now* (it extends the old tree perfectly). That needs approvals signed by the approvers' own keys (`KNOWN-LIMITS.md` G1) |
| A log cut back to an earlier size (restored backup, truncation): "log shrank" | An action the agent took without asking, so it was never logged (use proxy mode; compare with the system of record) |
| A fork: a different tree of the same size, or one history shown to the witness and another to the auditor (the bundle must extend what the witness cosigned) | A witness that colludes with the operator, or runs on the operator's machine |
| (pull mode) A log that signs a bigger tree and refuses to prove it extends the old one: ALERT, not "outage". In push mode a log that simply stops pushing shows up as GAPS | Anything that happened between two checks and was fully repaired before the next |

## 5. Who runs the witness decides what it proves

| Level | Run by | It proves |
|---|---|---|
| 1 | the customer's internal audit or security | independence from the administrators of the system |
| 2 | an external auditor or an insurer | independence from the customer and from the vendor |
| 3 | the vendor, as a service | independence from the customer's administrators, **not from the vendor**. Say so |

Strongest: two or three witnesses from different organisations, and a verifier that demands them.

## 6. What the person asking for proof can demand

```
python verify.py bundle.zip --log-key <log public key> \
    --witness auditor=<key> --witness insurer=<key> \
    --min-witnesses 2 --max-age 36h
```

- `--min-witnesses K`: at least K *distinct trusted* witnesses must hold a valid cosignature on a checkpoint this log provably extends. A witness whose key you did not pin does not count.
- `--max-age AGE`: a witness counts only if its latest cosignature is that recent (`36h`, `7d`, `3600`). This needs the `cosignature/v1` timestamp; a plain signed-note cosignature has none and cannot prove freshness.
- The report also says how far the log is covered by K witnesses (`records 0..m`) and warns about the tail that is not yet witnessed.
- A witness that saw one history while the bundle shows another makes the bundle **fail** ("does NOT extend"), even when the log key signs everything correctly.

## 7. Setting it up (about ten minutes)

```
# on the witness's machine (a person who is not an administrator of the installation)
python -m omnios witness init --out witness --name auditor-witness      # prints its public key
# edit witness/witness.json: for each customer add
#   {"name": "acme", "origin": "omnios/acme", "log_key": "<the log's public key, received another way>"}
python -m omnios witness serve --config witness/witness.json --port 8100   # put TLS in front

# on the customer's installation
python -m omnios tenant witness --root data --id acme --name auditor-witness --key <witness public key> --url https://witness.example
python -m omnios serve --root data --push-interval 300
# or once, from a scheduler:   python -m omnios push --root data
```

Monthly: `python -m omnios witness report --config witness/witness.json --month 2026-10` (CLEAN / GAPS / NO COVERAGE / ALERT per log).

## 8. Failure modes, in plain words

| What happens | What you see |
|---|---|
| The witness is down | pushes fail with "witness unreachable"; the report shows GAPS; during a gap a rewrite could not have been noticed |
| The customer restores an old backup | the witness refuses ("log shrank"): ALERT. Correct behaviour: tell the witness's owner, who decides whether to accept a reset |
| The customer's push progress note is lost | the witness answers 409 with its size and the push continues |
| Someone sends a forged checkpoint to the witness | 403, not recorded: a stranger cannot make a customer's report say ALERT |
| The witness key is lost or leaked | register a new witness key (a change recorded in the ledger); old cosignatures stay valid for what they signed |

## 9. Honest limits of this implementation

- The push protocol is modelled on the C2SP witness `add-checkpoint` idea but is **our own JSON format**, not wire-compatible with third-party witnesses. `cosignature/v1` signatures follow the published description and have only been tested against this code.
- No authentication on `add-checkpoint` (it needs none: only validly signed, consistent checkpoints do anything), but also **no rate limiting**: put the witness behind a reverse proxy.
- One witness process holds its state in one JSON file; no replication or HA.
- Witness key rotation is manual: a new key can be registered, but a registered witness key cannot yet be *removed* from a tenant.
- Never run against a third party's witness, a real customer or a real auditor.
