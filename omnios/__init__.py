"""
omnios — the OmniOS trust platform (v2 DRAFT): action control + independently verifiable evidence for AI agents,
built for MANY customers (tenants) from the first line.

    canonical   one canonical JSON / digest definition, used by every other module
    tlog        RFC 9162 Merkle tree, C2SP signed checkpoints, witness logic (ported, tested in v1)
    ledger      per-tenant append-only evidence ledger (the leaf IS the record, so a third party can check the text)
    policy      rules as data: validation, hashing, versioned history
    identity    principals and API keys (agent / approver / admin / auditor), tenant-scoped
    engine      the action workflow: propose -> approve -> execute, and admin changes under the same four-eyes rule
    tenant      isolation by construction: one directory, one database pair, one signing key per customer
    api         the HTTP surface (/v1 for a tenant's people and agents, /public for verifiers, /platform for the operator)
    evidence    the evidence bundle (deliverable 3) and its stand-alone offline verifier
    witnessd    the multi-log witness and the monthly report (deliverable 4)
    assess      the Agent Control Check kit (deliverable 1)
    provision   tenant provisioning and handover (deliverable 2)

See docs/ARCHITECTURE.md for why it is shaped this way.
"""
__version__ = "2.0.0-draft"
