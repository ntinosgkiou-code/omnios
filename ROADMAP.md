# Roadmap

Honest status. Order of work, and only as a first design partner makes each item real:

## Done (tested)
- [x] Rules engine, four-eyes approvals, approver groups, limits, fail-closed behaviour
- [x] Signed append-only log per customer (Merkle tree, RFC 9162 layout)
- [x] Evidence bundles and an offline verifier
- [x] Witnesses on their own servers, outbound-only push, refusal of rewritten history, monthly report
- [x] Observe mode (dry run on reported actions)
- [x] Browser UI, Python SDK, assessment kit, tenant provisioning
- [x] CI on Python 3.11 and 3.12 (Linux and Windows) and a Docker build with a smoke test

## Next
- [ ] A first design partner with a real agent (G6)
- [ ] Approver-signed approvals (G1)
- [ ] Recovery of a lost admin key and reconciliation after a crash (G2, G3)
- [ ] An external security review and dependency pinning (G11)
- [ ] SSO, notifications, rate limiting (G5, G13)

## Not planned here
- Compliance claims or certification of any kind.
- A hosted multi-customer service run by the author before the items above.
