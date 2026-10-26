# Security

**This software has had no external security review and has never been run with a real agent, bank or customer.**
Do not put real money, real personal data or real credentials through it. [`docs/KNOWN-LIMITS.md`](docs/KNOWN-LIMITS.md) lists the known gaps with severity; some are serious (for example G1, approvals are attested by the platform and not signed by the approvers, and G11, no penetration test).

## Reporting a problem

Please report privately: **Security > Report a vulnerability** on this repository (GitHub private vulnerability reporting). Include what you did, what you expected and what happened.

What is most valuable, in this order:
1. **A way to make `omnios verify` (or the verifier inside a bundle) say VERIFIED for a bundle where a record was added, removed, edited or reordered.**
2. **A way for one customer to read or affect another customer's data** (the tenant isolation).
3. **A way for an agent to approve its own action, for one approver to count twice, or to bypass the rules or the four-eyes rule on rule changes.**
4. A way to make a witness cosign a checkpoint that does not extend the previous one.
5. Anything in the API that lets an unauthenticated caller do more than read the public checkpoint routes.

There is no bug bounty and no guaranteed response time: this is a draft maintained by one person. Reports are read and answered as soon as possible, and fixes are credited if you want.
