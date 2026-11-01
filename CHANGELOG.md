# Changelog

## Unreleased (2026-11-01)  Positioning and honesty update, documentation only
- README, landing page and roadmap now say who asks for this (auditors, insurers, large customers, the EU AI Act) and what the Gateway does and does not give them, instead of describing "control and proof" in the abstract.
- States plainly that no law requires a cryptographic record or an independent witness, so nobody is obliged to buy this, and that nobody has been shown to pay for it.
- Prompt injection: the Gateway is a second layer, not a filter. Added an honest note on the free Microsoft and AWS tools (the Microsoft toolkit is MIT and multi-framework, not Azure-only).
- The entry product is observe mode as an agent risk assessment (no credentials, nothing blocked); the proxy mode with customer keys comes only after an external security review.
- No code was changed.

## 2.0.0-draft (published 2026-10-26)  First public release of the source
- The platform as it stood on 2026-10-16: rules engine with four-eyes approvals, one signed append-only log per customer, evidence bundles with an offline verifier, witnesses that refuse rewritten history, observe mode, browser UI, Python SDK, assessment kit and provisioning. 175 tests.
- Published for reading, evaluation and review. **All rights reserved**, no license granted yet (`LICENSE`).
- Known limits are in `docs/KNOWN-LIMITS.md`: never run with a real agent, bank or customer; approvals are attested by the platform and not signed by the humans (G1); no external security review (G11).
- Added for publication: `pyproject.toml`, CI (tests on Python 3.11 and 3.12, Linux and Windows; Docker build with a smoke test), `SECURITY.md`, `CONTRIBUTING.md`, this changelog, an English `KNOWN-LIMITS.md` replacing the internal notes, a README with real demo output.
- Internal sales and coaching notes that were written for the maintainer are **not** part of this repository.
