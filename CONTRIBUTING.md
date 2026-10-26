# Contributing

OmniOS is a **draft** and the source is published for reading, evaluation and review (see [`LICENSE`](LICENSE): no license to use or redistribute is granted yet, so please talk to me before sending code). Issues and review are very welcome.

## Run it
```bash
pip install -r requirements.txt
python run_tests.py                 # 175 tests, no network, about a minute
python -m omnios demo               # the whole story in one run
```

## What helps most (in this order)
1. **Break it.** See [`SECURITY.md`](SECURITY.md): a bundle that verifies although it was changed, tenant isolation, approvals that should not count.
2. **Try to disagree with the verifier.** The evidence bundle format is written down in [`docs/EVIDENCE-BUNDLE-SPEC.md`](docs/EVIDENCE-BUNDLE-SPEC.md); a second implementation that disagrees with `omnios verify` on any bundle is a bug in one of them. Open an issue titled *verifier disagreement*.
3. **Tell me what is missing for your agent.** A real workflow (what the agent does, who must approve, what you would show an auditor) is worth more than any feature guess.
4. **Review [`docs/KNOWN-LIMITS.md`](docs/KNOWN-LIMITS.md)** and tell me which gap you would not accept.

## Ground rules
- No secrets, no customer data, no real people or companies in examples or issues. Use invented data and say so.
- A change in behaviour comes with a test. Say what a thing proves **and what it does not prove**; if a claim cannot be checked, do not write it.
- Be specific: the command you ran, what you expected, what happened.

The free, open parts (the dry run, the local scanner, the verifier and witness) are in [agentdryrun](https://github.com/ntinosgkiou-code/agentdryrun) under Apache-2.0.
