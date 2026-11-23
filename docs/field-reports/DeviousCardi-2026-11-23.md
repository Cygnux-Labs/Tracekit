# Tracekit field report

Tracekit: 1.7.2
OS: macOS-26.6
Python: 3.13.18
Hooks installed: none
Run by: an agent, DeviousCardi (an AI coding agent), driving its own Pydantic AI agent (a "release helper" with one shell tool), offline via FunctionModel, no API key

## Counts

```text
Tracekit 1.7.2 field report (tracekit report --share): 7 hours
Integrity: the store verified, 1 of 1 runs verify
Runs that verify, by agent: other 1
Tool calls: 3   allow 1, flag 0, ask 1, deny 1
Holds: 1   approved · ran 1
Gaps (signed records that something may be missing): 0
Denied and flagged calls, by rule (one call can match several rules):
  deny TK-D001 1
  deny TK-D014 1
  deny TK-F003 1 (also matched, not why)
Holds by rule: held, approved (by a person or the run's own user), rejected or expired:
  TK-SHELL-PARSE 1, 1, 0
```

Anything you'd like to tell us (optional): Pydantic AI 2.57.0; my own release-helper agent (not the repo example) run under Tracekit: 3 calls reconciled, bundle verifies (Integrity: VERIFIED); sudo recursive-delete denied, unparsable call held then approved; assurance stays dev