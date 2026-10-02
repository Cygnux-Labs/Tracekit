---
description: Export this session's evidence bundle and verify it offline
argument-hint: "[--key signer.pub] [--witness git:/path]"
---
Export and verify a bundle for the latest run, using the Bash tool:

1. `tracekit export --out /tmp/tracekit-latest.tkb`
2. `tracekit verify /tmp/tracekit-latest.tkb $ARGUMENTS`

Report the verdict line, every WARN and FAIL with its reason, and whether the result is UNANCHORED (no pinned key or
witness was checked). Do not describe a verified bundle as proof of intent or complete coverage.
