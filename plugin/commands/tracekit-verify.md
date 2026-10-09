---
description: Export this session's evidence bundle and verify it offline
argument-hint: "[--key signer.pub] [--witness git:/path]"
---
Export and verify a bundle for the latest run, using the Bash tool:

1. `d=$(mktemp -d) && tracekit export --out "$d/latest.tkb"` (a private directory, not a fixed `/tmp` path)
2. `tracekit verify "$d/latest.tkb" $ARGUMENTS`, in the same shell command as step 1
3. `rm -rf "$d"`

Report the verdict line, every WARN and FAIL with its reason, and whether the result is UNANCHORED (no pinned key or
witness was checked). Do not describe a verified bundle as proof of intent or complete coverage.
