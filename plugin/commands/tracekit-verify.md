---
description: Export this session's evidence bundle and verify it offline
---
Export and verify this session's run with one Bash tool command (a private directory, not a fixed `/tmp` path):

`d=$(mktemp -d) && tracekit last --open -o "$d/latest.tkb"; rm -rf "$d"`

`tracekit last --open` exports the dev signer's most recent run (this session's stays open until the session ends, so
it is verified up to its last checkpointed record), pins the dev signer's key and verifies it. Report the result as
printed: the verdict line, any warnings, and the line that says whether the record is proof against the agent (an
older Tracekit prints Integrity and Assurance lines instead: report those). Dev mode, or dev assurance, means the
signing key belongs to the same user as the agent. In system mode the agent's user cannot read the signer's store: say an administrator exports the
run with `tracekit export --v2 --config /etc/tracekit/signer.yaml --run RUN_ID`. Do not describe a verified bundle as
proof of intent or complete coverage.
