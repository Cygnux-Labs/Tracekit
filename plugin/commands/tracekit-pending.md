---
description: List tool calls held for approval
---
Run `tracekit pending` with the Bash tool and list each held call (id, tool, rule, reason). Tell the user that
approving or rejecting must be done from a terminal outside this session with `tracekit approve <id>` or
`tracekit reject <id>`; do not run those yourself.
