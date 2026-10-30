---
description: List tool calls held for approval
---
Run `tracekit approvals list` with the Bash tool and list each pending approval (id, tool, rules, expiry). Tell the
user that approving or rejecting must be done from a terminal outside this session with
`tracekit approvals approve <id>` or `tracekit approvals reject <id>`; do not run those yourself. Once the user says a
call is approved, make the same call again, with exactly the same arguments: it runs under that approval, once.
