---
description: List tool calls held for approval
---
Run `tracekit approvals list` in the shell and list each pending approval (id, tool, rules, expiry). Tell the
user that they approve or reject one themselves: in Claude Code by typing `! tracekit approvals approve <id>` (or
`reject`) in this session, where `!` runs it as them, or with the same command, without the `!`, from their own
terminal (in any other agent too; with a named
signer, as in system mode, only from the approver's own account: this session's user is the agent's); do not run
those yourself. Once the user says a call is approved, make the same call again, with exactly the same arguments: it
runs under that approval, once.
