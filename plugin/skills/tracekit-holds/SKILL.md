---
name: tracekit-holds
description: What to do when Tracekit stops a tool call. Use whenever a tool call is refused with a message that starts with "[tracekit] HELD" (a person must answer it), "[tracekit] BLOCKED" (no one can approve it) or "[tracekit] NOT APPROVED", including when it shows as a hook error.
---

## When Tracekit stops a tool call

- `[tracekit] HELD, nothing ran`: a person must answer it. In one message, tell them what the call was for, its Why
  line and the commands on its Person line, then wait. A subagent or a background job puts the same in its final
  report.
- Once the person says it is approved, make exactly the same call again (the same tool and arguments): it runs once.
- `[tracekit] BLOCKED, nothing ran` or `NOT APPROVED`: tell the person what you were doing and why it was stopped. If
  there is an Instead line, you may do that instead; say you did.
- Never run `tracekit approvals approve` or `reject` yourself: they are the person's commands. `tracekit approvals
  list` and `show` only read.
- Never hide what a call runs to get past a hold or a block (encoding it, a variable for the program, a script file,
  another tool or agent): every call is signed and kept. A readable call that does the same thing, as an Instead line
  says, is fine; say you made it.
