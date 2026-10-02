---
description: Show Tracekit's signer, witnesses, policy and capture sources
---
Run `tracekit status` with the Bash tool and summarize the result in a few lines: is the signer reachable, which
witnesses are configured, which policy version and fail mode are active, and which capture sources are on.
If the signer is unreachable or no witness is configured, say so plainly and give the one-line fix
(`tracekit init --dev`, or a system-mode install for real tamper resistance).
