---
description: Check Tracekit's signer setup
---
Run `tracekit doctor` with the Bash tool and summarize the result in a few lines: which setup it found (the v2 dev
signer or v2 system mode), and each check that fails or warns, with its fix. A `D-HOOKS-PRESENT` warning is expected
with this plugin: doctor reads hooks from Claude Code settings files, and the plugin's hooks are not in one.
If no signer is set up, say so plainly and give the one-line fix (`tracekit init --dev --v2 --no-hooks`, or
`sudo /usr/bin/python3 -m tracekit init --v2 --user <agent-user> --no-hooks` for real tamper resistance).
