---
description: Check Tracekit's signer setup
---
Run `tracekit doctor` with the Bash tool and summarize the result in a few lines: which setup it found (the v2 dev
signer or v2 system mode), and each check that fails or warns, with its fix. Doctor from 1.3 counts this plugin's
hooks; there a `D-HOOKS-PRESENT` warning means `tracekit init`'s hooks run too, which blocks every approved call until
one of the two is removed. Before 1.3, doctor warns `D-HOOKS-PRESENT` with this plugin, which is expected.
If no signer is set up, say so plainly and give the one-line fix (`tracekit init --dev --v2 --no-hooks`, or
`sudo /usr/bin/python3 -m tracekit init --v2 --user <agent-user> --no-hooks` for real tamper resistance).
