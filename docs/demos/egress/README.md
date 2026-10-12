# Network coverage: an egress observer

The agent's one shell call (`./install.sh`) is allowed, and the script downloads from a host no call names. Its
connection goes through `tracekit egress serve`, a proxy outside the agent that the run's `proxy_env` points to; it
reports host, port, bytes and connections to the signer, never paths or content. Offline: the "outside" host is a
web server on this machine, which the observer's `egress.yaml` allows as `localhost`.

```sh
python examples/v2/demos/egress.py   # POSIX
tracekit verify run.tkb --trust trust.json
```

**What the record shows.** A signed `effect.observed` (observer `token:egress`, `attribution: token`, host and bytes),
a `reconcile.unexplained_effect` (no http call nor `explains` entry covers that host) and the server pack's
shadow-mode `incident.opened` that would notify. [verify.txt](verify.txt): `network observed (egress)` in the
coverage matrix, the unexplained host as a `[WARN] coverage` line.

**Why it matters.** A call's record says nothing of its side effects: an install script can reach anywhere. An
observer the agent doesn't control turns them into signed evidence the run's calls must explain.

[transcript.txt](transcript.txt) · [the example](../../../examples/v2/demos/egress.py) · [egress](../../egress.md)
