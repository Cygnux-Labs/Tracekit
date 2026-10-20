"""The agent in the Sandbox (docs/integrations/agent-sandbox.md): a stand-in for a real agent's tool loop.

It reaches the signer in another namespace at $TRACEKIT_SIGNER over HTTPS as its service account (the projected token
in $TRACEKIT_SIGNER_TOKEN_FILE) and holds no key. It decides two calls, records the allowed one, prints what the
signer decided, and then waits to be deleted with its run still open, as a killed or compromised pod leaves it.
"""
import signal

from tracekit.sdk.client import Client

CALLS = [("c1", "Bash", {"command": "ls"}),
         ("c2", "WebFetch", {"url": "http://169.254.169.254/latest/meta-data/"})]   # the node's cloud credentials

run = Client().run(agent="support-agent")
print(f"run {run.run_id}", flush=True)
for call_id, tool, args in CALLS:
    d = run.decide(call_id, tool, args)
    print(f"{call_id} {tool}: {d['decision']} {' '.join(d['rule_ids'])}".rstrip(), flush=True)
    if d["decision"] == "allow":
        run.complete(call_id)   # stand-in tools: nothing runs
print("waiting to be deleted", flush=True)
signal.pause()
