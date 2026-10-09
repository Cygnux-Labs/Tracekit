# Quickstart: the v2 signer (preview)

The v2 signer is still a preview. It records every tool call your agent makes as a signed event, decides each call
against a policy before it runs, and exports a run as a bundle that anyone can verify offline. This page runs it on
your own machine (macOS, Linux or Windows) as a **dev** signer, which runs as your own user. It takes about a minute;
`make quickstart` runs the same steps on a clean venv (`tests/test_quickstart.py`).

## 1. Install

```sh
python3 -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install tracekit-ai                             # preview: pip install . from a checkout
```

You don't start anything yourself. The first client that needs a signer starts one in the background and later
clients reuse it (`tracekit up` / `tracekit down` do the same by hand). The signer's keys and store live in your user's
data dir. It listens on a Unix socket in a private runtime dir. On Windows it listens on a loopback TCP port instead,
and publishes the port and a token in `%LOCALAPPDATA%\tracekit\run\endpoint.json`, which only you can read. Each side
proves it holds the token before any request is answered.

## 2. A scripted agent

Before each tool call runs, the agent asks the signer. The signer answers `allow`, `deny` or `ask` and signs that
decision.

```python
from tracekit.sdk.client import Client

with Client().run(agent="quickstart") as run:
    d = run.decide("call-1", "Bash", {"command": "ls"})            # allow
    run.complete("call-1")                                          # the result is recorded against that decision
    d = run.decide("call-2", "Bash", {"command": "pkill tracekitd"})
    print(d["decision"], d["rule_ids"])                             # deny ['TK-D007']: the agent can't stop its signer
    held = {"command": 'echo "unterminated'}
    d = run.decide("call-3", "Bash", held)                          # ask: a command the signer can't parse waits for a human
    aid = run.call("approval_request", tool_call_id="call-3")["approval_id"]
    print("approve with: tracekit approvals approve", aid)
    if run.call("approval_wait", approval_id=aid, timeout_ms=300000)["state"] == "approved" and \
            run.approval_consume("call-3", "Bash", held, approval_id_hint=aid)["ok"]:
        run.complete("call-3")                                      # run it only now, with exactly those arguments
    print("run", run.run_id)
```

The default policy is the coding pack (`tracekit/policy2/packs/coding.yaml`). An approval is bound to the call's
arguments: if they change after the approval, `approval_consume` refuses them.

Claude Code: `tracekit init --dev --v2` wires its hooks to the same signer (`python -I -m tracekit.integrations.claude_code`).

## 3. Approve from another terminal

```sh
tracekit approvals list
tracekit approvals show <id>        # the signer's copy of the arguments, in full
tracekit approvals approve <id>     # or: reject <id>
```

## 4. Export and verify

```sh
tracekit signer trust -o trust.json             # pins this signer's log key
tracekit export --v2 --run <run id> -o run.tkb
tracekit verify run.tkb --trust trust.json
```

```text
Integrity: VERIFIED.
Assurance: dev; records ed25519; checkpoint ed25519 (...); no witness cosignature; approvals: self
```

The signer finalises a run a few seconds after it closes. A bundle exported before that verifies as
`VERIFIED TO HEAD n (open)`.

## What `dev` assurance means

`Integrity: VERIFIED` means three things. The bundle's records were signed by the log key you pinned. They form one
unbroken chain. They are included in a checkpoint that key signed. Nothing in the bundle was edited, dropped or
reordered after it was signed.

`Assurance: dev` says how far to trust the signer itself, and in dev mode the answer is "not against the agent":

- The signer runs as **your user, the same user as the agent**. An agent that runs arbitrary commands as you can read
  the signer's key and store, stop the signer, or rewrite history and sign it again. The policy (TK-D007) makes such
  attempts visible and blocks the obvious ones. It can't make them impossible.
- **No witness** has cosigned a checkpoint, so nothing outside this machine can show that the log was not rolled back or
  forked.
- **Approvals are self-approvals**: the same user who runs the agent approved them, and the bundle says so.

Dev mode is for trying Tracekit and for catching mistakes, not attacks. Stronger assurance (`local`, `witnessed`) needs
a signer that runs as a different user or on another host, plus witnesses that cosign its checkpoints. Those are later
milestones.
