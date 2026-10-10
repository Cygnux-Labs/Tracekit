# Quickstart: the v2 signer (preview)

The v2 signer is still a preview. It records every tool call your agent makes as a signed event, decides each call
against a policy before it runs, and exports a run as a bundle that anyone can verify offline. This page runs it on
your own machine (macOS, Linux or Windows) as a **dev** signer, which runs as your own user. It takes about a minute;
`make quickstart` runs the same steps on a clean venv (`tests/test_quickstart.py`).

## 1. Install

```sh
python3 -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install 'tracekit-ai[signer]'                  # preview: pip install '.[signer]' from a checkout
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
`VERIFIED TO HEAD n (open)`. A record signed by a key after the log retired that key fails the bundle and names the
record.

The report (and `--json`) also lists tool calls by evidence tier (`tiers`), records by `args_source` (raw, parsed,
coerced), the `signer_isolation` the signer recorded for each run (`isolation`), the tool classes that fail open
(`fail-open classes`), and `key assurance`: `asserted`, because the log declares its own keys and nothing attests them
yet. A `witnessed+monitored` assurance level, which needs a log monitor, is not reported yet.

## What `dev` assurance means

`Integrity: VERIFIED` means three things. The bundle's records were signed by the log key you pinned. They form one
unbroken chain. They are included in a checkpoint that key signed. Nothing in the bundle was edited, dropped or
reordered after it was signed.

`Assurance` describes checkpoint cosigning only, not how the signer is isolated: `dev` when no pinned witness cosigned
the checkpoint (or the run holds a self-approval), `local` when only operator-run witnesses did, `witnessed` when enough
independent ones did. A same-user signer whose checkpoints a pinned witness cosigns verifies as `witnessed`: the witness
shows the log was not rolled back or forked after it cosigned, not that the agent could not reach the signer. How the
signer was isolated is recorded in each run's `signer_isolation` (`same-user` here).

In dev mode the signer is not protected against the agent:

- The signer runs as **your user, the same user as the agent**. An agent that runs arbitrary commands as you can read
  the signer's key and store, stop the signer, or rewrite history and sign it again. The policy (TK-D007) makes such
  attempts visible and blocks the obvious ones. It can't make them impossible.
- **No witness** has cosigned a checkpoint, so nothing outside this machine can show that the log was not rolled back or
  forked.
- **Approvals are self-approvals**: the same user who runs the agent approved them, and the bundle says so. A signer
  started with a config refuses self-approvals: list who may answer under `approvals: {approvers: [...]}` in
  `signer.yaml` (see `tracekit/signer/service.py`).

Dev mode is for trying Tracekit and for catching mistakes, not attacks. Protection against the agent needs a signer
that runs as a different user or on another host (system mode, below), plus witnesses that cosign its checkpoints.

## System mode (Linux; macOS experimental)

System mode runs the signer as its own OS user, so the agent's user can't reach its keys, its store or its policy.
As root, from a root-owned Python and checkout:

```bash
sudo /usr/bin/python3 -m tracekit init --v2 --user AGENT [--approver ADMIN] [--policy /etc/tracekit/policy.yaml]
```

This installs Tracekit into the root-owned virtualenv `/opt/tracekit` and creates the `tracekit-signer` user with its
data dir `/var/lib/tracekit-signer` (0700). It writes `/etc/tracekit/signer.yaml` and runs `tracekit signer serve
--config` under a hardened systemd unit (`tracekit-signer`: no capabilities, `ProtectSystem=strict`, a system-call
filter). The socket is `/run/tracekit-signer/signer.sock`. The command also wires the v2 Claude Code hook for AGENT.
The root-owned `/etc/tracekit/client.json` names the socket. Dev auto-spawn is then off, and a `TRACEKIT_SIGNER` that
names another signer is refused, so the call is blocked.

It refuses an AGENT that is root or in a sudo, wheel, admin, docker or similar group. The approver defaults to the
admin running `sudo` and must be another user than AGENT: approve from that account with `tracekit approvals`. A
`--policy` file must be root-owned. `sudo tracekit uninstall --v2` removes the service, the configs, the venv (unless
v1 system mode still uses it) and the hooks. It keeps the signer's data dir and user, which `--purge` also deletes.

What system mode protects, and what it doesn't:

- **Protected:** the signing keys, the store and the sequence numbers (they belong to the signer's user), the policy
  (the signer decides; `TRACEKIT_POLICY` in the agent's environment changes nothing), and approvals (the agent's uid
  can't answer its own). Another local user can't write into the agent's runs either. The hook keeps a run's token in
  the agent's own 0700 runtime dir, and the signer accepts that token only from the uid that registered the run.
- **Not protected:** any process the agent's user runs can read that user's run tokens and write into the agent's own
  runs, or start runs of its own. Binding runs to the harness's processes needs harness binding, which the v2 signer
  doesn't have yet. Root on the machine can do anything; witnesses on another host are the defence against that.
- **Not protected either:** the hook lives in AGENT's own `~/.claude/settings.json`, which AGENT can edit. Removing
  the hook, or running tools outside Claude Code, leaves no record and no gap; system mode secures what is recorded,
  not that everything is.

Check an install with `sudo tracekit doctor` ([docs/doctor.md](doctor.md) lists every check and its fix).

`eval/e8_insider_v2.py` checks these properties as real separate users (decoy signer, cross-user injection, signer
down, policy through the environment, self-approval).
