# Tracekit plugin for Hermes Agent

> **Experimental:** this works and is tested, but may change and gets less hardening than Tracekit's
> [stable core](https://github.com/Cygnux-Labs/Tracekit/wiki/Support).

[Tracekit](https://github.com/Cygnux-Labs/Tracekit) records every tool call Hermes makes as a signed, hash-chained
event, written by a signer the agent can't control, and gates each call with the signer's policy first: a deny blocks
the call, and an ask waits for a person to approve it. The run exports as a bundle anyone can verify offline.

The plugin registers two hooks, `pre_tool_call` and `post_tool_call`, and nothing else.

## Install

```bash
hermes plugins install Cygnux-Labs/Tracekit/integrations/hermes
hermes config set plugins.hook_callback_timeout 600   # so an approval can wait up to ~10 minutes
```

The plugin depends on `tracekit-ai`, which Hermes installs into its environment with your consent. With no signer
configured, the first tool call starts Tracekit's same-user dev signer. To use another signer, set `TRACEKIT_SIGNER`
in Hermes's environment (a Unix socket path, `tcp://127.0.0.1:PORT` with `TRACEKIT_SIGNER_TOKEN`, or an `https://` URL
with `TRACEKIT_SIGNER_TOKEN_FILE`).

Each Hermes session is one run, closed when Hermes exits; then `tracekit last` exports and verifies it.

## What it does

- **Before each call**, the signer decides it under the model's tool-call id. A deny blocks the call and the model
  reads the rule that blocked it. An ask waits inside the hook until someone approves it (`tracekit approvals`) or
  until shortly before `plugins.hook_callback_timeout`, then the call runs or is blocked.
- **After each call**, the signer records the outcome against the decision.
- **Fails closed.** If the signer refuses the call or anything else goes wrong, the call is blocked; so is a call made
  while the signer can't be reached, unless the signer's policy sets the run's fail mode to `open`. When the plugin
  can't load `tracekit-ai`, it blocks every call.

Details, and what Tracekit doesn't see: [Hermes Agent](https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Hermes).

## Disclosures

- **Network:** each tool call's name, arguments and outcome go to the Tracekit signer you configure: by default the
  same-user dev signer over a local socket. A result goes in full only for a tool the signer's policy marks
  untrusted; otherwise only its SHA-256 digest. Nothing else is contacted.
- **Background process:** with no `TRACEKIT_SIGNER` set, the plugin's first call starts the dev signer
  (`tracekit signer serve --dev`) as your user, if one isn't running. It stores the runs under your user's data
  directory and, in dev mode, keeps each call's redacted arguments and result encrypted for 7 days.
- **Reads outside the plugin:** Hermes's `plugins.hook_callback_timeout` (through `hermes_cli.config`), and the
  environment variables and files Tracekit's client reads to find its signer: `TRACEKIT_SIGNER`,
  `TRACEKIT_SIGNER_TOKEN_FILE`, `TRACEKIT_SIGNER_CA`, `TRACEKIT_SIGNER_CERT`, `TRACEKIT_SIGNER_KEY`, and in Tracekit's
  system mode `/etc/tracekit/client.json`.
- **Credentials:** `TRACEKIT_SIGNER_TOKEN` is read with Hermes's `get_secret`. The plugin stores nothing.
- **Approvals:** the plugin never answers Hermes's own approval prompt; Tracekit's approvals are answered in Tracekit.
