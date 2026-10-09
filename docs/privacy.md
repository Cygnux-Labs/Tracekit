# Privacy

Default: **redact, then hash.** Content is replaced by `{"hash": "sha256:…", "size": N, "redacted": bool}`, so a reviewer can check that a file or output matches a known one without the bundle carrying it. Operational fields needed to review an action stay in clear, after redaction.

## Content capture: hashed or full

What the agent did (the command, the file path, the URL) is always recorded in clear. What it read or wrote (file
contents, command output, prompts, fetched pages) is controlled by `content_capture` in the policy:

- `hashed` (default): the content is stored as a SHA-256 hash and its size. You can prove a file or output matches a
  known one, but you cannot read the content back from the log, so the log never becomes a copy of your code or data.
- `full`: the content is stored as text, so you can read exactly what the agent saw before each call. Known secrets
  (API keys, tokens, private keys, `.env` values) are still replaced by `[REDACTED:<kind>]`. The log now holds that
  data: protect bundles accordingly.

To turn it on, add one line to your policy file:

```yaml
extends: default
content_capture: full        # keep content readable
reasoning_capture: true      # also record the model's own text from the Claude Code transcript
```

Point Tracekit at it:

- **dev mode:** set `TRACEKIT_POLICY=/path/to/policy.yaml` in the environment the agent (and so its hooks) runs in.
- **system mode:** `TRACEKIT_POLICY` is ignored. Put a root-owned copy outside the agent's reach, set `"policy"` to its
  path in `/etc/tracekit/client.json`, then run `sudo tracekit migrate --system` to pin it and restart `tracekitd`.

Both settings are off by default, recorded in each run's `run.start`, and the verifier flags runs that used them.

## Field by field

| Event | Field | Default (`hashed`) | `full` |
|---|---|---|---|
| `run.start` | agent, model, host, os_user, cwd, commit, policy, fail_mode, sandbox | clear | clear |
| `run.start` | repo (git remote URL) | clear, credentials redacted | same |
| `user.prompt` | content | hash | redacted text |
| `tool.call` | `command`, `file_path`, `notebook_path`, `path`, `url`, `pattern`, `query`, `glob`, `description`, `subagent_type`, `child_agent_id`, `timeout`, `run_in_background`, `offset`, `limit` | clear, redacted | clear, redacted |
| `tool.call` | everything else (file contents for Write/Edit, `old_string`/`new_string`, MCP arguments) | hash | redacted text |
| `policy.decision` | decision, rule_ids, reasons | clear | clear |
| `tool.result` | output | hash | redacted text |
| `tool.result` | ok, duration_ms | clear | clear |
| `model.message` | content (only with `reasoning_capture`) | hash | redacted text |
| `model.exchange` (proxy) | model, status, stop reason, tool_use ids and names, timing | clear | clear |
| `model.exchange` (proxy) | request body, response body | hash (after redaction) | redacted text |
| `model.exchange` (proxy) | HTTP headers, including `x-api-key` / `authorization` | **never recorded** | **never recorded** |
| every hook event | `transcript` mark: path, length, sha256 of the transcript | clear (hash only, never content) | same |
| `approval` | approver user and uid, channel (tty), decision, wait time | clear | clear |
| `capture.gap`, `checkpoint`, `error`, `trace.tamper` | all | clear | clear |

**Never recorded, in any mode:** HTTP headers and API keys seen by the proxy; the signing key; environment variables (only what a tool call's own input contains); file contents the agent did not pass through a tool.

## Redaction patterns

Private key blocks, Anthropic / OpenAI / GitHub / AWS (access and secret keys) / Slack / Google / Stripe / npm tokens, `Authorization:` bearer values, JWTs, credentials in connection strings, `KEY=value` / `token: value` style assignments, and every value of a `KEY=value` line when the tool call read or printed a `.env` file. Dictionary keys are redacted too, and the same rules apply to hook, proxy and transcript content. Matches become `[REDACTED:<kind>]` and the field is marked `redacted: true`. Redaction runs **before** hashing, so a hash never commits to a secret.

Redaction is pattern-based and will miss secrets it doesn't recognise. A command line kept in clear can still contain one. If that's a concern, deny the pattern in policy or keep bundles internal.

## What hashes and metadata still leak

- **Paths and commands are in clear** (after redaction): file names, URLs, search queries and whole command lines can themselves be sensitive.
- **Hashes of low-entropy content can be guessed**: a hashed "yes", a short prompt or a known file can be confirmed by hashing candidates. Hashes are unsalted so reviewers can match known files; treat them as confirmable. The v2 signer publishes salted commitments instead (below).
- **Sizes and timing**: content sizes, tool durations and timestamps reveal activity patterns even when content is hashed.
- **Correlation**: the same file hashed in two runs links them; tool_use ids link proxy and hook events by design.
- **Witnesses** learn when checkpoints happen and how many records exist, nothing else.

## Bundles follow the ledger's rules

Export never re-reads the original content: a bundle holds exactly the event bodies the ledger holds (same redaction, same hashing), with records from other runs elided. `--otel` exports the same fields as spans and nothing more.

## The v2 signer

With the v2 signer service (`tracekit signer serve`), the signer redacts itself, whatever the client did:

- **What is redacted where.** A tool result and error (`complete`) go through the same redaction patterns before the
  signer commits to them; when the call's `command`, `file_path`, `path` or `pattern` mentions a `.env` file, every
  `KEY=value` line is redacted too. The signer's copy of a pending call's arguments, which the approver sees, is
  redacted the same way and shows `[REDACTED:<kind>]` markers. The policy decides on the unredacted arguments: the
  signer saw them, the record never holds them.
- **The manifest.** A `tool.result` record carries `redaction: {rules, count, client_claimed}`: the rules that fired
  and how often, never the values. A client may send content it already redacted (`redacted: true` and its own
  `redaction: {rules, count}`); the signer records that claim under `client`, redacts again anyway, and adds
  `client_redaction_incomplete: true` when it still found a secret. A claim never lowers what the signer redacts.
- **Commitments, not hashes.** Every published digest of agent content (`args_commitment` on decisions, approvals
  and model tool uses, a result's `output.hash`, `state.write` and `model.exchange` digests) is
  `hmac-sha256:HMAC(salt, digest)`, where `digest` is the `sha256:` of the canonical JSON (for a result: after
  redaction) and `salt` is derived per record from a key only the signer holds. Guessing a 4-digit PIN from its
  commitment needs that salt. A record's `binding_digest` is a sha256 over its published binding only.
- **Reveal for one record.** `tracekit signer reveal --record <seq>` (the owner of the signer's keys only) prints the
  salt of that record. An auditor who holds the content can then recompute that one commitment; the salt says nothing
  about any other record. Verifying a bundle never needs a salt.

## What leaves the machine

- The ledger stays on the signer host.
- Witnesses get only checkpoint hashes, `seq`, `kid` and timestamps, never content.
- A bundle contains the selected runs' events (per the table above); records from other runs are **elided** to `seq`, `hash`, `prev_hash`, `sig`.
- `--otel` adds `otel.json` with the same fields as spans; nothing more.
