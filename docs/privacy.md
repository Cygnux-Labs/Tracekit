# Privacy (v0.2)

Default: **redact, then hash.** Content is replaced by `{"hash": "sha256:…", "size": N, "redacted": bool}`, so a reviewer can check that a file or output matches a known one without the bundle carrying it. Operational fields needed to review an action stay in clear, after redaction.

Set `content_capture: "full"` in the policy to keep redacted content in clear. Set `reasoning_capture: true` to record model text from the transcript. Both are off by default, recorded in `run.start`, and flagged by the verifier.

## Field by field

| Event | Field | Default (`hashed`) | `full` |
|---|---|---|---|
| `run.start` | agent, model, host, os_user, cwd, commit, policy, fail_mode, sandbox | clear | clear |
| `run.start` | repo (git remote URL) | clear, credentials redacted | same |
| `user.prompt` | content | hash | redacted text |
| `tool.call` | `command`, `file_path`, `notebook_path`, `path`, `url`, `pattern`, `query`, `glob`, `description`, `subagent_type`, `timeout`, `run_in_background`, `offset`, `limit` | clear, redacted | clear, redacted |
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
- **Hashes of low-entropy content can be guessed**: a hashed "yes", a short prompt or a known file can be confirmed by hashing candidates. Hashes are unsalted so reviewers can match known files; treat them as confirmable.
- **Sizes and timing**: content sizes, tool durations and timestamps reveal activity patterns even when content is hashed.
- **Correlation**: the same file hashed in two runs links them; tool_use ids link proxy and hook events by design.
- **Witnesses** learn when checkpoints happen and how many records exist, nothing else.

## Bundles follow the ledger's rules

Export never re-reads the original content: a bundle holds exactly the event bodies the ledger holds (same redaction, same hashing), with records from other runs elided. `--otel` exports the same fields as spans and nothing more.

## What leaves the machine

- The ledger stays on the signer host.
- Witnesses get only checkpoint hashes, `seq`, `kid` and timestamps, never content.
- A bundle contains the selected runs' events (per the table above); records from other runs are **elided** to `seq`, `hash`, `prev_hash`, `sig`.
- `--otel` adds `otel.json` with the same fields as spans; nothing more.
