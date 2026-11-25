# Privacy

Default: **redact, then hash.** Content is replaced by `{"hash": "sha256:…", "size": N, "redacted": bool}`, so a reviewer can check that a file or output matches a known one without the bundle carrying it. Operational fields needed to review an action stay in clear, after redaction.

## Content capture: hashed or full

What the agent did (the command, the file path, the URL, and each of them in a call on several) is always recorded in
clear. What it read or wrote (file contents, command output, prompts, fetched pages) is controlled by
`content_capture` in the policy:

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
  path in `/etc/tracekit/client.json`, then run `sudo /opt/tracekit/bin/python -I -m tracekit migrate --system` to pin it and restart `tracekitd`.

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
| `model.exchange` (proxy) | model, status, stop reason, tool_use ids and names, timing, token usage | clear | clear |
| `model.exchange` (v2: LLM gateway) | model, stop reason, tool_use ids and names, usage (input, output, cache-read and cache-write tokens), the record's signed time | clear | clear |
| `model.exchange` (v2: Claude Code transcript tailer) | model, the message id, usage (input, output, cache-read and cache-write tokens, once per message), each tool use's id and name, the ids of the tool results sent since the last response (`tool_results_sent`), the record's signed time | clear | clear |
| `model.exchange` (v2: Claude Code transcript tailer) | the transcript line: the model's thinking, text and tool uses, the line's own timestamp | salted commitment; the line is kept only in the [content vault](#the-content-vault), when the signer keeps content | same |
| `model.exchange` (proxy) | request body, response body | hash (after redaction) | redacted text |
| `model.exchange` (proxy) | HTTP headers, including `x-api-key` / `authorization` | **never recorded** | **never recorded** |
| every hook event | `transcript` mark: path, length, sha256 of the transcript | clear (hash only, never content) | same |
| `approval` | approver user and uid, channel (tty), decision, wait time | clear | clear |
| `capture.gap`, `checkpoint`, `error`, `trace.tamper` | all | clear | clear |

**Never recorded, in any mode:** HTTP headers and API keys seen by the proxy; the signing key; environment variables (only what a tool call's own input contains); file contents the agent did not pass through a tool.

## Redaction patterns

Private key blocks, Anthropic / OpenAI / GitHub / AWS (access and secret keys) / Slack / Google / Stripe / npm tokens, `Authorization:` bearer values, JWTs, credentials in connection strings, `KEY=value` / `token: value` style assignments, and every value of a `KEY=value` line when the tool call read or printed a `.env` file. Dictionary keys are redacted too, and the same rules apply to hook, proxy and transcript content. Matches become `[REDACTED:<kind>]` and the field is marked `redacted: true`. Redaction runs **before** hashing, so a hash never commits to a secret. In a command, any value (a pattern's match, an assignment's, a `.env` line's) is hidden only up to where the shell ends its word (a blank, a line end, an operator, a redirection or code outside quotes) and never past a quote it didn't open, so what the command runs after it stays in clear. The same holds in code a shell runs from the command: a `$(...)`, a heredoc or herestring a shell reads, an `sh -c` or `eval` script. Elsewhere a value is hidden as far as its rule reads, as in content: in a comment, a heredoc body a program reads as data (`cat > f`, `tee`) or as its program (`python3 <<EOF`), an interpreter's `-c` program and each word of an argument list; when the command names a `.env` file, a heredoc body's `KEY=value` lines are hidden to their ends, up to the body's end line. A variable's name (`$TOKEN`) is no value and stays in view. An assignment's value is hidden whole, in a command and in content: one in quotes to the quote that closes them, also where the quote opens before its name (`-H "X-Api-Token: a b"`, `echo "token: a b"`), with every part its word joins (`TOKEN="a"' b'`, `TOKEN=a\ b`; in a command, `TOKEN="a$(x)b"` with its `$(x)` in view). A private key is hidden whole. The spellings of a secret that are not `KEY=value` are hidden too: a JSON or Python key's value (`"password": "x"`), a string with a prefix or triple quotes (`r'x'`, `"""x"""`), the lines of a YAML block scalar (`password: |`), the value of a long option that ends in a secret word (`--token x`, `--api-key=x`; not `--secret-id` or `--password-file`, which name a secret or its place), `curl -u user:x` (the part after the colon), `sshpass -p`, `mysql -px`, `redis-cli -a`, `docker login -p`, `gh secret set -b` and `npm config set <key> <value>` for a key that names a secret, and, in a structured argument, the string at a key that ends in a secret word (`API_TOKEN`, `Authorization`, `X-Api-Key`) or a `{"name": "Authorization", "value": "…"}` pair's value. A value those programs only read as data stays clean in a held call's copy; another program's quoted option value does not. A held call's copy may hide only clean values: one word of plain text with no blank or shell character, not where a program runs, read exactly as bash reads it. A held call whose copy would hide more is denied, never asked (`TK-HIDDEN-CODE`, [policy](policy-v2.md)): no person can see what they would approve. Where the signer can't read the command as bash does, a value is hidden as content rules read it, and a held call is denied if one is.

Redaction is pattern-based and will miss secrets it doesn't recognise. A command line kept in clear can still contain one. If that's a concern, deny the pattern in policy or keep bundles internal.

## What hashes and metadata still leak

- **Paths and commands are in clear** (after redaction): file names, URLs, search queries and whole command lines can themselves be sensitive.
- **Hashes of low-entropy content can be guessed**: a hashed "yes", a short prompt or a known file can be confirmed by hashing candidates. Hashes are unsalted so reviewers can match known files; treat them as confirmable. The v2 signer publishes salted commitments instead (below).
- **Sizes and timing**: content sizes, tool durations and timestamps reveal activity patterns even when content is hashed.
- **Token counts**: a model response's usage is in clear (the gateway's records, and the transcript tailer's for Claude Code), so its output tokens say how long each reply was, and its input and cache counts how large the context was, even where the text is only committed.
- **Correlation**: the same file hashed in two runs links them; tool_use ids link proxy and hook events by design.
- **Witnesses** learn when checkpoints happen and how many records exist, nothing else.

## Bundles follow the ledger's rules

Export never re-reads the original content: a bundle holds exactly the event bodies the ledger holds (same redaction, same hashing), with records from other runs elided. `--otel` exports the same fields as spans and nothing more.

## The v2 signer

With the v2 signer service (`tracekit signer serve`), the signer redacts itself, whatever the client did:

- **What is redacted where.** A tool result and error (`complete`) go through the same redaction patterns before the
  signer commits to them; when the call's `command`, `file_path`, `path` or `pattern` mentions a `.env` file, every
  `KEY=value` line is redacted too. The signer's copy of a pending call's arguments, which the approver sees, is
  redacted the same way and shows `[REDACTED:<kind>]` markers, but in a shell line (a `command`, `cmd` or `script`
  argument and the like, a typed call's `typed_line`, `process_manage` text) a value is hidden only up to where the
  shell ends its word, as above, in the code it runs too, which the policy's own shell parser finds where the line holds
  it (a script `sh -c`, `eval`, `ssh`, `watch` or `trap` runs, a heredoc a shell reads). What runs after it stays in
  view; a comment and a heredoc body a program reads as data are text, redacted as content. A variable's name
  (`$TOKEN`) is no value where bash expands it; in `'...'`, `$'...'`, after a backslash or in a body kept as written it
  is text, and hidden. A code runner's arguments TK-S012 holds (`code`, `source`, `input` …; `args`, `argv`) are read
  as its program and as an argv. A held call whose copy would hide more than clean values is denied instead
  (`TK-HIDDEN-CODE`, [limits](limits.md)). When
  redaction may have hidden more than values in an argument (more than 256 characters, or text with a
  blank, a line end, a quote or another character the shell reads), the copy's argument starts with a line saying how
  many characters it hid, `# [N characters hidden by redaction]`, and which characters of shell code were among them
  (`, among them ; and a line break, which a shell can read as code]`): a shell comment, so what reads the copy as a
  command (`tracekit analyze --v2`, `tracekit why`) reads the rest as before. The copy the signer keeps of a call it
  doesn't hold has no such line. The policy decides on the unredacted arguments:
  the signer saw them, the record never holds them.
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
  salt of that record. An auditor who holds the content can then recompute that record's commitments; the salt opens
  no other record. Every record has its own salt, so a reveal opens exactly one record.
  Verifying a bundle never needs a salt.
- **The provenance index.** To know which argument values only untrusted content brought into a run
  ([policy](policy-v2.md#provenance-untrusted-and-from-untrusted)), the signer keeps, per open run and in memory only,
  keyed hashes (HMAC-SHA256 under a key drawn at random per signer process) of the values in its untrusted tools'
  results and observed inputs, read before redaction (so "password: attacker@evil.example" still names its address;
  a secret's keyed hash is in that memory too, and nothing else). They are never written to disk or into a record,
  go when the run ends, and are gone after a restart. Records name the argument (field), the kind of value and the
  record it came from, never the value; an `input.observed` record holds only a commitment to the content, like a
  result. For a tool the policy lists as untrusted, `decide` answers `send_result` and the adapters send the result
  itself instead of its digest: the signer redacts it and commits to it like any result, and keeps nothing of it in
  clear. For any other tool the adapters send the result's digest (`sha256:…`), so the record's `output.size` is the
  size of that digest as the signer received it, not of the result.

## The content vault

Records hold commitments, never content. Replaying a run (`tracekit why`) needs the content: the exact model requests
and responses, tool arguments and results. The signer can keep it, when you turn it on:

```yaml
# signer.yaml
content: {retain: true, retention_days: 30, max_record_bytes: 1048576}   # default: retain: false
```

- **Off by default.** With `retain: false` the signer stores no content at all. `tracekit doctor` (`D-CONTENT-VAULT`)
  says whether the vault is on and for how long it keeps content.
- **On for the dev signer (1.2.2).** The same-user dev signer (`tracekit up`) keeps content for 7 days and grants your
  user `content_read`, so `tracekit view --dev` can show what each call ran (its redacted arguments); each read is a
  `content.accessed` record. It runs as you and you hold every dev key already, so this gives no one new access.
  `TRACEKIT_DEV_CONTENT=0` (set before the dev signer starts) keeps nothing.
- **What it keeps.** Exactly what the signer commits to, after its own redaction, one item per record: a
  `policy.decision`'s arguments (redacted as the approver sees them), a `tool.result`'s result or error, an
  `input.observed` value, and a `model.exchange`'s `body` (the request, or the assembled response) when the client
  sends one. The [gateway](gateway.md#what-is-recorded) sends it only when the signer says the vault is on. Content over
  `max_record_bytes` is not kept, and the vault says `too_large`. Nothing unredacted is ever written. A decision whose
  arguments the redaction changed no longer opens its `args_commitment`: `content_get` marks it `redacted` and returns
  no salt, which could only test guesses of the removed value.
- **Encryption.** AES-256-GCM per record, under a random key per run. That key is stored wrapped by the content master
  key `keys/content.key`, created on first start (0600, the signer's user, like the other keys). The record is bound in
  as associated data: `{log_id, run_id, seq (its run_seq), commitment}`. A blob copied to another record doesn't decrypt.
  The file store keeps blobs under `store/content/<log>/<run>/<seq>`; Postgres in `tracekit_content` and
  `tracekit_content_keys` (schema version 2: run `tracekit signer migrate`). Neither is in the readers' grants.
- **Access is signed.** Only the signer reads the vault, through the `content_get` RPC: `{run_id, seqs (at most 1000
  run_seqs), purpose}`, for a run of the caller's tenant. The caller needs the `content_read` grant in `authorize`,
  which no identity has by default (agents never do). Each item says its record's `type` (and an `input.observed`'s
  `source`, RPC version 25) and comes back as `{content, salt}`, with the record's salt
  as `tracekit signer reveal` gives it, so the caller recomputes the commitment, as `{content, redacted: true}` (no
  salt) for decision arguments redaction changed and for a model exchange redaction changed whose `tool_uses` carry
  `args_commitment` (the record's salt opens those too, over the arguments before redaction), or as `{state: not_retained | too_large
  | erased}`. Every successful call writes a signed `content.accessed{principal, run_id, seqs, purpose}` into the
  tenant's signer run (`tracekit/signer`). From the shell: `tracekit signer content get --run R --seq N... --purpose
  CASE-1`; from Python: `Client().content_get({...})`.
- **Erasure.** `tracekit signer content erase --run R [--reason TEXT]` (the `content_erase` grant, never a default), and
  retention: at the signer's start and every hour after, runs whose key was stored more than `retention_days` ago,
  except, on the dev signer, a run holding nothing but a person's answers to TIPS' lessons, at most 64 (each
  `tracekit:lessons:person` observe is an action, a lesson's id, its text's sha256 and, on a retire, the record that
  disproved it (`RUN:SEQ`); the signer refuses any other value under that source), which the Claude Code hook reads
  back before it gives a lesson
  ([coding agents](coding-agents.md#lessons-at-the-first-prompt)). Other signers keep no such exception.
  Both delete the run's wrapped key and its blobs, then write a signed `content.erased{run_id, reason, by}`: the record
  is written only once the key is gone (a storage error writes none, and the erasure can be retried). The signer keeps
  nothing more for an erased run in its live store. Erasure doesn't reach copies taken before it: a backup, a WAL
  archive or a replica of the store still holds the run's wrapped key and blobs, and opens with `keys/content.key`
  ([limits](limits.md#content-vault-11)). Records and commitments are untouched, and bundles still verify. Erasing a
  run (on request or by retention) also erases its `tracekit why` replay runs (runs whose `run.registered` names it in
  `replay_of`) and its findings runs (`analyzes`), each with its own `content.erased`: a replay run's requests and a
  reviewer model's call (`tracekit analyze --v2 --review`) copy the run's content, so their content never outlives the
  run's.
- **Transcript lines (Claude Code).** The transcript tailer commits to each line it reports, whole: a prompt, the
  model's thinking (a summary, or only its sealed signature), its text and its tool uses, with the line's working
  directory and flags. With the vault on, the line itself is the record's `body`: kept, redacted, encrypted and
  erasable like any content. With it off, the text stays in Claude Code's own transcript; the record holds only the
  commitment. The sealed forms of reasoning (a thinking block's signature, `redacted_thinking`, OpenAI's
  `encrypted_content`) are kept byte for byte in the body, so a run recorded now can be checked if a provider later
  lets an auditor read them.
- **Prompts at the hook.** The Claude Code hook (and the Codex, Cursor and Gemini CLI hooks) also records each prompt as
  the harness submitted it (`input.observed`): a commitment, the prompt itself kept in the vault when it is on. A live
  constraint it states records a commitment to the file it names, never the name.
- **Model responses (`tracekit.instrument()` model calls, OpenAI Agents).** Each recorded model response commits to
  what the model returned: autotrace to the SDK's message (or the stream as it accumulated), the OpenAI Agents
  integration to the response's output items. With the vault on, that is the record's `body` too, so the model's
  reasoning and text before each tool call can be read by `tracekit analyze --v2`; with it off, the record holds only
  the commitment.
- **Model messages from integrations and coding agents.** A framework integration records each model message it sees,
  and a Codex, Gemini CLI, Cursor or Crush hook what the model said since the last hook (from Codex's rollout, Gemini
  CLI's chat recording, Cursor's `afterAgentThought` and `afterAgentResponse`, Crush's `TurnEnd`
  `last_assistant_message`): a commitment always, and the message (its reasoning, sealed forms byte for byte, text and
  calls) as the record's `body` only when the signer says the vault is on. Without the vault the text stays where it
  came from: the framework's memory, the agent's own files ([reasoning](reasoning.md)).
- **Reasoning summaries through the LLM gateway.** The gateway asks the provider to show the reasoning a request has
  the model do but hides ([gateway](gateway.md#readable-reasoning); `show_reasoning: false` turns it off), so its
  responses carry the provider's summaries of the reasoning, to the agent and, with the vault on, into the response's
  `body`: kept, redacted, encrypted and erasable like the rest of it. With the vault off, the record holds only the
  commitment. A summary can restate what the model read, in words the redaction patterns may not match.
- **Findings carry no content.** `tracekit analyze --v2` reads content through `content_get` (a `content.accessed`
  record each), and a finding names only its rule, severity, trust tier and the records it cites by `run_seq` and
  hash. The paths and excerpts it prints come from the content it read and are never signed. With `--review`, the
  reviewer model's call is a `model.exchange` in the findings run; with the vault on, its bodies (the run's text sent
  and the model's explanation) are kept there as content, erased with the analysed run.
- **Bundles never hold vault content.** A bundle that holds `content.accessed` or `content.erased` records needs a 1.1
  verifier.

## The lessons folder

TIPS' [lessons](viewer.md#lessons) read the dev signer's vault (the calls' arguments and the typed part of your
prompts), each read a signed `content.accessed` record with purpose `tracekit tips` or `tracekit view`. Nothing is
written until you approve a lesson (or add one). Then `<dev data dir>/lessons/` holds, per Claude Code project folder,
one Markdown note per lesson and a `MEMORY.md` index: the lesson's text (an identifier the agent searched for, a path,
a program, a flag or a setting, an error's name, or your own sentence quoted as you typed it), its kind, its status,
when you approved it, the `run:run_seq` of up to 8 signed records it rests on, and that of the signed record of your
answer (an observe whose kept value is the action, the id and the sha256 of the lesson's text, never the text). A
lesson whose text matches a secret's shape, a bank
number or a value the signer redacted is refused, never cut. A retire may name the record that disproved the lesson
(`--because RUN:SEQ`, kept in the note as `retired_because` and in the signed answer): its run id and seq, never the
record's content. The folder is a git repository: every approve, retire, restore and add is a commit, so its history
keeps what a retired lesson said. A session's run keeps, in the vault, the ids of the lessons it was given and the
block's sha256, never their text.

The dev data dir is `~/Library/Application Support/tracekit/data` on macOS, `$XDG_DATA_HOME/tracekit` (else
`~/.local/share/tracekit`) on Linux and `%LOCALAPPDATA%\tracekit` on Windows. To erase the lessons and their history,
delete the folder: `rm -rf "<dev data dir>/lessons"`; a later approve starts a new one. Retiring a lesson stops it
being given but keeps it, and its text stays in the git history until the folder is deleted. Erasing a run's content
(`tracekit signer content erase --run R`) doesn't touch a lesson already approved from it.

## What leaves the machine

- The ledger stays on the signer host.
- Witnesses get only checkpoint hashes, `seq`, `kid` and timestamps, never content.
- v2 witnesses, the public witness included (the default once it is deployed; `--no-witness` opts out), get each
  log's origin (signer.yaml `origin`, default `tracekit.local/k<SHA-256 of the log key>`; each tenant's registry log is
  `<origin>/registry/<hash>`, never the tenant's name) and log vkey, its tree sizes and root hashes, the log's
  signature, and the time each checkpoint is sent, so they learn how often and how much each log grows. The public
  witness stores per origin the key, the latest size and root and the last time it cosigned, and the client address
  only in memory, for its rate limits ([what the public witness sees](public-witness-privacy.md)).
- A bundle contains the selected runs' events (per the table above); records from other runs are **elided** to `seq`, `hash`, `prev_hash`, `sig`.
- A v2 bundle holds snapshots of the policies the run's records cite, and only where a verifier checks against one:
  the policy (its rules, patterns, agent bounds and detection rules) an agent's approval was decided under, and the
  one policy a run with an incident was decided under (the verifiers recompute its incidents from it), each once as
  `policies/<policy_hash>.json`, copied from the signer's `<data_dir>/policies`. A run with neither carries no policy.
- `--otel` adds `otel.json` with the same fields as spans; nothing more.
- The [reference reviewer](approvals.md#the-reference-reviewer) (`tracekit reviewer`, off unless you run it) sends a
  model provider, through your LLM gateway, the `approval_review` view of each approval it answers: the tool, the rules'
  reason and rationale, the bounds and budget left, and the signer's **redacted** copy of the tenant's arguments. It
  serves only the tenants its config lists; leave a tenant out when its arguments must not reach a model provider.
  As [the AI approver](approvals.md#the-ai-approver) on a laptop it sends the endpoint you name (`url`, with your own
  key) the same view plus the run's last calls (tool, decision, rules), people's reasons on earlier answers and the
  playbook. It reads no file of the project.
- With the AI approver on, an `approval.request` of a rule `approval_agent` lists records its precedent key in the
  clear: the rules, the tool, what each rule read of the call, and the project folder's name. For `TK-A025` that is
  how each package source was selected and the source's scheme, host and port, never its path (a path can hold a
  token); for `TK-A062` and `TK-SHELL-PARSE` the command, redacted as the approver's copy is (`.env` values too) and
  cut to 256 characters. In a run that isn't clean (a secret read, lost events) the key shows no target at all. Its
  digest over the full key is a commitment, so what redaction or the cut left out can't be confirmed by a guess.
- `tracekit analyze --v2 --review` (off unless you pass it) sends the model at `--review-url` (default: the reviewer
  it picks of those configured, `TRACEKIT_REVIEW_URL`'s, else the Anthropic or OpenAI API whose key is set, preferring
  another model family than the agent's; [findings](findings.md#the-reviewer-model-tk-x210)) one JSON copy of the run it analyses, cut to about 48,000 characters: what the person asked, what the model
  said, each call's tool, decision and arguments, the effects observers recorded, and the findings so far, each text
  as the vault keeps it (**redacted** by the signer). For a run whose text must not leave your machines, point `--review-url` at a
  model you run yourself (an open-weights model behind a local `/v1/chat/completions` or `/v1/messages` endpoint), or
  at your LLM gateway in front of one.
