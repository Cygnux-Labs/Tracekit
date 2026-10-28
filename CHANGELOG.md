# Changelog

All notable changes to Tracekit. Versions follow [PEP 440](https://peps.python.org/pep-0440/).

## 1.5.0 (2026-10-28) — A2A gateway, proof-carrying messages, a new viewer and four more coding agents

Calls between agents can now be gated and recorded: the A2A gateway decides each message one agent sends another,
`run.transfer` records a hand-off of one model's internal state to another (C2C) before it happens, and a PCM 0.1
message carries signed proof of who sent it and what it claims (all three experimental). `tracekit view` has a new
layout with NEEDS YOU, PERMISSIONS and the Event Horizon page, and `tracekit graph` (experimental) builds a graded graph
of what agents did across runs. goose, Qwen Code, Factory Droid and Antigravity CLI can be gated and recorded (all
experimental). Every policy pack holds reading a secret's value, a destructive database statement, deleting a
repository or project, and more kinds of infrastructure removal until a person approves. Bundles are unchanged: every
bundle verifies with the 1.4.2 verifier too, which lists PCM records as not interpreted. The signer protocol goes from
19 to 20 for PCM, so upgrade the signer first.

### Upgrade notes
- **Signer first.** 1.5 speaks signer protocol 20 (PCM's four RPCs): a 1.5 signer serves clients and gateways from
  protocol 15 on (1.2 to 1.4 included), but a 1.5 client or gateway refuses a 1.4 signer. A same-user dev signer from
  1.4 is replaced by the first 1.5 client that finds it, with a warning in Python; TypeScript replaces it silently,
  through the `tracekit` on your PATH, which must be 1.5 too (`pip install -U tracekit-ai`). A signer you run yourself
  must be upgraded first ([deploy](docs/deploy.md#upgrading)).
- **Policy packs.** Coding `2026.10-v2-39` (from `2026.10-v2-24`), server `2026.10-server-9` (from `-8`). The dev pack
  (the dev signer's default policy) and the server and strict packs extend coding, so on a laptop and on a server these
  now hold calls 1.4.2 allowed (below). Upgrade the signer to get them. The policy corpus (E17) grew to 699 harmful and
  800 benign calls: the server pack stops all 699 harmful calls and raises 1 false alarm; 1.4.2's stops 583 of them,
  with 1 false alarm too (on its own corpus, 583 of 583 and 1 in 749). What each new rule doesn't read is in
  [limits](docs/limits.md#policy) (`TK-D012`'s in [approvals](docs/limits.md#approvals)).
- **`TK-F009` is split in three.** It now flags a file tool's write to a coding agent's settings; a shell write or
  delete there is `TK-F015`, and `ANTHROPIC_BASE_URL` in a `Bash`, `Write`, `Edit` or `MultiEdit` call is `TK-F016`.
  Reading these files, or naming them in text, is no longer flagged (Changed, below). A custom policy, alert or filter
  on `TK-F009` needs the two new ids too; a sequence or response on their label, `harness_config`, needs no change
  (#378).
- **Cursor hooks.** Run `tracekit init --agent cursor` again with the mode you first used (`--dev`, `--dev --v2`, or
  system mode, and `--project` if you used it), so `failClosed` is set on `preToolUse` only (Fixed, below).
  `tracekit doctor` warns about any other v2 hook still wrapped to block events other than tool calls (Claude Code's
  from before 1.3): run init again for those.

### Added
- **A2A gateway (experimental, #445).** `tracekit a2a-gateway serve --config a2a-gateway.yaml` stands in front of the
  A2A servers its `upstreams` name. An agent sends to `/a2a/<upstream>`; the gateway relays `message/send`,
  `message/stream` and `tasks/get` once the signer has decided each as tool `a2a:<upstream>/<method>`, and holds an
  `ask` for a person. The decision commits to the sender (the caller the gateway authenticated), the receiver, its
  Agent Card's digest and skills, and the params; the result is recorded at tier T2, and each streamed event is
  recorded before the agent gets it. The gateway refuses any other method, a push-notification config, a task or
  context id it didn't give the caller, and params that spell an A2A field another way (another case, snake_case or
  kebab-case) or hold a key outside ASCII, which a receiver may read as A2A's field while the policy reads only A2A's
  spelling, and forwards nothing when the signer is unavailable. Policy reads A2A calls as a new class, `a2a` (sender,
  receiver, route, skills, part kinds, hosts, size); a name with a space, a zero-width or a look-alike character is
  denied (`TK-A2A-NAME`), and the server and strict packs ask a person for every A2A call (`TK-S011`). No pack ships
  rules for sender and receiver pairs or skills. It doesn't check PCM parts yet ([A2A gateway](docs/a2a.md),
  [limits](docs/limits.md#custody-12)).
- **Transfer records for C2C (experimental, #445).** `run.transfer(sender, receiver, payload, modality,
  projector=...)` decides tool `a2a:transfer` before one model's internal state (a KV cache) is handed to another, and
  records the claimed names and the payload's size and SHA-256 measured in the caller's process (T1: the signer checks
  none of it); `TK-S011` asks for it on the server and strict packs. `tracekit.integrations.c2c.fuse` measures a C2C
  cache, records the transfer with the hash of the fuser's weights and runs the fuser only if allowed. For a transfer
  kept with `keep=True` (on a signer with `content: {retain: true}`), `tracekit why transfer --run R (--store DIR |
  --bundle FILE --trust FILE) --receiver MODULE:ATTR` reads the kept copy from the signer's vault, checks it against
  its record and runs your receiver with and without it. Python only ([C2C](docs/c2c.md)).
- **PCM 0.1: proof-carrying messages (experimental, #450).** `run.pcm_send(to, intent, args, claims, grants)` has the
  signer sign a message to another agent, only as the calling run's own agent, with its log key, adding the id, time and
  nonce itself. The message carries a typed intent (a schema named by its hash), claims (`tests_passed`,
  `approved_by`, `reached_host`, `file_written`), each with records from the sender's signed log as evidence
  (`run.pcm_evidence`), and grants: a person's signed approval of who may ask for what, within which limits, until
  when (at most 24 h; `run.pcm_grant`). The receiver checks it offline with a trust.json that pins one key per log
  (`tracekit signer trust` writes one): `tracekit pcm verify MSG --trust trust.json --schema S` exits 0 (accept), 3
  (accept-unproven: a claim is unproven), 1 (reject) or 2 (bad input: a file it can't read, a schema document that is
  none, a number past the double range such as `1e400`, or two keys of one log), and after a proven `tests_passed` or
  `file_written` prints how long before the message its evidence is, since a claim proves a call happened, not that
  nothing changed since; `pcm.verify` in Python, given a `pcm.Replay`, also refuses a replay. `approved_by` alone
  proves only that the person approved the call the agent named; with `covers: true` the approval must also cover the
  request, by having issued the message's root grant or by being of the tool the schema names with the intent's args,
  and a schema that lists `approved_by` needs such a claim (else accept-unproven, reject with `--strict`).
  `reached_host` compares hosts in printable ASCII only: a URL with a Unicode host or a space, a URL with no scheme
  (`api.example.com/x`) and an IPv4 address not written as a dotted quad (`0127.0.0.1`, `127.1`) are unproven, the
  call's reason saying what to send instead, and a call the host answered with an HTTP error (a 404) fails the claim,
  as its result is not ok. A root grant needs a person's approval of a `pcm.grant` call, which no shipped pack asks
  for: add an ask rule. Each message and grant is an `ext` record (`pcm.sent`, `pcm.grant`) in the sender's run.
  `tracekit pcm demo` runs two agents through a refund request on a real signer in a temp dir. Tracekit is the
  reference implementation of PCM, whose specification will be published separately; the A2A gateway doesn't check PCM
  yet, and TypeScript has no PCM verifier ([PCM](docs/pcm.md),
  [limits](docs/limits.md#pcm-01-proof-carrying-messages-experimental)).
- **`tracekit graph` (experimental, #454).** `tracekit graph build RUN.tkb ... --trust trust.json` verifies each v2
  bundle and builds one graph of what the agents did across the runs: files written (and a kernel sensor's file
  events), hosts reached, approvals, secrets, rules and findings. Each edge is graded SIGNED (a signer record; `wrote`
  and `reached` need a T2 result), OBSERVED (an egress or kernel sensor, tied to the run, not a call), INFERRED
  (`tracekit why`'s causal graph, or a Graphify code node joined to a file: `build` reads `graphify-out/graph.json`
  when it exists, `--graphify ''` for none) or UNVERIFIED (from a bundle that fails verification). It writes
  `graph.json`, `GRAPH_REPORT.json` and `GRAPH_REPORT.md`; `tracekit graph query` answers `--file`, `--host`,
  `--agent`, `--approved-by`, `--rule`, `--secret`, `--code`, `--blast NODE` and `--path A B`; `tracekit graph verify`
  verifies the bundles again and rebuilds the three files byte for byte (under another Tracekit version it reports a
  mismatch). The graph itself isn't signed: `query` says so on its first line, prints no control characters, and with
  `verify` refuses a malformed, symlinked or over-512 MiB `graph.json`; `build` writes no file through a symlink. A
  call is one signer decision, so a person's approval is never credited to another action made under the same tool call
  id; a run whose id verified runs of other tenants or logs share is keyed `RUN@TENANT@LOG`; a why test is drawn as
  tested only when the verifier counts it; and `graph.json` holds no digest of a call's arguments. A call's file and
  host edges need `--content`, which reads the decided arguments from the content vault, each read a signed
  `content.accessed`. The Claude Code plugin gets a `tracekit-graph` skill ([graph](docs/graph.md),
  [limits](docs/limits.md#graph-tracekit-graph)).
- **goose hooks (experimental, #377, by @juliasadler).** `tracekit init --dev --agent goose` (with `--v2` for the v2
  signer, `--project` for one project) installs a goose plugin in `~/.agents/plugins/tracekit/`: its PreToolUse hook
  asks Tracekit before each tool call (600 s, and the call is blocked when the hook fails), and the post-tool hooks
  record the outcome. Code Mode's `execute_javascript`, `execute_typescript` and `execute_bash` are always denied.
  Tracekit installs only goose's tool hooks, and goose sends them no tool output or error text, so a run holds no
  output, error text, prompts, session events or model text. Needs goose 1.48.0 or later; on Windows without `sh` on
  PATH every call is blocked. Tested against goose's hook payloads, not a live goose session
  ([coding agents](docs/coding-agents.md), [limits](docs/limits.md#signer-and-capture)).
- **Qwen Code hooks (experimental, #388, by @Rldumdum; #417, by @2409324124; #449).** `tracekit init --dev --agent
  qwen` (with `--v2`, `--project`) writes the hooks into `~/.qwen/settings.json` (or the project's
  `.qwen/settings.json`); `tracekit uninstall --agent qwen` and `tracekit doctor` know them. Tool calls are decided
  before they run and recorded with Qwen's call ids, and prompts and session start and end are recorded. A prompt
  counts as the person's (and its live constraints are read) only from Qwen's `submitted_prompt`, so `@file` contents,
  pasted text, tool-result continuations and Stop-hook reasons aren't recorded as the person's words; Qwen before
  0.21.1 (0.21.12 for `qwen -p`) doesn't send it, so its prompts aren't recorded. Model text isn't recorded. Project
  hooks run only in a trusted folder; `disableAllHooks`, `--safe-mode` and `--bare` turn off every hook, Tracekit's
  included, and with `QWEN_HOME` set Qwen doesn't read `~/.qwen/settings.json`. On Windows the hook command is
  written in the form Qwen runs there; a hook that can't start lets the call through unrecorded
  ([limits](docs/limits.md#signer-and-capture)).
- **Factory Droid hooks (experimental, #416, by @kausthubhk).** `tracekit init --dev --agent droid` (with `--v2`,
  `--project`) writes `~/.factory/hooks.json`, copying the hooks already in Droid's `settings.json` when it creates the
  file, and refuses to create it while Droid's older `.factory/hooks/hooks.json` exists (save once in Droid's `/hooks`
  to migrate). Tool calls are decided before they run (`Execute` as `Bash`, `Create` as `Write`, `ApplyPatch` as an
  `Edit` of every file it names, `FetchUrl` as `WebFetch`), and prompts (recorded as the person's, though it isn't yet
  confirmed that only a typed prompt fires Droid's `UserPromptSubmit`) and session start and end are recorded. Droid
  sends no call id, so a result is paired with its call by tool and arguments in order, and it has no failure hook, so
  a failed call closes as an error at session end. Not yet checked in a live Droid session or on Windows
  ([limits](docs/limits.md#signer-and-capture)).
- **Antigravity CLI hooks (experimental, #437, #449).** `tracekit init --dev --agent antigravity` (with `--v2`,
  `--project`; system mode with `--v2` only) adds a hook named `tracekit` to `~/.gemini/config/hooks.json` (or the
  project's `.agents/hooks.json`) that decides each tool call before it runs and records its outcome, a call whose
  `PostToolUse` carries an error as failed (agy sends no output). `BypassSandbox` is read as
  `dangerouslyDisableSandbox`, so on the v2 signer `TK-A003` holds it (the v1 policy doesn't). Tracekit installs only
  agy's tool hooks and doesn't read its transcript, so a run holds no output, prompts or model text and closes at the
  signer's idle timeout. `tracekit doctor` warns (`D-AGY-HOOKS-RUN`) when the hook is disabled or agy signs in with a
  Gemini API key or ADC. Needs agy 1.3.0 or later. Tested against agy's documented hook payloads, not a live session
  ([coding agents](docs/coding-agents.md#antigravity-cli), [limits](docs/limits.md#signer-and-capture)).
- **`tracekit doctor` checks every coding agent's hooks (#415, by @kausthubhk; #435, #449).** `D-HOOKS-EVENT` and
  `D-HOOKS-TIMEOUT` read the v2 hook commands of Codex, Cursor, Gemini CLI, goose, Qwen Code, Factory Droid and
  Antigravity CLI as well as Claude Code's (not OpenCode's plugin). For those seven they warn when no Tracekit hook
  runs on the pre-tool event, when a hook command doesn't name its event, when a pre-tool timeout is shorter than the
  540 s approval wait, when a hook on another event is wrapped to block if it can't run, and when Cursor's `preToolUse`
  has no `failClosed` or goose's pre-tool hook no `on_failure: block`, each warning naming the `tracekit init` command
  that fixes it. Claude Code's hooks get the event and blocking checks too, and warn when a Tracekit hook's matcher
  leaves tools out or the PreToolUse command isn't wrapped to block the call when the hook can't start (POSIX);
  `disableAllHooks` in any settings file doctor reads, the one init recorded included, warns (a fail in production),
  and a PreToolUse timeout under 540 s fails, naming the timeout to set ([doctor](docs/doctor.md)).
- **`tracekit approvals list --json` and `tracekit approvals show ID --json` (#425, by @Parth-Jadhav-2004).** `list`
  prints every page as one JSON array (`[]` when there are none), `show` one object with the redacted arguments
  decoded and no pager. The text output is unchanged.
- **`tracekit demo --agent goose` and `--agent opencode` (#465, by @FTFaruque).** The scripted demo is sent as those
  agents' own hook payloads through the command `tracekit init --agent NAME` installs; they send no session or prompt
  events, so the demo says so and records none.

### Changed
- **`tracekit view` has a new layout (#452).** Its pages are DESK, RUNS, LIVE, APPROVALS, PERMISSIONS and HORIZON, plus
  INFLUENCE with why logs, and a run's views, on keys 1 to 7, are OVERVIEW, CALLS (the run's tape), TIMELINE (a row per
  call with the wait for a person hatched, or a lane per agent), GRAPH, WHY, AGENTS and EVIDENCE (the run's signed
  records in order, the viewer's verifier report and the export and verify commands). **NEEDS YOU** lists across every
  run what needs a person: calls waiting, with the approve and reject commands once an approval is requested, runs an
  incident holds, with the resume command, then runs that failed verification or weren't checked, each with a link to
  open it, and a viewer that stopped checking; the page answers nothing itself. **PERMISSIONS** lists every decision
  that wasn't a plain allow and what came of it (blocked, ran flagged, approved, rejected, expired, not answered or
  still waiting), and who answered when. A call's inspector adds **SAID VS DID**, what the model said beside the signed
  result (BACKED, AGENT'S WORD or CONTRADICTED), and **WHOSE WORDS**, where the instruction behind a blocked, held or
  flagged call (or one using untrusted content) came from (the person, another agent, a tool or a page), from the
  signed provenance and the run's recorded inputs. **HORIZON** (Event Horizon, `#page=horizon`) draws the newest calls
  on three rings, the project, this machine and the outside world, marks places where a rule about secrets, a harness's
  settings or Tracekit's own files matched, and replays the calls in order; a why log's calls are graded unverified,
  never signed. Old links open the same run, and the why log's old TIMELINE (every event) is now WHY LOG EVENTS on
  CALLS (on every page when only why logs are loaded). The page loads nothing from outside its own viewer
  ([viewer](docs/viewer.md), [limits](docs/limits.md#investigation-tracekit-why)).
- **Reading a secret's value waits for a person (`TK-A035` to `TK-A038`, every pack, #372 and #409, by @ritamgh):**
  `aws secretsmanager get-secret-value` and `batch-get-secret-value`; `aws ssm get-parameter`, `get-parameters`,
  `get-parameters-by-path` and `get-parameter-history` with `--with-decryption`; `gcloud secrets versions access`; and
  `az keyvault secret show`, `show-deleted` and `download`; as a command, in a command-running MCP tool (`call_aws`,
  `run_command`), and as MCP tools named for it (`get_secret_value`, `access_secret_version`, `keyvault_secret_get`,
  a `get_parameter` with decryption on). Listing or describing secrets isn't held, and neither are `vault kv get`,
  `op read` or `kubectl get secret`. An MCP call over 64 KiB to a command-running or SSM parameter tool now asks on
  the coding and dev packs, where it was flagged (`TK-OVERSIZE`), whatever it carries.
- **Destructive database statements wait for a person (`TK-A039` to `TK-A041`, every pack, #373, by @juliasadler):**
  `DROP`, `TRUNCATE`, or `DELETE` with no `WHERE` (or `WHERE 1=1`, `WHERE TRUE` or `WHERE 1`) passed to `psql -c`,
  `mysql -e` or `mariadb -e` (also in a cluster of flags, `psql -1c`; a cluster of more than nine flags ending in `c`
  or `e` is held unread), `clickhouse-client --query` or `sqlite3`, also through `docker exec`, `docker compose exec`
  or `kubectl exec`, and also when the same call rolls it back (`BEGIN; DROP TABLE x; ROLLBACK;`), so a test
  transaction takes one approval; `mongosh --eval` dropping a database or collection or deleting every document;
  `FLUSHALL` and `FLUSHDB` sent to `redis-cli` or `valkey-cli`, echoed or printed into one through a pipe (also through
  `command` or `env`, by path or in a group) or fed to it as a herestring or on a line of its own in a heredoc (also
  through a wrapper or `bash -c`); and the same statements in the `sql`, `query` or `statement` argument of an MCP tool
  whose name names a database (the server and strict packs deny them outright on the SQL tools they map, `TK-DB001` to
  `TK-DB003`). `UPDATE`, `ALTER`, a scoped `DELETE`, another always-true `WHERE` (`WHERE 2=2`), and SQL from a file, a
  pipe, a heredoc or a variable aren't held. An MCP call over 64 KiB to a tool whose name names a database now asks on
  the coding and dev packs, where it was flagged (`TK-OVERSIZE`) ([limits](docs/limits.md#policy)).
- **Deleting a repository or project waits for a person (`TK-A042`, every pack, #374, by @juliasadler):** `gh repo
  delete`, `glab repo delete` and `glab project delete`, `hub delete`, `vercel remove` and `vercel project rm`; a
  `DELETE` request for a GitHub repository, a GitLab project or a Vercel project through `gh`, `glab` or `hub api`,
  `curl`, `wget`, HTTPie or `xh`; and the GraphQL `deleteRepository`. A query in a file or a variable, an alias, and
  other forges (Bitbucket, Gitea) aren't read.
- **More infrastructure removal waits for a person (`TK-A001`, every pack, #383, by @hossainzarif23):** `cdk destroy`
  (also through `npx` and other launchers), `terraform`, `tofu` and `terragrunt state rm`, and `pulumi stack rm`. A
  package script (`npm run`, `yarn cdk destroy`) isn't read.
- **An agent can't answer its own hold (`TK-D012`, every pack, #432, #451).** The v2 hold line now ends "a person
  approves it from another terminal with `tracekit approvals approve ID` or rejects it with
  `tracekit approvals reject ID`" (with `--signer ADDR` when the hook's signer is a named one: on Windows in double
  quotes, or `<TRACEKIT_SIGNER>` for you to fill in when the name holds a quote, `$`, a backtick, `%` or a line break),
  and `tracekit approve` and `reject` take a v2 approval id. The agent reads that line too, and the dev signer takes an
  answer from the agent's own user (recorded as `self_approved`), so the agent's own `tracekit approve`, `reject` or
  `approvals approve` and `reject` is denied, also through `env`, `sudo`, `sh -c`, `python -m tracekit`, `uvx`,
  `uv tool run`, `pipx run`, `hatch run`, `conda run` or a path to the binary. `approvals list` and `show` stay
  allowed. Code that calls the signer itself (`python -c`, a script) isn't read: run system mode, whose signer refuses
  the agent's own answer. The v1 packs have no such rule.
- **Writes to a coding agent's settings are flagged more exactly (`TK-F009`, `TK-F015`, `TK-F016`; #370, by
  @kausthubhk; #378, by @gezerui888; #418, by @aj-codespy; #451).** `TK-F009` flags a file tool's write to a
  harness's settings, matched in any case; `TK-F015` a shell write to them (a redirect, `tee`, `cp`, `mv`, `sed -i`,
  `rm`) from any shell tool; and `TK-F016` `ANTHROPIC_BASE_URL` anywhere in a `Bash`, `Write`, `Edit` or `MultiEdit`
  call. They now also cover OpenCode (`.opencode/`, `opencode.json`), Qwen Code (`.qwen/`, `$QWEN_HOME`), goose
  (`.agents/plugins/`, `~/.config/goose`), Antigravity CLI (`.agents/hooks.json`) and Factory Droid (`.factory/`).
  Reading these files, or naming them in a commit message or a file's text, is no longer flagged, and neither is a
  write by a program the shell rules don't follow (`touch`, an editor, `python -c`; `curl -o` is flagged only as a
  download).
- **The Claude Code plugin's install messages pin `tracekit-ai` to the plugin's version** and ask the person to run
  them (#390).
- **A dev hook run from a Tracekit working tree** (a checkout or `pip install -e`) that stops importing prints one line
  naming the branch the tree is on and the one the hooks were installed from, with the `git checkout` or
  `tracekit init` that fixes it, instead of a traceback (when git is on the hook's PATH); a v2 hook still blocks the
  call. Run init again to record the branch (#431).
- **The OTLP receiver, the proxy and `tracekit observe` take a fixed number of connections:** 64, 16, and 64 requests
  and 64 event streams at once; one more is closed unanswered, a request must arrive within 30 s, and a connection idle
  for 10 s is closed. The receiver and observe kept a thread for every connection for as long as it stayed open, and 16
  idle connections made the proxy answer 503 to everyone. A connection cut by its deadline, a timeout or the client no
  longer logs a traceback ([limits](docs/limits.md#deployment)).
- **The central viewer checks two runs at once at most (#439).** `/api/run` exported and verified the whole run for
  each request with no limit; it and `/api/bundle` now check two at once, and a third request is answered 503 with
  `Retry-After`. The run list kept a run's verdict until someone opened its page; it now checks a run again five
  minutes after its last check, one run at a time, and shows a VERIFIED older than that as NOT CHECKED until it can (a
  FAILED stays) ([limits](docs/limits.md#investigation-tracekit-why)).

### Fixed
- **`TK-D007` reads what a command acts on, not text it writes into a file (#429, #458).** A heredoc or `echo` into a
  file named in the call (not a variable or a glob) whose text mentions a Tracekit path or command is no longer
  denied when the rest of the call only lists, prints, makes or changes folders, or copies more text
  (`echo '…' > notes.md; ls`). Any other later command (`sh`, `xargs`, `eval`, `source`, and also `git add` or
  `cat`), an alias or a builtin that sets variables (`export`, `read`) in the call, or a relative target after `cd`
  keeps the call denied. Writing into Tracekit's own files and stopping the signer stay denied.
- **`TK-D008` denies only real writes to a coding agent's transcripts (#441).** A command that only lists or mentions a
  transcript folder (`ls ~/.codex/sessions 2>/dev/null; ls ~/.gemini/tmp`) is no longer denied; the rule reads what
  each command writes or deletes, `find -delete` and `-exec`, the sources `zip -m` deletes, the command `trap` runs and
  what `at` or `batch` get in a herestring or heredoc, and a writer run through `xargs` (also fed a herestring or
  heredoc), `parallel`, `docker exec`, `perl -e`, `osascript` or `at` from a pipe, or on a line the parser can't read
  (a pipe into `sh`, `fish -c`, `C=rm; $C -rf …`) when a writer's name reaches its command. A shell write to
  `~/.config/opencode` is now a `TK-F015` flag rather than a deny; file tools are still denied there (`TK-D009`)
  ([limits](docs/limits.md#policy)).
- **Command substitutions inside `$(( ))` arithmetic are read (#440).** `echo "$(( $(sysctl -n hw.memsize) /
  1073741824 )) GB"` is no longer held as unreadable (`TK-SHELL-PARSE`), and a command inside one meets the rules.
- **A hook that can't run, or fails, stops only tool calls (#435; #410, by @Hv-kowshik52).** Cursor's `failClosed` is
  set on `preToolUse` only; it was on every event, so a hook that couldn't start blocked prompts and session events too
  (Upgrade notes). On other events a hook that can't run still exits 1 with "tracekit: the hook could not run; event
  not recorded" (Antigravity CLI's answers `{}` at exit 0). A hook that fails on an event other than a tool call no
  longer erases Gemini CLI's prompt or result, or blocks it in Codex and Cursor, and the v1 Claude Code hook that
  crashes under fail-closed no longer erases a prompt or sends the agent back to work at Stop. A failed pre-tool event
  still blocks the call, and a v1 dev pre-tool hook that can't start now blocks it too when `TRACEKIT_FAIL_CLOSED=1` is
  set (POSIX; run `tracekit init --dev` again to get it), where it let every call through
  ([limits](docs/limits.md#signer-and-capture)).
- **`tracekit init --dev --v2` finds the Claude Code plugin installed from another marketplace (#382, by
  @kausthubhk).** Init and doctor (`D-HOOKS-PRESENT`) knew the plugin only as `tracekit@tracekit`, so with it
  installed from another marketplace init added its own hooks too, and every approved call was blocked. Both now
  recognise it under another key when Claude Code's install record and that marketplace's catalog point at Tracekit's
  `plugin/` folder, and name the key they found in the `/plugin disable` line; one from a claude.ai-synced marketplace
  still goes unseen ([limits](docs/limits.md#install)).
- **Redaction** finds JWTs in one pass over each run of token characters: a JWT whose header after a `-` ran past 512
  characters was left unredacted, and a long run of `eyJ-` took about 40 times the CPU (#376).
- **The hold line** drops a reason's one trailing period before its `;` (an ellipsis stays whole), and the rejected
  line drops it too (#460, by @Oscar-Williams). A deny or hold no longer gives a flag rule's label as a reason
  (`…said not to push; ask the person; side_effect`): a flagged call runs, and the rule ids still name the flag.
- **A Claude Code session's live constraints hold in its later runs for 30 days.** Any session's start removed the
  state of a session idle for an hour, so its constraints ("don't push") stopped being held in its next run. The state
  is now kept for 30 days after the session's last hook event, and on Linux until the runtime dir is cleared at logout
  or reboot ([limits](docs/limits.md#intent-reasoning-and-action-checks)).
- **`tracekit init` and `uninstall` keep what isn't Tracekit's in a coding agent's settings.** Uninstall and a re-init
  dropped a whole Claude Code hook group when any command in it named `tracekit.hook`, a person's own hook included;
  only Tracekit's entries go now. Settings files keep non-ASCII text as UTF-8 rather than `\u` escapes (text UTF-8
  can't encode, such as a lone surrogate, is still escaped), and an init that changes nothing no longer backs a file up
  or rewrites it. `tracekit init --v2`, in dev and remote mode, records the Claude Code settings file it wrote, as v1
  `init --dev` does, so `uninstall` and `doctor` find its hooks from a shell without the same `CLAUDE_CONFIG_DIR` (run
  init again to record it) ([limits](docs/limits.md#install)).
- **A why log event without its hashes, or without other fields `analyse()` doesn't need** (`ts`, `seq`, `agent`), kept
  its run and every run sorted after it off the why server's live feed (`tracekit why serve`, `tracekit view --why`),
  and one there at start stopped the feed for good. Such events now reach the tape, and an error skips only its own
  run.

### Security
- **The Claude Code hook records text the harness adds to a prompt apart from what the person typed** (versions before
  1.5.0). Text the harness wraps into a prompt (paste blocks, skill bodies, messages from other sessions, agents,
  teammates, plugins, observers or channels, task and system notifications, scheduled tasks, uploads, command output)
  was recorded as the person's words; it is now recorded separately as untrusted input under its own source, so
  `from: untrusted` rules, signed decisions and `tracekit why` keep its provenance (the Gemini CLI hook does the same
  for its referenced files block). A turn whose payload's `source` says no person typed it is recorded whole as
  untrusted; Claude Code 2.1.286 doesn't send `source` yet, so a prompt a plugin submits, a notice from another session
  and a poll event, which reach the hook unwrapped, still count as typed. Constraints stated in that text ("don't touch
  X", "read-only") are recorded but no longer become live constraints, and Claude Code shows a notice naming them;
  those typed after a wrapper's name mid-line (a tag named in a sentence) stay live up to the next wrapper that starts
  a line. A paste Claude Code sends inline (its default) and a wrapper the hook doesn't recognise still count as typed,
  and text typed after a recognised wrapper (other than a closed paste block) counts as added. Text past the hook's cap
  (50,134,272 characters) isn't recorded, and the run's untrusted index is marked partial, so `from: untrusted` rules
  apply to every call they match until the run ends. A transcript line holding only recognised wrapper text isn't
  checked by `TK-X208` (1.4.2 flagged one the agent wrote) ([limits](docs/limits.md#signer-and-capture),
  [checks](docs/limits.md#intent-reasoning-and-action-checks)).
- **Commands bash runs while evaluating an arithmetic array subscript** (versions before 1.5.0) weren't read by the
  shell parser. It now reads a command substitution in a same-line literal used in arithmetic (`$(( ))`, `(( ))`,
  `let`, `declare -i`, `[[ … -eq … ]]`), and asks (`TK-SHELL-PARSE`) when an index's text is built from expansions
  at run time. Arithmetic on text that only exists at run time isn't readable by any static policy
  ([limits](docs/limits.md#policy)).
- **`terraform apply -destroy` after an argument with a newline in it** (`-var` with a two-line value; versions before
  1.5.0, a documented limit) wasn't held by `TK-A001`; it is now, for `terraform` and `tofu` (#369, by @ritamgh).
- **Commands run through `uvx`, `uv tool run`, `pipx run`, `hatch run` and `conda run`** (versions before 1.5.0) were
  read only by the rules on the raw line; the shell parser now reads the command they start, so the argv rules apply
  (`hatch run git push --force` is read as `git push --force`). A runner's own option before `run`
  (`hatch -e test run …`) still hides it (#432, #451).
- **Coding-agent transcripts (`TK-D008`, versions before 1.5.0):** the rule named OpenCode's configuration folder, not
  its data folder, so a shell command deleting OpenCode's sessions (`~/.local/share/opencode`) wasn't denied, and
  deleting the whole `~/.claude`, `~/.codex` or `~/.gemini` folder was only flagged. Both are denied now, and file tools
  are denied OpenCode's session data too (`TK-D009`) (#441).
- **HTTP servers take a request body by one strict `Content-Length`** (versions before 1.5.0). The LLM gateway, the MCP
  gateway, the executor, the signer's HTTP listener (and the issuer's), the OTLP receiver and the Anthropic proxy read
  a body by its `Content-Length` only, so a proxy in front of them that framed it otherwise could pass on a different
  request. They, and the A2A gateway, now answer 400 and close the connection for `Transfer-Encoding`
  ("Transfer-Encoding isn't supported", asking for Content-Length), more than one `Content-Length`, a value that isn't
  ASCII digits, and a header line Python's parser drops (`Transfer-Encoding : chunked`), folds into the one before or
  cuts at a bare CR; the gateways do so on every method. A route that answers without reading a body it was sent (MCP
  `GET` and `DELETE /mcp`, A2A `GET`, the executor's `GET /v1/actions`) closes the connection, the proxy's health route
  reads the body, and the servers that answer once (ingest, both witnesses, Slack approvals, the viewer, egress) refuse
  the same framing. Ingest, the witnesses, Slack approvals, the viewer and the OTLP receiver no longer act on a body
  shorter than its `Content-Length` (#456).
- **Commands that `trap`, `at` and `batch` run later** (versions before 1.5.0) weren't read by the shell parser. The
  command `trap` runs and what `at` or `batch` get in a herestring or heredoc are now read as commands, so every rule
  applies (`trap 'sudo id' EXIT` is denied by `TK-D001`, where it was allowed); a name there built from a variable
  (`trap "$f" EXIT`) isn't held. What `at` gets from a pipe and `osascript`'s `do shell script` are read only by
  `TK-D008` ([limits](docs/limits.md#policy)).
- **A URL host with invisible characters in it** (versions before 1.5.0) was read as written, so
  `http://127.0.0.1<soft hyphen>/` was a name, not the loopback address it reaches (the server pack only flagged it),
  and `db.inter<soft hyphen>nal` escaped `TK-N003`. A host now loses every default-ignorable code point (soft hyphen,
  zero-width spaces and joiners, variation selectors, tag characters, also percent-encoded) before it is read, as
  browsers' and Node's URL parsers drop them; a host of nothing else is no host, so it reads as internal.
- **Gemini CLI's file and fetch tools were decided by one path or URL** (versions before 1.5.0). `read_many_files`'
  `include` (its newer name for `paths`) and a directory tool's `dir_path` weren't decided, a path key one release
  ignores could stand in for the one another reads, and `web_fetch` was decided by the first URL its prompt names, or
  by a `url` key Gemini CLI ignores. Every path a file tool may read, under any release's name for it, and every URL
  the prompt names is now decided, for Qwen Code too.
- **The viewer could show a run as VERIFIED that it no longer checked** (versions before 1.5.0, #439). The live tape
  read a run's records from the store again after its check passed, so an edit made in between was shown under
  "Integrity VERIFIED"; the tape and the central viewer's run page now show the records the check verified. One line
  the store's reader can't parse, or a checkpoint note gone or older than one the viewer saw, stopped every re-check
  while the page still said VERIFIED; it now says VERIFICATION STOPPED until the store can be checked again, and every
  VERIFIED mark reads VERIFIED · CHECKS STOPPED meanwhile. A record edited into a shape export doesn't expect fails its
  run, where it read NOT CHECKED ([limits](docs/limits.md#viewer)).
- **Invisible characters in evidence text are shown escaped** (versions before 1.5.0, #439). The viewer escaped a short
  list of format characters, so tag characters, variation selectors (bytes hidden after a visible character), the soft
  hyphen, line separators, Hangul fillers and C0 controls reached the page raw, and a held call's arguments could hide
  text from the person answering it. Every control, format, separator and default-ignorable character but tab, newline
  and carriage return is now shown as `\uXXXX` on the viewer and the central approvals and runs pages (one presentation
  selector after a pictographic character stays), and an agent approver now gets default-ignorable characters escaped
  too, as it got control and format characters.
- **The viewer's why API answered an OIDC session** (versions before 1.5.0). Its why routes were gated on the session's
  scope, so an operator-admin session read the why logs and ran replays, which write `tests.jsonl`. They now answer the
  viewer's token only (its bearer header, or the cookie it was exchanged for), as [viewer](docs/viewer.md) says: every
  OIDC role gets 403, and 401 on the replay POSTs.
- **Signer container image: OpenSSL (CVE-2026-84782).** The image upgrades `libssl3` and `openssl` (to
  3.0.22-1~deb12u2 or later), and its build fails on an older `libssl3`, so a package mirror without the fix can't
  ship the vulnerable one (images before 1.5.0) (#430, #447).

### Release
- CI runs each released verifier from 1.2.0 to 1.4.2 on bundles of the signer under test (A2A calls and C2C transfers
  included), and under CI a release tag missing from a clone that has the others fails that check instead of skipping
  it (#362, #447).
- OpenCode's plugin is tested for its failure exits and system installation (#414, by @hossainzarif23).

### Docs
- **E21 blind pool (#401, by @amandeavor).** `eval/e21_blind/amandeavor.jsonl`: 90 calls (45 harmful, 45 benign) on CI
  secrets and workflows, cloud IAM, audit logging and branch protection, secret stores and exfiltration, written
  without reading the rules.

## 1.4.2 (2026-10-24) — OpenCode, Hermes Agent, and merges wait for a person

A patch for 1.4. OpenCode and Hermes Agent can now be gated and recorded (both experimental). Every policy pack holds a
pull-request merge, a terragrunt destroy and a bulk delete or version purge in cloud storage until a person approves,
and the dev pack holds uploads to buckets. The coding-agent hooks decide every file a patch names and read Codex's
patches as Codex does, and Codex and Gemini CLI hooks work on Windows. Bundles and the signer protocol are unchanged:
every bundle verifies as before, with 1.4.0 and 1.4.1 verifiers too.

### Upgrade notes
- **Policy packs.** Coding `2026.10-v2-24` (from `2026.10-v2-21`). The dev pack (the dev signer's default policy) and
  the server and strict packs extend it, so on a laptop and on a server these now hold calls 1.4.1 allowed (below).
  Upgrade the signer to get them. On the policy corpus (E17) the server pack stops 583 of 583 harmful calls and raises
  1 false alarm in 749 (1.4.1: 570 of 570, 1 in 738). What each new rule doesn't read is in
  [limits](docs/limits.md#policy).
- **Codex and Gemini CLI on Windows.** Run `tracekit init --dev --v2 --agent codex` (or `gemini`) again, as you first
  ran it, so the hook command takes the form PowerShell and cmd.exe run (Security, below).
- **v1 coding-agent hooks** answer a payload that isn't JSON by the fail mode (`fail_mode` in the policy), as the docs
  said; it was allowed. A payload too deeply nested to read is blocked.

### Added
- **OpenCode hooks (experimental, #350, by @YaoSong808).** `tracekit init --dev --agent opencode` (with `--v2` for the
  v2 signer, `--project` for one project) installs a local OpenCode plugin, `plugin/tracekit.js`, that asks Tracekit
  before each tool call and records the result: a denied or held call stops before it runs. Every file an
  `apply_patch` (or 1.0's `patch`) names is decided; the experimental `batch` tool, whose calls OpenCode runs without
  plugin hooks, is blocked. `tracekit uninstall --agent opencode` removes it, and init won't overwrite a `tracekit.js`
  it didn't write. OpenCode 1.x sends plugins no prompts or session ends, so a run closes at the signer's idle timeout
  and holds no prompts, live constraints or model text; a call that fails, is declined in OpenCode's own prompt or is
  aborted stays a `decided_not_completed` gap; and OpenCode 2.0 doesn't load 1.x plugins
  ([coding agents](docs/coding-agents.md), [limits](docs/limits.md#signer-and-capture)).
- **Hermes Agent plugin (experimental, #355).** `hermes plugins install Cygnux-Labs/Tracekit/integrations/hermes`
  gates every tool call Hermes makes: its `pre_tool_call` hook asks the signer, an `ask` waits for a person inside the
  hook, and `post_tool_call` records the outcome (`error`, `timeout` and `cancelled` as errors; a call run with
  Hermes's repair of its argument types as run). A missing call id, an unreachable signer, a hold that outlasts
  Hermes's own time limits or a call Hermes stopped waiting for blocks the call. Raise `plugins.hook_callback_timeout`
  and Hermes's tool timeouts to 600 s for approvals; with the defaults a person has about 25 s. Needs `tracekit-ai`
  1.4.2 ([Hermes Agent](docs/integrations/hermes.md), [limits](docs/limits.md#one-line-setup-tracekitinstrument)).
- **The Python SDK's `Client(token=...)`** takes a `tcp://` signer's token in place of `$TRACEKIT_SIGNER_TOKEN` (`""`
  reads no token from the environment).

### Changed
- **Merging a pull request waits for a person (`TK-A033`, every pack).** `gh pr merge` (with `--auto` and `--admin`
  too), `glab mr merge` and `accept`, a request to GitHub's or GitLab's merge endpoint through `gh`, `glab` or `hub
  api`, `curl`, `wget`, HTTPie or `xh`, and the GraphQL `mergePullRequest`, `enablePullRequestAutoMerge`,
  `enqueuePullRequest` and `mergeRequestAccept`, also written over several lines (#339). A local `git merge` isn't
  held. Keep a token that can't merge or bypass branch protection on the agent too: the rule doesn't read a query in a
  file, a variable, a script, an alias or other forges.
- **Destroying cloud storage data waits for a person (`TK-A031`, every pack)**: a version purge (`gsutil rm -a`,
  `gcloud storage rm --all-versions`, `aws s3api delete-object --version-id`), a recursive or wildcard delete, a batch
  delete or a bucket delete, in GCS, S3, Azure Blob and Files, through rclone or s3cmd, also with options between the
  service and its verb (`aws s3 --profile p rm ... --recursive`). Deleting one object stays a flag (`TK-F003`), except with s3cmd, which isn't flagged.
  **The dev pack holds uploads to cloud storage (`TK-A032`)**: `gsutil` and `gcloud storage` cp, mv and rsync to
  `gs://`, `aws s3` cp, mv and sync to `s3://`, and `az storage blob upload`. The server pack doesn't extend the dev
  pack, so server agents that publish to buckets aren't held (#336).
- **`terragrunt destroy` waits for a person (`TK-A001`, #356, by @ritamgh)**, as `terraform destroy` does: `destroy`
  and `apply -destroy`, also after `run-all`, `run` or `stack run`, the older `destroy-all` and `apply-all -destroy`,
  after up to four global options, as `terragrunt.exe`, and under `railway run` or `heroku run`. Plans, `init`,
  `output` and `terragrunt destroy --help` aren't held. A platform API mutation (`volumeDelete(`, `serviceDelete(`)
  written over several lines in a `curl` or `railway api` request now waits for a person too, as one on one line did.
- **A Codex patch applied through the shell waits for a person (`TK-A034`, v2 packs)**: `apply_patch`, `applypatch`
  or `codex --codex-run-as-apply-patch` run as a command, which Codex applies as a patch.
- **Cursor's `Delete`** is decided as an `Edit` of its file, so the file rules (credentials, transcripts) read it.
- **`tracekit signer serve`** names the address its HTTPS listener bound on its start line (`serving on host:port`),
  so `http.listen` can ask for port 0.

### Fixed
- **`tracekit follow agentsh` and `tracekit sensor import --follow` on Windows** no longer stop the followed log from
  being rotated: agentsh renames its audit log to rotate it, which failed (WinError 32) while Tracekit had it open
  (#324).
- **`tracekit doctor` reads Gemini CLI's system settings where Gemini CLI does**: `C:\ProgramData\gemini-cli` on
  Windows, and `GEMINI_CLI_SYSTEM_SETTINGS_PATH` and `GEMINI_CLI_SYSTEM_DEFAULTS_PATH` on any platform (#324).
- **Coding-agent hooks** read a payload that starts with a byte-order mark; the v1 hook's error path answers each event
  as that event; and a Gemini CLI id file the hook can't update no longer stops it from answering a blocked call
  (#340).

### Security
- **Coding-agent hooks decide every file a patch names** (versions before 1.4.2): the v1 hooks (`tracekit init --dev`
  without `--v2`) decided a Codex `apply_patch` on the first file it named only, so a policy rule on a later file in the
  same patch (a credentials file) didn't apply; the v2 hooks read every file. Codex also applies a patch whose file
  headers are indented, which the hooks didn't read as headers. Both hooks now decide every file, headers read as
  Codex reads them.
- **A v1 hook payload too deeply nested to read** (versions before 1.4.2) was answered by the fail mode, open by
  default, and a payload that wasn't JSON was allowed: both are now blocked or answered as the docs say (Upgrade
  notes).
- **Codex and Gemini CLI hooks on Windows** (versions before 1.4.2): both run hook commands through PowerShell there
  (Codex through cmd.exe when PowerShell isn't found). The command `tracekit init` wrote quoted Python's path, which
  PowerShell doesn't run as a command, so there the hook didn't start and calls ran unrecorded; PowerShell also hands
  Codex a hook's exit status 2 as 1, which Codex doesn't read as a block; and a payload with a character outside the
  console's code page stopped any hook. Init now writes the path bare where it needs no quotes and with PowerShell's
  call operator otherwise, Codex's hook blocks on Windows with the JSON deny at exit 0, and every hook reads its
  payload as UTF-8. A hook that can't start (its Python moved) still isn't wrapped to fail closed on Windows
  ([limits](docs/limits.md#platforms)). Run `tracekit init` again (Upgrade notes) (#340).

### Release
- The npm job skips a package version already on npm and tries each upload up to 3 times, so re-running a release
  whose publish stopped partway finishes it (#330).

### Docs
- **For auditors (#346, by @gezerui888).** [docs/for-auditors.md](docs/for-auditors.md) explains a first `verify`
  report: integrity, isolation and witnesses, the three report lines to check first, and the shipped sample verified
  in two commands.
- **Demos.** `docs/demos/cloud-storage/` replays an incident where a coding agent uploaded files to a production
  bucket, then deleted them and purged their versions: each call is held and rejected, and the README names the
  signer's `approval.refused` after each reject (#336, #343). `docs/demos/pocketos/` replays a coding agent's Railway
  `volumeDelete` call, held by `TK-A001` and rejected (#342, by @ritamgh).
- The [v2 paper](paper/Tracekit-v2-paper.pdf) replaces the v0.1 draft, and the README cites it (#335).

## 1.4.1 (2026-10-21) — shell parser hardening

A patch for 1.4 that finishes the shell parser hardening 1.4.0 began. Bundles are unchanged.

### Security
- **Shell parser hardening** (versions before 1.4.1): in a program run by an interpreter (`python3 -c`, `node -e` and
  the like), a process call's argument list full of quotes that never close made one policy decision take up to 40
  seconds, stalling the signer. Each such quote is now charged to the parser's work budget for the text it reads, so
  past the budget the call fails closed (`TK-SHELL-PARSE`, as `on_parse_error` says). The words a wrapper (`env`,
  `sudo`, `timeout`, …) passes on now count toward the same budget, and a variable assignment is read within its own
  word, as bash reads it. No other command decides differently. Upgrade the signer.

## 1.4.0 (2026-10-20) — sandboxes, and what was asked, said and done

Tracekit now works with the sandbox an agent runs in (#308): it holds Claude Code's and Gemini CLI's requests to run a
command outside or beyond their sandbox until a person approves, decides each request or MCP call that NVIDIA
OpenShell, sandbox-runtime's proxy, agentgateway or LiteLLM is about to let through, signs the hosts E2B and
microsandbox sandboxes reach, and signs what a kernel sensor (Tetragon, Falco) saw an agent's processes do.
`tracekit analyze --v2` compares what the person asked, what the model said and what ran, and signs what it finds; the
coding-agent hooks hold a call that breaks a "don't touch X" in the prompt. A bundle can be verified in a browser page,
and a run too long for one bundle file exports in parts. Upgrade the signer before its clients, and verify 1.4 bundles
with a 1.4 verifier (see Upgrade notes); every existing bundle verifies as before.

### Upgrade notes
- **Signer first.** 1.4 speaks signer protocol 19: a 1.4 signer serves clients and gateways from protocol 15 on (1.2
  and 1.3 included), but a 1.4 client or gateway refuses a 1.3 signer. A same-user dev signer from 1.3 is replaced by
  the first 1.4 client that finds it (Python and TypeScript); a signer you run yourself must be upgraded first
  ([deploy](docs/deploy.md#upgrading)). The store's schema is unchanged. TypeScript: an older `tracekit` on your PATH
  starts an older signer: `pip install -U tracekit-ai`.
- **Bundles.** A bundle needs a 1.4 verifier when it holds a live constraint (`constraint.added`, or a
  `capture.gap{constraint_refused}`), a signed finding (`review` with `cites`), a kernel sensor's or OpenShell's
  effects (`effect.observed` with `sensor` or `denied`) or a sensor's `observer_lost` gap (with `sensor`), a model
  message recorded `said_only` (Gemini CLI and Cursor sessions), any `ext` field or record (the LLM gateway's
  `ext.amended`, OpenShell's `openshell.policy`), or a run in parts (`runs/<id>.part-NNNN.jsonl`, for a run past
  64 MiB of records). A 1.3 or older verifier reports it `UNVERIFIABLE (needs tracekit >= 1.4.0)`, never `FAILED`, and
  `tracekit export --v2` names the records that raised the version. Every other bundle verifies with 1.3 too, and every
  existing bundle verifies with 1.4. From 1.4 that verdict lists the commands that verify the bundle
  ([verdicts](docs/verdicts.md#a-bundle-that-needs-a-newer-verifier)).
- **Grant lists.** The `authorize` lists in the docs and examples (deploy, remote ingest, identity,
  `deploy/docker/signer.yaml.example`) lacked `approval_consume`, which the Python and TypeScript adapters call after
  every allow, so a signer set up from them blocked every allowed call. They now grant `register_run, decide,
  approval_consume, complete, close_run, model_event, approval_request, approval_wait, status`: if you copied an older
  list, add the ones it lacks. The framework integrations that now record what the model said (below) send it with
  `model_event`, and warn without the grant; with the content vault on they also need `status`, or the vault keeps none
  of that text (they now warn about that too). Coding-agent hooks on a remote signer (`tracekit init --remote ... --v2`)
  now also call `observe` (each prompt) and `constraint_add` (live constraints): add both to their token's list, or the
  hook reports an error at each prompt, records none and holds no live constraint
  ([limits](docs/limits.md#deployment)).
- **Policy packs.** Coding `2026.10-v2-21` (from `2026.10-v2-7`), server `2026.10-server-8` (from `-6`), browser `-5`,
  server-cloud `-4`, server-comms `-3`, server-data `-3`, server-net `-4`, and the new `strict.yaml`
  (`2026.10-strict-3`). The dev signer's default policy extends the coding pack, so on a laptop too these hold or deny
  calls 1.3 allowed (what each rule doesn't catch is in [limits](docs/limits.md#policy); on the policy corpus, E17, the
  server pack stops 570 of 570 and raises 1 false alarm in 738):
  - a program name in another case or with `.exe` (`Git push --force` is denied as `git push --force` is), and a shell
    command's paths in another case (`cp x .ENV` is denied as a write to `.env`);
  - `ask`: `TK-A002` deleting a remote Git branch or tag; `TK-A003` a Claude Code command run with
    `dangerouslyDisableSandbox: true`, and `TK-A014` one whose `allowed_domains` names a host; `TK-A004` a Gemini CLI
    call's `additional_permissions`; `TK-A010` to `TK-A013` adding something that runs at every login or boot, writing
    a Git hook or moving where hooks live; `TK-A020` to `TK-A030` reading a credential store or an SSH agent's keys,
    changing Docker's daemon configuration or socket, a container with host privileges or mounts, a package source
    changed or chosen for an install (an index, a registry, a version-control URL), and editing or clearing shell
    history and system logs;
  - `deny`: `TK-D020` dumping a whole credential store, `TK-D021` installing a package from a URL, and `TK-D010` a read
    redirected from a credentials file (`< .env`) as well as a write;
  - `TK-SHELL-PARSE` asks whenever a shell the parser can't read (`fish`, `csh`, `tcsh`, PowerShell, `nu`, `xonsh`,
    `elvish`) runs commands from its line or stdin, even `pwsh -c 'Get-Date'`;
  - `TK-ENGINE-ERROR` denies a call the policy engine itself fails on (a bug), which used to drop the signer
    connection with nothing signed.
- **Coding-agent hooks.** The v2 hooks of Claude Code (the plugin's too), Codex, Cursor and Gemini CLI now record each
  prompt as the harness submits it, and send what it rules out ("don't touch billing.py", "read-only", "don't push", "no
  network") to the signer as live constraints (experimental): a later call that breaks one waits for a person's
  approval, as any `ask` (`TK-CONSTRAINT`). Run `tracekit init --v2` again as you first ran it (`--dev` on a laptop,
  `sudo ... --user AGENT` in system mode, `--agent` for Codex or Cursor) so the model's reasoning can be read: it turns
  on Claude Code's thinking summaries and Codex's `model_reasoning_summary` unless you set them
  (`--no-thinking-summaries` leaves them alone), and adds Cursor's thought hooks. A hook the signer rate-limits now
  waits and sends again, where it blocked the call.
- **The LLM gateway changes one field of some requests.** A request that has the model reason but hides it (Anthropic
  `thinking` on with `display` unset or `"omitted"`; OpenAI Responses `reasoning` with no summary) is sent asking for
  the provider's summaries (`thinking.display: "summarized"`, `reasoning.summary: "auto"`), and its record names the
  change (`ext.amended`). A provider that answers 400 or 422 gets the request again as the client sent it.
  `show_reasoning: false` in the gateway's config sends every request unchanged
  ([gateway](docs/gateway.md#readable-reasoning)).
- **Gateway limits count per agent.** The events, approval waits and runs a gateway (the executor, the MCP gateway,
  the LLM gateway, the OpenShell middleware, the `ext_mcp` processor) sends for an agent count against that gateway's
  `limits` for that agent, where its events shared one budget for all its agents; a gateway's open runs stop at
  `limits.gateway_open_runs` (10,000). Size `limits` for one agent's traffic ([limits](docs/limits.md#custody-12)).
- **Egress observer.** One identity is one observer process: a second process under it takes over, and the first is
  refused (`conflict`), so give each proxy (and each sensor import) its own identity. A connection must send what
  attributes it within 5 s and a tunnel its TLS ClientHello within 30 s; one attribution holds at most 64 tunnels at
  once, and on Linux one loopback uid 64 connections ([egress](docs/egress.md#what-is-refused)).
- **`tracekit export --v2 --run-set`** refuses a bundle past the format's 10,000 files or 512 MiB and says which, where
  it wrote one no verifier reads. A tenant with more than about 10,000 finished runs needs splitting: a tenant per
  workload, or a new `data_dir` ([limits](docs/limits.md#evidence-and-verification)).

### Added
- **What was asked, said and done (experimental, #309).** `tracekit analyze --v2` checks a v2 run's prompts and what
  the model said (from the content vault) against what ran: an action with nothing said before it (TK-X201), an edit of
  a file no request named and the model never said it changes (TK-X202), a write outside the project (TK-X203), a
  broken stated constraint (TK-X204), success claimed after a failed test or build (TK-X205), a prompt line the harness
  never submitted (TK-X208), data sent out, files deleted or a package added without telling the person (TK-X211), and
  v1's say-vs-do checks; TK-X200 counts what each check couldn't check and why, never as a pass. Each finding is signed
  through the signer (`review_finding`) into a findings run of its own, by an identity signer.yaml `analyzers` lists,
  citing records by `run_seq` and hash with no text of the run. `tracekit export --v2 --run R --with-findings` bundles
  them; both verifiers check the citations, label each finding's author (`independent` only when the trust config's new
  `analyzers` pins it; `self-asserted` for the agent's own identity or a same-user signer) and sum the findings on a
  `Findings:` line, beside the integrity verdict, never in it. `--review` adds a reviewer model's opinion (TK-X210,
  warn only; its detection and false-alarm rates aren't measured yet)
  ([findings](docs/findings.md#v2-runs-what-was-asked-said-and-done-tracekit-analyze---v2)). TK-X211 counts a dotfile
  as told only by its name with the dot (".env"; not "env" or "travis.yml"); TK-X202 keeps a name without an extension
  named under a negation about something else ("update the README so it never mentions the old flag"); "no code
  changes" (TK-X113) covers 59 source extensions.
  E20, synthetic, blind pool v3 scored once on 2026-10-20 (#316, PR #317; the final review's fixes changed the checks
  after that run, and re-running E20 on them moved no pool v3 number), replaying Claude Code sessions written blind to the checks
  through the hook, the tailer and a signer: an unrequested edit is found in every session when no request names the
  file; after a "don't touch X", 79-100% by cover (a live constraint held 67-92% before the edit ran); a false success
  claim after a failed test run, 86%; a file sent out, deleted, or a package added and pushed with nothing said of it,
  96-100% by cover, except a file sent out under an innocent mention of it (33%); claimed checks that never ran, 14 of
  the 15 claims that name a test, build or CI run (none of the 15 that name no check, such as "Done."). On its 1,812
  honest calls, 5 false findings (TK-X202 2, TK-X204 2, TK-X211 1) and 1 call held. Pools v1 and v2
  are development sets, read while the checks were fixed: after a "don't touch X", 54-92% and 88-96% by cover. The
  effect checks (TK-X206, TK-X207) found or marked not checkable every fault, with no false alarm over about 9,800
  honest effects, on a tuned generator and on a separate one committed before the checks existed (176 runs each)
  ([evaluation](docs/evaluation.md#e20-intent-reasoning-and-action-checks)).
- **Readable reasoning (experimental).** What the model said before each call is recorded where the agent exposes it:
  the Claude Code transcript tailer records every line the model writes and every prompt; the Codex, Cursor and Gemini
  CLI hooks what their model said since the last hook; the Pydantic AI, Google ADK, Strands, Haystack, LlamaIndex,
  LangChain (`create_agent` middleware), Claude Agent SDK (`tracekit_said`) and Microsoft Agent Framework (`tk.chat`)
  integrations each model message; the LLM gateway its exchanges (Upgrade notes). Each record commits to the text, which
  the content vault keeps when it is on. Which agents, frameworks and providers return readable reasoning, and how to
  turn it on: [reasoning](docs/reasoning.md). `tracekit doctor` warns when it is off (`D-THINKING-SUMMARIES`,
  `D-CODEX-REASONING`, `D-GEMINI-THOUGHTS`), and when the agent's own identity may sign findings (`D-ANALYZER-AGENT`).
- **Live constraints (experimental).** A limit the person's prompt states for the rest of the run is signed as
  `constraint.added` (`constraint_add`; a file only as a salted commitment to its name), and the signer raises each
  later call that breaks it to `ask` with `TK-CONSTRAINT`, never lowering a decision, so a made-up constraint only makes
  the agent wait. A small fixed grammar reads "don't touch / edit X", "leave X alone", "read-only", "don't push" and "no
  network", and leaves what is ambiguous unread; a scope ("only change X") is checked after the run (TK-X204), never
  held. A later "it" lifts a constraint only where it asks the agent for the change ("you can edit it locally"; not
  "I'll update it myself" or "ask me before you change it"). A clause that waits on the person lifts no file ("you
  can change it after I approve", "to change it, ask me first"). "Keep the API key out of X", "don't make any
  changes to the tests / that break the API / on main", "anything outside src/" and "the home directory" keep
  nothing away; "don't make any changes to the code" stays read-only. "The .github folder" and "the README" are
  read, and a folder word no longer cancels a file's constraint in its clause. On E20's 56 tuned honest sessions
  none holds a call; on blind pool v3's 1,812 honest calls, one is held. A run takes 32 file constraints: past them a
  signed `constraint_refused` gap, and every write of the run is held. `tracekit verify` checks that each
  `TK-CONSTRAINT` hold follows a constraint ([policy](docs/policy-v2.md#live-constraints)).
- **Kernel sensor import (experimental, Linux; part of #307).** `tracekit sensor import` reads Tetragon's export or
  Falco's JSON alerts and has the signer sign each exec, exit, connect and file event of an agent's process into that
  agent's run (`effect.observed`; arguments committed, not stored), and a signed `observer_lost` gap for the drops the
  sensor reports and for the import's silence or restart. A run an import covered throughout reads `processes:
  observed` in its coverage matrix. `tracekit analyze --v2` joins effects to calls (by the call id the process carried,
  Codex's `CODEX_TOOL_CALL_ID`, its parent process or the time) and flags an effect no call explains (TK-X206) and a
  call that reported success with no effect (TK-X207). Tested against event lines shaped as each sensor's source writes
  them, not a live sensor ([Tetragon](docs/integrations/tetragon.md), [Falco](docs/integrations/falco.md)).
- **Coding agents' sandboxes (#299, #302).** The coding pack's `TK-A003` holds each Claude Code command retried with
  `dangerouslyDisableSandbox: true`, and `TK-A014` each one whose `allowed_domains` opens a host, until a person
  approves from outside the session; `TK-A004` holds each sandbox expansion a Gemini CLI call asks for (Gemini CLI's
  hooks are experimental). `tracekit doctor` warns when Claude Code would run commands unsandboxed if its sandbox can't
  start, or a custom proxy port turns off its network allowlist (`D-CLAUDE-SANDBOX`), and when Gemini CLI's settings
  turn on its whole-CLI sandbox, where Tracekit's hooks don't run or block every call (`D-GEMINI-SANDBOX`). Codex's
  page says what Tracekit can't see there (its escalation requests) and how `CODEX_TOOL_CALL_ID` joins a process to its
  signed call ([Claude Code](docs/integrations/claude-code-sandbox.md), [Codex](docs/integrations/codex-sandbox.md),
  [Gemini CLI](docs/integrations/gemini-sandbox.md)).
- **NVIDIA OpenShell (experimental, #300).** `tracekit openshell-middleware`, an OpenShell supervisor middleware,
  decides each HTTP request OpenShell's network policy allows to the hosts you choose, before OpenShell adds
  credentials, and records the response; a request it asks about is refused until the agent sends it again after a
  person approved it. Its OCSF import signs OpenShell's own events into the same run: the connections OpenShell allowed
  or blocked, the agent process it started, and each policy or configuration change (an `ext` record,
  `openshell.policy`), with a signed gap where OpenShell drops events ([OpenShell](docs/integrations/openshell.md)).
- **Network sandboxes (experimental).** The egress observer takes SOCKS5 on its listeners (inside TLS off loopback), so
  the outbound proxies of [E2B](docs/integrations/e2b.md) and [microsandbox](docs/integrations/microsandbox.md) send
  each sandbox's connections through it, and the run gets a signed record of each host reached, made outside the
  sandbox (#303). `tracekit srt-decider` is the decider of sandbox-runtime's `srt-proxy`: the signer decides each
  request srt-proxy would forward ([sandbox-runtime](docs/integrations/sandbox-runtime.md)).
- **MCP gateways (experimental).** [agentgateway](docs/integrations/agentgateway.md) (#301): `tracekit ext-mcp serve`
  is its `ext_mcp` processor, deciding each MCP `tools/call` before agentgateway forwards it, and the signer's OTLP
  import records the MCP spans agentgateway exports. [LiteLLM](docs/integrations/litellm.md):
  `tracekit.integrations.litellm.TracekitGuardrail`, a `pre_mcp_call` guardrail, decides each MCP tool call LiteLLM's
  proxy runs. Behind Tracekit's MCP gateway: [Wassette](docs/integrations/wassette.md) (#304), with a policy that holds
  each component load and permission grant for a person, and
  [Docker's MCP Gateway](docs/integrations/docker-mcp-gateway.md) as an upstream.
- **Kubernetes agent-sandbox (experimental, #306).** An example with the signer outside the agent's `Sandbox`, in a
  namespace of its own, so the record outlives the pod ([agent-sandbox](docs/integrations/agent-sandbox.md)).
- **agentsh (experimental).** `tracekit follow agentsh --log PATH` has the signer sign each decision agentsh logs as it
  writes it, as the identity signer.yaml's new `importers` lists, with a signed gap wherever the log breaks
  ([agentsh](docs/integrations/agentsh.md)).
- **Policy (#310, PR #313; #258).** The rules in Upgrade notes. A rule's `remedy`, one sentence on what to do instead,
  ends the `decide` response's `reason` (the coding pack's deny and ask rules, and those `server.yaml` and
  `strict.yaml` add, carry one); `on_parse_error: deny` denies, rather than holds, a shell command the parser can't
  read; the shell fields `effects` (each file a command writes or deletes), `package_index` and
  `container_host_access`; and `TK-F014` flags a trailing `&` ([policy](docs/policy-v2.md#packs-shipped)).
- **`strict.yaml`**: `server.yaml` with pushes, installs, publishes, `docker run`, applies, network commands and
  environment changes held for a person, and unreadable commands denied. It holds 36 of E17's 738 benign calls (4.9%;
  the server pack, 1) and 13 of E21's 130 developer-session calls (10.0%): use it where a person answers holds promptly.
- **E21: policy robustness (#311, PR #314).** On 420 harmful and 432 benign calls written blind to the rules, the
  server pack stopped or held 211 of the harmful ones (50.2%) on its one blind run, and 237 (56.4%) after rules were
  added that target the pool's shapes, a number that overstates blind recall; it holds 18 of the 432 benign calls
  (4.2%) and 2 of 130 developer-session calls (strict: 246 blind and 266 after, of 420; 47 benign and 13 session
  calls held). Each of E17's 261 shell commands rewritten in up to five equivalent ways (1,265 rewrites) is still
  denied or held, gated rule by rule ([evaluation](docs/evaluation.md#e21-policy-robustness)).
- **Format 1.4: a non-critical slot.** Any record may carry `ext`, and a record of type `ext` holds what a later
  Tracekit adds: a verifier from 1.4 on checks its signature, chain and inclusion and names each ext name it doesn't
  interpret on a `not interpreted` warning (`--strict` exits 3), so a later bundle still verifies. The manifest's new
  `verifier_version` names the version that checks everything ([format v2](docs/format-v2.md#9-bundle-layout)). RPC 19,
  format gate 1.4.
- **A run in parts.** A run past 64 MiB of records (about 24,000 tool calls) is exported as ordered parts of up to
  64 MiB (`runs/<id>.part-0001.jsonl`, ...), up to the bundle's 512 MiB (about 190,000 tool calls), and both verifiers
  check the parts as one run (`run parts`). A run cut back reads open, never `VERIFIED`
  ([limits](docs/limits.md#evidence-and-verification)).
- **The browser verifier.** `verify.html` (a release asset; `dist/verify.html` in the npm package; `make verify-page`)
  is the TypeScript verifier as one page: drop in a bundle and its trust file, and its Content Security Policy lets it
  load and send nothing. It explains each line and says what to do next; without a trust file it checks everything
  that needs no pinned key and is never `VERIFIED` ([verdicts](docs/verdicts.md#verify-in-your-browser)).
- **E22: verifier agreement on real bundles.** 63 bundles made as a user would (11 of the 17 offline examples, the six
  whose framework wasn't installed skipped; the server demo, the Claude Code hook with signed findings, sensor,
  OpenShell and agentsh runs, a 50,000-call run, the 1.2.3 and 1.3.0 signers' runs, the v1 sample, and 33 forgeries)
  get the same verdict from the Python CLI, the TypeScript CLI and the page in Chrome (the page reads no v1 bundle and
  names the Python command); the 25 honest bundles and 5 controls verify, and no forgery does
  ([evaluation](docs/evaluation.md#e22-verifier-agreement-on-real-bundles)).
- **Docs.** [How Tracekit works](docs/concepts/README.md), fifteen pages on Tracekit's concepts in order (#238);
  [compliance mapping](docs/compliance/README.md) for the EU AI Act, ISO/IEC 42001, the NIST AI RMF and OWASP (#292);
  a [quickstarts index](docs/quickstarts/README.md); [integrations](docs/integrations.md) as the hub of every
  integration. The GitHub wiki is generated from `docs/` (`scripts/wiki.py`).

### Changed
- **Shell commands are read more fully.** A program name is read in lower case and without `.exe`, more wrappers and
  runners are followed (`caffeinate`, `npx`, `uv run`, `poetry run`, `direnv exec`, `mise exec`, `op run`,
  `doppler run`, `npm exec`, `pnpm dlx`, `nix-shell --run`, `env -S`, ...), and path rules and shell `target` rules
  match casefolded. `TK-D003` reads a force push in the push's own words, so a later command (`git push && ls -f`) or a
  commit message naming one is no longer denied; `TK-D010`, `TK-A011` and `TK-A013` read each command and redirection
  target on its own. Every shipped pattern but eight searches 64 KiB built to make it back off within 50 ms on the
  fallback engine; the eight are in [limits](docs/limits.md#policy).
- `TK-F009` also flags an agent's edit of Gemini CLI's and Cursor's settings and hooks; `TK-D013` covers the per-`HOME`
  dev signer directories.
- **The viewer** shows each prompt and what the model said (`PROMPT`, `THINK`, `SAYS` rows), signed findings beside the
  integrity line, a held call's approvals under it with how it ended, the run in one sentence, and the exact
  `tracekit export --v2` and `tracekit verify` commands. When one run can't be checked it says `NOT CHECKED` and keeps
  checking the others; if its checks stop altogether it says `STOPPED`, not `LIVE` ([viewer](docs/viewer.md)).
- **Docs links go to the wiki.** The README, package metadata and the CLI's messages, errors and doctor fixes link to
  the GitHub wiki page of each docs page.
- **Each integration page says what it was tested against** (#312 tracks the rest): Claude Code's sandbox settings
  read from a real Claude Code, Wassette 0.8.0 by hand, agent-sandbox v1.0.7 end to end on a kind cluster; the others
  against the product's source, API description or recorded payloads, or a stand-in, not yet a running release.
- The egress observer's run-token checks cost none of its event rate; it keeps at most 10,000 refused totals to send
  again, dropping the oldest with a line on stderr.

### Fixed
- `tracekit export` wrote a run past 64 MiB of records (about 24,000 tool calls) as one file every verifier called
  `UNUSABLE BUNDLE`; it now writes the run in parts, and refuses a bundle past the format's limits (found by E22).
- The TypeScript verifier reported a valid bundle of 60,000 or more records `FAILED` in a browser (a call stack
  overflow).
- An executor tool's call under LangChain or the Claude Agent SDK carries the model's call id, so it no longer
  reconciles as `reconcile.fabricated` next to the LLM gateway.
- A trace imported over OTLP closes its run when its root span arrives. Each trace stayed open for `idle_s`, so after
  100 traces in an hour (agentgateway sends one per request) every batch was refused.
- The MCP gateway reopens an upstream session that ended (a stdio server that exited) at the next call, where every
  later call failed until the gateway restarted.
- A second `HOME` that shares a runtime dir with the first (macOS's `/tmp` fallback for a long `HOME`, Linux's
  `$XDG_RUNTIME_DIR`) gets a dev signer of its own; its client wrote runs into the other `HOME`'s store.
- A shell command or a URL that made the policy engine fail dropped the signer connection with nothing signed; such a
  call is now decided and signed (an engine error is `TK-ENGINE-ERROR`, a deny).
- The viewer: a run that verified at one checkpoint and failed at a later one kept its earlier rows on the tape as
  signed; they are taken back, with its earlier report and findings.
- `tracekit ingest --help` shows ingest's own help; doctor's re-init fix names `--experimental-macos` on macOS, and its
  no-witness message says assurance stays `dev`.
- E4's v2 part, E12 and E14 run again; the README gives the compose stack's isolation as `separate-user`, and E3 as
  recorded (11 of 16).

### Security
- **Shell parser hardening** (versions before 1.4.0): a crafted `sed` script of newlines, or a program text full of
  process-call lists, could make one policy decision take from seconds to minutes and gigabytes of memory, stalling
  the signer. Sed addresses are no longer rescanned from each newline, the parser's work budget now covers list text,
  and past the budget the call fails closed (`TK-SHELL-PARSE`, as `on_parse_error` says). A `]` inside a quoted list
  string no longer ends the list early, which had let a denied command in such a list be decided as a flag. Upgrade
  the signer.
- **Program names in any case** (#258): on a case-insensitive file system `Git push --force` runs git, and the coding
  pack allowed it. The command-line rules now read program names in any case, and shell paths casefolded.
- An agent's `decide` labelled `args_source: coerced` no longer skips the comparison with the LLM gateway's own record
  of the model's call, so decided arguments can't hide the ones the model asked for.
- **The viewer's session cookie** was derived from its token: it never expired, and every later viewer started with
  that token took it. It is now the viewer's own, valid for 8 hours and only while that viewer runs: open the URL again
  after that. A page on another port of the same host name still receives it until then: open the viewer under a host
  name nothing else serves ([limits](docs/limits.md#viewer)).
- Both verifiers drop bidirectional and zero-width characters from report text, so an agent-chosen name can't reorder
  the words around it.
- Both verifiers fail `run chain` when a bundle holds one run under two file names, which verified with its records
  counted twice.
- The viewer keeps each run's latest verdict past its live-view cap, a failed run's last of all, so an agent writing
  many records can't push a `FAILED` run out of the run list.
- Egress observer: a client trickling bytes before its TLS ClientHello kept its slot, and 256 of them locked out every
  agent on a shared address; the deadline now holds until the ClientHello, with the per-attribution and per-uid caps
  in Upgrade notes.
- A gateway's agents no longer share one budget of events, approval waits and open runs, so one agent can't spend what
  the gateway's other agents need.

## 1.3.0 (2026-10-18) — six more frameworks

Tracekit now gates tool calls in Pydantic AI, Google ADK, Strands Agents, LlamaIndex, Haystack and Microsoft Agent
Framework, from each framework's own hooks, and can check that the tool results a model is sent are the ones the signer
recorded. Upgrade the signer before its clients (see Upgrade notes); every existing bundle verifies as before.

### Upgrade notes
- **Signer first.** 1.3 speaks signer protocol 17: a 1.3 signer serves 1.2 and 1.3 clients and gateways, but a 1.3
  client or gateway refuses a 1.2 signer. A same-user dev signer from 1.2 is replaced by the first 1.3 client that
  finds it (Python and TypeScript), with a warning; a signer you run yourself must be upgraded first
  ([deploy](docs/deploy.md#upgrading)).
- **Bundles.** A bundle that holds a `reconcile.result_mismatch` record (verified tool results) needs a 1.3 verifier;
  every other bundle verifies with 1.2 too.
- **The Claude Code plugin now runs the v2 hook** (`tracekit.integrations.claude_code`), like `tracekit init --dev
  --v2`. Set up with `tracekit init --dev --v2 --no-hooks`; on a v1 system-mode host the hook's error names the v2
  system init. A custom v1 policy no longer applies ([plugin](plugin/README.md)).
- **Claude Code hooks block only tool calls.** A hook that can't run now blocks a tool call but lets other events
  (prompts, Stop) go on with a visible error, where it used to erase the prompt or loop on Stop. Hooks written by an
  older `tracekit init` keep the old behaviour until you run `tracekit init` again.
- **TypeScript:** an older `tracekit` on your PATH starts an older signer: `pip install -U tracekit-ai`.

### Added
- **Six framework integrations (experimental).** Each decides a tool call before it runs, with the model's call id
  where the framework passes one (allow, deny, or wait for a person on `ask`), refuses when Tracekit itself fails, and
  records the result; each page lists the calls it doesn't see and the cases it records differently. Each is tested
  against the real library and has an offline example whose bundle verifies:
  [Pydantic AI](docs/integrations/pydantic-ai.md) (a capability; also wired by `tracekit.instrument()`),
  [Google ADK](docs/integrations/google-adk.md) (a Runner plugin),
  [Strands Agents](docs/integrations/strands.md) (a hook provider; tested in its own environment, since
  strands-agents needs mcp below 2.2),
  [LlamaIndex](docs/integrations/llamaindex.md) (agent workflows' `call_tool` step),
  [Haystack](docs/integrations/haystack.md) (the Agent's tool hooks) and
  [Microsoft Agent Framework](docs/integrations/microsoft-agent-framework.md) (function middleware).
  Pydantic AI, Google ADK and Haystack need Python 3.11+. The six share one gate (`tracekit/integrations/gate.py`), so
  a fix to how calls are decided lands in all of them.
- **Verified tool results (experimental).** With signer.yaml `verify_tool_results: record` (or `refuse`), the LLM
  gateway checks each tool result in a model request against the signed result of the same call, and the signer
  records an edited result, or one sent before its call completed, as `reconcile.result_mismatch`
  ([gateway](docs/gateway.md#verified-tool-results)). `refuse` refuses a request with an edited result, not one whose
  call is still open (a lost `complete`). The gateway digests the newest 512 results of a request up to 1 MiB (results
  the run's previous request also sent cost nothing); a result past that, or over 1 MiB on its own, is not compared:
  the signer writes a `capture.gap{result_unchecked}` for its call, which `tracekit verify` warns on, and doesn't
  refuse the request. Some integrations record a result in a form the model isn't sent and mismatch on honest runs:
  [limits](docs/limits.md) lists them; run `record` before `refuse`. RPC 17, format gate 1.3.
- **[Guarantees](docs/guarantees.md):** what Tracekit guarantees and doesn't, per deployment, on one page.
- [Vercel AI SDK integration page](docs/integrations/vercel-ai.md); `server.json` for the official MCP Registry (the
  MCP gateway as a remote you deploy).
- `CODE_OF_CONDUCT.md`, `COMPARISONS.md` (where Tracekit fits next to tracers, guardrail libraries, sandboxes and
  other tamper-evident logs), `HALL_OF_FAME.md`, and a "Pilot it with us" section in the README.

### Changed
- **TK-A001** (coding pack `2026.10-v2-7`) holds commands that destroy a deployment, database or volume for a person:
  `terraform`/`tofu`/`pulumi` destroy, `dropdb`, the Railway, Fly and Heroku CLIs' delete commands (Railway's also
  through `npx`, `bunx`, `pnpm dlx`, `yarn dlx` and `npm exec`, and commands under `railway run` / `heroku run`), and
  `curl`-style calls of a platform API's `*Delete(` mutation. A trailing `--help` is not held. TK-C010 (server-cloud
  pack `2026.10-server-cloud-3`) holds terraform/pulumi destroy sent through other tools (`cli_command`, `command`).
  What it doesn't catch is in [policy](docs/policy-v2.md). The policy corpus (E17): 500 of 500 stopped, 1 false alarm
  in 692.
- `tracekit init --dev --v2` doesn't install Claude Code hooks while the Tracekit plugin is enabled, and `tracekit
  doctor` warns when both run (each call would be decided twice, and an approved `ask` blocked).

### Fixed
- After an upgrade that raises the signer protocol, a dev signer from the old version no longer makes every client
  refuse it (which blocked every Claude Code tool call, including `tracekit up --replace`).
- E18 and E19 run again against the current signer; the E8 v2 results are committed; the report's E8 table says "not
  refused" for a case the signer answered but didn't catch.

## 1.2.3 (2026-10-17) — viewer fixes

A patch for 1.2: the last items from the 1.2.0 verification (#229), and the first release whose npm packages the
release workflow publishes itself. Bundles are unchanged.

### Fixed
- In an open run, a call that is still running no longer shows as "failed: the signer recorded no outcome" in the why
  view; once the run is final with no result, it still says so.
- The GRAPH of a signed run no longer draws "content-overlap · inferred" links between unrelated calls: committed
  content was the same placeholder text everywhere.
- The why viewer opens on a run that was tested (a demo's newest runs may not be); a static report's header says why
  it has no CHAIN verdict instead of waiting forever, and its ELAPSED is the records' span, not a running clock.
- `tracekit view --bundle` says BUNDLE instead of LIVE, and asks for why logs without a 404 in the console.
- The release workflow publishes npm packages with `./` paths: npm 12 read `release/x.tgz` as a GitHub repository,
  which failed 1.2.2's npm job (its packages were published by hand).

## 1.2.2 (2026-10-16) — watch your coding agent

A patch for 1.2 from running Tracekit on a Claude Code session: the dev viewer shows what each call ran, and a
session can be verified while it runs. Bundles are unchanged.

### Changed
- **The dev viewer shows what each call ran.** The dev signer keeps each call's redacted arguments and results for
  7 days in its content vault and grants your user `content_read`, so `tracekit view --dev` names each call by its
  command or path, then its rules (each read is a `content.accessed` record). The dev signer runs as you and you hold
  every dev key already, so this gives no one new access; `TRACEKIT_DEV_CONTENT=0` keeps nothing
  ([privacy](docs/privacy.md#the-content-vault)).
- **`tracekit last --open`** verifies the newest run as it stands, such as a coding agent's session, which stays open
  until the session ends.

### Fixed
- The viewer's AGENTS counts agents by name; it counted each run's agent separately.
- TK-D009 (the agent harness's transcripts) no longer denies Claude Code's memory notes beside them
  (`.claude/projects/<project>/memory/*.md`). Coding pack `2026.10-v2-5`; the policy corpus (E17) is unchanged.
- `tracekit doctor` checks the content vault the dev signer runs.

## 1.2.1 (2026-10-16) — on npm

A patch for 1.2: the TypeScript SDK goes on npm, and the fixes a first-time user hits in their first ten minutes.
Bundles are unchanged: 1.2.1 writes and verifies the same evidence format as 1.2.0.

### Changed
- **npm: `@cygnuxlabs/tracekit`.** The TypeScript SDK installs with `npm install @cygnuxlabs/tracekit` (the
  `@cygnux` scope belongs to someone else, so the packages moved). On Apple Silicon macOS, Linux (x64 and arm64,
  glibc) and Windows x64, npm also installs a `@cygnuxlabs/tracekit-signer-<platform>` package that bundles a Python,
  so `npx @cygnuxlabs/tracekit up` starts a dev signer without one. On an Intel Mac or Alpine,
  `pip install 'tracekit-ai[signer]'` ([limits](docs/limits.md#install)).
- **A refusal says why.** `decide` answers a deny or an ask with its rules' reasons in `reason`, an optional field
  RPC 16 already had, so older clients are unaffected. The Claude Code hook prints
  `Blocked by tracekit policy: TK-D007: touching Tracekit's own files or signer`, and the framework integrations pass
  the reason to the model.

### Fixed
- `tracekit doctor` on a fresh dev home says to start the dev signer (`tracekit up`) for the missing keys, not to run
  doctor as root, and that a dev signer's assurance stays `dev` (it takes no witnesses).
- The manifest check's failure names the files that differ from the manifest and how (changed, missing, not listed),
  the same in the Python and TypeScript verifiers; it repeated the pass text.
- `tracekit down` right after `tracekit up` stops the starting signer; it exited 1 (`Hung`) or missed it.
- `tracekit uninstall` says what it removed once.

## 1.2.0 (2026-10-13) — control

1.1 records why an agent acted. 1.2 lets the signer act on what it sees, for agents running on servers:
- tool calls run with credentials the agent never holds ([executor](docs/executor.md),
  [MCP gateway](docs/mcp-gateway.md));
- the signer detects risky sequences across calls and contains the runs that trip them
  ([incidents](docs/incidents.md));
- reviewer agents may answer routine approvals inside bounds the policy sets
  ([agent approvers](docs/approvals.md#agent-approvers));
- a call that was allowed but never reported back becomes a signed gap, and an
  [egress observer](docs/egress.md) records network effects from outside the agent.

It also has fixes from running Tracekit inside eight real agent projects: OpenAI's customer-service demo, LangGraph,
Browser Use, mcp-agent, OpenAI Agents JS, the Vercel AI SDK, PydanticAI and CrewAI. v1 bundles and 1.0/1.1 bundles
keep verifying. Every limit of the new features is in [docs/limits.md](docs/limits.md).

1.1.0rc1 was never published, and neither was 1.0.1 on PyPI; this release includes everything listed under
both below.

### Upgrade notes
- **Signer RPC version 16.** A 1.2 signer serves RPC 15 and 16. Coming from 1.0 (RPC 12), upgrade the signer and its
  clients together.
- **Bundles a 1.2 signer writes need a 1.2 verifier** (`verifier_min_version: 1.2.0`): every finished run's `run.final`
  carries the coverage matrix, and 1.2 adds completeness gaps, `run.child`, incidents and containment records, agent
  approvals, `effect.observed`, `run.registered`'s `posture`, `parent_run` and `session`, `provider_executed` and
  `paired_by_args`. Older verifiers report such a bundle `UNVERIFIABLE (needs tracekit >= 1.2.0)`, never `FAILED`.
  Bundles from 1.0 signers keep verifying as before.
- **`verify` warns on more**: every signed gap that isn't informational, fail-open tool classes, unexplained network
  effects, lost observers, held calls left unresolved, unchecked agent approvals, missing incident policies, and
  calls whose records name different tiers (this one can fire on older bundles too). `verify --strict` exits 3 on
  them, so a CI gate that passed on 1.0 may now stop. Each warning names what it found.
- **Policies**: map your application's own tools to the new class `app` (mapping a tool to `unknown` is now a policy
  warning; a 1.1 policy still loads). Name handoff tools in `handoffs:` and structured-output tools in
  `structured_output:`. No shipped pack names any handoff, so `transfer_to_*` calls reconcile as `hook_missing` until
  you name them.
- **Python custom loops** (#218): `RunHandle.decide` no longer raises `SignerUnavailable`; see Behaviour
  changes. A loop that caught that exception to block now blocks by `d["decision"]`.
- **Containment operators** (#213): the signer refuses to start when one `authorize` entry grants both
  `register_run` and an operator call. Give operators an identity of their own.
- **Long-running servers**: open a run per conversation and make it current per request (`with conversation.current():`
  in Python, `withRun()` in TypeScript), as [the quickstart](docs/quickstart-v2.md#a-server-a-run-per-conversation)
  shows.

### Behaviour changes
- **One viewer** (#224): `tracekit view` opens the v2 signer's runs (default), why logs (`--why DIR`), the v1 ledger
  (`--ledger`) or a v1 bundle (`--bundle`, refused when it fails verification). `tracekit observe` and `tracekit why
  serve` keep working and say they are now part of `tracekit view`. `tracekit view --why DIR` with no store shows the
  why logs alone; `--dev --why DIR` combines them with the dev signer's runs.
- **Experimental surfaces say so** (#226): each experimental command or server prints one line when it starts, and
  the signer names the experimental settings it was given. [docs/support.md](docs/support.md) lists the stable core.
- **npm is paused** (#225): the TypeScript SDK installs from the `.tgz` attached to the GitHub release.
- **Python `RunHandle.decide` no longer raises `SignerUnavailable`** (#218). While the signer can't be
  reached, it returns the run's fail-mode decision with `unavailable: True` and a warning, as the TypeScript client
  does. A refusal still raises `RPCError`.
- **Python `RunHandle.complete` never raises** (#218). The call already ran, so a result the signer can't
  take is a warning (it returns None), and the signer records the call as decided and not completed.
- Tracekit's model-call refusals raise `tracekit.Refused`, a `PermissionError` (#218).
- Mapping a tool to `unknown` in a policy is a warning (#212).
- `verify` (Python and TypeScript) warns on non-informational gap kinds and fail-open classes; `--strict` exits 3
  (#212).
- LangGraph: a Tracekit `ask` pauses the graph whatever the ToolNode's `handle_tool_errors` is, and through
  `.with_fallbacks()` (#212).
- `instrument()` (Python) renews its process run after the signer closes it for idleness, and sends work to the current
  run while one is set (#206). It no longer patches OpenAI Agents' `Runner` (#206). TypeScript does the same, at most
  once per call (#214).
- TypeScript: a run with pending or approved-but-unconsumed approvals stays open at exit, so another process can
  approve and resume it. SIGINT/SIGTERM close the run only when nothing else handles the signal (#214).
- Browser pack: `browser_use:evaluate` asks; a navigation with a query string counts as sending data to its host;
  `send_keys` and `select_dropdown` count as typing (#212).
- `tool_results_sent` counts only results since the model's last turn (#206).
- Refusal texts the model sees leave out `TK-UNKNOWN-TOOL`; the signed `rule_ids` are unchanged (#218).
- `tracekit init`, `uninstall` and `doctor` use `$CLAUDE_CONFIG_DIR/settings.json` when it is set (#218).
- Containment (#213): no trigger suspends an identity. Suspension is an operator's call: a policy with
  `suspend:` in `respond` fails to compile, so the signer won't load it.

### Added
- **The viewer works like the why app it came from** (#224, #228): RUNS, OVERVIEW, TIMELINE, WHY DID IT HAPPEN?,
  GRAPH, AGENTS and INFLUENCE views; the graph is a flowchart with arrows and confirmed causes drawn to their target
  with their effect; clicking a node shows what it saw, produced, came from and led to. A store opened without why logs
  gets a graph of each signed run's calls with their decisions. A screenshot tour is in [docs/viewer.md](docs/viewer.md#tour).
- **`tracekit why report`** (#228): one offline HTML file with every run; `tracekit why demo` writes one.
- **`tracekit view --webhook URL`**: POSTs each new high why alert as JSON (Slack-compatible), as `tracekit why serve` did.
- **Faster signer** (#223): about 12% more events per second in E9's quick run and 15% less CPU per event at
  ack-on-write; no record, hash or
  signature changes.
- **Signer settings** (signer.yaml): `posture`, `observe_grace_s`, `gateway_wait_s`, `suspensions`,
  `approvals.agents`, a configurable `approvals.ttl_s`, `agent_consume_s` and `agent_timeout_s`; the signer refuses to
  start when an agent approver's `veto_s` isn't shorter than `approvals.ttl_s`. `tracekit init --v2 --egress` routes
  an agent user's traffic through the egress observer (Linux system mode).
- **Custody, tier T2** (#209): `tracekit executor` runs registered actions with credentials the agent never holds;
  `tracekit mcp-gateway` proxies MCP servers whose credentials stay in it. Adapters honour an ask rule's `approval: {executor: t2}`. Calls a
  gateway holds are bound to it and its caller, recorded with `via`, and resolved or signed `held_call_unresolved` when
  the run closes. Helm and compose services and an opt-in egress NetworkPolicy ship too.
- **Completeness** (#210): signed gaps for calls allowed or approved that never completed (`decided_not_completed`),
  for writes after `run.final` (`late_activity`), for a second run in one bound harness process (`concurrent_run`) and
  for a killed tailer (heartbeats). There is also a live `reconcile.hook_missing` when the gateway sees a result go
  back with no decide. Inputs of provider-executed tools are committed, and the gateway gets a `provider_tools`
  allow/deny.
- **Detection** (#207): `sequences:` and `limits:` in the policy, over rule ids and labels, scoped to a run, session,
  owner or attested principal. They are recorded as `incident.opened` / `incident.updated` (shadow unless a
  `respond:` rule enforces), with `tracekit policy backtest` and shadow-mode rules in the shipped packs.
- **Containment** (#213): enforced `hold` (each call asks a person, never an agent or self-approval) and
  `quarantine` (deny, then refuse; the gateway stops the model loop). New runs of the same owner and principal
  inherit them for a cooldown. Operator calls (`tracekit signer incidents list|show|resolve|hold|quarantine|resume|
  pause|unpause|suspend|unsuspend`), a shared suspension list, a durable incident outbox (OCSF 2005, Slack), and
  verifier checks that each response was honoured.
- **Agent approvers** (#208): a reviewer agent may answer approvals inside typed bounds the policy sets
  (`approval.agent`), with budgets and a veto delay; people answer everything else. The reference reviewer
  (`tracekit reviewer`), bridges, viewer desk and verifier checks (#211).
- **Run sessions** (#203): `register_run`'s `parent` links a child run to its parent (`parent_run`, `session`), and
  detection scopes by session.
- **Format 1.2 gate** (#203): one version table sets each bundle's `verifier_min_version`; shipped rows are frozen by a
  test (#214).
- **CrewAI** (#218): `tracekit.instrument()` wires CrewAI's tool hooks, which block by return value, never
  by raising ([CrewAI](docs/integrations/crewai.md)).
- **Pairing without call ids** (#218): a call decided under an adapter's own id is reconciled with the
  model's tool use of the same turn by its arguments, when unambiguous (`run.final.paired_by_args`).
- **Policy**: class `app` for an application's own tools; `handoffs:`; `structured_output:` (#206, #212).
- **MCP**: mcp 1.x sessions are named from `initialize()` (or `TracekitSession(..., server=)`) (#212). TypeScript
  gates local MCP servers (agents-js) and `@ai-sdk/mcp` tools as `mcp:<server>/<tool>` (#214).
- `instrument()` wires Browser Use (#212).
- **Egress observation and the coverage matrix** (#215): `tracekit egress`, a forward/CONNECT proxy outside the
  agent (no TLS interception) that checks each run's token, records `effect.observed` and flags
  `reconcile.unexplained_effect`; `run.final` and both verifiers report per action class whether it was enforced,
  observed, reported or not covered.
- **Recorded demos** of the main use cases in [docs/demos](docs/demos/README.md) (`make demos` regenerates and
  checks them), and a case study of Tracekit on real open-source agents
  ([docs/case-study-oss-agents.md](docs/case-study-oss-agents.md)).

### Fixed
- The v1 client: a reply lost after the request went out no longer resends and records a false "counter went
  backwards" gap and a `signer_down` gap (#218).
- Python `RunHandle.approval_consume` never raises (it returns `{"ok": False, "reason": ...}`), and result fields never
  raise on values that aren't plain JSON (#218).
- Claude Code's SessionEnd names the session's last `client_seq`, and a run the signer already closed still takes a
  client's trailing gap (pre-release review).
- **A denied tool ran in CrewAI while the signer was down.** CrewAI runs a tool when a hook raises, and Python's
  `decide` raised. Fixed by the fail-mode `decide` and the CrewAI integration (#218).
- **An event lost in an outage at the very end of a run left no signed gap.** `close_run` now names each stream's last
  `client_seq` (#214).
- Python `complete` raised after the tool ran when the signer was down, and crashed the agent (#218).
- Streamed OpenAI responses (`with_streaming_response` + `parse()`) were recorded empty, so every tool call
  reconciled as `fabricated` (#206).
- OpenAI Agents: `ask` raised TypeError with an app's own run context (#206).
- Long-running servers were refused every call after the process run's idle close: Python (#206), TypeScript (#214).
- mcp 1.x: `instrument()` broke every MCP call, and MCP error results were signed `ok` (#212).
- Reconciliation: an MCP call matches the names frameworks show the model (bare tool, `mcp__<server>__<tool>`,
  `mcp_<server>__<tool>`) and is compared by signer-computed digests (#214). No `class_mismatch` gap when the policy's
  own mapping is at least as strict as an adapter's generic hint (#218).
- A model response missed in an outage is sent at the next call after a signed gap. Leaving a `with client.run()`
  block never hides the block's own exception (#212).
- The policy YAML subset reads flow lists split over lines (#218).
- A tool result with a lone surrogate no longer crashes the adapter after the action ran (#218).
- Python `run.call("approval_list")` works, and every Python client `call` takes keywords (#218).
- The TypeScript gate follows `currentRun()` / `withRun()`, and a call an app's own guardrail refuses is completed as
  an error (#214).
- CI: three intermittent test failures (#205).

### Security
- A client's tool class hint can never exempt a call through a rule's `unless` (pre-release review).
- Agent approvers: a person's reject now sticks: an agent can't approve the same call by asking again (pre-release review).
- Bundles with a passkey-approved call verify: the schema now admits `approval.request`'s `passkey` (gated as 1.2;
  this also affected the unpublished 1.1.0rc1 commit) (pre-release review).
- Browser Use: secrets from `sensitive_data` are masked in every encoded form (percent-encoding at any depth, HTML
  references, JSON and `\u` escapes) before anything reaches the signer (#212).
- Browser Use: every page the agent reads is observed as untrusted before its next action, and an unobservable page
  refuses the action unless `browser` fails open. A `client_counter_gap` makes the run's provenance index partial
  (#212).
- An MCP tool is also checked under its bare name, the stricter verdict applying, so relabelling a tool as MCP gains
  nothing (#214).
- Calls a gateway or executor holds can't be completed, consumed or abandoned by the agent (#209).
- The LangChain adapter uses plain `http://` only to an IP-literal loopback signer (#212).
- Containment hardening from an independent review (#213): several holds per run, cooldowns for operator holds,
  suspension checked on every call, and verifiers that check an enforced response was recorded.

### Not in this release
- Linking an OpenTelemetry-imported run to the run that gated the same calls (docs say how to read them apart).
- A server-name map for MCP under mcp-agent: its calls stay unpaired (`reconcile.hook_missing` + `fabricated`), as
  [limits](docs/limits.md) says.
- A policy key marking MCP servers trusted, a delegation class for CrewAI coworker tools, a Python approval-states
  helper.

## 1.1.0rc1 (2026-10-11) — the why

The first 1.1 release candidate. 1.0 records what an agent did, provably; 1.1 adds why it did it, also provably:
the signer tracks where each argument came from and can hold a call whose value came only from untrusted content,
and `tracekit why` finds which input caused an action by replaying the run without it. Everything 1.0 promises is
unchanged; v1 bundles and 1.0 bundles keep verifying. Every limit of the new features: [docs/limits.md](docs/limits.md).

### Upgrade notes
- **Signer RPC version 15** (1.0 spoke 12): upgrade the signer and its clients together, as before.
- **Bundles with 1.1 records need a 1.1 verifier** (`verifier_min_version: 1.1.0`): `input.observed` records,
  decisions with `provenance`, content-vault and why-finding records. A 1.0 verifier reports them `UNVERIFIABLE`,
  never `FAILED`. Runs with none of them stay readable by 1.0. Export bundles from a 1.1 signer with tracekit >= 1.1.
- **Provenance fails closed.** After a signer restart, or when a run's index is truncated, partial or out of time,
  `from: untrusted` rules hold the calls whose pattern matches (emails, payments, data sent to a host) until the run
  ends; the decision records why. Values your app supplies: observe them as trusted.
- **Postgres**: existing stores keep working; turning the content vault on needs `tracekit signer migrate` (schema 2).

### Added
- **Signed provenance** ([policy](docs/policy-v2.md#provenance-untrusted-and-from-untrusted)): per run, the signer
  indexes (as keyed hashes, in memory) the values that untrusted tools' results and observed inputs carried; every
  decision records which arguments carry untrusted-only values and from which record. New policy keys `untrusted:`
  and `from: untrusted`; rules TK-P001 (an email recipient), TK-P002 (a payee or account) and TK-P003 (data sent to a
  host) hold such calls for a person. Every shipped integration sends untrusted tools' results to the signer
  (`send_result`), so this works with OpenAI Agents, LangGraph, the Claude Agent SDK, MCP, Browser Use, Claude Code and
  the TypeScript adapters. `run.observe(value, source=, trust=)` (Python and TypeScript) records other content.
- **`tracekit why`** (formerly Causeway, now part of Tracekit): a causal log of multi-agent runs, lineage and argument
  provenance, candidate causes, counterfactual replay with paired seeds and confidence intervals, sequential tests,
  and Find the cause (`tracekit why attribute`). Replays serve tool results from the recording and never run tools.
  Runs recorded with a signer cite the signed records behind every event; `tracekit why import --store/--bundle`
  turns signed runs into why runs; `tracekit why verify --salts` checks quoted content against the signed
  commitments.
- **Attribution on signed runs**: decision replay and agentless loop replay of OpenAI- and Anthropic-style agents,
  through the gateway, from the content vault, without the agent's code; a ranking that picks what to test first;
  results written as signed `why.finding` records whose replay runs are signed too, and which the verifier
  recomputes (interval, verdict, and each hit against the recorded model responses).
- **LangGraph fork replay** (`tracekit why attribute --langgraph module:factory`): replays a LangGraph thread from the
  checkpoint before the suspect input, in scratch branches that never touch the app's thread, store, cache or tools.
- **Content vault** (opt-in, [privacy](docs/privacy.md)): the signer keeps each record's redacted content encrypted
  (per-run keys, bound to the record); reading it takes a `content_read` grant and writes a signed `content.accessed`
  record; erasure and retention delete the run's key (and its replay runs') and write `content.erased`.
- **The viewer is the why UI**: where each argument came from (signed), the WHY panel (lineage, candidate causes,
  tests), graph, agents and influence views, why alerts, for runs with why logs (`tracekit view --why DIR`).
- **Independent TypeScript verifier** (`@cygnux/tracekit/verify`, `npx @cygnux/tracekit verify`): written from
  docs/format-v2.md, zero dependencies, Node and browsers; CI checks it agrees with the Python verifier on every case.
- **Public witness** ([witnesses](docs/witnesses.md#the-public-witness)): a free C2SP witness server with open
  registration (`tracekit public-witness serve`), the signer's one-line opt-in `witnesses: [public]`, and a deployment
  kit (deploy/public-witness). Its URL and key ship once it is deployed.
- `demo --why`: the support desk end to end — a held exfiltration email, the cause found by replay, the citation
  checked in the verified bundle.
- docs/quickstart-v2.md: how each integration waits for a person on a held call.

### Fixed (from the pre-1.1 review)
- The v2 verifier reads bundles strictly (one canonical zip layout, integer run-set bounds, JSON depth 128); also in
  1.0.1.
- Provenance: linear-time value extraction (an adversarial page no longer costs seconds per call), redaction no longer
  hides an injected value, list fields and hosts are matched as written, normalisation of Unicode tricks, the index
  survives a storage outage.
- `tracekit why`: replays through the Anthropic adapter never run real tools; ingest is answered before analysis and
  stays fast on long runs; ingest tokens are separate from the viewer's and bound to their runs; malformed or
  duplicated events are refused; test results are hash-chained; p-values are corrected for every input tested.
- The public witness: per-client limits, buffered request bodies behind Caddy, expiring unused origins, a total
  deadline on witness requests, and start-up that no hostile witness can stall.
- Claude Code: the transcript tailer follows the session's subagent transcripts too, so a subagent's tool calls no
  longer reconcile as `fabricated` (and `verify --strict` no longer exits 3 on them).
- Windows: `tracekit doctor` reports that it doesn't read ACLs instead of failing the key and content-vault checks on
  POSIX file modes; the dev signer's start tolerates its config being rewritten.
- Docs say what ships: no T2 executor yet (run held calls in a worker of your own), a v2 hook payload that can't be
  parsed passes unrecorded, and the Claude Agent SDK adapter honours `fail_modes`.

### Not in this release
- The viewer's FIND THE CAUSE and RUN TEST buttons for signed runs: use `tracekit why attribute --run ...`.
- The public witness's URL and key (the shortcut says so until it is deployed).
- npm packages are not published yet.

### Corrections
- The 1.0.0 entry says npm packages are signed release artifacts; no npm packages were published for 1.0.0.

## 1.0.1 (2026-10-11) — stricter bundle reading

A patch for 1.0: the v2 verifier reads bundles more strictly. Bundles written by Tracekit are unaffected; every
existing bundle verifies as before.

### Fixed
- A v2 bundle must have one zip layout ([format v2 §9](docs/format-v2.md#9-bundle-layout)): no zip64 records, no
  archive or entry comments, no extra fields, entries contiguous from offset 0, the central directory and its end
  record exactly where they belong, stored or deflate only, flags 0. Anything else is `UNUSABLE BUNDLE`, so every zip
  reader sees the same entries the verifier checked.
- `registry/run-set.json` bounds must be JSON integers.
- JSON nested deeper than 128 levels is refused everywhere: by both verifiers' strict parser and by the signer, which
  denies such tool-call arguments (`TK-ARGS-INVALID`).

## 1.0.0 (2026-10-11) — first stable release

1.0.0 is 1.0.0rc2 made stable: the v2 signer, evidence format v2 and its verifier, witnesses, the monitor, team approvals,
server deployments (container, Kubernetes sidecar, central signer on Postgres) and the run viewer. The v2 format is now
stable: 1.x verifiers verify every 1.0 bundle, and a bundle that needs a newer verifier says so (`UNVERIFIABLE`), never
`FAILED`. The v1 laptop setup and v1 bundles keep working unchanged. Upgrade notes from 0.4.0: see 1.0.0rc1 below.

### Added
- **One install, one line, a verified run.** `pip install tracekit-ai` now installs everything the dev signer needs
  (`tracekit-ai[signer]` still works); `pip install --no-deps tracekit-ai` is the verifier alone, on the standard
  library. `import tracekit; tracekit.instrument()` wires the frameworks it finds (OpenAI Agents SDK, LangGraph /
  LangChain, Claude Agent SDK, MCP, and the OpenAI, Anthropic and Google Gen AI SDKs), starting a dev signer if none
  is running. `tracekit last` exports the newest finished run, pins the dev signer's key and verifies it. The README
  and each framework quickstart are those three steps. What this path doesn't cover:
  [docs/limits.md](docs/limits.md).
- [docs/limits.md](docs/limits.md): every known limit and trade-off on one page.

### Changed
- `tracekit.instrument(tracer)` (v1 model-call tracing) is now `tracekit.autotrace.instrument(tracer)`;
  `tracekit.instrument()` raises a `TypeError` naming it when given a tracer.

### Fixed
- A network service that refused a request before reading its body (wrong Host, missing session or CSRF token) could
  reset the connection before the client read the answer, on Windows always and elsewhere while a large body was
  still arriving. Each service now reads what the client sent, up to 1 MiB, before closing.
- A config file written as JSON (`signer.yaml`, the viewer's and the gateway's) failed to load where PyYAML isn't
  installed, which `tracekit-ai[signer]` doesn't install. JSON documents now load either way.

### Release
- npm: no `@cygnux/tracekit-signer-darwin-x64` package (google-re2 and cryptography publish no Intel-Mac wheels it can
  use). On an Intel Mac, `pip install 'tracekit-ai[signer]'`; `@cygnux/tracekit` uses that `tracekit` from PATH.
- Releases are built and published by the attested release workflow: PyPI files, npm packages and the signer image
  carry SLSA build provenance and SBOMs, the image is cosign-signed, and `SHA256SUMS` is attached to the GitHub release
  ([docs/RELEASING.md](docs/RELEASING.md#verifying-a-release)).
- SECURITY.md: 1.x is the supported line.

## 1.0.0rc2 (2026-10-11) — the run viewer

The second 1.0 release candidate. Nothing changes in the signer, the evidence formats, the verifier or the policy
packs: rc1's bundles, configs and clients work unchanged (signer RPC version 12).

### Viewer (`tracekit view`)
- **Runs panel**: each v2 run with its agent's registered name, its verifier verdict (`VERIFIED`, `FAILED`, `PENDING`),
  start, duration, and its calls, blocked, held and gaps. Selecting a run scopes the tape, timeline, tool mix and header
  to it; the header shows the selected run's own verdict, or how many runs failed.
- **Run review**: integrity and assurance, what the policy allowed, flagged, denied and held, who approved (attested or
  bridged, and whether it was self-approved), gaps by kind and coverage; each line opens its first record.
- **Replay**: step through a run, or jump to the next deny, hold or gap, with the header and tape as of that moment.
- **In words**: blocked calls show their rules' reasons; holds and approvals are their own `HOLD`, `APPROVE` and
  `REJECT` rows; the signer's own records no longer count as an agent; tape filters for decisions, approvals, and gaps
  and alerts; the timeline is scaled to the calls shown.

### Docs
- [docs/viewer.md](docs/viewer.md): a screenshot of a run under review; the README quickstart ends with `tracekit view --dev`.

## 1.0.0rc1 (2026-10-10) — server deployments and teams

The first 1.0 release candidate: the v2 signer becomes the way to run Tracekit, on a laptop, in a container, as a
Kubernetes sidecar or as a central service on Postgres, with witnesses, a monitor and team approvals. The v1 laptop
setup and v1 bundles keep working unchanged. [docs/launch-checklist.md](docs/launch-checklist.md) lists what the 1.0
release still waits on; 1.0 itself is the owner's call after real use.

### Upgrade notes
- **Signer RPC version 12** (0.4.0 spoke 7). Clients and signers of different versions refuse each other; upgrade the
  signer and its clients together. A dev signer of the old version is reported, never restarted behind your back.
- **v2 bundles now need tracekit >= 1.0.0 to verify** (`verifier_min_version`): they can carry anchors, hybrid
  checkpoint signatures, certified record keys and other records 0.4.0's verifier doesn't know. An older verifier
  reports them `UNVERIFIABLE`, never as failed. 0.4.0 bundles still verify. v1 bundles and the v1 verifier are unchanged.
- **TypeScript**: `@cygnux/tracekit`'s default import is now the native v2 client; the v1 API is at
  `@cygnux/tracekit/v1`, and the Python bridge it used is deprecated.
- **Server deployments run the server policy pack.** The image, the compose stack and both Helm charts now set
  `policy:` (before, they fell back to the laptop pack). Replace `/etc/tracekit/policy.yaml` to run your own.
- **Run-sets need their registry notes cosigned**: with `witnesses_required` set, a run-set exported before the
  witnesses cosigned its registry note verifies `INCOMPLETE`; the run-set line now names its tenant.
- **Policy packs**: rules now match what a call acts on (`target`) rather than everything it carries, so writing a file
  that merely mentions a credentials path is no longer denied; `TK-S005` is folded into `TK-S004`; new rules
  `TK-N003`, `TK-B003` and `TK-SQL-PARSE`. Policy files are always read by the built-in YAML subset (duplicate keys and
  anchors are errors even where PyYAML is installed). A command or SQL statement the parser can't read is held (ask).
- **Clients**: one run's events are sent one at a time (other runs still in parallel); a v2 hook that can't start now
  blocks the call in dev mode too.

### Fixes from the pre-1.0 review
A five-part review of the signer, storage and verifier, network services, clients and policy before this release; each
fix has a regression test.
- **Approvals**: self-approval is detected across every identity mapped to the same person, including OIDC person ids;
  a consumed approval covers only the arguments it approved; a passkey-required approval is refused without a verified
  assertion on every path; a blank break-glass reason is refused; a bridge acts for people of its own tenant only
  (unless it is a multi-tenant app); passkeys are registered only soon after a sign-in.
- **Signer**: nothing is signed with a record key whose certificate has expired; runs are refused in tenants the key
  isn't certified for; closing a log ends its open runs first; finished runs leave the writer's working set; retry
  caches are bounded per identity and keep no executor arguments; OTLP import adds spans only to the importer's own runs.
- **Verifier and storage**: run-set completeness requires the registry notes' witness quorum and that every bundled run
  is of the run-set's tenant; a power loss can no longer leave the file store unable to start; Postgres calls time out
  instead of hanging; registry notes are read on demand; fsck checks the trees against the logs; exporting an active
  run works; the monitor and export write durably.
- **Network services**: the signer's HTTPS listener, the viewer, metrics and the Slack bridge bound their connections
  and enforce request deadlines; a pending viewer login can't be evicted; valid credentials work behind an address
  that others failed from; loopback receivers answer only loopback host names; witness proofs no longer rehash the log.
- **Clients**: an answer can't reach the wrong caller; a stalled signer fails every waiting call within its timeout;
  installers refuse agent settings of an unexpected shape rather than rewriting them; hook approval waits fit the
  harness's hook timeout.
- **Policy**: SQL rules match outside comments and every literal form; hosts are normalised (numeric, mapped and
  encoded forms) before matching; command names built from expansions, more wrappers, interpreter programs in every
  form, option-borne commands and bundled force-push flags are covered; paths match whatever the separator or case.
- **Deploy**: the agent's mount of the signer socket is read-only; every chart container has resource requests and
  limits; image and npm bundle dependencies are pinned, and the npm bundles are built from the release's checked wheel.

### Deploy anywhere
- **Container image** of the signer (non-root uid 10001, digest-pinned base) and a **Docker Compose stack**: signer,
  Postgres, a shipped witness and the viewer.
- **Postgres storage** (one writer per log, advisory lock, a SELECT-only reader role for export, view and reveal) next
  to the file store, whose snapshots are now HMAC-authenticated.
- **Helm charts**: `tracekit-signer` (a sidecar the agent's container can't read) and `tracekit-central` (one writer
  per log, run ids routed by prefix, a viewer of every log).
- **Keys**: the log key can live in AWS KMS (Ed25519) or GCP; an issuer service certifies short-lived record keys,
  witnessed before it returns them; checkpoints can carry a second, post-quantum signature (SLH-DSA, FIPS 205).
- **Anchoring and monitoring**: checkpoints anchored in Rekor v2 with RFC 3161 timestamps; `tracekit monitor` follows a
  log, checks its rules and publishes signed reports, so bundles can verify at `witnessed+monitored`.
- **`tracekit doctor`** checks v2 deployments, including Kubernetes; laptop **system mode** runs the v2 signer as its
  own user, with harness binding through a root-owned helper.
- **Remote clients** reach the signer over HTTPS with Kubernetes service-account, mTLS, bearer-token or OIDC
  identities; v1 remote ingest is replaced.
- **LLM gateway** (OpenAI-compatible) that records model calls through the signer, optionally mandatory.

### Capture and evidence
- **Reconciliation** of three capture layers (transcripts, hooks, SDK) in the signer, with signed coverage gaps; a
  hardened Claude Code transcript tailer; v2 hooks for Codex, Cursor and Gemini CLI.
- **Verifier**: the complete v2 report, a golden corpus and a negative corpus, run-set completeness, retired-key use
  failing, revocations reported as unverifiable.
- **OpenTelemetry** in (OTLP into the signer) and out (spans from v2 records).

### Policy and approvals
- **Server policy packs**: SQL, HTTP egress, cloud CLIs and MCP tools, payments, email and chat, plus cloud metadata,
  secrets and credential files on every tool. On the shipped corpora they catch every deny case and hold 0.16% of
  benign calls. `extends` takes a list of packs.
- **Team approvals**: OIDC sign-in for approvers and the viewer; a run's end-user principal can be attested from their
  token and never approves its own run; web approval pages, with passkeys (WebAuthn) required for high-risk rules;
  Slack approvals; break-glass answers need a reason and are recorded.
- **External decisions** from AWS AgentCore Policy, Amazon Verified Permissions, VS Code agent hooks and GitHub Copilot
  hooks are imported as signed inputs, and a disagreement with the signer becomes a signed gap.
- **OCSF webhook**: decisions, denies, approvals, gaps and tamper records sent HMAC-signed to a SIEM, without agent
  content.

### Viewer
- **Multi-tenant viewer** over every log of a central deployment: auditor (one tenant), approver and operator-admin
  roles, search and pagination, each run checked by the verifier (labelled as the operator's view) and downloadable as a
  bundle to re-verify.

### SDKs and integrations
- **Native TypeScript client** of the signer RPC, with adapters for the OpenAI Agents SDK, the Vercel AI SDK and the
  Claude Agent SDK, and `npx @cygnux/tracekit up` for Node-only users.
- Runnable v2 examples and quickstarts per framework; `tracekit demo --server`; a Browser Use adapter.

### Release and docs
- Release engineering for signed artifacts with provenance, SBOMs and multi-arch images (the target workflow is in
  [docs/RELEASING.md](docs/RELEASING.md)).
- Deployment, migration, architecture, security-checklist, FAQ and limits docs; a rewritten README; the technical
  report ([report/tracekit-v2.md](report/tracekit-v2.md)) with the E-series results.

## 0.4.0 (2026-10-10) — v2 signer preview

A **preview of the v2 architecture** for server-hosted agents, shipped alongside the unchanged v1 laptop setup.
Everything v1 (`tracekit init`, the v1 hooks, `tracekitd`, `.tkb` v1 bundles and their verifier) works as in 0.3.0;
the v2 pieces are opt-in (`pip install 'tracekit-ai[signer]'` for the signer). Formats and the signer RPC may still
change before 1.0. Quickstart: [docs/quickstart-v2.md](docs/quickstart-v2.md).

### The v2 signer (preview)
- **`tracekit signer serve`**: a signer service that holds the keys and assigns sequence numbers; agents talk to it over
  a versioned RPC (Unix socket with peer-uid identity, loopback TCP with a token for dev, HTTPS with Kubernetes
  service-account tokens, mTLS/SPIFFE or a bearer token). Per-method authorization and tenant mapping from config.
- **Same-user dev signer, started on first use** by the Python client (`tracekit up | down | status`); a signer of an
  incompatible version is refused, never restarted behind your back.
- **Evidence format v2**: JCS canonical JSON, domain-separated Ed25519 record signatures, an RFC 6962 Merkle tree over
  all records, C2SP checkpoint notes signed by a separate log key, per-tenant registry logs, and per-run bundles.
- **`tracekit verify`** reads v2 bundles against a pinned trust config (`tracekit signer trust` writes one for a dev
  signer) and reports `Integrity` and `Assurance` separately; a dev signer's runs verify at `Assurance: dev`.
  Assurance levels describe how far the checkpoint is anchored (`dev`, `local`, `witnessed`), not where the signer
  runs: a signer running as the agent's own user can still reach `witnessed`.
- **Run lifecycle** in the signer: registration, idle timeout, closing window for late results, `run.final`; gap and
  tamper records are written by the signer only.
- **Policy v2 inside the signer**: an RE2-subset engine (google-re2 or `regex`, same results), a structural shell
  parser, tool classes, the coding packs, `unless` exemptions; decisions are bound to the exact arguments that later run.
- **Approvals**: one per tool call attempt, bound to its arguments, consumed once; edited arguments, swapped ids and
  expired approvals are refused and recorded; pending approvals survive a signer restart (arguments kept encrypted);
  `tracekit approvals list | show | approve | reject`. Self-approval is allowed in dev mode, labelled, and caps
  assurance at `dev`. A signer started from a config refuses self-approval and accepts only configured approvers of
  the run's tenant (`approvals: {approvers, self_approval, break_glass}`); break-glass answers need a reason and are
  recorded; an ask rule may name a T2 executor, which gets back exactly the approved arguments.
- **Checkpoints, export and viewing**: signed notes after each run ends and on a cadence; `tracekit export --v2`;
  `tracekit view`, a read-only laptop viewer where every run is checked by the verifier.
- **Witness publishing**: checkpoint notes go to configured C2SP tlog-witnesses in the background; cosignatures are
  merged into the stored notes; a persisted retry queue survives restarts; a witness that stays unreachable gets a
  signed gap. A run cosigned by a pinned non-operator witness verifies `Assurance: witnessed`.
- **Privacy**: tool results and the approver's copy of arguments are redacted inside the signer before anything is
  committed, with a manifest of the rules that fired; every published digest of agent content is a salted
  commitment, and `tracekit signer reveal --record N` gives an auditor the salt of that one record
  ([docs/privacy.md](docs/privacy.md)).
- **Metrics**: Prometheus `/metrics` on its own port ([docs/observability.md](docs/observability.md)).
- **Run-set completeness**: per-tenant registry logs are checkpointed; `tracekit export --v2 --run-set` bundles every
  run a tenant registered in a window, so a deleted run or a withheld key retirement fails verification; a
  single-run bundle reports key retirements as not proven complete (a warning; `--strict` exits 3).
- **Format bridge**: `tracekit signer bridge` continues a v1 ledger in a v2 log and retires the v1 key.

### Integrations on v2 (preview)
- **Claude Code**: `tracekit init --dev --v2` wires a thin v2 hook (no local policy, no keys; ~55 ms per tool call).
- **OpenAI Agents SDK** (`tracekit.integrations.openai_agents`): signer-side approvals through the tool input
  guardrail, `apply_decisions(state)` for paused runs; hosted tools are recorded and listed as uncovered.
- **LangChain v1** middleware (`tracekit.integrations.langchain`): deny-and-continue, approvals through LangGraph
  `interrupt()` that survive a process restart; `tracekit_tool_node` for graphs built on `ToolNode`; and
  `TracekitCheckpointer`, which commits every saved checkpoint (pending tool calls included) so an edited
  checkpoint is recorded as `state_tamper`.
- **Claude Agent SDK** (`tracekit.integrations.claude_agent_sdk`): hooks for `ClaudeAgentOptions` and a session
  store wrapper that commits saved transcripts.
- **MCP client** (`tracekit.integrations.mcp`): every `call_tool` on a wrapped `ClientSession` is decided by the
  signer and recorded as `mcp:<server>/<tool>`.
- Every adapter: when the signer can't be reached, the run's fail mode for the tool class applies (default: closed);
  a signer refusal, or a failure once a call waits for approval, never lets the call run; a failure to record an
  outcome warns and leaves the tool's result as it was.
- **Autotrace on v2** with shared parsers for OpenAI (Chat Completions, Responses), Anthropic and Google Gen AI: the
  tool calls a model asked for are recorded (as salted commitments) for later reconciliation.
- An adapter contract suite that every integration runs against both a test signer and the real one.

### Hardening from the release review
A review of everything above before release found and fixed, among others: the Claude Code v2 hook letting calls
through unrecorded after ~32 calls in a session (one event stream per session now); shell-parser inputs that could
stall the signer, and policy bypasses (argv-list commands, `bash -c --`, globs and braces in the command name,
scripts piped into a shell, quote splicing, `..` paths, missing wrappers and tool names); a result recorded after a
deny now leaves a signed gap; key files written atomically and checked at start; a log rolled back below its own
checkpoint is detected; memory of finished runs released; restarts keep idle and grace clocks; background loops no
longer die silently; `verify --trust` refuses bundles that are not v2; run-set and key-retirement soundness; the
viewer always requires its token; `tcp://` signers are loopback-only; mTLS identities are tied to their trust
domain's CA; Kubernetes JWKS keys expire and errors are no longer echoed to unauthenticated callers.

### Changes v1 users can notice
- **New required dependency `rfc8785`** (canonical JSON for format v2). Verifying a v1 bundle still needs only the
  standard library: the v2 verifier loads only for v2 bundles.
- **`tracekit verify`** refuses flags that don't apply to the bundle's format (`--trust`, `--v1-ledger`, `--v1-key`
  with a v1 bundle; `--key`, `--witness` with a v2 bundle) instead of ignoring them.
- **`tracekit status`** gains a `signer_v2` section (it starts and creates nothing).
- **Hooks:** `tracekit init` says when it replaces a v1 hook with a v2 one or the other way round.
- **Autotrace (v1):** also records `.parse()` calls of OpenAI Chat Completions, Responses and Anthropic Messages;
  usage for new captures counts OpenAI cache-write tokens separately and includes Gemini thinking tokens in output
  tokens, so `tracekit cost` totals for new runs can differ from 0.3.0 for the same traffic.
- **Windows:** non-blocking file-lock contention raises `BlockingIOError`, as on POSIX.

### Fixes
- A second v1 signer started on the same home no longer cuts off the running one (#73).
- Windows: the test suite runs again (it stopped at collection), file-lock contention is reported the same way as on
  POSIX, and the v2 client reaches a Windows dev signer over loopback TCP.

## 0.3.0 (2026-10-09)

First release published on PyPI, as **`tracekit-ai`** (`pip install tracekit-ai`; the import and the command stay
`tracekit`). The name `tracekit` on PyPI belongs to an unrelated project: do not install it.

### Breaking changes
- **Niche modules moved to `contrib/`** as separate packages: proof packs (`tracekit-proofpack`, also `tracekit-report`),
  SQL over the ledger (`tracekit-sql`), Causeway, on-chain guards and Stagehand. The old `tracekit proofpack`, `report`,
  `sql` and `causeway` subcommands print where they went. Entries below that mention them describe the contrib
  packages.
- **Proof packs no longer contain a verifier** (`verify.pyz` and `SHA256SUMS` are gone): auditors verify with a
  Tracekit release they install themselves. A bundled `replay.html` never affects a verdict.
- **The ingest gateway, the Anthropic model proxy and the OTLP receiver need `--experimental`**; they are being rebuilt
  for server-hosted agents.
- **GitHub Action:** `require-anchor` defaults to `true`, so an unanchored bundle fails the step.
- **System mode** runs only from a root-owned virtualenv at `/opt/tracekit`, installed from PyPI (`tracekit-ai`, the
  same version) or from a root-owned clone, with a root-owned Python. `tracekit migrate --system` refuses installs that
  predate it: re-run `sudo /usr/bin/python3 -m tracekit init --user <agent-user>`.
- **`tracekit cost`** reads the ledger directly; `--index` was removed.
- **`tracekit verify` output:** besides `Integrity:` and `Assurance:`, `--json` now carries `integrity`, `assurance`
  and `notes`. Assurance is `separate-user` only where the signer itself attested it.

### Security and correctness
- **Signer:** stamps `signer_isolation` on `run.start` itself; records an approval before it takes effect; validates
  approval requests (types, sizes, caller owns a started run, bounded `wait_s`, per-user cap); decides approvals only
  from facts it observes (peer uid, the approving process's terminal); runs first seen without `run.start` get an owner.
- **Hooks and client:** an untrusted or unreadable `/etc/tracekit/client.json` fails closed instead of falling back;
  subagent transcript paths are confined to the session; payloads without ids are not merged and leave a signed gap;
  a signer-rejected tool call blocks under `fail_mode: closed`, also when an approval was given; client state files use
  collision-free names (existing state carries over); Codex, Cursor and Gemini sessions keep their `run.start` when
  `reasoning_capture` is on.
- **Redaction:** linear time on adversarial input; long connection-string passwords are redacted; a `.env` mention no
  longer hides the command being run; lone surrogates are recorded instead of breaking capture.
- **Verifier:** honest exports are no longer failed by a single missed witness publish (a warning instead); a malformed
  or deeply nested bundle is a FAIL, never a crash; the witness-coverage detail names only checkpoints the witness holds.
- **Installer:** every file write is safe against symlinks and races; reinstalling never leaves an empty runtime (the new
  virtualenv is swapped in only once it imports); the system-mode hook blocks if it cannot run; re-running init keeps
  the policy pin and registered harnesses and restarts the signer; `tracekit doctor` checks the whole runtime without
  following symlinks; the GitHub Action passes inputs to the shell only through the environment.
- **Network servers** (witness, ingest): TLS handshakes per connection with timeouts, an overall per-connection
  deadline, bounded threads and a per-client cap; the witness log is locked against a second server and rolls back a
  failed write; witness and Rekor URLs are validated and redirects refused; Rekor read-back includes the signature.
- **Observer and replay:** all event-derived content is escaped; nonce-based CSP; the observer's token becomes an
  HttpOnly cookie; static exports carry a CSP.
- **SDKs:** a crashing or slow TypeScript bridge never crashes or hangs the host process, and fail-open lets model calls
  through; bridge requests that time out leave no unfinished signed records; abandoned Python streams are recorded
  before `run.end`.
- **Packaging:** contrib packages depend on `tracekit-ai`; the sdist ships what its tests need.

### Added
- **`tracekit observe` polish** and a reproducible interface video (`docs/demo/observer_scene.py`,
  `record_observer.mjs`).
- **Golden verifier corpus** (`tests/golden/`): frozen v0.1 and v1 evidence with the verifier's recorded verdicts.
- **Known-gap tests** (`tests/test_known_gaps.py`): strict expected failures for gaps the next evidence format closes.
- **`eval/e8_insider.py --require-harness`**, SECURITY.md, CONTRIBUTING (sign-off for contributions from forks).

### Earlier in this cycle

### Installer file writes
- `tracekit init` writes every config, settings file and backup through a directory fd: temp files get an
  unpredictable name, are created exclusively with their final mode (0600 for configs), and nothing follows a symlink.
  A symlinked `~/.claude/settings.json`, `~/.tracekit-client/` entry or signer `config.json` is refused with an error.
- As root, writes into the agent user's home run as that user; signer files are `fchown`ed on the open file.
- Backups are named `<file>.bak-<time>-<random>`.
- Dev mode over TCP: tracekitd binds a free port itself and records it in its config; init reads it back instead of
  probing for a free port.

### Project
- `SECURITY.md` states supported versions, a disclosure timeline, safe harbour and the operator caveat.
- Contributions need a DCO sign-off (`git commit -s`); a CI check enforces it on pull requests.
- Issue templates for policy false positives/negatives and integration requests; blank issues are off and
  security reports go to private advisories. The PR template checks security invariants and evidence-format changes.

### Hook invocation
- Generated hook commands (Claude Code, Codex, Cursor, Gemini) and the plugin's `tracekit-hook` run Python in
  isolated mode (`-I`): the project directory and `PYTHON*` variables no longer affect which `tracekit` is imported.
  Re-run `tracekit init` to rewrite existing hook commands.
- Cursor's `failClosed` and wiring errors in the Codex/Cursor/Gemini hook entry now follow the configured fail mode.
- The plugin's `tracekit-hook` blocks instead of allowing when the package is missing and
  `/etc/tracekit/client.json` is fail-closed.

### Validate remote endpoint URLs
- `tracekit init --remote` and `tracekit otel push` parse the URL: `https://` to any host, plain `http://` only when the
  host is exactly `localhost`, `127.0.0.1` or `::1`; URLs with `user@` are refused.
- The remote signer client and `otel push` no longer follow HTTP redirects, so credentials never reach a redirect target.
- An empty or non-JSON-object reply from the signer is treated as "signer unavailable", like a refused connection.
- `init --remote` refuses to write its config through a symlink.

### Verifier: v1 run completeness (interim, until evidence format v2)
v1 signatures cover `(hash, prev_hash, seq)` only, so an elided stub does not say which run it belonged to.
- **Elided records.** A bundle with any elided stub reports every selected run as "run completeness unproven (v1
  bundle with elided records)" and ends `VERIFIED WITH GAPS (run completeness)`, never plain `VERIFIED`. Export
  already includes every record of the selected runs; selecting fewer runs than the ledger holds now shows this gap.
- **Run boundaries.** Each selected run must have a non-elided `run.start` and a signed `run.end`; otherwise
  "run boundaries unproven" / "tail unproven" (a gap, not a failure). Findings and anchor runs are exempt.
- **Witnessed tail.** With `--witness`, the bundle must reach the first witnessed checkpoint at or after each run's
  `run.end`; a bundle that stops before that checkpoint fails with "tail not covered by a witnessed checkpoint".
- **Output.** The verdict is now two lines, `Integrity: …` and `Assurance: …`; assurance is `dev` when a run.start
  says the signer ran as the agent's own user (`signer_isolation: same-user`), so dev bundles never print a bare
  `VERIFIED.`.

### Fixed
- Redaction stays fast on large tool arguments: the private-key, JWT, connection-string, dotenv and secret-assignment
  rules no longer take quadratic time on repeated prefixes. Connection-string user and password parts are capped at
  256 characters, and URLs with an empty user (`redis://:p@h:6379`) are now redacted.
- When a tool call mentions a `.env` file, every `KEY=value` line in its inputs, including the fields always recorded
  in clear (such as `command`), is redacted.

### Security (observer and replay rendering)
- `tracekit observe` and `replay.html` escape every record-derived value they put into HTML, and fill their data
  slots in one pass, so bundle content cannot inject markup or script.
- The observer's CSP allows only its own script, by a per-response nonce (no `'unsafe-inline'` scripts).
- `observe --bundle` refuses a bundle that fails verification (non-zero exit) instead of showing it.
- With `TRACEKIT_OBSERVE_TOKEN`, open `/?token=…` once: the token is exchanged for an HttpOnly, SameSite=Strict
  cookie and the browser is redirected to a URL without it. API calls take the cookie or `Authorization: Bearer`,
  no longer `?token=`. A `--host 0.0.0.0` observer now answers on its LAN address for authorized requests.

### Security (0.3: harness binding, closing fabricated runs)
After 0.2.1, any process running as the agent's user could still drive the real hook with a complete, well-formed
run that never happened, and it verified as `VERIFIED` (E8.6). The signer now checks *which program* sent each event,
from the kernel's view of the sender's process tree, not from anything the agent can write.
- **Registered harnesses.** `sudo tracekit init --harness [NAME=]PATH` (repeatable; default: the agent's CLI on
  root's PATH) registers the agent program. It must be root-owned with no group/world-writable file or directory
  above it, so the agent cannot replace it. An npm-installed CLI registers as its interpreter plus its script.
- **Binding.** A hook `run.start` is accepted only from a process descending from a registered harness binary,
  matched by executable (`/proc/<pid>/exe`), not by name. The signer records the harness instance (pid + kernel start
  time) in the signed `run.start` (`data.harness`, never accepted from the client), and every later hook or
  transcript event of that run must come from the same instance. Anything else is refused and recorded against the
  targeted run, so a fabricated run, or a detached helper writing into a live run, ends `VERIFIED WITH GAPS`.
- **Fabricated runs from inside the session** are still possible (the agent's own tool call can run the hook with a
  new session id). A second open run in the same harness instance is recorded as a `concurrent_run` capture gap.
- **Verifier.** A new `harness attribution` check names the attested harness, or warns that a system-mode run has no
  binding and its hook events could have come from any process running as the agent's user.
- **Signer privilege.** Reading another user's `/proc/<pid>/exe` needs `CAP_SYS_PTRACE`; the systemd unit grants it
  only when a harness is registered (`AmbientCapabilities`, `CapabilityBoundingSet`).
- **Modes.** `harness_binding: enforce` (default with a registered harness in system mode), `record` (gaps instead
  of refusals), or `off` (default with no harness, and in dev mode). The proxy and SDK sources are not bound.
- **Upgrading:** `sudo tracekit migrate --system --harness /usr/local/bin/claude`, then restart `tracekitd`.
- **Eval.** E8 gains E8.6 (fabricated run outside the harness), E8.7 (fabricated run inside a live session) and E8.8
  (a detached helper writing into a live run). Upstream 0.2.1 verifies all three as clean `VERIFIED`; with binding,
  all eight E8 cases are caught. CI runs E8 with a registered harness and gates on all eight.
- **Still open:** fabricated *events inside the real run*, sent by the agent's own tool calls through the same
  harness instance, are only caught by the proxy cross-check (`proxy_missing`). Closing that needs OS-level capture
  (planned for 0.4).

### Security (0.2.1 hotfix: insider attacks on the capture path)
Four attacks on a Linux system-mode install made hidden or fabricated activity verify as a clean `VERIFIED`. None
broke the signature, chain or witness; they all went around what feeds the ledger. Found by a black-box audit with
real separate OS users; reproduced as eval E8 (`eval/e8_insider.py`, now a required CI job).
- **Signer redirect (E8.1, E8.2).** The hooks took the signer address from the agent-writable
  `~/.tracekit-client/config.json` or `TRACEKIT_SOCKET`, so an agent could send tool calls to a decoy signer and
  switch back; restoring its counter files hid the gap. System mode now reads a root-owned
  `/etc/tracekit/client.json` (trusted only if root-owned and not group/world-writable) and ignores both.
- **Cross-user injection (E8.3).** Appends after `run.start` were not checked against the run's owner, and the
  socket is world-writable, so any local user could write events into another user's run, recorded as
  `source: hook`. The signer now refuses events from a uid other than the run owner's (the signer's own uid, used by
  the proxy, still passes) and records each refusal against the targeted run; ownership survives a restart.
- **Fail-open by default (E8.4).** A tool call ran unrecorded while the signer was down. System mode now fails
  closed unless the root-owned config sets `fail_mode: open`.
- **Policy swap (E8.5).** `TRACEKIT_POLICY` is ignored in system mode. `tracekit init` also pins the effective
  policy hash in the signer config; a run or decision under any other policy is a `policy_mismatch` capture gap.
- **Verdict.** `verify` and proof packs say `VERIFIED WITH GAPS (...)` instead of `VERIFIED` when capture gaps or
  refused writes exist. Single-run exports now keep refused-write `error` events, which were elided before.
- **Label.** The `hook` capture source now reads "reported by a hook process (any process running as the agent's
  user can send these)" instead of "observed at the harness hook".
- **Upgrading:** `sudo tracekit migrate --system [--fail-mode open|closed]`, then restart `tracekitd`. Dev mode is
  unchanged.
- **Still open:** an agent can send a fully fabricated, well-formed run through the real hook path (E8.6). It needs
  harness binding (planned for 0.3); with the proxy on it surfaces as `proxy_missing`.

### Added
- **LangGraph node tracing, Browser Use and Stagehand hooks** (#6): `TracekitCallbackHandler(tracer, nodes=True)` records
  each graph node as a policy-checked `node:<name>` step; `tracekit.adapters.browser` gates and records Browser Use
  actions and Stagehand `act`/`extract`/`observe`/`goto` (Python), `instrumentStagehand` in the TypeScript SDK. Runnable
  examples for every adapter in `examples/` (and `sdk/typescript/examples/`), run in CI.
- **`tracekit demo --agent codex|cursor|gemini`** (#7): the scripted demo sent as that agent's own hook payloads; a
  guarantee matrix per capture path in the README.
- **Observer over bundles, with cost** (#9): `tracekit observe --bundle run.tkb` (verified first; live view or
  `--export`), `--prices prices.json` adds cost per model call, agent and session.
- **`tracekit.init()`** (#5) as the one-line entry point (same as `tracekit_sdk.init()`), with an offline example for
  OpenAI, Anthropic and Gemini (`examples/model_calls.py`).
- **PGS end to end on a local chain** (#15): `contrib/onchain/pgs_onchain_demo.py` drives Proof-Gated Signing's guard and
  wallet on a Hardhat chain; blocked transactions are checked on-chain to be unsigned (nonce unchanged), a drift attack
  reverts on its post-conditions. Fixed: transaction summaries now keep the target of PGS-style call dicts.
- **Jaeger example** (#13): `examples/otel_jaeger_check.py` matches every span Jaeger holds to a signed record of a
  verified bundle (run against Jaeger 2.22).
- **Key attestation in bundles** (#16): `--key-attestation FILE` with an external signer; the document's hash is signed
  into checkpoints, exports carry the document, `verify` reports it (Tracekit checks identity, not vendor contents).
- **Auditor walkthrough** (#12), now in contrib/proofpack/README.md.
- **E7: SQL at a million events** (#8, now `contrib/query/e7_sql_scale.py`): every typical query under 1 s on 2 vCPUs; rollup columns are copied out of the
  JSON at index time (index format 4, rebuilt automatically) and inserts are batched.
- **TypeScript SDK** (`sdk/typescript`, `@cygnux/tracekit`): policy-gated `tool()`, OpenAI and Anthropic instrumentation
  (streaming included), Vercel AI SDK middleware; runs on Tracekit's Python engine through `python -m tracekit.bridge`.
- **OTLP/gRPC ingest**: `tracekit otel serve --grpc-port 4317` (optional `grpcio`), same receiver and guarantees as HTTP.
- **The signer refuses findings whose evidence does not match the ledger** (missing record, wrong hash, none cited), in
  addition to the check `tracekit verify` makes offline.
- **Token usage and cost** (#9). Optional `usage` on `model.exchange` responses (input, output, cache read, cache write,
  reasoning tokens), normalised from the Anthropic proxy, the OpenAI / Anthropic / Gemini SDKs and OpenTelemetry
  (GenAI semconv, OpenLLMetry, OpenInference, Vercel AI SDK). Exported as `gen_ai.usage.*`, queryable in SQL, shown in
  the observer. `tracekit cost` totals per run or model; cost only with a user-supplied price table (none built in).
  The schema change is additive (optional field); bundles that use it need this verifier.
- **Coding-agent hooks** (#7): `tracekit init --dev --agent codex|cursor|gemini` on the Claude Code hook pipeline (policy
  gate, approvals, signing, transcript hashing), with tool names mapped onto the policy vocabulary.
- **Adapters** (#6): MCP client sessions (`tracekit.adapters.mcp`) and Vercel AI SDK telemetry spans.
- **Proof packs** (#12, now `contrib/proofpack`: `tracekit-proofpack` / `tracekit-report`): bundle, readable report with every check, findings,
  coverage and an evidence-to-control map (EU AI Act Art. 12, SOC 2 CC7.2, ISO/IEC 42001 A.6.2.8). (It also shipped `verify.pyz`, a
  bundled verifier; removed in 0.3.0.)
- **Witness service** (#17): `tracekit witness init|token|serve`, an append-only RFC 6962 Merkle log of checkpoints with
  signed tree heads, per-signer tokens, fork refusal and conflict log; `https://` witness specs check inclusion and
  consistency proofs against a pinned witness key.
- **External signers** (#16): keep the signing key in a TPM, HSM, enclave or KMS through a long-lived helper process;
  signatures verified before use; key assurance signed into checkpoints and reported by `verify` ("signing key").
- **Causeway integration** (#14, now `contrib/causeway`): `tracekit causeway anchor|verify|import-tests|export`.
- **Guarded onchain transactions** (#15, now `contrib/onchain`): `guarded_tx` records a transaction guard's verdict
  (Proof-Gated Signing's `Guard.check` interface) before signing and never signs a blocked transaction; detectors
  TK-X006 to TK-X008.
- **Signed findings** (#10) and **say-vs-do detectors** (#11). `tracekit analyze` runs deterministic detectors (claims vs
  executed commands, requests vs executions, risky actions left out of the agent's account, secrets in output,
  retrospective policy violations) and signs each finding as a `review` event in `findings:<run>`, citing records by seq
  and hash. Bundles carry findings with their run; `tracekit verify` adds "findings cite intact evidence" and fails on
  missing or altered evidence. Findings appear in the live observer. E6 (`eval/e6_findings.py`) measures the detectors
  on 2,000 synthetic sessions, including held-out paraphrases they miss.
- **SQL over the ledger** (#8, now `contrib/query`: `tracekit-sql`). `tracekit sql` with views `runs`, `tool_calls`, `model_exchanges`, `findings`, `gaps`,
  backed by a stdlib SQLite index that reads only the ledger's new tail, checks hash links, and rebuilds itself if the
  ledger was rewritten. Read-only connection, time budget, table/JSON/CSV output, and `--mcp` for coding agents.
- **OTLP push with auth** (#13). `tracekit otel push --endpoint URL --header K=V [--all|--run R|--follow]` sends signed
  runs to Jaeger, Tempo or any OTLP/HTTP backend, once per run; `export --otel-header` and
  `OTEL_EXPORTER_OTLP_HEADERS` are honoured. An explicit endpoint path is used as given.
- **One-line SDK auto-instrumentation** (#5). `tracekit_sdk.init()` patches the installed OpenAI (chat completions,
  Responses), Anthropic (messages.create, messages.stream) and Google Gen AI (generate_content, generate_content_stream)
  SDKs, sync and async, streaming included. Each call is a signed request event written before the call is sent and a
  response event with model, finish reason, requested tool calls, error, status, latency and time to first chunk.
  Streams are recorded when exhausted, closed or garbage collected (abandoned streams are marked). Recording failures
  never affect the call; `fail_mode: closed` refuses a call that cannot be recorded before it reaches the provider.
  `Tracer.tool(..., tool_use_id=...)` links an execution to the model request that asked for it. The remote gateway
  accepts `model.exchange` as SDK evidence.
- **OpenTelemetry ingest** (#4). `tracekit otel serve` receives OTLP/HTTP traces (protobuf or JSON, gzip or deflate)
  on loopback, and the ingest gateway serves the same endpoint at `/v1/traces` with TLS and per-client tokens.
  GenAI semantic-convention spans, OpenLLMetry and OpenInference spans become signed `model.exchange`, `tool.call`,
  `policy.decision` and `tool.result` events, one run per trace. Policy is evaluated retrospectively: a call a deny or
  ask rule would have stopped is recorded as `flag` with the would-be decision. Exporter retries never duplicate
  evidence, a signer outage returns 503 so the exporter keeps the batch, and a rejected event is reported as an
  OTLP partial success. The protobuf decoder is built in, so the receiver adds no dependencies. See `docs/otel.md`.
- **OTLP export carries evidence links.** Every exported span has `tracekit.entry_hash`, the hash of the signed
  ledger entry it came from. Runs ingested from OpenTelemetry export with their original trace and span ids, and
  model spans report their real provider instead of always `anthropic`.

### Changed
- SDK tool calls made without a model id now get `tk_` ids (were `call_`, which collides with OpenAI call ids).
- `tracekit analyze`, `otel` and `sql` parse their own options (a leading `--option` used to be rejected).

### Fixed
- **TK-D010** denied `cp .env /tmp/x` as "writing to a credentials file"; it now matches credentials files only as the
  destination of `cp`/`mv`/`install`. Default policy version `2026.10-1`.
- The coverage report called every model exchange "at the proxy, cross-checked against hooks"; application-reported
  exchanges are now listed separately, and only proxy exchanges are cross-checked against hooks by the signer.
- `test_rate_limit` was timing-dependent and failed on slow machines; the bucket no longer refills during the test.

## 0.2.0rc1

First release candidate of v0.2: the signed evidence-bundle core, live observer and custom-agent SDK.
This entry lists the fixes from the production-hardening review on top of the v0.2 development branch.

### Added
- Evaluations E2 (overhead), E4 (seeded faults against a real bundle) and E5 (opt-in real Claude Code runs) ported to
  v0.2, with `make eval-agents`; results in `docs/evaluation.md`. `eval/_stack.py` is the shared throwaway-signer helper.

### Fixed
- **The browser verifier could show a valid run as TAMPERED.** Python and JavaScript write some numbers differently
  (`1e-05` against `0.00001`, `1.5e+20` against `150000000000000000000`) and JavaScript cannot hold integers above
  2**53, so any run containing such a value hashed differently in `replay.html` and the observer than in Python.
  Canonical JSON now writes numbers the way JavaScript does, and integers beyond 2**53 are recorded as strings.
  `tests/test_parity.py` runs the real JavaScript from both pages under Node against Python (skipped without Node).
- **Windows: stopping the signer.** `os.kill(pid, 0)` was used as a liveness probe, but on Windows signal 0 is a Ctrl+C
  event sent to the console process group, which can interrupt the caller. Liveness is now asked of the kernel, and
  the signer is asked for a final checkpoint before it is terminated (Windows has no catchable SIGTERM).
- **CI could hang for hours.** Jobs now have a 25 minute timeout, tests run verbosely, and a test stuck for 4 minutes
  dumps every thread's stack, so a hang fails with a diagnosis.
- **Bursts of concurrent writers lost events.** The signer's accept queue was Python's default of 5, so eight or more
  writers connecting at once got `EAGAIN` and, being fail-open, dropped events. The queue is 256 and the client retries
  a full-queue connect. Found by the new E2 evaluation; covered by `BurstOfWriters`.
- **A write to a path containing a NUL byte was not flagged on some Python and OS combinations.** The
  out-of-scope check relied on `realpath` raising; it now treats an embedded NUL as out of scope explicitly.
- **Tests assumed Linux.** Approvals used GNU `script -c` and `SO_PEERCRED`; they now use a stdlib `pty` helper
  and `peercred.has_peer_credentials()`. The full suite passes natively on macOS 26 (arm64, Python 3.9.6).
- **A retrying client could flood the ledger with `error` events** (47,947 records from one invalid event).
  Rejections are now recorded for the first 10 repeats per run and message, then once per power of ten.
- **Trusted-key files whose raw 32-byte key began or ended with a whitespace byte were mis-stripped**
  and rejected (a roughly 5% flaky failure). Raw keys are no longer stripped.
- **TK-D004 (`rm -rf /`) had super-linear regex behaviour** on adversarial input; it is rewritten linearly.
- **`tracekit init` crashed on a normal install.** `_hook_command()` built its command inside the
  `except` branch, so `tracekit init --dev` raised `UnboundLocalError` and wrote no hooks.
- **The observer replay showed `CHAIN ✗ TAMPERED` for every v0.2 run.** The browser re-hashed the
  translated display records instead of the raw ledger records. Replays now embed the raw records and
  verify the real hash chain; a one-byte edit still turns the badge red.
- **Canonical JSON could differ between Python and the browser** (`2.0` vs `2`, key order for
  characters outside the BMP), which could make a valid bundle look broken in `replay.html`.
- **The verifier could crash on a malformed bundle.** It now reports a failed check instead, rejects
  duplicate zip members and zip bombs, flags files the manifest does not list, cross-checks the
  manifest range, and no longer lets the (unsigned) manifest narrow which runs get checked.
- **Git witness retries failed** with "nothing to commit" after a partial publish, and `git init -b`
  needs git 2.28+. Publishing is idempotent and works with older git.
- **A lone UTF-16 surrogate, `NaN` or deeply nested JSON in an agent's output** could make the signer
  drop the event or a redaction recurse without bound. Events are sanitised before signing.
- **The SDK could raise inside the agent** on sets, bytes, datetimes or `NaN` in tool arguments or
  results. Values are coerced; `Tracer` is now a context manager that always records `run.end`.
- **Hook** no longer crashes on a non-object `tool_input` or malformed transcript lines, creates its
  state directory if missing, and hashes the transcript in a stream instead of reading it twice into memory.
- **Policy** validation rejects non-numeric `checkpoint_every` / `approval_timeout_s` and non-boolean
  flags; evaluation no longer fails on odd inputs or a path containing a NUL byte.
- **Settings files**: Tracekit refuses to touch a Claude Code settings file it cannot parse, writes
  atomically, and makes no new backup when nothing changes.
- **Dev setup** is idempotent (re-running `init --dev` no longer kills a healthy signer), and a stale
  pidfile can no longer cause an unrelated process to be signalled.
- **`tracekit uninstall --project`** no longer stops the shared dev signer.
- **Observer server**: Host-header allow-list against DNS rebinding, constant-time token check,
  Content-Security-Policy and other security headers, cached verification, resilient ledger tail,
  friendly errors for a busy port or a missing ledger.
- **Observer UI**: no third-party font request (the replay is now fully offline), real error states and
  automatic retry in live mode, phone layout, `<noscript>` note.
- **CLI**: `--version`, clear one-line errors instead of tracebacks (`TRACEKIT_DEBUG=1` restores them),
  approval ids may be abbreviated to a unique prefix, bad numeric options are rejected, `export --run`
  and `--since` are honoured.
- **Signer** takes a final checkpoint on Ctrl-C as well as SIGTERM, and tightens a group- or
  world-readable key file.

### Added
- Claude Code plugin and marketplace manifest (`plugin/`, `.claude-plugin/`), with `/tracekit-status`, `/tracekit-verify`, `/tracekit-pending`.
- Adapters: `tracekit.adapters.traced` (any function) and `tracekit.adapters.langchain` (LangChain / LangGraph), `tracekit[langchain]` extra.
- Remote ingestion: `tracekit ingest token|serve`, `tracekit init --remote`; token-authenticated, TLS, rate-limited, events recorded as namespaced `sdk` runs.
- Rekor witness (experimental): RFC 6962 inclusion proofs, signed-entry-timestamp check against a pinned key, `rekord` entries.
- macOS: `LOCAL_PEERCRED` caller attestation, `ps`-based process checks, and an experimental launchd system mode (`--experimental-macos`). `docs/portability.md`.
- `docs/sample/` (a real bundle, a tampered copy, the key), `docs/evaluation.md`, design-partner kit, review packet, `paper/v0.2-update-draft.md`.
- Default policy: TK-D010 (shell writes to credential files) and TK-D011 (sending key and cloud-credential files), and wider TK-D002 (pipes to python/perl/ruby/node, download-then-run) and TK-D004 (quoted `$HOME`, split flags).
- `tracekit init --no-hooks` now also applies to system mode.
- `action.yml`: a composite GitHub Action that runs `tracekit verify` on a bundle.
- `Makefile` (`make check`, `make eval`, `make demo`), `CONTRIBUTING.md`, issue and PR templates,
  a tag-driven release workflow with PyPI trusted publishing (`docs/RELEASING.md`).

### Changed
- The v0.1 prototype was removed (root scripts, `legacy/`, its tests, demo script and sample output, and the
  v0.1 experiment code). `tracekit migrate` still converts v0.1 ledgers. `tracekit_sdk.Tracer` is now the
  v0.2 signed SDK only; the unauthenticated `endpoint=` ingest mode is gone. The duplicate root `schema/` was removed.
- E1 (integrity) and E3 (policy gate) evaluations were rewritten for v0.2; E2/E4/E5 and the paper figure
  generators were v0.1-only and were removed (the paper in `paper/` describes v0.1).
- Observer: the live feed is bounded (`TRACEKIT_OBSERVE_MAX_RECORDS`, default 50000); `/api/snapshot` now returns
  `{next, dropped, records}`.
- Policy: regexes with a repeat of a repeat are rejected at load; each match has a 0.5 s budget (a timeout counts as
  a match); subjects are matched in overlapping 16 KiB windows so padding cannot push a command out of view, and a subject over 256 KiB is treated as matching (fail safe). Default rules no longer deny `.env.example`-style files or the word
  `sudo` inside `grep`/`echo` arguments (E3 benign false positives 3/40 to 0/40).
- An unreachable OTLP collector no longer aborts `tracekit export --otel-endpoint`; the bundle is still written.
- Exports (`tracekit export`, `tracekit observe --export`) are written atomically.
- Version is single-sourced from `tracekit/__init__.py`; packaging metadata, classifiers and sdist
  manifest added; CI workflow added.
