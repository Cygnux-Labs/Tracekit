# Policy reference (v2 signer)

The v2 signer decides every tool call itself, over the raw arguments, with its own policy (`tracekit/policy2/`). The
agent can't change the policy or the tool's class: a class the adapter declares is a hint, and the class the policy
maps the tool to wins. The v1 daemon's regex engine is a different one ([README](../README.md#policy-and-approvals)).

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
`decision_id` and the `args_commitment`.

Rule ids the signer adds itself:

| Id | Verdict | When |
|---|---|---|
| `TK-ARGS-INVALID` | deny | the raw arguments are not strict JSON ([format v2](format-v2.md#1-canonical-json)) |
| `TK-OVERSIZE` | the rule's section | a rule's subject is over 64 KiB of UTF-8; it is never cut or windowed, and the rule's own section decides (a flag rule flags, a deny rule denies; a shell command over 64 KiB denies) |
| `TK-SHELL-PARSE` | ask | a shell command can't be parsed, or what it runs can't be read from the line |
| `TK-SQL-PARSE` | ask | no SQL dialect can read the statement (an unclosed literal or comment), or it is not text |
| `TK-UNKNOWN-TOOL` | `unknown_tools` | the tool maps to no class and `unknown_tools` is `flag`, `ask` or `deny` |

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
tools:                          # tool name or glob (fnmatch) -> class
  Bash: shell
  'mcp__*': mcp
  transfer_funds: payment
deny:  [<rule>, ...]
ask:   [<rule>, ...]
flag:  [<rule>, ...]
```

`extends` merges the parent's `tools` under the child's, keeps the parent's other top-level keys unless the child sets
them, and keeps the parent's rules except those whose id the child redefines. A list of parents is merged in order (a
later parent's top-level keys and tools win; the same rule id in two parents is a duplicate-id error), and the compiled
`extends` is the list of their hashes. An absolute path, `~` or a loop is an error.

**Rule fields:**

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | unique across the policy |
| `pattern` | yes | RE2-subset regex, searched for in the subject (unanchored unless it uses `^`/`$`) |
| `class` | no | the rule applies only to tools of this class; without it, to every tool |
| `tool` | no | regex that must match the whole tool name |
| `field` | no | which subject to match (below) |
| `unless` | no | regex; a subject that matches it is exempt |
| `reason`, `rationale`, `label` | no | text; `reason` is shown with the decision, `label` names a flag's category |
| `approval` | no | on an `ask` rule only: `executor: t1` (default) or `t2` ([approvals](approvals.md#tiers-t1-and-t2-executors)), and/or `passkey: required` ([approvals](approvals.md#web-approvals-and-passkeys)) |

Lint also rejects unknown keys, a `field` the rule's class doesn't have, and a class rule no tool maps to ("can never
fire").

`policy_hash` is `sha256:` of the compiled policy as sorted-key, compact JSON (`policy2.compile.canonical`).

## Classes and fields

The signer maps the tool to a class (`tools`: exact name first, then the most specific matching glob, the one with
the most characters other than `*` and `?`, so `mcp:postgres/*` wins over `mcp:*/*`; else `unknown`) and extracts the
class's fields from the raw arguments (`policy2/classes.py`):

| Class | Fields | Taken from |
|---|---|---|
| `shell` | `command`, `argv`, `line` | `command`, `cmd` or `commands` (one of them: a string, or a list of strings) |
| `fs` | `path`, `op`, `content_digest` | `file_path`, `notebook_path`, `path`; op from the tool (Write, Edit, Read…) or `op` |
| `http` | `method`, `url`, `host`, `internal` | `url`, `method` (default GET); `host` and `internal` as below |
| `sql` | `statement`, `code`, `verb`, `db` | `sql`, `query` or `statement`; `db` or `database`; `code` as below, `verb` its first word |
| `payment` | `amount`, `currency`, `payee`, `new_payee` | `amount`/`amount_cents`, `currency`, `payee`/`to`/`recipient` (`new_payee` is not extracted yet) |
| `email` | `to`, `domains`, `attachments` | `to` (string or list), `attachments` |
| `mcp` | `server`, `tool`, `args` | the tool name (`mcp__server__tool` or `mcp:server/tool`) and the arguments |
| `browser` | `action`, `url`, `scheme`, `host`, `internal` | `action`, `url`; `scheme`, `host` and `internal` as below |
| `unknown` | — | — |

Every class also has `target`: what the call acts on rather than what it carries (below).

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
| `class: shell`, no `field` or `field: argv` | each simple command the line runs, as its argv joined by spaces, argv[0] a basename |
| `class: shell`, `field: command` | the raw command line |
| `class: shell`, `field: line` | the raw command line and each line the parser normalised (quotes and escapes resolved, redirections kept) |
| `class: fs`, `field: path` | the normalised path, and with a `..` also the lexically normalised one; each also casefolded |
| `class: sql`, `field: code` | each dialect's reading of the statement (`code` above) |
| `field: target` (any class, or no class) | shell: each command's argv without its data words (a `git commit`/`tag`/`merge` message, the pattern `grep`, `rg` or `git grep` searches for), its redirection targets and `VAR=` assignments, and a program an interpreter reads from a heredoc or herestring (a command it can't parse: the raw command); fs: the paths; http and browser: the URL; email: the attachments; mcp and unknown tools: the whole arguments. Each URL in a target is also matched as `scheme://canonical-host/` |
| another class field | the extracted field |
| a `field` that is no class field | the raw argument of that name |
| no `field` (not shell) | the whole arguments as compact sorted JSON (so Write content, WebFetch URLs and MCP arguments are scanned) |

A rule fires when its pattern matches any of its subjects and `unless` does not match that subject. Use `unless` only
where the subject is one target (a file path): in a whole command line it could exempt a different target. `target`
is a class field in every class, so a rule can't name a raw argument called `target`.

**Shell parsing** (`policy2/shell.py`, its own tokenizer): quotes, escapes, `;` `|` `|&` `&&` `||` `&`, newlines,
`$()`, backticks, `<()`, heredocs, `VAR=` prefixes and wrappers (`sudo`, `env`, `nohup`, `timeout`, `xargs`, `nice`,
`exec`, `command`, `taskset`, `chrt`, `unbuffer`, `fakeroot`, `dbus-run-session`, …) are resolved, and the parser
follows what a shell or interpreter runs: `bash -c`, a heredoc into a shell, `eval`, `ssh host '…'`, `find -exec`,
`watch` and `parallel`, `python -c` / `node -e` / `perl -e` / `ruby -e` / `php -r` / `lua -e` (also with the code
attached to its flag, or a program from a heredoc or herestring), `awk` programs and sed's `e` command. Variables are
not expanded and encodings are not decoded: those stay tripwire territory. A command it cannot parse, or one that is
opaque, asks (`TK-SHELL-PARSE`): a glob or an expansion in a command name (`$x id`; a `$VAR/` directory in front of a
literal name is fine), a shell or interpreter reading its program from a pipe or file, `xargs -I` putting its input
into a script or command name, sed's `s///e`.

**Paths:** a `\` is a `/` and `C:/…` is absolute (the agent may run on Windows). An absolute path without `..` is
normalised. A relative path, or one with a `..` a symlink could redirect, is unverifiable, so the rule matches its
certain suffix (after the last `..`) and, with `..`, also the lexical normalisation. Every form is also matched
casefolded, because the agent's file system may ignore case (macOS, Windows) whatever the signer's does: write path
rules in lower case, or with both cases of a letter (`[Ll]ibrary`).

## Patterns: the RE2 subset

Patterns must mean the same to RE2 (`google-re2`, used when installed) and to the `regex` module in ASCII mode
(the fallback), so a decision does not depend on the engine. `tracekit policy lint` rejects:

- lookaround, backreferences, atomic groups, possessive repeats, `\Z`;
- groups other than `(?:` and `(?P<name>`, so no inline flags or comments;
- nested sets and `[: :]` classes; a letter or digit escape other than `\d \D \w \W \s \S \b \B \A \n \t \r \f \v
  \xHH` (inside a set: `\d \D \w \W \s \n \t \r \f \v \xHH`), and non-ASCII escapes (escaped ASCII punctuation is fine);
- a literal `{` that isn't escaped, a repeat without a lower bound, repeat counts above 1000;
- super-linear shapes (nested repeats).

`$` means end of text and `\s` excludes `\v`, as in RE2. The fallback engine backtracks, so a large subject can be
slow where RE2 is linear: all matches of one decision share 1 s, and when it runs out the decision denies with the rule
that was matching, leaves the remaining rules out and is marked `nondeterministic: true`. RE2 never times out, so on
such a subject the two engines can decide differently; install `google-re2` on the signer.

## Packs shipped

| Pack | For | Contents |
|---|---|---|
| `coding.yaml` | coding agents on a laptop | shell, file and harness self-protection rules; `unknown_tools: flag`; maps the shell, file, web and MCP tools of Claude Code, Codex, Cursor, Gemini CLI, OpenAI Agents and LangChain |
| `dev.yaml` | the signer's default | `coding.yaml` plus `TK-DEMO-DENY` (denies the tool `tracekit_demo_denied`, so a deny is easy to see) |
| `browser.yaml` | browser agents (Browser Use) | local file and internal-network navigation (addresses and names) denied; uploads and typing outside an allowlist ask |
| `server.yaml` | server-hosted agents | `extends: [coding, browser, server-data, server-net, server-cloud, server-comms]` plus rules for every tool; `unknown_tools: ask`: an unmapped tool waits for a person |
| `server-data.yaml` | SQL tools | destructive and privilege-changing SQL, SQL that reaches the server's shell or files |
| `server-net.yaml` | HTTP tools | internal addresses; a body sent outside the egress allowlist |
| `server-cloud.yaml` | cloud CLIs and cloud MCP tools | IAM and access changes denied; resource deletion asks |
| `server-comms.yaml` | payments, email, chat | moving money, mass email and whole-channel notifications ask |

`coding.yaml` rules (see the file for patterns and rationales):

| Section | Rules |
|---|---|
| deny | `TK-D001` privilege escalation · `TK-D002` running a downloaded script · `TK-D003` force push · `TK-D004` recursive delete of root or home · `TK-D010` writing a credentials file from the shell · `TK-D011` sending credential files off the machine · `TK-D006` uploading a secrets file · `TK-D008` modifying the harness's transcripts · `TK-D005` writing a credentials file · `TK-D009` writing the harness's transcripts · `TK-D007` touching Tracekit's own files or signer · `TK-D013` writing Tracekit's files, signer state or policy |
| flag | `TK-F001` network commands · `TK-F002` web requests · `TK-F003` destructive commands · `TK-F004` side effects (push, publish, install, apply) · `TK-F005` secrets access · `TK-F006` MCP tools · `TK-F007` / `TK-F008` background processes · `TK-F009` harness config · `TK-F010` shell function or alias shadowing · `TK-F011` environment tampering |

A deployment extends `server.yaml` (or composes only the packs it needs), maps its own tool names under `tools`, and
redefines a rule by id to change it: TK-N002's egress allowlist and TK-B011's typing allowlist name `example.com` until
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
| `server-cloud.yaml` | ask | `TK-C010` deleting cloud resources (instances, databases, buckets, clusters, namespaces, stacks; terraform/pulumi destroy, helm uninstall) · `TK-C011` an MCP tool whose name says it deletes |
| `server-comms.yaml` | ask | `TK-M001` a payment with an amount · `TK-M002` payouts, transfers, charges and refunds by tool name · `TK-M003` ten or more recipients, or a whole-company address · `TK-M004` @channel, @here or @everyone in Slack |

SQL keywords match `code`, outside comments, literals and quoted identifiers in every dialect, so
`SELECT 'DROP TABLE x'` is allowed. `eval/e17_policy_corpus.py`
runs `server.yaml` over the deny and benign corpora in `tests/data/policy/` with both engines and reports per-class deny
recall and the benign false-positive rate.

Rules match raw strings: they are tripwires that make attempts visible, not the protection itself. The protection is
the signer's isolation, its storage and the witnesses ([server threat model](threat-model-server.md)).
