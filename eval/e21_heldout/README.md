# E21 — held-out policy evaluation corpus

A labelled corpus of agent tool calls for measuring how well Tracekit's policy
gate (allow / hold / deny, decided before a tool call runs) **generalises** to
inputs it was not built against.

## What it is

`corpus.jsonl` is a frozen, held-out set of tool calls, each labelled `harmful`
or `benign`. It is a *measurement instrument*, not a rule fixture: you score the
gate against it (recall on harmful, false-positive rate on benign) and read the
number as an estimate of generalisation.

- 852 items: 420 harmful, 432 benign.
- Harmful spans 14 categories (credential access, exfiltration, persistence,
  privilege escalation, defense evasion, supply chain, destructive, cloud,
  kubernetes, database, container escape, prompt-injection action, MCP misuse,
  obfuscation). Benign spans everyday dev and ops work plus deliberate hard
  negatives that *look* dangerous but are fine.
- About a third of harmful items (0.345) use one or more evasion techniques
  (quoting, case, whitespace, env prefixes, wrappers, absolute paths,
  abbreviations, alias binaries, encoding, interpreters, substitution, unicode).
- Shells and OSes vary: bash/zsh/sh phrasing and PowerShell where the tool is a
  shell, plus framework tool shapes (`sql_query`, `http_request`, `s3_put`,
  `send_email`, `kubectl`) and `mcp__server__tool` calls.

## Written blind to the rules

This corpus was authored **without reading the policy engine** — not
`tracekit/policy2/` or `tracekit/policy/`, the policy packs, the policy evals
(E3/E17), `docs/policy-v2.md`, or any rule ids or patterns. It reflects
independent threat knowledge (public detection-rule shapes, MITRE ATT&CK, the
OWASP Top 10 for LLM applications), so that a score against it reflects
generalisation rather than memorisation of the gate's own rules.

## Rules for using it

- **Never tune the gate on this corpus.** Do not read a failing item, then edit
  a rule to make that item pass. The moment the corpus informs a rule, it stops
  measuring generalisation and this file must be considered burned.
- **Do not edit items to change the score.** Fixing a genuine labelling mistake
  is fine and should be called out in the commit; everything else is tuning.
- **Grow by adding a new versioned file, never by editing this one.** New
  material goes in `corpus.v2.jsonl` (then `v3`, …) so each version stays a
  fixed, citable instrument and historical scores remain reproducible.

## Safety

Every payload is realistic in shape but harmless as data: hosts are only
`example.com` / `.org` / `.net` or TEST-NET ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24, and the link-local cloud-metadata IP);
credentials are obvious placeholders (`AKIAEXAMPLE…`); no real people,
companies, secrets or systems appear. Items use only well-known technique shapes
that public detection-rule sets already describe. Nothing here is a working
exploit, and nothing targets a real host.

## Schema

One JSON object per line:

| field | type | notes |
|---|---|---|
| `tool` | string | `Bash`/`bash`/`shell`/`terminal`/`Write`/`Edit`/`Read`/`WebFetch`, a framework tool (`sql_query`, `http_request`, `s3_put`, `send_email`, `kubectl`, …), or `mcp__<server>__<tool>` |
| `args` | object | the tool's natural arguments, e.g. `{"command": "…"}`, `{"file_path": "…", "content": "…"}`, `{"url": "…", "method": "POST", "body": "…"}`, `{"query": "…"}` |
| `label` | string | `harmful` or `benign` |
| `severity` | string | `critical`/`high`/`medium`/`low` — **harmful items only**; absent on benign |
| `technique` | string[] | MITRE ATT&CK ids where they apply (e.g. `T1552.005`); may be empty |
| `owasp` | string[] | OWASP Top 10 for LLM ids where they apply (e.g. `LLM06`); may be empty |
| `category` | string | one of the 14 harmful or 3 benign categories listed above |
| `evasion` | string[] | evasion tags; empty for plain items |
| `note` | string | short reason for the label |

Validate with any JSONL reader: every line parses, required fields are present,
`severity` appears iff `label == "harmful"`, and `category` matches the label's
side. (The scratch validator used to build this is not committed.)
