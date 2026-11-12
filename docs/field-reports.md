# Field reports

Every number Tracekit publishes so far comes from us: our own agents, our evals and our demos. A field report is a
week of your real use, as counts only, posted as a GitHub issue or a pull request. You use Tracekit as you always do
and share the counts; we read from them which shipped rules to change (a rule people approve nearly every time is a
false alarm). Each one is a measurement from outside our machines.

## Run Tracekit for a week

`--share` needs Tracekit 1.6.0 or later (`pip install -U tracekit-ai`).

```bash
tracekit init --dev --v2               # Claude Code's hooks and the dev signer; --agent codex, cursor, ...: coding-agents.md
# work as you always do, for a week
tracekit report --share --since 7d     # the week's counts, to post
```

[Coding agents](coding-agents.md) has the hooks for Codex, Cursor, Gemini CLI and the others, and the
[quickstart](quickstart-v2.md) has the SDKs and frameworks. `tracekit report --share` reads the dev signer's store as
`tracekit report` does ([weekly report](viewer.md#weekly-report)) and prints its counts alone:

```text
Tracekit 1.6.0 field report (tracekit report --share): 7 days
Integrity: the store verified, 31 of 31 runs verify
Runs that verify, by agent: claude-code 27, codex 2, other 2
Tool calls: 18,204   allow 15,733, flag 2,318, ask 61, deny 92
Holds: 58   expired 41, approved · ran 12, rejected 5   (3 of the agent's retries of a held call, counted with it)
Gaps (signed records that something may be missing): 14   witness_late 9, tailer_lost 3, run_abandoned 2
Denied and flagged calls, by rule (one call can match several rules):
  deny TK-D007 64
  deny TK-D002 19
  deny TK-SHELL-PARSE 2 (not placed)
  deny custom rule 4
  deny TK-F001 11 (also matched, not why)
  flag TK-F011 1,402
  flag TK-UNKNOWN-TOOL 377 (not placed)
  ...
Holds by rule: held, approved (by a person or the run's own user), rejected or expired:
  TK-A015 31, 4, 27
  TK-A001 22, 21, 1
  ...
```

(The numbers above are an example, not a measurement.) A rule marked `also matched, not why` is a rule of another
section that matched the call too; `not placed` is an engine check, or a rule of a policy the report can't read, which
may or may not be why ([weekly report](viewer.md#weekly-report)). The holds count a call held at once and the agent's
retry of it, which ran under its approval, as one hold, so the line says how many such asks it counted with their
held calls. `Holds by rule` reads the signed approval records: a hold counts as approved when its first answer
approved it, by a person or the run's own user (on a dev signer, every answer is the run's own user's), even if the
approval then expired unused; rejected or expired counts the holds never approved. A rule approved nearly every time
(TK-A001 above) is likely a false alarm, and one rejected or let expire is doing its job. It exits 1, as `tracekit report` does, when the store or a run fails to verify: post the report anyway.

## Without a hook: replay past transcripts

```bash
tracekit audit --share --since 7d      # Claude Code's and Gemini CLI's sessions (~/.claude/projects, ~/.gemini/tmp), replayed through the policy
```

[`tracekit audit`](audit.md) puts no hook in your agent's loop and starts no signer: it replays the tool calls in
Claude Code's and Gemini CLI's past sessions through today's dev policy pack and counts what it would have done. Its counts are a
replay, not a signed record, and a floor of what the signer would hold ([limits](limits.md#audit-tracekit-audit)).
`--share` prints the same kind of counts: the number of sessions, the calls by decision, and each rule by the decision
of the calls it matched, marked as `report --share` marks it.

## What is shared, and what isn't

| `--share` prints | It never prints |
|---|---|
| The Tracekit version, and the window's length in days (no date or time) | The store's or the transcripts' path, the policy file, the trust note, the tenant |
| Whether the store verifies, and how many runs do (`report`) | A run id, a session id, a user id or any identity |
| The runs that verify, by agent: Tracekit's own names, every other as `other` (`report`); the number of sessions (`audit`) | A tool's arguments, a command, a path or a URL it touched |
| Tool calls by decision: allow, flag, ask, deny | An example call, a rule's description, a hold's reason or who answered it |
| Holds by outcome: approved · ran, rejected, expired, ... (`report`) | What the model or the person said, a tool's result, a gap's reason |
| The gaps by kind: the signer's own kinds, any other as `other` (`report`) | An agent name that isn't Tracekit's own |
| Each rule with its decision and its count: Tracekit's own rule ids, every other as `custom rule` (`no rule` for a decision no rule named, `report`); each rule's holds, with how many were approved (by a person or the run's own user, as on a dev signer) and how many never approved were rejected or expired (`report`) | A rule id that isn't Tracekit's own; any record, hash or signature |

An agent name is printed only when it is one Tracekit's own hooks and tools give a run (`claude-code`, `codex`,
`cursor`, `gemini-cli`, `opencode`, `goose`, `qwen-code`, `droid`, `antigravity`, `crush`, `agentsh`,
`tracekit-why`). Any other is counted as `other`: an SDK or framework run is named by your code or after your script's
file (`tracekit.instrument()`), it can name a customer or a project, and an agent can register its run under any name
it likes. A rule id is printed only when it is one of the shipped packs', an engine check's or the signer's own; a rule
of a policy you wrote is counted as `custom rule`, all such rules together. `tracekit report --share`
says so on stderr. Read the block before you post it all the same; in the form, say in your own words what your
`other` agents and `custom rule` rules are, if you want to.

`report --share` reads no call's arguments from the dev signer's content vault, so it adds no `content.accessed`
record to your store.

## File a report

1. Run one of the commands above and read what it prints.
2. Open a [field report](https://github.com/Cygnux-Labs/Tracekit/issues/new?template=field-report.yml) and paste it.
3. Name the agent or framework and the kind of work. Anything else you'd like to tell us is optional.

`tracekit feedback` prints that form's link pre-filled
(your Tracekit, OS, Python, which agents' hooks are installed, and the week's `report --share` counts when the dev
signer has a store) and exactly what the link holds; it sends nothing, and `--open` opens it in your browser. For one
false alarm, `tracekit feedback --harmless <approval-id> [--why "one line"]` fills in the held call's rule ids, tool
name, policy hash and verdict, and your Tracekit, OS, Python and hook names, never its command, arguments or paths;
it prints all of it before anything is submitted (`tracekit approvals show` prints the line).
To send a report as a pull request instead, so it stays in the repository and you show as a contributor,
`tracekit feedback --file report.md` writes one to fill in
([docs/field-reports](https://github.com/Cygnux-Labs/Tracekit/tree/main/docs/field-reports) says where it goes).

A way an agent could get a call past the policy is a security problem: report it privately, as
[SECURITY.md](../SECURITY.md) says, not in a field report.

## Reports so far

None yet. Each report we receive is listed here with its issue, credited to its author as they want to be named.
