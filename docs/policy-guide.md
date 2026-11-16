# Your own policy

The signer decides every tool call with a policy. The packs Tracekit ships cover the common cases; your own policy
adds the rules that are yours: a command your company never lets an agent run, a tool only your team uses. This page
takes one rule from a file to a running signer. Everything it uses is in the [reference](policy-v2.md).

## 1. Start from a pack

```yaml
version: '2026.11-acme-1'
description: Acme's agents
extends: packs/server.yaml
```

`extends` keeps the pack's rules and adds yours. Pick the pack for where your agents run: `server.yaml` for agents in
your product or on servers, `coding.yaml` for coding agents ([packs shipped](policy-v2.md#packs-shipped)). The path is
relative to your file: the container image and the Helm charts put the packs in `/etc/tracekit/packs`, so a policy at
`/etc/tracekit/policy.yaml` extends `packs/server.yaml` ([deploy](deploy.md)).

## 2. Write a rule

```yaml
ask:
  - id: ACME-A001
    class: shell
    pattern: '^terraform (apply|destroy)'
    reason: changing infrastructure from an agent session
    remedy: A person approves the held call, or runs it themselves.
```

A rule sits under `deny` (the call is blocked), `ask` (it is held until a person approves it) or `flag` (it runs and
the signed record marks it). When several rules match, the strictest wins. `class` says which tools the rule reads
(`shell`, `file`, `http`, `payment` and the rest: [classes and fields](policy-v2.md#classes-and-fields)); `pattern`
is matched against what the call does as the signer reads it ([patterns](policy-v2.md#patterns-the-re2-subset)), and
`unless` exempts the cases you name. The id is yours; the signer's own ids (`TK-HOLD`, `TK-SHELL-PARSE` and the others
in [decisions](policy-v2.md#decisions)) are refused.

## 3. Check it

```sh
tracekit policy lint acme.yaml       # every error at once
tracekit policy compile acme.yaml    # the canonical policy and its policy_hash
```

The `policy_hash` is what every decision made under this policy will carry, so a record always says which version of
your rules decided it. A signer refuses to start on a policy that doesn't lint.

## 4. Roll it out as `flag` first

Put a new rule under `flag`, run it for a few days, and watch what it marks in `tracekit view`: each decision shows its
verdict and the rule ids that matched. When it marks only what it should, move it to `ask` or `deny`.

Past calls can't be decided again under a new rule: a signed run keeps a commitment to each call's arguments, not the
arguments themselves. `tracekit policy backtest` replays detection (sequences, limits and `respond`) over past runs,
not new `deny`, `ask` or `flag` rules.

## 5. Run it

- **Agents on servers:** set `policy: /etc/tracekit/policy.yaml` in the signer's `signer.yaml` (Helm's
  `signer.policy`, the compose stack's `policy.yaml`); [deploy](deploy.md).
- **Coding agents on laptops:** system mode takes the file at install, root-owned so the agent can't change it:
  `tracekit init --v2 --user <agent user> --policy /etc/tracekit/policy.yaml` ([deploy](deploy.md)).
- **To try it on your machine:** `tracekit signer serve --config signer.yaml` with `policy:` set, then point a client
  or a hook at it with `TRACEKIT_SIGNER` (its socket path or URL). The dev signer that `tracekit up` starts always runs
  the built-in dev pack.

Restart the signer to load a change.

## 6. See it work

- `tracekit view` shows each call as it is decided: the verdict, the rule ids and the reason.
- A held call waits in the viewer's approvals. A person answers it there, with `tracekit approvals approve ID`, or
  from Slack ([approvals](approvals.md)); the agent's retry then runs.
- Every decision is signed with the `policy_hash`, so a run's bundle shows which policy decided each call, and
  `tracekit verify` checks it offline.
