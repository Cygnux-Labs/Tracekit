# Falco

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).
> Linux only.

[Falco](https://github.com/falcosecurity/falco) watches system calls from the kernel and raises an alert when one
matches a rule. `tracekit sensor import` reads Falco's JSON alerts of the rules below and sends each one of an agent's
process to the v2 signer, which signs it into the agent's run as an `effect.observed` record, the same way it does
[Tetragon's](tetragon.md) events. It works whatever sandbox the agent runs in, or none.

| | Falco | Tracekit |
|---|---|---|
| What it does | Matches system calls against rules, and writes an alert for each match | Signs each alert of a `tracekit` rule into the run of the agent that caused it, joined to the tool call when the process names one, and signs a gap for the drops Falco reports |
| Where | A DaemonSet (or a host service) with its kernel driver | The import next to Falco, the signer outside the agent |
| What a third party can check later | Nothing signed: alerts in a file or another output | A signed, hash-chained bundle, verified offline |

## Setup

**1. Falco** (`/etc/falco/config.d/tracekit.yaml`): JSON alerts with their fields and tags, to a file, and every
drop reported:

```yaml
json_output: true
json_include_output_fields_property: true
json_include_tags_property: true
priority: debug                 # the drop alert is a debug-priority rule
file_output:
  enabled: true
  keep_alive: true
  filename: /var/log/falco/tracekit.json
syscall_event_drops:
  threshold: 0                  # any drop, not only above 10 % of a second's events
  actions: [log, alert]
  rate: 1                       # a report every second a drop happens, not one every 30 s
  max_burst: 10
```

Or `program_output` with `keep_alive: true` and `program: tracekit sensor import --config /etc/tracekit/sensor.yaml`,
which reads stdin. Container and Kubernetes fields come from Falco's container plugin (on in its Linux packages).

**2. Rules** (`/etc/falco/rules.d/tracekit.yaml`). The import records only alerts of rules tagged `tracekit`, from the
fields their output names, so each rule's output names all of them:

```yaml
- macro: tracekit_agent
  condition: k8s.ns.name = agents          # your agents: a namespace, a container name, a uid

- rule: Tracekit agent exec
  desc: A program an agent started
  condition: evt.type in (execve, execveat) and evt.dir = < and tracekit_agent
  output: >
    agent exec type=%evt.type pid=%proc.pid exe=%proc.exepath cmdline=%proc.cmdline uid=%user.uid
    container=%container.id ns=%k8s.ns.name pod=%k8s.pod.name call=%proc.env[CODEX_TOOL_CALL_ID]
  priority: INFORMATIONAL
  tags: [tracekit]

- rule: Tracekit agent connect
  desc: An agent opened a network connection
  condition: evt.type = connect and evt.dir = < and fd.type in (ipv4, ipv6) and tracekit_agent
  output: >
    agent connect type=%evt.type pid=%proc.pid exe=%proc.exepath to=%fd.sip port=%fd.sport uid=%user.uid
    container=%container.id ns=%k8s.ns.name pod=%k8s.pod.name call=%proc.env[CODEX_TOOL_CALL_ID]
  priority: INFORMATIONAL
  tags: [tracekit]

- rule: Tracekit agent write outside the workspace
  desc: An agent opened a file outside its workspace for writing
  condition: >
    evt.type in (open, openat, openat2) and evt.dir = < and evt.is_open_write = true and fd.type = file
    and not fd.name startswith /workspace/ and not fd.name startswith /tmp/ and tracekit_agent
  output: >
    agent write type=%evt.type pid=%proc.pid exe=%proc.exepath file=%fd.name uid=%user.uid
    container=%container.id ns=%k8s.ns.name pod=%k8s.pod.name call=%proc.env[CODEX_TOOL_CALL_ID]
  priority: INFORMATIONAL
  tags: [tracekit]
```

Put your own workspace path in the third rule.

**3. The signer** gives the import its own identity and the `observe_effect` grant, as for
[Tetragon](tetragon.md#setup).

**4. The import**, on each node (`sensor.yaml`):

```yaml
sensor: falco
signer: https://signer.internal:8443
runs:
  - match: {namespace: agents, pod: "coder-*"}            # globs over namespace, pod, container (id), uid
    caller: k8s_sa:system:serviceaccount:agents:coder
```

```sh
tracekit sensor import --config sensor.yaml --follow /var/log/falco/tracekit.json
```

Falco's `container.id` is the short (12 character) id.

## What is recorded

One `effect.observed` per alert of a `tracekit` rule (`sensor: falco`, format 1.4,
[format v2](../format-v2.md#3-events)), attributed as for [Tetragon](tetragon.md#attribution):

| `evt.type` | `kind` | Fields |
|---|---|---|
| `execve`, `execveat` | `exec` | `binary` (`proc.exepath`), `pid`, `args_commitment` (`proc.cmdline`, committed to, never stored) |
| `connect` | `connect` | `host` (`fd.sip`), `port` (`fd.sport`) |
| `open`, `openat`, `openat2` | `file` | `path` (`fd.name`) |

Falco has no exit events in these rules, and no process id across executions (no `exec_id`). Alerts of other rules
aren't recorded. `proc.env[CODEX_TOOL_CALL_ID]` joins a record to the Codex tool call that started it
([Tetragon](tetragon.md#tool-calls) says how, and what the join is worth).

`tracekit analyze --v2` checks the records against the run's calls as for
[Tetragon](tetragon.md#checking-effects-against-calls) (TK-X206, TK-X207), with one difference: Falco names no parent
process, so a process a call left running and what it starts after that call's window are TK-X206 findings, and a
process's connections and writes are joined to it by `pid` and time.

## Losses

Falco numbers no alerts. It reports drops between its kernel driver and itself as the alert
`Falco internal: syscall event drop`, with that second's counts (`n_drops`, `n_evts`): the import sends it as `lost`,
a signed `capture.gap{observer_lost}` in each run it covers, which ends that coverage
([Tetragon](tetragon.md#losses) says how). With Falco's defaults it reports a second only when more than 10 % of its
events were dropped, and at most one second in 30: the settings above report every second with a drop. Alerts Falco
drops from a full output queue (`outputs_queue.capacity`) show only in its log and its metric
`falcosecurity_falco_outputs_queue_num_drops_total`: alert on it in your monitoring.

## What Tracekit sees and doesn't

- **Sees:** the alerts of the `tracekit` rules for the agents' processes, as Falco wrote them, and the drops Falco
  reports.
- **Doesn't see:** system calls the rules don't match, alerts with a field the rule's output doesn't name (the import
  can't attribute them, so they're skipped, or counted as lost when the process is an agent's but the effect can't be
  built), and anything before the import's first heartbeat.
- **Doesn't check:** that Falco's alerts are true. The records are the import's assertion of what Falco said, and a
  root user on the node can change Falco, its output or the import.

[Limits](../limits.md#kernel-sensor-import) lists these with what to do. A bundle with these records needs verifier
1.4.0 or later.
