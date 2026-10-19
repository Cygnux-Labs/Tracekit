# Tetragon

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](../support.md).
> Linux only.

[Tetragon](https://github.com/cilium/tetragon) is an eBPF sensor: it sees, in the kernel, the processes a workload
starts, the connections it opens and the files it writes, and exports them as JSON lines. `tracekit sensor import`
reads that export and sends each event of an agent's process to the v2 signer, which signs it into the agent's run as
an `effect.observed` record. It works whatever sandbox the agent runs in, or none.

| | Tetragon | Tracekit |
|---|---|---|
| What it does | Sees processes, connections and file writes in the kernel, and exports them | Signs each one into the run of the agent that caused it, joined to the tool call when the process names one, and signs a gap for what Tetragon says it dropped |
| Where | A DaemonSet (or a host service) with eBPF programs in the kernel | The import next to Tetragon, the signer outside the agent |
| What a third party can check later | Nothing signed: an export file, rotated away | A signed, hash-chained bundle, verified offline |

Tracekit doesn't check or change what Tetragon sees: a record says what Tetragon exported, under the import's own
signer identity. The same import reads [Falco](falco.md)'s alerts.

## Setup

**1. Tetragon.** Export to a file, keep the agents' events and the throttle events, and, for [Codex](#tool-calls),
keep the one environment variable that names the tool call (Helm values):

```yaml
tetragon:
  exportAllowList: |-
    {"namespace":["agents"],"event_set":["PROCESS_EXEC","PROCESS_EXIT","PROCESS_KPROBE"]}
    {"event_set":["PROCESS_THROTTLE"]}
  extraArgs:
    enable-process-environment-variables: "true"
    filter-environment-variables: CODEX_TOOL_CALL_ID
```

The chart writes the export to `/var/log/tetragon/tetragon.log` on each node. Outside Kubernetes, the same flags are
`--export-filename`, `--export-allowlist`, `--enable-process-environment-variables` and
`--filter-environment-variables`. Field filters (`--field-filters`) must keep `process` with its `pod`,
`environment_variables`, and the kprobe `args`.

**2. A TracingPolicy** for connections and for writes outside the workspace. Exec and exit events need none: Tetragon
always sends them.

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  name: tracekit-agent-effects
  namespace: agents
spec:
  kprobes:
  - call: security_socket_connect     # every connect, after the kernel copied the address
    syscall: false
    args:
    - index: 1
      type: sockaddr
    selectors:
    - matchArgs:
      - index: 1
        operator: Family
        values: [AF_INET, AF_INET6]
  - call: security_file_permission    # every read and write path (write, sendfile, io_uring, ...)
    syscall: false
    args:
    - index: 0
      type: file
    - index: 1
      type: int
    selectors:
    - matchArgs:
      - index: 0
        operator: FileType
        values: [reg]                 # regular files: no pipes or sockets
      - index: 0
        operator: NotPrefix
        values: [/workspace/, /tmp/]  # the agent's own directories
      - index: 1
        operator: Mask
        values: ["2"]                 # MAY_WRITE
```

Three filters on one selector need a 5.3 or later kernel. Put your own workspace path in `NotPrefix`.

**3. The signer.** Give the import its own identity and the `observe_effect` grant, never a default, and keep it out
of every agent's hands:

```yaml
authorize: {"mtls:spiffe://acme.org/tracekit-sensor": [observe_effect]}
tenants: {"mtls:spiffe://acme.org/tracekit-sensor": acme}   # the tenant whose runs it covers
```

**4. The import**, on each node, next to Tetragon's export (`sensor.yaml`):

```yaml
sensor: tetragon
signer: https://signer.internal:8443   # its identity: TRACEKIT_SIGNER_TOKEN_FILE or _CERT/_KEY
runs:
  - match: {namespace: agents, pod: "coder-*"}            # globs over namespace, pod, container (id), uid
    caller: k8s_sa:system:serviceaccount:agents:coder      # the agent's signer identity
```

```sh
tracekit sensor import --config sensor.yaml --follow /var/log/tetragon/tetragon.log
kubectl logs -n kube-system ds/tetragon -c export-stdout -f | tracekit sensor import --config sensor.yaml
```

`--follow` reads from the file's end on and keeps reading across Tetragon's rotation. Without `--follow` it reads the
file once and exits; without a file, stdin.

## Attribution

The first `runs` entry whose `match` fits the event's process (its pod's namespace and name, its container id, its
uid) attributes it: the signer gives the event to the latest open run of that entry's `caller`
(`attribution: identity` in the record). An event of a process no entry matches is not an agent's: the import skips
it. An event of a matched process whose caller has no open run is a signed `capture.gap{effect_outside_run}` in the
tenant's signer run.

## What is recorded

One `effect.observed` per event, in the run (`source: signer`, format 1.4,
[format v2](../format-v2.md#3-events)):

| Tetragon event | `kind` | Fields |
|---|---|---|
| `process_exec` | `exec` | `binary`, `pid`, `exec_id`, `args_commitment` (the arguments, committed to, never stored) |
| `process_exit` | `exit` | `status`, `signal` |
| `process_kprobe` with a `sockaddr_arg` (`security_socket_connect`) or `sock_arg` (`tcp_connect`) | `connect` | `host` (the address), `port` |
| `process_kprobe` with a `file_arg` or `path_arg` | `file` | `path` |

Every record also has `observer` (the import's identity), `sensor: tetragon`, `ts` (Tetragon's time) and
`attribution`. Other events (other kprobes, tracepoints, LSM hooks) aren't recorded, nor are the `procFS` exec events
of processes already running when Tetragon started.

`run.final`'s coverage matrix says `processes observed (tetragon)` when the import covered the run throughout: it
was alive when the run registered, sent a heartbeat at least every 30 s, and reported no loss.

## Tool calls

Codex puts the id of the tool call that started a command into its environment as `CODEX_TOOL_CALL_ID`, the id Tracekit
records as the call's `tool_call_id` ([coding agents](../coding-agents.md)). With Tetragon keeping that variable
(step 1), each record of the command's processes carries it as `tool_call_id`, and `explained_by: call` when the run
decided that call and didn't deny it. The id is the agent's claim: the process can change or remove it. A record with
no `explained_by` is activity no decided call accounts for.

Claude Code puts no such id into the commands it runs, so its runs' records carry none.

## Losses

Tetragon numbers no events, so a missing one can't be seen from the stream. What it reports in the stream becomes a
signed gap:

- `rate_limit_info`: its export rate limit (`--export-rate-limit`) dropped that many events.
- `process_throttle` (`THROTTLE_START`): its cgroup rate limit (`--cgroup-rate`) stopped sending a cgroup's exec and
  exit events.

The import adds lines it can't read and an agent's events it can't record. It sends them to the signer as `lost`,
which writes a `capture.gap{observer_lost}` in each run the import covers (in the tenant's signer run when it covers
none) and ends its coverage of those runs: their matrix says processes not covered. An import that stops sending for
90 s, or restarts, is the same gap, as for the [egress observer](../egress.md#heartbeats-and-coverage).

Tetragon counts some drops only in its metrics (`--metrics-server`): `tetragon_observer_ringbuf_events_lost_total`,
`tetragon_observer_ringbuf_queue_events_lost_total`, `tetragon_events_export_failed_total`. Alert on them in your
monitoring: the import doesn't read them.

## What Tracekit sees and doesn't

- **Sees:** what Tetragon exported for the agents' processes, as Tetragon reported it, and the losses Tetragon reports
  in its export.
- **Doesn't see:** what Tetragon didn't export: events its policies didn't select, drops it counts only in metrics,
  events of a container that started before Tetragon applied a namespaced policy to it (without Tetragon's OCI runtime
  hooks, policies apply best effort), and anything before the import's first heartbeat.
- **Doesn't check:** that Tetragon's events are true. The records are the import's assertion of what Tetragon said; a
  root user on the node can change Tetragon, its export or the import.

[Limits](../limits.md#kernel-sensor-import) lists these with what to do. A bundle with these records needs verifier
1.4.0 or later.
