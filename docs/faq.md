# FAQ and limits

Every known limit and trade-off, from all the docs, is listed in one place: [known limits](limits.md).

## What does a verified bundle prove?

That the records in it are the ones the signer signed: none edited, dropped, reordered or added after signing, all in
one chain covered by a checkpoint signed by the log key **you** pinned. The `Assurance` line says who else vouches for
that checkpoint (witnesses, Rekor, a monitor). [Reading a verify report](verdicts.md) explains every line.

## What can't Tracekit prove?

- **Intent.** A record says a call was made, not why.
- **That everything was recorded.** An action that crosses no capture layer (a subprocess the hook never sees, app
  code that skips the adapter, a call outside a gateway that isn't mandatory) leaves no record. The report lists which
  layers ran, the tier of each tool call, and the signed gaps; it never says "complete".
- **That what the agent reported is true.** In-process capture (tier T1: hooks, adapters, SDKs) proves what the agent
  process *reported*; out-of-process capture (T2: the [LLM gateway](gateway.md), a T2 executor) proves
  what crossed that boundary. Imported telemetry (T3, [OpenTelemetry](otel.md)) proves only that it was received.
- **That nothing was deleted, only that deletion shows.** Tracekit is tamper-*evident*, not tamper-proof.
- **Anything against the operator without outside help.** Whoever runs the signer can rewrite or fork its log with its
  own key. Detection needs a witness the operator doesn't control **and** a [monitor](monitor.md); prevention would need
  attested hardware (a TEE), which Tracekit doesn't claim.

Each limit is mapped to its attacker in the threat models: [laptop](threat-model-laptop.md),
[server](threat-model-server.md).

## What does same-user dev mode protect?

Nothing against the agent itself. The dev signer runs as your user, the same user as the agent, so an agent that can
run commands can read the signer's key, stop it, or rewrite its store and sign it again. The policy blocks the obvious
attempts (`TK-D007`) and every record is still signed and chained, so dev mode catches mistakes and accidents and
gives you real bundles to try the verifier on. Every dev bundle says so: `isolation: same-user`, and usually
`Assurance: dev` and `approvals: self`. Protection against the agent starts with
[system mode](deploy.md#laptop-system-mode) or a server signer.

## What does harness binding not stop?

Harness binding (`tracekit init --v2 --harness NAME=PATH`, Linux) makes the signer accept a run from the agent's uid
only from below the registered program's process tree. It stops a run started by some other program of the agent's
user. It does not stop:

- a process the agent starts **from inside** the harness session (its own shell tool): it is a descendant of the real
  harness;
- the agent's user starting **its own instance** of the registered harness, with its own code loaded into it: the
  harness runs as that user, who controls its environment;
- fabricated events sent from inside a live harness session (E8 doesn't cover these; only a cross-check against an
  out-of-process record, such as the LLM gateway, catches them);
- anything on macOS or Windows, where there is no binding.

What does: the harness under another user, or a mandatory gateway as an independent record (`gateway_mandatory`).
Details: [threat model: laptop](threat-model-laptop.md#two-properties-kept-apart).

## How much does it slow an agent down?

The only signer numbers committed in this repository are from `eval/e9_signer_perf.py --quick --storage postgres` on
macOS (12 CPUs, Python 3.11, Postgres store; `eval/results/e9_signer_perf_postgres.json`), measured through the real
Unix socket with the Python client:

| Measure | Result |
|---|---|
| decide + complete per tool call, ack-on-write, 1,000 calls | p50 0.59 ms, p99 5.17 ms, max 8.8 ms |
| decide + complete per tool call, ack-on-fsync, 200 calls | p50 0.66 ms, p99 0.86 ms |
| throughput, 4 client processes for 5 s, ack-on-write | 3,954 events/s |

The gates (p99 ≤ 5 ms added per tool call at ack-on-write, ≥ 1,000 events/s) are enforced on Linux only; on macOS,
and with `--quick`, the numbers are informational, and this run missed the latency gate. Run `make eval` on Linux
(it runs E9 `--quick`) or `eval/e9_signer_perf.py` for your own machine. Not measured: a separate-user signer, the
HTTPS transport, and throughput across hosts ([evaluation](evaluation.md#what-is-not-measured)).

## What happens when the signer is down?

Each tool class fails **closed** by default: the call is blocked. A class you set to `open` (`fail_modes:
{default: closed, read: open}` in signer.yaml) runs unrecorded, and the run's next call after the outage makes the
signer write a signed gap covering exactly the missed calls. The report lists every fail-open class. `eval/e14_outage.py`
checks each outage case ([evaluation](evaluation.md#e14-outage-behaviour)).

## Can old bundles still be verified?

Yes. Verifiers are frozen per format version and formats only grow: a v1 bundle verifies with `tracekit verify
--key`, a v2 bundle with `--trust`, and a v1 ledger bridged into a v2 log with `--v1-ledger` ([migration](migration.md)).

## Does my data leave the machine?

Only to the places you configure: witnesses get checkpoint notes (hashes and sizes), Rekor gets a hash of a note, a
remote signer gets what your agents send it. Arguments are hashed by default ([privacy](privacy.md)).

## Which platforms?

Dev mode on Linux, macOS and Windows; laptop system mode on Linux, experimental on macOS; containers and Kubernetes
on Linux ([platforms](portability.md), [deployment](deploy.md)).
