# Latent transfers and C2C

> **Experimental:** this works and is tested, but may change and gets less hardening than the [stable core](support.md).

C2C (Cache-to-Cache) can hand a model's internal state, such as a KV cache, to another model through a learned adapter. `run.transfer` records and gates that hand-off before it happens. It records the claimed sender, receiver, adapter and modality, plus a local size and SHA-256 measurement; it never sends the payload to the signer by default.

`run.transfer` records the transfer that [PCM 0.1](pcm.md)'s transfer-record extension describes; the `transfer` payload that would carry its evidence to the receiver is not built yet. Tracekit is the reference implementation.

## `run.transfer`

```python
from tracekit.sdk.client import Client

run = Client().run("pipeline")
out = run.transfer("qwen2.5-7b@<rev>", "llama-3.2-1b@<rev>", cache_bytes,
                   "kv-cache", projector="c2c-fuser@<rev>")
if not out["ok"]:
    raise RuntimeError(out.get("reason") or out["rule_ids"])
# only now hand cache_bytes to the receiver
```

It decides tool `a2a:transfer`. An ask waits up to five minutes; an unanswered request is abandoned. It fails closed if the signer is unavailable, regardless of run fail modes. If `ok` is true, `tool.result` was recorded before the method returned.

| Fields | Source |
|---|---|
| `sender`, `receiver`, `projector`, `modality` | Caller claims, listed under `claimed`. |
| `size`, `digest` | Caller-process measurements of the payload, listed under `measured`. |
| `measured=` fields | Further caller-process measurements. |

This is T1 evidence: the signer checks none of those claims or measurements, and cannot prove that measured bytes are what the receiver used. With `keep=True`, the hex payload is included in the result for an enabled encrypted content vault; records still hold commitments. A payload larger than about one quarter of a frame is recorded but not kept.

## Policy

The shipped packs map `a2a:transfer` to `a2a` through `coding.yaml`'s `a2a:*` mapping. With `coding.yaml` and `dev.yaml` no rule matches a transfer, so it is allowed and recorded. `server.yaml` and `strict.yaml` ask a person for every `a2a` call, transfers included (`TK-S011`), until a deployment replaces `TK-S011` with a rule scoped to its allowed triples, as the [A2A gateway](a2a.md#policy) page shows. Use the class fields described on the [A2A gateway](a2a.md#policy): `route` is `sender->receiver via projector`; `size`, `modality`, `projector` and `weights` are also available. Transfer names are lower-cased for `a2a` rules, and a non-printable-ASCII or space-containing name is denied as `TK-A2A-NAME`, with the fixed reason and remedy and without echoing the name.

```yaml
deny:
  - id: TRANSFER-TRIPLES
    class: a2a
    field: route
    pattern: '.'
    unless: '^qwen2\.5-7b@abc123->llama-3\.2-1b@def456 via c2c-fuser@0\.1$'
  - id: TRANSFER-WEIGHTS
    class: a2a
    field: weights
    pattern: '.'
    unless: '^sha256:<the weights hash you checked>$'
```

## C2C

`tracekit.integrations.c2c.fuse` measures a C2C cache, calls `run.transfer`, and runs the fuser only if allowed. A denial, unapproved ask or unavailable signer raises `Refused`; nothing is fused.

```python
from tracekit.integrations import c2c

cache = c2c.fuse(run, rosetta, sharer_cache, receiver_cache,
                 sender="qwen2.5-0.5b@<rev>", receiver="qwen3-0.6b@<rev>",
                 projector="c2c-fuser@<rev>")
```

`rosetta` is C2C's `RosettaModel`; caches are legacy `(key, value)` pairs per layer. For inference, call under `torch.no_grad()`. It measures the sharer's cache in layer/key/value order and records `weights` (the hash of canonical JSON of the used fusers' parameter dtype, shape and bytes hashes), `layers` (`[receiver layer, sharer layer, fuser index]`) and tensor `layout` (`[dtype, shape, bytes]`). C2C, torch and transformers are optional; without C2C, `fuse` raises an `ImportError` naming its repository.

## `tracekit why transfer`

For a `keep=True` transfer, `tracekit why transfer` reads the record and retained copy, checks their commitments and the copy's size and digest, then runs the supplied receiver with the transfer and with `None`.

```bash
TRACEKIT_SIGNER=... tracekit why transfer --run <run_id> --store <signer-data-dir> --receiver myapp.replay:answer
```

It rebuilds a C2C cache from `layout` where possible. The receiver is investigator-supplied code, runs unrecorded, and should be deterministic because each arm runs once. `change` is one minus `difflib`'s similarity ratio. `--bundle FILE --trust FILE` reads a verified bundle; `--transfer SEQ` chooses another completed transfer.

## Limits

- A transfer is recorded only when code calls `run.transfer` or `c2c.fuse`; a direct in-process hand-off is invisible.
- Transfer fields are caller claims or caller-process measurements as marked. The signer does not verify them beyond the `TK-A2A-NAME` spelling check.
- `keep=True` retains only payloads that fit; otherwise `tracekit why transfer` has no payload to compare.
- `c2c.fuse` hashes fuser weights on every call, copying tensors to CPU.
- The comparison runs each receiver arm once, so a nondeterministic receiver produces a noisy change.
- Transfers are Python-only while experimental; the TypeScript SDK has no `transfer` method.

See [limits](limits.md#custody-12).
