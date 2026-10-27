"""Tracekit for C2C (Cache-to-Cache, github.com/thu-nics/C2C; docs/c2c.md), experimental: `fuse` records and gates one
sharer model's KV cache crossing into a receiver's through a C2C fuser, as a transfer (RunHandle.transfer), before the
fuser runs. A deny, an ask no one approved or the signer unreachable raises Refused, and nothing is fused.

    from tracekit.integrations import c2c
    cache = c2c.fuse(run, rosetta, sharer_cache, receiver_cache, sender="qwen2.5-0.5b@<rev>",
                     receiver="qwen3-0.6b@<rev>", projector="c2c-fuser@<rev>")

Tracekit only calls C2C's public API: a RosettaModel's layer map (`projector_dict`, which set_projector_config
fills) and its fusers (`projector_list`), each called through Projector.forward(source_kv, target_kv). It copies and
vendors none of C2C's code. C2C, torch and transformers stay optional: this module imports without them, and `fuse`
says what to install.

The transfer's record commits to the caller's claims, `sender` and `receiver` (model ids) and `projector` (the fuser's
id), and to what this code measured from the objects it was given: `size` and `digest` (sha256) of the sharer's cache
as sent (each layer's key, then its value, their bytes in that order), `weights` (the fuser's weights hash: the sha256
of the canonical JSON {projector index: {parameter name: [dtype, shape, sha256 of its bytes]}} of the projectors the
layer map uses), `layers` (that map: [receiver layer, sharer layer, projector index]) and `layout` (each tensor's
[dtype, shape, bytes]). The record lists these under `measured` and the claims under `claimed`. Measured means here,
in the caller's process (tier T1): the signer can't check it, nor that the bytes measured are the bytes fused. The
payload reaches the signer only with keep=True, for its content vault: `tracekit why transfer` then checks that copy
against the recorded size and digest and measures what it changed in the receiver's answer.
"""
import hashlib

from tracekit.format.canon import canonical
from tracekit.sdk.client import Refused, named_rules

try:
    from rosetta.model.wrapper import RosettaModel
except ImportError:   # C2C is optional: fuse says what to install
    RosettaModel = None

MODALITY = "kv-cache"


def fuse(run, model, source, target, *, sender, receiver, projector, source_idx=1, keep=False):
    """`target` (the receiver's KV cache: a list of (key, value) per layer, as Cache.to_legacy_cache() gives it) with
    `source` (the sharer's) fused in by `model`, a C2C RosettaModel whose base model is the receiver and whose
    model_list[source_idx] is the sharer. This happens only once `run` (a RunHandle) allows the transfer, else it
    raises Refused. `sender`, `receiver` and `projector` are ids with their versions, the caller's claims. `keep`:
    also keep the sharer's cache, encrypted in the signer's content vault, for `tracekit why transfer`. Call it under
    torch.no_grad() for inference."""
    if RosettaModel is None:
        raise ImportError("tracekit.integrations.c2c needs C2C: install it from https://github.com/thu-nics/C2C "
                          "(it brings torch and transformers)")
    if not isinstance(model, RosettaModel):
        raise TypeError(f"fuse takes a C2C RosettaModel, not {type(model).__name__}")
    layers = layer_map(model, source_idx)
    tensors = [_raw(t) for kv in source for t in kv]
    out = run.transfer(sender, receiver, b"".join(raw for *_, raw in tensors), MODALITY, projector, keep=keep,
                       measured={"weights": weights(model, layers), "layers": layers,
                                 "layout": [[dtype, shape, len(raw)] for dtype, shape, raw in tensors]})
    if not out["ok"]:
        why = "; ".join(x for x in (named_rules(out["rule_ids"]), out.get("reason")) if x)
        raise Refused(f"Tracekit refused the transfer from {sender} to {receiver}: {why or out['decision']}")
    return fused(model, source, target, layers)


def layer_map(model, source_idx=1):
    """[[receiver layer, sharer layer, projector index]] of a RosettaModel, for model_list[source_idx] into its base
    model: the first pair set_projector_config gave each receiver layer, which C2C applies."""
    pairs = model.projector_dict.get(model.base_model_idx, {}).get(source_idx)
    if not pairs:
        raise ValueError(f"the model maps no layer of model_list[{source_idx}] into its base model: call "
                         "set_projector_config first")
    return sorted([int(t), int(p[0][0]), int(p[0][1])] for t, p in pairs.items())


def weights(model, layers):
    """The weights hash of the projectors `layers` uses (see the module docstring)."""
    # lean: hashes the fuser on every fuse (a copy to the CPU); cache it per model once fusing in a loop costs too much
    tree = {}
    for i in sorted({p for *_, p in layers}):
        tree[str(i)] = {}
        for name, t in model.projector_list[i].state_dict().items():
            dtype, shape, raw = _raw(t)
            tree[str(i)][name] = [dtype, shape, hashlib.sha256(raw).hexdigest()]
    return "sha256:" + hashlib.sha256(canonical(tree)).hexdigest()


def fused(model, source, target, layers):
    """`target` with `source` fused in at each [receiver layer, sharer layer, projector] of `layers` by C2C's fuse
    call, with no record: what a receiver re-runs `tracekit why transfer` with."""
    out = list(target)
    for t, s, p in layers:
        out[t] = tuple(model.projector_list[p].forward(tuple(source[s]), tuple(target[t])))
    return out


def unpack(data, layout):
    """The cache `fuse` sent, rebuilt from its bytes and its record's `layout`: a list of (key, value) per layer."""
    tensors, at = [], 0
    for dtype, shape, n in layout:
        tensors.append(_tensor(dtype, shape, data[at:at + n]))
        at += n
    if at != len(data) or len(tensors) % 2:
        raise ValueError(f"the layout names {at} bytes in {len(tensors)} tensors; the payload has {len(data)}")
    return list(zip(tensors[::2], tensors[1::2]))


def _raw(t):
    """(dtype, shape, bytes) of a tensor: a torch tensor's, else a buffer's (a numpy array, a memoryview)."""
    if hasattr(t, "detach"):
        import torch
        t = t.detach().cpu().contiguous()
        return str(t.dtype), list(t.shape), t.view(torch.uint8).numpy().tobytes()
    m = memoryview(t)
    return m.format, list(m.shape), m.tobytes()


def _tensor(dtype, shape, raw):
    if dtype.startswith("torch."):
        import torch
        return torch.frombuffer(bytearray(raw), dtype=torch.uint8).view(getattr(torch, dtype[6:])).reshape(shape)
    return memoryview(raw).cast(dtype, shape)
