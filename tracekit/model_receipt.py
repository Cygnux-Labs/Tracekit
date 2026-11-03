"""Model receipts: what a weights file a tool call wrote held, and `tracekit verify-model`, which checks a file against
one (docs/coding-agents.md#weights-files-a-call-wrote).

    tracekit verify-model OLD NEW --bundle B --run R --trust T

A receipt is a file's sha256 and size and, for `.safetensors` (an 8-byte little-endian header length, a JSON header
mapping each tensor's name to its dtype, shape and data_offsets, then the tensors' bytes), the sha256 of each tensor's
bytes, all read in one pass. `.gguf`, `.pt`, `.pth` and `.ckpt` get the file's hash only. A file that can't be read as
its format says, or is past MAX_BYTES, gets a reason in place of the hashes (`refused`).

The coding-agent hooks (tracekit.integrations.claude_code, which the other harnesses' hooks share) put the receipt of
each weights file a call wrote into the call's result, next to its digest (`model_receipts`, each `reported_by: hook`):
the hook is the agent's own process, so a receipt is its report, not something the signer saw. The signer commits to
the result as to any other, and the record holds only that commitment: verify-model reads the result back from the
signer's content vault (content_get, as `tracekit analyze --v2` does), each checked against its record's commitment
with the salt the vault returns, once the bundle verifies."""
import argparse
import hashlib
import os
import stat
import sys

from . import constraints
from .findings import WRITE_TOOLS
from .format.canon import canonical, loads_strict
from .policy2.classes import PATH_KEYS, SHELL_KEYS

WEIGHTS = (".safetensors", ".gguf", ".pt", ".pth", ".ckpt")
CHUNK = 1 << 20
MAX_HEADER = 100_000_000   # the safetensors library's own bound: it loads no file with a longer header
# lean: a file past 8 GiB gets no receipt (the Hugging Face Hub shards a model at 5 GB by default): hashing more could
# outlast the PostToolUse hook's 30 s timeout on a slow disk; raise it once the hook hashes off the call's path
MAX_BYTES = 8 << 30
MAX_TENSORS = 128 << 10   # bytes of a receipt's tensor hashes as canonical JSON: about 1,000 tensors
MAX_FILES = 4   # receipts in one call's result: with MAX_TENSORS, half the vault's default 1 MiB per record
ZERO = "sha256:" + "0" * 64


def receipts(tool, args, cwd):
    """The receipts of the weights files (WEIGHTS) call (`tool`, `args`) wrote, as constraints.facts reads what a call
    writes: a write tool's path, or a shell command's write targets (constraints.shell), relative ones against `cwd`.
    Each is marked `reported_by: hook`. A relative path is refused when the command changes directory or there is no
    `cwd`. At most MAX_FILES receipts, then one entry counting the files past them."""
    args, cwd, cd = args if isinstance(args, dict) else {}, cwd if isinstance(cwd, str) else "", False
    if tool in WRITE_TOOLS:
        paths = [next((args[k] for k in PATH_KEYS if isinstance(args.get(k), str)), "")]
    elif any(args.get(k) is not None for k in SHELL_KEYS):
        s = constraints.shell(args)
        paths, cd = s["paths"], s["cd"]
    else:
        return []
    paths = list(dict.fromkeys(p for p in paths if p.lower().endswith(WEIGHTS)))
    out = []
    for p in paths[:MAX_FILES]:
        full = os.path.expanduser(p)
        if not os.path.isabs(full) and (cd or not cwd):
            r = {"path": p, "refused": "a path relative to a directory the command changed to" if cd else
                 "a relative path, and the hook was given no working directory"}
        else:
            r = receipt(os.path.join(cwd, full))
        out.append(dict(r, reported_by="hook"))
    if len(paths) > MAX_FILES:
        out.append({"refused": f"{len(paths) - MAX_FILES} more weights file(s): a call's result holds at most "
                               f"{MAX_FILES} receipts", "reported_by": "hook"})
    return out


def receipt(path):
    """{"path", "size", "sha256"} of the file at `path`, with "tensors" ({name: sha256 of its bytes}) for a
    .safetensors file; {"path", "refused": why} for one that can't be read as its format says, or past MAX_BYTES."""
    try:   # O_NONBLOCK: a FIFO in its place must not block the hook
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    except OSError as e:
        return {"path": path, "refused": e.strerror or type(e).__name__}
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        return {"path": path, "refused": "not a regular file"}
    with os.fdopen(fd, "rb") as f:
        try:
            if st.st_size > MAX_BYTES:
                raise ValueError(f"{st.st_size} bytes, more than the {MAX_BYTES} a receipt reads")
            if path.lower().endswith(".safetensors"):
                return {"path": path, "size": st.st_size, **_safetensors(f, st.st_size)}
            whole = hashlib.sha256()
            _feed(f, st.st_size, whole)
            return {"path": path, "size": st.st_size, "sha256": "sha256:" + whole.hexdigest()}
        except (OSError, ValueError) as e:
            return {"path": path, "refused": str(e)}


def _safetensors(f, size):
    """{"sha256", "tensors"} of safetensors file `f` of `size` bytes, read once. ValueError for a file the format
    doesn't allow: each tensor's data_offsets ([begin, end), from the end of the header) must lie in the file, and the
    tensors, sorted by them, fill the data exactly, as the safetensors library requires."""
    head = f.read(8)
    if len(head) < 8:
        raise ValueError("shorter than a safetensors header length")
    n = int.from_bytes(head, "little")
    if n > MAX_HEADER:
        raise ValueError(f"a header of {n} bytes, more than the {MAX_HEADER} the safetensors library reads")
    if n > size - 8:
        raise ValueError(f"a header of {n} bytes, past the end of the file")
    raw = f.read(n)
    if len(raw) < n:
        raise ValueError("the file changed while it was read")
    try:
        header = loads_strict(raw)
    except ValueError as e:
        raise ValueError(f"the header is not strict JSON ({e})") from None
    if not isinstance(header, dict):
        raise ValueError("the header is not a JSON object")
    spans = []
    for name, t in header.items():
        if name == "__metadata__":
            continue
        o = t.get("data_offsets") if isinstance(t, dict) else None
        if not (isinstance(o, list) and len(o) == 2 and all(type(x) is int for x in o) and 0 <= o[0] <= o[1]):
            raise ValueError(f"tensor {name[:128]!r} has no data_offsets [begin, end]")
        spans.append((o[0], o[1], name))
    data, at = size - 8 - n, 0
    if any(end > data for _, end, _ in spans):
        raise ValueError("a tensor's data_offsets reach past the end of the file")
    for begin, end, _ in sorted(spans):
        if begin != at:
            raise ValueError(f"the tensors leave a gap or overlap at data byte {at}")
        at = end
    if at != data:
        raise ValueError(f"{data - at} bytes after the last tensor")
    if len(canonical({name: ZERO for _, _, name in spans})) > MAX_TENSORS:
        raise ValueError(f"{len(spans)} tensors: their hashes are more than the {MAX_TENSORS} bytes a receipt holds")
    whole, tensors = hashlib.sha256(head + raw), {}
    for begin, end, name in sorted(spans):
        h = hashlib.sha256()
        _feed(f, end - begin, whole, h)
        tensors[name] = "sha256:" + h.hexdigest()
    return {"sha256": "sha256:" + whole.hexdigest(), "tensors": tensors}


def _feed(f, n, *hashes):
    """Read the next `n` bytes of `f` into each of `hashes`, CHUNK at a time."""
    while n:
        b = f.read(min(CHUNK, n))
        if not b:
            raise ValueError("the file changed while it was read")
        for h in hashes:
            h.update(b)
        n -= len(b)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit verify-model", description="check model file NEW against the receipt "
                                 "a coding-agent hook recorded in a run when a call wrote it, and name the tensors "
                                 "that differ from OLD. The bundle is verified first; the receipt is read from the "
                                 "signer's content vault and checked against its record's commitment. Exit 0 only "
                                 "when all of that holds and NEW matches.")
    ap.add_argument("old", help="the model file before the run")
    ap.add_argument("new", help="the model file to check")
    ap.add_argument("--bundle", required=True, help="the run's v2 bundle (tracekit export --v2)")
    ap.add_argument("--run", required=True, help="the run's id")
    ap.add_argument("--trust", required=True, help="the trust config to verify the bundle against (as tracekit verify)")
    a = ap.parse_args(argv)
    from .sdk.client import Client, SignerUnavailable
    from .signer.rpc_schema import RPCError
    from .verify.v2 import _CONTROL
    from .why import import_v2
    from .why.signed import EvidenceAlert, vault_content

    def fail(why, code=1):
        print(f"tracekit verify-model: {why}", file=sys.stderr)
        return code

    def shown(text):   # recorded and file text, printed without control characters
        return _CONTROL.sub("", str(text))[:512]

    try:
        runs, _, code = import_v2.bundle_records(a.bundle, a.trust)
    except OSError as e:
        return fail(e)
    if code:
        return fail(f"{a.bundle} does not verify against {a.trust} (`tracekit verify` says why)")
    records = runs.get(a.run)
    if not records:
        return fail(f"{a.bundle} holds no run {a.run}")
    print(f"bundle: verified, run {a.run}")
    old, new = receipt(a.old), receipt(a.new)
    for r in (old, new):
        if "refused" in r:
            return fail(f"{r['path']}: {r['refused']}")
    results = {r["event"]["run_seq"]: r for r in records if r["event"]["type"] == "tool.result"}
    client, got, unopened, recorded = Client(), 0, 0, []
    try:
        for seq, content, opened in vault_content(client, list(results.values()), f"tracekit verify-model {a.run}"):
            got += 1
            result = content.get("result") if isinstance(content, dict) else None
            found = result.get("model_receipts") if isinstance(result, dict) else None
            if not isinstance(found, list):
                continue
            if not opened:   # redaction changed it: it opens no commitment
                unopened += 1
                continue
            recorded += [(seq, r) for r in found if isinstance(r, dict)]
    except (SignerUnavailable, OSError) as e:
        return fail(f"the signer can't be reached for the run's content ({e})")
    except RPCError as e:   # no vault, no content_read grant, or a run this signer doesn't hold
        return fail(f"the signer gave no content: {e}")
    except EvidenceAlert as e:
        return fail(f"EVIDENCE ALERT: {e}", 4)
    finally:
        client.close()
    if results and not got:
        return fail(f"the signer returned none of the run's {len(results)} tool results: their content isn't kept "
                    "(content.retain off, past its retention, or erased)")
    if got < len(results):
        print(f"content: {len(results) - got} of the run's {len(results)} tool results not kept by the signer")
    if unopened:
        print(f"content: {unopened} tool result(s) with receipts changed by redaction, so not checked and not used")
    seq, rec = next(((s, r) for s, r in recorded if r.get("sha256") == new["sha256"]), (None, None))
    same = rec is not None and all(rec.get(k) == new.get(k) for k in ("size", "sha256", "tensors"))
    if rec is None:
        print(f"NEW {shown(a.new)}: {new['sha256']} matches none of the {len(recorded)} receipt(s) in the run")
    else:
        print(f"receipt: {shown(rec.get('path'))}, written by tool call "
              f"{shown(results[seq]['event']['data']['tool_use_id'])} (run_seq {seq}), reported by the "
              f"{shown(rec.get('reported_by'))}")
        print(f"NEW {shown(a.new)}: {'matches' if same else 'does NOT match'} the recorded receipt ({new['sha256']})")
    if "tensors" in old and "tensors" in new:
        o, n = old["tensors"], new["tensors"]
        diff = [("changed", k) for k in sorted(o.keys() & n.keys()) if o[k] != n[k]] + \
            [("added", k) for k in sorted(n.keys() - o.keys())] + [("removed", k) for k in sorted(o.keys() - n.keys())]
        print(f"OLD -> NEW: {len(diff)} of {len(o.keys() | n.keys())} tensors differ")
        for what, k in diff:
            print(f"  {what}: {shown(k)}")
    else:
        print(f"OLD -> NEW: the file {'is the same' if old['sha256'] == new['sha256'] else 'differs'} (no tensor "
              "hashes for this format)")
    return 0 if same else 1
