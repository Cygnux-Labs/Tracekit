"""Model receipts: what a weights file a tool call wrote held, and `tracekit verify-model`, which checks a file against
one (docs/coding-agents.md#weights-files-a-call-wrote).

    tracekit verify-model OLD NEW --bundle B --run R --trust T

A receipt is a file's sha256 and size and, for `.safetensors` (an 8-byte little-endian header length, a JSON header
mapping each tensor's name to its dtype, shape and data_offsets, then the tensors' bytes), a sha256 of each tensor (its
dtype and shape, then its bytes) and one of the header's `__metadata__`, all read in one pass. `.gguf`, `.pt`, `.pth`
and `.ckpt` get the file's hash only. A file that can't be read as its format says, is past MAX_BYTES, or isn't read
before the hook's deadline gets a reason in place of the hashes (`refused`).

The coding-agent hooks (tracekit.integrations.claude_code, which the other harnesses' hooks share) put the receipt of
each weights file a call wrote into the call's result, next to its digest (`model_receipts`, each `reported_by: hook`):
the hook is the agent's own process, so a receipt is its report, not something the signer saw. The signer commits to
the result as to any other, and the record holds only that commitment: verify-model reads the result back from the
signer's content vault (content_get, as `tracekit analyze --v2` does), each checked against its record's commitment
with the salt the vault returns, once the bundle verifies."""
import argparse
import hashlib
import math
import os
import stat
import sys
import time

from . import constraints
from .format.canon import canonical, loads_strict
from .policy2.classes import PATH_KEYS

WEIGHTS = (".safetensors", ".gguf", ".pt", ".pth", ".ckpt")
# the tools the hook receipts, by the names every harness's hook gives them (agent_hooks.tool): only their results
# carry the hook's model_receipts, and verify-model counts a receipt only in one of theirs
WRITERS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
TOOLS = (*WRITERS, "Bash")
CHUNK = 1 << 20
# lean: a file past 8 GiB gets no receipt (the Hugging Face Hub shards a model at 5 GB by default); raise it once the
# hook hashes off the call's path
MAX_BYTES = 8 << 30
# lean: the hook hashes for at most 10 s per call, well inside the PostToolUse hook's 30 s timeout, and refuses the
# receipts it hadn't finished (out of time); one read that blocks (a hung network file system) can still outlast it
BUDGET_S = 10.0
MAX_TENSORS = 96 << 10   # bytes of a receipt's tensor hashes as canonical JSON: about 800 tensors
# a header past this holds more tensors than a receipt takes (a tensor's entry is under twice its hash's), or more
# than 256 KiB of metadata: refused before it is read
MAX_HEADER = 2 * MAX_TENSORS + (256 << 10)
MAX_TEXT = 4096   # characters of a path or a reason a receipt records (Linux's PATH_MAX)
MAX_FILES = 4   # receipts in one call's result: with MAX_TENSORS and MAX_TEXT, under half a frame (sdk sendable)
ZERO = "sha256:" + "0" * 64
# a call's receipts when they would take its result past the half frame a result may use (claude_code._post)
TOO_LARGE = {"refused": "the receipts would take the call's result past the half frame a result may use",
             "reported_by": "hook"}


def receipts(tool, args, cwd, later=False):
    """The receipts of the weights files (WEIGHTS) call (`tool`, `args`) of one of TOOLS wrote: a write tool's path, or
    a Bash command's write targets (constraints.shell), relative ones against `cwd`. `later`: the harness's hook says
    the call's effect comes after its post-tool hook (agent_hooks.LATER).
    Each is marked `reported_by: hook`, its path and reason JSON-safe (a lone surrogate escaped) and cut to MAX_TEXT.
    Refused rather than guessed: what _named refuses, and a relative path when there is no `cwd`. At most MAX_FILES
    receipts, then one entry counting the files past them, all hashed within BUDGET_S. Never raises: any other error
    is a refusal too, so the call's result is still sent."""
    try:
        out = _receipts(tool, args, cwd, later)
    except Exception as e:   # the receipts ride on the call's result, which goes to the signer whatever happens here
        out = [{"refused": f"the hook could not read the call's weights files ({type(e).__name__})"}]
    return [{**r, **{k: _text(r[k]) for k in ("path", "refused") if k in r}, "reported_by": "hook"} for r in out]


def _named(tool, args, later=False):
    """[(path, why the hook can't place it, or None)] of the weights files call (`tool`, `args`) of one of TOOLS
    writes, as it names them: a write tool's path, or a Bash command's write targets (constraints.shell); none for
    another tool. Refused rather than guessed: a path starting with `~`; every path of a call whose writes may land
    after the hook reads (`later`, run_in_background or Qwen Code's is_background, constraints.shell's `later`:
    systemd-run, at), or of a command line whose paths are elsewhere (constraints.shell's `elsewhere`: cp -t, git -C,
    env --chdir, chroot, ssh, ...); and a relative one when the command changes directory (`cd`: cd, pushd, popd, git
    --work-tree)."""
    args = args if isinstance(args, dict) else {}
    if tool in WRITERS:
        paths, s = [next((args[k] for k in PATH_KEYS if isinstance(args.get(k), str)), "")], {}
    elif tool == "Bash":
        s = constraints.shell(args)
        paths = s["paths"]
    else:
        return []
    later = later or s.get("later") or any(args.get(k) for k in ("run_in_background", "is_background"))
    return [(p, "a path starting with ~, which the hook doesn't expand" if p.startswith("~") else
             "the call's writes may land after the hook reads (a command left running, input typed into another "
             "session, systemd-run, at)" if later else
             "the command line's paths are in another directory, root or host (cp -t, git -C, env --chdir, chroot, "
             "ssh, ...)" if s.get("elsewhere") else "a path relative to a directory the command changed to"
             if s.get("cd") and not os.path.isabs(p) else None)
            for p in dict.fromkeys(p for p in paths if p.lower().endswith(WEIGHTS))]


def _receipts(tool, args, cwd, later):
    named = _named(tool, args, later)
    cwd, deadline, out = cwd if isinstance(cwd, str) else "", time.monotonic() + BUDGET_S, []
    for p, why in named[:MAX_FILES]:
        why = why or (None if os.path.isabs(p) or cwd else
                      "a relative path, and the hook was given no working directory")
        out.append({"path": p, "refused": why} if why else receipt(os.path.join(cwd, p), deadline))
    if len(named) > MAX_FILES:
        out.append({"refused": f"{len(named) - MAX_FILES} more weights file(s): a call's result holds at most "
                               f"{MAX_FILES} receipts"})
    return out


def _text(s):
    return s.encode("utf-8", "backslashreplace").decode("utf-8")[:MAX_TEXT]


def receipt(path, deadline=math.inf):
    """{"path", "size", "sha256"} of the file at `path`, with "tensors" ({name: sha256 of its dtype and shape as
    canonical JSON, then its bytes}) and "metadata" (sha256 of the header's `__metadata__` as canonical JSON) for a
    .safetensors file; {"path", "refused": why} for one that can't be read as its format says, past MAX_BYTES, or not
    read by `deadline` (time.monotonic())."""
    try:   # O_NONBLOCK: a FIFO in its place must not block the hook
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    except (OSError, ValueError) as e:   # ValueError: a NUL in the path, or a lone surrogate it can't encode
        return {"path": path, "refused": getattr(e, "strerror", None) or str(e)}
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        return {"path": path, "refused": "not a regular file"}
    with os.fdopen(fd, "rb") as f:
        try:
            if st.st_size > MAX_BYTES:
                raise ValueError(f"{st.st_size} bytes, more than the {MAX_BYTES} a receipt reads")
            if path.lower().endswith(".safetensors"):
                return {"path": path, "size": st.st_size, **_safetensors(f, st.st_size, deadline)}
            whole = hashlib.sha256()
            _feed(f, st.st_size, deadline, whole)
            return {"path": path, "size": st.st_size, "sha256": "sha256:" + whole.hexdigest()}
        except (OSError, ValueError) as e:
            return {"path": path, "refused": str(e)}


def _safetensors(f, size, deadline):
    """{"sha256", "tensors", "metadata"} of safetensors file `f` of `size` bytes, read once. ValueError for a header
    past MAX_HEADER, or a file the format doesn't allow: each tensor's data_offsets ([begin, end), from the end of the
    header) must lie in the file, and the tensors, sorted by them, fill the data exactly. A tensor's dtype and shape
    aren't checked against its byte span: both are in its hash."""
    head = f.read(8)
    if len(head) < 8:
        raise ValueError("shorter than a safetensors header length")
    n = int.from_bytes(head, "little")
    if n > MAX_HEADER:
        raise ValueError(f"a header of {n} bytes, more than the {MAX_HEADER} a receipt reads")
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
        spans.append((o[0], o[1], name, canonical({"dtype": t.get("dtype"), "shape": t.get("shape")})))
    data, at = size - 8 - n, 0
    if any(end > data for _, end, _, _ in spans):
        raise ValueError("a tensor's data_offsets reach past the end of the file")
    spans.sort()
    for begin, end, _, _ in spans:
        if begin != at:
            raise ValueError(f"the tensors leave a gap or overlap at data byte {at}")
        at = end
    if at != data:
        raise ValueError(f"{data - at} bytes after the last tensor")
    if len(canonical({name: ZERO for _, _, name, _ in spans})) > MAX_TENSORS:
        raise ValueError(f"{len(spans)} tensors: their hashes are more than the {MAX_TENSORS} bytes a receipt holds")
    whole, tensors = hashlib.sha256(head + raw), {}
    for begin, end, name, kind in spans:
        h = hashlib.sha256(kind)
        _feed(f, end - begin, deadline, whole, h)
        tensors[name] = "sha256:" + h.hexdigest()
    return {"sha256": "sha256:" + whole.hexdigest(), "tensors": tensors,
            "metadata": "sha256:" + hashlib.sha256(canonical(header.get("__metadata__"))).hexdigest()}


def _feed(f, n, deadline, *hashes):
    """Read the next `n` bytes of `f` into each of `hashes`, CHUNK at a time, until `deadline`."""
    while n:
        if time.monotonic() >= deadline:
            raise ValueError(f"out of time: the hook hashes for at most {BUDGET_S:g} s per call")
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
                                 "signer's content vault and checked against its record's commitment. Exit 0 when "
                                 "all of that holds and NEW matches, 1 when it doesn't, 2 when the bundle doesn't "
                                 "verify, 4 when the vault's content doesn't open its record (an evidence alert).")
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
        return fail(e, 2)
    if code:
        return fail(f"{a.bundle} does not verify against {a.trust} (`tracekit verify` says why)", 2)
    records = runs.get(a.run)
    if not records:
        return fail(f"{a.bundle} holds no run {a.run}", 2)
    print(f"bundle: verified, run {a.run}")
    old, new = receipt(a.old), receipt(a.new)
    for r in (old, new):
        if "refused" in r:
            return fail(f"{r['path']}: {r['refused']}")
    results = {r["event"]["run_seq"]: r for r in records if r["event"]["type"] == "tool.result"}
    decisions = {r["event"]["data"]["decision_id"]: r for r in records
                 if r["event"]["type"] == "policy.decision" and "decision_id" in r["event"]["data"]}
    client, kept, args = Client(), {}, {}   # run_seq -> a tool result's content, a decision's arguments
    try:
        for seq, content, opened in vault_content(client, [*results.values(), *decisions.values()],
                                                  f"tracekit verify-model {a.run}"):
            if opened:   # else redaction changed it, so it opens no commitment (only a decision's arguments can be)
                (kept if seq in results else args)[seq] = content
    except (SignerUnavailable, OSError) as e:
        return fail(f"the signer can't be reached for the run's content ({e})")
    except RPCError as e:   # no vault, no content_read grant, or a run this signer doesn't hold
        return fail(f"the signer gave no content: {e}")
    except EvidenceAlert as e:
        return fail(f"EVIDENCE ALERT: {e}", 4)
    finally:
        client.close()
    if results and not kept:
        return fail(f"the signer returned none of the run's {len(results)} tool results: their content isn't kept "
                    "(content.retain off, past its retention, or erased)")
    if len(kept) < len(results):
        print(f"content: {len(results) - len(kept)} of the run's {len(results)} tool results not kept by the signer")
    recorded, ignored = [], 0   # a receipt counts only in the result of a call of TOOLS whose arguments name its file
    for seq, content in sorted(kept.items()):
        result = content.get("result") if isinstance(content, dict) else None
        found = result.get("model_receipts") if isinstance(result, dict) else None
        d = decisions.get(results[seq]["event"]["data"].get("decision_id"))
        named = [n for n, why in _named(d["event"]["data"].get("tool"), args.get(d["event"]["run_seq"])) if not why] \
            if d else []   # only the paths the hook hashes
        for r in found if isinstance(found, list) else ():
            path = r.get("path") if isinstance(r, dict) else None
            if isinstance(path, str) and r.get("reported_by") == "hook" and any(
                    path == n or not os.path.isabs(n) and path.endswith(os.sep + n) for n in named):
                recorded.append((seq, r))
            else:
                ignored += 1
    if ignored:
        print(f"content: {ignored} receipt(s) ignored: not in the result of a {', '.join(TOOLS)} call whose "
              "recorded arguments name the file")
    seq, rec = next(((s, r) for s, r in recorded if r.get("sha256") == new["sha256"]), (None, None))
    same = rec is not None and all(rec.get(k) == new.get(k) for k in ("size", "sha256", "tensors", "metadata"))
    if rec is None:
        print(f"NEW {shown(a.new)}: {new['sha256']} matches none of the {len(recorded)} receipt(s) in the run")
    else:
        call = results[seq]["event"]["data"]
        print(f"receipt: {shown(rec.get('path'))}, hashed after tool call {shown(call['tool_use_id'])} (run_seq {seq}, "
              f"ok: {'true' if call['ok'] else 'false'}), recorded by the agent-side hook")
        print(f"NEW {shown(a.new)}: {'matches' if same else 'does NOT match'} the recorded receipt ({new['sha256']})")
    differs = "differs" if old["sha256"] != new["sha256"] else "is the same"
    if "tensors" in old and "tensors" in new:
        o, n = old["tensors"], new["tensors"]
        diff = [("changed", k) for k in sorted(o.keys() & n.keys()) if o[k] != n[k]] + \
            [("added", k) for k in sorted(n.keys() - o.keys())] + [("removed", k) for k in sorted(o.keys() - n.keys())]
        print(f"OLD -> NEW: the file {differs}; {len(diff)} of {len(o.keys() | n.keys())} tensors differ (dtype, "
              f"shape or bytes); the metadata {'differs' if old['metadata'] != new['metadata'] else 'is the same'}")
        for what, k in diff:
            print(f"  {what}: {shown(k)}")
    else:
        print(f"OLD -> NEW: the file {differs} (no tensor hashes for this format)")
    return 0 if same else 1
