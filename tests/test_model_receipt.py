"""Model receipts (tracekit.model_receipt): a weights file's hashes, the hook recording them in the result of a call
that wrote one, and `tracekit verify-model` end to end against the dev signer's content vault."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shlex
import shutil
import struct
import tempfile
import time
import unittest
from unittest import mock

import adapter_contract as ac
from factories import rewrite_bundle, wait_for
from tracekit import cli, model_receipt, policy
from tracekit.format.canon import canonical
from tracekit.integrations import claude_code
from tracekit.policy2 import compile as pc
from tracekit.policy2.engine import Engine
from tracekit.sdk import autospawn
from tracekit.sdk.client import Client, RunHandle
from tracekit.signer import service as svc
from tracekit.signer.quotas import MAX_LINE
from tracekit.signer.rpc_schema import RPCError
from tracekit.storage.file import FileReader

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LATER = ("the call's writes may land after the hook reads (a command left running, input typed into another session, "
         "systemd-run, at)")
HAVE_SDK = importlib.util.find_spec("claude_agent_sdk") is not None
receipt = model_receipt.receipt


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def tensor(data, dtype="U8", shape=None):
    """A tensor's hash in a receipt: its dtype and shape as canonical JSON, then its bytes."""
    return sha(canonical({"dtype": dtype, "shape": [len(data)] if shape is None else shape}) + data)


def safetensors(path, tensors, header=None, metadata=None, pad=False):
    """A .safetensors file written by hand: `tensors` ({name: bytes}) back to back, under their own header (a
    __metadata__ entry first, as the safetensors library writes one; `pad`: spaces to a multiple of 8 bytes, as it
    pads) or `header` (a dict, or raw bytes)."""
    hdr, at = {"__metadata__": metadata or {"format": "pt"}}, 0
    for name, data in tensors.items():
        hdr[name] = {"dtype": "U8", "shape": [len(data)], "data_offsets": [at, at + len(data)]}
        at += len(data)
    raw = header if isinstance(header, bytes) else json.dumps(hdr if header is None else header).encode()
    raw += b" " * (-len(raw) % 8 if pad else 0)
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(raw)) + raw + b"".join(tensors.values()))
    return path


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(dir="/tmp" if os.path.isdir("/tmp") else None)   # short: macOS caps socket paths
        self.addCleanup(shutil.rmtree, self.d, True)

    def path(self, name):
        return os.path.join(self.d, name)


class Receipt(Base):
    def test_a_safetensors_file_gets_its_hash_each_tensors_and_its_metadatas(self):
        for pad in (False, True):   # the safetensors library pads its header with spaces
            p = safetensors(self.path("m.safetensors"), {"embed": b"\x01" * 16, "mlp": b"\x02" * 8}, pad=pad)
            with open(p, "rb") as f:
                whole = f.read()
            self.assertEqual(receipt(p), {"path": p, "size": len(whole), "sha256": sha(whole),
                                          "tensors": {"embed": tensor(b"\x01" * 16), "mlp": tensor(b"\x02" * 8)},
                                          "metadata": sha(b'{"format":"pt"}')}, pad)

    def test_tensors_are_read_in_offset_order_a_chunk_at_a_time(self):
        a, b = b"first tensor", b"second"
        p = safetensors(self.path("m.safetensors"), {"x": a + b}, header={
            "b": {"dtype": "U8", "shape": [6], "data_offsets": [12, 18]},
            "a": {"dtype": "U8", "shape": [12], "data_offsets": [0, 12]}})
        with mock.patch.object(model_receipt, "CHUNK", 5):
            self.assertEqual(receipt(p)["tensors"], {"a": tensor(a), "b": tensor(b)})

    def test_a_dtype_shape_or_metadata_change_with_the_same_bytes_changes_its_hash(self):
        data = b"\x00" * 16
        base = {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]}
        was = receipt(safetensors(self.path("a.safetensors"), {"w": data}, header={"w": base}))
        for name, header in (("dtype", {"w": dict(base, dtype="I32")}), ("shape", {"w": dict(base, shape=[4])}),
                             ("metadata", {"__metadata__": {"lr": "1e-4"}, "w": base})):
            now = receipt(safetensors(self.path(f"{name}.safetensors"), {"w": data}, header=header))
            self.assertNotEqual((now["tensors"], now["metadata"]), (was["tensors"], was["metadata"]), name)
            self.assertEqual(now["tensors"] == was["tensors"], name == "metadata", name)

    def test_other_weight_formats_get_the_file_hash_only(self):
        for name in ("m.gguf", "m.pt", "m.pth", "m.ckpt"):
            p = self.path(name)
            with open(p, "wb") as f:
                f.write(b"GGUF weights")
            self.assertEqual(receipt(p), {"path": p, "size": 12, "sha256": sha(b"GGUF weights")}, name)

    def refused(self, raw):
        p = self.path("bad.safetensors")
        with open(p, "wb") as f:
            f.write(raw)
        r = receipt(p)
        self.assertEqual(sorted(r), ["path", "refused"], r)
        return r["refused"]

    def test_a_file_the_format_does_not_allow_is_refused_with_its_reason(self):
        def framed(header, data=b""):
            return struct.pack("<Q", len(header)) + header + data

        def offsets(**spans):
            return framed(json.dumps({k: {"dtype": "U8", "data_offsets": o} for k, o in spans.items()}).encode(),
                          b"1234")
        for raw, why in (
                (b"\x01\x02", "shorter than a safetensors header length"),
                (struct.pack("<Q", 1000) + b"{}", "a header of 1000 bytes, past the end of the file"),
                (framed(b"{not json"), "the header is not strict JSON"),
                (framed(b"[1]"), "the header is not a JSON object"),
                (framed(b'{"a": {"dtype": "U8"}}'), "tensor 'a' has no data_offsets"),
                (offsets(a=[0, 100]), "a tensor's data_offsets reach past the end of the file"),
                (offsets(a=[0, 2], b=[3, 4]), "the tensors leave a gap or overlap at data byte 2"),
                (offsets(a=[0, 3], b=[2, 4]), "the tensors leave a gap or overlap at data byte 3"),
                (offsets(a=[0, 2]), "2 bytes after the last tensor")):
            with self.subTest(why=why):
                self.assertIn(why, self.refused(raw))

    def test_a_header_past_the_cap_is_refused_before_it_is_parsed(self):
        """Review of d9c6ee7c: a 99 MB header was parsed before any bound (14.8 s, 1.3 GB)."""
        p = safetensors(self.path("m.safetensors"), {"w": b"\x00"}, metadata={"notes": "x" * model_receipt.MAX_HEADER})
        with mock.patch.object(model_receipt, "loads_strict") as parse:
            r = receipt(p)
        self.assertRegex(r["refused"], rf"^a header of \d+ bytes, more than the {model_receipt.MAX_HEADER} a receipt "
                                       r"reads$")
        parse.assert_not_called()

    def test_a_file_past_the_size_bound_is_refused_unread(self):
        p = safetensors(self.path("m.safetensors"), {"a": b"\x00" * 64})
        with mock.patch.object(model_receipt, "MAX_BYTES", 64), mock.patch.object(model_receipt, "_feed") as feed:
            r = receipt(p)
        self.assertEqual(r, {"path": p, "refused": f"{os.path.getsize(p)} bytes, more than the 64 a receipt reads"})
        feed.assert_not_called()

    def test_hashing_stops_at_the_deadline(self):
        """Review of d9c6ee7c: no time budget, so a slow disk could outlast the hook's timeout."""
        p = safetensors(self.path("m.safetensors"), {"a": b"\x00" * 64})
        shutil.copyfile(p, self.path("m.pt"))
        for p in (p, self.path("m.pt")):
            self.assertEqual(receipt(p, time.monotonic())["refused"],
                             f"out of time: the hook hashes for at most {model_receipt.BUDGET_S:g} s per call", p)

    def test_a_receipt_past_its_tensor_bound_is_refused(self):
        p = safetensors(self.path("m.safetensors"), {f"layer.{i}": b"\x00" for i in range(8)})
        with mock.patch.object(model_receipt, "MAX_TENSORS", 200):
            self.assertEqual(receipt(p)["refused"], "8 tensors: their hashes are more than the 200 bytes a receipt "
                                                    "holds")

    def test_no_file_a_directory_a_fifo_or_an_unencodable_path_is_refused_without_blocking(self):
        self.assertEqual(receipt(self.path("none.pt"))["refused"], "No such file or directory")
        os.mkdir(self.path("dir.safetensors"))
        self.assertEqual(receipt(self.path("dir.safetensors"))["refused"], "not a regular file")
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.path("fifo.safetensors"))
            self.assertEqual(receipt(self.path("fifo.safetensors"))["refused"], "not a regular file")
        # review of d9c6ee7c: os.open raises ValueError for these, which the hook didn't catch
        self.assertEqual(receipt(self.path("m\x00.pt"))["refused"], "a NUL byte in the path")
        # the OS's words: POSIX can't encode a lone surrogate, Windows (UTF-16 paths) finds no such file
        self.assertTrue(receipt(self.path("\ud800.pt"))["refused"])


class Receipts(Base):
    """Which files a call wrote, as the hook reads them."""

    def setUp(self):
        super().setUp()
        self.w = safetensors(self.path("model.safetensors"), {"a": b"\x01\x02"})

    def test_a_write_tools_path_and_a_shell_commands_write_targets(self):
        want = [dict(receipt(self.w), reported_by="hook")]
        self.assertEqual(model_receipt.receipts("Write", {"file_path": self.w, "content": "x"}, "/elsewhere"), want)
        for cmd in ("cp edited.bin model.safetensors", "python edit.py > model.safetensors"):
            self.assertEqual(model_receipt.receipts("Bash", {"command": cmd}, self.d), want, cmd)

    def test_other_files_and_calls_get_none(self):
        readme = self.path("README.md")
        self.assertEqual(model_receipt.receipts("Write", {"file_path": readme, "content": "x"}, self.d), [])
        self.assertEqual(model_receipt.receipts("Bash", {"command": "cp a.txt b.txt"}, self.d), [])
        self.assertEqual(model_receipt.receipts("Read", {"file_path": self.w}, self.d), [])
        self.assertEqual(model_receipt.receipts("Bash", {"command": f"sha256sum {self.w}"}, self.d), [])

    def test_a_relative_path_the_hook_cant_place_is_refused(self):
        self.assertEqual(model_receipt.receipts("Bash", {"command": "cd sub && cp a model.safetensors"}, self.d),
                         [{"path": "model.safetensors", "refused": "a path relative to a directory the command "
                                                                   "changed to", "reported_by": "hook"}])
        self.assertEqual(model_receipt.receipts("Bash", {"command": "cp a model.safetensors"}, None)[0]["refused"],
                         "a relative path, and the hook was given no working directory")

    def test_a_call_gets_at_most_max_files_receipts_then_a_count(self):
        cmd = "; ".join(f"cp a {i}.pt" for i in range(model_receipt.MAX_FILES + 2))
        out = model_receipt.receipts("Bash", {"command": cmd}, self.d)
        self.assertEqual(len(out), model_receipt.MAX_FILES + 1)
        self.assertEqual(out[-1], {"refused": f"2 more weights file(s): a call's result holds at most "
                                              f"{model_receipt.MAX_FILES} receipts", "reported_by": "hook"})

    def test_paths_and_reasons_are_json_safe_and_bounded(self):
        """Review of d9c6ee7c: a NUL or a lone surrogate in a path raised, and a path had no bound."""
        out = model_receipt.receipts("Write", {"file_path": self.path("m\x00.pt")}, self.d) + \
            model_receipt.receipts("Bash", {"command": "cp a m.pt"}, self.path("\ud800")) + \
            model_receipt.receipts("Write", {"file_path": "/" + "a" * 10000 + ".pt"}, self.d)
        # the last two are the OS's words (Windows: no such file, invalid argument)
        self.assertEqual([r["refused"][:20] for r in out[:1]], ["a NUL byte in the pa"])
        self.assertTrue(all(r["refused"] for r in out[1:]), out)
        self.assertEqual(out[1]["path"], os.path.join(self.path("\ud800"), "m.pt").encode("utf-8", "backslashreplace")
                         .decode())
        self.assertEqual(len(out[2]["path"]), model_receipt.MAX_TEXT)
        canonical(out)   # what the signer commits to

    def test_an_unexpected_error_is_a_refusal_not_an_exception(self):
        with mock.patch.object(model_receipt, "receipt", side_effect=MemoryError):
            self.assertEqual(model_receipt.receipts("Write", {"file_path": self.w}, self.d), [{
                "refused": "the hook could not read the call's weights files (MemoryError)", "reported_by": "hook"}])

    def test_the_call_shares_one_deadline(self):
        """Review of 6b0a568e: with BUDGET_S 0 this passed with a deadline per file too. The first file uses up the
        call's budget, so the second is out of time, though it alone would hash in time."""
        for name in ("1.safetensors", "2.safetensors"):
            safetensors(self.path(name), {"a": b"\x01"})
        real, pauses = model_receipt.receipt, iter((0.1, 0))

        def slow(path, deadline):
            time.sleep(next(pauses))
            return real(path, deadline)
        with mock.patch.object(model_receipt, "BUDGET_S", 0.05), mock.patch.object(model_receipt, "receipt", slow):
            out = model_receipt.receipts("Bash", {"command": "cp a 1.safetensors; cp a 2.safetensors"}, self.d)
        self.assertEqual([r["refused"] for r in out], ["out of time: the hook hashes for at most 0.05 s per call"] * 2)

    def test_a_path_the_hook_would_have_to_guess_is_refused(self):
        """Review of 6b0a568e: `cp -t out src` got a receipt of its source, `env -C sub` and `git -C sub` ones of the
        file in the hook's directory, and a quoted ~ was expanded."""
        src = safetensors(self.path("src.safetensors"), {"a": b"\x01"})
        elsewhere = ("the command line's paths are in another directory, root or host (cp -t, git -C, env --chdir, "
                     "chroot, ssh, ...)")
        home, cd = "a path starting with ~, which the hook doesn't expand", "a path relative to a directory the " \
            "command changed to"
        # review of d013a1dd: a cluster (cp -vt), popd and git --work-tree slipped through
        for cmd, why in (("cp -t out src.safetensors", elsewhere), (f"cp -t /out {src}", elsewhere),
                         ("cp -vt out src.safetensors", elsewhere), ("cp -rt out src.safetensors", elsewhere),
                         ("mv -ft out src.safetensors", elsewhere), ("install -Dt out src.safetensors", elsewhere),
                         ("env -C sub cp x model.safetensors", elsewhere),
                         ("git -C sub mv x model.safetensors", elsewhere),
                         ("env --chdir=sub cp x model.safetensors", elsewhere), ("cp x '~/model.safetensors'", home),
                         ("cp x ~/model.safetensors", home), ("popd; cp x model.safetensors", cd),
                         ("git --work-tree=sub restore model.safetensors", cd),
                         # review of c15728a3: a prefix of a long option, sudo -D, and a command run on another root or
                         # host hashed the file here
                         ("env --ch=sub cp x model.safetensors", elsewhere),
                         ("sudo -D sub cp x model.safetensors", elsewhere),
                         (f"chroot /jail cp x {self.w}", elsewhere), (f"ssh host cp x {self.w}", elsewhere),
                         (f"unshare -m cp x {self.w}", elsewhere)):
            self.assertEqual([r.get("refused") for r in model_receipt.receipts("Bash", {"command": cmd}, self.d)],
                             [why], cmd)
        self.assertEqual(model_receipt.receipts("Write", {"file_path": "~/model.safetensors"}, self.d)[0]["refused"],
                         home)

    def test_a_write_that_may_land_after_the_hook_reads_is_refused(self):
        """Review of 59c428db: `cp new.pt m.pt` run in the background got a receipt of the file before the copy, and
        so did a command systemd-run runs later; a harness's hook marks input typed into another session `later`."""
        for args, later in (({"command": "cp new.pt model.safetensors", "run_in_background": True}, False),
                            ({"command": "cp new.pt model.safetensors", "is_background": True}, False),
                            ({"command": "systemd-run cp new.pt model.safetensors"}, False),
                            ({"command": "at now <<< 'cp new.pt model.safetensors'"}, False),
                            ({"command": "cp new.pt model.safetensors"}, True)):
            self.assertEqual([r["refused"] for r in model_receipt.receipts("Bash", args, self.d, later)], [LATER], args)

    def test_a_command_the_line_leaves_running_is_refused(self):
        """Review of 76f4444d: `cp new.pt m.pt &` got a receipt of the file before the copy. A lone & refuses the line;
        &&, 2>&1 and &> are no background. A coproc line gets none either (the policy's parser reads no path in it)."""
        for cmd in ("cp new.pt model.safetensors &", "nohup cp a model.safetensors &", "( cp a model.safetensors ) &"):
            self.assertEqual([r["refused"] for r in model_receipt.receipts("Bash", {"command": cmd}, self.d)], [LATER],
                             cmd)
        self.assertEqual(model_receipt.receipts("Bash", {"command": "coproc cp new.pt t.pt; mv t.pt model.safetensors"},
                                                self.d), [])
        want = [dict(receipt(self.w), reported_by="hook")]
        for cmd in ("cp a model.safetensors && ls", "cp a model.safetensors 2>&1", "cp a model.safetensors &> log"):
            self.assertEqual(model_receipt.receipts("Bash", {"command": cmd}, self.d), want, cmd)

    def test_setsid_that_forks_is_refused_and_plain_setsid_is_not(self):
        """Review of 277705e6: `setsid -f cp a /w/m.pt` returns at once, and its receipt was of the file before the
        copy. Plain setsid runs its command in the foreground in a hook's non-interactive shell."""
        for cmd in ("setsid -f cp new.pt model.safetensors", "setsid --fork cp new.pt model.safetensors",
                    "setsid --fo cp new.pt model.safetensors", "setsid -cf cp new.pt model.safetensors"):
            self.assertEqual([r["refused"] for r in model_receipt.receipts("Bash", {"command": cmd}, self.d)], [LATER],
                             cmd)
        want = [dict(receipt(self.w), reported_by="hook")]
        for cmd in ("setsid cp new.pt model.safetensors", "setsid cp -f new.pt model.safetensors"):
            self.assertEqual(model_receipt.receipts("Bash", {"command": cmd}, self.d), want, cmd)

    def test_a_relative_path_of_a_shell_with_its_own_dir_path_is_refused(self):
        """Gemini CLI's and Qwen Code's shell runs in its dir_path (directory in older releases), Cursor's in its
        working_directory, Codex's in its workdir, agy's in its Cwd (in any case), Crush's in its working_dir, so a
        relative path there is no file of the hook's cwd; an absolute one still is. The review of #570: agy's and
        Crush's names were missing, and a value that isn't a string was read as none."""
        for key in ("dir_path", "directory", "working_directory", "workdir", "Cwd", "cwd", "CWD", "working_dir"):
            self.assertEqual(model_receipt.receipts("Bash", {"command": "cp a model.safetensors", key: "sub"},
                                                    self.d)[0]["refused"],
                             "a path relative to a directory the command changed to", key)
            self.assertEqual(model_receipt.receipts("Bash", {"command": f"cp a {shlex.quote(self.w)}", key: "sub"},
                                                    self.d),
                             [dict(receipt(self.w), reported_by="hook")], key)
        for value in (["sub"], 5):
            self.assertEqual(model_receipt.receipts("Bash", {"command": "cp a model.safetensors", "workdir": value},
                                                    self.d)[0]["refused"],
                             "a path relative to a directory the command changed to", value)

    def test_another_commands_t_or_c_flag_refuses_nothing(self):
        """Review of d013a1dd: `grep -C3` or `sort -t,` anywhere in a command refused every weights path in it."""
        want = [dict(receipt(self.w), reported_by="hook")]
        for cmd in ("grep -C3 x f; cp x model.safetensors", "sort -t, -k1 a.csv > s.csv; cp x model.safetensors"):
            self.assertEqual(model_receipt.receipts("Bash", {"command": cmd}, self.d), want, cmd)


class HookRecords(Base):
    """The Claude Code hook (which the other harnesses' hooks share) puts the receipts in the result it completes."""

    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, {"TRACEKIT_RUNTIME_DIR": self.path("run"), "HOME": self.path("home"),
                                           "TRACEKIT_CLIENT_HOME": self.path("client")})
        env.start()
        self.addCleanup(env.stop)
        # receipts, not the policy: the dev pack without its holds on a weights write (TK-A058, TK-A059), so each
        # write here runs; VerifyModel's is held and a person approves it
        pol = pc.build(svc.DEFAULT_POLICY)[0]
        pol["ask"] = [r for r in pol["ask"] if r["id"] not in ("TK-A058", "TK-A059")]
        service = svc.SignerService(self.path("data"), policy=Engine(pol), grace_s=0)
        self.addCleanup(service.close)
        self.frames, self.untrusted = [], ()

        def handle(identity, frame):
            self.frames.append(frame)
            out = service.handle_frame(identity, frame)
            # a tool in self.untrusted is decided as one the policy marks untrusted: its result goes itself
            return dict(out, send_result=True) if frame["method"] == "decide" and frame["tool"] in self.untrusted \
                else out
        os.environ["TRACEKIT_SIGNER"] = ac._serve(self, handle)   # tests/conftest.py restores the environment

    def complete(self, tid):
        return next(f for f in self.frames if f["method"] == "complete" and f["tool_call_id"] == tid)

    def call(self, tid, tool, args, cwd=None, response=None, event="PostToolUse"):
        p = {"session_id": "s1", "tool_use_id": tid, "tool_name": tool, "tool_input": args, "cwd": cwd or self.d}
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(claude_code.handle(dict(p, hook_event_name="PreToolUse")), 0)
            self.assertEqual(claude_code.handle(dict(p, hook_event_name=event, tool_response=response or {
                "stdout": "", "stderr": "", "interrupted": False})), 0)
        return self.complete(tid)["result"]

    def full_capture(self):
        with open(policy.DEFAULT_POLICY, encoding="utf-8") as f:
            text = f.read().replace("content_capture: hashed", "content_capture: full", 1)
        with open(self.path("policy.yaml"), "w", encoding="utf-8") as f:
            f.write(text)
        os.environ["TRACEKIT_POLICY"] = self.path("policy.yaml")

    def test_a_weights_write_carries_its_receipt_and_another_file_none(self):
        w = safetensors(self.path("model.safetensors"), {"a": b"\x01\x02", "b": b"\x03"})
        result = self.call("t1", "Bash", {"command": "cp edited.bin model.safetensors"})
        self.assertEqual(result["model_receipts"], [dict(receipt(w), reported_by="hook")])
        self.assertEqual(sorted(result), ["hash", "model_receipts", "redacted", "size"])   # next to the digest
        self.assertNotIn("model_receipts", self.call("t2", "Write", {"file_path": self.path("notes.md"),
                                                                     "content": "x"}))

    def test_a_path_no_receipt_can_read_still_completes_the_call(self):
        """Review of d9c6ee7c: a NUL in the path, or a lone surrogate in the payload's cwd (which no decision reads),
        made the hook fail, and the call's result was never recorded; so did running out of time."""
        self.assertEqual(self.call("t1", "Write", {"file_path": self.path("m\x00.safetensors"), "content": "x"})[
            "model_receipts"][0]["refused"], "a NUL byte in the path")
        for tid, odd in (("t2", "\ud800"), ("t3", "\udc80")):
            got = self.call(tid, "Bash", {"command": "cp a model.safetensors"}, cwd=self.path(odd))["model_receipts"]
            self.assertEqual(got[0]["path"], os.path.join(self.path(odd), "model.safetensors").encode(
                "utf-8", "backslashreplace").decode())
        safetensors(self.path("model.safetensors"), {"a": b"\x01"})
        with mock.patch.object(model_receipt, "BUDGET_S", 0):
            self.assertIn("out of time", self.call("t4", "Bash", {"command": "cp a model.safetensors"})[
                "model_receipts"][0]["refused"])

    def test_receipts_that_would_take_the_result_past_its_frame_are_dropped_with_a_reason(self):
        """Review of d9c6ee7c: with content_capture: full, receipts could take a result that fits its frame past it,
        and the client refused to send the call's result at all."""
        self.full_capture()
        safetensors(self.path("model.safetensors"), {f"model.layers.{i}.weight": b"\x00" for i in range(700)})
        cp = {"command": "cp a model.safetensors"}
        self.assertEqual(self.call("t1", "Bash", cp, response={"stdout": "x" * 500_000})["model_receipts"],
                         [model_receipt.TOO_LARGE])   # the result fits half a frame, with the marker too
        result = self.call("t2", "Bash", cp, response={"stdout": "x" * 1_000_000})
        self.assertEqual((len(result["value"]["stdout"]), "model_receipts" in result), (1_000_000, False))

    def test_the_marker_is_left_out_too_when_it_would_take_the_result_past_its_frame(self):
        """Review of 6b0a568e: the marker's 133 bytes took a result within that much of the frame limit past it."""
        self.full_capture()
        self.call("t1", "Bash", {"command": "true"}, response={"stdout": "x"})
        size = len(json.dumps(self.complete("t1"), separators=(",", ":"), ensure_ascii=False).encode())
        safetensors(self.path("model.safetensors"), {"a": b"\x01"})
        stdout = "x" * (MAX_LINE - 60 - size + 1)   # its complete 60 bytes under the frame limit without receipts
        self.assertNotIn("model_receipts", self.call("t2", "Bash", {"command": "cp a model.safetensors"},
                                                     response={"stdout": stdout}))

    def test_another_tools_result_goes_as_it_came_and_a_receipt_tools_key_is_the_hooks(self):
        """Review of c15728a3: the clients dropped a model_receipts key from every result, so the record committed to
        a result the tool didn't return and provenance never read what the key held. An MCP or web tool's result now
        goes as it came; only a tool the hook receipts (Bash, untrusted here) has a key it didn't set removed."""
        self.untrusted = ("mcp__sh__run", "WebFetch", "Bash")
        planted = [{"path": self.path("model.safetensors"), "sha256": model_receipt.ZERO, "reported_by": "hook"}]
        for tid, tool, args in (("t1", "mcp__sh__run", {"command": "cp a model.safetensors"}),
                                ("t2", "WebFetch", {"url": "https://example.com/model.safetensors"})):
            self.assertEqual(self.call(tid, tool, args, response={"content": "x", "model_receipts": planted}),
                             {"content": "x", "model_receipts": planted}, tool)
        self.assertEqual(self.call("t3", "Bash", {"command": "ls"},
                                   response={"stdout": "x", "model_receipts": planted}), {"stdout": "x"})

    @unittest.skipUnless(HAVE_SDK, "claude-agent-sdk not installed")
    def test_an_sdk_integration_sends_a_tools_result_as_it_came(self):
        """Review of c15728a3: the Python client dropped a model_receipts key from an SDK integration's result."""
        import anyio
        from tracekit.integrations import claude_agent_sdk
        self.untrusted = ("mcp__sh__run",)
        c = Client()
        self.addCleanup(c.close)
        hooks = claude_agent_sdk.tracekit_hooks(c, c.register_run({"agent": {"name": "claude-agent-sdk"}}))
        pre, post = hooks["PreToolUse"][0].hooks[0], hooks["PostToolUse"][0].hooks[0]
        p = {"tool_use_id": "t1", "tool_name": "mcp__sh__run", "tool_input": {"command": "cp a model.safetensors"}}
        planted = [{"path": self.path("model.safetensors"), "sha256": model_receipt.ZERO, "reported_by": "hook"}]
        self.assertEqual(anyio.run(pre, dict(p, hook_event_name="PreToolUse"), "t1", None), {})
        anyio.run(post, dict(p, hook_event_name="PostToolUse", tool_response={
            "content": "x", "model_receipts": planted}), "t1", None)
        self.assertEqual(self.complete("t1")["result"], {"content": "x", "model_receipts": planted})

    def test_input_typed_into_another_session_or_a_monitor_gets_no_receipt(self):
        """Review of 59c428db: Codex's write_stdin, agy's send_input and Qwen Code's monitor, decided as Bash, type into
        another session or leave a command running, so the hook read the file before their write."""
        from tracekit import agent_hooks
        from tracekit.integrations import harness_hooks
        agent = mock.patch.object(claude_code, "AGENT", claude_code.AGENT)   # harness_hooks.run sets it
        agent.start()
        self.addCleanup(agent.stop)
        safetensors(self.path("model.safetensors"), {"a": b"\x01"})
        cp = "cp new.pt model.safetensors"
        for tid, harness, name, ti in (("t1", "codex", "write_stdin", {"session_id": 1, "chars": cp + "\n"}),
                                       ("t2", "qwen", "monitor", {"command": cp})):
            p = {"session_id": f"s-{harness}", "tool_use_id": tid, "tool_name": name, "tool_input": ti, "cwd": self.d}
            for event, more in (("PreToolUse", {}), ("PostToolUse", {"tool_response": {"output": ""}})):
                self.assertEqual(harness_hooks.run(harness, json.dumps(dict(p, hook_event_name=event, **more)),
                                                   io.StringIO(), io.StringIO()), 0, (harness, event))
            self.assertEqual([r["refused"] for r in self.complete(tid)["result"]["model_receipts"]], [LATER], harness)
        q = agent_hooks.normalise("antigravity", {
            "hook_event_name": "PostToolUse", "conversationId": "c1", "stepIdx": 3,
            "toolCall": {"name": "manage_task", "args": {"Action": "send_input", "Input": cp}}})
        self.assertEqual((q["tool_name"], q["later"]), ("Bash", True))
        # Devin's write_to_process types into a shell it started earlier, as Codex's write_stdin does
        q = agent_hooks.normalise("devin", {"hook_event_name": "PreToolUse", "session_id": "s-devin",
                                            "tool_name": "write_to_process", "tool_input": {"shell_id": "main", "input": cp}})
        self.assertEqual((q["tool_name"], q["later"]), ("Bash", True))

    def test_a_call_that_failed_gets_no_receipts(self):
        """Review of 6b0a568e: a failed, interrupted or is_error call got receipts too."""
        safetensors(self.path("model.safetensors"), {"a": b"\x01"})
        for tid, event, response in (("t1", "PostToolUseFailure", None), ("t2", "PostToolUse", {"interrupted": True}),
                                     ("t3", "PostToolUse", {"is_error": True})):
            self.assertNotIn("model_receipts", self.call(tid, "Bash", {"command": "cp a model.safetensors"},
                                                         response=response, event=event), event)


class Help(unittest.TestCase):
    def test_help_names_every_exit_code(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(["verify-model", "--help"])
        self.assertIn("Exit 0 when all of that holds and NEW matches, 1 when it doesn't, 2 when the bundle doesn't "
                      "verify, 4 when the vault's content doesn't open its record (an evidence alert).",
                      " ".join(out.getvalue().split()))


@unittest.skipUnless(os.name == "posix", "POSIX paths and the dev signer's socket")
class VerifyModel(Base):
    """`tracekit verify-model` on a bundle the dev signer exported, the receipt read from its content vault."""

    def setUp(self):
        super().setUp()
        # TRACEKIT_DEV_GRACE: a closed run is final 0.2 s after, not 5 s
        env = mock.patch.dict(os.environ, {"TRACEKIT_RUNTIME_DIR": self.path("run"), "TRACEKIT_DEV_IDLE": "60",
                                           "TRACEKIT_DEV_GRACE": "0.2", "PYTHONPATH": ROOT,
                                           "HOME": self.path("home"), "XDG_DATA_HOME": self.path("data")})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("TRACEKIT_SIGNER", None)
        self.addCleanup(autospawn.down)
        self.old = safetensors(self.path("old.safetensors"), {"embed": b"\x01" * 32, "mlp": b"\x02" * 32})
        edited = safetensors(self.path("edited.bin"), {"embed": b"\x01" * 32, "mlp": b"\x02" * 31 + b"\x03"})
        self.new = self.path("model.safetensors")
        p = {"session_id": "s1", "tool_use_id": "t1", "tool_name": "Bash", "cwd": self.d,
             "tool_input": {"command": "cp edited.bin model.safetensors"}}
        with contextlib.redirect_stdout(io.StringIO()):
            # the dev pack holds a weights write (TK-A059): a person approves it, and the agent's retry runs
            held = io.StringIO()
            with contextlib.redirect_stderr(held):
                self.assertEqual(claude_code.handle(dict(p, tool_use_id="t0", hook_event_name="PreToolUse")), 2)
            self.assertRegex(held.getvalue(), r"^\[tracekit\] HELD, nothing ran: apr-[0-9a-f]+ \(TK-A059\)")
            c = Client()
            c.approval_decide({"approval_id": held.getvalue().split()[4], "decision": "approve"})
            self.assertEqual(claude_code.handle(dict(p, hook_event_name="PreToolUse")), 0)
            shutil.copyfile(edited, self.new)
            self.assertEqual(claude_code.handle(dict(p, hook_event_name="PostToolUse", tool_response={
                "stdout": "", "stderr": "", "interrupted": False})), 0)
            st = claude_code._load(claude_code._state("s1"))
            # receipts of a backdoored file, as model.safetensors, in the results of an MCP shell tool and a web fetch
            # (as their outputs could plant them) and of a write to another file
            self.backdoor = safetensors(self.path("backdoor.safetensors"), {"embed": b"\x01" * 32, "mlp": b"\x06" * 32})
            planted = dict(receipt(self.backdoor), path=self.new, reported_by="hook")
            run = RunHandle(c, st)
            for tid, tool, args in (("t2", "mcp__sh__run", {"command": "cp x model.safetensors"}),
                                    ("t3", "WebFetch", {"url": "https://example.com/model.safetensors"}),
                                    ("t4", "Write", {"file_path": self.path("notes.md"), "content": "x"})):
                run.decide(tid, tool, args)
                self.assertIsNotNone(run.complete(tid, result={"model_receipts": [planted]}))
            c.close()
            self.run_id = st["run_id"]
            self.assertEqual(claude_code.handle({"hook_event_name": "SessionEnd", "session_id": "s1"}), 0)
        store = os.path.join(svc.dev_data_dir(), "store")
        self.assertTrue(wait_for(lambda: list(FileReader(store).iter_run("default", self.run_id))[-1]["event"]["type"]
                                 == "run.final", 20), "no run.final after the grace window")
        self.trust, self.bundle = self.path("trust.json"), self.path("run.tkb")
        for argv in (["signer", "trust", "--dev", "-o", self.trust],
                     ["export", "--v2", "--run", self.run_id, "--dev", "-o", self.bundle]):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(argv), 0)

    def verify(self, old, new, bundle=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["verify-model", old, new, "--bundle", bundle or self.bundle, "--run", self.run_id,
                             "--trust", self.trust])
        return code, out.getvalue(), err.getvalue()

    def test_new_matches_its_receipt_and_the_changed_tensor_is_named(self):
        """The weights write held under the dev pack (setUp) gets its receipt once a person approves the retry."""
        code, out, err = self.verify(self.old, self.new)
        self.assertEqual(code, 0, err)
        self.assertEqual(out.splitlines(), [
            f"bundle: verified, run {self.run_id}",
            "content: 3 receipt(s) ignored: not in the result of a Write, Edit, MultiEdit, NotebookEdit, Bash call "
            "whose recorded arguments name the file",
            # after t0's hold and its approval
            f"receipt: {self.new}, hashed after tool call t1 (run_seq 6, ok: true), recorded by the agent-side hook",
            f"NEW {self.new}: matches the recorded receipt ({receipt(self.new)['sha256']})",
            "OLD -> NEW: the file differs; 1 of 2 tensors differ (dtype, shape or bytes); the metadata is the same",
            "  changed: mlp"])

    def test_a_file_no_call_wrote_matches_no_receipt(self):
        code, out, _ = self.verify(self.new, self.old)
        self.assertEqual(code, 1)
        self.assertIn(f"NEW {self.old}: {receipt(self.old)['sha256']} matches none of the 1 receipt(s) in the run", out)

    def test_a_receipt_planted_in_a_call_that_doesnt_name_its_file_doesnt_count(self):
        """Review of 6b0a568e: any tool result's model_receipts counted, so a planted receipt passed a backdoored
        file as recorded by the hook. Review of c15728a3: so did one in an MCP shell tool's result, whose command
        names the file; a receipt counts only in a call of a tool the hook receipts."""
        code, out, _ = self.verify(self.old, self.backdoor)
        self.assertEqual(code, 1)
        self.assertIn("content: 3 receipt(s) ignored", out)
        self.assertIn(f"NEW {self.backdoor}: {receipt(self.backdoor)['sha256']} matches none of the 1 receipt(s) in "
                      "the run", out)

    def test_a_bundle_that_does_not_verify_exits_2(self):
        """Review of d9c6ee7c: a bundle that failed verification exited 1, as a NEW that doesn't match does."""
        def edit(files, _):
            name = next(n for n in files if n.startswith("runs/"))
            self.assertIn(b'"t1"', files[name])
            files[name] = files[name].replace(b'"t1"', b'"t2"', 1)
        rewrite_bundle(self.bundle, self.path("tampered.tkb"), edit)
        code, out, err = self.verify(self.old, self.new, self.path("tampered.tkb"))
        self.assertEqual((code, out), (2, ""))
        self.assertIn("tampered.tkb does not verify against", err)

    def test_a_receipt_altered_in_the_vault_fails_its_commitment(self):
        real = Client.content_get

        def altered(client, req):
            got = real(client, req)
            for item in got["items"]:
                for r in (item.get("content") or {}).get("result", {}).get("model_receipts", ()):
                    r["tensors"]["mlp"] = receipt(self.old)["tensors"]["mlp"]
            return got
        with mock.patch.object(Client, "content_get", altered):
            code, _, err = self.verify(self.old, self.new)
        self.assertEqual(code, 4)
        self.assertIn("tracekit verify-model: EVIDENCE ALERT: run ", err)
        self.assertIn("does not open the record's commitment", err)

    def test_only_the_hooks_receipts_count_and_their_wording_is_fixed(self):
        """Review of d9c6ee7c: `reported_by` was printed from the vault's content, whatever it said."""
        real = receipt(self.new)

        def content(client, records, purpose):   # t1's arguments, which name the file, and its result
            d = next(r for r in records if r["event"]["type"] == "policy.decision")
            yield d["event"]["run_seq"], {"command": "cp edited.bin model.safetensors"}, True
            yield next(r for r in records if r["event"]["type"] == "tool.result")["event"]["run_seq"], {"result": {
                "model_receipts": [dict(real, reported_by="an auditor\x1b[2J")]}}, True
        with mock.patch("tracekit.why.signed.vault_content", content):
            code, out, _ = self.verify(self.old, self.new)
        self.assertEqual(code, 1)
        self.assertIn("matches none of the 0 receipt(s) in the run", out)
        self.assertNotIn("auditor", out)

    def test_arguments_redaction_changed_name_no_file(self):
        real = receipt(self.new)

        def content(client, records, purpose):   # t1's arguments, unopened (redaction changed them), and its result
            d = next(r for r in records if r["event"]["type"] == "policy.decision")
            yield d["event"]["run_seq"], {"command": "cp edited.bin model.safetensors"}, False
            yield next(r for r in records if r["event"]["type"] == "tool.result")["event"]["run_seq"], {"result": {
                "model_receipts": [dict(real, reported_by="hook")]}}, True
        with mock.patch("tracekit.why.signed.vault_content", content):
            code, out, _ = self.verify(self.old, self.new)
        self.assertEqual(code, 1)
        self.assertIn("matches none of the 0 receipt(s) in the run", out)

    def test_a_receipt_of_a_path_the_hook_refuses_doesnt_count(self):
        """Review of d013a1dd: verify-model counted a receipt the hook had made of `cp -vt out src`'s source."""
        real = receipt(self.new)

        def content(client, records, purpose):   # t1's arguments, now a command the hook refuses, and its result
            d = next(r for r in records if r["event"]["type"] == "policy.decision")
            yield d["event"]["run_seq"], {"command": "cp -vt out model.safetensors"}, True
            yield next(r for r in records if r["event"]["type"] == "tool.result")["event"]["run_seq"], {"result": {
                "model_receipts": [dict(real, reported_by="hook")]}}, True
        with mock.patch("tracekit.why.signed.vault_content", content):
            code, out, _ = self.verify(self.old, self.new)
        self.assertEqual(code, 1)
        self.assertIn("matches none of the 0 receipt(s) in the run", out)

    def test_content_not_kept_or_not_granted_is_said_plainly(self):
        for answer, why in ((lambda c, req: {"items": [{"seq": s, "state": "not_retained"} for s in req["seqs"]]},
                             "the signer returned none of the run's 4 tool results: their content isn't kept"),
                            (mock.Mock(side_effect=RPCError("forbidden", "content_get needs the content_read grant")),
                             "the signer gave no content: forbidden: content_get needs the content_read grant")):
            with mock.patch.object(Client, "content_get", answer):
                code, _, err = self.verify(self.old, self.new)
            self.assertEqual(code, 1)
            self.assertIn(f"tracekit verify-model: {why}", err)

    def test_an_unreachable_signer_is_said_plainly(self):
        os.environ["TRACEKIT_SIGNER"] = self.path("gone.sock")
        code, _, err = self.verify(self.old, self.new)
        self.assertEqual(code, 1)
        self.assertIn("tracekit verify-model: the signer can't be reached for the run's content", err)


if __name__ == "__main__":
    unittest.main()
