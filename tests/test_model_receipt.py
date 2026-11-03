"""Model receipts (tracekit.model_receipt): a weights file's hashes, the hook recording them in the result of a call
that wrote one, and `tracekit verify-model` end to end against the dev signer's content vault."""
import contextlib
import hashlib
import io
import json
import os
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
from tracekit.sdk import autospawn
from tracekit.sdk.client import Client
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError
from tracekit.storage.file import FileReader

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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
        self.assertEqual(receipt(self.path("m\x00.pt"))["refused"], "embedded null byte")
        self.assertIn("surrogates not allowed", receipt(self.path("\ud800.pt"))["refused"])


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
        self.assertEqual([r["refused"][:20] for r in out], ["embedded null byte", "'utf-8' codec can't ",
                                                             "File name too long"])
        self.assertEqual(out[1]["path"], self.path("\\ud800/m.pt"))
        self.assertEqual(len(out[2]["path"]), model_receipt.MAX_TEXT)
        canonical(out)   # what the signer commits to

    def test_an_unexpected_error_is_a_refusal_not_an_exception(self):
        with mock.patch.object(model_receipt, "receipt", side_effect=MemoryError):
            self.assertEqual(model_receipt.receipts("Write", {"file_path": self.w}, self.d), [{
                "refused": "the hook could not read the call's weights files (MemoryError)", "reported_by": "hook"}])

    def test_the_call_shares_one_deadline(self):
        with mock.patch.object(model_receipt, "BUDGET_S", 0):
            out = model_receipt.receipts("Bash", {"command": "cp a model.safetensors"}, self.d)
        self.assertEqual(out[0]["refused"], "out of time: the hook hashes for at most 0 s per call")


class HookRecords(Base):
    """The Claude Code hook (which the other harnesses' hooks share) puts the receipts in the result it completes."""

    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, {"TRACEKIT_RUNTIME_DIR": self.path("run"), "HOME": self.path("home"),
                                           "TRACEKIT_CLIENT_HOME": self.path("client")})
        env.start()
        self.addCleanup(env.stop)
        service = svc.SignerService(self.path("data"), policy=svc.load_policy(), grace_s=0)
        self.addCleanup(service.close)
        self.frames = []

        def handle(identity, frame):
            self.frames.append(frame)
            return service.handle_frame(identity, frame)
        os.environ["TRACEKIT_SIGNER"] = ac._serve(self, handle)   # tests/conftest.py restores the environment

    def call(self, tid, tool, args, cwd=None, response=None):
        p = {"session_id": "s1", "tool_use_id": tid, "tool_name": tool, "tool_input": args, "cwd": cwd or self.d}
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(claude_code.handle(dict(p, hook_event_name="PreToolUse")), 0)
            self.assertEqual(claude_code.handle(dict(p, hook_event_name="PostToolUse", tool_response=response or {
                "stdout": "", "stderr": "", "interrupted": False})), 0)
        return next(f["result"] for f in self.frames if f["method"] == "complete" and f["tool_call_id"] == tid)

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
            "model_receipts"][0]["refused"], "embedded null byte")
        for tid, odd in (("t2", "\ud800"), ("t3", "\udc80")):
            got = self.call(tid, "Bash", {"command": "cp a model.safetensors"}, cwd=self.path(odd))["model_receipts"]
            self.assertEqual(got[0]["path"], self.path(odd.encode("utf-8", "backslashreplace").decode() +
                                                       "/model.safetensors"))
        safetensors(self.path("model.safetensors"), {"a": b"\x01"})
        with mock.patch.object(model_receipt, "BUDGET_S", 0):
            self.assertIn("out of time", self.call("t4", "Bash", {"command": "cp a model.safetensors"})[
                "model_receipts"][0]["refused"])

    def test_receipts_that_would_take_the_result_past_its_frame_are_dropped_with_a_reason(self):
        """Review of d9c6ee7c: with content_capture: full, receipts could take a result that fits its frame past it,
        and the client refused to send the call's result at all."""
        with open(policy.DEFAULT_POLICY, encoding="utf-8") as f:
            text = f.read().replace("content_capture: hashed", "content_capture: full", 1)
        with open(self.path("policy.yaml"), "w", encoding="utf-8") as f:
            f.write(text)
        os.environ["TRACEKIT_POLICY"] = self.path("policy.yaml")
        safetensors(self.path("model.safetensors"), {f"model.layers.{i}.weight": b"\x00" for i in range(700)})
        result = self.call("t1", "Bash", {"command": "cp a model.safetensors"}, response={"stdout": "x" * 1_000_000})
        self.assertEqual(result["model_receipts"], [model_receipt.TOO_LARGE])
        self.assertEqual(len(result["value"]["stdout"]), 1_000_000)


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
            self.assertEqual(claude_code.handle(dict(p, hook_event_name="PreToolUse")), 0)
            shutil.copyfile(edited, self.new)
            self.assertEqual(claude_code.handle(dict(p, hook_event_name="PostToolUse", tool_response={
                "stdout": "", "stderr": "", "interrupted": False})), 0)
            self.run_id = claude_code._load(claude_code._state("s1"))["run_id"]
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
        code, out, err = self.verify(self.old, self.new)
        self.assertEqual(code, 0, err)
        self.assertEqual(out.splitlines(), [
            f"bundle: verified, run {self.run_id}",
            f"receipt: {self.new}, written by tool call t1 (run_seq 2), reported by the hook",
            f"NEW {self.new}: matches the recorded receipt ({receipt(self.new)['sha256']})",
            "OLD -> NEW: the file differs; 1 of 2 tensors differ (dtype, shape or bytes); the metadata is the same",
            "  changed: mlp"])

    def test_a_file_no_call_wrote_matches_no_receipt(self):
        code, out, _ = self.verify(self.new, self.old)
        self.assertEqual(code, 1)
        self.assertIn(f"NEW {self.old}: {receipt(self.old)['sha256']} matches none of the 1 receipt(s) in the run", out)

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

        def content(client, records, purpose):
            yield records[0]["event"]["run_seq"], {"result": {"model_receipts": [
                dict(real, reported_by="the signer\x1b[2J")]}}, True
        with mock.patch("tracekit.why.signed.vault_content", content):
            code, out, _ = self.verify(self.old, self.new)
        self.assertEqual(code, 1)
        self.assertIn("matches none of the 0 receipt(s) in the run", out)
        self.assertNotIn("the signer", out)

    def test_content_not_kept_or_not_granted_is_said_plainly(self):
        for answer, why in ((lambda c, req: {"items": [{"seq": s, "state": "not_retained"} for s in req["seqs"]]},
                             "the signer returned none of the run's 1 tool results: their content isn't kept"),
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
