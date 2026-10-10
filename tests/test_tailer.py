"""The L1 transcript tailer (tracekit/tailer.py) against an in-process signer: what it records from a Claude Code
transcript, each way of losing the transcript (a signer-written tailer_lost gap), the delegated token the system-mode
tailer calls with, and the hook starting it at SessionStart."""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
import uuid
from unittest import mock

from tracekit import install, tailer
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import REQUESTS, RPCError

ME = CallerIdentity("uid", str(os.getuid()) if hasattr(os, "getuid") else "0", True)
TAILER = CallerIdentity("uid", "999998", True)
ARGS = {"command": "ls -la"}
TOOL_USE = {"type": "assistant", "uuid": "u-1", "message": {"id": "msg_1", "model": "claude-x", "content": [
    {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": ARGS}]}}
RESULT = {"type": "user", "uuid": "u-2", "message": {"content": [
    {"type": "tool_result", "tool_use_id": "toolu_1", "content": "file listing"}]}}
PROMPT = {"type": "user", "uuid": "u-3", "message": {"role": "user", "content": "deploy the build to staging-7731"}}
NEXT = {"type": "assistant", "uuid": "u-4", "message": {"id": "msg_2", "model": "claude-x", "content": [
    {"type": "tool_use", "id": "toolu_2", "name": "Read", "input": {"file_path": "a.txt"}}]}}


def line(e):
    return (json.dumps(e) + "\n").encode()


class Run:
    """The run handle the tailer calls, answered in process for `identity`."""

    def __init__(self, signer, out, identity=ME, token=None):
        self.signer, self.identity, self.seq = signer, identity, 0
        self.run_id, self.run_token = out["run_id"], token or out["run_token"]

    def call(self, method, **fields):
        req = {"run_id": self.run_id, "run_token": self.run_token, **fields}
        if "request_id" in REQUESTS[method]["properties"]:
            req["request_id"] = uuid.uuid4().hex
        if "client_seq" in REQUESTS[method]["properties"]:
            req.update(stream="tailer", client_seq=self.seq)
            self.seq += 1
        return self.signer.call(self.identity, method, req)


@unittest.skipIf(os.name == "nt", "the tailer is POSIX-only")
class Tailer(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.signer = svc.SignerService(os.path.join(self.d, "data"), grace_s=600, fsck_every_s=0,
                                        authorize={f"uid:{TAILER.subject}": install.TAILER_METHODS})
        self.addCleanup(self.signer.close)
        self.out = self.signer.register_run({"request_id": "r", "agent": {"name": "claude-code"}})
        self.run = Run(self.signer, self.out)
        self.path = os.path.join(self.d, "session.jsonl")

    def write(self, *entries, mode="ab"):
        with open(self.path, mode) as f:
            f.write(b"".join(e if isinstance(e, bytes) else line(e) for e in entries))

    def tail(self, *steps, uid=None, run=None):
        """Tail until every step has run, one per wake."""
        until, steps = os.path.join(self.d, "until"), list(steps)
        open(until, "w").close()

        def wait():
            steps.pop(0)() if steps else os.remove(until)
        tailer.tail(run or self.run, self.path, os.getuid() if uid is None else uid, until, wait)

    def events(self):
        return Run(self.signer, self.out).call("read", limit=1000)["events"]

    def lost(self):
        return [e["data"]["reason"] for e in self.events()
                if e["type"] == "capture.gap" and e["data"]["kind"] == "tailer_lost"]

    def test_tool_uses_and_results_become_model_events_accepted_in_the_closing_window(self):
        self.write(TOOL_USE, RESULT)
        Run(self.signer, self.out).call("close_run")
        self.tail(lambda: self.write(NEXT))
        ex = [e["data"] for e in self.events() if e["type"] == "model.exchange"]
        self.assertEqual([(x["exchange_id"], x["phase"]) for x in ex], [("msg_1", "response"), ("msg_2", "response")])
        self.assertEqual([(t["id"], t["name"], t["executed_by"]) for t in ex[0]["tool_uses"]],
                         [("toolu_1", "Bash", "client")])
        self.assertTrue(ex[0]["tool_uses"][0]["args_commitment"].startswith("hmac-sha256:"))
        self.assertEqual((ex[0]["tool_results_sent"], ex[1]["tool_results_sent"]), ([], ["toolu_1"]))
        self.assertEqual(self.lost(), [])

    def test_the_args_commitment_opens_with_the_hooks_args_digest(self):
        self.write(TOOL_USE)
        self.tail()
        e = next(e for e in self.events() if e["type"] == "model.exchange")
        label = "model.exchange:" + e["data"]["salt_id"]
        self.assertEqual(e["data"]["tool_uses"][0]["args_commitment"],
                         self.signer._commit(label, event_hash({"tool": "Bash", "args": ARGS})))

    def test_a_prompt_is_recorded_only_as_a_commitment(self):
        self.write(PROMPT)
        self.tail()
        ex = [e["data"] for e in self.events() if e["type"] == "model.exchange"]
        self.assertEqual([(x["exchange_id"], x["phase"]) for x in ex], [("u-3", "request")])
        self.assertTrue(ex[0]["content_digest"].startswith("hmac-sha256:"))
        with open(os.path.join(self.d, "data", "store", "records.jsonl")) as f:
            self.assertNotIn("staging-7731", f.read())

    def test_symlink_at_open_is_lost(self):
        other = os.path.join(self.d, "other.jsonl")
        with open(other, "wb") as f:
            f.write(line(TOOL_USE))
        os.symlink(other, self.path)
        self.tail()
        self.assertEqual(len(self.lost()), 1)
        self.assertIn("cannot open the transcript", self.lost()[0])
        self.assertFalse(any(e["type"] == "model.exchange" for e in self.events()))

    def test_symlink_at_a_later_open_is_lost(self):
        other = os.path.join(self.d, "other.jsonl")
        open(other, "w").close()
        self.tail(lambda: None, lambda: os.symlink(other, self.path))   # the transcript appears as a symlink
        self.assertIn("cannot open the transcript", self.lost()[0])

    def test_symlink_swapped_in_after_open_is_lost(self):
        self.write(TOOL_USE)
        other = os.path.join(self.d, "other.jsonl")
        open(other, "w").close()

        def swap():
            os.remove(self.path)
            os.symlink(other, self.path)
        self.tail(swap)
        self.assertEqual(self.lost(), [f"a symlink replaced the transcript (at transcript offset {len(line(TOOL_USE))}; "
                                       f"reported by uid:{ME.subject})"])

    def test_truncation_between_polls_is_lost(self):
        self.write(TOOL_USE, RESULT)
        self.tail(lambda: open(self.path, "r+").truncate(10))
        self.assertIn("shrank to 10 bytes", self.lost()[0])

    def test_replacement_is_lost(self):
        self.write(TOOL_USE)

        def replace():
            new = self.path + ".new"
            with open(new, "wb") as f:
                f.write(line(TOOL_USE) + line(NEXT))
            os.replace(new, self.path)
        self.tail(replace)
        self.assertIn("another file replaced the transcript", self.lost()[0])
        self.assertEqual(len([e for e in self.events() if e["type"] == "model.exchange"]), 1)

    def test_a_line_already_read_edited_in_place_is_lost(self):
        self.write(TOOL_USE, RESULT)

        def edit():   # same size, same inode
            with open(self.path, "r+b") as f:
                data = f.read()
                f.seek(0)
                f.write(data.replace(b"ls -la", b"ls -lR"))
        self.tail(edit, lambda: self.write(NEXT))
        self.assertIn("a line already read changed in place", self.lost()[0])
        self.assertEqual(len([e for e in self.events() if e["type"] == "model.exchange"]), 1)

    def test_owner_mismatch_is_refused(self):
        self.write(TOOL_USE)
        self.tail(uid=os.getuid() + 1)
        self.assertIn(f"not a regular file of uid {os.getuid() + 1}", self.lost()[0])
        self.assertFalse(any(e["type"] == "model.exchange" for e in self.events()))

    def test_an_unreadable_line_is_lost(self):
        self.write(TOOL_USE, b"{not json\n")
        self.tail()
        self.assertEqual(self.lost(), [f"the line at offset {len(line(TOOL_USE))} is not a JSON object "
                                       f"(at transcript offset {len(line(TOOL_USE))}; reported by uid:{ME.subject})"])

    def test_a_transcript_that_never_appears_is_lost(self):
        self.tail(lambda: None)
        self.assertIn("the transcript never appeared", self.lost()[0])

    @unittest.skipIf(os.name != "nt" and os.getuid() == 0, "root reads past the permissions")
    def test_a_transcript_it_may_not_reach_is_lost(self):
        sub = os.path.join(self.d, "projects")
        os.mkdir(sub, 0o700)
        self.path = os.path.join(sub, "session.jsonl")
        self.write(TOOL_USE)
        os.chmod(sub, 0o600)   # no search: the file exists but cannot be opened
        self.addCleanup(os.chmod, sub, 0o700)
        self.tail()
        self.assertIn("cannot open the transcript: Permission denied", self.lost()[0])

    def test_a_tailer_that_stops_while_the_run_is_open_is_lost(self):
        self.write(TOOL_USE)
        with mock.patch.object(tailer, "IDLE_TAILER_S", -1):
            self.tail(lambda: self.fail("still tailing after the idle limit"))
        self.assertIn("the tailer stopped", self.lost()[0])
        self.assertEqual(len([e for e in self.events() if e["type"] == "model.exchange"]), 1)

    def test_a_partial_line_waits_for_its_end(self):
        raw = line(TOOL_USE)
        self.write(raw[:20])
        self.tail(lambda: self.write(raw[20:]))
        self.assertEqual(len([e for e in self.events() if e["type"] == "model.exchange"]), 1)
        self.assertEqual(self.lost(), [])

    def test_the_tailer_stops_once_the_run_is_final(self):
        Run(self.signer, self.out).call("close_run")
        self.signer.grace_s = 0
        self.signer.sweep()
        self.write(TOOL_USE)
        self.tail(lambda: self.fail("still tailing a final run"))

    def test_a_client_cannot_send_a_gap_record(self):
        for method, fields in (("model_event", {"provider": "p", "model": "m", "phase": "request"}),
                               ("state_write", {"key": "k", "value_digest": "sha256:" + "0" * 64})):
            self.run.call(method, **fields)   # accepted as such
            with self.assertRaises(RPCError) as cm:
                self.run.call(method, **fields, type="capture.gap", kind="tailer_lost")
            self.assertEqual(cm.exception.code, "invalid_request")
        with self.assertRaises(RPCError) as cm:
            self.signer.call(ME, "capture_gap", {"kind": "tailer_lost", "reason": "x"})
        self.assertEqual(cm.exception.code, "invalid_request")
        self.assertEqual(self.lost(), [])

    def test_a_delegated_token_works_only_for_its_identity_and_the_authorized_calls(self):
        token = self.run.call("delegate_run", identity=f"uid:{TAILER.subject}")["run_token"]
        as_tailer = Run(self.signer, self.out, TAILER, token)
        self.write(TOOL_USE, b"oops\n")
        self.tail(run=as_tailer)
        self.assertEqual(len(self.lost()), 1)   # written by the signer, from the tailer's report
        for method, code in (("close_run", "forbidden"), ("delegate_run", "forbidden")):
            with self.assertRaises(RPCError) as cm:
                as_tailer.call(method, **({"identity": "uid:1"} if method == "delegate_run" else {}))
            self.assertEqual(cm.exception.code, code)
        with self.assertRaises(RPCError) as cm:   # the owner's token is not the tailer's
            Run(self.signer, self.out, TAILER).call("model_event", provider="p", model="m", phase="request")
        self.assertEqual(cm.exception.code, "run_token_invalid")
        with self.assertRaises(RPCError) as cm:   # nor the tailer's the owner's
            Run(self.signer, self.out, ME, token).call("model_event", provider="p", model="m", phase="request")
        self.assertEqual(cm.exception.code, "run_token_invalid")
        self.assertIn(f"reported by uid:{TAILER.subject}", self.lost()[0])

    def test_a_run_is_delegated_only_to_an_identity_with_an_authorize_entry(self):
        with self.assertRaises(RPCError) as cm:   # unconfigured, a uid would keep every method of the run
            self.run.call("delegate_run", identity="uid:4242")
        self.assertEqual(cm.exception.code, "forbidden")

    @unittest.skipUnless(sys.platform.startswith("linux"), "inotify is Linux-only")
    def test_inotify_wakes_on_an_append(self):
        self.write(TOOL_USE)
        wait = tailer._waiter(self.path)
        self.write(NEXT)
        t = time.monotonic()
        wait()
        self.assertLess(time.monotonic() - t, tailer.POLL_S / 2)


@unittest.skipIf(os.name == "nt", "the tailer is POSIX-only")
class HookStartsTheTailer(unittest.TestCase):
    def setUp(self):
        from tracekit.integrations import claude_code
        self.cc, d = claude_code, tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, d, True)
        env = mock.patch.dict(os.environ, {"TRACEKIT_RUNTIME_DIR": d})
        env.start()
        self.addCleanup(env.stop)
        self.client = mock.Mock()
        self.client.register_run.return_value = {"run_id": "run-1", "run_token": "tok"}
        self.client.call.return_value = {"run_token": "delegated"}

    def start(self, system=None, sid="s1"):
        p = {"hook_event_name": "SessionStart", "session_id": sid, "transcript_path": "/home/agent/t.jsonl"}
        popen = mock.Mock()
        with mock.patch.object(self.cc.subprocess, "Popen", popen), \
                mock.patch.object(self.cc, "system_config", return_value=system), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.cc._handle(self.client, p, "SessionStart", sid, None), 0)
        return popen

    def test_dev_mode_starts_one_same_user_tailer_per_run(self):
        popen = self.start()
        argv = popen.call_args.args[0]
        self.assertEqual(argv[1:], ["-I", "-m", "tracekit.tailer"])
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        handle = json.loads(popen.return_value.stdin.write.call_args.args[0])
        self.assertEqual(handle, {"run_id": "run-1", "run_token": "tok", "path": "/home/agent/t.jsonl",
                                  "until": self.cc._state("s1")})
        self.start().assert_not_called()   # SessionStart again (resume, clear): the run has its tailer

    def test_system_mode_runs_it_as_the_tailer_user_with_a_delegated_token(self):
        t = {"user": "tracekit-tailer", "uid": 999998, "python": "/opt/tracekit/bin/python"}
        popen = self.start({"signer": "/run/s.sock", "tailer": t})
        self.assertEqual(popen.call_args.args[0], ["sudo", "-n", "-u", "tracekit-tailer", "/opt/tracekit/bin/python",
                                                   "-I", "-m", "tracekit.tailer"])
        self.assertEqual(self.client.call.call_args.args,
                         ("delegate_run", {"run_id": "run-1", "run_token": "tok", "identity": "uid:999998"}))
        handle = json.loads(popen.return_value.stdin.write.call_args.args[0])
        self.assertEqual(handle, {"run_id": "run-1", "run_token": "delegated", "path": "/home/agent/t.jsonl"})

    def test_system_mode_without_a_tailer_records_a_tailer_lost_gap(self):
        self.start({"signer": "/run/s.sock"}).assert_not_called()
        self.assertEqual(self.client.call.call_args.args, ("tailer_lost", {
            "run_id": "run-1", "run_token": "tok", "reason": "no transcript tailer is installed", "offset": 0}))

    def test_a_run_registered_after_an_idle_close_gets_its_own_tailer(self):
        self.start()
        self.client.register_run.return_value = {"run_id": "run-2", "run_token": "tok-2"}
        closed = [True]

        def call(method, req):
            if closed.pop() if closed else False:
                raise RPCError("run_closed", req["run_id"])
            return {"decision": "allow"}
        self.client.call.side_effect = call
        popen = mock.Mock()
        with mock.patch.object(self.cc.subprocess, "Popen", popen), \
                mock.patch.object(self.cc, "system_config", return_value=None):
            self.cc._run(self.client, "s1", send="decide", tool_call_id="t", tool="Bash", args={}, args_source="parsed")
        handle = json.loads(popen.return_value.stdin.write.call_args.args[0])
        self.assertEqual((handle["run_id"], handle["path"]), ("run-2", "/home/agent/t.jsonl"))


if __name__ == "__main__":
    unittest.main()
