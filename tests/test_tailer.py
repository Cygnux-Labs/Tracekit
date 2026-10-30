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
from tracekit.deploy import files
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.sdk.client import SignerUnavailable
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
# the lines Claude Code writes before a tool_use line of the same message: one per content block
THINKING = {"type": "assistant", "uuid": "u-5", "cwd": "/work/proj", "message": {"id": "msg_1", "model": "claude-x",
            "content": [{"type": "thinking", "thinking": "list the files first", "signature": "EqQBsealed"}]}}
SAID = {"type": "assistant", "uuid": "u-6", "cwd": "/work/proj", "message": {"id": "msg_1", "model": "claude-x",
        "content": [{"type": "text", "text": "Listing the files."}]}}


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
        if "client_seq" in REQUESTS[method]["properties"] and "client_seq" not in fields:
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

    def tail(self, *steps, uid=None, run=None, status=None, offsets=None):
        """Tail until every step has run, one per wake."""
        until, steps = os.path.join(self.d, "until"), list(steps)
        open(until, "w").close()

        def wait():
            steps.pop(0)() if steps else os.remove(until)
        tailer.tail(run or self.run, self.path, os.getuid() if uid is None else uid, until, wait, status, offsets)

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

    def sub(self, *entries, name="agent-a1.jsonl"):
        """Append to a subagent's transcript, where Claude Code writes it: <session>/subagents/agent-*.jsonl (a
        workflow's agent's: <session>/subagents/workflows/<workflow>/agent-*.jsonl)."""
        path = os.path.join(self.d, "session", "subagents", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "ab") as f:
            f.write(b"".join(line(e) for e in entries))
        return path

    def test_subagent_tool_uses_are_reported_as_they_appear(self):
        self.write(TOOL_USE)
        sub_use = {**NEXT, "message": {**NEXT["message"], "id": "msg_s1"}}
        self.tail(lambda: self.sub(PROMPT), lambda: self.sub(sub_use), lambda: self.write(RESULT))
        ex = [e["data"] for e in self.events() if e["type"] == "model.exchange" and e["data"]["phase"] == "response"]
        self.assertEqual(sorted(x["exchange_id"] for x in ex), ["msg_1", "msg_s1"])
        self.assertEqual([t["id"] for x in ex if x["exchange_id"] == "msg_s1" for t in x["tool_uses"]], ["toolu_2"])
        self.assertEqual(self.lost(), [])

    def test_a_subagent_line_already_read_edited_in_place_is_lost(self):
        self.write(TOOL_USE)
        path = self.sub(NEXT)

        def edit():
            with open(path, "r+b") as f:
                data = f.read()
                f.seek(0)
                f.write(data.replace(b"a.txt", b"b.txt"))
        self.tail(lambda: None, edit, lambda: None)
        self.assertIn("subagent transcript agent-a1.jsonl: a line already read changed in place", self.lost()[0])

    def test_a_workflows_agents_calls_reconcile_and_a_decide_no_transcript_asks_for_is_still_fabricated(self):
        """A workflow's agents (Claude Code's Workflow tool) decide under the session's run, and their transcripts are in
        <session>/subagents/workflows/<workflow>/: the tailer never read them, so each of their calls was a
        reconcile.fabricated gap (60,227 in one dev store). Read, they reconcile; a decide no transcript asks for is
        still fabricated."""
        hook = Run(self.signer, self.out)
        for tcid, tool, args in (("toolu_1", "Bash", ARGS), ("toolu_2", "Read", {"file_path": "a.txt"}),
                                 ("toolu_9", "Bash", {"command": "ls /tmp"})):
            hook.call("decide", tool_call_id=tcid, tool=tool, args=args, args_source="parsed")
        self.write(TOOL_USE)
        wf_use = {**NEXT, "message": {**NEXT["message"], "id": "msg_w1"}}
        self.tail(lambda: self.sub(wf_use, name=os.path.join("workflows", "wf_1-a2b", "agent-a2.jsonl")))
        hook.call("close_run")
        self.signer.sweep(time.monotonic() + 3600)
        with open(os.path.join(self.d, "data", "store", "records.jsonl"), "rb") as f:
            events = [json.loads(x)["event"] for x in f.read().splitlines()]
        self.assertEqual([(e["type"], e.get("tool_call_id")) for e in events if e["type"].startswith("reconcile.")],
                         [("reconcile.fabricated", "toolu_9")])
        self.assertEqual(self.lost(), [])

    def test_a_symlink_among_a_workflows_transcripts_is_lost(self):
        """A workflow's directories are checked as the subagents' one is: a symlink in place of `workflows` or of one
        workflow's directory, or a transcript that is a symlink (opened with O_NOFOLLOW), stops the tailer with a
        signed tailer_lost."""
        self.write(TOOL_USE)
        elsewhere = os.path.join(self.d, "elsewhere")
        os.makedirs(os.path.join(elsewhere, "wf_9"))
        with open(os.path.join(elsewhere, "agent-a9.jsonl"), "wb") as f:
            f.write(line(PROMPT))
        w = os.path.join(self.d, "session", "subagents", "workflows")
        for target, link, want in (
                (elsewhere, w, f"a symlink is in place of {w}"),
                (elsewhere, os.path.join(w, "wf_1"), f"a symlink is in place of {os.path.join(w, 'wf_1')}"),
                (os.path.join(elsewhere, "agent-a9.jsonl"), os.path.join(w, "wf_1", "agent-a2.jsonl"),
                 "subagent transcript agent-a2.jsonl: cannot open the transcript")):
            with self.subTest(link=os.path.relpath(link, w)):
                shutil.rmtree(os.path.join(self.d, "session"), ignore_errors=True)
                os.makedirs(os.path.dirname(link))
                os.symlink(target, link)
                self.tail(lambda: None)
                self.assertIn(want, self.lost()[-1])

    def test_a_symlink_in_place_of_the_subagents_directory_is_lost(self):
        self.write(TOOL_USE)
        elsewhere = os.path.join(self.d, "elsewhere")
        os.makedirs(os.path.join(self.d, "session"))
        os.mkdir(elsewhere)
        os.symlink(elsewhere, os.path.join(self.d, "session", "subagents"))
        self.tail(lambda: None)
        self.assertIn("a symlink is in place of", self.lost()[0])

    def test_a_later_run_of_the_session_starts_where_the_earlier_runs_lines_end(self):
        # after an idle close, or a resumed session: the transcript's lines so far are an earlier run's
        self.write(PROMPT, TOOL_USE, RESULT)
        sub = self.sub(PROMPT)
        offsets = {self.path: os.path.getsize(self.path), sub: os.path.getsize(sub)}
        self.tail(lambda: self.write(NEXT), lambda: self.sub(THINKING), offsets=offsets)
        ex = [e["data"] for e in self.events() if e["type"] == "model.exchange"]
        self.assertEqual([(x["exchange_id"], x["phase"]) for x in ex], [("msg_2", "response"), ("msg_1", "response")])
        self.assertEqual(self.lost(), [])

    def test_an_earlier_runs_line_changed_before_a_later_run_reads_on_is_lost(self):
        self.write(TOOL_USE, RESULT)
        end = os.path.getsize(self.path)
        with open(self.path, "r+b") as f:
            data = f.read()
            f.seek(0)
            f.write(data.replace(b"ls -la", b"ls -lh"))

        def edit():   # once the tailer has read the earlier lines, as the hook left them
            with open(self.path, "r+b") as f:
                f.write(data)
        self.tail(lambda: None, edit, offsets={self.path: end})
        self.assertIn("a line already read changed in place", self.lost()[0])
        self.tail(offsets={self.path: os.path.getsize(self.path) + 1})   # past its end: it was rewritten
        self.assertIn("shrank", self.lost()[-1])

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

    def test_thinking_and_text_lines_are_model_events_committed_only_without_the_vault(self):
        self.write(PROMPT, THINKING, SAID, TOOL_USE)
        self.tail()
        ex = [e["data"] for e in self.events() if e["type"] == "model.exchange"]
        self.assertEqual([(x["exchange_id"], x["phase"], "tool_uses" in x) for x in ex],
                         [("u-3", "request", False), ("msg_1", "response", False), ("msg_1", "response", False),
                          ("msg_1", "response", True)])
        self.assertTrue(all(x["content_digest"].startswith("hmac-sha256:") for x in ex))
        self.assertEqual([x.get("tool_results_sent") for x in ex[1:]], [None, None, []])   # on the tool_use line only
        with open(os.path.join(self.d, "data", "store", "records.jsonl")) as f:
            stored = f.read()
        for text in ("list the files first", "Listing the files", "EqQBsealed", "/work/proj"):
            self.assertNotIn(text, stored)
        label = "model.exchange:" + ex[1]["salt_id"]   # the commitment is to the line as read
        self.assertEqual(ex[1]["content_digest"], self.signer._commit(label, event_hash({"transcript": "main",
                                                                                         "entry": THINKING})))
        self.assertEqual(self.lost(), [])

    def test_with_the_vault_each_line_is_kept_whole_and_opens_its_commitment(self):
        signer = svc.SignerService(os.path.join(self.d, "vault"), grace_s=600, fsck_every_s=0,
                                   content={"retain": True},
                                   authorize={f"uid:{ME.subject}": sorted(svc.DEFAULT_GRANTS | {svc.CONTENT_READ})})
        self.addCleanup(signer.close)
        out = signer.register_run({"request_id": "r", "agent": {"name": "claude-code"}})
        prompt = {**PROMPT, "cwd": "/work/proj", "isMeta": False}
        self.write(prompt, THINKING, TOOL_USE)
        sub = {**SAID, "isSidechain": True, "message": {**SAID["message"], "id": "msg_s"}}
        self.tail(lambda: self.sub(sub), run=Run(signer, out),
                  status=lambda: signer.call(ME, "status", {}))
        recs = [e for e in Run(signer, out).call("read", limit=100)["events"] if e["type"] == "model.exchange"]
        got = signer.call(ME, "content_get", {"run_id": out["run_id"], "seqs": [e["run_seq"] for e in recs],
                                              "purpose": "test"})["items"]
        self.assertEqual([x["content"] for x in got], [
            {"transcript": "main", "entry": prompt}, {"transcript": "main", "entry": THINKING},
            {"transcript": "main", "entry": TOOL_USE}, {"transcript": "agent-a1.jsonl", "entry": sub}])
        self.assertTrue(all("salt" in x for x in got))   # each opens its record's commitment

    def test_a_burst_of_lines_past_the_rate_limit_is_sent_whole(self):
        signer = svc.SignerService(os.path.join(self.d, "burst"), grace_s=600, fsck_every_s=0,
                                   limits=svc.Limits(events_per_s=2000, burst=50))
        self.addCleanup(signer.close)
        out = signer.register_run({"request_id": "r", "agent": {"name": "claude-code"}})
        self.write(*({**SAID, "uuid": f"u-{i}"} for i in range(1000)))
        self.tail(run=Run(signer, out))
        events = [e for e in Run(signer, out).call("read", limit=1000, from_seq=0)["events"]]
        n = sum(e["type"] == "model.exchange" for e in events)
        if n < 1000:   # read pages
            n += sum(e["type"] == "model.exchange" for e in Run(signer, out).call(
                "read", limit=1000, from_seq=events[-1]["run_seq"] + 1)["events"])
        self.assertEqual(n, 1000)
        self.assertFalse([e for e in events if e["type"] == "capture.gap"])

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
        self.cc, self.d = claude_code, tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, self.d, True)
        env = mock.patch.dict(os.environ, {"TRACEKIT_RUNTIME_DIR": self.d})
        env.start()
        self.addCleanup(env.stop)
        self.client = mock.Mock()
        self.client.register_run.return_value = {"run_id": "run-1", "run_token": "tok"}
        self.client.call.return_value = {"run_token": "delegated"}

    def start(self, system=None, sid="s1", path="/home/agent/t.jsonl", source="startup"):
        p = {"hook_event_name": "SessionStart", "session_id": sid, "transcript_path": path, "source": source}
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
                                  "offsets": {"/home/agent/t.jsonl": 0}, "until": self.cc._state("s1")})
        self.start().assert_not_called()   # SessionStart again (resume, clear): the run has its tailer

    def test_system_mode_runs_it_as_the_tailer_user_with_a_delegated_token(self):
        t = {"user": "tracekit-tailer", "uid": 999998, "python": "/opt/tracekit/bin/python"}
        popen = self.start({"signer": "/run/s.sock", "tailer": t})
        self.assertEqual(popen.call_args.args[0], ["sudo", "-n", "-u", "tracekit-tailer", "/opt/tracekit/bin/python",
                                                   "-I", "-m", "tracekit.tailer"])
        self.assertEqual(self.client.call.call_args.args,
                         ("delegate_run", {"run_id": "run-1", "run_token": "tok", "identity": "uid:999998"}))
        handle = json.loads(popen.return_value.stdin.write.call_args.args[0])
        self.assertEqual(handle, {"run_id": "run-1", "run_token": "delegated", "path": "/home/agent/t.jsonl",
                                  "offsets": {"/home/agent/t.jsonl": 0}})

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

    def transcript(self, *entries):
        path = os.path.join(self.d, "t.jsonl")
        with open(path, "ab") as f:
            f.write(b"".join(e if isinstance(e, bytes) else line(e) for e in entries))
        return path

    def decide(self, closed=False):
        """A PreToolUse's decide, on a run the signer has idle-closed if `closed`. -> the handle of the tailer it
        started, if any."""
        def call(method, req):
            if closed and req["run_id"] == "run-1":
                raise RPCError("run_closed", req["run_id"])
            return {"decision": "allow"}
        self.client.call.side_effect = call
        popen = mock.Mock()
        with mock.patch.object(self.cc.subprocess, "Popen", popen), \
                mock.patch.object(self.cc, "system_config", return_value=None):
            self.cc._run(self.client, "s1", send="decide", tool_call_id="t", tool="Bash", args={}, args_source="parsed")
        return popen.called and json.loads(popen.return_value.stdin.write.call_args.args[0])

    def test_a_run_after_an_idle_close_reads_on_where_the_earlier_run_was_last_seen_open(self):
        path = self.transcript(PROMPT, TOOL_USE)
        self.start(path=path)
        sub = os.path.join(self.d, "t", "subagents", "agent-a1.jsonl")
        wf = os.path.join(self.d, "t", "subagents", "workflows", "wf_1", "agent-a2.jsonl")   # a workflow's agent's
        for p in (sub, wf):
            os.makedirs(os.path.dirname(p))
            with open(p, "wb") as f:
                f.write(line(PROMPT))
        self.transcript(b'{"type": "assistant", "uuid": "u-')   # a line Claude Code is still writing
        self.assertFalse(self.decide())   # run 1 takes it: those lines are its tailer's
        seen = {path: len(line(PROMPT) + line(TOOL_USE)), sub: len(line(PROMPT)), wf: len(line(PROMPT))}
        self.transcript(b'7"}\n', RESULT, NEXT)   # Claude Code writes on; then an hour passes, and run 1 is closed
        self.client.register_run.return_value = {"run_id": "run-2", "run_token": "tok-2"}
        self.assertEqual(self.decide(closed=True)["offsets"], seen)

    def test_a_session_that_goes_on_with_no_state_reads_on_from_where_its_transcript_ends(self):
        """A SessionEnd removes the session's state; Claude Code then went on with the session (a message to it, a usage
        limit's reset) with no SessionStart. Its new run had no tailer until a compaction's SessionStart started one
        from the transcript's first line: every earlier run's call was a hook_missing gap again (2,840 in one run)."""
        path = self.transcript(PROMPT, TOOL_USE, RESULT)
        p = {"hook_event_name": "UserPromptSubmit", "session_id": "s1", "transcript_path": path, "prompt": "go on"}
        popen = mock.Mock()
        with mock.patch.object(self.cc.subprocess, "Popen", popen), \
                mock.patch.object(self.cc, "system_config", return_value=None):
            self.cc._handle(self.client, p, "UserPromptSubmit", "s1", None)
        handle = json.loads(popen.return_value.stdin.write.call_args.args[0])
        self.assertEqual(handle["offsets"], {path: os.path.getsize(path)})

    def prompt(self, path, popen, system=None):
        """A UserPromptSubmit of session s1 naming transcript `path`, tailers started through the mock `popen`."""
        p = {"hook_event_name": "UserPromptSubmit", "session_id": "s1", "transcript_path": path, "prompt": "go on"}
        with mock.patch.object(self.cc.subprocess, "Popen", popen), \
                mock.patch.object(self.cc, "system_config", return_value=system):
            return self.cc._handle(self.client, p, "UserPromptSubmit", "s1", None)

    def test_a_run_a_prompts_later_call_registers_starts_its_tailer_at_once(self):
        # the prompt's first call can't reach the signer; one of its observations then registers the run
        path = self.transcript(PROMPT, TOOL_USE, RESULT)
        self.client.register_run.side_effect = [SignerUnavailable("busy"), {"run_id": "run-1", "run_token": "tok"}]
        popen = mock.Mock()
        with self.assertRaises(SignerUnavailable):
            self.prompt(path, popen)
        self.assertEqual(json.loads(popen.return_value.stdin.write.call_args.args[0])["offsets"],
                         {path: os.path.getsize(path)})

    def test_a_tailer_started_again_after_a_failed_start_reads_from_where_its_run_began(self):
        path = self.transcript(PROMPT, TOOL_USE, RESULT)
        begun, popen = os.path.getsize(path), mock.Mock()
        system = {"signer": "/run/s.sock", "tailer": {"user": "tracekit-tailer", "uid": 999998,
                                                      "python": "/opt/tracekit/bin/python"}}
        self.client.call.side_effect = RPCError("forbidden", "delegate_run refused")
        with self.assertRaises(RPCError):
            self.prompt(path, popen, system)
        popen.assert_not_called()
        self.transcript(NEXT)   # the run's own lines, written before its next event
        self.client.call.side_effect = None
        self.assertEqual(self.prompt(path, popen, system), 0)
        self.assertEqual(json.loads(popen.return_value.stdin.write.call_args.args[0])["offsets"], {path: begun})

    def test_a_run_whose_tailer_starts_after_its_first_event_reads_on_from_where_the_transcript_ends(self):
        # a run an earlier hook registered with no transcript known: a compaction's SessionStart names it hours later
        files.write_json(self.cc._state("s1"), {"run_id": "run-1", "run_token": "tok", "stream": "x", "seq": 3})
        path = self.transcript(PROMPT, TOOL_USE, RESULT)
        handle = json.loads(self.start(path=path, source="compact").return_value.stdin.write.call_args.args[0])
        self.assertEqual(handle["offsets"], {path: os.path.getsize(path)})

    def test_a_resumed_sessions_run_reads_its_transcript_from_where_it_ends(self):
        path = self.transcript(PROMPT, TOOL_USE, RESULT, b'{"partial')   # the session's history: earlier runs'
        handle = json.loads(self.start(path=path, source="resume").return_value.stdin.write.call_args.args[0])
        self.assertEqual(handle["offsets"], {path: os.path.getsize(path) - len(b'{"partial')})


if __name__ == "__main__":
    unittest.main()
