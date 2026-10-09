"""Trust decisions in the hook, client, signer approvals, SDK bridge and migration.

    python3 -m pytest tests/test_trust_hardening.py -q
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

try:
    import pwd
except ImportError:  # Windows
    pwd = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import autotrace, bridge, client, hook, migrate, policy  # noqa: E402
from tracekit.core import GENESIS, SCHEMA_VERSION, canon, new_id, now_ts  # noqa: E402
from factories import DaemonCase, ev, ledger_records, make_signer, run_start, tool_call  # noqa: E402

AGENT_UID, OTHER_UID = 1001, 1002


class _ClientHome(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        env = mock.patch.dict(os.environ, {"TRACEKIT_CLIENT_HOME": os.path.join(self.d, "client")})
        env.start()
        self.addCleanup(env.stop)


class StateNames(_ClientHome):
    def test_run_ids_that_used_to_collide_get_distinct_files(self):
        long_a, long_b = "x" * 120 + "a", "x" * 120 + "b"
        for a, b in (("a/b", "a_b"), (long_a, long_b)):
            self.assertNotEqual(client.state_name(a), client.state_name(b))
            self.assertNotEqual(hook._started_flag(a), hook._started_flag(b))
            self.assertNotEqual(client._RunLock(a).path, client._RunLock(b).path)

    def test_state_under_the_legacy_name_is_carried_over(self):
        runs = os.path.join(client.client_dir(), "runs")
        with open(os.path.join(runs, "sess_1.json"), "w") as f:
            json.dump({"cseq": 5, "gap": None}, f)
        open(os.path.join(runs, "sess_1.started"), "w").close()
        with client._RunLock("sess/1") as rl:
            self.assertEqual(rl.state["cseq"], 5)
        self.assertTrue(os.path.exists(hook._started_flag("sess/1")))
        self.assertFalse(os.path.exists(os.path.join(runs, "sess_1.json")))


class TranscriptPath(unittest.TestCase):
    def test_session_id_cannot_leave_the_transcript_directory(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        main = os.path.join(d, "proj", "s.jsonl")
        outside = os.path.join(d, "subagents", "agent-a1.jsonl")  # what "<proj>/../subagents/..." would reach
        os.makedirs(os.path.dirname(main))
        os.makedirs(os.path.dirname(outside))
        for f in (main, outside):
            open(f, "w").close()
        for sid in ("..", "../proj", "/etc", "a/b", "a\\b", ""):
            self.assertEqual(hook.transcript_path_for({"transcript_path": main, "session_id": sid, "agent_id": "a1"}), main, sid)
        self.assertEqual(hook.transcript_path_for({"transcript_path": main, "session_id": "s", "agent_id": "../a1"}), main)
        ok = os.path.join(d, "proj", "s", "subagents", "agent-a1.jsonl")
        os.makedirs(os.path.dirname(ok))
        open(ok, "w").close()
        self.assertEqual(hook.transcript_path_for({"transcript_path": main, "session_id": "s", "agent_id": "a1"}), ok)


class HookMain(_ClientHome):
    def run_hook(self, payload, fail_mode="open", send=None, **pol_extra):
        pol, raw = policy.load()
        pol = dict(pol, fail_mode=fail_mode, **pol_extra)
        sent = []

        def fake_send(ev, attach=None, stream="hook"):
            sent.append(ev)
            return send(ev) if send else {"ok": True}
        with mock.patch.object(policy, "load", return_value=(pol, raw)), mock.patch.object(client, "send", fake_send), \
                mock.patch("sys.stdin", io.StringIO(json.dumps(payload))), mock.patch("sys.stderr", io.StringIO()) as err:
            code = hook.main()
        return code, sent, err.getvalue()

    def test_missing_ids_are_not_merged_into_one_run(self):
        pre = {"hook_event_name": "PreToolUse", "cwd": self.d, "tool_name": "Bash", "tool_input": {"command": "ls"}}
        for payload, run in ((pre, "_unattributed"), (dict(pre, session_id="s1"), "s1"),
                             ({"hook_event_name": "UserPromptSubmit", "prompt": "hi"}, "_unattributed")):
            code, sent, err = self.run_hook(payload)
            self.assertEqual(code, 0, payload)
            self.assertEqual([(e["type"], e["run_id"], e["data"]["kind"]) for e in sent], [("capture.gap", run, "missing_ids")])
            self.assertIn("event not recorded", err)
        self.assertEqual(self.run_hook(pre, "closed")[0], 2)
        denied = dict(pre, tool_input={"command": "sudo rm -rf /"})
        self.assertEqual(self.run_hook(denied)[0], 2, "a policy deny still blocks without ids")

    def test_rejected_tool_call_requests_a_gap_and_follows_fail_mode(self):
        pre = {"hook_event_name": "PreToolUse", "session_id": "s1", "cwd": self.d, "tool_name": "Bash",
               "tool_use_id": "t1", "tool_input": {"command": "ls"}}

        def reject_calls(ev):
            return {"ok": False, "error": "refused"} if ev["type"] == "tool.call" else {"ok": True}
        for fail_mode, want in (("closed", 2), ("open", 0)):
            code, sent, _ = self.run_hook(pre, fail_mode, reject_calls)
            self.assertEqual(code, want, fail_mode)
            gaps = [e for e in sent if e["type"] == "capture.gap"]
            self.assertEqual([g["data"]["kind"] for g in gaps], ["client_rejected"])
            self.assertIn("t1", gaps[0]["data"]["reason"])

    def test_rejected_tool_call_blocks_before_an_approval_can_allow_it(self):
        pre = {"hook_event_name": "PreToolUse", "session_id": "s1", "cwd": self.d, "tool_name": "Bash",
               "tool_use_id": "t1", "tool_input": {"command": "git push"}}
        ask = [{"id": "TK-A1", "tool": "Bash", "pattern": r"\bgit\s+push\b", "reason": "push"}]

        def reject_calls(ev):
            return {"ok": False, "error": "refused"} if ev["type"] == "tool.call" else {"ok": True}
        with mock.patch.object(hook, "wait_for_approval", return_value=(True, "approved")):
            self.assertEqual(self.run_hook(pre, "closed", reject_calls, ask=ask)[0], 2)
            self.assertEqual(self.run_hook(pre, "closed", ask=ask)[0], 0)


class LoneSurrogates(DaemonCase):
    def hook(self, payload):
        with mock.patch("sys.stdin", io.StringIO(json.dumps(payload))), mock.patch("sys.stderr", io.StringIO()):
            return hook.main()

    def test_tool_input_and_output_with_lone_surrogates_are_recorded(self):
        base = {"session_id": "s1", "tool_use_id": "t1", "cwd": self.d, "tool_name": "Bash",
                "tool_input": {"command": "echo \ud800"}}
        self.assertEqual(self.hook(dict(base, hook_event_name="PreToolUse")), 0)
        self.assertEqual(self.hook(dict(base, hook_event_name="PostToolUse", tool_response={"stdout": "\ud800"})), 0)
        events = {r["event"]["type"]: r["event"] for r in self.records()}
        self.assertEqual(events["tool.call"]["data"]["input"]["command"]["value"], "echo �")
        self.assertIn("hash", events["tool.result"]["data"]["output"])
        self.assertNotIn("capture.gap", events)


@unittest.skipIf(os.name == "nt", "system config is unsupported on Windows")
class SystemConfigFailsClosed(_ClientHome):
    def entry(self, payload, path):
        with mock.patch.object(client, "SYSTEM_CONFIG", path), mock.patch.dict(os.environ, {"TRACEKIT_FAIL_CLOSED": ""}), \
                mock.patch("sys.stdin", io.StringIO(json.dumps(payload))), mock.patch("sys.stderr", io.StringIO()) as err:
            return hook._entry(), err.getvalue()

    def test_bad_root_config_blocks_only_tool_calls(self):
        path = os.path.join(self.d, "client.json")
        with open(path, "w") as f:
            f.write("{ nope")
        os.chmod(path, 0o644)
        pre = {"hook_event_name": "PreToolUse", "session_id": "s1", "tool_use_id": "t1", "cwd": self.d,
               "tool_name": "Bash", "tool_input": {"command": "ls"}}
        prompt = {"hook_event_name": "UserPromptSubmit", "session_id": "s1", "prompt": "hi"}
        real_stat = os.stat

        def root_owned(p, *a, **kw):  # passes the ownership check, so the parse branch runs
            st = real_stat(p, *a, **kw)
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, 0) + tuple(st)[5:]) if p == path else st
        for owner, want in ((None, "owned by root"), (root_owned, "cannot be parsed")):
            with mock.patch.object(client.os, "stat", owner or real_stat):
                code, err = self.entry(pre, path)
                self.assertEqual(code, 2, want)
                self.assertIn(want, err)
                code, err = self.entry(prompt, path)
                self.assertEqual(code, 0, want)
                self.assertIn(want, err)


class Approvals(unittest.TestCase):
    def signer(self, **cfg):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        s = make_signer(d, **cfg)
        s._run("r").update(started=True, agent_uid=AGENT_UID)
        return s

    def request(self, s, uid=AGENT_UID, tid="t"):
        return s.handle({"op": "approval_request", "run_id": "r", "tool_use_id": tid, "timeout_s": 30}, uid, 999999)

    @unittest.skipIf(os.name == "nt", "needs a POSIX session")
    def test_forged_interactive_flag_is_ignored(self):
        s = self.signer(mode="dev", allow_same_user_approval=True)
        aid = self.request(s)["approval_id"]
        r = s.handle({"op": "approve", "approval_id": aid, "decision": "approve", "interactive": True}, None, None)
        self.assertFalse(r["ok"])
        self.assertIn("interactive terminal", r["error"])
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], stdin=subprocess.DEVNULL,
                                 start_new_session=True)
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        r = s.handle({"op": "approve", "approval_id": aid, "decision": "approve", "interactive": True}, OTHER_UID, child.pid)
        self.assertFalse(r["ok"])
        self.assertIn("interactive terminal", r["error"])
        r = s.handle({"op": "approve", "approval_id": aid, "decision": "approve", "interactive": False}, OTHER_UID, 999998)
        self.assertTrue(r["ok"], r)

    def test_unknown_approving_process_is_refused(self):
        s = self.signer()
        aid = self.request(s)["approval_id"]
        r = s.handle({"op": "approve", "approval_id": aid, "decision": "approve"}, OTHER_UID, None)
        self.assertFalse(r["ok"])
        self.assertIn("cannot identify the approving process", r["error"])

    def test_approval_list_is_scoped_to_who_may_decide(self):
        s = self.signer()
        self.request(s)
        self.assertEqual(s.handle({"op": "approval_list"}, AGENT_UID, 1)["pending"], [])
        self.assertEqual(s.handle({"op": "approval_list"}, None, None)["pending"], [])
        self.assertEqual(len(s.handle({"op": "approval_list"}, OTHER_UID, 1)["pending"]), 1)
        self.assertEqual(s.handle({"op": "status"}, OTHER_UID, 1)["pending_approvals"], 1)
        dev = self.signer(mode="dev", allow_same_user_approval=True)
        self.request(dev)
        self.assertEqual(dev.handle({"op": "approval_list"}, None, None)["pending"], [])

    def test_request_fields_are_bounded_strings(self):
        s = self.signer()
        base = {"op": "approval_request", "run_id": "r", "tool_use_id": "t", "timeout_s": 30}
        for bad in ({"tool_use_id": 7}, {"tool_use_id": ["t"]}, {"tool_use_id": "t" * 201}, {"agent_id": ""},
                    {"agent_id": {"x": 1}}, {"rule_ids": "TK-A1"}, {"rule_ids": ["x"] * 33}, {"rule_ids": [1]},
                    {"rule_ids": ["x" * 101]}):
            r = s.handle({**base, **bad}, AGENT_UID, 999999)
            self.assertFalse(r["ok"], bad)
        self.assertEqual(s.approvals, {})
        self.assertTrue(s.handle({**base, "agent_id": "a1", "rule_ids": ["TK-A1"]}, AGENT_UID, 999999)["ok"])

    def test_decision_takes_effect_only_once_recorded(self):
        s = self.signer()
        aid = self.request(s)["approval_id"]
        with mock.patch.object(s.ledger, "append", side_effect=OSError("disk full")), self.assertRaises(OSError):
            s.handle({"op": "approve", "approval_id": aid, "decision": "approve"}, OTHER_UID, 999998)
        self.assertIsNone(s.approvals[aid]["decision"])
        self.assertIsNone(s.approvals[aid]["approver"])

    def test_run_without_run_start_is_owned_by_its_writer(self):
        s = self.signer()
        self.assertTrue(s.handle({"op": "append", "cseq": 0, "event": tool_call("t1", run="late")}, AGENT_UID, 1)["ok"])
        self.assertEqual(s.runs["late"]["agent_uid"], AGENT_UID)
        r = s.handle({"op": "approval_request", "run_id": "late", "tool_use_id": "t1", "timeout_s": 30}, AGENT_UID, 999999)
        self.assertTrue(r["ok"], r)
        self.assertFalse(s.handle({"op": "append", "cseq": 1, "event": tool_call("t2", run="late")}, OTHER_UID, 1)["ok"])

    def test_every_user_can_record_gaps_in_the_unattributed_run(self):
        s = self.signer()
        gap = ev("capture.gap", {"reason": "hook payload has no session_id", "kind": "missing_ids"}, "_unattributed")
        for uid in (AGENT_UID, OTHER_UID):
            self.assertTrue(s.handle({"op": "append", "cseq": 0, "event": gap}, uid, 1)["ok"], uid)
        self.assertIsNone(s.runs["_unattributed"]["agent_uid"])
        kinds = [r["event"]["data"]["kind"] for r in ledger_records(s.home) if r["event"]["type"] == "capture.gap"]
        self.assertNotIn("counter", kinds)

    @unittest.skipIf(pwd is None, "needs a passwd database")
    def test_numeric_owner_without_passwd_entry_is_restored(self):
        uid = 3999999
        try:
            pwd.getpwuid(uid)
            self.skipTest(f"uid {uid} has a passwd entry here")
        except KeyError:
            pass
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        s = make_signer(d)
        self.assertTrue(s.handle({"op": "append", "cseq": 0, "event": run_start()}, uid, 1)["ok"])
        s.ledger.close()
        s = make_signer(d)
        self.addCleanup(s.ledger.close)
        self.assertEqual(s.runs["r1"]["agent_uid"], uid)

    def test_request_needs_a_run_the_caller_owns(self):
        s = self.signer()
        self.assertFalse(self.request(s, OTHER_UID)["ok"])
        r = s.handle({"op": "approval_request", "run_id": "unknown-run", "tool_use_id": "t", "timeout_s": 30}, AGENT_UID, 1)
        self.assertFalse(r["ok"])
        self.assertTrue(self.request(s)["ok"])

    def test_wait_s_must_be_a_bounded_finite_number(self):
        s = self.signer()
        aid = self.request(s)["approval_id"]
        for bad in (float("inf"), float("nan"), -1, 10 ** 9, "20", True, None):
            r = s.handle({"op": "approval_wait", "approval_id": aid, "wait_s": bad}, AGENT_UID, 1)
            self.assertFalse(r["ok"], bad)
        self.assertTrue(s.handle({"op": "approval_wait", "approval_id": aid, "wait_s": 0}, AGENT_UID, 1)["ok"])

    def test_pending_approvals_are_capped_per_uid(self):
        from tracekit import daemon
        s = self.signer()
        with mock.patch.object(daemon, "MAX_PENDING_APPROVALS_PER_UID", 2):
            self.assertTrue(self.request(s, tid="a")["ok"])
            self.assertTrue(self.request(s, tid="b")["ok"])
            r = self.request(s, tid="c")
        self.assertFalse(r["ok"])
        self.assertIn("too many pending", r["error"])


class FakeTracer:
    def __init__(self, fail_mode="open", reject=False):
        self._policy = {"content_capture": "hashed", "fail_mode": fail_mode}
        self._ended, self.events, self.reject = False, [], reject

    def _event(self, t, data):
        return {"schema_version": SCHEMA_VERSION, "id": new_id(), "seq": 0, "prev_hash": GENESIS, "ts": now_ts(),
                "run_id": "r", "agent_id": "main", "parent_id": None, "source": "sdk", "type": t, "data": data}

    def _send(self, ev, attach=None):
        if self.reject:
            from tracekit.agent_sdk import TracekitSDKError
            raise TracekitSDKError("signer rejected SDK event: schema")
        self.events.append(ev)
        return {"ok": True}


class Autotrace(unittest.TestCase):
    def tearDown(self):
        autotrace._LATE.clear()

    def stream(self, t):
        ex = autotrace._Exchange(t, "openai", "chat", "m", {}, True)
        ex.begin()
        return autotrace._StreamProxy(iter([{"choices": []}]), ex, lambda ex, item: None)

    def test_stream_finishing_after_end_leaves_a_gap(self):
        t = FakeTracer()
        s = self.stream(t)
        t._ended = True
        list(s)
        self.assertEqual([e["type"] for e in t.events], ["model.exchange", "capture.gap"])
        self.assertEqual(t.events[-1]["data"]["kind"], "late_stream")

    def test_garbage_collected_stream_is_queued_not_sent_from_del(self):
        t = FakeTracer()
        s = self.stream(t)
        s.__del__()
        self.assertEqual(len(t.events), 1, "nothing is sent from __del__")
        autotrace._wrap(lambda self: None, "openai", "chat", False, None, None, None)(None)  # the next model call flushes
        self.assertIn("abandoned", t.events[-1]["data"]["error"])

    def test_generator_finalisation_queues_instead_of_sending(self):
        t = FakeTracer()
        s = self.stream(t)
        it = iter(s)
        next(it)
        it.close()  # GeneratorExit, as when the GC finalises a half-read stream
        self.assertEqual(len(t.events), 1, "nothing is sent from a finaliser")
        self.assertEqual(list(autotrace._LATE), [s._tk_ex])

    def test_tracer_end_records_abandoned_streams_before_run_end(self):
        from tracekit.agent_sdk import Tracer
        sent = []
        with mock.patch.object(client, "send", lambda ev, **kw: (sent.append(ev), {"ok": True})[1]):
            t = Tracer(agent="a", cwd=tempfile.gettempdir())
            self.stream(t).__del__()
            t.end()
        self.assertEqual([e["type"] for e in sent], ["run.start", "model.exchange", "model.exchange", "run.end"])
        self.assertIn("abandoned", sent[2]["data"]["error"])
        self.assertFalse(autotrace._LATE)

    def test_queued_streams_are_flushed_at_exit_without_init(self):
        import subprocess
        code = "from tracekit import autotrace\nclass E:\n    def finish(self, **k): print('flushed')\nautotrace._LATE.append(E())"
        out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(out.stdout.strip(), "flushed", out.stderr)

    def test_model_calls_after_the_run_ended_follow_the_fail_mode(self):
        ran = []
        call = autotrace._wrap(lambda self: ran.append(1), "openai", "chat", False, lambda ex, out: None, None, None)
        for mode in ("open", "closed"):
            t = FakeTracer(mode)
            t._ended = True
            autotrace._STATE["tracer"] = t
            self.addCleanup(autotrace._STATE.__setitem__, "tracer", None)
            if mode == "closed":
                with self.assertRaises(PermissionError):
                    call(None)
            else:
                call(None)
        self.assertEqual(ran, [1], "open runs the call unrecorded; closed refuses it")

    def test_signer_rejection_honours_fail_closed(self):
        with self.assertRaises(PermissionError):
            self.stream(FakeTracer("closed", reject=True))
        with mock.patch("sys.stderr", io.StringIO()):
            self.stream(FakeTracer("open", reject=True))

    def test_text_length_is_tracked_without_rescanning(self):
        ex = autotrace._Exchange(FakeTracer(), "openai", "chat", "m", {}, True)
        for _ in range(3):
            ex.add_text("abc")
        self.assertEqual(ex.text_len, 9)
        with mock.patch.object(autotrace, "MAX_TEXT", 9):
            ex.add_text("more")
        self.assertEqual("".join(ex.text), "abcabcabc")


class BridgeTimeouts(unittest.TestCase):
    def test_a_request_past_its_timeout_is_answered_once_with_an_error(self):
        out = io.StringIO()
        b = bridge.Bridge(out)
        b.op_slow = lambda r: time.sleep(0.5)
        th = b.submit({"id": 7, "op": "slow", "timeout_s": 0.05}, threading.BoundedSemaphore(1))
        th.join(5)
        replies = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual(len(replies), 1)
        self.assertFalse(replies[0]["ok"])
        self.assertIn("timed out", replies[0]["error"])

    def test_workers_are_bounded(self):
        b = bridge.Bridge(io.StringIO())
        slots = threading.BoundedSemaphore(1)
        release = threading.Event()
        b.op_hold = lambda r: release.wait(5)
        first = b.submit({"id": 1, "op": "hold"}, slots)
        self.assertIsNone(b.submit({"id": 2, "op": "ping"}, slots), "a full pool never blocks the reader")
        self.assertEqual(json.loads(b.out.getvalue())["error"], "bridge busy")
        release.set()
        first.join(5)
        b.submit({"id": 3, "op": "ping"}, slots).join(5)
        self.assertIn('"id": 3, "ok": true', b.out.getvalue())

    def late(self, op, req, run):
        out = io.StringIO()
        b = bridge.Bridge(out)
        b.runs["r1"] = run
        b.submit({"id": 1, "op": op, "run": "r1", "timeout_s": 0.05, **req}, threading.BoundedSemaphore(1)).join(5)
        self.assertEqual([json.loads(x)["error"] for x in out.getvalue().splitlines()], ["request timed out after 0.05 s"])
        return b

    def test_a_late_tool_begin_ends_its_call(self):
        class SlowCall:
            tool_use_id, exits = "t1", []

            def __enter__(self):
                time.sleep(0.3)

            def __exit__(self, et, e, tb):
                self.exits.append(str(e))
        call = SlowCall()
        b = self.late("tool_begin", {"name": "Bash", "args": {}}, mock.Mock(tool=lambda *a: call))
        self.assertEqual((b.calls, call.exits), ({}, ["caller timed out"]))

    def test_a_late_model_begin_finishes_its_exchange(self):
        t = FakeTracer()
        with mock.patch.object(autotrace._Exchange, "begin", lambda self: time.sleep(0.3)):
            b = self.late("model_begin", {"provider": "openai", "request": {}}, t)
        self.assertEqual(b.exchanges, {})
        self.assertEqual([(e["data"]["phase"], e["data"]["error"]) for e in t.events], [("response", "caller timed out")])

    def test_a_request_past_its_deadline_before_a_worker_starts_does_not_run(self):
        b = bridge.Bridge(io.StringIO())
        ran, held = [], []
        b.op_mark = lambda r: ran.append(1)
        start = threading.Thread.start
        with mock.patch.object(threading.Thread, "start", lambda th: start(th) if isinstance(th, threading.Timer) else held.append(th)):
            b.submit({"id": 1, "op": "mark", "timeout_s": 0.01}, threading.BoundedSemaphore(1))
        time.sleep(0.2)
        start(held[0])
        held[0].join(5)
        self.assertEqual(ran, [])
        self.assertIn("timed out", json.loads(b.out.getvalue())["error"])


class Migrate(unittest.TestCase):
    def ledger(self, lines):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "v01.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return path

    def record(self, seq, prev, **kw):
        body = {"seq": seq, "prev": prev, "ts": 1700000000 + seq, "session_id": "s", **kw}
        import hashlib
        return {**body, "hash": hashlib.sha256(canon(body).encode()).hexdigest()}

    def test_send_refuses_a_broken_chain_unless_forced(self):
        r0 = self.record(0, GENESIS, event="UserPromptSubmit", prompt="hi")
        r1 = self.record(1, "0" * 64, event="SessionEnd")  # does not link to r0
        path = self.ledger([json.dumps(r0), json.dumps(r1)])
        with mock.patch.object(client, "send") as send, mock.patch("sys.stdout", io.StringIO()), \
                mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(migrate.main([path, "--send"]), 1)
            send.assert_not_called()
            migrate.main([path, "--send", "--force"])
            self.assertTrue(send.called)

    def test_malformed_lines_are_reported_not_a_crash(self):
        r0 = self.record(0, GENESIS, event="UserPromptSubmit", prompt="hi")
        path = self.ledger([json.dumps(r0), "[1, 2]", "not json", json.dumps({"seq": 2})])
        with mock.patch("sys.stdout", io.StringIO()) as out, mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(migrate.main([path]), 1)
        self.assertIn("BROKEN", out.getvalue())


if __name__ == "__main__":
    unittest.main()
