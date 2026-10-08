"""Trust decisions in the hook, client, signer approvals, SDK bridge and migration.

    python3 -m pytest tests/test_trust_hardening.py -q
"""
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import autotrace, bridge, client, hook, migrate, policy  # noqa: E402
from tracekit.core import GENESIS, SCHEMA_VERSION, canon, new_id, now_ts  # noqa: E402
from factories import make_signer  # noqa: E402

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
    def run_hook(self, payload, fail_mode="open", send=None):
        pol, raw = policy.load()
        pol = dict(pol, fail_mode=fail_mode)
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
        for payload in (pre, dict(pre, session_id="s1"), {"hook_event_name": "UserPromptSubmit", "prompt": "hi"}):
            code, sent, err = self.run_hook(payload)
            self.assertEqual((code, sent), (0, []), payload)
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


@unittest.skipIf(os.name == "nt", "system config is unsupported on Windows")
class SystemConfigFailsClosed(_ClientHome):
    def test_malformed_root_config_blocks_tool_calls(self):
        path = os.path.join(self.d, "client.json")
        with open(path, "w") as f:
            f.write("{ nope")
        os.chmod(path, 0o644)
        pre = {"hook_event_name": "PreToolUse", "session_id": "s1", "tool_use_id": "t1", "cwd": self.d,
               "tool_name": "Bash", "tool_input": {"command": "ls"}}
        with mock.patch.object(client, "SYSTEM_CONFIG", path), mock.patch.dict(os.environ, {"TRACEKIT_FAIL_CLOSED": ""}), \
                mock.patch("sys.stdin", io.StringIO(json.dumps(pre))), mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(hook._entry(), 2)


class Approvals(unittest.TestCase):
    def signer(self, **cfg):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        s = make_signer(d, **cfg)
        s._run("r").update(started=True, agent_uid=AGENT_UID)
        return s

    def request(self, s, uid=AGENT_UID, tid="t"):
        return s.handle({"op": "approval_request", "run_id": "r", "tool_use_id": tid, "timeout_s": 30}, uid, 999999)

    def test_forged_interactive_flag_is_ignored(self):
        s = self.signer(mode="dev", allow_same_user_approval=True)
        aid = self.request(s)["approval_id"]
        r = s.handle({"op": "approve", "approval_id": aid, "decision": "approve", "interactive": True}, None, None)
        self.assertFalse(r["ok"])
        self.assertIn("interactive terminal", r["error"])
        r = s.handle({"op": "approve", "approval_id": aid, "decision": "approve", "interactive": False}, OTHER_UID, 999998)
        self.assertTrue(r["ok"], r)

    def test_approval_list_is_scoped_to_who_may_decide(self):
        s = self.signer()
        self.request(s)
        self.assertEqual(s.handle({"op": "approval_list"}, AGENT_UID, 1)["pending"], [])
        self.assertEqual(s.handle({"op": "approval_list"}, None, None)["pending"], [])
        self.assertEqual(len(s.handle({"op": "approval_list"}, OTHER_UID, 1)["pending"]), 1)
        self.assertEqual(s.handle({"op": "status"}, OTHER_UID, 1)["pending_approvals"], 1)

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
        autotrace.flush()
        self.assertIn("abandoned", t.events[-1]["data"]["error"])

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
        started = threading.Event()
        threading.Thread(target=lambda: (started.set(), b.submit({"id": 2, "op": "ping"}, slots)), daemon=True).start()
        started.wait(5)
        time.sleep(0.1)
        self.assertNotIn('"id": 2', b.out.getvalue(), "the second request waits for a free worker")
        release.set()
        first.join(5)
        end = time.time() + 5
        while '"id": 2' not in b.out.getvalue() and time.time() < end:
            time.sleep(0.02)
        self.assertIn('"id": 2', b.out.getvalue())


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
