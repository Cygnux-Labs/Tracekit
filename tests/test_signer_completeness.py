"""Completeness on the v2 signer (v1 run completeness: test_completeness.py): signed gaps for what was decided but never
reported (calls that never completed, undecided tool results a gateway sees mid-run, trailing client_seq values, writes
after run.final, overlapping runs, a stopped tailer), hooks that know their event, and the gateway's provider-run
tools."""
import io
import json
import os
import time
import unittest
from unittest import mock

from test_signer_lifecycle import FAIL_MODES, Lifecycle
from test_signer_service import ME, OTHER, PAY_ASKS, records
from tracekit import agent_hooks, gateway, parsers
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.integrations import claude_code, harness_hooks
from tracekit.signer import service as svc

GATEWAY = CallerIdentity("mtls", "spiffe://acme/gateway", True)
FLEET = CallerIdentity("uid", "999004", True)


class Completeness(Lifecycle):
    def open(self):
        self.s = svc.SignerService(self.dir, policy=PAY_ASKS, fail_modes=FAIL_MODES, grace_s=60, idle_s=3600,
                                   gateways=["mtls:spiffe://acme/*"], multi_run_apps=["uid:999004"],
                                   authorize={"mtls:spiffe://acme/*": ["model_event", "close_run"]})
        self.closed = False

    def final(self, run):
        self.call("close_run", run)
        self.s.sweep(time.monotonic() + 61)
        return self.events(run["run_id"])

    def gaps(self, events, kind):
        return [e for e in events if e["type"] == "capture.gap" and e["data"]["kind"] == kind]


class TestDecidedNotCompleted(Completeness):
    def test_an_allowed_or_approved_call_that_never_completes_is_a_gap(self):
        run = self.register()
        self.decide(run, 0, "done")
        self.decide(run, 1, "lost")
        self.decide(run, 2, "denied-after-retry")   # its later decide is the one that counts
        self.decide(run, 3, "approved", tool="pay")
        aid = self.call("approval_request", {**run, "tool_call_id": "approved"})["approval_id"]
        self.call("approval_decide", {"approval_id": aid, "decision": "approve"}, OTHER)
        self.assertTrue(self.call("approval_consume", {**run, "tool_call_id": "approved", "tool": "pay",
                                                       "args_source": "parsed", "args": {}})["ok"])
        self.decide(run, 4, "unapproved", tool="pay")   # asked, never approved: it may not run, so no gap
        d = self.decide(run, 5, "done")   # decided again: only this decide is open now
        self.call("complete", self.ev(run, 6, tool_call_id="done", decision_id=d["decision_id"], status="ok",
                                      args_digest=event_hash({"tool": "read_file", "args": {}})))
        gaps = self.gaps(self.final(run), "decided_not_completed")
        self.assertEqual(sorted(g["tool_call_id"] for g in gaps), ["approved", "denied-after-retry", "lost"])
        self.assertTrue(all(g["source"] == "signer" and g["attempt"] == 0 for g in gaps))
        self.assertIn("approved and never completed", next(g for g in gaps if g["tool_call_id"] == "approved")[
            "data"]["reason"])

    def test_capped_then_counted(self):
        run = self.register()
        with mock.patch.object(svc, "DECIDED_GAPS_MAX", 2):
            for i in range(5):
                self.decide(run, i, f"tc-{i}")
            gaps = self.gaps(self.final(run), "decided_not_completed")
        self.assertEqual([g.get("tool_call_id") for g in gaps], ["tc-0", "tc-1", None])
        self.assertEqual(gaps[-1]["data"]["missed_events"], 3)


class TestLiveHookMissing(Completeness):
    def gw(self, run, seq, **kw):
        return self.call("model_event", self.ev(run, seq, stream="gx", provider="openai", model="m",
                                                caller=f"uid:{ME.subject}", **kw), GATEWAY)

    def test_a_gateway_request_sending_back_an_undecided_result_is_recorded_at_once(self):
        run = self.register()
        uses = [{"id": i, "name": "Bash", "executed_by": "client", "args_source": "parsed",
                 "args_digest": event_hash({"tool": "Bash", "args": {}})} for i in ("decided", "hidden")]
        self.gw(run, 0, phase="response", tool_uses=uses)
        self.decide(run, 0, "decided", tool="Bash")
        self.gw(run, 1, phase="request", tool_results_sent=["decided", "hidden"])
        live = [r["event"] for r in records(self.dir) if r["event"]["run_id"] == run["run_id"]]
        self.assertEqual([(e["type"], e.get("tool_call_id")) for e in live[-2:]],
                         [("model.exchange", None), ("reconcile.hook_missing", "hidden")])
        self.gw(run, 2, phase="request", tool_results_sent=["hidden"])   # named again: one record only
        es = self.final(run)
        self.assertEqual([e["tool_call_id"] for e in es if e["type"] == "reconcile.hook_missing"], ["hidden"])
        self.assertEqual(es[-1]["data"]["coverage"]["unreconciled"], {"hook_missing": 1})


class TestTrailingCounterGaps(Completeness):
    def test_close_run_names_the_last_client_seq_of_each_stream(self):
        run = self.register()
        self.decide(run, 0)
        self.call("close_run", {**run, "last_client_seq": [{"stream": "s", "client_seq": 3},
                                                          {"stream": "other", "client_seq": 0}]})
        self.s.sweep(time.monotonic() + 61)
        gaps = self.gaps(self.events(run["run_id"]), "client_counter_gap")
        self.assertEqual([(g["stream"], g["data"]["missed_events"]) for g in gaps], [("s", 3), ("other", 1)])

    def test_a_gateway_ends_its_stream_without_closing_the_run(self):
        run = self.register()
        out = self.call("close_run", {**run, "caller": f"uid:{ME.subject}",
                                      "last_client_seq": [{"stream": "gx", "client_seq": 1}]}, GATEWAY)
        self.assertEqual(out["state"], "open")
        self.decide(run, 0)   # the run is still open
        self.refused("forbidden", "close_run", {**run, "caller": f"uid:{ME.subject}"}, OTHER)
        es = self.events(run["run_id"])
        self.assertEqual([g["data"]["missed_events"] for g in self.gaps(es, "client_counter_gap")], [2])
        self.assertNotIn("run.closing", [e["type"] for e in es])

    def test_the_gateway_reports_a_stream_whose_last_exchanges_never_arrived(self):
        client = mock.Mock()
        client.model_event.side_effect = [{"fail_modes": {}}, gateway.SignerUnavailable("down")]
        gw = gateway.Gateway("https://up.example", "k", client=client)
        key = ("run-1", "tok", "uid:1")
        self.assertTrue(gw.record(key, "x1", phase="request"))
        self.assertFalse(gw.record(key, "x2", phase="response"))
        with mock.patch.object(gateway, "MAX_RUNS", 1):
            gw._run(("run-2", "tok", "uid:1"))   # evicts run-1
        req = client.close_run.call_args.args[0]
        self.assertEqual((req["run_id"], req["caller"], req["last_client_seq"][0]["client_seq"]), ("run-1", "uid:1", 1))
        gw.close()   # run-2 sent nothing: nothing to report
        self.assertEqual(client.close_run.call_count, 1)


class TestLateActivity(Completeness):
    def test_writes_after_run_final_are_counted_per_run_in_the_tenants_registry(self):
        run = self.register()
        self.call("close_run", run)
        self.s.sweep(time.monotonic() + 61)
        for i in range(2):
            self.refused("run_closed", "state_write", self.ev(run, i + 1, key="k", value_digest="sha256:" + "0" * 64))
        self.refused("run_closed", "decide", self.ev(run, 3, tool_call_id="t", tool="read_file", args_source="parsed",
                                                     args={}))
        self.s.flush_refusals()
        leaf_of = self.s.log.leaf
        self.close()
        late = [r for r in records(self.dir) if r["event"]["type"] == "capture.gap"
                and r["event"]["data"]["kind"] == "late_activity"]
        self.assertEqual(len(late), 1)
        e = late[0]["event"]
        self.assertEqual((e["tenant"], e["run_id"], e["data"]["run_id"], e["data"]["missed_events"]),
                         ("default", "tracekit/signer", run["run_id"], 3))
        self.assertIn("decide 1, state_write 2", e["data"]["reason"])
        with open(os.path.join(self.dir, "store", "registry.jsonl"), "rb") as f:
            leaves = {bytes.fromhex(json.loads(line)["leaf"]) for line in f.read().splitlines()}
        self.assertIn(leaf_of(late[0]), leaves)


class TestConcurrentRun(Completeness):
    def test_overlapping_runs_of_one_owner_are_a_gap_in_the_newer(self):
        first = self.register()
        second = self.register()
        self.call("close_run", second)
        child = self.call("register_run", {"agent": {"name": "a"}, "parent": first})   # first's session
        other = self.register(OTHER)   # another owner
        gaps = {r["run_id"]: self.gaps(self.events(r["run_id"]), "concurrent_run")
                for r in (first, second, child, other)}
        self.assertEqual([g["data"]["run_id"] for g in gaps[second["run_id"]]], [first["run_id"]])
        self.assertEqual([gaps[r["run_id"]] for r in (first, child, other)], [[], [], []])
        self.assertIn("multi_run_apps", gaps[second["run_id"]][0]["data"]["reason"])

    def test_off_for_multi_run_apps(self):
        self.register(FLEET)
        run = self.register(FLEET)
        self.assertEqual(self.gaps(self.events(run["run_id"]), "concurrent_run"), [])


class TestTailerHeartbeat(Completeness):
    def test_a_tailer_whose_heartbeats_stop_is_a_gap(self):
        run, quiet = self.register(), self.register()
        self.s.call(ME, "tailer_heartbeat", run)
        self.s.sweep(time.monotonic() + svc.TAILER_LOST_S - 5)
        self.s.sweep(time.monotonic() + svc.TAILER_LOST_S + 1)
        self.s.sweep(time.monotonic() + 2 * svc.TAILER_LOST_S)   # once
        lost = self.gaps(self.events(run["run_id"]), "tailer_lost")
        self.assertEqual(len(lost), 1)
        self.assertIn("no tailer_heartbeat", lost[0]["data"]["reason"])
        self.assertEqual(self.gaps(self.events(quiet["run_id"]), "tailer_lost"), [])   # never had a tailer

    def test_the_tailer_sends_heartbeats_and_stops_on_a_signer_without_them(self):
        from tracekit import tailer
        from tracekit.signer.rpc_schema import RPCError
        run = mock.Mock()
        run.call.side_effect = RPCError("invalid_request", "unknown method tailer_heartbeat")
        self.assertIsNone(tailer._heartbeat(run))
        run.call.side_effect = None
        self.assertIsNotNone(tailer._heartbeat(run))
        run.call.assert_called_with("tailer_heartbeat")


class TestHookEvent(unittest.TestCase):
    def entry(self, raw, *event):
        err = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(raw)), mock.patch("sys.stderr", err):
            return claude_code._entry(*event), err.getvalue()

    def test_an_unparseable_pre_tool_payload_is_blocked_when_the_hook_knows_its_event(self):
        code, err = self.entry("{not json", "PreToolUse")
        self.assertEqual(code, 2)
        self.assertIn("PreToolUse hook payload is not a JSON object; tool call blocked", err)
        self.assertEqual(self.entry("[1]", "PostToolUse")[0], 0)
        self.assertEqual(self.entry("{not json")[0], 0)   # installed before 1.2: the payload alone, as before

    def test_the_other_harnesses_block_it_too(self):
        out = io.StringIO()
        self.assertEqual(harness_hooks.run("cursor", "{not json", out, io.StringIO(), event="preToolUse"), 2)
        self.assertEqual(json.loads(out.getvalue())["permission"], "deny")
        self.assertEqual(harness_hooks.run("codex", "{not json", io.StringIO(), io.StringIO()), 0)

    def test_init_names_each_event(self):
        from tracekit import install
        cmd = install._hook_command(install.V2_HOOK, args=("PreToolUse",))
        self.assertIn("PreToolUse", cmd)
        self.assertIn("BeforeTool", install._hook_command(agent_hooks.V2_MODULE, "entry", ("gemini", "BeforeTool")))


class TestProviderTools(Completeness):
    def test_a_provider_tools_input_is_committed_and_never_fabricated(self):
        resp = {"id": "msg_1", "model": "m", "stop_reason": "end_turn", "content": [
            {"type": "server_tool_use", "id": "srvtoolu_1", "name": "web_search", "input": {"query": "q"}}]}
        (use,) = parsers.parse("anthropic:messages", resp)["tool_uses"]
        self.assertEqual(use["args_digest"], event_hash({"tool": "web_search", "args": {"query": "q"}}))
        out = parsers.parse("openai:responses", {"id": "r", "output": [
            {"type": "web_search_call", "id": "ws_1", "action": {"type": "search", "query": "q"}},
            {"type": "image_generation_call", "id": "ig_1"}]})["tool_uses"]
        self.assertEqual([("args_digest" in t, t["executed_by"]) for t in out], [(True, "provider"), (False, "provider")])
        run = self.register()
        self.call("model_event", self.ev(run, 0, stream="gx", provider="anthropic", model="m", phase="response",
                                         caller=f"uid:{ME.subject}", tool_uses=[use]), GATEWAY)
        self.decide(run, 0, "srvtoolu_1", tool="web_search")
        es = self.final(run)
        ex = next(e for e in es if e["type"] == "model.exchange")
        self.assertTrue(ex["data"]["tool_uses"][0]["args_commitment"].startswith("hmac-sha256:"))
        self.assertEqual([e for e in es if e["type"].startswith("reconcile.")], [])
        self.assertEqual(es[-1]["data"]["provider_executed"], 1)

    def test_a_request_declaring_a_denied_provider_tool_is_refused(self):
        req = {"model": "m", "tools": [{"type": "web_search_20250305", "name": "web_search"},
                                       {"type": "bash_20250124", "name": "bash"}, {"name": "mine", "input_schema": {}}],
               "mcp_servers": [{"name": "s"}]}
        self.assertEqual(parsers.provider_tools("anthropic:messages", req), ["web_search", "mcp_servers"])
        gw = gateway.Gateway("https://up.example", "k", provider_tools={"deny": ["mcp_servers"]})
        self.assertEqual(gw.refused_tools("anthropic:messages", req), ["mcp_servers"])
        gw = gateway.Gateway("https://up.example", "k", provider_tools={"allow": ["web_search"]})
        self.assertEqual(gw.refused_tools("anthropic:messages", req), ["mcp_servers"])
        self.assertEqual(gateway.Gateway("https://up.example", "k").refused_tools("anthropic:messages", req), [])


if __name__ == "__main__":
    unittest.main()
