"""Completeness on the v2 signer (v1 run completeness: test_completeness.py): signed gaps for what was decided but never
reported (calls that never completed, undecided tool results a gateway sees mid-run, trailing client_seq values, writes
after run.final, overlapping runs, a stopped tailer), hooks that know their event, and the gateway's provider-run
tools."""
import io
import json
import os
import shutil
import signal
import tempfile
import time
import unittest
from unittest import mock

from test_detect import EGRESS, SECRET, engine as detecting
from test_signer_lifecycle import FAIL_MODES, Lifecycle
from test_signer_service import ME, OTHER, PAY_ASKS, records
from tracekit import agent_hooks, gateway, parsers
from tracekit.deploy import files
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.integrations import claude_code, harness_hooks
from tracekit.policy2.engine import Engine
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError
from tracekit.storage.file import FileStorage

GATEWAY = CallerIdentity("mtls", "spiffe://acme/gateway", True)
TAILER = CallerIdentity("uid", "999005", True)
DELEGATE = CallerIdentity("uid", "999006", True)   # another identity a run is delegated to


class Completeness(Lifecycle):
    def open(self):
        self.s = svc.SignerService(self.dir, policy=PAY_ASKS, fail_modes=FAIL_MODES, grace_s=60, idle_s=3600,
                                   gateways=["mtls:spiffe://acme/*"],
                                   authorize={"mtls:spiffe://acme/*": ["model_event", "close_run"],
                                              "uid:999005": ["tailer_heartbeat", "model_event", "tailer_lost"],
                                              "uid:999006": ["model_event"]})
        self.closed = False

    def restart(self):
        """A signer that stopped without its snapshot: the run state is replayed from the records."""
        with mock.patch.object(FileStorage, "snapshot_put"):
            self.close()
        self.open()

    def final(self, run):
        self.call("close_run", run)
        self.s.sweep(time.monotonic() + 61)
        return self.events(run["run_id"])

    def gaps(self, events, kind):
        return [e for e in events if e["type"] == "capture.gap" and e["data"]["kind"] == kind]

    def approve(self, run, tcid, attempt=0):
        aid = self.call("approval_request", {**run, "tool_call_id": tcid, "attempt": attempt})["approval_id"]
        self.call("approval_decide", {"approval_id": aid, "decision": "approve"}, OTHER)
        self.assertTrue(self.call("approval_consume", {**run, "tool_call_id": tcid, "tool": "pay",
                                                       "args_source": "parsed", "args": {}, "attempt": attempt})["ok"])


class TestDecidedNotCompleted(Completeness):
    def test_an_allowed_or_approved_call_that_never_completes_is_a_gap(self):
        run = self.register()
        self.decide(run, 0, "done")
        self.decide(run, 1, "lost")
        self.decide(run, 2, "denied-after-retry")   # its later decide is the one that counts
        self.decide(run, 3, "approved", tool="pay")
        self.approve(run, "approved")
        self.decide(run, 4, "unapproved", tool="pay")   # asked, never approved: it may not run, so no gap
        d = self.decide(run, 5, "done")   # decided again: only this decide is open now
        self.call("complete", self.ev(run, 6, tool_call_id="done", decision_id=d["decision_id"], status="ok",
                                      args_digest=event_hash({"tool": "read_file", "args": {}})))
        gaps = self.gaps(self.final(run), "decided_not_completed")
        self.assertEqual(sorted(g["tool_call_id"] for g in gaps), ["approved", "denied-after-retry", "lost"])
        self.assertTrue(all(g["source"] == "signer" and g["attempt"] == 0 for g in gaps))
        reason = next(g for g in gaps if g["tool_call_id"] == "approved")["data"]["reason"]
        self.assertIn("approved and never completed", reason)
        self.assertIn("read the harness's transcript or the app's log for whether it ran", reason)

    def test_a_later_decide_of_the_call_hides_no_decision_that_let_it_run(self):
        run = self.register()
        self.decide(run, 0, "x")   # allowed, then decided again with arguments that can't be read: denied
        self.assertEqual(self.call("decide", self.ev(run, 1, tool_call_id="x", tool="read_file", args_source="raw",
                                                     args="{bad"))["decision"], "deny")
        self.decide(run, 2, "p", tool="pay")   # approved and consumed, then decided again as another attempt
        self.approve(run, "p")
        self.call("decide", self.ev(run, 3, tool_call_id="p", tool="pay", args_source="parsed", args={}, attempt=1))
        gaps = self.gaps(self.final(run), "decided_not_completed")
        self.assertEqual([(g["tool_call_id"], g["attempt"]) for g in gaps], [("x", 0), ("p", 0)])

    def test_an_approved_call_completed_under_a_later_decide_is_no_gap(self):
        """An adapter resumed in another process decides again before it consumes the approval (openai_agents)."""
        for restart in (False, True):
            with self.subTest(restart=restart):
                if self.closed:
                    self.open()
                run = self.register()
                self.decide(run, 0, "p", tool="pay")
                aid = self.call("approval_request", {**run, "tool_call_id": "p"})["approval_id"]
                d = self.decide(run, 1, "p", tool="pay")
                self.call("approval_decide", {"approval_id": aid, "decision": "approve"}, OTHER)
                self.assertTrue(self.call("approval_consume", {**run, "tool_call_id": "p", "tool": "pay",
                                                               "args_source": "parsed", "args": {}})["ok"])
                self.call("complete", self.ev(run, 2, tool_call_id="p", decision_id=d["decision_id"], status="ok",
                                              args_digest=event_hash({"tool": "pay", "args": {}})))
                if restart:
                    self.restart()
                self.assertEqual(self.gaps(self.final(run), "decided_not_completed"), [])

    def test_capped_then_counted(self):
        run = self.register()
        with mock.patch.object(svc, "DECIDED_GAPS_MAX", 2):
            for i in range(5):
                self.decide(run, i, f"tc-{i}")
            gaps = self.gaps(self.final(run), "decided_not_completed")
        self.assertEqual([g.get("tool_call_id") for g in gaps], ["tc-0", "tc-1", None])
        self.assertEqual(gaps[-1]["data"]["missed_events"], 3)
        self.assertIn("read the run's decisions with no tool.result", gaps[-1]["data"]["reason"])

    def test_a_call_a_gateway_holds_is_one_gap_next_to_detection(self):
        """In one run under a detecting policy: a call a gateway decided and never completed is held_call_unresolved
        only, the client's own is decided_not_completed only, and the sequence the two calls make opens an incident."""
        self.close()
        self.s = svc.SignerService(self.dir, policy=detecting(), grace_s=60, gateways=["mtls:spiffe://acme/*"],
                                   authorize={"mtls:spiffe://acme/*": ["decide"]})
        self.closed = False
        run = self.register()
        args = {"tool": SECRET[0], "args_source": "parsed", "args": SECRET[1]}
        self.call("decide", {**run, "stream": "gx", "client_seq": 0, "tool_call_id": "held", "caller": f"uid:{ME.subject}",
                             **args}, GATEWAY)
        self.call("decide", self.ev(run, 0, tool_call_id="lost", tool=EGRESS[0], args_source="parsed", args=EGRESS[1]))
        d = self.call("decide", self.ev(run, 1, tool_call_id="done", tool="read_file", args_source="parsed",
                                        args={"path": "a"}))
        self.call("complete", self.ev(run, 2, tool_call_id="done", decision_id=d["decision_id"], status="ok",
                                      args_digest=event_hash({"tool": "read_file", "args": {"path": "a"}})))
        self.call("close_run", run)
        self.s.sweep(time.monotonic() + 61 + svc.GATEWAY_WAIT_S)
        events = self.events(run["run_id"])
        self.assertEqual([g["tool_call_id"] for g in self.gaps(events, "held_call_unresolved")], ["held"])
        self.assertEqual([g["tool_call_id"] for g in self.gaps(events, "decided_not_completed")], ["lost"])
        incidents = [e["data"] for e in events if e["type"] == "incident.opened"]
        self.assertEqual([(i["trigger"], i["rule_ids"]) for i in incidents], [("sequence", ["Q"])])
        self.assertEqual(events[-1]["type"], "run.final")


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
        self.assertIn("or one refused it before deciding (then the result is that refusal); check the agent's hooks",
                      live[-1]["data"]["detail"])
        self.gw(run, 2, phase="request", tool_results_sent=["hidden"])   # named again: one record only
        es = self.final(run)
        self.assertEqual([e["tool_call_id"] for e in es if e["type"] == "reconcile.hook_missing"], ["hidden"])
        self.assertEqual(es[-1]["data"]["coverage"]["unreconciled"], {"hook_missing": 1})

    def test_a_handoff_is_recorded_at_once_unless_the_policy_names_it(self):
        handoff = [{"id": "h", "name": "transfer_to_refunds_agent", "executed_by": "client", "args_source": "parsed",
                    "args_digest": event_hash({"tool": "transfer_to_refunds_agent", "args": {}})}]
        for handoffs, want in (([], ["h"]), (["transfer_to_refunds_agent"], [])):
            with self.subTest(handoffs=handoffs):
                self.s.policy = Engine({**PAY_ASKS.policy, "handoffs": handoffs})   # the operator
                run = self.register()
                self.gw(run, 0, phase="response", tool_uses=handoff)
                self.gw(run, 1, phase="request", tool_results_sent=["h"])
                live = [r["event"] for r in records(self.dir) if r["event"]["run_id"] == run["run_id"]
                        and r["event"]["type"] == "reconcile.hook_missing"]
                self.assertEqual([e["tool_call_id"] for e in live], want)
                if live:
                    self.assertIn("name it in the policy's handoffs:", live[0]["data"]["detail"])


    def test_a_structured_output_tool_is_not_recorded_at_once(self):
        self.s.policy = Engine({**PAY_ASKS.policy, "structured_output": ["AgentOutput"]})
        run = self.register()
        self.gw(run, 0, phase="response", tool_uses=[{"id": "o", "name": "AgentOutput", "executed_by": "client",
                                                      "args_source": "parsed", "args_digest": event_hash(
                                                          {"tool": "AgentOutput", "args": {}})}])
        self.gw(run, 1, phase="request", tool_results_sent=["o"])
        self.assertEqual([e for e in self.final(run) if e["type"].startswith("reconcile.")], [])


class TestTrailingCounterGaps(Completeness):
    def test_close_run_names_the_last_client_seq_of_each_stream(self):
        run = self.register()
        self.decide(run, 0)
        self.call("close_run", {**run, "last_client_seq": [{"stream": "s", "client_seq": 3},
                                                          {"stream": "other", "client_seq": 0}]})
        self.s.sweep(time.monotonic() + 61)
        gaps = self.gaps(self.events(run["run_id"]), "client_counter_gap")
        self.assertEqual([(g["stream"], g["data"]["missed_events"]) for g in gaps], [("s", 3), ("other", 1)])

    def test_a_refused_event_is_no_gap_but_hides_none(self):
        run = self.register()
        self.decide(run, 0)
        bad = self.ev(run, 1, tool_call_id="tc-1", decision_id="dec-none", status="ok",
                      args_digest="sha256:" + "0" * 64)
        for seq in (1, 3):   # 1: the next value, seen and refused; 3: skips 2, so it covers nothing
            with self.assertRaises(RPCError):
                self.call("complete", {**bad, "client_seq": seq})
        self.decide(run, 5, "tc-2")
        self.call("close_run", {**run, "last_client_seq": [{"stream": "s", "client_seq": 5}]})
        self.s.sweep(time.monotonic() + 61)
        gaps = self.gaps(self.events(run["run_id"]), "client_counter_gap")
        self.assertEqual([g["data"]["missed_events"] for g in gaps], [3])   # 2..4

    def test_a_run_the_signer_closed_still_takes_the_clients_trailing_gap(self):
        run = self.register()
        self.decide(run, 0)
        self.call("close_run", run)   # the signer closed it meanwhile (idle, grace): the client's close comes after
        self.refused("run_closed", "close_run", run)   # nothing to add: refused as before
        self.call("close_run", {**run, "last_client_seq": [{"stream": "s", "client_seq": 5}]})
        self.s.sweep(time.monotonic() + 61)
        self.assertEqual([g["data"]["missed_events"] for g in self.gaps(self.events(run["run_id"]),
                                                                         "client_counter_gap")], [5])

    def test_after_a_restart_the_trailing_gap_is_still_written_and_not_twice(self):
        run = self.register()
        self.decide(run, 0)
        self.decide(run, 1, "tc-2")
        self.call("close_run", {**run, "last_client_seq": [{"stream": "s", "client_seq": 3}]})   # one gap: 2..3
        self.restart()   # the stream's writer is forgotten; its tail is rebuilt from that gap
        self.call("state_write", self.ev(run, 3, key="k", value_digest="sha256:" + "0" * 64))   # covered: no 2nd gap
        self.s.sweep(time.monotonic() + 61)
        self.assertEqual([g["data"]["missed_events"] for g in self.gaps(self.events(run["run_id"]),
                                                                         "client_counter_gap")], [2])

    def test_a_restart_does_not_hide_a_trailing_gap(self):
        run = self.register()
        self.decide(run, 0)
        self.restart()
        self.call("close_run", {**run, "last_client_seq": [{"stream": "s", "client_seq": 4}]})
        self.s.sweep(time.monotonic() + 61)
        self.assertEqual([g["data"]["missed_events"] for g in self.gaps(self.events(run["run_id"]),
                                                                         "client_counter_gap")], [4])

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

    def test_a_stream_another_identity_ends_still_takes_its_values(self):
        run = self.register()
        self.call("close_run", {**run, "last_client_seq": [{"stream": "gx", "client_seq": 5}]})
        self.call("model_event", self.ev(run, 0, stream="gx", provider="openai", model="m", phase="request",
                                         caller=f"uid:{ME.subject}"), GATEWAY)   # not refused as reused
        gap = self.gaps(self.events(run["run_id"]), "client_counter_gap")[0]
        self.assertIn(f"uid:{ME.subject} said stream gx of run {run['run_id']} ended", gap["data"]["reason"])

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

    def test_a_gateways_report_after_run_final_goes_in_the_tenants_signer_run(self):
        run = self.register()
        self.call("model_event", self.ev(run, 0, stream="gx", provider="openai", model="m", phase="request",
                                         caller=f"uid:{ME.subject}"), GATEWAY)
        self.call("close_run", run)
        self.s.sweep(time.monotonic() + 61)
        report = {**run, "caller": f"uid:{ME.subject}", "last_client_seq": [{"stream": "gx", "client_seq": 2}]}
        self.assertEqual(self.call("close_run", report, GATEWAY)["state"], "closing")
        self.s.flush_refusals()
        leaf_of = self.s.log.leaf
        self.close()
        gaps = [r for r in records(self.dir) if r["event"]["type"] == "capture.gap"]
        self.assertEqual([(r["event"]["run_id"], r["event"]["data"]["kind"], r["event"]["data"].get("run_id"),
                           r["event"]["stream"], r["event"]["data"]["missed_events"]) for r in gaps],
                         [("tracekit/signer", "client_counter_gap", run["run_id"], "gx", 2)])   # no late_activity
        with open(os.path.join(self.dir, "store", "registry.jsonl"), "rb") as f:
            self.assertIn(leaf_of(gaps[0]), {bytes.fromhex(json.loads(line)["leaf"]) for line in f.read().splitlines()})

    def test_a_close_run_ends_only_streams_its_caller_wrote_and_values_it_gapped_stay_gapped(self):
        run = self.register()
        self.call("model_event", self.ev(run, 0, stream="gx", provider="openai", model="m", phase="request",
                                         caller=f"uid:{ME.subject}"), GATEWAY)
        theirs = {**run, "run_token": self.s.call(ME, "delegate_run", {**run, "identity": "uid:999006"})["run_token"]}
        self.call("model_event", self.ev(theirs, 0, stream="t", provider="anthropic", model="m", phase="request"),
                  DELEGATE)
        self.decide(run, 0)
        self.call("close_run", {**run, "last_client_seq": [{"stream": s, "client_seq": 40} for s in ("gx", "t")]
                                + [{"stream": "s", "client_seq": 3}]})   # not the gateway's stream or the other uid's
        self.call("model_event", self.ev(run, 3, provider="openai", model="m", phase="request"))   # 1..2 had a gap
        self.call("model_event", self.ev(run, 5, provider="openai", model="m", phase="request"))
        self.call("close_run", {**run, "caller": f"uid:{ME.subject}",
                                "last_client_seq": [{"stream": "gx", "client_seq": 1}]}, GATEWAY)
        gaps = self.gaps(self.events(run["run_id"]), "client_counter_gap")
        self.assertEqual([(g["stream"], g["data"]["missed_events"]) for g in gaps], [("s", 3), ("s", 1), ("gx", 1)])
        self.assertIn(f"uid:{ME.subject} through a gateway said stream gx", gaps[-1]["data"]["reason"])

    def test_the_gateway_stops_cleanly_on_sigterm_and_says_when_the_signer_refuses_its_report(self):
        handlers = []
        srv = mock.Mock(server_address=("127.0.0.1", 1))

        def serve_forever():
            handlers.append(signal.getsignal(signal.SIGTERM))
            raise KeyboardInterrupt   # what that handler raises
        srv.serve_forever.side_effect = serve_forever
        self.addCleanup(signal.signal, signal.SIGTERM, signal.getsignal(signal.SIGTERM))
        with mock.patch.object(gateway, "serve", return_value=srv), mock.patch.object(gateway, "load_config"), \
                mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(gateway.main(["serve", "--config", "gateway.yaml"]), 0)
        self.assertEqual(handlers, [signal.default_int_handler])
        srv.gateway.close.assert_called_once_with()
        client = mock.Mock()
        client.model_event.side_effect = gateway.SignerUnavailable("down")
        client.close_run.side_effect = RPCError("forbidden", "spiffe://acme/gateway is not authorized for close_run")
        gw, err = gateway.Gateway("https://up.example", "k", client=client), io.StringIO()
        self.assertFalse(gw.record(("run-1", "tok", "uid:1"), "x1", phase="request"))
        with mock.patch("sys.stderr", err):
            gw.close()
        self.assertIn("grant this gateway close_run next to model_event in signer.yaml authorize", err.getvalue())


class TestLateActivity(Completeness):
    def test_writes_after_run_final_are_counted_per_run_in_the_tenants_registry(self):
        run, learned = self.register(), self.register()
        for r in (run, learned):
            self.call("close_run", r)
        self.s.sweep(time.monotonic() + 61)
        # a client learns from its first write that its run ended (a hook, and in dev mode its tailer on its own
        # stream, then register a new run; SessionEnd closes it): none of that counts
        for r in (run, learned):
            self.refused("run_closed", "decide", self.ev(r, 1, tool_call_id="t", tool="read_file", args_source="parsed",
                                                         args={}))
            self.refused("run_closed", "model_event", self.ev(r, 0, stream="tailer", provider="anthropic", model="m",
                                                              phase="request"))
            self.refused("run_closed", "close_run", r)
        for i in range(2):
            self.refused("run_closed", "state_write", self.ev(run, i + 2, key="k", value_digest="sha256:" + "0" * 64))
        self.refused("run_closed", "decide", self.ev(run, 4, tool_call_id="t", tool="read_file", args_source="parsed",
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
    def bound(self, pid, method="register_run", **req):
        """`method` as called from inside harness process `pid` (the harness helper's answer, patched)."""
        h = {"name": "claude", "exe": "/usr/bin/claude", "pid": pid, "start_time": 1}
        with mock.patch.object(self.s, "_harnesses", ["claude"]), \
                mock.patch.object(self.s, "_chain", lambda identity: [{"pid": 1}, h]), \
                mock.patch.object(svc.harness_helper, "match", lambda procs, harnesses: (h, None)):
            return self.call(method, req if method != "register_run" else {"agent": {"name": "a"}, **req})

    def act(self, pid, run, seq):
        return self.bound(pid, "decide", **self.ev({k: run[k] for k in ("run_id", "run_token")}, seq,
                                                   tool_call_id=f"t{seq}", tool="read_file", args_source="parsed",
                                                   args={}))

    def concurrent(self, run):
        return [r["event"]["data"]["run_id"] for r in records(self.dir) if r["event"]["run_id"] == run["run_id"]
                and r["event"]["type"] == "capture.gap" and r["event"]["data"]["kind"] == "concurrent_run"]

    def test_overlapping_runs_of_one_harness_process_are_a_gap_in_the_newer_once_both_record_events(self):
        first, older, quiet = self.bound(100), self.bound(400), self.bound(300)
        second, newer = self.bound(100), self.bound(400)
        resumed = self.bound(300)   # `quiet`'s session ended without SessionEnd: its run stays open, with no events
        elsewhere = self.bound(200)   # another harness process: two Claude Code windows side by side
        for pid, run in ((100, second), (300, resumed), (200, elsewhere), (400, older)):
            self.act(pid, run, 0)
        self.assertEqual(self.concurrent(second), [])   # its older run has recorded nothing since
        self.act(100, first, 0)
        self.act(100, first, 1)
        self.assertEqual(self.concurrent(second), [first["run_id"]])
        self.act(400, newer, 0)   # the older run's event came first
        self.assertEqual(self.concurrent(newer), [older["run_id"]])
        child = self.bound(100, parent={k: first[k] for k in ("run_id", "run_token")})   # first's session
        self.act(100, child, 0)
        unbound = [self.register(), self.register()]   # an SDK or a server: several runs at once by design
        for r in unbound:
            self.decide(r, 0)
        self.close()
        self.assertEqual([self.concurrent(r) for r in (first, older, quiet, resumed, elsewhere, child, *unbound)],
                         [[]] * 8)
        children = [r["event"] for r in records(self.dir) if r["event"]["type"] == "run.child"]
        self.assertEqual([(e["run_id"], e["data"]["run_id"], e["source"]) for e in children],
                         [(first["run_id"], child["run_id"], "signer")])
        self.assertEqual(self.concurrent(second), [first["run_id"]])   # once


class TestTailerHeartbeat(Completeness):
    def test_a_tailer_whose_heartbeats_stop_is_a_gap(self):
        run, quiet = self.register(), self.register()
        with self.assertRaises(RPCError) as cm:   # the agent's own token can't keep a killed tailer alive
            self.s.call(ME, "tailer_heartbeat", run)
        self.assertEqual(cm.exception.code, "forbidden")
        token = self.s.call(ME, "delegate_run",{**run, "identity": f"uid:{TAILER.subject}"})["run_token"]
        self.s.call(TAILER, "tailer_heartbeat", {**run, "run_token": token})
        self.s.sweep(time.monotonic() + svc.TAILER_LOST_S - 5)
        self.s.sweep(time.monotonic() + svc.TAILER_LOST_S + 1)
        self.s.sweep(time.monotonic() + 2 * svc.TAILER_LOST_S)   # once
        lost = self.gaps(self.events(run["run_id"]), "tailer_lost")
        self.assertEqual(len(lost), 1)
        self.assertIn("no tailer_heartbeat", lost[0]["data"]["reason"])
        # system mode puts no `tracekit` on root's PATH
        self.assertIn("run `sudo /opt/tracekit/bin/python -I -m tracekit doctor` to check the tailer",
                      lost[0]["data"]["reason"])
        self.assertEqual(self.gaps(self.events(quiet["run_id"]), "tailer_lost"), [])   # never had a tailer

    def tailer(self, run):
        return {**run, "run_token": self.s.call(ME, "delegate_run", {**run, "identity": f"uid:{TAILER.subject}"})[
            "run_token"]}

    def test_a_tailer_is_watched_from_its_token_and_a_second_token_is_a_gap(self):
        run, other = self.register(), self.register()
        self.tailer(run)   # killed before its first heartbeat
        self.tailer(run)
        self.s.call(ME, "delegate_run", {**other, "identity": f"uid:{DELEGATE.subject}"})   # no tailer: not watched
        self.s.sweep(time.monotonic() + svc.TAILER_LOST_S + 1)
        es = self.events(run["run_id"])
        self.assertEqual(len(self.gaps(es, "tailer_lost")), 1)
        (again,) = self.gaps(es, "tailer_redelegated")
        self.assertIn(f"uid:{ME.subject} took a second transcript tailer token", again["data"]["reason"])
        self.assertEqual(self.gaps(self.events(other["run_id"]), "tailer_lost"), [])

    def test_a_tailer_killed_across_a_clean_restart_is_still_a_gap(self):
        run = self.register()
        self.s.call(TAILER, "tailer_heartbeat", self.tailer(run))
        self.close()   # with its snapshot: the run's `tailed` stays
        self.open()
        self.s.sweep(time.monotonic() + svc.TAILER_LOST_S + 1)
        self.assertEqual(len(self.gaps(self.events(run["run_id"]), "tailer_lost")), 1)

    def test_a_loss_the_tailer_reported_is_not_written_again(self):
        run = self.register()
        token = self.tailer(run)
        self.s.call(TAILER, "tailer_heartbeat", token)
        self.call("tailer_lost", {**token, "reason": "the transcript shrank to 0 bytes (truncated)", "offset": 5},
                  TAILER)
        self.s.sweep(time.monotonic() + svc.TAILER_LOST_S + 1)
        self.assertEqual(len(self.gaps(self.events(run["run_id"]), "tailer_lost")), 1)

    def test_a_tailers_records_show_it_alive_too(self):
        run = self.register()
        token = self.tailer(run)
        self.s.call(TAILER, "tailer_heartbeat", token)
        self.s._beats[("default", run["run_id"])] -= svc.TAILER_LOST_S   # its last heartbeat: long ago
        self.call("model_event", self.ev(token, 0, stream="tailer", provider="anthropic", model="m", phase="request"),
                  TAILER)
        self.s.sweep(time.monotonic() + 1)
        self.assertEqual(self.gaps(self.events(run["run_id"]), "tailer_lost"), [])

    def test_the_tailer_sends_heartbeats_and_stops_only_on_a_signer_or_token_without_them(self):
        from tracekit import tailer
        run = mock.Mock()
        for code, stops in (("invalid_request", True), ("forbidden", True), ("quota_exceeded", False)):
            run.call.side_effect = RPCError(code, "unknown method tailer_heartbeat" if code == "invalid_request"
                                            else "refused")
            self.assertEqual(tailer._heartbeat(run) is None, stops, code)
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

    def test_a_run_the_hook_found_ended_is_not_tried_again(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        client = mock.Mock()
        client.call.side_effect = [RPCError("run_closed", "r1"), {"decision": "allow"}]
        client.register_run.return_value = {"run_id": "r2", "run_token": "t2"}
        with mock.patch.object(claude_code.autospawn, "runtime_dir", lambda: d):
            files.write_json(claude_code._state("s"), {"run_id": "r1", "run_token": "t1", "stream": "x", "seq": 0})
            for tid in ("t1", "t0"):   # PostToolUses after an idle close: only the first reaches the signer
                with self.assertRaises(RPCError):
                    claude_code._run(client, "s", register=False, send="complete", tool_call_id=tid)
            claude_code._run(client, "s", send="decide", tool_call_id="t2")   # the next PreToolUse
        self.assertEqual([(c.args[0], c.args[1]["run_id"]) for c in client.call.call_args_list],
                         [("complete", "r1"), ("decide", "r2")])

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
        half = {k: v for k, v in use.items() if k != "args_digest"}   # an args_source needs its digest
        self.refused("invalid_request", "model_event", self.ev(run, 0, stream="gx", provider="anthropic", model="m",
                                                               phase="response", caller=f"uid:{ME.subject}",
                                                               tool_uses=[half]), GATEWAY)
        self.call("model_event", self.ev(run, 0, stream="gx", provider="anthropic", model="m", phase="response",
                                         caller=f"uid:{ME.subject}", tool_uses=[use]), GATEWAY)
        self.decide(run, 0, "srvtoolu_1", tool="web_search")
        es = self.final(run)
        ex = next(e for e in es if e["type"] == "model.exchange")
        self.assertTrue(ex["data"]["tool_uses"][0]["args_commitment"].startswith("hmac-sha256:"))
        self.assertEqual([e for e in es if e["type"].startswith("reconcile.")], [])
        self.assertEqual(es[-1]["data"]["provider_executed"], 1)

    def test_under_gateway_mandatory_only_the_gateways_provider_tool_uses_count(self):
        self.s.gateway_mandatory = True
        run = self.register()
        self.decide(run, 0, "fab")
        self.decide(run, 1, "srv", tool="web_search")
        uses = [{"id": i, "name": "web_search", "executed_by": "provider"} for i in ("fab", "srv")]
        self.call("model_event", self.ev(run, 2, provider="openai", model="m", phase="response", tool_uses=uses))
        self.call("model_event", self.ev(run, 0, stream="gx", provider="openai", model="m", phase="response",
                                         caller=f"uid:{ME.subject}", tool_uses=uses[1:]), GATEWAY)
        es = self.final(run)
        self.assertEqual([(e["type"], e["tool_call_id"]) for e in es if e["type"].startswith("reconcile.")],
                         [("reconcile.fabricated", "fab")])   # the agent's own word for a provider tool use is no L3
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

    def test_openai_hosted_mcp_is_denied_by_its_type_and_client_run_tools_are_never_refused(self):
        req = {"model": "m", "tools": [{"type": "mcp", "server_label": "gh", "server_url": "https://x"},
                                       {"type": "local_shell"}, {"type": "computer_use_preview"},
                                       {"type": "apply_patch"}, {"type": "function", "name": "f"}]}
        for deny, refused in ((["mcp"], ["mcp:gh"]), (["mcp:gh"], ["mcp:gh"]), (["mcp:other"], [])):
            self.assertEqual(gateway.Gateway("https://up.example", "k", provider_tools={"deny": deny})
                             .refused_tools("openai:responses", req), refused)
        for allow, refused in ((["web_search"], ["mcp:gh"]), (["mcp"], []), (["mcp:gh"], [])):
            self.assertEqual(gateway.Gateway("https://up.example", "k", provider_tools={"allow": allow})
                             .refused_tools("openai:responses", req), refused)


if __name__ == "__main__":
    unittest.main()


class BeatRace(unittest.TestCase):
    def test_a_heartbeat_racing_the_sweep_that_ends_its_run_leaves_no_beat(self):
        key, run = ("default", "r1"), {"final": False}
        beats = {key: 0.0}

        class Sweep:
            """The lock a heartbeat takes, with the sweep that makes the run final (and drops its beat) just before."""
            def __enter__(self):
                run["final"] = True
                beats.pop(key, None)

            def __exit__(self, *exc):
                return False

        signer = mock.Mock(_beats=beats, _beats_lock=Sweep(), log=mock.Mock(runs={key: run}))
        signer._authorize.return_value = key
        with self.assertRaises(RPCError):
            svc.SignerService._tailer_heartbeat(signer, ME, {"run_id": "r1"})
        self.assertEqual(beats, {})
