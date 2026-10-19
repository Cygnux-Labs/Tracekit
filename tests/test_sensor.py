"""The kernel sensor import (tracekit/sensor.py) and the signer's side of it (observe_effect with `sensor`): events
attributed to runs by the configured mapping, joined to the tool call their process's environment names, losses as
signed gaps, coverage in run.final's matrix and the verifier. The event lines are shaped as each sensor writes them,
from its own source (cited per builder)."""
import json
import os
import tempfile
import time
import types
import unittest
from unittest import mock

from test_signer_lifecycle import Lifecycle
from test_signer_service import ME, OTHER
from tracekit import sensor
from tracekit.bundle_v2 import export
from tracekit.identity.base import CallerIdentity
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import SignerUnavailable
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError
from tracekit.verify import v2

SENSOR = CallerIdentity("mtls", "spiffe://acme/tetragon", True)
TIME = "2026-10-12T10:00:01.615123456Z"   # protojson Timestamp: nanoseconds
EXEC_ID = "a2luZC1jb250cm9sLXBsYW5lOjExNDI4NjE1NjM2OTAxOjUxNTgz"
PARENT_EXEC_ID = "a2luZC1jb250cm9sLXBsYW5lOjkwNzkyMjU2MjMy"
RUNS = [{"match": {"namespace": "agents", "pod": "coder-*"}, "caller": f"uid:{ME.subject}"},
        {"match": {"namespace": "agents", "pod": "idle-*"}, "caller": f"uid:{OTHER.subject}"}]


def process(pod="coder-1", env=None, **kw):
    """A Tetragon Process as its JSON export writes it (api/v1/tetragon/tetragon.proto Process, protojson with proto
    names: pkg/encoder/encoder.go UseProtoNames; the wrapper pid and uid as numbers, environment_variables as
    {Key, Value} with --enable-process-environment-variables), after docs/content/en/docs/use-cases/process-lifecycle/
    process-execution.md."""
    return {"exec_id": EXEC_ID, "pid": 51583, "uid": 1000, "cwd": "/workspace", "binary": "/usr/bin/curl",
            "arguments": "-s https://example.com/install.sh", "flags": "execve clone",
            "start_time": "2026-10-12T10:00:01.615Z", "auid": 4294967295,
            "pod": {"namespace": "agents", "name": pod, "container": {
                "id": "containerd://1fb931d2f6e5e4cfdbaf30fdb8e2fdd81320bdb3047ded50120a4f82838209ce",
                "name": "agent", "image": {"id": "docker.io/acme/agent@sha256:" + "8e" * 32,
                                           "name": "docker.io/acme/agent:latest"},
                "start_time": "2026-10-12T09:00:00Z", "pid": 50}, "workload": pod, "workload_kind": "Pod"},
            "docker": "1fb931d2f6e5e4cfdbaf30fdb8e2fdd", "parent_exec_id": PARENT_EXEC_ID,
            "refcnt": 1, **({"environment_variables": [{"Key": k, "Value": v} for k, v in env.items()]} if env else {}),
            **kw}


def line(event, **top):
    """A GetEventsResponse line (api/v1/tetragon/events.proto): the event, node_name and time."""
    return json.dumps({**event, "node_name": "kind-control-plane", "time": TIME, **top})


def exec_line(**kw):
    return line({"process_exec": {"process": process(**kw), "parent": process(binary="/bin/bash")}})


def exit_line(**kw):   # ProcessExit: status uint32, left out when 0; signal a string
    return line({"process_exit": {"process": process(**kw), "parent": process(binary="/bin/bash"), "signal": "SIGKILL",
                                  "time": TIME}})


def kprobe_line(function, args, **kw):
    """A ProcessKprobe of the sample TracingPolicy (docs/integrations/tetragon.md), after docs/content/en/docs/use-cases/
    filename-access.md: function_name, args as KprobeArgument (sockaddr_arg: KprobeSockaddr family, addr, port)."""
    return line({"process_kprobe": {"process": process(**kw), "parent": process(binary="/bin/bash"),
                                    "function_name": function, "args": args, "action": "KPROBE_ACTION_POST",
                                    "policy_name": "tracekit-agent-effects", "return_action": "KPROBE_ACTION_POST"}})


CONNECT = [{"sockaddr_arg": {"family": "AF_INET", "addr": "93.184.215.14", "port": 443}}, {"int_arg": 16}]
WRITE = [{"file_arg": {"path": "/home/agent/.bashrc", "permission": "-rw-r--r--"}}, {"int_arg": 2}]
RATE_LIMITED = line({"rate_limit_info": {"number_of_dropped_process_events": "12"}})   # uint64: a JSON string


class TestTetragonLines(unittest.TestCase):
    def effect(self, text):
        attrs, effect = sensor.tetragon(json.loads(text))
        return attrs, effect()

    def test_exec_exit_connect_and_file_events(self):
        attrs, e = self.effect(exec_line(env={"CODEX_TOOL_CALL_ID": "call_7", "HOME": "/root"}))
        self.assertEqual(attrs, {"namespace": "agents", "pod": "coder-1", "uid": 1000, "container":
                                 "containerd://1fb931d2f6e5e4cfdbaf30fdb8e2fdd81320bdb3047ded50120a4f82838209ce"})
        self.assertEqual(e, {"kind": "exec", "args_digest": sensor._digest("-s https://example.com/install.sh"),
                             "ts": "2026-10-12T10:00:01.615123Z", "pid": 51583, "binary": "/usr/bin/curl",
                             "exec_id": EXEC_ID, "parent_exec_id": PARENT_EXEC_ID, "tool_call_id": "call_7"})
        self.assertEqual({k: self.effect(exit_line())[1][k] for k in ("kind", "status", "signal")},
                         {"kind": "exit", "status": 0, "signal": "SIGKILL"})
        self.assertEqual({k: self.effect(kprobe_line("security_socket_connect", CONNECT))[1][k]
                          for k in ("kind", "host", "port")}, {"kind": "connect", "host": "93.184.215.14", "port": 443})
        tcp = [{"sock_arg": {"family": "AF_INET6", "type": "SOCK_STREAM", "protocol": "IPPROTO_TCP",
                             "saddr": "fd00::2", "daddr": "2606:2800:21F:CB07::1", "sport": 40000, "dport": 443,
                             "cookie": "18446623433578736768", "state": "TCP_SYN_SENT"}}]
        self.assertEqual({k: self.effect(kprobe_line("tcp_connect", tcp))[1][k] for k in ("kind", "host", "port")},
                         {"kind": "connect", "host": "2606:2800:21f:cb07::1", "port": 443})
        self.assertEqual({k: self.effect(kprobe_line("security_file_permission", WRITE))[1][k] for k in
                          ("kind", "path")}, {"kind": "file", "path": "/home/agent/.bashrc"})

    def test_what_the_import_does_not_record(self):
        self.assertIsNone(self.effect(exec_line(flags="procFS auid rootcwd"))[1])   # running when Tetragon started
        self.assertIsNone(self.effect(kprobe_line("security_bprm_check", [{"int_arg": 1}]))[1])
        self.assertIsNone(sensor.tetragon(json.loads(line({"process_tracepoint": {"process": process()}}))))
        self.assertIsNone(sensor.tetragon({"process_throttle": {"type": "THROTTLE_STOP", "cgroup": "x"}}))
        e = self.effect(exec_line(env={"CODEX_TOOL_CALL_ID": "call 7; not an id"}))[1]   # an id the signer refuses
        self.assertNotIn("tool_call_id", e)

    def test_losses_the_stream_reports(self):
        self.assertIn("dropped 12 event(s)", sensor.tetragon(json.loads(RATE_LIMITED)))
        throttled = sensor.tetragon(json.loads(line({"process_throttle": {
            "type": "THROTTLE_START", "cgroup": "cri-containerd-1fb931d2.scope"}})))
        self.assertIn("throttled the exec and exit events of cgroup cri-containerd-1fb931d2.scope", throttled)


def falco_line(rule, evt_type, **fields):
    """A Falco alert as json_output writes it (userspace/engine/formats.cpp: time with nanoseconds, rule, priority,
    source, hostname, output, tags, output_fields with the fields the rule's output names, typed as libsinsp's tojson
    gives them: proc.pid and user.uid numbers, fd.sport a number, fd.sip a string), for the sample rules of
    docs/integrations/falco.md."""
    f = {"evt.time": 1791799201615123456, "evt.type": evt_type, "proc.pid": 51583, "proc.exepath": "/usr/bin/curl",
         "proc.cmdline": "curl -s https://example.com/install.sh", "user.uid": 1000, "container.id": "1fb931d2f6e5",
         "k8s.ns.name": "agents", "k8s.pod.name": "coder-1", "proc.env[CODEX_TOOL_CALL_ID]": "call_7", **fields}
    return json.dumps({"hostname": "node-1", "output": f"10:00:01.615123456: Informational {rule}",
                       "output_fields": f, "priority": "Informational", "rule": rule, "source": "syscall",
                       "tags": ["tracekit"], "time": TIME})


# userspace/falco/falco_outputs.cpp handle_msg and event_drops.cpp: an internal alert, every count a string
FALCO_DROPS = json.dumps({"output": "Falco internal: syscall event drop. 1287 system calls dropped in last second.",
                          "priority": "Debug", "rule": "Falco internal: syscall event drop", "time": TIME,
                          "output_fields": {"ebpf_enabled": "1", "n_drops": "1287", "n_drops_buffer_total": "1287",
                                            "n_drops_bug": "0", "n_drops_page_faults": "0", "n_evts": "23110"},
                          "hostname": "node-1", "source": "internal"})


class TestFalcoLines(unittest.TestCase):
    def effect(self, text):
        attrs, effect = sensor.falco(json.loads(text))
        return attrs, effect()

    def test_exec_connect_and_file_events(self):
        attrs, e = self.effect(falco_line("Tracekit agent exec", "execve"))
        self.assertEqual(attrs, {"namespace": "agents", "pod": "coder-1", "container": "1fb931d2f6e5", "uid": 1000})
        self.assertEqual(e, {"kind": "exec", "args_digest": sensor._digest("curl -s https://example.com/install.sh"),
                             "ts": "2026-10-12T10:00:01.615123Z", "pid": 51583, "binary": "/usr/bin/curl",
                             "tool_call_id": "call_7"})
        e = self.effect(falco_line("Tracekit agent connect", "connect", **{"fd.sip": "93.184.215.14",
                                                                          "fd.sport": 443}))[1]
        self.assertEqual((e["kind"], e["host"], e["port"]), ("connect", "93.184.215.14", 443))
        e = self.effect(falco_line("Tracekit agent write outside the workspace", "openat",
                                   **{"fd.name": "/home/agent/.bashrc"}))[1]
        self.assertEqual((e["kind"], e["path"]), ("file", "/home/agent/.bashrc"))

    def test_what_the_import_does_not_record(self):
        other = json.loads(falco_line("Terminal shell in container", "execve"))
        self.assertIsNone(sensor.falco(dict(other, tags=["container", "shell"])))   # not a tracekit rule
        self.assertIsNone(self.effect(falco_line("Tracekit agent exec", "clone"))[1])
        self.assertIn("dropping 1287 of 23110 syscall event(s) in one second", sensor.falco(json.loads(FALCO_DROPS)))


class Sensed(Lifecycle):
    def open(self):
        self.s = svc.SignerService(self.dir, policy=Engine({"tools": {"Bash": "shell"}}), grace_s=0, idle_s=3600,
                                   observe_grace_s=60, authorize={
                                       "mtls:spiffe://acme/tetragon": ["observe_effect"],
                                       "mtls:spiffe://acme/falco": ["observe_effect"],
                                       f"uid:{ME.subject}": sorted(svc.DEFAULT_GRANTS)})
        self.closed = False

    def importer(self, name="tetragon"):
        who = CallerIdentity("mtls", f"spiffe://acme/{name}", True)
        return sensor.Import(types.SimpleNamespace(observe_effect=lambda req: self.call("observe_effect", req, who)),
                             name, RUNS)

    def final(self, run, after=61):
        self.call("close_run", run)
        self.s.sweep(time.monotonic() + after)
        return self.events(run["run_id"])

    def typed(self, events, typ):
        return [e for e in events if e["type"] == typ]

    def gaps(self, events, kind):
        return [e["data"] for e in self.typed(events, "capture.gap") if e["data"]["kind"] == kind]


class TestImport(Sensed):
    def test_events_go_to_the_mapped_run_with_their_claimed_call_and_verify(self):
        imp = self.importer()
        self.assertTrue(imp.flush())   # its first heartbeat: it covers the runs registered from now on
        run = self.register()
        self.call("decide", self.ev(run, 0, tool_call_id="call_7", tool="Bash", args_source="parsed",
                                    args={"command": "curl -s https://example.com/install.sh"}))
        for text in (exec_line(env={"CODEX_TOOL_CALL_ID": "call_7"}),
                     kprobe_line("security_socket_connect", CONNECT, env={"CODEX_TOOL_CALL_ID": "call_9"}),
                     kprobe_line("security_file_permission", WRITE), exit_line(),
                     exec_line(pod="web-1")):   # a pod no runs entry matches: not an agent's
            imp.add(text)
        self.assertTrue(imp.flush())
        self.assertEqual(imp.skipped, 1)
        es = self.final(run)
        effects = [e["data"] for e in self.typed(es, "effect.observed")]
        # the call a process's environment names is the agent's claim: recorded, never signed as explaining the
        # effect, whether the run decided that call (call_7) or not (call_9); TK-X206 checks it
        self.assertEqual([(d["kind"], d.get("tool_call_id"), "explained_by" in d) for d in effects],
                         [("exec", "call_7", False), ("connect", "call_9", False), ("file", None, False),
                          ("exit", None, False)])
        x = effects[0]
        self.assertEqual({k: x[k] for k in ("observer", "sensor", "attribution", "tool_call_id", "binary", "pid",
                                            "parent_exec_id")},
                         {"observer": "mtls:spiffe://acme/tetragon", "sensor": "tetragon", "attribution": "identity",
                          "tool_call_id": "call_7", "binary": "/usr/bin/curl", "pid": 51583,
                          "parent_exec_id": PARENT_EXEC_ID})   # the process that started it: TK-X206's ancestry
        self.assertRegex(x["args_commitment"], "^hmac-sha256:")   # the arguments' digest never in the clear
        self.assertNotIn("args_digest", x)
        matrix = self.typed(es, "run.final")[0]["data"]["matrix"]
        self.assertEqual((matrix["processes"], matrix["network"]),
                         ({"status": "observed", "layers": ["tetragon"]}, {"status": "none", "layers": []}))
        self.open()
        self.s.checkpoint()
        note = self.s.log.storage.checkpoint_latest()[1]
        bundle, trust = os.path.join(self.dir, "b.tkb"), os.path.join(self.dir, "trust.json")
        export(self.s.log.storage, "default", run["run_id"], note, bundle)
        with open(trust, "w") as f:
            json.dump({"logs": [self.s.vkey], "algs": ["ed25519"]}, f)
        rep, code = v2.verify(bundle, trust)
        self.assertEqual((code, rep.integrity), (0, "VERIFIED"), rep.checks)
        self.assertIn("processes observed (tetragon)", {c["check"]: c for c in rep.checks}["coverage matrix"]["detail"])

    def test_an_event_no_open_run_holds_is_a_gap_in_the_signer_run(self):
        imp = self.importer()
        imp.add(exec_line(pod="idle-1"))   # mapped to an identity with no open run
        self.assertTrue(imp.flush())
        (gap,) = [d for d in self.gaps(self.events("tracekit/signer"), "effect_outside_run")]
        self.assertIn(f"tetragon mtls:spiffe://acme/tetragon saw exec by pid 51583 (/usr/bin/curl) at "
                      f"2026-10-12T10:00:01.615123Z that no open run holds: uid:{OTHER.subject} has no open run",
                      gap["reason"])

    def test_a_loss_is_a_signed_gap_and_ends_coverage(self):
        imp = self.importer()
        imp.flush()
        run = self.register()
        imp.add(RATE_LIMITED)
        imp.add('{"process_exec": {"process": ')   # cut off
        imp.add(exec_line(binary=""))   # an agent's event the signer would refuse: no binary
        imp.add(exec_line(pod="web-1", binary=""))   # the same of a process no runs entry matches: skipped
        self.assertTrue(imp.flush())
        es = self.final(run)
        (lost,) = self.gaps(es, "observer_lost")
        self.assertIn("the tetragon import mtls:spiffe://acme/tetragon reported lost events: 1 x Tetragon's export "
                      "rate limit dropped 12 event(s)", lost["reason"])
        self.assertIn("2 x tetragon lines the import could not read or record", lost["reason"])
        self.assertEqual(self.typed(es, "run.final")[0]["data"]["matrix"]["processes"], {"status": "none", "layers": []})

    def test_a_loss_with_no_run_covered_goes_to_the_signer_run(self):
        imp = self.importer()
        imp.add(RATE_LIMITED)
        imp.flush()
        (lost,) = self.gaps(self.events("tracekit/signer"), "observer_lost")
        self.assertIn("rate limit dropped 12 event(s)", lost["reason"])

    def test_a_silent_or_restarted_import_is_a_gap_in_its_words(self):
        imp = self.importer()
        imp.flush()
        run = self.register()
        self.s.sweep(time.monotonic() + svc.TAILER_LOST_S + 1)
        (lost,) = self.gaps(self.events(run["run_id"]), "observer_lost")
        self.assertIn("no observe_effect from the tetragon import mtls:spiffe://acme/tetragon", lost["reason"])
        self.open()
        imp.flush(time.monotonic() + svc.HEARTBEAT_S)
        later = self.register()
        imp.instance = "a-new-process"
        imp.flush(time.monotonic() + 2 * svc.HEARTBEAT_S)
        (lost,) = self.gaps(self.events(later["run_id"]), "observer_lost")
        self.assertIn("the tetragon import mtls:spiffe://acme/tetragon restarted", lost["reason"])

    def test_the_signer_keeps_sensor_and_net_effects_apart(self):
        run = self.register()
        exec_effect = {"kind": "exec", "ts": "2026-10-12T10:00:00.000000Z", "pid": 1, "binary": "/bin/sh", **run}
        net = {"kind": "net", "host": "a.example", "port": 443, "bytes_out": 1, "bytes_in": 1, "connections": 1,
               "first_ts": "2026-10-12T10:00:00.000000Z", "last_ts": "2026-10-12T10:00:00.000000Z", **run}
        for req in ({"effects": [exec_effect]}, {"effects": [net], "sensor": "tetragon"}, {"effects": [], "lost": "x"},
                    {"effects": [dict(exec_effect, kind="file")], "sensor": "tetragon"}):   # a file event needs a path
            with self.subTest(req):
                self.refused("invalid_request", "observe_effect", {"instance": "i", **req}, SENSOR)
        self.refused("forbidden", "observe_effect", {"instance": "i", "sensor": "tetragon",
                                                     "effects": [dict(exec_effect, caller=f"uid:{ME.subject}")]})


class TestFalcoImport(Sensed):
    def test_falco_events_and_drops(self):
        imp = self.importer("falco")
        imp.flush()
        run = self.register()
        self.call("decide", self.ev(run, 0, tool_call_id="call_7", tool="Bash", args_source="parsed",
                                    args={"command": "curl -s https://example.com/install.sh"}))
        imp.add(falco_line("Tracekit agent exec", "execve"))
        imp.add(falco_line("Tracekit agent exec", "execve", **{"k8s.pod.name": "idle-1"}))   # no open run
        imp.add(falco_line("Tracekit agent exec", "execve", **{"k8s.ns.name": None, "k8s.pod.name": None}))   # host
        imp.add(FALCO_DROPS)
        self.assertTrue(imp.flush())
        es = self.final(run)
        [x] = [e["data"] for e in self.typed(es, "effect.observed")]
        self.assertEqual({k: x.get(k) for k in ("sensor", "kind", "tool_call_id", "explained_by", "observer")},
                         {"sensor": "falco", "kind": "exec", "tool_call_id": "call_7", "explained_by": None,
                          "observer": "mtls:spiffe://acme/falco"})
        (lost,) = self.gaps(es, "observer_lost")
        self.assertIn("the falco import mtls:spiffe://acme/falco reported lost events: 1 x Falco reported dropping "
                      "1287 of 23110", lost["reason"])
        (outside,) = self.gaps(self.events("tracekit/signer"), "effect_outside_run")
        self.assertIn("falco mtls:spiffe://acme/falco saw exec by pid 51583", outside["reason"])
        self.assertEqual(imp.skipped, 1)


class TestDelivery(Sensed):
    def test_an_unreachable_signer_gets_the_same_request_again(self):
        imp = self.importer()
        imp.client = types.SimpleNamespace(observe_effect=mock.Mock(side_effect=[SignerUnavailable("down"), None]))
        imp.add(exec_line())
        self.assertFalse(imp.flush())
        self.assertTrue(imp.flush())
        first, second = (c[0][0] for c in imp.client.observe_effect.call_args_list)
        self.assertEqual(first, second)

    def test_past_the_buffer_events_are_a_loss(self):
        imp = self.importer()
        with mock.patch.object(sensor, "MAX_PENDING", 1):
            imp.add(exec_line())
            imp.add(exec_line())
        self.assertEqual(len(imp.pending), 1)
        self.assertEqual(list(imp.lost.values()), [1])

    def test_a_refusal_stops_the_import(self):
        imp = self.importer()
        imp.client = types.SimpleNamespace(observe_effect=mock.Mock(side_effect=RPCError("forbidden", "no grant")))
        with self.assertRaises(RPCError):
            imp.flush()


class TestCommand(unittest.TestCase):
    def config(self, text):
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w") as f:
            f.write(text)
        self.addCleanup(os.unlink, path)
        return path

    def test_config(self):
        cfg = sensor.load_config(self.config("sensor: tetragon\nsigner: https://signer.internal:8443\nruns:\n"
                                             "  - match: {namespace: agents, pod: \"coder-*\"}\n"
                                             "    caller: k8s_sa:system:serviceaccount:agents:coder\n"))
        self.assertEqual(cfg["runs"], [{"match": {"namespace": "agents", "pod": "coder-*"},
                                        "caller": "k8s_sa:system:serviceaccount:agents:coder"}])
        for bad in ("sensor: auditd\nsigner: x\nruns: []\n", "sensor: tetragon\nsigner: x\n",
                    "sensor: tetragon\nsigner: x\nruns:\n  - match: {cgroup: x}\n    caller: uid:1\n"):
            with self.subTest(bad), self.assertRaises(ValueError):
                sensor.load_config(self.config(bad))
        self.assertEqual(sensor.main(["import", "--config", self.config("sensor: x\n")]), 2)
        good = self.config("sensor: tetragon\nsigner: x\nruns:\n  - match: {uid: 1000}\n    caller: uid:1000\n")
        self.assertEqual(sensor.main(["import", "--config", good, "--follow", "/nonexistent/tetragon.log"]), 2)

    def test_run_sends_a_file_and_returns(self):
        sent = []
        imp = sensor.Import(types.SimpleNamespace(observe_effect=sent.append), "tetragon", RUNS)
        self.assertEqual(sensor.run(imp, [exec_line().encode() + b"\n", RATE_LIMITED.encode() + b"\n"]), 0)
        self.assertEqual([len(r["effects"]) for r in sent if r["effects"]], [1])
        self.assertIn("rate limit", next(r["lost"] for r in sent if "lost" in r))

    def test_follow_reads_across_rotation(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        path = os.path.join(d.name, "tetragon.log")
        with open(path, "w") as f:
            f.write("old\n")   # before the import started: not read
        steps = [lambda: _append(path, "a\nb"), lambda: _append(path, "\n"),
                 lambda: (os.rename(path, path + ".1"), _append(path + ".1", "c\n"), _append(path, "d\n"))]

        def sleep(_):
            if not steps:
                raise InterruptedError
            steps.pop(0)()
        got, f = [], open(path, "rb")
        self.addCleanup(f.close)
        with mock.patch.object(sensor.time, "sleep", sleep):
            try:
                for text in sensor._follow(f, path):
                    got.append(text)
            except InterruptedError:
                pass
        self.assertEqual(got, [b"a\n", b"b\n", b"c\n", b"d\n"])


def _append(path, text):
    with open(path, "a") as f:
        f.write(text)


if __name__ == "__main__":
    unittest.main()
