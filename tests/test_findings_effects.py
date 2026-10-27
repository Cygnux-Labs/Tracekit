"""TK-X206 and TK-X207 (tracekit/findings_effects.py): a kernel sensor's effects joined to the calls a run decided,
on runs replayed into an in-process signer on a synthetic clock with the sensor import's identity
(eval/e20_alignment.py's effects replay): positive, negative and not checkable for each way an effect is explained."""
import os
import random
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval.e20_alignment import SENSOR, Signer, effects_replay  # noqa: E402
from tracekit import findings_effects, findings_v2  # noqa: E402
from tracekit.why.signed import vault_content  # noqa: E402

CWD = "/workspace/app"


class Scene:
    """A run: its calls (signer times, seconds from its start) and the processes a sensor saw, with exec ids and
    parent exec ids (`parents`, as Tetragon gives) or neither (as Falco), its clock `skew` seconds ahead."""

    def __init__(self, parents=True, skew=0.0, sensor=True):
        self.pid = 100
        self.sess = {"calls": [], "procs": [], "skew": skew, "parents": parents, "sensor": sensor,
                     "latency": (0.3, 0.3), "end": 1.0,
                     "harness": {"pid": 7, "exec_id": "harness", "binary": "/usr/bin/node", "effects": []}}

    def call(self, tid, tool, args, t0, t1):
        self.sess["calls"].append({"id": tid, "tool": tool, "args": args, "t0": t0, "t1": t1, "ok": True})
        self.sess["end"] = max(self.sess["end"], t1 + 1)
        return tid

    def proc(self, binary, t, parent="harness", claim=None, effects=()):
        """A process starting at `t`, its effects [(kind, t, fields)]. -> its exec id."""
        self.pid += 1
        self.sess["procs"].append({"pid": self.pid, "exec_id": f"x{self.pid}", "parent": parent, "binary": binary,
                                   "t": t, "claim": claim, "effects": list(effects), "exit": None, "role": "-"})
        self.sess["end"] = max(self.sess["end"], t + 1)
        return f"x{self.pid}"

    def harness(self, kind, t, **fields):
        """An effect of the agent's harness, a process running from before the run."""
        self.sess["harness"]["effects"].append((kind, t, fields))
        self.sess["end"] = max(self.sess["end"], t + 1)


@unittest.skipIf(os.name == "nt", "the in-process signer's sensor identity is POSIX-only here")
class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.signer = Signer(os.path.join(self.d, "data"), SENSOR)
        self.addCleanup(self.signer.close)

    def analyze(self, scene, **opts):
        self.records, content = effects_replay(self.signer, scene.sess, random.Random(0))
        self.content = content
        return findings_v2.analyze(self.records, content, effects=findings_effects.options(**opts))

    def statuses(self, out, binary):
        """{kind: (status, call, how)} of the effects of the processes of `binary`."""
        shown = out["shown"]["effects"]
        return {r["event"]["data"]["kind"]: tuple(shown[r["event"]["run_seq"]][k] for k in ("status", "call", "how"))
                for r in self.records if r["event"]["type"] == "effect.observed"
                and r["event"]["data"]["binary"] == binary and r["event"]["run_seq"] in shown}

    def found(self, out, rule):
        return [(f, d) for f, d in zip(out["findings"], out["shown"]["details"]) if f["verdict"]["rule"] == rule]


def bash(s, tid, cmd, t0, t1, program, **effects):
    """A Bash call whose shell runs `program`, which has `effects`."""
    s.call(tid, "Bash", {"command": cmd}, t0, t1)
    sh = s.proc("/bin/bash", t0 + 0.05)
    return s.proc(program, t0 + 0.1, sh, effects=[(k, t0 + 0.2, v) for k, v in effects.items()])


class TheHarnessOwn(Base):   # TK-X203, TK-X204 of a sensor's file and connect effects
    def test_the_harness_own_writes_are_counted_not_checkable_and_a_calls_write_there_still_found(self):
        s = Scene()
        s.sess["prompt"] = "Fix the bug. Read-only outside src/, and no network."
        s.harness("file", 2.0, path="/home/agent/.claude/projects/p/s.jsonl")   # its transcript
        s.harness("connect", 2.5, host="160.79.104.10", port=443)               # its model call
        bash(s, "b", "echo '{}' > /home/agent/.claude/settings.json", 5.0, 5.5, "/usr/bin/tee",
             file={"path": "/home/agent/.claude/settings.json"})               # a call writing the harness's state
        self.records, content = effects_replay(self.signer, s.sess, random.Random(0))
        out = findings_v2.analyze(self.records, content, project=CWD, effects=findings_effects.options())
        whats = [d["what"] for f, d in self.found(out, "TK-X203")]
        self.assertEqual([w for w in whats if "s.jsonl" in w], [])
        self.assertEqual(len([w for w in whats if "settings.json" in w]), 2)   # the command, and what the sensor saw
        checks = out["coverage"]["verdict"]["checks"]
        self.assertIn({"reason": "agent_process", "n": 1}, checks["TK-X203"]["not_checkable"])
        self.assertIn({"reason": "agent_process", "n": 2}, checks["TK-X204"]["not_checkable"])   # file and connect
        self.assertEqual([d["what"] for f, d in self.found(out, "TK-X204") if "node" in d["what"]], [])
        self.assertIn("TK-X203 for 1 effect: a process running before the run", findings_v2.render(out))


class EffectWithNoAction(Base):   # TK-X206
    def test_a_process_no_call_started_is_found_and_the_finding_holds_no_plaintext(self):
        s = Scene()
        bash(s, "t1", "git status", 1.0, 2.0, "/usr/bin/git")
        s.proc("/usr/bin/curl", 10.0, effects=[("connect", 10.1, {"host": "203.0.113.7", "port": 443})])
        bash(s, "t2", "ls", 20.0, 21.0, "/usr/bin/ls")
        out = self.analyze(s)
        self.assertEqual(self.statuses(out, "/usr/bin/curl"), {"exec": ("found", None, None),
                                                               "connect": ("found", None, None)})
        [(f, d)] = self.found(out, "TK-X206")
        self.assertEqual(f["verdict"], {"kind": "finding", "rule": "TK-X206", "severity": "high",
                                        "window": {"grace_s": 2.0, "skew_s": 0.5}})   # the window it joined with
        effects = [r for r in self.records if r["event"]["type"] == "effect.observed"
                   and r["event"]["data"]["binary"] == "/usr/bin/curl"]
        self.assertEqual(f["cites"], [{"run_seq": r["event"]["run_seq"], "hash": r["hash"]} for r in effects])
        self.assertIn("/usr/bin/curl start and connect to 203.0.113.7:443", d["what"])
        self.assertIn("no call that runs processes was in progress then [window: grace 2 s, clock skew 0.5 s]",
                      d["what"])
        vaulted = {c.get("command") for _, c, _ in vault_content(self.signer, self.records, "test")} - {None}
        self.assertTrue(vaulted and not any(v in str(out["findings"]) for v in vaulted))
        self.assertEqual(out["coverage"]["verdict"]["checks"]["TK-X206"]["found"], 1)

    def test_the_processes_of_a_call_and_their_children_are_explained_by_it(self):
        s = Scene()
        bash(s, "t1", "curl -s https://example.com", 1.0, 3.0, "/usr/bin/curl",
             connect={"host": "93.184.215.14", "port": 443})
        out = self.analyze(s)
        self.assertEqual(self.statuses(out, "/bin/bash"), {"exec": ("explained", "t1", "window")})
        self.assertEqual(self.statuses(out, "/usr/bin/curl"), {"exec": ("explained", "t1", "ancestry"),
                                                               "connect": ("explained", "t1", "process")})
        self.assertEqual(self.found(out, "TK-X206"), [])

    def test_a_process_naming_a_call_is_rechecked(self):
        # R7: the claim (CODEX_TOOL_CALL_ID) holds only for a call the run ran, inside its window, of a fitting tool
        s = Scene()
        s.call("read", "Read", {"file_path": f"{CWD}/a.py"}, 1.0, 1.2)
        s.call("sh", "Bash", {"command": "make"}, 5.0, 6.0)
        s.proc("/usr/bin/make", 5.1, claim="sh")             # fits, in its window
        s.proc("/usr/bin/python3", 1.1, claim="read")        # a Read call starts no process
        s.proc("/usr/bin/wget", 30.0, claim="sh")            # long after that call's window
        s.proc("/usr/bin/nc", 31.0, claim="never")           # a call the run never decided
        out = self.analyze(s)
        self.assertEqual(self.statuses(out, "/usr/bin/make"), {"exec": ("explained", "sh", "claim")})
        whys = {d["what"].split(": ", 1)[1].split(" [")[0] for _, d in self.found(out, "TK-X206")}
        self.assertEqual(whys, {"it names call read, but that call's tool, Read, doesn't start a process",
                                "it names call sh (Bash), but happened outside that call's window",
                                "it names call never (its environment's tool call id, the agent's claim), which the "
                                "run never decided"})
        decision = next(r for r in self.records if r["event"]["type"] == "policy.decision"
                        and r["event"]["data"]["tool_use_id"] == "read")
        f = next(f for f, d in self.found(out, "TK-X206") if "call read" in d["what"])
        self.assertIn({"run_seq": decision["event"]["run_seq"], "hash": decision["hash"]}, f["cites"])

    def test_a_daemon_a_call_left_running_is_that_calls_with_parent_ids_and_a_finding_without(self):
        for parents in (True, False):
            with self.subTest(parents=parents):
                s = Scene(parents=parents)
                server = bash(s, "t1", "python3 -m http.server &", 1.0, 2.0, "/usr/bin/python3.12")
                s.proc("/usr/bin/curl", 40.0, server, effects=[("connect", 40.1, {"host": "93.184.215.14",
                                                                                   "port": 443})])
                out = self.analyze(s)
                self.assertEqual(self.statuses(out, "/usr/bin/curl")["connect"][0], "explained" if parents else "found")
        s = Scene()   # Codex: the daemon's child names the call too, long after its window: its parent vouches
        s.call("sh", "Bash", {"command": "node server.js &"}, 1.0, 2.0)
        server = s.proc("/usr/local/bin/node", 1.1, claim="sh")
        s.proc("/usr/bin/git", 40.0, server, claim="sh")
        self.assertEqual(self.statuses(self.analyze(s), "/usr/bin/git"), {"exec": ("explained", "sh", "ancestry")})

    def test_hook_like_processes_are_not_checkable_and_hide_no_other_program(self):
        s = Scene()
        s.call("r", "Read", {"file_path": f"{CWD}/a.py"}, 5.0, 5.2)
        hook = s.proc("/bin/sh", 4.8)                        # Tracekit's PreToolUse hook, before the decision
        s.proc("/opt/tracekit/bin/python3", 4.81, hook)
        s.proc("/usr/bin/curl", 4.82, hook)                  # a planted hook's program is no hook
        out = self.analyze(s)
        self.assertEqual(self.statuses(out, "/bin/sh"), {"exec": ("hook_like", None, None)})
        self.assertEqual(self.statuses(out, "/opt/tracekit/bin/python3"), {"exec": ("hook_like", None, None)})
        self.assertEqual(self.statuses(out, "/usr/bin/curl"), {"exec": ("found", None, None)})
        self.assertEqual(out["coverage"]["verdict"]["checks"]["TK-X206"]["not_checkable"],
                         [{"reason": "hook_like", "n": 2}])

    def test_the_harness_own_effects_are_not_checkable_but_a_write_tools_file_is_explained(self):
        s = Scene()
        s.call("w", "Write", {"file_path": "/etc/hosts", "content": "x"}, 5.0, 5.2)
        s.harness("file", 5.05, path="/etc/hosts")
        s.harness("connect", 9.0, host="160.79.104.10", port=443)       # its model call
        s.harness("file", 9.5, path="/home/agent/.claude/projects/p/s.jsonl")   # its transcript
        out = self.analyze(s)
        got = self.statuses(out, "/usr/bin/node")
        self.assertEqual(got["connect"], ("agent_process", None, None))
        joined = [out["shown"]["effects"][r["event"]["run_seq"]] for r in self.records
                  if r["event"]["type"] == "effect.observed" and r["event"]["data"].get("path") == "/etc/hosts"]
        self.assertEqual(joined, [{"call": "w", "how": "path", "status": "explained"}])
        self.assertEqual(self.found(out, "TK-X206"), [])

    def test_clock_skew_within_the_tolerance_passes_and_past_it_is_labelled_with_the_fix(self):
        for skew, seen in ((0.3, None), (3.0, "ahead_s"), (-3.0, "behind_s")):
            with self.subTest(skew=skew):
                s = Scene(skew=skew)
                bash(s, "t1", "git status", 1.0, 1.4, "/usr/bin/git")
                out = self.analyze(s)
                window = out["shown"]["effect_window"]
                if seen is None:
                    self.assertNotIn("skew_seen", window)
                    self.assertEqual(self.found(out, "TK-X206"), [])
                    continue
                self.assertIn(seen, window["skew_seen"])
                [(_, d)] = self.found(out, "TK-X206")
                self.assertEqual(d["labels"], ["clock_skew"])
                self.assertIn(f"pass --clock-skew {window['skew_seen']['suggest_s']:g}", d["what"])
                again = findings_v2.analyze(self.records, self.content, effects=findings_effects.options(
                    skew_s=window["skew_seen"]["suggest_s"]))
                self.assertEqual(self.found(again, "TK-X206"), [])


class ActionWithNoEffect(Base):   # TK-X207
    def checks(self, out, tid):
        return out["shown"]["calls"][tid]["checks"].get("TK-X207")

    def test_a_command_whose_program_never_ran_is_found(self):
        s = Scene()
        bash(s, "ran", "git status", 1.0, 2.0, "/usr/bin/git")
        s.call("faked", "Bash", {"command": "cd src && make -j4 test > log.txt"}, 5.0, 6.0)
        s.proc("/bin/bash", 5.05)
        out = self.analyze(s)
        self.assertEqual((self.checks(out, "ran"), self.checks(out, "faked")), ("checked", "found"))
        [(f, d)] = self.found(out, "TK-X207")
        self.assertEqual(f["verdict"]["severity"], "medium")
        self.assertIn("Bash (call faked) returned ok, but the tetragon sensor saw no start of make", d["what"])

    def test_a_write_shows_up_where_the_sensor_selects_writes(self):
        s = Scene()
        s.call("in", "Write", {"file_path": f"{CWD}/a.py", "content": "x"}, 1.0, 1.1)
        s.call("seen", "Write", {"file_path": "/etc/hosts", "content": "x"}, 3.0, 3.1)
        s.harness("file", 3.05, path="/etc/hosts")
        s.call("unseen", "Write", {"file_path": "/etc/cron.d/x", "content": "x"}, 5.0, 5.1)
        out = self.analyze(s, skips=["/workspace", "/tmp"])
        self.assertEqual([self.checks(out, t) for t in ("in", "seen", "unseen")], [None, "checked", "found"])
        out = self.analyze(s)
        self.assertEqual(self.checks(out, "unseen"), "sensor_paths")

    def test_a_fetch_needs_a_connection_besides_the_harness_own_traffic(self):
        s = Scene()
        s.harness("connect", 0.5, host="160.79.104.10", port=443)   # the model API, outside any fetch
        s.call("f1", "WebFetch", {"url": "https://docs.python.org/"}, 2.0, 4.0)
        s.harness("connect", 2.2, host="151.101.0.223", port=443)
        s.call("f2", "WebFetch", {"url": "https://pypi.org/"}, 8.0, 10.0)
        s.harness("connect", 9.0, host="160.79.104.10", port=443)     # only the model API again
        out = self.analyze(s)
        self.assertEqual((self.checks(out, "f1"), self.checks(out, "f2")), ("checked", "found"))

    def test_what_a_hook_may_have_run_is_not_checkable(self):
        s = Scene()
        s.call("r", "Read", {"file_path": f"{CWD}/a.py"}, 1.0, 1.2)
        s.proc("/opt/tracekit/bin/python3", 0.9)                       # a hook outside any call
        s.call("t", "Bash", {"command": "python3 -m pytest -q"}, 5.0, 7.0)
        s.proc("/opt/tracekit/bin/python3", 6.9)                       # only the PostToolUse hook ran a python
        out = self.analyze(s)
        self.assertEqual(self.checks(out, "t"), "hook_binary")

    def test_without_a_sensor_nothing_is_checked_and_coverage_says_so(self):
        s = Scene(sensor=False)
        s.call("t", "Bash", {"command": "git status"}, 1.0, 2.0)
        s.signer = None
        with tempfile.TemporaryDirectory() as d:
            bare = Signer(os.path.join(d, "data"))   # no sensor import ever reached it
            try:
                records, content = effects_replay(bare, s.sess, random.Random(0))
                out = findings_v2.analyze(records, content)
            finally:
                bare.close()
        checks = out["coverage"]["verdict"]["checks"]
        self.assertEqual((checks["TK-X206"]["not_checkable"], checks["TK-X207"]["not_checkable"]),
                         ([{"reason": "no_sensor", "n": 1}], [{"reason": "no_sensor", "n": 1}]))
        self.assertNotIn("TK-X207", out["shown"]["calls"]["t"]["checks"])
        text = findings_v2.render(out)
        self.assertIn("TK-X207 for 1 call: run.final's coverage matrix doesn't say a kernel sensor observed", text)
        self.assertIn("run `tracekit sensor import` for this run", text)


class Parts(unittest.TestCase):
    def test_the_programs_a_command_runs(self):
        self.assertEqual(findings_effects._programs("cd src; FOO=1 timeout 10 python3 -m pytest 2>&1 | tail -5"),
                         ["python3", "tail"])
        self.assertEqual(findings_effects._programs("echo hi > out.txt && sudo env X=1 ./build.sh"), ["./build.sh"])
        self.assertEqual(findings_effects._programs("cd /x && export A=1"), [])
        # a `#` starts a comment only at the start of a word, as in a shell
        self.assertEqual(findings_effects._programs("make a#b && rm -rf c"), ["make", "rm"])
        self.assertEqual(findings_effects._programs("make all #x && rm -rf c"), ["make"])
        self.assertTrue(findings_effects._matches("/usr/bin/python3.12", "python3"))
        self.assertFalse(findings_effects._matches("/usr/bin/gofmt", "go"))

    def test_the_options_are_command_line_flags(self):
        import argparse
        ap = argparse.ArgumentParser()
        findings_effects.arguments(ap)
        self.assertEqual(findings_effects.from_args(ap.parse_args(
            ["--effect-grace", "5", "--clock-skew", "2", "--sensor-skip", "/workspace/", "--sensor-skip", ""])),
            {"grace_s": 5.0, "skew_s": 2.0, "skips": ["/workspace"]})
        self.assertIsNone(findings_effects.from_args(ap.parse_args([]))["skips"])


if __name__ == "__main__":
    unittest.main()


class Bounded(unittest.TestCase):
    def test_a_call_with_no_result_does_not_make_each_effect_scan_every_call(self):
        import datetime
        import time

        def iso(t):
            return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        recs, content, t = [], {}, 1_700_000_000.0

        def rec(typ, data, ts, body=None):
            recs.append({"event": {"type": typ, "run_seq": len(recs), "run_id": "r", "source": "sdk", "stream": "s",
                                   "ts": iso(ts), "data": data}, "hash": f"sha256:{len(recs):064x}"})
            if body is not None:
                content[len(recs) - 1] = body
        rec("run.registered", {"agent": {"name": "x"}}, t)
        for i in range(3000):   # the first call never returns
            t += 1
            rec("policy.decision", {"tool_use_id": f"t{i}", "tool": "Edit", "decision": "allow"}, t,
                {"file_path": f"/w/f{i}.py"})
            if i:
                rec("tool.result", {"tool_use_id": f"t{i}", "ok": True}, t + 0.5)
        for j in range(12000):   # the harness's own writes after the calls
            t += 0.01
            rec("effect.observed", {"kind": "file", "path": f"/home/u/.claude/x{j}.jsonl", "op": "write", "pid": 7,
                                    "binary": "/usr/bin/node", "sensor": "tetragon", "ts": iso(t)}, t + 0.1)
        rec("run.final", {"matrix": {"processes": {"status": "observed"}}}, t + 1)
        t0 = time.perf_counter()
        out = findings_v2.analyze(recs, lambda want: ((r["event"]["run_seq"], content[r["event"]["run_seq"]], True)
                                                      for r in want if r["event"]["run_seq"] in content))
        self.assertLess(time.perf_counter() - t0, 3)   # was ~10 s: each effect scanned every call before it
        self.assertEqual(out["coverage"]["verdict"]["checks"]["TK-X206"]["not_checkable"],
                         [{"reason": "agent_process", "n": 12000}])
