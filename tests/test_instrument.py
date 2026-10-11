"""The three-step quickstart in this checkout: `tracekit.instrument()` (tracekit/autowire.py) in a scripted agent of
each installed framework, against a dev signer it starts, then `tracekit last`. tests/test_quickstart.py runs the same
agents from the built wheel in a fresh venv."""
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import warnings
from importlib import metadata
from unittest import mock

from adapter_contract import OnReal
from quickstart_agents import AGENTS, REFUSED

from tracekit import autowire
from tracekit.sdk.client import Client, SignerUnavailable, current_run
from tracekit.signer.rpc_schema import RPCError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def installed(requirements):
    try:
        for r in requirements:
            metadata.version(r.split(">")[0].split("<")[0].split("=")[0])
    except metadata.PackageNotFoundError:
        return False
    return sys.version_info >= (3, 10)


class DevSigner(unittest.TestCase):
    """A temp HOME, data dir and runtime dir: the dev signer the agents start is this class's own."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(dir="/tmp" if os.path.isdir("/tmp") else None)   # macOS caps socket paths
        cls.addClassCleanup(shutil.rmtree, cls.dir, True)
        home = os.path.join(cls.dir, "home")
        cls.env = {k: v for k, v in os.environ.items() if not k.startswith("TRACEKIT_")}
        cls.env.update(HOME=home, USERPROFILE=home, LOCALAPPDATA=os.path.join(home, "local"),
                       XDG_DATA_HOME=os.path.join(home, "data"), TRACEKIT_RUNTIME_DIR=os.path.join(cls.dir, "run"),
                       TRACEKIT_DEV_IDLE="120", PYTHONPATH=ROOT)
        cls.addClassCleanup(cls.sh, "-m", "tracekit", "down")

    @classmethod
    def sh(cls, *argv, code=0, stdin=None):
        p = subprocess.run([sys.executable, *argv], capture_output=True, text=True, env=cls.env, cwd=cls.dir,
                           timeout=120, input=stdin)
        assert code is None or p.returncode == code, f"{argv} exited {p.returncode}\n{p.stdout}\n{p.stderr}"
        return p


class TestEmptyStore(DevSigner):
    def test_no_runs_yet(self):
        p = self.sh("-m", "tracekit", "last", code=1)
        self.assertIn("no runs in the dev signer's store", p.stderr)
        self.assertIn("tracekit.instrument()", p.stderr)


class TestThreeSteps(DevSigner):
    def test_each_framework(self):
        for name, (reqs, script) in AGENTS.items():
            if not installed(reqs):   # skipTest in a subTest skips them all where pytest has no subtests
                print(f"skipped {name}: {' '.join(reqs)} not installed")
                continue
            with self.subTest(name):
                out = json.loads(self.sh("-c", script).stdout.splitlines()[-1])
                self.assertTrue(out[0].startswith("ran "), out)
                if name != "openai":
                    self.assertIn(REFUSED, out[1])
                p = self.sh("-m", "tracekit", "last")
                self.assertIn("Integrity: VERIFIED.\nAssurance: dev", p.stdout)
                bundle = p.stdout.split("bundle: ", 1)[1].splitlines()[0]
                self.assertTrue(os.path.isfile(bundle) and os.path.isfile(bundle[:-4] + ".trust.json"))
                self.assertIn("next: tracekit view --dev", p.stdout)
                self.sh("-m", "tracekit", "verify", bundle, "--trust", bundle[:-4] + ".trust.json")

    def test_a_run_still_open_is_named_and_skipped(self):
        if not installed(AGENTS["mcp"][0]):
            self.skipTest("mcp not installed")
        self.sh("-c", AGENTS["mcp"][1])
        older = self.sh("-m", "tracekit", "last").stdout.splitlines()[0]
        # an agent killed before it could close its run
        self.sh("-c", "import os, tracekit; r = tracekit.instrument('killed'); print(r.run_id, flush=True); "
                      "os._exit(0)")
        p = self.sh("-m", "tracekit", "last")
        self.assertIn("(killed) is still open", p.stderr)
        self.assertIn("showing the run before it", p.stderr)
        self.assertEqual(p.stdout.splitlines()[0], older)

    def test_idempotent(self):
        if not installed(AGENTS["mcp"][0]):
            self.skipTest("mcp not installed")
        p = self.sh("-c", "import tracekit; a = tracekit.instrument(); print(a is tracekit.instrument(), a.run_id)")
        self.assertTrue(p.stdout.startswith("True "), p.stdout)


class TestInstrument(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(autowire._STATE, run=None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_nothing_installed_warns_and_records_nothing(self):
        with mock.patch.object(autowire, "_version", return_value=None), \
                mock.patch("tracekit.sdk.client.Client") as client, warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self.assertIsNone(autowire.instrument())
        client.assert_not_called()
        self.assertEqual(len(w), 1)
        self.assertIn("nothing is recorded", str(w[0].message))

    def test_no_signer_says_what_to_do(self):
        with mock.patch.object(autowire, "_version", return_value="1.0"), \
                mock.patch.dict(os.environ, TRACEKIT_SIGNER=os.path.join(tempfile.gettempdir(), "no-such.sock")), \
                self.assertRaises(SignerUnavailable) as cm:
            autowire.instrument()
        self.assertIn("unset it for a same-user dev signer", str(cm.exception))
        self.assertIsNone(autowire._STATE["run"])

    def test_a_framework_that_cannot_be_wired_is_skipped_with_a_warning(self):
        def broken(run):
            raise ImportError("cannot import name 'ToolNode'")
        wired = mock.Mock()
        frameworks = (("Broken", "broken", (1,), (2,), "broken>=1,<2", "custom", broken),
                      ("Fine", "fine", (1,), (2,), "fine>=1,<2", "custom", wired))
        versions = {"broken": "1.5", "fine": "2.1rc1"}
        with mock.patch.object(autowire, "FRAMEWORKS", frameworks), \
                mock.patch.object(autowire, "_version", side_effect=versions.get), \
                mock.patch("tracekit.sdk.client.Client"), mock.patch("atexit.register"), \
                mock.patch("tracekit.autotrace.instrument"), warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            run = autowire.instrument()
        wired.assert_called_once_with(run)
        msgs = [str(x.message) for x in w]
        self.assertIn("Broken 1.5 not wired (ImportError: cannot import name 'ToolNode'). Tracekit is tested with "
                      "broken>=1,<2", msgs[0])
        self.assertIn("Fine 2.1rc1 is wired but untested", msgs[1])

    def test_instrument_called_while_wiring_returns_the_same_run(self):
        """A module imported while a framework is wired may call instrument() itself (a script named after the
        package it imports): it gets the run at once instead of waiting for the call that is wiring."""
        inner = []
        frameworks = (("Fine", "fine", (1,), (2,), "fine>=1,<2", "custom", lambda run: inner.append(autowire.instrument())),)
        with mock.patch.object(autowire, "FRAMEWORKS", frameworks), \
                mock.patch.object(autowire, "_version", return_value="1.5"), \
                mock.patch("tracekit.sdk.client.Client"), mock.patch("atexit.register"), \
                mock.patch("tracekit.autotrace.instrument"):
            run = autowire.instrument()
        self.assertEqual(inner, [run])

    def test_a_tracer_names_the_v1_function(self):
        with self.assertRaises(TypeError) as cm:
            autowire.instrument(object())
        self.assertIn("tracekit.autotrace.instrument(tracer)", str(cm.exception))

    def test_mcp_sessions_share_one_stream(self):
        if not installed(AGENTS["mcp"][0]):
            self.skipTest("mcp not installed")
        from mcp import ClientSession
        seen = []

        async def call_tool(gate, *a, **kw):
            seen.append(gate)
        run = mock.Mock(registered={"run_id": "r", "run_token": "t"})
        with mock.patch.object(ClientSession, "call_tool", ClientSession.call_tool), \
                mock.patch("tracekit.integrations.mcp.TracekitSession.call_tool", call_tool):
            autowire._mcp(run)
            a, b = object.__new__(ClientSession), object.__new__(ClientSession)
            for s in (a, b, a):
                asyncio.run(s.call_tool("t", {}))
        self.assertIs(seen[0], seen[2])
        self.assertIsNot(seen[0], seen[1])
        self.assertEqual((seen[0].stream, seen[0]._seq), (seen[1].stream, seen[1]._seq))

    def test_release(self):
        for v, want in (("0.23.1", (0, 23, 1)), ("1.2.14", (1, 2, 14)), ("2.3.0rc1", (2, 3, 0)), ("1.4.dev0", (1, 4))):
            self.assertEqual(autowire._release(v), want)


if __name__ == "__main__":
    unittest.main()


class ProcessRun(OnReal, unittest.TestCase):
    """The client instrument() wires every adapter with: calls addressed to the process run follow the current run,
    and a process run the signer closed is renewed, never refused for good."""

    def setUp(self):
        self.client = autowire._process_client(Client, RPCError, current_run)(self.serve_signer())
        self.addCleanup(self.client.close)
        self.process = self.client.start("server")
        self.seq = 0

    def decide(self, call_id):
        """A decide as an adapter sends it: addressed to the process run, numbered by the adapter's own counter."""
        self.seq += 1
        return self.client.decide({"run_id": self.process.run_id, "run_token": self.process.run_token,
                                   "stream": "adapter", "client_seq": self.seq - 1, "tool_call_id": call_id,
                                   "tool": "read_file", "args_source": "parsed", "args": {}})

    def tools(self, run):
        return [e["data"]["tool_use_id"] for e in self.events({"run_id": run.run_id}) if e["type"] == "policy.decision"]

    def gaps(self, run):
        return [e for e in self.events({"run_id": run.run_id}) if e["type"] == "capture.gap"]

    def test_calls_follow_the_current_run_and_leave_no_gap(self):
        self.decide("c1")
        with self.client.run("conversation") as conversation:   # a server's run per request
            self.decide("c2")
        self.decide("c3")
        self.assertEqual((self.tools(self.process), self.tools(conversation)), (["c1", "c3"], ["c2"]))
        self.assertEqual((self.gaps(self.process), self.gaps(conversation)), ([], []))

    def test_a_process_run_the_signer_closed_is_renewed(self):
        first = self.process.run_id
        self.decide("c1")
        self.client.close_run({"run_id": first, "run_token": self.process.run_token})   # as an idle close does
        with self.assertWarnsRegex(UserWarning, "closed run .*recording in a new run"):
            self.decide("c2")
        self.assertNotEqual(self.process.run_id, first)
        self.assertEqual(self.tools(self.process), ["c2"])
        self.assertEqual(self.gaps(self.process), [])
        self.decide("c3")   # an adapter still addressing the first run reaches the new one
        self.assertEqual(self.tools(self.process), ["c2", "c3"])
