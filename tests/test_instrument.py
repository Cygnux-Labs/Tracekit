"""The three-step quickstart in this checkout: `tracekit.instrument()` (tracekit/autowire.py) in a scripted agent of
each installed framework, against a dev signer it starts, then `tracekit last`. tests/test_quickstart.py runs the same
agents from the built wheel in a fresh venv."""
import asyncio
import contextlib
import gc
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
import warnings
import weakref
from importlib import metadata
from unittest import mock

from adapter_contract import OnReal
from quickstart_agents import AGENTS, REFUSED

from tracekit import autowire
from tracekit.format.canon import event_hash
from tracekit.sdk.client import AsyncClient, Client, SignerUnavailable, current_run
from tracekit.wiki import wiki_url
from tracekit.signer.rpc_schema import REQUESTS, RPCError
from tracekit.testing import FakeSigner

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
                       TRACEKIT_DEV_IDLE="120", TRACEKIT_DEV_GRACE="0.2", PYTHONPATH=ROOT)
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


class TestOpenRun(DevSigner):
    def test_last_open_verifies_a_run_still_open(self):
        """A coding agent's session run stays open until the session ends: `tracekit last` only skipped it, so nothing
        verified the session as it stood."""
        p = self.sh("-c", "import os; from tracekit.sdk.client import Client; r = Client().run('open-one'); "
                          "r.decide('c1', 'Bash', {'command': 'ls'}); print(r.run_id, flush=True); os._exit(0)")
        run_id = p.stdout.split()[0]
        self.assertIn("tracekit last --open verifies it as it stands", self.sh("-m", "tracekit", "last", code=1).stderr)
        out = self.sh("-m", "tracekit", "last", "--open").stdout
        self.assertIn(f"run {run_id} (open-one)\nIntegrity: VERIFIED TO HEAD", out)
        self.assertIn("(open).\nAssurance: dev", out)


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

    def test_no_system_signer_names_a_doctor_command_root_can_run(self):
        """System-mode init puts no `tracekit` command on root's PATH, so the fix `sudo tracekit doctor` found none."""
        class Down:
            def start(self, agent):
                raise SignerUnavailable("no signer answering")

        env = {k: v for k, v in os.environ.items() if k != "TRACEKIT_SIGNER"}
        with mock.patch.object(autowire, "_version", return_value="1.0"), \
                mock.patch.object(autowire, "_process_client", return_value=Down), \
                mock.patch("tracekit.client.SYSTEM_CONFIG", __file__), mock.patch.dict(os.environ, env, clear=True), \
                self.assertRaises(SignerUnavailable) as cm:
            autowire.instrument()
        self.assertIn("system mode: start the system signer (`sudo /opt/tracekit/bin/python -I -m tracekit doctor` "
                      "says what is wrong)", str(cm.exception))

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
        self.assertIn(f"wire it by hand ({wiki_url('docs/custom.md')})", msgs[0])   # was docs/custom.md, a repo path
        self.assertIn("Fine 2.1rc1 is wired but untested", msgs[1])

    def test_every_framework_names_a_docs_page(self):
        """Its not-wired warning sends people to that page's wiki URL."""
        docs = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")
        self.assertEqual([f[5] for f in autowire.FRAMEWORKS if not os.path.exists(os.path.join(docs, f[5] + ".md"))], [])

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

    def test_mcp_sessions_are_freed_once_dropped(self):
        if not installed(AGENTS["mcp"][0]):
            self.skipTest("mcp not installed")
        from mcp import ClientSession

        async def call_tool(gate, *a, **kw):
            pass
        run = mock.Mock(registered={"run_id": "r", "run_token": "t"})
        with mock.patch.object(ClientSession, "call_tool", ClientSession.call_tool), \
                mock.patch("tracekit.integrations.mcp.TracekitSession.call_tool", call_tool):
            autowire._mcp(run)
            refs = []
            for _ in range(50):   # a session per request, as a server opens them
                s = object.__new__(ClientSession)
                asyncio.run(s.call_tool("t", {}))
                refs.append(weakref.ref(s))
                del s
            gc.collect()
        self.assertEqual([r for r in refs if r() is not None], [])

    def test_browser_use_tools_are_gated_on_one_stream(self):
        """Every Tools built after instrument() (an Agent builds one) has its actions decided, all on one signer stream
        (a run allows 64)."""
        class Tools:
            def __init__(self):
                self.registry = types.SimpleNamespace(execute_action=self.execute)

            async def execute(self, action_name, params, **kw):
                return f"ran {action_name}"
        sent, fake = [], FakeSigner(lambda tool, args: ("allow", []))

        class Recording:
            def __getattr__(self, method):
                return lambda req: sent.append((method, req)) or getattr(fake, method)(req)
        run = types.SimpleNamespace(client=Recording(), registered=fake.register_run({"request_id": "r1", "agent": {"name": "bu"}}))
        with mock.patch.dict(sys.modules, {"browser_use": types.SimpleNamespace(Tools=Tools)}):
            autowire._browser_use(run)
        outs = [asyncio.run(Tools().registry.execute_action("navigate", {"url": "https://example.com/"}))
                for _ in range(2)]
        self.assertEqual(outs, ["ran navigate"] * 2)
        decides = [req for method, req in sent if method == "decide"]
        self.assertEqual([d["tool"] for d in decides], ["browser_use:navigate"] * 2)
        self.assertEqual(len({d["stream"] for d in decides}), 1)

    def test_an_mcp_1_session_is_named_by_its_initialize_result(self):
        if not installed(AGENTS["mcp"][0]):
            self.skipTest("mcp not installed")

        class ClientSession:   # mcp 1.x: no server_info
            async def initialize(self):
                return types.SimpleNamespace(serverInfo=types.SimpleNamespace(name="github"))

            async def call_tool(self, name, arguments=None):
                pass
        seen = []

        async def call_tool(gate, *a, **kw):
            seen.append(gate._server)
        run = mock.Mock(registered={"run_id": "r", "run_token": "t"})
        with mock.patch("mcp.ClientSession", ClientSession), \
                mock.patch("tracekit.integrations.mcp.TracekitSession.call_tool", call_tool):
            autowire._mcp(run)
            named, unnamed = ClientSession(), ClientSession()
            asyncio.run(named.initialize())
            for s in (named, unnamed):
                asyncio.run(s.call_tool("t", {}))
        self.assertEqual(seen, ["github", None])

    def test_exit_leaves_a_run_open_while_approvals_of_it_wait(self):
        class Run:
            run_id, closed = "r", False

            def __init__(self, listing):
                self.listing = listing

            def call(self, method, **fields):
                return self.listing(fields["state"])

            def close(self, reason=None):
                self.closed = True

        def no_grant(state):
            raise RPCError("forbidden", "approval_list")

        for listing, closed in ((lambda s: {"approvals": []}, True),
                                (lambda s: {"approvals": [{"approval_id": "a"}] if s == "approved" else []}, False),
                                (lambda s: {"approvals": [{"approval_id": "a"}] if s == "requested" else []}, False),
                                (no_grant, True)):   # a listing that fails waits for nothing
            run = Run(listing)
            with self.assertLogs("tracekit", "WARNING") if not closed else contextlib.nullcontext():
                autowire._close(run)
            self.assertEqual(run.closed, closed)

    def test_release(self):
        for v, want in (("0.23.1", (0, 23, 1)), ("1.2.14", (1, 2, 14)), ("2.3.0rc1", (2, 3, 0)), ("1.4.dev0", (1, 4))):
            self.assertEqual(autowire._release(v), want)


if __name__ == "__main__":
    unittest.main()


class ProcessRun(OnReal, unittest.TestCase):
    """The client instrument() wires every adapter with: new work follows the current run, a call's complete goes to
    the run it was decided in, and a process run the signer closed is renewed, never refused for good."""

    def setUp(self):
        self.path = self.serve_signer()
        self.client = autowire._process_client(Client, RPCError, current_run, REQUESTS)(self.path)
        self.addCleanup(self.client.close)
        self.process = self.client.start("server")
        self.seq = 0

    def event(self, method, call_id, **fields):
        """An event as an adapter sends it: addressed to the process run, numbered by the adapter's own counter."""
        self.seq += 1
        req = {"run_id": self.process.run_id, "run_token": self.process.run_token, "stream": "adapter",
               "client_seq": self.seq - 1, "tool_call_id": call_id, **fields}
        return self.client.call(method, req)

    def decide(self, call_id):
        return self.event("decide", call_id, tool="read_file", args_source="parsed", args={})

    def complete(self, call_id, d):
        return self.event("complete", call_id, decision_id=d["decision_id"], status="ok",
                          args_digest=event_hash({"tool": "read_file", "args": {}}))

    def records(self, run, typ):
        return [e["tool_call_id"] for e in self.events({"run_id": run.run_id}) if e["type"] == typ]

    def gaps(self, run):
        return [e for e in self.events({"run_id": run.run_id}) if e["type"] == "capture.gap"]

    def test_new_work_follows_the_current_run_and_a_complete_its_decide(self):
        d1 = self.decide("c1")
        with self.client.run("conversation") as conversation:   # a server's run per conversation
            d2 = self.decide("c2")
            d3 = self.decide("c3")
            self.complete("c2", d2)
        self.complete("c3", d3)   # after the block: still to the run it was decided in, which takes it late
        self.complete("c1", d1)
        self.assertEqual((self.records(self.process, "policy.decision"), self.records(conversation, "policy.decision")),
                         (["c1"], ["c2", "c3"]))
        self.assertEqual((self.records(self.process, "tool.result"), self.records(conversation, "tool.result")),
                         (["c1"], ["c2", "c3"]))
        # no gap: conversations overlap the process run by design (no harness process binds them)
        self.assertEqual((self.gaps(self.process), self.gaps(conversation)), ([], []))

    def test_a_resent_event_keeps_its_number(self):
        req = {"run_id": self.process.run_id, "run_token": self.process.run_token, "stream": "adapter",
               "client_seq": 0, "request_id": "r-1", "tool_call_id": "c1", "tool": "read_file",
               "args_source": "parsed", "args": {}}
        first = self.client.call("decide", dict(req))
        self.assertEqual(self.client.call("decide", dict(req)), first)   # not a conflict, not a second record
        self.assertEqual(self.records(self.process, "policy.decision"), ["c1"])

    def test_close_goes_to_the_run_it_names(self):
        with self.client.run("conversation") as conversation:
            self.process.close()
            self.decide("c1")
        self.assertEqual([e["type"] for e in self.events({"run_id": self.process.run_id})][-1], "run.closing")
        self.assertEqual(self.records(conversation, "policy.decision"), ["c1"])

    def test_a_process_run_the_signer_closed_is_renewed(self):
        first = self.process.run_id
        d1 = self.decide("c1")
        self.client.close_run({"run_id": first, "run_token": self.process.run_token})   # as an idle close does
        with self.assertLogs("tracekit", "WARNING") as logs:
            self.decide("c2")
        self.assertIn(f"closed run {first}", logs.output[0])
        self.assertNotEqual(self.process.run_id, first)
        self.assertEqual(self.records(self.process, "policy.decision"), ["c2"])
        self.complete("c1", d1)   # the call decided before the renewal completes in the run it was decided in
        self.assertEqual(self.records(types.SimpleNamespace(run_id=first), "tool.result"), ["c1"])
        registered = self.events({"run_id": self.process.run_id})[0]["data"]
        self.assertEqual(registered.get("parent_run"), first)   # linked to the run it replaces
        self.decide("c3")   # an adapter still addressing the first run reaches the new one
        self.assertEqual(self.records(self.process, "policy.decision"), ["c2", "c3"])
        self.assertEqual(self.gaps(self.process), [])

    def test_close_ends_the_adapter_streams_it_renumbered(self):
        d1 = self.decide("c1")
        sent = Client.call

        def down(client, method, req=None):
            if method == "complete":
                raise SignerUnavailable("the signer is down")
            return sent(client, method, req)
        with mock.patch.object(Client, "call", down), self.assertRaises(SignerUnavailable):
            self.complete("c1", d1)   # numbered by the adapter and renumbered, never received
        self.process.close()
        gaps = [g["data"] for g in self.gaps(self.process) if g["data"]["kind"] == "client_counter_gap"]
        self.assertEqual([g["missed_events"] for g in gaps], [1])

    def test_approval_list_reaches_the_current_run(self):
        self.assertEqual(self.client.approval_list({"run_id": self.process.run_id})["approvals"], [])

    def test_one_call_id_in_two_conversations_stays_in_each(self):
        with self.client.run("a") as a:
            d1 = self.decide("call_0")
            with self.client.run("b") as b:
                self.complete("call_0", self.decide("call_0"))   # the same id in another conversation
            self.complete("call_0", d1)
        self.assertEqual((self.records(a, "tool.result"), self.records(b, "tool.result")), (["call_0"], ["call_0"]))

    def test_a_forgotten_call_completes_in_the_current_run(self):
        with mock.patch.object(autowire, "KEEP", 2), self.client.run("a") as a:
            ds = [self.decide(f"c{i}") for i in range(3)]   # pushes c0's entries out
            self.complete("c0", ds[0])
        self.assertEqual(self.records(a, "tool.result"), ["c0"])

    def test_a_model_response_goes_to_the_run_of_its_request(self):
        ev = {"run_id": self.process.run_id, "run_token": self.process.run_token, "provider": "p", "model": "m",
              "exchange_id": "ex-1"}
        self.client.call("model_event", {**ev, "phase": "request"})
        with self.client.run("conversation") as conversation:   # e.g. a stream finished during the next request
            self.client.call("model_event", {**ev, "phase": "response"})
        self.assertEqual([e["data"]["phase"] for e in self.events({"run_id": self.process.run_id})
                          if e["type"] == "model.exchange"], ["request", "response"])
        self.assertEqual([e for e in self.events({"run_id": conversation.run_id}) if e["type"] == "model.exchange"], [])

    def test_a_process_run_closed_on_purpose_is_not_renewed(self):
        self.process.close()
        with self.assertRaises(RPCError):
            self.decide("c1")
        self.assertEqual(self.client.ids, {self.process.run_id})

    def test_an_async_handle_can_be_current(self):
        async def go():
            run = await AsyncClient(self.path).run("async")
            with run.current():
                return current_run.get() is run
        self.assertTrue(asyncio.run(go()))
