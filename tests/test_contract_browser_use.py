"""The adapter contract (tests/adapter_contract.py) for the Browser Use adapter (tracekit/integrations/browser_use.py),
through a stand-in for Browser Use's action registry (browser-use is not a test dependency); the browser policy pack;
and, with browser-use installed, the adapter on a real Tools registry.

The adapter holds an `ask` while it waits for the approval, so the driver runs each action on a thread of its own and
returns once the approval is requested, as tests/test_contract_mcp.py does.
"""
import asyncio
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import threading
import time
import types
import unittest
from unittest import mock

import adapter_contract as ac
from tracekit.format.canon import event_hash
from tracekit.integrations.browser_use import trace_tools
from tracekit.policy2 import compile as pc
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import Client
from tracekit.signer import service as svc
from tracekit.signer.pipeline import salt_label
from tracekit.testing import FakeSigner

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACK = os.path.join(ROOT, "tracekit", "policy2", "packs", "browser.yaml")
PAGE = "https://shop.example/login"
PW, USER = "hunter2-Correct-Horse", "alice@shop.example"   # sensitive_data values: never sent to the signer
SECRETS = {"https://*.shop.example": {"pw": PW}, "user": USER}

try:
    from browser_use.agent.views import ActionResult
except ImportError:
    HAVE_BU, BU_MODULES = False, {n: types.ModuleType(n) for n in ("browser_use", "browser_use.agent",
                                                                     "browser_use.agent.views")}

    class ActionResult:
        def __init__(self, extracted_content=None, error=None):
            self.extracted_content, self.error = extracted_content, error

        def model_dump(self, mode=None, exclude_none=False):
            return {k: v for k, v in vars(self).items() if v is not None or not exclude_none}
    BU_MODULES["browser_use.agent.views"].ActionResult = ActionResult
else:
    HAVE_BU, BU_MODULES = True, {}


def type_text(index: int, text: str) -> str:
    ac.RAN.append("input")
    return f"typed into {index}"


ACTIONS = {f.__name__: f for f in ac.TOOLS} | {"input": type_text}


class Page:
    async def get_current_page_url(self):
        return PAGE


class Registry:
    """Stands in for browser_use's Registry: fills placeholders the way Browser Use does, then runs the action."""

    def __init__(self, ran_with):
        self.ran_with = ran_with

    async def execute_action(self, action_name, params, browser_session=None, sensitive_data=None, **kw):
        flat = {}
        for k, v in (sensitive_data or {}).items():
            flat.update(v if isinstance(v, dict) else {k: v})
        params = {k: flat.get(v, re.sub(r"<secret>(.*?)</secret>", lambda m: flat[m.group(1)], v))
                  if isinstance(v, str) else v for k, v in params.items()}
        self.ran_with.append(params)
        return ActionResult(extracted_content=ACTIONS[action_name](**params))


class Recording:
    """The signer, with every request it was sent kept as JSON."""

    def __init__(self, signer):
        self.signer, self.sent = signer, []

    def __getattr__(self, method):
        def call(req):
            self.sent.append((method, json.dumps(req)))
            return getattr(self.signer, method)(req)
        return call


class Driver:
    SKIP = {"retry": "a Browser Use action has no call id: every action is a call of its own",
            "saved_state": "the adapter holds the action while it waits for the approval: there is no saved state to "
                           "resume in a new process, replay or edit",
            "modes": "actions run async only, with no streaming path",
            "l1": "the adapter commits no agent state"}

    def __init__(self, case, signer_path, **kw):
        patch = mock.patch.dict(sys.modules, BU_MODULES)   # the deny result is browser_use's ActionResult
        patch.start()
        case.addCleanup(patch.stop)
        client = Client(signer_path)
        case.addCleanup(client.close)
        self.signer, self.kw, self.secrets, self.ran_with = Recording(client), kw, None, []
        r = client.register_run({"agent": {"name": "contract"}})
        self._run = {"run_id": r["run_id"], "run_token": r["run_token"]}

    def run(self):
        return self._run

    def call(self, tool, args, tcid="call-1", mode="sync"):
        ac.RAN.clear()
        self.out = {}
        tools = trace_tools(types.SimpleNamespace(registry=Registry(self.ran_with)), self.signer, self._run, **self.kw)

        def go():
            try:
                self.out["result"] = asyncio.run(tools.registry.execute_action(
                    tool, args, browser_session=Page(), sensitive_data=self.secrets))
            except Exception as e:
                self.out["raised"] = f"{type(e).__name__}: {e}"
        self.waiting = threading.Thread(target=go)
        self.waiting.start()
        while self.waiting.is_alive():
            aid = next((a["approval_id"] for a in self.signer.signer.approval_list({"run_id": self._run["run_id"]})[
                "approvals"] if a["state"] == "requested"), None)
            if aid:
                return {"ran": [], "seen": None, "is_error": False, "continued": False, "raised": None,
                        "approval_id": aid}
            time.sleep(0.02)
        return self.finish()

    def resume(self, hint=ac.HINT, replay=False):
        self.waiting.join(60)
        return self.finish()

    def finish(self):
        r = self.out.get("result")
        return {"ran": list(ac.RAN), "seen": r and (r.error or r.extracted_content), "is_error": bool(r and r.error),
                "continued": r is not None, "raised": self.out.get("raised"), "approval_id": None}


def _sha(value):
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


class BrowserUseContract(ac.Contract):
    driver = Driver

    def decided_args(self):
        return [json.loads(req)["args"] for method, req in self.d.signer.sent if method == "decide"]

    def test_secret_values_reach_the_action_but_never_the_signer(self):
        self.d.secrets = SECRETS
        self.d.call("input", {"index": 4, "text": "<secret>pw</secret>"})
        self.d.call("input", {"index": 5, "text": "user"}, "call-2")    # a bare name Browser Use also fills
        self.d.call("input", {"index": 6, "text": PW}, "call-3")        # the value itself, written out
        self.assertEqual([p["text"] for p in self.d.ran_with], [PW, USER, PW])
        sent = json.dumps(self.d.signer.sent) + json.dumps(self.events(self.d.run()))
        self.assertNotIn(PW, sent)
        self.assertNotIn(USER, sent)
        self.assertEqual(self.decided_args(), [
            {"index": 4, "text": "<secret>pw</secret>", "page_url": PAGE, "typed_secrets": {"pw": [_sha(PW)]}},
            {"index": 5, "text": "user", "page_url": PAGE, "typed_secrets": {"user": [_sha(USER)]}},
            {"index": 6, "text": "<secret>pw</secret>", "page_url": PAGE, "typed_secrets": {"pw": [_sha(PW)]}}])
        self.assert_bound(3)

    def test_the_approver_never_sees_a_typed_secrets_digest(self):
        self.d.secrets = SECRETS
        aid = self.d.call("pay", {"to": "<secret>pw</secret>", "cents": 1500})["approval_id"]
        self.assertEqual(self.client.approval_get({"approval_id": aid})["args"],
                         {"to": "<secret>pw</secret>", "cents": 1500, "page_url": PAGE,
                          "typed_secrets": {"pw": ["[REDACTED:typed_secret]"]}})
        self.approve(aid)
        self.assertEqual(self.d.resume()["ran"], ["pay"])

    def test_ask_is_refused_when_the_caller_cannot_wait_or_nobody_decides_in_time(self):
        self.d.kw["approval_wait_s"] = 0
        self.refused(self.d.call("pay", ac.PAY), "cannot wait")
        self.d.kw["approval_wait_s"] = 0.2
        self.paused()
        self.refused(self.d.resume(), "approval requested")


class TestOnFakeSigner(BrowserUseContract, ac.OnFake, unittest.TestCase):
    pass


class TestOnRealSigner(BrowserUseContract, ac.OnReal, unittest.TestCase):
    def test_an_auditor_with_the_value_confirms_the_typed_secret(self):
        self.d.secrets = SECRETS
        self.d.call("input", {"index": 4, "text": "<secret>pw</secret>"})
        [e] = [e for e in self.events(self.d.run()) if e["type"] == "policy.decision"]
        self.assertEqual(e["data"]["tool"], "browser_use:input")
        salt = svc._salt(self.service._salt_key, salt_label(e))   # what `tracekit signer reveal` prints for e

        def opens(value):
            args = {"index": 4, "text": "<secret>pw</secret>", "page_url": PAGE, "typed_secrets": {"pw": [_sha(value)]}}
            digest = event_hash({"tool": "browser_use:input", "args": args})
            return e["data"]["args_commitment"] == "hmac-sha256:" + hmac.new(salt, digest.encode(), "sha256").hexdigest()
        self.assertEqual((opens(PW), opens("hunter3")), (True, False))


class BrowserPack(unittest.TestCase):
    def test_pack_decisions(self):
        e = Engine(pc.build(PACK)[0])
        for tool, args, verdict in [
                ("navigate", {"url": "https://docs.python.org/3/"}, "allow"),
                ("navigate", {"url": "file:///etc/passwd"}, "deny"),
                ("navigate", {"url": "http://169.254.169.254/latest/meta-data/"}, "deny"),
                ("navigate", {"url": "localhost:8080/admin"}, "deny"),
                ("navigate", {"url": "https://10.0.0.7/"}, "deny"),
                ("navigate", {"url": "https://metadata.google.internal/"}, "deny"),
                ("navigate", {"url": "http://localhost@docs.python.org/"}, "allow"),   # the host is docs.python.org
                ("upload_file", {"index": 2, "path": "/tmp/cv.pdf", "page_url": "https://example.com/"}, "ask"),
                ("input", {"index": 1, "text": "x", "page_url": "https://shop.example.com/login"}, "allow"),
                ("input", {"index": 1, "text": "x", "page_url": "https://example.com.evil.test/"}, "ask"),
                ("input", {"index": 1, "text": "x", "page_url": ""}, "ask"),   # no page: never on the allowlist
                ("click", {"index": 1, "page_url": "https://anything.test/"}, "allow")]:
            with self.subTest(tool=tool, args=args):
                self.assertEqual(e.decide("browser_use:" + tool, args)["verdict"], verdict)

    def test_offline_example_runs(self):
        p = subprocess.run([sys.executable, os.path.join(ROOT, "examples", "browser_use_agent.py")], cwd=ROOT,
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("TK-B001", p.stdout)
        self.assertIn("finished", p.stdout)


@unittest.skipUnless(HAVE_BU, "browser-use not installed (pip install 'browser-use==0.13.11', Python 3.11+)")
class OnRealTools(unittest.TestCase):
    def test_actions_of_a_real_registry_are_gated(self):
        from browser_use import Tools
        tools = Tools()

        @tools.registry.action("Echo the text.")
        async def echo(text: str):
            return f"echo {text}"

        @tools.registry.action("Delete a path.")
        async def wipe(path: str):
            raise AssertionError("a denied action ran")
        fake = FakeSigner(ac._rule)
        signer = Recording(fake)
        trace_tools(tools, signer, fake.register_run({"request_id": "r1", "agent": {"name": "bu"}}))
        model = tools.registry.create_action_model()

        async def go():   # Tools.act, the path Agent.run takes
            return [await tools.act(model(**{name: params}), browser_session=None, sensitive_data={"pw": PW, "user": USER})
                    for name, params in (("echo", {"text": "<secret>pw</secret>"}), ("echo", {"text": "user"}),
                                         ("wipe", {"path": "/"}))]
        placeholder, bare, denied = asyncio.run(go())
        self.assertEqual((placeholder.extracted_content, bare.extracted_content), (f"echo {PW}", f"echo {USER}"))
        self.assertIsInstance(denied, ActionResult)
        self.assertIn("R-WIPE", denied.error)
        self.assertNotIn(PW, json.dumps(signer.sent))
        self.assertEqual([json.loads(r)["args"] for m, r in signer.sent if m == "decide"], [
            {"text": "<secret>pw</secret>", "page_url": "", "typed_secrets": {"pw": [_sha(PW)]}},
            {"text": "user", "page_url": "", "typed_secrets": {"user": [_sha(USER)]}},
            {"path": "/", "page_url": ""}])
