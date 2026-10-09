"""The adapter contract (tests/adapter_contract.py) for the Claude Code v2 hook (tracekit/integrations/claude_code.py).

The driver plays Claude Code: it sends PreToolUse, runs the tool when the hook lets it, and reports the outcome with
PostToolUse or PostToolUseFailure. Each event runs the hook's entry point in this process with a client of its own,
as each Claude Code event is a process of its own; between events the hook keeps its state in the runtime dir.
tests/test_hook_v2.py runs the hook as the command `tracekit init` wires.
"""
import contextlib
import io
import json
import os
import threading
import time
import unittest
from unittest import mock

import adapter_contract as ac
from tracekit.integrations import claude_code
from tracekit.sdk.client import Client

TOOLS = {f.__name__: f for f in ac.TOOLS}


class Driver:
    SKIP = {"retry": "Claude Code gives every tool use its own tool_use_id and never runs one twice",
            "saved_state": "the PreToolUse hook holds the call while it waits for the approval: there is no saved "
                           "state to resume in a new process, replay or edit",
            "modes": "every hook event is a process: there is no async or streaming path",
            "l1": "no state wrapper (the hook's L1 is the transcript tailer, M1b-07)"}

    def __init__(self, case, signer_path):
        self.case, d = case, ac.tmpdir(case)
        env = mock.patch.dict(os.environ, {"TRACEKIT_SIGNER": signer_path, "TRACEKIT_RUNTIME_DIR": os.path.join(d, "run"),
                                           "HOME": os.path.join(d, "home")})
        env.start()
        case.addCleanup(env.stop)
        for k in ("TRACEKIT_FAIL_CLOSED", "TRACEKIT_POLICY"):
            os.environ.pop(k, None)
        self.client = Client(signer_path)
        case.addCleanup(self.client.close)

    def run(self):
        with open(claude_code._state("s1")) as f:
            return json.load(f)

    def hook(self, event, tcid, tool, args, **fields):
        payload = {"hook_event_name": event, "session_id": "s1", "tool_use_id": tcid, "tool_name": tool,
                   "tool_input": args, **fields}
        err = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(json.dumps(payload))), contextlib.redirect_stderr(err):
            return claude_code._entry(), err.getvalue()

    def requested(self, tcid):
        """The approval the hook waits for on this call, if any yet."""
        if not os.path.exists(claude_code._state("s1")):
            return None
        return next((a["approval_id"] for a in self.client.approval_list({"run_id": self.run()["run_id"]})["approvals"]
                     if a["tool_call_id"] == tcid and a["state"] == "requested"), None)

    def call(self, tool, args, tcid="call-1", mode="sync"):
        ac.RAN.clear()
        self.pending, self.pre = (tool, args, tcid), {}
        self.waiting = threading.Thread(target=lambda: self.pre.update(out=self.hook("PreToolUse", tcid, tool, args)))
        self.waiting.start()
        while self.waiting.is_alive():
            aid = self.requested(tcid)
            if aid:
                return {"ran": [], "seen": None, "is_error": False, "continued": False, "raised": None,
                        "approval_id": aid}
            time.sleep(0.02)
        return self.finish()

    def resume(self, hint=ac.HINT, replay=False):
        self.waiting.join(60)
        return self.finish()

    def finish(self):
        (tool, args, tcid), (code, err) = self.pending, self.pre["out"]
        # a blocked call: Claude Code hands the reason to the model as the tool's error result and the turn goes on
        out = {"ran": [], "seen": err, "is_error": code == 2, "continued": True, "raised": None, "approval_id": None}
        if code == 2:
            return out
        self.case.assertEqual(code, 0, err)
        try:
            out["seen"] = TOOLS[tool](**args)
            event, fields = "PostToolUse", {"tool_response": {"stdout": out["seen"]}}
        except Exception as e:
            out["raised"] = f"{type(e).__name__}: {e}"
            event, fields = "PostToolUseFailure", {"error": str(e)}
        self.case.assertEqual(self.hook(event, tcid, tool, args, **fields), (0, ""))
        out["ran"] = list(ac.RAN)
        return out


class TestOnFakeSigner(ac.Contract, ac.OnFake, unittest.TestCase):
    driver = Driver


class TestOnRealSigner(ac.Contract, ac.OnReal, unittest.TestCase):
    driver = Driver
