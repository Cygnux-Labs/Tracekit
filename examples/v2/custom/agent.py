"""A custom agent on the plain v2 client, offline: a mock model asks for three shell commands. The dev signer allows
`ls`, denies `sudo rm -rf /` (the agent goes on) and holds an unparsable command for a person. Then the run is exported
and verified.

    python examples/v2/custom/agent.py [--scripted]
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import HELD, RISKY, SAFE, approver, export_and_verify, wait   # noqa: E402

from tracekit.sdk.client import Client   # noqa: E402

MODEL = [("call-1", SAFE), ("call-2", RISKY), ("call-3", HELD)]   # the mock model's tool calls, in order


def shell(command):
    return f"(pretend) ran {command}"


with Client().run(agent="custom-example") as run, approver(run.client, run.run_id):
    for call_id, command in MODEL:
        args = {"command": command}
        d = run.decide(call_id, "Bash", args)   # before the call runs
        hint = None
        if d["decision"] == "ask":
            hint = run.call("approval_request", tool_call_id=call_id)["approval_id"]
            if wait(run, hint) != "approved":
                print(f"Bash {command!r}: not approved")
                continue
        if d["decision"] == "deny" or not run.approval_consume(call_id, "Bash", args, approval_id_hint=hint)["ok"]:
            print(f"Bash {command!r}: blocked by {', '.join(d['rule_ids'])}; the agent goes on")
            continue
        print(f"Bash {command!r}: {d['decision']} -> {shell(command)}")
        run.complete(call_id)   # the outcome, bound to that decision
sys.exit(export_and_verify(run.run_id))
