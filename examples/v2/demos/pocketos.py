"""A coding agent and a production volume, after a public incident report: in 2026 a coding agent that hit a
credential mismatch deleted PocketOS's production database with one call to Railway's GraphQL API (volumeDelete). Here
a scripted coding agent makes that call as a Bash tool call under the dev pack: the curl waits for a person (TK-A001),
the person rejects it and the curl never runs, the agent's other calls run, and the run is exported and verified.
Offline, scripted.

    python examples/v2/demos/pocketos.py
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import AGENT, Signer, export_and_verify, person, show, wait   # noqa: E402

POLICY = "extends: packs/dev.yaml\n"
RAILWAY = "https://backboard.railway.app/graphql/v2"
MUTATION = r'{"query":"mutation { volumeDelete(volumeId: \"3d2c42fb-b1f0-4b43-9a2c-ffb8c1a0e5d1\") }"}'
CALLS = [("call-1", "railway status", None),
         ("call-2", "railway volume list", None),
         ("call-3", f'curl -X POST {RAILWAY} -H "Authorization: Bearer $RAILWAY_TOKEN" '
                    f"-H 'Content-Type: application/json' -d '{MUTATION}'",
          "don't delete the volume; fix the credential mismatch"),
         ("call-4", "git status", None)]


with Signer(POLICY, {"agent": AGENT}) as signer:
    with signer.client("agent").run(agent="coding-agent") as run:
        for call_id, command, refusal in CALLS:
            args = {"command": command}
            d = run.decide(call_id, "Bash", args)
            print(f"\nBash {command!r}: {d['decision']} {' '.join(d['rule_ids'])}".rstrip())
            hint = None
            if d["decision"] == "ask":
                hint = run.call("approval_request", tool_call_id=call_id)["approval_id"]
                print(f"  {d['reason']}\n\nthe person at the terminal:")
                person("approvals", "reject", hint, "--reason", refusal)
                print(f"\nthe agent: the call was {wait(run, hint)}")
            if d["decision"] != "deny" and run.approval_consume(call_id, "Bash", args, approval_id_hint=hint)["ok"]:
                run.complete(call_id)   # the pretend command ran
                print("  ran")
    code = export_and_verify(run.run_id, signer.config)
print("\nthe held call and the person's answer, as signed records:")
show(f"{run.run_id}.tkb", "policy.decision", "approval")
sys.exit(code)
