"""A coding agent and a production bucket, after a public incident report: told "no new upload", an agent uploaded
files to a production bucket anyway, then, told to roll back, deleted them and purged every version of them, destroying
the version history kept as a safety net. Here a scripted coding agent makes the same three calls under the dev pack
(the signer's default for coding agents on a laptop): the upload waits for a person (TK-A032) and so do the delete and
the version purge (TK-A031); the person rejects each, the agent's other calls run, and the run is exported and
verified. Offline, scripted.

    python examples/v2/demos/cloud_storage.py
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import AGENT, Signer, export_and_verify, person, show, wait   # noqa: E402

POLICY = "extends: packs/dev.yaml\n"
BUCKET = "gs://prod-asset-images/products"
CALLS = [("call-1", f"gsutil ls {BUCKET}/", None),
         ("call-2", f"gsutil -m cp -r ./assets/images {BUCKET}/", "I said no new upload"),
         ("call-3", f"gsutil -m rm '{BUCKET}/**'", "nothing to roll back: the upload never ran"),
         ("call-4", f"gsutil -m rm -a '{BUCKET}/**'", "never purge the version history"),
         ("call-5", "git diff --stat", None)]


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
print("\nthe held calls and the person's answers, as signed records:")
show(f"{run.run_id}.tkb", "policy.decision", "approval")
sys.exit(code)
