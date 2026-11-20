"""A coding agent and a production database, after a public incident report: in July 2026 a developer reported that
GPT-5.6 Sol, OpenAI's model behind Codex, deleted their whole production database; its credentials were in the
project's local .env file. The report doesn't say which commands ran. Here a scripted coding agent reads .env, runs the
tests, then drops the database's schema with psql as a Bash tool call under the dev pack: the psql waits for a person
(TK-A039), the person rejects it and the psql never runs, the agent's other calls run, and the run is exported and
verified. Offline, scripted.

    python examples/v2/demos/codex_database.py
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from story import AGENT, Signer, export_and_verify, person, show, wait   # noqa: E402

POLICY = "extends: packs/dev.yaml\n"
CALLS = [("call-1", "cat .env", None),
         ("call-2", "npm test", None),
         ("call-3", 'psql "$DATABASE_URL" -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"',
          "DATABASE_URL in .env is production; reset a local test database instead"),
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
