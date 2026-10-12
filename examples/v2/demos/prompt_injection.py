"""Prompt injection, held by provenance: the LangGraph agent of ../langchain/injection.py fetches a page that plants an
instruction to email the order history to records@offsite.example, and its mock model follows it. The signer's
policy (the server pack, the page fetcher listed as untrusted) holds send_email because its recipient came only from
that page (TK-P001); a person rejects it, the agent goes on, and the run is exported and verified. Offline.

    python examples/v2/demos/prompt_injection.py
"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path += [HERE, os.path.join(HERE, "langchain")]
from injection import THREAD, graph_factory, record   # noqa: E402
from story import AGENT, Signer, export_and_verify, person, show   # noqa: E402

from langgraph.types import Command   # noqa: E402

POLICY = """extends: packs/server.yaml
tools: {fetch_page: app, get_weather: app, send_email: email}
untrusted: [fetch_page]   # what a fetched page says is untrusted content
"""

with Signer(POLICY, {"agent": AGENT}) as signer:
    with signer.client("agent").run(agent="langgraph-injection") as run:
        graph = graph_factory(run.client, run.registered)
        held = record(graph)["__interrupt__"][0].value["tracekit"]   # the graph paused on the ask
        print(f"{held['tool']} held by {', '.join(held['rule_ids'])}; the person at the terminal looks and says no:")
        person("approvals", "show", held["approval_id"])
        person("approvals", "reject", held["approval_id"], "--reason", "the address came from the fetched page")
        out = graph.invoke(Command(resume={"approval_id": held["approval_id"]}), THREAD)
        print(f"{out['messages'][-2].name}: {out['messages'][-2].content}\nagent: {out['messages'][-1].content}")
    code = export_and_verify(run.run_id, signer.config)
print("\nthe signed decision, approval and outcome of send_email:")
show(f"{run.run_id}.tkb", "policy.decision", "approval", "tool.result")
sys.exit(code)
