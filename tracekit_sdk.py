"""Trace explicitly instrumented custom agents (LangGraph, CrewAI, Pi, or your own code).

``Tracer`` writes signed ``source=sdk`` events through the signer ``tracekit init`` configured. Set it
up once with ``tracekit init --dev`` (or ``sudo tracekit init --user <agent-user>`` for Linux system mode). The SDK
does not discover agents or observe calls that are not routed through its methods, and ``tool()``
must wrap the real call for Tracekit to enforce policy before it runs and record the result.

    from tracekit_sdk import Tracer
    with Tracer(agent="research-bot") as t:             # one run per Tracer; run.end is recorded when the block exits
        t.prompt("Summarise the Q3 filings")
        worker = t.subagent("fetcher", "Download filings")   # appears as a child lane
        worker.think("Need the 10-Q first")
        with worker.tool("http_get", {"url": "https://example.com/10q"}) as call:
            call.result({"status": 200, "bytes": 18234})
        worker.done("Fetched 3 filings")
        t.say("Summary: ...")

One line records the model calls this process makes through the OpenAI, Anthropic and Google Gen AI SDKs (sync,
async, streaming) as signed model.exchange events; calls made any other way are not seen:

    import tracekit_sdk
    tracer = tracekit_sdk.init(agent="research-bot")
    # ... use openai / anthropic / google-genai as usual; wrap tool executions with tracer.tool(...)

An agent on another machine uses the same API after ``tracekit init --remote URL`` (docs/remote-ingest.md); there a
call held by an ``ask`` rule is refused, because approvals are not available remotely.
"""
from tracekit.agent_sdk import TracekitSDKError, Tracer
from tracekit.autotrace import init, instrument, shutdown, uninstrument

__all__ = ["Tracer", "TracekitSDKError", "init", "instrument", "uninstrument", "shutdown"]
