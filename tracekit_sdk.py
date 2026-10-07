"""Trace explicitly instrumented custom agents (LangGraph, CrewAI, Pi, or your own code).

``Tracer`` writes signed ``source=sdk`` events to the local Tracekit signer's ledger. Set the
signer up once with ``tracekit init --dev`` (or ``sudo tracekit init --system`` on Linux). The SDK
does not discover agents or observe calls that are not routed through its methods, and ``tool()``
must wrap the real call for Tracekit to enforce policy before it runs and record the result.

    from tracekit_sdk import Tracer
    with Tracer(agent="research-bot") as t:             # one run per Tracer; run.end is always recorded
        t.prompt("Summarise the Q3 filings")
        worker = t.subagent("fetcher", "Download filings")   # appears as a child lane
        worker.think("Need the 10-Q first")
        with worker.tool("http_get", {"url": "https://example.com/10q"}) as call:
            call.result({"status": 200, "bytes": 18234})
        worker.done("Fetched 3 filings")
        t.say("Summary: ...")

One line records every model call made through the OpenAI, Anthropic and Google Gen AI SDKs (sync, async,
streaming) as signed model.exchange events:

    import tracekit_sdk
    tracer = tracekit_sdk.init(agent="research-bot")
    # ... use openai / anthropic / google-genai as usual; wrap tool executions with tracer.tool(...)

Remote ingestion (agents on other machines writing to this ledger) is not supported.
"""
from tracekit.agent_sdk import TracekitSDKError, Tracer
from tracekit.autotrace import init, instrument, shutdown, uninstrument

__all__ = ["Tracer", "TracekitSDKError", "init", "instrument", "uninstrument", "shutdown"]
