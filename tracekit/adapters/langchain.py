"""LangChain / LangGraph adapter (needs ``pip install langchain-core``).

    from tracekit.agent_sdk import Tracer
    from tracekit.adapters.langchain import TracekitCallbackHandler
    with Tracer(agent="my-graph") as tracer:
        handler = TracekitCallbackHandler(tracer)
        graph.invoke(inputs, config={"callbacks": [handler]})

Every tool the framework runs is policy-checked before it executes: a denied call raises
``PermissionError`` out of the callback, which LangChain propagates, so the tool body does not run.
The result or error is recorded when the tool finishes. Anything that doesn't go through LangChain's
callback system (a tool that shells out on its own, model calls) is not recorded by this adapter."""
import json

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError as e:  # pragma: no cover
    raise ImportError("tracekit.adapters.langchain needs langchain-core: pip install langchain-core") from e


class TracekitCallbackHandler(BaseCallbackHandler):
    raise_error = True  # a policy denial must stop the tool, not be logged and ignored
    run_inline = True   # run in the calling thread so the denial is raised before the tool starts

    def __init__(self, tracer):
        self.tracer = tracer
        self._open = {}

    def on_tool_start(self, serialized, input_str, *, run_id, inputs=None, **kwargs):
        name = (serialized or {}).get("name") or kwargs.get("name") or "tool"
        args = inputs if isinstance(inputs, dict) else _parse(input_str)
        call = self.tracer.tool(name, args)
        call.__enter__()  # raises PermissionError on deny / unapproved ask
        self._open[run_id] = call

    def on_tool_end(self, output, *, run_id, **kwargs):
        call = self._open.pop(run_id, None)
        if call is not None:
            call.result(getattr(output, "content", output))
            call.__exit__(None, None, None)

    def on_tool_error(self, error, *, run_id, **kwargs):
        call = self._open.pop(run_id, None)
        if call is not None:
            call.__exit__(type(error), error, None)


def _parse(input_str):
    if isinstance(input_str, dict):
        return input_str
    try:
        value = json.loads(input_str)
        if isinstance(value, dict):
            return value
    except (TypeError, ValueError):
        pass
    return {"input": input_str}
