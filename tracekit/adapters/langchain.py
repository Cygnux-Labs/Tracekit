"""LangChain / LangGraph adapter (needs ``pip install langchain-core``).

    from tracekit.agent_sdk import Tracer
    from tracekit.adapters.langchain import TracekitCallbackHandler
    with Tracer(agent="my-graph") as tracer:
        handler = TracekitCallbackHandler(tracer)
        graph.invoke(inputs, config={"callbacks": [handler]})

Every tool the framework runs is policy-checked before it executes: a denied call raises
``PermissionError`` out of the callback, which LangChain propagates, so the tool body does not run.
The result or error is recorded when the tool finishes. Anything that doesn't go through LangChain's
callback system (a tool that shells out on its own, model calls) is not recorded by this adapter.

LangGraph node tracing is opt-in: ``TracekitCallbackHandler(tracer, nodes=True)`` also records each
graph node as a signed ``node:<name>`` step (args: the superstep and the edges that triggered it),
so the ledger shows which nodes ran, in what order, between the tool calls. Node steps go through
the policy like any tool, so a rule on ``node:*`` can stop a graph before a node runs."""
import json

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError as e:  # pragma: no cover
    raise ImportError("tracekit.adapters.langchain needs langchain-core: pip install langchain-core") from e


class TracekitCallbackHandler(BaseCallbackHandler):
    raise_error = True  # a policy denial must stop the tool, not be logged and ignored
    run_inline = True   # run in the calling thread so the denial is raised before the tool starts

    def __init__(self, tracer, nodes=False):
        self.tracer = tracer
        self.nodes = nodes
        self._open = {}
        self._inside = {}  # run_id of a runnable nested inside a traced node -> that node's run_id

    def on_chain_start(self, serialized, inputs, *, run_id, parent_run_id=None, metadata=None, **kwargs):
        if not self.nodes:
            return
        if parent_run_id is not None and (parent_run_id in self._inside or parent_run_id in self._open):
            self._inside[run_id] = self._inside.get(parent_run_id, parent_run_id)
            return  # a runnable inside a node (it inherits the node's metadata): not a new step
        node = (metadata or {}).get("langgraph_node")
        if not node or kwargs.get("name") not in (None, node):
            return
        args = {"step": (metadata or {}).get("langgraph_step")}
        triggers = (metadata or {}).get("langgraph_triggers")
        if triggers:
            args["triggers"] = [str(t) for t in triggers]
        call = self.tracer.tool("node:" + str(node), args)
        call.__enter__()  # raises PermissionError on deny: the node does not run
        self._open[run_id] = call

    def on_chain_end(self, outputs, *, run_id, **kwargs):
        if self._inside.pop(run_id, None) is not None:
            return
        call = self._open.pop(run_id, None)
        if call is not None:
            call.result(_jsonable(outputs))
            call.__exit__(None, None, None)

    def on_chain_error(self, error, *, run_id, **kwargs):
        if self._inside.pop(run_id, None) is not None:
            return
        call = self._open.pop(run_id, None)
        if call is not None:
            call.__exit__(type(error), error, None)

    def on_tool_start(self, serialized, input_str, *, run_id, parent_run_id=None, inputs=None, **kwargs):
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


def _jsonable(value):
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return repr(value)
