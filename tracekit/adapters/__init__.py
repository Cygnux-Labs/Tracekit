"""Adapters that route a framework's real tool calls through ``tracekit.agent_sdk.Tracer``.

* ``traced(tracer)``: decorate any sync or async function so each call is policy-checked before it
  runs (a denied call raises ``PermissionError`` and the function body never executes) and its result
  is recorded.
* ``tracekit.adapters.langchain.TracekitCallbackHandler``: the same for LangChain / LangGraph tools.

Policy rules match on the tool's name (the default rules know `Bash`, `Write`, `Edit`, ...): name a shell
tool `Bash` to get the shell rules, or add rules for your own tool names in a policy file.
Only calls that go through an adapter are recorded; anything a framework does outside it is not seen.
"""
import functools
import inspect


def _args_of(fn, args, kwargs):
    try:
        bound = inspect.signature(fn).bind_partial(*args, **kwargs)
        return dict(bound.arguments)
    except (TypeError, ValueError):
        return {"args": list(args), "kwargs": dict(kwargs)}


def traced(tracer, name=None):
    """Decorator factory: ``@traced(tracer)`` or ``@traced(tracer, name="http_get")``."""
    def deco(fn):
        tool_name = name or fn.__name__
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def awrapper(*args, **kwargs):
                with tracer.tool(tool_name, _args_of(fn, args, kwargs)) as call:
                    result = await fn(*args, **kwargs)
                    call.result(result)
                    return result
            return awrapper

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            with tracer.tool(tool_name, _args_of(fn, args, kwargs)) as call:
                result = fn(*args, **kwargs)
                call.result(result)
                return result
        return wrapper
    return deco
