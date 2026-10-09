"""Stagehand action hooks (Python): each page call is a policy-checked, signed ``browser:<method>`` step.

    from tracekit.agent_sdk import Tracer
    from tracekit_stagehand import instrument_stagehand

    with Tracer(agent="shopper") as tracer:
        page = instrument_stagehand(stagehand.page, tracer)     # act / extract / observe / goto

A denied call raises PermissionError. Stagehand is not imported here: the hook wraps the object you pass in."""
import functools
import inspect

from tracekit.adapters.browser import _summary

STAGEHAND_METHODS = ("act", "extract", "observe", "goto")


def instrument_stagehand(page, tracer, methods=STAGEHAND_METHODS, prefix="browser:"):
    """Wrap Stagehand page methods (sync or async) so each call is a policy-checked, signed step."""
    for name in methods:
        original = getattr(page, name, None)
        if original is None or getattr(original, "_tracekit", False):
            continue
        setattr(page, name, _wrap(original, tracer, prefix + name))
    return page


def _wrap(original, tracer, tool_name):
    def args_of(args, kwargs):
        recorded = dict(kwargs)
        if args:
            first = args[0]
            recorded["input"] = first if isinstance(first, (str, int, float, bool, dict, list)) else repr(first)
        return recorded

    if inspect.iscoroutinefunction(original):
        @functools.wraps(original)
        async def wrapper(*args, **kwargs):
            with tracer.tool(tool_name, args_of(args, kwargs)) as call:
                result = await original(*args, **kwargs)
                call.result(_summary(result))
                return result
    else:
        @functools.wraps(original)
        def wrapper(*args, **kwargs):
            with tracer.tool(tool_name, args_of(args, kwargs)) as call:
                result = original(*args, **kwargs)
                call.result(_summary(result))
                return result
    wrapper._tracekit = True
    return wrapper
