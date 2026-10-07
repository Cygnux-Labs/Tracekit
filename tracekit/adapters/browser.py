"""Browser-agent action hooks: Browser Use and Stagehand (Python).

    from tracekit.agent_sdk import Tracer
    from tracekit.adapters.browser import instrument_browser_use, instrument_stagehand

    with Tracer(agent="shopper") as tracer:
        tools = instrument_browser_use(Tools(), tracer)      # browser_use.Tools (or a Controller)
        agent = Agent(task=..., llm=..., tools=tools)
        await agent.run()

    page = instrument_stagehand(stagehand.page, tracer)     # act / extract / observe / goto

Every browser action is recorded as a signed ``browser:<action>`` tool call and checked against the
policy before it runs, so a rule such as ``tool: "browser:navigate"`` with a ``url`` pattern can keep
an agent off a domain. A denied Browser Use action is handed back to the agent as an error result
(the action does not run and the agent can recover); a denied Stagehand call raises PermissionError.
Neither library is imported here: both hooks wrap the object you pass in."""
import functools
import inspect

STAGEHAND_METHODS = ("act", "extract", "observe", "goto")


def instrument_browser_use(tools, tracer, prefix="browser:"):
    """Wrap ``tools.registry.execute_action`` (browser_use ``Tools``/``Controller``). Returns ``tools``."""
    registry = getattr(tools, "registry", None)
    if registry is None or not hasattr(registry, "execute_action"):
        raise TypeError("expected a browser_use Tools/Controller with .registry.execute_action")
    if getattr(registry.execute_action, "_tracekit", False):
        return tools
    original = registry.execute_action

    @functools.wraps(original)
    async def execute_action(action_name, params, *args, **kwargs):
        call = tracer.tool(prefix + str(action_name), dict(params or {}))
        try:
            call.__enter__()
        except PermissionError as denied:
            return _denied_result(denied)
        try:
            result = await original(action_name, params, *args, **kwargs)
        except BaseException as error:
            call.__exit__(type(error), error, None)
            raise
        error = getattr(result, "error", None)
        call.result(_summary(result))
        if error:
            failure = RuntimeError(str(error))
            call.__exit__(RuntimeError, failure, None)
        else:
            call.__exit__(None, None, None)
        return result

    execute_action._tracekit = True
    registry.execute_action = execute_action
    return tools


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


def _summary(result):
    dump = getattr(result, "model_dump", None)
    if callable(dump):
        try:
            data = dump(exclude_none=True)
            data.pop("images", None)  # screenshots stay out of the ledger
            return data
        except Exception:
            pass
    return result


def _denied_result(denied):
    try:
        from browser_use.agent.views import ActionResult
    except ImportError:
        raise denied
    return ActionResult(error=str(denied))
