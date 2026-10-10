"""Browser Use (tested with browser-use 0.13.11): every action the agent's Tools run (navigate, click, input, extract,
upload_file, custom actions) is decided by the signer before it runs and recorded after.

    from browser_use import Agent, Tools
    from tracekit.integrations.browser_use import trace_tools
    run = signer.register_run({"request_id": "r1", "agent": {"name": "shopper"}})
    tools = trace_tools(Tools(), signer, run)
    agent = Agent(task=..., llm=..., tools=tools, sensitive_data={"https://*.shop.example": {"pw": "..."}})

An action is recorded as `browser_use:<action>` with its params and the URL of the page it ran on (`page_url`) as args.
`sensitive_data` values never reach the signer: the args keep Browser Use's `<secret>name</secret>` placeholders (a
literal value in the params or page URL is put back to its placeholder), and each secret the action types is added as
`typed_secrets: {name: [sha256 of the value]}`, so the signed args commitment lets an auditor who holds the value and
the record's revealed salt confirm what was typed. `deny` skips the action and hands the agent an ActionResult with
the refusal as its error, and the run goes on. `ask` waits up to `approval_wait_s` for a person (HeldCalls).
"""
import hashlib
import re
import uuid

from tracekit.format.canon import event_hash
from tracekit.integrations.held import HeldCalls

BLOCKED = "Action blocked by policy: "
_PLACEHOLDER = re.compile(r"<secret>(.*?)</secret>")


def trace_tools(tools, signer, run, approval_wait_s=300):
    """Gate every action of `tools` (browser_use Tools, or a Controller) through the signer. Returns `tools`."""
    execute, actions = tools.registry.execute_action, _Actions(signer, run, approval_wait_s)

    async def execute_action(action_name, params, *a, **kw):
        return await actions.gate(execute, action_name, params, *a, **kw)
    tools.registry.execute_action = execute_action
    return tools


def _secrets(sensitive_data):
    """[(value, name)] of every secret, longest value first. A domain-scoped secret counts on every domain."""
    pairs = set()
    for key, v in (sensitive_data or {}).items():
        pairs |= {(val, name) for name, val in v.items()} if isinstance(v, dict) else {(v, key)}
    return sorted(((v, n) for v, n in pairs if isinstance(v, str) and v), key=lambda p: -len(p[0]))


def _mask(x, secrets):
    """`x` with every secret value replaced by its placeholder."""
    if isinstance(x, str):
        for value, name in secrets:
            x = x.replace(value, f"<secret>{name}</secret>")
        return x
    if isinstance(x, dict):
        return {k: _mask(v, secrets) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [_mask(v, secrets) for v in x]
    return x


def _strings(x):
    if isinstance(x, str):
        yield x
    elif isinstance(x, (dict, list)):
        for v in (x.values() if isinstance(x, dict) else x):
            yield from _strings(v)


async def _page_url(session):
    try:
        return str(await session.get_current_page_url() or "")
    except Exception:   # no session, or no page yet: an empty page_url, which an allowlist rule never exempts
        return ""


class _Actions(HeldCalls):
    CLASS = "browser"

    async def gate(self, execute, action, params, *a, **kw):
        secrets = _secrets(kw.get("sensitive_data"))
        args = _mask({**(params or {}), "page_url": await _page_url(kw.get("browser_session", a[0] if a else None))},
                     secrets)
        # Registry._replace_sensitive_data fills a <secret>name</secret> placeholder, and a param that is exactly a name
        typed = {n for s in _strings(args) for n in _PLACEHOLDER.findall(s) + [s]}
        # lean: a domain-scoped name gets the digest of its value on every domain; match page_url to the domain
        # patterns if one digest per call is needed
        digests = {n: sorted({"sha256:" + hashlib.sha256(v.encode()).hexdigest() for v, m in secrets if m == n})
                   for n in typed & {n for _, n in secrets}}
        if digests:
            args["typed_secrets"] = digests
        tool, call_id = f"browser_use:{action}", uuid.uuid4().hex
        why, d = await self._gate(call_id, tool, args)
        if why is not None:
            from browser_use.agent.views import ActionResult
            return ActionResult(error=BLOCKED + why)
        if d is None:   # the signer unreachable and the run fails open: the action runs unrecorded
            return await execute(action, params, *a, **kw)
        req = {"tool_call_id": call_id, "decision_id": d["decision_id"],
               "args_digest": event_hash({"tool": tool, "args": args})}
        try:
            out = await execute(action, params, *a, **kw)
        except Exception as e:
            await self._complete(call_id, req, status="error", error=_mask(f"{type(e).__name__}: {e}", secrets)[:4096])
            raise
        dump = out.model_dump(mode="json", exclude_none=True) if hasattr(out, "model_dump") else out
        await self._complete(call_id, req, status="error" if getattr(out, "error", None) else "ok",
                             result=event_hash(dump))
        return out
