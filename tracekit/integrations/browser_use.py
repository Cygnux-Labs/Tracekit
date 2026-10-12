"""Browser Use (tested with browser-use 0.13.11): every action the agent's Tools run (navigate, click, input, extract,
upload_file, evaluate, custom actions) is decided by the signer before it runs and recorded after.

    from browser_use import Agent, Tools
    from tracekit.integrations.browser_use import trace_tools
    run = signer.register_run({"request_id": "r1", "agent": {"name": "shopper"}})
    tools = trace_tools(Tools(), signer, run)
    agent = Agent(task=..., llm=..., tools=tools, sensitive_data={"https://*.shop.example": {"pw": "..."}})

An action is recorded as `browser_use:<action>` with its params and the URL of the page it ran on (`page_url`) as args.
`sensitive_data` values reach the signer in none of the forms a URL, a page or JSON writes them in: the args keep
Browser Use's `<secret>name</secret>` placeholders (a value in the params, the page URL, a result or the page's text,
written out or percent-, HTML- or JSON-encoded, is put back to its placeholder), and each secret the action types is
added as `typed_secrets: {name: [sha256 of the value]}`, so the signed args commitment lets an auditor who holds the
value and the record's revealed salt confirm what was typed. Before an action is decided, every browser state Browser
Use made since the session's last action (what the model read of the page: URL, title, tabs and the page's text) is
observed as untrusted content, so the hosts it names are in the run's provenance index; one that can't be observed
refuses the action unless the run's fail mode for `browser` is open. `deny` skips the action and hands the agent an
ActionResult with the refusal as its error, and the run goes on. `ask` waits for a person (HeldCalls) up to
`approval_wait_s`, which ends before Browser Use's own action timeout; an approval with a T2 executor runs the params of
the signer's copy.
"""
import asyncio
import functools
import hashlib
import re
import uuid
import warnings
from html.entities import html5

from tracekit.format.canon import event_hash
from tracekit.integrations.held import HeldCalls
from tracekit.sdk.client import SignerUnavailable, fail_open, result_field
from tracekit.signer.rpc_schema import RPCError

BLOCKED = "Action blocked by policy: "
_PLACEHOLDER = re.compile(r"<secret>(.*?)</secret>")
PAGE_URL_S = 2   # how long reading the page's URL may take before the action is decided with page_url ""
# lean: what the model read past this many characters of a page's text is not observed (Browser Use shows the model
# 40,000 by default); observe in parts if pages that long carry what provenance must see
PAGE_TEXT = 100_000
_NAMES = {}   # a character -> the HTML5 character reference names that write it (`amp;`, `AMP`, ...)
for _name, _ch in html5.items():
    if len(_ch) == 1:
        _NAMES.setdefault(_ch, []).append(_name)
_JSON = {'"': '\\"', "\\": "\\\\", "/": "\\/", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _action_timeout_s():
    """Browser Use's own per-action timeout (BROWSER_USE_ACTION_TIMEOUT_S, else 180 s): it cancels an action, approval
    wait included, that runs longer."""
    try:
        from browser_use.tools.service import _DEFAULT_ACTION_TIMEOUT_S
        return float(_DEFAULT_ACTION_TIMEOUT_S)
    except (ImportError, TypeError, ValueError):
        # lean: a Browser Use without it gets 0.13's default; read the timeout from wherever a release that moves it
        # keeps it
        return 180.0


def trace_tools(tools, signer, run, approval_wait_s=None):
    """Gate every action of `tools` (browser_use Tools, or a Controller) through the signer. Returns `tools`.
    `approval_wait_s`: how long an `ask` waits for a person; by default, and at most, five sixths of Browser Use's
    action timeout (150 s of 180 s), leaving the rest for the action itself."""
    return _wrap(tools, _actions(signer, run, approval_wait_s))


def _actions(signer, run, approval_wait_s=None):
    limit = _action_timeout_s() * 5 / 6
    if approval_wait_s is not None and approval_wait_s > limit:
        warnings.warn(f"tracekit: approval_wait_s={approval_wait_s:g} is past Browser Use's action timeout, which "
                      f"cancels the action: an ask waits {limit:g} s. Raise BROWSER_USE_ACTION_TIMEOUT_S to wait "
                      "longer", stacklevel=3)
    return _Actions(signer, run, limit if approval_wait_s is None else min(approval_wait_s, limit))


def _wrap(tools, actions):
    """`tools` with every action gated by `actions` (one _Actions may gate many Tools: one signer stream)."""
    execute = tools.registry.execute_action

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


def _percent(data):
    return "".join(f"%(?:25)*(?i:{b:02x})" for b in data)


@functools.lru_cache(maxsize=256)
def _written(value):
    """`value` as it may be written in a URL, a page or JSON: each character as itself; percent-encoded (UTF-8, or
    Latin-1 below U+0100; either hex case; encoded again any number of times), a space also as `+`; as an HTML
    character reference (decimal or hex, with or without its `;`, or any HTML5 name); or as a JSON escape (`\\/`, `\\"`,
    or `\\u` and each UTF-16 unit in either hex case). No two forms of a character match the same text (a text that
    almost matches would otherwise be retried in every combination of them), and the longest is tried first."""
    # lean: a run of backslashes in a secret still backtracks in every split of `\\\\` (JSON's backslash) into two
    # characters, exponentially past about 20 in a row; mask such a secret in parts if one has that many
    out = []
    for ch in value:
        units = ch.encode("utf-16-be", "surrogatepass")
        forms = {re.escape(ch), _percent(ch.encode("utf-8", "surrogatepass")), f"&#0*{ord(ch)};?",
                 f"&#[xX]0*(?i:{ord(ch):x});?",
                 "".join(f"\\\\u(?i:{units[i]:02x}{units[i + 1]:02x})" for i in range(0, len(units), 2))}
        forms |= {re.escape("&" + n) for n in _NAMES.get(ch, ())} | {re.escape(e) for e in [_JSON.get(ch)] if e}
        if 0x80 <= ord(ch) < 0x100:
            forms.add(_percent([ord(ch)]))
        if ch == " ":
            forms.add(r"\+")
        out.append("(?:" + "|".join(sorted(forms, key=lambda f: (-len(f), f))) + ")")
    return re.compile("".join(out))


def _mask(x, secrets):
    """`x` with every secret value, in any form _written matches, replaced by its placeholder."""
    if isinstance(x, str):
        for value, name in secrets:
            x = _written(value).sub(lambda m, name=name: f"<secret>{name}</secret>", x)
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
        return str(await asyncio.wait_for(session.get_current_page_url(), PAGE_URL_S) or "")
    except Exception:   # no session, no page yet, or no answer in time: "", which an allowlist rule never exempts
        return ""


def _page(state):
    """What the model read of the page in Browser Use's browser state, or None for no state."""
    dom = getattr(state, "dom_state", None)
    try:
        text = dom.llm_representation() if dom is not None else ""
    except Exception:   # a state Browser Use could not capture: its URL, title and tabs still count
        text = ""
    url = getattr(state, "url", None)
    return None if url is None else {"url": url, "title": getattr(state, "title", ""), "text": text[:PAGE_TEXT],
                                     "tabs": [getattr(t, "url", "") for t in getattr(state, "tabs", None) or ()]}


def _pages(session):
    """The pages of the browser states Browser Use made for `session` and no action has observed yet, oldest first. At
    the session's first action its get_browser_state_summary, which makes the state each agent step reads (and those
    an action asks for), is wrapped to queue the page of every state it makes."""
    made = getattr(session, "get_browser_state_summary", None)
    pages = getattr(made, "tracekit_pages", None)
    if made is None or pages is not None:
        return pages or []
    # lean: the state the step read before this first action is Browser Use 0.13's private cache, which a focus change
    # (a tab closing) clears first; wrap the session when it is made if that first step matters
    pages = [p for p in [_page(getattr(session, "_cached_browser_state_summary", None))] if p]

    async def make(*a, **kw):
        state = await made(*a, **kw)
        page = _page(state)
        if page is not None and page not in pages[-1:]:   # `navigate` reads the page the next step reads again
            pages.append(page)
        return state
    make.tracekit_pages = pages
    object.__setattr__(session, "get_browser_state_summary", make)   # BrowserSession, a pydantic model, forbids extras
    return pages


def _blocked(why):
    from browser_use.agent.views import ActionResult
    return ActionResult(error=BLOCKED + why)


class _Actions(HeldCalls):
    CLASS = "browser"

    async def gate(self, execute, action, params, *a, **kw):
        secrets, session = _secrets(kw.get("sensitive_data")), kw.get("browser_session", a[0] if a else None)
        # what the agent read since the last action, before anything it decided from it runs. An observe that fails
        # has spent its client_seq: the signer's gap for it makes the run's provenance index partial, so from:
        # untrusted rules hold every send from then on, and no page needs a second try
        pages = _pages(session)
        try:
            while pages:
                page = _mask(pages.pop(0), secrets)
                await self._rpc("observe", source="browser_use:page", trust="untrusted", value=page)
        except SignerUnavailable as e:
            pages.clear()
            if not fail_open(self.fail_modes, self.CLASS):
                return _blocked(f"signer unavailable, so the page the agent read was not observed: {e}")
        except RPCError as e:
            pages.clear()
            return _blocked(f"the signer refused the page's content: {e}")
        args = _mask({**(params or {}), "page_url": await _page_url(session)}, secrets)
        # Registry._replace_sensitive_data fills a <secret>name</secret> placeholder, and a param that is exactly a name
        typed = {n for s in _strings(args) for n in _PLACEHOLDER.findall(s) + [s]}
        # lean: a domain-scoped name gets the digest of its value on every domain; match page_url to the domain
        # patterns if one digest per call is needed
        digests = {n: sorted({"sha256:" + hashlib.sha256(v.encode()).hexdigest() for v, m in secrets if m == n})
                   for n in typed & {n for _, n in secrets}}
        if digests:
            args["typed_secrets"] = digests
        tool, call_id = f"browser_use:{action}", uuid.uuid4().hex
        why, d, run = await self._gate(call_id, tool, args)
        if why is not None:
            return _blocked(why)
        if d is None:   # the signer unreachable and the run fails open: the action runs unrecorded
            return await execute(action, params, *a, **kw)
        if run != args:   # the signer's copy (T2) differs from what was sent: its params, placeholders and all, run
            args, params = run, {k: v for k, v in run.items() if k not in ("page_url", "typed_secrets")}
        req = {"tool_call_id": call_id, "decision_id": d["decision_id"],
               "args_digest": event_hash({"tool": tool, "args": args})}
        try:
            out = await execute(action, params, *a, **kw)
        except Exception as e:
            await self._complete(call_id, req, status="error", error=_mask(f"{type(e).__name__}: {e}", secrets)[:4096])
            raise
        dump = out.model_dump(mode="json", exclude_none=True) if hasattr(out, "model_dump") else out
        await self._complete(call_id, req, status="error" if getattr(out, "error", None) else "ok",
                             result=result_field(d.get("send_result"), _mask(dump, secrets)))
        return out
