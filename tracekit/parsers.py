"""L3 model-response parsers (04-design §6): what a model asked to run, read from the provider's response.

Pure functions over each SDK's response object or its `model_dump()` (Google Gen AI: the snake_case dump), and over
the request kwargs the call was made with:

    parse("openai:chat", response, request) -> {"exchange_id": the provider's response id, "model", "finish", "usage",
                                                "tool_uses": [...], "tool_results_sent": [tool call ids in the request]}

A tool use is {id, name, executed_by: client|provider, args_source, args_digest | args_unparseable}. The digest is
sha256(JCS({"tool", "args"})) over the strictly parsed arguments: a raw arguments string that fails strict parsing
gives `args_unparseable: true` and no digest. Tools the provider runs itself (web search, file search, code
interpreter, hosted MCP, ...) are `executed_by: provider` and carry no arguments: no signer decision covers them.
Gemini function calls without an id get `gemini:<response id>:<index>` and `id_synthetic: true`.

`Stream(kind)` accumulates a streamed response, chunk by chunk, into the shape `parse` reads.
"""
import hashlib

import rfc8785

from tracekit import usage as _usage
from tracekit.format.canon import event_hash, loads_strict
from tracekit.signer import rpc_schema


def _get(obj, *path, default=None):
    for p in path:
        if obj is None:
            return default
        if isinstance(obj, dict):
            obj = obj.get(p)
        elif isinstance(p, int):
            try:
                obj = obj[p]
            except (IndexError, KeyError, TypeError):
                return default
        else:
            obj = getattr(obj, p, None)
    return default if obj is None else obj


def _list(obj, *path):
    v = _get(obj, *path, default=[])
    return v if isinstance(v, (list, tuple)) else []


def _id(x):
    """A provider's tool call id as the RPC's ID: kept when it fits, else `sha256:<hex>` of it, so an id format the
    RPC does not accept never refuses the call."""
    s = str(x)
    return s if not rpc_schema.validate(rpc_schema.ID, s) else "sha256:" + hashlib.sha256(s.encode()).hexdigest()


def tool_use(id, name, args=None, args_source="parsed", executed_by="client"):
    t = {"id": _id(id), "name": str(name)[:256] or "?", "executed_by": executed_by}
    if executed_by == "provider":
        return t
    t["args_source"] = args_source
    if hasattr(args, "model_dump"):   # an SDK object: the fields the provider sent
        args = args.model_dump(mode="json", by_alias=True, exclude_unset=True)
    try:
        value = loads_strict(args) if args_source == "raw" else args
        t["args_digest"] = event_hash({"tool": t["name"], "args": value})
    except (ValueError, TypeError, rfc8785.CanonicalizationError):   # StrictJSONError is a ValueError
        t["args_unparseable"] = True
    return t


def _out(rid, model, finish, usage, uses, sent):
    return {"exchange_id": rid, "model": model, "finish": finish,
            "usage": {k: v for k, v in (usage or {}).items() if v is not None} or None,
            "tool_uses": uses, "tool_results_sent": [_id(i) for i in sent if i]}


# ------------------------------------------------------------------ OpenAI Chat Completions

def openai_chat(resp, request=None):
    uses = []
    for c in _list(resp, "choices"):
        for tc in _list(c, "message", "tool_calls"):
            if _get(tc, "type") == "custom":   # free-form input: the string itself is the value
                uses.append(tool_use(_get(tc, "id"), _get(tc, "custom", "name"), _get(tc, "custom", "input")))
            else:
                uses.append(tool_use(_get(tc, "id"), _get(tc, "function", "name"), _get(tc, "function", "arguments"),
                                     "raw"))
    sent = [_get(m, "tool_call_id") for m in _list(request, "messages") if _get(m, "role") == "tool"]
    return _out(_get(resp, "id"), _get(resp, "model"), _get(resp, "choices", 0, "finish_reason"),
                _usage.from_openai(_get(resp, "usage")), uses, sent)


def _at(items, i):
    while len(items) <= i:
        items.append({})
    return items[i]


def _openai_chat_chunk(acc, chunk):
    for k in ("id", "model", "usage"):
        if _get(chunk, k) is not None:
            acc[k] = _get(chunk, k)
    for c in _list(chunk, "choices"):
        choice = _at(acc.setdefault("choices", []), _get(c, "index", default=0))
        if _get(c, "finish_reason"):
            choice["finish_reason"] = _get(c, "finish_reason")
        for tc in _list(c, "delta", "tool_calls"):
            call = _at(choice.setdefault("message", {}).setdefault("tool_calls", []), _get(tc, "index", default=0))
            for k in ("id", "type"):
                if _get(tc, k):
                    call[k] = _get(tc, k)
            for k, field in (("function", "arguments"), ("custom", "input")):
                if _get(tc, k) is not None:
                    part = call.setdefault(k, {field: ""})
                    if _get(tc, k, "name"):
                        part["name"] = _get(tc, k, "name")
                    part[field] += _get(tc, k, field, default="")


# ------------------------------------------------------------------ OpenAI Responses

# output item type -> tool name, for tools the provider runs itself
PROVIDER_ITEMS = {"web_search_call": "web_search", "file_search_call": "file_search",
                  "code_interpreter_call": "code_interpreter", "image_generation_call": "image_generation",
                  "mcp_call": "mcp"}
# output item type -> (tool name or None for the item's `name`, the field holding the arguments, args_source)
CLIENT_ITEMS = {"function_call": (None, "arguments", "raw"), "custom_tool_call": (None, "input", "parsed"),
                "computer_call": ("computer", "action", "parsed"),
                "local_shell_call": ("local_shell", "action", "parsed"), "shell_call": ("shell", "action", "parsed"),
                "apply_patch_call": ("apply_patch", "operation", "parsed")}


def openai_responses(resp, request=None):
    uses = []
    for item in _list(resp, "output"):
        typ = _get(item, "type")
        if typ in CLIENT_ITEMS:
            name, field, source = CLIENT_ITEMS[typ]
            uses.append(tool_use(_get(item, "call_id"), name or _get(item, "name"), _get(item, field), source))
        elif typ in PROVIDER_ITEMS:
            name = _get(item, "name") if typ == "mcp_call" else PROVIDER_ITEMS[typ]
            uses.append(tool_use(_get(item, "call_id") or _get(item, "id"), name, executed_by="provider"))
    sent = [_get(i, "call_id") for i in _list(request, "input") if str(_get(i, "type", default="")).endswith("_output")]
    return _out(_get(resp, "id"), _get(resp, "model"), _get(resp, "incomplete_details", "reason") or _get(resp, "status"),
                _usage.from_openai(_get(resp, "usage")), uses, sent)


def _openai_responses_event(acc, ev):
    typ = _get(ev, "type") or ""
    if typ == "response.output_item.done":   # kept for a stream that never completes
        acc.setdefault("output", []).append(_get(ev, "item"))
    elif _get(ev, "response") is not None:
        acc.update(id=_get(ev, "response", "id"), model=_get(ev, "response", "model"))
        if typ in ("response.completed", "response.incomplete", "response.failed"):
            acc["final"] = _get(ev, "response")


# ------------------------------------------------------------------ Anthropic Messages

PROVIDER_BLOCKS = ("server_tool_use", "mcp_tool_use")


def anthropic(resp, request=None):
    uses = []
    for b in _list(resp, "content"):
        typ = _get(b, "type")
        if typ == "tool_use":   # input: the accumulated JSON string when streamed, else the SDK's decoded object
            inp = _get(b, "input")
            uses.append(tool_use(_get(b, "id"), _get(b, "name"), inp, "raw" if isinstance(inp, str) else "parsed"))
        elif typ in PROVIDER_BLOCKS:
            uses.append(tool_use(_get(b, "id"), _get(b, "name"), executed_by="provider"))
    sent = [_get(b, "tool_use_id") for m in _list(request, "messages") for b in _list(m, "content")
            if _get(b, "type") == "tool_result"]
    return _out(_get(resp, "id"), _get(resp, "model"), _get(resp, "stop_reason"),
                _usage.from_anthropic(_get(resp, "usage")), uses, sent)


_ANTHROPIC_USAGE = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")


def _anthropic_event(acc, ev):
    typ, usage = _get(ev, "type"), None
    if typ == "message_start":
        m = _get(ev, "message")
        acc.update(id=_get(m, "id"), model=_get(m, "model"))
        usage = _get(m, "usage")
    elif typ == "content_block_start":
        b = _get(ev, "content_block")
        _at(acc.setdefault("content", []), _get(ev, "index", default=0)).update(
            {k: _get(b, k) for k in ("type", "id", "name", "input")})
    elif typ == "content_block_delta" and _get(ev, "delta", "partial_json"):
        b = _at(acc.setdefault("content", []), _get(ev, "index", default=0))
        b["input"] = (b["input"] if isinstance(b.get("input"), str) else "") + _get(ev, "delta", "partial_json")
    elif typ == "message_delta":
        acc["stop_reason"] = _get(ev, "delta", "stop_reason") or acc.get("stop_reason")
        usage = _get(ev, "usage")
    for k in _ANTHROPIC_USAGE:   # message_delta carries the final counts
        if _get(usage, k) is not None:
            acc.setdefault("usage", {})[k] = _get(usage, k)


# ------------------------------------------------------------------ Google Gen AI

def gemini(resp, request=None):
    rid, uses = _get(resp, "response_id"), []
    for c in _list(resp, "candidates"):
        for p in _list(c, "content", "parts"):
            fc = _get(p, "function_call")
            if fc is None:
                continue
            t = tool_use(_get(fc, "id") or f"gemini:{rid or ''}:{len(uses)}", _get(fc, "name"), _get(fc, "args", default={}))
            if not _get(fc, "id"):
                t["id_synthetic"] = True
            uses.append(t)
    contents = _get(request, "contents")
    sent = [_get(p, "function_response", "id") for c in (contents if isinstance(contents, list) else [contents])
            for p in _list(c, "parts")]
    fr = _get(resp, "candidates", 0, "finish_reason")
    return _out(rid, _get(resp, "model_version"), getattr(fr, "name", fr), _usage.from_gemini(_get(resp, "usage_metadata")),
                uses, sent)


def _gemini_chunk(acc, chunk):
    for k in ("response_id", "model_version", "usage_metadata"):
        if _get(chunk, k) is not None:
            acc[k] = _get(chunk, k)
    for i, c in enumerate(_list(chunk, "candidates")):
        cand = _at(acc.setdefault("candidates", []), i)
        if _get(c, "finish_reason") is not None:
            cand["finish_reason"] = _get(c, "finish_reason")
        parts = cand.setdefault("content", {"parts": []})["parts"]
        parts.extend(p for p in _list(c, "content", "parts") if _get(p, "function_call") is not None)


# ------------------------------------------------------------------ dispatch

PARSERS = {"openai:chat": (openai_chat, _openai_chat_chunk), "openai:responses": (openai_responses, _openai_responses_event),
           "anthropic:messages": (anthropic, _anthropic_event), "gemini:generate_content": (gemini, _gemini_chunk)}


def parse(kind, response, request=None):
    return PARSERS[kind][0](response, request)


class Stream:
    """One streamed response, accumulated: `add(chunk)` per chunk, then `parse(request)`."""

    def __init__(self, kind):
        self.kind, self.acc, self.seen = kind, {}, False

    def add(self, chunk):
        self.seen = True
        PARSERS[self.kind][1](self.acc, chunk)

    def parse(self, request=None):
        return parse(self.kind, self.acc.get("final", self.acc), request)
