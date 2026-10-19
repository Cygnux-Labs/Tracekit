"""L3 model-response parsers (04-design §6): what a model asked to run, read from the provider's response.

Pure functions over each SDK's response object or its `model_dump()` (Google Gen AI: the snake_case dump), and over
the request kwargs the call was made with:

    parse("openai:chat", response, request) -> {"exchange_id": the provider's response id, "model", "finish", "usage",
                                                "tool_uses": [...], "tool_results_sent": [tool call ids in the request]}

A tool use is {id, name, executed_by: client|provider, args_source, args_digest | args_unparseable}. The digest is
sha256(JCS({"tool", "args"})) over the strictly parsed arguments: a raw arguments string that fails strict parsing
gives `args_unparseable: true` and no digest. Tools the provider runs itself (web search, file search, code
interpreter, hosted MCP, ...) are `executed_by: provider`, with the digest of their input where the provider returns it
(Anthropic server_tool_use `input`, OpenAI web_search_call `action`, file_search_call `queries`, code_interpreter_call
`code`, mcp_call `arguments`): no signer decision covers them. `provider_tools(kind, request)` names the ones a request
declares; `tool_results(kind, request)` gives the tool results a request sends, with their content.
A tool use the provider sent without an id gets `<provider>:<response id>:<index>` and `id_synthetic: true` (a random
nonce in place of a missing response id, so two such responses never share one).

`Stream(kind)` accumulates a streamed response, chunk by chunk, into the shape `parse` reads, keeping what the model
said (text, reasoning and the provider's sealed reasoning) within MAX_TEXT characters and MAX_INDEX parts of a Gemini
candidate, as JSON: the SDK objects of autotrace's chunks as the SDK dumps them, so the response hashes.

    said(kind, response) -> [{"kind": "reasoning" | "text", "form": "full" | "summary" | "encrypted" | "withheld",
                              "text": str, "tools": [ids of the tool uses right after it, before the next segment]}]

in the response's order: what the model said before each tool use. `form`: the model's own reasoning text (`full`: an
open model's reasoning_content, a Responses reasoning item's content), a summary of it (Anthropic thinking, which
current Claude models return summarized; a Responses reasoning summary; Gemini thought parts), only the provider's
sealed form (`encrypted`: an empty thinking block's signature, redacted_thinking, encrypted_content, a Gemini
thought_signature), or none of it (`withheld`: reasoning happened, nothing of it came back). The ids are `parse`'s.
"""
import base64
import hashlib
import uuid

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


def _plain(x):
    """What a stream keeps of an SDK object (autotrace's chunks: a Responses item, a Gemini part, usage) as JSON, as
    the gateway's chunks are, so the response can be hashed and kept: the SDK's own JSON dump (bytes as base64)."""
    f = getattr(x, "model_dump", None)
    return f(mode="json") if callable(f) else x


def _list(obj, *path):
    v = _get(obj, *path, default=[])
    return v if isinstance(v, (list, tuple)) else []


def _id(x):
    """A provider's tool call id as the RPC's ID: kept when it fits, else `sha256:<hex>` of it, so an id format the
    RPC does not accept never refuses the call."""
    s = str(x)
    return s if not rpc_schema.validate(rpc_schema.ID, s) else "sha256:" + hashlib.sha256(s.encode()).hexdigest()


def tool_use(id, name, args=None, args_source="parsed", executed_by="client"):
    """`id` None or empty: `parse` gives the tool use a synthetic one. A provider-run tool use has an args digest only
    when the provider returned its input (`args`) and that input parses."""
    t = {"id": _id(id) if id not in (None, "") else None, "name": str(name)[:256] or "?", "executed_by": executed_by}
    if executed_by == "provider" and args is None:
        return t
    t["args_source"] = args_source
    if hasattr(args, "model_dump"):   # an SDK object: the fields the provider sent
        args = args.model_dump(mode="json", by_alias=True, exclude_unset=True)
    try:
        value = loads_strict(args) if args_source == "raw" else args
        t["args_digest"] = event_hash({"tool": t["name"], "args": value})
    except (ValueError, TypeError, rfc8785.CanonicalizationError):   # StrictJSONError is a ValueError
        if executed_by == "provider":   # no decide to compare it with: recorded without arguments
            del t["args_source"]
        else:
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


MAX_INDEX = 1024   # a streamed choice, tool call or content block index an upstream may name


def _at(items, i):
    """items[i], made on first use; an index that isn't a small non-negative integer gets a scratch dict (ignored), so
    one upstream event can't allocate millions of entries."""
    if not (type(i) is int and 0 <= i < MAX_INDEX):
        return {}
    while len(items) <= i:
        items.append({})
    return items[i]


def _append(d, field, piece):
    """Collect streamed text for d[field] (joined once by Stream.parse): appending to a str in a dict copies it whole
    every time, quadratic in a long argument."""
    if isinstance(piece, str):
        d.setdefault("\0" + field, []).append(piece)


# lean: characters of text and reasoning one streamed response keeps, as much as a model_event body can carry (half a
# frame); past it the rest is dropped and the response marked "truncated". Raise it with the frame size.
MAX_TEXT = 1 << 19


def _text(acc, d, field, piece):
    """_append for what the model said, within MAX_TEXT characters per response (`acc`)."""
    if not isinstance(piece, str):
        return
    left = acc.get("\0left", MAX_TEXT)
    if len(piece) > left:
        acc["truncated"], piece = True, piece[:left]
    acc["\0left"] = left - len(piece)
    _append(d, field, piece)


def _joined(node):
    """Turn every collected piece list back into its field (and drop the text budget)."""
    if isinstance(node, list):
        for x in node:
            _joined(x)
    elif isinstance(node, dict):
        for k in [k for k in node if isinstance(k, str) and k.startswith("\0")]:
            pieces = node.pop(k)
            if isinstance(pieces, list):
                field = k[1:]
                node[field] = (node[field] if isinstance(node.get(field), str) else "") + "".join(pieces)
        for v in node.values():
            _joined(v)


def _openai_chat_chunk(acc, chunk):
    for k in ("id", "model", "usage"):
        if _get(chunk, k) is not None:
            acc[k] = _plain(_get(chunk, k))
    for c in _list(chunk, "choices"):
        choice = _at(acc.setdefault("choices", []), _get(c, "index", default=0))
        if _get(c, "finish_reason"):
            choice["finish_reason"] = _get(c, "finish_reason")
        for field in ("content", "reasoning_content", "reasoning"):   # reasoning: vLLM, DeepSeek; OpenRouter, Ollama
            if isinstance(_get(c, "delta", field), str):
                _text(acc, choice.setdefault("message", {}), field, _get(c, "delta", field))
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
                    _append(part, field, _get(tc, k, field, default=""))


# ------------------------------------------------------------------ OpenAI Responses

# output item type -> tool name, for tools the provider runs itself
PROVIDER_ITEMS = {"web_search_call": "web_search", "file_search_call": "file_search",
                  "code_interpreter_call": "code_interpreter", "image_generation_call": "image_generation",
                  "mcp_call": "mcp"}
# provider-run output item type -> (the field holding its input, args_source)
PROVIDER_ARGS = {"web_search_call": ("action", "parsed"), "file_search_call": ("queries", "parsed"),
                 "code_interpreter_call": ("code", "parsed"), "mcp_call": ("arguments", "raw")}
# output item type -> (tool name or None for the item's `name`, the field holding the arguments, args_source)
CLIENT_ITEMS = {"function_call": (None, "arguments", "raw"), "custom_tool_call": (None, "input", "parsed"),
                "computer_call": ("computer", "action", "parsed"),
                "local_shell_call": ("local_shell", "action", "parsed"), "shell_call": ("shell", "action", "parsed"),
                "apply_patch_call": ("apply_patch", "operation", "parsed"),
                "tool_search_call": ("tool_search", "arguments", "parsed")}


def openai_responses(resp, request=None):
    uses = []
    for item in _list(resp, "output"):
        typ = _get(item, "type")
        if (typ == "shell_call" and _get(item, "environment", "type") == "container_reference"
                or typ == "tool_search_call" and _get(item, "execution") == "server"):   # hosted: the provider runs it
            _, field, source = CLIENT_ITEMS[typ]
            uses.append(tool_use(_get(item, "call_id") or _get(item, "id"), CLIENT_ITEMS[typ][0], _get(item, field),
                                 source, executed_by="provider"))
        elif typ in CLIENT_ITEMS:
            name, field, source = CLIENT_ITEMS[typ]
            uses.append(tool_use(_get(item, "call_id"), name or _get(item, "name"), _get(item, field), source))
        elif typ in PROVIDER_ITEMS:
            name = _get(item, "name") if typ == "mcp_call" else PROVIDER_ITEMS[typ]
            field, source = PROVIDER_ARGS.get(typ, (None, "parsed"))
            uses.append(tool_use(_get(item, "call_id") or _get(item, "id"), name, field and _get(item, field), source,
                                 executed_by="provider"))
    sent = [_get(i, "call_id") for i in _list(request, "input") if str(_get(i, "type", default="")).endswith("_output")]
    return _out(_get(resp, "id"), _get(resp, "model"), _get(resp, "incomplete_details", "reason") or _get(resp, "status"),
                _usage.from_openai(_get(resp, "usage")), uses, sent)


def _openai_responses_event(acc, ev):
    typ = _get(ev, "type") or ""
    if typ == "response.output_item.done":   # kept for a stream that never completes
        acc.setdefault("output", []).append(_plain(_get(ev, "item")))
    elif _get(ev, "response") is not None:
        acc.update(id=_get(ev, "response", "id"), model=_get(ev, "response", "model"))
        if typ in ("response.completed", "response.incomplete", "response.failed"):
            acc["final"] = _plain(_get(ev, "response"))


# ------------------------------------------------------------------ Anthropic Messages

PROVIDER_BLOCKS = ("server_tool_use", "mcp_tool_use")


def anthropic(resp, request=None):
    uses = []
    for b in _list(resp, "content"):
        typ = _get(b, "type")
        inp = _get(b, "input")   # the accumulated JSON string when streamed, else the SDK's decoded object
        if typ in ("tool_use", *PROVIDER_BLOCKS):
            uses.append(tool_use(_get(b, "id"), _get(b, "name"), inp, "raw" if isinstance(inp, str) else "parsed",
                                 "client" if typ == "tool_use" else "provider"))
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
        blk = _at(acc.setdefault("content", []), _get(ev, "index", default=0))
        blk.update({k: _get(b, k) for k in ("type", "id", "name", "input")})
        for k in ("text", "thinking", "signature", "data"):   # data: a redacted_thinking block, whole
            if isinstance(_get(b, k), str):
                blk[k] = ""
                _text(acc, blk, k, _get(b, k))
    elif typ == "content_block_delta" and _get(ev, "delta", "partial_json"):
        b = _at(acc.setdefault("content", []), _get(ev, "index", default=0))
        if not isinstance(b.get("input"), str):
            b["input"] = ""
        _append(b, "input", _get(ev, "delta", "partial_json"))
    elif typ == "content_block_delta":   # text_delta, thinking_delta, signature_delta
        b = _at(acc.setdefault("content", []), _get(ev, "index", default=0))
        for k in ("text", "thinking", "signature"):
            _text(acc, b, k, _get(ev, "delta", k))
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
            uses.append(tool_use(_get(fc, "id"), _get(fc, "name"), _get(fc, "args", default={})))
    contents = _get(request, "contents")
    sent = [_get(p, "function_response", "id") for c in (contents if isinstance(contents, list) else [contents])
            for p in _list(c, "parts")]
    fr = _get(resp, "candidates", 0, "finish_reason")
    return _out(rid, _get(resp, "model_version"), getattr(fr, "name", fr), _usage.from_gemini(_get(resp, "usage_metadata")),
                uses, sent)


def _gemini_chunk(acc, chunk):
    for k in ("response_id", "model_version", "usage_metadata"):
        if _get(chunk, k) is not None:
            acc[k] = _plain(_get(chunk, k))
    for i, c in enumerate(_list(chunk, "candidates")):
        cand = _at(acc.setdefault("candidates", []), i)
        if _get(c, "finish_reason") is not None:
            fr = _get(c, "finish_reason")
            cand["finish_reason"] = getattr(fr, "value", fr)   # the SDK's enum: its JSON value
        parts = cand.setdefault("content", {"parts": []})["parts"]
        for p in _list(c, "content", "parts"):
            sig = _get(p, "thought_signature")
            if isinstance(sig, bytes):   # the SDK's object; its JSON dump is base64
                sig = base64.b64encode(sig).decode()
            fc = _get(p, "function_call") is not None
            if not (fc or isinstance(_get(p, "text"), str) or sig):
                continue
            # text and thought parts: a run of one kind joined
            last = None if fc else parts[-1] if parts and isinstance(parts[-1], dict) and "\0text" in parts[-1] else None
            if last is None or sig or bool(last.get("thought")) != bool(_get(p, "thought")):
                if len(parts) >= MAX_INDEX:   # a part per chunk (one flipping `thought`): past this, dropped
                    acc["truncated"] = True
                    continue
                last = _plain(p) if fc else {"text": "", "\0text": [], **({"thought": True} if _get(p, "thought") else {})}
                parts.append(last)
            if not fc:
                if isinstance(sig, str):
                    last["thought_signature"] = sig
                _text(acc, last, "text", _get(p, "text"))


# ------------------------------------------------------------------ dispatch

PARSERS = {"openai:chat": (openai_chat, _openai_chat_chunk), "openai:responses": (openai_responses, _openai_responses_event),
           "anthropic:messages": (anthropic, _anthropic_event), "gemini:generate_content": (gemini, _gemini_chunk)}


ANTHROPIC_CLIENT_TOOLS = ("custom", "bash_", "text_editor_", "computer_", "memory_")   # typed tools the client runs
# OpenAI tool types other than function and custom that the client runs (CLIENT_ITEMS): the gateway's provider_tools
# never refuses them, though provider_tools() names them (tracekit why doesn't replay them); shell and tool_search may
# be hosted, so they are not among them
OPENAI_CLIENT_TOOLS = ("local_shell", "apply_patch", "computer_use_preview")


def provider_tools(kind, req):
    """The tools request `req` (a dict) lets the provider run itself, by name: an Anthropic typed tool the client does
    not run (its name), `mcp_servers`, `container`; an OpenAI tool of a type other than function and custom
    (`<type>[:<server_label>]`), `web_search_options`. Unknown types count, so a list of them errs towards the
    provider."""
    tools = [t for t in req.get("tools") or [] if isinstance(t, dict)]
    if kind == "anthropic:messages":
        names = [str(t.get("name") or t["type"]) for t in tools
                 if "type" in t and not str(t["type"]).startswith(ANTHROPIC_CLIENT_TOOLS)]
        return names + [k for k in ("mcp_servers", "container") if req.get(k)]
    names = [":".join(str(v) for v in (t.get("type"), t.get("server_label")) if v) for t in tools
             if t.get("type", "function") not in ("function", "custom")]
    return names + ["web_search_options"] * ("web_search_options" in req)


def tool_results(kind, req):
    """[(tool call id, content)] of each tool result request `req` (a dict) sends the model, oldest first: an OpenAI
    chat `role: tool` message's content, a Responses `*_output` item's output, an Anthropic `tool_result` block's
    content. Ids as the RPC takes them (_id); a result without an id is left out."""
    if kind == "openai:chat":
        pairs = [(_get(m, "tool_call_id"), _get(m, "content")) for m in _list(req, "messages") if _get(m, "role") == "tool"]
    elif kind == "openai:responses":
        pairs = [(_get(i, "call_id"), _get(i, "output")) for i in _list(req, "input")
                 if str(_get(i, "type", default="")).endswith("_output")]
    elif kind == "anthropic:messages":
        pairs = [(_get(b, "tool_use_id"), _get(b, "content")) for m in _list(req, "messages")
                 for b in _list(m, "content") if _get(b, "type") == "tool_result"]
    else:
        return []
    return [(_id(i), c) for i, c in pairs if i]


def parse(kind, response, request=None):
    out = PARSERS[kind][0](response, request)
    nonce = out["exchange_id"] or uuid.uuid4().hex
    for i, t in enumerate(out["tool_uses"]):
        if t["id"] is None:
            t.update(id=_id(f"{kind.split(':')[0]}:{nonce}:{i}"), id_synthetic=True)
    return out


# ------------------------------------------------------------------ what the model said

TOOL = None   # a tool use, in a _said_* walk


def _seg(kind, form, text=""):
    return {"kind": kind, "form": form, "text": text if isinstance(text, str) else "", "tools": []}


def _sealed(sealed):
    return _seg("reasoning", "encrypted" if sealed else "withheld")


def _said_anthropic(resp):
    for b in _list(resp, "content"):
        typ = _get(b, "type")
        if typ == "thinking":   # current models summarize it; display "omitted" leaves only the signature
            text = _get(b, "thinking", default="")
            yield _seg("reasoning", "summary", text) if text else _sealed(_get(b, "signature"))
        elif typ == "redacted_thinking":
            yield _sealed(_get(b, "data"))
        elif typ == "text" and _get(b, "text"):
            yield _seg("text", "full", _get(b, "text"))
        elif typ in ("tool_use", *PROVIDER_BLOCKS):
            yield TOOL


def _said_chat(resp):
    for c in _list(resp, "choices"):
        m = _get(c, "message")
        for field in ("reasoning_content", "reasoning"):
            if isinstance(_get(m, field), str) and _get(m, field):
                yield _seg("reasoning", "full", _get(m, field))
        text = _get(m, "content")
        if isinstance(text, str) and text.lstrip().startswith("<think>") and "</think>" in text:   # inline, open models
            think, _, text = text.lstrip()[len("<think>"):].partition("</think>")
            yield _seg("reasoning", "full", think)
        if isinstance(text, str) and text.strip():
            yield _seg("text", "full", text)
        for _ in _list(m, "tool_calls"):
            yield TOOL


def _said_responses(resp):
    for item in _list(resp, "output"):
        typ = _get(item, "type")
        if typ == "reasoning":
            full = "\n".join(t for t in (_get(x, "text") for x in _list(item, "content")) if isinstance(t, str) and t)
            summary = "\n".join(t for t in (_get(x, "text") for x in _list(item, "summary")) if isinstance(t, str) and t)
            yield _seg("reasoning", "full", full) if full else _seg("reasoning", "summary", summary) if summary \
                else _sealed(_get(item, "encrypted_content"))
        elif typ == "message":
            text = "".join(t for t in (_get(x, "text") for x in _list(item, "content")) if isinstance(t, str))
            if text:
                yield _seg("text", "full", text)
        elif typ in CLIENT_ITEMS or typ in PROVIDER_ITEMS:
            yield TOOL


def _said_gemini(resp):
    for c in _list(resp, "candidates"):
        for p in _list(c, "content", "parts"):
            text = _get(p, "text")
            if _get(p, "thought"):   # a thought summary (include_thoughts)
                yield _seg("reasoning", "summary", text) if text else _sealed(_get(p, "thought_signature"))
                continue
            if _get(p, "thought_signature"):   # the reasoning behind this part, sealed
                yield _sealed(True)
            if _get(p, "function_call") is not None:
                yield TOOL
            elif isinstance(text, str) and text:
                yield _seg("text", "full", text)


SAID = {"openai:chat": _said_chat, "openai:responses": _said_responses, "anthropic:messages": _said_anthropic,
        "gemini:generate_content": _said_gemini}


def said(kind, response):
    """What the model said in `response`, in order (see the module docstring)."""
    ids, out = iter([t["id"] for t in parse(kind, response)["tool_uses"]]), []
    for s in SAID[kind](response):
        if s is not TOOL:
            out.append(s)
            continue
        tid = next(ids, None)
        if out and tid:
            out[-1]["tools"].append(tid)
    return out


class Stream:
    """One streamed response, accumulated: `add(chunk)` per chunk, then `parse(request)`."""

    def __init__(self, kind):
        self.kind, self.acc, self.seen = kind, {}, False

    def add(self, chunk):
        self.seen = True
        PARSERS[self.kind][1](self.acc, chunk)

    def content(self):
        """The response accumulated so far, as one JSON value."""
        _joined(self.acc)
        return self.acc.get("final", self.acc)

    def parse(self, request=None):
        return parse(self.kind, self.content(), request)
