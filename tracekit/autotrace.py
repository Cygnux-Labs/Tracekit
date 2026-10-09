"""One-line tracing of model calls made through the OpenAI, Anthropic and Google Gen AI Python SDKs.

    import tracekit_sdk
    tracer = tracekit_sdk.init(agent="research-bot")     # patches every installed provider SDK
    client = openai.OpenAI(); client.chat.completions.create(...)   # recorded, signed, checkpointed

Every call becomes two signed ``model.exchange`` events in the tracer's run: a request (written before the call
is sent, so a crash mid-call still leaves evidence it was made) and a response with the model, finish reason, the
tool calls the model asked for, error, HTTP status, latency and time to first chunk. Sync, async and streaming calls
are covered; a stream is recorded when it is exhausted or closed, and a garbage-collected one at the next model
call, the end of the run or exit, so an abandoned stream still leaves a response event marked as such.

Into a v2 run (``init(run=handle)``, or any call made inside ``with client.run(...)``, see tracekit.sdk.client) the
two events go through the signer's ``model_event``: the request lists the tool results it sends back, the response
the tool calls tracekit.parsers read from it. The fail mode is the run's, from register_run (``model``, else
``default``), in place of the policy's ``fail_mode``.

Content (prompts, outputs) is redacted and hashed by default, exactly as for every other Tracekit capture path;
``content_capture: full`` in the policy records it in clear.

Guarantees
* Instrumentation never changes what the SDK returns or raises. If recording fails the call still runs, unless the
  policy says ``fail_mode: closed``, in which case a call whose request cannot be recorded is refused
  (``PermissionError``) before it is sent.
* ``init`` is idempotent and ``shutdown`` restores the original methods.
* Once the tracer's run has ended, model calls are no longer recorded: under ``fail_mode: closed`` they are refused
  (``PermissionError``), under ``open`` they run unrecorded.
* Events are ``source=sdk``: the application reported them. They are evidence of what the process sent and received
  through these SDKs, not of calls made any other way (raw HTTP, other SDKs, other processes).
"""
import atexit
import collections
import functools
import importlib
import os
import sys
import threading
import time
import uuid

from . import client, parsers, privacy
from . import usage as _usage
from .core import jsonable
from .parsers import _get
from .sdk.client import AsyncRunHandle, RunHandle, current_run, fail_open
from .signer.rpc_schema import MAX_RESULTS_SENT

MAX_TEXT = 1024 * 1024   # streamed text kept for the (hashed) response content
_STATE = {"tracer": None, "patched": [], "lock": threading.RLock()}
_LATE = collections.deque()   # exchanges of garbage-collected streams, recorded on the next flush (never from __del__)


# ------------------------------------------------------------------ helpers

def _dump(obj):
    """Pydantic models (all three SDKs) -> plain data; anything else -> jsonable."""
    for attr in ("model_dump", "to_dict", "dict"):
        f = getattr(obj, attr, None)
        if callable(f):
            try:
                return jsonable(f())
            except Exception:
                pass
    return jsonable(obj)


def _request_content(kwargs):
    drop = {"extra_headers", "extra_query", "timeout", "http_client", "stream_options"}
    return jsonable({k: v for k, v in kwargs.items() if k not in drop and type(v).__name__ not in ("Omit", "NotGiven")})


def _status_of(exc):
    for attr in ("status_code", "code", "status"):
        v = getattr(exc, attr, None)
        if isinstance(v, int) and 100 <= v < 600:
            return v
    return None


# ------------------------------------------------------------------ recording

class _Exchange:
    """One model call. begin() -> request event; finish() -> response event (exactly once)."""

    def __init__(self, tracer, provider, operation, model, kwargs, streamed, on_resp=None, on_item=None):
        self.tracer, self.provider, self.operation = tracer, provider, operation
        self.model, self.kwargs, self.streamed = model, kwargs, streamed
        self.on_resp, self.on_item = on_resp, on_item
        self.id = "ex_" + uuid.uuid4().hex[:20]
        self.t0 = time.monotonic()
        self.first_byte = None
        self.done = False
        self.lock = threading.Lock()
        self.stop_reason, self.tool_uses, self.text, self.resp_model, self.chunks = None, {}, [], None, 0
        self.text_len = 0
        self.usage = None

    def response(self, resp):
        if self.on_resp:
            self.on_resp(self, resp)

    def item(self, item):
        if self.on_item:
            self.on_item(self, item)

    def add_text(self, t):
        if isinstance(t, str) and self.text_len < MAX_TEXT:
            self.text.append(t)
            self.text_len += len(t)

    def add_usage(self, u):
        self.usage = _usage.merge(self.usage, u)

    def _capture(self):
        return self.tracer._policy.get("content_capture", "hashed")

    def begin(self):
        if self.tracer._ended:
            self.done = True
            return
        data = {"exchange_id": self.id, "phase": "request", "model": self.model, "streamed": self.streamed,
                "upstream": f"sdk:{self.provider}:{self.operation}", "attribution": "none",
                "request": privacy.content(_request_content(self.kwargs), self._capture())}
        try:
            self.tracer._send(self.tracer._event("model.exchange", data))
        except client.SignerUnavailable as e:
            raise PermissionError(f"Tracekit: signer unavailable and fail_mode=closed; model call refused: {e}") from e
        except Exception as e:
            if self.tracer._policy.get("fail_mode") == "closed":
                raise PermissionError(f"Tracekit: request not recorded and fail_mode=closed; model call refused: {e}") from e
            _note_failure()

    def chunk(self):
        self.chunks += 1
        if self.first_byte is None:
            self.first_byte = time.monotonic()

    def finish(self, response=None, error=None, status=None, abandoned=False):
        with self.lock:
            if self.done:
                return
            self.done = True
        if self.tracer._ended:  # e.g. a stream finished after the run ended: its response can no longer be recorded
            try:
                self.tracer._send(self.tracer._event("capture.gap", {
                    "reason": f"model call {self.id} finished after the run ended; its response was not recorded",
                    "kind": "late_stream"}))
            except Exception:
                _note_failure()
            return
        try:
            tools = [{"id": str(i)[:200], "name": str(n)[:200]} for i, n in list(self.tool_uses.items())[:128] if i and n]
            if response is not None:
                content = _dump(response)
            elif self.text or tools:
                content = {"text": "".join(self.text)[:MAX_TEXT], "tool_calls": tools}
            else:
                content = None
            if abandoned and not error:
                error = f"stream abandoned after {self.chunks} chunk(s)"
            data = {"exchange_id": self.id, "phase": "response", "model": self.resp_model or self.model,
                    "streamed": self.streamed, "status": status if status is not None else (None if error else 200),
                    "duration_ms": int((time.monotonic() - self.t0) * 1000),
                    "first_byte_ms": int((self.first_byte - self.t0) * 1000) if self.first_byte else None,
                    "stop_reason": str(self.stop_reason)[:100] if self.stop_reason is not None else None,
                    "tool_uses": tools, "error": str(error)[:500] if error else None,
                    "upstream": f"sdk:{self.provider}:{self.operation}", "attribution": "none"}
            if self.usage:
                data["usage"] = self.usage
            if content is not None:
                data["response"] = privacy.content(content, self._capture())
            self.tracer._send(self.tracer._event("model.exchange", data))
        except Exception:
            _note_failure()


class _RunExchange:
    """One model call recorded into a v2 run as two `model_event`s: the request (with the tool results it sends back)
    before the call, and the response with what tracekit.parsers read from it."""

    def __init__(self, run, provider, operation, kwargs, streamed):
        self.run, self.provider, self.kwargs, self.streamed = run, provider, kwargs, streamed
        self.kind, self.model = f"{provider}:{operation}", _model_kw(kwargs)
        self.id = "ex_" + uuid.uuid4().hex[:20]
        self.stream = parsers.Stream(self.kind) if streamed else None
        self.parsed, self.chunks, self.done, self.lock = None, 0, False, threading.Lock()

    def _fail_closed(self):
        """The run's fail mode for model calls: `model` in register_run's fail_modes, else `default`."""
        return not fail_open(self.run.registered.get("fail_modes"), "model")

    def _send(self, phase, model, out, **fields):
        # lean: async calls record through the sync client, holding the event loop for one local round trip; use
        # AsyncClient's thread hop if that shows up in latency
        sent = out["tool_results_sent"][-MAX_RESULTS_SENT:]   # lean: the newest results only, in very long histories
        self.run.call("model_event", provider=self.provider, model=str(model or "")[:128], phase=phase,
                      exchange_id=self.id, streamed=self.streamed, **({"tool_results_sent": sent} if sent else {}),
                      **fields)

    def begin(self):
        if self.run.closed:
            self.done = True
            if self._fail_closed():
                raise PermissionError("Tracekit: the run has ended and its fail mode is closed; model call refused")
            return
        try:
            self._send("request", self.model, parsers.parse(self.kind, None, self.kwargs))
        except Exception as e:
            if self._fail_closed():
                raise PermissionError(f"Tracekit: request not recorded and the run's fail mode is closed; model call "
                                      f"refused: {e}") from e
            _note_failure()

    def response(self, resp):
        self.parsed = parsers.parse(self.kind, resp, self.kwargs)

    def item(self, item):
        self.stream.add(item)

    def chunk(self):
        self.chunks += 1

    def _out(self):
        """The complete message when the SDK handed one over (a stream finished with get_final_message() after part of
        it went through the proxy), else what the proxy saw of the stream."""
        if self.parsed is not None:
            return self.parsed
        return self.stream.parse(self.kwargs) if self.stream and self.stream.seen else None

    @property
    def stop_reason(self):
        return (self._out() or {}).get("finish")

    def finish(self, response=None, error=None, status=None, abandoned=False):
        with self.lock:
            if self.done:
                return
            self.done = True
        try:
            out = self._out() or parsers.parse(self.kind, None, self.kwargs)
            if abandoned and not error:
                error = f"stream abandoned after {self.chunks} chunk(s)"
            fields = {"stop_reason": out["finish"] and str(out["finish"])[:100], "usage": out["usage"],
                      "tool_uses": out["tool_uses"][:128],   # lean: the RPC's cap; v1 caps the same way
                      "error": error and str(error)[:1024]}
            self._send("response", out["model"] or self.model, out, **{k: v for k, v in fields.items() if v})
        except Exception:
            _note_failure()


_FAILURES = {"n": 0, "warned": False}


def _note_failure():
    _FAILURES["n"] += 1
    if not _FAILURES["warned"]:
        _FAILURES["warned"] = True
        print("[tracekit] could not record a model call; the call itself was not affected", file=sys.stderr, flush=True)


# ------------------------------------------------------------------ provider extraction

def _openai_chat(ex, resp):
    ex.resp_model = _get(resp, "model")
    ex.add_usage(_usage.from_openai(_get(resp, "usage")))
    ex.stop_reason = _get(resp, "choices", 0, "finish_reason")
    for ch in _get(resp, "choices", default=[]) or []:
        for tc in _get(ch, "message", "tool_calls", default=[]) or []:
            ex.tool_uses[_get(tc, "id")] = _get(tc, "function", "name") or _get(tc, "type")


def _openai_chat_chunk(ex, chunk):
    ex.resp_model = ex.resp_model or _get(chunk, "model")
    ex.add_usage(_usage.from_openai(_get(chunk, "usage")))  # last chunk, with stream_options={"include_usage": True}
    for ch in _get(chunk, "choices", default=[]) or []:
        if _get(ch, "finish_reason"):
            ex.stop_reason = _get(ch, "finish_reason")
        d = _get(ch, "delta")
        t = _get(d, "content")
        ex.add_text(t)
        for tc in _get(d, "tool_calls", default=[]) or []:
            idx = _get(tc, "index", default=0)
            key = _get(tc, "id")
            if key:
                ex._idx = getattr(ex, "_idx", {})
                ex._idx[idx] = key
                ex.tool_uses.setdefault(key, None)
            name = _get(tc, "function", "name")
            if name:
                k = key or getattr(ex, "_idx", {}).get(idx)
                if k:
                    ex.tool_uses[k] = name


def _openai_responses(ex, resp):
    ex.resp_model = _get(resp, "model")
    ex.add_usage(_usage.from_openai(_get(resp, "usage")))
    ex.stop_reason = _get(resp, "incomplete_details", "reason") or _get(resp, "status")
    for item in _get(resp, "output", default=[]) or []:
        if _get(item, "type") in ("function_call", "custom_tool_call", "mcp_call"):
            ex.tool_uses[_get(item, "call_id") or _get(item, "id")] = _get(item, "name")


def _openai_responses_event(ex, ev):
    t = _get(ev, "type") or ""
    if t in ("response.completed", "response.incomplete", "response.failed"):
        _openai_responses(ex, _get(ev, "response"))
    elif t == "response.output_text.delta":
        d = _get(ev, "delta")
        ex.add_text(d)
    elif t == "response.output_item.added":
        item = _get(ev, "item")
        if _get(item, "type") in ("function_call", "custom_tool_call", "mcp_call"):
            ex.tool_uses[_get(item, "call_id") or _get(item, "id")] = _get(item, "name")


def _anthropic_msg(ex, resp):
    ex.resp_model = _get(resp, "model")
    ex.add_usage(_usage.from_anthropic(_get(resp, "usage")))
    ex.stop_reason = _get(resp, "stop_reason")
    for b in _get(resp, "content", default=[]) or []:
        if _get(b, "type") in ("tool_use", "server_tool_use", "mcp_tool_use"):
            ex.tool_uses[_get(b, "id")] = _get(b, "name")


def _anthropic_event(ex, ev):
    t = _get(ev, "type")
    if t == "message_start":
        ex.resp_model = _get(ev, "message", "model")
        ex.add_usage(_usage.from_anthropic(_get(ev, "message", "usage")))
    elif t == "content_block_start":
        b = _get(ev, "content_block")
        if _get(b, "type") in ("tool_use", "server_tool_use", "mcp_tool_use"):
            ex.tool_uses[_get(b, "id")] = _get(b, "name")
    elif t == "content_block_delta":
        txt = _get(ev, "delta", "text")
        ex.add_text(txt)
    elif t == "message_delta":
        ex.stop_reason = _get(ev, "delta", "stop_reason") or ex.stop_reason
        ex.add_usage(_usage.from_anthropic(_get(ev, "usage")))


def _gemini(ex, resp):
    ex.resp_model = _get(resp, "model_version") or ex.resp_model
    ex.add_usage(_usage.from_gemini(_get(resp, "usage_metadata")))
    fr = _get(resp, "candidates", 0, "finish_reason")
    if fr is not None:
        ex.stop_reason = getattr(fr, "name", None) or str(fr)
    for i, cand in enumerate(_get(resp, "candidates", default=[]) or []):
        for p in _get(cand, "content", "parts", default=[]) or []:
            fc = _get(p, "function_call")
            if fc is not None:
                ex.tool_uses[_get(fc, "id") or f"{ex.id}:{i}:{_get(fc, 'name')}"] = _get(fc, "name")
            t = _get(p, "text")
            if ex.streamed:
                ex.add_text(t)


# ------------------------------------------------------------------ stream proxies

class _StreamProxy:
    """Wraps an SDK stream (sync and/or async). Delegates everything; records the response when the stream ends."""

    def __init__(self, inner, ex):
        object.__setattr__(self, "_tk_inner", inner)
        object.__setattr__(self, "_tk_ex", ex)
        object.__setattr__(self, "_tk_it", None)

    def __getattr__(self, name):
        return getattr(self._tk_inner, name)

    def __setattr__(self, name, value):
        setattr(self._tk_inner, name, value)

    def _item(self, item):
        self._tk_ex.chunk()
        try:
            self._tk_ex.item(item)
        except Exception:
            pass
        return item

    def _end(self, error=None, abandoned=False):
        self._tk_ex.finish(response=None, error=error, status=_status_of(error) if error else None, abandoned=abandoned)

    # sync
    def __iter__(self):
        it = iter(self._tk_inner)
        object.__setattr__(self, "_tk_it", it)
        try:
            for item in it:
                yield self._item(item)
        except GeneratorExit:
            _LATE.append(self._tk_ex)  # finalisation may run from the GC: no signer I/O here
            raise
        except BaseException as e:
            self._end(error=repr(e))
            raise
        self._end()

    def __next__(self):
        it = self._tk_it
        if it is None:
            it = iter(self._tk_inner)
            object.__setattr__(self, "_tk_it", it)
        try:
            return self._item(next(it))
        except StopIteration:
            self._end()
            raise
        except BaseException as e:
            self._end(error=repr(e))
            raise

    def __enter__(self):
        if hasattr(self._tk_inner, "__enter__"):
            self._tk_inner.__enter__()
        return self

    def __exit__(self, et, e, tb):
        try:
            if hasattr(self._tk_inner, "__exit__"):
                return self._tk_inner.__exit__(et, e, tb)
        finally:
            self._end(error=repr(e) if e else None, abandoned=not self._tk_ex.done and e is None and not self._completed())

    def _completed(self):
        return self._tk_ex.stop_reason is not None

    def close(self):
        try:
            f = getattr(self._tk_inner, "close", None)
            if f:
                return f()
        finally:
            self._end(abandoned=not self._completed())

    # async
    def __aiter__(self):
        return self._agen()

    async def _agen(self):
        try:
            async for item in self._tk_inner:
                yield self._item(item)
        except GeneratorExit:
            _LATE.append(self._tk_ex)  # finalisation may run from the GC: no signer I/O here
            raise
        except BaseException as e:
            self._end(error=repr(e))
            raise
        self._end()

    async def __anext__(self):
        it = self._tk_it
        if it is None:
            it = self._tk_inner.__aiter__()
            object.__setattr__(self, "_tk_it", it)
        try:
            return self._item(await it.__anext__())
        except StopAsyncIteration:
            self._end()
            raise
        except BaseException as e:
            self._end(error=repr(e))
            raise

    async def __aenter__(self):
        if hasattr(self._tk_inner, "__aenter__"):
            await self._tk_inner.__aenter__()
        return self

    async def __aexit__(self, et, e, tb):
        try:
            if hasattr(self._tk_inner, "__aexit__"):
                return await self._tk_inner.__aexit__(et, e, tb)
        finally:
            self._end(error=repr(e) if e else None, abandoned=e is None and not self._completed())

    async def aclose(self):
        try:
            f = getattr(self._tk_inner, "aclose", None) or getattr(self._tk_inner, "close", None)
            if f:
                r = f()
                if hasattr(r, "__await__"):
                    await r
        finally:
            self._end(abandoned=not self._completed())

    def __del__(self):
        if not self._tk_ex.done:
            _LATE.append(self._tk_ex)


class _ManagerProxy:
    """anthropic ``messages.stream(...)`` returns a context manager whose __enter__ yields the stream."""

    def __init__(self, inner, make_ex):
        self._inner, self._make_ex, self._proxy = inner, make_ex, None

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def _wrap(self, stream, ex):
        self._proxy = _StreamProxy(stream, ex)
        return self._proxy

    def __enter__(self):
        ex = self._make_ex()
        try:
            return self._wrap(self._inner.__enter__(), ex)
        except BaseException as e:
            ex.finish(error=repr(e), status=_status_of(e))
            raise

    def __exit__(self, et, e, tb):
        try:
            return self._inner.__exit__(et, e, tb)
        finally:
            self._finish_from_snapshot(e)

    async def __aenter__(self):
        ex = self._make_ex()
        try:
            return self._wrap(await self._inner.__aenter__(), ex)
        except BaseException as e:
            ex.finish(error=repr(e), status=_status_of(e))
            raise

    async def __aexit__(self, et, e, tb):
        try:
            return await self._inner.__aexit__(et, e, tb)
        finally:
            self._finish_from_snapshot(e)

    def _finish_from_snapshot(self, e):
        p = self._proxy
        if p is None or p._tk_ex.done:
            return
        snap = getattr(p._tk_inner, "current_message_snapshot", None)
        try:
            if snap is not None and not e:
                p._tk_ex.response(snap)
        except Exception:
            pass
        p._tk_ex.finish(error=repr(e) if e else None, status=_status_of(e) if e else None,
                        abandoned=not e and p._tk_ex.stop_reason is None)


# ------------------------------------------------------------------ patch table

def _model_kw(kwargs):
    m = kwargs.get("model")
    return str(m)[:200] if m is not None and type(m).__name__ not in ("Omit", "NotGiven") else None


# (provider, module, class, method, operation, is_async, on_response, on_stream_item, stream_kind)
#  stream_kind: "kwarg" -> streamed when stream=True; "always" -> method always streams; "manager" -> context manager
TARGETS = [
    ("openai", "openai.resources.chat.completions", "Completions", "create", "chat", False, _openai_chat, _openai_chat_chunk, "kwarg"),
    ("openai", "openai.resources.chat.completions", "AsyncCompletions", "create", "chat", True, _openai_chat, _openai_chat_chunk, "kwarg"),
    ("openai", "openai.resources.chat.completions", "Completions", "parse", "chat", False, _openai_chat, _openai_chat_chunk, None),
    ("openai", "openai.resources.chat.completions", "AsyncCompletions", "parse", "chat", True, _openai_chat, _openai_chat_chunk, None),
    ("openai", "openai.resources.responses", "Responses", "create", "responses", False, _openai_responses, _openai_responses_event, "kwarg"),
    ("openai", "openai.resources.responses", "AsyncResponses", "create", "responses", True, _openai_responses, _openai_responses_event, "kwarg"),
    ("openai", "openai.resources.responses", "Responses", "parse", "responses", False, _openai_responses, _openai_responses_event, None),
    ("openai", "openai.resources.responses", "AsyncResponses", "parse", "responses", True, _openai_responses, _openai_responses_event, None),
    ("anthropic", "anthropic.resources.messages", "Messages", "create", "messages", False, _anthropic_msg, _anthropic_event, "kwarg"),
    ("anthropic", "anthropic.resources.messages", "AsyncMessages", "create", "messages", True, _anthropic_msg, _anthropic_event, "kwarg"),
    ("anthropic", "anthropic.resources.messages", "Messages", "parse", "messages", False, _anthropic_msg, _anthropic_event, None),
    ("anthropic", "anthropic.resources.messages", "AsyncMessages", "parse", "messages", True, _anthropic_msg, _anthropic_event, None),
    ("anthropic", "anthropic.resources.messages", "Messages", "stream", "messages", False, _anthropic_msg, _anthropic_event, "manager"),
    ("anthropic", "anthropic.resources.messages", "AsyncMessages", "stream", "messages", False, _anthropic_msg, _anthropic_event, "manager"),
    ("gemini", "google.genai.models", "Models", "generate_content", "generate_content", False, _gemini, _gemini, None),
    ("gemini", "google.genai.models", "AsyncModels", "generate_content", "generate_content", True, _gemini, _gemini, None),
    ("gemini", "google.genai.models", "Models", "generate_content_stream", "generate_content", False, _gemini, _gemini, "always"),
    ("gemini", "google.genai.models", "AsyncModels", "generate_content_stream", "generate_content", True, _gemini, _gemini, "always"),
]
PROVIDERS = ("openai", "anthropic", "gemini")


def flush():
    """Record the streams that were garbage-collected before they finished."""
    while _LATE:
        try:
            ex = _LATE.popleft()
        except IndexError:
            return
        ex.finish(abandoned=True)


atexit.register(flush)


def _wrap(orig, provider, operation, is_async, on_resp, on_item, stream_kind):
    def make_ex(kwargs, streamed):
        flush()
        t = _target()
        if t is None:
            return None
        if isinstance(t, (RunHandle, AsyncRunHandle)):
            ex = _RunExchange(getattr(t, "_sync", t), provider, operation, kwargs, streamed)
        elif getattr(t, "_ended", False):
            if t._policy.get("fail_mode") == "closed":
                raise PermissionError("Tracekit: the run has ended and fail_mode=closed; model call refused")
            return None
        else:
            ex = _Exchange(t, provider, operation, _model_kw(kwargs), kwargs, streamed, on_resp, on_item)
        ex.begin()
        return ex

    if stream_kind == "manager":
        @functools.wraps(orig)
        def manager(self, *args, **kwargs):
            inner = orig(self, *args, **kwargs)
            if _target() is None:
                return inner
            return _ManagerProxy(inner, lambda: make_ex(kwargs, True) or _NullEx())
        manager.__tracekit_wrapped__ = orig
        return manager

    def streamed_of(kwargs):
        return stream_kind == "always" or (stream_kind == "kwarg" and kwargs.get("stream") is True)

    if is_async:
        @functools.wraps(orig)
        async def awrapper(self, *args, **kwargs):
            streamed = streamed_of(kwargs)
            ex = make_ex(kwargs, streamed)
            if ex is None:
                return await orig(self, *args, **kwargs)
            try:
                out = await orig(self, *args, **kwargs)
            except BaseException as e:
                ex.finish(error=repr(e), status=_status_of(e))
                raise
            if streamed:
                return _StreamProxy(out, ex)
            try:
                ex.response(out)
            except Exception:
                pass
            ex.finish(response=out)
            return out
        awrapper.__tracekit_wrapped__ = orig
        return awrapper

    @functools.wraps(orig)
    def wrapper(self, *args, **kwargs):
        streamed = streamed_of(kwargs)
        ex = make_ex(kwargs, streamed)
        if ex is None:
            return orig(self, *args, **kwargs)
        try:
            out = orig(self, *args, **kwargs)
        except BaseException as e:
            ex.finish(error=repr(e), status=_status_of(e))
            raise
        if streamed:
            return _StreamProxy(out, ex)
        try:
            ex.response(out)
        except Exception:
            pass
        ex.finish(response=out)
        return out
    wrapper.__tracekit_wrapped__ = orig
    return wrapper


def _target():
    """What a model call records into: the current v2 run (`with client.run(...)`), else what `instrument` was given."""
    run = current_run.get()
    return run if run is not None else _STATE["tracer"]


class _NullEx:
    done = True
    stop_reason = None

    def chunk(self):
        pass

    def item(self, item):
        pass

    def response(self, resp):
        pass

    def finish(self, *a, **k):
        pass


def instrument(tracer, providers=PROVIDERS):
    """Patch the installed provider SDKs to record into ``tracer``: a v1 ``Tracer``, a v2 run handle, or None for
    only the current v2 run. Returns the list of patched methods."""
    with _STATE["lock"]:
        _STATE["tracer"] = tracer
        done = []
        for provider, mod, cls, meth, op, is_async, on_resp, on_item, kind in TARGETS:
            if provider not in providers:
                continue
            try:
                klass = getattr(importlib.import_module(mod), cls)
            except (ImportError, AttributeError):
                continue
            orig = klass.__dict__.get(meth)
            if orig is None or getattr(orig, "__tracekit_wrapped__", None) is not None:
                if orig is not None:
                    done.append(f"{provider}:{cls}.{meth}")
                continue
            setattr(klass, meth, _wrap(orig, provider, op, is_async, on_resp, on_item, kind))
            _STATE["patched"].append((klass, meth, orig))
            done.append(f"{provider}:{cls}.{meth}")
        return done


def uninstrument():
    with _STATE["lock"]:
        for klass, meth, orig in reversed(_STATE["patched"]):
            setattr(klass, meth, orig)
        _STATE["patched"].clear()
        _STATE["tracer"] = None


def init(agent=None, session_id=None, providers=PROVIDERS, cwd=None, run=None):
    """Start a run and record every model call made through the installed provider SDKs. Idempotent: a second call
    returns the active tracer. The run ends at interpreter exit (or call ``tracer.end()`` / ``shutdown()``).

    With ``run``, a v2 run handle (tracekit.sdk.client), model calls are recorded into that run instead; you close it.
    Either way, a call made inside ``with client.run(...)`` goes to that block's run."""
    from .agent_sdk import Tracer
    if run is not None:
        instrument(run, providers)
        return run
    with _STATE["lock"]:
        t = _STATE["tracer"]
        if t is not None and not getattr(t, "_ended", True):
            return t
        name = agent or os.environ.get("TRACEKIT_AGENT") or os.path.splitext(os.path.basename(sys.argv[0] or "python"))[0] or "python"
        t = Tracer(agent=name, session_id=session_id, cwd=cwd)
        instrument(t, providers)
        atexit.register(_atexit, t)
        return t


def _atexit(t):
    try:
        flush()
        if _STATE["tracer"] is t and not t._ended:
            t.end("process exit")
    except Exception:
        pass


def shutdown(reason="done"):
    with _STATE["lock"]:
        t = _STATE["tracer"]
        flush()
        uninstrument()
        if t is not None and not getattr(t, "_ended", True):   # a v2 run handle is closed by its owner
            t.end(reason)
