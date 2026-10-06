"""One-line tracing of model calls made through the OpenAI, Anthropic and Google Gen AI Python SDKs.

    import tracekit_sdk
    tracer = tracekit_sdk.init(agent="research-bot")     # patches every installed provider SDK
    client = openai.OpenAI(); client.chat.completions.create(...)   # recorded, signed, checkpointed

Every call becomes two signed ``model.exchange`` events in the tracer's run: a request (written before the call
is sent, so a crash mid-call still leaves evidence it was made) and a response with the model, finish reason, the
tool calls the model asked for, error, HTTP status, latency and time to first chunk. Sync, async and streaming calls
are covered; a stream is recorded when it is exhausted, closed or garbage collected, so an abandoned stream still
leaves a response event marked as such.

Content (prompts, outputs) is redacted and hashed by default, exactly as for every other Tracekit capture path;
``content_capture: full`` in the policy records it in clear.

Guarantees
* Instrumentation never changes what the SDK returns or raises. If recording fails the call still runs, unless the
  policy says ``fail_mode: closed``, in which case a call whose request cannot be recorded is refused
  (``PermissionError``) before it is sent.
* ``init`` is idempotent and ``shutdown`` restores the original methods.
* Events are ``source=sdk``: the application reported them. They are evidence of what the process sent and received
  through these SDKs, not of calls made any other way (raw HTTP, other SDKs, other processes).
"""
import atexit
import functools
import importlib
import os
import sys
import threading
import time
import uuid

from . import client, privacy
from .core import jsonable

MAX_TEXT = 1024 * 1024   # streamed text kept for the (hashed) response content
_STATE = {"tracer": None, "patched": [], "lock": threading.RLock()}


# ------------------------------------------------------------------ helpers

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

    def __init__(self, tracer, provider, operation, model, kwargs, streamed):
        self.tracer, self.provider, self.operation = tracer, provider, operation
        self.model, self.kwargs, self.streamed = model, kwargs, streamed
        self.id = "ex_" + uuid.uuid4().hex[:20]
        self.t0 = time.monotonic()
        self.first_byte = None
        self.done = False
        self.lock = threading.Lock()
        self.stop_reason, self.tool_uses, self.text, self.resp_model, self.chunks = None, {}, [], None, 0

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
        except Exception:
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
        if self.tracer._ended:  # e.g. a stream garbage-collected after the run ended: nothing left to attach it to
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
            if content is not None:
                data["response"] = privacy.content(content, self._capture())
            self.tracer._send(self.tracer._event("model.exchange", data))
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
    ex.stop_reason = _get(resp, "choices", 0, "finish_reason")
    for ch in _get(resp, "choices", default=[]) or []:
        for tc in _get(ch, "message", "tool_calls", default=[]) or []:
            ex.tool_uses[_get(tc, "id")] = _get(tc, "function", "name") or _get(tc, "type")


def _openai_chat_chunk(ex, chunk):
    ex.resp_model = ex.resp_model or _get(chunk, "model")
    for ch in _get(chunk, "choices", default=[]) or []:
        if _get(ch, "finish_reason"):
            ex.stop_reason = _get(ch, "finish_reason")
        d = _get(ch, "delta")
        t = _get(d, "content")
        if isinstance(t, str) and sum(map(len, ex.text)) < MAX_TEXT:
            ex.text.append(t)
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
        if isinstance(d, str) and sum(map(len, ex.text)) < MAX_TEXT:
            ex.text.append(d)
    elif t == "response.output_item.added":
        item = _get(ev, "item")
        if _get(item, "type") in ("function_call", "custom_tool_call", "mcp_call"):
            ex.tool_uses[_get(item, "call_id") or _get(item, "id")] = _get(item, "name")


def _anthropic_msg(ex, resp):
    ex.resp_model = _get(resp, "model")
    ex.stop_reason = _get(resp, "stop_reason")
    for b in _get(resp, "content", default=[]) or []:
        if _get(b, "type") in ("tool_use", "server_tool_use", "mcp_tool_use"):
            ex.tool_uses[_get(b, "id")] = _get(b, "name")


def _anthropic_event(ex, ev):
    t = _get(ev, "type")
    if t == "message_start":
        ex.resp_model = _get(ev, "message", "model")
    elif t == "content_block_start":
        b = _get(ev, "content_block")
        if _get(b, "type") in ("tool_use", "server_tool_use", "mcp_tool_use"):
            ex.tool_uses[_get(b, "id")] = _get(b, "name")
    elif t == "content_block_delta":
        txt = _get(ev, "delta", "text")
        if isinstance(txt, str) and sum(map(len, ex.text)) < MAX_TEXT:
            ex.text.append(txt)
    elif t == "message_delta":
        ex.stop_reason = _get(ev, "delta", "stop_reason") or ex.stop_reason


def _gemini(ex, resp):
    ex.resp_model = _get(resp, "model_version") or ex.resp_model
    fr = _get(resp, "candidates", 0, "finish_reason")
    if fr is not None:
        ex.stop_reason = getattr(fr, "name", None) or str(fr)
    for i, cand in enumerate(_get(resp, "candidates", default=[]) or []):
        for p in _get(cand, "content", "parts", default=[]) or []:
            fc = _get(p, "function_call")
            if fc is not None:
                ex.tool_uses[_get(fc, "id") or f"{ex.id}:{i}:{_get(fc, 'name')}"] = _get(fc, "name")
            t = _get(p, "text")
            if ex.streamed and isinstance(t, str) and sum(map(len, ex.text)) < MAX_TEXT:
                ex.text.append(t)


# ------------------------------------------------------------------ stream proxies

class _StreamProxy:
    """Wraps an SDK stream (sync and/or async). Delegates everything; records the response when the stream ends."""

    def __init__(self, inner, ex, on_item, final=None):
        object.__setattr__(self, "_tk_inner", inner)
        object.__setattr__(self, "_tk_ex", ex)
        object.__setattr__(self, "_tk_on", on_item)
        object.__setattr__(self, "_tk_final", final)
        object.__setattr__(self, "_tk_it", None)

    def __getattr__(self, name):
        return getattr(self._tk_inner, name)

    def __setattr__(self, name, value):
        setattr(self._tk_inner, name, value)

    def _item(self, item):
        self._tk_ex.chunk()
        try:
            self._tk_on(self._tk_ex, item)
        except Exception:
            pass
        return item

    def _end(self, error=None, abandoned=False):
        resp = None
        if self._tk_final and not error:
            try:
                resp = self._tk_final(self._tk_inner)
            except Exception:
                resp = None
        if resp is not None:
            self._tk_on_final(resp)
        self._tk_ex.finish(response=None, error=error, status=_status_of(error) if error else None, abandoned=abandoned)

    def _tk_on_final(self, resp):
        try:
            self._tk_on(self._tk_ex, resp)
        except Exception:
            pass

    # sync
    def __iter__(self):
        it = iter(self._tk_inner)
        object.__setattr__(self, "_tk_it", it)
        try:
            for item in it:
                yield self._item(item)
        except GeneratorExit:
            self._end(abandoned=True)
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
            self._end(abandoned=True)
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
        try:
            if not self._tk_ex.done:
                self._end(abandoned=True)
        except Exception:
            pass


class _ManagerProxy:
    """anthropic ``messages.stream(...)`` returns a context manager whose __enter__ yields the stream."""

    def __init__(self, inner, make_ex):
        self._inner, self._make_ex, self._proxy = inner, make_ex, None

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def _wrap(self, stream, ex):
        self._proxy = _StreamProxy(stream, ex, _anthropic_event)
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
                _anthropic_msg(p._tk_ex, snap)
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
    ("openai", "openai.resources.responses", "Responses", "create", "responses", False, _openai_responses, _openai_responses_event, "kwarg"),
    ("openai", "openai.resources.responses", "AsyncResponses", "create", "responses", True, _openai_responses, _openai_responses_event, "kwarg"),
    ("anthropic", "anthropic.resources.messages", "Messages", "create", "messages", False, _anthropic_msg, _anthropic_event, "kwarg"),
    ("anthropic", "anthropic.resources.messages", "AsyncMessages", "create", "messages", True, _anthropic_msg, _anthropic_event, "kwarg"),
    ("anthropic", "anthropic.resources.messages", "Messages", "stream", "messages", False, _anthropic_msg, _anthropic_event, "manager"),
    ("anthropic", "anthropic.resources.messages", "AsyncMessages", "stream", "messages", False, _anthropic_msg, _anthropic_event, "manager"),
    ("gemini", "google.genai.models", "Models", "generate_content", "generate_content", False, _gemini, _gemini, None),
    ("gemini", "google.genai.models", "AsyncModels", "generate_content", "generate_content", True, _gemini, _gemini, None),
    ("gemini", "google.genai.models", "Models", "generate_content_stream", "generate_content", False, _gemini, _gemini, "always"),
    ("gemini", "google.genai.models", "AsyncModels", "generate_content_stream", "generate_content", True, _gemini, _gemini, "always"),
]
PROVIDERS = ("openai", "anthropic", "gemini")


def _wrap(orig, provider, operation, is_async, on_resp, on_item, stream_kind):
    def make_ex(kwargs, streamed):
        t = _STATE["tracer"]
        if t is None or getattr(t, "_ended", False):
            return None
        ex = _Exchange(t, provider, operation, _model_kw(kwargs), kwargs, streamed)
        ex.begin()
        return ex

    if stream_kind == "manager":
        @functools.wraps(orig)
        def manager(self, *args, **kwargs):
            inner = orig(self, *args, **kwargs)
            if _STATE["tracer"] is None:
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
                return _StreamProxy(out, ex, on_item)
            try:
                on_resp(ex, out)
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
            return _StreamProxy(out, ex, on_item)
        try:
            on_resp(ex, out)
        except Exception:
            pass
        ex.finish(response=out)
        return out
    wrapper.__tracekit_wrapped__ = orig
    return wrapper


class _NullEx:
    done = True
    stop_reason = None

    def chunk(self):
        pass

    def finish(self, *a, **k):
        pass


def instrument(tracer, providers=PROVIDERS):
    """Patch the installed provider SDKs to record into ``tracer``. Returns the list of patched methods."""
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


def init(agent=None, session_id=None, providers=PROVIDERS, cwd=None):
    """Start a run and record every model call made through the installed provider SDKs. Idempotent: a second call
    returns the active tracer. The run ends at interpreter exit (or call ``tracer.end()`` / ``shutdown()``)."""
    from .agent_sdk import Tracer
    with _STATE["lock"]:
        t = _STATE["tracer"]
        if t is not None and not t._ended:
            return t
        name = agent or os.environ.get("TRACEKIT_AGENT") or os.path.splitext(os.path.basename(sys.argv[0] or "python"))[0] or "python"
        t = Tracer(agent=name, session_id=session_id, cwd=cwd)
        instrument(t, providers)
        atexit.register(_atexit, t)
        return t


def _atexit(t):
    try:
        if _STATE["tracer"] is t and not t._ended:
            t.end("process exit")
    except Exception:
        pass


def shutdown(reason="done"):
    with _STATE["lock"]:
        t = _STATE["tracer"]
        uninstrument()
        if t is not None and not t._ended:
            t.end(reason)
