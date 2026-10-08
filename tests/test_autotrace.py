"""One-line auto-instrumentation of the OpenAI, Anthropic and Google Gen AI SDKs (issue #5).
The SDKs talk to in-process mock transports: no network, no API keys.  python3 -m pytest tests/test_autotrace.py -q"""
import asyncio
import gc
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import autotrace, client, install, schema  # noqa: E402
from tracekit.core import GENESIS, SCHEMA_VERSION, new_id, now_ts  # noqa: E402
from tracekit.ledger import read_records  # noqa: E402

try:
    import httpx2 as httpx
except ImportError:
    try:
        import httpx
    except ImportError:
        httpx = None
try:
    import openai
except ImportError:
    openai = None
try:
    import anthropic
except ImportError:
    anthropic = None
try:
    from google import genai
    from google.genai import types as gtypes
except ImportError:
    genai = None


class FakeTracer:
    def __init__(self, capture="hashed", down=False, fail_mode="open"):
        self._policy = {"content_capture": capture, "fail_mode": fail_mode}
        self._ended = False
        self.events = []
        self.down = down

    def _event(self, t, data):
        return {"schema_version": SCHEMA_VERSION, "id": new_id(), "seq": 0, "prev_hash": GENESIS, "ts": now_ts(), "run_id": "r",
                "agent_id": "main", "parent_id": None, "source": "sdk", "type": t, "data": data}

    def _send(self, ev, attach=None):
        if self.down:
            if self._policy["fail_mode"] == "closed":
                raise client.SignerUnavailable("down")
            return None
        errs = schema.validate(ev)
        assert not errs, errs
        self.events.append(ev)
        return {"ok": True}

    def end(self, reason="done"):
        self._ended = True

    def pairs(self):
        req = [e["data"] for e in self.events if e["data"]["phase"] == "request"]
        resp = [e["data"] for e in self.events if e["data"]["phase"] == "response"]
        return req, resp


def sse(events):
    return "".join(f"event: {e.get('type', 'message')}\ndata: {json.dumps(e)}\n\n" for e in events) if events and "type" in events[0] \
        else "".join(f"data: {json.dumps(e)}\n\n" for e in events) + "data: [DONE]\n\n"


OPENAI_CHAT = {"id": "c1", "object": "chat.completion", "created": 1, "model": "gpt-4o-2024", "choices": [{
    "index": 0, "finish_reason": "tool_calls", "message": {"role": "assistant", "content": None, "tool_calls": [
        {"id": "call_a", "type": "function", "function": {"name": "Bash", "arguments": "{\"command\": \"ls\"}"}}]}}],
    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}
OPENAI_CHUNKS = [
    {"id": "c2", "object": "chat.completion.chunk", "created": 1, "model": "gpt-4o-2024", "choices": [{"index": 0, "delta": {"role": "assistant", "content": "Hel"}}]},
    {"id": "c2", "object": "chat.completion.chunk", "created": 1, "model": "gpt-4o-2024", "choices": [{"index": 0, "delta": {"content": "lo"}}]},
    {"id": "c2", "object": "chat.completion.chunk", "created": 1, "model": "gpt-4o-2024", "choices": [{"index": 0, "delta": {"tool_calls": [
        {"index": 0, "id": "call_s", "type": "function", "function": {"name": "Read", "arguments": ""}}]}}]},
    {"id": "c2", "object": "chat.completion.chunk", "created": 1, "model": "gpt-4o-2024", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}]
ANTHROPIC_MSG = {"id": "m1", "type": "message", "role": "assistant", "model": "claude-x-1", "stop_reason": "tool_use", "stop_sequence": None,
                 "content": [{"type": "text", "text": "ok"}, {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": "pwd"}}],
                 "usage": {"input_tokens": 3, "output_tokens": 4}}
ANTHROPIC_EVENTS = [
    {"type": "message_start", "message": {**ANTHROPIC_MSG, "content": [], "stop_reason": None}},
    {"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "toolu_s", "name": "Grep", "input": {}}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": "{}"}},
    {"type": "content_block_stop", "index": 0},
    {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None}, "usage": {"output_tokens": 4}},
    {"type": "message_stop"}]


def transport(handler):
    def h(request):
        status, body, stream = handler(request)
        if stream:
            return httpx.Response(status, headers={"content-type": "text/event-stream"}, content=body.encode())
        return httpx.Response(status, json=body)
    return httpx.MockTransport(h)


@unittest.skipUnless(httpx is not None, "httpx not installed")
class Base(unittest.TestCase):
    providers = autotrace.PROVIDERS

    def setUp(self):
        self.t = FakeTracer()
        autotrace.instrument(self.t, self.providers)

    def tearDown(self):
        autotrace.uninstrument()


@unittest.skipUnless(openai is not None, "openai not installed")
class OpenAI(Base):
    def client(self, handler, cls=None):
        cls = cls or openai.OpenAI
        http = (httpx.AsyncClient if cls is openai.AsyncOpenAI else httpx.Client)(transport=transport(handler))
        return cls(api_key="sk-test-key-not-real", base_url="http://mock/v1", http_client=http, max_retries=0)

    def test_chat_completion(self):
        c = self.client(lambda r: (200, OPENAI_CHAT, False))
        out = c.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "list files"}], tools=[])
        self.assertEqual(out.choices[0].finish_reason, "tool_calls")  # the SDK's return value is untouched
        (req,), (resp,) = self.t.pairs()
        self.assertEqual((req["model"], req["streamed"], req["upstream"]), ("gpt-4o", False, "sdk:openai:chat"))
        self.assertTrue(req["request"]["hash"].startswith("sha256:"))
        self.assertEqual((resp["model"], resp["stop_reason"], resp["status"]), ("gpt-4o-2024", "tool_calls", 200))
        self.assertEqual(resp["tool_uses"], [{"id": "call_a", "name": "Bash"}])
        self.assertEqual(req["exchange_id"], resp["exchange_id"])

    def test_streaming(self):
        c = self.client(lambda r: (200, sse(OPENAI_CHUNKS), True))
        stream = c.chat.completions.create(model="gpt-4o", messages=[], stream=True)
        text = "".join(ch.choices[0].delta.content or "" for ch in stream)
        self.assertEqual(text, "Hello")
        (_,), (resp,) = self.t.pairs()
        self.assertTrue(resp["streamed"])
        self.assertEqual(resp["tool_uses"], [{"id": "call_s", "name": "Read"}])
        self.assertEqual(resp["stop_reason"], "tool_calls")
        self.assertIsNotNone(resp["first_byte_ms"])

    def test_streaming_with_context_manager_and_break(self):
        c = self.client(lambda r: (200, sse(OPENAI_CHUNKS), True))
        with c.chat.completions.create(model="gpt-4o", messages=[], stream=True) as stream:
            for ch in stream:
                break
        (_,), (resp,) = self.t.pairs()
        self.assertIn("abandoned", resp["error"])

    def test_http_error_is_recorded_and_reraised(self):
        c = self.client(lambda r: (429, {"error": {"message": "slow down", "type": "rate_limit"}}, False))
        with self.assertRaises(openai.RateLimitError):
            c.chat.completions.create(model="gpt-4o", messages=[])
        (_,), (resp,) = self.t.pairs()
        self.assertEqual(resp["status"], 429)
        self.assertIn("RateLimitError", resp["error"])

    def test_async_and_async_stream(self):
        async def go():
            c = self.client(lambda r: (200, OPENAI_CHAT, False), openai.AsyncOpenAI)
            await c.chat.completions.create(model="gpt-4o", messages=[])
            c2 = self.client(lambda r: (200, sse(OPENAI_CHUNKS), True), openai.AsyncOpenAI)
            s = await c2.chat.completions.create(model="gpt-4o", messages=[], stream=True)
            return [ch async for ch in s]
        chunks = asyncio.run(go())
        self.assertEqual(len(chunks), 4)
        req, resp = self.t.pairs()
        self.assertEqual([r["streamed"] for r in resp], [False, True])
        self.assertEqual(resp[1]["tool_uses"], [{"id": "call_s", "name": "Read"}])

    def test_api_key_never_recorded_even_in_full_capture(self):
        self.t._policy["content_capture"] = "full"
        c = self.client(lambda r: (200, OPENAI_CHAT, False))
        c.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "my key is sk-ant-abcdefghijklmnopqrstuvwx"}],
                                  extra_headers={"Authorization": "Bearer sk-test-key-not-real"})
        blob = json.dumps(self.t.events)
        self.assertNotIn("sk-test-key-not-real", blob)
        self.assertNotIn("sk-ant-abcdefghijklmnopqrstuvwx", blob)
        self.assertIn("[REDACTED:anthropic_key]", blob)


@unittest.skipUnless(anthropic is not None, "anthropic not installed")
class Anthropic(Base):
    def client(self, handler, cls=None):
        cls = cls or anthropic.Anthropic
        http = (httpx.AsyncClient if cls is anthropic.AsyncAnthropic else httpx.Client)(transport=transport(handler))
        return cls(api_key="test", base_url="http://mock", http_client=http, max_retries=0)

    def test_create(self):
        c = self.client(lambda r: (200, ANTHROPIC_MSG, False))
        out = c.messages.create(model="claude-x", max_tokens=10, messages=[{"role": "user", "content": "hi"}])
        self.assertEqual(out.stop_reason, "tool_use")
        (req,), (resp,) = self.t.pairs()
        self.assertEqual((resp["model"], resp["stop_reason"], resp["tool_uses"]), ("claude-x-1", "tool_use", [{"id": "toolu_1", "name": "Bash"}]))

    def test_create_stream_true(self):
        c = self.client(lambda r: (200, sse(ANTHROPIC_EVENTS), True))
        evs = list(c.messages.create(model="claude-x", max_tokens=10, messages=[], stream=True))
        self.assertEqual(len(evs), 6)
        (_,), (resp,) = self.t.pairs()
        self.assertEqual((resp["stop_reason"], resp["tool_uses"]), ("tool_use", [{"id": "toolu_s", "name": "Grep"}]))

    def test_messages_stream_manager_get_final_message(self):
        c = self.client(lambda r: (200, sse(ANTHROPIC_EVENTS), True))
        with c.messages.stream(model="claude-x", max_tokens=10, messages=[]) as s:
            msg = s.get_final_message()
        self.assertEqual(msg.stop_reason, "tool_use")
        (_,), (resp,) = self.t.pairs()
        self.assertEqual((resp["stop_reason"], resp["tool_uses"], resp["error"]), ("tool_use", [{"id": "toolu_s", "name": "Grep"}], None))

    def test_async_stream_manager(self):
        async def go():
            c = self.client(lambda r: (200, sse(ANTHROPIC_EVENTS), True), anthropic.AsyncAnthropic)
            async with c.messages.stream(model="claude-x", max_tokens=10, messages=[]) as s:
                return [e async for e in s]
        self.assertTrue(asyncio.run(go()))
        (_,), (resp,) = self.t.pairs()
        self.assertEqual(resp["stop_reason"], "tool_use")


@unittest.skipUnless(genai is not None, "google-genai not installed")
class Gemini(Base):
    RESP = {"candidates": [{"content": {"role": "model", "parts": [{"text": "hi"}, {"function_call": {"id": "g1", "name": "search", "args": {}}}]},
                            "finish_reason": "STOP"}], "model_version": "gemini-x-001"}

    def test_generate_content_sync_async_and_stream(self):
        from google.genai import models
        resp = gtypes.GenerateContentResponse.model_validate(self.RESP)
        saved = (models.Models._generate_content, models.AsyncModels._generate_content,
                 models.Models._generate_content_stream)

        async def agen(self, **kw):
            return resp

        def gen_stream(self, **kw):
            yield resp
            yield resp
        models.Models._generate_content = lambda self, **kw: resp
        models.AsyncModels._generate_content = agen
        models.Models._generate_content_stream = gen_stream
        try:
            c = genai.Client(api_key="test")
            c.models.generate_content(model="gemini-x", contents="hi")
            asyncio.run(c.aio.models.generate_content(model="gemini-x", contents="hi"))
            list(c.models.generate_content_stream(model="gemini-x", contents="hi"))
        finally:
            models.Models._generate_content, models.AsyncModels._generate_content, models.Models._generate_content_stream = saved
        req, out = self.t.pairs()
        self.assertEqual(len(req), 3)
        for r in out:
            self.assertEqual((r["model"], r["stop_reason"], r["tool_uses"]), ("gemini-x-001", "STOP", [{"id": "g1", "name": "search"}]))
        self.assertEqual([r["streamed"] for r in out], [False, False, True])


@unittest.skipUnless(openai is not None and httpx is not None, "openai not installed")
class Lifecycle(unittest.TestCase):
    def tearDown(self):
        autotrace.uninstrument()

    def test_idempotent_patch_and_clean_restore(self):
        from openai.resources.chat.completions import Completions
        orig = Completions.create
        t = FakeTracer()
        autotrace.instrument(t)
        once = Completions.create
        autotrace.instrument(t)
        self.assertIs(Completions.create, once)
        autotrace.uninstrument()
        self.assertIs(Completions.create, orig)

    def test_recording_failure_never_breaks_the_call(self):
        t = FakeTracer(down=True)
        autotrace.instrument(t)
        c = openai.OpenAI(api_key="k", base_url="http://mock/v1", http_client=httpx.Client(transport=transport(lambda r: (200, OPENAI_CHAT, False))))
        self.assertEqual(c.chat.completions.create(model="m", messages=[]).id, "c1")

    def test_fail_closed_refuses_unrecorded_calls_before_sending(self):
        t = FakeTracer(down=True, fail_mode="closed")
        autotrace.instrument(t)
        sent = []
        c = openai.OpenAI(api_key="k", base_url="http://mock/v1", max_retries=0,
                          http_client=httpx.Client(transport=transport(lambda r: (sent.append(1), (200, OPENAI_CHAT, False))[1])))
        with self.assertRaises(PermissionError):
            c.chat.completions.create(model="m", messages=[])
        self.assertEqual(sent, [], "the request must never reach the provider")

    def test_abandoned_stream_is_recorded_on_gc(self):
        t = FakeTracer()
        autotrace.instrument(t)
        c = openai.OpenAI(api_key="k", base_url="http://mock/v1", http_client=httpx.Client(transport=transport(lambda r: (200, sse(OPENAI_CHUNKS), True))))
        s = c.chat.completions.create(model="m", messages=[], stream=True)
        del s
        gc.collect()
        autotrace.flush()  # queued by __del__, recorded at the next call, shutdown or exit
        self.assertEqual(len(t.pairs()[1]), 1)
        self.assertIn("abandoned", t.pairs()[1][0]["error"])

    def test_no_tracer_means_no_overhead_path(self):
        autotrace.uninstrument()
        from openai.resources.chat.completions import Completions
        self.assertIsNone(getattr(Completions.create, "__tracekit_wrapped__", None))


@unittest.skipUnless(openai is not None and httpx is not None, "openai not installed")
class Signed(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.home = os.path.join(self.d, "signer")
        self.old = os.environ.get("TRACEKIT_CLIENT_HOME")
        os.environ["TRACEKIT_CLIENT_HOME"] = os.path.join(self.d, "client")
        install.init_dev(self.home, [], start=True)

    def tearDown(self):
        autotrace.shutdown()
        install.stop_dev_daemon(self.home)
        if self.old is None:
            os.environ.pop("TRACEKIT_CLIENT_HOME", None)
        else:
            os.environ["TRACEKIT_CLIENT_HOME"] = self.old
        shutil.rmtree(self.d, ignore_errors=True)

    def test_init_records_a_signed_run_and_links_tool_execution(self):
        import tracekit_sdk
        t = tracekit_sdk.init(agent="mock-bot", session_id="auto-1", cwd=self.d)
        self.assertIs(tracekit_sdk.init(), t)
        import tracekit
        self.assertIs(tracekit.init(), t)  # the documented `tracekit.init()` is the same entry point
        c = openai.OpenAI(api_key="k", base_url="http://mock/v1", http_client=httpx.Client(transport=transport(lambda r: (200, OPENAI_CHAT, False))))
        out = c.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "ls"}])
        call = out.choices[0].message.tool_calls[0]
        with t.tool("Bash", json.loads(call.function.arguments), tool_use_id=call.id) as tc:
            tc.result("a.txt")
        tracekit_sdk.shutdown()
        evs = [r["event"] for _, r, _ in read_records(os.path.join(self.home, "ledger", "ledger.jsonl")) if r and not r.get("elided")]
        mine = [e for e in evs if e["run_id"] == "auto-1"]
        self.assertEqual([e["type"] for e in mine], ["run.start", "model.exchange", "model.exchange", "tool.call", "policy.decision",
                                                     "tool.result", "run.end"])
        resp = mine[2]["data"]
        self.assertEqual(resp["tool_uses"][0]["id"], mine[3]["data"]["tool_use_id"], "model request and execution share one id")
        self.assertFalse([e for e in evs if e["type"] == "capture.gap"])


if __name__ == "__main__":
    unittest.main()
