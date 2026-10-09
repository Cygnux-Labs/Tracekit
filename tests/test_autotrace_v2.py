"""Autotrace into v2 runs (tracekit/autotrace.py with tracekit.sdk.client run handles): each provider SDK, sync, async
and streaming, against FakeSigner and the real signer served in this process; the SDKs talk to mock transports."""
import asyncio
import gc
import json
import os
import threading
import unittest

from adapter_contract import OnFake, OnReal
from test_autotrace import ANTHROPIC_EVENTS, ANTHROPIC_MSG, OPENAI_CHAT, OPENAI_CHUNKS, anthropic, genai, gtypes, httpx, \
    openai, sse, transport
from tracekit import autotrace
from tracekit.sdk.client import Client, RunHandle

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors", "parsers")


def vector(name, i):
    with open(os.path.join(VECTORS, name + ".json"), encoding="utf-8") as f:
        return json.load(f)[i]


RESPONSES = vector("openai_responses", 0)
RESPONSES_STREAM = vector("openai_responses", 1)
TOOL_RESULT = [{"role": "user", "content": "ls"},
               {"role": "assistant", "tool_calls": [{"id": "call_prev", "type": "function",
                                                     "function": {"name": "Bash", "arguments": "{}"}}]},
               {"role": "tool", "tool_call_id": "call_prev", "content": "a.txt"}]


def openai_client(handler, cls=None):
    cls = cls or openai.OpenAI
    http = (httpx.AsyncClient if cls is openai.AsyncOpenAI else httpx.Client)(transport=transport(handler))
    return cls(api_key="k", base_url="http://mock/v1", http_client=http, max_retries=0)


def anthropic_client(handler, cls=None):
    cls = cls or anthropic.Anthropic
    http = (httpx.AsyncClient if cls is anthropic.AsyncAnthropic else httpx.Client)(transport=transport(handler))
    return cls(api_key="k", base_url="http://mock", http_client=http, max_retries=0)


@unittest.skipUnless(httpx is not None and openai is not None and anthropic is not None, "provider SDKs not installed")
class Recording:
    def setUp(self):
        self.client = Client(self.serve_signer())
        self.addCleanup(self.client.close)
        self.run = self.client.run("autotrace")
        self.assertIs(autotrace.init(run=self.run), self.run)
        self.addCleanup(autotrace._LATE.clear)
        self.addCleanup(autotrace.uninstrument)

    def exchanges(self, run=None):
        """[(request data, response data)] of `run`, paired by exchange_id."""
        run = run or self.run
        evs = [e["data"] for e in self.events({"run_id": run.run_id, "run_token": run.run_token})
               if e["type"] in ("model.exchange", "model.event")]
        reqs = [d for d in evs if d["phase"] == "request"]
        resps = {d["exchange_id"]: d for d in evs if d["phase"] == "response"}
        return [(r, resps.get(r["exchange_id"])) for r in reqs]

    def one(self):
        [(req, resp)] = self.exchanges()
        return req, resp

    def ids(self, resp):
        return [(t["id"], t["executed_by"]) for t in resp.get("tool_uses", [])]

    # --- OpenAI ---

    def test_chat_create_sends_results_and_reads_tool_calls(self):
        out = openai_client(lambda r: (200, OPENAI_CHAT, False)).chat.completions.create(model="gpt-4o",
                                                                                         messages=TOOL_RESULT)
        self.assertEqual(out.choices[0].message.tool_calls[0].id, "call_a")   # the SDK's return value is untouched
        req, resp = self.one()
        self.assertEqual((req["tool_results_sent"], req["streamed"]), (["call_prev"], False))
        self.assertEqual((resp["stop_reason"], self.ids(resp)), ("tool_calls", [("call_a", "client")]))
        self.assertEqual(resp["tool_results_sent"], ["call_prev"])

    def test_chat_parse(self):
        openai_client(lambda r: (200, OPENAI_CHAT, False)).chat.completions.parse(model="gpt-4o", messages=[])
        self.assertEqual(self.ids(self.one()[1]), [("call_a", "client")])

    def test_chat_stream_and_stream_manager(self):
        c = openai_client(lambda r: (200, sse(OPENAI_CHUNKS), True))
        self.assertEqual(len(list(c.chat.completions.create(model="m", messages=[], stream=True))), 4)
        with c.chat.completions.stream(model="m", messages=[]) as s:
            s.until_done()
        for req, resp in self.exchanges():
            self.assertEqual((req["streamed"], resp["stop_reason"], self.ids(resp)),
                             (True, "tool_calls", [("call_s", "client")]))

    def test_chat_async_and_async_stream(self):
        async def go():
            c = openai_client(lambda r: (200, sse(OPENAI_CHUNKS), True), openai.AsyncOpenAI)
            s = await c.chat.completions.create(model="m", messages=[], stream=True)
            return [ch async for ch in s]
        self.assertEqual(len(asyncio.run(go())), 4)
        self.assertEqual(self.ids(self.one()[1]), [("call_s", "client")])

    def test_responses_create_and_stream(self):
        c = openai_client(lambda r: (200, RESPONSES["response"], False))
        c.responses.create(model="gpt-5", input=RESPONSES["request"]["input"])
        c = openai_client(lambda r: (200, sse(RESPONSES_STREAM["stream"]), True))
        with c.responses.stream(model="gpt-5", input="weather?") as s:
            s.until_done()
        (req, resp), (_, streamed) = self.exchanges()
        self.assertEqual(req["tool_results_sent"], ["call_prev", "call_prev2", "call_prev3"])
        self.assertEqual(self.ids(resp), [(t["id"], t["executed_by"]) for t in RESPONSES["expect"]["tool_uses"]])
        self.assertEqual([t.get("args_unparseable") for t in resp["tool_uses"]][:2], [None, True])
        self.assertEqual((streamed["streamed"], self.ids(streamed)), (True, [("call_s", "client")]))

    def test_responses_parse_sync_and_async(self):
        openai_client(lambda r: (200, RESPONSES["response"], False)).responses.parse(model="gpt-5", input="hi")
        asyncio.run(openai_client(lambda r: (200, RESPONSES["response"], False), openai.AsyncOpenAI)
                    .responses.parse(model="gpt-5", input="hi"))
        want = [(t["id"], t["executed_by"]) for t in RESPONSES["expect"]["tool_uses"]]
        self.assertEqual([self.ids(resp) for _, resp in self.exchanges()], [want, want])

    # --- Anthropic ---

    def test_messages_create_and_stream_true(self):
        c = anthropic_client(lambda r: (200, ANTHROPIC_MSG, False))
        c.messages.create(model="claude-x", max_tokens=10, messages=[])
        c = anthropic_client(lambda r: (200, sse(ANTHROPIC_EVENTS), True))
        self.assertEqual(len(list(c.messages.create(model="claude-x", max_tokens=10, messages=[], stream=True))), 6)
        (_, plain), (_, streamed) = self.exchanges()
        self.assertEqual([t["args_source"] for t in plain["tool_uses"]], ["parsed"])
        self.assertEqual([t["args_source"] for t in streamed["tool_uses"]], ["raw"])   # the streamed JSON string
        self.assertEqual(streamed["stop_reason"], "tool_use")

    def test_messages_stream_manager_sync_and_async(self):
        c = anthropic_client(lambda r: (200, sse(ANTHROPIC_EVENTS), True))
        with c.messages.stream(model="claude-x", max_tokens=10, messages=[]) as s:
            self.assertEqual(s.get_final_message().stop_reason, "tool_use")

        async def go():
            ac = anthropic_client(lambda r: (200, sse(ANTHROPIC_EVENTS), True), anthropic.AsyncAnthropic)
            async with ac.messages.stream(model="claude-x", max_tokens=10, messages=[]) as s:
                return [e async for e in s]
        self.assertTrue(asyncio.run(go()))
        for _, resp in self.exchanges():
            self.assertEqual((resp["stop_reason"], self.ids(resp), resp.get("error")),
                             ("tool_use", [("toolu_s", "client")], None))

    def test_messages_parse(self):
        anthropic_client(lambda r: (200, ANTHROPIC_MSG, False)).messages.parse(model="claude-x", max_tokens=10,
                                                                               messages=[])
        self.assertEqual(self.ids(self.one()[1]), [("toolu_1", "client")])

    # --- Google Gen AI ---

    @unittest.skipUnless(genai is not None, "google-genai not installed")
    def test_generate_content_sync_async_and_stream(self):
        from google.genai import models
        resp = gtypes.GenerateContentResponse.model_validate(vector("gemini_generate_content", 0)["response"])

        async def agen(self, **kw):
            return resp

        def gen_stream(self, **kw):
            yield resp
        saved = (models.Models._generate_content, models.AsyncModels._generate_content,
                 models.Models._generate_content_stream)
        models.Models._generate_content = lambda self, **kw: resp
        models.AsyncModels._generate_content = agen
        models.Models._generate_content_stream = gen_stream
        try:
            c = genai.Client(api_key="test")
            c.models.generate_content(model="g", contents="hi")
            asyncio.run(c.aio.models.generate_content(model="g", contents="hi"))
            list(c.models.generate_content_stream(model="g", contents="hi"))
        finally:
            models.Models._generate_content, models.AsyncModels._generate_content, \
                models.Models._generate_content_stream = saved
        out = self.exchanges()
        self.assertEqual([r["streamed"] for _, r in out], [False, False, True])
        for _, r in out:
            self.assertEqual(self.ids(r), [("fc-1", "client"), ("gemini:r-1:1", "client")])
            self.assertEqual(r["tool_uses"][1]["id_synthetic"], True)

    # --- lifecycle ---

    def test_errors_are_reraised_and_recorded(self):
        c = openai_client(lambda r: (500, {"error": {"message": "boom"}}, False))
        with self.assertRaises(openai.InternalServerError):
            c.chat.completions.create(model="m", messages=[])
        self.assertIn("InternalServerError", self.one()[1]["error"])

    def test_abandoned_stream_is_recorded_at_the_next_call(self):
        c = openai_client(lambda r: (200, sse(OPENAI_CHUNKS), True))
        s = c.chat.completions.create(model="m", messages=[], stream=True)
        next(iter(s))
        del s
        gc.collect()
        c.chat.completions.create(model="m", messages=[], stream=True).close()
        self.assertIn("abandoned", self.exchanges()[0][1]["error"])

    def test_runs_in_two_threads_do_not_mix(self):
        c, runs, errors = openai_client(lambda r: (200, OPENAI_CHAT, False)), {}, []

        def work(name):
            try:
                with self.client.run(name) as run:
                    for _ in range(5):
                        c.chat.completions.create(model=name, messages=[])
                    runs[name] = run
            except Exception as e:   # pragma: no cover - reported below
                errors.append(e)
        threads = [threading.Thread(target=work, args=(n,)) for n in ("model-a", "model-b")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        for name, run in runs.items():
            self.assertEqual([req["model"] for req, _ in self.exchanges(run)], [name] * 5)
        self.assertEqual(self.exchanges(), [], "calls inside another run's block never reach the default run")

    def test_closed_run_refuses_under_fail_closed(self):
        sent = []
        c = openai_client(lambda r: (sent.append(1), (200, OPENAI_CHAT, False))[1])
        self.run.close()
        with self.assertRaises(PermissionError):
            c.chat.completions.create(model="m", messages=[])
        self.assertEqual(sent, [])


class TestOnFake(OnFake, Recording, unittest.TestCase):
    pass


class TestOnReal(OnReal, Recording, unittest.TestCase):
    pass


@unittest.skipUnless(httpx is not None and openai is not None, "openai not installed")
class FailMode(unittest.TestCase):
    """The run's fail mode for model calls, when the signer cannot be reached."""

    def call(self, fail_modes):
        run = RunHandle(Client(signer="/nonexistent/tracekit.sock"), {"run_id": "r", "run_token": "t",
                                                                      "fail_modes": fail_modes})
        autotrace.init(run=run)
        self.addCleanup(autotrace.uninstrument)
        sent = []
        c = openai_client(lambda r: (sent.append(1), (200, OPENAI_CHAT, False))[1])
        try:
            return c.chat.completions.create(model="m", messages=[]).id, sent
        except PermissionError:
            return None, sent

    def test_closed_refuses_before_sending(self):
        self.assertEqual(self.call({"default": "closed"}), (None, []))

    def test_model_class_overrides_default(self):
        self.assertEqual(self.call({"default": "closed", "model": "open"}), ("c1", [1]))
        self.assertEqual(self.call({"default": "open", "model": "closed"}), (None, []))


if __name__ == "__main__":
    unittest.main()
