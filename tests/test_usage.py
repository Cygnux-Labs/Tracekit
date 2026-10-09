"""Token usage and cost (#9): normalisation per provider, every capture path, export, `tracekit cost`.
python3 -m pytest tests/test_usage.py -q"""
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import autotrace, install, otlp, otlp_wire, schema, usage  # noqa: E402
from tracekit.otel import to_otlp_json  # noqa: E402
from tracekit.proxy import SSEScan  # noqa: E402

sys.path.insert(0, os.path.join(ROOT, "tests"))
import test_autotrace as T  # noqa: E402
import test_otlp as O  # noqa: E402


class Normalise(unittest.TestCase):
    def test_providers_agree_on_shape(self):
        self.assertEqual(usage.from_openai({"prompt_tokens": 100, "completion_tokens": 20, "prompt_tokens_details": {"cached_tokens": 60},
                                            "completion_tokens_details": {"reasoning_tokens": 5}}),
                         {"input_tokens": 40, "output_tokens": 20, "cache_read_tokens": 60, "cache_write_tokens": None, "reasoning_tokens": 5})
        self.assertEqual(usage.from_openai({"input_tokens": 10, "output_tokens": 3, "input_tokens_details": {"cached_tokens": 4}})["input_tokens"], 6)
        self.assertEqual(usage.from_anthropic({"input_tokens": 7, "output_tokens": 9, "cache_read_input_tokens": 100, "cache_creation_input_tokens": 50}),
                         {"input_tokens": 7, "output_tokens": 9, "cache_read_tokens": 100, "cache_write_tokens": 50, "reasoning_tokens": None})
        self.assertEqual(usage.from_gemini({"prompt_token_count": 30, "candidates_token_count": 8, "cached_content_token_count": 10,
                                            "thoughts_token_count": 2})["input_tokens"], 20)
        self.assertEqual(usage.from_otel({"gen_ai.usage.input_tokens": 12, "gen_ai.usage.output_tokens": 4})["output_tokens"], 4)
        self.assertEqual(usage.from_otel({"llm.token_count.prompt": 5, "llm.token_count.completion": 1})["input_tokens"], 5)

    def test_garbage_is_dropped_not_recorded(self):
        for bad in (None, {}, {"prompt_tokens": "lots"}, {"input_tokens": -5, "output_tokens": True}, {"input_tokens": 10 ** 15}):
            self.assertIsNone(usage.from_openai(bad) if bad is None or "prompt_tokens" in bad else usage.from_anthropic(bad), bad)

    def test_streaming_merge(self):
        start = usage.from_anthropic({"input_tokens": 50, "output_tokens": 1})
        end = usage.from_anthropic({"output_tokens": 30})
        self.assertEqual((usage.merge(start, end)["input_tokens"], usage.merge(start, end)["output_tokens"]), (50, 30))


class Capture(unittest.TestCase):
    @unittest.skipUnless(T.openai is not None and T.httpx is not None, "openai SDK not installed")
    def test_sdk_records_usage(self):
        t = T.FakeTracer()
        autotrace.instrument(t)
        try:
            c = T.openai.OpenAI(api_key="k", base_url="http://mock/v1", http_client=T.httpx.Client(transport=T.transport(lambda r: (200, T.OPENAI_CHAT, False))))
            c.chat.completions.create(model="m", messages=[])
            a = T.anthropic.Anthropic(api_key="k", base_url="http://mock", http_client=T.httpx.Client(transport=T.transport(lambda r: (200, T.sse(T.ANTHROPIC_EVENTS), True))))
            list(a.messages.create(model="c", max_tokens=5, messages=[], stream=True))
        finally:
            autotrace.uninstrument()
        resp = t.pairs()[1]
        self.assertEqual((resp[0]["usage"]["input_tokens"], resp[0]["usage"]["output_tokens"]), (10, 5))
        self.assertEqual((resp[1]["usage"]["input_tokens"], resp[1]["usage"]["output_tokens"]), (3, 4))  # start + final delta merged

    def test_proxy_scanner(self):
        s = SSEScan()
        for ev in T.ANTHROPIC_EVENTS:
            s.feed(f"data: {json.dumps(ev)}\n".encode())
        self.assertEqual((s.usage["input_tokens"], s.usage["output_tokens"]), (3, 4))

    def test_otel_ingest_and_schema(self):
        doc = O.payload(O.span("2222222222222222", "chat", {"gen_ai.operation.name": "chat", "gen_ai.request.model": "m",
                                                            "gen_ai.usage.input_tokens": 120, "gen_ai.usage.output_tokens": 30,
                                                            "gen_ai.usage.cache_read.input_tokens": 100}))
        items, _ = otlp.Mapper(cwd="/").plan(otlp_wire.decode(json.dumps(doc).encode(), "application/json")[0])
        resp = next(ev for _, ev, _, _ in items if ev["data"].get("phase") == "response")
        self.assertEqual(schema.validate(resp), [])
        self.assertEqual(resp["data"]["usage"], {"input_tokens": 20, "output_tokens": 30, "cache_read_tokens": 100,
                                                 "cache_write_tokens": None, "reasoning_tokens": None})
        bad = json.loads(json.dumps(resp))
        bad["data"]["usage"]["input_tokens"] = -1
        self.assertTrue(schema.validate(bad))

    def test_export_round_trips_semconv_totals(self):
        req = {"seq": 1, "id": "a" * 32, "ts": "2026-10-07T00:00:00.000000Z", "run_id": "r", "agent_id": "main", "source": "sdk",
               "type": "model.exchange", "data": {"exchange_id": "x", "phase": "request", "streamed": False}}
        resp = dict(req, seq=2, data={"exchange_id": "x", "phase": "response", "streamed": False, "upstream": "sdk:openai:chat",
                                      "usage": {"input_tokens": 20, "output_tokens": 30, "cache_read_tokens": 100}})
        spans = [s for rs in to_otlp_json([req, resp])["resourceSpans"] for ss in rs["scopeSpans"] for s in ss["spans"]]
        attrs = {a["key"]: a["value"] for s in spans for a in s["attributes"]}
        self.assertEqual(attrs["gen_ai.usage.input_tokens"], {"intValue": "120"})  # semconv: cached input is part of input
        self.assertEqual(usage.from_otel({"gen_ai.usage.input_tokens": 120, "gen_ai.usage.output_tokens": 30,
                                          "gen_ai.usage.cache_read.input_tokens": 100})["input_tokens"], 20)


class Cost(unittest.TestCase):
    def test_prices_match_and_never_guess(self):
        p = usage.Prices({"per": 1_000_000, "models": {"gpt-4o*": {"input": 2, "output": 10, "cache_read": 1}, "gpt-4o-mini*": {"input": 1, "output": 1}}})
        u = {"input_tokens": 1_000_000, "output_tokens": 100_000, "cache_read_tokens": 1_000_000}
        self.assertAlmostEqual(p.cost("gpt-4o-2024", u), 2 + 1 + 1)
        self.assertAlmostEqual(p.cost("gpt-4o-mini-x", {"input_tokens": 1_000_000, "output_tokens": 0}), 1)  # longest glob wins
        self.assertIsNone(p.cost("unknown-model", u))
        with self.assertRaises(ValueError):
            usage.Prices({"nope": 1})

    @unittest.skipUnless(T.openai is not None and T.httpx is not None, "openai SDK not installed")
    def test_cli_end_to_end(self):
        import subprocess
        d = tempfile.mkdtemp()
        old = os.environ.get("TRACEKIT_CLIENT_HOME")
        os.environ["TRACEKIT_CLIENT_HOME"] = os.path.join(d, "client")
        home = os.path.join(d, "signer")
        install.init_dev(home, [], start=True)
        try:
            import tracekit_sdk
            tracekit_sdk.init(agent="b", session_id="cost-1", cwd=d)
            c = T.openai.OpenAI(api_key="k", base_url="http://mock/v1", http_client=T.httpx.Client(transport=T.transport(lambda r: (200, T.OPENAI_CHAT, False))))
            for _ in range(3):
                c.chat.completions.create(model="gpt-4o", messages=[])
            tracekit_sdk.shutdown()
            prices = os.path.join(d, "p.json")
            json.dump({"models": {"gpt-4o*": {"input": 1000000, "output": 2000000}}}, open(prices, "w"))
            out = subprocess.run([sys.executable, "-m", "tracekit", "cost", "--home", home,
                                  "--prices", prices, "--format", "json"], capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(out.returncode, 0, out.stderr)
            row = json.loads(out.stdout)[0]
            self.assertEqual((row["run"], row["calls"], row["input"], row["output"], row["cost_usd"]), ("cost-1", 3, 30, 15, 60.0))
            # the observer shows the same cost, live or over an exported bundle (#9)
            from tracekit import bundle
            tkb, html = os.path.join(d, "c.tkb"), os.path.join(d, "c.html")
            bundle.export(home, tkb, run="cost-1")
            p = subprocess.run([sys.executable, "-m", "tracekit", "observe", "--bundle", tkb, "--prices", prices, "--export", html],
                               capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("verified", p.stderr)
            boot = json.loads(open(html, encoding="utf-8").read().split("const BOOT = ", 1)[1].split(";\n", 1)[0])
            self.assertEqual([r["cost"] for r in boot if r.get("event") == "tk_model"], [20.0, 20.0, 20.0])
        finally:
            install.stop_dev_daemon(home)
            if old is None:
                os.environ.pop("TRACEKIT_CLIENT_HOME", None)
            else:
                os.environ["TRACEKIT_CLIENT_HOME"] = old
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
