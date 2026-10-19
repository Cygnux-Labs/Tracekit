"""L3 model-response parsers (tracekit/parsers.py) against the recorded shapes in tests/vectors/parsers/: each vector is
parsed as a plain dict and, when the provider SDK is installed, as the SDK's own typed objects; both must give
`expect` (and `said`, what the model said, where the vector has it), and every tool use must be one the signer's
model_event accepts."""
import glob
import importlib
import json
import os
import unittest

from tracekit import parsers
from tracekit.format.canon import event_hash
from tracekit.signer import rpc_schema

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors", "parsers")
# vector file -> (kind, response type, stream item type)
KINDS = {"openai_chat": ("openai:chat", "openai.types.chat:ChatCompletion", "openai.types.chat:ChatCompletionChunk"),
         "openai_responses": ("openai:responses", "openai.types.responses:Response",
                              "openai.types.responses:ResponseStreamEvent"),
         "anthropic_messages": ("anthropic:messages", "anthropic.types:Message", "anthropic.types:RawMessageStreamEvent"),
         "gemini_generate_content": ("gemini:generate_content", "google.genai.types:GenerateContentResponse",
                                     "google.genai.types:GenerateContentResponse")}


def _typed(path):
    """A function that validates a dict into the SDK type at `module:name`, or None when the SDK is not installed."""
    mod, name = path.split(":")
    try:
        from pydantic import TypeAdapter
        return TypeAdapter(getattr(importlib.import_module(mod), name)).validate_python
    except ImportError:
        return None


def _body(kind, case, response=lambda d: d, item=lambda d: d):
    """The response as parse reads it: the case's, or its stream accumulated."""
    if "stream" not in case:
        return response(case["response"])
    s = parsers.Stream(kind)
    for chunk in case["stream"]:
        s.add(item(chunk))
    return s.content()


def _parse(kind, case, response=lambda d: d, item=lambda d: d):
    return parsers.parse(kind, _body(kind, case, response, item), case["request"])


class Vectors(unittest.TestCase):
    def cases(self):
        files = sorted(glob.glob(os.path.join(VECTORS, "*.json")))
        self.assertEqual({os.path.basename(f)[:-5] for f in files}, set(KINDS))
        for f in files:
            kind, resp, item = KINDS[os.path.basename(f)[:-5]]
            with open(f, encoding="utf-8") as fh:
                for case in json.load(fh):
                    yield kind, resp, item, case

    def test_dicts(self):
        for kind, _, _, case in self.cases():
            with self.subTest(kind=kind, case=case["name"]):
                self.assertEqual(_parse(kind, case), case["expect"])

    def test_sdk_objects(self):
        for kind, resp, item, case in self.cases():
            response, chunk = _typed(resp), _typed(item)
            if response is None:
                continue
            with self.subTest(kind=kind, case=case["name"]):
                self.assertEqual(_parse(kind, case, response, chunk), case["expect"])

    def test_said(self):
        cases = [(k, r, i, c) for k, r, i, c in self.cases() if "said" in c]
        self.assertEqual({k for k, *_ in cases}, set(parsers.SAID))   # every provider has said vectors
        for kind, resp, item, case in cases:
            for typed in (False, True):
                response, chunk = (_typed(resp), _typed(item)) if typed else (lambda d: d, lambda d: d)
                if response is None:
                    continue
                with self.subTest(kind=kind, case=case["name"], typed=typed):
                    self.assertEqual(parsers.said(kind, _body(kind, case, response, chunk)), case["said"])

    def test_tool_uses_fit_the_rpc(self):
        schema = rpc_schema.REQUESTS["model_event"]["properties"]["tool_uses"]
        for kind, _, _, case in self.cases():
            self.assertEqual(rpc_schema.validate(schema, case["expect"]["tool_uses"]), [], case["name"])

    def test_every_case_kind_is_covered(self):
        uses = [t for _, _, _, c in self.cases() for t in c["expect"]["tool_uses"]]
        self.assertTrue(any(t.get("args_unparseable") for t in uses))
        self.assertTrue(any(t["executed_by"] == "provider" for t in uses))
        self.assertTrue(any(t.get("id_synthetic") for t in uses))
        self.assertTrue({"raw", "parsed"} <= {t.get("args_source") for t in uses})


class HostileStreams(unittest.TestCase):
    def test_an_index_an_upstream_names_allocates_nothing_and_odd_types_dont_raise(self):
        s = parsers.Stream("openai:chat")
        for chunk in ({"choices": [{"index": 2_000_000, "delta": {}}]}, {"choices": [{"index": -1}]},
                      {"choices": [{"index": "x"}]},
                      {"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": 5}}]}}]}):
            s.add(chunk)
        self.assertLessEqual(len(s.acc.get("choices", [])), 1)
        s.parse()
        a = parsers.Stream("anthropic:messages")
        for ev in ({"type": "content_block_start", "index": 10 ** 9, "content_block": {"type": "tool_use"}},
                   {"type": "content_block_delta", "index": 0, "delta": {"partial_json": 5}}):
            a.add(ev)
        self.assertLessEqual(len(a.acc.get("content", [])), 1)

    def test_a_gemini_stream_flipping_thought_every_chunk_keeps_a_bounded_number_of_parts(self):
        g = parsers.Stream("gemini:generate_content")
        for i in range(5000):   # each flip starts a part
            g.add({"candidates": [{"content": {"parts": [{"text": "g", "thought": bool(i % 2)}]}}]})
        body = g.content()
        self.assertEqual((len(body["candidates"][0]["content"]["parts"]), body["truncated"]), (parsers.MAX_INDEX, True))

    def test_streamed_arguments_accumulate_in_linear_time(self):
        import time
        piece = '"abcdefghijklmn",'
        for kind, start, delta in (
                ("openai:chat", {"choices": [{"index": 0, "delta": {"tool_calls": [
                    {"index": 0, "id": "c1", "function": {"name": "w", "arguments": "["}}]}}]},
                 lambda p: {"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": p}}]}}]}),
                ("anthropic:messages", {"type": "content_block_start", "index": 0,
                                        "content_block": {"type": "tool_use", "id": "t1", "name": "w", "input": {}}},
                 lambda p: {"type": "content_block_delta", "index": 0, "delta": {"partial_json": p}})):
            def took(n):   # the best of two, so a busy runner's pause isn't counted
                best = float("inf")
                for _ in range(2):
                    s, t0 = parsers.Stream(kind), time.perf_counter()
                    s.add(start)
                    for _ in range(n):
                        s.add(delta(piece))
                    s.parse()
                    best = min(best, time.perf_counter() - t0)
                return best

            with self.subTest(kind):   # 8x the pieces (1.7 MB in 17-byte pieces): 8x the time; appended to a str, 25x+
                self.assertLess(took(100_000), 16 * took(12_500))


class Reasoning(unittest.TestCase):
    def case(self, name):
        with open(os.path.join(VECTORS, "anthropic_messages.json"), encoding="utf-8") as f:
            return next(c for c in json.load(f) if c["name"].startswith(name))

    def test_a_stream_keeps_thinking_and_the_sealed_reasoning_byte_exact(self):
        case, plain = self.case("said, stream:"), self.case("said: a thinking")
        s = parsers.Stream("anthropic:messages")
        for ev in case["stream"]:
            s.add(ev)
        blocks = s.content()["content"]
        sig, red = plain["response"]["content"][0]["signature"], plain["response"]["content"][1]["data"]
        self.assertEqual([(b["type"], b.get("thinking"), b.get("signature"), b.get("data"), b.get("text"))
                          for b in blocks[:3]],
                         [("thinking", "Read pager.py, then fix the off-by-one.", sig, None, None),
                          ("redacted_thinking", None, None, red, None), ("text", None, None, None, "Reading pager.py.")])
        self.assertEqual(blocks[4]["signature"], sig)

    def test_text_past_max_text_is_dropped_and_marked_and_tool_uses_are_unchanged(self):
        start = {"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": ""}}
        s = parsers.Stream("anthropic:messages")
        s.add(start)
        for _ in range(3):
            s.add({"type": "content_block_delta", "index": 0,
                   "delta": {"type": "thinking_delta", "thinking": "x" * (parsers.MAX_TEXT // 2)}})
        s.add({"type": "content_block_start", "index": 1,
               "content_block": {"type": "tool_use", "id": "t1", "name": "Bash", "input": {}}})
        s.add({"type": "content_block_delta", "index": 1, "delta": {"partial_json": '{"command": "ls"}'}})
        body = s.content()
        self.assertEqual((len(body["content"][0]["thinking"]), body["truncated"]), (parsers.MAX_TEXT, True))
        self.assertEqual(s.parse()["tool_uses"], [parsers.tool_use("t1", "Bash", '{"command": "ls"}', "raw")])
        self.assertNotIn("\0left", body)
        json.dumps(body)   # the budget leaves nothing a body can't carry

    def test_said_reads_odd_shapes_without_raising(self):
        for kind in parsers.SAID:
            for resp in (None, {}, {"content": 5, "choices": [None], "output": [None], "candidates": [{"content": 1}]}):
                self.assertEqual(parsers.said(kind, resp), [], (kind, resp))


class Rules(unittest.TestCase):
    def test_provider_tools_carry_the_digest_of_the_input_the_provider_returned(self):
        t = parsers.tool_use("ws_1", "web_search", '{"q": 1}', "raw", executed_by="provider")
        self.assertEqual(t, {"id": "ws_1", "name": "web_search", "executed_by": "provider", "args_source": "raw",
                             "args_digest": event_hash({"tool": "web_search", "args": {"q": 1}})})
        bare = {"id": "ws_1", "name": "web_search", "executed_by": "provider"}
        for args in (None, '{"q": '):   # no input returned, or one that does not parse: no digest
            self.assertEqual(parsers.tool_use("ws_1", "web_search", args, "raw", executed_by="provider"), bare)

    def test_unparseable_raw_strings(self):
        for raw in ('{"a": ', '{"a": 1, "a": 2}', '{"n": NaN}', '{"id": 9007199254740993}', "", None):
            t = parsers.tool_use("c", "t", raw, "raw")
            self.assertEqual((t.get("args_unparseable"), "args_digest" in t), (True, False), raw)

    def test_parsed_values_that_are_not_canonical_json(self):
        self.assertTrue(parsers.tool_use("c", "t", {"n": float("nan")})["args_unparseable"])

    def test_ids_the_rpc_does_not_accept_become_digests(self):
        schema = rpc_schema.REQUESTS["model_event"]["properties"]
        for raw in ("call/1+2=", "a b", "x" * 129):
            out = parsers.parse("openai:chat", {"choices": [{"message": {"tool_calls": [
                {"id": raw, "type": "function", "function": {"name": "t", "arguments": "{}"}}]}}]},
                {"messages": [{"role": "tool", "tool_call_id": raw}]})
            self.assertEqual(out["tool_uses"][0]["id"], out["tool_results_sent"][0], raw)
            self.assertTrue(out["tool_results_sent"][0].startswith("sha256:"), raw)
            self.assertEqual(rpc_schema.validate(schema["tool_uses"], out["tool_uses"]), [], raw)
            self.assertEqual(rpc_schema.validate(schema["tool_results_sent"], out["tool_results_sent"]), [], raw)

    def test_hosted_shell_and_tool_search_are_run_by_the_provider(self):
        out = parsers.parse("openai:responses", {"id": "resp_1", "output": [
            {"type": "shell_call", "call_id": "sh_1", "action": {"commands": ["ls"]},
             "environment": {"type": "container_reference", "container_id": "c"}},
            {"type": "shell_call", "call_id": "sh_2", "action": {"commands": ["ls"]}},
            {"type": "tool_search_call", "call_id": "ts_1", "execution": "server", "arguments": {"q": "x"}},
            {"type": "tool_search_call", "call_id": "ts_2", "execution": "client", "arguments": {"q": "x"}}]})
        self.assertEqual([(t["id"], t["executed_by"]) for t in out["tool_uses"]],
                         [("sh_1", "provider"), ("sh_2", "client"), ("ts_1", "provider"), ("ts_2", "client")])

    def test_a_missing_call_id_gets_a_synthetic_one(self):
        out = parsers.parse("openai:responses", {"id": "resp_1", "output": [
            {"type": "function_call", "name": "t", "arguments": "{}"}]})
        self.assertEqual(out["tool_uses"][0]["id"], "openai:resp_1:0")
        self.assertTrue(out["tool_uses"][0]["id_synthetic"])
        resp = {"candidates": [{"content": {"parts": [{"function_call": {"name": "t", "args": {}}}]}}]}
        a, b = (parsers.parse("gemini:generate_content", resp)["tool_uses"][0]["id"] for _ in range(2))
        self.assertNotEqual(a, b)   # no response id: never the same synthetic id twice
        for kind, out in (("openai:responses", out),
                          ("gemini:generate_content", parsers.parse("gemini:generate_content", resp))):
            self.assertNotIn("None", [t["id"] for t in out["tool_uses"]])
            self.assertEqual(rpc_schema.validate(rpc_schema.REQUESTS["model_event"]["properties"]["tool_uses"],
                                                 out["tool_uses"]), [], kind)

    def test_streamed_chat_custom_tool_call(self):
        # the SDK's chunk type has no custom tool calls yet, so this shape is a dict only
        s = parsers.Stream("openai:chat")
        for part in ({"id": "call_c", "type": "custom", "custom": {"name": "apply_patch", "input": "*** Begin"}},
                     {"custom": {"input": " Patch"}}):
            s.add({"id": "chatcmpl-3", "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, **part}]}}]})
        self.assertEqual(s.parse()["tool_uses"], [parsers.tool_use("call_c", "apply_patch", "*** Begin Patch")])

    def test_raw_and_parsed_agree_on_strict_input(self):
        self.assertEqual(parsers.tool_use("c", "t", '{"b": [1, 2.0], "a": "x"}', "raw")["args_digest"],
                         parsers.tool_use("c", "t", {"a": "x", "b": [1, 2]})["args_digest"])


if __name__ == "__main__":
    unittest.main()
