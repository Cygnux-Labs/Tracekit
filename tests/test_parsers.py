"""L3 model-response parsers (tracekit/parsers.py) against the recorded shapes in tests/vectors/parsers/: each vector is
parsed as a plain dict and, when the provider SDK is installed, as the SDK's own typed objects; both must give
`expect`, and every tool use must be one the signer's model_event accepts."""
import glob
import importlib
import json
import os
import unittest

from tracekit import parsers
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


def _parse(kind, case, response=lambda d: d, item=lambda d: d):
    if "stream" not in case:
        return parsers.parse(kind, response(case["response"]), case["request"])
    s = parsers.Stream(kind)
    for chunk in case["stream"]:
        s.add(item(chunk))
    return s.parse(case["request"])


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


class Rules(unittest.TestCase):
    def test_provider_tools_carry_no_arguments(self):
        t = parsers.tool_use("ws_1", "web_search", '{"q": 1}', "raw", executed_by="provider")
        self.assertEqual(t, {"id": "ws_1", "name": "web_search", "executed_by": "provider"})

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
