#!/usr/bin/env python3
"""One line traces every model call: tracekit.init(). Runs offline: the real OpenAI, Anthropic and Google GenAI clients
talk to an in-process mock HTTP transport, so no key and no network are needed. In your code, drop the transport.
Each provider is skipped if its SDK isn't installed. Afterwards: `tracekit cost` and `tracekit verify` on the run."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import httpx  # noqa: E402

import tracekit  # noqa: E402

try:  # newer openai/anthropic releases ship on httpx2; google-genai stays on httpx
    import httpx2
except ImportError:
    httpx2 = httpx


def mock(body, stream=None, lib=httpx2):
    def handle(request):
        if stream:
            return lib.Response(200, headers={"content-type": "text/event-stream"}, content="".join(stream).encode())
        return lib.Response(200, json=body)
    return lib.Client(transport=lib.MockTransport(handle))


tracekit.init(agent="model-calls-example")   # <- the one line
done = []

try:
    import openai
except ImportError:
    openai = None
if openai:
    chat = {"id": "c1", "object": "chat.completion", "created": 1, "model": "gpt-4o-2026", "usage": {"prompt_tokens": 120, "completion_tokens": 9},
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "Paris"}}]}
    chunks = [{"id": "c2", "object": "chat.completion.chunk", "created": 1, "model": "gpt-4o-2026", "choices": [{"index": 0, "delta": {"content": t}}]}
              for t in ("Bon", "jour")] + [{"id": "c2", "object": "chat.completion.chunk", "created": 1, "model": "gpt-4o-2026", "choices": [],
                                             "usage": {"prompt_tokens": 8, "completion_tokens": 2}}]
    c = openai.OpenAI(api_key="sk-example", base_url="http://mock/v1", http_client=mock(chat), max_retries=0)
    print("openai   :", c.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "Capital of France?"}]).choices[0].message.content)
    s = openai.OpenAI(api_key="sk-example", base_url="http://mock/v1",
                      http_client=mock(None, [f"data: {json.dumps(x)}\n\n" for x in chunks] + ["data: [DONE]\n\n"]), max_retries=0)
    print("openai   :", "".join(ch.choices[0].delta.content or "" for ch in s.chat.completions.create(
        model="gpt-4o", messages=[], stream=True, stream_options={"include_usage": True}) if ch.choices), "(streamed: one entry)")
    done.append("openai")

try:
    import anthropic
except ImportError:
    anthropic = None
if anthropic:
    msg = {"id": "m1", "type": "message", "role": "assistant", "model": "claude-example-1", "stop_reason": "end_turn", "stop_sequence": None,
           "content": [{"type": "text", "text": "Hello"}], "usage": {"input_tokens": 12, "output_tokens": 3, "cache_read_input_tokens": 400}}
    a = anthropic.Anthropic(api_key="sk-example", base_url="http://mock", http_client=mock(msg), max_retries=0)
    print("anthropic:", a.messages.create(model="claude-example", max_tokens=16, messages=[{"role": "user", "content": "hi"}]).content[0].text)
    done.append("anthropic")

try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None
if genai:
    body = {"candidates": [{"content": {"role": "model", "parts": [{"text": "Hallo"}]}, "finishReason": "STOP"}],
            "modelVersion": "gemini-example-001", "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 2}}
    g = genai.Client(api_key="example", http_options=types.HttpOptions(base_url="http://mock", httpx_client=mock(body, lib=httpx)))
    print("gemini   :", g.models.generate_content(model="gemini-example", contents="hi").text)
    done.append("gemini")

tracekit.shutdown()
print("model calls example finished:", ", ".join(done) or "no provider SDK installed")
