"""What the model said before its tool calls, as Tracekit's integrations and agent hooks record it (docs/reasoning.md).

An integration lists one model message as items, in order: `thought(...)` for the model's reasoning, `text(...)` for
what it wrote, `call(...)` for each tool call it asked for. `Said` sends the message as one model_event response:

- `tool_uses`: the calls, under the ids the integration decides them by, so `tracekit analyze --v2` finds what the
  model said before each call and the signer's reconciliation pairs each with its decision (a call without an id gets
  a synthetic one, which pairs by its arguments only);
- `content_digest`: the digest of the message written as an OpenAI Responses `output`, which parsers.said reads: a
  reasoning item's `summary` for reasoning text (what most providers return), its `content` when the text is the
  model's own full reasoning, its `encrypted_content` for the provider's sealed form (a signature, redacted or
  encrypted reasoning) kept byte for byte; a message item for text; a function_call item per call. `source` (an agent
  transcript or hook payload the record was read from) goes in the message too;
- `body`: the message, when the signer keeps content (VaultBody); without the vault the text stays where it came from.

An empty message is not sent. `Said` never raises: a message it could not record warns, and the agent goes on.
"""
import base64
import warnings

from tracekit import parsers
from tracekit.format.canon import canonical, event_hash
from tracekit.sdk.client import VaultBody


def thought(text=None, sealed=None, full=False):
    """The model's reasoning: `text` as it came back (None or "": none came back), `sealed` the provider's sealed form
    (str, or bytes kept as base64), `full` when `text` is the model's own reasoning, not a summary of it."""
    item = {"type": "reasoning", "summary": []}
    if text:
        item["content" if full else "summary"] = [{"type": "reasoning_text" if full else "summary_text", "text": text}]
    if isinstance(sealed, (bytes, bytearray)):
        sealed = base64.b64encode(sealed).decode()
    if sealed:
        item["encrypted_content"] = sealed
    return item


def text(t):
    """What the model wrote, as items: an open model's inline `<think>...</think>` at its start is its full reasoning."""
    s = t.lstrip() if isinstance(t, str) else ""
    if s.startswith("<think>") and "</think>" in s:
        think, _, rest = s[len("<think>"):].partition("</think>")
        return [thought(think.strip(), full=True), *text(rest)]
    return [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": t}]}] if s else []


def call(id, name, args):
    """A tool call the model asked for: `id` the one the integration decides it under (None: it has none), `args` as
    the model sent them (its JSON text) or as the integration parsed them."""
    return {"type": "function_call", "call_id": id or None, "name": name,
            "arguments": args if isinstance(args, str) else canonical(args).decode()}


class Said:
    """`send(**fields)` sends a model_event (the integration's stream and client_seq); `status()` is the signer's
    status answer (VaultBody). Call it with a message's items (an iterable, read inside its own guard, so a generator
    that fails reading the framework's message only warns); it blocks on the signer, so async code runs it in a
    thread."""

    def __init__(self, send, status):
        self.send, self.vault = send, VaultBody(status)

    def __call__(self, items, model=None, provider=None, source=None):
        try:
            output = [i for x in items for i in (x if isinstance(x, list) else [x]) if i]
            if not output:
                return
            body = {"output": output, **({"source": source} if source else {})}
            uses = parsers.parse("openai:responses", body)["tool_uses"]
            # lean: the RPC's cap; send the rest in a second model_event if messages ever carry more
            self.send(provider=str(provider or "unknown")[:64], model=str(model or "unknown")[:128], phase="response",
                      content_digest=event_hash(body), **self.vault(body), **({"tool_uses": uses[:128]} if uses else {}))
        except Exception as e:
            warnings.warn(f"tracekit: what the model said was not recorded: {type(e).__name__}: {e}", stacklevel=2)
