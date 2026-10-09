"""Token usage, normalised across providers, and cost from a user-supplied price table.

Recorded on ``model.exchange`` responses as::

    "usage": {"input_tokens": int, "output_tokens": int, "cache_read_tokens": int|null,
              "cache_write_tokens": int|null, "reasoning_tokens": int|null}

``input_tokens`` counts input that was not served from cache, so the four input/output buckets add up without double
counting (OpenAI reports cached tokens inside prompt_tokens; Anthropic reports them separately; both normalise to the
same shape). ``reasoning_tokens`` is a breakdown of ``output_tokens``, not an addition to it.

Tracekit ships no prices: they change, and a stale built-in table would produce confident wrong numbers. ``tracekit
cost`` uses a JSON file you maintain::

    {"currency": "USD", "per": 1000000,
     "models": {"gpt-4o*": {"input": 2.5, "output": 10, "cache_read": 1.25},
                "claude-*":  {"input": 3, "output": 15, "cache_read": 0.3, "cache_write": 3.75}}}

Model names match by exact name first, then by the longest matching glob."""
import fnmatch
import json

FIELDS = ("input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens", "reasoning_tokens")


def _g(o, *path):
    for p in path:
        if o is None:
            return None
        o = o.get(p) if isinstance(o, dict) else getattr(o, p, None)
    return o


def _int(v):
    if isinstance(v, bool) or v is None:
        return None
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if 0 <= n < 10 ** 12 else None


def _clean(d):
    out = {k: _int(d.get(k)) for k in FIELDS}
    if out["input_tokens"] is None and out["output_tokens"] is None:
        return None
    out["input_tokens"] = out["input_tokens"] or 0
    out["output_tokens"] = out["output_tokens"] or 0
    return out


def from_openai(u):
    """Chat Completions (prompt/completion_tokens) or Responses API (input/output_tokens)."""
    if u is None:
        return None
    prompt = _int(_g(u, "prompt_tokens"))
    if prompt is not None or _g(u, "completion_tokens") is not None:
        cached = _int(_g(u, "prompt_tokens_details", "cached_tokens")) or 0
        write = _int(_g(u, "prompt_tokens_details", "cache_write_tokens")) or 0
        return _clean({"input_tokens": max(0, (prompt or 0) - cached - write), "output_tokens": _g(u, "completion_tokens"),
                       "cache_read_tokens": cached or None, "cache_write_tokens": write or None,
                       "reasoning_tokens": _g(u, "completion_tokens_details", "reasoning_tokens")})
    inp = _int(_g(u, "input_tokens"))
    cached = _int(_g(u, "input_tokens_details", "cached_tokens")) or 0
    write = _int(_g(u, "input_tokens_details", "cache_write_tokens")) or 0
    return _clean({"input_tokens": None if inp is None else max(0, inp - cached - write), "output_tokens": _g(u, "output_tokens"),
                   "cache_read_tokens": cached or None, "cache_write_tokens": write or None,
                   "reasoning_tokens": _g(u, "output_tokens_details", "reasoning_tokens")})


def from_anthropic(u):
    if u is None:
        return None
    return _clean({"input_tokens": _g(u, "input_tokens"), "output_tokens": _g(u, "output_tokens"),
                   "cache_read_tokens": _g(u, "cache_read_input_tokens"), "cache_write_tokens": _g(u, "cache_creation_input_tokens")})


def from_gemini(u):
    if u is None:
        return None
    prompt = _int(_g(u, "prompt_token_count"))
    cached = _int(_g(u, "cached_content_token_count")) or 0
    out, thoughts = _int(_g(u, "candidates_token_count")), _int(_g(u, "thoughts_token_count"))
    # Gemini counts thoughts apart from candidates; reasoning_tokens is a breakdown of output_tokens
    return _clean({"input_tokens": None if prompt is None else max(0, prompt - cached),
                   "output_tokens": None if out is None and thoughts is None else (out or 0) + (thoughts or 0),
                   "cache_read_tokens": cached or None, "reasoning_tokens": thoughts})


def from_otel(a):
    """GenAI semantic conventions, OpenLLMetry and OpenInference span attributes."""
    inp = _int(a.get("gen_ai.usage.input_tokens", a.get("gen_ai.usage.prompt_tokens", a.get("llm.token_count.prompt",
                                                                                            a.get("ai.usage.promptTokens")))))
    out = a.get("gen_ai.usage.output_tokens", a.get("gen_ai.usage.completion_tokens", a.get("llm.token_count.completion",
                                                                                         a.get("ai.usage.completionTokens"))))
    cached = _int(a.get("gen_ai.usage.cache_read.input_tokens", a.get("gen_ai.usage.cache_read_input_tokens",
                                                                      a.get("llm.token_count.prompt_details.cache_read")))) or 0
    write = a.get("gen_ai.usage.cache_creation.input_tokens", a.get("gen_ai.usage.cache_creation_input_tokens",
                                                                     a.get("llm.token_count.prompt_details.cache_write")))
    # GenAI semconv counts cached input inside input_tokens (like OpenAI); keep the buckets additive
    return _clean({"input_tokens": None if inp is None else max(0, inp - cached), "output_tokens": out,
                   "cache_read_tokens": cached or None, "cache_write_tokens": write,
                   "reasoning_tokens": a.get("gen_ai.usage.reasoning_tokens", a.get("llm.token_count.completion_details.reasoning"))})


def merge(a, b):
    """Streaming: later reports override earlier ones field by field (Anthropic sends input at start, output at the end)."""
    if not a:
        return b
    if not b:
        return a
    out = dict(a)
    for k in FIELDS:
        if b.get(k):
            out[k] = b[k]
    return out


# ------------------------------------------------------------------ cost

class Prices:
    def __init__(self, table):
        if not isinstance(table, dict) or not isinstance(table.get("models"), dict):
            raise ValueError("price table needs a 'models' object")
        self.per = float(table.get("per", 1_000_000))
        self.currency = str(table.get("currency", "USD"))
        self.models = table["models"]

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f))

    def rate(self, model):
        if not model:
            return None
        if model in self.models:
            return self.models[model]
        hits = [k for k in self.models if fnmatch.fnmatchcase(model, k)]
        return self.models[max(hits, key=len)] if hits else None

    def cost(self, model, usage):
        """-> cost, or None when the model has no price (never guessed)."""
        r = self.rate(model)
        if r is None or not usage:
            return None
        c = (usage.get("input_tokens") or 0) * float(r.get("input", 0)) + (usage.get("output_tokens") or 0) * float(r.get("output", 0))
        c += (usage.get("cache_read_tokens") or 0) * float(r.get("cache_read", r.get("input", 0)))
        c += (usage.get("cache_write_tokens") or 0) * float(r.get("cache_write", r.get("input", 0)))
        return c / self.per
