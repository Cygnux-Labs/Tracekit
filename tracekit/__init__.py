"""Tracekit 0.3: signed, checkpointed evidence of what AI agents did.

Tracekit proves what its capture path recorded, and that it hasn't changed since it was
signed and checkpointed. It does not prove intent, complete coverage, or that a reported
result is real. See docs/threat-model-laptop.md.
"""
__version__ = "1.1.0.dev0"


def __getattr__(name):
    """`tracekit.instrument()`: one line wires the v2 signer into this process's agent (tracekit.autowire).
    `tracekit.init()` / `tracekit.shutdown()`: v1 model-call tracing (tracekit.autotrace). Imported lazily so
    `import tracekit` stays cheap for the hook and the verifier."""
    if name == "instrument":
        from .autowire import instrument
        return instrument
    if name in ("init", "shutdown", "uninstrument"):
        from . import autotrace
        return getattr(autotrace, name)
    raise AttributeError(f"module 'tracekit' has no attribute {name!r}")
