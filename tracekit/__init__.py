"""Tracekit 0.3: signed, checkpointed evidence of what AI agents did.

Tracekit proves what its capture path recorded, and that it hasn't changed since it was
signed and checkpointed. It does not prove intent, complete coverage, or that a reported
result is real. See docs/threat-model-laptop.md.
"""
__version__ = "1.0.0rc1"


def __getattr__(name):
    """`tracekit.init()` / `tracekit.shutdown()`: one-line model-call tracing (tracekit.autotrace), imported lazily so
    `import tracekit` stays cheap for the hook and the verifier."""
    if name in ("init", "shutdown", "instrument", "uninstrument"):
        from . import autotrace
        return getattr(autotrace, name)
    raise AttributeError(f"module 'tracekit' has no attribute {name!r}")
