"""Signature messages. v1 is the frozen `core.sig_message`, re-exported. A v2 message is a JCS object whose "t" names
its purpose, so a signature made for one purpose never verifies as another."""
from tracekit.core import sig_message as sig_message_v1
from tracekit.format.canon import canonical

__all__ = ["PURPOSES", "RECORD_FIELDS", "message", "sig_message_v1", "sig_message_v2"]

PURPOSES = ("record", "checkpoint", "approval", "cert", "retire", "export")
RECORD_FIELDS = ("alg", "kid", "log_id", "seq", "prev_hash", "tenant", "run_id", "run_seq", "run_prev_hash", "hash")


def message(purpose, body):
    if purpose not in PURPOSES:
        raise ValueError(f"unknown signature purpose {purpose!r}")
    if "t" in body:
        raise ValueError("'t' is the domain tag")
    return canonical({**body, "t": f"tracekit.{purpose}.v2"})


def sig_message_v2(fields):
    return message("record", {k: fields[k] for k in RECORD_FIELDS})
