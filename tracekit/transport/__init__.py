"""Newline-delimited JSON frames over a stream socket: one request object per line, one response object per line.

A frame is `{"method": ..., ...}`; the transport only reads `method`. The caller's identity is established again for
every frame by the transport's authenticator, never taken from the frame's content.
"""
import json

from tracekit.format.canon import StrictJSONError, loads_strict
from tracekit.signer.quotas import MAX_LINE
from tracekit.signer.rpc_schema import RPCError

READ_TIMEOUT_S = 30


def read_frame(rfile):
    """The next frame as a dict; None at end of stream. A line over MAX_LINE raises quota_exceeded."""
    line = rfile.readline(MAX_LINE + 1)
    if not line.endswith(b"\n"):
        if len(line) > MAX_LINE:
            raise RPCError("quota_exceeded", f"frame longer than {MAX_LINE} bytes")
        return None   # end of stream, possibly mid-line
    try:
        frame = loads_strict(line)
    except StrictJSONError as e:
        raise RPCError("invalid_request", str(e)) from None
    if not isinstance(frame, dict):
        raise RPCError("invalid_request", "a frame must be a JSON object")
    return frame


def write_frame(conn, obj):
    conn.sendall(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode() + b"\n")


def serve(conn, rfile, authenticate, handle):
    """Answer frames until the peer closes, a read times out, a line is too long or a frame fails authentication.

    `authenticate(conn, frame)` returns a CallerIdentity; `handle(identity, frame)` returns the response dict. Both
    raise RPCError for a refusal.
    """
    while True:
        try:
            frame = read_frame(rfile)
        except OSError:   # includes the read timeout
            return
        except RPCError as e:
            write_frame(conn, e.wire())
            if e.code == "invalid_request":
                continue
            return   # the rest of an oversized line can't be framed
        if frame is None:
            return
        try:
            out = handle(authenticate(conn, frame), frame)
        except RPCError as e:
            write_frame(conn, e.wire())
            if e.code == "unauthenticated":
                return
            continue
        write_frame(conn, out)
