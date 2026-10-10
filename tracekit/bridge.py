"""Deprecated, removed in 0.5.0: the TypeScript SDK's native v2 client talks to the signer without it.

Language bridge: other runtimes (the TypeScript SDK, sdk/typescript) drive the Python Tracer over stdio, so every
language gets the same policy engine, redaction, signer client and event format, with nothing reimplemented.

    python -m tracekit.bridge          # started by the SDK; one JSON object per line in each direction

Request:  {"id": 1, "op": "<op>", ...}        Reply: {"id": 1, "ok": true, ...} | {"id": 1, "ok": false, "error": "...", "denied": bool}

ops
  start        agent, session_id?, cwd?                          -> run
  prompt       run, text
  say / think  run, text                                         (recorded only with reasoning_capture)
  tool_begin   run, name, args, tool_use_id?                     -> call   (policy evaluated here; denied: ok=false, denied=true)
  tool_end     call, result?, error?
  model_begin  run, provider, operation, model?, request, streamed  -> exchange   (written before the request is sent)
  model_end    exchange, response?, error?, status?, stop_reason?, tool_uses?, usage?, model?, first_byte_ms?
  end          run, reason?
  ping

Requests run concurrently on a bounded pool of worker threads, so a call held for approval does not stall the others;
when every worker is busy a request is answered at once with the error "bridge busy". A request that has not finished
within its timeout_s (default 300 s, at most an hour, counted from when it was received) is answered with an error; if
it finishes late, a tool call it opened is ended and a model call it began is finished, both with the error "caller
timed out". If the signer is unreachable the Tracer's fail mode applies exactly as in Python: open records
a gap later, closed refuses."""
import json
import math
import os
import sys
import threading
import time

from . import autotrace
from .agent_sdk import Tracer

MAX_WORKERS = 32
DEFAULT_TIMEOUT_S, MAX_TIMEOUT_S = 300.0, 3660.0


class Bridge:
    def __init__(self, out):
        self.out, self.lock = out, threading.Lock()
        self.runs, self.calls, self.exchanges = {}, {}, {}
        self.n = 0

    def _id(self, prefix):
        with self.lock:
            self.n += 1
            return f"{prefix}{self.n}"

    def reply(self, obj):
        with self.lock:
            self.out.write(json.dumps(obj, default=str) + "\n")
            self.out.flush()

    def handle(self, req, answered=None):
        """Run one request and reply, unless its timeout already answered it (answered is set)."""
        rid = req.get("id")
        try:
            res = getattr(self, "op_" + str(req.get("op")), None)
            if res is None:
                raise ValueError(f"unknown op {req.get('op')!r}")
            out = {"id": rid, "ok": True, **(res(req) or {})}
        except PermissionError as e:
            out = {"id": rid, "ok": False, "denied": True, "error": str(e)}
        except Exception as e:
            out = {"id": rid, "ok": False, "denied": False, "error": f"{type(e).__name__}: {e}"}
        if not self._answer(answered, out) and out["ok"]:
            self._abandon(out)

    def _answer(self, answered, out):
        """Reply unless already answered; True if this reply was sent."""
        with self.lock:
            if answered is not None:
                if answered.is_set():
                    return False
                answered.set()
        self.reply(out)
        return True

    def _abandon(self, out):
        """The caller gave up on this request: close what it opened so no late evidence or state is left."""
        call = self.calls.pop(out.get("call"), None)
        if call is not None:
            call.__exit__(RuntimeError, RuntimeError("caller timed out"), None)
        ex = self.exchanges.pop(out.get("exchange"), None)
        if ex is not None:
            ex.finish(error="caller timed out")

    def submit(self, req, slots):
        """Run req on a worker thread if one of the bounded slots is free (else answer "bridge busy"), with a timer
        that answers it with an error if it runs past its timeout. Returns the thread, or None when busy."""
        t = req.get("timeout_s", DEFAULT_TIMEOUT_S)
        if isinstance(t, bool) or not isinstance(t, (int, float)) or not math.isfinite(t) or t <= 0:
            t = DEFAULT_TIMEOUT_S
        answered = threading.Event()
        timer = threading.Timer(min(t, MAX_TIMEOUT_S), self._answer, (answered, {
            "id": req.get("id"), "ok": False, "denied": False, "error": f"request timed out after {min(t, MAX_TIMEOUT_S)} s"}))
        timer.daemon = True

        def work():
            try:
                if not answered.is_set():  # its deadline may have passed before the worker started
                    self.handle(req, answered)
            finally:
                timer.cancel()
                slots.release()
        timer.start()
        if not slots.acquire(blocking=False):
            timer.cancel()
            self._answer(answered, {"id": req.get("id"), "ok": False, "denied": False, "error": "bridge busy"})
            return None
        th = threading.Thread(target=work, daemon=True)
        th.start()
        return th

    def op_ping(self, r):
        return {"pong": True}

    def op_start(self, r):
        t = Tracer(agent=str(r.get("agent") or "ts-agent"), session_id=r.get("session_id"), cwd=r.get("cwd"))
        h = self._id("r")
        self.runs[h] = t
        return {"run": h, "session_id": t.session_id, "fail_mode": t._policy.get("fail_mode", "open")}

    def _run(self, r):
        t = self.runs.get(r.get("run"))
        if t is None:
            raise ValueError("unknown run")
        return t

    def op_prompt(self, r):
        self._run(r).prompt(r.get("text"))

    def op_say(self, r):
        self._run(r).say(r.get("text"))

    def op_think(self, r):
        self._run(r).think(r.get("text"))

    def op_tool_begin(self, r):
        args = r.get("args") if isinstance(r.get("args"), dict) else {"value": r.get("args")}
        call = self._run(r).tool(str(r.get("name") or "tool"), args, r.get("tool_use_id"))
        call.__enter__()  # PermissionError on deny or unapproved hold: the tool must not run
        h = self._id("c")
        self.calls[h] = call
        return {"call": h, "tool_use_id": call.tool_use_id}

    def op_tool_end(self, r):
        call = self.calls.pop(r.get("call"), None)
        if call is None:
            raise ValueError("unknown call")
        if r.get("error") is not None:
            call.__exit__(RuntimeError, RuntimeError(str(r["error"])[:2000]), None)
        else:
            call.result(r.get("result"))
            call.__exit__(None, None, None)

    def op_model_begin(self, r):
        ex = autotrace._Exchange(self._run(r), str(r.get("provider") or "unknown")[:50], str(r.get("operation") or "call")[:50],
                                 str(r["model"])[:200] if r.get("model") else None, r.get("request") if isinstance(r.get("request"), dict)
                                 else {"request": r.get("request")}, bool(r.get("streamed")))
        ex.begin()
        h = self._id("x")
        self.exchanges[h] = ex
        return {"exchange": h}

    def op_model_end(self, r):
        ex = self.exchanges.pop(r.get("exchange"), None)
        if ex is None:
            raise ValueError("unknown exchange")
        ex.resp_model = r.get("model") or ex.resp_model
        ex.stop_reason = r.get("stop_reason")
        for t in r.get("tool_uses") or []:
            if isinstance(t, dict) and t.get("id"):
                ex.tool_uses[str(t["id"])] = str(t.get("name") or "?")
        u = r.get("usage")
        if isinstance(u, dict):
            from .usage import _clean
            ex.add_usage(_clean(u))
        if isinstance(r.get("first_byte_ms"), (int, float)):
            ex.first_byte = ex.t0 + r["first_byte_ms"] / 1000
        ex.finish(response=r.get("response"), error=r.get("error"), status=r.get("status"))

    def op_end(self, r):
        t = self.runs.pop(r.get("run"), None)
        if t is not None:
            t.end(str(r.get("reason") or "done"))


def main():
    if not os.environ.get("TRACEKIT_NO_DEPRECATION"):
        print("tracekit.bridge is deprecated and removed in 0.5.0: the TypeScript SDK's native v2 client "
              "(import { Client } from \"@cygnux/tracekit\") needs no Python bridge. TRACEKIT_NO_DEPRECATION=1 silences this.",
              file=sys.stderr, flush=True)
    b = Bridge(sys.stdout)
    b.reply({"id": 0, "ok": True, "ready": True, "protocol": 1})
    slots, threads = threading.BoundedSemaphore(MAX_WORKERS), []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            b.reply({"id": None, "ok": False, "error": "invalid JSON"})
            continue
        if not isinstance(req, dict):
            b.reply({"id": None, "ok": False, "error": "request must be a JSON object"})
            continue
        th = b.submit(req, slots)
        threads = [x for x in threads if x.is_alive()] + ([th] if th else [])
    deadline = time.time() + 10
    for th in threads:  # stdin closed: let in-flight requests finish, then end any run still open
        th.join(max(0.0, deadline - time.time()))
    for t in list(b.runs.values()):
        try:
            t.end("bridge closed")
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
