"""Language bridge: other runtimes (the TypeScript SDK, sdk/typescript) drive the Python Tracer over stdio, so every
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

Requests run concurrently (one thread each), so a call held for approval does not stall the others. If the signer is
unreachable the Tracer's fail mode applies exactly as in Python: open records a gap later, closed refuses."""
import json
import sys
import threading
import time

from . import autotrace
from .agent_sdk import Tracer


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

    def handle(self, req):
        rid = req.get("id")
        try:
            res = getattr(self, "op_" + str(req.get("op")), None)
            if res is None:
                raise ValueError(f"unknown op {req.get('op')!r}")
            self.reply({"id": rid, "ok": True, **(res(req) or {})})
        except PermissionError as e:
            self.reply({"id": rid, "ok": False, "denied": True, "error": str(e)})
        except Exception as e:
            self.reply({"id": rid, "ok": False, "denied": False, "error": f"{type(e).__name__}: {e}"})

    def op_ping(self, r):
        return {"pong": True}

    def op_start(self, r):
        t = Tracer(agent=str(r.get("agent") or "ts-agent"), session_id=r.get("session_id"), cwd=r.get("cwd"))
        h = self._id("r")
        self.runs[h] = t
        return {"run": h, "session_id": t.session_id}

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
    b = Bridge(sys.stdout)
    b.reply({"id": 0, "ok": True, "ready": True, "protocol": 1})
    threads = []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            b.reply({"id": None, "ok": False, "error": "invalid JSON"})
            continue
        th = threading.Thread(target=b.handle, args=(req,), daemon=True)
        th.start()
        threads.append(th)
        threads = [x for x in threads if x.is_alive()]
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
