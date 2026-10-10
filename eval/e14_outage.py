#!/usr/bin/env python3
"""E14: outage behaviour of the v2 signer and its clients (04-design §2.3, §2.4, §2.8, §7.1, §11). POSIX only.

The signer's fail modes are {default: closed, fs: open}: Read is an fs call, Bash a shell call. Each scenario checks
its expected outcome:

  a  signer down, fail-closed class (Claude Code v2 hook, Bash): every call is blocked
  b  signer down, fail-open class (the hook, Read): the calls run; once the signer is back, the run's next call makes it
     write a signed client_counter_gap covering exactly the missed calls
  c  signer kill -9'd and restarted mid-run (Python client): the run goes on, and an approval requested before the
     restart is approved, consumed and completed after it
  d  network partition to an HTTPS signer (a TCP proxy that silently drops all traffic; the held-call adapter that MCP
     and Browser Use share): every call returns within the client timeout with its class's fail mode, and a
     client_counter_gap covers the missed calls afterwards; p50/p99 added latency during and after the partition
  e  witness unreachable: the signer keeps answering, a signed witness_failed gap appears after the threshold, and the
     witness cosigns the latest checkpoint once it is back
  f  storage refuses writes (ENOSPC): clients get `unavailable`, every acknowledged call is in the store, and a signed
     signer_unavailable gap follows the recovery
  g  a and b through the TS client: skipped with the reason without node or the built SDK

a-c and g drive `tracekit signer serve`; d-f run the signer in process to inject the fault and shorten its timers
(witness gap threshold, publish backoff, storage retry). Every signer's store must pass `tracekit signer fsck`.
Writes eval/results/e14_outage.json; exit 1 when a scenario misses its expectation.
"""
import argparse
import asyncio
import contextlib
import io
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _stack import ROOT, pct, summarize, v2_signer, write_results  # noqa: E402

sys.path.insert(0, os.path.join(ROOT, "tests"))   # the test PKI and in-test witness
from test_identity_mtls import Pki  # noqa: E402
from test_signer_service import ME  # noqa: E402
from test_witness_publish import NAME, ORIGIN, VKEY, FakeWitness  # noqa: E402
from tracekit.format import checkpoint, registry  # noqa: E402
from tracekit.integrations import claude_code  # noqa: E402
from tracekit.integrations.held import HeldCalls  # noqa: E402
from tracekit.sdk.client import Client  # noqa: E402
from tracekit.signer import pipeline  # noqa: E402
from tracekit.signer import service as svc  # noqa: E402
from tracekit.signer.rpc_schema import REQUESTS, RPCError  # noqa: E402
from tracekit.storage.base import StorageUnavailable  # noqa: E402
from tracekit.storage.file import FileStorage  # noqa: E402
from tracekit.tlog_witness import TlogWitness  # noqa: E402
from tracekit.transport import answering_hello, hello  # noqa: E402
from tracekit.transport import http as tk_http  # noqa: E402

FAIL_MODES = {"default": "closed", "fs": "open"}
FAIL_CFG = "fail_modes: {default: closed, fs: open}\n"
READ, BASH = ("Read", {"file_path": "src/a.py"}), ("Bash", {"command": "ls"})
TIMEOUT_S = 1.0   # the client timeout under the partition


def events(data_dir):
    with open(os.path.join(data_dir, "store", "records.jsonl"), "rb") as f:
        return [json.loads(line)["event"] for line in f.read().splitlines()]


def counters(evs, run_id):
    """(the client_seq values of the run's events, the missed_events of its client_counter_gaps), in log order."""
    evs = [e for e in evs if e.get("run_id") == run_id]
    return ([e["client_seq"] for e in evs if "client_seq" in e],
            [e["data"]["missed_events"] for e in evs
             if e["type"] == "capture.gap" and e["data"]["kind"] == "client_counter_gap"])


def kinds(evs, kind):
    return [e for e in evs if e["type"] == "capture.gap" and e["data"]["kind"] == kind]


def fsck(data_dir):
    return svc.fsck(data_dir)[:20]


def hooks(d, n):
    """a and b: two Claude Code sessions, registered while the signer is up, call through an outage."""
    data, rt = os.path.join(d, "hooks"), os.path.join(d, "rt")
    os.makedirs(rt, 0o700)
    p, sock = v2_signer(data, config=FAIL_CFG)

    def pre(sid, call, i):
        payload = {"hook_event_name": "PreToolUse", "session_id": sid, "tool_use_id": f"{sid}-{i}",
                   "tool_name": call[0], "tool_input": call[1]}
        with contextlib.redirect_stderr(io.StringIO()):
            return claude_code.handle(payload)
    try:
        with mock.patch.dict(os.environ, {"TRACEKIT_SIGNER": sock, "TRACEKIT_RUNTIME_DIR": rt}):
            up = [pre("a", BASH, 0), pre("b", READ, 0)]
            p.kill()
            p.wait()
            closed = [pre("a", BASH, i) for i in range(1, n + 1)]
            opened = [pre("b", READ, i) for i in range(1, n + 1)]
            p, _ = v2_signer(data, config=FAIL_CFG)
            back = pre("b", READ, n + 1)
            run_b = claude_code._load(claude_code._state("b"))["run_id"]
    finally:
        p.terminate()
        p.wait(30)
    seqs, gaps = counters(events(os.path.join(data, "data")), run_b)
    problems = fsck(os.path.join(data, "data"))
    a = {"calls_while_down": n, "blocked": closed.count(2), "ok": up[0] == 0 and closed == [2] * n and not problems}
    b = {"calls_while_down": n, "ran": opened.count(0), "client_seqs_recorded": seqs, "client_counter_gaps": gaps,
         "fsck_problems": problems,
         "ok": up[1] == back == 0 and opened == [0] * n and seqs == [0, n + 1] and gaps == [n] and not problems}
    return a, b


def restart(d):
    """c: an approval requested before a kill -9 and restart is answered, consumed and completed after it."""
    data, cfg = os.path.join(d, "restart"), "approvals: {self_approval: allow}\n"
    p, sock = v2_signer(data, config=cfg)
    c = Client(sock, timeout=10)
    try:
        run = c.run("e14")
        before = run.decide("c0", *READ)["decision"]
        asked = run.decide("pay", "tracekit_demo_ask", {"to": "acct-42"})["decision"]
        aid = run.call("approval_request", tool_call_id="pay")["approval_id"]
        p.kill()
        p.wait()
        p, _ = v2_signer(data, config=cfg)
        after = run.decide("c1", *READ)["decision"]
        c.approval_decide({"approval_id": aid, "decision": "approve"})
        state = run.call("approval_wait", approval_id=aid, timeout_ms=5000)["state"]
        consumed = run.approval_consume("pay", "tracekit_demo_ask", {"to": "acct-42"}, approval_id_hint=aid)["ok"]
        completed = "run_seq" in run.complete("pay")
        run.close()
    finally:
        c.close()
        p.terminate()
        p.wait(30)
    problems = fsck(os.path.join(data, "data"))
    out = {"decide_before": before, "decide_after": after, "asked": asked, "approval_after_restart": state,
           "consumed": consumed, "completed": completed, "fsck_problems": problems}
    out["ok"] = (before, after, asked, state, consumed, completed, problems) == (
        "allow", "allow", "ask", "approved", True, True, [])
    return out


class Proxy:
    """A TCP forwarder to 127.0.0.1:port; while `drop` is set it reads and discards everything (a partition, not a
    reset: no FIN, no RST)."""

    def __init__(self, port):
        self.port, self.drop = port, threading.Event()
        self.srv = socket.create_server(("127.0.0.1", 0))
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                a, _ = self.srv.accept()
            except OSError:
                return
            b = socket.create_connection(("127.0.0.1", self.port))
            for src, dst in ((a, b), (b, a)):
                threading.Thread(target=self._pump, args=(src, dst), daemon=True).start()

    def _pump(self, src, dst):
        try:
            while data := src.recv(65536):
                if not self.drop.is_set():
                    dst.sendall(data)
        except OSError:
            pass
        for s in (src, dst):
            s.close()


class Fs(HeldCalls):
    CLASS = "fs"


class Shell(HeldCalls):
    CLASS = "shell"


def partition(d, samples, n):
    """d: an HTTPS signer behind a proxy that drops all traffic for a while."""
    pki, data = Pki(d), os.path.join(d, "https")
    cert, key = pki.issue("server")
    token = os.path.join(d, "bearer")
    with open(token, "w") as f:
        f.write(uuid.uuid4().hex * 2)
    s = svc.SignerService(data, fail_modes=FAIL_MODES, authorize={"token:http": sorted(REQUESTS)})
    _, auths, tls = tk_http.configure({"listen": "127.0.0.1:0", "cert": cert, "key": key, "authenticators": ["token"],
                                       "token_file": token})
    srv = tk_http.HttpServer(("127.0.0.1", 0), auths, tls, answering_hello(s.handle_frame, hello()))
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
    proxy = Proxy(srv.server_address[1])
    with mock.patch.dict(os.environ, {"TRACEKIT_SIGNER_CA": pki.path, "TRACEKIT_SIGNER_TOKEN_FILE": token}):
        c = Client(f"https://127.0.0.1:{proxy.srv.getsockname()[1]}", timeout=TIMEOUT_S)
    fs, shell = (cls(c, c.register_run({"agent": {"name": "e14"}})) for cls in (Fs, Shell))

    def gate(adapter, call):
        t = time.perf_counter()
        why, decided = asyncio.run(adapter._gate(uuid.uuid4().hex, *call))
        return (time.perf_counter() - t) * 1000, why is None, decided is not None

    try:
        base = [gate(fs, READ) for _ in range(samples)]
        proxy.drop.set()
        during_fs = [gate(fs, READ) for _ in range(n)]
        during_shell = [gate(shell, BASH) for _ in range(n)]
        proxy.drop.clear()
        after = [gate(fs, READ) for _ in range(samples)] + [gate(shell, BASH)]
    finally:
        proxy.srv.close()
        srv.shutdown()
        srv.server_close()
        s.close()
    evs, problems = events(data), fsck(data)
    p50 = pct([ms for ms, _, _ in base], 50)

    def added(rows):
        ms = [m for m, _, _ in rows]
        return {**summarize(ms), "added_p50": round(pct(ms, 50) - p50, 2), "added_p99": round(pct(ms, 99) - p50, 2)}
    during = during_fs + during_shell
    gaps = [counters(evs, a.run["run_id"])[1] for a in (fs, shell)]
    out = {"client_timeout_ms": TIMEOUT_S * 1000, "baseline": summarize([m for m, _, _ in base]),
           "during": added(during), "after": added(after[:-1]),
           "fs_ran_unrecorded": sum(ran and not dec for _, ran, dec in during_fs),
           "shell_blocked": sum(not ran for _, ran, _ in during_shell), "client_counter_gaps": gaps,
           "fsck_problems": problems}
    out["ok"] = (all(ran and dec for _, ran, dec in base + after)
                 and max(m for m, _, _ in during) <= TIMEOUT_S * 1000 + 500
                 and out["fs_ran_unrecorded"] == out["shell_blocked"] == n and gaps == [[n], [n]] and not problems)
    return out


def wait_for(fn, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if fn():
            return True
        time.sleep(0.05)
    return False


def witness(d, n):
    """e: the only witness unreachable for longer than the gap threshold, then back."""
    data, w = os.path.join(d, "witness"), FakeWitness()
    s = svc.SignerService(data, origin=ORIGIN)   # the witness knows the signer's logs before it goes down
    s.close()
    public = checkpoint.parse_vkey(s.vkey)[3]
    for origin in (ORIGIN, registry.origin(ORIGIN, s.log.tenant_salt("default"))):
        w.logs[origin] = checkpoint.vkey(origin, checkpoint.ED25519, public)
    port, logs = w.server.server_address[1], w.logs
    w.stop()
    with mock.patch.multiple(svc, WITNESS_GAP_S=0.5, BACKOFF_S=(0.05, 0.2), TICK_S=0.05):
        s = svc.SignerService(data, grace_s=0, witnesses=[TlogWitness(w.url, VKEY, timeout=1)], origin=ORIGIN)
        try:
            run = s.call(ME, "register_run", {"request_id": uuid.uuid4().hex, "agent": {"name": "e14"}})
            seq = iter(range(1 << 30))

            def decide():
                try:
                    s.call(ME, "decide", {"request_id": uuid.uuid4().hex, "run_id": run["run_id"],
                                          "run_token": run["run_token"], "stream": "s", "client_seq": next(seq),
                                          "tool_call_id": uuid.uuid4().hex, "tool": READ[0], "args_source": "parsed",
                                          "args": READ[1]})
                    return True
                except RPCError:
                    return False
            served = [decide() for _ in range(n)]
            s.checkpoint()
            gapped = wait_for(lambda: kinds(events(data), "witness_failed"), 15)
            served += [decide() for _ in range(n)]
            w = FakeWitness(port)
            w.logs = logs
            s.checkpoint()   # the gap records grew the tree: a new note

            def caught_up():
                latest = s.log.storage.checkpoint_latest()
                return latest and f"— {NAME} " in latest[1] and latest[0] == s.log.storage.tree.size
            cosigned = wait_for(caught_up, 15)
        finally:
            s.close()
            w.stop()
    evs, problems = events(data), fsck(data)
    out = {"calls_while_down": len(served), "answered": sum(served),
           "witness_failed_gaps": len(kinds(evs, "witness_failed")),
           "degraded_unanchored_gaps": len(kinds(evs, "degraded_unanchored")), "cosigned_after_recovery": cosigned,
           "fsck_problems": problems}
    out["ok"] = all(served) and gapped and cosigned and not problems
    return out


class Full(FileStorage):
    """File storage whose appends fail while `full` is set."""
    full = False

    def append_batch(self, records):
        if Full.full:
            raise StorageUnavailable("No space left on device")
        super().append_batch(records)


def storage(d, n):
    """f: the storage refuses every write for a while."""
    data = os.path.join(d, "storage")
    with mock.patch.object(pipeline, "RECOVER_S", 0.1):
        s = svc.SignerService(data, open_storage=lambda: Full(os.path.join(data, "store")))
        try:
            run = s.call(ME, "register_run", {"request_id": uuid.uuid4().hex, "agent": {"name": "e14"}})
            acked, refused, seq = {}, {}, iter(range(1 << 30))

            def decide():
                cseq = next(seq)
                try:
                    acked[cseq] = s.call(ME, "decide", {
                        "request_id": uuid.uuid4().hex, "run_id": run["run_id"], "run_token": run["run_token"],
                        "stream": "s", "client_seq": cseq, "tool_call_id": uuid.uuid4().hex, "tool": READ[0],
                        "args_source": "parsed", "args": READ[1]})["run_seq"]
                    return True
                except RPCError as e:
                    refused[e.code] = refused.get(e.code, 0) + 1
                    return False
            for _ in range(n):
                decide()
            Full.full = True
            during = [decide() for _ in range(n)]
            Full.full = False
            recovered = wait_for(decide, 5)
            for _ in range(n):
                decide()
        finally:
            Full.full = False
            s.close()
    evs, problems = events(data), fsck(data)
    stored = {e["client_seq"]: e["run_seq"] for e in evs if e.get("run_id") == run["run_id"] and "client_seq" in e}
    seqs, gaps = counters(evs, run["run_id"])
    out = {"acknowledged": len(acked), "refused": refused,
           "acknowledged_lost": sum(stored.get(k) != v for k, v in acked.items()),
           "signer_unavailable_gaps": len(kinds(evs, "signer_unavailable")), "client_counter_gaps": gaps,
           "fsck_problems": problems}
    out["ok"] = (not any(during) and set(refused) == {"unavailable"} and recovered and out["acknowledged_lost"] == 0
                 and out["signer_unavailable_gaps"] == 1 and gaps == [sum(refused.values())] and not problems)
    return out


TS = """
import { createInterface } from "node:readline";
const { Client } = await import(process.env.E14_CLIENT);
const n = Number(process.env.E14_N), lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
const c = new Client({ signer: process.env.E14_SOCK, timeoutMs: 5000 });
const run = await c.registerRun("e14-ts");
const read = (i) => run.decide(`r${i}`, "Read", { file_path: "src/a.py" }, { tool_class_hint: "fs" });
const bash = (i) => run.decide(`b${i}`, "Bash", { command: "ls" }, { tool_class_hint: "shell" });
const up = (await read(0)).decision;
console.log("kill");
await lines.next();
const open = [], closed = [];
for (let i = 1; i <= n; i++) open.push(await read(i));
for (let i = 1; i <= n; i++) closed.push(await bash(i));
console.log("restart");
await lines.next();
const back = await read(n + 1);
await c.close();
const ok = (ds, decision) => ds.filter((d) => d.unavailable && d.decision === decision).length;
const out = { run_id: run.runId, up, ran: ok(open, "allow"), blocked: ok(closed, "deny"), back: back.decision };
console.log(JSON.stringify(out));
"""


def ts(d, n):
    """g: b and a through the TS client; None and the reason when it cannot run."""
    client = pathlib.Path(ROOT, "sdk", "typescript", "dist", "v2", "client.js")
    if not shutil.which("node"):
        return None, "node is not installed"
    if not client.exists():
        return None, f"{client} is not built (make test-ts)"
    data = os.path.join(d, "ts")
    p, sock = v2_signer(data, config=FAIL_CFG)
    env = dict(os.environ, E14_CLIENT=client.as_uri(), E14_SOCK=sock, E14_N=str(n))
    node = subprocess.Popen(["node", "--input-type=module", "-e", TS], env=env, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        for step in ("kill", "restart"):
            if node.stdout.readline().strip() != step:
                raise SystemExit(f"the Node part failed:\n{node.communicate(timeout=30)[1]}")
            if step == "kill":
                p.kill()
                p.wait()
            else:
                p, _ = v2_signer(data, config=FAIL_CFG)
            node.stdin.write("go\n")
            node.stdin.flush()
        out, err = node.communicate(timeout=60)
        if node.returncode:
            raise SystemExit(f"the Node part failed:\n{err}")
    finally:
        node.kill()
        p.terminate()
        p.wait(30)
    r = json.loads(out.splitlines()[-1])
    seqs, gaps = counters(events(os.path.join(data, "data")), r.pop("run_id"))
    problems = fsck(os.path.join(data, "data"))
    r.update(calls_while_down=2 * n, client_seqs_recorded=seqs, client_counter_gaps=gaps, fsck_problems=problems)
    r["ok"] = (r["up"] == r["back"] == "allow" and r["ran"] == r["blocked"] == n and seqs == [0, 2 * n + 1]
               and gaps == [2 * n] and not problems)
    return r, None


def main(argv=None):
    if os.name != "posix":
        raise SystemExit("E14 needs POSIX (Unix sockets, kill -9)")
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--quick", action="store_true", help="fewer calls per phase (make eval)")
    a = ap.parse_args(argv)
    n, samples = (5, 30) if a.quick else (20, 200)
    d = tempfile.mkdtemp(prefix="e14-", dir="/tmp")   # short socket paths
    out = {"platform": sys.platform, "python": sys.version.split()[0], "quick": a.quick, "skipped": {}}
    try:
        r = out["scenarios"] = {}
        r["a_fail_closed"], r["b_fail_open"] = hooks(d, n)
        r["c_restart"] = restart(d)
        r["d_partition"] = partition(d, samples, n)
        r["e_witness_unreachable"] = witness(d, n)
        r["f_storage_unavailable"] = storage(d, n)
        r["g_typescript"], why = ts(d, n)
        if why:
            out["skipped"]["g_typescript"] = why
            del r["g_typescript"]
    finally:
        shutil.rmtree(d, ignore_errors=True)
    for k, v in r.items():
        print(f"{k}: {'ok' if v['ok'] else 'FAILED'} {json.dumps({x: y for x, y in v.items() if x != 'ok'})}")
    for k, why in out["skipped"].items():
        print(f"{k}: skipped ({why})")
    dp = r["d_partition"]
    print(f"partition: added p50/p99 {dp['during']['added_p50']}/{dp['during']['added_p99']} ms during, "
          f"{dp['after']['added_p50']}/{dp['after']['added_p99']} ms after (client timeout {TIMEOUT_S * 1000:g} ms)")
    out["gates"] = {k: v["ok"] for k, v in r.items()}
    print("wrote", write_results("e14_outage", out))
    return 0 if all(out["gates"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
