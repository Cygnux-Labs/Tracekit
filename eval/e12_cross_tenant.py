#!/usr/bin/env python3
"""E12: tenants on one signer stay apart (04-design §2.2, §7.1-7.2).

Part 1, cross-tenant requests. One v2 signer, in process, with two tenants mapped by its `tenants` config from two
Unix uid identities (as the Unix socket stamps them; both authorized for every method and OTLP import). Tenant b's
identity attacks tenant a's run, which has a pending approval and an imported trace run. Each attack must be refused
(an RPC refusal, or nothing of tenant a's reached or changed):

  run_token     a's run id and run token, presented from b's identity, for every per-run method
  guessed_id    a's run id (and a random one) with b's own run token; a token edited to name a's run
  delegate_run  delegating b's run to an identity with no authorize entry; delegating a's run with a's token
  approvals     approval_get / approval_decide / approval_wait / approval_consume on a's approval; approval_list
  otlp_import   spans of a's trace id, posted from b's identity, must not reach a's trace run
  run_set       a's run-set export holds nothing of b's; b's run-set presented as a's fails verification
  observability the metrics and the witnesses' logs list name no tenant, run id or identity

Part 2, in-process leaks. Against `tracekit signer serve`: concurrent asyncio tasks and threads, each inside its own
`with client.run(...)`, make every call through `current_run` (a contextvar); concurrent promises in Node do the same
with `withRun`/`currentRun` (AsyncLocalStorage; skipped with the reason when node or the built TS SDK is missing). Every
call must be recorded in its own task's run, and only there.
Writes eval/results/e12_cross_tenant.json; exit 0 only when every attack is refused and no call leaks.
"""
import asyncio
import base64
import hashlib
import json
import os
import pathlib
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _stack import ROOT, v2_signer, write_results  # noqa: E402
from tracekit.bundle_v2 import export  # noqa: E402
from tracekit.format.canon import event_hash  # noqa: E402
from tracekit.identity.base import CallerIdentity  # noqa: E402
from tracekit.policy2.engine import Engine  # noqa: E402
from tracekit.sdk.client import AsyncClient, Client, current_run  # noqa: E402
from tracekit.signer import otel as signer_otel  # noqa: E402
from tracekit.signer import service as svc  # noqa: E402
from tracekit.signer.rpc_schema import REQUESTS, RPCError  # noqa: E402
from tracekit.storage.base import registry_tree  # noqa: E402
from tracekit.verify import v2  # noqa: E402

# lean: stamped in process as the Unix socket stamps a peer uid (tests/test_identity.py covers the stamping); run part 1
# over the socket as two real users, as root like E8 v2, if it should cover the transport too
A, B = CallerIdentity("uid", "1001", True), CallerIdentity("uid", "1002", True)
TENANTS = {"uid:1001": "tenant-a", "uid:1002": "tenant-b"}
TRACE = "5b8efff798038103d269b633813fc60c"
CALLS, WORKERS = 20, 8
rng = random.Random(12)


def code(fn):
    """The RPC refusal code of fn(), None when it was not refused."""
    try:
        fn()
    except RPCError as e:
        return e.code
    return None


def otlp_body(span_id, args):
    attrs = {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "Bash",
             "gen_ai.tool.call.arguments": json.dumps(args)}
    span = {"traceId": TRACE, "spanId": span_id, "name": "execute_tool Bash", "kind": 1,
            "startTimeUnixNano": "1760000000000000000", "endTimeUnixNano": "1760000001000000000",
            "attributes": [{"key": k, "value": {"stringValue": v}} for k, v in attrs.items()]}
    return json.dumps({"resourceSpans": [{"resource": {"attributes": []},
                                          "scopeSpans": [{"scope": {"name": "e12"}, "spans": [span]}]}]}).encode()


def records(s, tenant, run_id):
    return [r["event"] for r in s.log.storage.iter_run(tenant, run_id)]


def zip_files(path):
    with zipfile.ZipFile(path) as z:
        return {n: z.read(n) for n in z.namelist()}


def write_zip(path, files):
    m = json.loads(files["manifest.json"])   # repaired, as an attacker without the keys can
    m["files"] = {n: hashlib.sha256(b).hexdigest() for n, b in files.items() if n != "manifest.json"}
    files["manifest.json"] = json.dumps(m).encode()
    with zipfile.ZipFile(path, "w") as z:
        for n, b in files.items():
            z.writestr(n, b)


def cross_tenant(d):
    methods = [*REQUESTS, svc.OTLP_IMPORT]
    s = svc.SignerService(os.path.join(d, "signer"), grace_s=0, tenants=TENANTS,
                          authorize={"uid:1001": methods, "uid:1002": methods},
                          policy=Engine({"ask": [{"id": "E12-PAY", "tool": "pay", "pattern": "^"}]}))
    try:
        def call(who, method, **req):
            if "request_id" in REQUESTS[method]["properties"]:
                req.setdefault("request_id", os.urandom(8).hex())
            return s.call(who, method, req)

        def register(identity):
            out = call(identity, "register_run", agent={"name": "e12"})
            return {"run_id": out["run_id"], "run_token": out["run_token"]}
        a, b = register(A), register(B)
        pay = {"to": "acct-42", "cents": 1500}
        d1 = call(A, "decide", **a, stream="s", client_seq=0, tool_call_id="tc-1", tool="pay",
                  args_source="parsed", args=pay)
        aid = call(A, "approval_request", **a, tool_call_id="tc-1")["approval_id"]
        before = records(s, "tenant-a", a["run_id"])
        cases = {}

        def case(name, attempts):
            """attempts: [(label, the refusal code or None when it went through)]; refused when each has a code."""
            cases[name] = {"refused": all(c for _, c in attempts), "attempts": dict(attempts)}

        per_run = {"read": {}, "close_run": {}, "decide": dict(stream="s", client_seq=9, tool_call_id="tc-x",
                                                                tool="read_file", args_source="parsed", args={}),
                   "complete": dict(stream="s", client_seq=9, tool_call_id="tc-1", status="ok",
                                    decision_id=d1["decision_id"], args_digest=event_hash({"tool": "pay", "args": pay})),
                   "state_write": dict(stream="s", client_seq=9, key="k", value_digest="sha256:" + "0" * 64),
                   "model_event": dict(stream="s", client_seq=9, provider="p", model="m", phase="request"),
                   "approval_request": dict(tool_call_id="tc-1", attempt=1), "tailer_lost": dict(reason="x", offset=0),
                   "delegate_run": dict(identity="uid:1002"), "approval_abandon": dict(approval_id=aid)}
        case("run_token", [(m, code(lambda: call(B, m, **a, **req))) for m, req in per_run.items()])
        claims = json.loads(base64.urlsafe_b64decode(b["run_token"].split(".")[0] + "=="))
        edited = base64.urlsafe_b64encode(json.dumps({**claims, "run_id": a["run_id"], "tenant": "tenant-a"},
                                                     separators=(",", ":"), sort_keys=True).encode()).rstrip(b"=")
        case("guessed_id", [
            ("a's run id, b's token", code(lambda: call(B, "read", run_id=a["run_id"], run_token=b["run_token"]))),
            ("a random run id, b's token", code(lambda: call(B, "read", run_id=os.urandom(16).hex(),
                                                             run_token=b["run_token"]))),
            ("b's token edited to name a's run", code(lambda: call(B, "read", run_id=a["run_id"], run_token=(
                edited.decode() + "." + b["run_token"].split(".")[1]))))])
        case("delegate_run", [
            ("b's run to an identity without an authorize entry",
             code(lambda: call(B, "delegate_run", **b, identity="token:http"))),
            ("a's run, with a's token, to b", code(lambda: call(B, "delegate_run", **a, identity="uid:1002")))])
        consumed = call(B, "approval_consume", **b, tool_call_id="tc-1", tool="pay", args_source="parsed", args=pay,
                        approval_id_hint=aid)   # answers ok: false with the rules that refused it
        listed = call(B, "approval_list")["approvals"] + call(B, "approval_list", run_id=a["run_id"])["approvals"]
        case("approvals", [
            ("approval_get", code(lambda: call(B, "approval_get", approval_id=aid))),
            ("approval_decide", code(lambda: call(B, "approval_decide", approval_id=aid,
                                                  decision="approve"))),
            ("approval_wait with b's run", code(lambda: call(B, "approval_wait", **b, approval_id=aid, timeout_ms=0))),
            ("approval_consume with b's run", consumed and None if consumed["ok"] else ",".join(consumed["rule_ids"])),
            ("approval_list", "not listed" if aid not in [x["approval_id"] for x in listed] else None)])
        if records(s, "tenant-a", a["run_id"]) != before:
            cases["run_token"]["refused"] = False
            cases["run_token"]["attempts"]["a's run unchanged"] = None

        trace_run = signer_otel.run_id(TRACE)
        s.otlp(A, otlp_body("1111111111111111", {"command": "ls"}), "application/json", None)
        mine = records(s, "tenant-a", trace_run)
        status, _, _ = s.otlp(B, otlp_body("2222222222222222", {"command": "cat a.txt"}), "application/json", None)
        case("otlp_import", [("a's trace run unchanged", "unchanged" if records(s, "tenant-a", trace_run) == mine
                              else None),
                             ("b's spans went to b's own run", "own run" if status == 200 and
                              records(s, "tenant-b", trace_run) else None)])

        for who, run in ((A, a), (B, b)):
            call(who, "close_run", **run)
        s.sweep(time.monotonic() + 1)
        s.checkpoint()
        st = s.log.storage
        trust = os.path.join(d, "trust.json")
        with open(trust, "w") as f:
            json.dump({"logs": [s.vkey], "algs": ["ed25519"]}, f)

        def run_set(tenant, run_id, path):
            export(st, tenant, run_id, st.checkpoint_latest()[1], path,
                   run_set=(0, st.checkpoint_latest(registry_tree(tenant))[0]), tenant_salt=s.log.tenant_salt(tenant))
            return zip_files(path)
        files_a = run_set("tenant-a", a["run_id"], os.path.join(d, "a.tkb"))
        files_b = run_set("tenant-b", b["run_id"], os.path.join(d, "b.tkb"))
        honest = v2.verify(os.path.join(d, "a.tkb"), trust)[1]
        rs = json.loads(files_b["registry/run-set.json"])
        rs["tenant_salt"] = json.loads(files_a["registry/run-set.json"])["tenant_salt"]
        files_b["registry/run-set.json"] = json.dumps(rs).encode()
        write_zip(os.path.join(d, "b-as-a.tkb"), files_b)
        forged = v2.verify(os.path.join(d, "b-as-a.tkb"), trust)[1]
        blob = b"".join(files_a.values())
        case("run_set", [
            ("a's run-set names none of b's runs", "absent" if b["run_id"].encode() not in blob else None),
            ("a's run-set verifies", "baseline" if honest == v2.EXIT_OK else None),
            ("b's run-set as a's", f"exit {forged}" if forged != v2.EXIT_OK else None)])

        seen = s.metrics.render() + s.logs_list()
        names = {"identities": TENANTS, "tenants": TENANTS.values(), "run ids": (a["run_id"], b["run_id"], trace_run)}
        case("observability", [(k, "absent" if not any(n in seen for n in v) else None) for k, v in names.items()])
        return cases
    finally:
        s.close()


# --- part 2: run handles in one process ---

def store_calls(data_dir):
    """run_id -> [tool_call_id of each decide recorded in it]."""
    out = {}
    with open(os.path.join(data_dir, "data", "store", "records.jsonl"), "rb") as f:
        for line in f:
            e = json.loads(line)["event"]
            if e["type"] == "policy.decision" and "tool_call_id" in e:
                out.setdefault(e["run_id"], []).append(e["tool_call_id"])
    return out


def leaks(owned, calls):
    """Calls recorded in another worker's run, and runs missing calls of their own."""
    wrong = sorted(t for run, ts in calls.items() if run in owned for t in ts if not t.startswith(owned[run]))
    short = sorted(owned[run] for run in owned if len(calls.get(run, [])) != CALLS)
    return {"in_another_run": wrong, "runs_missing_calls": short}


def py_tasks(sock):
    owned = {}

    async def main():
        client = AsyncClient(sock)

        async def one(n):
            async with await client.run("e12-task") as run:
                owned[run.run_id] = f"task{n}-"
                for i in range(CALLS):
                    await asyncio.sleep(rng.random() / 500)
                    await current_run.get().decide(f"task{n}-{i}", "read_file", {"path": "a.py"})
        await asyncio.gather(*(one(n) for n in range(WORKERS)))
        await client.close()
    asyncio.run(main())
    return owned


def py_threads(sock):
    owned, client = {}, Client(sock)

    def one(n):
        with client.run("e12-thread") as run:
            owned[run.run_id] = f"thread{n}-"
            for i in range(CALLS):
                time.sleep(rng.random() / 500)
                current_run.get().decide(f"thread{n}-{i}", "read_file", {"path": "a.py"})
    threads = [threading.Thread(target=one, args=(n,)) for n in range(WORKERS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    client.close()
    return owned


TS = """
const { Client, withRun, currentRun } = await import(process.env.E12_CLIENT);
const [workers, calls] = [Number(process.env.E12_WORKERS), Number(process.env.E12_CALLS)];
const c = new Client({ signer: process.env.E12_SOCK });
const owned = {};
await Promise.all(Array.from({ length: workers }, async (_, n) => {
  const run = await c.registerRun("e12-ts");
  owned[run.runId] = `ts${n}-`;
  await withRun(run, async () => {
    for (let i = 0; i < calls; i++) {
      await new Promise((r) => setTimeout(r, Math.random() * 2));
      await currentRun().decide(`ts${n}-${i}`, "read_file", { path: "a.py" });
    }
  });
  await run.close();
}));
await c.close();
console.log(JSON.stringify(owned));
"""


def ts_promises(sock):
    """(owned, None) or (None, why it was skipped)."""
    client = pathlib.Path(ROOT, "sdk", "typescript", "dist", "v2", "client.js")
    if not shutil.which("node"):
        return None, "node is not installed"
    if not client.exists():
        return None, f"{client} is not built (make test-ts)"
    env = dict(os.environ, E12_CLIENT=client.as_uri(), E12_SOCK=sock, E12_WORKERS=str(WORKERS), E12_CALLS=str(CALLS))
    p = subprocess.run(["node", "--input-type=module", "-e", TS], env=env, capture_output=True, text=True, timeout=120)
    if p.returncode:
        raise SystemExit(f"the Node part failed:\n{p.stderr}")
    return json.loads(p.stdout.splitlines()[-1]), None


def in_process(d):
    data = os.path.join(d, "serve")
    p, sock = v2_signer(data)
    owned, skipped = {}, {}
    try:
        parts = {"python_asyncio_tasks": py_tasks(sock), "python_threads": py_threads(sock)}
        parts["node_async_local_storage"], why = ts_promises(sock)
        if why:
            skipped["node_async_local_storage"] = why
            del parts["node_async_local_storage"]
    finally:
        p.terminate()
        p.wait(30)
    calls = store_calls(data)
    for name, o in parts.items():
        owned[name] = leaks(o, calls)
    return owned, skipped


def main():
    if os.name != "posix":
        raise SystemExit("E12 needs POSIX (Unix sockets)")
    d = tempfile.mkdtemp(prefix="e12-", dir="/tmp")   # short socket paths
    try:
        cases = cross_tenant(d)
        leak, skipped = in_process(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    for name, c in cases.items():
        print(f"{name}: {'refused' if c['refused'] else 'NOT REFUSED'} {c['attempts']}", flush=True)
    for name, x in leak.items():
        print(f"{name}: {'no leak' if not any(x.values()) else 'LEAK'} {x}", flush=True)
    for name, why in skipped.items():
        print(f"{name}: skipped, {why}", flush=True)
    ok = all(c["refused"] for c in cases.values()) and not any(v for x in leak.values() for v in x.values())
    out = {"platform": sys.platform, "python": sys.version.split()[0], "workers": WORKERS, "calls_per_worker": CALLS,
           "cross_tenant": cases, "in_process": leak, "skipped": skipped, "all_refused_and_no_leak": ok}
    print("wrote", write_results("e12_cross_tenant", out))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
