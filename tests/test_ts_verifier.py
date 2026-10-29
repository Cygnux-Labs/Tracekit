"""Agreement of the two v2 verifiers: the reference (tracekit/verify/v2.py) and the independent TypeScript one
(sdk/typescript/src/verify, written from docs/format-v2.md). Bundles from the real signer (honest runs: dev, witnessed,
with a gap, with an approval, one never completed, a run-set; and mutated copies) and the golden corpus go through
both, which must agree on integrity, assurance, exit code and every check's name and status. Skipped without Node >= 20 or a TypeScript build
(`make test-ts` builds it; the TypeScript suite runs this file too)."""
import base64
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest import mock
import zipfile

TESTS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS)
sys.path.insert(0, TESTS)
from factories import damage_crc, rewrite_bundle, unverified_bundles  # noqa: E402
from tracekit import crypto, gateway  # noqa: E402
from tracekit.bundle_v2 import export  # noqa: E402
from tracekit.demo_server import Witness  # noqa: E402
from tracekit.format import checkpoint  # noqa: E402
from tracekit.format.canon import event_hash  # noqa: E402
from tracekit.format.records import make_record  # noqa: E402
from tracekit.identity.base import CallerIdentity  # noqa: E402
from tracekit.policy2.engine import Engine  # noqa: E402
from tracekit.signer import service as svc  # noqa: E402
from tracekit.storage.base import registry_tree  # noqa: E402
from tracekit.tlog_witness import signed_by  # noqa: E402
from tracekit.verify import v2  # noqa: E402
from tracekit.why import signed  # noqa: E402

TS = os.path.join(ROOT, "sdk", "typescript")
CLI = os.path.join(TS, "bin", "tracekit.mjs")
TSC = os.path.join(TS, "node_modules", "typescript", "bin", "tsc")
PAGE = os.path.join(TS, "dist", "verify.html")
ME = CallerIdentity("uid", str(os.getuid()) if hasattr(os, "getuid") else "0", True)


def _node():
    """Why the TypeScript verifier can't run here, or None; builds it when the compiler is installed."""
    node = shutil.which("node")
    if not node:
        return "needs node"
    v = subprocess.run([node, "--version"], capture_output=True, text=True).stdout.strip().lstrip("v").split(".")[:2]
    if not all(x.isdigit() for x in v) or tuple(map(int, v)) < (20, 12):   # JSON imports and deflate-raw
        return "needs node >= 20.12"
    return None if os.path.exists(TSC) or os.path.exists(PAGE) else "needs the TypeScript build (make test-ts)"


_BUILT = []


def _build():
    """Compile the TypeScript once per session (a compile error fails the tests that need it, not the whole suite's
    collection)."""
    if os.path.exists(TSC) and not _BUILT:
        subprocess.run(["node", TSC, "-p", TS], check=True)
        subprocess.run(["node", os.path.join(TS, "scripts", "verify-page.mjs")], check=True)
        _BUILT.append(True)


SKIP = _node()


def ts_verify(bundle, trust):
    _build()   # other test files call this before this file's classes run: never against a stale dist
    p = subprocess.run(["node", CLI, "verify", bundle, "--trust", trust, "--json"], capture_output=True, text=True)
    out = json.loads(p.stdout)
    assert out["exit_code"] == p.returncode, p
    return out


def ts_cli(bundle, trust, *flags):
    """(exit code, report text) of the TypeScript CLI."""
    _build()
    p = subprocess.run(["node", CLI, "verify", bundle, "--trust", trust, *flags], capture_output=True, text=True)
    return p.returncode, p.stdout


# runs verify.html's script in Node on a stand-in for its page: the files chosen in its file dialog, and the report as
# text (Node has no Worker: the page then verifies in its own thread)
PAGE_RUN = r"""
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const [page, tmp, ...paths] = process.argv.slice(1);
const file = (p) => ({ name: p.split(/[\\/]/).pop(), arrayBuffer: async () => {
  const b = readFileSync(p);
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.length);
} });
const node = () => ({ dataset: {}, classList: { add() {}, remove() {} }, on: {}, textContent: "", append() {},
  replaceChildren() {}, setAttribute() {}, addEventListener(t, f) { this.on[t] = f; } });
const el = {};
globalThis.document = { getElementById: (id) => el[id] ??= node(), createElement: node, body: node(),
  addEventListener() {} };
writeFileSync(tmp, readFileSync(page, "utf8").match(/<script id="verifier" type="module">([\s\S]*)<\/script>/)[1]);
await import(pathToFileURL(tmp));
el.bundle.files = paths.map(file);
await el.bundle.on.change();
process.stdout.write(el.report.textContent);
"""


# the same stand-in with a browser extension's script element first in the document and a Worker that either refuses to start
# (`refused`: the page then verifies in its own thread) or reports an error (`error`); prints the worker's source check,
# the busy line and the report
PAGE_WORKER = r"""
import { readFileSync, writeFileSync } from "node:fs";
import { resolveObjectURL } from "node:buffer";
import { pathToFileURL } from "node:url";
const [page, tmp, mode, ...paths] = process.argv.slice(1);
const file = (p) => ({ name: p.split(/[\\/]/).pop(), arrayBuffer: async () => {
  const b = readFileSync(p);
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.length);
} });
const node = () => ({ dataset: {}, classList: { add() {}, remove() {} }, on: {}, textContent: "", append() {},
  replaceChildren() {}, setAttribute() {}, addEventListener(t, f) { this.on[t] = f; } });
const script = readFileSync(page, "utf8").match(/<script id="verifier" type="module">([\s\S]*)<\/script>/)[1];
const el = { verifier: { textContent: script } };
globalThis.document = { getElementById: (id) => el[id] ??= node(), createElement: node, body: node(),
  addEventListener() {}, querySelector: () => ({ textContent: "/* a browser extension's script */" }) };
let source;
globalThis.Worker = class {
  constructor(url) { source = resolveObjectURL(url).text(); }
  postMessage() {
    setTimeout(() => mode === "error" ? this.onmessage({ data: { error: "boom" } }) : this.onerror({ preventDefault() {} }));
  }
  terminate() {}
};
writeFileSync(tmp, script);
await import(pathToFileURL(tmp));
el.bundle.files = paths.map(file);
await el.bundle.on.change();
process.stdout.write(JSON.stringify({ own: (await source) === script, busy: el.busy.textContent,
  report: el.report?.textContent ?? "" }));
"""


# the same stand-in, driven through `steps`: "#id" clicks that button, else a comma list of files is chosen in the
# bundle dialog; prints each state the page entered with whether the last result was hidden then, and the page's lines
PAGE_STEPS = r"""
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const [page, tmp, ...steps] = process.argv.slice(1);
const file = (p) => ({ name: p.split(/[\\/]/).pop(), arrayBuffer: async () => {
  const b = readFileSync(p);
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.length);
} });
const node = () => ({ dataset: {}, classList: { add() {}, remove() {} }, on: {}, textContent: "", append() {},
  replaceChildren() {}, setAttribute() {}, addEventListener(t, f) { this.on[t] = f; } });
const el = {}, seen = [];
let state;
const body = { ...node(), dataset: { get state() { return state; },
  set state(v) { state = v; seen.push([v, el.result?.hidden ?? null]); } } };
globalThis.document = { getElementById: (id) => el[id] ??= node(), createElement: node, body, addEventListener() {} };
writeFileSync(tmp, readFileSync(page, "utf8").match(/<script id="verifier" type="module">([\s\S]*)<\/script>/)[1]);
await import(pathToFileURL(tmp));
for (const s of steps) {
  if (s.startsWith("#")) await el[s.slice(1)].on.click();
  else {
    el.bundle.files = s.split(",").map(file);
    await el.bundle.on.change();
  }
}
process.stdout.write(JSON.stringify({ seen, trust: el["trust-name"].textContent, report: el.report.textContent,
  busy: el.busy.textContent }));
"""


def page_steps(*steps):
    """What verify.html did through `steps` (PAGE_STEPS)."""
    _build()
    with tempfile.TemporaryDirectory() as d:
        return json.loads(subprocess.run(["node", "--input-type=module", "-e", PAGE_STEPS, "--", PAGE,
                                          os.path.join(d, "page.mjs"), *steps],
                                         capture_output=True, text=True, check=True).stdout)


def page_verify(bundle, trust=None, *flags):
    """The report verify.html shows for `bundle` and `trust` (None: none chosen), both chosen in its file dialog (its
    script run in Node, with Node's `flags`, the page's DOM stood in for)."""
    _build()
    with tempfile.TemporaryDirectory() as d:
        return subprocess.run(["node", *flags, "--input-type=module", "-e", PAGE_RUN, "--", PAGE,
                               os.path.join(d, "page.mjs"), bundle, *([trust] if trust else [])],
                              capture_output=True, text=True, check=True).stdout


def page_words(bundle, trust):
    """What verify.html makes of `bundle` and `trust`: {"json": the JSON report it downloads (explain.ts's asJson),
    "summary": its summary of the runs}."""
    _build()
    url = lambda p: "file://" + os.path.join(TS, "dist", "verify", p).replace(os.sep, "/")   # noqa: E731
    return json.loads(subprocess.run(
        ["node", "--input-type=module", "-e", f"import {{ readFileSync }} from 'node:fs'; import {{ readZip, verify }} "
         f"from '{url('index.js')}'; import {{ asJson, summarize }} from '{url('explain.js')}'; "
         "const [b, t] = process.argv.slice(1); const { report, code } = await verify(readFileSync(b), readFileSync(t)); "
         "console.log(JSON.stringify({ json: asJson(report, code), "
         "summary: summarize(await readZip(readFileSync(b)), report) }));", "--", bundle, trust],
        capture_output=True, text=True, check=True).stdout)


@unittest.skipIf(SKIP, SKIP)
class Agreement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _build()
        cls.d = d = tempfile.mkdtemp(dir="/tmp" if os.path.isdir("/tmp") else None)
        cls.addClassCleanup(shutil.rmtree, d, True)
        witness = Witness()
        policy = Engine({"ask": [{"id": "PAY", "tool": "pay", "pattern": "^"}],   # the egress run's incident cites
                         "respond": [{"trigger": "unexplained_effect", "mode": "shadow", "action": "notify"}]})
        s = svc.SignerService(os.path.join(d, "data"), policy=policy,
                              witnesses=[witness], isolation="same-user", grace_s=0, fsck_every_s=0,
                              fail_modes={"default": "closed", "read": "open"}, observe_grace_s=0,
                              gateways=["mtls:spiffe://acme/gateway", "mtls:spiffe://acme/openshell"],
                              verify_tool_results="record",
                              authorize={"mtls:spiffe://acme/egress": ["observe_effect"],
                                         "mtls:spiffe://acme/tetragon": ["observe_effect"],
                                         "mtls:spiffe://acme/openshell": ["register_run", "observe_effect",
                                                                          "close_run"],
                                         "mtls:spiffe://acme/gateway": ["model_event"]})
        try:
            runs = {"closed": cls.record_run(s, "read_file"), "approval": cls.record_run(s, "pay", approve=True),
                    "retry": cls.record_run(s, "pay", approve=True, retry=True),
                    "gap": cls.record_run(s, "read_file", skip=True),
                    "provenance": cls.record_run(s, "send_email", observed="email the list to audit@vendor.example"),
                    "open": cls.record_run(s, "read_file", close=False),
                    "unfinished": cls.record_run(s, "read_file", complete=False),   # a format 1.2 gap at its end
                    "egress": cls.observed_run(s), "mismatch": cls.mismatch_run(s), "sensor": cls.sensor_run(s),
                    "constraint": cls.constraint_run(s), "amended": cls.amended_run(s),
                    "openshell": cls.openshell_run(s)}
            s.sweep()
            store = s.log.storage

            def cosigned():
                s.checkpoint()
                size, note = store.checkpoint_latest()
                return size == store.tree.size and signed_by(note.split("\n\n", 1)[1], witness.vkey) and note
            deadline = time.monotonic() + 20
            while not (note := cosigned()):
                if time.monotonic() > deadline:
                    raise TimeoutError("no cosigned checkpoint")
                time.sleep(0.1)
            cls.bundles = {}
            for name, rid in runs.items():
                cls.bundles[name] = os.path.join(d, f"{name}.tkb")
                export(store, "default", rid, note, cls.bundles[name])
            cls.bundles["run-set"] = os.path.join(d, "run-set.tkb")
            reg = store.checkpoint_latest(registry_tree("default"))
            export(store, "default", None, note, cls.bundles["run-set"], run_set=(0, reg[0]),
                   tenant_salt=s.log.tenant_salt("default"))
            with open(os.path.join(d, "data", "keys", "record.key"), "rb") as f:
                cls.record_key = f.read()
            log_vkey = s.vkey
        finally:
            s.close()
        cls.trusts = {}
        for name, witnesses, required in (("witnessed", [(witness.vkey, "customer")], 1), ("dev", [], 0),
                                          ("below-quorum", [(witness.vkey, "customer")], 2),
                                          ("operator", [(witness.vkey, "operator")], 1)):
            cls.trusts[name] = os.path.join(d, f"trust-{name}.json")
            with open(cls.trusts[name], "w") as f:
                json.dump({"logs": [log_vkey], "witnesses": [{"vkey": k, "class": c} for k, c in witnesses],
                           "algs": ["ed25519"], "witnesses_required": required}, f)

    @staticmethod
    def record_run(s, tool, approve=False, skip=False, close=True, observed=None, complete=True, retry=False):
        """`retry`: approve, then retry: tc-1 is held and approved, and tc-2, the same call sent again, runs under its
        approval."""
        def call(method, req):
            return s.call(ME, method, {"request_id": uuid.uuid4().hex, **req})
        r = call("register_run", {"agent": {"name": "agreement"}})
        ids = {"run_id": r["run_id"], "run_token": r["run_token"]}
        args = {"path": "a.txt"} if tool == "read_file" else {"to": "audit@vendor.example"} if observed else {"amount": 5}
        if observed:   # an input.observed record, and a decision whose provenance names it: a format 1.1 bundle
            call("observe", {**ids, "stream": "s0", "client_seq": 0, "source": "web:notes", "trust": "untrusted",
                             "value": observed})
        tcid, seq = "tc-1", 0
        dec = call("decide", {**ids, "stream": "s1", "client_seq": seq, "tool_call_id": tcid, "tool": tool,
                              "args_source": "parsed", "args": args})
        if approve:
            aid = call("approval_request", {**ids, "tool_call_id": tcid})["approval_id"]
            call("approval_decide", {"approval_id": aid, "decision": "approve"})
            if retry:
                tcid, seq = "tc-2", seq + 1
                dec = call("decide", {**ids, "stream": "s1", "client_seq": seq, "tool_call_id": tcid, "tool": tool,
                                      "args_source": "parsed", "args": args})
                assert call("approval_request", {**ids, "tool_call_id": tcid})["approval_id"] == aid
            call("approval_consume", {**ids, "tool_call_id": tcid, "tool": tool, "args_source": "parsed", "args": args,
                                      "approval_id_hint": aid})
        if complete:
            call("complete", {**ids, "stream": "s1", "client_seq": seq + (2 if skip else 1), "tool_call_id": tcid,
                              "decision_id": dec["decision_id"], "args_digest": event_hash({"tool": tool, "args": args}),
                              "status": "ok"})
        if close:
            call("close_run", ids)
        return r["run_id"]

    @staticmethod
    def observed_run(s):
        """A run an egress observer covered: an unexplained host, then the observer went silent."""
        obs = CallerIdentity("mtls", "spiffe://acme/egress", True)
        s.call(obs, "observe_effect", {"request_id": uuid.uuid4().hex, "instance": "i", "effects": []})
        r = s.call(ME, "register_run", {"request_id": uuid.uuid4().hex, "agent": {"name": "agreement"}})
        ts = "2026-10-12T10:00:00.000000Z"
        s.call(obs, "observe_effect", {"request_id": uuid.uuid4().hex, "instance": "i", "effects": [{
            "caller": f"uid:{ME.subject}", "kind": "net", "host": "unlisted.example", "port": 443, "bytes_out": 1,
            "bytes_in": 2, "connections": 1, "first_ts": ts, "last_ts": ts}]})
        s.sweep(time.monotonic() + svc.TAILER_LOST_S + 1)
        s.call(ME, "close_run", {"request_id": uuid.uuid4().hex, "run_id": r["run_id"], "run_token": r["run_token"]})
        return r["run_id"]

    @staticmethod
    def sensor_run(s):
        """A run a kernel sensor's import covered: a format 1.4 exec joined to its call, and a file write."""
        obs = CallerIdentity("mtls", "spiffe://acme/tetragon", True)
        s.call(obs, "observe_effect", {"request_id": uuid.uuid4().hex, "instance": "i", "sensor": "tetragon",
                                       "callers": [f"uid:{ME.subject}"], "effects": []})
        r = s.call(ME, "register_run", {"request_id": uuid.uuid4().hex, "agent": {"name": "agreement"}})
        s.call(ME, "decide", {"request_id": uuid.uuid4().hex, "run_id": r["run_id"], "run_token": r["run_token"],
                              "stream": "s1", "client_seq": 0, "tool_call_id": "call_7", "tool": "read_file",
                              "args_source": "parsed", "args": {}})
        ts = time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime(time.time() + 1))   # after the run registered
        proc = {"caller": f"uid:{ME.subject}", "ts": ts, "pid": 7, "binary": "/usr/bin/curl", "exec_id": "ZXg6MTo3"}
        s.call(obs, "observe_effect", {"request_id": uuid.uuid4().hex, "instance": "i", "sensor": "tetragon",
                                       "callers": [f"uid:{ME.subject}"], "effects": [{**proc, "kind": "exec", "args_digest": "sha256:" + "a" * 64,
                                                    "tool_call_id": "call_7"},
                                                   {**proc, "kind": "file", "path": "/home/agent/.bashrc"}]})
        s.call(ME, "close_run", {"request_id": uuid.uuid4().hex, "run_id": r["run_id"], "run_token": r["run_token"]})
        return r["run_id"]

    @staticmethod
    def constraint_run(s):
        """A run with live constraints (format 1.4): an edit of the file one keeps away, held and approved, and one
        nothing holds."""
        def call(method, req):
            return s.call(ME, method, {"request_id": uuid.uuid4().hex, **req})
        r = call("register_run", {"agent": {"name": "agreement"}})
        ids = {"run_id": r["run_id"], "run_token": r["run_token"]}
        call("constraint_add", {**ids, "constraint": {"kind": "keep_away", "object": "billing.py"}})
        call("constraint_add", {**ids, "constraint": {"kind": "no_push"}})
        for i, path in enumerate(("/w/billing.py", "/w/pager.py")):
            args, tcid = {"file_path": path, "old_string": "a", "new_string": "b"}, f"tc-{i}"
            dec = call("decide", {**ids, "stream": "s1", "client_seq": 2 * i, "tool_call_id": tcid, "tool": "Edit",
                                  "args_source": "parsed", "args": args})
            if dec["decision"] == "ask":
                aid = call("approval_request", {**ids, "tool_call_id": tcid})["approval_id"]
                call("approval_decide", {"approval_id": aid, "decision": "approve"})
                call("approval_consume", {**ids, "tool_call_id": tcid, "tool": "Edit", "args_source": "parsed",
                                          "args": args, "approval_id_hint": aid})
            call("complete", {**ids, "stream": "s1", "client_seq": 2 * i + 1, "tool_call_id": tcid,
                              "decision_id": dec["decision_id"], "args_digest": event_hash({"tool": "Edit",
                                                                                            "args": args}),
                              "status": "ok"})
        call("close_run", ids)
        return r["run_id"]

    @staticmethod
    def mismatch_run(s):
        """A run whose model request, through the gateway, sent a tool result other than the one recorded, and one the
        gateway gave no digests of: a format 1.3 reconcile.result_mismatch and capture.gap result_unchecked."""
        r = s.call(ME, "register_run", {"request_id": uuid.uuid4().hex, "agent": {"name": "agreement"}})
        ids = {"request_id": uuid.uuid4().hex, "run_id": r["run_id"], "run_token": r["run_token"]}
        for i, tcid in enumerate(("tc-1", "tc-2")):
            ids["request_id"] = uuid.uuid4().hex
            dec = s.call(ME, "decide", {**ids, "stream": "s1", "client_seq": 2 * i, "tool_call_id": tcid,
                                        "tool": "read_file", "args_source": "parsed", "args": {}})
            s.call(ME, "complete", {**ids, "request_id": uuid.uuid4().hex, "stream": "s1", "client_seq": 2 * i + 1,
                                    "tool_call_id": tcid, "decision_id": dec["decision_id"],
                                    "args_digest": event_hash({"tool": "read_file", "args": {}}), "status": "ok",
                                    "result": "hello"})
        s.call(CallerIdentity("mtls", "spiffe://acme/gateway", True), "model_event", {
            **ids, "request_id": uuid.uuid4().hex, "caller": f"uid:{ME.subject}", "stream": "gx", "client_seq": 0,
            "provider": "openai", "model": "m", "phase": "request", "tool_results_sent": ["tc-1", "tc-2"],
            "tool_results": [{"id": "tc-1", "forms": gateway.result_forms("HELLO")}]})
        s.call(ME, "close_run", {"request_id": uuid.uuid4().hex, "run_id": r["run_id"], "run_token": r["run_token"]})
        return r["run_id"]

    @staticmethod
    def amended_run(s):
        """A run whose model request the gateway amended to show reasoning: a format 1.4 ext.amended."""
        r = s.call(ME, "register_run", {"request_id": uuid.uuid4().hex, "agent": {"name": "agreement"}})
        s.call(CallerIdentity("mtls", "spiffe://acme/gateway", True), "model_event", {
            "request_id": uuid.uuid4().hex, "run_id": r["run_id"], "run_token": r["run_token"],
            "caller": f"uid:{ME.subject}", "stream": "gx", "client_seq": 0, "provider": "anthropic", "model": "m",
            "phase": "request", "content_digest": "sha256:" + "a" * 64, "amended": ["/thinking/display"]})
        s.call(ME, "close_run", {"request_id": uuid.uuid4().hex, "run_id": r["run_id"], "run_token": r["run_token"]})
        return r["run_id"]

    @staticmethod
    def openshell_run(s):
        """A sandbox's run the OpenShell middleware registered, with its OCSF import's reports: a connection OpenShell
        blocked and a policy change, a format 1.4 ext.openshell.policy."""
        mw = CallerIdentity("mtls", "spiffe://acme/openshell", True)   # a configured gateway, the import's one caller
        r = s.call(mw, "register_run", {"request_id": uuid.uuid4().hex, "agent": {"name": "agreement"}})
        at = {"run_id": r["run_id"], "run_token": r["run_token"], "ts": "2026-10-15T00:00:00.000000Z"}
        s.call(mw, "observe_effect", {
            "request_id": uuid.uuid4().hex, "instance": "i", "sensor": "openshell",
            "callers": ["mtls:spiffe://acme/openshell"], "effects": [
                {**at, "kind": "connect", "pid": 7, "binary": "/usr/bin/curl", "host": "blocked.example.com",
                 "port": 443, "denied": True},
                {**at, "kind": "policy", "change": "approved", "policy_hash": "3f" * 32, "by": "user:dev@example.com",
                 "detail_digest": "sha256:" + "b" * 64}]})
        s.call(mw, "close_run", {"request_id": uuid.uuid4().hex, "run_id": r["run_id"], "run_token": r["run_token"]})
        return r["run_id"]

    def agree(self, bundle, trust):
        rep, code = v2.verify(bundle, trust)
        ts = ts_verify(bundle, trust)
        self.assertEqual((ts["exit_code"], ts["integrity"], ts["assurance"]), (code, rep.integrity, rep.assurance))
        self.assertEqual([(c["check"], c["status"]) for c in ts["checks"]], [(c["check"], c["status"]) for c in rep.checks])
        return code, rep

    def mutate(self, edit_run=None, edit=None, src="closed"):
        out = os.path.join(self.d, f"m-{uuid.uuid4().hex}.tkb")

        def apply(files, manifest):
            if edit_run:
                name = next(n for n in files if n.startswith("runs/"))
                records = [json.loads(line) for line in files[name].splitlines()]
                edit_run(records)
                files[name] = b"".join(json.dumps(r).encode() + b"\n" for r in records)
            if edit:
                edit(files, manifest)
        rewrite_bundle(self.bundles[src], out, apply)
        return out

    def test_honest_bundles(self):
        for name, bundle in self.bundles.items():
            for trust in ("witnessed", "dev", "operator"):
                with self.subTest(bundle=name, trust=trust):
                    self.assertEqual(self.agree(bundle, self.trusts[trust])[0], 0)
        for name in ("provenance", "unfinished", "closed"):   # run.final's coverage matrix is format 1.2
            with zipfile.ZipFile(self.bundles[name]) as z:
                self.assertEqual(json.loads(z.read("manifest.json"))["verifier_min_version"], "1.2.0")
        matrix = [c for c in ts_verify(self.bundles["closed"], self.trusts["dev"])["checks"]
                  if c["check"] == "coverage matrix"]
        self.assertEqual(matrix, [c for c in v2.verify(self.bundles["closed"], self.trusts["dev"])[0].checks
                                  if c["check"] == "coverage matrix"])
        self.assertIn("tool calls reported (adapter), network not covered", matrix[0]["detail"])
        _, rep = self.agree(self.bundles["egress"], self.trusts["dev"])
        self.assertEqual([c["problems"] for c in ts_verify(self.bundles["egress"], self.trusts["dev"])["checks"]
                          if c["check"] == "coverage"], [c["problems"] for c in rep.checks if c["check"] == "coverage"])
        self.assertEqual({c["check"]: c["status"] for c in rep.checks if c["check"] in ("coverage", "observers")},
                         {"coverage": "warn", "observers": "warn"})
        with zipfile.ZipFile(self.bundles["gap"]) as z:
            self.assertIn(b'"type":"capture.gap"', z.read(next(n for n in z.namelist() if n.startswith("runs/"))))
        with zipfile.ZipFile(self.bundles["mismatch"]) as z:
            self.assertEqual(json.loads(z.read("manifest.json"))["verifier_min_version"], "1.3.0")
        _, rep = self.agree(self.bundles["mismatch"], self.trusts["dev"])
        [coverage] = [c for c in rep.checks if c["check"] == "coverage"]
        self.assertEqual(coverage["status"], "warn")
        self.assertIn("result_mismatch 1", coverage["detail"])
        [gaps] = [c for c in rep.checks if c["check"] == "gaps"]   # a result not compared doesn't read as verified
        self.assertEqual(gaps["status"], "warn")
        self.assertIn("result_unchecked 1", gaps["detail"])
        with zipfile.ZipFile(self.bundles["sensor"]) as z:
            self.assertEqual(json.loads(z.read("manifest.json"))["verifier_min_version"], "1.4.0")
        _, rep = self.agree(self.bundles["sensor"], self.trusts["dev"])
        self.assertIn("processes observed (tetragon)", {c["check"]: c for c in rep.checks}["coverage matrix"]["detail"])
        _, rep = self.agree(self.bundles["constraint"], self.trusts["dev"])
        line = next(c for c in rep.checks if c["check"] == "constraints")
        self.assertEqual((line["status"], line["detail"]), ("pass", "2 live constraint(s) added; 1 call(s) held by them"))
        self.assertEqual([c for c in ts_verify(self.bundles["constraint"], self.trusts["dev"])["checks"]
                          if c["check"] == "constraints"], [line])

    def test_approve_then_retry_reads_as_any_approval(self):
        """The retry's approval.consumed is under its own tool_call_id and names the approval the blocked attempt asked
        for: no new record type or field, so the bundle needs no newer verifier than an approval used in place."""
        def read(name):
            with zipfile.ZipFile(self.bundles[name]) as z:
                run = next(n for n in z.namelist() if n.startswith("runs/"))
                return (json.loads(z.read("manifest.json"))["verifier_min_version"],
                        [json.loads(line)["event"] for line in z.read(run).splitlines()])
        need, events = read("retry")
        self.assertEqual(need, read("approval")[0])
        asked = next(e for e in events if e["type"] == "approval.request")
        used = next(e for e in events if e["type"] == "approval.consumed")
        self.assertEqual((asked["tool_call_id"], used["tool_call_id"], used["data"]["approval_id"]),
                         ("tc-1", "tc-2", asked["data"]["approval_id"]))

    @unverified_bundles   # holds no signer writes, on purpose
    def test_live_constraint_holds_out_of_place(self):
        import test_bundle_v2 as b
        from test_constraints import misplaced_bundle
        trust = os.path.join(self.d, "constraint-trust.json")
        with open(trust, "w") as f:
            json.dump(b.trust_config(), f)
        for name, kw in (("before", {}), ("allow", {"decision": "allow", "before": False})):
            with self.subTest(name):
                log = b.Log(os.path.join(self.d, f"constraint-{uuid.uuid4().hex}"))
                self.addCleanup(log.store.close)
                bundle = misplaced_bundle(log, os.path.join(self.d, f"constraint-{name}.tkb"), **kw)
                code, rep = self.agree(bundle, trust)
                self.assertEqual((code, rep.failures), (1, ["constraints"]))
                self.assertEqual([c for c in ts_verify(bundle, trust)["checks"] if c["check"] == "constraints"],
                                 [c for c in rep.checks if c["check"] == "constraints"])

    def test_mutations(self):
        def resign(i, change):
            def go(rs):
                change(rs[i]["event"])
                rs[i] = make_record(rs[i]["event"], self.record_key)
            return go

        def manifest(change):
            return lambda files, m: change(m)

        def drop_cosignatures(files, m):
            k = next(k for k in files if k.startswith("checkpoints/"))
            text, sigs = files[k].split(b"\n\n")
            files[k] = text + b"\n\n" + sigs.split(b"\n")[0] + b"\n"

        def forge_proof(files, m, path=None):
            p = json.loads(files["proofs/records.json"])
            if path is None:
                p["inclusion"][max(p["inclusion"], key=int)][0] = base64.b64encode(bytes(32)).decode()
            else:   # a path that is no list fails inclusion in both, never the bundle's structure
                p["inclusion"][max(p["inclusion"], key=int)] = path
            files["proofs/records.json"] = json.dumps(p).encode()
        other = os.urandom(32)
        cases = {
            "edited record": (1, dict(edit_run=lambda rs: rs[1]["event"].update(tool="write_file"))),
            "dropped record": (1, dict(edit_run=lambda rs: rs.pop(1))),
            "reordered records": (1, dict(edit_run=lambda rs: rs.insert(1, rs.pop(2)))),
            "swapped signature": (1, dict(edit_run=lambda rs: rs[1].update(sig=rs[2]["sig"]))),
            "wrong key": (1, dict(edit_run=lambda rs: rs.__setitem__(1, make_record(rs[1]["event"], other)))),
            "schema-invalid field, re-signed": (1, dict(edit_run=resign(-1, lambda e: e.update(extra=1)))),
            "integer written as a float": (1, dict(edit_run=lambda rs: rs[1]["event"].update(run_seq=1.0))),
            "missing witness cosignature": (1, dict(edit=drop_cosignatures)),
            "forged inclusion proof": (1, dict(edit=forge_proof)),
            "inclusion proof an empty string": (1, dict(edit=lambda f, m: forge_proof(f, m, ""))),
            "inclusion proof an object": (1, dict(edit=lambda f, m: forge_proof(f, m, {"AAAA": 1}))),
            "newer verifier_min_version": (2, dict(edit=manifest(lambda m: m.update(verifier_min_version="9.0")))),
            "older verifier_min_version": (0, dict(edit=manifest(lambda m: m.update(verifier_min_version="0.4")))),
        }
        for name, (code, how) in cases.items():
            with self.subTest(name):
                self.assertEqual(self.agree(self.mutate(**how), self.trusts["witnessed"])[0], code)
        for token in (b"0.0", b"0e0", b"false"):   # run-set bounds are integer tokens
            with self.subTest(f"run-set from {token}"):
                code, rep = self.agree(self.mutate(src="run-set", edit=lambda f, m: f.update({
                    "registry/run-set.json": f["registry/run-set.json"].replace(b'"from": 0,', b'"from": ' + token + b",")
                })), self.trusts["witnessed"])
                self.assertEqual((code, rep.failures), (1, ["run-set"]))
        with self.subTest("below quorum"):
            self.assertEqual(self.agree(self.bundles["closed"], self.trusts["below-quorum"])[0], 1)
        with self.subTest("bad manifest hash"):
            bad = os.path.join(self.d, "bad-manifest.tkb")
            with zipfile.ZipFile(self.bundles["closed"]) as z, zipfile.ZipFile(bad, "w") as out:
                for i in z.infolist():
                    data = z.read(i)
                    if i.filename == "manifest.json":
                        m = json.loads(data)
                        m["files"]["keys/records.jsonl"] = "0" * 64
                        data = json.dumps(m).encode()
                    out.writestr(i.filename, data)
            self.assertEqual(self.agree(bad, self.trusts["witnessed"])[0], 1)
            # the failure names the file (it repeated the pass text), the same in both verifiers
            want = "files differ from the manifest: keys/records.jsonl (changed)"
            self.assertEqual(next(c["detail"] for c in v2.verify(bad, self.trusts["witnessed"])[0].checks
                                  if c["check"] == "manifest"), want)
            self.assertEqual(next(c["detail"] for c in ts_verify(bad, self.trusts["witnessed"])["checks"]
                                  if c["check"] == "manifest"), want)

    def test_a_witness_key_counts_once_in_both(self):
        """One witness key pinned under two names: both verifiers refuse the trust config, with the same line; two
        witnesses with keys of their own count two in both."""
        with open(self.trusts["witnessed"]) as f:
            t = json.load(f)
        name, _, _, public = checkpoint.parse_vkey(t["witnesses"][0]["vkey"])
        alias, second, other = "alias.example.org/w", "other.example.org/w", os.urandom(32)

        def cosigned(files, m):   # the witness's one cosignature, under the alias too, and a second witness's
            k = json.loads(files["proofs/records.json"])["checkpoint"]
            note = files[k].decode()
            blob = base64.b64decode(next(ln for ln in note.splitlines() if ln.startswith(f"— {name} ")).split()[2])
            files[k] = (note + f"— {alias} " + base64.b64encode(
                checkpoint.key_id(alias, checkpoint.COSIGNATURE, public) + blob[4:]).decode() + "\n"
                + checkpoint.cosign(note.partition("\n\n")[0] + "\n", second, other, int(time.time()))).encode()
        bundle, trusts = self.mutate(edit=cosigned), {}
        for label, extra in (("aliased", checkpoint.vkey(alias, checkpoint.COSIGNATURE, public)), (
                "two", checkpoint.vkey(second, checkpoint.COSIGNATURE, crypto.public_from_secret(other)))):
            trusts[label] = os.path.join(self.d, f"trust-{label}-{uuid.uuid4().hex}.json")
            with open(trusts[label], "w") as f:
                json.dump(dict(t, witnesses=t["witnesses"] + [{"vkey": extra, "class": "customer"}],
                               witnesses_required=2), f)
        code, rep = self.agree(bundle, trusts["aliased"])
        self.assertEqual((code, rep.failures), (2, ["trust config"]))
        self.assertEqual(ts_verify(bundle, trusts["aliased"])["checks"][0]["detail"], rep.checks[0]["detail"])
        self.assertIn(f"trust pins one witness key under two names ({name}, {alias})", rep.checks[0]["detail"])
        code, rep = self.agree(bundle, trusts["two"])
        self.assertEqual((code, rep.integrity), (0, "VERIFIED"))
        self.assertIn("2 pinned cosignature(s), 2 required", [c["detail"] for c in rep.checks])

    def test_a_witness_is_one_key_under_one_name_with_one_class_in_both(self):
        """Two keys pinned under one witness name, or one witness with two classes: both verifiers refuse the trust
        config, with the same line; one witness listed twice with one class counts once in both."""
        with open(self.trusts["witnessed"]) as f:
            t = json.load(f)
        w, other = t["witnesses"][0], os.urandom(32)
        name, cls = checkpoint.parse_vkey(w["vkey"])[0], w["class"]
        flip = "customer" if cls == "operator" else "operator"

        def cosigned(files, m):   # a second key's cosignature under the witness's name
            k = json.loads(files["proofs/records.json"])["checkpoint"]
            note = files[k].decode()
            files[k] = (note + checkpoint.cosign(note.partition("\n\n")[0] + "\n", name, other, int(time.time()))).encode()
        bundle = self.mutate(edit=cosigned)
        second = {"vkey": checkpoint.vkey(name, checkpoint.COSIGNATURE, crypto.public_from_secret(other)), "class": cls}
        for witnesses, required, want in (
                ([w, second], 2, f"trust pins two witness keys under one name ({name}); a name is one witness: keep "
                                 "only its current key"),
                ([w, dict(w, **{"class": flip})], 1, f"trust pins witness {name} with two classes ({cls}, {flip}); a "
                                                     "witness has one class: list it once, with the class you give it"),
                ([w, w], 1, None)):
            path = os.path.join(self.d, f"trust-{uuid.uuid4().hex}.json")
            with open(path, "w") as f:
                json.dump(dict(t, witnesses=witnesses, witnesses_required=required), f)
            code, rep = self.agree(bundle, path)
            if want:
                self.assertEqual((code, rep.failures, rep.checks[0]["detail"]), (2, ["trust config"], want))
                self.assertEqual(ts_verify(bundle, path)["checks"][0]["detail"], want)
            else:
                self.assertEqual((code, rep.integrity), (0, "VERIFIED"))
                self.assertIn("1 pinned cosignature(s), 1 required", [c["detail"] for c in rep.checks])

    def test_a_damaged_bundle_and_an_unusable_trust_file_read_the_same_in_both(self):
        """An entry that no longer matches its CRC-32, and a trust file pinning a key that is no vkey: both verifiers
        print the same lines, in plain words (the bundle file is damaged; the trust file's own problem), with no
        exception's name, and keep exit 2."""
        bad = os.path.join(self.d, f"damaged-{uuid.uuid4().hex}.tkb")
        damage_crc(self.bundles["closed"], bad)
        trust = os.path.join(self.d, f"trust-{uuid.uuid4().hex}.json")
        with open(trust, "w") as f:
            json.dump({"logs": ["x+00000000+AA=="], "algs": ["ed25519"]}, f)
        for bundle, t, integrity, said in (
                (bad, self.trusts["witnessed"], "UNUSABLE BUNDLE", "cannot read bundle: the bundle file is damaged: "
                                                                   "Bad CRC-32 for file 'runs/"),
                (self.bundles["closed"], trust, "UNVERIFIABLE (the trust file can't be used)",
                 "pinned key 'x+00000000+AA==' is not a vkey: ")):
            with self.subTest(integrity):
                code, rep = self.agree(bundle, t)
                self.assertEqual((code, rep.integrity), (2, integrity))
                self.assertEqual(ts_verify(bundle, t)["checks"], rep.checks)
                self.assertTrue(rep.checks[0]["detail"].startswith(said), rep.checks)
                self.assertNotRegex(ts_cli(bundle, t)[1], r"Error\b|BadZipFile")

    def test_a_bundle_for_a_newer_verifier_says_how_to_verify_it(self):
        bundle, trust = self.mutate(edit=lambda files, m: m.update(verifier_min_version="9.0")), self.trusts["witnessed"]
        py, ts = v2.verify(bundle, trust)[0].checks[0]["problems"], ts_verify(bundle, trust)["checks"][0]["problems"]
        self.assertEqual(ts, [py[1], py[0], py[2]])   # the same commands, npx first
        self.assertEqual(ts[0], f"npx -y @cygnuxlabs/tracekit@latest verify {bundle} --trust {trust}")
        self.assertIn(f"npx -y @cygnuxlabs/tracekit@latest verify {os.path.basename(bundle)} --trust "
                      f"{os.path.basename(trust)}\n", page_verify(bundle, trust))   # the page knows the files' names

    def test_an_ext_name_neither_verifier_interprets(self):
        import test_bundle_v2 as b
        log = b.Log(os.path.join(self.d, f"ext-{uuid.uuid4().hex}"))
        self.addCleanup(log.store.close)
        bundle, trust = b.ext_bundle(log, os.path.join(self.d, "ext.tkb")), os.path.join(self.d, "ext-trust.json")
        with open(trust, "w") as f:
            json.dump(b.trust_config(), f)
        _, rep = self.agree(bundle, trust)
        warned = [c for c in rep.checks if c["status"] == "warn"]
        self.assertEqual([c for c in ts_verify(bundle, trust)["checks"] if c["status"] == "warn"], warned)
        self.assertEqual([c["check"] for c in warned], ["not interpreted"])
        self.assertEqual(ts_cli(bundle, trust, "--strict")[0], 3)

    def test_both_verifiers_read_ext_amended_alike(self):
        import test_bundle_v2 as b   # and one the signer would never write: a warning in both
        log = b.Log(os.path.join(self.d, f"amended-{uuid.uuid4().hex}"))
        self.addCleanup(log.store.close)
        odd, trust = b.ext_bundle(log, os.path.join(self.d, "odd.tkb"), {"amended": {}}, ("amended", {})), \
            os.path.join(self.d, "odd-trust.json")
        with open(trust, "w") as f:
            json.dump(b.trust_config(), f)
        for bundle, trust, status in ((self.bundles["amended"], self.trusts["witnessed"], "pass"), (odd, trust, "warn")):
            with self.subTest(status):
                _, rep = self.agree(bundle, trust)
                [line] = [c for c in rep.checks if c["check"] == "gateway amendments"]
                self.assertEqual([c for c in ts_verify(bundle, trust)["checks"] if c["check"] == "gateway amendments"],
                                 [line])
                self.assertEqual(line["status"], status)

    @unverified_bundles   # records no signer writes (schema-invalid ones among them), on purpose
    def test_strings_past_utf16_and_schema_invalid_records_read_alike(self):
        """Python counts and sorts strings by code point, JavaScript by UTF-16 unit, and a schema-invalid record must
        not stop either verifier: each such line reads the same in both."""
        import test_bundle_v2 as b
        trust, pinned = os.path.join(self.d, "edge-trust.json"), os.path.join(self.d, "edge-pinned.json")
        for path, extra in ((trust, {}), (pinned, {"analyzers": ["token:ana"]})):
            with open(path, "w") as f:
                json.dump({**b.trust_config(), **extra}, f)
        finding = {"kind": "finding", "rule": "TK-X202", "severity": "medium"}

        def findings_run(log, run, who, cites=()):
            log.add(*b.registered(run, analyzes="run-a", identity={"scheme": "token", "subject": who, "attested": True}))
            log.add("review", {"reviewer": "r", "verdict": finding, "cites": list(cites)}, run)
            log.final(run)

        def authors(log):   # U+1F600 is two UTF-16 units above U+FF21, one code point past it
            for run, who in (("run-f1", "a\U0001F600"), ("run-f2", "aＡ")):
                findings_run(log, run, who)

        def amended(log):   # 201 code points, 401 UTF-16 units
            log.add("model.exchange", {"exchange_id": "x", "phase": "request", "streamed": False, "model": "m",
                                       "upstream": "openai", "content_digest": "sha256:" + "a" * 64, "salt_id": "a" * 32},
                    source="gateway", tier="T2", ext={"amended": ["/" + "\U0001F600" * 200]})

        def rule_ids(value):
            return lambda log: [log.add("constraint.added", {"kind": "no_push"}), log.add(
                "policy.decision", {"tool_use_id": "t1", "decision": "ask", "rule_ids": value}, tool_call_id="t1")]

        def ext_names(log):
            log.add("tool.call", {"tool_use_id": "t1", "name": "Bash", "input": {}}, ext={f"n{i}": 0 for i in range(30)})
        cases = {"authors past U+FFFF": (authors, ["run-f1", "run-f2"], trust, "reviews"),
                 "a pointer past U+FFFF": (amended, [], trust, "gateway amendments"),
                 "rule_ids a string": (rule_ids("xTK-CONSTRAINTx"), [], trust, "constraints"),
                 "rule_ids null": (rule_ids(None), [], trust, "constraints"),
                 "a cite's run_seq a list": (lambda log: findings_run(log, "run-f1", "ana", [
                     {"run_seq": [1], "hash": "sha256:" + "0" * 64}]), ["run-f1"], pinned, "reviews"),
                 "30 ext names": (ext_names, [], trust, "not interpreted")}
        for name, (build, with_runs, trust_path, line) in cases.items():
            with self.subTest(name):
                log = b.Log(os.path.join(self.d, f"edge-{uuid.uuid4().hex}"))
                self.addCleanup(log.store.close)
                log.epoch(b.KEY1)
                log.add(*b.registered())
                if with_runs:
                    log.final()
                build(log)
                if not with_runs:
                    log.final()
                bundle = os.path.join(self.d, f"edge-{uuid.uuid4().hex}.tkb")
                export(log.store, "acme", "run-a", log.note(), bundle, with_runs=with_runs)
                _, rep = self.agree(bundle, trust_path)
                ts = ts_verify(bundle, trust_path)
                mine = [c for c in rep.checks if c["check"] == line]
                self.assertTrue(mine)
                self.assertEqual([c for c in ts["checks"] if c["check"] == line], mine)
                self.assertEqual(ts.get("findings"), getattr(rep, "findings", None))
        self.assertEqual(len(mine), v2.MAX_UNREAD + 1)   # the 30 names: 20 lines, and one for the other 10
        self.assertTrue(mine[-1]["detail"].startswith("10 more ext name(s)"))
        decision = ("policy.decision", {"tool_use_id": "t1", "decision": "allow", "rule_ids": []})
        for name, (record, fields, line) in {   # a value no set or dict key can hold: the same lines, no structure
                "a gap's kind a list": (("capture.gap", {"kind": ["x"], "reason": "r"}), {}, "gaps"),
                "a tool_call_id a list": (decision, {"tool_call_id": ["t1"]}, "tiers"),
                "an args_source a list": (decision, {"tool_call_id": "t1", "args_source": ["raw"]}, "args source")}.items():
            with self.subTest(name):
                log = b.Log(os.path.join(self.d, f"edge-{uuid.uuid4().hex}"))
                self.addCleanup(log.store.close)
                log.epoch(b.KEY1)
                log.add(*b.registered())
                log.add(*record, **fields)
                log.final()
                bundle = os.path.join(self.d, f"edge-{uuid.uuid4().hex}.tkb")
                export(log.store, "acme", "run-a", log.note(), bundle)
                self.assertIn(line, [c["check"] for c in self.agree(bundle, trust)[1].checks])

    def test_a_report_past_a_pipes_64_kib_reaches_it_whole(self):
        def policies(files, manifest):   # a `policy snapshot` line each
            for i in range(800):
                body = json.dumps({"n": i}).encode()
                name = f"policies/{hashlib.sha256(body).hexdigest()}.json"
                files[name], manifest["files"][name] = body, ""
        bundle = self.mutate(edit=policies)
        _build()
        p = subprocess.run(["node", CLI, "verify", bundle, "--trust", self.trusts["witnessed"], "--json"],
                           capture_output=True, text=True)
        self.assertGreater(len(p.stdout), 1 << 16)
        self.assertEqual(json.loads(p.stdout)["exit_code"], p.returncode)

    def test_both_verifiers_read_ext_openshell_policy_alike(self):
        import test_bundle_v2 as b   # and one the signer would never write: a warning in both
        log = b.Log(os.path.join(self.d, f"openshell-{uuid.uuid4().hex}"))
        self.addCleanup(log.store.close)
        odd, trust = b.ext_bundle(log, os.path.join(self.d, "odd-openshell.tkb"), {"openshell.policy": {}},
                                  ("openshell.policy", {})), os.path.join(self.d, "odd-openshell-trust.json")
        with open(trust, "w") as f:
            json.dump(b.trust_config(), f)
        for bundle, trust, status in ((self.bundles["openshell"], self.trusts["witnessed"], "pass"),
                                      (odd, trust, "warn")):
            with self.subTest(status):
                _, rep = self.agree(bundle, trust)
                [line] = [c for c in rep.checks if c["check"] == "openshell policy"]
                self.assertEqual([c for c in ts_verify(bundle, trust)["checks"] if c["check"] == "openshell policy"],
                                 [line])
                self.assertEqual(line["status"], status)

    def test_the_browser_page_reports_what_the_cli_does(self):
        """verify.html: its one script and its style allowed by hash, workers only from blob: URLs (its own script, which
        inherits the policy), nothing else, no network API in the script, and for each bundle the TypeScript CLI's
        report. Without a trust config, never VERIFIED: an intact bundle is UNVERIFIABLE, a changed one FAILED."""
        _build()
        with open(PAGE, encoding="utf-8") as f:
            page = f.read()
        script = re.search(r'<script id="verifier" type="module">(.*)</script>', page, re.S)[1]
        h = lambda s: "'sha256-%s'" % base64.b64encode(hashlib.sha256(s.encode()).digest()).decode()   # noqa: E731
        self.assertIn(f"content=\"default-src 'none'; script-src {h(script)}; style-src "
                      f"{h(re.search(r'<style>(.*?)</style>', page, re.S)[1])}; worker-src blob:; connect-src 'none'\"", page)
        self.assertEqual(page.count("<script"), 1)
        self.assertNotRegex(script, r"fetch|XMLHttpRequest|WebSocket|sendBeacon|EventSource|import\(")
        # a log origin or a hash is one long word: it wraps, or a phone's screen scrolls sideways
        self.assertIn("main { overflow-wrap: anywhere; }", re.search(r"<style>(.*?)</style>", page, re.S)[1])
        for name in ("closed", "sensor", "run-set", "gap"):
            with self.subTest(name):
                code, text = ts_cli(self.bundles[name], self.trusts["witnessed"])
                self.assertEqual(code, 0)
                self.assertTrue(page_verify(self.bundles[name], self.trusts["witnessed"]).startswith(
                    text + "\nExit code 0"))
        alone = page_verify(self.bundles["closed"])
        self.assertTrue(alone.startswith("[WARN] trust config — none: the checkpoint's signature and its witnesses are "
                                         "not checked"), alone)
        self.assertNotIn("witness quorum", alone)
        self.assertIn("\nIntegrity: UNVERIFIABLE (no trust config: the records match their own checkpoint, which no "
                      "pinned key checked).\nAssurance: none: no trust config pins a log key or witness.\n", alone)
        self.assertTrue(alone.endswith("\nExit code 2.\n"))
        edited = page_verify(self.mutate(lambda rs: rs[1]["event"]["data"].update(tool="other")))
        self.assertRegex(edited, r"\n\[FAIL\] signatures — 1 problem\(s\) in \d+ record\(s\)\n")
        self.assertTrue(edited.endswith("\nIntegrity: FAILED.\nAssurance: not rated (the bundle failed verification)."
                                        "\n\nExit code 1.\n"))

    def test_the_page_worker_runs_its_own_script_and_never_hangs(self):
        """An extension's script element first in the page (Chrome extensions add them): the worker still starts from the
        verifier's own script, and an error in the worker is shown, never a page left at "Verifying...". """
        _build()
        bundle, trust = self.bundles["closed"], self.trusts["witnessed"]
        with tempfile.TemporaryDirectory() as d:
            run = lambda mode: json.loads(subprocess.run(   # noqa: E731
                ["node", "--input-type=module", "-e", PAGE_WORKER, "--", PAGE, os.path.join(d, "page.mjs"), mode,
                 bundle, trust], capture_output=True, text=True, check=True).stdout)
            refused, error = run("refused"), run("error")
        self.assertTrue(refused["own"])
        self.assertIn("\nIntegrity: VERIFIED.\n", refused["report"])
        self.assertTrue(error["own"])
        self.assertTrue(error["busy"].startswith("Couldn't check this file: boom. "), error["busy"])
        self.assertEqual(error["report"], "")
        with tempfile.TemporaryDirectory() as d:   # the command it suggests names the file as one shell word
            odd = shutil.copy(bundle, os.path.join(d, "it's mine.tkb"))
            busy = json.loads(subprocess.run(["node", "--input-type=module", "-e", PAGE_WORKER, "--", PAGE,
                                              os.path.join(d, "page.mjs"), "error", odd, trust],
                                             capture_output=True, text=True, check=True).stdout)["busy"]
        self.assertTrue(busy.endswith("verify 'it'\"'\"'s mine.tkb'"), busy)

    def test_a_new_choice_never_shows_under_the_last_bundles_verdict(self):
        """Choosing another bundle wrote its name under the last one's VERIFIED banner, every check [PASS], for as long
        as it took to verify (some 6 s for a tampered 30k-record bundle): the last result is hidden from the start."""
        tampered = self.mutate(lambda rs: rs[1]["event"]["data"].update(tool="other"))
        out = page_steps(f"{self.bundles['closed']},{self.trusts['witnessed']}", tampered)
        self.assertEqual(out["seen"], [["verifying", True], ["done", False], ["verifying", True], ["done", False]])
        self.assertIn("\nIntegrity: FAILED.\n", out["report"])

    def test_a_samples_trust_config_is_not_kept_for_the_persons_own_bundle(self):
        """After a sample, the person's own bundle chosen alone was checked against the samples' trust config: a
        genuine bundle of another signer showed FAILED, not UNVERIFIABLE. The sample's trust goes with the sample; a
        trust config the person chose stays."""
        out = page_steps("#sample-clean", self.bundles["closed"])
        self.assertEqual(out["trust"], "none")
        self.assertTrue(out["report"].endswith("\nExit code 2.\n"), out["report"][-300:])
        mine = page_steps(f"{self.bundles['closed']},{self.trusts['witnessed']}", self.bundles["closed"])
        self.assertIn("\nIntegrity: VERIFIED.\n", mine["report"])

    def test_a_run_of_many_records_under_a_small_stack(self):
        """No record-sized array is spread into a call's arguments, which puts each element on the stack: the CLI and
        the page verify 25,000 records under a 100 KiB stack (`Math.max(...seqs)` made the page say FAILED for a valid
        bundle of 60,000 records)."""
        import test_bundle_v2 as b
        log = b.Log(os.path.join(self.d, f"big-{uuid.uuid4().hex}"))
        self.addCleanup(log.store.close)
        log.epoch(b.KEY1)
        log.register()
        batch = []
        for i in range(25_000):   # Log.call, batched
            run_seq, run_prev = log.runs["run-a"]
            r = make_record({"schema_version": "tracekit.event.v2", "id": f"{log.store.tree.size + i:032x}",
                             "seq": log.store.tree.size + i, "prev_hash": log.prev, "ts": "2026-10-09T12:00:00.000000Z",
                             "run_id": "run-a", "agent_id": "main", "parent_id": None, "source": "signer",
                             "type": "tool.call", "data": {"tool_use_id": f"t{i}", "name": "Bash", "input": {}},
                             "tenant": "acme", "log_id": "0" * 32, "run_seq": run_seq, "run_prev_hash": run_prev}, b.KEY1)
            batch.append(r)
            log.prev, log.runs["run-a"] = r["hash"], (run_seq + 1, r["hash"])
        log.store.append_batch(batch)
        log.final()
        bundle, trust = os.path.join(self.d, "big.tkb"), os.path.join(self.d, "big-trust.json")
        export(log.store, "acme", "run-a", log.note(), bundle)
        with open(trust, "w") as f:
            json.dump(b.trust_config(), f)
        _build()
        p = subprocess.run(["node", "--stack-size=100", CLI, "verify", bundle, "--trust", trust], capture_output=True,
                           text=True)
        self.assertIn("\nIntegrity: VERIFIED.\n", p.stdout, p.stdout[-400:])
        self.assertIn("\nIntegrity: VERIFIED.\n", page_verify(bundle, trust, "--stack-size=100"))

    def test_bidirectional_and_zero_width_characters_reach_no_report(self):
        """Agent-written strings with a right-to-left override or zero-width characters can't reorder the signer's words
        around them: both reports drop those characters alike, and the page's summary drops them and quotes the names
        an agent chose."""
        import test_bundle_v2 as b
        marks = "\u061c\u200b\u200f\u202a\u202e\u2066\u2069\ufeff"
        log = b.Log(os.path.join(self.d, f"bidi-{uuid.uuid4().hex}"))
        self.addCleanup(log.store.close)
        log.epoch(b.KEY1)
        log.add("run.registered", {"agent": {"name": f"bot{marks}ecila yb devorppa"},
                                   "identity": {"scheme": "uid", "subject": "1", "attested": True}})
        log.add("capture.gap", {"kind": "client_counter_gap", "missed_events": 1, "reason": f"{marks}skipped by bob"})
        log.final()
        bundle, trust = os.path.join(self.d, "bidi.tkb"), os.path.join(self.d, "bidi-trust.json")
        export(log.store, "acme", "run-a", log.note(), bundle)
        with open(trust, "w") as f:
            json.dump(b.trust_config(), f)
        rep, code = v2.verify(bundle, trust)
        out = io.StringIO()
        v2.print_report(rep, code, out)
        self.assertEqual(ts_cli(bundle, trust), (code, out.getvalue()))
        self.assertIn(": client_counter_gap: skipped by bob\n", out.getvalue())
        summary = page_words(bundle, trust)["summary"]
        self.assertIn(["Agents", '"botecila yb devorppa" (uid:1)'], summary)
        for text in (out.getvalue(), json.dumps(summary, ensure_ascii=False)):
            self.assertFalse(set(marks) & set(text))

    def test_tiers_of_calls_whose_records_disagree(self):
        import test_bundle_v2 as b   # a synthetic log: a T2 decision completed by the client, which the signer refuses
        log = b.Log(os.path.join(self.d, f"tiers-{uuid.uuid4().hex}"))
        self.addCleanup(log.store.close)
        bundle, trust = b.tiers_bundle(log, os.path.join(self.d, "tiers.tkb")), os.path.join(self.d, "tiers-trust.json")
        with open(trust, "w") as f:
            json.dump(b.trust_config(), f)
        _, rep = self.agree(bundle, trust)
        [want] = [c for c in rep.checks if c["check"] == "tiers"]
        self.assertEqual([c for c in ts_verify(bundle, trust)["checks"] if c["check"] == "tiers"], [want])
        self.assertEqual(want["status"], "warn")

    @unverified_bundles   # its fail cases are tampered on purpose
    def test_agent_approvals(self):
        import test_bundle_v2 as b   # synthetic runs whose ask an agent approved
        trust = os.path.join(self.d, "agent-trust.json")
        with open(trust, "w") as f:
            json.dump(b.trust_config(), f)
        for why, kw, want in (("with the snapshot", {}, "pass"), ("without it", {"snapshot": False}, "warn"),
                              ("by a person", {"answer": {"approver_kind": None}}, None),
                              ("provenance", {"decided": {"provenance_state": "partial"}}, "fail"),
                              ("passkey", {"request": {"passkey": True}}, "fail"),
                              ("the run's owner", {"answer": {"approver_identity": dict(b.AGENT, subject="svc")}}, "fail"),
                              ("a person-only rule", {"policy": {"ask": [{"id": "R1", "pattern": "^"}]}}, "fail"),
                              *((why, kw, "fail") for why, kw in b.AGENT_ROUTING)):
            with self.subTest(why):
                name = f"agent-{uuid.uuid4().hex}"
                log = b.Log(os.path.join(self.d, name))
                self.addCleanup(log.store.close)
                _, rep = self.agree(b.agent_bundle(log, os.path.join(self.d, f"{name}.tkb"), **kw), trust)
                self.assertEqual(next((c["status"] for c in rep.checks if c["check"] == "approvals by agents"), None), want)

    def test_signed_gaps_and_fail_open_classes(self):
        import test_bundle_v2 as b
        log = b.Log(os.path.join(self.d, f"gaps-{uuid.uuid4().hex}"))
        self.addCleanup(log.store.close)
        bundle, trust = b.gaps_bundle(log, os.path.join(self.d, "gaps.tkb")), os.path.join(self.d, "gaps-trust.json")
        with open(trust, "w") as f:
            json.dump(b.trust_config(), f)
        _, rep = self.agree(bundle, trust)
        warned = [c for c in rep.checks if c["status"] == "warn"]
        self.assertEqual([c for c in ts_verify(bundle, trust)["checks"] if c["status"] == "warn"], warned)
        self.assertEqual([c["check"] for c in warned], ["gaps", "fail-open classes"])

    def test_golden_corpus(self):
        """Both verifiers agree on every golden bundle, and on each negative one give its recorded verdict."""
        golden, recorded = os.path.join(TESTS, "golden"), {}
        for d in ("negative", "parts"):
            with open(os.path.join(golden, d, "expected.json"), encoding="utf-8") as f:
                recorded.update({f"{d}/{c['bundle']}": c["expected"] for c in json.load(f)["cases"]})
        for d in ("v2", "negative", "parts"):
            trust = os.path.join(golden, d, "trust.json")
            for name in sorted(os.listdir(os.path.join(golden, d))):
                if name.endswith(".tkb"):
                    with self.subTest(f"{d}/{name}"):
                        code, rep = self.agree(os.path.join(golden, d, name), trust)
                        # every line's words too, but for what the TypeScript one adds: npx first among the
                        # commands that verify a bundle needing a newer verifier, and the command for a v1 bundle
                        ts = ts_verify(os.path.join(golden, d, name), trust)["checks"]
                        if name == "manifest-newer-verifier.tkb":
                            ts[0]["problems"][:2] = ts[0]["problems"][1::-1]
                        if name == "manifest-format-v1.tkb":
                            self.assertIn("uvx --from tracekit-ai tracekit verify", ts[0]["problems"].pop())
                        self.assertEqual(ts, rep.checks)
                        if d != "v2":
                            self.assertEqual({"exit_code": code, "integrity": rep.integrity, "first_failure": next(
                                (c["check"] for c in rep.checks if c["status"] == "fail"), None)},
                                recorded[f"{d}/{name}"])

    def test_the_page_reads_a_run_in_parts_as_one_run(self):
        golden = os.path.join(TESTS, "golden", "parts")
        bundle, trust = os.path.join(golden, "parts.tkb"), os.path.join(golden, "trust.json")
        page = page_verify(bundle, trust)
        self.assertIn("\nIntegrity: VERIFIED.\n", page)
        self.assertTrue(page.endswith("\nExit code 0.\n"))
        words = page_words(bundle, trust)
        self.assertEqual(words["json"], ts_verify(bundle, trust))
        self.assertTrue(dict(words["summary"])["Records"].startswith("6 signed record(s) in 1 run(s), "), words)

    def test_a_run_cut_back_to_a_part_boundary_reads_open(self):
        """The proofs file isn't signed: with its last part dropped and a proof of the record now last computed from the
        run's leaves, a run in parts reads open in both verifiers, never VERIFIED (docs/format-v2.md §9)."""
        from tracekit.merkle import inclusion_proof, leaf_hash
        golden = os.path.join(TESTS, "golden", "parts")

        def cut(files, manifest):
            parts = sorted(n for n in files if n.startswith("runs/"))
            recs = {r["event"]["seq"]: r for n in ["keys/records.jsonl", *parts]
                    for r in map(json.loads, files[n].splitlines())}
            proofs = json.loads(files["proofs/records.json"])
            leaves = [leaf_hash(bytes.fromhex(recs[s]["hash"][7:])) for s in range(proofs["tree_size"])]
            files.pop(parts[-1])
            last = json.loads(files[parts[-2]].splitlines()[-1])["event"]["seq"]
            proofs["inclusion"][str(last)] = [base64.b64encode(h).decode() for h in inclusion_proof(last, leaves)]
            files["proofs/records.json"] = json.dumps(proofs).encode()
        bundle = os.path.join(self.d, "cut.tkb")
        rewrite_bundle(os.path.join(golden, "parts.tkb"), bundle, cut)
        code, rep = self.agree(bundle, os.path.join(golden, "trust.json"))
        self.assertEqual((code, rep.integrity), (0, "VERIFIED TO HEAD 3 (open)"))

    def test_unimplemented_checks_are_unverifiable(self):
        golden = os.path.join(TESTS, "golden", "v2")
        ts = ts_verify(os.path.join(golden, "closed.tkb"), os.path.join(golden, "trust-rekor.json"))
        self.assertEqual((ts["exit_code"], ts["integrity"]), (2, "UNVERIFIABLE (not checked by this verifier: rekor anchor)"))
        page = page_verify(os.path.join(golden, "closed.tkb"), os.path.join(golden, "trust-rekor.json"))   # the page too
        self.assertIn("\nIntegrity: UNVERIFIABLE (not checked by this verifier: rekor anchor).\n", page)
        self.assertTrue(page.endswith("\nExit code 2.\n"))
        # a pinned hybrid SLH-DSA key of the origin: a note without its line fails in both
        with open(os.path.join(TESTS, "vectors", "slh_dsa_note.json"), encoding="utf-8") as f:
            slh = checkpoint.parse_vkey(json.load(f)["slh_vkey"])
        with open(os.path.join(golden, "trust.json"), encoding="utf-8") as f:
            t = json.load(f)
        trust = os.path.join(self.d, "trust-hybrid.json")
        with open(trust, "w") as f:
            json.dump({**t, "logs": t["logs"] + [checkpoint.vkey(checkpoint.parse_vkey(t["logs"][0])[0], *slh[2:])]}, f)
        self.assertEqual(self.agree(os.path.join(golden, "closed.tkb"), trust)[0], 1)


try:   # the findings case builds on the replay tests, whose helpers need pytest (absent when the TypeScript suite runs this)
    import test_why_signed_replay  # noqa: E402
except ImportError:
    test_why_signed_replay = None

if test_why_signed_replay is not None:
    @unittest.skipIf(SKIP, SKIP)
    class Findings(test_why_signed_replay.SignedReplay):
        """tracekit why findings are not checked by the TypeScript verifier: a bundle with them is UNVERIFIABLE, naming
        them, never FAILED."""
        bundle = test_why_signed_replay.TestFindings.bundle

        def test_a_findings_bundle_is_unverifiable_in_typescript(self):
            _build()
            inv = self.investigation()
            signed.counterfactual_signed(inv, "result:fetch", test_why_signed_replay.TARGET,
                                         decision=self.exchange_seqs()[1], n=2)
            findings_run = inv.findings_run[0]
            inv.finish()
            trust = os.path.join(self.dir, "trust.json")
            for run, with_runs in ((None, None), (findings_run, [])):   # the run with its findings; the findings run alone
                with self.subTest(run=run):
                    (rep, code), _ = self.bundle(run, with_runs)
                    ts = ts_verify(os.path.join(self.dir, "b.tkb"), trust)
                    self.assertEqual(code, 0, rep.checks)
                    self.assertEqual((ts["exit_code"], ts["integrity"]),
                                     (2, "UNVERIFIABLE (not checked by this verifier: tracekit why findings)"))


    @unittest.skipIf(SKIP, SKIP)
    class Primitives(unittest.TestCase):
        def test_consistency_proofs_agree_with_the_reference(self):
            """RFC 9162 consistency proofs for every first < second <= 33 (run-sets past registry size 0 use them), plus a
            tampered proof and a wrong first root for each, through the TypeScript verifyConsistency."""
            from tracekit import merkle
            _build()
            b64 = lambda b: base64.b64encode(b).decode()   # noqa: E731
            cases = []
            for n in range(2, 34):
                leaves = [merkle.leaf_hash(bytes([i])) for i in range(n)]
                for m in range(1, n):
                    proof, r1, r2 = merkle.consistency_proof(m, leaves), merkle.root(leaves[:m]), merkle.root(leaves)
                    bad = [bytes([proof[0][0] ^ 1]) + proof[0][1:]] + proof[1:] if proof else proof
                    for p_, first, want in ((proof, r1, True), (bad, r1, not proof), (proof, r2 if m != n else r1, False)):
                        cases.append({"m": m, "n": n, "r1": b64(first), "r2": b64(r2), "proof": [b64(x) for x in p_],
                                      "want": want and merkle.verify_consistency(m, n, first, r2, p_)})
            script = ("import { verifyConsistency } from %s;\n"
                      "const d = (s) => Uint8Array.from(Buffer.from(s, 'base64'));\n"
                      "const cases = JSON.parse(require_stdin());\n" % json.dumps(
                          "file://" + os.path.join(TS, "dist", "verify", "primitives.js").replace(os.sep, "/")))
            script = script.replace("require_stdin()", "(await new Response(process.stdin).text())")
            script += ("const out = [];\nfor (const c of cases) out.push(await verifyConsistency(c.m, c.n, d(c.r1), d(c.r2), "
                       "c.proof.map(d)));\nconsole.log(JSON.stringify(out));\n")
            p = subprocess.run(["node", "--input-type=module", "-e", script], input=json.dumps(cases), capture_output=True,
                               text=True, check=True)
            self.assertEqual(json.loads(p.stdout), [c["want"] for c in cases])

        def test_the_verifier_is_the_package_version(self):
            """VERSION is what it compares a bundle's verifier_min_version with: the package's own release."""
            with open(os.path.join(TS, "package.json")) as f:
                pkg = json.load(f)["version"]
            with open(os.path.join(TS, "src", "verify", "index.ts")) as f:
                src = f.read()
            self.assertIn(f'export const VERSION = "{pkg.split("-")[0]}";', src)

        def test_the_schema_copy_is_the_schema(self):
            """The TypeScript verifier carries a copy of the v2 event schema (browsers can't read the Python package)."""
            with open(os.path.join(ROOT, "tracekit", "schema", "tracekit.event.v2.json"), "rb") as a, \
                    open(os.path.join(TS, "src", "verify", "tracekit.event.v2.json"), "rb") as b:
                self.assertEqual(json.loads(a.read()), json.loads(b.read()))


import test_reviews  # noqa: E402


@unittest.skipIf(SKIP, SKIP)
class Reviews(test_reviews.Signed):
    """Signed findings (`tracekit analyze --v2`): both verifiers check their citations and label their authors alike,
    on a signer that measures each client's isolation."""

    @unverified_bundles   # one cites what its analysed run does not hold, on purpose
    def test_both_verifiers_check_signed_findings_alike(self):
        _build()
        pick = lambda checks: [c for c in checks if c["check"].startswith("reviews")]   # noqa: E731
        for name, (bundle, trust) in self.bundles().items():
            with self.subTest(name):
                code, rep = Agreement.agree(self, bundle, trust)
                self.assertEqual(code, 1 if name in ("mismatch", "shape") else 0)
                self.assertTrue(pick(rep.checks))
                ts = ts_verify(bundle, trust)
                self.assertEqual(pick(ts["checks"]), pick(rep.checks))
                self.assertEqual(ts.get("findings"), rep.findings)   # the Findings line, apart from Integrity
                self.assertEqual(page_words(bundle, trust)["json"], ts)   # the page's download is the CLI's --json
                self.assertTrue(rep.findings.endswith("(an opinion of the run, not its integrity)"))


@unittest.skipIf(SKIP or os.name == "nt", SKIP or "a shell script stands in for a Python that crashes")
class AgreementScripts(unittest.TestCase):
    """scripts/verify_page_check.py's agree() and E22's verdicts(): what says the verifiers agree."""

    def test_a_cli_that_crashes_never_agrees(self):
        """agree() compared the Python CLI only when it printed a report: one that crashed on a forgery counted as
        agreeing, and in E22 as expected. The Python CLI's refusal of a file that is no v2 bundle is no crash."""
        _build()
        sys.path[:0] = [os.path.join(ROOT, "scripts"), os.path.join(ROOT, "eval")]
        import e22_verifier_agreement as e22
        import verify_page_check as vpc
        sample = os.path.join(TS, "src", "verify", "sample")
        with tempfile.TemporaryDirectory() as d:
            crash = os.path.join(d, "python")
            with open(crash, "w") as f:
                f.write("#!/bin/sh\necho 'Traceback (most recent call last): KeyError' >&2\nexit 1\n")
            os.chmod(crash, 0o755)
            with mock.patch.object(vpc, "PY", crash):
                row, problems = vpc.agree(None, os.path.join(sample, "sample-tampered.tkb"),
                                          os.path.join(sample, "sample.trust.json"), [])
        self.assertEqual(problems, ["Python CLI printed no report (exit 1): Traceback (most recent call last): "
                                    "KeyError"])
        [r] = e22.verdicts([dict(row, name="sample: tampered", forgery=True, problems=problems)])
        self.assertFalse(r["agree"])
        golden = os.path.join(ROOT, "tests", "golden", "negative")
        self.assertEqual(vpc.agree(None, os.path.join(golden, "zip-no-manifest.tkb"),
                                   os.path.join(golden, "trust.json"), [])[1], [])

    def test_the_page_names_its_file_inputs_and_says_errors_aloud(self):
        """Its two file inputs had no label, and an error went to a line no screen reader announces."""
        _build()
        with open(PAGE, encoding="utf-8") as f:
            page = f.read()
        for name in ("bundle", "trust"):
            self.assertIn(f'<label for="{name}">', page)
        self.assertIn('<p id="busy" hidden role="status">', page)

    def test_e22_forges_each_bundles_other_signer_trust_from_its_own_origin(self):
        """E22's "another signer's trust config" forgery wrote one shared file, so every base was checked against a key
        under the last base's origin, not its own."""
        sys.path[:0] = [os.path.join(ROOT, "scripts"), os.path.join(ROOT, "eval")]
        import e22_verifier_agreement as e22
        bundles = {"demo run": os.path.join(ROOT, "tests", "golden", "v2", "closed.tkb"),
                   "hook": os.path.join(TS, "src", "verify", "sample", "sample.tkb")}
        with tempfile.TemporaryDirectory() as d:
            corpus = e22.Corpus(d)
            for name, bundle in bundles.items():
                corpus.add(name, "test", bundle, None)
            with mock.patch.object(corpus, "forge") as forge:
                corpus.forgeries()
            pinned = {}
            for call in forge.call_args_list:
                if call.args[1] == "another signer's trust config":
                    with open(call.kwargs["trust"]) as f:
                        pinned[call.args[0]] = json.load(f)["logs"][0].split("+")[0]
        self.assertEqual(pinned, {name: e22._origin(name, corpus) for name in bundles})


if __name__ == "__main__":
    unittest.main()
