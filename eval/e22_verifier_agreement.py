#!/usr/bin/env python3
"""E22: verifier agreement on real bundles. Every bundle is made from scratch the way a user makes it, in a HOME of its
own (no TRACEKIT_* variable; the examples, the hook and `tracekit export` reach that HOME's dev signer), then verified
three ways: `tracekit verify --json`, the TypeScript CLI and the browser page (sdk/typescript/dist/verify.html, in Chrome
through Playwright: headless for every bundle, again with a script added before the page's own as an extension adds
one, and headed for `--headed` of them). The three must give the same verdict, exit code and check lines, by the rules
of scripts/verify_page_check.py; an honest bundle must verify, a forgery must not.

  examples   each offline example of examples/v2 (a scripted model, no API key), with its trust config; one whose
             framework is not installed is skipped (`--python NAME=PY` runs an example with another interpreter)
  demo       `tracekit demo --server`: a witness-cosigned run and its tampered copy
  hook       the Claude Code hook `tracekit init --dev --v2` wires: an allowed, a denied and a held call a person
             approves with `tracekit approvals approve`; exported with the findings `tracekit analyze --v2` signs
  sensors    a run Tetragon and Falco imports covered (tests/test_sensor.py's lines); OpenShell's middleware with its
             OCSF import and an agentsh follower run (bundles of the tests that drive them against a real signer)
  open       a run exported while open, and again once closed
  large      `--calls` tool calls of a scripted client through `tracekit signer serve` (the server pack): the run
             exported open at each tenth, the largest bundle export accepts verified, and once closed (a run past
             64 MiB of records goes in parts; export refuses a bundle past the format's limits: a refusal is noted)
  released   a run of the released 1.2.3 and 1.3.0 signers (their tags, by `git archive`); docs/sample/demo-run.tkb (v1)
  forgeries  of several of the above, the manifest refreshed as a careful forger would: a record edited (and re-hashed),
             deleted, two records swapped, the run truncated, an older checkpoint swapped in, another signer's trust
             config, and every record and the checkpoint re-signed with a forger's keys (a control verifies that copy
             against the forger's own trust config)

    python eval/e22_verifier_agreement.py [--calls N] [--python NAME=PY ...] [--headed N] [--out DIR]

Needs node and the TypeScript build (`make test-ts`); without Playwright the page is left out and the CLIs compared.
Writes eval/results/e22_verifier_agreement.json; exit 0 when every bundle agrees, every honest one verifies and no
forgery does.
"""
import argparse
import base64
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
import uuid
import zipfile
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _stack import ROOT, write_results  # noqa: E402
from tracekit import crypto, merkle  # noqa: E402
from tracekit.bundle_v2 import _jsonl  # noqa: E402
from tracekit.format import checkpoint  # noqa: E402
from tracekit.format.canon import event_hash  # noqa: E402
from tracekit.format.records import RecordSigner  # noqa: E402

EX, TESTS = os.path.join(ROOT, "examples", "v2"), os.path.join(ROOT, "tests")
sys.path[:0] = [os.path.join(ROOT, "scripts"), EX, TESTS]
import verify_page_check as vpc  # noqa: E402

EXAMPLES = ["custom", "langchain", "openai_agents", "claude_agent_sdk", "mcp", "google_adk", "haystack", "llama_index",
            "pydantic_ai", "strands", "agent_framework", "demos/agent_approvers", "demos/completeness",
            "demos/containment", "demos/egress", "demos/prompt_injection", "langchain/injection"]
HARVEST = {   # bundles the tests export from a real signer: name -> the test
    "openshell ocsf": "test_openshell.Ocsf.test_each_class_goes_to_its_sandboxs_run_and_verifies_in_both_verifiers",
    "openshell replaced run": "test_openshell.Supervisor."
                              "test_a_run_the_signer_closed_is_replaced_and_its_bundle_verifies",
    "agentsh follower": "test_follow.TestAgentsh.test_each_decision_is_signed_from_the_end_of_the_log_on"}
RELEASED = ["v1.2.3", "v1.3.0"]
FORGED = ["example custom", "demo run", "hook", "sensors", "openshell ocsf"]   # the bundles forged, each every way


def tk(*argv, cwd=None, check=True, py=sys.executable):
    p = subprocess.run([py, "-m", "tracekit", *argv], cwd=cwd, capture_output=True, text=True)
    if check and p.returncode:
        raise RuntimeError(f"tracekit {argv[0]} exited {p.returncode}: {p.stderr.strip()[-600:]}")
    return p


def final(run_id, out, *config):
    """Export the run once the signer has finalised it (a few seconds after it closes)."""
    deadline = time.monotonic() + 60
    while True:
        tk("export", "--v2", "--run", run_id, *config, "-o", out)
        with zipfile.ZipFile(out) as z:
            if any(b'"type":"run.final"' in z.read(n) for n in z.namelist() if n.startswith("runs/")):
                return out
        if time.monotonic() > deadline:
            raise TimeoutError(f"run {run_id} was not final within 60 s")
        time.sleep(0.5)


# ---- the corpus (run in its own HOME: main() starts this as a child) ----

class Corpus:
    def __init__(self, out):
        self.out, self.cases, self.skipped, self.notes = out, [], [], {}

    def dir(self, name):
        d = os.path.join(self.out, name.replace(" ", "-").replace("/", "-"))
        os.makedirs(d, exist_ok=True)
        return d

    def add(self, name, source, bundle, trust, forgery=False):
        self.cases.append({"name": name, "source": source, "bundle": bundle, "trust": trust, "forgery": forgery})

    def examples(self, pythons):
        for name in EXAMPLES:
            script = os.path.join(EX, name, "agent.py") if os.path.isdir(os.path.join(EX, name)) else \
                os.path.join(EX, name + ".py")
            d = self.dir(f"example {name}")
            p = subprocess.run([pythons.get(name, sys.executable), script, "--scripted"], cwd=d, capture_output=True,
                               text=True, timeout=900)
            bundles = sorted(n for n in os.listdir(d) if n.endswith(".tkb"))
            if p.returncode or not bundles:
                last = (p.stderr.strip().splitlines() or [f"no bundle, exit {p.returncode}"])[-1]
                self.skipped.append({"name": f"example {name}", "why": last[:300]})
                continue
            for n in bundles:
                self.add(f"example {name}" + (", tampered copy" if "tamper" in n else ""), "examples/v2",
                         os.path.join(d, n), os.path.join(d, "trust.json"), forgery="tamper" in n)

    def demo(self):
        d = self.dir("demo")
        kept = tk("demo", "--server", "--keep").stdout.rsplit("kept ", 1)[1].strip()
        for n in ("run.tkb", "tampered.tkb", "trust.json"):
            shutil.copy(os.path.join(kept, n), d)
        shutil.rmtree(kept, True)
        self.add("demo run", "tracekit demo --server", os.path.join(d, "run.tkb"), os.path.join(d, "trust.json"))
        self.add("demo tampered", "tracekit demo --server", os.path.join(d, "tampered.tkb"),
                 os.path.join(d, "trust.json"), forgery=True)

    def hook(self):
        """A Claude Code session through the hooks of `tracekit init --dev --v2`, as Claude Code runs them."""
        from story import HELD, RISKY, SAFE
        from tracekit.integrations import claude_code
        d = self.dir("hook")
        tk("init", "--dev", "--v2", cwd=d)
        with open(os.path.expanduser("~/.claude/settings.json")) as f:
            hooks = json.load(f)["hooks"]

        def hook(event, **fields):
            p = subprocess.Popen(hooks[event][0]["hooks"][0]["command"], shell=True, cwd=d, stdin=subprocess.PIPE,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            p.stdin.write(json.dumps({"hook_event_name": event, "session_id": "e22", **fields}))
            p.stdin.close()
            return p

        def done(p):
            p.stderr.read()
            return p.wait(120)

        done(hook("SessionStart"))
        for tid, command in (("t1", SAFE), ("t2", RISKY), ("t3", HELD)):
            p = hook("PreToolUse", tool_name="Bash", tool_input={"command": command}, tool_use_id=tid)
            if command == HELD:   # "[tracekit] waiting for approval apr-... (rule)": a person approves it
                tk("approvals", "approve", p.stderr.readline().split()[4])
            if done(p) == 0:
                done(hook("PostToolUse", tool_name="Bash", tool_input={"command": command}, tool_use_id=tid,
                          tool_response={"stdout": "ok"}))
        with open(claude_code._state("e22")) as f:
            run_id = json.load(f)["run_id"]
        done(hook("SessionEnd", reason="exit"))
        tk("signer", "trust", "-o", os.path.join(d, "trust.json"))
        self.add("hook", "Claude Code hook (dev signer)", final(run_id, os.path.join(d, "hook.tkb")),
                 os.path.join(d, "trust.json"))
        tk("analyze", "--v2", "--run", run_id)
        out = os.path.join(d, "hook-findings.tkb")
        tk("export", "--v2", "--run", run_id, "--with-findings", "-o", out)
        self.add("hook with findings", "tracekit analyze --v2", out, os.path.join(d, "trust.json"))

    def open_run(self):
        """A run exported while open, then once closed; and the closed run with the open one's checkpoint."""
        from tracekit.sdk.client import Client
        d = self.dir("open")
        tk("signer", "trust", "-o", os.path.join(d, "trust.json"))
        run = Client().run(agent="e22-open")
        for i in range(6):
            run.decide(f"c{i}", "read_file", {"path": f"src/m{i}.py"})
            run.complete(f"c{i}")
            if i == 2:
                tk("export", "--v2", "--run", run.run_id, "-o", os.path.join(d, "open.tkb"))
        run.close()
        final(run.run_id, os.path.join(d, "closed.tkb"))
        for n in ("open", "closed"):
            self.add(f"run {n}", "dev signer", os.path.join(d, f"{n}.tkb"), os.path.join(d, "trust.json"))

        def older(files, manifest):   # the closed run's records under the checkpoint taken while it was open
            with zipfile.ZipFile(os.path.join(d, "open.tkb")) as z:
                old = {n: z.read(n) for n in z.namelist() if n.startswith(("checkpoints/", "proofs/"))}
            for n in [n for n in files if n.startswith(("checkpoints/", "proofs/"))]:
                del files[n], manifest["files"][n]
            files.update(old)
            manifest["files"].update(dict.fromkeys(old, ""))
        self.forge("run closed", "older checkpoint", older)

    def large(self, calls):
        """A scripted client's `calls` tool calls through `tracekit signer serve`, on its Unix socket."""
        from story import AGENT, Signer
        from tracekit.sdk.client import Client
        d = self.dir("large")
        with Signer("extends: packs/server.yaml\ntools: {read_file: fs}\n", {},
                    authorize={f"uid:{os.getuid()}": [*AGENT, "checkpoint_nudge"]},
                    limits={"events_per_s": 10**9, "burst": 10**9}) as signer:
            config, trust = ("--config", signer.config), os.path.join(d, "trust.json")
            tk("signer", "trust", *config, "-o", trust)
            notes, kept = self.notes.setdefault("large", {"calls": calls}), None
            run, t0 = Client().run(agent="e22-large"), time.monotonic()
            for i in range(1, calls + 1):
                if run.decide(f"c{i}", "read_file", {"path": f"src/pkg{i % 97}/mod{i}.py"})["decision"] == "allow":
                    run.complete(f"c{i}")
                if i % max(1, calls // 10) == 0 and i < calls and "refused" not in notes:   # open, every tenth
                    t1, out = time.monotonic(), os.path.join(d, f"open-{i}.tkb")
                    try:
                        tk("export", "--v2", "--run", run.run_id, *config, "-o", out)
                        kept = (i, out)
                    except RuntimeError as e:   # over the bundle limits: the largest accepted is verified
                        notes["refused"] = f"open at {i} calls: {e}"
                    t0 += time.monotonic() - t1   # the calls' time, not the exports'
            run.close()
            notes["calls_per_s"] = round(calls / (time.monotonic() - t0))
            if kept:
                self.add(f"large, open at {kept[0]} calls", "tracekit signer serve", kept[1], trust)
                notes["open_bundle_mb"] = round(os.path.getsize(kept[1]) / 1e6, 1)
            try:
                self.add(f"large, {calls} calls", "tracekit signer serve",
                         final(run.run_id, os.path.join(d, "large.tkb"), *config), trust)
            except RuntimeError as e:
                notes["closed"] = str(e)
        del os.environ["TRACEKIT_SIGNER"]   # Signer's: the dev signer again

    def sensors(self):
        """A run Tetragon's and Falco's imports covered, on an in-process signer, as tests/test_sensor.py drives it."""
        import test_sensor as ts
        from test_signer_service import ME
        from tracekit import sensor
        from tracekit.bundle_v2 import export
        from tracekit.identity.base import CallerIdentity
        from tracekit.policy2.engine import Engine
        from tracekit.signer import service as svc
        d = self.dir("sensors")
        sensors = {n: CallerIdentity("mtls", f"spiffe://acme/{n}", True) for n in ("tetragon", "falco")}
        s = svc.SignerService(os.path.join(d, "data"), policy=Engine({"tools": {"Bash": "shell"}}), grace_s=0,
                              observe_grace_s=60, authorize={f"uid:{ME.subject}": sorted(svc.DEFAULT_GRANTS), **{
                                  f"mtls:{who.subject}": ["observe_effect"] for who in sensors.values()}})
        try:
            def call(who, method, **req):
                return s.call(who, method, {"request_id": uuid.uuid4().hex, **req})
            imports = {n: sensor.Import(types.SimpleNamespace(observe_effect=lambda req, who=who: call(
                who, "observe_effect", **req)), n, ts.RUNS) for n, who in sensors.items()}
            for imp in imports.values():
                imp.flush()   # its first heartbeat: it covers the runs registered from now on
            r = call(ME, "register_run", agent={"name": "coder"})
            ids = {"run_id": r["run_id"], "run_token": r["run_token"]}
            call(ME, "decide", **ids, stream="s1", client_seq=0, tool_call_id="call_7", tool="Bash",
                 args_source="parsed", args={"command": "./install.sh"})
            for text in (ts.exec_line(env={"CODEX_TOOL_CALL_ID": "call_7"}), ts.kprobe_line(
                    "security_socket_connect", ts.CONNECT), ts.kprobe_line("security_file_permission", ts.WRITE),
                    ts.exit_line()):
                imports["tetragon"].add(text)
            for text in (ts.falco_line("Tracekit agent exec", "execve"), ts.falco_line(
                    "Tracekit agent connect", "connect", **{"fd.sip": "93.184.215.14", "fd.sport": 443}),
                    ts.FALCO_DROPS):
                imports["falco"].add(text)
            for imp in imports.values():
                imp.flush()
            call(ME, "close_run", **ids)
            s.sweep(time.monotonic() + 61)
            s.checkpoint()
            export(s.log.storage, "default", r["run_id"], s.log.storage.checkpoint_latest()[1],
                   os.path.join(d, "sensors.tkb"))
            with open(os.path.join(d, "trust.json"), "w") as f:
                json.dump({"logs": [s.vkey], "algs": ["ed25519"]}, f)
        finally:
            s.close()
        self.add("sensors", "Tetragon and Falco imports", os.path.join(d, "sensors.tkb"), os.path.join(d, "trust.json"))

    def harvest(self):
        """The first bundle each HARVEST test verifies, kept."""
        from tracekit.verify import v2
        real = v2.verify
        for name, test in HARVEST.items():
            d, kept = self.dir(name), []

            def keep(bundle, trust, *a, **kw):
                if not kept:
                    kept.append((shutil.copy(bundle, os.path.join(d, "bundle.tkb")),
                                 shutil.copy(trust, os.path.join(d, "trust.json"))))
                return real(bundle, trust, *a, **kw)
            with mock.patch.object(v2, "verify", keep):
                result = unittest.TextTestRunner(stream=io.StringIO()).run(
                    unittest.defaultTestLoader.loadTestsFromName(test))
            if result.wasSuccessful() and kept and not result.skipped:
                self.add(name, test.split(".")[0], *kept[0])
            else:
                why = (result.skipped or result.errors or result.failures or [(None, "no bundle")])[0][1]
                self.skipped.append({"name": name, "why": why.strip().splitlines()[-1][:300]})

    def released(self):
        for tag in RELEASED:
            d = self.dir(f"released {tag}")
            root = os.path.join(d, "src")
            p = subprocess.run(["git", "-C", ROOT, "archive", "--format=zip", tag, "tracekit"], capture_output=True)
            if p.returncode:
                self.skipped.append({"name": f"released {tag}", "why": f"no tag {tag} in this clone"})
                continue
            with zipfile.ZipFile(io.BytesIO(p.stdout)) as z:
                z.extractall(root)
            bundle, trust = os.path.join(d, f"{tag}.tkb"), os.path.join(d, "trust.json")
            p = subprocess.run([sys.executable, "-c", RELEASED_RUN, bundle, trust], cwd=d, capture_output=True,
                               text=True, env={**os.environ, "PYTHONPATH": root})
            if p.returncode:
                self.skipped.append({"name": f"released {tag}", "why": p.stderr.strip().splitlines()[-1][:300]})
                continue
            self.add(f"released {tag}", f"tracekit {tag[1:]} (git archive)", bundle, trust)
        self.add("v1 demo-run.tkb", "docs/sample", os.path.join(ROOT, "docs", "sample", "demo-run.tkb"), None)

    # ---- forgeries ----

    def forge(self, base, how, edit, trust=None):
        from factories import rewrite_bundle
        case = next(c for c in self.cases if c["name"] == base)
        out = os.path.join(os.path.dirname(case["bundle"]), f"{how.replace(' ', '-')}.tkb")
        rewrite_bundle(case["bundle"], out, edit)
        self.add(f"{base}: {how}", "forgery", out, trust or case["trust"], forgery=True)

    def forgeries(self):
        def run(files):   # the bundle's main run: its longest
            return max((n for n in files if n.startswith("runs/")), key=lambda n: files[n].count(b"\n"))

        def lines(edit):
            def apply(files, manifest):
                n = run(files)
                recs = [json.loads(x) for x in files[n].splitlines()]
                edit(recs)
                files[n] = _jsonl(recs)
            return apply

        def edited(recs):   # a decision turned into allow, else a timestamp moved; re-hashed (it can't be re-signed)
            r = next((r for r in recs if r["event"]["data"].get("decision") in ("deny", "ask")), recs[len(recs) // 2])
            if r["event"]["data"].get("decision") in ("deny", "ask"):
                r["event"]["data"]["decision"] = "allow"
            else:
                r["event"]["ts"] = r["event"]["ts"][:-2] + ("1Z" if r["event"]["ts"][-2] != "1" else "2Z")
            r["hash"] = event_hash(r["event"])

        def swapped(recs):
            i = len(recs) // 2
            recs[i - 1], recs[i] = recs[i], recs[i - 1]

        for base in FORGED:
            if not any(c["name"] == base for c in self.cases):
                continue
            self.forge(base, "record edited", lines(edited))
            self.forge(base, "record deleted", lines(lambda recs: recs.pop(len(recs) // 2)))
            self.forge(base, "records swapped", lines(swapped))
            self.forge(base, "run truncated", lines(lambda recs: recs.__delitem__(slice(len(recs) // 2 + 1, None))))
            other = os.path.join(self.dir("forger"), "other-signer.trust.json")
            with open(other, "w") as f:
                json.dump({"logs": [_vkey(_origin(base, self), os.urandom(32))], "algs": ["ed25519"]}, f)
            self.forge(base, "another signer's trust config", lambda files, manifest: None, trust=other)
            forger = os.path.join(self.dir("forger"), f"{base.replace(' ', '-')}.trust.json")
            self.forge(base, "re-signed by a forger", lambda files, manifest: _resign(files, forger))
            self.add(f"{base}: re-signed by a forger, forger's trust config (control)", "forgery",
                     self.cases[-1]["bundle"], forger)


def _origin(base, corpus):
    with zipfile.ZipFile(next(c for c in corpus.cases if c["name"] == base)["bundle"]) as z:
        return next(z.read(n) for n in z.namelist() if n.startswith("checkpoints/")).decode().split("\n", 1)[0]


def _vkey(origin, secret):
    return checkpoint.vkey(origin, checkpoint.ED25519, crypto.public_from_secret(secret))


def _resign(files, trust_out):
    """Every record re-signed with a forger's record key (declared in place of the signer's), the chains rebuilt, the
    proofs from a tree of the forger's (its other leaves made up) and the checkpoint signed with the forger's log key
    under the same origin; witness cosignatures dropped. Writes the trust config pinning the forger's log key."""
    sign, log_secret = RecordSigner(os.urandom(32)), os.urandom(32)
    names = [n for n in files if n.endswith(".jsonl")]
    recs = {n: [json.loads(x) for x in files[n].splitlines()] for n in names}
    hashes, runs = {}, {}
    for r in sorted((r for rs in recs.values() for r in rs), key=lambda r: r["event"]["seq"]):
        e = r["event"]
        if e["type"] == "signer.epoch":
            e["data"]["keys"] = [{"kid": sign.kid, "alg": sign.alg, "spki": base64.b64encode(sign.spki).decode()}]
        e["prev_hash"] = hashes.get(e["seq"] - 1, e["prev_hash"])
        e["run_prev_hash"] = runs.get((e["tenant"], e["run_id"], e["run_seq"] - 1), e["run_prev_hash"])
        r.update(sign(e))
        hashes[e["seq"]] = runs[(e["tenant"], e["run_id"], e["run_seq"])] = r["hash"]
    for n in names:
        files[n] = _jsonl(recs[n])
    [cp] = [n for n in files if n.startswith("checkpoints/")]
    origin, size = files[cp].decode().split("\n")[:2]
    leaves = [merkle.leaf_hash(os.urandom(32)) for _ in range(int(size))]
    for seq, h in hashes.items():
        leaves[seq] = merkle.leaf_hash(bytes.fromhex(h[len("sha256:"):]))
    proofs = json.loads(files["proofs/records.json"])
    proofs["inclusion"] = {s: [base64.b64encode(h).decode() for h in merkle.inclusion_proof(int(s), leaves)]
                           for s in proofs["inclusion"]}
    files["proofs/records.json"] = json.dumps(proofs).encode()
    text = checkpoint.body(origin, int(size), merkle.root(leaves))
    files[cp] = (text + "\n" + checkpoint.sign(text, origin, log_secret)).encode()
    with open(trust_out, "w") as f:
        json.dump({"logs": [_vkey(origin, log_secret)], "algs": ["ed25519"]}, f)


# a released signer's run: two calls, closed, finalised and exported (the API of 1.2.0 to 1.4)
RELEASED_RUN = """
import json, os, sys, tempfile, time, uuid
from tracekit.bundle_v2 import export
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.signer.service import SignerService
s = SignerService(tempfile.mkdtemp(dir="."), grace_s=0)
me = CallerIdentity("uid", str(os.getuid()), True)
call = lambda method, **req: s.call(me, method, {"request_id": uuid.uuid4().hex, **req})
r = call("register_run", agent={"name": "released"})
ids = {"run_id": r["run_id"], "run_token": r["run_token"]}
for i, (tool, args) in enumerate([("read_file", {"path": "README.md"}), ("Bash", {"command": "ls"})]):
    d = call("decide", **ids, stream="s1", client_seq=2 * i, tool_call_id=f"c{i}", tool=tool, args_source="parsed",
             args=args)
    call("complete", **ids, stream="s1", client_seq=2 * i + 1, tool_call_id=f"c{i}", decision_id=d["decision_id"],
         args_digest=event_hash({"tool": tool, "args": args}), status="ok")
call("close_run", **ids)
for _ in range(100):
    s.sweep(time.monotonic() + 60)
    s.checkpoint()
    size, note = s.log.storage.checkpoint_latest()
    if size == s.log.storage.tree.size:
        break
    time.sleep(0.1)
export(s.log.storage, "default", r["run_id"], note, sys.argv[1])
json.dump({"logs": [s.vkey], "algs": ["ed25519"]}, open(sys.argv[2], "w"))
s.close()
"""


def build(out, calls, pythons):
    c = Corpus(out)
    for step in (lambda: c.examples(pythons), c.demo, c.hook, c.open_run, lambda: c.large(calls), c.sensors,
                 c.harvest, c.released, c.forgeries):
        step()
    return {"cases": c.cases, "skipped": c.skipped, "notes": c.notes}


# ---- the comparison ----

EXTENSION = """(() => {   // what a Chrome extension does at document_start: a script element of its own, before the page's
  const add = () => document.documentElement.prepend(Object.assign(document.createElement("script"), {
    textContent: "window.__extension = true"}));
  if (document.documentElement) add();
  else new MutationObserver((_, o) => { if (document.documentElement) { o.disconnect(); add(); } })
    .observe(document, {childList: true});
})();"""
PASSES = [("headless", True, False), ("extension", True, True), ("headed", False, False)]


def compare(cases, headed):
    """Each case three ways in each pass of PASSES (headed: `headed` of the cases, spread over the corpus): the rows
    of the headless pass, with every pass's problems. Without Playwright the TypeScript CLI's report stands for the
    page's."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        sync_playwright = None
    rows = {c["name"]: dict(c, problems=[]) for c in cases}
    if sync_playwright is None:
        # a bundle with no trust config is the page's alone to compare (the TypeScript CLI hands a v1 bundle to
        # Python): without the page it is skipped, not a row
        compared, left = [c for c in cases if c["trust"]], [c["name"] for c in cases if not c["trust"]]
        for c in compared:
            row, problems = vpc.agree(None, c["bundle"], c["trust"], [])
            rows[c["name"]].update(row, problems=problems)
        return [rows[c["name"]] for c in compared], "Playwright is not importable: the page was not run" + (
            f"; not compared without it: {', '.join(left)}" if left else "")
    with sync_playwright() as pw:
        for name, headless, extension in PASSES:
            sample = cases if name != "headed" else cases[::max(1, len(cases) // max(1, headed))][:headed]
            try:
                browser = pw.chromium.launch(channel="chrome", headless=headless)
            except Exception:
                browser = pw.chromium.launch(headless=headless)
            ctx = browser.new_context(accept_downloads=True)
            page, errors = ctx.new_page(), []
            page.on("console", lambda m: errors.append(m.text) if m.type in ("error", "warning") else None)
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on("request", lambda r: None if r.url.startswith(("file:", "blob:", "data:")) else errors.append(
                f"request {r.url}"))
            page.add_init_script("""new PerformanceObserver((l) => { for (const e of l.getEntries())
                window.__long = Math.max(window.__long || 0, e.duration); }).observe({type: 'longtask'});""")
            if extension:
                page.add_init_script(EXTENSION)
            page.goto("file://" + vpc.PAGE)
            if extension and page.evaluate("document.scripts[0].id") == "verifier":
                rows[cases[0]["name"]]["problems"].append("extension: no script element before the page's")
            errors.clear()   # the page's policy refusing the extension's inline script
            for c in sample:
                row, problems = vpc.agree(page, c["bundle"], c["trust"], errors)
                r = rows[c["name"]]
                if name == "headless":
                    r.update(row)
                elif row["page"] != r.get("page"):
                    problems.append(f"exit {row['page']}, headless {r.get('page')}")
                r["problems"] += [f"{name}: {p}" for p in problems]
            browser.close()
    return list(rows.values()), None


def verdicts(rows):
    """Each row's `agree` (no problem in any pass) and `expected`: an honest bundle verified by the Python CLI (the
    reference), a forgery by none of the three, a forgery's control by all three."""
    for r in rows:
        exits = {r.get(k) for k in ("python", "typescript", "page")} - {None}
        r["agree"] = not r["problems"]
        r["expected"] = (exits == {0} if r["name"].endswith("(control)") else 0 not in exits if r["forgery"]
                         else r.get("python") == 0)
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--calls", type=int, default=50_000, help="tool calls in the large run (default 50,000)")
    ap.add_argument("--python", action="append", default=[], metavar="NAME=PY",
                    help="run example NAME (as in EXAMPLES) with this interpreter, which has its framework")
    ap.add_argument("--headed", type=int, default=5, help="bundles verified again in a headed browser (default 5)")
    ap.add_argument("--out", help="keep the corpus in this new directory (default: removed)")
    ap.add_argument("--build", help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.build:
        print(json.dumps(build(a.build, a.calls, dict(x.split("=", 1) for x in a.python))))
        return 0
    if not (shutil.which("node") and os.path.exists(vpc.PAGE)):
        print("skipped: needs node and the TypeScript build (make test-ts)")
        return 0
    # a HOME of its own, short (macOS caps the dev signer's socket path at 104 bytes), with private data and runtime
    # dirs where they don't follow HOME
    work = tempfile.mkdtemp(prefix="e22-", dir="/tmp" if os.path.isdir("/tmp") else None)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("TRACEKIT_", "XDG_"))}
    env.update(HOME=os.path.join(work, "home"), XDG_RUNTIME_DIR=os.path.join(work, "run"), PYTHONPATH=ROOT)
    os.environ.clear()
    os.environ.update(env)   # the corpus, the verifiers and the browser
    os.makedirs(os.path.join(work, "run"), 0o700)
    out = a.out or os.path.join(work, "corpus")
    os.makedirs(out)
    try:
        t0 = time.monotonic()
        p = subprocess.run([sys.executable, os.path.abspath(__file__), "--build", out, "--calls", str(a.calls),
                            *(f"--python={x}" for x in a.python)], capture_output=True, text=True)
        if p.returncode:
            sys.exit(f"building the corpus failed:\n{p.stderr[-3000:]}")
        corpus = json.loads(p.stdout)
        print(f"corpus: {len(corpus['cases'])} bundles in {time.monotonic() - t0:.0f} s; skipped "
              f"{[s['name'] for s in corpus['skipped']]}", flush=True)
        rows, page_skipped = compare(corpus["cases"], a.headed)
    finally:
        tk("down", check=False)   # this HOME's dev signer
        shutil.rmtree(work, True)
    rows = verdicts(rows)
    for r in rows:
        print(f"{'ok ' if r['agree'] and r['expected'] else 'BAD'} {r['name'][:64]:64} python {r.get('python')} "
              f"ts {r.get('typescript')} page {r.get('page')}  {(r.get('integrity') or '')[:48]}")
        for x in r["problems"]:
            print(f"      {x[:400]}")
    timed = ("name", "python", "typescript", "page", "python_s", "typescript_s", "page_s", "longest_task_ms")
    results = {
        "platform": sys.platform, "bundles": len(rows), "forgeries": sum(r["forgery"] for r in rows),
        "agree": sum(r["agree"] for r in rows), "as_expected": sum(r["expected"] for r in rows),
        "skipped": corpus["skipped"] + ([{"name": "page", "why": page_skipped}] if page_skipped else []),
        "large": {**corpus["notes"].get("large", {}), "bundles": [
            {k: round(r[k], 2) if isinstance(r.get(k), float) else r.get(k) for k in timed}
            for r in rows if r["name"].startswith("large")]},
        "cases": [{k: r.get(k) for k in ("name", "source", "forgery", "python", "typescript", "page", "integrity",
                                          "agree", "expected", "problems")} for r in rows]}
    print("wrote", write_results("e22_verifier_agreement", results))
    print(f"{results['agree']} of {len(rows)} agree, {results['as_expected']} as expected ({results['forgeries']} "
          "forgeries)")
    return 0 if results["agree"] == results["as_expected"] == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
