#!/usr/bin/env python3
"""Record the offline demos in docs/demos/ (docs/demos/README.md). Each demo runs its example against a fresh signer in
a temp dir (its own HOME and runtime dir, so never yours), and its folder gets transcript.txt (the command and its
output, the temp dir shown as $TMP and your home as ~), run.tkb, trust.json and verify.txt.

    python scripts/record_demos.py [NAME ...]           # record every demo, or the named ones
    python scripts/record_demos.py --check [NAME ...]   # write nothing: each saved run.tkb still verifies as its
                                                        # verify.txt says, and each demo still runs to the same verdicts

A demo whose optional dependency is missing (or that needs a Unix socket, off POSIX) is skipped, saying why.
"""
import argparse
import concurrent.futures
import glob
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(ROOT, "docs", "demos")
# folder -> (the example and its arguments, the modules it needs, whether it starts a configured signer: POSIX only)
SCENARIOS = {
    "guardrails": (["examples/v2/custom/agent.py", "--scripted"], (), False),
    "prompt-injection": (["examples/v2/demos/prompt_injection.py"], ("langchain", "langgraph"), True),
    "mcp": (["examples/v2/mcp/agent.py", "--scripted"], ("mcp",), False),
    "agent-approvers": (["examples/v2/demos/agent_approvers.py"], (), True),
    "containment": (["examples/v2/demos/containment.py"], (), True),
    "completeness": (["examples/v2/demos/completeness.py"], (), False),
    "egress": (["examples/v2/demos/egress.py"], (), True),
}
PYTHONPATH = ROOT + os.pathsep + os.environ.get("PYTHONPATH", "")   # this checkout's tracekit, installed or not


def missing(name):
    """Why demo `name` can't run here, or None."""
    _, modules, configured = SCENARIOS[name]
    absent = [m for m in modules if importlib.util.find_spec(m) is None]
    if absent:
        return f"{', '.join(absent)} not installed"
    return "its person approves on a Unix socket: POSIX only" if configured and os.name != "posix" else None


def run(name):
    """Run demo `name` in a new temp dir: (its transcript, the temp dir holding its bundle). RuntimeError if it
    fails."""
    argv = SCENARIOS[name][0]
    tmp = tempfile.mkdtemp(prefix="tk-demo-", dir="/tmp" if os.path.isdir("/tmp") else None)   # macOS caps socket paths
    home = os.path.join(tmp, "home")
    env = dict(os.environ, HOME=home, USERPROFILE=home, LOCALAPPDATA=os.path.join(home, "local"),
               XDG_DATA_HOME=os.path.join(home, "data"), TRACEKIT_RUNTIME_DIR=os.path.join(tmp, "run"), TMPDIR=tmp,
               PYTHONUNBUFFERED="1", PYTHONPATH=PYTHONPATH)
    for k in ("TRACEKIT_SIGNER", "TRACEKIT_SIGNER_TOKEN", "TRACEKIT_SIGNER_TOKEN_FILE", "TRACEKIT_EGRESS_PROXY"):
        env.pop(k, None)
    try:
        p = subprocess.run([sys.executable, os.path.join(ROOT, *argv[0].split("/")), *argv[1:]], cwd=tmp, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
    finally:   # the dev signer the example may have started
        subprocess.run([sys.executable, "-m", "tracekit", "down"], cwd=tmp, env=env, capture_output=True)
    if p.returncode:
        raise RuntimeError(f"{name}: {' '.join(argv)} exited {p.returncode} (its files are in {tmp})\n{p.stdout}")
    text = f"$ python {' '.join(argv)}\n{p.stdout}"
    for path, shown in ((os.path.realpath(tmp), "$TMP"), (tmp, "$TMP"), (ROOT, "."), (os.path.expanduser("~"), "~")):
        text = text.replace(path, shown)
    return text, tmp


def verify(folder, bundle="run.tkb"):
    """`tracekit verify` of `bundle` in `folder` against its trust.json, as verify.txt holds it."""
    p = subprocess.run([sys.executable, "-m", "tracekit", "verify", bundle, "--trust", "trust.json"], cwd=folder,
                       capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=PYTHONPATH))
    return f"$ tracekit verify run.tkb --trust trust.json\n{p.stdout}{p.stderr}"


def verdicts(report):
    """Each check's status and name, and the integrity line: what a fresh run must repeat."""
    return re.findall(r"^\[(\w+)\] ([^—\n]+?) —|^(Integrity: .*)$", report, re.M)


def bundle_of(tmp):
    [bundle] = [b for b in glob.glob(os.path.join(tmp, "*.tkb")) if os.path.basename(b) != "tampered.tkb"]
    return bundle


def record(name):
    text, tmp = run(name)
    try:
        folder = os.path.join(DEMOS, name)
        os.makedirs(folder, exist_ok=True)
        shutil.copyfile(bundle_of(tmp), os.path.join(folder, "run.tkb"))
        shutil.copyfile(os.path.join(tmp, "trust.json"), os.path.join(folder, "trust.json"))
        for file, content in (("transcript.txt", text), ("verify.txt", verify(folder))):
            with open(os.path.join(folder, file), "w", encoding="utf-8", newline="\n") as f:
                f.write(content)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return f"{name}: recorded"


def check(name):
    """(whether demo `name` holds, what to say about it)."""
    folder = os.path.join(DEMOS, name)
    with open(os.path.join(folder, "verify.txt"), encoding="utf-8") as f:
        saved = f.read()
    if verify(folder) != saved:
        return False, f"{name}: run.tkb no longer verifies as verify.txt says"
    why = missing(name)
    if why:
        return True, f"{name}: the saved bundle verifies; not run again ({why})"
    try:
        _, tmp = run(name)
    except RuntimeError as e:
        return False, str(e)
    try:
        fresh = verify(tmp, os.path.basename(bundle_of(tmp)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if verdicts(fresh) != verdicts(saved):
        return False, f"{name}: a fresh run verifies differently from verify.txt:\n{fresh}"
    return True, f"{name}: ok"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="run and verify every demo again; write nothing")
    ap.add_argument("names", nargs="*", metavar="NAME", help=", ".join(SCENARIOS))
    a = ap.parse_args(argv)
    names = a.names or list(SCENARIOS)
    if set(names) - set(SCENARIOS):
        ap.error(f"no demo {', '.join(sorted(set(names) - set(SCENARIOS)))}; the demos: {', '.join(SCENARIOS)}")
    if a.check:
        with concurrent.futures.ThreadPoolExecutor() as pool:   # each demo has its own signer and temp dir
            results = list(pool.map(check, names))
        print("\n".join(said for _, said in results))
        return 0 if all(ok for ok, _ in results) else 1
    for name in names:
        why = missing(name)
        try:
            print(f"{name}: skipped ({why})" if why else record(name), flush=True)
        except RuntimeError as e:
            print(e, file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
