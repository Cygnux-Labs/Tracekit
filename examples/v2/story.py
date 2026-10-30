"""What the v2 examples share: the shell commands their mock models ask for, approving an `ask`, a signer started
from its own config, and exporting and verifying the finished run.

With `--scripted` each approval is given from a second process (`tracekit approvals approve`), as a person would;
without it the example waits for you to approve from another terminal.
"""
import contextlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

import tracekit.policy2
from tracekit.sdk.client import Client

SCRIPTED = "--scripted" in sys.argv
SAFE, RISKY, HELD = "ls", "sudo rm -rf /", 'echo "unterminated'   # allow; deny (TK-D001); ask (TK-SHELL-PARSE)
PACKS = os.path.join(os.path.dirname(tracekit.policy2.__file__), "packs")
AGENT = ["register_run", "decide", "complete", "observe", "state_write", "approval_request", "approval_wait",
         "approval_consume", "approval_abandon", "close_run", "status"]   # what an agent's token may call
PERSON = ["approval_list", "approval_get", "approval_decide", "approval_revoke", "incident_list", "incident_show",
          "incident_resolve", "run_resume", "checkpoint_nudge", "status"]   # the person here: answers, ends holds
NOISE = {"policy_hash", "engine", "expires_at", "decision_id", "nonce", "args_commitment", "binding", "binding_digest",
         "redaction", "output", "detect", "conditions_hash", "args_key", "salt_id", "approver_identity", "channel",
         "not_before", "consume_by"}   # hashes and ids `show` leaves out
ANSWERING = threading.Lock()   # held while approver() answers and prints, so wait() returns after its line


def tracekit(*argv, check=True):
    p = subprocess.run([sys.executable, "-m", "tracekit", *argv], capture_output=True, text=True)
    if check and p.returncode:
        sys.exit(f"tracekit {' '.join(argv)} failed:\n{p.stdout}{p.stderr}")
    return p


def person(*argv):
    """Run a tracekit command as the person at this terminal would type it; print it and what it answers."""
    print(f"$ tracekit {shlex.join(argv)}\n{tracekit(*argv).stdout.rstrip()}")


class Signer:
    """A signer started from its own signer.yaml in a temp dir, as a deployment runs one, and stopped on exit. `policy`
    is its policy's YAML (`extends: packs/server.yaml` reaches the shipped packs). The person at this terminal (your
    uid, the approver alice) reaches it on a Unix socket, which the tracekit commands here use ($TRACEKIT_SIGNER).
    Each name in `tokens` ({name: methods it may call}) is the identity token:<name> on loopback HTTP; `reviewers`
    names the agent approvers among them. POSIX only: the person is a uid. Leaves no process or temp dir behind,
    also when it fails to start or is interrupted."""

    def __init__(self, policy, tokens, reviewers=(), **config):
        self.dir, self.proc = tempfile.mkdtemp(prefix="tk-"), None
        try:
            self._start(policy, tokens, reviewers, config)
        except BaseException:   # SystemExit and KeyboardInterrupt too: no __exit__ runs for a with that never began
            self.__exit__()
            raise

    def _start(self, policy, tokens, reviewers, config):
        shutil.copytree(PACKS, os.path.join(self.dir, "packs"))
        with open(os.path.join(self.dir, "policy.yaml"), "w") as f:
            f.write(policy)
        me = f"uid:{os.getuid()}"
        self.config = os.path.join(self.dir, "signer.yaml")
        with open(self.config, "w") as f:   # JSON is YAML
            json.dump({"data_dir": "data", "socket": "s.sock", "policy": "policy.yaml", "grace_s": 1,
                       "http": {"listen": "127.0.0.1:0", "insecure_loopback": True,   # a free port, told when serving
                                "authenticators": ["token"], "tokens": "tokens.json"},
                       "approvals": {"approvers": [me], "persons": {me: "alice"},
                                     **({"agents": [f"token:{n}" for n in reviewers]} if reviewers else {})},
                       "authorize": {me: PERSON, **{f"token:{n}": m for n, m in tokens.items()}}, **config}, f)
        for name in tokens:
            with open(self.token(name), "w") as f:
                f.write(tracekit("signer", "token", "add", name, "--config", self.config).stdout)
        self.proc = subprocess.Popen([sys.executable, "-m", "tracekit", "signer", "serve", "--config", self.config],
                                     stdout=subprocess.PIPE, text=True)
        line = self.proc.stdout.readline()
        if " serving on " not in line:
            sys.exit(f"the signer did not start: tracekit signer serve --config {self.config}")
        self.url = "http://" + line.rsplit(" on ", 1)[1].strip()
        os.environ["TRACEKIT_SIGNER"] = os.path.join(self.dir, "s.sock")

    def token(self, name):
        return os.path.join(self.dir, name + ".token")

    def client(self, name):
        """A client that calls the signer as token:<name>."""
        os.environ["TRACEKIT_SIGNER_TOKEN_FILE"] = self.token(name)   # read when the client is made
        return Client(self.url)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self.proc is not None:
            self.proc.terminate()
            self.proc.wait()
        shutil.rmtree(self.dir, True)


@contextlib.contextmanager
def approver(client, run_id):
    """While inside: each approval the run requests is approved (--scripted) or shown for a person to answer."""
    stop, seen = threading.Event(), set()

    def watch():
        while not stop.wait(0.1):
            for a in client.approval_list({"run_id": run_id})["approvals"]:
                if a["state"] != "requested" or a["approval_id"] in seen:
                    continue
                seen.add(a["approval_id"])
                if SCRIPTED:
                    with ANSWERING:
                        print(tracekit("approvals", "approve", a["approval_id"]).stdout.strip(), flush=True)
                else:
                    print(f"{a['tool']} waits for a person. In another terminal:\n"
                          f"  tracekit approvals show {a['approval_id']}\n"
                          f"  tracekit approvals approve {a['approval_id']}    # or reject", flush=True)
    t = threading.Thread(target=watch, daemon=True)
    t.start()
    try:
        yield
    finally:
        stop.set()
        t.join()


def wait(run, approval_id):
    """The approval's final state: approved, rejected or expired; once approver() has printed its answer, so the
    lines read in the order things happened."""
    state = "requested"
    while state == "requested":
        state = run.call("approval_wait", approval_id=approval_id, timeout_ms=60000)["state"]
    with ANSWERING:
        return state


def export_and_verify(run_id, config=None):
    """Export the closed run once the signer has finalised it (a few seconds after it closes), verify it against this
    signer's pinned key and print the report. `config`: a Signer's, else the dev signer. Returns the verifier's exit
    code."""
    out, where = f"{run_id}.tkb", ("--config", config) if config else ()
    tracekit("signer", "trust", *where, "-o", "trust.json")
    deadline = time.monotonic() + 30
    while True:
        if os.path.exists(out):
            os.remove(out)
        tracekit("export", "--v2", "--run", run_id, *where, "-o", out)
        p = tracekit("verify", out, "--trust", "trust.json", check=False)
        if "Integrity: VERIFIED." in p.stdout or time.monotonic() > deadline:
            break
        time.sleep(0.5)
    print(f"\n$ tracekit verify {out} --trust trust.json\n{p.stdout}{p.stderr}", end="")
    return p.returncode


def show(bundle, *types):
    """Print the bundle's signed records of these types: the run's sequence number, type and what it says."""
    with zipfile.ZipFile(bundle) as z:
        name = next(n for n in z.namelist() if n.startswith("runs/"))
        events = [json.loads(line)["event"] for line in z.read(name).splitlines()]
    for e in events:
        if e["type"] in types:
            print(f"  #{e['run_seq']} {e['type']} {json.dumps(_brief(e['data']), sort_keys=True)}")


def _brief(v):
    return {k: _brief(x) for k, x in v.items() if k not in NOISE} if isinstance(v, dict) else v
