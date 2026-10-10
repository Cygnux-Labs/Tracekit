"""Shared helpers for the evaluations: a throwaway dev signer and a way to fire hook payloads at it."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tracekit import install  # noqa: E402


class Stack:
    """A dev-mode signer in a temp dir. Use as a context manager; `env` is the environment for child processes."""

    def __init__(self, checkpoint_every=50, witness=True):
        self.dir = tempfile.mkdtemp(prefix="tracekit-eval-")
        self.home = os.path.join(self.dir, "signer")
        self.client_home = os.path.join(self.dir, "client")
        self.env = dict(os.environ, TRACEKIT_CLIENT_HOME=self.client_home,
                        PYTHONPATH=ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
        self.env.pop("TRACEKIT_POLICY", None)
        self._saved = {k: os.environ.get(k) for k in ("TRACEKIT_CLIENT_HOME", "TRACEKIT_POLICY")}
        self.checkpoint_every = checkpoint_every
        self.witness = witness

    def __enter__(self):
        os.environ["TRACEKIT_CLIENT_HOME"] = self.client_home
        os.environ.pop("TRACEKIT_POLICY", None)
        install.init_dev(self.home, [], checkpoint_every=self.checkpoint_every)
        return self

    def __exit__(self, *a):
        self.stop()
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.dir, ignore_errors=True)

    def stop(self):
        install.stop_dev_daemon(self.home)  # writes a final checkpoint

    @property
    def ledger(self):
        return os.path.join(self.home, "ledger", "ledger.jsonl")

    @property
    def witness_spec(self):
        return f"git:{os.path.join(self.home, 'witness')}"

    def hook(self, payload, timeout=30):
        """Run `python -m tracekit.hook` once. Returns (exit code, milliseconds)."""
        t = time.perf_counter()
        r = subprocess.run([sys.executable, "-m", "tracekit.hook"], input=json.dumps(payload), capture_output=True,
                           text=True, env=self.env, timeout=timeout)
        return r.returncode, (time.perf_counter() - t) * 1000

    def fill(self, n_events, run_id="fill"):
        """Append about n_events events in-process through the SDK (fast way to grow the ledger)."""
        from tracekit.agent_sdk import Tracer
        done = 0
        with Tracer(agent="eval-fill", session_id=run_id) as t:
            while done < n_events:
                with t.tool("Read", {"file_path": f"src/f{done % 50}.py"}) as c:
                    c.result({"bytes": 1000 + done % 97})
                done += 2
        return done


def v2_signer(data_dir, durability="ack-on-write", config=""):
    """Start `tracekit signer serve` (v2) on a Unix socket in data_dir, rate limits off, with `config` (YAML lines)
    added to its config. Returns (process, socket); the process has said it is serving."""
    os.makedirs(data_dir, exist_ok=True)
    cfg, sock = os.path.join(data_dir, "signer.yaml"), os.path.join(data_dir, "s.sock")
    with open(cfg, "w") as f:
        f.write(f"data_dir: data\nsocket: s.sock\ndurability: {durability}\n"
                "limits: {events_per_s: 1000000000, burst: 1000000000}\n" + config)
    p = subprocess.Popen([sys.executable, "-m", "tracekit", "signer", "serve", "--config", cfg], cwd=ROOT,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if b"serving" not in p.stdout.readline():
        p.kill()
        raise SystemExit(f"the v2 signer did not start: {sys.executable} -m tracekit signer serve --config {cfg}")
    return p, sock


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def summarize(xs):
    return {"n": len(xs), "p50": round(pct(xs, 50), 2), "p95": round(pct(xs, 95), 2), "max": round(max(xs), 2)}


def write_results(name, data):
    out = os.path.join(ROOT, "eval", "results")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, name + ".json"), "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    return os.path.join(out, name + ".json")
