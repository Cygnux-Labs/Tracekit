"""Witness checkpoints (docs/witnesses.md).

A checkpoint commits to the ledger head:
    {"type": "tracekit.checkpoint.v1", "head_seq", "head_hash", "ts", "kid", "sig"}
    sig = Ed25519(canon(checkpoint without sig))
Published copies live where the agent's user cannot rewrite them, so rebuilding the whole
chain on disk (even with the signing key) no longer matches what the witnesses hold.

Witness specs:  file:/abs/path.jsonl   git:/abs/clone[@remote]   rekor:  (off; not in v0.2 core)
"""
import json
import os
import subprocess

from . import crypto
from .core import b64d, b64e, canon, now_ts

CP_TYPE = "tracekit.checkpoint.v1"


def make_checkpoint(head_seq, head_hash, keys, ts=None):
    cp = {"type": CP_TYPE, "head_seq": head_seq, "head_hash": head_hash, "ts": ts or now_ts(), "kid": keys.kid}
    cp["sig"] = b64e(crypto.sign(keys.secret, canon(cp).encode("utf-8")))
    return cp


def verify_checkpoint(cp, public):
    body = {k: v for k, v in cp.items() if k != "sig"}
    try:
        return cp.get("type") == CP_TYPE and crypto.verify(public, canon(body).encode("utf-8"), b64d(cp["sig"]))
    except Exception:
        return False


class FileWitness:
    def __init__(self, path):
        self.path, self.name = path, f"file:{path}"

    def publish(self, cp):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(cp, sort_keys=True) + "\n")
            f.flush(); os.fsync(f.fileno())
        return self.name

    def read(self):
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
        return out


def _git(args, cwd=None, git_dir=None, check=True):
    cmd = ["git"] + (["--git-dir", git_dir] if git_dir else []) + args
    env = dict(os.environ, GIT_AUTHOR_NAME="tracekitd", GIT_AUTHOR_EMAIL="tracekitd@localhost",
               GIT_COMMITTER_NAME="tracekitd", GIT_COMMITTER_EMAIL="tracekitd@localhost", GIT_TERMINAL_PROMPT="0")
    return subprocess.run(cmd, cwd=cwd, env=env, check=check, capture_output=True, text=True, timeout=60)


class GitWitness:
    """A clone owned by the signer. Checkpoints are committed and, if a remote is given, pushed
    to a repository the agent's user cannot push to (protected branch, security-team owned)."""

    def __init__(self, spec_path):
        path, _, remote = spec_path.partition("@")
        self.path, self.remote, self.name = path, remote or None, f"git:{spec_path}"

    def _ensure(self):
        if not os.path.isdir(os.path.join(self.path, ".git")):
            os.makedirs(self.path, exist_ok=True)
            if self.remote:
                r = _git(["clone", self.remote, self.path], check=False)
                if r.returncode != 0:
                    _git(["init", "-q", "-b", "main"], cwd=self.path)
                    _git(["remote", "add", "origin", self.remote], cwd=self.path)
            else:
                _git(["init", "-q", "-b", "main"], cwd=self.path)

    def publish(self, cp):
        self._ensure()
        rel = os.path.join("checkpoints", cp["kid"].replace(":", "_"), f"{cp['head_seq']:012d}.json")
        full = os.path.join(self.path, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            json.dump(cp, f, sort_keys=True, indent=1)
        _git(["add", rel], cwd=self.path)
        _git(["commit", "-q", "-m", f"checkpoint {cp['kid']} seq {cp['head_seq']}"], cwd=self.path)
        if self.remote:
            _git(["push", "-q", "origin", "HEAD:main"], cwd=self.path)  # raises if unreachable
        return self.name

    def read(self):
        """Read checkpoints from a working clone or a bare repository."""
        out = []
        bare = not os.path.isdir(os.path.join(self.path, ".git")) and os.path.exists(os.path.join(self.path, "HEAD"))
        if bare:
            r = _git(["ls-tree", "-r", "--name-only", "HEAD"], git_dir=self.path, check=False)
            for rel in r.stdout.split():
                if rel.startswith("checkpoints/") and rel.endswith(".json"):
                    s = _git(["show", f"HEAD:{rel}"], git_dir=self.path, check=False).stdout
                    try:
                        out.append(json.loads(s))
                    except ValueError:
                        pass
            return out
        base = os.path.join(self.path, "checkpoints")
        for root, _dirs, files in os.walk(base):
            for fn in files:
                if fn.endswith(".json"):
                    try:
                        with open(os.path.join(root, fn), encoding="utf-8") as f:
                            out.append(json.load(f))
                    except ValueError:
                        pass
        return out


class RekorWitness:
    name = "rekor:"

    def publish(self, cp):
        raise NotImplementedError("Rekor witness is off by default and not part of v0.2 core; see docs/witnesses.md")

    def read(self):
        return []


def from_spec(spec):
    kind, _, rest = spec.partition(":")
    if kind == "file":
        return FileWitness(rest)
    if kind == "git":
        return GitWitness(rest)
    if kind == "rekor":
        if os.environ.get("TRACEKIT_ENABLE_REKOR") != "1":
            raise ValueError("rekor witness requires TRACEKIT_ENABLE_REKOR=1 (public and permanent; see docs/witnesses.md)")
        return RekorWitness()
    raise ValueError(f"unknown witness spec {spec!r} (use file:/path or git:/path[@remote])")
