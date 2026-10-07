"""Witness checkpoints (docs/witnesses.md).

A checkpoint commits to the ledger head:
    {"type": "tracekit.checkpoint.v1", "head_seq", "head_hash", "ts", "kid", "sig"}
    sig = Ed25519(canon(checkpoint without sig))
Published copies live where the agent's user cannot rewrite them, so rebuilding the whole
chain on disk (even with the signing key) no longer matches what the witnesses hold.

Witness specs:  file:/abs/path.jsonl   git:/abs/clone[@remote]   https://witness.example[#token=..&key=..]  (tracekit witness serve)
                rekor:https://rekor.sigstore.dev  (experimental, TRACEKIT_ENABLE_REKOR=1)
"""
import json
import os
import subprocess

from . import crypto
from .core import b64d, b64e, canon, now_ts

CP_TYPE = "tracekit.checkpoint.v1"


def make_checkpoint(head_seq, head_hash, keys, ts=None):
    cp = {"type": CP_TYPE, "head_seq": head_seq, "head_hash": head_hash, "ts": ts or now_ts(), "kid": keys.kid}
    assurance = getattr(keys, "assurance", "file")
    if assurance != "file":  # signed with the checkpoint; absent (= file) keeps older checkpoints byte-identical
        cp["key_assurance"] = assurance
    if getattr(keys, "attestation_sha256", None):
        cp["key_attestation_sha256"] = keys.attestation_sha256
    cp["sig"] = b64e(keys.sign(canon(cp).encode("utf-8")) if hasattr(keys, "sign") else crypto.sign(keys.secret, canon(cp).encode("utf-8")))
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
                    c = json.loads(line)
                except ValueError:
                    continue
                if isinstance(c, dict):
                    out.append(c)
        return out


def _git(args, cwd=None, git_dir=None, check=True):
    cmd = ["git"] + (["--git-dir", git_dir] if git_dir else []) + args
    env = dict(os.environ, GIT_AUTHOR_NAME="tracekitd", GIT_AUTHOR_EMAIL="tracekitd@localhost",
               GIT_COMMITTER_NAME="tracekitd", GIT_COMMITTER_EMAIL="tracekitd@localhost", GIT_TERMINAL_PROMPT="0")
    return subprocess.run(cmd, cwd=cwd, env=env, check=check, capture_output=True, text=True, timeout=60)


def _git_init(path):
    """`git init` on main for any git version (`-b` needs 2.28+)."""
    _git(["init", "-q"], cwd=path)
    _git(["symbolic-ref", "HEAD", "refs/heads/main"], cwd=path)


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
                    _git_init(self.path)
                    _git(["remote", "add", "origin", self.remote], cwd=self.path)
            else:
                _git_init(self.path)

    def publish(self, cp):
        self._ensure()
        rel = os.path.join("checkpoints", cp["kid"].replace(":", "_"), f"{cp['head_seq']:012d}.json")
        full = os.path.join(self.path, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            json.dump(cp, f, sort_keys=True, indent=1)
        _git(["add", rel], cwd=self.path)
        if _git(["diff", "--cached", "--quiet"], cwd=self.path, check=False).returncode != 0:
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
                        c = json.loads(s)
                    except ValueError:
                        continue
                    if isinstance(c, dict):
                        out.append(c)
            return out
        base = os.path.join(self.path, "checkpoints")
        for root, _dirs, files in os.walk(base):
            for fn in files:
                if fn.endswith(".json"):
                    try:
                        with open(os.path.join(root, fn), encoding="utf-8") as f:
                            c = json.load(f)
                    except (ValueError, OSError):
                        continue
                    if isinstance(c, dict):
                        out.append(c)
        return out


class HttpWitness:
    """A `tracekit witness serve` log. Spec: https://host:port[#token=/path/token&key=/path/witness.pub&state=/path/sth.json]

    publish(): POST the checkpoint with the token; the receipt's tree head and inclusion proof are checked when a key is pinned.
    read(): every entry must come with a valid inclusion proof against a tree head signed by the pinned witness key, and
    the tree head must be consistent (RFC 6962 consistency proof) with the last one this client saw. Without a pinned
    key read() refuses: a witness you do not authenticate adds nothing."""

    def __init__(self, spec):
        from urllib.parse import parse_qs
        url, _, frag = spec.partition("#")
        self.url = url.rstrip("/")
        opts = {k: v[0] for k, v in parse_qs(frag).items()}
        self.token_path = opts.get("token") or os.environ.get("TRACEKIT_WITNESS_TOKEN_FILE")
        self.key_path = opts.get("key") or os.environ.get("TRACEKIT_WITNESS_PUBKEY")
        self.state_path = opts.get("state")
        self.name = f"witness:{self.url}"
        if not (self.url.startswith("https://") or self.url.startswith(("http://127.0.0.1", "http://localhost", "http://[::1]"))):
            raise ValueError("witness URLs must use https (plain http only for localhost)")

    def _key(self):
        if not self.key_path:
            return None
        with open(self.key_path, "rb") as f:
            k = f.read()
        if len(k) != 32:
            raise ValueError(f"{self.key_path}: not a raw 32-byte Ed25519 public key")
        return k

    def _http(self, method, path, body=None, token=None):
        import urllib.error
        import urllib.request
        h = {"Content-Type": "application/json"}
        if token:
            h["Authorization"] = "Bearer " + token
        req = urllib.request.Request(self.url + path, data=json.dumps(body).encode() if body is not None else None, method=method, headers=h)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=15) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {}

    def _check_sth(self, sth, key):
        from .witness_server import verify_sth
        if not verify_sth(sth, key):
            raise ValueError(f"{self.name}: tree head is not signed by the pinned witness key")
        if self.state_path:
            try:
                with open(self.state_path, encoding="utf-8") as f:
                    old = json.load(f)
            except (OSError, ValueError):
                old = None
            if old and old["tree_size"] > sth["tree_size"]:
                raise ValueError(f"{self.name}: log shrank from {old['tree_size']} to {sth['tree_size']} entries")
            if old and 0 < old["tree_size"] <= sth["tree_size"]:
                from . import merkle
                code, r = self._http("GET", f"/v1/consistency?first={old['tree_size']}&second={sth['tree_size']}")
                proof = [bytes.fromhex(x) for x in (r.get("proof") or [])] if code == 200 else None
                if proof is None or not merkle.verify_consistency(old["tree_size"], sth["tree_size"], bytes.fromhex(old["root_hash"]),
                                                                  bytes.fromhex(sth["root_hash"]), proof):
                    raise ValueError(f"{self.name}: log is not consistent with the tree head seen before (rewritten history)")
            tmp = self.state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"tree_size": sth["tree_size"], "root_hash": sth["root_hash"]}, f)
            os.replace(tmp, self.state_path)

    def publish(self, cp):
        if not self.token_path:
            raise ValueError(f"{self.name}: no token (add #token=/path/to/token)")
        with open(self.token_path, encoding="utf-8") as f:
            token = f.read().strip()
        code, r = self._http("POST", "/v1/checkpoints", cp, token)
        if code not in (200, 201):
            raise RuntimeError(f"{self.name}: HTTP {code}: {r.get('error', r)}")
        key = self._key()
        if key is not None:
            from . import merkle
            self._check_sth(r["sth"], key)
            leaf = merkle.leaf_hash(canon(cp).encode("utf-8"))
            if not merkle.verify_inclusion(r["index"], r["sth"]["tree_size"], leaf, [bytes.fromhex(x) for x in r["inclusion"]],
                                           bytes.fromhex(r["sth"]["root_hash"])):
                raise RuntimeError(f"{self.name}: receipt's inclusion proof does not verify")
        return self.name

    def read(self):
        from . import merkle
        key = self._key()
        if key is None:
            raise ValueError(f"{self.name}: pin the witness public key (#key=/path/witness.pub) to read from it")
        out, after, sth0 = [], -1, None
        while True:
            code, r = self._http("GET", f"/v1/checkpoints?after={after}")
            if code != 200:
                raise RuntimeError(f"{self.name}: HTTP {code}")
            sth = r["sth"]
            if sth0 is None:
                self._check_sth(sth, key)
                sth0 = sth
            elif not __import__("tracekit.witness_server", fromlist=["verify_sth"]).verify_sth(sth, key):
                raise ValueError(f"{self.name}: tree head is not signed by the pinned witness key")
            root = bytes.fromhex(sth["root_hash"])
            for e in r["entries"]:
                leaf = merkle.leaf_hash(canon(e["cp"]).encode("utf-8"))
                if not merkle.verify_inclusion(e["index"], sth["tree_size"], leaf, [bytes.fromhex(x) for x in e["inclusion"]], root):
                    raise ValueError(f"{self.name}: entry {e['index']} has no valid inclusion proof")
                out.append(e["cp"])
            if not r["entries"]:
                return out
            after = r["entries"][-1]["index"]


def from_spec(spec):
    if spec.startswith(("https://", "http://")):
        return HttpWitness(spec)
    kind, _, rest = spec.partition(":")
    if kind == "file":
        return FileWitness(rest)
    if kind == "git":
        return GitWitness(rest)
    if kind == "rekor":
        if os.environ.get("TRACEKIT_ENABLE_REKOR") != "1":
            raise ValueError("rekor witness requires TRACEKIT_ENABLE_REKOR=1 (public and permanent; see docs/witnesses.md)")
        from .rekor import RekorWitness
        return RekorWitness(rest)
    raise ValueError(f"unknown witness spec {spec!r} (use file:/path, git:/path[@remote] or https://witness[#key=...])")
