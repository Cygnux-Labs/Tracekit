"""Witness service: an append-only, Merkle-tree checkpoint log that signers publish to and verifiers read from.

    tracekit witness init  --home /srv/tkw                        # creates the witness key; prints its public key path
    tracekit witness token build-box --home /srv/tkw --signer-pub /var/lib/tracekit/ledger/signer.pub   # token shown once
    tracekit witness serve --home /srv/tkw --host 0.0.0.0 --port 8444 --cert c.pem --key k.pem

    # on the signer host (tracekit init / config.json):
    --witness 'https://witness.example:8444#token=/var/lib/tracekit/witness.token&key=/var/lib/tracekit/witness.pub'
    # verifying:
    tracekit verify run.tkb --witness 'https://witness.example:8444#key=witness.pub'

Why it helps: a checkpoint held only on the signer's machine can be rewritten by whoever controls that machine. The
witness keeps every checkpoint in an append-only log it signs (RFC 6962 tree, signed tree heads), so:
* a checkpoint is accepted only with a valid signature from the signer key registered for that token;
* a second, different head for a sequence number already logged is refused and recorded as a conflict (a fork:
  someone rewrote the ledger and tried to publish the new history);
* every entry a verifier reads comes with an inclusion proof against a signed tree head, and clients check
  consistency proofs between tree heads they have seen, so the witness cannot quietly drop or rewrite entries either.

The witness stores only checkpoints (sequence numbers, hashes, key ids, timestamps): never ledger content."""
import argparse
import hashlib
import hmac
import json
import os
import secrets
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlsplit

from . import crypto, merkle
from .merkle import tiles
from .netserver import Server
from .core import b64d, b64e, canon, now_ts
from .locking import lock_file
from .witness import CP_TYPE, verify_checkpoint

STH_TYPE = "tracekit.witness.sth.v1"
MAX_BODY = 64 * 1024
PAGE = 1000


def sth_message(sth):
    return canon({k: v for k, v in sth.items() if k != "sig"}).encode("utf-8")


def verify_sth(sth, public):
    try:
        return sth.get("type") == STH_TYPE and crypto.verify(public, sth_message(sth), b64d(sth["sig"]))
    except Exception:
        return False


class Log:
    def __init__(self, home):
        self.home = home
        self.lock = threading.RLock()
        self.leaves_path = os.path.join(home, "log.jsonl")
        self.conflicts_path = os.path.join(home, "conflicts.jsonl")
        self._lockf = open(os.path.join(home, "log.lock"), "a+b")  # held for the Log's lifetime
        try:
            lock_file(self._lockf, blocking=False)
        except OSError:
            self._lockf.close()
            raise RuntimeError(f"another witness is already using {home}") from None
        with open(os.path.join(home, "witness.key"), "rb") as f:
            self.secret = f.read()
        self.public = crypto.public_from_secret(self.secret)
        self.kid = crypto.kid(self.public)
        self.entries, self.by_kid_seq, self._sth = [], {}, None
        self.tree = tiles.Tree(tiles.MemoryTileStore())   # proofs read O(log n) tiles, not every leaf
        if os.path.exists(self.leaves_path):
            with open(self.leaves_path, "rb+") as f:
                data = f.read()
                good = data[:data.rfind(b"\n") + 1]
                if len(good) < len(data):
                    # a write cut short before its newline was never fsynced or acknowledged: set it aside, so the
                    # next entry starts on a fresh line
                    print(f"tracekit witness: warning: last line of {self.leaves_path} is incomplete; moved it to "
                          f"{self.leaves_path}.torn", file=sys.stderr)
                    with open(self.leaves_path + ".torn", "ab") as t:
                        t.write(data[len(good):] + b"\n")
                    f.truncate(len(good))
            for line in good.decode("utf-8").splitlines():
                if line.strip():
                    self._index(json.loads(line))

    def close(self):
        self._lockf.close()

    def _index(self, e):
        self.entries.append(e)
        self.tree.append(merkle.leaf_hash(canon(e["cp"]).encode("utf-8")))
        self.by_kid_seq[(e["cp"]["kid"], e["cp"]["head_seq"])] = len(self.entries) - 1

    def sth(self):
        """The signed head of the tree as it is now, signed once per tree size."""
        with self.lock:
            if self._sth is None or self._sth["tree_size"] != self.tree.size:
                body = {"type": STH_TYPE, "tree_size": self.tree.size, "root_hash": self.tree.root().hex(), "ts": now_ts(),
                        "kid": self.kid}
                body["sig"] = b64e(crypto.sign(self.secret, sth_message(body)))
                self._sth = body
            return self._sth

    def tokens(self):
        try:
            with open(os.path.join(self.home, "tokens.json"), encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def add(self, client, cp):
        """-> (http status, response)."""
        with self.lock:
            key = (cp["kid"], cp["head_seq"])
            if key in self.by_kid_seq:
                i = self.by_kid_seq[key]
                if self.entries[i]["cp"]["head_hash"] == cp["head_hash"]:
                    return 200, self._receipt(i, duplicate=True)
                rec = {"ts": now_ts(), "client": client, "kid": cp["kid"], "head_seq": cp["head_seq"],
                       "logged_hash": self.entries[i]["cp"]["head_hash"], "offered_hash": cp["head_hash"]}
                with open(self.conflicts_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")
                return 409, {"error": "fork: a different head is already logged for this sequence number", "conflict": rec}
            e = {"cp": cp, "client": client, "received": now_ts()}
            data = (json.dumps(e, sort_keys=True) + "\n").encode("utf-8")
            with open(self.leaves_path, "ab", buffering=0) as f:
                size = f.seek(0, os.SEEK_END)
                try:
                    if f.write(data) != len(data):
                        raise OSError("short write to the witness log")
                    os.fsync(f.fileno())
                except OSError:
                    f.truncate(size)  # never leave an unacknowledged entry in the log
                    raise
            self._index(e)
            return 201, self._receipt(len(self.entries) - 1)

    def _receipt(self, i, duplicate=False):
        sth = self.sth()
        return {"index": i, "sth": sth, "inclusion": [h.hex() for h in self.tree.inclusion_proof(i, sth["tree_size"])],
                "duplicate": duplicate}

    def page(self, kid=None, after=-1):
        with self.lock:
            sth = self.sth()
            out = []
            for i in range(max(0, after + 1), sth["tree_size"]):
                cp = self.entries[i]["cp"]
                if kid and cp["kid"] != kid:
                    continue
                out.append({"index": i, "cp": cp, "inclusion": [h.hex() for h in self.tree.inclusion_proof(i, sth["tree_size"])]})
                if len(out) >= PAGE:
                    break
            return {"sth": sth, "entries": out}

    def consistency(self, first, second):
        with self.lock:
            if not 0 < first <= second <= self.tree.size:
                return None
            return [h.hex() for h in self.tree.consistency_proof(first, second)]


def init(home):
    os.makedirs(home, exist_ok=True)
    kp = os.path.join(home, "witness.key")
    if not os.path.exists(kp):
        secret, public = crypto.generate()
        fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(secret)
        with open(os.path.join(home, "witness.pub"), "wb") as f:
            f.write(public)
    with open(os.path.join(home, "witness.pub"), "rb") as f:
        return os.path.join(home, "witness.pub"), crypto.kid(f.read())


def add_token(home, name, signer_pub):
    if len(signer_pub) != 32:
        raise ValueError("signer public key must be the raw 32-byte Ed25519 key (ledger/signer.pub)")
    p = os.path.join(home, "tokens.json")
    try:
        with open(p, encoding="utf-8") as f:
            tokens = json.load(f)
    except (OSError, ValueError):
        tokens = {}
    if name in tokens:
        raise ValueError(f"client {name!r} already has a token")
    token = "tkw_" + secrets.token_urlsafe(32)
    tokens[name] = {"sha256": hashlib.sha256(token.encode()).hexdigest(), "signer_pub": b64e(signer_pub), "kid": crypto.kid(signer_pub),
                    "created": now_ts()}
    tmp = p + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(tokens, f, indent=2)
    os.replace(tmp, p)
    return token


def make_handler(log):
    class H(BaseHTTPRequestHandler):
        server_version = "tracekit-witness"

        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            u = urlsplit(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            try:
                if u.path == "/v1/sth":
                    return self._send(200, log.sth())
                if u.path == "/v1/key":
                    return self._send(200, {"kid": log.kid, "public_key_b64": b64e(log.public)})
                if u.path == "/v1/checkpoints":
                    return self._send(200, log.page(q.get("kid"), int(q.get("after", -1))))
                if u.path == "/v1/consistency":
                    p = log.consistency(int(q["first"]), int(q["second"]))
                    return self._send(200, {"proof": p}) if p is not None else self._send(400, {"error": "bad tree sizes"})
                if u.path == "/v1/conflicts":
                    rows = []
                    if os.path.exists(log.conflicts_path):
                        with open(log.conflicts_path, encoding="utf-8") as f:
                            rows = [json.loads(x) for x in f if x.strip()][-PAGE:]
                    return self._send(200, {"conflicts": rows})
            except (KeyError, ValueError):
                return self._send(400, {"error": "bad query"})
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            if urlsplit(self.path).path != "/v1/checkpoints":
                return self._send(404, {"error": "not found"})
            auth = self.headers.get("Authorization", "")
            digest = hashlib.sha256(auth[7:].strip().encode()).hexdigest() if auth.startswith("Bearer ") else None
            client = rec = None
            for name, r in log.tokens().items():
                if digest and hmac.compare_digest(str(r.get("sha256", "")), digest):
                    client, rec = name, r
            if not client:
                return self._send(401, {"error": "unauthorized"})
            try:
                n = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                n = -1
            if not 0 < n <= MAX_BODY:
                return self._send(413, {"error": "bad body size"})
            try:
                cp = json.loads(self.rfile.read(n))
            except ValueError:
                return self._send(400, {"error": "invalid JSON"})
            if not (isinstance(cp, dict) and cp.get("type") == CP_TYPE and isinstance(cp.get("head_seq"), int)
                    and isinstance(cp.get("head_hash"), str) and len(cp["head_hash"]) == 64):
                return self._send(400, {"error": "not a tracekit checkpoint"})
            if cp.get("kid") != rec["kid"] or not verify_checkpoint(cp, b64d(rec["signer_pub"])):
                return self._send(403, {"error": "checkpoint is not signed by the signer key registered for this token"})
            code, body = log.add(client, cp)
            return self._send(code, body)
    return H


class _Server(Server):
    log = None

    def server_close(self):
        super().server_close()
        if self.log:
            self.log.close()


def serve(home, host="127.0.0.1", port=8444, ssl_context=None):
    srv = _Server((host, port), BaseHTTPRequestHandler, ssl_context)  # bind first: a second instance stops here
    try:
        srv.log = Log(home)
    except BaseException:
        srv.server_close()
        raise
    srv.RequestHandlerClass = make_handler(srv.log)
    return srv


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit witness")
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init")
    i.add_argument("--home", required=True)
    t = sub.add_parser("token")
    t.add_argument("name")
    t.add_argument("--home", required=True)
    t.add_argument("--signer-pub", required=True, help="the signer's ledger/signer.pub")
    s = sub.add_parser("serve")
    s.add_argument("--home", required=True)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8444)
    s.add_argument("--cert")
    s.add_argument("--key")
    s.add_argument("--insecure-http", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "init":
        path, kid = init(a.home)
        print(f"witness key {kid}; give verifiers {path} (pin it with #key=...)")
        return 0
    if a.cmd == "token":
        init(a.home)
        with open(a.signer_pub, "rb") as f:
            pub = f.read()
        try:
            print(add_token(a.home, a.name, pub))
        except ValueError as e:
            print(f"tracekit witness: {e}", file=sys.stderr)
            return 2
        print(f"(client {a.name!r}, signer {crypto.kid(pub)}; shown once)", file=sys.stderr)
        return 0
    init(a.home)
    loopback = a.host in ("127.0.0.1", "localhost", "::1")
    if not a.cert and not loopback and not a.insecure_http:
        print("tracekit witness: refusing plain HTTP on a non-loopback address; pass --cert/--key", file=sys.stderr)
        return 2
    ctx = None
    if a.cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(a.cert, a.key)
    srv = serve(a.home, a.host, a.port, ctx)
    print(f"tracekit witness: listening on {'https' if a.cert else 'http'}://{a.host}:{srv.server_address[1]}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
