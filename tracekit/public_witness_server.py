"""A public C2SP tlog-witness (v1.1.0) with open registration: the server behind tracekit.public_witness.

    tracekit public-witness init --home /srv/pw --name witness.example.org/w1   # prints the cosignature vkey
    tracekit public-witness serve --home /srv/pw --host 0.0.0.0 --port 7380 --insecure-http   # TLS in front (Caddy)

    POST /add-checkpoint   tlog_witness's request: "old <size>", the consistency proof, a blank line, the signed note
    POST /register         {"origin", "vkey", "checkpoint"}: the log's Ed25519 vkey (named after the origin) and a
                           note of that origin signed by it, as proof of possession; one vkey per origin, the first
    GET  /stats            {"origins_7d", "weeks": {"2026-W41": n}}: distinct origins cosigned, never which

Per origin it keeps the vkey, the latest cosigned size and root, and when it last cosigned (state.db, SQLite with
synchronous=FULL: each request is one transaction). It cosigns a note only when it verifies under the registered key
and the consistency proof from the stored size holds, so it never cosigns two trees that fork. Limits: bodies of
MAX_BODY (the client's), REGISTRATIONS_PER_DAY per client network (an IPv4 address, an IPv6 /64), CHECKPOINTS_PER_MIN
per origin (429), MAX_ORIGINS.
Client IPs are counted in memory for the current window only, never stored, and no request is logged."""
import argparse
import base64
import binascii
import datetime
import ipaddress
import json
import os
import re
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler

from tracekit import crypto, merkle
from tracekit.public_witness import ORIGIN, ORIGIN_FORMAT
from tracekit.deploy import files
from tracekit.format import checkpoint
from tracekit.netserver import MAX_PER_IP, MAX_THREADS, Server
from tracekit.tlog_witness import MAX_BODY

REGISTRATIONS_PER_DAY, CHECKPOINTS_PER_MIN, MAX_ORIGINS = 100, 30, 100_000
MAX_PROOF = 63
DAY_S, WEEK_S = 86400, 7 * 86400


def init(home, name):
    """Create the witness key in `home` once; returns its cosignature vkey."""
    os.makedirs(home, 0o700, exist_ok=True)
    d = files.open_dir(home)
    try:
        if files.read(d, "witness.key") is None:
            secret, public = crypto.generate()   # the vkey first: a key without its vkey is never left behind
            files.write(d, "witness.vkey", (checkpoint.vkey(name, checkpoint.COSIGNATURE, public) + "\n").encode(),
                        0o644)
            files.write(d, "witness.key", secret)
        return files.read(d, "witness.vkey").decode("ascii").strip()
    finally:
        files.close(d)


def week(ts):
    y, w, _ = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isocalendar()
    return f"{y}-W{w:02d}"


class Witness:
    def __init__(self, home):
        d = files.open_dir(home)
        try:
            self.secret, vkey = files.read(d, "witness.key"), files.read(d, "witness.vkey")
        finally:
            files.close(d)
        if self.secret is None or vkey is None:
            raise ValueError(f"{home} has no witness key: run `tracekit public-witness init` first")
        self.vkey = vkey.decode("ascii").strip()
        self.name = checkpoint.parse_vkey(self.vkey)[0]
        self.lock = threading.Lock()
        self.db = sqlite3.connect(os.path.join(home, "state.db"), isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS origins (origin TEXT PRIMARY KEY, vkey TEXT NOT NULL, "
                        "size INTEGER NOT NULL, root BLOB NOT NULL, last INTEGER, week TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS weeks (week TEXT PRIMARY KEY, n INTEGER NOT NULL)")
        self._hits = {}   # limit -> (window, {key: count}): the current window's counts only

    def close(self):
        self.db.close()

    def _limited(self, limit, key, most, period):
        """Count one hit of `key`; True once it is over `most` in this `period`."""
        with self.lock:
            window = int(time.time() // period)
            if self._hits.get(limit, (None,))[0] != window:
                self._hits[limit] = (window, {})
            counts = self._hits[limit][1]
            counts[key] = counts.get(key, 0) + 1
            return counts[key] > most

    def register(self, ip, req):
        """-> (status, text)."""
        try:   # one IPv6 host holds a whole /64
            net = str(ipaddress.ip_network(f"{ip}/64" if ":" in ip else ip, strict=False))
        except ValueError:
            net = ip
        if self._limited("register", net, REGISTRATIONS_PER_DAY, DAY_S):
            return 429, f"over {REGISTRATIONS_PER_DAY} registrations from your network today: try again tomorrow\n"
        if not (isinstance(req, dict) and set(req) == {"origin", "vkey", "checkpoint"}
                and all(isinstance(v, str) for v in req.values())):
            return 400, "the body is JSON {origin, vkey, checkpoint}\n"
        origin = req["origin"]
        if not (len(origin) <= 255 and ORIGIN.fullmatch(origin)):
            return 400, f"this witness takes origins shaped {ORIGIN_FORMAT}: set `origin` in signer.yaml\n"
        try:
            name, _, type_, _ = checkpoint.parse_vkey(req["vkey"])
            if type_ != checkpoint.ED25519 or name != origin:
                return 400, "the vkey is the log's Ed25519 key, named after the origin\n"
            if checkpoint.open_note(req["checkpoint"], [req["vkey"]])[0] != origin:
                return 400, "the checkpoint is of another origin\n"
        except checkpoint.NoteError as e:
            return 403, f"the checkpoint does not verify under the vkey: {e}\n"
        with self.lock, self.db:   # one transaction: committed on return, rolled back on an exception
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute("SELECT vkey FROM origins WHERE origin = ?", (origin,)).fetchone()
            if row:
                return (200, "registered\n") if row[0] == req["vkey"] else \
                    (409, "this origin is registered with another key: set another `origin` in signer.yaml\n")
            if self.db.execute("SELECT count(*) FROM origins").fetchone()[0] >= MAX_ORIGINS:
                return 403, "this witness is full: run your own witness (docs/witnesses.md)\n"
            self.db.execute("INSERT INTO origins VALUES (?, ?, 0, ?, NULL, NULL)", (origin, req["vkey"], merkle.root([])))
            return 200, "registered\n"

    def add_checkpoint(self, body):
        """-> (status, text): C2SP tlog-witness add-checkpoint."""
        head, sep, note = body.partition("\n\n")
        lines = head.split("\n")
        m = re.fullmatch(r"old (0|[1-9][0-9]{0,19})", lines[0])
        if not (sep and m and len(lines) <= 1 + MAX_PROOF):
            return 400, "malformed request\n"
        old = int(m.group(1))
        try:
            proof = [base64.b64decode(h, validate=True) for h in lines[1:]]
        except (binascii.Error, ValueError):
            return 400, "malformed consistency proof\n"
        origin = note.partition("\n")[0]
        with self.lock:
            row = self.db.execute("SELECT vkey FROM origins WHERE origin = ?", (origin,)).fetchone()
        if row is None:
            return 404, "unknown origin: POST /register it first\n"
        try:
            _, size, root, _ = checkpoint.open_note(note, [row[0]])
        except checkpoint.NoteError as e:
            return 403, f"not signed by the origin's registered key ({e}); a new log key needs a new `origin`\n"
        if old > size:
            return 400, "old size is past the checkpoint\n"
        if size >= 1 << 63:   # SQLite's INTEGER
            return 400, "the tree size is over 2^63 - 1\n"
        if self._limited("checkpoint", origin, CHECKPOINTS_PER_MIN, 60):
            return 429, f"over {CHECKPOINTS_PER_MIN} checkpoints of this origin this minute\n"
        now = int(time.time())
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            stored, stored_root, last_week = self.db.execute(
                "SELECT size, root, week FROM origins WHERE origin = ?", (origin,)).fetchone()
            if old != stored:
                return 409, f"{stored}\n"
            if old == 0 and proof:
                return 400, "no proof from size 0\n"
            if old and not merkle.verify_consistency(old, size, stored_root, root, proof):
                return 422, "the checkpoint is not consistent with the one this witness cosigned\n"
            this_week = week(now)
            self.db.execute("UPDATE origins SET size = ?, root = ?, last = ?, week = ? WHERE origin = ?",
                            (size, root, now, this_week, origin))
            if last_week != this_week:
                self.db.execute("INSERT INTO weeks VALUES (?, 1) ON CONFLICT(week) DO UPDATE SET n = n + 1",
                                (this_week,))
        return 200, checkpoint.cosign(note.partition("\n\n")[0] + "\n", self.name, self.secret, now)

    def stats(self):
        with self.lock:
            recent = self.db.execute("SELECT count(*) FROM origins WHERE last >= ?",
                                     (int(time.time()) - WEEK_S,)).fetchone()[0]
            weeks = dict(self.db.execute("SELECT week, n FROM weeks ORDER BY week"))
        return {"origins_7d": recent, "weeks": weeks}


def make_handler(witness, proxied=False):
    """proxied: behind the TLS proxy (deploy/public-witness), whose X-Forwarded-For names the client: Caddy sets it
    to the address it was connected from."""
    class H(BaseHTTPRequestHandler):
        server_version = "tracekit-public-witness"

        def log_message(self, *a):
            pass

        def _send(self, code, text, ctype="text/plain; charset=utf-8"):
            data = text.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path != "/stats":
                return self._send(404, "not found\n")
            return self._send(200, json.dumps(witness.stats()), "application/json")

        def do_POST(self):
            if self.path not in ("/add-checkpoint", "/register"):
                return self._send(404, "not found\n")
            try:
                n = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                n = -1
            if not 0 < n <= MAX_BODY:
                return self._send(413, f"the body is 1 to {MAX_BODY} bytes\n")
            try:
                body = self.rfile.read(n).decode("utf-8")
                if self.path == "/register":
                    ip = (self.headers.get("X-Forwarded-For", "").rpartition(",")[2].strip() if proxied
                          else "") or self.client_address[0]
                    code, text = witness.register(ip, json.loads(body))
                else:
                    code, text = witness.add_checkpoint(body)
            except ValueError:   # not UTF-8, not JSON
                code, text = 400, "malformed request\n"
            self._send(code, text, "text/x.tlog.size" if code == 409 and self.path == "/add-checkpoint"
                       else "text/plain; charset=utf-8")
    return H


class _Server(Server):
    witness = None

    def server_close(self):
        super().server_close()
        if self.witness:
            self.witness.close()


def serve(home, host="127.0.0.1", port=7380, proxied=False):
    """proxied: every connection comes from the TLS proxy, so the per-address connection limit is lifted."""
    srv = _Server((host, port), BaseHTTPRequestHandler, max_per_ip=MAX_THREADS if proxied else MAX_PER_IP)
    try:
        srv.witness = Witness(home)
    except BaseException:
        srv.server_close()
        raise
    srv.RequestHandlerClass = make_handler(srv.witness, proxied)
    return srv


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit public-witness")
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init", help="create the witness key; prints its cosignature vkey")
    i.add_argument("--home", required=True)
    i.add_argument("--name", required=True, help="the witness's key name, e.g. witness.example.org/w1")
    s = sub.add_parser("serve")
    s.add_argument("--home", required=True)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=7380)
    s.add_argument("--insecure-http", action="store_true", help="plain HTTP beyond loopback, for TLS terminated in front")
    s.add_argument("--proxied", action="store_true", help="behind a proxy that sets X-Forwarded-For to the client's "
                                                          "address (Caddy): limits count that address")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "init":
            print(init(a.home, a.name))
            return 0
        if a.host not in ("127.0.0.1", "localhost", "::1") and not a.insecure_http:
            print("tracekit public-witness: refusing plain HTTP on a non-loopback address; terminate TLS in front "
                  "(deploy/public-witness) and pass --insecure-http", file=sys.stderr)
            return 2
        srv = serve(a.home, a.host, a.port, a.proxied)
    except (OSError, ValueError) as e:
        print(f"tracekit public-witness: {e}", file=sys.stderr)
        return 2
    print(f"tracekit public-witness: {srv.witness.vkey} listening on http://{a.host}:{srv.server_address[1]}",
          flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
