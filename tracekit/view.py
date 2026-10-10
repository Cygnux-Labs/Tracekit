"""`tracekit view`: the laptop viewer for the v2 signer's runs (04-design §10).

Reads the signer's file store without its lock (FileReader), exports each run with bundle_v2 and checks it with
verify.v2, the code `tracekit verify` runs, against a trust config that pins the store's own log.vkey. The page, server
and security are the observer's (observe.py): each run's verifier report is an alert on the run's lane, followed by its
events only when it verifies; a run that fails is shown only as the failure report. A run whose last record no
checkpoint covers yet waits for the signer's next note (at most CHECKPOINT_S). The viewer never opens a signing key.
Every request needs the token in the printed URL ($TRACEKIT_VIEW_TOKEN, else a random one), exchanged once for a
session cookie, also on loopback, where any local user or process could otherwise connect.

Dev assurance: the pinned log key is read from the directory being checked, so a run that verifies matches the key of
whoever can write that directory, the same user as the dev signer and this viewer.

    tracekit view [--dev | --config signer.yaml | --data-dir DIR] [--host H] [--port N]
                  [--tls-cert FILE --tls-key FILE | --insecure-http]
"""
import argparse
import atexit
import collections
import io
import json
import os
import secrets
import shutil
import ssl
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer

from . import observe
from .bundle_v2 import export
from .format.records import RecordSigner
from .signer.service import dev_data_dir, load_config, read_vkey
from .storage.base import StorageCorrupt
from .storage.file import NOTE, FileReader
from .verify import v2

POLL_S = 1.0
HANDSHAKE_S = 30
DEV_NOTE = ("trust pins this store's own log.vkey: dev assurance, the viewer runs as the same user as the dev signer "
            "and proves only that the records match that key")


class Translator(observe.Translator):
    """v2 records -> the observer's record shape. A v2 policy.decision names its tool (there is no tool.call), and a
    type the observer has no row for is shown as an info alert, so every record of the run appears in order."""

    def feed(self, rec):
        e = rec["event"]
        t, d = e["type"], e.get("data") or {}
        if t == "run.registered":
            self.agent_names[e["run_id"]] = (d.get("agent") or {}).get("name") or "agent"
            return [{**self._base(e, rec, "SessionStart"), "source": f"{d.get('signer_isolation')} signer"}]
        if t in ("run.closing", "run.final"):
            return [{**self._base(e, rec, "SessionEnd"), "reason": d.get("reason") or t}]
        if t == "policy.decision":
            self.pending[d.get("tool_use_id")] = ({**e, "data": {"name": d.get("tool"), "tool_use_id": d.get("tool_use_id")}},
                                                  rec)
        return super().feed(rec) or [self.alert(e, rec, "info", t, json.dumps(d, ensure_ascii=False)[:200])]


class StoreFeed:
    """What observe.make_handler serves (records, base, lock, verify()), from a v2 signer's data dir."""

    def __init__(self, data_dir):
        self.store = os.path.join(data_dir, "store")
        self.records, self.base, self.lock = [], 0, threading.Condition()
        self.runs = {}   # (tenant, run_id) -> {"count": records verified, "shown": records translated, "failed": report}
        self.tr = Translator()
        self.tmp = tempfile.mkdtemp(prefix="tk-view-")
        atexit.register(shutil.rmtree, self.tmp, True)
        self.trust = os.path.join(self.tmp, "trust.json")
        with open(self.trust, "w", encoding="utf-8") as f:
            json.dump({"logs": [read_vkey(data_dir)], "witnesses": [], "algs": [RecordSigner.alg],
                       "witnesses_required": 0}, f)
        threading.Thread(target=self._watch, daemon=True).start()

    def _watch(self):
        seen = None
        while True:
            stamp = []
            for name in ("records.jsonl", NOTE):
                try:
                    st = os.stat(os.path.join(self.store, name))
                    stamp.append((st.st_size, st.st_mtime_ns))
                except FileNotFoundError:
                    stamp.append(None)
            if stamp != seen:
                seen = stamp
                try:
                    self.refresh()
                except (OSError, ValueError, StorageCorrupt) as e:
                    print(f"tracekit view: cannot read {self.store}: {e}", file=sys.stderr, flush=True)
            time.sleep(POLL_S)

    def refresh(self):
        """Verify every run that grew since it was last verified and a checkpoint now covers."""
        reader = FileReader(self.store)
        note = reader.checkpoint_latest()
        if note and note[0] > reader.tree.size:
            reader = FileReader(self.store)   # opened after the note: holds every record it covers
        for key, run in list(reader.runs.items()):
            if note and run["seqs"][-1] < note[0] and len(run["seqs"]) != self.runs.get(key, {}).get("count"):
                self._verify(reader, note[1], key, len(run["seqs"]))

    def _verify(self, reader, note, key, count):
        tenant, run_id = key
        out = os.path.join(self.tmp, "run.tkb")
        try:
            export(reader, tenant, run_id, note, out)
            rep, code = v2.verify(out, self.trust)
        except ValueError as e:   # the store does not match its own checkpoint
            rep, code = v2.Report(), v2.EXIT_FAIL
            rep.integrity, rep.assurance = "FAILED", "none"
            rep.check("export", False, str(e))
        text = io.StringIO()
        v2.print_report(rep, code, text)
        state = self.runs.get(key) or {"count": 0, "shown": 0, "failed": None}
        e = {"run_id": run_id}
        if code:
            new = [self.tr.alert(e, {}, "high", f"RUN {run_id} · Integrity {rep.integrity}", text.getvalue())]
            state = dict(state, count=count, failed=rep.integrity)
        else:
            records = list(reader.iter_run(tenant, run_id))
            new = [x for r in records[state["shown"]:] for x in self.tr.feed(r)]
            types = collections.Counter(r["event"]["type"] for r in records)
            verdicts = collections.Counter(r["event"]["data"].get("decision") for r in records
                                           if r["event"]["type"] == "policy.decision")
            summary = (f"tenant {tenant} · agent {self.tr.agent_names.get(run_id, '?')} · "
                       f"{'final' if types['run.final'] else 'closing' if types['run.closing'] else 'open'} · decisions "
                       + (", ".join(f"{v} {n}" for v, n in sorted(verdicts.items())) or "none")
                       + f" · approvals {types['approval']} · gaps {types['capture.gap']}")
            new.append(self.tr.alert(e, records[-1], "info", f"RUN {run_id} · Integrity {rep.integrity} · Assurance "
                                     f"{rep.assurance.split(';')[0]}", f"{summary}\n{DEV_NOTE}\n\n{text.getvalue()}"))
            state = dict(state, count=count, shown=len(records), failed=None)
        with self.lock:
            self.runs[key] = state
            # lean: keeps every translated record in memory; bound it like observe.Feed once stores hold millions
            self.records.extend(new)
            self.lock.notify_all()

    def verify(self):
        """For the page's chain badge: records verified, and the runs that failed."""
        with self.lock:
            return (sum(s["shown"] for s in self.runs.values() if not s["failed"]),
                    [f"run {k[1]} of tenant {k[0]}: {s['failed']}" for k, s in self.runs.items() if s["failed"]], None)


class _TLSServer(ThreadingHTTPServer):
    """HTTPS, with each handshake on the request's own thread so a silent client never stalls the others."""
    tls = None

    def finish_request(self, request, client_address):
        request.settimeout(HANDSHAKE_S)   # a client that connects and stays silent frees its thread
        try:
            s = self.tls.wrap_socket(request, server_side=True)
        except OSError:   # the timeout, or not TLS
            return
        with s:
            super().finish_request(s, client_address)


def server(feed, host, port, token, tls=None):
    """The viewer's HTTP server (HTTPS with `tls`, an ssl.SSLContext), open to requests that present `token` (or the
    session cookie it is exchanged for); call serve_forever()."""
    if not token:
        raise ValueError("the viewer needs a token")
    srv = (_TLSServer if tls else ThreadingHTTPServer)((host, port),
                                                       observe.make_handler(feed, token, [host], secure=bool(tls)))
    srv.tls, srv.daemon_threads = tls, True
    return srv


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit view", description="laptop viewer for the v2 signer's runs (read-only)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dev", action="store_true", help="the same-user dev signer's data dir (the default)")
    g.add_argument("--config", help="signer.yaml: view its data_dir")
    g.add_argument("--data-dir", help="a signer data dir (holds store/ and log.vkey)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7778)
    ap.add_argument("--tls-cert", help="PEM certificate: serve HTTPS (required beyond loopback)")
    ap.add_argument("--tls-key", help="PEM private key of --tls-cert")
    ap.add_argument("--insecure-http", action="store_true", help="serve plain HTTP beyond loopback anyway")
    a = ap.parse_args(argv)
    loopback = a.host in observe.LOOPBACK_HOSTS
    if bool(a.tls_cert) != bool(a.tls_key):
        print("tracekit view: --tls-cert and --tls-key go together", file=sys.stderr)
        return 2
    if not loopback and not a.tls_cert:
        if not a.insecure_http:
            print("tracekit view: refusing plain HTTP beyond loopback; pass --tls-cert and --tls-key "
                  "(or --insecure-http)", file=sys.stderr)
            return 2
        print("tracekit view: WARNING: plain HTTP beyond loopback; the token and every record cross the network "
              "unencrypted", file=sys.stderr)
    token = os.environ.get("TRACEKIT_VIEW_TOKEN") or secrets.token_urlsafe(24)
    try:
        tls = None
        if a.tls_cert:
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(a.tls_cert, a.tls_key)
        data_dir = a.data_dir or (load_config(a.config)["data_dir"] if a.config else dev_data_dir())
        feed = StoreFeed(data_dir)
        srv = server(feed, a.host, a.port, token, tls)
    except (OSError, ValueError) as e:
        print(f"tracekit view: {e}", file=sys.stderr)
        return 1
    scheme = "https" if tls else "http"
    print(f"tracekit view on {scheme}://{a.host}:{srv.server_address[1]}/"
          + ("" if os.environ.get("TRACEKIT_VIEW_TOKEN") else f"?token={token}")
          + f"  (store: {feed.store}, read-only; {DEV_NOTE})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
