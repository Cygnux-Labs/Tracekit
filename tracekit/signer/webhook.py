"""Webhooks of the v2 signer (docs/webhooks.md): each `webhook` entry of signer.yaml gets the signer's decisions, denies,
approvals, gaps and tamper records as OCSF 1.3 events, POSTed as a JSON array from its own thread.

    webhook: [{url: https://siem.example.org/tracekit, format: ocsf, events: [deny, approval, gap, tamper],
               secret_file: webhook.secret}]

A deny, a refused approval, a gap and a tamper record are Detection Findings (class 2004); other decisions and
approval steps are API Activity (class 6003). Agent content leaves only as the digests and commitments the records
hold. Each body is signed: `X-Tracekit-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>." + body)>`.
The writer only queues records (QUEUE at most; more are dropped and counted); failed posts are retried with backoff,
then dropped and counted in tracekit_signer_webhook_dropped_total.
"""
import hashlib
import hmac
import json
import os
import queue
import threading
import time
import urllib.error
import urllib.request

from tracekit import __version__
from tracekit.client import no_redirect_opener, remote_url_error
from tracekit.otel import _ns

EVENTS = ("decision", "deny", "approval", "gap", "tamper")
QUEUE, BATCH, RETRIES, BACKOFF_S, TIMEOUT_S = 10000, 100, 5, (0.5, 30.0), 10
OCSF_VERSION = "1.3.0"
# what of a record's data leaves: ids, verdicts, identities, digests and commitments, never free text
KEEP = ("decision", "rule_ids", "tool", "tool_use_id", "args_commitment", "approval_id", "binding_digest", "policy_hash",
        "requester", "approver", "via", "self_approved", "break_glass", "expires_at", "kind", "before", "after")


def kinds(e):
    """The `events` names record event `e` falls under."""
    t = e["type"]
    if t == "policy.decision":
        return {"decision", "deny"} if e["data"]["decision"] == "deny" else {"decision"}
    return {"approval"} if t.startswith("approval") else {"gap"} if t == "capture.gap" else \
        {"tamper"} if t == "trace.tamper" else set()


def ocsf(r):
    """The OCSF event of record `r`."""
    e, d = r["event"], r["event"]["data"]
    who = d.get("approver") or d.get("requester")
    out = {"time": int(_ns(e["ts"])) // 1_000_000, "message": e["type"],
           "metadata": {"version": OCSF_VERSION, "uid": e["id"], "correlation_uid": e["run_id"], "log_name": e["log_id"],
                        "product": {"name": "Tracekit", "vendor_name": "Tracekit", "version": __version__}},
           "unmapped": {"tracekit": {"tenant": e["tenant"], "run_id": e["run_id"], "run_seq": e["run_seq"],
                                     "seq": e["seq"], "type": e["type"], "event_hash": r["hash"],
                                     **{k: d[k] for k in KEEP if k in d}}}}
    if (e["type"] == "policy.decision" and d["decision"] == "deny") or e["type"] in (
            "approval.refused", "approval.binding_mismatch", "capture.gap", "trace.tamper"):
        title = f"{e['type']} {d['kind']}" if "kind" in d else e["type"]
        return dict(out, class_uid=2004, category_uid=2, activity_id=1, type_uid=200401,
                    severity_id=5 if e["type"] == "trace.tamper" else 3,
                    finding_info={"uid": e["id"], "title": title, "types": [e["type"]]})
    activity = 1 if e["type"] == "approval.request" else 3 if e["type"].startswith("approval") else 99
    return dict(out, class_uid=6003, category_uid=6, activity_id=activity, type_uid=600300 + activity, severity_id=1,
                api={"operation": e["type"], "service": {"name": "tracekit-signer"}},
                actor={"user": {"uid": who}} if who else {"app_uid": e["run_id"]}, src_endpoint={"uid": e["run_id"]})


def signature(secret, body, t=None):
    t = int(time.time()) if t is None else t
    return f"t={t},v1=" + hmac.new(secret, f"{t}.".encode() + body, hashlib.sha256).hexdigest()


def load(section, base, path):
    """The Sender arguments of signer.yaml's `webhook` section; secret files are relative to `base`."""
    out = []
    for w in section if isinstance(section, list) else [None]:
        if not (isinstance(w, dict) and set(w) == {"url", "format", "events", "secret_file"}
                and isinstance(w["url"], str) and not remote_url_error(w["url"]) and w["format"] == "ocsf"
                and isinstance(w["events"], list) and w["events"] and set(w["events"]) <= set(EVENTS)
                and isinstance(w["secret_file"], str)):
            raise ValueError(f"{path}: each webhook is {{url (https, or http to loopback), format: ocsf, events (of "
                             f"{', '.join(EVENTS)}), secret_file}}")
        with open(os.path.join(base, w["secret_file"]), "rb") as f:
            secret = f.read().strip()
        if not secret:
            raise ValueError(f"{path}: {w['secret_file']} is empty")
        out.append({"url": w["url"], "events": w["events"], "secret": secret})
    return out


class Sender:
    """POSTs the OCSF events of the records given to `put` that fall under `events` to `url`. `dropped`: a metrics
    Counter by reason (queue_full, failed, shutdown)."""

    def __init__(self, url, events, secret, dropped):
        self.url, self.events, self.secret, self.dropped = url, set(events), secret, dropped
        self._q, self._stop = queue.Queue(QUEUE), threading.Event()
        self._thread = threading.Thread(target=self._loop, name="tracekit-signer-webhook", daemon=True)
        self._thread.start()

    def put(self, records):
        """Queue `records` (on the writer: never blocks)."""
        for r in records:
            if kinds(r["event"]) & self.events:
                try:
                    self._q.put_nowait(r)
                except queue.Full:
                    self.dropped.inc("queue_full")

    def _post(self, body):
        req = urllib.request.Request(self.url, data=body, method="POST", headers={
            "Content-Type": "application/json", "X-Tracekit-Signature": signature(self.secret, body)})
        try:
            with no_redirect_opener().open(req, timeout=TIMEOUT_S) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except OSError:   # unreachable, reset or timed out
            return 0

    def _loop(self):
        last = False
        while not last:
            r = self._q.get()
            if r is None:
                return
            batch = [r]
            while len(batch) < BATCH:
                try:
                    r = self._q.get_nowait()
                except queue.Empty:
                    break
                if r is None:
                    last = True
                    break
                batch.append(r)
            try:
                body = json.dumps([ocsf(r) for r in batch]).encode()
            except Exception:   # a record this mapping does not know: count it, keep going
                self.dropped.inc("failed", len(batch))
                continue
            for attempt in range(RETRIES):
                status = self._post(body)
                if 200 <= status < 300:
                    break
                if 400 <= status < 500 and status not in (408, 429):   # refused: sending it again won't help
                    self.dropped.inc("failed", len(batch))
                    break
                if attempt + 1 == RETRIES:
                    self.dropped.inc("failed", len(batch))
                elif self._stop.wait(min(BACKOFF_S[0] * 2 ** attempt, BACKOFF_S[1])):
                    self.dropped.inc("shutdown", len(batch))
                    return

    def close(self):
        # lean: events still queued at shutdown are dropped (counted); persist the queue if they must survive restarts
        n = 0
        while True:
            try:
                n += self._q.get_nowait() is not None
            except queue.Empty:
                break
        if n:
            self.dropped.inc("shutdown", n)
        self._stop.set()
        self._q.put(None)
        self._thread.join()
