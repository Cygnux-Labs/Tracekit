"""Webhooks of the v2 signer (docs/webhooks.md): each `webhook` entry of signer.yaml gets the signer's decisions, denies,
approvals, gaps, tamper and incident records as OCSF 1.3 events, POSTed as a JSON array from its own thread.

    webhook: [{url: https://siem.example.org/tracekit, format: ocsf, events: [deny, approval, gap, tamper, incident],
               secret_file: webhook.secret},
              {format: slack, events: [incident], secret_file: slack.url}]   # the Slack webhook URL is the secret

A deny, a refused approval, a gap and a tamper record are Detection Findings (class 2004); other decisions and
approval steps are API Activity (class 6003). Agent content leaves only as the digests and commitments the records
hold. Each body is signed: `X-Tracekit-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>." + body)>`.
The writer only queues records (QUEUE at most; more are dropped and counted); failed posts are retried with backoff,
then dropped and counted in tracekit_signer_webhook_dropped_total.

Incident records (INCIDENT: incident.*, run.held/resumed/quarantined, identity.suspension) go through an Outbox
instead: a cursor over the record log that moves only once the endpoint took a batch, so they are delivered at least
once, across outages and restarts, as OCSF Incident Findings (class 2005, `finding_info_list[0].uid` the incident id) or
Slack messages. Operator notes (`reason`) never leave.
"""
import hashlib
import hmac
import json
import logging
import os
import queue
import threading
import time
import urllib.error
import urllib.request

from tracekit import __version__
from tracekit.deploy import files
from tracekit.client import no_redirect_opener, remote_url_error
from tracekit.otel import _ns

EVENTS = ("decision", "deny", "approval", "gap", "tamper", "incident")
INCIDENT = ("incident.opened", "incident.updated", "incident.capped", "incident.resolved", "incident.response",
            "run.held", "run.resumed", "run.quarantined", "identity.suspension")
QUEUE, BATCH, RETRIES, BACKOFF_S, TIMEOUT_S = 10000, 100, 5, (0.5, 30.0), 10
OCSF_VERSION = "1.3.0"
# what of a record's data leaves: ids, verdicts, identities, digests and commitments, never free text
KEEP = ("decision", "rule_ids", "tool", "tool_use_id", "args_commitment", "approval_id", "binding_digest", "policy_hash",
        "requester", "approver", "via", "self_approved", "break_glass", "expires_at", "kind", "before", "after")
INCIDENT_KEEP = ("incident_id", "trigger", "rule_ids", "scope", "mode", "actions", "would", "by", "person", "inherited",
                 "resumed", "enabled", "identity", "state", "cap")
SCAN, POLL_S = 1000, 1.0   # records an outbox reads at a time; how long it sleeps when the log has nothing new


def kinds(e):
    """The `events` names record event `e` falls under."""
    t = e["type"]
    if t == "policy.decision":
        return {"decision", "deny"} if e["data"]["decision"] == "deny" else {"decision"}
    return {"approval"} if t.startswith("approval") else {"gap"} if t == "capture.gap" else \
        {"tamper"} if t == "trace.tamper" else {"incident"} if t in INCIDENT else set()


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


def ocsf_incident(r, related=()):
    """The OCSF Incident Finding of incident record `r`; `related`: the records it cites, each a related event whose
    uid is its event_hash."""
    e, d = r["event"], r["event"]["data"]
    activity, status = {"incident.opened": (1, 1), "incident.resolved": (3, 4)}.get(e["type"], (2, 2))
    severity = 4 if e["type"] in ("run.held", "run.quarantined") or "quarantine" in d.get("actions", ()) else 3
    uid = d.get("incident_id") or f"{e['tenant']}/{d.get('identity', e['type'])}"
    return {"time": int(_ns(e["ts"])) // 1_000_000, "message": e["type"], "class_uid": 2005, "category_uid": 2,
            "activity_id": activity, "type_uid": 200500 + activity, "severity_id": severity, "status_id": status,
            "metadata": {"version": OCSF_VERSION, "uid": e["id"], "correlation_uid": e["run_id"], "log_name": e["log_id"],
                         "product": {"name": "Tracekit", "vendor_name": "Tracekit", "version": __version__}},
            "finding_info_list": [{"uid": uid, "title": f"{e['type']} {d.get('trigger') or d.get('state') or ''}".strip(),
                                   "types": [e["type"]],
                                   "related_events": [{"uid": x["hash"], "type": x["event"]["type"],
                                                       "product_uid": "tracekit"} for x in [r, *related]]}],
            "unmapped": {"tracekit": {"tenant": e["tenant"], "run_id": e["run_id"], "run_seq": e["run_seq"],
                                      "seq": e["seq"], "type": e["type"], "event_hash": r["hash"],
                                      **{k: d[k] for k in INCIDENT_KEEP if k in d}}}}


def _slack(text):
    """`text` as Slack mrkdwn shows it literally: no mention, link or markup a tool name or principal could carry."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack(r, related=()):
    """A Slack message line for incident record `r`: what happened, where and to which tools, all escaped."""
    e, d = r["event"], r["event"]["data"]
    tools = sorted({x["event"]["data"]["tool"] for x in related if isinstance(x["event"]["data"].get("tool"), str)})
    scope = d.get("scope") or {}
    parts = [f"Tracekit {e['type']}", d.get("incident_id"), d.get("trigger"), ", ".join(d.get("rule_ids") or ()),
             scope and f"{scope['kind']} {scope['id']}", f"run {e['run_id']} (tenant {e['tenant']})",
             d.get("actions") and "actions " + ", ".join(d["actions"]), d.get("identity") and f"identity {d['identity']}",
             d.get("state"), d.get("by") and f"by {d['by']}", tools and "tools " + ", ".join(tools)]
    return "`" + _slack(" · ".join(str(x) for x in parts if x)).replace("`", "'") + "`"


def post(url, body, secret=None):
    """POST `body` (signed when there is a secret); the HTTP status, 0 when the endpoint can't be reached."""
    headers = {"Content-Type": "application/json", **({"X-Tracekit-Signature": signature(secret, body)} if secret else {})}
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with no_redirect_opener().open(req, timeout=TIMEOUT_S) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except OSError:   # unreachable, reset or timed out
        return 0


def signature(secret, body, t=None):
    t = int(time.time()) if t is None else t
    return f"t={t},v1=" + hmac.new(secret, f"{t}.".encode() + body, hashlib.sha256).hexdigest()


def load(section, base, path):
    """The Sender arguments of signer.yaml's `webhook` section; secret files are relative to `base`."""
    out = []
    for w in section if isinstance(section, list) else [None]:
        slack_ = isinstance(w, dict) and w.get("format") == "slack"
        if not (isinstance(w, dict) and set(w) == {"format", "events", "secret_file"} | (set() if slack_ else {"url"})
                and (slack_ or isinstance(w["url"], str) and not remote_url_error(w["url"]) and w["format"] == "ocsf")
                and isinstance(w["events"], list) and w["events"] and set(w["events"]) <= set(EVENTS)
                and (not slack_ or w["events"] == ["incident"]) and isinstance(w["secret_file"], str)):
            raise ValueError(f"{path}: each webhook is {{url (https, or http to loopback), format: ocsf, events (of "
                             f"{', '.join(EVENTS)}), secret_file}}, or {{format: slack, events: [incident], "
                             "secret_file (holding the Slack webhook URL)}")
        with open(os.path.join(base, w["secret_file"]), "rb") as f:
            secret = f.read().strip()
        if not secret:
            raise ValueError(f"{path}: {w['secret_file']} is empty")
        if slack_:
            url = secret.decode("utf-8", "replace")
            if not url.startswith("https://") or remote_url_error(url):
                raise ValueError(f"{path}: {w['secret_file']} does not hold an https Slack webhook URL")
            out.append({"url": url, "events": ["incident"], "secret": None, "format": "slack"})
        else:
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
                status = post(self.url, body, self.secret)
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


class Outbox:
    """Delivers the incident records of the log to one webhook at least once (receivers dedupe by incident id and
    record uid): a cursor over the record log, kept in `path`, that moves past a batch only once the endpoint took it.
    `read(lo, hi)`: the records with lo <= seq < hi written so far; `related(record)`: the records it cites; `start`:
    where a new cursor starts (the log's size: earlier records are not sent; an unreadable cursor starts again at 0).
    `failed`: a metrics Counter by reason."""

    def __init__(self, url, secret, fmt, path, read, related, start, failed):
        self.url, self.secret, self.fmt, self.path, self.read, self.related = url, secret, fmt, path, read, related
        self.failed = failed
        try:
            with open(path, encoding="utf-8") as f:
                self.cursor = json.load(f)["cursor"]
            if type(self.cursor) is not int or self.cursor < 0:
                raise ValueError(f"cursor {self.cursor!r}")
        except FileNotFoundError:
            self.cursor = start
        except (OSError, ValueError, KeyError, TypeError) as e:   # resend from the log's start: receivers dedupe
            logging.getLogger(__name__).warning("tracekit signer: the outbox cursor %s is unreadable (%s): resending "
                                                "incident records from the start of the log", path, e)
            self.cursor = 0
        self._stop, self.wake = threading.Event(), threading.Event()
        self._thread = threading.Thread(target=self._loop, name="tracekit-signer-outbox", daemon=True)
        self._thread.start()

    def put(self, records):
        """On the writer: wake the outbox when a batch holds an incident record."""
        if any(r["event"]["type"] in INCIDENT for r in records):
            self.wake.set()

    def _body(self, batch):
        rel = [self.related(r) for r in batch]
        if self.fmt == "slack":
            return json.dumps({"text": "\n".join(slack(r, x) for r, x in zip(batch, rel))}).encode()
        return json.dumps([ocsf_incident(r, x) for r, x in zip(batch, rel)]).encode()

    def _loop(self):
        attempt = 0
        while not self._stop.is_set():
            try:
                records = list(self.read(self.cursor, self.cursor + SCAN))
                batch = [r for r in records if r["event"]["type"] in INCIDENT][:BATCH]
                status = post(self.url, self._body(batch), self.secret) if batch else 200
            except Exception:   # storage down, or a record this mapping does not know: try again later
                self.failed.inc("error")
                records, status = [], 0
            if not records:
                self.wake.wait(POLL_S)
                self.wake.clear()
                continue
            if not (200 <= status < 300 or 400 <= status < 500 and status not in (408, 429)):
                self.failed.inc("retry")
                attempt += 1
                self._stop.wait(min(BACKOFF_S[0] * 2 ** attempt, BACKOFF_S[1]))
                continue
            if status >= 300:   # refused: sending it again won't help
                self.failed.inc("refused", len(batch))
            attempt = 0
            last = batch[-1] if len(batch) == BATCH else records[-1]
            self.cursor = last["event"]["seq"] + 1
            try:
                files.write_json(self.path, {"cursor": self.cursor})
            except OSError:   # kept in memory: a restart resends from the last saved cursor
                pass

    def close(self):
        self._stop.set()
        self.wake.set()
        self._thread.join()
