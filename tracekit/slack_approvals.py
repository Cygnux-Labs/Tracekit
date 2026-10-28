"""Slack approvals (docs/approvals.md#slack): a bridge that posts each pending approval it may see on the v2 signer to a
Slack channel, with Approve and Reject buttons, and answers a click as the Slack user who clicked.

    tracekit approvals slack serve --config slack.yaml

slack.yaml (relative paths are from this file):
    signer: https://signer.internal:8443     # as TRACEKIT_SIGNER; credentials from TRACEKIT_SIGNER_TOKEN_FILE etc.
    channel: C0123456789
    bot_token_file: slack-bot-token          # the app's bot token (chat:write, usergroups:read)
    signing_secret_file: slack-signing-secret
    listen: 127.0.0.1:3000                   # POST /slack/interactivity: the app's interactivity Request URL
    tls: {cert: tls.crt, key: tls.key}       # needed beyond loopback, unless insecure_http: true (TLS terminated in front)
    groups: [S0123456789]                    # user groups signer.yaml names as approvers (slack:<team>/<group>)
    poll_s: 5

The signer authorizes the bridge's identity for approval_list, approval_get and approval_decide_on_behalf only; the
approver is `slack:<team>/<user>`, and the signer checks it (or one of `groups` the user is in) against its approvers
and its self-approval rule. A callback is answered only with a valid v0 signature, a timestamp within WINDOW_S of now,
and a signature not seen before. What the agent chose (tool, arguments, reason) is posted as plain text, never mrkdwn.
An approval an agent approver's answer can still decide (its summary's `agent`) is not posted; it is once people must
answer it: escalated, in shadow mode, or with agent approvals switched off (docs/approvals.md).
"""
import hashlib
import hmac
import json
import logging
import os
import re
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler

from tracekit import yamlmini
from tracekit.client import no_redirect_opener
from tracekit.netserver import Lines, Server, body_length, read_body
from tracekit.signer.metrics import _loopback
from tracekit.signer.rpc_schema import RPCError

PATH = "/slack/interactivity"
API = "https://slack.com/api"
WINDOW_S, MAX_BODY, POLL_S, GROUPS_TTL_S, TIMEOUT_S = 300, 64 * 1024, 5.0, 60.0, 10
KEYS = {"signer", "channel", "bot_token_file", "signing_secret_file", "listen", "tls", "insecure_http", "groups",
        "poll_s", "api_url"}
SLACK_ID = re.compile(r"[A-Z0-9]{1,30}")
LIVE = ("requested", "approved")
log = logging.getLogger(__name__)


class SlackError(Exception):
    pass


def _secret(base, name):
    with open(os.path.join(base, name), encoding="utf-8") as f:
        value = f.read().strip()
    if not value:
        raise ValueError(f"{name} is empty")
    return value


def load(path):
    with open(path, encoding="utf-8") as f:
        cfg = yamlmini.load_any(f.read()) or {}
    base = os.path.dirname(os.path.abspath(path))
    need = {"signer", "channel", "bot_token_file", "signing_secret_file", "listen"}
    if not (isinstance(cfg, dict) and need <= set(cfg) <= KEYS and SLACK_ID.fullmatch(str(cfg["channel"]))
            and all(isinstance(g, str) and SLACK_ID.fullmatch(g) for g in cfg.get("groups", []))):
        raise ValueError(f"{path}: needs {', '.join(sorted(need))} (channel and groups: Slack ids); takes "
                         f"{', '.join(sorted(KEYS - need))}")
    host = str(cfg["listen"]).rpartition(":")[0].strip("[]")
    if not (_loopback(host) or cfg.get("tls") or cfg.get("insecure_http") is True):
        raise ValueError(f"{path}: listen {host!r} is not loopback: set tls {{cert, key}}, or insecure_http: true "
                         "when TLS is terminated in front")
    cfg["bot_token"] = _secret(base, cfg.pop("bot_token_file"))
    cfg["signing_secret"] = _secret(base, cfg.pop("signing_secret_file")).encode()
    if cfg.get("tls"):
        cfg["tls"] = {k: os.path.join(base, cfg["tls"][k]) for k in ("cert", "key")}
    return cfg


class Bridge:
    def __init__(self, cfg, signer):
        """`signer`: a tracekit.sdk.client.Client authenticated as the bridge."""
        self.cfg, self.signer = cfg, signer
        self.api = cfg.get("api_url", API).rstrip("/")
        self.posted = {}   # approval_id -> {"ts": message ts, "a": approval_get answer, "state": state shown}
        self.seen = {}     # signature -> its request ts: callbacks already answered
        self.seen_lock = threading.Lock()
        self.members = {}  # user group id -> (fetched at, user ids)
        self.lock = threading.RLock()

    def slack(self, method, **fields):
        body = urllib.parse.urlencode({k: v if isinstance(v, str) else json.dumps(v) for k, v in fields.items()})
        req = urllib.request.Request(f"{self.api}/{method}", data=body.encode(), method="POST", headers={
            "Authorization": f"Bearer {self.cfg['bot_token']}", "Content-Type": "application/x-www-form-urlencoded"})
        with no_redirect_opener().open(req, timeout=TIMEOUT_S) as r:
            out = json.loads(r.read())
        if not out.get("ok"):
            raise SlackError(f"{method}: {out.get('error')}")
        return out

    def verify(self, ts, sig, body, now=None):
        """Whether a callback's X-Slack-Request-Timestamp `ts` and X-Slack-Signature `sig` sign `body`, fresh and not
        seen before."""
        now = time.time() if now is None else now
        if not re.fullmatch(r"[0-9]{1,12}", ts or "") or abs(now - int(ts)) > WINDOW_S:
            return False
        want = "v0=" + hmac.new(self.cfg["signing_secret"], f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()
        if not (sig or "").isascii() or not hmac.compare_digest(want, sig):
            return False
        with self.seen_lock:   # not self.lock: a click is never kept waiting on a Slack call
            # lean: prunes the whole cache per callback; a time-ordered deque if callbacks pass a few per second
            # kept by the request's own ts, which is what freshness is judged by: a clock behind Slack's can't reopen it
            self.seen = {k: t for k, t in self.seen.items() if abs(now - t) <= WINDOW_S}
            if sig in self.seen:
                return False
            self.seen[sig] = int(ts)
        return True

    @staticmethod
    def blocks(a, state=None, user=None, answered=None):
        def one(v):
            """Agent-supplied text on one line, quoted: no newline in it can start a line that reads as the signer's."""
            return json.dumps(v, ensure_ascii=False)
        lines = [f"Tool: {one(a['tool'])}", f"Run: {a['run_id']}", f"Call: {a['tool_call_id']} attempt {a['attempt']}",
                 f"Rules: {', '.join(a['rule_ids'])}", f"Requested by: {a['requester']}", f"Expires: {a['expires_at']}"]
        esc = a.get("escalation")
        if esc:
            lines.append("Escalated to people by " + (
                f"the reviewer agent: {one(esc.get('reason', 'no reason given'))} (model output, over arguments the "
                "requesting agent supplied)" if esc["by"] == "agent" else f"the signer: {esc.get('reason', '')}"))
        # what the agent supplied comes last, so Slack's length cut can only shorten it, never the signer's lines
        if "reason" in a:
            lines.append(f"Reason given by the agent (unverified): {one(a['reason'])}")
        lines.append("Arguments (the signer's redacted copy): " + ("(deleted)" if a["args"] is None else one(a["args"])))
        out = [{"type": "section", "text": {"type": "plain_text", "text": "\n".join(lines)[:2900]}},
               {"type": "context", "elements": [{"type": "plain_text", "text": a["approval_id"]}]}]
        if state == "requested":
            out.append({"type": "actions", "elements": [
                {"type": "button", "action_id": d, "value": a["approval_id"], "style": style,
                 "text": {"type": "plain_text", "text": d.capitalize()}}
                for d, style in (("approve", "primary"), ("reject", "danger"))]})
        elif user or not answered:   # user: a Slack id the signature vouched for, safe in mrkdwn
            out.append({"type": "context", "elements": [
                {"type": "mrkdwn", "text": f"*{state}*" + (f" by <@{user}>" if user else "")}]})
        else:   # answered elsewhere: who the signer says answered, as plain text
            out.append({"type": "context", "elements": [{"type": "plain_text",
                                                         "text": f"{state} by {answered['by']}"[:2900]}]})
        return out

    def show(self, aid, state, user=None, answered=None):
        """Update the posted message of `aid` to `state`. Never raises: a message Slack won't update (deleted, its
        channel archived) is logged, and a final state is dropped from `posted` either way, so it can't pile up."""
        with self.lock:   # claim the change; Slack is called outside the lock
            p = self.posted.get(aid)
            if p is None or p["state"] == state:
                return
            before, p["state"] = p["state"], state
            if state not in LIVE:
                del self.posted[aid]
        try:
            self.slack("chat.update", channel=self.cfg["channel"], ts=p["ts"], text=f"Tracekit approval {state}",
                       blocks=self.blocks(p["a"], state, user, answered))
        except (SlackError, OSError) as e:
            log.warning("tracekit slack: the message of %s was not updated to %s: %s", aid, state, e)
            with self.lock:
                if state in LIVE and self.posted.get(aid) is p and p["state"] == state:
                    p["state"] = before   # the next poll tries again

    def poll(self):
        """Post the approvals waiting for a person's answer that are not posted yet (never one an agent approver's
        answer can still decide); update the posted ones whose state moved."""
        live, page = {}, {"next_cursor": None}
        while True:
            page = self.signer.approval_list({"cursor": page["next_cursor"]} if page["next_cursor"] else {})
            live.update((x["approval_id"], x) for x in page["approvals"])
            if page["next_cursor"] is None:
                break
        # lean: what was posted is kept in memory, so a restart posts the pending approvals again; persist the
        # message ids if duplicates after a restart matter
        for aid, x in live.items():
            if x["state"] == "requested" and aid not in self.posted and not x.get("agent"):
                try:   # one approval that can't be posted doesn't hold back the others
                    a = self.signer.approval_get({"approval_id": aid})
                    ts = self.slack("chat.postMessage", channel=self.cfg["channel"], text="Tracekit approval requested",
                                    blocks=self.blocks(a, "requested"))["ts"]
                except (SlackError, OSError, RPCError) as e:
                    log.warning("tracekit slack: %s was not posted (next poll tries again): %s", aid, e)
                    continue
                with self.lock:
                    self.posted.setdefault(aid, {"ts": ts, "a": a, "state": "requested"})
        for aid in list(self.posted):   # gone from the list: its run ended (answered or not, it can't be answered now)
            x = live.get(aid, {"state": "ended with its run"})
            self.show(aid, x["state"], answered=x.get("answered"))

    def in_groups(self, user):
        out, now = [], time.monotonic()
        for g in self.cfg.get("groups", ()):
            at, users = self.members.get(g, (None, ()))
            if at is None or now - at > GROUPS_TTL_S:
                users = set(self.slack("usergroups.users.list", usergroup=g)["users"])
                self.members[g] = (now, users)
            if user in users:
                out.append(g)
        return out

    def click(self, payload):
        """Answer one block_actions callback as the Slack user who clicked. Raises ValueError when it is malformed."""
        try:
            action, user = payload["actions"][0], payload["user"]["id"]
            team = payload["user"].get("team_id") or payload["team"]["id"]
            aid, decision = action["value"], action["action_id"]
        except (KeyError, IndexError, TypeError) as e:
            raise ValueError("not a block_actions callback") from e
        if not (SLACK_ID.fullmatch(str(user)) and SLACK_ID.fullmatch(str(team)) and decision in ("approve", "reject")
                and isinstance(aid, str)):
            raise ValueError("not a Tracekit approval button")
        groups = [f"slack:{team}/{g}" for g in self.in_groups(user)]
        try:
            out = self.signer.approval_decide_on_behalf({"approval_id": aid, "decision": decision,
                                                         "approver": f"slack:{team}/{user}",
                                                         **({"groups": groups} if groups else {})})
        except RPCError as e:
            self.slack("chat.postEphemeral", channel=self.cfg["channel"], user=user, text=f"Tracekit refused: {e}")
            return
        self.show(aid, out["state"], user)


def make_handler(bridge):
    class Handler(Lines, BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != PATH:
                return self.answer(404)
            n, why = body_length(self.headers)
            if why or n is None:
                return self.answer(400)
            if n > MAX_BODY:
                return self.answer(413)
            body = read_body(self, n)
            if body is None:
                return
            if not bridge.verify(self.headers.get("X-Slack-Request-Timestamp"), self.headers.get("X-Slack-Signature"),
                                 body):
                return self.answer(401)
            try:
                payload = json.loads(urllib.parse.parse_qs(body.decode("utf-8"))["payload"][0])
                if payload.get("type") == "block_actions":
                    bridge.click(payload)
            except (ValueError, KeyError, AttributeError):
                return self.answer(400)
            except Exception:   # the signer or Slack failed: Slack shows the clicker an error, nothing was decided
                log.exception("tracekit slack: a callback failed")
                return self.answer(500)
            self.answer(200)

        def answer(self, code):
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass
    return Handler


def serve(cfg, signer):
    """A started bridge: (the bound HTTP server, serving; the Bridge). Stop with shutdown() and server_close()."""
    bridge = Bridge(cfg, signer)
    host, _, port = str(cfg["listen"]).rpartition(":")
    ctx = None
    if cfg.get("tls"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cfg["tls"]["cert"], cfg["tls"]["key"])
    srv = Server((host.strip("[]"), int(port)), make_handler(bridge), ctx)

    def loop():
        while True:
            try:
                bridge.poll()
            except Exception:   # the signer or Slack is unreachable: try again next round
                log.exception("tracekit slack: polling the signer failed")
            time.sleep(float(cfg.get("poll_s", POLL_S)))
    threading.Thread(target=loop, name="tracekit-slack-poll", daemon=True).start()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, bridge


def main(config):
    from tracekit.sdk.client import Client
    try:
        cfg = load(config)
    except (OSError, ValueError) as e:
        print(f"tracekit approvals slack: {e}", file=sys.stderr)
        return 2
    srv, _ = serve(cfg, Client(cfg["signer"]))
    print(f"tracekit approvals slack: listening on {cfg['listen']}{PATH}", file=sys.stderr)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        srv.shutdown()
        srv.server_close()
    return 0
