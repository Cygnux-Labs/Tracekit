"""Slack approvals (tracekit/slack_approvals.py, docs/approvals.md#slack): a real signer over its socket, the bridge
authenticated as this process's uid and granted only approval_list, approval_get and approval_decide_on_behalf, a
fake Slack Web API, and recorded interactivity payloads (tests/data/slack/) signed as Slack signs them."""
import hashlib
import hmac
import http.client
import json
import os
import threading
import time
import unittest
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import test_signer_service as ts
from tracekit import slack_approvals as slack
from tracekit.identity.base import CallerIdentity
from tracekit.policy2.engine import Engine
from tracekit.sdk.client import Client
from tracekit.signer import service as svc
from tracekit.signer.rpc_schema import RPCError
from test_signer_privacy import SECRET

PAYLOAD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "slack", "block_actions.json")
SIGNING = b"8f742231b10e8888abcd99yyyzzz85a5"
AGENT = CallerIdentity("uid", "555555", True)
ASKS = Engine({"ask": [{"id": "PAY", "tool": "^pay$", "pattern": "^"}]})
APPROVALS = {"approvers": ["slack:T0TEAM/U0APPROVER", "slack:T0TEAM/S0OPS", "slack:T0TEAM/U0SELF", "slack:T0TEAM/U0BOB"],
             "persons": {"slack:T0TEAM/U0SELF": "alice", f"uid:{AGENT.subject}": "alice", "slack:T0TEAM/U0BOB": "bob"}}


class FakeSlack(BaseHTTPRequestHandler):
    def do_POST(self):
        fields = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
        method = self.path.rsplit("/", 1)[1]
        self.server.calls.append((method, {k: json.loads(v) if k == "blocks" else v for k, v in fields.items()}))
        out = {"ok": True, "ts": f"1760000000.{len(self.server.calls):06d}"}
        if method == "usergroups.users.list":
            out["users"] = self.server.groups.get(fields["usergroup"], [])
        body = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def start(case, srv):
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    case.addCleanup(srv.server_close)
    case.addCleanup(srv.shutdown)
    return srv.server_address[1]


class Bridge(unittest.TestCase):
    def setUp(self):
        d = ts.tmpdir(self)
        me = f"uid:{os.getuid()}"
        cfg = {"data_dir": d, "socket": os.path.join(d, "s.sock"), "approvals": APPROVALS,
               "authorize": {me: ["approval_list", "approval_get", "approval_decide_on_behalf"]}}
        self.s = svc.open_service(cfg, policy=ASKS)
        self.addCleanup(self.s.close)
        servers = svc.serve(cfg, self.s)
        for srv in servers:
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        self.dir = d
        self.api = ThreadingHTTPServer(("127.0.0.1", 0), FakeSlack)
        self.api.calls, self.api.groups = [], {"S0OPS": ["U0GROUPIE"]}
        port = start(self, self.api)
        signer = Client(cfg["socket"])
        self.addCleanup(signer.close)
        self.bridge = slack.Bridge({"channel": "C0CHAN", "bot_token": "xoxb-test", "signing_secret": SIGNING,
                                    "groups": ["S0OPS"], "api_url": f"http://127.0.0.1:{port}"}, signer)
        self.port = start(self, ThreadingHTTPServer(("127.0.0.1", 0), slack.make_handler(self.bridge)))

    def pending(self, args=None, principal=None):
        run = self.s.call(AGENT, "register_run", {"request_id": "reg", "agent": {"name": "a"},
                                                  **({"principal": principal} if principal else {})})
        self.run = {"run_id": run["run_id"], "run_token": run["run_token"]}
        self.s.call(AGENT, "decide", {"request_id": "d", **self.run, "stream": "s", "client_seq": 0,
                                      "tool_call_id": "tc-1", "tool": "pay", "args_source": "parsed",
                                      "args": args or {"to": "acct-42", "cents": 1500}})
        return self.s.call(AGENT, "approval_request", {"request_id": "a", **self.run, "tool_call_id": "tc-1"})["approval_id"]

    def state(self, aid):
        return self.s.log.approvals[aid]["state"]

    def click(self, aid, user="U0APPROVER", decision="approve", ts=None, sig=None):
        with open(PAYLOAD, encoding="utf-8") as f:
            p = json.load(f)
        p["actions"][0].update(value=aid, action_id=decision)
        p["user"]["id"] = user
        body = urllib.parse.urlencode({"payload": json.dumps(p)}).encode()
        ts = str(int(time.time())) if ts is None else ts
        sig = sig or "v0=" + hmac.new(SIGNING, f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()
        return self.post(body, {"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig})

    def post(self, body, headers):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            c.request("POST", slack.PATH, body=body, headers={"Content-Type": "application/x-www-form-urlencoded",
                                                                **headers})
            r = c.getresponse()
            r.read()
            return r.status
        finally:
            c.close()

    def calls(self, method):
        return [f for m, f in self.api.calls if m == method]

    def approvals(self):
        self.s.close()
        return [r["event"]["data"] for r in ts.records(self.dir) if r["event"]["type"] == "approval"]


class TestSignature(Bridge):
    def test_bad_signature_old_timestamp_and_replay_are_refused(self):
        aid = self.pending()
        self.assertEqual(self.click(aid, sig="v0=" + "0" * 64), 401)
        self.assertEqual(self.click(aid, ts=str(int(time.time()) - slack.WINDOW_S - 5)), 401)
        self.assertEqual(self.click(aid, ts="12x"), 401)
        self.assertEqual(self.post(b"payload=%7B%7D", {}), 401)
        self.assertEqual(self.state(aid), "requested")
        ts_, body = str(int(time.time())), urllib.parse.urlencode({"payload": json.dumps({"type": "block_actions"})})
        sig = "v0=" + hmac.new(SIGNING, f"v0:{ts_}:{body}".encode(), hashlib.sha256).hexdigest()
        headers = {"X-Slack-Request-Timestamp": ts_, "X-Slack-Signature": sig}
        self.assertEqual(self.post(body.encode(), headers), 400)   # signed, but not a button callback
        self.assertEqual(self.post(body.encode(), headers), 401)   # the same signed request again: a replay

    def test_verify_window_and_cache(self):
        body, ts_ = b"x", "1000"
        sig = "v0=" + hmac.new(SIGNING, b"v0:1000:x", hashlib.sha256).hexdigest()
        self.assertTrue(self.bridge.verify(ts_, sig, body, now=1000 + slack.WINDOW_S))
        self.assertFalse(self.bridge.verify(ts_, sig, body, now=1001))   # replayed within the window
        self.assertFalse(self.bridge.verify("999", sig, body, now=999))  # another timestamp: another signature
        self.assertFalse(self.bridge.verify(ts_, sig, body, now=1001 + slack.WINDOW_S))   # too old
        self.assertFalse(self.bridge.verify("2000", "v0=\u00e9" + "0" * 63, body, now=2000))   # non-ASCII: refused, no raise


class TestDecisions(Bridge):
    def test_approve_end_to_end(self):
        aid = self.pending({"to": "acct-42", "cents": 1500, "note": "<!channel> *bold* " + SECRET})
        self.bridge.poll()
        self.bridge.poll()   # posted once
        [post] = self.calls("chat.postMessage")
        self.assertEqual(post["channel"], "C0CHAN")
        text = post["blocks"][0]["text"]
        self.assertEqual(text["type"], "plain_text")   # agent-chosen strings never reach mrkdwn
        for want in ("Tool: pay", self.run["run_id"], "Rules: PAY", "Expires: ", "acct-42"):
            self.assertIn(want, text["text"])
        self.assertNotIn(SECRET, json.dumps(post))   # the signer's redacted copy
        self.assertEqual([(b["action_id"], b["value"]) for b in post["blocks"][-1]["elements"]],
                         [("approve", aid), ("reject", aid)])

        self.assertEqual(self.click(aid), 200)
        self.assertEqual(self.state(aid), "approved")
        [update] = self.calls("chat.update")
        self.assertEqual(update["ts"], "1760000000.000001")
        self.assertEqual(update["blocks"][-1]["elements"][0]["text"], "*approved* by <@U0APPROVER>")
        out = self.s.call(AGENT, "approval_consume", {"request_id": "c", **self.run, "tool_call_id": "tc-1",
                                                      "tool": "pay", "args_source": "parsed",
                                                      "args": {"to": "acct-42", "cents": 1500,
                                                               "note": "<!channel> *bold* " + SECRET}})
        self.assertTrue(out["ok"])
        [rec] = self.approvals()
        self.assertEqual((rec["approver"], rec["channel"], rec["self_approved"]),
                         ("slack:T0TEAM/U0APPROVER", "slack", False))
        self.assertEqual(rec["approver_identity"], {"scheme": "slack", "subject": "T0TEAM/U0APPROVER", "attested": False})
        self.assertEqual(rec["via"], {"scheme": "uid", "subject": str(os.getuid()), "attested": True})

    def test_reject_end_to_end(self):
        aid = self.pending()
        self.bridge.poll()
        self.assertEqual(self.click(aid, decision="reject"), 200)
        self.assertEqual(self.state(aid), "rejected")
        self.assertEqual(self.calls("chat.update")[0]["blocks"][-1]["elements"][0]["text"], "*rejected* by <@U0APPROVER>")
        self.assertEqual(self.approvals()[0]["decision"], "reject")

    def test_member_of_an_approver_group(self):
        aid = self.pending()
        self.assertEqual(self.click(aid, user="U0GROUPIE"), 200)
        self.assertEqual(self.state(aid), "approved")
        self.assertEqual(self.approvals()[0]["groups"], ["slack:T0TEAM/S0OPS"])

    def test_user_not_configured_as_approver_is_refused(self):
        aid = self.pending()
        self.assertEqual(self.click(aid, user="U0STRANGER"), 200)
        self.assertEqual(self.state(aid), "requested")
        [eph] = self.calls("chat.postEphemeral")
        self.assertEqual(eph["user"], "U0STRANGER")
        self.assertIn("not an approver", eph["text"])

    def test_self_approval_through_slack_is_refused(self):
        aid = self.pending()   # the agent's uid and U0SELF are the same person (persons)
        self.assertEqual(self.click(aid, user="U0SELF"), 200)
        self.assertEqual(self.state(aid), "requested")
        self.assertIn("its own run's approval", self.calls("chat.postEphemeral")[0]["text"])

    def test_the_runs_principal_may_not_approve(self):
        aid = self.pending(principal="bob")
        self.assertEqual(self.click(aid, user="U0BOB"), 200)
        self.assertEqual(self.state(aid), "requested")

    def test_message_updated_on_expiry(self):
        aid = self.pending()
        self.bridge.poll()
        self.s.sweep(wall=time.time() + svc.APPROVAL_TTL_S + 1)
        self.bridge.poll()
        [update] = self.calls("chat.update")
        self.assertEqual(update["blocks"][-1]["elements"][0]["text"], "*expired*")
        self.assertNotIn(aid, self.bridge.posted)


class TestGrant(Bridge):
    def on_behalf(self, who, aid, approver="slack:T0TEAM/U0APPROVER", **kw):
        return self.s.call(who, "approval_decide_on_behalf", {"request_id": uuid.uuid4().hex, "approval_id": aid,
                                                               "decision": "approve", "approver": approver, **kw})

    def test_on_behalf_is_never_a_default(self):
        aid = self.pending()
        with self.assertRaises(RPCError) as cm:
            self.on_behalf(AGENT, aid)   # a uid keeps every other method by default
        self.assertEqual(cm.exception.code, "forbidden")
        self.assertEqual(self.state(aid), "requested")

    def test_groups_of_another_team_are_refused(self):
        aid = self.pending()
        with self.assertRaises(RPCError) as cm:
            self.on_behalf(CallerIdentity("uid", str(os.getuid()), True), aid, "slack:T0OTHER/U0X",
                           groups=["slack:T0TEAM/S0OPS"])
        self.assertEqual(cm.exception.code, "invalid_request")

    def test_bridge_answers_only_through_on_behalf(self):
        aid = self.pending()
        with self.assertRaises(RPCError) as cm:
            self.s.call(CallerIdentity("uid", str(os.getuid()), True), "approval_decide",
                        {"request_id": "x", "approval_id": aid, "decision": "approve"})
        self.assertEqual(cm.exception.code, "forbidden")


class TestConfig(unittest.TestCase):
    def write(self, d, text):
        path = os.path.join(d, "slack.yaml")
        for name in ("bot", "signing"):
            with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                f.write(f"{name}-secret\n")
        with open(path, "w", encoding="utf-8") as f:
            f.write("signer: /run/s.sock\nchannel: C0CHAN\nbot_token_file: bot\nsigning_secret_file: signing\n" + text)
        return path

    def test_secrets_come_from_files_and_beyond_loopback_needs_tls(self):
        d = ts.tmpdir(self)
        cfg = slack.load(self.write(d, "listen: 127.0.0.1:3000\n"))
        self.assertEqual((cfg["bot_token"], cfg["signing_secret"]), ("bot-secret", b"signing-secret"))
        with self.assertRaisesRegex(ValueError, "not loopback"):
            slack.load(self.write(d, "listen: 0.0.0.0:3000\n"))
        self.assertTrue(slack.load(self.write(d, "listen: 0.0.0.0:3000\ninsecure_http: true\n")))
        with self.assertRaises(ValueError):
            slack.load(self.write(d, "listen: 127.0.0.1:3000\nbot_token: inline\n"))


if __name__ == "__main__":
    unittest.main()
