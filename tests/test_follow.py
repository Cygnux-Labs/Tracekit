"""`tracekit follow` (tracekit/follow.py) and the signer's `importers`: a sandbox's audit log followed into imported runs
while it is written, each decision a policy.external record, each skipped sequence, unreadable line and stopped stream a
signed gap; the follower's runs are not reconciled and are watched for its heartbeats."""
import hashlib
import json
import os
import time
import uuid
from unittest import mock

from adapter_contract import _serve
from test_signer_lifecycle import Lifecycle
from test_signer_service import ME, records
from tracekit import follow
from tracekit.bundle_v2 import export
from tracekit.identity.base import CallerIdentity
from tracekit.sdk.client import Client, SignerUnavailable
from tracekit.signer import rpc_schema, service as svc
from tracekit.verify import v2

FOLLOWER = CallerIdentity("mtls", "spiffe://acme/nono-follow", True)
GRANTS = ["register_run", "decision_import", "tailer_heartbeat", "tailer_lost", "close_run"]

# nono's event payloads exactly as serde writes them: the golden vectors of crates/nono/src/audit.rs:2292-2490 (nono
# cf73ec0), whose leaf hashes NonoLog checks; command_policy lines (shaped as its vector, :2455-2489) carry decisions
# from nono's vocabulary (crates/nono-cli/src/tool-sandbox/command_policy_decision.rs:44-58)
STARTED = '{"type":"session_started","started":"2026-04-21T20:00:00Z","command":["claude"]}'
RUNTIME = ('{"type":"sandbox_runtime","event":{"timestamp":"2026-04-21T20:00:00Z","platform":"macOS",'
           '"tool_sandbox_active":false}}')
DENIED = ('{"type":"capability_decision","entry":{"timestamp":{"secs_since_epoch":5,"nanos_since_epoch":0},'
          '"request":{"capability_type":"capability","request_id":"req-1","path":"/tmp/example","access":"ReadWrite",'
          '"reason":"need scratch space","child_pid":42,"session_id":"sess-1"},'
          '"decision":{"Denied":{"reason":"outside policy"}},"backend":"terminal","duration_ms":12}}')
URL_OPEN = ('{"type":"url_open","request":{"request_id":"open-1","url":"https://example.com/callback","child_pid":42,'
            '"session_id":"sess-1"},"success":true,"error":null}')
NETWORK = ('{"type":"network","event":{"timestamp_unix_ms":5,"mode":"reverse","decision":"deny",'
           '"target":"api.example.com","port":443,"method":"POST","path":"/v1/chat","status":403,"reason":"policy"}}')
ENDED = '{"type":"session_ended","ended":"2026-04-21T20:00:01Z","exit_code":0}'
GOLDEN = {STARTED: "c33fec3894d439b2cb313e7b24d142d8a87ce4e839e8c8e66851d14ad7595c69",
          RUNTIME: "de97a52ba94e3201c97dc53ebc51e901ef7b3c965c6bb336365e2fa367522109",
          DENIED: "fb0ff01abb9de69f3c50deb6b828a25d941d7541856d81b8fa3da84b95aa125a",
          URL_OPEN: "ce74e0fa39cd9c9f74ba3eaf509cf88d2b39b771360f646fae3e385c1ca37f2d",
          NETWORK: "629b456dfbf72482f4c68050d40978bdd644947584605f1df4d39346b67875f8",
          ENDED: "076e559e44135ff9a3d27403d1d6ad389bb04542956a064fc23acb37824c70bb"}


def command(decision):
    return ('{"type":"command_policy","event":{"timestamp":"2026-04-21T20:00:00Z","session_id":"sess-1",'
            f'"command":"gh","caller":"session","decision":"{decision}","reason":null,"stdio_mode":"piped",'
            '"argv_hash":"aabbcc","env_name_hash":"ddeeff","cwd_hash":"001122","argv_display":["gh","pr","list"],'
            '"env_names_display":[],"cwd_display":"/home/user","exit_code":0}}')


class NonoLog:
    """An audit-events.ndjson as nono's AuditRecorder appends it (crates/nono/src/audit.rs:552-580): one
    AuditEventRecord per line (:210-226), leaf SHA256("nono.audit.event.alpha\\n" || event_json) and chain
    SHA256("nono.audit.chain.alpha\\n" || previous chain or 32 zero bytes || leaf) (:667-686)."""

    def __init__(self, path):
        self.path, self.seq, self.prev = path, 0, None
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def line(self, event_json, seq=None):
        leaf = hashlib.sha256(b"nono.audit.event.alpha\n" + event_json.encode()).digest()
        if event_json in GOLDEN:
            assert leaf.hex() == GOLDEN[event_json], event_json
        chain = hashlib.sha256(b"nono.audit.chain.alpha\n" + (self.prev or bytes(32)) + leaf).digest()
        rec = {"sequence": self.seq if seq is None else seq, "prev_chain": self.prev and self.prev.hex(),
               "leaf_hash": leaf.hex(), "chain_hash": chain.hex(), "event_json": event_json,
               "event": json.loads(event_json)}
        self.seq, self.prev = rec["sequence"] + 1, chain
        return json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + "\n"

    def write(self, *events, raw=""):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(raw + "".join(self.line(e) for e in events))


class InProcess:
    """The follower's signer client: the in-process service, called as the follower's identity."""

    def __init__(self, s):
        self.s, self.down, self.fail_after, self.calls = s, False, None, []

    def call(self, method, req=None, **fields):
        if self.down or self.fail_after is not None and len(self.calls) >= self.fail_after:
            raise SignerUnavailable("down")
        req = {**(req or {}), **fields}
        if "request_id" in rpc_schema.REQUESTS[method]["properties"]:
            req.setdefault("request_id", uuid.uuid4().hex)
        self.calls.append(method)
        return self.s.call(FOLLOWER, method, req)


class Followed(Lifecycle):
    def open(self):
        self.s = svc.SignerService(self.dir, grace_s=0, idle_s=3600, importers=[FOLLOWER.scheme + ":" + FOLLOWER.subject],
                                   authorize={"mtls:spiffe://acme/nono-follow": GRANTS,
                                              f"uid:{ME.subject}": sorted(svc.DEFAULT_GRANTS | {"decision_import"})})
        self.closed = False
        self.client = InProcess(self.s)
        self.root = os.path.join(self.dir, "nono", "audit")

    def session(self, name="20260421-200000-11111"):
        return NonoLog(os.path.join(self.root, name, "audit-events.ndjson"))

    def log(self, nono_log, **kw):
        return follow.Log(self.client, nono_log.path, "nono", lambda rec: follow.nono("s1", rec), want=0, **kw)

    def recorded(self):
        return [r["event"] for r in records(self.dir)]

    def typed(self, typ):
        return [e for e in self.recorded() if e["type"] == typ]

    def gaps(self):
        return [e["data"]["reason"] for e in self.typed("capture.gap")]

    def reasons(self):
        """The follower's gaps as it worded them, without what the signer adds."""
        tail = " (at transcript offset "
        return [g[:g.index(tail)] for g in self.gaps() if tail in g]

    def verify(self, run_id):
        self.s.checkpoint()
        note = self.s.log.storage.checkpoint_latest()[1]
        bundle, trust = os.path.join(self.dir, "b.tkb"), os.path.join(self.dir, "trust.json")
        export(self.s.log.storage, "default", run_id, note, bundle)
        with open(trust, "w") as f:
            json.dump({"logs": [self.s.vkey], "algs": ["ed25519"]}, f)
        rep, code = v2.verify(bundle, trust)
        return code, {c["check"]: c for c in rep.checks}


class TestNono(Followed):
    def test_each_decision_is_signed_while_the_session_runs(self):
        nl = self.session()
        nl.write(STARTED, RUNTIME, DENIED)
        discover = follow.nono_sessions(self.client, self.root, follow.QUIET_S)
        [log] = discover()
        log.step()
        [d] = self.typed("policy.external")   # before the session ends
        self.assertEqual((d["source"], d["tier"], d["data"]["system"], d["data"]["decision"], d["data"]["tool_use_id"],
                          d["data"]["tool"], d["data"]["reason"], d["data"]["signature"], d["data"]["identity"]["subject"]),
                         ("import", "T3", "nono", "deny", "20260421-200000-11111:2", "capability_decision/capability",
                          "terminal: outside policy", "unverified", "spiffe://acme/nono-follow"))
        with open(nl.path, "rb") as f:   # the record committed to is the line exactly as nono wrote it
            line = f.read().splitlines()[2]
        self.assertEqual(d["data"]["record"], {"hash": self.s._commit(f"policy.external:{d['data']['salt_id']}",
                                                                      "sha256:" + hashlib.sha256(line).hexdigest()),
                                               "size": len(line)})
        nl.write(URL_OPEN, command("allowed"), command("invocation_denied"), NETWORK, ENDED)
        log.step()
        self.assertTrue(log.done)
        self.assertEqual(discover(), [])
        [reg] = self.typed("run.registered")
        self.assertEqual((reg["source"], reg["tier"], reg["data"]["fidelity"], reg["data"]["agent"]["name"]),
                         ("import", "T3", "none", "nono"))
        self.assertEqual([(e["data"]["decision"], e["data"]["tool"], e["data"].get("reason"))
                          for e in self.typed("policy.external")],
                         [("deny", "capability_decision/capability", "terminal: outside policy"),
                          ("allow", "url_open", None), ("allow", "command_policy/gh", None),
                          ("deny", "command_policy/gh", None), ("deny", "network", "policy")])
        self.assertEqual(self.typed("run.closing")[0]["data"]["reason"], "close_run")   # at session_ended
        self.s.sweep(time.monotonic() + 1)
        self.assertEqual(self.gaps(), [])   # not reconciled: no decision_mismatch for calls the signer never decided
        code, checks = self.verify(reg["run_id"])
        self.assertEqual(code, 0)
        self.assertEqual(checks["external decisions"]["detail"],
                         "5 imported: nono 5; signatures verified 0, unverified 5; 0 disagree with the signer")

    def test_a_sequence_that_jumps_or_repeats_is_a_signed_gap(self):
        nl = self.session()
        nl.write(STARTED, DENIED)
        nl.seq = 5
        nl.write(URL_OPEN)
        nl.seq = 5
        nl.write(command("denied"))
        self.log(nl).step()
        self.assertEqual(self.reasons(), [
            f"nono sequence 5 follows 1: 3 record(s) missing; read {nl.path} for what they say",
            f"nono sequence 5 follows 5: records repeated or out of order; read {nl.path} for what they say"])
        self.assertEqual(len(self.typed("policy.external")), 3)   # what nono said is recorded all the same

    def test_unreadable_and_unknown_lines_are_gaps_and_the_log_goes_on(self):
        nl = self.session()
        nl.write(STARTED)
        nl.write(raw='{"sequence":1,"event":\n')
        nl.write('{"type":"something_new","x":1}', command("not_a_decision"), DENIED)
        self.log(nl).step()
        bad, new, odd = self.reasons()
        self.assertRegex(bad, r"^the line at byte \d+ of .+ is not a nono audit record \(JSONDecodeError: ")
        self.assertRegex(new, r"^nono event type 'something_new' is not one Tracekit maps \(byte \d+ of .+\): read it "
                              r"there$")
        self.assertRegex(odd, r"^nono command_policy decision 'not_a_decision' is not one Tracekit maps")
        self.assertEqual([e["data"]["tool_use_id"] for e in self.typed("policy.external")], ["s1:3"])

    def test_the_signer_unreachable_holds_the_line_and_records_it_once(self):
        nl = self.session()
        nl.write(STARTED, DENIED)
        nl.seq = 3
        nl.write(URL_OPEN)   # a gap and a decision: the signer drops away between the two
        log = self.log(nl)
        self.client.fail_after = 3   # register_run, the decision at seq 1, the gap at seq 3
        with self.assertRaises(SignerUnavailable):
            log.step()
        self.assertEqual((len(self.gaps()), len(self.typed("policy.external"))), (1, 1))
        self.client.fail_after = None
        log.step()
        self.assertEqual((len(self.gaps()), len(self.typed("policy.external"))), (1, 2))

    def test_a_stream_that_stops_is_a_signed_gap(self):
        quiet, truncated, removed, stopped = (self.session(f"s-{n}") for n in range(4))
        for nl in (quiet, truncated, removed, stopped):
            nl.write(STARTED, DENIED)
        logs = [self.log(nl, quiet=60) for nl in (quiet, truncated, removed, stopped)]
        for log in logs:
            log.step()
        logs[0].grew -= 61
        with open(truncated.path, "r+b") as f:
            f.truncate(10)
        os.remove(removed.path)
        for log in logs[:3]:
            log.step()
        with mock.patch.object(follow, "POLL_S", 0):   # SIGTERM after one round: the loop ends, the log with a gap
            self.assertEqual(follow.follow(iter([[logs[3]]]).__next__, iter([False, True]).__next__), [])
        self.assertTrue(all(log.done for log in logs))
        size = os.path.getsize(quiet.path)
        self.assertEqual(self.reasons(), [
            "no new record for 60s and no session_ended: nono stopped before it finished the session, or the session "
            f"is idle; Tracekit no longer follows {quiet.path}",
            f"{truncated.path} was truncated to 10 bytes after Tracekit read {size} bytes of it: what it held past "
            f"those, and anything written to it later, is not recorded; Tracekit no longer follows {truncated.path}",
            f"{removed.path} was removed after Tracekit read {size} bytes of it: what it held past those, and anything "
            f"written to it later, is not recorded; Tracekit no longer follows {removed.path}",
            f"the follower was stopped before the log ended; Tracekit no longer follows {stopped.path}"])
        self.assertEqual(len(self.typed("run.closing")), 4)

    def test_a_killed_follower_is_a_gap_the_signer_writes(self):
        nl = self.session()
        nl.write(STARTED, DENIED)
        log = self.log(nl)
        log.step()
        log.beat -= follow.HEARTBEAT_S
        log.heartbeat()   # alive: the signer hears from it
        self.s.sweep(time.monotonic() + svc.TAILER_LOST_S - 1)
        self.assertEqual(self.gaps(), [])
        self.s.sweep(time.monotonic() + svc.TAILER_LOST_S + 1)   # then nothing: it was killed
        [gap] = self.gaps()
        self.assertRegex(gap, r"^no tailer_heartbeat for \d+s while the run was open: the log follower stopped or was "
                              r"killed; what the log says after that is not recorded: read the log itself for it, and "
                              r"restart `tracekit follow`$")

    def test_at_start_only_running_sessions_then_every_new_one(self):
        done, old, live = self.session("done"), self.session("old"), self.session("live")
        for nl in (done, old, live):
            nl.write(STARTED)
        with open(os.path.join(os.path.dirname(done.path), "session.json"), "w") as f:
            f.write("{}")
        os.utime(old.path, (time.time() - 100, time.time() - 100))
        os.makedirs(os.path.join(self.root, "no log yet"))
        discover = follow.nono_sessions(self.client, self.root, quiet=60)
        self.assertEqual([log.path for log in discover()], [live.path])
        new = self.session("new")
        os.makedirs(os.path.dirname(new.path), exist_ok=True)
        self.assertEqual(discover(), [])   # its directory first, its log at the next wake
        new.write(STARTED, ENDED)
        [log] = discover()
        log.step()
        self.assertTrue(log.done)


class TestOverASocket(Followed):
    def open(self):
        super().open()
        self.s.close()
        me = [f"uid:{ME.subject}", "token:dev"]   # the socket's peer (token:dev where there is no AF_UNIX)
        self.s = svc.SignerService(self.dir, grace_s=0, idle_s=3600, importers=me, authorize=dict.fromkeys(me, GRANTS))

    def test_the_sdk_client_follows_a_session_while_it_runs(self):
        client = Client(_serve(self, self.s.handle_frame))
        self.addCleanup(client.close)
        nl = self.session()
        nl.write(STARTED, DENIED)
        seen = []

        def stopping():   # each round: first the decision while the session runs, then its end
            seen.append([e["data"]["decision"] for e in self.typed("policy.external")])
            if len(seen) == 2:
                nl.write(ENDED)
            return len(seen) == 3

        with mock.patch.object(follow, "POLL_S", 0):
            self.assertEqual(follow.follow(follow.nono_sessions(client, self.root, 60), stopping), [])
        self.assertEqual(seen, [[], ["deny"], ["deny"]])
        self.assertEqual([e["source"] for e in self.recorded() if e["type"] in ("run.registered", "run.closing")],
                         ["import", "import"])


class TestImporters(Followed):
    def test_an_importers_run_is_imported_and_another_run_is_reconciled_as_before(self):
        mine = self.register()
        theirs = self.register(FOLLOWER)
        for run, who in ((mine, ME), (theirs, FOLLOWER)):
            self.call("decision_import", {"run_id": run["run_id"], "system": "nono", "decision": "deny",
                                          "tool_call_id": "s:1", "tool": "network", "record": "{}"}, FOLLOWER)
            self.call("close_run", run, who)
        self.s.sweep(time.monotonic() + 1)
        regs = {e["run_id"]: e for e in self.typed("run.registered")}
        self.assertEqual((regs[mine["run_id"]]["source"], regs[theirs["run_id"]]["source"]), ("sdk", "import"))
        self.assertNotIn("fidelity", regs[mine["run_id"]]["data"])
        self.assertEqual([(e["run_id"], e["data"]["kind"]) for e in self.typed("capture.gap")],
                         [(mine["run_id"], "decision_mismatch")])   # only the reconciled run compares decisions
