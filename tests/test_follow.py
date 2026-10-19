"""`tracekit follow` (tracekit/follow.py) and the signer's `importers`: agentsh's audit log followed into an imported
run while it is written, each decision a policy.external record, each skipped or repeated sequence, new chain,
unreadable line and stopped stream a signed gap; the follower's runs are not reconciled and are watched for its
heartbeats."""
import hashlib
import hmac
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
from tracekit.storage.file import FileStorage
from tracekit.verify import v2

FOLLOWER = CallerIdentity("mtls", "spiffe://acme/agentsh-follow", True)
GRANTS = ["register_run", "decision_import", "tailer_heartbeat", "tailer_lost", "close_run"]

# agentsh events as its JSONL store writes them with audit.integrity off: json.Marshal of a types.Event
# (internal/store/jsonl/jsonl.go:98-114, pkg/types/events.go:23-70): lines 1, 12, 29, 40 and 46 of agentsh's
# examples/sample-events.jsonl (agentsh 0ce9939)
CREATED = ('{"id":"evt-001","timestamp":"2025-01-15T10:30:00.000Z","type":"session_created",'
           '"session_id":"sess-abc123","fields":{"workspace":"/home/user/project","policy":"default"}}')
RM = ('{"id":"evt-012","timestamp":"2025-01-15T10:30:15.000Z","type":"command_policy","session_id":"sess-abc123",'
      '"command_id":"cmd-004","operation":"command_precheck","policy":{"decision":"deny",'
      '"effective_decision":"deny","rule":"commands.deny[0]","message":"rm -rf blocked for safety"},'
      '"fields":{"command":"rm","args":["-rf","/"]}}')
SHADOW = ('{"id":"evt-029","timestamp":"2025-01-15T10:30:40.002Z","type":"file_read","session_id":"sess-abc123",'
          '"command_id":"cmd-008","pid":12355,"path":"/etc/shadow","policy":{"decision":"deny",'
          '"effective_decision":"deny","rule":"files.deny[0]","message":"sensitive system files blocked"},'
          '"fields":{}}')
NPM = ('{"id":"evt-040","timestamp":"2025-01-15T10:31:00.000Z","type":"command_policy","session_id":"sess-abc123",'
       '"command_id":"cmd-012","operation":"command_precheck","policy":{"decision":"approve",'
       '"effective_decision":"allow","rule":"commands.approve[0]","message":"npm install requires approval",'
       '"approval":{"required":true,"mode":"interactive","id":"apr-001"}},'
       '"fields":{"command":"npm","args":["install"]}}')
PYTHON = ('{"id":"evt-046","timestamp":"2025-01-15T10:31:20.001Z","type":"command_redirected",'
          '"session_id":"sess-abc123","command_id":"cmd-013","policy":{"decision":"redirect",'
          '"effective_decision":"allow","rule":"commands.redirect[0]","redirect":{"from_command":"python",'
          '"to_command":"python3"}},"fields":{"from_command":"python","from_args":["script.py"],'
          '"to_command":"python3","to_args":["script.py"]}}')


def rotated(code, last=None):
    """The record agentsh writes when it starts a new chain (internal/store/integrity_wrapper.go:535-567): a
    types.Event, so `session_id` is there though empty, whose map fields Go writes with their keys sorted."""
    prior = None if last is None else {"last_entry_hash_seen_in_log": "ab" * 32, "last_sequence_seen_in_log": last}
    return json.dumps({"timestamp": "2026-10-19T10:00:00Z", "type": "integrity_chain_rotated", "session_id": "",
                       "fields": gomap({"reason": "sidecar missing; starting fresh chain", "reason_code": code,
                                        "prior_chain_summary": prior,
                                        "new_chain": {"format_version": 2, "sequence": 0,
                                                      "key_fingerprint": "sha256:" + "cd" * 16}})},
                      separators=(",", ":"))


def gomap(v):
    """`v` with every map's keys sorted, as Go's encoding/json writes a map."""
    if isinstance(v, dict):
        return {k: gomap(v[k]) for k in sorted(v)}
    return [gomap(x) for x in v] if isinstance(v, list) else v


class AgentshLog:
    """agentsh's `audit.output`: with audit.integrity on, each event re-marshalled as a map with `integrity`
    {format_version, sequence, prev_hash, entry_hash}, entry_hash HMAC-SHA256(key, "2|<sequence>|<prev_hash>|<the
    event's canonical JSON>"), prev_hash empty at a chain's start (internal/audit/integrity.go:26-32, 199-240,
    381-411)."""
    KEY = b"k" * 32

    def __init__(self, path, integrity=True):
        self.path, self.integrity, self.seq, self.prev = path, integrity, 0, ""

    def line(self, event):
        if not self.integrity:
            return event + "\n"
        data = gomap(json.loads(event))
        if data["type"] == "integrity_chain_rotated":
            self.seq, self.prev = 0, ""
        canonical = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        h = hmac.new(self.KEY, f"2|{self.seq}|{self.prev}|{canonical}".encode(), "sha256").hexdigest()
        wrapped = gomap({**data, "integrity": None})
        wrapped["integrity"] = {"format_version": 2, "sequence": self.seq, "prev_hash": self.prev, "entry_hash": h}
        self.seq, self.prev = self.seq + 1, h
        return json.dumps(wrapped, separators=(",", ":"), ensure_ascii=False) + "\n"

    def write(self, *events, raw=""):
        """`raw`: text written as it is, before the events."""
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
        self.s = svc.SignerService(self.dir, grace_s=0, idle_s=3600,
                                   importers=[FOLLOWER.scheme + ":" + FOLLOWER.subject],
                                   authorize={"mtls:spiffe://acme/agentsh-follow": GRANTS,
                                              f"uid:{ME.subject}": sorted(svc.DEFAULT_GRANTS | {"decision_import"})})
        self.closed = False
        self.client = InProcess(self.s)

    def agentsh(self, integrity=True, client=None):
        """agentsh's log, two events written to it before the follower starts (not imported), and its follower."""
        al = AgentshLog(os.path.join(self.dir, "audit.jsonl"), integrity)
        al.write(CREATED, RM)
        return al, follow.Log(client or self.client, al.path)

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


class TestAgentsh(Followed):
    def test_each_decision_is_signed_from_the_end_of_the_log_on(self):
        al, log = self.agentsh()
        al.write(CREATED, SHADOW, NPM, PYTHON)
        log.step()
        imported = self.typed("policy.external")   # while agentsh writes the log
        self.assertEqual([(e["data"]["system"], e["data"]["decision"], e["data"]["tool"], e["data"]["tool_use_id"],
                           e["data"]["rule_ids"], e["data"]["reason"]) for e in imported],
                         [("agentsh", "deny", "file_read", "evt-029", ["files.deny[0]"],
                           "deny: sensitive system files blocked"),
                          ("agentsh", "allow", "command_policy", "evt-040", ["commands.approve[0]"],
                           "allow, policy said approve: npm install requires approval"),
                          ("agentsh", "allow", "command_redirected", "evt-046", ["commands.redirect[0]"],
                           "allow, policy said redirect")])
        d, x = imported[0], imported[0]["data"]
        self.assertEqual((d["source"], d["tier"], x["signature"], x["identity"]["subject"]),
                         ("import", "T3", "unverified", "spiffe://acme/agentsh-follow"))
        with open(al.path, "rb") as f:   # the record committed to is the line exactly as agentsh wrote it
            line = f.read().splitlines()[3]
        self.assertEqual(x["record"], {"hash": self.s._commit(f"policy.external:{x['salt_id']}",
                                                              "sha256:" + hashlib.sha256(line).hexdigest()),
                                       "size": len(line)})
        self.assertEqual(self.gaps(), [])
        [reg] = self.typed("run.registered")
        self.assertEqual((reg["source"], reg["tier"], reg["data"]["fidelity"], reg["data"]["agent"]["name"]),
                         ("import", "T3", "none", "agentsh"))
        with mock.patch.object(follow, "POLL_S", 0):   # stopped (SIGTERM): the run ends with a gap
            follow.follow(log, iter([False, True]).__next__)
        self.assertTrue(log.done)
        self.assertEqual(self.reasons(), [f"the follower was stopped before the log ended; Tracekit no longer follows "
                                          f"{al.path}"])
        self.assertEqual(self.typed("run.closing")[0]["data"]["reason"], "close_run")
        self.s.sweep(time.monotonic() + 1)
        # not reconciled: no decision_mismatch for calls the signer never decided
        self.assertEqual([e["data"]["kind"] for e in self.typed("capture.gap")], ["tailer_lost"])
        code, checks = self.verify(reg["run_id"])
        self.assertEqual(code, 0)
        self.assertEqual(checks["external decisions"]["detail"],
                         "3 imported: agentsh 3; signatures verified 0, unverified 3; 0 disagree with the signer")

    def test_a_jump_a_repeat_and_a_new_chain_are_signed_gaps_and_an_initial_one_is_not(self):
        al, log = self.agentsh()
        al.write(SHADOW)
        al.seq = 6
        al.write(NPM)
        al.seq = 6
        al.write(PYTHON, rotated("sidecar_missing", last=7), SHADOW, rotated("initial"), NPM)
        log.step()
        self.assertEqual(self.reasons(), [
            f"agentsh sequence 6 follows 2: 3 record(s) missing; read {al.path} for what they say",
            f"agentsh sequence 6 follows 6: records repeated or out of order; read {al.path} for what they say",
            "agentsh started a new integrity chain (sidecar_missing: sidecar missing; starting fresh chain); agentsh "
            "says the last sequence of the chain before was 7; the last Tracekit read was 6"])
        self.assertEqual(len(self.typed("policy.external")), 5)   # what agentsh said is recorded all the same

    def test_a_line_is_read_once_it_is_ended(self):
        al, log = self.agentsh()
        al.write(raw=al.line(SHADOW)[:-1])
        log.step()
        self.assertEqual(self.typed("policy.external"), [])
        al.write(raw="\n")
        log.step()
        self.assertEqual([e["data"]["tool_use_id"] for e in self.typed("policy.external")], ["evt-029"])

    def test_unreadable_and_unknown_lines_are_gaps_and_the_log_goes_on(self):
        al, log = self.agentsh()
        al.write('{"type":"file_read","policy":{"decision":"not_a_decision"}}', SHADOW,
                 raw='{"id":"evt-1","type":\n{"id":"evt-2"}\n')
        log.step()
        bad, untyped, odd = self.reasons()
        self.assertRegex(bad, r"^the line is not an agentsh audit record \(JSONDecodeError: .+\) \(byte \d+ of .+\): "
                              r"read it there$")
        self.assertRegex(untyped, r"^the line is not an agentsh audit record \(KeyError: 'type'\)")
        self.assertRegex(odd, r"^agentsh file_read decision 'not_a_decision' is not one Tracekit maps \(byte \d+ of "
                              r".+\): read it there$")
        self.assertEqual([e["data"]["tool_use_id"] for e in self.typed("policy.external")], ["evt-029"])

    def test_a_decision_the_signer_would_refuse_is_a_gap_and_the_log_goes_on(self):
        al, log = self.agentsh()
        al.write('{"id":"evt-9","type":"","policy":{"decision":"deny","rule":["a"]}}', SHADOW)   # no tool, a list rule
        log.step()
        [refused] = self.reasons()
        self.assertRegex(refused, r"^the record at byte \d+ of .+ holds a decision the signer would refuse \(tool: "
                                  r"shorter than 1; rule_ids\[0\]: expected string, got list\): it is in that log only$")
        self.assertEqual([e["data"]["tool_use_id"] for e in self.typed("policy.external")], ["evt-029"])

    def test_the_signer_unreachable_holds_the_line_and_records_it_once(self):
        al, log = self.agentsh()
        al.write(SHADOW)
        al.seq = 5
        al.write(NPM)   # a gap and a decision: the signer drops away between the two
        self.client.fail_after = 3   # register_run, the decision at sequence 2, the gap at 5
        with self.assertRaises(SignerUnavailable):
            log.step()
        self.assertEqual((len(self.gaps()), len(self.typed("policy.external"))), (1, 1))
        self.client.fail_after = None
        log.step()
        self.assertEqual((len(self.gaps()), len(self.typed("policy.external"))), (1, 2))

    def test_a_truncated_log_is_a_signed_gap_that_ends_the_following(self):
        al, log = self.agentsh()
        al.write(SHADOW)
        log.step()
        size = os.path.getsize(al.path)
        with open(al.path, "r+b") as f:
            f.truncate(10)
        log.step()
        self.assertTrue(log.done)
        self.assertEqual(self.reasons(), [
            f"{al.path} was truncated to 10 bytes after Tracekit read {size} bytes of it: what it held past those, and "
            f"anything written to it later, is not recorded; Tracekit no longer follows {al.path}"])
        self.assertEqual(len(self.typed("run.closing")), 1)

    def test_a_killed_follower_is_a_gap_the_signer_writes(self):
        al, log = self.agentsh()
        al.write(SHADOW)
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

    def test_a_follower_killed_after_a_gap_it_went_on_from_is_a_gap_too(self):
        al, log = self.agentsh()
        al.write(SHADOW)
        al.seq = 6
        al.write(NPM)   # a sequence gap: the follower records it and goes on
        log.step()
        self.s.sweep(time.monotonic() + svc.TAILER_LOST_S + 1)   # then it is killed
        sequence, killed = self.gaps()
        self.assertIn("agentsh sequence 6 follows 2", sequence)
        self.assertIn("the log follower stopped or was killed", killed)

    def test_a_follower_killed_across_a_signer_restart_without_a_snapshot_is_a_gap(self):
        al, log = self.agentsh()
        al.write(SHADOW)
        log.step()   # its run registered
        with mock.patch.object(FileStorage, "snapshot_put"):   # the signer stopped without its snapshot
            self.close()
        self.open()   # the run's state replayed from its records: still watched for the follower's heartbeats
        self.s.sweep(time.monotonic() + svc.TAILER_LOST_S + 1)
        [gap] = self.gaps()
        self.assertIn("the log follower stopped or was killed", gap)

    def test_a_rotated_log_is_followed_into_the_new_one(self):
        al, log = self.agentsh()
        al.write(SHADOW)
        log.step()
        al.write(NPM)   # written before the rotation: read from the renamed file
        os.rename(al.path, al.path + ".1")
        log.step()   # the new log isn't made yet
        al.write(PYTHON)
        log.step()
        self.assertEqual([e["data"]["tool_use_id"] for e in self.typed("policy.external")],
                         ["evt-029", "evt-040", "evt-046"])
        self.assertEqual(self.gaps(), [])   # the sequence runs on across files
        with open(al.path, "r+b") as f:   # a failed write agentsh took back: an incomplete line, then cut
            f.seek(0, 2)
            f.write(b'{"id":"evt-0')
        log.step()
        with open(al.path, "r+b") as f:
            f.truncate(os.path.getsize(al.path) - len(b'{"id":"evt-0'))
        al.write(SHADOW)
        log.step()
        self.assertEqual((len(self.typed("policy.external")), self.gaps()), (4, []))

    def test_without_integrity_lines_carry_no_sequence_to_check(self):
        al, log = self.agentsh(integrity=False)
        al.write(SHADOW, '{"timestamp":"2025-01-15T10:31:21Z","type":"file_read","session_id":"s","policy":'
                         '{"decision":"soft_delete","rule":"' + "r" * 80 + '"}}')
        log.step()
        self.assertEqual([(e["data"]["decision"], e["data"]["tool_use_id"], e["data"]["rule_ids"])
                          for e in self.typed("policy.external")],
                         [("deny", "evt-029", ["files.deny[0]"]), ("deny", "line-1", ["r" * 64])])
        self.assertEqual(self.gaps(), [])


class TestOverASocket(Followed):
    def open(self):
        super().open()
        self.s.close()
        me = [f"uid:{ME.subject}", "token:dev"]   # the socket's peer (token:dev where there is no AF_UNIX)
        self.s = svc.SignerService(self.dir, grace_s=0, idle_s=3600, importers=me, authorize=dict.fromkeys(me, GRANTS))

    def test_the_sdk_client_follows_the_log_while_it_is_written(self):
        client = Client(_serve(self, self.s.handle_frame))
        self.addCleanup(client.close)
        al, log = self.agentsh(client=client)
        al.write(SHADOW)
        seen = []

        def stopping():   # each round: nothing before the first read, then the decision, then a stop (SIGTERM)
            seen.append([e["data"]["decision"] for e in self.typed("policy.external")])
            return len(seen) == 3

        with mock.patch.object(follow, "POLL_S", 0):
            follow.follow(log, stopping)
        self.assertTrue(log.done)
        self.assertEqual(seen, [[], ["deny"], ["deny"]])
        self.assertEqual([e["source"] for e in self.recorded() if e["type"] in ("run.registered", "run.closing")],
                         ["import", "import"])


class TestImporters(Followed):
    def test_an_importers_run_is_imported_and_another_run_is_reconciled_as_before(self):
        mine = self.register()
        theirs = self.register(FOLLOWER)
        for run, who in ((mine, ME), (theirs, FOLLOWER)):
            self.call("decision_import", {"run_id": run["run_id"], "system": "agentsh", "decision": "deny",
                                          "tool_call_id": "evt-1", "tool": "file_read", "record": "{}"}, FOLLOWER)
            self.call("close_run", run, who)
        self.s.sweep(time.monotonic() + 1)
        regs = {e["run_id"]: e for e in self.typed("run.registered")}
        self.assertEqual((regs[mine["run_id"]]["source"], regs[theirs["run_id"]]["source"]), ("sdk", "import"))
        self.assertNotIn("fidelity", regs[mine["run_id"]]["data"])
        self.assertEqual([(e["run_id"], e["data"]["kind"]) for e in self.typed("capture.gap")],
                         [(mine["run_id"], "decision_mismatch")])   # only the reconciled run compares decisions
