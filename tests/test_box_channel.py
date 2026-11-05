"""Tracekit Box's agent channel (#602; Box's docs/agent-channel.md): a `box_daemons` identity's box run and its
signer-written `ext.box` label, `channel_open` and the box's own identity `box:<uid>/<box id>` (one per box: its own
owner, quotas, request ids, cooldowns and approvals, the channel's methods only, each run a child of its box run), the
contract's version 21 in both directions, and what the verifier says of a box's runs (tests/test_ts_verifier.py holds
the TypeScript verifier to the same lines)."""
import importlib.util
import io
import json
import os
import socket
import unittest
import uuid
from unittest import mock

from factories import BOX, box_runset_bundle
from test_signer_service import ME, PAY_ASKS, ROOT, SocketSigner, tmpdir
from tracekit.bundle_v2 import export
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.signer import rpc_schema, service as svc
from tracekit.signer.quotas import Limits
from tracekit.signer.rpc_schema import REQUESTS, RPCError
from tracekit.transport import Bound
from tracekit.verify import protection, summary, v2

DAEMON, OTHER_DAEMON = CallerIdentity("uid", "1001", True), CallerIdentity("uid", "1002", True)
CLIENT = CallerIdentity("uid", "2000", True)   # an agent outside any box
DAEMONS = {"uid:1001": "firecracker", "uid:1002": "firecracker"}
_spec = importlib.util.spec_from_file_location("e17_detection", os.path.join(ROOT, "eval", "e17_detection.py"))
e17 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(e17)


def rid():
    return uuid.uuid4().hex


class Signer(unittest.TestCase):
    def signer(self, **kw):
        kw = {"box_daemons": DAEMONS, "policy": PAY_ASKS, **kw}
        self.dir = tmpdir(self)
        s = svc.SignerService(self.dir, fsck_every_s=0, **kw)
        self.addCleanup(s.close)
        return s

    def box_run(self, s, daemon=DAEMON, box=BOX):
        out = s.call(daemon, "register_run", {"request_id": rid(), "agent": {"name": "tkbox"}, "box": box})
        return {"run_id": out["run_id"], "run_token": out["run_token"]}

    def channel(self, s, daemon=DAEMON, box=BOX):
        """(the box run's handle, the identity its channel's frames are handled as)."""
        run = self.box_run(s, daemon, box)
        out = s.call(daemon, "channel_open", dict(run))
        self.assertIsInstance(out, Bound)
        self.assertEqual(rpc_schema.validate(rpc_schema.RESPONSES["channel_open"], out), [])
        return run, out.identity

    def register(self, s, who, **kw):
        out = s.call(who, "register_run", {"request_id": rid(), "agent": {"name": "claude-code"}, **kw})
        return {"run_id": out["run_id"], "run_token": out["run_token"]}

    def refused(self, code, s, who, method, req):
        with self.assertRaises(RPCError) as cm:
            s.call(who, method, req)
        self.assertEqual(cm.exception.code, code, cm.exception)
        return cm.exception

    @staticmethod
    def registered(s, run):
        """The run.registered record of `run`, as stored."""
        return next(r["event"] for r in s.log.storage.iter_range(0, s.log.storage.tree.size)
                    if r["event"]["run_id"] == run["run_id"] and r["event"]["type"] == "run.registered")


class TestConfig(Signer):
    def test_box_daemons_take_a_uid_and_a_known_engine(self):
        for bad in ({"token:box": "firecracker"}, {"uid:1001": "docker"}, {"uid:*": "firecracker"}, ["uid:1001"]):
            with self.subTest(bad), self.assertRaises(ValueError):
                svc.SignerService(tmpdir(self), box_daemons=bad)

    def test_no_other_config_entry_names_a_box_identity(self):
        """A box identity gets the channel's methods and nothing a table could add (a gateway's `caller`, a tenant, an
        approver's view)."""
        for kw in ({"gateways": ["box:1001/*"]}, {"tenants": {"box:*": "acme"}},
                   {"authorize": {"box:1001/b-1": ["read"]}}, {"approvals": {"approvers": ["box:1001/b-1"]}},
                   {"multi_tenant_apps": ["box:1001/b-1"]}):
            with self.subTest(kw), self.assertRaisesRegex(ValueError, "box: identity"):
                svc.SignerService(tmpdir(self), **kw)

    def test_authorize_never_grants_channel_open(self):
        """Only box_daemons opens a channel: an `authorize` entry listing every method (channel_open among them)
        grants it nothing, and a box daemon needs none."""
        s = self.signer(authorize={"uid:2000": sorted(REQUESTS.keys() - {"content_get"} - svc.OPERATOR)})
        run = self.register(s, CLIENT)
        self.assertIn("not authorized for channel_open", self.refused("forbidden", s, CLIENT, "channel_open",
                                                                      run).message)
        self.assertIn("channel_open", svc.NEVER_DEFAULT)
        self.channel(s)

    def test_load_config_takes_box_daemons(self):
        d = tmpdir(self)
        path = os.path.join(d, "signer.yaml")
        with open(path, "w") as f:
            f.write('data_dir: data\nfsck_every_s: 0\nbox_daemons: {"uid:1001": firecracker}\n')
        s = svc.open_service(svc.load_config(path))
        self.addCleanup(s.close)
        self.assertEqual(s.box_daemons, {"uid:1001": "firecracker"})


class TestLabel(Signer):
    def test_the_signer_writes_ext_box_with_the_engine_from_its_config(self):
        s = self.signer()
        e = self.registered(s, self.box_run(s))
        self.assertEqual(e["ext"], {"box": {**BOX, "engine": "firecracker"}})
        self.assertEqual(e["data"]["identity"]["subject"], "1001")

    def test_only_a_box_daemon_registers_a_box_run(self):
        s = self.signer()
        req = {"request_id": rid(), "agent": {"name": "a"}, "box": BOX}
        self.refused("forbidden", s, CLIENT, "register_run", req)
        _, box = self.channel(s)
        self.refused("forbidden", s, box, "register_run", req)   # a box's agent can't label a run either

    def test_a_box_run_has_no_parent(self):
        """A labelled run with parent_run is its box's agent channel's (the replay gives it the box's identity)."""
        s = self.signer()
        up = self.register(s, DAEMON)
        self.refused("invalid_request", s, DAEMON, "register_run", {"request_id": rid(), "agent": {"name": "a"},
                                                                    "box": BOX, "parent": up})

    def test_no_request_sets_the_engine_or_any_ext(self):
        s = self.signer()
        for req in ({"box": {**BOX, "engine": "docker"}}, {"ext": {"box": BOX}}):
            with self.subTest(req):
                self.refused("invalid_request", s, DAEMON, "register_run",
                             {"request_id": rid(), "agent": {"name": "a"}, **req})
        run = self.box_run(s)
        self.refused("invalid_request", s, DAEMON, "decide", {
            **run, "request_id": rid(), "stream": "s", "client_seq": 0, "tool_call_id": "t", "tool": "Bash",
            "args_source": "parsed", "args": {}, "ext": {"box": BOX}})

    def test_the_label_and_the_owner_survive_a_restart_without_a_snapshot(self):
        """Replayed from the records: the box run's label, so its channel still opens, and its channel's runs' owner,
        the box (their run.registered names the daemon), so the box still sees its own approvals."""
        cfg = {"approvals": {"approvers": ["group:corp/ops"]}}   # no one else of the tenant sees them
        s = self.signer(**cfg)
        run, box = self.channel(s)
        child = self.register(s, box)
        s.call(box, "decide", {**child, "request_id": rid(), "stream": "s", "client_seq": 0, "tool_call_id": "t",
                               "tool": "pay", "args_source": "parsed", "args": {"amount": 5}})
        aid = s.call(box, "approval_request", {**child, "request_id": rid(), "tool_call_id": "t"})["approval_id"]
        s.close()
        snaps = os.path.join(self.dir, "store", "snapshots")
        for name in os.listdir(snaps):
            os.unlink(os.path.join(snaps, name))
        s = svc.SignerService(self.dir, policy=PAY_ASKS, fsck_every_s=0, box_daemons=DAEMONS, **cfg)
        self.addCleanup(s.close)
        box = s.call(DAEMON, "channel_open", dict(run)).identity
        self.assertEqual(s.call(box, "approval_get", {"approval_id": aid})["state"], "requested")
        self.refused("unknown_approval", s, DAEMON, "approval_get", {"approval_id": aid})


class TestChannelOpen(Signer):
    def test_the_channel_is_the_box_identity_in_the_box_runs_tenant(self):
        s = self.signer(tenants={"uid:1001": "acme"})
        run, box = self.channel(s)
        self.assertEqual((box.scheme, box.subject, box.attested), ("box", "1001/b-1", True))
        self.assertEqual(s.call(box, "status", {})["identity"], {"scheme": "box", "subject": "1001/b-1",
                                                                 "attested": True})
        child = self.register(s, box)
        self.assertEqual(s.tokens.claims(child["run_token"])["tenant"], "acme")

    def test_only_a_box_daemon_opens_a_channel(self):
        s = self.signer()
        run = self.register(s, CLIENT)
        e = self.refused("forbidden", s, CLIENT, "channel_open", run)
        self.assertIn("not authorized for channel_open", e.message)

    def test_only_for_its_own_box_run(self):
        s = self.signer()
        theirs = self.box_run(s, OTHER_DAEMON, dict(BOX, id="b-2"))
        self.refused("run_token_invalid", s, DAEMON, "channel_open", theirs)
        mine = self.box_run(s)
        self.refused("run_token_invalid", s, DAEMON, "channel_open", {**mine, "run_token": theirs["run_token"]})

    def test_only_for_a_box_run(self):
        s = self.signer()
        plain = self.register(s, DAEMON)   # a protocol 20 daemon's run: no label, no channel
        self.assertNotIn("ext", self.registered(s, plain))
        self.refused("invalid_request", s, DAEMON, "channel_open", plain)

    def test_only_while_the_box_run_is_open(self):
        s = self.signer()
        run = self.box_run(s)
        s.call(DAEMON, "close_run", {**run, "request_id": rid()})
        self.refused("run_closed", s, DAEMON, "channel_open", run)

    def test_a_box_identity_never_comes_through_a_gateway(self):
        s = self.signer(gateways=["mtls:spiffe://acme/gw"], authorize={"mtls:spiffe://acme/gw": ["decide"]})
        _, box = self.channel(s)
        child = self.register(s, box)
        e = self.refused("forbidden", s, CallerIdentity("mtls", "spiffe://acme/gw", True), "decide", {
            **child, "request_id": rid(), "caller": "box:1001/b-1", "stream": "g", "client_seq": 0,
            "tool_call_id": "t", "tool": "Bash", "args_source": "parsed", "args": {}})
        self.assertIn("own connection", e.message)


class TestBoxIdentity(Signer):
    def test_it_is_granted_the_channels_methods_only(self):
        s = self.signer()
        run, box = self.channel(s)
        child = self.register(s, box)
        for method, req in (("approval_decide", {"request_id": rid(), "approval_id": "a", "decision": "approve"}),
                            ("delegate_run", {**child, "identity": "uid:1001"}), ("read", dict(child)),
                            ("approval_list", {}), ("channel_open", dict(run)), ("tailer_heartbeat", dict(child)),
                            ("checkpoint_nudge", {})):
            with self.subTest(method):
                self.assertIn("not authorized", self.refused("forbidden", s, box, method, req).message)
        self.assertEqual(svc.CHANNEL_METHODS, {"register_run", "decide", "complete", "observe", "model_event",
                                               "state_write", "approval_request", "approval_wait", "approval_consume",
                                               "approval_get", "approval_abandon", "constraint_add", "close_run",
                                               "tailer_lost", "status"})

    def test_each_run_is_a_child_of_its_box_run_with_its_label(self):
        s = self.signer()
        run, box = self.channel(s)
        e = self.registered(s, self.register(s, box))
        self.assertEqual((e["data"]["parent_run"], e["data"]["session"]), (run["run_id"], run["run_id"]))
        # the identity the transport established (a closed format field), its box in ext.box, and no general claim
        self.assertEqual(e["data"]["identity"], {"scheme": "uid", "subject": "1001", "attested": True})
        self.assertEqual(e["data"]["signer_isolation"], "unknown")
        self.assertEqual(e["ext"], {"box": {**BOX, "engine": "firecracker"}})
        self.assertEqual(s.log.runs[(e["tenant"], e["run_id"])]["owner"], "box:1001/b-1")

    def test_its_runs_record_isolation_unknown_whatever_the_signers_own(self):
        """A signer that fixes every run's isolation (the dev signer: same-user) still records a box channel's run as
        unknown, so no general claim covers it; the daemon's box run keeps the signer's."""
        s = self.signer(isolation="same-user")
        run, box = self.channel(s)
        self.assertEqual(self.registered(s, self.register(s, box))["data"]["signer_isolation"], "unknown")
        self.assertEqual(self.registered(s, run)["data"]["signer_isolation"], "same-user")

    def test_a_reused_box_id_reaches_only_its_own_box_runs_runs(self):
        """Two box runs a daemon gives one box id share the identity box:<uid>/<box id>; each channel still writes, and
        sees the approvals of, only the runs registered under its own box run."""
        s = self.signer()
        _, first = self.channel(s)
        _, second = self.channel(s)
        self.assertEqual(first.subject, second.subject)
        theirs = self.register(s, first)
        s.call(first, "decide", {**theirs, "request_id": rid(), "stream": "s", "client_seq": 0, "tool_call_id": "t",
                                 "tool": "pay", "args_source": "parsed", "args": {"amount": 5}})
        aid = s.call(first, "approval_request", {**theirs, "request_id": rid(), "tool_call_id": "t"})["approval_id"]
        e = self.refused("run_token_invalid", s, second, "close_run", {**theirs, "request_id": rid()})
        self.assertIn("another box run", e.message)
        self.refused("unknown_approval", s, second, "approval_get", {"approval_id": aid})
        self.assertEqual(s.call(first, "approval_get", {"approval_id": aid})["state"], "requested")
        s.call(first, "close_run", {**theirs, "request_id": rid()})

    def test_it_sends_no_parent_and_registers_nothing_once_its_box_run_closed(self):
        s = self.signer()
        run, box = self.channel(s)
        mine = self.register(s, box)
        self.refused("forbidden", s, box, "register_run", {"request_id": rid(), "agent": {"name": "a"},
                                                           "parent": mine})
        s.call(DAEMON, "close_run", {**run, "request_id": rid()})
        self.refused("run_closed", s, box, "register_run", {"request_id": rid(), "agent": {"name": "a"}})

    def test_it_touches_neither_its_box_run_nor_another_boxs_runs(self):
        s = self.signer()
        run, box = self.channel(s)
        _, other = self.channel(s, OTHER_DAEMON, dict(BOX, id="b-2"))
        theirs = self.register(s, other)
        call = {"request_id": rid(), "stream": "s", "client_seq": 0, "tool_call_id": "t", "tool": "Bash",
                "args_source": "parsed", "args": {}}
        for target in (run, theirs):   # holding the token is not enough: it was issued to another identity
            with self.subTest(target["run_id"]):
                self.refused("run_token_invalid", s, box, "decide", {**call, **target})
        # and no one hands it a token for a run: a box identity has no authorize entry to delegate to
        self.refused("forbidden", s, DAEMON, "delegate_run", {**run, "identity": "box:1001/b-1"})

    def test_a_box_of_the_same_id_under_another_daemon_is_another_identity(self):
        s = self.signer()
        _, a = self.channel(s)
        _, b = self.channel(s, OTHER_DAEMON)
        self.assertNotEqual(a.subject, b.subject)
        theirs = self.register(s, b)
        self.refused("run_token_invalid", s, a, "close_run", {**theirs, "request_id": rid()})

    def test_it_sees_only_its_own_runs_approvals(self):
        """Even under the dev signer's rules (no `approvals` config), where any identity of a tenant sees its
        approvals."""
        s = self.signer()
        _, box = self.channel(s)
        _, other = self.channel(s, OTHER_DAEMON, dict(BOX, id="b-2"))

        def ask(who):
            run = self.register(s, who)
            s.call(who, "decide", {**run, "request_id": rid(), "stream": "s", "client_seq": 0, "tool_call_id": "t",
                                   "tool": "pay", "args_source": "parsed", "args": {"amount": 5}})
            return s.call(who, "approval_request", {**run, "request_id": rid(), "tool_call_id": "t"})["approval_id"]
        mine, theirs, daemons = ask(box), ask(other), ask(DAEMON)
        self.assertEqual(s.call(box, "approval_get", {"approval_id": mine})["approval_id"], mine)
        for aid in (theirs, daemons):
            self.refused("unknown_approval", s, box, "approval_get", {"approval_id": aid})
        self.assertEqual(s.call(DAEMON, "approval_get", {"approval_id": theirs})["approval_id"], theirs)

    def test_its_daemons_suspension_stops_it(self):
        s = self.signer()
        _, box = self.channel(s)
        child = self.register(s, box)
        with open(os.path.join(self.dir, "suspensions.json"), "w") as f:
            json.dump({"default": {"uid:1001": {"by": "uid:0", "at": "2026-11-05T00:00:00Z"}}}, f)
        e = self.refused("forbidden", s, box, "close_run", {**child, "request_id": rid()})
        self.assertIn("uid:1001 is suspended", e.message)


class TestOneIdentityPerBox(Signer):
    """One box's agent can't use up another box's limits or its daemon's."""

    def test_open_runs(self):
        s = self.signer(limits=Limits(open_runs=3))
        _, a = self.channel(s)
        _, b = self.channel(s, box=dict(BOX, id="b-2"))
        for _ in range(3):
            self.register(s, a)
        self.refused("quota_exceeded", s, a, "register_run", {"request_id": rid(), "agent": {"name": "a"}})
        self.register(s, b)
        self.register(s, DAEMON)   # its third: its two box runs are open

    def test_event_rate(self):
        s = self.signer(limits=Limits(events_per_s=0.001, burst=4))
        _, a = self.channel(s)   # each of the daemon's register_runs spends one of its own
        _, b = self.channel(s, box=dict(BOX, id="b-2"))
        run = self.register(s, a)
        for i in range(3):
            s.call(a, "observe", {**run, "request_id": rid(), "stream": "s", "client_seq": i, "source": "user",
                                  "trust": "trusted", "value": "x"})
        e = self.refused("quota_exceeded", s, a, "observe", {**run, "request_id": rid(), "stream": "s", "client_seq": 3,
                                                             "source": "user", "trust": "trusted", "value": "x"})
        self.assertIsNotNone(e.retry_after_ms)
        self.register(s, b)
        self.register(s, DAEMON)

    def test_pending_approvals(self):
        s = self.signer(limits=Limits(pending_approvals=1))
        _, a = self.channel(s)
        _, b = self.channel(s, box=dict(BOX, id="b-2"))

        def ask(who, tcid="t"):
            run = self.register(s, who)
            s.call(who, "decide", {**run, "request_id": rid(), "stream": "s", "client_seq": 0, "tool_call_id": tcid,
                                   "tool": "pay", "args_source": "parsed", "args": {"amount": 5}})
            return run, {**run, "request_id": rid(), "tool_call_id": tcid}
        s.call(a, "approval_request", ask(a)[1])
        self.refused("quota_exceeded", s, a, "approval_request", ask(a)[1])
        for who in (b, DAEMON):
            with self.subTest(who.subject):
                s.call(who, "approval_request", ask(who)[1])

    def test_request_ids(self):
        s = self.signer()
        _, a = self.channel(s)
        _, b = self.channel(s, box=dict(BOX, id="b-2"))
        req = {"request_id": "same", "agent": {"name": "a"}}
        runs = {s.call(who, "register_run", dict(req))["run_id"] for who in (a, b, DAEMON)}
        self.assertEqual(len(runs), 3)   # one id, three identities: three requests

    def test_a_hold_cools_down_its_own_box_only(self):
        """An operator's hold of one box's run starts that box's new runs held (cooldown, by owner); another box's and
        the daemon's start as they would."""
        op = CallerIdentity("uid", "3000", True)
        s = self.signer(authorize={"uid:3000": ["run_hold"]}, approvals={"approvers": ["group:corp/ops"]})
        _, a = self.channel(s)
        _, b = self.channel(s, box=dict(BOX, id="b-2"))
        held = self.register(s, a)
        s.call(op, "run_hold", {"request_id": rid(), "run_id": held["run_id"]})

        def first(who):
            run = self.register(s, who)
            return s.call(who, "decide", {**run, "request_id": rid(), "stream": "s", "client_seq": 0,
                                          "tool_call_id": "t", "tool": "read_file", "args_source": "parsed",
                                          "args": {}})["decision"]
        self.assertEqual(first(a), "ask")
        self.assertEqual((first(b), first(DAEMON)), ("allow", "allow"))

    def test_an_owner_scoped_detection_contains_its_own_box_only(self):
        """#603's review: a sequence scoped by owner that one box's agent completes holds that box's runs (and its new
        ones, by cooldown); not the other box's, nor its daemon's box runs, whose records name the same uid."""
        pol = {**e17.POLICY, "sequences": [{"id": "Q", "steps": ["secret", "egress"], "scope": "owner", "window": 600}],
               "respond": [{"trigger": "Q", "mode": "enforce", "action": "hold", "cooldown_s": 600}]}
        s = self.signer(policy=e17.engine(pol), approvals={"approvers": ["group:corp/ops"]})
        box_a, a = self.channel(s)
        box_b, b = self.channel(s, box=dict(BOX, id="b-2"))
        mine, theirs = self.register(s, a), self.register(s, b)
        n = iter(range(100))

        def decide(who, run, tool):
            i = next(n)
            return s.call(who, "decide", {**run, "request_id": rid(), "stream": "s", "client_seq": i,
                                          "tool_call_id": f"t{i}", "tool": tool[0], "args_source": "parsed",
                                          "args": tool[1]})
        decide(a, mine, e17.SECRET)
        decide(a, mine, e17.EGRESS)
        held = {name: bool(s.log.runs[("default", r["run_id"])].get("held"))
                for name, r in (("a's run", mine), ("b's run", theirs), ("box run a", box_a), ("box run b", box_b))}
        self.assertEqual(held, {"a's run": True, "b's run": False, "box run a": False, "box run b": False})
        read = ("read_file", {"path": "/a"})
        self.assertEqual(decide(a, self.register(s, a), read)["decision"], "ask")   # inherits the hold
        self.assertEqual(decide(b, self.register(s, b), read)["decision"], "allow")
        self.assertFalse(s.log.runs[("default", self.box_run(s, box=dict(BOX, id="b-3"))["run_id"])].get("held"))


class TestContractVersion(unittest.TestCase):
    """Version 21 adds the channel and the label; a version 20 client keeps working with no label (TestChannelOpen's
    test_only_for_a_box_run), and a version 20 signer refuses both, so the client gets no label."""

    def test_version_21_adds_optional_fields_and_one_method(self):
        self.assertEqual(rpc_schema.RPC_VERSION, 21)
        self.assertEqual(rpc_schema.RPC_MIN, 15)
        self.assertNotIn("box", REQUESTS["register_run"]["required"])
        self.assertEqual(rpc_schema.validate(REQUESTS["register_run"], {"request_id": "r", "agent": {"name": "a"}}), [])

    def test_a_version_20_signer_refuses_the_channel_and_the_label(self):
        v20 = {m: s for m, s in REQUESTS.items() if m != "channel_open"}
        reg = REQUESTS["register_run"]
        v20["register_run"] = {**reg, "properties": {k: v for k, v in reg["properties"].items() if k != "box"}}
        s = svc.SignerService(tmpdir(self), box_daemons=DAEMONS, fsck_every_s=0)
        self.addCleanup(s.close)
        with mock.patch.dict(REQUESTS, v20, clear=True):
            for method, req in (("channel_open", {"run_id": "r", "run_token": "t"}),
                                ("register_run", {"request_id": rid(), "agent": {"name": "a"}, "box": BOX})):
                with self.subTest(method), self.assertRaises(RPCError) as cm:
                    s.call(DAEMON, method, req)
                self.assertEqual(cm.exception.code, "invalid_request")
        self.assertFalse(any("ext" in r["event"] for r in s.log.storage.iter_range(0, s.log.storage.tree.size)))


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "no Unix sockets")
class TestEndToEnd(unittest.TestCase):
    """A stand-in Box daemon (this process's uid, in box_daemons) over the signer's Unix socket: it registers its box
    run on one connection and opens the box's channel on another, which then carries a coding agent's hook frames
    verbatim; the agent's run, exported, verifies with the box's lines and never the general claim."""

    def setUp(self):
        d = tmpdir(self)
        self.cfg = {"data_dir": d, "socket": os.path.join(d, "s.sock"), "grace_s": 0, "fsck_every_s": 0,
                    "box_daemons": {f"uid:{ME.subject}": "firecracker"}}
        self.service = svc.open_service(self.cfg, policy=PAY_ASKS)
        for srv in svc.serve(self.cfg, self.service):
            self.addCleanup(self.service.close)
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)

    def connect(self):
        c = SocketSigner(self.cfg["socket"])
        self.addCleanup(c.close)
        return c

    def test_a_boxed_agents_run_through_the_channel(self):
        daemon = self.connect()
        box = daemon.register_run({"request_id": rid(), "agent": {"name": "tkbox"}, "box": BOX})
        box_run = {"run_id": box["run_id"], "run_token": box["run_token"]}
        channel = self.connect()
        lo, hi = channel.hello({})["proto"]   # the hook's first frame: the signer serves version 21 and older ones
        self.assertEqual((lo, hi), (rpc_schema.RPC_MIN, rpc_schema.RPC_VERSION))
        self.assertEqual(channel.channel_open(dict(box_run)), {"identity": f"box:{ME.subject}/b-1"})
        # the hook's frames, unchanged: the signer names its run and parents it
        run = channel.register_run({"request_id": rid(), "agent": {"name": "claude-code", "version": "2.1.0"}})
        ids = {"run_id": run["run_id"], "run_token": run["run_token"]}
        d = channel.decide({**ids, "request_id": rid(), "stream": "h", "client_seq": 0, "tool_call_id": "toolu_1",
                            "tool": "Bash", "args_source": "parsed", "args": {"command": "ls"}})
        channel.complete({**ids, "request_id": rid(), "stream": "h", "client_seq": 1, "tool_call_id": "toolu_1",
                          "decision_id": d["decision_id"], "status": "ok",
                          "args_digest": event_hash({"tool": "Bash", "args": {"command": "ls"}})})
        self.assertEqual(channel.status({})["identity"]["scheme"], "box")
        with self.assertRaises(RPCError) as cm:   # the channel stays the box's: no second channel, no daemon calls
            channel.channel_open(dict(box_run))
        self.assertEqual(cm.exception.code, "forbidden")
        with self.assertRaises(RPCError) as cm:   # the box run's own token is the daemon's
            channel.close_run({**box_run, "request_id": rid()})
        self.assertEqual(cm.exception.code, "run_token_invalid")
        channel.close_run({**ids, "request_id": rid()})
        daemon.close_run({**box_run, "request_id": rid()})
        self.assertEqual(daemon.status({})["identity"]["scheme"], "uid")   # the daemon's own connection is its own

        s = self.service
        s.sweep()
        s.checkpoint()
        _, note = s.log.storage.checkpoint_latest()
        out, trust = os.path.join(self.cfg["data_dir"], "agent.tkb"), os.path.join(self.cfg["data_dir"], "trust.json")
        export(s.log.storage, "default", run["run_id"], note, out)
        with open(trust, "w") as f:
            json.dump({"logs": [s.vkey], "witnesses": [], "algs": ["ed25519"], "witnesses_required": 0}, f)
        rep, code = v2.verify(out, trust)
        self.assertEqual(code, 0, rep.checks)
        [line] = [c for c in rep.checks if c["check"] == "boxed agent"]
        self.assertEqual((line["status"], line["detail"]), ("pass", "PROOF AGAINST THE BOXED AGENT (micro-VM): the "
                                                                    "signing key was outside its box for this run."))
        said = io.StringIO()
        summary(rep, code, rep.integrity, rep.assurance, said)
        self.assertEqual(said.getvalue().splitlines()[1:], [
            "PROOF AGAINST THE BOXED AGENT (micro-VM): the signing key was outside its box for this run.",
            "This run's records are the agent's own account of its calls; the box's doors (its connections and file "
            "writes) are the record of what it could do.",
            "Before you run anything the box wrote, review it: code you run on this machine can reach the key."])


class TestVerifier(unittest.TestCase):
    """What verify says of a box's runs: the box's lines, never the general claim (tracekit.verify.protection)."""

    @staticmethod
    def rep(isolation, boxed=None):
        r = type("Rep", (), {"isolation": isolation, "checks": []})()
        if boxed is not None:
            r.boxed = boxed
        return r

    def test_a_box_bundle_gets_the_box_lines_only(self):
        lines = ["PROOF AGAINST THE BOXED AGENT (micro-VM): ...", "This run's records ..."]
        for iso in ({"separate-user": 1}, {"remote": 1}, {"unknown": 1}):   # the daemon's run is a separate user's
            with self.subTest(iso):
                said = protection(self.rep(iso, (1, lines)), "witnessed; records ed25519", False)
                self.assertEqual(said, lines)

    def test_a_run_set_claims_only_for_the_runs_it_holds(self):
        """#603's review: a run-set's registry records point to other runs' run.registered, labels included. A plain
        run's run-set bundle whose range holds a box run gets no box line: it isn't that run's. Its protection lines are
        the ones the same run gets exported alone (whatever this platform's signer recorded for it)."""
        bundle, alone, trust = box_runset_bundle(tmpdir(self))
        lines = []
        for path in (bundle, alone):
            rep, code = v2.verify(path, trust)
            self.assertEqual(code, 0, rep.checks)
            self.assertNotIn("boxed agent", [c["check"] for c in rep.checks])
            said = io.StringIO()
            summary(rep, code, rep.integrity, rep.assurance, said)
            self.assertNotIn("BOXED", said.getvalue())
            lines.append(protection(rep, rep.assurance, False))
            self.assertTrue(set(lines[-1]) <= set(said.getvalue().splitlines()), said.getvalue())
        self.assertEqual(lines[0], lines[1])
        self.assertFalse(any(x.startswith("PROOF") for x in lines[0]), lines[0])   # a dev run: never proof

    def test_a_mixed_bundle_never_gets_the_general_claim(self):
        lines = ["PROOF AGAINST THE BOXED AGENT (micro-VM): ..."]
        said = protection(self.rep({"separate-user": 2}, (1, lines)), "witnessed; records ed25519", False)
        self.assertFalse(any(x.startswith("PROOF AGAINST THE AGENT") for x in said), said)
        self.assertTrue(said[0].startswith("NOT SHOWN: "), said)
        self.assertEqual(said[-1], lines[0])
        plain = protection(self.rep({"separate-user": 2}), "witnessed; records ed25519", False)
        self.assertTrue(plain[0].startswith("PROOF AGAINST THE AGENT: "), plain)

    def test_a_label_the_signer_never_writes_claims_nothing(self):
        e = {"type": "run.registered", "seq": 3, "data": {"identity": {"scheme": "uid", "subject": "1001"}},
             "ext": {"box": {**BOX, "engine": "firecracker"}}}
        child = {**e, "data": {**e["data"], "parent_run": "r"}}
        good = {"the agent's own account": child, "as the Box daemon recorded them": e,
                "as the Box daemon recorded them.": {**e, "ext": {"box": {"id": "b-1", "allow": [], "engine":
                                                                          "firecracker",
                                                                          "image_digest": BOX["image_digest"]}}}}
        bad = [{**e, "type": "tool.call"}, {**e, "ext": {"box": {**BOX, "engine": "docker"}}},
               {**e, "ext": {"box": {**BOX, "engine": ["firecracker"]}}},
               {**e, "ext": {"box": {**BOX, "engine": "firecracker", "extra": 1}}},
               {**e, "ext": {"box": {**BOX, "engine": "firecracker", "channel": "other"}}},
               {**e, "ext": {"box": {**BOX, "engine": "firecracker", "allow": [1]}}},
               {**e, "ext": {"box": {**BOX, "engine": "firecracker", "image_digest": "sha256:x"}}},
               {**e, "ext": {"box": {**BOX, "engine": "firecracker", "id": "b 1"}}},
               {**e, "data": {"identity": {"scheme": "token", "subject": "box"}}},
               {**child, "data": {"identity": {"scheme": "box", "subject": "1001/b-1"}, "parent_run": "r"}}]
        for said, x in good.items():
            rep = v2.Report()
            rep.anchored = ["w.example/w (customer) at 2026-11-05T00:00:00Z"]
            v2._box(rep, [x])
            self.assertEqual(rep.checks[0]["status"], "pass", x)
            self.assertIn(said, rep.checks[0]["problems"][0])
            self.assertEqual(rep.checks[0]["problems"][2], "anchored by w.example/w (customer) at 2026-11-05T00:00:00Z")
            self.assertEqual(rep.boxed, (1, [rep.checks[0]["detail"], *rep.checks[0]["problems"]]))
        for events in ([x] for x in bad):
            with self.subTest(events):
                rep = v2.Report()
                v2._box(rep, events)
                self.assertEqual(rep.checks[0]["status"], "warn")
                self.assertEqual(rep.boxed[0], 1)
                self.assertTrue(rep.boxed[1][0].startswith("NOT SHOWN: "), rep.boxed)


if __name__ == "__main__":
    unittest.main()
