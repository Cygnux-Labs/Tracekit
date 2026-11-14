"""export_run (RPC contract 23): a customer downloads a run of its own tenant over the signer's HTTP API as the .tkb
bundle the operator's `tracekit export --v2` writes (tracekit/signer/service.py, sdk/client.py, cli.py)."""
import base64
import binascii
import contextlib
import io
import itertools
import json
import os
import random
import string
import threading
import time
import unittest
import zipfile
from unittest import mock

import test_signer_service as ts
from factories import patch_env, signer_without_fsync
from test_issuer import ISSUANCE, NAME, TOKEN, scopes
from test_witness_publish import VKEY, FakeWitness
from tracekit import cli, issuer
from tracekit.bundle_v2 import run_name
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.identity.token import TokenStore
from tracekit.sdk.client import Client, SignerUnavailable
from tracekit.signer import service as svc
from tracekit.signer.quotas import MAX_LINE, Limits, Quotas
from tracekit.signer.rpc_schema import RPCError
from tracekit.tlog_witness import TlogWitness
from tracekit.transport import http as tk_http
from tracekit.verify import v2 as verify_v2
from tracekit.verify.v2 import MAX_TOTAL

AGENT = ["register_run", "decide", "complete", "model_event", "close_run", "status"]   # an agent's grants: no export_run


def write_secret(path, text):
    """A new token file, owner-only from its creation, as docs/remote-ingest.md has operators write one."""
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
        f.write(text)


class TestExportRun(unittest.TestCase):
    """A signer with two tenants, acme and beta.co, on its plain-HTTP loopback listener: each tenant's agent token
    records runs, and its owner tokens (owner-a and owner-a2 of acme, owner-b of beta.co) hold export_run alone."""

    def setUp(self):
        self.d, self.n = ts.tmpdir(self), itertools.count()
        self.tokens = TokenStore(os.path.join(self.d, "tokens.json"))
        self.config = os.path.join(self.d, "signer.yaml")
        with open(self.config, "w") as f:   # JSON is YAML
            json.dump({"data_dir": "data", "grace_s": 0, "fsck_every_s": 0,
                       "limits": {"events_per_s": 1e6, "burst": 10 ** 6},
                       "http": {"listen": "127.0.0.1:0", "insecure_loopback": True, "authenticators": ["token"],
                                "tokens": "tokens.json"},
                       "authorize": {"token:agent-a": AGENT, "token:agent-b": AGENT,
                                     **dict.fromkeys(["token:owner-a", "token:owner-a2", "token:owner-a3",
                                                      "token:owner-b", "token:no-tenant"], ["export_run"])}}, f)
        cfg = svc.load_config(self.config)
        self.s = svc.open_service(cfg, policy=ts.PAY_ASKS)
        self.addCleanup(self.s.close)
        (srv,) = svc.serve(cfg, self.s)
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.url = f"http://127.0.0.1:{srv.server_address[1]}"
        self.secrets = []
        self.A, self.A2 = (CallerIdentity("token", n, True, {"tenant": "acme"}) for n in ("owner-a", "owner-a2"))
        self.B = CallerIdentity("token", "owner-b", True, {"tenant": "beta.co"})

    def export(self, who, run_id, **req):
        """export_run in process, as `who`."""
        return self.s.call(who, "export_run", {"run_id": run_id, **req})

    def refused(self, code, who, run_id, **req):
        """The refusal of export_run as `who`, which must have `code`."""
        with self.assertRaises(RPCError) as cm:
            self.export(who, run_id, **req)
        self.assertEqual(cm.exception.code, code, cm.exception)
        return cm.exception

    def token(self, name, tenant):
        """A token file for a new token `name` of `tenant`."""
        path = os.path.join(self.d, f"{name}.token")
        self.secrets.append(self.tokens.add(name, 3600, tenant=tenant))
        write_secret(path, self.secrets[-1])
        return path

    def client(self, name, tenant):
        c = Client(self.url, timeout=10, token_file=self.token(name, tenant))
        self.addCleanup(c.close)
        return c

    def agent_run(self, agent, tenant, said=()):
        """The id of a closed run of token `agent` of `tenant`: one call, then a model response per list in `said` of
        the tool uses (the provider's own) it names."""
        me, seq = CallerIdentity("token", agent, True, {"tenant": tenant}), itertools.count()

        def call(method, req):
            return self.s.call(me, method, {"request_id": f"r{next(self.n)}", **req})
        ids = call("register_run", {"agent": {"name": "agent"}})
        ids = {"run_id": ids["run_id"], "run_token": ids["run_token"]}
        args = {"path": "a.txt"}
        d = call("decide", {**ids, "stream": "s", "client_seq": next(seq), "tool_call_id": "tc-1", "tool": "read_file",
                            "args_source": "parsed", "args": args})
        call("complete", {**ids, "stream": "s", "client_seq": next(seq), "tool_call_id": "tc-1", "status": "ok",
                          "decision_id": d["decision_id"], "args_digest": event_hash({"tool": "read_file", "args": args})})
        for uses in said:
            call("model_event", {**ids, "stream": "s", "client_seq": next(seq), "provider": "openai", "model": "gpt",
                                 "phase": "response", "tool_uses": uses})
        call("close_run", ids)
        return ids["run_id"]

    def settle(self):
        """Every run final and a checkpoint over them, as a running signer has them within seconds."""
        self.s.sweep(time.monotonic() + 1)
        self.s.checkpoint()

    def verified(self, data):
        """The bundle `data` written to a file, after it verifies against the signer's log key."""
        path, trust = os.path.join(self.d, f"b{next(self.n)}.tkb"), os.path.join(self.d, "trust.json")
        with open(path, "wb") as f:
            f.write(data)
        with open(trust, "w") as f:
            json.dump({"logs": [self.s.vkey], "witnesses": [], "algs": ["ed25519"], "witnesses_required": 0}, f)
        rep, code = verify_v2.verify(path, trust)
        self.assertEqual(code, verify_v2.EXIT_OK, rep.failures)
        return path

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_the_callers_own_run_downloads_and_verifies(self):
        mine = self.agent_run("agent-a", "acme")
        theirs = self.agent_run("agent-b", "beta.co", [[{"id": "c-1", "name": "beta_only_tool", "executed_by": "provider"}]])
        self.settle()
        path = self.verified(self.client("owner-a", "acme").export_bundle(mine))
        with zipfile.ZipFile(path) as z:
            self.assertEqual([n for n in z.namelist() if n.startswith("runs/")], [run_name("acme", mine)])
            held = b"".join(z.read(n) for n in z.namelist())
        keys, secrets = os.path.join(self.s.data_dir, "keys"), []
        for name in os.listdir(keys):
            with open(os.path.join(keys, name), "rb") as f:
                k = f.read()
            secrets += [k.strip(), binascii.hexlify(k), base64.b64encode(k)]
        self.assertTrue(secrets)
        for leak in [theirs.encode(), b"beta.co", b"beta_only_tool", *(s.encode() for s in self.secrets), *secrets]:
            self.assertNotIn(leak, held)

    def test_another_tenants_run_is_refused_as_a_missing_one(self):
        theirs = self.agent_run("agent-b", "beta.co")
        self.settle()
        owner, refusals = self.client("owner-a", "acme"), []
        for rid in (theirs, "no-such-run"):
            for req in ({"run_id": rid}, {"run_id": rid, "offset": 1, "digest": "sha256:" + "0" * 64}):
                with self.assertRaises(RPCError) as cm:
                    owner.export_run(req)
                refusals.append((cm.exception.code, cm.exception.message.replace(rid, "RUN"), cm.exception.retry_after_ms))
        self.assertEqual(refusals, [("unknown_run", "RUN", None)] * 4)

    def test_an_identity_without_the_grant_is_refused(self):
        mine = self.agent_run("agent-a", "acme")
        self.settle()
        with self.assertRaises(RPCError) as cm:   # the run's own agent: every grant of its list, not this one
            self.client("agent-a", "acme").export_run({"run_id": mine})
        self.assertEqual(cm.exception.code, "forbidden")
        for who in (ts.ME, CallerIdentity("token", "dev", True)):   # no default: identities that get every default grant
            with self.subTest(who=who.subject), self.assertRaises(RPCError) as cm:
                self.s.call(who, "export_run", {"run_id": mine})
            self.assertEqual(cm.exception.code, "forbidden")

    def test_a_bundle_larger_than_one_frame_arrives_whole(self):
        rnd = random.Random(7)   # random names, which deflate barely shrinks, as records hold them

        def text(n):
            return "".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(n))
        said = [[{"id": text(128), "name": text(256), "executed_by": "provider"} for _ in range(128)] for _ in range(40)]
        with signer_without_fsync():
            mine = self.agent_run("agent-a", "acme", said)
        self.settle()
        owner = self.client("owner-a", "acme")
        with mock.patch.object(self.s, "_export_bytes", wraps=self.s._export_bytes) as built:
            first = owner.export_run({"run_id": mine})
            self.assertGreater(first["size"], MAX_LINE)   # more than one answer can carry
            self.assertLess(len(first["data"]), MAX_LINE)
            data = owner.export_bundle(mine)
        self.assertEqual(built.call_count, 1)   # the second download, at the same checkpoint, takes the bundle built
        self.assertEqual((len(data), data[:len(base64.b64decode(first["data"]))]),
                         (first["size"], base64.b64decode(first["data"])))
        with zipfile.ZipFile(self.verified(data)) as z:
            self.assertIn(said[-1][-1]["name"].encode(), z.read(run_name("acme", mine)))

    def test_the_remote_cli_export_is_the_operators_byte_for_byte(self):
        mine = self.agent_run("agent-a", "acme")
        self.agent_run("agent-b", "beta.co")
        self.settle()
        operator, remote = os.path.join(self.d, "operator.tkb"), os.path.join(self.d, "remote.tkb")
        code, _, err = self.cli("export", "--v2", "--config", self.config, "--tenant", "acme", "--run", mine, "-o",
                                operator)
        self.assertEqual(code, 0, err)
        patch_env(self, TRACEKIT_SIGNER=self.url, TRACEKIT_SIGNER_TOKEN_FILE=self.token("owner-a", "acme"))
        code, out, err = self.cli("export", "--v2", "--run", mine, "-o", remote)
        self.assertEqual(code, 0, err)
        self.assertIn(f"wrote {remote}: run {mine} from {self.url}", out)
        self.assertIn(f"tracekit verify {remote} --trust trust.json", out)
        with open(operator, "rb") as f, open(remote, "rb") as g:
            self.assertEqual(f.read(), g.read())
        code, _, err = self.cli("export", "--v2", "--run", mine, "--tenant", "beta.co", "-o", remote)   # its own choice
        self.assertEqual(code, 2)
        self.assertIn("--tenant", err)

    def test_an_unknown_digest_is_refused_without_a_build(self):
        """A made-up digest made the signer read the store and build the bundle again on every call."""
        mine = self.agent_run("agent-a", "acme")
        self.settle()
        first = self.export(self.A, mine)
        with mock.patch.object(self.s, "_export_bytes", wraps=self.s._export_bytes) as built:
            for _ in range(25):
                self.refused("conflict", self.A, mine, digest="sha256:" + "0" * 64, offset=0)
            self.assertEqual(self.export(self.A, mine, digest=first["digest"])["data"], first["data"])
        self.assertEqual(built.call_count, 0)

    def test_the_latest_note_is_read_outside_the_lock_and_never_for_a_chunk(self):
        """It was read under the export lock on every call: on Postgres, a query every chunk waited behind."""
        mine = self.agent_run("agent-a", "acme")
        self.settle()
        real, held = self.s.log.storage.checkpoint_latest, []

        def latest(*a):
            if threading.current_thread() is threading.main_thread():   # not the signer's own checkpoint thread
                held.append(self.s._exports_lock.locked())
            return real(*a)
        with mock.patch.object(self.s.log.storage, "checkpoint_latest", side_effect=latest):
            first = self.export(self.A, mine)
            self.export(self.A, mine, digest=first["digest"], offset=0)
        self.assertEqual(held, [False])

    def test_a_build_waits_for_no_other(self):
        """One lock was held while any bundle was built: every other tenant's export queued behind it."""
        mine, other = self.agent_run("agent-a", "acme"), self.agent_run("agent-a", "acme")
        theirs, more = self.agent_run("agent-b", "beta.co"), self.agent_run("agent-b", "beta.co")
        self.settle()
        started, release, real = threading.Event(), threading.Event(), self.s._export_bytes

        def slow(key):   # acme's build takes as long as the test says
            if key[0] == "acme":
                started.set()
                release.wait(10)
            return real(key)
        with mock.patch.object(self.s, "_export_bytes", side_effect=slow):
            t = threading.Thread(target=self.export, args=(self.A, mine))
            t.start()
            self.assertTrue(started.wait(10))
            t0 = time.monotonic()
            self.assertGreater(self.export(self.B, theirs)["size"], 0)   # another tenant's builds at once
            for run_id in (mine, other):   # the same tenant's: told to ask again, never queued
                e = self.refused("unavailable", self.A2, run_id)
                self.assertEqual((e.message, e.retry_after_ms), ("the signer is building another bundle of your "
                                                                 "tenant: ask again", svc.EXPORT_RETRY_MS))
            with mock.patch.object(svc, "EXPORT_BUILDS", 1):   # past the builds at once: the same
                self.assertEqual(self.refused("unavailable", self.B, more).message,
                                 "the signer is building as many bundles as it builds at once: ask again")
            self.assertLess(time.monotonic() - t0, 5)
            release.set()
            t.join(10)
        self.assertGreater(self.export(self.A2, other)["size"], 0)

    def test_builds_are_rate_limited_per_identity_and_per_tenant(self):
        runs, theirs = [self.agent_run("agent-a", "acme") for _ in range(3)], self.agent_run("agent-b", "beta.co")
        self.settle()
        self.s._export_quotas = (Quotas(Limits(events_per_s=0.001, burst=1)), Quotas(Limits(events_per_s=0.001, burst=2)))
        self.export(self.A, runs[0])
        self.export(self.A, runs[0])   # the bundle kept at this checkpoint: no build
        self.assertGreater(self.refused("quota_exceeded", self.A, runs[1]).retry_after_ms, 0)   # owner-a's one build
        self.export(self.A2, runs[1])   # acme's second
        self.refused("quota_exceeded", CallerIdentity("token", "owner-a3", True, {"tenant": "acme"}), runs[2])   # acme's
        self.export(self.B, theirs)   # another tenant's own

    def test_a_tenant_never_drops_another_tenants_bundle_in_use(self):
        """Four bundles were kept for the whole signer: one tenant's downloads cut another's short."""
        theirs, runs = self.agent_run("agent-b", "beta.co"), [self.agent_run("agent-a", "acme") for _ in range(5)]
        self.settle()
        begun = self.export(self.B, theirs)   # beta.co begins a download
        size = begun["size"]
        with mock.patch.multiple(svc, EXPORT_TENANT_BYTES=int(2.5 * size), EXPORT_KEPT_BYTES=int(3.5 * size)):
            digests = [self.export(self.A, r)["digest"] for r in runs[:4]]   # acme keeps its last two
            self.assertEqual(self.export(self.B, theirs, digest=begun["digest"], offset=1)["offset"], 1)
            self.refused("conflict", self.A, runs[0], digest=digests[0])   # acme's own oldest went
            self.export(self.A, runs[3], digest=digests[3])
            with mock.patch.object(svc, "EXPORT_KEPT_BYTES", int(1.5 * size)):   # full of beta.co's download in use
                self.refused("unavailable", self.A, runs[4])
                self.export(self.A, runs[3], digest=digests[3])   # nothing of acme's dropped for a refused one
                self.export(self.B, theirs, digest=begun["digest"])
                with mock.patch.object(svc, "EXPORT_IDLE_S", -1):   # unused that long: it may go
                    self.export(self.A, runs[4])
                self.refused("conflict", self.B, theirs, digest=begun["digest"])
            with mock.patch.object(svc, "EXPORT_TENANT_BYTES", size // 2):   # more than a tenant may hold
                self.refused("quota_exceeded", self.B, theirs)

    def test_an_agent_or_an_identity_with_no_tenant_of_its_own_is_refused(self):
        mine = self.agent_run("agent-a", "acme")
        self.settle()
        e = self.refused("forbidden", CallerIdentity("token", "no-tenant", True), mine)   # not the default tenant's runs
        self.assertIn("no tenant of its own", e.message)
        # an OIDC person's keys together: export_run as a person, a call that writes as a group member (a run delegated
        # to it, an OTLP importer: not register_run), refused; calls that only read, accepted
        alice = CallerIdentity("oidc", "corp/alice", True, {"person": "alice", "groups": ["corp/agents"],
                                                            "tenant": "acme"})
        self.s.authorize["person:alice"] = ["export_run"]
        for writes in (["decide", "complete", "model_event"], ["otlp_import"], ["register_run"]):
            self.s.authorize["group:corp/agents"] = writes
            with self.subTest(writes):
                self.assertIn(f"also granted calls that write ({', '.join(sorted(writes))})",
                              self.refused("forbidden", alice, mine).message)
        self.s.authorize["group:corp/agents"] = ["status", "read", "approval_list"]
        self.assertGreater(self.export(alice, mine)["size"], 0)
        for authorize, why in (({"token:sub": ["decide", "complete", "model_event", "export_run"]},
                                r"calls that write: token:sub \(complete, decide, model_event\)"),
                               ({"token:app": ["otlp_import", "export_run"]}, r"token:app \(otlp_import\)"),
                               ({"token:agent-x": ["register_run", "export_run"]}, r"token:agent-x \(register_run\)"),
                               ({"uid:1001": ["export_run"]}, "gives no tenant"),
                               ({"mtls:spiffe://acme/*": ["export_run"]}, "gives no tenant")):
            with self.subTest(authorize), self.assertRaisesRegex(ValueError, why):   # at startup
                svc.SignerService(ts.tmpdir(self), authorize=authorize)
        svc.SignerService(ts.tmpdir(self), tenants={"uid:1001": "acme"}, authorize={
            "uid:1001": ["export_run", *sorted(svc.EXPORT_READS)]}).close()   # every call that only reads

    def test_the_client_holds_no_more_than_the_size_named(self):
        c = Client(self.url, timeout=5, token_file=self.token("owner-a", "acme"))
        self.addCleanup(c.close)
        digest, chunk = "sha256:" + "0" * 64, base64.b64encode(b"x" * 10).decode()
        with mock.patch.object(c, "export_run", return_value={"digest": digest, "size": MAX_TOTAL + 1, "offset": 0,
                                                              "data": chunk}):
            with self.assertRaisesRegex(SignerUnavailable, "over the format's 512 MiB"):
                c.export_bundle("r")
        with mock.patch.object(c, "export_run", side_effect=[{"digest": digest, "size": 15, "offset": 0, "data": chunk},
                                                             {"digest": digest, "size": 15, "offset": 10, "data": chunk}]):
            with self.assertRaisesRegex(SignerUnavailable, "sent 10 bytes at 10 of a bundle of 15"):
                c.export_bundle("r")


class TestIssuedRecordKeys(unittest.TestCase):
    """A signer whose record keys an issuer certifies: the certificate in every bundle's key records names its
    tenants."""

    def export(self, tenants):
        """export_run of an acme run by acme's owner, on a signer whose record key is certified for `tenants`."""
        d = ts.tmpdir(self)
        fw = FakeWitness()
        self.addCleanup(fw.stop)
        token = os.path.join(d, "token")
        write_secret(token, TOKEN)
        iss = issuer.Issuer(os.path.join(d, "issuer"), NAME, ISSUANCE, scopes(log_ids=("*",), tenants=tenants),
                            [TlogWitness(fw.url, VKEY, timeout=2)])
        fw.logs[ISSUANCE] = iss.log_vkey
        srv = tk_http.HttpServer(*tk_http.configure({"listen": "127.0.0.1:0", "authenticators": ["token"],
                                                     "token_file": token, "insecure_loopback": True}), iss.handle_frame)
        threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        s = svc.SignerService(os.path.join(d, "signer"), grace_s=0, authorize={
            "token:agent": ["register_run", "close_run"], "token:owner": ["export_run"]}, record_key={"issuer": {
                "url": f"http://127.0.0.1:{srv.server_address[1]}", "vkey": iss.vkey, "issuance_log_vkey": iss.log_vkey,
                "tenants": list(tenants), "ttl_s": 600, "token_file": token}})
        self.addCleanup(s.close)
        agent = CallerIdentity("token", "agent", True, {"tenant": "acme"})
        run = s.call(agent, "register_run", {"request_id": "r1", "agent": {"name": "a"}})
        s.call(agent, "close_run", {"request_id": "r2", "run_id": run["run_id"], "run_token": run["run_token"]})
        s.sweep(time.monotonic() + 1)
        s.checkpoint()
        return s.call(CallerIdentity("token", "owner", True, {"tenant": "acme"}), "export_run", {"run_id": run["run_id"]})

    def test_a_certificate_naming_another_tenant_is_refused(self):
        """acme's own bundle named beta.co in keys/records.jsonl, and each signer.epoch when tenants joined or left."""
        with self.assertRaises(RPCError) as cm:
            self.export(("acme", "beta.co"))
        self.assertEqual(cm.exception.code, "forbidden")
        self.assertIn("certificates, which name tenants other than yours", cm.exception.message)
        self.assertNotIn("beta.co", cm.exception.message)
        with zipfile.ZipFile(io.BytesIO(base64.b64decode(self.export(("acme",))["data"]))) as z:
            self.assertIn(b'"tenants":["acme"]', z.read("keys/records.jsonl"))


if __name__ == "__main__":
    unittest.main()
