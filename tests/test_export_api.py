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
import time
import unittest
import zipfile
from unittest import mock

import test_signer_service as ts
from factories import patch_env, signer_without_fsync
from tracekit import cli
from tracekit.bundle_v2 import run_name
from tracekit.format.canon import event_hash
from tracekit.identity.base import CallerIdentity
from tracekit.identity.token import TokenStore
from tracekit.sdk.client import Client
from tracekit.signer import service as svc
from tracekit.signer.quotas import MAX_LINE
from tracekit.signer.rpc_schema import RPCError
from tracekit.verify import v2 as verify_v2

AGENT = ["register_run", "decide", "complete", "model_event", "close_run", "status"]   # an agent's grants: no export_run


class TestExportRun(unittest.TestCase):
    """A signer with two tenants, acme and beta, on its plain-HTTP loopback listener: each tenant's agent token records
    runs, and acme's owner token holds export_run alone."""

    def setUp(self):
        self.d, self.n = ts.tmpdir(self), itertools.count()
        self.tokens = TokenStore(os.path.join(self.d, "tokens.json"))
        self.config = os.path.join(self.d, "signer.yaml")
        with open(self.config, "w") as f:   # JSON is YAML
            json.dump({"data_dir": "data", "grace_s": 0, "fsck_every_s": 0,
                       "limits": {"events_per_s": 1e6, "burst": 10 ** 6},
                       "http": {"listen": "127.0.0.1:0", "insecure_loopback": True, "authenticators": ["token"],
                                "tokens": "tokens.json"},
                       "authorize": {"token:agent-a": AGENT, "token:agent-b": AGENT, "token:owner-a": ["export_run"]}},
                      f)
        cfg = svc.load_config(self.config)
        self.s = svc.open_service(cfg, policy=ts.PAY_ASKS)
        self.addCleanup(self.s.close)
        (srv,) = svc.serve(cfg, self.s)
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.url = f"http://127.0.0.1:{srv.server_address[1]}"
        self.secrets = []

    def token(self, name, tenant):
        """A token file for a new token `name` of `tenant`."""
        path = os.path.join(self.d, f"{name}.token")
        self.secrets.append(self.tokens.add(name, 3600, tenant=tenant))
        with open(path, "w") as f:
            f.write(self.secrets[-1])
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


if __name__ == "__main__":
    unittest.main()
