"""`tracekit demo --server`: the v2 signer end to end in a temp dir, nothing touched outside it.

A dev signer (keys and store in the temp dir, policy: the dev pack) with an in-process test witness that cosigns its
checkpoints. A scripted agent run: `ls` allowed, `sudo rm -rf /` denied and the agent goes on, an unparsable command
held until it is approved. The run is exported, verified against a trust config pinning the log key and the witness,
then a copy whose denied call is rewritten as allowed fails verification.
"""
import os
import shutil
import socket
import tempfile
import threading
import time
import zipfile

from tracekit import crypto
from tracekit.bundle_v2 import export
from tracekit.demo import say
from tracekit.deploy import files
from tracekit.format import checkpoint
from tracekit.sdk.client import Client
from tracekit.signer.service import SignerService, _dev_token
from tracekit.storage.file import FileReader
from tracekit.tlog_witness import log_signed, signed_by
from tracekit.transport import answering_hello, hello
from tracekit.verify import v2

CALLS = [("call-1", "ls"), ("call-2", "sudo rm -rf /"), ("call-3", 'echo "unterminated')]


class Witness:
    """An in-process witness (tracekit.tlog_witness.TlogWitness's interface) that cosigns each note its log signed."""
    # lean: no consistency check against the last cosigned size; a demo only, real witnesses (omniwitness) keep one
    name = "witness.demo.tracekit.local"

    def __init__(self):
        self.secret = os.urandom(32)
        self.vkey = checkpoint.vkey(self.name, checkpoint.COSIGNATURE, crypto.public_from_secret(self.secret))

    def latest(self, empty_note, log_vkey):
        return 0, None

    def add_checkpoint(self, note, log_vkey, old, proof):
        signed = log_signed(note, log_vkey)
        checkpoint.open_note(signed, [log_vkey])   # only notes the log signed
        return checkpoint.cosign(signed.split("\n\n", 1)[0] + "\n", self.name, self.secret, int(time.time()))


def _serve(d, service):
    """The signer's address: a Unix socket, or a loopback port whose token goes to $TRACEKIT_SIGNER_TOKEN."""
    handle = answering_hello(service.handle_frame, hello())
    if hasattr(socket, "AF_UNIX"):
        from tracekit.transport.unix import UnixServer
        path = os.path.join(d, "signer.sock")
        srv = UnixServer(path, handle)
    else:
        from tracekit.transport.tcp_dev import TcpDevServer
        token = _dev_token()
        srv = TcpDevServer(os.path.join(d, "endpoint.json"), token, handle)
        path = f"tcp://127.0.0.1:{srv.server_address[1]}"
        os.environ["TRACEKIT_SIGNER_TOKEN"] = token.secret
    threading.Thread(target=srv.serve_forever, args=(0.2,), daemon=True).start()
    return path, srv


def agent(client):
    """The scripted agent; returns its run id."""
    with client.run(agent="demo-server") as run:
        for call_id, command in CALLS:
            args = {"command": command}
            d = run.decide(call_id, "Bash", args)
            print(f"  Bash {command!r}: {d['decision']} {' '.join(d['rule_ids'])}")
            hint = None
            if d["decision"] == "ask":
                hint = run.call("approval_request", tool_call_id=call_id)["approval_id"]
                a = client.approval_decide({"approval_id": hint, "decision": "approve"})   # `tracekit approvals approve`
                print(f"    approved {hint} (self-approved: {a['self_approved']})")
            if d["decision"] != "deny" and run.approval_consume(call_id, "Bash", args, approval_id_hint=hint)["ok"]:
                run.complete(call_id)   # the pretend command ran
        return run.run_id


def export_final(store, run_id, witness, out, timeout=30):
    """Export the run once the signer has finalised it and the witness cosigned a checkpoint covering it."""
    deadline = time.monotonic() + timeout
    while True:
        reader = FileReader(store)
        size, note = reader.checkpoint_latest() or (0, "")
        *_, last = reader.iter_run("default", run_id)
        if (last["event"]["type"] == "run.final" and size > last["event"]["seq"]
                and signed_by(note.split("\n\n", 1)[1], witness.vkey)):
            break
        if time.monotonic() > deadline:
            raise TimeoutError("no cosigned checkpoint covers the finished run")
        time.sleep(0.2)
    export(reader, "default", run_id, note, out)


def tamper(src, dst):
    """A copy whose denied call is rewritten as allowed."""
    with zipfile.ZipFile(src) as z:
        bundle = {n: z.read(n) for n in z.namelist()}
    name = next(n for n in bundle if n.startswith("runs/"))
    bundle[name] = bundle[name].replace(b'"decision":"deny"', b'"decision":"allow"', 1)
    with zipfile.ZipFile(dst, "w") as z:
        for n, v in bundle.items():
            z.writestr(n, v)


def main(keep=False):
    d = tempfile.mkdtemp(prefix="tk-demo-", dir="/tmp" if os.path.isdir("/tmp") else None)   # macOS caps socket paths
    service = srv = None
    try:
        say(f"setup: dev signer and an in-process test witness in {d}")
        witness = Witness()
        service = SignerService(os.path.join(d, "data"), witnesses=[witness], isolation="same-user", grace_s=0.5,
                                fsck_every_s=0)
        path, srv = _serve(d, service)
        client = Client(path)
        say("agent run (SCRIPTED: fixed tool calls, not a model)")
        run_id = agent(client)
        client.close()
        say("export the run once it is final and a witness cosigned it")
        out, trust = os.path.join(d, "run.tkb"), os.path.join(d, "trust.json")
        export_final(os.path.join(d, "data", "store"), run_id, witness, out)
        files.write_json(trust, {"logs": [service.vkey], "witnesses": [{"vkey": witness.vkey, "class": "customer"}],
                                 "algs": ["ed25519"], "witnesses_required": 1}, 0o644)
        print(f"  wrote {out}\n  trust config {trust}: pins the log key and the witness")
        say("verify offline with the pinned trust config")
        rep, code = v2.verify(out, trust)
        v2.print_report(rep, code)
        say("tamper test: rewrite the denied call as allowed in a copy, then verify again")
        bad = os.path.join(d, "tampered.tkb")
        tamper(out, bad)
        rep2, code2 = v2.verify(bad, trust)
        v2.print_report(rep2, code2)
        print(f"\n  original bundle exit {code}, tampered bundle exit {code2}")
        return 0 if code == 0 and code2 != 0 else 1
    finally:
        if srv:
            srv.shutdown()
            srv.server_close()
        if service:
            service.close()
        if keep:
            print(f"\nkept {d}")
        else:
            shutil.rmtree(d, ignore_errors=True)

