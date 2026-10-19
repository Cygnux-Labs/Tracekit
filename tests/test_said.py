"""What the model said, as the integrations record it (tracekit.integrations.said): one model_event response per model
message, its calls under the ids they are decided by, a commitment always, the message itself only with the content
vault, and a message that can't be recorded only warns. `recorded` and `vault` serve the framework tests."""
import json
import os
import unittest
import warnings
from unittest import mock

import test_content_vault as tcv
from test_bundle_v2 import LOG_SECRET, ORIGIN, pub
from tracekit import parsers
from tracekit.bundle_v2 import export
from tracekit.format import checkpoint
from tracekit.format.canon import event_hash
from tracekit.integrations import said
from tracekit.signer.rpc_schema import RPCError
from tracekit.storage.file import FileStorage
from tracekit.verify import v2

VAULT = {"content": {"max_record_bytes": 1 << 20}}


def recorded(r):
    """The model_event fields an integration sent through a mock RunHandle `r`."""
    return [c.kwargs for c in r.call.call_args_list if c.args and c.args[0] == "model_event"]


def vault(r, on=True):
    """`r`, a mock RunHandle, answering model_event, with the signer's vault on or off."""
    answer = r.call.side_effect
    r.call.side_effect = lambda m, **f: {} if m == "model_event" else answer(m, **f)
    r.client.status.return_value = VAULT if on else {}
    return r


def failing(r):
    """`r`, a mock RunHandle whose model_event the signer refuses."""
    answer = r.call.side_effect

    def call(m, **f):
        if m == "model_event":
            raise RPCError("run_closed", "r")
        return answer(m, **f)
    r.call.side_effect = call
    return r


def segments(fields):
    """parsers.said over a recorded body: [(kind, form, text, the ids of the calls right after it)]."""
    return [(s["kind"], s["form"], s["text"], s["tools"]) for s in parsers.said("openai:responses", fields["body"])]


class Helper(unittest.TestCase):
    def said(self, items, status=VAULT, **kw):
        sent = []
        said.Said(lambda **f: sent.append(f), lambda: status)(items, **kw)
        return sent

    def test_a_message_is_one_response_its_calls_under_the_decided_ids(self):
        (f,) = self.said([said.thought("read it first", sealed=b"\x01sig"), said.text("Reading a.py."),
                          said.call("call-7", "Read", {"file_path": "a.py"}), said.call("call-8", "Read", '{"x":1}')],
                         model="m-1", provider="anthropic")
        self.assertEqual((f["phase"], f["model"], f["provider"]), ("response", "m-1", "anthropic"))
        self.assertEqual([(t["id"], t["args_digest"]) for t in f["tool_uses"]],
                         [("call-7", event_hash({"tool": "Read", "args": {"file_path": "a.py"}})),
                          ("call-8", event_hash({"tool": "Read", "args": {"x": 1}}))])
        self.assertEqual(f["content_digest"], event_hash(f["body"]))
        self.assertEqual(segments(f), [("reasoning", "summary", "read it first", []),
                                       ("text", "full", "Reading a.py.", ["call-7", "call-8"])])
        self.assertEqual(f["body"]["output"][0]["encrypted_content"], "AXNpZw==")   # the sealed form, kept

    def test_the_forms_full_summary_sealed_and_withheld(self):
        (f,) = self.said([said.thought("all of it", full=True), said.thought(sealed="ENC"), said.thought(),
                          *said.text("<think>step by step</think>The answer."), said.call(None, "t", {})])
        self.assertEqual([s[:3] for s in segments(f)], [
            ("reasoning", "full", "all of it"), ("reasoning", "encrypted", ""), ("reasoning", "withheld", ""),
            ("reasoning", "full", "step by step"), ("text", "full", "The answer.")])
        self.assertTrue(f["tool_uses"][0]["id_synthetic"])   # no id: paired by its arguments only

    def test_the_body_goes_only_with_the_vault(self):
        (f,) = self.said([said.text("hi")], status={})
        self.assertNotIn("body", f)
        self.assertIn("content_digest", f)
        (f,) = self.said([said.text("hi")], status={"content": {"max_record_bytes": 10}})   # too large for it
        self.assertNotIn("body", f)

    def test_an_empty_message_is_not_sent(self):
        self.assertEqual(self.said([None, said.text(""), *said.text("  ")]), [])

    def test_a_message_that_cant_be_recorded_only_warns(self):
        def bad():
            yield said.text("ok")
            raise AttributeError("a framework type that changed")
        for items, send in ((bad(), lambda **f: None), ([said.text("ok")], mock.Mock(side_effect=RPCError("run_closed", "r")))):
            with self.subTest(send=send), self.assertWarnsRegex(UserWarning, "what the model said was not recorded"):
                said.Said(send, lambda: {})(items)


class OnTheSigner(tcv.Vault):
    """On a real signer: the record commits to the message, the vault opens that commitment, and the run's bundle
    verifies."""

    def send(self, **f):
        return self.s.model_event(self.req(**f))

    def test_the_vault_opens_the_commitment_and_the_bundle_verifies(self):
        msg = [said.thought("check the balance first", sealed="sig-1"), said.text("Paying."),
               said.call("call-1", "pay", {"to": "acct-42"})]
        said.Said(self.send, lambda: self.s.status({}))(msg, model="m", provider="openai")
        (e,) = [e for e in self.records() if e["type"] == "model.exchange"]
        self.assertEqual([t["id"] for t in e["data"]["tool_uses"]], ["call-1"])
        (item,) = self.get(e["run_seq"])
        self.assertEqual(segments({"body": item["content"]})[0][:3], ("reasoning", "summary", "check the balance first"))
        self.opens(item, event_hash(item["content"]), e)
        self.s.close()
        trust = os.path.join(self.dir, "trust.json")
        with open(trust, "w") as f:
            json.dump({"logs": [checkpoint.vkey(ORIGIN, checkpoint.ED25519, pub(LOG_SECRET))], "algs": ["ed25519"]}, f)
        store = FileStorage(os.path.join(self.dir, "store"))
        try:
            text = checkpoint.body(ORIGIN, store.tree.size, store.tree.root())
            out = os.path.join(self.dir, "b.tkb")
            export(store, self.run["tenant"], self.run["run_id"], text + "\n" + checkpoint.sign(text, ORIGIN, LOG_SECRET),
                   out)
        finally:
            store.close()
        self.assertEqual(v2.verify(out, trust)[1], 0)
        self.assertNotIn(b"check the balance first", b"".join(v2.read_zip(out).values()))


class OffTheVault(OnTheSigner):
    content = None

    def test_the_vault_opens_the_commitment_and_the_bundle_verifies(self):
        with warnings.catch_warnings():
            warnings.filterwarnings("error", "tracekit")
            said.Said(self.send, lambda: self.s.status({}))([said.text("hidden words")])
        (e,) = [e for e in self.records() if e["type"] == "model.exchange"]
        self.assertTrue(e["data"]["content_digest"].startswith("hmac-sha256:"))
        with open(os.path.join(self.dir, "store", "records.jsonl")) as f:
            self.assertNotIn("hidden words", f.read())
