"""How much a transfer changed what its receiver answered: the receiver re-run with what was sent and without it.
Experimental, as transfers are (RunHandle.transfer).

    tracekit why transfer --run R --store DIR --receiver MODULE:ATTR [--transfer SEQ]

The transfer is a run's a2a:transfer kept with keep=True (RunHandle.transfer, tracekit.integrations.c2c.fuse). Its
arguments and its payload come from the signer's content vault (content_get, each read a signed content.accessed),
each checked against its record's commitment, and the payload against the size and digest the transfer recorded.
The receiver, the investigator's code, is called twice: with what was sent (a C2C cache rebuilt from its layout, else
the payload's bytes) and with None. It runs where the investigator runs it, unrecorded; make it deterministic (greedy
decoding), since each arm runs once.
"""
import difflib
import hashlib

from ..integrations.c2c import unpack
from ..sdk.client import TRANSFER
from .import_v2 import _calls
from .signed import EvidenceAlert, vault_content


def effect(client, records, receiver, purpose, seq=None):
    """{"seq", "sender", "receiver", "change", "sentence", "with", "without"} for the kept transfer whose decision is
    record `seq` of `records` (one run's; default: its last completed one). `change` is 0 for the same answer up to 1
    for answers with nothing in common (1 - difflib's ratio). ValueError when there is no such transfer or the vault
    holds no copy; EvidenceAlert when the copy is not what the transfer recorded."""
    calls = [c for c in _calls(records).values() if c["decision"]["event"]["data"]["tool"] == TRANSFER
             and "result" in c and seq in (None, c["decision"]["event"]["run_seq"])]
    if not calls:
        raise ValueError("no completed transfer" + (f" at record {seq}" if seq is not None else "") + " in this run")
    want = [calls[-1]["decision"], calls[-1]["result"]]
    seq = want[0]["event"]["run_seq"]
    got = {s: (content, opened) for s, content, opened in vault_content(client, want, purpose)}
    (args, a_ok), (kept, k_ok) = (got.get(r["event"]["run_seq"], (None, False)) for r in want)
    payload = (kept or {}).get("result")
    if not (isinstance(payload, dict) and isinstance(payload.get("payload"), str)):
        raise ValueError(f"transfer {seq}: the vault holds no copy of what was sent: transfer with keep=True to a "
                         "signer with content: {retain: true}")
    if not (a_ok and k_ok):
        raise ValueError(f"transfer {seq}: the vault holds no arguments for it, or redaction changed them or its copy, "
                         "so they open no commitment: nothing to measure")
    data = bytes.fromhex(payload["payload"])
    if len(data) != args.get("size") or "sha256:" + hashlib.sha256(data).hexdigest() != args.get("digest"):
        raise EvidenceAlert(f"transfer {seq}: the copy in the vault is not the size and digest the transfer recorded: "
                            "the sending process recorded one payload and kept another")
    try:
        sent = unpack(data, args["layout"]) if "layout" in args else data
    except (TypeError, ValueError, RuntimeError) as e:   # memoryview's or torch's word on a layout that doesn't fit
        raise ValueError(f"transfer {seq}: its layout does not fit its payload: {e}") from None
    with_, without = str(receiver(sent)), str(receiver(None))
    change = round(1 - difflib.SequenceMatcher(None, without, with_, autojunk=False).ratio(), 3)
    sentence = ("The transfer did not change the receiver's answer." if change == 0 else
                f"The transfer changed the receiver's answer by {change:.0%} (0% is the same answer, 100% shares "
                "nothing with it).")
    return {"seq": seq, "sender": args.get("sender"), "receiver": args.get("receiver"), "change": change,
            "sentence": sentence, "with": with_, "without": without}
