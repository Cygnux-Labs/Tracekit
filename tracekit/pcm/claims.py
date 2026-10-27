"""Claims of proof-carrying messages (#436): what a claim says, checked offline against its evidence, records of the
sender's own run under a checkpoint note the pinned log key signed (cosigned by the witnesses trust.json requires),
each with its inclusion proof, and a policy.decision's args opened by its salt.

A claim is proven only by what the signer recorded itself: a person's approval, an observer's effect.observed, or a
tool.result a gateway or executor wrote (T2: the record's own `source` and `tier`, which no client sets). A result the
agent's process reported (T1) is its own word, so a claim that rests on one is unproven."""
import base64
import functools
import hmac
import os

from tracekit import core, merkle, yamlmini
from tracekit.findings_text import _simple, command_facts
from tracekit.format import checkpoint
from tracekit.format.canon import event_hash
from tracekit.pcm import CLAIM_ARGS, check_args
from tracekit.policy2 import classes

_RANK = {"proven": 0, "unproven": 1, "failed": 2}
PACKS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policy2", "packs")


class EvidenceError(ValueError):
    pass


def evidence(ev, msg, trust):
    """[(event, its opened args or None)] of evidence item `ev` of message `msg`; EvidenceError when it does not
    verify against trust.json `trust` or comes from another log than the one whose key signed `msg`."""
    try:
        origin, size, root, cosigs = checkpoint.open_note(ev["checkpoint"], trust["logs"],
                                                          [w["vkey"] for w in trust.get("witnesses", [])])
    except checkpoint.NoteError as e:
        raise EvidenceError(f"checkpoint: {e}") from None
    if origin != msg["sig"]["key"].rpartition("+")[0]:   # run ids are the client's: unique per log and tenant only
        raise EvidenceError(f"checkpoint: of log {origin[:128]}, not the one that signed the message")
    if len(cosigs) < trust.get("witnesses_required", 0):
        raise EvidenceError(f"checkpoint: {len(cosigs)} pinned cosignature(s), {trust['witnesses_required']} required")
    out = []
    for i, r in enumerate(ev["records"], 1):
        e = r["event"]
        if not isinstance(e, dict) or event_hash(e) != r["hash"]:
            raise EvidenceError(f"record {i}: hash does not match the event")
        try:
            proof = [base64.b64decode(p, validate=True) for p in r["proof"]]
        except ValueError:   # binascii.Error, or a non-ASCII entry
            proof = None
        if type(e.get("seq")) is not int or proof is None or not merkle.verify_inclusion(
                e["seq"], size, merkle.leaf_hash(bytes.fromhex(r["hash"][7:])), proof, root):
            raise EvidenceError(f"record {i}: not in the checkpoint")
        # lean: the sender's own run only; accept a parent session's runs when sub-agents' records are needed
        if (e.get("tenant"), e.get("run_id")) != (msg["from"]["tenant"], msg["from"]["run"]):
            raise EvidenceError(f"record {i}: from run {str(e.get('run_id'))[:128]}, not the sender's")
        args = None
        if "salt" in r or "args" in r:
            d = e["data"]
            digest = event_hash({"tool": d.get("tool"), "args": r.get("args")}).encode()
            if not (e["type"] == "policy.decision" and "salt" in r and "args" in r and "args_commitment" in d
                    and hmac.compare_digest("hmac-sha256:" + hmac.new(bytes.fromhex(r["salt"]), digest, "sha256")
                                            .hexdigest(), d["args_commitment"])):
                raise EvidenceError(f"record {i}: the args do not open its decision's commitment")
            args = r["args"]
        out.append((e, args))
    return out


@functools.lru_cache(maxsize=None)
def placed():
    """{tool: class} of the tool names the policy packs shipped with tracekit map (verifier code, never a bundle's
    policy); a pattern, or a name two packs class differently, is left out."""
    seen = {}
    for name in sorted(os.listdir(PACKS)):
        if name.endswith(".yaml"):
            for tool, cls in (yamlmini.loads(core.read_text(os.path.join(PACKS, name))).get("tools") or {}).items():
                seen.setdefault(tool, set()).add(cls)
    return {tool: cls for tool, (cls, *more) in seen.items() if not more and "*" not in tool}


def _ran(recs, match, what, cls=None):
    """(result, detail) of the claim that a call whose opened args `match(tool, args)` ran and succeeded: proven by a
    T2 result, unproven by the agent's own (T1) or by a tool the verifier can't place as class `cls`."""
    best = ("failed", f"no call in the evidence {what}")
    for e, args in recs:
        d = e["data"]
        if not isinstance(args, dict) or d["decision"] == "deny" or not match(d["tool"], args):
            continue
        # lean: the shipped packs' tools map; a custom shell or http tool is unproven until the verifier takes one
        if cls and placed().get(d["tool"]) != cls:   # a `command` or `url` field alone is not a shell or http call
            got = ("unproven", f"a tool the verifier can't place as a {cls} tool")
            best = min(got, best, key=lambda o: _RANK[o[0]])
            continue
        for x, _ in recs:
            r = x["data"]
            if x["type"] != "tool.result" or (r.get("decision_id"), r["tool_use_id"]) != (d["decision_id"],
                                                                                           d["tool_use_id"]):
                continue
            if r["ok"] is not True:
                got = ("failed", f"call {d['tool_use_id']} {what}, and failed")
            elif (x["source"], x.get("tier")) == ("gateway", "T2"):
                return "proven", f"call {d['tool_use_id']} {what}, run by {r.get('via')} (T2)"
            else:
                got = ("unproven", "the result is the agent's own report (T1)")
            best = min(got, best, key=lambda o: _RANK[o[0]])   # a tie: what a matching call says
    return best


def tests_passed(a, recs):
    # one simple command: in `pytest || true` or `pytest; true` the call's status is not the tests'
    if len(list(_simple(a["suite"]))) != 1 or "test" not in command_facts(a["suite"])[0]:
        return "failed", f"{a['suite'][:64]!r} is not a single test command"
    return _ran(recs, lambda tool, args: classes.extract("shell", tool, args).get("command") == a["suite"],
                f"ran {a['suite'][:64]!r}", "shell")


def approved_by(a, recs):
    for e, _ in recs:
        d = e["data"]
        if e["type"] == "approval" and d["decision"] == "approve" and d["tool_use_id"] == a["call"] \
                and a["person"] in (d.get("person"), d["approver"]) and d.get("approver_kind", "person") == "person" \
                and d.get("self_approved") is not True:
            return "proven", f"approval seq {e['seq']} by {a['person']} of {a['call']}"
    return "failed", f"no approval of {a['call']} by the person {a['person']}"


def reached_host(a, recs):
    for e, _ in recs:
        d = e["data"]
        if e["type"] == "effect.observed" and d.get("host") == a["host"] and d.get("kind") in ("net", "connect") \
                and not d.get("denied"):
            return "proven", f"effect.observed seq {e['seq']}: {d['observer']} saw the run reach {a['host']}"
    return _ran(recs, lambda tool, args: classes.extract("http", tool, args).get("host") == a["host"],
                f"reached {a['host']}", "http")


def file_written(a, recs):
    if ".." in a["path"].replace("\\", "/").split("/"):   # fs_path keeps only what follows the last `..`
        return "failed", f"{a['path'][:64]} has a `..`: name the file's own path"

    def match(tool, args):   # the op by the tool's name: an `op` in the args is the agent's word
        f, content = classes.extract("fs", tool, args), args.get("content")
        return classes.FS_OPS.get(tool) == "write" and f.get("path") == classes.fs_path(a["path"]) \
            and isinstance(content, str) and "sha256:" + core.sha256_hex(content) == a["digest"]
    return _ran(recs, match, f"wrote {a['path'][:64]} with {a['digest']}")


CHECKERS = {"tests_passed": tests_passed, "approved_by": approved_by, "reached_host": reached_host,
            "file_written": file_written}


def check_claim(c, msg, trust):
    """{type, result: proven, unproven or failed, detail} of claim `c` of message `msg`."""
    errs = check_args({"fields": CLAIM_ARGS[c["type"]]}, c["args"])
    if errs:
        result, detail = "failed", "; ".join(errs)
    elif "evidence" not in c:
        result, detail = "unproven", "no evidence"
    else:
        try:
            result, detail = CHECKERS[c["type"]](c["args"], evidence(c["evidence"], msg, trust))
        except EvidenceError as e:
            result, detail = "failed", str(e)
    return {"type": c["type"], "result": result, "detail": detail}
