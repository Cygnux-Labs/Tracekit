"""Claims of proof-carrying messages (#436): what a claim says, checked offline against its evidence, records of the
sender's own run under a checkpoint note the pinned log key signed (cosigned by the witnesses trust.json requires),
each with its inclusion proof, and a policy.decision's args opened by its salt.

A claim is proven only by what the signer recorded itself: a person's approval, an observer's effect.observed, or a
tool.result a gateway or executor wrote (T2: the record's own `source` and `tier`, which no client sets). A result the
agent's process reported (T1) is its own word, so a claim that rests on one is unproven."""
import functools
import hmac
import ipaddress
import os
import re
import shlex
import unicodedata
from urllib.parse import unquote

from tracekit import core, merkle, yamlmini
from tracekit.format import checkpoint
from tracekit.format.canon import event_hash
from tracekit.pcm import CLAIM_ARGS, check_args
from tracekit.policy2 import classes
from tracekit.schema import V2, validate

_RANK = {"proven": 0, "unproven": 1, "failed": 2}
PACKS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policy2", "packs")
# PCM 0.1's test runners: the leading words of a suite, its program by its bare name (a strict subset of the test
# runners command_facts knows, without wrappers such as `uv run` or `sudo`), and flags with which a runner runs no
# tests, with the long ones' prefixes (argparse takes `--he` for `--help`)
TEST_RUNNERS = [r.split() for r in (
    "pytest", "py.test", "python -m pytest", "python3 -m pytest", "python -m unittest", "python3 -m unittest", "tox",
    "nox", "nose2", "trial", "behave", "jest", "vitest", "mocha", "ava", "karma", "cucumber", "playwright test",
    "phpunit", "rspec", "ctest", "npm test", "npm run test", "yarn test", "yarn run test", "pnpm test", "pnpm run test",
    "bun test", "go test", "cargo test", "cargo nextest run", "dotnet test", "deno test", "swift test", "mix test",
    "bazel test", "make test", "make check", "mvn test", "mvn verify", "gradle test", "gradle check")]
NO_TESTS, NO_TESTS_LONG = frozenset(("-h", "-V")), ("--help", "--version", "--collect-only")
# what a suite may not hold, so that shlex reads its words as sh does: operators and redirections, expansions and
# escapes ($'\'' quotes apart in shlex and sh), comments, braces, globs and control characters but the tab
_NOT_IN_SUITE = re.compile(r"[;&|()<>$`\\#{}*?\[\]\x00-\x08\x0a-\x1f\x7f]")
_ABSOLUTE = re.compile(r"/|[A-Za-z]:/")   # what fs_path keeps absolute
_DEVIATIONS = re.compile("[\u00df\u03c2\u200c\u200d]")   # UTS 46's deviation characters


class EvidenceError(ValueError):
    pass


def evidence(ev, msg, trust):
    """[(event, its opened args or None)] of evidence item `ev` of message `msg`; EvidenceError when it does not
    verify against trust.json `trust`, holds a record that is no valid v2 event, or comes from another log than the one
    whose key signed `msg`."""
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
            proof = [checkpoint._unb64(p) for p in r["proof"]]   # canonical base64 only (PCM 0.1)
        except ValueError:
            proof = None
        if type(e.get("seq")) is not int or proof is None or not merkle.verify_inclusion(
                e["seq"], size, merkle.leaf_hash(bytes.fromhex(r["hash"][7:])), proof, root):
            raise EvidenceError(f"record {i}: not in the checkpoint")
        # lean: the sender's own run only; accept a parent session's runs when sub-agents' records are needed
        if (e.get("tenant"), e.get("run_id")) != (msg["from"]["tenant"], msg["from"]["run"]):
            raise EvidenceError(f"record {i}: from run {str(e.get('run_id'))[:128]}, not the sender's")
        if errs := validate(e) if e.get("schema_version") == V2 else [f"not a {V2} event"]:
            raise EvidenceError(f"record {i}: not a valid event ({errs[0][:256]})")
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
    T2 result, unproven by the agent's own (T1), by a tool the verifier can't place as class `cls`, or by a call
    `match` can't tell (None)."""
    best = ("failed", f"no call in the evidence {what}")
    for e, args in recs:
        d = e["data"]
        # the two the event schema leaves optional
        m = isinstance(args, dict) and d["decision"] != "deny" and {"tool", "decision_id"} <= d.keys() \
            and match(d["tool"], args)
        if m is None:
            best = min(("unproven", f"the verifier can't tell whether call {d['tool_use_id']} {what}"), best,
                       key=lambda o: _RANK[o[0]])
        if not m:
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


def test_command(suite):
    """Whether `suite` is a PCM 0.1 test command: one line of plain words (in `pytest || true`, `pytest &` or
    `pytest; true` the call's status is not the tests'), a listed runner by its bare name, no flag that runs no
    tests."""
    try:
        words = [] if _NOT_IN_SUITE.search(suite) else shlex.split(suite)
    except ValueError:   # unbalanced quotes
        return False
    return any(words[:len(r)] == r for r in TEST_RUNNERS) and not any(
        w in NO_TESTS or len(w) > 2 and any(f.startswith(w) for f in NO_TESTS_LONG) for w in words)


def malformed(type_, a):
    """Why the args `a` of a claim of `type_`, valid by their table, still say nothing a verifier can check; else
    None. A malformed claim fails with or without evidence."""
    if type_ == "tests_passed" and not test_command(a["suite"]):
        return f"{a['suite'][:64]!r} is not a single test command"
    path = a.get("path", "").replace("\\", "/")
    if type_ == "file_written" and ".." in path.split("/"):   # fs_path keeps only what follows the last `..`
        return f"{a['path'][:64]} has a `..`: name the file's own path"
    if type_ == "file_written" and not _ABSOLUTE.match(path):
        return f"{a['path'][:64]} is relative: name the file's absolute path"
    return None


def tests_passed(a, recs):
    return _ran(recs, lambda tool, args: classes.extract("shell", tool, args).get("command") == a["suite"],
                f"ran {a['suite'][:64]!r}", "shell")


def approved_by(a, recs):
    for e, _ in recs:
        d = e["data"]
        if e["type"] == "approval" and d["decision"] == "approve" and d["tool_use_id"] == a["call"] \
                and d.get("person") == a["person"] and d.get("approver_kind", "person") == "person" \
                and d.get("self_approved") is not True:
            return "proven", f"approval seq {e['seq']} by {a['person']} of {a['call']}"
    return "failed", f"no approval of {a['call']} by the person {a['person']}"


def _deviant(text):
    """Whether `text`, percent-decoded and NFKC-normalised, holds one of the four UTS 46 deviation characters (sharp s,
    final sigma, ZWNJ, ZWJ): IDNA 2003 maps them away (fass.example for the name with a sharp s) where a browser keeps
    them, so a host with one names two hosts."""
    return bool(_DEVIATIONS.search(unicodedata.normalize("NFKC", unquote(text))))


def _a_label(info):
    """The host of classes.url_info's `info` as PCM 0.1 compares hosts: an IPv6 address as url_info writes it, an IPv4
    address or a name without its one trailing dot and in ASCII by Python's `idna` codec, of labels of a-z, 0-9, `_`
    and `-` only; None when it has none or it won't encode."""
    h = info.get("host")
    if h is None:
        return None
    if h.startswith("["):   # url_info writes an IPv6 address so; `[` alone (from %5b) is none
        try:
            return h if h.endswith("]") and ipaddress.IPv6Address(h[1:-1]) else None
        except ValueError:
            return None
    name = h[:-1] if h.endswith(".") else h
    # lean: IDNA 2003 (the stdlib), not UTS 46; take the idna package if a host they read apart matters
    try:
        label = name.encode("idna").decode("ascii") if name and not name.endswith(".") else None
    except UnicodeError:
        return None
    return label if label and re.fullmatch(r"[a-z0-9_-]+(\.[a-z0-9_-]+)*", label) else None


def _host(host):
    """A claim's or an effect's host (a name or address, maybe with a port of 1 to 5 digits) as PCM 0.1 compares
    hosts, None when it won't parse."""
    if not isinstance(host, str) or re.search(r"[/\\?#@\s\[\]]", host) or _deviant(host) \
            or host.count(":") == 1 and not re.fullmatch(r"[^:]*:[0-9]{1,5}", host):
        return None
    return _a_label(classes.url_info(f"http://[{host}]/" if host.count(":") > 1 else f"http://{host}/"))


def reached_host(a, recs):
    want = _host(a["host"])
    if want is None:
        return "unproven", f"{a['host'][:64]} is no host the verifier can read"
    seen = ("failed", "")
    for e, _ in recs:
        d = e["data"]
        if e["type"] == "effect.observed" and d.get("kind") in ("net", "connect") and not d.get("denied"):
            got = _host(d.get("host"))
            if got == want:
                return "proven", f"effect.observed seq {e['seq']}: {d['observer']} saw the run reach {a['host']}"
            if got is None:
                seen = ("unproven", f"effect.observed seq {e['seq']}: a host the verifier can't read")

    def match(tool, args):
        info = classes.url_info(args["url"]) if isinstance(args.get("url"), str) else {}
        # no URL, or one with no host a browser reads (file:, mailto:, gopher:)
        if "host" not in info and not info.get("internal") or info.get("scheme") not in (*classes.SPECIAL, None):
            return False
        # lean: a deviation character anywhere in the URL, its path too, makes it unproven; read the host alone if a
        # path with one matters
        got = None if info.get("ambiguous") or _deviant(args["url"]) else _a_label(info)
        return None if got is None else got == want
    return min(_ran(recs, match, f"reached {a['host']}", "http"), seen, key=lambda o: _RANK[o[0]])


def file_written(a, recs):
    want = classes.fs_path(a["path"])

    def match(tool, args):   # the op by the tool's name: an `op` in the args is the agent's word
        got, content = classes.extract("fs", tool, args).get("path"), args.get("content")
        if not (classes.FS_OPS.get(tool) == "write" and isinstance(got, str) and isinstance(content, str)
                and "sha256:" + core.sha256_hex(content) == a["digest"]):
            return False
        if got == want:
            return True
        # a relative path (or what follows a `..`) may be this file, from a working directory the record doesn't hold
        return None if not _ABSOLUTE.match(got) and ("/" + want).endswith("/" + got) else False
    return _ran(recs, match, f"wrote {a['path'][:64]} with {a['digest']}")


CHECKERS = {"tests_passed": tests_passed, "approved_by": approved_by, "reached_host": reached_host,
            "file_written": file_written}


def check_claim(c, msg, trust):
    """{type, result: proven, unproven or failed, detail} of claim `c` of message `msg`."""
    errs = check_args({"fields": CLAIM_ARGS[c["type"]]}, c["args"])
    bad = "; ".join(errs) if errs else malformed(c["type"], c["args"])
    if bad:
        result, detail = "failed", bad
    elif "evidence" not in c:
        result, detail = "unproven", "no evidence"
    else:
        try:
            result, detail = CHECKERS[c["type"]](c["args"], evidence(c["evidence"], msg, trust))
        except EvidenceError as e:
            result, detail = "failed", str(e)
    return {"type": c["type"], "result": result, "detail": detail}
