"""Claims of proof-carrying messages (#436): what a claim says, checked offline against its evidence, records of the
sender's own run under a checkpoint note the pinned log key signed (cosigned by the witnesses trust.json requires),
each with its inclusion proof, and a policy.decision's args opened by its salt.

A claim is proven only by what the signer recorded itself: a person's approval, an observer's effect.observed, or a
tool.result a gateway or executor wrote (T2: the record's own `source` and `tier`, which no client sets). A result the
agent's process reported (T1) is its own word, so a claim that rests on one is unproven."""
import functools
import hmac
import ipaddress
import json
import os
import posixpath
import re
import shlex
import unicodedata
from urllib.parse import unquote

from tracekit import core, merkle
from tracekit.format import checkpoint
from tracekit.format.canon import canonical, event_hash
from tracekit.pcm import CLAIM_ARGS, check_args
from tracekit.policy2 import classes
from tracekit.schema import V2, validate

_RANK = {"proven": 0, "unproven": 1, "failed": 2}
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
_DRIVE = re.compile(r"[A-Za-z]:[\\/]")   # a Windows drive path, the only one read with `\` as `/`
# UTS 46's deviation characters, and capital sharp s, which casefolding makes ss and UTS 46 a sharp s
_DEVIATIONS = re.compile("[\u00df\u03c2\u1e9e\u200c\u200d]")
# Cherokee letters: Nameprep's Unicode 3.2 table has no case pairs for them, Python's codec lower-cases them by its own
_CHEROKEE = re.compile("[\u13a0-\u13f5\u13f8-\u13fd\uab70-\uabbf]")
_C0 = "".join(map(chr, range(0x21)))


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
    """{tool: class}: PCM 0.1's tool placement table, tools.json beside this module (verifier code, never a bundle's
    policy). It froze the tool names the policy packs of tracekit 1.4 mapped, but patterns and names two packs class
    differently, so a pack added or edited since changes no verdict."""
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools.json"), encoding="utf-8") as f:
        return json.load(f)


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
        # lean: PCM 0.1's frozen table; a custom shell or http tool is unproven until a later PCM version places it
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
    if type_ == "file_written":
        path, windows = a["path"], _DRIVE.match(a["path"])
        if ".." in (path.replace("\\", "/") if windows else path).split("/"):   # only what follows it is certain
            return f"{path[:64]} has a `..`: name the file's own path"
        if not (windows or path.startswith("/")):
            return f"{path[:64]} is relative: name the file's absolute path"
    return None


def tests_passed(a, recs):
    return _ran(recs, lambda tool, args: classes.extract("shell", tool, args).get("command") == a["suite"],
                f"ran {a['suite'][:64]!r}", "shell")


def approved_by(a, recs):
    """Proven by the person's approval of call `call` with the approval.request it answers and the policy.decision
    that request names: the call id is the agent's own name for the call, so only the decision says what was approved.
    A proven claim adds {tool, args} of that decision (args None unless the evidence opens it), which the detail shows
    too, the agent's tool name as JSON so it can't spell args."""
    best = ("failed", f"no approval of {a['call']} by the person {a['person']}")
    for e, _ in recs:
        d = e["data"]
        if not (e["type"] == "approval" and d["decision"] == "approve" and d["tool_use_id"] == a["call"]
                and d.get("person") == a["person"] and d.get("approver_kind", "person") == "person"
                and d.get("self_approved") is not True):
            continue
        asked = {x["data"]["decision_id"] for x, _ in recs
                 if x["type"] == "approval.request" and x["data"]["approval_id"] == d.get("approval_id")}
        for x, args in recs:
            c = x["data"]
            if x["type"] == "policy.decision" and c.get("decision_id") in asked and c["tool_use_id"] == a["call"] \
                    and c.get("tool"):
                return "proven", (f"approval seq {e['seq']} by {a['person']} of {canonical(c['tool']).decode()} call "
                                  f"{a['call']}" + ("" if args is None else f" with args {canonical(args).decode()}")), \
                    {"tool": c["tool"], "args": args}
        # failed, not unproven: the sender picks the evidence and can always add both; without them the agent's call
        # id is all that would say what was approved
        best = ("failed", f"approval seq {e['seq']} by {a['person']} of {a['call']}, but the evidence holds no decision "
                          "of the call it approved: add the approval.request it answers and the policy.decision that "
                          "request names")
    return best


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
    if not name or name.endswith(".") or _CHEROKEE.search(name):
        return None
    # lean: IDNA 2003 (the stdlib), not UTS 46; take the idna package if a host they read apart matters
    try:
        label = name.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return label if re.fullmatch(r"[a-z0-9_-]+(\.[a-z0-9_-]+)*", label) else None


def _brackets_ok(url):
    """Whether the authority of `url`, as url_info's urlsplit reads it, passes PCM 0.1's bracket rule: no `[` or `]`,
    or one of each around an IPv6 or IPvFuture address that opens the host after the last `@`, followed by nothing
    or `:`. urlsplit's own check differs between Python releases; every release reads a URL that passes alike."""
    u = re.sub(r"[\t\n\r]", "", classes.with_scheme(url).lstrip(_C0))
    u = u[m.end():] if (m := re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", u)) else u
    auth = re.split(r"[/?#]", u[2:], maxsplit=1)[0] if u.startswith("//") else ""
    if "[" not in auth and "]" not in auth:
        return True
    host = auth.rpartition("@")[2]
    inside, close, after = host[1:].partition("]")
    if (auth.count("["), auth.count("]")) != (1, 1) or host[:1] != "[" or not close or after[:1] not in ("", ":"):
        return False
    try:
        ipaddress.IPv6Address(inside)
    except ValueError:
        return re.fullmatch(r"v[0-9A-Fa-f]+\..+", inside) is not None
    return True


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
            # only a connection opened reaches a host: a kernel sensor's connect is the attempt, and an egress minute
            # with none is a connect that failed (egress._forward) or a later minute of one opened before
            if got == want and d["kind"] == "net" and d["connections"] > 0:
                return "proven", f"effect.observed seq {e['seq']}: {d['observer']} saw the run reach {a['host']}"
            if got is None:
                seen = ("unproven", f"effect.observed seq {e['seq']}: a host the verifier can't read")
            elif got == want:
                seen = ("unproven", f"effect.observed seq {e['seq']}: {d['observer']} saw " + (
                    f"no connection to {a['host']} open" if d["kind"] == "net" else
                    f"the run try to connect to {a['host']}, an attempt"))

    def match(tool, args):
        info = classes.url_info(args["url"]) if isinstance(args.get("url"), str) else {}
        # no URL, or one with no host a browser reads (file:, mailto:, gopher:)
        if "host" not in info and not info.get("internal") or info.get("scheme") not in (*classes.SPECIAL, None):
            return False
        # lean: a deviation character anywhere in the URL, its path too, makes it unproven; read the host alone if a
        # path with one matters
        got = None if info.get("ambiguous") or _deviant(args["url"]) or not _brackets_ok(args["url"]) else \
            _a_label(info)
        return None if got is None else got == want
    return min(_ran(recs, match, f"reached {a['host']}", "http"), seen, key=lambda o: _RANK[o[0]])


def _path(raw, windows):
    """(path, absolute) of a file path as PCM 0.1 compares it, by Windows rules (`\\` and `/` separate; absolute: a
    drive path) or POSIX ones (`/` alone separates, `\\` is part of a name; absolute: from `/`, so `C:/x` is not). An
    absolute path without `..` is normalised as POSIX normpath does; of any other only what follows its last `..`
    is certain, without empty and `.` segments. classes.fs_path, which policy rules match, reads `\\` as `/` always."""
    path = raw.replace("\\", "/") if windows else raw
    parts = path.split("/")
    if (_DRIVE.match(raw) if windows else path.startswith("/")) and ".." not in parts:
        return posixpath.normpath(path), True
    tail = parts[len(parts) - parts[::-1].index(".."):] if ".." in parts else parts
    return "/".join(p for p in tail if p not in ("", ".")), False


def file_written(a, recs):
    windows = bool(_DRIVE.match(a["path"]))   # the claim's rules read the call's path too
    want = _path(a["path"], windows)[0]

    def match(tool, args):   # the op by the tool's name: an `op` in the args is the agent's word
        raw, content = classes.first(args, *classes.PATH_KEYS), args.get("content")
        if not (classes.FS_OPS.get(tool) == "write" and isinstance(raw, str) and isinstance(content, str)
                and "sha256:" + core.sha256_hex(content) == a["digest"]):
            return False
        got, absolute = _path(raw, windows)
        if absolute and got == want:
            # one file on Windows; on POSIX, where `\\` is part of a name and C:/x relative, maybe two: there only the
            # claim's own string is surely its file
            return True if raw == a["path"] or not windows else None
        # a relative path (or what follows a `..`) may be this file, from a working directory the record doesn't hold
        return None if not absolute and ("/" + want).endswith("/" + got) else False
    return _ran(recs, match, f"wrote {a['path'][:64]} with {a['digest']}")


CHECKERS = {"tests_passed": tests_passed, "approved_by": approved_by, "reached_host": reached_host,
            "file_written": file_written}


def check_claim(c, msg, trust):
    """{type, result: proven, unproven or failed, detail} of claim `c` of message `msg`, and for a proven approved_by
    `approved`: {tool, args} of the decision the person approved."""
    errs = check_args({"fields": CLAIM_ARGS[c["type"]]}, c["args"])
    bad, approved = "; ".join(errs) if errs else malformed(c["type"], c["args"]), []
    if bad:
        result, detail = "failed", bad
    elif "evidence" not in c:
        result, detail = "unproven", "no evidence"
    else:
        try:
            result, detail, *approved = CHECKERS[c["type"]](c["args"], evidence(c["evidence"], msg, trust))
        except EvidenceError as e:
            result, detail = "failed", str(e)
    return {"type": c["type"], "result": result, "detail": detail, **({"approved": approved[0]} if approved else {})}
