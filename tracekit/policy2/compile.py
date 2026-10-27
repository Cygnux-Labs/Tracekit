"""Policy v2 compiler: YAML or JSON in, canonical JSON and a policy_hash out.

Patterns are limited to a syntax that RE2 and the `regex` module (ASCII mode, after `translate`) match the same way,
so a decision does not depend on which engine made it. `build` returns every lint error at once.
"""
import hashlib
import itertools
import json
import ntpath
import os
import posixpath
import re

from .. import yamlmini
from ..policy import PolicyError, _sre_c, _sre_p, check_regex
from ..wiki import wiki_url

SECTIONS = ("deny", "ask", "flag")
DETECT = ("sequences", "limits", "respond")   # signer-side detection (signer/detect.py), merged by id like rules
TOP_KEYS = {"version", "description", "extends", "tools", "untrusted", "handoffs", "structured_output", "unknown_tools",
            "explains", "on_parse_error", *SECTIONS, *DETECT}
RULE_KEYS = {"id", "class", "tool", "field", "pattern", "unless", "reason", "rationale", "label", "approval", "from",
             "remedy"}
MAX_REMEDY = 200   # characters: one sentence the agent and the person read with the decision
# the rule ids the engine and the signer give a decision themselves (and TK-APPROVAL-*): a rule can't pass for one
RESERVED_IDS = {"TK-UNKNOWN-TOOL", "TK-SQL-PARSE", "TK-SHELL-PARSE", "TK-OVERSIZE", "TK-ENGINE-ERROR", "TK-ARGS-INVALID",
                "TK-CONSTRAINT", "TK-HOLD", "TK-QUARANTINE", "TK-LIMIT-SUM", "TK-APPROVED"}
# a remedy says what to do, in the present tense: not what one might, could or should do
_HEDGE = re.compile(r"(?i)\b(please|should|would|could|might|maybe|perhaps|consider|try to)\b")
# an ask rule's `approval`: executor t2 runs only the signer's copy; passkey required: approving needs a passkey;
# agent: a reviewer agent may answer calls within its bounds (_lint_agent)
APPROVAL = {"executor": ("t1", "t2"), "passkey": ("required",)}
SCOPES = ("run", "session", "owner", "principal")
MAX_WINDOW = 86400   # seconds
MAX_STEPS = 64       # an incident cites at most 64 records: one per step
MAX_DETECT = 1024    # sequences and limits together: a decision's `detect` lists at most 1024
MAX_DENIED = 1000    # denied_calls `max`: the calls a scope remembers in its window
TRIGGERS = ("executed_against_policy", "denied_calls", "provenance", "class_mismatch", "refusal_burst", "tamper",
            "unexplained_effect")
NOTIFY_ONLY = ("class_mismatch", "refusal_burst", "tamper")   # never enforced, whatever `respond` says
MODES, ACTIONS = ("off", "shadow", "enforce"), ("notify", "hold", "quarantine")
SEQ_KEYS = {"id", "steps", "scope", "window", "unless"}
LIMIT_KEYS = {"id", "match", "count", "sum", "max", "window", "scope"}
RESPOND_KEYS = {"trigger", "mode", "action", "cooldown_s", "suspend"}   # `suspend` only to refuse it by name
RESPOND_MORE = {"denied_calls": {"max", "window", "scope"}, "refusal_burst": {"max"}}   # the triggers that read more
AGENT_KEYS, BOUND_KEYS, BUDGET_KEYS = {"mode", "allow", "budget", "veto_s"}, {"type", "min", "max", "enum", "pattern"}, \
    {"count", "sum", "window", "scope"}
BOUND_TYPES = {"integer": int, "string": str, "boolean": bool}
MAX_WINDOW_S = 30 * 86400   # a budget's longest window: the signer keeps agent approvals this long
# every class also has `target`: what the call acts on (engine.Engine._targets), so one rule without a class can match it
CLASSES = {"shell": {"command", "argv", "line", "code", "effects", "package_index", "container_host_access"},
           "fs": {"path", "op", "content_digest"},
           "http": {"method", "url", "host", "internal", "sends_to"}, "sql": {"statement", "code", "verb", "db"},
           "payment": {"amount", "currency", "payee", "new_payee", "payees"},
           "email": {"to", "domains", "attachments", "recipients"}, "mcp": {"server", "tool", "args"},
           "browser": {"action", "url", "scheme", "host", "internal", "sends_to"}, "app": set(), "unknown": set()}
for _fields in CLASSES.values():
    _fields.add("target")
MAX_REPEAT = 1000   # RE2's limit for {n,m}
WS = "\\t\\n\\f\\r "   # RE2's \s; Python's also has \v
_ESCAPES = set("dDwWsSbBAntrfv")
_CLASS_ESCAPES = set("dDwWsntrfv")
_OPS = {_sre_c.LITERAL, _sre_c.NOT_LITERAL, _sre_c.ANY, _sre_c.IN, _sre_c.BRANCH, _sre_c.SUBPATTERN,
        _sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT, _sre_c.AT}
_ATS = {_sre_c.AT_BEGINNING, _sre_c.AT_END, _sre_c.AT_BOUNDARY, _sre_c.AT_NON_BOUNDARY, _sre_c.AT_BEGINNING_STRING}


def canonical(pol):
    # lean: plain sorted-key JSON; switch to tracekit.format.canon (JCS) once it lands on main
    return json.dumps(pol, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def policy_hash(pol):
    return "sha256:" + hashlib.sha256(canonical(pol).encode("utf-8")).hexdigest()


def translate(pattern):
    """Check the lexical subset and return the pattern for the `regex` module: `$` means end of text and `\\s`
    excludes \\v, as in RE2. Raises PolicyError for syntax RE2 lacks or reads differently."""
    out, i, n, cls = [], 0, len(pattern), None
    while i < n:
        c = pattern[i]
        if c == "\\":
            e = pattern[i + 1:i + 2]
            if e == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", pattern[i + 2:i + 4]):
                out.append(pattern[i:i + 4])
                i += 4
                continue
            if not e or (e.isalnum() and e not in (_CLASS_ESCAPES if cls is not None else _ESCAPES)) or not e.isascii():
                raise PolicyError(f"escape \\{e} is outside the RE2 subset")
            out.append({"s": WS if cls is not None else f"[{WS}]", "S": f"[^{WS}]"}.get(e, pattern[i:i + 2]))
            i += 2
            continue
        if cls is not None:
            if c == "[":
                raise PolicyError("nested sets and [: :] classes are outside the RE2 subset; escape a literal [")
            if c == "]" and i > cls:
                cls = None
        elif c == "[":
            cls = i + 1 + (pattern[i + 1:i + 2] == "^")   # a ] right after [ or [^ is literal
            out.append(pattern[i:cls])
            i = cls
            continue
        elif c == "(" and pattern.startswith("(?", i) and not pattern.startswith(("(?:", "(?P<"), i):
            raise PolicyError("only (?: and (?P< groups are allowed (no flags, lookaround or comments)")
        elif c == "{" and not re.match(r"\{\d+(,\d*)?\}", pattern[i:]):
            raise PolicyError("a literal { must be escaped, and a repeat needs a lower bound")
        elif c == "$":
            c = "\\Z"
        out.append(c)
        i += 1
    return "".join(out)


def _walk(items, room=MAX_REPEAT):
    """`room`: what RE2 still allows a nested repeat count (the product of nested counts is at most MAX_REPEAT)."""
    for op, av in items:
        if op not in _OPS or (op == _sre_c.AT and av not in _ATS):
            raise PolicyError("lookaround, backreferences, atomic groups, possessive repeats and \\Z are outside the RE2 subset")
        if op in (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT):
            count = av[0] if av[1] == _sre_c.MAXREPEAT else av[1]
            if count > room:
                raise PolicyError(f"repeat counts above {MAX_REPEAT}, nested ones multiplied, are outside the RE2 subset")
            _walk(av[2], room // max(count, 1))
        elif op == _sre_c.SUBPATTERN:
            _walk(av[-1], room)
        elif op == _sre_c.BRANCH:
            for b in av[1]:
                _walk(b, room)


def check_pattern(pattern):
    """Raise PolicyError unless the pattern is in the RE2 subset and has no super-linear nested repeat."""
    translate(pattern)
    try:
        check_regex(pattern)
    except re.error as e:
        raise PolicyError(f"bad regex: {e}") from e
    _walk(_sre_p.parse(pattern))


MAX_EXACT = 64   # strings an exact set of the literal walk may hold before it gives up on exactness


def literals(pattern):
    """The prefilter of a checked pattern: a tuple of lower-case ASCII strings of two or more characters, one of which
    is in the lower-cased text of every match (so a subject holding none of them can't match), or None when the
    pattern has no such set. Case variants fold (`[Mm][Ee]` is "me"); a class of more than eight characters, an
    optional or repeated part and any non-ASCII character end a literal run. A string holding another of the set is
    left out: the shorter one is in every subject the longer one is."""
    exact, req = _seq(_sre_p.parse(pattern))
    req = exact if exact is not None else req
    if not req or min(map(len, req)) < 2:
        return None
    return tuple(sorted(s for s in req if not any(t != s and t in s for t in req)))


def _seq(items):
    """(exact, required) of a sequence: every string it can match when that set is small (else None), and a set one of
    which every match contains (None: no such set)."""
    run, found, exact = {""}, [], True
    for op, av in items:
        ex, req = _node(op, av)
        prod = {a + b for a in run for b in ex} if ex is not None else None
        if prod is not None and len(prod) <= MAX_EXACT:
            run = prod
            continue
        exact = False
        found.append(run)
        run = set(ex) if ex is not None else {""}
        if req is not None:
            found.append(req)
    if exact:
        return frozenset(run), None
    found.append(run)
    return None, max(found, key=lambda s: (min(map(len, s)), -len(s)))


def _node(op, av):
    if op == _sre_c.LITERAL:
        return ({chr(av).lower()}, None) if av < 128 else (None, None)
    if op == _sre_c.AT:
        return {""}, None
    if op == _sre_c.IN:
        chars = set()
        for kind, v in av:
            if kind == _sre_c.LITERAL and v < 128:
                chars.add(chr(v).lower())
            elif kind == _sre_c.RANGE and v[1] < 128 and v[1] - v[0] < 26:
                chars.update(chr(c).lower() for c in range(v[0], v[1] + 1))
            else:   # NEGATE, a category (\d, \s, \w), a wide range or a non-ASCII character
                return None, None
        return (chars, None) if len(chars) <= 8 else (None, None)
    if op == _sre_c.SUBPATTERN:
        return _seq(av[-1])
    if op == _sre_c.BRANCH:
        parts = [_seq(b) for b in av[1]]
        if all(ex is not None for ex, _ in parts) and len(set().union(*(ex for ex, _ in parts))) <= MAX_EXACT:
            return set().union(*(ex for ex, _ in parts)), None
        reqs = [ex if ex is not None else req for ex, req in parts]
        return None, (None if any(r is None or "" in r for r in reqs) else set().union(*reqs))
    if op in (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT):
        lo, hi, items = av
        ex, req = _seq(items)
        if ex is not None and hi <= 2:   # x? and x{1,2}: their exact strings
            out = {""} if lo == 0 else set()
            for k in range(max(lo, 1), hi + 1):
                out |= {"".join(p) for p in itertools.product(ex, repeat=k)}
            if len(out) <= MAX_EXACT:
                return out, None
        if lo == 0:
            return None, None
        return None, (ex if ex is not None else req)
    return None, None   # ANY, NOT_LITERAL


def _read(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    # always the built-in subset, never PyYAML: a policy must mean the same on every signer (PyYAML would keep the last
    # of two duplicate keys and expand anchors and merge keys the subset rejects)
    return yamlmini.loads(text) if path.endswith((".yaml", ".yml")) else json.loads(text)


def build(path, seen=()):
    """Return (effective_policy, errors). `extends` names a relative file, or a list of them merged in order; the
    result records each parent's policy_hash."""
    try:
        pol = _read(path)
    except Exception as e:   # OSError, JSON or YAML syntax: all reported as lint errors
        return {}, [f"{path}: {e}"]
    if not isinstance(pol, dict):
        return {}, [f"{path}: not a mapping"]
    errors = [f"{path}: unknown key {k!r}" for k in sorted(set(pol) - TOP_KEYS)]
    for sec in SECTIONS + DETECT:
        if not isinstance(pol.get(sec, []), list):
            errors.append(f"{path}: {sec} must be a list")
            pol[sec] = []
    if not isinstance(pol.get("tools", {}), dict):
        errors.append(f"{path}: tools must map tool names to classes")
        pol["tools"] = {}
    if not (isinstance(pol.get("untrusted", []), list) and all(isinstance(u, str) for u in pol.get("untrusted", []))):
        errors.append(f"{path}: untrusted must list tool classes and tool name globs")
        pol["untrusted"] = []
    for key in ("handoffs", "structured_output"):   # tool names reconciliation reads in its own way
        if not (isinstance(pol.get(key, []), list) and all(isinstance(h, str) for h in pol.get(key, []))):
            errors.append(f"{path}: {key} must list tool name globs")
            pol[key] = []
        for h in pol.get(key, []):
            if len(re.sub(r"\[[^]]*\]|[*?]", "", h)) < 3:   # a glob this loose names any tool
                errors.append(f"{path}: {key} entry {h!r} is too loose: name the tools exactly")
    explains = pol.get("explains", [])
    if not (isinstance(explains, list) and all(
            isinstance(x, dict) and len(set(x) & {"tool", "label"}) == 1 and set(x) <= {"tool", "label", "hosts"}
            and isinstance(x.get("tool", x.get("label")), str) and isinstance(x.get("hosts"), list) and x["hosts"]
            and all(isinstance(h, str) and h for h in x["hosts"]) for x in explains)):
        errors.append(f"{path}: explains must list {{tool or label, hosts: [host globs]}}: the hosts a tool's own "
                      f"dependencies reach ({wiki_url('docs/egress.md', 'explains')})")
        pol["explains"] = []
    base = pol.pop("extends", None)
    parents = []
    for b in base if isinstance(base, list) else [] if base is None else [base]:
        if not isinstance(b, str) or posixpath.isabs(b) or ntpath.isabs(b) or b.startswith("~"):
            errors.append(f"{path}: extends must be a relative path; the compiled policy names the parent by hash")
        elif os.path.realpath(os.path.join(os.path.dirname(path), b)) in seen + (os.path.realpath(path),):
            errors.append(f"{path}: extends loop at {b}")
        else:
            parent, perr = build(os.path.join(os.path.dirname(path), b), seen + (os.path.realpath(path),))
            errors += perr
            parents.append(parent)
    if parents:
        own = {r.get("id") for sec in SECTIONS for r in pol.get(sec, []) if isinstance(r, dict)}
        merged = {k: v for p in parents for k, v in p.items() if k not in SECTIONS + ("extends",)}
        merged.update({k: v for k, v in pol.items() if k not in SECTIONS})
        merged["tools"] = {k: v for p in parents + [pol] for k, v in p.get("tools", {}).items()}
        untrusted = list(dict.fromkeys(u for p in parents + [pol] for u in p.get("untrusted", [])))
        if untrusted:
            merged["untrusted"] = untrusted
        explains = [x for p in parents + [pol] for x in p.get("explains", [])]
        if explains:
            merged["explains"] = [x for i, x in enumerate(explains) if x not in explains[:i]]
        for key in ("handoffs", "structured_output"):
            if any(key in p for p in parents + [pol]):
                merged[key] = list(dict.fromkeys(h for p in parents + [pol] for h in p.get(key, [])))
        for sec in SECTIONS:
            rules = [r for p in parents for r in p.get(sec, []) if isinstance(r, dict) and r.get("id") not in own]
            # a rule two parents both carry (TK-P003 in server-net and browser) is kept once
            merged[sec] = [r for i, r in enumerate(rules) if r not in rules[:i]] + pol.get(sec, [])
        for sec in DETECT:   # by id (respond: by trigger): a deployment adds a sequence and keeps the pack's
            mine = {item_id(x) for x in pol.get(sec, [])}
            items = [x for p in parents for x in p.get(sec, []) if item_id(x) not in mine]
            items = [x for i, x in enumerate(items) if x not in items[:i]] + pol.get(sec, [])
            if items:
                merged[sec] = items
        merged["extends"] = [policy_hash(p) for p in parents] if isinstance(base, list) else policy_hash(parents[0])
        pol = merged
    return pol, errors + _lint(pol, path)


def item_id(x):
    """The id a detection entry is merged and named by: a respond entry's trigger, anything else's id."""
    return x.get("trigger" if "trigger" in x else "id") if isinstance(x, dict) else None


def _lint(pol, path):
    errors, ids = [], set()
    tools = pol.get("tools", {})
    for tool, cls in tools.items():
        if cls not in CLASSES:
            errors.append(f"{path}: tool {tool!r} has unknown class {cls!r}")
    if pol.get("unknown_tools", "allow") not in SECTIONS + ("allow",):
        errors.append(f"{path}: unknown_tools must be allow, flag, ask or deny")
    if pol.get("on_parse_error", "ask") not in ("ask", "deny"):
        errors.append(f"{path}: on_parse_error must be ask or deny")
    for sec in SECTIONS:
        for r in pol.get(sec, []):
            if not isinstance(r, dict) or not isinstance(r.get("id"), str) or not isinstance(r.get("pattern"), str):
                errors.append(f"{path}: {sec} rule needs a string id and pattern: {r!r}")
                continue
            where = f"{path}: {sec} rule {r['id']}"
            errors += [f"{where}: unknown key {k!r}" for k in sorted(set(r) - RULE_KEYS)]
            errors += [f"{where}: {k} must be a string" for k in sorted(set(r) & RULE_KEYS - {"approval"})
                       if not isinstance(r[k], str)]
            if r.get("from", "untrusted") != "untrusted":
                errors.append(f"{where}: from must be untrusted")
            if isinstance(r.get("remedy"), str):
                errors += [f"{where}: remedy {e}" for e in _lint_remedy(r["remedy"], sec)]
            if "approval" in r and (sec != "ask" or not isinstance(r["approval"], dict) or not r["approval"]
                                    or any(v not in APPROVAL.get(k, ()) for k, v in r["approval"].items()
                                           if k != "agent")):
                errors.append(f"{where}: approval must be {{executor?: t1|t2, passkey?: required, agent?}}, on an ask "
                              "rule")
            elif "agent" in r.get("approval", {}):
                errors += [f"{where}: approval.agent: {e}" for e in _lint_agent(r)]
            if r["id"] in ids:
                errors.append(f"{where}: duplicate id")
            if r["id"] in RESERVED_IDS or r["id"].startswith("TK-APPROVAL-"):
                errors.append(f"{where}: the engine or the signer gives a decision this id itself; name the rule "
                              "another way")
            ids.add(r["id"])
            for key in ("pattern", "unless", "tool"):
                try:
                    if isinstance(r.get(key), str):
                        check_pattern(r[key])
                        if key == "unless" and all(re.search(translate(r[key]), s, re.ASCII) for s in ("", "\0\n")):
                            errors.append(f"{where}: can never fire: unless matches every subject")
                except PolicyError as e:
                    errors.append(f"{where}: {key}: {e}")
            cls, field = r.get("class"), r.get("field")
            if cls is not None and cls not in CLASSES:
                errors.append(f"{where}: unknown class {cls!r}")
            elif cls is not None and field is not None and field not in CLASSES[cls]:
                errors.append(f"{where}: can never fire: class {cls} has no field {field!r}")
            elif cls not in (None, "unknown") and cls not in tools.values():
                errors.append(f"{where}: can never fire: no tool maps to class {cls}")
    labels = {r.get("label") for sec in SECTIONS for r in pol.get(sec, []) if isinstance(r, dict)}
    for x in pol.get("explains", []):
        if "label" in x and x["label"] not in labels:
            errors.append(f"{path}: explains {x['label']!r}: no rule has this label")
        errors += [f"{path}: explains host {h!r} is too loose: after its last wildcard it needs a dot and two or more "
                   "labels (*.pythonhosted.org, not *.com or *pypi.org); or name the hosts" for h in x["hosts"]
                   if _loose_host(h)]
    return errors + _lint_detect(pol, path)


def _lint_remedy(text, sec):
    """The errors of a rule's `remedy`: on a deny or ask rule, one plain sentence of at most MAX_REMEDY characters
    that says what to do, in the present tense."""
    return [e for bad, e in (
        (sec == "flag", "is for a deny or ask rule: a flagged call runs"),
        (len(text) > MAX_REMEDY, f"is over {MAX_REMEDY} characters: say what to do in one sentence"),
        (not re.fullmatch(r"[A-Z][^\x00-\x1f\x7f]*\.", text), "is one line that starts with a capital letter and ends "
                                                             "with a period"),
        (bool(_HEDGE.search(text)), "says what to do, in the present tense (`Push without --force.`), not what one "
                                    "should, could or might do")) if bad]


def _loose_host(glob):
    """Whether host glob `glob` is too loose: not an exact host, nor a dot and two or more labels after its last
    wildcard."""
    if not re.search(r"[*?[]", glob):
        return False
    tail = re.split(r"[*?\]]", glob)[-1]
    labels = tail.split(".")[1:]
    return not tail.startswith(".") or len(labels) < 2 or "" in labels


def _int(v, lo=0, hi=float("inf")):
    return type(v) is int and lo <= v <= hi


def _lint_detect(pol, path):
    """Errors of the sequences, limits and respond sections. A step or limit names a rule id, a rule's label or `*`
    (every call); it counts only allowed calls and consumed approvals, so a name only deny rules carry never counts."""
    rules = [r for sec in SECTIONS for r in pol.get(sec, []) if isinstance(r, dict) and isinstance(r.get("id"), str)]
    known = {"*"} | {r["id"] for r in rules} | {r["label"] for r in rules if isinstance(r.get("label"), str)}
    live = {"*"} | {n for sec in ("ask", "flag") for r in pol.get(sec, []) if isinstance(r, dict)
                    for n in (r.get("id"), r.get("label"))}
    errors, ids = [], set()
    if (pol.get("sequences") or pol.get("limits")) and pol.get("unknown_tools", "allow") == "allow":
        errors.append(f"{path}: sequences and limits need unknown_tools flag, ask or deny: an unmapped tool's calls "
                      "would count for nothing")
    if len(pol.get("sequences", [])) + len(pol.get("limits", [])) > MAX_DETECT:
        errors.append(f"{path}: at most {MAX_DETECT} sequences and limits together")

    def name(where, n):
        if not isinstance(n, str):
            errors.append(f"{where}: {n!r} is not a rule id or label")
        elif n in pol.get("tools", {}) and n not in known:
            errors.append(f"{where}: {n!r} is a raw tool name; name a rule id or label (the signer's reading of the "
                          "call), which an alias can't dodge")
        elif n not in known:
            errors.append(f"{where}: unknown rule id or label {n!r}")
        elif n not in live:
            errors.append(f"{where}: {n!r} can never count: only deny rules carry it, and a denied call never counts")

    def common(where, x, keys, required):
        errors.extend(f"{where}: unknown key {k!r}" for k in sorted(set(x) - keys))
        errors.extend(f"{where}: needs {k}" for k in required if k not in x)
        if "window" in x and not _int(x["window"], 1, MAX_WINDOW):
            errors.append(f"{where}: window must be whole seconds from 1 to {MAX_WINDOW}")
        if x.get("scope", "run") not in SCOPES:
            errors.append(f"{where}: scope must be one of {', '.join(SCOPES)}")
        if "max" in x and not _int(x["max"], 1, 2 ** 53 - 1):
            errors.append(f"{where}: max must be a positive integer")

    for sec, keys in (("sequences", SEQ_KEYS), ("limits", LIMIT_KEYS)):
        for x in pol.get(sec, []):
            if not isinstance(x, dict) or not isinstance(x.get("id"), str):
                errors.append(f"{path}: {sec} entry needs a string id: {x!r}")
                continue
            where = f"{path}: {sec} {x['id']}"
            if x["id"] in ids or x["id"] in TRIGGERS:
                errors.append(f"{where}: duplicate id (sequences, limits and built-in triggers share names)")
            ids.add(x["id"])
            common(where, x, keys, ("steps", "window") if sec == "sequences" else ("match", "max", "window"))
            if sec == "sequences":
                steps, unless = x.get("steps"), x.get("unless", [])
                if not isinstance(steps, list) or not steps or len(steps) > MAX_STEPS:
                    errors.append(f"{where}: steps must be a list of 1 to {MAX_STEPS} rule ids or labels")
                for n in steps if isinstance(steps, list) else []:
                    name(f"{where}: step", n)
                if not isinstance(unless, list) or not all(isinstance(n, str) and n in known for n in unless):
                    errors.append(f"{where}: unless must list rule ids or labels of this policy")
                continue
            if "match" in x:
                name(f"{where}: match", x["match"])
            s = x.get("sum")
            if ("count" in x) == ("sum" in x) or "count" in x and x["count"] is not True:
                errors.append(f"{where}: needs `count: true` or `sum: {{field, currency_field}}`, not both")
            elif s is not None and not (isinstance(s, dict) and set(s) == {"field", "currency_field"}
                                        and all(isinstance(v, str) for v in s.values())):
                errors.append(f"{where}: sum must be {{field, currency_field}}: argument names, in minor units")
            elif s is not None and x.get("match") == "*":
                errors.append(f"{where}: a sum limit must match a rule id or label, not *: every other call would be "
                              "held for an amount it doesn't have")
    triggers = set()
    for x in pol.get("respond", []):
        if not isinstance(x, dict) or not isinstance(x.get("trigger"), str):
            errors.append(f"{path}: respond entry needs a string trigger: {x!r}")
            continue
        t, where = x["trigger"], f"{path}: respond {x['trigger']}"
        if t in triggers:
            errors.append(f"{where}: duplicate trigger")
        triggers.add(t)
        more, extra = RESPOND_MORE.get(t, set()), set().union(*RESPOND_MORE.values())
        common(where, x, RESPOND_KEYS | extra, ("mode", "action") + (("max",) if "max" in more else ()))
        errors.extend(f"{where}: {t} doesn't read {k!r}: only denied_calls takes max, window and scope, and "
                      "refusal_burst max" for k in sorted(set(x) & extra - more))
        if t not in ids and t not in TRIGGERS:
            errors.append(f"{where}: trigger must be a sequence or limit id or one of {', '.join(TRIGGERS)}")
        if x.get("mode") not in MODES or x.get("action") not in ACTIONS:
            errors.append(f"{where}: mode must be {'|'.join(MODES)} and action {'|'.join(ACTIONS)}")
        if t in NOTIFY_ONLY and (x.get("action") != "notify" or x.get("mode") == "enforce"):
            errors.append(f"{where}: {t} is notify-only: it is never enforced; use mode shadow (or off) and action "
                          "notify")
        if t == "denied_calls" and "window" not in x:
            errors.append(f"{where}: needs window")
        if t == "denied_calls" and _int(x.get("max"), MAX_DENIED + 1, 2 ** 53):
            errors.append(f"{where}: max must be at most {MAX_DENIED}")
        if "cooldown_s" in x and not _int(x["cooldown_s"], 0, MAX_WINDOW):
            errors.append(f"{where}: cooldown_s must be whole seconds from 0 to {MAX_WINDOW}")
        if "suspend" in x:
            errors.append(f"{where}: suspend is an operator's action, never a trigger's: content the agent reads can "
                          "steer every trigger, and the run's owner may be an identity other runs share (tracekit "
                          "signer incidents suspend)")
    return errors


def _lint_agent(rule):
    """The errors of an ask rule's approval.agent: {mode, allow: {fields: {NAME: {type, min?, max?, enum?, pattern?}}},
    budget?: {count?, sum?: {field, max}, window, scope}, veto_s?}."""
    a, errors = rule["approval"]["agent"], []
    if not isinstance(a, dict) or not set(a) <= AGENT_KEYS:
        return [f"takes {sorted(AGENT_KEYS)}"]
    if a.get("mode") not in ("shadow", "enforce"):
        errors.append("mode must be shadow or enforce")
    if rule["approval"].get("passkey") == "required":
        errors.append("a passkey rule is answered by people only")
    if "from" in rule:
        errors.append("a `from: untrusted` rule is answered by people only")
    if "veto_s" in a and not _int(a["veto_s"], 1):
        errors.append("veto_s must be a positive integer (seconds)")
    fields = a.get("allow", {}).get("fields") if isinstance(a.get("allow"), dict) and set(a["allow"]) == {"fields"} \
        else None
    if not (isinstance(fields, dict) and fields):
        return errors + ["allow must be {fields: {NAME: {type, min?, max?, enum?, pattern?}}}, at least one field"]
    for name, b in fields.items():
        if not (isinstance(b, dict) and set(b) <= BOUND_KEYS and b.get("type") in BOUND_TYPES):
            errors.append(f"field {name}: takes type (integer|string|boolean), min, max, enum, pattern")
            continue
        typ = BOUND_TYPES[b["type"]]
        if any(k in b for k in ("min", "max")) and (typ is not int or not all(_int(b.get(k, 0), -2 ** 53)
                                                                            for k in ("min", "max"))):
            errors.append(f"field {name}: min and max are integers, on an integer field")
        if "enum" in b and not (isinstance(b["enum"], list) and b["enum"] and all(type(v) is typ for v in b["enum"])):
            errors.append(f"field {name}: enum lists values of its type")
        if "pattern" in b:
            try:
                if typ is not str or not isinstance(b["pattern"], str):
                    raise PolicyError("a pattern is a string, on a string field")
                check_pattern(b["pattern"])
            except PolicyError as e:
                errors.append(f"field {name}: pattern: {e}")
    budget = a.get("budget")
    if budget is not None:
        s = budget.get("sum") if isinstance(budget, dict) else None
        if not (isinstance(budget, dict) and set(budget) <= BUDGET_KEYS and ({"count", "sum"} & set(budget))
                and _int(budget.get("count", 1), 1) and budget.get("scope") in ("tenant", "requester")
                and _int(budget.get("window"), 1) and budget["window"] <= MAX_WINDOW_S
                and (s is None or isinstance(s, dict) and set(s) == {"field", "max"} and _int(s["max"], 1)
                     and fields.get(s["field"], {}).get("type") == "integer"
                     and _int(fields[s["field"]].get("min"), 0))):
            errors.append(f"budget must be {{count?, sum?: {{field (an integer field with min >= 0), max}}, window (seconds, at most "
                          f"{MAX_WINDOW_S}), scope: tenant|requester}}, with count or sum")
    return errors


def _unfiltered(pattern):
    """Whether a pattern has no prefilter (`literals`) though no string of one character or none matches it (a
    catch-all such as `^` or `.` needs none)."""
    try:
        if not isinstance(pattern, str) or literals(pattern) is not None:
            return False
        rx = re.compile(translate(pattern), re.ASCII)
    except (PolicyError, re.error):
        return False
    return not any(rx.search(chr(c)) for c in range(128)) and not rx.search("")


def warnings(pol):
    """What lint lets through but a person should know: a tool mapped to class unknown (what every unmapped tool is, so
    unknown_tools still decides it; a 1.1 policy may do it, so it isn't an error), a rule the prefilter can't skip
    (`_unfiltered`), and an agent approver on a money-moving rule (class payment, or a tool the policy maps to payment)
    without executor t2 binds the approval, not what runs."""
    payments = [t for t, c in pol.get("tools", {}).items() if c == "payment"]

    def money(r):
        if r.get("class") == "payment":
            return True
        try:
            return "class" not in r and "tool" in r and any(re.fullmatch(r["tool"], t) for t in payments)
        except re.error:
            return False
    return [f"tool {t!r} maps to class 'unknown', which unknown_tools decides like any unmapped tool: map an "
            "application's own tool to class app (known, no class fields)"
            for t, c in pol.get("tools", {}).items() if c == "unknown"] + [
        f"{sec} rule {r['id']}: no literal of two or more characters is in every match, so the rule is searched on "
        "every call its class and tool reach; name the text it looks for (a command, a key name, a path part)"
        for sec in SECTIONS for r in pol.get(sec, []) if isinstance(r, dict) and _unfiltered(r.get("pattern"))] + [
        f"ask rule {r['id']}: approval.agent on a payment tool without executor t2: the agent's approval binds the "
        "arguments the agent reported, not what its process runs; add executor: t2"
        for r in pol.get("ask", []) if isinstance(r, dict) and isinstance(r.get("approval"), dict)
        and "agent" in r["approval"] and money(r) and r["approval"].get("executor") != "t2"]

