"""Policy v2 compiler: YAML or JSON in, canonical JSON and a policy_hash out.

Patterns are limited to a syntax that RE2 and the `regex` module (ASCII mode, after `translate`) match the same way,
so a decision does not depend on which engine made it. `build` returns every lint error at once.
"""
import hashlib
import json
import ntpath
import os
import posixpath
import re

from .. import yamlmini
from ..policy import PolicyError, _sre_c, _sre_p, check_regex

SECTIONS = ("deny", "ask", "flag")
TOP_KEYS = {"version", "description", "extends", "tools", "unknown_tools", "deny", "ask", "flag"}
RULE_KEYS = {"id", "class", "tool", "field", "pattern", "unless", "reason", "rationale", "label", "approval"}
EXECUTORS = ({"executor": "t1"}, {"executor": "t2"})   # an ask rule's `approval`: t2 runs only the signer's copy
CLASSES = {"shell": {"command", "argv"}, "fs": {"path", "op", "content_digest"}, "http": {"method", "url", "host"},
           "sql": {"statement", "verb", "db"}, "payment": {"amount", "currency", "payee", "new_payee"},
           "email": {"to", "domains", "attachments"}, "mcp": {"server", "tool", "args"}, "browser": {"action", "url"},
           "unknown": set()}
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


def _walk(items):
    for op, av in items:
        if op not in _OPS or (op == _sre_c.AT and av not in _ATS):
            raise PolicyError("lookaround, backreferences, atomic groups, possessive repeats and \\Z are outside the RE2 subset")
        if op in (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT):
            if av[0] > MAX_REPEAT or (av[1] != _sre_c.MAXREPEAT and av[1] > MAX_REPEAT):
                raise PolicyError(f"repeat counts above {MAX_REPEAT} are outside the RE2 subset")
            _walk(av[2])
        elif op == _sre_c.SUBPATTERN:
            _walk(av[-1])
        elif op == _sre_c.BRANCH:
            for b in av[1]:
                _walk(b)


def check_pattern(pattern):
    """Raise PolicyError unless the pattern is in the RE2 subset and has no super-linear nested repeat."""
    translate(pattern)
    try:
        check_regex(pattern)
    except re.error as e:
        raise PolicyError(f"bad regex: {e}") from e
    _walk(_sre_p.parse(pattern))


def _read(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    return yamlmini.load_any(text) if path.endswith((".yaml", ".yml")) else json.loads(text)


def build(path, seen=()):
    """Return (effective_policy, errors). `extends` names a relative file; the result records its policy_hash."""
    try:
        pol = _read(path)
    except Exception as e:   # OSError, JSON or YAML syntax: all reported as lint errors
        return {}, [f"{path}: {e}"]
    if not isinstance(pol, dict):
        return {}, [f"{path}: not a mapping"]
    errors = [f"{path}: unknown key {k!r}" for k in sorted(set(pol) - TOP_KEYS)]
    for sec in SECTIONS:
        if not isinstance(pol.get(sec, []), list):
            errors.append(f"{path}: {sec} must be a list")
            pol[sec] = []
    if not isinstance(pol.get("tools", {}), dict):
        errors.append(f"{path}: tools must map tool names to classes")
        pol["tools"] = {}
    base = pol.pop("extends", None)
    if base is not None:
        if not isinstance(base, str) or posixpath.isabs(base) or ntpath.isabs(base) or base.startswith("~"):
            errors.append(f"{path}: extends must be a relative path; the compiled policy names the parent by hash")
        elif os.path.realpath(os.path.join(os.path.dirname(path), base)) in seen + (os.path.realpath(path),):
            errors.append(f"{path}: extends loop at {base}")
        else:
            parent, perr = build(os.path.join(os.path.dirname(path), base), seen + (os.path.realpath(path),))
            errors += perr
            own = {r.get("id") for sec in SECTIONS for r in pol.get(sec, []) if isinstance(r, dict)}
            merged = {k: v for k, v in parent.items() if k not in SECTIONS + ("extends",)}
            merged.update({k: v for k, v in pol.items() if k not in SECTIONS})
            merged["tools"] = {**parent.get("tools", {}), **pol.get("tools", {})}
            for sec in SECTIONS:
                merged[sec] = [r for r in parent.get(sec, []) if isinstance(r, dict) and r.get("id") not in own] + pol.get(sec, [])
            merged["extends"] = policy_hash(parent)
            pol = merged
    return pol, errors + _lint(pol, path)


def _lint(pol, path):
    errors, ids = [], set()
    tools = pol.get("tools", {})
    for tool, cls in tools.items():
        if cls not in CLASSES:
            errors.append(f"{path}: tool {tool!r} has unknown class {cls!r}")
    if pol.get("unknown_tools", "allow") not in SECTIONS + ("allow",):
        errors.append(f"{path}: unknown_tools must be allow, flag, ask or deny")
    for sec in SECTIONS:
        for r in pol.get(sec, []):
            if not isinstance(r, dict) or not isinstance(r.get("id"), str) or not isinstance(r.get("pattern"), str):
                errors.append(f"{path}: {sec} rule needs a string id and pattern: {r!r}")
                continue
            where = f"{path}: {sec} rule {r['id']}"
            errors += [f"{where}: unknown key {k!r}" for k in sorted(set(r) - RULE_KEYS)]
            errors += [f"{where}: {k} must be a string" for k in sorted(set(r) & RULE_KEYS - {"approval"})
                       if not isinstance(r[k], str)]
            if "approval" in r and (sec != "ask" or r["approval"] not in EXECUTORS):
                errors.append(f"{where}: approval must be {{executor: t1|t2}}, on an ask rule")
            if r["id"] in ids:
                errors.append(f"{where}: duplicate id")
            ids.add(r["id"])
            for key in ("pattern", "unless", "tool"):
                try:
                    if isinstance(r.get(key), str):
                        check_pattern(r[key])
                except PolicyError as e:
                    errors.append(f"{where}: {key}: {e}")
            cls, field = r.get("class"), r.get("field")
            if cls is not None and cls not in CLASSES:
                errors.append(f"{where}: unknown class {cls!r}")
            elif cls is not None and field is not None and field not in CLASSES[cls]:
                errors.append(f"{where}: can never fire: class {cls} has no field {field!r}")
            elif cls not in (None, "unknown") and cls not in tools.values():
                errors.append(f"{where}: can never fire: no tool maps to class {cls}")
    return errors

