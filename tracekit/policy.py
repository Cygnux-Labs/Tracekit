"""Versioned policy (C7): load YAML or JSON, hash, evaluate. Rules carry stable ids so every
decision is auditable. An unusable policy raises PolicyError; it never silently means "no rules".

The *effective* policy (after `extends`) is what gets hashed, recorded in run.start, sent to
the signer and put in bundles, as canonical JSON.
"""
import json
import os
import re
import signal
import threading

from . import yamlmini
from .core import canon, sha256_hex

HERE = os.path.dirname(os.path.abspath(__file__))
POLICY_DIR = os.path.join(HERE, "policy")
DEFAULT_POLICY = os.path.join(POLICY_DIR, "default.yaml")
FIELD_FOR_TOOL = {"Bash": "command", "Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path",
                  "Read": "file_path", "NotebookEdit": "notebook_path", "WebFetch": "url", "WebSearch": "query",
                  "Glob": "pattern", "Grep": "pattern"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
SECTIONS = ("deny", "ask", "flag")
# C8: only calls Tracekit intercepts *before* they run can be held for approval
ASKABLE = re.compile(r"^(Bash|Write|Edit|MultiEdit|NotebookEdit|WebFetch|mcp__.*)$")
TOP_KEYS = {"version", "fail_mode", "content_capture", "reasoning_capture", "transcript_hashing", "checkpoint_every",
            "approval_timeout_s", "extends", "deny", "ask", "flag", "_note", "description"}


try:  # Python 3.11 moved the regex parser
    from re import _constants as _sre_c, _parser as _sre_p
except ImportError:  # pragma: no cover - Python 3.9 / 3.10
    import sre_constants as _sre_c, sre_parse as _sre_p

WINDOW, STEP = 16 * 1024, 12 * 1024   # longer subjects are matched in overlapping windows: padding cannot hide a command
MAX_SUBJECT = 256 * 1024     # beyond this a subject counts as matching every rule that applies to the tool (fail safe)
REGEX_BUDGET_S = 0.5         # per rule, where the platform lets us interrupt a match (POSIX, main thread)


class PolicyError(Exception):
    pass


class RegexTimeout(Exception):
    pass


def _unbounded(node):
    op, av = node
    return op in (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT) and av[1] == _sre_c.MAXREPEAT


def _starts_unbounded(items):
    if not items:
        return False
    node = items[0]
    op, av = node
    if _unbounded(node):
        return True
    if op == _sre_c.SUBPATTERN:
        return _starts_unbounded(av[-1])
    if op == _sre_c.BRANCH:
        return any(_starts_unbounded(b) for b in av[1])
    return False


def _risky(items):
    """True for an unbounded repeat whose body itself begins with an unbounded repeat, the shape
    behind catastrophic backtracking: (a+)+, (.*a)*, (a*b*)*. A body that starts with a fixed
    delimiter, like (-[a-z]*\\s+)*, is unambiguous and allowed."""
    for node in items:
        op, av = node
        if _unbounded(node) and _starts_unbounded(av[2]):
            return True
        if op in (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT):
            if _risky(av[2]):
                return True
        elif op == _sre_c.SUBPATTERN:
            if _risky(av[-1]):
                return True
        elif op == _sre_c.BRANCH:
            if any(_risky(b) for b in av[1]):
                return True
        elif op in (_sre_c.ASSERT, _sre_c.ASSERT_NOT):
            if _risky(av[1]):
                return True
    return False


def check_regex(pattern):
    """Raise re.error for a bad pattern and PolicyError for one that risks catastrophic backtracking."""
    parsed = _sre_p.parse(pattern)
    re.compile(pattern)
    if _risky(parsed):
        raise PolicyError("regex has a repeat of a repeat (e.g. '(a+)+'), which can hang matching; "
                          "rewrite it with a bounded or non-nested form")


class _Budget:
    """Interrupt a runaway regex match. Only possible with SIGALRM on the main thread; elsewhere the
    structural check in `check_regex` is the protection."""

    def __enter__(self):
        self.on = hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread()
        if self.on:
            def boom(signum, frame):
                raise RegexTimeout()
            self.old = signal.signal(signal.SIGALRM, boom)
            signal.setitimer(signal.ITIMER_REAL, REGEX_BUDGET_S)
        return self

    def __exit__(self, *exc):
        if self.on:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, self.old)
        return False


def _parse(path, raw):
    if path.endswith((".yaml", ".yml")):
        return yamlmini.load_any(raw)
    return json.loads(raw)


def _resolve(path, seen=()):
    if path in seen:
        raise PolicyError(f"policy extends loop at {path}")
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    pol = _parse(path, raw)
    if not isinstance(pol, dict):
        raise PolicyError(f"policy {path} is not a mapping")
    base = pol.pop("extends", None)
    if base:
        bpath = DEFAULT_POLICY if base == "default" else (base if os.path.isabs(base) else os.path.join(os.path.dirname(path), base))
        parent = _resolve(bpath, seen + (path,))
        merged = {k: v for k, v in parent.items() if k not in SECTIONS}
        merged.update({k: v for k, v in pol.items() if k not in SECTIONS})
        for sec in SECTIONS:
            ids = {r.get("id") for r in pol.get(sec) or []}
            merged[sec] = [r for r in parent.get(sec) or [] if r.get("id") not in ids] + list(pol.get(sec) or [])
        merged["extends"] = base
        pol = merged
    return pol


def validate(pol):
    unknown = set(pol) - TOP_KEYS
    if unknown:
        raise PolicyError(f"unknown policy keys: {sorted(unknown)}")
    ids = set()
    for section in SECTIONS:
        rules = pol.get(section) or []
        if not isinstance(rules, list):
            raise PolicyError(f"{section} must be a list")
        for r in rules:
            if not isinstance(r, dict) or "id" not in r or "pattern" not in r:
                raise PolicyError(f"rule without id or pattern in {section}: {r}")
            if r["id"] in ids:
                raise PolicyError(f"duplicate rule id {r['id']}")
            ids.add(r["id"])
            try:
                check_regex(str(r["pattern"])); check_regex(str(r.get("tool", ".*")))
            except re.error as e:
                raise PolicyError(f"rule {r['id']}: bad regex: {e}") from e
            except PolicyError as e:
                raise PolicyError(f"rule {r['id']}: {e}") from e
    if pol.get("fail_mode", "open") not in ("open", "closed"):
        raise PolicyError("fail_mode must be open or closed")
    if pol.get("content_capture", "hashed") not in ("hashed", "full"):
        raise PolicyError("content_capture must be hashed or full")
    for key in ("reasoning_capture", "transcript_hashing"):
        if key in pol and not isinstance(pol[key], bool):
            raise PolicyError(f"{key} must be true or false")
    for key in ("checkpoint_every", "approval_timeout_s"):
        if key in pol and (isinstance(pol[key], bool) or not isinstance(pol[key], (int, float)) or not pol[key] > 0
                           or pol[key] != pol[key] or pol[key] == float("inf")):
            raise PolicyError(f"{key} must be a positive number")


def load(path=None):
    """Return (effective_policy, canonical_json_text). Raises PolicyError on an unusable file."""
    from .client import SystemConfigError, system_config
    try:
        sc = system_config()
    except SystemConfigError as e:
        raise PolicyError(str(e)) from e
    if sc is not None:  # 0.2.1 system mode: the agent's environment cannot choose the policy or the fail mode
        path = path or sc.get("policy") or DEFAULT_POLICY
    else:
        path = path or os.environ.get("TRACEKIT_POLICY") or DEFAULT_POLICY
    try:
        pol = _resolve(path)
        pol.setdefault("deny", []); pol.setdefault("ask", []); pol.setdefault("flag", [])
        validate(pol)
        if sc is not None:
            pol["fail_mode"] = sc.get("fail_mode", "closed") if sc.get("fail_mode") in ("open", "closed") else "closed"
        return pol, canon(pol)
    except PolicyError:
        raise
    except Exception as e:
        raise PolicyError(f"policy {path} unusable: {e}") from e


def policy_hash(pol):
    return "sha256:" + sha256_hex(canon(pol))


def subject(tool, ti, field=None):
    field = field or FIELD_FOR_TOOL.get(tool)
    if field and isinstance(ti, dict) and field in ti:
        v = ti[field]
        return ("true" if v else "false") if isinstance(v, bool) else str(v)
    if field and field != FIELD_FOR_TOOL.get(tool):
        return ""  # the rule names a field this call doesn't have
    return canon(ti or {})


def _windows(text):
    if len(text) <= WINDOW:
        yield text
        return
    for i in range(0, len(text), STEP):
        yield text[i:i + WINDOW]
        if i + WINDOW >= len(text):
            break


def _matches(r, tool, ti):
    """True when the rule applies. A match that cannot finish in time, or a subject too large to scan, counts
    as a match: a rule that cannot be evaluated must not silently let the call through. Anchors (^ $) in a
    rule see window edges when the subject is longer than WINDOW."""
    try:
        with _Budget():
            if not re.fullmatch(str(r.get("tool", ".*")), (tool or "")[:4096]):
                return False
            text = subject(tool, ti, r.get("field"))
            if len(text) > MAX_SUBJECT:
                return True
            pattern = re.compile(str(r["pattern"]))
            return any(pattern.search(w) for w in _windows(text))
    except RegexTimeout:
        return True


def evaluate(pol, tool, ti, cwd=None):
    """Return {'decision', 'rule_ids', 'reasons', 'flags'}; decision in allow|deny|ask|flag.
    Precedence: deny > ask > flag > allow."""
    if not isinstance(ti, dict):
        ti = {} if ti is None else {"value": ti}
    rule_ids, reasons, flags = [], [], []
    deny = ask = False
    for r in pol.get("deny", []):
        if _matches(r, tool, ti):
            deny = True
            rule_ids.append(r["id"]); reasons.append(r.get("reason", r["pattern"]))
    for r in pol.get("ask", []):
        if ASKABLE.match(tool or "") and _matches(r, tool, ti):
            ask = True
            rule_ids.append(r["id"]); reasons.append(r.get("reason", r["pattern"]))
    for r in pol.get("flag", []):
        if _matches(r, tool, ti):
            if r["id"] not in rule_ids:
                rule_ids.append(r["id"])
            flags.append(r.get("label", "flag"))
    if tool in WRITE_TOOLS and cwd:
        p = str(ti.get("file_path") or ti.get("notebook_path") or "")
        if p:
            try:
                if "\x00" in p:  # not a real path; whether realpath rejects it varies by Python version and OS
                    raise ValueError("embedded NUL")
                ap = os.path.realpath(os.path.join(cwd, os.path.expanduser(p)))
                inside = (ap + os.sep).startswith(os.path.realpath(cwd) + os.sep)
            except (ValueError, OSError):  # an unresolvable path counts as out of scope
                inside = False
            if not inside:
                flags.append("out_of_scope_write"); rule_ids.append("TK-SCOPE")
    decision = "deny" if deny else ("ask" if ask else ("flag" if flags else "allow"))
    return {"decision": decision, "rule_ids": rule_ids, "reasons": reasons, "flags": sorted(set(flags))}


def rule_index(pol):
    return {r["id"]: (sec, r) for sec in SECTIONS for r in pol.get(sec) or []}
