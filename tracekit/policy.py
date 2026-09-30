"""Versioned policy (C7): load YAML or JSON, hash, evaluate. Rules carry stable ids so every
decision is auditable. An unusable policy raises PolicyError; it never silently means "no rules".

The *effective* policy (after `extends`) is what gets hashed, recorded in run.start, sent to
the signer and put in bundles, as canonical JSON.
"""
import json
import os
import re

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


class PolicyError(Exception):
    pass


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
                re.compile(str(r["pattern"])); re.compile(str(r.get("tool", ".*")))
            except re.error as e:
                raise PolicyError(f"rule {r['id']}: bad regex: {e}") from e
    if pol.get("fail_mode", "open") not in ("open", "closed"):
        raise PolicyError("fail_mode must be open or closed")
    if pol.get("content_capture", "hashed") not in ("hashed", "full"):
        raise PolicyError("content_capture must be hashed or full")


def load(path=None):
    """Return (effective_policy, canonical_json_text). Raises PolicyError on an unusable file."""
    path = path or os.environ.get("TRACEKIT_POLICY") or DEFAULT_POLICY
    try:
        pol = _resolve(path)
        pol.setdefault("deny", []); pol.setdefault("ask", []); pol.setdefault("flag", [])
        validate(pol)
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


def _matches(r, tool, ti):
    return re.fullmatch(str(r.get("tool", ".*")), tool or "") and re.search(str(r["pattern"]), subject(tool, ti, r.get("field")))


def evaluate(pol, tool, ti, cwd=None):
    """Return {'decision', 'rule_ids', 'reasons', 'flags'}; decision in allow|deny|ask|flag.
    Precedence: deny > ask > flag > allow."""
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
        p = str((ti or {}).get("file_path") or (ti or {}).get("notebook_path") or "")
        if p:
            ap = os.path.realpath(os.path.join(cwd, os.path.expanduser(p)))
            if not (ap + os.sep).startswith(os.path.realpath(cwd) + os.sep):
                flags.append("out_of_scope_write"); rule_ids.append("TK-SCOPE")
    decision = "deny" if deny else ("ask" if ask else ("flag" if flags else "allow"))
    return {"decision": decision, "rule_ids": rule_ids, "reasons": reasons, "flags": sorted(set(flags))}


def rule_index(pol):
    return {r["id"]: (sec, r) for sec in SECTIONS for r in pol.get(sec) or []}
