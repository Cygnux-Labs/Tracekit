"""Redaction and the field-by-field privacy rules from docs/privacy.md.

Order is always: redact -> classify (value or hash reference) -> sign.
The same functions are used for the local ledger and for exported bundles, so a bundle can
never contain more than the ledger does.
"""
import re

from .core import content_ref, content_value

# Every pattern must stay linear on large adversarial input (tests/test_redaction_runtime.py):
# no unbounded repeat that many match starts can each scan to the end of the string.
SECRET_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:(?!-----BEGIN )[\s\S])*?"
                               r"-----END [A-Z0-9 ]*PRIVATE KEY-----")),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}")),
    ("openai_key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    # a header segment starting a run is unbounded; one after "-" (many such starts can share a run) is bounded.
    # lean: a JWT header over 512 chars right after "-" is not redacted; scan runs in code if that shows up
    ("jwt", re.compile(r"\beyJ(?:(?<!-eyJ)[A-Za-z0-9_\-]{8,}|[A-Za-z0-9_\-]{8,512})"
                       r"\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("connection_string", re.compile(r"\b[a-z][a-z0-9+.\-]{0,31}://[^\s:/@]{0,256}:[^\s@]{1,256}@[^\s]+", re.I)),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("bearer_token", re.compile(r"(?i)\b(authorization\s*:\s*(?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=\-]{12,}")),
    ("aws_secret_key", re.compile(r"(?i)(aws_secret_access_key[\"']?\s*[=:]\s*[\"']?)[A-Za-z0-9/+]{40}")),
]
# dotenv-style lines: every value is treated as secret when the content comes from a .env file
DOTENV_LINE = re.compile(r"(?m)^([ \t]*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=\s*)([\"']?)([^\n\"']+)")
DOTENV_PATH = re.compile(r"(^|[/\s'\"=@<])\.env(\.[A-Za-z0-9_-]+)?\b")
# KEY=value / key: value assignments whose key looks secret (.env files, configs, commands)
ASSIGNMENT = re.compile(
    r"(?im)\b([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIALS?)[A-Z0-9_]*)"
    r"(\s*[=:]\s*)([\"']?)([^\s\"'#]{4,})")


# cheap literal pre-checks (lower-cased) so a pattern only runs when its text could be present
_PREFILTER = {"private_key": ("private key",), "anthropic_key": ("sk-ant-",), "openai_key": ("sk-",), "github_token": ("gh", "github_pat_"),
              "aws_access_key": ("akia", "asia"), "slack_token": ("xox",), "jwt": ("eyj",), "connection_string": ("://",),
              "google_api_key": ("aiza",), "stripe_key": ("_live_", "_test_"), "npm_token": ("npm_",),
              "bearer_token": ("authorization",), "aws_secret_key": ("aws_secret_access_key",)}


def redact_text(s):
    """Return (redacted_string, was_redacted)."""
    out, hit = s, False
    low = s.lower()
    for name, pat in SECRET_PATTERNS:
        if not any(x in low for x in _PREFILTER.get(name, ("",))):
            continue
        if pat.groups:  # keep the label part (e.g. "Authorization: Bearer "), drop the secret
            out, n = pat.subn(lambda m, name=name: m.group(1) + f"[REDACTED:{name}]", out)
        else:
            out, n = pat.subn(f"[REDACTED:{name}]", out)
        hit = hit or n > 0
    out, n = _redact_assignments(out)
    return out, hit or n > 0


_AFTER = re.compile(r"(\s*[=:]\s*)([\"']?)([^\s\"'#]{4,})")
_IDCH = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")


_KWS = ("secret", "password", "passwd", "token", "apikey", "api_key", "private_key", "access_key", "credential")


def _kw_hits(s):
    low = s.lower()
    hits = []
    for kw in _KWS:
        i = low.find(kw)
        while i >= 0:
            hits.append((i, i + len(kw)))
            i = low.find(kw, i + 1)
    return sorted(hits)


def _redact_assignments(s):
    """Same result as ASSIGNMENT.subn(...) but fast on large inputs: find the keywords with
    str.find, then look around each one."""
    hits = _kw_hits(s)
    if not hits:
        return s, 0
    out, last, n, pos, b = [], 0, 0, 0, 0
    for ks, ke in hits:
        if ks < pos or ks < b:  # ks < b: same identifier as the previous hit, already handled
            continue
        a, b = ks, ke
        while a > 0 and s[a - 1] in _IDCH:
            a -= 1
        while b < len(s) and s[b] in _IDCH:
            b += 1
        am = _AFTER.match(s, b)
        if am and a >= last:
            out.append(s[last:am.start(3)])
            out.append("[REDACTED:assignment]")
            last = pos = am.end(3)
            n += 1
    out.append(s[last:])
    return "".join(out), n


def redact_dotenv(s):
    """Redact every value of KEY=value lines (used for content read from .env files)."""
    out, n = DOTENV_LINE.subn(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED:dotenv]", s)
    return out, n > 0


def mentions_dotenv(*texts):
    return any(isinstance(t, str) and DOTENV_PATH.search(t) for t in texts)


MAX_DEPTH = 64


def redact(obj, dotenv=False, _depth=0):
    """Recursively redact every string (and every key). Returns (obj, was_redacted).
    Nesting beyond MAX_DEPTH is replaced by a marker instead of recursing without bound."""
    if _depth > MAX_DEPTH:
        return "[truncated: nesting too deep]", True
    if isinstance(obj, str):
        out, hit = redact_text(obj)
        if dotenv:
            out, hit2 = redact_dotenv(out)
            hit = hit or hit2
        return out, hit
    if isinstance(obj, list):
        res = [redact(x, dotenv, _depth + 1) for x in obj]
        return [r[0] for r in res], any(r[1] for r in res)
    if isinstance(obj, dict):
        out, hit = {}, False
        for k, v in obj.items():
            rk, hk = redact_text(k) if isinstance(k, str) else (k, False)
            rv, hv = redact(v, dotenv, _depth + 1)
            out[rk] = rv
            hit = hit or hk or hv
        return out, hit
    return obj, False


# Tool-input fields recorded in clear (after redaction): the minimum a security reviewer needs
# to see *what* was done. Everything else is recorded as a hash unless content_capture=full.
ALWAYS_CLEAR = {"command", "file_path", "notebook_path", "path", "url", "pattern", "query", "glob",
                "description", "subagent_type", "child_agent_id", "timeout", "run_in_background", "offset", "limit"}


def tool_input(tool, ti, content_capture="hashed"):
    """Map a raw tool_input dict to {field: content} per docs/privacy.md."""
    out, ti = {}, ti or {}
    dotenv = mentions_dotenv(ti.get("command"), ti.get("file_path"), ti.get("path"), ti.get("pattern"))
    for k, v in ti.items():
        rk = redact_text(k)[0] if isinstance(k, str) else k
        rv, red = redact(v, dotenv)
        if content_capture == "full" or k in ALWAYS_CLEAR:
            out[rk] = content_value(rv, red)
        else:
            out[rk] = content_ref(rv, red)
    return out


def content(value, content_capture="hashed", dotenv=False):
    """Tool results, prompts and model text: hashed unless content_capture=full.
    dotenv=True (the call read or printed a .env file) redacts every KEY=value line."""
    rv, red = redact(value, dotenv)
    return content_value(rv, red) if content_capture == "full" else content_ref(rv, red)
