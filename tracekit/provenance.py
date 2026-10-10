"""The values a JSON value carries, for the signer's provenance index (docs/policy-v2.md, `from: untrusted`).

values(obj) lists (kind, normalised value) pairs: emails, URLs (each URL and its classes.url_target form), hosts,
absolute file paths, digit runs of 8 or more and leaf strings of 6..256 characters. Only verbatim values: a value
paraphrased or re-encoded on its way into a call reads as a new value.
"""
import re
import unicodedata

from tracekit.policy2 import classes

MAX_TEXT = 1 << 20   # characters scanned per value
MAX_VALUES = 4096    # pairs returned per value
_URL = re.compile(r"(?i)\b(?:https?|wss?|ftp)://[^\s'\"<>`]+")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b")
_HOST = re.compile(r"(?<![\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b(?![.-]?\w)")
_IP = re.compile(r"(?<![\w.:])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])|\[[0-9A-Fa-f:.]+\]")
_PATH = re.compile(r"(?<![^\s\"'=(\[,])(?:/|[A-Za-z]:[\\/])[^\s\"'<>`|;]+")
_DIGITS = re.compile(r"[0-9](?:[ -]?[0-9]){7,}")
_TRAIL = ".,;:!?)]}'\""


def _text(s, out):
    t = unicodedata.normalize("NFKC", s).replace("\u3002", ".")
    for m in _EMAIL.finditer(t):
        out["email", m.group(0).casefold()] = True
    for m in _URL.finditer(s):
        url = m.group(0).rstrip(_TRAIL)
        out["url", url] = True
        target = classes.url_target(url)
        if target:
            out["url", target] = True
            out["host", target.split("://", 1)[1][:-1]] = True
    for m in _HOST.finditer(t):
        out["host", m.group(0).casefold()] = True
    for m in _IP.finditer(t):
        host = classes.url_info("http://" + m.group(0)).get("host")
        if host:
            out["host", host] = True
    for m in _PATH.finditer(s):
        path = classes.fs_path(m.group(0).rstrip(_TRAIL))
        if path not in ("", "/"):
            out["path", path] = True
    for m in _DIGITS.finditer(s):
        out["digits", re.sub("[ -]", "", m.group(0))] = True


def values(obj):
    """[(kind, value)] of a JSON value, in a fixed order (dict keys sorted), without repeats; at most MAX_VALUES pairs
    from at most MAX_TEXT characters of text."""
    out, budget, stack = {}, MAX_TEXT, [obj]
    while stack and budget > 0 and len(out) < MAX_VALUES:
        v = stack.pop()
        if isinstance(v, dict):
            stack.extend(v[k] for k in sorted(v, reverse=True))
        elif isinstance(v, list):
            stack.extend(reversed(v))
        elif isinstance(v, (int, float)) and not isinstance(v, bool):
            _text(str(v), out)
        elif isinstance(v, str):
            s, budget = v[:budget], budget - len(v)
            _text(s, out)
            leaf = " ".join(s.split())
            if 6 <= len(leaf) <= 256:
                out["string", leaf] = True
    return list(out)[:MAX_VALUES]
