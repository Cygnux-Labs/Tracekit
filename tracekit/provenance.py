"""The values a JSON value carries, for the signer's provenance index (docs/policy-v2.md, `from: untrusted`).

values(obj) lists (kind, normalised value) pairs: emails, URLs (each URL and its classes.url_target form), hosts (of
URLs, of emails in content, bare dotted names and IPv4 addresses), absolute file paths, digit runs of 8 or more (with
' ', '.' or '-' between digits) and leaf strings of 6..256 characters, dict keys included. Every pattern reads the text
as norm() leaves it. Only verbatim values: a value paraphrased or re-encoded on its way into a call reads as a new value.
The work is linear in the text: no pattern backtracks over more than a bounded window.
"""
import re
import time
import unicodedata

from tracekit.policy2 import classes

MAX_TEXT = 1 << 20   # characters scanned per value
MAX_VALUES = 4096    # pairs returned per value
_URL = re.compile(r"(?i)\b(?:https?|wss?|ftp)://[^\s'\"<>`]+")
_LOCAL = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@")   # starts only where a run starts: linear
_DOMAIN = re.compile(r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b")
_HOST = re.compile(r"(?<![\w.@-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b(?![.-]?\w)")
_IP = re.compile(r"(?<![\w.:])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])|\[[0-9A-Fa-f:.]+\]")
_PATH = re.compile(r"(?<![^\s\"'=(\[,])(?:/|[A-Za-z]:[\\/])[^\s\"'<>`|;]+")
_DIGITS = re.compile(r"[0-9](?:[ .-]?[0-9]){7,}")
_TRAIL = ".,;:!?)]}'\""
# default-ignorable code points outside the format (Cf) category
_IGNORABLE = frozenset([0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x3164, 0xFFA0, *range(0x180B, 0x1810),
                        *range(0xFE00, 0xFE10), *range(0xE0100, 0xE01F0)])


def norm(s):
    """`s` without format (Cf) and other default-ignorable characters, NFKC (fullwidth forms, no-break and thin spaces
    as spaces), ideographic full stops as dots: the text every pattern reads, in content and in a call alike."""
    if not s.isascii():
        s = "".join(c for c in s if ord(c) not in _IGNORABLE and unicodedata.category(c) != "Cf")
    return unicodedata.normalize("NFKC", s).replace("。", ".")


def host(h):
    """A canonical host (classes.url_info) as the index keys it."""
    return norm(h).casefold()


class _Full(Exception):
    pass


def _text(t, out, email_hosts, deadline):
    def add(kind, v):
        out[kind, v] = True
        if len(out) > MAX_VALUES:
            raise _Full
    targets = {}
    for m in _LOCAL.finditer(t):
        d = _DOMAIN.match(t, m.end(), m.end() + 255)
        if d:
            add("email", (m.group(0)[-65:] + d.group(0)).casefold())
            if email_hosts:
                add("host", d.group(0).casefold())
    _check(deadline)
    for m in _URL.finditer(t):
        url = m.group(0).rstrip(_TRAIL)
        add("url", url)
        if url not in targets:
            targets[url] = classes.url_target(url)
        if targets[url]:
            add("url", targets[url])
            add("host", host(targets[url].split("://", 1)[1][:-1]))
    _check(deadline)
    for m in _HOST.finditer(t):
        add("host", m.group(0).casefold())
    for m in _IP.finditer(t):
        h = classes.url_info("http://" + m.group(0)).get("host")
        if h:
            add("host", h)
    _check(deadline)
    for m in _PATH.finditer(t):
        path = classes.fs_path(m.group(0).rstrip(_TRAIL))
        if path not in ("", "/"):
            add("path", path)
    for m in _DIGITS.finditer(t):
        add("digits", re.sub("[ .-]", "", m.group(0)))
        for g in re.split("[ .-]", m.group(0)):   # "acct 12345678 9": the account alone too
            if len(g) >= 8:
                add("digits", g)
    _check(deadline)


def _check(deadline):
    if deadline is not None and time.monotonic() > deadline:
        raise TimeoutError("provenance values past the deadline")


def values(obj, email_hosts=True, deadline=None):
    """([(kind, value)], overflow) of a JSON value, in a fixed order (dict keys sorted, each key before its value),
    without repeats; at most MAX_VALUES pairs from at most MAX_TEXT characters of text, and `overflow` when there was
    more. With `email_hosts`, an email's domain is a host value too (content: a page naming audit@vendor.example brings
    the host vendor.example); without, it is not (a recipient's own domain is not a host the call sends to). Past
    `deadline` (a time.monotonic()) raises TimeoutError."""
    out, budget, stack = {}, MAX_TEXT, [obj]
    try:
        while stack:
            v = stack.pop()
            if isinstance(v, dict):
                stack.extend(x for k in sorted(v, reverse=True) for x in (v[k], k))
            elif isinstance(v, list):
                stack.extend(reversed(v))
            elif isinstance(v, (int, float)) and not isinstance(v, bool):
                _text(str(v), out, email_hosts, deadline)
            elif isinstance(v, str):
                if budget <= 0:
                    return list(out), True
                s, budget = v[:budget], budget - len(v)
                t = norm(s)
                _text(t, out, email_hosts, deadline)
                leaf = " ".join(t.split())
                if 6 <= len(leaf) <= 256:
                    out["string", leaf] = True
                    if len(out) > MAX_VALUES:
                        raise _Full
                if budget < 0:
                    return list(out), True
    except _Full:
        return list(out)[:MAX_VALUES], True
    return list(out), False
