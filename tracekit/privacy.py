"""Redaction and the field-by-field privacy rules from docs/privacy.md.

Order is always: redact -> classify (value or hash reference) -> sign.
The same functions are used for the local ledger and for exported bundles, so a bundle can
never contain more than the ledger does.
"""
import collections
import re

from .core import content_ref, content_value, scrub

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
    # a run of token characters and two more dot-separated segments, from the run's start only; _redact_jwts()
    # finds where in the run the header starts
    ("jwt", re.compile(r"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    # scheme://user: only; _redact_connections() finds the password and host without backtracking
    ("connection_string", re.compile(r"\b[a-z][a-z0-9+.\-]{0,31}://[^\s:/@]{0,256}:", re.I)),
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


MARK = re.compile(r"\[REDACTED:([a-z_]+)\]")   # what redaction leaves in place of what it took out


def _hides(text):
    """Whether a mark in place of `text` takes out anything besides the marks `text` holds."""
    return bool(MARK.sub("", text))


def redact_text(s, counts=None):
    """Return (redacted_string, was_redacted). `counts` (a collections.Counter), when given, gets one per mark a rule
    wrote over something besides marks: text that holds marks already (a client's redaction, or look-alikes) can lose
    them to a mark, so the marks before and after don't say how many were written."""
    out, hit = _patterns(s, counts)
    out, n = _redact_assignments(out, counts)
    return out, hit or n > 0


def _patterns(s, counts=None):
    """(`s` with each SECRET_PATTERNS match marked, whether one was). `counts`: as for redact_text."""
    out, hit = s, False
    low = s.lower()
    for name, pat in SECRET_PATTERNS:
        if not any(x in low for x in _PREFILTER.get(name, ("",))):
            continue
        if name == "connection_string":
            out, n = _redact_connections(pat, out)
        elif name == "jwt":
            out, n = _redact_jwts(pat, out)
        elif pat.groups:  # keep the label part (e.g. "Authorization: Bearer "), drop the secret
            out, n = pat.subn(lambda m, name=name: m.group(1) + f"[REDACTED:{name}]", out)
        else:
            out, n = pat.subn(f"[REDACTED:{name}]", out)
        hit = hit or n > 0
        if n and counts is not None:   # none of these patterns matches marks alone
            counts[name] += n
    return out, hit


_PW_STOP = re.compile(r"[\s@]")
_HOST_END = re.compile(r"\s|\Z")
_PORT = re.compile(r"[0-9]{1,5}[/?#]")   # host:port/path: a URL with no password, its path free to hold an "@"
_WEB = ("http", "https", "ws", "wss")   # schemes whose URLs carry addresses in a path or query, not a password


def _redact_connections(prefix, s):
    """Redact scheme://user:password@host. The password runs to the first whitespace or "@" after the
    prefix; every prefix inside one such run shares that end, so it is found once per run and the
    scan stays linear however many prefixes the input repeats. In a web URL a port and a path after the prefix
    (http://host:8080/compose?to=a@b.example) are a URL, not a password; any other scheme's are a password
    (postgres://app:2024#Spring@db)."""
    out, last, n, pos, stop = [], 0, 0, 0, -1
    while True:
        m = prefix.search(s, pos)
        if not m:
            break
        if m.end() > stop:
            st = _PW_STOP.search(s, m.end())
            stop = st.start() if st else len(s)
        web = _PORT.match(s, m.end(), stop) and m.group().partition(":")[0].lower() in _WEB
        if stop > m.end() and s.startswith("@", stop) and not web:
            end = _HOST_END.search(s, stop + 1).start()
            if end > stop + 1:
                out += [s[last:m.start()], "[REDACTED:connection_string]"]
                last = pos = end
                n += 1
                continue
        pos = m.start() + 1
    out.append(s[last:])
    return "".join(out), n


_WORD = re.compile(r"\w")


def _redact_jwts(run, s):
    """Redact header.payload.signature tokens. run finds a run of token characters followed by two more
    dot-separated segments; the header starts at the run's leftmost "eyJ" after a non-word character (inside the
    run, a "-") and is at least 8 characters more. Each run is read once, so the scan stays linear however many
    "eyJ-" the input repeats."""
    out, last, n, pos = [], 0, 0, 0
    while True:
        m = run.search(s, pos)
        if not m:
            break
        dot = s.index(".", m.start())
        at = s.find("eyJ", m.start(), dot)
        while at != -1 and dot - at - 3 >= 8:
            after_non_word = s[at - 1] == "-" if at > m.start() else not (at and _WORD.match(s, at - 1))
            if after_non_word:
                break
            at = s.find("eyJ", at + 1, dot)
        if at == -1 or dot - at - 3 < 8:
            pos = dot + 1
            continue
        out += [s[last:at], "[REDACTED:jwt]"]
        last = pos = m.end()
        n += 1
    out.append(s[last:])
    return "".join(out), n


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


def _assignments(s, end=None):
    """(start, end) of each value _redact_assignments hides in `s`: ASSIGNMENT's, found fast on large inputs (the
    keywords with str.find, then a look around each one). `end(name_end, m)`: where the value _AFTER's match `m` found
    after a name ending at `name_end` ends instead, or None to leave it."""
    last = b = 0
    for ks, ke in _kw_hits(s):
        if ks < last or ks < b:  # ks < b: same identifier as the previous hit, already handled
            continue
        a, b = ks, ke
        while a > 0 and s[a - 1] in _IDCH:
            a -= 1
        while b < len(s) and s[b] in _IDCH:
            b += 1
        am = _AFTER.match(s, b)
        if am and a >= last:
            e = am.end(3) if end is None else end(b, am)
            if e is not None and e > am.start(3):
                yield am.start(3), e
                last = e


def _redact_assignments(s, counts=None):
    """Same result as ASSIGNMENT.subn(...) (_assignments). `counts`: as for redact_text."""
    out, last, n = [], 0, 0
    for v, e in _assignments(s):
        out += [s[last:v], "[REDACTED:assignment]"]
        if counts is not None and _hides(s[v:e]):
            counts["assignment"] += 1
        last, n = e, n + 1
    out.append(s[last:])
    return "".join(out), n


def redact_dotenv(s, counts=None):
    """Redact every value of KEY=value lines (used for content read from .env files). `counts`: as for redact_text."""
    def mark(m):
        if counts is not None and _hides(m.group(3)):
            counts["dotenv"] += 1
        return f"{m.group(1)}{m.group(2)}[REDACTED:dotenv]"
    out, n = DOTENV_LINE.subn(mark, s)
    return out, n > 0


def mentions_dotenv(*texts):
    return any(isinstance(t, str) and DOTENV_PATH.search(t) for t in texts)


MAX_DEPTH = 64
NESTED = "[truncated: nesting too deep]"   # what redact() leaves in place of what is nested deeper than MAX_DEPTH


def redact(obj, dotenv=False, _depth=0, counts=None, commands=(), noted=False, _shell=False):
    """Recursively redact every string (and every key). Returns (obj, was_redacted).
    Nesting beyond MAX_DEPTH is replaced by a marker instead of recursing without bound. `counts`: as for
    redact_text, and one under `nesting` per marker. `commands`: the (lower-case) names of arguments whose strings, at
    any depth, are shell lines, each redacted as redact_command reads it (not counted). `noted`: a string redaction may
    have hid more than values in (hidden) starts with NOTE, so a person reading it knows (an approver's copy)."""
    if _depth > MAX_DEPTH:
        if counts is not None:
            counts["nesting"] += 1
        return NESTED, True
    if isinstance(obj, str):
        if _shell:
            out, hit = redact_command(obj, dotenv)
        else:
            out, hit = redact_text(obj, counts)
            if dotenv:
                out, hit2 = redact_dotenv(out, counts)
                hit = hit or hit2
        n = noted and hidden(obj, out)
        return (NOTE.format(n) + out if n else out), hit
    if isinstance(obj, list):
        res = [redact(x, dotenv, _depth + 1, counts, commands, noted, _shell) for x in obj]
        return [r[0] for r in res], any(r[1] for r in res)
    if isinstance(obj, dict):
        out, hit = {}, False
        for k, v in obj.items():
            rk, hk = redact_text(k, counts) if isinstance(k, str) else (k, False)
            rv, hv = redact(v, dotenv, _depth + 1, counts, commands, noted,
                            _shell or isinstance(k, str) and k.lower() in commands)
            out[rk] = rv
            hit = hit or hk or hv
        return out, hit
    return obj, False


NOTE_CHARS = 256   # what redaction hides, past which a person is told how much: more than a few secrets' worth
# the note's own line, a shell comment: a shell line's readers (findings, why) parse what follows it as before
NOTE = "# [{} characters hidden by redaction]\n"
_SHELL_READS = re.compile(r"[\s;&|<>()`$\\'\"]")


def hidden(before, after):
    """How many characters redaction took out of string `before` to give `after` (marks aside), when the person reading
    `after` should be told: the count when it is over NOTE_CHARS, or when what it took holds a blank, a line end, a
    quote, a backslash or another character the shell reads, so it may be more than one value (words, lines, code);
    else 0."""
    b, a = MARK.sub("", before), MARK.sub("", after)
    took = collections.Counter(_SHELL_READS.findall(b)) - collections.Counter(_SHELL_READS.findall(a))
    n = len(b) - len(a)
    return n if n > NOTE_CHARS or n > 0 and took else 0


# Tool-input fields recorded in clear (after redaction): the minimum a security reviewer needs
# to see *what* was done. Everything else is recorded as a hash unless content_capture=full.
ALWAYS_CLEAR = {"command", "file_path", "notebook_path", "path", "url", "pattern", "query", "glob",
                "description", "subagent_type", "child_agent_id", "timeout", "run_in_background", "offset", "limit",
                "commands", "paths", "urls"}
# fields that say which action ran: a .env mention in them turns on dotenv redaction for the others, never for them
ACTION_FIELDS = ("command", "file_path", "path", "pattern")
# a call's several commands or files (Cline's run_commands, a patch's files): each entry is an ACTION_FIELDS value
ACTION_LISTS = ("commands", "paths")


# a shell line as bash reads it, so an approver's copy hides a value and never what runs after it (redact_command)
_SPECIAL = re.compile(r"[ \t\n;&|<>()'\"`\\$#]")   # what bash reads outside quotes
_SPECIAL_DQ = re.compile(r'["\\$`]')   # and inside "..."
_SHELLISH = re.compile(r"[ \t\n;&|<>()'\"`\\${}]")   # each ends a value in a part _read_shell leaves unread
_ENDS = re.compile(r"[ \t;&|]+")
_EXPANDS = re.compile(r"\$\(\(|\$\(|\$\{|`")   # where code starts in a heredoc body bash expands
_CLOSES = {"$((": (")", "(", 2), "$(": (")", "("), "${": ("}", "{"), "`": ("`",)}   # _past's arguments past each
_CASE = re.compile(r"case(?=[ \t\n;&|<>()]|\Z)")
_NAME_EQ = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*=")   # a word's KEY=, named as DOTENV_LINE names it
_LEAD = re.compile(r"[ \t]*(?:export\s+)?")   # what DOTENV_LINE reads before a KEY


def _past(s, k, close, open_="", depth=1):
    """Past the `close` that closes the `depth` brackets open before `k` (each `open_` opens one more), else len(s);
    a backslash keeps the character after it."""
    find = re.compile("[" + re.escape(open_ + close) + r"\\]").search
    while depth:
        m = find(s, k)
        if not m:
            return len(s)
        k = m.end() + (m.group() == "\\")
        depth += (m.group() == open_) - (m.group() == close)
    return k


def _delimiter(s, k):
    """(the end line a heredoc's `<<` names, quotes removed; whether `<<-` strips its tabs; whether a quote or a
    backslash in it keeps the body as written; where the word ends) for the `<<` just before `k`, or None when it names
    none."""
    tabs = s.startswith("-", k)
    k += tabs
    while s.startswith((" ", "\t"), k):
        k += 1
    word, start = [], k
    while k < len(s) and s[k] not in " \t\n;&|<>()":
        if s[k] in "'\"":
            e = s.find(s[k], k + 1)
            if e < 0:
                return None
            word.append(s[k + 1:e])
            k = e + 1
        else:
            k += s[k] == "\\"
            word.append(s[k:k + 1])
            k += 1
    return ("".join(word), tabs, any(c in "'\"\\" for c in s[start:k]), k) if word else None


def _end_line(s, k, end, tabs):
    """(where the end line `end` of the heredoc body starting at `k` starts, where it ends), both len(s) when no line
    ends it; `tabs`: it may start with tabs (`<<-`)."""
    while k < len(s):
        e = s.find("\n", k)
        e = len(s) if e < 0 else e
        if (s[k:e].lstrip("\t") if tabs else s[k:e]) == end:
            return k, e
        k = e + 1
    return len(s), len(s)


def _read_shell(s):
    """Shell line `s` as bash reads it, for redact_command: (cut, starts, body). `cut`, a bytearray one longer than `s`:
    1 at each place a hidden value ends at the latest, which is each blank, line end and control operator outside
    quotes, each start of code ($(, <(, >(), each shell character of a part left unread, and the end. A comment and a
    heredoc body have none (but for what bash expands in a body): they are text, not code. `starts`: where each word
    outside quotes starts. `body`: 1 inside each heredoc body.
    lean: reads quotes, backslashes, $'...', comments, heredocs and $(...); backquotes, ${...} and arithmetic are left
    unread, as is the rest of the line once a `case` starts inside $(...) (its patterns' parentheses), so a value there
    ends at its first shell character; read them as the policy's shell parser does if such a value must be hidden whole."""
    n = len(s)
    cut, starts, body = bytearray(n + 1), [], bytearray(n + 1)
    cut[n] = 1

    def unread(a, b):
        for m in _SHELLISH.finditer(s, a, b):
            cut[m.start()] = 1
            starts.append(m.end())   # where a word may start
        return b

    frames, pending, dq, word, i = [], [], False, False, 0   # frames: [parentheses open, word, dq] of each $( <( >(
    while i < n:
        m = (_SPECIAL_DQ if dq else _SPECIAL).search(s, i)
        j = m.start() if m else n
        if j > i and not (dq or word):
            if frames and _CASE.match(s, i):
                unread(i, n)
                break
            starts.append(i)
            word = True
        i = j
        if i == n:
            break
        c = s[i]
        if not dq and (c in " \t\n;&|<>()" or c == "#" and not word):
            cut[i], word = 1, False
            if c in " \t;&|":   # blanks and these operators only end words: a run of them at once
                e = _ENDS.match(s, i).end()
                cut[i:e] = b"\1" * (e - i)
                i = e
                continue
            if c == "#":   # a comment, to its line's end
                e = s.find("\n", i)
                i = n if e < 0 else e
                continue
            if c == "\n":   # the bodies of the heredocs this line opened follow it, each to its end line
                i += 1
                for end, tabs, kept in pending:
                    b, e = _end_line(s, i, end, tabs)
                    body[i:b] = b"\1" * (b - i)
                    while not kept and (x := _EXPANDS.search(s, i, b)):   # its $(...) and `...` run as it is read
                        i = unread(x.start(), min(_past(s, x.end(), *_CLOSES[x.group()]), b))
                    cut[e] = 1
                    i = min(e + 1, n)
                pending = []
                continue
            if s.startswith("((", i):   # arithmetic
                i = unread(i, _past(s, i + 2, ")", "(", 2))
                continue
            if c == "(" and frames:
                frames[-1][0] += 1
            elif c == ")" and frames:
                if frames[-1][0]:
                    frames[-1][0] -= 1
                else:
                    _, word, dq = frames.pop()
            elif s.startswith("<<", i):   # a heredoc, or a herestring (<<<: its third < names no end line)
                if d := _delimiter(s, i + 2):
                    pending.append(d[:3])
                    i = d[3]
                    continue
                i += 1   # past both: <<< 'x' is no heredoc from its second <
            elif c in "<>" and s.startswith("(", i + 1):   # process substitution
                frames.append([0, False, False])
                i += 1
            i += 1
            continue
        if not (dq or word):   # a part of a word: in "...", or quoted, escaped or expanded outside quotes
            starts.append(i)
            word = True
        if c == "\\":
            i += 2
        elif c == "'":
            e = s.find("'", i + 1)
            i = n if e < 0 else e + 1
        elif c == '"':
            dq = not dq
            i += 1
        elif c == "`":
            i = unread(i, _past(s, i + 1, "`"))
        elif s.startswith("$((", i):
            i = unread(i, _past(s, i + 3, ")", "(", 2))
        elif s.startswith("${", i):
            i = unread(i, _past(s, i + 2, "}", "{"))
        elif s.startswith("$(", i):   # code: it ends a value, and is read as a line of its own
            cut[i] = 1
            frames.append([0, word, dq])
            dq = word = False
            i += 2
        elif s.startswith("$'", i) and not dq:
            i = _past(s, i + 2, "'")
        else:
            i += 1
    return cut, starts, body


def redact_command(cmd, dotenv=False, own=True):
    """(shell line `cmd` as an approver's copy shows it, whether it changed): each SECRET_PATTERNS match, and the value
    of each secret-looking KEY=value (ASSIGNMENT's) and, with `dotenv`, of every KEY=value, but a value only up to
    where the shell ends it (_read_shell's cut: a blank, a line end, a control operator or code outside quotes), so what
    runs after it stays in view. A comment and a heredoc body have no cut: a value there runs as far as its pattern
    reads, as in content (with `dotenv`, each KEY=value line's to its line's end). `own` False: with `dotenv`, only a
    heredoc body's KEY=value lines, the line's own values kept (as v1 records a command)."""
    cut, starts, body = _read_shell(cmd)

    def bounded(v, e, gap):
        """[v, e) cut at the shell's end of the value, or None when a cut stands between its name (ending at `gap`) and
        it: `A= cmd` runs cmd."""
        if cut.find(1, gap, v) >= 0:
            return None
        k = cut.find(1, v, e)
        return e if k < 0 else k if k > v else None

    found = [(v, e, "assignment") for v, e in _assignments(cmd, lambda b, m: bounded(m.start(3), m.end(3), b))]
    if dotenv:
        for p in starts if own else ():   # a word KEY=value: its value is the rest of the word, its quotes kept in view
            if m := _NAME_EQ.match(cmd, p):
                v, e = m.end(), cut.find(1, m.end())
                v += 2 if cmd.startswith("$'", v) else cmd.startswith(("'", '"'), v)
                e -= 2 if cmd.startswith("\\\n", e - 2) else e > v and cmd[e - 1] in "'\""
                if e > v:
                    found.append((v, e, "dotenv"))
        words = set(starts)
        for m in DOTENV_LINE.finditer(cmd):   # a line KEY=value in a body, in quotes, or in a part left unread
            if (own or body[m.start(3)]) and _LEAD.match(cmd, m.start(1)).end() not in words and \
                    (e := bounded(m.start(3), m.end(3), cmd.rindex("=", m.start(1), m.end(1)) + 1)):
                found.append((m.start(3), e, "dotenv"))
    if "private key" in cmd.lower():   # a key's lines are SECRET_PATTERNS' to hide whole: a value can't cut them
        keys = [m.span() for m in SECRET_PATTERNS[0][1].finditer(cmd)]
        found = [x for x in found if not any(a < x[1] and x[0] < b for a, b in keys)]
    marks = []
    for v, e, kind in sorted(found):
        if marks and v < marks[-1][1]:   # inside the value before it, or overlapping it: one mark
            p = marks.pop()
            v, e, kind = p[0], max(e, p[1]), "dotenv" if "dotenv" in (kind, p[2]) else kind
        marks.append((v, e, kind))
    out, last = [], 0
    for v, e, kind in marks:
        out += [cmd[last:v], f"[REDACTED:{kind}]"]
        last = e
    out = _patterns("".join(out + [cmd[last:]]))[0]
    return out, out != cmd


def tool_input(tool, ti, content_capture="hashed"):
    """Map a raw tool_input dict to {field: content} per docs/privacy.md."""
    out, ti = {}, scrub(ti or {})
    dotenv = mentions_dotenv(*(ti.get(k) for k in ACTION_FIELDS),
                             *(x for k in ACTION_LISTS if isinstance(ti.get(k), list) for x in ti[k]))
    for k, v in ti.items():
        rk = redact_text(k)[0] if isinstance(k, str) else k
        if k in ("command", "commands"):   # a shell line, or several: a value hidden to where the shell ends it, and
            # with a .env file named, a heredoc body's KEY=value lines, the line's own values kept (redact_command)
            done = [redact_command(c, dotenv, own=False) if isinstance(c, str) else redact(c)
                    for c in (v if isinstance(v, list) else [v])]
            rv, red = [c for c, _ in done] if isinstance(v, list) else done[0][0], any(h for _, h in done)
        else:
            rv, red = redact(v, dotenv and k not in ACTION_FIELDS and k not in ACTION_LISTS)
        if content_capture == "full" or k in ALWAYS_CLEAR:
            out[rk] = content_value(rv, red)
        else:
            out[rk] = content_ref(rv, red)
    return out


def content(value, content_capture="hashed", dotenv=False):
    """Tool results, prompts and model text: hashed unless content_capture=full.
    dotenv=True (the call read or printed a .env file) redacts every KEY=value line."""
    rv, red = redact(scrub(value), dotenv)
    return content_value(rv, red) if content_capture == "full" else content_ref(rv, red)
