"""Redaction and the field-by-field privacy rules from docs/privacy.md.

Order is always: redact -> classify (value or hash reference) -> sign.
The same functions are used for the local ledger and for exported bundles, so a bundle can
never contain more than the ledger does.
"""
import bisect
import collections
import functools
import importlib
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
    out, n = _redact_assignments(out, counts)
    return out, hit or n > 0


def _secret_spans(s):
    """(start, end, kind) of what each SECRET_PATTERNS rule hides in `s`: redact_text's marks, found in `s` itself."""
    low = s.lower()
    for name, pat in SECRET_PATTERNS:
        if any(x in low for x in _PREFILTER.get(name, ("",))):
            spans = _connections(pat, s) if name == "connection_string" else _jwts(pat, s) if name == "jwt" else (
                (m.end(1) if pat.groups else m.start(), m.end()) for m in pat.finditer(s))
            yield from ((a, b, name) for a, b in spans)


_PW_STOP = re.compile(r"[\s@]")
_HOST_END = re.compile(r"\s|\Z")
_PORT = re.compile(r"[0-9]{1,5}[/?#]")   # host:port/path: a URL with no password, its path free to hold an "@"
_WEB = ("http", "https", "ws", "wss")   # schemes whose URLs carry addresses in a path or query, not a password


def _connections(prefix, s):
    """(start, end) of each scheme://user:password@host in `s`. The password runs to the first whitespace or "@" after
    the prefix; every prefix inside one such run shares that end, so it is found once per run and the scan stays
    linear however many prefixes the input repeats. In a web URL a port and a path after the prefix
    (http://host:8080/compose?to=a@b.example) are a URL, not a password; any other scheme's are a password
    (postgres://app:2024#Spring@db)."""
    pos, stop = 0, -1
    while True:
        m = prefix.search(s, pos)
        if not m:
            return
        if m.end() > stop:
            st = _PW_STOP.search(s, m.end())
            stop = st.start() if st else len(s)
        web = _PORT.match(s, m.end(), stop) and m.group().partition(":")[0].lower() in _WEB
        if stop > m.end() and s.startswith("@", stop) and not web:
            end = _HOST_END.search(s, stop + 1).start()
            if end > stop + 1:
                yield m.start(), end
                pos = end
                continue
        pos = m.start() + 1


def _marked(s, spans, name):
    """(`s` with each of `spans` marked as `name`, how many)."""
    out, last, n = [], 0, 0
    for a, b in spans:
        out += [s[last:a], f"[REDACTED:{name}]"]
        last, n = b, n + 1
    out.append(s[last:])
    return "".join(out), n


def _redact_connections(prefix, s):
    return _marked(s, _connections(prefix, s), "connection_string")


_WORD = re.compile(r"\w")


def _jwts(run, s):
    """(start, end) of each header.payload.signature token in `s`. run finds a run of token characters followed by two
    more dot-separated segments; the header starts at the run's leftmost "eyJ" after a non-word character (inside the
    run, a "-") and is at least 8 characters more. Each run is read once, so the scan stays linear however many
    "eyJ-" the input repeats."""
    pos = 0
    while True:
        m = run.search(s, pos)
        if not m:
            return
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
        yield at, m.end()
        pos = m.end()


def _redact_jwts(run, s):
    return _marked(s, _jwts(run, s), "jwt")


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


def _assignments(s, end=None, stop=None):
    """(start, end) of each value _redact_assignments hides in `s`: ASSIGNMENT's, found fast on large inputs (the
    keywords with str.find, then a look around each one). `end(name_end, m)`: where the value _AFTER's match `m` found
    after a name ending at `name_end` ends instead, or None to leave it; `stop(name_end)`: where its match may end at
    the latest (so a value cut short is read once: linear)."""
    last = b = 0
    for ks, ke in _kw_hits(s):
        if ks < last or ks < b:  # ks < b: same identifier as the previous hit, already handled
            continue
        a, b = ks, ke
        while a > 0 and s[a - 1] in _IDCH:
            a -= 1
        while b < len(s) and s[b] in _IDCH:
            b += 1
        am = _AFTER.match(s, b, stop(b) if stop else len(s))
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


def redact(obj, dotenv=False, _depth=0, counts=None, commands=(), noted=False, _shell=False, unclean=None):
    """Recursively redact every string (and every key). Returns (obj, was_redacted).
    Nesting beyond MAX_DEPTH is replaced by a marker instead of recursing without bound. `counts`: as for
    redact_text, and one under `nesting` per marker. `commands`: the (lower-case) names of arguments whose strings, at
    any depth, are shell lines (redact_command, not counted), but a list of strings under one other than `commands`
    is an argv: each word as a word (its program's place, a shell's script as a line: _argv_hows). `noted`: a string
    redaction may have hid more than values in starts with a line saying so (hidden), so a person reading it knows (an
    approver's copy). `unclean`: as for redact_command, for every command string."""
    if _depth > MAX_DEPTH:
        if counts is not None:
            counts["nesting"] += 1
        return NESTED, True
    if isinstance(obj, str):
        if _shell:
            out, hit = redact_command(obj, dotenv, how="line" if _shell in (True, "lines") else _shell, unclean=unclean)
        else:
            out, hit = redact_text(obj, counts)
            if dotenv:
                out, hit2 = redact_dotenv(out, counts)
                hit = hit or hit2
        return (hidden(obj, out) if noted else "") + out, hit
    if isinstance(obj, list):
        hows = _argv_hows(obj) if _shell is True and all(isinstance(x, str) for x in obj) else {}
        res = [redact(x, dotenv, _depth + 1, counts, commands, noted, hows.get(k, _shell), unclean)
               for k, x in enumerate(obj)]
        return [r[0] for r in res], any(r[1] for r in res)
    if isinstance(obj, dict):
        out, hit = {}, False
        for k, v in obj.items():
            rk, hk = redact_text(k, counts) if isinstance(k, str) else (k, False)
            name = k.lower() if isinstance(k, str) else None
            rv, hv = redact(v, dotenv, _depth + 1, counts, commands, noted,
                            _shell or name in commands and ("lines" if name == "commands" else True), unclean)
            out[rk] = rv
            hit = hit or hk or hv
        return out, hit
    return obj, False


def _argv_hows(words):
    """{index: how} for redact_command of each word of argv `words`: "line" for a shell's script (_code_words),
    "program" in a program's place (_programs), "code" where the reader can't follow it, else "word"."""
    code, programs = _code_words(_argv(words)), _programs(_argv(words))
    return {k: {"shell": "line", "code": "code"}.get(code.get(k), "program" if k in programs else "word")
            for k in range(len(words))}


# the rule that denies a held call whose approver's copy would hide more than clean values (approver_copy), its reason
# and what to do: v2's signer and v1's hook give the same
HIDDEN_CODE = "TK-HIDDEN-CODE"
HIDDEN_CODE_REASON = ("this command puts code behind text that looks like a secret, so a person can't see what "
                      "they'd approve")
HIDDEN_CODE_REMEDY = "Rewrite it without inline secrets (read them from the environment or a file the command names)."
HIDDEN_CODE_MESSAGE = (f"Blocked by Tracekit: {HIDDEN_CODE_REASON}; {HIDDEN_CODE_REMEDY[0].lower()}"
                       f"{HIDDEN_CODE_REMEDY[1:-1]} ({HIDDEN_CODE})")   # what v1 tells the agent


def screened(decision, ti, recorded, unclean):
    """v1's `decision` on a call with tool input `ti`, recorded as `recorded` (tool_input's, with `unclean`): a hold
    whose record, which its approver reads, would hide more than clean values in its command is denied
    (HIDDEN_CODE); a hold that hides values says how much (`note`, the summary's first line)."""
    if decision["decision"] != "ask":
        return decision
    if unclean:
        return {**decision, "decision": "deny", "rule_ids": decision["rule_ids"] + [HIDDEN_CODE],
                "reasons": decision["reasons"] + [f"{HIDDEN_CODE_REASON}. Instead: {HIDDEN_CODE_REMEDY}"]}
    shown = (recorded.get("command") or {}).get("value") if isinstance(recorded.get("command"), dict) else None
    return {**decision, "note": hidden(ti["command"], shown)} if isinstance(ti.get("command"), str) and \
        isinstance(shown, str) else decision


def approver_copy(args, dotenv, commands):
    """(the approver's copy of a held call's parsed `args`: redact with each string under an argument named in
    `commands` read as a shell line or an argv, and noted; whether it hides more than clean values in a command, one
    word of plain text no shell reads as more each, which no person can approve the call by: redact_command's
    `unclean`)."""
    unclean = []
    return redact(args, dotenv, commands=commands, noted=True, unclean=unclean)[0], bool(unclean)


NOTE_CHARS = 256   # what redaction hides, past which a person is told how much: more than a few secrets' worth
# the note's own line, a shell comment: a shell line's readers (findings, why) parse what follows it as before
NOTE = "# [{} characters hidden by redaction]\n"
NOTE_CODE = "# [{} characters hidden by redaction, among them {}, which a shell can read as code]\n"
_SHELL_READS = re.compile(r"[\s;&|<>()`$\\'\"]")
_CODE_READS = "\n;&|<>()$`"   # of those, the ones that make code


def hidden(before, after):
    """The line that tells the person reading `after` how many characters redaction took out of string `before` to give
    it (marks aside), when they should be told, else "": when it took more than NOTE_CHARS, or a blank, a line end, a
    quote, a backslash or another character the shell reads, so it may be more than one value (words, lines, code);
    naming each of _CODE_READS it took (NOTE_CODE)."""
    b, a = MARK.sub("", before), MARK.sub("", after)
    took = collections.Counter(_SHELL_READS.findall(b)) - collections.Counter(_SHELL_READS.findall(a))
    n = len(b) - len(a)
    if not (n > NOTE_CHARS or n > 0 and took):
        return ""
    code = ["a line break" if c == "\n" else c for c in _CODE_READS if c in took]
    return NOTE_CODE.format(n, " ".join(code[:-1]) + " and " + code[-1] if code[1:] else code[0]) if code else \
        NOTE.format(n)


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
_SPECIAL_DQ = re.compile(r'["\\$`]')   # and inside "...": what a shell running a "..." script reads apart from it
_ENDS = re.compile(r"(?:[ \t;|]|&(?!>))+")   # blanks and control operators, read at once (&> is a redirection)
_REDIRECT = re.compile(r"&>>?|<>|<&|>&|>\||>>|[<>]")   # (a heredoc's and a herestring's aside)
_FD = re.compile(r"[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\}")   # the descriptor a redirection names before it: 2>, {fd}>
_BLANKS = str.maketrans("", "", " \t")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")   # a KEY, as DOTENV_LINE names it
_EXPANDS = re.compile(r"\$\(\(|\$\(|\$\{|`")   # where code starts in a heredoc body bash expands
_CLOSES = {"$((": (")", "(", 2), "$(": (")", "("), "${": ("}", "{"), "`": ("`",)}   # _past's arguments past each
_CASE = re.compile(r"case(?=[ \t\n;&|<>()]|\Z)")
_NAME_EQ = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*=")   # a word's KEY=, named as DOTENV_LINE names it
_ARRAY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")   # what an array's (…) follows: x=(1 2), x+=(3)
_LEAD = re.compile(r"[ \t]*(?:export\s+)?")   # what DOTENV_LINE reads before a KEY
_SEP = re.compile(r"\s*[=:]\s*[\"']?")   # what ASSIGNMENT reads between a name and its value
# what on a line may give a program's name another meaning (a function, an alias, PATH) or send what a program prints
# to one that runs it (>(…), a coprocess, a named pipe): no heredoc on it is data
_UNSURE = re.compile(r"\b(?:alias|enable|hash|function|coproc|mkfifo|mknod)\b|\(\s*\)|>\(|\b(?:BASH_ENV|ENV|PATH)\+?=")
_DEPTH = 8   # code read as a shell line of its own inside another this deep: deeper, the reader can't follow it
# $( <( >( open at once, past which the reader doesn't follow the line: each holds the line's state, which made a
# line of 256 KiB of "$( take 0.6 s with the garbage collector on
_FRAMES = 64
_EVERY = ("eval", "ssh")   # each word after one is code a shell reads as a line: eval's, ssh's remote command
# what a hidden value may not hold in a held call's copy: a blank or a character the shell reads (a separator, a
# quote, an expansion, a pattern)
_CODE_LIKE = re.compile(r"[\s|&;()<>'\"\\$`{}*?\[\]]")
_MADE = re.compile(r"\$(?!\{?IFS\b)|`")   # an expansion that makes text (IFS only splits it)
_REFERENCE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})")   # a variable's name, no value


def _past(s, k, close, open_="", depth=1, end=None):
    """Past the `close` that closes the `depth` brackets open before `k` (each `open_` opens one more), else `end`
    (len(s)); a backslash keeps the character after it."""
    end = len(s) if end is None else end
    find = re.compile("[" + re.escape(open_ + close) + r"\\]").search
    while depth:
        m = find(s, k, end)
        if not m:
            return end
        k = m.end() + (m.group() == "\\")
        depth += (m.group() == open_) - (m.group() == close)
    return min(k, end)


def _delimiter(s, k, end):
    """(the end line a heredoc's `<<` names, quotes removed; whether `<<-` strips its tabs; whether a quote or a
    backslash in it keeps the body as written; where the word ends) for the `<<` just before `k`, or None when it names
    none before `end`."""
    tabs = s.startswith("-", k, end)
    k += tabs
    while k < end and s[k] in " \t":
        k += 1
    word, start = [], k
    while k < end and s[k] not in " \t\n;&|<>()":
        if s[k] in "'\"":
            e = s.find(s[k], k + 1, end)
            if e < 0:
                return None
            word.append(s[k + 1:e])
            k = e + 1
        else:
            k += s[k] == "\\"
            word.append(s[k:k + 1])
            k += 1
    return ("".join(word), tabs, any(c in "'\"\\" for c in s[start:k]), min(k, end)) if word else None


def _end_line(s, k, end, tabs, z):
    """(where the end line `end` of the heredoc body starting at `k` starts, where it ends), both `z` when no line
    before `z` ends it; `tabs`: it may start with tabs (`<<-`)."""
    while k < z:
        e = s.find("\n", k, z)
        e = z if e < 0 else e
        if (s[k:e].lstrip("\t") if tabs else s[k:e]) == end:
            return k, e
        k = e + 1
    return z, z


@functools.cache
def _policy(name):
    """tracekit.policy2's module `name` (shell, engine), imported once and only when a command needs it: the hook that
    records a plain command never pays for the parser."""
    return importlib.import_module("tracekit.policy2." + name)


class _At(str):
    """A command's word as bash gives it, knowing its place among the command's words (`at`), which shell's readers of
    a command return as they were given it."""


def _argv(words):
    """`words`, each an _At knowing its place."""
    out = [_At(w) for w in words]
    for k, w in enumerate(out):
        w.at = k
    return out


def _words(s, spans):
    """The words at `spans` of shell line `s` as bash gives them, near enough to name a program and its options:
    without their quotes and backslashes (_argv)."""
    return _argv(s[a:b].translate(_policy("shell")._UNQUOTED) for a, b in spans)


def _code_words(words):
    """{index: how} of each of a command's `words` (_words) that is code: a shell's -c script, su's or script's -c and
    each word after eval or ssh, which a shell reads as a line of its own ("shell"); an interpreter's -c or -e program
    ("interp"); another shell's -c, and every word after more such programs than are read one by one ("code");
    wherever in the command their program is named (sudo sh -c, docker exec c sh -c, xargs python3 -c)."""
    shell = _policy("shell")
    found, runs = {}, 0
    for j, w in enumerate(words):
        name = shell.base_name(w)
        kind = shell._kind(name)
        if not (kind or name in _EVERY or name in shell.SHELLS or name in shell.DASH_C or name in shell.FOREIGN_SHELLS):
            continue
        rest, runs = words[j + 1:j + 65], runs + 1
        if name in _EVERY or len(words) > j + 65 or runs > 16:
            found.update(dict.fromkeys(range(j + 1, len(words)), "shell" if name in _EVERY else "code"))
            break
        if name in shell.SHELLS:
            mode, script = shell._shell_mode(rest, name)
            got = [script] if mode == "c" else []
        elif kind:
            got = shell._code_arg(kind, rest)
            got = got if isinstance(got, list) else [got]
        else:
            got = [shell._dash_c(rest)]
        how = "shell" if name in shell.SHELLS or name in shell.DASH_C else "interp" if kind else "code"
        for g in got:   # the word itself, or the option word it is part of (-c'…')
            k = g.at if isinstance(g, _At) else next(
                (k for k in range(j + 1, len(words)) if g and words[k][:1] == "-" and words[k].endswith(g)), None)
            if k is not None:
                found[k] = how if found.get(k, how) == how else "code"
    return found


def _programs(words):
    """The indexes of a command's `words` (_words) in a program's place: its first that isn't an assignment, the one
    each wrapper or runner there runs (sudo, env, xargs, uv run: shell._unwrap) and the one after find's -exec, in
    turn."""
    shell = _policy("shell")
    out, todo = set(), [0]
    while todo:
        i = todo.pop()
        while i < len(words) and shell._ASSIGN.match(words[i]):
            i += 1
        if i >= len(words) or i in out:
            continue
        out.add(i)
        name, args = shell.base_name(words[i]), words[i + 1:i + 65]
        runner = name.partition("@")[0]
        wrapper = name if name in shell.WRAPPERS else runner if runner in shell.RUNNERS and \
            shell.runner_at(runner, args) else None
        todo += [i + 1 + len(args) - len(inner) for inner in shell._unwrap(wrapper, args) if inner] if wrapper else []
        todo += [i + 2 + k for k, a in enumerate(args)
                 if name == "find" and a in ("-exec", "-execdir", "-ok", "-okdir")]
    return out


def _stdin(stages, nested):
    """How the heredoc or herestring each of pipeline `stages` (each a command's _words) reads is read: "data" when a
    program that reads only data (shell.DATA_ONLY: cat, tee; awk's or sed's program aside) reads it, and so does each
    stage after it, outside a substitution, a subshell or a block, on a line _UNSURE finds nothing on (not `nested`);
    "shell" when a shell, at or batch reads its script from stdin there or after it and no interpreter does; "interp"
    when an interpreter does and no shell; else "code"."""
    shell = _policy("shell")
    out, data, sh, other = [], True, False, False
    for words in reversed(stages):
        names = [shell.base_name(w) for w in words]
        k = next((k for k, w in enumerate(words) if not shell._ASSIGN.match(w)), len(words))
        kind = k < len(words) and shell._kind(names[k])
        data = data and k < len(words) and names[k] in shell.DATA_ONLY and not (
            kind and shell._reads_stdin(kind, words[k + 1:]))
        sh = sh or any(x in ("at", "batch") or x in shell.SHELLS and shell._shell_mode(words[j + 1:j + 65], x)[0] ==
                       "stdin" for j, x in enumerate(names))
        other = other or any(shell._kind(x) not in (None, "awk", "sed") for x in names)
        out.append("data" if data and not nested else "shell" if sh and not other else "interp" if other and not sh
                   else "code")
    return out[::-1]


def _command():
    """A simple command as _read_shell reads it: its words' and herestrings' spans; whether it reads a heredoc, and
    has a quote or a backslash in a word (so a word may be code the line itself doesn't read); how its stdin is read."""
    return {"words": [], "here": [], "docs": False, "quoted": False, "how": None}


class _Reading:
    """Shell line `s` as _read_shell reads it. `cut`, `body`, `unsure`, `quote` and `inq`: bytearrays one longer than
    `s`. `cut`: 1 at each place a hidden value ends at the latest, which is the first character of each blank run,
    control operator and redirection outside quotes, each line end, each start of code ($( <( >( ` ${), the end of a
    heredoc's body and of a script read on its own, and the end; text, what a program reads as data or as an
    interpreter's program (a comment, a heredoc body cat or python3 reads, python3 -c's code, a word of an argv), has
    none, so a value there is hidden as far as its rule reads, as in content. `body`: 1 in each heredoc body. `unsure`:
    1 in what the reader can't read as bash does (_read_shell). `quote`: 1 at each quote that opens or closes a part
    ($'…''s at its $); `inq`: 1 in each part after its opening quote, to its closing one. `starts`: where each word
    outside quotes may start. `pipes`: each pipeline's commands' word spans, of all the code read as a shell line.
    `subst`: whether one has a process substitution."""

    def __init__(self, s):
        n = len(s)
        self.s, self.starts, self.pipes, self.subst = s, [], [], False
        self.cut, self.body, self.unsure, self.quote, self.inq = (bytearray(n + 1) for _ in range(5))
        self.cut[n] = 1


def _mark(a, start, end):
    a[start:end] = b"\1" * (end - start)


def _read_shell(s, how="line"):
    """Shell line `s` as bash reads it (or, `how` "word", one word of data): a _Reading. Code in a word or a heredoc
    is read again as code (_code_words, _stdin): a heredoc, herestring or word a shell reads as a line of its own (sh
    -c's script, eval's words), as such a line; an interpreter's program, as text. Unsure: what the reader can't read
    exactly as bash does: what follows a heredoc's end word with an expansion or a line continuation in it ($'EOF'), a
    "..." script with a backslash, $ or ` (which the shell running the line reads first), what another program reads as
    code (ssh's stdin, fish -c's script), backquotes, ${...}, arithmetic, an array's (...), the rest of a $(...) once a
    `case` starts in it, a script nested more than _DEPTH deep.
    lean: a command other than those _code_words and _programs name that runs a word as code (watch, trap, git's
    aliases) has it read as a word; a value there is hidden as far as its quotes and its rule read, and a held call's
    copy hides none with a blank or a shell character in it (approver_copy)."""
    r = _Reading(s)
    cut, body, unsure, quote, inq, starts = r.cut, r.body, r.unsure, r.quote, r.inq, r.starts
    plain = not _UNSURE.search(s)
    if how != "line":
        return r

    def unread(a, b):   # code the reader doesn't follow: a value ends where it starts
        cut[a] = 1
        _mark(unsure, a, b)
        return b

    def read_code(a, b, how, depth):
        """[a, b) is code: read as a shell line of its own (`how` "shell"), text (an interpreter's), or unsure."""
        cut[b] = 1
        if how == "shell" and depth < _DEPTH:
            inq[a:b + 1] = bytes(b + 1 - a)
            read(a, b, depth + 1)
        elif how != "interp":
            _mark(unsure, a, b)

    def word_code(a, b, how, depth):
        """The word at [a, b) is code: what one '…', or "…" with no \\ $ or `, holds read as `how` says; else the
        word read as text (an interpreter's) or unsure."""
        if how == "shell" and b - a > 1 and s[a] in "'\"" and quote.find(1, a + 1, b) == b - 1 and (
                s[a] == "'" or not _SPECIAL_DQ.search(s, a + 1, b - 1)):
            read_code(a + 1, b - 1, how, depth)
        elif how != "interp":
            _mark(unsure, a, b)

    def finish(pipe, nested, depth):
        """Pipeline `pipe` is read: what reads each heredoc and herestring of its commands, and which words are code."""
        r.pipes.append([c["words"] for c in pipe])
        if not any(c["quoted"] or c["here"] or c["docs"] for c in pipe):
            return
        words = [_words(s, c["words"]) for c in pipe]
        for c, how in zip(pipe, _stdin(words, nested)):
            c["how"] = how
        for c, ws in zip(pipe, words):
            for k, how in _code_words(ws).items():
                word_code(*c["words"][k], how, depth)
            for a, b in c["here"]:
                if c["how"] != "data":
                    word_code(a, b, c["how"], depth)

    def read(a, z, depth):
        cmd, frames, pending = _command(), [], []   # frames: the line's state around each $( <( >(, to go on with
        pipe, dq, word, redir, ws, i, parens, cases = [cmd], False, False, None, a, a, 0, 0

        def nested():
            return bool(frames) or parens > 0 or cases > 0 or depth > 0 or not plain

        def end_word(e):   # the word at [ws, e): a command's, a herestring, or a file a redirection names
            nonlocal word, redir, cases
            word = False
            if redir == "<<<":
                cmd["here"].append((ws, e))
            elif not redir and not (s.startswith(("<", ">"), e) and _FD.fullmatch(s, ws, e)):
                if not cmd["words"]:
                    cases += {"case": 1, "esac": -(cases > 0)}.get(s[ws:e], 0)
                cmd["words"].append((ws, e))
            redir = None

        def end_command(piping):   # the command ends; it pipes into the next one, or its pipeline ends too
            nonlocal cmd, pipe
            if not piping:
                finish(pipe, nested(), depth)
                pipe = []
            cmd = _command()
            pipe.append(cmd)

        def frame(at):   # a $( <( >( opens at `at`, its code a line of its own, a word of this line (or part of one)
            nonlocal cmd, pipe, dq, word, redir
            if len(frames) >= _FRAMES:
                _mark(unsure, at, z)
                return z
            frames.append([0, True, dq, ws if word else at, cmd, pipe, redir])
            cmd, dq, word, redir = _command(), False, False, None
            pipe = [cmd]
            return at + 2

        while i < z:
            m = (_SPECIAL_DQ if dq else _SPECIAL).search(s, i, z)
            j = m.start() if m else z
            if dq:
                _mark(inq, i, j)
            elif j > i and not word:
                if frames and _CASE.match(s, i):
                    _mark(unsure, i, z)
                    i = z
                    break
                starts.append(i)
                ws, word = i, True
            i = j
            if i == z:
                break
            c = s[i]
            if not dq and c in "<>" and s.startswith("(", i + 1):   # a process substitution: a word, or part of one
                cut[i], r.subst = 1, True
                i = frame(i)
                continue
            if not dq and c == "(" and word and _ARRAY.fullmatch(s, ws, i):   # an array's values: one word to bash
                e = _past(s, i + 1, ")", "(", end=z)
                _mark(unsure, i, e)
                i = e
                continue
            if not dq and (c in " \t\n;&|<>()" or c == "#" and not word):
                if word:
                    end_word(i)
                cut[i] = 1
                if c in "<>" or s.startswith("&>", i):   # a redirection: the word after it names a file, or is text
                    if s.startswith("<<<", i):
                        redir, e = "<<<", i + 3
                    elif s.startswith("<<", i) and (d := _delimiter(s, i + 2, z)):   # a heredoc: after the line
                        if re.search(r"[$`]|\\\n", s[i + 2:d[3] + 1]):   # its end line isn't the word as written
                            _mark(unsure, i, z)
                            i = z
                            break
                        pending.append((*d[:3], cmd))
                        cmd["docs"], e = True, d[3]
                    else:
                        e = _REDIRECT.match(s, i, z).end()
                        redir = s[i:e]
                    i = e
                    continue
                if c in " \t;&|":
                    e = _ENDS.match(s, i, z).end()
                    ops = s[i:e].translate(_BLANKS)
                    if ops:
                        end_command(ops in ("|", "|&"))
                    i = e
                    continue
                if c == "#":   # a comment, to its line's end: text
                    e = s.find("\n", i, z)
                    i = z if e < 0 else e
                    continue
                if c == "\n":   # the bodies of the heredocs this line opened follow it, each to its end line
                    end_command(False)   # (a pipeline the line ends in | goes on after them: its last stage reads none)
                    i += 1
                    for end, tabs, kept, owner in pending:
                        b, e = _end_line(s, i, end, tabs, z)
                        how = owner["how"] or "code"   # (one a $(...) opened that a line end in another ends: unsure)
                        _mark(body, i, b)
                        if how == "data":
                            while not kept and (x := _EXPANDS.search(s, i, b)):   # its $(...) and `...` run now
                                i = unread(x.start(), min(_past(s, x.end(), *_CLOSES[x.group()], end=b), b))
                        else:
                            read_code(i, b, how, depth)
                        cut[b] = cut[e] = 1   # its end line stays in view
                        i = min(e + 1, z)
                    pending = []
                    continue
                if s.startswith("((", i):   # arithmetic
                    i = unread(i, _past(s, i + 2, ")", "(", 2, end=z))
                    continue
                if c == ")" and frames and not frames[-1][0]:   # the end of a $( <( >(: its line is read
                    finish(pipe, True, depth)
                    _, word, dq, ws, cmd, pipe, redir = frames.pop()
                else:   # a subshell's ( or ), or a case pattern's ): the command before it ends where it is
                    end_command(False)
                    if frames:
                        frames[-1][0] += 1 if c == "(" else -1
                    else:
                        parens = max(0, parens + (1 if c == "(" else -1))
                i += 1
                continue
            if not (dq or word):   # a part of a word: in "...", or quoted, escaped or expanded outside quotes
                starts.append(i)
                ws, word = i, True
            if dq:   # what bash reads in "...": in its part, as its closing quote is
                _mark(inq, i, i + 1 + (c == "\\"))
            if c == "\\":
                cmd["quoted"] = True
                i += 2
            elif c == "'":
                cmd["quoted"], quote[i] = True, 1
                e = s.find("'", i + 1, z)
                e = z if e < 0 else e
                if e < z:
                    quote[e] = 1
                _mark(inq, i + 1, e + 1)
                i = e + 1
            elif c == '"':
                cmd["quoted"], quote[i] = True, 1
                dq = not dq
                i += 1
            elif c == "`":
                i = unread(i, _past(s, i + 1, "`", end=z))
            elif s.startswith("$((", i):
                i = unread(i, _past(s, i + 3, ")", "(", 2, end=z))
            elif s.startswith("${", i):
                i = unread(i, _past(s, i + 2, "}", "{", end=z))
            elif s.startswith("$(", i):   # code: it ends a value, and is read as a line of its own
                cut[i] = 1
                i = frame(i)
            elif s.startswith("$'", i) and not dq:
                cmd["quoted"], quote[i] = True, 1
                e = _past(s, i + 2, "'", end=z)
                closed = s.startswith("'", e - 1) and e - 1 > i + 1
                if closed:
                    quote[e - 1] = 1
                _mark(inq, i + 1, e + (not closed))
                i = e
            else:   # a $ alone, or a parameter: in the value it is in ($IFS: the value hides it, so a held call denies)
                i += 1
        if word:
            end_word(min(i, z))
        while frames:
            finish(pipe, True, depth)
            pipe = frames.pop()[5]
        finish(pipe, nested(), depth)

    read(0, len(s), 0)
    return r


def _feeds(r, marks):
    """(program, fed) of _Reading `r` with `marks` (sorted spans), for a held call's copy: `program`, 1 in each word in
    a program's place (_programs) of a command a mark is in, of code read as a shell line; `fed`, whether the line hands
    text to code the reader doesn't follow: a program, a shell's script or eval's word made by an expansion, a source
    or . with one (`$X`, `eval "$x"`, `sh -c "$c"`; $IFS only splits), a stage after the first that may run what it
    reads (`| sh`, `| xargs rm`: engine._may_run_input), or a process substitution on a line where a shell or an
    interpreter runs."""
    shell, s = _policy("shell"), r.s
    program, fed, starts = bytearray(len(s) + 1), False, [v for v, _, _ in marks]
    for pipe in r.pipes:
        for k, spans in enumerate(pipe):
            if not spans:
                continue
            lo, hi = spans[0][0], spans[-1][1]
            j = bisect.bisect_left(starts, lo)
            marked = j > 0 and marks[j - 1][1] > lo or j < len(starts) and starts[j] < hi
            made = bool(_MADE.search(s, lo, hi))
            if not (marked or made or k or r.subst):
                continue
            words = _words(s, spans)
            for i in _programs(words):
                _mark(program, *spans[i])
                name, raw = shell.base_name(words[i]), s[spans[i][0]:spans[i][1]]
                fed = fed or bool(_MADE.search(raw)) or r.subst and (
                    name in shell.SHELLS or name in ("source", ".") or shell._kind(name) not in (None, "awk", "sed")) \
                    or made and name in ("source", ".") \
                    or k > 0 and _policy("engine")._may_run_input([name] + words[i + 1:])
            fed = fed or made and any(how == "shell" and _MADE.search(s, *spans[i])
                                      for i, how in _code_words(words).items())
    return program, fed


def _rank(kind, first=("private_key", "dotenv", "assignment")):
    """Which of two marks one mark that covers both is named for: the first of `first` among them, else the earlier."""
    return first.index(kind) if kind in first else len(first)


def redact_command(cmd, dotenv=False, own=True, how="line", unclean=None):
    """(shell line `cmd` as an approver's copy shows it, whether it changed): what each SECRET_PATTERNS rule hides, the
    value of each secret-looking KEY=value (ASSIGNMENT's) and, with `dotenv`, of every KEY=value; in code read as a
    shell line, each only up to where the shell ends its word (_Reading.cut) and never past a quote it didn't open, so
    what runs after it stays in view; in text (a body cat or python3 reads, a comment) and where the reader is unsure,
    as far as its rule reads, as in content (with `dotenv`, each KEY=value line's to its line's end);
    a private key whole. `own` False: with `dotenv`, only a heredoc body's KEY=value lines, the line's own values kept
    (as v1 records a command). `how`: "line", or `cmd` is an argv's word: "word" (data), "program" (in a program's
    place) or "code" (the reader can't follow it). `unclean`, a list: gets True when a mark hides more than a clean
    value, one word of plain text no shell reads as more (approver_copy): what it hides holds a blank or a shell
    character, is in a program's place or where the reader is unsure, or the line runs code the reader doesn't follow
    (_feeds)."""
    r = _read_shell(cmd, "word" if how != "line" else how)
    cut, quote, inq = r.cut, r.quote, r.inq

    def bounded(v, e):
        """[v, e) cut where the shell ends the word at v, or None when nothing is left of it."""
        k = cut.find(1, v, e)
        if k == v:
            return None
        e = e if k < 0 else k
        if quote.find(1, v, e) >= 0:   # a quote it didn't open: its own part's closing one, or one it opens and leaves
            e = quote.find(1, v, e) if inq[v] else quote.rfind(1, v, e) if inq[e] else e
        return e if e > v else None

    def value(b, v, e):
        """bounded(v, e) for a value after a name ending at `b`, or None when the shell ends the line, or the name's
        `=`, before it: `A= cmd` runs cmd."""
        gap = cmd[b:v]
        if ("\n" in gap or gap[:1] == "=") and any(c in " \t\n" and cut[k] for k, c in enumerate(gap, b)):
            return None
        return bounded(v, e)

    def stop(b):   # where ASSIGNMENT's value after a name ending at `b` ends at the latest: its word's end
        m = _SEP.match(cmd, b)
        return cut.find(1, m.end()) if m else b

    found = [(v, e, "assignment") for v, e in _assignments(cmd, lambda b, m: value(b, m.start(3), m.end(3)), stop)]
    for v, e, name in _secret_spans(cmd):
        if e := e if name == "private_key" else bounded(v, e):   # a private key whole: every line of it
            found.append((v, e, name))
    if dotenv:
        for p in r.starts:   # a word KEY=value: its value is the rest of the word, or what its quotes hold
            if (own or r.body[p]) and (m := _NAME_EQ.match(cmd, p)):
                v, e = m.end(), cut.find(1, m.end())
                e -= 2 if cmd.startswith("\\\n", e - 2) else 0
                q = v + 1 + cmd.startswith("$'", v)
                if cmd.startswith(("'", '"', "$'"), v) and quote.find(1, q, e) == e - 1:
                    v, e = q, e - 1
                if e := bounded(v, e):
                    found.append((v, e, "dotenv"))
        words = set(r.starts)
        for m in DOTENV_LINE.finditer(cmd):   # a line KEY=value in a body, in quotes, or in text
            k = _LEAD.match(cmd, m.start(1)).end()
            if (own or r.body[m.start(3)]) and k not in words and (e := value(_NAME.match(cmd, k).end(), m.start(3),
                                                                                m.end(3))):
                found.append((m.start(3), e, "dotenv"))
    marks = []
    for v, e, kind in sorted(x for x in found if not _REFERENCE.fullmatch(cmd, x[0], x[1])):   # ($TOKEN: no secret)
        if marks and v < marks[-1][1]:   # inside the value before it, or overlapping it: one mark
            p = marks.pop()
            v, e, kind = p[0], max(e, p[1]), min(p[2], kind, key=_rank)
        marks.append((v, e, kind))
    if unclean is not None and marks:
        program, fed = (bytearray(len(cmd) + 1), False) if how != "line" else _feeds(r, marks)
        if fed or how in ("program", "code") or any(_CODE_LIKE.search(cmd, v, e) or r.unsure.find(1, v, e) >= 0 or
                                       program.find(1, v, e) >= 0 for v, e, _ in marks):
            unclean.append(True)
    out, last = [], 0
    for v, e, kind in marks:
        out += [cmd[last:v], f"[REDACTED:{kind}]"]
        last = e
    out = "".join(out + [cmd[last:]])
    return out, out != cmd


def tool_input(tool, ti, content_capture="hashed", unclean=None):
    """Map a raw tool_input dict to {field: content} per docs/privacy.md. `unclean`: as for redact_command, for each
    command."""
    out, ti = {}, scrub(ti or {})
    dotenv = mentions_dotenv(*(ti.get(k) for k in ACTION_FIELDS),
                             *(x for k in ACTION_LISTS if isinstance(ti.get(k), list) for x in ti[k]))
    for k, v in ti.items():
        rk = redact_text(k)[0] if isinstance(k, str) else k
        if k in ("command", "commands"):   # a shell line, or several: a value hidden to where the shell ends it, and
            # with a .env file named, a heredoc body's KEY=value lines, the line's own values kept (redact_command)
            done = [redact_command(c, dotenv, own=False, unclean=unclean) if isinstance(c, str) else redact(c)
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
