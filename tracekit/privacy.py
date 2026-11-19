"""Redaction and the field-by-field privacy rules from docs/privacy.md.

Order is always: redact -> classify (value or hash reference) -> sign.
The same functions are used for the local ledger and for exported bundles, so a bundle can
never contain more than the ledger does.
"""
import collections
import functools
import importlib
import json
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
# KEY=value / key: value assignments whose key looks secret (.env files, configs, commands), the value in quotes too
# (a shell's $'...' as well)
ASSIGNMENT = re.compile(
    r"(?im)\b([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIALS?)[A-Z0-9_]*)"
    r"(\s*[=:]\s*)((?:\$'|[\"'])?)([^\s\"'#]{4,})")


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


_AFTER = re.compile(r"(\s*[=:]\s*)((?:\$'|[\"'])?)([^\s\"'#]{4,})")
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


def redact(obj, dotenv=False, _depth=0, counts=None, commands=(), noted=False, _shell=False, unclean=None, own=True,
           budget=None):
    """Recursively redact every string (and every key). Returns (obj, was_redacted).
    Nesting beyond MAX_DEPTH is replaced by a marker instead of recursing without bound. `counts`: as for
    redact_text, and one under `nesting` per marker. `commands`: the (lower-case) names of arguments whose strings, at
    any depth, are shell lines (redact_command, not counted), but a list of strings under one other than `commands`
    is an argv: each word as a word (its program's place, a shell's script as a line: _argv_hows). TK-S012's code
    arguments (CODE_ARGS) are an interpreter's program, its args or argv (ARGV_ARGS) an argv, after the program its
    call names. `noted`: a string redaction may have hid more than values in starts with a line saying so (hidden), so
    a person reading it knows (an approver's copy). `unclean`: as for redact_command, for every command string; and it
    gets True when redaction takes a character that makes code out of any other string or any key (_coded: a sql
    query, a program's code), or hides a value that starts a word of its own there (_spaced: `A=TOKEN: reboot`).
    `own`: as for redact_command; `budget`: the call's Budget."""
    if _depth > MAX_DEPTH:
        if counts is not None:
            counts["nesting"] += 1
        return NESTED, True
    if isinstance(obj, str):
        if _shell:
            out, hit = redact_command(obj, dotenv, own, "line" if _shell in (True, "lines") else _shell, unclean, budget)
        else:
            out, hit = redact_text(obj, counts)
            if dotenv:
                out, hit2 = redact_dotenv(out, counts)
                hit = hit or hit2
            if hit and unclean is not None and (_coded(obj, out) or _spaced(obj, dotenv)):
                unclean.append(True)
        return (hidden(obj, out) if noted else "") + out, hit
    if isinstance(obj, list):
        hows = _argv_hows(obj, budget) if _shell is True and all(isinstance(x, str) for x in obj) else {}
        res = [redact(x, dotenv, _depth + 1, counts, commands, noted, hows.get(k, _shell), unclean, own, budget)
               for k, x in enumerate(obj)]
        return [r[0] for r in res], any(r[1] for r in res)
    if isinstance(obj, dict):
        out, hit = {}, False
        for k, v in obj.items():
            rk, hk = redact_text(k, counts) if isinstance(k, str) else (k, False)
            if hk and unclean is not None and (_coded(k, rk) or _spaced(k)):
                unclean.append(True)
            name = k.lower() if isinstance(k, str) else None
            how = _shell or name in commands and ("lines" if name == "commands" else True)
            if not how and k in CODE_ARGS and isinstance(v, str):
                rv, hv = redact(v, dotenv, _depth + 1, counts, commands, noted, "interp", unclean, own, budget)
            elif not how and k in ARGV_ARGS and isinstance(v, list) and all(isinstance(x, str) for x in v):
                program = next((obj[p] for p in _PROGRAM_ARGS if isinstance(obj.get(p), str)), None)
                rv, hv = redact([program, *v] if program else v, dotenv, _depth + 1, counts, commands, noted, True,
                                unclean, own, budget)
                rv = rv[1:] if program else rv
            else:
                rv, hv = redact(v, dotenv, _depth + 1, counts, commands, noted, how, unclean, own, budget)
            out[rk] = rv
            hit = hit or hk or hv
        return out, hit
    return obj, False


# the arguments TK-S012 holds as what a code runner, a notebook or a process runs (policy2/packs/server-core.yaml):
# code, where any hidden value is unclean, and an argv, run by the program the call names beside it
CODE_ARGS = frozenset(("code", "python_code", "source", "cell_source", "cell_content", "input"))
ARGV_ARGS = frozenset(("args", "argv"))
_PROGRAM_ARGS = ("command", "cmd", "program", "executable")


def _spaced(s, dotenv=False):
    """Whether a value redaction hides in text `s` (ASSIGNMENT's; with `dotenv`, DOTENV_LINE's) starts after a blank
    that follows its name (`TOKEN: x`, `password = x`): a word of its own, which a shell that reads the text runs."""
    for v, _ in _assignments(s):
        k = v
        while k and s[k - 1] in "=:\"'$" or k and s[k - 1].isspace():
            k -= 1
        if any(c.isspace() for c in s[k:v]):
            return True
    return dotenv and any(re.search(r"\s", m.group(1)[_LEAD.match(m.group(1)).end():]) for m in DOTENV_LINE.finditer(s))


def _argv_hows(words, budget=None):
    """{index: how} for redact_command of each word of argv `words`, as the policy's parser reads the argv (_Facts,
    each place an index): "line" for a script a shell runs (sh -c's, watch's), "interp" for an interpreter's program
    (and each word of an interpreter the parser can't read: deno), "program" for a program's name or a script file a
    shell or interpreter runs, "code" for one a program that may run it gets (not one of DATA_READERS: sqlite3, vim)
    or one of several the parser joins into code (ssh's), else "word"; every word "code" when the parser can't read
    the argv, or reads code in it it can't place."""
    facts = _Facts.of(argv=words, budget=budget)
    every = dict.fromkeys(range(len(words)), "code")
    if not facts.sure:
        return every
    hows = dict.fromkeys(range(len(words)), "word")
    for reads in (False, True):   # a word any data reader gets is data, whichever other command gets it too
        for name, spans in facts.args:
            for a, _, data in spans:
                if data == reads:
                    hows[a] = "word" if reads else "interp" if _unread_interpreter(name) else "code"
    for how, at, inner, within in facts.placed:
        if within is not None:   # in a word its own line reading reads
            continue
        if at is None:
            return every
        for k in range(*at):
            hows[k] = "code" if inner is None else "line" if how == "shell" else "interp"
    for at, within in facts.programs:
        if within is None and at is None:
            return every
        if within is None:
            hows[at[0]] = "program"
    return hows


# the arguments a call's command is in, at any depth and in any case (the engine's, TK-S010's), and the one a typed
# call's line is in (typed_lines): each read as the shell line or the argv it is, by the engine and by an approver's copy
COMMAND_KEYS = frozenset(("command", "commands", "cmd", "cmds", "script", "shell_command"))
TYPED_LINE = "typed_line"


def typed_lines(tool, args):
    """The arguments of a call besides COMMAND_KEYS that the signer decides as a shell line (signer.service.evaluate),
    which its approver's copy and v1's record read as one too: `typed_line` (the line typed keys put text into), and
    process_manage's `data` (what a write or a submit types into a running process)."""
    if not isinstance(args, dict):
        return []
    return [TYPED_LINE] * isinstance(args.get(TYPED_LINE), str) + ["data"] * (
        tool == "process_manage" and args.get("action") in ("write", "submit") and isinstance(args.get("data"), str))


# the rule that denies a held call whose approver's copy would hide more than clean values (approver_copy), its reason
# and what to do: v2's signer and v1's hook give the same; v1 also denies a hold whose summary would be cut
HIDDEN_CODE = "TK-HIDDEN-CODE"
HIDDEN_CODE_REASON = ("this command puts code behind text that looks like a secret, so a person can't see what "
                      "they'd approve")
HIDDEN_CODE_REMEDY = "Rewrite it without inline secrets (read them from the environment or a file the command names)."
SUMMARY_CHARS = 400   # what v1's approval summary holds (approval_summary): a hold whose summary is longer is denied
LONG_REASON = f"this call is too long for its approval request ({SUMMARY_CHARS} characters), so a person can't see " \
              "what they'd approve"
LONG_REMEDY = "Split it into shorter calls."


def hidden_message(decision):
    """What v1 tells the agent of a hold `decision` screened denies (HIDDEN_CODE): its reason and what to do."""
    reason, _, remedy = decision["reasons"][-1].partition(". Instead: ")
    return f"Blocked by Tracekit: {reason}; {remedy[:1].lower()}{remedy[1:].rstrip('.')} ({HIDDEN_CODE})"


def approval_summary(name, recorded, note=""):
    """What v1's approval request shows the person who answers it: the tool's `name`, the `note` (hidden), and every
    argument as `recorded` (tool_input's): the call's command, file or URL first (each of several, when it names
    several), then each other `key=value` (a string as is, anything else as JSON; a hashed one as its reference)."""
    shown, first = [], set()
    for one, many in (("command", "commands"), ("file_path", "paths"), ("url", "urls")):
        each = (recorded.get(many) or {}).get("value")   # a call on several, each decided: the approver sees all
        v = each if isinstance(each, list) and len(each) > 1 else (recorded.get(one) or {}).get("value")
        if v:
            shown, first = [f"{len(v)} {many}={json.dumps(v)}" if isinstance(v, list) else f"{one}={v}"], {one, many}
            break
    for k, v in recorded.items():
        if k not in first:
            v = v.get("value", v) if isinstance(v, dict) else v
            shown.append(f"{k}={v if isinstance(v, str) else json.dumps(v, sort_keys=True)}")
    return f"{name} {note}{' '.join(shown)}"


def screened(decision, name, ti, recorded, unclean):
    """v1's `decision` on a call of tool `name` with tool input `ti`, recorded as `recorded` (tool_input's, with
    `unclean`): a hold whose record, which its approver reads, would hide more than clean values (unclean), or whose
    approval summary, every argument as tool_input keeps it in clear, would be cut (longer than SUMMARY_CHARS), is
    denied (HIDDEN_CODE); else its `summary` is that, starting with how much it hides when it hides more than values
    (`note`)."""
    if decision["decision"] != "ask":
        return decision
    shown = (recorded.get("command") or {}).get("value") if isinstance(recorded.get("command"), dict) else None
    note = hidden(ti["command"], shown) if isinstance(ti.get("command"), str) and isinstance(shown, str) else ""
    summary = approval_summary(name, tool_input(name, ti, "full"), note)
    if unclean or len(summary) > SUMMARY_CHARS:
        reason, remedy = (HIDDEN_CODE_REASON, HIDDEN_CODE_REMEDY) if unclean else (LONG_REASON, LONG_REMEDY)
        return {**decision, "decision": "deny", "rule_ids": decision["rule_ids"] + [HIDDEN_CODE],
                "reasons": decision["reasons"] + [f"{reason}. Instead: {remedy}"]}
    return {**decision, "note": note, "summary": summary}


class Budget:
    """One call's budget for the policy parser's readings of its strings (policy2.shell's MAX_WORK, as its `work`),
    each reading charged PARSE_COST more, and those readings by text: past it, what is left is not read, so a held call
    with a value there is denied (TK-HIDDEN-CODE), and a call of thousands of strings reads in bounded time."""

    def __init__(self):
        self.work, self.facts = [0], {}


PARSE_COST = 256   # what one reading spends of a call's Budget besides its text: about 1,000 readings a call


def approver_copy(args, dotenv, tool="", noted=True, budget=None):
    """(the approver's copy of a held call of `tool` with parsed `args`: redact with each string under COMMAND_KEYS or
    typed_lines read as a shell line or an argv, and, `noted`, noted; whether it hides more than clean values, which
    no person can approve the call by: redact's `unclean`). `budget`: the call's (a Budget), for a second copy."""
    unclean = []
    return redact(args, dotenv, commands=COMMAND_KEYS | set(typed_lines(tool, args)), noted=noted,
                  unclean=unclean, budget=budget or Budget())[0], bool(unclean)


NOTE_CHARS = 256   # what redaction hides, past which a person is told how much: more than a few secrets' worth
# the note's own line, a shell comment: a shell line's readers (findings, why) parse what follows it as before
NOTE = "# [{} characters hidden by redaction]\n"
NOTE_CODE = "# [{} characters hidden by redaction, among them {}, which a shell can read as code]\n"
_SHELL_READS = re.compile(r"[\s;&|<>()`$\\'\"]")
_CODE_READS = "\n;&|<>()$`"   # of those, the ones that make code
# the & that starts a URL query's next parameter (?api_key=…&limit=10): no command follows it, only an assignment
_QUERY = re.compile(r"&(?=[A-Za-z0-9_.~%-]+=)")


def _took(before, after, query=False):
    """(how many characters redaction took out of string `before` to give `after`, marks aside; a Counter of the
    _SHELL_READS characters among them, with `query` a URL query's & aside: _QUERY)."""
    b, a = MARK.sub("", before), MARK.sub("", after)
    n = len(b) - len(a)
    if query:
        b, a = _QUERY.sub("", b), _QUERY.sub("", a)
    return n, collections.Counter(_SHELL_READS.findall(b)) - collections.Counter(_SHELL_READS.findall(a))


def _coded(before, after):
    """Whether redaction took one of _CODE_READS out of `before` to give `after` (a held call's copy can't hide it),
    a URL query's & aside."""
    return any(c in _CODE_READS for c in _took(before, after, True)[1])


def hidden(before, after):
    """The line that tells the person reading `after` how many characters redaction took out of string `before` to give
    it (marks aside), when they should be told, else "": when it took more than NOTE_CHARS, or a blank, a line end, a
    quote, a backslash or another character the shell reads, so it may be more than one value (words, lines, code);
    naming each of _CODE_READS it took (NOTE_CODE)."""
    n, took = _took(before, after)
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
_SEP = re.compile(r"\s*[=:]\s*(?:\$'|[\"'])?")   # what ASSIGNMENT reads between a name and its value
# what on a line may give a program's name another meaning (a function, an alias, PATH) or send what a program prints
# to one that runs it (>(…), a coprocess, a named pipe): no heredoc on it is data
_UNSURE = re.compile(r"\b(?:alias|enable|hash|function|coproc|mkfifo|mknod)\b|\(\s*\)|>\(|\b(?:BASH_ENV|ENV|PATH)\+?=")
# $( <( >( open at once, past which the reader doesn't follow the line: each holds the line's state, which made a
# line of 256 KiB of "$( take 0.6 s with the garbage collector on
_FRAMES = 64
_REFERENCE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})")   # a variable's name, no value
# where each character of a shell line sits (_Reading.ctx): in code; in '...', "..." or $'...'; in a heredoc body bash
# keeps as written, or a comment; in a body it expands
CODE, SQ, DQ, ANSI, LITERAL, EXPANDED = range(6)
_CODE_LIKE = re.compile(r"[\s|&;()<>'\"\\$`{}*?\[\]]")
# what a value hidden in a held call's copy may not hold where it sits (_clean): in code, a blank or any character the
# shell reads; elsewhere, what separates commands or words in a shell or most languages (a blank, ; & | ( ) < > ` and
# $, as in ${IFS}), since a program may read a quoted word or a body as code the policy's parser doesn't (docker exec c
# sh -c, Rscript -e) or write it to a script that runs later (>> ~/.bashrc), and what bash still reads there: a quote
# that ends it, and in "...", $'...' and a body it expands, a backslash
# programs that only read their words as data (what they print, fetch, match or keep), never as code: a hidden value
# in a quoted word one of them gets is text; given to any other, it may be the program's code (sqlite3's .shell,
# osascript, expect, vim -c, a git hook, docker run), which the copy can't show around a hidden value: unclean
DATA_READERS = frozenset((
    "echo", "printf", "cat", "tee", "grep", "egrep", "fgrep", "zgrep", "rg", "ag", "jq", "yq", "gojq", "base64",
    "openssl", "sha256sum", "sha1sum", "md5sum", "shasum", "wc", "head", "tail", "sort", "uniq", "cut", "tr", "curl",
    "wget", "http", "https", "xh", "touch", "mkdir", "ls", "cp", "mv", "rm", "ln", "chmod", "chown", "test", "[",
    "true", "false", "export", "declare", "local", "readonly", "typeset"))
# options whose value is data though their program may run other words it gets as code: a value hidden there may be
# text a shell would split (`--set "k=a b"`). Each value is the word after its option or joined to it (`--set=k=v`,
# `-pSECRET`); every other word of these programs is code to them, as any program's outside DATA_READERS
_DATA_OPTIONS = {
    "terraform": ("-var",),   # an input variable's value, which the configuration reads as a value
    "helm": ("--set", "--set-string", "--set-json"),   # a chart value, which its templates render as text
    "kubectl": ("--from-literal",),   # a secret's or config map's key=value, which it stores
    # a database client's connection (user, host, port, database, and mysql's, mongosh's and redis-cli's password),
    # never its code: psql's -c and its \!, mysql's -e and its system, mongosh's --eval, redis-cli's EVAL, -f files
    "psql": ("-U", "--username", "-h", "--host", "-p", "--port", "-d", "--dbname"),
    "mysql": ("-u", "--user", "-h", "--host", "-P", "--port", "-D", "--database", "-p", "--password"),
    "mongosh": ("-u", "--username", "-p", "--password", "--host", "--port", "--authenticationDatabase"),
    "redis-cli": ("-u", "-h", "-p", "-a", "--user", "--pass"),
}
# a database client's positional connection URI (scheme://…) is data too
_URI, _URI_CLIENTS = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://"), ("psql", "mysql", "mongosh", "redis-cli")
# environment variables a program reads as data (a connection or a credential), whatever the program: a value given
# one before a program not among DATA_READERS is data (`DATABASE_URL=… npm run migrate`); any other name there may be
# code the program runs (LD_PRELOAD, NODE_OPTIONS, PYTHONSTARTUP, BASH_ENV, GIT_SSH_COMMAND, EDITOR, PAGER)
_DATA_ENV = re.compile(r"DATABASE_URL|PGPASSWORD|MYSQL_PWD|\w*_(?:URL|DSN|PASSWORD|PASSWD|TOKEN|SECRET|API_KEY)|"
                       r"\w*_ACCESS_KEY\w*")


def _data_args(name, args):
    """The indexes of `args` (program `name`'s words after its name) that are data to it as _DATA_OPTIONS says."""
    opts, out = _DATA_OPTIONS.get(name, ()), set()
    for k, a in enumerate(args):
        if k and args[k - 1] in opts or any(a.startswith(o + "=") or len(o) == 2 and a.startswith(o) and len(a) > 2
                                            for o in opts) or name in _URI_CLIENTS and _URI.match(a):
            out.add(k)
    return out
_SEEN = {CODE: _CODE_LIKE, SQ: re.compile(r"[\s|&;()<>$`']"), DQ: re.compile(r'[\s|&;()<>$`"\\]'),
         ANSI: re.compile(r"[\s|&;()<>$`'\\]"), LITERAL: re.compile(r"[\s|&;()<>$`]"),
         EXPANDED: re.compile(r"[\s|&;()<>$`\\]")}


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


def _end_line(s, k, end, tabs, z, joins=False):
    """(where the end line `end` of the heredoc body starting at `k` starts, where it ends), both `z` when no line
    before `z` ends it; `tabs`: it may start with tabs (`<<-`); `joins`: a backslash-newline joins two lines into one
    first, as bash reads an unquoted end word's body (`x\\⏎EOF` is no end line; `E\\⏎OF` is)."""
    while k < z:
        start, parts = k, []
        while True:
            e = s.find("\n", k, z)
            e = z if e < 0 else e
            part = s[k:e]
            if not (joins and e < z and (len(part) - len(part.rstrip("\\"))) % 2):
                break
            parts.append(part[:-1])
            k = e + 1
        line = "".join(parts) + part
        if (line.lstrip("\t") if tabs else line) == end:
            return start, e
        k = e + 1
    return z, z


@functools.cache
def _policy(name):
    """tracekit.policy2's module `name` (shell, engine), imported once and only when a command needs it: the hook that
    records a plain command never pays for the parser."""
    return importlib.import_module("tracekit.policy2." + name)


def _words(s, spans):
    """The words at `spans` of shell line `s` as bash gives them, near enough to name a program and its options:
    without their quotes and backslashes."""
    return [s[a:b].translate(_policy("shell")._UNQUOTED) for a, b in spans]


def _unread_interpreter(name):
    """Whether `name` is an interpreter's (engine._INTERPRETER) whose program the parser doesn't read (deno, bun)."""
    return bool(_policy("engine")._INTERPRETER.fullmatch(name)) and not _policy("shell")._kind(name)


class _Facts:
    """What the policy's own shell parser (policy2.shell.analyse, analyse_argv) reads in a shell `line` or an `argv`,
    by where in it each thing stands (a span; an argv's, word indexes), which decides for a held call's copy what is
    code: `programs`, (at, within) of each program a command it finds runs, at any depth (through a wrapper, a runner,
    a function, a reserved word, sh -c, eval, ssh, watch, trap, a heredoc), and of the script file each shell, source
    or interpreter runs (`bash x.sh`, `. ./env.sh`, `python3 x.py`): `at` its word's span, None where the line doesn't
    hold it as written (a variable's value, an alias's), `within` the span of the code it was read from (None: the
    line); `placed`, (how, at, inner, within) of each text it reads again as code (policy2.shell._learned); `args`,
    (name, the spans of its words) of each command; `sure`, False when it can't read the line (ParseError, over
    engine.MAX_SUBJECT, past the call's Budget, its loop values' readings cut) or a command runs what it can't read
    (opaque: `echo x | sh`, `$X` it can't follow, sed's `e`). Readings are kept by text in the call's Budget (of)."""

    def __init__(self, line=None, argv=None, work=None):
        self.programs, self.placed, self.args, self.sure, work = [], [], [], False, [0] if work is None else work
        shell, engine = _policy("shell"), _policy("engine")
        if (len(line) if line is not None else sum(map(len, argv))) > engine.MAX_SUBJECT:
            return
        try:
            shell.charge(work, PARSE_COST)
            cmds, *_, learned = shell.analyse(line, work=work) if line is not None else \
                shell.analyse_argv(argv, work=work)
        except (shell.ParseError, RecursionError):
            return
        for c, at, within in learned["programs"]:
            name, args = c["argv"][0], c["argv"][1:]
            self.programs.append((at, within))
            data = _data_args(name, args) if name in _DATA_OPTIONS else ()
            self.args.append((name, [(*a.at, name in DATA_READERS or k in data) for k, a in enumerate(args)
                                     if getattr(a, "at", None)]))
            kind, script = shell._kind(name), None
            if name in shell.SHELLS:
                mode, script = shell._shell_mode(args, name)
                script = script if mode is None else None
            elif name in ("source", "."):
                script = args[0] if args else None
            elif kind not in (None, "awk", "sed") and shell._code_arg(kind, args) is None:
                script = next((a for a in args if a[:1] != "-"), None)
            if script:   # (as a program's word: where it is written as it is)
                self.programs.append((script.at if getattr(script, "inner", None) else None, within))
        self.placed = learned["placed"]
        self.sure = not learned["pieces_cut"] and not any(c.get("opaque") for c in cmds)

    @classmethod
    def of(cls, line=None, argv=None, budget=None):
        """The reading of `line` or `argv` in `budget` (a Budget): one per text a call holds, however many times."""
        budget = budget or Budget()
        key = line if line is not None else tuple(argv)
        if key not in budget.facts:
            budget.facts[key] = cls(line, argv, budget.work)
        return budget.facts[key]


def _data_stdin(stages, nested):
    """For each of pipeline `stages` (each a command's _words): whether the heredoc or herestring it reads is data: a
    program that reads only data (shell.DATA_ONLY: cat, tee; awk's or sed's program aside) reads it, and so does each
    stage after it, outside a substitution, a subshell or a block, on a line _UNSURE finds nothing on (not
    `nested`)."""
    shell = _policy("shell")
    out, data = [], True
    for words in reversed(stages):
        k = next((k for k, w in enumerate(words) if not shell._ASSIGN.match(w)), len(words))
        name = shell.base_name(words[k]) if k < len(words) else ""
        kind = shell._kind(name)
        data = data and name in shell.DATA_ONLY and not (kind and shell._reads_stdin(kind, words[k + 1:]))
        out.append(data and not nested)
    return out[::-1]


def _command():
    """A simple command as _read_shell reads it: its words' and herestrings' spans; whether it reads a heredoc, and
    has a quote or a backslash in a word (so a word may be code the line itself doesn't read); whether its stdin is
    data (_data_stdin)."""
    return {"words": [], "here": [], "docs": False, "quoted": False, "data": None}


class _Reading:
    """Shell line `s` as _read_shell reads it. `cut`, `ctx`, `body`, `unsure`, `interp`, `quote` and `inq`:
    bytearrays one longer than `s`. `cut`: 1 at each place a hidden value ends at the latest, which is the first
    character of each blank run, control operator and redirection outside quotes, each line end, each start of code
    ($( <( >( ` ${), the end of a heredoc's body and of a script read on its own, and the end; text a program reads as
    data (a comment, a heredoc body cat reads) has none, so a value there is hidden as far as its rule reads, as in
    content. `ctx`: where each character sits (CODE, SQ, DQ, ANSI, LITERAL, EXPANDED). `body`: 1 in each heredoc body.
    `unsure`: 1 in what the reader can't read as bash does (_read_shell); `interp`: 1 in an interpreter's program.
    `quote`: 1 at each quote that opens or closes a part ($'…''s at its $); `inq`: 1 in each part after its opening
    quote, to its closing one. `data`: 1 in each herestring and heredoc body a program that reads only data reads.
    `starts`: where
    each word outside quotes may start. `pipes`: each pipeline's commands' word spans, of all the code read as a shell
    line."""

    def __init__(self, s):
        n = len(s)
        self.s, self.starts, self.pipes = s, [], []
        self.cut, self.ctx, self.body, self.unsure, self.interp, self.quote, self.inq, self.data = (
            bytearray(n + 1) for _ in range(8))
        self.cut[n] = 1


def _mark(a, start, end, value=1):
    a[start:end] = bytes([value]) * (end - start)


def _read_shell(s, facts=None):
    """Shell line `s` as bash reads it: a _Reading. With `facts` (_Facts: the policy parser's reading), what it reads
    again as code is read so where the parser places it: a shell line it holds verbatim (sh -c's '…', a heredoc a
    shell reads) as a line of its own, an interpreter's program as interp, other code as unsure. A heredoc body is
    data when _data_stdin says so; else unsure. Unsure too: what the reader can't read exactly as bash does: what
    follows a heredoc's end word with an expansion or a line continuation in it ($'EOF'), backquotes, ${...},
    arithmetic, an array's (...), the rest of a $(...) once a `case` starts in it, more than _FRAMES substitutions open
    at once. A backslash-newline outside quotes, as bash deletes it first, joins what is on either side of it."""
    r = _Reading(s)
    cut, ctx, body, unsure, quote, inq, starts = r.cut, r.ctx, r.body, r.unsure, r.quote, r.inq, r.starts
    plain = not _UNSURE.search(s)

    def unread(a, b):   # code the reader doesn't follow: a value ends where it starts
        cut[a] = 1
        _mark(unsure, a, b)
        return b

    def read_code(a, b):
        """[a, b) is a shell line the parser placed there: read as one of its own."""
        cut[b] = 1
        for x in (ctx, inq, quote, unsure):
            x[a:b + 1] = bytes(b + 1 - a)
        read(a, b, 1)

    def finish(pipe, nested, depth):
        """Pipeline `pipe` is read: whether each command's heredoc and herestring are data."""
        r.pipes.append([c["words"] for c in pipe])
        if not any(c["quoted"] or c["here"] or c["docs"] for c in pipe):
            return
        for c, data in zip(pipe, _data_stdin([_words(s, c["words"]) for c in pipe], nested)):
            c["data"] = data
            for a, b in c["here"]:
                _mark(r.data if data else unsure, a, b)

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
                _mark(ctx, i, j, DQ)
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
                cut[i] = 1
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
                if c == "#":   # a comment, to its line's end: text no shell runs
                    e = s.find("\n", i, z)
                    e = z if e < 0 else e
                    _mark(ctx, i, e, LITERAL)
                    i = e
                    continue
                if c == "\n":   # the bodies of the heredocs this line opened follow it, each to its end line
                    end_command(False)   # (a pipeline the line ends in | goes on after them: its last stage reads none)
                    i += 1
                    for end, tabs, kept, owner in pending:
                        b, e = _end_line(s, i, end, tabs, z, not kept)
                        _mark(body, i, b)
                        if owner["data"]:
                            _mark(r.data, i, b)
                            _mark(ctx, i, b, LITERAL if kept else EXPANDED)
                            while not kept and (x := _EXPANDS.search(s, i, b)):   # its $(...) and `...` run now
                                i = unread(x.start(), min(_past(s, x.end(), *_CLOSES[x.group()], end=b), b))
                        else:
                            _mark(unsure, i, b)
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
            if c == "\\" and s.startswith("\n", i + 1) and not dq:   # bash deletes it: no word starts or ends there
                i += 2
                continue
            if not (dq or word):   # a part of a word: in "...", or quoted, escaped or expanded outside quotes
                starts.append(i)
                ws, word = i, True
            if dq:   # what bash reads in "...": in its part, as its closing quote is
                _mark(inq, i, i + 1 + (c == "\\"))
                _mark(ctx, i, i + 1 + (c == "\\"), DQ)
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
                _mark(ctx, i + 1, e + 1, SQ)
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
                _mark(ctx, i + 1, e + (not closed), ANSI)
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
    for how, at, inner, _ in sorted((p for p in facts.placed if p[1]), key=lambda p: (p[1][0], -p[1][1])) if facts \
            else ():   # (one around another first: the inner one is read again in it)
        if how == "interp":
            _mark(r.interp, *at)
        elif inner:
            read_code(*inner)
        else:
            _mark(unsure, *at)
    return r


def _rank(kind, first=("private_key", "dotenv", "assignment")):
    """Which of two marks one mark that covers both is named for: the first of `first` among them, else the earlier."""
    return first.index(kind) if kind in first else len(first)


def _marks(cmd, r, dotenv, own, expands):
    """([(start, end, kind)] of what redact_command hides in shell line `cmd` as _Reading `r` reads it, sorted; the
    starts of those a value's name ends in the word before: `KEY: x`, `KEY = x`). `expands`: bash expands `cmd`'s
    $NAME, so one where it does ($TOKEN, "$TOKEN", a body with an unquoted end word) is no value."""
    cut, quote, inq, ctx = r.cut, r.quote, r.inq, r.ctx
    crossed = set()
    k = cmd.find("<<")
    after = cmd.find("\n", k) if k >= 0 else -1   # v1 hides a .env value of its line only after its first heredoc line

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
        `=`, before it (`A= cmd` runs cmd); one a blank stands before (`KEY: x`, in quotes or a body too: a word of its
        own to a shell that reads it) is hidden and `crossed`."""
        gap = cmd[b:v]
        if any(c in " \t\n" for c in gap):
            if ("\n" in gap or gap[:1] == "=") and any(c in " \t\n" and cut[k] for k, c in enumerate(gap, b)):
                return None
            crossed.add(v)
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
            if (own or 0 <= after < p) and (m := _NAME_EQ.match(cmd, p)):
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
            if (own or 0 <= after < m.start(3)) and k not in words and (
                    e := value(_NAME.match(cmd, k).end(), m.start(3), m.end(3))):
                found.append((m.start(3), e, "dotenv"))
    marks = []
    for v, e, kind in sorted(found):
        if expands and ctx[v] in (CODE, DQ, EXPANDED) and not (r.unsure[v] or r.interp[v]) and \
                _REFERENCE.fullmatch(cmd, v, e):
            continue   # a variable's name where bash expands it: no secret, and what the remedy asks for
        if marks and v < marks[-1][1]:   # inside the value before it, or overlapping it: one mark
            p = marks.pop()
            v, e, kind = p[0], max(e, p[1]), min(p[2], kind, key=_rank)
        marks.append((v, e, kind))
    return marks, crossed


def _clean(s, r, marks, crossed, facts):
    """Whether each of `marks` (in shell line `s` as _Reading `r` reads it with the policy parser's _Facts `facts`)
    hides only a clean value, which an approver may see a copy without: on a line the parser reads whole (_Facts.sure);
    not where the parser read a program or code it can't place in the line (a git alias's value, a variable's program:
    its `within`, None the whole line), nor in a program's or a script file's word it places; in one place
    (_Reading.ctx) and holding nothing _SEEN there; not in an interpreter's program, nor where the reader is unsure; in
    quotes, and when it starts a word of its own (`crossed`: `KEY: x`) anywhere, data: in a word a program of
    DATA_READERS gets or an option of _DATA_OPTIONS takes, a herestring or a heredoc such a program reads, a value
    assigned where no program runs (`K='a b'`) or to a name of _DATA_ENV."""
    if not facts.sure:
        return False
    program, data, loose = bytearray(len(s) + 1), bytearray(r.data), []
    for _, at, _, within in facts.placed:
        if at is None:
            loose.append(within)
    for at, within in facts.programs:
        if at is None:
            loose.append(within)
        else:
            _mark(program, *at)
    # each word as the innermost command that gets it reads it: echo's `$(osascript -e '…')` is osascript's code; a
    # word a wrapper passes on (sudo curl -H '…') is the data reader's
    for a, b, reads, name in sorted(((a, b, reads, name) for name, spans in facts.args for a, b, reads in spans),
                                    key=lambda w: (w[0] - w[1], w[2])):
        _mark(data, a, b, reads)
        if _unread_interpreter(name):
            _mark(r.interp, a, b)
    shell = _policy("shell")
    for pipe in r.pipes:   # an assignment with no program on its command sets the shell's own variable: data; one
        for spans in pipe:   # before a program, when its name is one of _DATA_ENV
            alone = all(shell._ASSIGN.match(s, a, b) for a, b in spans)
            for a, b in spans:
                if not (m := shell._ASSIGN.match(s, a, b)):
                    break
                if alone or _DATA_ENV.fullmatch(s, a, a + len(m.group().rstrip("+=").split("[")[0])):
                    _mark(data, a, b)
    for v, e, _ in marks:   # (one that leaves its quotes, body or comment holds what ends them, which _SEEN finds)
        c = r.ctx[v]
        if v in crossed and data.count(1, v, e) < e - v or r.unsure.find(1, v, e) >= 0 or \
                r.interp.find(1, v, e) >= 0 or \
                program.find(1, v, e) >= 0 or _SEEN[c].search(s[v:e] if c == CODE else _QUERY.sub("", s[v:e])) or \
                any(w is None or w[0] < e and v < w[1] for w in loose) or \
                c in (SQ, DQ, ANSI) and data.count(1, v, e) < e - v:
            return False
    return True


def redact_command(cmd, dotenv=False, own=True, how="line", unclean=None, budget=None):
    """(shell line `cmd` as an approver's copy shows it, whether it changed): what each SECRET_PATTERNS rule hides, the
    value of each secret-looking KEY=value (ASSIGNMENT's) and, with `dotenv`, of every KEY=value; in code read as a
    shell line, each only up to where the shell ends its word (_Reading.cut) and never past a quote it didn't open, so
    what runs after it stays in view; in text (a body cat reads, a comment), in an interpreter's program and where the
    reader is unsure, as far as its rule reads, as in content (with `dotenv`, each KEY=value line's to its line's end);
    a private key whole; a variable's name where bash expands it, never. `own` False: with `dotenv`, the line's own
    values kept but after its first heredoc line (as v1 records a command). `how`: "line", or `cmd` is a word of an
    argv: "word", "program" (a program's name), "interp" (an interpreter's program) or "code" (the parser can't read
    the argv). `unclean`, a list: gets True when a mark hides more than a clean value (_clean; for an argv's word, any
    mark in a program's name, an interpreter's program or an argv the parser can't read, and any holding a blank or a
    character the shell reads, or starting a word of its own). `budget`: the call's Budget for the parser's readings."""
    r = _read_shell(cmd) if how == "line" else _Reading(cmd)
    marks, crossed = _marks(cmd, r, dotenv, own, how == "line")
    if unclean is not None and marks:
        if how != "line":
            dirty = how != "word" or any(_CODE_LIKE.search(cmd, v, e) or v in crossed for v, e, _ in marks)
        else:
            facts = _Facts.of(cmd, budget=budget)
            if facts.sure and facts.placed:   # what the parser reads as code, read as such: sh -c's value ends at `;`
                r = _read_shell(cmd, facts)
                marks, crossed = _marks(cmd, r, dotenv, own, True)
            dirty = bool(marks) and not _clean(cmd, r, marks, crossed, facts)
        if dirty:
            unclean.append(True)
    out, last = [], 0
    for v, e, kind in marks:
        out += [cmd[last:v], f"[REDACTED:{kind}]"]
        last = e
    out = "".join(out + [cmd[last:]])
    return out, out != cmd


def tool_input(tool, ti, content_capture="hashed", unclean=None):
    """Map a raw tool_input dict to {field: content} per docs/privacy.md. Each shell line or argv under COMMAND_KEYS
    or typed_lines is redacted as the shell reads it (redact_command), with a .env file named, a command's own
    KEY=value values kept but after its first heredoc line; `unclean` (as for redact) for every field."""
    out, ti, budget = {}, scrub(ti or {}), Budget()
    dotenv = mentions_dotenv(*(ti.get(k) for k in ACTION_FIELDS),
                             *(x for k in ACTION_LISTS if isinstance(ti.get(k), list) for x in ti[k]))
    lines = COMMAND_KEYS | set(typed_lines(tool, ti))
    for k, v in ti.items():
        rk = redact_text(k)[0] if isinstance(k, str) else k
        if isinstance(k, str) and k.lower() in lines:
            rv, red = redact(v, dotenv, commands=lines, _shell="lines" if k.lower() == "commands" else True,
                             unclean=unclean, own=k not in ("command", "commands"), budget=budget)
        else:   # (an argv's program beside it: ARGV_ARGS)
            near = {p: ti[p] for p in _PROGRAM_ARGS if p in ti and p != k} if k in ARGV_ARGS else {}
            rv = redact({**near, k: v}, dotenv and k not in ACTION_FIELDS and k not in ACTION_LISTS, unclean=unclean,
                        budget=budget)[0][rk]
            red = rv != v
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
