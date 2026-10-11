"""Policy v2 engine: deterministic matching over a compiled policy (design §4.2).

google-re2 when installed, else the `regex` module on the same pattern subset in ASCII mode (`compile.translate`).
Every decision names the engine (id@version) and the policy_hash. Precedence: deny > ask > flag > allow.
"""
import fnmatch
import re
import time

from . import classes, shell
from .compile import CLASSES, SECTIONS, canonical, policy_hash, translate

MAX_SUBJECT = 64 * 1024     # bytes of UTF-8; a longer subject is never cut or windowed: TK-OVERSIZE in its rule's section
_URL = re.compile(r"(?i)\b(?:https?|wss?|ftp):[^\s'\"<>`]*")
_BARE_ADDRESS = re.compile(r"[0-9][0-9A-Za-z.]*(:[0-9]*)?([/?#]|$)")   # curl 2852039166/latest
REGEX_TIMEOUT_S = 1.0       # fallback engine only: the time all matches of one decision share; a match that runs out
                            # of it denies, marked nondeterministic


def _backend(name):
    """Return (engine id, compile(pattern), match(compiled, text, full, deadline)); only the fallback uses the
    deadline (time.monotonic())."""
    if name != "regex":
        try:
            import re2
        except ImportError:
            if name == "re2":
                raise
        else:
            from importlib.metadata import version
            opts = re2.Options()
            opts.log_errors = False
            return (f"re2@{version('google-re2')}", lambda p: re2.compile(p, opts),
                    lambda c, s, full, deadline: (c.fullmatch if full else c.search)(s))
    import regex
    return (f"regex@{regex.__version__}", lambda p: regex.compile(translate(p), regex.ASCII | regex.V0),
            lambda c, s, full, deadline: (c.fullmatch if full else c.search)(
                s, timeout=max(deadline - time.monotonic(), 1e-6)))


class Engine:
    def __init__(self, policy, backend=None):
        """`policy` is a compiled policy (compile.build); `backend` forces "re2" or "regex"."""
        self.policy, self.policy_hash = policy, policy_hash(policy)
        self.engine, compile_, self._match = _backend(backend)
        self.rules = [(sec, r, compile_(r["tool"]) if "tool" in r else None, compile_(r["pattern"]),
                       compile_(r["unless"]) if "unless" in r else None)
                      for sec in SECTIONS for r in self.policy.get(sec, [])]

    def tool_class(self, tool):
        tools = self.policy.get("tools", {})
        if tool in tools:
            return tools[tool]
        # the most specific glob wins (most characters that are not * or ?), so mcp:postgres/* beats mcp:*/*
        hits = sorted((-len(pat.replace("*", "").replace("?", "")), pat) for pat in tools if fnmatch.fnmatchcase(tool, pat))
        return tools[hits[0][1]] if hits else "unknown"

    def untrusted_results(self, tool):
        """Whether the policy's `untrusted` list (tool classes and tool name globs) marks the tool's results untrusted."""
        cls = self.tool_class(tool)
        return any(u == cls if u in CLASSES else fnmatch.fnmatchcase(tool, u) for u in self.policy.get("untrusted", ()))

    def decide(self, tool, args, cls=None, untrusted=None):
        """Return {verdict, rule_ids, policy_hash, engine[, nondeterministic]} for one tool call. `cls` overrides the
        class the policy maps the tool to. `untrusted(subject)`: the hits of the subject's values that only untrusted
        content brought into the run; a `from: untrusted` rule matches a subject only when there is one (never without
        `untrusted`)."""
        args = args if isinstance(args, dict) else {"value": args}
        cls = cls or self.tool_class(tool)
        fields = classes.extract(cls, tool, args)
        hits = {sec: [] for sec in SECTIONS}
        if cls == "unknown" and self.policy.get("unknown_tools") in SECTIONS:
            hits[self.policy["unknown_tools"]].append("TK-UNKNOWN-TOOL")
        if cls == "sql" and fields.get("statement") is not None and not fields.get("code"):
            hits["ask"].append("TK-SQL-PARSE")   # no dialect reads it: an unclosed literal or comment, or not text
        nondeterministic, deadline = False, time.monotonic() + REGEX_TIMEOUT_S
        parsed = [], [], []
        if cls == "shell":
            command = fields.get("command", "")
            if len(_text(command if isinstance(command, str) else canonical(command)).encode()) > MAX_SUBJECT:
                hits["deny"].append("TK-OVERSIZE")
            else:
                try:
                    parsed = _shell(args)
                except shell.ParseError:
                    hits["ask"].append("TK-SHELL-PARSE")
                    parsed = [], [], [command if isinstance(command, str) else canonical(command)]   # its own target
                if any(c["opaque"] for c in parsed[0]):
                    hits["ask"].append("TK-SHELL-PARSE")
        for sec, rule, tool_re, pat, unless in self.rules:
            if rule.get("class", cls) != cls:
                continue
            try:
                if tool_re is not None and not self._match(tool_re, _text(tool), True, deadline):
                    continue
                for subject in self._subjects(cls, rule.get("field"), args, fields, parsed):
                    subject = _text(subject)
                    if len(subject.encode("utf-8")) > MAX_SUBJECT:
                        hits[sec].append("TK-OVERSIZE")   # the rule's own verdict: a flag rule cannot block a large call
                        break
                    # `unless`: an exemption checked against the same subject (use it only where the subject is one
                    # target, e.g. a file path; in a whole command it could exempt a different target)
                    if self._match(pat, subject, False, deadline) and not (
                            unless is not None and self._match(unless, subject, False, deadline)) and (
                            "from" not in rule or untrusted is not None and untrusted(subject)):
                        hits[sec].append(rule["id"])
                        break
            except TimeoutError:   # the time of the whole decision is spent: deny, and leave the other rules out
                nondeterministic = True
                hits["deny"].append(rule["id"])
                break
        verdict = next((sec for sec in SECTIONS if hits[sec]), "allow")
        out = {"verdict": verdict, "rule_ids": list(dict.fromkeys(hits["deny"] + hits["ask"] + hits["flag"])),
               "policy_hash": self.policy_hash, "engine": self.engine}
        if nondeterministic:
            out["nondeterministic"] = True
        return out

    @staticmethod
    def _subjects(cls, field, args, fields, parsed):
        """A class field matches the signer's extraction; any other field names a raw argument; no field scans the
        whole call (Write/Edit content, WebFetch url and prompt, MCP args). A shell `line` is the raw command and
        each line the parser normalised; an fs `path` with `..` also matches its lexically normalised form, and each
        entry of a `paths` list (every file of a Codex patch) is a path too. `target` (every class) is what the call
        acts on rather than what it carries (Engine._targets); sql `code` is one subject per dialect reading."""
        if field == "target":
            return Engine._targets(cls, args, fields, parsed)
        if cls == "sql" and field == "code":
            return fields.get("code", [])
        if cls == "shell" and field in (None, "argv"):
            return [" ".join(c["argv"]) for c in parsed[0]]
        if cls == "shell" and field == "line":
            return Engine._subjects(cls, "command", args, fields, parsed) + parsed[1]
        if field is None:
            return [canonical(args)]
        if cls == "fs" and field == "path" and isinstance(args.get("paths"), list):   # a call on several files
            raws = [classes.first(args, *classes.PATH_KEYS)] + args["paths"]
            return list(dict.fromkeys(f for r in raws for f in classes.fs_forms(r)))
        value = fields.get(field) if field in CLASSES.get(cls, ()) else args.get(field)
        if value is None:
            return []
        if cls == "fs" and field == "path" and isinstance(value, str):
            return classes.fs_forms(classes.first(args, *classes.PATH_KEYS))
        return [value if isinstance(value, str) else canonical(value)]

    @staticmethod
    def _targets(cls, args, fields, parsed):
        """shell: each command's argv without its data words (shell.data_words), the redirection targets, assignments
        and heredoc programs; fs: the paths; http and browser: the URL; email: the attachments; mcp and unknown tools:
        the whole call. Each URL is also matched as scheme://canonical-host/ (classes.url_target), so a host in decimal,
        hex, octal or IPv6 form reads as the address it is."""
        if cls == "shell":
            words = [[a for i, a in enumerate(c["argv"]) if i not in shell.data_words(c["argv"])] for c in parsed[0]]
            urls = [u for w in [a for ws in words for a in ws] + parsed[2]
                    for u in _URL.findall(w) + (["http://" + w] if _BARE_ADDRESS.match(w) else [])]
            return [" ".join(w) for w in words] + parsed[2] + [t for t in map(classes.url_target, urls) if t]
        if cls == "fs":
            return Engine._subjects(cls, "path", args, fields, parsed)
        if cls in ("http", "browser"):
            url = fields.get("url")
            if not isinstance(url, str):
                return [] if url is None else [canonical(url)]
            return [url] + [t for t in [classes.url_target(url)] if t]
        if cls == "email":
            files = fields.get("attachments")
            return [f if isinstance(f, str) else canonical(f) for f in (files if isinstance(files, list) else [files])
                    if f is not None]
        return [canonical(args)] if cls in ("mcp", "unknown") else []


def _shell(args):
    """(commands, normalised lines, other words that name something) of a shell call. `command` or `cmd` is a command
    line or an argv list; `commands` (OpenAI's shell tool) a list of command lines. Anything else, or more than one of
    them, raises ParseError."""
    present = [k for k in classes.SHELL_KEYS if args.get(k) is not None]
    if len(present) > 1:
        raise shell.ParseError(f"more than one command field: {present}")
    value = args[present[0]] if present else ""
    strings = isinstance(value, list) and value and all(isinstance(a, str) for a in value)
    if isinstance(value, str):
        return shell.analyse(value)
    if strings and present == ["commands"]:
        return shell.analyse("\n".join(value))
    if strings:
        return shell.analyse_argv(value)
    raise shell.ParseError("the command is neither a string nor a list of strings")


def _text(s):
    """Lone surrogates (valid in JSON escapes, not in UTF-8) become \\udxxx text, the same for both engines."""
    return s.encode("utf-8", "backslashreplace").decode("utf-8")
