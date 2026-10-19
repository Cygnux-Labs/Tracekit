"""Policy v2 engine: deterministic matching over a compiled policy (design §4.2).

google-re2 when installed, else the `regex` module on the same pattern subset in ASCII mode (`compile.translate`).
Every decision names the engine (id@version) and the policy_hash. Precedence: deny > ask > flag > allow.
"""
import fnmatch
import functools
import re
import time

from . import classes, shell
from .compile import BOUND_TYPES, CLASSES, SECTIONS, canonical, literals, policy_hash, translate

MAX_SUBJECT = 64 * 1024     # bytes of UTF-8; a longer subject is never cut or windowed: TK-OVERSIZE in its rule's section
AGENT_ARGS_MAX = 16 * 1024  # bytes of a call's arguments (as canonical JSON) an agent approval may cover
# arguments the class extractors read as one field: a call carrying two of a group is a person's to answer
ALIASES = (classes.SHELL_KEYS, classes.PATH_KEYS, classes.PAYEE_KEYS, classes.RECIPIENT_KEYS,
           ("amount", "amount_cents"), ("sql", "query", "statement"), ("db", "database"))
_URL = re.compile(r"(?i)\b(?:https?|wss?|ftp):[^\s'\"<>`]*")
_BARE_ADDRESS = re.compile(r"[0-9][0-9A-Za-z.]*(:[0-9]*)?([/?#]|$)")   # curl 2852039166/latest
# ...when it reads as an IPv4 address outside 0.0.0.0/8, which no call reaches: not 1.txt, 2fa/ or head -n 50's 50.
# lean: a dotted number (npm version 1.2.3) still reads as one; read bare words only in network commands if it flags
# too much
_BARE_TARGET = re.compile(r"http://[1-9][0-9]*(\.[0-9]+){3}/")
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
        self.tool_class = functools.lru_cache(maxsize=1024)(self.tool_class)   # a glob scan per call otherwise
        self.engine, compile_, self._match = _backend(backend)
        # each rule's prefilter (compile.literals): a subject holding none of its strings is not searched
        self.rules = [(sec, r, compile_(r["tool"]) if "tool" in r else None, compile_(r["pattern"]),
                       compile_(r["unless"]) if "unless" in r else None, literals(r["pattern"]))
                      for sec in SECTIONS for r in self.policy.get(sec, [])]
        self._of = {}
        # an ask rule's approval.agent patterns: (rule id, argument name) -> compiled
        self._bounds = {(r["id"], name): compile_(b["pattern"]) for _, r, *_ in self.rules
                        for name, b in (r.get("approval") or {}).get("agent", {}).get("allow", {}).get("fields", {}).items()
                        if "pattern" in b}

    def bounds(self, rule, args, deadline):
        """[(condition, passed)] of ask rule `rule`'s approval.agent bounds over a call's `args`: a closed world, not
        decide's search. Every argument is one the bounds name, and each one they name is there; a value has exactly
        the field's JSON type (the string "100", 1e2, 99.9 and true are no integer); a list passes when it has
        elements and every one does, and an integer list's total is within `max`; no two alias arguments (amount and
        amount_cents) at once; the arguments fit in AGENT_ARGS_MAX. A pattern matches the whole value; TimeoutError
        past `deadline` (time.monotonic())."""
        fields = rule["approval"]["agent"]["allow"]["fields"]
        if not isinstance(args, dict):
            return [("the arguments are an object", False)]
        out = [(f"the arguments fit in {AGENT_ARGS_MAX} bytes",
                len(canonical(args).encode("utf-8", "surrogatepass")) <= AGENT_ARGS_MAX),
               ("every argument is one the bounds name", set(args) <= set(fields)),
               ("no two alias arguments", not any(len(set(g) & set(args)) > 1 for g in ALIASES))]
        for name, b in fields.items():
            v = args.get(name)
            ok = v != [] and all(self._within(rule["id"], name, b, x, deadline) for x in (v if isinstance(v, list)
                                                                                           else [v]))
            if ok and isinstance(v, list) and "max" in b:   # a list of amounts is bounded by its total, not each
                ok = sum(v) <= b["max"]
            out.append((f"{name}: {canonical(b)}", ok))
        return out

    def _within(self, rid, name, b, v, deadline):
        typ = BOUND_TYPES[b["type"]]
        return type(v) is typ and (typ is not int or b.get("min", v) <= v <= b.get("max", v)) and (
            "enum" not in b or any(type(e) is typ and e == v for e in b["enum"])) and (
            "pattern" not in b or bool(self._match(self._bounds[(rid, name)], _text(v), True, deadline)))

    def is_handoff(self, tool):
        """Whether the policy's `handoffs:` names `tool` as one the framework runs as a handoff to another agent: never
        gated, so the model asking for one is not a missing decide."""
        return any(fnmatch.fnmatchcase(tool, h) for h in self.policy.get("handoffs", ()))

    def is_structured_output(self, tool):
        """Whether the policy's `structured_output:` names `tool` as one the model asks for in its structured output
        rather than as a tool call (Browser Use's actions), or as the tool call that carries that output: reconciliation
        expects no tool use for its decides and no decide for its tool uses."""
        return any(fnmatch.fnmatchcase(tool, h) for h in self.policy.get("structured_output", ()))

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
        """Return {verdict, rule_ids, policy_hash, engine[, nondeterministic][, oversize]} for one tool call
        (`oversize`: the subjects TK-OVERSIZE stands for, named by their rule and field). `cls` overrides the class the
        policy maps the tool to. `untrusted(subject, field)`: the hits of the subject's values that only
        untrusted content brought into the run (`field`: the rule's); a `from: untrusted` rule matches a subject only
        when there is one (never without `untrusted`), and matches each element of a list field (payees, recipients)
        on its own."""
        args = args if isinstance(args, dict) else {"value": args}
        cls = cls or self.tool_class(tool)
        fields = classes.extract(cls, tool, args)
        hits = {sec: [] for sec in SECTIONS}
        if cls == "unknown" and self.policy.get("unknown_tools") in SECTIONS:
            hits[self.policy["unknown_tools"]].append("TK-UNKNOWN-TOOL")
        if cls == "sql" and fields.get("statement") is not None and not fields.get("code"):
            hits["ask"].append("TK-SQL-PARSE")   # no dialect reads it: an unclosed literal or comment, or not text
        nondeterministic, deadline = False, time.monotonic() + REGEX_TIMEOUT_S
        parsed, oversize = ([], [], []), []
        if cls == "shell":
            command = fields.get("command", "")
            if len(_text(command if isinstance(command, str) else canonical(command)).encode()) > MAX_SUBJECT:
                hits["deny"].append("TK-OVERSIZE")
                oversize.append("the shell command")
            else:
                unreadable = hits[self.policy.get("on_parse_error", "ask")]   # TK-SHELL-PARSE's section
                try:
                    parsed = _shell(args)
                except shell.ParseError:
                    unreadable.append("TK-SHELL-PARSE")
                    parsed = [], [], [command if isinstance(command, str) else canonical(command)]   # its own target
                if any(c["opaque"] for c in parsed[0]):
                    unreadable.append("TK-SHELL-PARSE")
        name, memo = _text(tool), {}
        if cls not in self._of:   # the rules a class's calls reach: those of no class and of that class
            self._of[cls] = [x for x in self.rules if x[1].get("class", cls) == cls]
        for sec, rule, tool_re, pat, unless, lits in self._of[cls]:
            try:
                if tool_re is not None and not self._match(tool_re, name, True, deadline):
                    continue
                key = (rule.get("field"), "from" in rule)   # rules on the same subjects read them once
                if key not in memo:
                    memo[key] = _prepare(self._subjects(cls, key[0], args, fields, parsed, key[1]))
                texts, lows, joined, big = memo[key]
                hit = None
                if lits is None or any(s in joined for s in lits):
                    for subject, low in zip(texts, lows):
                        # `unless`: an exemption checked against the same subject (use it only where the subject is
                        # one target, e.g. a file path; in a whole command it could exempt a different target)
                        if (lits is None or len(texts) == 1 or any(s in low for s in lits)) and self._match(
                                pat, subject, False, deadline) and not (
                                unless is not None and self._match(unless, subject, False, deadline)) and (
                                "from" not in rule or untrusted is not None and untrusted(subject, rule.get("field"))):
                            hit = rule["id"]
                            break
                if hit is None and big:   # the rule's own verdict: a flag rule cannot block a large call
                    hit = "TK-OVERSIZE"
                    field = rule.get("field") or ("argv" if cls == "shell" else "the whole arguments")
                    oversize.append(f"{rule['id']}'s subject ({field})")
                if hit is not None:
                    hits[sec].append(hit)
            except TimeoutError:   # the time of the whole decision is spent: deny, and leave the other rules out
                nondeterministic = True
                hits["deny"].append(rule["id"])
                break
        verdict = next((sec for sec in SECTIONS if hits[sec]), "allow")
        out = {"verdict": verdict, "rule_ids": list(dict.fromkeys(hits["deny"] + hits["ask"] + hits["flag"])),
               "policy_hash": self.policy_hash, "engine": self.engine}
        if nondeterministic:
            out["nondeterministic"] = True
        if oversize:
            out["oversize"] = oversize
        return out

    @staticmethod
    def _subjects(cls, field, args, fields, parsed, split=False):
        """A class field matches the signer's extraction; any other field names a raw argument; no field scans the
        whole call (Write/Edit content, WebFetch url and prompt, MCP args). A shell `line` is the raw command and
        each line the parser normalised; an fs `path` with `..` also matches its lexically normalised form, and each
        entry of a `paths` list (every file of a Codex patch) is a path too. `target` (every class) is what the call
        acts on rather than what it carries (Engine._targets); sql `code` is one subject per dialect reading. With
        `split`, a list value is one subject per element (nested lists flattened)."""
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
        if split and isinstance(value, list):
            return [v if isinstance(v, str) else canonical(v) for v in _flat(value)]
        return [value if isinstance(value, str) else canonical(value)]

    @staticmethod
    def _targets(cls, args, fields, parsed):
        """shell: each command's argv without its data words (shell.data_words), the redirection targets, assignments
        and heredoc programs; fs: the paths; http and browser: the URL; email: the attachments; mcp, app and unknown
        tools: the whole call. Each URL is also matched as scheme://canonical-host/ (classes.url_target), so a host in
        decimal, hex, octal or IPv6 form reads as the address it is."""
        if cls == "shell":
            words = [[a for i, a in enumerate(c["argv"]) if i not in data] for c in parsed[0]
                     for data in [shell.data_words(c["argv"])]]
            found = [a for ws in words for a in ws] + parsed[2]
            urls = [t for t in map(classes.url_target, (u for w in found for u in _URL.findall(w))) if t]
            bare = [t for t in (classes.url_target("http://" + w) for w in found if _BARE_ADDRESS.match(w))
                    if t and _BARE_TARGET.fullmatch(t)]
            return [" ".join(w) for w in words] + parsed[2] + urls + bare
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
        return [canonical(args)] if cls in ("mcp", "app", "unknown") else []


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


def _flat(values):
    return [x for v in values for x in (_flat(v) if isinstance(v, list) else [v])]


def _prepare(subjects):
    """(the subjects as text, up to the first longer than MAX_SUBJECT; their lower-case forms; those joined by a
    newline; whether one was longer). A rule matches the subjects before a long one and, matching none, takes
    TK-OVERSIZE, as one that walked them in order would."""
    texts = []
    for s in subjects:
        b = s.encode("utf-8", "backslashreplace")
        if len(b) > MAX_SUBJECT:
            break
        texts.append(b.decode("utf-8"))
    lows = [t.lower() for t in texts]
    return texts, lows, "\n".join(lows), len(texts) < len(subjects)


def _text(s):
    """Lone surrogates (valid in JSON escapes, not in UTF-8) become \\udxxx text, the same for both engines."""
    return s.encode("utf-8", "backslashreplace").decode("utf-8")
