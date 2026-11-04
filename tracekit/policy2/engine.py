"""Policy v2 engine: deterministic matching over a compiled policy (design §4.2).

google-re2 when installed, else the `regex` module on the same pattern subset in ASCII mode (`compile.translate`).
Every decision names the engine (id@version) and the policy_hash. Precedence: deny > ask > flag > allow.
"""
import ast
import fnmatch
import functools
import posixpath
import re
import time
import unicodedata

from . import classes, shell
from .compile import BOUND_TYPES, CLASSES, SECTIONS, canonical, literals, policy_hash, translate

MAX_SUBJECT = 64 * 1024     # bytes of UTF-8; a longer subject is never cut or windowed: TK-OVERSIZE in its rule's section
AGENT_ARGS_MAX = 16 * 1024  # bytes of a call's arguments (as canonical JSON) an agent approval may cover
# arguments the class extractors read as one field: a call carrying two of a group is a person's to answer
ALIASES = (classes.SHELL_KEYS, classes.PATH_KEYS, classes.PAYEE_KEYS, classes.RECIPIENT_KEYS,
           ("amount", "amount_cents"), ("sql", "query", "statement"), ("db", "database"))
_URL = re.compile(r"(?i)\b(?:https?|wss?|ftp):[^\s'\"<>`]*")
_DOTTED = re.compile(r"(?:^|/)\.\.?(?:/|$)|(?<!:)//")   # a path with . or .. parts, or an empty one (not a URL's)
# a line with a word _DOTTED finds (and maybe more): _DOTTED's `$` also matches before a word's last newline
_DOTTED_WORD = re.compile(r"(?:^|[/ ])\.\.?(?:[/ ]|\n? |$)|(?<!:)//")
_BARE_ADDRESS = re.compile(r"[0-9][0-9A-Za-z.]*(:[0-9]*)?([/?#]|$)")   # curl 2852039166/latest
# ...when it reads as an IPv4 address outside 0.0.0.0/8, which no call reaches: not 1.txt, 2fa/ or head -n 50's 50.
# lean: a dotted number (npm version 1.2.3) still reads as one; read bare words only in network commands if it flags
# too much
_BARE_TARGET = re.compile(r"http://[1-9][0-9]*(\.[0-9]+){3}/")
_SCHEDULED = {"trap", "at <<<", "at <<", "batch <<<", "batch <<"}   # shell.py's `via` for code run later
# what every second reading of a line starts from (shell.analyse's `readings`): an expansion or substitution read as
# empty, a pattern as matching nothing or as the names its brackets make. The texts the parser reads hold only the
# line's characters ($'…' decodes others, after a $)
_SECOND = re.compile(r"[$`*?[]")
# the shell fields whose subjects carry a tag of up to this many bytes (ACT:, RUNS_DOWNLOAD: …), which doesn't count
# toward a subject's size: a command just under MAX_SUBJECT isn't oversize for being tagged
_TAGGED = {"tracekit": 16, "downloads": 16}
REGEX_TIMEOUT_S = 1.0      # fallback engine only: the time all matches of one decision share; a match that runs out
                            # of it denies, marked nondeterministic


def _backend(name):
    """Return (engine id, compile(pattern, anycase=False), match(compiled, text, full, deadline)); only the fallback
    uses the deadline (time.monotonic())."""
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
            return (f"re2@{version('google-re2')}", lambda p, anycase=False: re2.compile("(?i)" * anycase + p, opts),
                    lambda c, s, full, deadline: (c.fullmatch if full else c.search)(s))
    import regex
    return (f"regex@{regex.__version__}", lambda p, anycase=False: regex.compile(
                translate(p), regex.ASCII | regex.V0 | regex.IGNORECASE * anycase),
            lambda c, s, full, deadline: (c.fullmatch if full else c.search)(
                s, timeout=max(deadline - time.monotonic(), 1e-6)))


class Engine:
    def __init__(self, policy, backend=None):
        """`policy` is a compiled policy (compile.build); `backend` forces "re2" or "regex"."""
        self.policy, self.policy_hash = policy, policy_hash(policy)
        self.tool_class = functools.lru_cache(maxsize=1024)(self.tool_class)   # a glob scan per call otherwise
        self.engine, compile_, self._match = _backend(backend)
        # each rule's prefilters (compile.literals), of its pattern and of its tool pattern: a subject or a tool name
        # holding none of its strings is not searched. An a2a rule matches in any case, as every prefilter does: the
        # names it reads are lower-cased (classes.a2a_fields)
        def rx(r, key):
            return compile_(r[key], r.get("class") == "a2a")
        self.rules = [(sec, r, compile_(r["tool"]) if "tool" in r else None, rx(r, "pattern"),
                       rx(r, "unless") if "unless" in r else None, literals(r["pattern"]),
                       literals(r["tool"]) if "tool" in r else None)
                      for sec in SECTIONS for r in self.policy.get(sec, [])]
        # The filesystem persistence rules are the source of truth for paths whose written text stays executable.
        self._persistent_targets = [pat for _, rule, _, pat, *_ in self.rules if rule["id"] in ("TK-A010", "TK-A012")]
        self._of = {}
        # an ask rule's approval.agent patterns: (rule id, argument name) -> compiled
        self._bounds = {(r["id"], name): compile_(b["pattern"]) for _, r, *_ in self.rules
                        for name, b in (r.get("approval") or {}).get("agent", {}).get("allow", {}).get("fields", {}).items()
                        if "pattern" in b}
        # the names `tools:` lists (not its globs) by spelling, for listed(); a spelling two names share names both
        self._spelled = {}
        for t in self.policy.get("tools", {}):
            if not any(c in t for c in "*?[") and _spelling(t):   # a name with no ASCII letter or digit spells none
                self._spelled.setdefault(_spelling(t), []).append(t)

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

    def listed(self, tool):
        """The names `tools:` lists that `tool` spells with case, spaces and punctuation ignored (every one, when two
        share the spelling: the server pack's `bash` and the coding pack's `Bash`), when it lists neither `tool` nor a
        glob that takes it; [] otherwise. Frameworks rewrite the names they are given: CrewAI's hooks see `bash` for a
        tool declared `Bash`, `multi_edit` for `MultiEdit`."""
        if tool in self.policy.get("tools", {}) or self.tool_class(tool) != "unknown":
            return []
        return list(self._spelled.get(_spelling(tool), ()))

    def untrusted_results(self, tool):
        """Whether the policy's `untrusted` list (tool classes and tool name globs) marks the tool's results untrusted,
        or those of a tool it spells (listed)."""
        return any(any(u == self.tool_class(name) if u in CLASSES else fnmatch.fnmatchcase(name, u)
                       for u in self.policy.get("untrusted", ()))
                   for name in (tool, *self.listed(tool)))

    def reads(self, tool, cls=None):
        """{section: [rule ids]} decide() reads for a call of `tool` (`cls` overrides its class, as for decide): those
        of no class or of that class whose tool pattern takes its name (the viewer's WHY THIS DECISION)."""
        cls, name, deadline = cls or self.tool_class(tool), _text(tool), time.monotonic() + REGEX_TIMEOUT_S
        low, out = name.lower(), {sec: [] for sec in SECTIONS}
        for sec, rule, tool_re, *_, tool_lits in self.rules:
            if rule.get("class", cls) == cls and self._named(tool_re, tool_lits, name, low, deadline):
                out[sec].append(rule["id"])
        return out

    def _named(self, tool_re, lits, name, low, deadline):
        """Whether a rule's tool pattern takes the tool `name` (`low`: lower-cased); none takes every name. A name
        holding none of the pattern's literals is not searched: 27 searches of a 48 KiB MCP name of `run_` took the
        fallback engine 0.3 s on a laptop, past its 1 s on CI's macOS runners (#481)."""
        return tool_re is None or (lits is None or any(map(low.__contains__, lits))) and self._match(
            tool_re, name, True, deadline)

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
        if cls == "a2a" and fields.get("unreadable"):
            hits["deny"].append("TK-A2A-NAME")   # a name with spellings its rules can't see (classes.a2a_fields)
        parsed, oversize, on_parse_error = ([], [], [], [], []), [], self.policy.get("on_parse_error", "ask")
        cause = None
        if cls == "shell":
            command = fields.get("command", "")
            if len(_text(command if isinstance(command, str) else canonical(command)).encode()) > MAX_SUBJECT:
                hits["deny"].append("TK-OVERSIZE")
                oversize.append("the shell command")
            else:
                parsed, unread = self._parse(args, command)
                # what trap, at or batch run later and the parser can't read (trap "$f" EXIT) isn't held, as before
                # their code was read; with a writer's name in it, it counts for TK-D008 (_effects)
                held = next((c for c in parsed[0] if c["opaque"] and not _SCHEDULED.intersection(c["via"])), None)
                if unread or held:
                    hits[on_parse_error].append("TK-SHELL-PARSE")
                    cause = "syntax" if unread else _unread_cause(held)
        # from here: the fallback's time is its matches', not the parse's, which is the same on either engine and bounded by MAX_WORK (a few times the 64 KiB input)
        nondeterministic, deadline = False, time.monotonic() + REGEX_TIMEOUT_S
        name, memo = _text(tool), {}
        low_name = name.lower()
        if cls not in self._of:   # the rules a class's calls reach: those of no class and of that class
            self._of[cls] = [x for x in self.rules if x[1].get("class", cls) == cls]

        def hit(entry, parsed, memo, oversize):
            """The id a rule gives the call (its own, or TK-OVERSIZE when it matches none of the subjects before one
            over MAX_SUBJECT), else None; TimeoutError past the deadline."""
            sec, rule, tool_re, pat, unless, lits, tool_lits = entry
            if tool_re is not None and not self._named(tool_re, tool_lits, name, low_name, deadline):
                return None
            # rules on the same subjects read them once (a shell rule with no field reads argv)
            field = rule.get("field")
            key = ("argv" if field is None and cls == "shell" else field, "from" in rule)
            if key not in memo:
                memo[key] = _prepare(self._subjects(cls, key[0], args, fields, parsed, key[1]),
                                     _TAGGED.get(key[0], 0))
            texts, lows, joined, big = memo[key]
            if lits is None or any(map(joined.__contains__, lits)):
                for subject, low in zip(texts, lows):
                    # `unless`: an exemption checked against the same subject (use it only where the subject is
                    # one target, e.g. a file path; in a whole command it could exempt a different target)
                    if (lits is None or len(texts) == 1 or any(map(low.__contains__, lits))) and self._match(
                            pat, subject, False, deadline) and not (
                            unless is not None and self._match(unless, subject, False, deadline)) and (
                            "from" not in rule or untrusted is not None and _brought(untrusted, subject, rule.get("field"),
                                                                                     fields)):
                        return rule["id"]
            if big:   # the rule's own verdict: a flag rule cannot block a large call
                field = rule.get("field") or ("argv" if cls == "shell" else "the whole arguments")
                oversize.append(f"{rule['id']}'s subject ({field})")
                return "TK-OVERSIZE"
            return None
        for entry in self._of[cls]:
            try:
                if (found := hit(entry, parsed, memo, oversize)) is not None:
                    hits[entry[0]].append(found)
            except TimeoutError:   # the time of the whole decision is spent: deny, and leave the other rules out
                nondeterministic = True
                hits["deny"].append(entry[1]["id"])
                break
        # a deny that only a second reading of the command makes (an expansion read as empty, a pattern as matching
        # nothing: `rm -rf "$D"/`), and not the command as written, takes on_parse_error's section: the line can't say
        # whether $D is empty, so by default a person answers it. A line with no $, backquote or pattern character has
        # no second reading (_SECOND): it reads the same without them, so each of its denies is as written
        written = [x for x in self._of[cls] if x[0] == "deny" and x[1]["id"] in hits["deny"]]
        if cls == "shell" and on_parse_error == "ask" and written and not nondeterministic and (
                not isinstance(command, str) or _SECOND.search(command)):
            parsed, memo = self._parse(args, command, readings=False)[0], {}
            for entry in written:
                try:
                    if hit(entry, parsed, memo, []) is None:
                        hits["deny"].remove(entry[1]["id"])
                        hits["ask"].append(entry[1]["id"])
                except TimeoutError:   # it stays a deny
                    nondeterministic = True
                    break
        verdict = next((sec for sec in SECTIONS if hits[sec]), "allow")
        out = {"verdict": verdict, "rule_ids": list(dict.fromkeys(hits["deny"] + hits["ask"] + hits["flag"])),
               "policy_hash": self.policy_hash, "engine": self.engine}
        if nondeterministic:
            out["nondeterministic"] = True
        if oversize:
            out["oversize"] = oversize
        if cause:
            out["unread"] = cause
        return out

    def _parse(self, args, command, readings=True):
        """(shell.analyse() of a shell call, or what _plain() reads of one the parser can't read; whether it can't).
        `readings`: False reads the command only as written (shell.analyse)."""
        target = (lambda t: any(p.search(_text(t.casefold())) for p in self._persistent_targets)) \
            if self._persistent_targets else None
        try:
            return _shell(args, target, readings), False
        except shell.ParseError as e:
            return (_plain(command, getattr(e, "at", 0), readings, target) if isinstance(command, str) else
                    _plain(canonical(command), 0, readings, target)), True

    @staticmethod
    def _subjects(cls, field, args, fields, parsed, split=False):
        """A class field matches the signer's extraction; any other field names a raw argument; no field scans the
        whole call (Write/Edit content, WebFetch url and prompt, MCP args). A shell `line` is the raw command and
        each line the parser normalised, a shell `code` those without the text a command only writes into a file
        (shell.analyse); an fs `path` with `..` also matches its lexically normalised form, and each entry of a
        `paths` list (every file of a Codex patch) is a path too, and an http field is read for each URL of a `urls`
        list too (every URL a Gemini CLI web_fetch prompt names). `target` (every class) is what the call
        acts on rather than what it carries (Engine._targets); shell `effects` the files it writes or deletes
        (_effects); sql `code` is one subject per dialect reading. With
        `split`, a list value is one subject per element (nested lists flattened)."""
        if cls == "http" and field is not None and isinstance(args.get("urls"), list):   # a call on several URLs
            urls = canonical(args["urls"])
            if len(_text(urls).encode()) > MAX_SUBJECT:   # unread, as a long subject is: TK-OVERSIZE in its rule's section
                return [urls]
            one = {k: v for k, v in args.items() if k != "urls"}
            return list(dict.fromkeys(s for a in [one] + [{**one, "url": u} for u in args["urls"]] for s in
                                      Engine._subjects(cls, field, a, classes.extract(cls, "", a), parsed, split)))
        if field == "target":
            return Engine._targets(cls, args, fields, parsed)
        if cls == "shell" and field == "effects":
            return _effects(parsed)
        if cls == "shell" and field == "tracekit":
            return _tracekit(parsed)
        if cls == "shell" and field == "downloads":
            return _code(parsed) + _downloads(parsed)
        if cls == "shell" and field == "package_index":
            return _package_indexes(parsed[0], parsed[2])
        if cls == "shell" and field == "container_host_access":
            return _container_host_access(parsed[0])
        if cls == "sql" and field == "code":
            return fields.get("code", [])
        if cls == "shell" and field == "code":
            return _code(parsed)
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
        and heredoc programs, each also casefolded as a path is (the agent's file system may ignore case: `cp x .ENV`
        writes .env on macOS); fs: the paths; http and browser: the URL; email: the attachments; a2a: the receiver;
        mcp: the whole call without the text it only carries (_acted_on), each string in it with a `/` or `\\` also
        read as a path is (classes.fs_forms: `/root/.aws//credentials`); app and unknown tools: the whole call. Each
        URL is also matched as scheme://canonical-host/ (classes.url_target), so a host in decimal, hex, octal or IPv6
        form reads as the address it is: of mcp, app and unknown tools, each URL in a string of what they act on."""
        if cls == "shell":
            commands = parsed[0]
            words = [[a for i, a in enumerate(c["argv"]) if i not in data] for c in commands
                     for data in [shell.data_words(c["argv"]) | set(c.get("data_words", ()))]]
            stdin = [s for c in commands if not c.get("data_stdin") for s in c["stdin"]]
            found = [a for ws in words for a in ws] + parsed[2] + stdin
            urls = [t for t in map(classes.url_target, (u for w in found if ":" in w for u in _URL.findall(w))) if t]
            bare = [t for t in (classes.url_target("http://" + w) for w in found if _BARE_ADDRESS.match(w))
                    if t and _BARE_TARGET.fullmatch(t)]
            targets = [" ".join(w) for w in words] + parsed[2] + stdin
            return _path_forms(targets) + urls + bare
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
        if cls == "a2a":   # the agent or model it reaches, and the message it carries
            to = fields.get("receiver")
            receiver = [] if to is None else [to if isinstance(to, str) else canonical(to)]
            return receiver + [canonical(args.get("params"))]
        if cls not in ("mcp", "app", "unknown"):
            return []
        tool = fields.get("tool")
        call = _acted_on(args, _carried(tool if isinstance(tool, str) else "")) if cls == "mcp" else args
        strings = _strings(call)
        paths = [f for s in strings if "/" in s or "\\" in s for f in classes.fs_forms(s)] if cls == "mcp" else []
        urls = [t for t in map(classes.url_target, (u for s in strings for u in _URL.findall(s))) if t]
        return list(dict.fromkeys([canonical(call)] + paths + urls))


def _unread_cause(command):
    """Why the parser can't read what an opaque command runs, as a key of compile.ENGINE_REASONS's TK-SHELL-PARSE
    causes: a function the line defines and doesn't call, or exports (function); its name is built by a variable or
    substitution (name) or a pattern (pattern); a shell bash isn't (foreign);
    a shell, interpreter, source, at, batch, parallel or xargs that runs code from a pipe, a file or its input (input);
    else other."""
    name = command["argv"][0]
    if any(v.endswith("(defined)") for v in command["via"]):
        return "function"
    if re.search(r"[$`]", command["word"]):
        return "name"
    if re.search(r"[*?[{]", command["word"]):
        return "pattern"
    if name in shell.FOREIGN_SHELLS:
        return "foreign"
    if name in shell.SHELLS or shell._kind(name) or name in ("source", ".", "at", "batch", "parallel", "xargs") or \
            name in shell.DASH_C or command["via"][-1:] == ["xargs"]:
        return "input"
    return "other"


def _path_forms(targets):
    """Targets, each also as plainly written (/etc/./x, /etc//x and /etc/y/../x name /etc/x) and casefolded."""
    have = set(targets)
    targets = targets + [n for n in (" ".join(posixpath.normpath(p) if _DOTTED.search(p) else p for p in t.split(" "))
                                     for t in targets if _DOTTED_WORD.search(t)) if n not in have]
    have = set(targets)
    return targets + [f for f in dict.fromkeys(map(str.casefold, targets)) if f not in have]


def _shell(args, persistent_target=None, readings=True):
    """shell.analyse() of a shell call: (commands, normalised lines, other words that name something, files
    redirections write, code). `command` or `cmd` is a command line or an argv list; `commands` (OpenAI's shell tool)
    a list of command lines. Anything else, or more than one of them, raises ParseError."""
    present = [k for k in classes.SHELL_KEYS if args.get(k) is not None]
    if len(present) > 1:
        raise shell.ParseError(f"more than one command field: {present}")
    value = args[present[0]] if present else ""
    strings = isinstance(value, list) and value and all(isinstance(a, str) for a in value)
    if isinstance(value, str):
        return shell.analyse(value, persistent_target, readings)
    if strings and present == ["commands"]:
        return shell.analyse("\n".join(value), persistent_target, readings)
    if strings:
        return shell.analyse_argv(value, readings)
    raise shell.ParseError("the command is neither a string nor a list of strings")


# a piece of a line between ;, &, | and newlines outside quotes, as bash separates commands; a quote left open runs to
# the end of the line, as bash reads no command after it; a # that starts a word comments out the rest of its line, a
# quote in it too
_PIECE = re.compile(r"""(?:(?<![^ \t\n;&|(])(?<!\\.)#[^\n]*|[^;&|\n'"\\]|\\.?|'[^']*(?:'|\Z)|"(?:[^"\\]|\\.?)*(?:"|\Z))+""", re.S)


def _plain(raw, at=0, readings=True, persistent_target=None):
    """What a command the parser can't read is decided on: its text as its target and code; the line before the word
    it stopped in (`at`: where), parsed; and each piece of the rest (_PIECE), from the one it stopped in, split on
    blanks as a command (shell.analyse_argv), so a rule that reads plain words still holds what it held (`sudo id
    {1..3..1}`). A part that can't be read so is left out; the parts share one parse budget (shell.MAX_WORK).
    `persistent_target`: as for shell.analyse, so text echoed into ~/.bashrc stays code in the head too."""
    out, start, work = ([], [], [raw], [], [raw]), 0, [0]
    head = raw[:max(0, *(raw.rfind(c, 0, at) for c in " \t\n"))]
    found = []
    if head.strip():
        try:
            found.append(shell.analyse(head, persistent_target, readings, work))
            last = ([m.span() for m in _PIECE.finditer(head)] or [(0, 0)])[-1]
            start = last[0] if last[1] == len(head) else last[1] + 1   # after a separator that ends the head
        except shell.ParseError:
            pass
    for piece in (m.group() for m in _PIECE.finditer(raw, start)):
        try:
            found.append(shell.analyse_argv(piece.split(), readings, work) if piece.split() else ())
        except shell.ParseError:
            continue
    for reading in found:
        for into, more in zip(out, reading):
            into += more
    return out


# variables that set a package source: before a command (`PIP_INDEX_URL=… pip install`), or through env or export
_SOURCE_VARIABLES = dict.fromkeys(("PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "UV_INDEX_URL", "UV_INDEX",
                                   "UV_EXTRA_INDEX_URL", "UV_DEFAULT_INDEX", "UV_FIND_LINKS"), "pypi.org")
_SOURCE_VARIABLES["NPM_CONFIG_REGISTRY"] = "registry.npmjs.org"


_PIP = re.compile(r"pip[0-9.]*")


def _package_indexes(commands, refs=()):
    """Return only explicitly selected non-default package sources, one subject per effective option or variable."""
    words = list(refs) + [a for c in commands if c["argv"][:1] in (["env"], ["export"]) for a in c["argv"][1:]]
    out = [value for name, eq, value in (w.partition("=") for w in words)
           if eq and name.upper() in _SOURCE_VARIABLES and _non_default_source(value, _SOURCE_VARIABLES[name.upper()])]
    for command in commands:
        argv = command["argv"]
        if not argv:
            continue
        exe = argv[0].rsplit("/", 1)[-1].casefold()
        args = argv[1:]
        if exe.startswith("python") or exe == "py":   # py: the Windows launcher
            module = _python_module(args)
            if module[:1] == ["pip"]:
                exe, args = "pip", module[1:]
        exe = "pip" if _PIP.fullmatch(exe) else {"uvx": "uv", "npx": "npm", "pnpx": "pnpm"}.get(exe, exe)
        if exe == "pip":
            default, options = "pypi.org", {"-i", "--index-url", "--extra-index-url", "-f", "--find-links"}
        elif exe == "uv":
            default, options = "pypi.org", {"-i", "--index-url", "--extra-index-url", "--default-index", "--index",
                                            "-f", "--find-links"}
            if args[:1] == ["pip"]:
                args = args[1:]
        elif exe in ("npm", "pnpm", "yarn", "bun"):
            default, options = "registry.npmjs.org", {"--registry"}
        elif exe in ("poetry", "cargo", "gem"):
            default, options = {"poetry": "pypi.org", "cargo": "crates.io", "gem": "rubygems.org"}[exe], {
                "poetry": {"--source"}, "cargo": {"--index", "--registry"}, "gem": {"--source"}}[exe]
        else:
            continue
        command = next((a for a in args if not a.startswith("-")), None)   # after global options (pip --isolated)
        if command in ("publish", "unpublish"):
            continue   # publishing doesn't change where installs come from
        if exe == "gem" and command in ("install", "i", "update", "fetch"):
            options = options | {"-s"}   # --source's short form there (gem cert's -s signs)
        elif exe == "gem" and command == "sources":
            options = {"-a", "--add"}   # a source every later install reads
        if command == "config" and "set" in args or exe == "npm" and command == "set":
            # `set key value` or `set key=value ...`, options anywhere
            words = [a for a in args[args.index("set") + 1:] if not a.startswith("-")]
            for i, word in enumerate(words):
                key, eq, value = word.partition("=")
                value = value if eq else words[i + 1] if i + 1 < len(words) else None
                if value is not None and (
                        (exe == "pip" and key.rsplit(".", 1)[-1] in {"index-url", "extra-index-url", "find-links"})
                        or (exe in ("npm", "pnpm", "yarn", "bun") and (key == "registry" or key.endswith(":registry")))):
                    if _non_default_source(value, default):
                        out.append(value)
            continue
        selected, i = [], 0
        while i < len(args):
            arg = args[i]
            name, value = (arg.split("=", 1) + [None])[:2] if "=" in arg else (arg, None)
            # pip (optparse) takes a long option's unique prefix: --index-u is --index-url
            if exe == "pip" and len(name) > 2 and name.startswith("--"):
                name = next((o for o in options if o.startswith(name)), name)
            scoped = exe in ("npm", "pnpm", "yarn", "bun") and name.startswith("--@") and name.endswith(":registry")
            if name in options or scoped:
                if value is None and i + 1 < len(args):
                    value = args[i + 1]
                    i += 1
                if scoped:   # a scope's own registry (--@acme:registry=…), whatever --registry says
                    out += [value] if value is not None and _non_default_source(value, default) else []
                elif exe in ("npm", "pnpm", "yarn", "bun"):
                    selected = [value] if value is not None else []  # npm uses the last --registry
                elif value is not None:
                    if exe == "uv" and name == "--index" and "=" in value:
                        value = value.split("=", 1)[1]
                    selected.append(value)
            elif exe == "pip" and arg.startswith("-i") and arg != "-i":
                selected.append(arg[2:])
            i += 1
        for value in selected:
            if value is None or _non_default_source(value, default):
                out.append(value or "<missing>")
    return out


def _python_module(args):
    """[module, its arguments...] that `python ARGS` runs with -m, read past python's own options (in a cluster too,
    -W and -X with their value: `python -I -m pip`, `python -mpip`), else []."""
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] not in ("-", "--"):
        word = args[i]
        i += 1
        if word.startswith("--"):
            i += word == "--check-hash-based-pycs"
            continue
        for j, c in enumerate(word[1:], 2):
            if c == "c":
                return []
            if c in "mWX":
                value = word[j:]
                if not value and i < len(args):
                    value, i = args[i], i + 1
                if c == "m":
                    return [value] + args[i:]
                break
    return []


def _non_default_source(value, default):
    host = classes.url_info(value).get("host")
    return host != default


# docker/podman run options that take no value; any other long option without `=` takes the next word
_RUN_FLAGS = {"--detach", "--interactive", "--tty", "--rm", "--init", "--privileged", "--read-only", "--publish-all",
              "--no-healthcheck", "--oom-kill-disable", "--disable-content-trust", "--quiet", "--sig-proxy", "--help",
              "--use-api-socket", "--replace", "--rmi", "--http-proxy", "--env-host", "--no-hosts", "--passwd",
              "--read-only-tmpfs", "--tls-verify"}
# a mount source that hands the container the host's root, /proc, /etc or root's home (a file under /etc, such as
# /etc/localtime, isn't one)
_HOST_PATH = re.compile(r"/|/proc(/.*)?|/etc|/root(/.*)?")
_CONTAINER_VERBS = {"run", "create", "exec", "container"}
# docker's and podman's global options that always take the next word, a verb's name too (`docker --context run run`),
# and those that never do; another reads one unless an option or a verb follows
_GLOBAL_VALUED = {"-H", "--host", "-c", "--context", "--connection", "--config", "-l", "--log-level", "--url",
                  "--tlscacert", "--tlscert", "--tlskey", "--identity", "--root", "--runroot", "--storage-driver",
                  "--storage-opt", "--cgroup-manager", "--events-backend", "--hooks-dir", "--module", "--tmpdir",
                  "--runtime", "--runtime-flag", "--conmon", "--network-cmd-path", "--network-config-dir",
                  "--volumepath", "--imagestore", "--db-backend", "--ssh"}
_GLOBAL_FLAGS = {"-D", "--debug", "--tls", "--tlsverify", "-r", "--remote", "--syslog", "--noout", "-v", "--version",
                 "-h", "--help"}


def _host_path(source):
    """Whether mount source `source` is a _HOST_PATH, read as the runtime resolves it (`//`, `/.`)."""
    p = posixpath.normpath(source)
    return bool(_HOST_PATH.fullmatch("/" + p.lstrip("/") if p.startswith("/") else p))


def _container_host_access(commands):
    """A docker/podman run, create or exec (also as `container run`, and after the CLI's global options: docker -H
    host, --context prod, podman --remote; one that takes a value takes it whatever it is named, _GLOBAL_VALUED) whose
    own options (those before the image or container: later words are
    the command it runs) give it host privileges or every capability, the host's process space, or a _HOST_PATH."""
    for command in commands:
        argv = command["argv"]
        if not argv or argv[0].rsplit("/", 1)[-1] not in ("docker", "podman"):
            continue
        words, i = argv[1:], 0
        while i < len(words) and words[i].startswith("-"):   # a global option, and its value (_GLOBAL_VALUED)
            w = words[i]
            i += 1 if "=" in w or w in _GLOBAL_FLAGS or w not in _GLOBAL_VALUED and i + 1 < len(words) and (
                words[i + 1].startswith("-") or words[i + 1] in _CONTAINER_VERBS) else 2
        words = words[i:]
        words = words[1:] if words[:1] == ["container"] else words
        if words[:1] not in (["run"], ["create"], ["exec"]):
            continue
        args, i = words[1:], 0
        while i < len(args) and args[i].startswith("-"):
            arg = args[i]
            if arg.startswith("--"):
                name, eq, value = arg.partition("=")
                takes = not eq and name not in _RUN_FLAGS
            else:   # a short cluster: flags, then at most one option, valued by the rest or the next word
                j = next((j for j, c in enumerate(arg[1:], 1) if c not in "ditPq"), len(arg))
                name, value = "-" + arg[j:j + 1], arg[j + 1:].removeprefix("=")
                takes = j < len(arg) and not value
            if takes and i + 1 < len(args) and not args[i + 1].startswith("-"):   # an option is never a value
                i += 1
                value = args[i]
            i += 1
            if (name == "--privileged" and value.lower() not in ("0", "f", "false")
                    or name == "--pid" and value == "host"
                    or name == "--cap-add" and any(c.strip().upper().removeprefix("CAP_") == "ALL"
                                                   for c in value.split(","))
                    or name in ("-v", "--volume") and _host_path(value.partition(":")[0])
                    or name == "--mount" and any(k in ("src", "source") and _host_path(v)
                                                 for k, _, v in (item.partition("=") for item in value.split(",")))):
                return ["host-access"]
    return []


_HISTORY = (".bash_history", ".zsh_history", "fish_history", "consolehost_history.txt")


def _log_or_history(path):
    """Whether a path is under /var/log (macOS's /private/var/log too) or names a shell history file, in any case."""
    p = path.replace("\\", "/").casefold()
    return p.startswith(("/var/log", "/private/var/log")) or any(part.endswith(_HISTORY) for part in p.split("/"))


def _effects(parsed):
    """The files the commands write, each as WRITE_TARGET:path, and delete, as DELETE_TARGET:path, each also with the
    path resolved (_normal) and casefolded: what redirections write, and what rm, unlink, shred, truncate, tee, cp, mv, install, ln, dd,
    sed -i and perl -i name, find with -delete, -exec rm or an -exec that writes each file found (sed -i), awk's
    print > "file", zip -m's sources, and one of those that git, docker, podman, kubectl or parallel runs from its words
    (git rm). When a command writes files the line names only at run time or inside code it runs (_opaque), or the
    parser can't read what one runs (its `opaque`: `| sh`, `fish -c`, a name an expansion builds) and a writer's name
    reaches it (_reaches_unread), every word on the line and each herestring and heredoc text is one it may write, as
    MAY_WRITE:word (only TK-D008 reads those); for one the parser can't read, each normalised line too (a name an
    expansion builds may hold the path). A link ln or cp -s/-l makes is also MAY_WRITE: a later write through it
    writes the file it points at."""
    tags = ["WRITE_TARGET:" + _text(ref) for ref in parsed[3]] + _command_effects(parsed[0])
    unread, scripts = any(c["opaque"] for c in parsed[0]), _written_scripts(parsed[0])
    if any(_opaque(c, scripts) for c in parsed[0]) or unread and _reaches_unread(parsed):
        # lean: a read on the same line as such a writer counts as a write (as TK-D008 read the whole line before
        # #421); follow the names into the writer if that holds real reads
        tags += ["MAY_WRITE:" + w for c in parsed[0] for w in c["argv"][1:] + c["stdin"]]
        tags += ["MAY_WRITE:" + line for line in parsed[1] if unread]
    tags += [k + ":" + n for k, _, path in (t.partition(":") for t in tags)
             if k != "MAY_WRITE" and (n := _normal(path)) != path]
    return list(dict.fromkeys(tags + [k + ":" + path.casefold() for k, _, path in (t.partition(":") for t in tags)]))


def _normal(path):
    """A target with `.`, `..` and repeated separators resolved, a `\\` read as `/`: `~/./.claude` is `~/.claude`. A
    `..` after a symlink may lead elsewhere, so this is only a second reading: it adds matches, and the target as
    written is still read. One that resolves to a start of ~ or $ it didn't have (`./~/.claude`, `x/../$HOME`) names
    a folder of that name here, and keeps a ./ in front. POSIX keeps two leading slashes, which Linux and macOS read as
    one: `//var/log` is `/var/log` (a Windows `\\\\host` share keeps its two)."""
    p = posixpath.normpath(path.replace("\\", "/")) if path else path
    if p.startswith("//") and path.startswith("/"):
        p = p[1:]
    if p.startswith(("~", "$")) and not path.startswith(("~", "$")):
        p = "./" + p
    return path if p == "." else p


_WRITER = re.compile(r"\b(?:rm|unlink|truncate|shred|mv|tee|dd|ln|perl)\b")
_WRITE_WORD = re.compile(r"\b(?:rm|unlink|truncate|shred|mv|tee|dd|ln|sed|perl|find)\b|>")
_INTERPRETER = re.compile(r"perl|python[\d.]*|node(?:js)?|ruby|php|bun|deno|lua")
_APPLESCRIPT_WRITE = re.compile(r"(?i)do ?shell ?script|\bdelete\b")   # JXA's doShellScript too


_SETS_VARIABLES = shell._VARIABLE_SETTING_BUILTINS | {"set"}


def _reaches_unread(parsed):
    """Whether a writer's name reaches a command the parser can't read: in its words or its name as written
    (`rm${IFS}-rf${IFS}…`), and in an echo's or printf's words earlier in its pipeline (`echo 'rm …' | sh`), also as
    `>`, sed or find; in another earlier stage's words or any herestring or heredoc text there, as a writer's name only
    (`jq 'select(.n > 1)' x | $PAGER` and a `>` in `$PY - <<EOF` aren't); and, when its name is an expansion
    (`$C -rf x`), in the values the line gives variables (`C=rm`, `read C <<< rm`, `printf -v C rm`, `set -- rm`).
    A redirection elsewhere on the line (`$PAGER x 2>/dev/null`) and another pipeline's command don't."""
    commands = parsed[0]
    last = {c["pipeline"]: i for i, c in enumerate(commands) if c["opaque"]}
    for c in (c for i, c in enumerate(commands) if i <= last.get(c["pipeline"], -1)):
        words = _WRITE_WORD if c["opaque"] or c["argv"][0] in ("echo", "printf") else _WRITER
        if any(words.search(w.lower()) for w in [c["word"]] * c["opaque"] + c["argv"][1:]) or \
                any(_WRITER.search(s.lower()) for s in c["stdin"]):
            return True
    if not any(c["opaque"] and re.search(r"[$`]", c["word"]) for c in commands):
        return False
    values = [r for r in parsed[2] if shell._ASSIGN.match(r)] + [
        w for c in commands if c["argv"][0] in _SETS_VARIABLES or shell._sets_with_v(c["argv"])
        for w in c["argv"][1:] + c["stdin"]]
    return any(_WRITER.search(v.lower()) for v in values)


def _opaque(command, scripts=None):
    """Whether a command writes files _command_effects can't name: a writer whose operand is a variable or a
    substitution (rm "$f"), or zip -m reading its names from stdin (-@); xargs, parallel, a container's exec or ssh,
    or an interpreter running code with a write in it (xargs rm, parallel 'rm {}', docker exec c sh -c 'rm …',
    perl -e 'open F, ">", …': Python whose code the line shows, its -c code, heredoc or a script the line wrote
    (`scripts`, _written_scripts), only when that code also has a real write, a spawner or an exec-style call,
    _PY_ACTS, so `if n > 1` or a word `find` in it is no write); at or batch scheduling commands from a pipe or a file
    (the parser reads a herestring or heredoc), or osascript's do shell script or a Finder delete."""
    argv = command["argv"]
    exe = argv[0].rsplit("/", 1)[-1].casefold()
    if exe in ("rm", "unlink", "shred", "truncate", "tee", "cp", "mv", "install", "ln"):
        return any("$" in a or "`" in a for a in argv[1:])
    if exe == "zip" and _zip_moves(argv[1:]):
        return any("$" in a or "`" in a or re.fullmatch(r"-[^-]*@[^-]*", a) for a in argv[1:])
    if exe in ("xargs", "parallel", "docker", "podman", "kubectl", "ssh") or \
            _INTERPRETER.fullmatch(exe):
        # lean: Python whose words name a write (`>`, rm, find …) is released when the code the line shows has
        # nothing _PY_ACTS finds: a write by a call _PY_ACTS doesn't list is then missed; Python whose words name no
        # write stays no writer, as before #589, even when its code writes; add the call to _PY_ACTS when one turns up
        return any(_WRITE_WORD.search(a) for a in argv[1:]) and (
            (code := _python_code(command, scripts or {})) is None or bool(_PY_ACTS.search(code)))
    if exe in ("at", "batch"):   # at -l, -r, -d, -c and -V list, remove, show or print: they schedule nothing
        return not command["stdin"] and not any(a in ("-l", "-r", "-d", "-c", "-V") for a in argv[1:])
    if exe == "osascript":
        return any(_APPLESCRIPT_WRITE.search(a) for a in argv[1:] + command["stdin"])
    return False


_ZIP_VALUED = ("-b", "-n", "-t", "-tt", "-P", "-Z", "-s", "-O", "--out", "-lf", "-ds", "-sp", "-x", "-i")


def _zip_moves(args):
    """Whether zip's options say -m (--move): it deletes the files it adds. An m in an option's value (-b/tmp/m,
    -s100m, -n.mp3, -Pmmm, a pattern after -x) isn't one."""
    skip = False
    for a in args:
        if skip:
            skip = False
        elif a in _ZIP_VALUED:
            skip = True
        elif a == "--move" or re.fullmatch(r"-[^-bnPtZsOxi]*m[^-]*", a):   # an m before any option taking a value
            return True
    return False


def _command_effects(commands):
    out = []
    for command in commands:
        argv = command["argv"]
        if not argv:
            continue
        exe = argv[0].rsplit("/", 1)[-1]
        args = argv[1:]
        if exe == "find":
            # what its -exec runs write (the parser doesn't emit them when a container runs the find: `docker exec c
            # find . -exec rm x \;`); -delete or an -exec rm (unlink, shred, truncate, mv {}) deletes each file found,
            # one that writes `{}` (sed -i, perl -i, cp /dev/null {}) writes it. An -exec's run ends at the first `;` or
            # `+`, so a find it runs (through git or a container) has no run of its own: the recursion stays shallow
            runs = _command_effects([{"argv": [run[0].casefold()] + run[1:]} for run in shell._find_execs(args)])
            out.extend(runs)
            found = {t.partition(":")[0] for t in runs if t.partition(":")[2] == "{}"}
            if "-delete" in args or any(a in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(args)
                                        and args[i + 1].rsplit("/", 1)[-1].casefold() in (
                                            "rm", "unlink", "shred", "truncate") for i, a in enumerate(args)):
                found.add("DELETE_TARGET")
            if not found:
                continue
            # its start paths (after its options: -L, -H, BSD's -E, -x …, and `--`), what its path tests and
            # -files0-from name (`-path '*/x/*'`; -delete implies -depth, under which -prune doesn't keep find out of a
            # folder), and the log and history names among its tests (`-name .bash_history`) but those `-prune` leaves out
            paths = []
            for arg in args:
                if re.fullmatch(r"-[A-Za-z]|-O[0-9]*|--", arg):
                    continue
                if arg.startswith("-"):
                    break
                paths.append(arg)
            paths += [args[i + 1] for i in range(len(args) - 1) if args[i] in (
                "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex", "-files0-from")]
            pruned = {i for i in range(len(args)) if args[i + 1:i + 2] == ["-prune"]}
            paths += [a for i, a in enumerate(args) if i not in pruned and _log_or_history(a)]
            kind = "DELETE_TARGET" if "DELETE_TARGET" in found else "WRITE_TARGET"
            out.extend(kind + ":" + path for path in dict.fromkeys(paths))
        elif exe in ("rm", "unlink", "shred", "truncate", "tee", "cp", "mv", "install", "ln"):
            valued = ("-s", "--size", "-r", "--reference") if exe == "truncate" else (
                "-t", "--target-directory", "-m", "--mode", "-o", "--owner", "-g", "--group", "-S", "--suffix")
            operands, directory, skip = [], None, None
            for arg in args:
                if skip:
                    directory = arg if skip in ("-t", "--target-directory") else directory
                    skip = None
                elif arg in valued:
                    skip = arg
                elif arg.startswith("--target-directory="):
                    directory = arg.split("=", 1)[1]
                elif not arg.startswith("-") or arg == "-":
                    operands.append(arg)
            if exe in ("rm", "unlink", "shred"):
                deleted, written = operands, []
            elif exe in ("truncate", "tee"):
                deleted, written = [], operands
            else:   # cp, mv, install and ln write the last operand or -t's directory, and in a directory each source's
                # name (`cp -t ~ x/.bash_history`, `cp x/.bash_history ~/`); mv also removes its sources
                sources = operands if directory is not None else operands[:-1]
                dest = directory if directory is not None else next(iter(operands[-1:]), None)
                written = [] if dest is None else [dest] + [
                    dest.rstrip("/") + "/" + src.rstrip("/").rsplit("/", 1)[-1] for src in sources
                    if directory is not None or len(sources) > 1 or dest.endswith("/") or dest in ("~", ".", "..")]
                deleted = sources if exe == "mv" else []
            out.extend(["DELETE_TARGET:" + path for path in deleted] + ["WRITE_TARGET:" + path for path in written])
            if exe == "ln" or exe == "cp" and any(a in ("--link", "--symbolic-link")
                                                  or re.fullmatch(r"-[A-Za-z]*[ls]\w*", a) for a in args):
                out.extend("MAY_WRITE:" + path for path in written)
        elif exe == "dd":
            out.extend("WRITE_TARGET:" + arg[3:] for arg in args if arg.startswith("of="))
        elif exe in ("sed", "perl") and any(re.match(r"-[nrsuzE]*i|--in-place" if exe == "sed" else r"-[0-9alnpw]*i", a)
                                            for a in args):
            if exe == "sed":   # the operands after the script: the first one unless -e, -f or their long forms give it
                files, script_seen, skip = [], False, False
                for arg in args:
                    if skip:
                        skip, script_seen = False, True
                    elif arg in ("--expression", "--file") or re.fullmatch(r"-[A-Za-z]*[ef]", arg):
                        skip = True
                    elif arg.startswith(("--expression=", "--file=")) or re.match(r"-[A-Za-z]*[ef].", arg) and \
                            not arg.startswith("--"):
                        script_seen = True
                    elif arg.startswith("-"):
                        continue
                    elif script_seen:
                        files.append(arg)
                    else:
                        script_seen = True
            else:
                execute = next((i for i, arg in enumerate(args)
                                if arg in ("-e", "--execute") or arg.startswith("-e")
                                or arg.startswith("-") and "e" in arg[1:]), None)
                if execute is not None:
                    option = args[execute]
                    takes_next = option in ("-e", "--execute") or ("e" in option[1:] and not option.startswith("-e"))
                    files = args[execute + (2 if takes_next else 1):]
                else:
                    positional = [i for i, arg in enumerate(args) if not arg.startswith("-")]
                    files = args[positional[0] + 1:] if positional else []
            out.extend("WRITE_TARGET:" + path for path in files)
        elif exe in ("git", "docker", "podman", "kubectl", "parallel"):
            # the writer they are or run from their own words (git rm or mv, docker exec c rm, kubectl cp, parallel rm
            # ::: …), read from its name on (a git message or grep pattern is data)
            data = shell.data_words(argv)
            j = next((j for j in range(1, len(argv)) if j not in data and argv[j].rsplit("/", 1)[-1].casefold() in (
                "rm", "unlink", "shred", "truncate", "tee", "cp", "mv", "install", "ln", "dd", "sed", "perl", "find")),
                     None)
            if j is not None:
                out.extend(_command_effects([{"argv": [argv[j].casefold()] + argv[j + 1:]}]))
        elif exe == "zip" and _zip_moves(args):   # -m deletes the files it adds: the operands after the archive
            operands, skip = [], False
            for arg in args:
                if skip:
                    skip = False
                elif arg in _ZIP_VALUED:
                    # lean: -x and -i take every word to the next option; a pattern after the first reads as a source,
                    # which only holds more; read the list if one is held wrongly
                    skip = True
                elif not arg.startswith("-"):
                    operands.append(arg)
            out.extend("DELETE_TARGET:" + path for path in operands[1:])
        elif exe in ("awk", "gawk", "mawk", "nawk"):   # print or printf > "file" in its program
            out.extend("WRITE_TARGET:" + path for path in re.findall(r'>>?\s*"([^"\n]+)"', shell._awk_program(args) or ""))
        elif exe in ("sqlite3", "sqlite"):
            # every operand (the database among them), when its SQL (the operands and a heredoc or herestring) writes
            # outside literals and comments, or can't be read
            # lean: SQL read from a file (`sqlite3 db < x.sql`, `.read x.sql`) isn't seen; read it if one is held wrongly
            operands = [a for a in args if not a.startswith("-")]
            code = classes.sql_code("\n".join(operands + list(command.get("stdin", ()))),
                                    *classes.SQL_DIALECTS["sqlite"])
            if code is None or _SQL_WRITE.search(code):
                out.extend("WRITE_TARGET:" + a for a in operands)
    return out


_SQL_WRITE = re.compile(r"(?im)\b(?:insert|update|delete|drop|create|alter|replace\s+into|vacuum|reindex)\b"
                        r"|^\s*\.(?:restore|import)\b")

# Python code that may run text or a program, or write, move or delete a file: exec-style calls and what looks a name
# up at run time, unpicklers, process spawners (os's, and any name imported from os), and file writes (a w, a, x or +
# mode, os.open's write flags, pathlib's, os's and shutil's file operations, the writers of pandas, numpy and plots)
_PY_ACTS = re.compile(
    r"\b(?:exec|eval|compile|execfile|__import__|import_module|importlib|runpy|pickle|cPickle|_pickle|dill|marshal|"
    r"shelve|jsonpickle|subprocess|pty|ctypes|cffi|getattr|setattr|globals|locals|__builtins__|builtins|codeop|"
    r"shutil|sqlite3|urlretrieve|inplace|O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND)\b|\byaml\.(?:load|load_all|unsafe_load|"
    r"full_load)\b|\bcode\.\w|\bos\.(?:system|popen|exec\w*|spawn\w*|posix_spawn\w*|fork\w*|remove|unlink|rmdir|"
    r"removedirs|rename|renames|replace|truncate|makedirs|mkdir|mkfifo|mknod|symlink|link|chmod|chown|lchown|utime|"
    r"kill\w*|putenv|chdir|chroot|open|fdopen|ftruncate|write|writev|pwrite\w*|sendfile|copy_file_range)\b|"
    r"\bfrom\s+(?:os|posix|nt)\s+import\b|\bimport\s+os\s+as\b|\bposix\b|"
    r"\.(?:write_text|write_bytes|unlink|rmdir|touch|mkdir|rename|replace|symlink_to|hardlink_to|chmod|open|"
    r"save\w*|to_(?:csv|json|parquet|pickle|excel|sql|hdf|feather|html|markdown|latex|xml|stata))\s*\(|"
    r"\b(?:filename|FileHandler|RotatingFileHandler|basicConfig)\b|"
    r"['\"][rbtU]*[wax+][rbtU+]*['\"]")   # a mode a file opens with, anywhere: `open(p, 'w' if … else 'r')`
_PYTHON = re.compile(r"python[0-9.]*t?")
# Python inline code that only reads a download as data (TK-A046; TK-D002 for a downloaded file a command names), as
# an allowlist of syntax: `import json` and `import sys`, reading sys.stdin, json.load and json.loads, subscripts,
# len and print, comprehensions, comparisons and string formatting; `files` adds open() in read mode, sys.argv and a
# value's get, keys, values and items. Anything else, a dunder name too, isn't data.
_DATA_NODES = (ast.Module, ast.Expr, ast.Assign, ast.Name, ast.Load, ast.Store, ast.Constant, ast.Subscript, ast.Slice,
               ast.Tuple, ast.List, ast.Dict, ast.Set, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp,
               ast.comprehension, ast.JoinedStr, ast.FormattedValue, ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare,
               ast.IfExp, ast.Call, ast.Attribute, ast.Import, ast.alias, ast.keyword, ast.operator, ast.unaryop,
               ast.boolop, ast.cmpop, ast.expr_context)
_DATA_ATTRS = {("sys", "stdin"), ("sys.stdin", "read"), ("sys.stdin", "readline"), ("sys.stdin", "readlines"),
               ("json", "load"), ("json", "loads")}


def _dotted(node):
    """`a.b.c` as text for a chain of names, else None."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and (base := _dotted(node.value)):
        return base + "." + node.attr
    return None


def _data_only(code, files=False):
    """Whether Python code passes _DATA_NODES' allowlist (see above)."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    stored = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    calls = {"print", "len"} | ({"open"} if files else set())
    names = calls | {"json", "sys"} | stored
    for node in ast.walk(tree):
        if not isinstance(node, _DATA_NODES):
            return False
        if isinstance(node, ast.Import):
            if any(a.name not in ("json", "sys") or a.asname for a in node.names):
                return False
        elif isinstance(node, ast.Name):
            if "__" in node.id or node.id not in names:
                return False
        elif isinstance(node, ast.Attribute):
            base = _dotted(node.value)
            if "__" in node.attr or not (
                    (base, node.attr) in _DATA_ATTRS or files and (base, node.attr) == ("sys", "argv") or
                    isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and
                    node.attr in ("format", "join") or
                    files and base not in ("json", "sys", "sys.stdin") and node.attr in ("get", "keys", "values", "items")):
                return False
        elif isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                if f.id not in calls or f.id == "open" and (node.keywords or len(node.args) > 2 or len(node.args) == 2 and not (
                        isinstance(node.args[1], ast.Constant) and node.args[1].value in ("r", "rb", "rt"))):
                    return False
            elif not isinstance(f, ast.Attribute):
                return False
        elif isinstance(node, ast.Assign):
            if not all(isinstance(t, ast.Name) or isinstance(t, ast.Tuple) and all(isinstance(e, ast.Name) for e in t.elts)
                       for t in node.targets):
                return False
    return True


def _base(path):
    """The last part of a path as written (`./i.sh` and `/tmp/./i.sh` are i.sh)."""
    return posixpath.basename(posixpath.normpath(path)) if path else path


def _operand(args, valued=()):
    """The first argument that is no option (an option in `valued` takes the next word), or None."""
    i = 0
    while i < len(args):
        if args[i] == "--":
            return args[i + 1] if i + 1 < len(args) else None
        if not args[i].startswith("-") or args[i] == "-":
            return args[i]
        i += 2 if args[i] in valued else 1
    return None


def _python_code(command, scripts):
    """The program text a Python command runs, when the line shows it: its -c code, the heredoc or herestring it reads,
    or a script this line wrote (`scripts`: base name -> text); else None."""
    argv = command["argv"]
    if not _PYTHON.fullmatch(argv[0]) or not _plain_python(argv):   # -i runs stdin after it: what runs isn't shown
        return None
    code = shell._code_arg("python", argv[1:])
    if code is None and shell._reads_stdin("python", argv[1:]) and command["stdin"]:
        code = "\n".join(command["stdin"])
    if code is None and _python_module(argv[1:]) == [] and (script := _operand(argv[1:], shell.INTERP_VALUE_OPTS)):
        code = scripts.get(_base(script))
    return code


def _written_scripts(commands):
    """Base name -> the text this line's cat, tee, echo or printf writes into a file (a script it may then run), for a
    file nothing else on the line writes (`cp evil.py s.py` after it: what runs isn't that text)."""
    out, others = {}, set()
    for c in commands:
        name = c["argv"][0]
        if name in ("cat", "tee", "echo", "printf"):
            text = "\n".join(c["stdin"] + (c["argv"][1:] if name in ("echo", "printf") else []))
            files = list(c.get("out", ())) + ([a for a in c["argv"][1:] if not a.startswith("-")] if name == "tee" else [])
            for f in files:
                out.setdefault(_base(f), []).append(text)
        else:
            others |= {_base(f) for f in c.get("out", ())}
    others |= {_base(t.partition(":")[2]) for t in _command_effects(
        [c for c in commands if c["argv"][0] not in ("cat", "tee", "echo", "printf")])}
    return {f: "\n".join(texts) for f, texts in out.items() if f not in others}


# TK-D007's allowlists (#589): the programs that may read a file's contents under Tracekit's dirs (which files they
# may read there the pack's `unless` names: the installed package and /etc/tracekit's client.json and policy), and
# the programs that may list one; any other program there acts
_PLAIN_READERS = {"cat", "head", "tail", "grep", "egrep", "fgrep", "sed", "jq"}
_LISTERS = {"ls", "stat", "test", "[", "find"}
_NAVIGATE = ("cd", "pushd", "popd")
# a later pipeline stage that only filters text: what an earlier stage prints goes no further than the terminal
_FILTERS = {"head", "tail", "grep", "egrep", "fgrep", "wc", "sort", "uniq", "cut", "tr", "sed", "jq", "column", "nl",
            "cat"}
# variables the shell or a program reads on its own (cd's CDPATH, HOME and OLDPWD, a startup file, a search path): an
# assignment to one is never a value the line only reads
_SPECIAL = re.compile(r"CDPATH|HOME|OLDPWD|PWD|PATH|IFS|ENV|BASH_ENV|SHELLOPTS|BASHOPTS|GLOBIGNORE|PROMPT_COMMAND|"
                      r"PS[0-4]|TMPDIR|HISTFILE|INPUTRC|MAIL\w*|LD_\w+|DYLD_\w+|PYTHON\w*|XDG_\w+|TRACEKIT\w*|LESS\w*|"
                      r"PAGER|EDITOR|VISUAL")


def _sed_reads_only(script):
    """Whether a sed script only reads and prints: its s and y commands taken out (s's flags without w or e), what is
    left only picks and prints lines (shell._sed_prints)."""
    rest = re.sub(r"([sy])([^\\\n])((?:\\.|(?!\2).){0,200})\2((?:\\.|(?!\2).){0,200})\2([A-Za-z0-9]{0,8})",
                  lambda m: ";" if not set("we") & set(m.group(5)) else "w", script)
    return shell._sed_prints(rest)


def _reading(argv):
    """What a command does with the files it names, for TK-D007: "read" (a _PLAIN_READERS program: sed only with -n
    and a script that only prints, grep without -r), "deep" (grep -r: every file under a folder), "list" (a _LISTERS
    program: find without an action, -fprint, -fls or -files0-from; pgrep and ps naming no file), else None."""
    name, args = argv[0], argv[1:]
    if name == "sed":
        script = shell._sed_scripts(args)
        return "read" if "-n" in args and script is not None and shell._sed_prints(script) and not any(
            re.match(r"-[nrsuzE]*[if]|--in-place|--file", a) for a in args) else None
    if name in ("grep", "egrep", "fgrep"):
        return "deep" if any(re.fullmatch(r"-[A-Za-z]*[rR][A-Za-z]*", a) or a.startswith(
            ("--recursive", "--dereference-recursive", "--directories=recurse", "-d")) for a in args) else "read"
    if name in _PLAIN_READERS:
        return "read"
    if name == "find":
        return None if any(a.startswith(("-exec", "-ok", "-fprint", "-fls", "-files0-from", "--files0-from")) or
                           a == "-delete" for a in args) else "list"
    if name in _LISTERS or name in ("pgrep", "ps") and not any("/" in a for a in args):
        return "list"
    return None


_SIGNER_MODULE = re.compile(r"tracekit\.(?:daemon|proxy|signer)\b")
# the parts of Tracekit's signer code may read, by name: the RPC schema's tables, reconcile's comparison, and the
# service's policy loader on its default policy
_SIGNER_READS = {"rpc_schema": {"REQUESTS", "RESPONSES", "RPC_VERSION", "RPC_MIN", "RPCError"},
                 "reconcile": {"compared", "model_names"}, "service": {"load_policy", "DEFAULT_POLICY"}}
_PY_LOOKUP = re.compile(r"\b(?:runpy|importlib|import_module|__import__|__dict__|__builtins__|builtins)\b|"
                        r"(?<![\w.])(?:getattr|exec|eval|compile|globals|locals|vars)\s*\(")


def _runs_signer(code):
    """Whether code that names tracekit.signer, .daemon or .proxy may reach more than _SIGNER_READS: the daemon or the
    proxy, any other module or name, a name imported under another name (`load_policy as lp`), a module alias used
    other than to reach an allowed name, a name looked up at run time (runpy, getattr, importlib …), or a module
    reached by its full name."""
    if re.search(r"tracekit\.(?:daemon|proxy)\b", code) or _PY_LOOKUP.search(code) or \
            re.search(r"\btracekit\.signer\.\w+\.\w", code):
        return True
    aliases = {}   # a name the code gives one of the signer's modules -> that module
    for m in re.finditer(r"\bfrom\s+tracekit\.signer(?:\.(\w+))?\s+import\s+\(?([\w\s,*]+)", code):
        for item in m.group(2).replace("\n", " ").split(","):
            name, _, alias = (x.strip() for x in item.partition(" as "))
            if not name:
                continue
            if m.group(1) is None and name in _SIGNER_READS:
                aliases[alias or name] = name
            elif m.group(1) not in _SIGNER_READS or alias or name not in _SIGNER_READS[m.group(1)]:
                return True
    for m in re.finditer(r"\bimport\s+tracekit\.signer(?:\.(\w+))?(?:\s+as\s+(\w+))?", code):
        if m.group(1) not in _SIGNER_READS or not m.group(2):
            return True
        aliases[m.group(2)] = m.group(1)
    for alias, module in aliases.items():
        uses = re.findall(r"(?<![\w.])%s\b(\.\w+)?" % re.escape(alias), code)
        if any(u and u[1:] not in _SIGNER_READS[module] for u in uses) or uses.count("") > 1:   # the import names it
            return True
    return False


def _tracekit(parsed):
    """What a shell call does to Tracekit itself (TK-D007), each as a tagged subject. ACT: what a command acts on or
    runs, its words joined (but data words), its stdin, the files redirections write, _effects' files, the other words
    that name something (assignments, heredoc programs). READ, DEEP and LIST: one subject per word a command that only
    reads names (_reading; the pack's `unless` names the files a READ may name under Tracekit's dirs): DEEP for a
    recursive read, a pattern, a reader whose output goes on to a file, a substitution or anything but a filter
    (`find … > l; xargs cat < l`, `cat $(find …)`, `find … | while read f`), and the folder a cd, pushd or popd enters
    where every command only reads or lists and no redirection writes (else the cd is ACT); a file a redirection
    reads is READ, an assignment the line uses only in readers (_private) LIST. SIGNER_MODULE: an ACT text whose code
    reaches more of Tracekit's signer than it may read (_runs_signer). Each also normalised and casefolded as a path
    is (_path_forms)."""
    commands, refs, written = parsed[0], parsed[2], set(parsed[3])
    learned = parsed[5] if len(parsed) > 5 else None
    kinds = [_reading(c["argv"]) for c in commands]
    roams = not written and all(k or c["argv"][0] in _NAVIGATE for c, k in zip(commands, kinds))
    stages = {}   # pipeline -> the stage of each command, and whether it only filters
    for c in commands:
        stages.setdefault(c["pipeline"], []).append((c.get("stage", 0), c["argv"][0] in _FILTERS))
    act, listed, read, deep = [], [], [], []
    for c, kind in zip(commands, kinds):
        data = shell.data_words(c["argv"]) | set(c.get("data_words", ()))
        words = [a for i, a in enumerate(c["argv"]) if i not in data]
        named = [a for a in words[1:] if not re.fullmatch(r"-[^/=]*", a)]
        feeds = any(s > c.get("stage", 0) and not f for s, f in stages[c["pipeline"]]) or \
            bool({"$()", "``", "<()"} & set(c["via"])) or bool(c.get("out"))
        if c["argv"][0] in _NAVIGATE:
            if roams:
                deep += named
            else:
                act.append(" ".join(words))
        elif kind is None:
            act.append(" ".join(words))
        else:
            {"read": read, "list": listed, "deep": deep}["deep" if feeds or c["glob"] else kind].extend(named)
        act += [] if c.get("data_stdin") else c["stdin"]
    reads, private = set(learned["read"]) if learned else set(), _private(learned, commands, "\n".join(act))
    for r in refs:
        (listed if r not in written and r in private else read if r not in written and r in reads else act).append(r)
    act += [t.partition(":")[2] for t in _effects(parsed)]

    def tag(name, texts):
        return [name + s for s in _path_forms(list(dict.fromkeys(texts)))]
    return tag("ACT:", act) + tag("LIST:", listed) + tag("READ:", read) + tag("DEEP:", deep) + \
        ["SIGNER_MODULE:" + s for s in dict.fromkeys(act) if _SIGNER_MODULE.search(s) and _runs_signer(s)]


def _private(learned, commands, acted):
    """The assignment words that set a shell variable only commands that read use: standalone (the shell's own, not a
    command's environment), of no variable the shell or a program reads on its own (_SPECIAL), its $NAME in none of the
    `acted` text (the words, code and stdin of the commands that act), with nothing on the line that may set or export
    any variable (`set` too: set -a exports them) or name one at run time (${!x})."""
    if not learned or learned["any_set"] or "*" in learned["unresolved"] or any(c["argv"][0] == "set" for c in commands):
        return set()
    used = set(re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", acted))
    return {text for name, text in learned["assigned"] if name not in used and not _SPECIAL.fullmatch(name)}


_FETCHERS = ("curl", "wget")
_EXPANDED = re.compile(r"\$\([^)]*\)?|\$\{[^}]*\}?|\$(?:[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])|`[^`]*`?|[*?[\]]")   # in a name
# a substitution (or process substitution) whose command is curl or wget, as a word holds it
_FETCHED = re.compile(r"(?:\$\(|`|<\()\s*(?:[^\s|;&()`]*/)?(?:curl|wget)\b")
_EXTRACTORS = {"tar", "bsdtar", "unzip", "gunzip", "bunzip2", "unxz", "xz", "7z", "7za", "zstd", "unzstd", "cpio", "ar"}
# curl's and wget's short options that take a value (in a cluster, the rest of it or the next word)
_VALUED = {"curl": set("AbcCdDeEFHKmoPQrtTuUwxXyYz"), "wget": set("aABDeiIlOoPQRtTUwX")}


def _fetched_files(argv):
    """(the files a curl or wget writes what it downloads to, whether it may write one the line can't name): curl's -o
    and -O (the URL's last part), wget's -O, or the URL's last part when wget has no -O; a name with an expansion,
    curl -J, --output-dir or -K, and wget -i, -r, -m or --content-disposition can't be named. `-` is stdout."""
    name, args = argv[0], argv[1:]
    remote = [_base(re.sub(r"[?#].*", "", a.split("://", 1)[1].partition("/")[2])) or "index.html"
              for a in args if re.match(r"(?i)[a-z][a-z0-9+.-]*://", a)]
    files, unknown, named, i = set(), False, False, 0
    while i < len(args):
        a, nxt = args[i], args[i + 1] if i + 1 < len(args) else ""
        long, _, value = a.partition("=")
        if long in ("--output", "--output-document"):
            files.add(value if _ else nxt)
            named, i = True, i + (not _)
        elif a in ("--remote-name", "--remote-name-all"):
            files.update(remote)
            named = True
        elif long in ("--remote-header-name", "--output-dir", "--config", "--input-file", "--recursive", "--mirror",
                      "--content-disposition"):
            unknown = True
        elif re.fullmatch(r"-[A-Za-z0-9#:]+", a):
            for k, ch in enumerate(a[1:], 2):
                if ch == "O" and name == "curl":
                    files.update(remote)
                    named = True
                elif ch in "Jrmi" and (ch == "J") == (name == "curl") or ch == "K" and name == "curl":
                    unknown = True
                if ch in _VALUED[name]:
                    value = a[k:] or nxt
                    i += not a[k:]
                    if ch in ("o" if name == "curl" else "O"):
                        files.add(value)
                        named = True
                    break
        i += 1
    if name == "wget" and not named:
        files.update(remote)
    files.discard("-")
    return files, unknown


def _runs_files(c):
    """The files command c runs as code: its program when that is a path, the script a shell or interpreter runs (the
    file its stdin is redirected from, when it reads its program there), a file source or . reads."""
    argv, name = c["argv"], c["argv"][0]
    out, kind = [c["word"]], shell._kind(name)
    if name in shell.SHELLS:
        mode, _ = shell._shell_mode(argv[1:])
        out += [_operand(argv[1:], shell.SHELL_VALUE_OPTS)] if mode is None else list(c.get("in", ()))
    elif kind and kind not in ("awk", "sed") and shell._code_arg(kind, argv[1:]) is None:
        if shell._reads_stdin(kind, argv[1:]):
            out += list(c.get("in", ()))
        elif module := _python_module(argv[1:]):   # python -m m runs m.py, or the package m
            out += [module[0].replace(".", "/") + ".py", module[0].partition(".")[0]]
        else:
            out.append(_operand(argv[1:], shell.INTERP_VALUE_OPTS))
    elif name in ("source", "."):
        out += argv[1:2]
    return [f for f in out if f]


# what may name a downloaded file without running it (TK-D002): programs that print what they read (to the terminal
# or a filter: else what they print may run), remove it, or copy or move it (the copy is downloaded too)
_TAINT_READERS = {"cat", "head", "tail", "grep", "egrep", "fgrep", "wc", "jq", "file", "stat", "ls",
                  "test", "[", "sha256sum", "shasum", "sha1sum", "md5", "md5sum", "cksum", "diff", "cmp", "od",
                  "hexdump", "strings", "sort", "cut", "nl"}
_TAINT_MOVES = {"rm", "unlink", "chmod", "cp", "mv"}
# a file a program or shell loads by itself wherever it is: one downloaded there runs
_AUTOLOAD = re.compile(r"(?:^|/)(?:conftest\.py|sitecustomize\.py|usercustomize\.py|[^/]*\.pth|\.bashrc|\.bash_profile|"
                       r"\.bash_login|\.bash_logout|\.bash_aliases|\.aliases|\.zsh_aliases|\.profile|\.zshrc|\.zshenv|"
                       r"\.zprofile|\.zlogin|\.kshrc|\.mkshrc|\.cshrc|\.tcshrc|\.envrc|\.pythonrc(?:\.py)?|"
                       r"package\.json|"
                       # a tool's config, which can name code it runs (`addopts = -p`, a make recipe, core.fsmonitor)
                       r"pytest\.ini|tox\.ini|setup\.cfg|pyproject\.toml|[Mm]akefile|GNUmakefile|[Jj]ustfile|Rakefile|"
                       r"Gemfile|Cargo\.toml|build\.rs|\.npmrc|\.yarnrc(?:\.yml)?|\.gitconfig|\.git/config|"
                       r"\.pre-commit-config\.yaml)$|(?:^|/)\.git/hooks/[^/]+$|"
                       # a program planted where a later call finds it by name: a bin dir
                       r"(?:^|/)s?bin/[^/]+$")
# code an interpreter imports by a name a later call needn't spell (`import x` x.py, require('./x') x.js, `use x`
# x.pm, `python3 .` __main__.py), from the working tree or a search path
_IMPORTABLE = (".py", ".pyc", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pm", ".lua")
# a scratch dir nothing imports from by itself (but a search path's dir in it: site-packages, node_modules), spelled
# literally: $TMPDIR or a variable may be the working tree
_SCRATCH = re.compile(r"(?:(?:/private)?/(?:var/)?tmp|(?:/private)?/var/folders|"
                      r"(?:~|/Users/[^/]+|/home/[^/]+)/Downloads)/"
                      r"(?!(?:.*/)?(?:site-packages|dist-packages|node_modules)/)[^$`]*$")
# what runs code on a line that downloads: a shell, an interpreter, and these
_RUNNERS = {"source", ".", "eval", "exec"}
# the options of a Python that runs its inline code (or json.tool) and nothing else: -i would read stdin after it
_PY_PLAIN_FLAGS = re.compile(r"-[IEsBu]*[cm]?")


def _plain_python(argv, refs=()):
    """Whether a Python runs the program its words give and nothing more: every option before its -c code, -m module,
    `-` or script is one of _PY_PLAIN_FLAGS (-I, -E, -s, -B, -u), and nothing on the line sets PYTHONINSPECT."""
    if any("PYTHONINSPECT" in w for w in list(refs) + argv):
        return False
    for a in argv[1:]:
        if a == "-" or not a.startswith("-"):
            return True
        if not _PY_PLAIN_FLAGS.fullmatch(a):
            return False
        if a[-1] in "cm":
            return True
    return False


def _downloads(parsed):
    """Where downloaded bytes run, as RUNS_DOWNLOAD: the command (TK-D002), and where a download's pipe feeds code that
    may run or store it, as PIPED_TO_CODE: the command (TK-A046). A file curl or wget wrote (-o, -O, its redirection, a
    later stage's redirection or tee) is downloaded, and so is a copy of it (cp, mv, a reader's redirection). Runs: any
    command or assignment that names a downloaded file (`BASH_ENV=f`, `--rcfile f`, `openssl -in f`, `sh f`) unless it
    is one that only prints, removes or copies it (_TAINT_READERS whose output reaches no more than the terminal or a
    filter, _TAINT_MOVES, Python inline code _data_only reads as data); a downloaded file whose name a program or shell
    loads by itself (_AUTOLOAD: conftest.py, a .pth, a shell rc file, a git hook, a bin dir or one the line puts on
    PATH), and importable code (_IMPORTABLE) outside a scratch dir, also as a copy of a pattern or an expansion; any
    script or path program when the line can't name a download (curl -J, an archive); a substitution of curl or wget,
    a variable the line sets to one, or a substitution that reads a downloaded file, as a command's name, in eval or
    source, in -c code, in a herestring or pipe into a shell or interpreter; and on a line that downloads, wherever it
    is, any shell, interpreter, source, eval or exec, and any program named by a path, a pattern or an expansion, but
    data-only Python when no download may be code it imports. Piped to code: a later stage of a download's pipeline
    that is a shell with -c or a script, an
    interpreter with a script or a module (python -m json.tool aside), or with inline code: Python's unless _data_only
    reads it as data."""
    commands, tags = parsed[0], []
    files, unknown, piped = set(), False, {}
    for k, c in enumerate(commands):
        if c["argv"][0] in _FETCHERS:
            named, maybe = _fetched_files(c["argv"])
            files |= named | set(c.get("out", ()))
            unknown |= maybe
            piped.setdefault(c["pipeline"], k)
        elif c["pipeline"] in piped:   # a later stage of a download's pipeline stores what it gets
            files |= set(c.get("out", ())) | ({a for a in c["argv"][1:] if not a.startswith("-")}
                                             if c["argv"][0] == "tee" else set())
    # each name a pattern: an expansion in one may be any text (`-o "view-$(basename $p).json"` is view-*.json); one
    # that is only an expansion may be any file, and so may any, past 64 patterns
    paths = set(files)
    names = {_EXPANDED.sub("*", _base(f)) for f in files}
    exact, patterns = {n for n in names if "*" not in n}, {n for n in names if "*" in n}
    tainted = [m.group(1) for r in parsed[2] + [a for c in commands for a in c["argv"][1:]]
               if (m := re.match(r"([A-Za-z_][A-Za-z0-9_]*)\+?=", r)) and _FETCHED.search(r)]
    uses = re.compile(r"\$\{?(?:%s)\b" % "|".join(map(re.escape, tainted))) if tainted else None
    stages = {}
    for c in commands:
        stages.setdefault(c["pipeline"], []).append((c.get("stage", 0), c["argv"][0] in _FILTERS))

    def downloaded(path):
        return _base(path) in exact or any(fnmatch.fnmatchcase(_base(path), p) for p in patterns if p != "*")

    def fetched(text):   # curl's output, a variable set to it, or a substitution that reads a downloaded file
        return bool(_FETCHED.search(text) or uses and uses.search(text) or
                    re.search(r"\$\(|`", text) and any(map(downloaded, re.findall(r"[\w./-]+", text))))

    def named(c):   # the downloaded files a command names: in a word, after a word's `=`, or as its stdin
        words = c["argv"][1:] + [a.partition("=")[2] for a in c["argv"][1:] if "=" in a] + list(c.get("in", ()))
        return [w for w in words if w and downloaded(w)]

    def passes(c):   # its output goes no further than the terminal or a filter
        return not c.get("out") and not ({"$()", "``", "<()"} & set(c["via"])) and not any(
            s > c.get("stage", 0) and not f for s, f in stages[c["pipeline"]])
    # copies: a reader's redirection, cp and mv, from a downloaded file or text; until nothing new is found
    for _ in range(8):
        size = len(exact) + len(patterns)
        for c in commands:
            name, args = c["argv"][0], [a for a in c["argv"][1:] if not a.startswith("-")]
            if not (named(c) or any(map(fetched, c["argv"][1:] + c["stdin"]))):
                continue
            unknown |= name in _EXTRACTORS
            dest = args[-1:] if name in ("cp", "mv") and len(args) > 1 else []
            copies = list(c.get("out", ())) + (args if name == "tee" else []) + [
                d.rstrip("/") + "/" + _base(s) for d in dest for s in args[:-1]] + dest
            for f in copies:
                paths.add(f)
                (patterns if "*" in (n := _EXPANDED.sub("*", _base(f))) else exact).add(n)
        if len(exact) + len(patterns) == size:
            break
    unknown |= "*" in patterns or len(patterns) > 64
    fetchers = [k for k, c in enumerate(commands) if c["argv"][0] in _FETCHERS]
    for c in commands if fetchers else ():   # a copy of what a pattern or an expansion names may be the download
        args = [a for a in c["argv"][1:] if not a.startswith("-")]
        if c["argv"][0] in ("cp", "mv", "install", "ln", "rsync") and any(re.search(r"[*?[$`]", s) for s in args[:-1]):
            paths.update([args[-1]] + [args[-1].rstrip("/") + "/" + _base(s) for s in args[:-1]])
        if any(re.search(r"[*?[$`]", a) for a in c["argv"][1:] + c["stdin"]):
            paths.update(c.get("out", ()))
    assigns = parsed[2] + [a for c in commands if c["argv"][0] == "export" for a in c["argv"][1:]]
    # a dir the line puts on PATH: a download planted there runs when a later call names it
    bins = {d.rstrip("/") for r in assigns if r.startswith("PATH=") for d in r[5:].split(":") if d and "$" not in d}
    homeless = any(r.startswith("HOME=") for r in assigns) or any(c["argv"][0] == "ln" for c in commands)

    def loadable(path):   # importable code a later call may import: but in a scratch dir the line can't redirect
        path = posixpath.normpath(path)
        return path.endswith(_IMPORTABLE) and (homeless or not _SCRATCH.match(path))
    if any(_AUTOLOAD.search(p := f.replace("\\", "/")) or loadable(p) or posixpath.dirname(p).rstrip("/") in bins
           for f in paths):
        tags.append("RUNS_DOWNLOAD:a file a program, shell or later call loads by its name")
    # data-only Python may run on a line that downloads only when no download may be code it imports
    code_downloaded = unknown or any(posixpath.normpath(p).endswith(_IMPORTABLE) for p in paths)
    for r in parsed[2]:   # an assignment that names one: BASH_ENV, ENV, PYTHONSTARTUP …
        if "=" in r and downloaded(r.partition("=")[2]):
            tags.append("RUNS_DOWNLOAD:" + r)
    carries = set()   # the pipelines an earlier stage of which names a download's output
    for k, c in enumerate(commands):
        argv, kind = c["argv"], shell._kind(c["argv"][0])
        code = shell._dash_c(argv[1:]) if argv[0] in shell.SHELLS else \
            shell._code_arg(kind, argv[1:]) if kind else None
        plain = kind == "python" and _plain_python(argv, parsed[2])
        data = plain and code is not None and _data_only(code, files=True)
        use = named(c) if argv[0] not in _FETCHERS else []
        if code is not None and not use:   # code that names a downloaded file, or imports a downloaded module
            use = [w for w in re.findall(r"[\w./-]+", code) if any(downloaded(w + e) for e in ("",) + _IMPORTABLE)] + [
                m for m in re.findall(r"\b(?:import|from)\s+(\w+)", code) if downloaded(m + ".py")]
        ran = [f for f in _runs_files(c) if downloaded(f) or fetched(f) or unknown and (f is not c["word"] or "/" in f)]
        harmless = argv[0] in _TAINT_READERS and passes(c) or argv[0] in _TAINT_MOVES or data
        runner = argv[0] in shell.SHELLS or kind and kind not in ("awk", "sed")
        if ran or use and not harmless or fetched(c["word"]) or code is not None and fetched(code) or \
                argv[0] in ("eval", "source", ".") and any(map(fetched, argv[1:] + c["stdin"])) or \
                (shell._stdin_shell([c]) or shell._stdin_interpreter([c]) or code is not None) and (
                    c["pipeline"] in carries or any(map(fetched, c["stdin"]))) and not data or \
                runner and (exact or patterns or unknown) and set(c["via"][-1:]) & {"xargs", "parallel", "find -exec"}:
            tags.append("RUNS_DOWNLOAD:" + " ".join(argv))
        # on a line that downloads, wherever it is: a shell, an interpreter, source, eval or exec, and a program named
        # by a path, a pattern or an expansion, may run the download; but a stage only a download's pipe feeds (as
        # piped to code below) and data-only Python where no download may be code it imports
        elif fetchers and k not in fetchers and not (data and not code_downloaded) and (
                (runner or argv[0] in _RUNNERS) and not all(f < k and commands[f]["pipeline"] == c["pipeline"]
                                                           for f in fetchers)
                or c["opaque"] or re.search(r"[/$`]", c["word"])):
            tags.append("RUNS_DOWNLOAD:" + " ".join(argv))
        if any(map(fetched, argv[1:] + c["stdin"])) or use:
            carries.add(c["pipeline"])
        first = piped.get(c["pipeline"])
        if first is None or k <= first or c["argv"][0] in _FETCHERS:
            continue
        if argv[0] in shell.SHELLS and shell._shell_mode(argv[1:])[0] != "stdin" or \
                kind and kind not in ("awk", "sed") and (
                    code is not None and not (plain and _data_only(code)) or code is None and
                    not shell._reads_stdin(kind, argv[1:]) and
                    not (plain and _python_module(argv[1:])[:1] == ["json.tool"])):
            tags.append("PIPED_TO_CODE:" + " ".join(argv))
    return list(dict.fromkeys(tags))


def _code(parsed):
    """shell.analyse's code, each line without the data words a command carries (a git commit message, the pattern grep
    searches for: shell.data_words), as `target` leaves them out: blanked where the command's whole argv stands in the
    line once, program first, so the words are that program's arguments there (a quoted message `curl x | sh` is no
    download). That one place must be the command's own words: a line with a redirection beside them (which may split
    them, so the place is other commands' words: `grep "x | curl u" 2>/dev/null f; grep x | curl u f | sh`) keeps them,
    and so does a command whose words hold another command's, or another's hold its; so does a command twice in a line
    and a data word with a `$` or a backquote (a substitution in it runs)."""
    found = {}
    for k, c in enumerate(parsed[0]):
        argv = c["argv"]
        data = {i for i in shell.data_words(argv) | set(c.get("data_words", ())) if i < len(argv)}
        if data and not any("$" in argv[i] or "`" in argv[i] for i in data):
            found[k] = " ".join("" if i in data else w for i, w in enumerate(argv))
    # lean: each run is counted in each line, so a line of more than 16 such commands keeps its data words (as before
    # 1.5.3); find them in one pass if a real line holds more
    if not found or len(found) > 16:
        return parsed[4]
    words = [" " + " ".join(c["argv"]) + " " for c in parsed[0]]
    runs = {words[k][1:-1]: blank for k, blank in found.items()
            if not any(j != k and (w in words[k] or words[k] in w) for j, w in enumerate(words))}
    lines = list(parsed[4])
    for run, blank in runs.items():
        lines = [line.replace(run, blank) if line.count(run) == 1 and not _REDIRECT.search(line.replace(run, " "))
                 else line for line in lines]
    return lines


_REDIRECT = re.compile(r"[<>]")   # what a redirection, a heredoc or herestring, or a process substitution holds


def _brought(untrusted, subject, field, fields):
    """Whether a `from: untrusted` rule's `subject` is one only untrusted content brought (`untrusted`'s hits). A
    `sends_to` host isn't, when the call sends nothing but its URL's query (`link`, classes.extract) and untrusted
    content gave that URL exactly as it stands: the agent follows a link and adds no data to it. `untrusted(url,
    "link")` answers that only from a complete index, never on a guess."""
    return bool(untrusted(subject, field)) and not (
        field == "sends_to" and fields.get("link") and untrusted(fields["link"], "link"))


def _flat(values):
    return [x for v in values for x in (_flat(v) if isinstance(v, list) else [v])]


# arguments whose text an MCP tool that posts or sends a message only carries (an issue's title and body, a message, a
# comment): a path or an address named there is mentioned, not read or fetched
_CARRIED = frozenset(("title", "body", "text", "description", "comment", "message", "subject", "content"))
_POSTS = frozenset(("post", "comment", "reply"))
# what `create` posts: the thing it names, the first word after it or the last one or two before a for, on, to and
# the like (create_issue, createPullRequest, create_github_issue, create_comment_on_issue; create_commit_for_pr creates
# a commit; one right after create, with its word, says where or how: create_to_do_issue posts an issue,
# create_from_pr_sandbox makes a sandbox, and alone it is where: create_on_issue posts on the issue, create_from_issue
# makes something from it); a name that also says file, cache, rule, job or workflow (create_note_file) creates
# something acted on
_CREATED = frozenset(("issue", "issues", "comment", "comments", "discussion", "review", "ticket", "note", "notes", "pr",
                      "worklog", "worklogs"))
_LINKS = frozenset(("for", "on", "in", "to", "from", "with", "at", "of", "by", "into", "under", "via"))
_ACTED = frozenset(("file", "files", "cache", "rule", "rules", "job", "jobs", "cron", "workflow", "function"))
_MESSAGES = frozenset(("message", "messages", "email", "mail", "dm", "chat", "notification"))
# a name that types, sends keys, runs or holds code: what such a tool carries is what it runs
_RUNS = frozenset(("type", "typing", "key", "keys", "keystroke", "keystrokes", "run", "exec", "execute", "eval",
                   "evaluate", "code", "cell", "cells", "script", "command", "cmd", "shell", "terminal", "kernel", "repl"))
_FETCHES = frozenset(("fetch", "read", "open", "get", "download", "navigate", "browse", "visit", "load", "scrape", "crawl"))


def _carried(tool):
    """The argument names whose string values MCP tool `tool` only carries: _CARRIED when its name says it posts,
    comments, replies, creates an issue, comment, pull request or the like (_CREATED), or sends a message, and doesn't
    say it types, sends keys, runs or holds code or a cell (_RUNS); `query` and `q` when it says it searches and doesn't
    say it fetches or reads (_FETCHES) or runs. Words in snake, kebab or camel case."""
    seq = re.findall(r"[a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", tool).casefold())
    words, out = set(seq), set()
    after = seq[seq.index("create") + 1:] if "create" in seq else []
    if after[:1] and after[0] in _LINKS:   # create_on_issue posts on the issue; create_from_issue makes something else
        after = after[2:] or (after[1:2] if after[0] in ("on", "to", "in", "into") else [])
    thing = after[:next((i for i, w in enumerate(after) if w in _LINKS), len(after))]
    creates = any(t[:1] and t[0] in _CREATED or t[:2] in (["pull", "request"], ["merge", "request"])
                  for t in (thing, thing[-1:], thing[-2:])) and not words & _ACTED
    posts = words & _POSTS or creates or "send" in words and words & _MESSAGES
    if posts and not words & _RUNS:
        out |= _CARRIED
    if any(w.startswith("search") for w in words) and not words & (_RUNS - {"code"} | _FETCHES):
        out |= {"query", "q"}
    return out


def _acted_on(value, carried):
    """An MCP call's arguments without the string values of those it only carries (`carried`, _carried's, at any
    depth): an object or a list under such a name is still read."""
    if isinstance(value, dict):
        return {k: _acted_on(v, carried) for k, v in value.items() if not (isinstance(v, str) and k.casefold() in carried)}
    if isinstance(value, list):
        return [_acted_on(v, carried) for v in value]
    return value


def _strings(value):
    """Every string in a JSON value, its objects' keys too."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in [k] + _strings(v)]
    return [s for v in value for s in _strings(v)] if isinstance(value, list) else []


def _prepare(subjects, tag=0):
    """(the subjects as text, up to the first longer than MAX_SUBJECT, past `tag` bytes a field's own tag adds
    (_TAGGED); their lower-case forms; those joined by a newline; whether one was longer). A rule matches the subjects
    before a long one and, matching none, takes TK-OVERSIZE, as one that walked them in order would."""
    texts = []
    for s in subjects:
        b = s if s.isascii() else s.encode("utf-8", "backslashreplace")   # ASCII is its own UTF-8
        if len(b) > MAX_SUBJECT + tag:
            break
        texts.append(s if b is s else b.decode("utf-8"))
    lows = [t.lower() for t in texts]
    return texts, lows, "\n".join(lows), len(texts) < len(subjects)


def _text(s):
    """Lone surrogates (valid in JSON escapes, not in UTF-8) become \\udxxx text, the same for both engines."""
    return s.encode("utf-8", "backslashreplace").decode("utf-8")


def _spelling(name):
    """A tool name as CrewAI's sanitize_tool_name leaves it, without its `_`: accents dropped (NFKD, then ASCII),
    lower-cased, letters and digits only."""
    return re.sub(r"[^0-9a-z]", "", unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode().lower())
