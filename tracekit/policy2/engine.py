"""Policy v2 engine: deterministic matching over a compiled policy (design §4.2).

google-re2 when installed, else the `regex` module on the same pattern subset in ASCII mode (`compile.translate`).
Every decision names the engine (id@version) and the policy_hash. Precedence: deny > ask > flag > allow.
"""
import fnmatch
import functools
import itertools
import posixpath
import re
import shlex
import time
import unicodedata
from urllib.parse import unquote

from . import classes, shell
from .compile import BOUND_TYPES, CLASSES, SECTIONS, canonical, literals, policy_hash, requirements, translate

MAX_SUBJECT = 64 * 1024     # bytes of UTF-8; a longer subject is never cut or windowed: TK-OVERSIZE in its rule's section
# a space inside one argv word, in the argv subject a rule also reads (_subjects): rules match argv joined by spaces,
# where a quoted value with a space looked like two words (`git -C 'my dir' push --force`); this one is no blank (\s)
# on either engine, no word character, matched by [^ ], and one byte, so that subject is never longer than the other
WORD_SPACE = "\x7f"
# a word that is only a variable the parser doesn't know there ($x, "${x}", $_), in a third argv subject: TK-D012 reads
# it as an action it can't read; a loop's or a literal's variable stays as written
UNKNOWN_WORD = "$\x7f"
_BARE_VARIABLE = re.compile(r"\$\{?([A-Za-z_]\w*)\}?")
MAX_URLS = 64               # URLs of an http call's `urls` list read one by one (Gemini CLI's web_fetch takes 20); more
                            # deny as TK-OVERSIZE, as a longer shell command does
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
_PROSE_SPLIT = re.compile(r"[\s()<>{}\[\],;'\"`|]+")   # a message's words: `(169.254.169.254)`, `169.254.169.254,`
_SCHEDULED = {"at <<<", "at <<", "batch <<<", "batch <<"}   # shell.py's `via` for code at or batch run later
# what every second reading of a line starts from (shell.analyse's `readings`): an expansion or substitution read as
# empty, a pattern as matching nothing or as the names its brackets make. The texts the parser reads hold only the
# line's characters ($'…' decodes others, after a $)
_SECOND = re.compile(r"[$`*?[]")
# the shell fields whose subjects carry a tag of up to this many bytes (ACT:, SIGNER_MODULE: …), which doesn't count
# toward a subject's size: a command just under MAX_SUBJECT isn't oversize for being tagged
_TAGGED = {"tracekit": 16}
REGEX_TIMEOUT_S = 1.0      # fallback engine only: the time all matches of one decision share; a match that runs out
                            # of it denies, marked nondeterministic
# what deciding an argument as a command (shell.hidden_commands) spends of its call's work budget beyond its parse: a
# decision's pass of every deny rule takes about as long as parsing 128 characters of commands does (~110 us)
DECISION_COST = 128
# the subject length from which a rule's alternatives' strings (compile.requirements) are checked before it is searched:
# a shorter subject's search costs no more than the check (E21's calls decided 2-4% slower at p99 with every one checked)
REQUIREMENTS_FROM = 1024


# the characters RE2's case-insensitive match folds to an ASCII letter, as macOS's file system does, each as that
# letter: a long s (U+017F) and the Kelvin sign (U+212A); the fallback engine's ASCII mode folds neither
_ASCII_FOLDS = str.maketrans("ſK", "sk")


def _backend(name):
    """Return (engine id, compile(pattern, anycase=False), match(compiled, text, full, deadline)); only the fallback
    uses the deadline: [seconds left] of the 1 s (REGEX_TIMEOUT_S) its regex matches of one decision (or bounds check)
    share, each spending it by the time it takes. Reading the call (its parse, its subjects) isn't charged to it: that
    is the same work on either engine, bounded by the input size limits (MAX_SUBJECT, shell.MAX_WORK) as on RE2."""
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
    ignorecase = int(regex.IGNORECASE)

    def match(c, s, full, deadline):
        if deadline[0] <= 0:   # spent: a tiny match could finish inside any floor, so the outcome would vary by machine
            raise TimeoutError("the fallback's 1 s for this decision is spent")
        start = time.perf_counter()
        try:
            found = (c.fullmatch if full else c.search)(s, timeout=deadline[0])
            # a pattern matched in any case also as RE2 folds the text, which ASCII mode doesn't (_ASCII_FOLDS); its
            # flag as an int, read last: `flags & regex.IGNORECASE` ran Python's enum code on every match
            if found is None and ("ſ" in s or "K" in s) and c.flags & ignorecase:
                left = deadline[0] - (time.perf_counter() - start)
                if left <= 0:
                    raise TimeoutError("the fallback's 1 s for this decision is spent")
                found = (c.fullmatch if full else c.search)(s.translate(_ASCII_FOLDS), timeout=left)
            return found
        finally:
            deadline[0] -= time.perf_counter() - start
    return (f"regex@{regex.__version__}", lambda p, anycase=False: regex.compile(
                translate(p), regex.ASCII | regex.V0 | regex.IGNORECASE * anycase), match)


class Engine:
    def __init__(self, policy, backend=None):
        """`policy` is a compiled policy (compile.build); `backend` forces "re2" or "regex"."""
        self.policy, self.policy_hash = policy, policy_hash(policy)
        self.tool_class = functools.lru_cache(maxsize=1024)(self.tool_class)   # a glob scan per call otherwise
        self.engine, self._compile, self._match = _backend(backend)
        compile_ = self._compile
        # each rule's prefilters (compile.literals), of its pattern and of its tool pattern: a subject or a tool name
        # holding none of its strings is not searched, nor a long subject that holds a string of each set of none of
        # the pattern's alternatives (compile.requirements). An a2a rule matches in any case, as every prefilter does:
        # the names it reads are lower-cased (classes.a2a_fields); so does a rule on the `tracekit` field, whose
        # subjects are also casefolded as a path is (_tracekit): the agent's file system may ignore case where the
        # pattern names a folder in mixed case
        def rx(r, key):
            return compile_(r[key], r.get("class") == "a2a" or r.get("field") == "tracekit")
        self.rules = [(sec, r, compile_(r["tool"]) if "tool" in r else None, rx(r, "pattern"),
                       rx(r, "unless") if "unless" in r else None, lits := literals(r["pattern"]),
                       _finer(requirements(r["pattern"]), lits), literals(r["tool"]) if "tool" in r else None)
                      for sec in SECTIONS for r in self.policy.get(sec, [])]
        # on RE2, every rule's prefilter strings are one RE2 Set, which finds each string a text holds in one search
        # (768 strings over 300 characters: 0.8 us; the dev pack's rules scanned 688 of them one at a time), so a
        # rule's prefilter is a lookup of its strings' ids (holds() in decide). The Set also holds `^`, which matches
        # every text: a match without it is one RE2 couldn't finish (its DFA out of memory, which the binding doesn't
        # report), and that text is scanned. The fallback scans: {id(strings): frozenset of their ids}
        self._set, self._ids = None, {}
        if self.engine.startswith("re2@"):
            import re2
            index = {}
            for *_, lits, _, _ in self.rules:
                for x in lits or ():
                    index.setdefault(x, len(index))
            opts = re2.Options()
            opts.log_errors, opts.max_mem = False, 64 << 20
            self._set = re2.Set.SearchSet(opts)
            for x in index:
                self._set.Add(re2.escape(x))
            self._every = self._set.Add("^")
            self._set.Compile()
            self._ids = {id(lits): frozenset(map(index.__getitem__, lits)) for *_, lits, _, _ in self.rules if lits}
        # on the fallback, a pattern whose top level is an alternation of parts that each have a prefilter is searched a
        # part at a time, each only where the subject holds one of its strings: the regex module can't skip ahead in an
        # alternation as it can in one part (TK-S002 took 36 us over a curl line, its parts 9 and 2 us), and a search
        # of a|b matches where one of a or b does: {id(compiled pattern): [(compiled part, its strings), ...]}
        self._parts = {}
        if not self.engine.startswith("re2@"):
            for _, r, _, pat, *_ in self.rules:
                parts = _alternatives(r["pattern"]) or ()
                if parts and all(map(literals, parts)):
                    self._parts[id(pat)] = [(rx({**r, "pattern": a}, "pattern"), literals(a)) for a in parts]
        # The filesystem persistence rules are the source of truth for paths whose written text stays executable.
        self._persistent_targets = [pat for _, rule, _, pat, *_ in self.rules if rule["id"] in ("TK-A010", "TK-A012")]
        self._deny_ids = {r["id"] for sec, r, *_ in self.rules if sec == "deny"}
        self._of = {}
        # whether a rule's tool pattern takes a tool name, by (pattern, name): RE2's matches spend no deadline (_backend)
        self._names = {} if self.engine.startswith("re2@") else None
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
        once its matches spend `deadline` (_backend)."""
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
        cls, name, deadline = cls or self.tool_class(tool), _text(tool), [REGEX_TIMEOUT_S]
        low, out = name.lower(), {sec: [] for sec in SECTIONS}
        for sec, rule, tool_re, *_, tool_lits in self.rules:
            if _reaches(rule, cls) and self._named(tool_re, tool_lits, name, low, deadline):
                out[sec].append(rule["id"])
        return out

    def _named(self, tool_re, lits, name, low, deadline):
        """Whether a rule's tool pattern takes the tool `name` (`low`: lower-cased); none takes every name. A name
        holding none of the pattern's literals is not searched: 27 searches of a 48 KiB MCP name of `run_` took the
        fallback engine 0.3 s on a laptop, past its 1 s on CI's macOS runners (#481)."""
        if tool_re is None:
            return True
        if self._names is not None and (tool_re, name) in self._names:
            return self._names[tool_re, name]
        got = bool((lits is None or any(map(low.__contains__, lits))) and self._match(tool_re, name, True, deadline))
        if self._names is not None and len(self._names) < 4096 and len(name) <= 256:
            self._names[tool_re, name] = got
        return got

    def decide(self, tool, args, cls=None, untrusted=None, _hidden=0, _budget=None):
        """Return {verdict, rule_ids, policy_hash, engine[, nondeterministic][, oversize]} for one tool call
        (`oversize`: the subjects TK-OVERSIZE stands for, named by their rule and field). `cls` overrides the class the
        policy maps the tool to. `untrusted(subject, field)`: the hits of the subject's values that only
        untrusted content brought into the run (`field`: the rule's); a `from: untrusted` rule matches a subject only
        when there is one (never without `untrusted`), and matches each element of a list field (payees, recipients)
        on its own. A shell call's argument that the parser reads as a command a deny rule matches (a command a tool
        runs from its arguments: `hyperfine 'cmd'`, `ssh -o ProxyCommand=cmd`, `make --eval='x: ; cmd'`, outside
        their data words: shell.hidden_commands) holds the call with that rule's id; `_hidden`: how deep in such
        arguments this call is (two levels are read), where a text the parser can't read is no command. A decision
        has one budget (`_budget`: its work and its deadline), which everything it reads shares: its parse, its other
        readings, what it reads of a line the parser can't read (_plain) and each argument it reads as a command
        (DECISION_COST each). Once it is spent nothing more is read, and the call is held (TK-SHELL-PARSE, budget)."""
        args = args if isinstance(args, dict) else {"value": args}
        cls = cls or self.tool_class(tool)
        fields = classes.extract(cls, tool, args, MAX_SUBJECT)
        hits = {sec: [] for sec in SECTIONS}
        if cls == "unknown" and self.policy.get("unknown_tools") in SECTIONS:
            hits[self.policy["unknown_tools"]].append("TK-UNKNOWN-TOOL")
        if cls == "sql" and fields.get("statement") is not None and not fields.get("code"):
            hits["ask"].append("TK-SQL-PARSE")   # no dialect reads it: an unclosed literal or comment, or not text
        if cls == "a2a" and fields.get("unreadable"):
            hits["deny"].append("TK-A2A-NAME")   # a name with spellings its rules can't see (classes.a2a_fields)
        parsed, oversize, on_parse_error = ([], [], [], [], []), [], self.policy.get("on_parse_error", "ask")
        cause = None
        work, deadline = _budget or ([0], [REGEX_TIMEOUT_S])   # (shell.charge; _backend)
        if cls == "http" and isinstance(args.get("urls"), list) and len(args["urls"]) > MAX_URLS:
            hits["deny"].append("TK-OVERSIZE")
            oversize.append(f"the urls list (more than {MAX_URLS})")
        if cls == "shell":
            command = fields.get("command", "")
            if len(_text(command if isinstance(command, str) else canonical(command)).encode()) > MAX_SUBJECT:
                hits["deny"].append("TK-OVERSIZE")
                oversize.append("the shell command")
            else:
                parsed, unread = self._parse(args, command, work, fallback=not _hidden)
                if _hidden and unread:   # (the parser can't read it as a command)
                    return {"verdict": "allow", "rule_ids": [], "policy_hash": self.policy_hash, "engine": self.engine,
                            "unparsed": True}
                if _hidden:   # each command also without its first word (gdb's `shell cmd`, expect's `spawn cmd`)
                    parsed = ([*parsed[0], *({**c, "argv": c["argv"][1:]} for c in parsed[0] if c["argv"][1:])],
                              *parsed[1:])
                # what at or batch run later and the parser can't read (at now <<< "$JOB") isn't held, as before
                # their code was read; with a writer's name in it, it counts for TK-D008 (_effects). A trap's action
                # runs in this shell, within the call: held as any other
                held = next((c for c in parsed[0] if c["opaque"] and not _SCHEDULED.intersection(c["via"])), None)
                if unread or held:
                    hits[on_parse_error].append("TK-SHELL-PARSE")
                    cause = unread or _unread_cause(held)
                # a hook's mark for text typed into a command already running, a key or a line left open
                # (agent_hooks: OpenHands' terminal): it runs with what comes before or after it, which this call
                # alone doesn't show. Only ever holds: a call without the mark is decided as before
                if args.get("typed") is True and not _hidden and "TK-SHELL-PARSE" not in hits[on_parse_error]:
                    hits[on_parse_error].append("TK-SHELL-PARSE")
                    cause = "typed"
        # the fallback's 1 s covers its regex matches alone (_backend): reading the call (the parse, the subjects) isn't
        # charged to it, and is bounded by the input size limits, as on RE2
        nondeterministic = False
        name, memo = _text(tool), {}
        low_name = name.lower()
        if cls not in self._of:   # the rules a class's calls reach: those of no class and of that class (_reaches),
            # each with the subjects it reads, its memo key (rules on the same subjects read them once; a shell rule with
            # no field reads argv), its prefilter strings' ids in the RE2 Set and its _parts
            self._of[cls] = [(*x, ("argv" if x[1].get("field") is None and cls == "shell" else x[1].get("field"),
                                   "from" in x[1]), self._ids.get(id(x[5])), self._parts.get(id(x[3])))
                             for x in self.rules if _reaches(x[1], cls)]
            self._of[cls, "deny"] = [x for x in self._of[cls] if x[0] == "deny"]

        spent = []   # why the engine's reading of the parse stopped (its budget), if it did
        in_set = {}   # (RE2) the ids of the prefilter strings each text holds: one Set search a text

        def holds(lits, ids, text):
            """Whether `text` holds one of a rule's prefilter strings `lits` (compile.literals; `ids`: theirs in the RE2
            Set), so its pattern may match there: a lookup on RE2, a str scan for each on the fallback."""
            if ids is None:
                return any(map(text.__contains__, lits))
            if (have := in_set.get(text)) is None:
                have = in_set[text] = frozenset(self._set.Match(text))
            return not have.isdisjoint(ids) if self._every in have else any(map(text.__contains__, lits))

        def finds(pattern, anycase, whole, texts):
            """Whether a regex the call gives (pgrep's, grep's) matches one of `texts`, on this engine's backend: linear
            on re2, within the decision's deadline on the fallback (TimeoutError). One the backend refuses (its syntax,
            its size) may match anything."""
            try:
                rx = self._compile(pattern, anycase)
            except Exception:   # re2.error, regex.error or compile.PolicyError: whatever the backend can't compile
                return True
            return any(self._match(rx, t, whole, deadline) for t in texts)

        def hit(entry, parsed, memo, oversize):
            """The id a rule gives the call (its own, or TK-OVERSIZE when it matches none of the subjects before one
            over MAX_SUBJECT), else None; TimeoutError past the deadline."""
            sec, rule, tool_re, pat, unless, lits, req, tool_lits, key, ids, parts = entry
            if tool_re is not None and not self._named(tool_re, tool_lits, name, low_name, deadline):
                return None
            if key not in memo:
                try:
                    subjects = self._subjects(cls, key[0], args, fields, parsed, key[1], finds, work, name)
                except shell.ParseError as e:   # the reading spent the decision's budget: held, as an unread line is
                    subjects, spent[:] = [], [e.cause]
                memo[key] = _prepare(subjects, _TAGGED.get(key[0], 0))
            texts, lows, joined, big = memo[key]
            if lits is None or holds(lits, ids, joined):
                for subject, low in zip(texts, lows):
                    # `unless`: an exemption checked against the same subject (use it only where the subject is
                    # one target, e.g. a file path; in a whole command it could exempt a different target)
                    if (lits is None or len(texts) == 1 or holds(lits, ids, low)) and (
                            req is None or len(low) < REQUIREMENTS_FROM or
                            any(all(any(map(low.__contains__, s)) for s in alt) for alt in req)) and (
                            self._match(pat, subject, False, deadline) if parts is None else any(
                                self._match(rx, subject, False, deadline) for rx, strings in parts
                                if any(map(low.__contains__, strings)))) and not (
                            unless is not None and self._match(unless, subject, False, deadline)) and (
                            "from" not in rule or untrusted is not None and _brought(untrusted, subject, rule.get("field"),
                                                                                     fields)):
                        return rule["id"]
            if big:   # the rule's own verdict: a flag rule cannot block a large call
                field = rule.get("field") or ("argv" if cls == "shell" else "the whole arguments")
                oversize.append(f"{rule['id']}'s subject ({field})")
                return "TK-OVERSIZE"
            return None
        # (an argument's command: its denies) less the rules whose tool pattern needs a string the tool's name lacks
        # (_named would refuse the name without a search): kept per class and name
        if (rules := self._of.get((cls, bool(_hidden), low_name))) is None:
            rules = [x for x in (self._of[cls, "deny"] if _hidden else self._of[cls])
                     if x[7] is None or any(map(low_name.__contains__, x[7]))]
            if len(self._of) < 4096 and len(low_name) <= 256:
                self._of[cls, bool(_hidden), low_name] = rules
        for entry in rules:
            # a rule with no tool pattern whose subjects, read already, are none or hold none of its strings (and none
            # is over MAX_SUBJECT) gives nothing: hit() would match nothing
            if entry[2] is None and (m := memo.get(entry[8])) and not m[3] and (
                    not m[0] or entry[5] is not None and not holds(entry[5], entry[9], m[2])):
                continue
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
        # no second reading (_SECOND): it reads the same without them, so each of its denies is as written; nor has a
        # line whose second readings read nothing more (shell's `more`: read as written it is the same parse, its
        # rules read the same subjects). A reading the budget cut short moves none
        written = [x for x in self._of[cls, "deny"] if x[1]["id"] in hits["deny"]] if hits["deny"] else []
        same = len(parsed) > 5 and not parsed[5]["more"]
        if cls == "shell" and on_parse_error == "ask" and written and not nondeterministic and not _hidden and not same \
                and (not isinstance(command, str) or _SECOND.search(command)):
            parsed, memo = self._parse(args, command, work, readings=False)[0], {}
            for entry in written:
                try:
                    if hit(entry, parsed, memo, []) is None and work[0] <= shell.MAX_WORK:
                        hits["deny"].remove(entry[1]["id"])
                        hits["ask"].append(entry[1]["id"])
                except TimeoutError:   # it stays a deny
                    nondeterministic = True
                    break
        # (only where nothing else holds the call: a held line's arguments add no stop, and an unread one's refs are
        # its raw text). Each is decided on this decision's budget; one that runs out of time denies, as a match here
        # would
        if cls == "shell" and _hidden < 2 and not nondeterministic and not hits["deny"] and not hits["ask"] \
                and work[0] <= shell.MAX_WORK:
            for text in shell.hidden_commands(parsed[0], parsed[2]):
                for t in (text, *text.split(None, 1)[1:]):   # without its first word where that can't be read
                    work[0] += DECISION_COST
                    inner = {} if work[0] > shell.MAX_WORK else self.decide(
                        tool, {"command": t}, "shell", untrusted, _hidden + 1, (work, deadline))
                    nondeterministic |= bool(inner.get("nondeterministic"))
                    for rid in inner.get("rule_ids", ()):
                        if rid in self._deny_ids and rid not in hits["deny"] and rid not in hits["ask"]:
                            hits["deny" if nondeterministic else "ask"].append(rid)
                    if not inner.get("unparsed"):
                        break
                if nondeterministic or work[0] > shell.MAX_WORK:
                    break
        if (spent or work[0] > shell.MAX_WORK) and "TK-SHELL-PARSE" not in hits[on_parse_error]:
            hits[on_parse_error].append("TK-SHELL-PARSE")
            cause = cause or "budget"
        if self.policy.get("oversize") == "ask" and "TK-OVERSIZE" in hits["deny"]:   # what it can't read waits for a
            hits["deny"] = [i for i in hits["deny"] if i != "TK-OVERSIZE"]          # person (the dev pack), not a deny
            hits["ask"].append("TK-OVERSIZE")
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

    def _parse(self, args, command, work, readings=True, fallback=True):
        """(shell.analyse() of a shell call, or what _plain() reads of one the parser can't read; why it can't, its
        ParseError's cause, else None). `readings`: False reads the command only as written (shell.analyse); `work`:
        the decision's budget (shell.charge), which _plain() spends too. `fallback`: False leaves _plain() out (None
        in its place), for a caller that only asks whether the command reads. A `commands` list is read joined, as one
        shell runs it (LangChain's ShellTool), and each entry on its own too, as its own shell runs it (OpenAI's shell
        tool, Cline's run_commands), where an open quote, a trailing \\ or a here-doc in one can't hide the next: the
        call is decided on what either reading finds."""
        parts = [self._parse_one(args, command, work, readings, fallback)]
        for c in commands_each(args):
            parts.append(self._parse_one({"command": c}, c, work, readings, fallback))
        return parts[0] if len(parts) == 1 else (None if any(p is None for p, _ in parts) else
                                                 joined_readings([p for p, _ in parts]),
                                                 next((c for _, c in parts if c), None))

    def _parse_one(self, args, command, work, readings=True, fallback=True):
        """_parse's reading of one shell call as written."""
        target = (lambda t: any(p.search(_text(t.casefold())) for p in self._persistent_targets)) \
            if self._persistent_targets else None
        start = work[0]
        try:
            return _shell(args, target, readings, work), None
        except shell.ParseError as e:
            if not fallback:
                return None, e.cause
            return (_plain(command, work, work[0] - start, getattr(e, "at", 0), readings, target, getattr(e, "cmds", ()))
                    if isinstance(command, str) else _plain(canonical(command), work, 0, 0, readings, target)), e.cause

    @staticmethod
    def _subjects(cls, field, args, fields, parsed, split=False, finds=None, work=None, tool=""):
        """A class field matches the signer's extraction; any other field names a raw argument; no field scans the
        whole call (Write/Edit content, WebFetch url and prompt, MCP args). A shell `line` is the raw command and
        each line the parser normalised, a shell `code` those without the text a command only writes into a file
        (shell.analyse); an fs `path` with `..` also matches its lexically normalised form, and each entry of a
        `paths` list (every file of a Codex patch) is a path too, and an http field is read for each URL of a `urls`
        list too (every URL a Gemini CLI web_fetch prompt names). `target` (every class) is what the call
        acts on rather than what it carries (Engine._targets); shell `effects` the files it writes or deletes
        (_effects); sql `code` is one subject per dialect reading. With
        `split`, a list value is one subject per element (nested lists flattened). `finds`: decide's matcher of a
        regex the call gives (_finds); `work`: the decision's budget, which reading Tracekit's paths spends
        (shell.charge)."""
        if cls == "http" and field is not None and isinstance(args.get("urls"), list):   # a call on several URLs
            urls = canonical(args["urls"])
            if len(args["urls"]) > MAX_URLS or len(_text(urls).encode()) > MAX_SUBJECT:   # unread (decide's TK-OVERSIZE)
                return [urls]
            one = {k: v for k, v in args.items() if k != "urls"}
            # read once what no URL changes (a raw argument's canonical form); per URL, the class's fields and target
            each = [{**one, "url": u} for u in args["urls"]] if field == "target" or field in CLASSES[cls] else []
            return list(dict.fromkeys(s for a in [one, *each] for s in Engine._subjects(
                cls, field, a, classes.extract(cls, "", a, MAX_SUBJECT), parsed, split)))
        if field == "target":
            return Engine._targets(cls, args, fields, parsed)
        if cls == "shell" and field == "effects":
            return _effects(parsed)
        if cls == "shell" and field == "tracekit":
            return _tracekit(parsed, finds, [0] if work is None else work)
        if cls == "shell" and field == "package_index":
            return _package_indexes(parsed[0], parsed[2])
        if cls == "shell" and field == "container_host_access":
            return _container_host_access(parsed[0])
        if cls == "shell" and field == "push":
            return _pushes(parsed[0])
        if cls == "unknown" and field == "run":
            return _runs(args, tool)
        if cls == "sql" and field == "code":
            return fields.get("code", [])
        if cls == "shell" and field == "code":
            return _code(parsed)
        if cls == "shell" and field in (None, "argv"):
            # and each again with its words' own spaces as WORD_SPACE where a word before its last has one (the last
            # word's move no word after it: sqlite3's SQL is searched once), and with each word that is only a variable
            # the line gives no value there (shell's unresolved: not a loop's, nor one it knows) as UNKNOWN_WORD
            unknown = (parsed[5] if len(parsed) > 5 else {}).get("unresolved", ())
            return list(dict.fromkeys([" ".join(c["argv"]) for c in parsed[0]] + [
                " ".join(w.replace(" ", WORD_SPACE) for w in c["argv"]) for c in parsed[0]
                if " " in "".join(c["argv"][:-1])] + [
                " ".join(UNKNOWN_WORD if (m := _BARE_VARIABLE.fullmatch(w)) and m.group(1) in unknown else w
                         for w in c["argv"]) for c in parsed[0] if unknown and "$" in "".join(c["argv"])]))
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
        read as a path is (classes.fs_forms: `/root/.aws//credentials`); app and unknown tools: the whole call;
        harness (a coding agent's message to its own agents): only the URLs and bare network addresses in it (its words
        split at spaces and punctuation, a bare IPv4 address also read as its canonical host, as a shell argv's is), so the
        rules that read a target for file names (TK-S004, TK-F005) don't read a prompt's prose as a file it opens. Each
        URL is also matched as scheme://canonical-host/ (classes.url_target), so a host in decimal, hex, octal or IPv6
        form reads as the address it is: of mcp, app and unknown tools, each URL in a string of what they act on."""
        if cls == "shell":
            commands = parsed[0]
            words = [[a for i, a in enumerate(c["argv"]) if i not in data] for c in commands
                     for data in [shell.data_words(c["argv"]) | set(c.get("data_words", ()))]]
            stdin = [s for c in commands if not c.get("data_stdin") for s in c["stdin"]]
            found = [a for ws in words for a in ws] + parsed[2] + stdin
            urls = [t for t in _url_targets([u for w in found if ":" in w for u in _URL.findall(w)]) if t]
            bare = [t for t in _url_targets(["http://" + w for w in found if _BARE_ADDRESS.match(w)])
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
        if cls == "harness":   # a message to the agent's own agents: the addresses it names, not its file names
            strings = _strings(args)
            urls = [u for s in strings for u in _URL.findall(s)]
            bare = list(dict.fromkeys(w for s in strings for w in _PROSE_SPLIT.split(s) if _BARE_ADDRESS.match(w)))
            # a bare address's canonical host, without a scheme: TK-S001 reads it, and TK-F012 (egress, `://`) doesn't
            # flag prose that only names a version (1.2.3 reads as an address)
            hosts = [t[7:-1] for t in (classes.url_target("http://" + w) for w in bare) if t and _BARE_TARGET.fullmatch(t)]
            return list(dict.fromkeys(urls + [t for t in map(classes.url_target, urls) if t] + bare + hosts))
        if cls not in ("mcp", "app", "unknown"):
            return []
        tool = fields.get("tool")
        call = _acted_on(args, _carried(tool if isinstance(tool, str) else "")) if cls == "mcp" else args
        strings = _strings(call)
        paths = [f for s in strings if "/" in s or "\\" in s for f in classes.fs_forms(s)] if cls == "mcp" else []
        urls = [t for t in map(classes.url_target, (u for s in strings for u in _URL.findall(s))) if t]
        return list(dict.fromkeys([canonical(call)] + paths + urls))


def _alternatives(pattern):
    """A checked pattern's top-level alternatives (`a|b(c|d)` is `a` and `b(c|d)`), or None when it has one."""
    parts, depth, cls, start, i = [], 0, None, 0, 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if cls is not None:
            if c == "]" and i > cls:
                cls = None
        elif c == "[":
            cls = i + 1 + (pattern[i + 1:i + 2] == "^")   # a ] right after [ or [^ is literal (compile.translate)
            i = cls
            continue
        elif c in "()":
            depth += 1 if c == "(" else -1
        elif c == "|" and not depth:
            parts.append(pattern[start:i])
            start = i + 1
        i += 1
    return parts + [pattern[start:]] if parts else None


def _finer(req, lits):
    """compile.requirements when it says more than compile.literals: None where each alternative needs a string of one
    set and those sets together are the literals (`(?:ab|cd|ef)`), whose check, made first, already said it."""
    if req is not None and all(len(alt) == 1 for alt in req) and {s for alt in req for s in alt[0]} == set(lits or ()):
        return None
    return req


def _reaches(rule, cls):
    """Whether a rule reads a call of class `cls`: one of no class or of that class (decide and reads alike)."""
    return rule.get("class", cls) == cls


def _unread_cause(command):
    """Why the parser can't read what an opaque command runs, as a key of compile.ENGINE_REASONS's TK-SHELL-PARSE
    causes: a function the line defines and doesn't call, or exports (function); its name is built by a variable or
    substitution (name) or a pattern (pattern); a shell bash isn't (foreign);
    a shell, interpreter, source, at, batch, parallel or xargs that runs code from a pipe, a file or its input (input);
    else other; or the cause the parser gives (`unread`: a word's expansions combine in more ways than it reads)."""
    name = command["argv"][0]
    if command.get("unread"):
        return command["unread"]
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


def _url_targets(urls):
    """classes.url_target of each URL, each one read once: a line's readings repeat its words."""
    of = {u: classes.url_target(u) for u in dict.fromkeys(urls)}
    return [of[u] for u in urls]


def _path_forms(targets):
    """Targets, each also as plainly written (/etc/./x, /etc//x and /etc/y/../x name /etc/x) and casefolded."""
    have = set(targets)
    targets = targets + [n for n in (" ".join(posixpath.normpath(p) if _DOTTED.search(p) else p for p in t.split(" "))
                                     for t in targets if ("." in t or "//" in t) and _DOTTED_WORD.search(t))
                         if n not in have]
    have = set(targets)
    return targets + [f for f in dict.fromkeys(map(str.casefold, targets)) if f not in have]


def commands_each(args):
    """The entries of a shell call's `commands` list of command lines, when it has several and no other command field:
    each is also read on its own (Engine._parse, constraints.shell), else []."""
    cmds = args.get("commands")
    return cmds if isinstance(cmds, list) and len(cmds) > 1 and all(isinstance(c, str) for c in cmds) and \
        [k for k in classes.SHELL_KEYS if args.get(k) is not None] == ["commands"] else []


def joined_readings(parts):
    """Several readings of one shell call (_shell's or _plain's tuples) as one: their lists joined, and what else they
    learned (shell._learned) when every one has it."""
    out = [[x for p in parts for x in p[i]] for i in range(5)]
    if all(len(p) > 5 for p in parts):
        learned = [p[5] for p in parts]
        out.append({k: (any(d[k] for d in learned) if isinstance(learned[0][k], bool) else
                        set().union(*(d[k] for d in learned)) if isinstance(learned[0][k], set) else
                        [x for d in learned for x in d[k]]) for k in learned[0]})
    return tuple(out)


def _shell(args, persistent_target=None, readings=True, work=None):
    """shell.analyse() of a shell call: (commands, normalised lines, other words that name something, files
    redirections write, code). `command` or `cmd` is a command line or an argv list; `commands` (OpenAI's shell tool)
    a list of command lines. Anything else, or more than one of them, raises ParseError."""
    present = [k for k in classes.SHELL_KEYS if args.get(k) is not None]
    if len(present) > 1:
        raise shell.ParseError(f"more than one command field: {present}")
    value = args[present[0]] if present else ""
    strings = isinstance(value, list) and value and all(isinstance(a, str) for a in value)
    if isinstance(value, str):
        return shell.analyse(value, persistent_target, readings, work)
    if strings and present == ["commands"]:
        return shell.analyse("\n".join(value), persistent_target, readings, work)
    if strings:
        return shell.analyse_argv(value, readings, work)
    raise shell.ParseError("the command is neither a string nor a list of strings")


# a piece of a line between ;, &, | and newlines outside quotes, as bash separates commands; a quote left open runs to
# the end of the line, as bash reads no command after it; a # that starts a word comments out the rest of its line, a
# quote in it too
_PIECE = re.compile(r"""(?:(?<![^ \t\n;&|(])(?<!\\.)#[^\n]*|[^;&|\n'"\\]|\\.?|'[^']*(?:'|\Z)|"(?:[^"\\]|\\.?)*(?:"|\Z))+""", re.S)


def _plain(raw, work, spent, at=0, readings=True, persistent_target=None, cmds=()):
    """What a command the parser can't read is decided on: its text as its target and code; the commands it read
    before it stopped (`cmds`: a substitution bash runs inside quotes, `let 'x[$(cmd)]'`); the line before the word
    it stopped in (`at`: where), parsed; and each piece of the rest (_PIECE), from the one it stopped in, split on
    blanks as a command (shell.analyse_argv), so a rule that reads plain words still holds what it held (`sudo id
    {1..3..1}`). A part that can't be read so is left out. Each spends the decision's budget (`work`), which the parse
    that stopped spent `spent` of: the head, which costs about as much again, is read only when the budget has that
    left, else left out with its pieces (its commands are `cmds`), and once the budget is spent nothing more is read.
    `persistent_target`: as for shell.analyse, so text echoed into ~/.bashrc stays code in the head too."""
    out, start = (list(cmds), [], [raw], [], [raw]), 0
    head = raw[:max(0, *(raw.rfind(c, 0, at) for c in " \t\n"))]
    found = []
    if head.strip():
        last = ([m.span() for m in _PIECE.finditer(head)] or [(0, 0)])[-1]
        after = last[0] if last[1] == len(head) else last[1] + 1   # after a separator that ends the head
        if work[0] + spent > shell.MAX_WORK:
            start = after
        else:
            try:
                found.append(shell.analyse(head, persistent_target, readings, work))
                start = after
            except shell.ParseError:
                pass
    for piece in (m.group() for m in _PIECE.finditer(raw, start)):
        if work[0] > shell.MAX_WORK:   # spent: the rest isn't read (32,000 pieces took 0.6 s)
            break
        try:
            found.append(shell.analyse_argv(piece.split(), readings, work) if piece.split() else ())
        except shell.ParseError:
            pass
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


# git's own options before its command that take the next word as their value (git -C dir push); the rest are flags
_GIT_VALUED = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env",
               "--attr-source"}
# git push's long options (git push -h), each with what it means here: a reason to hold the push, "value" (it takes
# the next word unless given with `=`), or "" (neither). git reads a unique prefix of one as it, and so does _pushes.
# A force (-f, --force, --force-with-lease, a +refspec) is TK-D003's deny and a delete (-d, --delete, --prune, a
# :refspec) TK-A002's ask, so they give no reason here: a denied force push isn't also told to wait for approval
_PUSH_LONG = {"all": "all", "branches": "all", "mirror": "all", "delete": "", "prune": "", "tags": "tags",
              "follow-tags": "tags", "force": "", "force-with-lease": "", "force-if-includes": "",
              "repo": "value", "recurse-submodules": "value", "receive-pack": "value", "exec": "value",
              "push-option": "value", "verbose": "", "quiet": "", "dry-run": "", "porcelain": "", "thin": "",
              "set-upstream": "", "progress": "", "verify": "", "no-verify": "", "signed": "", "atomic": "",
              "ipv4": "", "ipv6": ""}
_PUSH_SHORT = {"d": "", "f": "", "v": "", "q": "", "n": "", "u": "", "4": "", "6": ""}   # and -o VALUE
_REMOTE_PUSH = re.compile(r"remote\..+\.(?:push|mirror)")   # a config key, casefolded (its remote name keeps case)
# gh api's options that take a value (gh api --help), each with what it gives here: -F fills gh's placeholders
# ({owner}, {repo}, {branch}) in its value, -f doesn't; hub api reads -t as --flat, which takes none
_GH_VALUED = {"-X": "method", "--method": "method", "-F": "field", "--field": "field", "-f": "raw", "--raw-field": "raw",
              "--input": "input", "-H": "", "--header": "", "-t": "", "--template": "", "-q": "", "--jq": "", "-p": "",
              "--preview": "", "--hostname": "", "--cache": ""}
_GH_HOST = re.compile(r"(?:[a-z][a-z0-9+.-]*://[^/]*(?=/|$))?", re.I)   # a URL's scheme and host


# an expansion, or a {…} word gh (its {branch}: the current branch) or a program running gh fills in (find -exec's,
# parallel's and xargs -I{}'s {}); gh's {owner} and {repo} are the current repository
_GH_OPENS = re.compile(r"[$`]|\{(?!(?:owner|repo)\})[^{}]*\}")
_GH_UNIT = re.compile(r"\$\{[^}]*\}?|`[^`]*`?|\$[A-Za-z_]\w*|\$.?|\{[^{}]*\}", re.S)
# routes of repos/<owner>/<repo>/ that write no branch: a literal one after an expansion places the call
_GH_SAFE = frozenset((
    "actions", "assignees", "attestations", "autolinks", "automated-security-fixes", "branches", "check-runs",
    "check-suites", "code-scanning", "collaborators", "comments", "commits", "dependabot", "deployments", "dispatches",
    "environments", "forks", "hooks", "interaction-limits", "invitations", "issues", "keys", "labels", "milestones",
    "notifications", "pages", "private-vulnerability-reporting", "projects", "properties", "pulls", "releases",
    "rulesets", "secret-scanning", "statuses", "subscription", "tags", "topics", "vulnerability-alerts"))
_GH_WRITES = ("git", "contents", "merges", "merge-upstream")   # routes that write a branch
# a segment GitHub can route in an owner's, a repo's or a route's place (a name, or gh's {owner} and {repo}); anything
# else there (`%`, `,,`) is a word a program running gh fills in, which the line can't tell
_GH_SEGMENT = re.compile(r"[\w.-]+|\{(?:owner|repo)\}")
_GH_ONE_WORD = frozenset(("app", "emojis", "events", "feeds", "gists", "graphql", "issues", "licenses", "markdown",
                          "meta", "notifications", "octocat", "organizations", "rate_limit", "repositories", "user",
                          "versions", "zen"))   # GitHub's endpoints of one segment


def _gh_mask(text, replaced=None):
    """`text` with each part the line can't tell (an expansion: `$X`, `${…}`, `$(…)` with what it nests, a backquoted
    span; a {…} word gh or the program running it fills in; the word xargs -I replaces, `replaced`) one NUL: a unit
    that may stand for any number of segments, a `/` inside it not one of the path's."""
    text = text.replace(replaced, "\0") if replaced else text
    out, i = [], 0
    while m := _GH_OPENS.search(text, i):
        out.append(text[i:m.start()] + "\0")
        if text.startswith("$(", m.start()):
            depth, j = 0, m.start() + 1
            while j < len(text) and (depth := depth + (text[j] == "(") - (text[j] == ")")) > 0:
                j += 1
            i = j + 1
        else:
            i = _GH_UNIT.match(text, m.start()).end()
    return "".join(out) + text[i:]


def _gh_routes(endpoint, replaced=None, strict=True):
    """(the route a gh api endpoint names, lower-cased; whether the line can't tell where a write to it goes; whether
    an expansion comes before its route), read from its path as GitHub routes it, after a URL's scheme and host and
    GHES's api/v3/: repos/<owner>/<repo>/<route>/…, repositories/<id>/<route>/…, <route>/… for the rest. An
    expansion or {branch} (_gh_mask) may stand for any number of segments: one (or an empty segment) at or before the
    route's place leaves the route to the first literal segment after it that names one (_GH_SAFE, git, contents,
    merges, merge-upstream), and unknown without one; so does a segment there GitHub can't route (_GH_SEGMENT). Unknown
    too: an endpoint of one segment that isn't one of GitHub's (_GH_ONE_WORD), a `.` or `..` segment, and an expansion
    after git/, where it names the ref. Not `strict` (a word after gh's endpoint, which gh refuses), a word there is
    read as GitHub routes it."""
    if not endpoint:
        return [], False, False
    path = _gh_mask(endpoint, replaced)
    segs = re.split(r"[?#]", path[_GH_HOST.match(path).end():], maxsplit=1)[0].strip("/").split("/")
    if segs[:1] == ["api"]:   # GHES serves the API at /api/v3/
        segs = segs[2:] if segs[1:2] == ["v3"] else segs[1:]
    if strict and len(segs) == 1 and segs[0].lower() not in _GH_ONE_WORD:   # (xargs -J %, parallel -I ,,: the input)
        return [], True, True
    # from a later repos/ or repositories/ segment that an owner and a repo (an id) follow, past a host without a
    # scheme (//api.github.com/…) or another prefix; an expansion before it may be any path. Elsewhere (user/repos,
    # orgs/o/repos: creating a repository) it is a route of the path's own
    k = next((k for k, s in enumerate(segs) if s.lower() == "repos" and len(segs) > k + 2 or
              s.lower() == "repositories" and len(segs) > k + 1), 0)
    if any(s in (".", "..") for s in segs) or any("\0" in s for s in segs[:k]):
        return [], True, True
    segs = segs[k:]
    first = segs[0].lower() if segs else ""
    at = 3 if first == "repos" else 2 if first == "repositories" else 0
    # an empty segment (a doubled `/`, or an expansion read as empty), or one GitHub can't route, is as unplaced as an
    # expansion
    opened = next((j for j, s in enumerate(segs[:at + 1])
                   if (not _GH_SEGMENT.fullmatch(s) if strict else "\0" in s or not s)), None)
    if opened is None:
        route = segs[at].lower() if at < len(segs) else ""
        return [route] if route else [], route == "git" and any("\0" in s for s in segs[at + 1:]), False
    for j in range(opened + 1, len(segs)):
        route = segs[j].lower()
        if route in _GH_SAFE or route in _GH_WRITES:
            return [route], route == "git" and any("\0" in s for s in segs[j + 1:]), True
    return [], True, True


def _git_push(argv):
    """Why a git push needs a person, from its argv as the parser read it: a list of `PUSH:<why> <word>`, empty for a
    push of named branches other than main and master; None for any other command. A push is `git push` (after git's
    own options, `git -C dir push`), `git send-pack`, which names its refs as push does, `hub push` (hub runs git) and
    git-push or git-send-pack themselves. Held: a target of main or master (`main`, `HEAD:main`, `refs/heads/master`,
    `heads/main`, `:main`); one the line can't tell (no refspec, so push.default picks; HEAD, @ or origin/HEAD; an
    expansion or a pattern, or a remote's push or mirror setting given with -c or --config-env); tags (--tags,
    --follow-tags, a refs/tags/ or tags/ refspec, `tag <name>`); every branch (--all, --mirror, the `:` refspec); an
    option push doesn't take, or an ambiguous prefix, which git refuses (send-pack's --stdin, whose refs come from its
    input, among them). A force or a delete is another rule's (_PUSH_LONG).
    lean: a git alias (`git p`) or `git subtree push` isn't read, as TK-D003 doesn't read them; nor a tag pushed by its
    bare name (`git push origin v1.0`), which reads as a branch"""
    name = _program(argv)
    why = []
    if name in ("git", "hub"):
        i = 1
        while i < len(argv) and argv[i].startswith("-"):
            # a remote's push or mirror setting given for this run (`-c remote.origin.push=HEAD:main`) picks the target
            value = argv[i + 1] if argv[i] in ("-c", "--config-env") and i + 1 < len(argv) else \
                argv[i].removeprefix("--config-env=") if argv[i].startswith("--config-env=") else None
            if value is not None and _REMOTE_PUSH.fullmatch(value.partition("=")[0].casefold()):
                why.append("unknown " + value)
            i += 2 if argv[i] in _GIT_VALUED else 1
        if argv[i:i + 1] not in (["push"], ["send-pack"]):
            return None
        words = argv[i + 1:]
    elif name in ("git-push", "git-send-pack"):
        words = argv[1:]
    else:
        return None
    positional, i = [], 0
    while i < len(words):
        w = words[i]
        i += 1
        if w == "--":
            positional += words[i:]
            break
        if w.startswith("--"):
            opt, eq, _ = w[2:].partition("=")
            names = [opt] if opt in _PUSH_LONG or opt.startswith("no-") else [n for n in _PUSH_LONG if n.startswith(opt)]
            if len(names) != 1:
                why.append("unknown " + w)
                continue
            kind = "" if names[0].startswith("no-") and names[0] != "no-verify" else _PUSH_LONG[names[0]]
            if kind == "value":
                i += not eq
            elif kind:
                why.append(f"{kind} {w}")
        elif w.startswith("-") and len(w) > 1:
            kinds = set()
            for j, c in enumerate(w[1:], 1):
                if c == "o":   # -o takes the rest of the word, or the next one
                    i += j == len(w) - 1
                    break
                kinds.add(_PUSH_SHORT.get(c, "unknown"))
                if c not in _PUSH_SHORT:
                    break
            why += [f"{k} {w}" for k in sorted(kinds - {""})]
        else:
            positional.append(w)
    refspecs = positional[1:]   # the first is the repository
    if not refspecs:
        why.append("unknown no refspec")
    tag = False
    for r in refspecs:
        if tag or r == "tag":   # `tag <name>` pushes refs/tags/<name>
            why.append("tags tag " + r)
            tag = not tag
            continue
        spec = r[1:] if r.startswith("+") else r
        src, colon, dst = spec.partition(":")
        target = dst if colon else src
        ref = target.removeprefix("refs/")   # git reads `heads/main` as refs/heads/main, `tags/v1` as a tag
        if spec == ":":
            why.append("all " + r)
        if "refs/tags/" in spec or ref.startswith("tags/"):
            why.append("tags " + r)
        elif ref.removeprefix("heads/") in ("main", "master"):
            why.append("default " + r)
        elif not target or target in ("HEAD", "@") or target.endswith("/HEAD") or any(c in target for c in "$`*?[{"):
            why.append("unknown " + r)
    return ["PUSH:" + w[:64] for w in why]   # what matters is the reason; a word is cut, so a subject stays short


def _gh_api(argv, replaced=None):
    """A gh or hub api call's argv percent-decoded, as GitHub reads its path (`git/refs/heads%2Fmain`), and
    `PUSH:contents` when it puts or deletes a repository's file (repos/<o>/<r>/contents/…), which commits to the
    default branch unless a branch field names another. A branch the line can't tell is held too: HEAD, one gh reads
    from a file (`-F branch=@b.txt`) or an expansion gives, and any with --input, whose body then names the branch
    (the fields go to the query). The words are read as gh reads them: an option that takes a value takes the rest
    of its word or the next word (`-f --method=GET` is a field), the method only from -X or --method (the last; POST
    with a field or --input, else GET) and the branch only from a field (`-F branch={branch}` is the current one); a
    method that is an expansion the line can't resolve counts as a write. The endpoint's route is _gh_routes' (with
    `replaced`, the word xargs -I puts its input in place of): a write there gives `PUSH:merges` for repos/<o>/<r>/merges
    (any form), `PUSH:merge-upstream` for a fork's merge-upstream into the default branch or one the line can't tell,
    and `PUSH:unknown` where the line can't tell where it goes (`"$EP"`, `repos/o/r/$P`, `git/refs/heads/$B`, a `..`
    segment, no endpoint, which xargs appends). A PUT or DELETE with an expansion before its route is unknown too
    when its body is the contents API's (message and content, or message and sha, or one the line can't read) and
    no literal branch field names another branch."""
    words = [unquote(w) for w in argv]
    valued = _GH_VALUED.keys() - ({"-t"} if _program(argv) == "hub" else set())
    given, positional, i = [], [], 2
    while i < len(words):
        w, i = words[i], i + 1
        if w == "--":
            positional += words[i:]
            break
        if w.startswith("--"):
            name, eq, value = w.partition("=")
        elif w.startswith("-") and len(w) > 1:   # a cluster (-iXPUT): its first valued letter takes the rest
            k = next((k for k in range(1, len(w)) if "-" + w[k] in valued), len(w))
            name, eq, value = "-" + w[k:k + 1], w[k + 1:k + 2] == "=", w[k + 1:].removeprefix("=")
        else:
            positional.append(w)
            continue
        if name not in valued:
            continue   # a flag (--paginate, -i) or an option gh refuses
        if not eq and not value:
            value, i = (words[i] if i < len(words) else ""), i + 1
        given.append((_GH_VALUED[name], value))
    kinds = {kind for kind, _ in given}
    fields = [(kind, *v.partition("=")[::2]) for kind, v in given if kind in ("field", "raw")]
    method = next((v for kind, v in reversed(given) if kind == "method"),
                  "POST" if kinds & {"field", "raw", "input"} else "GET")
    magic, branch = next(((kind == "field", v) for kind, key, v in reversed(fields) if key == "branch"), (False, ""))
    branch = branch.removeprefix("refs/").removeprefix("heads/")
    keys = {key for _, key, _ in fields}
    unread_body = "input" in kinds or any("$" in k or "`" in k for k in keys)
    # a branch field that alone names a branch other than the default: literal, and no body or field name hides another
    named = bool(branch) and not unread_body and branch[:1] != "@" and "$" not in branch and "`" not in branch and \
        not (magic and "{branch}" in branch) and branch.casefold() not in ("main", "master", "head")
    routes, unknown, expanded = [], not positional, False   # no endpoint: xargs appends it (gh refuses none)
    for n, endpoint in enumerate(positional):   # (gh takes one; read each of more, which gh refuses)
        found, unread, before = _gh_routes(endpoint, replaced, strict=not n)
        routes, unknown, expanded = routes + found, unknown or unread, expanded or before
    unread_method = not method or "$" in method or "`" in method
    put, delete = (unread_method or method.upper() == m for m in ("PUT", "DELETE"))
    write = unread_method or method.upper() not in ("GET", "HEAD")
    # a PUT or DELETE with an expansion before its route may be the contents API's, whose file path is every segment
    # after contents/ (X=o/r/contents: repos/$X/issues/1 is a file), but only with the body that API takes
    unknown = unknown or expanded and not named and (put and (unread_body or {"message", "content"} <= keys) or
                                                      delete and (unread_body or {"message", "sha"} <= keys))
    out = [" ".join(words)]
    if write and unknown:
        out.append("PUSH:unknown " + (positional[0] if positional else "")[:64])
    elif write and "merges" in routes:
        out.append("PUSH:merges " + method[:64])
    elif write and "merge-upstream" in routes and not named:
        out.append("PUSH:merge-upstream " + branch[:64])
    elif (put or delete) and "contents" in routes and not named:
        out.append("PUSH:contents " + method[:64])
    return out


def _pushes(commands):
    """Each command's argv, as the `argv` field reads it, but a git push as what makes it need a person (_git_push):
    one `PUSH:<why> <word>` subject each, none for a push of named branches other than main and master; a gh or hub
    api call also percent-decoded (_gh_api); a kubectl dry run (_kubectl_dry_run) as `DRYRUN:<argv>`."""
    out, replaced = [], None
    for command in commands:
        argv = command["argv"]
        if argv[:1] in (["xargs"], ["gxargs"]):   # the word its -I puts the input in place of, for what it runs
            inner = next(shell._unwrap(argv[0], argv[1:]))
            replaced = shell._xargs_replace(argv[1:len(argv) - len(inner)])
        elif not {"xargs", "gxargs"} & set(command.get("via", ())):
            replaced = None   # (the word was that xargs' only)
        push = _git_push(argv)
        out += push if push is not None else ["DRYRUN:" * _kubectl_dry_run(argv) + " ".join(argv)]
        if push is None and _program(argv) in ("gh", "hub") and argv[1:2] == ["api"]:
            given = replaced if {"xargs", "gxargs"} & set(command.get("via", ())) else None
            out += [s for s in _gh_api(argv, given) if s not in out]
        runner = {v.split(" ", 1)[0] for v in command.get("via", ())} & {"xargs", "gxargs", "parallel", "find", "fd"}
        out += [s for s in _gh_repo_sync(argv, bool(runner)) if s not in out]
    return out


def _gh_repo_sync(argv, runner=False):
    """`PUSH:repo-sync <branch>` for `gh repo sync <owner/repo>`, which merges the fork's branch from its upstream: the
    default branch unless --branch names another, held for main, master or HEAD (any case, refs/heads/ too) or a branch
    the line can't tell. With no repository it updates the local one from its remote, a pull: none, unless a `runner`
    (xargs, parallel, find -exec, fd -x) may give it one."""
    if _program(argv) != "gh" or argv[1:3] != ["repo", "sync"]:
        return []
    repo, branch, i = None, "", 3
    while i < len(argv):
        w, i = argv[i], i + 1
        if w in ("-b", "--branch", "-s", "--source"):
            value, i = (argv[i] if i < len(argv) else ""), i + 1
        elif w.startswith(("--branch=", "--source=")) or w[:2] in ("-b", "-s") and len(w) > 2:
            value = w.partition("=")[2] if w.startswith("--") else w[2:]
        elif w.startswith("-"):
            continue   # --force (TK-D003's deny), or an option gh refuses
        else:
            repo = repo or w
            continue
        if w.lstrip("-")[:1] == "b":
            branch = value
    branch = branch.removeprefix("refs/").removeprefix("heads/")
    named = branch and "$" not in branch and "`" not in branch and branch.casefold() not in ("main", "master", "head")
    return [] if repo is None and not runner or named else ["PUSH:repo-sync " + (branch or "default")[:64]]


def _kubectl_dry_run(argv):
    """Whether a kubectl command is a dry run as kubectl reads its words: its last --dry-run (bare, =client or =server;
    not =none or =false) comes before a bare `--`, after which kubectl reads every word as a name; no word before that
    is --raw (a request sent as given) or holds an expansion the line can't resolve (`"$D"` may be `--` or a later
    --dry-run=none), and no --dry-run word comes right after an option that may take it as its value (_kubectl_takes:
    `--field-manager --dry-run`)."""
    if _program(argv) != "kubectl":
        return False
    last = None
    for prev, word in zip(argv, argv[1:]):
        if word == "--":
            break
        if word.startswith("--raw") or "$" in word or "`" in word:
            return False
        if word == "--dry-run" or word.startswith("--dry-run="):
            if _kubectl_takes(prev):
                return False
            last = word
    return last in ("--dry-run", "--dry-run=client", "--dry-run=server")


# kubectl's options that take no word after them: its boolean flags, and those with a value they take only after `=`
# (--dry-run, --validate, --cascade); any other option may take the next word as its value
_KUBECTL_FLAGS = {"all", "all-namespaces", "allow-missing-template-keys", "cascade", "delete-emptydir-data",
                  "disable-compression", "disable-eviction", "dry-run", "force", "force-conflicts", "help",
                  "ignore-daemonsets", "ignore-not-found", "insecure-skip-tls-verify", "interactive", "local",
                  "match-server-version", "no-headers", "now", "output-watch-events", "overwrite", "prune", "quiet",
                  "record", "recursive", "save-config", "server-print", "server-side", "show-kind", "show-labels",
                  "show-managed-fields", "stdin", "tty", "validate", "wait", "warnings-as-errors", "watch",
                  "watch-only", "windows-line-endings"}
_KUBECTL_SHORT_FLAGS = set("ARhiqtw")   # --all-namespaces, --recursive, --help, --stdin, --quiet, --tty, --watch


def _kubectl_takes(word):
    """Whether kubectl gives the word after `word` to it as its value: an option written without `=` that isn't one of
    its flags, or a short-option cluster whose first letter that takes a value ends the word (`-Rf`, not `-nprod`)."""
    if word.startswith("--"):
        return "=" not in word and word[2:] not in _KUBECTL_FLAGS
    if word.startswith("-") and "=" not in word:
        return next((k for k in range(1, len(word)) if word[k] not in _KUBECTL_SHORT_FLAGS), None) == len(word) - 1
    return False


# what a tool no pack maps is given to run (_runs): TK-S010's command arguments and the SQL ones, in any case
_COMMAND_KEYS = {"command", "commands", "cmd", "cmds", "script", "shell_command"}
_SQL_KEYS = {"sql", "query", "statement"}
_BLANKS = re.compile(r"\s+")   # any Unicode blank: a form feed, a vertical tab, a no-break or line separator space
_PLAIN_WORD = re.compile(r"[A-Za-z0-9_.:/-]*")   # a value that is one word of plain characters: no blank, quote,
# metacharacter, expansion or other character the shell reads


def _runs(args, tool=""):
    """The `run` field of a tool no pack maps: for each argument TK-S010 reads as a command (at any depth, its name in
    any case), `WORD:<its last /-part>` when it is one word of plain characters (letters, digits, `_ . : / -`), else
    `CMD:<value>` (a string as given, a list or an object as canonical JSON); `MCPCMD:<value>` for any value when the
    tool's name is an MCP tool's in a case no pack maps (`MCP:x/y`), as TK-S010 reads an MCP tool's; and for each string under a sql,
    query or statement argument (at any depth, its name in any case, in a list or an object too) each statement as
    every SQL dialect lexes it (classes.sql_read: comments and literals blanked), split at its `;`s, each blank run a
    space: `SQL;<statement>` for one a `;` ends, `SQL:<statement>` for the last; before a literal or comment that
    doesn't close, only those a `;` ends (a database may run them, then fails on the rest)."""
    out, tag = [], "MCPCMD:" if _text(tool).casefold().startswith(("mcp:", "mcp__")) else "CMD:"
    # a call over MAX_SUBJECT isn't lexed (every pack that reads `run` denies it unread: TK-OVERSIZE): its SQL is the
    # whole call as written, longer than MAX_SUBJECT, which every rule on it takes as TK-OVERSIZE
    whole = canonical(args)
    whole = "SQL:" + whole if len(whole) > MAX_SUBJECT else None

    def lex(text):
        for code, closed in dict.fromkeys(classes.sql_read(text, *d) for d in classes.SQL_DIALECTS.values()):
            *ended, last = _BLANKS.sub(" ", code).split(";")
            out.extend("SQL;" + p.strip() for p in ended if p.strip())
            if closed and last.strip():
                out.append("SQL:" + last.strip())

    def walk(value, sql=False, cmd=False):
        """`sql`, `cmd`: under a sql or command argument already read, so each string is lexed once (the keys of an
        object under a sql argument too) and a command argument's value is written out once, at the outermost."""
        if isinstance(value, str):
            if sql and not whole:
                lex(value)
            return
        items = value.items() if isinstance(value, dict) else enumerate(value) if isinstance(value, list) else ()
        for key, v in items:
            name = key.lower() if isinstance(key, str) else None
            if sql and not whole and name is not None:
                lex(key)
            if name in _COMMAND_KEYS and not cmd:
                plain = tag == "CMD:" and isinstance(v, str) and _PLAIN_WORD.fullmatch(v)
                out.append("WORD:" + v.rsplit("/", 1)[-1] if plain else tag + (v if isinstance(v, str) else canonical(v)))
                walk(v, sql, True)
            elif name in _SQL_KEYS and not sql:
                if whole:
                    out.append(whole)
                walk(v, True, cmd)
            else:
                walk(v, sql, cmd)
    walk(args)
    return list(dict.fromkeys(out))


def _program(argv):
    """The program an argv runs, by its file name, casefolded and without .exe."""
    return argv[0].replace("\\", "/").rsplit("/", 1)[-1].casefold().removesuffix(".exe") if argv else ""


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
    expansion builds may hold the path). A script the line writes, then runs, writes what its code does (the parser
    reads it as that inline code is: shell.read_file), and may write each word the run gives it, MAY_WRITE. A link ln
    or cp -s/-l makes is also MAY_WRITE: a later write through it writes the file it points at. Read once per parse
    (the `effects` field and _tracekit both read it): kept in what the parse learned."""
    learned = parsed[5] if len(parsed) > 5 else {}
    if "effects" not in learned:
        learned["effects"] = _write_effects(parsed)
    return learned["effects"]


def _write_effects(parsed):
    tags = ["WRITE_TARGET:" + _text(ref) for ref in parsed[3]] + _command_effects(parsed[0])
    tags += ["MAY_WRITE:" + w for c in parsed[0] for w in c.get("script_args", ())]
    unread = any(c["opaque"] for c in parsed[0])
    if any(_opaque(c) for c in parsed[0]) or unread and _reaches_unread(parsed):
        # lean: a read on the same line as such a writer counts as a write (as TK-D008 read the whole line before
        # #421); follow the names into the writer if that holds real reads
        tags += ["MAY_WRITE:" + w for c in parsed[0] for w in c["argv"][1:] + c["stdin"]]
        tags += ["MAY_WRITE:" + line for line in parsed[1] if unread]
    tags += [k + ":" + n for k, _, path in (t.partition(":") for t in tags)
             if k != "MAY_WRITE" and (n := _normal(path)) != path]
    # a pattern under ~ is also each folder of an agent's it may match (`rm -rf ~/.cla*` deletes ~/.claude)
    tags += [k + ":" + f for k, _, path in (t.partition(":") for t in tags)
             if k != "MAY_WRITE" and shell._GLOB.search(path) for f in _pattern_forms(path)]
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
    if not any(c["opaque"] and ("$" in c["word"] or "`" in c["word"]) for c in commands):
        return False
    values = [r for r in parsed[2] if shell._ASSIGN.match(r)] + [
        w for c in commands if c["argv"][0] in _SETS_VARIABLES or shell._sets_with_v(c["argv"])
        for w in c["argv"][1:] + c["stdin"]]
    return any(_WRITER.search(v.lower()) for v in values)


def _opaque(command):
    """Whether a command writes files _command_effects can't name: a writer whose operand is a variable or a
    substitution (rm "$f"), or zip -m reading its names from stdin (-@); xargs, parallel, a container's exec or ssh,
    or an interpreter running code with a write in it (xargs rm, parallel 'rm {}', docker exec c sh -c 'rm …',
    perl -e 'open F, ">", …'); at or batch scheduling commands from a pipe or a file (the parser reads a herestring
    or heredoc), or osascript's do shell script or a Finder delete."""
    argv = command["argv"]
    exe = argv[0].rsplit("/", 1)[-1].casefold()
    if exe in ("rm", "unlink", "shred", "truncate", "tee", "cp", "mv", "install", "ln"):
        return any("$" in a or "`" in a for a in argv[1:])
    if exe == "zip" and _zip_moves(argv[1:]):
        return any("$" in a or "`" in a or re.fullmatch(r"-[^-]*@[^-]*", a) for a in argv[1:])
    if exe in ("xargs", "parallel", "docker", "podman", "kubectl", "ssh") or \
            _INTERPRETER.fullmatch(exe):
        return any(_WRITE_WORD.search(a) for a in argv[1:])
    if exe in ("at", "batch"):   # at -l, -r, -d, -c and -V list, remove, show or print: they schedule nothing
        return not command["stdin"] and not any(a in ("-l", "-r", "-d", "-c", "-V") for a in argv[1:])
    if exe == "osascript":
        return any(_APPLESCRIPT_WRITE.search(a) for a in argv[1:] + command["stdin"])
    return False


_ZIP_MOVE = re.compile(r"-[^-bnPtZsOxi]*m[^-]*")
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
        elif a == "--move" or _ZIP_MOVE.fullmatch(a):   # an m before any option taking a value
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
        trust = _python_module(args) if _PYTHON_EXE.fullmatch(exe) else [exe, *args]
        if trust[:3] == ["tracekit", "signer", "trust"]:   # the trust config it writes (TK-D007's unless reads its line)
            # -o, -oPATH, -o=PATH, and --out as argparse takes it: any prefix from --o (--ou, --out=…, --ou=…),
            # whatever the installed CLI's abbreviation setting
            for a, w in zip(trust, trust[1:] + [""]):
                flag, eq, value = a.partition("=")
                if len(flag) > 2 and "--out".startswith(flag):
                    out.append("WRITE_TARGET:" + (value if eq else w))
                elif a.startswith("-o") and not a.startswith("--"):
                    out.append("WRITE_TARGET:" + (a[2:].removeprefix("=") or w))
            continue
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
        elif exe in ("gzip", "bzip2", "xz", "lzma", "lzip", "compress") and not any(
                a in ("-k", "--keep", "-c", "--stdout", "--to-stdout", "-t", "--test", "-l", "--list") or
                re.fullmatch(r"-[A-Za-z0-9]*[kctl][A-Za-z0-9]*", a) for a in args):
            # it replaces each file with its compressed copy, its content kept: one it may write (TK-D008 reads those)
            out.extend("MAY_WRITE:" + a for a in args if not a.startswith("-"))
        elif exe == "tar" and "--remove-files" in args or exe == "rsync" and "--remove-source-files" in args:
            # each file it adds (tar's operands but its archive and -C's directory; rsync's sources) it then deletes
            skip, operands = False, []
            for i, a in enumerate(args):
                if skip:
                    skip = False
                elif exe == "tar" and (a in ("-f", "--file", "-C", "--directory") or re.fullmatch(r"-[A-Za-z]*[fC]", a)):
                    skip = True
                elif not a.startswith("-") and not (exe == "tar" and i == 0 and re.fullmatch(r"[A-Za-z]+", a)):
                    operands.append(a)
            out.extend("DELETE_TARGET:" + a for a in (operands[:-1] if exe == "rsync" else operands))
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


# the options of a sed that only reads: any other (GNU's -i, BSD's -I, -f, a prefix of --in-place such as --in) may
# write or run what the line doesn't show
_SED_READ_OPTION = re.compile(r"-[nrsuzEe]+|--|--(?:quiet|silent|regexp-extended|expression|null-data|separate|"
                              r"unbuffered|posix|debug|sandbox)(?:=[\w\W]*)?")


def _reading(argv):
    """What a command does with the files it names, for TK-D007: "read" (a _PLAIN_READERS program: sed only with -n
    and a script that only prints, grep without -r), "deep" (grep -r: every file under a folder), "list" (a _LISTERS
    program: find without an action, -fprint, -fls or -files0-from; pgrep and ps naming no file), else None."""
    name, args = argv[0], argv[1:]
    if name == "sed":
        script = shell._sed_scripts(args)
        return "read" if "-n" in args and script is not None and shell._sed_prints(script) and all(
            _SED_READ_OPTION.fullmatch(a) for a in args if a.startswith("-") and a != "-") else None
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


# the SDK names that find the dev signer's data or start and stop it (tracekit.signer's own are _runs_signer's), the
# CLI's modules code may run it through, and the ones of its autospawn module code may use
_SDK = re.compile(r"\b(?:autospawn|dev_data_dir|data_dir_at|run_module|__main__)\b|\btracekit\.cli\b|\bimport\s+cli\b")
_SDK_READS = {"status", "Hung", "SignerUnavailable", "Incompatible"}
# where a Python comment or string literal may start, and the rest of each kind of literal: its text (a backslash
# escapes any character, a newline too) up to its closing quote, or to its line's end (the code's, triple-quoted)
_PY_OPEN = re.compile(r"#|(?<![\w])([rRbBuUfF]{0,2})(\"\"\"|'''|\"|')")
_PY_REST = {'"""': re.compile(r'(?:[^\\"]|\\[\s\S]|"(?!""))*(?:"""|\Z)'),
            "'''": re.compile(r"(?:[^\\']|\\[\s\S]|'(?!''))*(?:'''|\Z)"),
            '"': re.compile(r'(?:[^\\"\n]|\\[\s\S])*"?'), "'": re.compile(r"(?:[^\\'\n]|\\[\s\S])*'?")}


def _py_code(code):
    """Python code with each comment and string literal emptied ('' for a literal), in one pass left to right as the
    tokenizer reads them: a quote in a comment starts nothing, nor one in a literal. An f-string's text stays: the code
    in its braces runs."""
    out, i = [], 0
    while m := _PY_OPEN.search(code, i):
        out.append(code[i:m.start()])
        if m.group() == "#":
            nl = code.find("\n", m.end())
            i = len(code) if nl < 0 else nl
            continue
        rest = _PY_REST[m.group(2)].match(code, m.end())
        out.append(rest.group() if "f" in m.group(1).lower() else "''")
        i = rest.end()
    return "".join(out) + code[i:]


_SDK_PATH = re.compile(r"\b(?:dev_data_dir|data_dir_at)\b")


def _reaches_sdk(code, work):
    """Whether code reaches the dev signer's data dir or lifecycle through Tracekit's SDK: dev_data_dir or data_dir_at
    imported, called or read as an attribute; autospawn (tracekit.sdk's, or another module's import of it) used for more
    than _SDK_READS, used bare, or with a name looked up at run time. Outside comments and string literals (_py_code),
    but for that look-up: a string a spawner runs is the parser's command, with its own subject (an edit script's text
    is no call). Linear in the code but for each name autospawn is imported as, which reads it again (charged to
    `work`, shell.charge).
    The CLI reached from code (tracekit.__main__ imported, tracekit.cli's main called, runpy.run_module('tracekit'))
    runs what its argv says: it reaches the lifecycle where the argv is built at run time or a literal in the code
    names down, uninstall, up or signer (`main(['down'])`; not `sys.argv = ['tracekit', '--version']`).
    lean: a string run by another runner (timeit, pdb.run) isn't read; read strings too if an agent uses one."""
    if _PY_LOOKUP.search(code) and re.search(r"(?<!/)\bautospawn\b(?!\.py)", code):
        return True
    raw, code = code, _py_code(code)
    if (re.search(r"\b(?:import|from)\s+tracekit\.__main__\b|\bfrom\s+tracekit\s+import\s+[\w\s,()]*?\b__main__\b",
                  code) or re.search(r"\bmain\s*\(", code) and re.search(
                      r"\b(?:import|from)\s+tracekit\.cli\b|\bfrom\s+tracekit\s+import\s+[\w\s,()]*?\bcli\b", code) or
            re.search(r"\brun_module\s*\(\s*(?:\w+\s*=\s*)?['\"]tracekit(?:\.cli|\.__main__)?['\"]", raw)) and (
            re.search(r"['\"](?:down|uninstall|up|signer)['\"]", raw) or
            re.search(r"\bsys\.argv\s*(?:\[[^]\n]*\])?\s*[+]?=(?!\s*\[)|\bmain\s*\((?!\s*[\[)])", code)):
        return True
    if _SDK_PATH.search(code) and (
            re.search(r"\.\s*(?:dev_data_dir|data_dir_at)\b|\b(?:dev_data_dir|data_dir_at)\s*\(", code) or any(
                (i := re.search(r"\bimport\b", run.group())) and _SDK_PATH.search(run.group(), i.end())
                for run in re.finditer(r"[\w\s,()*.]+", code))):   # an import's names: one run of these characters
        return True
    # autospawn reached as an attribute (but in an import's module path) for more than _SDK_READS, or kept bare in code
    # that imports Tracekit (`m = tracekit.sdk.autospawn; m.down()`; a sed script's text isn't such code)
    imports = re.search(r"\b(?:import|from)\s+tracekit\b", code)
    if any(m.group(1) not in _SDK_READS and (m.group(1) or imports) and not re.search(
            r"\b(?:import|from)\s+[\w.]*\Z", code[max(0, m.start() - 80):m.start()])
           for m in re.finditer(r"\.\s*autospawn\b(?:\s*\.\s*(\w+))?", code)):
        return True
    aliases = re.findall(r"\bimport\s+tracekit\.sdk\.autospawn\s+as\s+(\w+)", code)
    for module, listed, names in re.findall(r"\bfrom\s+(tracekit[\w.]*)\s+import\s+(?:\(([^()]*)\)|([\w \t,*]+))",
                                            code):
        for item in (listed or names).replace("\n", " ").split(","):
            name, _, alias = (x.strip() for x in item.partition(" as "))
            if module == "tracekit.sdk.autospawn" and name and (alias or name not in _SDK_READS):
                return True
            if name == "autospawn" or name == "*" and module == "tracekit.sdk":   # (a star import names it)
                aliases.append(alias or "autospawn")
    for alias in dict.fromkeys(aliases):
        shell.charge(work, len(code))
        uses = re.findall(r"(?<![\w.])%s\b(\.\w+)?" % re.escape(alias), code)
        if any(u and u[1:] not in _SDK_READS for u in uses) or uses.count("") > 1:   # the import names it
            return True
    return False


# the signer's command lines, as pgrep -f and ps show them: the dev signer autospawn starts (sdk.autospawn.SIGNER_ARGV:
# its client's sys.executable, a full path, often a venv's `python`, and -P), the system one, a module run; and its
# process names, as pgrep, pidof and killall match them
_DEV_SIGNER = "-P -m tracekit signer serve --dev"
_SIGNER_LINES = tuple(f"{python} {_DEV_SIGNER}" for python in (
    "/usr/bin/python3", "/opt/homebrew/bin/python3.12", "/Users/u/project/.venv/bin/python", "/home/u/venv/bin/python",
    "python3", "python")) + ("tracekit signer serve --config /etc/tracekit/signer.yaml", "python3 -m tracekit.signer",
                             "python3 -m tracekit.daemon", "tracekitd")
_SIGNER_NAMES = ("python", "python3", "python3.12", "Python", "tracekit", "tracekitd")
_SIGNER_NAME = re.compile(r"[Pp]ython[0-9.]*|tracekitd?")
_EXPANDS = re.compile(r"\$[\w({]|`")   # a word the shell builds at run time
# the options that take a value: pgrep's, pkill's, killall's and pidof's; grep's
_FINDER_VALUED = {"-d", "-g", "-G", "-P", "-s", "-t", "-u", "-U", "-F", "--signal", "--parent", "--uid", "--euid",
                  "--group", "--pidfile", "--session", "--terminal", "--delimiter", "--ns", "--user"}
_GREP_VALUED = {"-e", "--regexp", "-f", "--file", "-m", "--max-count", "-A", "-B", "-C", "--context"}


def _finder(args, valued=_FINDER_VALUED):
    """(the one-letter options a pgrep, pkill, killall, pidof or grep gives, its patterns: grep's -e values and the
    words no option takes; a signal such as -9 or -TERM is no option here)."""
    flags, patterns, i = "", [], 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return flags, patterns + args[i + 1:]
        if a in ("-e", "--regexp") and valued is _GREP_VALUED and i + 1 < len(args):
            patterns.append(args[i + 1])
        elif a.startswith("--"):
            flags += {"--full": "f", "--exact": "x", "--ignore-case": "i", "--fixed-strings": "F",
                      "--invert-match": "v", "--regex": "r"}.get(a, "")
        elif a.startswith("-") and len(a) > 1 and not (a[1:].isdigit() or a[1:].isupper() and a not in valued):
            flags += a[1:]
        elif not a.startswith("-"):
            patterns.append(a)
        i += 2 if a in valued else 1
    return flags, patterns


def _finds(pattern, flags, texts, finds):
    """Whether a finder's pattern (an extended regex; a fixed string with F; whole with x) matches one of `texts`,
    through decide's `finds` (Engine.decide: never Python's re, which an agent's `(.*)*Z` holds for minutes); one the
    line builds at run time (an expansion) may match anything. GNU's word edges \\< and \\> read as \\b, a basic
    regex's \\| as |."""
    if _EXPANDS.search(pattern):
        return True
    if "F" in flags:
        key = str.casefold if "i" in flags else str
        return any(key(pattern) == key(t) if "x" in flags else key(pattern) in key(t) for t in texts)
    pattern = re.sub(r"\\(.)", lambda m: {"<": r"\b", ">": r"\b", "|": "|"}.get(m.group(1), m.group()), pattern,
                     flags=re.S)
    return finds(pattern, "i" in flags, "x" in flags, texts)


def _kills_signer(commands, finds):
    """The signer a line may stop by what finds it, as `kill <its command line>` (TK-D007's kill), once: a pkill or a
    killall whose pattern or name matches it, or a kill given pids at run time (a substitution, a variable, xargs)
    on a line where pgrep or pidof matches it, or ps does by name (-C) or through each grep and awk after it in its
    pipeline (a grep -v drops nothing here; awk's regexes and strings are its patterns). Matched against the signer's
    command lines with pgrep -f, else its names; pidof and killall match a whole name (killall -r and -m a regex).
    Each pipeline is read once, from its last stage: what follows a ps is folded in as the stages are passed.
    lean: a ps with no -C, grep or awk, and grep's basic-regex groups, aren't read; read them if one is used."""
    killer = any(c["argv"][0] == "kill" and (c["via"][-1:] in (["xargs"], ["parallel"]) or any(
        "$" in a or "`" in a for a in c["argv"][1:])) for c in commands)
    # a kill of every process the user may signal (pid -1: `kill -9 -1`, `kill -s KILL -1`, `kill -- -1`)
    for c in commands:
        args = c["argv"][1:]
        if c["argv"][0] == "kill" and "-1" in args[1 + (args[:1] in (["-s"], ["-n"])):]:   # (after its signal)
            return ["kill " + _SIGNER_LINES[0]]
    for c in commands:
        name, args = c["argv"][0], c["argv"][1:]
        if name in ("pkill", "killall") or killer and name in ("pgrep", "pidof"):
            flags, patterns = _finder(args)
            if name in ("pidof", "killall") and not {"r", "m"} & set(flags):
                found = any(_EXPANDS.search(p) or _SIGNER_NAME.fullmatch(p) for p in patterns)
            else:
                found = any(_finds(p, flags, _SIGNER_LINES if "f" in flags and name in ("pkill", "pgrep") else
                                   _SIGNER_NAMES, finds) for p in patterns)
            if found:
                return ["kill " + _SIGNER_LINES[0]]
    if not killer or not any(c["argv"][0] == "ps" for c in commands):
        return []
    pipelines = {}
    for c in commands:
        pipelines.setdefault(c["pipeline"], {}).setdefault(c.get("stage", 0), []).append(c)
    for stages in pipelines.values():
        # for each signer line, whether every grep after here (but -v) and every awk with patterns matches it, and
        # whether one of them is there at all
        greps, awks, filtered = [True] * len(_SIGNER_LINES), [True] * len(_SIGNER_LINES), False
        for stage in sorted(stages, reverse=True):
            for c in stages[stage]:
                if c["argv"][0] != "ps":
                    continue
                named = [p for a, v in zip(c["argv"][1:], c["argv"][2:]) if a == "-C" for p in v.split(",")]
                if any(_EXPANDS.search(p) or _SIGNER_NAME.fullmatch(p) for p in named) or filtered and any(
                        g and a for g, a in zip(greps, awks)):
                    return ["kill " + _SIGNER_LINES[0]]
            for c in stages[stage]:
                if c["argv"][0] in ("grep", "egrep", "fgrep", "rg"):
                    f, ps = _finder(c["argv"][1:], _GREP_VALUED)
                    filtered = True
                    if "v" not in f:
                        greps = [g and all(_finds(p, f, [s], finds) for p in ps[:1]) for g, s in zip(greps, _SIGNER_LINES)]
                elif shell._kind(c["argv"][0]) == "awk":
                    ps = [a or b for a, b in re.findall(r'/((?:\\.|[^/\\\n])+)/|"((?:\\.|[^"\\\n])+)"',
                                                        shell._awk_program(c["argv"][1:]) or "")]
                    if ps:
                        filtered = True
                        awks = [a and any(_finds(p, "", [s], finds) for p in ps) for a, s in zip(awks, _SIGNER_LINES)]
    return []


def _bases(commands, work, cdpath=()):
    """The folders a cd or pushd on the line enters (a relative one read from the one before it, and from each folder
    of a CDPATH the line sets), and each one `env -C`, `tar -C`, `git -C` or `make -C` runs in: where a relative path
    may land. Each once, charged to `work` (shell.charge)."""
    out, base = [], None
    for c in commands:
        argv = c["argv"]
        if argv[0] in ("cd", "pushd"):
            to = next((a for a in argv[1:] if not a.startswith("-") or a == "-"), "~")
            out += [posixpath.normpath(posixpath.join(p, to)) for p in cdpath if to[:1] not in ("/", "~", "$", "-")]
        elif argv[0] in ("env", "tar", "git", "make"):
            to = next((argv[i + 1] if a in ("-C", "--chdir", "--directory") else a.partition("=")[2] or a[2:]
                       for i, a in enumerate(argv[:-1]) if a in ("-C", "--chdir", "--directory") or
                       a.startswith(("--chdir=", "--directory=")) or a.startswith("-C") and argv[0] != "env"), None)
        else:
            continue
        if to and to.startswith(("/", "~", "$")):
            base = to
        elif to and to != "-" and base:
            base = posixpath.normpath(posixpath.join(base, to))
        else:
            continue
        shell.charge(work, len(base))
        out.append(base)
    return list(dict.fromkeys(out))


# a component of one of Tracekit's paths (TK-D007's) that a pattern in a word may stand for: `trace?it`, `*`
_COMPONENTS = ("tracekit", "Application Support", "Library", "tracekit-signer", ".tracekit-signer", ".tracekit-client",
               ".local", "share", "lib", "data", "keys", "run", "site-packages", "dist-packages",
               ".claude", ".codex", ".gemini")   # (and TK-D008's agents' folders under ~: _effects)


# the component of a Tracekit path a bare pattern under each of these stands for (`Application Support/*`)
_UNDER = {"Application Support": "tracekit", "Library": "Application Support", "share": "tracekit",
          "lib": "tracekit-signer"}


def _pattern_forms(path):
    """A path with a pattern in a component under a folder of _UNDER or ~, each such component read in turn as each of
    _COMPONENTS it matches when it has letters of its own (`trace?it`, `*Support`, `.trace*`), else as the one _UNDER
    names; one elsewhere (`./src/*`, `./*tracekit*`, a repo's `tracekit/**`) isn't Tracekit's."""
    parts, out = path.split("/"), []
    for i, p in enumerate(parts):
        if shell._GLOB.search(p) and i and (parts[i - 1] in _UNDER or parts[i - 1] == "~"):
            names = _COMPONENTS if len(re.sub(r"[*?]|\[[^]]*\]", "", p)) > 1 else [_UNDER.get(parts[i - 1], "")]
            out += ["/".join(parts[:i] + [n] + parts[i + 1:]) for n in names if fnmatch.fnmatchcase(n, p)]
    return out


# a for or select loop's words, in a normalised line: what its variable takes
_LOOP = re.compile(r"(?:^|[;&|(]\s*|\b(?:do|then|else)\s+)(?:for|select)\s+[A-Za-z_]\w*\s+in\s+"
                   r"(.+?)\s*(?:;|\n|\s+do\b|$)")


_OPTION = re.compile(r"-[^/=]*")   # an option, not a path or an assignment (_tracekit's named words)
_PYTHON_EXE = re.compile(r"(?:pyw?|pypy|pythonw?)[0-9.]*t?")


def _tracekit(parsed, finds, work):
    """What a shell call does to Tracekit itself (TK-D007), each as a tagged subject. ACT: what a command acts on or
    runs, its words joined (but data words), its stdin, the files redirections write, _effects' files, the other words
    that name something (assignments, heredoc programs). READ, DEEP and LIST: one subject per word a command that only
    reads names (_reading; the pack's `unless` names the files a READ may name under Tracekit's dirs): DEEP for a
    recursive read, a pattern, a reader whose output goes on to a file, a substitution or anything but a filter
    (`find … > l; xargs cat < l`, `cat $(find …)`, `find … | while read f`), and the folder a cd, pushd or popd enters
    where every command only reads or lists and no redirection writes (else the cd is ACT); a file a redirection
    reads is READ, an assignment the line uses only in readers (_private) LIST. A loop's words count as the words of
    its commands (DEEP where every command only reads or lists, else ACT), a relative word also as read from each
    folder a cd on the line enters (_bases), and a kill of what finds the signer as acting on it (_kills_signer).
    SIGNER_MODULE: an ACT text whose code reaches more of Tracekit's signer than it may read (_runs_signer), or its
    data or lifecycle through the SDK (_reaches_sdk). Each also normalised and casefolded as a path is (_path_forms).
    `work`: the decision's budget, which this reading spends (shell.charge)."""
    commands, refs, written = parsed[0], parsed[2], set(parsed[3])
    learned = parsed[5] if len(parsed) > 5 else None
    kinds = [_reading(c["argv"]) for c in commands]
    roams = not written and all(k or c["argv"][0] in _NAVIGATE for c, k in zip(commands, kinds))
    feeding = {}   # pipeline -> the last stage of a command in it that does more than filter
    for c in commands:
        if c["argv"][0] not in _FILTERS:
            feeding[c["pipeline"]] = max(feeding.get(c["pipeline"], -1), c.get("stage", 0))
    # what a line sets that moves its paths: HOME (~ and a bare cd), CDPATH (a relative cd), a link (ln -s) to a folder
    homes = [r.partition("=")[2] for r in refs if r.startswith("HOME=")]
    bases = _bases(commands, work, [p for r in refs if r.startswith("CDPATH=") for p in r[7:].split(":") if p])
    links = {c["argv"][-1].rstrip("/"): c["argv"][-2] for c in commands if c["argv"][0] == "ln" and len(c["argv"]) > 2
             and any(re.fullmatch(r"-\w*s\w*|--symbolic", a) for a in c["argv"][1:])}

    def at(names):   # each name, as read from the folders the line enters, through HOME, a link or a pattern it may be
        out, joined = list(names), "".join(names)   # (a pattern holds a *, ? or [)
        for n in dict.fromkeys(names) if bases or homes or links or ("*" in joined or "?" in joined or "[" in joined) and \
                any(map(shell._GLOB.search, names)) else ():
            if not n or "://" in n:
                continue
            more = [posixpath.normpath(posixpath.join(b, n)) for b in bases if n[0] not in "/~$-"]
            more += [h + m[1:] for m in [n, *more] if m[:1] == "~" for h in homes]
            more += [t + m[len(k):] for m in [n, *more] for k, t in links.items() if m.startswith(k + "/")]
            more += [f for m in [n, *more] for f in _pattern_forms(m)]
            shell.charge(work, sum(map(len, more)))
            out += more
        return out
    act, listed, read, deep = _kills_signer(commands, finds), [], [], []
    for c, kind in zip(commands, kinds):
        data = shell.data_words(c["argv"]) | set(c.get("data_words", ()))
        words = [a for i, a in enumerate(c["argv"]) if i not in data]
        named = [a for a in words[1:] if not _OPTION.fullmatch(a)]
        if c["argv"][0] == "find":   # what find names: each pattern of -path or -name, under each folder it starts at
            starts = list(itertools.takewhile(lambda a: not a.startswith(("-", "(", "!")), c["argv"][1:]))
            named += [posixpath.join(s, p) for a, p in zip(c["argv"], c["argv"][1:])
                      if a in ("-path", "-wholename", "-ipath", "-iwholename", "-name", "-iname") for s in starts]
        feeds = feeding.get(c["pipeline"], -1) > c.get("stage", 0) or \
            bool({"$()", "``", "<()"} & set(c["via"])) or bool(c.get("out"))
        if c["argv"][0] in _NAVIGATE:
            if roams:
                deep += at(named)
            else:
                act += [" ".join(words)] + at(named)
        elif kind is None:
            act += [" ".join(words)] + at(named)[len(named):]
        else:
            {"read": read, "list": listed, "deep": deep}["deep" if feeds or c["glob"] else kind].extend(at(named))
        act += [] if c.get("data_stdin") else c["stdin"]
    # a loop over literal words is read in its body already (shell.py knows the variable's values there)
    loops = [h for line in parsed[1] for h in _LOOP.findall(line) if re.search(r"[$`*?[]", h)]
    (deep if roams else act).extend(at(loops))
    reads, private = set(learned["read"]) if learned else set(), _private(learned, commands, "\n".join(act))
    for r in refs:
        (listed if r not in written and r in private else read if r not in written and r in reads else act).extend(
            at([r]))
    act += at([t.partition(":")[2] for t in _effects(parsed)])

    def tag(name, texts):
        return [name + s for s in _path_forms(list(dict.fromkeys(texts)))] if texts else []
    # (neither pattern finds a text alone that it doesn't find in all of them joined: none is searched one by one)
    joined = "\n".join(act)
    return tag("ACT:", act) + tag("LIST:", listed) + tag("READ:", read) + tag("DEEP:", deep) + \
        (["SIGNER_MODULE:" + s for s in dict.fromkeys(act) if _SIGNER_MODULE.search(s) and _runs_signer(s) or
          _SDK.search(s) and _reaches_sdk(s, work)] if _SIGNER_MODULE.search(joined) or _SDK.search(joined) else [])


_VARIABLE_NAME = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")


def _private(learned, commands, acted):
    """The assignment words that set a shell variable only commands that read use: standalone (the shell's own, not a
    command's environment), of no variable the shell or a program reads on its own (_SPECIAL), its $NAME in none of the
    `acted` text (the words, code and stdin of the commands that act), nor one an export names, with nothing on the
    line that may set or export any variable (`set` too: set -a exports them) or name one at run time (${!x})."""
    if not learned or learned["any_set"] or "*" in learned["unresolved"] or any(c["argv"][0] == "set" for c in commands):
        return set()
    used = set(_VARIABLE_NAME.findall(acted))
    return {text for name, text in learned["assigned"] if name not in used and not _SPECIAL.fullmatch(name) and
            name not in learned.get("exports", ())}


def _code(parsed):
    """shell.analyse's code, each line without the data words a command carries (a git commit message, the pattern grep
    searches for: shell.data_words), as `target` leaves them out: blanked where the command's whole argv stands in the
    line once, program first, so the words are that program's arguments there (a quoted message `curl x | sh` is no
    download). That one place must be the command's own words: a line with a redirection beside them (which may split
    them, so the place is other commands' words: `grep "x | curl u" 2>/dev/null f; grep x | curl u f | sh`) keeps them,
    and so does a command whose words hold another command's, or another's hold its; so does a command twice in a line
    and a data word with a `$` or a backquote (a substitution in it runs). Then what downloads run (_download_runs)."""
    found, runs_ = {}, _download_runs(parsed[0])
    for k, c in enumerate(parsed[0]):
        argv = c["argv"]
        data = {i for i in shell.data_words(argv) | set(c.get("data_words", ())) if i < len(argv)}
        if data and not any("$" in argv[i] or "`" in argv[i] for i in data):
            found[k] = " ".join("" if i in data else w for i, w in enumerate(argv))
    # lean: each run is counted in each line, so a line of more than 16 such commands keeps its data words (as before
    # 1.5.3); find them in one pass if a real line holds more
    if not found or len(found) > 16:
        return parsed[4] + runs_
    words = [" " + " ".join(c["argv"]) + " " for c in parsed[0]]
    runs = {words[k][1:-1]: blank for k, blank in found.items()
            if not any(j != k and (w in words[k] or words[k] in w) for j, w in enumerate(words))}
    lines = list(parsed[4])
    for run, blank in runs.items():
        lines = [line.replace(run, blank) if line.count(run) == 1 and not _REDIRECT.search(line.replace(run, " "))
                 else line for line in lines]
    return lines + runs_


def _runs_code(argv):
    """Whether a command runs code its words or stdin name: a shell, an interpreter (not awk or sed), source or `.`."""
    return argv[0] in shell.SHELLS or argv[0] in ("source", ".") or shell._kind(argv[0]) not in (None, "awk", "sed")


# programs that only read, print, check or reformat their input (a pager, a hash, a filter, jq's language)
_DATA_ONLY = {"jq", "yq", "gojq", "jaq", "grep", "egrep", "fgrep", "zgrep", "rg", "ag", "tee", "cat", "less", "more",
              "most", "bat", "head", "tail", "wc", "sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum",
              "shasum", "md5sum", "md5", "b2sum", "cksum", "sort", "uniq", "cut", "tr", "column", "nl", "fold", "fmt",
              "od", "xxd", "hexdump", "base64", "strings", "file", "diff", "cmp", "comm", "paste", "rev", "tac",
              "gunzip", "zcat", "gzip", "bzip2", "bunzip2", "xz", "unxz", "zstd", "unzstd", "xmllint", "pbcopy",
              "wl-copy", "xclip", "true", ":", "read", "mapfile", "readarray", "awk", "gawk", "mawk", "nawk", "sed",
              "gsed", "iconv", "dos2unix", "pv", "ts", "jless", "fx", "html2text", "openssl", "echo", "printf"}


def _may_run_input(argv):
    """Whether a program a download is piped into may run what it reads: a shell or interpreter reading its code from
    stdin, or any program not known to read only data (_DATA_ONLY; tar only listing). awk's and sed's code is read
    on its own (TK-D002's system(), the parser's sed e), and so is what a wrapper or runner runs (env, nice, xargs:
    the parser gives it as a command of its own)."""
    name, args = argv[0], argv[1:]
    if name in shell.WRAPPERS or name in shell.RUNNERS and args[:1] and args[0] in shell.RUNNERS[name][0]:
        return False
    if name in shell.SHELLS:
        return shell._shell_mode(args)[0] == "stdin"
    if (kind := shell._kind(name)) and kind not in ("awk", "sed"):
        return shell._reads_stdin(kind, args)
    if name in ("tar", "gtar", "bsdtar"):
        return not any(a == "--list" or re.fullmatch(r"-?[A-Za-z]*t[A-Za-z]*", a) for a in args[:1] + [
            a for a in args if a.startswith("-") and not a.startswith("--")])
    return name not in _DATA_ONLY


def _download_runs(commands):
    """What a line's downloads run, in the spelling TK-D002 and TK-A046 judge: a download a process substitution feeds
    to a shell, an interpreter or source, as a file it names or its stdin (`python3 <(curl u)`, `python3 < <(curl u)`),
    is that download piped into it (`curl | python3 /dev/stdin`, `curl | python3`; source's or .'s, `curl | sh`); so is
    one whose output goes into a process substitution that runs code (`curl u > >(sh)`, `curl -o >(python3 -) u`). A
    download that saves a file (_saves) from a host other than this machine (not a health check), and a command
    anywhere on the line outside its pipeline (before it too: a background job, a FIFO, a trap, a loop's next turn)
    that runs what it saved, is `curl ; sh <it>`: run by its path or name where that is a saved file's or the URL's
    name, or any path with a name the server picks (-J, -K); a shell, interpreter or source given one as a word or a
    redirection, or naming one in its inline code."""
    out, host = [], {}   # each URL's host, read once: a line's readings repeat its words
    for d in commands:
        tool = d["argv"][0]
        if tool not in ("curl", "wget"):
            continue
        # a later stage of its pipeline that may run what it reads: any program but one known to read only data
        # (_DATA_ONLY, tar listing), a shell or an interpreter that reads its code from stdin; one given its code
        # (-c, a script) is TK-A046's
        for c in commands:
            if c["pipeline"] == d["pipeline"] and c.get("stage", 0) > d.get("stage", 0) and _may_run_input(c["argv"]):
                out.append(f"{tool} | sh")
                break
        if "<()" in d["via"]:
            for c in commands:
                subs = [w for w in c["argv"][1:] + list(c.get("in", ())) if w.startswith("<(")]
                if subs and _runs_code(c["argv"]):
                    out += [f"{tool} | " + ("sh" if c["argv"][0] in ("source", ".") else
                                            shlex.join(["/dev/stdin" if w == s else w for w in c["argv"]])) for s in subs]
            continue
        saved = _saves(d, commands)
        if any(t.startswith(">(") for t in saved):
            out += [f"{tool} | " + shlex.join(c["argv"]) for c in commands if ">()" in c["via"] and _runs_code(c["argv"])]
        hosts = {host[u] if u in host else host.setdefault(u, classes.url_info(u).get("host") or "")
                 for u in _URL.findall(" ".join(d["argv"][1:]))}
        if not saved or hosts and all(h == "localhost" or h.startswith(("127.", "[::1]", "::1")) for h in hosts):
            continue
        names = {posixpath.basename(w) for w in d["argv"][1:] + saved} - {""}
        anyname = tool == "curl" and any(re.fullmatch(r"--remote-header-name|--config|-[A-Za-z]*[JK][A-Za-z]*", a)
                                         for a in d["argv"][1:])

        def runs(c):
            given = c["argv"][1:] + list(c.get("in", ()))
            return posixpath.basename(c["word"]) in names or anyname and "/" in c["word"] or _runs_code(c["argv"]) and (
                anyname and given or any(posixpath.basename(w) in names or re.search(
                    r"(?<![\w.-])(?:%s)(?![\w-])" % "|".join(map(re.escape, names)), w) for w in given))
        out += [f"{tool} ; sh {c['word']}" for c in commands if c["pipeline"] != d["pipeline"] and runs(c)]
    return out


_NOWHERE = ("-", "/dev/null", "/dev/stdout", "/dev/stderr")


_CURL_OUTPUT = re.compile(r"--output(?:=(.*))?|-[A-Za-z]*?o(.*)")
_WGET_OUTPUT = re.compile(r"--output-document(?:=(.*))?|-[A-Za-z]*?O(.*)")
_CURL_NAMED = re.compile(r"--remote-name(?:-all)?|--remote-header-name|--config|-[A-Za-z]*[OJK][A-Za-z]*")


def _saves(d, commands):
    """The files a download writes: curl's -o or --output, or its URL's name with -O, -J or --remote-name (or any, with
    a config file's options: -K); wget's -O or --output-document, else its URL's name (not with --spider); a
    redirection or tee in its pipeline. Not stdout or /dev/null (a link check)."""
    curl, args = d["argv"][0] == "curl", d["argv"][1:]
    out = [t for c in commands if c["pipeline"] == d["pipeline"]
           for t in list(c.get("out", ())) + (c["argv"][1:] if c["argv"][0] == "tee" else [])]
    named = not curl and "--spider" not in args
    option = _CURL_OUTPUT if curl else _WGET_OUTPUT
    for a, value in zip(args, args[1:] + [""]):
        if m := option.fullmatch(a):
            out.append(next((g for g in m.groups() if g), value))
            named = named and curl
        elif curl and _CURL_NAMED.fullmatch(a):
            named = True
    return [t for t in out if t and t not in _NOWHERE and not t.startswith("-")] + [
        a for a in args if named and not a.startswith("-")]   # the URL, whose name it takes


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
    (_TAGGED); their casefolded forms, which the prefilters read (RE2 matching in any case folds a long s to s and the
    Kelvin sign to k, as casefold() does and lower() doesn't); those joined by a newline; whether one was longer). A
    rule matches the subjects before a long one and, matching none, takes TK-OVERSIZE, as one that walked them in
    order would."""
    texts = []
    for s in subjects:
        b = s if s.isascii() else s.encode("utf-8", "backslashreplace")   # ASCII is its own UTF-8
        if len(b) > MAX_SUBJECT + tag:
            break
        texts.append(s if b is s else b.decode("utf-8"))
    lows = [t.casefold() for t in texts]
    return texts, lows, "\n".join(lows), len(texts) < len(subjects)


def _text(s):
    """Lone surrogates (valid in JSON escapes, not in UTF-8) become \\udxxx text, the same for both engines."""
    return s.encode("utf-8", "backslashreplace").decode("utf-8")


def _spelling(name):
    """A tool name as CrewAI's sanitize_tool_name leaves it, without its `_`: accents dropped (NFKD, then ASCII),
    lower-cased, letters and digits only."""
    return re.sub(r"[^0-9a-z]", "", unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode().lower())
