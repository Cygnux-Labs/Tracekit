"""Policy v2 engine: deterministic matching over a compiled policy (design §4.2).

google-re2 when installed, else the `regex` module on the same pattern subset in ASCII mode (`compile.translate`).
Every decision names the engine (id@version) and the policy_hash. Precedence: deny > ask > flag > allow.
"""
import bisect
import collections
import fnmatch
import functools
import itertools
import json
import posixpath
import re
import shlex
import time
import unicodedata
from urllib.parse import unquote, urlsplit

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

    def decide(self, tool, args, cls=None, untrusted=None, _hidden=0, _budget=None, _pieces=True):
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
        (DECISION_COST each). Once it is spent nothing more is read, and the call is held (TK-SHELL-PARSE, budget).
        Loop values' own readings (shell's pieces, `_pieces`) are read last, in what the budget leaves: one that spends
        it holds the call as the line read without them decides it, never looser."""
        args = args if isinstance(args, dict) else {"value": args}
        cls = cls or self.tool_class(tool)
        if cls == "shell":
            args = classes.with_workdir(args)
        fields = classes.extract(cls, tool, args, MAX_SUBJECT)
        hits = {sec: [] for sec in SECTIONS}
        if cls == "unknown" and self.policy.get("unknown_tools") in SECTIONS:
            hits[self.policy["unknown_tools"]].append("TK-UNKNOWN-TOOL")
        if cls == "sql" and fields.get("statement") is not None and not fields.get("code"):
            hits["ask"].append("TK-SQL-PARSE")   # no dialect reads it: an unclosed literal or comment, or not text
        if cls == "a2a" and fields.get("unreadable"):
            hits["deny"].append("TK-A2A-NAME")   # a name with spellings its rules can't see (classes.a2a_fields)
        parsed, oversize, on_parse_error = ([], [], [], [], []), [], self.policy.get("on_parse_error", "ask")
        cause, pieces_read = None, False
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
                parsed, unread = self._parse(args, command, work, fallback=not _hidden, pieces=_pieces)
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
                elif parsed[5:] and parsed[5].get("pieces_cut"):   # loop values the budget left unread
                    hits[on_parse_error].append("TK-SHELL-PARSE")
                    cause = "budget"
                pieces_read = bool(parsed[5:] and parsed[5].get("pieces"))
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
            """The id a rule gives the call (its own, or TK-OVERSIZE when it matches none of the subjects it can read
            and one is over MAX_SUBJECT), else None; TimeoutError past the deadline."""
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
            parsed, memo = self._parse(args, command, work, readings=False, pieces=_pieces)[0], {}
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
                        tool, {"command": t}, "shell", untrusted, _hidden + 1, (work, deadline), _pieces)
                    nondeterministic |= bool(inner.get("nondeterministic"))
                    for rid in inner.get("rule_ids", ()):
                        if rid in self._deny_ids and rid not in hits["deny"] and rid not in hits["ask"]:
                            hits["deny" if nondeterministic else "ask"].append(rid)
                    if not inner.get("unparsed"):
                        break
                if nondeterministic or work[0] > shell.MAX_WORK:
                    break
        if (spent or work[0] > shell.MAX_WORK or len(parsed) > 5 and parsed[5].get("unread")) and \
                "TK-SHELL-PARSE" not in hits[on_parse_error]:
            hits[on_parse_error].append("TK-SHELL-PARSE")
            cause = cause or "budget"
        # a call over MAX_SUBJECT (its arguments as JSON), which the policy can't read, waits for a person (the dev pack),
        # not a deny; a smaller one whose reading makes a subject longer (a variable expanded several times, more URLs
        # than are read one by one) stays a deny, as the agent chose to make it so
        if self.policy.get("oversize") == "ask" and "TK-OVERSIZE" in hits["deny"] and \
                len(_text(canonical(args)).encode()) > MAX_SUBJECT:
            hits["deny"] = [i for i in hits["deny"] if i != "TK-OVERSIZE"]
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
        if (spent or work[0] > shell.MAX_WORK) and pieces_read and _budget is None:
            # the loop values' own readings left the rest of the reading no budget: held, and never looser than the
            # line read without them
            base = self.decide(tool, args, cls, untrusted, _hidden, None, False)
            out["verdict"] = max(out["verdict"], base["verdict"], key=("allow", *reversed(SECTIONS)).index)
            out["rule_ids"] = list(dict.fromkeys(base["rule_ids"] + out["rule_ids"]))
            out.update((k, base[k]) for k in ("nondeterministic", "oversize") if k in base and k not in out)
        return out

    def _parse(self, args, command, work, readings=True, fallback=True, pieces=True):
        """(shell.analyse() of a shell call, or what _plain() reads of one the parser can't read; why it can't, its
        ParseError's cause, else None). `readings`: False reads the command only as written (shell.analyse); `work`:
        the decision's budget (shell.charge), which _plain() spends too. `fallback`: False leaves _plain() out (None
        in its place), for a caller that only asks whether the command reads. A `commands` list is read joined, as one
        shell runs it (LangChain's ShellTool), and each entry on its own too, as its own shell runs it (OpenAI's shell
        tool, Cline's run_commands), where an open quote, a trailing \\ or a here-doc in one can't hide the next: the
        call is decided on what either reading finds. `pieces`: shell.analyse's."""
        parts = [self._parse_one(args, command, work, readings, fallback, pieces)]
        for c in commands_each(args):
            parts.append(self._parse_one({"command": c}, c, work, readings, fallback, pieces))
        return parts[0] if len(parts) == 1 else (None if any(p is None for p, _ in parts) else
                                                 joined_readings([p for p, _ in parts]),
                                                 next((c for _, c in parts if c), None))

    def _parse_one(self, args, command, work, readings=True, fallback=True, pieces=True):
        """_parse's reading of one shell call as written."""
        # a file a line writes text into, as written and resolved (_normal: C:\u\.bashrc is C:/u/.bashrc)
        target = (lambda t: any(p.search(_text(f.casefold())) for f in {t, _normal(t)}
                                for p in self._persistent_targets)) if self._persistent_targets else None
        start = work[0]
        try:
            return _shell(args, target, readings, work, pieces), None
        except shell.ParseError as e:
            if not fallback:
                return None, e.cause
            return (_plain(command, work, work[0] - start, getattr(e, "at", 0), readings, target, getattr(e, "cmds", ()))
                    if isinstance(command, str) else _plain(canonical(command), work, 0, 0, readings, target,
                                                            getattr(e, "cmds", ()))), e.cause

    @staticmethod
    def _subjects(cls, field, args, fields, parsed, split=False, finds=None, work=None, tool=""):
        """A class field matches the signer's extraction; any other field names a raw argument; no field scans the
        whole call (Write/Edit content, WebFetch url and prompt, MCP args). A shell `line` is the raw command and
        each line the parser normalised (each also with `\\` as `/`: _slashes), a shell `code` those without the
        text a command only writes into a file
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
            return _effects(parsed, work)
        if cls == "shell" and field == "tracekit":
            return _tracekit(parsed, finds, [0] if work is None else work)
        if cls == "shell" and field == "package_index":
            return _package_indexes(parsed[0], parsed[2])
        if cls == "shell" and field == "environment":
            return _environment_sent(parsed)
        if cls == "shell" and field == "harness_launch":
            return _harness_launches(parsed[0], parsed[2], parsed[5] if len(parsed) > 5 else {})
        if cls == "shell" and field == "gh_runs":
            return _gh_runs(parsed[0])
        if cls == "shell" and field == "container_host_access":
            return _container_host_access(parsed[0])
        if cls == "shell" and field == "push":
            return _pushes(parsed[0])
        if cls in ("unknown", "mcp") and field == "run":
            return _runs(args, tool)
        if cls == "sql" and field == "code":
            return fields.get("code", [])
        if cls == "shell" and field == "code":
            return _code(parsed, [0] if work is None else work)
        if cls == "shell" and field in (None, "argv"):
            # and each again with its words' own spaces as WORD_SPACE where a word before its last has one (the last
            # word's move no word after it: sqlite3's SQL is searched once), and with each word that is only a variable
            # the line gives no value there (shell's unresolved: not a loop's, nor one it knows) as UNKNOWN_WORD; each
            # also with `\` as `/` (_slashes), as a line is
            # and a harness a runner, a JavaScript runtime or python -m starts as `<harness> <its own words>`, the
            # identity TK-A070 reads (_harness), so a rule on `claude plugin …` reads `npx @anthropic-ai/claude-code
            # plugin …` and `node node_modules/.bin/claude plugin …` too
            unknown = (parsed[5] if len(parsed) > 5 else {}).get("unresolved", ())
            return _slashes(list(dict.fromkeys([" ".join(c["argv"]) for c in parsed[0]] + [
                h for c in parsed[0] if (h := _as_harness(c["argv"]))] + [
                " ".join(w.replace(" ", WORD_SPACE) for w in c["argv"]) for c in parsed[0]
                if " " in "".join(c["argv"][:-1])] + [
                " ".join(UNKNOWN_WORD if (m := _BARE_VARIABLE.fullmatch(w)) and m.group(1) in unknown else w
                         for w in c["argv"]) for c in parsed[0] if unknown and "$" in "".join(c["argv"])])))
        if cls == "shell" and field == "line":   # (and each publish as its program's: _published)
            return Engine._subjects(cls, "command", args, fields, parsed) + _slashes(parsed[1]) + list(dict.fromkeys(
                p for c in parsed[0] if (p := _published(c["argv"]))))
        if cls == "fs" and field == "ci_workflow" and isinstance(fields.get(field), str):   # and its wrappers unwrapped
            return list(dict.fromkeys([fields[field], *shell.unwrapped(fields[field])]))
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
        and heredoc programs, each also read as a path is (_path_forms: `\\` as `/`, as Windows reads one, and
        casefolded, as the agent's file system may ignore case: `cp x .ENV`
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


def _slashes(texts):
    """Texts of a shell call, each with a `\\` in it also read as `/`: a Windows path (Git Bash keeps a quoted or
    escaped `\\`, and C:\\x is C:/x, as classes.fs_path reads one). A second reading: it adds matches. The parser's
    texts hold a `\\` only where the shell keeps one; a line it can't read is read as written (_plain), so too."""
    more = [t.replace("\\", "/") for t in texts if "\\" in t]
    have = set(texts) if more else ()
    return texts + [n for n in dict.fromkeys(more) if n not in have]


def _path_forms(targets):
    """Targets, each also with `\\` as `/` (_slashes), as plainly written (/etc/./x, /etc//x and /etc/y/../x name
    /etc/x) and casefolded."""
    targets = _slashes(targets)
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


def _merged(dicts):
    """Dicts of lists (the names a line gives a value, with their values) as one."""
    out = {}
    for d in dicts:
        for k, v in d.items():
            out.setdefault(k, []).extend(v)
    return out


def joined_readings(parts):
    """Several readings of one shell call (_shell's or _plain's tuples) as one: their lists joined, and what else they
    learned (shell._learned) when every one has it."""
    out = [[x for p in parts for x in p[i]] for i in range(5)]
    if all(len(p) > 5 for p in parts):
        learned = [p[5] for p in parts]
        out.append({k: (any(d[k] for d in learned) if isinstance(learned[0][k], bool) else
                        set().union(*(d[k] for d in learned)) if isinstance(learned[0][k], set) else
                        _merged(d[k] for d in learned) if isinstance(learned[0][k], dict) else
                        [x for d in learned for x in d[k]]) for k in learned[0]})
    return tuple(out)


def _shell(args, persistent_target=None, readings=True, work=None, pieces=True):
    """shell.analyse() of a shell call: (commands, normalised lines, other words that name something, files
    redirections write, code). `command` or `cmd` is a command line or an argv list; `commands` (OpenAI's shell tool)
    a list of command lines. Anything else, or more than one of them, raises ParseError."""
    present = [k for k in classes.SHELL_KEYS if args.get(k) is not None]
    if len(present) > 1:
        raise shell.ParseError(f"more than one command field: {present}")
    value = args[present[0]] if present else ""
    strings = isinstance(value, list) and value and all(isinstance(a, str) for a in value)
    if isinstance(value, str):
        return shell.analyse(value, persistent_target, readings, work, pieces=pieces)
    if strings and present == ["commands"]:
        return shell.analyse("\n".join(value), persistent_target, readings, work, pieces=pieces)
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


# the agent harnesses' CLIs (a hook or plugin of Tracekit's runs in their settings), also under the name a package
# runner or an interpreter runs them by (npx @anthropic-ai/claude-code runs claude-code; node …/@openai/codex/…;
# python -m hermes_cli.main; hermes-agent; CodeBuddy Code's codebuddy-code, cbc and codebuddy-lowmem; python -m gptme
# and gptme's front ends, which load its plugins as it does)
_HARNESS_CLIS = frozenset(("claude", "codex", "gemini", "qwen", "opencode", "kilo", "kilocode", "goose", "droid", "agy",
                           "antigravity", "crush", "devin", "hermes", "cline", "openhands", "cursor-agent", "copilot",
                           "codebuddy", "gptme"))
_HARNESS_NAMES = {"claude-code": "claude", "gemini-cli": "gemini", "qwen-code": "qwen", "opencode-ai": "opencode",
                  "hermes-agent": "hermes", "hermes-acp": "hermes", "hermes_cli": "hermes",
                  "openhands-ai": "openhands", "codebuddy-code": "codebuddy", "cbc": "codebuddy",
                  "codebuddy-lowmem": "codebuddy", "gptme-tui": "gptme", "gptme-acp": "gptme", "gptme-server": "gptme"}
_HARNESS_PACKAGE = re.compile(r"(?<![\w.-])(?:@anthropic-ai/(claude-code)|@openai/(codex)|@google/(gemini-cli)|"
                              r"@qwen-code/(qwen-code)|(opencode-ai)|@kilocode/(cli)|(cline)|(hermes-agent)|"
                              r"@github/(copilot)|@tencent-ai/(codebuddy-code))(?:/|$)")
_JS_RUNTIMES = ("node", "nodejs", "bun", "deno", "tsx")
# what makes a harness read settings other than the person's, or none: HOME, XDG_CONFIG_HOME, Windows' APPDATA and
# LOCALAPPDATA (where a harness there keeps its settings), and each harness's own
# home, config, settings or data variable (CLAUDE_CONFIG_DIR, CODEX_HOME, HERMES_HOME, OPENCODE_CONFIG,
# OPENHANDS_WORK_DIR, GOOSE_PATH_ROOT, CRUSH_GLOBAL_DATA, COPILOT_HOME, CODEBUDDY_CONFIG_DIR, CLAUDE_CODE_SIMPLE, as
# --bare sets it; gptme has none of its own: ~/.config/gptme, or $XDG_CONFIG_HOME/gptme); an option that loads other
# settings or none (claude --settings, --setting-sources and --bare; --config, --profile, but not gptme's --profile,
# which profiles the run: _NOT_SETTINGS; copilot's --config-dir: _SETTINGS_OWN; codex's -p, and its -c only for a key
# of its hooks, notify, sandbox, approvals or profiles, read in its whole value (`-c 'features={hooks=false}'`): -c
# model_reasoning_effort=high is no such key, and codex's --disable of such a feature); hermes's -p
_SETTINGS_VARIABLE = re.compile(r"HOME|USERPROFILE|APPDATA|LOCALAPPDATA|XDG_CONFIG_HOME|"
                                r"(?:CLAUDE|CODEX|GEMINI|QWEN|OPENCODE|KILO|KILOCODE|GOOSE|FACTORY|DROID|ANTIGRAVITY|"
                                r"AGY|CRUSH|DEVIN|HERMES|CLINE|OPENHANDS|CURSOR|COPILOT|"
                                r"CODEBUDDY)_\w*(?:HOME|CONFIG|SETTING|DIR|PROFILE|SIMPLE|PLUGIN|PATH|ROOT|DATA)\w*",
                                re.I)
_SETTINGS_OPTION = re.compile(r"--(?:settings|setting-sources|config|profile)(?:=[\w\W]*)?|--bare")
_SETTINGS_SHORT = {"codex": ("-c", "-p"), "hermes": ("-p",)}
_SETTINGS_OWN = {"copilot": ("--config-dir",)}   # a long option one harness alone reads so (also as --x=value)
_NOT_SETTINGS = {"gptme": ("--profile",)}   # a _SETTINGS_OPTION a harness reads as no settings (in any form)
_SETTINGS_KEY = re.compile(r"(?<![^\W_])(?:hooks?|notify|sandbox|approvals?|profiles?)(?![^\W_])", re.I)
# the builtins that set a variable from their words (read's names, printf -v's, an assignment word)
_SETS_VARIABLE = ("env", "export", "declare", "typeset", "local", "readonly", "read", "printf", "mapfile",
                  "readarray")


def _harness(argv):
    """The harness CLI (_HARNESS_CLIS) an argv starts, by its name, a package's at any version (npx, bunx, pnpm dlx run
    one by it: claude-code@latest), a script under a harness package a JavaScript runtime runs (after any options:
    node -r x …/cli.js), or one it runs by the harness's name (node_modules/.bin/claude, `"$(which claude)"`), or a
    module python -m runs; else None."""
    name = re.sub(r"(?<=.)@[^@]*$", "", _program(argv))
    name = _HARNESS_NAMES.get(name, name)
    if name in _HARNESS_CLIS:
        return name
    if name in _JS_RUNTIMES:
        m = next(filter(None, (_HARNESS_PACKAGE.search(a.replace("\\", "/")) for a in argv[1:])), None)
        found = m and next(g for g in m.groups() if g)
        if found:
            return _HARNESS_NAMES.get(found, {"cli": "kilo"}.get(found, found))
        # the script it runs, as a harness installs one: its package's bin link (node_modules/.bin/claude) or the path a
        # name resolves to (`"$(which claude)"`); a file merely named for one (gemini.js) is none
        script = _js_script(argv) or ""
        located = shell.LOCATED_TEXT.fullmatch(script)
        name = located.group(1) if located else shell.base_name(script) if _BIN_LINK.search(script) else ""
        name = _HARNESS_NAMES.get(name, name)
        return name if name in _HARNESS_CLIS else None
    if _PYTHON_EXE.fullmatch(name):
        module = _python_module(argv[1:])[:1]
        return module and {"hermes_cli": "hermes", "gptme": "gptme"}.get(module[0].split(".")[0]) or None
    return None


_BIN_LINK = re.compile(r"(?:^|[/\\])node_modules[/\\]\.bin[/\\][^/\\]+$")   # a package's bin link
def _as_harness(argv):
    """`<harness> <its own words>` for a harness an argv starts under another name (a package's, at a version, a
    JavaScript runtime's script: _harness; python -m's module with its own options, as the packs read it), else
    None."""
    h = _harness(argv)
    name = re.sub(r"(?<=.)@[^@]*$", "", _program(argv))
    if not h or name == h:
        return None
    if name in _JS_RUNTIMES:
        script = _js_script(argv)
        rest = argv[argv.index(script, 1) + 1:] if script in argv[1:] else None
    else:
        rest = argv[1:]
    return None if rest is None else " ".join([h, *rest])


# a JavaScript runtime's options that take the next word (node's, then bun's, deno's and tsx's), and its subcommands
# before the script (deno run, bun run)
_JS_VALUED = frozenset((
    "-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions", "--env-file",
    "--env-file-if-exists", "--input-type", "--title", "--unhandled-rejections", "--disable-warning", "--inspect-port",
    "--debug-port", "--max-http-header-size", "--redirect-warnings", "--report-dir", "--report-directory",
    "--report-filename", "--report-signal", "--secure-heap", "--secure-heap-min", "--stack-trace-limit", "--stack-size",
    "--tls-cipher-list", "--tls-keylog", "--trace-event-categories", "--trace-event-file-pattern", "--watch-path",
    "--diagnostic-dir", "--dns-result-order", "--heapsnapshot-signal", "--heapsnapshot-near-heap-limit",
    "--icu-data-dir", "--openssl-config", "--cpu-prof-dir", "--cpu-prof-name", "--cpu-prof-interval", "--heap-prof-dir",
    "--heap-prof-name", "--heap-prof-interval", "--localstorage-file", "--experimental-sea-config", "--run",
    "--test-name-pattern", "--test-skip-pattern", "--test-reporter", "--test-reporter-destination",
    "--test-concurrency", "--test-shard", "--test-timeout", "--test-coverage-include", "--test-coverage-exclude",
    "--experimental-config-file", "--snapshot-blob", "--build-snapshot-config", "--policy-integrity",
    "--experimental-policy", "--network-family-autoselection-attempt-timeout", "--max-old-space-size",
    "--max-semi-space-size", "--use-largepages", "--watch-kill-signal", "--disable-proto", "--v8-pool-size",
    "--config", "-c", "--cwd", "--preload", "--define", "-d", "--loader", "-l", "--tsconfig-override", "--tsconfig",
    "--port", "--main-fields", "--location", "--seed", "--cert", "--lock", "--import-map"))
_JS_SUBCOMMANDS = ("run", "x", "exec", "watch")


def _js_script(argv):
    """The script a JavaScript runtime runs: its first word that is no option, an option's value or a subcommand; None
    for code it is given (-e, -p, --eval) or none."""
    skip = False
    for a in argv[1:]:
        if skip:
            skip = False
        elif a in ("-e", "--eval", "-p", "--print"):
            return None
        elif a in _JS_VALUED:
            skip = True
        elif not a.startswith("-") and a not in _JS_SUBCOMMANDS:
            return a
    return None


def _set_names(commands, refs, given=()):
    """The variables a line sets or unsets, in any way bash sets one: an assignment word (`X=`, `X+=`, before a command
    or alone, through env, export, declare, typeset, local or readonly), read's names, printf -v's and mapfile's, a
    loop's (`for HOME in …`, select; `given`: the names the parse saw given a value), let's, getopts's, unset's, a
    nameref's target (`declare -n r=HOME`) and a ${X:=word}'s."""
    words = [w for w in refs if re.match(r"[A-Za-z_]\w*\+?=", w)]
    names = set(given) | {n for c in commands for a in c["argv"] for n in re.findall(r"\$\{([A-Za-z_]\w*):?=", a)}
    for c in commands:
        argv = c["argv"]
        if argv[0] == "let":
            names.update(n for a in argv[1:] for n in re.findall(r"([A-Za-z_]\w*)\s*(?:[-+*/%^|&]|<<|>>)?=(?!=)", a))
        elif argv[0] == "getopts":
            names.update(argv[2:3])
        elif argv[0] == "unset":
            names.update(a for a in argv[1:] if not a.startswith("-"))
        elif argv[0] in ("declare", "typeset", "local") and any(re.fullmatch(r"-[a-zA-Z]*n[a-zA-Z]*", a)
                                                                  for a in argv[1:]):
            names.update(a.partition("=")[2] for a in argv[1:] if "=" in a)
        if argv[0] not in _SETS_VARIABLE:
            continue
        if argv[0] == "printf":
            words += [b for a, b in zip(argv, argv[1:]) if a == "-v"]
        elif argv[0] in ("read", "mapfile", "readarray"):
            words += [a for a, before in zip(argv[1:], argv) if not a.startswith("-") and before not in (
                "-p", "-d", "-n", "-N", "-t", "-u", "-i", "-C", "-c", "-O", "-s")]
        else:
            words += [a for a in argv[1:] if "=" in a]
    return names | {w.split("=", 1)[0].removesuffix("+") for w in words}


def _gh_runs(commands):
    """What gh runs that its own commands don't say, which TK-A084 holds (`GH: <words>`): an alias set or imported
    (`gh alias set m 'pr merge --admin'`; a --shell one runs a shell), an extension installed, upgraded, browsed for or
    run by exec, and a command that is none of gh's own (shell.GH_COMMANDS: an alias's or an extension's, a program of
    its own), and the editor, pager or browser it is set to run."""
    out = []
    for c in commands:
        argv = c["argv"]
        if argv[0] != "gh" or len(argv) < 2 or not argv[1] or argv[1].startswith("-"):   # (an empty word is none)
            continue
        sub, args = argv[1], argv[2:]
        if sub == "alias" and args[:1] in (["set"], ["import"]) or sub in ("extension", "ext", "extensions") and \
                args[:1] in (["install"], ["upgrade"], ["exec"], ["browse"]) or sub not in shell.GH_COMMANDS or \
                sub == "config" and args[:1] == ["set"] and {"editor", "pager", "browser"} & set(args[1:]):
            out.append("GH: " + " ".join(argv[1:3]))
    return out


def _harness_launches(commands, refs=(), learned=None):
    """`LAUNCH:<harness> <why>` for each harness CLI (_harness) the line starts with settings it chooses: a home or
    settings variable the line sets (_SETTINGS_VARIABLE, _set_names), an env that runs it clearing variables (-i) or
    unsetting one of those (-u), a settings option among its words (_SETTINGS_OPTION, _SETTINGS_SHORT; codex's -c
    for a key of _SETTINGS_KEY, and its --disable of such a feature), words xargs gives it from its input, or a word
    set at run time (`$(echo --settings)`, `"$@"` after `set -- --bare`, `$OPTS` a live shell exported), which may be
    an option; such a run reads none of the person's settings, the hooks that record it among them. Also codex's
    `features disable` of such a feature, which saves the change in its settings. learned: what the parse learned
    (shell.analyse), its names given a value and variables read with none.
    lean: a variable set anywhere on the line counts for every harness on it; read it per command if that holds a run
    a person needs"""
    if not any(_harness(c["argv"]) for c in commands):   # (no harness: nothing to read; env's, the parse unwraps)
        return []
    learned = learned or {}
    named = sorted(n for n in _set_names(commands, refs, learned.get("given", ())) if _SETTINGS_VARIABLE.fullmatch(n))
    # a variable with a value the line doesn't give it (from the shell it runs in), or one that may hold a word built
    # at run time or an option
    given = learned.get("given", {})
    unknown = set(learned.get("unresolved", set())) - set(given) | {
        n for n, values in given.items() if not values or any(re.match(r"\s*-|[\w\W]*[$`]", v) for v in values)}
    run_time = re.compile(r"\$[(@*#0-9!?-]|\$\{[@*#0-9!]|`" + "".join(
        f"|\\$\\{{?{re.escape(n)}\\b" for n in sorted(unknown) if n != "*") + (r"|\$" if "*" in unknown else ""))
    out = []
    for command in commands:
        argv = command["argv"]
        at = _env_chdir(argv)[1] if argv[0] == "env" else None
        if at and _harness(argv[at:]):   # env's own words, before the harness it runs
            own = argv[1:at]
            unset = [b for a, b in zip(own, own[1:]) if a in ("-u", "--unset")] + [
                a.partition("=")[2] or a[2:] for a in own if a.startswith(("--unset=", "-u")) and len(a) > 2]
            if any(re.fullmatch(r"-[A-Za-z]*i[A-Za-z]*|--ignore-environment|-", a) for a in own) or any(
                    _SETTINGS_VARIABLE.fullmatch(n) for n in unset):
                out.append(f"LAUNCH:{_harness([argv[at]])} env clears its settings")
        exe = _harness(argv)
        if not exe:
            continue
        args = argv[1:]
        def value(i, a, at):   # an option's value, in its word (after `at`) or the next
            return a[at:].removeprefix("=") or (args[i + 1] if i + 1 < len(args) else "")
        options = [a for i, a in enumerate(args) if (
            _SETTINGS_OPTION.fullmatch(a) or a.partition("=")[0] in _SETTINGS_OWN.get(exe, ())) and not (
            exe == "codex" and a.startswith("--config") and not _SETTINGS_KEY.search(value(i, a, 8))) and
            a.partition("=")[0] not in _NOT_SETTINGS.get(exe, ())]
        short = _SETTINGS_SHORT.get(exe, ())
        options += [a for i, a in enumerate(args) if a[:2] in short and not (exe == "codex" and a[:2] == "-c" and not
                    _SETTINGS_KEY.search(value(i, a, 2)))]
        if exe == "codex":   # --disable hooks is -c features.hooks=false; `features disable hooks` saves it
            options += [a for i, a in enumerate(args) if re.fullmatch(r"--disable(?:=.*)?", a, re.S) and
                        _SETTINGS_KEY.search(value(i, a, 9))]
            later = args[args.index("features") + 1:] if "features" in args else []
            off = later[later.index("disable") + 1:] if "disable" in later else None
            if off is not None and (not off or any(_SETTINGS_KEY.search(a) or re.search(r"\$|`", a) for a in off)):
                options.append("features disable")
        why = [f"variable {n}" for n in named] + [f"option {o}" for o in options]
        why += ["arguments from xargs's input"] * (command.get("via", [])[-1:] == ["xargs"])
        # one that starts with it, or one bash may split (no blank in it: unquoted) into words that may be options
        why += [f"a word set at run time {w[:40]}" for w in args
                if run_time.match(w) or run_time.search(w) and not re.search(r"\s", w)]
        out += [f"LAUNCH:{exe} {w}" for w in why]
    return list(dict.fromkeys(out))



# programs that send what they read off the machine (gh: a gist, an API call or a body it reads from stdin; aws: s3;
# openssl: s_client), and those that pass on only a count or a hash of what they read
_SENDERS = {"curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "rsync", "telnet", "http", "https",
            "xh", "xhs", "ftp", "lftp", "sendmail", "mail", "mailx", "mutt", "rclone", "gsutil"}
_SENDING = {"gh": ("gist", "api"), "aws": ("s3",), "openssl": ("s_client",)}
_SUMMARIES = {"wc", "md5", "md5sum", "sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum", "shasum", "cksum",
              "b2sum"}
_ENV_OPTIONS = {"-u": 1, "--unset": 1, "-C": 1, "--chdir": 1, "-P": 1, "-a": 1, "--argv0": 1}
# a process's environ file in any spelling (/proc/self/task/$$/environ, cd /proc/self; cat environ), or a pattern
# under /proc that may be one
_ENVIRON_FILE = re.compile(r"/proc/\S*?environ\b|/proc/\S*[*?[]|(?:^|[@<=])(?:\./)?environ$")
_DUMPERS = {"env", "printenv", "export", "declare", "typeset", "set"}
# code that reads the whole environment rather than one value: jq's `env` or `$ENV` (not env.HOME), awk iterating
# ENVIRON, Python's os.environ, Node's process.env, Ruby's ENV, Perl's %ENV, PHP's getenv() or $_ENV, as a whole
_ENVIRON_CODE = {
    "jq": re.compile(r"(?<![\w$.])(?:env|\$ENV)(?![\w.\[])"),
    "awk": re.compile(r"\bin\s+ENVIRON\b"),
    "python": re.compile(r"\bos\.environ\b(?!\s*(?:\[|\.(?:get|setdefault|pop)\b))|\benviron\.(?:items|keys|values|copy)\b"),
    "node": re.compile(r"\bprocess\.env\b(?!\s*(?:\.\w|\[))"),
    "ruby": re.compile(r"\bENV\b(?!\s*(?:\[|\.(?:fetch|key\?|has_key\?|include\?)))"),
    "perl": re.compile(r"%ENV\b"),
    "php": re.compile(r"\bgetenv\(\s*\)|\$_ENV\b(?!\s*\[)")}


def _environment_dump(command, files=()):
    """Whether a command prints the whole environment: env or printenv with no command or name, export, set, declare
    or typeset with no name (but declare -f's functions), BSD ps's `e` (ps eww, macOS's -E), code that reads it whole
    (_ENVIRON_CODE: inline, a heredoc, jq's or awk's program), a read of a process's environ file, or of `files`, the
    ones the line writes it into. One that runs on another host (ssh's remote command) prints that host's."""
    argv = command["argv"]
    prog, args = _program(argv), argv[1:]
    if "ssh" in command.get("via", ()):
        return False
    named = args + list(command.get("in", ()))
    joined = "\0".join(named)   # (_ENVIRON_FILE needs "/proc/" or "environ" in a word)
    if (files or "environ" in joined or "/proc/" in joined) and any(_ENVIRON_FILE.search(w) or any(
            re.search(r"(?<![\w.-])%s$" % re.escape(f), w) for f in files) for w in named):
        return True
    if prog == "env":
        i = 0
        while i < len(args) and (args[i].startswith("-") or "=" in args[i]):
            if args[i] in ("-S", "--split-string") or args[i].startswith("--split-string="):
                return False   # it runs a command
            i += 1 + _ENV_OPTIONS.get(args[i], 0)
        return i >= len(args)
    if prog == "printenv":
        return all(a.startswith("-") for a in args)
    if prog in ("export", "declare", "typeset"):
        return all(a.startswith("-") for a in args) and not any(re.fullmatch(r"-[a-zA-Z]*[fF][a-zA-Z]*", a) for a in args)
    if prog == "ps":
        return any(re.fullmatch(r"[A-Za-z]*e[A-Za-z]*|-[A-Za-z]*E[A-Za-z]*", a) for a in args)
    kind = "jq" if prog in ("jq", "gojq", "jaq") else shell._kind(prog)
    if kind in _ENVIRON_CODE:
        code = [a for a in args if not a.startswith("-")][:1] if kind == "jq" else [shell._code_arg(kind, args)]
        return any(t and _ENVIRON_CODE[kind].search(t) for t in code + list(command.get("stdin", ())))
    return prog == "set" and not args


def _sends(command):
    """Whether a command sends what it reads off the machine: _SENDERS; gh's gist or api, or any of its commands given
    stdin (`--body-file -`, `-F -`, `@-`); aws s3; openssl s_client."""
    prog, argv = _program(command["argv"]), command["argv"]
    return prog in _SENDERS or prog in _SENDING and any(a in _SENDING[prog] for a in argv[1:3]) or prog == "gh" and \
        any(a in ("-", "@-") or a.endswith(("=-", "=@-")) for a in argv[2:])


def _environment_sent(parsed):
    """`SENT:<printer> <sender>` for each command that prints the whole environment (_environment_dump) into one that
    sends it off the machine (_sends): a later stage of its pipeline, a sender anywhere in it (in a block, a loop or a
    subshell there, behind a wrapper, in code a shell or eval runs, in a substitution or process substitution of it:
    `env | (timeout 9 curl …)`, `env | { x; curl …; }`, `env | sh -c 'curl …'`, `env | tee >(curl …)`), or that
    sender's own words, herestring or heredoc (a substitution, process substitution, block or subshell whose output
    reaches it: the parse's `reaches`; `$(env)` in a heredoc), unless a stage on the way only counts or hashes it (wc,
    sha256sum); a file it is written into, then read or sent (`env > /tmp/e; curl -T /tmp/e …`); a redirection to
    /dev/tcp or /dev/udp on a line that prints it; and a sender that reads a process's environ file itself (`curl -d
    @/proc/self/environ`). parsed: shell.analyse's."""
    commands = parsed[0]
    files, dumps, more = set(), [], True
    while more:   # (a file the environment is written into is read as it, until the line writes it into no more)
        dumps = [c for c in commands if _environment_dump(c, files)]
        held = files | {o for d in dumps for o in d.get("out", ()) if o not in _NOWHERE} | {
            a for c in commands if _program(c["argv"]) == "tee" and any(
                d["pipeline"] == c["pipeline"] and (d.get("stage") or 0) < (c.get("stage") or 0) for d in dumps)
            for a in c["argv"][1:] if not a.startswith("-")}
        more, files = held != files, held
    if not dumps:
        return []
    senders = [c for c in commands if _sends(c)]
    out = [f"SENT:environ {_program(s['argv'])}" for s in senders if _program(s["argv"]) != "ssh" and
           _environment_dump({"argv": ["", *s["argv"][1:]], "in": s.get("in", ())}, files)]
    if any(re.match(r"/dev/(?:tcp|udp)/", w) for c in commands for w in list(c.get("out", ())) + list(c.get("in", ()))):
        out.append("SENT:environ /dev/tcp")
    summaries, at_of = {}, {}   # per pipeline: the stages that only count or hash; each sender's stages by program
    for c in commands:
        if _program(c["argv"]) in _SUMMARIES:
            summaries.setdefault(c.get("pipeline"), []).append((c.get("stage") or 0))
    # where each sender reads: its own stage, and each stage it is inside (inside: a block, a loop, a subshell, code a
    # shell or eval runs, a substitution or a process substitution, behind any wrapper, each reads that stage's input)
    for s in senders:
        at_of.setdefault((s.get("pipeline"), False), {}).setdefault(_program(s["argv"]), []).append((s.get("stage") or 0))
        for p, k in dict.fromkeys(s.get("reaches") or ()):
            at_of.setdefault((p, True), {}).setdefault(_program(s["argv"]), []).append(k)
    for stages in [*summaries.values(), *(v for by in at_of.values() for v in by.values())]:
        stages.sort()

    def until(p, stage):   # the first stage after `stage` that only counts or hashes
        ks = summaries.get(p, ())
        i = bisect.bisect_right(ks, stage)
        return ks[i] if i < len(ks) else float("inf")

    def reached(p, stage, same):   # the senders reading pipeline p after `stage` (or at it: `same`), by program
        end = until(p, stage)
        return [prog for inside in (False, True) for prog, ks in at_of.get((p, inside), {}).items()
                if (i := (bisect.bisect_left if same and not inside else bisect.bisect_right)(ks, stage)) < len(ks)
                and ks[i] <= end]
    for d in dumps:
        own = d.get("pipeline"), (d.get("stage") or 0)
        # a printer inside a substitution or block prints out of it from its own pipeline's last stage
        spots = [own] + [spot for spot in dict.fromkeys(d.get("reaches") or ()) if until(*own) == float("inf")]
        out += [f"SENT:{_program(d['argv'])} {prog}" for p, stage in spots for prog in reached(p, stage, (p, stage) != own)]
        if "<<" in d.get("via", ()):   # in a heredoc's substitution: what reads that heredoc
            out += [f"SENT:{_program(d['argv'])} {_program(s['argv'])}" for s in senders if any(
                ("$(" in t or "`" in t) and _program(d["argv"]) in t for t in s.get("stdin", ()))]
    return list(dict.fromkeys(out))


def _package_indexes(commands, refs=()):
    """Return only explicitly selected non-default package sources, one subject per effective option or variable."""
    words = list(refs) + [a for c in commands if c["argv"][:1] in (["env"], ["export"]) for a in c["argv"][1:]]
    out = [value for name, eq, value in (w.partition("=") for w in words)
           if eq and name.upper() in _SOURCE_VARIABLES and _non_default_source(value, _SOURCE_VARIABLES[name.upper()])]
    for command in commands:
        argv = command["argv"]
        if not argv:
            continue
        exe = _program(argv)
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
        if not argv or _program(argv) not in ("docker", "podman"):
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


def _gh_api(argv, replaced=None, runner=False):
    """A gh or hub api call's argv percent-decoded, as GitHub reads its path (`git/refs/heads%2Fmain`), and
    `PUSH:contents` when it puts or deletes a repository's file (repos/<o>/<r>/contents/…), which commits to the
    default branch unless a branch field names another. A branch the line can't tell is held too: HEAD, one gh reads
    from a file (`-F branch=@b.txt`) or an expansion gives, two branch fields, and any with --input, whose body then
    names the branch (the fields go to the query). The words are read as gh reads them: an option that takes a value
    takes the rest of its word or the next word (`-f --method=GET` is a field), the method only from -X or --method (the
    last; POST with a field or --input, else GET) and the branch only from a field (`-F branch={branch}` is the current
    one); a method that is an expansion the line can't resolve counts as a write. The endpoint's route is _gh_routes'
    (with `replaced`, the word xargs -I or parallel -I puts its input in place of; a branch holding it, or a {…} word
    when a `runner` runs gh, is one the runner fills in): a write there gives `PUSH:merges` for
    repos/<o>/<r>/merges (any form), `PUSH:merge-upstream` for a fork's merge-upstream into the default branch or one the line can't tell,
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
    # gh sends every -f field, then every -F field: of two branch fields, the line can't tell which GitHub reads
    branches = [(kind == "field", v) for kind, key, v in fields if key == "branch"]
    magic, branch = branches[0] if len(branches) == 1 else (False, "")
    branch = branch.removeprefix("refs/").removeprefix("heads/")
    keys = {key for _, key, _ in fields}
    unread_body = "input" in kinds or any("$" in k or "`" in k for k in keys)
    # a branch field that alone names a branch other than the default: literal, and no body or field name hides another;
    # not one a runner fills in (the word xargs -I or parallel -I replaces, a {…} word under any runner)
    filled = bool(replaced) and replaced in branch or runner and re.search(r"\{[^{}]*\}", branch)
    named = bool(branch) and not unread_body and branch[:1] != "@" and "$" not in branch and "`" not in branch and \
        not (magic and "{branch}" in branch) and not filled and branch.casefold() not in ("main", "master", "head")
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
    api call also percent-decoded (_gh_api), and GitHub's REST API through curl, wget, HTTPie or xh as gh api's is
    read (_github_rest); a kubectl dry run (_kubectl_dry_run) or a publish's (_publish_dry_run) as `DRYRUN:<argv>`,
    unless xargs, parallel, find -exec or fd -x runs it, which may add any word to it (`false`, --dry-run=none); each
    also with its program as its base name (_program), where that differs, and a publish as `<program> publish`
    (_published)."""
    out, replaced = [], None
    for command in commands:
        argv = command["argv"]
        runner = {v.split(" ", 1)[0] for v in command.get("via", ())} & {"xargs", "gxargs", "parallel", "find", "fd"}
        if argv[:1] in (["xargs"], ["gxargs"]):   # the word its -I puts the input in place of, for what it runs
            inner = next(shell._unwrap(argv[0], argv[1:]))
            replaced = shell._xargs_replace(argv[1:len(argv) - len(inner)])
        elif argv[:1] == ["parallel"]:   # (its -I, as xargs' is read)
            i = 1
            while i < len(argv) and argv[i].startswith("-"):
                i += 2 if argv[i] in shell.PARALLEL_OPTS else 1
            replaced = shell._xargs_replace(argv[1:i])
        elif not {"xargs", "gxargs", "parallel"} & runner:
            replaced = None   # (the word was that runner's only)
        push = _git_push(argv)
        dry = "DRYRUN:" * (not runner and (_kubectl_dry_run(argv) or _publish_dry_run(argv)))
        # (and with its program by name, as its file's base name gives it: npm.cmd is npm, /usr/bin/npm npm; and a
        # publish after any options as its program's publish: _published)
        out += push if push is not None else [dry + " ".join(argv)] + [
            dry + " ".join([_program(argv), *argv[1:]])] * (_program(argv) != argv[0]) + [
            dry + p for p in [_published(argv)] if p]
        if push is None and _program(argv) in ("gh", "hub") and argv[1:2] == ["api"]:
            given = replaced if {"xargs", "gxargs", "parallel"} & runner else None
            out += [s for s in _gh_api(argv, given, bool(runner)) if s not in out]
        out += [s for s in _github_rest(argv) if s not in out]
        out += [s for s in _gh_repo_sync(argv, bool(runner)) if s not in out]
    return out


_REST_CLIENTS = {"curl", "wget", "http", "https", "xh", "xhs"}
_GITHUB_API = re.compile(r"(?:^|[/@])api\.github\.com(?:[:/]|$)|/api/v3(?:/|$)", re.I)
_HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
_CURL_DATA = re.compile(r"-d|--data(?:-\w+)?|-F|--form(?:-string)?|--json")


def _github_rest(argv):
    """`PUSH:<why> <method>` for a write to GitHub's REST API (api.github.com, or GHES's /api/v3/) through curl, wget,
    HTTPie or xh, as _gh_api reads gh api's: main's or master's ref (git/refs/heads/main), a file put or deleted
    (contents/, unless a literal branch in the body names another), a merge (merges, merge-upstream), or a write
    whose route the line can't tell. The method is curl's -X or --request (POST with data or a form, PUT with -T),
    wget's --method (POST with --post-data or --post-file), HTTPie's and xh's first word when it is one (POST with
    request items); one the line can't resolve counts as a write."""
    prog = _program(argv)
    if prog not in _REST_CLIENTS:
        return []
    args = [unquote(a) for a in argv[1:]]
    urls = [a.removeprefix("--url=") for a in args if _GITHUB_API.search(a)]
    if not urls:
        return []
    method, body = "", []
    for a, after in zip(args, args[1:] + [""]):
        if prog == "curl":
            if a in ("-X", "--request"):
                method = after
            elif a.startswith("--request="):
                method = a.partition("=")[2]
            elif a.startswith("-X") and len(a) > 2:
                method = a[2:]
            elif _CURL_DATA.fullmatch(a.partition("=")[0]):
                body.append(a.partition("=")[2] if "=" in a and a.startswith("--") else after)
            elif a in ("-T", "--upload-file"):
                body.append("@" + after)
        elif prog == "wget":
            if a.startswith("--method"):
                method = a.partition("=")[2] or after
            elif a.startswith(("--post-data", "--post-file", "--body-data", "--body-file")):
                body.append(("@" if "file" in a else "") + (a.partition("=")[2] or after))
    if prog == "curl" and not method:
        method = "PUT" if any(a in ("-T", "--upload-file") for a in args) else "POST" if body else \
            "HEAD" if any(a in ("-I", "--head") for a in args) else "GET"
    elif prog == "wget" and not method:
        method = "POST" if body else "GET"
    elif prog not in ("curl", "wget"):
        words = [a for a in args if not a.startswith("-")]
        method = words[0] if words and words[0].upper() in _HTTP_METHODS else ""
        body = [w for w in words[1 + bool(method):] if re.search(r":?=|@", w) and not _GITHUB_API.search(w)]
        method = method or ("POST" if body else "GET")
    unread_method = not method or "$" in method or "`" in method
    write = unread_method or method.upper() not in ("GET", "HEAD", "OPTIONS")
    if not write:
        return []
    put, delete = (unread_method or method.upper() == m for m in ("PUT", "DELETE"))
    text = " ".join(body)
    branches = re.findall(r'"branch"\s*:\s*"([^"]*)"|\bbranch:?=([^\s&]*)', text)   # (two: as gh api's, untold)
    branch = "".join(branches[0]) if len(branches) == 1 else ""
    # as written, and a JSON body's top-level one as JSON reads it (no escape or quote: `m\u0061in`, HTTPie's `:=`)
    told = not re.search(r"[\\\"']", branch) and all(b == branch for b in map(_json_branch, body) if b is not None)
    branch = branch.removeprefix("refs/").removeprefix("heads/")
    named = told and bool(branch) and "@" not in text and not re.search(r"[$`]", text + branch) and \
        branch.casefold() not in ("main", "master", "head")
    out = []
    for url in urls:
        routes, unknown, _ = _gh_routes(url, strict=False)
        path = _gh_mask(url)
        if re.search(r"/git/refs/heads/(?:main|master)(?:[/?#]|$)", path, re.I):
            out.append(f"PUSH:ref {method[:64]}")
        elif unknown:
            out.append(f"PUSH:unknown {url[:64]}")
        elif "merges" in routes:
            out.append(f"PUSH:merges {method[:64]}")
        elif "merge-upstream" in routes and not named:
            out.append(f"PUSH:merge-upstream {branch[:64]}")
        elif (put or delete) and "contents" in routes and not named:
            out.append(f"PUSH:contents {method[:64]}")
    return out


def _json_branch(text):
    """The branch a JSON object body names at its top as JSON reads it, "" for none, a value that isn't a string or a
    key repeated in any object (which parsers read apart); None for a body that isn't a JSON object."""
    repeated = []

    def pairs(items):
        repeated.append(len({k for k, _ in items}) < len(items))
        return dict(items)
    try:
        doc = json.loads(text, object_pairs_hook=pairs)
    except (ValueError, RecursionError):
        return None
    if not isinstance(doc, dict):
        return None
    value = "" if any(repeated) else doc.get("branch", "")
    return value if isinstance(value, str) else ""


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


# a word of a dry run the line can't tell: an expansion it can't resolve, or a pattern (`fals?`, `--dry*`, `[f]alse`)
# or a find -exec {} that may give any word, as `false` or --dry-run=none
_UNTOLD = re.compile(r"[$`*?\[]|\{\}")


def _kubectl_dry_run(argv):
    """Whether a kubectl command is a dry run as kubectl reads its words: its last --dry-run (bare, =client or =server;
    not =none or =false) comes before a bare `--`, after which kubectl reads every word as a name; no word before that
    is --raw (a request sent as given) or a word the line can't tell (_UNTOLD: `"$D"` may be `--` or a later
    --dry-run=none), and no --dry-run word comes right after an option that may take it as its value (_kubectl_takes:
    `--field-manager --dry-run`)."""
    if _program(argv) != "kubectl":
        return False
    last = None
    for prev, word in zip(argv, argv[1:]):
        if word == "--":
            break
        if word.startswith("--raw") or _UNTOLD.search(word):
            return False
        if word == "--dry-run" or word.startswith("--dry-run="):
            if _kubectl_takes(prev):
                return False
            last = word
    return last in ("--dry-run", "--dry-run=client", "--dry-run=server")


# the package publishers whose publish takes --dry-run, and the flags of theirs that take no value (so a --dry-run
# after one is no option's value)
_PUBLISHERS = {"npm", "pnpm", "yarn", "bun", "cargo", "uv", "poetry"}
_PUBLISH_FLAGS = {"--provenance", "--workspaces", "--ws", "--include-workspace-root", "--ignore-scripts", "--json",
                  "--force", "-f", "--quiet", "-q", "--silent", "--verbose", "-v", "--no-git-checks", "--recursive",
                  "-r", "--build", "--allow-dirty", "--no-verify", "--locked", "--frozen", "--offline"}


def _published(argv):
    """`<program> publish` for a command that publishes a package, after any number of options (each with a value
    or not, read in one pass, where a pattern bounds them: TK-A056, TK-F004): _PUBLISHERS' publish (a program
    corepack or a package runner names with its version too: npm@10), npm's pu to publi, cargo's after a +toolchain,
    pnpm's after recursive, multi or m, and yarn's npm publish (after its workspaces foreach or workspace <name>); else
    None. The command a package manager's exec, x or dlx runs, and a wrapper's, are commands of their own the parser
    gives (shell.runner_at, shell._unwrap). The push and line fields read it beside the command as written."""
    prog = shell.base_name(argv[0]).partition("@")[0] if argv else ""
    if prog not in _PUBLISHERS:
        return None
    i = 1 + (prog == "cargo" and argv[1:2] != [] and argv[1].startswith("+"))
    valued = False   # (the word before is an option, so this one may be its value)
    while i < len(argv):
        w = argv[i]
        if w == "publish" or prog == "npm" and w in ("pu", "pub", "publ", "publi") or prog == "yarn" and \
                argv[i:i + 2] == ["npm", "publish"]:
            return f"{prog} publish"
        skip = 2 if prog == "yarn" and (argv[i:i + 2] == ["workspaces", "foreach"] or w == "workspace") else \
            1 if prog == "pnpm" and w in ("recursive", "multi", "m") else 0
        if skip:   # its command follows, after options of its own
            i, valued = i + skip, False
            continue
        if not w.startswith("-") and not valued:
            return None
        valued = w.startswith("-")
        i += 1
    return None


def _publish_dry_run(argv):
    """Whether a package publish is a dry run, which publishes nothing (npm, pnpm or bun publish, yarn's `npm publish`,
    cargo, uv or poetry publish; not Yarn 1's `yarn publish`, which may ignore a flag it doesn't know and publish): its
    last --dry-run (bare or =true; not =false, nor --no-dry-run after it, nor followed by `false`) comes before a bare
    `--`, after no option that may take it as its value, no other spelling nopt reads as it is on the line, and no word
    before is one the line can't tell (_UNTOLD)."""
    if _program(argv) not in _PUBLISHERS or "publish" not in argv[1:4] or _program(argv) == "yarn" and \
            argv[argv.index("publish") - 1] != "npm":
        return False
    last = None
    for i, (prev, word) in enumerate(zip(argv, argv[1:]), 1):
        if word == "--":
            break
        if _UNTOLD.search(word):
            return False
        name = word.split("=")[0]
        bare = name.lstrip("-").lower()
        while bare.startswith("no-"):
            bare = bare[3:]
        if not (name.startswith("-") and bare.startswith("dr")):
            continue
        # nopt, npm's and pnpm's option parser, reads one dash or three, an abbreviation (`--dry`) and `no-` in any case
        if name not in ("--dry-run", "--no-dry-run"):
            return False
        if prev.startswith("-") and "=" not in prev and prev not in _PUBLISH_FLAGS and prev != "--dry-run":
            return False
        last = word, argv[i + 1:i + 2]
    # nopt also takes a `true` or `false` right after a bare boolean option as its value: `--dry-run false` publishes
    return last is not None and last[0] in ("--dry-run", "--dry-run=true") and last[1] != ["false"]


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
    """The `run` field of a tool no pack maps, or of an MCP tool: for each argument TK-S010 reads as a command (at any
    depth, its name in any case), `WORD:<its last /-part>` and the program name it gives (shell.base_name: reboot.exe
    is reboot) when it is one word of plain characters (letters, digits, `_ . : / -`), else
    `CMD:<value>` (a string as given, a list or an object as canonical JSON); `MCPCMD:<value>` for any value when the
    tool's name is an MCP tool's in a case no pack maps (`MCP:x/y`), as TK-S010 reads an MCP tool's; and for each string under a sql,
    query or statement argument (at any depth, its name in any case, in a list or an object too) each statement as
    every SQL dialect lexes it (classes.sql_read: comments and literals blanked), split at its `;`s, each blank run a
    space: `SQL;<statement>` for one a `;` ends, `SQL:<statement>` for the last; before a literal or comment that
    doesn't close, only those a `;` ends (a database may run them, then fails on the rest)."""
    out, tag = [], "MCPCMD:" if _text(tool).casefold().startswith(("mcp:", "mcp__")) else "CMD:"
    # a call over MAX_SUBJECT isn't lexed: its SQL is the whole call as written, longer than MAX_SUBJECT, which every
    # rule on it takes as TK-OVERSIZE in its section (dev, the pack that reads `run`, holds it: `oversize: ask`)
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
                out.extend(["WORD:" + w for w in (v.rsplit("/", 1)[-1], shell.base_name(v))] if plain else [
                    tag + (v if isinstance(v, str) else canonical(v))])
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
    """The program an argv runs, by its file name, casefolded and without .exe (shell.base_name)."""
    return shell.base_name(argv[0]) if argv else ""


_HISTORY = (".bash_history", ".zsh_history", "fish_history", "consolehost_history.txt")


def _log_or_history(path):
    """Whether a path is under /var/log (macOS's /private/var/log too) or names a shell history file, in any case."""
    p = path.replace("\\", "/").casefold()
    return p.startswith(("/var/log", "/private/var/log")) or any(part.endswith(_HISTORY) for part in p.split("/"))


def _effects(parsed, work=None):
    """The files the commands write, each as WRITE_TARGET:path, and delete, as DELETE_TARGET:path, each also with the
    path resolved (_normal) and casefolded: what redirections write, and what rm, unlink, shred, truncate, tee, cp, mv, install, ln, dd,
    sed -i, perl -i and ruby -i name, find with -delete, -exec rm or an -exec that writes each file found (sed -i: each name
    its -name tests, under each start path), awk's
    print > "file", zip -m's sources, each file a download writes (shell.download_writes: one it can't name holds the
    line as unread), and one of those that git, docker, podman, kubectl or parallel runs from its words
    (git rm). What chmod, chown, chgrp, chflags, chattr and setfacl change is MODE_TARGET:path
    (_MODE_CHANGERS). When a command writes files the line names only at run time or inside code it runs (_opaque), or the
    parser can't read what one runs (its `opaque`: `| sh`, `fish -c`, a name an expansion builds) and a writer's name
    reaches it (_reaches_unread), every word on the line and each herestring and heredoc text is one it may write, as
    MAY_WRITE:word (only TK-D008 reads those); for one the parser can't read, each normalised line too (a name an
    expansion builds may hold the path). A script the line writes, then runs, writes what its code does (the parser
    reads it as that inline code is: shell.read_file), and may write each word the run gives it, MAY_WRITE. A link ln
    or cp -s/-l makes is also MAY_WRITE: a later write through it writes the file it points at. Read once per parse
    (the `effects` field and _tracekit both read it): kept in what the parse learned."""
    learned = parsed[5] if len(parsed) > 5 else {}
    if "effects" not in learned:
        learned["effects"] = _write_effects(parsed, [0] if work is None else work)
    return learned["effects"]


# a host key added to known_hosts: an append to it (`>>`, `tee -a`, `ssh-keyscan … >>`) is APPEND_TARGET, which no
# shipped rule reads, where any other write of it is a WRITE_TARGET as any file in .ssh/ is (TK-D023)
_KNOWN_HOSTS = re.compile(r"(?i)(?:^|[/\\])\.ssh[/\\]known_hosts2?$")   # (a Windows spelling too)


def _variable(parsed, name):
    """The values the line gives variable `name`: as an assignment (a reference; `+=` too), inline, or an argument of
    export, declare, typeset, readonly, local or env."""
    return [r.partition("=")[2] for r in parsed[2] if re.match(name + r"\+?=", r)] + [
        a.partition("=")[2] for c in parsed[0] if c["argv"][0] in ("export", "declare", "typeset", "readonly", "local", "env")
        for a in c["argv"][1:] if re.match(name + r"\+?=", a)]


_READINGS = 4   # the readings of one cd that _walk takes as alternatives
_FOLDERS_MAX = 16   # the folders one line may be in at a command: past it the line is unread (held)
_NAVIGATING = ("cd", "pushd", "popd")


def _destinations(arg, cur, homes, oldpwd, cdpath):
    """Where a cd or pushd to `arg` may lead from folder `cur` (None: the one the line starts in): a bare one HOME
    (`homes`); `-` an OLDPWD the line gives (a `$OLDPWD` is read by the parse; any folder the line was in before stays one
    it may be in: _walk keeps them); an absolute one as written; a relative one joined to the folder and to each CDPATH folder."""
    if arg is None:
        return list(homes)
    if arg == "-":
        return list(oldpwd)
    if arg.startswith(("/", "~", "$")):
        return [arg]
    return [posixpath.join(cur, arg) if cur else arg] + [posixpath.join(c, arg) for c in cdpath]


def _walk(parsed, work):
    """(for each command of the line, the folders it may run in (the folder the line starts in is none), whether
    there are more than _FOLDERS_MAX). The folders of a cd or pushd (and of one a CDPATH, HOME or OLDPWD the line sets
    reads another way); a cd that fails, a `cd -` and a popd leave or return to a folder the line was in, so every one
    it was in stays one it may be in (a folder stack's entries are all among them). Past _FOLDERS_MAX the oldest are
    dropped and the line is held as unread. A new folder is charged to `work` (shell.charge)."""
    learned = parsed[5] if len(parsed) > 5 else {}
    if "walk" in learned:
        return learned["walk"]
    cdpath, homes, oldpwd = _cdpath(parsed), _variable(parsed, "HOME") or ["~"], _variable(parsed, "OLDPWD")
    folders, out, held, commands, i = [None], [], False, parsed[0], 0
    while i < len(commands):
        c = commands[i]
        if c["argv"][0] not in _NAVIGATING:
            out.append(tuple(f for f in folders if f))
            i += 1
            continue
        j = i   # (a cd's readings share its pipeline: each is a place the line may go; a line the parser can't read gives every
        # command one, so a group past _READINGS is taken a step at a time, each step over the folders so far)
        while (j < len(commands) and commands[j]["pipeline"] == c["pipeline"] and commands[j]["argv"][0] in _NAVIGATING
               and j - i < _READINGS):
            j += 1
        new = [d for cur in folders for g in commands[i:j] if g["argv"][0] != "popd"
               for d in _destinations(next((a for a in g["argv"][1:] if a == "-" or not a.startswith("-")), None),
                                      cur, homes, oldpwd, cdpath)]
        shell.charge(work, sum(min(len(d), 64) + 1 for d in dict.fromkeys(new)))   # (a long folder costs no more than 64)
        folders = list(dict.fromkeys([*folders, *new]))
        if len(folders) > _FOLDERS_MAX:
            folders, held = folders[-_FOLDERS_MAX:], True
        out += [()] * (j - i)
        i = j
    learned["walk"] = result = (out, held)
    return result


def _walk_held(parsed, work):
    """_walk's result; when its work spends the budget, no command is read as in a folder and the line is held as unread
    (the texts of its commands, and the paths they spell out, are still read)."""
    learned = parsed[5] if len(parsed) > 5 else {}
    try:
        return _walk(parsed, work)
    except shell.ParseError:
        learned["unread"] = True
        try:   # once more on a budget of its own: an earlier command that spent the decision's leaves the folders of a later one
            return _walk(parsed, [0])
        except shell.ParseError:
            return learned.setdefault("walk", ([()] * len(parsed[0]), True))


def _write_effects(parsed, work):
    learned = parsed[5] if len(parsed) > 5 else {}
    tags = []
    try:
        _collect_effects(parsed, work, tags, learned)
    except shell.ParseError:   # the budget is spent: what was read stays (a trust-root deny among it), and the line is held
        learned["unread"] = True
    return list(dict.fromkeys(tags + [k + ":" + path.casefold() for k, _, path in (t.partition(":") for t in tags)]))


def _collect_effects(parsed, work, tags, learned):
    """_write_effects' reading, appending each effect to `tags` as it is read."""
    env = [f"--{opt}={v}" for var, opt in (("GIT_DIR", "git-dir"), ("GIT_WORK_TREE", "work-tree"))
           for v in _variable(parsed, var)]
    if env:   # git given another repository or work tree by the environment is read as given them by option
        parsed = ([dict(c, argv=[c["argv"][0], *env, *c["argv"][1:]]) if _program(c["argv"]) == "git" else c
                   for c in parsed[0]], *parsed[1:])
    appended = collections.Counter(learned.get("appended", ()))
    for ref in parsed[3]:
        add = appended[ref] > 0 and bool(_KNOWN_HOSTS.search(_text(ref)))
        appended[ref] -= 1
        tags.append(("APPEND_TARGET:" if add else "WRITE_TARGET:") + _text(ref))
    tags += _command_effects(parsed[0], work)
    # a write to `{}` in code a find's -exec runs (its sh -c script given {} as $1) writes each file the find finds
    if "{}" in parsed[3]:
        tags += ["WRITE_TARGET:" + f for c in parsed[0] if _program(c["argv"]) == "find" and any(
            a in ("-exec", "-execdir", "-ok", "-okdir") for a in c["argv"]) for f in _find_files(c["argv"][1:], work)]
    tags += ["MAY_WRITE:" + w for c in parsed[0] for w in c.get("script_args", ())]
    unread = any(c["opaque"] for c in parsed[0])
    if any(_opaque(c) for c in parsed[0]) or unread and _reaches_unread(parsed):
        # lean: a read on the same line as such a writer counts as a write (as TK-D008 read the whole line before
        # #421); follow the names into the writer if that holds real reads
        tags += ["MAY_WRITE:" + w for c in parsed[0] for w in c["argv"][1:] + c["stdin"]]
        tags += ["MAY_WRITE:" + line for line in parsed[1] if unread]
    # a relative target a command after a cd writes is also read in the folder the cd entered, resolved (`cd ~/.hermes
    # && sed -i … config.yaml`); one with a pattern only as each protected path it may make (`cd ~/.cursor && cp x
    # plug?ns/y.js`), as a pattern isn't one there when the folder is a Claude Code worktree's (`cd .claude/worktrees/w
    # && rm src/*.orig`)
    # (and what env -C runs, in its folder)
    options = learned.get("globs", ())

    def forms_of(kind, path):
        """(kind, form) of each protected path a pattern may make; a path that reads as more than the readers take
        (their ParseError) is held instead, where the rest of the line keeps what it was read as."""
        try:
            return [(kind, f) for f in _pattern_forms(path, work) + _protected_forms(path, options, work)]
        except shell.ParseError:
            learned["unread"] = True   # (decide holds the line as an unread one beside what the rules found)
            return [("ROOT_TARGET", path)]

    def joined(folder, effects, find=False):
        out = [(k, _normal(folder.rstrip("/") + "/" + path)) for k, _, path in (t.partition(":") for t in effects)
               if k != "MAY_WRITE" and path[:1] not in ("/", "~", "$", "")]
        tagged = [(("WRITE_TARGET" if k == "APPEND_TARGET" and not _KNOWN_HOSTS.search(p) else k) + ":" + p)
                  for k, p in out if not shell._GLOB.search(p)]
        tagged += [k + ":" + f for k, p in out if shell._GLOB.search(p) for k, f in forms_of(k, p)]
        return tagged + [k + ":" + r for k, p in out if k in ("DELETE_TARGET", "MODE_TARGET") and not find
                         for r in _roots_below(p)]
    appends = collections.Counter(learned.get("appended", ()))
    where, held = _walk_held(parsed, work)
    if held:
        learned["unread"] = True   # (decide holds the line as an unread one beside what the rules found)
    for c, bases in zip(parsed[0], where):
        if c["argv"][0] in _NAVIGATING:
            continue
        for base in bases:
            outs = []
            for o in c.get("out", ()):   # (an append is one only as many times as the line appends to it)
                outs.append(("APPEND_TARGET:" if appends[o] > 0 else "WRITE_TARGET:") + o)
                appends[o] -= 1
            tags += joined(base, outs + _command_effects([c], work), c["argv"][0] == "find")
            if c["argv"][0] == "find":   # (its start paths, read from the folder, for the trust roots under them)
                tags += _command_effects([dict(c, argv=_find_in(c["argv"], base))], work)
        folder, at = _env_chdir(c["argv"]) if c["argv"][0] == "env" else (None, None)
        if folder and at:
            for base in bases or [""]:
                there = folder if folder.startswith(("/", "~", "$")) or not base else posixpath.join(base, folder)
                tags += joined(there, _command_effects([{"argv": c["argv"][at:]}], work), c["argv"][at] == "find")
                if c["argv"][at] == "find":
                    tags += _command_effects([{"argv": _find_in(c["argv"][at:], there)}], work)
    # an upgrade of every tool takes each from the configured index: held where the line changes which index, configuration or
    # Python it uses (a variable, uv's --config-file, --directory or --project, another folder's uv.toml after a cd)
    every = [i for i, c in enumerate(parsed[0]) if c["argv"] and (
        _program(c["argv"]) == "pipx" and "upgrade-all" in c["argv"] or _program(c["argv"]) == "uv" and "tool" in c["argv"]
        and "upgrade" in c["argv"] and any(a in ("--all", "-a") for a in c["argv"]))]
    if every and (any(_variable(parsed, n) for n in _UPGRADE_SETTINGS) or any(where[i] for i in every) or any(
            a.startswith(("--config-file", "--directory", "--project", "--index", "--default-index", "--python"))
            for i in every for a in parsed[0][i]["argv"])):
        tags.append("ROOT_TARGET:upgrade-all setting")
    # the environment a pip, uv pip or interpreter module installs into, named by a VIRTUAL_ENV the line gives
    if any(c["argv"][0] == "uv" for c in parsed[0]):   # uv syncs, runs and installs into a project's environment
        tags += ["WRITE_TARGET:" + v for v in _variable(parsed, "UV_PROJECT_ENVIRONMENT")]
    if any(c["argv"][0] in ("pip", "pip3", "uv", "python", "python3") for c in parsed[0]) and any(
            a in ("install", "sync", "ensurepip") for c in parsed[0] for a in c["argv"][1:]):
        tags += ["WRITE_TARGET:" + v for v in _variable(parsed, "VIRTUAL_ENV")]
    # a target a placeholder or variable stands for, on a line that asks where the Python lives (`uv tool list
    # --show-paths | xargs -I{} cp x {}/bin/python`)
    if any(c["argv"][:3] in (["uv", "tool", "list"], ["uv", "tool", "dir"], ["uv", "python", "dir"], ["pipx", "environment"],
                             ["pipx", "list"]) for c in parsed[0]):
        tags += ["ROOT_TARGET:" + path for k, _, path in (t.partition(":") for t in tags)
                 if k in ("WRITE_TARGET", "INTO_TARGET", "TREE_TARGET", "WORKTREE_TARGET") and re.search(r"\{\}|\$", path)]
    # tracekit run by xargs takes its action (init, which records the hook's Python) from input the line makes
    if any(c.get("via", [])[-1:] == ["xargs"] and (_program(c["argv"]) == "tracekit" or (
            _PYTHON_EXE.fullmatch(_program(c["argv"])) and _python_module(c["argv"][1:])[:1] == ["tracekit"]))
           for c in parsed[0]):
        tags.append("ROOT_TARGET:xargs tracekit")
    # an install location the line gives as a variable (`DESTDIR=… make install`), where a command runs that the parser doesn't know
    if any(not _known_program(_program(c["argv"])) for c in parsed[0] if c["argv"]):
        tags += ["INSIDE_TARGET:" + r.partition("=")[2] for r in parsed[2] if _NAME_VALUE.match(r)]
    if any(_program(c["argv"]) == "mktemp" for c in parsed[0] if c["argv"]):   # it makes its file in TMPDIR
        tags += ["NAMED_TARGET:" + v for n in ("TMPDIR", "TMP", "TEMP") for v in _variable(parsed, n)]
    # a CDPATH or OLDPWD set some way the parse doesn't read (printf -v, read, eval) puts a cd anywhere: held with the writes
    if any(c["argv"][0] in _NAVIGATING for c in parsed[0]) and any(
            c["argv"][0] in ("printf", "read", "mapfile", "readarray", "eval") and any(
                re.search(r"\b(?:CDPATH|OLDPWD)\b", a) for a in c["argv"][1:]) for c in parsed[0]):
        tags.append("ROOT_TARGET:CDPATH")
    # a path through a link the line makes is also read as what it points at (`ln -s ~/.cursor/plugins p && cp x
    # p/local/y`; a copy into the link, TREE_TARGET and INTO_TARGET, too), and what a delete or mode change there takes
    # of a trust root (_roots_below)
    links = _links(parsed[0])
    through, seen = [], {(k, p) for k, _, p in (t.partition(":") for t in tags) if k != "MAY_WRITE"}
    todo = [(k, p, 0) for k, p in seen]
    links = {link: target for link, target in links.items() if link}
    while todo and links:   # (a link to a link: a path is read through links until none applies, at most as deep as there
        k, path, depth = todo.pop()   # are links, so a loop of them ends; each path once)
        parts = path.split("/")
        for n in range(1, len(parts) + 1) if depth < len(links) else ():   # (each folder along the path: a lookup)
            link = "/".join(parts[:n])
            if link in links and (n < len(parts) or k in ("INTO_TARGET", "TREE_TARGET", "WORKTREE_TARGET")):
                made = (k, links[link] + path[len(link):])
                if made not in seen:
                    seen.add(made)
                    through.append(made)
                    todo.append((*made, depth + 1))
                    shell.charge(work, len(made[1]))
    tags += [k + ":" + p for k, p in through] + [k + ":" + r for k, p in through if k in ("DELETE_TARGET", "MODE_TARGET")
                                                   for r in _roots_below(p)]
    # a target a substitution makes of where Tracekit's Python lives (`ln -sf x "$(command -v tracekit)"`), a variable the
    # line gives one, or an unresolved expansion followed by a root's own name (`$D/tracekit-ai/bin/python`) may be it
    where = "|".join(re.escape(n) for n, text in learned.get("assigned", ()) if _from_where(text))
    tags += ["ROOT_TARGET:" + path for k, _, path in (t.partition(":") for t in tags)
             if k in ("WRITE_TARGET", "DELETE_TARGET", "MODE_TARGET", "INTO_TARGET", "TREE_TARGET", "WORKTREE_TARGET") and (
                 _from_where(path) or _root_named(path) or _root_glob(path) or where and re.search(
                     r"\$\{?(?:%s)\b" % where, path))]
    tags += [k + ":" + n for k, _, path in (t.partition(":") for t in tags)
             if k != "MAY_WRITE" and (n := _normal(path)) != path]
    # a pattern under ~ is also each folder of an agent's it may match (`rm -rf ~/.cla*` deletes ~/.claude), and a
    # pattern anywhere each protected path it may make (`cp x ~/.cur?or/plugins/…`: _protected_forms)
    forms = [kf for k, _, path in (t.partition(":") for t in tags) if k != "MAY_WRITE" and shell._GLOB.search(path)
             for kf in forms_of(k, path)]
    tags += [k + ":" + f for k, f in forms] + [k + ":" + r for k, f in forms if k in ("DELETE_TARGET", "MODE_TARGET")
                                                for r in _roots_below(f)]
    # once every path is read as it is where it lands: what a folder's contents may write there (TREE_TARGET) is held
    # where it may take a trust root's place, and a name copied into a folder is a write where the folder holds a
    # protected path
    resolved = [(k, path) for k, _, path in (t.partition(":") for t in tags)]
    tags += ["ROOT_TARGET:" + p for k, p in resolved if k == "NAMED_TARGET" and _names_root(p)]
    tags += ["ROOT_TARGET:" + p for k, p in resolved if k == "INSIDE_TARGET" and _names_root(p, along=False)]
    tags += ["WRITE_TARGET:" + p for k, p in resolved if k == "INTO_TARGET" and _holds_protected(p.rpartition("/")[0])] + [
        t for k, p in resolved if k in ("TREE_TARGET", "WORKTREE_TARGET") for t in [
            "WRITE_TARGET:" + p, *_held_roots(p, k == "TREE_TARGET")]]


# where the Python the plugin's hook runs and a harness's hooks folder that no whole-folder rule keeps live, in full
# under a home: deleting, moving or changing the mode of a folder along one takes it too (_under_roots)
# lean: a UV_TOOL_DIR, PIPX_HOME or XDG_DATA_HOME elsewhere isn't read; list a place when a rule protects it
_ROOT_PLACES = tuple(tuple(p.split("/")) for p in (
    ".local/bin/tracekit", ".local/share/uv/tools/tracekit-ai", ".local/share/pipx/venvs/tracekit-ai",
    ".local/pipx/venvs/tracekit-ai", "Library/Application Support/pipx/venvs/tracekit-ai", "Documents/Cline/Hooks"))


# a command that says where Tracekit's Python lives, run in a substitution: read from the first `$(` or backquote of a
# line on, a plain search of the rest (a lazy match from each of many would take quadratic time)
_WHERE_ROOT = re.compile(r"(?:command\s+-v|which|type\s+-p|whereis)\s+tracekit|\buv\s+(?:tool|python)\s+(?:dir|list)|"
                         r"\bpipx\s+(?:environment|list)|\.local/share/(?:uv|pipx)|uv/tools|pipx/venvs|uv/python|\.local/bin")
# an unresolved expansion followed by the name of a trust root's own folder or file
_ROOT_NAME = re.compile(r"tracekit-ai|uv/python|\.local/bin/tracekit")
_EXPANSION_AT = re.compile(r"\$[\w({@*#?!$-]|`")   # (a `$` that ends a pattern, `\.py$`, is no expansion)
_SUBSTITUTION_AT = re.compile(r"\$\(|`")


def _after(start, pattern, text):
    """Whether `pattern` is found after the first `start` in a line of `text`."""
    return any((m := start.search(line)) and pattern.search(line, m.end()) for line in text.split("\n"))


def _from_where(path):
    return _after(_SUBSTITUTION_AT, _WHERE_ROOT, path)


def _root_named(path):
    return _after(_EXPANSION_AT, _ROOT_NAME, path)


# the names of a trust root's folders and files, which a pattern after an unresolved expansion may make
_ROOT_NAMES = frozenset(c for place in _ROOT_PLACES for c in place) | {"tracekit-ai", "python"}


def _root_glob(path):
    """Whether a pattern after an unresolved expansion (`$D/tracekit-?i`, `$D/*`) may make one of _ROOT_NAMES."""
    parts = path.split("/")
    k = next((i for i, p in enumerate(parts) if _EXPANSION_AT.search(p)), None)
    after = parts[k + 1:k + 9] if k is not None else []
    return any(   # (a `**` before the last name is a find's any depth: what it finds is named by the last)
        shell._GLOB.search(p) and len(p) < 256 and not (p == "**" and i < len(after) - 1)
        and any(shell._glob_fits(shell._glob_tokens(p), n, True) for n in _ROOT_NAMES) for i, p in enumerate(after))


# the paths, by their components, whose files an agent's harness runs or reads as settings, hooks and plugins (as
# TK-F009 and TK-F015 name them) and the Python the Tracekit plugin's hook runs (TK-D007, TK-D013): a pattern in a
# write, delete or mode target may make one of these
# lean: a path the rules name only through a variable or a file name alone (opencode.json, crush.json) and PowerShell's
# profiles aren't listed; add a path here when a rule protects it
_PROTECTED_PATHS = tuple(tuple(p.split("/")) for p in (
    ".claude", ".codex", ".gemini", ".opencode", ".kilo", ".kilocode", ".qwen", ".factory", ".devin", ".cline",
    ".hermes", ".openhands", ".copilot", ".jcode", ".kiro", ".openinterpreter", ".codebuddy", ".claude.json", ".mcp.json",
    ".cursor", ".agents", ".clinerules", ".github", ".goose", ".config",   # (a whole one deleted; or as the paths below)
    ".cursor/plugins", ".cursor/hooks.json", ".cursor/mcp.json", ".clinerules/hooks", "Documents/Cline/Hooks",
    ".github/hooks",
    ".github/copilot/settings.json", ".github/copilot/settings.local.json", "etc/github-copilot", ".agents/hooks.json",
    ".agents/plugins", ".agents/recipes", ".agents/agents", ".agents/skills", ".goose/recipes", ".goose/agents",
    ".config/opencode", ".config/kilo", ".config/goose", ".config/crush", ".config/devin", ".config/gptme",
    ".local/bin/tracekit", "uv/tools/tracekit-ai", "pipx/venvs/tracekit-ai")) + tuple(
    place[:k] for place in _ROOT_PLACES for k in range(1, len(place) + 1))   # (and the folders along each trust root)
_LONGEST = max(map(len, _PROTECTED_PATHS))
_HOME_FOLDERS = ("Documents", "Library")   # (the first folders of _ROOT_PLACES that only a home has)
# the paths a `**` under a home may stand for the folders of: the Python's (its trust roots and the folders along them)
# and those that start with a dot, which a `**` can't make, so the path spells them out
_STAR_PATHS = frozenset(tuple(c.casefold() for c in place[:k]) for place in _ROOT_PLACES if place[0] != "Documents"
                        for k in range(1, len(place) + 1)) | frozenset(
    tuple(c.casefold() for c in chain) for chain in _PROTECTED_PATHS if chain[0][:1] == ".")
_BY_FIRST = {}   # each path of _PROTECTED_PATHS under its first component, casefolded: a literal one is a lookup
for _path in _PROTECTED_PATHS:
    _BY_FIRST.setdefault(_path[0].casefold(), []).append(_path)
# the first components a pattern may make, as written: one that starts with a dot only dot names, any other the rest
_FIRSTS = {dot: list(dict.fromkeys(p[0] for p in _PROTECTED_PATHS if (p[0][:1] == ".") == dot)) for dot in (True, False)}
_PATTERNED_MAX = 32   # the patterned components of one path read: a bound that keeps the reading linear


_FORMS_MAX = 64   # the forms one path reads as: past it the path is unread (held)


def _protected_forms(path, options=(), work=None):
    """`path` with each run of its components that matches one of _PROTECTED_PATHS, a pattern among them, written as
    that path: as bash matches a pattern (shell._glob_fits), a leading dot only by a dot (`.cur?or/plug?ns` is
    .cursor/plugins, `.*/plugins` is too, `*/plugins` isn't), unless the line's glob `options` (shell._glob_options)
    hold dotglob (`*/plugins` is then too, where a home or the folder the line starts in may hold it) or nocaseglob
    (`.CUR?OR` is .cursor); "unread" ones read as both. A component `**` is zero or more folders (zsh's, and bash's
    with globstar) under a home: each of none to _LONGEST - 1 of them, `~/.local/**/bin` is also ~/.local/bin. Read around its
    first _PATTERNED_MAX patterned components; at most two `**` and _FORMS_MAX forms, else unread (ParseError); the
    forms are charged to `work` (shell.charge).
    lean: an option a profile, the environment or an earlier call sets isn't read; a path over 4 KiB gets each form only
    up to the protected path it makes; docs/limits.md says what to do"""
    parts = path.split("/")
    homed = any(_HOME_START.fullmatch("/".join(parts[:n])) for n in (1, 2, 3))   # (a `**` is read under a home only)
    stars = [i for i, p in enumerate(parts) if p in ("**", "***")] if homed else []
    if len(stars) > 2:
        raise shell.ParseError("a path with more than two ** components is not supported")
    out = []
    for counts in itertools.product(range(_LONGEST), repeat=len(stars)):
        made, at = list(parts), 0
        for i, k in zip(stars, counts):
            made[i + at:i + at + 1] = ["*"] * k
            at += k - 1
        out += _forms_of(made, options, len(path) <= 4096, bool(stars)) + (
            ["/".join(made)] if stars and not any(map(shell._GLOB.search, made)) else [])
    out = list(dict.fromkeys(out))
    if len(out) > _FORMS_MAX:
        raise shell.ParseError("a pattern that reads as more than %d protected paths" % _FORMS_MAX)
    shell.charge([0] if work is None else work, sum(map(len, out)))
    return out


def _forms_of(parts, options, whole, named=False):
    """_protected_forms' forms of one path, as its components (`whole`: with those after the protected path; `named`:
    only a path of the Python's (_STAR_PATHS) that starts at a name the path spells out or in a home, and ends at its end or goes on from
    by a name it spells out)."""
    dotglob, nocase = bool({"dotglob", "unread"} & set(options)), bool({"nocaseglob", "unread"} & set(options))
    out = []
    patterned = [i for i, p in enumerate(parts) if shell._GLOB.search(p)][:_PATTERNED_MAX]
    tokens = {i: shell._glob_tokens(parts[i]) for i in patterned}   # (a component past them reads as written)
    # each pattern's runs of plain characters, which a name it makes holds: a quick no before _glob_fits, read from its
    # tokens (a bracket holding `[` ends where bash ends it); none read for one with a backslash, which escapes them
    pieces = {i: None if "\\" in parts[i] else "".join(t if isinstance(t, str) else "\0" for t in tokens[i]).split("\0")
              for i in patterned}
    if nocase:
        pieces = {i: p and [c.casefold() for c in p] for i, p in pieces.items()}
    dot = {i: tokens[i][:1] == ["."] for i in patterned}   # a literal leading dot, escaped too: it may make a dot name
    # `*`, `.*`: any name (any dot name), the dot rule aside
    anything = {i for i in patterned if set(parts[i][1:] if parts[i][:1] == "." else parts[i]) == {"*"}}

    def fits(i, n):
        if parts[i].casefold() == n.casefold():   # a folder written out: the file system may ignore its case (macOS)
            return True
        if i not in tokens or not (dot[i] or dotglob) and n[:1] == "." or pieces[i] and not all(
                c in (n.casefold() if nocase else n) for c in pieces[i]):
            return False
        return i in anything or shell._glob_fits(tokens[i], n, nocase)   # a pattern: bash matches it in the name's case

    def rooted(i):   # where a dot folder is a harness's: in a home, or the folder the line starts in
        return not i or bool(_HOME_START.fullmatch("/".join(parts[:i]) or "/")) or set(parts[:i]) <= {"", "."}
    for i in sorted({i - j for i in patterned for j in range(_LONGEST) if i - j >= 0}):
        firsts = [parts[i]] if parts[i].casefold() in _BY_FIRST else [
            n for n in (_FIRSTS[True] * (dotglob and rooted(i)) + _FIRSTS[False] if dotglob else _FIRSTS[dot[i]])
            if fits(i, n)] if i in tokens else []
        # (a pattern makes a folder that only a home has, Documents or Library, only in a home)
        for names in (names for n in firsts for names in _BY_FIRST[n.casefold()] if (
                rooted(i) or i not in tokens or names[0] not in _HOME_FOLDERS) and (
                not named or tuple(c.casefold() for c in names) in _STAR_PATHS)):
            span = range(i, i + len(names))
            if span[-1] < len(parts) and any(k in tokens for k in span) and all(map(fits, span[1:], names[1:])) and (
                    not named or span[-1] + 1 == len(parts) or not shell._GLOB.search(parts[span[-1] + 1])):
                out.append("/".join(parts[:i] + list(names) + (parts[i + len(names):] if whole else [])))
    return out


def _env_chdir(argv):
    """(the folder env -C or --chdir runs its command in (None without one), where in argv the command it runs starts,
    None with none)."""
    args, i, folder = argv[1:], 0, None
    while i < len(args):
        a = args[i]
        if re.fullmatch(r"-[iv0]*C|--chdir", a):
            folder, i = (args[i + 1] if i + 1 < len(args) else None), i + 2
        elif re.match(r"-[iv0]*C.|--chdir=", a):
            folder, i = a.partition("=")[2] if a.startswith("--") else a[a.index("C") + 1:], i + 1
        elif a in ("-u", "--unset", "-P", "-a", "--argv0", "-S", "--split-string"):
            i += 2
        elif a.startswith("-") or "=" in a:
            i += 1
        else:
            break
    return folder, (i + 1 if i < len(args) else None)


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
    exe = _program(argv)
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


# the folders under a home a find's `**` may stand for that the rules protect, so a protected name it tests is read in
# each (`find ~ -name config` finds ~/.ssh/config), when it searches a home (or all of /)
_HOME_START = re.compile(r"~[^/]*|\$\{?HOME\}?|/|/root|/(?:home|Users)/[^/]+|[A-Za-z]:[/\\]Users[/\\][^/\\]+", re.I)
_FIND_FOLDERS = (".ssh", ".aws", ".git", ".claude", ".codex", ".gemini", ".hermes", ".config")

def _under_roots(path, home=False, one_part=True):
    """Each trust root `path` is a folder along, as the parts of the root below `path` (`~/.local/share/uv` holds
    uv/tools/tracekit-ai): where its last parts are the first of one of _ROOT_PLACES (a dot folder alone, else two or
    more, so a project's `uv` or `library` is none), or, with `home`, `path` is a home, which holds them whole. A path
    that is neither absolute nor under ~ or $ is read as written only (a relative one may be anywhere; a cd's is
    joined)."""
    if path[:1] not in ("/", "~", "$"):
        return []
    path = _normal(path).rstrip("/") or "/"
    parts = path.casefold().split("/")
    at_home = home and _HOME_START.fullmatch(path)
    in_home = len(parts) > 1 and bool(_HOME_START.fullmatch("/".join(path.split("/")[:-1]) or "/"))   # (~/Library, not a project's)
    return [place[k:] for place in _ROOT_PLACES for k in range(len(place) - 1, -1, -1)
            if k == 0 and at_home or k and parts[-k:] == [c.casefold() for c in place[:k]] and (
                k > 1 or place[0][:1] == "." or in_home and one_part)]


def _roots_below(path, home=False, one_part=True):
    """The trust roots a delete or move of `path` takes (_under_roots), each as a path."""
    return [path.rstrip("/") + "/" + "/".join(rest) for rest in _under_roots(path, home, one_part)]


def _names_root(path, along=True):
    """Whether `path` is a trust root, is under one, or (`along`) is a folder along one (`~/.local/share/uv`,
    `~/.local/bin`). A bare home is none: what is written in it is the member or path that names a root."""
    if path[:1] not in ("/", "~", "$"):
        return False
    path = _normal(path).rstrip("/") or "/"
    parts = tuple(path.casefold().split("/"))
    return along and bool(_under_roots(path)) or any(
        parts[i:i + len(place)] == place for place in _ROOT_FOLDED for i in range(len(parts) - len(place) + 1))


_ROOT_FOLDED = tuple(tuple(c.casefold() for c in place) for place in _ROOT_PLACES)


def _above_home(dest):
    """Whether `dest` is a home or a folder above one (/, /Users, /home): anything it holds is written there."""
    d = dest.rstrip("/") or "/"
    return bool(_HOME_START.fullmatch(d) or re.fullmatch(r"/(?:home|Users|root)?|(?:~[^/]*|\$\{?HOME\}?)(?:/\.\.)+", d))


def _held_roots(dest, home=True):  # (home False: a git worktree writer's folder, whose one-part folders (Documents) are no root)
    """What extracting or merging into `dest` may put in a trust root's place, each as ROOT_TARGET (TK-F015 holds
    it; a write that names a root is TK-D007's, denied): the roots below `dest`, and, with `home`, a home or a folder above
    one (an archive's unread members, a patch, a copy of a folder's contents there may be a root, the client record, a
    harness's settings). A git work tree writer's bare home (`home` False: a pull, a checkout of a branch, a stash pop)
    holds none: what it names there is read as a path (_tree_writes)."""
    return ["ROOT_TARGET:" + r for r in _roots_below(dest, home, home)] + (
        ["ROOT_TARGET:" + dest] if home and _above_home(dest) else [])


def _find_starts(args):
    """The positions in a find's arguments of its start paths (after its options: -L, -H, BSD's -E, -x …, and `--`)."""
    starts = []
    for i, arg in enumerate(args):
        if re.fullmatch(r"-[A-Za-z]|-O[0-9]*|--", arg):
            continue
        if arg.startswith("-") or arg in ("!", "("):
            break
        starts.append(i)
    return starts


def _find_in(argv, folder):
    """A find's argv with each relative start path read from `folder`."""
    out = list(argv)
    for i in _find_starts(argv[1:]):
        out[i + 1] = out[i + 1] if out[i + 1].startswith(("/", "~", "$")) else posixpath.join(folder, out[i + 1])
    return out


def _find_files(args, work):
    """The files a find's arguments find, as the rules read paths: under each start path (after its options: -L, -H,
    BSD's -E, -x …, and `--`; `.` when none), each name its -name or -iname tests (`./**/.env`; a protected name of
    shell.GLOB_NAMES it is or a pattern may make also in each of _FIND_FOLDERS, `~/.ssh/config`; under a .git
    folder, also in its hooks: `.git/hooks/pre-commit`), else
    the start path and all under it; what its path tests and -files0-from name (`-path '*/x/*'`; -delete implies
    -depth, under which -prune doesn't keep find out of a folder); and the log and history names among its tests. A
    name test that is negated (`! -name`, `-not -name`) or pruned names no file it finds."""
    starts = list(dict.fromkeys(args[i] for i in _find_starts(args)))
    # each name test's value that finds files: neither negated (before its test) nor pruned (after it)
    kept = [i for i in range(1, len(args)) if args[i + 1:i + 2] != ["-prune"]]
    tested = list(dict.fromkeys(args[i] for i in kept if args[i - 1] in ("-name", "-iname") and
                                args[max(i - 2, 0):i - 1] not in (["!"], ["-not"])))
    # each protected name a name or pattern stands for (`*.py` and `.DS_Store` stand for none: read as they are)
    # (find matches as fnmatch does: `*` and `?` match a leading dot, -iname in any case)
    folded = {args[i] for i in kept if args[i - 1] == "-iname"}
    names = [n for t in tested for n in [t, *shell._unglob(t, ("dotglob",) + ("nocaseglob",) * (t in folded))]
             if n in shell.GLOB_NAMES]
    paths = [p for i in range(1, len(args)) if args[i - 1] in ("-path", "-ipath", "-wholename", "-iwholename",
                                                                 "-regex", "-iregex", "-files0-from")
             for p in [args[i], *shell._unglob(args[i], ("dotglob",))]]
    starts = starts or ["."]
    # each trust root under a start, and each folder along the way, that a name test finds (find matches a name as
    # fnmatch does, a `*` matching a leading dot; a path whole, a `*` matching `/` too) with what it takes of a root, and
    # from a start short of a home what a root holds: a name test's name inside it, any file for a path test (`find ~/.local/bin -name 'trace?it' -delete`, `find ~/.local/share/uv
    # -name python -delete`)
    path_tests = [(args[i], args[i - 1] in ("-ipath", "-iwholename")) for i in kept
                  if args[i - 1] in ("-path", "-ipath", "-wholename", "-iwholename")]
    by_path = bool(path_tests)
    # a test that finds only what no trust root is (a link that points nowhere, an empty file or folder) leaves the
    # start's contents out of a delete: `find ~/.local/bin -xtype l -delete`, when it is all of the expression (an AND of
    # -type, -empty, -xtype l and depth limits, -delete last, no -L or -H, which change what -xtype tests)
    after = args[(_find_starts(args) or [0])[-1] + 1:]
    safe, saw, i = bool(after) and after[-1] == "-delete" and not any(
        re.fullmatch(r"-[LH]+", a) for a in args[:(_find_starts(args) or [0])[0]]), False, 0
    while safe and i < len(after):
        a = after[i]
        saw |= a == "-empty" or a == "-xtype" and after[i + 1:i + 2] == ["l"]
        i += 1 + (a in ("-type", "-xtype", "-maxdepth", "-mindepth"))
        safe = a in ("-empty", "-delete", "-depth", "-xdev", "-mount", "-a", "-and", "-type", "-xtype", "-maxdepth",
                     "-mindepth")
    safe = safe and saw
    # each trust root under a start, and each folder along the way, that a name test finds (find matches a name as
    # fnmatch does, a `*` matching a leading dot; a path whole, a `*` matching `/` too) with what it takes of a root, and
    # from a start short of a home what a root holds: a name test's name inside it, any file for a path test (`find ~/.local/bin -name 'trace?it' -delete`, `find ~/.local/share/uv
    # -name python -delete`)
    path_tests = [(args[i], args[i - 1] in ("-ipath", "-iwholename")) for i in kept
                  if args[i - 1] in ("-path", "-ipath", "-wholename", "-iwholename")]
    by_path = bool(path_tests)
    reached = []
    shell.charge(work, len(starts) * sum(map(len, tested)))   # (each start with each test)
    tokens = [(shell._glob_tokens(t), t in folded) for t in tested]
    for s in starts if tested or by_path else ():
        for rest in _under_roots(s, True):
            for k in range(1, len(rest) + 1):
                here = s.rstrip("/") + "/" + "/".join(rest[:k])
                if any(shell._glob_fits(t, rest[k - 1], fold) for t, fold in tokens) or any(
                        fnmatch.fnmatchcase(here.casefold() if fold else here, pattern.casefold() if fold else pattern)
                        for pattern, fold in path_tests):
                    reached += [here, *_roots_below(here)]
                if k == len(rest) and not _HOME_START.fullmatch(s.rstrip("/") or "/"):
                    reached += [here + "/**/" + t for t in tested] + [here + "/**"] * by_path
    # a name found in a .git folder may be one of its hooks (`find .git -name pre-commit`)
    hooks = [f"{s.rstrip('/')}/hooks/{t}" for s in starts if s.rstrip("/").endswith(".git") for t in tested]
    # a protected name in one of the folders under a home that keep them (`find ~ -name config` finds ~/.ssh/config;
    # a project's config is no such file)
    homes = [s for s in starts if _HOME_START.fullmatch(s.rstrip("/") or "/")]
    found = [f"{s.rstrip('/')}/**/{t}" for s in starts for t in tested] + hooks + [
        f"{s.rstrip('/')}/{d}/{n}" for s in homes for n in names for d in _FIND_FOLDERS] + [
        f"{s.rstrip('/')}/{n}" for s in starts for n in names] if tested else [
        s.rstrip("/") + "/**" for s in starts if not safe]
    return list(dict.fromkeys(starts + found + reached + paths + [args[i] for i in kept if _log_or_history(args[i])]))


# an awk program's output redirection: > or >> and the expression it writes to, up to a `;`, `}`, newline or `|`
_AWK_PART = r'"[^"\n]*"|ARGV\[[^]\n]*\]|[A-Za-z_]\w*'
_AWK_OUTPUT = re.compile(r'>>?\s*(\([^()\n]*\)|(?:%s)(?:[ \t]+(?:%s))*)' % (_AWK_PART, _AWK_PART))
_AWK_ASSIGN = re.compile(r'\b([A-Za-z_]\w*)\s*=\s*"([^"\n]*)"')


def _awk_outputs(args):
    """The files an awk program prints to (print or printf > or >>): a string, a variable the command line (-v) or
    the program gives a string, ARGV[n] (its n-th operand), or a concatenation of those in parentheses (`> (".e"
    "nv")`, `-v f=.env … > f`), and FILENAME or ARGV[i] of an index it computes, each file it is given."""
    program = shell._awk_program(args) or ""
    given = dict(_AWK_ASSIGN.findall(program))
    given.update(a.partition("=")[::2] for a, prev in zip(args, [""] + args) if prev in ("-v", "--assign") and "=" in a)
    operands = args[args.index(program) + 1:] if program in args else []
    out = []
    for target in _AWK_OUTPUT.findall(program):
        parts = re.findall(r'("[^"\n]*")|ARGV\[\s*([^]\n]*?)\s*\]|([A-Za-z_]\w*)', target)
        if parts == [("", "", "FILENAME")] or any(i and not i.isdigit() for _, i, _ in parts):   # each it reads
            out += [a for a in operands if not re.match(r"[A-Za-z_]\w*=", a) and a != "-"]
        elif parts and all(text or name in given or i and 0 < int(i) <= len(operands) for text, i, name in parts):
            out.append("".join(text[1:-1] if text else operands[int(i) - 1] if i else given[name]
                               for text, i, name in parts))
    return out


# programs that write the file an option names (sort -o, iconv -o, gpg -o, openssl -out, base64 -o, uudecode -o; a
# download's: download_writes) or one of their operands: uniq's second, xxd -r's second, sponge's, patch's (the file
# it patches, in its -d folder), ed's and ex's, emacs's (--batch with --eval edits them unseen), and vim's, vi's or
# nvim's unless read-only (-R, -M; a script, -c, + or --headless edits them unseen, and a terminal's keys in one); the
# options of theirs that take a value, which is no operand
_OUTPUT_OPTION = {"sort": ("-o", "--output"), "iconv": ("-o", "--output"), "gpg": ("-o", "--output"),
                  "gpg2": ("-o", "--output"), "openssl": ("-out",), "patch": ("-o", "--output"),
                  "base64": ("-o", "--output"), "uudecode": ("-o", "--output-file")}
# ssh-keygen's options that take a value (its getopt string, OpenSSH 10.2), and its modes that do not make -f a file
# the write rules read. Reading: -i and -e export to stdout, -y prints the public key, -l and -B a fingerprint, -F finds
# a host in known_hosts, -r prints a fingerprint resource, -L shows a certificate, -Q checks a KRL, -M screen and every
# -Y mode read -f (an input file, a key that signs, allowed signers). -R is here because removing a host from
# known_hosts is not a write the rules read: the row at docs/limits.md and
# test_a_host_key_appended_to_known_hosts_is_its_only_write_not_denied record known_hosts as the exception (appending a
# host key there is ordinary work, so naming it is not a write). Every other mode writes what -f names (no mode at all:
# a new key pair; -p and -c rewrite the key in place; -H rewrites known_hosts; -k a KRL; -A host keys under it), and a
# mode this list does not name is read as writing.
_SSH_KEYGEN_VALUED = frozenset("CDEFIMNOPRVYZabfgmnrstwz")
_SSH_KEYGEN_READS = frozenset("ieylBFrLQRMY")


def _ssh_keygen_writes(args):
    """The files `ssh-keygen ARGS` writes by -f, its options read as getopt reads them (a cluster's letters, a valued
    option's value attached or the next word, options after operands too, none after `--`): none in a reading mode."""
    modes, files, i = set(), [], 0
    while i < len(args) and args[i] != "--":
        a = args[i]
        for j, ch in enumerate(a[1:] if a.startswith("-") else "", 1):
            modes.add(ch)
            if ch in _SSH_KEYGEN_VALUED:   # the rest of the word, else the next word, is its value
                value = a[j + 1:] or (args[i + 1] if i + 1 < len(args) else "")
                i += not a[j + 1:]
                if ch == "f" and value:
                    files.append(value)
                break
        i += 1
    return [] if modes & _SSH_KEYGEN_READS else files
_OUTPUT_OPERAND = {"uniq": 1, "xxd": 1, "sponge": 0, "patch": 0, "ed": 0, "red": 0, "ex": 0, "vim": 0, "vi": 0,
                   "nvim": 0, "emacs": 0}
_EDITS_ALL = ("ed", "red", "ex", "vim", "vi", "nvim", "emacs")   # an editor: every file it is given
_VALUED = {"patch": ("-i", "--input", "-p", "--strip", "-d", "--directory", "-D", "--ifdef", "-F", "--fuzz", "-r",
                     "--reject-file", "-B", "--prefix", "-Y", "--basename-prefix", "-z", "--suffix", "-V",
                     "--version-control", "-g", "--get"),
           **dict.fromkeys(("vim", "vi", "nvim", "ex"), ("-c", "--cmd", "-S", "-u", "-U", "-i", "-T", "-w", "-W", "-t",
                                                          "-q", "--listen", "--startuptime")),
           "emacs": ("--eval", "-l", "--load", "-f", "--funcall", "--insert", "-L", "--directory", "-t", "--terminal",
                     "-d", "--display", "--chdir", "-u", "--user", "--script", "-x", "--dump-file", "-T", "--title",
                     "--name", "-g", "--geometry", "-fn", "--font", "-fg", "-bg")}


def _outputs(exe, args):
    """The files `exe ARGS` writes, by _OUTPUT_OPTION and _OUTPUT_OPERAND (a word after an option counts as its
    value, so an operand is only a word no option before it takes)."""
    options = _OUTPUT_OPTION.get(exe, ())
    out = [b for a, b in zip(args, args[1:]) if a in options] + [
        a.partition("=")[2] if a.startswith("--") else a[len(o):] for a in args for o in options
        if a.startswith(o) and a != o and (a[len(o)] == "=" if a.startswith("--") else len(o) == 2)]
    valued = options + _VALUED.get(exe, ())
    if exe in _OUTPUT_OPERAND and not (exe in ("vim", "vi", "nvim") and any(re.fullmatch(r"-[a-zA-Z]*[RM][a-zA-Z]*", a)
                                                                           for a in args)) and (
            exe != "xxd" or any(re.fullmatch(r"-[a-z]*r[a-z]*", a) for a in args)):
        operands = [a for a, before in zip(args, [""] + args) if not a.startswith(("-", "+")) and before not in valued]
        out += operands[_OUTPUT_OPERAND[exe]:][:None if exe in _EDITS_ALL else 1]
        folder = [b for a, b in zip(args, args[1:]) if a in ("-d", "--directory")] + [
            a.partition("=")[2] for a in args if a.startswith("--directory=")] if exe == "patch" else []
        out += [posixpath.join(folder[-1], o) for o in out if folder and not o.startswith(("/", "~", "$"))]
    return out


# the in-place editors (GNU sed as gsed, a versioned perl or ruby: perl5.34), and the switches each reads in a cluster
# before its in-place one: sed's flags (then -e, -f or -l take the rest), perl's and ruby's flags, those that take
# digits and go on (-l, -0, ruby's -W and -T), and those that take the rest as their value (-e, -I, -M …)
_EDITOR = re.compile(r"(?:g(?=sed))?(sed|perl|ruby)[0-9.]*")
_IN_PLACE_FLAGS = {"sed": ("nrsuzEb", ""), "perl": ("acnpsStTuUvwWX", "l0"), "ruby": ("acdlnpsSvwyh", "0WT")}


def _in_place(editor, arg):
    """Whether `arg` makes sed, perl or ruby edit its files in place: -i or BSD sed's -I alone or after flags in a
    cluster (`sed -Ei`, `perl -spi`, `perl -lpi`, `ruby -Wpi`), or a prefix of sed's --in-place (`--in`)."""
    if editor is None:
        return False
    if arg.startswith("--"):
        flag = arg.partition("=")[0]
        return editor == "sed" and len(flag) > 2 and "--in-place".startswith(flag)
    flags, digits = _IN_PLACE_FLAGS[editor]
    i = 1
    while arg[:1] == "-" and i < len(arg):
        c = arg[i]
        if c == "i" or c == "I" and editor == "sed":
            return True
        if c in digits:
            i += 1
            while i < len(arg) and arg[i].isdigit():
                i += 1
        elif c in flags:
            i += 1
        else:
            return False
    return False


# decompressors (also gzip -d and kin) and the suffix each file loses (.tgz is a .tar)
_DECOMPRESSORS = {"gunzip": "gzip", "unxz": "xz", "bunzip2": "bzip2", "unlzma": "lzma", "unzstd": "zstd",
                  "uncompress": "compress", "unlz4": "lz4"}
_PACKED = re.compile(r"(?i)\.(?:t(?:gz|az|xz|bz2?|lz|zst))$|\.(?:gz|z|xz|lzma|bz2|zst|lz4|lz|br)$")
# the options of these writers that take the next word (which is then no file)
_WRITER_VALUED = {
    "yq": ("-o", "--output-format", "-p", "--input-format", "-I", "--indent", "--from-file", "--expression",
           "--split-exp", "--arg", "--argjson", "--rawfile", "--slurpfile"),
    "sd": ("-f", "--flags", "-n", "--max-replacements"),
    "dos2unix": ("-c", "--convmode", "-ul", "-cp"), "split": ("-l", "--lines", "-b", "--bytes", "-C", "--line-bytes",
                                                             "-n", "--number", "-a", "--suffix-length", "-t",
                                                             "--separator", "--additional-suffix", "--filter"),
    "csplit": ("-f", "--prefix", "-b", "--suffix-format", "-n", "--digits"),
    "tar": ("-f", "--file", "-C", "--directory", "-T", "--files-from", "-X", "--exclude-from", "-b",
            "--blocking-factor", "-H", "--format", "-I", "--use-compress-program", "--transform", "--strip-components",
            "-N", "--newer"),
    "unzip": ("-d", "-P", "-x"), "ditto": ("--arch", "--bom")}


def _operands(exe, args):
    """`args` without options and the words _WRITER_VALUED's options take."""
    valued, out, skip = _WRITER_VALUED.get(exe, ()), [], 0
    for a in args:
        if skip:
            skip -= 1
        elif a in valued:
            skip = 2 if a in ("--arg", "--argjson", "--rawfile", "--slurpfile") else 1
        elif not a.startswith("-") or a == "-":
            out.append(a)
    return out


_COMPRESSORS = ("gzip", "xz", "bzip2", "lzma", "zstd", "lz4", "lzip", "compress", "brotli")


def _cluster(a):
    """Whether `a` is one dash and an option cluster of letters or digits (-xzf, -dfo)."""
    return len(a) > 1 and a[0] == "-" and a[1] != "-" and a[1:].isalnum()


def _in_folder(folder, members):
    """Each member an extract writes in its folder (a leading / dropped, as tar and unzip drop one), or the folder
    itself, `DIR/`, when it names none."""
    return [posixpath.join(folder, m.lstrip("/")) for m in members] if members else [folder.rstrip("/") + "/"]


def _decompressed(tool, args):
    """The files a decompressor writes: its -o or --output (zstd, lz4, brotli; also last in a cluster, -dfo FILE),
    lz4's second operand, else each file without its suffix (gzip's -S or --suffix too), in zstd's --output-dir-flat
    folder, or under its --output-dir-mirror folder at the file's own path; none when it prints, tests or lists (-c,
    -t, -l)."""
    if any(a in ("--stdout", "--to-stdout", "--test", "--list") or _cluster(a) and set(a[1:]) & set("ctl")
           for a in args):
        return []
    outputs, suffix, operands, skip, folder = [], None, [], None, None   # folder: (DIR, whether it mirrors the path)
    for a in args:
        if skip:
            if skip == "o":
                outputs.append(a)
            elif skip == "S":
                suffix = a
            else:
                folder = (a, skip == "--output-dir-mirror")
            skip = None
        elif tool == "zstd" and a.partition("=")[0] in ("--output-dir-flat", "--output-dir-mirror"):
            if "=" in a:
                folder = (a.partition("=")[2], a.startswith("--output-dir-mirror"))
            else:
                skip = a
        elif tool in ("zstd", "lz4", "brotli") and (a == "--output" or _cluster(a) and a[-1] == "o"):
            skip = "o"
        elif tool in ("zstd", "lz4", "brotli") and a.startswith("--output="):
            outputs.append(a.partition("=")[2])
        elif a in ("-S", "--suffix") or _cluster(a) and a[-1] == "S":
            skip = "S"
        elif a.startswith("--suffix="):
            suffix = a.partition("=")[2]
        elif not a.startswith("-"):
            operands.append(a)
    if outputs:
        return outputs
    if tool == "lz4" and len(operands) == 2 and not any(a in ("-m", "--multiple") for a in args):
        return operands[1:]
    if suffix:
        return [a[:-len(suffix)] for a in operands if a.endswith(suffix) and len(a) > len(suffix)]
    out = [_PACKED.sub(lambda m: ".tar" if m.group().lower().startswith(".t") else "", a) for a in operands
           if _PACKED.search(a)]
    if not folder:
        return out
    # recursive (-r) or given a folder, it writes files the line doesn't name into the folder: the folder itself
    walks = any(a == "--recursive" or _cluster(a) and "r" in a for a in args) or any(
        a in (".", "..") or a.endswith("/") for a in operands)
    return [folder[0].rstrip("/") + "/"] * walks + [
        folder[0].rstrip("/") + "/" + (a.lstrip("/") if folder[1] else posixpath.basename(a)) for a in out]


def _extracted_tar(args):
    """What tar -x writes: each member it names in the folder of the last -C before it (GNU tar's) and of the first -C
    on the line (bsdtar's), or, naming none, those folders (an old-style first word's letters take the next words in
    turn); None for a tar that doesn't extract."""
    first = args[0] if args and not args[0].startswith("-") else ""
    if not ("x" in first or any(a in ("--extract", "--get") or _cluster(a) and "x" in a for a in args)):
        return None
    rest, folders, takes = (args[1:] if first else args), [], [c for c in first if c in "fCTXb"]
    operands, skip = [], None
    for a in rest:
        if takes:
            if takes.pop(0) == "C":
                folders.append(a)
            continue
        if skip:
            folders += [a] if skip in ("-C", "--directory") else []
            skip = None
        elif a.startswith("--directory="):
            folders.append(a.partition("=")[2])
        elif a in _WRITER_VALUED["tar"]:
            skip = a
        elif _cluster(a) and a[-1] in "fCTXb":
            skip = "-" + a[-1]
        elif a[:1] == "-" and a[1:2] != "-" and (c := a.find("C")) > 0 and len(a) > c + 1 and (
                c == 1 or a[1:c].isalnum()):
            folders.append(a[c + 1:])   # -Cdir, -xCdir
        elif not a.startswith("-"):
            operands.append((folders[-1] if folders else ".", a))
    first = folders[0] if folders else "."
    return list(dict.fromkeys([w for folder, m in operands for w in _in_folder(folder, [m]) + _in_folder(first, [m])]
                              or _in_folder(first, []) + _in_folder(folders[-1] if folders else ".", [])))


def _more_writes(exe, args):
    """The files these writers write, or None for a program that is none of them: yq -i's (the files after its
    expression), sd's (in place unless it previews), dos2unix's and kin's (in place, or -n's new files), a decompressor's
    (each file without its suffix, unless it prints or tests), ditto's (as cp's), an extract's (tar -x, unzip, 7z x or
    e: each member it names in its folder, or the folder itself, `DIR/`, whose files it can't tell), git config -f's
    file, and the files split and csplit make (their prefix, as a pattern)."""
    unix = re.sub(r"^(?:dos|unix|mac)2(?:dos|unix|mac)$", "dos2unix", exe)
    if exe == "yq":
        if not any(a in ("-i", "--inplace", "--in-place") or _cluster(a) and "i" in a for a in args):
            return []
        operands = [a for a in _operands(exe, args) if a not in ("eval", "e", "eval-all", "ea")]
        given = any(a.startswith(("--from-file", "--expression")) for a in args)
        return operands if given else operands[1:]
    if exe == "sd":
        return [] if any(a in ("-p", "--preview") for a in args) else _operands(exe, args)[2:]
    if unix == "dos2unix":
        operands = _operands("dos2unix", args)
        return operands[1::2] if any(a in ("-n", "--newfile") for a in args) else operands
    # (lz4 decompresses a .lz4 without -d, and writes its second operand either way)
    lz4 = exe == "lz4" and (len(ops := _operands(exe, args)) == 2 or any(o.lower().endswith(".lz4") for o in ops))
    tool = _DECOMPRESSORS.get(exe) or (exe if exe in _COMPRESSORS and any(
        a in ("--decompress", "--uncompress") or _cluster(a) and "d" in a for a in args) or lz4 else None)
    if tool:
        return _decompressed(tool, args)
    if exe == "ditto":
        operands = _operands(exe, args)
        return operands[-1:] + [operands[-1].rstrip("/") + "/" + s.rstrip("/").rsplit("/", 1)[-1] for s in operands[:-1]
                                if len(operands) > 2] if len(operands) > 1 else []
    if exe in ("tar", "bsdtar", "gtar"):
        return _extracted_tar(args)
    if exe == "unzip":
        folder, members, skip, excluding = ".", [], None, False
        for a in args:
            if skip:
                folder, skip = a, None
            elif a == "-x":   # the rest are names it leaves out
                excluding = True
            elif _cluster(a) and a[-1] == "d":   # -d DIR, -od DIR
                skip = True
            elif a.startswith("-d") and len(a) > 2:
                folder = a[2:]
            elif not a.startswith("-") and not excluding:
                members.append(a)
        return _in_folder(folder, members[1:])
    if exe in ("7z", "7za", "7zz", "7zr") and args[:1] in (["x"], ["e"]):
        folder = next((a[2:] for a in args if a.startswith("-o") and len(a) > 2), ".")
        operands = [a for a in args[1:] if not a.startswith("-")]
        return _in_folder(folder, operands[1:])   # (the first is the archive)
    if exe in ("split", "csplit"):
        operands = _operands(exe, args)
        prefix = next((b for a, b in zip(args, args[1:]) if a in ("-f", "--prefix")), None) or next(
            (a.partition("=")[2] for a in args if a.startswith("--prefix=")), None) if exe == "csplit" else \
            (operands[1] if len(operands) > 1 else None)
        return [(prefix or ("xx" if exe == "csplit" else "x")) + "*"]
    return None


def _printf_words(args):
    """The words printf FORMAT ARGS prints, split as xargs splits them: each conversion takes the next argument, and
    the format is used again while some are left."""
    if not args:
        return []
    fmt, rest, out = args[0], list(args[1:]), ""
    conversion = re.compile(r"%[-#0 +']*\d*(?:\.\d*)?[a-zA-Z%]")
    for _ in range(len(rest) + 1):
        out += conversion.sub(lambda m: "%" if m.group() == "%%" else rest.pop(0) if rest else "", fmt)
        if not rest or not any(m.group() != "%%" for m in conversion.finditer(fmt)):
            break
    return out.replace("\\n", "\n").replace("\\t", "\t").split()


# what changes a file's mode, owner, flags or ACL (_effects' MODE_TARGET): `chmod -x` or `chmod 000` stops a hook
# script from starting as surely as a write does, so TK-F015 reads these as it reads writes
# lean: icacls and attrib (Windows) and xattr aren't read; add one if it can stop a hook there
_MODE_CHANGERS = frozenset(("chmod", "chown", "chgrp", "chflags", "chattr", "setfacl"))
_MODE_WORD = re.compile(r"[0-7]{3,4}|-[rwxXst]+|[ugoa]*(?:[-+=](?:[rwxXst]*|[ugo]))+(?:,[ugoa]*(?:[-+=](?:[rwxXst]*|[ugo]))+)*")
_SELF = ("$USER", "${USER}", "$LOGNAME", "${LOGNAME}", "$(whoami)", "$(id -un)", "`whoami`", "`id -un`")


def _drops_access(exe, args):
    """Whether a mode, owner, flag or ACL change can take the owner's read or execute from a file, as a
    chmod 000 or -x or u-r does, or a chown to another user (SAFE_MODE_TARGET when not: `chmod 755 d`, `+x`, `chown
    $(whoami) d`, any chgrp). One it can't tell (a mode copied from a file, --reference) and chflags, chattr and
    setfacl, which may make a file immutable, do."""
    if exe == "chgrp":
        return False
    words = [a for a in args if not a.startswith("-") or _MODE_WORD.fullmatch(a)]
    if exe == "chown":
        owner = next((a.strip("'\"") for a in words), "").partition(":")[0]
        return not (owner in ("", *_SELF) or "/" in owner or owner[:1] == "~") or any(
            a.startswith("--reference") for a in args)
    if exe != "chmod":
        return True
    modes = [a for a in words if _MODE_WORD.fullmatch(a)]
    if not modes or any(a.startswith("--reference") for a in args):
        return True
    for mode in modes:
        if re.fullmatch(r"[0-7]{3,4}", mode):
            if int(mode[-3]) & 5 != 5:
                return True
            continue
        for clause in mode.lstrip("-").split(",") if mode[:1] != "-" else [mode]:
            who = re.match(r"[ugoa]*", clause).group()
            if who and not set(who) & {"u", "a"}:
                continue
            for op, perms in re.findall(r"([-+=])([rwxXst]*|[ugo])", clause[len(who):] if mode[:1] != "-" else clause):
                if op == "-" and set(perms) & set("rxXugo") or op == "=" and not (
                        "r" in perms and set(perms) & set("xX")):
                    return True
    return False


_CHAIN_PREFIXES = frozenset(tuple(c.casefold() for c in chain[:k]) for chain in _PROTECTED_PATHS
                            for k in range(1, len(chain) + 1))   # (each folder along a protected path, in any case)


def _holds_protected(dest):
    """Whether `dest`, a destination that may be a folder, ends in one that holds a protected path or is one."""
    parts = _normal(dest).casefold().split("/")
    return any(tuple(parts[-k:]) in _CHAIN_PREFIXES for k in range(1, min(len(parts), _LONGEST) + 1))


def _copies(dests, sources, work, merges=False, folder=False, contents=False, parents=False):
    """(what cp, mv, ln and install write, each source's name in each destination as INTO, the folders they write the
    contents of as TREE): each destination, and in it each source's name where the destination is a folder (`folder`:
    -t's, several sources) or ends in `/` or is a home, written; the name in any destination as INTO_TARGET, which
    _write_effects makes a write where the destination, resolved (a cd's, a link's), holds a protected path
    (`cp x ~/.local/bin` writes ~/.local/bin/x, `cp -R x/plugins ~/.cursor` ~/.cursor/plugins). TREE_TARGET (what a
    folder's contents may write, held by _held_roots): a source that is `dir/`, `.` or a pattern (a folder's contents:
    `cp -R evil/ dest` as macOS reads it), and with `merges` (cp -r, rsync) each name, which merges into a folder of
    that name. The pairs are charged to `work`."""
    dests = list(dict.fromkeys(dests))
    names = list(dict.fromkeys(src.rstrip("/").lstrip("/") if parents else src.rstrip("/").rsplit("/", 1)[-1]
                               for src in sources))   # (--parents: the whole path of a source, under the destination)
    shell.charge(work, sum(map(len, dests)) * max(len(names), 1) + sum(map(len, names)) * len(dests))
    written = [d for dest in dests for d in [dest] + [dest.rstrip("/") + "/" + name for name in names if (
        folder or dest.endswith("/") or dest in ("~", ".", "..") or _holds_protected(dest))]]
    into = [dest.rstrip("/") + "/" + name for dest in dests for name in names]
    contents = contents or any(src.endswith("/") or src.rstrip("/").rsplit("/", 1)[-1] in (".", "..") or shell._GLOB.search(src)
                               for src in sources)   # (contents: -T, whose destination is the folder itself)
    tree = [dest for dest in dests if contents] + (into if merges else [])
    return written, into, tree


def _command_effects(commands, work):
    out = []
    # what each pipeline's find, echo or printf prints, for a writer xargs runs there: it writes or deletes each name
    # (`find . -name .env | xargs sed -i …`, `echo .env | xargs …`, `printf '.e%s' nv | xargs …`); a stage that prints
    # what the line doesn't name (ls, grep, cat) may print each protected name one of its words is part of (`ls -a |
    # grep env` prints .env)
    prints = {}
    for c in commands if any(c.get("via", [])[-1:] == ["xargs"] for c in commands) else ():
        prog, words = _program(c["argv"]), [w for w in c["argv"][1:] if not w.startswith("-")]
        if prog == "find":
            found = _find_files(c["argv"][1:], work)
        elif prog in ("echo", "printf"):
            found = words + (_printf_words(words) if prog == "printf" else [])
        elif prog not in ("xargs", "gxargs") and c.get("via", [])[-1:] != ["xargs"]:
            parts = {p for w in words if len(p := re.sub(r"[\\^$.*+?()[\]{}|]", "", w).casefold()) > 1}
            found = [n for n in shell.GLOB_NAMES if any(p in n for p in parts)] + words + [w.rstrip("/") + "/*" for w in words if not shell._GLOB.search(w)]
        else:
            continue
        prints.setdefault(c.get("pipeline"), []).extend(found)
    for command in commands:
        try:
            out.extend(_effects_of(command, prints, work))
        except shell.ParseError:   # the budget is spent: the command's own words stand in for what it writes
            out.extend(_literal_effects(command))
    return out




def _effects_of(command, prints, work):
    """What one command writes, deletes or changes (_command_effects)."""
    out = []
    argv = command["argv"]
    if not argv:
        return out
    exe = _program(argv)
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
        return out
    printed = prints.get(command.get("pipeline"), []) if command.get("via", [])[-1:] == ["xargs"] else []
    if printed:
        out.extend(kind + ":" + path for t in _command_effects([{"argv": argv + ["{}"]}], work)
                   for kind, _, target in [t.partition(":")] if target == "{}" and kind != "MAY_WRITE"
                   for path in printed)
    if exe == "find":
        # what its -exec runs write (the parser doesn't emit them when a container runs the find: `docker exec c
        # find . -exec rm x \;`); -delete or an -exec rm (unlink, shred, truncate, mv {}) deletes each file found,
        # one that writes `{}` (sed -i, perl -i, cp /dev/null {}) writes it. An -exec's run ends at the first `;` or
        # `+`, so a find it runs (through git or a container) has no run of its own: the recursion stays shallow
        runs = _command_effects([{"argv": [run[0].casefold()] + run[1:]} for run in shell._find_execs(args)], work)
        out.extend(runs)
        # the file its -fprint, -fprint0, -fprintf or -fls writes its list into
        out.extend("WRITE_TARGET:" + b for a, b in zip(args, args[1:]) if a in ("-fprint", "-fprint0", "-fprintf",
                                                                              "-fls"))
        found = {t.partition(":")[0] for t in runs if t.partition(":")[2] == "{}"}
        if "-delete" in args or any(a in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(args)
                                    and shell.base_name(args[i + 1]) in (
                                        "rm", "unlink", "shred") for i, a in enumerate(args)):
            found.add("DELETE_TARGET")
        out.extend(kind + ":" + path for kind in sorted(found) for path in _find_files(args, work))
    elif exe in ("rm", "unlink", "shred", "truncate", "tee", "cp", "mv", "install", "ln", "link"):
        directories, operands, skip = [], [], False
        words = args
        if exe in ("cp", "mv", "install", "ln", "link"):
            directories, words = shell.target_directories(args)
        valued = ("-s", "--size", "-r", "--reference") if exe == "truncate" else (
            "-m", "--mode", "-o", "--owner", "-g", "--group", "-S", "--suffix")
        for arg in words:
            if skip:
                skip = False
            elif arg in valued:
                skip = True
            elif not arg.startswith("-") or arg == "-":
                operands.append(arg)
        if exe in ("rm", "unlink", "shred"):
            deleted, written = operands, []
        elif exe in ("truncate", "tee"):
            deleted, written = [], operands
        else:   # cp, mv, install and ln write the last operand or each -t directory, and in a directory each source's
            # name (`cp -t ~ x/.bash_history`, `cp x/.bash_history ~/`); mv also removes its sources
            sources = operands if directories else operands[:-1]
            written, into, tree = _copies(directories or operands[-1:], sources, work, exe == "cp" and any(
                re.fullmatch(r"-[A-Za-z]*[rRa][A-Za-z]*", a) or a in ("--recursive", "--archive") for a in args),
                bool(directories) or len(sources) > 1,
                exe == "cp" and any(re.fullmatch(r"-[A-Za-z]*T[A-Za-z]*", a) or a == "--no-target-directory" for a in args),
                exe == "cp" and "--parents" in args)
            out.extend(["INTO_TARGET:" + p for p in into] + ["TREE_TARGET:" + p for p in tree]
                       if exe in ("cp", "install") else ["INTO_TARGET:" + p for p in into])
            deleted = sources if exe == "mv" else []
        # tee's options come before its first file or `--` (after either, `-a` is a file: BSD's tee reads none
        # after a file, so `tee FILE -a` overwrites FILE)
        options = list(itertools.takewhile(lambda a: a.startswith("-") and a != "--", args))
        append = exe == "tee" and any(a in ("-a", "--append") or re.fullmatch(r"-[a-zA-Z]+", a) and "a" in a
                                      for a in options)
        out.extend(["DELETE_TARGET:" + path for path in deleted + [r for d in deleted for r in _roots_below(d)]] + [
            ("APPEND_TARGET:" if append and _KNOWN_HOSTS.search(path) else "WRITE_TARGET:") + path
            for path in written])
        if exe == "ln" or exe == "cp" and any(a in ("--link", "--symbolic-link")
                                              or re.fullmatch(r"-[A-Za-z]*[ls]\w*", a) for a in args):
            out.extend("MAY_WRITE:" + path for path in written)
    elif exe == "dd":
        out.extend("WRITE_TARGET:" + arg[3:] for arg in args if arg.startswith("of="))
    elif exe in _MODE_CHANGERS:   # each word but an option: the mode, owner or ACL with the files (none is a path)
        drops = _drops_access(exe, args)
        out.extend(("MODE_TARGET:" if drops else "SAFE_MODE_TARGET:") + p for a in args if not a.startswith("-")
                   for p in [a, *(_roots_below(a) if drops else [])])
    elif (written := _more_writes(exe, args)) is not None:
        out.extend("WRITE_TARGET:" + path for path in written)
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
        out.extend("DELETE_TARGET:" + a for d in (operands[:-1] if exe == "rsync" else operands)
                   for a in [d, *_roots_below(d)])
    elif (editor := _EDITOR.fullmatch(exe)) and any(_in_place(editor.group(1), a) for a in args):
        if editor.group(1) == "sed":   # the operands after the script: the first unless -e, -f or theirs give it
            files, script_seen, skip, suffix = [], False, False, False
            for arg in args:
                after_in_place, suffix = suffix, False
                if skip:
                    skip, script_seen = False, True
                elif after_in_place and (arg == "" or re.fullmatch(r"\.[\w.~-]*", arg)):   # BSD's -i '' or .bak
                    continue
                elif arg in ("--expression", "--file") or re.fullmatch(r"-[A-Za-z]*[ef]", arg):
                    skip = True
                elif arg.startswith(("--expression=", "--file=")) or re.match(r"-[A-Za-z]*[ef].", arg) and \
                        not arg.startswith("--"):
                    script_seen = True
                elif arg.startswith("-"):
                    suffix = bool(re.fullmatch(r"-[A-Za-z]*[iI]", arg))
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
        # git config's -f file, unless it only reads (--get, --list)
        if exe == "git" and "config" in args and not any(a.startswith(("--get", "--list")) or a == "-l"
                                                          for a in args):
            out.extend("WRITE_TARGET:" + f for f in [b for a, b in zip(args, args[1:]) if a in ("-f", "--file")] +
                       [a.partition("=")[2] for a in args if a.startswith("--file=")])
        # the writer they are or run from their own words (git rm or mv, docker exec c rm, kubectl cp, parallel rm
        # ::: …), read from its name on (a git message or grep pattern is data)
        data = shell.data_words(argv)
        j = next((j for j in range(1, len(argv)) if j not in data and shell.base_name(argv[j]) in (
            "rm", "unlink", "shred", "truncate", "tee", "cp", "mv", "install", "ln", "dd", "sed", "perl", "find")),
                 None)
        if j is not None:
            out.extend(_command_effects([{"argv": [argv[j].casefold()] + argv[j + 1:]}], work))
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
        out.extend("DELETE_TARGET:" + path for d in operands[1:] for path in [d, *_roots_below(d)])
    elif exe in ("awk", "gawk", "mawk", "nawk"):
        out.extend("WRITE_TARGET:" + path for path in _awk_outputs(args))
        if any(a in ("-iinplace", "--include=inplace") or a == "inplace" and b in ("-i", "--include")
               for a, b in zip(args, [""] + args)):   # gawk's inplace extension writes every file it reads
            program = shell._awk_program(args)
            if program in args:
                out.extend("WRITE_TARGET:" + a for a in args[args.index(program) + 1:]
                           if not a.startswith("-") and "=" not in a)
    elif exe in ("curl", "wget"):   # each file a download writes, by all its options (shell.download_writes)
        out.extend("WRITE_TARGET:" + path for path in shell.download_writes([exe, *args])[0])
    elif exe == "ssh-keygen":   # -f names what a writing mode creates or rewrites (above)
        out.extend("WRITE_TARGET:" + path for path in _ssh_keygen_writes(args))
    elif exe in _OUTPUT_OPTION or exe in _OUTPUT_OPERAND:
        out.extend("WRITE_TARGET:" + path for path in _outputs(exe, args))
    elif exe in ("sqlite3", "sqlite"):
        # every operand (the database among them), when its SQL (the operands and a heredoc or herestring) writes
        # outside literals and comments, or can't be read
        # lean: SQL read from a file (`sqlite3 db < x.sql`, `.read x.sql`) isn't seen; read it if one is held wrongly
        operands = [a for a in args if not a.startswith("-")]
        code = classes.sql_code("\n".join(operands + list(command.get("stdin", ()))),
                                *classes.SQL_DIALECTS["sqlite"])
        if code is None or _SQL_WRITE.search(code):
            out.extend("WRITE_TARGET:" + a for a in operands)
    out.extend(_tree_writes(exe, args, work))
    out.extend(_installs(command, exe, args))
    if not _known_program(exe):   # a program the parser doesn't know: held where its words name a trust root
        out.extend("NAMED_TARGET:" + w for w in _named_words(args))
        out.extend("INSIDE_TARGET:" + w for w in _assigned_words(args))
    out.extend("NAMED_TARGET:" + w for w in _side_outputs(exe, args, command))
    return out


_NAME_VALUE = re.compile(r"(?:-D)?[A-Za-z_][A-Za-z0-9_.]*=")


def _named_words(args):
    """The words of a program's arguments that may be a path: each word that isn't an option, and an option's `=` value (not
    an install location's: `--prefix ~/.local` is read as `PREFIX=~/.local`, _assigned_words)."""
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
        elif a in _LOCATION_OPTIONS:
            skip = True
        elif a.startswith("--"):
            out += [a.partition("=")[2]] * ("=" in a and a.partition("=")[0] not in _LOCATION_OPTIONS)
        elif a.startswith("-") and len(a) > 2:   # an attached value (`-o~/.local/bin/x`, `-C~/x`, `-v~/a:/m`)
            out += _pieces(a[2:].lstrip("="))
        elif not a.startswith("-") and not _NAME_VALUE.match(a):
            out += _pieces(a)
    return out


_LOCATION_OPTIONS = ("--prefix", "--destdir", "--libdir", "--bindir", "--exec-prefix", "--sbindir", "--sysconfdir")


def _pieces(word):
    """A word and the parts of it a path may be in (`CREATE:/x`, `/a:/m`, `a=/x`, `x,y`)."""
    return [word] + [w for w in re.split(r"[:=,]", word) if w and w != word] * bool(re.search(r"[:=,]", word))


def _assigned_words(args):
    """The values of assignment-form words (`PREFIX=…`, `DESTDIR=…`, `-DCMAKE_INSTALL_PREFIX=…`): an install location.
    One is held where it is a trust root or inside one (INSIDE_TARGET), not for a folder along one (`PREFIX=~/.local`
    is ordinary)."""
    return [a.partition("=")[2] for a in args if _NAME_VALUE.match(a)] + _option_values(
        args, *_LOCATION_OPTIONS)


def _option_values(args, *names):
    """The values of options as `-o X`, `-oX`, `-o=X`, `--output X` and `--output=X` give them."""
    out = []
    for i, a in enumerate(args):
        for n in names:
            if a == n:
                out += args[i + 1:i + 2]
            elif n.startswith("--") and a.startswith(n + "="):
                out.append(a[len(n) + 1:])
            elif not n.startswith("--") and a.startswith(n) and len(a) > len(n) and a[:2] == n:
                out.append(a[len(n):].lstrip("="))
    return out


_SED_WRITE = re.compile(r"(?:^|[\s;{}/])[wW]\s*([^\s;}]+)")
# the files an editor is told to write: vim's and ex's :w, :write, :saveas, :sav, :wq, :x, :up (past a !), emacs's write-file
_EDITOR_WRITE = re.compile(r"(?:^|[\s:|;'\"])(?:w(?:rite)?|sav(?:eas)?|wq|x|up(?:date)?|f(?:ile)?|r(?:ead)?)!?\s+([^\s|;'\"]+)|"
                           r"write-file\s+\"([^\"]+)\"|set-visited-file-name\s+\"([^\"]+)\"")
_SQLITE_FILE = re.compile(r"(?i)\.(?:output|once|backup|save|import|read|dump|clone|cd|trace|log)\s+(?:--\w+\s+)*(\S+)|"
                          r"\bvacuum\s+(?:\w+\s+)?into\s+['\"]([^'\"]*)['\"]|\battach\s+(?:database\s+)?['\"]([^'\"]*)['\"]")


def _side_outputs(exe, args, command):
    """The files a known program may write by an option or a script that _command_effects doesn't read (each held as
    NAMED_TARGET where it names a trust root): mktemp's template and -p, sed's `w` and `W`, awk's string literals, sqlite3's
    .output, .backup, .trace, .log and attach and `vacuum into`, git's archive -o, bundle, format-patch -o and --output (past
    its own options), tree -o, less -o, uv export and pip compile -o, pip download -d and wheel -w, zstd's and brotli's -o,
    an archive a tar, zip, 7z, pax, jar or ar creates, an editor's `:w`, `saveas` and write-file."""
    words = [a for a in args if not a.startswith("-")]
    if exe == "mktemp":
        return words + _option_values(args, "-p", "--tmpdir")
    if exe in ("sed", "gsed"):
        return [m.group(1) for a in words for m in _SED_WRITE.finditer(a)]
    if exe in ("awk", "gawk", "mawk", "nawk"):
        program = shell._awk_program(args) or ""
        return re.findall(r"\"([^\"\n]*)\"", program)
    if exe in ("sqlite3", "sqlite"):
        return [g.strip("\"'") for m in _SQLITE_FILE.finditer("\n".join(words + list(command.get("stdin", ()))))
                for g in m.groups() if g]
    if exe == "git":
        i = shell._git_sub(args)
        sub = args[i] if i is not None else ""
        rest = [a for a in args[i + 1:] if not a.startswith("-")] if i is not None else []
        if sub == "bundle":
            return rest[1:2] * (rest[:1] == ["create"])
        return _option_values(args[i:], "--output", "--output-directory") + (
            _option_values(args[i:], "-o") if sub in ("archive", "format-patch") else [])
    if exe in ("tar", "gtar", "bsdtar"):
        letters, values, _, _ = _tar_words(args)
        return values["f"] * bool(set(letters) & set("cru"))
    if exe == "zip":
        return words[:1] + _option_values(args, "-O", "--output-file")
    if exe in ("7z", "7za", "7zr", "7zz", "7zip"):
        return words[1:2] * bool(words[:1] and words[0] in ("a", "u"))
    if exe == "pax":
        return _option_values(args, "-f") * ("-w" in args)
    if exe == "jar":
        return args[1:2] * bool(args[:1] and set(args[0].lstrip("-")) & set("cu"))
    if exe == "ar":
        return args[1:2] * bool(args[:1] and set(args[0].lstrip("-")) & set("rqc"))
    if exe in ("vim", "vi", "nvim", "ex", "emacs", "red", "ed"):
        text = "\n".join([*args, *command.get("stdin", ())])
        return [m.group(1) or m.group(2) for m in _EDITOR_WRITE.finditer(text)]
    if exe in ("tree", "zstd", "brotli", "unzstd"):
        return _option_values(args, "-o", "--output") + [b for a, b in zip(args, args[1:]) if re.fullmatch(
            r"-[A-Za-z]*o", a) and exe == "tree"]
    if exe == "less":
        return _option_values(args, "-o", "-O", "--log-file", "--LOG-FILE")
    if exe == "uv":
        if words[:1] in (["init"], ["venv"]):
            return words[1:]
        if words[:1] == ["export"] or words[:2] == ["pip", "compile"]:
            return _option_values(args, "-o", "--output-file")
        return _option_values(args, "--out-dir", "-o") if words[:1] == ["build"] else []
    if exe in ("pip", "pip3") or _PYTHON_EXE.fullmatch(exe) and _python_module(args)[:1] == ["pip"]:
        return _option_values(args, "-d", "--dest") + _option_values(args, "-w", "--wheel-dir") if any(
            w in ("download", "wheel") for w in words) else []
    if exe in ("docker", "podman"):   # a volume or mount that makes a folder of the host writable in the container
        return [p for a in _option_values(args, "-v", "--volume", "--mount") for p in _pieces(a)]
    return []


def _literal_effects(command):
    """What a command's own words say it writes, with no pattern and no pairing of its words (nothing is charged, so a
    reading that spent the budget leaves a command after it its trust-root deny): the last operand or each -t folder of
    cp, mv, install, ln and link, each operand of rm, unlink and shred deleted, of truncate and tee written, of a mode
    changer; any other program's words as names (NAMED_TARGET, held where one names a trust root)."""
    argv = command["argv"]
    exe, args = _program(argv), argv[1:]
    words = [a for a in args if not a.startswith("-")]
    if exe in ("rm", "unlink", "shred"):
        return ["DELETE_TARGET:" + w for w in words]
    if exe in ("truncate", "tee"):
        return ["WRITE_TARGET:" + w for w in words]
    if exe in ("cp", "mv", "install", "ln", "link"):
        folders, words = shell.target_directories(args)   # (-t, -vt, --target=, -t~/x, as cp reads them)
        words = [w for w in words if not w.startswith("-")]
        dests = folders or words[-1:]
        sources = words if folders else words[:-1]
        names = [s.rstrip("/").rsplit("/", 1)[-1] for s in sources]
        # (each source's name in each destination, as _copies reads them, where there are few enough pairs to read uncharged)
        into = [d.rstrip("/") + "/" + n for d in dests for n in names] if len(dests) * len(names) <= 512 else []
        return ["WRITE_TARGET:" + w for w in dests + into] + [
            "DELETE_TARGET:" + w for w in words[:-1] * (exe == "mv" and not folders)]
    if exe in _MODE_CHANGERS:
        return ["MODE_TARGET:" + w for w in words]
    return ["NAMED_TARGET:" + w for w in _named_words(args)] + ["INSIDE_TARGET:" + w for w in _assigned_words(args)]


# the programs that read, list, or only name a file (and the builtins that set or run one): they are known not to write
# the folder they are given. A program the line runs that is neither here, nor one the parser reads the writes of
# (_command_effects' branches), nor an interpreter (TK-D007 reads its code), is held when a word of it names a trust root
# or a folder along one (NAMED_TARGET, which _write_effects holds as ROOT_TARGET after resolving the word)
# lean: a program that writes there but is named in none of these and given a variable's value, a pattern or a path built
# at run time isn't read; add a name here when a reader is held wrongly
_KNOWN_PROGRAMS = frozenset((
    "cat", "head", "tail", "less", "more", "bat", "grep", "egrep", "fgrep", "rg", "ag", "ack", "wc", "ls", "ll", "la", "dir",
    "stat", "file", "du", "df", "diff", "cmp", "md5sum", "md5", "shasum", "sha1sum", "sha256sum", "sha512sum", "cksum", "xxd",
    "hexdump", "od", "strings", "readlink", "realpath", "dirname", "basename", "which", "whereis", "type", "command", "test",
    "[", "[[", "echo", "printf", "true", "false", ":", "sleep", "date", "uname", "whoami", "id", "pwd", "cd", "pushd", "popd",
    "jq", "yq", "sort", "uniq", "cut", "tr", "tree", "mkdir", "touch", "export", "set", "unset", "alias", "unalias", "source",
    ".", "exit", "return", "sudo", "nohup", "nice", "time", "timeout", "xargs", "exec", "builtin", "trap", "wait", "locate",
    "mdfind", "lsof", "ps", "hash", "history", "printenv", "ulimit", "umask", "read", "shift", "local", "declare", "readonly",
    "typeset", "let", "sh", "bash", "zsh", "dash", "ksh", "fish", "env", "uv", "pipx", "pip", "pip3", "virtualenv", "tracekit",
    "kill", "pkill", "killall", "pgrep", "systemctl", "launchctl", "chmod", "chown", "chgrp", "nl",
    "column", "comm", "join", "paste", "fold", "fmt", "expand", "unexpand", "rev", "tac", "seq", "yes", "mktemp", "sync",
    "gzip", "bzip2", "xz", "lzma", "lzip", "compress", "zip", "unzip", "tar", "rsync", "curl", "wget", "git", "docker",
    "podman", "kubectl", "parallel", "sqlite3", "sqlite", "awk", "gawk", "mawk", "nawk", "ssh-keygen", "ditto", "cpio", "pax",
    "7z", "7za", "7zr", "7zz", "7zip", "patch", "unar", "cabextract", "jar", "lha", "lzh", "unrar", "ar", "hdiutil", "find",
    "rm", "unlink", "shred", "truncate", "tee", "cp", "mv", "install", "ln", "link", "dd", "ssh", "telnet", "dig", "nslookup",
    "host", "sed", "perl", "ruby", "node", "nodejs", "php", "lua",
    "osascript", "ed", "red", "ex", "vim", "vi", "nvim", "emacs"))
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")


def _known_program(exe):
    """Whether the parser reads what `exe` writes, or it is a reader (_KNOWN_PROGRAMS), an editor, an interpreter or a
    program with an output option or operand (_OUTPUT_OPTION, _OUTPUT_OPERAND)."""
    return (exe in _KNOWN_PROGRAMS or exe in _OUTPUT_OPTION or exe in _OUTPUT_OPERAND or exe in _EDITS_ALL
            or bool(_EDITOR.fullmatch(exe) or _PYTHON_EXE.fullmatch(exe) or _INTERPRETER.fullmatch(exe)))


# what git only reads, given -C or --work-tree's folder (any other subcommand may write there)
_GIT_READS = frozenset(("status", "log", "diff", "show", "ls-files", "ls-tree", "rev-parse", "rev-list", "describe",
                        "blame", "grep", "cat-file", "show-ref", "shortlog", "name-rev", "version", "help"))


_GIT_MAGIC = re.compile(r":[/!^(]|:\(|\*|\.\.?$|\[|\?")


def _git_foreign(sub, args, after):
    """Whether a git work tree writer is given content that isn't the repository's own: another repository's (--git-dir,
    --work-tree, `-c core.worktree`, a repository operand on pull, --separate-git-dir), a patch (apply, am), a tree it
    checks out whole (read-tree -u, checkout-index -a, --pathspec-from-file) or a whole-tree or magic pathspec (`.`,
    `:/`, `*`, `:(top)`, `:!x`) that may name any path."""
    return (any(a.startswith(("--git-dir", "--work-tree", "--separate-git-dir", "--pathspec-from-file")) or
                a in ("--git-dir", "--work-tree", "--separate-git-dir") for a in args)
            or any(a.startswith("core.worktree") for a in args) or sub in ("apply", "am")
            or sub == "pull" and any(re.search(r"[/:]|^[.~]", w) for w in after[:1])
            or sub == "read-tree" and "-u" in args or sub == "checkout-index" and any(a in ("-a", "--all") for a in args)
            or sub in ("checkout", "restore", "reset", "stash", "rm", "mv", "clean", "switch", "sparse-checkout")
            and any(_GIT_MAGIC.search(w) for w in after))


# git's subcommands that write the files of a work tree (in the folder it runs in, `-C`'s, or --work-tree's)
_GIT_WORKTREE = frozenset(("checkout", "pull", "merge", "reset", "restore", "apply", "am", "stash", "cherry-pick", "rebase",
                           "revert", "clean", "read-tree", "switch", "sparse-checkout", "submodule", "worktree", "clone",
                           "init", "mv", "rm", "checkout-index", "bisect"))
_PIP_ENV_OPTIONS = ("--python", "-p", "--target", "-t", "--prefix", "--root", "--directory")   # (pip's and uv's: where it installs)
_TRACEKIT_AI = re.compile(r"tracekit-ai")   # (a name as PEP 503 normalises it: _normalise_name)


def _normalise_name(word):
    """`word` as PEP 503 reads a package name (runs of - _ . are one -, in lower case): Tracekit_AI is tracekit-ai."""
    return re.sub(r"[-_.]+", "-", word).lower()


_QUIET = ("-q", "-v", "--quiet", "--verbose", "--no-progress", "--no-cache", "--include-injected", "--color=never", "--native-tls")
# what changes the index, the configuration or the Python an upgrade of every tool uses
_UPGRADE_SETTINGS = ("UV_PYTHON", "UV_CONFIG_FILE", "UV_PROJECT", "UV_WORKING_DIR", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL",
                     "UV_INDEX", "PIP_CONFIG_FILE", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIPX_DEFAULT_PYTHON")


def _installs(command, exe, args):
    """What a package manager or an interpreter's module installs or creates in an environment: WRITE_TARGET of the
    environment it names (pip's --target, --prefix, --root and -t, uv pip's --python, a VIRTUAL_ENV in front, the
    interpreter or pip it is run by, `-m ensurepip`, `-m venv`, `uv venv`, `virtualenv`), so a trust root there is denied
    as any write to it is; and ROOT_TARGET (held) of a uv tool or pipx install, inject, runpip, upgrade or reinstall
    whose words name tracekit-ai (a name, a path, a URL), which replaces or shadows the install."""
    word = command.get("word") or command["argv"][0]   # (the program as written: the parse leaves its file name)
    words = [a for a in args if not a.startswith("-")]
    out = []
    module = _python_module(args) if _PYTHON_EXE.fullmatch(exe) else []
    sub = (module[1:2] if module[:1] == ["pip"] else words[:1]) if exe in ("pip", "pip3") or module[:1] == ["pip"] else (
        words[1:2] if exe == "uv" and words[:1] == ["pip"] else words[:1])
    sub = sub[0] if sub else ""
    pip_like = exe in ("pip", "pip3") or module[:1] == ["pip"] or exe == "uv" and words[:1] == ["pip"]
    if "/" in word and (module[:1] in (["pip"], ["ensurepip"], ["venv"]) or exe in ("pip", "pip3")):
        out.append("WRITE_TARGET:" + (posixpath.dirname(posixpath.dirname(word)) or "."))   # <venv>/bin/python -m pip: the venv
    if pip_like and sub in ("install", "uninstall", "sync", "download") or module[:1] in (["ensurepip"], ["venv"]):
        every = list(args) + list(module[1:])
        out += ["WRITE_TARGET:" + v for a, v in zip(every, every[1:]) if a in _PIP_ENV_OPTIONS] + [
            "WRITE_TARGET:" + a.partition("=")[2] for a in every if a.startswith(("--target=", "--prefix=", "--root=",
                                                                                     "--python="))]
    if exe in ("virtualenv",) or exe == "uv" and words[:1] == ["venv"] or module[:1] == ["venv"]:
        out += ["WRITE_TARGET:" + w for w in (words[1:] if exe == "uv" else module[1:] if module else words)
                if not w.startswith("-")]
    action = words[1] if exe == "uv" and words[:1] == ["tool"] and words[1:2] else words[0] if exe == "pipx" and words else ""
    tools = (exe == "uv" and words[:1] == ["tool"] and action in ("install", "upgrade", "reinstall")) or (
        exe == "pipx" and action in ("install", "inject", "runpip", "upgrade", "reinstall", "install-all", "upgrade-all",
                                     "reinstall-all"))
    if tools:
        plain = action == "install" and not any(a.startswith("-") for a in args)   # (the name as on PyPI, no option: what the plugin asks for)
        out += ["ROOT_TARGET:" + w for w in words if _TRACEKIT_AI.search(_normalise_name(w)) and not (
            plain and _normalise_name(w) == w == "tracekit-ai")]
        # --force replaces a command another install put in ~/.local/bin; runpip runs pip in a venv; install-all and
        # reinstall-all rebuild every venv (tracekit-ai's too); an upgrade of every tool (`uv tool upgrade --all`, pipx's
        # upgrade-all) takes each from the configured index, which an option here or a write to its settings (TK-A030,
        # TK-A024) would change, and it names no replacement: held only with another option
        options = [a for a in args if a.startswith("-") and a not in _QUIET]
        every = action == "upgrade-all" or action == "upgrade" and any(a in ("--all", "-a") for a in args)
        if any(a in ("--force", "-f") for a in args) or action in ("runpip", "install-all", "reinstall-all") or (
                action == "reinstall" and any(a in ("--all", "-a") for a in args)) or (
                every and any(a not in ("--all", "-a") for a in options)):
            out.append("ROOT_TARGET:" + exe + " " + action)
    return out


# tar's options, as GNU tar and bsdtar read them. A short letter is a flag (_TAR_FLAGS), takes a value (f, C, b), or is
# one the two read differently or that selects members another way (-s, -K, -T, -X, -I ...): the members are then unread.
_TAR_FLAGS = frozenset("xtcrudAzjJZvpkmOUPahnSlwWBoRMyiqE")
_TAR_VALUED = "fCb"
# a long option that takes a value (its next word without `=`), and the ones that choose or rename members
_TAR_LONG_VALUED = frozenset(("directory", "file", "transform", "xform", "exclude", "exclude-from", "exclude-tag",
                              "exclude-tag-all", "exclude-tag-under", "exclude-vcs-ignores", "files-from", "strip-components",
                              "newer-mtime", "newer", "after-date", "owner", "group", "mode", "blocking-factor",
                              "use-compress-program", "label", "index-file", "to-command", "suffix", "listed-incremental",
                              "level", "pax-option", "format", "checkpoint-action", "occurrence", "rsh-command",
                              "volno-file", "tape-length", "add-file", "starting-file", "include", "include-from", "options",
                              "gid", "uid", "gname", "uname", "newer-than", "older-than", "newer-mtime-than", "cd",
                              "hole-detection", "sparse-version", "warning", "quoting-style",
                              "atime-preserve", "one-top-level", "backup", "mtime", "clamp-mtime", "xattrs-include",
                              "xattrs-exclude", "acls-exclude", "selinux-exclude", "info-script", "new-volume-script",
                              "volume-script", "rmt-command"))
_TAR_LONG_FLAGS = frozenset(("extract", "get", "create", "list", "append", "update", "diff", "compare", "delete",
                             "verbose", "preserve-permissions", "same-permissions", "keep-old-files", "keep-newer-files",
                             "keep-directory-symlink", "overwrite", "overwrite-dir", "to-stdout", "no-same-owner",
                             "same-owner", "no-same-permissions", "numeric-owner", "gzip", "gunzip", "bzip2", "xz", "lzip",
                             "zstd", "compress", "uncompress", "auto-compress", "dereference", "hard-dereference",
                             "wildcards", "no-wildcards", "wildcards-match-slash", "no-wildcards-match-slash", "anchored",
                             "no-anchored", "ignore-case", "no-ignore-case", "null", "no-null", "totals", "verify",
                             "sparse", "one-file-system", "remove-files", "unlink-first", "recursive-unlink", "touch",
                             "ignore-zeros", "ignore-command-error", "ignore-failed-read", "no-auto-compress",
                             "no-recursion", "recursion", "absolute-names", "show-defaults", "show-omitted-dirs", "version",
                             "help", "usage", "xattrs", "no-xattrs", "acls", "no-acls", "selinux", "no-selinux", "posix",
                             "fast-read", "no-overwrite-dir", "delay-directory-restore", "no-delay-directory-restore",
                             "exclude-backups", "exclude-caches", "exclude-caches-all", "exclude-caches-under", "keep-old",
                             "safe-writes", "no-seek", "seek", "full-time", "check-links", "interactive", "confirmation",
                             "block-number", "read-full-records", "restrict", "skip-old-files"))
# the ones that name or rename the members the archive extracts, or that skip some
_TAR_MEMBERS = ("transform", "xform", "exclude", "files-from", "strip-components", "include", "starting-file", "options",
                "add-file", "one-top-level")


def _tar_words(args):
    """(the letters of a tar line's options, each valued letter's values, its other operands, whether what it
    extracts is unread): an old-style first word without a dash (`xfC a.tar dir`), clusters (`-xfC a.tar dir`),
    attached values (`-Cdir`), the long options as GNU tar spells them (`--directory`, `--file`, `--extract`, `--get`,
    each valued one as _TAR_LONG_VALUED lists them, any unambiguous prefix of one, `=` or the next word its value), and
    a letter or long option it doesn't know. Unread: -s, --transform, -K, -T, -X, --exclude*, --files-from,
    --strip-components or an option not listed (the operands are then not the members it writes)."""
    letters, values, operands, unread, i = "", collections.defaultdict(list), [], False, 0
    while i < len(args):
        a, i = args[i], i + 1
        if a == "--":
            operands += args[i:]
            break
        if a.startswith("--"):
            name, eq, value = a[2:].partition("=")
            if name in _TAR_LONG_VALUED or name in _TAR_LONG_FLAGS:
                full = [name]
            else:   # an unambiguous abbreviation (`--dir`, `--transf`): every option it may be
                full = [o for o in sorted(_TAR_LONG_VALUED | _TAR_LONG_FLAGS) if o.startswith(name)] if len(name) > 1 else []
            if not full:
                unread = True
                continue
            if any(o in _TAR_LONG_VALUED for o in full) and not eq and i < len(args):
                value, i = args[i], i + 1
            for o in full:
                if o in ("directory", "cd"):
                    values["C"].append(value)
                elif o == "file":
                    values["f"].append(value)
                elif o in ("extract", "get"):
                    letters += "x"
                elif o == "to-stdout":
                    letters += "O"
                if o in _TAR_MEMBERS or o.startswith("exclude"):
                    unread = True
        elif a.startswith("-") and len(a) > 1 or i == 1 and a and not a.startswith("-") and re.fullmatch(r"[A-Za-z]+", a):
            cluster, pending = a.lstrip("-"), []
            for j, c in enumerate(cluster):
                letters += c
                if c in _TAR_VALUED:
                    if cluster[j + 1:] and a.startswith("-"):   # attached: -Cdir
                        values[c].append(cluster[j + 1:])
                        break
                    pending.append(c)   # (an old-style word's valued letters each take the next word)
                elif c not in _TAR_FLAGS:
                    unread = True
            for c in pending:
                if i < len(args):
                    values[c].append(args[i])
                    i += 1
        else:
            operands.append(a)
    return letters, values, operands, unread


def _plain_member(member):
    return not (shell._GLOB.search(member) or member.endswith("/") or member in (".", ".."))


def _tree_writes(exe, args, work):
    """What a program that writes a whole tree writes: tar -x into -C's folder, unzip into -d's, ditto, pax, cpio, 7z
    and python -m zipfile or tarfile into theirs (default: here): the files it names there, else TREE_TARGET, where
    _held_roots holds a folder that may take a trust root's place; rsync's destination and each source's name in it
    (and what --delete takes); git's -C or --work-tree folder for any subcommand but a reader's, apply's --directory and
    clone's folder."""
    members, into = [], []
    if exe in ("tar", "gtar", "bsdtar"):
        letters, values, operands, unread = _tar_words(args)
        if "x" not in letters or "O" in letters:
            return []
        into = values["C"]
        if not unread:
            members = operands
    elif exe == "unzip" and not any(re.fullmatch(r"-[A-Za-z]*[lptZ][A-Za-z]*", a) for a in args):
        into = [b for a, b in zip(args, args[1:]) if re.fullmatch(r"-[A-Za-z]*d", a)] + [
            a[2:] for a in args if a.startswith("-d") and len(a) > 2]
        words, rest = [], iter(args)
        for a in rest:
            if a == "-x":   # the members it leaves out follow
                break
            if re.fullmatch(r"-[A-Za-z]*d", a):
                next(rest, None)
            elif not a.startswith("-"):
                words.append(a)
        members = words[1:]
    elif exe == "ditto":
        into = [a for a in args if not a.startswith("-")][-1:]
    elif _PYTHON_EXE.fullmatch(exe) and (mod := _python_module(args))[:1] in (["zipfile"], ["tarfile"]):
        if not any(a in ("-e", "--extract") for a in mod[1:]):
            return []
        into = [a for a in mod[1:] if not a.startswith("-")][1:2]
    elif exe in ("pax", "cpio"):
        passing = exe == "cpio" and any(re.fullmatch(r"-[A-Za-z]*p[A-Za-z]*|--pass-through", a) for a in args)
        if exe == "cpio" and not passing and not any(re.fullmatch(r"-[A-Za-z]*i[A-Za-z]*|--extract", a) for a in args):
            return []
        if exe == "pax" and not any(re.fullmatch(r"-[A-Za-z]*r[A-Za-z]*", a) for a in args):
            return []
        into = ([a for a in args if not a.startswith("-")][-1:] if passing else ["."]) + [
            w for a in args for w in re.findall(r"(?:~|/)[^\s,'\"]*", a)] + [
            b for a, b in zip(args, args[1:]) if a in ("-D", "--directory")]
    elif exe == "patch":   # the files its diff names, in -d's folder (here by default)
        if any(a in ("--dry-run", "-C", "--check") for a in args):
            return []
        into = [b for a, b in zip(args, args[1:]) if a in ("-d", "--directory")] + [
            a[2:] for a in args if re.fullmatch(r"-d.+", a)] + [a.partition("=")[2] for a in args if a.startswith("--directory=")]
    elif exe in ("unar", "cabextract", "jar", "lha", "lzh", "unrar", "ar"):
        words = [a for a in args if not a.startswith("-")]
        if exe == "unar":
            into = [b for a, b in zip(args, args[1:]) if a in ("-o", "-output-directory", "--output-directory")]
        elif exe == "cabextract":
            if any(a in ("-l", "--list", "-t", "--test") for a in args):
                return []
            into = [b for a, b in zip(args, args[1:]) if a in ("-d", "--directory")] + [
                a.partition("=")[2] for a in args if a.startswith("--directory=")] + [a[2:] for a in args if re.fullmatch(r"-d.+", a)]
        elif exe == "jar":
            if not any("x" in a for a in args[:1]):
                return []
            into = [b for a, b in zip(args, args[1:]) if a == "-C"]
        elif exe in ("lha", "lzh"):
            if not any(re.match(r"-?[xe]", a) for a in args[:1]):
                return []
            into = [m.group(1) for a in args if (m := re.search(r"(?:^-?|[a-z])w=(.+)$", a))]
        elif exe == "unrar":
            if args[:1] not in (["x"], ["e"]):
                return []
            into = words[2:3]
        elif exe == "ar" and not any("x" in a for a in args[:1]):
            return []
    elif exe == "hdiutil" and args[:1] == ["attach"]:   # a disk image mounted over a folder
        into = [b for a, b in zip(args, args[1:]) if a in ("-mountpoint", "-mountroot")]
        if not into:
            return []
    elif exe in ("7z", "7za", "7zr", "7zz", "7zip"):
        if not any(a in ("x", "e") for a in args[:1]):
            return []
        into = [a[2:] for a in args if a.startswith("-o") and len(a) > 2]
    elif exe == "rsync":
        operands = [a for a in args if not a.startswith("-")]
        local = [a for a in operands[-1:] if not re.match(r"[^/]*:", a)]
        if not local:
            return []
        written, into_names, tree = _copies(local, operands[:-1], work, True, len(operands) > 2)
        deletes = ["DELETE_TARGET:" + d + r for d in local for r in ["", *_roots_below(d, True)]
                   if any(a.startswith("--delete") for a in args)]
        return ["WRITE_TARGET:" + w for w in written] + ["INTO_TARGET:" + w for w in into_names] + [
            "TREE_TARGET:" + w for w in tree] + deletes
    elif exe == "git":
        folders, i, sub = [], 0, None
        while i < len(args):
            a, i = args[i], i + 1
            if a in ("-C", "--work-tree", "--git-dir", "-c", "--namespace") and i < len(args):
                folders += [args[i]] if a in ("-C", "--work-tree") else []
                i += 1
            elif a.startswith(("--work-tree=", "--git-dir=")):
                folders += [a.partition("=")[2]] if a.startswith("--work-tree") else []
            elif not a.startswith("-"):
                sub = a
                break
        after = [a for a in args[i:] if not a.startswith("-")]
        into = [a.partition("=")[2] for a in args[i:] if a.startswith("--directory=")] * (sub == "apply") + (
            after[-1:] if sub == "clone" and len(after) > 1 else [])
        if sub is None or sub in _GIT_READS:
            return []
        # a worktree writer writes -C's or --work-tree's folder, else the one the line is in. Given content that isn't the
        # repository's own (_git_foreign) it may write anything there: a home is then held whole (TREE_TARGET); a pull, a
        # checkout of a branch, a stash pop writes what the repository has, so a home holds only the paths it names
        # (`checkout -f .local`, `checkout evil -- Library`: WORKTREE_TARGET, which holds the roots below a path)
        writer = sub in _GIT_WORKTREE
        foreign = writer and _git_foreign(sub, args, after)
        whole = (folders or ["."]) if foreign else []
        named = [f.rstrip("/") + "/" + w for f in (folders or ["."]) for w in after if not w.startswith(":") and
                 w not in (".", "..", "*")] if writer else []
        shell.charge(work, len(folders or ["."]) * len(after))
        kept = [f for f in (folders or ["."]) if writer and not foreign and not _above_home(f)]
        return ["WRITE_TARGET:" + f for f in folders + into] + ["TREE_TARGET:" + f for f in whole + into + named] + [
            "WORKTREE_TARGET:" + f for f in kept]
    else:
        return []
    into = list(dict.fromkeys(into)) or ["."]
    shell.charge(work, len(into) * len(members))
    if members and all(map(_plain_member, members)):   # named members are the only files it writes there (each may be a folder)
        return ["WRITE_TARGET:" + d.rstrip("/") + "/" + m for d in into for m in members] + [
            "TREE_TARGET:" + d.rstrip("/") + "/" + m for d in into for m in members]
    return ["WRITE_TARGET:" + d for d in into] + ["TREE_TARGET:" + d for d in into]


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
_SDK = re.compile(r"\b(?:autospawn|dev_data_dir|data_dir_at|run_module|__main__|record_hooks_settings|record_hook_python)\b|\btracekit\.cli\b|"
                  r"\bimport\s+(?:cli|install)\b|\btracekit\.install\b|\b(?:walk_packages|iter_modules|run_path)\b|"
                  r"['\"]\.(?:install|cli)['\"]|\btracekit\b[^\n]{0,80}['\"]\s*\+\s*['\"]")
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
            re.search(r"['\"](?:down|uninstall|up|signer|init)['\"]", raw) or
            re.search(r"\bsys\.argv\s*(?:\[[^]\n]*\])?\s*[+]?=(?!\s*\[)|\bmain\s*\((?!\s*[\[)])", code)):
        return True
    # the client config's own writer: init records the Python the plugin's hook runs (install.record_hook_python,
    # record_hooks_settings), named anywhere in the code, a string included; and tracekit.install or tracekit.cli reached
    # by a name looked up (importlib, __import__) or code run from a string (exec, eval, compile)
    if re.search(r"\brecord_hook_python\b|\brecord_hooks_settings\b|\b(?:import|from)\s+tracekit\.install\b|"
                 r"\bfrom\s+tracekit\s+import\s+[\w\s,()]*?\binstall\b", raw + "\n" + code):
        return True
    # tracekit run as a module whatever its argv (run_module, run_path), a package of it walked, or a submodule looked up by a
    # relative name (`import_module('.install', package='tracekit')`)
    if re.search(r"\btracekit\b", raw) and re.search(r"\b(?:run_module|run_path|walk_packages|iter_modules)\b", raw):
        return True
    if re.search(r"\btracekit\b", raw) and re.search(r"['\"]\.(?:install|cli)['\"]", raw):
        return True
    if re.search(r"\btracekit\b", raw) and _PY_LOOKUP.search(raw) and re.search(r"['\"]\s*\+\s*['\"]", raw):   # a name built
        return True
    if re.search(r"\btracekit\.(?:install|cli)\b|\bfrom\s+tracekit\s+import\s+[\w\s,()]*?\b(?:install|cli)\b|\bimport\s+cli\b",
                 raw) and (_PY_LOOKUP.search(raw) or re.search(r"\b(?:exec|eval|compile)\s*\(", raw)):
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


def _links(commands):
    """Each symbolic link a command on the line makes, the link's path (no trailing /) to what it points at."""
    return {c["argv"][-1].rstrip("/"): c["argv"][-2] for c in commands if c["argv"][0] == "ln" and len(c["argv"]) > 2
            and any(re.fullmatch(r"-\w*s\w*|--symbolic", a) for a in c["argv"][1:])}


def _cdpath(parsed):
    """The folders of a CDPATH the line sets (_variable)."""
    return [p for v in _variable(parsed, "CDPATH") for p in v.split(":") if p]


def _bases(commands, where, work):
    """For each command, the folders its relative paths may be read from: the ones the line may be in at it (_walk's
    `where`), and the one `env -C`, `tar -C`, `git -C` or `make -C` runs it in (a relative one also from each of those).
    Each charged to `work` (shell.charge)."""
    out = []
    for c, here in zip(commands, where):
        argv, extra = c["argv"], []
        if argv[0] in ("env", "tar", "git", "make"):
            to = next((argv[i + 1] if a in ("-C", "--chdir", "--directory") else a.partition("=")[2] or a[2:]
                       for i, a in enumerate(argv[:-1]) if a in ("-C", "--chdir", "--directory") or
                       a.startswith(("--chdir=", "--directory=")) or a.startswith("-C") and argv[0] != "env"), None)
            if to and to != "-":
                extra = [to] + ([] if to.startswith(("/", "~", "$")) else [posixpath.normpath(posixpath.join(b, to))
                                                                         for b in here])
                shell.charge(work, sum(map(len, extra)))
        out.append(tuple(dict.fromkeys([*here, *extra])))
    return out


# a component of one of Tracekit's paths (TK-D007's) that a pattern in a word may stand for: `trace?it`, `*`
_COMPONENTS = ("tracekit", "Application Support", "Library", "tracekit-signer", ".tracekit-signer", ".tracekit-client",
               ".local", "share", "lib", "data", "keys", "run", "site-packages", "dist-packages",
               ".claude", ".codex", ".gemini")   # (and TK-D008's agents' folders under ~: _effects)


# the component of a Tracekit path a bare pattern under each of these stands for (`Application Support/*`)
_UNDER = {"Application Support": "tracekit", "Library": "Application Support", "share": "tracekit",
          "lib": "tracekit-signer"}


def _pattern_forms(path, work):
    """A path with a pattern in a component under a folder of _UNDER or ~, each such component read in turn as each of
    _COMPONENTS it matches when it has letters of its own (`trace?it`, `*Support`, `.trace*`), else as the one _UNDER
    names; one elsewhere (`./src/*`, `./*tracekit*`, a repo's `tracekit/**`) isn't Tracekit's. Read at the first
    _PATTERNED_MAX patterned components, at most _FORMS_MAX forms (else ParseError: unread), each charged to `work`; a
    path over 4 KiB gets each form only up to the component."""
    parts, out = path.split("/"), []
    for i in [i for i, p in enumerate(parts) if shell._GLOB.search(p)][:_PATTERNED_MAX]:
        if i and (parts[i - 1] in _UNDER or parts[i - 1] == "~"):
            p = parts[i]
            names = _COMPONENTS if len(re.sub(r"[*?]|\[[^]]*\]", "", p)) > 1 else [_UNDER.get(parts[i - 1], "")]
            out += ["/".join(parts[:i] + [n] + (parts[i + 1:] if len(path) <= 4096 else [])) for n in names
                    if fnmatch.fnmatchcase(n, p)]
            if len(out) > _FORMS_MAX:
                raise shell.ParseError("a pattern that reads as more than %d paths of Tracekit's" % _FORMS_MAX)
    shell.charge(work, sum(map(len, out)))
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
    data or lifecycle through the SDK (_reaches_sdk). TARGET: each file the line writes, links, deletes or changes the
    mode of (_effects), also among ACT: a rule that must not read a command's own words (`readlink PATH`) reads these.
    Each also normalised and casefolded as a path is (_path_forms).
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
    where, _ = _walk_held(parsed, work)
    try:
        per = _bases(commands, where, work)   # (the folders each command may be in, not every one the line enters)
    except shell.ParseError:   # (the budget: the line's own texts below are still read, and the line is held as unread)
        per = [()] * len(commands)
        if len(parsed) > 5:
            parsed[5]["unread"] = True
    tail = per[-1] if per else ()
    links = _links(commands)

    def at(names, bases=None):   # each name, as read from the folders the command is in, through HOME, a link or a pattern
        bases = tail if bases is None else bases
        out, joined = list(names), "".join(names)   # (a pattern holds a *, ? or [)
        for n in dict.fromkeys(names) if bases or homes or links or ("*" in joined or "?" in joined or "[" in joined) and \
                any(map(shell._GLOB.search, names)) else ():
            if not n or "://" in n:
                continue
            more = [posixpath.normpath(posixpath.join(b, n)) for b in bases if n[0] not in "/~$-"]
            more += [h + m[1:] for m in [n, *more] if m[:1] == "~" for h in homes]
            more += [t + m[len(k):] for m in [n, *more] for k, t in links.items() if m.startswith(k + "/")]
            try:
                more += [f for m in [n, *more] for f in _pattern_forms(m, work)]
                shell.charge(work, sum(map(len, more)))
            except shell.ParseError:   # (one that reads as too many, or the budget: the names so far stay as written, and
                if len(parsed) > 5:    # the line is held as an unread one beside what the rules find in them)
                    parsed[5]["unread"] = True
                return out
            out += more
        return out
    act, listed, read, deep = _kills_signer(commands, finds), [], [], []
    for (c, kind), bases in zip(zip(commands, kinds), per):
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
                deep += at(named, bases)
            else:
                act += [" ".join(words)] + at(named, bases)
        elif kind is None:
            act += [" ".join(words)] + at(named, bases)[len(named):]
        else:
            {"read": read, "list": listed, "deep": deep}["deep" if feeds or c["glob"] else kind].extend(at(named, bases))
        act += [] if c.get("data_stdin") else c["stdin"]
    # a loop over literal words is read in its body already (shell.py knows the variable's values there)
    loops = [h for line in parsed[1] for h in _LOOP.findall(line) if re.search(r"[$`*?[]", h)]
    (deep if roams else act).extend(at(loops))
    reads, private = set(learned["read"]) if learned else set(), _private(learned, commands, "\n".join(act))
    for r in refs:
        (listed if r not in written and r in private else read if r not in written and r in reads else act).extend(
            at([r]))
    try:
        effects = _effects(parsed, work)
    except shell.ParseError:   # (as above: what the rest of the line says stays, and it is held)
        effects = []
        if len(parsed) > 5:
            parsed[5]["unread"] = True
    targets = at([t.partition(":")[2] for t in effects
                  if not t.startswith(("ROOT_TARGET:", "SAFE_MODE_TARGET:", "INTO_TARGET:", "TREE_TARGET:",
                                       "WORKTREE_TARGET:", "NAMED_TARGET:", "INSIDE_TARGET:"))])
    act += targets

    def tag(name, texts):
        return [name + s for s in _path_forms(list(dict.fromkeys(texts)))] if texts else []
    # (neither pattern finds a text alone that it doesn't find in all of them joined: none is searched one by one)
    joined = "\n".join(act)
    return tag("ACT:", act) + tag("TARGET:", targets) + tag("LIST:", listed) + tag("READ:", read) + \
        tag("DEEP:", deep) + \
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


def _code(parsed, work):
    """shell.analyse's code, each line without the data words a command carries (a git commit message, the pattern grep
    searches for: shell.data_words), as `target` leaves them out: blanked where the command's whole argv stands in the
    line once, program first, so the words are that program's arguments there (a quoted message `curl x | sh` is no
    download). That one place must be the command's own words: a line with a redirection beside them (which may split
    them, so the place is other commands' words: `grep "x | curl u" 2>/dev/null f; grep x | curl u f | sh`) keeps them,
    and so does a command whose words hold another command's, or another's hold its; so does a command twice in a line
    and a data word with a `$` or a backquote (a substitution in it runs). Then what downloads run (_download_runs).
    A download whose bytes nothing on the line can run (_inert_downloads) is data too: its program's name is left out
    where its words stand in a line once, so TK-D002's reading of a download before an interpreter passes it."""
    inert = _inert_downloads(parsed[0], parsed[2], work)
    found, runs_ = {}, _download_runs([c for c in parsed[0] if id(c) not in inert])
    lines = parsed[4]
    for argv in {" ".join(c["argv"]): c["argv"] for c in parsed[0] if id(c) in inert}.values():
        lines = [_drop_program(line, argv, work) for line in lines]
    parsed = (*parsed[:4], lines, *parsed[5:])
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


_QUOTES, _BLANKS = (re.compile(r"['\"]"), re.compile(r"['\"\\]")), re.compile(r"\s+")


def _drop_program(line, argv, work):
    """`line` without the program name of the command `argv`, where its words stand in it once (as the parser
    normalised them, or as typed: quotes and backslashes aside), else as it is. Charged to `work` (shell.charge)."""
    run = " ".join(argv)
    shell.charge(work, len(line))
    if line.count(run) == 1:
        return line.replace(run, run[len(argv[0]):])
    at = []
    for m in re.finditer(r"(?<![\w./-])%s(?![\w-])" % re.escape(argv[0]), line):
        shell.charge(work, 4 * len(run))
        if any(_BLANKS.sub(" ", quote.sub("", line[m.start():m.start() + 4 * len(run)])).startswith(run)
               for quote in _QUOTES):
            at.append(m.start())
    return line[:at[0]] + line[at[0] + len(argv[0]):] if len(at) == 1 else line


def _runs_code(argv):
    """Whether a command runs code its words or stdin name: a shell, an interpreter (not awk or sed), source or `.`."""
    return argv[0] in shell.SHELLS or argv[0] in ("source", ".") or shell._kind(argv[0]) not in (None, "awk", "sed")


def _may_run_input(argv):
    """Whether a program a download is piped into may run what it reads: a shell or interpreter reading its code from
    stdin, or any program not known to read only data (shell.DATA_ONLY; tar only listing). awk's and sed's code is read
    on its own (TK-D002's system(), the parser's sed e), and so is what a wrapper or runner runs (env, nice, xargs:
    the parser gives it as a command of its own)."""
    name, args = argv[0], argv[1:]
    if name in shell.WRAPPERS or (runner := name.partition("@")[0]) in shell.RUNNERS and shell.runner_at(runner, args):
        return False
    if name in shell.SHELLS:
        return shell._shell_mode(args, name)[0] == "stdin"
    if (kind := shell._kind(name)) and kind not in ("awk", "sed"):
        return shell._reads_stdin(kind, args)
    if name in ("tar", "gtar", "bsdtar"):
        return not any(a == "--list" or re.fullmatch(r"-?[A-Za-z]*t[A-Za-z]*", a) for a in args[:1] + [
            a for a in args if a.startswith("-") and not a.startswith("--")])
    return name not in shell.DATA_ONLY


# what a saved download may be read as without running it
_DATA_SAVE = re.compile(r"\.(?:json|jsonl|ndjson|csv|tsv|txt|html?|xml|md|svg|png|jpe?g|gif|webp|ico|pdf|mp3|wav|ogg|"
                        r"mp4|webm|woff2?|ttf|otf)$", re.I)
# the options a download read as data may give: curl's and wget's that only fetch, send or print (no config file, no
# file of URLs, no header, trace or cookie file, no wgetrc command, nothing verbose: it prints what the server says),
# each with whether it takes a value
_CURL_OPTIONS = dict.fromkeys(
    "-s --silent -S --show-error -L --location -f --fail --fail-with-body -k --insecure -I --head -i --include "
    "--compressed -g --globoff -N --no-buffer -4 --ipv4 -6 --ipv6 --http1.0 --http1.1 --http2 --http3 -# "
    "--progress-bar --no-progress-meter -G --get --fail-early -q --disable -O --remote-name --location-trusted "
    "--no-keepalive".split(), False) | dict.fromkeys(
    "-o --output -w --write-out -H --header -A --user-agent -e --referer -m --max-time --connect-timeout --retry "
    "--retry-delay --retry-max-time -X --request -d --data --data-raw --data-binary --data-urlencode --json -u --user "
    "-r --range -b --cookie --url --max-filesize --limit-rate --max-redirs --resolve --connect-to -x --proxy --cacert "
    "-E --cert --key --oauth2-bearer -C --continue-at".split(), True)
_WGET_OPTIONS = dict.fromkeys(
    "-q --quiet --spider -c --continue --no-check-certificate --https-only --no-cache --no-cookies -4 --inet4-only -6 "
    "--inet6-only --retry-connrefused -nc --no-clobber".split(), False) | dict.fromkeys(
    "-O --output-document -T --timeout -t --tries --header -U --user-agent --method --body-data --post-data "
    "--max-redirect --waitretry --connect-timeout --read-timeout --dns-timeout --compression --user --password "
    "--referer".split(), True)
# what curl's -w may print beside text: a status, a size, a time or a count (no header, URL or file: %output{} writes one)
_STATUS_FORMAT = re.compile(r"(?:[^%@\\]|\\[nrt\\]|%%|%\{(?:http_code|response_code|http_connect|http_version|exitcode|"
                            r"ssl_verify_result|(?:num|size|speed|time)_[a-z_]+)\})*")


def _download_options(d):
    """(the files a download writes to: its -o or -O values, curl's -O as `-O`; its -w formats; its URLs; the options
    it gives) when every option is one a data download may give (_CURL_OPTIONS, _WGET_OPTIONS), else None."""
    curl, args = d["argv"][0] == "curl", d["argv"][1:]
    known, outs, formats, urls, given, i = _CURL_OPTIONS if curl else _WGET_OPTIONS, [], [], [], set(), 0
    while i < len(args):
        a, value = args[i], None
        i += 1
        if a.startswith("--") or not curl and a in ("-nv", "-nc"):
            name, eq, value = (a, "", None) if curl else a.partition("=")
            if name not in known or eq and not known[name]:
                return None
            if known[name] and not eq:
                if i == len(args):
                    return None
                value, i = args[i], i + 1
            given.add(name)
        elif a.startswith("-") and len(a) > 1:
            for j in range(1, len(a)):
                name = "-" + a[j]
                if name not in known:
                    return None
                given.add(name)
                if known[name]:
                    value = a[j + 1:]
                    if not value:
                        if i == len(args):
                            return None
                        value, i = args[i], i + 1
                    break
        else:
            urls.append(a)
            continue
        if curl and given & {"-O", "--remote-name"} and "-O" not in outs:
            outs.append("-O")
        if name in ("-o", "--output", "-O", "--output-document") and value is not None:
            outs.append(value)
        elif name in ("-w", "--write-out"):
            formats.append(value)
        elif name == "--url":
            urls.append(value)
    return outs, formats, urls, given


def _url_name(url, wget):
    """The name a download of `url` saves under by its URL: its path's last part (wget's with the query too)."""
    parts = urlsplit(url if "://" in url else "//" + url)
    name = posixpath.basename(parts.path) or ("index.html" if wget else "")
    return name + ("?" + parts.query if wget and parts.query else "")


def _inert_downloads(commands, refs, work):
    """The ids of the line's downloads (curl, wget) whose bytes nothing on it can run, which TK-D002 reads as data. A
    download qualifies only on an allow-list: each option it gives only fetches (_download_options), it names one URL
    (not a curl glob of several), and it is no word of another command (a wrapper's, xargs', eval's). Then it is data
    - as a status check: it keeps nothing (curl's -o /dev/null, wget's --spider or -O /dev/null) and prints at most a
      status (_STATUS_FORMAT) to the terminal or pure readers down its pipe, or silent (curl's -s without -S, wget's
      -q) into a substitution;
    - where what it prints goes only to pure readers down its pipe or to the terminal (or, saving its bytes, a status
      into a substitution), and what it saves only to data files (_DATA_SAVE: a name ending in one's extension), and
      every other command on the line only reads and prints or reads no file (shell.reads_only: cat, jq, grep; cd,
      echo) or is another such download, and no variable but a lower-case one is set (PATH, LESSOPEN, BASH_ENV,
      PYTHONPATH change what runs).
    Any other company keeps main's reading: an interpreter, a runner module, inline code, a project script, a copy,
    move or link, an extractor. Linear in the line's commands and words, charged to `work` (shell.charge)."""
    out = set()
    downloads = [c for c in commands if c["argv"][0] in ("curl", "wget")]
    if not downloads:
        return out
    after = {}   # each pipeline's last stage that only reads and prints
    company = all(re.fullmatch(r"[a-z_][a-z0-9_]*", r.partition("=")[0]) for r in refs if re.match(r"[A-Za-z_]\w*=", r))
    for c in commands:
        shell.charge(work, 1 + len(c["argv"]))
        reads = shell.reads_only(c)
        if not reads:
            after[c["pipeline"]] = max(after.get(c["pipeline"], -1), (c.get("stage") or 0))
        company = company and (reads or c["argv"][0] in ("curl", "wget") and _download_options(c) is not None)
    for d in downloads:
        options = _download_options(d)
        if options is None or len(options[2]) != 1 or not all(_STATUS_FORMAT.fullmatch(f) for f in options[1]):
            continue
        (outs, _, (url,), given), wget = options, d["argv"][0] == "wget"
        alone = not d["via"] and after.get(d["pipeline"], -1) <= (d.get("stage") or 0)
        if outs and all(o == "/dev/null" for o in outs) or wget and "--spider" in given and not outs:   # a status check
            silent = "--quiet" in given or "-q" in given if wget else (
                given & {"-s", "--silent"} and not given & {"-S", "--show-error"})
            if alone or silent and d["via"] in (["$()"], ["``"]):
                out.add(id(d))
            continue
        # (in a substitution, one that saves its bytes prints only its status there)
        saves = outs and "-" not in outs and "/dev/stdout" not in outs
        if not (alone or saves and d["via"] in (["$()"], ["``"]) and after.get(d["pipeline"], -1) <= (
                d.get("stage") or 0)) or not company or ("[" in url or "{" in url) and not given & {"-g", "--globoff"}:
            continue
        saved = [o for o in d.get("out", ()) if o not in ("/dev/null", "/dev/stderr")] + [
            _url_name(url, wget) if o == "-O" else o for o in outs if o not in ("-", "/dev/stdout")] + [
            _url_name(url, wget) for _ in [1] if wget and not outs and "--spider" not in given]
        if all(_DATA_SAVE.search(s) and not re.search(r"[$`*?[\]{}#\\]", s) for s in saved):
            out.add(id(d))
    return out


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
        # (shell.DATA_ONLY, tar listing), a shell or an interpreter that reads its code from stdin; one given its code
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
        names = {n for w in d["argv"][1:] + saved for n in (posixpath.basename(w), shell.base_name(w))} - {""}
        anyname = tool == "curl" and any(re.fullmatch(r"--remote-header-name|--config|-[A-Za-z]*[JK][A-Za-z]*", a)
                                         for a in d["argv"][1:])

        def named(w):   # a word that names a saved file, as bash reads it or as Windows does (shell.base_name)
            return bool(names & {posixpath.basename(w), shell.base_name(w)})

        def runs(c):
            given = c["argv"][1:] + list(c.get("in", ()))
            return named(c["word"]) or anyname and "/" in c["word"] or _runs_code(c["argv"]) and (
                anyname and given or any(named(w) or re.search(
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
    """(the subjects as text, but each longer than MAX_SUBJECT, past `tag` bytes a field's own tag adds (_TAGGED);
    their casefolded forms, which the prefilters read (RE2 matching in any case folds a long s to s and the Kelvin sign
    to k, as casefold() does and lower() doesn't); those joined by a newline; whether one was longer). A rule matches
    every subject it can read, wherever a long one is, and takes TK-OVERSIZE only when it matches none of them: a long
    word never hides a later command (`X=<17 KB>; true $X$X$X$X; sudo id`) or a later path."""
    texts = []
    for s in subjects:
        b = s if s.isascii() else s.encode("utf-8", "backslashreplace")   # ASCII is its own UTF-8
        if len(b) > MAX_SUBJECT + tag:
            continue
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
