"""Policy v2 engine: deterministic matching over a compiled policy (design §4.2).

google-re2 when installed, else the `regex` module on the same pattern subset in ASCII mode (`compile.translate`).
Every decision names the engine (id@version) and the policy_hash. Precedence: deny > ask > flag > allow.
"""
import fnmatch
import functools
import posixpath
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
        parsed, oversize = ([], [], [], [], []), []
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
                    # its own target and code
                    raw = command if isinstance(command, str) else canonical(command)
                    parsed = [], [], [raw], [], [raw]
                if any(c["opaque"] for c in parsed[0]):
                    unreadable.append("TK-SHELL-PARSE")
        # from here: the fallback's time is its matches', not the parse's, which is the same on either engine and bounded by MAX_WORK (a few times the 64 KiB input)
        nondeterministic, deadline = False, time.monotonic() + REGEX_TIMEOUT_S
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
        each line the parser normalised, a shell `code` those without the text a command only writes into a file
        (shell.analyse); an fs `path` with `..` also matches its lexically normalised form, and each entry of a
        `paths` list (every file of a Codex patch) is a path too. `target` (every class) is what the call
        acts on rather than what it carries (Engine._targets); shell `effects` the files it writes or deletes
        (_effects); sql `code` is one subject per dialect reading. With
        `split`, a list value is one subject per element (nested lists flattened)."""
        if field == "target":
            return Engine._targets(cls, args, fields, parsed)
        if cls == "shell" and field == "effects":
            return _effects(parsed)
        if cls == "shell" and field == "package_index":
            return _package_indexes(parsed[0], parsed[2])
        if cls == "shell" and field == "container_host_access":
            return _container_host_access(parsed[0])
        if cls == "sql" and field == "code":
            return fields.get("code", [])
        if cls == "shell" and field == "code":
            return parsed[4]
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
        writes .env on macOS); fs: the paths; http and browser: the URL; email: the attachments; mcp, app and unknown
        tools: the whole call. Each URL is also matched as scheme://canonical-host/ (classes.url_target), so a host in
        decimal, hex, octal or IPv6 form reads as the address it is."""
        if cls == "shell":
            words = [[a for i, a in enumerate(c["argv"]) if i not in data] for c in parsed[0]
                     for data in [shell.data_words(c["argv"])]]
            found = [a for ws in words for a in ws] + parsed[2]
            urls = [t for t in map(classes.url_target, (u for w in found for u in _URL.findall(w))) if t]
            bare = [t for t in (classes.url_target("http://" + w) for w in found if _BARE_ADDRESS.match(w))
                    if t and _BARE_TARGET.fullmatch(t)]
            targets = [" ".join(w) for w in words] + parsed[2]
            have = set(targets)
            return targets + [f for f in dict.fromkeys(map(str.casefold, targets)) if f not in have] + urls + bare
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
    """shell.analyse() of a shell call: (commands, normalised lines, other words that name something, files
    redirections write, code). `command` or `cmd` is a command line or an argv list; `commands` (OpenAI's shell tool)
    a list of command lines. Anything else, or more than one of them, raises ParseError."""
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


# variables that set a package source: before a command (`PIP_INDEX_URL=… pip install`), or through env or export
_SOURCE_VARIABLES = dict.fromkeys(("PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "UV_INDEX_URL", "UV_INDEX",
                                   "UV_EXTRA_INDEX_URL", "UV_DEFAULT_INDEX", "UV_FIND_LINKS"), "pypi.org")
_SOURCE_VARIABLES["NPM_CONFIG_REGISTRY"] = "registry.npmjs.org"


def _package_indexes(commands, refs=()):
    """Return only explicitly selected non-default package sources, one subject per effective option or variable."""
    words = list(refs) + [a for c in commands if c["argv"][:1] in (["env"], ["export"]) for a in c["argv"][1:]]
    out = [value for name, eq, value in (w.partition("=") for w in words)
           if eq and name.upper() in _SOURCE_VARIABLES and _non_default_source(value, _SOURCE_VARIABLES[name.upper()])]
    for command in commands:
        argv = command["argv"]
        if not argv:
            continue
        exe = argv[0].rsplit("/", 1)[-1].lower()
        args = argv[1:]
        if exe.startswith("python") and len(args) >= 2 and args[:2] == ["-m", "pip"]:
            exe, args = "pip", args[2:]
        exe = "pip" if re.fullmatch(r"pip[0-9.]*", exe) else {"uvx": "uv", "npx": "npm", "pnpx": "pnpm"}.get(exe, exe)
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
        if next((a for a in args if not a.startswith("-")), None) in ("publish", "unpublish"):
            continue   # publishing doesn't change where installs come from
        if args[:1] == ["config"] and "set" in args or exe == "npm" and args[:1] == ["set"]:
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
            if name in options:
                if value is None and i + 1 < len(args):
                    value = args[i + 1]
                    i += 1
                if exe in ("npm", "pnpm", "yarn", "bun"):
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


def _non_default_source(value, default):
    host = classes.url_info(value).get("host")
    return host != default


# docker/podman run options that take no value; any other long option without `=` takes the next word
_RUN_FLAGS = {"--detach", "--interactive", "--tty", "--rm", "--init", "--privileged", "--read-only", "--publish-all",
              "--no-healthcheck", "--oom-kill-disable", "--disable-content-trust", "--quiet", "--sig-proxy", "--help",
              "--use-api-socket", "--replace", "--rmi", "--http-proxy", "--env-host", "--no-hosts", "--passwd",
              "--read-only-tmpfs", "--tls-verify"}
_HOST_PATH = re.compile(r"/|/proc(/.*)?")   # a mount source that hands the container the host's root or /proc


def _host_path(source):
    """Whether mount source `source` is the host's root or /proc, read as the runtime resolves it (`//`, `/.`)."""
    p = posixpath.normpath(source)
    return bool(_HOST_PATH.fullmatch("/" + p.lstrip("/") if p.startswith("/") else p))


def _container_host_access(commands):
    """A docker/podman run whose own options (those before the image: later words are the container's command) give
    it host privileges, the host's process space, or the host's root or /proc."""
    for command in commands:
        argv = command["argv"]
        if len(argv) < 2 or argv[0].rsplit("/", 1)[-1] not in ("docker", "podman") or argv[1] != "run":
            continue
        args, i = argv[2:], 0
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
    path casefolded: what redirections write, and what rm, unlink, shred, truncate, tee, cp, mv, install, ln, dd,
    sed -i and perl -i name, and find with -delete or -exec rm."""
    tags = ["WRITE_TARGET:" + _text(ref) for ref in parsed[3]] + _command_effects(parsed[0])
    return list(dict.fromkeys(tags + [k + ":" + path.casefold() for k, _, path in (t.partition(":") for t in tags)]))


def _command_effects(commands):
    out = []
    for command in commands:
        argv = command["argv"]
        if not argv:
            continue
        exe = argv[0].rsplit("/", 1)[-1]
        args = argv[1:]
        if exe == "find" and ("-delete" in args or any(
                a in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(args)
                and args[i + 1].rsplit("/", 1)[-1] in ("rm", "unlink", "shred", "truncate") for i, a in enumerate(args))):
            # its start paths, and the log and history names among its tests (`-name .bash_history`) but those
            # `-prune` leaves out
            paths = []
            for arg in args:
                if arg.startswith("-"):
                    break
                paths.append(arg)
            pruned = {i for i in range(len(args)) if args[i + 1:i + 2] == ["-prune"]}
            paths += [a for i, a in enumerate(args) if i not in pruned and _log_or_history(a)]
            out.extend("DELETE_TARGET:" + path for path in dict.fromkeys(paths))
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
    return out


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
