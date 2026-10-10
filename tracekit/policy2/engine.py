"""Policy v2 engine: deterministic matching over a compiled policy (design §4.2).

google-re2 when installed, else the `regex` module on the same pattern subset in ASCII mode (`compile.translate`).
Every decision names the engine (id@version) and the policy_hash. Precedence: deny > ask > flag > allow.
"""
import fnmatch

from . import classes, shell
from .compile import CLASSES, SECTIONS, canonical, policy_hash, translate

MAX_SUBJECT = 64 * 1024     # bytes of UTF-8; a longer subject is denied (TK-OVERSIZE), never cut or windowed
REGEX_TIMEOUT_S = 1.0       # fallback engine only: a match that runs out of time denies, marked nondeterministic


def _backend(name):
    """Return (engine id, compile(pattern), match(compiled, text, full))."""
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
                    lambda c, s, full: (c.fullmatch if full else c.search)(s))
    import regex
    return (f"regex@{regex.__version__}", lambda p: regex.compile(translate(p), regex.ASCII | regex.V0),
            lambda c, s, full: (c.fullmatch if full else c.search)(s, timeout=REGEX_TIMEOUT_S))


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
        return next((cls for pat, cls in sorted(tools.items()) if fnmatch.fnmatchcase(tool, pat)), "unknown")

    def decide(self, tool, args, cls=None):
        """Return {verdict, rule_ids, policy_hash, engine[, nondeterministic]} for one tool call. `cls` overrides the
        class the policy maps the tool to."""
        args = args if isinstance(args, dict) else {"value": args}
        cls = cls or self.tool_class(tool)
        fields = classes.extract(cls, tool, args)
        hits = {sec: [] for sec in SECTIONS}
        if cls == "unknown" and self.policy.get("unknown_tools") in SECTIONS:
            hits[self.policy["unknown_tools"]].append("TK-UNKNOWN-TOOL")
        nondeterministic = False
        parsed = [], []
        if cls == "shell":
            command = fields.get("command", "")
            if len(_text(command if isinstance(command, str) else canonical(command)).encode()) > MAX_SUBJECT:
                hits["deny"].append("TK-OVERSIZE")
            else:
                try:
                    parsed = _shell(args)
                except shell.ParseError:
                    hits["ask"].append("TK-SHELL-PARSE")
                if any(c["opaque"] for c in parsed[0]):
                    hits["ask"].append("TK-SHELL-PARSE")
        for sec, rule, tool_re, pat, unless in self.rules:
            if rule.get("class", cls) != cls:
                continue
            try:
                if tool_re is not None and not self._match(tool_re, _text(tool), True):
                    continue
                for subject in self._subjects(cls, rule.get("field"), args, fields, parsed):
                    subject = _text(subject)
                    if len(subject.encode("utf-8")) > MAX_SUBJECT:
                        hits["deny"].append("TK-OVERSIZE")
                        break
                    # `unless`: an exemption checked against the same subject (use it only where the subject is one
                    # target, e.g. a file path; in a whole command it could exempt a different target)
                    if self._match(pat, subject, False) and not (unless is not None and self._match(unless, subject, False)):
                        hits[sec].append(rule["id"])
                        break
            except TimeoutError:
                nondeterministic = True
                hits["deny"].append(rule["id"])
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
        entry of a `paths` list (every file of a Codex patch) is a path too."""
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


def _shell(args):
    """(commands, normalised lines) of a shell call. `command` or `cmd` is a command line or an argv list; `commands`
    (OpenAI's shell tool) a list of command lines. Anything else, or more than one of them, raises ParseError."""
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
