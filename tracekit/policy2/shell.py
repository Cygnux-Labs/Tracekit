"""Structural shell parser for policy matching (design §4.4; no bashlex).

`parse(command)` returns every simple command the line would run, including those reached through wrappers, `sh -c`
strings, substitutions, heredocs into a shell and interpreter one-liners:
`{"argv": [...], "via": [...], "pipeline": n, "glob": bool, "opaque": bool}`. argv[0] is a basename;
`via` says how the command was reached (empty at top level); commands with the same `pipeline` are stages of one
pipeline, in order. `opaque`: what the command runs cannot be read from the line (a glob or brace in its name, a shell
reading its script from a pipe, a file or inherited stdin, `source` of a stream). Variables are not expanded and
encodings are not decoded. A line it cannot parse raises ParseError.

`analyse(command)` also returns the normalised lines: each parsed script with quotes and escapes resolved and
redirections kept, for rules that match a whole command line.
"""
import re


class ParseError(ValueError):
    pass


MAX_DEPTH = 32
MAX_WORK = 1 << 18   # characters parsed in total, re-parsed consumer strings included: 4 × the largest subject, so
                     # a worst-case command costs a fraction of a second of the signer (the parser holds the GIL)
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash"}
# wrapper -> (options that take a value, positional arguments before the command)
WRAPPERS = {"command": ((), 0), "env": (("-u", "-C", "--unset", "--chdir"), 0), "nohup": ((), 0),
            "time": (("-f", "-o", "--format", "--output"), 0),
            "xargs": (("-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s", "--arg-file", "--delimiter", "--max-lines",
                       "--max-args", "--max-procs", "--max-chars", "--process-slot-var"), 0),
            "busybox": ((), 0), "exec": (("-a",), 0), "timeout": (("-s", "-k", "--signal", "--kill-after"), 1),
            "nice": (("-n", "--adjustment"), 0),
            "sudo": (("-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-R", "-T", "--user", "--group", "--close-from",
                      "--chdir", "--host", "--prompt", "--role", "--type", "--other-user", "--chroot",
                      "--command-timeout"), 0),
            "doas": (("-u", "-C"), 0), "stdbuf": (("-i", "-o", "-e", "--input", "--output", "--error"), 0),
            "setsid": ((), 0), "chroot": (("--userspec", "--groups"), 1), "builtin": ((), 0),
            "nsenter": (("-t", "-S", "-G", "--target", "--setuid", "--setgid"), 0),
            "unshare": (("-R", "-w", "-S", "-G", "--root", "--wd", "--setuid", "--setgid", "--propagation",
                         "--setgroups", "--map-user", "--map-group", "--map-users", "--map-groups"), 0),
            "flock": (("-w", "-E", "--wait", "--timeout", "--conflict-exit-code"), 1),
            "ionice": (("-c", "-n", "-p", "-P", "-u", "--class", "--classdata", "--pid", "--pgid", "--uid"), 0),
            "strace": (("-a", "-b", "-e", "-E", "-I", "-o", "-O", "-p", "-P", "-s", "-S", "-u", "-X", "--output"), 0),
            "runuser": (("-u", "-g", "-G", "-s", "-w", "--user", "--group", "--supp-group", "--shell",
                         "--whitelist-environment"), 0)}
# commands that run a string through a shell: -c anywhere in their arguments (getopt permutes)
DASH_C = {"su", "script"}
STREAMS = ("/dev/stdin", "/dev/fd/", "/proc/self/fd/", "<(")
KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "{", "}", "!"}
SSH_OPTS = set("-b -c -D -E -e -F -I -i -J -L -l -m -O -o -p -Q -R -S -W -w".split())
INTERPRETER = re.compile(r"python[0-9.]*|node|nodejs|perl|ruby")
CODE_FLAGS = {"python": "c", "node": "ep", "perl": "eE", "ruby": "e"}
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=")
_REDIR = re.compile(r"(\d*|\{\w+\})(&>>|&>|>>|>&|>\||<<<|<<-|<<|<&|<>|>|<)")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-]")
_ANSI = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "v": "\v"}
# lean: interpreter code is scanned for string or list literals passed to a process-spawning call, plus backticks in
# perl/ruby; code that builds the command at run time is not followed (tripwire territory, like encodings)
_CALL = re.compile(r"\b(system|popen|execSync|execFileSync|exec|spawn\w*|run|call|check_call|check_output|Popen|getoutput)\s*\(\s*")
_STR = re.compile(r"""(['"])((?:\\.|(?!\1)[^\\\n])*)\1""")
_TICK = re.compile(r"`([^`]*)`")


def parse(command):
    return analyse(command)[0]


def analyse(command):
    """(the commands, the normalised lines)."""
    ctx = {"cmds": [], "lines": [], "pipes": 0, "depth": 0, "work": 0}
    _Parser(command, ctx, []).script()
    return ctx["cmds"], [x for x in ctx["lines"] if x]


def analyse_argv(argv):
    """analyse() for a command given as an argv list, run without a shell."""
    ctx = {"cmds": [], "lines": [" ".join(argv)], "pipes": 1, "depth": 0, "work": 0}
    _Parser("", ctx, []).emit(list(argv), 1, [])
    return ctx["cmds"], [x for x in ctx["lines"] if x]


def _unwrap(name, args):
    opts, positional = WRAPPERS[name]
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if name == "command" and a in ("-v", "-V"):
            return []   # a lookup, not a run
        if a.startswith("-") and len(a) > 1:
            i += 2 if a in opts else 1
        elif _ASSIGN.match(a):
            i += 1
        else:
            break
    return args[i + positional:]


def _shell_mode(args):
    """('c', script) for sh -c, ('stdin', None) when the shell reads its script from stdin (or a stream such as
    /dev/stdin or <( )), else (None, None). Options after -c are skipped as the shell does: the script is the first
    operand."""
    i, flags = 0, ""
    while i < len(args):
        a = args[i]
        if a in ("-o", "+o", "-O", "+O"):
            i += 2
            continue
        if a in ("--", "-"):
            i += 1
            break
        if a[:1] not in "-+" or len(a) == 1:
            break
        if a[0] == "-" and not a.startswith("--"):
            flags += a[1:]
        i += 1
    if "c" in flags:
        return ("c", args[i]) if i < len(args) else (None, None)
    if "s" in flags or i >= len(args) or args[i].startswith(STREAMS):
        return "stdin", None
    return None, None   # a script file


def _dash_c(args):
    """The value of -c/--command (also bundled, as in -lc), or None."""
    for i, a in enumerate(args):
        if a == "--":
            break
        long = next((f for f in ("--command", "--session-command") if a.startswith(f)), None)
        if long and a[len(long):len(long) + 1] == "=":
            return a[len(long) + 1:]
        if a == long or (re.fullmatch(r"-[A-Za-z]+", a) and "c" in a):
            rest = "" if long else a[a.index("c") + 1:]
            return rest or (args[i + 1] if i + 1 < len(args) else None)
    return None


def _split_string(args):
    """env -S: the string it splits into the command, joined with the arguments after it; None without -S."""
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] != "--":
        a = args[i]
        if a in ("-S", "--split-string"):
            return " ".join(args[i + 1:])
        if a.startswith("--split-string="):
            return " ".join([a[15:]] + args[i + 1:])
        if re.fullmatch(r"-[iv0]*S.+", a, re.S):
            return " ".join([a[a.index("S") + 1:]] + args[i + 1:])
        i += 2 if a in WRAPPERS["env"][0] else 1
    return None


def _ssh_command(args):
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in SSH_OPTS else 1
    return " ".join(args[i + 1:])


def _find_execs(args):
    out, cur = [], None
    for a in args:
        if cur is None:
            if a in ("-exec", "-execdir", "-ok", "-okdir"):
                cur = []
        elif a in (";", "+"):
            if cur:
                out.append(cur)
            cur = None
        else:
            cur.append(a)
    return out


def _code_arg(kind, args):
    for i, a in enumerate(args[:-1]):
        if (kind == "node" and a in ("--eval", "--print")) or \
                (re.fullmatch(r"-[A-Za-z]+", a) and a[-1] in CODE_FLAGS[kind]):
            return args[i + 1]
    return None


def _ansi_c(text):
    def one(m):
        e = m.group(1)
        if e[0] in "xu" and len(e) > 1:
            return chr(int(e[1:], 16))
        if e[0] in "01234567":
            return chr(int(e, 8))
        return _ANSI.get(e, e)
    return re.sub(r"\\(x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|[0-7]{1,3}|.)", one, text, flags=re.S)


class _Parser:
    def __init__(self, src, ctx, via):
        self.s, self.i, self.ctx, self.via, self.heredocs, self.out = src, 0, ctx, via, [], []
        ctx["work"] += len(src)
        if ctx["work"] > MAX_WORK:
            raise ParseError("too much nested shell text")

    def peek(self, k=0):
        return self.s[self.i + k:self.i + k + 1]

    def at(self, text):
        return self.s.startswith(text, self.i)

    def enter(self):
        self.ctx["depth"] += 1
        if self.ctx["depth"] > MAX_DEPTH:
            raise ParseError("nested too deeply")

    def leave(self):
        self.ctx["depth"] -= 1

    def nested(self, text, via):
        _Parser(text, self.ctx, via).script()

    def script(self):
        self.list(None)
        self.flush()
        if self.heredocs:
            raise ParseError(f"heredoc {self.heredocs[0]['delim']} not terminated")

    def flush(self):
        while self.out[-1:] == [";"]:
            self.out.pop()
        self.ctx["lines"].append(" ".join(self.out))

    def blank(self):
        s = self.s
        while self.i < len(s):
            if s[self.i] in " \t":
                self.i += 1
            elif self.at("\\\n"):
                self.i += 2
            elif s[self.i] == "#":
                j = s.find("\n", self.i)
                self.i = len(s) if j < 0 else j
            else:
                break

    def gap(self):
        self.blank()
        while self.peek() == "\n":
            self.i += 1
            self.read_heredocs()
            self.blank()

    def list(self, end):
        self.enter()
        while True:
            self.gap()
            if not self.peek() or self.peek() == ")":
                break
            self.pipeline()
            self.blank()
            self.out.append(self.s[self.i:self.i + 2] if self.at("&&") or self.at("||") else
                            self.peek() if self.peek() in (";", "&") else ";")
            if self.at("&&") or self.at("||"):
                self.i += 2
                self.gap()
                if not self.peek() or self.peek() == ")":
                    raise ParseError("command expected after && or ||")
            elif self.at(";;"):
                raise ParseError("case is not supported")
            elif self.peek() in (";", "&"):
                self.i += 1
            elif self.peek() not in ("\n", ")", ""):
                raise ParseError(f"unexpected {self.peek()!r}")
        if (self.peek() == ")") != (end == ")"):
            raise ParseError("unmatched )" if end is None else "missing )")
        self.i += end is not None
        self.leave()

    def pipeline(self):
        self.ctx["pipes"] += 1
        pid = self.ctx["pipes"]
        while True:
            if not self.simple(pid):
                raise ParseError("command expected")
            self.blank()
            if self.at("||"):
                return
            if self.at("|&"):
                self.i += 2
            elif self.peek() == "|":
                self.i += 1
            else:
                return
            self.out.append("|")
            self.gap()

    def simple(self, pid):
        words, globs, strings, docs = [], [], [], []
        consumed = loop_header = False
        while True:
            self.blank()
            c = self.peek()
            if not c or c in "\n;|)" or (c == "&" and not self.at("&>")):
                break
            consumed = True
            if c == "(":
                if words or loop_header or self.at("(("):
                    raise ParseError("unexpected ( (arithmetic and function definitions are not supported)")
                self.i += 1
                self.out.append("(")
                self.list(")")
                self.out.append(")")
                continue
            m = None if c in "<>" and self.peek(1) == "(" else _REDIR.match(self.s, self.i)
            if m:
                self.i = m.end()
                self.blank()
                target = self.word()
                if target is None:
                    raise ParseError("redirection without a target")
                self.out += [m.group(0), target[0]]
                if m.group(2) in ("<<", "<<-"):
                    docs.append({"delim": target[0], "strip": m.group(2) == "<<-", "expand": target[0] == target[1],
                                 "via": self.via, "cmds": []})
                    self.heredocs.append(docs[-1])
                elif m.group(2) == "<<<":
                    strings.append(target[0])
                continue
            start = self.i
            text, raw, g = self.word()
            self.out.append(text)
            if loop_header:
                continue
            if not words and raw == text and text in KEYWORDS:
                continue
            if not words and raw == text and text in ("for", "select"):
                loop_header = True   # the loop words are not run; `do` starts the body
                continue
            if not words and raw == text and text in ("case", "function", "coproc"):
                raise ParseError(f"{text} is not supported")
            if not words and _ASSIGN.match(self.s, start):
                continue
            words.append(text)
            globs.append(g)
        cmds = self.emit(words, pid, self.via, any(globs), globs) if words else []
        for d in docs:
            d["cmds"] = cmds
        shell = _stdin_shell(cmds)
        if shell and not docs and not strings:
            shell["opaque"] = True   # its script comes from a pipe, a file or inherited stdin
        for text in strings if shell else ():
            self.nested(text, shell["via"] + [shell["argv"][0] + " <<<"])
        return consumed

    def emit(self, argv, pid, via, glob=False, globs=None):
        """`globs[i]`: argv[i] has an unquoted glob or brace (only words of the line itself have one)."""
        cmds, globs = [], globs or [False] * len(argv)
        while argv:
            if len(via) > MAX_DEPTH:
                raise ParseError("nested too deeply")
            name, args = argv[0].rsplit("/", 1)[-1] or argv[0], argv[1:]
            cmd = {"argv": [name] + args, "via": via, "pipeline": pid, "glob": glob, "opaque": globs[0]}
            self.ctx["cmds"].append(cmd)
            cmds.append(cmd)
            if name in DASH_C:
                if _dash_c(args) is None:
                    cmd["opaque"] = True   # an interactive shell: it runs whatever its stdin holds
                else:
                    self.nested(_dash_c(args), via + [name + " -c"])
            elif name == "sg":
                self.nested(" ".join(a for a in args[1:] if a != "-c"), via + ["sg -c"])
            elif name == "watch":
                i = 0
                while i < len(args) and args[i].startswith("-"):
                    i += 2 if args[i] in ("-n", "--interval") else 1
                self.nested(" ".join(args[i:]), via + ["watch sh -c"])
            elif name == "env" and _split_string(args) is not None:
                self.nested(_split_string(args), via + ["env -S"])
            elif name in WRAPPERS:
                if name == "runuser" and _dash_c(args) is not None:
                    self.nested(_dash_c(args), via + ["runuser -c"])
                inner = _unwrap(name, args)
                if name == "flock" and inner[:1] in (["-c"], ["--command"]):
                    self.nested(" ".join(inner[1:2]), via + ["flock -c"])
                    break
                argv, via, globs = inner, via + [name], globs[len(argv) - len(inner):]
                continue
            elif name in SHELLS:
                mode, script = _shell_mode(args)
                if mode == "c":
                    self.nested(script, via + [name + " -c"])
            elif name in ("source", ".") and args[:1] and args[0].startswith(STREAMS):
                cmd["opaque"] = True
            elif name == "eval":
                self.nested(" ".join(args), via + ["eval"])
            elif name == "ssh":
                self.nested(_ssh_command(args), via + ["ssh"])
            elif name == "find":
                for inner in _find_execs(args):
                    self.emit(inner, pid, via + ["find -exec"])
            elif INTERPRETER.fullmatch(name):
                self.code(name, args, pid, via)
            break
        return cmds

    def code(self, name, args, pid, via):
        kind = "python" if name.startswith("python") else "node" if name.startswith("node") else name
        code = _code_arg(kind, args)
        if code is None:
            return
        via = via + [name + " code"]
        for m in _CALL.finditer(code):
            if kind == "python" and m.group(1) == "exec":
                continue   # Python's exec runs Python, not a shell
            rest = code[m.end():]
            if rest.startswith("[") and "]" in rest:
                argv = [body for _, body in _STR.findall(rest[:rest.index("]")])]
                if argv:
                    self.emit(argv, pid, via)
            elif _STR.match(rest):
                self.nested(_STR.match(rest).group(2), via)
        for m in _TICK.finditer(code) if kind in ("perl", "ruby") else ():
            self.nested(m.group(1), via)

    def read_heredocs(self):
        docs, self.heredocs = self.heredocs, []
        s = self.s
        for d in docs:
            lines = []
            while True:
                if self.i >= len(s):
                    raise ParseError(f"heredoc {d['delim']} not terminated")
                j = s.find("\n", self.i)
                end = len(s) if j < 0 else j
                line, self.i = s[self.i:end], min(end + 1, len(s))
                if (line.lstrip("\t") if d["strip"] else line) == d["delim"]:
                    break
                lines.append(line)
            body = "\n".join(lines)
            shell = _stdin_shell(d["cmds"])
            if shell:
                self.nested(body, shell["via"] + [shell["argv"][0] + " <<"])
            elif d["expand"]:
                _Parser(body, self.ctx, d["via"] + ["<<"]).dquote(None)

    def word(self):
        """Return (text, raw source, has an unquoted glob or brace expansion), or None at an operator or the end."""
        s, start, buf, bare = self.s, self.i, [], []
        while self.i < len(s):
            c = s[self.i]
            if c in "<>" and self.peek(1) == "(":
                at = self.i
                self.i += 2
                self.sub(c + "()")
                buf.append(s[at:self.i])
                continue
            if c in " \t\n;&|()<>":
                break
            if c == "\\":
                if not self.at("\\\n"):
                    buf.append(s[self.i + 1:self.i + 2])
                self.i += 2
            elif c == "'":
                j = s.find("'", self.i + 1)
                if j < 0:
                    raise ParseError("unterminated '")
                buf.append(s[self.i + 1:j])
                self.i = j + 1
            elif c == '"':
                self.i += 1
                buf.append(self.dquote('"'))
            elif c == "$":
                buf.append(self.dollar(False))
            elif c == "`":
                buf.append(self.backtick())
            else:
                bare.append(c)
                buf.append(c)
                self.i += 1
        if self.i == start:
            return None
        bare = "".join(bare)   # neither pattern backtracks: each scan from a `[` or `{` stops at the next bracket
        glob = re.search(r"[*?]|\[[^][]+\]", bare) or any("," in b or ".." in b for b in re.findall(r"\{[^{}]*\}", bare))
        return "".join(buf), s[start:self.i], bool(glob)

    def sub(self, label):
        via, out, self.via, self.out = self.via, self.out, self.via + [label], []
        self.list(")")
        self.flush()
        self.via, self.out = via, out

    def dquote(self, term):
        """Read up to `term` ("\"", "}" or None for a heredoc body), running substitutions; return the text."""
        self.enter()
        s, buf = self.s, []
        while True:
            if self.i >= len(s):
                if term is None:
                    break
                raise ParseError(f"unterminated {term}")
            c = s[self.i]
            if c == term:
                self.i += 1
                break
            if c == "\\" and self.peek(1) and self.peek(1) in '$`"\\\n':
                if self.peek(1) != "\n":
                    buf.append(self.peek(1))
                self.i += 2
            elif c == "$":
                buf.append(self.dollar(True))
            elif c == "`":
                buf.append(self.backtick())
            else:
                buf.append(c)
                self.i += 1
        self.leave()
        return "".join(buf)

    def dollar(self, in_dq):
        s, start, nxt = self.s, self.i, self.peek(1)
        if nxt == "'" and not in_dq:
            m = re.compile(r"((?:\\.|[^'\\])*)'", re.S).match(s, self.i + 2)
            if not m:
                raise ParseError("unterminated $'")
            self.i = m.end()
            return _ansi_c(m.group(1))
        if nxt == '"' and not in_dq:
            self.i += 2
            return self.dquote('"')
        if self.at("$(("):
            depth, j = 0, self.i + 1
            while j < len(s):
                depth += {"(": 1, ")": -1}.get(s[j], 0)
                if depth == 0:
                    break
                j += 1
            if j >= len(s):
                raise ParseError("unterminated $((")
            # arithmetic only if the inner "(" closes right before the outer ")": bash runs `$((cmd) )` as a subshell
            inner, k = 0, self.i + 2
            while k < j:
                inner += {"(": 1, ")": -1}.get(s[k], 0)
                if inner == 0:
                    break
                k += 1
            if k != j - 1:
                raise ParseError("$(( that is not arithmetic (a subshell inside $( )) is not supported")
            if "$(" in s[self.i + 3:j] or "`" in s[self.i + 3:j]:
                raise ParseError("command substitution inside $(( )) is not supported")
            self.i = j + 1
        elif nxt == "(":
            self.i += 2
            self.sub("$()")
        elif nxt == "{":
            self.i += 2
            self.dquote("}")
        else:
            m = _NAME.match(s, self.i + 1)
            self.i = m.end() if m else self.i + 1
        return s[start:self.i]

    def backtick(self):
        m = re.compile(r"((?:\\.|[^`\\])*)`", re.S).match(self.s, self.i + 1)
        if not m:
            raise ParseError("unterminated `")
        start, self.i = self.i, m.end()
        self.nested(re.sub(r"\\([`\\$])", r"\1", m.group(1)), self.via + ["``"])
        return self.s[start:self.i]


def _stdin_shell(cmds):
    return next((c for c in cmds if c["argv"][0] in SHELLS and _shell_mode(c["argv"][1:])[0] == "stdin"), None)
