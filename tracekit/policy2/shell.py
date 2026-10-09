"""Structural shell parser for policy matching (design §4.4; no bashlex).

`parse(command)` returns every simple command the line would run, including those reached through wrappers, `sh -c`
strings, substitutions, heredocs into a shell and interpreter one-liners:
`{"argv": [...], "via": [...], "pipeline": n, "redirects": [[op, target]], "glob": bool}`. argv[0] is a basename;
`via` says how the command was reached (empty at top level); commands with the same `pipeline` are stages of one
pipeline, in order. Variables are not expanded and encodings are not decoded. A line it cannot parse raises ParseError.
"""
import re


class ParseError(ValueError):
    pass


MAX_DEPTH = 32
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash"}
# wrapper -> (options that take a value, positional arguments before the command)
WRAPPERS = {"command": ((), 0), "env": (("-u", "-C", "--unset", "--chdir"), 0), "nohup": ((), 0),
            "time": (("-f", "-o"), 0), "xargs": (("-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s"), 0),
            "busybox": ((), 0), "exec": (("-a",), 0), "timeout": (("-s", "-k", "--signal", "--kill-after"), 1),
            "nice": (("-n",), 0), "sudo": (("-u", "-g", "-C", "-D", "-p", "-r", "-t", "-U", "-R", "-T"), 0),
            "doas": (("-u", "-C"), 0)}
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
_STR = re.compile(r"""(['"])((?:\\.|(?!\1).)*)\1""")
_TICK = re.compile(r"`([^`]*)`")


def parse(command):
    ctx = {"cmds": [], "pipes": 0, "depth": 0}
    _Parser(command, ctx, []).script()
    return ctx["cmds"]


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
    """('c', script) for sh -c, ('stdin', None) when the shell reads its script from stdin, else (None, None)."""
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-o", "+o", "-O", "+O"):
            i += 2
        elif a == "--":
            break
        elif a[:1] in "-+" and len(a) > 1:
            if a[0] == "-" and not a.startswith("--") and "c" in a:
                return ("c", args[i + 1]) if i + 1 < len(args) else (None, None)
            if a[0] == "-" and not a.startswith("--") and "s" in a:
                return "stdin", None
            i += 1
        else:
            return None, None   # a script file
    return ("stdin", None) if i + 1 >= len(args) else (None, None)


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
        self.s, self.i, self.ctx, self.via, self.heredocs = src, 0, ctx, via, []

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
        if self.heredocs:
            raise ParseError(f"heredoc {self.heredocs[0]['delim']} not terminated")

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
            self.gap()

    def simple(self, pid):
        words, glob, redirects, strings, docs = [], False, [], [], []
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
                self.list(")")
                continue
            m = None if c in "<>" and self.peek(1) == "(" else _REDIR.match(self.s, self.i)
            if m:
                self.i = m.end()
                self.blank()
                target = self.word()
                if target is None:
                    raise ParseError("redirection without a target")
                if m.group(2) in ("<<", "<<-"):
                    docs.append({"delim": target[0], "strip": m.group(2) == "<<-", "expand": target[0] == target[1],
                                 "via": self.via, "cmds": []})
                    self.heredocs.append(docs[-1])
                else:
                    redirects.append([m.group(0), target[0]])
                    if m.group(2) == "<<<":
                        strings.append(target[0])
                continue
            start = self.i
            text, raw, g = self.word()
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
            glob |= g
        cmds = self.emit(words, pid, self.via, redirects, glob) if words else []
        for d in docs:
            d["cmds"] = cmds
        shell = _stdin_shell(cmds)
        for text in strings if shell else ():
            self.nested(text, shell["via"] + [shell["argv"][0] + " <<<"])
        return consumed

    def emit(self, argv, pid, via, redirects=(), glob=False):
        cmds = []
        while argv:
            if len(via) > MAX_DEPTH:
                raise ParseError("nested too deeply")
            name, args = argv[0].rsplit("/", 1)[-1] or argv[0], argv[1:]
            cmd = {"argv": [name] + args, "via": via, "pipeline": pid, "redirects": list(redirects), "glob": glob}
            self.ctx["cmds"].append(cmd)
            cmds.append(cmd)
            if name in WRAPPERS:
                argv, via, redirects = _unwrap(name, args), via + [name], ()
                continue
            if name in SHELLS:
                mode, script = _shell_mode(args)
                if mode == "c":
                    self.nested(script, via + [name + " -c"])
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
        """Return (text, raw source, has_unquoted_glob), or None at an operator or the end."""
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
        return "".join(buf), s[start:self.i], bool(re.search(r"[*?]|\[[^]]+\]", "".join(bare)))

    def sub(self, label):
        via, self.via = self.via, self.via + [label]
        self.list(")")
        self.via = via

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
