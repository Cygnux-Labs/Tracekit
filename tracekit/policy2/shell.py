"""Structural shell parser for policy matching (design §4.4; no bashlex).

`parse(command)` returns every simple command the line would run, including those reached through wrappers, `sh -c`
strings, substitutions, heredocs into a shell and interpreter one-liners:
`{"argv": [...], "via": [...], "pipeline": n, "glob": bool, "opaque": bool}`. argv[0] is a basename, the part after any
`\\` in lower case and without a `.exe` (the agent's file system may ignore case: macOS runs git for `Git`; Windows
runs git.exe for git); `via` says how the command was
reached (empty at top level); commands with the same `pipeline` are stages of one pipeline, in order. `opaque`: what
the command runs cannot be read from the line (a glob, brace or expansion in its name, a shell or interpreter reading
its script from a pipe, a file or inherited stdin, `source` of a stream).
Variables are not expanded and encodings are not decoded. A line it cannot parse raises ParseError.

`analyse(command)` also returns the normalised lines: each parsed script with quotes and escapes resolved and
redirections kept, and again with its program names in lower case when that differs, for rules that match a whole
command line; the words that name something besides the commands' argv: redirection targets, `VAR=` assignments
and the program an interpreter reads from a heredoc or herestring; the targets of the redirections that write a
file (`>`, `>>`, `>|`, `&>`, `&>>`, `<>`, `>&` to a name rather than a descriptor); and the code: the command and the
normalised lines without the text a command only writes into a file (the words of an echo or printf, the heredoc or
herestring a cat or tee copies, with its output redirected to a file a literal names; a word with an expansion, or a
body with a command substitution, is kept; out of the command, only the top level's is cut).
"""
import re


class ParseError(ValueError):
    pass


MAX_DEPTH = 32
MAX_WORK = 1 << 18   # characters parsed in total, re-parsed consumer strings, the list each process call in
                     # interpreter code reads and the words each wrapper level copies included: 4 × the largest
                     # subject, so a worst-case command costs a fraction of a second of the signer (the parser holds
                     # the GIL)
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "rbash", "mksh", "ksh93", "yash", "posh", "lksh", "oksh"}
# shells whose language the parser doesn't read: the commands they get on their line or from stdin are opaque
FOREIGN_SHELLS = {"fish", "csh", "tcsh", "pwsh", "powershell", "nu", "xonsh", "elvish"}
# the options of uv run and uv tool run (uvx) that take a value, as uv 0.13 lists them, and their hidden aliases
# (--constraint, --trusted-host, ...): neither takes the other's, so the union reads both
UV_OPTS = ("--from", "-w", "--with", "--with-editable", "--with-requirements", "-c", "--constraints", "--constraint",
           "-b", "--build-constraints", "--build-constraint", "--overrides", "--override", "--env-file",
           "--python-platform", "--torch-backend", "--index", "--default-index", "-i", "--index-url",
           "--extra-index-url", "-f", "--find-links", "--index-strategy", "--keyring-provider", "-P",
           "--upgrade-package", "--upgrade-group", "--resolution", "--prerelease", "--prerelease-package",
           "--fork-strategy", "--exclude-newer", "--exclude-newer-package", "--no-sources-package",
           "--reinstall-package", "--link-mode", "-C", "--config-setting", "--config-settings",
           "--config-settings-package", "--no-build-isolation-package", "--no-build-package", "--no-binary-package",
           "--cache-dir", "--refresh-package", "-p", "--python", "--python-preference", "--python-fetch", "--color",
           "--allow-insecure-host", "--trusted-host", "--directory", "--project", "--config-file",
           "--preview-features", "--preview-feature", "--package", "--extra", "--no-extra", "--group", "--no-group",
           "--only-group", "--no-editable-package")
# wrapper -> (options that take a value, positional arguments before the command)
WRAPPERS = {"command": ((), 0), "env": (("-u", "-C", "-P", "-a", "--unset", "--chdir", "--argv0"), 0), "nohup": ((), 0),
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
                         "--whitelist-environment"), 0),
            "taskset": ((), 1), "chrt": (("-T", "-P", "-D", "--sched-runtime", "--sched-period", "--sched-deadline"), 1),
            "unbuffer": ((), 0), "fakeroot": (("-l", "-s", "-i", "-b", "--lib", "--faked"), 0),
            "dbus-run-session": (("--config-file", "--dbus-daemon"), 0),
            "caffeinate": (("-t", "-w"), 0), "arch": (("-arch", "-d", "-e"), 0), "pkexec": (("--user",), 0),
            "gtimeout": (("-s", "-k", "--signal", "--kill-after"), 1), "npx": (("-p", "--package"), 0),
            "bunx": (("-p", "--package"), 0), "dotenv": (("-e", "-v", "-p"), 0),
            "uvx": (UV_OPTS, 0),
            "torsocks": (("-u", "-p", "-a", "-P", "--user", "--pass", "--address", "--port"), 0),
            "proxychains": (("-f",), 0), "proxychains4": (("-f",), 0), "firejail": ((), 0),
            "sandbox-exec": (("-f", "-n", "-p", "-D"), 0), "ssh-agent": (("-a", "-E", "-t", "-O", "-P"), 0),
            "systemd-run": (("-u", "--unit", "-p", "--property", "-E", "--setenv", "--description", "--slice", "--uid",
                             "--gid", "--nice", "--working-directory", "-H", "--host", "-M", "--machine", "--on-active",
                             "--on-boot", "--on-startup", "--on-unit-active", "--on-unit-inactive", "--on-calendar"), 0),
            "valgrind": ((), 0), "ltrace": (("-a", "-A", "-D", "-e", "-F", "-l", "-n", "-o", "-p", "-s", "-u", "-w"), 0),
            "chpst": (("-u", "-U", "-b", "-e", "-/", "-n", "-l", "-L", "-m", "-d", "-o", "-p", "-f", "-c", "-r", "-t"), 0),
            "s6-setuidgid": ((), 1), "gosu": ((), 1), "su-exec": ((), 1), "with-contenv": ((), 0),
            "dumb-init": (("-r", "--rewrite"), 0), "tini": (("-p", "-e"), 0)}
# runner -> (its subcommands that run a command, options that take a value, positional arguments before the command;
# "--": the command follows a `--`, after the tools to run it with)
# lean: a wrapper or runner not named here (bwrap, whose options take two values) hides what it runs from the rules
# anchored on a command's name (TK-D001, TK-D003, TK-D010, ...); name it here when one turns up (docs/limits.md)
RUNNERS = {"uv": (("run",), UV_OPTS, 0), "hatch": (("run",), (), 0),
           "conda": (("run",), ("-n", "--name", "-p", "--prefix", "--cwd"), 0),
           "poetry": (("run",), ("-C", "--directory", "-P", "--project"), 0), "pipenv": (("run",), (), 0),
           "pdm": (("run",), ("-p", "--project"), 0), "direnv": (("exec",), (), 1),
           "pipx": (("run",), ("--spec", "--python", "--python-args", "--with", "--fetch-python", "-i", "--index-url",
                              "--pip-args", "--cooldown", "--backend"), 0),
           "op": (("run",), ("--env-file", "--account", "--config", "--environment"), 0),
           "doppler": (("run",), ("-p", "--project", "-c", "--config", "--token", "--scope", "--mount"), 0),
           "mise": (("exec", "x"), ("-C", "--cd", "-j", "--jobs"), "--"),
           "npm": (("exec", "x"), ("-p", "--package", "-w", "--workspace"), 0),
           "pnpm": (("exec", "dlx"), ("-C", "--dir", "-F", "--filter", "--package"), 0),
           "yarn": (("exec", "dlx"), ("-p", "--package"), 0), "bun": (("x",), ("-p", "--package"), 0)}
# runners whose argparse takes any unambiguous prefix of a long option (`pipx run --sp tracekit-ai tracekit`)
ARGPARSE = {"pipx", "conda"}
# GNU parallel runs its command words through a shell, as watch does; these options take a value
PARALLEL_OPTS = {"-a", "-d", "-E", "-I", "-j", "-n", "-N", "-L", "-P", "-S", "-s", "-C", "--arg-file", "--delimiter", "--jobs",
                 "--max-procs", "--max-args", "--max-lines", "--max-chars", "--sshlogin", "--sshloginfile", "--slf",
                 "--colsep", "--joblog", "--results", "--tmpdir", "--workdir", "--wd", "--timeout", "--retries", "--delay",
                 "--env", "--tag-string", "--transfer-file", "--return", "--basefile", "--bf"}
SHELL_VALUE_OPTS = {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}
# commands that run a string through a shell: -c anywhere in their arguments (getopt permutes)
DASH_C = {"su", "script"}
STREAMS = ("/dev/stdin", "/dev/fd/", "/proc/self/fd/", "<(")
KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "{", "}", "!"}
SSH_OPTS = set("-b -c -D -E -e -F -I -i -J -L -l -m -O -o -p -Q -R -S -W -w".split())
KINDS = [("python", re.compile(r"python[0-9.]*")), ("node", re.compile(r"node|nodejs")), ("perl", re.compile(r"perl[0-9.]*")),
         ("ruby", re.compile(r"ruby[0-9.]*")), ("php", re.compile(r"php[0-9.]*")), ("lua", re.compile(r"lua[0-9.]*|luajit")),
         ("awk", re.compile(r"[gmn]?awk")), ("sed", re.compile(r"g?sed"))]
CODE_FLAGS = {"python": "c", "node": "ep", "perl": "eE", "ruby": "e", "php": "r", "lua": "e"}
# options of an interpreter that take a value (so the word after them is not the script)
INTERP_VALUE_OPTS = {"-W", "-X", "-r", "-I", "--require", "--input-type", "-d", "-c"}
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=")
_REDIR = re.compile(r"(\d*|\{\w+\})(&>>|&>|>>|>&|>\||<<<|<<-|<<|<&|<>|>|<)")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-]")
_ANSI = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "v": "\v"}
# lean: interpreter code is scanned for string or list literals passed to a process-spawning call (with or without
# parentheses: perl's and ruby's `system "x"`), plus backticks in perl/ruby/php, and sed's `e` command; code that builds
# the command at run time, and awk's `print | "cmd"` and `"cmd" | getline`, are not followed (tripwire territory)
_CALL = re.compile(r"\b(system|popen|execSync|execFileSync|exec|spawn\w*|run|call|check_call|check_output|Popen|getoutput|"
                   r"shell_exec|passthru|proc_open|os\.execute)(\s*\(\s*|\s+)")
# (sed addresses and s/// parts are bounded so a long script cannot make the scan quadratic; the whitespace runs stay
# off `\n`, which is already a start, so a newline-only script is not re-scanned from each one)
_SED_ADDR = r"(?:^|[;\n{}])[^\S\n]*(?:(?:[0-9$,~+!]|/(?:\\.|[^/\\\n]){0,200}/)[^\S\n]*){0,8}"
_SED_E = re.compile(_SED_ADDR + r"e([^\n]*)")
_SED_S_E = re.compile(_SED_ADDR + r"s([^\\\n])(?:\\.|(?!\1).){0,200}\1(?:\\.|(?!\1).){0,200}\1[^;\n}]{0,20}e")
_STR = re.compile(r"""(['"])((?:\\.|(?!\1)[^\\\n])*)\1""")
# in a `[...]` argv list, the next string literal or the list's end: the first `]` outside a literal (a literal is
# consumed whole, so a `]` in one is skipped); a quote whose literal never closes is charged for the line it read
_LIST_NEXT = re.compile(r"""['"\]]""")
_TICK = re.compile(r"`([^`]*)`")


def parse(command):
    return analyse(command)[0]


def analyse(command):
    """(the commands, the normalised lines, the other words that name something, the files redirections write, the
    code)."""
    ctx = {"cmds": [], "lines": [], "refs": [], "written": [], "kept": [], "cut": [], "pipes": 0, "depth": 0, "work": 0,
           "exp": 0}
    _Parser(command, ctx, []).script()
    code, at = [], 0
    for a, b in sorted(ctx["cut"]):   # each cut a space, so the text on either side doesn't join
        code += [command[at:a], " "]
        at = b
    return (ctx["cmds"], [x for x in ctx["lines"] if x], ctx["refs"], ctx["written"],
            ["".join(code) + command[at:]] + [x for x in ctx["kept"] if x])


def analyse_argv(argv):
    """analyse() for a command given as an argv list, run without a shell."""
    ctx = {"cmds": [], "lines": [], "refs": [], "written": [], "kept": [], "cut": [], "pipes": 1, "depth": 0, "work": 0,
           "exp": 0}
    words = list(argv)
    lines = _lines(words, _programs(words, _Parser("", ctx, []).emit(list(argv), 1, [])))
    return (ctx["cmds"], [x for x in lines + ctx["lines"] if x], ctx["refs"], ctx["written"],
            [x for x in lines + ctx["kept"] if x])


def data_words(argv):
    """Indexes of argv words that are data, not something the command acts on: a git commit or tag message and the
    pattern a grep-family command searches for (unless -e or -f gives it)."""
    name, i = argv[0], 1
    if name == "git":   # the subcommand, after git's own options
        while i < len(argv) and argv[i].startswith("-"):
            i += 2 if argv[i] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix",
                                  "--config-env") else 1
        name, i = (argv[i] if i < len(argv) else ""), i + 1
        if name in ("commit", "tag", "merge", "stash", "notes"):
            out = set()
            for j, a in enumerate(argv[i:], i):
                if a in ("-m", "--message") or re.fullmatch(r"-[A-Za-z]*m", a):
                    out.add(j + 1)
                elif a.startswith("--message=") or (re.match(r"-[A-Za-z]*m.", a) and not a.startswith("--")):
                    out.add(j)
            return out
    if name not in ("grep", "egrep", "fgrep", "rg", "ag", "ack"):
        return set()
    args = argv[i:]
    if any(a.startswith(("--regexp", "--file")) or re.fullmatch(r"-[A-Za-z]*[ef][A-Za-z0-9]*", a) for a in args):
        return set()
    for j, a in enumerate(args, i):
        if a == "--":
            return {j + 1}
        if not a.startswith("-"):
            return {j}
    return set()


def _name_unreadable(text):
    """A command name an expansion builds: anything other than a literal name, or a path under a leading $VAR/."""
    return bool(re.search(r"[$`]", re.sub(r"^(\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\})/", "", text)))


def _kind(name):
    return next((kind for kind, rx in KINDS if rx.fullmatch(name)), None)


def _unwrap(name, args):
    """What a wrapper, or a runner's subcommand (args[0]: `uv run`), runs."""
    if name in WRAPPERS:
        opts, positional = WRAPPERS[name]
    else:
        _, opts, positional = RUNNERS[name]
        args = args[1:]
        if positional == "--":
            return args[args.index("--") + 1:] if "--" in args else []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if name == "command" and a in ("-v", "-V"):
            return []   # a lookup, not a run
        if a.startswith("-"):   # a bare `-` too (env - cmd: an empty environment)
            i += 2 if a in opts or name in ARGPARSE and a.startswith("--") and any(o.startswith(a) for o in opts) else 1
        elif _ASSIGN.match(a) or name == "hatch" and a.startswith("+"):   # hatch run's +var=… matrix selection
            i += 1
        else:
            break
    inner = args[i + positional:]
    if name == "hatch" and inner:   # hatch run [ENV:]ARGS: the environment it runs the command in
        inner = [inner[0].split(":", 1)[-1]] + inner[1:]
    return inner


def _shell_mode(args):
    """('c', script) for sh -c, ('stdin', None) when the shell reads its script from stdin (or a stream such as
    /dev/stdin or <( ), or -c without a script, as xargs bash -c runs it), else (None, None). Options after -c are
    skipped as the shell does: the script is the first operand."""
    i, flags = 0, ""
    while i < len(args):
        a = args[i]
        if a in SHELL_VALUE_OPTS:
            i += 2
            continue
        if a in ("--", "-"):
            i += 1
            break
        if a[:1] not in ("-", "+") or len(a) == 1:   # an empty word is an operand too
            break
        if a[0] == "-" and not a.startswith("--"):
            flags += a[1:]
        i += 1
    if "c" in flags:
        return ("c", args[i]) if i < len(args) else ("stdin", None)
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
        if a == "--split-string" or re.fullmatch(r"-[iv0]*S", a):
            return " ".join(args[i + 1:])
        if a.startswith("--split-string="):
            return " ".join([a[15:]] + args[i + 1:])
        if re.fullmatch(r"-[iv0]*S.+", a, re.S):
            return " ".join([a[a.index("S") + 1:]] + args[i + 1:])
        i += 2 if a in WRAPPERS["env"][0] else 1
    return None


def _foreign_runs_text(shell, args):
    """Whether a FOREIGN_SHELLS shell runs commands from its line or stdin: -c (also in a cluster, -lc, but for
    PowerShell, whose options are words: -ExecutionPolicy), --command or PowerShell's -Command or -EncodedCommand (any
    prefix, any case), or no script file before them."""
    for a in args:
        if not a.startswith("-"):
            return False   # a script file
        name = a.lstrip("-").split("=", 1)[0].lower()
        if shell not in ("pwsh", "powershell") and re.fullmatch(r"-[a-z]*c[a-z]*", a) or name and (
                "command".startswith(name) or name == "ec" or "encodedcommand".startswith(name)):
            return True
    return True


def _npm_call(args):
    """The script of npm exec's (npx's) -c/--call, among the options before the command it runs, or None."""
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] != "--":
        if args[i] in ("-c", "--call"):
            return args[i + 1] if i + 1 < len(args) else ""
        if args[i].startswith("--call="):
            return args[i][7:]
        i += 2 if args[i] in ("-p", "--package", "-w", "--workspace") else 1
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
    """The program text an interpreter gets on its command line (-c code, -ccode, -e code, ...), or None."""
    if kind == "awk":
        return _awk_program(args)
    if kind == "sed":
        return _sed_scripts(args)
    flags = CODE_FLAGS[kind]
    for i, a in enumerate(args):
        if kind == "node" and a in ("--eval", "--print"):
            return args[i + 1] if i + 1 < len(args) else None
        if kind == "node" and a.startswith(("--eval=", "--print=")):
            return a.split("=", 1)[1]
        if re.fullmatch(r"-[A-Za-z]+", a):
            if a[-1] in flags:
                return args[i + 1] if i + 1 < len(args) else None
        elif re.match(r"-[A-Za-z]", a):   # code attached to its flag: -c"..." is the word -c...
            k = next((j for j, ch in enumerate(re.match(r"-([A-Za-z]*)", a).group(1)) if ch in flags), None)
            if k is not None:
                return a[k + 2:]
    return None


def _awk_program(args):
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-e", "--source"):
            return args[i + 1] if i + 1 < len(args) else None
        if a in ("-f", "--file") or a.startswith("--file="):
            return None
        if a == "--":
            return args[i + 1] if i + 1 < len(args) else None
        if not a.startswith("-") or a == "-":
            return a
        i += 2 if a in ("-F", "-v", "--field-separator", "--assign") else 1
    return None


def _sed_scripts(args):
    scripts, i, operand = [], 0, None
    while i < len(args):
        a = args[i]
        if a == "--expression" or re.fullmatch(r"-[A-Za-z]*e", a):
            scripts.append(args[i + 1] if i + 1 < len(args) else "")
            i += 2
            continue
        if a.startswith("--expression="):
            scripts.append(a.split("=", 1)[1])
        elif re.match(r"-[A-Za-z]*e.", a) and not a.startswith("--"):
            scripts.append(a[a.index("e") + 1:])
        elif a in ("-f", "--file") or a.startswith("--file="):
            return None
        elif a in ("-l", "--line-length"):
            i += 1
        elif not a.startswith("-") and operand is None:
            operand = a
        i += 1
    return "\n".join(scripts) if scripts else operand


def _reads_stdin(kind, args):
    """An interpreter with no program on its command line reads it from stdin."""
    if kind in ("awk", "sed") or _code_arg(kind, args) is not None:
        return False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-":
            return True
        if a == "--":
            return i + 1 >= len(args) or args[i + 1] == "-"
        if not a.startswith("-") or (kind == "python" and a.startswith("-m")):
            return False   # a script file or a module
        i += 2 if a in INTERP_VALUE_OPTS else 1
    return True


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
        self.s, self.i, self.ctx, self.via, self.heredocs, self.out, self.progs = src, 0, ctx, via, [], [], []
        self.data = set()   # indexes in self.out of the words the code leaves out
        self.charge(len(src))

    def charge(self, n):
        self.ctx["work"] += n
        if self.ctx["work"] > MAX_WORK:
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
        if self.out[-1:] == [";"]:   # the separator list() put after the last pipeline; a `;` word before it stays
            self.out.pop()
        lines = _lines(self.out, self.progs)
        self.ctx["lines"] += lines
        self.ctx["kept"] += _lines(["" if i in self.data else w for i, w in enumerate(self.out)], self.progs) \
            if self.data else lines

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
        pid, piped = self.ctx["pipes"], False
        while True:
            if not self.simple(pid, piped):
                raise ParseError("command expected")
            piped = True
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

    def simple(self, pid, piped=False):
        words, globs, names, strings, docs, idx, spans, here = [], [], [], [], [], [], [], []
        consumed = loop_header = stdin_redirect = to_file = False
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
                start = self.i
                target = self.word()
                if target is None:
                    raise ParseError("redirection without a target")
                self.out += [m.group(0), target[0]]
                if m.group(2) in ("<<", "<<-"):
                    docs.append({"delim": target[0], "strip": m.group(2) == "<<-", "expand": target[0] == target[1],
                                 "via": self.via, "cmds": [], "data": False})
                    self.heredocs.append(docs[-1])
                elif m.group(2) == "<<<":
                    strings.append(target[0])
                    if not target[3]:
                        here.append((len(self.out) - 1, start, self.i))
                else:
                    self.ctx["refs"].append(target[0])
                    stdin_redirect |= m.group(2) in ("<", "<&", "<>")
                    writes = m.group(2) not in ("<", "<&") and not (
                        m.group(2) == ">&" and re.fullmatch(r"\d*-?", target[0]))
                    if writes:
                        self.ctx["written"].append(target[0])
                    if m.group(2) in ("&>", "&>>") or m.group(1) in ("", "1") and m.group(2) in (">", ">>", ">|", ">&"):
                        # stdout, the last one: into a file a literal names, not a descriptor, a device or a variable
                        to_file = writes and not target[3] and (
                            target[0] == "/dev/null" or not re.search(r"(^|/)(dev|proc)/", target[0]))
                continue
            start = self.i
            text, raw, g, expanded = self.word()
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
            if not words and _ASSIGN.match(self.s, start, self.i):   # within the word, as bash reads it
                self.ctx["refs"].append(text)
                continue
            words.append(text)
            idx.append(len(self.out) - 1)
            spans.append(None if expanded else (len(self.out) - 1, start, self.i))
            globs.append(g)
            names.append(g or (expanded and _name_unreadable(text)))
        cmds = self.emit(words, pid, self.via, any(globs), names) if words else []
        self.progs += [idx[k] for k in _programs(words, cmds)]
        # cat, tee, echo or printf into a file only copies text there: its herestring and echo's or printf's words
        # (and its heredoc, read_heredocs) are data, which the code leaves out.
        # lean: the code doesn't follow the text into that file, so a later command of the same call that runs or reads
        # it (`sh x.sh`, `xargs rm < list`) acts on what it names unseen, as a second call would; keep the text when
        # another command of the call names the file it wrote if that shows up
        data = to_file and bool(words) and words[0] in ("cat", "tee", "echo", "printf")
        if data:
            marks = here + ([s for s in spans[1:] if s] if words[0] in ("echo", "printf") else [])
            self.data.update(i for i, _, _ in marks)
            if not self.via:   # the top level's text is the command's own
                self.ctx["cut"] += [(a, b) for _, a, b in marks]
        for d in docs:
            d["cmds"], d["data"] = cmds, data
        shell = _stdin_shell(cmds)
        if shell and not docs and not strings:
            shell["opaque"] = True   # its script comes from a pipe, a file or inherited stdin
        for text in strings if shell else ():
            self.nested(text, shell["via"] + [shell["argv"][0] + " <<<"])
        interp = None if shell else _stdin_interpreter(cmds)
        if interp and not docs and not strings and (piped or stdin_redirect):
            interp["opaque"] = True   # its program comes from a pipe or a file
        for text in strings if interp else ():
            self.program(interp, text, " <<<")
        return consumed

    def program(self, cmd, text, label):
        """An interpreter's program from a heredoc or herestring: scanned as its -c code would be, and a ref."""
        self.ctx["refs"].append(text)
        self.scan(_kind(cmd["argv"][0]), text, cmd["pipeline"], cmd["via"] + [cmd["argv"][0] + label])

    def emit(self, argv, pid, via, glob=False, unreadable=None):
        """`unreadable[i]`: argv[i] is not a literal name (an unquoted glob or brace, or an expansion; only words of
        the line itself have one)."""
        cmds, unreadable, repl = [], unreadable or [False] * len(argv), None
        while argv:
            if len(via) > MAX_DEPTH:
                raise ParseError("nested too deeply")
            name, args = _lower_name(argv[0].rsplit("/", 1)[-1] or argv[0]), argv[1:]
            # xargs -I{} inserting its input into a script or a command name: what runs comes from stdin
            tainted = repl is not None and (repl in argv[0] or (
                (name in SHELLS or _kind(name)) and any(repl in a for a in args)))
            cmd = {"argv": [name] + args, "via": via, "pipeline": pid, "glob": glob, "opaque": unreadable[0] or tainted}
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
            elif name == "parallel":
                i = 0
                while i < len(args) and args[i].startswith("-"):
                    i += 2 if args[i] in PARALLEL_OPTS else 1
                words = next((args[i:j] for j in range(i, len(args)) if args[j] in (":::", "::::", ":::+", "::::+")),
                             args[i:])
                if words:
                    self.nested(" ".join(words), via + ["parallel sh -c"])
                else:
                    cmd["opaque"] = True   # it reads the commands from stdin
            elif name == "env" and _split_string(args) is not None:
                self.nested(_split_string(args), via + ["env -S"])
            elif (name == "npx" or name == "npm" and args[:1] in (["exec"], ["x"])) and \
                    (script := _npm_call(args if name == "npx" else args[1:])) is not None:
                self.nested(script, via + [name + " -c"])
            elif name == "uv" and args[:2] in (["tool", "run"], ["tool", "uvx"]):   # uvx's long forms
                argv, via, unreadable = ["uvx"] + args[2:], via + ["uv tool run"], unreadable[2:]
                self.charge(len(argv))
                continue
            elif name in WRAPPERS or name in RUNNERS and args[:1] and args[0] in RUNNERS[name][0]:
                if name == "runuser" and _dash_c(args) is not None:
                    self.nested(_dash_c(args), via + ["runuser -c"])
                inner = _unwrap(name, args)
                if name == "flock" and inner[:1] in (["-c"], ["--command"]):
                    self.nested(" ".join(inner[1:2]), via + ["flock -c"])
                    break
                if name == "xargs":
                    repl = _xargs_replace(args[:len(args) - len(inner)])
                argv, via, unreadable = inner, via + [name], unreadable[len(argv) - len(inner):]
                self.charge(len(argv))   # each wrapper level copies the words after it
                continue
            elif name in SHELLS:
                mode, script = _shell_mode(args)
                if mode == "c":
                    self.nested(script, via + [name + " -c"])
            elif name in FOREIGN_SHELLS:
                cmd["opaque"] = cmd["opaque"] or _foreign_runs_text(name, args)
            elif name in ("source", ".") and args[:1] and args[0].startswith(STREAMS):
                cmd["opaque"] = True
            elif name == "eval":
                self.nested(" ".join(args), via + ["eval"])
            elif name == "ssh":
                self.nested(_ssh_command(args), via + ["ssh"])
            elif name == "nix-shell":   # --run and --command take a script, as sh -c does
                for i in range(len(args) - 1):
                    if args[i] in ("--run", "--command"):
                        self.nested(args[i + 1], via + ["nix-shell --run"])
            elif name == "find":
                for inner in _find_execs(args):
                    self.emit(inner, pid, via + ["find -exec"])
            elif _kind(name):
                code = _code_arg(_kind(name), args)
                if code is not None:
                    self.scan(_kind(name), code, pid, via + [name + " code"], cmd)
            break
        return cmds

    def scan(self, kind, code, pid, via, cmd=None):
        """Follow the commands a program runs (see _CALL); sed's `s///e`, which runs what the input holds, makes
        `cmd` opaque."""
        if kind == "sed":
            for m in _SED_E.finditer(code):
                if m.group(1).strip():
                    self.nested(m.group(1).strip(), via)
                elif cmd is not None:
                    cmd["opaque"] = True   # a bare `e` runs the pattern space
            if cmd is not None and _SED_S_E.search(code):
                cmd["opaque"] = True
            return
        for m in _CALL.finditer(code):
            if kind == "python" and m.group(1) == "exec":
                continue   # Python's exec runs Python, not a shell
            i = m.end()
            if code.startswith("[", i):
                argv, k = [], i + 1
                while (end := _LIST_NEXT.search(code, k)) and end.group() != "]":
                    if lit := _STR.match(code, end.start()):
                        argv.append(lit.group(2))
                        k = lit.end()
                    else:   # a quote that doesn't close: the match read to the end of its line
                        nl = code.find("\n", end.start())
                        self.charge((len(code) if nl < 0 else nl) - end.start())
                        k = end.start() + 1
                self.charge((end.start() if end else len(code)) - i)   # overlapping lists read the same text again
                if end and argv:
                    self.emit(argv, pid, via)
            elif lit := _STR.match(code, i):
                self.nested(lit.group(2), via)
        for m in _TICK.finditer(code) if kind in ("perl", "ruby", "php") else ():
            self.nested(m.group(1), via)

    def read_heredocs(self):
        docs, self.heredocs = self.heredocs, []
        s = self.s
        for d in docs:
            lines, start = [], self.i
            while True:
                if self.i >= len(s):
                    raise ParseError(f"heredoc {d['delim']} not terminated")
                j = s.find("\n", self.i)
                end = len(s) if j < 0 else j
                line, at, self.i = s[self.i:end], self.i, min(end + 1, len(s))
                if (line.lstrip("\t") if d["strip"] else line) == d["delim"]:
                    break
                lines.append(line)
            body = "\n".join(lines)
            # a data heredoc's body, unless a command substitution in it runs (what it runs may read a heredoc of its
            # own, which only this text holds)
            if d["data"] and not d["via"] and not (d["expand"] and re.search(r"\$\(|`", body)):
                self.ctx["cut"].append((start, at))
            shell, interp = _stdin_shell(d["cmds"]), _stdin_interpreter(d["cmds"])
            if shell:
                self.nested(body, shell["via"] + [shell["argv"][0] + " <<"])
            elif interp:
                self.program(interp, body, " <<")
            if not shell and d["expand"]:
                _Parser(body, self.ctx, d["via"] + ["<<"]).dquote(None)

    def word(self):
        """Return (text, raw source, has an unquoted glob or brace expansion, has a parameter expansion or command
        substitution), or None at an operator or the end."""
        s, start, buf, bare, exp = self.s, self.i, [], [], self.ctx["exp"]
        while self.i < len(s):
            c = s[self.i]
            if c in "<>" and self.peek(1) == "(":
                at = self.i
                self.i += 2
                self.ctx["exp"] += 1
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
        return "".join(buf), s[start:self.i], bool(glob), self.ctx["exp"] != exp

    def sub(self, label):
        saved = self.via, self.out, self.progs, self.data
        self.via, self.out, self.progs, self.data = self.via + [label], [], [], set()
        self.list(")")
        self.flush()
        self.via, self.out, self.progs, self.data = saved

    def arith(self):
        """Read `$(( ))` from after its `$((`, running the substitutions in it; dollar() calls it only when the text
        has `$(` or a backtick and skips any other `$(( ))` unread. It must end in `))`: bash runs `$((cmd) )` as a
        subshell. Held: a single quote or `$'` (bash does not quote with `'` here, so a substitution inside one still
        runs); a newline; brackets (Bash re-expands array indices); parentheses that don't pair up; any parenthesis
        when the text has a quote, backtick or backslash (bash's counts skip quoted ones, in different places, so the
        shell could end it elsewhere); or a backtick when the text has a double quote (bash expands "..." here its
        own way)."""
        self.enter()
        s, start, depth = self.s, self.i, 0
        while self.i < len(s) and (s[self.i] != ")" or depth):
            c = s[self.i]
            if c == "\\":
                self.i += 2
            elif c == "'" or self.at("$'"):
                raise ParseError("a single quote in $(( )) that has $( or a backtick is not supported")
            elif c == '"':
                self.i += 1
                self.dquote('"')
            elif c == "$":
                self.dollar(False)
            elif c == "`":
                self.backtick()
            else:
                depth += {"(": 1, ")": -1}.get(c, 0)
                self.i += 1
        if not self.at("))"):
            raise ParseError("unterminated $((" if self.i >= len(s) else
                             "$(( that is not arithmetic (a subshell inside $( )) is not supported")
        body = s[start:self.i]
        self.charge(len(body))   # each level reads the levels inside it again
        parens, level = re.findall(r"[()]", body), 0
        for p in parens:
            level += 1 if p == "(" else -1
            if level < 0:
                break
        # lean: such a line is held (TK-SHELL-PARSE), not read; read it when real commands need one (docs/limits.md)
        if level or "\n" in body or "[" in body or parens and re.search(r"[\"'`\\]", body) or '"' in body and "`" in body:
            raise ParseError("a newline, bracket, unpaired parentheses, a parenthesis with a quote, backtick or backslash, "
                             "or a backtick with a double quote in $(( )) that has $( or a backtick is not supported")
        self.i += 2
        self.leave()

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
        self.ctx["exp"] += 1
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
                self.i += 3
                self.arith()
            else:
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
        self.ctx["exp"] += 1
        self.nested(re.sub(r"\\([`\\$])", r"\1", m.group(1)), self.via + ["``"])
        return self.s[start:self.i]


def _lower_name(word):
    """`word` with the name after its last / or \\ in lower case and without a `.exe` (Windows runs git.exe for git):
    the directories keep their case."""
    i = max(word.rfind("/"), word.rfind("\\")) + 1
    name = word[i:].lower()
    return word[:i] + (name[:-4] if name.endswith(".exe") and len(name) > 4 else name)


def _programs(words, cmds):
    """Indexes in `words` of the program names of `cmds`, emit's commands for them (a wrapper's and what it runs), and
    of what a find among them runs (the word after each -exec, -execdir, -ok or -okdir)."""
    out = []
    for c in cmds:
        k = len(words) - len(c["argv"])
        if k >= 0 and words[k + 1:] == c["argv"][1:]:
            out.append(k)
            if c["argv"][0] == "find":
                out += [k + j + 1 for j, a in enumerate(c["argv"][:-1]) if a in ("-exec", "-execdir", "-ok", "-okdir")]
    return out


def _lines(words, progs):
    """The line `words` make, and again with the program names at indexes `progs` in lower case when that differs."""
    low = list(words)
    for i in progs:
        low[i] = _lower_name(low[i])
    return [" ".join(words)] + ([" ".join(low)] if low != words else [])


def _stdin_shell(cmds):
    return next((c for c in cmds if c["argv"][0] in SHELLS and _shell_mode(c["argv"][1:])[0] == "stdin"), None)


def _stdin_interpreter(cmds):
    return next((c for c in cmds if _kind(c["argv"][0]) and _reads_stdin(_kind(c["argv"][0]), c["argv"][1:])), None)


def _xargs_replace(opts):
    """The string xargs replaces with its input (-I R, -iR, -i, --replace[=R]), or None."""
    for i, a in enumerate(opts):
        if a == "-I":
            return opts[i + 1] if i + 1 < len(opts) else None
        if a.startswith("-I") or (a.startswith("-i") and len(a) > 2):
            return a[2:]
        if a in ("-i", "--replace"):
            return "{}"
        if a.startswith("--replace="):
            return a[10:]
    return None
