"""Structural shell parser for policy matching (design §4.4; no bashlex).

`parse(command)` returns every simple command the line would run, including those reached through wrappers, `sh -c`
strings, substitutions, heredocs into a shell, at or batch, trap's action and interpreter one-liners:
`{"argv": [...], "word": str, "via": [...], "pipeline": n, "glob": bool, "opaque": bool, "stdin": [...]}`. argv[0] is
a basename, the part after any `\\` casefolded and without a `.exe` (the agent's file system may ignore case: macOS
runs git for `Git`; Windows runs git.exe for git); `word` is that first word as written (a path, or the text of a name
an expansion builds); `via` says how the command was reached (empty at top level); commands with the same `pipeline`
are stages of one pipeline, in order. `opaque`: what the command runs cannot be read from the line (a glob, brace or
expansion in its name, a shell or interpreter reading its script from a pipe, a file or inherited stdin, `source` of
a stream). `stdin`: the herestring and heredoc text the command reads (the names `xargs rm <<< x` deletes).
Variables are not expanded and encodings are not decoded. A line it cannot parse raises ParseError.

`analyse(command)` also returns the normalised lines: each parsed script with quotes and escapes resolved and
redirections kept, and again with its program names casefolded when that differs, for rules that match a whole
command line; the words that name something besides the commands' argv: redirection targets, `VAR=` assignments
and the program an interpreter reads from a heredoc or herestring; the targets of the redirections that write a
file (`>`, `>>`, `>|`, `&>`, `&>>`, `<>`, `>&` to a name rather than a descriptor); and the code: the command and the
normalised lines without the text a command only writes into a file (the words of an echo or printf, the heredoc or
herestring a cat or tee copies, with its output redirected to a file a literal names; the text is cut only if every
later command in the same call is inert; a word with an expansion, or a body with a command substitution, is kept;
out of the command, only the top level's is cut).
"""
import itertools
import math
import re


class ParseError(ValueError):
    pass


class _Expansion(str):
    """A parameter expansion or command substitution as written, which bash may expand to nothing; `empty`: what it
    expands to when its variable is empty or unset (a default's word: ${X:-w} is w, with w's own expansions empty),
    else nothing; `word`: a default's word as written, read where a $HOME is kept (${X:-$HOME} may be $HOME)."""
    empty = word = ""


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
_COMMAND_NAME_ASSIGN = re.compile(r"(?:PATH|BASH_ENV|ENV)(?:\[[^]]*\])?\+?=")
_VARIABLE_SETTING_BUILTINS = {"read", "mapfile", "readarray", "declare", "typeset", "local", "export", "readonly",
                             "let", "eval", "unset"}
# what may set any variable of the shell, now or later (a DEBUG trap, an alias with expand_aliases on, a sourced file)
_SETS_ANY = _VARIABLE_SETTING_BUILTINS | {"source", ".", "trap", "getopts", "wait", "alias", "shopt", "enable",
                                          "compgen"}   # compgen -V NAME (bash 5.3)


def _sets_with_v(argv):
    """printf -v NAME, also attached (-vNAME, -v'NAME'): it sets NAME."""
    return argv[0] == "printf" and any(a.startswith("-v") for a in argv[1:])


def _sets_keyword(argv):
    """set -k (or -o keyword) may be on: every later NAME=value word is then an assignment, and one before a special
    builtin stays in POSIX mode. Any option cluster with a k, a `keyword` word, or a word the parser can't read counts;
    words after `--` are positional parameters."""
    if argv[0] != "set":
        return False
    words = argv[1:argv.index("--")] if "--" in argv else argv[1:]
    return any(re.search(r"[$`*?[]", w) or re.fullmatch(r"-[A-Za-z]*k[A-Za-z]*", w) or w == "keyword" for w in words)


# an expansion with none inside it: a default's word is emptied innermost first (_Parser.dollar)
_INNERMOST = re.compile(r"\$\{[^${}]*\}|\$\([^$()`]*\)|`[^`$]*`|\$(?:[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])")
# a quote or backslash pair of a word as written, its text in group 1, 2 or 3 (a default's word read without them)
_UNQUOTE = re.compile(r"""\\(.)|'([^']*)'|"((?:\\.|[^"\\])*)\"""", re.S)
# a bracket expression of a pathname pattern: whether it is negated, and its set (a ] first is one of its characters)
_BRACKET = re.compile(r"\[([!^]?)(\]?[^]]*)\]")
_PLAIN_VARIABLE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")   # $NAME or ${NAME}, fully matched
# the operators bash reads across a deleted backslash-newline
_JOINED = {"&&", "||", ";;", ";&", ";;&", "|&", "<<", "<<-", "<<<", ">>", "<&", ">&", "<>", ">|", "&>", "&>>", "((",
           "<(", ">("}
_REDIR = re.compile(r"(\d*|\{\w+\})(&>>|&>|>>|>&|>\||<<<|<<-|<<|<&|<>|>|<)")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-]")
# a pathname pattern in a word's unquoted text; a ] first in a bracket is one of its characters ([]x], [!]x])
_GLOB = re.compile(r"[*?]|\[[!^]?(?:\][^][]*|[^][]+)\]")
_HOME_WORD = re.compile(r"\$(?:HOME|\{HOME\})")   # the one bare variable the packs name as a word
_DEFAULT = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):?[-=?][^{}]*\}")   # a variable with a default, assignment or check
# the start of "$@", "${@...}" or "${name[@]...}": no word at all when there are no parameters or the array is empty
_ALL_ITEMS = re.compile(r"\$(?:@|\{!?(?:@|[A-Za-z_][A-Za-z0-9_]*(?:\[@\]|@)))")
_ANSI = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "v": "\v",
         "\\": "\\", "'": "'", '"': '"', "?": "?"}
# an escape in $'…' as bash 5 reads one (lib/sh/strtrans.c): \x{…} (any hex digits) or 1-2 hex digits, \u 1-4 and \U 1-8,
# 1-3 octal digits, \cX a control character (\c\\ is \c with one backslash), or any one character
_ANSI_ESCAPE = re.compile(r"\\(x\{[0-9A-Fa-f]*\}?|x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,3}|"
                          r"c\\\\|c.|.)", re.S)
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


def analyse(command, persistent_target=None, readings=True, work=None):
    """(the commands, the normalised lines, the other words that name something, the files redirections write, the
    code). `readings`: False reads the line only as written, without its second readings (_Parser.simple). `work`: a
    budget ([characters parsed]) several parses share, MAX_WORK in all."""
    ctx = {"cmds": [], "lines": [], "refs": [], "written": [], "kept": [], "kept_batches": [], "always_cut": [],
           "cut": [], "steps": [], "redefined": set(),
           "command_names_mutable": False,
           "pipes": 0, "depth": 0, "work": [0] if work is None else work, "exp": 0,
           "persistent_target": persistent_target, "any_set": False,
           "brace": min(MAX_BRACE, (64 << 10) - len(command)),   # what brace expansions may still add
           "readings": readings, "nested": set()}
    # A literal can become an arithmetic variable name on the same line. Read
    # substitutions inside its array index when that line has an arithmetic
    # evaluation context; bash re-expands that index while evaluating it.
    arithmetic = re.compile(r"\$\(\(|\(\(|\blet\b|\b(?:declare|local|typeset)\b[^\n]*\s-i\b|\$\{[A-Za-z_][A-Za-z0-9_]*\[")
    for line in command.replace("\\\n", "").splitlines():   # bash deletes a backslash-newline before it reads
        has_context = any(marker in line for marker in ("$((", "((", "let ", "declare ", "local ", "typeset ", "${"))
        test_open = line.find("[[")
        has_test_context = test_open >= 0 and any(line.find(op, test_open + 2) >= 0 for op in ("-eq", "-ne", "-lt", "-le", "-gt", "-ge"))
        if (has_context and arithmetic.search(line)) or has_test_context:
            parameterized_index = _has_parameterized_index(line)
            if parameterized_index and re.search(r"\$\((?!\()|`|\$\{[^{}]*\$\}\s*\(", line):
                raise ParseError("a parameterized arithmetic subscript on a line with a substitution is not supported")
            literals = list(_STR.finditer(line))
            i = 0
            while i < len(line):
                m = re.search(r"(?<![\w'\"])[A-Za-z_][A-Za-z0-9_]*\[", line[i:])
                if not m:
                    break
                start = i + m.start()
                end = line.find("]", i + m.end())
                if end < 0:
                    break
                word = line[start:end + 1]
                if "$" in word or "`" in word:
                    literals.append((start, end + 1, word))
                i = end + 1
            for literal in literals:
                text = literal.group(2) if hasattr(literal, "re") else literal[2]
                if not _subscript_substitution(text):
                    continue
                pos = 0
                while True:
                    match = re.search(r"\$\(|`", text[pos:])
                    if not match:
                        break
                    start = pos + match.start()
                    parser = _Parser(text, ctx, ["arithmetic subscript"])
                    parser.i = start
                    if text.startswith("$(", parser.i):
                        parser.dollar(False)
                    else:
                        parser.backtick()
                    pos = parser.i
    top = _Parser(command, ctx, [])
    try:
        top.script()
    except ParseError as e:
        e.at = top.i   # where the line stops being readable: the words before it may still be (engine._plain)
        raise
    ctx["cut"] += ctx["always_cut"]
    active = False
    for step in reversed(ctx["steps"]):
        if not ctx["command_names_mutable"] and not active:
            ctx["cut"] += step["marks"]
            step["cut"] = bool(step["marks"])
        active |= not step["inert"]
    for step, cmd, indexes in ctx.get("cut_data_words", []):
        if step.get("cut"):
            cmd["data_words"] = indexes
    for step, cmd in ctx.get("cut_data_stdin", []):
        if step.get("cut"):
            cmd["data_stdin"] = True
    for words, progs, data_steps, gones in ctx["kept_batches"]:
        blank = {i for indexes, step in data_steps if step.get("cut") for i in indexes}
        words = ["" if i in blank else w for i, w in enumerate(words)]
        ctx["kept"] += _lines(words, progs) + [x for gone in gones for x in _lines_without(
            words, progs, {i: t for i, t in gone.items() if i not in blank})]
    code, at = [], 0
    for a, b in sorted(ctx["cut"]):   # each cut a space, so the text on either side doesn't join
        code += [command[at:a], " "]
        at = b
    return (ctx["cmds"], [x for x in ctx["lines"] if x], ctx["refs"], ctx["written"],
            ["".join(code) + command[at:]] + [x for x in ctx["kept"] if x])


def analyse_argv(argv, readings=True, work=None):
    """analyse() for a command given as an argv list, run without a shell."""
    ctx = {"cmds": [], "lines": [], "refs": [], "written": [], "kept": [], "kept_batches": [], "always_cut": [],
           "cut": [], "steps": [], "redefined": set(),
           "command_names_mutable": False,
           "pipes": 1, "depth": 0, "work": [0] if work is None else work, "exp": 0, "any_set": False, "brace": MAX_BRACE,
           "readings": readings, "nested": set()}
    words = list(argv)
    lines = _lines(words, _programs(words, _Parser("", ctx, []).emit(list(argv), 1, [])))
    return (ctx["cmds"], [x for x in lines + ctx["lines"] if x], ctx["refs"], ctx["written"],
            [x for x in lines + ctx["kept"] if x])


def _git_env_alias(word):
    """The command of a git `!` alias that a `GIT_CONFIG_VALUE_<n>=!cmd` word sets through the environment, else None;
    ParseError for GIT_CONFIG_PARAMETERS, whose aliases this parser doesn't read."""
    if word.startswith("GIT_CONFIG_PARAMETERS="):
        raise ParseError("git config from GIT_CONFIG_PARAMETERS is not read")
    m = re.fullmatch(r"(?s)GIT_CONFIG_VALUE_\d+=\s*!(.*)", word)
    return m and m.group(1)


def _sed_prints(script):
    """Whether a sed script only picks and prints lines: with its /pattern/ addresses left out, nothing but line
    numbers, ranges, braces and the commands that read, write and run nothing."""
    return bool(re.fullmatch(r"[\s\d,$~!;{}+pPlqQnNdDhHgGxz=]*", re.sub(r"/(?:[^/\\\n]|\\.)*/[IM]{0,2}", "", script)))


def data_words(argv):
    """Indexes of argv words that are data, not something the command acts on: a git commit or tag message, a log's
    --grep, the pattern a grep-family command searches for (unless -e, -f or --pre is given) and a `sed -n` script
    that only picks and prints lines."""
    name, i = argv[0], 1
    if name == "git":   # the subcommand, after git's own options
        while i < len(argv) and argv[i].startswith("-"):
            i += 2 if argv[i] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix",
                                  "--config-env") else 1
        name, i = (argv[i] if i < len(argv) else ""), i + 1
        out = set()
        for j, a in enumerate(argv[i:] if name in ("log", "rev-list", "shortlog", "whatchanged", "show", "reflog")
                              else (), i):
            if a == "--grep" and j + 1 < len(argv):
                out.add(j + 1)
            elif a.startswith("--grep="):
                out.add(j)
        if name in ("commit", "tag", "merge", "stash", "notes"):
            for j, a in enumerate(argv[i:], i):
                if a in ("-m", "--message") or re.fullmatch(r"-[A-Za-z]*m", a):
                    out.add(j + 1)
                elif a.startswith("--message=") or (re.match(r"-[A-Za-z]*m.", a) and not a.startswith("--")):
                    out.add(j)
            return out
        if name not in ("grep", "egrep", "fgrep", "rg", "ag", "ack"):
            return out
    if name == "sed" and "-n" in argv[1:]:
        # a script only once it is the script (after -e or -f the words are files) and only while it just picks and
        # prints lines: s, w, r, e and the like write, read or run what they name
        out, i, given = set(), 1, False
        while i < len(argv):
            a = argv[i]
            if a in ("-e", "--expression", "-f", "--file"):
                if a in ("-e", "--expression") and i + 1 < len(argv) and _sed_prints(argv[i + 1]):
                    out.add(i + 1)
                given = True
                i += 2
                continue
            if a.startswith(("--expression=", "--file=")) or (a[:2] in ("-e", "-f") and len(a) > 2):
                if a.startswith(("--expression=", "-e")) and _sed_prints(a.split("=", 1)[1] if a[1] == "-" else a[2:]):
                    out.add(i)
                given = True
            elif a.startswith("-"):
                pass
            elif a:
                if not given and _sed_prints(a):
                    out.add(i)
                break
            i += 1
        return out
    if name not in ("grep", "egrep", "fgrep", "rg", "ag", "ack"):
        return set()
    args = argv[i:]
    if any(a.startswith(("--regexp", "--file", "--pre")) or re.fullmatch(r"-[A-Za-z]*[ef][A-Za-z0-9]*", a)
           for a in args):
        return set()
    for j, a in enumerate(args, i):
        if a == "--":
            return {j + 1}
        if not a.startswith("-"):
            return {j}
    return set()


def _redefined(redefined, name):
    """Whether name may have been redefined."""
    return name in redefined


def _git_stdin_message(argv):
    if not argv or argv[0] != "git":
        return False
    i = 1
    while i < len(argv) and argv[i].startswith("-"):
        i += 2 if argv[i] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix",
                              "--config-env") else 1
    if i >= len(argv) or argv[i] != "commit":
        return False
    args = argv[i + 1:]
    return any((args[j] == "-F" and j + 1 < len(args) and args[j + 1] == "-") or args[j] == "--file=-"
               for j in range(len(args)))


def _name_unreadable(text):
    """A command name an expansion builds: anything other than a literal name, or a path under a leading $VAR/."""
    return bool(re.search(r"[$`]", re.sub(r"^(\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\})/", "", text)))


# characters the brace expansions of a line may add to it, and no more than keeps it within 64 KiB (the engine's
# MAX_SUBJECT, past which a subject denies as TK-OVERSIZE): past it a word is kept as written, its command unreadable
MAX_BRACE = 16 * 1024
# a sequence bash 3.2 and bash 5 read alike: two plain integers of at most 18 digits, or two letters
_SEQ = re.compile(r"(-?[0-9]{1,18})\.\.(-?[0-9]{1,18})|([A-Za-z])\.\.([A-Za-z])")


def _skip(w, i):
    """The index after the quoted or expanded part of the word w that starts at i (a \\ pair, '...', "...", $'...',
    $"...", ${...}), or i when none starts there. A word with a command or process substitution never gets here."""
    c = w[i]
    if c == "\\":
        return i + 2
    if c == "'":
        j = w.find("'", i + 1)
        return len(w) if j < 0 else j + 1
    if c == '"' or w.startswith(("$'", '$"'), i):
        q, j = (w[i + 1], i + 2) if c == "$" else ('"', i + 1)
        while j < len(w) and w[j] != q:
            j += 2 if w[j] == "\\" else 1
        return j + 1
    if w.startswith("${", i):   # to its matching }, past the quotes in it
        depth, j = 1, i + 2
        while j < len(w) and depth:
            if w[j] == "\\":
                j += 2
                continue
            if w[j] in "'\"":
                j = _skip(w, j)
                continue
            depth += {"{": 1, "}": -1}.get(w[j], 0)
            j += 1
        return j
    return i


def _gobble(w, i):
    """bash's brace_gobbler (braces.c) for the `}` that ends a brace opened just before index i: (its index, the commas
    at the brace's own depth, whether `..` is there), or None. A `}` at that depth ends it only after a comma or `..`
    there, so bash runs `{zq},~/}` as `zq} ~/`; one deeper ends a deeper brace."""
    level, commas, dots = 0, [], False
    while i < len(w):
        j = _skip(w, i)
        if j != i:
            i = j
            continue
        c = w[i]
        if c == "}" and not level and (commas or dots):
            return i, commas, dots
        if c == "{":
            level += 1
        elif c == "}" and level:
            level -= 1
        elif c == "," and not level:
            commas.append(i)
        elif c == "." and not level and w.startswith("..", i) and w[i + 2:i + 3] != "}":
            dots = True
        i += 1
    return None


def _brace_at(w, charge, room=MAX_BRACE):
    """The first brace expression bash expands in the text w (braces.c brace_expand): (its start, the index after its
    `}`, the texts it puts there, whether bash expands those again: a comma's alternatives), or None. It starts at the
    first unquoted `{` (not `${`, and not one that begins w with a `}` after it) that _gobble ends. Unreadable
    (ParseError): one with `..` at its own depth, no comma there and no plain sequence (_SEQ; bash 4 and later expand
    those in ways bash 3.2 doesn't: a step, padding, a sign, both letter cases, braces or commas inside), or a
    sequence of more than `room` words."""
    charge(len(w))
    opens, marks, closes, i = [], [], [], 0   # unquoted: each { that may start one; commas and ..; each }
    while i < len(w):
        j = _skip(w, i)
        if j != i:
            i = j
            continue
        if w[i] == "{" and (i or w[1:2] != "}"):
            opens.append(i)
        elif w[i] == "}":
            closes.append(i)
        elif w[i] == "," or w.startswith("..", i):
            marks.append(i)
        i += 1
    # a `{` opens a brace only with a comma or .. after it and a } after that: past the last such, none does
    last = max((m for m in marks if closes and m < closes[-1]), default=-1)
    for i in opens:
        if i >= last:
            break
        found = _gobble(w, i + 1)
        charge((found[0] if found else len(w)) - i)   # each `{` that ends no brace is read to the end again
        if not found:
            continue
        end, commas, dots = found
        if commas:
            cuts = [i] + commas + [end]
            return i, end + 1, [w[a + 1:b] for a, b in zip(cuts, cuts[1:])], True
        m = _SEQ.fullmatch(w, i + 1, end)
        if not m:
            raise ParseError("a brace expression with .. that isn't a plain sequence is not supported")
        if m.group(3) and m.group(3).isupper() != m.group(4).isupper() or \
                m.group(1) and any(re.match(r"-?0[0-9]", x) for x in m.group(1, 2)):
            raise ParseError("a zero-padded or mixed-case brace sequence is not supported")
        lo, hi = (int(m.group(1)), int(m.group(2))) if m.group(1) else (ord(m.group(3)), ord(m.group(4)))
        if abs(hi - lo) >= room:
            raise ParseError("a brace expansion that makes too much text")
        seq = range(lo, hi + 1) if lo <= hi else range(lo, hi - 1, -1)
        return i, end + 1, [str(x) if m.group(1) else chr(x) for x in seq], False
    return None


def _brace(word, charge, room=MAX_BRACE, depth=0):
    """bash's brace expansion of one word as written, its quotes and escapes kept for the reader: the words it makes,
    in bash's order, or None when it has no brace expression. As bash, each comma's alternative is expanded on its own
    and so is the text after the brace. Unreadable (ParseError) past `room` characters, past the parse budget (the
    strings it builds count), braces nested past MAX_DEPTH, or a command or process substitution in a word whose
    braces expand: each copy would run it, and the parser reads it once."""
    words, rest, found = [""], word, _brace_at(word, charge, room)
    if found is None:
        return None
    if re.search(r"\$\(|`|[<>]\(", word):
        raise ParseError("a substitution in a word with a brace expansion is not supported")
    if depth > MAX_DEPTH:
        raise ParseError("braces nested too deeply")
    while found is not None:
        a, b, texts, again = found
        alts = [x for t in texts for x in ((_brace(t, charge, room, depth + 1) or [t]) if again else [t])]
        made = len(alts) * sum(map(len, words)) + len(words) * sum(len(rest[:a]) + len(x) for x in alts)
        if made > room:
            raise ParseError("a brace expansion that makes too much text")
        charge(made)
        words, rest = [w + rest[:a] + x for w in words for x in alts], rest[b:]
        found = _brace_at(rest, charge, room)
    if sum(map(len, words)) + len(words) * len(rest) > room:
        raise ParseError("a brace expansion that makes too much text")
    return [w + rest for w in words]


def _unglob(text):
    """The names the bracket expressions of a pathname pattern can make, at most 16 (`authorized_key[s]` is
    authorized_keys, `[ab]` makes two), its other pattern characters kept; [] when it has none it can list (a negated
    set, a class such as [:alpha:], a range or a product of more)."""
    segments, sets, at = [], [], 0
    for m in _BRACKET.finditer(text):
        if m.group(1) or "[" in m.group(2):
            return []
        chars = []
        for r in re.finditer(r"(.)-(.)|.", m.group(2), re.S):
            lo, hi = (ord(r.group(1)), ord(r.group(2))) if r.group(1) else (ord(r.group()),) * 2
            if hi - lo >= 16:
                return []
            chars += map(chr, range(lo, hi + 1))
        segments.append(text[at:m.start()])
        sets.append(list(dict.fromkeys(chars)))
        at = m.end()
    if not sets or math.prod(map(len, sets)) > 16:
        return []
    return ["".join(a + b for a, b in zip(segments, chosen)) + text[at:] for chosen in itertools.product(*sets)]


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
    """The text of $'text' as bash makes it: escapes decoded, an unknown one (\\z, a \\x or \\u without digits) kept
    with its backslash, and cut at its first NUL, which ends bash's C string (`r$'\\x00zz'm` is rm)."""
    def one(m):
        e = m.group(1)
        if e[0] in "xuU" and len(e) > 1:
            v = int(e[1:].strip("{}") or "0", 16) & (0xFF if e[0] == "x" else -1)   # \x makes a byte
            return chr(v) if v < 0x110000 else m.group()
        if e[0] in "01234567":
            return chr(int(e, 8) & 0xFF)
        if e[0] == "c" and len(e) > 1:   # a control character: ? is DEL
            return "\x7f" if e[1] == "?" else chr(ord(e[1].upper()) & 0x1F)
        return _ANSI.get(e, "\\" + e)
    return _ANSI_ESCAPE.sub(one, text).split("\0", 1)[0]


_SUBSCRIPT = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z0-9_]+\[|\]|\$\(|`")


def _subscript_substitution(text):
    """Whether a `$(` or backtick sits in an array subscript still open (`a[$(cmd)`, `` a[x`cmd` ``), in one pass (a
    regex that scans from each name to the next `]` took seconds over a long word)."""
    inside = False
    for m in _SUBSCRIPT.finditer(text):
        if m.group() in ("$(", "`"):
            if inside:
                return True
        else:
            inside = m.group() != "]"
    return False


def _has_parameterized_index(text):
    """Find parameter expansion in a bracketed index with one forward scan."""
    inside = False
    i = 0
    while i < len(text):
        c = text[i]
        if c == "[":
            inside = True
        elif c == "]":
            inside = False
        elif inside and c == "$":
            if text.startswith("${", i) or (
                i + 1 < len(text) and text[i + 1] not in "({" and _NAME.match(text, i + 1)
            ):
                return True
        i += 1
    return False


class _Parser:
    def __init__(self, src, ctx, via):
        self.s, self.i, self.ctx, self.via, self.heredocs, self.out, self.progs = src, 0, ctx, via, [], [], []
        self.cwd_changed = False
        self.data = set()   # indexes in self.out whose data words are blanked when their step is cut
        self.data_steps = []
        self.gone = [{} for _ in range(12)]   # each second reading's text of the words in self.out it changes (None: gone)
        # the variables bash expands to a non-empty value here, which no second reading empties: $PWD (bash sets it),
        # one the line gave a literal (`D=build; rm -rf "$D"/`) and a for loop's over literal words, in its body;
        # self.blocks: the compound commands (if, while, until, for, select, { }) the parser is in, each (its keyword,
        # the variables it made known, forgotten at its end); only in a { } group does an assignment surely run before
        # what follows it. Each known one maps to the literals it may hold ([]: not known; IFS: bash's default, which
        # no assignment gives back)
        self.known, self.blocks = {"PWD": [], "IFS": []}, []
        self.charge(len(src))

    def charge(self, n):
        self.ctx["work"][0] += n
        if self.ctx["work"][0] > MAX_WORK:
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
        # a new shell sets $PWD and IFS; a trap runs later
        known = {} if via[-1:] == ["trap"] else {k: v for k, v in self.known.items() if k in ("PWD", "IFS")}
        key = (text, tuple(via), frozenset(known))
        if key in self.ctx["nested"]:   # the same text read the same way again (each reading's eval): the same commands
            return
        self.ctx["nested"].add(key)
        p = _Parser(text, self.ctx, via)
        p.known = known
        p.script()

    def script(self):
        self.list(None)
        self.flush()
        if self.heredocs:
            raise ParseError(f"heredoc {self.heredocs[0]['delim']} not terminated")

    def flush(self):
        if self.out[-1:] == [";"]:   # the separator list() put after the last pipeline; a `;` word before it stays
            self.out.pop()
        gones, more = list(map(dict, dict.fromkeys(frozenset(g.items()) for g in self.gone if g))), []
        self.progs = list(dict.fromkeys(self.progs))   # each reading of a command names its program again
        for gone in gones:
            self.charge(2 * sum(map(len, self.out)))   # each reading's line, here and again for the code (analyse)
            more += _lines_without(self.out, self.progs, gone)
        self.ctx["lines"] += _lines(self.out, self.progs) + more
        self.ctx["kept_batches"].append((self.out.copy(), self.progs.copy(), self.data_steps.copy(), gones))

    def blank(self):
        s = self.s
        while self.i < len(s):
            if s[self.i] in " \t":
                self.i += 1
            elif self.at("\\\n"):
                j = self.i
                while s.startswith("\\\n", j):
                    j += 2
                # bash deletes it first, so the characters on either side join: (\⏎( is ((, <<\⏎-EOF is <<-EOF
                left, right = s[max(0, self.i - 2):self.i], s[j:j + 2]
                if any(left[k:] + right[:n] in _JOINED for k in range(len(left)) for n in range(1, len(right) + 1)):
                    raise ParseError("a backslash-newline inside an operator is not supported")
                self.i = j
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
        vanish, patterns, cuts, slots, alones = [], [], [], [], []   # per word: .vanish, a pathname pattern, .cut, .slots,
        # .alone
        consumed = loop_header = stdin_redirect = stdout_redirect = to_file = False
        dynamic = brace_unread = False   # brace_unread: the command is held (a brace kept as written, a split name)
        timed = 0   # how many leading words are an unquoted `time` and its -p or --: bash's keyword, so far
        # an assignment here runs whenever what follows it on the line does: outside compound commands but a { }
        # group, first in its list (not after && or ||, nor a pipeline stage), and no keyword but a { before it
        sure = (not self.blocks or self.blocks[-1][0] == "{") and (self.out[-1] if self.out else ";") in (";", "&", "(")
        assigns, header = [], []   # (name, its literal or None, +=); a loop header's literal words (None: other)

        def untime():   # the words so far only time what follows: read that as the command's start
            nonlocal timed
            if timed and timed == len(words):
                del words[:], globs[:], names[:], idx[:], spans[:], vanish[:], patterns[:], cuts[:], slots[:], alones[:]
                timed = 0
        while True:
            self.blank()
            c = self.peek()
            if not c or c in "\n;|)" or (c == "&" and not self.at("&>")):
                break
            consumed = True
            if c == "(":
                untime()
                if words or loop_header or self.at("(("):
                    raise ParseError("unexpected ( (arithmetic and function definitions are not supported)")
                self.i += 1
                self.out.append("(")
                known = dict(self.known)
                self.list(")")
                self.known = known   # what the subshell sets stays in it
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
                dynamic |= bool(re.search(r"[$`]", target[1]))
                self.out += [m.group(0), target[0]]
                if m.group(2) in ("<<", "<<-"):
                    docs.append({"delim": target[0], "strip": m.group(2) == "<<-", "expand": target[0] == target[1],
                                 "via": self.via, "cmds": [], "data": False, "step": None})
                    self.heredocs.append(docs[-1])
                elif m.group(2) == "<<<":
                    strings.append(target[0])
                    if not target[3]:
                        here.append((len(self.out) - 1, start, self.i))
                else:
                    # the name, and again with its expansions empty (self.cut)
                    named = [target[0]] + [t for t in dict.fromkeys(self.cut) if t and t != target[0]] * \
                        self.ctx["readings"] + [t for texts in self.fill([self.slots]) for t in texts]
                    made = [c for t in named for c in _unglob(t)] if self.ctx["readings"] and target[2] else []
                    self.charge(sum(map(len, made)))   # each name its pattern may make
                    named = list(dict.fromkeys(named + made))
                    self.ctx["refs"] += named
                    stdin_redirect |= m.group(2) in ("<", "<&", "<>")
                    writes = m.group(2) not in ("<", "<&") and not (
                        m.group(2) == ">&" and re.fullmatch(r"\d*-?", target[0]))
                    if writes:
                        self.ctx["written"] += named
                    if m.group(2) in ("&>", "&>>") or m.group(1) in ("", "1") and m.group(2) in (">", ">>", ">|", ">&"):
                        stdout_redirect = True
                        # stdout, the last one: into a file a literal names, not a descriptor, a device or a variable
                        to_file = writes and not target[2] and not target[3] and \
                            (target[0].startswith("/") or not self.cwd_changed) and \
                            (target[0] == "/dev/null" or not re.search(r"(^|/)(dev|proc)/", target[0])) and \
                            not (self.ctx.get("persistent_target") and self.ctx["persistent_target"](target[0]))
                continue
            start = self.i
            text, raw, g, expanded = self.word()
            if raw != self.s[start:self.i] and self.peek() in ("<", ">") and re.fullmatch(r"\d+|\{\w+\}", raw):
                raise ParseError("a backslash-newline inside a redirection is not supported")   # bash reads 2\⏎> as 2>
            self.out.append(text)
            if loop_header:
                header.append(None if g or re.search(r"[$`]", raw) else text)
                continue
            if raw == text and (text in KEYWORDS or text in ("for", "select", "case", "function", "coproc")):
                untime()
            if not words and raw == text and text in KEYWORDS:
                sure = text == "{"   # the group's first command
                if text in ("while", "until"):   # its condition and body run again after the body's later commands
                    self.known = {}
                if text in ("if", "while", "until", "{"):
                    self.blocks.append((text, []))
                elif text in ("fi", "done", "}") and self.blocks:
                    for name in self.blocks.pop()[1]:
                        self.known.pop(name, None)
                continue
            if not words and raw == text and text in ("for", "select"):
                loop_header = text   # the loop words are not run; `do` starts the body
                continue
            if not words and raw == text and text in ("case", "function", "coproc"):
                raise ParseError(f"{text} is not supported")
            if not words and (m := _ASSIGN.match(raw)):   # within the word, as bash reads it
                assigns.append((re.match(r"\w+", raw).group(), None if m.group(1) or expanded else text.partition("=")[2],
                                m.group().endswith("+=")))
                self.ctx["refs"].append(text)
                self.ctx["command_names_mutable"] |= bool(_COMMAND_NAME_ASSIGN.match(text))
                if (alias := _git_env_alias(text)) is not None:
                    self.nested(alias, self.via + ["git alias"])
                continue
            if timed == len(words) and raw == text and (text == "time" or words and text in ("-p", "--")):
                timed += 1
            pieces, ifs = None, self.ifs
            if "{" in self.bare:   # an unquoted { outside substitutions: maybe a brace expansion
                # one _brace can't read, or beside a substitution (each word it makes runs it), is kept as written and
                # its command is unreadable (opaque), so the rules still read the rest; past the parse budget, the line
                try:
                    if re.search(r"\$\(|`|[<>]\(", raw):
                        raise ParseError("a substitution in a word with a brace is not supported")
                    pieces = _brace(raw, self.charge, self.ctx["brace"] + len(raw))
                    if pieces is not None and ifs:   # lean: each word it makes would split again; held instead
                        pieces = None
                        raise ParseError("a brace beside an unquoted $IFS is not supported")
                    self.ctx["brace"] -= sum(len(p) + 1 for p in pieces or [raw]) - 1 - len(raw)
                except ParseError:
                    if self.ctx["work"][0] > MAX_WORK:
                        raise
                    brace_unread, ifs = True, []   # the word stays as written
                # an argument bash brace-expands is the words it makes; a command name it builds is unreadable
                if pieces is not None and not words:
                    g, pieces = True, None
            if ifs and pieces is None:   # bash splits the word at each (IFS is the default)
                at = [start] + [i for span in ifs for i in span] + [self.i]
                pieces = [self.s[a:b] for a, b in zip(at[::2], at[1::2])]
                brace_unread |= not words   # a name built so is an evasion: held, as before, and read
            if pieces is not None:
                self.out.pop()
            for text, raw, g, expanded in [(text, raw, g, expanded)] if pieces is None else \
                    filter(None, map(self.relex, pieces)):
                if pieces is None and text == "" and self.alone:
                    self.out.pop()
                    continue
                if pieces is not None:
                    self.out.append(text)
                words.append(text)
                dynamic |= bool(re.search(r"[$`]", raw))
                idx.append(len(self.out) - 1)
                spans.append(None if expanded or pieces is not None else (len(self.out) - 1, start, self.i))
                globs.append(g)
                names.append(g or (expanded and _name_unreadable(text)))
                vanish.append(self.vanish)
                patterns.append(bool(_GLOB.search(self.bare)))
                cuts.append(self.cut)
                slots.append(self.slots)
                alones.append(self.alone)
        cmds = self.emit(words, pid, self.via, any(globs), names) if words else []
        if brace_unread and cmds:
            cmds[0]["opaque"] = True
        self.progs += [idx[k] for k in _programs(words, cmds)]
        git_stdin_message = _git_stdin_message(words)
        # cat, tee, echo or printf into a file only copies text there: its herestring and echo's or printf's words
        # (and its heredoc, read_heredocs) are data, which the code leaves out.
        # lean: a later, separate call can still consume a file whose copied text this call cut; that later call is
        # evaluated as its own policy input.
        data = to_file and bool(words) and words[0] in ("cat", "tee", "echo", "printf") and \
            not _redefined(self.ctx["redefined"], words[0])
        # bash drops a word made only of expansions when they expand to nothing (an unset $X), joins an empty one into
        # the rest of its word ($X-rf is -rf), and under nullglob drops a pattern that matches nothing: read the command
        # in each of word()'s readings, and again without the patterns (self.cut). Its commands are also the ones that
        # read this command's stdin, heredoc and herestring (`| sh $X` is `| sh`). Of a command that only copies text
        # into a file, only the line.
        seen, as_written = {tuple(words)}, cmds
        for k in range(12 if (dynamic or any(patterns)) and self.ctx["readings"] else 0):
            texts = [None if v and not cut[k % 6] or k > 5 and p else cut[k % 6]   # None: gone
                     for v, p, cut in zip(vanish, patterns, cuts)]
            kept = [i for i, t in enumerate(texts) if t is not None]
            alt = [texts[i] for i in kept]
            self.gone[k].update((idx[i], t) for i, t in enumerate(texts) if t != words[i])   # and the line (flush)
            if alt and tuple(alt) not in seen and not data:
                seen.add(tuple(alt))
                self.charge(sum(map(len, alt)))   # each reading is read as a command of its own
                more = self.emit(alt, pid, self.via, any(globs),
                                 [names[i] if texts[i] == words[i] else globs[i] or _name_unreadable(texts[i])
                                  for i in kept])
                cmds = cmds + more
                self.progs += [idx[kept[j]] for j in _programs(alt, more)]
        # and as bash runs it with each literal a known variable may hold (certain: `F=~/.x; cat "$F"` is `cat ~/.x`),
        # and with each name a bracket pattern can make (possible, as the empty readings: `cat key[s]` may be `cat keys`)
        extra = itertools.chain(  # built one at a time, each charged (below) before the next; None: a word gone
            ([w if t is None else None if not t and a else t for t, w, a in zip(texts, words, alones)]
             for texts in self.fill(slots)),
            (words[:i] + [c] + words[i + 1:] for i, p in enumerate(patterns) if p and self.ctx["readings"]
             for c in _unglob(words[i])))
        for k, texts in enumerate(extra, 12):
            self.charge(len(texts))
            kept = [i for i, t in enumerate(texts) if t is not None]
            alt = [texts[i] for i in kept]
            # lean: past the 4th, a reading makes a command, not a line: a rule on the line or code (TK-D011) reads the
            # first 4 (a loop over hundreds of words would read its whole script again for each); line all if needed
            if k < 16:
                self.gone += [{} for _ in range(k + 1 - len(self.gone))]
                self.gone[k].update((idx[i], t) for i, t in enumerate(texts) if t != words[i])
            if alt and tuple(alt) not in seen and not data:
                seen.add(tuple(alt))
                self.charge(sum(map(len, alt)))
                more = self.emit(alt, pid, self.via, any(globs), [names[i] if texts[i] == words[i] else
                                                                  bool(_GLOB.search(texts[i])) or _name_unreadable(texts[i])
                                                                  for i in kept])
                cmds = cmds + more
                self.progs += [idx[kept[j]] for j in _programs(alt, more)]
        self.track_values(words, cmds, assigns, loop_header and (loop_header, header), sure and not dynamic)
        marks = []
        if data:
            marks = here + ([s for s in spans[1:] if s] if words[0] in ("echo", "printf") else [])
            data_indexes = [i for i, _, _ in marks]
            self.data.update(data_indexes)
        else:
            data_indexes = []
        inert = bool(words) and words[0] in ("cd", "pushd", "popd", "pwd", "ls", "mkdir", "true", ":") or \
            bool(words) and words[0] in ("echo", "printf") and "-v" not in words[1:] and not stdout_redirect
        step = {"inert": (data and not dynamic) or
                         (inert and not (stdin_redirect or docs or strings or loop_header or dynamic)),
                "marks": [(a, b) for _, a, b in marks] if not self.via else []}
        if git_stdin_message:
            step["inert"] = False
            for cmd in cmds:
                cmd["data_stdin"] = True
        self.ctx["steps"].append(step)
        if data_indexes:
            self.data_steps.append((data_indexes, step))
        if data and cmds:
            if words[0] in ("echo", "printf"):
                self.ctx.setdefault("cut_data_words", []).append((step, cmds[0], list(range(1, len(words)))))
            else:
                self.ctx.setdefault("cut_data_stdin", []).append((step, cmds[0]))
        for d in docs:
            d["cmds"], d["data"], d["step"] = cmds, data or git_stdin_message, step
            d["always_data"] = git_stdin_message
        for c in cmds:
            c["stdin"] += strings
        shell = _stdin_shell(cmds)
        # its script comes from a pipe, a file or inherited stdin; one only a second reading makes (`bash $f` read as
        # `bash`) from a pipe or a file: the script file of an ordinary `bash $f` isn't held
        if shell and not docs and not strings and shell["argv"][0] in SHELLS and (
                piped or stdin_redirect or shell is _stdin_shell(as_written)):
            shell["opaque"] = True
        for text in strings if shell else ():
            self.nested(text, shell["via"] + [shell["argv"][0] + " <<<"])
        interp = None if shell else _stdin_interpreter(cmds)
        if interp and not docs and not strings and (piped or stdin_redirect):
            interp["opaque"] = True   # its program comes from a pipe or a file
        for text in strings if interp else ():
            self.program(interp, text, " <<<")
        if words and words[0] in ("cd", "pushd", "popd"):
            self.cwd_changed = True
        self.track_redefinitions(cmds)
        return consumed

    def fill(self, slots):
        """Each way the known variables word() found in the words' `slots` (None: a word with none) may be set at
        once, as the words' texts (None for a word with none): `for f in a b` sets $f to a, then to b."""
        names = sorted({p[0] for s in slots if s for p in s if isinstance(p, tuple)})
        if not names:
            return []
        out = []
        for values in itertools.product(*(self.known.get(n, ()) for n in names)):
            env = dict(zip(names, values))
            out.append([s and "".join(env[p[0]] if isinstance(p, tuple) else p for p in s) for s in slots])
            self.charge(sum(len(t) for t in out[-1] if t))
        return out

    def track_values(self, words, cmds, assigns, loop, sure):
        """Update self.known (__init__) after a simple command: a variable it gives a literal on its own, or with
        `export` (`export D=build`), is known when that surely runs (`sure`) before what follows it (`;`, a newline, `&&`
        or a subshell's end); a for loop's over literal words is known in its body; any other variable it sets is not;
        and after a command that may set any (read, declare, unset, eval, source, trap, alias, printf -v, one whose
        name the parser can't read) none is, for the rest of the line. A known variable keeps the literals it may hold
        (the loop's words; [""]: certainly empty, after `X=` or `unset X`), [] when unknown. `loop`: (for or select,
        the words after it); `assigns`: (name, the literal it gets or None, whether it is appended to: +=)."""
        if loop:
            kind, (name, *rest) = loop[0], loop[1] or [None]
            literal = kind == "for" and rest[:1] == ["in"] and len(rest) > 1 and None not in rest[1:]
            # the body runs again after its later commands: what they may change isn't known in it, nor after it
            self.known = {}
            if literal and not self.ctx["any_set"] and name != "IFS":
                self.known[name] = rest[1:]   # select sets it to nothing on a reply that picks no item
            self.blocks.append((kind, [name]))
            return
        if words[:1] in (["cd"], ["pushd"], ["popd"]):   # $PWD is the literal it surely goes to (cd alone: ~)
            args = words[1:]
            while args[:1] and args[0].startswith("-") and args[0] != "-" and args.pop(0) != "--":
                pass
            to = args[0] if args else "~" if words[0] == "cd" else "-"
            self.known.pop("PWD", None)
            if words[0] != "popd" and to and to[0] not in "-+" and sure and not re.search(r"[*?[]", to) and \
                    not self.ctx["any_set"]:
                self.known["PWD"] = [to]
                if self.blocks:
                    self.blocks[-1][1].append("PWD")
        if words[:1] == ["export"] and words[1:] and not assigns and sure and all(
                re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\+?=.+", w, re.S) for w in words[1:]):
            assigns = [(n.rstrip("+"), v, n.endswith("+")) for n, v in (w.split("=", 1) for w in words[1:])]
            words = []
        elif words[:1] == ["unset"] and all(re.fullmatch(r"-v|[A-Za-z_][A-Za-z0-9_]*", w) for w in words[1:]):
            assigns, words = [(n, "", False) for n in words[1:] if n != "-v"], []   # each now certainly empty
        elif any(c["opaque"] or c["argv"][0] in _SETS_ANY or _sets_with_v(c["argv"]) or _sets_keyword(c["argv"])
                 for c in cmds):
            self.ctx["any_set"] = True
        then = self.peek() in ("", "\n", ";", ")") or self.at("&&")
        for name, value, plus in assigns:
            old = self.known.pop(name, None)
            # X+=y of an X the line doesn't know may be y alone: not known; X= (or unset X) is known to be empty
            if value is None or not (sure and then) or words or self.ctx["any_set"] or name == "IFS" or plus and not old:
                continue
            self.known[name] = [o + value for o in old] if plus else [value]
            if self.blocks:   # a group's: forgotten at its }, as the group may not run
                self.blocks[-1][1].append(name)

    def track_redefinitions(self, cmds):
        """Record redefinitions and mutations which make command names untrustworthy."""
        copies = {"cat", "tee", "echo", "printf"}
        for cmd in cmds:
            argv = cmd["argv"]
            self.ctx["command_names_mutable"] |= (argv[0] in ("alias", "unalias", "shopt", "enable", "source", ".", "hash") or
                                                  argv[0] in _VARIABLE_SETTING_BUILTINS or
                                                  _sets_with_v(argv) or
                                                  "command_not_found_handle" in argv or
                                                  any(_COMMAND_NAME_ASSIGN.match(a) for a in argv[1:]))
            if argv[0] == "alias":
                self.ctx["redefined"].update(a.split("=", 1)[0] for a in argv[1:] if a.split("=", 1)[0] in copies)
            elif argv[0] == "enable" and "-n" in argv:
                self.ctx["redefined"].update(a for a in argv[1:] if a in copies)
            elif argv[0] in ("source", ".") and len(argv) > 1:
                self.ctx["redefined"].update(copies)

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
            cmd = {"argv": [name] + args, "word": argv[0], "via": via, "pipeline": pid, "glob": glob,
                   "opaque": unreadable[0] or tainted, "stdin": []}
            self.ctx["cmds"].append(cmd)
            cmds.append(cmd)
            if name in ("export", "declare", "typeset", "readonly", "local", "env"):   # git config set in the environment
                for a in args:
                    if (alias := _git_env_alias(a)) is not None:
                        self.nested(alias, via + ["git alias"])
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
            elif name == "git":
                # a shell alias runs its command as sh -c does: set for this run (`git -c alias.x='!cmd' x`) or saved
                # for a later one (`git config alias.x '!cmd'`); one from a variable or an included file isn't read
                if any(re.match(r"(?i)--config-env=(alias|include)", a)
                       or j and args[j - 1] == "-c" and re.match(r"(?i)include(if)?\.", a) for j, a in enumerate(args)):
                    raise ParseError("git config from a variable or an included file is not read")
                for j, a in enumerate(args):
                    m = re.fullmatch(r"(?is)alias\.[^=\s]+(?:=\s*!(.*))?", a)
                    nxt = args[j + 1].lstrip() if m and m.group(1) is None and j + 1 < len(args) else ""
                    if m and (m.group(1) is not None or nxt.startswith("!")):
                        self.nested(m.group(1) if m.group(1) is not None else nxt[1:], via + ["git alias"])
            elif name == "trap" and len(args) > 1 and not re.fullmatch(r"-[lpP]*", args[0]):
                # its action runs on a signal or at exit (`trap 'rm -rf "$d"' EXIT`); `-` or a lone condition resets
                self.nested(args[1] if args[0] == "--" else args[0], via + ["trap"])
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
                parts, at, self.i = [s[self.i:end]], self.i, min(end + 1, len(s))
                # an unquoted heredoc: bash deletes a backslash-newline before it compares a line with the delimiter
                while d["expand"] and j >= 0 and (len(parts[-1]) - len(parts[-1].rstrip("\\"))) % 2:
                    parts[-1] = parts[-1][:-1]
                    j = s.find("\n", self.i)
                    end = len(s) if j < 0 else j
                    parts.append(s[self.i:end])
                    self.i = min(end + 1, len(s))
                line = "".join(parts)
                if (line.lstrip("\t") if d["strip"] else line) == d["delim"]:
                    break
                lines.append(line)
            body = "\n".join(lines)
            for c in d["cmds"]:
                c["stdin"].append(body)
            # a data heredoc's body, unless a command substitution in it runs (what it runs may read a heredoc of its
            # own, which only this text holds)
            if d["data"] and not d["via"] and not (d["expand"] and re.search(r"\$\(|`", body)):
                if d.get("always_data"):
                    self.ctx["always_cut"].append((start, at))
                else:
                    d["step"]["marks"].append((start, at))
            shell, interp = _stdin_shell(d["cmds"]), _stdin_interpreter(d["cmds"])
            if shell:
                self.nested(body, shell["via"] + [shell["argv"][0] + " <<"])
            elif interp:
                self.program(interp, body, " <<")
            # an unquoted heredoc's substitutions run now, in this shell, also before at or batch get the text
            if (not shell or shell["argv"][0] not in SHELLS) and d["expand"]:
                p = _Parser(body, self.ctx, d["via"] + ["<<"])
                p.known = {}   # read after the rest of its line, which may set a variable after the body runs
                p.dquote(None)

    def relex(self, piece):
        """word() over one word a brace expansion made (_brace refuses a substitution in it), or None for an empty
        one, which bash drops."""
        saved = self.s, self.i
        self.s, self.i = piece, 0
        try:
            return self.word()
        finally:
            self.s, self.i = saved

    def word(self):
        """Return (text, raw source, has an unquoted glob or brace expansion, has a parameter expansion or command
        substitution), or None at an operator or the end. The raw source leaves out an unquoted backslash-newline:
        bash deletes it before it reads the word, so `ti\\<newline>me` is the keyword time. self.vanish: the word is only
        unquoted parameter expansions and command substitutions, which bash drops when they expand to nothing. self.cut:
        its text in each second reading (simple()): as written; with each of those empty, as bash joins an empty one
        into the rest of the word; and with only those empty that touch a character other than / = : , @ (`${X}push`,
        not `repos/$R/x`, which rules read as built at run time); each again keeping a bare $HOME. A word that is only
        those is empty in each."""
        s, start, buf, bare, exp, joins, alone, ifs = self.s, self.i, [], [], self.ctx["exp"], [], True, []
        while self.i < len(s):
            c = s[self.i]
            if c in "<>" and self.peek(1) == "(":
                alone = False   # a process substitution is a file name, never nothing
                at = self.i
                self.i += 2
                self.ctx["exp"] += 1
                self.sub(c + "()")
                buf.append(s[at:self.i])
                continue
            if c in " \t\n;&|()<>":
                break
            if c == "\\":
                if self.at("\\\n"):
                    joins.append(self.i)
                else:
                    buf.append(s[self.i + 1:self.i + 2])
                    alone = False
                self.i += 2
            elif c == "'":
                alone = False
                j = s.find("'", self.i + 1)
                if j < 0:
                    raise ParseError("unterminated '")
                buf.append(s[self.i + 1:j])
                self.i = j + 1
            elif c == '"' or self.at('$"'):   # $"...": "..." translated
                n = len(buf)
                self.i += 1 + (c == "$")
                self.dquote('"', buf=buf)
                inner = [p for p in buf[n:] if p]   # one expansion, read to where bash ends it, is all of "$@"
                alone = alone and c == '"' and len(inner) == 1 and isinstance(inner[0], _Expansion) and \
                    bool(_ALL_ITEMS.match(inner[0]))
            elif c == "$":
                at = self.i
                buf.append(self.dollar(False))
                alone = alone and isinstance(buf[-1], _Expansion)
                if buf[-1] in ("$IFS", "${IFS}") and "IFS" in self.known and not self.ctx["any_set"]:
                    ifs.append((at, self.i))
            elif c == "`":
                buf.append(self.backtick())
            else:
                alone = False
                bare.append(c)
                buf.append(c)
                self.i += 1
        if self.i == start:
            return None
        text = "".join(buf)
        self.vanish, self.cut, self.ifs, self.slots = False, (text,) * 6, ifs, None
        self.alone = alone and self.ctx["exp"] != exp   # only unquoted expansions: gone when they are empty
        if self.ctx["exp"] != exp:
            known = {} if self.ctx["any_set"] else self.known   # a known variable reads as written, never empty
            pieces, glued, j = [str(p) if (m := _PLAIN_VARIABLE.fullmatch(p)) and m.group(1) in known else p
                                for p in buf if p], set(), 0
            # the text with each known variable that has literals as a slot, (name,), for fill()
            slots = [(m.group(1),) if isinstance(p, _Expansion) and (m := _PLAIN_VARIABLE.fullmatch(p)) and
                     known.get(m.group(1)) else p for p in buf if p]
            self.slots = slots if any(isinstance(p, tuple) for p in slots) else None
            self.vanish = alone and all(isinstance(p, _Expansion) and not p.empty for p in pieces)
            while j < len(pieces):   # each run of expansions, and whether it touches such a character
                k = j
                while k < len(pieces) and isinstance(pieces[k], _Expansion):
                    k += 1
                if j < k and (j and pieces[j - 1][-1] not in "/=:,@" or k < len(pieces) and pieces[k][0] not in "/=:,@"):
                    glued.update(range(j, k))
                j = k + 1

            def cut(keep, home=False):   # home: a $HOME and a default's word as written are kept
                return "".join(p if not isinstance(p, _Expansion) or keep(i, p) else p.word if home else p.empty
                               for i, p in enumerate(pieces))
            empty = cut(lambda i, p: False), cut(lambda i, p: _HOME_WORD.fullmatch(p), True)
            self.cut = empty * 3 if self.vanish else (text, text) + empty + (
                cut(lambda i, p: i not in glued), cut(lambda i, p: i not in glued or _HOME_WORD.fullmatch(p), True))
        bare = self.bare = "".join(bare)   # neither pattern backtracks: each scan from a `[` or `{` stops at the next bracket
        glob = _GLOB.search(bare) or any("," in b or ".." in b for b in re.findall(r"\{[^{}]*\}", bare))
        raw = "".join(s[a + 2:b] for a, b in zip([start - 2] + joins, joins + [self.i]))
        return text, raw, bool(glob), self.ctx["exp"] != exp

    def sub(self, label):
        saved = self.via, self.out, self.progs, self.data, self.data_steps, self.gone, dict(self.known)
        self.via, self.out, self.progs, self.data, self.data_steps = self.via + [label], [], [], set(), []
        self.gone = [{} for _ in range(12)]
        self.list(")")
        self.flush()
        self.via, self.out, self.progs, self.data, self.data_steps, self.gone, self.known = saved   # a subshell's own

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
        # Bash expands an arithmetic array index a second time. If parameter
        # expansion can build a substitution there, the resulting program is
        # not present for this parser to read.
        subscript_start = body.find("[")
        subscript_end = body.find("]", subscript_start + 1) if subscript_start >= 0 else -1
        if subscript_end >= 0:
            index = body[subscript_start:subscript_end + 1]
            plain_parameters = re.sub(r"\$\{[^{}]*\}|\$[A-Za-z_][A-Za-z0-9_]*", "", index)
            if "$" in plain_parameters or "`" in index or re.search(r"\$\{[^{}]*\$\}\s*\(", index):
                raise ParseError("an expandable command in an arithmetic subscript is not supported")
            # A same-line assignment can supply text that bash evaluates again as
            # an arithmetic subscript. Its command is not available to this parse.
            line_start = self.s.rfind("\n", 0, start) + 1
            line_end = self.s.find("\n", self.i)
            if line_end < 0:
                line_end = len(self.s)
            line = self.s[line_start:line_end]
            if "$" in index and re.search(r"\$\(|`", line):
                raise ParseError("a parameterized arithmetic subscript on a line with a substitution is not supported")
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


    def dquote(self, term, in_dq=False, buf=None):
        """Read up to `term` ("\"", "}" or None for a heredoc body), running substitutions; return the text (`buf`:
        a list to add its pieces to instead, an _Expansion apart). In a `${...}` (term "}"; in_dq: itself inside double
        quotes), a backslash escapes any character and quotes pair up, so a `}` inside them doesn't end it (POSIX,
        bash). Unreadable there: a single quote around `$`, a backtick or a backslash; and in a double-quoted `${...}`,
        a `}` inside quotes or a single quote around `}` or `"` (bash's posix mode reads those apart)."""
        self.enter()
        s, buf, quoted = self.s, [] if buf is None else buf, False
        while True:
            if self.i >= len(s):
                if term is None:
                    break
                raise ParseError(f"unterminated {term}")
            c = s[self.i]
            if term == "}" and c == "\\":
                self.i += 2
                continue
            if term == "}" and c == "'" and not quoted:
                j = s.find("'", self.i + 1)
                if j < 0 or re.search(r"[}$`\\\"]" if in_dq else r"[$`\\]", s[self.i + 1:j]):
                    raise ParseError("a single quote around a special character in ${...} is not supported")
                self.i = j + 1
                continue
            quoted ^= term == "}" and c == '"'
            if c == term and quoted and in_dq:
                raise ParseError("a } inside quotes in a double-quoted ${...} is not supported")
            if c == term and not quoted:
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
        if self.at("$\\\n"):   # bash deletes the backslash-newline first: what follows decides what the $ starts
            j = start + 1
            while s.startswith("\\\n", j):
                j += 2
            m = _NAME.match(s, j)
            if s[j:j + 1] in ("(", "{"):
                # lean: a $( or ${ across one is held, not read; read it if real commands write one
                raise ParseError("a backslash-newline between $ and ( or { is not supported")
            if s[j:j + 1] in ("'", '"') and not in_dq:
                self.i, nxt = j - 1, s[j]   # the $'...' or $"..." it is, read below
            elif not m:
                self.i += 1
                return "$"
            else:
                self.i = m.end()
                self.ctx["exp"] += 1
                return _Expansion("$" + m.group())
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
            arithmetic_body = s[self.i + 3:j]
            if "\\\n" in arithmetic_body:   # bash joins the lines first, so the body may hold a $( this text doesn't
                raise ParseError("a backslash-newline in $(( )) is not supported")
            possible_subscript = re.sub(r"\$\{[^{}]*\}|\$[A-Za-z_][A-Za-z0-9_]*", "", arithmetic_body)
            builds_substitution = re.search(r"\$\{[^{}]*\$\}\s*\(", arithmetic_body)
            line_start = s.rfind("\n", 0, self.i) + 1
            line_end = s.find("\n", self.i)
            if line_end < 0:
                line_end = len(s)
            line_has_substitution = re.search(r"\$\((?!\()|`", s[line_start:line_end])
            if "$(" in arithmetic_body or "`" in arithmetic_body or (
                    "[" in arithmetic_body and ("$" in possible_subscript or builds_substitution or
                                                "$" in arithmetic_body and line_has_substitution)):
                self.i += 3
                self.arith()
            else:
                self.i = j + 1
        elif nxt == "(":
            self.i += 2
            self.sub("$()")
        elif nxt == "{":
            if s[self.i + 2:self.i + 3] in (" ", "\t", "\n", "|"):   # bash 5.3 runs it in this shell: ${ cmd; }
                raise ParseError("a ${ command; } substitution is not supported")
            self.i += 2
            self.dquote("}", in_dq)
        else:
            m = _NAME.match(s, self.i + 1)
            self.i = m.end() if m else self.i + 1
        text = s[start:self.i]
        # HOME is set unless this line may have emptied it, and so is a variable the line gave only literals that aren't
        # empty: its default, assignment or check is the variable ($HOME as the packs name it, ${HOME:-x}, ${HOME:?}; or
        # the literal the line gave it, D=/; rm -rf "${D:?}"/); the default stays what it is when it may be empty
        named = _DEFAULT.fullmatch(text)
        values = self.known.get(named.group(1)) if named and not (self.ctx["any_set"] and named.group(1) == "HOME") \
            else None
        plain = named and ("" not in (values or ()) if named.group(1) == "HOME" else bool(values) and "" not in values)
        # never nothing: arithmetic, a lone $, and ${X:?...}, which stops the command instead
        if not plain and (text == "$" or text.startswith("$((") or re.fullmatch(r"(?s)\$\{\w+:\?.*", text)):
            return text
        # always nothing, as written too: an empty alternative, a length of 0, all of it removed (${X:+}, ${X:0:0},
        # ${X%%*})
        if re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::?\+|:(?![-=?+])[^:{}]*:0+|%%\*|##\*)\}", text):
            return _Expansion("")
        expansion = _Expansion("$" + named.group(1) if plain else text)
        if m := re.fullmatch(r"(?s)\$\{\w+:?[-=](.*)\}", text):   # bash runs the word when X is empty (unset, no colon)
            expansion.word = _UNQUOTE.sub(lambda q: next(g for g in q.groups() if g is not None), m.group(1))
            expansion.empty = expansion.word
            while (emptied := _INNERMOST.sub("", expansion.empty)) != expansion.empty:   # ${X:-$Y} may be nothing
                expansion.empty = emptied
        return expansion

    def backtick(self):
        m = re.compile(r"((?:\\.|[^`\\])*)`", re.S).match(self.s, self.i + 1)
        if not m:
            raise ParseError("unterminated `")
        start, self.i = self.i, m.end()
        self.ctx["exp"] += 1
        self.nested(re.sub(r"\\([`\\$])", r"\1", m.group(1)), self.via + ["``"])
        return _Expansion(self.s[start:self.i])


def _lower_name(word):
    """`word` with the name after its last / or \\ casefolded and without a `.exe` (Windows runs git.exe for git; macOS
    runs /bin/sh for `ſh`, its file system folding case as casefold does): the directories keep their case."""
    i = max(word.rfind("/"), word.rfind("\\")) + 1
    name = word[i:].casefold()
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
    """The line `words` make, and again with the program names at indexes `progs` casefolded when that differs."""
    low = list(words)
    for i in progs:
        low[i] = _lower_name(low[i])
    return [" ".join(words)] + ([" ".join(low)] if low != words else [])


def _lines_without(words, progs, gone):
    """_lines() with the word at each index in `gone` read as its text there, or left out where that is None (bash drops
    an empty expansion, an unmatched glob)."""
    words = [gone.get(i, w) for i, w in enumerate(words)]
    keep = [i for i, w in enumerate(words) if w is not None]
    at = {i: k for k, i in enumerate(keep)}
    return _lines([words[i] for i in keep], [at[p] for p in progs if p in at])


def _stdin_shell(cmds):
    """A shell reading its script from stdin, or at or batch, which read from it the commands they schedule."""
    return next((c for c in cmds if c["argv"][0] in SHELLS and _shell_mode(c["argv"][1:])[0] == "stdin"
                 or c["argv"][0] in ("at", "batch")), None)


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
