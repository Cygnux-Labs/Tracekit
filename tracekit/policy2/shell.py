"""Structural shell parser for policy matching (design §4.4; no bashlex).

`parse(command)` returns every simple command the line would run, including those reached through wrappers, `sh -c`
strings, substitutions, heredocs into a shell, at or batch, trap's action and interpreter one-liners:
`{"argv": [...], "word": str, "via": [...], "pipeline": n, "glob": bool, "opaque": bool, "stdin": [...]}`. argv[0] is
a basename, the part after any `\\` casefolded and without a `.exe` (the agent's file system may ignore case: macOS
runs git for `Git`; Windows runs git.exe for git); `word` is that first word as written (a path, or the text of a name
an expansion builds); `via` says how the command was reached (empty at top level); commands with the same `pipeline`
are stages of one pipeline, in order. `opaque`: what the command runs cannot be read from the line (a glob, brace or
expansion in its name, a shell or interpreter reading its script from a pipe, a file or inherited stdin, `source` of
a stream). `stdin`: the herestring and heredoc text the command reads (the names `xargs rm <<< x` deletes). A command
of the line itself also has `out` and `in`, the files its redirections write and read, and `stage`, its place in its
pipeline (0 first). `moved`: the stdin it inherits may be one the line moved (_reads_only). `background`: True when the
and-or list it is in ends in `&` (`a && b &` sends both), when it is in a block whose closing word that `&` follows
(`{ a; } &`, `while …; do a; done &`, if, for, select, case: from the and-or list the block opened in), or when one it
runs in does (a subshell, an `sh -c` string); absent otherwise.
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
import ast
import base64
import collections
import itertools
import json
import math
import posixpath
import re
import shlex
import urllib.parse


class ParseError(ValueError):
    cause = "syntax"   # the TK-SHELL-PARSE cause it gives (compile.ENGINE_REASONS)


class _Unclosed(ParseError):
    cause = "quote"   # a ' " or $' the line doesn't close


class _Expansion(str):
    """A parameter expansion or command substitution as written, which bash may expand to nothing; `empty`: what it
    expands to when its variable is empty or unset (a default's word: ${X:-w} is w, with w's own expansions empty),
    else nothing; `word`: a default's word as written, read where a $HOME is kept (${X:-$HOME} may be $HOME);
    `quoted`: written inside double quotes, so bash neither splits nor globs what it expands to; `alt`: what it may
    expand to when each expansion with a word takes it (${X:+w} is w when X is set, ${X/*/w} w), its word's own
    expansions too, or None for `empty`. `values`: each text it may expand to (its word read so: _Parser.ways), or
    None for a plain one's (_Parser.ways: a variable's literals, else as written or empty); `unread`: more than
    MAX_READINGS."""
    empty = word = ""
    alt = values = None
    quoted = unread = False


class _Quoted(str):
    """Text of an expansion's word that quotes or a backslash make literal: never its pattern's end nor a &."""


class _Expanded(str):
    """A word holding variables this shell expands in it (`names`: not one the line gives a literal), whose values
    become code where bash parses the word again (_Parser.code)."""
    names = frozenset()


class _Spliced(_Expanded):
    """A word holding an expansion whose text the line makes and the parser can't read (_Parser.unsafe): code bash
    parses again from it (eval's words, sh -c's script, a trap's action, a script the line writes) may hold more than
    the parser reads there."""


MAX_DEPTH = 32
# the texts a word may make as its expansions take each of their values (_Parser.ways), and the ways the words of a
# command that make more than its uniform readings combine (simple): past it the word or command is unread
# (TK-SHELL-PARSE's `readings`), so a word of 300 expansions costs no more than one of 8. 256 reads a docker or rsync
# line of seven defaults; each reading spends the parse budget (MAX_WORK), which bounds a hostile line's time
MAX_READINGS = 256
# what reading one more nested text costs beyond its characters (a parser of its own: _Parser.nested), so many short
# ones (an alias used a thousand times, each use read with each of its values) spend the budget as their time does
NESTED_COST = 64
# what each command read costs beyond its words: the engine reads each one several times over (its argv, effects,
# Tracekit's paths), so 32,000 one-letter commands (`a|a|…`, 63 KiB) spend the budget rather than a second of the signer.
# At most 15: a 64 KiB arithmetic line of 8,192 `$(id)` (test_arithmetic_expansion_parses_in_linear_time…) stays read
COMMAND_COST = 15
MAX_WORK = 1 << 18   # characters parsed in total, re-parsed consumer strings, the list each process call in
                     # interpreter code reads and the words each wrapper level copies included: 4 × the largest
                     # subject, so a worst-case command costs a fraction of a second of the signer (the parser holds
                     # the GIL)
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "rbash", "mksh", "ksh93", "yash", "posh", "lksh", "oksh"}
# shells whose language the parser doesn't read: the commands they get on their line or from stdin are opaque
FOREIGN_SHELLS = {"fish", "csh", "tcsh", "pwsh", "powershell", "nu", "xonsh", "elvish"}
# shells whose grammar isn't bash's: code they read is held where it uses an operator only bash has (_Parser.nested)
_POSIX_SHELLS = SHELLS - {"bash", "rbash", "zsh"}
_BASH_ONLY = re.compile(r"&>|\|&|>&\s*(?![\d-])\S|\[\[|\$'|<<<")
# what may put bash in POSIX mode, where its grammar is POSIX's too
_POSIX_MODE = re.compile(r"\bposix\b|POSIXLY_CORRECT")
# shopt options that change how bash parses code (`#` as text, extglob's patterns, aliases, POSIX's grammar)
_PARSING_OPTIONS = {"interactive_comments", "extglob", "expand_aliases", "posix"}
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
# wrapper -> (options that take a value, positional arguments before the command); an option not named is read both
# ways (_unwrap)
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
            # strace 6's options that take a value (an optional one, --x=v, is one word)
            "strace": (("-a", "-b", "-e", "-E", "-I", "-o", "-O", "-p", "-P", "-s", "-S", "-u", "-U", "-X", "--columns",
                        "--detach-on", "--env", "--interruptible", "--output", "--summary-syscall-overhead", "--attach",
                        "--trace-path", "--string-limit", "--summary-sort-by", "--summary-columns", "--user",
                        "--const-print-style", "--argv0", "--trace", "--trace-fds", "--abbrev", "--verbose", "--raw",
                        "--read", "--write", "--fault", "--inject", "--status", "--signal", "--kvm", "--syscall-limit",
                        "--stack-trace-frame-limit"), 0),
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
            "dumb-init": (("-r", "--rewrite"), 0), "tini": (("-p", "-e"), 0), "entr": ((), 0),
            "watchexec": (("-w", "--watch", "-W", "--watch-non-recursive", "-e", "--exts", "-f", "--filter", "-i",
                           "--ignore", "-d", "--debounce", "--delay-run", "-s", "--signal", "--stop-signal",
                           "--stop-timeout", "--shell", "-E", "--env", "--workdir", "--on-busy-update",
                           "--emit-events-to", "--project-origin", "--filter-file", "--ignore-file", "--poll",
                           "--color", "--log-file", "-j", "--filter-prog", "--fs-events"), 0)}
# wrapper or runner -> options known to take no value (_unwrap reads an option neither table names both ways), a
# short-option cluster of them too (`caffeinate -dims`, `sudo -Eu root`)
_UV_FLAGS = ("-q", "--quiet", "-v", "--verbose", "--frozen", "--locked", "--no-sync", "--isolated", "--no-project",
             "--offline", "--active", "--all-extras", "--no-dev", "--exact", "--refresh", "-U", "--upgrade", "-n",
             "--no-cache")
WRAPPER_FLAGS = {"caffeinate": ("-d", "-i", "-m", "-s", "-u"),
                 "xargs": ("-0", "-r", "-t", "-p", "-x", "-o", "--null", "--no-run-if-empty", "--verbose",
                           "--interactive", "--exit", "--open-tty"),
                 "env": ("-i", "-0", "-v", "--ignore-environment", "--null", "--debug"),
                 "timeout": ("-v", "--verbose", "--foreground", "--preserve-status"),
                 "gtimeout": ("-v", "--verbose", "--foreground", "--preserve-status"),
                 "time": ("-p", "-v", "-a", "-q", "--portability", "--verbose", "--append", "--quiet"),
                 "exec": ("-c", "-l"),
                 "sudo": ("-A", "-b", "-E", "-e", "-H", "-i", "-K", "-k", "-l", "-n", "-P", "-S", "-s", "-V", "-v",
                          "--askpass", "--background", "--preserve-env", "--edit", "--set-home", "--login",
                          "--remove-timestamp", "--reset-timestamp", "--list", "--non-interactive",
                          "--preserve-groups", "--stdin", "--shell", "--validate"),
                 "strace": ("-c", "-C", "-d", "-D", "-f", "-F", "-i", "-k", "-n", "-q", "-r", "-t", "-T", "-v", "-w",
                            "-x", "-y", "-z", "-Z", "--follow-forks", "--summary-only", "--summary", "--seccomp-bpf",
                            "--output-separately", "--no-abbrev"),
                 "flock": ("-s", "-x", "-u", "-n", "-o", "-F", "--shared", "--exclusive", "--unlock", "--nonblock",
                           "--close", "--no-fork", "--verbose"),
                 "setsid": ("-c", "-f", "-w", "--ctty", "--fork", "--wait"),
                 "npx": ("-y", "--yes", "-q", "--quiet"), "uvx": _UV_FLAGS, "uv": _UV_FLAGS,
                 "entr": ("-a", "-c", "-cc", "-d", "-n", "-p", "-r", "-s", "-z")}
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
           "yarn": (("exec", "dlx"), ("-p", "--package"), 0), "bun": (("x",), ("-p", "--package"), 0),
           "bundle": (("exec",), ("--gemfile",), 0), "rye": (("run",), ("--pyproject",), 0),
           "pixi": (("run", "exec"), ("-e", "--environment", "--manifest-path", "-s", "--spec", "-c", "--channel"), 0),
           "micromamba": (("run",), ("-n", "--name", "-p", "--prefix", "-r", "--root-prefix", "--cwd", "-a",
                                     "--attach", "--label"), 0),
           "mamba": (("run",), ("-n", "--name", "-p", "--prefix", "--cwd"), 0)}
# GNU parallel runs its command words through a shell, as watch does; these options take a value
PARALLEL_OPTS = {"-a", "-d", "-E", "-I", "-j", "-n", "-N", "-L", "-P", "-S", "-s", "-C", "--arg-file", "--delimiter", "--jobs",
                 "--max-procs", "--max-args", "--max-lines", "--max-chars", "--sshlogin", "--sshloginfile", "--slf",
                 "--colsep", "--joblog", "--results", "--tmpdir", "--workdir", "--wd", "--timeout", "--retries", "--delay",
                 "--env", "--tag-string", "--transfer-file", "--return", "--basefile", "--bf"}
SHELL_VALUE_OPTS = {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}
# commands that run a string through a shell: -c anywhere in their arguments (getopt permutes)
DASH_C = {"su", "script"}
_STREAM = re.compile(r"/dev/(?:stdin|fd/)|/proc/[^/]+/(?:task/[^/]+/)?fd/")


def _stream(path):
    """Whether a path names a stream, not a file: stdin, a descriptor or a process substitution, however it is spelled
    (`//dev/stdin`, `/dev/./stdin`, `/proc/thread-self/fd/0`, `/proc/$$/task/1/fd/0`, `/dev/fd/$fd`)."""
    if path.startswith("<("):
        return True
    return path.startswith("/") and bool(_STREAM.match("/" + posixpath.normpath(path).lstrip("/")))


KEYWORDS = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "{", "}", "!"}
# bash's reserved words: an alias of one is expanded where the word is one (`alias do='do cmd;'`)
_RESERVED = KEYWORDS | {"for", "select", "case", "esac", "in", "function", "coproc", "time", "[[", "]]"}
SSH_OPTS = set("-b -c -D -E -e -F -I -i -J -L -l -m -O -o -p -Q -R -S -W -w".split())
KINDS = [("python", re.compile(r"python[0-9.]*")), ("node", re.compile(r"node|nodejs")), ("perl", re.compile(r"perl[0-9.]*")),
         ("ruby", re.compile(r"ruby[0-9.]*")), ("php", re.compile(r"php[0-9.]*")), ("lua", re.compile(r"lua[0-9.]*|luajit")),
         ("awk", re.compile(r"[gmn]?awk")), ("sed", re.compile(r"g?sed"))]
CODE_FLAGS = {"python": "c", "node": "ep", "perl": "eE", "ruby": "e", "php": "r", "lua": "e"}
# options of an interpreter that take a value (so the word after them is not the script)
INTERP_VALUE_OPTS = {"-W", "-X", "-r", "-I", "--require", "--input-type", "-d", "-c", "--import", "--loader",
                     "--experimental-loader"}
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=")
_COMMAND_NAME_ASSIGN = re.compile(r"(?:PATH|BASH_ENV|ENV)(?:\[[^]]*\])?\+?=")
# variables whose value bash runs: a prompt (PS0, PS1 and PS2 in an interactive shell, PS4 under xtrace, any with
# ${X@P}) is expanded as double-quoted text is, after its \ escapes; PROMPT_COMMAND is a script an interactive shell
# runs; BASH_ENV and ENV are expanded so and the file they name is sourced by a new shell (ENV by an interactive one
# only: _interactive); BASH_CMDS and BASH_ALIASES give a command name a path or an alias (_Parser.code_variable); git
# runs its editor, pager, ssh, askpass, external diff and proxy as a command, from these or its EDITOR's fallbacks
_CODE_VARIABLES = {"PS0": "prompt", "PS1": "prompt", "PS2": "prompt", "PS4": "prompt", "PROMPT_COMMAND": "script",
                   "BASH_ENV": "file", "ENV": "file", "BASH_CMDS": None, "BASH_ALIASES": None,
                   **dict.fromkeys(("GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "GIT_PAGER", "GIT_SSH_COMMAND", "GIT_SSH",
                                    "GIT_ASKPASS", "SSH_ASKPASS", "GIT_EXTERNAL_DIFF", "GIT_PROXY_COMMAND", "EDITOR",
                                    "VISUAL", "PAGER"), "script")}
# builtins that take variable names, where bash evaluates a NAME[subscript] (test, [ and [[ after -v, printf's -v)
_NAME_BUILTINS = {"read", "unset", "declare", "typeset", "local", "readonly", "export", "mapfile", "readarray",
                  "getopts", "wait", "test", "[", "[[", "printf"}
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


def _names_ifs(command):
    """Whether a line may name IFS in any spelling: with its quotes, backslashes and $'…' escapes resolved
    (`I"F"S`, `I\\FS`, `$'\\x49'FS`), or an indirect expansion (${!x}), which may name any variable."""
    plain = _ANSI_C_STRING.sub(lambda m: _ansi_c(m.group(1)), command)
    return "IFS" in _QUOTING.sub("", plain) or "${!" in command


_ANSI_C_STRING = re.compile(r"\$'((?:\\.|[^'\\])*)'")
_QUOTING = re.compile(r"[\"'\\\n]")


# a variable's value read through as a program's path (_Parser.simple): only the characters of an ordinary path, so a
# value a changed IFS would split there (`X=/usr/bin/sudo,id`) is not
_PLAIN_PATH = re.compile(r"[A-Za-z0-9_./~+-]+")


_SETS_NAME = re.compile(r"\b[A-Za-z_]\w*(?:\[[^]]*\])?\+?=|\$\{[A-Za-z_]\w*:?=|\b(?:for|select)\s+[A-Za-z_]\w*\b|"
                        r"\(\([^)]*")
_SETS_ANY_TEXT = re.compile(r"\b(?:" + "|".join(sorted(_SETS_ANY - {"wait"})).replace(".|", "") + r")\b|\bprintf\s+-v|"
                            r"\bwait\b[^;&|\n]*?\s-[A-Za-z]*p|(?:^|[\s;&|(])\.\s")   # (wait sets one only with -p)


def _settings(text):
    """Where shell text may give a variable a value, read in one pass: ({each name an assignment (`name=`, `name+=`,
    `${name:=…}`, a subscript's too), a loop or arithmetic names: its last place}, the last place of any builtin that
    sets variables by name (read, eval, declare …, printf -v, source), the last place of set or shift (a function's
    positional parameters)). _Parser.stable asks it once per name, not a search of the text per name and loop."""
    last = {}
    for m in _SETS_NAME.finditer(text):
        for n in re.findall(r"[A-Za-z_]\w*", m.group()):
            last[n] = m.start()
    return last, max((m.start() for m in _SETS_ANY_TEXT.finditer(text)), default=-1), \
        max((m.start() for m in re.finditer(r"\b(?:set|shift)\b", text)), default=-1)


# commands that print only what files or the system hold, and those that print their own words (a name, a path, a
# date, numbers), which are plain when those words are (_reads_only)
_READERS = {"cat", "head", "tail", "grep", "egrep", "fgrep", "rg", "cut", "sort", "uniq", "wc", "nproc", "tr", "ls"}
_ECHOERS = {"date", "basename", "dirname", "mktemp", "realpath", "readlink", "seq", "pwd", "whoami", "id", "uname"}
_PLAIN_WORD = re.compile(r"[\w./:,@%+=~${}-]*")   # (a $NAME in one is a value the line doesn't make: unsafe's)
_ECHO_OPTIONS = re.compile(r"-[neE]+")


def _digits_only(c):
    """Whether a command prints only digits (and blanks) whatever it reads: grep -o of a digit class, tr -dc of the
    digits, wc counting its stdin."""
    argv = c["argv"]
    if argv[0] in ("grep", "egrep") and any(re.fullmatch(r"-[a-zA-Z]*o[a-zA-Z]*", a) for a in argv[1:]):
        pattern = [a for a in argv[1:] if not a.startswith("-")][:1]
        return bool(pattern) and bool(re.fullmatch(r"(?:\[0-9\]|\\d|\[\[:digit:\]\])[+*]?", pattern[0]))
    if argv[0] == "tr":
        return argv[1:2] == ["-dc"] and argv[2:] in (["0-9"], ["[:digit:]"])
    return argv[0] == "wc" and all(a.startswith("-") for a in argv[1:]) and not c.get("in")


_LINE_SUBSTITUTION = re.compile(r"\$\((?!\()|`")   # a command substitution on a line (_Parser.line_substitutes)
# a substitution bash runs as a file's bytes, with no program: $(<f), $(0<f), `<f` (_Parser.unsafe)
_FILE_SUBSTITUTION = re.compile(r"(?:\$\(|`)\s*\d*<(?![<(&])")
# a parameter that is a number whatever the line does: $?, $#, $$, $!, $-'s flags, a length ${#X}
_NUMBER = re.compile(r"\$(?:[?#$!-]|\{#\w*\})")
# an expansion with no operator: $X, ${X}, $1, ${10}, $@, ${@} (_Parser.unsafe's code reading)
_PLAIN_EXPANSION = re.compile(r"\$(?:[A-Za-z_]\w*|[0-9@]|\{(?:[A-Za-z_]\w*|[0-9]+|@)\})")


def _prints(cmds, ctx):
    """What commands (a word's substitutions) print: 0 only digits (one pipeline whose last stage prints only digits,
    _digits_only), 1 what files and the system hold (_reads_only), 2 text the line may make (_Parser.unsafe)."""
    if cmds and _digits_only(cmds[-1]) and len({c["pipeline"] for c in cmds}) == 1:
        return 0
    return 1 if _reads_only(cmds, ctx) else 2


def _arith_names(text):
    """The variables arithmetic text evaluates the values of: its names, and "@" for a positional parameter in it."""
    return set(re.findall(r"[A-Za-z_]\w*", text)) | ({"@"} if re.search(r"\$\{?[0-9@*]", text) else set())


def _sets_positional(args):
    """Whether `set args` replaces $1 and the rest: an operand, `--` or `-`; not options alone (`set -e`, `set -o
    pipefail`: an o takes the next word)."""
    i = 0
    while i < len(args):
        if args[i] in ("--", "-") or not args[i].startswith(("-", "+")):
            return True
        i += 2 if "o" in args[i][1:] else 1
    return False


def _reads_only(cmds, ctx):
    """Whether commands (a substitution's, a pipeline's) only print what files or the system hold, not text the line
    makes: each one of _READERS, of _ECHOERS with plain words, or echo of variables the line gives no such text
    (`echo "$r"`), given no text of the line to print (a herestring or heredoc) and reading no file the line writes
    text it makes into (made_files: its own text, a crafting program's, or a copy of one; a pattern may name one);
    tr only deleting or squeezing; or any, when they are one pipeline whose last stage prints only digits
    (_digits_only: `a; wc -l` prints a's text too). What a file the line doesn't write holds is trusted as running it
    is (read_file reads only what the line writes); a value read, mapped or given as a parameter isn't such a file's,
    nor is a descriptor a reader is given (`<&3`) or a stdin it inherits where the line may have moved that (`exec <
    f1` before it, `{ …; } <<< x`, `x | eval "$(cat)"`, code bash reads again: the command's `moved`). A stdin the
    call itself gives (`n=$(grep -c x $f)` with $f empty) is trusted as a file on disk is."""
    made = ctx["made_files"]
    if cmds and _digits_only(cmds[-1]) and len({c["pipeline"] for c in cmds}) == 1:
        return True
    for c in cmds:
        argv, given = c["argv"], c["argv"][1:] + list(c.get("in", ()))
        operands = [a for a in argv[1:] if not a.startswith("-")]
        if argv[0] not in _READERS and not (argv[0] in _ECHOERS and all(map(_PLAIN_WORD.fullmatch, argv[1:]))) and \
                not (argv[0] == "echo" and all(
                    _ECHO_OPTIONS.fullmatch(a) or (v := _PLAIN_VARIABLE.fullmatch(a)) and not v.group(1).isdigit()
                    and v.group(1) not in ctx["unread_values"] | ctx["opaque_values"] for a in argv[1:])) or \
                c["stdin"] or "*" in made or c["glob"] and made or \
                any(w.rsplit("/", 1)[-1].casefold() in made for w in given) or \
                any(re.fullmatch(r"\d+|-", f) or _stream(f) or made and re.search(r"[$`]", f) for f in given) or \
                argv[0] in _READERS and argv[0] not in ("nproc", "ls") and not c.get("stage") and not c.get("in") and \
                len(operands) <= (argv[0] in ("grep", "egrep", "fgrep", "rg")) and \
                (c.get("moved", True) or ctx["stdin_moved"]) or \
                argv[0] == "tr" and not re.fullmatch(r"-[ds]+", argv[1] if argv[1:] else ""):
            return False
    return True


# NAME OP after a ${: a parameter (a special one, an array element, an indirect name too) with a default or an
# assignment (-, =), an alternate (+), each with or without the colon, or a pattern substitution (/, //, /#, /%): its
# word follows. Matched on the pieces dquote reads, one character each (\x01 for an expansion or quoted text)
_OPERATOR = re.compile(r"!?(?:[A-Za-z_]\w*|\d+|[@*#?$!-])(?:\[[^]]*\])?(:?[-=+]|/[/#%]?)")


def _assignments(ways):
    """Each way the expansions of `ways` (_Parser.ways) take a value at once; None past MAX_READINGS, an unread word or
    command (never fewer ways: any of them may be the one that runs). The command substitutions, read as written or
    empty, take one of those together: a mix of them makes no text a rule reads that all as written or all empty
    doesn't (`echo "a: $(grep -c a f) b: $(grep -c b f)"` is 2 readings, not 2 to the power of its substitutions)."""
    subs = [p for p, w in ways.items() if _SUBSTITUTION.match(p) and not p.startswith("$((") and w == (str(p), "")]
    rest = {p: w for p, w in ways.items() if p not in subs}
    if math.prod(map(len, rest.values())) * (2 if subs else 1) > MAX_READINGS:
        return None
    return [{**dict(zip(rest, c)), **{p: str(p) if written else "" for p in subs}}
            for written in ((True, False) if subs else (True,)) for c in itertools.product(*rest.values())]


# a bracket expression of a pathname pattern: whether it is negated, and its set (a ] first is one of its characters)
_BRACKET = re.compile(r"\[([!^]?)(\]?[^]]*)\]")
# $NAME or ${NAME}, fully matched, and a function's positional parameter $1 to $9 (_Parser.call)
_PLAIN_VARIABLE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*|[1-9])\}?")
# what bash splits or globs in an unquoted expansion's value (IFS as bash sets it)
_SPLIT_OR_GLOB = re.compile(r"[ \t\n*?[]")
# variables bash itself sets as the line runs, whatever the line gives them: never known (track_values). $_ is the
# last word of the command before; REPLY, OPTARG, MAPFILE, BASH_REMATCH what read, getopts, mapfile and [[ =~ ]] set;
# the rest bash keeps up to date (OLDPWD at a cd, COPROC at coproc, the BASH_ and COMP_ families)
_BASH_SETS = {"_", "REPLY", "OPTARG", "OPTIND", "OPTERR", "MAPFILE", "FUNCNAME", "PIPESTATUS", "COPROC", "OLDPWD",
              "DIRSTACK", "GROUPS", "LINENO", "RANDOM", "SRANDOM", "SECONDS", "EPOCHSECONDS", "EPOCHREALTIME", "HISTCMD",
              "PPID", "UID", "EUID", "SHLVL", "LINES", "COLUMNS", "HOSTNAME", "HOSTTYPE", "MACHTYPE", "OSTYPE",
              "READLINE_LINE", "READLINE_POINT", "READLINE_MARK", "READLINE_ARGUMENT"}


def _bash_sets(name):
    return name in _BASH_SETS or name.startswith(("BASH", "COMP_"))
# a line that may download (TK-D002's curl or wget, in any case): a function there isn't read (_Parser.define)
_DOWNLOADS = re.compile(r"(?i)curl|wget")
# a function definition where a command starts: `name()` or `function name [()]` (its body follows, _Parser.define)
_FUNCTION = re.compile(r"function[ \t]+([A-Za-z_][\w.:-]*)[ \t]*(?:\([ \t]*\))?|([A-Za-z_][\w.:-]*)[ \t]*\([ \t]*\)")
# names a function can't take here: bash's reserved words, and the builtins whose meaning this parser relies on to know
# a variable's value or the working directory (export, unset, cd), or that bash calls by itself
_UNREAD_FUNCTIONS = KEYWORDS | {"for", "in", "case", "esac", "select", "function", "time", "coproc", "[[", "]]", "cd",
                                "pushd", "popd", "export", "unset", "command_not_found_handle"}
_ESAC = re.compile(r"esac(?=[\s;&|)]|$)")
# "$@" and its kin: a function's arguments, each a word (_Parser.call); $* and "$*" too
_ALL_ARGUMENTS = ('"$@"', '"${@}"', "$@", "${@}", "$*", "${*}", '"$*"', '"${*}"')
_PLAIN = re.compile(r"""[^ \t\n;&|()<>\\'"$`]+""")   # characters _Parser.word() reads as themselves
# the operators bash reads across a deleted backslash-newline
_JOINED = {"&&", "||", ";;", ";&", ";;&", "|&", "<<", "<<-", "<<<", ">>", "<&", ">&", "<>", ">|", "&>", "&>>", "((",
           "<(", ">("}
_REDIR = re.compile(r"(\d*|\{\w+\})(&>>|&>|>>|>&|>\||<<<|<<-|<<|<&|<>|>|<)")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-]")
# a pathname pattern in a word's unquoted text; a ] first in a bracket is one of its characters ([]x], [!]x])
_GLOB = re.compile(r"[*?]|\[[!^]?(?:\][^][]*|[^][]+)\]")
_HOME_WORD = re.compile(r"\$(?:HOME|\{HOME\})")   # the one bare variable the packs name as a word
_DEFAULT = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):?[-=?][^{}]*\}")   # a variable with a default, assignment or check
# arithmetic, a subscript, an indirect name or an offset (of a special parameter too: ${@:x}, ${1:x}): bash may
# evaluate a value of the line there (_Parser.word)
_EVALUATES = re.compile(r"\$(?:\(\(|\{(?:!|#?(?:[A-Za-z_]\w*|[@*0-9]+)(?:\[|:(?![-=?+]))))")
# ${X=…}, ${X:=…}, ${X::=…}, ${X[i]:=…}, ${!X=…}; and ${X=…}, ${X:=…}, one whose word the parser may follow (dollar)
_ASSIGNS = re.compile(r"\$\{!?([A-Za-z_]\w*)(?:\[[^]]*\])?:{0,2}=")
_PLAIN_ASSIGN = re.compile(r"\$\{([A-Za-z_]\w*):?=")
_NAME_LIST = re.compile(r"\$\{![A-Za-z_]\w*[@*]\}")   # ${!X@}, ${!X*}: the names of the variables set when it runs
_VALUE_OF = re.compile(r"\$(?:([A-Za-z_]\w*)$|\{([A-Za-z_]\w*)(?:\[[^]]*\])?(?:\}$|:?[-=?]))")


def _value_of(p):
    """The variable expansion `p` is the value of when it is set ($X, ${X}, a default, assignment or check; an element
    of it too, ${X[i]}: any element may be the one a subscript names), or None."""
    m = _VALUE_OF.match(p)
    return m and (m.group(1) or m.group(2))


def _fields(parts):
    """A word's text from its `parts`, each (text, whether bash splits it: an unquoted expansion's value); where one it
    splits has a blank, the tuple of words bash makes of it at IFS's default (a leading or trailing blank ends a word,
    and makes none)."""
    if not any(s and re.search(r"[ \t\n]", t) for t, s in parts):
        return "".join(t for t, _ in parts)
    words, cur = [], ""
    for t, s in parts:
        first, *rest = re.split(r"[ \t\n]+", t) if s else [t]
        cur += first
        for r in rest:
            words += [cur] if cur else []
            cur = r
    return tuple(words + [cur] if cur else words)


# a name arithmetic assigns: X=, X+= and the like, ++X, X-- (_Parser.arith_sets)
# (a name starts after no word character and is followed by one run of blanks: linear on long names and blank runs)
_ARITH_SETS = re.compile(r"(?<!\w)([A-Za-z_]\w*)\s*(?:\[[^]]*\]\s*)?(?:(?:[-+*/%&|^]|<<|>>)?=(?!=)|\+\+|--)|"
                         r"(?:\+\+|--)\s*([A-Za-z_]\w*)")
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
_PY_CALL = re.compile(_CALL.pattern.replace(r"(\s*\(\s*|\s+)", r"(\s*\(\s*)"))   # (Python calls with parentheses)
# (sed addresses and s/// parts are bounded so a long script cannot make the scan quadratic; the whitespace runs stay
# off `\n`, which is already a start, so a newline-only script is not re-scanned from each one)
_SED_ADDR = r"(?:^|[;\n{}])[^\S\n]*(?:(?:[0-9$,~+!]|/(?:\\.|[^/\\\n]){0,200}/)[^\S\n]*){0,8}"
_SED_E = re.compile(_SED_ADDR + r"e([^\n]*)")
_SED_S_E = re.compile(_SED_ADDR + r"s([^\\\n])(?:\\.|(?!\1).){0,200}\1(?:\\.|(?!\1).){0,200}\1[^;\n}]{0,20}e")
# Python's process spawners by module, read with the code's own imports (`import subprocess as sp`, `from os import
# system`); code that looks a name up at run time can call any, and is scanned with _CALL as other languages are
_PY_SPAWNERS = {"os": r"system|popen|exec[lv]\w*|spawn\w*|posix_spawnp?|startfile",
                "subprocess": r"run|call|check_call|check_output|Popen|getoutput|getstatusoutput",
                "pty": r"spawn", "commands": r"getoutput|getstatusoutput",
                "asyncio": r"create_subprocess_shell|create_subprocess_exec"}
_PY_DYNAMIC = re.compile(r"\b(?:getattr|__import__|importlib|import_module|eval|exec|compile|globals|locals|vars|"
                         r"builtins|__builtins__|__dict__)\b")
_PY_IMPORT = re.compile(r"\bimport\s+([A-Za-z_][\w.]*(?:\s+as\s+\w+)?"
                        r"(?:[ \t]*,[ \t]*[A-Za-z_][\w.]*(?:\s+as\s+\w+)?)*)")
_PY_FROM = re.compile(r"\bfrom\s+(os|subprocess|pty|commands|asyncio)\s+import\s+\(?\s*([\w\s,*]+)")


def _py_calls(code):
    """The pattern _Parser.scan finds Python's process-spawning calls with: each module's spawners under the names the
    code imports it and them as; _CALL itself when the code looks names up at run time (getattr, __import__,
    eval …), with its parentheses."""
    if _PY_DYNAMIC.search(code):
        return _PY_CALL
    names = {m: {m} for m in _PY_SPAWNERS}
    bare = []
    for m in _PY_IMPORT.finditer(code):
        for item in m.group(1).split(","):
            mod, _, alias = item.strip().partition(" as ")
            if mod in names:
                names[mod].add(alias.strip() or mod)
    for m in _PY_FROM.finditer(code):
        for item in m.group(2).replace("\n", " ").split(","):
            name, _, alias = item.strip().partition(" as ")
            if name == "*" or re.fullmatch(_PY_SPAWNERS[m.group(1)], name):
                bare.append(_PY_SPAWNERS[m.group(1)] if name == "*" else re.escape(alias.strip() or name))
    called = [f"(?:{'|'.join(map(re.escape, sorted(n)))})\\.(?:{_PY_SPAWNERS[m]})" for m, n in names.items()] + bare
    return re.compile(r"(?<![\w.])(%s)(\s*\(\s*)" % "|".join(called))


# a string literal's opening in interpreter code: Python's prefixes (r, b, u, f and their pairs) and triple quotes,
# JS's template and Perl's, Ruby's and PHP's command backquote; Perl's q(), qq() and qw() (any bracket or mark)
_OPEN = re.compile(r"""([rRbBuUfF]{0,2})('''|\"\"\"|['"`])""")
_PERL_Q = re.compile(r"q([qw]?)\s*([^\w\s=,;)\]}>])")
_PAIRS = {"(": ")", "[": "]", "{": "}", "<": ">"}
# a literal's body up to its closing quote, on its line (a template's across lines)
_BODY = {q: re.compile(r"(?:\\.|[^\\%s\n])*%s" % (q, q), re.S) for q in "'\""}
_BODY["`"] = re.compile(r"(?:\\.|[^\\`])*`", re.S)
# where a value it interpolates may hold quotes of its own (Ruby's "#{…}", a Python f-string's {…}), up to a close on
# the line (a brace without one is text: the alternatives don't overlap, so a literal that never closes stays linear)
_BODY_BRACED = {(k, q): re.compile(r"(?:\\.|%s|[^\\%s\n%s])*%s" % (alts, q, mark, q))
                for k, mark, alts in (("ruby", "#", r"#\{[^}\n]{0,200}\}|#(?!\{[^}\n]{0,200}\})"),
                                      ("python", "{", r"\{[^}\n]{0,200}\}|\{(?![^}\n]{0,200}\})"))
                for q in "'\""}
# a backslash escape as the C-like languages read one (JS, Perl, Ruby, PHP, Lua, awk): \x and \u forms, an octal run
# (Lua's decimal), a control character (\cX), a backslash-newline, or any one character
_C_ESCAPE = re.compile(r"\\(x\{[0-9A-Fa-f]+\}|x[0-9A-Fa-f]{1,2}|u\{[0-9A-Fa-f]+\}|u[0-9A-Fa-f]{4}|[0-9]{1,3}|c.|.)",
                       re.S)
_C_CONTROLS = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f", "v": "\v", "e": "\x1b", "s": " ",
               "\n": ""}
# where a double-quoted literal takes a value made at run time: JS's ${…}, Ruby's #{…}, Perl's and PHP's $name and
# @name (with a subscript or ->), PHP's {$…}
_INTERPOLATE = {"node": re.compile(r"\$\{[^}]*\}"), "ruby": re.compile(r"#\{(?:[^}]*\}|.*)|#[@$][\w@]+", re.S),
                "perl": re.compile(r"[$@]\{?[A-Za-z_:][\w:]*\}?(?:->)?(?:\[[^\]]*\]|\{[^}]*\})*"),
                "php": re.compile(r"\{\$[^}]*\}|\$[A-Za-z_]\w*(?:->\w+|\[[^\]]*\])*")}
# what a value the code makes at run time reads as in shell text: a variable no line gives (_Parser reads it as any)
UNKNOWN = "${_tk_value}"


def _c_unescape(kind, body):
    """`body` with the escapes of a C-like language decoded (Lua's \\ddd is decimal, the others' octal)."""
    def one(m):
        e = m.group(1)
        if e[0] in "xu" and len(e) > 1:
            v = int(e[1:].strip("{}"), 16)
            return chr(v) if v < 0x110000 else ""
        if e[0].isdigit():
            return chr(int(e) & 0xFF) if kind == "lua" else chr(int(e, 8) & 0xFF) if set(e) <= set("01234567") else e
        if e[0] == "c" and len(e) > 1 and kind in ("perl", "ruby"):
            return chr(ord(e[1].upper()) & 0x1F)
        return _C_CONTROLS.get(e, e)
    return _C_ESCAPE.sub(one, body)


def _py_value(prefix, quote, body):
    """A Python literal's text as Python makes it (bytes read as Latin-1), else `body` as written."""
    if "\\" not in body and "\r" not in body:   # no escape and no newline Python rewrites: the text is the body
        return body
    try:
        v = ast.literal_eval(prefix + quote + body + quote)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return body
    return v.decode("latin-1") if isinstance(v, bytes) else v if isinstance(v, str) else body


def _string_at(kind, code, k, charge):
    """(pieces, end) of the string literal at `k` in code of `kind`: its text with its escapes decoded as the language
    decodes them, and None for each value it interpolates at run time (an f-string's {…}, a template's ${…}, Ruby's
    #{…}, Perl's and PHP's $x in double quotes); None when no literal starts there. `charge(n)`: the parse's budget,
    spent on what a literal that never closes read."""
    if kind == "perl" and (q := _PERL_Q.match(code, k)) and (k == 0 or not (code[k - 1].isalnum() or code[k - 1] in "_$@%")):
        close = _PAIRS.get(q.group(2), q.group(2))
        end = code.find(close, q.end())
        if end < 0:
            charge(len(code) - k)
            return None
        body = code[q.end():end]
        return ([" ".join(body.split())] if q.group(1) == "w" else _decoded(kind, '"' if q.group(1) else "'", body),
                end + 1)
    m = _OPEN.match(code, k)
    if not m:
        return None
    pre, quote = m.group(1).lower(), m.group(2)
    if (pre or len(quote) == 3) and kind != "python" or quote == "`" and kind not in ("node", "perl", "ruby", "php"):
        return None
    if len(quote) == 3:
        end = code.find(quote, m.end())
        if end < 0:
            charge(len(code) - k)
            return None
        body, after = code[m.end():end], end + 3
    else:
        braced = (kind, quote) if kind == "ruby" and quote == '"' or kind == "python" and "f" in pre else None
        b = (_BODY_BRACED[braced] if braced else _BODY[quote]).match(code, m.end())
        if not b:
            nl = code.find("\n", k)
            charge((len(code) if nl < 0 else nl) - k)
            return None
        body, after = code[m.end():b.end() - 1], b.end()
    if kind == "python":
        if "f" not in pre:
            return [_py_value(pre, quote, body)], after
        plain = pre.replace("f", "")
        # (a { that doesn't close here holds a quote of its own: the rest is a value made at run time)
        cut = re.search(r"(?<!\{)\{[^{}]*$", body)
        body, rest = (body[:cut.start()], True) if cut else (body, False)
        return [{"{{": "{", "}}": "}"}.get(p, None if p[:1] == "{" else _py_value(plain, quote, p))
                for p in re.split(r"(\{\{|\}\}|\{[^{}]*\})", body) if p] + [None] * rest, after
    return _decoded(kind, quote, body), after


def _decoded(kind, quote, body):
    """A non-Python literal's pieces (_string_at): single quotes in Perl, Ruby and PHP take only \\\\ and \\'."""
    if quote == "'" and kind in ("perl", "ruby", "php"):
        return [re.sub(r"\\([\\'])", r"\1", body)]
    rx, out, at = _INTERPOLATE.get(kind) if (quote == "`" if kind == "node" else quote != "'") else None, [], 0
    for m in rx.finditer(body) if rx else ():
        out += [_c_unescape(kind, body[at:m.start()]), None]
        at = m.end()
    return out + [_c_unescape(kind, body[at:])]


def _literal_start(kind, code, i, k):
    """Whether a literal may start at `i` (not inside a name: `sub"x"` isn't one); `k`: where the text read starts."""
    if code[i] in "'\"`":
        return True
    return (i == k or not (code[i - 1].isalnum() or code[i - 1] == "_")) and (
        code[i] in "rRbBuUfF" and kind == "python" or code[i] == "q" and kind == "perl")


# a run of characters at which no literal starts, and no quote or backslash, which _arg_text and _literals take in one
# step: a prefix letter after a word character is inside a name (_literal_start; `\w` is isalnum() or `_`), and one
# not before a quote (after at most one more: _OPEN) starts none
_NO_LITERAL = {"python": re.compile(r"""(?:[^'"`\\rRbBuUfF]|(?<=\w)[rRbBuUfF]|[rRbBuUfF](?![rRbBuUfF]*['"`]))+"""),
               "perl": re.compile(r"""(?:[^'"`\\q]|(?<=\w)q)+""")}
_NO_LITERAL_OTHER = re.compile(r"""[^'"`\\]+""")
_NESTING = re.compile(r"[()\[\]{}]")
# a run of characters _skip_value passes over: no quote, closing bracket or comma, nor a stop (each is among `)];` and
# newline)
_VALUE_RUN = re.compile(r"""[^'"`)\]},;\n]+""")


def _skip_value(kind, code, k, stops, charge):
    """Where the argument at `k` ends: the next `,` or stop character outside brackets and string literals (a quote that
    doesn't close on its line skips the line, so the scan stays linear)."""
    depth = 0
    while k < len(code):
        if m := _VALUE_RUN.match(code, k):
            depth += sum(map(m.group().count, "([{"))
            k = m.end()
            continue
        ch = code[k]
        if ch in "'\"`":
            lit = _string_at(kind, code, k, charge)
            k = lit[1] if lit else len(code) if (nl := code.find("\n", k)) < 0 else nl
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth:
            depth -= 1
        elif depth == 0 and (ch == "," or ch in stops):
            return k
        k += 1
    return k


_COMMENT = re.compile(r"[ \t\n]*(?:(?:#|//)[^\n]*)?")


def _blank_end(code, k, stops):
    """Past the blanks and comments (`#` or `//` to the end of its line) at `k`; a newline in `stops` ends there."""
    end = _COMMENT.match(code, k).end()
    return code.index("\n", k) if "\n" in stops and "\n" in code[k:end] else end


_EXECUTABLE = re.compile(r"sys\.executable")
_KEYWORD = re.compile(r"[A-Za-z_]\w*\s*=(?!=)|\*\*|\{")
# a %-format's and .format()'s placeholders (%% and {{ }} are their characters)
_FORMAT = {"%": re.compile(r"%%|%(?:\([^)]*\))?[-#0 +]*(?:\*|\d+)?(?:\.(?:\*|\d+))?[a-zA-Z]"),
           "{": re.compile(r"\{\{|\}\}|\{[^{}]*\}")}
# a value the code takes from the home folder: the home itself (os.path.expanduser's word, Path.home(), $HOME's
# readers in Python, JS, Perl and Ruby)
_HOME_EXPR = re.compile(r"""(?:os\.path\.expanduser|File\.expand_path|(?:pathlib\.)?Path)\(\s*(['"])(~[^'"]*)\1\s*\)"""
                        r"""(?:\.expanduser\(\))?|(?:pathlib\.)?Path\.home\(\)|os\.homedir\(\)|process\.env\.HOME|"""
                        r"""os\.(?:environ\.get|getenv)\(\s*(['"])HOME\3\s*\)|(?:os\.environ|ENV)\[\s*(['"])HOME\4\s*\]|"""
                        r"""\$ENV\{\s*['"]?HOME['"]?\s*\}|Dir\.home|require\(\s*(['"])os\5\s*\)\.homedir\(\)""")


def _arg_text(kind, code, k, end, charge):
    """The argument code[k:end] as text pieces (_string_at's), or None when it holds no literal: its literals at its top
    level decoded and joined (side by side, by +, or Perl's and PHP's .), each other operand among them None (a value
    made at run time), a %-format's or .format()'s placeholders None, a method or subscript on it (`"cmd".strip()`) the
    text itself, and a home folder's reader (_HOME_EXPR) its path. False for text no expression makes, a quote or a
    backslash outside a literal (a call's name found inside a string: `"… call again (…\\'s"`)."""
    pieces, run, depth, fmt, saw, i = [], [], 0, None, False, k
    plain = _NO_LITERAL.get(kind, _NO_LITERAL_OTHER)

    def operand(trailing):   # the text between literals: a joiner, a format, a method, or a value made at run time
        nonlocal fmt, saw
        text = "".join(run).strip()
        run.clear()
        if not text or text == "+" or text == "." and kind in ("perl", "php"):
            return False
        if saw and (text[0] == "%" or text.startswith(".format(")):
            fmt = text[0] if text[0] == "%" else "{"
            return True
        if home := _HOME_EXPR.fullmatch(text.strip("+. ")):
            pieces.append(home.group(2) or "$HOME")
            saw = True
            return False
        if not (saw and trailing and text[0] in ".["):
            pieces.append(None)
        return False
    while i < end:
        c = code[i]
        if _literal_start(kind, code, i, k) and (lit := _string_at(kind, code, i, charge)) is not None:
            if depth:
                run.append(code[i:lit[1]])
            elif operand(False):
                break
            else:
                pieces += lit[0]
                saw = True
            i = lit[1]
            continue
        if c in "'\"`\\":
            return False
        if i > k and (m := plain.match(code, i, end)):
            for b in _NESTING.findall(m.group()):
                depth = depth + 1 if b in "([{" else depth - (depth > 0)
            run.append(m.group())
            i = m.end()
            continue
        depth += c in "([{"
        depth -= depth > 0 and c in ")]}"
        run.append(c)
        i += 1
    else:
        operand(True)
    if not saw:
        return None
    out = []
    for p in pieces:
        at = 0
        for m in _FORMAT[fmt].finditer(p) if fmt and p is not None else ():
            out += [p[at:m.start()], {"%%": "%", "{{": "{", "}}": "}"}.get(m.group())]
            at = m.end()
        out.append(p if p is None or not fmt else p[at:])
    merged = []
    for p in out:
        if p is not None and merged and merged[-1] is not None:
            merged[-1] += p
        elif p != "":
            merged.append(p)
    return tuple(merged) or ("",)


def _text_of(pieces):
    """Shell text from an argument's pieces: a value made at run time is an unknown variable there (UNKNOWN)."""
    return "".join(UNKNOWN if p is None else p for p in pieces)


def _call_args(kind, code, i, paren, charge):
    """A call's arguments from `i` (after its `(`, or its name for one without parentheses: Perl's and Ruby's `system
    "cmd"`, which ends at a `;` or newline), and where they end: each a tuple of text pieces (_arg_text: a literal, or
    an expression holding one; sys.executable is python), a list of those for a list or tuple (an element without a
    literal: a value made at run time, (None,)), or None for any other argument; keyword arguments and an options
    object ({stdio: …}) left out. `charge(n)`: the parse's budget, spent on what a quote that never closes read."""
    items, k, stops = [], i, ")" if paren else ";\n"
    while True:
        k = _blank_end(code, k, stops)
        if k >= len(code) or code[k] in stops:
            return items, k
        start, end = k, _skip_value(kind, code, k, stops, charge)
        item = ...
        if _EXECUTABLE.fullmatch(code[k:end].strip()):
            item = ("python",)
        elif code[k] in "[(" and code[k:end].rstrip()[-1:] in "])":
            item, e, close = [], k + 1, code[k:end].rstrip()[-1]
            while (e := _blank_end(code, e, "")) < end and code[e] != close:
                ee = _skip_value(kind, code, e, close, charge)
                text = code[e:ee].strip()
                item.append(("python",) if _EXECUTABLE.fullmatch(text) else (None,) if text[:1] == "*" else
                            (None,) if (words := _arg_text(kind, code, e, ee, charge)) is None else words)
                e = ee + (code[ee:ee + 1] == ",")
            if False in item:   # (no list: text no expression makes)
                item = None
            elif code[k] == "(" and len(item) == 1 and "," not in code[k:end]:   # (x): an expression, not a tuple
                item = item[0]
        elif not _KEYWORD.match(code, k):
            item = _arg_text(kind, code, k, end, charge) or None
        k = end
        if item is not ...:
            items.append(item)
        k += k < len(code) and code[k] == ","
        if k == start:
            return items, k


def _literals(kind, code, charge):
    """The text of each string literal in `code`, in order (_string_at's pieces as shell text)."""
    k, plain = 0, _NO_LITERAL.get(kind, _NO_LITERAL_OTHER)
    while k < len(code):
        if _literal_start(kind, code, k, 0) and (lit := _string_at(kind, code, k, charge)) is not None:
            yield _text_of(lit[0])
            k = lit[1]
        else:
            k = m.end() if (m := plain.match(code, k)) else k + 1


_STR = re.compile(r"""(['"])((?:\\.|(?!\1)[^\\\n])*)\1""")
_TICK = re.compile(r"`([^`]*)`")
_AWK_STRING = re.compile(r'"((?:\\.|[^"\\\n])*)"')


def _awk_pipes(code):
    """(command, whether a print writes into it) of each pipe in awk code, outside its string literals: "cmd" | getline,
    and print | "cmd" (|& too: gawk's coprocess; not \\| or ||)."""
    spans = list(_AWK_STRING.finditer(code))
    for k, m in enumerate(spans):
        if re.match(r"\s*\|\s*getline\b", code[m.end():m.end() + 64]):
            yield m.group(1), False
        if re.search(r"(?<![\\|])\|&?\s*$", code[spans[k - 1].end() if k else 0:m.start()]):
            yield m.group(1), True


_QX = re.compile(r"(?:%x|\bqx)\s*([({\[<])")
# a delete of a folder and all it holds, by language
_DELETES = {"python": re.compile(r"(?<![\w.])(?:shutil\.)?rmtree\s*\(|\bos\.removedirs\s*\("),
            "node": re.compile(r"\b(?:rmSync|rmdirSync|rm|rmdir|rimraf|removeSync|remove|emptyDirSync)\s*\("),
            "perl": re.compile(r"\b(?:rmtree|remove_tree)\b\s*\(?"),
            "ruby": re.compile(r"\bFileUtils\.(?:rm_rf|rm_r|remove_dir|remove_entry(?:_secure)?|rmtree)\b\s*\(?")}
# git's config keys whose value it runs as a shell command (an alias's only with a leading !), and its value if given
_GIT_RUNS_KEY = (r"alias\.[^=\s]+|core\.(?:editor|pager|sshcommand|fsmonitor|askpass|gitproxy|alternaterefscommand)|"
                 r"sequence\.editor|credential\.(?:[^=\s]*\.)?helper|diff\.(?:external|[^=\s]*\.(?:textconv|command))|"
                 r"(?:diff|merge)tool\.[^=\s]*\.cmd|merge\.[^=\s]*\.driver|filter\.[^=\s]*\.(?:clean|smudge|process)|"
                 r"gpg\.(?:[^=\s]*\.)?program|pager\.[^=\s]*|interactive\.difffilter|sendemail\.[^=\s]*(?:cmd|server)|"
                 r"uploadpack\.packobjectshook|remote\.[^=\s]*\.(?:uploadpack|receivepack)|submodule\.[^=\s]*\.update|"
                 r"web\.browser|(?:browser|man)\.[^=\s]*\.cmd")
_GIT_RUNS = re.compile(rf"(?is)({_GIT_RUNS_KEY})(?:=(.*))?")
# a git config key this parser reads as a git command or a forced push: alias.<name>, remote.<name>.mirror and
# remote.<name>.push; its value if given (KEY=VALUE)
_GIT_CONFIG_KEY = re.compile(r"(?is)(alias)\.([^=\s]+)(?:=(.*))?|remote\..+\.(mirror|push)(?:=(.*))?")
_CONFIG_ENV = re.compile(r"(?i)--config-env=(alias|include)")   # git's options that read config it can't see
_INCLUDE = re.compile(r"(?i)include(if)?\.")
# git's own options that take a value (before its subcommand), and its subcommands' options whose value it runs as a
# shell command (grep's -O only attached: alone, the word after it is the pattern)
_GIT_VALUE_OPTS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env", "--attr-source"}
_GIT_CODE_OPTS = {"rebase": ("-x", "--exec"), "difftool": ("-x", "--extcmd"), "grep": ("-O", "--open-files-in-pager"),
                  "filter-branch": ("--setup", "--tree-filter", "--index-filter", "--env-filter", "--msg-filter",
                                    "--commit-filter", "--parent-filter", "--tag-name-filter"),
                  "clone": ("-u", "--upload-pack"), "fetch": ("--upload-pack",), "pull": ("--upload-pack",),
                  "ls-remote": ("--upload-pack",), "archive": ("--exec",), "push": ("--receive-pack", "--exec"),
                  "send-email": ("--sendmail-cmd", "--to-cmd", "--cc-cmd", "--header-cmd", "--smtp-server")}


def parse(command):
    return analyse(command)[0]


def analyse(command, persistent_target=None, readings=True, work=None, downloads=False, aliases=None):
    """(the commands, the normalised lines, the other words that name something, the files redirections write, the
    code, what else it learned: _learned). `readings`: False reads the line only as written, without its second
    readings (_Parser.simple). `work`: a budget ([characters parsed]) several parses share, MAX_WORK in all.
    `downloads`: the line may download (_may_download), so a function on it isn't read (_Parser.define). `aliases`:
    the aliases the line defines ({name: [values]}), read wherever a command has the name (_Parser.emit): bash may
    parse a use after its definition runs (a trap's action, a later line), so the line is read again with them until
    it defines no more."""
    ctx = {"cmds": [], "lines": [], "refs": [], "written": [], "kept": [], "kept_batches": [], "always_cut": [],
           "cut": [], "steps": [], "redefined": set(), "functions": {}, "calling": [], "read": [], "assigned": [],
           "unresolved": set(), "uncalled": {}, "exported": set(), "ifs_named": _names_ifs(command),
           "downloads": downloads or bool(_DOWNLOADS.search(command)), "decoded": set(), "command_names_mutable": False,
           "pipes": 0, "depth": 0, "work": [0] if work is None else work, "exp": 0,
           "persistent_target": persistent_target, "any_set": False,
           "brace": min(MAX_BRACE, (64 << 10) - len(command)),   # what brace expansions may still add
           "readings": readings, "nested": set(), "aliases": {k: list(v) for k, v in (aliases or {}).items()},
           "subscripts": [], "arith": False, "files": {}, "runs": [], "alias_used": set(), "namerefs": {},
           "arith_names": set(), "unread_values": set(), "code_names": [], "made_files": set(),
           "opaque_values": set(), "joined_values": set(), "reassigned": set(), "export_built": False,
           "stdin_moved": False, "more": False,
           # since an expansion set a variable the parser can't follow, each command is unread (simple); each variable
           # a ${F=w} may have given its word w, and those words (dollar, ways); each value the line gives IFS (None:
           # one it can't read), each literal it gives a variable anywhere, and each command with what its unquoted
           # expansions may expand to and the variables they read whose literals it doesn't know there (_made_text)
           "assigns": False, "defaults": {}, "ifs_values": [], "given": {}, "split_values": [], "exports": set()}
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
                if _subscript_substitution(text):
                    _substitutions(text, ctx, ["arithmetic subscript"])
    top = _Parser(command, ctx, [])
    try:
        top.script()
        if _POSIX_MODE.search(command) and _BASH_ONLY.search(command):
            raise ParseError("an operator only bash has, on a line that may turn on POSIX mode, is not supported")
        for *run, known in list(ctx["runs"]):   # a script the line runs, again now that a heredoc on its line is read
            top.known = known   # (what the line knew where it runs)
            top.read_file(*run)
        # a function the line defines and doesn't call after (a definition after its name's last call too), or
        # exports, runs where the policy doesn't see it (a later call in a shell that persists, any bash child): its
        # body is read as if it ran, and it is held
        held = [(name, body) for name, bodies in ctx["functions"].items()
                for body in (bodies if name in ctx["exported"] else ctx["uncalled"].get(name, []))]
        # and so is an alias it defines and doesn't use (once the line is read with all of them: below)
        held += [(f"alias {name}", value) for name, values in ctx["aliases"].items() if ctx["aliases"] == (aliases or {})
                 and name not in ctx["alias_used"] for value in values]
        for name, body in held:
            first = len(ctx["cmds"])
            p = _Parser(body, ctx, [f"{'' if name.startswith('alias ') else 'function '}{name} (defined)"])
            p.known = {}
            p.script()
            for c in ctx["cmds"][first:first + 1]:
                c["opaque"] = True
        _made_text(ctx)
        _home_readings(ctx)
        _tracekit_copies(ctx)
        # a value the line gives with a substitution in a subscript (x='a[$(cmd)]'), on a line where bash may evaluate
        # one as a name or a number (_Parser.word): bash runs the substitution then
        done = set()
        while ctx["arith"] and (todo := [s for s in ctx["subscripts"] if s not in done]):
            for text, via in todo:
                done.add((text, via))
                _substitutions(text, ctx, [*via, "arithmetic subscript"])
    except ParseError as e:
        e.at = top.i   # where the line stops being readable: the words before it may still be (engine._plain)
        e.cmds = ctx["cmds"]   # and the commands it read before (a substitution in a subscript: let 'x[$(cmd)]')
        raise
    again = None
    if ctx["aliases"] != (aliases or {}):
        again = analyse(command, persistent_target, readings, ctx["work"], downloads, ctx["aliases"])
    elif ctx["functions"] and not ctx["downloads"] and _may_download(ctx):
        again = analyse(command, persistent_target, readings, work, downloads=True, aliases=aliases)
    if again is not None:
        again[5]["more"] |= ctx["more"]   # (what this reading read decided how the line is read again)
        return again
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
            ["".join(code) + command[at:]] + [x for x in ctx["kept"] if x], _learned(ctx))


def _xtrace(argv):
    """Whether set or shopt -o may turn on xtrace (which expands PS4): an x in set's option cluster, -o xtrace, or an
    option the line builds."""
    built = any(re.search(r"[$`]", a) for a in argv[1:])
    if argv[0] == "set":
        return built or any(re.fullmatch(r"[-+][A-Za-z]*x[A-Za-z]*", a) or a == "xtrace" for a in argv[1:])
    return argv[0] == "shopt" and any(re.fullmatch(r"-[a-z]*o[a-z]*", a) for a in argv[1:]) and (
        built or "xtrace" in argv[1:])


def _made_text(ctx):
    """Once the line is read: a variable it gives text it makes and can't read (unread_values: a substitution's output
    that may be crafted, what read reads from such text) or joins parameters it doesn't know (joined_values: `Z=$X$Y`
    of X='a[$', Y='(cmd)]'), where bash evaluates the value as arithmetic or a name (`x=$(printf …); : $((x))`,
    declare -i, ${s:x}: a subscript in it runs) is held; where code bash parses again
    holds it, or a value read, mapped or otherwise not one the parser can name (opaque_values), in any order on the
    line (eval "echo $x"), that command is opaque. A name export or readonly is given from such text (`export $(cat
    .env | xargs)`) doesn't run a subscript (bash's export doesn't evaluate one), but may set PS4, BASH_ENV or a value
    arithmetic reads: held only on a line with a later shell, a script run by its path, xtrace (`set -x`, `shopt -os
    xtrace`, an option the line builds) or arithmetic."""
    if (ctx["unread_values"] | ctx["joined_values"]) & ctx["arith_names"]:
        raise ParseError("a value the line makes, evaluated as arithmetic or a name, is not supported")
    for cmd, names in ctx["code_names"]:
        cmd["opaque"] = cmd["opaque"] or bool(names & (ctx["unread_values"] | ctx["opaque_values"]))
    if ctx["export_built"] and (ctx["arith_names"] or any(
            c["argv"][0] in SHELLS or "/" in c["word"] or _xtrace(c["argv"]) for c in ctx["cmds"])):
        raise ParseError("a name export gives from text the parser can't read, beside a shell, xtrace or arithmetic, "
                         "is not supported")
    # a shopt that changes how bash parses (`#` as text under interactive_comments off, extglob, aliases, POSIX), on a
    # line with code bash reads again: that code is read with bash's usual grammar
    if any(c["via"] for c in ctx["cmds"]) and any(
            c["argv"][0] in ("shopt", "set") and _PARSING_OPTIONS & set(c["argv"][1:]) for c in ctx["cmds"]):
        raise ParseError("a shopt that changes how bash parses, on a line with code bash reads again, is not supported")
    # bash splits an unquoted expansion at IFS's characters (a blank, by default): a command whose unquoted expansion
    # reads a variable the line gives a literal with one only after it (a loop or function may run it first), which
    # it didn't read, is held; and where the line gives IFS a value, one whose values may hold one of its characters
    # or a blank (bash's default may no longer split there), as the parser reads them split at a blank or as one word
    chars = None if None in ctx["ifs_values"] else set(" \t\n" + "".join(ctx["ifs_values"]))
    for cmd, values, names in ctx["split_values"]:
        later = [v for n, k in names for v in ctx["given"].get(n, ())[k:]]
        if any(v and (chars is None or chars & set(v)) for v in later + (values if ctx["ifs_values"] else [])):
            cmd["opaque"], cmd["unread"] = True, cmd.get("unread") or "split"


# a home or root as a word names it: ~ (~user too), $HOME, /home/<u>, /Users/<u>, /root or /
_HOME_OR_ROOT = re.compile(r"(?:~[\w.-]*|\$HOME|\$\{HOME\}|/+(?:home|Users)(?:/+[^/]+)?|/+root)?/*")


def _function_variable(word):
    """Whether `word` is NAME=VALUE with a NAME bash imports from the environment as a function (BASH_FUNC_x%%, an
    older bash's x())."""
    target, eq, _ = word.partition("=")
    return bool(eq) and (target.startswith("BASH_FUNC_") or "%%" in target or "()" in target)


# GitHub's ref endpoint (gh api's path, or in a URL) and its GraphQL endpoint, and a field or body naming force with
# any value but a literal false or 0 (a JSON "force" key, `-F force=$F`, gh's `-F force=@file`, GraphQL's `force:`)
_GIT_REFS = re.compile(r"(?:^|/)repos/[^/\s]+/[^/\s]+/git/refs(?:/|$|[?#])")
_GRAPHQL = re.compile(r"(?:^|/)graphql/?(?:$|[?#])")
_FORCE_FIELD = re.compile(r'(?i)(?:^-f|(?<![\w$-]))force"?\s*(?::=|[:=])\s*(?!"?(?-i:false|0)"?\s*(?:$|[,}&)]))')
# the options that give an API call's body, per program: from a file or input, a field (only its name is read: a
# value is that field's alone) or data read whole; HTTPie's and xh's (any other program's) items are fields too
_BODY_OPTIONS = {"gh": {"--input": "file", "-f": "field", "-F": "field", "--field": "field", "--raw-field": "field"},
                 "curl": {"-T": "file", "--upload-file": "file", "-d": "data", "--data": "data", "--data-ascii": "data",
                          "--data-binary": "data", "--data-raw": "data", "--data-urlencode": "data", "--json": "data"},
                 "wget": {"--post-file": "file", "--body-file": "file", "--post-data": "data", "--body-data": "data"}}
_CURL_FLAGS = "012346aBfgGhiIjJklLMnNOpqRsSvVZ#:"   # curl's short options with no value (`-sd @f` is -s -d @f)


def _ref_update(name, args):
    """How an API call (gh api, curl, wget, HTTPie, xh) updates a GitHub ref: "force" with a field or body naming force
    (any value but a literal false or 0) to /repos/<owner>/<repo>/git/refs/…, or in a GraphQL updateRef or updateRefs;
    "unread" for a call to a ref with a body the parser can't read (_unread_body), which may force; else None. A PATCH
    without force only fast-forwards the ref, as a plain push does.
    lean: a GraphQL query from a file or a variable, and a body from stdin through a pipe or redirect (`… | http PATCH
    …`), aren't read; read them if an agent sends one"""
    refs = any(_GIT_REFS.search(a) for a in args)
    if not refs and not (any(_GRAPHQL.search(a) for a in args) and any(re.search(r"updateRefs?\b", a) for a in args)):
        return None
    if any(_FORCE_FIELD.search(a) for a in args):
        return "force"
    return "unread" if refs and _unread_body(name, args) else None


def _unread_body(name, args):
    """Whether an API call's body is one the parser can't read: from a file or input (gh's --input, curl's -T or
    `-d @f`, wget's --body-file) or built by an expansion (curl's or wget's data, `-d "$B"`; a gh, HTTPie or xh field's
    name, `-F "$K=true"`)."""
    options = _BODY_OPTIONS.get(name, {"--raw": "data"})
    for i, a in enumerate(args):
        opt, value = a, args[i + 1] if i + 1 < len(args) else ""
        if a.startswith("--"):
            opt, eq, attached = a.partition("=")
            value = attached if eq else value
        elif a.startswith("-") and len(a) > 2:   # a short option's value attached (-d@f), after curl's flags (-sd)
            a = "-" + (a[1:].lstrip(_CURL_FLAGS) if name == "curl" else a[1:])
            opt, value = a[:2], a[2:] or value
        elif name not in _BODY_OPTIONS and "=" in a:   # an HTTPie or xh item: a field (a header's name has a colon)
            opt, value = "field", a.partition("=")[0].removesuffix(":")
            if ":" in value:
                continue
        how = "field" if opt == "field" else options.get(opt)
        if how == "file" or how == "data" and (value.startswith("@") or re.search(r"[$`]", value)) or \
                how == "field" and re.search(r"[$`]", value.partition("=")[0]):
            return True
    return False


def _copy_operands(args):
    """cp's, ln's, install's or mv's possible sources and destinations. Each option is read both ways, with a value
    (GNU's `--sparse X` or `--suf X`, after the operands too) and without (BSD's `install -S`), so a word after one may
    be either; none with -t (GNU's --target-directory, abbreviated too; not the value of a letter before it that takes
    one in GNU's or BSD's tools: `-Stk`), whose copies keep their sources' names."""
    ops, value = [], False   # (each operand, whether it may be an option's value)
    for i, a in enumerate(args):
        if a == "--":
            ops += [(w, False) for w in args[i + 1:]]
            break
        if a.startswith("-") and a != "-":
            if re.match(r"-[^-SmogBfDhlMNTt]*t", a) or a.startswith("--t") and "--target-directory".startswith(
                    a.partition("=")[0]):
                return [], []
            value = "=" not in a
            continue
        ops.append((a, value))
        value = False
    if len(ops) < 2:
        return [], []
    last = max(k for k, (_, v) in enumerate(ops) if not v or k == 0)   # the destination, if each value is one
    return [w for w, _ in ops[:-1]], [w for w, _ in ops[last:]]


def _base(path):
    """The name a path's last part gives: //tmp/tk, ./tk and sub/tk/ are all tk."""
    return posixpath.basename(posixpath.normpath(path))


def _tracekit_copies(ctx):
    """A path a cp, ln, install or mv on the line makes of Tracekit's entry point (the console script, the package or
    its __main__.py or cli.py) or of a source the parser can't name (an expansion, a substitution or a pattern: it may
    be Tracekit's, `$(command -v tracekit)`, /usr/local/bin/trace?it), run by any path with that name (a copy's
    folder is not followed: //tmp/tk, a relative tk run as /abs/tk, sub/tk after a cd), or by python as a script or a
    module (`python -m tk` of tk.py), is read as the tracekit command too (TK-D012), wherever on the line.
    lean: a copy an earlier call made is read by its own name; TK-D012's comment and docs/limits.md say so"""
    made = set()
    for c in ctx["cmds"]:
        if c["argv"][0] in ("cp", "ln", "install", "mv"):
            sources, dests = _copy_operands(c["argv"][1:])
            if any(_TRACEKIT_SCRIPT.fullmatch(s) or re.search(r"[$`*?[]", s) for s in sources):
                made |= {_base(d) for d in dests}
    if not made:
        return
    for c in list(ctx["cmds"]):
        run = ["tracekit", *c["argv"][1:]] if c.get("word") and _base(c["word"]) in made else \
            _python_runs(c["argv"][1:], made) if _kind(c["argv"][0]) == "python" else None
        if run is not None:
            ctx["cmds"].append(dict(c, argv=run, via=c["via"] + [c["argv"][0]]))


def _home_readings(ctx):
    """Each recursive rm the line runs, read again where its operands name a home or root another way: a relative one
    after a cd or pushd there (`cd && rm -rf *`), one through a link the line made there (`ln -s ~ h; rm -rf h/*`) and
    the words echo or printf pipes into xargs (`echo ~ | xargs rm -rf`), so TK-D004 reads them as that home or root.
    lean: in the line's order, whatever subshell or branch the cd is in; a cd elsewhere (or one it can't name) ends it"""
    where, links, printed = None, {}, {}
    for c in list(ctx["cmds"]):
        argv = c["argv"]
        ops = [a for a in argv[1:] if not a.startswith("-")]
        if argv[0] in ("cd", "pushd"):
            where = "~" if not ops else ops[0] if ops[0] and _HOME_OR_ROOT.fullmatch(ops[0]) else None
        elif argv[0] == "ln" and len(ops) > 1 and _HOME_OR_ROOT.fullmatch(ops[0]) and any(
                re.fullmatch(r"-\w*s\w*|--symbolic", a) for a in argv[1:]):
            links[ops[-1].rstrip("/")] = ops[0]
        elif argv[0] in ("echo", "printf") and ops:
            printed[c["pipeline"]] = (c.get("stage", 0), ops)
        if c["via"][-1:] == ["xargs"] and c["pipeline"] in printed and printed[c["pipeline"]][0] < c.get("stage", 0):
            argv = argv + printed[c["pipeline"]][1]
        if argv[0] != "rm" or not any(re.fullmatch(r"-\w*[rR]\w*|--recursive", a) for a in argv[1:]):
            continue
        read = [argv[0]]
        for a in argv[1:]:
            head, slash, rest = a.partition("/")
            if not a.startswith("-") and head in links and slash:
                a = links[head].rstrip("/") + "/" + rest
            elif a and not a.startswith(("-", "/", "~", "$")) and where is not None:   # (rm '' removes nothing)
                a = where.rstrip("/") + "/" + a
            read.append(a)
        if read != c["argv"]:
            ctx["cmds"].append({**c, "argv": read, "via": c["via"] + ["read at home"]})


def hidden_commands(cmds, refs):
    """The texts an argument may run as a shell command, for the engine to read (Engine.decide): each word of a command
    with a blank in it, outside its data words (data_words; a search's words, _searches; echo's, printf's and a jq
    filter's text), the words of a program whose code the parser reads itself (a shell's, an interpreter's, eval's,
    git's) and a word holding a substitution (which it read), and each assignment's value; each also from after each
    of its first four `=` that ends a name or option (`--eval=…`, `exec=…`, `ProxyCommand=…`), without a leading `!`
    or `|` (vim's -c '!…', LESSOPEN's '|…'); the engine reads each also without its first word (gdb's 'shell …',
    expect's 'spawn …', osascript's 'do shell script …').
    lean: a command in one word with no blank (`man -P reboot`) isn't read; read it if one turns up"""
    words = []
    for c in cmds:
        argv = c["argv"]
        if argv[0] in SHELLS or argv[0] in _DATA_COMMANDS or argv[0] in _READS_ITS_CODE or argv[0] in DASH_C or \
                _kind(argv[0]) or _searches(argv) or c["via"][-1:] == ["read at home"]:
            continue
        data = data_words(argv) | set(c.get("data_words", ()))
        words += [w for i, w in enumerate(argv) if i and i not in data]
    words += [r for r in refs if _ASSIGN.match(r)]
    out = []
    for w in dict.fromkeys(w for w in words if _BLANK.search(w) and not _SUBSTITUTION.search(w)):
        texts, at = [w], 0
        while len(texts) < 5 and (m := _NAMED.match(w, at)):
            at = m.end()
            texts.append(w[at:])
        for t in texts:
            out.append(t.lstrip(" \t\n!|"))
    return [t for t in dict.fromkeys(out) if _BLANK.search(t.strip())]


_BLANK = re.compile(r"[ \t\n]")
# the `=` of a name or option before a value, from the word's start or the last such `=` (`--a=exec=cmd`): four
_NAMED = re.compile(r"[^\s=]*=")
# programs whose words the parser reads as code itself (emit): their arguments are read exactly
_READS_ITS_CODE = {"eval", "watch", "parallel", "sg", "nix-shell", "git", "ssh", "trap", "alias", "compgen"}
# commands whose words are text they print or a pattern they match (TK-D012's and the like's data, never a command)
_DATA_COMMANDS = {"echo", "printf", "jq", "yq", "gojq", "jaq"}


def _searches(argv):
    """Whether a command only searches: grep, rg, ag, ack and their kin (rg without --pre, which runs a command on each
    file), or git grep, whose words are patterns and files (its -O, which runs a pager, is read as code)."""
    if argv[0] == "git":
        sub = _git_sub(argv[1:])
        return sub is not None and argv[1 + sub] == "grep"
    return argv[0] in ("grep", "egrep", "fgrep", "zgrep", "rg", "ag", "ack", "pgrep") and not any(
        a == "--pre" or a.startswith("--pre=") for a in argv[1:])


def charge(work, n):
    """Spend `n` of a parse's budget (analyse's `work`), which the engine's reading of the parse shares: ParseError past
    MAX_WORK."""
    work[0] += n
    if work[0] > MAX_WORK:
        raise ParseError("too much nested shell text")


def _learned(ctx):
    """What else the parse found: the files redirections read; the assignments that stand alone, (name, the word as
    written), which set a variable of the shell (not of a command's environment); the variables an expansion read
    without a value the line gives it ("*": an indirect ${!x}, which may be any); whether a command may have set any
    variable (or exported one: set, read, declare …), and the names an export of literal names exported; the parse's
    work budget, which the engine's reading of it spends on (charge); whether a second reading (`readings`) read
    anything the line as written doesn't (more: without it, analyse(readings=False) is the same parse)."""
    return {"read": ctx["read"], "assigned": ctx["assigned"], "unresolved": ctx["unresolved"],
            "any_set": ctx["any_set"], "exports": ctx["exports"], "work": ctx["work"], "more": ctx["more"]}


def analyse_argv(argv, readings=True, work=None, downloads=False):
    """analyse() for a command given as an argv list, run without a shell."""
    ctx = {"cmds": [], "lines": [], "refs": [], "written": [], "kept": [], "kept_batches": [], "always_cut": [],
           "cut": [], "steps": [], "redefined": set(), "functions": {}, "calling": [], "read": [], "assigned": [],
           "unresolved": set(), "uncalled": {}, "exported": set(), "ifs_named": False,
           "downloads": downloads or any(_DOWNLOADS.search(a) for a in argv), "decoded": set(),
           "command_names_mutable": False,
           "pipes": 1, "depth": 0, "work": [0] if work is None else work, "exp": 0, "any_set": False, "brace": MAX_BRACE,
           "readings": readings, "nested": set(), "aliases": {}, "subscripts": [], "arith": False, "files": {},
           "runs": [], "alias_used": set(), "namerefs": {}, "arith_names": set(), "unread_values": set(),
           "code_names": [], "made_files": set(), "opaque_values": set(), "joined_values": set(), "reassigned": set(), "export_built": False,
           "stdin_moved": False, "more": False, "assigns": False, "defaults": {}, "ifs_values": [], "given": {},
           "split_values": [],
           "exports": set()}
    words = list(argv)
    lines = _lines(words, _programs(words, _Parser("", ctx, []).emit(list(argv), 1, [])))
    _made_text(ctx)
    if ctx["functions"] and not ctx["downloads"] and _may_download(ctx):
        again = analyse_argv(argv, readings, work, downloads=True)
        again[5]["more"] |= ctx["more"]
        return again
    return (ctx["cmds"], [x for x in lines + ctx["lines"] if x], ctx["refs"], ctx["written"],
            [x for x in lines + ctx["kept"] if x], _learned(ctx))


def _may_download(ctx):
    """Whether a parsed line may download (so its functions aren't read: TK-D002 reads its text, where a body comes
    before the download): a command on it is curl or wget, or has the name of a word the line didn't write plainly
    (quotes, an escape or an expansion made it: c''url, $'\\x63url', $X''rl), which may hide one."""
    return any(c["argv"][0] in ("curl", "wget") or c["argv"][0] in ctx["decoded"] for c in ctx["cmds"])


def _git_sub(args):
    """The index in git's `args` of its subcommand, past its own options and their values; None without one."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in _GIT_VALUE_OPTS else 1
    return i if i < len(args) else None


def _git_env_alias(word):
    """The command a `GIT_CONFIG_VALUE_<n>=…` word may give git through the environment (its key may be one git runs:
    an alias's after its !, core.pager's), else None; ParseError for GIT_CONFIG_PARAMETERS, which this parser doesn't
    read."""
    if word.startswith("GIT_CONFIG_PARAMETERS="):
        raise ParseError("git config from GIT_CONFIG_PARAMETERS is not read")
    m = re.fullmatch(r"(?s)GIT_CONFIG_VALUE_\d+=\s*!?(.*)", word)
    return m and m.group(1)


def _sed_prints(script):
    """Whether a sed script only picks and prints lines: with its /pattern/ addresses left out, nothing but line
    numbers, ranges, braces and the commands that read, write and run nothing."""
    return bool(re.fullmatch(r"[\s\d,$~!;{}+pPlqQnNdDhHgGxz=]*", re.sub(r"/(?:[^/\\\n]|\\.)*/[IM]{0,2}", "", script)))


def data_words(argv):
    """Indexes of argv words that are data, not something the command acts on: a git commit or tag message, a log's
    --grep, the pattern a grep-family command searches for (unless -e, -f or --pre is given), a `sed -n` script
    that only picks and prints lines, and the title, body or notes of a GitHub issue, pull request or release."""
    name, i = argv[0], 1
    if name == "gh" and argv[1:2] in (["issue"], ["pr"], ["release"]):
        out = set()
        for j, a in enumerate(argv[2:], 2):
            if a in ("-t", "--title", "-b", "--body", "-n", "--notes", "--subject") and j + 1 < len(argv):
                out.add(j + 1)
            elif a.startswith(("--title=", "--body=", "--notes=", "--subject=")):
                out.add(j)
        return out
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
    return ("$" in text or "`" in text) and bool(_DYNAMIC_CHARACTER.search(_VARIABLE_DIRECTORY.sub("", text)))


_DYNAMIC_CHARACTER = re.compile(r"[$`]")
_VARIABLE_DIRECTORY = re.compile(r"^(\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\})/")


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


_KINDS = re.compile("|".join(f"(?P<{kind}>{rx.pattern})" for kind, rx in KINDS))   # all of KINDS in one search


def _kind(name):
    m = _KINDS.fullmatch(name)
    return m and m.lastgroup


def _takes(a, opts, flags):
    """The words wrapper option `a` may take, itself included: 2 for one its table names as taking a value, 1 for a
    flag, a `--x=v` or a cluster of flags (one ending in an option that takes a value takes the next word too, one with
    its value attached doesn't); (1, 2) for any other, which may be either."""
    if a in opts:
        return (2,)
    if a in flags or a.startswith("--") and "=" in a:
        return (1,)
    if re.fullmatch(r"-[A-Za-z0-9]{2,}", a):
        for k, c in enumerate(a[1:], 2):
            if "-" + c in opts:
                return (1,) if k < len(a) else (2,)
            if "-" + c not in flags:
                return (1, 2)
        return (1,)
    return (1, 2)


def _unwrap(name, args):
    """What a wrapper, or a runner's subcommand (args[0]: `uv run`), may run: each command, one at a time, the reading
    as flags first. An option neither its table nor WRAPPER_FLAGS names may take a value (`strace --user bob cmd`), so
    it is read both ways (_takes), as is a prefix of a long option (GNU's getopt_long and argparse take a unique one:
    `nice --a 3 id`, but a flag's whole name before a longer one's: strace's --summary)."""
    if name in WRAPPERS:
        opts, positional = WRAPPERS[name]
    else:
        _, opts, positional = RUNNERS[name]
        args = args[1:]
        if positional == "--":
            yield args[args.index("--") + 1:] if "--" in args else []
            return
    # GNU env takes any word with a = for an assignment (`=`, `=x`), also after --; bash's time keyword its assignments
    assigns = (lambda a: "=" in a) if name == "env" else _ASSIGN.match
    starts, todo, seen = [], [0], set()
    while todo:   # each word a command may start at (the flag reading first), each position read once
        i = todo.pop()
        if i in seen:
            continue
        seen.add(i)
        a = args[i] if i < len(args) else None
        if a == "--":
            i += 1
            while name in ("env", "time") and i < len(args) and assigns(args[i]):
                i += 1
            starts.append(i)
        elif a is None or name == "command" and a in ("-v", "-V"):   # the end, or a lookup, not a run
            starts.append(None)
        elif a.startswith("-"):   # a bare `-` too (env - cmd: an empty environment)
            todo += [i + n for n in reversed(_takes(a, opts, WRAPPER_FLAGS.get(name, ())))]
        elif assigns(a) or name == "hatch" and a.startswith("+"):   # hatch run's +var=… matrix selection
            todo.append(i + 1)
        else:
            starts.append(i)
    for i in dict.fromkeys(starts):   # one at a time: the caller charges each before the next is copied
        inner = [] if i is None else args[i + positional:]
        if name == "hatch" and inner:   # hatch run [ENV:]ARGS: the environment it runs the command in
            inner = [inner[0].split(":", 1)[-1]] + inner[1:]
        yield inner


def _shell_mode(args):
    """('c', script) for sh -c, ('stdin', None) when the shell reads its script from stdin (or a stream such as
    /dev/stdin or <( ), or -c without a script, as xargs bash -c runs it), else (None, its script file). Options after
    -c are skipped as the shell does: the script is the first operand."""
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
    if "s" in flags or i >= len(args) or _stream(args[i]):
        return "stdin", None
    return None, args[i]   # a script file


def _interactive(args):
    """Whether a shell given `args` starts interactive, and so reads ENV: -i among its options (also bundled, -ic),
    or zsh's -o interactive and --interactive."""
    i = 0
    while i < len(args) and args[i][:1] in ("-", "+") and args[i] not in ("-", "--"):
        a = args[i]
        named = args[i + 1] if a in SHELL_VALUE_OPTS and i + 1 < len(args) else a
        if re.match(r"-[^-]*i", a) or a[0] == "-" and re.sub(r"[-_]", "", named).lower() == "interactive":
            return True
        i += 2 if a in SHELL_VALUE_OPTS else 1
    return False


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
    """env -S: env's arguments with the string it splits in its place, as the words env reads again (its options,
    assignments and the command); None without -S. Unreadable (ParseError): a string with a backslash, $ or # (env's
    own escapes, variables and comments) or quotes that don't close."""
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] != "--":
        a = args[i]
        if a == "--split-string" or re.fullmatch(r"-[iv0]*S", a):
            text, rest = (args[i + 1] if i + 1 < len(args) else ""), args[i + 2:]
        elif a.startswith("--split-string="):
            text, rest = a[15:], args[i + 1:]
        elif re.fullmatch(r"-[iv0]*S.+", a, re.S):
            text, rest = a[a.index("S") + 1:], args[i + 1:]
        else:
            i += 2 if a in WRAPPERS["env"][0] else 1
            continue
        # lean: env's escapes, ${NAME} and # comments are not read; held until real commands use them
        if re.search(r"[\\$#]", text):
            raise ParseError("env -S with a backslash, $ or # is not supported")
        try:
            words = shlex.split(text)
        except ValueError as e:
            raise ParseError(f"env -S: {e}") from None
        flags = re.match(r"-([iv0]*)", a).group(1)
        return args[:i] + (["-" + flags] if flags else []) + words + rest
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


_SSH_COMMAND_OPTION = re.compile(r"(?is)\s*(?:proxy|local|knownhosts|remote)command\s*[=\s]\s*(.*)")


def _ssh_option_commands(args):
    """The commands ssh, scp or sftp's -o options give (ProxyCommand, LocalCommand, KnownHostsCommand, RemoteCommand:
    -o 'Key value', -oKey=value)."""
    for i, a in enumerate(args):
        value = args[i + 1] if a == "-o" and i + 1 < len(args) else a[2:] if a.startswith("-o") and len(a) > 2 else None
        if value is not None and (m := _SSH_COMMAND_OPTION.fullmatch(value)):
            yield m.group(1)


def _rsync_shells(args):
    """The remote shell commands rsync runs on this machine: -e VALUE (in a cluster too: -avze VALUE, -essh) and
    --rsh[=]VALUE."""
    for i, a in enumerate(args):
        if a == "--":
            return
        if a == "--rsh" or re.fullmatch(r"-[A-Za-z]*e", a):
            if i + 1 < len(args):
                yield args[i + 1]
        elif a.startswith("--rsh="):
            yield a[6:]
        elif m := re.fullmatch(r"(?s)-[A-Za-z]*?e(.+)", a):
            if not a.startswith("--"):
                yield m.group(1)


_VARIABLE_NAME = re.compile(r"\$\{?([A-Za-z_]\w*)")
# an expansion with an operator the parser reads as written: not a default, alternate or replacement (${X:-w}, ${X+w},
# ${X/a/b}), nor ${X} or ${#X}
_UNREAD_OPERATOR = re.compile(r"\$\{(?:!|[A-Za-z_]\w*(?!\w|:?[-=+?]|/|\})|(?:[0-9]+|[@*])(?![0-9]|:?[-=+?]|/|\}))")
_COVERAGE_VALUE_OPTS = {"--rcfile", "--source", "--omit", "--include", "--context", "--concurrency", "--data-file",
                        "--debug"}


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
        if re.match(r"-[A-Za-z]", a):
            for j, ch in enumerate(re.match(r"-([A-Za-z]*)", a).group(1)):
                if ch in flags:   # code attached to its flag (-c"..." is the word -c...), else the next word
                    return a[j + 2:] or (args[i + 1] if i + 1 < len(args) else None)
                if ch in _VALUED[kind]:   # an option whose value is the rest of the word (-Mmodule, -rlib)
                    break
    return None


# each interpreter's options that take the rest of their word as their value
_VALUED = {"python": "WXm", "node": "r", "perl": "MmIxdD", "ruby": "rIxCEFKT", "php": "dcz", "lua": "l"}


def _loaded(kind, args):
    """The code an interpreter's options other than its code flag load, before its script: (`code`, perl's -M or -m
    value, `use X;…`), (`module`, a module node's --import, --require, -r or --loader, or ruby's -r, names), (`held`,
    python's -X presite=, a module it imports first)."""
    for i, a in enumerate(args):
        if a == "--" or not a.startswith("-"):
            return
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if kind == "perl" and re.match(r"-[mM].", a, re.S):
            yield "code", a[2:].lstrip("-")
        elif kind == "node" and a in ("--import", "--require", "-r", "--loader", "--experimental-loader"):
            yield "module", nxt
        elif kind == "node" and a.startswith(("--import=", "--require=", "--loader=", "--experimental-loader=")):
            yield "module", a.split("=", 1)[1]
        elif kind == "ruby" and (a == "-r" or re.match(r"-r.", a, re.S)):
            yield "module", a[2:] or nxt
        elif kind == "python" and (a == "-X" and nxt.startswith("presite") or a.startswith("-Xpresite")):
            yield "held", nxt


def _data_url(url):
    """The text a data: URL holds (base64 or percent-encoded)."""
    head, _, data = url.partition(",")
    if head.endswith(";base64"):
        try:
            return base64.b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "replace")
        except ValueError:
            return ""
    return urllib.parse.unquote(data)


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


def _stream_name(path):
    """Whether a program's file operand is its stdin: `-` or a stream (_stream)."""
    return path == "-" or _stream(path)


def _program_files(args):
    """The files awk's, sed's or make's -f (--file, --makefile; attached too: -f-, --file=x) names."""
    out = []
    for i, a in enumerate(args):
        if a in ("-f", "--file", "--makefile") and i + 1 < len(args):
            out.append(args[i + 1])
        elif m := re.fullmatch(r"(?s)--(?:file|makefile)=(.*)|-[A-Za-z]*f(.+)", a):
            out.append(m.group(1) if m.group(1) is not None else m.group(2))
    return out


def _reads_stdin(kind, args):
    """An interpreter with no program on its command line reads it from stdin, as one given a stream for its script
    does (python3 /dev/stdin, perl -, awk -f -, sed -f /dev/fd/0)."""
    if kind in ("awk", "sed"):
        return any(_stream_name(f) for f in _program_files(args))
    if _code_arg(kind, args) is not None:
        return False
    i = 0
    while i < len(args):
        a = args[i]
        if _stream_name(a):
            return True
        if a == "--":
            return i + 1 >= len(args) or _stream_name(args[i + 1])
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


_PRINTF_SPEC = re.compile(r"%%|%[-+ #0-9.]*[a-zA-Z]")


def _printf(args):
    """What printf prints given `args`: its format, escapes decoded (_ansi_c), with each %s given the next argument as
    it is and each %b with its escapes decoded (_echo_e, whose \\c ends the output), again while arguments remain;
    nothing for -v, which sets a variable. None for any other conversion (a width or precision, %c, %q, %(…)T …),
    whose output this doesn't model."""
    args = args[1:] if args[:1] == ["--"] else args
    if not args or args[0].startswith("-v"):
        return ""
    pieces, rest, out, used = re.split(f"({_PRINTF_SPEC.pattern})", args[0]), args[1:], [], 0
    if any(p not in ("%%", "%s", "%b") for p in pieces[1::2]):
        return None
    # (\c is no escape of a format: bash's printf prints it as written, and goes on)
    pieces[::2] = (_ansi_c(re.sub(r"\\(.)", lambda m: "\\\\c" if m.group(1) == "c" else m.group(), p, flags=re.S))
                   for p in pieces[::2])
    while True:
        for k, p in enumerate(pieces):
            if k % 2 == 0 or p == "%%":
                out.append(p if k % 2 == 0 else "%")
                continue
            arg, used = rest[used] if used < len(rest) else "", used + 1
            text, stop = (arg, False) if p == "%s" else _echo_e(arg)
            out.append(text)
            if stop:
                return "".join(out)
        if used >= len(rest) or len(pieces) == 1 or set(pieces[1::2]) == {"%%"}:
            return "".join(out)


_ECHO_ESCAPE = re.compile(r"\\(0[0-7]{0,3}|c|[1-7])|" + _ANSI_ESCAPE.pattern, re.S)


def _echo_e(text):
    """(What echo -e, sh's echo and printf's %b make of text, whether it ends the output there): _ansi_c's escapes,
    but an octal one is \\0 and up to three more digits (\\1 to \\7 stay as written, as bash's strtrans.c keeps them
    for echo), and \\c ends the output."""
    out, at = [], 0
    for m in _ECHO_ESCAPE.finditer(text):
        out.append(text[at:m.start()])
        at = m.end()
        if m.group(1) == "c":
            return "".join(out), True
        out.append(_ansi_c(m.group()) if not m.group(1) else m.group() if m.group(1) in "1234567" else
                   chr(int(m.group(1)[1:] or "0", 8) & 0xFF))
    return "".join(out) + text[at:], False


_SUBSTITUTION = re.compile(r"\$\(|`")


def _substitutions(text, ctx, via):
    """Read each command substitution in `text` (a `$(` or backtick), as bash runs them when it evaluates the text as
    an arithmetic subscript."""
    pos = 0
    while match := _SUBSTITUTION.search(text, pos):
        parser = _Parser(text, ctx, via)
        parser.i = match.start()
        if text.startswith("$(", parser.i):
            parser.dollar(False)
        else:
            parser.backtick()
        pos = parser.i


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


# the patterns _Parser's word(), dollar(), unsafe() and emit() match most often, compiled once
_PARAMETER = re.compile(r"\$\{?([A-Za-z_]\w*|[0-9@*])")
_VARIABLE = re.compile(r"[A-Za-z_]\w*")
_INDIRECT = re.compile(r"\$\{!([A-Za-z_]\w*)")
_READ_VARIABLE = re.compile(r"\$\{?(!?)([A-Za-z_][A-Za-z0-9_]*)")
_CHECKED = re.compile(r"(?s)\$\{(\w+):\?.*")
_ALWAYS_EMPTY = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::?\+|:(?![-=?+])[^:{}]*:0+|%%\*|##\*)\}")
_IFS_EXPANSION = re.compile(r"\$\{?IFS(?!\w)")
_PIP = re.compile(r"pip[0-9.]*")


class _Parser:
    def __init__(self, src, ctx, via):
        self.s, self.i, self.ctx, self.via, self.heredocs, self.out, self.progs = src, 0, ctx, via, [], [], []
        self.cwd_changed = False
        self.data = set()   # indexes in self.out whose data words are blanked when their step is cut
        self.data_steps = []
        self.gone = [{} for _ in range(12)]   # each second reading's text of the words in self.out it changes (None: gone)
        self.unwrapped = set()   # emit(): (pipeline, wrapper, what it may run) read where an option may take a value
        # the variables bash expands to a non-empty value here, which no second reading empties: $PWD (bash sets it),
        # one the line gave a literal (`D=build; rm -rf "$D"/`) and a for loop's over literal words, in its body;
        # self.blocks: the compound commands (if, while, until, for, select, { }) the parser is in, each (its keyword,
        # the variables it made known, forgotten at its end); only in a { } group does an assignment surely run before
        # what follows it. Each known one maps to the literals it may hold ([]: not known; IFS: bash's default, which
        # no assignment gives back)
        self.known, self.blocks = {"PWD": [], "IFS": []}, []
        self.list_start = self.closed = 0   # list(): the and-or list being read, a block's opening a pipeline closed
        self.called = False   # simple(): the command calls a function (_Parser.call)
        self.said = {}   # (pipeline, stage) -> the text that stage prints, when the line gives it (simple)
        # word(): the word holds an expansion the parser can't read (unsafe); the variables this shell expands in it
        # (unknown: unsafe's `code` reading of the word, for code bash parses again)
        self.spliced, self.expanded, self.unknown, self.joined = False, frozenset(), False, False
        self.feeding, self.crafted = False, {}   # simple(): its input may be text the line makes; each pipeline's
        # the stdin a command here inherits may be one the line moved: in code bash reads again (eval, sh -c, a
        # function, a script), and (sub) in a substitution of a later pipeline stage or a compound command's (`x |
        # eval "$(cat)"`, `{ …; } < f`); `piped`: simple's command is a later pipeline stage
        self.inherit, self.piped = bool(via), False
        self.line = (0, -1, False)   # line_substitutes': the last line it searched (start, end) and what it found
        self.charge(len(src))

    def charge(self, n):
        charge(self.ctx["work"], n)

    def line_substitutes(self):
        """Whether the line of the text that self.i is on holds a `$(` or a backquote (dollar's arithmetic check),
        each line searched once: searching it again for each `$((` on it was quadratic (a 63 KiB line took 1.75 s)."""
        start, end, found = self.line
        if not start <= self.i < end:
            start, end = self.s.rfind("\n", 0, self.i) + 1, self.s.find("\n", self.i)
            end = len(self.s) if end < 0 else end
            self.charge(end - start)
            found = bool(_LINE_SUBSTITUTION.search(self.s, start, end))
            self.line = start, end, found
        return found

    def unsafe(self, p, made, code=False):
        """Whether expansion `p` (as written) may be text the line makes and the parser can't read: a substitution's
        output where what it runs may make text (`made`, _prints: 2) or a file's bytes (`$(<f)`, `$(0<f)`), an indirect
        name (${!x}), a variable the line gives such text (unread_values), a positional parameter on a line that gives
        such text or a subscript as one ("@": positional). Never a number ($((…)), ${#X}, $?, $#, $$, $!) nor a literal
        the line gives. With `code` (text bash parses again as code: eval's words, sh -c's string, a trap's action, a
        heredoc or herestring a shell reads, a script the line writes), pessimistically: any value but a number, the
        digits a substitution prints (made 0), and a variable or parameter the parser reads as its one literal here
        (literal(): given on this list's straight line, not after a branch, loop, call or declare that may change
        it, nor one bash sets itself; expanded plainly, `$X` or `${X}`, and quoted or a literal bash neither splits
        nor globs: `X='*'; eval echo $X` isn't read)."""
        if p.startswith("$((") or _NUMBER.fullmatch(p):
            return False
        if "$(" in p or "`" in p:
            return made >= 1 if code else made == 2 or bool(_FILE_SUBSTITUTION.match(p))
        m = _PARAMETER.match(p)
        if not m or p.startswith("${!") or m.group(1) in self.ctx["unread_values"]:
            return True
        name = m.group(1)
        if self.known.get(name) and not self.ctx["any_set"]:
            if name == "@":   # a call's literal arguments, each a word ("$@") or split and globbed ($@)
                return code and not (_PLAIN_EXPANSION.fullmatch(p) and (
                    p.quoted or not any(_SPLIT_OR_GLOB.search(a) for a in self.known["@"])))
            return code and self.literal(p) is None
        if not _VARIABLE.fullmatch(name):   # a positional parameter
            return code or "@" in self.ctx["unread_values"]
        return code

    def literal(self, p):
        """The one literal a plain expansion `p` ($X, ${X}, $1) reads as here (word() puts it in the word), or None: a
        variable the parser knows one literal of (not on a line where any may be set, or that names IFS, where bash's
        splitting can't be told, nor one any reading of the line may give another value: reassigned), quoted, or one
        bash neither splits nor globs."""
        m = _PLAIN_VARIABLE.fullmatch(p)
        if not m or self.ctx["any_set"] or self.ctx["ifs_named"] or m.group(1) in self.ctx["reassigned"]:
            return None
        v = self.known.get(m.group(1), ())
        return v[0] if len(v) == 1 and (p.quoted or not _SPLIT_OR_GLOB.search(v[0])) else None

    def ways(self, pieces):
        """Each expansion in `pieces` (text and _Expansions) and the texts it may expand to: its own values
        (_Expansion.values) or, a plain one's, each literal the line gives the variable (literal()'s conditions, a
        loop's words too), as written where the line sets it to a value the parser doesn't know ($PWD), else as written
        or empty; and where it is the variable's value, each word a ${F=w} on the line may have given it (dollar), and,
        of one it doesn't know here, each literal the line gave it (maybe(): after a command that may set any, a block,
        a loop, an array's elements; unquoted, bash splits one with a blank). One written alike takes one value
        throughout. None for an unread one."""
        known, out = {} if self.ctx["any_set"] else self.known, {}
        for p in pieces:
            if isinstance(p, _Expansion) and p not in out:
                if p.unread:
                    return None
                name = (m := _PLAIN_VARIABLE.fullmatch(p)) and m.group(1)
                if p.values is not None:
                    out[p] = p.values
                elif name not in known:
                    out[p] = (str(p), "")
                elif known[name] and not self.ctx["ifs_named"] and name not in self.ctx["reassigned"]:
                    out[p] = tuple(known[name])
                else:
                    out[p] = (str(p),)
                if (self.ctx["defaults"] or self.ctx["given"]) and (n := _value_of(p)) and \
                        (more := (*self.ctx["defaults"].get(n, ()), *self.maybe(n, known))):
                    out[p] = tuple(dict.fromkeys(out[p] + more))
        return out

    def maybe(self, name, known):
        """The literals the line has given `name` so far where the parser doesn't know which one it holds here (not
        `known`, or the line names IFS or reassigns it): each may be its value, never dropped (ways(), word())."""
        if known.get(name) and not self.ctx["ifs_named"] and name not in self.ctx["reassigned"]:
            return ()
        return tuple(self.ctx["given"].get(name, ()))

    def array(self):
        """The elements of an array an assignment word gives (X=(…), X+=(…)), from its `(` to its `)`: each literal
        one's value (a [i]= subscript's too), and None for one an expansion, a pattern or a brace makes. $X is
        ${X[0]}, and a subscript may name any element: each may be the variable's value (ways(), maybe()). The flags
        word() sets are left as their elements' together (simple: what the variable may hold)."""
        self.i += 1
        self.out.append("(")
        values, spliced, unknown, joined = [], False, False, False
        while True:
            self.gap()
            if self.peek() == ")":
                self.i += 1
                self.out.append(")")
                self.spliced, self.unknown, self.joined = spliced, unknown or None in values, joined
                return values
            word = self.word()
            if word is None:
                raise ParseError("an array element the parser can't read is not supported")
            text, raw, g, expanded = word
            self.out.append(text)
            spliced, unknown, joined = spliced or self.spliced, unknown or self.unknown, joined or self.joined
            if (sub := re.match(r"\[[^]$`]*\]\+?=", raw)) and not re.search(r"[$`*?[{\\'\"]", raw[sub.end():]):
                values.append(raw[sub.end():])
            else:
                values.append(None if sub or g or expanded else text)

    def combine(self, pieces, ways):
        """Each text `pieces` makes as its expansions take their `ways` (ways()) at once (_assignments), in order, each
        but the first (the text read) charged; None past MAX_READINGS."""
        picks = _assignments(ways)
        if picks is None:
            return None
        self.charge((len(picks) - 1) * sum(map(len, pieces)))
        return list(dict.fromkeys("".join(v[p] if isinstance(p, _Expansion) else p for p in pieces) for v in picks))

    def reassign(self, name):
        """`name` gets a value the parser doesn't follow (${X:=…}, arithmetic, {X}<): not the literal this reading knew,
        nor in any other (a heredoc's body, a prompt's or eval's text is read by a parser of its own) for the rest of
        the line (literal())."""
        self.known.pop(name, None)
        self.ctx["reassigned"].add(name)
        if name == "IFS":
            self.ctx["ifs_values"].append(None)

    def arith_sets(self, text):
        """Arithmetic text assigns the names it does (`$((X=1))`, `${s:i++}`): a number now, not the literal the line
        gave them. One whose name an expansion builds (`$(($Y$W=1))` may set IFS) may be any: every variable and IFS
        are unknown from here. Either, or an expansion in it that assigns or lists names (bash expands those first),
        leaves this command and the rest of the line unread (simple)."""
        for m in _ARITH_SETS.finditer(text):
            self.reassign(next(filter(None, m.groups())))
            self.ctx["assigns"] = True
        if re.search(r"[$`]", text) and re.search(r"(?<![=!<>])=(?!=)|\+\+|--", text):
            self.ctx["any_set"] = self.ctx["ifs_named"] = self.ctx["assigns"] = True
            self.ctx["ifs_values"].append(None)
        if "$" in text and (_ASSIGNS.search(text) or _NAME_LIST.search(text)):
            self.ctx["assigns"] = True

    def positional(self, words):
        """Words the line gives as $1 and the rest (set's operands, a call's, a script's or sh -c's arguments): text it
        makes (`set -- "$(printf …)"; : $(($1))`) makes every positional parameter unread ("@": unsafe, and analyse's
        arithmetic check); a part of a subscript, or a parameter the parser doesn't know, joined ("@": joined_values:
        `set -- 'a[$' '(x)]'; : $(($1$2))`). A whole literal subscript is read as word() reads any."""
        if any(isinstance(w, _Spliced) for w in words):
            self.ctx["unread_values"].add("@")
        if any(re.search(r"[][$`]", w) for w in words):
            self.ctx["joined_values"].add("@")

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

    def close_block(self):
        """The innermost block ends: what it made known is forgotten, and where its and-or list began goes back to
        list() (a block sent to the background runs from its opening)."""
        _, names, opened = self.blocks.pop()
        for name in names:
            self.known.pop(name, None)
        self.closed = min(self.closed, opened)

    def nested(self, text, via, args=()):
        # a new shell sets $PWD and IFS; a trap runs later, where $IFS still splits as it does here; a script given
        # literal `args` has them as $1 to $9 and "$@", as call() gives a function's. Code a shell of another grammar
        # reads (sh, dash, ksh: the nearest shell in `via`) is read as bash's only where it uses no operator bash alone
        # has (`&>` is a background job and a redirection in dash)
        if next((w for v in reversed(via) for w in [v.split(" ", 1)[0]] if w in SHELLS), None) in _POSIX_SHELLS and \
                _BASH_ONLY.search(text):
            raise ParseError("an operator only bash has, in code another shell reads, is not supported")
        known = {k: v for k, v in self.known.items() if k in (("IFS",) if via[-1:] == ["trap"] else ("PWD", "IFS"))}
        if args and not any("$" in a or "`" in a for a in args):
            known.update({str(i): [a] for i, a in enumerate(args[:9], 1)}, **{"@": list(args)})
        self.positional(args)
        key = (text, tuple(via), frozenset(known), tuple(args))
        if key in self.ctx["nested"]:   # the same text read the same way again (each reading's eval): the same commands
            return
        self.ctx["nested"].add(key)
        self.charge(NESTED_COST)
        p = _Parser(text, self.ctx, via)
        p.known = known
        p.script()

    def code(self, cmd, words):
        """The text `words` give as code bash parses again (eval's words, sh -c's script, a trap's action, a git alias):
        one holding a value the parser can't name (unsafe's `code` reading: `eval "echo $(printf …)"`, `eval "$1"`,
        `eval "echo $(< f)"`), or a pattern on a line that makes files (`eval echo *`), makes `cmd` opaque; so does a
        variable in one that the line gives such a value later in its order (analyse: a loop's next turn, a function's
        later call)."""
        if any(isinstance(w, _Spliced) or getattr(w, "unknown", False) or
               getattr(w, "glob", False) and self.ctx["files"] for w in words):   # (a pattern may name a file it made)
            cmd["opaque"] = True
        self.ctx["code_names"].append((cmd, {n for w in words if isinstance(w, _Expanded) for n in w.names}))
        return " ".join(words)

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
            elif s.startswith("\\\n", self.i):
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
        """Commands up to `end`: None (the text's end), ")" or "esac" (a case arm's ;;, ;&, ;;& or the esac)."""
        self.enter()
        arm, start = end == "esac", None   # start: where the commands of the and-or list being read begin
        # a list nested in a pipeline (a subshell, a case arm) leaves the enclosing list's and-or state as it found it
        enclosing = self.list_start, self.closed
        while True:
            self.gap()
            if not self.peek() or self.peek() == ")" or arm and (self.at(";;") or self.at(";&") or
                                                               _ESAC.match(self.s, self.i)):
                break
            start = len(self.ctx["cmds"]) if start is None else start
            self.list_start = self.closed = start
            self.pipeline()
            start = min(start, self.closed)   # a block the pipeline closed: from the and-or list it opened in
            self.blank()
            if self.peek() == "&" and not self.at("&&"):   # the and-or list runs in the background: each command it
                for cmd in self.ctx["cmds"][start:]:      # runs, a block's from its opening, nested ones too
                    cmd["background"] = True
            if not (self.at("&&") or self.at("||")):
                start = None
            self.out.append(self.s[self.i:self.i + 2] if self.at("&&") or self.at("||") else
                            self.peek() if self.peek() in (";", "&") else ";")
            if self.at("&&") or self.at("||"):
                self.i += 2
                self.gap()
                if not self.peek() or self.peek() == ")":
                    raise ParseError("command expected after && or ||")
            elif self.at(";;") or arm and self.at(";&"):
                if not arm:
                    raise ParseError(";; outside a case arm")
                break
            elif self.peek() in (";", "&"):
                self.i += 1
            elif self.peek() not in ("\n", ")", ""):
                raise ParseError(f"unexpected {self.peek()!r}")
        if (self.peek() == ")") != (end == ")"):
            raise ParseError("unmatched )" if end is None else "missing )")
        self.i += end == ")"
        self.list_start, self.closed = enclosing
        self.leave()

    def case(self):
        """`case WORD in [(]PATTERN[|PATTERN]...) LIST ;; ... esac`, after its `case`: the word and the patterns are
        expanded (a substitution in them runs) and every arm is read, as each branch of an if is; what an arm assigns is
        not known after it (each arm is a block that may not run)."""
        self.enter()
        self.blank()
        if self.word() is None:
            raise ParseError("case without a word")
        self.gap()
        if (self.word() or (None, None))[1] != "in":
            raise ParseError("case without in")
        self.blocks.append(("case", [], self.list_start))
        while True:
            self.gap()
            if _ESAC.match(self.s, self.i):
                self.i += 4
                break
            self.i += self.peek() == "("
            while True:
                self.blank()
                if self.word() is None:
                    raise ParseError("a case pattern expected")
                self.blank()
                if self.peek() not in ("|", ")"):
                    raise ParseError("a case pattern without )")
                self.i += 1
                if self.s[self.i - 1] == ")":
                    break
            self.list("esac")
            self.i += next((len(op) for op in (";;&", ";;", ";&") if self.at(op)), 0)
        self.close_block()
        self.leave()

    def define(self, name, at):
        """A function definition: `name() BODY` or `function name [()] BODY`, BODY a { } or ( ) group, read to its end
        without running it (its commands run where it is called, _Parser.call). Each definition is kept: a call reads
        every body the name was given on the line, as a condition may decide which one stands. A function named as a
        copying command (echo, cat …) is no longer one that only copies text (track_redefinitions)."""
        if name in _UNREAD_FUNCTIONS:
            raise ParseError(f"a function named {name} is not supported")
        if self.ctx["downloads"]:   # held as 1.5.3 held every function: TK-D002 reads the line's text, body before call
            e = ParseError("a function on a line that downloads is not read")
            e.cause = "download"
            raise e
        self.i = at
        self.gap()
        if self.peek() not in ("{", "("):
            raise ParseError("a function body that isn't a { } or ( ) group is not supported")
        start = self.i
        # a parser of its own, whose commands, lines and state go nowhere: the body only runs where it is called
        dry = _Parser(self.s, {**self.ctx, "cmds": [], "lines": [], "refs": [], "written": [], "kept": [],
                               "kept_batches": [], "always_cut": [], "cut": [], "steps": [], "nested": set(),
                               "redefined": set(self.ctx["redefined"]), "functions": dict(self.ctx["functions"]),
                               "uncalled": {}, "calling": [], "work": [0]}, self.via)
        dry.i, dry.known = start, {}
        while True:
            dry.pipeline()
            if not dry.blocks:
                break
            dry.blank()
            dry.i += 2 if dry.at("&&") or dry.at("||") else dry.peek() in (";", "&")
            dry.gap()
            if not dry.peek() or dry.peek() == ")":
                raise ParseError("a function body without its end")
        if dry.heredocs:
            raise ParseError("a heredoc that starts on a function body's last line is not supported")
        self.i = dry.i
        self.charge(self.i - start)
        self.ctx["functions"].setdefault(name, []).append(self.s[start:self.i])
        self.ctx["uncalled"].setdefault(name, []).append(self.s[start:self.i])
        self.ctx["redefined"].add(name)

    def stable(self):
        """The known variables nothing after here may set again (_settings, of the rest of the text and every function
        body): entering a loop, those its later commands may change are no longer known in it, nor after it. Each
        text is read once (ctx's settings); each call costs the budget its known variables and bodies."""
        cache = self.ctx.setdefault("settings", {})
        bodies = [b for each in self.ctx["functions"].values() for b in each]
        self.charge(len(self.known) + len(bodies))
        here = cache[self.s] if self.s in cache else cache.setdefault(self.s, _settings(self.s))
        inside = [cache[b] if b in cache else cache.setdefault(b, _settings(b)) for b in bodies]
        if here[1] >= self.i or re.match(r"\.\s", self.s[self.i:self.i + 2]) or any(b[1] >= 0 for b in inside):
            return {}
        names = set().union(*(b[0] for b in inside))
        positional = here[2] >= self.i or any(b[2] >= 0 for b in inside)
        return {k: v for k, v in self.known.items() if k not in ("PWD", "IFS") and v and not (
            positional if k.isdigit() or k == "@" else here[0].get(k, -1) >= self.i or k in names)}

    def call(self, name, args, via, cmd):
        """Read each body of function `name` as it runs when called with `args`: $1 to $9, "$@", $* and "$*" are the
        arguments when the call gives literals (else unknown, so a body that runs one is held), the caller's known
        variables are the body's. A call within its own body (recursion) or past 8 calls deep is unreadable (opaque)."""
        calling = self.ctx["calling"]
        if "trap" not in via:   # a trap's call runs later, when the shell (which may persist) may hold another body
            self.ctx["uncalled"].pop(name, None)
        if name in calling or len(calling) >= 8:
            cmd["opaque"] = True
            return
        known = {} if self.ctx["any_set"] else {k: v for k, v in self.known.items() if not (k.isdigit() or k == "@")}
        if not any("$" in a or "`" in a for a in args):
            known.update({str(i): [a] for i, a in enumerate(args[:9], 1)}, **{"@": list(args)})
        self.positional(args)
        calling.append(name)
        try:
            for body in self.ctx["functions"][name]:
                key = ("function", body, tuple(via), tuple(sorted((k, tuple(v)) for k, v in known.items())))
                if key not in self.ctx["nested"]:
                    self.ctx["nested"].add(key)
                    p = _Parser(body, self.ctx, via + ["function " + name])
                    p.known = dict(known)
                    p.script()
        finally:
            calling.pop()
        self.called = True

    def pipeline(self):
        self.ctx["pipes"] += 1
        pid, piped, stage = self.ctx["pipes"], False, 0
        while True:
            if not self.simple(pid, piped, stage):
                raise ParseError("command expected")
            piped, stage = True, stage + 1
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

    def simple(self, pid, piped=False, stage=0):
        words, globs, names, strings, docs, idx, spans, here, exps = [], [], [], [], [], [], [], [], []
        first = len(self.ctx["cmds"])   # the commands its substitutions run, then its own, follow
        self.piped = piped
        # per word: .vanish, a pathname pattern, .cut, .slots, .alone, .full, a known variable in it (.given or .slots),
        # .readings
        vanish, patterns, cuts, slots, alones, fulls, givens, reads, parts = [], [], [], [], [], [], [], [], []
        splits = []   # per word: a value of an unquoted expansion in it has a blank (word(): self.splits)
        raws = []   # per word: its source, as written
        outs, ins = [], []   # the files this command's redirections write, and those they read
        into, others = [], []   # of outs, those its stdout goes to, and the rest
        consumed = loop_header = stdin_redirect = stdout_redirect = to_file = self.called = False
        # bash reads a reserved word only where a command starts: after an assignment, a redirection or a word that
        # expands to nothing it is a program (`x= for`, `${X::0} then` run for and then), which is read too, as well as
        # the keyword; `function` there is held, and `f()` isn't a definition
        reserved = True
        dynamic = brace_unread = False   # brace_unread: the command is held (a brace kept as written, a split name, an
        # unquoted IFS it can't split at)
        values, unknown = [], []   # what its words' unquoted expansions may expand to, and the variables they read
        # whose literals the parser doesn't know there (word(): self.values, self.unknown_names)
        unread = False   # a word of it (a redirection's target too) has more readings than MAX_READINGS
        # a herestring holds an expansion the parser can't read (_Spliced), or a value it can't name (unsafe's code);
        # so does a loop's header (header_spliced: the former)
        spliced = unknown_string = header_unknown = header_spliced = header_joined = False
        timed = 0   # how many leading words are an unquoted `time` and its -p or --: bash's keyword, so far
        # an assignment here runs whenever what follows it on the line does: outside compound commands but a { }
        # group, first in its list (not after && or ||, nor a pipeline stage), and no keyword but a { before it
        sure = (not self.blocks or self.blocks[-1][0] == "{") and (self.out[-1] if self.out else ";") in (";", "&", "(")
        assigns, header, assigned = [], [], []   # (name, its literal or None, +=); a loop header's literal words
        # (None: other); (name, the assignment word)
        header_blank = []   # the readings with a blank of the loop header's words an expansion joins

        def untime():   # the words so far only time what follows: read that as the command's start
            nonlocal timed
            if timed and timed == len(words):
                # the program time runs where time is no keyword: past a pipeline's start, or in a shell without one
                shells = [v.split()[0] for v in self.via if v.split()[0] in SHELLS]
                if stage or shells and shells[-1] in ("sh", "dash", "ash", "posh"):
                    self.emit(words[:timed], pid, self.via)
                del words[:], globs[:], names[:], idx[:], spans[:], vanish[:], patterns[:], cuts[:], slots[:], alones[:]
                del fulls[:], givens[:], reads[:], parts[:], splits[:], raws[:]
                timed = 0
        while True:
            self.blank()
            c = self.peek()
            if not c or c in "\n;|)" or (c == "&" and not self.at("&>")):
                break
            consumed = True
            if not words and not loop_header and reserved and (m := _FUNCTION.match(self.s, self.i)):
                self.define(m.group(1) or m.group(2), m.end())
                continue
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
            # a redirection starts with a decimal (_REDIR's \d), {, & or an angle bracket
            m = _REDIR.match(self.s, self.i) if (c in "{&<>" or c.isdecimal()) and not (
                c in "<>" and self.peek(1) == "(") else None
            if m:
                reserved = False   # (`>f function x`: bash runs a program named function)
                if m.group(1)[:1] == "{":   # {X}<f gives X the descriptor's number
                    self.reassign(m.group(1)[1:-1])
                self.i = m.end()
                self.blank()
                start = self.i
                target = self.word()
                if target is None:
                    raise ParseError("redirection without a target")
                exps += self.exps
                brace_unread |= self.unsplit
                dynamic |= bool(re.search(r"[$`]", target[1]))
                self.out += [m.group(0), target[0]]
                if m.group(2) in ("<<", "<<-"):
                    if re.search(r"[$`]", target[1]):   # bash ends it at the word as written, unexpanded
                        raise ParseError("a heredoc delimiter with an expansion is not supported")
                    docs.append({"delim": target[0], "strip": m.group(2) == "<<-", "expand": target[0] == target[1],
                                 "via": self.via, "cmds": [], "data": False, "step": None, "known": dict(self.known)})
                    self.heredocs.append(docs[-1])
                elif m.group(2) == "<<<":
                    strings.append(target[0])
                    if self.ifs:   # bash doesn't split it: IFS's own characters are its text (`sh<<<"I="${IFS}rm …`)
                        strings.append(re.sub(r"\$\{IFS\}|\$IFS(?!\w)", " \t\n", target[0]))
                    spliced |= self.spliced
                    unknown_string |= self.unknown
                    if not target[3]:
                        here.append((len(self.out) - 1, start, self.i))
                else:
                    # the name, and again with its expansions empty (self.cut) and each way they combine
                    unread |= self.readings is None
                    other = [t for t in dict.fromkeys(self.cut + (self.readings or ())) if t and t != target[0]]
                    self.ctx["more"] |= bool(other)
                    named = [target[0]] + other * self.ctx["readings"] + [t for texts in self.fill([self.slots])
                                                                          for t in texts]
                    if self.ifs:   # bash splits an unquoted $IFS's value out of the name: `>${IFS}f` writes f
                        at, was = [start] + [i for span in self.ifs for i in span] + [self.i], self.spliced
                        for a, b in zip(at[::2], at[1::2]):   # each piece, and with its expansions empty
                            if piece := self.relex(self.s[a:b]):
                                other = [t for t in dict.fromkeys(self.cut) if t]
                                self.ctx["more"] |= bool(other)
                                named += [piece[0]] + other * self.ctx["readings"]
                        self.spliced = was
                    made = [c for t in named for c in _unglob(t)] if self.ctx["readings"] and target[2] else []
                    self.ctx["more"] |= bool(made)
                    self.charge(sum(map(len, made)))   # each name its pattern may make
                    named = list(dict.fromkeys(named + made))
                    self.ctx["refs"] += named
                    stdin_redirect |= m.group(2) in ("<", "<&", "<>")
                    writes = m.group(2) not in ("<", "<&") and not (
                        m.group(2) == ">&" and re.fullmatch(r"\d*-?", target[0]))
                    if writes:
                        self.ctx["written"] += named
                        outs += named
                        stdout = m.group(2) in ("&>", "&>>") or \
                            m.group(1) in ("", "1") and m.group(2) in (">", ">>", ">|", ">&")
                        # (a name the line builds from text it can't read, or a pattern, may be any file's: "*")
                        (into if stdout else others).extend((n, m.group(2) in (">>", "&>>")) for n in
                                                            named + ["*"] * bool(target[2] or self.spliced))
                    elif not re.fullmatch(r"\d*-?", target[0]):
                        self.ctx["read"] += named
                    if m.group(2) in ("<", "<&", "<>"):   # a descriptor it duplicates: /dev/fd/N (_stream)
                        ins += ["/dev/fd/" + n for n in named] if m.group(2) == "<&" else named
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
            exps += self.exps
            brace_unread |= self.unsplit
            if raw != text:   # quotes, an escape or an expansion made it: a command of this name may hide its name
                self.ctx["decoded"].add(_lower_name(text.rsplit("/", 1)[-1] or text))
            if raw != self.s[start:self.i] and self.peek() in ("<", ">") and re.fullmatch(r"\d+|\{\w+\}", raw):
                raise ParseError("a backslash-newline inside a redirection is not supported")   # bash reads 2\⏎> as 2>
            self.out.append(text)
            if loop_header:
                # a word whose every expansion is a variable's one known literal (word(): given) is that literal
                header.append(None if g or re.search(r"[$`]", text) or re.search(r"[$`]", raw) and not self.given
                              else text)
                if header[-1] is None and self.readings:   # (a word with a blank an expansion joins: track_values)
                    header_blank += [r for r in self.readings if re.search(r"[ \t\n]", r) and
                                     not any(e in r for e in self.exps)]   # (none of its expansions as written)
                header_unknown |= self.unknown or self.spliced
                header_spliced |= self.spliced
                header_joined |= self.joined
                continue
            if raw == text and (text in KEYWORDS or text in ("for", "select", "case", "function", "coproc")):
                untime()
            if not words and not reserved and raw == text and text in KEYWORDS | {"for", "select", "case"}:
                self.emit([text], pid, self.via)
            if not words and raw == text and text in KEYWORDS:
                sure = text == "{"   # the group's first command
                if text in ("while", "until"):   # its condition and body run again after the body's later commands
                    self.known = self.stable()
                if text in ("if", "while", "until", "{"):
                    self.blocks.append((text, [], self.list_start))
                elif text in ("fi", "done", "}") and self.blocks and self.blocks[-1][0] != "case":   # case() ends its own
                    self.close_block()
                continue
            if not words and raw == text and text in ("for", "select"):
                loop_header = text   # the loop words are not run; `do` starts the body
                continue
            if not words and raw == text and text == "case":
                self.case()
                continue
            if not words and raw == text and text in ("function", "coproc"):
                raise ParseError(f"{text} is not supported")
            if not words and "[" in raw and re.match(r"[A-Za-z_]\w*\[(?![^]]*\])", raw):   # bash: a[ x ]=1 is a word
                raise ParseError("a subscript with a blank where a command starts is not supported")
            # within the word, as bash reads it; after the time keyword too (`time IFS= eval …`, `time x=$(…)`)
            if (not words or timed and timed == len(words)) and (m := _ASSIGN.match(raw)):
                reserved = False
                elements = self.array() if raw.endswith("=") and self.peek() == "(" else None   # X=(…), X+=(…)
                assigns.append((re.match(r"\w+", raw).group(), None if m.group(1) or expanded or elements is not None
                                else text.partition("=")[2], m.group().endswith("+=")))
                self.ctx["refs"].append(text)
                assigned.append((assigns[-1][0], text))
                if expanded:   # (an expansion made its value: env's check, emit)
                    self.ctx.setdefault("expanded_assigned", set()).add(assigns[-1][0])
                self.ctx["command_names_mutable"] |= bool(_COMMAND_NAME_ASSIGN.match(text))
                if (alias := _git_env_alias(text)) is not None:
                    self.nested(alias, self.via + ["git alias"])
                self.ctx["arith"] |= bool(m.group(1))   # bash evaluates the subscript
                if m.group(1):
                    self.arith_sets(m.group(1))
                var, value, plus = assigns[-1]
                if var == "IFS":   # (None: a value the parser can't read; a prefix's too: eval, . and a function use it)
                    self.ctx["ifs_values"].append(None if plus else value)
                if value is not None or elements:
                    self.ctx["given"].setdefault(var, []).extend([value] if elements is None else
                                                                 [v for v in elements if v is not None])
                elif not m.group(1) and self.readings:   # one an expansion joins: each literal reading with a blank
                    self.ctx["given"].setdefault(var, []).extend(   # (bash splits it where X is unquoted: X=" rm"$Y)
                        v for r in self.readings for v in [r.partition("=")[2]]
                        if re.search(r"[ \t\n]", v) and not any(e in v for e in self.exps))
                if self.ctx["namerefs"].get(var, 1) is None:   # the first assignment names its target
                    raise ParseError(f"an assignment through the nameref {var}, which has no target, is not supported")
                # what the variable now holds: text the line makes, or a value the parser can't name; and whether it
                # joins parameters the parser doesn't know (`Z=$X$Y`: arithmetic holds it, analyse's _made_text)
                if self.spliced or self.unknown:
                    self.ctx["unread_values" if self.spliced else "opaque_values"].add(var)
                if self.joined:
                    self.ctx["joined_values"].add(var)
                if var in _CODE_VARIABLES:   # an array (X=(…)) or X+=… is not read
                    self.code_variable(var, None if plus or self.peek() == "(" else value, self.via)
                continue
            values += self.values
            unknown += self.unknown_names
            if timed == len(words) and raw == text and (text == "time" or words and text in ("-p", "--")):
                timed += 1
            else:
                reserved = False
            pieces, ifs = None, self.ifs
            if raw in _ALL_ARGUMENTS and "@" in self.known and not self.ctx["any_set"]:
                # a function's arguments: "$@" is each one, "$*" all of them joined by a space; unquoted, bash splits
                # them, and globs them (one with a pattern character is left unread)
                items = [" ".join(self.known["@"])] if raw in ('"$*"', '"${*}"') else self.known["@"]
                if not raw.startswith('"'):
                    items = None if any(re.search(r"[*?[]", a) for a in items) else \
                        [w for a in items for w in a.split()]
                pieces = None if items is None else [shlex.quote(a) for a in items]
            if pieces is None and "{" in self.bare:   # an unquoted { outside substitutions: maybe a brace expansion
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
                if self.spliced or self.expanded or self.unknown or g:
                    text = (_Spliced if self.spliced else _Expanded)(text)
                    text.names, text.unknown, text.glob, text.joined = self.expanded, self.unknown, bool(g), self.joined
                words.append(text)
                raws.append(raw)
                dynamic |= "$" in raw or "`" in raw
                idx.append(len(self.out) - 1)
                spans.append(None if expanded or pieces is not None else (len(self.out) - 1, start, self.i))
                globs.append(g)
                names.append(g or (expanded and _name_unreadable(text)))
                vanish.append(self.vanish)
                patterns.append(bool(_GLOB.search(self.bare)))
                cuts.append(self.cut)
                reads.append(self.readings)
                splits.append(self.splits)
                parts.append((self.parts, self.ways_))
                slots.append(self.slots)
                alones.append(self.alone)
                fulls.append(self.full or not expanded)
                givens.append(self.given or self.slots is not None)
        # a command whose every expansion is a variable the line gives literals (one each, or a for loop's words) is
        # read in full as bash runs it (word(), fill): a name it builds is no longer unreadable, unless bash would split
        # or glob a value
        if dynamic and all(fulls) and not any(_SPLIT_OR_GLOB.search(v) for s in slots if s for p in s
                                              if isinstance(p, tuple) for v in self.known.get(p[0], ())):
            names = globs[:]
        # but a bare program name a variable gives (X=rm; $X …) only hides that name: it is read and still held, as a
        # name the line builds; a path (PY=.venv/bin/python; $PY …) is read
        names = [n or g and any("/" not in t or not _PLAIN_PATH.fullmatch(t)
                                for t in ([w] if s is None else [x[0] for x in self.fill([s])]))
                 for n, g, w, s in zip(names, givens, words, slots)]
        # an IFS the command is given (IFS= eval …, IFS= . ./f, IFS= f) is the one what it runs in this shell splits and
        # joins with: not bash's default there
        outer = self.known
        if any(name == "IFS" for name, _, _ in assigns):
            self.known = {k: v for k, v in self.known.items() if k != "IFS"}
        # what read, mapfile or a loop is given may be text the line makes (variable_names, track_values): a
        # herestring or heredoc, or what a substitution, process substitution or earlier stage runs makes
        self.feeding = bool(strings or docs) or self.crafted.get(pid, False) or \
            not _reads_only(self.ctx["cmds"][first:], self.ctx)
        cmds = self.emit(words, pid, self.via, any(globs), names) if words else []
        if brace_unread and cmds:
            cmds[0]["opaque"] = True
        if (values or unknown) and cmds:   # held if bash may split them where the parser doesn't (_made_text)
            self.ctx["split_values"].append((cmds[0], values, unknown))
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
        seen, as_written, read = {tuple(words)}, list(cmds), {}
        columns, globbed = list(zip(*cuts)) or [()] * 6, any(patterns)   # columns[k]: each word's cut[k]
        for k in range(12 if (dynamic or globbed) and self.ctx["readings"] else 0):
            key = (columns[k % 6], k > 5 and globbed)
            if key in read:   # the texts of an earlier reading: the same command, and the same line
                self.gone[k].update(read[key])
                continue
            texts = [None if v and not t or k > 5 and p else t   # None: gone
                     for t, v, p in zip(columns[k % 6], vanish, patterns)]
            kept = [i for i, t in enumerate(texts) if t is not None]
            alt = [texts[i] for i in kept]
            read[key] = [(idx[i], t) for i, t in enumerate(texts) if t != words[i]]
            self.ctx["more"] |= bool(read[key])
            self.gone[k].update(read[key])   # and the line (flush)
            if alt and tuple(alt) not in seen and not data:
                seen.add(tuple(alt))
                self.charge(sum(map(len, alt)))   # each reading is read as a command of its own
                more = self.emit(alt, pid, self.via, any(globs),
                                 [names[i] if texts[i] == words[i] else globs[i] or _name_unreadable(texts[i])
                                  for i in kept])
                cmds += more
                self.progs += [idx[kept[j]] for j in _programs(alt, more)]
        # and as its words' expansions combine (word(): self.readings), where a word makes more than its uniform
        # readings above: each way those words combine, the others as written and as when theirs are empty; past
        # MAX_READINGS ways (a word's, or these words' together) the command is unread, held
        grown, joint, combos = [i for i, (r, c, w, sp) in enumerate(zip(reads, cuts, words, splits))
                                if r and (sp or not set(r) <= {w, *c})], {}, []
        for i in grown:   # an expansion written alike in two words takes one value in both (`cp "$f" "$f.bak"`)
            for p, values in parts[i][1].items():
                joint.setdefault(p, values)
        unread |= None in reads or (each := _assignments(joint)) is None
        # a plain ${F=w} here (dollar) changes what F expands to after it: copies of one expansion that reads F, or a
        # variable named indirectly, take different values on either side of it, which one value per text (ways) can't
        # read (`--${F-f}${F=}${F-f}orce` is --force), so this command and the rest of the line are unread
        for name in {m.group(1) for p in exps if "=" in p for m in _PLAIN_ASSIGN.finditer(p)}:
            copies = collections.Counter(p for p in exps
                                         if p.startswith("${!") or re.search(rf"(?<!\w){name}(?!\w)", p))
            self.ctx["assigns"] |= any(n > 1 for n in copies.values())
        if grown and not unread and self.ctx["readings"]:
            self.ctx["more"] = True
            # (split as bash splits an unquoted expansion's value: a tuple of words, _fields)
            picks = [{i: _fields([(v[p], not p.quoted and v[p] != p) if isinstance(p, _Expansion) else (p, False)
                                  for p in parts[i][0]]) for i in grown} for v in each]
            self.charge(2 * len(picks) * sum(map(len, words)))   # each pick read with the others as written and empty
            combos = [[(None if alones[i] and not pick[i] else pick[i]) if i in pick else
                       None if rest is not words and vanish[i] and not rest[i] else rest[i] for i in range(len(words))]
                      for rest in (words, columns[2]) for pick in picks]
        if unread and cmds and not data:
            cmds[0]["opaque"], cmds[0]["unread"] = True, "readings"
        elif self.ctx["assigns"] and cmds and not data:   # (its readings are still read)
            cmds[0]["opaque"], cmds[0]["unread"] = True, "assigns"
        # and as bash runs it with each literal a known variable may hold (certain: `F=~/.x; cat "$F"` is `cat ~/.x`),
        # and with each name a bracket pattern can make (possible, as the empty readings: `cat key[s]` may be `cat keys`)
        self.ctx["more"] |= self.ctx["readings"] and any(patterns)   # (a name a pattern makes, below)
        extra = itertools.chain(  # built one at a time, each charged (below) before the next; None: a word gone
            combos,
            ([w if t is None else None if not t and a else t for t, w, a in zip(texts, words, alones)]
             for texts in self.fill(slots, True)),
            (words[:i] + [c] + words[i + 1:] for i, p in enumerate(patterns) if p and self.ctx["readings"]
             for c in _unglob(words[i])))
        glob = any(globs)
        for k, texts in enumerate(extra, 12):
            self.charge(len(texts))
            # each word's words in alt (kept: the word each is of): none for a word gone, the words bash splits a word
            # into (a tuple: fill's)
            if None in texts or tuple in map(type, texts):
                kept = [i for i, t in enumerate(texts) if t is not None for _ in ((t,) if isinstance(t, str) else t)]
                alt = [f for t in texts if t is not None for f in ((t,) if isinstance(t, str) else t)]
            else:
                kept, alt = range(len(texts)), texts
            # lean: past the 4th, a literal's or a pattern's reading makes a command, not a line: a rule on the line
            # or code (TK-D011) reads the first 4 (a loop over hundreds of words would read its whole script again for
            # each); line all if needed
            if k < 16 + len(combos):
                self.gone += [{} for _ in range(k + 1 - len(self.gone))]
                self.gone[k].update((idx[i], " ".join(t) if isinstance(t, tuple) else t) for i, t in enumerate(texts)
                                    if t != words[i])
            if alt and (key := tuple(alt)) not in seen and not data:
                seen.add(key)
                self.charge(sum(map(len, alt)))
                more = self.emit(alt, pid, self.via, glob, [names[i] if f == words[i] else
                                                            bool(_GLOB.search(f)) or _name_unreadable(f)
                                                            for f, i in zip(alt, kept)])
                cmds += more
                self.progs += [idx[kept[j]] for j in _programs(alt, more)]
        self.known = outer
        # bash sets $_ to the last word of each simple command it runs, OPTARG to an option's value getopts reads: each
        # literal one may be the value later on the line (given), where TK-D012 also denies one in the action position
        for c in cmds:
            options = [w[2:] if w[:1] == "-" else w for w in c["argv"][3:]] if c["argv"][0] == "getopts" else []
            for name, said in (("_", c["argv"][-1:] if c["argv"][1:] else [c["word"]]), ("OPTARG", options)):
                self.ctx["given"].setdefault(name, []).extend(w for w in said if not ("$" in w or "`" in w))
        self.crafted[pid] = self.feeding or not _reads_only(self.ctx["cmds"][first:], self.ctx)
        # (assignments after the time keyword alone are the shell's own, as without it: `time N=PS4`)
        bare = [] if timed and timed == len(words) else words
        self.track_values(bare, cmds, assigns, loop_header and (loop_header, header, header_unknown, header_spliced,
                                                                header_joined, header_blank),
                          sure and not dynamic, raws)
        if not bare:   # assignments alone set the shell's own variables, not a command's environment
            self.ctx["assigned"] += assigned
        if self.called:   # a function may set any variable, IFS or the directory
            self.known = {}
        marks = []
        if data:
            marks = here + ([s for s in spans[1:] if s] if words[0] in ("echo", "printf") else [])
            data_indexes = [i for i, _, _ in marks]
            self.data.update(data_indexes)
        else:
            data_indexes = []
        inert = bool(words) and words[0] not in self.ctx["functions"] and words[0] in (
            "cd", "pushd", "popd", "pwd", "ls", "mkdir", "true", ":") or \
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
        # the text this command writes into a file, for a later source or run of it (run_file): echo's words (as bash's
        # echo and as sh's or echo -e decode them), printf's output, or the herestring or heredoc cat or tee copies, each
        # with the newline it ends in; None: text the line doesn't give (an expansion in it the parser can't read, a
        # printf conversion it doesn't model). tee's text: what an echo or printf before it in its pipeline prints
        tee = [a for a in words[1:] if not a.startswith("-")] if words[:1] == ["tee"] else []
        files = into + [(a, "-a" in words or "--append" in words) for a in tee]
        text = None
        if words and not _redefined(self.ctx["redefined"], words[0]) and \
                not any(isinstance(w, _Spliced) or getattr(w, "unknown", False) for w in words):
            if words[0] == "echo":   # as written and decoded, whatever -e or -E says (bash under posix and xpg_echo
                # decodes despite -E), and as dash's prints it: only a first -n is an option, -e and -E are text
                i = next((i for i, w in enumerate(words[1:], 1) if not re.fullmatch(r"-[neE]+", w)), len(words))
                flags = "".join(words[1:i])
                end = "" if "n" in flags else "\n"
                said, stop = _echo_e(" ".join(words[i:]))
                dash, dash_stop = _echo_e(" ".join(words[1 + (words[1:2] == ["-n"]):]))
                raw, decoded = " ".join(words[i:]) + end, said + ("" if stop else end)
                # bash's own reading first (its last -e or -E says), the other last: an append joins its first and
                # last readings, written's ends, to the earlier write's
                bash, other = (decoded, raw) if flags.replace("n", "")[-1:] == "e" else (raw, decoded)
                text = list(dict.fromkeys([bash, dash + ("" if dash_stop or words[1:2] == ["-n"] else "\n"), other]))
            elif words[0] == "printf":
                text = None if (printed := _printf(words[1:])) is None else [printed]
            elif words[0] in ("cat", "tee") and (strings or docs) and not (piped or stdin_redirect or spliced) and \
                    (words[0] == "tee" or all(a.startswith("-") for a in words[1:])):
                text = [s + "\n" for s in strings] + docs   # a heredoc's text once read_heredocs reads it
            elif words[0] == "tee" and piped and not (strings or docs or stdin_redirect):
                text = self.said.get((pid, stage - 1))
        self.said[(pid, stage)] = text
        # crafted: text the line gives, or that a program which may make text writes (not a reader's, nor git's), or a
        # reader's copy of a file the line made (`cat f1 > f2`; a pattern may name one)
        made = self.ctx["made_files"]
        crafted = text is not None or not words or not (
            words[0] in _READERS or words[0] in _ECHOERS or words[0] == "git") or "*" in made or any(globs) and made or \
            any(w.rsplit("/", 1)[-1].casefold() in made for w in list(words[1:]) + ins)
        for (name, append), made in [(f, text) for f in files] + [(f, None) for f in others]:
            if not name.startswith(("/dev/", "/proc/")):   # a device keeps nothing to run
                key = name.rsplit("/", 1)[-1].casefold()
                self.ctx["files"].setdefault(key, []).append((made, append, crafted))
                if crafted:
                    self.ctx["made_files"].add(key)
        for c in cmds:
            c["stdin"] += strings
            c["out"], c["in"], c["stage"] = outs, ins, stage
        if (stdin_redirect or strings or docs) and "exec" in words[:1] + [c["argv"][0] for c in cmds]:
            self.ctx["stdin_moved"] = True   # what reads the shell's stdin after it reads that (_reads_only)
        shell = _stdin_shell(cmds)
        # its script comes from a pipe, a file or inherited stdin; one only a second reading makes (`bash $f` read as
        # `bash`) from a pipe or a file: the script file of an ordinary `bash $f` isn't held; `bash --version` and
        # `--help` print and exit
        if shell and not docs and not strings and shell["argv"][0] in SHELLS and (
                piped or stdin_redirect or shell is _stdin_shell(as_written)) and (
                piped or stdin_redirect or not set(shell["argv"][1:] or ["-"]) <= {"--version", "--help"}):
            shell["opaque"] = True
        # its code holds a value the parser can't name (`sh <<< "echo $(printf …)"`); not at's or batch's, which run it
        # later, outside the call (engine._SCHEDULED)
        if shell and unknown_string and shell["argv"][0] in SHELLS:
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

    def fill(self, slots, split=False):
        """Each way the known variables word() found in the words' `slots` (None: a word with none) may be set at
        once, as the words' texts (None for a word with none): `for f in a b` sets $f to a, then to b. Values alike
        (`for f in a a`) give one list, made once and charged each time. With `split`, a word an unquoted literal
        with a blank splits is the tuple of words bash makes of it (_fields)."""
        names = sorted({p[0] for s in slots if s for p in s if isinstance(p, tuple)})
        if not names:
            return []
        out, made = [], {}
        for values in itertools.product(*(self.known.get(n, ()) for n in names)):
            if values not in made:
                env = dict(zip(names, values))
                texts = [s and (_fields([(env[p[0]], not p[1]) if isinstance(p, tuple) else (p, False) for p in s])
                                if split else "".join(env[p[0]] if isinstance(p, tuple) else p for p in s)) for s in slots]
                made[values] = texts, sum(len(t) if isinstance(t, str) else sum(map(len, t)) for t in texts if t)
            texts, n = made[values]
            out.append(texts)
            self.charge(n)
        return out

    def track_values(self, words, cmds, assigns, loop, sure, raws=()):
        """Update self.known (__init__) after a simple command: a variable it gives a literal on its own, or with
        `export` (`export D=build`), is known when that surely runs (`sure`) before what follows it (`;`, a newline, `&&`
        or a subshell's end); a for loop's over literal words is known in its body; any other variable it sets is not;
        and after a command that may set any (read, declare, unset, eval, source, trap, alias, printf -v, one whose
        name the parser can't read) none is, for the rest of the line. A known variable keeps the literals it may hold
        (the loop's words; [""]: certainly empty, after `X=` or `unset X`), [] when unknown. `loop`: (for or select,
        the words after it); `assigns`: (name, the literal it gets or None, whether it is appended to: +=); `raws`: the
        words as written (an export's names must be, to set those alone)."""
        if loop:
            kind, (name, *rest) = loop[0], loop[1] or [None]
            literal = kind == "for" and rest[:1] == ["in"] and len(rest) > 1 and None not in rest[1:]
            if name == "IFS":
                self.ctx["ifs_values"] += rest[1:] if literal else [None]
            if literal and name:
                self.ctx["given"].setdefault(name, []).extend(rest[1:])
            elif name:   # its literal words, and each literal reading with a blank of a word an expansion joins
                self.ctx["given"].setdefault(name, []).extend(   # (` rm`$Y: bash splits it)
                    [w for w in rest[1:] if w is not None] * (rest[:1] == ["in"]) + loop[5])
            # the body runs again after its later commands: what they may change isn't known in it, nor after it
            self.known = self.stable()
            if literal and name and not self.ctx["any_set"] and name != "IFS" and not _bash_sets(name):
                self.known[name] = rest[1:]   # select sets it to nothing on a reply that picks no item
            elif name:   # (None: a name the line builds)
                self.known.pop(name, None)
            if name in self.ctx["namerefs"] and self.ctx["namerefs"][name] is None:   # each word is its target
                raise ParseError(f"a loop over the nameref {name}, which has no target, is not supported")
            # what it holds: text the line makes (`for x in $(printf …)`, `for y in $x` of such an x); a value the
            # parser can't name (an expansion it can't, the parameters, a reply, a pattern on a line that makes files);
            # else readers' or literals
            parameters = kind == "for" and rest[:1] != ["in"]   # `for x; do`: "$@"
            if not literal and (self.feeding or loop[3] or parameters and "@" in self.ctx["unread_values"]):
                self.ctx["unread_values"].add(name)
            elif not literal and (loop[2] or rest[:1] != ["in"] or kind == "select" or self.ctx["files"]):
                self.ctx["opaque_values"].add(name)
            if not literal and (loop[4] or parameters and "@" in self.ctx["joined_values"]):
                self.ctx["joined_values"].add(name)
            for word in (rest[1:] if rest[:1] == ["in"] else [None]) if name in _CODE_VARIABLES else ():
                self.code_variable(name, word, self.via)   # (None: a word or reply the parser can't read)
            self.blocks.append((kind, [name], self.list_start))
            return
        # a function's or script's arguments may move or be replaced (set and shift through command or builtin too)
        for a in [words, *(c["argv"] for c in cmds)]:
            if a[:1] == ["shift"] or a[:1] == ["set"] and _sets_positional(a[1:]):
                self.positional(a[1:])
                for name in [k for k in self.known if k.isdigit() or k == "@"]:
                    del self.known[name]
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
            self.ctx["exports"].update(name for name, _, _ in assigns)
        elif words[:1] == ["unset"] and all(re.fullmatch(r"-v|[A-Za-z_][A-Za-z0-9_]*", w) for w in words[1:]):
            assigns, words = [(n, "", False) for n in words[1:] if n != "-v"], []   # each now certainly empty
        elif words[:1] == ["export"] and all(re.fullmatch(r"[A-Za-z_]\w*(?:\+?=.*)?", w, re.S) for w in words[1:]) \
                and len(raws) == len(words) and all(re.match(r"[A-Za-z_]\w*(?:\+?=|$)", r) for r in raws[1:]) \
                and not any(c["opaque"] for c in cmds):
            # an export of names it writes (no option, no name the line builds) sets those alone: each is no longer
            # known (where it may not run: after && or in a block), its literals still read (maybe, variable_names)
            assigns, words = [(re.match(r"\w+", w).group(), None, False) for w in words[1:]], []
            self.ctx["exports"].update(name for name, _, _ in assigns)
        elif any(c["opaque"] or c["argv"][0] in _SETS_ANY and not (
                c["argv"][0] == "wait" and not any(re.match(r"-[A-Za-z]*p", a) for a in c["argv"][1:])) or
                 _sets_with_v(c["argv"]) or _sets_keyword(c["argv"]) for c in cmds):
            self.ctx["any_set"] = True   # (wait sets a variable only with -p)
        then = self.peek() in ("", "\n", ";", ")") or self.at("&&")
        for name, value, plus in assigns:
            old = self.known.pop(name, None)
            # X+=y of an X the line doesn't know may be y alone: not known; X= (or unset X) is known to be empty; one
            # bash sets itself (`_`: the last word of the command before) never is
            if value is None or not (sure and then) or words or self.ctx["any_set"] or name == "IFS" or \
                    plus and not old or _bash_sets(name):
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
                                                  any(map(_COMMAND_NAME_ASSIGN.match, argv[1:])))
            if argv[0] == "alias":
                self.ctx["redefined"].update(a.split("=", 1)[0] for a in argv[1:] if a.split("=", 1)[0] in copies)
            elif argv[0] == "enable" and "-n" in argv:
                self.ctx["redefined"].update(a for a in argv[1:] if a in copies)
            elif argv[0] in ("source", ".") and len(argv) > 1:
                self.ctx["redefined"].update(copies)

    def program(self, cmd, text, label):
        """An interpreter's program from a heredoc or herestring: scanned as its -c code would be, and a ref."""
        self.ctx["refs"].append(text)
        if cmd["argv"][0] in ("make", "gmake"):
            for line in _recipes(text):
                self.nested(line, cmd["via"] + [cmd["argv"][0] + label])
        else:
            self.scan(_kind(cmd["argv"][0]), text, cmd["pipeline"], cmd["via"] + [cmd["argv"][0] + label], cmd)

    def variable_names(self, name, args, via):
        """The variables a builtin of _NAME_BUILTINS names (or let): bash evaluates a subscript there, so the line's
        values may be (_Parser.word); held: a subscript with an expansion (bash expands it again), a name built from
        text the parser can't read (_Spliced: `read "$N"`, `declare "$N=…"`, whose subscript runs and whose code
        variable may be any; export's and readonly's evaluate no subscript, so theirs are held only where such a
        variable can act: analyse's _made_text), a nameref to one of _CODE_VARIABLES or to a name the line builds, an
        assignment through a nameref declared without a target (the first one sets it), or one of _CODE_VARIABLES
        read, mapfile, getopts, wait or printf sets from what it reads, or given with += (to a value the line doesn't
        give). Bookkept for analyse: the names bash evaluates as arithmetic (let, [[ … -eq … ]], declare -i), and what
        each variable it sets holds (unread_values: text the line makes; opaque_values: a value the parser can't name,
        read or mapped)."""
        declares = name in ("declare", "typeset", "local", "readonly", "export")
        names = _named(name, args)
        self.ctx["arith"] |= bool(names) or name in ("let", "[[")
        nameref = declares and any(re.fullmatch(r"-\w*n\w*", a) for a in args)
        compares = ("-eq", "-ne", "-lt", "-le", "-gt", "-ge")
        if name == "let" or name == "[[" and any(a in compares for a in args) or \
                declares and any(re.fullmatch(r"-\w*i\w*", a) for a in args):
            self.ctx["arith_names"].update(n for a in args for n in _arith_names(a))   # (let x=y evaluates y too)
        # an arithmetic assignment where bash evaluates one (let's expressions, [[ … -eq … ]]'s operands, a subscript
        # below), a nameref or an integer variable (whose later values are arithmetic) sets variables the parser can't
        # follow (arith_sets): this command and the rest of the line are unread (simple)
        operands = args if name == "let" else [o for i, c in enumerate(args) if name == "[[" and c in compares
                                               for o in args[max(i - 1, 0):i] + args[i + 1:i + 2]]
        for a in operands:
            self.arith_sets(a)
        if name in ("declare", "typeset", "local") and any(re.fullmatch(r"-\w*[ni]\w*", a) for a in args):
            self.ctx["assigns"] = True
        for word in names:
            if (m := re.match(r"[A-Za-z_][A-Za-z0-9_]*\[", word)) and re.search(r"[$`]", word[m.end():word.rfind("]")]):
                raise ParseError("an expansion in a subscript a builtin evaluates is not supported")
            if m:
                self.arith_sets(word[m.end():word.rfind("]")])
            target, eq, value = word.partition("=")
            if re.search(r"[$`]", target):   # a name the parser can't read: `declare "$N=…"`, `read "$N"`
                if name not in ("export", "readonly"):
                    raise ParseError("a variable name built from text the parser can't read is not supported")
                self.ctx["export_built"] = True
                continue
            plus, target = target.endswith("+"), target.rstrip("+")
            var = target.split("[", 1)[0]
            if nameref and (re.search(r"[$`]", value) or value.split("[", 1)[0] in _CODE_VARIABLES):
                raise ParseError(f"a nameref to {value} is not supported")
            if (var == "IFS" or nameref and value.split("[", 1)[0] == "IFS") and (eq or not declares) and \
                    name not in ("unset", "test", "[", "[["):   # a value IFS gets (None: one the parser can't read)
                literal = declares and eq and not (nameref or plus or re.search(r"[$`]", value))
                self.ctx["ifs_values"].append(value if literal else None)
            if declares and eq and not re.search(r"[$`]", value):
                self.ctx["given"].setdefault(var, []).append(value)
            if nameref:
                self.ctx["namerefs"][var] = value or None
            elif self.ctx["namerefs"].get(var, 1) is None and name not in ("unset", "test", "[", "[["):
                raise ParseError(f"an assignment through the nameref {var}, which has no target, is not supported")
            # given text the line makes: a word holding it, what read or mapfile reads from it (simple's feeding), and
            # what printf -v prints; a value the parser can't name: any other read or mapped, a word holding one
            if isinstance(word, _Spliced) if declares else name == "printf" or \
                    name in ("read", "mapfile", "readarray") and self.feeding:
                self.ctx["unread_values"].add(var)
            elif name in ("read", "mapfile", "readarray") or declares and getattr(word, "unknown", False):
                self.ctx["opaque_values"].add(var)
            if declares and getattr(word, "joined", False):
                self.ctx["joined_values"].add(var)
            if var in _CODE_VARIABLES and (eq if declares else name not in ("unset", "test", "[", "[[", "let")):
                self.code_variable(var, value if eq and var == target and not plus and not re.search(r"[$`]", value)
                                   else None, via)

    def run_file(self, path, via, cmd, direct=False, gives=(), unread=False, kind=None):
        """`cmd` sources or runs the file `path`, giving it the words `gives` (direct: by its path, so its #! names the
        program, _reader): the text the line writes into it (written) is read as that program's code, here and again at
        the line's end (analyse), once a heredoc on the same line is read; a file the line writes with text it doesn't
        give, one no program here reads, or (`unread`: a path an expansion or pattern makes) any file the line writes
        makes `cmd` opaque. `cmd` keeps `gives` as its script_args: a script the line writes may write each word the
        run gives it (engine._effects). `kind`: a file a program reads its commands from (configs)."""
        self.ctx["runs"].append((path, via, cmd, direct, gives, unread, kind, dict(self.known)))
        self.read_file(path, via, cmd, direct, gives, unread, kind)

    def written(self, path):
        """The texts the line may write into the file `path` names (by its name in any case, as macOS's file system
        reads one, and each write to a name the line builds): each write alone, and the writes since each truncation
        joined in order (>> appends); None for one whose text the line doesn't give. A heredoc not read yet is no text
        yet (read_file reads the file again at the line's end).
        lean: a name the line builds, with text it doesn't give, isn't counted for a path from / or ~ (a program run
        by its full path); count it if a crafted one is seen"""
        out, joined = [], None
        for made, append, _ in self.ctx["files"].get(path.rsplit("/", 1)[-1].casefold(), []) + [
                w for w in self.ctx["files"].get("*", []) if w[0] is not None or not path.startswith(("/", "~"))]:
            texts = None if made is None else [t if isinstance(t, str) else None if t.get("unknown") else
                                               t.get("text", "") + "\n" * ("text" in t) for t in made]
            if texts is None or None in texts:
                out.append(None)
                joined = None
                continue
            out += texts
            ends = [texts[0], texts[-1]]
            if append and joined:
                joined = [joined[0] + ends[0], joined[1] + ends[1]]
                self.charge(sum(map(len, joined)))
                out += joined
            else:
                joined = ends
        return out

    def read_file(self, path, via, cmd, direct, gives, unread=False, kind=None):
        # lean: an interpreter's script the line writes with text it doesn't give (`sed … a.py > b.py; python3 b.py`),
        # or names at run time, is trusted as one already on disk, as before; hold it if a crafted one is seen
        shell = direct or _reader("", cmd["argv"][0], False) in SHELLS
        if unread:   # a path the line builds: any file it writes may be the one
            cmd["opaque"] = cmd["opaque"] or shell and bool(self.ctx["files"])
            return
        texts = self.written(path)
        self.charge(len(texts))   # each run reads each write again: many of both on one line spend the budget
        at, inside = tuple(via), via + ["file " + path]
        if kind:   # a config: the commands it gives, read as shell; one whose text the line doesn't give is held
            for text in texts:
                if (key := ("config", path, text, at)) in self.ctx["nested"]:
                    continue
                self.ctx["nested"].add(key)
                if kind == "python" and text is not None:
                    self.scan("python", text, cmd["pipeline"], via + ["config " + path], cmd)
                    continue
                for line in [None] if text is None else _config_lines(kind, text):
                    if line is None:
                        cmd["opaque"] = True
                    else:
                        self.nested(line, via + ["config " + path])
            return
        for text in texts:
            if text is None:
                cmd["opaque"] = cmd["opaque"] or shell
                continue
            cmd["script_args"] = gives
            key = ("file", path, text, at, tuple(gives))   # read once: again, it would define its functions again
            if key in self.ctx["nested"]:
                continue
            self.ctx["nested"].add(key)
            program = _reader(text, cmd["argv"][0], direct)
            if program is None:
                cmd["opaque"] = True
            elif program in SHELLS:   # (run by its path: its #! names the shell, for nested's grammar)
                self.nested(text, via + [program] + inside[len(via):] if direct else inside, gives)
            else:   # read as the inline code of its interpreter (python3 -c, node -e), for what it runs and writes
                # lean: code it can't read there (a spawner given a name) isn't held, as before; hold it if one hides
                first, kept = len(self.ctx["cmds"]), {k: type(self.ctx[k])(self.ctx[k]) for k in
                                                      ("unread_values", "arith_names", "code_names", "depth")}
                try:
                    self.emit([program, "-" + CODE_FLAGS[_kind(program)][0], text, *gives], cmd["pipeline"], inside)
                except ParseError:   # (a literal it runs that isn't shell)
                    if self.ctx["work"][0] > MAX_WORK:
                        raise
                for c in self.ctx["cmds"][first:]:
                    c["opaque"] = False
                self.ctx.update(kept)   # (its string literals read as shell are no shell of this line)

    def code_variable(self, name, value, via):
        """One of _CODE_VARIABLES the line sets to `value` (None: one it can't read): its value is read as the code bash
        runs (a prompt's or a file name's substitutions, PROMPT_COMMAND's script). Held: a value the line can't read, a
        file from a stream, a path or alias for a command name; for ENV, which only an interactive shell reads, only on
        a line that runs one (here, or where emit reaches it)."""
        kind = _CODE_VARIABLES[name]
        if value is None or kind is None or kind == "file" and _stream(value):
            if name == "ENV" and not any(c["argv"][0] in SHELLS and _interactive(c["argv"][1:])
                                         for c in self.ctx["cmds"]):
                self.ctx["env_unread"] = True
                return
            raise ParseError(f"{name} set to a value the parser can't read is not supported")
        if kind == "script":
            self.nested(value, via + [name])
            return
        self.prompt(value, via + [name], kind == "prompt")
        for text in self.written(value) if kind == "file" else ():   # a file it names the line writes: its code
            if text is None:
                raise ParseError(f"{name} naming a file the line writes with text it can't read is not supported")
            self.nested(text, via + [name, "file " + value])

    def prompt(self, value, via, escapes=True):
        """A value bash expands as double-quoted text is, running its substitutions; held: a prompt's \\ escape (\\044 is
        a $), or a character past ASCII, which a locale that can't show it writes as \\uXXXX, an escape again."""
        if escapes and ("\\" in value or not value.isascii()):
            raise ParseError("a prompt with a \\ escape is not supported")
        p = _Parser(value, self.ctx, via)
        p.known = {}
        p.dquote(None)

    def git_words(self, head, value, tail, pid, via, cmd, cmds):
        """A git alias's value read as the git command it names, between `head` (git and its options) and the words
        its use gives after it (`tail`); one shlex can't split makes `cmd` opaque."""
        try:
            words = shlex.split(value)
        except ValueError:
            cmd["opaque"] = True
            return
        if words:
            cmds += self.emit([*head, *words, *tail], pid, via + ["git alias"])

    def tmux(self, args, pid, via, cmds):
        """tmux's commands (split at a `;` word): the keys send-keys types into a pane's shell (a key's name read as
        what it types: Space, Enter, C-m …; -l types its words as they are), and the command new-session, new-window,
        split-window or respawn-pane runs (one word: a shell's line)."""
        i = 0
        while i < len(args) and args[i].startswith("-"):   # tmux's own options (-L, -S, -f, -c, -T take a value)
            i += 2 if args[i] in ("-L", "-S", "-f", "-c", "-T") else 1
        groups = [[]]
        for a in args[i:]:
            if a in (";", "\\;"):
                groups.append([])
            else:
                groups[-1].append(a)
        for sub, *rest in filter(None, groups):
            j, literal = 0, False
            while j < len(rest) and rest[j].startswith("-") and len(rest[j]) > 1:
                literal |= sub in ("send-keys", "send") and "l" in rest[j]
                j += 2 if rest[j][-1] in ("tNc" if sub in ("send-keys", "send") else "cefFlnstxyLT") else 1
            if sub in ("send-keys", "send"):
                for line in re.split(r"[\r\n]", "".join(k if literal else _TMUX_KEYS.get(k, k) for k in rest[j:])):
                    if line.strip():
                        self.nested(line, via + ["tmux send-keys"])
            elif sub in ("new-session", "new", "new-window", "neww", "split-window", "splitw", "respawn-pane",
                         "respawnp", "respawn-window", "respawnw") and rest[j:]:
                if len(rest[j:]) == 1:
                    self.nested(rest[j], via + ["tmux " + sub])
                else:
                    cmds += self.emit(rest[j:], pid, via + ["tmux " + sub])

    def configs(self, name, args, via, cmd):
        """The files a program reads commands from, where the line writes them (by name: a name it builds isn't one
        here): make's Makefile or -f file, the package.json scripts npm, yarn, pnpm and bun run (install runs its
        lifecycle ones) and their .npmrc, pip install's setup.py (its code), pyproject.toml and setup.cfg (held), git's
        config files and the one GIT_CONFIG_GLOBAL or GIT_CONFIG_SYSTEM names: read as the commands they give, or held
        (read_file). Not inside a config's own commands (`git config …` lines), which read the same files.
        lean: a file the line writes under a name it builds isn't read as a config; read it if a crafted one is seen"""
        if any(v.startswith("config ") for v in via):
            return
        if name in ("make", "gmake"):
            files = dict.fromkeys([f for f in _program_files(args) if not _stream_name(f)] or ["GNUmakefile", "makefile"],
                                  "make")
        elif name in ("npm", "yarn", "pnpm", "bun"):
            files = {".npmrc": "npmrc", ".yarnrc": "npmrc", ".yarnrc.yml": "npmrc",
                     **({} if "--ignore-scripts" in args else {"package.json": "scripts"})}
        elif name == "git":
            files = dict.fromkeys(["config", ".gitconfig", "gitconfig", *self.ctx["given"].get("GIT_CONFIG_GLOBAL", ()),
                                   *self.ctx["given"].get("GIT_CONFIG_SYSTEM", ())], "git")
        elif "install" in args:
            files = {"setup.py": "python", "pyproject.toml": None, "setup.cfg": None}
        else:
            return
        for path, kind in files.items():
            if path and path.rsplit("/", 1)[-1].casefold() in self.ctx["files"]:
                if kind is None:
                    cmd["opaque"] = True
                else:
                    self.run_file(path, via + [name], cmd, kind=kind)

    def emit(self, argv, pid, via, glob=False, unreadable=None):
        """`unreadable[i]`: argv[i] is not a literal name (an unquoted glob or brace, or an expansion; only words of
        the line itself have one)."""
        cmds, unreadable, repl = [], unreadable or [False] * len(argv), None
        while argv:
            if len(via) > MAX_DEPTH:
                raise ParseError("nested too deeply")
            name, args = _lower_name(argv[0].rsplit("/", 1)[-1] or argv[0]), argv[1:]
            if _function_variable(argv[0]):   # a word bash can't assign, which a program it runs may import, as env's
                raise ParseError("a function given through the environment is not supported")
            # xargs -I{} inserting its input into a script or a command name: what runs comes from stdin
            tainted = repl is not None and bool(repl in argv[0] or (
                (name in SHELLS or _kind(name)) and any(repl in a for a in args)))
            cmd = {"argv": [name] + args, "word": argv[0], "via": via, "pipeline": pid, "glob": glob,
                   "opaque": unreadable[0] or tainted, "stdin": [], "moved": self.inherit or bool(self.blocks)}
            self.ctx["cmds"].append(cmd)
            cmds.append(cmd)
            self.charge(COMMAND_COST)
            if not unreadable[0] and "/" in argv[0]:   # a file run by its path
                self.run_file(argv[0], via, cmd, True, args)
            if not unreadable[0] and argv[0] in self.ctx["functions"]:   # and as the program of that name, if it isn't
                self.call(argv[0], args, via, cmd)
            if not unreadable[0] and argv[0] in self.ctx["aliases"] and "alias " + argv[0] not in via:
                self.ctx["alias_used"].add(argv[0])
                for value in self.ctx["aliases"][argv[0]]:   # bash reads an alias's text in its name's place
                    # one ending in a blank: bash reads the next word as an alias too (`alias e='echo '; e b`)
                    if value[-1:] in (" ", "\t") and args[:1] and args[0] in self.ctx["aliases"]:
                        raise ParseError("an alias ending in a blank before another alias is not supported")
                    self.nested(" ".join([value, *map(shlex.quote, args)]), via + ["alias " + argv[0]])
            if name in _NAME_BUILTINS or name == "let":
                self.variable_names(name, args, via)
            if name in ("export", "declare", "typeset", "readonly") and any(re.fullmatch(r"-\w*f\w*", a) for a in args):
                self.ctx["exported"].update(a for a in args if not a.startswith(("-", "+")))   # export -f: any child
            if name in ("export", "declare", "typeset", "readonly", "local", "env"):   # git config set in the environment
                for a in args:
                    if (alias := _git_env_alias(a)) is not None:
                        self.nested(alias, via + ["git alias"])
                    if name == "env" and (m := re.match(r"(GIT_(?:CONFIG_\w+|ALLOW_PROTOCOL))=", a)):
                        self.ctx["given"].setdefault(m.group(1), []).append(a[m.end():])
            if name in ("make", "gmake", "npm", "yarn", "pnpm", "bun", "git") or _PIP.fullmatch(name) or \
                    _kind(name) == "python" and args[:2] == ["-m", "pip"]:
                self.configs(name, args, via, cmd)
            if name in DASH_C:
                if _dash_c(args) is None:
                    cmd["opaque"] = True   # an interactive shell: it runs whatever its stdin holds
                else:
                    self.nested(self.code(cmd, [_dash_c(args)]), via + [name + " -c"])
            elif name == "sg":
                self.nested(self.code(cmd, [a for a in args[1:] if a != "-c"]), via + ["sg -c"])
            elif name == "watch":
                i = 0
                while i < len(args) and args[i].startswith("-"):
                    i += 2 if args[i] in ("-n", "--interval") else 1
                self.nested(self.code(cmd, args[i:]), via + ["watch sh -c"])
            elif name == "parallel":
                i = 0
                while i < len(args) and args[i].startswith("-"):
                    i += 2 if args[i] in PARALLEL_OPTS else 1
                words = next((args[i:j] for j in range(i, len(args)) if args[j] in (":::", "::::", ":::+", "::::+")),
                             args[i:])
                if words:
                    self.nested(self.code(cmd, words), via + ["parallel sh -c"])
                else:
                    cmd["opaque"] = True   # it reads the commands from stdin
            elif name == "env" and (split := _split_string(args)) is not None:   # env reads the words again
                argv, via, unreadable = ["env", *split], via + ["env -S"], [False] * (1 + len(split))
                self.charge(len(argv))
                continue
            elif (name == "npx" or name == "npm" and args[:1] in (["exec"], ["x"])) and \
                    (script := _npm_call(args if name == "npx" else args[1:])) is not None:
                self.nested(self.code(cmd, [script]), via + [name + " -c"])
            elif name == "hub":   # git's wrapper: its words are git's
                argv, via, unreadable = ["git", *args], via + ["hub"], unreadable
                continue
            elif name == "uv" and args[:2] in (["tool", "run"], ["tool", "uvx"]):   # uvx's long forms
                argv, via, unreadable = ["uvx"] + args[2:], via + ["uv tool run"], unreadable[2:]
                self.charge(len(argv))
                continue
            elif name in WRAPPERS or name in RUNNERS and args[:1] and args[0] in RUNNERS[name][0]:
                if name == "runuser" and _dash_c(args) is not None:
                    self.nested(self.code(cmd, [_dash_c(args)]), via + ["runuser -c"])
                more = _unwrap(name, args)
                inner = next(more)
                for other in more:   # what it may run where an option it doesn't know takes a value, each read once
                    if (key := (pid, name, tuple(other))) not in self.unwrapped:
                        self.unwrapped.add(key)
                        self.charge(len(other))   # as each wrapper level copies the words after it
                        cmds += self.emit(other, pid, via + [name], glob, unreadable[len(argv) - len(other):])
                for a in args[:len(args) - len(inner)]:   # env PS4=… bash -x: the environment it gives the command
                    target, eq, value = a.partition("=")
                    if eq and re.search(r"[$`]", target):   # a name the parser can't read may be any (`env "$N=…"`)
                        raise ParseError("a variable name built from text the parser can't read is not supported")
                    if _function_variable(a):   # bash imports BASH_FUNC_x%%='() { …; }' as function x of its shell
                        raise ParseError("a function given through the environment is not supported")
                    if eq and (var := target.split("[", 1)[0]) in _CODE_VARIABLES:
                        self.code_variable(var, value if var == target and not re.search(r"[$`]", value) else None, via)
                # an expansion in an assignment env reads may split into a word with no `=`, which env runs before the
                # rest (`X=${X::0}" cmd"; env =$X a` runs cmd): one of a variable the line gave from expansions whose
                # value it doesn't know there (`${X::0}`, `${Y/a/b}`, an unknown variable's), or with an operator it
                # reads as written (`${X#}`, `${X%/}`, `${X:1}`, `${!X}`), may be any command
                # lean: one the environment or a substitution gives (`env HOME=$HOME/x`, `H=$(mktemp -d); env HOME=$H`,
                # `S=$PWD; env HOME=$S/h`: 27 calls of the real week's replay) isn't held, nor one a later assignment or
                # a loop gives; a quoted one, which doesn't split, is held too
                if name == "env":
                    # (clean: no literal the line gives it has a blank, and each value it gives it is a substitution's
                    # or plain expansions of the environment's variables, of known ones or of clean ones, without a
                    # blank; any other given an expansion is made)
                    known, clean = {n for n, v in self.known.items() if v}, set()
                    values = collections.defaultdict(list)
                    for n, w in self.ctx["assigned"]:
                        values[n].append(w.split("=", 1)[1])
                    lined = set(values) | {n for n, v in self.ctx["given"].items() if v}
                    while more := {n for n, vs in values.items() if n not in clean and not any(
                            _BLANK.search(g) for g in self.ctx["given"].get(n, ())) and all(
                            _SUBSTITUTION.search(v) or not _BLANK.search(v) and not re.search(r"\$\{(?![A-Za-z_]\w*\})", v)
                            and not (set(_VARIABLE_NAME.findall(v)) - known - clean) & lined for v in vs)}:
                        clean |= more
                    made = {n for n, w in self.ctx["assigned"] if n not in known | clean and not _SUBSTITUTION.search(w)
                            and ("$" in w or n in self.ctx.get("expanded_assigned", ()))}
                    if any(unreadable[k] and "=" in a and not a.startswith("-") and (made.intersection(
                            _VARIABLE_NAME.findall(a.split("=", 1)[1])) or _UNREAD_OPERATOR.search(a))
                           for k, a in enumerate(args[:len(args) - len(inner)], 1)):
                        cmd["opaque"] = True
                if name == "flock" and inner[:1] in (["-c"], ["--command"]):
                    self.nested(self.code(cmd, inner[1:2]), via + ["flock -c"])
                    break
                if name == "xargs":
                    repl = _xargs_replace(args[:len(args) - len(inner)])
                argv, via, unreadable = inner, via + [name], unreadable[len(argv) - len(inner):]
                self.charge(len(argv))   # each wrapper level copies the words after it
                continue
            elif name in SHELLS:
                if self.ctx.get("env_unread") and _interactive(args):
                    raise ParseError("ENV set to a value the parser can't read is not supported")
                for k, a in enumerate(args[:-1]):   # the file an interactive shell sources first
                    if a in ("--rcfile", "--init-file") and not any(b == "--" for b in args[:k]):
                        self.run_file(args[k + 1], via + [name], cmd, unread=unreadable[k + 2])
                mode, script = _shell_mode(args)
                if mode == "c":
                    self.positional(args[args.index(script) + 1:] if script in args else args)
                    self.nested(self.code(cmd, [script]), via + [name + " -c"])
                elif mode is None:
                    k = args.index(script)
                    self.run_file(script, via + [name], cmd, gives=args[k + 1:], unread=unreadable[k + 1])
            elif name in FOREIGN_SHELLS:
                cmd["opaque"] = cmd["opaque"] or _foreign_runs_text(name, args)
            elif name in ("source", ".") and (script := args[1:] if args[:1] == ["--"] else args)[:1]:
                if _stream(script[0]):
                    cmd["opaque"] = True
                else:
                    self.run_file(script[0], via + [name], cmd, gives=script[1:],
                                  unread=unreadable[len(argv) - len(script)])
            elif name == "eval":   # it drops a leading --
                self.nested(self.code(cmd, args[1:] if args[:1] == ["--"] else args), via + ["eval"])
            elif name == "fc" or name == "history" and any(re.fullmatch(r"-\w*[srn]\w*", a) for a in args):
                cmd["opaque"] = True   # fc runs history or an editor it names; history -s, -r, -n put commands in it
            elif name == "history" and any(re.fullmatch(r"-\w*[wa]\w*", a) for a in args):
                for a in (a for a in args if not a.startswith("-")):   # it writes the history into the file
                    self.ctx["files"].setdefault(a.rsplit("/", 1)[-1].casefold(), []).append((None, False, True))
                    self.ctx["made_files"].add(a.rsplit("/", 1)[-1].casefold())
            elif name == "compgen":   # -C runs a command, -W's words are expanded again, -F calls a function
                for k, a in enumerate(args):
                    if m := re.fullmatch(r"-[A-Za-z]*?([CWF])(.*)", a, re.S):
                        if m.group(1) == "F":
                            raise ParseError("compgen -F (a function it calls) is not supported")
                        value = m.group(2) or (args[k + 1] if k + 1 < len(args) else "")
                        self.nested(self.code(cmd, [value if m.group(1) == "C" else ": " + value]),
                                    via + ["compgen -" + m.group(1)])
            elif name == "alias":
                options = True   # its options end at the first word that isn't one, after --, or at a lone - (a word)
                for a in args:
                    if options and a.startswith("-") and a != "-":
                        if re.search(r"[$`]", a):   # it may split into a lone - and an alias (`-${IFS}-x=…`)
                            raise ParseError("an alias word the line builds is not supported")
                        options = a != "--"
                        continue
                    options, (alias, eq, value) = False, a.partition("=")
                    if not eq and re.search(r"[$`]", a) or isinstance(a, _Spliced):
                        raise ParseError("an alias word the line builds is not supported")
                    if not eq:
                        continue
                    if not alias or re.search(r"[$`*?[\]{}\s'\"\\/]", alias) or alias in _RESERVED:
                        raise ParseError("an alias whose name the line builds, or a reserved word's, is not supported")
                    # its text runs into the rest of the line where it is used: a heredoc (bash reads its body from
                    # after the use), a comment (the rest of the line is gone: its heredoc's body runs) or a trailing \
                    if re.search(r"<<(?!<)|(?:^|[\s;&|()])#|\\\Z", value):
                        raise ParseError("an alias whose text changes how the rest of its line reads is not supported")
                    values = self.ctx["aliases"].setdefault(alias, [])
                    if value not in values:
                        values.append(value)
            elif name == "hash" and any(re.search(r"[$`]", a) or re.match(r"-\w*p", a) for a in args):
                raise ParseError("hash -p (a path for a command name) is not supported")
            elif name == "git":
                # a shell alias runs its command as sh -c does: set for this run (`git -c alias.x='!cmd' x`) or saved
                # for a later one (`git config alias.x '!cmd'`); one from a variable or an included file isn't read
                if any(_CONFIG_ENV.match(a) or j and args[j - 1] == "-c" and _INCLUDE.match(a)
                       for j, a in enumerate(args)):
                    raise ParseError("git config from a variable or an included file is not read")
                # and so do the other keys whose value git runs (core.pager, core.fsmonitor, credential.helper …), as
                # `-c KEY=VALUE` or `git config KEY VALUE`; a subcommand's option that takes a command (rebase -x),
                # bisect run's words and submodule foreach's script: each read as the code it is, held where it can't be
                sub = _git_sub(args)
                if any(re.match(r"(?i)--config-env=", a) and _GIT_RUNS.match(a[13:]) or
                       j and args[j - 1] == "--config-env" and _GIT_RUNS.match(a) for j, a in enumerate(args)):
                    cmd["opaque"] = True   # a command git runs from a variable the parser can't read
                for j, a in enumerate(args):
                    m = _GIT_RUNS.fullmatch(a)
                    if not m or m.group(2) is None and (sub is None or args[sub] != "config" or j + 1 >= len(args)):
                        continue
                    value = (m.group(2) if m.group(2) is not None else args[j + 1]).lstrip()
                    alias = m.group(1).lower().startswith("alias.")
                    if not alias or value.startswith("!"):
                        self.code(cmd, args[j:j + 1 + (m.group(2) is None)])
                        self.nested(value[1:] if value.startswith("!") else value, via + ["git alias" if alias else "git config"])
                # an alias to a git command is that command, read in its use's place with the use's words after it:
                # given for this run (`git -c alias.p='push -f' p`) or saved (`git config alias.p 'push -f'`, then `git
                # p`); a saved one is also read as if it ran (a later call may use it). A config that makes a push
                # force is a forced push: a mirror remote (remote.<name>.mirror, `git remote add --mirror`) or a +
                # push refspec, for this run's push or saved for any later one
                # (with the -c pairs the environment gives: GIT_CONFIG_KEY_<n> and GIT_CONFIG_VALUE_<n>)
                saved, here = self.ctx.setdefault("git_aliases", {}), {}
                env = [] if via[-1:] == ["git config"] else _git_config_env(self.ctx["given"])   # (once)
                cargs, csub = env + args, None if sub is None else sub + len(env)
                for j, a in enumerate(cargs):
                    m = _GIT_CONFIG_KEY.fullmatch(a)
                    if not m:
                        continue
                    given = j and cargs[j - 1] == "-c" and (csub is None or j < csub)
                    key, written = (m.group(1), m.group(3)) if m.group(1) else (m.group(4), m.group(5))
                    if written is not None:
                        value = written if given else None
                    elif given:
                        value = "true"   # a bare key is true
                    else:
                        value = cargs[j + 1] if csub is not None and cargs[csub] == "config" and csub < j < len(cargs) - 1 \
                            else None
                    if value is None:
                        continue
                    key = key.lower()
                    if key == "alias" and not value.lstrip().startswith("!"):
                        (here if given else saved)[m.group(2).lower()] = value
                        if not given:
                            self.git_words(["git", *[a for a in args[:sub] if a]], value, [], pid, via, cmd, cmds)
                    elif key == "mirror" and value.strip().lower() not in ("false", "no", "off", "0", "") or \
                            key == "push" and value.lstrip().startswith("+"):
                        force = "--mirror" if key == "mirror" else value.strip()
                        if not given:
                            cmds += self.emit(["git", "push", force], pid, via + ["git config"])
                        elif csub is not None and cargs[csub] == "push":   # (without the -c pair: read once)
                            head = [a for k, a in enumerate(cargs[:csub]) if k not in (j - 1, j) and k >= len(env)]
                            cmds += self.emit(["git", *head, cargs[csub], force, *cargs[csub + 1:]], pid,
                                              via + ["git config"])
                # a URL of git's ext:: transport runs its command (git's % escapes decoded), read as those words; where
                # a config or the environment allows the transport, a word the line builds may be one: held
                allows = any(re.fullmatch(r"(?is)protocol\.(?:ext\.)?allow=(?:always|user)", a) for a in cargs) or any(
                    "ext" in v for v in self.ctx["given"].get("GIT_ALLOW_PROTOCOL", ()))
                for k, a in enumerate(args):
                    if (at := a.lower().find("ext::")) >= 0:
                        if words := _ext_words(a[at + 5:]):
                            cmds += self.emit(words, pid, via + ["git ext::"])
                    elif allows and k + 1 < len(unreadable) and unreadable[k + 1]:
                        cmd["opaque"] = True
                if sub is not None and args[sub] == "remote" and args[sub + 1:sub + 2] == ["add"] and any(
                        a in ("--mirror", "--mirror=push") for a in args[sub + 2:]):
                    cmds += self.emit(["git", "push", "--mirror"], pid, via + ["git config"])
                if sub is not None and (value := {**saved, **here}.get(args[sub].lower())) is not None:
                    self.git_words(["git", *args[:sub]], value, args[sub + 1:], pid, via, cmd, cmds)
                opts = _GIT_CODE_OPTS.get(args[sub], ()) if sub is not None else ()
                for j in range(sub + 1 if opts else len(args), len(args)):
                    a, nxt = args[j], args[j + 1:j + 2]
                    for o in opts:
                        if o != "-O" and nxt and (a == o or len(o) == 2 and re.fullmatch(rf"-[A-Za-z]*{o[1]}", a)):
                            self.nested(self.code(cmd, nxt), via + [f"git {args[sub]} {o}"])
                        elif a.startswith(o + "=" if o[1] == "-" else o) and len(a) > len(o) + (o[1] == "-"):
                            self.nested(self.code(cmd, [a[len(o) + (o[1] == "-"):]]), via + [f"git {args[sub]} {o}"])
                if sub is not None and args[sub] == "bisect" and args[sub + 1:sub + 2] == ["run"] and args[sub + 2:]:
                    cmds += self.emit(args[sub + 2:], pid, via + ["git bisect run"])   # (git quotes each word for sh)
                elif sub is not None and args[sub] == "submodule" and "foreach" in args[sub + 1:]:
                    rest = args[args.index("foreach", sub + 1) + 1:]
                    while rest[:1] in (["--recursive"], ["--quiet"], ["-q"]):
                        rest = rest[1:]
                    if rest:   # one word is sh -c's script; more, a command line it runs
                        self.nested(self.code(cmd, rest), via + ["git submodule foreach"])
            elif name == "tmux":
                self.tmux(args, pid, via, cmds)
            elif name == "screen" and "-X" in args:   # -X stuff types its text into a window's shell; -X exec runs
                k = args.index("-X")
                if args[k + 1:k + 2] == ["stuff"] and args[k + 2:]:
                    for line in re.split(r"[\r\n]", _typed(args[k + 2])):
                        if line.strip():
                            self.nested(line, via + ["screen stuff"])
                elif args[k + 1:k + 2] == ["exec"] and args[k + 2:]:
                    rest = args[k + 3:] if re.fullmatch(r"[.!|:]+", args[k + 2]) else args[k + 2:]
                    cmds += self.emit(rest, pid, via + ["screen exec"])
            elif name in ("docker", "podman") and (args[:1] in (["run"], ["create"]) or args[:2] == ["container", "run"]):
                # a mount of a home or root, then a delete of its mount point in the container: a delete of that home
                mounts = {}
                for k, a in enumerate(args):
                    v = args[k + 1] if a in ("-v", "--volume") and k + 1 < len(args) else a[9:] if \
                        a.startswith("--volume=") else a[2:] if a.startswith("-v") and len(a) > 2 else None
                    if a == "--mount" and k + 1 < len(args) or a.startswith("--mount="):
                        f = dict(x.partition("=")[::2] for x in (args[k + 1] if a == "--mount" else a[8:]).split(","))
                        v = f.get("source", f.get("src", "")) + ":" + f.get("target", f.get("destination", f.get("dst", "")))
                    if v and ":" in v and (src := v.split(":")[0]) and _HOME_OR_ROOT.fullmatch(src):
                        mounts[v.split(":")[1].rstrip("/") or "/"] = src
                for k, a in enumerate(args):
                    if a.rsplit("/", 1)[-1] == "rm" and mounts:
                        ops = [next((src.rstrip("/") + w[len(dst):] or "/" for dst, src in mounts.items()
                                     if w.rstrip("/") == dst or w.startswith(dst.rstrip("/") + "/")), w) for w in args[k + 1:]]
                        if ops != args[k + 1:]:
                            cmds += self.emit(["rm", *ops], pid, via + [name + " mount"])
            elif name in ("fd", "fdfind") and (k := next((j for j, a in enumerate(args) if a in (
                    "-x", "--exec", "-X", "--exec-batch")), None)) is not None and args[k + 1:]:
                # what it runs on each file found; an rm -r of all it finds under a home or root (no filter but a
                # match-all pattern) is that rm of the folders it searches
                run = args[k + 1:args.index(";", k) if ";" in args[k:] else len(args)]
                cmds += self.emit(run, pid, via + ["fd -x"])
                ops = [a for a in args[:k] if not a.startswith("-")]
                if run[:1] == ["rm"] and len(ops) > 1 and ops[0] in (".", "", "^") and all(
                        a in ("-H", "--hidden", "-I", "--no-ignore", "-u", "-uu", "-a", "--absolute-path") or
                        not a.startswith("-") for a in args[:k]):
                    cmds += self.emit([*run, *ops[1:]], pid, via + ["fd -x rm"])
            elif name == "gh" and args[:2] == ["repo", "sync"] and any(a in ("--force", "-f") for a in args):
                cmds += self.emit(["git", "push", "--force"], pid, via + ["gh repo sync"])   # a hard reset of the branch
            elif name in ("gh", "curl", "wget", "http", "https", "xh", "xhs") and (how := _ref_update(name, args)):
                if how == "force":
                    cmds += self.emit(["git", "push", "--force"], pid, via + [name + " api"])
                else:   # held: a body the parser can't read may force
                    cmd["opaque"], cmd["unread"] = True, "body"
            elif name == "trap" and len(args) > 1 and not re.fullmatch(r"-[lpP]*", args[0]):
                # its action runs on a signal or at exit (`trap 'rm -rf "$d"' EXIT`); `-` or a lone condition resets
                self.nested(self.code(cmd, args[1:2] if args[0] == "--" else args[:1]), via + ["trap"])
            elif name == "trap" and len(args) == 1 and re.search(r"[$`]", args[0]):
                cmd["opaque"] = True   # a word bash may split into an action and its conditions
            elif name in ("ssh", "scp", "sftp"):
                for value in _ssh_option_commands(args):   # run on this machine, through a shell
                    self.nested(self.code(cmd, [value]), via + [name + " -o"])
                if name == "ssh":
                    self.code(cmd, args)
                    self.nested(_ssh_command(args), via + ["ssh"])
            elif name == "rsync":
                for value in _rsync_shells(args):
                    self.nested(self.code(cmd, [value]), via + ["rsync -e"])
            elif name == "nix" and args[:1] in (["develop"], ["shell"]):   # -c/--command: the command it runs
                k = next((j for j, a in enumerate(args) if a in ("-c", "--command")), None)
                if k is not None and args[k + 1:]:
                    cmds += self.emit(args[k + 1:], pid, via + ["nix " + args[0]])
            elif name == "coverage" and args[:1] == ["run"]:   # python's own argv: a script, or -m and a module
                k = 1
                while k < len(args) and args[k].startswith("-") and args[k] not in ("-m", "--"):
                    k += 2 if args[k] in _COVERAGE_VALUE_OPTS else 1
                k += args[k:k + 1] == ["--"]
                if args[k:]:
                    cmds += self.emit(["python", *args[k:]], pid, via + ["coverage run"])
            elif name == "nix-shell":   # --run and --command take a script, as sh -c does
                for i in range(len(args) - 1):
                    if args[i] in ("--run", "--command"):
                        self.nested(self.code(cmd, args[i + 1:i + 2]), via + ["nix-shell --run"])
            elif name == "find":
                for inner in _find_execs(args):
                    self.emit(inner, pid, via + ["find -exec"])
                    # rm -r on what it finds empties its starting points as -delete does: read so too, with the tests
                    # before the -exec (TK-D004 reads which pick every file)
                    if inner[:1] == ["rm"] and "{}" in inner and any(
                            re.fullmatch(r"-\w*[rR]\w*|--recursive", a) for a in inner[1:]):
                        k = next(j for j, a in enumerate(args) if a in ("-exec", "-execdir", "-ok", "-okdir"))
                        cmds += self.emit(["find", *args[:k], "-delete"], pid, via + ["find -exec rm"])
            elif _kind(name):
                if _kind(name) == "python" and (run := _python_runs(args)) is not None:
                    cmds += self.emit(run, pid, via + [name])   # Tracekit's CLI, read as the tracekit command
                # code its other options load: perl's -M (`use X;…`), a module node imports or requires and ruby
                # requires (a data: URL's code, a file the line writes), python's -X presite (held), each read as code
                for what, value in _loaded(_kind(name), args):
                    if what == "code":
                        self.scan(_kind(name), value, pid, via + [name + " -M"], cmd)
                    elif value.startswith("data:"):
                        self.scan(_kind(name), _data_url(value), pid, via + [name + " import"], cmd)
                    elif what == "held" or _stream_name(value):
                        cmd["opaque"] = True
                    else:
                        self.run_file(value, via + [name], cmd)
                code = _code_arg(_kind(name), args)
                if code is not None:
                    self.scan(_kind(name), code, pid, via + [name + " code"], cmd)
                elif _kind(name) in CODE_FLAGS and (i := _script_operand(_kind(name), args)) is not None:
                    # a script the line may write
                    self.run_file(args[i], via + [name], cmd, gives=args[i + 1:], unread=unreadable[i + 1])
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
        calls, loose = _py_calls(code) if kind == "python" else _CALL, False
        for m in calls.finditer(code):
            if kind == "python" and m.group(1) == "exec":
                continue   # Python's exec runs Python, not a shell
            i = m.end()
            items, end = _call_args(kind, code, i, "(" in m.group(2), self.charge)
            self.charge(end - i)   # overlapping calls read the same text again
            first = items[0] if items else None
            loose |= calls not in (_CALL, _PY_CALL) and not isinstance(first, (tuple, list))
            words = [w for it in items for w in ([it] if isinstance(it, tuple) else it or [])]
            if isinstance(first, tuple):   # a command line (system's, a shell=True string) or a program's name
                self.nested(_text_of(first), via)
            # every literal is the argv, the call's own words or a list's or tuple's (spawnSync("git", ["push"]));
            # exec's and spawn's first is the file, then the argv (os.execlp("git", "git", "push")); an argument the
            # code makes at run time (`chr(45) + "f"`, f"{rev}:f", "%s" % x) is a value the parser doesn't know there,
            # read as an unknown variable is (_arg_text)
            if isinstance(first, list) or len(words) > 1:
                self.argv(words, pid, via)
                if len(words) > 2 and re.match(r"exec|spawn", m.group(1).rsplit(".", 1)[-1]):
                    self.argv(words[1:], pid, via)
        # Perl's and Ruby's open of a pipe ("|cmd", "cmd|", or "-|" and the command's words); awk's "cmd" | getline and
        # print | "cmd" (a shell there runs what the program prints: each of its literals); Ruby's %x() and Perl's qx()
        for m in re.finditer(r"\bopen\s*(\(?)", code) if kind in ("perl", "ruby") else ():
            items, end = _call_args(kind, code, m.end(), bool(m.group(1)), self.charge)
            self.charge(end - m.end())
            texts = [it for it in items if isinstance(it, tuple)]
            for n, it in enumerate(texts):
                text = _text_of(it).strip()
                if text in ("-|", "|-") and texts[n + 1:]:   # one word is a shell's line, more a command's words
                    if len(texts) == n + 2:
                        self.nested(_text_of(texts[n + 1]), via)
                    else:
                        self.argv(texts[n + 1:], pid, via)
                    break
                if text.startswith("|") or text.endswith("|"):
                    self.nested(text.strip("|"), via)
        for body, printed in _awk_pipes(code) if kind == "awk" else ():
            text = _c_unescape("awk", body)
            self.nested(text, via)
            loose |= printed and bool(w := text.split()) and w[0].rsplit("/", 1)[-1] in SHELLS
        for m in _QX.finditer(code) if kind in ("perl", "ruby") else ():
            close = code.find(_PAIRS[m.group(1)], m.end())
            self.charge((len(code) if close < 0 else close) - m.end())
            if close >= 0:
                self.nested(code[m.end():close], via)
        # a delete of a folder and all it holds (shutil.rmtree, fs.rmSync, File::Path's rmtree, FileUtils.rm_rf): rm -rf
        # of its first argument, so TK-D004 and the other delete rules read it
        for m in _DELETES[kind].finditer(code) if kind in _DELETES else ():
            items, end = _call_args(kind, code, m.end(), "(" in m.group(), self.charge)
            self.charge(end - m.end())
            if items and isinstance(items[0], tuple):
                self.argv([("rm",), ("-rf",), items[0]], pid, via)
        # a spawner given a name, not a literal: what it runs may be any of the code's literals, each read as shell (one
        # that isn't shell leaves the program unreadable)
        for text in _literals(kind, code, self.charge) if loose else ():
            depth = self.ctx["depth"]
            try:
                self.nested(text, via)
            except ParseError:
                if self.ctx["work"][0] > MAX_WORK or cmd is None:
                    raise
                self.ctx["depth"], cmd["opaque"] = depth, True
        for m in _TICK.finditer(code) if kind in ("perl", "ruby", "php") else ():
            self.nested(m.group(1), via)

    def argv(self, words, pid, via):
        """Run `words` (each _arg_text's pieces) as a command: its literals, or with a value the code makes at run time
        read as an unknown variable in its place."""
        if all(None not in w for w in words):
            self.emit(["".join(w) for w in words], pid, via)
        else:
            self.nested(" ".join("".join('"%s"' % UNKNOWN if p is None else shlex.quote(p) for p in w) or "''"
                                 for w in words), via)

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
            # an unquoted heredoc's substitutions run now, in this shell (in its quotes too, which are text here), and
            # what reads it gets the text they and its escapes make; one whose value the parser can't name (unsafe's code
            # reading) may make code that a shell reading it, or a script it is copied into, runs; at's or batch's runs
            # later, outside the call (engine._SCHEDULED): only text the line makes is
            text = empty = body
            if d["expand"]:
                p, parts, first = _Parser(body, self.ctx, d["via"] + ["<<"]), [], len(self.ctx["cmds"])
                p.known = d["known"]   # what the line knew at its command
                text = p.dquote(None, buf=parts)
                made, code = _prints(self.ctx["cmds"][first:], self.ctx), not shell or shell["argv"][0] in SHELLS
                d["unknown"] = any(isinstance(x, _Expansion) and p.unsafe(x, made, code) for x in parts)
                if shell and d["unknown"]:
                    shell["opaque"] = True
                # and with each expansion as what it is when its variable is empty, as words are read again: a
                # shell reading `$'\163${X}\165\144\157'` runs sudo
                empty = "".join(x.empty if isinstance(x, _Expansion) else x for x in parts)
            d["text"] = text   # what a file it is copied into holds (run_file)
            if shell:
                for code in dict.fromkeys((text, empty)):
                    self.nested(code, shell["via"] + [shell["argv"][0] + " <<"])
            elif interp:
                self.program(interp, text, " <<")

    def relex(self, piece):
        """word() over one word a brace expansion or $IFS made (_brace refuses a substitution in it), or None for an
        empty one (a backslash-newline alone too), which bash drops."""
        saved = self.s, self.i
        self.s, self.i = piece, 0
        try:
            word = self.word()
            return word if word and word[1] else None
        finally:
            self.s, self.i = saved

    def word(self):
        """Return (text, raw source, has an unquoted glob or brace expansion, has a parameter expansion or command
        substitution), or None at an operator or the end. The raw source leaves out an unquoted backslash-newline:
        bash deletes it before it reads the word, so `ti\\<newline>me` is the keyword time. self.vanish: the word is only
        unquoted parameter expansions and command substitutions, which bash drops when they expand to nothing. self.cut:
        its text in each second reading (simple()): as written; with each expansion that has a word as that word
        (_Expansion.alt: ${X:+w} is w); with each of those empty, as bash joins an empty one into the rest of the word;
        and with only those empty that touch a character other than / = : , @ (`${X}push`, not `repos/$R/x`, which
        rules read as built at run time); each again keeping a bare $HOME. A word that is only those is empty in each,
        but where one of them has a word. self.readings: each text it makes as its expansions combine (ways()), None past
        MAX_READINGS; self.parts and self.ways_: its pieces and their ways, which simple() combines across words."""
        s, start, buf, bare, exp, joins, alone, ifs = self.s, self.i, [], [], self.ctx["exp"], [], True, []
        unsplit = False
        first = len(self.ctx["cmds"])   # the commands its substitutions run follow
        while self.i < len(s):
            if m := _PLAIN.match(s, self.i):   # a run of plain characters, read in one step
                alone = False
                bare.append(m.group())
                buf.append(m.group())
                self.i = m.end()
                continue
            c = s[self.i]
            if c in "<>" and self.peek(1) == "(":
                alone = False   # a process substitution is a file name, never nothing
                at, first = self.i, len(self.ctx["cmds"])
                self.i += 2
                self.ctx["exp"] += 1
                self.sub(c + "()")
                if len(self.ctx["cmds"]) == first:   # bash 5 makes an empty one nothing (<()x is x)
                    raise ParseError("an empty process substitution is not supported")
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
                    raise _Unclosed("unterminated '")
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
                elif _IFS_EXPANSION.match(buf[-1]):   # bash splits the word at what it may expand to,
                    unsplit = True                            # which the parser can't tell: its command is held
            elif c == "`":
                buf.append(self.backtick())
        if self.i == start:
            return None
        known = {} if self.ctx["any_set"] else self.known   # a known variable reads as written, never empty
        given = buf
        # a word with no expansion (each one counts in exp) is its text alone: none of what follows reads more of it
        plain = self.ctx["exp"] == exp
        self.exps = [] if plain else [p for p in buf if isinstance(p, _Expansion)]   # as written (simple)
        # a variable the line surely gave one literal expands to it, as bash runs it; unquoted, only a literal bash
        # neither splits nor globs (the others are fill()'s slots); none on a line that names IFS (literal())
        if self.ctx["exp"] != exp:
            buf = [v if isinstance(p, _Expansion) and (v := self.literal(p)) is not None else p for p in buf]
            # an unquoted pattern a known value holds globs as one written there would (`X='*'; eval echo $X`)
            vglob = any(isinstance(p, _Expansion) and not p.quoted and (m := _PLAIN_VARIABLE.fullmatch(p)) and
                        any(re.search(r"[*?[]", v) for v in known.get(m.group(1), ())) for p in buf)
        else:
            vglob = False
        text = "".join(buf)
        # a substitution in a subscript the word's literal text holds (x='a[$(cmd)]'): bash runs it wherever it
        # evaluates the value as a name or a number (analyse)
        if "$(" in text or "`" in text:
            # (an expansion is ${_} there, a value the line doesn't give: git${X} is a name it builds)
            literal = text if self.ctx["exp"] == exp else \
                "".join("${_}" if isinstance(p, _Expansion) else p for p in buf)
            if _SUBSTITUTION.search(literal) and _subscript_substitution(literal):
                self.ctx["subscripts"].append((literal, tuple(self.via)))
        self.vanish, self.cut, self.ifs, self.slots, self.full = False, (text,) * 6, ifs, None, False
        self.unsplit = unsplit   # an unquoted IFS expansion the parser can't split at (simple: held)
        # bash splits what an unquoted expansion expands to at IFS's characters (a blank, by default): its values
        # (its own, a word a ${F=w} gave, a literal the line gave a variable it doesn't know here: ways, maybe) are
        # read split
        # (self.splits: simple's combinations; fill() splits a known literal). self.values, with the known literals and
        # a number's characters, are held where the line may give IFS one of their characters, and so are the literals
        # given only later (a loop may run it first) of the variables it reads but doesn't know (_made_text)
        self.values, self.splits, self.unknown_names = ([], False, []) if self.ctx["exp"] != exp else ((), False, ())
        for p in buf if self.ctx["exp"] != exp else ():
            if isinstance(p, _Expansion) and not p.quoted:
                n = _value_of(p)
                own = [v for v in (*(p.values or ()), p.empty, p.alt or "", *self.ctx["defaults"].get(n, ()),
                                   *self.maybe(n, known)) if v and v != p]
                self.splits = self.splits or any(re.search(r"[ \t\n]", v) for v in own)
                self.values += own + list(known.get(n, ())) + ["-0123456789"] * bool(p[:3] == "$((" or
                                                                                    _NUMBER.fullmatch(p))
                if n and n not in known:
                    self.unknown_names.append((n, len(self.ctx["given"].get(n, ()))))
        # and each way its expansions combine (ways): None past MAX_READINGS, an unread word. A plain variable the line
        # knows is read as written here: its literals are fill()'s
        if plain:
            self.parts, self.ways_, self.readings = list(buf), {}, (text,)
            self.spliced = self.unknown = self.joined = self.given = False
            self.expanded = frozenset()
        else:
            self.parts = [str(p) if isinstance(p, _Expansion) and (m := _PLAIN_VARIABLE.fullmatch(p)) and
                          m.group(1) in known else p for p in buf]
            self.ways_ = self.ways(self.parts)
            readings = None if self.ways_ is None else self.combine(self.parts, self.ways_)
            self.readings = None if readings is None else tuple(readings)
            made = _prints(self.ctx["cmds"][first:], self.ctx)
            self.spliced = any(isinstance(p, _Expansion) and self.unsafe(p, made) for p in buf)
            self.unknown = any(isinstance(p, _Expansion) and self.unsafe(p, made, True) for p in buf)
            self.expanded = frozenset(m.group(1) for p in buf if isinstance(p, _Expansion)
                                      for m in [_VARIABLE_NAME.match(p)] if m)   # (_Expanded's names)
            # a parameter the parser didn't replace by its literal (a number's aside): what it joins may hold a
            # subscript arithmetic would run (`Z=$X$Y` of X='a[$' and Y='(cmd)]')
            self.joined = any(isinstance(p, _Expansion) and p[:2] != "$(" and p[:1] != "`" and
                              not _NUMBER.fullmatch(p) for p in buf)
            self.given = any(p is not q for p, q in zip(given, buf))   # a known variable's literal is in the word
        self.alone = alone and self.ctx["exp"] != exp   # only unquoted expansions: gone when they are empty
        if self.ctx["exp"] != exp:
            # every expansion in the word is a variable the line gives literals
            self.full = not self.ctx["ifs_named"] and all(
                not isinstance(p, _Expansion) or (m := _PLAIN_VARIABLE.fullmatch(p)) and known.get(m.group(1))
                for p in buf if p)
            pieces, glued, j = [str(p) if (m := _PLAIN_VARIABLE.fullmatch(p)) and m.group(1) in known else p
                                for p in buf if p], set(), 0
            # the text with each known variable that has literals as a slot, (name, quoted), for fill()
            slots = [(m.group(1), p.quoted) if isinstance(p, _Expansion) and (m := _PLAIN_VARIABLE.fullmatch(p)) and
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
            alt = "".join((p.empty if p.alt is None else p.alt) if isinstance(p, _Expansion) else p for p in pieces)
            self.cut = (empty[0], alt) + empty * 2 if self.vanish else (text, alt) + empty + (
                cut(lambda i, p: i not in glued), cut(lambda i, p: i not in glued or _HOME_WORD.fullmatch(p), True))
        bare = self.bare = "".join(bare)   # neither pattern backtracks: each scan from a `[` or `{` stops at the next bracket
        glob = _GLOB.search(bare) or "{" in bare and any("," in b or ".." in b for b in re.findall(r"\{[^{}]*\}", bare))
        raw = "".join(s[a + 2:b] for a, b in zip([start - 2] + joins, joins + [self.i])) if joins else s[start:self.i]
        return text, raw, bool(glob) or vglob, self.ctx["exp"] != exp

    def sub(self, label):
        saved = self.via, self.out, self.progs, self.data, self.data_steps, self.gone, dict(self.known), self.inherit, \
            self.piped
        self.via, self.out, self.progs, self.data, self.data_steps = self.via + [label], [], [], set(), []
        self.gone = [{} for _ in range(12)]
        self.inherit = self.inherit or self.piped or bool(self.blocks)   # the stdin of the command it is in
        self.list(")")
        self.flush()
        self.via, self.out, self.progs, self.data, self.data_steps, self.gone, self.known, self.inherit, self.piped = \
            saved   # a subshell's own

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
        a `}` inside quotes or a single quote around `}` or `"` (bash's posix mode reads those apart). There `buf` gets
        the text without its quotes, quoted text as _Quoted, `$'…'` and `$"…"` too (bash's extquote), for the
        expansion's word (dollar)."""
        self.enter()
        s, buf, quoted = self.s, [] if buf is None else buf, False
        while True:
            if self.i >= len(s):
                if term is None:
                    break
                raise (_Unclosed if term == '"' else ParseError)(f"unterminated {term}")
            c = s[self.i]
            if term == "}" and c == "\\":
                if self.peek(1) != "\n":   # bash deletes a backslash-newline
                    buf.append(_Quoted(self.peek(1)))
                self.i += 2
                continue
            if term == "}" and not quoted and (self.at('$"') or self.at("$'")):   # "…" translated; $'…' as '…' (one
                self.i += 1   # with a backslash is held below: bash may end it at a \')
                continue
            if term == "}" and c == "'" and not quoted:
                j = s.find("'", self.i + 1)
                if j < 0 or re.search(r"[}$`\\\"]" if in_dq else r"[$`\\]", s[self.i + 1:j]):
                    raise ParseError("a single quote around a special character in ${...} is not supported")
                buf.append(_Quoted(s[self.i + 1:j]))
                self.i = j + 1
                continue
            if term == "}" and c == '"':
                quoted = not quoted
                self.i += 1
                continue
            if c == term and quoted and in_dq:
                raise ParseError("a } inside quotes in a double-quoted ${...} is not supported")
            if c == term and not quoted:
                self.i += 1
                break
            # a backslash takes $ ` \ and a newline as text, and " too but in a heredoc
            if c == "\\" and self.peek(1) and self.peek(1) in ('$`\\\n' if term is None else '$`"\\\n'):
                if self.peek(1) != "\n":
                    buf.append(self.peek(1))
                self.i += 2
            elif c == "$":
                buf.append(self.dollar(True))
            elif c == "`":
                buf.append(self.backtick())
            else:
                buf.append(_Quoted(c) if quoted else c)
                self.i += 1
        self.leave()
        return "".join(buf)

    def dollar(self, in_dq):
        s, start, nxt, op, pieces = self.s, self.i, self.peek(1), None, []
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
                if self.ctx["any_set"] or not self.known.get(m.group()):
                    self.ctx["unresolved"].add(m.group())
                return _Expansion("$" + m.group())
        if nxt == "'" and not in_dq:
            m = re.compile(r"((?:\\.|[^'\\])*)'", re.S).match(s, self.i + 2)
            if not m:
                raise _Unclosed("unterminated $'")
            self.i = m.end()
            return _ansi_c(m.group(1))
        if nxt == '"' and not in_dq:
            self.i += 2
            return self.dquote('"')
        if nxt not in ("(", "{", "[") and not _NAME.match(s, self.i + 1):   # a lone $ is itself: a literal
            self.i += 1
            return "$"
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
            self.ctx["arith_names"].update(_arith_names(arithmetic_body))
            self.arith_sets(arithmetic_body)
            possible_subscript = re.sub(r"\$\{[^{}]*\}|\$[A-Za-z_][A-Za-z0-9_]*", "", arithmetic_body)
            builds_substitution = re.search(r"\$\{[^{}]*\$\}\s*\(", arithmetic_body)
            if "$(" in arithmetic_body or "`" in arithmetic_body or (
                    "[" in arithmetic_body and ("$" in possible_subscript or builds_substitution or
                                                "$" in arithmetic_body and self.line_substitutes())):
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
            self.dquote("}", in_dq, buf=pieces)
            if op := _OPERATOR.match("".join(p if type(p) is str and len(p) == 1 else "\x01" for p in pieces)):
                pieces = pieces[op.end():]   # its word
        elif nxt == "[":   # lean: bash's old $[ ] arithmetic is held, not read; read it as $(( )) if commands use it
            raise ParseError("$[ ] arithmetic is not supported")
        else:
            m = _NAME.match(s, self.i + 1)
            self.i = m.end() if m else self.i + 1
            # bash deletes a backslash-newline first, so a name runs on past one (`$X\⏎d` is $Xd)
            while s.startswith("\\\n", self.i) and m and m.group()[0] not in "0123456789@*#?$!-" and \
                    (n := re.compile(r"(?:\\\n)+\w+").match(s, self.i)):
                self.i = n.end()
        text = s[start:self.i]
        bare = text.replace("\\\n", "") if "\\\n" in text else text   # bash deletes a backslash-newline first
        if bare[1:2] in ("(", "{") and (e := _EVALUATES.match(bare)):
            self.ctx["arith"] = True
            if bare[1] == "{":   # an offset's or subscript's names: bash evaluates their values
                self.ctx["arith_names"].update(_arith_names(bare[e.end():-1]))
                self.arith_sets(bare[e.end():-1])
        # ${!x}: x's value names the variable, a subscript in it evaluated
        if (v := _INDIRECT.match(bare)) and \
                v.group(1) in self.ctx["unread_values"] | self.ctx["joined_values"]:
            raise ParseError("an indirect ${!x} of a value the parser can't read is not supported")
        assigned = "=" in bare and _ASSIGNS.match(bare)
        if assigned and assigned.group(1) in _CODE_VARIABLES:
            raise ParseError(f"${{{assigned.group(1)}=…}} is not supported")
        if _NAME_LIST.fullmatch(bare):   # the names of the variables set as it runs: an expansion may have set one
            self.ctx["assigns"] = True
        if bare.startswith("${") and bare.endswith("@P}"):   # its value expanded as a prompt is
            v = re.fullmatch(r"\$\{([A-Za-z_]\w*)@P\}", bare)
            known = {} if self.ctx["any_set"] else self.known
            if not (v and known.get(v.group(1))):
                raise ParseError("${…@P} of a value the line doesn't give is not supported")
            for value in known[v.group(1)]:
                self.prompt(value, self.via + ["@P"])
        # quoted, IFS as bash sets it: code made of it (sh -c "a${IFS}b") is two lines; any other spelling of it, or a
        # name that may be it (${!x}), is held
        if in_dq and ("IFS" in bare or "!" in bare) and (
                re.match(r"\$\{?IFS(?!\w)", bare) or re.fullmatch(r"\$\{![A-Za-z_]\w*\}", bare)):
            if bare not in ("$IFS", "${IFS}") or "IFS" not in self.known or self.ctx["any_set"]:
                raise ParseError("a quoted $IFS the parser can't read is not supported")
            return " \t\n"
        # a variable read without a value the line gives it
        if v := _READ_VARIABLE.match(text):
            if v.group(1) or self.ctx["any_set"] or not self.known.get(v.group(2)):
                self.ctx["unresolved"].add("*" if v.group(1) else v.group(2))
        # HOME is set unless this line may have emptied it, and so is a variable the line gave only literals that aren't
        # empty: its default, assignment or check is the variable ($HOME as the packs name it, ${HOME:-x}, ${HOME:?}; or
        # the literal the line gave it, D=/; rm -rf "${D:?}"/); the default stays what it is when it may be empty
        named = _DEFAULT.fullmatch(text)
        values = self.known.get(named.group(1)) if named and not (self.ctx["any_set"] and named.group(1) == "HOME") \
            else None
        plain = named and ("" not in (values or ()) if named.group(1) == "HOME" else bool(values) and "" not in values)
        # never nothing: a lone $, ${X:?...}, which stops the command instead, and arithmetic (a number the line can't
        # know, so a command name with one is unreadable: python$((3)) is python3); but a check of a variable a ${F=w}
        # may have given w is w too (ways)
        if not plain and (text == "$" or (q := _CHECKED.fullmatch(text)) and
                          q.group(1) not in self.ctx["defaults"]):
            return text
        if text.startswith("$(("):
            expansion = _Expansion(text)
            expansion.empty = expansion.word = text
            expansion.values = (text,)
            expansion.quoted = in_dq
            return expansion
        # always nothing, as written too: an empty alternative, a length of 0, all of it removed (${X:+}, ${X:0:0},
        # ${X%%*})
        if _ALWAYS_EMPTY.fullmatch(text):
            return _Expansion("")
        expansion = _Expansion("$" + named.group(1) if plain else bare if nxt not in "({" else text)   # ($X\⏎d: $Xd)
        expansion.quoted = in_dq
        # the word bash may expand it to: a default's or an assignment's, the value when the parameter is empty (also
        # set but empty, without the colon); an alternate's, when it is set; a substitution's replacement, when the
        # pattern matches all of it (the pattern ends at its first / outside quotes and nested expansions, a / first in
        # it its own; a bare & is the text matched, read as nothing; without a /, the matches are removed). Each is one
        # more value (`values`, with as written and empty where those may be), its own expansions read each way too
        # lean: a value made from the variable's own (#, %, a replacement's &, ^, ",", @Q and the other @ transforms,
        # a substring) is read as written and as nothing, as an unknown one, also of a variable the line gives a
        # literal (D=xy; ${D#x} isn't read as y); compute them on the literals if real commands need it
        if op and not plain:
            kind = op.group(1)
            end = next((i for i, p in enumerate(pieces) if i and type(p) is str and p == "/"), None)
            word = pieces if kind[0] != "/" else None if end is None else pieces[end + 1:]
            words = ()
            if word is not None:
                read = [_Quoted("") if kind[0] == "/" and type(p) is str and p == "&" else p for p in word]
                expansion.word = "".join(word)
                if kind[-1] in "-=":
                    expansion.empty = "".join(p.empty if isinstance(p, _Expansion) else p for p in read)
                expansion.alt = "".join((p.empty if p.alt is None else p.alt) if isinstance(p, _Expansion) else p
                                        for p in read)
                words = None if (ways := self.ways(read)) is None else self.combine(read, ways)
            expansion.unread = words is None
            words = tuple(words or ())
            expansion.values = ("",) + words if kind[-1] == "+" else (text,) + words if kind[0] == ":" else \
                (text, "") + words
        if assigned and not plain:   # X may get the word: no longer the literal the line gave it (a plain one keeps it)
            name = assigned.group(1)
            given = () if self.ctx["any_set"] else self.known.get(name, ())
            self.reassign(name)
            # a plain ${F=w} or ${F:=w} of a literal w: F may hold w, or the literals it had, for the rest of the line
            # (ways); any other assignment is one the parser can't follow: this command and the rest are unread (simple)
            m = _PLAIN_ASSIGN.match(bare)
            if m and expansion.values and not re.search(r"[$`]", bare[m.end():]) and \
                    name not in ("IFS", "HOME", "PWD", "PATH") and not _bash_sets(name):
                self.ctx["defaults"].setdefault(name, {}).update(dict.fromkeys((*given, *expansion.values[1:])))
            else:
                self.ctx["assigns"] = True
        return expansion

    def backtick(self):
        m = re.compile(r"((?:\\.|[^`\\])*)`", re.S).match(self.s, self.i + 1)
        if not m:
            raise ParseError("unterminated `")
        start, self.i = self.i, m.end()
        self.ctx["exp"] += 1
        # bash takes \`, \\ and \$ for the character, and deletes a backslash-newline, before it reads the text
        self.nested(re.sub(r"\\([`\\$])|\\\n", r"\1", m.group(1)), self.via + ["``"])
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


def _named(name, args):
    """The words builtin `name` (one of _NAME_BUILTINS, or let) takes as variable names (an assignment word for
    declare and its kin, an expression for let): read's (and its -a value), mapfile's and readarray's after their
    options and those options' values, wait -p's value, getopts' second operand, the -v values of printf, test, [ and
    [[, and the other builtins' words that aren't options. ParseError for mapfile's -C, whose callback runs code."""
    if name in ("test", "[", "[[", "printf"):
        return [b for a, b in zip(args, args[1:]) if a == "-v"] + [a[2:] for a in args if name == "printf" and a[:2] == "-v"]
    if name == "getopts":
        return args[1:2]
    if name not in ("read", "mapfile", "readarray", "wait"):
        return args if name == "let" else [a for a in args if not a.startswith(("-", "+"))]
    valued, out, i = {"read": "dinNptu", "wait": ""}.get(name, "dnOsuCc"), [], 0
    while i < len(args) and args[i].startswith("-") and args[i] != "--":
        a, i = args[i], i + 1
        for k, c in enumerate(a[1:], 2):
            if c == "C" and name != "read":
                raise ParseError("mapfile -C (a callback it runs) is not supported")
            names = c == "a" and name == "read" or c == "p" and name == "wait"   # -a NAME, wait -p NAME
            if names or c in valued:
                if names:
                    out.append(a[k:] or (args[i] if i < len(args) else ""))
                i += not a[k:]
                break
    return out + (args[i + (args[i:i + 1] == ["--"]):] if name != "wait" else [])


_TRACEKIT_MODULE = re.compile(r"tracekit(?:\.cli|\.__main__)?")
_TRACEKIT_SCRIPT = re.compile(r"(?i)(?:.*[/\\])?tracekit(?:\.exe|[/\\](?:__main__|cli)\.py)?[/\\]?")


def _python_runs(args, copies=frozenset()):
    """`tracekit …` where python's `args` run Tracekit's CLI: its module (-m tracekit, tracekit.cli or tracekit.__main__,
    -mtracekit, -Im, past options with a value: -X 'a b', -W), the one a module runner runs (runpy's first word; the
    first word not an option after a later -m or --module: cProfile, pdb, trace --module), or a script whose path
    names Tracekit's entry point (~/.local/bin/tracekit, a tracekit folder, its __main__.py or cli.py); else None.
    `copies`: the names the line copies or links Tracekit's entry point to (_tracekit_copies), as a script's or a
    module's (tk.py: -m tk) name."""
    i, module, rest = 0, None, []
    while i < len(args) and args[i].startswith("-") and args[i] not in ("-", "--"):
        m = re.fullmatch(r"-[bBdEhiIOPqsSuvVx]*([cmWX])(.*)", args[i], re.S)
        if args[i] == "--check-hash-based-pycs" or m and m.group(1) in "WX" and not m.group(2):
            i += 2
        elif m and m.group(1) == "c":
            return None
        elif m and m.group(1) == "m":
            module, rest = (m.group(2), args[i + 1:]) if m.group(2) else ((args[i + 1:i + 2] or [None])[0], args[i + 2:])
            break
        else:
            i += 1
    if module is None:
        i += args[i:i + 1] == ["--"]
        return ["tracekit", *args[i + 1:]] if i < len(args) and (
            _TRACEKIT_SCRIPT.fullmatch(args[i]) or _base(args[i]) in copies) else None
    while not (_TRACEKIT_MODULE.fullmatch(module) or {module, module.rpartition(".")[2] + ".py"} & copies):
        if module == "runpy" and rest:
            module, rest = rest[0], rest[1:]
        elif (k := next((j for j, w in enumerate(rest) if w in ("-m", "--module")), None)) is not None and \
                (j := next((j for j in range(k + 1, len(rest)) if not rest[j].startswith("-")), None)) is not None:
            module, rest = rest[j], rest[j + 1:]
        else:
            return None
    return ["tracekit", *rest]


def _script_operand(kind, args):
    """The index in `args` of the script file an interpreter of `kind` (one of CODE_FLAGS') runs: its first operand
    after its options (and their values); None for a module (python -m), stdin (-, a stream) or no operand."""
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] != "-":
        if args[i] == "--":
            i += 1
            break
        if kind == "python" and args[i].startswith("-m"):
            return None
        i += 2 if args[i] in INTERP_VALUE_OPTS else 1
    return i if i < len(args) and args[i] != "-" and not _stream(args[i]) else None


def _reader(text, runner, direct):
    """The program that reads a script file `runner` runs (a shell or one of CODE_FLAGS' interpreters), else None (no
    program this parser reads): run by its path (`direct`), the one its #! line names (an env one's command, with no
    option: env -S splits and -i empties what follows), or bash for a file without one; else `runner` itself
    (source and . are the shell's)."""
    if not direct:
        return "sh" if runner in ("source", ".") else runner
    if not text.startswith("#!"):
        return "sh"
    words = text[2:].split("\n", 1)[0].split()
    if words and words[0].rsplit("/", 1)[-1] == "env":
        words = [w for w in words[1:] if "=" not in w]
    program = words[0].rsplit("/", 1)[-1] if words and not words[0].startswith("-") else None
    return program if program in SHELLS or _kind(program or "") in CODE_FLAGS else None


_MAKE_EXPANSION = re.compile(r"\$\$|\$\([^()]*\)|\$\{[^{}]*\}|\$.", re.S)


def _recipes(text):
    """The shell lines a Makefile's text runs: each recipe line (a tab first, or after a rule's `;`; its @, - and +
    dropped), each $(shell …) and != assignment's command, a backslash-newline joined; make's own expansions ($(X),
    ${X}, $@ …) read as a value the parser doesn't know, $$ as $."""
    text = text.replace("\\\n", " ")
    lines = re.findall(r"\$\(shell\s([^()]*)\)", text)
    for line in text.split("\n"):
        if line.startswith("\t"):
            lines.append(line[1:])
        elif (m := re.match(r"[^\t#=:]+:(?![=:])[^;=#]*;(.*)", line)) or (m := re.match(r"[^#=]*!=(.*)", line)):
            lines.append(m.group(1))
    return [_MAKE_EXPANSION.sub(lambda m: "$" if m.group() == "$$" else UNKNOWN, x.lstrip(" \t@+-")) for x in lines]


# .npmrc and .yarnrc keys whose value npm or yarn runs, or that name a program or a file of more config
_NPMRC_RUNS = re.compile(r"(?im)^\s*[\"']?(?:script-shell|shell|git|editor|browser|viewer|node-options|onload-script|"
                         r"init-module|userconfig|globalconfig|prefix|yarnPath|plugins|scriptShell)\b")


def _config_lines(kind, text):
    """The shell lines a config file `kind` gives (None: one that can't be read, held): a Makefile's recipes, the
    scripts of a package.json (npm, yarn, pnpm and bun run them, and install runs its lifecycle ones), an .npmrc's that
    names a program (None), and git's config as the `git config KEY VALUE` lines it amounts to (its include None)."""
    if kind == "make":
        return _recipes(text)
    if kind == "npmrc":
        return [None] if _NPMRC_RUNS.search(text) else []
    if kind == "scripts":
        try:
            scripts = json.loads(text).get("scripts", {})
        except (ValueError, AttributeError):
            return [None]
        return [v if isinstance(v, str) else None for v in scripts.values()] if isinstance(scripts, dict) else [None]
    section, out = None, []
    for line in text.split("\n"):
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        if m := re.fullmatch(r'\[\s*([^\]\s"]+)(?:\s+"((?:\\.|[^"\\])*)")?\s*\]', line):
            section = m.group(1) + ("" if m.group(2) is None else "." + m.group(2))
            continue
        key, eq, value = line.partition("=")
        if section is None:
            continue
        if section.lower().startswith("include"):
            return [None]
        value = value.strip()
        value = value[1:-1] if len(value) > 1 and value[0] == value[-1] == '"' else value
        out.append(f"git config {shlex.quote(section + '.' + key.strip())} {shlex.quote(value if eq else 'true')}")
    return out


def _ext_words(url):
    """The argv git's ext:: transport runs for `url` (after ext::): words at unescaped spaces, `% ` a space, `%%` a %, %s
    and %S the service's name (upload-pack, git-upload-pack), %G and %V nothing."""
    words, cur = [], []
    for m in re.finditer(r"%(.)|( )|([^% ]+|%$)", url, re.S):
        if m.group(2):
            words.append("".join(cur))
            cur = []
        else:
            cur.append(m.group(3) if m.group(1) is None else
                       {" ": " ", "%": "%", "s": "upload-pack", "S": "git-upload-pack"}.get(m.group(1), ""))
    return [w for w in words + ["".join(cur)] if w]


# tmux's names of the keys that type a blank or end a line
_TMUX_KEYS = {"Space": " ", "Enter": "\n", "KPEnter": "\n", "C-m": "\n", "C-j": "\n", "^M": "\n", "^J": "\n",
              "Tab": "\t", "C-i": "\t"}


def _typed(text):
    """What screen's `stuff` types for `text`: its \\ooo octal, \\n, \\r, \\t and \\\\ escapes and ^X control
    characters decoded."""
    return re.sub(r"\\([0-7]{1,3})|\\([nrt\\^])|\^(.)", lambda m: chr(int(m.group(1), 8)) if m.group(1) else
                  {"n": "\n", "r": "\r", "t": "\t"}.get(m.group(2), m.group(2)) if m.group(2) else
                  chr(ord(m.group(3).upper()) & 0x1F), text)


def _git_config_env(given):
    """git's -c pairs the environment gives it (GIT_CONFIG_KEY_<n> and GIT_CONFIG_VALUE_<n>, each literal the line
    gives them), as `-c KEY=VALUE` words."""
    return [w for name in sorted(given) if name.startswith("GIT_CONFIG_KEY_")
            for key in given[name] for value in given.get("GIT_CONFIG_VALUE_" + name[15:], ())
            for w in ("-c", f"{key}={value}")]


def _stdin_shell(cmds):
    """A shell reading its script from stdin, or at or batch, which read from it the commands they schedule."""
    return next((c for c in cmds if c["argv"][0] in SHELLS and _shell_mode(c["argv"][1:])[0] == "stdin"
                 or c["argv"][0] in ("at", "batch")), None)


def _stdin_interpreter(cmds):
    """An interpreter reading its program from stdin, or make its Makefile (-f -, -f /dev/stdin)."""
    return next((c for c in cmds if _kind(c["argv"][0]) and _reads_stdin(_kind(c["argv"][0]), c["argv"][1:]) or
                 c["argv"][0] in ("make", "gmake") and any(map(_stream_name, _program_files(c["argv"][1:])))), None)


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
