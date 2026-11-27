"""CLI grammars: an argv read as its CLI reads it (policy v2, docs/policy-v2.md#cli-grammars).

`read(command)` turns one parsed shell command (shell.analyse's dict) of a CLI with a table in grammars/ into a
Reading: its program, its command path (`release create`), its flags ({canonical name: [values]}, in order, a switch's
value "true" or "false") and its positionals, or None when the argv doesn't fit the grammar: an unknown subcommand or
flag, an abbreviated flag, a detached value that starts with `-` (a flag's spelling), too many or too few positionals,
or a word the line doesn't fix (a `$`, a backquote, a glob, a command run by xargs, parallel, find or fd, which add
words), but a double-quoted expansion the parse takes as a flag's value or a positional after `--`, and a folder's
pattern of paths (`dist/*`) it takes as a positional (read). A rule reads
a Reading only through `unless_cli` (engine); an argv that doesn't fit is read as text, as before.

Each table is generated from its CLI's own definition by scripts/gen_cli_grammars.py and names the release and commit
it came from. A table: {program, style, source, commands: {path: node or alias path}}; a node: f (its own flags), p
(flags it and its subcommands take), a ([min, max] positionals, max None: any), i (false: flags end at the first
positional), r (true: it parses no flags). A flag's kind: 0 a switch, 1 one value, "+" one or more (argparse), "?" an
optional value (given as `--x=v` or `-xv`; argparse also takes the next word that isn't an option), "x" a value the
grammar can't read; a string names the flag it spells (`-d`: `--draft`), with `!` a switch's negation (`--no-promote`:
`!--promote`).
"""
import collections
import functools
import json
import os
import re

# `words`: the argv with its command path as the table names it (an alias read as its command: `gh release new` is
# `gh release create`), the other words after it in their order; None for a style whose tables have no alias
Reading = collections.namedtuple("Reading", "program command flags positionals words")
DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "grammars")
PROGRAMS = frozenset(f[:-5] for f in os.listdir(DIR) if f.endswith(".json")) if os.path.isdir(DIR) else frozenset()
_ADDS_WORDS = {"xargs", "gxargs", "parallel", "find", "fd"}   # a runner that may append any word to what it runs
_UNFIXED = re.compile(r"[$`]")   # a word the line doesn't fix: an expansion (shell's argv keeps it; a glob: `glob`)
# a pattern of paths in a folder (`dist/*`, `./build/*.tgz`): every name it matches starts with that folder, so none is
# a flag or a subcommand; one with a pattern before its first `/` (`*`, `v*`) may match `--draft=false` or `view`. Not
# one with a `:` there (a URL's scheme): a URL's pattern is no file's
_PATH_GLOB = re.compile(r"[^-*?\[{$`/:][^*?\[{$`/:]*/|/")
_TRUE = {"1", "t", "T", "TRUE", "true", "True"}   # Go's strconv.ParseBool, as pflag and Go's flag read a switch
_FALSE = {"0", "f", "F", "FALSE", "false", "False"}


def program_of(command):
    """The program an unless_cli `command` pattern names: its leading word (`terraform` of `terraform( [a-z-]+)+`)."""
    return re.match(r"[a-z][a-z0-9-]*", command).group() if re.match(r"[a-z]", command) else ""


@functools.lru_cache(maxsize=None)
def table(program):
    with open(os.path.join(DIR, program + ".json"), encoding="utf-8") as f:
        return json.load(f)


def read(command):
    """The Reading of a shell command, or None (module docstring). A word whose expansions are all double-quoted and
    that has no pattern (shell's `whole`: one word, whatever its value) fixes the reading where the parse takes it as a
    flag's detached value (`curl -u "$KEY:"`, `--notes "$N"`) or as a positional after `--`; anywhere else it may be a
    flag (`gh release create "$TAG" -d` with TAG=--notes takes -d as the notes), and the argv doesn't fit. A pattern
    of paths in a folder (_PATH_GLOB: `dist/*`) fixes it as a positional or a value; any other (`*`) may match a flag."""
    argv = command["argv"]
    if argv[0] not in PROGRAMS or command.get("opaque") or any(
            v.split(" ", 1)[0] in _ADDS_WORDS for v in command.get("via", ())):
        return None
    held = [w for w in argv[1:] if _UNFIXED.search(w)]
    globs = [w for w in argv[1:] if getattr(w, "glob", False)]   # (a reading where one matched nothing has none)
    if _UNFIXED.search(argv[0]) or getattr(argv[0], "glob", False) or not all(
            getattr(w, "whole", False) for w in held) or not all(_PATH_GLOB.match(w) for w in globs):
        return None
    try:
        t = table(argv[0])
    except (OSError, ValueError):   # a table missing or broken: the command reads as text, as with none
        return None
    got = _STYLES[t["style"]](t, list(argv[1:]))
    if got is None:
        return None
    path, flags, positionals, rest = got
    if held or globs:   # (each as the very word the parse took: a value, or a positional after the first `--`; a
        values = {id(v) for vs in flags.values() for v in vs}   # path's glob a positional anywhere)
        after = {id(w) for w in argv[argv.index("--") + 1:]} if "--" in argv else set()
        taken = {id(p) for p in positionals}
        if not all(id(w) in values or id(w) in after and id(w) in taken for w in held) or \
                not all(id(w) in values or id(w) in taken for w in globs):
            return None
    lo, hi = _node(t, path).get("a", (0, None))
    helped = flags.get("--help", [""])[-1] == "true"   # (help is shown before missing positionals are counted)
    if len(positionals) < lo and not helped or hi is not None and len(positionals) > hi:
        return None
    return Reading(argv[0], " ".join(path), flags, tuple(positionals),
                   None if rest is None else (argv[0], *path, *rest))


@functools.lru_cache(maxsize=None)
def aliased(program):
    """Whether a program's table names an alias (a word for another command: gh's `release new`)."""
    if program not in PROGRAMS:
        return False
    try:
        return any(isinstance(v, str) for v in table(program)["commands"].values())
    except (OSError, ValueError):
        return False


@functools.lru_cache(maxsize=None)
def _alias_words(program):
    """The words that name an alias of a program's table (the last of each alias path: `new` of `release new`)."""
    return frozenset(path.split()[-1] for path, v in table(program)["commands"].items() if isinstance(v, str))


def canonical(command):
    """A shell command's argv as its CLI's table names its command where an alias made it differ (`gh release new` is
    `gh release create`), as one string, else None: the command path a cobra CLI finds from the leading words alone
    (_find), whatever the rest of the argv is (a glob, an expansion, a value spelled as a flag, a runner that adds
    words); another style's as its Reading's words."""
    argv = command["argv"]
    try:
        t = table(argv[0]) if argv[0] in PROGRAMS else None
    except (OSError, ValueError):
        t = None
    if t is None:
        return None
    if t["style"] != "cobra":
        reading = read(command)
        words = reading and reading.words
    elif _alias_words(argv[0]).isdisjoint(argv[1:]):   # (no alias in its words: its path as written)
        return None
    else:
        path, at, _, _ = _find(t, argv[1:])
        words = (argv[0], *path, *(w for k, w in enumerate(argv[1:]) if k not in at)) if [
            argv[1 + k] for k in at] != list(path) else None
    return " ".join(words) if words and list(words) != list(argv) else None


def command_path(command):
    """The command path a cobra CLI finds from an argv's leading words alone (_find), whatever the rest is; () for
    another style or a program with no table."""
    argv = command["argv"]
    try:
        t = table(argv[0]) if argv[0] in PROGRAMS else None
    except (OSError, ValueError):
        t = None
    return _find(t, argv[1:])[0] if t and t["style"] == "cobra" else ()


def subcommand(argv, program, valued=frozenset()):
    """The word in an argv's subcommand position (subcommand_at), or None when there is none."""
    i = subcommand_at(argv, program, valued)
    return argv[i] if i < len(argv) else None


def subcommand_at(argv, program, valued=frozenset(), path=()):
    """The index of the word in an argv's subcommand position (len(argv) for none): the first after the program that
    is no option or an option's value, each read by the program's table where it has one (the flags of `path`, the
    command group the argv's words follow, its root by default: `git -C dir push`, `kubectl -n x apply`; a cobra
    CLI's as cobra finds a subcommand, an option it doesn't know taking the next word: _cobra_skip), else by `valued`,
    the options the caller knows take a value (`yarn --cwd "$DIR" build`). Any other option is read as a switch, and
    so is one whose value is optional or that the table can't read (? and x) where an expansion follows it: that
    expansion may be the subcommand (`npm -s "$X"`, `helm --debug $X`)."""
    try:
        t = table(program) if program in PROGRAMS else None
        scope = _scope(program, path) if t else {}
    except (OSError, ValueError):
        t, scope = None, {}
    except KeyError:   # (a group the table doesn't name: a plugin's, docker compose, gcloud app services): the flags
        # every command below the deepest path it names takes (gcloud's --project), read without cobra's rules
        scope = {f: v for k in range(len(path)) if " ".join(path[:k]) in t["commands"]
                 for f, v in _node(t, path[:k]).get("p", {}).items()}
        t = None
    i = 1
    while i < len(argv) and argv[i].startswith("-") and argv[i] != "-":
        if t is not None and t["style"] == "cobra":
            i += _cobra_skip(scope, argv, i)
            continue
        got = None if "=" in argv[i] else _resolve(scope, argv[i])
        kind = got[1] if got is not None else 1 if "=" not in argv[i] and argv[i] in valued else 0
        told = i + 1 < len(argv) and not _UNFIXED.search(argv[i + 1])
        i += 2 if kind not in (0, "?", "x") or kind == "x" and told else 1
    return min(i, len(argv))


@functools.lru_cache(maxsize=4096)   # (the paths are a call's words: bounded)
def children(program, path):
    """The words a program's table names right after a command path (a tuple: git's `("config",)`: get, set, edit, …;
    gcloud's `("run", "services")`: update); none for a program or path no table names, or a command with none under
    it."""
    try:
        return frozenset(words[len(path)] for words in map(str.split, table(program)["commands"])
                         if len(words) > len(path) and tuple(words[:len(path)]) == path)
    except (OSError, ValueError):
        return frozenset()


@functools.lru_cache(maxsize=None)
def _deepest(program):
    """The most words a command of the program's table has."""
    return max(len(path.split()) for path in table(program)["commands"])


def _node(t, path):
    return t["commands"][" ".join(path)]


def _child(t, path, word):
    """The path one word below `path` names (a subcommand or an alias of one), or None: a word with a blank in it
    (`"release create"`, one argument) names none."""
    got = None if word[:1] == "-" or not word or re.search(r"\s", word) else t["commands"].get(" ".join((*path, word)))
    if got is None:
        return None
    return tuple(got.split()) if isinstance(got, str) else (*path, word)


@functools.lru_cache(maxsize=4096)
def _scope(program, path):
    """{spelling: kind} of the flags a command takes: every `p` from the root down, then its own `f`."""
    t, out = table(program), {}
    for k in range(len(path) + 1):
        out.update(_node(t, path[:k]).get("p", {}))
    out.update(_node(t, path).get("f", {}))
    return out


def _resolve(scope, spelling):
    """(canonical name, kind, negated) of a flag's spelling, or None when the command doesn't take it."""
    kind = scope.get(spelling)
    if kind is None:
        return None
    if not (isinstance(kind, str) and kind[:1] in ("-", "!")):
        return spelling, kind, False
    return kind.lstrip("!"), scope[kind.lstrip("!")], kind[0] == "!"


def _switch(value, negated=False):
    """A switch's value ("true", "false") from Go's ParseBool spellings, or None."""
    v = True if value in _TRUE else False if value in _FALSE else None
    return None if v is None else str(v != negated).lower()


def _detached(args, i):
    """The value at args[i] for the flag before it, or None: none left, or one spelled as a flag (`-d`); `-` alone
    (standard input) is a value."""
    if i >= len(args) or args[i].startswith("-") and args[i] != "-":
        return None
    return args[i]


def _options(scope, args, interspersed=True, switch_eq=_switch, one_dash_long=False, short_eq=False):
    """(flags, positionals) of `args` read as a getopt-style option parser reads them, or None on an error it would give
    or a reading this one can't be sure of. `--` ends the options; `--name=value`, or `--name value` for a flag that
    takes one; a cluster of short switches (`-sSL`) ends at a short flag that takes a value, which is the rest of the
    cluster or the next word. `interspersed`: False ends the options at the first positional (Go's flag, cobra's
    SetInterspersed(false)). `switch_eq(value, negated)`: a switch's value given as `--name=value`, None where the
    parser refuses one. `one_dash_long`: `-name` is `--name` (Go's flag: no clusters). `short_eq`: pflag's `-n=value` is n's value `value` (getopt's is `=value`)."""
    flags, pos, i = {}, [], 0
    while i < len(args):
        s = args[i]
        i += 1
        if len(s) < 2 or s[0] != "-":
            if not interspersed:
                return flags, pos + args[i - 1:]
            pos.append(s)
            continue
        if s == "--":
            return flags, pos + args[i:]
        long = s[1] == "-" or one_dash_long
        if long:
            name, eq, value = s.lstrip("-").partition("=")
            if s.startswith("---") or not name or name[0] == "=":
                return None
            got = _resolve(scope, "--" + name)
            if got is None or got[1] == "x":
                return None
            canon, kind, negated = got
            if kind in (0, "?") and not eq:
                value = str(not negated).lower() if kind == 0 else ""
            elif kind == 0 or negated:
                if (value := switch_eq(value, negated) if kind == 0 else None) is None:
                    return None
            elif not eq:
                if (value := _detached(args, i)) is None:
                    return None
                i += 1
            flags.setdefault(canon, []).append(value)
            continue
        j, n, resolved = 1, len(s), {}   # (by index, each letter resolved once: a cluster is read in one pass)
        while j < n:
            if (got := resolved.get(s[j], False)) is False:
                got = resolved[s[j]] = _resolve(scope, "-" + s[j])
            if got is None or got[1] == "x":
                return None
            canon, kind, negated = got
            if kind == 0 and not (short_eq and n > j + 2 and s[j + 1] == "="):   # a run of switches
                flags.setdefault(canon, []).append("false" if negated else "true")
                j += 1
                continue
            if short_eq and n > j + 2 and s[j + 1] == "=":   # pflag's `-n=value`
                if kind == "?" or (value := switch_eq(s[j + 2:], negated) if kind == 0 else s[j + 2:]) is None:
                    return None
                j = len(s)
            elif kind == 0:
                value, j = str(not negated).lower(), j + 1
            elif kind == "?" or len(s) > j + 1:
                value, j = s[j + 1:], len(s)
            else:
                if (value := _detached(args, i)) is None:
                    return None
                i, j = i + 1, len(s)
            flags.setdefault(canon, []).append(value)
    return flags, pos


def _cobra_skip(scope, args, i):
    """How many words cobra's stripFlags and Traverse take at args[i] while looking for a subcommand: a long flag
    without `=` and a two-character short one take the next word too unless they are switches (an unknown one does)."""
    s = args[i]
    if s.startswith("--") and "=" not in s:
        kind = scope.get(s)
    elif s.startswith("-") and "=" not in s and len(s) == 2:
        kind = scope.get(s)
    else:
        return 1
    if isinstance(kind, str):
        kind = scope.get(kind.lstrip("!")) if kind[:1] in ("-", "!") else kind
    return 1 if kind in (0, "?") else 2


def _merge(flags, more):
    for k, v in more.items():
        flags.setdefault(k, []).extend(v)


def _find(t, args):
    """cobra's Command.Find (Command.Traverse where the table says `traverse`) over `args`, by the words alone: (the
    command path, the index in args of each word that named it, the other words as (index, word) in their order, and
    for Traverse the (path, words) before each subcommand, which its parent parses)."""
    path, program, rest, at, before = (), t["program"], list(enumerate(args)), [], []
    while True:
        words, i, skips = [w for _, w in rest], 0, {}   # (a word's skip at this level, worked out once)
        scope = _scope(program, path)
        while i < len(words) and words[i] != "--" and (words[i][:1] == "-" or not words[i]):
            if (k := skips.get(words[i])) is None:
                k = skips[words[i]] = _cobra_skip(scope, words, i)
            i += k
        child = _child(t, path, words[i]) if i < len(words) and words[i] != "--" else None
        if child is None:
            return path, at, rest, before
        at.append(rest[i][0])
        if t.get("traverse"):
            before.append((path, words[:i]))
            rest = rest[i + 1:]
        else:
            rest = rest[:i] + rest[i + 1:]
        path = child


def _cobra(t, args):
    """spf13/cobra: the command path (_find: Command.Find, or Command.Traverse where the table says `traverse`: then the
    flags before each subcommand are parsed by its parent), then pflag over the rest with the command's flags."""
    path, _, rest, levels = _find(t, args)
    program, flags, before_words = t["program"], {}, []
    for level, words in levels:
        before = _options(_scope(program, level), words, short_eq=True)
        if before is None or before[1]:
            return None
        _merge(flags, before[0])
        before_words += words
    args = [w for _, w in rest]
    node = _node(t, path)
    if node.get("r"):
        return path, flags, args, before_words + args
    got = _options(_scope(program, path), args, node.get("i", True), short_eq=True)
    if got is None:
        return None
    _merge(flags, got[0])
    return path, flags, got[1], before_words + args


def _argparse(t, args):
    """argparse, as the AWS CLI and gcloud (calliope) use it: options anywhere, by their whole name (neither allows an
    abbreviation), as `--name=value` or `--name value`; a list option takes every word up to the next option; a word
    that names a subcommand of the command reached descends while no positional came before it."""
    path, program, flags, pos, i = (), t["program"], {}, [], 0
    while i < len(args):
        s = args[i]
        i += 1
        if s == "--":   # the rest are positionals
            pos += args[i:]
            break
        if s[:1] != "-" or s == "-":
            child = None if pos else _child(t, path, s)
            if child is None:
                pos.append(s)
            else:
                path = child
            continue
        name, eq, value = s.partition("=") if s.startswith("--") else (s, "", "")
        got = _resolve(_scope(program, path), name)
        if got is None or got[1] == "x":
            return None
        canon, kind, negated = got
        if kind == 0:
            if eq:
                return None
            values = [str(not negated).lower()]
        elif eq:
            values = [value]
        else:
            values = []
            while (kind == "+" or not values) and (v := _detached(args, i)) is not None:
                values.append(v)
                i += 1
            if not values and kind != "?":
                return None
        flags.setdefault(canon, []).extend(values or [""])
    return path, flags, pos, None


_HELP_WORDS = ("-h", "-help", "--help")


def _hashicorp(t, args):
    """hashicorp/cli as terraform runs it: -h, -help or --help anywhere before `--` asks for help and runs nothing;
    -chdir=DIR before the subcommand; the subcommand is the longest command the leading plain words name; Go's flag
    package reads its own arguments (`-name` is `--name`; options end at the first positional)."""
    end = args.index("--") if "--" in args else len(args)
    helped = any(a in _HELP_WORDS for a in args[:end])
    flags, j = {}, 0
    while j < len(args) and args[j].startswith("-"):
        if args[j].startswith("-chdir=") and len(args[j]) > 7:
            flags["--chdir"] = [args[j][7:]]
        elif args[j] not in _HELP_WORDS or j >= end:
            return None   # (terraform's other flags before a subcommand: -version, or an error)
        j += 1
    k, deepest = j, _deepest(t["program"])   # (no longer a run than the deepest command: hashicorp/cli's
    while k < len(args) and k - j < deepest and args[k] and " " not in args[k] and args[k][0] != "-":
        k += 1                                   # LongestPrefix finds none longer)
    path = next((tuple(args[j:n]) for n in range(k, j, -1) if " ".join(args[j:n]) in t["commands"]), None)
    if path is None:
        return None
    rest = [a for n, a in enumerate(args[j + len(path):], j + len(path)) if n >= end or a not in _HELP_WORDS]
    got = _options(_scope(t["program"], path), rest, interspersed=False, one_dash_long=True)
    if got is None:
        return None
    _merge(flags, got[0])
    if helped:
        flags["--help"] = ["true"]
    return path, flags, got[1], None


def _refused(value, negated):
    """A switch given a value (`--force=yes`): git, optparse and curl refuse or ignore one; read as not fitting."""
    return None


def _git(t, args):
    """git: its own options before the command (git.c), then parse-options: a command with subcommands
    (OPT_SUBCOMMAND) reads its options up to the first positional, which names the subcommand; a command without reads
    options anywhere (or up to the first positional where it says so)."""
    program, path = t["program"], ()
    got = _options(_scope(program, path), args, interspersed=False, switch_eq=_refused)
    if got is None:
        return None
    flags, rest = got
    while rest and (child := _child(t, path, rest[0])) is not None:
        path, args = child, rest[1:]
        head = _options(_scope(program, path), args, interspersed=False, switch_eq=_refused)
        if head is not None and head[1] and _child(t, path, head[1][0]) is not None:
            _merge(flags, head[0])
            rest = head[1]
            continue
        got = _options(_scope(program, path), args, _node(t, path).get("i", True), switch_eq=_refused)
        if got is None:
            return None
        _merge(flags, got[0])
        return path, flags, got[1], None
    return (path, flags, rest, None) if path or not rest else None


def _optparse(t, args):
    """optparse, as pip uses it: the general options before the command, then the command's (and the general ones)
    anywhere; a whole name only (optparse would take an abbreviation)."""
    program = t["program"]
    got = _options(_scope(program, ()), args, interspersed=False, switch_eq=_refused)
    if got is None or not got[1]:
        return None if got is None else ((), got[0], [], None)
    path = _child(t, (), got[1][0])
    rest = None if path is None else _options(_scope(program, path), got[1][1:], switch_eq=_refused)
    if rest is None:
        return None
    _merge(got[0], rest[0])
    return path, got[0], rest[1], None


def _curl(t, args):
    """curl's getparameter: options anywhere, every other word a URL; `--name=value` (curl 8.10 on); a switch given a
    value isn't read (curl ignores the value)."""
    got = _options(_scope(t["program"], ()), args, switch_eq=_refused)
    return None if got is None else ((), got[0], got[1], None)


def _nopt(t, args):
    """nopt, as npm reads its command line: options anywhere (any config key, any command), `--name=value` or
    `--name value`, a Boolean also followed by `true` or `false`, which it takes; the first positional names the
    command. Only whole names and npm's one-letter shorthands are read (nopt also takes abbreviations)."""
    scope, flags, pos, i, at = _scope(t["program"], ()), {}, [], 0, None
    while i < len(args):
        s = args[i]
        i += 1
        if re.fullmatch(r"-{2,}", s):
            at = i if at is None and i < len(args) else at
            pos += args[i:]
            break
        if s[:1] != "-" or s == "-":
            at = i - 1 if at is None else at
            pos.append(s)
            continue
        name, eq, value = s.partition("=")
        got = _resolve(scope, name)
        if got is None or got[1] not in (0, 1):
            return None
        canon, kind, negated = got
        if kind == 0:
            if not eq and i < len(args) and args[i] in ("true", "false"):
                value, eq = args[i], "="
                i += 1
            if eq and value not in ("true", "false"):
                return None
            value = str((value != "false" if eq else True) != negated).lower()
        elif not eq:
            if (value := _detached(args, i)) is None:
                return None
            i += 1
        flags.setdefault(canon, []).append(value)
    if not pos:
        return (), flags, [], []
    path = _child(t, (), pos[0])
    return None if path is None else (path, flags, pos[1:], args[:at] + args[at + 1:])


_STYLES = {"cobra": _cobra, "argparse": _argparse, "hashicorp": _hashicorp, "git": _git, "optparse": _optparse,
           "curl": _curl, "nopt": _nopt}
