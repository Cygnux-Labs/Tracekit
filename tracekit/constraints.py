"""Stated constraints: what a person's request (or a model's own text) says not to do, read by a small grammar, and
whether a call breaks one. `tracekit analyze --v2` checks them after the run (TK-X204, docs/findings.md); the Claude
Code hook hands the ones a person's prompt states to the signer, which holds a later call that breaks one for a
person's approval (live constraints, docs/policy-v2.md#live-constraints).

    extract(text)        -> [(kind, object or None)], in the text's order
    facts(tool, args)    -> what a call does, as far as a constraint cares
    breaks(kind, facts, is_object) -> what in the call breaks a constraint of `kind`, or None
    lifts(kind, mentions(text), is_object) -> whether a later request names what a constraint keeps away

Kinds (rpc_schema.CONSTRAINT_KINDS):
  keep_away X    "don't touch / modify / edit / change / delete X", "leave X alone", "X stays untouched", "X is
                 read-only", "read-only on X": a call that writes X breaks it
  only_change X  "only change / edit / modify / touch X": a call that writes any other file breaks it
  read_only      "read-only" naming no file, "don't change anything": any call that writes breaks it
  no_push        "don't push", "never push", "no pushing": a git push breaks it
  no_network     "no network", "no internet", "don't go online", "offline": a call that reaches the network breaks it

The grammar reads a clause at a time (a sentence end, a comma, semicolon, colon or bracket, "but", "except", "though"
end one) and, for a file, the WINDOW words before and after it in its clause: a negation and a change verb before it
("don't touch X"), a keep word after it ("X stays untouched", "leave X alone") or "read-only" either side. Files listed
after a kept one ("don't touch a.py or b.py") are kept too. An object is a file name, lower-cased, compared by
basename (norm).
lean: a fixed phrase list, English only; a phrasing outside it ("X is frozen", "hands off X") states no constraint, and
"don't forget to update X" reads as one. Grow the lists from real misses, never from the held-out pool.
"""
import hashlib
import re

from .findings import WRITE_TOOLS
from .policy2.classes import PATH_KEYS, SHELL_KEYS
from .policy2.engine import _shell as _parse
from .policy2.shell import ParseError

OBJECT_KINDS = ("keep_away", "only_change")
MAX_TEXT = 1 << 16   # lean: characters of one text the grammar reads; past it, cut
WINDOW = 4
CLAUSE = re.compile(r"(?<=[.!?])\s+|\n+|[,;:()\[\]]\s*|\s+(?:but|except|though)\s+", re.I)
TOKEN = re.compile(r"[\w.~/\\'-]+")
READ_ONLY = re.compile(r"\bread[\s_-]*only\b", re.I)
FILE_LIKE = re.compile(r"\w\.\w|/|^\.\w")
NEGATIONS = frozenset(("not", "never", "don't", "dont", "won't", "wont", "mustn't", "shouldn't", "didn't", "didnt",
                       "can't", "cannot", "without", "avoid"))
VERBS = frozenset(("touch", "touching", "touched", "modify", "modifying", "modified", "edit", "editing", "edited",
                   "change", "changing", "changed", "delete", "deleting", "deleted", "alter", "altering", "altered",
                   "rewrite", "rewriting", "overwrite", "overwriting", "update", "updating", "updated", "remove",
                   "removing", "removed", "write", "writing"))
KEEP = frozenset(("untouched", "unchanged", "intact", "read-only"))
LEAVE = frozenset(("leave", "leaves", "leaving", "left"))
LIST = frozenset(("or", "and", "nor"))
PUSH = frozenset(("push", "pushing", "pushed"))
NETWORK = frozenset(("network", "internet", "online", "web"))
ASKS_CHANGE = VERBS | {"fix", "add", "create", "implement", "apply"}   # a later request that asks for a change
LIFT = {"no_push": PUSH, "no_network": NETWORK | {"download", "fetch", "curl", "install"}, "read_only": ASKS_CHANGE}
LIFT_WORDS = frozenset().union(*LIFT.values())
WRITERS = {"tee": "all", "touch": "all", "mkdir": "all", "rm": "all", "rmdir": "all", "truncate": "all",
           "cp": "last", "mv": "last", "install": "last", "ln": "last"}
NET_COMMANDS = frozenset(("curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "telnet", "ftp",
                          "http", "https"))
NET_GIT = frozenset(("push", "pull", "fetch", "clone", "ls-remote"))
INSTALLERS = frozenset(("pip", "pip3", "npm", "yarn", "pnpm", "cargo", "gem", "go", "apt", "apt-get", "brew", "uv",
                        "poetry"))
INSTALL = frozenset(("install", "i", "add", "get"))
GIT_WRITES = frozenset(("commit", "push", "reset", "checkout", "merge", "rebase", "apply", "am", "rm", "mv", "restore",
                        "clean", "stash", "switch", "cherry-pick", "revert"))
NET_TOOLS = frozenset(("WebFetch", "WebSearch", "web_fetch", "web_search"))
READ_TOOLS = frozenset(("Read", "Grep", "Glob", "LS", "read_file", "list_files", "list_directory"))


def norm(name):
    """A file name as constraints compare it: its basename, lower-cased, without quotes or a trailing dot."""
    return re.split(r"[/\\]", str(name).strip("'\"`"))[-1].rstrip(".").lower()


def digest(name):
    """What the signer commits a constraint's object as."""
    return "sha256:" + hashlib.sha256(norm(name).encode("utf-8", "surrogatepass")).hexdigest()


def _tokens(clause):
    return [t.rstrip(".-") or t for t in TOKEN.findall(READ_ONLY.sub("read-only", clause.lower().replace("’", "'")))]


def _negated(tokens, i, words=NEGATIONS):
    return bool(set(tokens[max(0, i - WINDOW):i]) & words)


def _kept(tokens, i, nxt):
    """Whether the file at tokens[i] is kept away: a negation and a change verb before it, a keep word after it (before
    the next file, at tokens[nxt]), "leave ... X ... alone", or "read-only" either side."""
    before = tokens[max(0, i - WINDOW):i]
    end = min(nxt, i + 1 + WINDOW)
    after = tokens[i + 1:end]
    return bool(set(before) & NEGATIONS and set(before) & VERBS or set(after) & KEEP or "read-only" in before
                or "alone" in after and set(before) & LEAVE)


def _clause(tokens):
    """[(kind, object or None)] of one clause's tokens; also the clause's files kept away (for mentions)."""
    files = {i: t for i, t in enumerate(tokens) if FILE_LIKE.search(t) and norm(t)}
    out, kept, last, at = [], set(), None, [*files, len(tokens)] if files else ()
    for n, (i, t) in enumerate(files.items()):
        if _kept(tokens, i, at[n + 1]) or last in kept and set(tokens[last + 1:i]) <= LIST:
            kept.add(i)
            out.append(("keep_away", norm(t)))
        elif "only" in tokens[max(0, i - WINDOW):i] and set(tokens[max(0, i - WINDOW):i]) & VERBS \
                and not _negated(tokens, i):
            out.append(("only_change", norm(t)))
        last = i
    if not files and ("read-only" in tokens or set(tokens) & NEGATIONS and set(tokens) & VERBS and "anything" in tokens):
        out.append(("read_only", None))
    for i, t in enumerate(tokens):
        if t in PUSH and _negated(tokens, i, NEGATIONS | {"no"}):
            out.append(("no_push", None))
        elif t in NETWORK and _negated(tokens, i, NEGATIONS | {"no"}) or t == "offline":
            out.append(("no_network", None))
    return list(dict.fromkeys(out)), {files[i] for i in kept}


def extract(text):
    """The constraints `text` states: [(kind, object or None)], each once, in order."""
    out = []
    for clause in CLAUSE.split(text[:MAX_TEXT] if isinstance(text, str) else ""):
        out += _clause(_tokens(clause))[0]
    return list(dict.fromkeys(out))


def mentions(text):
    """(the files `text` names other than to keep them away, the words of LIFT_WORDS it uses other than negated):
    what a later request lifts a constraint with."""
    names, words = set(), set()
    for clause in CLAUSE.split(text[:MAX_TEXT] if isinstance(text, str) else ""):
        tokens = _tokens(clause)
        _, kept = _clause(tokens)
        for i, t in enumerate(tokens):
            if FILE_LIKE.search(t) and t not in kept and norm(t):
                names.add(norm(t))
            elif t in LIFT_WORDS and not _negated(tokens, i, NEGATIONS | {"no"}):
                words.add(t)
    return names, words


def lifts(kind, mention, is_object):
    """Whether a later request (`mention`, from mentions()) names what a constraint of `kind` keeps away: its file, a
    push, the network, a change."""
    names, words = mention
    if kind in OBJECT_KINDS:
        return any(is_object(n) for n in names)
    return bool(words & LIFT[kind] or kind == "read_only" and names)


def shell(cmd):
    """What a shell command does: {"paths": what it writes as far as the policy engine's parser reads it, "cd": it
    changes directory, "push": a git push, "network": a command that reaches the network, "writes": it writes or
    commits}. `cmd`: a command line, or a shell call's arguments (`command` or `cmd` a line or an argv list,
    `commands` a list of lines), read as the policy engine reads them (policy2/shell.py: wrappers, `bash -c`, `eval`,
    substitutions and pipelines included).
    lean: redirections, tee/touch/mkdir/rm/rmdir/truncate arguments, cp/mv/install/ln destinations and sed/perl -i
    files; a word with a variable, a glob or a command substitution is no path; a line the parser can't read (`case`,
    over its size) does nothing, and the policy's TK-SHELL-PARSE answers for it. Read scripts the call runs if real
    writes hide there."""
    out = {"paths": [], "cd": False, "push": False, "network": False, "writes": False}
    try:
        cmds, _, _, written = _parse(cmd if isinstance(cmd, dict) else {"command": cmd if isinstance(cmd, str) else ""})
    except ParseError:
        return out
    for c in cmds:
        name, rest = c["argv"][0], c["argv"][1:]
        args = [w for w in rest if not w.startswith("-")]
        out["cd"] = out["cd"] or name in ("cd", "pushd")
        mode = WRITERS.get(name)
        if name in ("sed", "perl") and any(w.startswith(("-i", "--in-place")) or w.startswith("-p") and "i" in w
                                           for w in rest):
            mode = "files"
        targets = (args if mode == "all" else args[-1:] if mode == "last" and len(args) > 1
                   else args[1:] if mode == "files" else [])
        sub = next((a for a in args[:2] if a in GIT_WRITES | NET_GIT), None) if name == "git" else \
            args[0] if args else None
        out["paths"] += targets
        out["push"] = out["push"] or name == "git" and "push" in args
        out["network"] = out["network"] or name in NET_COMMANDS or name == "git" and sub in NET_GIT or (
            name in INSTALLERS and sub in INSTALL)
        out["writes"] = out["writes"] or bool(targets) or name == "git" and sub in GIT_WRITES or (
            name in INSTALLERS and sub in INSTALL)
    written = [t for t in written if not t.startswith("/dev/")]   # /dev/null, a terminal, a descriptor: no file
    out["writes"] = out["writes"] or bool(written)
    out["paths"] = [t for t in out["paths"] + written if not set(t) & set("$`*?[")]
    return out


def facts(tool, args, cls=None):
    """What call (`tool`, `args`) does, as far as a constraint cares: {"names": the basenames of what it writes,
    "write": it writes at all, "push": a git push, "network": it reaches the network}. `cls`: the policy's class of
    the tool when known (http and browser calls reach the network). A write tool (or another fs tool that writes)
    writes its path and each of its `paths` (every file of a Codex patch, whose text is its `command`); any other call
    with a command (`command`, `cmd` or `commands`) is a shell command."""
    args = args if isinstance(args, dict) else {}
    write = tool in WRITE_TOOLS or cls == "fs" and tool not in READ_TOOLS and args.get("op") != "read"
    if not write and any(args.get(k) is not None for k in SHELL_KEYS):
        s = shell(args)
        return {"names": [norm(p) for p in s["paths"] if norm(p)], "write": s["writes"], "push": s["push"],
                "network": s["network"]}
    paths = [next((args[k] for k in PATH_KEYS if isinstance(args.get(k), str)), None),
             *(args["paths"] if isinstance(args.get("paths"), list) else ())]
    return {"names": list(dict.fromkeys(norm(p) for p in paths if isinstance(p, str) and norm(p))) if write else [],
            "write": write, "push": False, "network": cls in ("http", "browser") or tool in NET_TOOLS}


def breaks(kind, f, is_object):
    """What in a call (its `facts`) breaks a constraint of `kind` whose object `is_object(name)` tests: the file name,
    or the kind's own word ("push", "network", "write"); None when it doesn't."""
    if kind == "keep_away":
        return next((n for n in f["names"] if is_object(n)), None)
    if kind == "only_change":
        return next((n for n in f["names"] if not is_object(n)), None)
    if kind == "read_only":
        return (f["names"] or ["write"])[0] if f["write"] else None
    return {"no_push": "push", "no_network": "network"}[kind] if f[kind[3:]] else None


def held(kind, name):
    """What the agent is told when a live constraint holds its call (`name`: from breaks(), out of its own
    arguments)."""
    return {"keep_away": f"the person's request in this run said not to modify {name}",
            "only_change": f"the person's request in this run said to change only certain files, and {name} is not "
                           "one of them",
            "read_only": "the person's request in this run said to make no changes (read-only)",
            "no_push": "the person's request in this run said not to push",
            "no_network": "the person's request in this run said not to use the network"}[kind] + \
        "; ask the person (TK-CONSTRAINT)"
