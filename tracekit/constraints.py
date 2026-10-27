"""Stated constraints: what a person's request (or a model's own text) says not to do, read by a small grammar, and
whether a call breaks one. `tracekit analyze --v2` checks them after the run (TK-X204, docs/findings.md); the Claude
Code hook hands the ones a person's prompt states to the signer, which holds a later call that breaks one for a
person's approval (live constraints, docs/policy-v2.md#live-constraints).

    extract(text)        -> [(kind, object or None)], in the text's order
    facts(tool, args)    -> what a call does, as far as a constraint cares
    breaks(kind, facts, is_object) -> what in the call breaks a constraint of `kind`, or None
    lifts(kind, mentions(text), is_object) -> whether a later request names what a constraint keeps away

Kinds (rpc_schema.CONSTRAINT_KINDS):
  keep_away X    a negated change of X ("don't touch / edit / modify / write to / mess with X", "please refrain from
                 editing X", "make no changes to X", "I'd rather you didn't touch X", "I don't want X changed"), X
                 said to stay as it is ("leave / keep X alone / as is / exactly as it is / out of this", "X must stay
                 unchanged", "the X file must not change", "X is off-limits / read-only / frozen / out of scope / not
                 part of this / maintained elsewhere", "X belongs to another team", "nothing in X should change"),
                 "hands off X", "stay away from / out of (the) X", "keep your changes out of X", "under no
                 circumstances touch X", "read-only on X"; "make no changes there" or "don't change it" for the file
                 named last before ("X is generated; make no changes there"), "them" for each: a call that writes X
                 breaks it. X is a file ("billing.py", a name of EXTENSIONLESS: "the Dockerfile") or a directory
                 ("src/legacy/", "anything in vendor/", "the vendor folder": a write under it breaks it). Not a change
                 of one aspect of X ("don't change the public API of X", "the signature in X", "nothing in X changes
                 its behaviour")
  only_change X  "only change / edit / touch X", "only X should change", "X is the only file to edit", "limit / restrict
                 / confine the change to X", "touch nothing but X", "don't change anything (any file) except / but /
                 other than X", "everything outside X is off-limits", "read-only except X", and each file the text
                 names when it says "don't change anything else", "X and nothing else" or "everything else is out of
                 scope": a call that writes any other file breaks it (TK-X204; the hook holds no call for it)
  read_only      "don't change anything", "change nothing", and "read-only" naming no file as an instruction
                 ("read-only: just look", "stay read-only", "work in read-only mode"; not "a read-only mode", "make the
                 connection read-only", "nothing should change for callers"): any write breaks it
  no_push        "don't push", "never push", "no pushing" (also "don't push it to origin"; not a scoped push: "don't
                 push to main", "never push secrets"): a git push breaks it
  no_network     "no network (access)", "no internet", "don't go online", "don't use the web", "work / stay offline":
                 a call that reaches the network breaks it. A push or network negation is an instruction only with
                 nothing but words of ASKING before it ("please don't", "you must not", "I don't want"; not "we
                 don't use the network in unit tests", "the app works without network access")

The grammar reads a sentence at a time, leaving out code blocks, quoted or indented lines ("> don't touch X", code four
spaces in), quoted spans ("the README says \"don't touch X\"") and questions other than requests ("could you leave X
alone?", "don't touch X, ok?"; not "should I change X?"), then a clause at a time (a comma, semicolon, colon or bracket,
"but", "except", "though" end one; a clause that starts with an exception word after "don't change anything" or
"read-only" belongs to it). For a file it reads the WINDOW words around it: the change word whose object it is (before
it, with no clause of its own between: not "don't change how X is imported", nor "don't change the tests to make X
pass") and a negation before that, or a state after it past filler words ("X should stay as it is"). Files listed after
a kept one ("don't touch a.py or b.py") are kept too. A negation followed by a word that turns it around ("don't forget
to", "don't hesitate to", "you don't need to", "I don't mind if") negates nothing. A condition after the file (or the
push, the network, "anything") states none: "don't edit X until the tests pass", "without checking Y first", "unless",
"before", "if", "while the server runs", "when DEBUG is set" (the change is allowed once it holds, which the grammar
can't check; "while you work", "while fixing Y" are the task itself, no condition; the person's own go-ahead, "before I
review", "without asking me first", keeps the constraint). A later clause of the same text that asks for what a
constraint keeps away lifts it there ("don't touch X for now; ... after that, update X too"; "don't change anything,
then fix it"), but not a file where it waits on the person ("you can change X after I approve"). A network word is
negated only with nothing but words of use between ("don't use the network", not "don't change the network code") and
no noun after it ("no web UI changes"); "offline" only where the clause begins with it as an instruction ("work
offline", not "make the CLI work offline"). An object is a file name, lower-cased, compared by basename (norm). A pass
reads each clause once, and the files an "it" stands for once (_read): word sets, short fixed sequences, one suffix
scan per clause; the regular expressions have no nested quantifiers.
lean: fixed word lists, English only; a phrasing outside them ("keep the diff to X", a constraint on a file named two
clauses back) states no constraint. Grow the lists from real misses, never from the held-out pool.
lean: not linear in two places: a negated push or network word, or a lift word, reads the words before it in its clause
again (a 64 KiB clause of them, under a second), and "them" stands for each file of the clause before it in every
clause that says it (64 KiB of "don't change them" after 3,000 to 5,000 files: about 2 s and up to 1.1 GiB). Read them
once per clause if real texts get near that.
"""
import hashlib
import re

from .findings import WRITE_TOOLS
from .policy2.classes import PATH_KEYS, SHELL_KEYS
from .policy2.engine import _shell as _parse
from .policy2.shell import ParseError

OBJECT_KINDS = ("keep_away", "only_change")
MAX_TEXT = 1 << 16   # lean: characters of one text the grammar reads; past it, cut
WINDOW = 5
SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")
# within a sentence, keeping the word; a space run is tried from its start only (from inside it, quadratic)
CLAUSE = re.compile(r"[,;:()\[\]—–]\s*|(?<!\s)\s+(?=(?:but|except|though)\s)", re.I)
TOKEN = re.compile(r"[\w.~/\\'-]+")
READ_ONLY = re.compile(r"\bread[\s_-]*only\b", re.I)
NO_CASE = re.compile(r"\b(?:under|in) no (?:circumstances|case)\b")
FOLDERS = frozenset(("directory", "folder", "dir"))
# before a word of FOLDERS, a place rather than a folder's name: "the home directory" is no home/ (a project under /home
# would have every write held)
PLACES = frozenset(("home", "root", "current", "working", "parent"))
OFF_LIMITS = re.compile(r"\boff[\s_-]*limits\b", re.I)
FILE_LIKE = re.compile(r"\w\.\w|/|^\.\w")
# files people name without an extension: each is a file name too ("don't touch the Dockerfile")
EXTENSIONLESS = frozenset(("dockerfile", "containerfile", "makefile", "gnumakefile", "justfile", "jenkinsfile",
                           "vagrantfile", "gemfile", "rakefile", "procfile", "pipfile", "brewfile", "codeowners",
                           "license", "copying"))
NEGATIONS = frozenset(("not", "never", "don't", "dont", "do'nt", "won't", "wont", "mustn't", "mustnt", "shouldn't",
                       "shouldnt", "can't", "cant", "cannot", "without", "avoid", "avoiding", "refrain"))
# a word after a negation that turns it around: "don't forget to update X" asks for the change
UNNEGATE = frozenset(("forget", "forgetting", "hesitate", "fail", "neglect", "omit", "skip", "miss", "need", "needs",
                      "have", "afraid", "mind", "care", "worry", "think", "know"))
EXCEPT = frozenset(("except", "but", "besides", "other", "apart", "excluding", "save"))   # "anything except X"
PARTICIPLES = frozenset(("touched", "modified", "edited", "changed", "deleted", "altered", "updated", "removed",
                         "rewritten", "overwritten", "renamed", "refactored", "reformatted", "moved", "patched"))
NOUNS = frozenset(("changes", "change", "modifications", "modification", "edits", "edit", "alterations", "updates",
                   "rewrites", "writes"))
BASE = frozenset(("touch", "modify", "edit", "change", "delete", "alter", "rewrite", "update", "remove", "write"))
VERBS = BASE | PARTICIPLES | NOUNS | frozenset((
    "touching", "modifying", "editing", "changing", "deleting", "altering", "rewriting", "overwrite", "overwriting",
    "updating", "removing", "writing", "mess", "messing", "tamper", "tampering", "fiddle", "fiddling", "tinker",
    "tinkering", "patch", "patching", "refactor", "refactoring", "reformat", "reformatting", "rename", "renaming",
    # common typos
    "chnage", "cahnge", "chage", "chnge", "modfy", "modifiy", "mdoify", "edti", "eidt", "udpate", "updte", "tocuh",
    "tuch", "rewite"))
# what a file kept away is said to be, after it ("X is off-limits", "leave X as is", "X belongs to another team")
STATES = tuple(tuple(s.split()) for s in (
    "untouched", "unchanged", "intact", "read-only", "unmodified", "unedited", "frozen", "locked", "pristine",
    "off-limits", "hands-off", "as-is", "as is", "as it is", "as they are", "out of scope", "out of bounds",
    "not part of", "not in scope", "maintained elsewhere", "managed elsewhere", "owned elsewhere",
    "maintained by another", "owned by another", "maintained by a different", "owned by a different",
    "belongs to another", "belongs to a different", "belongs to someone", "someone else's", "not ours", "not yours",
    "unchaged", "untuoched"))
# what may stand between a file and what it is said to be: "X must stay as is", "X should not be changed"
FILLER = frozenset(("is", "are", "be", "been", "being", "was", "stays", "stay", "stayed", "remains", "remain",
                    "remained", "should", "must", "shall", "can", "may", "needs", "need", "has", "have", "to", "as",
                    "kept", "left", "considered", "treated", "completely", "fully", "entirely", "strictly", "totally",
                    "please", "so", "too", "also", "still", "really", "always", "absolutely", "ever", "get", "gets",
                    "exactly", "file", "folder", "directory", "dir"))   # "leave X exactly as it is", "the X file must"
AFTER_NEG = frozenset(("not", "never", "mustn't", "mustnt", "shouldn't", "shouldnt", "can't", "cant", "cannot",
                       "shan't"))   # "X must not be changed", "X shouldn't change"
AWAY = tuple(tuple(s.split()) for s in ("hands off", "stay away from", "keep away from",
                                        "steer clear of", "stay clear of", "stay out of", "keep out of"))
LEAVE = frozenset(("leave", "leaves", "leaving", "left", "keep", "keeps", "keeping"))
# between a change word and its file: no clause of its own ("don't change how X is imported")
BLOCK = frozenset(("how", "what", "why", "when", "where", "whether", "which", "who", "whose", "so", "because", "that",
                   "than", "since", "while", "if", "unless"))
# after "any changes", which ones ("that break the API", "beyond the fix", "for the sake of style"; not "for now", "for
# any reason", "directly"); "to", "in" or "on" (WHERE) not before a word of PROJECT, the whole project ("don't make any
# changes to the code", "on disk")
PICKS = frozenset(("that", "which", "beyond", "outside"))
PROJECT = frozenset(("code", "codebase", "repo", "repository", "project", "files", "workspace", "session", "tree",
                     "disk"))
DETERMINERS = frozenset(("the", "a", "an", "any", "this", "that", "these", "those", "your", "my", "our", "its",
                         "their"))
# after the file: a condition, so no constraint ("don't edit X until the tests pass", "without checking Y first", "while
# the server runs"); a word of WHILE only before someone other than YOU, and "while" before a word of the agent's work
# ("don't touch X while you're at it", "leave X alone while fixing Y" hold)
CONDITIONAL = frozenset(("unless", "until", "before", "if", "without", "first"))
WHILE = frozenset(("while", "when", "whenever", "after", "once"))
YOU = frozenset(("you", "you're", "youre", "we", "we're", "i", "i'm"))
# a condition that is the person's own go-ahead keeps the constraint: holding the call for them is what they ask
# ("don't push before I review", "without asking me first", "until I say so", "unless I confirm")
PERSON = frozenset(("i", "me", "us", "we", "my", "our"))
GO_AHEAD = frozenset(("say", "says", "said", "approve", "approves", "approved", "approval", "confirm", "confirms",
                      "confirmed", "confirmation", "review", "reviews", "reviewed", "ask", "asking", "asked", "ok",
                      "okay", "sign", "signs", "signed", "permission", "go-ahead"))
# between a change word and the file, a word of WHERE makes the file only where the change would be: "don't change the
# public API of X", "the signature in X" keep nothing away; "anything in X", "the code in X" do (WHOLE)
WHERE = frozenset(("of", "in", "inside", "within", "under"))
WHOLE = frozenset(("anything", "any", "something", "nothing", "stuff", "things", "thing", "code", "lines", "line",
                   "file", "files", "else", "at", "all", "whatsoever", "single", "part", "parts", "bit", "to"))
ANAPHORS = frozenset(("it", "there", "them"))
SCOPE = frozenset(("limit", "limited", "limits", "limiting", "restrict", "restricted", "restricting", "confine",
                   "confined", "confining", "scope", "scoped"))   # "keep the patch limited to X"
OUTSIDE = (["everything", "outside"], ["everything", "but"], ["everything", "except"], ["everything", "besides"],
           ["everything", "beyond"], ["anything", "outside"])   # "everything outside X is off-limits"
POLITE = (("could", "you"), ("can", "you"), ("would", "you"), ("will", "you"), ("could", "we"), ("can", "we"),
          ("please",), ("kindly",))   # a question that asks for something: "could you leave X alone?"
TAGS = frozenset(("ok", "okay", "right", "alright", "please", "yes", "yeah", "thanks"))   # "don't touch X, ok?"
LIST = frozenset(("or", "and", "nor"))
PUSH = frozenset(("push", "pushing", "pushed"))
NETWORK = frozenset(("network", "internet", "online", "web"))
NET_USE = frozenset(("use", "using", "access", "accessing", "connect", "connecting", "reach", "reaching", "go", "going",
                     "call", "calling", "hit", "browse", "browsing", "search", "searching", "the", "any", "a", "to",
                     "on", "onto", "of", "from", "be"))   # between a negation and a network word: "don't use the web"
# what may follow it: "no network access, please"; not a scope ("no network in unit tests")
NET_AFTER = frozenset(("access", "calls", "requests", "connections", "connection", "traffic", "use", "usage",
                       "searches", "browsing", "for", "during", "whatsoever", "either", "and", "or", "nor", "this",
                       "here", "now", "please", "again", "anymore", "is", "are", "allowed", "today"))
OFFLINE = frozenset(("work", "stay", "remain", "keep", "be", "go", "do", "run", "operate", "you", "you're", "we're"))
LEAD = frozenset(("please", "just", "and", "but", "though", "so", "also", "then"))
# what may come before the negation of a push or the network: an instruction ("please don't push", "you must not use
# the network", "I don't want"), not a description ("we don't use the network in unit tests")
ASKING = LEAD | frozenset(("you", "i", "let's", "lets", "should", "must", "shall", "will", "would", "can", "could",
                           "really", "absolutely", "definitely", "do", "i'd", "rather"))
# what may come before a change word, in its base form, that asks the agent for the change ("you can edit it", "feel
# free to change it", "go ahead and fix it", "later you can update it", "locally you can edit it", "you're free to
# edit it"; not "ask me before you change it", "I'll update it myself", "you may need to change it")
ALLOWING = LEAD | frozenset(("you", "you're", "can", "may", "could", "should", "must", "feel", "free", "to", "go",
                             "ahead", "now", "later", "locally"))
# what may follow a refused push and still refuse every push ("don't push the branch", "don't push it yet"); another
# word scopes it ("don't push to main", "never push secrets"): no constraint
PUSHED = frozenset(("anything", "it", "them", "this", "that", "these", "those", "yet", "please", "now", "the", "any",
                    "my", "your", "our", "changes", "change", "commits", "commit", "code", "branch", "branches", "work",
                    "fix", "ever", "either", "again", "today", "at", "all"))
REMOTES = frozenset(("origin", "remote", "remotes", "github", "gitlab", "upstream", "anywhere"))   # "push to origin"
# "read-only" naming no file holds every write only as an instruction: it starts the clause or follows a word of
# OFFLINE that does ("stay read-only", "work in read-only mode", "everything is read-only"), and what follows it is
# no noun it describes ("a read-only mode", "read-only replicas")
READ_ONLY_AFTER = frozenset(("please", "for", "here", "now", "today", "throughout", "again", "too", "also"))
ASKS_CHANGE = VERBS | {"fix", "add", "create", "implement", "apply"}   # a later request that asks for a change
LIFT = {"no_push": PUSH, "no_network": NETWORK | {"download", "fetch", "curl", "install"}, "read_only": ASKS_CHANGE}
# a later clause of the same text that starts with one of these makes "don't change anything" a step before it
# ("investigate, don't change anything, then speed it up")
SEQUENCE = frozenset(("then", "afterwards", "later", "next"))
LIFT_WORDS = frozenset().union(*LIFT.values())
# a clause that names no file states nothing without one of these
STATING = ANAPHORS | PUSH | NETWORK | {"offline", "anything", "any", "nothing", "read-only", "everything"}
# what a model says it does to a file (changes()): the change words, and those of fixing and adding
SAID_CHANGE = VERBS | frozenset((
    "fix", "fixes", "fixing", "fixed", "adjust", "adjusts", "adjusting", "adjusted", "tweak", "tweaks", "tweaking",
    "tweaked", "add", "adds", "adding", "added", "replace", "replaces", "replacing", "replaced", "rework", "reworking",
    "reworked", "extend", "extending", "extended", "bump", "bumping", "bumped", "apply", "applies", "applying",
    "applied", "insert", "inserting", "inserted", "append", "appending", "appended", "correct", "correcting",
    "corrected", "implement", "implementing", "implemented", "create", "creating", "created", "wrote", "rewrote",
    "convert", "converting", "converted", "migrate", "migrating", "migrated", "port", "porting", "ported", "simplify",
    "simplifying", "simplified", "harden", "hardening", "hardened", "regenerate", "regenerating", "regenerated",
    "trim", "trimming", "trimmed"))
SAID_NEG = NEGATIONS | {"no", "didn't", "didnt", "doesn't", "doesnt", "haven't", "hasn't", "isn't", "aren't", "wasn't",
                        "nothing", "neither", "nor", "nobody"}
TURNED = frozenset(("forget", "forgetting", "hesitate", "fail", "neglect", "omit", "skip", "miss"))
BUG = frozenset(("bug", "bugs", "issue", "problem", "error", "defect", "fault", "regression", "typo", "culprit"))
AT = frozenset(("is", "was", "are", "lives", "sits", "really", "actually", "still", "also", "in", "inside", "within",
                "the", "real", "whole"))   # between a defect and its file: "the bug is really in X"
# between a file and what it gets, after it: "X needs the same fix", "X also gets updated"
AUX = frozenset(("needs", "need", "gets", "get", "got", "is", "are", "was", "will", "should", "must", "also", "too",
                 "the", "same", "a", "an", "this", "that", "small", "one", "now", "getting", "has", "have", "been",
                 "be", "being", "requires", "require", "any", "more", "further", "similar", "matching"))
WRITERS = {"tee": "all", "touch": "all", "mkdir": "all", "rm": "all", "rmdir": "all", "truncate": "all",
           "shred": "all", "unlink": "all", "black": "all", "isort": "all", "rustfmt": "all", "cp": "last",
           "mv": "last", "install": "last", "ln": "last", "rsync": "last", "scp": "last", "patch": "first"}
FORMATTERS = {"prettier": ("--write", "-w"), "gofmt": ("-w",), "eslint": ("--fix",), "clang-format": ("-i",),
              "autopep8": ("-i", "--in-place")}   # rewrite their files in place with one of these flags
UNREAD = frozenset("$`*?[{")   # a word with one of these (a variable, a glob, a substitution) is no path
FIND_NAMES = ("-name", "-iname", "-path", "-ipath", "-wholename")   # what find -delete or -exec acts on
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
    """A file name as constraints compare it: its basename, lower-cased, without quotes or a trailing dot; a directory
    ("src/legacy/") its last name and a slash ("legacy/")."""
    parts = re.split(r"[/\\]", str(name).strip("'\"`"))
    base = parts[-1] or len(parts) > 1 and parts[-2] and parts[-2] + "/"
    return (base or "").rstrip(".").lower()


def names(paths):
    """What constraints compare of the paths a call writes: each basename (norm), then each directory over it as
    "name/" (a keep_away of a directory breaks on a write under it).
    lean: by name, any depth: a directory of that name over the project matches too; compare paths if that holds
    honest calls."""
    files = [norm(p) for p in paths]
    dirs = [d.lower() + "/" for p in paths for d in re.split(r"[/\\]", p)[:-1] if d not in ("", ".", "..")]
    return list(dict.fromkeys(n for n in files + dirs if n))


def digest(name):
    """What the signer commits a constraint's object as."""
    return "sha256:" + hashlib.sha256(norm(name).encode("utf-8", "surrogatepass")).hexdigest()


def _tokens(clause):
    low = OFF_LIMITS.sub("off-limits", READ_ONLY.sub("read-only", clause.lower().replace("’", "'")))
    if " no c" in low:   # "under no circumstances touch X", "under no circumstances should X be edited"
        low = NO_CASE.sub("never", low)
    return [t.rstrip(".-") or t for t in TOKEN.findall(low)]


def _file(t):
    return ("." in t or "/" in t) and bool(FILE_LIKE.search(t)) and bool(norm(t)) or t in EXTENSIONLESS


def _negation(tokens, i, words=NEGATIONS):
    """The index of the word of `words` within WINDOW before tokens[i] that negates it, or None: the nearest, and none
    of UNNEGATE after it ("don't forget to push")."""
    at = next((k for k in range(i - 1, max(0, i - WINDOW) - 1, -1) if tokens[k] in words), None)
    return None if at is None or set(tokens[at + 1:i]) & UNNEGATE else at


def _negated(tokens, i, words=NEGATIONS):
    return _negation(tokens, i, words) is not None


def _tied(tokens, i, words=VERBS):
    """The index of the change word (of `words`) whose object tokens[i] is: the nearest within WINDOW before it, with
    no clause of its own (BLOCK) or infinitive ("to make") between; or None."""
    for k in range(i - 1, max(0, i - WINDOW) - 1, -1):
        t = tokens[k]
        if t in words:
            return k
        if t in BLOCK or t == "to" and k + 1 < i and tokens[k + 1] not in DETERMINERS and not _file(tokens[k + 1]):
            return None
    return None


def _where(tokens, c, i):
    """Whether the change word at tokens[c] has an object of its own before the file at tokens[i], which is only where
    the change is: a word of WHERE between them, with a word before it that is no determiner, change noun or word of
    WHOLE ("the public API of X"; not "anything in X", "any code in X")."""
    p = next((k for k in range(i - 1, c, -1) if tokens[k] in WHERE), None)
    return p is not None and not set(tokens[c + 1:p]) <= WHOLE | WHERE | DETERMINERS | NOUNS


def _conditions(tokens):
    """[i]: whether a condition follows tokens[i] in the clause: a word of CONDITIONAL, or of WHILE before anyone but
    YOU ("while the server runs", not "while you work" or "while fixing Y"); none from the person's own go-ahead on
    (a condition word with PERSON and GO_AHEAD in the four words after it: "before I review", "without asking me
    first"), which keeps the constraint."""
    out, seen = [False] * (len(tokens) + 1), False
    for i in range(_mine(tokens) - 1, -1, -1):
        out[i] = seen
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        seen = seen or tokens[i] in CONDITIONAL or tokens[i] in WHILE and nxt not in YOU and not (
            tokens[i] == "while" and nxt.endswith("ing"))
    return out


def _mine(tokens):
    """The index of the clause's condition on the person's own go-ahead (a condition word with PERSON and GO_AHEAD in
    the four words after it: "before I review", "without asking me first"), or len(tokens)."""
    return next((k for k, t in enumerate(tokens) if (t in CONDITIONAL or t in WHILE)
                 and set(tokens[k + 1:k + 5]) & PERSON and set(tokens[k + 1:k + 5]) & GO_AHEAD), len(tokens))


def _asking(tokens, n):
    """Whether the negation at tokens[n] is an instruction (ASKING before it; "without" only after a word of OFFLINE
    that starts the clause: "work without network access", not "the app works without network access")."""
    if tokens[n] == "without":
        return _instruction(tokens, n)
    return set(tokens[:n]) <= ASKING


def _refused(tokens, c):
    """Whether the change word at tokens[c] is negated: a negation before it (_negation), "no" or "zero" right before a
    noun ("no changes", "no further edits"), or "rather you didn't"."""
    if _negation(tokens, c) is not None:
        return True
    if tokens[c] in NOUNS and (c > 0 and tokens[c - 1] in ("no", "zero") or c > 1 and tokens[c - 2] in ("no", "zero")
                               and tokens[c - 1] in ("more", "further", "other", "additional", "single", "any")):
        return True
    return bool({"didn't", "didnt"} & set(tokens[max(0, c - 2):c])
                and {"rather", "prefer"} & set(tokens[max(0, c - 5):c]))


def _negating(tokens):
    """Whether a clause holds a negation that is not turned around (UNNEGATE: "don't forget to")."""
    return any((t in NEGATIONS or t in ("no", "nothing", "nobody", "none", "neither", "nor"))
               and not set(tokens[k + 1:k + 3]) & UNNEGATE
               for k, t in enumerate(tokens))


def _prohibited(tokens, i):
    """Whether a negation governs a change of the file at tokens[i]: a change word tied to it with a negation of
    SAID_NEG before ("don't touch X", "nobody should ever edit X"; not "don't change the signature in X": _where), or
    after it a negation and, past filler words, a participle or a change word that ends the clause ("X must not be
    edited", "X should never change"; not "X never writes the token", "X must not crash")."""
    c = _tied(tokens, i)
    if c is not None and not _where(tokens, c, i) and SAID_NEG & set(tokens[max(0, c - WINDOW):c]):
        return True
    for k in range(i + 1, min(len(tokens), i + 1 + WINDOW)):
        if tokens[k] in SAID_NEG or tokens[k].endswith("n't"):
            m = _first(tokens, k, len(tokens))
            return m < len(tokens) and (tokens[m] in PARTICIPLES or tokens[m] in VERBS and m + 1 == len(tokens))
        if tokens[k] not in FILLER:
            return False
    return False


def _phrase(tokens, k, phrases):
    return any(tuple(tokens[k:k + len(p)]) == p for p in phrases)


def _first(tokens, i, end):
    """The index of the first word after tokens[i], within WINDOW and before `end`, that is no FILLER word, or `end`."""
    return next((k for k in range(i + 1, min(end, i + 1 + WINDOW)) if tokens[k] not in FILLER), end)


def _stated_after(tokens, i, end, leave=False, neg=False, nothing=False):
    """Whether what follows the file at tokens[i] (up to `end`, past FILLER words) keeps it away: a state ("X is
    off-limits"), "alone", "be" or "out" after a leave word, a negated change ("X must not be changed"), a participle
    after a negation ("I don't want X changed") or a change after "nothing in" ("nothing in X should change")."""
    for k in range(i + 1, min(end, i + 1 + WINDOW)):
        t = tokens[k]
        if _phrase(tokens, k, STATES) or leave and t in ("alone", "be", "out") or neg and t in PARTICIPLES \
                or nothing and t in VERBS and not set(tokens[k + 1:k + 2]) & DETERMINERS:
            return True   # not "nothing in X changes its behaviour": an aspect of X
        if t in AFTER_NEG:
            m = _first(tokens, k, end)
            return m < end and tokens[m] in VERBS
        if t not in FILLER:
            return False
    return False


def _kept(tokens, i, end, cond):
    """Whether the file (or "it", "there") at tokens[i] is kept away: a negated change word tied to it ("don't touch
    X", "make no changes to X"), a state after it, "hands off X", "stay away from X", "read-only on X"; none with a
    condition after it (cond[i])."""
    if cond[i]:
        return False
    c = _tied(tokens, i)
    j = i   # past determiners: "stay out of the infra/ folder"
    while j > 0 and tokens[j - 1] in DETERMINERS:
        j -= 1
    if tokens[j - 1:j] == ["outside"]:
        return False   # "don't make any changes outside src/": a scope
    if c is not None and _refused(tokens, c) and not _where(tokens, c, i) or any(
            tokens[max(0, j - len(p)):j] == list(p) for p in AWAY) or tokens[max(0, j - 2):j] == ["out", "of"] and any(
            tokens[n] in LEAVE and set(tokens[n + 1:j - 3]) <= DETERMINERS | {"all", "own", "code", "other", "of"}
            and tokens[j - 3] in NOUNS | {"hands", "yourself"} for n in range(max(0, j - 2 - WINDOW), j - 3)):
        return True   # "keep (all) your (own) changes out of X"; not "keep this (key) out of X"
    if tokens[max(0, i - 2):i] in (["read-only", "on"], ["read-only", "for"], ["read-only", "to"]):
        return True
    return _stated_after(tokens, i, end, bool(set(tokens[max(0, i - WINDOW):i]) & LEAVE),
                         _negation(tokens, i) is not None, i > 1 and tokens[i - 2] == "nothing")


def _anything(tokens):
    """The index of the clause's "read-only", of its "anything" (or "any file", "any other", "any changes" with no
    object after it) a change is negated before ("don't change anything", "I don't want anything changed", "don't make
    any changes"; not "don't make any changes to the tests"), or of its "nothing" after a change word or before "else"
    or a modal ("touch nothing but X", "nothing should change except X"); or None."""
    neg = verb = None
    if not {"anything", "any", "nothing", "read-only"} & set(tokens):
        return None
    for k, t in enumerate(tokens):
        nxt = tokens[k + 1:k + 2]
        if t == "read-only":
            return k
        if t in NEGATIONS:
            neg, verb = k, None
        elif t in UNNEGATE:
            neg = None
        elif t in VERBS:
            verb = k
        elif t == "nothing" and (verb is not None and tokens[verb] in BASE
                                 or nxt in (["else"], ["should"], ["must"], ["may"], ["shall"])):
            return k
        elif (t == "anything" or t == "any" and (nxt in (["file"], ["files"], ["other"]) or set(nxt) & NOUNS and not
                                                  _of_a_thing(tokens, k + 2))) \
                and neg is not None and (verb is not None or set(tokens[k + 1:k + 1 + WINDOW]) & VERBS):
            return k   # not "any changes to X": a change of X
    return None


def _of_a_thing(tokens, i):
    """Whether tokens[i:] says which "any changes" it means: what they are to ("to the tests", "in the schema", "on
    main"; not the whole project: "to the code", "in this repo") or another word of PICKS ("that break the API",
    "beyond what the fix needs", "for the sake of style"); not how many or when ("of any kind", "under any
    circumstances", "in the meantime", "to any file", "for now")."""
    while tokens[i:i + 1] == ["directly"]:   # "directly on main": what follows says which
        i += 1
    t, after = tokens[i:i + 1], tokens[i + 1:i + 4]
    if t and t[0] in PICKS or t == ["for"] and after[:2] == ["the", "sake"]:
        return True
    return bool(set(t) & (WHERE | {"to", "on", "onto"})) and after[:1] != ["any"] \
        and after[:2] != ["the", "meantime"] and not set(after) & PROJECT \
        and not (t == ["on"] and after[:2] in (["your", "own"], ["my", "own"], ["this", "machine"], ["my", "machine"],
                                                 ["my", "computer"], ["this", "computer"], ["your", "computer"]))


def _else(tokens):
    """Whether the clause keeps everything else away: "everything else is out of scope", "leave everything else
    alone"."""
    k = next((k for k in range(len(tokens) - 1) if tokens[k:k + 2] == ["everything", "else"]), None)
    return k is not None and (bool(set(tokens[max(0, k - 2):k]) & LEAVE)
                              or _stated_after(tokens, k + 1, len(tokens), leave=True))


def _suffix(tokens, words):
    """[i]: whether a word of `words` comes after tokens[i] in the clause."""
    out, seen = [False] * (len(tokens) + 1), False
    for i in range(len(tokens) - 1, -1, -1):
        out[i] = seen
        seen = seen or tokens[i] in words
    return out


def _only(tokens, i, end, later):
    """Whether the file at tokens[i] is the only one to change: "only change X", "only X should change", "X is the only
    file to edit", "limit the change to X"."""
    before = tokens[max(0, i - WINDOW):i]
    if "only" in before and (set(before) & VERBS and not _negated(tokens, i)
                             or (k := _first(tokens, i, end)) < end and tokens[k] in VERBS):
        return True
    return tokens[i + 1:i + 4] in (["is", "the", "only"], ["are", "the", "only"]) and later[i + 3] \
        or tokens[i - 1:i] == ["to"] and bool(set(before) & SCOPE)


def _clause(tokens, before=()):
    """[(kind, object or None)] of one clause's tokens and the names of the files it keeps away; ("else", None): "don't
    change anything else", which extract() reads with the text's other files. `before`: the names of the files of the
    latest clause before it that names one, which "it" or "there" stands for in a clause that names none ("X is
    generated; make no changes there", _referent); none when that clause asks for a change or sets a condition ("fix X;
    don't rewrite it"): _read."""
    files = {i: t for i, t in enumerate(tokens) if _file(t)}
    if FOLDERS & set(tokens):   # "the vendor / .github folder": a directory; files stay in the clause's order
        files = dict(sorted({**files, **{i: t + "/" for i, t in enumerate(tokens[:-1]) if tokens[i + 1] in FOLDERS
                                         and t.lstrip(".").replace("_", "").replace("-", "").isalpha()
                                         and t not in DETERMINERS | PLACES}}.items()))
    if not files and not STATING & set(tokens):
        return [], set()
    cond, later = _conditions(tokens), _suffix(tokens, VERBS)
    out, kept, last, at = [], set(), None, [*files, len(tokens)] if files else ()
    m, only, excepts = _anything(tokens), (), False
    if m is not None:   # "don't change anything except X (or Y)": X and Y only, up to a negation after them
        only, excepted = set(), False
        for k in range(m + 1, len(tokens)):
            excepted = tokens[k] in EXCEPT or excepted and tokens[k] not in NEGATIONS
            excepts |= excepted
            if excepted and k in files:
                only.add(k)
    for n, (i, t) in enumerate(files.items()):
        if i in only or tokens[max(0, i - 2):i] in OUTSIDE and _stated_after(tokens, i, at[n + 1]):
            out.append(("only_change", norm(t)))
        elif _kept(tokens, i, at[n + 1], cond) or last in kept and set(tokens[last + 1:i]) <= LIST:
            kept.add(i)
            out.append(("keep_away", norm(t)))
        elif _only(tokens, i, at[n + 1], later):
            out.append(("only_change", norm(t)))
        last = i
    names = {norm(files[i]) for i in kept}
    k, before = _referent(tokens, before)
    if k is not None and _kept(tokens, k, len(tokens), cond):
        out += [("keep_away", n) for n in before]
        names.update(before)
    if m is not None and tokens[m] in ("anything", "nothing") and tokens[m + 1:m + 2] == ["else"] or _else(tokens):
        out.append(("else", None))
    elif m is not None and not files and not excepts and not cond[m] and (
            tokens[m] in ("anything", "any") or tokens[m] == "read-only" and _read_only(tokens, m)
            or tokens[m] == "nothing" and not set(tokens[m + 1:m + 2]) & {"should", "must", "may", "shall"}):
        out.append(("read_only", None))   # "except the docs": some change is allowed, but not which
    for i, t in enumerate(tokens):
        if t in PUSH and (n := _negation(tokens, i, NEGATIONS | {"no"})) is not None and _asking(tokens, n) \
                and not cond[i] and _bare(tokens, i):
            out.append(("no_push", None))
        elif t in NETWORK and _network(tokens, i) and not cond[i] or t == "offline" and _instruction(tokens, i) \
                and not cond[i]:
            out.append(("no_network", None))
    return list(dict.fromkeys(out)), names


def _read_only(tokens, i):
    """Whether "read-only" at tokens[i] is an instruction (READ_ONLY_AFTER)."""
    lead = next(k for k, t in enumerate(tokens) if t not in LEAD)
    after = tokens[i + 1:i + 2]
    return (i == lead or i - lead <= 3 and tokens[lead] in OFFLINE | {"everything"}) and (
        not after or after[0] in READ_ONLY_AFTER or after == ["mode"] and i > lead)


def _bare(tokens, i):
    """Whether the push at tokens[i] is every push: up to the next "or", "and" or "nor" (or a condition, which
    _conditions reads), only words of PUSHED follow it, and "to" or "into" only before a word of REMOTES ("don't push
    it to origin", not "to main")."""
    for k in range(i + 1, len(tokens)):
        t = tokens[k]
        if t in LIST or t in CONDITIONAL or t in WHILE:
            return True
        if t in ("to", "into", "onto"):
            return next((x for x in tokens[k + 1:] if x not in DETERMINERS), None) in REMOTES
        if t not in PUSHED:
            return False
    return True


def _referent(tokens, files):
    """(the index of a clause's "it", "there" or "them", the names it stands for: the last of `files`, those of the
    latest clause that names one (_files), or for "them" each of them), or (None, []) when the clause names a file
    itself."""
    k = None if any(map(_file, tokens)) else next((k for k, t in enumerate(tokens) if t in ANAPHORS), None)
    return (k, files if tokens[k] == "them" else files[-1:]) if k is not None and files else (None, [])


def _files(tokens):
    """The names (norm) of the files a clause names."""
    return [norm(t) for t in tokens if _file(t)]


def _network(tokens, i):
    """Whether the network word at tokens[i] is negated, as an instruction (_asking): only words of use between ("don't
    use the internet"), no noun after it ("don't change the network code", "no web UI changes")."""
    n = _negation(tokens, i, NEGATIONS | {"no"})
    return n is not None and _asking(tokens, n) and set(tokens[n + 1:i]) <= NET_USE and (
        i + 1 == len(tokens) or tokens[i + 1] in NET_AFTER)


def _instruction(tokens, i):
    """Whether "offline" at tokens[i] is an instruction: within three words of an OFFLINE word that begins the clause
    ("please work offline", "keep everything offline"; not "make the CLI work offline")."""
    lead = next(k for k, t in enumerate(tokens) if t not in LEAD)
    return i - lead <= 3 and tokens[lead] in OFFLINE


def _plain(text):
    """`text` without what it quotes: fenced code blocks, a quoted line ("> ...") or indented one (code, four spaces or
    a tab), and a span in backticks or double quotes that holds a space (a quoted file name stays)."""
    lines = []
    for line in "".join(text.split("```")[::2]).replace("“", '"').replace("”", '"').split("\n"):
        if line.lstrip().startswith(">") or line.startswith(("    ", "\t")):
            continue
        for q in ("`", '"'):
            parts = line.split(q)
            if len(parts) % 2:   # balanced
                line = "".join(p if k % 2 == 0 or not any(c.isspace() for c in p) else " "
                               for k, p in enumerate(parts))
        lines.append(line)
    return "\n".join(lines)


def _clauses(text):
    """The token lists of `text`'s clauses, quotes and code left out (_plain) and questions too, other than polite
    requests ("could you leave X alone?") and tagged ones ("don't touch X, ok?"): a clause that starts with an
    exception word ("except the docs", "but foo.py": with a file, as "but" also starts a clause of its own) after one
    that says "don't change anything" or "read-only" is part of it."""
    cur, marked = None, None   # marked: whether cur says so, once asked
    for sentence in SENTENCE.split(_plain(text[:MAX_TEXT]) if isinstance(text, str) else ""):
        parts = [_tokens(c) for c in CLAUSE.split(sentence)]
        if sentence.rstrip().endswith("?"):
            first = next((p for p in parts if p), [])
            if not any(tuple(first[:len(p)]) == p for p in POLITE) and not (len(parts) > 1 and parts[-1]
                                                                              and set(parts[-1]) <= TAGS):
                continue
        for tokens in parts:
            if cur is not None and tokens and tokens[0] in EXCEPT and (tokens[0] != "but" or any(
                    FILE_LIKE.search(t) and norm(t) for t in tokens)):
                marked = _anything(cur) is not None if marked is None else marked
                if marked:
                    cur += tokens
                    continue
            if cur is not None:
                yield cur
            cur, marked = tokens, None
    if cur is not None:
        yield cur


def _read(text):
    """[(the clause's tokens, its constraints, the names of the files it keeps away)] of each clause of `text`: what
    extract() and mentions() read, once per text."""
    out, before = [], []
    for tokens in _clauses(text):
        out.append((tokens, *_clause(tokens, before)))
        if any(map(_file, tokens)):   # read once: what a later "it" keeps away, if this clause asks no change of it
            before = [] if tokens[:1] in (["if"], ["unless"], ["when"], ["once"]) or any(
                t in ASKS_CHANGE and not _negated(tokens, i) for i, t in enumerate(tokens)) else _files(tokens)
    return out


def extract(text, read=None):
    """The constraints `text` states (or its _read(), `read`): [(kind, object or None)], each once, in order. "Don't
    change anything else" keeps the text to the files it names (only_change each; nothing when it names none)."""
    read = _read(text) if read is None else read
    # what a clause asks for, not negated -> the last such clause: a file it changes (_said), a LIFT word; by "it" or
    # "there" for the file named before, where the clause asks the agent for the change (ALLOWING: "X is frozen in
    # production, but you can edit it locally"; not "to change it, ...", "should you change it"), apart: that lifts no
    # constraint on the person's own go-ahead ("never touch X without asking me first. Change the timeout there"). No
    # file where the clause names the person's go-ahead, or the next clause does with nothing else to ask or refuse
    # ("you can change it after I approve", "..., but ask me first"; not "..., but don't push before I review")
    asked, by_it, before = {}, {}, []
    for j, (tokens, _, _) in enumerate(read if any(found for _, found, _ in read) else ()):
        nxt = set(read[j + 1][0]) if j + 1 < len(read) else set()
        near = set(tokens) | (set() if nxt & LIFT_WORDS or nxt & NEGATIONS else nxt)
        mine = PERSON & near and GO_AHEAD & near
        if tokens[:1] and tokens[0] in SEQUENCE:
            asked["then"] = j
        for i, t in enumerate(tokens):
            if _file(t) and not mine and _said(tokens, i) == "changed":
                asked[norm(t)] = j
            elif t in LIFT_WORDS and not _negated(tokens, i, NEGATIONS | {"no"}) and not BLOCK & set(tokens[:i]):
                asked[t] = j   # not "tell me what you'd change"
        k, it = _referent(tokens, before)
        c = None if k is None or mine else _tied(tokens, k, SAID_CHANGE)
        if c is not None and set(tokens[:c]) <= ALLOWING and not tokens[c].endswith(("s", "ed", "ing")) \
                and next(t for t in tokens if t not in LEAD) not in ("to", "should", "must"):
            by_it.update(dict.fromkeys(it, j))
        before = _files(tokens) or before
    out = [c for j, (tokens, found, _) in enumerate(read) for c in found if not any(asked.get(w, -1) > j for w in (
        (c[1],) if c[0] in OBJECT_KINDS else (*LIFT[c[0]], "then") if c[0] == "read_only" else LIFT.get(c[0], ())))
        and not (c[0] in OBJECT_KINDS and by_it.get(c[1], -1) > j and _mine(tokens) == len(tokens))]
    if ("else", None) in out:
        kept = set().union(*(k for _, _, k in read))
        out = [c for c in out if c[0] != "else"] + [("only_change", norm(t)) for tokens, _, _ in read for t in tokens
                                                    if _file(t) and norm(t) not in kept]
    return list(dict.fromkeys(out))


def changes(read):
    """{name: "changed" or "kept"} of the files (and words) a model's text (its _read()) says it changes or leaves
    alone. "changed": a change word whose object it is, not negated ("fixing X", "apply the same fix to X", "X needs
    the same fix", "the bug is in X; fixing it there"); "kept": what extract() keeps away, or such a change negated
    ("no need to change X", "X doesn't need any changes", "I won't need to edit X"). A mere mention ("X imports Y",
    "consistent with X") is neither."""
    out, before = {}, []
    for tokens, _, kept in read:
        for name in kept:
            out[name] = "kept"
        for i, name in [(i, norm(t)) for i, t in enumerate(tokens) if norm(t)]:
            said = name not in out and _said(tokens, i)
            if said:
                out[name] = said
        k, it = _referent(tokens, before)   # "fixing it": the file named before; for "them", each, read once
        if it and (said := _said(tokens, k)):
            out.update((name, said) for name in it if name not in out)
        before = _files(tokens) or before
    return out


def _said(tokens, i):
    """"changed", "kept" or None: what tokens[i]'s clause says of it (changes())."""
    for k in range(i - 1, max(0, i - WINDOW) - 1, -1):   # "the bug is in X": where the change goes
        if tokens[k] in BUG:
            return None if set(tokens[max(0, k - 2):k]) & SAID_NEG else "changed"
        if tokens[k] not in AT:
            break
    c = _tied(tokens, i, SAID_CHANGE)
    if c is not None:
        n = next((n for n in range(c - 1, max(0, c - WINDOW) - 1, -1) if tokens[n] in SAID_NEG), None)
        return "kept" if n is not None and not set(tokens[n + 1:c]) & TURNED else "changed"
    neg = False
    for k in range(i + 1, min(len(tokens), i + 1 + WINDOW)):   # "X needs the same fix", "X doesn't need changes"
        t = tokens[k]
        if t in SAID_CHANGE:
            return "kept" if neg else "changed"
        if t in SAID_NEG or t.endswith("n't"):
            neg = True
        elif t not in AUX:
            return None
    return None


def mentions(text, read=None):
    """(the files `text` (or its _read(), `read`) names other than to keep them away, the words of LIFT_WORDS it uses
    other than negated): what a later request lifts a constraint with."""
    names, words, read = set(), set(), _read(text) if read is None else read
    kept = set().union(*(k for _, _, k in read))
    for tokens, _, _ in read:
        for i, t in enumerate(tokens):
            if _file(t) and norm(t) not in kept:
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
    """What a shell command does: {"paths": what it writes as far as the policy engine's parser reads it, "dirs": those
    of its paths a recursive rm or rmdir deletes as directories, "cd": it changes directory, "push": a git push,
    "network": a command that reaches the network, "writes": it writes or commits}. `cmd`: a command line, or a shell
    call's arguments (`command` or `cmd` a line or an argv list, `commands` a list of lines), read as the policy engine
    reads them (policy2/shell.py: wrappers, `bash -c`, `eval`, substitutions and pipelines included).
    lean: redirections, the arguments of tee/touch/mkdir/rm/rmdir/truncate/shred/unlink and of formatters that write
    in place (black, isort, rustfmt; prettier --write, gofmt -w, ruff format, ruff check --fix, ...), cp/mv/install/
    ln/rsync/scp destinations, patch's file, dd of=, sed/perl -i files, git rm/mv/restore paths and git checkout's
    after `--`, and the -name of a find that deletes or runs a command; a word with a variable, a glob, braces or a
    command substitution is no path; a line the parser can't read (`case`, over its size) does nothing, and the
    policy's TK-SHELL-PARSE answers for it. Read scripts the call runs if real writes hide there."""
    out = {"paths": [], "dirs": [], "cd": False, "push": False, "network": False, "writes": False}
    try:
        cmds, _, _, written, _ = _parse(cmd if isinstance(cmd, dict) else
                                        {"command": cmd if isinstance(cmd, str) else ""})
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
        targets = (args if mode == "all" else args[-1:] if mode == "last" and len(args) > 1 else args[:1]
                   if mode == "first" else args[1:] if mode == "files" else [])
        sub = next((a for a in args[:2] if a in GIT_WRITES | NET_GIT), None) if name == "git" else \
            args[0] if args else None
        if name == "rmdir" or name == "rm" and ("--recursive" in rest or any(
                w[:1] == "-" and w[1:2] != "-" and set(w) & {"r", "R"} for w in rest)):
            out["dirs"] += targets   # "rm -r vendor" deletes vendor/ too
        elif name == "git" and sub in ("rm", "mv", "restore"):
            targets = args[args.index(sub) + 1:]
        elif name == "git" and sub == "checkout" and "--" in rest:
            targets = rest[rest.index("--") + 1:]
        elif name == "dd":
            targets = [a[3:] for a in rest if a.startswith("of=")]
        elif name == "find" and {"-delete", "-exec", "-execdir"} & set(rest):
            targets = [rest[k + 1] for k, a in enumerate(rest[:-1]) if a in FIND_NAMES]
        elif set(FORMATTERS.get(name, ())) & set(rest):
            targets = args
        elif name == "ruff" and (sub == "format" or sub == "check" and "--fix" in rest):
            targets = args[1:]
        out["paths"] += targets
        out["push"] = out["push"] or name == "git" and "push" in args
        out["network"] = out["network"] or name in NET_COMMANDS or name == "git" and sub in NET_GIT or (
            name in INSTALLERS and sub in INSTALL)
        out["writes"] = out["writes"] or bool(targets) or name == "patch" or name == "git" and sub in GIT_WRITES or (
            name in INSTALLERS and sub in INSTALL)
    written = [t for t in written if not t.startswith("/dev/")]   # /dev/null, a terminal, a descriptor: no file
    out["writes"] = out["writes"] or bool(written)
    out["paths"] = [t for t in out["paths"] + written if not set(t) & UNREAD]
    out["dirs"] = [t for t in out["dirs"] if not set(t) & UNREAD]
    return out


def facts(tool, args, cls=None):
    """What call (`tool`, `args`) does, as far as a constraint cares: {"names": the basenames of what it writes, then
    the directories over them (names()), "write": it writes at all, "push": a git push, "network": it reaches the
    network}. `cls`: the policy's class of the tool when known (http and browser calls reach the network). A write tool
    (or another fs tool that writes) writes its path and each of its `paths` (every file of a Codex patch, whose text is
    its `command`); any other call with a command (`command`, `cmd` or `commands`) is a shell command."""
    args = args if isinstance(args, dict) else {}
    write = tool in WRITE_TOOLS or cls == "fs" and tool not in READ_TOOLS and args.get("op") != "read"
    if not write and any(args.get(k) is not None for k in SHELL_KEYS):
        s = shell(args)
        return {"names": names(s["paths"] + [d.rstrip("/") + "/" for d in s["dirs"] if d.rstrip("/")]),
                "write": s["writes"], "push": s["push"], "network": s["network"]}
    paths = [next((args[k] for k in PATH_KEYS if isinstance(args.get(k), str)), None),
             *(args["paths"] if isinstance(args.get("paths"), list) else ())]
    return {"names": names([p for p in paths if isinstance(p, str)]) if write else [],
            "write": write, "push": False, "network": cls in ("http", "browser") or tool in NET_TOOLS}


def breaks(kind, f, is_object):
    """What in a call (its `facts`) breaks a constraint of `kind` whose object `is_object(name)` tests: the file name,
    or the kind's own word ("push", "network", "write"); None when it doesn't."""
    if kind == "keep_away":
        return next((n for n in f["names"] if is_object(n)), None)
    if kind == "only_change":   # a file's directories ("src/") are no file of it
        return next((n for n in f["names"] if not n.endswith("/") and not is_object(n)), None)
    if kind == "read_only":
        return (f["names"] or ["write"])[0] if f["write"] else None
    return {"no_push": "push", "no_network": "network"}[kind] if f[kind[3:]] else None


def held(kind, name):
    """What the agent is told when a live constraint holds its call (`name`: from breaks(), out of its own
    arguments; for "many", the most files of one call the signer checks; for "full", the most file constraints a run
    takes)."""
    return {"keep_away": f"the person's request in this run said not to modify {name}",
            "only_change": f"the person's request in this run said to change only certain files, and {name} is not "
                           "one of them",
            "read_only": "the person's request in this run said to make no changes (read-only)",
            "no_push": "the person's request in this run said not to push",
            "no_network": "the person's request in this run said not to use the network",
            "many": f"the call writes more than {name} files, more than are checked against what the person's request "
                    "in this run said not to change",
            "full": f"the run has the most file constraints the signer takes ({name}), and a further one was not "
                    "added, so every write is held"}[kind] + \
        "; ask the person"
