"""TK-X205 and the v1 text checks on a v2 run (`tracekit analyze --v2`, docs/findings.md): what the model told the
person against what the run did.

  TK-X205 (critical) a success claim (tests pass, fixed, works, done, builds, deployed, merged, pushed, ...) after the
          last related call failed: its signed result is ok: false, or its output reads as a failure (`2 failed`, a
          Traceback, a non-zero exit, a test runner's failure summary). Related: a test run for a test claim; the last
          test run and the last build for "fixed", "done", "works"; a deploy, merge, push, commit or install for those.
  TK-X101..X104 (high) the model said it ran the tests (or that they pass), committed, pushed or installed, and no
          such command ran before it (nor in the same model message)
  TK-X111..X114 (critical) the model said it did not push, delete, change files or use the network, after the run
          did: a denial that names files or words ("didn't touch billing.py", "nothing else") is read against those
  TK-X120 (high) a risky action (force push, recursive delete, history rewrite, migration or drop, package publish,
          sudo) ran, and nothing the model said with it or after it mentions it

The ported checks keep v1's ids and meaning (tracekit/findings.py, whose X105 TK-X205 generalises; X001/X002 are the
signer's reconcile, X004/X005 are dropped). They read the v2 view: what the model said from the vault through
parsers.said (its text for claims and denials; text and reasoning for a mention), a gateway's record of a message in
place of an agent's, commands from the arguments the signer decided on, a result from its signed tool.result (`ok`)
and vaulted content, else the transcript's copy of it, which can show a failure but never clear one.

Read in tokens, never with backtracking regular expressions: each pattern is a word set or a short token sequence and
each text is cut at MAX_TEXT characters, so the pass is linear in what it reads (tests/test_findings_text.py times
64 KiB hostile inputs) and stays within the analysis's time budget (past it, what is left is not checkable: budget).
"""
import bisect
import hashlib
import posixpath
import re
import shlex

from .findings import WRITE_TOOLS

CLAIMED = {"TK-X101": "tests", "TK-X102": "commit", "TK-X103": "push", "TK-X104": "install"}
DENIED = ("TK-X111", "TK-X112", "TK-X113", "TK-X114")
CHECKS = ("TK-X205", *CLAIMED, *DENIED, "TK-X120")
MESSAGE_CHECKS = CHECKS[:-1]   # counted per model message with text; TK-X120 per call
SEVERITIES = {"TK-X205": "critical", "TK-X101": "high", "TK-X102": "high", "TK-X103": "high", "TK-X104": "high",
              "TK-X111": "critical", "TK-X112": "critical", "TK-X113": "critical", "TK-X114": "critical",
              "TK-X120": "high"}
# also rpc_schema.FINDING_TITLES: the fixed titles the signer writes beside a signed finding
TITLES = {"TK-X205": "Success claimed after a failure", "TK-X101": "Test run claimed, none ran",
          "TK-X102": "Commit claimed, none ran", "TK-X103": "Push claimed, none ran",
          "TK-X104": "Install claimed, none ran", "TK-X111": "Push denied, but it ran",
          "TK-X112": "Deletion denied, but it ran", "TK-X113": "File changes denied, but files changed",
          "TK-X114": "Network use denied, but it ran", "TK-X120": "Risky action not mentioned"}
_DENIAL = ("the model told the person it did not do something the run shows it did",
           "read the action and its result, and treat the rest of the model's account of this run with care")
WHY = {
    "TK-X205": ("the model told the person it succeeded while the last check it ran had failed",
                "rerun the failing command and read its output before relying on this run's result"),
    **dict.fromkeys(CLAIMED, ("the model claimed an action that no command in the run carried out",
                              "run the action yourself, or check that it ran some way Tracekit does not see")),
    **dict.fromkeys(DENIED, _DENIAL),
    "TK-X120": ("a risky action ran and the model's account of the run leaves it out",
                "check what the action changed; require approval for it with a policy rule"),
}
REASONS = {   # not checkable: (why, the change that makes it checkable)
    "no_result": ("the call a claim rests on has no recorded result",
                  "complete every call (the integrations do; a crashed agent leaves its last call without one)"),
    "no_account": ("the model said nothing readable with the action or after it",
                   "keep the model's messages: Claude Code `tracekit init --dev --v2` with the content vault on; "
                   "other agents the Tracekit LLM gateway (docs/gateway.md)"),
}

MAX_TEXT = 1 << 16   # lean: characters of one record's text these checks read; past it the rest of a message is cut
SNIPPET = 160
MAX_NAMES = 16   # lean: the files and words of one denial matched against a call's targets; past it they are cut
# a word (a file name or path keeps its dots and slashes, "didn't" its apostrophe), or one other character
TOKEN = re.compile(r"[a-z0-9_]+(?:'[a-z]+)?(?:[./][a-z0-9_]+)*|\S")
PARTS = re.compile(r"[/._:+-]+")

STOPS = frozenset(".!?;")
BREAKS = frozenset((",", ":", "(", ")", "—", "–", "but", "however", "although", "though", "except", "whereas",
                    "while"))
NEG = frozenset(("not", "no", "never", "nothing", "none", "nor", "neither", "cannot", "without", "nobody"))
HEDGE = frozenset(("should", "would", "could", "might", "may", "will", "shall", "once", "if", "unless", "until",
                   "whether", "when", "whenever", "expect", "expecting", "hopefully", "hope", "likely", "probably",
                   "need", "needs", "try", "trying", "going", "want", "plan", "planning", "let", "let's", "lets",
                   "sure", "ensure", "assuming", "supposed"))
PAST = frozenset(("initially", "earlier", "previously", "originally", "before", "first", "was", "were", "had"))
ZERO = frozenset(("no", "zero", "0", "without", "nothing", "none"))
FAILS = frozenset(("fail", "fails", "failed", "failing", "failure", "failures", "error", "errors", "errored",
                   "broken", "breaks", "broke", "crash", "crashes", "crashed", "flaky", "regression", "regressions"))
# a success word says something worked only beside what it is about ("the tests pass", "the build is clean")
SUCCESS = frozenset(("pass", "passes", "passed", "passing", "green", "succeed", "succeeds", "succeeded", "successful",
                     "successfully", "ok", "okay", "clean", "cleanly", "happy", "good", "fine", "work", "works",
                     "worked", "working", "compiles", "compiled", "builds"))
# these claim success on their own ("Done.", "The fix works.", "All green.")
GENERIC = frozenset(("fixed", "resolved", "solved", "done", "complete", "completed", "finished", "works", "worked",
                     "working", "succeeded", "successful", "successfully", "green", "ready", "passes", "passing"))
# phrases that claim success as GENERIC words do ("All set.", "That did the trick.", "The bug is gone.")
IDIOMS = frozenset((("all", "set"), ("all", "good"), ("good", "to", "go"), ("did", "the", "trick"), ("checks", "out"),
                    ("wrapped", "up"), ("is", "gone"), ("are", "gone")))
SPECIFIC = {"deployed": "deploy", "shipped": "deploy", "released": "deploy", "merged": "merge", "pushed": "push",
            "committed": "commit", "installed": "install"}
TEST_NOUNS = frozenset(("test", "tests", "testing", "tested", "suite", "suites", "spec", "specs", "ci", "checks",
                        "pytest", "jest", "vitest", "mocha", "unittest", "rspec", "tox", "phpunit", "e2e"))
BUILD_NOUNS = frozenset(("build", "builds", "compile", "compiles", "compiled", "compilation"))
LINT_NOUNS = frozenset(("lint", "linter", "linting", "lints", "mypy", "ruff", "eslint", "flake8", "pylint", "pyright",
                        "typecheck", "typechecks", "types", "clippy", "tsc"))
RAN = frozenset(("ran", "reran", "rerun", "executed", "tested", "verified", "confirmed", "validated"))
FAMILIES = {"tests": ("test",), "generic": ("test", "build"), "build": ("build",), "lint": ("lint",),
            "deploy": ("deploy",), "merge": ("merge",), "push": ("push",), "commit": ("commit",),
            "install": ("install",)}
DENY = {"TK-X111": frozenset(("push", "pushed", "pushing", "pushes", "remote", "remotes", "origin", "upstream",
                              "github")),
        "TK-X112": frozenset(("delete", "deleted", "deleting", "deletes", "remove", "removed", "removing", "removes",
                              "erase", "erased", "wipe", "wiped", "rm")),
        "TK-X113": frozenset(("touch", "touched", "touching", "modify", "modified", "modifying", "modifications",
                              "change", "changed", "changing", "changes", "edit", "edited", "editing", "edits",
                              "alter", "altered", "write", "wrote", "written", "writing", "rewrite", "rewrote",
                              "update", "updated", "updating")),
        "TK-X114": frozenset(("network", "internet", "external", "outbound", "http", "https", "online"))}
NET_NOUNS = frozenset(("calls", "call", "requests", "request", "connections", "connection", "traffic", "access",
                       "services", "service", "apis", "api", "endpoints", "endpoint", "downloads", "downloaded",
                       "fetch", "fetched", "sent", "hosts"))
KEPT = {"TK-X111": frozenset(("unpushed",)), "TK-X113": frozenset(("untouched", "unchanged", "intact", "unmodified")),
        "TK-X114": frozenset(("offline",))}
LOCAL_VERBS = frozenset(("kept", "keep", "keeping", "left", "leave", "leaving", "remain", "remains", "stay", "stays",
                         "still", "only"))
OTHER = frozenset(("else", "other", "others", "besides", "outside", "beyond", "apart"))
DENIED_WORDS = frozenset().union(*DENY.values(), *KEPT.values(), LOCAL_VERBS, NET_NOUNS, ("local", "locally"))
GENERIC_OBJECTS = frozenset((
    "the", "a", "an", "any", "anything", "everything", "all", "some", "it", "its", "them", "they", "this", "that",
    "these", "those", "i", "we", "you", "my", "our", "your", "to", "in", "on", "of", "for", "from", "with", "at", "by",
    "and", "or", "so", "as", "is", "are", "be", "been", "have", "has", "do", "does", "did", "make", "made", "single",
    "one", "file", "files", "code", "codebase", "repo", "repository", "project", "thing", "things", "here", "there",
    "now", "existing", "related", "needed", "necessary", "required", "also", "just", "actually", "really", "during",
    "session", "task", "work", "branch", "branches", "remote", "origin", "upstream", "commits", "commit", "anywhere",
    "yet", "over", "via", "using", "use", "used", "calls", "call", "requests", "request", "connections", "access",
    "service", "services", "data", "content", "contents", "single", "own", "way", "time", "again", "further",
    "additional", "more", "else", "other", "others", "was", "were", "will", "would", "been", "being", "can", "could",
    "should", "please", "i'm", "i've", "we've", "it's", "there's", "which", "what", "who", "where", "how", "why",
    "anyone", "machine", "outside", "beyond", "besides", "apart", "except", "than", "only", "still", "left"))
DENY_RULES = {w: tuple(r for r in DENY if w in DENY[r] or w in KEPT.get(r, ())) for w in
              frozenset().union(*DENY.values(), *KEPT.values())}
# a clause with none of these words claims, admits and denies nothing: it is not read further
TRIGGERS = frozenset().union(SUCCESS, GENERIC, SPECIFIC, RAN, FAILS, DENY_RULES, *IDIOMS, (
    "run", "made", "created", "except", "local", "locally", "machine"))
# what v1 counted as mentioning each risky action (findings.py), with the plain words for a deletion
MENTIONS = {"force push": ("force", "--force"), "recursive delete": ("delet", "remov", "rm -", "clean", "wipe", "purg"),
            "history rewrite": ("reset", "rebase", "rewr"), "database migration or drop": ("migrat", "drop"),
            "package publish": ("publish", "upload"), "privilege escalation": ("sudo", "root")}

# --------------------------------------------------------------------------- commands
SEPARATORS = frozenset((";", ";;", "&&", "||", "|", "|&", "&", "(", ")"))
PREFIXES = frozenset(("sudo", "doas", "env", "time", "nice", "nohup", "command", "exec", "npx", "bunx", "pnpx",
                      "timeout", "stdbuf", "xargs"))
RUNNERS = {"uv": "run", "poetry": "run", "pipenv": "run", "pdm": "run", "hatch": "run", "rye": "run",
           "bundle": "exec", "npm": "exec"}
PYTHONS = re.compile(r"python(?:3(?:\.\d+)?)?|py|pypy3?")
TEST_PROGS = frozenset(("pytest", "py.test", "jest", "vitest", "mocha", "rspec", "tox", "nox", "phpunit", "ctest",
                        "ava", "karma", "nose2", "trial", "behave", "cucumber", "unittest"))
LINT_PROGS = frozenset(("ruff", "flake8", "pylint", "mypy", "pyright", "eslint", "golangci-lint", "rubocop",
                        "shellcheck", "biome"))
NET_PROGS = frozenset(("curl", "wget", "http", "https", "nc", "ncat", "netcat", "ssh", "scp", "sftp", "rsync", "ftp",
                       "telnet", "socat"))
NET_TOOLS = frozenset(("webfetch", "websearch", "web_fetch", "web_search", "fetch", "http_request"))
JS = frozenset(("npm", "yarn", "pnpm", "bun"))
SHELL_KEYS = ("command", "cmd", "script", "commands")


def _clip(v):
    return v[:MAX_TEXT] if isinstance(v, str) else ""


def _simple(cmd):
    """The simple commands of a shell command line, each a list of words."""
    for line in _clip(cmd).split("\n"):
        if not line.strip():
            continue
        try:
            lex = shlex.shlex(line, posix=True, punctuation_chars=True)
            lex.whitespace_split = True
            words = list(lex)
        except ValueError:   # unbalanced quotes: words as whitespace leaves them
            words = line.split()
        cur = []
        for w in words:
            if w in SEPARATORS:
                if cur:
                    yield cur
                cur = []
            else:
                cur.append(w)
        if cur:
            yield cur


def _argv(words):
    """(program, its arguments) of one simple command, past variable assignments and wrappers (sudo, env, timeout,
    `uv run`, `bundle exec`, ...); and whether a wrapper was sudo or doas."""
    i, sudo = 0, False
    while i < len(words):
        w, base = words[i], posixpath.basename(words[i])
        if "=" in w and w.split("=", 1)[0].isidentifier():
            i += 1
        elif base in PREFIXES:
            sudo = sudo or base in ("sudo", "doas")
            i += 1
            while i < len(words) and (words[i].startswith("-") or words[i][:1].isdigit()):
                i += 1
        elif RUNNERS.get(base) and i + 1 < len(words) and words[i + 1] == RUNNERS[base]:
            i += 2
        else:
            break
    if i >= len(words):
        return "", [], sudo
    return posixpath.basename(words[i]).lower(), words[i + 1:], sudo


def _force(args):
    return any(a in ("-f", "--force") or a.startswith(("--force", "+")) and len(a) > 1
               or a[:1] == "-" and a[1:2] != "-" and "f" in a for a in args)


def command_facts(cmd):
    """(families: what a command line does, as v1's patterns and more runners named it; its write targets; its delete
    targets; the words of its git pushes). Families: test, build, lint, commit, push, install, delete, network,
    deploy, merge, and the risky labels of TK-X120."""
    from .findings_v2 import _targets
    fams, deletes, pushes = set(), [], []
    for words in _simple(cmd):
        prog, args, sudo = _argv(words)
        if sudo:
            fams.add("privilege escalation")
        plain = [a for a in args if not a.startswith("-")]
        sub, nxt = (plain + ["", ""])[:2]
        sub, nxt = sub.lower(), nxt.lower()
        low = [w.lower() for w in words]
        parts = {p for w in low for p in PARTS.split(w)}
        if "migrate" in parts or prog == "alembic" and "upgrade" in plain or any(
                a == "drop" and b in ("table", "database", "schema") for a, b in zip(low, low[1:])):
            fams.add("database migration or drop")
        if PYTHONS.fullmatch(prog) and "-m" in args:
            mod = args[args.index("-m") + 1].lower() if args.index("-m") + 1 < len(args) else ""
            prog, args = mod, args[args.index("-m") + 2:]
            plain = [a for a in args if not a.startswith("-")]
            sub = plain[0].lower() if plain else ""
        if prog in TEST_PROGS or prog == "playwright" and sub == "test":
            fams.add("test")
        elif prog in JS:
            if sub in ("test", "t") or sub == "run" and nxt.startswith("test"):
                fams.add("test")
            elif sub == "run" and nxt in ("build", "compile"):
                fams.add("build")
            elif sub == "run" and nxt in ("lint", "typecheck", "type-check", "check"):
                fams.add("lint")
            elif sub == "run" and nxt.startswith("deploy"):
                fams.add("deploy")
            elif sub in ("install", "i", "add", "ci"):
                fams.add("install")
            elif sub == "publish":
                fams.add("package publish")
        elif prog in ("go", "cargo", "dotnet", "deno", "swift", "mix", "bazel"):
            fams.add({"test": "test", "nextest": "test", "build": "build", "check": "build", "vet": "lint",
                      "clippy": "lint", "install": "install", "add": "install", "get": "install",
                      "publish": "package publish"}.get(sub, ""))
        elif prog in ("make", "gmake"):
            fams.add("test" if sub in ("test", "tests", "check") else "build" if sub in ("", "all", "build") else
                     "lint" if sub == "lint" else "deploy" if sub.startswith("deploy") else "")
        elif prog in ("mvn", "mvnw", "gradle", "gradlew"):
            tasks = {a.lower().rsplit(":", 1)[-1] for a in plain}
            fams.add("test" if tasks & {"test", "verify", "check"} else
                     "build" if tasks & {"compile", "package", "install", "build", "assemble"} else "")
        elif prog in ("tsc", "webpack") or prog in ("next", "vite") and sub == "build" or prog == "cmake" and (
                "--build" in args) or prog == "build":
            fams.add("lint" if "--noemit" in {a.lower() for a in args} else "build")
        elif prog in LINT_PROGS or prog in ("black", "prettier") and "--check" in args:
            fams.add("lint")
        elif prog in ("pip", "pip3", "pipx", "conda", "gem", "brew", "apt", "apt-get") and sub == "install" \
                or prog == "uv" and (sub == "add" or sub == "pip" and nxt == "install") or prog == "poetry" and (
                sub == "add"):
            fams.add("install")
        elif prog in ("twine", "flit", "poetry", "uv") and sub in ("upload", "publish") or prog == "gem" and (
                sub == "push"):
            fams.add("package publish")
        elif prog in ("rm", "rmdir", "unlink", "shred", "srm"):
            fams.add("delete")
            deletes += plain
            flags = "".join(a[1:] for a in args if a[:1] == "-" and a[1:2] != "-")
            if prog == "rm" and ("r" in flags or "R" in flags or "--recursive" in args):
                fams.add("recursive delete")
        elif prog == "find" and "-delete" in args:
            fams.add("delete")
            deletes += plain[:1]
        elif prog in NET_PROGS:
            fams.add("network")
        elif prog == "git":
            j = 0
            while j < len(args) and args[j].startswith("-"):   # git -C dir, -c key=value
                j += 2 if args[j] in ("-C", "-c") else 1
            gsub, rest = (args[j].lower(), args[j + 1:]) if j < len(args) else ("", [])
            fams.add({"commit": "commit", "push": "push", "merge": "merge", "rebase": "history rewrite",
                      "filter-branch": "history rewrite", "filter-repo": "history rewrite", "rm": "delete",
                      "pull": "network", "fetch": "network", "clone": "network", "ls-remote": "network"}.get(gsub, ""))
            if gsub == "push":
                fams.add("network")
                pushes += rest
                if _force(rest):
                    fams.add("force push")
            elif gsub == "rm":
                deletes += [a for a in rest if not a.startswith("-")]
            if gsub == "reset" and "--hard" in rest or "--rebase" in rest:
                fams.add("history rewrite")
        elif prog == "gh" and sub == "pr" and nxt == "merge":
            fams.add("merge")
        elif prog in ("kubectl", "helm", "terraform", "pulumi", "fly", "flyctl", "netlify", "vercel", "serverless",
                      "sls", "cdk", "eb", "gcloud", "ansible-playbook") and (
                sub in ("apply", "up", "deploy", "install", "upgrade", "rollout") or "deploy" in plain
                or prog in ("vercel", "ansible-playbook")) or prog.startswith("deploy"):
            fams.add("deploy")
    fams.discard("")
    writes = [p for p in _targets(cmd)[0] if not p.startswith("/dev/")]
    return fams, writes, deletes, pushes


# --------------------------------------------------------------------------- results

# a runner's own failure summary, a non-zero exit: the run failed, whatever else its output says
FAIL_LINES = ("FAIL", "--- FAIL", "Failed!", "FAILURES!", "BUILD FAILED", "BUILD FAILURE", "npm ERR!", "make: ***",
              "! [rejected]", "✕", "✗")
FAIL_TEXT = ("test result: failed", "tests failed", "test failed", "build failed", "build failure",
             "compilation failed", "non-zero exit", "nonzero exit", "command failed", "no tests ran",
             "no tests found", "elifecycle", "failed to push")
# a crash or an error line: a failure unless the runner's summary says the run passed (a passing test may log one)
WEAK_LINES = ("ERROR", "Traceback (most recent call last)", "panic:", "error[", "error:", "Error:", "fatal:", "[ERROR]",
              "E   ")
WEAK_TEXT = ("traceback (most recent call last)", "panicked at", "assertionerror", "assertion failed",
             "segmentation fault")
PASS_LINES = ("OK", "ok ", "ok\t", "PASS", "BUILD SUCCESS", "test result: ok")
FAIL_WORDS = frozenset(("failed", "failing", "failure", "failures", "error", "errors", "errored", "broken"))
COUNTED = frozenset(("test", "tests", "spec", "specs", "example", "examples", "suite", "suites", "check", "checks",
                     "file", "files", "assertion", "assertions"))
EXIT_KEYS = frozenset(("exit_code", "exitcode", "returncode", "return_code", "exit_status"))


def _count(t):
    """`t` is a number above 0 (read without int(): a token may be thousands of digits long)."""
    return t.isdigit() and t.strip("0") != ""


def failure(text):
    """A short quote of the line that makes `text`, a command's output, read as a failure, or None. A runner's
    failure summary (`2 failed`, `FAILED (failures=1)`, `--- FAIL`, `Tests: 1 failed`), `failures=N` or a non-zero
    exit decides; a Traceback or an error line counts unless a pass summary (`3 passed`, `OK`, `ok  pkg`) is there."""
    weak, passed = None, False
    for line in _clip(text).split("\n"):
        s = line.strip()
        low = s.lower()
        if s.startswith(FAIL_LINES) or s.endswith((" FAILED", " FAILED]", " FAIL")) or any(f in low for f in FAIL_TEXT):
            return s[:SNIPPET]
        ts = TOKEN.findall(low)
        for i, t in enumerate(ts):
            if t in FAIL_WORDS and (
                    i and _count(ts[i - 1]) or i > 1 and ts[i - 1] in COUNTED and _count(ts[i - 2])
                    or i + 2 < len(ts) and ts[i + 1] in ("=", ":") and _count(ts[i + 2])):
                return s[:SNIPPET]   # "2 failed", "1 tests failed", "failures=1", "Errors: 3"
            if t in ("exit", "exited") and any(_count(x) for x in ts[i + 1:i + 5]) and "0" not in ts[i + 1:i + 5] \
                    and {"code", "status"} & set(ts[i + 1:i + 4]):
                return s[:SNIPPET]   # "Exit code 1", "exit status 2", "exited with code 1"
            if t in ("passed", "passing") and i and _count(ts[i - 1]):
                passed = True        # "3 passed", "2 passing"
        passed = passed or s == "OK" or s.startswith(PASS_LINES) and not s.startswith(("OKAY", "PASSWORD"))
        if weak is None and (s.startswith(WEAK_LINES) or any(f in low for f in WEAK_TEXT)):
            weak = s[:SNIPPET]
    return None if passed else weak


def _strings(v, out, left):
    """String leaves of `v` (a tool result), up to `left` characters, and whether a key names a non-zero exit."""
    exit_ = False
    stack = [v]
    while stack and left > 0:
        x = stack.pop()
        if isinstance(x, str):
            out.append(x[:left])
            left -= len(out[-1])
        elif isinstance(x, dict):
            for k, y in x.items():
                if str(k).lower() in EXIT_KEYS and isinstance(y, int) and not isinstance(y, bool) and y:
                    exit_ = True
                stack.append(y)
        elif isinstance(x, list):
            stack.extend(reversed(x))
    return exit_


def result_failure(v):
    """Why a tool result's content reads as a failure, or None."""
    out = []
    if _strings(v, out, MAX_TEXT):
        return "a non-zero exit code"
    return failure("\n".join(out))


# --------------------------------------------------------------------------- what the model said

def _sentences(text):
    """(the sentence as written, [clauses, each a list of lower-cased tokens], a question) of `text`."""
    for line in _clip(text).replace("’", "'").split("\n"):
        clauses, cur, start = [], [], 0
        for m in TOKEN.finditer(line.lower()):
            t = m.group()
            if t in STOPS:
                if cur:
                    clauses.append(cur)
                if clauses:
                    yield line[start:m.end()].strip(), clauses, t == "?"
                clauses, cur, start = [], [], m.end()
            elif t in BREAKS:
                if cur:
                    clauses.append(cur)
                cur = ["except"] if t == "except" else []
            else:
                cur.append(t)
        if cur:
            clauses.append(cur)
        if clauses:
            yield line[start:].strip(), clauses, False


def _negates(t):
    return t in NEG or t.endswith("n't")


def _clause(ts):
    """(the words with which this clause claims something worked or was done, whether it says something failed or
    does not work, the verbs of an action it says was run)."""
    words = set(ts)
    claims, admits, neg, hedge = set(), "except" in words, False, False
    succ = words & (SUCCESS | GENERIC)
    for i, t in enumerate(ts):
        nxt = ts[i + 1:i + 3]
        if tuple(ts[i:i + 2]) in IDIOMS or tuple(ts[i:i + 3]) in IDIOMS:
            t = "done"   # an idiom claims what "done" does
        if _negates(t) and not (t in ZERO and any(x in FAILS for x in nxt)):
            neg = True
        elif t in HEDGE or t.endswith(("'ll", "'d")) or t == "to" and nxt[:1] and nxt[0] in SUCCESS | GENERIC:
            hedge = True
        elif t in FAILS:
            if any(x in ZERO for x in ts[max(0, i - 2):i]):
                claims.add("zero")   # "no failures", "0 failed", "nothing failed": a clean run claimed
            elif not succ and not words & PAST or i and _count(ts[i - 1]):
                admits = True        # "2 tests fail", "the build is broken"; not "fixed the failing test"
        elif t in SUCCESS or t in GENERIC or t in SPECIFIC or t in RAN or t == "run" and i and ts[i - 1] in (
                "have", "has", "had", "i've", "we've"):
            if neg:
                admits = admits or t in SUCCESS or t in GENERIC   # "doesn't work", "not passing", "isn't fixed"
            elif not hedge and not (t == "working" and nxt[:1] == ["on"]) and not (
                    t == "installed" and i and ts[i - 1] in ("already", "is", "are", "be", "pre")):
                claims.add(t)
    return claims, admits


def _objects(ts):
    """What a denial in clause `ts` is about: ("any",), ("else",) for "anything else", or ("named", names): the files
    and words it names."""
    if set(ts) & OTHER:
        return ("else",)
    rest = tuple(t for t in ts if t not in GENERIC_OBJECTS and not _negates(t) and t not in HEDGE and len(t) > 1
                 and t[0].isalnum() and not t.isdigit() and t not in DENIED_WORDS)
    return ("named", rest[:MAX_NAMES]) if rest else ("any",)


def _denials(ts):
    """{rule: objects} of the denials in one clause: a negation before a denied verb ("didn't push", "no changes",
    "nothing was deleted"), a word that denies on its own ("untouched", "offline"), or work kept local."""
    out, neg, words = {}, False, set(ts)
    for i, t in enumerate(ts):
        if _negates(t) and not (t in ZERO and any(x in FAILS for x in ts[i + 1:i + 3])):
            neg = True
        for rule in DENY_RULES.get(t, ()):
            if rule not in out and (neg or t in KEPT.get(rule, ())) and (
                    rule != "TK-X114" or t in ("network", "internet", "outbound", "offline") or words & NET_NOUNS):
                out[rule] = _objects(ts)
    if words & {"local", "locally"} and words & LOCAL_VERBS or {"my", "machine"} <= words and words & LOCAL_VERBS:
        out.setdefault("TK-X111", ("any",))
    if "TK-X111" in out:   # "no remote was updated" is about the push, not the files
        out.pop("TK-X113", None)
    return out


def read_message(text):
    """What one model message says: {"claims": categories it claims ("tests", "tests_run", "generic", "build",
    "lint", "deploy", "merge", "push", "commit", "install"), "denials": {rule: objects}, "files": the file names
    it names, "quote": {category or rule: the sentence}}; a sentence that admits a failure or does not work makes
    the message claim no success, whatever its other sentences say."""
    cats, denials, quote, admits, files = set(), {}, {}, False, set()
    for sentence, clauses, question in _sentences(text):
        words = {t for c in clauses for t in c}
        files |= {posixpath.basename(t) for t in words if "." in t[1:-1] or "/" in t}
        found = set()
        for ts in clauses:
            if TRIGGERS.isdisjoint(ts):
                continue
            claims, admit = _clause(ts)
            admits = admits or admit
            if question:
                continue
            for rule, obj in _denials(ts).items():
                denials.setdefault(rule, obj)
                quote.setdefault(rule, sentence)
            if claims & (SUCCESS | {"zero"}) - GENERIC:
                found.add("tests" if words & TEST_NOUNS or "zero" in claims and not words & (BUILD_NOUNS | LINT_NOUNS)
                          else "build" if words & BUILD_NOUNS else "lint" if words & LINT_NOUNS else
                          "generic" if claims & GENERIC else "")   # "no failures": a clean check run claimed
            if claims & GENERIC:
                found.add("tests" if words & TEST_NOUNS and claims & SUCCESS else "build" if words & BUILD_NOUNS
                          and claims & SUCCESS else "generic")
            if claims & RAN and set(ts) & TEST_NOUNS or "run" in claims and set(ts) & TEST_NOUNS:
                found.add("tests_run")
            elif claims & {"verified", "confirmed", "validated"}:
                found.add("generic")   # "I verified the fix": it works, says the model
            if {"made", "created"} & set(ts) and {"commit", "commits"} & set(ts):
                found.add("commit")
            found |= {SPECIFIC[w] for w in claims if w in SPECIFIC}
        found.discard("")
        for c in found:
            quote.setdefault(c, sentence)
        cats |= found
    if admits:
        cats -= {"tests", "generic", "build", "lint"}
    return {"claims": cats, "denials": denials, "files": files, "quote": quote}


def mentions(text):
    """The risky actions (TK-X120's labels) `text` mentions, as v1 read it: a fixed word stem anywhere."""
    low = _clip(text).lower()
    return {label for label, stems in MENTIONS.items() if any(s in low for s in stems)}


# --------------------------------------------------------------------------- the check

def _snip(s):
    s = " ".join(s.split())
    return s if len(s) <= SNIPPET else s[:SNIPPET - 1] + "…"


def _about(names, path):
    """Whether a denial that names `names` (file names or words) is about `path`."""
    low = path.lower()
    base, parts = posixpath.basename(low), set(PARTS.split(low))
    return any(base == posixpath.basename(n) if "." in n[1:-1] or "/" in n else n in parts or n.rstrip("s") in parts
               for n in names)


def _hit(obj, targets, allowed):
    """The targets of a call (paths, push words) a denial's objects cover."""
    if obj[0] == "any":
        return list(targets)
    if obj[0] == "else":
        return [t for t in targets if posixpath.basename(t.lower()) not in allowed]
    return [t for t in targets if _about(obj[1], t)]


def _shell(args):
    if not isinstance(args, dict):
        return None
    for k in SHELL_KEYS:
        v = args.get(k)
        if isinstance(v, str):
            return v
        if isinstance(v, list) and v and all(isinstance(x, str) for x in v):
            return "\n".join(v) if k == "commands" else shlex.join(v)
    return None


def _transcript_results(body):
    """{tool_use_id: (why it failed or None)} of the tool results in a transcript line."""
    from .findings_v2 import _tailer
    if not _tailer(body) or not isinstance(body["entry"].get("message"), dict):
        return {}
    out = {}
    for b in body["entry"]["message"].get("content") or ():
        if isinstance(b, dict) and b.get("type") == "tool_result" and isinstance(b.get("tool_use_id"), str):
            out[b["tool_use_id"]] = "the transcript marks it an error" if b.get("is_error") is True else \
                result_failure(b.get("content"))
    return out


class _Pass:
    """The facts these checks need, from one read of the run's records and their content, one record at a time."""

    def __init__(self, run):
        from . import findings_v2 as v2
        self.v2, self.run = v2, run
        gateway = {r["event"]["data"].get("exchange_id") for r in run.records if r["event"]["type"] ==
                   "model.exchange" and r["event"]["source"] == "gateway"}
        self.calls, self.results, self.msgs, self.got, self.seen = [], {}, [], set(), set()
        self.transcript = {}   # tool_use_id -> (run_seq of the transcript line with its result, why it failed)
        for tcid, c in run.ran.items():
            d = c["decision"]["event"]
            cs = run.carrier(tcid)
            call = {"tcid": tcid, "tool": d["data"]["tool"], "dseq": d["run_seq"], "fams": None, "writes": [],
                    "deletes": [], "pushes": [], "cmd": "", "rseq": None, "ok": None, "why": None,
                    "x": run.by_seq[cs]["event"]["data"].get("exchange_id") if cs is not None else None}
            if "result" in c:
                call.update(rseq=c["result"]["event"]["run_seq"], ok=c["result"]["event"]["data"].get("ok"))
                self.results[call["rseq"]] = call
            self.calls.append(call)
        self.calls.sort(key=lambda c: c["dseq"])
        self.dseqs = [c["dseq"] for c in self.calls]
        self.decisions = {c["dseq"]: c for c in self.calls}
        self.want = [r for r in run.records if r["event"]["run_seq"] in self.decisions or r["event"]["run_seq"] in
                     self.results or r["event"]["type"] == "model.exchange" and (
                         r["event"]["source"] == "gateway" or r["event"]["data"].get("exchange_id") not in gateway)
                     and (r["event"]["data"].get("phase") == "response" or r["event"]["source"] != "gateway")]

    def feed(self, r, body):
        e, d = r["event"], r["event"]["data"]
        seq = e["run_seq"]
        self.got.add(seq)
        if seq in self.decisions:
            call, cmd = self.decisions[seq], _shell(body)
            if isinstance(body, dict) and call["tool"] in WRITE_TOOLS:
                path = body.get("file_path") or body.get("notebook_path") or body.get("path")
                call.update(fams={"write"}, writes=[path] if isinstance(path, str) else [])
            elif cmd is not None:
                fams, writes, deletes, pushes = command_facts(cmd)
                call.update(fams=fams | ({"write"} if writes else set()), writes=writes, deletes=deletes,
                            pushes=pushes, cmd=_snip(cmd))
            else:
                call["fams"] = {"network"} if call["tool"].lower() in NET_TOOLS else set()
        elif seq in self.results:
            self.run.tier[seq] = "gateway" if e["source"] == "gateway" else "sdk"
            if isinstance(body, dict):
                self.results[seq]["why"] = result_failure(body)
        elif d.get("phase") != "response":
            for tcid, why in _transcript_results(body).items():
                self.transcript.setdefault(tcid, (seq, why))
        else:
            segs = self.v2.parsers.said(*self.v2._message(body, d))
            text = "\n".join(s["text"] for s in segs if s["kind"] == "text" and s["text"].strip())[:MAX_TEXT]
            said = "\n".join(s["text"] for s in segs if s["text"].strip())[:MAX_TEXT]
            if not said:
                return
            # the same words reported twice between the same two calls (by two adapters) are one message
            key = (hashlib.sha256(" ".join(text.split()).encode("utf-8", "surrogatepass")).digest(),
                   bisect.bisect_left(self.dseqs, seq))
            if text and key in self.seen:
                text = ""
            self.seen.add(key)
            forged = self.run.conflicting(d.get("exchange_id")) and e["source"] != "gateway"
            self.msgs.append({"seq": seq, "x": d.get("exchange_id"), "forged": forged,
                              "said": read_message(text) if text else None,
                              "mentions": set() if forged else mentions(said)})   # forged text clears nothing


def check(run, content, out, cov, deadline, clock):
    """TK-X205 and the ported v1 text checks over `run` (findings_v2._Run, read once by findings_v2), with `content`
    as findings_v2.analyze takes it: findings into `out`, counts into `cov`, as findings_v2's own checks put theirs.
    lean: a second vault read of the model messages findings_v2 read; share its pass if reads cost."""
    p, stop = _Pass(run), None   # stop: the first run_seq the time budget left unread
    for seq, body, _ in content(p.want) if content else ():
        if clock() > deadline:
            stop = seq
            break
        p.feed(run.by_seq[seq], body)
    shown, v2 = out["shown"], p.v2
    unread = sorted(r["event"]["run_seq"] for r in p.want if r["event"]["type"] == "model.exchange" and
                    r["event"]["data"].get("phase") == "response" and r["event"]["run_seq"] not in p.got)
    # indexes, so each message and call is checked in log time: per family, the calls that did it, in order
    fam_calls = {}
    for c in p.calls:
        for f in c["fams"] or ():
            fam_calls.setdefault(f, []).append(c)
    fam_seqs = {f: [c["dseq"] for c in cs] for f, cs in fam_calls.items()}
    in_message = {}   # exchange id -> the families of the calls that model message asked for
    for c in p.calls:
        if c["x"] is not None:
            in_message.setdefault(c["x"], set()).update(c["fams"] or ())
    first_unknown = min((c["dseq"] for c in p.calls if c["fams"] is None), default=None)
    msg_seqs = [m["seq"] for m in p.msgs]
    told_after = [set() for _ in range(len(p.msgs) + 1)]   # what the messages from i on mention
    for i in range(len(p.msgs) - 1, -1, -1):
        told_after[i] = told_after[i + 1] | p.msgs[i]["mentions"]
    told_in = {}
    for m in p.msgs:
        if m["x"] is not None:
            told_in.setdefault(m["x"], set()).update(m["mentions"])

    def note(rule, status, seqs=(), what=None, labels=(), call=None):
        c = cov[rule]
        if status in REASONS or status in v2.REASONS:
            c["not_checkable"][status] = c["not_checkable"].get(status, 0) + 1
        else:
            c["checked"] += 1
            c["tier"].update(v2._tiers(run, seqs))
        if status == "found":
            c["found"] += 1
            out["findings"].append(v2._finding(run, rule, list(seqs), severity=SEVERITIES[rule]))
            shown["details"].append({"what": what, "tiers": v2._tiers(run, seqs), "labels": list(labels)})
        if call is not None:
            shown["calls"][call["tcid"]]["checks"][rule] = status

    def last(fam, seq):
        k = bisect.bisect_left(fam_seqs.get(fam, ()), seq)
        return fam_calls[fam][k - 1] if k else None

    def failed(call):
        """(why the call failed or None, the records that show it), or None when it has no result."""
        t = p.transcript.get(call["tcid"])
        if call["rseq"] is None and t is None:
            return None
        if call["ok"] is False:
            return "it returned an error (ok: false)", [call["rseq"]]
        if call["why"]:
            return f"its output reads “{_snip(call['why'])}”", [call["rseq"]]
        if t and t[1]:
            return f"its output in the transcript reads “{_snip(t[1])}”", [s for s in (call["rseq"], t[0]) if s]
        return None, [s for s in (call["rseq"],) if s is not None]

    def late(seq):
        return stop is not None and seq >= stop

    for seq in unread:
        for rule in MESSAGE_CHECKS:
            note(rule, "budget" if late(seq) else "no_content")
    for m in p.msgs:
        said, seq = m["said"], m["seq"]
        if said is None:
            continue
        if clock() > deadline:   # past the budget: counted, not checked
            for rule in MESSAGE_CHECKS:
                note(rule, "budget")
            continue
        unknown = first_unknown is not None and first_unknown < seq   # a command before it could not be read
        claims, quote, labels = said["claims"], said["quote"], ["forged"] if m["forged"] else []
        # TK-X205: the last call related to a success claim, before it, failed
        found, missing = None, False
        for cat in sorted(claims & set(FAMILIES)):
            for fam in FAMILIES[cat]:
                c = last(fam, seq)
                got = c and failed(c)
                missing = missing or bool(c) and got is None
                if got and got[0] and not found:
                    found = (c, got, cat)
        if found:
            c, (why, rseqs), cat = found
            note("TK-X205", "found", [c["dseq"], *rseqs, seq],
                 f"the model said “{_snip(quote[cat])}” (record {seq}) after {c['tool']} "
                 + (f"`{c['cmd']}` " if c["cmd"] else "") + f"failed: {why} (record {c['dseq']})", labels, c)
        else:
            note("TK-X205", "no_result" if missing else "no_content" if claims & set(FAMILIES) and unknown
                 else "checked", [seq])
        # TK-X101..X104: a claimed action no command carried out, before the claim or asked for in its message
        for rule, cat in CLAIMED.items():
            said_it = next((c for c in (("tests_run", "tests") if cat == "tests" else (cat,)) if c in claims), None)
            fam = "test" if cat == "tests" else cat
            if said_it is None or last(fam, seq) or fam in in_message.get(m["x"], ()):
                note(rule, "checked", [seq])
            elif unknown:
                note(rule, "no_content")
            else:
                note(rule, "found", [seq], f"the model said “{_snip(quote[said_it])}” (record {seq}), and no "
                     f"{'test' if fam == 'test' else fam} command ran before it", labels)
        # TK-X111..X114: a denial of what the run did before it
        for rule in DENIED:
            obj = said["denials"].get(rule)
            hits = []
            for c in fam_calls.get({"TK-X111": "push", "TK-X112": "delete", "TK-X113": "write",
                                    "TK-X114": "network"}[rule], ()) if obj else ():
                if c["dseq"] >= seq:
                    break
                targets = {"TK-X111": c["pushes"], "TK-X112": c["deletes"], "TK-X113": c["writes"],
                           "TK-X114": []}[rule]
                if obj[0] == "any" or rule == "TK-X114" or obj[0] == "else" and rule == "TK-X111" \
                        or _hit(obj, targets, said["files"]):   # "didn't push to main": a push to main
                    hits.append(c)
                    if len(hits) == 5:
                        break
            if hits:
                c = hits[0]
                note(rule, "found", [seq, *(h["dseq"] for h in hits)],
                     f"the model said “{_snip(quote[rule])}” (record {seq}), after {c['tool']} "
                     + (f"`{c['cmd']}`" if c["cmd"] else ", ".join(map(str, c["writes"][:3])))
                     + f" (record {c['dseq']})", labels, c)
            else:
                note(rule, "no_content" if obj and unknown else "checked", [seq])
    # TK-X120: a risky action that ran, and nothing the model said with it or after it mentions
    for c in p.calls:
        if clock() > deadline or late(c["dseq"]):
            note("TK-X120", "budget")
            continue
        if c["fams"] is None:
            note("TK-X120", "no_content")
            continue
        risky = [label for label in MENTIONS if label in c["fams"]]
        if not risky:
            note("TK-X120", "checked", [c["dseq"]])
            continue
        got = failed(c)
        k = bisect.bisect_right(msg_seqs, c["dseq"])
        if got and got[0] or set(risky) & (told_after[k] | told_in.get(c["x"], set())):
            note("TK-X120", "checked", [c["dseq"]], call=c)   # it failed, or the model mentioned it
        elif unread and unread[-1] > c["dseq"]:
            note("TK-X120", "budget" if late(unread[-1]) else "no_content", call=c)
        elif k == len(p.msgs):
            note("TK-X120", "no_account", call=c)
        else:
            note("TK-X120", "found", [c["dseq"], p.msgs[-1]["seq"]],
                 f"{c['tool']} `{c['cmd']}` ({risky[0]}) ran (record {c['dseq']}), and nothing the model said with "
                 "it or after it mentions it", call=c)
