"""Fail-closed classes (docs/policy-v2.md#fail-closed-classes): with no signer answering, a hook whose fail mode lets a
call run still blocks one of four consequential classes: reading a secret, a deploy or publish, moving money, and a
push to main (or to a branch the line can't tell, of tags or of every branch, as TK-A056 reads one).

`decide(tool, args, policy, typed)` checks a call by class first, in code that reads what the call names (`classify`:
no pack says which calls these are, so a pack edited to allow everything leaves them blocked), then by the policy the
hook can read, as the signer reads a call (service.evaluate: a typed line, text written into a process, a file tool's
spelling, an MCP tool's mapping): the operator's (`policy`), else the shipped dev pack; a call that policy holds or
denies is blocked too, and one it fails on. A policy that can't be read or compiled adds nothing, and nothing here
ever allows a call the class check blocks. Text typed into a terminal (`typed`) runs only where it ends its line: a
fragment a later call could finish into a command of a class is blocked. The fail mode itself stays the signer's
(register_run's fail_modes) and the operator's (the system config): an argument of the call never chooses it. The
hook's answer is never a signed decision (integrations/claude_code.py, `HOOK_DECIDED`).
"""
import fnmatch
import functools
import os
import re

from . import compile as policy_compile, engine as engine_mod, grammar, shell
from .engine import Engine

CLASSES = ("secrets", "deploys", "payments", "pushes to main")
DEV_PACK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "packs", "dev.yaml")
# arguments a tool runs as a shell command (engine._COMMAND_KEYS, and the AWS API MCP server's cli_command), those
# that name a file, and the globs a search tool reads files by (Grep's glob; Glob's pattern: classify)
_COMMAND_KEYS = {*engine_mod._COMMAND_KEYS, "cli_command", "clicommand"}
_PATH_KEYS = {"file_path", "path", "notebook_path", "paths", "filename", "file", "uri", "target"}
_GLOB_KEYS = {"glob", "file_glob"}
# a file that holds a credential (a .env, not its .example, .sample, .template or .dist; cloud, SSH, package registry,
# Docker and Kubernetes credentials; a private key or certificate bundle)
_SECRET_FILE = re.compile(
    r"(?i)(?:^|[/\\])(?:\.env(?:\.(?!(?:example|sample|template|dist)$)[^/\\]+)?|\.aws[/\\](?:credentials|config)|"
    r"\.ssh[/\\]id_[^/\\]*(?<!\.pub)|[._]netrc|\.npmrc|\.pypirc|\.git-credentials|\.docker[/\\]config\.json|"
    r"\.kube[/\\]config|credentials\.json|[^/\\]+\.(?:pem|key|p12|pfx|keystore|jks))$")
# files of those kinds a glob that names one matches (`.env*`, `**/.aws/*`)
_SECRET_SAMPLES = ("/r/.env", "/r/.env.local", "/r/.env.production", "/h/.aws/credentials", "/h/.ssh/id_rsa",
                   "/h/.ssh/id_ed25519", "/h/.netrc", "/h/.npmrc", "/h/.pypirc", "/h/.git-credentials",
                   "/h/.docker/config.json", "/h/.kube/config", "/r/credentials.json", "/r/server.key", "/r/cert.pem")
_SECRET_NAME = re.compile(r"(?i)secret|credential|passw(?:or)?d|api[_-]?key|private[_-]?key|keychain|keyvault")
_MONEY_NAME = re.compile(r"(?i)refund|payout|transfer|charge|capture|payment|pay[_-]?invoice|send[_-]?money|withdraw")
_MONEY_HOST = re.compile(r"(?i)(?:^|[/@.\s\"'=])(?:api\.stripe\.com|api(?:-m)?\.paypal\.com|connect\.squareup\.com)\b")
# a command of these programs is in the class when one of its words is one of these words, or each word of a tuple is
# one
_WORDS = {
    "secrets": {"aws": ("secretsmanager", "get-parameter", "get-parameters", "get-parameters-by-path",
                        ("configure", "export-credentials")),
                "gcloud": ("secrets", ("auth", "print-access-token"), ("auth", "print-identity-token")),
                "az": ("keyvault",), "op": ("read", "inject", "item", "document"),
                "bw": ("get", "export"), "vault": ("read", "kv", "unwrap"), "bao": ("read", "kv", "unwrap"),
                "doppler": ("secrets", "run"), "infisical": ("secrets", "export", "run"), "lpass": ("show", "export"),
                "pass": ("show",), "gopass": ("show", "cat"), "keepassxc-cli": ("show", "export"),
                "security": ("find-generic-password", "find-internet-password", "dump-keychain", "export"),
                "kubectl": ("secret", "secrets", ("config", "view", "--raw")), "gh": (("auth", "token"),),
                "git": (("credential", "fill"),)},
    "deploys": {"npm": ("publish", "pu", "pub", "publ", "publi", "publis"), "pnpm": ("publish",), "yarn": ("publish",),
                "bun": ("publish",), "docker": ("push", "--push"), "podman": ("push", "--push"),
                "nerdctl": ("push", "--push"), "buildah": ("push",), "docker-compose": ("push",),
                "podman-compose": ("push",), "crane": ("push", "copy", "cp", "append", "mutate", "tag", "rebase",
                                                       "flatten"),
                "oras": ("push", "cp", "copy", "attach", "tag"), "goreleaser": ("release",),
                "helm": ("install", "upgrade", "push"),
                "terraform": ("apply", "destroy", "import"), "tofu": ("apply", "destroy", "import"),
                "terragrunt": ("apply", "destroy", "run-all"), "pulumi": ("up", "destroy"),
                "kubectl": ("apply", "delete", "create", "replace", "patch", "rollout", "scale", "set", "edit"),
                "gcloud": ("deploy", "update-traffic", "set-traffic", "migrate"),
                "gh": (("release", "create"), ("release", "new"), ("release", "edit"), ("workflow", "run")),
                "aws": ("deploy", "create-stack", "update-stack", "delete-stack", "update-function-code"),
                "firebase": ("deploy",), "vercel": ("deploy", "promote", "--prod"), "netlify": ("deploy",),
                "fly": ("deploy",), "flyctl": ("deploy",), "wrangler": ("deploy", "publish"), "railway": ("up",),
                "serverless": ("deploy",), "sls": ("deploy",), "cdk": ("deploy", "destroy"), "sam": ("deploy",),
                "cargo": ("publish",), "twine": ("upload",), "gem": ("push",), "uv": ("publish",),
                "poetry": ("publish",)},
    "payments": {"stripe": ("create", "capture", "confirm", "pay", "post")},
    "pushes to main": {"gh": (("pr", "merge"),), "git": (("subtree", "push"),)},
}


def classify(tool, args):
    """The class a call is in (CLASSES), "unreadable" for a shell command the parser can't read, or None: by the
    tool's name, the files, globs and hosts its arguments name (a `file://` URI as its path) and each command an
    argument runs, a line typed into a terminal (`typed_line`) and text written into a process (process_manage's
    `data`) among them. A command of a CLI listed here whose subcommand the line can't tell (an expansion it doesn't
    resolve: `git $X origin main`) is in that CLI's class."""
    name = tool if isinstance(tool, str) else ""
    if _SECRET_NAME.search(name):
        return "secrets"
    if _MONEY_NAME.search(name):
        return "payments"
    commands = {*_COMMAND_KEYS, "typed_line"} | ({"data"} if name == "process_manage" else set())
    globs = _GLOB_KEYS | ({"pattern"} if name == "Glob" else set())
    for key, value in _items(args):
        if not isinstance(value, str):
            continue
        path = value.strip()   # (a file:// URI ends in its path: the file name follows a /)
        if key in _PATH_KEYS and _SECRET_FILE.search(path) or key in globs and any(
                fnmatch.fnmatch(f, g) for f in _SECRET_SAMPLES for g in (path, "*/" + path)):
            return "secrets"
        if _MONEY_HOST.search(value):
            return "payments"
        if key in commands and (found := _command(value)):
            return found
    return None


def decide(tool, args, policy=None, typed=None):
    """(blocked, why) of a call with no signer answering, where its fail mode lets it run: its class (classify); text
    typed into a terminal (`typed`: the call's own) that leaves a line unfinished; the decision of `policy` (a path;
    unreadable, or a policy that doesn't compile: the dev pack's) as the signer reads the call, which holds, denies or
    fails; else (False, None): routine work runs. `why` names the class, the fragment or the rules."""
    from tracekit.signer import service   # (only with no signer answering: loaded here)
    found = classify(tool, args)
    if found:
        return True, ("a command the hook can't read" if found == "unreadable" else found)
    if typed is not None and not _typed_runs(typed):
        return True, "typed text a later call could finish into a command"
    for path in dict.fromkeys(p for p in (policy, DEV_PACK) if p):
        try:
            eng = _engine(path)
        except Exception:   # unreadable (an operator's root-only policy) or not compiled: the next one, then the
            continue        # class check alone
        try:
            d = service.evaluate(eng, tool, args if isinstance(args, dict) else {"value": args})[0]
        except Exception:   # (evaluate's own engine error is a deny; anything past it is no reason to run the call)
            return True, "the policy failed on this call"
        if d["verdict"] in ("deny", "ask"):
            return True, " ".join(d["rule_ids"])
        return False, None
    return False, None


def _typed_runs(text):
    """Whether typed text may run while no signer answers: keys alone with a ^C, which drops the line, or text whose
    last character ends its line, so no fragment is left for a later call to finish."""
    from tracekit.agent_hooks import KEYS, LINE_END
    return bool(text) and (bool(LINE_END.fullmatch(text[-1])) or "\x03" in text and KEYS.fullmatch(text) is not None)


@functools.lru_cache(maxsize=4)
def _engine(path):
    pol, errors = policy_compile.build(path)
    if errors:
        raise ValueError("; ".join(errors))
    return Engine(pol)


def _items(value, key=""):
    """(key, value) for every value in the arguments at any depth, a list's under its key; keys lower-cased."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _items(v, str(k).lower())
    elif isinstance(value, list):
        for v in value:
            yield from _items(v, key)
    else:
        yield key, value


def _command(text):
    """The class of a shell command line (classify), or None."""
    try:
        cmds = shell.parse(text)
    except shell.ParseError:
        return "unreadable"
    if any(c["opaque"] for c in cmds):
        return "unreadable"
    # a listed CLI whose subcommand the line can't tell (`git $X origin main`, or a word a runner fills in there:
    # `echo push | xargs -I{} git {} origin main`, engine._filled): its class
    for c, runner, replaced in engine_mod._run_by(cmds):
        program = engine_mod._program(c["argv"])
        word = grammar.subcommand(engine_mod._filled(c["argv"], runner, replaced), program,
                                  engine_mod._VALUED_OPTIONS.get(program, frozenset())) if any(
            program in p for p in _WORDS.values()) else None
        if word is not None and re.search(r"[$`]", word):
            return next(cls for cls in reversed(CLASSES) if program in _WORDS[cls])
    for s in engine_mod._pushes(cmds):   # (a subcommand the line can't tell: its CLI's class, as above)
        program = engine_mod._program(s.split(" ", 2)[1:2]) if s.startswith("PUSH:verb ") else None
        if s.startswith(("PUSH:release ", "PUSH:image ")):
            return "deploys"
        if s.startswith("PUSH:"):
            return next((cls for cls in reversed(CLASSES) if program in _WORDS[cls]), "pushes to main")
    for c in cmds:
        argv = c["argv"]
        if any(_SECRET_FILE.search(w) for w in argv[1:]) or any(_MONEY_HOST.search(w) for w in argv[1:]):
            return "secrets" if any(_SECRET_FILE.search(w) for w in argv[1:]) else "payments"
        words = set(argv[1:])
        for cls, programs in _WORDS.items():
            for want in programs.get(engine_mod._program(argv), ()):
                if (set(want) <= words) if isinstance(want, tuple) else want in words:
                    return cls
    return None
