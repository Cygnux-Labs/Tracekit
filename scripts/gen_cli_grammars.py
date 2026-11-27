#!/usr/bin/env python3
"""Generate tracekit/policy2/grammars/<program>.json, each from its CLI's own definition (tracekit/policy2/grammar.py
says what a table holds; docs/policy-v2.md#cli-grammars what a rule reads of it).

    python scripts/gen_cli_grammars.py fetch DIR   # once: each source at its pinned release, with `gh api`
    python scripts/gen_cli_grammars.py build DIR   # the tables, from DIR alone: no network, nothing of it run

A table records the release and commit it came from. What a source can't say (a flag a helper defines that the
extractor doesn't follow, a command a plugin adds) is left out of the table, so the reader finds the argv doesn't fit
and the rule reads it as text: a table may know too little, never a flag's kind wrong. A flag whose kind the source
doesn't settle is "x" (the reader refuses it), and one that may or may not take a value is read as taking one.
"""
import ast
import fnmatch
import glob
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "tracekit", "policy2", "grammars")
# program: (repo, release ref, the commit that ref named when the table was made, the one file to fetch, or None for
# the release's tarball). A ref that names another commit now (a moved tag) is refused, by fetch and by build
SOURCES = {
    "aws": ("aws/aws-cli", "2.41.0", "7e6f97cb7b149863b5133857b2095bca3f3cab47", None),
    "curl": ("curl/curl", "curl-8_23_0", "3163ec065643ba20709f190111f42c3e1fe95273", None),
    "docker": ("docker/cli", "v29.10.0", "fdd4b8e5da335e1d0d83d29af5045f57280cd694", None),
    "gcloud": ("google-cloud-sdk-unofficial/google-cloud-sdk", "v593.0.0", "d0b85d7e59d1ad5c6db843368328b56994f36f61",
               "data/cli/gcloud_completions.py"),
    "gh": ("cli/cli", "v2.105.0", "e1219499a578b69e3437adaa31cd60614e23c802", None),
    "git": ("git/git", "v2.56.1", "03b41523c576f26ad34085378717a0c1b287470f", None),
    "kubectl": ("kubernetes/kubectl", "v0.37.2", "b6fd7151e781c4619468e46cfefb5f4728cce747", None),
    # kubectl's global flags
    "cli-runtime": ("kubernetes/cli-runtime", "v0.37.2", "74089fa11904fd48208d1cf8678e76dfbb994f39", None),
    "npm": ("npm/cli", "v11.21.2", "1c66798c9def37e12509ccebb5b08cddf247c2e8", None),
    "pip": ("pypa/pip", "26.3", "191854fba83d1c69534f974564af85632372d995", None),
    "terraform": ("hashicorp/terraform", "v1.17.2", "ae094fc0ee6d4f3d2a990b40ac48a6d2dbaeb53e", None),
    # terraform's command runner (its help words)
    "hashicorp-cli": ("hashicorp/cli", "v1.1.7", "89d8cb579d5743d787fe3500594c9cf56abaefb5", None),
}


def fetch(base, only=()):
    """Each source at its pinned commit (the commit itself, not the ref, so a moved tag fetches nothing else)."""
    for name, (repo, ref, pinned, path) in SOURCES.items():
        if only and name not in only:
            continue
        sha = subprocess.run(["gh", "api", f"repos/{repo}/commits/{ref}", "--jq", ".sha"], capture_output=True,
                             text=True, check=True).stdout.strip()
        if sha != pinned:
            raise SystemExit(f"{repo} {ref} is commit {sha} now, not the pinned {pinned}: check the release, then pin it")
        os.makedirs(os.path.join(base, name), exist_ok=True)
        if path:
            with open(os.path.join(base, name, os.path.basename(path)), "wb") as f:
                subprocess.run(["gh", "api", "-H", "Accept: application/vnd.github.raw",
                                f"repos/{repo}/contents/{path}?ref={pinned}"], stdout=f, check=True)
        else:
            tar = os.path.join(base, name + ".tar.gz")
            with open(tar, "wb") as f:
                subprocess.run(["gh", "api", f"repos/{repo}/tarball/{pinned}"], stdout=f, check=True)
            subprocess.run(["tar", "-xzf", tar, "-C", os.path.join(base, name), "--strip-components", "1"],
                           check=True)
        with open(os.path.join(base, name + ".sha"), "w") as f:
            f.write(f"{repo} {ref} {sha}\n")
        print("fetched", name, sha)


def source(base, name):
    """The release a source dir holds, refused unless it is the pinned one (SOURCES)."""
    repo, ref, sha = open(os.path.join(base, name + ".sha")).read().split()
    if (repo, ref, sha) != SOURCES[name][:3]:
        raise SystemExit(f"{base}/{name} holds {repo} {ref} {sha}, not the pinned {' '.join(SOURCES[name][:3])}")
    return {"repo": repo, "ref": ref, "commit": sha}


def _plain(path, root):
    """Whether `path` is reached through no symlink below `root`: its real path is root's real path and the rest, each
    side resolved the same way (a symlinked root such as macOS's /tmp is no link in the tree)."""
    return os.path.realpath(path) == os.path.join(os.path.realpath(root), os.path.relpath(path, root))


def text(path):
    """A source file's text; one that is a symlink (an archive's link out of its tree) is refused."""
    if not _plain(path, os.path.dirname(os.path.abspath(path))):
        raise ValueError(f"{path}: a symlink; sources are read only as plain files")
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def sources(pattern):
    """The plain files a glob names, symlinks (and files under one, below the glob's fixed part) left out."""
    root = os.path.dirname(re.split(r"[*?[]", pattern, maxsplit=1)[0])
    return [f for f in glob.glob(pattern, recursive=True) if _plain(f, root)]


def write(program, style, sources, commands, **extra):
    """One command a line, sorted, so a regenerated table diffs by command."""
    head = {"program": program, "style": style, "source": sources, **extra}
    body = ",\n".join(f"  {json.dumps(k)}: {json.dumps(v, sort_keys=True, separators=(',', ':'))}"
                      for k, v in sorted(commands.items()))
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, program + ".json"), "w", encoding="utf-8") as f:
        f.write(json.dumps(head, sort_keys=True)[:-1] + ', "commands": {\n' + body + "\n}}\n")
    print(program, len(commands), "commands")


# The commands of the two large tables that a shipped pack reads by grammar, each with the groups above it and the
# commands under it: those TK-A035's unless_cli entries name and the text `unless` they narrow names (aws secretsmanager
# get-secret-value and batch-get-secret-value; gcloud secrets versions access) and those dev's TK-A056 names (gcloud
# run deploy, run services update and app deploy), on each gcloud track. No other aws or gcloud command fits, so a rule reads it as text,
# as a CLI with no grammar: whole, the tables are 4.3 and 3.9 MB. A rule that reads another of their commands by
# grammar adds it here (tests/test_policy_grammar.py checks each entry names a command its table keeps).
ONLY = {"aws": ("secretsmanager get-secret-value", "secretsmanager batch-get-secret-value"),
        "gcloud": tuple(track + path for track in ("", "alpha ", "beta ")
                        for path in ("secrets versions access", "run deploy", "run services update", "app deploy"))}


def only(program, commands):
    """`commands` with only the root, the ONLY commands of `program` (and the aliases naming them), the groups above
    them and the commands under them; every node as the whole table has it. -> the kept commands (the table's `only`)."""
    kept = [p for p in ONLY[program] if p in commands]
    keep = {""} | {" ".join(p.split()[:k]) for p in kept for k in range(1, len(p.split()) + 1)}
    keep |= {c for c in commands for p in kept if c.startswith(p + " ")}
    for c in list(commands):
        target = commands[c] if isinstance(commands[c], str) else c
        if target not in keep:
            del commands[c]
    return kept


def groups_take_no_positionals(commands):
    """A node with subcommands takes no positional of its own: a word there names a subcommand or isn't read."""
    for path in {" ".join(k.split()[:-1]) for k in commands if k}:
        if isinstance(commands.get(path), dict):
            commands[path].setdefault("a", [0, 0])


# gcloud: its static completion tree (data/cli/gcloud_completions.py), as `gcloud meta list-commands` builds it from
# calliope: each command's flags as bool, value, dynamic or a list of choices; the root's are global. calliope adds a
# hidden --no-X to each Boolean --X (parser_arguments._AddInvertedBooleanFlagIfNecessary) and refuses abbreviations
def gcloud(base):
    src = text(os.path.join(base, "gcloud", "gcloud_completions.py"))
    tree = json.loads(src[src.index("STATIC_COMPLETION_CLI_TREE =") + len("STATIC_COMPLETION_CLI_TREE ="):])   # (JSON)
    commands = {}

    def flags(given):
        out = {k: 0 if v == "bool" else 1 for k, v in given.items()}
        out.update({"--no-" + k[2:]: "!" + k for k, v in given.items()
                    if v == "bool" and not k.startswith("--no-") and "--no-" + k[2:] not in given})
        return out

    def walk(node, path):
        commands[" ".join(path)] = {"f": flags(node.get("flags", {}))}
        for name, child in node.get("commands", {}).items():
            walk(child, path + [name])
    walk(tree, [])
    commands[""] = {"p": commands[""].pop("f")}
    groups_take_no_positionals(commands)
    write("gcloud", "argparse", source(base, "gcloud"), commands, only=only("gcloud", commands))


# aws: AWS CLI v2's command table as clidriver builds it: a command per botocore service model (its latest API version)
# under the CLI's renames, an operation per model operation (xform_name), an argument per input member (a boolean as
# --X and --no-X, a list taking one or more values), the paging arguments of a paginated operation, --cli-input-json,
# --cli-input-yaml and --generate-cli-skeleton, ARGUMENT_RENAMES and HIDDEN_ALIASES; the global options of cli.json.
# The commands customizations add (s3, configure, wait, ...) aren't read
_FIRST_CAP = re.compile(r"(.)([A-Z][a-z]+)")
_END_CAP = re.compile(r"([a-z0-9])([A-Z])")


def xform_name(name, sep, special):
    """botocore.xform_name, its special cases read from its own source."""
    if sep in name:
        return name
    if (name, sep) in special[0]:
        return special[0][name, sep]
    if (m := special[1].search(name)) is not None:
        name = name[:-len(m.group())] + sep + m.group().lower()
    return _END_CAP.sub(r"\1" + sep + r"\2", _FIRST_CAP.sub(r"\1" + sep + r"\2", name)).lower()


def aws(base):
    root = os.path.join(base, "aws", "awscli")
    init = text(os.path.join(root, "botocore", "__init__.py"))
    cache = ast.literal_eval(re.search(r"_xform_cache = (\{.*?\n\})", init, re.S).group(1))
    special = re.compile(ast.literal_eval(re.search(r"_special_case_transform = re\.compile\((r?'[^']*')\)",
                                                    init).group(1)))
    assert "_first_cap_regex = re.compile('(.)([A-Z][a-z]+)')" in init   # (as _FIRST_CAP and _END_CAP here)
    assert "_end_cap_regex = re.compile('([a-z0-9])([A-Z])')" in init
    special = (cache, special)
    renames = {}
    for f in sources(os.path.join(root, "customizations", "**", "*.py")):
        for old, new in re.findall(r"rename_command\(\s*command_table,\s*'([\w-]+)',\s*'([\w-]+)'\s*\)", text(f)):
            renames[old] = new
    argrename = text(os.path.join(root, "customizations", "argrename.py"))
    arg_renames = ast.literal_eval(re.search(r"ARGUMENT_RENAMES = (\{.*?\n\})", argrename, re.S).group(1))
    hidden = ast.literal_eval(re.search(r"HIDDEN_ALIASES = (\{.*?\n\})", argrename, re.S).group(1))
    cli = json.loads(text(os.path.join(root, "data", "cli.json")))
    glob_flags = {}
    for name, opt in cli["options"].items():
        glob_flags["--" + name] = 0 if opt.get("action") in ("store_true", "store_false", "version") else 1
    commands = {"": {"p": glob_flags}}
    for svc_dir in sorted(sources(os.path.join(root, "botocore", "data", "*", ""))):
        versions = sorted(v for v in os.listdir(svc_dir) if os.path.exists(os.path.join(svc_dir, v, "service-2.json")))
        if not versions:
            continue
        svc = os.path.basename(os.path.dirname(svc_dir))
        cli_svc = renames.get(svc, svc)
        model = json.loads(text(os.path.join(svc_dir, versions[-1], "service-2.json")))
        pages = os.path.join(svc_dir, versions[-1], "paginators-1.json")
        pages = json.loads(text(pages)).get("pagination", {}) if os.path.exists(pages) else {}
        shapes = model["shapes"]
        commands[cli_svc] = {}
        for op_name, op in model["operations"].items():
            cli_op = xform_name(op_name, "-", special)
            f = {"--cli-input-json": 1, "--cli-input-yaml": 1, "--generate-cli-skeleton": "?"}
            members = shapes[op["input"]["shape"]].get("members", {}) if "input" in op else {}
            for m_name, m in members.items():
                arg = xform_name(m_name, "-", special)
                typ = shapes[m["shape"]]["type"]
                if typ == "boolean":
                    f["--" + arg], f["--no-" + arg] = 0, "!--" + arg
                else:
                    f["--" + arg] = "+" if typ == "list" else 1
            if op_name in pages:
                f.update({"--starting-token": 1, "--max-items": 1})
                if "limit_key" in pages[op_name]:
                    f["--page-size"] = 1
            for table, aliased in ((arg_renames, False), (hidden, True)):
                for key, new in table.items():
                    s, o, a = key.rsplit(".", 2)
                    if fnmatch.fnmatchcase(cli_svc, s) and fnmatch.fnmatchcase(cli_op, o) and "--" + a in f:
                        kind = f["--" + a]
                        if not aliased:
                            del f["--" + a]
                        f["--" + new] = "--" + a if aliased else kind
            # a streaming output is written to a file the command names (customizations/streamingoutputarg.py)
            out = shapes.get(op.get("output", {}).get("shape", ""), {})
            payload = out.get("members", {}).get(out.get("payload", ""), {})
            streams = bool(payload.get("streaming") or shapes.get(payload.get("shape", ""), {}).get("streaming"))
            commands[f"{cli_svc} {cli_op}"] = {"f": f, "a": [1, 1] if streams else [0, 0]}
    groups_take_no_positionals(commands)
    write("aws", "argparse", source(base, "aws"), commands, only=only("aws", commands))


# curl: tool_getparam.c's option table (aliases[]): ARG_NONE and ARG_BOOL are switches, the others take a value; an
# ARG_BOOL also reads as --no-X, its short letter as --no-X when it is documented so (ARG_NO); a string option also as
# --expand-X (getparameter). --help's value is optional and its own (tool_help), so it isn't read
def curl(base):
    src = text(os.path.join(base, "curl", "src", "tool_getparam.c"))
    table = src[src.index("static const struct LongShort aliases[] = {"):]
    table = table[:table.index("\n};")]
    flags = {}
    for name, desc, letter in re.findall(r'\{"([\w.-]+)",\s*([A-Z_|]+),\s*\'(.)\'', table):
        kinds = set(desc.split("|"))
        switch = kinds & {"ARG_NONE", "ARG_BOOL"}
        flags["--" + name] = "x" if name == "help" else 0 if switch else 1
        if "ARG_BOOL" in kinds:
            flags["--no-" + name] = "!--" + name
        if not switch:
            flags["--expand-" + name] = "--" + name
        if letter != " ":
            flags["-" + letter] = ("!--" if "ARG_NO" in kinds and "ARG_BOOL" in kinds else "--") + name
    assert len(flags) > 300 and flags["--get"] == 0 and flags["-X"] == "--request", flags.get("--get")
    write("curl", "curl", source(base, "curl"), {"": {"f": flags}})



def go_body(src, start, c_like=False):
    """The text of the block whose `{` is the first at or after `start`: strings, characters and comments skipped
    (Go's raw strings; C's /* */ comments with `c_like`)."""
    i = src.index("{", start)
    depth, k = 0, i
    quotes = "\"'" if c_like else "\"'`"
    while k < len(src):
        c = src[k]
        if c in quotes:
            m = re.compile(r'(?:\\.|[^\\%s\n])*%s' % (c, c)).match(src, k + 1) if c != "`" else None
            k = (src.index("`", k + 1) if c == "`" else m.end() - 1 if m else k) + 1
            continue
        if src.startswith("//", k):
            k = src.index("\n", k)
            continue
        if c_like and src.startswith("/*", k):
            k = src.index("*/", k) + 2
            continue
        depth += c == "{"
        depth -= c == "}"
        if depth == 0:
            return src[i:k + 1]
        k += 1
    raise ValueError("unclosed block")


# Go's flag package, by the call that defines a flag: XxxVar(&v, "name", ...) and Var(value, "name", ...) take the
# name second, Xxx("name", ...) first; a Bool is a switch, every other kind takes a value
_GO_VAR = re.compile(r'\b(\w+)\.(BoolVar|BoolFunc|StringVar|IntVar|Int64Var|UintVar|Uint64Var|Float64Var|DurationVar|'
                     r'TextVar|Var|Func)\(\s*(?:[^,()]|\([^()]*\))+,\s*"([\w.-]+)"')
_GO_NEW = re.compile(r'\b(\w+)\.(Bool|String|Int|Int64|Uint|Uint64|Float64|Duration)\(\s*"([\w.-]+)"')


def go_flags(body):
    out = {}
    for _, kind, name in _GO_VAR.findall(body) + _GO_NEW.findall(body):
        k = 0 if kind in ("Bool", "BoolVar", "BoolFunc") else 1
        out["--" + name] = k if out.get("--" + name, k) == k else "x"
    return out


# terraform: commands.go's command map (a key with spaces is a nested command), each command's Run and the
# arguments.ParseX, extendedFlagSet and Meta flag sets it reads; hashicorp/cli reads -h, -help and --help anywhere
# before `--` as help (cli.go processArgs), and Meta.process takes -no-color anywhere
def terraform(base):
    root = os.path.join(base, "terraform")
    cli_go = text(os.path.join(base, "hashicorp-cli", "cli.go"))
    assert 'if arg == "-h" || arg == "-help" || arg == "--help" {' in cli_go
    commands_go = text(os.path.join(root, "commands.go"))
    srcs = {f: text(f) for f in sources(os.path.join(root, "internal", "command", "*.go")) if not f.endswith("_test.go")}
    args_srcs = {f: text(f) for f in sources(os.path.join(root, "internal", "command", "arguments", "*.go"))
                 if not f.endswith("_test.go")}

    def func(srcs_, pattern):
        for src in srcs_.values():
            if m := re.search(pattern, src):
                return go_body(src, m.end())
        return None

    meta_sets = {name: go_flags(func(srcs, r"func \(m \*Meta\) %s\(" % name) or "")
                 for name in ("defaultFlagSet", "extendedFlagSet")}
    arg_sets = {name: go_flags(func(args_srcs, r"\nfunc %s\(" % name) or "") for name in ("defaultFlagSet",
                                                                                         "extendedFlagSet")}
    commands = {"": {"a": [0, 0]}}
    table = commands_go[commands_go.index("Commands = map[string]cli.CommandFactory{"):]
    for key, typ in re.findall(r'\n\t\t"([a-z][\w -]*)": func\(\) \(cli\.Command, error\) \{\s*return &command\.(\w+)\{',
                               table):
        run = func(srcs, r"func \(c \*%s\) Run\(" % typ)
        if run is None:
            continue
        flags, seen = {}, set()
        bodies = [run]
        while bodies:
            body = bodies.pop()
            for k, v in go_flags(body).items():
                flags[k] = v if flags.get(k, v) == v else "x"
            for name in re.findall(r"\b(?:c\.Meta\.|c\.|m\.)(defaultFlagSet|extendedFlagSet)\(", body):
                flags.update(meta_sets[name])
            for name in re.findall(r"(?<![.\w])(defaultFlagSet|extendedFlagSet)\(", body):
                flags.update(arg_sets[name])
            for name in re.findall(r"\barguments\.(Parse\w+)\(", body):
                if name not in seen and (b := func(args_srcs, r"\nfunc %s\(" % name)):
                    seen.add(name)
                    bodies.append(b)
        if "c.Meta.process(" in run or "c.process(" in run:
            flags["--no-color"] = 0
        flags.pop("--help", None)
        flags.pop("--h", None)
        commands[key] = {"f": flags, "i": False}
    assert {"apply", "destroy", "state rm"} <= set(commands) and commands["destroy"]["f"].get("--auto-approve") == 0
    write("terraform", "hashicorp", {**source(base, "terraform"), "runner": source(base, "hashicorp-cli")}, commands)


def go_args(src, i):
    """The arguments of the Go call whose `(` is at src[i], split at its top-level commas, and the index past `)`."""
    out, depth, start, k = [], 0, i + 1, i
    while k < len(src):
        c = src[k]
        if c in "\"'`":
            k = (src.index("`", k + 1) if c == "`" else
                 re.compile(r'(?:\\.|[^\\%s])*%s' % (c, c)).match(src, k + 1).end() - 1) + 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                out.append(src[start:k].strip())
                return [a for a in out if a], k + 1
        elif c == "," and depth == 1:
            out.append(src[start:k].strip())
            start = k + 1
        k += 1
    raise ValueError("unclosed call")


class GoTree:
    """The cobra command tree of a Go CLI, read from its source: each function's body, parameters and package; each
    file's imports; each package's string constants; each command literal (`&cobra.Command{...}`) a constructor builds,
    the commands it adds (AddCommand, AddGroup, through any function it passes the command to) and the flags it defines
    (on Flags() and PersistentFlags(), through any function it passes them to, with that function's string parameters
    bound to the call's literals)."""
    PFLAG = re.compile(r"\.(Bool|BoolP|BoolVar|BoolVarP|BoolFunc|BoolFuncP|Count|CountP|CountVar|CountVarP|"
                       r"String|StringP|StringVar|StringVarP|Var|VarP|VarPF|Func|FuncP|"
                       r"(?:Int|Int8|Int16|Int32|Int64|Uint|Uint8|Uint16|Uint32|Uint64|Float32|Float64|Duration|IP|"
                       r"IPMask|IPNet|BytesHex|BytesBase64|StringSlice|StringArray|StringToString|StringToInt|"
                       r"StringToInt64|IntSlice|Int32Slice|Int64Slice|UintSlice|Float32Slice|Float64Slice|BoolSlice|"
                       r"DurationSlice|IPSlice|Text|Time)(?:P|Var|VarP)?)\(")

    def __init__(self, roots, module_prefixes):
        self.funcs, self.consts, self.imports = {}, {}, {}
        self.prefixes = module_prefixes   # {import path prefix: source dir}
        for root in roots:
            for f in sources(os.path.join(root, "**", "*.go")):
                if f.endswith("_test.go") or "/vendor/" in f or "/testdata/" in f:
                    continue
                src, pkg = text(f), os.path.dirname(f)
                self.imports[f] = {}
                for alias, path in re.findall(r'^\s*(\w+)?\s*"([\w./-]+)"\s*$', self._import_block(src), re.M):
                    self.imports[f][alias or path.rsplit("/", 1)[-1].replace("-", "")] = path
                for m in re.finditer(r'^\t?(\w+)\s*(?:string\s*)?=\s*"([^"]*)"', self._const_blocks(src), re.M):
                    self.consts.setdefault(pkg, {})[m.group(1)] = m.group(2)
                for m in re.finditer(r"^func (?:\((\w+) \*?(\w+)\) )?(\w+)\(([^)]*)\)", src, re.M):
                    try:
                        body = go_body(src, m.end())
                    except ValueError:
                        continue
                    params = [p.strip() for p in m.group(4).split(",")]
                    names = [p.split()[0] if p.split() else "" for p in params]
                    self.funcs.setdefault((pkg, m.group(3)), []).append(
                        {"file": f, "recv": m.group(2), "params": names, "types": params, "body": body})

    @staticmethod
    def _import_block(src):
        return "\n".join(re.findall(r"import \((.*?)\)", src, re.S) + re.findall(r'^import (\w* ?"[^"]+")$', src, re.M))

    @staticmethod
    def _const_blocks(src):
        return "\n".join(re.findall(r"const \((.*?)\n\)", src, re.S) + re.findall(r"^const (\w+ (?:string )?= \"[^\"]*\")",
                                                                                     src, re.M))

    def pkg_dir(self, path):
        for prefix, d in self.prefixes.items():
            if path == prefix or path.startswith(prefix + "/"):
                return os.path.join(d, path[len(prefix):].lstrip("/"))
        return None

    def resolve(self, file, callee, body=""):
        """The functions a call names: `pkg.Name` through the file's imports, `Name` in its own package, `x.Name` a
        method Name of the type the selector before it names (o.PrintFlags.AddFlags: PrintFlags's), or of the type the
        variable x was made from in `body` (`x := o.ConfigFlags`, `x := pkg.NewMatchVersionFlags(...)`), or the one
        method of that name when only one type has it."""
        parts = callee.split(".")
        pkg = os.path.dirname(file)
        if len(parts) == 1:
            return self.funcs.get((pkg, parts[0]), [])
        if len(parts) == 2 and parts[0] in self.imports.get(file, {}):
            d = self.pkg_dir(self.imports[file][parts[0]])
            return self.funcs.get((d, parts[1]), []) if d else []
        methods = [f for (d, n), fs in self.funcs.items() if n == parts[-1] for f in fs if f["recv"]]
        types = [parts[-2][:1].upper() + parts[-2][1:]]
        if len(parts) == 2 and (m := re.search(r"\b%s\s*:?=\s*&?([\w.]+)" % re.escape(parts[0]), body)):
            made = m.group(1).rsplit(".", 1)[-1]
            types.append(made[3:] if made.startswith("New") else made)
        for typ in types:
            if got := [f for f in methods if f["recv"] == typ]:
                return got
        return methods if len({f["recv"] for f in methods}) == 1 else []

    def literal(self, arg, env, file):
        if re.fullmatch(r'"[^"\\]*"', arg):
            return arg[1:-1]
        if arg in env:
            return env[arg]
        return self.consts.get(os.path.dirname(file), {}).get(arg)

    def flags(self, fn, env, sets, depth=0):
        """[(persistent, name, shorthand, kind)] a function defines on the flag sets `sets` ({expression: persistent})
        with its parameters bound in `env`."""
        out, body, file = [], fn["body"], fn["file"]
        sets = dict(sets)
        for var, recv, which in re.findall(r"\b(\w+)\s*:?=\s*(\w+)\.(Flags|PersistentFlags)\(\)", body):
            if recv in env.get("__cmds__", ()):
                sets[var] = which == "PersistentFlags"
        for cmd in env.get("__cmds__", ()):
            sets[cmd + ".Flags()"], sets[cmd + ".PersistentFlags()"] = False, True
        for m in self.PFLAG.finditer(body):
            recv = re.search(r"([\w.]+(?:\(\))?)$", body[:m.start()])
            if recv is None or recv.group(1) not in sets:
                continue
            method, (args, end) = m.group(1), go_args(body, m.end() - 1)
            # the name is first unless the method takes a pointer or value first (...Var, ...VarP, Var, VarP, VarPF)
            first = 1 if re.search(r"Var(P|PF)?$", method) else 0
            if len(args) <= first:
                continue
            name = self.literal(args[first], env, file)
            short = self.literal(args[first + 1], env, file) if method.endswith(("P", "PF")) and \
                len(args) > first + 1 else ""
            if not name:
                continue
            kind = 0 if method.startswith(("Bool", "Count")) and "Slice" not in method else 1
            tail = body[end:end + 200]
            if method == "VarPF" and re.match(r"\s*\.NoOptDefVal\s*=\s*\"true\"", tail):
                kind = 0
            out.append((sets[recv.group(1)], name, short or "", kind))
        for name, val in re.findall(r'\.Lookup\("([\w-]+)"\)\.NoOptDefVal\s*=\s*"([^"]*)"', body):
            out.append((None, name, None, 0 if val == "true" else "?"))
        if re.search(r"\b(\w+)\.NoOptDefVal\s*=\s*\"true\"", body) and len(out) == 1 and out[0][3] == 1:
            out[0] = (*out[0][:3], 0)   # (a helper's `f := ...VarPF(...); f.NoOptDefVal = "true"`)
        if depth < 4:
            for m in re.finditer(r"(?<![\w.])([\w.]+)\(", body):
                callee = m.group(1)
                if callee.split(".")[-1] in ("Flags", "PersistentFlags", "AddCommand", "Lookup") or \
                        callee.startswith(("fmt.", "strings.", "errors.")):
                    continue
                try:
                    args, _ = go_args(body, m.end() - 1)
                except (ValueError, AttributeError):
                    continue
                passed = {k: a for k, a in enumerate(args) if a in sets or a in env.get("__cmds__", ())}
                if not passed:
                    continue
                for target in self.resolve(file, callee, body):
                    sub_env, sub_sets = {"__cmds__": ()}, {}
                    for k, a in enumerate(args):
                        if k >= len(target["params"]):
                            break
                        p, t = target["params"][k], target["types"][k]
                        if a in sets:
                            sub_sets[p] = sets[a]
                        elif a in env.get("__cmds__", ()) and "cobra.Command" in t:
                            sub_env["__cmds__"] += (p,)
                        elif (v := self.literal(a, env, file)) is not None:
                            sub_env[p] = v
                    out += self.flags(target, sub_env, sub_sets, depth + 1)
        return out

    def commands(self, fn, depth=0):
        """[(command literal text, the command's variable)] a constructor builds."""
        body = fn["body"]
        m = re.search(r"(\w+)\s*:?=\s*&cobra\.Command\{", body) or re.search(r"return &cobra\.Command\{", body)
        if m is None:
            return None
        return go_body(body, m.end() - 1), (m.group(1) if m.re.pattern.startswith("(") else None)

    def children(self, fn, cmd, depth=0):
        """The constructors the command `cmd` of `fn` adds as subcommands, directly or through a function it passes the
        command to (docker's commands.AddCommands)."""
        out, body, file = [], fn["body"], fn["file"]
        local = {v: c for v, c in re.findall(r"\b(\w+)\s*:?=\s*([\w.]+)\(", body)}
        for m in re.finditer(r"\b%s\.AddCommand\(|cmdutil\.AddGroup\(\s*%s\s*," % (cmd, cmd), body):
            args, _ = go_args(body, m.end() - 1 if m.group(0).endswith("(") else body.index("(", m.start()))
            for a in args:
                call = re.match(r"([\w.]+)\(", a)
                callee = call.group(1) if call else local.get(a)
                if callee:
                    out += [(t, callee) for t in self.resolve(file, callee, body)]
        for m in re.finditer(r"templates\.CommandGroups\{", body):   # kubectl's groups, added by groups.Add(cmd)
            block = go_body(body, m.end() - 1)
            callees = re.findall(r"(?<![\w.])([\w.]+)\(", block) + [local[v] for v in re.findall(r"\b(\w+)\s*,", block)
                                                                     if v in local]
            for callee in callees:
                out += [(t, callee) for t in self.resolve(file, callee, body) if "&cobra.Command{" in t["body"]]
        if depth < 2:
            for m in re.finditer(r"(?<![\w.])([\w.]+)\(([^()]*\b%s\b[^()]*)\)" % cmd, body):
                if m.group(1).endswith("AddCommand"):
                    continue
                for target in self.resolve(file, m.group(1), body):
                    args = [a.strip() for a in m.group(2).split(",")]
                    if cmd in args and args.index(cmd) < len(target["params"]):
                        out += self.children(target, target["params"][args.index(cmd)], depth + 1)
        return out


_COBRA_ARGS = [(r"cobra\.NoArgs|cli\.NoArgs|cmdutil\.NoArgsQuoteReminder", lambda: [0, 0]),
               (r"(?:cobra|cli|cmdutil)\.ExactArgs\((\d+)\b", lambda n: [int(n), int(n)]),
               (r"cobra\.MinimumNArgs\((\d+)\)|cli\.RequiresMinArgs\((\d+)\)|cmdutil\.MinimumArgs\((\d+)\b",
                lambda *n: [int(next(x for x in n if x)), None]),
               (r"cobra\.MaximumNArgs\((\d+)\)|cli\.RequiresMaxArgs\((\d+)\)", lambda *n: [0, int(next(x for x in n if x))]),
               (r"cobra\.RangeArgs\((\d+),\s*(\d+)\)|cli\.RequiresRangeArgs\((\d+),\s*(\d+)\)",
                lambda *n: [int(x) for x in n if x]),
               (r"cobra\.ArbitraryArgs", lambda: [0, None])]


def cobra_tree(tree, root_fn, program, extra_root_flags=(), root_children=()):
    """{path: node} of the command tree under the constructor `root_fn`: its Use's first word names it, Aliases its
    other names; Args gives its arity (cobra's, docker's and gh's validators; another: any); `DisableFlagParsing: true`
    `r`, SetInterspersed(false) `i`: False. cobra adds --help (-h unless the command takes -h) to every command that
    hasn't one, and --version (-v likewise) to the root when it has a Version."""
    commands = {}

    def kinds(flags):
        f, p = {}, {}
        for persistent, name, short, kind in flags:
            if persistent is None:   # (a Lookup(...).NoOptDefVal: the flag's kind, wherever it is defined)
                for d in (f, p):
                    if "--" + name in d:
                        d["--" + name] = kind
                continue
            d = p if persistent else f
            d["--" + name] = kind if d.get("--" + name, kind) == kind else "x"
            if short:
                d["-" + short] = "--" + name
        return f, p

    def walk(fn, path, inherited, stack=()):
        lit = tree.commands(fn)
        if lit is None or id(fn) in stack:
            return
        text_, var = lit
        use = re.search(r'\bUse:\s*(?:fmt\.Sprintf\()?"([^"\s%]+)', text_)
        if use is None:
            return
        name = use.group(1)
        if path is not None:
            path = path + [name]
        else:
            path = []
        key = " ".join(path)
        flags = tree.flags(fn, {"__cmds__": (var,)} if var else {"__cmds__": ()}, {}) if var else []
        f, p = kinds(flags)
        node = {}
        if not path:
            for name_, kind in extra_root_flags:
                p[name_] = kind
        scope = {**inherited, **p, **f}
        if "--help" not in scope:
            f["--help"] = 0
        if "-h" not in scope:
            f["-h"] = "--help"   # (cobra's help shorthand; pflag reads an unknown -h as help too)
        if not path and re.search(r"\bVersion:", text_) and "--version" not in scope:
            f["--version"] = 0
            if "-v" not in scope:
                f["-v"] = "--version"
        if f:
            node["f"] = f
        if p:
            node["p"] = p
        if re.search(r"\bDisableFlagParsing:\s*true", text_):
            node["r"] = True
        if var and re.search(r"\b\w+\.SetInterspersed\(false\)", fn["body"]):
            node["i"] = False
        args = re.search(r"\bArgs:\s*([^\n]+)", text_)
        for pattern, arity in _COBRA_ARGS:
            if args and (m := re.match(pattern, args.group(1).strip())):
                node["a"] = arity(*m.groups())
                break
        else:
            if args is None and not re.search(r"\bRunE?:", text_):
                node["a"] = [0, 0]   # (a command that runs nothing shows its help)
        commands[key] = node
        for alias in re.findall(r'"([^"]+)"', (re.search(r"\bAliases:\s*\[\]string\{([^}]*)\}", text_) or
                                               re.match("()", "")).group(1)):
            commands[" ".join(path[:-1] + [alias])] = key
        for child, _ in (tree.children(fn, var) if var else []) + (list(root_children) if not path else []):
            walk(child, path, {**inherited, **p}, (*stack, id(fn)))
        if not path and len(commands) > 1 and "a" not in node:
            node["a"] = [0, 0]   # (legacyArgs: the root's word must name a subcommand)
    walk(root_fn, None, {})
    return commands


def docker(base):
    """docker/cli: newDockerCommand (TraverseChildren: the root's flags come before a subcommand) and the commands each
    package registers in its init (commands.Register, RegisterLegacy). CLI plugins (compose, buildx) aren't read."""
    root = os.path.join(base, "docker")
    tree = GoTree([root], {"github.com/docker/cli": root})
    fn = tree.funcs[(os.path.join(root, "cmd", "docker"), "newDockerCommand")][0]
    assert "TraverseChildren: true" in fn["body"]
    registered = []
    for (pkg, name), fns in tree.funcs.items():
        if name == "init":
            for f in fns:
                for callee in re.findall(r"commands\.Register(?:Legacy)?\((\w+)\)", f["body"]):
                    registered += [(t, callee) for t in tree.funcs.get((pkg, callee), [])]
    commands = cobra_tree(tree, fn, "docker", root_children=registered)
    assert commands["volume rm"]["f"]["--force"] == 0 and commands["volume rm"]["a"] == [1, None], commands["volume rm"]
    write("docker", "cobra", source(base, "docker"), commands, traverse=True)


def kubectl(base):
    """kubectl: NewKubectlCommand, its command groups and AddCommand calls, the persistent flags of cli-runtime's
    ConfigFlags and kubectl's own (klog's -v and --vmodule come from Go's flag package and aren't read)."""
    root = os.path.join(base, "kubectl")
    runtime = os.path.join(base, "cli-runtime")
    tree = GoTree([root, runtime], {"k8s.io/kubectl": root, "k8s.io/cli-runtime": runtime})
    fn = tree.funcs[(os.path.join(root, "pkg", "cmd"), "NewKubectlCommand")][0]
    commands = cobra_tree(tree, fn, "kubectl")
    assert commands[""]["p"].get("--namespace") == 1 and commands["apply"]["f"].get("--dry-run") == "?", commands[""]
    write("kubectl", "cobra", {**source(base, "kubectl"), "flags": source(base, "cli-runtime")}, commands)


def gh(base):
    root = os.path.join(base, "gh")
    tree = GoTree([root], {"github.com/cli/cli/v2": root})
    fn = tree.funcs[(os.path.join(root, "pkg", "cmd", "root"), "NewCmdRoot")][0]
    commands = cobra_tree(tree, fn, "gh")
    assert commands["release create"]["f"]["--draft"] == 0 and commands["release create"]["f"]["-d"] == "--draft"
    write("gh", "cobra", source(base, "gh"), commands)


# git: git.c's commands[] (the builtins), each builtin's `struct option` arrays with parse-options.h's OPT_* macros
# expanded (a switch: BIT, NEGBIT, BITOP, COUNTUP, SET_INT, CMDMODE, a callback with PARSE_OPT_NOARG; an optional value:
# PARSE_OPT_OPTARG; ALIAS; SUBCOMMAND a subcommand with its function's options); --no-X for each long option without
# PARSE_OPT_NONEG (and X for one named no-X); git.adoc's synopsis for the options before the command
_C_DEFINE = re.compile(r"^#define\s+(_?OPT\w*)\(([^)]*)\)\s*((?:.*\\\n)*.*)$", re.M)


def c_split(args):
    """A C macro call's arguments, split at top-level commas."""
    out, depth, cur, q = [], 0, "", None
    for c in args:
        if q:
            cur += c
            q = None if c == q and not cur.endswith("\\" + q) else q
            continue
        if c in "\"'":
            q = c
        depth += c in "({"
        depth -= c in ")}"
        if c == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += c
    return out + ([cur.strip()] if cur.strip() else [])


def git(base):
    root = os.path.join(base, "git")
    macros = {}
    for h in sources(os.path.join(root, "*.h")):
        for name, params, body in _C_DEFINE.findall(text(h)):
            macros[name] = ([x.strip() for x in params.split(",") if x.strip()], body.replace("\\\n", " "))

    def expand(item, depth=0):
        """The option literals (`{ .type = ..., ... }`) a macro call expands to, its parameters replaced at once."""
        m = re.match(r"\s*(_?OPT\w*)\((.*)\)\s*$", item, re.S)
        if m is None or m.group(1) not in macros or depth > 8:
            return [item.strip()] if item.strip().startswith("{") else []
        params, body = macros[m.group(1)]
        args = dict(zip(params, c_split(m.group(2))))
        if args:
            body = re.sub(r"\b(%s)\b" % "|".join(map(re.escape, args)), lambda x: args[x.group(1)], body)
        return [x for part in c_split(body.strip()) for x in expand(part, depth + 1)]

    def field(lit, name):
        m = re.search(r"\.%s\s*=\s*([^,}]*)" % name, lit)
        v = m.group(1).strip() if m else ""
        while v.startswith("(") and v.endswith(")"):
            v = v[1:-1].strip()
        return v

    def options(body, file_src):
        """{spelling: kind} and {subcommand: function} of the option arrays a function's body defines or names."""
        flags, subs, items = {}, {}, []
        arrays = re.findall(r"struct option (\w+)\[\] = \{", body)
        for name in arrays + [n for n in re.findall(r"static struct option (\w+)\[\] = \{", file_src) if n in body]:
            src = body if name in arrays else file_src
            block = go_body(src, src.index("struct option %s[] = {" % name) + len("struct option %s[] = " % name), True)
            items += [x for part in c_split(block[1:-1]) for x in expand(part)]
        longs = {}
        for lit in items:
            typ, short, long_ = field(lit, "type"), field(lit, "short_name"), field(lit, "long_name")
            fl = field(lit, "flags")
            long_ = long_.strip('"') if long_.startswith('"') else ""
            short = short[1] if re.fullmatch(r"'[!-~]'", short) else ""   # (0 or '\\0': none)
            if typ == "OPTION_SUBCOMMAND":
                subs[long_] = field(lit, "subcommand_fn")
                continue
            if typ == "OPTION_ALIAS":
                target = field(lit, "value").strip('"')
                longs[long_] = ("alias", target)
                continue
            if typ in ("OPTION_BIT", "OPTION_NEGBIT", "OPTION_BITOP", "OPTION_COUNTUP", "OPTION_SET_INT"):
                kind = 0
            elif typ in ("OPTION_STRING", "OPTION_INTEGER", "OPTION_UNSIGNED", "OPTION_FILENAME", "OPTION_CALLBACK"):
                kind = 0 if "PARSE_OPT_NOARG" in fl else "?" if "PARSE_OPT_OPTARG" in fl else 1
                kind = "x" if "PARSE_OPT_LASTARG_DEFAULT" in fl else kind
            else:
                continue   # (OPTION_NUMBER, OPTION_LOWLEVEL_CALLBACK, groups, the end: not read)
            if "PARSE_OPT_NODASH" in fl:
                continue   # (given without a dash: grep's `(` and `)`)
            if long_:
                longs[long_] = (kind, "PARSE_OPT_NONEG" not in fl)
            if short:
                flags["-" + short] = ("--" + long_) if long_ else ("x" if kind != 0 else 0)
                if not long_:
                    flags["-" + short] = kind
        for name, v in longs.items():
            if v[0] == "alias":
                continue
            flags["--" + name] = v[0]
        for name, v in longs.items():
            if v[0] == "alias":
                if "--" + v[1] in flags:
                    flags["--" + name] = "--" + v[1]
            elif v[1]:
                neg = name[3:] if name.startswith("no-") else "no-" + name
                if "--" + neg not in flags and neg:
                    flags["--" + neg] = "!--" + name
        return flags, subs

    git_c = text(os.path.join(root, "git.c"))
    table = go_body(git_c, git_c.index("static struct cmd_struct commands[] = "), True)
    funcs = {}   # {(file, name): (body, the file's text)}: a subcommand's function is its file's (static)
    for f in sources(os.path.join(root, "builtin", "*.c")):
        src = text(f)
        for m in re.finditer(r"^(?:static )?int (\w+)\([^)]*\)\s*\{", src, re.M):
            funcs[f, m.group(1)] = (go_body(src, m.end() - 1, True), src)
    public = {name: key for key in funcs for name in [key[1]] if name.startswith("cmd_")}
    synopsis = text(os.path.join(root, "Documentation", "git.adoc"))
    synopsis = synopsis[synopsis.index("'git' ["):synopsis.index("<command> [<args>]")]
    glob_flags = {}
    for spelling, rest in re.findall(r"(--?[\w-]+)((?:\[?=<[^>]+>\]?| <[^>]+>)?)", synopsis):
        glob_flags[spelling] = "?" if rest.startswith("[") else 1 if rest else 0
    commands = {"": {"f": glob_flags, "i": False}}

    def add(path, key):
        if key not in funcs:
            return
        body, src = funcs[key]
        flags, subs = options(body, src)
        node = {"f": flags}
        if "PARSE_OPT_STOP_AT_NON_OPTION" in body:
            node["i"] = False
        commands[path] = node
        for sub, sub_fn in subs.items():
            add(path + " " + sub, (key[0], sub_fn))
    for name, fn in re.findall(r'\{\s*"([\w-]+)",\s*(\w+)', table):
        add(name, public.get(fn))
    assert commands["push"]["f"]["--force"] == 0 and commands["push"]["f"]["--repo"] == 1 and \
        commands["push"]["f"]["-f"] == "--force" and commands["push"]["f"]["--force-with-lease"] == "?", commands["push"]
    write("git", "git", source(base, "git"), commands)


# npm: every config definition is a flag of every command (nopt reads the whole command line): Boolean a switch, a
# type nopt reads only as a value (String, Number, a path, a URL, a list of values) one value, a type that mixes
# Boolean with another "x"; npm's shorthands (-g, -D, ...); the commands of cmd-list.js and its aliases
def npm(base):
    root = os.path.join(base, "npm")
    defs = text(os.path.join(root, "workspaces", "config", "lib", "definitions", "definitions.js"))
    flags = {}
    for m in re.finditer(r"\n  '?([\w-]+)'?: new Definition\('([\w-]+)', \{", defs):
        body = go_body(defs, m.end() - 1)
        typ = re.search(r"\n    type: (.+?),?\n    \w", body + "\n    x")
        typ = typ.group(1).strip() if typ else ""
        flags["--" + m.group(2)] = 0 if typ == "Boolean" else "x" if "Boolean" in typ or not typ else 1
        for short in re.findall(r"short: '([\w])'", body) + re.findall(r"short: \['?([\w])'", body):
            flags["-" + short] = "--" + m.group(2)
        if typ == "Boolean":
            flags["--no-" + m.group(2)] = "!--" + m.group(2)
    index = text(os.path.join(root, "workspaces", "config", "lib", "definitions", "index.js"))
    block = go_body(index, index.index("const shorthands = "))
    for short, expansion in re.findall(r"\n  '?([\w-]+)'?: \[([^\]]*)\]", block):
        words = [w.strip().strip("'") for w in expansion.split(",") if w.strip()]
        if len(words) == 1 and words[0] in flags:
            kind = words[0]
        elif len(words) == 2 and words[0] in flags and not words[1].startswith("-"):
            kind = 0   # a flag with its value (-s: --loglevel silent) takes no word of its own: a switch
        else:
            continue
        for spelling in ("-" + short, "--" + short):   # (nopt reads a shorthand after any number of dashes)
            flags.setdefault(spelling, kind)
    cmds = text(os.path.join(root, "lib", "utils", "cmd-list.js"))
    names = re.findall(r"^  '([\w-]+)',$", cmds[cmds.index("const commands = ["):cmds.index("]")], re.M)
    commands = {"": {"p": flags, "a": [0, 0]}}
    for n in names:
        commands[n] = {}
    aliases = go_body(cmds, cmds.index("const aliases = {") + len("const aliases = ") - 1)
    for alias, target in re.findall(r"\n  '?([\w-]+)'?: '([\w-]+)',", aliases):
        if target in commands:
            commands[alias] = target
    assert flags["--dry-run"] == 0 and commands["rm"] == "uninstall" and "publish" in commands, (flags["--dry-run"],)
    write("npm", "nopt", source(base, "npm"), commands)


# pip: optparse. cmdoptions.py's options (partial(Option, ...) and functions returning Option(...)), the general
# group on every command (the main parser reads it before the command, each command's parser after), each command's
# add_options (cmd_opts.add_option and the option groups it adds); an action that stores no value is a switch
_PIP_SWITCH = {"store_true", "store_false", "store_const", "count", "help", "version", "append_const"}


def pip(base):
    root = os.path.join(base, "pip", "src", "pip", "_internal")
    tree = ast.parse(text(os.path.join(root, "cli", "cmdoptions.py")))

    def option(call):
        """{spelling: kind} of an Option(...) or partial(Option, ...) call."""
        args = [a.value for a in call.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        kw = {k.arg: k.value for k in call.keywords}
        action = kw["action"].value if isinstance(kw.get("action"), ast.Constant) else "store"
        if action == "callback":
            kind = 1 if "type" in kw or "nargs" in kw else 0
        else:
            kind = 0 if action in _PIP_SWITCH else 1 if action in ("store", "append") else "x"
        long_ = next((a for a in args if a.startswith("--")), None)
        out = {}
        for a in args:
            if a.startswith("-"):
                out[a] = kind if a == long_ or long_ is None else long_
        return out
    defined = {}
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Call):
            name = (node.targets[0] if isinstance(node, ast.Assign) else node.target).id
            call = node.value
            if isinstance(call.func, ast.Name) and call.func.id == "partial":
                defined[name] = option(ast.Call(func=call.args[0], args=call.args[1:], keywords=call.keywords))
        elif isinstance(node, ast.FunctionDef):
            for ret in ast.walk(node):
                if isinstance(ret, ast.Return) and isinstance(ret.value, ast.Call) and \
                        getattr(ret.value.func, "id", "") == "Option":
                    defined[node.name] = option(ret.value)
    groups = {}
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Dict):
            name = (node.targets[0] if isinstance(node, ast.Assign) else node.target).id
            d = dict(zip([k.value for k in node.value.keys], node.value.values))
            if "options" in d:
                groups[name] = [e.id for e in d["options"].elts if isinstance(e, ast.Name)]
    general = {k: v for n in groups["general_group"] for k, v in defined.get(n, {}).items()}
    init = text(os.path.join(root, "commands", "__init__.py"))
    commands = {"": {"p": general, "i": False, "a": [0, 0]}}
    for name, module, cls in re.findall(r'"([\w-]+)": CommandInfo\(\s*"([\w.]+)",\s*"(\w+)"', init):
        mod = ast.parse(text(os.path.join(base, "pip", "src", *module.split(".")) + ".py"))
        flags = {}
        for fn in ast.walk(mod):
            if isinstance(fn, ast.FunctionDef) and fn.name == "add_options":
                for call in ast.walk(fn):
                    if not isinstance(call, ast.Call):
                        continue
                    f = call.func
                    if isinstance(f, ast.Attribute) and f.attr == "add_option":
                        if call.args and isinstance(call.args[0], ast.Call):
                            inner = call.args[0].func
                            flags.update(defined.get(getattr(inner, "attr", getattr(inner, "id", "")), {}))
                        else:
                            flags.update(option(call))
                    elif isinstance(f, ast.Attribute) and f.attr == "make_option_group" and call.args and \
                            isinstance(call.args[0], ast.Attribute) and call.args[0].attr in groups:
                        for n in groups[call.args[0].attr]:
                            flags.update(defined.get(n, {}))
        commands[name] = {"f": flags}
    assert commands["install"]["f"]["--upgrade"] == 0 and commands["install"]["f"]["-r"] == "--requirement", \
        commands["install"]["f"].get("--upgrade")
    write("pip", "optparse", source(base, "pip"), commands)

def main():
    cmd, base = sys.argv[1], os.path.abspath(sys.argv[2])
    only = set(sys.argv[3:])
    if cmd == "fetch":
        fetch(base, only)
        return
    for name, build in BUILDS.items():
        if not only or name in only:
            build(base)


BUILDS = {"gcloud": gcloud, "aws": aws, "curl": curl, "terraform": terraform, "gh": gh, "docker": docker, "kubectl": kubectl, "git": git, "npm": npm,
          "pip": pip}

if __name__ == "__main__":
    main()
