"""tracekit command line."""
import argparse
import getpass
import json
import os
import re
import sys

from . import __version__, agent_hooks, demo
from .wiki import wiki_url

NUDGE_WAIT_S = 5.0
LAST_WAIT_S = 15.0   # `tracekit last`: how long a run that just closed may take to be finalised (the grace window is 5 s)


def experimental_gate(enabled, what):
    """Experimental servers run only with --experimental, and always say they are being rebuilt."""
    if not enabled:
        print(f"tracekit: {what} is experimental and off by default; pass --experimental to run it", file=sys.stderr)
        return False
    print(f"tracekit: warning: {what} is experimental and being rebuilt; do not rely on it", file=sys.stderr)
    return True


def guidance():
    """The line `tracekit init --v2` prints once it installs hooks: where the agent's instructions for a held or blocked
    call are (the Claude Code plugin's tracekit-holds skill holds the same lines)."""
    return ("when Tracekit holds or blocks a call, the agent should tell you and pass on the commands: paste the lines "
            f"at {HOLDS_SKILL} into its CLAUDE.md or AGENTS.md")


# the lines guidance() names, in the Claude Code plugin's tracekit-holds skill
HOLDS_SKILL = "https://github.com/Cygnux-Labs/Tracekit/blob/main/plugin/skills/tracekit-holds/SKILL.md"


def next_step():
    """The line `tracekit init --dev --v2` ends with once it wired Claude Code's hooks: what to do now."""
    import shutil
    return (("next: install Claude Code (no `claude` on PATH yet), then start a session" if not shutil.which("claude")
             else "next: start a new Claude Code session (one already open doesn't load the hooks)")
            + ". A call the policy holds shows a `! tracekit approvals approve <id>` line: paste it into that session "
              "to allow the call once, then ask the agent to retry it. See every run: tracekit view --dev")


def _dev_key_fingerprint(data_dir, make=True):
    """The SHA-256 of the dev signer's log key (`tracekit verify` prints it for the key a trust file pins). With `make`
    (init) it is made when no signer made it yet, so init can print the key the signer will use without opening its
    store; without (up), a key not there is a FileNotFoundError and nothing is written."""
    import hashlib
    from . import crypto
    from .signer import service
    path = os.path.join(data_dir, "keys", "log.key")
    if make:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    try:
        with open(path, "rb") as f:
            secret = f.read()
    except FileNotFoundError:
        if not make:
            raise
        secret = crypto.generate()[0]
        try:
            service._write_new(path, secret)
        except FileExistsError:   # a signer made the same key while init was preparing its output
            with open(path, "rb") as f:
                secret = f.read()
    if len(secret) != 32:
        raise ValueError(f"{path} is not a 32-byte log key")
    return hashlib.sha256(crypto.public_from_secret(secret)).hexdigest()


def _witnessed(data_dir):
    """data_dir/witnessed.json as the signer wrote it at its last start ({witness name: size it held, None: no answer}),
    else None: no start wrote it yet, or the file is not that, and nothing of it is ever printed."""
    from .signer.service import WITNESSED
    try:
        with open(os.path.join(data_dir, WITNESSED), "rb") as f:
            got = json.loads(f.read(1 << 16))
    except (OSError, ValueError, RecursionError):
        return None
    sizes = isinstance(got, dict) and all(v is None or type(v) is int and v >= 0 for v in got.values())
    return got if sizes else None


def _dev_anchoring(data_dir, make=True):
    """The lines `init --dev --v2` and `up --wait` print: the dev signer's log key (made by init only: `make`), and
    whether a witness anchors its log as the signer last started (_witnessed), with what a change needs to apply."""
    from . import public_witness
    from .signer.service import NO_WITNESS
    try:
        key = f"log key SHA-256 fingerprint: {_dev_key_fingerprint(data_dir, make)}"
    except (OSError, ValueError):
        key = "start the signer with `tracekit up --wait` to see its log key"
    heard, name = _witnessed(data_dir), public_witness.VKEY.split("+")[0]
    using = bool(name) and heard is not None and name in heard   # the signer's last start used the public witness
    apply = "restart it with `tracekit up --replace` to apply"
    if os.path.exists(os.path.join(data_dir, NO_WITNESS)):
        return [key, f"public witness: off from the dev signer's next start (--no-witness); {apply}" if using
                else public_witness.LOST]
    if not public_witness.configured():
        return [key, public_witness.NOT_CONFIGURED]
    if heard is None:
        return [key, "public witness: on from the dev signer's next start"]
    if not using:
        return [key, f"public witness: on, but the dev signer last started without it; {apply}"]
    if heard[name] is None:
        return [key, "public witness: on, but it didn't answer when the dev signer started, so the log isn't anchored "
                     "until it does"]
    if heard[name] == 0:   # registered, as a new log is at its first start: the witness holds no checkpoint of it yet
        return [key, "registered with the public witness; nothing cosigned yet"]
    return [key, f"anchored: the public witness held this log at size {heard[name]} when the dev signer started"]


def _init_dev_witness(no_witness, public):
    """`tracekit init --dev --v2`: `--no-witness` turns the dev signer's witness off and only `--public-witness` turns
    it back on, so any other init keeps the choice; returns _dev_anchoring's lines."""
    from .signer.service import dev_data_dir, set_dev_witness
    data_dir = dev_data_dir()
    if no_witness or public:
        set_dev_witness(no_witness, data_dir)
    return _dev_anchoring(data_dir)


def experimental(what, help=False):
    """The one line each experimental command or server prints when it starts (docs/support.md); with `help`, the line
    its --help ends with, on stdout."""
    text = f"{what} is experimental: it works and is tested, but may change ({wiki_url('docs/support.md')})"
    print(f"\n{text}" if help else f"tracekit: {text}", file=sys.stdout if help else sys.stderr)


def _signer_home(a):
    from . import client
    return a.home or client.client_config().get("signer_home") or "/var/lib/tracekit"


_DELEGATED = {"observe": "observe", "analyze": "findings", "otel": "otlp", "cost": "cost", "witness": "witness_server",
              "public-witness": "public_witness_server",
             "deploy": "deploy.compose",
              "signer": "signer.service", "view": "view", "monitor": "monitor", "gateway": "gateway",
              "egress": "egress", "executor": "executor", "mcp-gateway": "mcp_gateway", "issuer": "issuer",
              "a2a-gateway": "a2a_gateway", "ext-mcp": "ext_mcp",
              "why": "why.cli", "reviewer": "reviewer", "srt-decider": "srt_decider",
              "openshell-middleware": "openshell", "follow": "follow",
              "sensor": "sensor", "ingest": "ingest", "graph": "graph", "pcm": "pcm.cli",
              "report": "report", "audit": "audit", "tips": "tips",
              "verify-model": "model_receipt", "feedback": "feedback"}  # subcommands with their own parsers
# delegated subcommands that are experimental (docs/support.md); otel has its own --experimental gate
_EXPERIMENTAL = {"why": "tracekit why", "gateway": "the LLM gateway", "egress": "the egress observer",
                 "executor": "the tool executor", "mcp-gateway": "the MCP gateway", "a2a-gateway": "the A2A gateway",
                 "reviewer": "the reference reviewer",
                 "openshell-middleware": "the OpenShell middleware",
                 "ext-mcp": "agentgateway's ext_mcp processor",
                 "issuer": "the record-key issuer", "witness": "the witness", "public-witness": "the public witness",
                 "monitor": "the log monitor", "deploy": "the compose stack", "cost": "tracekit cost",
                 "analyze": "tracekit analyze", "observe": "tracekit observe (the v1 ledger)",
                 "srt-decider": "the srt-proxy decider", "follow": "tracekit follow",
                 "sensor": "the kernel sensor import", "graph": "tracekit graph", "pcm": "tracekit pcm",
                 "report": "tracekit report", "audit": "tracekit audit", "tips": "tracekit tips",
                 "verify-model": "tracekit verify-model"}
_MOVED = {"sql": "query", "proofpack": "proofpack", "causeway": "causeway"}  # now separate packages under contrib/
GRANTS = "intent grants (tracekit grant, approvals approve --grant)"   # experimental, as their --help ends


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):   # a legacy console encoding (Windows cp1252) can't print every character
        if hasattr(stream, "reconfigure") and getattr(stream, "errors", "strict") == "strict":
            stream.reconfigure(errors="replace")
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:2] == ["migrate", "--system"]:  # 0.2.1; before argparse for the same REMAINDER reason as below
        rest, fm, harnesses = args[2:], None, []
        while rest:
            if rest[0] == "--fail-mode" and len(rest) > 1 and rest[1] in ("open", "closed") and fm is None:
                fm = rest[1]
            elif rest[0] == "--harness" and len(rest) > 1:
                harnesses.append(rest[1])
            else:
                print("usage: tracekit migrate --system [--fail-mode open|closed] [--harness [NAME=]PATH ...]", file=sys.stderr)
                return 2
            rest = rest[2:]
        from . import install
        return install.migrate_system(fm, harnesses)
    if args and args[0] in _MOVED:
        print(f"tracekit {args[0]}: moved to a separate package, https://github.com/Cygnux-Labs/Tracekit/tree/main/contrib/{_MOVED[args[0]]}",
              file=sys.stderr)
        return 2
    if args and args[0] in _DELEGATED:  # before argparse: REMAINDER would not pass a leading --option through
        import importlib
        run = importlib.import_module(f".{_DELEGATED[args[0]]}", __package__).main
        if args[0] not in _EXPERIMENTAL:
            return run(args[1:])
        if not {"-h", "--help"} & set(args[1:]):
            experimental(_EXPERIMENTAL[args[0]])
            return run(args[1:])
        try:   # its help ends with it, once, rather than a banner over the help
            return run(args[1:])
        finally:
            experimental(_EXPERIMENTAL[args[0]], help=True)
    ap, sub = _parser()
    if args and not args[0].startswith("-") and args[0] not in sub.choices:   # argparse would list every command
        import difflib
        near = difflib.get_close_matches(args[0], sub.choices, 1)
        print(f'tracekit: no command "{args[0]}".' + (f' Did you mean "{near[0]}"?' if near else ""),
              "tracekit help lists every command.", sep="\n", file=sys.stderr)
        return 2
    a = ap.parse_args(argv)
    try:
        if a.cmd in (None, "help"):
            return _help(ap, sub, getattr(a, "command", None))
        return _run(a)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0
    except SystemExit:
        raise
    except Exception as e:  # a CLI should print a reason, not a traceback; TRACEKIT_DEBUG=1 restores it
        if os.environ.get("TRACEKIT_DEBUG") == "1":
            raise
        print(f"tracekit: {type(e).__name__}: {e}", file=sys.stderr)
        return 1


# `tracekit help` and a bare `tracekit`: each command under what a person runs it for (tests/test_cli.py checks that
# every command is in exactly one group), then what Tracekit does that is not a command of its own
_GROUPS = (
    ("Start here", "init up down status doctor demo feedback"),
    ("See what agents did", "view last report audit tips why graph cost analyze"),
    ("Approvals", "approvals grant pending approve reject"),
    ("Evidence", "export verify verify-model pcm"),
    ("Policy", "policy"),
    ("Run it on a server", "signer deploy issuer monitor reviewer witness public-witness"),
    ("Record model, tool and network traffic", "gateway executor mcp-gateway a2a-gateway egress"),
    ("Connect other tools", "follow srt-decider openshell-middleware ext-mcp sensor"),
    ("Maintenance", "migrate uninstall"),
    ("Legacy (v1)", "daemon observe ingest otel proxy"),
)
_FEATURES = (
    ("Witnesses and anchoring: other parties cosign the signer's log, and Rekor and RFC 3161 timestamps anchor it "
     "(the free public witness is not deployed yet)", wiki_url("docs/witnesses.md")),
    ("Tracekit Box, a separate program: runs an agent in its own micro-VM whose only ways out are decided and signed",
     "https://github.com/Cygnux-Labs/Tracekit-box"),
    ("SDKs and integrations: tracekit.instrument() and the Python SDK, the TypeScript SDK, framework integrations "
     "and coding-agent hooks", wiki_url("docs/integrations.md")),
)


def _help(ap, sub, name):
    """`tracekit help NAME` is `tracekit NAME --help`; without NAME, every command in its group, each with its own help
    up to where its usage starts, then the features."""
    import textwrap
    if name in sub.choices or name in _MOVED:
        return main([name, "--help"])
    if name:
        print(f"tracekit help: no command named {name!r}; the commands are:\n"
              + textwrap.fill(", ".join(sorted(sub.choices)), 80, initial_indent="  ", subsequent_indent="  ",
                              break_on_hyphens=False), file=sys.stderr)
        return 2
    helps = {x.dest: x.help for x in sub._choices_actions}
    lines = [f"tracekit {__version__}: {ap.description}"]
    for title, names in _GROUPS:
        lines += ["", title]
        for n in names.split():
            text = re.split(r"[;:] (?=`|--|https?://)", helps[n])[0]
            if n in _EXPERIMENTAL and "experimental" not in text:
                text += " (experimental)"
            first = f"  {n:<14}  "
            if len(first) > 18:   # a name longer than the column gets a line of its own
                lines.append(first.rstrip())
                first = " " * 18
            lines.append(textwrap.fill(text, 80, initial_indent=first, subsequent_indent=" " * 18,
                                       break_on_hyphens=False))
    lines += ["", "Also in Tracekit"]
    for text, url in _FEATURES:
        lines += [textwrap.fill(text, 80, initial_indent="  ", subsequent_indent="  "), f"    {url}"]
    print("\n".join(lines + ["", "`tracekit help <command>` shows a command's options."]))
    return 0


def _parser():
    """tracekit's argument parser and its subcommands."""
    ap = argparse.ArgumentParser(prog="tracekit", description="Tamper-evident records of what AI agents did.")
    ap.add_argument("--version", action="version", version=f"tracekit {__version__}")
    sub = ap.add_subparsers(dest="cmd", metavar="command")

    p = sub.add_parser("help", help="every command, grouped by what it is for; `help COMMAND` shows its options",
                       description="Every command, grouped by what it is for, and the features that are not commands "
                                   "of their own; `tracekit help COMMAND` shows that command's options.")
    p.add_argument("command", nargs="?", help="a command's name")
    p = sub.add_parser("init", help="install the signer and a coding agent's hooks (--agent; default Claude Code)")
    p.add_argument("--remote", metavar="URL", help="agent on another machine: with --v2, send to this signer's HTTPS "
                                                   f"transport; without, to the deprecated ingest gateway ({wiki_url('docs/remote-ingest.md')})")
    p.add_argument("--token-file", help="with --remote: file holding the client token (or set TRACEKIT_REMOTE_TOKEN without "
                                        "--v2); with --v2 it is read on every call, so a rotated token needs no restart")
    p.add_argument("--ca", help="with --remote --v2: the CA bundle the signer's certificate must chain to (pinned)")
    p.add_argument("--dev", action="store_true", help="same-user signer (no root; weaker: the agent could rewrite the ledger)")
    p.add_argument("--home", help="signer home (dev mode)")
    p.add_argument("--v2", action="store_true", help="the v2 signer: with --dev, wire its hook for --agent (the signer "
                                                     "starts on first use); as root, install it in system mode")
    p.add_argument("--approver", help="with --v2, system mode: the user who answers the agent's approvals (default: "
                                      "$SUDO_USER, the admin running init)")
    p.add_argument("--policy", help="with --v2, system mode: the signer's policy file (root-owned; default: its own pack)")
    p.add_argument("--public-witness", action="store_true", help="with --v2: the public witness cosigns the signer's "
                                                                 "logs, undoing an earlier --no-witness (system mode: "
                                                                 "fails until it is deployed; "
                                                                 f"{wiki_url('docs/public-witness-privacy.md')}: it sees "
                                                                 "origins, sizes, roots and timing, never content)")
    p.add_argument("--no-witness", action="store_true", help="with --v2: no public witness, the default once it is "
                                                             "deployed, kept by later inits until --public-witness "
                                                             "(whoever holds the signing key can then rewrite the log "
                                                             "unseen)")
    p.add_argument("--egress", action="store_true", help="with --v2, system mode on Linux: the agent user's outside "
                                                         "traffic only through a local egress observer (an owner-match "
                                                         f"firewall rule; undone by uninstall; {wiki_url('docs/egress.md')})")
    p.add_argument("--project", action="store_true", help="hooks in ./.claude/settings.json instead of ~/.claude")
    p.add_argument("--no-hooks", action="store_true", help="install no agent hooks (an SDK agent, or the Claude Code "
                   "plugin's own hooks)")
    p.add_argument("--no-thinking-summaries", action="store_true", help="with --v2: leave Claude Code's "
                   "showThinkingSummaries and Codex's model_reasoning_summary alone (init turns them on so `tracekit "
                   "analyze --v2` can read the model's reasoning)")
    p.add_argument("--witness", action="append", default=[], help="file:/path.jsonl or git:/clone[@remote] (repeatable; default: the last init's, else a local clone)")
    p.add_argument("--checkpoint-every", type=int, help="records between checkpoints (default: the last init's, else 50)")
    p.add_argument("--user", help="system mode: the user whose agents are traced (default: $SUDO_USER)")
    p.add_argument("--no-service", action="store_true", help="system mode: do not install systemd/launchd")
    p.add_argument("--experimental-macos", action="store_true", help="allow system mode on macOS (not yet validated on hardware)")
    p.add_argument("--proxy", action="store_true", help="also run the model proxy and point Claude Code at it (C3; needs --experimental)")
    p.add_argument("--experimental", action="store_true", help="allow experimental surfaces (--proxy)")
    p.add_argument("--proxy-port", type=int, default=8787,
                   help="with --proxy: the port the model proxy listens on "
                        "(default: 8787)")
    p.add_argument("--fail-closed", action="store_true", help="proxy: refuse to forward when the signer can't record")
    p.add_argument("--managed", action="store_true", help="system mode, Claude Code: hooks in its admin-managed "
                   "settings (managed-settings.json), which the agent's user can't edit or turn off; they run in "
                   "every user's Claude Code on this machine (limits: a server-managed or MDM policy replaces the "
                   f"file, claude --bare may skip it; {wiki_url('docs/limits.md', 'dev-mode-vs-system-mode')})")
    p.add_argument("--managed-only", action="store_true", help="with --managed: also set allowManagedHooksOnly, which "
                   "stops every user's own Claude Code hooks on this machine (user, project, local and plugin ones)")
    p.add_argument("--agent", choices=("claude", *agent_hooks.HARNESSES), default="claude",
                   help="which coding agent's hooks to install (default: Claude Code)")
    p.add_argument("--harness", action="append", default=[], metavar="[NAME=]PATH",
                   help="system mode (0.3): the agent program whose processes may send events, e.g. /usr/local/bin/claude "
                        "(repeatable; must be root-owned). Default: the agent's CLI on PATH if installed root-owned; "
                        "with --v2: none (no binding)")
    p.add_argument("--signer-cmd", help="external signer helper command (TPM/HSM/enclave; see tracekit/extsigner.py)")
    p.add_argument("--signer-pub", help="with --signer-cmd: the helper key's raw 32-byte Ed25519 public key file")
    p.add_argument("--key-assurance", default="external", help="with --signer-cmd: where the key lives (tpm, hsm, tee, kms, smartcard)")
    p.add_argument("--i-understand-agent-is-privileged", dest="allow_privileged", action="store_true",
                   help="system mode: trace a user that is root or in a sudo/wheel/admin/docker/tracekit group anyway")
    p.add_argument("--key-attestation", help="with --signer-cmd: the device's attestation document for the key (TPM quote, "
                                             "enclave attestation, KMS key metadata); its hash is signed into checkpoints and "
                                             "exports carry it")

    p = sub.add_parser("status", help="what is set up here: hooks, signer, policy, capture sources")
    p.add_argument("--json", action="store_true", help="print everything it found as one JSON object")
    p = sub.add_parser("up", help="start the local signer (dev mode), or find the running one")
    p.add_argument("--wait", action="store_true", help="return once it answers")
    p.add_argument("--no-witness", action="store_true", help="no public witness for the dev signer (restarts it; "
                                                             "init --dev --v2 --public-witness turns it back on)")
    p.add_argument("--json", action="store_true", help="wait, then print its hello as JSON")
    p.add_argument("--replace", action="store_true", help="stop the running dev signer first, even an incompatible one")
    sub.add_parser("down", help="stop the local signer (dev mode)")
    p = sub.add_parser("doctor", help=f"check this setup (v1/v2 system mode, the dev signer); {wiki_url('docs/doctor.md')}")
    p.add_argument("--json", action="store_true", help="print [{id, status, detail, fix}]")
    p.add_argument("--config", help="check the v2 signer of this signer.yaml")
    p.add_argument("--k8s", action="store_true", help="check the Kubernetes pod doctor runs in (or --manifests)")
    p.add_argument("--manifests", metavar="DIR", help="with --k8s: check these rendered manifests instead")
    p.add_argument("--issuer-key", metavar="KEY_ID", help="the record key issuer's KMS key: the signer must not sign "
                   "with it")
    p = sub.add_parser("uninstall", help="remove Tracekit's hooks (your signed runs and keys stay: it says where, and "
                                         "how to delete them too)")
    p.add_argument("--project", action="store_true",
                   help="remove hooks from the selected agent's project settings file "
                        "instead of its user settings file")
    p.add_argument("--v2", action="store_true", help="as root: remove v2 system mode (service, configs, hooks)")
    p.add_argument("--purge", action="store_true", help="with --v2: also delete the signer's keys, log and user")
    p.add_argument("--agent", choices=("claude", *agent_hooks.HARNESSES), default="claude",
                   help="which coding agent's hooks to remove (default: Claude Code)")

    p = sub.add_parser("ingest", help="remote ingestion gateway (experimental): `ingest token NAME` / `ingest serve`",
                       add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("analyze", help="run the detectors over a run and sign the findings into the ledger "
                       "(--v2: check a v2 run's request, reasoning and actions)", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("cost", help="token usage (and cost, with your price table) per run or model", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("witness", help="run a witness log: `witness init|token|serve` (append-only, Merkle tree, signed heads)", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("public-witness", help="run a public C2SP tlog-witness with open registration: "
                       "`public-witness init|serve` (deploy/public-witness)", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("deploy", help="`deploy compose [--dir DIR]`: write the compose stack (signer, witness, viewer, "
                       "Postgres)", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("signer", help="the v2 signer service: `signer serve --dev`, `signer serve|fsck --config signer.yaml`", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("monitor", help="follow a v2 signer's logs, check their rules, publish a signed monitor report",
                       add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("gateway", help="LLM gateway for the v2 signer: `gateway serve --config gateway.yaml`", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("egress", help="egress observer for the v2 signer: `egress serve --config egress.yaml`",
                       add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("sensor", help="kernel sensor import for the v2 signer: `sensor import --config sensor.yaml`",
                       add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("reviewer", help="the reference agent approver: `reviewer serve|eval --config reviewer.yaml`",
                       add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("executor", help="tool executor for the v2 signer: `executor serve --config executor.yaml`",
                       add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("mcp-gateway", help="MCP gateway for the v2 signer: `mcp-gateway serve --config mcp-gateway.yaml`",
                       add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("a2a-gateway", help="A2A gateway for the v2 signer (experimental): `a2a-gateway serve --config "
                                           "a2a-gateway.yaml`", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("srt-decider", help="decide every request srt-proxy (Anthropic's sandbox-runtime) asks about: "
                                           "`srt-decider --allow-domain HOST -- srt-proxy ...`", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("openshell-middleware", help="NVIDIA OpenShell supervisor middleware for the v2 signer: "
                       "`openshell-middleware serve --config openshell-middleware.yaml`", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("ext-mcp", help="agentgateway's ext_mcp processor for the v2 signer: `ext-mcp serve`", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("issuer", help="record-key issuer for v2 signers: `issuer serve|revoke|vkey --config issuer.yaml`",
                       add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("follow", help="follow agentsh's audit log into the v2 signer as it is written: "
                       "`follow agentsh --log PATH`", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("otel", help="OpenTelemetry receiver (experimental): `otel serve` records agent spans sent over "
                                    "OTLP/HTTP", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("daemon", help="run the v1 signer, tracekitd, in the foreground (experimental)")
    p.add_argument("--home", help="signer home directory (default: the configured one, else /var/lib/tracekit)")
    p = sub.add_parser("proxy", help="run the model proxy in the foreground (experimental)")
    p.add_argument("--home", help="signer home directory (default: the configured one, else /var/lib/tracekit)")
    p.add_argument("--experimental", action="store_true", help="required: the proxy is being rebuilt")
    p.add_argument("--port", type=int, help="port to listen on (default: signer config, else 8787)")
    p.add_argument("--upstream", help="API URL to forward requests to "
                                       "(default: signer config, else https://api.anthropic.com)")

    p = sub.add_parser("observe", help="the old name of `tracekit view --ledger`: the v1 ledger or a v1 bundle in a "
                                       "read-only web page")
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("view", help="the viewer: the v2 signer's runs, each verified; --why DIR, --ledger, --bundle (read-only web UI)")
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("graph", help="what agents did across verified bundles: `graph build|query|verify`", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("report", help="what the agents did this week, on one page, from the v2 signer's store: runs, "
                       "calls, holds, denies and flags by rule, gaps, integrity (--since, --json, --share)",
                       add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("audit", help="replay your coding agents' past tool calls (Claude Code transcripts, Gemini CLI sessions, or a calls file) "
                       "through the policy and count what it would have held or denied; read-only, not a signed record", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("tips", help="what each step of your coding agents cost and how to cut it, as tracekit view's "
                       "TIPS page says it, from the dev signer's store and Claude Code's transcripts (--since, --json)",
                       add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("feedback", help="print a pre-filled GitHub issue, a field report or (--harmless ID) a false "
                       "alarm, and exactly what it holds; sends nothing (--open opens it in your browser)", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("verify-model", help="check a model file against the receipt a coding-agent hook recorded when "
                       "a call wrote it, and name the tensors that changed: `verify-model OLD NEW --bundle B --run R "
                       "--trust T`", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("why", help="causal investigation and replay of multi-agent runs: `why demo|record|serve|test|...`",
                       add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("pcm", help="PCM 0.1, proof-carrying messages between agents: `pcm verify MSG --trust T --schema S`, "
                       "`pcm demo`", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)

    sub.add_parser("pending", help="list tool calls waiting for approval")
    for name in ("approve", "reject"):
        p = sub.add_parser(name, help=f"{name} a held tool call, short for `tracekit approvals {name}` (run from a "
                           "terminal outside the agent's session)")
        p.add_argument("approval_id", nargs="?", help="id from `tracekit pending`; on a v1 signer (tracekitd), also a "
                       "prefix of one, or none for the only pending one")

    p = sub.add_parser("approvals", help="approvals on the v2 signer: `approvals list|show ID|approve ID|reject ID`, "
                       "`approvals slack serve --config slack.yaml`")
    p.add_argument("--signer", help="the signer's Unix socket or tcp://host:port (default: the same-user dev signer)")
    acts = p.add_subparsers(dest="action", required=True)
    q = acts.add_parser("list", help="approvals, those waiting for an answer first, newest first, each with what its "
                        "call runs")
    q.add_argument("--json", action="store_true", help="print one JSON array: every approval, in the signer's order")
    q.add_argument("--all", action="store_true", help="the expired ones too")
    q = acts.add_parser("show", help="one approval: why its call was held, what to do instead, the commands that "
                        "answer it, and the signer's copy of the arguments in full")
    q.add_argument("approval_id", help="the approval to show, from `tracekit approvals list`")
    q.add_argument("--json", action="store_true", help="print one JSON object without a pager")
    for name in ("approve", "reject"):
        q = acts.add_parser(name, help=f"{name} a pending approval" + (
            "; with --grant, also grant the run calls like it within limits (docs/intent-grants.md)" * (name == "approve")))
        q.add_argument("approval_id", help="the approval to " + name + ", from `tracekit approvals list`")
        q.add_argument("--reason", help="why, sent to the signer with the answer")
        if name == "approve":
            q.add_argument("--grant", action="store_true", help="also issue a payment grant from this held call: it "
                           "counts as the grant's first payment, and later payments within the limits run without a stop")
            _grant_flags(q, False)
    q = acts.add_parser("slack", help=f"the Slack approvals bridge ({wiki_url('docs/approvals.md', 'slack')})")
    q.add_argument("slack_action", choices=["serve"], help="serve: run the Slack bridge")
    q.add_argument("--config", required=True, help="slack.yaml")

    p = sub.add_parser("grant", help="intent grants on the v2 signer (experimental): approve a kind of costly call "
                       "once, within limits, "
                       "for one run: `grant add|list|revoke` (docs/intent-grants.md)",
                       epilog=f"{GRANTS} is experimental: it works and is tested, but may change "
                              f"({wiki_url('docs/support.md')})")
    p.add_argument("--signer", help="the signer's Unix socket or tcp://host:port (default: the same-user dev signer)")
    acts = p.add_subparsers(dest="action", required=True)
    q = acts.add_parser("add", help="grant a run's agent payments within limits, without a stop for each one")
    q.add_argument("--run", required=True, help="the run's id (tracekit view, or approvals show)")
    _grant_flags(q, True)
    q = acts.add_parser("list", help="the grants of the open runs you may see, with what each has left")
    q.add_argument("--run", help="only this run's")
    q.add_argument("--json", action="store_true", help="print one JSON array, as the signer gives it")
    q = acts.add_parser("revoke", help="end a grant: every call it would release is held again")
    q.add_argument("grant_id", help="g-... from tracekit grant list")
    q.add_argument("--reason", help="why, sent to the signer with the revocation")

    p = sub.add_parser("export", help="write a .tkb evidence bundle")
    p.add_argument("-o", "--out", default="tracekit.tkb", help="the bundle to write (default: tracekit.tkb)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--last", action="store_true", help="the most recent run (default)")
    g.add_argument("--run", help="the run to export, by its id")
    g.add_argument("--since", help="RFC3339 time, e.g. 2026-09-30T00:00:00.000000Z")
    p.add_argument("--otel", action="store_true", help="also include otel.json (OTLP/JSON); with --v2, write it next "
                   "to the bundle as <name>.otel.json")
    p.add_argument("--otel-endpoint", help="also POST the spans to an OTLP/HTTP collector, e.g. http://localhost:4318")
    p.add_argument("--otel-header", action="append", default=[], metavar="KEY=VALUE",
                   help="header for --otel-endpoint (repeatable; also read from OTEL_EXPORTER_OTLP_HEADERS)")
    p.add_argument("--home", help="signer home to read the ledger from")
    p.add_argument("--v2", action="store_true", help="format v2, from the v2 signer's store (with --run or --run-set)")
    p.add_argument("--run-set", action="store_true", help="with --v2: the tenant's run-set, every registry leaf up to "
                   "its latest registry checkpoint and the runs finalised in it (reads the signer's keys/)")
    p.add_argument("--tenant", help="with --v2: the run's tenant (default: the signer's default tenant)")
    p.add_argument("--config", help="with --v2: the signer's config (default: the same-user dev signer)")
    p.add_argument("--dev", action="store_true", help="with --v2: the same-user dev signer (the default)")
    p.add_argument("--data-dir", help="with --v2: a signer data dir (holds store/ and log.vkey), as tracekit view "
                   "reads one; it names no socket, so a run no checkpoint covers yet can't be exported from it")
    p.add_argument("--with-findings", action="store_true", help="with --v2 --run: also the run's findings runs "
                   "(`tracekit analyze --v2`, `tracekit why`) and replay runs, which the verifier checks")
    p.add_argument("--json", action="store_true", help="print what was written as one JSON object, for scripts (with "
                   "--v2: the verifier version the bundle needs, verifier_min_version, and the records that raised it)")

    p = sub.add_parser("last", help="the dev signer's most recent finished run: export it, pin the dev signer's key "
                                    "and verify it")
    p.add_argument("-o", "--out", help="the bundle (default: <run id>.tkb here); its trust config goes next to it")
    p.add_argument("--open", action="store_true", help="the most recent run even if it is still open (a coding "
                   "agent's session run stays open until the session ends), verified up to its last checkpointed record")
    p.add_argument("--detail", action="store_true", help="print every check, then the Integrity and Assurance lines, "
                   "as `tracekit verify --detail` does")

    p = sub.add_parser("verify", help="verify a .tkb offline")
    p.add_argument("bundle", help="the .tkb bundle to verify")
    p.add_argument("--witness", action="append", default=[], help="independent witness copy to check against")
    p.add_argument("--key", help="trusted signer public key (signer.pub file) or key id ed25519:...")
    p.add_argument("--strict", action="store_true", help="exit 3 on warnings")
    p.add_argument("--trust", help="format v2: pinned trust config (log keys, witness keys, algorithms)")
    p.add_argument("--v1-ledger", help="format v2: the v1 ledger.jsonl the log's format bridge continues")
    p.add_argument("--v1-key", help="with --v1-ledger: the v1 signer.pub")
    p.add_argument("--monitor-report", action="append", default=[],
                   help="format v2: a report of a monitor the trust config pins (tracekit monitor)")
    p.add_argument("--revocations", action="append", default=[],
                   help="format v2: record-key revocations, JSON lines (an issuer's issuance.jsonl)")
    p.add_argument("--detail", action="store_true", help="print every check, then the Integrity and Assurance lines "
                   "(the full report; scripts that read the text use it, or --json)")
    p.add_argument("--json", action="store_true", help="print the report as JSON")

    p = sub.add_parser("policy", help="check a v2 policy and try it on past runs: `policy compile FILE` prints "
                                      "canonical JSON and its hash; `policy lint FILE`; `policy backtest --policy P "
                                      "(--store DIR | --bundle B...)` prints the incidents its detection would open")
    p.add_argument("action", choices=("compile", "lint", "backtest"), help="compile, lint or backtest")
    p.add_argument("file", nargs="?", help="the policy file (compile and lint)")
    p.add_argument("--policy", help="backtest: the policy file")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--store", help="backtest: a signer's store directory (data_dir/store)")
    src.add_argument("--bundle", nargs="+", default=[], help="backtest: v2 bundles (.tkb)")

    p = sub.add_parser("migrate", help="read or convert a v0.1 ledger; `migrate --system` upgrades a 0.2.0 system install")
    p.add_argument("rest", nargs=argparse.REMAINDER)

    p = sub.add_parser("demo", help="end-to-end demo in a temp folder")
    p.add_argument("--real", action="store_true", help="drive a real `claude -p` session instead of the scripted agent")
    p.add_argument("--keep", action="store_true", help="keep the demo's temp folder (its bundles, trust config and "
                   "signer data) and print where it is; without it the folder is deleted at the end")
    p.add_argument("--detail", action="store_true", help="print every check of each verification, as `tracekit verify "
                   "--detail` does (not with --why)")
    p.add_argument("--server", action="store_true",
                   help="the v2 signer: a dev signer, a test witness, allow/deny/hold, export and verify")
    p.add_argument("--why", action="store_true",
                   help="`tracekit why` on the signer: a 3-agent desk, a held email, its cause found and cited")
    p.add_argument("--agent", default="claude", choices=demo.AGENTS,
                   help="send the scripted run as this coding agent's own hook payloads (default: claude)")
    return ap, sub


def _init_remote(a):
    from . import client
    from .deploy import files
    url = a.remote.rstrip("/")
    err = client.remote_url_error(url)
    if err:
        print(f"tracekit: --remote: {err}", file=sys.stderr)
        return 2
    if a.v2:
        return _init_remote_v2(a, url)
    token = os.environ.get("TRACEKIT_REMOTE_TOKEN", "")
    if a.token_file:
        with open(a.token_file, encoding="utf-8") as f:
            token = f.read().strip()
    if not token:
        print("tracekit: give the client token with --token-file or TRACEKIT_REMOTE_TOKEN", file=sys.stderr)
        return 2
    path = os.path.join(client.client_dir(), "config.json")
    files.write_json(path, {"socket": url, "socket_token": token, "mode": "remote", "signer_isolation": "remote"}, 0o600)
    print(f"remote signer configured: {url} (SDK only: Claude Code hooks are not installed; held calls are refused)")
    return 0


def _init_remote_v2(a, url):
    """Point v2 hooks and SDK clients at a remote signer's HTTPS transport (tracekit.sdk.client reads the env)."""
    from . import install
    if not url.startswith("https://") or not a.token_file:
        print("tracekit: --remote --v2 takes an https:// URL and --token-file", file=sys.stderr)
        return 2
    env = {"TRACEKIT_SIGNER": url, "TRACEKIT_SIGNER_TOKEN_FILE": os.path.abspath(a.token_file)}
    if a.ca:
        env["TRACEKIT_SIGNER_CA"] = os.path.abspath(a.ca)
    for k in ("TRACEKIT_SIGNER_TOKEN_FILE", "TRACEKIT_SIGNER_CA"):
        if k in env and not os.access(env[k], os.R_OK):
            print(f"tracekit: cannot read {env[k]}", file=sys.stderr)
            return 2
    hooks = None if a.no_hooks or a.agent != "claude" else (
        os.path.join(os.getcwd(), ".claude", "settings.json") if a.project else install.user_settings())
    try:
        on = hooks and install.install_hooks(hooks, module=install.V2_HOOK, signer=env,
                                             thinking=not a.no_thinking_summaries)
        if hooks and not a.project:
            install.record_hooks_settings(hooks)
    except install.SettingsError as e:
        print(f"tracekit: {e}", file=sys.stderr)
        return 1
    print(f"remote v2 signer configured: {url}; v2 hooks: {hooks or 'not installed'}")
    if hooks and not a.no_thinking_summaries:
        print(install.thinking_line(hooks, on))
    if hooks:
        print(guidance())
    print("for SDK clients, set:\n" + "\n".join(f"  export {k}={v}" for k, v in env.items()))
    return 0


def _match_pending(pend, prefix):
    hits = [x for x in pend if x["id"] == prefix] or [x for x in pend if x["id"].startswith(prefix)]
    return hits


def _run(a):
    if a.cmd == "init" and a.remote:
        return _init_remote(a)
    if a.cmd == "init":
        from . import install
        if not a.v2:
            experimental("the v1 signer (tracekit init without --v2)")
        if a.checkpoint_every is not None and a.checkpoint_every < 1:
            print("tracekit: --checkpoint-every must be at least 1", file=sys.stderr)
            return 2
        if not 1 <= a.proxy_port <= 65535:
            print("tracekit: --proxy-port must be between 1 and 65535", file=sys.stderr)
            return 2
        if a.proxy and not experimental_gate(a.experimental, "the model proxy (init --proxy)"):
            return 2
        if a.managed_only and not a.managed:   # alone, the hooks would go to settings the agent's user can edit
            print("tracekit: --managed-only goes with --managed", file=sys.stderr)
            return 2
        if a.managed and (a.dev or a.project or a.agent != "claude"):
            print("tracekit: " + ("--managed is for system mode: a --dev setup belongs to its user" if a.dev else
                                  "--managed and --project name different settings files: use one" if a.project else
                                  f"--managed is for Claude Code only: Tracekit wires no admin-managed settings for "
                                  f"{a.agent}, so its hooks go in the agent user's own config "
                                  f"({wiki_url('docs/limits.md')})"), file=sys.stderr)
            return 2
        signer = None
        if a.key_attestation and not a.signer_cmd:
            print("tracekit: --key-attestation goes with --signer-cmd (an attestation is about an external key)", file=sys.stderr)
            return 2
        if a.signer_cmd or a.signer_pub:
            import shlex
            from .extsigner import ASSURANCES
            if not (a.signer_cmd and a.signer_pub):
                print("tracekit: --signer-cmd and --signer-pub go together", file=sys.stderr)
                return 2
            if a.key_assurance not in ASSURANCES - {"file"}:
                print(f"tracekit: --key-assurance must be one of {sorted(ASSURANCES - {'file'})}", file=sys.stderr)
                return 2
            signer = {"type": "external", "argv": shlex.split(a.signer_cmd), "public_key": os.path.abspath(a.signer_pub),
                      "assurance": a.key_assurance}
            if a.key_attestation:
                signer["attestation"] = os.path.abspath(a.key_attestation)
        if a.v2 and (a.home or a.witness or a.proxy or a.fail_closed or signer):
            print("tracekit: --home, --witness, --proxy, --fail-closed and --signer-cmd are v1 "
                  "signer options; they don't apply with --v2", file=sys.stderr)
            return 2
        if (a.no_witness or a.public_witness) and not a.v2 or a.no_witness and a.public_witness:
            print("tracekit: --no-witness and --public-witness go with --v2, one at a time", file=sys.stderr)
            return 2
        if (a.approver or a.policy or a.egress or a.v2 and a.harness) and (a.dev or not a.v2):
            print("tracekit: --approver, --policy, --egress and --harness with --v2 are for --v2 system mode",
                  file=sys.stderr)
            return 2
        if a.v2 and not a.dev:
            if not a.user:
                print("tracekit: --v2 system mode needs --user AGENT, the user whose agent is traced", file=sys.stderr)
                return 2
            try:
                sock, settings = install.init_system_v2(a.user, a.approver, a.policy, os.getcwd() if a.project else None,
                                                        a.no_service, not a.no_hooks, a.experimental_macos,
                                                        a.allow_privileged, a.agent, a.harness,
                                                        a.public_witness or (False if a.no_witness else None),
                                                        a.egress, not a.no_thinking_summaries, a.managed, a.managed_only)
            except install.SettingsError as e:
                print(f"tracekit: {e}", file=sys.stderr)
                return 1
            except install.ServiceError as e:
                print(f"tracekit: installed, but {e}", file=sys.stderr)
                return 1
            print(f"v2 signer installed as a separate user; socket {sock}; config {install.V2_CONFIG}; "
                  f"hooks: {settings or 'not installed'}")
            from . import public_witness
            off = os.path.exists(install.V2_NO_WITNESS)   # this init's --no-witness, or an earlier one's, kept
            if off or not public_witness.configured():
                print(public_witness.LOST if off else public_witness.NOT_CONFIGURED)
            if settings:
                print(guidance())
            if settings and a.agent == "codex":
                import pwd

                print(agent_hooks.codex_trust_line(a.user, pwd.getpwnam(a.user).pw_dir))
            return 0
        if a.dev and a.v2 and a.agent != "claude":
            if not _signer_extra():
                return 2
            try:
                anchoring = _init_dev_witness(a.no_witness, a.public_witness)
                path = None if a.no_hooks else agent_hooks.install(a.agent, os.getcwd() if a.project else None, v2=True)
                summary = path and a.agent == "codex" and not a.no_thinking_summaries and agent_hooks.codex_reasoning(path)
            except install.SettingsError as e:
                print(f"tracekit: {e}", file=sys.stderr)
                return 1
            print(f"v2 {a.agent} hooks:", path or "not installed")
            print(install.DEV_MODE_LINE)
            print(*anchoring, sep="\n")
            if summary:
                print(agent_hooks.reasoning_line(*summary))
            if path:
                print(guidance())
            if path and a.agent == "codex":
                print(agent_hooks.codex_trust_line())
            return 0
        if a.dev and a.agent != "claude":
            home = a.home or os.path.expanduser("~/.tracekit-signer")
            try:
                cfg = install.init_dev(home, a.witness, a.checkpoint_every, None, fail_mode="closed" if a.fail_closed else None, signer=signer)
                path = None if a.no_hooks else agent_hooks.install(a.agent, os.getcwd() if a.project else None)
            except install.SettingsError as e:
                print(f"tracekit: {e}", file=sys.stderr)
                return 1
            print(f"dev signer running (same-user): {cfg['socket']}")
            print(install.DEV_MODE_LINE)
            print(f"{a.agent} hooks:", path or "not installed")
            if path and a.agent == "codex":
                print(agent_hooks.codex_trust_line())
            return 0
        if a.dev:
            home = a.home or os.path.expanduser("~/.tracekit-signer")
            hooks = None if a.no_hooks else (os.path.join(os.getcwd(), ".claude", "settings.json") if a.project
                                            else install.user_settings())
            if a.v2:
                if not _signer_extra():
                    return 2
                from .signer.service import dev_data_dir
                anchoring = _init_dev_witness(a.no_witness, a.public_witness)
                dev_data_dir()   # the plugin's hook blocks tool calls it cannot record once this exists
                plugin = hooks and install.plugin_enabled()
                if plugin:   # both would decide every call, and one would consume each approval the other waits on
                    settings_path, plugin_key = plugin
                    print(f"v2 hooks: not installed: the Tracekit Claude Code plugin, enabled in {settings_path}, "
                          f"runs them "
                          f"(with both, every approved call is blocked). To use init's hooks instead: "
                          f"/plugin disable {plugin_key}, then run init again")
                    print(install.DEV_MODE_LINE)
                    print(*anchoring, sep="\n")
                    if not a.no_thinking_summaries:
                        try:
                            print(install.thinking_line(hooks, install.thinking_on(hooks)))
                        except install.SettingsError as e:
                            print(f"tracekit: {e}", file=sys.stderr)
                            return 1
                    return 0
                try:
                    on = hooks and install.install_hooks(hooks, module=install.V2_HOOK,
                                                         thinking=not a.no_thinking_summaries)
                    if not a.project:   # None: --no-hooks, which doctor then reports as chosen
                        # --no-hooks takes an earlier init's hooks out, as system mode's does
                        for p in [] if hooks else install.user_settings_all():
                            if install._v2_hooks_in(p):
                                install.install_hooks(p, uninstall=True)
                        install.record_hooks_settings(hooks)
                except install.SettingsError as e:
                    print(f"tracekit: {e}", file=sys.stderr)
                    return 1
                print("v2 hooks:", hooks or "not installed")
                print(install.DEV_MODE_LINE)
                print(*anchoring, sep="\n")
                if hooks and not a.no_thinking_summaries:
                    print(install.thinking_line(hooks, on))
                if hooks:
                    print(guidance())
                    print(next_step())
                return 0
            try:
                cfg = install.init_dev(home, a.witness, a.checkpoint_every, hooks, proxy=a.proxy, proxy_port=a.proxy_port,
                                       fail_mode="closed" if a.fail_closed else None, signer=signer)
            except install.SettingsError as e:
                print(f"tracekit: {e}", file=sys.stderr)
                return 1
            if a.proxy:
                print(f"model proxy: {cfg['proxy_url']} (ANTHROPIC_BASE_URL set in {hooks or 'no settings file'})")
            print(f"dev signer running (same-user): {cfg['socket']}")
            print(install.DEV_MODE_LINE)
            print("hooks:", hooks or "not installed")
            return 0
        if a.agent in ("antigravity", "crush", "kilo", "devin"):   # the v1 system signer installs Claude Code's hooks only
            print(f"tracekit: --agent {a.agent} goes with --dev or --v2", file=sys.stderr)
            return 2
        user = a.user or os.environ.get("SUDO_USER") or getpass.getuser()
        try:
            cfg, settings = install.init_system(user, a.witness, a.checkpoint_every,
                                                os.getcwd() if a.project else None, a.no_service, proxy=a.proxy,
                                                proxy_port=a.proxy_port, managed=a.managed, managed_only=a.managed_only,
                                                fail_mode="closed" if a.fail_closed else None,
                                                experimental_macos=a.experimental_macos, hooks=not a.no_hooks, signer=signer,
                                                harnesses=a.harness, agent=a.agent, allow_privileged=a.allow_privileged)
        except install.SettingsError as e:
            print(f"tracekit: {e}", file=sys.stderr)
            return 1
        except install.ServiceError as e:
            print(f"tracekit: installed, but {e}", file=sys.stderr)
            return 1
        print(f"tracekitd installed as a separate user; socket {cfg['socket']}; hooks: {settings or 'not installed'}")
        return 0
    if a.cmd == "status":
        from . import install
        from .sdk import autospawn
        st, v2 = install.status(), autospawn.status()
        from . import client
        system = client.system_config()   # a root-owned config is system mode: the signer isn't the same user's
        dev = (st["client_config"] or {}).get("mode") == "dev" or v2.get("dev") and not system
        if a.json:
            print(json.dumps({**st, "signer_v2": v2, **({"dev_mode": install.DEV_MODE_LINE} if dev else {})}, indent=2))
            return 0
        cfg = st["client_config"] or {}   # system mode's: its hooks section
        chosen = (cfg.get("hooks") or {}).get("no_hooks") if system else cfg.get("no_hooks")
        print(*_status_lines(st, v2, install.plugin_enabled(), chosen), *([install.DEV_MODE_LINE] if dev else []),
              "(tracekit status --json prints all of it)", sep="\n")
        return 0
    if a.cmd == "up":
        from . import install
        from .sdk import autospawn
        from . import public_witness
        if not _signer_extra():
            return 2
        from .signer.service import set_dev_witness
        if a.no_witness:
            set_dev_witness(True)
        if a.replace or a.no_witness:
            autospawn.down()
        conn = autospawn.ensure(wait=a.wait or a.json)
        hello = conn and conn[2]
        if conn:
            conn[0].close()
        if a.json:
            print(json.dumps(hello))
        else:
            print(f"dev signer {hello['version']} running (pid {hello['pid']})" if hello else "dev signer starting")
            print(install.DEV_MODE_LINE)
            if a.wait:   # the data dir a client takes the signer's from (its hello's): read, nothing made there
                print(*_dev_anchoring(autospawn.data_dir(), make=False), sep="\n")
            elif a.no_witness:
                print(public_witness.LOST)
        return 0
    if a.cmd == "down":
        from .sdk import autospawn
        pid = autospawn.down()
        print(f"dev signer stopped (pid {pid})" if pid else "no dev signer running")
        return 0
    if a.cmd == "doctor":
        from . import doctor
        return doctor.main(a.config, a.json, a.k8s, a.manifests, a.issuer_key)
    if a.cmd == "uninstall" and (a.v2 or a.purge):
        from . import install
        if not a.v2 or a.project or a.agent != "claude":
            print("tracekit: --purge goes with --v2, which takes neither --project nor --agent", file=sys.stderr)
            return 2
        try:
            kept = install.uninstall_system_v2(a.purge)
        except install.SettingsError as e:
            print(f"tracekit: {e}", file=sys.stderr)
            return 1
        print("v2 system mode removed" + (f"; kept {' and user '.join(kept)} (--purge deletes them)" if kept else ""))
        return 0
    if a.cmd == "uninstall" and a.agent != "claude":
        path = agent_hooks.install(a.agent, os.getcwd() if a.project else None, uninstall=True)   # says what it removed
        for line in [] if a.project else _kept(path):
            print(line)
        return 0
    if a.cmd == "uninstall":
        from . import install
        try:
            if install.uninstall(os.getcwd() if a.project else None) == "no settings file":   # else it said what it removed
                print("tracekit: no Claude Code settings file, so no hooks to remove")
        except install.SettingsError as e:
            print(f"tracekit: {e}", file=sys.stderr)
            return 1
        for line in [] if a.project else _kept():
            print(line)
        return 0
    if a.cmd == "daemon":
        from . import daemon
        experimental("the v1 signer (tracekitd)")
        return daemon.main(["--home", _signer_home(a)])
    if a.cmd == "proxy":
        from . import proxy
        if not experimental_gate(a.experimental, "the model proxy (tracekit proxy)"):
            return 2
        return proxy.main(["--home", _signer_home(a)] + (["--port", str(a.port)] if a.port is not None else []) +
                          (["--upstream", a.upstream] if a.upstream else []))
    # a v2 id, `[<route>.]apr-` and 32 hex digits (signer/service.py): tracekitd's are hex
    if a.cmd in ("approve", "reject") and re.fullmatch(r"([a-z0-9-]+\.)?apr-[0-9a-f]{32}", a.approval_id or ""):
        return _approvals(argparse.Namespace(action=a.cmd, approval_id=a.approval_id, signer=None, reason=None))
    if a.cmd in ("pending", "approve", "reject"):
        from . import client
        if client.socket_path() == client.DEFAULT_SOCKET \
                and not os.path.exists(client.DEFAULT_SOCKET):   # no v1 signer here: the v2 signer's held calls
            if a.cmd == "pending":
                return _approvals(argparse.Namespace(action="list", signer=None, json=False, all=False))
            if not a.approval_id:
                print(f"tracekit {a.cmd}: name the approval: tracekit {a.cmd} <id> (tracekit pending lists them)",
                      file=sys.stderr)
                return 2
            return _approvals(argparse.Namespace(action=a.cmd, approval_id=a.approval_id, signer=None, reason=None))
        try:
            pend = client.rpc({"op": "approval_list"}).get("pending", [])
            if a.cmd == "pending":
                if not pend:
                    print("no tool calls waiting for approval")
                for x in pend:
                    print(f"{x['id']}  run={x['run_id']}  {x['summary']}  rules={','.join(x['rule_ids'])}  expires in {x['expires_in_s']}s")
                return 0
            aid = a.approval_id
            if not aid:
                if len(pend) != 1:
                    print(f"{len(pend)} pending; name one: tracekit {a.cmd} <id>", file=sys.stderr)
                    return 2
                aid = pend[0]["id"]
                print(f"{a.cmd}: {pend[0]['summary']}")
            else:
                hits = _match_pending(pend, aid)
                if len(hits) > 1:
                    print(f"'{aid}' matches {len(hits)} pending approvals; use more characters of the id", file=sys.stderr)
                    return 2
                if hits:
                    aid = hits[0]["id"]
            r = client.rpc({"op": "approve", "approval_id": aid, "decision": "approve" if a.cmd == "approve" else "reject"})
        except client.SignerUnavailable as e:
            print(f"signer unavailable: {e}", file=sys.stderr)
            return 2
        print(("ok: " + r["decision"]) if r.get("ok") else r.get("error"), file=sys.stdout if r.get("ok") else sys.stderr)
        return 0 if r.get("ok") else 1
    if a.cmd == "approvals":
        return _approvals(a)
    if a.cmd == "grant":
        return _grant(a)
    if a.cmd == "export" and (a.v2 or a.dev or a.data_dir or a.config or a.run_set or a.tenant):   # each names a v2 store
        return _export_v2(a)
    if a.cmd == "last":
        return _last(a)
    if a.cmd == "export":
        from . import bundle
        from .otel import parse_headers
        home = _signer_home(a)
        info = bundle.export(home, a.out, run=a.run, last=not (a.run or a.since), since=a.since, otel=a.otel,
                             otel_endpoint=a.otel_endpoint, otel_headers=parse_headers(a.otel_header))
        print(json.dumps(info, indent=2) if a.json else
              f"wrote {info['path']}: {'run' if len(info['runs']) == 1 else 'runs'} {', '.join(info['runs'])}, "
              f"{info['records']} records, {info['checkpoints']} checkpoint(s)"
              + (f"; spans sent to {a.otel_endpoint}: {info['otel_push']['status']}" if "otel_push" in info else "")
              + f"\nnext, verify it against the signer's key:\n  tracekit verify {_quote(info['path'])} --key "
              + _quote(os.path.join(home, "ledger", "signer.pub")))
        return 0
    if a.cmd == "verify":
        from .verify import is_v2
        v2_flags = a.trust or a.v1_ledger or a.v1_key or a.monitor_report or a.revocations
        v2 = is_v2(a.bundle)
        if v2 or v2 is None and v2_flags:   # an unreadable file given v2's flags: the v2 verifier says what's wrong
            from .verify import v2 as mod
            if a.key or a.witness:
                print("tracekit verify: --key and --witness are for v1 bundles; a v2 bundle is checked against --trust",
                      file=sys.stderr)
                return 2
            if not a.trust:
                print("tracekit verify: a v2 bundle needs --trust: the trust file of the signer that made it, a small "
                      ".json that pins its log key\n"
                      "  your own run: tracekit last writes <run>.trust.json next to the bundle; tracekit signer trust "
                      "-o trust.json writes the dev signer's (--config <signer.yaml> for a configured one)\n"
                      "  someone else's run: get theirs from the sender directly, not from beside or inside the bundle",
                      file=sys.stderr)
                return 2
            if bool(a.v1_ledger) != bool(a.v1_key):
                print("tracekit verify: --v1-ledger and --v1-key go together", file=sys.stderr)
                return 2
            rep, code = mod.verify(a.bundle, a.trust, a.v1_ledger, a.v1_key, a.monitor_report, a.revocations)
            if code == 0 and a.strict and rep.warnings:
                code = 3
            # a level rates only evidence that verified, as the Assurance line says
            integrity, assurance = rep.integrity, mod.NOT_RATED if code == mod.EXIT_FAIL else rep.assurance
        else:
            from .verify import v1 as mod
            if v2_flags:
                print("tracekit verify: --trust, --v1-ledger, --v1-key, --monitor-report and --revocations are for v2 "
                      "bundles; this is not a v2 bundle", file=sys.stderr)
                return 2
            rep, code = mod.verify(a.bundle, a.witness, a.strict, a.key)
            integrity, assurance = mod.integrity(rep, code), mod.assurance(rep)
        if a.json:
            print(json.dumps({"exit_code": code, "checks": rep.checks, "failures": rep.failures, "warnings": rep.warnings,
                              "integrity": integrity, "assurance": assurance, "notes": rep.notes,
                              **({"findings": rep.findings} if getattr(rep, "findings", None) else {})},
                             indent=2))
        elif a.detail:
            mod.print_report(rep, code)
        else:
            from .verify import summary
            summary(rep, code, integrity, assurance)
        return code
    if a.cmd == "policy":
        from .policy2 import compile as policy_compile
        if not (a.policy and (a.store or a.bundle) and not a.file if a.action == "backtest"
                else a.file and not (a.policy or a.store or a.bundle)):
            print("tracekit: `policy compile|lint FILE`, or `policy backtest --policy P (--store DIR | --bundle B...)`",
                  file=sys.stderr)
            return 2
        pol, errors = policy_compile.build(a.policy or a.file)
        for e in errors:
            print(e, file=sys.stderr)
        if errors:
            return 1
        for w in policy_compile.warnings(pol):
            print(f"warning: {w}", file=sys.stderr)
        if a.action == "backtest":
            from .policy2.engine import Engine
            from .signer import detect
            found, other = detect.backtest(Engine(pol), a.store, a.bundle)
            if other:
                print(f"tracekit: warning: {other} decision(s) were made under another policy: the backtest reads the "
                      "rule ids they recorded, so rules and labels this policy adds or changes are not applied to them "
                      "(arguments are not stored); run the policy in shadow on new runs to measure those",
                      file=sys.stderr)
            for typ, tenant, run_id, d in found:
                what = {"incident.opened": f"{d.get('trigger')} {','.join(d.get('rule_ids', ()))} scope "
                                           f"{d.get('scope', {}).get('kind')}",
                        "incident.capped": f"{d.get('cap')} cap ({d.get('trigger')})"}
                print(f"{typ:18} {tenant}/{run_id} {what.get(typ, '')}".rstrip())
            opened = sum(t == "incident.opened" for t, *_ in found)
            print(f"{opened} incident(s) would open" + ("" if detect.Detector.of(Engine(pol)) else
                                                         ": the policy has no sequences, limits or respond triggers"))
            return 0
        if a.action == "compile":
            print(policy_compile.canonical(pol))
            print(f"policy_hash: {policy_compile.policy_hash(pol)}", file=sys.stderr)
        else:
            print(f"ok: {a.file}")
        return 0
    if a.cmd == "migrate":
        from . import migrate
        return migrate.main(a.rest)
    if a.cmd == "demo" and a.why:
        from . import demo_why
        return demo_why.main(keep=a.keep)
    if a.cmd == "demo" and a.server:
        from . import demo_server
        return demo_server.main(keep=a.keep, detail=a.detail)
    if a.cmd == "demo":
        return demo.main(real=a.real, keep=a.keep, agent=a.agent, detail=a.detail)
    return 2


def _left(config):
    """What uninstalling a coding agent's hooks leaves beside its hook config `config`: the copies Tracekit made of a
    file there before changing it (files.backup's name.bak-<time>-<random>), and each such file now empty."""
    d = os.path.dirname(config)
    try:
        baks = sorted(n for n in os.listdir(d) if re.search(r"\.bak-\d{8}-\d{6}-[0-9a-f]{8}$", n))
    except OSError:
        return []
    empty = []
    for p in dict.fromkeys(os.path.join(d, n.rsplit(".bak-", 1)[0]) for n in baks):
        try:
            with open(p, encoding="utf-8") as f:
                text = f.read().strip()
            if not text or json.loads(text) in ({}, {"version": 1}):   # Cursor's hooks.json keeps its version
                empty.append((p, "empty now that Tracekit's entries are out"))
        except (OSError, ValueError):   # gone, or not empty JSON
            pass
    return empty + [(os.path.join(d, n), f"a copy Tracekit made before changing {n.rsplit('.bak-', 1)[0]}")
                    for n in baks]


def _kept(agent_config=None):
    """What `tracekit uninstall` leaves in place (the dev signer's keys and signed runs, the client config, the dev
    signer's runtime dir, a v1 dev signer's home, and what is _left of `agent_config`, a coding agent's hook config),
    each that exists, and the commands that delete them and Tracekit."""
    from . import client
    from .sdk import autospawn
    try:
        system, unread = client.system_config() is not None, None
    except client.SystemConfigError as e:   # one that can't be read is still system mode's
        system, unread = True, e
    cfg = {} if system else client.client_config()   # never read again: a broken one would raise there
    data = autospawn.data_dir()
    mine, shared = autospawn.own_runtime_dirs()
    where = [(data, "the dev signer's keys and signed runs: a bundle you exported verifies without them"),
             (client.client_home(), "Tracekit's client config"),
             # as uninstall() stops it: a dev home only, never system mode's signer home (/var/lib/tracekit)
             (cfg.get("signer_home") if cfg.get("mode") == "dev" else None, "the v1 dev signer's home"),
             *[(d, "the dev signer's runtime dir") for d in mine]]
    where = [(d, what) for d, what in where if d and os.path.isdir(d)] + (_left(agent_config) if agent_config else [])
    note = [f"{unread}, so this lists only your own files"] if unread else []
    if not where:
        return note
    paths = [d for d, _ in where]
    if sys.platform == "darwin":   # data/ and run/ in Tracekit's own Application Support dir (autospawn.data_dir)
        paths.insert(0, os.path.dirname(data))
    # a dir inside another one the command deletes isn't named again (Windows' run\ is inside its data dir)
    paths = [d for d in paths if not any(d.startswith(p + os.sep) for p in paths)]
    def ps(path):   # Windows: a PowerShell literal, '...' with each character it reads as a single quote doubled
        return "'" + re.sub("(['‘’‚‛])", r"\1\1", path) + "'"
    pip = ("uv tool uninstall" if re.search(r"[/\\]uv[/\\]tools[/\\]", sys.executable) else   # as claude_code.upgrade
           "pipx uninstall" if re.search(r"[/\\]pipx[/\\]venvs[/\\]", sys.executable) else
           f"& {ps(sys.executable)} -m pip uninstall" if os.name == "nt" else   # & runs a quoted program
           f"{_quote(sys.executable)} -m pip uninstall")
    # -LiteralPath: -Path reads [ ] * ? in a name as wildcards
    remove = (f"Remove-Item -Recurse -Force -LiteralPath {', '.join(map(ps, paths))}" if os.name == "nt"
              else f"rm -rf {' '.join(map(_quote, paths))}")
    return note + (["kept:"] + [f"  {d}  ({what})" for d, what in where]
            + [f"  runtime files under {shared} may be shared with another HOME's dev signer: run tracekit down first, "
               "and delete only what is yours"] * bool(shared)
            + ["to delete these and Tracekit too:", "  tracekit down", f"  {remove}", f"  {pip} tracekit-ai"])


def _status_lines(st, v2, plugin=None, chosen=False):
    """`tracekit status` for a person: the v2 signer (install.status's and autospawn.status's findings), where its
    keys and runs are, the hooks (and the Claude Code plugin's, `plugin`: install.plugin_enabled's; `chosen`: init
    --no-hooks chose none), then a v1 signer and proxy when there is one."""
    name = "dev signer" if v2.get("dev") else "signer"
    lines = [f"signer      {name} {v2['version']}, running (pid {v2['pid']}), socket {v2['socket']}" if "version" in v2
             else f"signer      {name}: {v2.get('error') or 'running'}"]
    if v2.get("data_dir"):
        lines.append(f"data        {v2['data_dir']} (its keys and signed runs)")
    found = [f"hooks       v2 hooks for {h['agent']} in {h['settings']}" if "agent" in h else
             f"hooks       {' and '.join(h['versions'])} hooks in {h['settings']} ({len(h['events'])} events)"
             for h in st["hooks"] if h.get("versions")]
    lines += [f"hooks       {h['settings']} isn't a settings file Tracekit can read, so its hooks are unknown"
              for h in st["hooks"] if "error" in h]
    if plugin:   # its hooks are the ones init writes, and init writes none while it is on
        found.append(f"hooks       the Claude Code plugin {plugin[1]}'s, enabled in {plugin[0]}")
    lines += found or ([] if any("error" in h for h in st["hooks"]) else   # unknown, not none
                       ["hooks       none, as init --no-hooks chose: SDK runs (tracekit.instrument()) are still "
                        "recorded; init without --no-hooks adds Claude Code's" if chosen else
                        "hooks       none in Claude Code's settings: tracekit init --dev --v2 adds them"])
    if st.get("signer"):   # its error is a problem only for v1 hooks, which use it (or may, in a file it can't read)
        v1 = any("v1" in h.get("versions", ()) or "error" in h for h in st["hooks"])
        lines.append("v1 signer   " + ("answering" if not st["signer"].get("error") else st["signer"]["error"] if v1
                                       else "not running (only v1 hooks use it)"))
    if st.get("proxy"):
        lines.append(f"proxy       {st['proxy']['url']}: {'reachable' if st['proxy']['reachable'] else 'unreachable'}")
    return lines


def _signer_extra():
    """True when the v2 signer's policy engine imports; else says how to install it."""
    from .policy2 import engine
    try:
        engine._backend(None)
    except ImportError:
        print("tracekit: the v2 signer needs its policy engine (google-re2 or regex), which a --no-deps install "
              "leaves out: pip install tracekit-ai", file=sys.stderr)
        return False
    return True


def _export_v2(a, show=print):
    """`tracekit export --v2`: read the store without its lock, with the newest checkpoint note. When none covers the
    run's last record yet, nudge the running signer and wait up to NUDGE_WAIT_S for one. `show` gets what it says
    it wrote (_exported)."""
    import time

    from .bundle_v2 import about as about_run
    from .bundle_v2 import export
    from .format import registry
    from .sdk.client import Client, Incompatible, SignerUnavailable
    from .signer.rpc_schema import RPCError
    from .signer.service import reader as open_reader
    from .signer.service import signer_config
    from .storage.base import StorageCorrupt, StorageUnavailable, registry_tree
    if not (a.run or a.run_set) or (a.dev, bool(a.config), bool(a.data_dir)).count(True) > 1:
        print("tracekit export --v2: needs --run RUN_ID or --run-set, and one of --dev, --config or --data-dir at most",
              file=sys.stderr)
        return 2
    reader = None

    def reopen():   # a reader opened now holds every record and note written before
        nonlocal reader
        if reader:
            reader.close()
        reader = open_reader(cfg)
    try:
        cfg = signer_config(a.config, a.data_dir)
        tenant = a.tenant or cfg.get("tenant", "default")
        reopen()
        if a.run_set:
            with open(os.path.join(cfg["data_dir"], "keys", "registry_salt.key"), "rb") as f:
                tsalt = registry.tenant_salt(f.read(), tenant)
            for _ in range(5):   # a reader opened after reading the record note holds the registry notes it covers
                note = reader.checkpoint_latest()
                reopen()
                if reader.checkpoint_latest() == note:
                    break
            reg = reader.checkpoint_latest(registry_tree(tenant))
            if note is None or reg is None:
                raise ValueError(f"no registry checkpoint of tenant {tenant!r} in the store yet")
            info = export(reader, tenant, a.run, note[1], a.out, run_set=(0, reg[0]), tenant_salt=tsalt,
                          policy_dir=os.path.join(cfg["data_dir"], "policies"))
            show(_exported(a, info, f"the run-set of tenant {tenant}: {info['runs']} runs, "
                                    f"{info['registry_leaves']} registry leaves"))
            return 0
        run = reader.runs.get((tenant, a.run))
        if run is None:
            raise ValueError(f"no run {a.run!r} of tenant {tenant!r} in the store")
        about = about_run(reader, tenant, a.run) if a.with_findings else []
        last = max(reader.runs[(tenant, r)]["seqs"][-1] for r in [a.run, *about])

        def signers(n):
            return {line.split(" ")[1] for line in n.split("\n\n", 1)[1].splitlines()}

        def covering():   # the newest anchored note covering the run with every cosigner of the newest note, else that
            note = reader.checkpoint_latest()
            for x in reader.anchors()[-1:]:
                if x["size"] > last and note and x["size"] < note[0] and signers(x["note"]) >= signers(note[1]):
                    return x["size"], x["note"]
            return note if note and note[0] > last else None
        note = covering()
        if note is None:
            if a.data_dir:
                raise ValueError(f"no checkpoint covers run {a.run!r} yet, and a data dir names no signer to ask for "
                                 "one: export again after its signer's next checkpoint, or with --config or --dev")
            try:
                if a.config and not cfg.get("socket"):
                    raise SignerUnavailable("the config names no socket")
                c = Client(cfg["socket"] if a.config else None, timeout=NUDGE_WAIT_S)   # None: the dev signer
                try:
                    c.checkpoint_nudge({})
                finally:
                    c.close()
            except (SignerUnavailable, Incompatible, RPCError) as e:
                raise ValueError(f"no checkpoint covers run {a.run!r} yet and no signer answered to write one ({e}); "
                                 "start the signer and export again") from None
            deadline = time.monotonic() + NUDGE_WAIT_S
            while (note := covering()) is None and time.monotonic() < deadline:
                time.sleep(0.1)
                reopen()
            if note is None:
                raise ValueError(f"the signer wrote no checkpoint covering run {a.run!r} within {NUDGE_WAIT_S:g}s")
        reopen()   # opened after the note: holds its records
        info = export(reader, tenant, a.run, note[1], a.out, with_runs=about,
                      policy_dir=os.path.join(cfg["data_dir"], "policies"))
        if a.otel or a.otel_endpoint:
            info["otel"] = _otel_v2(a, info["bundle"])
    except (OSError, ValueError, SignerUnavailable, StorageCorrupt, StorageUnavailable) as e:
        print(f"tracekit export: {e}", file=sys.stderr)
        return 1
    finally:
        if reader:
            reader.close()
    show(_exported(a, info, f"run {a.run}" + (f" and {len(about)} findings or replay run(s) about it" if about else "")))
    return 0


def _exported(a, info, what):
    """What `tracekit export --v2` says it wrote (info: bundle_v2.export's summary): the bundle, `what` it holds and
    the commands that verify it; with --json, info itself, for scripts."""
    if a.json:
        return json.dumps(info, indent=2)
    where = f" --config {_quote(a.config)}" if a.config else f" --data-dir {_quote(a.data_dir)}" if a.data_dir else ""
    out = _quote(info["bundle"])
    return (f"wrote {info['bundle']}: {what}, {info['records']} records; a verifier needs tracekit "
            f"{info['verifier_min_version']} or newer\n" + (f"spans: {info['otel']}\n" if info.get("otel") else "")
            + "next, pin the signer's log key and verify the bundle against it:\n"
              f"  tracekit signer trust{where} -o trust.json\n  tracekit verify {out} --trust trust.json")


def _quote(path):
    """`path` as one argument of a command line the user can paste (spaces in a profile dir, Windows backslashes)."""
    import shlex
    import subprocess
    return subprocess.list2cmdline([path]) if os.name == "nt" else shlex.quote(path)


def _last(a):
    """`tracekit last`: the dev signer's most recent finished run, exported, checked against a trust config that pins
    the dev signer's own log key (dev assurance: the same user holds that key), and verified. A newer run that is
    closing is waited for, up to LAST_WAIT_S; a newer one still open is named and skipped, or with --open taken as it
    stands."""
    import argparse
    import collections
    import time

    from .signer.pipeline import SIGNER_RUN
    from .signer.service import read_vkeys, reader as open_reader, signer_config
    from .storage.base import StorageCorrupt, StorageUnavailable
    from .verify import v2
    from .view import write_trust
    from .sdk.autospawn import data_dir
    deadline, waiting = time.monotonic() + LAST_WAIT_S, False
    store = os.path.join(data_dir(), "store")   # named when there is none yet
    try:
        cfg = signer_config(None)
        while True:
            r = open_reader(cfg)
            try:   # newest first, by their last record; each with the type of that record and its agent's name
                runs = []
                for _, key in sorted(((run["seqs"][-1], key) for key, run in r.runs.items() if key[1] != SIGNER_RUN[1]),
                                     reverse=True):
                    first = next(iter(r.iter_run(*key)))["event"]
                    runs.append((key, collections.deque(r.iter_run(*key), 1)[0]["event"]["type"],
                                 ((first.get("data") or {}).get("agent") or {}).get("name") or "?"))
                    if runs[-1][1] == "run.final":
                        break
            finally:
                r.close()
            if not (runs and runs[0][1] == "run.closing" and time.monotonic() < deadline):
                break
            if not waiting:
                print(f"tracekit last: run {runs[0][0][1]} ({runs[0][2]}) just closed; waiting up to {LAST_WAIT_S:g} s "
                      "while the signer finalises it", file=sys.stderr)
                waiting = True
            time.sleep(0.25)   # the signer finalises a closed run once its grace window has passed
    except FileNotFoundError:
        runs = []
    except (OSError, ValueError, StorageCorrupt, StorageUnavailable) as e:
        print(f"tracekit last: cannot read the dev signer's store: {e}", file=sys.stderr)
        return 1
    final = [x for x in runs if x[1] == "run.final"]
    for (_, run_id), kind, agent in [] if a.open else runs[:len(runs) - len(final)]:
        if kind == "run.closing":
            why = "closed, and not finalised yet: is the dev signer still running (`tracekit up`)?"
        elif agent == "claude-code":
            why = ("still open: it finishes when the session ends (`/exit` in Claude Code) "
                   "or after the signer's idle timeout; tracekit last --open verifies it as it stands")
        elif agent in ("opencode", "kilo", "goose", "antigravity"):   # their hooks get no session end
            why = (f"still open: Tracekit's {agent} hooks get no session end, so it finishes after the signer's idle "
                   "timeout; tracekit last --open verifies it as it stands")
        elif agent == "cline":   # a run is one task (agent_hooks: TaskComplete ends it)
            why = ("still open: it finishes when the Cline task completes, or after the signer's idle timeout (a "
                   "cancelled task sends no hook); tracekit last --open verifies it as it stands")
        elif agent in agent_hooks.AGENT_NAMES.values():
            why = ("still open: it finishes when the session ends "
                   "or after the signer's idle timeout; tracekit last --open verifies it as it stands")
        else:
            why = ("still open: it finishes when the agent's process exits (tracekit.instrument() closes its run "
                   "then) or after the signer's idle timeout; tracekit last --open verifies it as it stands")
        print(f"tracekit last: the newer run {run_id} ({agent}) is {why}" + (
            "; showing the run before it" if final else "; run tracekit last again once it has finished"),
            file=sys.stderr)
    pick = runs if a.open else final
    if not pick:
        if not runs:
            print(f"tracekit last: no runs in the dev signer's store ({store}) yet. `tracekit.instrument()` records "
                  "only the frameworks it lists, and says so when it finds none of them "
                  f"({wiki_url('docs/quickstart-v2.md', '2-one-line-in-your-agent')}); for any other agent, record "
                  f"its calls as {wiki_url('docs/quickstarts/custom.md')} shows. Claude Code: a session started after "
                  "`tracekit init --dev --v2` records its calls.", file=sys.stderr)
        return 1
    (tenant, run_id), _, agent = pick[0]
    out = os.path.abspath(a.out or f"{run_id}.tkb")
    ns = argparse.Namespace(run=run_id, run_set=False, dev=True, config=None, tenant=tenant, out=out, otel=False,
                            otel_endpoint=None, with_findings=False, json=False, data_dir=None)
    if _export_v2(ns, show=lambda s: None):
        return 1
    try:
        trust = write_trust(os.path.splitext(out)[0] + ".trust.json", read_vkeys(cfg["data_dir"]),
                            cfg.get("witnesses") or ())
    except (OSError, ValueError) as e:
        print(f"tracekit last: cannot pin the dev signer's key: {e}", file=sys.stderr)
        return 1
    rep, code = v2.verify(out, trust)
    print(f"run {run_id} ({agent})")
    if a.detail:
        v2.print_report(rep, code)
    else:
        from .verify import summary
        summary(rep, code, rep.integrity, rep.assurance)
    print(f"bundle: {out}\ncheck it again: tracekit verify {_quote(out)} --trust {_quote(trust)}\n"
          "next: tracekit view --dev   (every run, replayed and reviewed)")
    return code


def _otel_v2(a, bundle):
    """The OTLP/JSON spans of the runs in v2 bundle `bundle`, written to <bundle name>.otel.json and with
    --otel-endpoint sent there; returns the file's path."""
    import zipfile

    from .bundle_v2 import run_files
    from .otel import parse_headers, push
    from .signer.otel import payload
    with zipfile.ZipFile(bundle) as z:
        doc = {"resourceSpans": [rs for parts in run_files(z.namelist()).values() for rs in payload(
            [json.loads(line) for n in parts for line in z.read(n).splitlines()])["resourceSpans"]]}
    path = os.path.splitext(bundle)[0] + ".otel.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f)
    if a.otel_endpoint:
        status, body = push(a.otel_endpoint, doc, headers=parse_headers(a.otel_header))
        if status >= 300:
            raise ValueError(f"{a.otel_endpoint} answered HTTP {status}: {body[:200]}")
    return path


def _self_approved(state, dev):
    """What `approvals approve|reject` adds to an answer the signer recorded `self_approved`, one from the call's own
    requester (docs/approvals.md#who-may-answer): an approval counts, and why it is labelled; either answer keeps the
    run's assurance at dev (the verifier counts both). `dev`: the same-user dev signer answered (no named signer)."""
    if state != "approved":
        return ", by you, recorded as self-approved (an answer from the call's own requester): the run's assurance stays dev"
    why = ("the dev signer runs as your own user and can't tell you from your agent" if dev else
           "this signer lets the call's own requester answer (a dev signer, or approvals: {self_approval: allow} in its "
           "signer.yaml)")
    return (f", by you. It counts: {why}, so it records this as self-approved, and the run's assurance stays dev."
            + (" A signer started from signer.yaml refuses an approval from the call's own requester unless that file "
               "sets approvals: {self_approval: allow}." if dev else ""))


def _args(x):
    """The arguments of approval `x` (approval_get), decoded: None once it is no longer live."""
    from .format.canon import loads_strict
    return loads_strict(x["args"]) if x["args_source"] == "raw" and x["args"] is not None else x["args"]


def _gist(c, aid, n=60):
    """The call approval `aid` holds, in at most `n` characters: its command, file path or URL, else its arguments as
    JSON, from the signer's copy; "" when the signer gives none."""
    from .signer.rpc_schema import RPCError
    try:
        args = _args(c.approval_get({"approval_id": aid}))
    except RPCError:   # answered or gone since it was listed
        return ""
    if args is None:
        return ""
    v = next((args[k] for k in ("command", "file_path", "path", "url") if isinstance(args, dict)
              and isinstance(args.get(k), str)), None)
    text = " ".join((json.dumps(args) if v is None else v).split())
    return text if len(text) <= n else text[:n - 3] + "..."


def _expires_left(x):
    """How long approval `x` has left, as `show` and `list` print it: ` (in 55 min)` while it is requested or approved,
    ` (3 min ago)` once its time passed; nothing for one rejected, consumed or abandoned before then, whose expiry no
    longer counts. Another signer's time format is left as it is."""
    import datetime
    try:
        left = (datetime.datetime.strptime(x["expires_at"], "%Y-%m-%dT%H:%M:%S.%fZ")
                .replace(tzinfo=datetime.timezone.utc) - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    except ValueError:   # another signer's time format: as it is
        return ""
    if left < 0:
        return f" ({-left // 60:.0f} min ago)"
    return f" (in {left // 60:.0f} min)" if x["state"] in ("requested", "approved") else ""


def _stop_lines(c, x):
    """What `approvals show` adds to approval `x`: why its call was held and what to do instead (the reasons and
    remedies of its rules, in the policy whose hash it records: a shipped pack's, or one the dev signer kept), when
    it expires, the commands that answer it and where the viewer opens it."""
    from . import view
    from .integrations.claude_code import approvals_cmd
    from .policy2.compile import ENGINE_REASONS
    from .policy2.engine import Engine
    from .signer.service import dev_data_dir
    try:
        kept = None if c.signer else os.path.join(dev_data_dir(create=False), "policies")
    except FileNotFoundError:
        kept = None
    reasons = view.policy_reasons(kept=kept)
    known = reasons.get(x["policy_hash"], {})
    pol = reasons.policies.get(x["policy_hash"], {})
    flags = {r["id"] for r in pol.get("flag", [])}   # a flagged call runs
    engine = dict(ENGINE_REASONS)
    if "TK-SHELL-PARSE" in x["rule_ids"] and pol and x["args"] is not None:
        # the cause the signer gave the hook (its decision's `unread`), from the same engine on the signer's copy
        try:
            cause = Engine(pol).decide(x["tool"], _args(x)).get("unread")
        except Exception:   # as the signer's _evaluate: an engine error here leaves the general reason
            cause = None
        engine["TK-SHELL-PARSE"] = ENGINE_REASONS["TK-SHELL-PARSE"]["causes"].get(cause) or engine["TK-SHELL-PARSE"]
    rules = [(i, known.get(i) or engine.get(i) or {"reason": view.ENGINE_RULES.get(i, "")})
             for i in x["rule_ids"] if i != "TK-UNKNOWN-TOOL" and i not in flags]
    why = "; ".join(f"{r['reason']} ({i})" for i, r in rules if r.get("reason"))
    instead = " ".join(dict.fromkeys(r["remedy"] for _, r in rules if r.get("remedy")))
    left = _expires_left(x)
    cmd = approvals_cmd(c.signer)
    why = why or ("not on this machine: `tracekit policy compile <file>` prints the reasons of the signer's policy, "
                  + x["policy_hash"])
    # Claude Code runs a `!` line in the session as its OS user: the person's, with the dev signer (as the hook says)
    bang = not c.signer and _claude_code_run(x["run_id"])
    return [f"why         {why}",
            *([f"instead     {instead}"] if instead else []),
            f"expires     {x['expires_at']}{left}",
            *([f"answer      `{cmd} approve {x['approval_id']}` to allow it once, `{cmd} reject {x['approval_id']}` "
               "to refuse it" + ("; in the agent's Claude Code session, with a leading `! `" if bang else "")]
              if x["state"] == "requested" else []),
            *_grant_hint(x, reasons.policies.get(x["policy_hash"], {}), flags, cmd),
            f"record      tracekit view --approval {x['approval_id']}"
            + (" (with the --config or --data-dir of this signer)" if c.signer else ""),
            f"a false alarm? tracekit feedback --harmless {x['approval_id']}{cmd.removeprefix('tracekit approvals')}"]


def _claude_code_run(run_id):
    """Whether run `run_id` is a Claude Code session's on this machine: the v2 hook keeps each session's run in its
    state in the dev signer's runtime dir (integrations.claude_code._state)."""
    import glob

    from .sdk import autospawn
    try:
        d = autospawn.runtime_dir(create=False)
    except (OSError, autospawn.SignerUnavailable):
        return False
    for f in glob.glob(os.path.join(glob.escape(d), "claude-code-*.json")):
        try:
            with open(f, encoding="utf-8") as fh:
                if json.load(fh).get("run_id") == run_id:
                    return True
        except (OSError, ValueError, AttributeError):   # one a hook is replacing, or not a state file
            continue
    return False


def _grant_hint(x, pol, flags, cmd):
    """What `approvals show` says about granting calls like held call `x` (docs/intent-grants.md), when every rule that
    held it opts into a grant in its policy `pol`: how the grant reads the call, and a command that approves it and
    grants the run more like it, with limits from this call for the person to edit; [] otherwise."""
    from . import grants
    opted = {r["id"]: (r.get("approval") or {}).get("grant") for r in pol.get("ask", [])}
    intents = {opted.get(i) for i in x["rule_ids"] if i not in flags}
    if x["state"] != "requested" or len(intents) != 1 or None in intents:
        return []
    fields, why = grants.read(intents.pop(), _args(x))
    if fields is None:
        return [f"grant       a payment grant can't read this call ({why}): approve it on its own"]
    amount, cur = grants.show(fields["amount"], fields["currency"]), fields["currency"]
    line = f"grant       a payment grant reads it as {amount} to {json.dumps(fields['payee'])}"
    if cur not in grants.DECIMALS:
        return [line + f"; tracekit doesn't know {cur}'s minor units, so approve it on its own"]
    return [line + "; to approve it and let more payments like it run, set your own limits:",
            f"            {cmd} approve {x['approval_id']} --grant --payee {fields['payee']} --max '{amount}' "
            f"--total '{grants.show(fields['amount'] * 5, cur)}' --for 1h"]


def _approvals(a):
    """`tracekit approvals`. Strings an agent chose (tool, args, reason) are printed JSON-escaped, never raw."""
    import pydoc

    from .sdk.client import Client, Incompatible, SignerUnavailable
    from .signer.rpc_schema import RPCError
    if a.action == "slack":
        from . import slack_approvals
        experimental("the Slack approvals bridge")
        return slack_approvals.main(a.config)
    c = Client(a.signer)
    try:
        if a.action == "list":
            page, approvals = {"next_cursor": None}, []
            while True:
                page = c.approval_list({"cursor": page["next_cursor"]} if page["next_cursor"] else {})
                approvals.extend(page["approvals"])
                if page["next_cursor"] is None:
                    break
            # the live ones (still waiting for an answer) first, newest first: an approval expires a fixed time after
            # it was requested; the expired ones only with --all
            shown = sorted((x for x in approvals if a.all or x["state"] != "expired"),
                           key=lambda x: (x["state"] == "requested" and not x.get("run_closing"), x["expires_at"]),
                           reverse=True)
            for x in [] if a.json else shown:
                state = x["state"] + (" (run closing: expires with it)" if x.get("run_closing") else "")
                print(f"{x['approval_id']}  {state}  run={x['run_id']}  tool={json.dumps(x['tool'])}  "
                      f"rules={','.join(x['rule_ids'])}  expires {x['expires_at']}{_expires_left(x)}" + (
                          f"  {json.dumps(_gist(c, x['approval_id']))}" if x["state"] in ("requested", "approved")
                          else ""))
            if a.json:
                print(json.dumps(approvals))
            elif len(shown) < len(approvals):
                print(f"({len(approvals) - len(shown)} expired, not shown: list them with --all)")
            elif not approvals:
                try:
                    me = "{scheme}:{subject}".format(**c.status({})["identity"])
                except (RPCError, SignerUnavailable):
                    me = "this identity"
                print(f"no approvals to show\n(you are {me}: the signer lists an approval only to its run's "
                      "owner and to those who may answer it, which with an approvals section in signer.yaml are the "
                      "identities approvals.approvers lists)")
        elif a.action == "show":
            x = c.approval_get({"approval_id": a.approval_id})
            args = _args(x)
            if a.json:
                print(json.dumps({**x, "args": args}))
                return 0
            lines = [f"approval    {x['approval_id']} ({x['state']})", f"tool        {json.dumps(x['tool'])}",
                     *_stop_lines(c, x), f"rules       {', '.join(x['rule_ids'])}", f"policy      {x['policy_hash']}",
                     f"requester   {json.dumps(x['requester'])}", f"run         {x['run_id']}",
                     f"call        {x['tool_call_id']} attempt {x['attempt']}",
                     f"binding     {x['binding_digest']}", "arguments (the signer's copy, in full):",
                     json.dumps(args, indent=2) if x["args"] is not None else "  (deleted: the approval is no longer live)"]
            if "reason" in x:
                lines.append(f"reason given by the agent (unverified): {json.dumps(x['reason'])}")
            pydoc.pager("\n".join(lines) + "\n")
        else:
            if getattr(a, "grant", False):   # the grant first: if the signer refuses it, nothing is approved
                experimental(GRANTS)
                g = _grant_req(a, c.approval_get({"approval_id": a.approval_id})["run_id"], a.approval_id)
                print(_grant_issued({**c.grant_issue(g), "limits": g["limits"]}, c.signer is None))
            req = {"approval_id": a.approval_id, "decision": a.action, **({"reason": a.reason} if a.reason else {})}
            r = c.approval_decide(req)
            print(f"{r['state']}: {r['approval_id']}"
                  + (_self_approved(r["state"], c.signer is None) if r["self_approved"] else ""))
    except (SignerUnavailable, Incompatible) as e:
        print(f"signer unavailable: {e}", file=sys.stderr)
        return 2
    except RPCError as e:
        print(f"tracekit approvals: {e}", file=sys.stderr)
        return 1
    except ValueError as e:   # a grant flag that doesn't read (an amount, a duration)
        print(f"tracekit approvals: {e}", file=sys.stderr)
        return 2
    finally:
        c.close()
    return 0


def _grant_flags(q, required):
    """The flags that say a payment grant's limits, on `grant add` and `approvals approve --grant`."""
    q.add_argument("--tool", action="append", required=required, help="a tool whose calls the grant covers, as the "
                   "policy names it (mcp__payments__send_money); repeat it for each. From a held call, its tool is "
                   "one already")
    q.add_argument("--payee", action="append", required=required, help="a payee the agent may pay (repeat it for "
                   "each); the grant holds a payment to anyone else")
    q.add_argument("--total", required=required, help="the most all its payments add up to, such as '500 USDC'")
    q.add_argument("--max", help="the most one payment may be, such as '200 USDC' (default: the total)")
    q.add_argument("--count", type=int, help="the most payments it releases")
    q.add_argument("--for", dest="for_", default="1h", help="how long it lasts: 30m, 4h, at most 24h (default 1h)")
    q.add_argument("--note", help="your own words for what it is for, shown on every hold")


def _grant_req(a, run_id, approval_id=None):
    """The grant_issue request the grant flags of `a` say, for run `run_id` (ValueError when one doesn't read)."""
    import datetime

    from . import grants
    if not a.payee or not a.total:
        raise ValueError("a grant names its payees (--payee, one each) and its total (--total '500 USDC')")
    total, cur = grants.parse_amount(a.total)
    caveats = [{"field": "currency", "op": "==", "value": cur},
               {"field": "payee", "op": "in", "value": list(dict.fromkeys(a.payee))}]
    if a.max:
        most, other = grants.parse_amount(a.max)
        if other != cur:
            raise ValueError(f"--max is in {other} and --total in {cur}: a grant has one currency")
        caveats.append({"field": "amount", "op": "<=", "value": most})
    if a.count is not None and a.count < 1:
        raise ValueError("--count is at least 1")
    until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=grants.parse_for(a.for_))
    return {"run_id": run_id, "intent": "payment.send", "caveats": caveats,
            "limits": [{"op": "sum", "field": "amount", "max": total}]
            + ([{"op": "count", "max": a.count}] if a.count else []),
            "expires_at": until.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), **({"approval_id": approval_id} if approval_id else {}),
            **({"tools": list(dict.fromkeys(a.tool))} if a.tool else {}),
            **({"description": a.note} if a.note else {})}


def _grant_issued(r, dev):
    """What `grant add` and `approvals approve --grant` print for grant `r` the signer issued (its response, with the
    limits asked for); `dev`: the same-user dev signer issued it."""
    from . import grants
    g = r["grant"]
    return (f"grant {r['grant_id']} issued for run {g['issuer']['run']}: payments through "
            f"{', '.join(json.dumps(t) for t in r['tools'])} {grants.words(g, r['limits'], r['used'])}, "
            f"until {g['expires_at']}" + ("" if not r["self_approved"] else
                                          ". Recorded as self-approved: " + ("the dev signer runs as your own user and "
                                                                             "can't tell you from your agent" if dev else
                                                                             "you are the run's own user")))


def _grant(a):
    """`tracekit grant add|list|revoke` (docs/intent-grants.md). Strings an agent chose are printed JSON-escaped."""
    from . import grants
    from .sdk.client import Client, Incompatible, SignerUnavailable
    from .signer.rpc_schema import RPCError
    experimental(GRANTS)
    c = Client(a.signer)
    try:
        if a.action == "add":
            req = _grant_req(a, a.run)
            print(_grant_issued({**c.grant_issue(req), "limits": req["limits"]}, c.signer is None))
        elif a.action == "list":
            gs = c.grant_list({"run_id": a.run} if a.run else {})["grants"]
            if a.json:
                print(json.dumps(gs))
            for x in [] if a.json else gs:
                g = x["grant"]
                who = "self-approved (the run's own user, which the agent can be)" if x["self_approved"] else \
                    f"by {g['issuer'].get('person') or g['issuer']['id']}"
                print(f"{x['grant_id']}  {x['state']}  run={x['run_id']}  {g['intent'].split('@')[0]}  "
                      f"tools={','.join(json.dumps(t) for t in x['tools'])}  {who}  "
                      f"{grants.words(g, x['limits'], x['used'])}  until {g['expires_at']}"
                      + (f"  {json.dumps(x['description'])}" if x.get("description") else ""))
            if not gs and not a.json:
                print("no grants in the open runs you may see")
        else:
            r = c.grant_revoke({"grant_id": a.grant_id, **({"reason": a.reason} if a.reason else {})})
            print(f"revoked: {r['grant_id']} (run {r['run_id']}): its calls are held again")
    except (SignerUnavailable, Incompatible) as e:
        print(f"signer unavailable: {e}", file=sys.stderr)
        return 2
    except RPCError as e:
        print(f"tracekit grant: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"tracekit grant: {e}", file=sys.stderr)
        return 2
    finally:
        c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
