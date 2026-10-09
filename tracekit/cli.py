"""tracekit command line."""
import argparse
import getpass
import json
import os
import sys

from . import __version__

NUDGE_WAIT_S = 5.0


def experimental_gate(enabled, what):
    """Experimental servers run only with --experimental, and always say they are being rebuilt."""
    if not enabled:
        print(f"tracekit: {what} is experimental and off by default; pass --experimental to run it", file=sys.stderr)
        return False
    print(f"tracekit: warning: {what} is experimental and being rebuilt; do not rely on it", file=sys.stderr)
    return True


def _signer_home(a):
    from . import client
    return a.home or client.client_config().get("signer_home") or "/var/lib/tracekit"


_DELEGATED = {"observe": "observe", "analyze": "findings", "otel": "otlp", "cost": "cost", "witness": "witness_server",
              "signer": "signer.service", "view": "view"}  # subcommands with their own parsers
_MOVED = {"sql": "query", "proofpack": "proofpack", "report": "proofpack", "causeway": "causeway"}  # now separate packages under contrib/


def main(argv=None):
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
        return importlib.import_module(f".{_DELEGATED[args[0]]}", __package__).main(args[1:])
    ap = argparse.ArgumentParser(prog="tracekit", description="Signed, checkpointed evidence of what coding agents did.")
    ap.add_argument("--version", action="version", version=f"tracekit {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="command")

    p = sub.add_parser("init", help="install the signer and Claude Code hooks")
    p.add_argument("--remote", metavar="URL", help="SDK agent on another machine: send events to this ingest gateway (docs/remote-ingest.md)")
    p.add_argument("--token-file", help="with --remote: file holding the client token (or set TRACEKIT_REMOTE_TOKEN)")
    p.add_argument("--dev", action="store_true", help="same-user signer (no root; weaker: the agent could rewrite the ledger)")
    p.add_argument("--home", help="signer home (dev mode)")
    p.add_argument("--v2", action="store_true", help="with --dev: wire the Claude Code hook of the v2 signer (it starts "
                                                     "on first use)")
    p.add_argument("--project", action="store_true", help="hooks in ./.claude/settings.json instead of ~/.claude")
    p.add_argument("--no-hooks", action="store_true")
    p.add_argument("--witness", action="append", default=[], help="file:/path.jsonl or git:/clone[@remote] (repeatable)")
    p.add_argument("--checkpoint-every", type=int, default=50)
    p.add_argument("--user", help="system mode: the user whose agents are traced (default: $SUDO_USER)")
    p.add_argument("--no-service", action="store_true", help="system mode: do not install systemd/launchd")
    p.add_argument("--experimental-macos", action="store_true", help="allow system mode on macOS (not yet validated on hardware)")
    p.add_argument("--proxy", action="store_true", help="also run the model proxy and point Claude Code at it (C3; needs --experimental)")
    p.add_argument("--experimental", action="store_true", help="allow experimental surfaces (--proxy)")
    p.add_argument("--proxy-port", type=int, default=8787)
    p.add_argument("--fail-closed", action="store_true", help="proxy: refuse to forward when the signer can't record")
    p.add_argument("--managed", action="store_true", help="system mode: install hooks in Claude Code's admin-managed settings")
    p.add_argument("--managed-only", action="store_true", help="with --managed: also set allowManagedHooksOnly")
    p.add_argument("--agent", choices=("claude", "codex", "cursor", "gemini"), default="claude",
                   help="which coding agent's hooks to install (default: Claude Code)")
    p.add_argument("--harness", action="append", default=[], metavar="[NAME=]PATH",
                   help="system mode (0.3): the agent program whose processes may send events, e.g. /usr/local/bin/claude "
                        "(repeatable; must be root-owned). Default: the agent's CLI on PATH if installed root-owned")
    p.add_argument("--signer-cmd", help="external signer helper command (TPM/HSM/enclave; see tracekit/extsigner.py)")
    p.add_argument("--signer-pub", help="with --signer-cmd: the helper key's raw 32-byte Ed25519 public key file")
    p.add_argument("--key-assurance", default="external", help="with --signer-cmd: where the key lives (tpm, hsm, tee, kms, smartcard)")
    p.add_argument("--i-understand-agent-is-privileged", dest="allow_privileged", action="store_true",
                   help="system mode: trace a user that is root or in a sudo/wheel/admin/docker/tracekit group anyway")
    p.add_argument("--key-attestation", help="with --signer-cmd: the device's attestation document for the key (TPM quote, "
                                             "enclave attestation, KMS key metadata); its hash is signed into checkpoints and "
                                             "exports carry it")

    sub.add_parser("status", help="hooks, signer, witnesses, policy, fail mode, capture sources")
    p = sub.add_parser("up", help="find or start the same-user v2 dev signer")
    p.add_argument("--wait", action="store_true", help="return once it answers")
    p.add_argument("--json", action="store_true", help="wait, then print its hello as JSON")
    p.add_argument("--replace", action="store_true", help="stop the running dev signer first, even an incompatible one")
    sub.add_parser("down", help="stop the same-user v2 dev signer")
    sub.add_parser("doctor", help="system mode: check the signer and policy run from files the agent cannot modify")
    p = sub.add_parser("uninstall", help="remove hooks (the ledger is kept)")
    p.add_argument("--project", action="store_true")
    p.add_argument("--agent", choices=("claude", "codex", "cursor", "gemini"), default="claude")

    p = sub.add_parser("ingest", help="remote ingestion gateway: `ingest token NAME` / `ingest serve`", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("analyze", help="run the detectors over a run and sign the findings into the ledger", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("cost", help="token usage (and cost, with your price table) per run or model", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("witness", help="run a witness log: `witness init|token|serve` (append-only, Merkle tree, signed heads)", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("signer", help="the v2 signer service: `signer serve --dev`, `signer serve|fsck --config signer.yaml`", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("otel", help="OpenTelemetry receiver: `otel serve` records agent spans sent over OTLP/HTTP", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("daemon", help="run tracekitd in the foreground")
    p.add_argument("--home")
    p = sub.add_parser("proxy", help="run the model proxy in the foreground (experimental)")
    p.add_argument("--home")
    p.add_argument("--experimental", action="store_true", help="required: the proxy is being rebuilt")
    p.add_argument("--port", type=int)
    p.add_argument("--upstream")

    p = sub.add_parser("observe", help="live terminal for the ledger or a bundle (read-only web UI)")
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("view", help="laptop viewer for the v2 signer's runs, each verified (read-only web UI)")
    p.add_argument("rest", nargs=argparse.REMAINDER)

    sub.add_parser("pending", help="list tool calls waiting for approval")
    for name in ("approve", "reject"):
        p = sub.add_parser(name, help=f"{name} a held tool call (run from a terminal outside the agent's session)")
        p.add_argument("approval_id", nargs="?", help="id from `tracekit pending` (default: the only pending one)")

    p = sub.add_parser("approvals", help="approvals on the v2 signer: `approvals list|show ID|approve ID|reject ID`")
    p.add_argument("--signer", help="the signer's Unix socket or tcp://host:port (default: the same-user dev signer)")
    acts = p.add_subparsers(dest="action", required=True)
    acts.add_parser("list", help="pending and recent approvals")
    acts.add_parser("show", help="one approval, with the signer's copy of the arguments in full").add_argument("approval_id")
    for name in ("approve", "reject"):
        q = acts.add_parser(name, help=f"{name} a pending approval")
        q.add_argument("approval_id")
        q.add_argument("--reason")

    p = sub.add_parser("export", help="write a .tkb evidence bundle")
    p.add_argument("-o", "--out", default="tracekit.tkb")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--last", action="store_true", help="the most recent run (default)")
    g.add_argument("--run")
    g.add_argument("--since", help="RFC3339 time, e.g. 2026-09-30T00:00:00.000000Z")
    p.add_argument("--otel", action="store_true", help="also include otel.json (OTLP/JSON)")
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

    p = sub.add_parser("verify", help="verify a .tkb offline")
    p.add_argument("bundle")
    p.add_argument("--witness", action="append", default=[], help="independent witness copy to check against")
    p.add_argument("--key", help="trusted signer public key (signer.pub file) or key id ed25519:...")
    p.add_argument("--strict", action="store_true", help="exit 3 on warnings")
    p.add_argument("--trust", help="format v2: pinned trust config (log keys, witness keys, algorithms)")
    p.add_argument("--v1-ledger", help="format v2: the v1 ledger.jsonl the log's format bridge continues")
    p.add_argument("--v1-key", help="with --v1-ledger: the v1 signer.pub")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("policy", help="policy v2: `policy compile FILE` prints canonical JSON and its hash; `policy lint FILE`")
    p.add_argument("action", choices=("compile", "lint"))
    p.add_argument("file")

    p = sub.add_parser("migrate", help="read or convert a v0.1 ledger; `migrate --system` upgrades a 0.2.0 system install")
    p.add_argument("rest", nargs=argparse.REMAINDER)

    p = sub.add_parser("demo", help="end-to-end demo in a temp folder")
    p.add_argument("--real", action="store_true", help="drive a real `claude -p` session instead of the scripted agent")
    p.add_argument("--keep", action="store_true")
    p.add_argument("--agent", default="claude", choices=["claude", "codex", "cursor", "gemini"],
                   help="send the scripted run as this coding agent's own hook payloads (default: claude)")

    a = ap.parse_args(argv)
    try:
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


def _init_remote(a):
    from . import client
    from .deploy import files
    url = a.remote.rstrip("/")
    err = client.remote_url_error(url)
    if err:
        print(f"tracekit: --remote: {err}", file=sys.stderr)
        return 2
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


def _match_pending(pend, prefix):
    hits = [x for x in pend if x["id"] == prefix] or [x for x in pend if x["id"].startswith(prefix)]
    return hits


def _run(a):
    if a.cmd == "ingest":
        from . import ingest
        return ingest.main(a.rest)
    if a.cmd == "analyze":
        from . import findings
        return findings.main(a.rest)
    if a.cmd == "otel":
        from . import otlp
        return otlp.main(a.rest)
    if a.cmd == "init" and a.remote:
        return _init_remote(a)
    if a.cmd == "init":
        from . import install
        if a.checkpoint_every < 1:
            print("tracekit: --checkpoint-every must be at least 1", file=sys.stderr)
            return 2
        if not 1 <= a.proxy_port <= 65535:
            print("tracekit: --proxy-port must be between 1 and 65535", file=sys.stderr)
            return 2
        if a.proxy and not experimental_gate(a.experimental, "the model proxy (init --proxy)"):
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
        if a.v2 and not (a.dev and a.agent == "claude"):
            print("tracekit: --v2 wires the Claude Code hook in dev mode only (--dev); system mode comes later",
                  file=sys.stderr)
            return 2
        if a.v2 and (a.home or a.witness or a.proxy or a.fail_closed or signer):
            print("tracekit: --home, --witness, --proxy, --fail-closed and --signer-cmd are v1 signer options; "
                  "they don't apply with --v2", file=sys.stderr)
            return 2
        if a.dev and a.agent != "claude":
            from . import agent_hooks
            home = a.home or os.path.expanduser("~/.tracekit-signer")
            try:
                cfg = install.init_dev(home, a.witness, a.checkpoint_every, None, fail_mode="closed" if a.fail_closed else None, signer=signer)
                path = None if a.no_hooks else agent_hooks.install(a.agent, os.getcwd() if a.project else None)
            except install.SettingsError as e:
                print(f"tracekit: {e}", file=sys.stderr)
                return 1
            print(f"dev signer running (same-user): {cfg['socket']}")
            print(f"{a.agent} hooks:", path or "not installed")
            return 0
        if a.dev:
            home = a.home or os.path.expanduser("~/.tracekit-signer")
            hooks = None if a.no_hooks else (os.path.join(os.getcwd(), ".claude", "settings.json") if a.project
                                            else os.path.expanduser("~/.claude/settings.json"))
            if a.v2:
                if not _signer_extra():
                    return 2
                try:
                    if hooks:
                        install.install_hooks(hooks, module=install.V2_HOOK)
                except install.SettingsError as e:
                    print(f"tracekit: {e}", file=sys.stderr)
                    return 1
                print("v2 hooks:", hooks or "not installed")
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
            print("hooks:", hooks or "not installed")
            return 0
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
        print(f"tracekitd installed as a separate user; socket {cfg['socket']}; hooks: {settings or 'not installed'}")
        return 0
    if a.cmd == "status":
        from . import install
        from .sdk import autospawn
        print(json.dumps({**install.status(), "signer_v2": autospawn.status()}, indent=2))
        return 0
    if a.cmd == "up":
        from .sdk import autospawn
        if not _signer_extra():
            return 2
        if a.replace:
            autospawn.down()
        conn = autospawn.ensure(wait=a.wait or a.json)
        hello = conn and conn[2]
        if conn:
            conn[0].close()
        if a.json:
            print(json.dumps(hello))
        else:
            print(f"dev signer {hello['version']} running (pid {hello['pid']})" if hello else "dev signer starting")
        return 0
    if a.cmd == "down":
        from .sdk import autospawn
        pid = autospawn.down()
        print(f"dev signer stopped (pid {pid})" if pid else "no dev signer running")
        return 0
    if a.cmd == "doctor":
        from . import install
        return install.doctor()
    if a.cmd == "uninstall" and a.agent != "claude":
        from . import agent_hooks
        print("hooks removed from", agent_hooks.install(a.agent, os.getcwd() if a.project else None, uninstall=True))
        return 0
    if a.cmd == "uninstall":
        from . import install
        try:
            print("hooks removed from", install.uninstall(os.getcwd() if a.project else None))
        except install.SettingsError as e:
            print(f"tracekit: {e}", file=sys.stderr)
            return 1
        return 0
    if a.cmd == "daemon":
        from . import daemon
        return daemon.main(["--home", _signer_home(a)])
    if a.cmd == "proxy":
        from . import proxy
        if not experimental_gate(a.experimental, "the model proxy (tracekit proxy)"):
            return 2
        return proxy.main(["--home", _signer_home(a)] + (["--port", str(a.port)] if a.port is not None else []) +
                          (["--upstream", a.upstream] if a.upstream else []))
    if a.cmd in ("pending", "approve", "reject"):
        from . import client
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
    if a.cmd == "export" and a.v2:
        return _export_v2(a)
    if a.cmd == "export":
        from . import bundle
        from .otel import parse_headers
        info = bundle.export(_signer_home(a), a.out, run=a.run, last=not (a.run or a.since), since=a.since, otel=a.otel,
                             otel_endpoint=a.otel_endpoint, otel_headers=parse_headers(a.otel_header))
        print(json.dumps(info, indent=2))
        return 0
    if a.cmd == "verify":
        from .verify import v1, v2
        mod = v2 if v2.is_v2(a.bundle) else v1
        if mod is v2:
            if not a.trust:
                print("tracekit verify: a v2 bundle needs --trust (the verifier's pinned trust config)", file=sys.stderr)
                return 2
            if bool(a.v1_ledger) != bool(a.v1_key):
                print("tracekit verify: --v1-ledger and --v1-key go together", file=sys.stderr)
                return 2
            rep, code = v2.verify(a.bundle, a.trust, a.v1_ledger, a.v1_key)
            integrity, assurance = rep.integrity, rep.assurance
        else:
            rep, code = v1.verify(a.bundle, a.witness, a.strict, a.key)
            integrity, assurance = v1.integrity(rep, code), v1.assurance(rep)
        if a.json:
            print(json.dumps({"exit_code": code, "checks": rep.checks, "failures": rep.failures, "warnings": rep.warnings,
                              "integrity": integrity, "assurance": assurance, "notes": rep.notes},
                             indent=2))
        else:
            mod.print_report(rep, code)
        return code
    if a.cmd == "policy":
        from .policy2 import compile as policy_compile
        pol, errors = policy_compile.build(a.file)
        for e in errors:
            print(e, file=sys.stderr)
        if errors:
            return 1
        if a.action == "compile":
            print(policy_compile.canonical(pol))
            print(f"policy_hash: {policy_compile.policy_hash(pol)}", file=sys.stderr)
        else:
            print(f"ok: {a.file}")
        return 0
    if a.cmd == "migrate":
        from . import migrate
        return migrate.main(a.rest)
    if a.cmd == "demo":
        from . import demo
        return demo.main(real=a.real, keep=a.keep, agent=a.agent)
    return 2


def _signer_extra():
    """True when the v2 signer's policy engine imports; else says how to install it."""
    from .policy2 import engine
    try:
        engine._backend(None)
    except ImportError:
        print("tracekit: the v2 signer needs its policy engine: pip install 'tracekit-ai[signer]'", file=sys.stderr)
        return False
    return True


def _export_v2(a):
    """`tracekit export --v2`: read the store without its lock, with the newest checkpoint note. When none covers the
    run's last record yet, nudge the running signer and wait up to NUDGE_WAIT_S for one."""
    import time

    from .bundle_v2 import export
    from .format import registry
    from .sdk.client import Client, Incompatible, SignerUnavailable
    from .signer.rpc_schema import RPCError
    from .signer.service import signer_config
    from .storage.base import StorageCorrupt, registry_tree
    from .storage.file import FileReader
    if not (a.run or a.run_set) or a.dev and a.config:
        print("tracekit export --v2: needs --run RUN_ID or --run-set, and --dev or --config (not both)", file=sys.stderr)
        return 2
    try:
        cfg = signer_config(a.config)
        store, tenant = os.path.join(cfg["data_dir"], "store"), a.tenant or cfg.get("tenant", "default")
        reader = FileReader(store)
        if a.run_set:
            with open(os.path.join(cfg["data_dir"], "keys", "registry_salt.key"), "rb") as f:
                tsalt = registry.tenant_salt(f.read(), tenant)
            for _ in range(5):   # a reader opened after reading the record note holds the registry notes it covers
                note = reader.checkpoint_latest()
                reader = FileReader(store)
                if reader.checkpoint_latest() == note:
                    break
            reg = reader.checkpoint_latest(registry_tree(tenant))
            if note is None or reg is None:
                raise ValueError(f"no registry checkpoint of tenant {tenant!r} in {store} yet")
            print(json.dumps(export(reader, tenant, a.run, note[1], a.out, run_set=(0, reg[0]), tenant_salt=tsalt),
                             indent=2))
            return 0
        run = reader.runs.get((tenant, a.run))
        if run is None:
            raise ValueError(f"no run {a.run!r} of tenant {tenant!r} in {store}")
        last = run["seqs"][-1]

        def covering():
            note = reader.checkpoint_latest()
            return note if note and note[0] > last else None
        note = covering()
        if note is None:
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
            if note is None:
                raise ValueError(f"the signer wrote no checkpoint covering run {a.run!r} within {NUDGE_WAIT_S:g}s")
        info = export(FileReader(store), tenant, a.run, note[1], a.out)   # opened after the note: holds its records
    except (OSError, ValueError, SignerUnavailable, StorageCorrupt) as e:
        print(f"tracekit export: {e}", file=sys.stderr)
        return 1
    print(json.dumps(info, indent=2))
    return 0


def _approvals(a):
    """`tracekit approvals`. Strings an agent chose (tool, args, reason) are printed JSON-escaped, never raw."""
    import pydoc

    from .format.canon import loads_strict
    from .sdk.client import Client, Incompatible, SignerUnavailable
    from .signer.rpc_schema import RPCError
    c = Client(a.signer)
    try:
        if a.action == "list":
            page, shown = {"next_cursor": None}, 0
            while True:
                page = c.approval_list({"cursor": page["next_cursor"]} if page["next_cursor"] else {})
                for x in page["approvals"]:
                    shown += 1
                    print(f"{x['approval_id']}  {x['state']}  run={x['run_id']}  tool={json.dumps(x['tool'])}  "
                          f"rules={','.join(x['rule_ids'])}  expires {x['expires_at']}")
                if page["next_cursor"] is None:
                    break
            if not shown:
                print("no approvals")
        elif a.action == "show":
            x = c.approval_get({"approval_id": a.approval_id})
            args = loads_strict(x["args"]) if x["args_source"] == "raw" and x["args"] is not None else x["args"]
            lines = [f"approval    {x['approval_id']} ({x['state']})", f"tool        {json.dumps(x['tool'])}",
                     f"rules       {', '.join(x['rule_ids'])}", f"policy      {x['policy_hash']}",
                     f"requester   {json.dumps(x['requester'])}", f"run         {x['run_id']}",
                     f"call        {x['tool_call_id']} attempt {x['attempt']}", f"expires     {x['expires_at']}",
                     f"binding     {x['binding_digest']}", "arguments (the signer's copy, in full):",
                     json.dumps(args, indent=2) if x["args"] is not None else "  (deleted: the approval is no longer live)"]
            if "reason" in x:
                lines.append(f"reason given by the agent (unverified): {json.dumps(x['reason'])}")
            pydoc.pager("\n".join(lines))
        else:
            req = {"approval_id": a.approval_id, "decision": a.action, **({"reason": a.reason} if a.reason else {})}
            r = c.approval_decide(req)
            print(f"{r['state']}: {r['approval_id']}" + (" (self-approved: dev mode only)" if r["self_approved"] else ""))
    except (SignerUnavailable, Incompatible) as e:
        print(f"signer unavailable: {e}", file=sys.stderr)
        return 2
    except RPCError as e:
        print(f"tracekit approvals: {e}", file=sys.stderr)
        return 1
    finally:
        c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
