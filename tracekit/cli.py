"""tracekit command line."""
import argparse
import getpass
import json
import os
import sys


def _signer_home(a):
    from . import client
    return a.home or client.client_config().get("signer_home") or "/var/lib/tracekit"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit", description="Signed, checkpointed evidence of what coding agents did.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="install the signer and Claude Code hooks")
    p.add_argument("--dev", action="store_true", help="same-user signer (no root; weaker: the agent could rewrite the ledger)")
    p.add_argument("--home", help="signer home (dev mode)")
    p.add_argument("--project", action="store_true", help="hooks in ./.claude/settings.json instead of ~/.claude")
    p.add_argument("--no-hooks", action="store_true")
    p.add_argument("--witness", action="append", default=[], help="file:/path.jsonl or git:/clone[@remote] (repeatable)")
    p.add_argument("--checkpoint-every", type=int, default=50)
    p.add_argument("--user", help="system mode: the user whose agents are traced (default: $SUDO_USER)")
    p.add_argument("--no-service", action="store_true", help="system mode: do not install systemd/launchd")
    p.add_argument("--proxy", action="store_true", help="also run the model proxy and point Claude Code at it (C3)")
    p.add_argument("--proxy-port", type=int, default=8787)
    p.add_argument("--fail-closed", action="store_true", help="proxy: refuse to forward when the signer can't record")
    p.add_argument("--managed", action="store_true", help="system mode: install hooks in Claude Code's admin-managed settings")
    p.add_argument("--managed-only", action="store_true", help="with --managed: also set allowManagedHooksOnly")

    sub.add_parser("status", help="hooks, signer, witnesses, policy, fail mode, capture sources")
    p = sub.add_parser("uninstall", help="remove hooks (the ledger is kept)")
    p.add_argument("--project", action="store_true")

    p = sub.add_parser("daemon", help="run tracekitd in the foreground")
    p.add_argument("--home")
    p = sub.add_parser("proxy", help="run the model proxy in the foreground")
    p.add_argument("--home")
    p.add_argument("--port", type=int)
    p.add_argument("--upstream")

    p = sub.add_parser("observe", help="live terminal for the ledger (read-only web UI)")
    p.add_argument("--home")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=7777)
    p.add_argument("--export", help="write a self-contained replay HTML and exit")

    sub.add_parser("pending", help="list tool calls waiting for approval")
    for name in ("approve", "reject"):
        p = sub.add_parser(name, help=f"{name} a held tool call (run from a terminal outside the agent's session)")
        p.add_argument("approval_id", nargs="?", help="id from `tracekit pending` (default: the only pending one)")

    p = sub.add_parser("export", help="write a .tkb evidence bundle")
    p.add_argument("-o", "--out", default="tracekit.tkb")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--last", action="store_true", help="the most recent run (default)")
    g.add_argument("--run")
    g.add_argument("--since", help="RFC3339 time, e.g. 2026-09-30T00:00:00.000000Z")
    p.add_argument("--otel", action="store_true", help="also include otel.json (OTLP/JSON)")
    p.add_argument("--otel-endpoint", help="also POST the spans to an OTLP/HTTP collector, e.g. http://localhost:4318")
    p.add_argument("--home", help="signer home to read the ledger from")

    p = sub.add_parser("verify", help="verify a .tkb offline")
    p.add_argument("bundle")
    p.add_argument("--witness", action="append", default=[], help="independent witness copy to check against")
    p.add_argument("--key", help="trusted signer public key (signer.pub file) or key id ed25519:...")
    p.add_argument("--strict", action="store_true", help="exit 3 on warnings")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("migrate", help="read or convert a v0.1 ledger")
    p.add_argument("rest", nargs=argparse.REMAINDER)

    p = sub.add_parser("demo", help="end-to-end demo in a temp folder")
    p.add_argument("--real", action="store_true", help="drive a real `claude -p` session instead of the scripted agent")
    p.add_argument("--keep", action="store_true")

    a = ap.parse_args(argv)
    if a.cmd == "init":
        from . import install
        if a.dev:
            home = a.home or os.path.expanduser("~/.tracekit-signer")
            hooks = None if a.no_hooks else (os.path.join(os.getcwd(), ".claude", "settings.json") if a.project
                                            else os.path.expanduser("~/.claude/settings.json"))
            cfg = install.init_dev(home, a.witness, a.checkpoint_every, hooks, proxy=a.proxy, proxy_port=a.proxy_port,
                                   fail_mode="closed" if a.fail_closed else None)
            if a.proxy:
                print(f"model proxy: {cfg['proxy_url']} (ANTHROPIC_BASE_URL set in {hooks or 'no settings file'})")
            print(f"dev signer running (same-user): {cfg['socket']}")
            print("hooks:", hooks or "not installed")
            return 0
        user = a.user or os.environ.get("SUDO_USER") or getpass.getuser()
        cfg, settings = install.init_system(user, a.witness, a.checkpoint_every,
                                            os.getcwd() if a.project else None, a.no_service, proxy=a.proxy,
                                            proxy_port=a.proxy_port, managed=a.managed, managed_only=a.managed_only,
                                            fail_mode="closed" if a.fail_closed else None)
        print(f"tracekitd installed as user 'tracekit'; socket {cfg['socket']}; hooks in {settings}")
        return 0
    if a.cmd == "status":
        from . import install
        print(json.dumps(install.status(), indent=2))
        return 0
    if a.cmd == "uninstall":
        from . import install
        print("hooks removed from", install.uninstall(os.getcwd() if a.project else None))
        return 0
    if a.cmd == "daemon":
        from . import daemon
        return daemon.main(["--home", _signer_home(a)])
    if a.cmd == "proxy":
        from . import proxy
        return proxy.main(["--home", _signer_home(a)] + (["--port", str(a.port)] if a.port else []) +
                          (["--upstream", a.upstream] if a.upstream else []))
    if a.cmd == "observe":
        from . import observe
        return observe.main((["--home", a.home] if a.home else []) + ["--host", a.host, "--port", str(a.port)] +
                            (["--export", a.export] if a.export else []))
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
            r = client.rpc({"op": "approve", "approval_id": aid, "decision": "approve" if a.cmd == "approve" else "reject"})
        except client.SignerUnavailable as e:
            print(f"signer unavailable: {e}", file=sys.stderr)
            return 2
        print(("ok: " + r["decision"]) if r.get("ok") else r.get("error"), file=sys.stdout if r.get("ok") else sys.stderr)
        return 0 if r.get("ok") else 1
    if a.cmd == "export":
        from . import bundle
        info = bundle.export(_signer_home(a), a.out, run=a.run, last=True, since=a.since, otel=a.otel,
                             otel_endpoint=a.otel_endpoint)
        print(json.dumps(info, indent=2))
        return 0
    if a.cmd == "verify":
        from . import bundle
        rep, code = bundle.verify(a.bundle, a.witness, a.strict, a.key)
        if a.json:
            print(json.dumps({"exit_code": code, "checks": rep.checks, "failures": rep.failures, "warnings": rep.warnings}, indent=2))
        else:
            bundle.print_report(rep, code)
        return code
    if a.cmd == "migrate":
        from . import migrate
        return migrate.main(a.rest)
    if a.cmd == "demo":
        from . import demo
        return demo.main(real=a.real, keep=a.keep)
    return 2


if __name__ == "__main__":
    sys.exit(main())
