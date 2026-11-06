"""tracekit feedback: a pre-filled GitHub issue (the field-report form), printed with exactly what it holds.

It sends nothing and makes no network call: the person reads the link, opens it (--open hands it to the browser) and
submits it, or doesn't. A false alarm (--harmless) holds the approval's rule ids, tool name, policy hash and verdict,
never its command, arguments or paths.
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
import time
import urllib.parse
import webbrowser

from . import __version__

FORM = "https://github.com/Cygnux-Labs/Tracekit/issues/new?template=field-report.yml"


def url(title, fields):
    """The new-issue link: the form, its title and its fields by id (each a URL query parameter GitHub fills in)."""
    return FORM + "&" + urllib.parse.urlencode({"title": title, **fields}, quote_via=urllib.parse.quote)


def _hooks():
    """The coding agents Tracekit's hooks are installed for: Claude Code's settings files (v1 or v2 hooks) and the
    other agents' configs (v2 hooks, as tracekit doctor finds them)."""
    from .doctor import _dev_harnesses
    from .install import _installed_hooks
    return ["claude-code"] * any(h.get("events") for h in _installed_hooks()) + sorted(_dev_harnesses())


def field_report():
    """(title, fields) of a field report (#385): this machine's Tracekit, OS, Python and hooks, and tracekit report
    --share's week when the dev signer has a store."""
    from . import report
    from .signer.service import dev_data_dir
    from .storage.base import StorageCorrupt, StorageUnavailable
    fields = {"agent": f"Coding-agent hooks installed: {', '.join(_hooks()) or 'none'}\n"
                       "(filed with `tracekit feedback`, for #385)",
              "how-long": f"Tracekit {__version__}, {platform.platform(terse=True)}, Python {platform.python_version()}"}
    try:
        now = time.time()
        rep = report.build({"data_dir": dev_data_dir(create=False)}, now - 7 * 86400, now,
                           say=lambda s: print(f"tracekit feedback: {s}", file=sys.stderr, flush=True))
        fields = {"share": report.share(rep), **fields}
        print(f"tracekit feedback: {report.SHARE_NOTE}", file=sys.stderr)
    except (OSError, ValueError, StorageCorrupt, StorageUnavailable) as e:
        print(f"tracekit feedback: no week's counts ({e}); `tracekit audit --share --since 7d` prints a replay's",
              file=sys.stderr)
    return "Field report", fields


def false_alarm(x, why=None):
    """(title, fields) of approval `x` (approval_get's) as a false alarm: its rule ids (a rule that isn't Tracekit's
    own as "custom rule", as --share counts it), tool name, policy hash and verdict, and the person's one line `why`.
    Never the call's arguments: nothing else of `x` is read."""
    from .report import APPROVAL_RULES, tracekit_rules
    ours = tracekit_rules() | APPROVAL_RULES
    rules = list(dict.fromkeys(r if r in ours else "custom rule" for r in x["rule_ids"]))
    lines = [f"rules: {', '.join(rules)}", f"tool: {json.dumps(x['tool'])}", f"policy: {x['policy_hash']}",
             "verdict: ask (held for a person)", *([f"why: {' '.join(why.split())}"] if why and why.strip() else [])]
    return f"False alarm: {', '.join(rules)}", {"false-alarms": "\n".join(lines)}


def main(argv=None):
    from .signer.service import _escaped
    ap = argparse.ArgumentParser(prog="tracekit feedback", description="print a pre-filled GitHub issue (a field "
                                 "report, or a false alarm with --harmless) and exactly what it holds. It sends "
                                 "nothing: you open the link, read it and submit it.")
    ap.add_argument("--harmless", metavar="APPROVAL_ID", help="report this held call as a false alarm: its rule ids, "
                    "tool name, policy hash and verdict, never its command, arguments or paths")
    ap.add_argument("--why", help="with --harmless, one line on why the call was harmless")
    ap.add_argument("--signer", help="with --harmless, the signer's Unix socket or tcp://host:port (default: the "
                    "same-user dev signer)")
    ap.add_argument("--open", action="store_true", help="also open the link in your browser")
    a = ap.parse_args(argv)
    if a.why and not a.harmless:
        ap.error("--why goes with --harmless")
    if a.harmless:
        from .sdk.client import Client, Incompatible, SignerUnavailable
        from .signer.rpc_schema import RPCError
        c = Client(a.signer)
        try:
            title, fields = false_alarm(c.approval_get({"approval_id": a.harmless}), a.why)
        except (SignerUnavailable, Incompatible) as e:
            print(f"signer unavailable: {e}", file=sys.stderr)
            return 2
        except RPCError as e:
            print(f"tracekit feedback: {e}", file=sys.stderr)
            return 1
        finally:
            c.close()
    else:
        title, fields = field_report()
    link = url(title, fields)
    print(link, "", "the link holds exactly this, and nothing is sent until you submit it on GitHub:",
          f"title: {title}", sep="\n")
    for k, v in fields.items():
        print(f"{k}:", *(f"  {_escaped(line)}" for line in v.splitlines()), sep="\n")
    if a.open:
        webbrowser.open(link)
    return 0
