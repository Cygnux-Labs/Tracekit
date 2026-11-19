"""tracekit feedback: a pre-filled GitHub issue (the field-report form), printed with exactly what it holds.

It sends nothing and makes no network call: the person reads the link, opens it (--open hands it to the browser) and
submits it, or doesn't. A false alarm (--harmless) holds the approval's rule ids, tool name, policy hash and verdict,
and the Tracekit, OS, Python and hook names, never its command, arguments or paths; all of it is printed before
anything is submitted. --file writes a field report to send as a pull request instead.
"""
from __future__ import annotations

import argparse
import os
import platform
import re
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


def _week():
    """tracekit report --share's 7 days of the dev signer's store, or None when there is none (said on stderr)."""
    from . import report
    from .signer.service import dev_data_dir
    from .storage.base import StorageCorrupt, StorageUnavailable
    try:
        now = time.time()
        rep = report.build({"data_dir": dev_data_dir(create=False)}, now - 7 * 86400, now,
                           say=lambda s: print(f"tracekit feedback: {s}", file=sys.stderr, flush=True))
    except (OSError, ValueError, StorageCorrupt, StorageUnavailable) as e:
        print(f"tracekit feedback: no week's counts ({e}); `tracekit audit --share --since 7d` prints a replay's "
              "counts", file=sys.stderr)
        return None
    print(f"tracekit feedback: {report.SHARE_NOTE}", file=sys.stderr)
    return report.share(rep)


def _os():
    """The OS and its major.minor release (macOS-26.3, Windows-10, Linux-6.8): on Linux, platform.platform's terse form
    is the kernel's whole build string."""
    if platform.system() != "Linux":
        return platform.platform(terse=True)
    m = re.match(r"\d+(\.\d+)?", platform.release())
    return "Linux" + (f"-{m.group()}" if m else "")


def _about(share):
    """The form's two required fields, which every link fills: `share` and `agent`, this machine's Tracekit, OS, Python
    and hooks."""
    return {"share": share,
            "agent": f"Tracekit {__version__}, {_os()}, Python {platform.python_version()}\n"
                     f"Coding-agent hooks installed: {', '.join(_hooks()) or 'none'}\n(filed with `tracekit feedback`)"}


def _tool(name):
    """A tool's name as a link may hold it: a built-in one the default policy names (Bash, Edit, Read, WebFetch, ...)
    as it is; an MCP tool's, whose server and tool names can name a customer or a project, and any other, as what it
    is."""
    from .signer.service import DEFAULT_POLICY, load_policy
    if name in load_policy(DEFAULT_POLICY).policy.get("tools", {}) and not set("*?[") & set(name):
        return name
    return "an MCP tool" if name.startswith(("mcp__", "mcp:")) else "another tool"


# a report file's lines outside its counts block (tests/test_feedback.py checks each file in docs/field-reports/)
KEYS = ("Tracekit", "OS", "Python", "Hooks installed", "Run by", "Anything you'd like to tell us (optional)")


def report_file():
    """A field report as a file, to send as a pull request (docs/field-reports/README.md): this machine's Tracekit, OS,
    Python and hooks, report --share's week (tool calls, and each rule's holds with what people did with them), who
    ran it, and one optional line."""
    week = _week()
    return "\n".join([
        "# Tracekit field report", "", f"Tracekit: {__version__}", f"OS: {_os()}",
        f"Python: {platform.python_version()}", f"Hooks installed: {', '.join(_hooks()) or 'none'}",
        "Run by: a person / an agent (name it)", "", "## Counts", "",
        "```text", week or "(no dev store: paste what tracekit audit --share --since 7d prints here)", "```",
        "", f"{KEYS[-1]}:", ""])


def false_alarm(x, why=None, kept=None):
    """(title, fields) of approval `x` (approval_get's) as a false alarm: its rule ids (a rule that isn't Tracekit's
    own as "custom rule", as --share counts it), those that held it apart from those that only also matched (flags),
    as report._placed places them in its policy (a shipped pack's, or one the signer kept in directory `kept`), its tool
    name (_tool's), policy hash and verdict, and the person's one line `why`. Never the call's arguments: nothing else
    of `x` is read."""
    from . import view
    from .report import _placed, _shared, tracekit_rules
    ours, held, also = tracekit_rules(), [], []
    d = {"tool": x["tool"], "rule_ids": x["rule_ids"], "policy_hash": x["policy_hash"], "decision": "ask"}
    for rule, why_held in _placed(view.Translator(view.policy_reasons(kept=kept)), d):
        (also if why_held is False else held).append(_shared(rule["id"], ours))
    held, also = list(dict.fromkeys(held)), list(dict.fromkeys(also))
    lines = [f"rules: {', '.join(held)}" + (f" (also matched, not why: {', '.join(also)})" if also else ""),
             f"tool: {_tool(x['tool'])}", f"policy: {x['policy_hash']}", "verdict: ask (held for a person)",
             *([f"why: {' '.join(why.split())}"] if why and why.strip() else [])]
    return f"False alarm: {', '.join(held)}", {"notes": "\n".join(lines)}


def main(argv=None):
    from .cli import SIGNER_HELP
    from .signer.service import _escaped
    ap = argparse.ArgumentParser(prog="tracekit feedback", description="print a pre-filled GitHub issue (a field "
                                 "report, or a false alarm with --harmless) and exactly what it holds. It sends "
                                 "nothing: you open the link, read it and submit it.")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--harmless", metavar="APPROVAL_ID", help="report this held call as a false alarm: its rule ids, "
                   "tool name, policy hash and verdict, and the Tracekit, OS, Python and hook names, never its command, "
                   "arguments or paths; all of it is printed before anything is submitted")
    g.add_argument("--file", metavar="PATH", help="write a field report to this new file instead, to fill in and send as "
                   "a pull request (docs/field-reports/README.md)")
    ap.add_argument("--why", help="with --harmless, one line on why the call was harmless")
    ap.add_argument("--signer", help="with --harmless, " + SIGNER_HELP)
    ap.add_argument("--open", action="store_true", help="also open the link in your browser")
    a = ap.parse_args(argv)
    if a.why and not a.harmless:
        ap.error("--why goes with --harmless")
    if a.file:
        try:
            with open(a.file, "x", encoding="utf-8") as f:
                f.write(report_file())
        except OSError as e:
            print(f"tracekit feedback: {e}", file=sys.stderr)
            return 1
        print(f"wrote {a.file}: fill in who ran it and read it all (counts only: no command, path or content)\n"
              f"next: copy it to docs/field-reports/<github-login>-{time.strftime('%Y-%m-%d', time.gmtime())}.md in your "
              "fork of Cygnux-Labs/Tracekit and open a pull request; commit with `git commit -s`")
        return 0
    if a.harmless:
        from .report import _running
        from .sdk import autospawn
        from .sdk.client import Client, Incompatible, SignerUnavailable
        from .signer.rpc_schema import RPCError
        c = Client(a.signer)
        dev = not c.signer   # the dev signer: the one that runs, never one started for a printout
        kept = os.path.join(autospawn.data_dir(), "policies") if dev else None   # the policies it kept
        try:
            c = _running() if dev else c
            title, fields = false_alarm(c.approval_get({"approval_id": a.harmless}), a.why, kept)
        except (OSError, SignerUnavailable, Incompatible) as e:
            print(f"tracekit feedback: no signer is running, so {a.harmless[:64]} can't be read; run it again while "
                  "the signer that held the call runs, or name that signer with --signer"
                  if dev and not isinstance(e, Incompatible) else f"signer unavailable: {e}", file=sys.stderr)
            return 2
        except RPCError as e:
            print(f"tracekit feedback: {e}", file=sys.stderr)
            return 1
        finally:
            c.close()
        # the form's required fields, so it can be submitted; no store is read: one call is no week's counts, and
        # --signer's store may not be this machine's
        fields = {**_about("not included: a single false alarm"), **fields}
    else:
        title, fields = "Field report", _about(_week() or "no dev store on this machine (tracekit audit --share "
                                                          "--since 7d prints a replay's counts)")
    link = url(title, fields)
    print(link, "", "the link holds exactly this, and nothing is sent until you submit it on GitHub:",
          f"title: {title}", sep="\n")
    for k, v in fields.items():
        print(f"{k}:", *(f"  {_escaped(line)}" for line in v.splitlines()), sep="\n")
    if a.open:
        webbrowser.open(link)
    return 0
