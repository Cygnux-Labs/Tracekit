"""Signer-side field extractors (design §4.3): the fields a class rule matches, computed from the raw args.

The tool's class comes from the policy's `tools` map, never from the caller. A shell command's argv[] comes from
shell.py in the engine. Fields that need signer state (payment.new_payee) are not extracted yet.
"""
import posixpath
from urllib.parse import urlsplit

from tracekit.format.canon import event_hash

FS_OPS = {"Write": "write", "Edit": "edit", "MultiEdit": "edit", "NotebookEdit": "edit", "Read": "read",
          "Grep": "read", "Glob": "read"}


def _first(args, *keys):
    return next((args[k] for k in keys if args.get(k) is not None), None)


def fs_path(raw):
    """The path a rule matches. An absolute path without `..` is normalised; a relative path, or one with a `..` that
    a symlink could redirect, is unverifiable, so only its certain suffix (after the last `..`) is matched."""
    parts = raw.split("/")
    if raw.startswith("/") and ".." not in parts:
        return posixpath.normpath(raw)
    tail = parts[len(parts) - parts[::-1].index(".."):] if ".." in parts else parts
    return "/".join(p for p in tail if p not in ("", "."))


def _host(url):
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def extract(cls, tool, args):
    """{field: value} for `cls`; a missing value is left out."""
    if cls == "shell":
        out = {"command": _first(args, "command", "cmd")}
    elif cls == "fs":
        path = _first(args, "file_path", "notebook_path", "path")
        content = _first(args, "content", "new_string", "new_source", "edits")
        out = {"path": fs_path(path) if isinstance(path, str) else path, "op": FS_OPS.get(tool) or args.get("op"),
               "content_digest": None if content is None else event_hash(content)}
    elif cls in ("http", "browser"):
        url = _first(args, "url")
        if cls == "browser":
            out = {"url": url, "action": args.get("action")}
        else:
            out = {"url": url, "method": str(args.get("method") or "GET").upper(),
                   "host": _host(url) if isinstance(url, str) else None}
    elif cls == "sql":
        stmt = _first(args, "sql", "query", "statement")
        out = {"statement": stmt, "db": _first(args, "db", "database"),
               "verb": stmt.split()[0].upper() if isinstance(stmt, str) and stmt.split() else None}
    elif cls == "payment":
        out = {"amount": _first(args, "amount", "amount_cents"), "currency": args.get("currency"),
               "payee": _first(args, "payee", "to", "recipient")}
    elif cls == "email":
        to = args.get("to")
        to = [to] if isinstance(to, str) else to if isinstance(to, list) else []
        out = {"to": to, "attachments": args.get("attachments"),
               "domains": sorted({a.rsplit("@", 1)[1].lower() for a in to if isinstance(a, str) and "@" in a})}
    elif cls == "mcp":
        server, name = None, tool
        if tool.startswith("mcp__"):   # Claude Code's mcp__server__tool
            server, _, name = tool[5:].partition("__")
        elif tool.startswith("mcp:"):
            server, _, name = tool[4:].partition("/")
        out = {"server": server, "tool": name, "args": args}
    else:
        out = {}
    return {k: v for k, v in out.items() if v is not None}
