"""Signer-side field extractors (design §4.3): the fields a class rule matches, computed from the raw args.

The tool's class comes from the policy's `tools` map, never from the caller. A shell command's argv[] comes from
shell.py in the engine. Fields that need signer state (payment.new_payee) are not extracted yet.
"""
import ipaddress
import posixpath
import re
import unicodedata
from urllib.parse import unquote, urlsplit

from tracekit.format.canon import canonical, event_hash

SHELL_KEYS = ("command", "cmd", "commands")
PATH_KEYS = ("file_path", "notebook_path", "path")
BODY_KEYS = ("body", "data", "json", "files", "form", "content")   # an http call with one of these sends data
# Browser Use actions that send data to the page they run on
TYPING = ("input", "upload_file", "send_keys", "select_dropdown")
NAVIGATE = ("navigate", "go_to_url")   # Browser Use actions that load a URL: a query string in it is data sent to its host
RECIPIENT_KEYS = ("to", "cc", "bcc", "recipients")
PAYEE_KEYS = ("payee", "to", "recipient", "destination", "account", "account_number", "iban")
FS_OPS = {"Write": "write", "Edit": "edit", "MultiEdit": "edit", "NotebookEdit": "edit", "Read": "read",
          "Grep": "read", "Glob": "read"}


def first(args, *keys):
    return next((args[k] for k in keys if args.get(k) is not None), None)


def fs_path(raw):
    """The path a rule matches. A `\\` is a `/` (the agent may run on Windows: C:\\x is C:/x). An absolute path (/x or
    C:/x) without `..` is normalised; a relative path, or one with a `..` that a symlink could redirect, is
    unverifiable, so only its certain suffix (after the last `..`) is matched."""
    raw = raw.replace("\\", "/")
    parts = raw.split("/")
    if (raw.startswith("/") or re.match(r"[A-Za-z]:/", raw)) and ".." not in parts:
        return posixpath.normpath(raw)
    tail = parts[len(parts) - parts[::-1].index(".."):] if ".." in parts else parts
    return "/".join(p for p in tail if p not in ("", "."))


def fs_forms(raw):
    """What a path rule matches: fs_path(raw) and, when a `..` cut it short, also the lexically normalised path (the
    target unless a symlink redirects it); each also casefolded, because the agent's file system may ignore case
    (macOS, Windows) whatever the signer's does."""
    if not isinstance(raw, str):
        return []
    forms = [fs_path(raw)]
    if ".." in raw.replace("\\", "/").split("/"):
        forms.append(posixpath.normpath(raw.replace("\\", "/")))
    return list(dict.fromkeys(forms + [f.casefold() for f in forms]))


SPECIAL = ("http", "https", "ws", "wss", "ftp")   # the schemes a URL host is read for
_C0 = "".join(map(chr, range(0x21)))
_BAD = object()   # a host that looks like an address and is not a valid one


def _whatwg_host(url):
    """(scheme, host) as a browser (WHATWG URL) reads `url`: leading and trailing controls and spaces and every tab
    and newline dropped, view-source: and blob: peeled, `\\` a `/`, any number of slashes after the scheme, the host
    after the last `@`. The host is None for a scheme that has none; the scheme is None for //host."""
    u = re.sub(r"[\t\n\r]", "", url).strip(_C0)
    u = u[re.match(r"(?i)(?:(?:view-source|blob):[\x00-\x20]*)*", u).end():]
    m = re.match(r"([A-Za-z][A-Za-z0-9+.-]*):", u)
    scheme = m.group(1).lower() if m else None
    if scheme not in SPECIAL and (scheme or not re.match(r"[/\\]{2}", u)):
        return scheme, None
    rest = u[m.end():] if m else u
    host = re.split(r"[/?#]", rest.replace("\\", "/").lstrip("/"), maxsplit=1)[0].rpartition("@")[2]
    return scheme, (host[:host.find("]") + 1] if host.startswith("[") and "]" in host else host.split(":")[0])


def _number(part):
    """An IPv4 part in decimal, 0x hex or 0 octal, None for a name, -1 for a malformed number (08) or a decimal of more
    than 10 digits (over 2**32, and past Python's 4,300 digits int() refuses)."""
    if re.fullmatch(r"0[xX][0-9A-Fa-f]*", part):
        return int(part[2:] or "0", 16)
    if re.fullmatch(r"0[0-7]+", part):
        return int(part, 8)
    if re.fullmatch(r"[0-9]+", part):
        return -1 if len(part) > 1 and part[0] == "0" or len(part) > 10 else int(part)
    return None


def _address(host):
    """The ipaddress object a host names (IPv4 in any of inet_aton's forms: 1 to 4 parts, decimal, hex or octal), None
    for a name, or _BAD for something that ends in a number but is no address."""
    if ":" in host:
        try:
            return ipaddress.IPv6Address(host.strip("[]").split("%")[0])
        except ValueError:
            return _BAD
    parts = host.split(".")
    if len(parts) > 1 and parts[-1] == "":
        parts.pop()
    if _number(parts[-1]) is None:
        return None
    if len(parts) > 4:
        return _BAD
    nums = [_number(p) for p in parts]
    if None in nums or -1 in nums or any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return _BAD
    return ipaddress.IPv4Address(nums[-1] + sum(n << 8 * (3 - i) for i, n in enumerate(nums[:-1])))


def _canonical_host(host):
    """Percent-decoded, NFKC (fullwidth letters and digits), ideographic dots as dots, casefolded; an address in its
    canonical form, an IPv4-mapped or NAT64 IPv6 address as the IPv4 address it reaches."""
    h = unicodedata.normalize("NFKC", unquote(host)).replace("\u3002", ".").casefold()
    ip = _address(h)
    if ip is None or ip is _BAD:
        return ip or h
    ip = ip.ipv4_mapped or _nat64(ip) or ip if ip.version == 6 else ip
    return f"[{ip}]" if ip.version == 6 else str(ip)


def _nat64(ip):
    return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF) if int(ip) >> 32 == 0x64FF9B << 64 else None


def _special_address(host):
    ip = _address(host)
    if ip is None or ip is _BAD:
        return ip is _BAD
    ips = [ip]
    if ip.version == 6:   # IPv4-mapped, -compatible, 6to4 and NAT64 addresses reach the IPv4 address inside
        ips += [a for a in (ip.ipv4_mapped, ip.sixtofour, _nat64(ip)) if a]
        if int(ip) >> 32 == 0:
            ips.append(ipaddress.IPv4Address(int(ip)))
    return any(not a.is_global or a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved
               or a.is_unspecified for a in ips)


def with_scheme(url):
    """`url`, with http:// in front when it has no scheme: a browser's address bar, and curl, read host[:port]/path as
    http."""
    if re.match(r"(?i)[\x00-\x20]*((https?|wss?|ftp|file):|[a-z][a-z0-9+.-]*:(?![0-9])|[/\\]{2})",
                re.sub(r"[\t\n\r]", "", url)):
        return url
    return "http://" + url


def url_info(url):
    """{scheme, host, internal} of a URL. `host` is canonical (_canonical_host). `internal`: the host is a loopback,
    private, link-local, shared, reserved or other non-global address (also inside IPv6), looks like an address but is
    none, or a browser and Python's urllib read different hosts from the URL (http://a\\@b/), which also sets
    `ambiguous`."""
    url = with_scheme(url)
    scheme, wh = _whatwg_host(url)
    try:
        rh = urlsplit(url).hostname
    except ValueError:   # urllib cannot read it (an unclosed [): the host is unknown
        return {"scheme": scheme, "internal": True}
    hosts = [_canonical_host(h) for h in (wh, rh) if h]
    if not hosts:
        return {"scheme": scheme}
    host = hosts[0]
    internal = _BAD in hosts or len(set(hosts)) > 1 or _special_address(host.strip("[]"))
    return {"scheme": scheme, "host": None if host is _BAD else host, "internal": internal,
            **({"ambiguous": True} if len(set(hosts)) > 1 else {})}


def url_target(url):
    """The URL reduced to scheme://canonical-host/, for rules that look for a host in any notation."""
    info = url_info(url)
    return f"{info.get('scheme') or ''}://{info['host']}/" if info.get("host") else None


# SQL as each dialect lexes it: (backslash escapes in '' and "", $tag$ quotes, nested /* */, # comments, [ident],
# `ident`, -- starts a comment only before a space). A statement that splits differently in two dialects (a comment
# or literal one hides and the other runs) is matched in every reading.
# lean: Oracle q'[...]' quotes and MySQL's NO_BACKSLASH_ESCAPES are not modelled; add a reading if a deployment uses them
SQL_DIALECTS = {"postgres": (False, True, True, False, False, False, False),
                "mysql": (True, False, False, True, False, True, True),
                "sqlite": (False, False, False, False, True, True, False),
                "mssql": (False, False, True, False, True, False, False)}
_DOLLAR = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")
_MYSQL_RUN = re.compile(r"/\*!\d*")


def sql_code(stmt, backslash, dollar, nest, hash_comment, brackets, backtick, dash_space):
    """`stmt` with every comment a space and every literal or quoted identifier '' or "", as one dialect lexes it:
    what a keyword rule should see. None when a literal or comment is not closed (the database rejects it)."""
    out, i, n = [], 0, len(stmt)
    while i < n:
        c, two = stmt[i], stmt[i:i + 2]
        if (two == "--" and (not dash_space or stmt[i + 2:i + 3] in ("", " ", "\t", "\n", "\r", "\f", "\v"))) or \
                (c == "#" and hash_comment):
            j = stmt.find("\n", i)
            i = n if j < 0 else j
            out.append(" ")
        elif hash_comment and stmt.startswith("/*!", i):   # MySQL runs what /*! ... */ holds
            i = _MYSQL_RUN.match(stmt, i).end()
        elif two == "/*":
            depth, j = 1, i + 2
            while depth:
                close = stmt.find("*/", j)
                if close < 0:
                    return None
                opened = stmt.find("/*", j, close) if nest else -1
                depth, j = (depth + 1, opened + 2) if opened >= 0 else (depth - 1, close + 2)
            out.append(" ")
            i = j
        elif c in "'\"" or (c == "`" and backtick) or (c == "[" and brackets):
            close = "]" if c == "[" else c
            escapes = (backslash and c in "'\"") or (c == "'" and stmt[i - 1:i] in ("E", "e")
                                                      and not re.match(r"\w", stmt[i - 2:i - 1]))
            j = i + 1
            while True:
                if j >= n:
                    return None
                if escapes and stmt[j] == "\\":
                    j += 2
                elif stmt[j] != close:
                    j += 1
                elif stmt[j + 1:j + 2] == close:
                    j += 2
                else:
                    break
            out.append("''" if c == "'" else '""')
            i = j + 1
        elif c == "$" and dollar and _DOLLAR.match(stmt, i) and not re.match(r"[\w$]", stmt[i - 1:i]):
            tag = _DOLLAR.match(stmt, i).group(0)
            end = stmt.find(tag, i + len(tag))
            if end < 0:
                return None
            out.append("''")
            i = end + len(tag)
        else:
            out.append(c)
            i += 1
    return "".join(out)


A2A_PARTS = ("text", "file", "data")
A2A_NAME = re.compile(r"[!-~]+")   # printable ASCII without spaces: a name with one spelling for each logical name


def a2a_fields(args):
    """An agent-to-agent call's fields: what the A2A gateway sends (sender, the caller it authenticated; receiver, the
    upstream it names; skills, the ids of the skills the receiver's Agent Card lists; params, the JSON-RPC params) or
    run.transfer does (sender, receiver, modality, projector, size, digest, and with tracekit.integrations.c2c the
    fuser's weights hash), so a sender is the gateway's authenticated caller at tier T2 and the agent's own claim from
    run.transfer. `route` is sender->receiver, then ` via <projector>` when a transfer names one; `skills` the skill
    ids, sorted, matched as one JSON list like every list field, so a deny rule on it with `unless:
    '^\\[(("search"|"summarize"),?)*\\]$'` lets a message reach only a receiver offering no skill but those; `kinds` the
    message's part kinds, `hosts` the hosts its file parts point at, `size` the message's bytes (canonical JSON) or the
    transfer's; `weights` the hash the fuser's weights had, which a policy pins where an id (`projector`) is only the
    caller's word. The names (sender, receiver, projector, modality, weights, each skill and part kind) are matched in
    lower case, and the class's rules match in any case (Engine); a name that isn't printable ASCII without spaces (a
    look-alike or fullwidth letter, a zero-width or control character, a space around it) has spellings no rule
    written for its logical name matches, so `unreadable` names its field and the engine denies the call
    (TK-A2A-NAME). The signed arguments keep the caller's spelling."""
    params = args.get("params")
    message = params.get("message") if isinstance(params, dict) else None
    parts = [p for p in message["parts"] if isinstance(p, dict)] if isinstance(message, dict) and \
        isinstance(message.get("parts"), list) else []
    uris = [p["file"].get("uri") for p in parts if isinstance(p.get("file"), dict)]
    size = len(canonical(params)) if isinstance(params, dict) else args.get("size")
    names = {k: _name(args[k]) for k in ("sender", "receiver", "projector", "modality", "weights")
             if args.get(k) is not None}
    lists = {"skills": args.get("skills") or None,
             "kinds": [p.get("kind") or next((k for k in A2A_PARTS if k in p), "unknown") for p in parts] or None}
    names.update({k: [_name(x) for x in (v if isinstance(v, list) else [v])] for k, v in lists.items() if v})
    unreadable = [k for k, v in names.items() if v is None or isinstance(v, list) and None in v]
    names = {k: v for k, v in names.items() if k not in unreadable}
    sender, receiver, projector = names.get("sender"), names.get("receiver"), names.get("projector")
    return {**names, "skills": sorted(names["skills"]) if "skills" in names else None,
            "route": f"{sender}->{receiver}" + (f" via {projector}" if projector else "")
            if sender and receiver and "projector" not in unreadable else None,
            "hosts": sorted({url_info(u).get("host") or u for u in uris if isinstance(u, str)}) or None, "size": size,
            "unreadable": unreadable or None}


def _name(v):
    """`v` in lower case when it is a name (A2A_NAME), else None."""
    return v.lower() if isinstance(v, str) and A2A_NAME.fullmatch(v) else None


def extract(cls, tool, args):
    """{field: value} for `cls`; a missing value is left out."""
    if cls == "shell":
        out = {"command": first(args, *SHELL_KEYS)}
    elif cls == "fs":
        path = first(args, *PATH_KEYS)
        content = first(args, "content", "new_string", "new_source", "edits")
        out = {"path": fs_path(path) if isinstance(path, str) else path, "op": FS_OPS.get(tool) or args.get("op"),
               "content_digest": None if content is None else event_hash(content)}
    elif cls in ("http", "browser"):
        url = first(args, "url")
        info = url_info(url) if isinstance(url, str) else {}
        out = {"url": url, "host": info.get("host"), "internal": info.get("internal")}
        if cls == "browser":
            out.update(action=args.get("action"), scheme=info.get("scheme"))
            page, action = args.get("page_url"), tool.rpartition(":")[2]
            # the query as a browser reads it: tabs and newlines dropped, up to the fragment
            query = re.sub(r"[\t\n\r]", "", url).partition("#")[0].partition("?")[2] if isinstance(url, str) else ""
            if action in TYPING and isinstance(page, str):
                out["sends_to"] = url_info(page).get("host")
            elif action in NAVIGATE and query:
                out["sends_to"] = info.get("host")
        else:
            out["method"] = str(args.get("method") or "GET").upper()
            if out["method"] not in ("GET", "HEAD") or any(args.get(k) is not None for k in BODY_KEYS):
                out["sends_to"] = info.get("host")
    elif cls == "sql":
        stmt = first(args, "sql", "query", "statement")
        text = stmt if isinstance(stmt, str) else "\n;\n".join(stmt) if isinstance(stmt, list) and all(
            isinstance(s, str) for s in stmt) else None
        code = [] if text is None else list(dict.fromkeys(c for c in (sql_code(text, *d) for d in SQL_DIALECTS.values())
                                                          if c is not None))
        out = {"statement": stmt, "db": first(args, "db", "database"), "code": code or None,
               "verb": code[0].split()[0].upper() if code and code[0].split() else None}
    elif cls == "payment":
        out = {"amount": first(args, "amount", "amount_cents"), "currency": args.get("currency"),
               "payee": first(args, "payee", "to", "recipient"),
               "payees": [args[k] for k in PAYEE_KEYS if args.get(k) is not None] or None}
    elif cls == "email":
        to = args.get("to")
        to = [to] if isinstance(to, str) else to if isinstance(to, list) else []
        out = {"to": to, "attachments": args.get("attachments"),
               "recipients": [args[k] for k in RECIPIENT_KEYS if args.get(k) is not None] or None,
               "domains": sorted({a.rsplit("@", 1)[1].lower() for a in to if isinstance(a, str) and "@" in a})}
    elif cls == "mcp":
        server, name = None, tool
        if tool.startswith("mcp__"):   # Claude Code's mcp__server__tool
            server, _, name = tool[5:].partition("__")
        elif tool.startswith("mcp:"):
            server, _, name = tool[4:].partition("/")
        out = {"server": server, "tool": name, "args": args}
    elif cls == "a2a":
        out = a2a_fields(args)
    else:
        out = {}
    return {k: v for k, v in out.items() if v is not None}
