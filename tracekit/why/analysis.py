"""Investigation: alerts, argument provenance, candidate causes, timeline and workspace summaries.

Everything here is derived from the log and the tests recorded against it. Nothing calls a model.
"""
from __future__ import annotations

import bisect
import json
import os
import re
import sys
import unicodedata
import urllib.parse
from collections import deque
from itertools import islice
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from .. import provenance
from .core import COMMITTED, UNFINISHED, Run, chain_hash, glob_escape, load_run, ts_seconds, verify
from .graph import Graph, _text, build_graph, nodes_matching, target_hits

_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")   # starts only where a run starts: linear
_URL = re.compile(r"https?://[^\s\"'<>]+")
SENSITIVE_HINT = re.compile(r"send|email|mail|post|publish|transfer|pay|refund|delete|remove|export|upload|"
                            r"exec|shell|bash|write|deploy|sign|approve", re.I)


def _count(v: Any) -> int:
    """A token count as recorded, or 0 when it is not a count (a log written by hand or another tool)."""
    return v if type(v) is int and v >= 0 else 0


def integrity(run: Run) -> List[str]:
    """verify()'s problems, less a missing run.end: the page shows a running run as running, not as broken."""
    return [p for p in verify(run) if not p.startswith(UNFINISHED)]


def is_sensitive(run: Run, ev: Dict[str, Any]) -> Optional[str]:
    """'declared' if the run marked it sensitive, 'heuristic' if only the tool name suggests it."""
    if ev.get("sensitive"):
        return "declared"
    if not run.start.get("sensitive_tools") and SENSITIVE_HINT.search(ev.get("tool", "")):
        return "heuristic"
    return None


# --------------------------------------------------------------------------- argument provenance

def atoms(args: Any) -> List[str]:
    """Values worth tracing back (_leaves: JSON and query strings in values read too): the addresses and URLs in each
    string argument, the whole string when it has 6+ characters, and numbers the signer's index reads (a digit run of 8
    or more)."""
    out: List[str] = []
    for _, v in _leaves(args):
        if isinstance(v, str):
            out.extend(_EMAIL.findall(v) + _URL.findall(v))
            if len(v) >= 6:
                out.append(v)
        elif isinstance(v, (int, float)) and not isinstance(v, bool) and provenance.values(v)[0]:
            out.append(str(v))
    return list(dict.fromkeys(out))


_QUERY = re.compile(r"[\w.\[\]-]+=[^&\s]*(?:&[\w.\[\]-]+=[^&\s]*)*")


def _leaves(args: Any) -> Iterator[Tuple[Tuple[Any, ...], Any]]:
    """Each leaf of a call's arguments, in order, with the keys above it: dicts, lists and tuples walked, and a string
    that holds a JSON object or array, or a query string (`to=…&amount=…`), walked too under its own keys (the string
    is a leaf as well), three strings deep at most. Arguments that hold themselves are refused (ValueError)."""
    stack: List[Any] = [((), args, 0)]
    # the containers being walked, kept alive so no other takes an id of theirs; one met inside itself is a cycle
    inside: Dict[int, Any] = {}
    while stack:
        item = stack.pop()
        if isinstance(item, int):
            del inside[item]
            continue
        path, v, depth = item
        if isinstance(v, (dict, list, tuple)):
            if id(v) in inside:
                raise ValueError("the call's arguments hold themselves")
            inside[id(v)] = v
            stack.append(id(v))
            if isinstance(v, dict):
                stack.extend((path + (k,), x, depth) for k, x in reversed(list(v.items())))
            else:
                stack.extend((path, x, depth) for x in reversed(v))
        else:
            yield path, v
            inner = _parsed(v) if isinstance(v, str) and depth < 3 else None
            if inner is not None:
                stack.append((path, inner, depth + 1))


def _parsed(s: str) -> Any:
    """What a string argument holds when it is a JSON object or array, or a query string (a list of one-key dicts);
    else None."""
    t = s.strip()
    if t[:1] in ("{", "[") and len(t) <= provenance.MAX_TEXT:
        t = _shallow(t)
        try:
            return json.loads(t) if t is not None else None
        except ValueError:
            return None
    if "=" in t and _QUERY.fullmatch(t):
        return [{k: v} for k, v in urllib.parse.parse_qsl(t, keep_blank_values=True)]
    return None


def _shallow(t: str) -> Optional[str]:
    """JSON text `t` with each array or object nested more than 64 deep in place of a string of its text, so its keys
    above are read and the deeper part as the text it is (json.loads recurses as deep as the text nests, and how deep
    it may depends on the caller's); None when a part that deep never closes."""
    if t.count("[") + t.count("{") <= 64:
        return t
    out: List[str] = []
    depth, cut, last = 0, 0, 0
    for m in _JSON_TOKEN.finditer(t):
        c = m.group()
        if c in "[{":
            depth += 1
            if depth == 65:
                cut = m.start()
        elif c in "]}":
            if depth == 65:
                out += [t[last:cut], json.dumps(t[cut:m.end()])]
                last = m.end()
            depth -= 1
    return None if depth >= 65 else "".join(out) + t[last:]


_JSON_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[\[\]{}]')   # a string, or a bracket outside one
def arg_provenance(run: Run, g: Graph, action_ev: Dict[str, Any], memo: Optional[Dict[Any, Any]] = None
                   ) -> List[Dict[str, Any]]:
    """For each argument value, which earlier inputs or tool results hold it, read as the signer's index reads values
    (value_provenance).
    untrusted-only: only untrusted content brought it (the classic injection signature)
    trusted:        some trusted input (the task included) or tool result holds it
    generated:      no earlier source; the model produced it"""
    memo = {} if memo is None else memo
    ix = _index(run, memo)
    j = ix.call_ix.get(id(action_ev))
    if j is None:   # an event of another copy of the run
        return value_provenance(run, run.value(action_ev["args_ref"]), action_ev["seq"], memo)
    _settle(run, memo, ix, {j})
    return memo["rows"][ix.calls[j][0]]


def only_untrusted(row: Dict[str, Any]) -> str:
    """What an alert says of a value only untrusted content supplied (a row of value_provenance): where it appears, or
    the part of it untrusted content held (`its 77812290 appears only in mail:1`), the content read latest first; and
    for a trusted call's answer that counts as untrusted, what the call was given and where that came from (through
    other such calls: the content it started from), so a person approving the call knows untrusted content chose
    the answer."""
    srcs = sorted(row["sources"], key=lambda s: -s["seq"])   # the latest first: what the call was read after

    def names(ss: List[Dict[str, Any]]) -> str:
        return ", ".join(dict.fromkeys(s["label"] for s in ss))
    whole = [s for s in srcs if "part" not in s]
    parts: Dict[str, List[Dict[str, Any]]] = {}
    for s in srcs:
        if "part" in s:
            parts.setdefault(s["part"], []).append(s)
    said = "; ".join([f"'{_short(row['value'], 80)}' appears only in {names(whole)}"] * bool(whole) + [
        f"its {part} {'appear' if part.startswith('parts ') else 'appears'} only in {names(ss)}"
        for part, ss in parts.items()])
    said = (said if whole else f"'{_short(row['value'], 80)}': {said}") + "."
    src = next((s for s in srcs if "given" in s), None)
    return said + (" " + chosen(src) if src else "")


def chosen(src: Dict[str, Any]) -> str:
    """Why a trusted call's answer (a source of value_provenance carrying `given`) counts as untrusted: what the call
    was given, and where that came from."""
    given = src["given"]
    if not given["from"]:   # more tokens than are read (_rows)
        return (f"{src['label']}'s answer counts as untrusted: it was called with {given['value']}, and those past 64 "
                "aren't read.")
    return (f"{src['label']}'s answer counts as untrusted: it was called with '{given['value']}', which came only from "
            f"{', '.join(given['from'])}" + (f", and that only from {', '.join(given['origin'])}"
                                             if given["origin"] != given["from"] else "") + ".")


def _committed(v: Any) -> bool:
    """A signed run's content, imported as only its commitment: the same placeholder everywhere, no value to trace."""
    return isinstance(v, dict) and v.get("content") == COMMITTED


def value_provenance(run: Run, args: Any, before_seq: int, memo: Optional[Dict[Any, Any]] = None
                     ) -> List[Dict[str, Any]]:
    """arg_provenance for argument values that need not be recorded yet: the live guard calls this before a tool runs,
    with before_seq past the end of the log. Each atom is read as the signer's index reads values (_holds); the hosts
    and digit runs of text a model wrote in a free-text field (_text_leaves, _mentions) are atoms too, rows marked
    `in_text`.
    Content is read as it was when the call was made: a tool result is untrusted when the call was marked so, or when
    its content was observed as untrusted (an untrusted tool's result is recorded so) before the call.
    Untrusted content also brought an identifier (anything but such text) when it holds a value of it that no trusted
    content holds (an IBAN's digits written in groups, a URL's host), read wider than the index reads untrusted content
    (_wide), or when untrusted texts hold its parts (_split).
    A trusted call's result holds nothing an earlier call's arguments named (all of it, or its longest digit run) unless
    trusted content gave each argument that named it: an echo of the agent's own value (a lookup's error naming it, a
    validator returning it whole) didn't bring it, a lookup by a key the task gave did. A trusted call's result is
    untrusted content when the values of its arguments that were traced came only from untrusted content, one at least
    (a decoder, a calculator given the mail's values, a value the model made up beside them or not).
    memo: the readings of the run's content and calls (its index, each call's rows by its seq), kept across its calls
    and as its log grows (the live guard's checks)."""
    if _committed(args):   # a signed run's arguments: only their commitment, which is no argument value
        return []
    memo = {} if memo is None else memo
    ix = _index(run, memo)
    while True:   # a reading that met calls not yet read reads them (_settle), then reads again
        need: Set[int] = set()
        rows, _ = _rows(run, memo, ix, args, before_seq, need, by=False)
        if not need:
            return rows
        _settle(run, memo, ix, need)


def _settle(run: Run, memo: Dict[Any, Any], ix: "_Index", need: Set[int]) -> None:
    """Reads the arguments of calls `need` (indices of the index's calls) into memo["rows"] (by the call's seq), and
    first those of the earlier calls each reading meets: the earliest first, so a chain of calls (each given the last
    one's result) is read without recursing as deep as it is long."""
    done, keys, calls = memo.setdefault("rows", {}), memo.setdefault("keys", {}), ix.calls
    stack = sorted(need)
    while stack:
        j = stack[-1]
        if calls[j][0] in done:
            stack.pop()
            continue
        more: Set[int] = set()
        rows, by = _rows(run, memo, ix, run.value(calls[j][4].get("args_ref")), calls[j][0], more)
        more = {m for m in more if calls[m][0] not in done}
        if more:   # earlier calls, read first; then this one again
            stack += sorted(more)
        else:
            done[calls[j][0]], keys[calls[j][0]] = rows, by
            stack.pop()


def _tainted(rows: List[Dict[str, Any]]) -> bool:
    """Whether a call's arguments (the rows of what it was called by, _rows) were untrusted content's: some traced value
    came only from it, and none from trusted content (a value the model made up, or a hashed one, traces to nothing)."""
    return any(r["status"] == "untrusted-only" for r in rows) and not any(r["status"] == "trusted" for r in rows)


def _rows(run: Run, memo: Dict[Any, Any], ix: "_Index", args: Any, before_seq: int, need: Set[int], by: bool = True
          ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """value_provenance's rows of `args` before `before_seq`, and the rows of what the call was called by, which say
    whether a trusted call's answer counts as untrusted (_tainted): its rows that name something, trusted or not
    (_names: an address, URL or host, a distinctive digit run; a task's word such as `supplier` keeps no answer
    trusted), and a row for each distinctive token of its arguments
    (_tokens), the first 64 (past them, a row of untrusted-only for the rest: a call given more fails closed); each
    earlier call whose rows (memo["rows"]) the reading needed and didn't have is added to `need`, and the rows are then
    provisional."""
    if _committed(args):
        return [], []
    reads, calls = ix.reads, ix.calls
    done, keys = memo.setdefault("rows", {}), memo.setdefault("keys", {})
    hashed = (run.start.get("meta") or {}).get("content_capture") == "hashed"
    k = bisect.bisect_left(ix.seqs, before_seq)   # the content before the call
    trust_of: Dict[int, str] = {}
    tainted: Set[int] = set()

    def trust(i: int) -> str:   # as when the call was made; a trusted call's answer to untrusted arguments is untrusted
        if i not in trust_of:
            t, j = reads[i][1], ix.call_of.get(i)
            if t == "trusted" and j is not None:
                if ix.bound.get(i, before_seq) < before_seq:
                    t = "untrusted"
                elif calls[j][0] not in done:
                    need.add(j)
                elif _tainted(keys[calls[j][0]]):
                    t = "untrusted"
                    tainted.add(i)
            trust_of[i] = t
        return trust_of[i]

    found = atoms(args)
    text = {t: set(provenance.values(t, email_hosts=False)[0]) for t in _text_leaves(args)}   # each read once
    rows = []
    for a, in_text in [(a, False) for a in found] + [(m, True) for m in _mentions(text) if m not in found]:
        if hashed and a.startswith("sha256:"):  # a hash placeholder, not a value
            rows.append({"value": a, "status": "hashed", "sources": []})
            continue
        atom = _atom(a, text.get(a))
        p, free, vals, whole = atom
        part = a not in text   # an identifier, which a part only untrusted content holds came from that content
        if part:   # its digits as untrusted content is read: across any separator (`+1 (415) 555-0134`, `GB29/NWBK/…`)
            vals = vals | {v for v in _wide(a) if v[0] == "digits"}
        # what names the value, not a part of it others share: all of it, or its longest digit run (an IBAN's account)
        names = whole | set(sorted((v for v in vals if v[0] == "digits"), key=lambda v: len(v[1]))[-1:])
        echo = None
        for c in _naming(ix, atom, names):
            seq = calls[c][0]
            if seq >= before_seq:
                break
            if seq not in done:
                need.add(c)
            elif _given(memo, done[seq], atom, names):
                continue
            echo = seq
            break

        def counts(i: int) -> bool:   # trusted content that may be this value's source: not a call's echo of it
            ev = reads[i][0]
            return trust(i) == "trusted" and (ev["type"] != "action" or echo is None or ev["seq"] < echo)
        def has(i: int, values: Set[Tuple[str, str]]) -> Set[Tuple[str, str]]:   # those of `values` content i holds
            _, _, _, plain, rv, wide = reads[i]
            got = (rv | wide) & values
            if i in ix.truncated:   # more values than were read: the rest from its text
                got |= {v for v in values if ix.full(i, v, True)}
            return got
        held = {i for v in vals for i in ix.by_val.get(v, ()) if i < k}   # what may hold it: a value of it, or its text
        held |= {i for i in ix.truncated if i < k and has(i, vals)}
        if free:
            held.update(i for i in _token_holders(ix, p, k) if i < k)
        tv: Dict[Tuple[str, str], bool] = {}

        def trusted_val(v: Tuple[str, str]) -> bool:   # trusted content that may be the source holds value v of it
            if v not in tv:
                tv[v] = any(counts(i) for i in ix.by_val.get(v, ()) if i < k) or any(
                    counts(i) and ix.full(i, v, False) for i in ix.truncated if i < k)
            return tv[v]
        halves, pieces = _split(p, k, ix, trust) if free else (set(), [])
        # an identifier with white space in it, compared without (a decoder reads base64 broken over lines as it was)
        bare = _atom(_SPACE_RUN.sub("", a)) if part and " " in p else None
        if bare is not None:
            held |= {i for v in bare[3] for i in ix.by_val.get(v, ()) if i < k}
            if bare[1]:
                held.update(i for i in _token_holders(ix, bare[0], k) if i < k)
        srcs = []
        for i in sorted(held | halves):
            ev, _, label, plain, rv, wide = reads[i]
            t, found = trust(i), None
            if t == "trusted":
                if not (counts(i) and (_holds(atom, plain, rv) or bare is not None and _holds(bare, plain, rv)
                                       or i in ix.truncated and any(ix.full(i, v, False) for v in whole))):
                    continue
            elif not (_holds(atom, plain, rv, wide=True) or i in ix.truncated and has(i, whole)):
                if not part:
                    continue
                if i in halves:
                    found = "parts " + ", ".join(pieces)
                elif bare is not None and _holds(bare, plain, rv, wide=True):
                    found = bare[0]
                else:
                    found = next((v for _, v in sorted(has(i, vals)) if not trusted_val((_, v))), None)
                    if found is None:
                        continue
            src = {"node": "ev:" + ev["id"], "label": label, "trust": t, "seq": ev["seq"],
                   **({"part": found} if found is not None else {})}
            if i in tainted:   # a trusted call's answer to what only untrusted content gave it: what that was
                seq = calls[ix.call_of[i]][0]
                given = next(r for r in keys[seq] if r["status"] == "untrusted-only")
                came = sorted(given["sources"], key=lambda x: -x["seq"])   # the latest first
                src["given"] = {"value": given["value"],
                                "from": list(dict.fromkeys(x["label"] for x in came)),
                                "origin": list(dict.fromkeys(o for x in came for o in (
                                    x["given"]["origin"] if "given" in x else [x["label"]])))}
            srcs.append(src)
        if not srcs:
            status = "hashed" if hashed else "generated"  # with hashed capture there is no text to search
        elif all(s["trust"] == "untrusted" for s in srcs):
            status = "untrusted-only"
        else:
            status = "trusted"
        rows.append({"value": a, "status": status, "sources": srcs, **({"in_text": True} if in_text else {})})
    if not by:   # a call checked before it runs: what it was called by matters once it is an earlier call (_settle)
        return rows, []
    by = [r for r in rows if r["status"] in ("trusted", "untrusted-only") and _names(r["value"])]
    tokens = _tokens(args)
    holders = _key_holders(ix, {t for _, t in tokens[:64]}, k)
    for shown, token in tokens[:64]:
        came = [{"node": "ev:" + reads[i][0]["id"], "label": reads[i][2], "trust": trust(i),
                 "seq": reads[i][0]["seq"]} for i in holders[token]]
        by.append({"value": shown, "sources": came, "status": "generated" if not came else "trusted" if any(
            x["trust"] == "trusted" for x in came) else "untrusted-only"})
    if len(tokens) > 64:   # each search is one pass of a pattern of them all; more would slow every check
        by.append({"value": "more than 64 tokens that name something", "sources": [], "status": "untrusted-only"})
    return rows, by


def _tokens(args: Any) -> List[Tuple[str, str]]:
    """The distinctive tokens (_distinctive) of a call's arguments, as (the token, read plain), in order: of every
    string and number at every depth, whatever its key, each quoted part (`'ACME-7781'`, `"acme"`; not in JSON
    text, whose keys are quoted), each word (letters and digits with `-` `_` `.` `#` `/` between) and a word's runs of
    digits (`7781` of `ACME-7781`), and each number; 65 at most (_rows reads 64)."""
    out: Dict[str, str] = {}
    for _, v in _leaves(args):
        if len(out) > 64:
            break
        if isinstance(v, float) and v.is_integer():
            v = int(v)
        if isinstance(v, int) and not isinstance(v, bool):
            found = [(str(abs(v)), False)]
        elif isinstance(v, str):
            quoted = [] if v.lstrip()[:1] in ("{", "[") else [a or b for a, b in _QUOTED.findall(v)]
            found = [(x, True) for x in quoted] + [(x, False) for w in _WORD_TOKEN.findall(v)
                                                   for x in [w, *_DIGITS.findall(w)]]
        else:
            continue
        for shown, quoted in found:
            t = _DIGIT_SEP.sub("", shown).lower() if shown.isascii() and not quoted else _plain(shown)   # a word: plain
            if t not in out and _distinctive(t, quoted):
                out[t] = shown
    return [(shown, t) for t, shown in out.items()]


def _distinctive(t: str, quoted: bool = False) -> bool:
    """Whether a token of a lookup's arguments (read plain) names something a lookup can be by, so that one only
    untrusted content gave chose the record: letters and digits mixed, 3 or more of them (`a7781`, `acme-7781`,
    `svc-a12`), but no unit (`30s`, `5ms`, `2nd`); 4 or more digits that are no plausible year or date and no round
    number (`7781`; not `2026`, `20261101`, `1500`, `100`); or quoted, 3 or more characters but no common word
    (`'acme'`, `'ACME Ltd'`; not `'open'`). A name alone (`Emma`, `acme`) names nothing here."""
    run = "".join(_KEY_PART.findall(t))
    digits = sum(c.isdigit() for c in run)
    if digits and digits < len(run):
        return len(run) >= 3 and not _UNIT.fullmatch(run)
    if digits:
        if len(run) < 4 or len(run.rstrip("0")) <= 2:
            return False
        if len(run) == 4:
            return not 1900 <= int(run) <= 2100
        return len(run) != 8 or not _date(run)
    return quoted and len(t) >= 3 and t not in COMMON


def _date(d: str) -> bool:
    """Whether 8 digits read as a date of 1900 to 2100: year, month, day, or day and month either way, then year."""
    y, m, day = int(d[:4]), int(d[4:6]), int(d[6:])
    a, b, y2 = int(d[:2]), int(d[2:4]), int(d[4:])
    return 1900 <= y <= 2100 and 1 <= m <= 12 and 1 <= day <= 31 or \
        1900 <= y2 <= 2100 and 1 <= min(a, b) <= 12 and max(a, b) <= 31


def _names(value: str) -> bool:
    """Whether a value a call was given names something (_distinctive): an address, URL or host, a digit run that is no
    year, date or round number, or a free string with a distinctive token in it (_tokens: base64, `ACME-7781 iban`)."""
    _, free, _, whole = _atom(value)
    return bool(_tokens(value)) if free else any(kind != "digits" or _distinctive(v) for kind, v in whole
                                                 if kind != "string")


def _key_holders(ix: "_Index", tokens: Iterable[str], k: int) -> Dict[str, List[int]]:
    """For each of a call's tokens (_tokens, read plain), the contents before index `k` that hold it as a token in their
    text, its runs of letters and of digits with or without one character between (`A-781` holds `A781`, and `A781`
    `A-781`): by one pass over each content of a pattern of them all (a key found in it leaves the pattern, and the
    content is read again for the rest, which a key it matched may hold: `A-781` holds `781` too), each content read
    once for each key."""
    todo: Dict[Tuple[str, ...], List[str]] = {}
    for t in tokens:
        todo.setdefault(tuple(_KEY_PART.findall(t)), []).append(t)
    read = {p: ix.keys.get(p, (0, []))[0] for p in todo}
    hits = {p: list(ix.keys.get(p, (0, []))[1]) for p in todo}
    for i in range(min(read.values(), default=k), k):
        left = sorted(p for p in todo if read[p] <= i)
        while left:
            pat = re.compile(r"(?<![^\W_])(?:" + "|".join(r"[\W_]?".join(map(re.escape, p)) for p in left)
                             + r")(?![^\W_])")
            got = {tuple(_KEY_PART.findall(m.group())) for m in pat.finditer(ix.decimal(i))}
            if not got & set(left):
                break
            for p in got & set(left):
                hits[p].append(i)
            left = [p for p in left if p not in got]
    out: Dict[str, List[int]] = {}
    for p, ts in todo.items():
        if read[p] < k:
            ix.keys[p] = (k, hits[p])
        for t in ts:
            out[t] = [i for i in hits[p] if i < k]
    return out


def _naming(ix: "_Index", atom, names: Set[Tuple[str, str]]) -> List[int]:
    """The calls (indices) whose arguments name atom `atom`: hold it (_holds) or a value of it in `names`, in log
    order."""
    p, free = atom[0], atom[1]
    found = {c for v in names for c in ix.call_vals.get(v, ())}
    if free:
        if _WORDS4.fullmatch(p):
            found.update(ix.call_words.get(p, ()))
        else:
            found.update(c for c, call in enumerate(ix.calls) if p in call[1] and _bounded(p, call[1], False))
    return sorted(found)


def _token_holders(ix: "_Index", p: str, k: int) -> Iterable[int]:
    """The contents before index `k` that may hold free string `p` as a token, as untrusted content is read (_holds,
    wide): by the index's words for one word of letters and digits, else by its text."""
    if _ALNUM.fullmatch(p):
        return ix.alnums.get(p, ())
    return (i for i in range(k) if p in ix.reads[i][3] and _bounded(p, ix.reads[i][3], True))


def _given(memo: Dict[Any, Any], rows: List[Dict[str, Any]], atom, names: Set[Tuple[str, str]]) -> bool:
    """Whether trusted content gave every argument value of an earlier call (its rows, `rows`) that names atom `atom`
    (holds it, or a value of it in `names`): a lookup by a key the task gave, whose result is no echo of the agent's own
    value."""
    naming = [r for r in rows if _named(memo, r["value"], atom, names)]
    return bool(naming) and all(r["status"] == "trusted" for r in naming)


def _named(memo: Dict[Any, Any], value: str, atom, names: Set[Tuple[str, str]]) -> bool:
    key = ("value", value)
    if key not in memo:
        memo[key] = _plain(value), set(provenance.values(value)[0]), _wide(value)
    plain, vals, wide = memo[key]
    return _holds(atom, plain, vals) or bool((vals | wide) & names)


_DIGIT_SEP = re.compile(r"(?<=[0-9])[ .-](?=[0-9])")
_WORD = re.compile(r"(?<![\w.@/-])[^\W\d_]{2,}(?![\w.@/-]|:/)")
_SPACE = re.compile(r"\s")
_SPACE_RUN = re.compile(r"\s+")
_KEY_WORD = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])")
DESTINATION = frozenset(("recipient", "to", "cc", "bcc", "payee", "account", "iban", "url", "uri", "link", "host",
                         "domain", "destination", "target", "channel", "path", "file", "address", "email", "phone",
                         "number", "id", "beneficiary", "receiver", "creditor", "dest", "wallet", "payto", "endpoint",
                         "webhook", "bucket", "server", "repo", "remote", "addr", "acct", "routing", "swift", "bic",
                         "sortcode"))
FREE_TEXT = frozenset(("body", "text", "message", "content", "summary", "description", "subject", "note", "comment",
                       "html", "markdown", "caption", "reply", "status", "title", "msg", "template", "draft", "readme",
                       "payload", "script", "topic", "label", "motd", "bio", "headline", "post", "prompt", "memo",
                       "signature", "greeting"))
REFERENCE = frozenset(("ref", "reference"))
COMMON = frozenset(("open", "closed", "pending", "active", "inactive", "paid", "unpaid", "overdue", "draft", "sent", "new",
                    "all", "none", "null", "true", "false", "yes", "asc", "desc", "json", "csv", "xml", "pdf", "html",
                    "text", "error", "warning", "info", "debug", "prod", "staging", "test", "default", "today", "high",
                    "low", "medium", "done", "failed", "success", "approved", "rejected", "cancelled", "archived",
                    "eur", "usd", "gbp"))


def _key_words(key: Any) -> List[str]:
    return [w.lower() for w in _KEY_WORD.findall(key)] if isinstance(key, str) else []


def _identifier_key(key: Any) -> bool:
    """Whether an argument's key names where a call goes or what it acts on: a word of it, or two together, one of
    DESTINATION (`recipient`, `account_no`, `pay_to_the_order_of`, `sort_code`, `creditor_reference`), unless its last
    word is a free-text word (FREE_TEXT: `email_body`, `payee_comment`, `repo_readme`, `iban_note`). Words count in the
    plural too."""
    words = _key_words(key)
    return bool(words) and not _one_of(words[-1], FREE_TEXT) and any(
        _one_of(w, DESTINATION) for w in words + [a + b for a, b in zip(words, words[1:])])


def _text_key(key: Any) -> bool:
    """Whether an argument's key names text whatever its value (its last word a free-text word, or a reference:
    `subject`, `payment_ref`), when it is no identifier's."""
    words = _key_words(key)
    return bool(words) and _one_of(words[-1], FREE_TEXT | REFERENCE)


def _one_of(word: str, names: frozenset) -> bool:
    return word in names or any(word.endswith(end) and word[:-len(end)] + add in names
                                for end, add in (("s", ""), ("es", ""), ("ies", "y")))


def _prose(s: str) -> bool:
    """Whether string `s` reads as text a model wrote (a message body, a summary): white space and two or more words of
    letters that aren't part of an address, host, URL or path."""
    return _SPACE.search(s) is not None and next(islice(_WORD.finditer(s), 1, None), None) is not None


def _text_leaves(args: Any) -> Set[str]:
    """The string arguments read as text a model wrote. The nearest key decides: a value under an identifier's key
    (_identifier_key: `recipient`, `to_email`) is an identifier; one under a text key (_text_key: a subject, a body, a
    note, a payment_ref) is text whatever keys are above it (`{"email": {"body": …}}`), unless it is all one identifier
    (_lone_identifier: `IBAN: GB29 NWBK …`); one under another key is an identifier when a key above it is an
    identifier's (`{"file": {"name": …}}`), else text when it is prose (_prose). Anything else (a lone token under a key
    of no kind) is an identifier, whatever words are around it."""
    text: Set[str] = set()
    other: Set[str] = set()
    for path, v in _leaves(args):
        if not isinstance(v, str):
            continue
        key = path[-1] if path else None
        if _identifier_key(key) or _text_key(key) and not _reference_key(key) and _lone_identifier(v):
            other.add(v)
        elif _text_key(key) or not any(_identifier_key(k) for k in path) and _prose(v):
            text.add(v)
        else:
            other.add(v)
    return text - other


def _reference_key(key: Any) -> bool:
    """Whether an argument's key names a reference (its last word `ref` or `reference`: `payment_ref`), which quotes an
    identifier by design."""
    words = _key_words(key)
    return bool(words) and _one_of(words[-1], REFERENCE)


def _lone_identifier(v: str) -> bool:
    """Whether text `v` is identifiers only, in punctuation or not, after a label of up to four words or not (`IBAN`,
    `IBAN:`, `IBAN —`, `Backup host is`; before an IBAN `Emma Smith, IBAN` too), with a name after an IBAN or not: IBANs
    written in groups or not (`GB29 NWBK …`), addresses, URLs and hosts, one
    or more (`GB29… / DE89…`), and digit runs written in groups or not (`+44 7700 900123`) alone or after a label that
    ends in `:`, `#` or a dash (`Acct # 6016 …`; `about order 77812290` is text)."""
    t = v.strip(_AROUND)
    iban = _IBANS.search(t) is not None
    if iban:   # a name after an IBAN (`GB29… Emma Smith`, `GB29… (Emma)`)
        t = _NAME_AFTER.sub("", t)
    label = (_IBAN_LABEL if iban else _LABEL).match(t)
    return _identifiers(t, True) or label is not None and _identifiers(
        t[label.end():], label.group().rstrip()[-1] in ":#-–—")


def _identifiers(t: str, digits: bool) -> bool:
    """Whether text `t` holds identifiers (_lone_identifier; digit runs too when `digits`) and nothing else but
    separators (white space, `,` `;` `|` `&`, and ` / `, ` and `, ` or ` between words)."""
    rest, n = _IBANS.subn(" ", t)
    if digits:
        rest, m = _DIGIT_GROUPS.subn(" ", rest)
        n += m
    for x in _SEPARATED.split(rest):   # the first word that is no identifier ends it (a long body at once)
        w = x.strip(_AROUND)
        if w:
            _, free, _, whole = _atom(w)
            if free or not digits and any(k == "digits" for k, _ in whole):
                return False
            n += 1
    return n > 0


def _mentions(text: Dict[str, Set[Tuple[str, str]]]) -> List[str]:
    """The hosts and digit runs, as the signer's index reads them, in text a model wrote (_text_leaves, with the values
    the index reads in it, an address's domain not a host) but not in its addresses and URLs: atoms of their own, so a
    body that quotes one an untrusted page gave is said, not stopped."""
    out: List[str] = []
    for t, vals in sorted(text.items()):
        inner = {v for x in _EMAIL.findall(t) + _URL.findall(t) for v in provenance.values(x)[0]}
        out.extend(v for kind, v in sorted(vals - inner) if kind in ("host", "digits"))
    return list(dict.fromkeys(out))


def _plain(s: str) -> str:
    """`s` as the signer's index reads text (provenance.norm: no format characters, NFKC), case folded, its white space
    one space and without the ' ', '.' or '-' between two digits: a digit run written in groups reads as one."""
    return " ".join(_DIGIT_SEP.sub("", provenance.norm(s)).casefold().split())


def _atom(a: str, vals: Optional[Set[Tuple[str, str]]] = None
          ) -> Tuple[str, bool, Set[Tuple[str, str]], Set[Tuple[str, str]]]:
    """(atom `a` read plain, whether it is a free string (read as a whole token, not an address, URL, host or digit
    run), the values the signer's index reads in it (`vals`, when read already), those that are all of it)."""
    p, vals = _plain(a), set(provenance.values(a)[0]) if vals is None else vals
    whole = {(k, v) for k, v in vals if k == "string" or _plain(v) == p}
    return p, bool(p) and not any(k != "string" for k, _ in whole), vals, whole


def _holds(atom, plain: str, vals: Set[Tuple[str, str]], wide: bool = False) -> bool:
    """Whether content (its text read plain, the values the index reads in it) holds atom `atom` (_atom): an address,
    URL, host or digit run as a value of the content equal to it; a free string as a whole token of the text (_bounded;
    `wide`, untrusted content: or joined to one by _), or as a whole value (the string a JSON result holds)."""
    p, free, _, whole = atom
    return bool(whole & vals) or free and p in plain and _bounded(p, plain, wide)


def _bounded(p: str, plain: str, wide: bool) -> bool:
    """Whether `p` is in `plain` as a whole token: no letter, digit or _ just before or after it (`wide`: no letter or
    digit, so 'external_' holds 'external'), where `p` starts or ends with one."""
    head, tail = p[0].isalnum() or p[0] == "_", p[-1].isalnum() or p[-1] == "_"
    i = plain.find(p)
    for _ in range(64):   # the first copies one by one; past them (a page of near-copies), one pass of a pattern
        if i == -1:
            return False
        j = i + len(p)
        if not (head and i and _joins(plain[i - 1], wide)) and not (tail and j < len(plain) and _joins(plain[j], wide)):
            return True
        i = plain.find(p, i + 1)
    joins = r"[^\W_]" if wide else r"\w"
    return i != -1 and re.compile((f"(?<!{joins})" if head else "") + re.escape(p) + (f"(?!{joins})" if tail else "")
                                  ).search(plain, i) is not None


def _joins(c: str, wide: bool) -> bool:
    return c.isalnum() or c == "_" and not wide


_WORDS4 = re.compile(r"\w{4,}")
_ALNUMS4 = re.compile(r"[^\W_]{4,}")
_ALNUM = re.compile(r"[^\W_]{4,}")
_AROUND = " \t\r\n.,;:!?()[]{}<>\"'"
_LABEL = re.compile(r"(?:(?!https?:)[^\W\d_]+\.?(?:\s*[:#\-–—]+\s*|\s+)){1,4}")
_IBAN_LABEL = re.compile(r"(?:[^\W\d_]+\.?(?:\s*[:#,\-–—]+\s*|\s+)){1,4}")
_NAME_AFTER = re.compile(r"(?:[\s,]+\(?[A-Z][^\W\d_]*\)?){1,3}$")
_IBANS = re.compile(r"(?<![^\W_])[A-Za-z]{2}\d{2}(?:\s?[A-Za-z0-9]{4}){2,7}(?:\s?[A-Za-z0-9]{1,3})?(?![^\W_])")
_DIGIT_GROUPS = re.compile(r"(?<![^\W_])\+?\d(?:[\s.-]?\d){7,}(?![^\W_])")
_SEPARATED = re.compile(r"\s+(?:/|and|or)\s+|\s*[,;|&]\s*|\s+")
_QUOTED = re.compile(r"(?<!\w)'([^'\n]{3,}?)'(?!\w)|(?<!\w)\"([^\"\n]{3,}?)\"(?!\w)")
_WORD_TOKEN = re.compile(r"[^\W_]+(?:[-_.#/][^\W_]+)*")
_DIGITS = re.compile(r"\d+")
_DIGIT_ANY = re.compile(r"\d")
_UNIT = re.compile(r"\d+(?:ms|us|ns|s|sec|secs|m|min|mins|h|hr|hrs|d|w|wk|y|yr|yrs|k|kb|mb|gb|tb|px|em|pt|x|st|nd|rd|th"
                   r"|am|pm)")
_KEY_PART = re.compile(r"[^\W\d_]+|\d+")   # a run of letters, or of digits


class _Index:
    """The run's content and calls, read once and extended as its log grows (the live guard keeps it across its checks):
    reads, each content as (event, trust as recorded, label, text read plain, values, values read wider) in log order;
    seqs, theirs; by_val, the contents that hold each value; words and alnums, those that hold each word of 4 or more
    letters, digits or _ (and of letters and digits only); pre4, the lengths of the words by their first 4 characters;
    calls, each call as (seq, its arguments read plain, their values, those read wider, its event) in log order, with
    call_vals and call_words, the calls by their values and words, call_ix, each by its event (id()), call_of, the call
    whose result each content is; bound, the seq at which a call's result was observed as untrusted, by its content's
    index: a log the runtime wrote marks the call itself untrusted (`trust`), an older one has the agent observe the
    result as `tool:<name>` after the call, which makes every result of that content and tool, of that agent, untrusted
    from then on."""

    def __init__(self) -> None:
        self.n, self.last = 0, None   # events read, the last of them
        self.reads: List[Tuple] = []
        self.seqs: List[int] = []
        self.by_val: Dict[Tuple[str, str], List[int]] = {}
        self.words: Dict[str, List[int]] = {}
        self.alnums: Dict[str, List[int]] = {}
        self.pre4: Dict[str, Set[int]] = {}
        self.calls: List[Tuple] = []
        self.call_vals: Dict[Tuple[str, str], List[int]] = {}
        self.call_words: Dict[str, List[int]] = {}
        self.call_ix: Dict[int, int] = {}
        self.call_of: Dict[int, int] = {}
        self.bound: Dict[int, int] = {}
        self.keys: Dict[Tuple[str, ...], Tuple[int, List[int]]] = {}   # _key_holders: a key's holders, read so far
        self.ascii: Dict[int, str] = {}   # decimal(): a content's text with ASCII digits
        self.truncated: Set[int] = set()   # content with more values than were read (provenance.MAX_VALUES, MAX_TEXT)
        self.held: Dict[Tuple[int, Tuple[str, str], bool], bool] = {}   # full(): what their text was found to hold
        # in a log written before calls said their own trust: (agent, content, `tool:<name>`) -> the results not yet
        # observed, and the seq that content was first observed as untrusted at; from then on every result of it is
        self.recorded: Dict[Tuple[Any, ...], List[int]] = {}
        self.observed: Dict[Tuple[Any, ...], int] = {}

    def add(self, run: Run, memo: Dict[Any, Any], ev: Dict[str, Any]) -> None:
        if ev["type"] == "input":
            key = (ev["agent"], ev.get("ref"), ev.get("source"))
            if ev.get("trust") == "untrusted":
                self.observed.setdefault(key, ev["seq"])
                for i in self.recorded.pop(key, ()):
                    self.bound[i] = ev["seq"]
            self._content(ev, ev.get("trust", "trusted"), "task" if ev.get("kind") == "task" else
                          ev.get("source", "input"), _read(run, memo, ev, True))
        elif ev["type"] == "action":
            plain, cv, cw, _ = _read(run, memo, ev, False)
            j = len(self.calls)
            self.calls.append((ev["seq"], plain, cv, cw, ev))
            self.call_ix[id(ev)] = j
            for v in cv | cw:
                self.call_vals.setdefault(v, []).append(j)
            for w in set(_WORDS4.findall(plain)):
                self.call_words.setdefault(w, []).append(j)
            if ev.get("status") != "blocked":   # a call that ran: its result is content
                self.call_of[len(self.reads)] = j
                key = (ev["agent"], ev.get("result_ref"), "tool:" + ev["tool"])
                if key in self.observed:
                    self.bound[len(self.reads)] = ev["seq"]
                else:
                    self.recorded.setdefault(key, []).append(len(self.reads))
                self._content(ev, "untrusted" if ev.get("trust") == "untrusted" else "trusted", ev["tool"],
                              _read(run, memo, ev, True))

    def decimal(self, i: int) -> str:
        """Content `i`'s text read plain with every decimal digit as its ASCII digit (`٧٧٨١` is `7781`, as _wide reads
        other scripts' digits), read once."""
        if i not in self.ascii:
            t = self.reads[i][3]
            self.ascii[i] = t if t.isascii() else _DIGIT_ANY.sub(lambda m: str(unicodedata.digit(m.group())), t)
        return self.ascii[i]

    def full(self, i: int, v: Tuple[str, str], wide: bool) -> bool:
        """Whether content `i`, which holds more values than the index read, holds value `v` in its text (_bounded,
        `wide` as untrusted content is read), read once for each value."""
        key = (i, v, wide)
        if key not in self.held:
            self.held[key] = _bounded(_plain(v[1]), self.reads[i][3], wide)
        return self.held[key]

    def _content(self, ev: Dict[str, Any], trust: str, label: str, read: Tuple) -> None:
        i = len(self.reads)
        if read[3]:
            self.truncated.add(i)
        read = read[:3]
        self.reads.append((ev, trust, label, *read))
        self.seqs.append(ev["seq"])
        for v in read[1] | read[2]:
            self.by_val.setdefault(v, []).append(i)
        for w in set(_WORDS4.findall(read[0])):
            self.words.setdefault(w, []).append(i)
            self.pre4.setdefault(w[:4], set()).add(len(w))
        for w in set(_ALNUMS4.findall(read[0])):
            self.alnums.setdefault(w, []).append(i)


def _index(run: Run, memo: Dict[Any, Any]) -> _Index:
    """The run's _Index in `memo`, read on to the end of its log (anew for another log, with the rows read from it)."""
    ix = memo.get("index")
    if ix is None or len(run.events) < ix.n or ix.n and run.events[ix.n - 1] is not ix.last:
        ix = memo["index"] = _Index()
        memo.pop("rows", None)
        memo.pop("keys", None)
    for ev in run.events[ix.n:]:
        ix.add(run, memo, ev)
    ix.n, ix.last = len(run.events), run.events[-1] if run.events else None
    return ix


def _read(run: Run, memo: Dict[Any, Any], ev: Dict[str, Any], content: bool
          ) -> Tuple[str, Set[Tuple[str, str]], Set[Tuple[str, str]], bool]:
    """(the text read plain, the values the index reads, the values _wide reads, whether it holds more values than the
    index reads) of the content an event brought (`content`: an input's, a call's result), or of a call's arguments,
    each read once into `memo`; committed content has none."""
    key = ("read" if content else "args", ev["id"])
    if key not in memo:
        v = run.value(ev.get("args_ref") if not content else ev.get("ref") if ev["type"] == "input" else
                      ev.get("result_ref"))
        if _committed(v):
            memo[key] = "", set(), set(), False
        else:
            t = _text(v)
            vals, over = provenance.values(v)
            memo[key] = _plain(t), set(vals), _wide(t.lower() if content else t), over
    return memo[key]


_WIDE_DIGITS = re.compile(r"[0-9](?:[\W_]*[0-9])*")
_NUMBER_WORDS = {w: str(d) for d, w in enumerate("zero one two three four five six seven eight nine".split())}
_NUMBER_WORD = re.compile(r"\b(?:" + "|".join(_NUMBER_WORDS) + r")\b", re.I)
_AT = re.compile(r"\s*[\[(]?\s*\bat\b\s*[\])]?\s*", re.I)
_DOT = re.compile(r"\s*[\[(]?\s*\bdot\b\s*[\])]?\s*", re.I)


def _wide(text: str) -> Set[Tuple[str, str]]:
    """Values a text holds that the signer's index doesn't read: digit runs of 8 or more across any characters but
    letters between them (slashes, dashes, commas, line breaks), in another script's digits or written as words ("six
    zero one six"), and addresses spelled out ("audit at outside dot example"). Read in untrusted content only, where
    reading wider stops more, never fewer."""
    if not text.isascii():   # Arabic-Indic and other scripts' digits as the digits they are
        text = "".join(str(unicodedata.digit(c)) if unicodedata.digit(c, None) is not None else c for c in text)
    digits = _NUMBER_WORD.sub(lambda m: _NUMBER_WORDS[m.group(0).lower()], text)
    out = {("digits", d) for d in (re.sub("[^0-9]", "", m.group(0)) for m in _WIDE_DIGITS.finditer(digits))
           if len(d) >= 8}
    spelled = _DOT.sub(".", _AT.sub("@", text))
    if spelled != text:
        out |= {(k, v) for k, v in provenance.values(spelled)[0] if k in ("email", "host", "url")}
    return out


_ONE_WORD = re.compile(r"\w{8,256}")


def _split(p: str, k: int, ix: _Index, trust: Callable[[int], str]) -> Tuple[Set[int], List[str]]:
    """The untrusted contents before index `k` that hold atom `p` (read plain: one word of 8 to 256 letters, digits or
    _) in parts, each a whole word of one of them, from two or more of them: two parts of 4 or more characters, or more
    parts that each hold a digit too (an account number in pieces, not a name made of words), some part one no trusted
    content (the task included) holds (not a name the task gives, written as one word). The parts are looked up in the
    index's words (`ix.words`, by their lengths for their first 4 characters, `ix.pre4`)."""
    if not _ONE_WORD.fullmatch(p):
        return set(), []
    # a way to read p[:j] in parts: (the one content every part can come from, or -1 for two or more; every part holds
    # a digit; some part no trusted content holds; parts, 3 for three or more), each with how it was reached
    reach: List[Dict[tuple, tuple]] = [{} for _ in range(len(p) + 1)]
    reach[0][()] = ()
    for j in range(len(p) - 3):
        if not reach[j]:
            continue
        for size in ix.pre4.get(p[j:j + 4], ()):
            e = j + size
            if e > len(p):
                continue
            piece = p[j:e]
            hold = [i for i in ix.words.get(piece, ()) if i < k]
            u = frozenset(i for i in hold if trust(i) != "trusted")
            if not u:
                continue
            free, digit = not any(trust(i) == "trusted" for i in hold), any(c.isdigit() for c in piece)
            for st in list(reach[j]):
                if st:
                    one, nd, fr, n = st
                    new = (one if u == {one} else -1, nd and digit, fr or free, min(n + 1, 3))
                else:
                    new = (next(iter(u)) if len(u) == 1 else -1, digit, free, 1)
                reach[e].setdefault(new, (j, st, u))
    end = next((st for st in reach[len(p)] if st[0] == -1 and st[2] and (st[3] == 2 or st[3] == 3 and st[1])), None)
    out: Set[int] = set()
    pieces: List[str] = []
    e = len(p)
    while end:
        j, end, u = reach[e][end]
        out |= u
        pieces.insert(0, p[j:e])
        e = j
    return out, pieces


def suggest_target(run: Run, action_ev: Dict[str, Any], prov: Optional[List[Dict[str, Any]]] = None) -> str:
    spec = f"tool={action_ev['tool']}"
    pick = None
    if prov:
        pick = next((p["value"] for p in prov if p["status"] == "untrusted-only"), None)
    if pick is None:
        pick = next((a for a in atoms(run.value(action_ev["args_ref"])) if _EMAIL.fullmatch(a) or _URL.match(a)), None)
    if pick and "," not in pick and "=" not in pick and "~" not in pick:
        spec += f",arg~{pick}"
    return spec


# --------------------------------------------------------------------------- causes

def intervention_for(node: Dict[str, Any]) -> Optional[str]:
    ev = node["event"]
    if node["type"] == "input" and node.get("kind") != "task":
        return "input:" + glob_escape(ev["source"])
    if node["type"] == "message":
        return f"msg:{glob_escape(ev['agent'])}->{glob_escape(ev['to'])}"
    return None


def candidates(run: Run, g: Graph, action_node: str) -> List[Dict[str, Any]]:
    """Every upstream input and message channel of an action, with what is known about it:
    confirmed (tested, CI excludes 0), ruled-out (tested, any effect bounded below the minimum of
    interest), inconclusive (tested, the interval is too wide to say), or untested."""
    ev = g.nodes[action_node]["event"]
    anc = g.ancestors(action_node, ("observed",))
    hit_cache: Dict[str, bool] = {}

    def targets_this(spec: str) -> bool:
        if spec not in hit_cache:
            try:
                # the test is about this call only when its target matches no other call (graph._attach_tests)
                hit_cache[spec] = [h["id"] for h in target_hits(run, spec)] == [ev["id"]]
            except ValueError:
                hit_cache[spec] = False
        return hit_cache[spec]

    match_cache: Dict[str, set] = {}

    def matched(spec: str) -> set:
        if spec not in match_cache:
            try:
                match_cache[spec] = set(nodes_matching(g, spec))
            except ValueError:
                match_cache[spec] = set()
        return match_cache[spec]

    rows, seen = [], set()
    for nid in sorted(anc, key=lambda x: g.nodes[x]["seq"]):
        node = g.nodes[nid]
        spec = intervention_for(node)
        if not spec or spec in seen:
            continue
        seen.add(spec)
        tests = [t for t in run.tests if t.get("scope", "run") == "run" and targets_this(t["target"])
                 # a glob that removed several upstream items at once is not evidence about any single one
                 and (t["intervention"] == spec or matched(t["intervention"]) & anc == {nid})]
        best = max(tests, key=lambda t: (t["n"], abs(t["effect"])), default=None)
        if best is None:
            status = "untested"
        elif best["verdict"] == "causal":
            status = "contributing" if _role(best) == "contributing" else "confirmed"
        elif best["verdict"] == "suppressive":
            status = "suppressive"
        elif best["verdict"] == "not-applied":
            status = "untested"
        else:
            status = _settled(best)
        reuse = max((e.get("reuse", 0) for e in g.out_edges(nid, ("observed",))), default=0)
        rows.append({"node": nid, "label": node["label"], "kind": node["type"], "agent": node["agent"],
                     "trust": node.get("trust", "trusted"), "intervention": spec, "status": status,
                     "role": _role(best) if status in ("confirmed", "contributing") and best.get("p_with") is not None
                     else None,
                     "test": best, "reuse": reuse})
    order = {"confirmed": 0, "contributing": 1, "suppressive": 2, "inconclusive": 3, "untested": 4,
             "no-effect-seen": 5, "ruled-out": 6}
    rows.sort(key=lambda r: (order[r["status"]], -(r["test"]["effect"] if r["test"] else 0),
                             r["trust"] != "untrusted", -r["reuse"]))
    return rows


def _role(t: Dict[str, Any]) -> str:
    from .replay import role_for
    return t.get("role") or role_for(t.get("p_with") or 0, t["ci"])


def _settled(t: Dict[str, Any]) -> str:
    """ruled-out or inconclusive, also for tests saved before the two were told apart."""
    if t["verdict"] == "inconclusive" and t.get("stopped") == "futility":
        return "no-effect-seen"
    if t["verdict"] in ("ruled-out", "inconclusive"):
        return t["verdict"]
    lo, hi = t["ci"]
    m = t.get("min_effect", 0.2)
    return "ruled-out" if hi < m and lo > -m else "inconclusive"


LINEAGE_CHAINS = 20   # every input's chain would grow with the cube of a long run; candidates lists every input


def lineage(g: Graph, action_node: str) -> List[List[str]]:
    """The observed chains to the action from the LINEAGE_CHAINS nearest untrusted inputs (or, if none, inputs):
    shortest paths, all from one search back from the action."""
    nxt: Dict[str, Optional[str]] = {action_node: None}   # each ancestor's next step towards the action
    q = deque([action_node])
    while q:
        x = q.popleft()
        for e in g.in_edges(x, ("observed",)):
            if e["src"] not in nxt:
                nxt[e["src"]] = x
                q.append(e["src"])
    roots = [n for n in nxt if g.nodes[n]["type"] == "input" and g.nodes[n].get("trust") == "untrusted"] or \
            [n for n in nxt if g.nodes[n]["type"] == "input"]   # nearest first: nxt is in search order
    return [Graph.path(nxt, r)[::-1] for r in sorted(roots[:LINEAGE_CHAINS], key=lambda x: g.nodes[x]["seq"])]


# --------------------------------------------------------------------------- alerts

def alerts(run: Run, g: Graph) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    problems = integrity(run)
    if problems:
        out.append({"severity": "high", "title": "Log failed integrity check", "detail": problems[0], "node": None})
    for e in [*((run.start.get("meta") or {}).get("evidence_alerts") or []), *run.join_alerts]:  # capture gaps, a join
        out.append({"severity": "high", "title": e.get("title", "Evidence problem"), "detail": e.get("detail", ""),
                    "node": None})
    from . import influence
    from .import_v2 import content_checks
    goal = influence.goals(run, g)
    for c in content_checks(run):
        if c["verdict"] == "mismatched":
            out.append({"severity": "high", "title": "Content does not match what the signer committed to",
                        "detail": f"{c['kind']} of {c['agent']}: log seq {c['seq']} ({c['type']}). The why log's "
                                  "content was changed, or the record is about something else.",
                        "node": "ev:" + c["event"]})
    memo: Dict[Any, Any] = {}
    for nid, n in sorted(g.nodes.items(), key=lambda kv: kv[1]["seq"]):
        if n["type"] != "action":
            continue
        ev = n["event"]
        sens = is_sensitive(run, ev)
        prov = arg_provenance(run, g, ev, memo)
        bad = [p for p in prov if p["status"] == "untrusted-only" and not p.get("in_text")]
        quoted = [p for p in prov if p["status"] == "untrusted-only" and p.get("in_text")]
        untrusted_up = [g.nodes[a]["label"] for a in g.ancestors(nid, ("observed",))
                        if g.nodes[a]["type"] == "input" and g.nodes[a].get("trust") == "untrusted"] \
            if sens and not bad and ev.get("status") != "blocked" else []   # read only by the review alert
        base = {"node": nid, "tool": ev["tool"], "agent": ev["agent"], "seq": ev["seq"],
                "target": suggest_target(run, ev, prov), "sensitive": sens}
        got = influence.graded(g, nid, seen=False) if ev.get("status") != "blocked" else None
        u = got and influence.untrusted(got["edges"])
        if ev.get("status") == "blocked":
            pass  # reported below, once
        elif sens and bad:
            out.append({**base, "severity": "high",
                        "title": f"{ev['tool']} used a value that only untrusted content supplied",
                        "detail": only_untrusted(bad[0])})
        elif got and influence.drifted(got, goal):
            out.append({**base, "severity": "review", "title": f"{ev['tool']} serves no step of the task",
                        "detail": "A replay without the task kept it. See INFLUENCE for what it came from."})
        elif sens and quoted:
            out.append({**base, "severity": "review",
                        "title": f"{ev['tool']}'s text quotes a value that only untrusted content supplied",
                        "detail": only_untrusted(quoted[0])})
        elif u:
            out.append({**base, "severity": "review",
                        "title": f"{ev['tool']}'s `{u['field']}` traced to untrusted content" if u["grade"] == "exact"
                        else f"Untrusted content caused {ev['tool']}",
                        "detail": (f"{u['label']} holds the value, and nothing the signer indexed as trusted does."
                                   if u["grade"] == "exact" else
                                   f"A replay without {u['label']} changed it (effect {u['effect']:+.2f}).")
                        + " Test it without the task to see whether it serves the task."})
        elif sens and untrusted_up:
            out.append({**base, "severity": "review",
                        "title": f"Sensitive action {ev['tool']} is downstream of untrusted input",
                        "detail": "Reached from " + ", ".join(untrusted_up) + ". Reach is not cause; test it."})
        pol = ev.get("policy") or {}
        # a held call blocked at once whose retry ran under its approval is approved, as a call that ran itself
        if ev.get("status") == "blocked" and not (pol.get("approval") or {}).get("ran_by"):
            # a held call that no one approved never ran: it was held, not blocked
            said = answer(pol)
            title = (f"{ev['tool']} was held for approval and " + {
                "rejected": "rejected", "timed out": "timed out", "expired": "the approval expired", "abandoned":
                "the approval was abandoned", "revoked": "the approval was revoked"}.get(said, "not approved")
                if pol.get("decision") == "ask" else
                f"{ev['tool']} was blocked by " + ("Tracekit policy" if pol.get("decision") == "deny" else "the guard"))
            out.append({**base, "severity": "high", "title": title,
                        "detail": (ev.get("guard") or {}).get("reason", "")})
        elif ev.get("status") == "error":
            out.append({**base, "severity": "review", "title": f"{ev['tool']} failed",
                        "detail": _text(run.value(ev["result_ref"]))[:200]})
        if ev.get("mode") == "stub":
            out.append({**base, "severity": "info", "title": f"{ev['tool']} was stubbed in replay", "detail": ""})
    for ev in run.of_type("decision"):
        if ev.get("status") == "error":
            out.append({"severity": "review", "title": f"Model call failed ({ev['agent']})",
                        "detail": _text(run.value(ev["output"]))[:200], "node": "ev:" + ev["id"]})
    rank = {"high": 0, "review": 1, "info": 2}
    out.sort(key=lambda a: (rank[a["severity"]], a.get("seq", 0)))
    return out


# --------------------------------------------------------------------------- timeline

def _short(v: Any, n: int = 90) -> str:
    s = _text(v).replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


def timeline(run: Run) -> List[Dict[str, Any]]:
    rows = []
    t0 = None
    for ev in run.events:
        sec = ts_seconds(ev["ts"])
        t0 = sec if t0 is None else t0
        t = ev["type"]
        if t == "run.start":
            text = f"Run started ({ev.get('program') or 'unnamed program'})"
        elif t == "agent.start":
            text = f"{ev['agent']} joined" + (f", spawned by {ev['parent']}" if ev.get("parent") else "") + \
                   (f" ({ev['role']})" if ev.get("role") else "")
        elif t == "input":
            text = ("Task: " + _short(run.value(ev["ref"]), 120)) if ev.get("kind") == "task" else \
                   f"{ev['agent']} read {ev['source']}"
        elif t == "decision":
            srcs = [c["source"] or c["kind"] for c in ev["context"]]
            text = f"{ev['agent']} called {ev['model']} to {ev.get('purpose') or 'decide'} using {len(srcs)} inputs"
        elif t == "action":
            args = run.value(ev["args_ref"])
            text = f"{ev['agent']} {'was blocked from running' if ev.get('status') == 'blocked' else 'ran'} {ev['tool']}" \
                + ("" if _committed(args) else f"({_short(args, 70)})")
        elif t == "message":
            text = f"{ev['agent']} sent a message to {ev['to']}"
        elif t == "run.end":
            text = "Run finished"
        else:
            text = t
        rows.append({"seq": ev["seq"], "id": ev["id"], "node": "ev:" + ev["id"], "type": t, "agent": ev["agent"],
                     "t_ms": round((sec - t0) * 1000, 2), "duration_ms": ev.get("duration_ms"), "text": text,
                     "trust": ev.get("trust"), "status": ev.get("status"), "sensitive": ev.get("sensitive", False),
                     "mode": ev.get("mode"), "usage": ev.get("usage") or None})
    return rows


# --------------------------------------------------------------------------- summaries

def run_summary(run: Run, g: Optional[Graph] = None, al: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    g = g or build_graph(run, infer=False)
    al = alerts(run, g) if al is None else al
    task = next((run.value(e["ref"]) for e in run.of_type("input") if e.get("kind") == "task"), None)
    acts = run.of_type("action")
    decs = run.of_type("decision")
    usage = {"input_tokens": 0, "output_tokens": 0}
    for d in decs:
        for k in usage:
            usage[k] += _count((d.get("usage") if isinstance(d.get("usage"), dict) else {}).get(k))
    return {
        "run_id": run.run_id, "program": run.start.get("program", ""), "started": run.events[0]["ts"] if run.events else "",
        "task": task, "agents": sorted({e["agent"] for e in run.of_type("agent.start")}),
        "decisions": len(decs), "actions": len(acts), "messages": len(run.of_type("message")),
        "inputs": len([e for e in run.of_type("input") if e.get("kind") != "task"]),
        "untrusted_inputs": len([e for e in run.of_type("input") if e.get("trust") == "untrusted"]),
        "errors": len([e for e in acts + decs if e.get("status") == "error"]),
        "model_ms": round(sum(d.get("duration_ms") or 0 for d in decs), 2),
        "tool_ms": round(sum(a.get("duration_ms") or 0 for a in acts), 2),
        "usage": usage, "tests": len(run.tests),
        "confirmed_causes": len([t for t in run.tests if t["verdict"] == "causal" and not t.get("group")]),
        "alerts": {s: len([a for a in al if a["severity"] == s]) for s in ("high", "review", "info")},
        "integrity": "ok" if not integrity(run) else "failed",
        "tools_run": [a["tool"] for a in acts],
        "replayable": bool(run.start.get("program")),
        "finished": bool(run.events) and run.events[-1]["type"] == "run.end",
        "blocked": len([a for a in acts if a.get("status") == "blocked"]),
        "guard": (run.start.get("guard") or {}).get("mode"),
    }


def test_matrix(run: Run) -> Dict[str, Any]:
    rows: List[str] = []
    cols: List[str] = []
    cells: Dict[str, Dict[str, Any]] = {}
    for t in run.tests:
        if t.get("scope", "run") != "run":
            continue
        if t["intervention"] not in rows:
            rows.append(t["intervention"])
        if t["target"] not in cols:
            cols.append(t["target"])
        cells[t["intervention"] + "\u0000" + t["target"]] = t
    return {"rows": rows, "cols": cols,
            "cells": {k.replace("\u0000", "||"): v for k, v in cells.items()}}


def channel_report(run: Run, g: Graph) -> List[Dict[str, Any]]:
    """Per message channel: messages sent, how many were used by a later decision, and tested influence."""
    chans: Dict[str, Dict[str, Any]] = {}
    for n in g.nodes.values():
        if n["type"] != "message":
            continue
        key = f"{n['agent']}->{n['to']}"
        c = chans.setdefault(key, {"channel": key, "sent": 0, "used": 0, "tests": []})
        c["sent"] += 1
        if g.out_edges(n["id"], ("observed",)):
            c["used"] += 1
    for t in run.tests:
        if not t.get("group") and t["intervention"].startswith("msg:") and t["intervention"][4:] in chans:
            chans[t["intervention"][4:]]["tests"].append(t)
    return list(chans.values())


def investigation(run: Run) -> Dict[str, Any]:
    """Everything the investigation app needs for one run."""
    g = build_graph(run)
    al = alerts(run, g)
    actions, memo = {}, {}
    for nid, n in g.nodes.items():
        if n["type"] == "action":
            ev = n["event"]
            prov = arg_provenance(run, g, ev, memo)
            actions[nid] = {"provenance": prov, "candidates": candidates(run, g, nid),
                            "lineage": lineage(g, nid), "target": suggest_target(run, ev, prov),
                            "sensitive": is_sensitive(run, ev)}
    return {"graph": g, "alerts": al, "summary": run_summary(run, g, al), "timeline": timeline(run),
            "actions": actions, "matrix": test_matrix(run), "channels": channel_report(run, g)}


# --------------------------------------------------------------------------- workspace / influence graph

SEEN_KEPT = 5   # a source's occurrences listed (run, time, record); `runs` counts them all
CALLS_KEPT = 50   # risky calls INFLUENCE answers for, worst first; `calls_total` counts them all
ENDED = (None, "flagged", "held", "rejected", "blocked")   # how a call ended, worst last
# a person's answer to a held call, as an import (`decision`) or the runtime (`state`) records it
ANSWERS = {"approve": "approved", "approved": "approved", "reject": "rejected", "rejected": "rejected",
           "timeout": "timed out", "expired": "expired", "abandoned": "abandoned", "revoked": "revoked"}


def answer(policy: Dict[str, Any]) -> Optional[str]:
    """The answer to a held call (`policy`: its action's), in words: approved, rejected, timed out, expired, abandoned
    or revoked; None while nobody answered."""
    a = policy.get("approval") or {}
    return ANSWERS.get(a.get("decision") or a.get("state"))


def _ended(ev: Dict[str, Any]) -> Optional[str]:
    """How a call ended when it is one to look at: blocked (denied, or stopped by the guard), rejected (a person said
    no to it), held (a person's answer it never got) or flagged; else None."""
    p = ev.get("policy") or {}
    if p.get("decision") == "ask":
        said = answer(p)
        return None if said == "approved" else "rejected" if said == "rejected" else "held"
    return "blocked" if p.get("decision") == "deny" or ev.get("status") == "blocked" else \
        "flagged" if p.get("decision") == "flag" else None


def _reach(g: Graph) -> Tuple[List[str], Callable[[str], int]]:
    """(the run's calls in log order, a function giving the calls a node reaches over observed edges, the actions
    g.descendants finds from it, as a bit per call of that list), all worked out in one pass back through the log: an
    observed edge runs from an earlier event to a later one, so a node reaches itself (a call) and what its successors
    reach. A walk from each source instead took cubic time on a run whose model calls each see everything before them.
    A graph with an edge that runs back (none build_graph makes) is walked from each node."""
    order = sorted(g.nodes, key=lambda x: g.nodes[x]["seq"])
    calls = [x for x in order if g.nodes[x]["type"] == "action"]
    bit = {x: 1 << i for i, x in enumerate(calls)}
    reach: Dict[str, int] = {}
    for x in reversed(order):
        r = bit.get(x, 0)
        for e in g.out_edges(x, ("observed",)):
            if e["dst"] not in reach:
                return calls, lambda x: sum(bit.get(y, 0) for y in g.descendants([x]))
            r |= reach[e["dst"]]
        reach[x] = r
    return calls, reach.__getitem__


def _bits(r: int, calls: List[str]) -> Iterator[str]:
    """The calls of bits `r` (_reach's)."""
    while r:
        low = r & -r
        yield calls[low.bit_length() - 1]
        r ^= low


def influence_graph(runs: Iterable[Tuple[Run, Graph]]) -> Dict[str, Any]:
    """Cross-run, citation-like graph over (run, its graph without inferred edges) pairs. Sources are content (by
    hash); outcomes are tools. An edge says: in k runs this content was upstream of this tool (cited), and tests the
    code holding the run vouches for (Run.replayed) measured effect e; `ended`: how many of the calls it reached ended blocked, held or flagged (_ended). `groups`: the
    sources of each kind and trust (a harness's "<agent>:<kind>" source by its kind), in how many runs, the tools they
    reached in how many runs and the distinct calls of each that ended so, so hundreds of sources read at a glance, and
    in how many runs a call of each tool they reached ended blocked or held (`stopped_runs`). A source's `seen`: where
    it was read (its run's signed run id and agent, the time, the record's seq, its event's position in the why log),
    the first SEEN_KEPT."""
    from .influence import influences
    sources: Dict[str, Dict[str, Any]] = {}
    groups: Dict[Tuple[str, Any], Dict[str, Any]] = {}
    outcomes: Dict[str, Dict[str, Any]] = {}
    edges: Dict[str, Dict[str, Any]] = {}
    calls: List[Dict[str, Any]] = []
    for run, g in runs:
        calls += [{**c, "run": run.run_id} for c in influences(run, g, risky=True)]
        order, reach = _reach(g)
        tools: Dict[str, int] = {}   # each tool's calls and the calls that ended blocked, held or flagged, as _reach's bits
        ended = 0
        for i, x in enumerate(order):
            act = g.nodes[x]["event"]
            tools[act["tool"]] = tools.get(act["tool"], 0) | 1 << i
            ended |= (1 << i) if _ended(act) else 0
        for nid, n in g.nodes.items():
            if n["type"] != "input" or n.get("kind") == "task":
                continue
            ev = n["event"]
            kind = ev["source"].removeprefix(f"{ev.get('agent')}:")
            s = sources.setdefault(ev["ref"], {"id": ev["ref"], "labels": [], "trust": ev.get("trust"), "runs": 0,
                                               "cited_by": 0, "kind": kind,   # a signed run's: only committed
                                               "preview": "" if _committed(v := run.value(ev["ref"])) else _short(v, 140)})
            grp = groups.setdefault((s["kind"], s["trust"]), {"kind": s["kind"], "trust": s["trust"], "runs": set(),
                                                              "reach": {}, "ended": {}})
            grp["runs"].add(run.run_id)
            cite = ev.get("tracekit") or {}
            if len(s.setdefault("seen", [])) < SEEN_KEPT:
                s["seen"].append({"run": cite.get("run_id") or run.run_id, "agent": ev.get("agent"), "ts": ev.get("ts"),
                                  "seq": cite.get("seq"), "pos": ev.get("seq")})
            if ev["source"] not in s["labels"]:
                s["labels"].append(ev["source"])
            s["runs"] += 1
            s["cited_by"] += len([e for e in g.out_edges(nid, ("observed",)) if e["kind"].startswith("context")])
            reached = reach(nid)
            for tool in (t for t, bits in tools.items() if reached & bits):
                grp["reach"].setdefault(tool, set()).add(run.run_id)
                outcomes.setdefault(tool, {"id": tool, "runs": 0})
                e = edges.setdefault(ev["ref"] + "|" + tool, {"source": ev["ref"], "tool": tool, "reach_runs": 0,
                                                              "tests": [], "ended": {}})
                e["reach_runs"] += 1
            for x in _bits(reached & ended, order):
                act = g.nodes[x]["event"]
                how = _ended(act)
                e = edges[ev["ref"] + "|" + act["tool"]]
                e["ended"][how] = e["ended"].get(how, 0) + 1
                grp["ended"].setdefault(act["tool"], {}).setdefault(how, set()).add((run.run_id, x))
            spec = "input:" + glob_escape(ev["source"])
            for t in run.tests:   # replays the code holding the run vouches for: the log's own are its claim
                if t.get("scope", "run") == "run" and t["intervention"] == spec and chain_hash(t) in run.replayed:
                    tool = t["target"].split(",")[0].split("=", 1)[-1]
                    outcomes.setdefault(tool, {"id": tool, "runs": 0})
                    e = edges.setdefault(ev["ref"] + "|" + tool, {"source": ev["ref"], "tool": tool,
                                                                  "reach_runs": 0, "tests": [], "ended": {}})
                    e["tests"].append({"run": run.run_id, "target": t["target"], "effect": t["effect"],
                                       "ci": t["ci"], "verdict": t["verdict"], "n": t["n"]})
        for tool in {a["tool"] for a in run.of_type("action")}:
            outcomes.setdefault(tool, {"id": tool, "runs": 0})["runs"] += 1
    by_source: Dict[str, List[Dict[str, Any]]] = {}
    for e in edges.values():
        by_source.setdefault(e["source"], []).append(e)
        eff = [t["effect"] for t in e["tests"]]
        e["max_effect"] = max(eff) if eff else None
        e["confirmed"] = any(t["verdict"] == "causal" for t in e["tests"])
        e["ruled_out"] = bool(e["tests"]) and not e["confirmed"] and all(
            t["verdict"] != "causal" and _settled(t) == "ruled-out" for t in e["tests"])
    for s in sources.values():
        es = by_source.get(s["id"], [])
        s["max_effect"] = max([e["max_effect"] for e in es if e["max_effect"] is not None], default=None)
        s["confirmed_tools"] = sorted({e["tool"] for e in es if e["confirmed"]})
    src = sorted(sources.values(), key=lambda s: (-(s["max_effect"] or 0), -s["cited_by"]))
    # the calls to answer for first: those that serve no step of the task, then those tied to untrusted content, then
    # the worst ended, then the rest with an exact or measured edge, then those with untrusted content only in context;
    # otherwise in the order of the runs and their logs
    calls.sort(key=lambda c: (c["serves"] != "drift", not c["untrusted"], -ENDED.index(c["ended"]),
                              not any(e["grade"] in ("exact", "measured") for e in c["edges"])))
    return {"sources": src, "outcomes": sorted(outcomes.values(), key=lambda o: -o["runs"]),
            "edges": list(edges.values()), "calls": calls[:CALLS_KEPT], "calls_total": len(calls),
            "groups": [{**g, "runs": len(g["runs"]), "reach": {t: len(r) for t, r in g["reach"].items()},
                        "ended": {t: {how: len(c) for how, c in e.items()} for t, e in g["ended"].items()},
                        "stopped_runs": {t: n for t, e in g["ended"].items()
                                         if (n := len({r for how in ("blocked", "rejected", "held")
                                                       for r, _ in e.get(how, ())}))}}
                       for g in groups.values()]}


def broken_summary(path: str, err: Exception) -> Dict[str, Any]:
    """The workspace row of a run that cannot be analysed: listed, with why, so a bad log never hides a run."""
    return {"run_id": os.path.basename(path), "program": "", "started": "", "task": None, "agents": [], "decisions": 0,
            "actions": 0, "messages": 0, "inputs": 0, "untrusted_inputs": 0, "errors": 0, "model_ms": 0, "tool_ms": 0,
            "usage": {"input_tokens": 0, "output_tokens": 0}, "tests": 0, "confirmed_causes": 0,
            "alerts": {"high": 1, "review": 0, "info": 0}, "integrity": "failed", "tools_run": [], "replayable": False,
            "finished": False, "blocked": 0, "guard": None, "broken": f"{type(err).__name__}: {err}"[:300]}


def analyse(path: str, verify: Optional[Callable[[Run], Any]] = None) -> Dict[str, Any]:
    """What the workspace needs of one run folder: run, graph (no inferred edges), alerts and summary; or, for a run
    that cannot be analysed, its broken summary (listed with why, never dropped from the view). `verify`: the run's
    (Run.signed, Run.bound, Run.join_alerts) from signed records the caller holds; none without it."""
    try:
        run = load_run(path)
        if verify is not None:
            run.signed, run.bound, run.join_alerts = verify(run)
        return analysed_run(run, build_graph(run, infer=False))
    except Exception as e:
        if os.path.exists(os.path.join(path, "events.jsonl")) or not isinstance(e, FileNotFoundError):
            print(f"tracekit why: cannot analyse {path}: {e}", file=sys.stderr)
        return {"summary": broken_summary(path, e), "alerts": []}


def analysed_run(run: Run, g: Graph) -> Dict[str, Any]:
    al = alerts(run, g)
    return {"run": run, "graph": g, "alerts": al, "summary": run_summary(run, g, al)}


def workspace(paths: List[str], analysed: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Run summaries (newest first) and the influence graph; `analysed`: analyse() of each path, when cached."""
    items = analysed if analysed is not None else [analyse(p) for p in paths]
    runs = sorted((a["summary"] for a in items), key=lambda r: r["started"], reverse=True)
    return {"runs": runs, "influence": influence_graph((a["run"], a["graph"]) for a in items if "run" in a)}
