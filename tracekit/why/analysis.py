"""Investigation: alerts, argument provenance, candidate causes, timeline and workspace summaries.

Everything here is derived from the log and the tests recorded against it. Nothing calls a model.
"""
from __future__ import annotations

import bisect
import os
import re
import sys
import unicodedata
from collections import deque
from itertools import islice
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from .. import provenance
from .core import COMMITTED, UNFINISHED, Run, glob_escape, load_run, ts_seconds, verify
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
    """Values worth tracing back: addresses, URLs, whole string arguments of 6+ characters and numbers the signer's
    index reads (a digit run of 8 or more)."""
    out: List[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, str):
            found = _EMAIL.findall(v) + _URL.findall(v)
            out.extend(found)
            if not found and len(v) >= 6:
                out.append(v)
        elif isinstance(v, (int, float)) and not isinstance(v, bool) and provenance.values(v)[0]:
            out.append(str(v))

    walk(args)
    seen, uniq = set(), []
    for a in out:
        if a not in seen:
            seen.add(a)
            uniq.append(a)
    return uniq


def arg_provenance(run: Run, g: Graph, action_ev: Dict[str, Any], texts: Optional[List[Tuple]] = None,
                   memo: Optional[Dict[Any, Any]] = None) -> List[Dict[str, Any]]:
    """For each argument value, which earlier inputs or tool results hold it, read as the signer's index reads values
    (value_provenance).
    untrusted-only: only untrusted content brought it (the classic injection signature)
    trusted:        some trusted input (the task included) or tool result holds it
    generated:      no earlier source; the model produced it"""
    memo = {} if memo is None else memo
    ix = _index(run, memo, texts)
    j = ix[5].get(id(action_ev))
    if j is None:   # an event of another copy of the run
        return value_provenance(run, run.value(action_ev["args_ref"]), action_ev["seq"], texts, memo)
    _settle(run, memo, ix, {j})
    return memo["rows"][ix[3][j][0]]


def _committed(v: Any) -> bool:
    """A signed run's content, imported as only its commitment: the same placeholder everywhere, no value to trace."""
    return isinstance(v, dict) and v.get("content") == COMMITTED


def _texts(run: Run) -> List[Tuple]:
    """(event, its text lowercased, trust, label) of each input and each result of a call that ran, in log order; a
    committed one has no text."""
    untrusted_refs = {e["ref"] for e in run.of_type("input") if e.get("trust") == "untrusted"}
    # a tool result is untrusted when its content was also recorded as untrusted input, or when the
    # action itself is marked untrusted (e.g. a subagent's answer after it read untrusted content).
    # Not every result downstream of untrusted content: a trusted tool's own output stays trusted.
    texts = []
    for ev in run.events:
        if ev["type"] == "input":
            v = run.value(ev["ref"])
            texts.append((ev, "" if _committed(v) else _text(v).lower(), ev.get("trust", "trusted"),
                          "task" if ev.get("kind") == "task" else ev.get("source", "input")))
        elif ev["type"] == "action" and ev.get("status") != "blocked":
            # a tool result counts as untrusted if the same content was also recorded as untrusted input
            untrusted = ev["result_ref"] in untrusted_refs or ev.get("trust") == "untrusted"
            v = run.value(ev["result_ref"])
            texts.append((ev, "" if _committed(v) else _text(v).lower(),
                          "untrusted" if untrusted else "trusted", ev["tool"]))
    return texts


def value_provenance(run: Run, args: Any, before_seq: int, texts: Optional[List[Tuple]] = None,
                     memo: Optional[Dict[Any, Any]] = None) -> List[Dict[str, Any]]:
    """arg_provenance for argument values that need not be recorded yet: the live guard calls this before a tool runs,
    with before_seq past the end of the log. Each atom is read as the signer's index reads values (_holds); the hosts
    and digit runs of text a model wrote (_mentions) are atoms too, rows marked `in_text`.
    Untrusted content also brought an identifier (not text a model wrote, _prose) when it holds a value of it that no
    trusted content holds (an IBAN's digits written in groups, a URL's host), read wider than the index reads untrusted
    content (_wide), or when untrusted texts hold its parts (_split).
    A trusted call's result holds nothing an earlier call's arguments named (all of it, or its longest digit run) unless
    trusted content gave each argument that named it: an echo of the agent's own value (a lookup's error naming it, a
    validator returning it whole) didn't bring it, a lookup by a key the task gave did. A trusted call's result is
    untrusted content when only untrusted content brought every value of its arguments (a decoder, a calculator given
    the mail's values).
    texts: _texts(run); memo: the readings of the run's content and calls (each call's rows by its seq), kept across
    its calls; a log that grew keeps them, its index (memo["index"]) read again."""
    if _committed(args):   # a signed run's arguments: only their commitment, which is no argument value
        return []
    memo = {} if memo is None else memo
    ix = _index(run, memo, texts)
    while True:   # a reading that met calls not yet read reads them (_settle), then reads again
        need: Set[int] = set()
        rows = _rows(run, memo, ix, args, before_seq, need)
        if not need:
            return rows
        _settle(run, memo, ix, need)


def _settle(run: Run, memo: Dict[Any, Any], ix, need: Set[int]) -> None:
    """Reads the arguments of calls `need` (indices of the index's calls) into memo["rows"] (by the call's seq), and
    first those of the earlier calls each reading meets: the earliest first, so a chain of calls (each given the last
    one's result) is read without recursing as deep as it is long."""
    done, calls = memo.setdefault("rows", {}), ix[3]
    stack = sorted(need)
    while stack:
        j = stack[-1]
        if calls[j][0] in done:
            stack.pop()
            continue
        more: Set[int] = set()
        rows = _rows(run, memo, ix, run.value(calls[j][4].get("args_ref")), calls[j][0], more)
        more = {m for m in more if calls[m][0] not in done}
        if more:   # earlier calls, read first; then this one again
            stack += sorted(more)
        else:
            done[calls[j][0]] = rows
            stack.pop()


def _rows(run: Run, memo: Dict[Any, Any], ix, args: Any, before_seq: int, need: Set[int]) -> List[Dict[str, Any]]:
    """value_provenance's rows of `args` before `before_seq`; each earlier call whose rows (memo["rows"]) the reading
    needed and didn't have is added to `need`, and the rows are then provisional."""
    if _committed(args):
        return []
    reads, seqs, by_val, calls, call_of, _, words = ix
    done = memo.setdefault("rows", {})
    hashed = (run.start.get("meta") or {}).get("content_capture") == "hashed"
    k = bisect.bisect_left(seqs, before_seq)   # the content before the call
    trust_of: Dict[int, str] = {}

    def trust(i: int) -> str:   # a trusted call's result is untrusted when only untrusted content gave its arguments
        if i not in trust_of:
            t, j = reads[i][1], call_of.get(i)
            if t == "trusted" and j is not None:
                read = done.get(calls[j][0])
                if read is None:
                    need.add(j)
                elif read and all(r["status"] == "untrusted-only" for r in read):
                    t = "untrusted"
            trust_of[i] = t
        return trust_of[i]

    found = atoms(args)
    rows = []
    for a, in_text in [(a, False) for a in found] + [(m, True) for m in _mentions(args) if m not in found]:
        if hashed and a.startswith("sha256:"):  # a hash placeholder, not a value
            rows.append({"value": a, "status": "hashed", "sources": []})
            continue
        atom = _atom(a)
        p, word, vals, whole, wide_word = atom
        # what names the value, not a part of it others share: all of it, or its longest digit run (an IBAN's account)
        names = whole | set(sorted((v for v in vals if v[0] == "digits"), key=lambda v: len(v[1]))[-1:])
        echo = None
        for c, (seq, plain, cv, cw, _) in enumerate(calls):
            if seq >= before_seq:
                break
            if not (_holds(atom, plain, cv) or (cv | cw) & names):
                continue
            if seq not in done:
                need.add(c)
            elif _given(memo, done[seq], atom, names):
                continue
            echo = seq
            break

        def counts(i: int) -> bool:   # trusted content that may be this value's source: not a call's echo of it
            ev = reads[i][0]
            return trust(i) == "trusted" and (ev["type"] != "action" or echo is None or ev["seq"] < echo)
        held = {i for v in vals for i in by_val.get(v, ()) if i < k}   # what may hold it: a value of it, or its text
        if wide_word is not None:
            held |= {i for i in range(k) if p in reads[i][3] and wide_word.search(reads[i][3])}
        tv: Dict[Tuple[str, str], bool] = {}

        def trusted_val(v: Tuple[str, str]) -> bool:   # trusted content that may be the source holds value v of it
            if v not in tv:
                tv[v] = any(counts(i) for i in by_val.get(v, ()) if i < k)
            return tv[v]
        part = not _prose(a)   # an identifier, which a part only untrusted content holds came from that content
        halves = _split(p, k, words, trust) if word is not None else set()
        srcs = []
        for i in sorted(held | halves):
            ev, _, label, plain, rv, wide = reads[i]
            t = trust(i)
            if t == "trusted":
                if not (counts(i) and _holds(atom, plain, rv)):
                    continue
            elif not (_holds(atom, plain, rv, wide=True) or part and (
                    i in halves or any(not trusted_val(v) for v in (rv | wide) & vals))):
                continue
            srcs.append({"node": "ev:" + ev["id"], "label": label, "trust": t})
        if not srcs:
            status = "hashed" if hashed else "generated"  # with hashed capture there is no text to search
        elif all(s["trust"] == "untrusted" for s in srcs):
            status = "untrusted-only"
        else:
            status = "trusted"
        rows.append({"value": a, "status": status, "sources": srcs, **({"in_text": True} if in_text else {})})
    return rows


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


def _prose(s: str) -> bool:
    """Whether string `s` is text a model wrote (a message body, a summary): white space and two or more words of
    letters that aren't part of an address, host, URL or path. Anything else is an identifier (an account, an IBAN in
    groups, a name, a command's target)."""
    return _SPACE.search(s) is not None and next(islice(_WORD.finditer(s), 1, None), None) is not None


def _mentions(args: Any) -> List[str]:
    """The hosts and digit runs, as the signer's index reads them, in the text a model wrote into an argument (_prose),
    outside its addresses and URLs (atoms of their own): a body that quotes one an untrusted page gave is said, not
    stopped."""
    out: List[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, str) and _prose(v):
            rest = _URL.sub(" ", _EMAIL.sub(" ", v))
            out.extend(x for kind, x in provenance.values(rest, email_hosts=False)[0] if kind in ("host", "digits"))

    walk(args)
    return list(dict.fromkeys(out))


def _plain(s: str) -> str:
    """`s` as the signer's index reads text (provenance.norm: no format characters, NFKC), case folded, its white space
    one space and without the ' ', '.' or '-' between two digits: a digit run written in groups reads as one."""
    return " ".join(_DIGIT_SEP.sub("", provenance.norm(s)).casefold().split())


def _atom(a: str) -> Tuple[str, Optional["re.Pattern[str]"], Set[Tuple[str, str]], Set[Tuple[str, str]],
                             Optional["re.Pattern[str]"]]:
    """(atom `a` read plain, its whole-token pattern (None for an address, URL, host or digit run), the values the
    signer's index reads in it, those that are all of it, its pattern as untrusted content is read: a token that _ joins
    to another word too, as in 'External_')."""
    p, vals = _plain(a), set(provenance.values(a)[0])
    whole = {(k, v) for k, v in vals if k == "string" or _plain(v) == p}
    word = wide = None
    if not any(k != "string" for k, _ in whole):
        first, last, core = re.match(r"\w", p), re.search(r"\w$", p), re.escape(p)
        word = re.compile((r"(?<!\w)" if first else "") + core + (r"(?!\w)" if last else ""))
        wide = re.compile((r"(?<![^\W_])" if first else "") + core + (r"(?![^\W_])" if last else ""))
    return p, word, vals, whole, wide


def _holds(atom, plain: str, vals: Set[Tuple[str, str]], wide: bool = False) -> bool:
    """Whether content (its text read plain, the values the index reads in it) holds atom `atom` (_atom): an address,
    URL, host or digit run as a value of the content equal to it; a free string as a whole token of the text (not part
    of a longer word or digit run; `wide`, untrusted content: or joined to one by _), or as a whole value (the string a
    JSON result holds)."""
    p, word, _, whole, wide_word = atom
    w = wide_word if wide else word
    return bool(whole & vals) or w is not None and p in plain and w.search(plain) is not None


_WORDS4 = re.compile(r"\w{4,}")


def _index(run: Run, memo: Dict[Any, Any], texts: Optional[List[Tuple]]):
    """The run's content and calls, read once into `memo` for its calls: (each content as (event, trust, label, text
    read plain, values, values read wider) in log order, their seqs, the contents that hold each value, each call as
    (seq, its arguments read plain, their values, those read wider, its event) in log order, the call whose result each
    content is, each call by its event (id()), the contents that hold each word of 4 or more letters, digits or _)."""
    if "index" not in memo:
        reads = [(ev, trust, label, *_read(run, memo, ev, text))
                 for ev, text, trust, label in (_texts(run) if texts is None else texts)]
        trusts, before = [r[1] for r in reads], memo.get("trusts", [])
        if trusts[:len(before)] != before:   # an earlier result's content was observed as untrusted since: read again
            memo.pop("rows", None)
        memo["trusts"] = trusts
        by_val: Dict[Tuple[str, str], List[int]] = {}
        words: Dict[str, List[int]] = {}
        for i, r in enumerate(reads):
            for v in r[4] | r[5]:
                by_val.setdefault(v, []).append(i)
            for w in set(_WORDS4.findall(r[3])):
                words.setdefault(w, []).append(i)
        events = [e for e in run.events if e["type"] == "action"]
        calls = [(e["seq"], *_read(run, memo, e, None), e) for e in events]
        call_ix = {id(e): j for j, e in enumerate(events)}
        call_of = {i: call_ix[id(r[0])] for i, r in enumerate(reads)
                   if r[0]["type"] == "action" and id(r[0]) in call_ix}
        memo["index"] = reads, [r[0]["seq"] for r in reads], by_val, calls, call_of, call_ix, words
    return memo["index"]


def _read(run: Run, memo: Dict[Any, Any], ev: Dict[str, Any], text: Optional[str]
          ) -> Tuple[str, Set[Tuple[str, str]], Set[Tuple[str, str]]]:
    """(the text read plain, the values the index reads, the values _wide reads) of the content an event brought
    (`text`: _texts'), or of a call's arguments (text None), each read once into `memo`."""
    key = ("read" if text is not None else "args", ev["id"])
    if key not in memo:
        v = run.value(ev.get("args_ref") if text is None else ev.get("ref") if ev["type"] == "input" else
                      ev.get("result_ref"))
        if _committed(v):
            memo[key] = "", set(), set()
        else:
            t = _text(v) if text is None else text
            memo[key] = _plain(t), set(provenance.values(v)[0]), _wide(t)
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


def _split(p: str, k: int, words: Dict[str, List[int]], trust: Callable[[int], str]) -> Set[int]:
    """The untrusted contents before index `k` that hold atom `p` (read plain: one word of 8 to 256 letters, digits or
    _) in parts, each a whole word of one of them, from two or more of them: two parts of 4 or more characters, or more
    parts that each hold a digit too (an account number in pieces, not a name made of words), some part one no trusted
    content (the task included) holds (not a name the task gives, written as one word). `words`: the contents that hold
    each word of 4 or more characters."""
    if not _ONE_WORD.fullmatch(p):
        return set()
    # a way to read p[:j] in parts: (the one content every part can come from, or -1 for two or more; every part holds
    # a digit; some part no trusted content holds; parts, 3 for three or more), each with how it was reached
    reach: List[Dict[tuple, tuple]] = [{} for _ in range(len(p) + 1)]
    reach[0][()] = ()
    for j in range(len(p) - 3):
        if not reach[j]:
            continue
        for e in range(j + 4, len(p) + 1):
            piece = p[j:e]
            hold = [i for i in words.get(piece, ()) if i < k]
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
    j = len(p)
    while end:
        j, end, u = reach[j][end]
        out |= u
    return out


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
    texts, memo = _texts(run), {}
    for nid, n in sorted(g.nodes.items(), key=lambda kv: kv[1]["seq"]):
        if n["type"] != "action":
            continue
        ev = n["event"]
        sens = is_sensitive(run, ev)
        prov = arg_provenance(run, g, ev, texts, memo)
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
                        "detail": f"'{bad[0]['value']}' appears only in " +
                                  ", ".join(s["label"] for s in bad[0]["sources"]) + "."})
        elif got and influence.drifted(got, goal):
            out.append({**base, "severity": "review", "title": f"{ev['tool']} serves no step of the task",
                        "detail": "A replay without the task kept it. See INFLUENCE for what it came from."})
        elif sens and quoted:
            out.append({**base, "severity": "review",
                        "title": f"{ev['tool']}'s text quotes a value that only untrusted content supplied",
                        "detail": f"'{quoted[0]['value']}' appears only in " +
                                  ", ".join(s["label"] for s in quoted[0]["sources"]) + "."})
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
            answer = (pol.get("approval") or {}).get("decision")
            title = (f"{ev['tool']} was held for approval and " + {
                "reject": "rejected", "timeout": "timed out", "expired": "the approval expired", "abandoned":
                "the approval was abandoned", "revoked": "the approval was revoked"}.get(answer, "not approved")
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
    actions, texts = {}, _texts(run)
    for nid, n in g.nodes.items():
        if n["type"] == "action":
            ev = n["event"]
            prov = arg_provenance(run, g, ev, texts)
            actions[nid] = {"provenance": prov, "candidates": candidates(run, g, nid),
                            "lineage": lineage(g, nid), "target": suggest_target(run, ev, prov),
                            "sensitive": is_sensitive(run, ev)}
    return {"graph": g, "alerts": al, "summary": run_summary(run, g, al), "timeline": timeline(run),
            "actions": actions, "matrix": test_matrix(run), "channels": channel_report(run, g)}


# --------------------------------------------------------------------------- workspace / influence graph

SEEN_KEPT = 5   # a source's occurrences listed (run, time, record); `runs` counts them all
CALLS_KEPT = 50   # risky calls INFLUENCE answers for, worst first; `calls_total` counts them all
ENDED = (None, "flagged", "held", "blocked")   # how a call ended, worst last


def _ended(ev: Dict[str, Any]) -> Optional[str]:
    """How a call ended when it is one to look at: blocked (denied, or stopped by the guard), held (a person's answer it
    never got, or a no) or flagged; else None."""
    p = ev.get("policy") or {}
    if p.get("decision") == "ask":
        return None if (p.get("approval") or {}).get("decision") == "approve" else "held"
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
    hash); outcomes are tools. An edge says: in k runs this content was upstream of this tool (cited), and tests
    measured effect e; `ended`: how many of the calls it reached ended blocked, held or flagged (_ended). `groups`: the
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
            for t in run.tests:
                if t.get("scope", "run") == "run" and t["intervention"] == spec:
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
                                         if (n := len({r for how in ("blocked", "held") for r, _ in e.get(how, ())}))}}
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
