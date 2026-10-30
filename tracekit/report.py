"""`tracekit report`: what the agents did in a window, on one page, from the v2 signer's store
(docs/viewer.md#weekly-report).

For "what did our coding agents do this week?": the runs with a record in the window, by agent and identity; their
tool calls by decision; the holds, who answered them and the longest wait; the denies and flags by rule, each with up
to two example calls; the gaps by kind; and whether each run verifies. It reads the store as `tracekit view` does
(signer.service.reader, without the signer's lock, so the signer keeps running) and checks each run with view.check
(verify.v2 on the run's bundle, against the store's own log key or --log-vkey). Before any run is placed, every record
of the store, in every tenant and the signer's own runs, is checked against the newest checkpoint (_check_store): a
run holding a record that fails is listed as failed whatever its tenant and times, and one no checkpoint covers yet as
pending, so no time, tenant or run_id the store alone vouches for leaves a run out. A run is placed in the window by
its first and last records the checkpoint covers. Counts are of the records that verified, up to the newest
checkpoint, in the window; a run that fails is listed, never counted, and the command exits 1. A call is named as the
viewer names it: its tool and the field the tool is known by, from the dev signer's content vault when that signer is
running (view.dev_content_source: redacted arguments, and only those that open their record's commitment; each read
is a signed content.accessed record), else that its arguments aren't shown. It never starts a signer. An operator summary, not
evidence: its last lines say how to hand evidence over.

    tracekit report [--dev | --config signer.yaml | --data-dir DIR] [--log-vkey VKEY] [--since 7d|24h|DATE]
                    [--until DATE] [--tenant T] [--json]
"""
import argparse
import bisect
import collections
import datetime
import json
import os
import re
import shlex
import sys
import tempfile
import time

from . import view
from .format import canon, checkpoint
from .merkle import leaf_hash
from .merkle.tiles import MemoryTileStore, Tree
from .policy import subject
from .sdk import autospawn
from .sdk.client import Client, SignerUnavailable
from .signer.pipeline import SIGNER_RUN
from .signer.service import _escaped, dev_data_dir, load_config
from .storage.base import StorageCorrupt, StorageUnavailable
from .why.core import ts_seconds
from .why.signed import EvidenceAlert

DECISIONS = ("allow", "flag", "ask", "deny")
EXAMPLES = 2   # calls kept per rule
FLAGS_SHOWN = 6   # flag rules the text lists; --json has them all
CALL_WIDTH = 72   # characters of a call's arguments shown
TOP_GAPS = 3   # runs named under the gaps
EDITED = "was edited in the store (its hash doesn't match its event): listed whatever its tenant and times"
STORE_FAILED = "the store doesn't match the signer's checkpoint: listed whatever its times"
NO_ARGS = "arguments not shown (the record holds only their salted hash)"


def when(value, now=None):
    """--since/--until as seconds since the epoch: `<N>d` or `<N>h` before now, or an ISO 8601 date or time (UTC unless
    it names its offset)."""
    m = re.fullmatch(r"(\d+)([dh])", value)
    if m:
        return (time.time() if now is None else now) - int(m[1]) * (86400 if m[2] == "d" else 3600)
    try:
        t = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not 7d, 24h or an ISO date such as 2026-10-22") from None
    return (t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)).timestamp()


def call_text(tool, args):
    """A call as the viewer names it (policy.subject, as terminal.html's subject): its tool and the field that tool is
    known by, else its arguments; NO_ARGS without them."""
    if args is None:
        return f"{tool} · {NO_ARGS}"
    text = " ".join(subject(tool, args).split())
    return f"{tool} {text[:CALL_WIDTH]}" + "…" * (len(text) > CALL_WIDTH)


def _running():
    """A client of the dev signer that is running (autospawn.status's lookup): one that starts none, so a report with
    no signer running reads the store alone."""
    try:
        path, token = autospawn.address(autospawn.signer_dir(create=False))
    except ValueError as e:   # Windows: an endpoint.json without a port and token, or not JSON: no signer to read
        raise SignerUnavailable(str(e)) from None
    return Client(path, token=token)


def _check_store(r, size, root):
    """Every record of reader `r`, checked against the signer's checkpoint of `size` records and root `root` before any
    run is placed or counted, in every tenant and the signer's own runs, as verify.v2 checks a record: its hash is its
    event's, it is stored under the run its event names, and the hashes of the first `size` records make `root`. A
    store files a record under the tenant and run_id it holds (a file store reads them from the record), so an edit of
    those alone moves it to another run, the signer's or another tenant's: its hash then no longer matches.

    Returns (what fails the store as a whole, else None; {(tenant, run_id): what fails that run, for each run holding
    an edited record}; how many records were edited; how many records the store holds)."""
    tree, edited, n, count = Tree(MemoryTileStore()), {}, 0, 0
    for x in r.iter_range(0, sys.maxsize):
        seq, n = n, n + 1
        try:
            e = x["event"]
            key = e["tenant"], e["run_id"]
            seqs = (r.runs.get(key) or {}).get("seqs", ())
            i = bisect.bisect_left(seqs, seq)
            placed = e["seq"] == seq and i < len(seqs) and seqs[i] == seq   # a store may file it apart (Postgres)
            intact = canon.event_hash(e) == x["hash"]
            leaf = leaf_hash(bytes.fromhex(x["hash"][len("sha256:"):]))
        except (KeyError, TypeError, ValueError) as err:   # a record it can't read, or an event not canonical JSON
            return f"record {seq} can't be checked ({type(err).__name__})", edited, count, n
        if not placed:
            return f"record {seq} is stored under another run than the one it names", edited, count, n
        if not intact:
            count += 1
            edited.setdefault(key, f"record {seq} {EDITED}")
        if seq < size:
            tree.append(leaf)
    if tree.size < size:
        return f"the signer's checkpoint covers {size:,} records and the store holds {tree.size:,}", edited, count, n
    if size and tree.root() != root:
        return ("its records' hashes don't make the root of the signer's checkpoint: a record's hash was rewritten",
                edited, count, n)
    return None, edited, count, n


def _failed(rep):
    """The first failing check of verify.v2's report, with its first problem."""
    return next((f"{c['check']}: {(c['problems'] or [c['detail']])[0]}"[:200] for c in rep.checks
                 if c["status"] == "fail"), rep.integrity)


def _tally(key, records, tr, rules, unread):
    """Run `key`'s verified `records` in the window into `rules` ((decision, rule id, why) -> its count and up to
    EXAMPLES decisions, for each rule that matched a denied or flagged call; `why`: True for a rule of the section of
    that decision, False for one of another section that also matched, None for one this report can't place: an
    engine check, which has no section, or any rule of a policy it can't read) and `unread` (the denies and flags
    decided under a policy it can't read). Returns the calls held for a person (decided ask: tool_use_id -> when, its
    tool and its decision record) and, for each one answered, how long it waited for its first answer. What became of
    each hold is view.review's."""
    held, waits = {}, {}   # tool_use_id -> (when it was held, its tool, its record); tool_use_id -> its wait
    for x in records:
        e = x["event"]
        t, d = e["type"], e.get("data") or {}
        if t == "policy.decision" and d.get("decision") in ("deny", "flag"):
            secs = tr.reads(d).get("secs") or {}
            unread[d["decision"]] += d.get("policy_hash") not in tr.reasons
            for rule in tr.rules(d) or [{"id": "no rule", "reason": ""}]:
                why = (secs[rule["id"]] == d["decision"] if rule["id"] in secs else
                       True if rule["id"] == "no rule" else None)
                g = rules.setdefault((d["decision"], rule["id"], why), {
                    "decision": d["decision"], "rule": rule["id"], "why": why, "reason": rule["reason"], "count": 0,
                    "examples": []})
                g["count"] += 1
                if why and len(g["examples"]) < EXAMPLES:
                    g["examples"].append((key, x))
        elif t == "policy.decision" and d.get("decision") == "ask":
            held.setdefault(d.get("tool_use_id"), (ts_seconds(e["ts"]), d.get("tool"), x))
        elif t == "approval" and d.get("decision") in ("approve", "reject") and d.get("tool_use_id") in held:
            asked, tool, _ = held[d["tool_use_id"]]
            waits.setdefault(d["tool_use_id"], {"seconds": round(ts_seconds(e["ts"]) - asked), "tool": tool,
                                                "run_id": key[1]})
    return held, list(waits.values())


def _answer(a):
    """Who answered a hold (an entry of view.review's approvals), marked when they approved their own run's call (a
    rejection by the requester is no self-approval) or broke the glass."""
    return f"{a['approver']}" + " · self-approved" * (a["self_approved"] and a["decision"] == "approve") \
        + " · break-glass" * a["break_glass"]


def build(cfg, since, until, tenant=None, log_vkey=None, content=None, say=None, notes=()):
    """The report (what --json prints) of the runs of config `cfg`'s store with a record in [since, until), seconds since
    the epoch, of `tenant` or of every tenant. `content(run_id, records)`: the retained arguments of those decisions
    ({run_seq: args}), view.dev_content_source's. `say(text)`: told how many runs are checked before the checks.
    `notes`: lines the report shows as they are, such as why its calls show no arguments (the list that
    view.dev_content_source's `say` adds to while the report is built)."""
    vkeys, note = view.store_trust(cfg, log_vkey)
    tr = view.Translator(view.policy_reasons([cfg["policy"]] if cfg.get("policy") else [],
                                             cfg.get("data_dir") and os.path.join(cfg["data_dir"], "policies")))
    rules, waits, alerts, unread, hold_examples = {}, [], [], collections.Counter(), {}
    totals = {k: collections.Counter() for k in ("decisions", "holds", "answered", "gaps", "retries")}
    words = {}
    with tempfile.TemporaryDirectory(prefix="tk-report-") as tmp:
        trust = view.write_trust(os.path.join(tmp, "trust.json"), vkeys)
        r = view.reader(cfg)
        try:
            cp = r.checkpoint_latest()
            if cp and cp[0] > r.tree.size:   # a checkpoint written while it opened: read again, as StoreFeed.refresh
                r.close()
                r = view.reader(cfg)
            size, root = 0, None   # of the checkpoint, once its signature is checked: what places a run in time
            if cp:
                try:
                    _, size, root, _ = checkpoint.open_note(cp[1], vkeys)
                except checkpoint.NoteError as e:
                    raise ValueError(f"the store's newest checkpoint doesn't verify against the log key it pins ({e}), "
                                     "so no run's time can be read from it: pin the signer's key with --log-vkey "
                                     "(tracekit signer vkey)") from None
            problem, edited, count, held = _check_store(r, size, root)
            store = {"verdict": "failed" if problem or edited else "verified",
                     "detail": problem or count and f"{count:,} record{'s' * (count != 1)} edited (a record's hash "
                     "doesn't match its event): each run holding one is listed FAILED" or
                     f"every record matches the signer's checkpoint of {size:,} records",
                     "records": held, "covered": size, "newer": max(held - size, 0)}
            chosen = []   # (row, its run in the store, how many of its records to check: those the checkpoint covers)
            for key, run in sorted(r.runs.items()):
                why = edited.get(key) or problem and STORE_FAILED
                if not edited.get(key) and (key[1] == SIGNER_RUN[1] or tenant and key[0] != tenant):
                    continue   # checked above: listed only when it holds an edited record
                covered = bisect.bisect_left(run["seqs"], size)
                placed = 0 if why else covered   # the records that place it in time, and that its check reads
                first, last = [next(r.iter_range(s, s + 1)) for s in (run["seqs"][0], run["seqs"][placed - 1])]
                if placed:   # its first and last records the checkpoint covers, checked above: their times are signed
                    try:
                        if ts_seconds(last["event"]["ts"]) < since or ts_seconds(first["event"]["ts"]) >= until:
                            continue
                    except (KeyError, TypeError, ValueError):   # a signed time it can't read: shown, its check says why
                        pass
                # a run no checkpoint covers, or one that fails: named from the store, never counted
                d = first["event"].get("data") or {}
                name = (d.get("agent") or {}).get("name") if isinstance(d.get("agent"), dict) else None
                chosen.append(({"tenant": key[0], "run_id": key[1], "agent": name if isinstance(name, str) else None,
                                "identity": view._who(d["identity"]) if isinstance(d.get("identity"), dict) else None,
                                "first_ts": first["event"].get("ts"), "last_ts": last["event"].get("ts"),
                                "state": None, "verdict": "failed" if why else "pending",
                                "detail": why or "no checkpoint covers it yet",
                                "calls": {}, "gaps": 0, "not_covered": len(run["seqs"]) - covered},
                               run, placed))
            checked = [x for x in chosen if x[2]]
            if say and checked:
                say(f"checking {len(checked)} run{'s' * (len(checked) != 1)} ({sum(x[2] for x in checked):,} records) "
                    "with the verifier, as tracekit view does: a busy week takes minutes")
            runs = [row for row, *_ in chosen]
            for row, run, _ in checked:
                key = row["tenant"], row["run_id"]
                try:
                    rep, code, _, records = view.check(r, *key, cp[1], trust, os.path.join(tmp, "run.tkb"))
                except Exception as x:   # one run never stops the others being reported, as in the viewer
                    row.update(verdict="error", detail=f"not checked: {type(x).__name__}: {x}"[:200])
                    continue
                if code:
                    row.update(verdict="failed", detail=_failed(rep))
                    continue
                mine = [x for x in records if since <= ts_seconds(x["event"]["ts"]) < until]
                rv = view.review(mine, rep, "verified")
                row.update(verdict="verified", detail=rep.assurance.split(";")[0],
                           state=view.review(records, rep, "verified")["state"], calls=dict(rv["decisions"]),
                           gaps=sum(rv["gaps"].values()))
                held, held_waits = _tally(key, mine, tr, rules, unread)
                waits += held_waits
                for outcome, call in rv["hold_examples"].items():   # the first call of each outcome, of any run
                    if outcome not in hold_examples and call in held:
                        hold_examples[outcome] = key, held[call][2]
                totals["decisions"].update(rv["decisions"])
                totals["holds"].update(rv["holds"])
                totals["retries"]["n"] += rv["retries"]
                # answers to the holds in the window only, as Holds counts them
                totals["answered"].update(_answer(a) for a in rv["approvals"]
                                          if a["decision"] in ("approve", "reject") and a["tool_use_id"] in held)
                totals["gaps"].update(rv["gaps"])
                words.update(rv.get("gap_words", {}))
        finally:
            r.close()
    wanted = collections.defaultdict(list)   # a run's example decisions: one content read per run
    for key, x in [ex for g in rules.values() for ex in g["examples"]] + list(hold_examples.values()):
        wanted[key].append(x)
    args = {}
    for key, recs in wanted.items() if content else ():
        try:
            args.update({(key, s): a for s, a in content(key[1], recs).items()})
        except EvidenceAlert as x:   # the vault's content does not open its record: none of it is shown
            alerts.append(f"CONTENT NOT SHOWN for run {key[1]}: {x}")

    def example(key, x):
        e = x["event"]
        return {"run_id": key[1], "run_seq": e["run_seq"], "call": call_text(e["data"].get("tool"),
                                                                             args.get((key, e["run_seq"])))}
    for g in rules.values():
        shown = {}   # call text -> its example: the same call twice is shown once
        for key, x in g["examples"]:
            ex = example(key, x)
            shown.setdefault(ex["call"], ex)
        g["examples"] = list(shown.values())
    ok = [x for x in runs if x["verdict"] == "verified"]   # a run that doesn't verify names no agent or identity
    return {"window": {"since": _iso(since), "until": _iso(until)}, "source": view.store_name(cfg), "trust": note,
            "tenant": tenant, "store": store, "runs": runs,
            "by_agent": dict(collections.Counter(x["agent"] or "?" for x in ok).most_common()),
            "by_identity": dict(collections.Counter(x["identity"] for x in ok if x["identity"]).most_common()),
            "calls": {"total": sum(totals["decisions"].values()), **{k: totals["decisions"][k] for k in DECISIONS}},
            "holds": {"total": sum(totals["holds"].values()), "outcomes": dict(totals["holds"].most_common()),
                      "retries": totals["retries"]["n"],
                      "answered_by": dict(totals["answered"].most_common()),
                      "longest_wait": max(waits, key=lambda w: w["seconds"], default=None),
                      "examples": {o: example(*hold_examples[o]) for o, _ in totals["holds"].most_common()
                                   if o in hold_examples}},
            "rules": sorted(rules.values(), key=lambda g: (-g["count"], g["decision"], g["rule"], str(g["why"]))),
            "gaps": {"total": sum(totals["gaps"].values()), "by_kind": dict(totals["gaps"].most_common()),
                     "words": words},
            "notes": [f"{n:,} {'denied' if dec == 'deny' else 'flagged'} call{'s cite' if n != 1 else ' cites'} a "
                      "policy this report can't read (not shipped, not the --config policy, not kept readable in the "
                      "data dir's policies/), so none of their rules is placed as why: run it as the signer's user, or "
                      "pass the signer's --config" for dec, n in sorted(unread.items()) if n] + list(notes),
            "alerts": alerts, "label": view.OPERATOR_SIDE}


def _iso(secs):
    return datetime.datetime.fromtimestamp(secs, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _when(iso):
    return iso[:10] + " " + iso[11:16] + " UTC"


def _wait(s):
    return f"{s // 3600}h {s % 3600 // 60}m" if s >= 3600 else f"{s // 60}m {s % 60}s" if s >= 60 else f"{s}s"


def _counts(counter):
    return ", ".join(f"{k} {n:,}" for k, n in counter.items())


def text(rep, config=None, data_dir=None):
    """The report as plain text: a terminal's or an email's. `config`, `data_dir`: the store's, as the report was given
    it, for the command that exports a run."""
    w, runs, calls, holds, gaps = rep["window"], rep["runs"], rep["calls"], rep["holds"], rep["gaps"]
    ok = [x for x in runs if x["verdict"] == "verified"]
    out = [f"Tracekit report: {_when(w['since'])} to {_when(w['until'])}",
           f"Source: {rep['source']}" + (f" (tenant {rep['tenant']})" if rep["tenant"] else ""), "",
           f"Runs: {len(runs)}" + (f"   by agent{'' if len(ok) == len(runs) else f' (the {len(ok)} that verify)'}: "
                                   f"{_counts(rep['by_agent'])}" if ok else "")]
    if rep["by_identity"]:
        out.append(f"  by identity: {_counts(rep['by_identity'])}")
    out += ["", f"Tool calls: {calls['total']:,}   " + _counts({k: calls[k] for k in DECISIONS})]
    if holds["total"]:
        out += ["", f"Holds (calls held for a person): {holds['total']:,}   {_counts(holds['outcomes'])}"]
        if holds["retries"]:   # the asks that are no hold of their own
            out.append(f"  and {holds['retries']:,} of the agent's retries of a held call, under its approval: counted "
                       "with it")
        if holds["answered_by"]:
            out.append(f"  answered by: {_counts(holds['answered_by'])}")
        if holds["longest_wait"]:
            lw = holds["longest_wait"]
            out.append(f"  longest wait for an answer: {_wait(lw['seconds'])} ({lw['tool']}, run {lw['run_id']})")
        out += [f"  e.g. {o}: {x['call']}  (run {x['run_id']})" for o, x in holds["examples"].items()]
    for dec, title in (("deny", "Denied"), ("flag", "Flagged")):
        mine, flags = [g for g in rep["rules"] if g["decision"] == dec and g["why"]], dec == "flag"
        apart = [(f"also matched (not why it was {title.lower()})", False),
                 ("not placed (engine checks, which may be why, and rules of a policy this report can't read)", None)]
        if any(g["decision"] == dec for g in rep["rules"]):
            out += ["", f"{title} calls ({calls[dec]:,}), by rule (one call can match several rules):"]
            for g in mine[:FLAGS_SHOWN] if flags else mine:   # flags are many: the most frequent, one example each
                out.append(f"  {g['rule']}  {g['count']:,}  {g['reason']}".rstrip())
                out += [f"      e.g. {x['call']}  (run {x['run_id']})" for x in g["examples"][:1 if flags else None]]
            if flags and mine[FLAGS_SHOWN:]:
                out.append(f"  and {len(mine) - FLAGS_SHOWN} more flag rules (--json lists every rule)")
            for label, why in apart:
                them = {g["rule"]: g["count"] for g in rep["rules"] if g["decision"] == dec and g["why"] is why}
                if them:
                    out.append(f"  {label}: {_counts(them)}")
    if rep["notes"]:
        out += ["", *(f"Note: {n}" for n in rep["notes"])]
    if gaps["total"]:
        out += ["", f"Gaps (signed records that something may be missing): {gaps['total']:,}"]
        out += [f"  {k} {n:,}: {gaps['words'].get(k, k)}" for k, n in gaps["by_kind"].items()]
        most = sorted((x for x in runs if x["gaps"]), key=lambda x: -x["gaps"])[:TOP_GAPS]
        out.append("  most: " + ", ".join(f"run {x['run_id']} ({x['agent'] or '?'}) {x['gaps']:,}" for x in most))
    store = rep["store"]
    out += ["", "Integrity: " + ("the store FAILED; " if store["verdict"] != "verified" else "")
            + f"{len(ok)} of {len(runs)} runs verify"
            + (f" (assurance: {', '.join(sorted({x['detail'] for x in ok}))})" if ok else "")]
    if store["verdict"] != "verified":
        out.append(f"  {'FAILED':8} the store: {store['detail']}")
    for x in runs:
        # a signer's run, or another tenant's under --tenant, is listed only when it fails: its line names the tenant
        where = f", tenant {x['tenant']}" if x["run_id"] == SIGNER_RUN[1] or rep["tenant"] not in (None, x["tenant"]) \
            else ""
        if x["verdict"] != "verified":
            out.append(f"  {x['verdict'].upper():8} run {x['run_id']}{where} ({x['agent'] or '?'}): {x['detail']}")
        elif x["state"] != "final":
            out.append(f"  {'open':8} run {x['run_id']} ({x['agent'] or '?'}): verified to its latest checkpoint")
    if len(ok) < len(runs):
        out.append("  a run that doesn't verify is listed, not counted")
    if store["newer"]:   # the store's: such records may be of a run whose covered records are all before the window
        out.append(f"  not counted yet: {store['newer']:,} record{'s' * (store['newer'] != 1)} in the store newer than "
                   "the latest checkpoint")
    out += [f"  {a}" for a in rep["alerts"]]
    # tracekit export --v2 and tracekit signer trust name the store as the report was given it
    where = f" --config {shlex.quote(config)}" if config else \
        f" --data-dir {shlex.quote(os.path.abspath(data_dir))}" if data_dir else ""
    out += ["", "This is an operator summary, not evidence. To hand evidence to someone, export the run (a full run id "
                "from above) and a trust file that pins the signer's log key:",
            f"  tracekit export --v2{where}" + (f" --tenant {shlex.quote(rep['tenant'])}" if rep["tenant"] else "")
            + " --run <run id> -o run.tkb",
            f"  tracekit signer trust{where} -o trust.json"]
    out.append("They check the key in trust.json against their own copy of it, then: "
               "tracekit verify run.tkb --trust trust.json")
    return "\n".join(_escaped(line) for line in out)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tracekit report", description="what the agents did in a window, on one page, "
                                 "from the v2 signer's store (read as tracekit view reads it, while the signer runs): "
                                 "runs, tool calls, holds, denies and flags by rule, gaps and whether each run "
                                 "verifies. An operator summary, not evidence. (The compliance report of a bundle is "
                                 "tracekit-report, in contrib/proofpack.)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dev", action="store_true", help="the same-user dev signer's store (the default)")
    g.add_argument("--config", help="signer.yaml: report on its store")
    g.add_argument("--data-dir", help="a signer data dir (holds store/ and log.vkey)")
    ap.add_argument("--log-vkey", help="pin this log vkey (`tracekit signer vkey`) instead of the one the store names")
    ap.add_argument("--since", type=when, default="7d", help="7d, 24h, or an ISO date or time, UTC unless it says "
                                                             "(default: 7d)")
    ap.add_argument("--until", type=when, help="an ISO date or time, not included (default: now)")
    ap.add_argument("--tenant", help="this tenant's runs only (default: every tenant's)")
    ap.add_argument("--json", action="store_true", help="print the report as one JSON object")
    a = ap.parse_args(argv)
    try:
        cfg = load_config(a.config) if a.config else {"data_dir": a.data_dir or dev_data_dir()}
        dev, notes = not (a.config or a.data_dir), []
        rep = build(cfg, a.since, time.time() if a.until is None else a.until, a.tenant, a.log_vkey,
                    view.dev_content_source("tracekit report", _running, notes.append) if dev else None,
                    lambda s: print(f"tracekit report: {s}", file=sys.stderr, flush=True), notes)
    except (OSError, ValueError, StorageCorrupt, StorageUnavailable) as e:
        print(f"tracekit report: {e}", file=sys.stderr)
        return 1
    print(json.dumps(rep, indent=2) if a.json else text(rep, a.config, a.data_dir))
    # as tracekit verify: 1 when the store or a run fails, or a run couldn't be checked
    return int(rep["store"]["verdict"] != "verified" or any(x["verdict"] in ("failed", "error") for x in rep["runs"]))


if __name__ == "__main__":
    sys.exit(main())
