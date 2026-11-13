"""Bounded exhaustive checks (#487): every case within a stated bound, not a sample, so a pass proves the property
within the bound and a failure is a real bug. The decision logic over its whole finite domain; RFC 9162 Merkle proofs
for every tree size up to MERKLE_N (TRACEKIT_BOUND_MERKLE raises it); both v2 verifiers against every structural
mutation of the golden closed bundle, run-set and run in parts (tests/test_verify_v2_property.py samples bit flips of
the first)."""
import base64
import collections
import importlib.util
import itertools
import json
import os
import shutil
import tempfile
import unittest
import zipfile

import test_signer_service as ts
import test_ts_verifier as tv
from factories import process_pool, signer_without_fsync
from test_verify_v2_property import zipped

from tracekit import merkle
from tracekit.format.canon import event_hash
from tracekit.policy2 import compile as pc
from tracekit.policy2.engine import Engine
from tracekit.signer import service as svc
from tracekit.signer.quotas import Limits
from tracekit.signer.rpc_schema import RPCError
from tracekit.signer.service import STRICTNESS, _stricter
from tracekit.verify import v2

ENGINES = ("re2", "regex") if importlib.util.find_spec("re2") else ("regex",)

MERKLE_N = int(os.environ.get("TRACEKIT_BOUND_MERKLE", "32"))
LEAVES = [merkle.leaf_hash(b"leaf %d" % i) for i in range(MERKLE_N)]
ROOTS = [None] + [merkle.root(LEAVES[:n]) for n in range(1, MERKLE_N + 1)]
# another tree of each size: the same first n-1 leaves and another last one
FORKS = [None] + [merkle.root(LEAVES[:n - 1] + [merkle.leaf_hash(b"fork")]) for n in range(1, MERKLE_N + 1)]
OTHER, FORK = merkle.leaf_hash(b"other"), merkle.leaf_hash(b"fork")


def changed(h):
    return bytes([h[0] ^ 1]) + h[1:]


def one_edit(proof):
    """Every proof one edit away from `proof`: a hash changed or dropped at any place, or one added at any place."""
    for j in range(len(proof)):
        yield proof[:j] + [changed(proof[j])] + proof[j + 1:]
        yield proof[:j] + proof[j + 1:]
    for j in range(len(proof) + 1):
        yield proof[:j] + [OTHER] + proof[j:]


class MerkleProofs(unittest.TestCase):
    def test_inclusion(self):
        """Every size n <= MERKLE_N and index i: the proof verifies; no proof one edit away, no other leaf, index or
        root of this tree does. A checkpoint signs its size and root together, so another size is tried only with its
        own root, and verifies only where that tree's proof is the same proof (RFC 9162 takes the pair as given)."""
        for n in range(1, MERKLE_N + 1):
            for i in range(n):
                p = merkle.inclusion_proof(i, LEAVES[:n])

                def ok(index=i, size=n, leaf=LEAVES[i], proof=p, root=ROOTS[n]):
                    return merkle.verify_inclusion(index, size, leaf, proof, root)
                self.assertTrue(ok(), (n, i))
                for q in one_edit(p):
                    self.assertFalse(ok(proof=q), (n, i, q))
                for j in range(-1, n + 1):
                    if j != i:
                        self.assertFalse(ok(index=j), (n, i, j))
                        self.assertFalse(ok(leaf=LEAVES[j] if 0 <= j < n else OTHER), (n, i, j))
                for m in range(1, MERKLE_N + 1):
                    if m != n:
                        self.assertFalse(ok(root=ROOTS[m]), (n, i, m))
                        same = i < m and p == merkle.inclusion_proof(i, LEAVES[:m])
                        self.assertEqual(ok(size=m, root=ROOTS[m]), same, (n, i, m))

    def test_consistency(self):
        """Every 1 <= m <= n <= MERKLE_N: the proof verifies; no proof one edit away does, nor the roots swapped, nor
        another tree's root for either size; a history rewritten anywhere inside the first tree never proves consistent
        with the first tree's root, with its own proof (what a witness refuses); another size, with its own root,
        verifies only where that pair's proof is the same proof."""
        for n in range(1, MERKLE_N + 1):
            for m in range(1, n + 1):
                p = merkle.consistency_proof(m, LEAVES[:n])

                def ok(first=m, second=n, first_root=ROOTS[m], second_root=ROOTS[n], proof=p):
                    return merkle.verify_consistency(first, second, first_root, second_root, proof)
                self.assertTrue(ok(), (m, n))
                for q in one_edit(p):
                    self.assertFalse(ok(proof=q), (m, n, q))
                self.assertFalse(ok(first_root=FORKS[m]), (m, n))
                self.assertFalse(ok(second_root=FORKS[n]), (m, n))
                for j in range(m):
                    forked = LEAVES[:j] + [FORK] + LEAVES[j + 1:n]
                    self.assertFalse(ok(second_root=merkle.root(forked), proof=merkle.consistency_proof(m, forked)),
                                     (m, n, j))
                if m != n:
                    self.assertFalse(ok(first_root=ROOTS[n], second_root=ROOTS[m]), (m, n))
                self.assertFalse(ok(first=0), (m, n))
                for k in range(1, MERKLE_N + 1):
                    if k != m:
                        same = k <= n and p == merkle.consistency_proof(k, LEAVES[:n])
                        self.assertEqual(ok(first=k, first_root=ROOTS[k]), same, (m, n, k))
                    if k != n:
                        same = m <= k and p == merkle.consistency_proof(m, LEAVES[:k])
                        self.assertEqual(ok(second=k, second_root=ROOTS[k]), same, (m, n, k))


# two rules per section, and an exemption on the first deny rule
TOKENS = ("zzdeny1", "zzdeny2", "zzask1", "zzask2", "zzflag1", "zzflag2", "zzsafe")
RULES = (("D1", "deny", "zzdeny1"), ("D2", "deny", "zzdeny2"), ("A1", "ask", "zzask1"), ("A2", "ask", "zzask2"),
         ("F1", "flag", "zzflag1"), ("F2", "flag", "zzflag2"))
# the sections in the reverse of their precedence, and the tokens below in the reverse of the rules' order, so neither
# file order nor command order can stand in for the order the engine owes
POLICY = """tools: {Bash: shell}
flag:
  - {id: F1, class: shell, pattern: 'zzflag1'}
  - {id: F2, class: shell, pattern: 'zzflag2'}
ask:
  - {id: A1, class: shell, pattern: 'zzask1'}
  - {id: A2, class: shell, pattern: 'zzask2'}
deny:
  - {id: D1, class: shell, pattern: 'zzdeny1', unless: 'zzsafe'}
  - {id: D2, class: shell, pattern: 'zzdeny2'}
"""


def compiled(text):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "p.yaml")
        with open(path, "w") as f:
            f.write(text)
        pol, errs = pc.build(path)
    assert not errs, errs
    return pol


class DecisionLogic(unittest.TestCase):
    def test_the_highest_matched_section_decides_and_names_every_matched_rule(self):
        """All 128 combinations of the tokens in one command, on every engine: the verdict is the first of deny, ask
        and flag with a matching rule (else allow), and the rule ids are exactly the matching rules, deny's first, each
        section's in its order; D1's `unless` exempts it, and only it."""
        pol = compiled(POLICY)
        for engine in ENGINES:
            e = Engine(pol, engine)
            for k in range(len(TOKENS) + 1):
                for present in itertools.combinations(TOKENS, k):
                    hit = [(rid, sec) for rid, sec, token in RULES
                           if token in present and not (rid == "D1" and "zzsafe" in present)]
                    verdict = next((s for s in ("deny", "ask", "flag") if any(sec == s for _, sec in hit)), "allow")
                    hit = [rid for rid, _ in hit]
                    d = e.decide("Bash", {"command": " ".join(("echo",) + present[::-1])})
                    self.assertEqual((d["verdict"], d["rule_ids"]), (verdict, hit), (engine, present))

    def test_unknown_tools_and_unreadable_commands_get_their_sections_verdict(self):
        """Every `unknown_tools` and `on_parse_error` setting: an unmapped tool gets TK-UNKNOWN-TOOL in that section
        (allow when unset or `allow`), and a command the parser can't read gets TK-SHELL-PARSE in its section (ask when
        unset)."""
        for setting in (None, "allow", "flag", "ask", "deny"):
            pol = compiled(POLICY + (f"unknown_tools: {setting}\n" if setting else ""))
            for engine in ENGINES:
                d = Engine(pol, engine).decide("SomeNewTool", {"x": "zzdeny1"})
                self.assertEqual((d["verdict"], d["rule_ids"]),
                                 (setting, ["TK-UNKNOWN-TOOL"]) if setting not in (None, "allow") else ("allow", []),
                                 (setting, engine))
        for setting in (None, "ask", "deny"):
            pol = compiled(POLICY + (f"on_parse_error: {setting}\n" if setting else ""))
            for engine in ENGINES:
                d = Engine(pol, engine).decide("Bash", {"command": "echo 'unclosed"})
                self.assertEqual((d["verdict"], d["rule_ids"]), (setting or "ask", ["TK-SHELL-PARSE"]),
                                 (setting, engine))

    def test_stricter_over_its_whole_domain(self):
        """_stricter on every pair of readings from a domain covering its cases: the verdict is the stricter of the two
        (the first on a tie, with that reading's other fields), never weaker than either; rule ids are the ordered
        union; nondeterministic is the OR; oversize the ordered union, absent when both are."""
        ids = ([], ["X"], ["Y"], ["X", "Y"], ["Y", "X"])
        over = (None, ["o1"], ["o2"], ["o1", "o2"])
        readings = []
        for verdict, rule_ids, nondet, oversize in itertools.product(STRICTNESS, ids, (False, True), over):
            r = {"verdict": verdict, "rule_ids": rule_ids, "which": len(readings)}
            if nondet:
                r["nondeterministic"] = True
            if oversize:
                r["oversize"] = oversize
            readings.append(r)
        for a, b in itertools.product(readings, readings):
            d = _stricter(a, b)
            rank = STRICTNESS.index
            first = a if rank(a["verdict"]) >= rank(b["verdict"]) else b
            self.assertEqual(d["verdict"], first["verdict"])
            self.assertEqual(d["which"], first["which"])
            self.assertGreaterEqual(rank(d["verdict"]), max(rank(a["verdict"]), rank(b["verdict"])))
            self.assertEqual(d["rule_ids"], list(dict.fromkeys(a["rule_ids"] + b["rule_ids"])))
            self.assertEqual(d.get("nondeterministic", False),
                             bool(a.get("nondeterministic") or b.get("nondeterministic")))
            union = list(dict.fromkeys(a.get("oversize", []) + b.get("oversize", [])))
            self.assertEqual(d.get("oversize"), union or None)


GOLDEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden")


def verdict(code, integrity, assurance, checks):
    """What both verifiers must agree on (test_ts_verifier's Agreement.agree): the exit code, integrity, assurance and
    each line's check and status."""
    return code, integrity, assurance, [(c["check"], c["status"]) for c in checks]


def cut_back(entries):
    """The integrity a run cut back to a record may read (docs/limits.md, "A run cut back"): `VERIFIED TO HEAD n
    (open)` for the run's new last record, when the bundle has that record's inclusion proof; else None."""
    files = dict(entries)
    try:
        last = json.loads(next(b for n, b in entries if n.startswith("runs/")).split(b"\n")[-2])["event"]
        proofs = json.loads(files["proofs/records.json"])["inclusion"]
    except (StopIteration, IndexError, KeyError, ValueError, TypeError):
        return None
    return f"VERIFIED TO HEAD {last['run_seq']} (open)" if str(last.get("seq")) in proofs else None


class EveryStructuralMutation(unittest.TestCase):
    """Each mutation of BUNDLE refreshes the manifest's hashes, as anyone rewriting a bundle would. None verifies; a run
    cut back to a record whose inclusion proof the bundle holds reads open (exit 0) and never closed, since nothing in
    one run's bundle shows the dropped records (docs/limits.md, "A run cut back"; a run-set bundle shows them). The
    TypeScript verifier reads every mutation as the reference does (test_ts_verifier's agreement), and the Go one gives
    each its verdict (test_go_verifier.py)."""
    BUNDLE, TRUST = os.path.join(GOLDEN, "v2", "closed.tkb"), os.path.join(GOLDEN, "v2", "trust.json")

    @classmethod
    def setUpClass(cls):
        with zipfile.ZipFile(cls.BUNDLE) as z:
            cls.entries = [(n, z.read(n)) for n in z.namelist()]
        # entries the bundle may omit and still verify: the Rekor anchor is optional evidence
        cls.required = [i for i, (n, _) in enumerate(cls.entries) if not n.startswith(("rekor/", "tsa/"))]
        cls.lines = [i for i, (n, b) in enumerate(cls.entries) if n.endswith((".jsonl", ".note"))]   # one or many

    def setUp(self):
        self.d, self.made = tempfile.mkdtemp(), []   # each mutation's file and the reference's verdict on it
        self.addCleanup(shutil.rmtree, self.d, True)

    def outcome(self, entries):
        path = os.path.join(self.d, f"{len(self.made)}.tkb")
        with open(path, "wb") as f:
            f.write(zipped(entries, self.entries))
        rep, code = v2.verify(path, self.TRUST)   # raising fails the test
        rated = v2.NOT_RATED if code == v2.EXIT_FAIL else rep.assurance   # as --json gives it
        self.made.append((path, verdict(code, rep.integrity, rated, rep.checks)))
        return code, rep.integrity

    def assert_none(self, wrong):
        """No mutation verified, and the TypeScript verifier gives each the reference's verdict."""
        self.assertEqual(wrong, [])
        if not tv.SKIP:
            ts = tv.ts_verify_many([(path, self.TRUST) for path, _ in self.made])
            self.assertEqual([(path, got) for (path, want), got in zip(self.made, (
                verdict(t["exit_code"], t["integrity"], t["assurance"], t["checks"]) for t in ts)) if got != want], [])

    def check(self, entries, what, wrong):
        code, integrity = self.outcome(entries)
        if not (code in (1, 2) and integrity != "VERIFIED" or code == 0 and integrity == cut_back(entries)):
            wrong.append((what, code, integrity))

    def test_every_entry_dropped_duplicated_or_added(self):
        """Every entry the bundle needs dropped, every entry duplicated, and, listed in the manifest, every entry added
        under a name no bundle holds, and the trust config and a script added (a bundle carries neither)."""
        entries, wrong = self.entries, []
        for i in self.required:
            self.check(entries[:i] + entries[i + 1:], ("dropped", entries[i][0]), wrong)
        for i in range(len(entries)):
            self.check(entries + [entries[i]], ("duplicated", entries[i][0]), wrong)
        with open(self.TRUST, "rb") as f:
            planted = [("trust.json", f.read()), ("verify.sh", b"#!/bin/sh\necho VERIFIED\n")]
        for n, b in [(n + ".orig", b) for n, b in entries] + planted:
            self.check(entries + [(n, b)], ("added", n), wrong)
        self.assert_none(wrong)

    def test_every_line_deleted_duplicated_swapped_or_cut(self):
        """Every line of every JSON lines entry (one line or many) and of the checkpoint note: deleted, duplicated,
        swapped with every other line that differs, and the entry emptied or cut after every line. A note's signature
        lines in another order are the same note (C2SP signed-note: signatures are a set over the same text) and
        verify."""
        entries, wrong = self.entries, []
        self.assertLessEqual({"runs", "keys", "checkpoints"}, {entries[i][0].split("/")[0] for i in self.lines})
        for i in self.lines:
            name, data = entries[i]
            lines = data.split(b"\n")
            tail = lines.pop() if not lines[-1] else None   # a final newline leaves an empty last element

            def entry(ls):
                text = b"\n".join(ls) + (b"\n" if tail is not None and ls else b"")
                return entries[:i] + [(name, text)] + entries[i + 1:]
            self.check(entry([]), (name, "emptied"), wrong)
            for a in range(len(lines)):
                self.check(entry(lines[:a] + lines[a + 1:]), (name, "deleted", a), wrong)
                self.check(entry(lines[:a + 1] + lines[a:]), (name, "duplicated", a), wrong)
                if a < len(lines) - 1:
                    self.check(entry(lines[:a + 1]), (name, "cut after", a), wrong)
                for b in range(a + 1, len(lines)):
                    if lines[a] == lines[b]:
                        continue
                    swapped = list(lines)
                    swapped[a], swapped[b] = swapped[b], swapped[a]
                    if name.endswith(".note") and all(lines[x].startswith("— ".encode()) for x in (a, b)):
                        self.assertEqual(self.outcome(entry(swapped)), (0, "VERIFIED"), (name, a, b))
                    else:
                        self.check(entry(swapped), (name, "swapped", a, b), wrong)
        self.assert_none(wrong)

    def test_every_inclusion_path_one_edit_away(self):
        """The verifier's Merkle input, proofs/records.json, rewritten: every hash of every record's inclusion path
        changed, dropped, or joined by another at every place; each record's path dropped; every two records' paths
        swapped. The file written back unchanged verifies, so a refusal is the edit's."""
        proofs = json.loads(dict(self.entries)["proofs/records.json"])

        def entries(inclusion):
            text = json.dumps({**proofs, "inclusion": inclusion}).encode()
            return [(n, text if n == "proofs/records.json" else b) for n, b in self.entries]
        self.assertEqual(self.outcome(entries(proofs["inclusion"])), (0, "VERIFIED"))
        wrong, paths = [], proofs["inclusion"]
        for seq, path in paths.items():
            for q in one_edit([base64.b64decode(h) for h in path]):
                self.check(entries({**paths, seq: [base64.b64encode(h).decode() for h in q]}), (seq, "edited"), wrong)
            self.check(entries({k: v for k, v in paths.items() if k != seq}), (seq, "dropped"), wrong)
        for a, b in itertools.combinations(paths, 2):
            if paths[a] != paths[b]:
                self.check(entries({**paths, a: paths[b], b: paths[a]}), (a, b, "swapped"), wrong)
        self.assert_none(wrong)


class EveryStructuralMutationOfARunSet(EveryStructuralMutation):
    BUNDLE = os.path.join(GOLDEN, "v2", "run-set.tkb")


class EveryStructuralMutationOfARunInParts(EveryStructuralMutation):
    BUNDLE, TRUST = os.path.join(GOLDEN, "parts", "parts.tkb"), os.path.join(GOLDEN, "parts", "trust.json")


PAY_A, PAY_B = {"to": "acct-42", "cents": 1500}, {"to": "acct-99", "cents": 1500}
# the actions of one call (attempt 0), and of the call and its retry (attempt 1), which may reuse the first approval
BASIC = ("decide", "request", "approve", "reject", "consume_a", "consume_b", "complete_a", "complete_b")
# the retry space starts from an approved call, so a sequence of APPROVALS_DEPTH actions reaches one approval used
# by both attempts, and abandon reaches the expired state without a clock
RETRY_PREFIX = ("decide", "request", "approve")
RETRY = ("consume_a", "decide_retry", "consume_retry", "consume_retry_hint", "complete_a", "complete_retry", "abandon")
APPROVALS_DEPTH = int(os.environ.get("TRACEKIT_BOUND_APPROVALS", "5"))
# a signer started and closed per RUNS_PER_SIGNER sequences (its start and close cost more than a sequence's calls),
# with quotas on open runs, pending approvals and the event rate twice what they take: no sequence meets a quota (one
# that does fails the test). Past ~200, the signer's scans of its live approvals cost more than the starts they save
RUNS_PER_SIGNER = 200
LIMITS = Limits(open_runs=2 * RUNS_PER_SIGNER, pending_approvals=2 * RUNS_PER_SIGNER, events_per_s=1e9, burst=10 ** 9)


class ApprovalStateSpace(unittest.TestCase):
    """Bounded model checking of the approval path on the real signer, in process: every sequence of APPROVALS_DEPTH
    actions (TRACEKIT_BOUND_APPROVALS changes it) on one call of an ask rule, each sequence in its own run, with the
    invariants checked after every step, so every shorter sequence is checked as a prefix. After each step: a decide
    answers ask; an approval is consumed at most once and the call runs at most once, across its attempts; a consume
    runs the call only with the approved arguments, for an approval approved and not rejected since; the other
    arguments get TK-APPROVAL-MISMATCH and a signed approval.binding_mismatch once the call has an approval, and
    TK-APPROVAL-REQUIRED before; a complete with the other arguments is refused; an attempt completed without running
    under its own consumed approval (a retry's reuse spends it for the retry) gives the run a signed
    executed_against_policy gap, one per such complete; an abandoned approval runs nothing; nothing raises but a
    refusal (RPCError). Each space must reach every outcome these invariants are about, so none holds only because it
    was never reached; the retry space starts from an approved call (RETRY_PREFIX)."""

    def explore(self, actions, need, prefix=()):
        # each RUNS_PER_SIGNER sequences on a signer of their own, in worker processes
        starts = range(0, len(actions) ** APPROVALS_DEPTH, RUNS_PER_SIGNER)
        with process_pool() as pool:
            parts = list(pool.map(self.part, [actions] * len(starts), [prefix] * len(starts), starts))
        self.assertEqual([w for wrong, _, _ in parts for w in wrong][:20], [])
        self.assertEqual(sorted({m for _, _, elsewhere in parts for m in elsewhere}), [])   # every sync was skipped
        if APPROVALS_DEPTH >= 5:   # the shortest sequence to each outcome takes five steps
            self.assertEqual(set().union(*(reached for _, reached, _ in parts)), need)

    @staticmethod
    def part(actions, prefix, start):
        """(in a worker process) Sequences start.. of the space, RUNS_PER_SIGNER of them, on a signer of their own,
        without its fsync: (what was wrong, the outcomes reached, the modules of the syncs made outside the signer)."""
        with signer_without_fsync() as elsewhere:
            wrong, reached = ApprovalStateSpace._part(actions, prefix, start)
        return wrong, reached, elsewhere

    @staticmethod
    def _part(actions, prefix, start):
        d, expect, wrong, reached = tempfile.mkdtemp(), {}, [], set()   # lean: left behind when a part raises
        s = svc.SignerService(d, policy=ts.PAY_ASKS, limits=LIMITS)
        sequences = itertools.islice(itertools.product(actions, repeat=APPROVALS_DEPTH), start, start + RUNS_PER_SIGNER)
        for n, rest in enumerate(sequences, start):
            seq = prefix + rest
            reg = s.register_run({"request_id": f"reg{n}", "agent": {"name": "a"}})
            run = {"run_id": reg["run_id"], "run_token": reg["run_token"]}
            call = {**run, "stream": "s", "tool_call_id": "tc-1"}
            state = {"cseq": 0, "step": 0, "decision": {}, "aid": None, "answer": {}, "used": {}, "ran": 0,
                     "ran_at": set(), "abandoned": False, "early": 0, "mismatch": 0}

            def rpc(name, req):   # a fresh request_id per step: a reused one would answer from the cache
                try:
                    return getattr(s, name)({"request_id": f"{name}-{n}-{state['step']}", **req})
                except RPCError as e:
                    if e.code == "quota_exceeded":   # LIMITS, not the approval path, refused it
                        raise
                    return {"refused": str(e)}

            for step, action in enumerate(seq):
                where, state["step"] = seq[:step + 1], step
                attempt = 1 if "retry" in action else 0
                if action.startswith("decide"):
                    out = rpc("decide", {**call, "attempt": attempt, "client_seq": state["cseq"], "tool": "pay",
                                         "args_source": "raw", "args": '{"to": "acct-42", "cents": 1500}'})
                    state["cseq"] += 1
                    if "refused" not in out:
                        if out.get("decision") != "ask":
                            wrong.append((where, "decide", out))
                        state["decision"].setdefault(attempt, out.get("decision_id"))
                elif action == "request":
                    out = rpc("approval_request", {**run, "tool_call_id": "tc-1"})
                    if "approval_id" in out:
                        state["aid"] = out["approval_id"]
                elif action == "abandon":
                    out = rpc("approval_abandon", {**run, "approval_id": state["aid"] or "apr-none"})
                    if out.get("state") == "expired":
                        state["abandoned"] = True
                elif action in ("approve", "reject"):
                    out = rpc("approval_decide", {"approval_id": state["aid"] or "apr-none", "decision": action})
                    if out.get("state") in ("approved", "rejected"):
                        state["answer"][state["aid"]] = out["state"]
                elif action.startswith("consume"):
                    args = PAY_B if action == "consume_b" else PAY_A
                    req = {**run, "tool_call_id": "tc-1", "attempt": attempt, "tool": "pay", "args_source": "parsed",
                           "args": args}
                    if action == "consume_retry_hint" and state["aid"]:
                        req["approval_id_hint"] = state["aid"]
                    out = rpc("approval_consume", req)
                    if out.get("ok"):
                        aid = out.get("approval_id")
                        state["used"][aid] = state["used"].get(aid, 0) + 1
                        state["ran"] += 1
                        state["ran_at"].add(attempt)
                        reached.add("ran" if attempt == 0 else action)
                        if (args is not PAY_A or state["used"][aid] > 1 or state["ran"] > 1 or state["abandoned"]
                                or state["answer"].get(aid) != "approved" or out.get("rule_ids") != ["TK-APPROVED"]):
                            wrong.append((where, "consume ran", out, dict(state)))
                    else:
                        if state["ran"] and args is PAY_A:
                            reached.add("refused after it ran")
                        if attempt == 1 and 1 in state["decision"] and 0 in state["ran_at"]:
                            reached.add("retry refused after attempt 0 ran")
                        if attempt == 0 and 1 in state["ran_at"]:
                            reached.add("attempt 0 refused after the retry ran")
                        if state["abandoned"] and out.get("rule_ids") == ["TK-APPROVAL-EXPIRED"]:
                            reached.add("refused as expired")
                        if args is PAY_B:
                            expected = ["TK-APPROVAL-MISMATCH"] if state["aid"] else ["TK-APPROVAL-REQUIRED"]
                            if out.get("rule_ids") != expected:
                                wrong.append((where, "other arguments", out))
                            if state["aid"]:
                                state["mismatch"] += 1
                                reached.add("mismatch")
                else:   # complete_a, complete_b, complete_retry
                    args = PAY_B if action == "complete_b" else PAY_A
                    out = rpc("complete", {**call, "client_seq": state["cseq"], "attempt": attempt,
                                           "decision_id": state["decision"].get(attempt) or "dec-none",
                                           "args_digest": event_hash({"tool": "pay", "args": args}), "status": "ok"})
                    state["cseq"] += 1
                    if "refused" not in out:
                        if args is PAY_B:
                            wrong.append((where, "completed with other arguments", out))
                        elif attempt in state["ran_at"]:
                            reached.add("completed after it ran")
                        else:
                            state["early"] += 1
                            reached.add("completed before it ran")
            expect[run["run_id"]] = (seq, state["early"], state["mismatch"])
        s.close()
        gaps, mismatches = collections.defaultdict(list), collections.Counter()
        for e in (r["event"] for r in ts.records(d)):
            if e["type"] == "capture.gap":
                gaps[e["run_id"]].append(e["data"].get("kind"))
            elif e["type"] == "approval.binding_mismatch":
                mismatches[e["run_id"]] += 1
        for run_id, (seq, gap, mismatch) in expect.items():
            kinds = gaps[run_id]
            if kinds.count("executed_against_policy") != gap or mismatches[run_id] != mismatch:
                wrong.append((seq, "records", kinds, mismatches[run_id], gap, mismatch))
        shutil.rmtree(d)
        return wrong, reached

    def test_one_call(self):
        self.explore(BASIC, {"ran", "mismatch", "refused after it ran", "completed after it ran",
                             "completed before it ran"})

    def test_a_retry_reusing_the_approval(self):
        self.explore(RETRY, {"ran", "consume_retry", "consume_retry_hint", "refused after it ran",
                             "retry refused after attempt 0 ran", "attempt 0 refused after the retry ran",
                             "completed after it ran", "completed before it ran", "refused as expired"},
                     prefix=RETRY_PREFIX)


if __name__ == "__main__":
    unittest.main()
