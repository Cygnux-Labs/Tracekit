"""Bounded exhaustive checks (#487): every case within a stated bound, not a sample, so a pass proves the property
within the bound and a failure is a real bug. The decision logic over its whole finite domain; RFC 9162 Merkle proofs
for every tree size up to MERKLE_N (TRACEKIT_BOUND_MERKLE raises it); the v2 verifier against every structural mutation
of the golden closed bundle (tests/test_verify_v2_property.py samples bit flips of it)."""
import importlib.util
import itertools
import os
import tempfile
import unittest

from test_verify_v2_property import ENTRIES, JSONL, REQUIRED, TRUST, zipped

from tracekit import merkle
from tracekit.policy2 import compile as pc
from tracekit.policy2.engine import Engine
from tracekit.signer.service import STRICTNESS, _stricter
from tracekit.verify import v2

ENGINES = ("re2", "regex") if importlib.util.find_spec("re2") else ("regex",)

MERKLE_N = int(os.environ.get("TRACEKIT_BOUND_MERKLE", "32"))
LEAVES = [merkle.leaf_hash(b"leaf %d" % i) for i in range(MERKLE_N)]
ROOTS = [None] + [merkle.root(LEAVES[:n]) for n in range(1, MERKLE_N + 1)]
# the root of a fork: the same first n-1 leaves and another last one
FORKS = [None] + [merkle.root(LEAVES[:n - 1] + [merkle.leaf_hash(b"fork")]) for n in range(1, MERKLE_N + 1)]
OTHER = merkle.leaf_hash(b"other")


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
        """Every 1 <= m <= n <= MERKLE_N: the proof verifies; no proof one edit away does, nor the roots swapped, nor a
        fork's root for either size (what witnesses refuse); another size, with its own root, verifies only where that
        pair's proof is the same proof."""
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
POLICY = """tools: {Bash: shell}
deny:
  - {id: D1, class: shell, pattern: 'zzdeny1', unless: 'zzsafe'}
  - {id: D2, class: shell, pattern: 'zzdeny2'}
ask:
  - {id: A1, class: shell, pattern: 'zzask1'}
  - {id: A2, class: shell, pattern: 'zzask2'}
flag:
  - {id: F1, class: shell, pattern: 'zzflag1'}
  - {id: F2, class: shell, pattern: 'zzflag2'}
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
                    d = e.decide("Bash", {"command": " ".join(("echo",) + present)})
                    self.assertEqual((d["verdict"], d["rule_ids"]), (verdict, hit), (engine, present))

    def test_unknown_tools_and_unreadable_commands_get_their_sections_verdict(self):
        """Every `unknown_tools` and `on_parse_error` setting: an unmapped tool gets TK-UNKNOWN-TOOL in that section
        (allow when unset), and a command the parser can't read gets TK-SHELL-PARSE in its section (ask when unset)."""
        for setting in (None, "flag", "ask", "deny"):
            pol = compiled(POLICY + (f"unknown_tools: {setting}\n" if setting else ""))
            for engine in ENGINES:
                d = Engine(pol, engine).decide("SomeNewTool", {"x": "zzdeny1"})
                self.assertEqual((d["verdict"], d["rule_ids"]),
                                 (setting, ["TK-UNKNOWN-TOOL"]) if setting else ("allow", []), (setting, engine))
        for setting in (None, "ask", "deny"):
            pol = compiled(POLICY + (f"on_parse_error: {setting}\n" if setting else ""))
            for engine in ENGINES:
                d = Engine(pol, engine).decide("Bash", {"command": "echo 'unclosed"})
                self.assertEqual((d["verdict"], d["rule_ids"]), (setting or "ask", ["TK-SHELL-PARSE"]), (setting, engine))

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
            self.assertEqual(d.get("nondeterministic", False), bool(a.get("nondeterministic") or b.get("nondeterministic")))
            union = list(dict.fromkeys(a.get("oversize", []) + b.get("oversize", [])))
            self.assertEqual(d.get("oversize"), union or None)


NOTES = [i for i, (n, b) in enumerate(ENTRIES) if n.endswith(".note")]


class EveryStructuralMutation(unittest.TestCase):
    """Each mutation refreshes the manifest's hashes, as anyone rewriting a bundle would. None verifies, but a run cut
    back after a record reads open (`VERIFIED TO HEAD n (open)`, exit 0) and never closed: nothing in one run's bundle
    shows the dropped records (docs/limits.md, "A run cut back"; a run-set bundle shows them)."""

    def outcome(self, entries):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "m.tkb")
            with open(path, "wb") as f:
                f.write(zipped(entries))
            rep, code = v2.verify(path, TRUST)   # raising fails the test
        return code, rep.integrity

    def check(self, entries, what, wrong, cut_run=None):
        code, integrity = self.outcome(entries)
        if cut_run is not None:   # the run's records up to run_seq cut_run, and no run.final
            ok = (code, integrity) == (0, f"VERIFIED TO HEAD {cut_run} (open)") or (code in (1, 2) and integrity != "VERIFIED")
        else:
            ok = code in (1, 2) and integrity != "VERIFIED"
        if not ok:
            wrong.append((what, code, integrity))

    def test_every_entry_dropped_or_duplicated(self):
        wrong = []
        for i in REQUIRED:
            self.check(ENTRIES[:i] + ENTRIES[i + 1:], ("dropped", ENTRIES[i][0]), wrong)
        for i in range(len(ENTRIES)):
            self.check(ENTRIES + [ENTRIES[i]], ("duplicated", ENTRIES[i][0]), wrong)
        self.assertEqual(wrong, [])

    def test_every_line_deleted_duplicated_swapped_or_cut(self):
        """Every line of every JSON lines entry and checkpoint note: deleted, duplicated, swapped with every other line
        that differs, and the entry emptied or cut after every line."""
        wrong, counted = [], 0
        for i in JSONL + NOTES:
            name, data = ENTRIES[i]
            lines = data.split(b"\n")
            tail = lines.pop() if not lines[-1] else None   # a final newline leaves an empty last element

            def entry(ls):
                return ENTRIES[:i] + [(name, b"\n".join(ls) + (b"\n" if tail is not None else b""))] + ENTRIES[i + 1:]
            run = name.startswith("runs/")
            self.check(entry([]), (name, "emptied"), wrong)
            for a in range(len(lines)):
                self.check(entry(lines[:a] + lines[a + 1:]), (name, "deleted", a), wrong)
                self.check(entry(lines[:a + 1] + lines[a:]), (name, "duplicated", a), wrong)
                if a < len(lines) - 1:
                    self.check(entry(lines[:a + 1]), (name, "cut after", a), wrong, cut_run=a if run else None)
                for b in range(a + 1, len(lines)):
                    # a note's signatures are a set over the same text (C2SP signed-note): another order is the same note
                    signatures = name.endswith(".note") and all(lines[x].startswith("— ".encode()) for x in (a, b))
                    if lines[a] != lines[b] and not signatures:
                        swapped = list(lines)
                        swapped[a], swapped[b] = swapped[b], swapped[a]
                        self.check(entry(swapped), (name, "swapped", a, b), wrong)
                        counted += 1
            counted += 3 * len(lines) + 1
        self.assertGreater(counted, 0)
        self.assertEqual(wrong, [])


if __name__ == "__main__":
    unittest.main()
