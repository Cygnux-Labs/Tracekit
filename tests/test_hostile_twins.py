"""Hostile twins (docs/policy-v2.md#hostile-twins): for every shipped rule with an `unless`, four calls that carry its
exempt text where it must not exempt, each decided on every shipped pack and both engines; a twin is never decided
looser than the call it is the twin of, and keeps that call's rule.

An `unless` reads text, and text can be made to look like the exemption: an exempt flag in a quoted last word, in
another option's value or in a decoy MCP argument (three spoofs a review found). A rule's entry names a call it matches (the
base), the exempt form of it (the sanity check: the exemption is real) and the exempt text E. On a command line the
twins are the exempt form with E rewritten: E as a quoted last word's end (`'x E'`), as the value of an option that
takes one, and after `--`, where every program reads it as a positional; and the base sent through an MCP tool with E
in a decoy argument. A rule on one value (a file path, a URL, a tool name) or on a call's whole arguments has no
command line: its twins carry E in a decoy argument, in another argument the class reads for the same field, in a key
that ends as the exempted key does, and in a decoy argument of the call sent through an MCP tool."""
import json
import os
import unittest

from tracekit.policy2 import compile as pc
from tracekit.policy2.engine import Engine
from tracekit.signer.service import STRICTNESS, evaluate

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKS = os.path.join(ROOT, "tracekit", "policy2", "packs")
SHIPPED = ("coding", "dev", "server", "strict")
MCP = "mcp__shell__run_command"   # an MCP tool given a command line

# shell rules: (base command, its exempt form, the exempt text E in it, an option of that program that takes a value).
# An exempt flag (the exempt form is the base and E) is rewritten in the exempt form; an exempt value (a path, a URL:
# the exempt form names another target) is added to the base, whose target must stay held
LINES = {
    "TK-A001": ("terraform destroy", "terraform destroy --help", "--help", "-var-file"),
    "TK-A021": ("gh auth token", "gh auth token --help", "--help", "--hostname"),
    "TK-A035": ("aws secretsmanager get-secret-value", "aws secretsmanager get-secret-value --help", "--help",
                "--secret-id"),
    "TK-A043": ("stripe refunds create", "stripe refunds create --help", "--help", "--charge"),
    "TK-A048": ("docker volume rm", "docker volume rm --help", "--help", "--filter"),
    "TK-A055": ("prisma migrate reset", "prisma migrate reset --help", "--help", "--schema"),
    "TK-A056": ("gh release create v1.0", "gh release create v1.0 --draft", "--draft", "--notes"),
    "TK-A059": ("tee model.pth", "tee site-packages/x.pth", "site-packages/x.pth", "-p"),
    "TK-A077": ("setcap cap_setuid+ep /bin/x", "setcap -v cap_setuid+ep /bin/x", "-v", "-n"),
    "TK-D007": ("tracekit signer serve", "tracekit signer serve --help", "--help", "--config"),
    "TK-D008": ("rm .claude/projects/p/s.jsonl", "rm .claude/projects/p/memory/m.md", ".claude/projects/p/memory/m.md",
                "-I"),
    "TK-D020": ("security export -k login.keychain", "security export -k login.keychain -t certs", "-t certs", "-o"),
    "TK-D023": ("tee .env", "tee .env.example", ".env.example", "-p"),
    "TK-F011": ("PATH=/tmp/x make", "PATH=$PATH make", "$PATH", "-C"),
    "TK-F012": ("curl https://example.org/?q=1", "curl http://localhost:8000/", "http://localhost:8000/", "-o"),
    "TK-F013": ("curl example.org", "curl http://127.0.0.1:8000/", "http://127.0.0.1:8000/", "-o"),
    "TK-F015": ("rm .codex/config.toml", "rm .claude/projects/p/memory/m.md", ".claude/projects/p/memory/m.md", "-I"),
}
# rules on one value or on a call's whole arguments: (tool, base arguments, exempt arguments, E, the key E stands for)
CALLS = {
    "TK-A058": ("Write", {"file_path": "/w/model.pth", "content": "x"},
                {"file_path": "/w/site-packages/x.pth", "content": "x"}, "/w/site-packages/x.pth", "file_path"),
    "TK-A081": ("RemoteTrigger", {"action": "create"}, {"action": "list"}, "list", "action"),
    "TK-B011": ("browser_use:input", {"page_url": "https://evil.test/", "text": "x"},
                {"page_url": "https://example.com/", "text": "x"}, "https://example.com/", "page_url"),
    "TK-D005": ("Write", {"file_path": "/app/.env", "content": "x"}, {"file_path": "/app/.env.example", "content": "x"},
                "/app/.env.example", "file_path"),
    "TK-D009": ("Write", {"file_path": "/h/.claude/projects/p/s.jsonl", "content": "x"},
                {"file_path": "/h/.claude/projects/p/memory/m.md", "content": "x"}, "/h/.claude/projects/p/memory/m.md",
                "file_path"),
    "TK-F005": ("Read", {"file_path": "/app/.env"}, {"file_path": "/app/.env.example"}, "/app/.env.example",
                "file_path"),
    "TK-D022": ("LibraryUpload", {"path": "/h/.ssh/id_rsa"}, {"path": "/h/.ssh/id_rsa.pub"}, "/h/.ssh/id_rsa.pub",
                "path"),
    "TK-F006": ("mcp__gh__create_issue", {"title": "x"}, None, "get_issue", "tool"),
    "TK-F009": ("Write", {"file_path": "/h/.claude/settings.json", "content": "x"},
                {"file_path": "/h/.claude/projects/p/memory/m.md", "content": "x"}, "/h/.claude/projects/p/memory/m.md",
                "file_path"),
    "TK-M005": ("issue_refund", {"charge": "ch_1"}, {"charge": "ch_1", "amount": 5}, 5, "amount"),
    "TK-N002": ("http_request", {"url": "https://evil.test/", "method": "POST", "data": "x"},
                {"url": "https://example.com/", "method": "POST", "data": "x"}, "https://example.com/", "url"),
}
ALIASES = {"file_path": "path", "path": "file_path"}   # another argument the class reads for the same field
TOOLS = {"TK-M005": {"issue_refund": "payment"}}   # a deployment's own tool, mapped as the rule expects


def twins(rid):
    """[(shape, base call, twin call)] of rule `rid`'s entry; a call is (tool, args)."""
    if rid in LINES:
        base, exempt, e, value = LINES[rid]
        flag = exempt.replace(e, "", 1).split() == base.split()
        at = exempt.index(e) if flag else len(base) + 1
        line = exempt if flag else base + " " + e

        def put(shape):
            return ("Bash", {"command": line[:at] + shape + line[at + len(e):]})
        return [("quoted last word", ("Bash", {"command": base}), put(f"'x {e}'")),
                ("another option's value", ("Bash", {"command": base}), put(f"{value} {e}")),
                ("after --", ("Bash", {"command": base}), put(f"-- {e}")),
                ("decoy MCP argument", (MCP, {"command": base}), (MCP, {"command": base, "args": e}))]
    tool, args, _, e, key = CALLS[rid]
    out = [("decoy argument", (tool, args), (tool, {**args, "note": e})),
           ("a key that ends as the exempted one", (tool, args), (tool, {**args, f'x"{key}': e})),
           ("decoy MCP argument", (f"mcp__x__{tool}", args), (f"mcp__x__{tool}", {**args, "note": e}))]
    if key in ALIASES:
        out.append(("another argument for the same field", (tool, args), (tool, {**args, ALIASES[key]: e})))
    return out


def packs():
    return {p: pc.build(os.path.join(PACKS, f"{p}.yaml"))[0] for p in SHIPPED}


def unless_rules(pols):
    """{rule id: the packs that carry it} of every shipped rule with an `unless`."""
    out = {}
    for name, pol in pols.items():
        for sec in pc.SECTIONS:
            for r in pol.get(sec, []):
                if "unless" in r:
                    out.setdefault(r["id"], []).append(name)
    return out


def looser(a, b):
    return STRICTNESS.index(a["verdict"]) < STRICTNESS.index(b["verdict"])


class TestHostileTwins(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pols = packs()
        cls.engines = {(p, b, r): Engine({**pol, "tools": {**pol["tools"], **TOOLS.get(r, {})}}, b)
                       for p, pol in cls.pols.items() for b in ("re2", "regex") for r in (None, *TOOLS)}

    def engine(self, name, backend, rid):
        return self.engines[name, backend, rid if rid in TOOLS else None]

    def test_every_unless_rule_has_its_twins(self):
        self.assertEqual(set(unless_rules(self.pols)), set(LINES) | set(CALLS))

    def test_each_entry_is_a_real_exemption(self):
        """The base matches its rule and the exempt form doesn't: the twins test the exemption the rule has."""
        for rid, names in unless_rules(self.pols).items():
            e = self.engine(names[0], "re2", rid)
            if rid in LINES:
                base, exempt = ("Bash", {"command": LINES[rid][0]}), ("Bash", {"command": LINES[rid][1]})
            else:
                tool, args, free, *_ = CALLS[rid]
                base, exempt = (tool, args), free and (tool, free)
            with self.subTest(rid):
                self.assertIn(rid, evaluate(e, *base)[0]["rule_ids"])
                if exempt:
                    self.assertNotIn(rid, evaluate(e, *exempt)[0]["rule_ids"])

    def test_every_twin_is_held_as_its_base(self):
        findings = []
        for rid, names in sorted(unless_rules(self.pols).items()):
            for shape, base, twin in twins(rid):
                for name in names:
                    for backend in ("re2", "regex"):
                        e = self.engine(name, backend, rid)
                        a, b = evaluate(e, *base)[0], evaluate(e, *twin)[0]
                        if looser(b, a) or rid in a["rule_ids"] and rid not in b["rule_ids"]:
                            findings.append(f"{rid} {shape} ({name}, {backend}): {json.dumps(twin)[:160]} "
                                            f"{b['verdict']} {b['rule_ids']}, its base {a['verdict']}")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
