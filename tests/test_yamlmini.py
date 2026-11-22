"""tracekit.yamlmini, the YAML subset used when PyYAML is not installed (the signer container has none)."""
import json
import os
import random
import unittest
from unittest import mock

from tracekit import yamlmini
from tracekit.signer import service

HERE = os.path.dirname(os.path.abspath(__file__))


class FlowMappings(unittest.TestCase):
    def test_flow_mappings_nest_lists_and_mappings(self):
        self.assertEqual(yamlmini.loads('a: {"uid:1": t, l: 127.0.0.1:9, xs: ["p:*", q], n: {b: 1}, e: {}}'),
                         {"a": {"uid:1": "t", "l": "127.0.0.1:9", "xs": ["p:*", "q"], "n": {"b": 1}, "e": {}}})

    def test_a_flow_list_or_mapping_may_go_over_lines(self):
        text = "handoffs: [a, b,  # the first two\n  c]\nx:\n  - {k: [1,\n      2], m: \"]\"}\n"
        self.assertEqual(yamlmini.loads(text), {"handoffs": ["a", "b", "c"], "x": [{"k": [1, 2], "m": "]"}]})
        self.assertEqual(yamlmini.loads("pattern: ^rm -[rf]\n"), {"pattern": "^rm -[rf]"})
        with self.assertRaisesRegex(yamlmini.YAMLError, "line 1: unterminated flow list"):
            yamlmini.loads("a: [1,\n")

    def test_an_escaped_quote_does_not_end_a_double_quoted_string(self):
        """A `\"` inside a double-quoted flow string or key, as json.dumps writes it, didn't end it."""
        self.assertEqual(yamlmini.loads('m: {"note": "rack 12\\" A, row 3", "x": ["a\\\\", "b"]}\n"k\\"q": 1\n'),
                         {"m": {"note": 'rack 12" A, row 3', "x": ["a\\", "b"]}, 'k"q': 1})
        self.assertEqual(yamlmini.loads('m: {"a": "x\\"]",\n  "b": 2}\n'), {"m": {"a": 'x"]', "b": 2}})
        # a quote inside a plain item opens no string (as in PyYAML), so its backslash escapes nothing
        self.assertEqual(yamlmini.loads('content: {b: [a"x\\"y]}\n'), {"content": {"b": ['a"x\\"y']}})

    def test_a_doubled_single_quote_goes_on_with_the_string(self):
        for text, want in (("k: ['a'', b', c]", {"k": ["a', b", "c"]}), ("k: ['it''s, ok']", {"k": ["it's, ok"]}),
                           ("k: {a: 'don''t, stop'}", {"k": {"a": "don't, stop"}}),
                           ("deny: ['it''s [x']", {"deny": ["it's [x"]})):
            with self.subTest(text):
                self.assertEqual(yamlmini.loads(text + "\n"), want)

    def test_flow_quoting_reads_as_pyyaml_reads_it(self):
        """Differential, from a fixed seed: flow lists and mappings mixing plain items, '' in single-quoted strings,
        backslash escapes in double-quoted ones, commas, brackets and #. Where both parse, they agree."""
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML is not installed")
        r = random.Random(1074)

        def atom():
            body = "".join(r.choice("ab ,[]{}#'\"\\x") for _ in range(r.randrange(6)))
            return r.choice(["'" + body.replace("'", "''") + "'", json.dumps(body),
                             r.choice(["a", "b c", "a#b", 'x"y', "it's", 'a"x\\"y', "q #z", "rm-'rf", "a:'b", 'x-"y', "a - 'b"])])

        def key(i):
            return r.choice([f"k{i}", f"'k''{i}'", f'"k\\"{i}"'])

        def flow(d=0):
            items = [flow(d + 1) if d < 2 and r.random() < 0.25 else atom() for _ in range(r.randrange(4))]
            comma = ", " if items and r.random() < 0.2 else ""   # a trailing comma
            if r.random() < 0.5:
                return "[" + ", ".join(items) + comma + "]"
            return "{" + ", ".join(f"{key(i)}: {v}" for i, v in enumerate(items)) + comma + "}"

        both = 0
        for _ in range(5000):
            doc = "v: " + flow() + "\n"
            try:
                mine = yamlmini.loads(doc)
            except ValueError:   # a refusal; any other exception is a crash and fails the test
                continue
            try:
                theirs = yaml.safe_load(doc)
            except yaml.YAMLError:
                continue
            both += 1
            self.assertEqual(mine, theirs, doc)
        self.assertGreater(both, 4000)

    def test_a_trailing_comma_ends_a_flow_collection_and_an_empty_item_is_refused(self):
        self.assertEqual(yamlmini.loads("a: [x,]\nb: {retain: true,}\nc: [{a: 1,}]\n"),
                         {"a": ["x"], "b": {"retain": True}, "c": [{"a": 1}]})
        for text in ("v: {,}", "v: {a: 1, , b: 2}", "v: {a: {,}}", "v: [[], {}, [,], {,}]", "v: [a,,]"):
            with self.subTest(text), self.assertRaisesRegex(yamlmini.YAMLError, "empty item"):
                yamlmini.loads(text + "\n")

    def test_a_quote_in_a_plain_value_is_text(self):
        """Only the key's own string decides "unterminated key", and a quote inside a plain scalar opens no string."""
        for text, want in (('"contact": ops, "night desk', 'ops, "night desk'), ('"note": 5-\'7 days', "5-'7 days"),
                           ('"cmd": echo a,\'b', "echo a,'b"), ('"x": a:\'b', "a:'b"),
                           ('"title": the ["draft', 'the ["draft'), ("k: b,,'{ #", "b,,'{"), ("k: -[''#-{-", "-[''#-{-")):
            with self.subTest(text):
                self.assertEqual(list(yamlmini.loads(text + "\n").values()), [want])
        with self.assertRaisesRegex(yamlmini.YAMLError, "unterminated key"):
            yamlmini.loads('"abc: d\n')

    def test_block_lines_read_as_pyyaml_reads_them(self):
        """Differential, from a fixed seed: `key: value` lines with plain, single-quoted ('') and double-quoted keys,
        and plain values holding stray quotes, `,`, `:`, `-`, `[`, `{` and `#`. Where both parse, they agree; a plain
        scalar PyYAML reads is never refused; nothing but ValueError is raised."""
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML is not installed")
        r = random.Random(1074)
        both = 0
        for _ in range(5000):
            body = "".join(r.choice("ab -:'\"\\#") for _ in range(r.randrange(1, 5)))
            key = r.choice(["k", "a-b", "'" + body.replace("'", "''") + "'", json.dumps(body)])
            value = "".join(r.choice("ab -:,'\"[{#") for _ in range(r.randrange(1, 9))).strip() or "v"
            doc = f"{key}: {value}\n"
            try:
                mine = yamlmini.loads(doc)
            except ValueError:
                mine = None
            try:
                theirs = yaml.safe_load(doc)
            except yaml.YAMLError:
                continue
            if mine is None:
                self.assertTrue(value[:1] in "'\"[{&*!|>%@`#" or not isinstance(theirs, dict) or any(
                    isinstance(v, (dict, list)) for v in theirs.values()), f"refused a plain scalar: {doc!r}")
                continue
            both += 1
            self.assertEqual(mine, theirs, doc)
        self.assertGreater(both, 2000)

    def test_a_flow_list_over_lines_keeps_its_strings_whole(self):
        """A continuation line starts inside the flow list: a quote after `,` opens a string there, and ` #` in it is
        text, not a comment."""
        self.assertEqual(yamlmini.loads("deny: ['rm -rf /',\n  'sudo', 'curl x # y',\n  'wget']\n"),
                         {"deny": ["rm -rf /", "sudo", "curl x # y", "wget"]})
        self.assertEqual(yamlmini.loads("k: [[a,\n  b], 'c #d']\n"), {"k": [["a", "b"], "c #d"]})

    def test_documents_over_lines_read_as_pyyaml_reads_them(self):
        """Differential, from a fixed seed: block documents with comments, `- ` lists and flow lists over several
        lines. Where PyYAML reads a document, yamlmini reads it the same, and refuses none."""
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML is not installed")
        r = random.Random(1074)

        def quoted():
            v = "".join(r.choice("ab ,:#[]{}'\"\\-x\u00e9") for _ in range(r.randint(0, 7)))
            text = ("'" + v.replace("'", "''") + "'") if r.random() < 0.5 else json.dumps(v)
            if len(text) > 3 and r.random() < 0.05:   # a string over two lines, which yamlmini refuses
                text = text[:2] + "\n  " + text[2:]
                spans.append(text)
            return text

        def scalar(flow):
            if flow or r.random() < 0.6:
                return quoted()
            return r.choice(["abc", "a b", "x-y", "a.b", "path/to", "12", "true", "null", "a#b", "it's", 'say "hi"',
                             "rm-'rf", "a:'b", 'x-"y'])

        def comment():
            return r.choice(["", "", " # note", "  # a 'quoted' # thing", ' #"x'])

        def flow_list():
            parts = [("" if i == 0 else r.choice([", ", ",\n  ", ",", ",\n    "])) + scalar(True)
                     for i in range(r.randint(1, 5))]
            return "[" + r.choice(["", "\n  "]) + "".join(parts) + r.choice(["]", "\n]", ",\n]", ",]"])

        def doc():
            out = []
            for i in range(r.randint(1, 4)):
                kind = r.random()
                if kind < 0.4:
                    out.append(f"k{i}: {scalar(False)}{comment()}")
                elif kind < 0.8:
                    out.append(f"k{i}: {flow_list()}{comment()}")
                else:
                    out.append(f"k{i}:" + "".join(f"\n  - {scalar(False)}{comment()}" for _ in range(r.randint(1, 3))))
            return "\n".join(out) + "\n"

        both, spans = 0, []
        for _ in range(3000):
            del spans[:]
            d = doc()
            try:
                theirs = yaml.safe_load(d)
            except yaml.YAMLError:
                continue
            both += 1
            try:
                mine = yamlmini.loads(d)
            except ValueError:   # refused, never misread: only a quoted string over lines may be
                self.assertTrue(spans, d)
                continue
            self.assertEqual(mine, theirs, d)
        self.assertGreater(both, 2000)

    def test_a_quote_inside_a_plain_flow_item_is_text(self):
        self.assertEqual(yamlmini.loads("deny: [rm-'rf, curl']\n"), {"deny": ["rm-'rf", "curl'"]})
        self.assertEqual(yamlmini.loads("k: {x: a-'b, y: c'}\n"), {"k": {"x": "a-'b", "y": "c'"}})

    def test_a_quoted_string_over_lines_and_a_flow_item_starting_with_hash_are_refused(self):
        for text, why in (("k: ['a\n  b #c',\n  'd']\n", "ends on its line"), ("k: [a,#c\n  b]\n", "start with #")):
            with self.subTest(text), self.assertRaisesRegex(yamlmini.YAMLError, why):
                yamlmini.loads(text)

    def test_a_single_quoted_key_takes_a_doubled_quote(self):
        self.assertEqual(yamlmini.loads("v: {'it''s': 1}\n'a''b': 2\n"), {"v": {"it's": 1}, "a'b": 2})

    def test_a_flow_item_that_is_not_key_value_is_an_error(self):
        with self.assertRaises(yamlmini.YAMLError):
            yamlmini.loads("a: {b c}")

    def test_the_container_signer_config_loads_without_pyyaml(self):
        path = os.path.join(HERE, "..", "deploy", "docker", "signer.yaml.example")
        with mock.patch.dict("sys.modules", {"yaml": None}):
            cfg = service.load_config(path)
        self.assertEqual(cfg["tenants"], {"uid:1000": "default"})
        self.assertEqual(cfg["metrics"], {"listen": "127.0.0.1:9464"})


class WithoutPyYAML(unittest.TestCase):
    def test_a_json_config_loads_without_pyyaml(self):
        """A config written as JSON (JSON is YAML) loads where PyYAML isn't installed, as it does where it is."""
        text = '{"data_dir": "viewer", "storage": {"postgres": {"dsn_file": "reader.dsn"}}}'
        with mock.patch.dict("sys.modules", {"yaml": None}):
            self.assertEqual(yamlmini.load_any(text), {"data_dir": "viewer", "storage": {"postgres": {"dsn_file": "reader.dsn"}}})
            self.assertEqual(yamlmini.load_any("data_dir: viewer\n"), {"data_dir": "viewer"})


if __name__ == "__main__":
    unittest.main()
