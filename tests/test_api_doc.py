import importlib.util
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_generator():
    """scripts/ is no package: load the generator by its path."""
    spec = importlib.util.spec_from_file_location("api_doc", os.path.join(ROOT, "scripts", "api_doc.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(os.path.exists(os.path.join(ROOT, ".git")), "the page is checked in the repository; an sdist ships only part of it")
class ApiPage(unittest.TestCase):
    def test_the_field_tables_match_the_contract(self):
        """The page's tables are written from rpc_schema.py: a schema change without a rerun leaves it stale."""
        api_doc = load_generator()
        with open(api_doc.PAGE, encoding="utf-8") as f:
            page = f.read()
        self.assertEqual(api_doc.render(page), page, "docs/api.md is out of date: run python scripts/api_doc.py")

    def test_every_rpc_has_a_section_on_the_page(self):
        """An RPC added to the contract without a marker pair on the page would get no tables at all."""
        api_doc = load_generator()
        with open(api_doc.PAGE, encoding="utf-8") as f:
            page = f.read()
        self.assertEqual({m[1] for m in api_doc.MARKED.findall(page)}, set(api_doc.rpc_schema.REQUESTS))

    def test_the_versioning_and_error_prose_follows_the_contract(self):
        """A bump of RPC_VERSION or RPC_MIN, or a new error code, that leaves the hand-written prose stale fails."""
        api_doc = load_generator()
        schema = api_doc.rpc_schema
        with open(api_doc.PAGE, encoding="utf-8") as f:
            page = f.read()
        self.assertIn("this page describes version %d." % schema.RPC_VERSION, page)
        self.assertIn("from %d up to its own highest" % schema.RPC_MIN, page)
        self.assertRegex(page, r"(?m)^\| %d[ |]" % schema.RPC_VERSION)
        errors = page.split("\n## Errors\n", 1)[1].split("\n## ", 1)[0]
        codes = re.findall(r"(?m)^\| `(\w+)` \|", errors)
        self.assertEqual(sorted(codes), sorted(schema.ERROR_CODES))


class Tables(unittest.TestCase):
    def setUp(self):
        self.api_doc = load_generator()

    def row(self, schema, name):
        return next(r for r in self.api_doc.rows(schema) if r[0] == name)

    def test_a_branch_without_a_type_says_what_it_requires_and_when(self):
        """model_event's tool_uses: args_source and args_digest are required when executed_by is client."""
        schema = self.api_doc.rpc_schema.REQUESTS["model_event"]
        self.assertEqual(self.row(schema, "tool_uses[].args_source")[2], "depends")
        self.assertEqual(self.row(schema, "tool_uses[].id")[2], "yes")
        self.assertIn("(when `executed_by` is `\"client\"`: requires `args_source` and `args_digest`)",
                      self.row(schema, "tool_uses")[3])

    def test_a_null_in_an_enum_reads_as_json_null(self):
        self.assertEqual(self.api_doc.kind({"enum": ["enforce", None]}), "one of `enforce`, `null`")

    def test_the_limits_of_a_schema_are_in_the_notes(self):
        notes = self.api_doc.notes
        self.assertEqual(notes({"type": "array", "minItems": 2, "maxItems": 2}), "exactly 2 items")
        self.assertEqual(notes({"type": "array", "minItems": 1, "maxItems": 3}), "1 to 3 items")
        self.assertEqual(notes({"type": "array", "maxItems": 4, "items": {"type": "string", "maxLength": 9}}),
                         "up to 4 items; each item: up to 9 characters")
        self.assertEqual(notes({"type": "object", "additionalProperties": {"enum": ["open", "closed"]}}),
                         "each value: one of `open`, `closed`")
        self.assertEqual(notes({"oneOf": [{"type": "string", "maxLength": 71, "pattern": "^x"}, {"type": "null"}]}),
                         "up to 71 characters; matches `^x`")

    def test_an_if_then_limit_is_on_its_field(self):
        """decide's `args` is text of at most MAX_RAW_ARGS characters when args_source is raw."""
        schema = self.api_doc.rpc_schema.REQUESTS["decide"]
        self.assertIn("when `args_source` is `\"raw\"`: text; up to %d characters" % self.api_doc.rpc_schema.MAX_RAW_ARGS,
                      self.row(schema, "args")[3])

    def test_every_keyword_of_the_contract_is_rendered_or_named(self):
        """A schema keyword the generator does not render fails here until it renders it or the page says it is not shown."""
        shown = {"type", "properties", "required", "const", "enum", "items", "oneOf", "if", "then", "pattern",
                 "minLength", "maxLength", "minItems", "maxItems", "minimum", "maximum", "additionalProperties"}
        seen = set()

        def walk(s):
            if isinstance(s, dict):
                for k, v in s.items():
                    seen.add(k)
                    if k == "properties":
                        for x in v.values():
                            walk(x)
                    elif k != "additionalProperties" or isinstance(v, dict):
                        walk(v)
            elif isinstance(s, list):
                for x in s:
                    walk(x)
        for table in (self.api_doc.rpc_schema.REQUESTS, self.api_doc.rpc_schema.RESPONSES):
            walk(list(table.values()))
        self.assertEqual(seen - shown, set())

    def test_an_if_the_page_cannot_show_fails_naming_the_rpc_and_field(self):
        """An if on an enum, or without a then, or with an else, is an error, not a KeyError or a dropped limit."""
        api_doc = self.api_doc
        for bad in ({"if": {"properties": {"kind": {"enum": ["a"]}}}, "then": {"properties": {}}},
                    {"if": {"properties": {"kind": {"const": "a"}}}},
                    {"if": {"properties": {"kind": {"const": "a"}}}, "then": {"properties": {}}, "else": {}}):
            with self.assertRaises(ValueError):
                api_doc.conditions(bad)
        saved = api_doc.rpc_schema.REQUESTS["decide"]
        api_doc.rpc_schema.REQUESTS["decide"] = dict(saved, **{"if": {"properties": {"args_source": {"enum": ["raw"]}}}})
        try:
            with self.assertRaisesRegex(ValueError, "decide: .*args_source"):
                api_doc.block("decide")
        finally:
            api_doc.rpc_schema.REQUESTS["decide"] = saved

    def test_every_if_of_the_contract_is_one_the_page_can_show(self):
        def walk(s):
            if isinstance(s, dict):
                if "if" in s:
                    self.assertTrue(all("const" in v for v in s["if"]["properties"].values()))
                    self.assertIn("then", s)
                    self.assertNotIn("else", s)
                for k, v in s.items():
                    walk(v)
            elif isinstance(s, list):
                for x in s:
                    walk(x)
        walk(list(self.api_doc.rpc_schema.REQUESTS.values()) + list(self.api_doc.rpc_schema.RESPONSES.values()))

    def test_a_field_every_shape_requires_is_required(self):
        schema = {"type": "object", "required": ["a"], "properties": {"a": {}, "b": {}, "c": {}},
                  "oneOf": [{"required": ["b", "c"]}, {"required": ["b"]}]}
        self.assertEqual({r[0]: r[2] for r in self.api_doc.rows(schema)}, {"a": "yes", "b": "yes", "c": "depends"})

    def test_a_map_of_objects_lists_the_fields_of_its_values(self):
        schema = {"type": "object", "properties": {"m": {"type": "object", "additionalProperties": {
            "type": "object", "required": ["x"], "properties": {"x": {"type": "string"}, "y": {"type": "integer"}}}}}}
        self.assertEqual([(r[0], r[2]) for r in self.api_doc.rows(schema)],
                         [("m", "no"), ("m.*.x", "yes"), ("m.*.y", "no")])

    def test_a_constant_is_written_as_json(self):
        self.assertEqual(self.api_doc.kind({"const": True}), "always `true`")
        self.assertEqual(self.api_doc.kind({"const": "migrated"}), 'always `"migrated"`')
        self.assertEqual(self.api_doc.kind({"const": None}), "always `null`")

    def test_show_with_an_unknown_name_lists_the_known_ones(self):
        import contextlib
        import io
        import sys
        out = io.StringIO()
        argv, sys.argv = sys.argv, ["api_doc.py", "--show", "no_such_rpc"]
        try:
            with contextlib.redirect_stdout(out):
                code = self.api_doc.main()
        finally:
            sys.argv = argv
        self.assertEqual(code, 1)
        self.assertIn("no_such_rpc", out.getvalue())
        self.assertIn("register_run", out.getvalue())


if __name__ == "__main__":
    unittest.main()
