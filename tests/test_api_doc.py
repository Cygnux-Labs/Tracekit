import importlib.util
import os
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


if __name__ == "__main__":
    unittest.main()
