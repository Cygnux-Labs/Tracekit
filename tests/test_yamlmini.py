"""tracekit.yamlmini, the YAML subset used when PyYAML is not installed (the signer container has none)."""
import os
import unittest
from unittest import mock

from tracekit import yamlmini
from tracekit.signer import service

HERE = os.path.dirname(os.path.abspath(__file__))


class FlowMappings(unittest.TestCase):
    def test_flow_mappings_nest_lists_and_mappings(self):
        self.assertEqual(yamlmini.loads('a: {"uid:1": t, l: 127.0.0.1:9, xs: ["p:*", q], n: {b: 1}, e: {}}'),
                         {"a": {"uid:1": "t", "l": "127.0.0.1:9", "xs": ["p:*", "q"], "n": {"b": 1}, "e": {}}})

    def test_a_flow_item_that_is_not_key_value_is_an_error(self):
        with self.assertRaises(yamlmini.YAMLError):
            yamlmini.loads("a: {b c}")

    def test_the_container_signer_config_loads_without_pyyaml(self):
        path = os.path.join(HERE, "..", "deploy", "docker", "signer.yaml.example")
        with mock.patch.dict("sys.modules", {"yaml": None}):
            cfg = service.load_config(path)
        self.assertEqual(cfg["tenants"], {"uid:1000": "default"})
        self.assertEqual(cfg["metrics"], {"listen": "127.0.0.1:9464"})


if __name__ == "__main__":
    unittest.main()
