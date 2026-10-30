"""The version check the hand-wired integrations share (tracekit.integrations.version_check): a framework installed
outside the version Tracekit is tested with warns once per process, and one inside the range does not warn."""
import unittest
import warnings
from unittest import mock

from tracekit.integrations import version_check


class Check(unittest.TestCase):
    """The helper the five hand-wired integrations call."""

    def test_it_warns_for_a_version_outside_the_tested_range(self):
        with mock.patch.object(version_check, "_WARNED", set()), \
                mock.patch.object(version_check, "_version", return_value="2.0"), \
                warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            version_check.warn_untested("Fine", "fine", (1,), (2,), "fine>=1,<2")
        msgs = [str(x.message) for x in w if "is wired but untested" in str(x.message)]
        self.assertEqual(1, len(msgs))
        self.assertIn("Fine 2.0 is wired but untested; Tracekit is tested with fine>=1,<2", msgs[0])

    def test_it_does_not_warn_for_a_version_inside_the_tested_range(self):
        with mock.patch.object(version_check, "_WARNED", set()), \
                mock.patch.object(version_check, "_version", return_value="1.5"), \
                warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            version_check.warn_untested("Fine", "fine", (1,), (2,), "fine>=1,<2")
        self.assertEqual([], [str(x.message) for x in w if "is wired but untested" in str(x.message)])

    def test_it_warns_only_once_per_process(self):
        with mock.patch.object(version_check, "_WARNED", set()), \
                mock.patch.object(version_check, "_version", return_value="2.0"), \
                warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            version_check.warn_untested("Fine", "fine", (1,), (2,), "fine>=1,<2")
            version_check.warn_untested("Fine", "fine", (1,), (2,), "fine>=1,<2")
        self.assertEqual(1, len([x for x in w if "is wired but untested" in str(x.message)]))

    def test_it_does_not_warn_when_the_version_cannot_be_read(self):
        for version in (None, ""):   # "" is how instrument() reads a framework that isn't installed
            with self.subTest(version=version), mock.patch.object(version_check, "_WARNED", set()), \
                    mock.patch.object(version_check, "_version", return_value=version), \
                    warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                version_check.warn_untested("Fine", "fine", (1,), (2,), "fine>=1,<2")
            self.assertEqual([], [str(x.message) for x in w if "is wired but untested" in str(x.message)])

    def test_it_never_raises_when_the_version_cannot_be_read(self):
        with mock.patch.object(version_check, "_WARNED", set()), \
                mock.patch.object(version_check, "_version", side_effect=RuntimeError("unreadable metadata")), \
                warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            version_check.warn_untested("Fine", "fine", (1,), (2,), "fine>=1,<2")

    def test_it_warns_for_each_framework_separately(self):
        with mock.patch.object(version_check, "_WARNED", set()), \
                mock.patch.object(version_check, "_version", return_value="2.0"), \
                warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            version_check.warn_untested("Fine", "fine", (1,), (2,), "fine>=1,<2")
            version_check.warn_untested("Also Fine", "also-fine", (1,), (2,), "also-fine>=1,<2")
        self.assertEqual(2, len([x for x in w if "is wired but untested" in str(x.message)]))
