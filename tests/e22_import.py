"""Import the E22 verifier-agreement script the way a test needs it, without leaving its sys.path edits behind.

eval/e22_verifier_agreement.py puts scripts/, examples/v2/ and tests/ at the front of sys.path when it is imported.
A test that imported it used to leak examples/v2 into sys.path, so a later ``find_spec("crewai")`` found the
example folder instead of the real package and example tests ran without their dependencies (#721)."""
import importlib
import os
import sys

TESTS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS)


def import_e22(*extra):
    """Return the e22 module (and any ``extra`` modules from scripts/ or eval/) with sys.path as it was before."""
    saved = list(sys.path)
    sys.path[:0] = [os.path.join(ROOT, "scripts"), os.path.join(ROOT, "eval")]
    try:
        modules = [importlib.import_module("e22_verifier_agreement")]
        modules.extend(importlib.import_module(name) for name in extra)
    finally:
        sys.path[:] = saved
    return modules[0] if not extra else tuple(modules)
