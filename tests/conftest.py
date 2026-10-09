import os
import sys
from unittest import mock

import pytest

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(TESTS))
sys.path.insert(0, TESTS)

MARKERS = {
    "unit": "fast, in-process, no daemon or subprocess",
    "integration": "starts a real signer daemon or spawns hook processes",
    "e2e": "drives a whole agent flow end to end",
    "root": "needs root (OS-user isolation, root-owned files)",
    "k8s": "needs a Kubernetes cluster",
    "nightly": "too slow for every push; runs on the nightly schedule",
    "perf": "performance measurement",
}

# settings a developer's shell may carry that would change what the signer, hook or client does under test
SHELL_ENV = ("TRACEKIT_POLICY", "TRACEKIT_SOCKET", "TRACEKIT_CLIENT_HOME")


def pytest_configure(config):
    for name, doc in MARKERS.items():
        config.addinivalue_line("markers", f"{name}: {doc}")


def pytest_collection_modifyitems(config, items):
    """perf tests run only when asked for: `pytest -m perf`."""
    if "perf" in (config.getoption("-m") or ""):
        return
    for item in items:
        if "perf" in item.keywords:
            item.add_marker(pytest.mark.skip(reason="perf test: run with -m perf"))


@pytest.fixture(autouse=True, scope="session")
def _no_shell_env():
    with pytest.MonkeyPatch.context() as mp:
        for k in SHELL_ENV:
            mp.delenv(k, raising=False)
        yield


@pytest.fixture(autouse=True)
def _isolated_env():
    """Whatever a test does to os.environ is undone after it."""
    with mock.patch.dict(os.environ):
        yield
