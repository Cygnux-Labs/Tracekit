import os
import shutil
import sys
import tempfile
from unittest import mock

import pytest

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(TESTS))
sys.path.insert(0, TESTS)

import factories  # noqa: E402

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


@pytest.fixture
def inproc_signer(tmp_path):
    """An in-process Signer over a fresh home."""
    s = factories.make_signer(str(tmp_path / "signer"))
    yield s
    s.ledger.close()


@pytest.fixture
def dev_daemon(monkeypatch):
    """A real dev-mode signer daemon; yields its home. The client home points at it."""
    from tracekit import install
    d = tempfile.mkdtemp()
    home = os.path.join(d, "signer")
    monkeypatch.setenv("TRACEKIT_CLIENT_HOME", os.path.join(d, "client"))
    install.init_dev(home, [], start=True)
    yield home
    install.stop_dev_daemon(home)
    shutil.rmtree(d, ignore_errors=True)
