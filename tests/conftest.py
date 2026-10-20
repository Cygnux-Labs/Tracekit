import io
import json
import os
import sys
import tempfile
import time
import urllib.request
from unittest import mock

import pytest

TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(TESTS))
sys.path.insert(0, TESTS)

from tracekit import bundle_v2  # noqa: E402
from tracekit.format import checkpoint  # noqa: E402
from tracekit.verify import v2 as verify_v2  # noqa: E402

MARKERS = {
    "unit": "fast, in-process, no daemon or subprocess",
    "integration": "starts a real signer daemon or spawns hook processes",
    "e2e": "drives a whole agent flow end to end",
    "root": "needs root (OS-user isolation, root-owned files)",
    "k8s": "needs a Kubernetes cluster",
    "nightly": "too slow for every push; runs on the nightly schedule",
    "perf": "performance measurement",
    "quickstart": "builds the wheel into a fresh venv and runs docs/quickstart-v2.md (TRACEKIT_QUICKSTART=1)",
    "unverified_bundles": "exports v2 bundles the verifier rejects on purpose (a tampered or synthetic store, a "
                          "forged line), or that need a pinned issuer; skips the every-export-verifies check",
}

# settings a developer's shell may carry that would change what the signer, hook or client does under test
SHELL_ENV = ("TRACEKIT_POLICY", "TRACEKIT_SOCKET", "TRACEKIT_CLIENT_HOME", "CLAUDE_CONFIG_DIR",
             "GEMINI_CLI_SYSTEM_SETTINGS_PATH", "GEMINI_CLI_SYSTEM_DEFAULTS_PATH")
PROXIES = urllib.request.getproxies()


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
    """Whatever a test does to os.environ is undone after it. urlopen's shared opener keeps the proxies it read when it
    was built, which no restore undoes: built under a test's proxy settings, it would send every later urlopen there."""
    with mock.patch.dict(os.environ):
        yield
    leaked = [h.proxies for h in getattr(urllib.request._opener, "handlers", ())
              if isinstance(h, urllib.request.ProxyHandler) and h.proxies != PROXIES]
    if leaked:
        urllib.request.install_opener(None)
        pytest.fail(f"urlopen ran under this test's proxy settings {leaked}: give it an opener of its own "
                    "(urllib.request.build_opener) or run it in a child process")


# Every v2 bundle a test exports in this process is verified against the log key that signed its checkpoint: an honest
# bundle the verifier rejects is a bug (1.1's passkey approvals). Tests that export from a tampered store on purpose, or
# whose bundles need a pinned record-key issuer, carry @pytest.mark.unverified_bundles. Bundles exported by a child
# process are not seen here (docs/limits.md).
_VKEYS = {}            # (key name, key id) -> vkey of each log key that signed a checkpoint note in this process
_BUNDLES = {"check": True, "failures": [], "seconds": 0.0, "count": 0}
_log_line, _export = checkpoint.log_line, bundle_v2.export


def _recording_log_line(name, public, sig, type_=checkpoint.ED25519):
    _VKEYS[(name, checkpoint.key_id(name, type_, public))] = checkpoint.vkey(name, type_, public)
    return _log_line(name, public, sig, type_)


def _log_vkeys(storage, note):
    """The vkeys of the log keys that signed `note`: signed in this process, else written by a signer in a child process
    next to its store (data_dir/log.vkey)."""
    signed = checkpoint.signers(note)
    known = [_VKEYS[s] for s in sorted(signed) if s in _VKEYS]
    if not known and hasattr(storage, "root"):
        try:
            with open(os.path.join(os.path.dirname(storage.root), "log.vkey"), encoding="ascii") as f:
                known = [k for k in f.read().split() if checkpoint.parse_vkey(k)[:2] in signed]
        except OSError:
            pass
    return known


def _verified_export(storage, tenant, run_id, note, out_path, *args, **kw):
    info = _export(storage, tenant, run_id, note, out_path, *args, **kw)
    if _BUNDLES["check"]:
        t0 = time.monotonic()
        fd, trust = tempfile.mkstemp(suffix=".trust.json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"logs": _log_vkeys(storage, note), "algs": ["ed25519"]}, f)
        try:
            rep, code = verify_v2.verify(out_path, trust)
        finally:
            os.unlink(trust)
        if code != verify_v2.EXIT_OK:
            out = io.StringIO()
            verify_v2.print_report(rep, code, out)
            _BUNDLES["failures"].append(f"{out_path}:\n{out.getvalue()}")
        _BUNDLES["count"] += 1
        _BUNDLES["seconds"] += time.monotonic() - t0
    return info


checkpoint.log_line, bundle_v2.export = _recording_log_line, _verified_export


@pytest.fixture(autouse=True)
def _exported_bundles_verify(request):
    opted_out = request.node.get_closest_marker("unverified_bundles") is not None or \
        getattr(getattr(request, "function", None), "unverified_bundles", False)   # factories.unverified_bundles
    early, _BUNDLES["failures"] = _BUNDLES["failures"], []
    if early:   # exported outside any test (a setUpClass, a module fixture, a thread): never blamed on this one
        pytest.fail(f"a v2 bundle exported before {request.node.nodeid} (setUpClass, a module fixture or a thread) "
                    "fails verification:\n" + "\n".join(early), pytrace=False)
    _BUNDLES["check"] = not opted_out
    yield
    failures, _BUNDLES["failures"], _BUNDLES["check"] = _BUNDLES["failures"], [], True
    if failures and not opted_out:
        pytest.fail(f"{request.node.nodeid} exported a v2 bundle the verifier rejects (mark the test "
                    "@pytest.mark.unverified_bundles if that is on purpose):\n" + "\n".join(failures), pytrace=False)


def pytest_terminal_summary(terminalreporter):
    terminalreporter.write_line(f"exported v2 bundles verified: {_BUNDLES['count']} in {_BUNDLES['seconds']:.1f}s")
