import glob
import io
import json
import os
import shutil
import socketserver
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
SHELL_ENV = ("TRACEKIT_POLICY", "TRACEKIT_SOCKET", "TRACEKIT_CLIENT_HOME", "TRACEKIT_APPROVAL_WAIT",
             "CLAUDE_CONFIG_DIR", "GEMINI_CLI_SYSTEM_SETTINGS_PATH", "GEMINI_CLI_SYSTEM_DEFAULTS_PATH", "XDG_CONFIG_HOME",
             "CODEX_HOME", "CODEBUDDY_CONFIG_DIR", "CODEBUDDY_PROJECT_CONFIG_DIR", "GEMINI_CLI_HOME")
PROXIES = urllib.request.getproxies()

# A test's servers stop when it ends, and shutdown() returns once serve_forever sees it: after up to a poll interval
# (the stdlib's 0.5 s, the signer's 0.2 s). Thousands stop in a run; polled every 0.02 s they stop at once.
_serve_forever = socketserver.BaseServer.serve_forever
socketserver.BaseServer.serve_forever = lambda self, poll_interval=0.5: _serve_forever(self, min(poll_interval, 0.02))


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
    # and a runtime dir of the session's own: the per-user one is a developer's own dev signer's (a test that set none
    # recorded into its store) and, on Windows, inside the dev data dir (#516's CI)
    run = tempfile.mkdtemp(prefix="tk-run-", dir="/tmp" if os.name == "posix" else None)   # short: socket paths
    with pytest.MonkeyPatch.context() as mp:
        for k in SHELL_ENV:
            mp.delenv(k, raising=False)
        mp.setenv("TRACEKIT_RUNTIME_DIR", run)
        yield
    for d in [run, *glob.glob(run + "-*")]:   # and the side dirs (autospawn._side) of other HOMEs' signers
        try:   # a dev signer a test started there and left running
            from tracekit.sdk import autospawn
            autospawn.down(d=d)
        except ImportError:   # no v2 extra: no dev signer
            pass
        except (OSError, autospawn.Hung) as e:   # fails the session at its end, not the test that ran last
            _LEFT_RUNNING.append(f"{d}: {e}")
        finally:
            shutil.rmtree(d, ignore_errors=True)


_LEFT_RUNNING = []


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


# The real home's Tracekit folders, each with what places it, as the session starts. A test that makes one wrote outside
# its temp dirs, and the dev data dir also turns the plugin's hook from warning to blocking (#515). Silent where they
# already exist; a folder made outside any test (setUpClass, a module fixture) fails the session at its end.
# `~` comes from USERPROFILE on Windows, and the dev data dir follows the platform's own data directory: name what
# places each folder on the OS the tests run on (autospawn.data_dir).
_CLIENT_HOME_HINT = "TRACEKIT_CLIENT_HOME, or USERPROFILE" if os.name == "nt" else "TRACEKIT_CLIENT_HOME, or HOME"
HOME_DIRS = {os.path.join(os.path.expanduser("~"), ".tracekit-client"): _CLIENT_HOME_HINT}
try:   # the signer needs the v2 extra (the release dry run installs none); without it no dev data dir is made
    from tracekit.sdk import autospawn
    if os.name == "nt":
        _DATA_DIR_HINT = "LOCALAPPDATA"
    elif sys.platform == "darwin":
        _DATA_DIR_HINT = "HOME"
    else:
        _DATA_DIR_HINT = "XDG_DATA_HOME or HOME"
    HOME_DIRS[autospawn.data_dir()] = _DATA_DIR_HINT
except ImportError:
    pass
_HOME_DIRS_BEFORE = {p for p in HOME_DIRS if os.path.exists(p)}


def _made(before):
    """The folders made since `before`, each as the error names it; counted as known from now on."""
    made = [p for p in HOME_DIRS if p not in before and os.path.exists(p)]
    _HOME_DIRS_BEFORE.update(made)
    return [f"{p} (set {HOME_DIRS[p]} to a temp dir)" for p in made]


@pytest.fixture(autouse=True)
def _no_real_home_dirs(request):
    before = {p for p in HOME_DIRS if os.path.exists(p)}
    yield
    made = _made(before)
    if made:
        pytest.fail(f"{request.node.nodeid} made {made} in the real home folder", pytrace=False)


def pytest_sessionfinish(session):
    made = _made(set(_HOME_DIRS_BEFORE))
    if made:
        print(f"\nthis session made {made} in the real home folder, outside any test", file=sys.stderr)
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
    if _LEFT_RUNNING:
        print(f"\na dev signer a test left running in the session's runtime dir didn't stop: {_LEFT_RUNNING}",
              file=sys.stderr)
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


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
