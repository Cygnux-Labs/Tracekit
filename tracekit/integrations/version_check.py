"""The version check the integrations built by hand share: building one warns, once per process per framework, when
the installed framework is outside the versions Tracekit is tested with, as `tracekit.instrument()` does."""
import threading
import warnings

from tracekit.autowire import _release, _untested_warning, _version

_LOCK = threading.Lock()
_WARNED = set()   # the frameworks already warned about, this process


def warn_untested(label, dist, lo, hi, req):
    """Warn (once per process) that the framework `label` is installed at a version Tracekit is not tested with.

    `dist` is the distribution whose installed version is read, `lo` and `hi` the release tuples of the versions
    Tracekit is tested with (as `tracekit.instrument()` compares them), and `req` the pip requirement naming them. A
    version that can't be read (the distribution is not installed, or its metadata is unreadable) means no warning:
    this never raises.
    """
    try:
        version = _version(dist)
        if not version:
            return
        if lo <= _release(version) < hi:
            return
    except Exception:
        return
    with _LOCK:
        if label in _WARNED:
            return
        _WARNED.add(label)
    warnings.warn(f"tracekit: {_untested_warning(label, version, req)}", stacklevel=3)
