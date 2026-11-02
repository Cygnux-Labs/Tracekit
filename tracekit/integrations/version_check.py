"""The version check the integrations built by hand share: building one warns, once per process per framework, when
the installed framework is outside the versions Tracekit is tested with, as `tracekit.instrument()` does."""
import threading
import warnings

from tracekit.autowire import _release, _tested, _untested_warning, _version

_LOCK = threading.Lock()
_WARNED = set()   # the frameworks already warned about, this process


def warn_untested(label, req):
    """Warn (once per process) that the framework `label` is installed at a version Tracekit is not tested with.

    `req` is the pip requirement naming the versions Tracekit is tested with (`dist>=lo,<hi`), compared as
    `tracekit.instrument()` compares them. A version that can't be read (the distribution is not installed, or its
    metadata is unreadable) means no warning: this never raises.
    """
    try:
        dist = req.partition(">=")[0]
        version = _version(dist)
        if not version:
            return
        lo, hi = _tested(dist, req)
        if lo <= _release(version) < hi:
            return
    except Exception:
        return
    with _LOCK:
        if label in _WARNED:
            return
        _WARNED.add(label)
    warnings.warn(f"tracekit: {_untested_warning(label, version, req)}", stacklevel=3)
