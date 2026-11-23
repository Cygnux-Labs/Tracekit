from __future__ import annotations

import warnings


def warn_unrecorded(what: str, error: Exception, stacklevel: int = 2) -> None:
    recorded = getattr(error, "recorded", False)
    if recorded is True:
        return
    if recorded is None:
        warnings.warn(f"tracekit: {what} may not have been recorded: {error}", stacklevel=stacklevel + 1)
        return
    warnings.warn(f"tracekit: {what} not recorded: {error}", stacklevel=stacklevel + 1)
