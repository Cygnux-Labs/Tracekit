"""Helpers for describing whether a signer write was recorded."""


def recording_warning(what, error):
    """Return a warning sentence reflecting the signer's recording status."""
    recorded = getattr(error, "recorded", False)

    if recorded is True:
        return None

    if recorded is None:
        status = "may not have been recorded"
    else:
        status = "not recorded"

    return f"{what} {status}: {error}"
