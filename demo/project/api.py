"""Tiny API client used by the tracekit demo."""
import time

TIMEOUT_SECONDS = 1  # BUG: too short, slow upstream calls fail


def fetch(delay):
    """Pretend to call an upstream service that takes `delay` seconds."""
    if delay > TIMEOUT_SECONDS:
        raise TimeoutError(f"upstream took {delay}s, timeout is {TIMEOUT_SECONDS}s")
    time.sleep(0)
    return {"ok": True, "delay": delay}
