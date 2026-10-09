"""Shared test helpers."""
import time


def wait_for(cond, timeout=10, interval=0.05):
    """Poll cond() until it returns something truthy or the deadline passes; return its last value."""
    deadline = time.monotonic() + timeout
    while True:
        v = cond()
        if v or time.monotonic() >= deadline:
            return v
        time.sleep(interval)
