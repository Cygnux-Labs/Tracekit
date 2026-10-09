"""Quotas per (identity, tenant): event rate, open runs, pending approvals, streams per run, string and line sizes.

Refusals raise RPCError("quota_exceeded") at once. The rate limiter keeps a fixed number of buckets, evicting the least
recently used; nothing resets them all. `summarise` folds the refusals of a window into `refusal.summary` records so a
caller hammering a limit cannot make the signer write one record per refusal.
"""
import math
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from tracekit.signer.rpc_schema import MAX_RAW_ARGS, RPCError

MAX_LINE = 1 << 20   # bytes of one transport frame
COUNT_RETRY_MS = 1000   # a count frees up when a run closes or an approval is answered; no better estimate exists


@dataclass(frozen=True)
class Limits:
    events_per_s: float = 200.0
    burst: int = 400
    open_runs: int = 100
    pending_approvals: int = 100
    streams_per_run: int = 64
    max_string: int = MAX_RAW_ARGS   # characters of any string in a request
    buckets: int = 10000             # rate-limiter keys kept


class Quotas:
    def __init__(self, limits=Limits(), clock=time.monotonic):
        self.limits, self.clock = limits, clock
        self._buckets = OrderedDict()   # key -> (tokens, last refill)
        self._lock = threading.Lock()

    def take_event(self, identity, tenant):
        """Spend one event from the (identity, tenant) token bucket."""
        lim, key = self.limits, (identity.scheme, identity.subject, tenant)
        with self._lock:
            now = self.clock()
            tokens, last = self._buckets.pop(key, (lim.burst, now))
            tokens = min(lim.burst, tokens + (now - last) * lim.events_per_s)
            ok = tokens >= 1
            self._buckets[key] = (tokens - 1 if ok else tokens, now)
            while len(self._buckets) > lim.buckets:
                self._buckets.popitem(last=False)
        if not ok:
            raise RPCError("quota_exceeded", "event rate limit",
                           retry_after_ms=math.ceil((1 - tokens) / lim.events_per_s * 1000))

    def check_count(self, name, current):
        """`name` is open_runs, pending_approvals or streams_per_run; `current` is the count before the new one."""
        if current >= getattr(self.limits, name):
            raise RPCError("quota_exceeded", f"{name} limit {getattr(self.limits, name)}", retry_after_ms=COUNT_RETRY_MS)

    def check_strings(self, value):
        """Refuses a request holding a string longer than max_string. No retry_after_ms: the same request never fits."""
        stack = [value]
        while stack:
            v = stack.pop()
            if isinstance(v, dict):
                stack.extend(v)
                stack.extend(v.values())
            elif isinstance(v, list):
                stack.extend(v)
            elif isinstance(v, str) and len(v) > self.limits.max_string:
                raise RPCError("quota_exceeded", f"string longer than {self.limits.max_string} characters")


def summarise(refusals, window_s):
    """refusals: (ts, identity, tenant, code) tuples -> one `refusal.summary` dict per window, identity, tenant and code."""
    groups = {}
    for ts, identity, tenant, code in refusals:
        k = (math.floor(ts / window_s), identity.scheme, identity.subject, tenant, code)
        first, last, n = groups.get(k, (ts, ts, 0))
        groups[k] = (min(first, ts), max(last, ts), n + 1)
    return [{"type": "refusal.summary", "window_start": w * window_s, "window_s": window_s,
             "identity": {"scheme": scheme, "subject": subject}, "tenant": tenant, "code": code,
             "count": n, "first_ts": first, "last_ts": last}
            for (w, scheme, subject, tenant, code), (first, last, n) in groups.items()]
