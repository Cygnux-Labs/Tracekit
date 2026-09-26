#!/usr/bin/env python3
"""A NON-Claude agent traced with tracekit_sdk: a toy research pipeline with two
parallel workers. The 'tools' are stubs (no network), so this runs anywhere; swap
in your real framework calls. Shows up in the observer as its own session."""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from tracekit_sdk import Tracer  # noqa: E402

t = Tracer(agent="research-bot")
t.prompt("Compare the Q3 revenue of two companies and flag anything unusual.")
t.think("Two independent lookups, so run two workers in parallel, then compare.")


def worker(name, ticker, fail=False):
    w = t.subagent("fetcher", f"Fetch {ticker} Q3 figures")
    w.think(f"Look up {ticker} filings, then extract revenue.")
    with w.tool("http_get", {"url": f"https://filings.example/{ticker}/10q"}) as c:
        time.sleep(0.8)
        c.result({"status": 200, "bytes": 18234})
    try:
        with w.tool("parse_table", {"doc": f"{ticker}-10q", "field": "revenue"}) as c:
            time.sleep(0.5)
            if fail:
                raise ValueError("table not found on page 4")
            c.result({"revenue_musd": 412.7})
    except ValueError:
        w.say("Parsing failed; reporting partial result.")
    w.done(f"{ticker}: " + ("revenue unavailable" if fail else "revenue 412.7M"))


th = [threading.Thread(target=worker, args=("a", "ACME")), threading.Thread(target=worker, args=("b", "GLOBX", True))]
[x.start() for x in th]
[x.join() for x in th]
try:
    with t.tool("Bash", {"command": "sudo cp report.csv /var/reports/"}) as c:
        pass
except PermissionError as e:
    t.say(f"Could not publish: {e}")
t.done("ACME reported 412.7M; GLOBX figures could not be parsed.")
t.end()
print("custom agent finished; session", t.session_id)
