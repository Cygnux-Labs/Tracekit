#!/usr/bin/env python3
"""Live view of the ledger: prints each event as the agent works.

  python3 watch.py            follow new events (Ctrl-C to stop)
  python3 watch.py --all      replay everything, then follow
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
from hook import subject  # noqa: E402


def line(r):
    t = time.strftime("%H:%M:%S", time.localtime(r["ts"]))
    ev = r.get("event")
    if ev == "UserPromptSubmit":
        return f"{t}  YOU      {r.get('prompt', '')[:300]}"
    if ev == "model_turn":
        out = []
        for b in r["blocks"]:
            if b["kind"] == "thinking":
                out.append(f"{t}  THINKS   {b['text'][:300]}")
            elif b["kind"] == "thinking_redacted":
                out.append(f"{t}  THINKS   (withheld by provider)")
            elif b["kind"] == "text" and b["text"].strip():
                out.append(f"{t}  SAYS     {b['text'][:300]}")
        return "\n".join(out) or None
    if ev == "PreToolUse":
        p = r.get("policy") or {}
        tag = "BLOCKED " if p.get("decision") == "deny" else "DOES    "
        s = f"{t}  {tag} {r.get('tool_name')}: {subject(r.get('tool_name', ''), r.get('tool_input') or {})[:200]}"
        if p.get("reasons"):
            s += f"\n           ↳ policy: {'; '.join(p['reasons'])}"
        if p.get("flags"):
            s += f"\n           ↳ flags: {', '.join(p['flags'])}"
        return s
    if ev == "PostToolUse":
        resp = r.get("tool_response")
        txt = json.dumps(resp, ensure_ascii=False) if not isinstance(resp, str) else resp
        tag = "FAILED  " if r.get("failed") else "RESULT  "
        return f"{t}  {tag} {txt[:160]}"
    if ev == "judge_verdict":
        v = r.get("verdict") or {}
        return f"{t}  REVIEW   {v.get('alignment')}: {v.get('summary', '')[:300]}"
    return f"{t}  {ev}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--ledger", default=common.LEDGER)
    a = ap.parse_args()
    while not os.path.exists(a.ledger):
        time.sleep(0.5)
    with open(a.ledger, encoding="utf-8") as f:
        if not a.all:
            f.seek(0, os.SEEK_END)
        buf = ""
        while True:
            chunk = f.readline()
            if not chunk:
                time.sleep(0.3)
                continue
            buf += chunk
            if not buf.endswith("\n"):
                continue
            rec, buf = json.loads(buf), ""
            s = line(rec)
            if s:
                print(s, flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
