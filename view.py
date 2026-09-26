#!/usr/bin/env python3
"""Render the ledger as a local HTML report: for each session, the prompt, the
model's reasoning, every action with its policy decision and result, and the
automatic cross-checks between what the agent said and what it did.

  python3 view.py                 -> ~/.tracekit/report.html
  python3 view.py --out FILE --session ID --flagged-only
"""
import argparse
import html
import json
import os
import sys
import time
from collections import OrderedDict, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
import verify as verifier  # noqa: E402
from hook import subject, WRITE_TOOLS  # noqa: E402

FLAG_TEXT = {
    "denied": "Blocked by policy",
    "network": "Network access",
    "destructive": "Destructive command",
    "side_effect": "External side effect",
    "secrets_access": "Touched secrets/credentials",
    "external_tool": "External (MCP) tool",
    "out_of_scope_write": "Wrote outside the project folder",
    "silent_action": "Acted with no stated reasoning",
    "unmentioned_file": "Changed a file never mentioned in prompt or reasoning",
    "tool_error": "Tool returned an error",
    "no_result": "No result recorded (interrupted or failed)",
    "reasoning_withheld": "Provider withheld reasoning",
}
SEVERE = {"denied", "out_of_scope_write", "secrets_access", "unmentioned_file"}


def key_of(tool, ti):
    return f"{tool}|{common.canon(ti)}"


def is_error(resp):
    if isinstance(resp, dict):
        if resp.get("is_error") or resp.get("error") or resp.get("interrupted"):
            return True
        if resp.get("success") is False:
            return True
    return False


def build_sessions(records):
    """Two passes per session. Transcripts are flushed a step behind the hooks, so
    reasoning often lands in the ledger AFTER the action it explains. Pass 1 groups
    model output by message and maps each tool_use id to it; pass 2 builds the
    timeline and places each message's reasoning directly before its action."""
    sessions = OrderedDict()
    for r in records:
        sessions.setdefault(r.get("session_id") or "unknown", []).append(r)
    out = []
    for sid, recs in sessions.items():
        # ---- pass 1: group model turns by message id
        groups, order, gid_for_tool, gid_for_key = {}, [], {}, {}
        usage, models = defaultdict(int), set()
        for r in recs:
            if r.get("event") != "model_turn":
                continue
            gid = r.get("message_id") or r.get("transcript_uuid") or f"seq{r['seq']}"
            if gid not in groups:
                groups[gid] = {"id": gid, "model": r.get("model"), "blocks": [], "first_seq": r["seq"], "ts": r["ts"]}
                order.append(gid)
                for k, v in (r.get("usage") or {}).items():
                    if isinstance(v, int):
                        usage[k] += v
            models.add(r.get("model") or "?")
            groups[gid]["blocks"] += r["blocks"]
            for b in r["blocks"]:
                if b["kind"] == "tool_use":
                    if b.get("tool_use_id"):
                        gid_for_tool[b["tool_use_id"]] = gid
                    gid_for_key.setdefault(key_of(b["tool_name"], b["tool_input"]), gid)
        for g in groups.values():
            g["texts"] = [b["text"] for b in g["blocks"] if b["kind"] in ("thinking", "text") and b["text"].strip()]
            g["withheld"] = any(b["kind"] == "thinking_redacted" for b in g["blocks"])

        # ---- pass 2: timeline
        items, said, placed = [], [], set()
        actions_by_id, actions_by_key = {}, defaultdict(list)

        def place(gid):
            if gid and gid not in placed:
                placed.add(gid)
                g = groups[gid]
                said.extend(g["texts"])
                if g["texts"] or g["withheld"]:
                    items.append({"kind": "reasoning", "group": g})

        for r in recs:
            ev = r.get("event")
            if ev == "UserPromptSubmit":
                said.append(r.get("prompt") or "")
                items.append({"kind": "prompt", "rec": r})
            elif ev == "model_turn":
                gid = r.get("message_id") or r.get("transcript_uuid") or f"seq{r['seq']}"
                has_tool = any(b["kind"] == "tool_use" for b in groups[gid]["blocks"])
                if not has_tool:  # pure text (e.g. final answer): show where it happened
                    place(gid)
            elif ev == "PreToolUse":
                tool, ti = r.get("tool_name"), r.get("tool_input") or {}
                gid = gid_for_tool.get(r.get("tool_use_id")) or gid_for_key.get(key_of(tool, ti))
                place(gid)
                a = {"kind": "action", "pre": r, "post": None, "flags": []}
                pol = r.get("policy") or {}
                if pol.get("decision") == "deny":
                    a["flags"].append("denied")
                a["flags"] += pol.get("flags", [])
                if gid:
                    g = groups[gid]
                    if not g["texts"]:
                        a["flags"].append("reasoning_withheld" if g["withheld"] else "silent_action")
                context = "\n".join(said)
                if tool in WRITE_TOOLS:
                    path = str(ti.get("file_path") or ti.get("notebook_path") or "")
                    base = os.path.basename(path)
                    if base and base not in context and path not in context:
                        a["flags"].append("unmentioned_file")
                items.append(a)
                if r.get("tool_use_id"):
                    actions_by_id[r["tool_use_id"]] = a
                actions_by_key[key_of(tool, ti)].append(a)
            elif ev == "PostToolUse":
                a = actions_by_id.get(r.get("tool_use_id"))
                if not a:
                    q = actions_by_key.get(key_of(r.get("tool_name"), r.get("tool_input") or {}), [])
                    a = next((x for x in q if x["post"] is None), None)
                if a:
                    a["post"] = r
                    if r.get("failed") or is_error(r.get("tool_response")):
                        a["flags"].append("tool_error")
            else:
                items.append({"kind": "event", "rec": r})
        for gid in order:  # anything never matched to an action
            place(gid)
        for it in items:
            if it["kind"] == "action":
                if it["post"] is None and "denied" not in it["flags"]:
                    it["flags"].append("no_result")
                it["flags"] = sorted(set(it["flags"]), key=lambda f: (f not in SEVERE, f))
        ts = [r["ts"] for r in recs]
        acts = [i for i in items if i["kind"] == "action"]
        out.append({"id": sid, "items": items, "start": min(ts), "end": max(ts),
                    "cwd": next((r.get("cwd") for r in recs if r.get("cwd")), ""),
                    "n_actions": len(acts),
                    "n_flagged": sum(1 for a in acts if a["flags"]),
                    "n_severe": sum(1 for a in acts if SEVERE & set(a["flags"])),
                    "n_denied": sum(1 for a in acts if "denied" in a["flags"]),
                    "usage": dict(usage), "models": sorted(models)})
    return out


E = html.escape


def fmt_ts(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))


def pre(obj, limit=4000):
    s = obj if isinstance(obj, str) else json.dumps(obj, indent=2, ensure_ascii=False)
    return f"<pre>{E(s[:limit])}{'…' if len(s) > limit else ''}</pre>"


def render_item(it):
    if it["kind"] == "prompt":
        r = it["rec"]
        return f'<div class="card prompt"><div class="lbl">You asked · {fmt_ts(r["ts"])}</div>{pre(r.get("prompt") or "")}</div>'
    if it["kind"] == "reasoning":
        r, parts = it["group"], []
        for b in r["blocks"]:
            if b["kind"] == "thinking":
                parts.append(f'<details open><summary>Thinking (as reported by the model)</summary>{pre(b["text"])}</details>')
            elif b["kind"] == "thinking_redacted" and not any(x["kind"] == "thinking_redacted" for x in r["blocks"][:r["blocks"].index(b)]):
                parts.append('<div class="muted">Thinking happened but the provider withheld its text.</div>')
            elif b["kind"] == "text" and b["text"].strip():
                parts.append(f'<div class="said">{pre(b["text"])}</div>')
        return f'<div class="card reasoning"><div class="lbl">Model · {E(r.get("model") or "")}</div>{"".join(parts)}</div>'
    if it["kind"] == "action":
        p, post = it["pre"], it["post"]
        tool, ti = p.get("tool_name", ""), p.get("tool_input") or {}
        pol = (p.get("policy") or {})
        chips = "".join(f'<span class="chip {"sev" if f in SEVERE else ""}">{E(FLAG_TEXT.get(f, f))}</span>' for f in it["flags"])
        reasons = "".join(f"<div class='deny'>Denied: {E(x)}</div>" for x in pol.get("reasons", []))
        result = f'<details><summary>Result</summary>{pre(post.get("tool_response"))}</details>' if post else ""
        cls = "action flagged" if it["flags"] else "action"
        return (f'<div class="card {cls}" data-flagged="{1 if it["flags"] else 0}">'
                f'<div class="lbl">Action · {E(tool)} · {fmt_ts(p["ts"])} · seq {p["seq"]}</div>'
                f'<div class="subj">{E(subject(tool, ti)[:400])}</div>{chips}{reasons}'
                f'<details><summary>Full input</summary>{pre(ti)}</details>{result}</div>')
    r = it["rec"]
    if r.get("event") == "judge_verdict":
        v = r.get("verdict") or {}
        al = v.get("alignment", "?")
        cls = "sev" if al == "misaligned" else ""
        finds = "".join(
            f'<div style="margin-top:8px"><span class="chip {"sev" if f.get("severity") == "high" else ""}">'
            f'{E(str(f.get("severity")))} · {E(str(f.get("type")))}</span>{pre(f.get("evidence", ""))}'
            f'<div class="muted" style="font-size:12px">{E(f.get("why_it_matters", ""))}</div></div>'
            for f in v.get("findings", []))
        return (f'<div class="card judge"><div class="lbl">Independent review · {E(r.get("judge_model") or "")} · {fmt_ts(r["ts"])}</div>'
                f'<span class="chip {cls}">alignment: {E(al)}</span>{pre(v.get("summary", ""))}{finds}</div>')
    return f'<div class="card event"><span class="lbl">{E(r.get("event", "?"))} · {fmt_ts(r["ts"])}</span></div>'


CSS = """
:root{--bg:#f7f6f3;--fg:#1d1d1b;--muted:#6b6a66;--card:#fff;--line:#e3e1dc;--acc:#2f6fdb;--warn:#b7791f;--sev:#c53030;--ok:#2f855a}
:root[data-theme=dark]{color-scheme:dark;--bg:#161615;--fg:#ecebe8;--muted:#9c9a95;--card:#201f1e;--line:#33322f;--acc:#6ea0ff;--warn:#e0a84a;--sev:#ff6b6b;--ok:#5fc48a}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){color-scheme:dark;--bg:#161615;--fg:#ecebe8;--muted:#9c9a95;--card:#201f1e;--line:#33322f;--acc:#6ea0ff;--warn:#e0a84a;--sev:#ff6b6b;--ok:#5fc48a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}
header{padding:16px 20px;border-bottom:1px solid var(--line);display:flex;gap:16px;align-items:center;flex-wrap:wrap}
h1{font-size:18px;margin:0}.integrity{padding:4px 10px;border-radius:99px;font-weight:600}
.integrity.ok{background:color-mix(in srgb,var(--ok) 15%,transparent);color:var(--ok)}
.integrity.bad{background:color-mix(in srgb,var(--sev) 15%,transparent);color:var(--sev)}
main{display:grid;grid-template-columns:300px 1fr;min-height:calc(100vh - 60px)}
nav{border-right:1px solid var(--line);overflow:auto}nav a{display:block;padding:10px 16px;border-bottom:1px solid var(--line);color:inherit;text-decoration:none}
nav a:hover,nav a.on{background:var(--card)}.sid{font-family:ui-monospace,monospace;font-size:12px}
.stats{color:var(--muted);font-size:12px}.sevn{color:var(--sev);font-weight:600}
section{padding:16px 20px;display:none}section.on{display:block}
.card{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--line);border-radius:8px;padding:10px 12px;margin:8px 0}
.prompt{border-left-color:var(--acc)}.judge{border-left-color:var(--ok)}.reasoning{border-left-color:var(--muted)}.action.flagged{border-left-color:var(--warn)}
.lbl{font-size:12px;color:var(--muted);margin-bottom:4px}.subj{font-family:ui-monospace,monospace;font-size:13px;word-break:break-all}
.chip{display:inline-block;font-size:11px;padding:1px 8px;border-radius:99px;margin:6px 6px 0 0;background:color-mix(in srgb,var(--warn) 18%,transparent);color:var(--warn)}
.chip.sev{background:color-mix(in srgb,var(--sev) 18%,transparent);color:var(--sev)}.deny{color:var(--sev);font-size:12px;margin-top:4px}
pre{white-space:pre-wrap;word-break:break-word;margin:4px 0;font:12px/1.45 ui-monospace,monospace;max-height:400px;overflow:auto}
summary{cursor:pointer;color:var(--muted);font-size:12px}.muted{color:var(--muted)}.event{padding:4px 12px;border-left-color:transparent}
label{font-size:13px}.hide-clean .card:not(.flagged){display:none}
@media (max-width:760px){main{grid-template-columns:1fr}nav{max-height:220px;border-right:0;border-bottom:1px solid var(--line)}}
"""


def render(sessions, integrity):
    n, problems, head = integrity
    badge = (f'<span class="integrity ok">Ledger intact · {n} records</span>' if not problems else
             f'<span class="integrity bad">Tampering detected · {len(problems)} problems</span>')
    nav, secs = [], []
    for i, s in enumerate(sorted(sessions, key=lambda s: -s["start"])):
        on = " on" if i == 0 else ""
        tok = s["usage"].get("output_tokens", 0)
        nav.append(f'<a href="#" data-s="{i}" class="{on.strip()}"><div class="sid">{E(s["id"][:18])}</div>'
                   f'<div class="stats">{fmt_ts(s["start"])} · {s["n_actions"]} actions · '
                   f'<span class="{"sevn" if s["n_severe"] else ""}">{s["n_flagged"]} flagged</span></div></a>')
        head_html = (f'<h2 style="font-size:16px;margin:0 0 4px">Session {E(s["id"])}</h2>'
                     f'<div class="stats">{E(s["cwd"] or "")} · {fmt_ts(s["start"])} → {fmt_ts(s["end"])} · '
                     f'models: {E(", ".join(s["models"]) or "n/a")} · output tokens: {tok} · '
                     f'{s["n_denied"]} blocked · {s["n_severe"]} severe flags</div>')
        body = "".join(render_item(it) for it in s["items"])
        secs.append(f'<section data-s="{i}" class="{on.strip()}">{head_html}{body}</section>')
    probs = "".join(f"<li>{E(p)}</li>" for p in problems)
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent Trace Report</title><style>{CSS}</style></head><body>
<header><h1>Agent Trace Report</h1>{badge}<span class="stats">head {E((head or '')[:16])}…</span>
<label><input type="checkbox" id="fo"> Flagged actions only</label></header>
{'<ul style="color:var(--sev);padding:0 36px">' + probs + '</ul>' if problems else ''}
<main><nav>{''.join(nav) or '<p style="padding:16px">No sessions recorded yet.</p>'}</nav><div id="c">{''.join(secs)}</div></main>
<script>
document.querySelectorAll('nav a').forEach(a=>a.onclick=e=>{{e.preventDefault();
document.querySelectorAll('nav a,section').forEach(x=>x.classList.toggle('on',x.dataset.s===a.dataset.s));}});
document.getElementById('fo').onchange=e=>document.getElementById('c').classList.toggle('hide-clean',e.target.checked);
</script></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", default=common.LEDGER)
    ap.add_argument("--out", default=os.path.join(common.HOME, "report.html"))
    ap.add_argument("--session")
    ap.add_argument("--json", action="store_true", help="print the session summaries as JSON")
    a = ap.parse_args()
    records = common.read_ledger(a.ledger)
    sessions = build_sessions(records)
    if a.session:
        sessions = [s for s in sessions if s["id"].startswith(a.session)]
    if a.json:
        print(json.dumps([{k: v for k, v in s.items() if k != "items"} for s in sessions], indent=2))
        return
    integrity = verifier.verify(a.ledger)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(render(sessions, integrity))
    print(f"Wrote {a.out} ({len(sessions)} sessions)")


if __name__ == "__main__":
    main()
