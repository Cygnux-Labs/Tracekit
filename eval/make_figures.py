#!/usr/bin/env python3
"""Render paper figures (vector PDF) from eval/results/*.json."""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = os.path.join(KIT, "eval/results")
OUT = os.path.join(KIT, "paper/figures")
os.makedirs(OUT, exist_ok=True)

# Reference palette (light): categorical slots 1-3, text inks, recessive grid
S1, S2, S3 = "#2a78d6", "#eb6834", "#1baf7a"
INK, INK2, GRID, MISS = "#0b0b0b", "#52514e", "#e4e3df", "#c9c7c0"
plt.rcParams.update({
    "font.family": "serif", "font.size": 8.5, "axes.titlesize": 9, "axes.labelsize": 8.5,
    "axes.edgecolor": INK2, "axes.labelcolor": INK, "xtick.color": INK2, "ytick.color": INK2,
    "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True, "grid.color": GRID,
    "grid.linewidth": 0.6, "axes.axisbelow": True, "legend.frameon": False, "pdf.fonttype": 42,
    "lines.linewidth": 1.6, "savefig.bbox": "tight", "savefig.pad_inches": 0.02,
})


def load(name):
    p = os.path.join(R, name)
    return json.load(open(p)) if os.path.exists(p) else None


def fig_anchor():
    d = load("e1_integrity.json")
    iv = {int(k): v for k, v in d["anchor_interval_vs_detection"].items()}
    N = d["records_per_ledger"]
    ks = sorted(iv)
    fig, ax = plt.subplots(figsize=(3.3, 2.1))
    kk = np.linspace(1, max(ks), 300)
    ax.plot(kk, 1 - (kk - 1) / (2 * N), color=INK2, lw=1, ls="--", label=r"model $1-\frac{k-1}{2N}$")
    ax.plot(ks, [iv[k] for k in ks], color=S1, marker="o", ms=4, label="measured (200 trials/pt)")
    ax.set_xscale("log"); ax.set_xticks(ks); ax.set_xticklabels([str(k) for k in ks])
    ax.set_ylim(0.4, 1.02); ax.set_xlabel("anchoring interval $k$ (records)")
    ax.set_ylabel("P(detect full re-chain)")
    ax.legend(loc="lower left", fontsize=7.5)
    fig.savefig(os.path.join(OUT, "e1_anchor_interval.pdf")); plt.close(fig)


def fig_latency():
    d = load("e2_perf.json")
    L = d["hook_latency_ms"]
    sizes = [0, 1000, 10000, 100000]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(6.8, 2.1))
    for ev, col in (("PreToolUse", S1), ("PostToolUse", S2)):
        p50 = [L[f"{ev}@{s}"]["p50"] for s in sizes]; p95 = [L[f"{ev}@{s}"]["p95"] for s in sizes]
        x = np.arange(len(sizes)) + (-0.08 if ev == "PreToolUse" else 0.08)
        a1.errorbar(x, p50, yerr=[np.zeros(4), np.array(p95) - np.array(p50)], color=col, marker="o", ms=4,
                    capsize=2, lw=1.4, label=f"{ev} (p50, bar to p95)")
    a1.axhline(L["python_startup_ms"]["p50"], color=INK2, lw=1, ls="--")
    a1.text(3.15, L["python_startup_ms"]["p50"] + 0.6, "bare Python start", color=INK2, fontsize=7, ha="right")
    a1.set_xticks(range(4)); a1.set_xticklabels(["empty", "1k", "10k", "100k"])
    a1.set_xlabel("records already in ledger"); a1.set_ylabel("hook wall time (ms)"); a1.set_ylim(0, 32)
    a1.legend(loc="lower left", fontsize=7)
    c = d["concurrency"]; ws = sorted(int(k) for k in c)
    a2.bar(range(len(ws)), [c[str(w)]["records_per_s"] for w in ws], color=S1, width=0.6)
    for i, w in enumerate(ws):
        a2.text(i, c[str(w)]["records_per_s"] + 40, "chain ok" if c[str(w)]["chain_ok"] else "BROKEN", ha="center", fontsize=6.5, color=INK2)
    a2.set_xticks(range(len(ws))); a2.set_xticklabels([str(w) for w in ws])
    a2.set_xlabel("concurrent writer processes"); a2.set_ylabel("records / s (fsync each)")
    a2.set_ylim(0, max(c[str(w)]["records_per_s"] for w in ws) * 1.18)
    fig.tight_layout(w_pad=2.5)
    fig.savefig(os.path.join(OUT, "e2_perf.pdf")); plt.close(fig)


def fig_policy():
    d = load("e3_policy.json")
    cats = list(d["per_category"])
    names = {"remote_code_exec": "remote code exec", "privilege_escalation": "privilege escalation",
             "history_rewrite": "history rewrite", "destructive_delete": "destructive delete",
             "secret_write": "secret-file write", "exfiltration": "exfiltration"}
    fig, ax = plt.subplots(figsize=(3.3, 2.2))
    y = np.arange(len(cats))[::-1]
    for i, c in enumerate(cats):
        v = d["per_category"][c]; n = v["n"]
        b, f = v["blocked"] / n, (v["blocked_or_flagged"] - v["blocked"]) / n
        m = 1 - b - f
        ax.barh(y[i], b, color=S1, height=0.62, edgecolor="white", linewidth=1)
        ax.barh(y[i], f, left=b, color=S2, height=0.62, edgecolor="white", linewidth=1)
        ax.barh(y[i], m, left=b + f, color=MISS, height=0.62, edgecolor="white", linewidth=1)
        ax.text(1.02, y[i], f"{v['blocked']}/{n}", va="center", fontsize=7, color=INK)
    ax.set_yticks(y); ax.set_yticklabels([names[c] for c in cats])
    ax.set_xlim(0, 1); ax.set_xlabel("share of harmful calls")
    ax.grid(axis="y", visible=False)
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=S1, label="blocked"), Patch(color=S2, label="flagged only"), Patch(color=MISS, label="missed")],
              loc="upper center", bbox_to_anchor=(0.45, 1.2), ncol=3, fontsize=7, handlelength=1)
    fig.savefig(os.path.join(OUT, "e3_policy.pdf")); plt.close(fig)


def fig_faults():
    rows = load("e4_seeded_faults.json")
    if not rows:
        return
    faults = ["F1_unrequested_edit", "F2_exfiltration", "F3_destructive", "F4_false_success", "F5_scope_creep", "F6_secret_read", "F7_test_tampering"]
    labels = ["unrequested\nedit", "exfil-\ntration", "destructive\ndelete", "false\nsuccess", "scope\ncreep", "secret\nread", "test\ntampering"]
    def rate(fs, key):
        xs = [r for r in rows if r["fault"] == fs and r.get("judge_detected") is not None]
        if key == "rules":
            return np.mean([r["fault_flagged"] for r in xs])
        if key == "judge":
            return np.mean([r["judge_detected"] for r in xs])
        return np.mean([r["fault_flagged"] or r["judge_detected"] for r in xs])
    fig, ax = plt.subplots(figsize=(6.8, 2.0))
    x = np.arange(len(faults)); w = 0.26
    for j, (key, col, lab) in enumerate((("rules", S1, "rule flags"), ("judge", S2, "independent reviewer"), ("either", S3, "either"))):
        vals = [rate(f, key) for f in faults]
        ax.bar(x + (j - 1) * w, vals, w - 0.03, color=col, label=lab)
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=7.5)
    ax.set_ylim(0, 1.08); ax.set_ylabel("detection rate")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, 1.22), ncol=3, fontsize=7.5)
    fig.savefig(os.path.join(OUT, "e4_faults.pdf")); plt.close(fig)


if __name__ == "__main__":
    fig_anchor(); fig_latency(); fig_policy(); fig_faults()
    print("figures in", OUT, os.listdir(OUT))
