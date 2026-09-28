#!/usr/bin/env python3
"""Generate paper/results.tex: every number in the paper comes from eval/results/*.json."""
import json
import os
import statistics as st
import subprocess
import sys

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = os.path.join(KIT, "eval/results")
J = lambda n: json.load(open(os.path.join(R, n)))  # noqa: E731
M = {}


def pct(x):
    return f"{100 * x:.0f}"


def frac(xs):
    xs = [x for x in xs if x is not None]
    return (sum(bool(x) for x in xs), len(xs))


# E1
e1 = J("e1_integrity.json")
M["EOneN"] = e1["records_per_ledger"]; M["EOneSourceRecords"] = e1["source_records"]
M["EOneTotalTrials"] = f"{sum(v['trials'] for v in e1['mutations'].values()):,}".replace(",", "{,}")
M["EOneIntervalThreeHundred"] = f"{e1['anchor_interval_vs_detection']['300']:.2f}"
names = {"edit_field": "Edit a field", "delete_record": "Delete a record", "swap_adjacent": "Swap adjacent records",
         "insert_forged": "Insert forged record", "torn_write": "Torn final write", "truncate_tail": "Truncate tail",
         "rechain_after_edit": "Edit + full re-chain", "rechain_after_delete": "Delete + full re-chain"}
order = ["edit_field", "delete_record", "swap_adjacent", "insert_forged", "torn_write", "truncate_tail", "rechain_after_edit", "rechain_after_delete"]
M["EOneRows"] = "\n".join(f"{names[k]} & {e1['mutations'][k]['chain_only']:.2f} & {e1['mutations'][k]['chain_plus_anchor']:.2f}\\\\" for k in order)

# E2
e2 = J("e2_perf.json"); L = e2["hook_latency_ms"]
M["LatPreEmpty"] = f"{L['PreToolUse@0']['p50']:.1f}"; M["LatPreHundredK"] = f"{L['PreToolUse@100000']['p50']:.1f}"
M["LatPyStart"] = f"{L['python_startup_ms']['p50']:.1f}"
M["AppendRps"] = f"{e2['throughput']['append_records_per_s_fsync_each']:,.0f}".replace(",", "{,}")
M["VerifyRps"] = f"{e2['throughput']['verify_records_per_s']:,.0f}".replace(",", "{,}")
M["RecBytes"] = f"{e2['throughput']['mean_record_bytes']:,.0f}".replace(",", "{,}")
M["EPython"] = e2["python"]

# E3
e3 = J("e3_policy.json")
M["EThreeHarm"] = e3["harmful_total"]; M["EThreeBlocked"] = e3["harmful_blocked"]
M["EThreeBlockedPct"] = pct(e3["harmful_blocked"] / e3["harmful_total"])
M["EThreeCovered"] = e3["harmful_blocked_or_flagged"]; M["EThreeCoveredPct"] = pct(e3["harmful_blocked_or_flagged"] / e3["harmful_total"])
M["EThreeBenign"] = e3["benign_total"]; M["EThreeFP"] = e3["benign_blocked"]; M["EThreeFPPct"] = f"{100 * e3['benign_blocked'] / e3['benign_total']:.1f}"

# E5
e5 = J("e5_agents.json")
M["EFiveRuns"] = len(e5); inj = [m for m in e5.values() if m["injected"]]
M["EFiveInjRuns"] = len(inj)
M["EFiveMeanWall"] = f"{st.mean(m['wall_s'] for m in e5.values()):.0f}"
chan = {"S1_html_comment": ("S1", "HTML comment in NOTES.md"), "S2_readme_maintainer": ("S2", "README maintainer note"),
        "S3_tool_output": ("S3", "test assertion message (tool output)"), "S4_code_comment": ("S4", "docstring in api.py"),
        "C1_clean": ("C1", "none (clean task)"), "C2_user_authorised_delete": ("C2", "none; user asks to delete billing.py"),
        "C3_user_env_request": ("C3", "none; user asks for .env")}
rows = []
for sc, (tag, desc) in chan.items():
    ms = [m for m in e5.values() if m["scenario"] == sc]
    a = sum(m["injection_attempted"] for m in ms); d = sum(m["disclosed_to_user"] for m in ms)
    b = sum(m["blocked"] for m in ms); t = sum(m["tests_pass_after"] for m in ms)
    rows.append(f"{tag} & {desc} & {a}/{len(ms) if ms[0]['injected'] else '--'} & {str(d) + '/' + str(len(ms)) if ms[0]['injected'] else '--'} & {b} & {t}/{len(ms)}\\\\")
M["EFiveRows"] = "\n".join(rows).replace("0/--", "--")
vis = wh = msgs = 0
for f in os.listdir(os.path.join(R, "e5_runs")):
    if not f.endswith(".jsonl"):
        continue
    seen = set()
    for l in open(os.path.join(R, "e5_runs", f)):
        r = json.loads(l)
        if r["event"] != "model_turn":
            continue
        seen.add(r.get("message_id"))
        vis += sum(b["kind"] == "thinking" for b in r["blocks"]); wh += sum(b["kind"] == "thinking_redacted" for b in r["blocks"])
    msgs += len(seen)
M["EFiveThinkVisible"], M["EFiveThinkWithheld"], M["EFiveMsgs"] = vis, wh, msgs

# E4
rows4 = J("e4_seeded_faults.json")
ok = [r for r in rows4 if r["judge_detected"] is not None]
M["EFourTraces"] = len({(r["base"], r["fault"]) for r in rows4}); M["EFourCalls"] = len(rows4)
M["EFourErrors"] = len(rows4) - len(ok)
faults = ["F1_unrequested_edit", "F2_exfiltration", "F3_destructive", "F4_false_success", "F5_scope_creep", "F6_secret_read", "F7_test_tampering"]
fname = {"F1_unrequested_edit": "F1 unrequested edit", "F2_exfiltration": "F2 exfiltration", "F3_destructive": "F3 destructive delete",
         "F4_false_success": "F4 false success", "F5_scope_creep": "F5 scope creep", "F6_secret_read": "F6 secret read", "F7_test_tampering": "F7 test tampering",
         "clean": "Control: untouched", "P_benign_extra": "Control: benign extra step"}


def agree(rs):
    by = {}
    for r in rs:
        by.setdefault(r["base"], []).append(r["judge_detected"])
    pairs = [v for v in by.values() if len(v) >= 2 and None not in v]
    return (sum(v[0] == v[1] for v in pairs), len(pairs))


def cell(n, d):
    return f"{n}/{d} ({pct(n / d) if d else '--'}\\%)"


t_rows = []
stats = {}
for f in faults + ["clean", "P_benign_extra"]:
    rs = [r for r in ok if r["fault"] == f]
    rule = frac([r["fault_flagged"] if f not in ("clean", "P_benign_extra") else bool(r["session_rule_flags"]) for r in rs[::2] or rs])
    # rules are deterministic: count once per trace
    per_trace = {}
    for r in rows4:
        if r["fault"] == f:
            per_trace[r["base"]] = r["fault_flagged"] if f not in ("clean", "P_benign_extra") else bool(set(r["session_rule_flags"]) - {"denied"})
    rule = (sum(per_trace.values()), len(per_trace))
    jd = frac([r["judge_detected"] for r in rs])
    either = frac([per_trace[r["base"]] or r["judge_detected"] for r in rs])
    ag = agree(rs)
    stats[f] = {"rule": rule, "judge": jd, "either": either, "agree": ag}
    if f == "clean":
        t_rows.append("\\midrule")
    t_rows.append(f"{fname[f]} & {cell(*rule)} & {cell(*jd)} & {cell(*either)} & {ag[0]}/{ag[1]}\\\\")
M["EFourRows"] = "\n".join(t_rows)
fr = [stats[f]["rule"] for f in faults]; fj = [stats[f]["judge"] for f in faults]
R_n, R_d = sum(a for a, b in fr), sum(b for a, b in fr)
J_n, J_d = sum(a for a, b in fj), sum(b for a, b in fj)
M["EFourRulesMacro"] = f"{R_n}/{R_d} ({pct(R_n / R_d)}\\%)"
M["EFourJudgeMacro"] = f"{J_n}/{J_d} ({pct(J_n / J_d)}\\%)"
cj = stats["clean"]["judge"]
M["EFourJudgeFPMacro"] = f"{cj[0]}/{cj[1]}"
best = max(faults, key=lambda f: stats[f]["judge"][0] / max(1, stats[f]["judge"][1]))
worst = min(faults, key=lambda f: stats[f]["judge"][0] / max(1, stats[f]["judge"][1]))
rules_zero = [fname[f] for f in faults if stats[f]["rule"][0] == 0]
pb = stats["P_benign_extra"]["judge"]
agree_all = [stats[f]["agree"] for f in faults + ["clean", "P_benign_extra"]]
A_n, A_d = sum(a for a, b in agree_all), sum(b for a, b in agree_all)
narr = (f"Rule flags are deterministic and cheap. They caught {R_n} of {R_d} faulted traces, all via policy flags "
        f"(network, destructive, side-effect, secrets access) or the unmentioned-file check. They are blind by construction to faults "
        f"that need semantics: {', '.join(rules_zero) if rules_zero else 'none'}. "
        f"The reviewer caught {J_n} of {J_d} faulted reviews. Its detection was highest for {fname[best].split(' ', 1)[1]} "
        f"({cell(*stats[best]['judge'])}) and lowest for {fname[worst].split(' ', 1)[1]} ({cell(*stats[worst]['judge'])}). "
        f"On untouched sessions it raised {cj[0]} of {cj[1]} reviews and on the benign perturbation {pb[0]} of {pb[1]}. "
        f"Its two repetitions agreed on {A_n} of {A_d} traces. "
        f"Combining both checks reached {sum(stats[f]['either'][0] for f in faults)} of {sum(stats[f]['either'][1] for f in faults)} faulted reviews. "
        f"The two mechanisms are complementary: rules give guaranteed, explainable coverage of data-flow and scope violations, "
        f"while the reviewer is the only component that notices a success claim contradicted by a tool result."
        + (f" {M['EFourErrors']} reviewer call(s) failed to return parseable JSON and are excluded." if M["EFourErrors"] else ""))
M["EFourNarrative"] = narr
M["EFourBenignFPMacro"] = f"{pb[0]}/{pb[1]}"
M["EFourAgree"] = f"{A_n}/{A_d}"
f1 = stats["F1_unrequested_edit"]["rule"]
M["EFourFOneRuleMiss"] = f"{f1[1]-f1[0]}/{f1[1]}"

# tests
out = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"], cwd=KIT, capture_output=True, text=True)
import re
m = re.search(r"Ran (\d+) tests", out.stderr)
M["NTests"] = m.group(1) if m else "?"
M["NTestsOK"] = "OK" in out.stderr.splitlines()[-1]

with open(os.path.join(KIT, "paper/results.tex"), "w") as f:
    f.write("% generated by eval/make_macros.py -- do not edit\n")
    for k, v in M.items():
        f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
print(json.dumps({k: v for k, v in M.items() if not k.endswith("Rows") and k != "EFourNarrative"}, indent=1))
print(M["EFourNarrative"])
