#!/usr/bin/env python3
"""Measure policy coverage when harmful shell commands gain an equivalent shell layer."""

import argparse
import glob
import json
import os
import shlex
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "tests", "data", "policy", "deny")
PACK = os.path.join(ROOT, "tracekit", "policy2", "packs", "server.yaml")
RESULTS = os.path.join(ROOT, "eval", "results", "e21_robustness.json")
SHELL_TOOLS = {"Bash", "bash", "shell", "local_shell", "run_shell_command", "terminal"}
HELD = {"deny", "ask"}
TRANSFORMATIONS = {
    "cd-dot-and": "Prefix a stateless command with `cd . &&`; its working directory is unchanged.",
    "true-semi": "Prefix with `true;`; the extra command succeeds before the original command.",
    "command-prefix": "Prefix a single simple command with Bash's `command` builtin.",
    "bash-c": "Run the unchanged command text as a Bash command. This preserves Bash syntax such as here-strings; shlex quoting passes it as one -c argument.",
    "env-bash-c": "Use env to launch the same Bash -c command with unchanged command text. env adds no assignments, so Bash receives the same string and inherited environment.",
}
STATEFUL_BUILTINS = {"cd", "exit", "exec", "return", "set", "unset", "export", "readonly", "alias", "unalias", "umask", "trap"}

sys.path.insert(0, ROOT)
from tracekit.policy2 import compile as pc  # noqa: E402
from tracekit.policy2.engine import Engine  # noqa: E402
from tracekit.policy2 import shell  # noqa: E402


def load_cases():
    cases = []
    for path in sorted(glob.glob(os.path.join(CORPUS, "*.jsonl"))):
        with open(path, encoding="utf-8") as stream:
            for line_no, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                case = json.loads(line)
                if case.get("expect") not in HELD:
                    raise ValueError(f"{path}:{line_no}: expected deny-corpus verdict ask or deny")
                cases.append({"source": f"{os.path.basename(path)}:{line_no}", **case})
    if not cases:
        raise ValueError(f"no policy cases found in {CORPUS}")
    return cases


def rewrites(command):
    """Return same-shell equivalents and, when safe, equivalent child-shell wrappers. A command the parser can't read
    (held by TK-SHELL-PARSE) gets the same-shell prefixes only."""
    quoted = shlex.quote(command)
    out = {"cd-dot-and": f"cd . && {command}", "true-semi": f"true; {command}"}
    try:
        parsed = shell.analyse(command)[0]
    except shell.ParseError:
        return out
    if stateful_reason(command) is None:
        out.update({"bash-c": f"bash -c {quoted}", "env-bash-c": f"env bash -c {quoted}"})
    top_level = [cmd for cmd in parsed if not cmd["via"]]
    if (len(top_level) == 1 and all(not cmd["opaque"] for cmd in parsed)
            and not any(op in command for op in ("&&", "||", ";", "|", "\n", ">", "<", "$(", "`"))):
        out["command-prefix"] = f"command {command}"
    return out


def stateful_reason(command):
    """Return why child-shell rewrites would not preserve the agent shell's state."""
    try:
        parsed = shell.analyse(command)[0]
    except shell.ParseError:
        return "shell parse failed"
    for cmd in parsed:
        argv = cmd["argv"]
        name = argv[0]
        if name == "history":
            return "history state belongs to the current shell"
        if name in STATEFUL_BUILTINS:
            return f"stateful builtin: {name}"
    return None


def _rates(counts):
    return {"total": counts["total"], "contained": counts["contained"],
            "missed": counts["missed"], "rate": counts["contained"] / counts["total"] if counts["total"] else None}


def measure(cases, engines, policy):
    summaries = {name: Counter() for name in ("original", *TRANSFORMATIONS)}
    rule_counts = {name: defaultdict(Counter) for name in TRANSFORMATIONS}
    source_missed, mismatches, rewrite_misses, rule_misses, excluded_rewrites = [], [], [], [], []
    rewritten_cases = 0
    held_rule_ids = {rule["id"] for section in ("deny", "ask") for rule in policy.get(section, [])}
    held_rule_ids.add("TK-SHELL-PARSE")
    for case in cases:
        expected = case["expect"]
        args = case["args"]
        decisions = [engine.decide(case["tool"], args) for engine in engines]
        verdicts = [decision["verdict"] for decision in decisions]
        original_held = all(verdict in HELD for verdict in verdicts)
        summaries["original"]["total"] += 1
        summaries["original"]["contained" if original_held else "missed"] += 1
        if any((decision["verdict"], decision["rule_ids"]) != (decisions[0]["verdict"], decisions[0]["rule_ids"])
               for decision in decisions[1:]):
            mismatches.append({"source": case["source"], "form": "original", "decisions": decisions})
        if any(verdict != expected for verdict in verdicts):
            source_missed.append({"source": case["source"], "expected": expected, "verdicts": verdicts})

        command = args.get("command") if isinstance(args, dict) else None
        if case["tool"] not in SHELL_TOOLS or not isinstance(command, str) or not command:
            continue
        excluded = stateful_reason(command)
        if excluded:
            excluded_rewrites.append({"source": case["source"], "reason": excluded,
                                      "forms": ["bash-c", "env-bash-c"]})
        rewritten_cases += 1
        source_rules = (set(decisions[0]["rule_ids"]) & set(decisions[-1]["rule_ids"])) & held_rule_ids
        # A rule cohort contains only cases that both engines agree that rule held at source.
        for name, rewritten in rewrites(command).items():
            results = [engine.decide(case["tool"], {**args, "command": rewritten}) for engine in engines]
            rewritten_verdicts = [decision["verdict"] for decision in results]
            parser_held = all("TK-SHELL-PARSE" in decision["rule_ids"] for decision in results)
            contained = all(verdict in HELD for verdict in rewritten_verdicts) or parser_held
            summaries[name]["total"] += 1
            summaries[name]["contained" if contained else "missed"] += 1
            if any((decision["verdict"], decision["rule_ids"]) !=
                   (results[0]["verdict"], results[0]["rule_ids"]) for decision in results[1:]):
                mismatches.append({"source": case["source"], "form": name, "decisions": results})
            if not contained:
                rewrite_misses.append({"source": case["source"], "form": name, "verdicts": rewritten_verdicts})
            for rule_id in source_rules:
                counts = rule_counts[name][rule_id]
                counts["total"] += 1
                same_rule = all(rule_id in decision["rule_ids"] for decision in results)
                counts["same_rule"] += int(same_rule)
                counts["covered_by_rule_or_parse"] += int(same_rule or parser_held)
                counts["contained"] += int(contained)
                if not (same_rule or parser_held):
                    rule_misses.append({"source": case["source"], "form": name, "rule": rule_id})

    by_form = {name: _rates(summaries[name]) for name in summaries}
    per_rule = {}
    for form, rules in rule_counts.items():
        per_rule[form] = {rule: {**_rates(counts), "same_rule": counts["same_rule"],
                                "same_rule_rate": counts["same_rule"] / counts["total"] if counts["total"] else None,
                                "covered_by_rule_or_parse": counts["covered_by_rule_or_parse"],
                                "coverage_rate": counts["covered_by_rule_or_parse"] / counts["total"]
                                if counts["total"] else None}
                          for rule, counts in sorted(rules.items())}
    return {"source_cases": len(cases), "rewritten_cases": rewritten_cases,
            "by_form": by_form, "per_rule": per_rule,
            "source_missed": source_missed, "rewrite_missed": rewrite_misses,
            "rule_missed": rule_misses, "engine_mismatches": mismatches,
            "excluded_rewrites": excluded_rewrites}


def run(rebaseline=False):
    policy, errors = pc.build(PACK)
    if errors:
        raise ValueError("\n".join(errors))
    cases = load_cases()
    try:
        engines = (Engine(policy, "re2"), Engine(policy, "regex"))
    except ImportError as exc:
        raise RuntimeError("E21 requires google-re2; install the project evaluation dependencies") from exc
    measured = measure(cases, engines, policy)
    previous = None
    try:
        with open(RESULTS, encoding="utf-8") as stream:
            previous = json.load(stream).get("baseline")
    except FileNotFoundError:
        pass
    if previous is None and not rebaseline:
        raise ValueError("no saved baseline; pass --rebaseline to establish one explicitly")
    current_policy_hash = getattr(engines[0], "policy_hash", pc.policy_hash(policy))
    # Compare by rule id below; a policy hash change alone need not erase a useful baseline.
    baseline = ({"policy_hash": current_policy_hash, "engines": [getattr(e, "engine", None) for e in engines],
                 "by_form": measured["by_form"], "per_rule": measured["per_rule"]}
                if rebaseline else previous)
    regressions = []
    for form, old_rules in baseline.get("per_rule", {}).items():
        for rule_id, old in old_rules.items():
            metrics = measured["per_rule"].get(form, {}).get(rule_id)
            if metrics is None:
                regressions.append({"form": form, "rule": rule_id, "metric": "rule_missing",
                                    "baseline": old["rate"], "current": 0.0})
                continue
            if metrics["rate"] < old["rate"]:
                regressions.append({"form": form, "rule": rule_id, "metric": "contained_rate",
                                    "baseline": old["rate"], "current": metrics["rate"]})
            if metrics["coverage_rate"] < old["coverage_rate"]:
                regressions.append({"form": form, "rule": rule_id, "metric": "rule_coverage_rate",
                                    "baseline": old["coverage_rate"], "current": metrics["coverage_rate"]})
            if metrics["same_rule_rate"] < old.get("same_rule_rate", 0.0):
                regressions.append({"form": form, "rule": rule_id, "metric": "same_rule_rate",
                                    "baseline": old.get("same_rule_rate", 0.0), "current": metrics["same_rule_rate"]})
    no_regression = (not measured["source_missed"] and not measured["rewrite_missed"]
                     and not measured["rule_missed"]
                     and not measured["engine_mismatches"] and not regressions)
    return {**measured, "policy_hash": current_policy_hash,
            "engines": [getattr(e, "engine", None) for e in engines],
            "transformations": TRANSFORMATIONS, "baseline": baseline,
            "regressions": regressions,
            "no_regression": {"source_matches_expected": not measured["source_missed"],
                              "rewrites_contained": not measured["rewrite_missed"],
                              "every_source_rule_covers_rewrites": not measured["rule_missed"],
                              "engines_agree": not measured["engine_mismatches"],
                              "rewrite_coverage_not_below_baseline": not regressions},
            "ok": no_regression}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rebaseline", action="store_true", help="replace the saved baseline with this run")
    result = run(rebaseline=parser.parse_args().rebaseline)
    os.makedirs(os.path.dirname(RESULTS), exist_ok=True)
    with open(RESULTS, "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(f"{result['source_cases']} deny corpus cases")
    for form, counts in result["by_form"].items():
        print(f"{form}: {counts['contained']}/{counts['total']} contained ({counts['rate'] if counts['rate'] is not None else 0:.1%})")
    print(f"source misses {len(result['source_missed'])}; rewrite misses {len(result['rewrite_missed'])}; "
          f"rule misses {len(result['rule_missed'])}; engine mismatches {len(result['engine_mismatches'])}; "
          f"regressions {len(result['regressions'])}")
    print(f"wrote {os.path.relpath(RESULTS, ROOT)}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
