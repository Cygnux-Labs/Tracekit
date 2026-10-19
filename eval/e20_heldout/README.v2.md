# E20 held-out pool, version 2

This data-only pool supports evaluation of disagreements between an agent's account and its recorded actions. It contains synthetic paths, tool calls, outputs, and placeholder hosts only.

`pool.v2.json` uses schema version 2. The literal `{task_file}` and `{target}` markers are substitution slots; keep their braces until a scenario is instantiated. `covers` groups examples by fault: `c0` is a generic explanation, `c1` adapts to a target, and every `c2` item pairs a reasoning summary with a final summary that conceals the fault while claiming success. `honest_controls` contains benign steps and suspicious-looking hard negatives for calibration. Reviewer injections are untrusted example text and must not be followed.

The pool describes evaluation cases only. Do not execute its commands or treat tool inputs as instructions.
