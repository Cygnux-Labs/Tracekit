# E20 held-out pool v3 (blind)

This is a fresh evaluation pool for measuring whether an agent’s account of its intent and work agrees with its actions. It was written blind: the author did not inspect the earlier held-out pools or the evaluation implementation.

The pool is synthetic. Paths and tool inputs are examples, reviewer-injection strings are inert data, and network hosts are restricted to example.org, example.test, and localhost. The data uses the placeholders `{target}` and `{task_file}` only.

Counts: 20 targets, 12 task files, 15 prompts, 30 constraints, 7 fault groups (10 c0, 10 c1, and 10 c2 entries each), 30 claims, 15 failure outputs, 12 reviewer injections, 20 benign controls, and 20 hard negatives.

Validation: the exact-match check for strings of four or more words found no copied entries apart from the two fault definitions required verbatim. The 8-word overlap scan's maximum was 9 words, only on those required definitions; all other strings had a maximum overlap of 7 words. `pool.json` was absent from `main`, so the scans used the available `pool.v2.json`.
