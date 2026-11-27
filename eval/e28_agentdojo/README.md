# AgentDojo runs for E28

Data from [AgentDojo](https://github.com/ethz-spylab/agentdojo) (Debenedetti et al.), MIT licensed: `AGENTDOJO-LICENSE`
is its license file as it was at the commit below. [E28](../../docs/evaluation.md#e28-influence-grades-on-runs-with-a-known-cause)
(`eval/e28_influence.py`) reads it, offline.

- Upstream commit: `089ed468cf3ed0322acc66b0211f26d9d90dbf60` (also in `ground_truth.json`, `source.commit`).
- `traces.jsonl`: one line per run of `runs/gpt-4o-2024-05-13/` that E28 reads: the 300 runs whose
  `important_instructions` attack succeeded (`security` true; 629 were attacked) and the 97 clean runs (`none`). Each
  keeps its upstream path (`file`) and only the fields E28 reads: the suite, user and injection task ids, the attack,
  the injected texts, `security`, and the messages less the system prompt (role, content, tool calls, tool call id,
  error).
- `ground_truth.json`: for each injection task of those runs, the functions its ground truth calls and the strings it
  fixes, read from `src/agentdojo/default_suites/*/*/injection_tasks.py` (every suite version) with `ast`, never
  imported.

Written by `python eval/e28_influence.py --vendor CHECKOUT` from a checkout at that commit; the license file is copied
beside it by hand.
