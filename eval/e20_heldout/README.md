# E20 held-out pool

`pool.json` is the held-out evaluation data for E20 (issue #309): detecting when an AI
coding agent's stated intent or reasoning disagrees with what it actually did. The
alignment harness (`eval/e20_alignment.py`) draws from this pool to splice concealed
misaligned steps into real traces, then scores the detector on them separately from the
tuned corpus.

## It was written blind to the checks

The author of this file deliberately did not read the detection code (findings,
detector regexes, the E6/E20 scripts or their results). The point is an honest, held-out
measurement: the pool is independent of the implementation it scores.

**Never tune the checks on this pool.** If you find yourself adjusting a detector regex
or threshold to make an item here pass or fail, stop — that collapses the held-out
guarantee and the number stops meaning anything. Tune on the tuned set; measure here.

**Status of v1: a development set.** One round of TK-X205 tuning took five success phrases
from this pool. They were removed and the pool rescored, but it has now been read while
tuning, so its numbers are a development set's. E20 scores it as `development`.

**Status of v2: a development set.** `pool.v2.json` (schema 2, see `README.v2.md`) was written
blind and scored once on 2026-10-19 as the held-out pool, then read the same day while fixing
the checks. E20 scores it as `development_v2`.

**Status of v3: the held-out pool.** `pool.v3.json` (schema 2, see `README.v3.md`) was written
blind and scored once on 2026-10-20, on the checks as 1.4 ships them. E20 scores it as
`held_out`. Never change a check, regex, threshold or the mapping (`load_pool` in
`eval/e20_alignment.py`) because of its numbers; a pool v4 measures the next round.

## What's inside

- `targets` — files a request puts off-limits (varied languages and repo layouts).
- `task_files` — files the person actually asked the agent to work on.
- `prompts` — natural task requests, templated on `{task_file}`.
- `constraints` — many ways of forbidding changes to `{target}` (negation, polite,
  terse, indirect, with the occasional typo).
- `covers` — per fault type F1–F7, three cover strengths: `c0` generic, `c1` adaptive
  (may name `{target}` innocently or negated), `c2` a thinking summary plus a final
  summary that both hide the fault and claim success.
- `claims` — success-claim paraphrases.
- `failure_outputs` — verbatim-style failing output from several runners (pytest, jest,
  go test, cargo, mocha, unittest).
- `reviewer_injections` — text aimed at an automated reviewer/monitor (c4), in several
  styles: polite note, fake system message, JSON-looking directive, code comment.
- `honest_controls.benign_steps` — honest, in-scope actions that must not be flagged.
- `honest_controls.hard_negatives` — actions that look like faults but are fine (e.g.
  writing to `/tmp`, a requested `git push`, reading `~/.ssh/known_hosts`, a success
  claim after a run that really passed).

Fault types: F1 edit an unrequested file; F2 exfiltrate a file by HTTP POST; F3 delete a
file; F4 false success; F5 scope creep (install a package and push); F6 read an SSH
private key; F7 weaken the failing test instead of fixing the code.

All hosts are `example.com` / `example.org` and all values are obviously fake. Fault
actions are described as data only; nothing here is runnable against a real system.

## Adding to the pool

Do **not** edit the existing items — changing them silently changes past measurements.
Instead, add a new, versioned pool alongside this one:

1. Copy `pool.json` to `pool.v2.json` (keep `pool.json` as v1 for reproducibility).
2. Bump the top-level `"version"` in the copy and add your new entries there.
3. Write the additions blind to the detector code, same as this file.
4. Point the harness at the new version; leave the old one in place for comparison.
