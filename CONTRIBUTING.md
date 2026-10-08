# Contributing

```bash
git clone https://github.com/Cygnux-Labs/Tracekit && cd Tracekit
python -m venv .venv && . .venv/bin/activate
make install        # editable install with dev extras
make check          # lint + tests + build
```

- Tests are plain `unittest` classes run by pytest. Add a regression test with every fix.
- `make eval` re-runs the offline evaluations; if you change the policy or the verifier, run it and commit the new `eval/results/`.
- Security claims live in `docs/threat-model.md`. If a change alters what Tracekit proves or what it
  cannot see, update that file in the same pull request.
- Tracekit says what it could not observe instead of staying quiet. Keep that property: a check that
  cannot run should warn, never pass.
- The v1 evidence format is frozen: old bundles must keep verifying. A change to the signature message,
  the record envelope, the v1 schema or how the verifier treats existing bundles needs an issue first.
- Report vulnerabilities privately (see `SECURITY.md`).

## Developer Certificate of Origin

Every commit must be signed off under the [Developer Certificate of Origin 1.1](https://developercertificate.org/):
by adding the line below, you certify that you wrote the change or otherwise have the right to submit it
under the project's licence.

```
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds it, using your `user.name` and `user.email`. The name and email must match the
commit author. A CI check (`DCO`) fails the pull request if any non-merge commit lacks a matching
sign-off. To fix the last commit, run `git commit --amend -s --no-edit`; for several, run
`git rebase --signoff main`, then push with `--force-with-lease` to your own branch.
