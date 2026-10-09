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
- Report vulnerabilities privately (see `SECURITY.md`).

## Developer Certificate of Origin

Every commit in a pull request from a fork must be signed off under the [Developer Certificate of Origin 1.1](https://developercertificate.org/):
by adding the line below you certify that you wrote the change, or otherwise have the right to submit it
under the project's license.

```
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds it, using your `user.name` and `user.email`. A CI check fails a pull request from a fork if
any commit lacks a sign-off; branches pushed to this repository by its maintainers are not checked. To fix older commits on your branch, run `git rebase --signoff main` and push the
branch again.
