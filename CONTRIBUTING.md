# Contributing

```bash
git clone https://github.com/Cygnux-Labs/Tracekit && cd Tracekit
python -m venv .venv && . .venv/bin/activate
make install        # editable install with dev extras
make check          # lint + tests + build
```

## Tests and evals

- Tests are plain `unittest` classes run by pytest (`make test`, about two minutes: many start a real signer). Add a
  regression test with every fix; a change to the signer, store, verifier or policy needs one that fails without it.
- Root-only and Linux-only tests (system mode, harness binding) skip on a laptop. CI on Linux is the merge gate; macOS
  and Windows are advisory.
- `make test-ts` runs the TypeScript SDK's tests; `make quickstart` runs the [v2 quickstart](docs/quickstart-v2.md) in
  a clean venv.
- `make eval` re-runs the offline evaluations ([evaluation](docs/evaluation.md)); if you change the policy, the signer
  or the verifier, run it and commit the new `eval/results/`. E8 (insider attacks as real users) needs root and runs
  in CI.

## Adding a framework adapter

An adapter passes the adapter contract (`tests/adapter_contract.py`), against the fake signer and the real one:

1. Write a driver for it (`run`, `call`, `resume`, `tamper`, `retry`) in `tests/test_contract_<framework>.py`;
   `tests/test_contract_langchain.py` is the model.
2. An allowed call runs once and completes against its decision; a denied call never runs, the model gets an error
   result and the run goes on; a tool's exception reaches the framework and completes as an error; a retry is a new
   decision.
3. An `ask` pauses until a human approves it, then runs once; a rejected call never runs; a replayed snapshot, edited
   arguments, a rewritten call id or another run's approval is refused on resume.
4. Every call mode the framework has (async, streaming), resuming in a new process and the saved-state wrapper are
   covered, or listed in `SKIP` with the reason.
5. A runnable offline example in `examples/v2/<framework>/` and a page in `docs/quickstarts/`.

## Security invariants

These are the product's promise ([threat model: server](docs/threat-model-server.md#invariants), mapped to tests in
[tests/INVARIANTS.md](tests/INVARIANTS.md)). A change that weakens one is not merged:

- The agent never holds a signing key, a chain head or a sequence number.
- Nothing an agent-controlled process supplies (isolation level, fail mode, gap or tamper records, approval identity)
  is trusted by the signer or the verifier.
- Gaps are signed, never silent. A check that can't run warns; it never passes.
- Old evidence keeps verifying: the v1 format and the published v2 format are frozen, and the golden bundles in
  `docs/sample/` and `tests/fixtures/` are never regenerated.
- A bundle never carries verification code; the verifier and its trust config come from the party checking it.

If a change alters what Tracekit proves or what it can't see, update the threat model
([laptop](docs/threat-model-laptop.md), [server](docs/threat-model-server.md)) in the same pull request. Report
vulnerabilities privately (see [SECURITY.md](SECURITY.md)).

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
