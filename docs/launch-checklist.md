# Launch checklist for 1.0

Every M3 exit-gate item and every launch item, with what proves it, how to run it, and its state. States:

- **done**: green in CI on `main` (`.github/workflows/ci.yml`; the Linux `test` job is the merge gate).
- **done locally**: passes when run by hand; the CI job that would run it is in the owner's pending CI changes, or it
  needs root, Linux, docker or a cloud account that CI on `main` does not have.
- **owner action**: needs credentials, an external account, a run on hardware the owner holds, or a release decision.

The CI `test` job installs `.[dev]` only: no `psycopg`, and no `initdb` on `PATH`, so the Postgres tests skip there.

## M3 exit gate

| Item | Proved by | How to run | State |
|---|---|---|---|
| kind: the agent cannot read the signer's store or keys | `deploy/helm/e2e.sh` (`ls` of the keys from the agent container fails); `tests/test_helm.py` (rendered manifests: no signer volume in the agent container) | `sh deploy/helm/e2e.sh` (docker, kind, kubectl, helm); `python -m pytest tests/test_helm.py` | `test_helm.py`: done (it skips without helm, which GitHub's Ubuntu image has). `e2e.sh`: done locally (the kind job is in the owner's pending CI changes) |
| kind: doctor | `deploy/helm/e2e.sh` (`tracekit doctor --json` in the sidecar) | as above | done locally (kind job pending) |
| kind: fail-open gap on signer kill | `deploy/helm/e2e.sh`: SIGTERM to the sidecar's pid 1 mid-run, one `fs` (fail-open) call while it is down, the next call after it is back, then a verified export holding one signed `client_counter_gap` for exactly that call | as above | done locally (kind job pending); the step was added in this change and has not yet run on kind |
| KMS via recorded fakes and moto in CI | `tests/test_signer_kms.py` (`FakeKms` with the AWS API shapes; the same cases on moto's KMS, which `.[dev]` installs) | `python -m pytest tests/test_signer_kms.py` | done (moto only; there is no MiniStack run) |
| KMS: nightly real AWS | nothing yet: no real-AWS test and no scheduled workflow | | owner action (an AWS account and key, and a nightly job with its credentials) |
| A central-mode bundle verifies at `witnessed+monitored` | `tests/test_storage_postgres.py` `TestCentralOnPostgres`: a signer with the central chart's config shape (Postgres store, one writer per log, route prefix) is anchored in the in-test Rekor, watched by `tracekit.monitor`, and its run, exported through `PostgresReader`, verifies at `witnessed+monitored`. On the file store: `tests/test_monitor.py` `Signer` | `python -m pytest tests/test_storage_postgres.py -k Central` (needs `psycopg` and `TRACEKIT_TEST_PG_DSN`, or `initdb` and `pg_ctl` on `PATH`) | Postgres: done locally (skips in CI). File store: done |
| E14 green | `eval/e14_outage.py`; `eval/results/e14_outage.json` (full run, all seven scenarios `ok`, recorded on macOS) | `python eval/e14_outage.py` (POSIX); `make eval` runs `--quick` | done locally (no CI job runs E14) |
| Launch checklist complete, then 1.0 released | this page | | owner action |

## Launch

| Item | Proved by | How to run | State |
|---|---|---|---|
| Signed release with SBOM and provenance | [RELEASING.md](RELEASING.md) (target `release.yml` and `supply-chain.yml`); `scripts/release/build.py`. The `release.yml` on `main` builds and publishes to PyPI without attestations, SBOMs, npm or the image | `make release-dry-run` | owner action (apply the target workflows; create the `release`, `pypi` and `npm` environments) |
| `verify-release.sh` | `scripts/release/verify-release.sh`; `tests/test_release.py` (offline `--dry-run` checks: sums, SBOM, unlisted files) | `python -m pytest tests/test_release.py`; `TRACEKIT_RELEASE=1` adds the reproducible build and a full dry run | `--dry-run`: done. Attestation checks: owner action (need a release from the target workflow) |
| Security checklist | [security-checklist.md](security-checklist.md); `tests/test_security_checklist.py` (every HTTP handler listed and probed) | `python -m pytest tests/test_security_checklist.py` | done |
| Threat models | [threat-model-laptop.md](threat-model-laptop.md), [threat-model-server.md](threat-model-server.md); links checked by `tests/test_docs.py` | `python -m pytest tests/test_docs.py` | done |
| `SECURITY.md` | `SECURITY.md` (private reporting, disclosure timeline) | | owner action (its supported-versions table names 0.x: add the 1.0 line at release) |
| Docs index in the README | README's Docs list; `tests/test_readme.py` (every repository link names a file) | `python -m pytest tests/test_readme.py` | done |
| Quickstart on a clean machine (macOS, Linux, Windows) | `tests/test_quickstart.py` (builds the wheel into a fresh venv and runs [quickstart-v2.md](quickstart-v2.md)); the CI `package` job installs the wheel into a clean venv on Linux and runs `tracekit demo` (v1) | `make quickstart` (needs the package index) | Linux v1 demo: done. v2 quickstart on clean macOS, Linux and Windows machines: owner action (no CI job runs `make quickstart`) |
| Sample bundles verify | `docs/sample/`; `tests/test_hardening.py` `ShippedSample` (the bundle verifies, the tampered copy fails) | `python -m pytest tests/test_hardening.py -k ShippedSample` | done |
| PyPI, npm and ghcr names | `tracekit-ai` (`pyproject.toml`), `@cygnux/tracekit` and `@cygnux/tracekit-signer-*` (`sdk/typescript/package.json`), `ghcr.io/cygnux-labs/tracekit-signer` (the chart's default image) | | owner action (own the names, set up trusted publishing: [RELEASING.md](RELEASING.md#one-time-setup)) |
| Technical report | [report/tracekit-v2.md](../report/tracekit-v2.md); `tests/test_report.py` (its tables match `eval/results`) | `python -m pytest tests/test_report.py`; `python3 report/tables.py` regenerates the tables | done |
| E-series results current | `eval/results/*.json`, recorded on macOS; `tests/test_report.py` keeps the report equal to them but reruns nothing | `make eval` | done locally (no CI job reruns the evals) |
| E8 v2 on Linux as root | `eval/e8_insider_v2.py`. The CI `insider` job runs the v1 `eval/e8_insider.py` only; no E8 v2 result is recorded | as root on Linux, after `tracekit init --v2` (see the script's docstring) | owner action (a Linux host as root, or an `insider` job for v2) |
| E9 full on Linux | `eval/e9_signer_perf.py` (gates only on Linux without `--quick`); the recorded results are `--quick` runs on macOS | `python eval/e9_signer_perf.py` on Linux; `--storage postgres --dsn DSN` for Postgres | owner action (a full run on a Linux host) |
| Nightly real-AWS KMS | as in the exit gate | | owner action |
| CHANGELOG entry for 1.0 | `CHANGELOG.md` | | owner action (release notes are written once per release) |
| Version set | `tracekit/__init__.py` and `sdk/typescript/package.json` are at 0.4.0; `release.yml` refuses a tag that does not match | | owner action |
| 1.0 public launch | | | owner action: the owner's call, after real use |
