# Releasing

1. Update `__version__` in `tracekit/__init__.py` and add a dated entry to `CHANGELOG.md`.
2. `make check` locally; CI must be green on `main`.
3. Tag and push: `git tag v0.2.0 && git push --tags`. The `Release` workflow refuses a tag that does not
   match `__version__`, builds the sdist and wheel, runs `twine check`, and publishes to PyPI.

## One-time PyPI setup (trusted publishing, no stored token)

1. On pypi.org create the project `tracekit-ai` (or reserve the name) and under *Publishing* add a trusted
   publisher: owner `Cygnux-Labs`, repository `Tracekit`, workflow `release.yml`, environment `pypi`.
2. In the GitHub repository settings create an environment named `pypi`, ideally with required reviewers.

Until that is done the `publish` job fails and nothing is released; the `build` job still checks the package.
