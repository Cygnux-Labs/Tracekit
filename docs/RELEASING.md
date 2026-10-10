# Releasing

1. Update `__version__` in `tracekit/__init__.py` and add a dated entry to `CHANGELOG.md`.
2. `make check` locally; CI must be green on `main`.
3. Tag and push: `git tag v0.3.0 && git push origin v0.3.0`. The `Release` workflow refuses a tag that does not
   match `__version__`, builds the sdist and wheel, runs `twine check`, and publishes to PyPI.

## One-time PyPI setup (trusted publishing, no stored token)

1. On pypi.org create the project `tracekit-ai` (or reserve the name) and under *Publishing* add a trusted
   publisher: owner `Cygnux-Labs`, repository `Tracekit`, workflow `release.yml`, environment `pypi`.
2. In the GitHub repository settings create an environment named `pypi`, ideally with required reviewers.

Until that is done the `publish` job fails and nothing is released; the `build` job still checks the package.

## npm signer packages (`npx @cygnux/tracekit up` without Python)

`@cygnux/tracekit` lists `@cygnux/tracekit-signer-{darwin-arm64,darwin-x64,linux-x64-gnu,linux-arm64-gnu,win32-x64}`
as `optionalDependencies` at its own version; npm installs the one matching the platform, with no postinstall. Each
holds a python-build-standalone CPython (release and sha256 pinned in the script) with `tracekit-ai[signer]` and its
wheels unpacked into site-packages. After tracekit-ai is on PyPI at the `sdk/typescript/package.json` version:

1. `python3 scripts/build-signer-bundles.py` (or name some targets). It downloads and checks the pinned runtimes,
   `pip download --platform … --only-binary :all:`s the wheels for every target from one machine, records their
   hashes in `wheels.sha256`, strips tests and headers, writes `build/npm/tracekit-signer-<platform>/`, and prints each
   package's unpacked size.
2. `npm publish --access public` in each `build/npm/tracekit-signer-<platform>/`, then in `sdk/typescript/`.

Rebuild for CPython and OpenSSL security releases by bumping the pinned release in the script.
