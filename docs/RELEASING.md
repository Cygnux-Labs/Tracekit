# Releasing

> **Status:** this is the target release process. It applies once the owner has added `release.yml` and
> `supply-chain.yml` (below) to `.github/workflows/`; until then releases are built and published by the current
> release workflow without attestations or SBOMs, and `verify-release.sh` can check only `SHA256SUMS`.

A release is one tag. From it the release workflow builds the PyPI files, the npm packages and the multi-arch signer
image, attests each one (SLSA build provenance through GitHub artifact attestations), publishes them after approval,
and attaches every file with its SBOMs and `SHA256SUMS` to the GitHub release. Users check a download with
`scripts/release/verify-release.sh`.

## Procedure

1. Set the version in `tracekit/__init__.py` (`__version__`) and in `sdk/typescript/package.json` (`version` and the
   five `@cygnux/tracekit-signer-*` `optionalDependencies`), and add a dated entry to `CHANGELOG.md`.
2. `make check` and `make release-dry-run` locally; CI must be green on `main`.
3. Tag and push: `git tag v0.4.0 && git push origin v0.4.0`. The workflow refuses a tag that matches neither version.
4. Approve the `release` environment (build, image push, attestations), then `pypi`, then `npm`. Each needs a
   reviewer other than the person who pushed the tag.

### What gets built, signed and published

| Artifact | Built by | Signed / attested | Published to |
|---|---|---|---|
| `tracekit_ai-<v>.tar.gz`, `tracekit_ai-<v>-py3-none-any.whl` | `scripts/release/build.py` | build provenance (`actions/attest-build-provenance`); PEP 740 attestations from trusted publishing | PyPI, GitHub release |
| `cygnux-tracekit-<v>.tgz` | `scripts/release/build.py` (`npm pack`) | build provenance; `npm publish --provenance` | npm, GitHub release |
| `cygnux-tracekit-signer-<platform>-<v>.tgz` (5) | `scripts/build-signer-bundles.py`, `npm pack` | build provenance; `npm publish --provenance` | npm (before `@cygnux/tracekit`), GitHub release |
| `ghcr.io/cygnux-labs/tracekit-signer` (linux/amd64 + linux/arm64) | `docker buildx`, `deploy/docker/Dockerfile` | build provenance pushed to the registry; cosign keyless signature and CycloneDX attestation, by digest | ghcr.io |
| `tracekit-ai.cdx.json`, `tracekit-signer-image.cdx.json` | `scripts/release/build.py` (cyclonedx-bom, syft; versions pinned) | build provenance | GitHub release |
| `SHA256SUMS` | `scripts/release/build.py`, extended by the npm job | build provenance | GitHub release |

The sdist and wheel are byte-identical across builds of the same commit: `build.py` builds the tree committed at HEAD
(`git archive`), sets `SOURCE_DATE_EPOCH` to its commit time, takes the build backend from
`scripts/release/constraints.txt`, and normalises the sdist's tar metadata. `tests/test_release.py` checks it.

### Dry run

`make release-dry-run` builds the Python files, the `@cygnux/tracekit` tarball, the Python SBOM and `SHA256SUMS` into
a temporary directory twice, checks the two Python builds are identical, and runs `verify-release.sh --dry-run`
(sums and SBOM, no attestations). It publishes nothing; it needs the package index and npm. To keep the output:
`python3 scripts/release/build.py [OUT] [--image docker:IMAGE]` (default `dist/release/`; `--image` needs syft at
the pinned version), then `scripts/release/verify-release.sh --dry-run OUT`.

## Verifying a release

Download the GitHub release's files into a directory, then (needs the GitHub CLI, `gh auth login`):

```sh
scripts/release/verify-release.sh DIR ghcr.io/cygnux-labs/tracekit-signer@sha256:<digest>
```

It checks every file against `SHA256SUMS`, that the SBOM is present, and that every listed file and the image digest
carries a provenance attestation from `Cygnux-Labs/Tracekit`'s `release.yml`. A file from PyPI or npm can be
checked the same way: `gh attestation verify <file> --repo Cygnux-Labs/Tracekit`. The image signature also verifies
with cosign:

```sh
cosign verify ghcr.io/cygnux-labs/tracekit-signer@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/Cygnux-Labs/Tracekit/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## One-time setup

1. **PyPI** (trusted publishing, no stored token): on pypi.org, project `tracekit-ai`, add a trusted publisher: owner
   `Cygnux-Labs`, repository `Tracekit`, workflow `release.yml`, environment `pypi`.
2. **npm** (trusted publishing, no stored token): for `@cygnux/tracekit` and each `@cygnux/tracekit-signer-*`, add a
   trusted publisher on npmjs.com: repository `Cygnux-Labs/Tracekit`, workflow `release.yml`, environment `npm`.
   A package must exist before it can be configured; publish the first version by hand from the dry run's tarballs.
3. **GitHub**: environments `release`, `pypi` and `npm`, each with required reviewers and "prevent self-review",
   limited to `v*` tags. Package `tracekit-signer` on ghcr.io linked to the repository (first push creates it).

Until these are done the publish jobs fail and nothing is released; the build job still checks the package.

## npm signer packages (`npx @cygnux/tracekit up` without Python)

`@cygnux/tracekit` lists `@cygnux/tracekit-signer-{darwin-arm64,darwin-x64,linux-x64-gnu,linux-arm64-gnu,win32-x64}`
as `optionalDependencies` at its own version; npm installs the one matching the platform, with no postinstall. Each
holds a python-build-standalone CPython (release and sha256 pinned in the script) with `tracekit-ai[signer]` and its
wheels unpacked into site-packages. The release workflow builds them after tracekit-ai is on PyPI:
`python3 scripts/build-signer-bundles.py` downloads and checks the pinned runtimes, `pip download --platform …
--only-binary :all:`s the wheels for every target from one machine, records their hashes in `wheels.sha256`, strips
tests and headers, and writes `build/npm/tracekit-signer-<platform>/`.

Rebuild for CPython and OpenSSL security releases by bumping the pinned release in the script.

## Target workflows

Agents don't edit `.github/workflows/`; the owner applies these. Every action is pinned by commit SHA (the tag in
the comment).

`.github/workflows/release.yml` (replaces the current file):

```yaml
name: Release
# Tag a version (git tag v0.4.0 && git push origin v0.4.0). PyPI and npm use trusted publishing: no token is stored.
# docs/RELEASING.md has the procedure and the one-time setup.
on:
  push:
    tags: ["v*"]

permissions:
  contents: read

env:
  IMAGE: ghcr.io/cygnux-labs/tracekit-signer

jobs:
  build:
    runs-on: ubuntu-latest
    environment: release
    permissions:
      contents: read
      packages: write
      id-token: write
      attestations: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.12"
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version: "24"
      - run: python -m pip install -c scripts/release/constraints.txt build twine
      - name: Tag must match the package versions
        run: |
          v=$(python -c "import re;print(re.search(r'__version__ = \"([^\"]+)\"', open('tracekit/__init__.py').read()).group(1))")
          n=$(node -p "require('./sdk/typescript/package.json').version")
          [ "v$v" = "${GITHUB_REF_NAME}" ] && [ "v$n" = "${GITHUB_REF_NAME}" ] \
            || { echo "tag ${GITHUB_REF_NAME} != package v$v / npm v$n"; exit 1; }
      - uses: docker/setup-qemu-action@99012661954931238ded8c8b007157a8430204e1 # v4.4.0
      - uses: docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069 # v4.4.1
      - uses: docker/login-action@dbcb813823bdd20940b903addbd779551569679f # v4.6.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - id: image
        uses: docker/build-push-action@c3c9e263c25d99ce0380d002d59b67737d91b0dc # v7.4.0
        with:
          context: .
          file: deploy/docker/Dockerfile
          platforms: linux/amd64,linux/arm64
          push: true
          tags: ${{ env.IMAGE }}:${{ github.ref_name }}
          build-args: |
            VERSION=${{ github.ref_name }}
            REVISION=${{ github.sha }}
      - uses: anchore/sbom-action/download-syft@66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c # v0.24.3
        with:
          syft-version: v1.54.1
      - run: python scripts/release/build.py dist/release --image "${IMAGE}@${{ steps.image.outputs.digest }}"
      - run: python -m twine check dist/release/*.whl dist/release/*.tar.gz
      - uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2
        with:
          subject-path: dist/release/*
      - uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2
        with:
          subject-name: ${{ env.IMAGE }}
          subject-digest: ${{ steps.image.outputs.digest }}
          push-to-registry: true
      - uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2
        with:
          cosign-release: v3.1.3
      - name: Sign the image and attest its SBOM (keyless, by digest)
        run: |
          ref="${IMAGE}@${{ steps.image.outputs.digest }}"
          cosign sign --yes "$ref"
          cosign attest --yes --type cyclonedx --predicate dist/release/tracekit-signer-image.cdx.json "$ref"
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: release
          path: dist/release/

  pypi:
    needs: build
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write
    steps:
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          name: release
          path: release/
      - run: mkdir dist && cp release/*.whl release/*.tar.gz dist/
      - uses: pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33 # v1.14.2

  npm:
    # the signer packages bundle tracekit-ai from PyPI, so they build after it is published; they go up before
    # @cygnux/tracekit, which depends on them
    needs: pypi
    runs-on: ubuntu-latest
    environment: npm
    permissions:
      contents: read
      id-token: write
      attestations: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.12"
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version: "24"
          registry-url: https://registry.npmjs.org
      - run: npm install -g npm@12.2.0   # trusted publishing needs npm >= 11.5.1
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          name: release
          path: release/
      - run: python scripts/build-signer-bundles.py
      - name: Pack the signer packages into the release
        run: |
          for d in build/npm/tracekit-signer-*; do npm pack "./$d" --pack-destination release/; done
          cd release && rm SHA256SUMS && sha256sum * > SHA256SUMS
      - uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2
        with:
          subject-path: |
            release/cygnux-tracekit-signer-*.tgz
            release/SHA256SUMS
      - name: Publish (platform packages first)
        run: |
          for f in release/cygnux-tracekit-signer-*.tgz; do npm publish "$f" --provenance --access public; done
          npm publish release/cygnux-tracekit-[0-9]*.tgz --provenance --access public
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: release-final
          path: release/

  github-release:
    needs: npm
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          name: release-final
          path: release/
      - run: gh release create "${GITHUB_REF_NAME}" release/* --repo "${GITHUB_REPOSITORY}" --verify-tag --title "${GITHUB_REF_NAME}"
        env:
          GH_TOKEN: ${{ github.token }}
```

`.github/workflows/supply-chain.yml` (new):

```yaml
name: Supply chain
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "17 4 * * 1"   # weekly, for advisories published against unchanged code

permissions:
  contents: read

jobs:
  codeql:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    strategy:
      fail-fast: false
      matrix:
        language: [python, javascript-typescript]
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: github/codeql-action/init@24c54180a607b1449ed407dd24f251e4e9147c8d # v4.38.3
        with:
          languages: ${{ matrix.language }}
          build-mode: none
      - uses: github/codeql-action/analyze@24c54180a607b1449ed407dd24f251e4e9147c8d # v4.38.3

  pip-audit:
    # the dependency set a release installs: tracekit-ai with every extra, resolved and frozen
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.12"
      - run: |
          python -m pip install -c scripts/release/constraints.txt pip-audit
          python -m venv /tmp/locked
          /tmp/locked/bin/pip install ".[yaml,langchain,grpc,postgres,aws,signer]"
          /tmp/locked/bin/pip freeze --exclude tracekit-ai > /tmp/locked.txt
          python -m pip_audit --strict --no-deps -r /tmp/locked.txt

  dependency-review:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294 # v5.0.0
        with:
          fail-on-severity: high
          comment-summary-in-pr: on-failure

  coverage:
    # reported, not gated
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.12"
      - run: python -m pip install -e ".[dev]" -c scripts/release/constraints.txt pytest-cov
      - run: python -m pytest -q -o faulthandler_timeout=240 --cov=tracekit --cov=tracekit_sdk --cov-report=term --cov-report=xml
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: coverage
          path: coverage.xml

  release-dry-run:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.12"
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version: "24"
      - run: python -m pip install pytest -c scripts/release/constraints.txt
      - run: make release-dry-run PY=python
```
