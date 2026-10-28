# Releasing

> **Status:** 1.0.0 was the first release made this way (its PyPI files carry provenance and SBOMs); its npm job
> failed. npm packages are under the `@cygnuxlabs` org: 1.2.1's were published by hand (a package must exist before
> it takes a trusted publisher), and from 1.2.2 the release workflow publishes them. Earlier releases (1.0.0rc2 and
> before) carry only `SHA256SUMS`, so `verify-release.sh` can check only the sums for them.

A release is one tag. From it the release workflow builds the PyPI files, the npm packages and the multi-arch signer
image, attests each one (SLSA build provenance through GitHub artifact attestations), publishes them, and attaches every file with its SBOMs and `SHA256SUMS` to the GitHub release. Users check a download with
`scripts/release/verify-release.sh`.

## Procedure

1. Set the version in `tracekit/__init__.py` (`__version__`), in `sdk/typescript/package.json` (`version` and the
   four `@cygnuxlabs/tracekit-signer-*` `optionalDependencies`), in `sdk/typescript/src/verify/index.ts`
   (`VERSION`, which the verifier reports), in `docs/deploy-container.md`'s build example and `docs/deploy.md`'s
   clone example (the tag and the directory), in `server.json` and
   `plugin/.claude-plugin/plugin.json` (`version`), in both Helm charts (`appVersion` in `deploy/helm/*/Chart.yaml`
   and the image tag in `deploy/helm/*/values.yaml`, both `v<version>`) and in the README's licence line ("This is
   <version>"), and add a dated entry to `CHANGELOG.md`. In `sdk/typescript/package-lock.json` set the root package's
   `version` (twice) and `optionalDependencies` too, and put back each `node_modules/@cygnuxlabs/tracekit-signer-*`
   entry as `{"optional": true}`: the last release's locked versions don't satisfy the new ones, so `npm ci` (the
   release build) fails until they are unlocked; step 5 locks the new ones.
2. `make check` and `make release-dry-run` locally; CI must be green on `main`.
3. Tag and push: `git tag v<version> && git push origin v<version>`. The workflow refuses a tag other than `v` +
   `__version__`, and a `package.json` version that isn't its npm form.
4. The workflow runs `release` (build, image push, attestations), then `pypi`, then `npm` with no approval step: since
   2026-10-17 the environments have no required reviewers, so pushing a `v*` tag publishes. Add reviewers back
   (one-time setup, step 3) to require a second person.
5. Once the `npm` job has published, refresh the TypeScript lockfile in a follow-up PR: `make test-ts`, then commit
   `sdk/typescript/package-lock.json`. The version bump can't lock signer packages that aren't published yet, and once
   they are, `npm ci` (the `release-dry-run` job, `scripts/release/build.py`) fails until the lockfile names them. In
   the same PR add the tag to `RELEASED` in `tests/test_released_verifiers.py`, so CI runs this release's verifier on
   every later signer's bundles.
6. Once the `pypi` job has published, an owner of the `Cygnux-Labs` GitHub organisation publishes the MCP gateway's
   entry in the MCP Registry from the tagged checkout. The registry proves the `io.github.Cygnux-Labs` namespace
   through a GitHub login, and `mcp-publisher login github` (device flow) can't see the org's Owner role: create a
   classic token with only `read:org` and `read:user` and a 7-day expiry
   ([new token](https://github.com/settings/tokens/new?scopes=read:org,read:user&description=mcp-publisher)), run
   `mcp-publisher login github --token <token>`, then `mcp-publisher publish` (it reads `server.json`), then delete the
   token. The release workflow doesn't run this step.
7. If the release changed `plugin/`, copy it to
   [Cygnux-Labs/tracekit-claude-plugin](https://github.com/Cygnux-Labs/tracekit-claude-plugin), the source of the
   Claude Code plugin directory's listing (this repository is over the directory's 50 MiB limit). From the tagged
   checkout, `rsync -a --delete --exclude .git --exclude LICENSE plugin/ <clone>/` (the clone keeps its own
   `LICENSE`), then commit and push there; change nothing else. The directory picks up new commits about every 6 hours.
8. Host the browser verifier. The verifiers' upgrade lines send people with a bundle too new for theirs to
   https://cygnux-labs.github.io/Tracekit/verify/, so publish the release's `verify.html` there, as the latest, and at
   `verify/<v>/` for good: check the downloaded file (`gh attestation verify verify.html --repo Cygnux-Labs/Tracekit`),
   then on the `gh-pages` branch (the repository's Pages source, one-time setup step 4) copy it to
   `verify/<v>/index.html` and `verify/index.html`, commit and push. The release workflow doesn't run this step.
9. Publish the wiki, a generated view of `docs/`: from the tagged checkout run `python scripts/wiki.py /tmp/wiki --ref
   v<v>`, replace everything but `.git` in a clone of `Cygnux-Labs/Tracekit.wiki.git` with `/tmp/wiki`, commit and push
   (the first time, save any page in the Wiki tab: GitHub creates the wiki repository only then). Then run the
   website's `npm run check-links`: README, package metadata and the CLI's messages link to these pages.

### What gets built, signed and published

| Artifact | Built by | Signed / attested | Published to |
|---|---|---|---|
| `tracekit_ai-<v>.tar.gz`, `tracekit_ai-<v>-py3-none-any.whl` | `scripts/release/build.py` | build provenance (`actions/attest-build-provenance`); PEP 740 attestations from trusted publishing | PyPI, GitHub release |
| `cygnuxlabs-tracekit-<v>.tgz` | `scripts/release/build.py` (`npm pack`) | build provenance; `npm publish --provenance` | npm, GitHub release |
| `verify.html`, the browser verifier | `scripts/release/build.py` (the npm build's `dist/verify.html`, built twice and compared) | build provenance | GitHub release, the npm package (`dist/verify.html`), GitHub Pages (procedure step 8) |
| `cygnuxlabs-tracekit-signer-<platform>-<v>.tgz` (4) | `scripts/build-signer-bundles.py`, `npm pack` | build provenance; `npm publish --provenance` | npm (before `@cygnuxlabs/tracekit`), GitHub release |
| `ghcr.io/cygnux-labs/tracekit-signer` (linux/amd64 + linux/arm64) | `docker buildx`, `deploy/docker/Dockerfile` | build provenance pushed to the registry; cosign keyless signature and CycloneDX attestation, by digest | ghcr.io |
| `tracekit-ai.cdx.json`, `tracekit-signer-image.cdx.json` | `scripts/release/build.py` (cyclonedx-bom, syft; versions pinned) | build provenance | GitHub release |
| `SHA256SUMS` | `scripts/release/build.py`, extended by the npm job | build provenance | GitHub release |

The sdist and wheel are byte-identical across builds of the same commit: `build.py` builds the tree committed at HEAD
(`git archive`), sets `SOURCE_DATE_EPOCH` to its commit time, takes the build backend from
`scripts/release/constraints.txt`, and normalises the sdist's tar metadata. `tests/test_release.py` checks it.

### Dry run

`make release-dry-run` builds the Python files, the `@cygnuxlabs/tracekit` tarball, `verify.html`, the Python SBOM and `SHA256SUMS` into
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
checked the same way: `gh attestation verify <file> --repo Cygnux-Labs/Tracekit`. So can the browser verifier wherever
it came from (the attestation is of its bytes): before using it for evidence, save the page you would open, from the
release or https://cygnux-labs.github.io/Tracekit/verify/<v>/, as `verify.html`, run
`gh attestation verify verify.html --repo Cygnux-Labs/Tracekit`, and open that file. The image signature also verifies
with cosign:

```sh
cosign verify ghcr.io/cygnux-labs/tracekit-signer@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/Cygnux-Labs/Tracekit/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## One-time setup

1. **PyPI** (trusted publishing, no stored token): on pypi.org, project `tracekit-ai`, add a trusted publisher: owner
   `Cygnux-Labs`, repository `Tracekit`, workflow `release.yml`, environment `pypi`.
2. **npm** (trusted publishing, no stored token): for `@cygnuxlabs/tracekit` and each `@cygnuxlabs/tracekit-signer-*`, add a
   trusted publisher on npmjs.com: repository `Cygnux-Labs/Tracekit`, workflow `release.yml`, environment `npm`.
   A package must exist before it can be configured; publish the first version by hand from the dry run's tarballs.
3. **GitHub**: environments `release`, `pypi` and `npm`, each limited to `v*` tags; optionally with required
   reviewers and "prevent self-review" (off since 2026-10-17). Package `tracekit-signer` on ghcr.io linked to the repository (first push creates it).
4. **GitHub Pages**: create the `gh-pages` branch (empty but for `.nojekyll`) and set it as the repository's Pages
   source, so https://cygnux-labs.github.io/Tracekit/verify/ serves the browser verifier (procedure step 8).

Until these are done the publish jobs fail and nothing is released; the build job still checks the package.

## npm

After PyPI, the `npm` job builds the four signer packages from the release's own wheel, publishes them with provenance
and then `@cygnuxlabs/tracekit`, and adds their files to `SHA256SUMS`; `github-release` runs after it with those files
(`release-final`). A pre-release tag publishes under the `next` dist-tag, never `latest`.

## npm signer packages (`npx @cygnuxlabs/tracekit up` without Python)

`@cygnuxlabs/tracekit` lists `@cygnuxlabs/tracekit-signer-{darwin-arm64,linux-x64-gnu,linux-arm64-gnu,win32-x64}`
as `optionalDependencies` at its own version; npm installs the one matching the platform, with no postinstall. There
is no Intel-Mac package (its dependencies publish no usable wheels there): on an Intel Mac, `pip install
'tracekit-ai[signer]'` and the launcher uses that `tracekit` from PATH. Each
holds a python-build-standalone CPython (release and sha256 pinned in the script) with `tracekit-ai[signer]` and its
wheels unpacked into site-packages. The release workflow builds them from the release's own files:
`python3 scripts/build-signer-bundles.py [--release release]` checks the tracekit-ai wheel in `release/` against
`release/SHA256SUMS` (never fetching it from PyPI), downloads and checks the pinned runtimes, `pip download --platform …
--only-binary :all:`s that wheel's dependencies at the versions `scripts/release/runtime-constraints.txt` pins (the
signer image's pins too) for every target from one machine, records their hashes in `wheels.sha256`, strips
tests and headers, and writes `build/npm/tracekit-signer-<platform>/`.

Rebuild for CPython and OpenSSL security releases by bumping the pinned release in the script.

## Target workflows

Agents don't edit `.github/workflows/`; the owner applies these. Every action is pinned by commit SHA (the tag in
the comment).

`.github/workflows/release.yml` (replaces the current file):

```yaml
name: Release
# Tag a version (git tag v<version> && git push origin v<version>). PyPI and npm use trusted publishing: no token is stored.
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
    # the signer packages bundle the release's own tracekit-ai wheel (checked against SHA256SUMS); they go up after
    # PyPI and before @cygnuxlabs/tracekit, which depends on them
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
            release/cygnuxlabs-tracekit-signer-*.tgz
            release/SHA256SUMS
      - name: Publish (platform packages first)
        run: |
          for f in release/cygnuxlabs-tracekit-signer-*.tgz; do npm publish "$f" --provenance --access public; done
          npm publish release/cygnuxlabs-tracekit-[0-9]*.tgz --provenance --access public
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
