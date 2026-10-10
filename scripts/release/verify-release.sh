#!/bin/sh
# Check a downloaded Tracekit release (docs/RELEASING.md): every file in DIR matches SHA256SUMS, the Python SBOM is
# there, and each file listed in SHA256SUMS (and IMAGE, a ghcr.io/...@sha256:... reference) has a GitHub artifact
# attestation (SLSA provenance) from this repository's release workflow. --dry-run stops before the attestations,
# for a local build that was never attested.
#
#   scripts/release/verify-release.sh [--dry-run] DIR [IMAGE]
set -eu
REPO=Cygnux-Labs/Tracekit
WORKFLOW=$REPO/.github/workflows/release.yml

dry=0
if [ "${1:-}" = --dry-run ]; then dry=1; shift; fi
[ $# -ge 1 ] || { echo "usage: $0 [--dry-run] DIR [IMAGE]" >&2; exit 2; }
image=${2:-}
cd "$1"

[ -s SHA256SUMS ] || { echo "no SHA256SUMS in $1" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi
grep -q '"bomFormat": *"CycloneDX"' tracekit-ai.cdx.json 2>/dev/null \
    || { echo "tracekit-ai.cdx.json: missing or not a CycloneDX SBOM" >&2; exit 1; }
for f in *.whl *.tar.gz *.tgz; do
    [ -e "$f" ] || { echo "no $f in $1" >&2; exit 1; }
    grep -q "  $f\$" SHA256SUMS || { echo "$f is not listed in SHA256SUMS" >&2; exit 1; }
done
if [ $dry = 1 ]; then echo "dry run: sums and SBOM ok; attestations not checked"; exit 0; fi

cut -d' ' -f3- SHA256SUMS | while IFS= read -r f; do
    gh attestation verify "$f" --repo "$REPO" --signer-workflow "$WORKFLOW"
done
if [ -n "$image" ]; then gh attestation verify "oci://$image" --repo "$REPO" --signer-workflow "$WORKFLOW"; fi
echo "release verified"
