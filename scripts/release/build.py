#!/usr/bin/env python3
"""Build the release artifacts of the committed tree at HEAD into OUT (docs/RELEASING.md): the tracekit-ai sdist and
wheel (byte-identical across builds: SOURCE_DATE_EPOCH is HEAD's commit time, tool versions from constraints.txt), the
@cygnux/tracekit npm tarball, CycloneDX SBOMs of the Python package and, with --image, the container image, and
SHA256SUMS over all of it. Publishes nothing; the release workflow attests and publishes what it writes.

    python3 scripts/release/build.py [OUT] [--image REF]      (needs `pip install -c scripts/release/constraints.txt build`)
"""
import argparse
import gzip
import hashlib
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import venv

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONSTRAINTS = os.path.join(ROOT, "scripts", "release", "constraints.txt")
SYFT_VERSION = "1.54.1"
PY_SBOM = "tracekit-ai.cdx.json"
IMAGE_SBOM = "tracekit-signer-image.cdx.json"


def export_head(dest):
    """The tree committed at HEAD, extracted into `dest` (local edits and untracked files never reach a release)."""
    tar = subprocess.run(["git", "-C", ROOT, "archive", "--format=tar", "HEAD"], check=True, capture_output=True).stdout
    with tarfile.open(fileobj=io.BytesIO(tar)) as t:
        t.extractall(dest)


def normalize_sdist(path, epoch):
    """Rewrite the sdist with fixed member order, times, owners and modes, and a fixed gzip header time."""
    with tarfile.open(path) as t:
        members = [(m, t.extractfile(m).read() if m.isfile() else None) for m in sorted(t.getmembers(), key=lambda m: m.name)]
    with open(path, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as gz, \
            tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as out:
        for m, data in members:
            m.mtime, m.uid, m.gid, m.uname, m.gname, m.pax_headers = epoch, 0, 0, "", "", {}
            m.mode = 0o755 if m.isdir() or m.mode & 0o100 else 0o644
            out.addfile(m, io.BytesIO(data) if data is not None else None)


def python_dists(src, out, epoch):
    """sdist and wheel of `src` into `out`."""
    env = dict(os.environ, SOURCE_DATE_EPOCH=str(epoch), PIP_CONSTRAINT=CONSTRAINTS)
    subprocess.run([sys.executable, "-m", "build", "--sdist", "--wheel", "--outdir", out, src], check=True, env=env)
    for name in os.listdir(out):
        if name.endswith(".tar.gz"):
            normalize_sdist(os.path.join(out, name), epoch)


def npm_pack(src, out):
    """@cygnux/tracekit as the tarball `npm publish` uploads."""
    sdk = os.path.join(src, "sdk", "typescript")
    for cmd in (["npm", "ci", "--no-audit", "--no-fund"], ["npm", "run", "build"],
                ["npm", "pack", "--pack-destination", os.path.abspath(out)]):
        subprocess.run(cmd, cwd=sdk, check=True, shell=os.name == "nt")


def exe(env_dir, name):
    return os.path.join(env_dir, "Scripts" if os.name == "nt" else "bin", name)


def python_sbom(src, out, tmp):
    """CycloneDX SBOM of the built wheel installed with its dependencies into a fresh venv."""
    tool, target = os.path.join(tmp, "sbom-tool"), os.path.join(tmp, "sbom-target")
    wheel = next(os.path.join(out, n) for n in os.listdir(out) if n.endswith(".whl"))
    for env_dir, pkgs in ((tool, ["-c", CONSTRAINTS, "cyclonedx-bom"]), (target, [wheel])):
        venv.create(env_dir, with_pip=True)
        subprocess.run([exe(env_dir, "python"), "-m", "pip", "install", "-q", *pkgs], check=True)
    subprocess.run([exe(tool, "cyclonedx-py"), "environment", "--pyproject", os.path.join(src, "pyproject.toml"),
                    "--output-reproducible", "--of", "JSON", "-o", os.path.join(out, PY_SBOM),
                    exe(target, "python")], check=True)


def image_sbom(ref, out):
    """CycloneDX SBOM of the container image `ref` (a pushed digest, or a local `docker:` image for a dry run)."""
    version = subprocess.run(["syft", "--version"], check=True, capture_output=True, text=True).stdout.split()[-1]
    if version != SYFT_VERSION:
        sys.exit(f"syft {SYFT_VERSION} required, found {version}")
    subprocess.run(["syft", "scan", ref, "-o", f"cyclonedx-json={os.path.join(out, IMAGE_SBOM)}"], check=True)


def write_sums(out):
    lines = []
    for name in sorted(os.listdir(out)):
        if name != "SHA256SUMS":
            with open(os.path.join(out, name), "rb") as f:
                lines.append(f"{hashlib.sha256(f.read()).hexdigest()}  {name}\n")
    with open(os.path.join(out, "SHA256SUMS"), "w", newline="\n") as f:
        f.writelines(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out", nargs="?", default=os.path.join(ROOT, "dist", "release"))
    ap.add_argument("--image", help="also write the SBOM of this container image")
    args = ap.parse_args()
    epoch = int(subprocess.run(["git", "-C", ROOT, "log", "-1", "--format=%ct", "HEAD"],
                               check=True, capture_output=True, text=True).stdout)
    os.makedirs(args.out, exist_ok=True)
    if os.listdir(args.out):
        sys.exit(f"{args.out} is not empty")
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "src")
        export_head(src)
        python_dists(src, args.out, epoch)
        npm_pack(src, args.out)
        python_sbom(src, args.out, tmp)
    # lean: the image and the signer npm packages are built by the release workflow, not here (they need buildx and a
    # registry, and tracekit-ai on PyPI); add them to the dry run if their build breaks only at release time
    if args.image:
        image_sbom(args.image, args.out)
    write_sums(args.out)
    print(f"release artifacts in {args.out}")


if __name__ == "__main__":
    main()
