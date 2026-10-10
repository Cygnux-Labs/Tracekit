#!/usr/bin/env python3
"""Build the npm packages @cygnux/tracekit-signer-<platform>: a python-build-standalone CPython with tracekit-ai[signer]
and its wheels unpacked into site-packages, for `npx @cygnux/tracekit up` without a Python. A release step
(docs/RELEASING.md); npm install never runs it. It bundles the tracekit-ai wheel of this release from RELEASE (checked
against RELEASE/SHA256SUMS, as scripts/release/build.py writes it), never the package index's, and its dependencies at
the versions of scripts/release/runtime-constraints.txt.

    python3 scripts/build-signer-bundles.py [--release release] [--out build/npm] [target ...]
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONSTRAINTS = os.path.join(ROOT, "scripts", "release", "runtime-constraints.txt")
PY = "3.12"
PBS = ("https://github.com/astral-sh/python-build-standalone/releases/download/20261009/"
       "cpython-3.12.15+20261009-{triple}-install_only_stripped.tar.gz")
# npm key: (PBS triple, its sha256, npm os, npm cpu, pip --platform tags)
TARGETS = {
    # macosx_13_0: the pinned google-re2's oldest macOS wheel (older macOS runs the regex backend)
    "darwin-arm64": ("aarch64-apple-darwin", "233f8e15255b3e1d1fd47ea5dd5230dfed803f371138e896e54d98c60ae19f6f",
                     "darwin", "arm64", ["macosx_13_0_arm64"]),
    "darwin-x64": ("x86_64-apple-darwin", "fb3187d95334813b88940db0f1ca57b84cedfd552739c3a5771c3ea0e49988c9",
                   "darwin", "x64", ["macosx_10_13_x86_64"]),
    "linux-x64-gnu": ("x86_64-unknown-linux-gnu", "ffa8f85f1b56e88b687f08d743d817015524b86a9365fd921243132b80f1a36d",
                      "linux", "x64", ["manylinux_2_28_x86_64", "manylinux2014_x86_64"]),
    "linux-arm64-gnu": ("aarch64-unknown-linux-gnu", "2e1ba0e7f22e01c534caebf7f09e7820322bc0d055271d3434af671e8400f96f",
                        "linux", "arm64", ["manylinux_2_28_aarch64", "manylinux2014_aarch64"]),
    "win32-x64": ("x86_64-pc-windows-msvc", "11ed9f8a6ac64fb1b5a55e40e305a6744a3f77a70863c8f8197a6e4349abc64a",
                  "win32", "x64", ["win_amd64"]),
}
STRIP = {"include", "test", "tests", "idle_test"}


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def download(url, digest, dest):
    """`url` saved as `dest`, refused unless its sha256 is `digest`."""
    urllib.request.urlretrieve(url, dest)
    if sha256(dest) != digest:
        os.remove(dest)
        sys.exit(f"{url}: sha256 mismatch, expected {digest}")
    return dest


def release_wheel(release, version):
    """The tracekit-ai `version` wheel in `release`, refused unless release/SHA256SUMS lists it with its sha256."""
    name = f"tracekit_ai-{version}-py3-none-any.whl"
    path = os.path.join(release, name)
    try:
        with open(os.path.join(release, "SHA256SUMS"), encoding="utf-8") as f:
            sums = {n: h for h, _, n in (line.rstrip("\n").partition("  ") for line in f)}
    except FileNotFoundError:
        sys.exit(f"{release}: no SHA256SUMS (scripts/release/build.py writes it)")
    if name not in sums:
        sys.exit(f"{release}/SHA256SUMS does not list {name}")
    if not os.path.isfile(path) or sha256(path) != sums[name]:
        sys.exit(f"{path}: missing or not the file SHA256SUMS lists")
    return path


def pip_download(platforms, wheel, dest):
    """The tracekit-ai `wheel` with the signer extra and its pinned dependencies as wheels for `platforms`, into
    `dest`."""
    cmd = [sys.executable, "-m", "pip", "download", "-q", "-d", dest, "-c", CONSTRAINTS, f"{wheel}[signer]",
           "--only-binary", ":all:", "--implementation", "cp", "--python-version", PY]
    for p in platforms:
        cmd += ["--platform", p]
    subprocess.run(cmd, check=True)


def package_json(key, version):
    _, _, npm_os, cpu, _ = TARGETS[key]
    pkg = {"name": f"@cygnux/tracekit-signer-{key}", "version": version,
           "description": f"The Tracekit signer for {key}: a standalone CPython with tracekit-ai[signer]. "
                          "Installed by @cygnux/tracekit; not used directly.",
           "license": "MIT", "repository": {"type": "git", "url": "https://github.com/Cygnux-Labs/Tracekit"},
           "os": [npm_os], "cpu": [cpu], "files": ["python", "wheels.sha256"]}
    if npm_os == "linux":
        pkg["libc"] = ["glibc"]
    return pkg


def build(key, wheel, version, out):
    """Write out/tracekit-signer-<key>/ with the tracekit-ai `wheel` and return its size in bytes."""
    triple, digest, npm_os, _, platforms = TARGETS[key]
    pkg = os.path.join(out, f"tracekit-signer-{key}")
    shutil.rmtree(pkg, ignore_errors=True)
    os.makedirs(pkg)
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(download(PBS.format(triple=triple), digest, os.path.join(tmp, "python.tar.gz"))) as tar:
            # the archive's top dir is python/; it is hash-pinned, the data filter is where tarfile has it
            tar.extractall(pkg, **({"filter": "data"} if hasattr(tarfile, "data_filter") else {}))
        wheels = os.path.join(tmp, "wheels")
        pip_download(platforms, wheel, wheels)
        site = os.path.join(pkg, "python", *(["Lib"] if npm_os == "win32" else ["lib", f"python{PY}"]), "site-packages")
        lines = []
        for name in sorted(os.listdir(wheels)):
            lines.append(f"{sha256(os.path.join(wheels, name))}  {name}\n")
            # lean: unzips the wheel (no .data/ scripts or RECORD rewrite); enough for tracekit and its deps' wheels
            with zipfile.ZipFile(os.path.join(wheels, name)) as z:
                z.extractall(site)
    with open(os.path.join(pkg, "wheels.sha256"), "w") as f:
        f.writelines(lines)
    for top, dirs, names in os.walk(os.path.join(pkg, "python"), topdown=True):
        for d in [d for d in dirs if d in STRIP]:
            shutil.rmtree(os.path.join(top, d))
            dirs.remove(d)
        for n in names:   # npm pack drops symlinks (PBS's bin/python3 -> python3.12): store copies
            path = os.path.join(top, n)
            if os.path.islink(path):
                target = os.path.realpath(path)
                os.remove(path)
                shutil.copy2(target, path)
    with open(os.path.join(pkg, "package.json"), "w") as f:
        json.dump(package_json(key, version), f, indent=2)
        f.write("\n")
    return sum(os.lstat(os.path.join(top, n)).st_size for top, _, names in os.walk(pkg) for n in names)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--release", default=os.path.join(ROOT, "release"),
                    help="the release's files: its tracekit-ai wheel and SHA256SUMS (default ./release)")
    ap.add_argument("--out", default=os.path.join(ROOT, "build", "npm"))
    ap.add_argument("targets", nargs="*", help=f"some of {', '.join(TARGETS)} (default: all)")
    args = ap.parse_args(argv)
    if set(args.targets) - set(TARGETS):
        ap.error(f"unknown targets {sorted(set(args.targets) - set(TARGETS))}")
    with open(os.path.join(ROOT, "sdk", "typescript", "package.json")) as f:
        version = json.load(f)["version"]
    wheel = release_wheel(args.release, version)
    for key in args.targets or TARGETS:
        print(f"tracekit-signer-{key}@{version}: {build(key, wheel, version, args.out) / 1e6:.1f} MB unpacked")


if __name__ == "__main__":
    main()
