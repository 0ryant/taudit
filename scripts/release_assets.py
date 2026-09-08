#!/usr/bin/env python3
"""Local mirror of the release workflow's packaging steps.

`.github/workflows/release.yml` builds `taudit` per target, wraps the binary in
an archive with a fixed name, and writes a `<archive>.sha256` sidecar in
`sha256sum` format (`<hex>  <archive>`). When GitHub Actions is unavailable
(RELEASE_GATES.md §2.2 "CI outage fallback"), this script produces byte-for-byte
the same archive names and sidecar format from a local `cargo build --release`
so downstream channels (Azure DevOps task installer, Homebrew, Chocolatey) keep
working against `gh release upload`ed assets.

Subcommands:

  package          build (optional) and archive one target into dist/
  chocolatey-sync  stamp version + Windows checksum into packaging/chocolatey/

Locally built assets carry no provenance attestation and no SBOM. Say so in
the release notes; do not claim CI parity for them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# target triple -> (archive name, os label) — must match release.yml's matrix.
TARGETS: dict[str, tuple[str, str]] = {
    "x86_64-unknown-linux-gnu": ("taudit-x86_64-linux.tar.gz", "linux"),
    "aarch64-unknown-linux-gnu": ("taudit-aarch64-linux.tar.gz", "linux"),
    "x86_64-apple-darwin": ("taudit-x86_64-macos.tar.gz", "macos"),
    "aarch64-apple-darwin": ("taudit-aarch64-macos.tar.gz", "macos"),
    "x86_64-pc-windows-msvc": ("taudit-x86_64-windows.zip", "windows"),
}

CHOCO_DIR = REPO_ROOT / "packaging" / "chocolatey"
CHOCO_NUSPEC = CHOCO_DIR / "taudit.nuspec"
CHOCO_INSTALL = CHOCO_DIR / "tools" / "chocolateyinstall.ps1"
WINDOWS_ARCHIVE = TARGETS["x86_64-pc-windows-msvc"][0]


class ReleaseAssetError(RuntimeError):
    pass


def cargo_target_dir() -> Path:
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return Path(json.loads(out)["target_directory"])


def cli_version() -> str:
    manifest = (REPO_ROOT / "crates" / "taudit-cli" / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', manifest, re.MULTILINE)
    if not match:
        raise ReleaseAssetError("could not read version from crates/taudit-cli/Cargo.toml")
    return match.group(1)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_sidecar(archive: Path) -> Path:
    sidecar = archive.with_name(archive.name + ".sha256")
    # Same shape as `sha256sum <file>` and the pwsh step in release.yml.
    sidecar.write_text(f"{sha256_of(archive)}  {archive.name}\n", encoding="ascii")
    return sidecar


def read_sidecar(sidecar: Path, expected_name: str) -> str:
    text = sidecar.read_text(encoding="ascii").strip()
    parts = text.split()
    if len(parts) != 2 or parts[1] != expected_name or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
        raise ReleaseAssetError(f"{sidecar} is not a `<sha256>  {expected_name}` line: {text!r}")
    return parts[0]


def cmd_package(args: argparse.Namespace) -> int:
    target = args.target
    if target not in TARGETS:
        raise ReleaseAssetError(f"unknown target {target}; known: {', '.join(sorted(TARGETS))}")
    archive_name, os_label = TARGETS[target]

    if not args.no_build and not args.binary:
        builder = ["cross"] if args.use_cross else ["cargo"]
        subprocess.run(
            [*builder, "build", "--release", "--target", target, "-p", "taudit"],
            cwd=REPO_ROOT,
            check=True,
        )

    exe = "taudit.exe" if os_label == "windows" else "taudit"
    binary = Path(args.binary) if args.binary else cargo_target_dir() / target / "release" / exe
    if not binary.is_file():
        raise ReleaseAssetError(f"built binary not found: {binary}")

    # Refuse to package a binary whose --version disagrees with the manifest;
    # a stale target/ is the most likely way to ship the wrong bytes.
    if os_label == "windows" or sys.platform != "win32":
        try:
            reported = subprocess.run([str(binary), "--version"], check=True, capture_output=True, text=True).stdout.strip()
        except OSError:
            reported = ""
        expected = cli_version()
        if reported and expected not in reported:
            raise ReleaseAssetError(f"binary reports {reported!r} but Cargo.toml says {expected}; rebuild first")

    dist = REPO_ROOT / args.dist
    dist.mkdir(parents=True, exist_ok=True)
    archive = dist / archive_name
    if archive.exists():
        archive.unlink()

    if os_label == "windows":
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(binary, arcname=exe)
    else:
        with tarfile.open(archive, "w:gz") as tf:
            info = tf.gettarinfo(str(binary), arcname=exe)
            info.mode = 0o755
            with binary.open("rb") as handle:
                tf.addfile(info, handle)

    sidecar = write_sidecar(archive)
    print(f"packaged {archive.relative_to(REPO_ROOT)}")
    print(f"         {sidecar.relative_to(REPO_ROOT)}: {sidecar.read_text(encoding='ascii').strip()}")
    return 0


def _stamp(path: Path, replacements: list[tuple[str, str]]) -> None:
    text = path.read_text(encoding="utf-8")
    for pattern, replacement in replacements:
        text, count = re.subn(pattern, replacement, text, flags=re.MULTILINE)
        if count == 0:
            raise ReleaseAssetError(f"{path}: pattern {pattern!r} not found")
    # Keep LF: .gitattributes treats line endings as byte-significant.
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def cmd_chocolatey_sync(args: argparse.Namespace) -> int:
    version = args.version or cli_version()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ReleaseAssetError(f"Chocolatey stable packages need an X.Y.Z version, got {version!r}")
    sidecar = Path(args.sha256_file) if args.sha256_file else REPO_ROOT / args.dist / (WINDOWS_ARCHIVE + ".sha256")
    checksum = read_sidecar(sidecar, WINDOWS_ARCHIVE)
    tag = f"v{version}"

    _stamp(CHOCO_NUSPEC, [
        (r"<version>[^<]+</version>", f"<version>{version}</version>"),
        (r"releases/tag/v\d+\.\d+\.\d+", f"releases/tag/{tag}"),
        (r"for tag `v\d+\.\d+\.\d+`", f"for tag `{tag}`"),
    ])
    _stamp(CHOCO_INSTALL, [
        (r"^# taudit \d+\.\d+\.\d+ \(", f"# taudit {version} ("),
        (r"for tag v\d+\.\d+\.\d+", f"for tag {tag}"),
        (r"releases/download/v\d+\.\d+\.\d+/", f"releases/download/{tag}/"),
        (r"^\$checksum64  = '[^']*'", f"$checksum64  = '{checksum}'"),
    ])
    print(f"chocolatey: stamped {version} / {checksum[:12]}... into {CHOCO_NUSPEC.name} and {CHOCO_INSTALL.name}")
    if shutil.which("choco") and not args.no_pack:
        out = REPO_ROOT / args.dist
        out.mkdir(parents=True, exist_ok=True)
        subprocess.run(["choco", "pack", str(CHOCO_NUSPEC), "--outputdirectory", str(out)], check=True)
        print(f"chocolatey: packed {out / f'taudit.{version}.nupkg'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dist", default="dist", help="output directory relative to the repo root (default: dist)")
    sub = parser.add_subparsers(dest="command", required=True)

    pkg = sub.add_parser("package", help="build + archive one target the way release.yml does")
    pkg.add_argument("--target", required=True, choices=sorted(TARGETS))
    pkg.add_argument("--no-build", action="store_true", help="archive the existing target/<triple>/release binary")
    pkg.add_argument("--binary", help="archive this binary instead of target/<triple>/release/taudit (implies --no-build)")
    pkg.add_argument("--use-cross", action="store_true", help="build with `cross` instead of `cargo` (Linux arm64)")
    pkg.set_defaults(func=cmd_package)

    choco = sub.add_parser("chocolatey-sync", help="stamp version + checksum into packaging/chocolatey and `choco pack`")
    choco.add_argument("--version", help="X.Y.Z (default: crates/taudit-cli/Cargo.toml)")
    choco.add_argument("--sha256-file", help=f"path to {WINDOWS_ARCHIVE}.sha256 (default: <dist>/…)")
    choco.add_argument("--no-pack", action="store_true", help="skip `choco pack` even if choco is on PATH")
    choco.set_defaults(func=cmd_chocolatey_sync)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ReleaseAssetError, subprocess.CalledProcessError) as exc:
        print(f"release_assets: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    os.chdir(REPO_ROOT)
    sys.exit(main())
