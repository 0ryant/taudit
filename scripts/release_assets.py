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

HOMEBREW_FORMULA = REPO_ROOT / "packaging" / "homebrew" / "taudit.rb"
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


def load_sidecars(dist: Path) -> dict[str, str]:
    """Map archive name -> sha256, read from the `<archive>.sha256` sidecars."""
    sums: dict[str, str] = {}
    for sidecar in sorted(dist.glob("*.sha256")):
        name = sidecar.name[: -len(".sha256")]
        sums[name] = read_sidecar(sidecar, name)
    return sums


def cmd_sha256sums(args: argparse.Namespace) -> int:
    """Aggregate the per-asset sidecars into one `SHA256SUMS`.

    The sidecars stay the source of truth (release.yml writes them and the Azure
    DevOps task installer fetches them per asset); this is the roll-up humans and
    the other channels read.
    """
    dist = REPO_ROOT / args.dist
    sums = load_sidecars(dist)
    if not sums:
        raise ReleaseAssetError(f"no *.sha256 sidecars in {dist}")
    out = dist / "SHA256SUMS"
    with out.open("w", encoding="ascii", newline="\n") as handle:
        for name in sorted(sums):
            handle.write(f"{sums[name]}  {name}\n")
    print(f"wrote {out.relative_to(REPO_ROOT)} ({len(sums)} entries)")
    return 0


# Homebrew formula url fragment -> the archive it points at.
FORMULA_ARCHIVES = [
    "taudit-aarch64-macos.tar.gz",
    "taudit-x86_64-macos.tar.gz",
    "taudit-aarch64-linux.tar.gz",
    "taudit-x86_64-linux.tar.gz",
]


def set_formula(formula: str, version: str, sums: dict[str, str]) -> str:
    """Set `version` and each platform's `sha256` in a Homebrew formula string.

    Each `url` line names its archive; the `sha256` on the following line is
    replaced with that archive's real checksum. Raises if any of the four
    archives has no checksum, so a partial release cannot half-fill the formula.
    """
    missing = [a for a in FORMULA_ARCHIVES if a not in sums]
    if missing:
        raise ReleaseAssetError(f"no checksum for {', '.join(missing)} — build/download every archive first")
    out = re.sub(r'(\n\s*version\s+)"[^"]*"', rf'\g<1>"{version}"', formula, count=1)
    lines = out.splitlines(keepends=True)
    filled = 0
    for i, line in enumerate(lines):
        if "url " not in line:
            continue
        archive = next((a for a in FORMULA_ARCHIVES if a in line), None)
        if archive is None or i + 1 >= len(lines):
            continue
        replaced, count = re.subn(r'(sha256\s+)"[^"]*"', rf'\g<1>"{sums[archive]}"', lines[i + 1], count=1)
        if count:
            lines[i + 1] = replaced
            filled += 1
    if filled != len(FORMULA_ARCHIVES):
        raise ReleaseAssetError(f"formula: filled {filled} of {len(FORMULA_ARCHIVES)} sha256 lines")
    return "".join(lines)


def cmd_homebrew_sync(args: argparse.Namespace) -> int:
    version = args.version or cli_version()
    sums = load_sidecars(REPO_ROOT / args.dist)
    formula = HOMEBREW_FORMULA.read_text(encoding="utf-8")
    updated = set_formula(formula, version, sums)
    with HOMEBREW_FORMULA.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(updated)
    print(f"homebrew: {HOMEBREW_FORMULA.name} set to {version} with {len(FORMULA_ARCHIVES)} real checksums")
    return 0


def cmd_deb(args: argparse.Namespace) -> int:
    """Build a Debian package from an already-built Linux binary, via nFPM.

    nFPM packages; it does not compile. The binary comes from `--binary`, or from
    the packaged `taudit-<cpu>-linux.tar.gz` in dist/, so the .deb ships exactly
    the bytes the release archive ships. nFPM runs in Docker unless `nfpm` is on
    PATH, which keeps the Windows host free of Go tooling.
    """
    version = args.version or cli_version()
    dist = REPO_ROOT / args.dist
    staging = dist / "deb-build"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)

    if args.binary:
        shutil.copy2(args.binary, staging / "taudit")
    else:
        archive = dist / f"taudit-{args.cpu}-linux.tar.gz"
        if not archive.is_file():
            raise ReleaseAssetError(f"{archive} not found — run `package --target ...-linux-gnu` or pass --binary")
        with tarfile.open(archive, "r:gz") as tf:
            member = tf.getmember("taudit")
            extracted = tf.extractfile(member)
            if extracted is None:
                raise ReleaseAssetError(f"{archive} has no readable `taudit` member")
            (staging / "taudit").write_bytes(extracted.read())
    (staging / "taudit").chmod(0o755)
    shutil.copy2(REPO_ROOT / "man" / "taudit.1", staging / "taudit.1")
    shutil.copy2(REPO_ROOT / "LICENSE", staging / "copyright")

    arch = {"x86_64": "amd64", "aarch64": "arm64"}[args.cpu]
    config = (REPO_ROOT / "packaging" / "nfpm" / "taudit.yaml").read_text(encoding="utf-8")
    for token, value in {
        "{{VERSION}}": version,
        "{{ARCH}}": arch,
        "{{BINARY}}": "taudit",
        "{{MANPAGE}}": "taudit.1",
        "{{LICENSE}}": "copyright",
    }.items():
        if token not in config:
            raise ReleaseAssetError(f"packaging/nfpm/taudit.yaml lost its {token} placeholder")
        config = config.replace(token, value)
    with (staging / "nfpm.yaml").open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(config)

    packages = dist / "packages"
    packages.mkdir(exist_ok=True)
    if shutil.which("nfpm"):
        cmd = ["nfpm", "package", "--config", "nfpm.yaml", "--packager", args.packager, "--target", str(packages)]
        subprocess.run(cmd, cwd=staging, check=True)
    else:
        subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{staging}:/work",
                "-v", f"{packages}:/out",
                "-w", "/work",
                args.nfpm_image,
                "package", "--config", "nfpm.yaml", "--packager", args.packager, "--target", "/out",
            ],
            check=True,
        )
    built = sorted(packages.glob(f"*{version}*"))
    for path in built:
        print(f"packaged {path.relative_to(REPO_ROOT)}")
    if not built:
        raise ReleaseAssetError("nfpm reported success but produced no package")
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

    sums = sub.add_parser("sha256sums", help="roll the per-asset .sha256 sidecars up into one SHA256SUMS")
    sums.set_defaults(func=cmd_sha256sums)

    brew = sub.add_parser("homebrew-sync", help="set version + the four real sha256 values in the Homebrew formula")
    brew.add_argument("--version", help="X.Y.Z (default: crates/taudit-cli/Cargo.toml)")
    brew.set_defaults(func=cmd_homebrew_sync)

    deb = sub.add_parser("deb", help="build a .deb (or .rpm) from a built Linux binary via nFPM")
    deb.add_argument("--version", help="X.Y.Z (default: crates/taudit-cli/Cargo.toml)")
    deb.add_argument("--cpu", default="x86_64", choices=["x86_64", "aarch64"])
    deb.add_argument("--binary", help="binary to package (default: unpack it from the dist/ linux archive)")
    deb.add_argument("--packager", default="deb", choices=["deb", "rpm"])
    deb.add_argument("--nfpm-image", default="goreleaser/nfpm:v2.43.1", help="used only when nfpm is not on PATH")
    deb.set_defaults(func=cmd_deb)

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
