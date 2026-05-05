#!/usr/bin/env python3
"""Fail fast on crates.io publish metadata/version mistakes."""

from __future__ import annotations

import argparse
import os
import pathlib
import sys
import tomllib
from collections import Counter


ROOT = pathlib.Path(__file__).resolve().parents[1]
REQUIRED_METADATA = ("description",)
REQUIRED_ONE_OF = (("license", "license-file"),)
API_CRATE = "taudit-api"


def read_toml(path: pathlib.Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def workspace_members(root: pathlib.Path) -> tuple[dict, list[pathlib.Path]]:
    root_manifest = read_toml(root / "Cargo.toml")
    members = root_manifest.get("workspace", {}).get("members", [])
    return root_manifest, [root / member / "Cargo.toml" for member in members]


def inherited_value(package: dict, workspace_package: dict, key: str) -> str | None:
    value = package.get(key)
    if isinstance(value, str) and value.strip():
        return value
    if isinstance(value, dict) and value.get("workspace") is True:
        workspace_value = workspace_package.get(key)
        if isinstance(workspace_value, str) and workspace_value.strip():
            return workspace_value
    return None


def is_publishable(package: dict) -> bool:
    publish = package.get("publish")
    return publish is not False and publish != []


def expected_from_env() -> str | None:
    ref = os.environ.get("GITHUB_REF_NAME", "")
    if ref.startswith("v"):
        return ref[1:]
    return None


def compatible_workspace_api_requirement(api_version: str) -> str:
    parts = api_version.split(".")
    if len(parts) < 2:
        return api_version
    if parts[0] == "0":
        return ".".join(parts[:2])
    return parts[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--expected-release-version",
        default=expected_from_env(),
        help="Expected version for all publishable taudit crates except taudit-api.",
    )
    args = parser.parse_args()

    root_manifest, manifests = workspace_members(ROOT)
    workspace_package = root_manifest.get("workspace", {}).get("package", {})
    packages: list[tuple[pathlib.Path, dict]] = []
    errors: list[str] = []

    for manifest_path in manifests:
        manifest = read_toml(manifest_path)
        package = manifest.get("package", {})
        if not package or not is_publishable(package):
            continue
        packages.append((manifest_path, package))

        name = package.get("name", manifest_path.parent.name)
        for key in REQUIRED_METADATA:
            if inherited_value(package, workspace_package, key) is None:
                errors.append(f"{manifest_path}: package {name!r} missing required `{key}`")
        for keys in REQUIRED_ONE_OF:
            if not any(inherited_value(package, workspace_package, key) for key in keys):
                joined = "` or `".join(keys)
                errors.append(f"{manifest_path}: package {name!r} missing `{joined}`")

    release_versions = {
        package["name"]: package["version"]
        for _, package in packages
        if package.get("name") != API_CRATE
    }
    api_versions = {
        package["name"]: package["version"]
        for _, package in packages
        if package.get("name") == API_CRATE
    }
    api_version = api_versions.get(API_CRATE)
    workspace_api_dep = root_manifest.get("workspace", {}).get("dependencies", {}).get(API_CRATE)
    if api_version and isinstance(workspace_api_dep, dict):
        expected_api_req = compatible_workspace_api_requirement(api_version)
        api_dep_version = workspace_api_dep.get("version")
        if api_dep_version != expected_api_req:
            errors.append(
                f"workspace.dependencies.{API_CRATE} has version {api_dep_version!r}; "
                f"expected {expected_api_req!r} for local {API_CRATE}@{api_version}"
            )
    if args.expected_release_version:
        for name, version in sorted(release_versions.items()):
            if version != args.expected_release_version:
                errors.append(
                    f"{name}: version {version!r} does not match expected release "
                    f"{args.expected_release_version!r}"
                )
    elif release_versions:
        counts = Counter(release_versions.values())
        if len(counts) != 1:
            versions = ", ".join(f"{name}={version}" for name, version in sorted(release_versions.items()))
            errors.append(f"publishable release crate versions are not coherent: {versions}")

    release_version = args.expected_release_version
    if release_version is None and release_versions:
        release_version = Counter(release_versions.values()).most_common(1)[0][0]

    for manifest_path, _package in packages:
        manifest = read_toml(manifest_path)
        package = manifest["package"]
        name = package["name"]
        for section_name in ("dependencies", "dev-dependencies", "build-dependencies"):
            for dep_name, dep in manifest.get(section_name, {}).items():
                if dep_name == API_CRATE:
                    if isinstance(dep, dict) and "path" in dep:
                        if dep.get("workspace") is True:
                            continue
                        dep_version = dep.get("version")
                        expected_api_req = compatible_workspace_api_requirement(api_version or "")
                        if api_version and dep_version != expected_api_req:
                            errors.append(
                                f"{manifest_path}: {name} {section_name}.{API_CRATE} has version "
                                f"{dep_version!r}; expected {expected_api_req!r}"
                            )
                    continue
                if dep_name in release_versions and isinstance(dep, dict) and "path" in dep:
                    dep_version = dep.get("version")
                    if dep_version != release_version:
                        errors.append(
                            f"{manifest_path}: {name} {section_name}.{dep_name} has version "
                            f"{dep_version!r}; expected {release_version!r}"
                        )

    if errors:
        print("crates publish metadata check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(f"crates publish metadata check passed for {len(packages)} publishable crates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
