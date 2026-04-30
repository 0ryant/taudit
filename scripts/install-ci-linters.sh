#!/usr/bin/env bash
# Install pinned workflow linters for CI (Debian-like images, **linux_amd64**
# actionlint binary). Used by GitHub Actions, Azure Pipelines mirror, and
# GitLab CI before `scripts/quality-gate.sh ci-governance`.
#
# Local macOS / other arches: install actionlint + yamllint yourself (e.g.
# `brew install actionlint yamllint`) before running `ci-governance` outside CI.
set -euo pipefail

run_priv() {
  if [[ "$(id -u)" == "0" ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

ACTIONLINT_VERSION="${ACTIONLINT_VERSION:-1.7.12}"
# actionlint_${VERSION}_checksums.txt — linux_amd64 (GitHub-hosted, ADO, GitLab linux)
ACTIONLINT_SHA256="${ACTIONLINT_SHA256:-8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8}"
YAMLLINT_VERSION="${YAMLLINT_VERSION:-1.9.0}"

tmpdir=$(mktemp -d)
trap 'rm -rf "${tmpdir}"' EXIT

base="https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}"
archive="actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz"
curl -fsSL "${base}/actionlint_${ACTIONLINT_VERSION}_checksums.txt" -o "${tmpdir}/checksums.txt"
curl -fsSL "${base}/${archive}" -o "${tmpdir}/${archive}"
(
  cd "${tmpdir}"
  echo "${ACTIONLINT_SHA256}  ${archive}" > expected.sha256
  sha256sum -c expected.sha256
)
tar -xzf "${tmpdir}/${archive}" -C "${tmpdir}" actionlint
run_priv install -m 0755 "${tmpdir}/actionlint" /usr/local/bin/actionlint
actionlint -version

# System-wide so the next CI step (separate shell on GitLab) still finds yamllint.
run_priv python3 -m pip install --break-system-packages "yamllint==${YAMLLINT_VERSION}" 2>/dev/null \
  || run_priv python3 -m pip install "yamllint==${YAMLLINT_VERSION}"
yamllint --version
