#!/usr/bin/env bash
# Install the tools `scripts/quality-gate.sh local-ci` needs, on ANY host.
#
# The two existing installers are CI-image specific: install-governance-tools.sh
# hard-requires Linux x86_64 and apt, and install-ci-linters.sh downloads a
# linux_amd64 actionlint and installs with sudo. Neither runs on the maintainer's
# Windows host, which is why the local gate could not run there at all.
#
# This one uses only per-user package managers (pip, cargo, go), so it works in
# Git Bash on Windows, on macOS, and on Linux without root.
#
# gitleaks and trivy are deliberately not installed here: both ship as single
# binaries with per-platform release archives, and the pinned, checksum-verified
# download already lives in install-governance-tools.sh for Linux CI. On a dev
# box install them from their releases pages (or brew/choco/winget) once.
set -uo pipefail

failed=()
have() { command -v "$1" >/dev/null 2>&1; }

py() {
  for c in python3 python; do
    if have "$c"; then echo "$c"; return 0; fi
  done
  return 1
}

install_pip() {
  local tool="$1" pkg="$2" pybin
  if have "$tool"; then echo "ok    $tool (already installed)"; return 0; fi
  if ! pybin="$(py)"; then echo "SKIP  $tool — no python on PATH"; failed+=("$tool"); return 0; fi
  echo "---   installing $tool via pip"
  if "$pybin" -m pip install --quiet --disable-pip-version-check "$pkg"; then
    echo "ok    $tool"
  else
    echo "FAIL  $tool (pip install $pkg)"; failed+=("$tool")
  fi
}

install_cargo() {
  local tool="$1"; shift
  if have "$tool"; then echo "ok    $tool (already installed)"; return 0; fi
  if ! have cargo; then echo "SKIP  $tool — no cargo on PATH"; failed+=("$tool"); return 0; fi
  echo "---   installing $tool via cargo (this compiles; it is slow)"
  if cargo install "$@" --locked; then echo "ok    $tool"; else echo "FAIL  $tool"; failed+=("$tool"); fi
}

install_go() {
  local tool="$1" pkg="$2"
  if have "$tool"; then echo "ok    $tool (already installed)"; return 0; fi
  if ! have go; then echo "SKIP  $tool — no go on PATH"; failed+=("$tool"); return 0; fi
  echo "---   installing $tool via go install"
  if go install "$pkg"; then echo "ok    $tool"; else echo "FAIL  $tool"; failed+=("$tool"); fi
  have "$tool" || echo "note  ensure \"\$(go env GOPATH)/bin\" is on PATH"
}

echo "install-local-ci-tools: tools for \`just local-ci\`"

install_pip   yamllint   yamllint
install_pip   zizmor     zizmor
install_pip   checkov    checkov
install_go    actionlint github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
install_cargo cargo-insta cargo-insta
install_cargo cargo-deny  cargo-deny
install_cargo cargo-audit cargo-audit

echo
for t in gitleaks trivy; do
  if have "$t"; then
    echo "ok    $t (already installed)"
  else
    echo "TODO  $t — install from https://github.com/$([ "$t" = trivy ] && echo aquasecurity || echo gitleaks)/$t/releases"
    echo "      (or: brew install $t  /  choco install $t  /  winget install $t)"
  fi
done

echo
if [ "${#failed[@]}" -gt 0 ]; then
  echo "install-local-ci-tools: could not install: ${failed[*]}"
  echo "install-local-ci-tools: \`just local-ci\` will report these as SKIPPED"
  exit 1
fi
echo "install-local-ci-tools: done — run \`just local-ci\`"
