#!/usr/bin/env bash
# Install ecosystem-pinned governance CLI tools (Linux x86_64).
# Sources scripts/tool-versions.env — see standardise-ecosystem.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=tool-versions.env
set -a
source "${ROOT}/scripts/tool-versions.env"
set +a

run_priv() {
  if [[ "$(id -u)" == "0" ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

require_linux_amd64() {
  if [[ "$(uname -s)" != "Linux" ]] || [[ "$(uname -m)" != "x86_64" ]]; then
    echo "install-governance-tools: expected Linux x86_64 (got $(uname -s)/$(uname -m))"
    exit 1
  fi
}

require_linux_amd64

run_priv apt-get update
run_priv apt-get install -y wget curl ca-certificates gnupg lsb-release python3-pip

tmpdir=$(mktemp -d)
trap 'rm -rf "${tmpdir}"' EXIT

# --- Trivy (pinned tarball; avoids apt repo drift) ---
trivy_tar="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${trivy_tar}" -o "${tmpdir}/${trivy_tar}"
(
  cd "${tmpdir}"
  echo "${TRIVY_SHA256_LINUX_64BIT}  ${trivy_tar}" > trivy.sha256
  sha256sum -c trivy.sha256
)
run_priv tar -xzf "${tmpdir}/${trivy_tar}" -C /usr/local/bin trivy
trivy version

# --- Gitleaks ---
gl_tar="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${gl_tar}" -o "${tmpdir}/${gl_tar}"
(
  cd "${tmpdir}"
  echo "${GITLEAKS_SHA256_LINUX_X64}  ${gl_tar}" > gitleaks.sha256
  sha256sum -c gitleaks.sha256
)
tar -xzf "${tmpdir}/${gl_tar}" -C "${tmpdir}" gitleaks
run_priv install -m 0755 "${tmpdir}/gitleaks" /usr/local/bin/gitleaks
gitleaks version

# --- Checkov + zizmor (PyPI pins) ---
if [[ "$(id -u)" == "0" ]]; then
  python3 -m pip install --break-system-packages "checkov==${CHECKOV_VERSION}" "zizmor==${ZIZMOR_VERSION}"
else
  python3 -m pip install --user "checkov==${CHECKOV_VERSION}" "zizmor==${ZIZMOR_VERSION}"
  if [[ -n "${GITHUB_PATH:-}" ]]; then
    echo "${HOME}/.local/bin" >> "${GITHUB_PATH}"
  fi
  export PATH="${HOME}/.local/bin:${PATH}"
fi
export PATH="${HOME}/.local/bin:/usr/local/bin:${PATH}"
checkov --version
zizmor --version
