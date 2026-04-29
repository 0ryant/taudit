#!/usr/bin/env bash
# Run cellos_smoke using a pre-built supervisor image (e.g. from ghcr.io).
# Requires: docker, taudit binary under repo root bind mount, tests/fixtures/clean.yml.
#
# Env:
#   CELLOS_SUPERVISOR_IMAGE  — required (e.g. ghcr.io/owner/cellos-supervisor:main)
#   GITHUB_WORKSPACE         — optional; default PWD (repo root when bind-mounted as /work)
#   TAUDIT_BIN               — optional; default ${ROOT}/target/release/taudit
set -euo pipefail

ROOT="${GITHUB_WORKSPACE:-${PWD}}"
IMAGE="${CELLOS_SUPERVISOR_IMAGE:?set CELLOS_SUPERVISOR_IMAGE to ghcr.io/.../cellos-supervisor:tag}"

if [[ ! -f "${ROOT}/tests/fixtures/clean.yml" ]]; then
  echo "Expected ${ROOT}/tests/fixtures/clean.yml not found" >&2
  exit 1
fi

TAUDIT_BIN="${TAUDIT_BIN:-${ROOT}/target/release/taudit}"
case "${TAUDIT_BIN}" in
  /*) ;;
  *) TAUDIT_BIN="${ROOT}/${TAUDIT_BIN}" ;;
esac
if [[ ! -x "${TAUDIT_BIN}" ]]; then
  echo "taudit binary not executable: ${TAUDIT_BIN}" >&2
  exit 1
fi

# Path as seen inside the container (/work is ROOT).
if [[ "${TAUDIT_BIN}" != "${ROOT}"/* ]]; then
  echo "TAUDIT_BIN must be under ROOT (${ROOT})" >&2
  exit 1
fi
rel="${TAUDIT_BIN#"${ROOT}/"}"
argv0="/work/${rel}"
# Prefixes are evaluated in the container; argv0 lives under /work/...
work_bin_prefix="/work/$(dirname "${rel}")"

SPEC_PATH="$(mktemp /tmp/taudit-cellos-docker-spec.XXXXXX)"
cleanup() { rm -f "${SPEC_PATH}"; }
trap cleanup EXIT

cat >"${SPEC_PATH}" <<EOF
{
  "apiVersion": "cellos.io/v1",
  "kind": "ExecutionCell",
  "spec": {
    "id": "taudit-cellos-smoke-docker",
    "authority": {
      "secretRefs": [],
      "egressRules": []
    },
    "lifetime": { "ttlSeconds": 120 },
    "run": {
      "argv": ["${argv0}", "scan", "tests/fixtures/clean.yml", "--quiet", "--severity-threshold", "critical"],
      "workingDirectory": "/work"
    }
  }
}
EOF

echo "Running taudit inside CellOS supervisor container (${IMAGE})..."
docker run --rm \
  -v "${ROOT}:/work" \
  -v "${SPEC_PATH}:/cellos-spec.json:ro" \
  -w /work \
  -e CELL_OS_USE_NOOP_SINK=1 \
  -e "CELLOS_RUN_ARGV0_ALLOW_PREFIXES=${work_bin_prefix},/usr/bin,/bin" \
  "${IMAGE}" \
  "/cellos-spec.json"
