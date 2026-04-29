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

# Linux container runs the bind-mounted taudit; macOS/Windows host binaries are not ELF.
if command -v file >/dev/null 2>&1; then
  ft=$(file -b "${TAUDIT_BIN}" 2>/dev/null || true)
  case "${ft}" in
    *ELF*) ;;
    *)
      echo "cellos_smoke_docker.sh: need a Linux ELF taudit (e.g. build on ubuntu-latest in CI, or cross-compile). file(1): ${ft}" >&2
      exit 1
      ;;
  esac
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

# Spec must live under ROOT (single /work bind mount). File bind-mounts from
# /tmp are unreliable on some Docker engines ("Is a directory"). The container
# runs as non-root (uid 10001); chmod a+r so the cellos user can read the spec.
SPEC_PATH="$(mktemp "${ROOT}/.cellos-spec.XXXXXX.json")"
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

chmod a+r "${SPEC_PATH}"
spec_in_container="/work/$(basename "${SPEC_PATH}")"

echo "Running taudit inside CellOS supervisor container (${IMAGE})..."
docker run --rm \
  -v "${ROOT}:/work" \
  -w /work \
  -e CELL_OS_USE_NOOP_SINK=1 \
  -e "CELLOS_RUN_ARGV0_ALLOW_PREFIXES=${work_bin_prefix},/usr/bin,/bin" \
  "${IMAGE}" \
  "${spec_in_container}"
