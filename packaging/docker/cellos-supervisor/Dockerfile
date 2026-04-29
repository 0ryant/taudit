# cellos-supervisor — build from CellOS repo root as Docker context.
# Published by .github/workflows/publish-cellos-ghcr.yml to ghcr.io.
#
# Runtime is Ubuntu Noble to match GitHub-hosted ubuntu-latest glibc, so a
# taudit binary built on the runner can be bind-mounted into the container
# for smoke tests (scripts/cellos_smoke_docker.sh).
# syntax=docker/dockerfile:1

FROM ubuntu:noble AS build

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
  && rm -rf /var/lib/apt/lists/*

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.88 --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /src
COPY . .
RUN cargo build --release -p cellos-supervisor

FROM ubuntu:noble

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates libssl3 \
  && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/cellos-supervisor /usr/local/bin/cellos-supervisor

# Non-root runtime (Trivy DS-0002); binary is world-executable.
RUN useradd -r -u 10001 -s /usr/sbin/nologin cellos

USER cellos

ENTRYPOINT ["/usr/local/bin/cellos-supervisor"]
