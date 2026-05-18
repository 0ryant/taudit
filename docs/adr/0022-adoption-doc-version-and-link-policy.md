# ADR 0022: Adoption doc version and link policy

- **Status:** Accepted
- **Date:** 2026-05-18
- **Context:** [marketplace trust pack](../rc/v1.2.0/workstreams/marketplace-trust-pack.md), [README.md](../../README.md), [USERGUIDE.md](../../USERGUIDE.md).

## Context

Adoption docs can drift faster than code. The council found stale stable-version
examples, unpublished action references, and contradictory VS Code publication
state in planning material. Those are adoption risks.

## Decision

Adoption docs must use one of three labels:

- current stable: installable now through released channels;
- release candidate: exact prerelease version and explicit opt-in;
- planned: not presented as installable or published.

Docs may not reference `0ryant/taudit-action@v1`, Azure `Taudit@1`, VS Code
published listing, or `v1.2.0-rc.1` install commands as live until the matching
proof receipt exists.

Stable examples should pin the latest stable product version. RC examples must
pin the exact RC version and say they are prerelease opt-in.

## Lane Ownership

- **L6 docs/operator evidence** owns README, USERGUIDE, integration docs,
  golden paths, adoption docs, and marketplace copy.
- **L1 release coordination** owns release-note wording and version map.

## Acceptance Gates

- version/link audit passes across README, USERGUIDE, integration docs,
  golden paths, dogfood docs, and marketplace copy
- every planned surface has planned language
- every live surface has a receipt link
- no examples imply stable consumers auto-receive prereleases

## Consequences

Users get commands that match reality. The repo stops using aspirational docs as
implicit proof.
