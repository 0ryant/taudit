# taudit demo: Authority problem deck + bad workflow set

This demo turns the algol.cc authority thesis into a repeatable taudit proof pack.
It ships three intentionally bad GitHub Actions workflows, regenerates their scan
and graph artifacts, and includes a slide deck that uses the same visual direction
as the algol.cc site.

Core line:

> The failure class is mutable executable code inheriting authority from a trusted environment.

## Demo workflows

- `workflows/developer-tool-authority-path.yml` - mutable third-party deploy action inherits write, package, OIDC, and secret authority.
- `workflows/helper-path-authority-path.yml` - PATH mutation happens before a credential-bearing deploy action resolves helpers.
- `workflows/pr-writeback-authority-path.yml` - `pull_request_target` checks out PR code, runs package install, and keeps writeback authority in scope.

## Run

Regenerate the full demo pack with:

```powershell
.\demo\run-demo.ps1
```

The script:

- builds `taudit` once, then reuses the compiled binary for all workflows
- preserves the original flagship outputs under `demo/reports` and `demo/graphs`
- writes per-workflow outputs under `demo/reports/bad` and `demo/graphs/bad`
- renders each DOT graph to SVG with local Graphviz `dot` when available, or a pinned Node fallback when it is not

You can still run the flagship workflow by hand:

```powershell
cargo run -p taudit -- scan demo\workflows\developer-tool-authority-path.yml --no-color --format terminal
cargo run -p taudit -- map demo\workflows\developer-tool-authority-path.yml
cargo run -p taudit -- graph demo\workflows\developer-tool-authority-path.yml --format dot --rich-labels
cargo run -p taudit -- graph demo\workflows\developer-tool-authority-path.yml --format summary
```

## Generated artifacts

Flagship outputs:

- `reports/scan.txt`
- `reports/scan.json`
- `reports/map.txt`
- `graphs/authority.mmd`
- `graphs/authority.dot`
- `graphs/authority.svg`
- `graphs/summary.json`

Per-workflow outputs:

- `reports/bad/<workflow>.scan.txt`
- `reports/bad/<workflow>.scan.json`
- `reports/bad/<workflow>.map.txt`
- `graphs/bad/<workflow>.authority.mmd`
- `graphs/bad/<workflow>.authority.dot`
- `graphs/bad/<workflow>.authority.svg`
- `graphs/bad/<workflow>.summary.json`

Slide deck:

- `slides/authority-problem-deck.html`

## Story

1. GitHub's incident is about developer tooling inheriting developer authority.
2. taudit's current product already maps the CI/CD version of the same class.
3. Each bad workflow demonstrates a different way mutable or lower-trust execution reaches real authority.
4. The deck and graph artifacts make the authority path visible without claiming runtime proof.
5. The design-partner ask is still the same: map one real workflow path, show what it can reach, and make the rotation set obvious before incident response starts.

Read next:

- `reports/incident-brief.md`
- `reports/talk-track.md`
- `reports/authority-path-council.md`
