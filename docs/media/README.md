# Generated media (diagrams, optional screenshots)

**Policy:** treat visuals as **build artifacts** of the CLI, not hand-drawn marketing.

## Preferred: SVG from the graph export

1. Generate from the same commands users run, e.g.  
   `taudit graph <file> --format dot | dot -Tsvg -o docs/media/<name>.svg`
2. Commit the SVG **with** a note in the PR or in the doc that embeds it: **exact command** and **fixture or workflow path** used to regenerate.
3. Prefer **fixtures** (`tests/fixtures/*.yml`) for stable docs; repo workflows change more often.

## Terminal “screenshots”

Avoid committing **PNG** terminal captures unless they are produced by an **automated** renderer (e.g. `termtosvg`, `agg`) checked into a script. For onboarding, prefer **fenced code blocks** with real stdout (see [Golden paths](../golden-paths.md)); they stay searchable and align with snapshot testing.

## When to add a bitmap

Reserve raster images for **external** UIs (SARIF in VS Code, hosted dashboards) where SVG is not enough. Keep them under `docs/media/` and document regeneration.

## Related

- [Golden paths](../golden-paths.md)
- [Council research: docs + golden paths + screenshots](../research/2026-04-27-council-docs-golden-paths-screenshots.md)
