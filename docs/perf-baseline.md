# taudit performance baseline — v0.9

This document captures the first criterion-measured performance baseline for
taudit's hot paths. It exists so future regressions are detectable: any change
that moves these numbers significantly (10%+) deserves a look.

The numbers below come from a real run on the development machine — not
estimates. Re-run the suite (instructions at the bottom) to get fresh numbers
for your own hardware and to compare against this baseline.

## Environment

- **Hardware**: Apple M-series (`Darwin Kernel Version 25.2.0 ... arm64`,
  Apple Silicon laptop, on AC power, no thermal throttling observed during
  the run).
- **Toolchain**: `rustc 1.94.1 (e408947bf 2026-03-25) (Homebrew)` /
  `cargo 1.94.1 (Homebrew)`.
- **Build profile**: `bench` (release with `lto = true`,
  `codegen-units = 1`, `opt-level = 3`).
- **Criterion settings used for this baseline**:
  `--warm-up-time 1 --measurement-time 3 --sample-size 20`. These are
  reduced from criterion's defaults to keep the suite under five minutes
  end-to-end. The narrower confidence intervals you'd get with the defaults
  do not change any of the qualitative observations below.
- **taudit version**: 0.9.0 (HEAD = `11e71b2`).

## Results

All times below are the criterion-reported median (the middle of the
`time:` triple). Throughput is the `thrpt:` figure printed alongside.
"Elem" = nodes + edges (propagation), nodes (rules), or invariants
(custom rules); "B" = bytes of YAML (parsers).

### `taudit-core` — propagation engine (`bench_propagation`)

`propagation_analysis` BFS over a synthetic graph. The "elements"
counted by criterion are `nodes + edges` so the elements/sec figure is
directly comparable across both density factors.

| Group / size            | Median time | Throughput      |
| ----------------------- | ----------- | --------------- |
| sparse_1.5x / 10        | 681 ns      | 32.3 Melem/s    |
| dense_5x  / 10          | 5.58 µs     |  8.06 Melem/s   |
| sparse_1.5x / 100       | 28.2 µs     |  8.42 Melem/s   |
| dense_5x  / 100         | 289  µs     |  1.73 Melem/s   |
| sparse_1.5x / 1 000     | 1.22 ms     |  1.95 Melem/s   |
| dense_5x  / 1 000       | 13.3 ms     |  376 Kelem/s    |
| sparse_1.5x / 10 000    | 101  ms     |  234 Kelem/s    |
| dense_5x  / 10 000      | 1.08 s      |  46.5 Kelem/s   |

### `taudit-core` — individual rules (`bench_rules` / `rules_individual`)

Per-rule cost on the same fixture graph at three sizes (10 / 100 / 1 000
first-party steps wired into one chain).

| Rule                                       | n=10    | n=100   | n=1 000  |
| ------------------------------------------ | ------- | ------- | -------- |
| `authority_propagation`                    | 785 ns  | 1.80 µs | 10.5 µs  |
| `unpinned_action`                          | 235 ns  | 290 ns  | 1.02 µs  |
| `untrusted_with_authority`                 | 17.6 ns | 131 ns  | 1.48 µs  |
| `over_privileged_identity`                 | 192 ns  | 306 ns  | 1.74 µs  |

### `taudit-core` — full pipeline (`bench_rules` / `rules_run_all`)

`run_all_rules` (32 built-in rules + confidence cap + sort) on the same
fixtures.

| Graph size | Median time | Throughput   |
| ---------- | ----------- | ------------ |
| n=10       | 3.95 µs     | 6.08 Melem/s |
| n=100      | 74.3 µs     | 2.75 Melem/s |
| n=1 000    | 4.89 ms     | 409 Kelem/s  |

### `taudit-core` — custom invariant DSL (`bench_custom_rules`)

Cost split between loading invariant YAML and evaluating it against a
fixed fixture graph. The 1/10/100 axis is the *number of invariants*.
Coverage includes the v0.9 DSL additions: `graph_metadata:`,
`standalone:`, and the `not:` negation predicate.

| Stage / count          | Median time | Throughput        |
| ---------------------- | ----------- | ----------------- |
| `load`     1   rule    | 7.59 µs     | 131 Kelem/s       |
| `load`    10   rules   | 74.2 µs     | 135 Kelem/s       |
| `load`   100   rules   | 733  µs     | 137 Kelem/s       |
| `evaluate`  1  rule    | 281 ns      | 3.55 Melem/s      |
| `evaluate` 10  rules   | 2.93 µs     | 3.41 Melem/s      |
| `evaluate` 100 rules   | 28.7 µs     | 3.48 Melem/s      |

### Parsers — `bench_parse`

| Crate / input                                | Median time | Throughput   |
| -------------------------------------------- | ----------- | ------------ |
| GHA / `clean.yml`                            | 8.14 µs     | 33.2 MiB/s   |
| GHA / `over-privileged.yml`                  | 14.96 µs    | 39.7 MiB/s   |
| GHA / `propagation-leaky.yml`                | 23.5 µs     | 32.5 MiB/s   |
| GHA / synthetic 1 000 jobs                   | 9.37 ms     | 40.5 MiB/s   |
| ADO / inline `small.yml`                     | 11.96 µs    | 20.0 MiB/s   |
| ADO / inline `pr_with_var_group.yml`         | 13.16 µs    | 24.3 MiB/s   |
| ADO / inline `template_extends.yml`          | 13.65 µs    | 14.1 MiB/s   |
| ADO / synthetic 1 000 jobs                   | 8.37 ms     | 32.5 MiB/s   |
| GitLab / inline `small.yml`                  | 9.51 µs     | 22.4 MiB/s   |
| GitLab / inline `mr_with_oidc.yml`           | 12.21 µs    | 28.8 MiB/s   |
| GitLab / inline `include_extends.yml`        | 7.96 µs     | 28.2 MiB/s   |
| GitLab / synthetic 1 000 jobs                | 5.07 ms     | 31.9 MiB/s   |

## Observations

1. **Propagation is `O(V+E)` only when secrets are isolated; with dense
   cross-links, the per-source BFS reseeds and the engine becomes nearly
   `O(V·E)`.** Sparse-1.5x scaling from n=100 → n=10 000 is roughly linear
   in `V+E` (28 µs → 101 ms, ~3 600× the work for ~100× the nodes — about
   what you'd expect once edge count grows with node count). Dense-5x is
   far worse: n=100 → n=10 000 jumps 289 µs → 1.08 s (~3 700× the time for
   ~100× the nodes), because the BFS is run from every authority source
   and the dense graph means each source's frontier overlaps the others'.
   Real workflow graphs are sparse; this matters mostly as a guard against
   pathological synthetic inputs and as motivation for an eventual
   visited-set sharing optimisation.
2. **The propagation-walking rules (`authority_propagation`,
   `untrusted_with_authority`) dominate per-rule cost** — `unpinned_action`
   and `over_privileged_identity` are ~5–8× cheaper because they only walk
   the node list. `authority_propagation` at n=1 000 is 10.5 µs; the next
   most expensive single rule is 1.74 µs.
3. **`run_all_rules` at n=1 000 (4.89 ms) is dominated by the propagation
   rules and the metadata-walking ADO/GHA red-team rules.** A
   1 000-step graph is already an order of magnitude bigger than any real
   pipeline we've seen, so even the worst case here is sub-5 ms — the
   parsers are the bigger contributor on real workloads (see #4).
4. **GHA parse is the long pole at scale**: 9.37 ms for the 1 000-job
   synthetic vs. 4.89 ms for `run_all_rules` over a comparable graph.
   ADO is similar (8.37 ms); GitLab is fastest (5.07 ms) because its
   schema is shallower. On real-world inputs (10–100 jobs) every parser
   sits in the 10–25 µs range, so parsing is *not* the bottleneck on
   normal scans — but anyone running taudit against a generated mega-pipeline
   will see total wall-clock dominated by parse, not analysis.
5. **Custom invariant evaluation cost is linear in invariant count**
   (~287 ns per invariant on this fixture, holds within ±2% across the
   1 / 10 / 100 sweep). Loading is ~7.4 µs/rule and is also linear. There
   are no quadratic surprises in the DSL evaluator at the invariant counts
   anyone is likely to ship.

## How to re-run

```bash
# Full suite, default criterion settings (sample-size 100, ~5 min total
# on the dev machine):
cargo bench --workspace

# Faster pass, matching the settings used for this baseline document:
cargo bench --workspace -- --warm-up-time 1 --measurement-time 3 --sample-size 20

# A single bench:
cargo bench -p taudit-core --bench bench_propagation
```

Note: `cargo bench --workspace` runs *every* bench target in the workspace.
Some downstream crates (CLI, report sinks) only have unit-test benches —
those will run too, but they're fast.

## Comparing future runs against this baseline

Criterion supports named baselines so you can lock in this snapshot and
diff future runs against it.

```bash
# Save the current results as a named baseline:
cargo bench --workspace -- --save-baseline v091

# Later — compare a new run against that baseline:
cargo bench --workspace -- --baseline v091
```

Criterion will print delta percentages and flag any benchmark whose
median moved more than its noise threshold (default 5%).

When upgrading the baseline (after an intentional perf-affecting change),
re-save with a new name (`v092`, etc.) and update the table above with the
new numbers and a one-line note in *Observations* about what moved and why.
