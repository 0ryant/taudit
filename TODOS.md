# taudit — TODO backlog

MoSCoW: **Must** | **Should** | **Could** | **Won't**

**Parallel execution:** [`docs/jobs-phased-lanes.md`](docs/jobs-phased-lanes.md) (Phase 3 — ADO variable-group enrichment).

---

## Could Have

### `--ado-pat`: ADO variable group resolution at scan time

**Status:** Not started  
**Effort:** Medium (1–2 weeks)  
**Impact:** High noise reduction for ADO pipelines with variable groups

#### Problem

When taudit sees `- group: MyGroup` in an ADO pipeline it marks the graph
`[partial]` — it can't look inside the group to distinguish padlock-secret
variables from plain config strings, so it conservatively treats the entire
group as a secret blob. Every step that inherits from the group gets flagged.
In practice this produces ~144 `[partial]` criticals on a real enterprise
pipeline where only 8–12 involve genuinely secret variables.

BUG-3 (`--ignore-partial`) reduces the noise but doesn't eliminate it; the
graph stays `Partial` and baselines are unstable because the underlying
findings shift whenever group membership changes.

#### Proposed solution

Add three optional flags to `taudit scan` and `taudit verify`:

```
--ado-org    https://dev.azure.com/<org>
--ado-project <project>
--ado-pat    <PAT or $env var>
```

At parse time, after the ADO parser marks a group `[partial]`, call:

```
GET {org}/{project}/_apis/distributedtask/variablegroups?api-version=7.1
```

ADO returns each variable with:
- `isSecret: true` → value redacted → keep as `NodeKind::Secret`
- `isSecret: false` → value in clear → add to `plain_vars`, no Secret node

The graph node for the group becomes `Complete`. Baselines stabilise.
The 144 partial criticals collapse to the 8–12 that touch genuinely secret
variables.

#### PAT scope required

`Variable Groups (Read)` only — no write, no code, no build access.

In CI:

```yaml
- name: taudit verify
  run: |
    taudit verify \
      --ado-org https://dev.azure.com/MyOrg \
      --ado-project MyProject \
      --ado-pat "${{ secrets.TAUDIT_ADO_READ_PAT }}" \
      --policy .taudit/policy \
      --include-builtin \
      .pipelines/
```

#### Design constraints

- **Opt-in only.** Without `--ado-pat`, existing behaviour is unchanged.
  Static-only path remains fully functional via BUG-3 + `--ignore-partial`.
- **Graceful degradation.** If the API call fails (network blocked, expired
  PAT, permission denied) emit a `warning:` and fall back to the current
  partial-graph behaviour. Never fail the scan due to an enrichment error.
- **No caching between runs.** Group contents can change between pipeline
  runs. Fetch fresh on every invocation.
- **Reproducibility caveat documented.** Same YAML + different ADO group state
  → different graph. Document this explicitly in `docs/baselines.md` under a
  "ADO-aware mode" section: baselines created with `--ado-pat` should note the
  group snapshot date.
- **No secret leakage.** The PAT is injected via flag only; never logged,
  never written to disk. Audit log records "ado-enrichment: yes" without the
  token value.

#### Implementation sketch

1. Add `ado_org`, `ado_project`, `ado_pat` fields to `AdoParser` (or pass as
   `ParseContext`).
2. After parsing the YAML structure, for each `AdoVariable::Group`, if PAT
   present: call the API, iterate returned variables, populate `plain_vars`
   for non-secret entries and create `NodeKind::Secret` only for `isSecret:
   true` entries.
3. Remove the `graph.mark_partial(...)` call for that group (graph is now
   complete for it).
4. New `ureq` call using the existing `ureq` workspace dependency (already
   present in `taudit-cli`).
5. Add `--ado-pat` to `taudit scan` and `taudit verify` CLI variants.
6. Update `docs/verify.md` and `docs/baselines.md`.

#### Won't scope

- Caching group contents between runs.
- Writing back to ADO (strictly read-only).
- Supporting Azure DevOps Server (on-prem) — `dev.azure.com` cloud only for
  now.
- Service connection resolution (separate API, separate scope, separate
  feature).

### VulnOps tooling in CI/CD

**Status:** Not started  
**Effort:** TBD  
**Impact:** Centralise vulnerability-operations style checks alongside existing supply-chain gates (Trivy, Checkov, Gitleaks, `cargo deny` / `cargo audit`).

#### Scope (draft)

- [ ] Select **vulnops** (or named successor / integration path) and map overlap vs `scripts/quality-gate.sh`, `.github/workflows/security.yml`, and **CI mirrors** (`azure-pipelines.yml`, `.gitlab-ci.yml`).
- [ ] Add GitHub Actions job or extend governance stage; keep **secrets out of logs** and document any PAT/API scope.
- [ ] Mirror the same gate into **ADO / GitLab** mirrors once stable on `main`.
- [ ] Update [`docs/integrations/ci-mirrors.md`](docs/integrations/ci-mirrors.md) and release notes when behaviour is contract-stable.
