# Secret via Env Gate to Untrusted Consumer

**Rule ID:** `secret_via_env_gate_to_untrusted_consumer`
**Severity:** Critical
**Category:** Propagation
**Tags:** security, privilege-escalation, propagation, github-actions

## Detection

This rule fires when a job contains both:

1. A **writer** step earlier in the job that:
   - Carries metadata `writes_env_gate: true` (the parser stamps this when a `run:` body contains a write to `$GITHUB_ENV` or `$GITHUB_PATH`, or an ADO `##vso[task.setvariable]` call), AND
   - Holds at least one `HasAccessTo` edge to a `Secret` or `Identity` node — the value being laundered must derive from authority.

2. A **consumer** step later in the same job (matched via `META_JOB_NAME`) that:
   - Runs in trust zone `Untrusted` or `ThirdParty`, AND
   - Carries metadata `reads_env: true` — stamped by the parser when the step references `${{ env.X }}` in a `with:` value, an inline script body, or its own `env:` mapping.

The same-job constraint is enforced because `$GITHUB_ENV` only propagates within a single job; a writer in job A cannot launder into a consumer in job B.

## Risk

`$GITHUB_ENV` is the canonical GitHub Actions exfiltration path. The platform exposes a per-step file (`$GITHUB_ENV`) where one step can append `KEY=value` lines that become environment variables for every subsequent step in the same job. The intent is configuration sharing — set a build version, capture a commit hash, etc. The risk is that an authority value written into `$GITHUB_ENV` becomes ambient in the runner environment, accessible to any later step regardless of trust zone, **without any explicit `with:` or `env:` mapping that the audit graph can see**.

The two component rules each see only half of the chain:

- `self_mutating_pipeline` fires on the **writer** because writing to `$GITHUB_ENV` is intrinsically risky. It does not know which downstream step reads the value, or whether that step is untrusted.
- `untrusted_with_authority` fires when an untrusted step has a direct `HasAccessTo` edge to a `Secret`/`Identity`. But the consumer step in this pattern reads from `env.X`, not from `secrets.X` — there is no `HasAccessTo` edge for it to fire on. The graph does not connect the secret to the untrusted consumer.

This rule closes the composition gap. The attack scenario:

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: setup-credentials
        run: echo "CLOUD_KEY=${{ secrets.CLOUD_KEY }}" >> $GITHUB_ENV
      - name: build
        run: ./build.sh
      - name: deploy
        uses: some-org/deploy-action@main          # untrusted (unpinned)
        with:
          api-key: ${{ env.CLOUD_KEY }}            # reads laundered secret
```

Without this rule, `taudit scan` would emit a Critical finding on the writer (secret written to env gate) and Highs on the unpinned action — but no finding directly attributing the **chain**: a secret reached untrusted code. Operators reviewing the report would have to reason about the composition themselves, which is exactly the gap that R2 attack #3 exploited in the redteam round.

## Remediation

1. **Pass the secret to the consuming step via an explicit `env:` mapping** so the relationship is graph-visible:

   ```yaml
   - name: deploy
     uses: some-org/deploy-action@<sha>           # PIN the action
     with:
       api-key: ${{ secrets.CLOUD_KEY }}          # direct, not via env gate
   ```

   Or, when the consumer reads from `env`, declare the env on the step:

   ```yaml
   - name: deploy
     uses: some-org/deploy-action@<sha>
     env:
       CLOUD_KEY: ${{ secrets.CLOUD_KEY }}
   ```

   Either form produces a `HasAccessTo` edge that downstream rules and SIEMs can reason about.

2. **Pin the third-party consumer to a 40-char SHA** before exposing any secret-derived value to it. An unpinned action's behaviour can change at any moment.

3. **Audit every `$GITHUB_ENV` write in your workflow** for whether the value derives from a secret:

   ```bash
   grep -rn 'GITHUB_ENV' .github/workflows/
   ```

   For each match, ask: is the value a secret? Does any later step in the same job consume the variable? Is that step third-party or untrusted? If yes to all three, you have this finding.

4. **Verify:** Re-run `taudit scan`. The finding clears once the laundering chain is broken (either by pinning the consumer + passing the secret directly, or by removing the env-gate write entirely).

## See also

- [self_mutating_pipeline](self_mutating_pipeline.md) — writer half of this composition
- [untrusted_with_authority](untrusted_with_authority.md) — direct-access half of this composition
- [authority_propagation](authority_propagation.md) — multi-hop propagation through delegation edges
- [GitHub Actions — environment files](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-environment-variable)
