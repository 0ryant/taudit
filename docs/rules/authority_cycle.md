# Authority Cycle

**Rule ID:** `authority_cycle`
**Severity:** High
**Category:** Configuration
**Tags:** security, configuration

## Detection

taudit performs an iterative DFS over `DelegatesTo` edges in the authority graph. When a back edge is detected (a gray node reached again during DFS — the classic cycle detection signal), all nodes participating in the cycle are collected. If any cycles exist, a single High-severity finding is emitted listing all cycle members.

## Risk

A workflow call cycle means Workflow A calls Workflow B, which calls Workflow A (directly or transitively through C, D, ...). The risks are:

1. **Unbounded privilege accumulation:** Each call iteration re-enters the execution context with the same (or potentially escalating) authority. A credential that is valid for a single call may be observed multiple times by code in the loop.

2. **Infinite execution:** GitHub Actions limits reusable workflow call depth to 4 levels. A cycle can cause a workflow to fail at the depth limit, but the intermediate steps may have already executed with authority and produced side effects.

3. **Configuration error indicator:** Cycles almost never appear intentionally. Their presence usually indicates a misconfigured workflow reference — the wrong repository, a copy-paste error in a `uses:` path, or a refactoring that accidentally created a dependency loop.

4. **Security audit confusion:** When you trace what code runs during your deployment, a cycle makes it impossible to enumerate the full execution graph. This obscures the real attack surface.

## Remediation

1. **Visualize the delegation graph:**
   ```bash
   taudit map --format dot your-workflow.yml | dot -Tsvg -o map.svg
   open map.svg
   ```
   Look for DelegatesTo edges that form a loop. Every arrow going "backward" is a back edge and part of the cycle.

2. **Identify the back edge:** Once you see the cycle, find which `uses:` line creates the backward reference. This is usually in one of the workflows involved.

3. **Break the cycle:** The fix depends on why the cycle exists:
   - **Shared logic:** Extract the common logic into a third workflow that both call, without either calling the other.
   - **Copy-paste error:** Correct the `uses:` reference to point to the intended workflow.
   - **Refactoring artifact:** Remove or redirect the errant call.

4. **Example — before (cycle):**
   ```yaml
   # deploy.yml calls verify.yml
   jobs:
     deploy:
       uses: ./.github/workflows/verify.yml  # calls verify
   
   # verify.yml calls deploy.yml (the cycle)
   jobs:
     check:
       uses: ./.github/workflows/deploy.yml  # back edge
   ```

   **After (cycle broken):**
   ```yaml
   # Extract shared logic to shared.yml
   # deploy.yml calls shared.yml
   # verify.yml calls shared.yml
   # Neither calls the other
   ```

5. **Verify:** Re-run `taudit scan`. The finding should be gone. Also confirm that `taudit map --format dot` produces a DAG (no backward arrows).

## See also

- [cross_workflow_authority_chain](cross_workflow_authority_chain.md) — related: authority flowing into external workflows (acyclic case)
- [GitHub Actions — reusable workflows call depth limit](https://docs.github.com/en/actions/using-workflows/reusing-workflows#nesting-reusable-workflows)
