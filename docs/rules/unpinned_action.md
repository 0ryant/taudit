# Unpinned Action

**Rule ID:** `unpinned_action`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, supply-chain

## Detection

taudit checks every third-party action reference (Image node with trust zone ThirdParty or Untrusted) against a SHA-pin check: the `@ref` part must be exactly 40 or more hexadecimal characters. References like `@v4`, `@main`, `@latest`, or any named tag fail the check. The same action used in multiple jobs is deduplicated — it fires once per unique action reference, not once per job.

Container images (`container:` fields) are excluded from this rule — they are covered by [floating_image](floating_image.md) instead.

## Risk

A mutable tag reference means the action's code can change between your workflow runs without any change on your side. The attack path:

1. You reference `actions/checkout@v4`. This tag currently points to commit `abc123`.
2. The action maintainer's account is compromised, or they publish an update to `v4` that includes malicious code.
3. On the next run of your workflow, your job fetches the new code at `v4` — which is now different. You have no indication anything changed.
4. The new code reads your secrets from the environment and exfiltrates them.

This is a textbook supply-chain attack, and it has happened in production environments. The `tj-actions/changed-files` incident in 2023 is a documented example where a compromised action exfiltrated GitHub tokens from thousands of repositories.

Even a non-malicious tag update can silently break your build in ways that are hard to debug without pinning.

## Remediation

1. **Get the SHA for each flagged action:**
   ```bash
   gh api /repos/actions/checkout/commits/v4 --jq '.sha'
   # → 11bd71901bbe5b1630ceea73d27597364c9af683
   ```

2. **Replace the mutable tag with the SHA, keeping the tag as a comment:**
   ```yaml
   # Before
   - uses: actions/checkout@v4
   
   # After
   - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
   ```

3. **Automate future updates with Dependabot:**
   ```yaml
   # .github/dependabot.yml
   version: 2
   updates:
     - package-ecosystem: github-actions
       directory: /
       schedule:
         interval: weekly
       groups:
         actions:
           patterns: ["*"]
   ```
   Dependabot will open PRs that update the SHA comment and the pinned digest together.

4. **Bulk-pin existing workflows:** Use `pinact` or `pin-github-action` to pin everything at once:
   ```bash
   # pinact (Go)
   pinact run .github/workflows/*.yml
   
   # pin-github-action (Python)
   pin-github-action .github/workflows/ci.yml
   ```

5. **Verify:** Re-run `taudit scan`. Each previously-flagged action reference should now pass. If a finding persists, check that the SHA is exactly 40 hex characters — `v4.0.0` is still mutable.

## See also

- [authority_propagation](authority_propagation.md) — if the unpinned action also receives secrets, you have a Critical propagation finding
- [floating_image](floating_image.md) — same concept for container images
- [StepSecurity `pin-github-action`](https://github.com/step-security/pin-github-action)
- [tj-actions supply chain incident (2023)](https://blog.gitguardian.com/the-supply-chain-attack-in-tj-actions-changed-files-all-you-need-to-know/)
