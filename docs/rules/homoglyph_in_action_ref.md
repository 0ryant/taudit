# Homoglyph In Action Ref

**Rule ID:** `homoglyph_in_action_ref`
**Severity:** High
**Category:** Supply Chain
**Tags:** security, supply-chain
**Platform:** GitHub Actions only

## Detection

taudit fires when a `uses:` action reference contains non-ASCII characters — Unicode code points outside the range U+0000–U+007F. These characters can be homoglyphs: characters from non-Latin scripts that are visually indistinguishable from ASCII characters when rendered in most editors, terminals, and GitHub's diff UI.

The check is applied to every `uses:` field in all job steps, including `jobs.<job>.steps[*].uses` and reusable workflow call references.

## Risk

An attacker who controls a GitHub account with a name containing Unicode lookalike characters can register an action repository that appears identical to a trusted action when viewed casually. For example, Cyrillic `а` (U+0430) is visually identical to Latin `a` (U+0061) in most fonts. A `uses:` reference to `аctions/checkout@v4` (Cyrillic `а`) would resolve to a completely different repository from `actions/checkout@v4`.

The attack path:

1. An attacker registers a GitHub org or user account whose name contains one or more homoglyph substitutions of a trusted action publisher (e.g. `аctions` instead of `actions`).
2. The attacker publishes an action in that account with the same repository name as the target action.
3. A developer copies a `uses:` reference from an untrusted source (a comment, a Slack message, a documentation site controlled by the attacker) and pastes it into a workflow file.
4. The non-ASCII character is invisible to visual inspection. Code review, PR diff views, and editor syntax highlighting typically do not reveal the substitution.
5. The workflow runs the attacker's action with the full authority available to the job: secrets, the GITHUB_TOKEN, and any other credentials in scope.

SHA-pinning completely eliminates this attack vector because a SHA digest cannot be spoofed. A SHA pin resolves to exactly one git object regardless of the repository name or owner.

## Remediation

Pin all `uses:` references to SHA digests:

```yaml
# Before (vulnerable — tag reference; also vulnerable if owner contains homoglyphs)
- uses: actions/checkout@v4

# After (safe — SHA is not spoofable regardless of the action name)
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

To audit existing unpinned references for non-ASCII characters, run:

```bash
taudit explain homoglyph_in_action_ref
```

This will list every affected step with the file path, line number, and the flagged `uses:` value.

You can also check the raw bytes of any `uses:` reference directly:

```bash
# Check for non-ASCII bytes in workflow files
grep -Pn '[^\x00-\x7F]' .github/workflows/*.yml
```

**Verify:** Re-run `taudit scan`. The finding resolves when all `uses:` references in the flagged file are either (a) pinned to a SHA digest, or (b) contain only ASCII characters (U+0000–U+007F).

## See also

- [unpinned_action](unpinned_action.md) — fires on tag-pinned or floating action references regardless of character set
