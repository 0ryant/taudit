# Marketplace Growth Notes

Date: 2026-05-15
Scope: practical growth levers for `algol.taudit-vscode` and
`algol.taudit-azure-pipelines` after first public publish.

## Priority Order

1. **Metadata coverage**
   - Expand VS Code keywords to concrete operator intent:
     `ci-cd`, `pipeline-security`, `authority-graph`, `policy-as-code`,
     `supply-chain-security`, `sarif`, and supported CI providers.
   - Populate Azure DevOps `tags` for search/discovery:
     `azure-pipelines`, `pipeline-security`, `ci-cd`, `policy-as-code`,
     `supply-chain-security`, `authority-graph`, `taudit`.
   - Keep descriptions blunt and outcome-led.

2. **Listing conversion**
   - First screen must answer:
     what taudit does, which CI/CD systems it covers, and what operators paste
     first.
   - Both listings should link directly to:
     - a golden path
     - one demo story
     - the contract/operator guide

3. **Screenshots and demo media**
   - Minimum listing asset set:
     - one policy-gate screenshot
     - one authority-graph screenshot
     - one exploit-candidate graph screenshot
     - one short first-use motion demo
   - Every asset should be reproducible from a committed fixture or corpus
     workflow so screenshots can be regenerated without design drift.

4. **External acquisition surfaces**
   - Marketplace pages alone will not drive enough traffic.
   - Publish a small `algol.cc` product page and deep links for:
     - VS Code extension
     - Azure DevOps extension
     - GitHub action
     - crates.io package
     - demo story
   - Keep the repo README and docs index linking back to the Marketplace pages.

5. **Trust signals**
   - Complete publisher profile fields.
   - Track VS Code verified-publisher eligibility once the six-month domain and
     extension age thresholds are met.
   - Track Azure DevOps Top Publisher only as a long-tail outcome after installs,
     active installs, reviews, and support responsiveness exist.

## Search Terms Worth Owning

- CI/CD security
- pipeline security
- GitHub Actions security audit
- Azure Pipelines policy gate
- workflow security
- policy as code for pipelines
- authority graph
- exploit-candidate graph
- supply-chain review
- SARIF pipeline audit

## Asset Mapping

Use these repo artifacts as the canonical growth surfaces:

- Demo story:
  [`docs/demos/corpus-expo-docs-authority-exploit-story.md`](../demos/corpus-expo-docs-authority-exploit-story.md)
- Golden paths:
  [`docs/golden-paths.md`](../golden-paths.md)
- Integration index:
  [`docs/integrations/index.md`](../integrations/index.md)
- VS Code operator guide:
  [`docs/integrations/visual-studio-marketplace-extension-operator-guide.md`](../integrations/visual-studio-marketplace-extension-operator-guide.md)
- Azure DevOps contract:
  [`docs/integrations/azure-devops-marketplace-extension-contract.md`](../integrations/azure-devops-marketplace-extension-contract.md)

## Growth Loop

After each publish:

1. inspect listing metadata and broken links
2. verify screenshots/media still render
3. review installs, active installs, and ratings
4. patch listing copy in the next extension version if search/conversion is weak

The goal is not abstract SEO work. The goal is to make the extension easier to
find, easier to understand, and easier to paste into a real pipeline or editor
workflow.
