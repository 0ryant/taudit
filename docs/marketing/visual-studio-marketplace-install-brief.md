# taudit Visual Studio Marketplace install brief

Status: launch handoff
Date: 2026-05-23
Audience: marketing, DevRel, field security champions, platform security leads

## Install links

- VS Code extension: <https://marketplace.visualstudio.com/items?itemName=Algol.taudit-vscode>
- Azure Pipelines task: <https://marketplace.visualstudio.com/items?itemName=Algol.taudit-azure-pipelines>

## One-line positioning

Install taudit where pipeline reviews already happen: VS Code for local CI/CD
authority review, and Azure Pipelines for `Taudit@1` merge gates.

## Short description

taudit is a CI/CD authority graph analyzer. It models how secrets, tokens,
service connections, identities, images, and artifacts move through GitHub
Actions, Azure Pipelines, GitLab CI, and Bitbucket Pipelines.

Most scanners inspect a slice of the stack: secrets, CVEs, Terraform, YAML
shape, or JSON validity. taudit covers the missing layer: the pipeline as an
authority boundary. It shows who had access to what, where trust boundaries
were crossed, and which changes should block merge or become review focus
areas.

## Primary calls to action

### VS Code

Install the VS Code extension from Visual Studio Marketplace:

```text
ext install Algol.taudit-vscode
```

Use it to run:

- `taudit: Initialize Workspace Policy`
- `taudit: Verify Workspace`
- `taudit: Scan Workspace`
- `taudit: Graph Authority View`
- `taudit: Graph Exploit View`

Best audience: developers, AppSec reviewers, platform engineers, and security
champions who review pipeline YAML before or during PR work.

### Azure Pipelines

Install the Azure Pipelines task from Visual Studio Marketplace, then add
`Taudit@1` to pipeline YAML:

```yaml
steps:
  - task: Taudit@1
    displayName: Verify pipeline authority policy
    inputs:
      mode: verify
      version: 1.1.5
      policy: .taudit/policy/
      paths: |
        azure-pipelines.yml
```

Best audience: Azure DevOps organizations that want an installable policy gate
without custom Rust install steps, Cargo caching, or ad hoc PATH handling.

## Launch copy

### Social post

CI/CD is an authority system, but most tools still treat it like plain YAML.

taudit is now installable from Visual Studio Marketplace for VS Code and Azure
Pipelines. Use it to inspect pipeline authority graphs, gate risky changes with
`Taudit@1`, and review how secrets, identities, service connections, and
artifacts cross trust boundaries.

VS Code: <https://marketplace.visualstudio.com/items?itemName=Algol.taudit-vscode>

Azure Pipelines: <https://marketplace.visualstudio.com/items?itemName=Algol.taudit-azure-pipelines>

### Newsletter or blog opener

Secret scanners, Trivy, Terraform validation, TFLint, and JSON validators all
catch important slices of CI/CD risk. They do not answer the graph question:
which pipeline step can influence which authority-bearing step later?

taudit fills that gap. It turns GitHub Actions, Azure Pipelines, GitLab CI, and
Bitbucket Pipelines into typed authority graphs, then lets teams scan, verify,
and render those graphs from the editor or from Azure Pipelines.

Start in Visual Studio Marketplace:

- VS Code extension for local review and graph artifacts
- Azure Pipelines task for `Taudit@1` merge gates

### Internal enablement note

We are starting taudit adoption through Visual Studio Marketplace.

Install the VS Code extension if you review CI/CD changes locally. Install the
Azure Pipelines task if you own Azure DevOps merge gates. The first path to try
is `verify`: point taudit at a repo-local policy directory and the pipeline
YAML files you want to protect.

Treat partial modeling notes as review focus areas, not as automatic failure
and not as a clean bill of health. taudit preserves uncertainty when templates,
runtime expressions, or variable groups cannot be fully resolved.

## Proof points to use

- Graph-first analysis of CI/CD authority propagation.
- Works across GitHub Actions, Azure Pipelines, GitLab CI, and Bitbucket
  Pipelines.
- VS Code extension exposes typed commands instead of raw shell passthrough.
- Azure Pipelines task exposes typed inputs and runs a pinned taudit release
  asset on the agent.
- `verify` can act as a policy gate; `scan` stays advisory; `graph` produces
  authority or exploit-candidate artifacts for review.
- Baselines, suppressions, ignore files, and policy are separate controls.

## Do not say

- Do not say taudit replaces secret scanning, Trivy, TFLint, Terraform
  validation, ADF JSON validation, or platform YAML linters.
- Do not say a clean taudit run proves a pipeline is safe.
- Do not say partial analysis is a failure.
- Do not imply taudit performs runtime cloud permission resolution.

Preferred wording:

```text
taudit adds the CI/CD authority-graph layer that other scanners do not cover.
```

```text
Partial graph output is a review focus area: taudit is telling you where the
model preserved uncertainty.
```

## Follow-up proof assets

Marketing should ask product/engineering for these assets before a wider push:

- one VS Code `Verify Workspace` screenshot
- one VS Code authority graph screenshot
- one Azure Pipelines `Taudit@1` successful run screenshot
- one Azure Pipelines graph artifact screenshot
- one short first-use demo clip showing install, policy initialization, verify,
  and graph output

Canonical shot plan: [`../integrations/marketplace-media-shot-list.md`](../integrations/marketplace-media-shot-list.md).
