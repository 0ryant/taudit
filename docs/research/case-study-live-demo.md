# Case study live demo — public workflows × taudit

This page turns three well-known public incidents or reference pipelines into a **reproducible** `taudit scan` demo. Fixtures live under `docs/research/fixtures/` (pinned commits or `main` as noted).

## Prerequisites

```bash
cargo build -p taudit
TAUDIT=./target/debug/taudit   # or `taudit` after install
```

Summarise rule IDs (categories) from JSON:

```bash
$TAUDIT scan path/to/workflow.yml --format json \
  | jq -r '.findings[]?.category' | sort | uniq -c | sort -rn
```

## 1. Ultralytics `format.yml` (historic `pull_request_target`)

**Why two files?** On current `main`, Ultralytics uses `pull_request` (safer default than the 2024 incident window). The supply-chain write-up and Praetorian-style “pwn request” narrative still applies to the **historic** workflow that used `pull_request_target`.

| Fixture | Source |
|--------|--------|
| `fixtures/ultralytics-format-cb260c2-prt.yml` | `ultralytics/ultralytics` @ `cb260c243ffa3e0cc84820095cd88be2f5db86ca` — includes `pull_request_target` |
| `fixtures/ultralytics-format-main-branch.yml` | `ultralytics/ultralytics` `main` @ fetch date — `pull_request` + `contents: write` |

**Representative rule IDs** (PRT fixture, `taudit` built from this repo):

| Category | Role in narrative |
|----------|-------------------|
| `untrusted_with_authority` | Privileged token / secrets adjacent to untrusted execution surface |
| `authority_propagation` | Authority flows into lower-trust steps |
| `pr_trigger_with_floating_action_ref` | `uses: ultralytics/actions@main` — mutable ref under PR-class trigger |
| `no_workflow_level_permissions_block` | Broad defaults before explicit `permissions:` (historic file shape) |
| `unpinned_action` | Third-party action not pinned to digest |
| `long_lived_credential` | PAT-style or long-lived secret material in workflow inputs |

The **main-branch** fixture still yields criticals (e.g. `untrusted_with_authority`, `authority_propagation`) because wide `permissions:` + secrets passed into a third-party action is a high blast-radius pattern even without `pull_request_target`.

## 2. Rspack `release-canary.yml`

| Fixture | Source |
|--------|--------|
| `fixtures/rspack-release-canary.yml` | `web-infra-dev/rspack` `main` — scheduled + `workflow_dispatch` canary pipeline |

**Representative rule IDs:**

| Category | Role in narrative |
|----------|-------------------|
| `cross_workflow_authority_chain` | Reusable workflows (`uses: ./.github/workflows/...`) chain identity across jobs |
| `untrusted_with_authority` | Dispatch inputs (`commit`, `profile`, …) feed refs / commands |
| `authority_propagation` | `id-token: write` and other privileges propagate through the graph |
| `manual_dispatch_input_to_url_or_command` | Operator-supplied SHA / choice crossing into build |
| `unpinned_action` | Actions referenced by tag where the graph marks them unpinned |
| `over_privileged_identity` | Token / permissions broader than the narrow task |

This is **not** a `pull_request_target` story; it is a good second axis: **trusted-maintainer dispatch** and **reusable-workflow authority**.

## 3. Praetorian-style AI PR review (`gemini-code.yml`)

The research brief said “gpt-review”; the durable public caller we mirror is **`praetorian-inc/hadrian`**’s thin workflow that invokes **`praetorian-inc/public-workflows`** at a **full commit SHA** (hardened pattern).

| Fixture | Source |
|--------|--------|
| `fixtures/praetorian-gemini-code.yml` | `praetorian-inc/hadrian` `main` |

**Representative rule IDs:**

| Category | Role in narrative |
|----------|-------------------|
| `cross_workflow_authority_chain` | Caller → reusable workflow boundary |
| `risky_trigger_with_authority` | `pull_request_review_comment` re-fires on untrusted comment stream |
| `authority_propagation` | Secrets (`GEMINI_API_KEY`) cross into reusable callee |
| `over_privileged_identity` | `pull-requests: write` scope |

Despite SHA pinning and an explicit fork gate in `if:`, taudit still reports **propagation** and **trigger/authority** findings — useful to show the difference between “marketing secure” and “graph-precise”.

## Re-run after updating fixtures

```bash
curl -fsSL -o docs/research/fixtures/rspack-release-canary.yml \
  "https://raw.githubusercontent.com/web-infra-dev/rspack/main/.github/workflows/release-canary.yml"
```

Re-scan and refresh the tables above if policy or parsers change.
