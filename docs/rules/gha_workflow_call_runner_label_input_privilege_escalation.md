# GHA Reusable Callee Runner Label From Caller Input

**Rule ID:** `gha_workflow_call_runner_label_input_privilege_escalation`
**Severity:** High
**Category:** Trust
**Tags:** security, authority-confusion, github-actions, runner

## Detection

Fires when a `workflow_call` workflow defines an input bound to runner selection (`runner`, `runs-on`, `runner-vm-os`, `runner-label`, `os`) and a job sets `runs-on: ${{ inputs.<that> }}` (including `runs-on: ${{ fromJson(inputs.runs_on_labels) }}`), and the job has credential-bearing secrets, `id-token: write`, PAT-based checkout, or any publish/deploy authority.

## Risk

A caller that controls the runner label can route a privileged callable workflow onto an unintended runner pool. If the callable's value chain includes a self-hosted runner label, the caller can pin the job to a self-hosted runner under different trust assumptions than the callable's owners intended (workspace persistence, prior credential residue, neighbor-job interaction, custom tooling). Even within hosted runners, the caller can choose between Linux/macOS/Windows in a way that may bypass platform-specific protections the callable relied on.

## Remediation

Constrain the runner input to a closed enum and enforce the constraint with an `if:` gate before the privileged job runs. Where possible, hardcode `runs-on:` in the callable. Never accept caller input that can name a self-hosted label inside a callable that inherits secrets.
