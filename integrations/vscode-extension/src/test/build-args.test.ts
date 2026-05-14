import { test } from "node:test";
import assert from "node:assert/strict";
import { artifactExtension, buildArgs, GraphRequest, ScanRequest, VerifyRequest } from "../runner";

test("verify args include policy and controls", () => {
  const request: VerifyRequest = {
    mode: "verify",
    binaryPath: "taudit",
    platform: "github-actions",
    targets: ["/repo/.github/workflows"],
    cwd: "/repo",
    maxHops: 7,
    severityThreshold: "high",
    ignoreFile: "/repo/.tauditignore",
    suppressionsFile: "/repo/.taudit-suppressions.yml",
    suppressionMode: "tag-only",
    baselineRoot: "/repo",
    policyPath: "/repo/.taudit/policy",
    includeBuiltin: true,
    ignorePartial: true,
    format: "sarif",
  };

  assert.deepEqual(buildArgs(request, "/tmp/report.sarif"), [
    "verify",
    "--platform",
    "github-actions",
    "--max-hops",
    "7",
    "--severity-threshold",
    "high",
    "--ignore-file",
    "/repo/.tauditignore",
    "--suppressions",
    "/repo/.taudit-suppressions.yml",
    "--suppression-mode",
    "tag-only",
    "--baseline-root",
    "/repo",
    "--policy",
    "/repo/.taudit/policy",
    "--format",
    "sarif",
    "--include-builtin",
    "--ignore-partial",
    "--no-color",
    "--output",
    "/tmp/report.sarif",
    "/repo/.github/workflows",
  ]);
});

test("graph args never include output flag", () => {
  const request: GraphRequest = {
    mode: "graph",
    binaryPath: "taudit",
    platform: "auto",
    targets: ["/repo/.github/workflows/release.yml"],
    cwd: "/repo",
    maxHops: 4,
    format: "mermaid",
    view: "exploit",
  };

  assert.deepEqual(buildArgs(request, "/tmp/graph.mmd"), [
    "graph",
    "--platform",
    "auto",
    "--max-hops",
    "4",
    "--format",
    "mermaid",
    "--view",
    "exploit",
    "/repo/.github/workflows/release.yml",
  ]);
});

test("scan artifact extension tracks selected format", () => {
  const request: ScanRequest = {
    mode: "scan",
    binaryPath: "taudit",
    platform: "auto",
    targets: ["/repo/.github/workflows"],
    cwd: "/repo",
    maxHops: 4,
    format: "cloudevents",
  };

  assert.equal(artifactExtension(request), ".jsonl");
});
