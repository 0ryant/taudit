import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { buildArgv } = require("../Taudit/lib/argv");

test("buildArgv maps verify inputs deterministically", () => {
  const argv = buildArgv({
    mode: "verify",
    platform: "auto",
    policy: ".taudit/policy",
    includeBuiltin: true,
    gateOnAll: true,
    strict: true,
    ignorePartial: false,
    ignoreFile: ".tauditignore",
    suppressions: ".taudit/suppressions.yml",
    suppressionMode: "tag-only",
    baselineRoot: ".",
    format: "json",
    severityThreshold: "high",
    noColor: true,
    output: "taudit-report.json",
    paths: "azure-pipelines.yml\neng/pipeline.yml"
  });

  assert.deepEqual(argv, [
    "verify",
    "--platform", "auto",
    "--policy", ".taudit/policy",
    "--include-builtin",
    "--gate-on-all",
    "--strict",
    "--ignore-file", ".tauditignore",
    "--suppressions", ".taudit/suppressions.yml",
    "--suppression-mode", "tag-only",
    "--baseline-root", ".",
    "--format", "json",
    "--severity-threshold", "high",
    "--no-color",
    "--output", "taudit-report.json",
    "--",
    "azure-pipelines.yml",
    "eng/pipeline.yml"
  ]);
});

test("buildArgv keeps graph mode free of verify and scan flags", () => {
  const argv = buildArgv({
    mode: "graph",
    platform: "azure-devops",
    graphView: "exploit",
    format: "dot",
    ignoreFile: ".tauditignore",
    suppressions: ".taudit/suppressions.yml",
    suppressionMode: "tag-only",
    baselineRoot: ".",
    severityThreshold: "high",
    noColor: true,
    output: "graph.dot",
    paths: "azure-pipelines.yml"
  });

  assert.deepEqual(argv, [
    "graph",
    "--platform", "azure-devops",
    "--view", "exploit",
    "--format", "dot",
    "--",
    "azure-pipelines.yml"
  ]);
});
