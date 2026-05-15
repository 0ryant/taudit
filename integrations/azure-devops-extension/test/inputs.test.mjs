import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { normalizeInputs } = require("../Taudit/lib/inputs");

test("verify requires policy", () => {
  assert.throws(
    () => normalizeInputs({ mode: "verify", paths: "azure-pipelines.yml" }, {}),
    /policy is required/
  );
});

test("ado enrichment requires all fields", () => {
  assert.throws(
    () => normalizeInputs({
      mode: "scan",
      paths: "azure-pipelines.yml",
      adoOrg: "0ryant",
      adoProject: "taudit"
    }, {}),
    /ADO enrichment requires adoPat/
  );
});

test("graph output path stays workspace relative", () => {
  const input = normalizeInputs({
    mode: "graph",
    paths: "azure-pipelines.yml",
    output: "reports/graph.dot"
  }, {});
  assert.equal(input.output, "reports/graph.dot");
});

test("baselineRoot rejects absolute ADO-style workspace paths with a direct message", () => {
  assert.throws(
    () => normalizeInputs({
      mode: "scan",
      paths: "azure-pipelines.yml",
      baselineRoot: "C:\\agent\\_work\\1\\s"
    }, {}),
    /baselineRoot must be workspace-relative .* do not pass \$\(System\.DefaultWorkingDirectory\)/
  );
});

test("baselineRoot rejects Azure DevOps macro paths with a direct message", () => {
  assert.throws(
    () => normalizeInputs({
      mode: "scan",
      paths: "azure-pipelines.yml",
      baselineRoot: "$(System.DefaultWorkingDirectory)"
    }, {}),
    /baselineRoot must be workspace-relative .* do not pass \$\(System\.DefaultWorkingDirectory\)/
  );
});

test("policy rejects Azure DevOps macro paths", () => {
  assert.throws(
    () => normalizeInputs({
      mode: "verify",
      paths: "azure-pipelines.yml",
      policy: "$(Build.SourcesDirectory)/.taudit/policy"
    }, {}),
    /policy must be workspace-relative; do not pass \$\(System\.DefaultWorkingDirectory\) or other Azure DevOps path variables/
  );
});
