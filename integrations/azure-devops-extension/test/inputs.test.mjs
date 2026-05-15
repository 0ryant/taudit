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

test("ado context flags are forwarded independently for CLI parity", () => {
  const input = normalizeInputs({
    mode: "scan",
    paths: "azure-pipelines.yml",
    adoOrg: "0ryant",
    adoProject: "taudit"
  }, {});

  assert.equal(input.adoOrg, "0ryant");
  assert.equal(input.adoProject, "taudit");
  assert.equal(input.adoPat, "");
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

test("verify relativizes workspace-absolute policy paths from Azure Pipelines", () => {
  const input = normalizeInputs({
    mode: "verify",
    paths: "azure-pipelines.yml",
    policy: "/home/vsts/work/1/s/taudit/policy"
  }, {
    SYSTEM_DEFAULTWORKINGDIRECTORY: "/home/vsts/work/1/s"
  });

  assert.equal(input.policy, "taudit/policy");
});

test("graph ignores spurious policy values from filePath-style coercion", () => {
  const input = normalizeInputs({
    mode: "graph",
    paths: "azure-pipelines.yml",
    policy: "/home/vsts/work/1/s"
  }, {
    SYSTEM_DEFAULTWORKINGDIRECTORY: "/home/vsts/work/1/s"
  });

  assert.equal(input.policy, undefined);
});

test("optional file-like inputs drop workspace-root coercions", () => {
  const input = normalizeInputs({
    mode: "scan",
    paths: "azure-pipelines.yml",
    ignoreFile: "/home/vsts/work/1/s",
    suppressions: "/home/vsts/work/1/s",
    baselineRoot: "/home/vsts/work/1/s"
  }, {
    SYSTEM_DEFAULTWORKINGDIRECTORY: "/home/vsts/work/1/s"
  });

  assert.equal(input.ignoreFile, undefined);
  assert.equal(input.suppressions, undefined);
  assert.equal(input.baselineRoot, undefined);
});

test("explicit relative baselineRoot dot is preserved", () => {
  const input = normalizeInputs({
    mode: "scan",
    paths: "azure-pipelines.yml",
    baselineRoot: "."
  }, {
    SYSTEM_DEFAULTWORKINGDIRECTORY: "/home/vsts/work/1/s"
  });

  assert.equal(input.baselineRoot, ".");
});
