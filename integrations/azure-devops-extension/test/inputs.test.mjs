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
