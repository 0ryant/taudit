import { test } from "node:test";
import assert from "node:assert/strict";
import { isSupportedPipelinePath } from "../pathing";

test("pipeline detector accepts yml and yaml", () => {
  assert.equal(isSupportedPipelinePath("/repo/.github/workflows/release.yml"), true);
  assert.equal(isSupportedPipelinePath("/repo/.github/workflows/release.yaml"), true);
});

test("pipeline detector rejects non-yaml files", () => {
  assert.equal(isSupportedPipelinePath("/repo/README.md"), false);
  assert.equal(isSupportedPipelinePath("/repo/workflow.json"), false);
});
