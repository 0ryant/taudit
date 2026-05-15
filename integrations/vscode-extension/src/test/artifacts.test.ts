import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { existingArtifactPath } from "../artifacts";

test("existingArtifactPath returns undefined for missing artifacts", async () => {
  const missing = path.join(os.tmpdir(), "taudit-vscode-missing-artifact.txt");
  assert.equal(await existingArtifactPath(missing), undefined);
});

test("existingArtifactPath returns the path for present artifacts", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "taudit-vscode-artifact-"));
  const artifactPath = path.join(tempDir, "result.json");
  await fs.writeFile(artifactPath, "{}\n", "utf8");

  assert.equal(await existingArtifactPath(artifactPath), artifactPath);
});
