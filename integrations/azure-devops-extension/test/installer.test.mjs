import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const {
  normalizeVersion,
  installedBinaryPath,
} = require("../Taudit/lib/installer");

test("normalizeVersion strips a leading v only once", () => {
  assert.equal(normalizeVersion("v1.1.4"), "1.1.4");
  assert.equal(normalizeVersion("1.1.4"), "1.1.4");
});

test("installedBinaryPath is workspace-local and version-normalized", () => {
  const resolved = installedBinaryPath("/repo", "v1.1.4");
  const expectedName = process.platform === "win32" ? "taudit.exe" : "taudit";
  assert.equal(
    resolved,
    path.join("/repo", ".taudit-tools", "bin", "1.1.4", expectedName),
  );
});
