import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const {
  normalizeVersion,
  installedBinaryPath,
  windowsExpandArchiveCandidates,
  escapePowerShellSingleQuoted,
} = require("../Taudit/lib/installer");

test("normalizeVersion strips a leading v only once", () => {
  assert.equal(normalizeVersion("v1.1.5"), "1.1.5");
  assert.equal(normalizeVersion("1.1.5"), "1.1.5");
});

test("installedBinaryPath is workspace-local and version-normalized", () => {
  const resolved = installedBinaryPath("/repo", "v1.1.5");
  const expectedName = process.platform === "win32" ? "taudit.exe" : "taudit";
  assert.equal(
    resolved,
    path.join("/repo", ".taudit-tools", "bin", "1.1.5", expectedName),
  );
});

test("windows extraction candidates import the archive module explicitly", () => {
  const candidates = windowsExpandArchiveCandidates("C:\\tmp\\taudit.zip", "C:\\repo\\.taudit-tools");
  assert.equal(candidates.length, 2);
  for (const candidate of candidates) {
    assert.match(candidate.args.join(" "), /Import-Module Microsoft\.PowerShell\.Archive -ErrorAction Stop/);
    assert.match(candidate.args.join(" "), /Expand-Archive -LiteralPath/);
  }
});

test("powershell single-quoted escaping doubles embedded quotes", () => {
  assert.equal(
    escapePowerShellSingleQuoted("C:\\tmp\\O'Brien\\taudit.zip"),
    "C:\\tmp\\O''Brien\\taudit.zip",
  );
});
