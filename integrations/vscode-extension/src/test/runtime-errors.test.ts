import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  VerifyRequest,
  runTaudit,
  validateRequest,
} from "../runner";

test("validateRequest rejects an explicit missing taudit binary path", async () => {
  const request = makeVerifyRequest({
    binaryPath: path.join(os.tmpdir(), "taudit-vscode-missing-binary"),
  });

  assert.equal(
    await validateRequest(request),
    `Configured taudit binary path does not exist: ${request.binaryPath}`,
  );
});

test("validateRequest rejects a missing verify policy path before execution", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "taudit-vscode-"));
  const request = makeVerifyRequest({
    cwd: tempDir,
    targets: [tempDir],
    policyPath: path.join(tempDir, ".taudit", "policy"),
  });

  assert.equal(
    await validateRequest(request),
    `Configured taudit verify policy path does not exist: ${request.policyPath}`,
  );
});

test("validateRequest rejects verify policy paths that escape the workspace", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "taudit-vscode-"));
  const outsidePolicy = path.join(os.tmpdir(), "taudit-vscode-outside-policy");
  await fs.mkdir(outsidePolicy, { recursive: true });

  const request = makeVerifyRequest({
    cwd: tempDir,
    targets: [tempDir],
    policyPath: outsidePolicy,
  });

  assert.equal(
    await validateRequest(request),
    `Configured taudit verify policy path must stay inside the workspace: ${outsidePolicy}`,
  );
});

test("validateRequest rejects workflow targets that escape the workspace", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "taudit-vscode-"));
  const outsideTarget = path.join(os.tmpdir(), "taudit-vscode-outside.yml");
  await fs.writeFile(outsideTarget, "name: outside\n", "utf8");
  const policyDir = path.join(tempDir, ".taudit", "policy");
  await fs.mkdir(policyDir, { recursive: true });

  const request = makeVerifyRequest({
    cwd: tempDir,
    targets: [outsideTarget],
    policyPath: policyDir,
  });

  assert.equal(
    await validateRequest(request),
    `Configured taudit workflow path must stay inside the workspace: ${outsideTarget}`,
  );
});

test("validateRequest rejects invalid severityThreshold values before execution", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "taudit-vscode-"));
  const policyDir = path.join(tempDir, ".taudit", "policy");
  await fs.mkdir(policyDir, { recursive: true });

  const request = makeVerifyRequest({
    cwd: tempDir,
    targets: [tempDir],
    policyPath: policyDir,
    severityThreshold: "bogus",
  });

  assert.equal(
    await validateRequest(request),
    "Configured taudit severityThreshold must be one of critical, high, medium, low, or info.",
  );
});

test("validateRequest rejects non-integer maxHops values before execution", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "taudit-vscode-"));
  const policyDir = path.join(tempDir, ".taudit", "policy");
  await fs.mkdir(policyDir, { recursive: true });

  const request = makeVerifyRequest({
    cwd: tempDir,
    targets: [tempDir],
    policyPath: policyDir,
    maxHops: 2.5,
  });

  assert.equal(
    await validateRequest(request),
    "Configured taudit maxHops must be a positive integer.",
  );
});

test("runTaudit surfaces a missing PATH binary as a start failure", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "taudit-vscode-"));
  const policyDir = path.join(tempDir, ".taudit", "policy");
  await fs.mkdir(policyDir, { recursive: true });

  const request = makeVerifyRequest({
    binaryPath: "taudit-vscode-definitely-missing",
    cwd: tempDir,
    targets: [tempDir],
    policyPath: policyDir,
  });

  await assert.rejects(
    () => runTaudit(request, path.join(tempDir, "taudit-verify.json")),
    (error) =>
      error instanceof Error &&
      "code" in error &&
      error.code === "ENOENT",
  );
});

function makeVerifyRequest(
  overrides: Partial<VerifyRequest> = {},
): VerifyRequest {
  return {
    mode: "verify",
    binaryPath: "taudit",
    platform: "auto",
    targets: ["/repo/.github/workflows"],
    cwd: "/repo",
    maxHops: 4,
    policyPath: "/repo/.taudit/policy",
    includeBuiltin: false,
    ignorePartial: false,
    format: "json",
    ...overrides,
  };
}
