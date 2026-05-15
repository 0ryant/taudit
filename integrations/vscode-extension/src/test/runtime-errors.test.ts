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
