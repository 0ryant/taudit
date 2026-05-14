import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";
import type { TauditExtensionApi } from "../../extension";

export async function run(): Promise<void> {
  const extension = vscode.extensions.getExtension<TauditExtensionApi>(
    "algol.taudit-vscode",
  );
  assert.ok(extension, "Extension should be discoverable in the extension host");

  await extension.activate();
  const api = extension.exports;
  assert.ok(api, "Extension API should be available after activation");

  const commands = await vscode.commands.getCommands(true);
  for (const command of [
    "taudit.verifyWorkspace",
    "taudit.scanWorkspace",
    "taudit.scanFile",
    "taudit.graphAuthority",
    "taudit.graphExploit",
    "taudit.showOutput",
  ]) {
    assert.ok(commands.includes(command), `Missing command: ${command}`);
  }

  const repoRoot = getRepoRoot();
  const tauditBinaryPath = path.join(repoRoot, "target", "debug", "taudit");
  assert.ok(
    fs.existsSync(tauditBinaryPath),
    `Expected built taudit binary at ${tauditBinaryPath}`,
  );

  const config = vscode.workspace.getConfiguration("taudit");
  await config.update("binaryPath", tauditBinaryPath, vscode.ConfigurationTarget.Global);
  await config.update("platform", "github-actions", vscode.ConfigurationTarget.Global);
  await config.update(
    "workflowPaths",
    ["tests/fixtures/clean.yml"],
    vscode.ConfigurationTarget.Global,
  );
  await config.update(
    "verify.policyPath",
    "tests/fixtures/verify-golden-noop-policy.yml",
    vscode.ConfigurationTarget.Global,
  );
  await config.update("verify.format", "json", vscode.ConfigurationTarget.Global);
  await config.update("scan.format", "json", vscode.ConfigurationTarget.Global);
  await config.update("graph.format", "mermaid", vscode.ConfigurationTarget.Global);

  const cleanFixture = path.join(repoRoot, "tests", "fixtures", "clean.yml");
  const doc = await vscode.workspace.openTextDocument(cleanFixture);
  await vscode.window.showTextDocument(doc);

  await vscode.commands.executeCommand("taudit.scanWorkspace");
  assertArtifactExists(api.getLastArtifactPath(), "scanWorkspace");

  await vscode.commands.executeCommand("taudit.verifyWorkspace");
  assertArtifactExists(api.getLastArtifactPath(), "verifyWorkspace");

  await vscode.commands.executeCommand("taudit.graphAuthority");
  assertArtifactExists(api.getLastArtifactPath(), "graphAuthority");

  await vscode.commands.executeCommand("taudit.graphExploit");
  assertArtifactExists(api.getLastArtifactPath(), "graphExploit");

  await vscode.commands.executeCommand("taudit.scanFile");
  assertArtifactExists(api.getLastArtifactPath(), "scanFile");
}

function getRepoRoot(): string {
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  assert.ok(workspaceFolder, "Expected repo workspace to be opened for integration tests");
  return workspaceFolder.uri.fsPath;
}

function assertArtifactExists(
  artifactPath: string | undefined,
  label: string,
): void {
  assert.ok(artifactPath, `${label} should set a last artifact path`);
  assert.ok(fs.existsSync(artifactPath), `${label} artifact should exist: ${artifactPath}`);
}
