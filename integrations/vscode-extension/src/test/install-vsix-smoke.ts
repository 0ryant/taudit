import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
import {
  downloadAndUnzipVSCode,
  resolveCliArgsFromVSCodeExecutablePath,
} from "@vscode/test-electron";

interface ExtensionPackage {
  publisher: string;
  name: string;
  version: string;
}

async function main(): Promise<void> {
  const extensionRoot = path.resolve(__dirname, "..", "..");
  const packageJsonPath = path.join(extensionRoot, "package.json");
  const vsixPath = path.join(extensionRoot, "taudit-vscode.vsix");

  assert.ok(fs.existsSync(packageJsonPath), `Missing package.json: ${packageJsonPath}`);
  assert.ok(fs.existsSync(vsixPath), `Missing VSIX package: ${vsixPath}`);

  const extensionPackage = JSON.parse(
    fs.readFileSync(packageJsonPath, "utf8"),
  ) as ExtensionPackage;
  const extensionId = `${extensionPackage.publisher}.${extensionPackage.name}`;
  const expectedListing = `${extensionId}@${extensionPackage.version}`;

  const vscodeExecutablePath = await downloadAndUnzipVSCode("stable");
  const [cli, ...cliArgs] = resolveCliArgsFromVSCodeExecutablePath(
    vscodeExecutablePath,
  );

  runCli(cli, [...cliArgs, "--install-extension", vsixPath, "--force"]);

  const listResult = runCli(cli, [
    ...cliArgs,
    "--list-extensions",
    "--show-versions",
  ]);
  assert.match(
    listResult.stdout,
    new RegExp(`^${escapeRegex(expectedListing)}$`, "m"),
    `Installed extension list should contain ${expectedListing}`,
  );

  runCli(cli, [...cliArgs, "--uninstall-extension", extensionId]);
}

function runCli(
  cli: string,
  args: string[],
): {
  stdout: string;
  stderr: string;
} {
  const result = spawnSync(cli, args, {
    encoding: "utf8",
    shell: process.platform === "win32",
  });

  if (result.status !== 0) {
    const stderr = result.stderr?.trim() ?? "";
    const stdout = result.stdout?.trim() ?? "";
    throw new Error(
      `VS Code CLI failed (${result.status ?? "unknown"}): ${[stdout, stderr]
        .filter((value) => value.length > 0)
        .join("\n")}`,
    );
  }

  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
