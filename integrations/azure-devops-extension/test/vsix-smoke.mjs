import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import packageJson from "../package.json" with { type: "json" };

const extensionRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const vsixPath = path.join(
  extensionRoot,
  "dist",
  `algol.taudit-azure-pipelines-${packageJson.version}.vsix`,
);

function tryList(command, args) {
  try {
    return execFileSync(command, args, {
      cwd: extensionRoot,
      encoding: "utf8",
    });
  } catch (error) {
    return { command, error };
  }
}

function listWithPowerShell(executable) {
  const script = [
    "$archive = [System.IO.Path]::GetFullPath($args[0])",
    "Add-Type -AssemblyName System.IO.Compression.FileSystem",
    "$zip = [System.IO.Compression.ZipFile]::OpenRead($archive)",
    "try { $zip.Entries | ForEach-Object { $_.FullName } } finally { $zip.Dispose() }",
  ].join("; ");

  return tryList(executable, ["-NoProfile", "-Command", script, vsixPath]);
}

function listVsixEntries() {
  const attempts = [
    ["unzip", ["-l", vsixPath]],
    ["tar", ["-tf", vsixPath]],
  ];

  for (const [command, args] of attempts) {
    const result = tryList(command, args);
    if (typeof result === "string") {
      return result;
    }
  }

  for (const executable of ["pwsh", "powershell"]) {
    const result = listWithPowerShell(executable);
    if (typeof result === "string") {
      return result;
    }
  }

  assert.fail("No archive listing command available for VSIX smoke test");
}

test("packaged VSIX contains task runtime dependencies", () => {
  const listing = listVsixEntries();

  assert.match(listing, /Taudit\/task\.json/);
  assert.match(listing, /Taudit\/index\.js/);
  assert.match(listing, /Taudit\/node_modules\/azure-pipelines-task-lib\//);
});
