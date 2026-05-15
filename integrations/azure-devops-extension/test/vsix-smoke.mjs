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

test("packaged VSIX contains task runtime dependencies", () => {
  const listing = execFileSync("unzip", ["-l", vsixPath], {
    cwd: extensionRoot,
    encoding: "utf8",
  });

  assert.match(listing, /Taudit\/task\.json/);
  assert.match(listing, /Taudit\/index\.js/);
  assert.match(listing, /Taudit\/node_modules\/azure-pipelines-task-lib\//);
});
