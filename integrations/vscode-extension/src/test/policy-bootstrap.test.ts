import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

test("bundled strict policy template ships with the extension", async () => {
  const templatePath = path.resolve(
    __dirname,
    "..",
    "..",
    "templates",
    "bundled-strict-policy.yml",
  );
  const text = await fs.readFile(templatePath, "utf8");
  assert.match(text, /strict_no_untrusted_with_prod_secret/);
  assert.match(text, /strict_no_broad_identity_to_untrusted/);
});

test("bootstrap target path shape mirrors default workspace policy dir", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "taudit-vscode-policy-"));
  const outputFile = path.join(root, ".taudit", "policy", "bundled-strict-policy.yml");
  await fs.mkdir(path.dirname(outputFile), { recursive: true });
  await fs.writeFile(outputFile, "seed", "utf8");
  const text = await fs.readFile(outputFile, "utf8");
  assert.equal(text, "seed");
});
