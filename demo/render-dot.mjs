import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import { instance } from "@viz-js/viz";

async function main() {
  const [, , inputPath, outputPath] = process.argv;

  if (!inputPath || !outputPath) {
    throw new Error("Usage: node render-dot.mjs <input.dot> <output.svg>");
  }

  const dotSource = await readFile(inputPath, "utf8");
  const viz = await instance();
  const svg = viz.renderString(dotSource, {
    engine: "dot",
    format: "svg",
  });

  if (typeof svg !== "string") {
    throw new Error("Graph renderer did not return SVG text.");
  }

  await mkdir(path.dirname(outputPath), { recursive: true });
  await writeFile(outputPath, svg, "utf8");
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exit(1);
});