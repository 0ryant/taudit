"use strict";

function parseStructuredOutput(stdout, outputPath) {
  const direct = parseJson(stdout);
  if (direct) {
    return direct;
  }
  if (!outputPath) {
    return undefined;
  }
  try {
    const text = require("node:fs").readFileSync(outputPath, "utf8");
    return parseJson(text);
  } catch {
    return undefined;
  }
}

function parseJson(text) {
  const trimmed = String(text || "").trim();
  if (!trimmed.startsWith("{")) {
    return undefined;
  }
  try {
    return JSON.parse(trimmed);
  } catch {
    return undefined;
  }
}

function outcomeFor(exitCode) {
  if (exitCode === 0) {
    return "pass";
  }
  if (exitCode === 1) {
    return "violations";
  }
  return "config-error";
}

module.exports = {
  outcomeFor,
  parseStructuredOutput
};
