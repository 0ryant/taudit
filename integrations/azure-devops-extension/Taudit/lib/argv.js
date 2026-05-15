"use strict";

const { splitPaths } = require("./inputs");

function buildArgv(input) {
  const argv = [input.mode];

  addPair(argv, "--platform", input.platform || "auto");
  addPair(argv, "--ado-org", input.adoOrg);
  addPair(argv, "--ado-project", input.adoProject);
  addPair(argv, "--max-hops", input.maxHops == null ? undefined : String(input.maxHops));

  if (input.mode === "verify") {
    addPair(argv, "--policy", input.policy);
    addFlag(argv, "--include-builtin", input.includeBuiltin);
    addFlag(argv, "--gate-on-all", input.gateOnAll);
    addFlag(argv, "--strict", input.strict);
    addFlag(argv, "--ignore-partial", input.ignorePartial);
  }

  if (input.mode === "graph") {
    addPair(argv, "--view", input.graphView || "authority");
    addPair(argv, "--format", input.format);
  } else {
    addPair(argv, "--ignore-file", input.ignoreFile);
    addPair(argv, "--suppressions", input.suppressions);
    addPair(argv, "--suppression-mode", input.suppressionMode);
    addPair(argv, "--baseline-root", input.baselineRoot);
    addPair(argv, "--format", input.format);
    addPair(argv, "--severity-threshold", input.severityThreshold);
    addFlag(argv, "--no-color", input.noColor);
    addPair(argv, "--output", input.output);
  }

  argv.push("--");
  argv.push(...splitPaths(input.paths));
  return argv;
}

function addPair(argv, flag, value) {
  if (value == null || value === "") {
    return;
  }
  argv.push(flag, String(value));
}

function addFlag(argv, flag, enabled) {
  if (enabled) {
    argv.push(flag);
  }
}

module.exports = {
  buildArgv
};
