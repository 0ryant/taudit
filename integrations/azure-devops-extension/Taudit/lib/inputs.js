"use strict";

const MODE_FORMATS = {
  scan: ["terminal", "json", "sarif", "cloudevents"],
  verify: ["text", "json", "sarif"],
  graph: ["json", "dot", "mermaid", "summary"]
};

const ENUMS = {
  mode: ["verify", "scan", "graph"],
  platform: ["auto", "github-actions", "azure-devops", "gitlab", "bitbucket"],
  suppressionMode: ["downgrade", "tag-only"],
  graphView: ["authority", "exploit"],
  severityThreshold: ["critical", "high", "medium", "low", "info"]
};

function normalizeInputs(raw, env) {
  const normalized = {
    mode: raw.mode || "verify",
    version: raw.version || "1.1.4",
    paths: raw.paths || "azure-pipelines.yml",
    platform: raw.platform || "auto",
    suppressionMode: raw.suppressionMode || "downgrade",
    graphView: raw.graphView || "authority",
    noColor: raw.noColor == null ? true : parseBoolean("noColor", raw.noColor),
    cwd: env.SYSTEM_DEFAULTWORKINGDIRECTORY || env.BUILD_SOURCESDIRECTORY || process.cwd()
  };

  copyString(raw, normalized, "adoOrg");
  copyString(raw, normalized, "adoProject");
  copyString(raw, normalized, "policy");
  copyString(raw, normalized, "ignoreFile");
  copyString(raw, normalized, "suppressions");
  copyString(raw, normalized, "baselineRoot");
  copyString(raw, normalized, "format");
  copyString(raw, normalized, "output");
  copyString(raw, normalized, "severityThreshold");

  normalized.adoPat = raw.adoPat || env.TAUDIT_ADO_PAT || "";
  normalized.includeBuiltin = parseOptionalBoolean("includeBuiltin", raw.includeBuiltin);
  normalized.gateOnAll = parseOptionalBoolean("gateOnAll", raw.gateOnAll);
  normalized.strict = parseOptionalBoolean("strict", raw.strict);
  normalized.ignorePartial = parseOptionalBoolean("ignorePartial", raw.ignorePartial);
  normalized.fallbackCargo = parseOptionalBoolean("fallbackCargo", raw.fallbackCargo);

  if (raw.maxHops != null && String(raw.maxHops).trim() !== "") {
    normalized.maxHops = parsePositiveInteger("maxHops", raw.maxHops);
  }

  validateEnums(normalized);
  validateModeFormat(normalized);
  validateVerifyPolicy(normalized);
  validatePathLikeInputs(normalized);
  return normalized;
}

function splitPaths(value) {
  return String(value || "")
    .split(/\r?\n/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function copyString(raw, normalized, key) {
  if (raw[key] == null) {
    return;
  }
  const value = String(raw[key]).trim();
  if (value !== "") {
    normalized[key] = value;
  }
}

function validateEnums(input) {
  for (const [key, values] of Object.entries(ENUMS)) {
    if (input[key] && !values.includes(input[key])) {
      throw new Error(`invalid ${key}: expected one of ${values.join(", ")}`);
    }
  }
}

function validateModeFormat(input) {
  if (!input.format) {
    return;
  }
  const values = MODE_FORMATS[input.mode] || [];
  if (!values.includes(input.format)) {
    throw new Error(`invalid format for ${input.mode}: expected one of ${values.join(", ")}`);
  }
}

function validateVerifyPolicy(input) {
  if (input.mode === "verify" && !input.policy) {
    throw new Error("policy is required for verify mode");
  }
}

function validatePathLikeInputs(input) {
  for (const entry of splitPaths(input.paths)) {
    validateWorkspacePath("paths", entry, false);
  }
  for (const key of ["policy", "ignoreFile", "suppressions", "baselineRoot", "output"]) {
    if (input[key]) {
      validateWorkspacePath(key, input[key], {
        isOutput: key === "output",
        baselineRoot: key === "baselineRoot"
      });
    }
  }
}

function validateWorkspacePath(name, value, options = {}) {
  const { isOutput = false, baselineRoot = false } = options;
  const path = String(value);
  if (path.includes("\0") || path.includes("\n") || path.includes("\r")) {
    throw new Error(`${name} must be a single workspace-relative path`);
  }
  if (/^\$\([^)]+\)(?:[\\/].*)?$/.test(path)) {
    if (baselineRoot) {
      throw new Error("baselineRoot must be workspace-relative (for example '.' or '.taudit'); do not pass $(System.DefaultWorkingDirectory) or an absolute path");
    }
    throw new Error(`${name} must be workspace-relative; do not pass $(System.DefaultWorkingDirectory) or other Azure DevOps path variables`);
  }
  if (path.startsWith("/") || /^[A-Za-z]:[\\/]/.test(path)) {
    if (baselineRoot) {
      throw new Error("baselineRoot must be workspace-relative (for example '.' or '.taudit'); do not pass $(System.DefaultWorkingDirectory) or an absolute path");
    }
    throw new Error(`${name} must be workspace-relative`);
  }
  const segments = path.split(/[\\/]+/).filter(Boolean);
  if (segments.includes("..")) {
    throw new Error(`${name} must not traverse outside the workspace`);
  }
  if (isOutput && (segments[0] === ".git" || (segments[0] === ".github" && segments[1] === "workflows"))) {
    throw new Error("output must not target repository control or workflow files");
  }
}

function parseOptionalBoolean(name, value) {
  if (value == null || String(value).trim() === "") {
    return false;
  }
  return parseBoolean(name, value);
}

function parseBoolean(name, value) {
  const lower = String(value).trim().toLowerCase();
  if (lower === "true") {
    return true;
  }
  if (lower === "false") {
    return false;
  }
  throw new Error(`invalid boolean for ${name}: expected true or false`);
}

function parsePositiveInteger(name, value) {
  const text = String(value).trim();
  const parsed = Number.parseInt(text, 10);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 10000 || String(parsed) !== text) {
    throw new Error(`invalid ${name}: expected integer between 1 and 10000`);
  }
  return parsed;
}

module.exports = {
  normalizeInputs,
  splitPaths
};
