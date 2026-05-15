"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const tl = require("azure-pipelines-task-lib/task");
const { buildArgv } = require("./lib/argv");
const { normalizeInputs } = require("./lib/inputs");
const { resolveTaudit } = require("./lib/installer");
const { outcomeFor, parseStructuredOutput } = require("./lib/results");

const execFileAsync = promisify(execFile);

async function main() {
  try {
    const input = normalizeInputs(readTaskInputs(), process.env);
    if (input.adoPat) {
      tl.setSecret(input.adoPat);
    }

    const tauditPath = await resolveTaudit(input);
    const argv = buildArgv(input);
    const outputPath = input.output ? path.join(input.cwd, input.output) : "";
    if (outputPath) {
      await fs.mkdir(path.dirname(outputPath), { recursive: true });
    }

    const result = await runTaudit(tauditPath, argv, input, outputPath);
    const parsed = parseStructuredOutput(result.stdout, outputPath);
    const outcome = outcomeFor(result.exitCode);

    setOutputVariable("taudit.exitCode", String(result.exitCode));
    setOutputVariable("taudit.outcome", outcome);
    setOutputVariable("taudit.reportPath", outputPath);
    setOutputVariable("taudit.tauditVersion", input.version);
    if (parsed && parsed.findings) {
      setOutputVariable("taudit.findingsCount", String(parsed.findings.length));
    }

    logSummary(input, tauditPath, result.exitCode, outcome, outputPath);

    if (result.exitCode === 0) {
      tl.setResult(tl.TaskResult.Succeeded, `taudit ${input.mode} passed`);
      return;
    }

    const stderr = result.stderr.trim();
    const reason = stderr || `taudit ${input.mode} exited ${result.exitCode}`;
    tl.setResult(tl.TaskResult.Failed, reason);
  } catch (error) {
    tl.setResult(tl.TaskResult.Failed, error.message || String(error));
  }
}

function readTaskInputs() {
  return {
    mode: tl.getInput("mode", false),
    version: tl.getInput("version", false),
    paths: tl.getInput("paths", false),
    platform: tl.getInput("platform", false),
    adoOrg: tl.getInput("adoOrg", false),
    adoProject: tl.getInput("adoProject", false),
    adoPat: tl.getInput("adoPat", false),
    policy: tl.getInput("policy", false),
    includeBuiltin: tl.getInput("includeBuiltin", false),
    ignoreFile: tl.getInput("ignoreFile", false),
    suppressions: tl.getInput("suppressions", false),
    suppressionMode: tl.getInput("suppressionMode", false),
    baselineRoot: tl.getInput("baselineRoot", false),
    gateOnAll: tl.getInput("gateOnAll", false),
    strict: tl.getInput("strict", false),
    ignorePartial: tl.getInput("ignorePartial", false),
    format: tl.getInput("format", false),
    output: tl.getInput("output", false),
    graphView: tl.getInput("graphView", false),
    severityThreshold: tl.getInput("severityThreshold", false),
    maxHops: tl.getInput("maxHops", false),
    noColor: tl.getInput("noColor", false),
    fallbackCargo: tl.getInput("fallbackCargo", false)
  };
}

async function runTaudit(binary, argv, input, outputPath) {
  const env = input.adoPat ? { ...process.env, TAUDIT_ADO_PAT: input.adoPat } : process.env;
  try {
    const { stdout = "", stderr = "" } = await execFileAsync(binary, argv, {
      cwd: input.cwd,
      env,
      maxBuffer: 16 * 1024 * 1024,
      shell: false
    });
    if (input.mode === "graph" && outputPath) {
      await fs.writeFile(outputPath, stdout, "utf8");
    }
    return { exitCode: 0, stdout, stderr };
  } catch (error) {
    const exitCode = Number.isInteger(error.code) ? error.code : 2;
    const stdout = error.stdout || "";
    const stderr = error.stderr || String(error.message || error);
    if (input.mode === "graph" && outputPath && stdout) {
      await fs.writeFile(outputPath, stdout, "utf8").catch(() => {});
    }
    return { exitCode, stdout, stderr };
  }
}

function setOutputVariable(name, value) {
  tl.setVariable(name, String(value || ""), false, true);
}

function logSummary(input, tauditPath, exitCode, outcome, outputPath) {
  tl.debug(`taudit path: ${tauditPath}`);
  tl.debug(`taudit argv: ${JSON.stringify(buildArgv(input))}`);
  tl.debug(`taudit cwd: ${input.cwd}`);
  tl.debug(`taudit output path: ${outputPath || "(none)"}`);
  tl.debug(`taudit outcome: ${outcome}`);
  tl.debug(`taudit exit code: ${exitCode}`);
}

main();
