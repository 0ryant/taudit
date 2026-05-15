import * as fs from "node:fs/promises";
import * as path from "node:path";
import { execFile } from "node:child_process";
import * as vscode from "vscode";
import {
  GraphFormat,
  ScanFormat,
  SuppressionMode,
  TauditPlatform,
  VerifyFormat,
} from "./config";

export type CommandMode = "scan" | "verify" | "graph";
export type GraphView = "authority" | "exploit";

export interface SharedOptions {
  binaryPath: string;
  platform: TauditPlatform;
  targets: string[];
  cwd: string;
  maxHops: number;
  severityThreshold?: string;
  ignoreFile?: string;
  suppressionsFile?: string;
  suppressionMode?: SuppressionMode;
  baselineRoot?: string;
}

export interface ScanRequest extends SharedOptions {
  mode: "scan";
  format: ScanFormat;
}

export interface VerifyRequest extends SharedOptions {
  mode: "verify";
  format: VerifyFormat;
  policyPath: string;
  includeBuiltin: boolean;
  ignorePartial: boolean;
}

export interface GraphRequest extends SharedOptions {
  mode: "graph";
  format: GraphFormat;
  view: GraphView;
}

export type TauditRequest = ScanRequest | VerifyRequest | GraphRequest;

export interface CommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  artifactPath: string;
}

const SEVERITY_THRESHOLDS = new Set([
  "critical",
  "high",
  "medium",
  "low",
  "info",
]);

export function artifactExtension(request: TauditRequest): string {
  if (request.mode === "graph") {
    switch (request.format) {
      case "dot":
        return ".dot";
      case "mermaid":
        return ".mmd";
      case "summary":
      case "json":
        return ".json";
    }
  }

  const format = request.format;
  if (format === "json" || format === "sarif") {
    return `.${format}`;
  }
  if (format === "cloudevents") {
    return ".jsonl";
  }
  return ".txt";
}

export function buildArgs(
  request: TauditRequest,
  artifactPath?: string,
): string[] {
  const args: string[] = [request.mode];

  if (request.platform) {
    args.push("--platform", request.platform);
  }

  args.push("--max-hops", String(request.maxHops));

  if (request.mode !== "graph" && request.severityThreshold) {
    args.push("--severity-threshold", request.severityThreshold);
  }

  if (request.mode !== "graph" && request.ignoreFile) {
    args.push("--ignore-file", request.ignoreFile);
  }

  if (request.mode !== "graph" && request.suppressionsFile) {
    args.push("--suppressions", request.suppressionsFile);
  }

  if (request.mode !== "graph" && request.suppressionMode) {
    args.push("--suppression-mode", request.suppressionMode);
  }

  if (request.mode !== "graph" && request.baselineRoot) {
    args.push("--baseline-root", request.baselineRoot);
  }

  if (request.mode === "verify") {
    args.push("--policy", request.policyPath, "--format", request.format);
    if (request.includeBuiltin) {
      args.push("--include-builtin");
    }
    if (request.ignorePartial) {
      args.push("--ignore-partial");
    }
    args.push("--no-color");
  } else if (request.mode === "scan") {
    args.push("--format", request.format, "--no-color");
  } else {
    args.push("--format", request.format, "--view", request.view);
  }

  if (artifactPath && request.mode !== "graph") {
    args.push("--output", artifactPath);
  }

  args.push(...request.targets);
  return args;
}

export async function ensureStorageDir(
  context: vscode.ExtensionContext,
  workspaceName: string,
): Promise<string> {
  const root = path.join(context.globalStorageUri.fsPath, "results", workspaceName);
  await fs.mkdir(root, { recursive: true });
  return root;
}

export function createArtifactPath(
  storageDir: string,
  request: TauditRequest,
): string {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const viewSuffix =
    request.mode === "graph" ? `-${request.view}` : "";
  return path.join(
    storageDir,
    `taudit-${request.mode}${viewSuffix}-${timestamp}${artifactExtension(request)}`,
  );
}

export async function runTaudit(
  request: TauditRequest,
  artifactPath: string,
): Promise<CommandResult> {
  const args = buildArgs(request, artifactPath);
  const result = await execFileAsync(request.binaryPath, args, {
    cwd: request.cwd,
    maxBuffer: 16 * 1024 * 1024,
  });

  if (request.mode === "graph") {
    await fs.writeFile(artifactPath, result.stdout, "utf8");
  }

  return {
    exitCode: result.exitCode,
    stdout: result.stdout,
    stderr: result.stderr,
    artifactPath,
  };
}

export async function validateRequest(
  request: TauditRequest,
): Promise<string | undefined> {
  if (!Number.isInteger(request.maxHops) || request.maxHops < 1) {
    return "Configured taudit maxHops must be a positive integer.";
  }

  if (
    request.mode !== "graph" &&
    request.severityThreshold &&
    !SEVERITY_THRESHOLDS.has(request.severityThreshold)
  ) {
    return "Configured taudit severityThreshold must be one of critical, high, medium, low, or info.";
  }

  if (usesExplicitPath(request.binaryPath) && !(await pathExists(request.binaryPath))) {
    return `Configured taudit binary path does not exist: ${request.binaryPath}`;
  }

  const outsideWorkspace = validateWorkspaceBoundTargets(
    request.cwd,
    request.targets,
  );
  if (outsideWorkspace) {
    return outsideWorkspace;
  }

  if (request.mode === "verify" && !(await pathExists(request.policyPath))) {
    return `Configured taudit verify policy path does not exist: ${request.policyPath}`;
  }
  if (
    request.mode === "verify" &&
    !pathStaysWithinWorkspace(request.cwd, request.policyPath)
  ) {
    return `Configured taudit verify policy path must stay inside the workspace: ${request.policyPath}`;
  }

  if (request.mode !== "graph") {
    if (request.ignoreFile && !(await pathExists(request.ignoreFile))) {
      return `Configured taudit ignore file does not exist: ${request.ignoreFile}`;
    }
    if (
      request.ignoreFile &&
      !pathStaysWithinWorkspace(request.cwd, request.ignoreFile)
    ) {
      return `Configured taudit ignore file must stay inside the workspace: ${request.ignoreFile}`;
    }
    if (
      request.suppressionsFile &&
      !(await pathExists(request.suppressionsFile))
    ) {
      return `Configured taudit suppressions file does not exist: ${request.suppressionsFile}`;
    }
    if (
      request.suppressionsFile &&
      !pathStaysWithinWorkspace(request.cwd, request.suppressionsFile)
    ) {
      return `Configured taudit suppressions file must stay inside the workspace: ${request.suppressionsFile}`;
    }
    if (request.baselineRoot && !(await pathExists(request.baselineRoot))) {
      return `Configured taudit baseline root does not exist: ${request.baselineRoot}`;
    }
    if (
      request.baselineRoot &&
      !pathStaysWithinWorkspace(request.cwd, request.baselineRoot)
    ) {
      return `Configured taudit baseline root must stay inside the workspace: ${request.baselineRoot}`;
    }
  }

  return undefined;
}

interface ExecFileSuccess {
  exitCode: number;
  stdout: string;
  stderr: string;
}

function execFileAsync(
  file: string,
  args: string[],
  options: {
    cwd: string;
    maxBuffer: number;
  },
): Promise<ExecFileSuccess> {
  return new Promise((resolve, reject) => {
    execFile(file, args, options, (error, stdout, stderr) => {
      if (!error) {
        resolve({
          exitCode: 0,
          stdout,
          stderr,
        });
        return;
      }

      const execError = error as NodeJS.ErrnoException & {
        code?: number | string;
      };
      const exitCode =
        typeof execError.code === "number" ? execError.code : undefined;

      if (exitCode !== undefined) {
        resolve({
          exitCode,
          stdout,
          stderr,
        });
        return;
      }

      reject(error);
    });
  });
}

function usesExplicitPath(binaryPath: string): boolean {
  return (
    path.isAbsolute(binaryPath) ||
    binaryPath.startsWith(".") ||
    binaryPath.includes(path.sep)
  );
}

async function pathExists(targetPath: string): Promise<boolean> {
  try {
    await fs.access(targetPath);
    return true;
  } catch {
    return false;
  }
}

function validateWorkspaceBoundTargets(
  cwd: string,
  targets: string[],
): string | undefined {
  for (const target of targets) {
    if (!pathStaysWithinWorkspace(cwd, target)) {
      return `Configured taudit workflow path must stay inside the workspace: ${target}`;
    }
  }
  return undefined;
}

function pathStaysWithinWorkspace(workspaceRoot: string, candidate: string): boolean {
  const root = path.resolve(workspaceRoot);
  const resolved = path.resolve(candidate);
  const relative = path.relative(root, resolved);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}
