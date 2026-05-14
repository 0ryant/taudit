import * as path from "node:path";
import * as vscode from "vscode";
import { isSupportedPipelinePath } from "./pathing";

export type TauditPlatform =
  | "auto"
  | "github-actions"
  | "azure-devops"
  | "gitlab"
  | "bitbucket";

export type VerifyFormat = "text" | "json" | "sarif";
export type ScanFormat = "terminal" | "json" | "sarif" | "cloudevents";
export type GraphFormat = "json" | "dot" | "mermaid" | "summary";
export type SuppressionMode = "downgrade" | "tag-only";

export interface TauditSettings {
  binaryPath: string;
  platform: TauditPlatform;
  workflowPaths: string[];
  verifyPolicyPath: string;
  verifyIncludeBuiltin: boolean;
  verifyIgnorePartial: boolean;
  verifyFormat: VerifyFormat;
  scanFormat: ScanFormat;
  graphFormat: GraphFormat;
  ignoreFile: string;
  suppressionsFile: string;
  suppressionMode: SuppressionMode;
  baselineRoot: string;
  maxHops: number;
  severityThreshold: string;
  runOnSave: boolean;
}

export interface WorkspaceTargetContext {
  folder: vscode.WorkspaceFolder;
  targets: string[];
}

export function readSettings(): TauditSettings {
  const config = vscode.workspace.getConfiguration("taudit");
  return {
    binaryPath: config.get<string>("binaryPath", "taudit"),
    platform: config.get<TauditPlatform>("platform", "auto"),
    workflowPaths: config.get<string[]>("workflowPaths", [".github/workflows/"]),
    verifyPolicyPath: config.get<string>("verify.policyPath", ".taudit/policy/"),
    verifyIncludeBuiltin: config.get<boolean>("verify.includeBuiltin", false),
    verifyIgnorePartial: config.get<boolean>("verify.ignorePartial", false),
    verifyFormat: config.get<VerifyFormat>("verify.format", "json"),
    scanFormat: config.get<ScanFormat>("scan.format", "json"),
    graphFormat: config.get<GraphFormat>("graph.format", "mermaid"),
    ignoreFile: config.get<string>("controls.ignoreFile", ""),
    suppressionsFile: config.get<string>("controls.suppressionsFile", ""),
    suppressionMode: config.get<SuppressionMode>(
      "controls.suppressionMode",
      "downgrade",
    ),
    baselineRoot: config.get<string>("controls.baselineRoot", ""),
    maxHops: config.get<number>("maxHops", 4),
    severityThreshold: config.get<string>("severityThreshold", "").trim(),
    runOnSave: config.get<boolean>("runOnSave", false),
  };
}

export function getPrimaryWorkspaceFolder():
  | vscode.WorkspaceFolder
  | undefined {
  return vscode.workspace.workspaceFolders?.[0];
}

export function getWorkspaceTargets(
  settings: TauditSettings,
): WorkspaceTargetContext | undefined {
  const folder = getPrimaryWorkspaceFolder();
  if (!folder) {
    return undefined;
  }

  const targets = settings.workflowPaths
    .map((value) => value.trim())
    .filter((value) => value.length > 0)
    .map((value) => path.resolve(folder.uri.fsPath, value));

  return {
    folder,
    targets: targets.length > 0 ? targets : [folder.uri.fsPath],
  };
}

export function resolveWorkspacePath(
  folder: vscode.WorkspaceFolder | undefined,
  candidate: string,
): string {
  if (!folder || candidate.trim().length === 0) {
    return candidate;
  }

  if (path.isAbsolute(candidate)) {
    return candidate;
  }

  return path.resolve(folder.uri.fsPath, candidate);
}
export { isSupportedPipelinePath };
