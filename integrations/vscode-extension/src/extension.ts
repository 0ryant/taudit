import * as path from "node:path";
import * as vscode from "vscode";
import {
  getPrimaryWorkspaceFolder,
  getWorkspaceTargets,
  isSupportedPipelinePath,
  readSettings,
  resolveWorkspacePath,
} from "./config";
import {
  GraphRequest,
  GraphView,
  ScanRequest,
  TauditRequest,
  VerifyRequest,
  createArtifactPath,
  ensureStorageDir,
  runTaudit,
  validateRequest,
} from "./runner";

let outputChannel: vscode.OutputChannel;
let lastArtifactPath: string | undefined;

export interface TauditExtensionApi {
  getLastArtifactPath(): string | undefined;
}

export function activate(
  context: vscode.ExtensionContext,
): TauditExtensionApi {
  outputChannel = vscode.window.createOutputChannel("taudit");
  context.subscriptions.push(outputChannel);

  context.subscriptions.push(
    vscode.commands.registerCommand("taudit.verifyWorkspace", async () => {
      await runWorkspaceVerify(context);
    }),
    vscode.commands.registerCommand("taudit.scanWorkspace", async () => {
      await runWorkspaceScan(context);
    }),
    vscode.commands.registerCommand("taudit.scanFile", async () => {
      await runActiveFileScan(context, true);
    }),
    vscode.commands.registerCommand("taudit.graphAuthority", async () => {
      await runWorkspaceGraph(context, "authority");
    }),
    vscode.commands.registerCommand("taudit.graphExploit", async () => {
      await runWorkspaceGraph(context, "exploit");
    }),
    vscode.commands.registerCommand("taudit.showOutput", async () => {
      outputChannel.show(true);
      if (lastArtifactPath) {
        await openArtifact(lastArtifactPath);
      }
    }),
    vscode.workspace.onDidSaveTextDocument(async (document) => {
      if (!readSettings().runOnSave || !isSupportedPipelinePath(document.uri.fsPath)) {
        return;
      }

      await runActiveFileScan(context, false, document);
    }),
  );

  return {
    getLastArtifactPath: () => lastArtifactPath,
  };
}

export function deactivate(): void {}

async function runWorkspaceVerify(
  context: vscode.ExtensionContext,
): Promise<void> {
  const settings = readSettings();
  const workspace = getWorkspaceTargets(settings);

  if (!workspace) {
    void vscode.window.showErrorMessage(
      "taudit verify requires an open workspace folder.",
    );
    return;
  }

  const request: VerifyRequest = {
    mode: "verify",
    binaryPath: settings.binaryPath,
    platform: settings.platform,
    targets: workspace.targets,
    cwd: workspace.folder.uri.fsPath,
    maxHops: settings.maxHops,
    severityThreshold: normalizeOptional(settings.severityThreshold),
    ignoreFile: normalizeResolvedPath(workspace.folder, settings.ignoreFile),
    suppressionsFile: normalizeResolvedPath(
      workspace.folder,
      settings.suppressionsFile,
    ),
    suppressionMode: settings.suppressionMode,
    baselineRoot: normalizeResolvedPath(workspace.folder, settings.baselineRoot),
    policyPath: resolveWorkspacePath(workspace.folder, settings.verifyPolicyPath),
    includeBuiltin: settings.verifyIncludeBuiltin,
    ignorePartial: settings.verifyIgnorePartial,
    format: settings.verifyFormat,
  };

  await executeRequest(context, request, workspace.folder.name, true);
}

async function runWorkspaceScan(
  context: vscode.ExtensionContext,
): Promise<void> {
  const settings = readSettings();
  const workspace = getWorkspaceTargets(settings);

  if (!workspace) {
    void vscode.window.showErrorMessage(
      "taudit scan requires an open workspace folder.",
    );
    return;
  }

  const request: ScanRequest = {
    mode: "scan",
    binaryPath: settings.binaryPath,
    platform: settings.platform,
    targets: workspace.targets,
    cwd: workspace.folder.uri.fsPath,
    maxHops: settings.maxHops,
    severityThreshold: normalizeOptional(settings.severityThreshold),
    ignoreFile: normalizeResolvedPath(workspace.folder, settings.ignoreFile),
    suppressionsFile: normalizeResolvedPath(
      workspace.folder,
      settings.suppressionsFile,
    ),
    suppressionMode: settings.suppressionMode,
    baselineRoot: normalizeResolvedPath(workspace.folder, settings.baselineRoot),
    format: settings.scanFormat,
  };

  await executeRequest(context, request, workspace.folder.name, true);
}

async function runWorkspaceGraph(
  context: vscode.ExtensionContext,
  view: GraphView,
): Promise<void> {
  const settings = readSettings();
  const workspace = getWorkspaceTargets(settings);

  if (!workspace) {
    void vscode.window.showErrorMessage(
      "taudit graph requires an open workspace folder.",
    );
    return;
  }

  const request: GraphRequest = {
    mode: "graph",
    binaryPath: settings.binaryPath,
    platform: settings.platform,
    targets: workspace.targets,
    cwd: workspace.folder.uri.fsPath,
    maxHops: settings.maxHops,
    view,
    format: settings.graphFormat,
  };

  await executeRequest(context, request, workspace.folder.name, true);
}

async function runActiveFileScan(
  context: vscode.ExtensionContext,
  revealArtifact: boolean,
  document?: vscode.TextDocument,
): Promise<void> {
  const targetDocument = document ?? vscode.window.activeTextEditor?.document;
  if (!targetDocument) {
    if (revealArtifact) {
      void vscode.window.showErrorMessage("No active file to scan.");
    }
    return;
  }

  if (!isSupportedPipelinePath(targetDocument.uri.fsPath)) {
    if (revealArtifact) {
      void vscode.window.showErrorMessage(
        "taudit scan file supports only .yml or .yaml documents.",
      );
    }
    return;
  }

  const settings = readSettings();
  const workspaceFolder = vscode.workspace.getWorkspaceFolder(targetDocument.uri);
  const cwd = workspaceFolder?.uri.fsPath ?? path.dirname(targetDocument.uri.fsPath);

  const request: ScanRequest = {
    mode: "scan",
    binaryPath: settings.binaryPath,
    platform: settings.platform,
    targets: [targetDocument.uri.fsPath],
    cwd,
    maxHops: settings.maxHops,
    severityThreshold: normalizeOptional(settings.severityThreshold),
    ignoreFile: normalizeResolvedPath(workspaceFolder, settings.ignoreFile),
    suppressionsFile: normalizeResolvedPath(
      workspaceFolder,
      settings.suppressionsFile,
    ),
    suppressionMode: settings.suppressionMode,
    baselineRoot: normalizeResolvedPath(workspaceFolder, settings.baselineRoot),
    format: settings.scanFormat,
  };

  const workspaceName = workspaceFolder?.name ?? "single-file";
  await executeRequest(context, request, workspaceName, revealArtifact, revealArtifact);
}

async function executeRequest(
  context: vscode.ExtensionContext,
  request: TauditRequest,
  workspaceName: string,
  revealArtifact: boolean,
  notify = true,
): Promise<void> {
  const validationError = await validateRequest(request);
  if (validationError) {
    outputChannel.appendLine(validationError);
    if (notify) {
      outputChannel.show(true);
      void vscode.window.showErrorMessage(validationError);
    }
    return;
  }

  const storageDir = await ensureStorageDir(context, sanitizeName(workspaceName));
  const artifactPath = createArtifactPath(storageDir, request);
  const argsPreview = previewArgs(request);

  outputChannel.appendLine(`$ ${request.binaryPath} ${argsPreview}`);

  let result;
  try {
    result = await runTaudit(request, artifactPath);
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unknown taudit execution error.";
    outputChannel.appendLine(message);
    if (notify) {
      outputChannel.show(true);
      void vscode.window.showErrorMessage(`taudit failed to start: ${message}`);
    }
    return;
  }

  if (result.stdout.trim().length > 0) {
    outputChannel.appendLine(result.stdout.trimEnd());
  }

  if (result.stderr.trim().length > 0) {
    outputChannel.appendLine(result.stderr.trimEnd());
  }

  lastArtifactPath = artifactPath;

  if (revealArtifact) {
    await openArtifact(artifactPath);
  }

  if (result.exitCode === 0) {
    if (notify) {
      void vscode.window.showInformationMessage(
        `taudit ${request.mode} passed. Artifact: ${path.basename(artifactPath)}`,
      );
    }
    return;
  }

  if (result.exitCode === 1) {
    if (notify) {
      void vscode.window.showWarningMessage(
        `taudit ${request.mode} reported findings or violations. Artifact: ${path.basename(artifactPath)}`,
      );
    }
    return;
  }

  if (notify) {
    outputChannel.show(true);
    void vscode.window.showErrorMessage(
      `taudit ${request.mode} failed with exit ${result.exitCode}.`,
    );
  }
}

function normalizeOptional(value: string): string | undefined {
  return value.trim().length > 0 ? value : undefined;
}

function normalizeResolvedPath(
  folder: vscode.WorkspaceFolder | undefined,
  candidate: string,
): string | undefined {
  const value = candidate.trim();
  if (value.length === 0) {
    return undefined;
  }
  return resolveWorkspacePath(folder, value);
}

async function openArtifact(artifactPath: string): Promise<void> {
  const document = await vscode.workspace.openTextDocument(artifactPath);
  await vscode.window.showTextDocument(document, {
    preview: false,
    preserveFocus: true,
  });
}

function previewArgs(request: TauditRequest): string {
  return [
    request.mode,
    ...(request.mode === "verify"
      ? ["--policy", request.policyPath, "--format", request.format]
      : request.mode === "scan"
        ? ["--format", request.format]
        : ["--format", request.format, "--view", request.view]),
    ...request.targets,
  ].join(" ");
}

function sanitizeName(name: string): string {
  return name.replace(/[^A-Za-z0-9._-]+/g, "-");
}
