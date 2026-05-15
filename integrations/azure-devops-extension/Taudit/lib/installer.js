"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

const execFileAsync = promisify(execFile);

async function resolveTaudit(input) {
  const cachedBinary = installedBinaryPath(input.cwd, input.version);
  if (fs.existsSync(cachedBinary)) {
    return cachedBinary;
  }

  try {
    return await installFromRelease(input.version, input.cwd);
  } catch (error) {
    if (!input.fallbackCargo) {
      throw new Error(`taudit release asset install failed and fallbackCargo is false: ${error.message}`);
    }
    return await installWithCargoFallback(input.version, input.cwd);
  }
}

function normalizeVersion(version) {
  return String(version).startsWith("v") ? String(version).slice(1) : String(version);
}

function binaryName() {
  return process.platform === "win32" ? "taudit.exe" : "taudit";
}

function installedBinaryPath(workspace, version) {
  return path.join(workspace, ".taudit-tools", "bin", normalizeVersion(version), binaryName());
}

function releaseAssetFor(platform, arch) {
  const osName = platform === "darwin" ? "macos" : platform === "linux" ? "linux" : platform === "win32" ? "windows" : null;
  const cpu = arch === "x64" ? "x86_64" : arch === "arm64" ? "aarch64" : null;
  if (!osName || !cpu) {
    throw new Error(`unsupported runner platform ${platform}/${arch}`);
  }
  const ext = osName === "windows" ? "zip" : "tar.gz";
  return `taudit-${cpu}-${osName}.${ext}`;
}

async function installFromRelease(version, workspace) {
  const asset = releaseAssetFor(process.platform, process.arch);
  const normalizedVersion = normalizeVersion(version);
  const tag = `v${normalizedVersion}`;
  const url = `https://github.com/0ryant/taudit/releases/download/${tag}/${asset}`;
  const checksumUrl = `${url}.sha256`;
  if (typeof fetch !== "function") {
    throw new Error("fetch is unavailable");
  }

  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "taudit-ado-task-"));
  try {
    const archive = path.join(dir, asset);
    const checksum = path.join(dir, `${asset}.sha256`);
    await download(url, archive);
    await download(checksumUrl, checksum);
    await verifyChecksum(archive, checksum);

    const binDir = path.join(workspace, ".taudit-tools", "bin", normalizedVersion);
    await fsp.mkdir(binDir, { recursive: true });
    const output = path.join(binDir, binaryName());
    if (!fs.existsSync(output)) {
      await extractArchive(archive, binDir, binaryName());
      await fsp.chmod(output, 0o755).catch(() => {});
    }
    return output;
  } finally {
    await fsp.rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

async function download(url, outputPath) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`download failed ${response.status} for ${url}`);
  }
  const arrayBuffer = await response.arrayBuffer();
  await fsp.writeFile(outputPath, Buffer.from(arrayBuffer));
}

async function verifyChecksum(archivePath, checksumPath) {
  const checksumText = await fsp.readFile(checksumPath, "utf8");
  const expected = checksumText.trim().split(/\s+/)[0].toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(expected)) {
    throw new Error("invalid checksum file");
  }
  const actual = crypto.createHash("sha256").update(await fsp.readFile(archivePath)).digest("hex");
  if (actual !== expected) {
    throw new Error("release asset checksum mismatch");
  }
}

async function extractArchive(archivePath, binDir, binaryName) {
  if (archivePath.endsWith(".zip")) {
    await extractZipArchive(archivePath, binDir);
  } else {
    await execFileAsync("tar", ["-xzf", archivePath, "-C", binDir]);
  }
  const output = path.join(binDir, binaryName);
  if (!fs.existsSync(output)) {
    throw new Error(`taudit binary not found after extracting ${path.basename(archivePath)}`);
  }
}

async function extractZipArchive(archivePath, binDir) {
  const failures = [];

  for (const candidate of windowsExpandArchiveCandidates(archivePath, binDir)) {
    try {
      await execFileAsync(candidate.command, candidate.args, { shell: false });
      return;
    } catch (error) {
      failures.push(`${candidate.label}: ${error.message || String(error)}`);
    }
  }

  try {
    await execFileAsync("tar", ["-xf", archivePath, "-C", binDir], { shell: false });
    return;
  } catch (error) {
    failures.push(`tar: ${error.message || String(error)}`);
  }

  throw new Error(
    "failed to extract taudit Windows release asset. Tried PowerShell Expand-Archive with explicit Microsoft.PowerShell.Archive import and tar fallback. " +
    "If the runner lacks those extraction dependencies, enable fallbackCargo=true. Details: " +
    failures.join(" | ")
  );
}

function windowsExpandArchiveCandidates(archivePath, binDir) {
  const script =
    `$ErrorActionPreference = 'Stop'; ` +
    `Import-Module Microsoft.PowerShell.Archive -ErrorAction Stop; ` +
    `Expand-Archive -LiteralPath '${escapePowerShellSingleQuoted(archivePath)}' ` +
    `-DestinationPath '${escapePowerShellSingleQuoted(binDir)}' -Force`;

  return [
    {
      label: "pwsh Expand-Archive",
      command: "pwsh",
      args: ["-NoProfile", "-Command", script]
    },
    {
      label: "powershell Expand-Archive",
      command: "powershell",
      args: ["-NoProfile", "-Command", script]
    }
  ];
}

function escapePowerShellSingleQuoted(value) {
  return String(value).replace(/'/g, "''");
}

async function installWithCargoFallback(version, workspace) {
  const normalizedVersion = normalizeVersion(version);
  const root = path.join(workspace, ".taudit-tools", "cargo", normalizedVersion);
  const output = path.join(root, "bin", binaryName());
  if (fs.existsSync(output)) {
    return output;
  }

  await fsp.mkdir(root, { recursive: true });
  await execFileAsync("cargo", [
    "install",
    "taudit",
    "--version",
    normalizedVersion,
    "--locked",
    "--root",
    root
  ]);
  if (!fs.existsSync(output)) {
    throw new Error("cargo fallback install completed but taudit binary was not found");
  }
  await fsp.chmod(output, 0o755).catch(() => {});
  return output;
}

module.exports = {
  resolveTaudit,
  normalizeVersion,
  installedBinaryPath,
  windowsExpandArchiveCandidates,
  escapePowerShellSingleQuoted
};
