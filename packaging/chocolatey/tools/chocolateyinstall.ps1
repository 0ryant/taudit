$ErrorActionPreference = 'Stop'

# taudit 1.3.3 (x86_64 Windows), downloaded from the GitHub Release for tag v1.3.3
# and verified by SHA-256. The binary is not code-signed; see the release page for
# what is and is not claimed. Version and checksum lines are stamped by
# `scripts/release_assets.py chocolatey-sync` — do not hand-edit them.

$packageName = 'taudit'
$toolsDir    = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"
$url64       = 'https://github.com/0ryant/taudit/releases/download/v1.3.3/taudit-x86_64-windows.zip'
$checksum64  = '9c68647328f427e646badabeb3c2cec1e5aa34452ab203601b5da46a8d69db7e'

$packageArgs = @{
  packageName    = $packageName
  unzipLocation  = $toolsDir
  url64bit       = $url64
  checksum64     = $checksum64
  checksumType64 = 'sha256'
}

Install-ChocolateyZipPackage @packageArgs

# The archive contains taudit.exe at its root. Chocolatey shims every .exe under
# tools\ automatically, so `taudit` lands on PATH; nothing is written outside tools\.
