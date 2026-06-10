$ErrorActionPreference = "Stop"

function FailOrSkip([string]$Reason) {
  $required = $env:PANICSCAN_SIGNING_REQUIRED
  if ($required -eq "1" -or $required -eq "true") {
    Write-Error "signing required but unavailable: $Reason"
  }
  Write-Output "signing_skipped=$Reason"
  exit 0
}

function Get-ArtifactDir {
  if ($env:PANICSCAN_ARTIFACT_DIR) {
    return $env:PANICSCAN_ARTIFACT_DIR
  }
  if (-not $env:PANICSCAN_ARTIFACT_NAME) {
    Write-Error "PANICSCAN_ARTIFACT_NAME or PANICSCAN_ARTIFACT_DIR is required"
  }
  $distRoot = if ($env:PANICSCAN_DIST_ROOT) { $env:PANICSCAN_DIST_ROOT } else { "dist" }
  return (Join-Path $distRoot $env:PANICSCAN_ARTIFACT_NAME)
}

function Get-SignTool {
  if ($env:PANICSCAN_SIGNTOOL -and (Test-Path $env:PANICSCAN_SIGNTOOL)) {
    return $env:PANICSCAN_SIGNTOOL
  }

  $kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
  if (Test-Path $kitsRoot) {
    $candidate = Get-ChildItem -Path $kitsRoot -Recurse -Filter signtool.exe |
      Where-Object { $_.FullName -match "\\x64\\signtool\.exe$" } |
      Sort-Object FullName -Descending |
      Select-Object -First 1
    if ($candidate) {
      return $candidate.FullName
    }
  }

  $fromPath = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($fromPath) {
    return $fromPath.Source
  }

  return $null
}

$artifactDir = Get-ArtifactDir
if (-not (Test-Path $artifactDir)) {
  Write-Error "artifact directory not found: $artifactDir"
}

$binary = Join-Path $artifactDir "panicscan.exe"
if (-not (Test-Path $binary)) {
  Write-Error "artifact binary not found: $binary"
}

if (-not $env:PANICSCAN_WINDOWS_CERTIFICATE_P12_BASE64) {
  FailOrSkip "PANICSCAN_WINDOWS_CERTIFICATE_P12_BASE64 is not set"
}
if (-not $env:PANICSCAN_WINDOWS_CERTIFICATE_PASSWORD) {
  FailOrSkip "PANICSCAN_WINDOWS_CERTIFICATE_PASSWORD is not set"
}

$signTool = Get-SignTool
if (-not $signTool) {
  FailOrSkip "signtool.exe was not found"
}

$timestampUrl = if ($env:PANICSCAN_WINDOWS_TIMESTAMP_URL) {
  $env:PANICSCAN_WINDOWS_TIMESTAMP_URL
} else {
  "http://timestamp.digicert.com"
}

$certPath = Join-Path ([System.IO.Path]::GetTempPath()) "panicscan-codesign.p12"
[System.IO.File]::WriteAllBytes($certPath, [Convert]::FromBase64String($env:PANICSCAN_WINDOWS_CERTIFICATE_P12_BASE64))

try {
  & $signTool sign /fd SHA256 /td SHA256 /tr $timestampUrl /f $certPath /p $env:PANICSCAN_WINDOWS_CERTIFICATE_PASSWORD /d "PanicScan" $binary
  if ($LASTEXITCODE -ne 0) {
    Write-Error "signtool sign failed with exit code $LASTEXITCODE"
  }
  & $signTool verify /pa /v $binary
  if ($LASTEXITCODE -ne 0) {
    Write-Error "signtool verify failed with exit code $LASTEXITCODE"
  }
  Write-Output "signed_platform=windows"
  Write-Output "signed_binary=$binary"
}
finally {
  if (Test-Path $certPath) {
    Remove-Item -Force $certPath
  }
}
