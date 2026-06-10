$ErrorActionPreference = "Stop"

function FailOrSkip([string]$Reason) {
  $required = $env:PANICSCAN_SIGNING_REQUIRED
  if ($required -eq "1" -or $required -eq "true") {
    Write-Error "signature verification required but unavailable: $Reason"
  }
  Write-Output "signature_verification_skipped=$Reason"
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

$signTool = Get-SignTool
if (-not $signTool) {
  FailOrSkip "signtool.exe was not found"
}

& $signTool verify /pa /v $binary
if ($LASTEXITCODE -ne 0) {
  FailOrSkip "Windows Authenticode signature did not verify"
}
Write-Output "signature_verified_platform=windows"
Write-Output "signature_verified_binary=$binary"
