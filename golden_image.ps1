<#
.SYNOPSIS
    Creates a golden image baseline using Vitia Invenire on a clean Windows 11 machine.

.DESCRIPTION
    Installs Vitia Invenire (via install.ps1) and runs baseline create to capture the
    trusted reference state. Everything lives under %LOCALAPPDATA%\VitiaInvenire.

.PARAMETER InstallDir
    Installation directory. Default: $env:LOCALAPPDATA\VitiaInvenire

.PARAMETER Output
    Golden image output path. Default: $InstallDir\golden_image.json

.PARAMETER ConfigPath
    Optional config YAML to pass to baseline create (e.g., to limit check categories).

.PARAMETER SkipInstall
    Skip installation if Vitia Invenire is already installed.

.EXAMPLE
    # Online one-liner (paste into PowerShell):
    powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/rondilley/Vitia_Invenire_AI/main/golden_image.ps1 | iex"

.EXAMPLE
    # From local clone or USB:
    .\golden_image.ps1

.EXAMPLE
    # Custom output path:
    .\golden_image.ps1 -Output D:\baselines\laptop_model_x.json

.EXAMPLE
    # Skip install (tool already installed):
    .\golden_image.ps1 -SkipInstall -Output .\golden.json
#>

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\VitiaInvenire",
    [string]$Output = "",
    [string]$ConfigPath = "",
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"

$PythonDir = Join-Path $InstallDir "python"
$PythonExe = Join-Path $PythonDir "python.exe"
$ScriptsDir = Join-Path $PythonDir "Scripts"
$ToolExe = Join-Path $ScriptsDir "vitia-invenire.exe"
$ToolsDir = Join-Path $InstallDir "tools"
$NmapDir = Join-Path $ToolsDir "nmap"
$YaraDir = Join-Path $ToolsDir "yara"

# Default output path
if (-not $Output) {
    $Output = Join-Path $InstallDir "golden_image.json"
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "  Vitia Invenire - Golden Image Baseline"
Write-Host "  ----------------------------------------------------------"
Write-Host ""

# ---------------------------------------------------------------------------
# [1/3] Install Vitia Invenire
# ---------------------------------------------------------------------------

Write-Host "  [1/3] Installing Vitia Invenire ..."

if ($SkipInstall) {
    # Verify the tool is actually available
    if ((Test-Path $ToolExe) -or (Get-Command vitia-invenire -ErrorAction SilentlyContinue)) {
        Write-Host "         Skipping installation (-SkipInstall specified)."
    } else {
        # Check if the Python module is importable
        if ((Test-Path $PythonExe)) {
            $moduleCheck = & $PythonExe -c "import vitia_invenire; print('ok')" 2>&1
            if ($moduleCheck -match "ok") {
                Write-Host "         Skipping installation (-SkipInstall specified)."
            } else {
                Write-Error "Vitia Invenire is not installed. Remove -SkipInstall to install it first."
                exit 1
            }
        } else {
            Write-Error "Vitia Invenire is not installed. Remove -SkipInstall to install it first."
            exit 1
        }
    }
} else {
    # Find install.ps1 -- check PSScriptRoot first, then CWD
    $installScript = $null

    if ($PSScriptRoot -and (Test-Path $PSScriptRoot)) {
        $candidate = Join-Path $PSScriptRoot "install.ps1"
        if (Test-Path $candidate) {
            $installScript = $candidate
        }
    }

    if (-not $installScript) {
        $candidate = Join-Path (Get-Location).Path "install.ps1"
        if (Test-Path $candidate) {
            $installScript = $candidate
        }
    }

    if (-not $installScript) {
        # Download install.ps1 from GitHub
        Write-Host "         install.ps1 not found locally, downloading from GitHub ..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $installScript = Join-Path $env:TEMP "vitia_install.ps1"
        try {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/rondilley/Vitia_Invenire_AI/main/install.ps1" -OutFile $installScript -UseBasicParsing
        } catch {
            Write-Error "Failed to download install.ps1: $_"
            exit 1
        }
    } else {
        Write-Host "         Using local install.ps1: $installScript"
    }

    # Run install.ps1 with -SkipScan
    Write-Host "         Running install.ps1 -SkipScan ..."
    Write-Host ""
    try {
        & $installScript -SkipScan -InstallDir $InstallDir
    } catch {
        Write-Error "Installation failed: $_"
        exit 1
    }

    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        Write-Error "Installation failed with exit code $LASTEXITCODE."
        exit 1
    }

    Write-Host ""
}

# ---------------------------------------------------------------------------
# Set up PATH for this session (install.ps1 does this in its own scope)
# ---------------------------------------------------------------------------

$pathAdditions = @($ScriptsDir, $PythonDir)
if (Test-Path $NmapDir) {
    $pathAdditions += $NmapDir
}
if (Test-Path $YaraDir) {
    $pathAdditions += $YaraDir
}

foreach ($dir in $pathAdditions) {
    if ($env:PATH -notlike "*$dir*") {
        $env:PATH = "$dir;$env:PATH"
    }
}

# ---------------------------------------------------------------------------
# [2/3] Create golden image baseline
# ---------------------------------------------------------------------------

Write-Host "  [2/3] Creating golden image baseline ..."

# Ensure output directory exists
$outputDir = Split-Path -Path $Output -Parent
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# Build the baseline create command arguments
$baselineArgs = @("baseline", "create", "--output", $Output)
if ($ConfigPath) {
    if (-not (Test-Path $ConfigPath)) {
        Write-Error "Config file not found: $ConfigPath"
        exit 1
    }
    $baselineArgs += @("--config", $ConfigPath)
}

Write-Host "         Output: $Output"
if ($ConfigPath) {
    Write-Host "         Config: $ConfigPath"
}
Write-Host ""

$prevErrorPref = $ErrorActionPreference
$ErrorActionPreference = "Continue"

if (Test-Path $ToolExe) {
    & $ToolExe @baselineArgs
} else {
    & $PythonExe -m vitia_invenire @baselineArgs
}

$baselineExitCode = $LASTEXITCODE
$ErrorActionPreference = $prevErrorPref

if ($baselineExitCode -and $baselineExitCode -ne 0) {
    Write-Host ""
    Write-Error "Baseline creation failed with exit code $baselineExitCode."
    exit 1
}

if (-not (Test-Path $Output)) {
    Write-Host ""
    Write-Error "Baseline creation failed. Output file not found: $Output"
    exit 1
}

# ---------------------------------------------------------------------------
# [3/3] Summary
# ---------------------------------------------------------------------------

$fileInfo = Get-Item $Output
$fileSizeKB = [math]::Round($fileInfo.Length / 1024, 1)

Write-Host ""
Write-Host "  [3/3] Golden image baseline created."
Write-Host ""
Write-Host "  ----------------------------------------------------------"
Write-Host "  Output file:  $Output"
Write-Host "  File size:    $fileSizeKB KB"
Write-Host "  Created:      $($fileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host ""
Write-Host "  To compare a device against this baseline:"
Write-Host "    vitia-invenire baseline compare --baseline `"$Output`""
Write-Host ""
