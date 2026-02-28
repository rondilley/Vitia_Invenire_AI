<#
.SYNOPSIS
    Bootstrap installer for Vitia Invenire on fresh Windows 11 machines.

.DESCRIPTION
    Downloads Python embeddable ZIP, bootstraps pip, installs Vitia Invenire,
    and optionally runs a scan. No admin required, no system-wide changes.
    Everything lives under %LOCALAPPDATA%\VitiaInvenire.

.PARAMETER InstallDir
    Installation directory. Default: $env:LOCALAPPDATA\VitiaInvenire

.PARAMETER SkipScan
    Install only, do not run a scan after installation.

.PARAMETER Uninstall
    Remove the installation directory and exit.

.EXAMPLE
    # Online one-liner (paste into PowerShell):
    powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/rondilley/Vitia_Invenire_AI/main/install.ps1 | iex"

.EXAMPLE
    # From local clone or USB:
    .\install.ps1

.EXAMPLE
    # Install without scanning:
    .\install.ps1 -SkipScan

.EXAMPLE
    # Uninstall:
    .\install.ps1 -Uninstall
#>

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\VitiaInvenire",
    [switch]$SkipScan,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

$PythonVersion = "3.13.2"
$PythonZipUrl = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip"
$GetPipUrl = "https://bootstrap.pypa.io/get-pip.py"
$GitHubArchiveUrl = "https://github.com/rondilley/Vitia_Invenire_AI/archive/refs/heads/main.zip"
$PythonDir = Join-Path $InstallDir "python"
$PythonExe = Join-Path $PythonDir "python.exe"
$ScriptsDir = Join-Path $PythonDir "Scripts"
$ToolExe = Join-Path $ScriptsDir "vitia-invenire.exe"

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

function Write-Banner {
    Write-Host ""
    Write-Host "  Vitia Invenire - Windows Supply Chain Security Assessment"
    Write-Host "  ----------------------------------------------------------"
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Test-Is64BitWindows {
    return ([Environment]::Is64BitOperatingSystem) -and
           ($env:OS -eq "Windows_NT")
}

function Find-LocalSource {
    # Check PSScriptRoot first, then current directory
    $candidates = @()
    if ($PSScriptRoot -and (Test-Path $PSScriptRoot)) {
        $candidates += $PSScriptRoot
    }
    $cwd = Get-Location
    if ($cwd.Path -ne $PSScriptRoot) {
        $candidates += $cwd.Path
    }

    foreach ($dir in $candidates) {
        $pyproject = Join-Path $dir "pyproject.toml"
        if (Test-Path $pyproject) {
            $content = Get-Content $pyproject -Raw
            if ($content -match 'name\s*=\s*"vitia-invenire"') {
                return $dir
            }
        }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

if ($Uninstall) {
    Write-Banner
    if (Test-Path $InstallDir) {
        Write-Host "  Removing $InstallDir ..."
        Remove-Item -Recurse -Force $InstallDir
        Write-Host "  Uninstall complete."
    } else {
        Write-Host "  Nothing to remove. $InstallDir does not exist."
    }
    Write-Host ""
    exit 0
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

Write-Banner
Write-Host "  [1/6] Checking prerequisites ..."

if (-not (Test-Is64BitWindows)) {
    Write-Error "Vitia Invenire requires 64-bit Windows."
    exit 1
}

# Enforce TLS 1.2 before any network requests
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "         Windows 64-bit confirmed."
Write-Host "         TLS 1.2 enforced."

# ---------------------------------------------------------------------------
# Download and extract Python embeddable ZIP
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "  [2/6] Setting up Python $PythonVersion ..."

if (Test-Path $PythonExe) {
    Write-Host "         Python already installed, skipping download."
} else {
    if (-not (Test-Path $PythonDir)) {
        New-Item -ItemType Directory -Path $PythonDir -Force | Out-Null
    }

    $zipPath = Join-Path $env:TEMP "python-$PythonVersion-embed-amd64.zip"

    Write-Host "         Downloading Python embeddable ZIP ..."
    try {
        Invoke-WebRequest -Uri $PythonZipUrl -OutFile $zipPath -UseBasicParsing
    } catch {
        Write-Error "Failed to download Python: $_"
        exit 1
    }

    Write-Host "         Extracting to $PythonDir ..."
    try {
        Expand-Archive -Path $zipPath -DestinationPath $PythonDir -Force
    } catch {
        Write-Error "Failed to extract Python ZIP: $_"
        exit 1
    }

    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Write-Host "         Python extracted."
}

# ---------------------------------------------------------------------------
# Enable site-packages in the ._pth file
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "  [3/6] Configuring Python for pip ..."

$pthPattern = Join-Path $PythonDir "python*._pth"
$pthFiles = Get-ChildItem -Path $pthPattern -ErrorAction SilentlyContinue

if ($pthFiles.Count -eq 0) {
    Write-Error "Could not find Python ._pth file in $PythonDir"
    exit 1
}

$pthFile = $pthFiles[0].FullName
$pthContent = Get-Content $pthFile -Raw

if ($pthContent -match "^#import site") {
    $pthContent = $pthContent -replace "#import site", "import site"
    Set-Content -Path $pthFile -Value $pthContent -NoNewline
    Write-Host "         Enabled site-packages (uncommented import site)."
} elseif ($pthContent -match "^import site") {
    Write-Host "         site-packages already enabled."
} else {
    Add-Content -Path $pthFile -Value "`nimport site"
    Write-Host "         Appended 'import site' to ._pth file."
}

# ---------------------------------------------------------------------------
# Bootstrap pip
# ---------------------------------------------------------------------------

$pipExe = Join-Path $ScriptsDir "pip.exe"

if (Test-Path $pipExe) {
    Write-Host "         pip already installed."
} else {
    $getPipPath = Join-Path $env:TEMP "get-pip.py"

    Write-Host "         Downloading get-pip.py ..."
    try {
        Invoke-WebRequest -Uri $GetPipUrl -OutFile $getPipPath -UseBasicParsing
    } catch {
        Write-Error "Failed to download get-pip.py: $_"
        exit 1
    }

    Write-Host "         Running get-pip.py ..."
    try {
        & $PythonExe $getPipPath --no-warn-script-location 2>&1 | Out-Null
    } catch {
        Write-Error "Failed to bootstrap pip: $_"
        exit 1
    }

    Remove-Item $getPipPath -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $pipExe)) {
        Write-Error "pip installation failed. $pipExe not found."
        exit 1
    }

    Write-Host "         pip installed."
}

# ---------------------------------------------------------------------------
# Install Vitia Invenire
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "  [4/6] Installing Vitia Invenire ..."

$localSource = Find-LocalSource

if ($localSource) {
    Write-Host "         Installing from local source: $localSource"
    $installTarget = $localSource
} else {
    Write-Host "         Installing from GitHub (no local source detected) ..."
    $installTarget = $GitHubArchiveUrl
}

try {
    & $PythonExe -m pip install $installTarget --no-warn-script-location --quiet 2>&1 | ForEach-Object {
        if ($_ -match "error|ERROR|Error") { Write-Host "         $_" }
    }
} catch {
    Write-Error "Failed to install Vitia Invenire: $_"
    exit 1
}

# ---------------------------------------------------------------------------
# Verify installation
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "  [5/6] Verifying installation ..."

if (Test-Path $ToolExe) {
    Write-Host "         vitia-invenire.exe found."
} else {
    # Check if it installed as a module without a script entry point
    $moduleCheck = & $PythonExe -c "import vitia_invenire; print('ok')" 2>&1
    if ($moduleCheck -match "ok") {
        Write-Host "         Module installed (no script entry point yet)."
        Write-Host "         Use: $PythonExe -m vitia_invenire"
    } else {
        Write-Error "Installation verification failed. Neither vitia-invenire.exe nor the Python module was found."
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Update session PATH
# ---------------------------------------------------------------------------

if ($env:PATH -notlike "*$ScriptsDir*") {
    $env:PATH = "$ScriptsDir;$PythonDir;$env:PATH"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "  [6/6] Installation complete."
Write-Host ""
Write-Host "  Install directory:  $InstallDir"
if (Test-Path $ToolExe) {
    Write-Host "  Tool path:          $ToolExe"
}
Write-Host "  Python path:        $PythonExe"
Write-Host ""
Write-Host "  Commands (this session):"
Write-Host "    vitia-invenire scan              Run a full security assessment"
Write-Host "    vitia-invenire scan --list-checks List all checks"
Write-Host "    vitia-invenire --help             Show all commands"
Write-Host ""
Write-Host "  Uninstall:"
Write-Host "    Remove-Item -Recurse -Force `"$InstallDir`""
Write-Host ""

# ---------------------------------------------------------------------------
# Run scan (unless -SkipScan)
# ---------------------------------------------------------------------------

if (-not $SkipScan) {
    Write-Host "  Starting security assessment ..."
    Write-Host "  ----------------------------------------------------------"
    Write-Host ""
    if (Test-Path $ToolExe) {
        & $ToolExe scan
    } else {
        & $PythonExe -m vitia_invenire scan
    }
}
