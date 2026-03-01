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
$NmapVersion = "7.92"
$NmapZipUrl = "https://nmap.org/dist/nmap-$NmapVersion-win32.zip"
$YaraVersion = "4.5.2"
$YaraZipUrl = "https://github.com/VirusTotal/yara/releases/download/v$YaraVersion/yara-v$YaraVersion-2326-win64.zip"
$PythonDir = Join-Path $InstallDir "python"
$PythonExe = Join-Path $PythonDir "python.exe"
$ScriptsDir = Join-Path $PythonDir "Scripts"
$ToolExe = Join-Path $ScriptsDir "vitia-invenire.exe"
$ToolsDir = Join-Path $InstallDir "tools"
$NmapDir = Join-Path $ToolsDir "nmap"
$YaraDir = Join-Path $ToolsDir "yara"

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

function Write-Banner {
    Write-Host ""
    Write-Host "  Vitia Invenire - Windows Security Assessment"
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
Write-Host "  [1/10] Checking prerequisites ..."

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
Write-Host "  [2/10] Setting up Python $PythonVersion ..."

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
Write-Host "  [3/10] Configuring Python for pip ..."

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
    $prevErrorPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $getPipOutput = & $PythonExe $getPipPath --no-warn-script-location 2>&1
    $getPipExitCode = $LASTEXITCODE
    $ErrorActionPreference = $prevErrorPref

    if ($getPipExitCode -ne 0) {
        Write-Host ""
        $getPipOutput | ForEach-Object { Write-Host "         $_" }
        Write-Host ""
        Write-Error "Failed to bootstrap pip (exit code $getPipExitCode)."
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
Write-Host "  [4/10] Installing Vitia Invenire ..."

# Embeddable Python lacks setuptools/wheel -- install them first
$prevErrorPref = $ErrorActionPreference
$ErrorActionPreference = "Continue"

Write-Host "         Installing build tools (setuptools, wheel) ..."
$buildOutput = & $PythonExe -m pip install setuptools wheel --no-warn-script-location 2>&1
$buildExitCode = $LASTEXITCODE
$ErrorActionPreference = $prevErrorPref

if ($buildExitCode -ne 0) {
    Write-Host ""
    Write-Host "         Failed to install build tools (exit code $buildExitCode):"
    $buildOutput | ForEach-Object { Write-Host "         $_" }
    Write-Host ""
    Write-Error "Failed to install setuptools/wheel."
    exit 1
}

$localSource = Find-LocalSource

if ($localSource) {
    Write-Host "         Installing from local source: $localSource"
    $installTarget = $localSource
} else {
    Write-Host "         Installing from GitHub (no local source detected) ..."
    $installTarget = $GitHubArchiveUrl
}

$prevErrorPref = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$pipOutput = & $PythonExe -m pip install $installTarget --no-warn-script-location 2>&1
$pipExitCode = $LASTEXITCODE
$ErrorActionPreference = $prevErrorPref

if ($pipExitCode -ne 0) {
    Write-Host ""
    Write-Host "         pip install failed (exit code $pipExitCode):"
    $pipOutput | ForEach-Object { Write-Host "         $_" }
    Write-Host ""
    Write-Error "Failed to install Vitia Invenire. See output above."
    exit 1
}

Write-Host "         Installed successfully."

# ---------------------------------------------------------------------------
# Install Nmap (portable ZIP -- no admin required)
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "  [5/10] Installing Nmap $NmapVersion ..."

$nmapInstalled = $false
$nmapExe = Join-Path $NmapDir "nmap.exe"

# Check if already installed locally or on system PATH
if (Test-Path $nmapExe) {
    Write-Host "         Nmap already installed in tools directory."
    $nmapInstalled = $true
} elseif (Get-Command nmap -ErrorAction SilentlyContinue) {
    Write-Host "         Nmap found on system PATH, skipping local install."
    $nmapInstalled = $true
} else {
    $nmapZipPath = Join-Path $env:TEMP "nmap-$NmapVersion-win32.zip"

    try {
        Write-Host "         Downloading Nmap portable ZIP ..."
        Invoke-WebRequest -Uri $NmapZipUrl -OutFile $nmapZipPath -UseBasicParsing

        if (-not (Test-Path $ToolsDir)) {
            New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
        }

        # Extract to temp first, then move the inner folder
        $nmapTempDir = Join-Path $env:TEMP "nmap-extract"
        if (Test-Path $nmapTempDir) {
            Remove-Item -Recurse -Force $nmapTempDir
        }

        Write-Host "         Extracting ..."
        Expand-Archive -Path $nmapZipPath -DestinationPath $nmapTempDir -Force

        # Nmap ZIP contains a top-level folder like "nmap-7.95"
        $innerDir = Get-ChildItem -Path $nmapTempDir -Directory | Select-Object -First 1
        if ($innerDir) {
            if (Test-Path $NmapDir) {
                Remove-Item -Recurse -Force $NmapDir
            }
            Move-Item -Path $innerDir.FullName -Destination $NmapDir -Force
        } else {
            # No inner folder -- contents are at top level
            if (Test-Path $NmapDir) {
                Remove-Item -Recurse -Force $NmapDir
            }
            Move-Item -Path $nmapTempDir -Destination $NmapDir -Force
        }

        Remove-Item $nmapZipPath -Force -ErrorAction SilentlyContinue
        Remove-Item $nmapTempDir -Recurse -Force -ErrorAction SilentlyContinue

        if (Test-Path $nmapExe) {
            Write-Host "         Nmap $NmapVersion installed."
            $nmapInstalled = $true
        } else {
            Write-Host "         WARNING: Nmap extraction succeeded but nmap.exe not found."
            Write-Host "         The NMAP-001 check will be skipped during scans."
        }
    } catch {
        Write-Host "         WARNING: Failed to install Nmap: $_"
        Write-Host "         The NMAP-001 check will be skipped during scans."
        Write-Host "         To install manually: https://nmap.org/download.html"
        Remove-Item $nmapZipPath -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Install YARA (standalone binary from GitHub releases -- no admin required)
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "  [6/10] Installing YARA $YaraVersion ..."

$yaraInstalled = $false
$yaraExe = Join-Path $YaraDir "yara64.exe"

# Check if already installed locally or on system PATH
if (Test-Path $yaraExe) {
    Write-Host "         YARA already installed in tools directory."
    $yaraInstalled = $true
} elseif (Get-Command yara64 -ErrorAction SilentlyContinue) {
    Write-Host "         yara64 found on system PATH, skipping local install."
    $yaraInstalled = $true
} else {
    $yaraZipPath = Join-Path $env:TEMP "yara-$YaraVersion-win64.zip"

    try {
        Write-Host "         Downloading YARA $YaraVersion from GitHub ..."
        Invoke-WebRequest -Uri $YaraZipUrl -OutFile $yaraZipPath -UseBasicParsing

        if (-not (Test-Path $ToolsDir)) {
            New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
        }

        if (-not (Test-Path $YaraDir)) {
            New-Item -ItemType Directory -Path $YaraDir -Force | Out-Null
        }

        Write-Host "         Extracting ..."
        Expand-Archive -Path $yaraZipPath -DestinationPath $YaraDir -Force

        Remove-Item $yaraZipPath -Force -ErrorAction SilentlyContinue

        # YARA ZIP may extract yara64.exe directly or into a subfolder
        if (-not (Test-Path $yaraExe)) {
            # Check for nested folder
            $nested = Get-ChildItem -Path $YaraDir -Recurse -Filter "yara64.exe" | Select-Object -First 1
            if ($nested) {
                # Move all files from the nested folder up
                $nestedDir = $nested.DirectoryName
                Get-ChildItem -Path $nestedDir -File | Move-Item -Destination $YaraDir -Force
                # Clean up empty nested dirs
                Get-ChildItem -Path $YaraDir -Directory | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        if (Test-Path $yaraExe) {
            Write-Host "         YARA $YaraVersion installed."
            $yaraInstalled = $true
        } else {
            # Check if only yara.exe (not yara64.exe) was provided
            $yaraExe32 = Join-Path $YaraDir "yara.exe"
            if (Test-Path $yaraExe32) {
                # Create yara64.exe as a copy so REQUIRES_TOOLS finds it
                Copy-Item -Path $yaraExe32 -Destination $yaraExe
                Write-Host "         YARA $YaraVersion installed (copied yara.exe to yara64.exe)."
                $yaraInstalled = $true
            } else {
                Write-Host "         WARNING: YARA extraction succeeded but yara64.exe not found."
                Write-Host "         The YARA-001 check will be skipped during scans."
            }
        }
    } catch {
        Write-Host "         WARNING: Failed to install YARA: $_"
        Write-Host "         The YARA-001 check will be skipped during scans."
        Write-Host "         To install manually: https://github.com/VirusTotal/yara/releases"
        Remove-Item $yaraZipPath -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Install HardeningKitty PowerShell module
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "  [7/10] Installing HardeningKitty module ..."

$hkInstalled = $false
try {
    $hkCheck = Get-Module -ListAvailable -Name HardeningKitty -ErrorAction SilentlyContinue
    if ($hkCheck) {
        Write-Host "         HardeningKitty already installed."
        $hkInstalled = $true
    }
} catch {
    # Module check failed, proceed to install
}

if (-not $hkInstalled) {
    # Try PSGallery first, then fall back to direct GitHub download
    try {
        # Ensure NuGet provider is available for Install-Module
        $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
        if (-not $nuget -or $nuget.Version -lt [Version]"2.8.5.201") {
            Write-Host "         Installing NuGet package provider ..."
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -Confirm:$false | Out-Null
        }

        # Ensure PSGallery is trusted to avoid interactive prompts
        $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($repo -and $repo.InstallationPolicy -ne "Trusted") {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }

        Write-Host "         Installing HardeningKitty from PSGallery ..."
        Install-Module -Name HardeningKitty -Scope CurrentUser -Force -AllowClobber -Confirm:$false -ErrorAction Stop
        Write-Host "         HardeningKitty installed."
        $hkInstalled = $true
    } catch {
        Write-Host "         PSGallery install failed, trying GitHub download ..."
        try {
            $hkUrl = "https://github.com/scipag/HardeningKitty/archive/refs/heads/master.zip"
            $hkZip = Join-Path $env:TEMP "HardeningKitty.zip"
            $hkModBase = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "WindowsPowerShell\Modules\HardeningKitty"

            $ProgressPreference = "SilentlyContinue"
            Invoke-WebRequest -Uri $hkUrl -OutFile $hkZip -UseBasicParsing
            $ProgressPreference = "Continue"

            $hkTmpDir = Join-Path $env:TEMP "hk-extract"
            if (Test-Path $hkTmpDir) { Remove-Item $hkTmpDir -Recurse -Force }
            Expand-Archive -Path $hkZip -DestinationPath $hkTmpDir -Force
            Remove-Item $hkZip -Force -ErrorAction SilentlyContinue

            if (Test-Path $hkModBase) { Remove-Item $hkModBase -Recurse -Force }
            $hkInner = Get-ChildItem $hkTmpDir -Directory | Select-Object -First 1
            if ($hkInner) {
                New-Item -ItemType Directory -Path (Split-Path $hkModBase) -Force | Out-Null
                Move-Item $hkInner.FullName -Destination $hkModBase -Force
            }
            Remove-Item $hkTmpDir -Recurse -Force -ErrorAction SilentlyContinue

            if (Test-Path (Join-Path $hkModBase "HardeningKitty.psm1")) {
                Write-Host "         HardeningKitty installed from GitHub."
                $hkInstalled = $true
            } else {
                Write-Host "         WARNING: GitHub download succeeded but module files not found."
            }
        } catch {
            Write-Host "         WARNING: Failed to install HardeningKitty: $_"
            Write-Host "         The HK-001 check will be skipped during scans."
            Write-Host "         To install manually: Install-Module -Name HardeningKitty -Scope CurrentUser"
        }
    }
}

# ---------------------------------------------------------------------------
# Verify installation
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "  [8/10] Verifying installation ..."

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
# Summary
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "  [9/10] Updating session PATH ..."

$pathAdditions = @($ScriptsDir, $PythonDir)
if ($nmapInstalled -and (Test-Path $NmapDir)) {
    $pathAdditions += $NmapDir
}
if ($yaraInstalled -and (Test-Path $YaraDir)) {
    $pathAdditions += $YaraDir
}

foreach ($dir in $pathAdditions) {
    if ($env:PATH -notlike "*$dir*") {
        $env:PATH = "$dir;$env:PATH"
    }
}

Write-Host "         PATH updated for this session."

Write-Host ""
Write-Host "  [10/10] Installation complete."
Write-Host ""
Write-Host "  Install directory:  $InstallDir"
if (Test-Path $ToolExe) {
    Write-Host "  Tool path:          $ToolExe"
}
Write-Host "  Python path:        $PythonExe"
if ($nmapInstalled) {
    Write-Host "  Nmap:               Installed (network vulnerability scanning enabled)"
} else {
    Write-Host "  Nmap:               Not installed (install manually for NMAP-001)"
}
if ($yaraInstalled) {
    Write-Host "  YARA:               Installed (malware rule scanning enabled)"
} else {
    Write-Host "  YARA:               Not installed (install manually for YARA-001)"
}
if ($hkInstalled) {
    Write-Host "  HardeningKitty:     Installed (CIS benchmark auditing enabled)"
} else {
    Write-Host "  HardeningKitty:     Not installed (install manually for HK-001)"
}
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
        & $ToolExe scan --format console,json,html
    } else {
        & $PythonExe -m vitia_invenire scan --format console,json,html
    }
}
