# Vitia Invenire - Windows Supply Chain Security Assessment Tool

**Vitia Invenire** ("Finding Faults" in Latin) is a comprehensive local security assessment tool for Windows 11 systems assembled and integrated in third-party facilities. It validates laptops for supply chain security threats before deployment to customers.

## Why This Exists

Real-world supply chain compromises are documented and ongoing:

- **Lenovo Superfish (2015):** Rogue root CA certificate enabling MITM on all HTTPS traffic
- **ASUS ShadowHammer (2019):** Trojanized ASUS Live Update utility targeting specific MAC addresses
- **Gigabyte UEFI Backdoor (2023):** Firmware-level binary dropper via Windows Platform Binary Table (WPBT)
- **CosmicStrand/BlackLotus (2022-2023):** UEFI rootkits persisting in EFI System Partition and SPI flash
- **PKfail (2024):** Hundreds of device models shipping with leaked Secure Boot Platform Keys

Laptops assembled in Singapore (or any third-party integrator) pass through multiple hands -- component suppliers, assemblers, firmware flashers, OS image creators, QA testers -- any of whom could introduce malicious modifications.

## Quick Deploy

For fresh Windows 11 laptops with no Python or git installed. Paste this one-liner into PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/rondilley/Vitia_Invenire_AI/main/install.ps1 | iex"
```

This downloads a standalone Python, installs Vitia Invenire, and runs a scan. No admin privileges required. Everything installs to `%LOCALAPPDATA%\VitiaInvenire` with no persistent system changes.

### USB / Offline Install

Copy the repository to a USB drive. On the target machine, open PowerShell in the repo directory:

```powershell
.\install.ps1
```

The installer detects the local source automatically -- no internet needed.

### Options

```powershell
# Install without running a scan:
.\install.ps1 -SkipScan

# Custom install location:
.\install.ps1 -InstallDir "D:\Tools\VitiaInvenire"

# Uninstall (removes the install directory):
.\install.ps1 -Uninstall
# Or manually:
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\VitiaInvenire"
```

## Capabilities

Vitia Invenire performs **60+ security checks** across 15 categories, producing structured JSON and HTML reports with severity-scored findings.

### Check Catalog

#### Hardware & Firmware Fingerprinting (7 checks)

| Check ID | Name | Description | Admin |
|----------|------|-------------|-------|
| HW-001 | Hardware Inventory | Full hardware fingerprint: CPU, RAM, storage, NIC, GPU, USB, TPM, battery, display, audio, camera, SMBIOS | No |
| FW-INFO-001 | Firmware Information | BIOS/UEFI, Embedded Controller, NVMe, NIC, GPU VBIOS, Intel ME, Thunderbolt, audio codec, WiFi, Bluetooth, fingerprint reader, webcam, storage controller firmware versions | No |
| FW-SUB-001 | Subsystem Firmware Audit | Deep enumeration of every device with its own firmware or embedded processor -- any component a supplier could trojan. Covers audio codecs, NICs, WiFi/BT modules, GPUs, NVMe controllers, Thunderbolt controllers, webcams, fingerprint readers, TPM, Intel CSME, USB controllers, SD card readers, WWAN/LTE modems. Cross-references firmware versions against vendor-published baselines. | No |
| SB-KEY-001 | Secure Boot Keys | UEFI Secure Boot key enrollment audit: PK, KEK, db, dbx validation | Yes |
| PCI-001 | PCI Device Audit | PCI/PCIe device enumeration, vendor ID cross-reference, rogue device detection | No |
| BIOS-CFG-001 | BIOS Configuration | BIOS/UEFI configuration audit: boot order, virtualization, TPM, Secure Boot settings | No |
| GHOST-001 | Ghost Device Analysis | Registry forensics for previously connected devices (JTAG, debug hardware, Hak5 tools) | No |

#### Executable & Library Integrity (7 checks)

| Check ID | Name | Description | Admin |
|----------|------|-------------|-------|
| BIN-001 | System Binary Hashing | SHA256 hash all .exe/.dll/.sys/.ocx in System32, SysWOW64, drivers, Program Files | No |
| PROC-001 | Process Integrity | Hash running process executables and loaded DLLs, flag unusual locations | No |
| PE-001 | PE Header Analysis | Entropy analysis, packing detection, suspicious import detection, imphash computation | No |
| SIG-001 | Signature Verification | Authenticode signature verification (embedded + catalog) for system binaries | No |
| DLL-HIJACK-001 | DLL Hijack Detection | DLLs loaded from incorrect paths indicating DLL hijacking attacks | No |
| HASH-001 | Hash Lookup | NIST NSRL and VirusTotal hash comparison for unknown binary classification | No |
| CATALOG-001 | Catalog Integrity | Verify system files against Windows catalog signatures, detect HashMismatch tampering | No |

#### OEM Pre-Installation (5 checks)

| Check ID | Name | Description | Admin |
|----------|------|-------------|-------|
| WPBT-001 | WPBT Analysis | Windows Platform Binary Table firmware binary dropper detection | Yes |
| OEM-001 | OEM Activation | OA3/SLIC BIOS marker and license validation | No |
| RECOV-001 | Recovery Partition | WinRE (winre.wim) integrity and recovery partition audit | Yes |
| OOBE-001 | OOBE Customization | OEM first-boot tasks, Unattend.xml, default profile audit | No |
| TELEM-001 | Telemetry Config | DiagTrack endpoint redirection, WER endpoint config | No |

#### Supply Chain Priority (10 checks)

| Check ID | Name | Description | Admin |
|----------|------|-------------|-------|
| CERT-001 | Certificate Store | Rogue root CA detection against Microsoft Trusted Root Program | No |
| FW-001 | Firmware Integrity | BIOS/UEFI integrity, Secure Boot status, TPM status, Device Guard | Yes |
| AMT-001 | Intel AMT/vPro/ME | Intel AMT provisioning state, ME version, default credential check | Yes |
| BOOT-001 | Boot Configuration | Full BCD analysis: test signing, debug mode, hypervisor, recovery | Yes |
| ACCT-001 | User Accounts | Hidden/unauthorized accounts, RID hijacking, admin group membership | No |
| WMI-001 | WMI Persistence | WMI event subscription analysis (EventFilter, EventConsumer, Binding) | Yes |
| DRV-001 | Driver Integrity | Driver signature verification, LOLDrivers cross-reference | Yes |
| SVC-001 | Service Analysis | Unauthorized services, unquoted paths, suspicious binary locations | No |
| NET-CFG-001 | Network Config | Hosts file tampering, DNS, proxy, NRPT, PAC file analysis | No |
| INTEGRITY-001 | Cross-Path Integrity | Cross-validation of system data via multiple query paths to detect rootkit hooking | Yes |

#### Secondary Built-in (10 checks)

| Check ID | Name | Description | Admin |
|----------|------|-------------|-------|
| SOFT-001 | Software Inventory | Pre-installed software audit, remote access tool detection | No |
| TASK-001 | Scheduled Tasks | Suspicious scheduled task analysis (LOLBin execution, network actions) | No |
| REG-001 | Registry Autostart | Autorun/persistence registry keys (Run, RunOnce, Winlogon, Shell) | No |
| NET-CONN-001 | Network Connections | Active TCP/UDP connections, C2 beacon detection, suspicious port analysis | No |
| NET-PROC-001 | Network Process Audit | Detects processes interacting with the network stack: listening sockets, raw sockets, promiscuous mode / passive packet capture (e.g. pcap, npcap, raw NIC access), port knockers, and processes bound to all interfaces. Flags unexpected network-aware processes on a new device. | No |
| FW-RULE-001 | Firewall Rules | Inbound allow rules, broad port ranges, all-profile rules | Yes |
| ESP-001 | EFI Partition | EFI System Partition inspection for unexpected files (BlackLotus indicators) | Yes |
| PS-001 | PowerShell Profiles | PowerShell profile persistence (all four profile locations) | No |
| FILE-001 | File Integrity | SFC /verifyonly and DISM component store health | Yes |
| DEF-001 | Defender Status | Windows Defender config, exclusions, tamper protection, scan history | No |

#### Advanced Persistence & Defense Evasion (4 checks)

| Check ID | Name | Description | Admin |
|----------|------|-------------|-------|
| COM-001 | COM Hijacking | CLSID hijacking detection (HKCU overriding HKLM) | No |
| BITS-001 | BITS Job Persistence | BITS transfer job analysis (survives reboots, firewall-permitted) | Yes |
| ETW-001 | ETW Tampering | ETW provider/session tampering detection (defense evasion) | Yes |
| PIPE-001 | Named Pipes | Named pipe enumeration, C2 framework pipe detection | No |

#### OS Security (9 checks)

| Check ID | Name | Description | Admin |
|----------|------|-------------|-------|
| WSL-001 | WSL Audit | WSL installation, distro enumeration, Kali/Parrot detection | No |
| SSH-001 | OpenSSH Audit | sshd config, authorized_keys, firewall scope, CVE check | Yes |
| RDP-001 | RDP Audit | RDP enabled state, NLA enforcement, connection history | No |
| SPOOL-001 | Print Spooler | PrintNightmare remnant detection, Point and Print config | No |
| EVTLOG-001 | Event Log Config | Log size/retention, disabled log detection, forensic readiness | No |
| VSS-001 | VSS Audit | Volume Shadow Copy config, service status, deletion evidence | No |
| DPAPI-001 | DPAPI Audit | Credential Manager entries, DPAPI master keys, stored credentials | No |
| WER-001 | WER Audit | Windows Error Reporting endpoint config, crash dump settings | No |
| BROWSER-001 | Browser Audit | Default browser, forced extensions, search engine policies | No |

#### Network Configuration (4 checks)

| Check ID | Name | Description | Admin |
|----------|------|-------------|-------|
| WIFI-001 | Wireless Profiles | Pre-configured WiFi networks, open network detection | No |
| VPN-001 | VPN Audit | Pre-configured VPN connections, third-party VPN software | No |
| IPV6-001 | IPv6 Audit | IPv6 config, DHCPv6, SLAAC, transition mechanisms | No |
| WPAD-001 | WPAD/LLMNR | WPAD, LLMNR, NetBIOS-NS, mDNS poisoning configuration | No |

#### Firmware Deep Analysis (3 checks)

| Check ID | Name | Description | Admin |
|----------|------|-------------|-------|
| ACPI-001 | ACPI Tables | ACPI table analysis: WPBT, DMAR, BGRT, IVRS | Yes |
| BOOTGUARD-001 | Intel Boot Guard | Boot Guard status, SPI flash write protection | Yes |
| DMA-001 | DMA Protection | Kernel DMA Protection, Thunderbolt security level | No |

#### External Tool Integrations (4 checks)

| Check ID | Name | Description | Admin |
|----------|------|-------------|-------|
| HK-001 | HardeningKitty | HardeningKitty PowerShell module audit mode | Yes |
| NMAP-001 | Nmap Scan | Local port scan with service detection and vulnerability NSE scripts | No |
| NESSUS-001 | Nessus Scan | Nessus credentialed local scan via pyTenable REST API | Yes |
| CIS-001 | CIS-CAT Scan | CIS-CAT Pro CLI Windows 11 Enterprise benchmark | Yes |

#### Meta (1 check)

| Check ID | Name | Description | Admin |
|----------|------|-------------|-------|
| DATA-001 | Reference Data Staleness | Checks age of bundled reference data files and warns when they need updating | No |

### Threat Coverage Matrix

| Threat | Relevant Checks |
|--------|----------------|
| Rogue Root CA (Superfish-class) | CERT-001 |
| UEFI Rootkit (BlackLotus-class) | ESP-001, FW-001, SB-KEY-001, BOOT-001, BOOTGUARD-001 |
| Firmware Backdoor (Gigabyte-class) | WPBT-001, ACPI-001, FW-INFO-001 |
| Trojanized Update (ShadowHammer-class) | SIG-001, BIN-001, HASH-001, PE-001 |
| Hardware Implant | HW-001, PCI-001, DMA-001, FW-SUB-001 |
| Component Firmware Trojan (NIC, GPU, audio, WiFi, etc.) | FW-SUB-001, FW-INFO-001, HW-001 |
| Intel ME/AMT Exploitation | AMT-001, FW-INFO-001, BOOTGUARD-001 |
| DLL Hijacking / Side-Loading | DLL-HIJACK-001, PROC-001, PE-001 |
| WMI Persistence | WMI-001 |
| COM Object Hijacking | COM-001 |
| Unauthorized Remote Access | SSH-001, RDP-001, SOFT-001, VPN-001 |
| Network Poisoning (LLMNR/WPAD) | WPAD-001, NET-CFG-001 |
| Driver-Level Compromise (LOLDrivers) | DRV-001, SIG-001 |
| Credential Theft Pre-staging | DPAPI-001, WIFI-001 |
| Defense Evasion | ETW-001, EVTLOG-001, DEF-001 |
| C2 Communication | NET-CONN-001, NET-PROC-001, PIPE-001, BITS-001 |
| Passive Reconnaissance / Packet Capture | NET-PROC-001 |
| Covert Network Listener / Port Knocker | NET-PROC-001, NET-CONN-001 |
| PrintNightmare Remnants | SPOOL-001 |
| WSL-based Attack Hiding | WSL-001 |
| PKfail (Leaked Secure Boot Keys) | SB-KEY-001 |
| Thunderspy (DMA Attack) | DMA-001 |

## Severity Levels

| Severity | Meaning | Example |
|----------|---------|---------|
| CRITICAL | Confirmed compromise indicator or trivially exploitable backdoor | Rogue root CA, WMI persistence subscription, pre-planted SSH authorized_keys |
| HIGH | Strong anomaly requiring immediate investigation | Unsigned driver, unknown PCI device, AMT enabled with defaults |
| MEDIUM | Configuration weakness or missing hardening | Secure Boot disabled, small event logs, LLMNR enabled |
| LOW | Minor issue or informational with slight risk | Outdated firmware, non-default but benign configuration |
| INFO | Baseline data collection, no action needed | Hardware fingerprint, software inventory listing |

## Installation

### Prerequisites

- Python 3.11+
- Windows 11 target system for full assessment (develops/runs on Linux with graceful degradation)

### Install from source

```bash
git clone <repo-url>
cd vitia_invenire
pip install -e .
```

### Install dependencies only

```bash
pip install -r requirements.txt
```

## Usage

### Basic scan (all checks, console + JSON output)

```bash
vitia-invenire scan
```

### List all available checks

```bash
vitia-invenire scan --list-checks
```

### Run specific categories only

```bash
vitia-invenire scan --categories "Certificates,Firmware,Persistence"
```

### Full scan with HTML report

```bash
vitia-invenire scan --format console,json,html --output-dir ./reports
```

### Skip checks requiring admin privileges

```bash
vitia-invenire scan --skip-admin-checks
```

### Require admin (exit with error if not elevated)

```bash
vitia-invenire scan --require-admin
```

### Randomize check execution order (anti-evasion)

```bash
vitia-invenire scan --randomize-order
```

### Use custom configuration

```bash
vitia-invenire scan --config my_config.yaml
```

### Run as Python module

```bash
python -m vitia_invenire scan --list-checks
```

### Create a golden image baseline from a trusted device

```bash
vitia-invenire baseline create --output golden.json
```

### Compare current system against a baseline

```bash
vitia-invenire baseline compare --baseline golden.json
```

### Passive network beaconing monitor

```bash
vitia-invenire monitor --duration 300 --output-dir ./reports
```

### Update reference data (run on a trusted machine, not the device under assessment)

```bash
vitia-invenire update-data
```

## CLI Reference

```
vitia-invenire scan [OPTIONS]

Options:
  --categories TEXT     Comma-separated categories to run (default: all)
  --severity TEXT       Minimum severity to report (default: INFO)
  --output-dir TEXT     Output directory for reports (default: ./reports)
  --format TEXT         Output formats: json,html,console (default: console,json)
  --config PATH        Path to config YAML
  --skip-admin-checks  Skip checks requiring admin privileges
  --require-admin      Exit with error if not running as admin
  --randomize-order    Randomize check execution order (anti-evasion)
  --list-checks        List all available checks and exit
  --verbose            Verbose output during scanning
  --help               Show help message and exit
```

```
vitia-invenire baseline [create|compare] [OPTIONS]

Options:
  --output TEXT        Output file for baseline, create mode (default: baseline.json)
  --baseline PATH     Baseline file to compare against, compare mode
  --config PATH       Path to config YAML
  --help              Show help message and exit
```

```
vitia-invenire monitor [OPTIONS]

Options:
  --duration INTEGER   Monitoring duration in seconds (default: 300)
  --output-dir TEXT    Output directory for monitor results (default: ./reports)
  --help              Show help message and exit
```

```
vitia-invenire update-data

Fetch latest reference data from trusted sources.
Run this on a TRUSTED machine, not on the device under assessment.
```

## Output Formats

### JSON Report

Structured JSON with full machine-readable results:

```json
{
  "report_id": "uuid",
  "hostname": "LAPTOP-001",
  "os_version": "Windows 11 Pro 23H2",
  "scan_start": "2026-02-27T10:00:00Z",
  "scan_end": "2026-02-27T10:15:00Z",
  "hardware_fingerprint": { ... },
  "binary_analysis_summary": { ... },
  "results": [
    {
      "check_id": "CERT-001",
      "check_name": "Certificate Store Audit",
      "status": "failed",
      "findings": [
        {
          "check_id": "CERT-001",
          "title": "Unknown Root CA Certificate Detected",
          "severity": "HIGH",
          "affected_item": "CN=Superfish Inc., Thumbprint=C864...",
          "evidence": "Certificate not in Microsoft Trusted Root Program",
          "recommendation": "Remove untrusted root CA certificate"
        }
      ]
    }
  ],
  "summary": {
    "CRITICAL": 0,
    "HIGH": 2,
    "MEDIUM": 5,
    "LOW": 3,
    "INFO": 40
  }
}
```

### HTML Report

Self-contained HTML report with:
- Executive summary with severity breakdown
- Filterable findings table
- Expandable evidence sections
- Hardware fingerprint summary
- Print-friendly layout

### Console Output

Rich terminal output with:
- Progress bars during scan
- Color-coded severity indicators
- Summary table at completion

## Dependencies

### Required

| Package | Purpose |
|---------|---------|
| pydantic >= 2.0 | Data models, validation, JSON serialization |
| click >= 8.0 | CLI framework |
| rich >= 13.0 | Terminal output, progress bars, tables |
| jinja2 >= 3.0 | HTML report templating |
| pyyaml >= 6.0 | Configuration file parsing |
| psutil >= 5.9 | Process enumeration, network connections |
| pefile >= 2023.2.7 | PE header analysis (cross-platform) |
| signify >= 0.7 | Authenticode signature verification (cross-platform) |

### Optional

| Package | Purpose |
|---------|---------|
| python-nmap >= 0.7 | Nmap integration (requires nmap binary) |
| pyTenable >= 1.4 | Nessus REST API integration |
| requests >= 2.28 | VirusTotal API lookups |
| py-cpuinfo >= 9.0 | Detailed CPU feature flag enumeration |

## Cross-Platform Development

Vitia Invenire targets Windows 11 but is developed on Linux:

- All collectors have `platform_available()` guards returning False on non-Windows
- Checks gracefully skip with status "skipped" and reason on non-Windows
- `platform.py` provides `is_windows()`, `is_admin()`, `has_tool()` utilities
- Tests requiring Windows APIs use `@pytest.mark.skipif(not is_windows())`
- Full integration testing occurs on the target Windows 11 laptop

## Project Structure

```
src/vitia_invenire/
    __init__.py             # Package version
    __main__.py             # python -m entry point
    cli.py                  # Click CLI interface
    config.py               # YAML configuration loader
    engine.py               # Check orchestration and discovery
    models.py               # Pydantic data models
    platform.py             # OS/privilege detection
    collectors/             # Data collection abstraction layer
        powershell.py       # PowerShell subprocess runner
        registry.py         # Windows Registry reader
        wmi_collector.py    # WMI query wrapper
        command.py          # Generic subprocess runner
    checks/                 # 60+ security check modules
        base.py             # BaseCheck abstract base class
        ...                 # One module per check
    reporters/              # Output formatters
        json_reporter.py    # JSON output
        html_reporter.py    # HTML report (Jinja2)
        console_reporter.py # Rich terminal output
    templates/
        report.html.j2      # HTML report template
    data/                   # Reference data files
        check_config.yaml       # Default check configuration
        kernel_binaries.json    # Known Windows kernel binary hashes
        known_good_certs.json
        known_bad_certs.json
        known_debug_devices.json  # JTAG, Bus Pirate, Hak5, etc.
        known_pci_vendors.json
        lol_drivers.json
        offensive_tools.json    # Known offensive tool signatures
        suspicious_imports.json
        suspicious_pipes.json
        suspicious_ports.json
tests/                      # Test suite
```

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See [LICENSE](LICENSE) for the full text.
