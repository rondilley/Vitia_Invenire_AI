"""ACPI-001: ACPI Table Security Audit.

Checks for the WPBT (Windows Platform Binary Table) ACPI table which
can be used to inject binaries at boot time. Checks for DMAR table
presence indicating VT-d/IOMMU support. Reports all ACPI table
signatures for firmware inventory.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.collectors import registry
from vitia_invenire.models import Category, Finding, Severity

# Known ACPI table signatures and their descriptions
_ACPI_TABLE_DESCRIPTIONS: dict[str, str] = {
    "APIC": "Multiple APIC Description Table (MADT)",
    "BGRT": "Boot Graphics Resource Table",
    "BERT": "Boot Error Record Table",
    "CPEP": "Corrected Platform Error Polling Table",
    "CSRT": "Core System Resource Table",
    "DBG2": "Debug Port Table 2",
    "DBGP": "Debug Port Table",
    "DMAR": "DMA Remapping Table (Intel VT-d)",
    "DRTM": "Dynamic Root of Trust for Measurement",
    "DSDT": "Differentiated System Description Table",
    "ECDT": "Embedded Controller Boot Resources Table",
    "EINJ": "Error Injection Table",
    "ERST": "Error Record Serialization Table",
    "FACP": "Fixed ACPI Description Table (FADT)",
    "FACS": "Firmware ACPI Control Structure",
    "FPDT": "Firmware Performance Data Table",
    "GTDT": "Generic Timer Description Table",
    "HEST": "Hardware Error Source Table",
    "HPET": "High Precision Event Timer Table",
    "IORT": "I/O Remapping Table (ARM)",
    "IVRS": "I/O Virtualization Reporting Structure (AMD Vi)",
    "LPIT": "Low Power Idle Table",
    "MCFG": "PCI Express Memory Mapped Configuration",
    "MCHI": "Management Controller Host Interface",
    "MPST": "Memory Power State Table",
    "MSCT": "Maximum System Characteristics Table",
    "MSDM": "Microsoft Data Management Table",
    "NFIT": "NVDIMM Firmware Interface Table",
    "PCCT": "Platform Communications Channel Table",
    "PPTT": "Processor Properties Topology Table",
    "PSDT": "Persistent System Description Table",
    "RASF": "ACPI RAS Feature Table",
    "RSDT": "Root System Description Table",
    "SBST": "Smart Battery Specification Table",
    "SDEV": "Secure Devices Table",
    "SLIC": "Software Licensing Description Table",
    "SLIT": "System Locality Distance Information Table",
    "SPCR": "Serial Port Console Redirection Table",
    "SPMI": "Server Platform Management Interface Table",
    "SRAT": "System Resource Affinity Table",
    "SSDT": "Secondary System Description Table",
    "STAO": "Status Override Table",
    "TCPA": "Trusted Computing Platform Alliance Table",
    "TPM2": "TPM 2.0 Table",
    "UEFI": "UEFI ACPI Data Table",
    "WAET": "Windows ACPI Emulated Devices Table",
    "WDAT": "Watchdog Action Table",
    "WDDT": "Watchdog Descriptor Table",
    "WDRT": "Watchdog Resource Table",
    "WPBT": "Windows Platform Binary Table",
    "WSMT": "Windows SMM Security Mitigations Table",
    "XSDT": "Extended System Description Table",
}


class ACPITablesCheck(BaseCheck):
    """Audit ACPI tables for security-relevant entries."""

    CHECK_ID = "ACPI-001"
    NAME = "ACPI Table Security Audit"
    DESCRIPTION = (
        "Checks for WPBT ACPI table (firmware-level binary injection), "
        "DMAR table (VT-d/IOMMU support), and reports all ACPI table "
        "signatures for firmware inventory."
    )
    CATEGORY = Category.FIRMWARE
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Enumerate ACPI tables via PowerShell accessing firmware tables
        # Using Get-CimInstance for ACPI table enumeration
        acpi_result = run_ps(
            "$signatures = @(); "
            "try { "
            "  $acpi = Get-CimInstance -Namespace 'root\\wmi' "
            "    -ClassName MSAcpi_ThermalZoneTemperature "
            "    -ErrorAction SilentlyContinue; "
            "} catch { }; "
            "# Get ACPI table signatures via firmware table provider "
            "$tableNames = @(); "
            "try { "
            "  $fw = [System.Runtime.InteropServices.Marshal]; "
            "  $acpiTables = Get-CimInstance -Namespace 'root\\wmi' "
            "    -ClassName MSSMBios_RawSMBiosTables -ErrorAction SilentlyContinue; "
            "} catch { }; "
            "# Use registry to check ACPI entries "
            "$acpiEnum = Get-ChildItem 'HKLM:\\HARDWARE\\ACPI\\' "
            "  -ErrorAction SilentlyContinue | "
            "  Select-Object PSChildName; "
            "$acpiEnum",
            timeout=20,
            as_json=True,
        )

        # Also try direct enumeration via a different method
        table_enum_result = run_ps(
            "Get-ChildItem 'HKLM:\\HARDWARE\\ACPI\\' -ErrorAction SilentlyContinue | "
            "ForEach-Object { $_.PSChildName }",
            timeout=15,
            as_json=False,
        )

        acpi_tables: list[str] = []
        if table_enum_result.success and table_enum_result.output:
            for line in table_enum_result.output.splitlines():
                table_name = line.strip()
                if table_name:
                    acpi_tables.append(table_name)

        # Try another approach to get ACPI tables
        if not acpi_tables:
            fw_table_result = run_ps(
                "try { "
                "  Add-Type -TypeDefinition @'"
                "    using System; "
                "    using System.Runtime.InteropServices; "
                "    public class FirmwareTable { "
                "      [DllImport(\"kernel32.dll\", SetLastError=true)] "
                "      public static extern uint EnumSystemFirmwareTables(uint FirmwareTableProviderSignature, IntPtr pFirmwareTableEnumBuffer, uint BufferSize); "
                "    } "
                "'@ -ErrorAction SilentlyContinue; "
                "  $acpiSig = [BitConverter]::ToUInt32([Text.Encoding]::ASCII.GetBytes('ACPI'), 0); "
                "  $size = [FirmwareTable]::EnumSystemFirmwareTables($acpiSig, [IntPtr]::Zero, 0); "
                "  if ($size -gt 0) { "
                "    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size); "
                "    [FirmwareTable]::EnumSystemFirmwareTables($acpiSig, $buf, $size) | Out-Null; "
                "    $bytes = New-Object byte[] $size; "
                "    [System.Runtime.InteropServices.Marshal]::Copy($buf, $bytes, 0, $size); "
                "    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf); "
                "    for ($i = 0; $i -lt $bytes.Length; $i += 4) { "
                "      if ($i + 4 -le $bytes.Length) { "
                "        [Text.Encoding]::ASCII.GetString($bytes, $i, 4) "
                "      } "
                "    } "
                "  } "
                "} catch { "
                "  'ERROR: ' + $_.Exception.Message "
                "}",
                timeout=15,
                as_json=False,
            )

            if fw_table_result.success and fw_table_result.output:
                for line in fw_table_result.output.splitlines():
                    table_name = line.strip()
                    if (
                        table_name
                        and not table_name.startswith("ERROR:")
                        and len(table_name) == 4
                    ):
                        acpi_tables.append(table_name)

        # Deduplicate
        acpi_tables = list(dict.fromkeys(acpi_tables))

        # Check for WPBT
        has_wpbt = any(t.upper() == "WPBT" for t in acpi_tables)
        if has_wpbt:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WPBT ACPI Table Present",
                description=(
                    "The Windows Platform Binary Table (WPBT) is present in "
                    "firmware. WPBT allows the BIOS/UEFI to inject an "
                    "executable binary into Windows at every boot, before "
                    "the OS loads. This is used by OEMs for persistent "
                    "software installation but has been abused for rootkit "
                    "persistence (e.g., Lenovo Superfish, Computrace/LoJack). "
                    "Cross-reference with WPBT-001 check for binary analysis."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="WPBT ACPI Table",
                evidence=(
                    "ACPI table WPBT detected in firmware enumeration.\n"
                    "WPBT enables firmware-level binary injection into Windows."
                ),
                recommendation=(
                    "Investigate the WPBT binary content. Check if the OEM "
                    "has a legitimate use for WPBT. If the binary is unknown "
                    "or suspicious, consider a BIOS update that removes WPBT "
                    "or contact the OEM. Cross-reference with WPBT-001 check."
                ),
                references=[
                    "https://docs.microsoft.com/en-us/windows-hardware/drivers/bringup/windows-platform-binary-table",
                    "https://eclypsium.com/2018/01/15/system-firmware-threats/",
                ],
            ))

        # Check for DMAR (Intel VT-d)
        has_dmar = any(t.upper() == "DMAR" for t in acpi_tables)
        has_ivrs = any(t.upper() == "IVRS" for t in acpi_tables)

        if has_dmar:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="DMAR Table Present (Intel VT-d Supported)",
                description=(
                    "The DMA Remapping Table (DMAR) is present, indicating "
                    "Intel VT-d IOMMU hardware support. VT-d provides DMA "
                    "protection against hardware-based attacks such as "
                    "Thunderbolt DMA attacks."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="DMAR ACPI Table",
                evidence="DMAR table present - Intel VT-d hardware available.",
                recommendation=(
                    "Ensure VT-d is enabled in BIOS settings and Windows "
                    "Kernel DMA Protection is active."
                ),
                references=[
                    "https://docs.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt",
                ],
            ))
        elif has_ivrs:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="IVRS Table Present (AMD Vi Supported)",
                description=(
                    "The I/O Virtualization Reporting Structure (IVRS) is "
                    "present, indicating AMD-Vi IOMMU hardware support."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="IVRS ACPI Table",
                evidence="IVRS table present - AMD-Vi hardware available.",
                recommendation="Ensure AMD-Vi is enabled in BIOS settings.",
                references=[
                    "https://docs.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt",
                ],
            ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No IOMMU Table Found (DMAR/IVRS)",
                description=(
                    "Neither DMAR (Intel VT-d) nor IVRS (AMD-Vi) ACPI tables "
                    "were found. Without IOMMU support, the system is "
                    "vulnerable to DMA-based attacks via Thunderbolt, PCI "
                    "Express, and other DMA-capable interfaces."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="IOMMU ACPI Table",
                evidence="Neither DMAR nor IVRS table found in ACPI enumeration.",
                recommendation=(
                    "Enable VT-d (Intel) or AMD-Vi in BIOS settings if "
                    "supported by the hardware."
                ),
                references=[
                    "https://docs.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt",
                ],
            ))

        # Check WSMT (Windows SMM Security Mitigations Table)
        has_wsmt = any(t.upper() == "WSMT" for t in acpi_tables)
        if not has_wsmt and acpi_tables:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WSMT Table Not Present",
                description=(
                    "The Windows SMM Security Mitigations Table (WSMT) is "
                    "not present. WSMT confirms that firmware has implemented "
                    "SMM security mitigations required for Virtualization-Based "
                    "Security (VBS) features."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="WSMT ACPI Table",
                evidence="WSMT table not found in ACPI enumeration.",
                recommendation=(
                    "Update firmware to a version that includes WSMT support "
                    "for full VBS compatibility."
                ),
                references=[
                    "https://docs.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs",
                ],
            ))

        # Report all ACPI table signatures
        if acpi_tables:
            evidence_lines = []
            for table in sorted(acpi_tables):
                desc = _ACPI_TABLE_DESCRIPTIONS.get(
                    table.upper(), "Unknown/vendor-specific table"
                )
                evidence_lines.append(f"  {table}: {desc}")

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="ACPI Table Inventory",
                description=f"Found {len(acpi_tables)} ACPI table signature(s) in firmware.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="ACPI Tables",
                evidence="\n".join(evidence_lines),
                recommendation=(
                    "Review ACPI table inventory for unexpected or unknown tables."
                ),
                references=[
                    "https://uefi.org/specifications",
                ],
            ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Unable to Enumerate ACPI Tables",
                description=(
                    "Could not enumerate ACPI table signatures. This may be "
                    "due to insufficient privileges or platform limitations."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="ACPI Tables",
                evidence="ACPI table enumeration returned no results.",
                recommendation=(
                    "Run the check with administrator privileges. Some systems "
                    "may restrict firmware table access."
                ),
                references=[
                    "https://uefi.org/specifications",
                ],
            ))

        return findings
