"""VSS-001: Volume Shadow Copy Service Audit.

Checks shadow copy status, Volume Shadow Copy Service (VSS) and
Microsoft Software Shadow Copy Provider (SWPRV) service status.
Attackers commonly disable VSS to prevent backup and recovery,
particularly during ransomware attacks.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity


class VSSAuditCheck(BaseCheck):
    """Audit Volume Shadow Copy service and shadow copy status."""

    CHECK_ID = "VSS-001"
    NAME = "VSS and Shadow Copy Audit"
    DESCRIPTION = (
        "Checks Volume Shadow Copy Service (VSS) and SWPRV service "
        "status. Enumerates existing shadow copies. VSS disabled or "
        "shadow copies deleted may indicate ransomware preparation."
    )
    CATEGORY = Category.CONFIGURATION
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Check VSS service status
        vss_svc_result = run_ps(
            "Get-Service -Name VSS -ErrorAction SilentlyContinue | "
            "Select-Object Name, Status, StartType, DisplayName",
            timeout=15,
            as_json=True,
        )

        # Check SWPRV (Microsoft Software Shadow Copy Provider) service
        swprv_svc_result = run_ps(
            "Get-Service -Name SWPRV -ErrorAction SilentlyContinue | "
            "Select-Object Name, Status, StartType, DisplayName",
            timeout=15,
            as_json=True,
        )

        vss_disabled = False
        swprv_disabled = False
        svc_evidence_parts: list[str] = []

        for label, svc_result in [("VSS", vss_svc_result), ("SWPRV", swprv_svc_result)]:
            if svc_result.success and svc_result.json_output:
                svc_data = svc_result.json_output
                if isinstance(svc_data, list):
                    svc_data = svc_data[0] if svc_data else {}
                start_type = str(svc_data.get("StartType", ""))
                status = str(svc_data.get("Status", "")).lower()
                display_name = str(svc_data.get("DisplayName", label))

                # StartType: 4=Disabled, 3=Manual, 2=Automatic
                is_disabled = start_type.lower() in ("disabled", "4")
                if label == "VSS":
                    vss_disabled = is_disabled
                else:
                    swprv_disabled = is_disabled

                status_text = "Running" if status in ("running", "4") else "Stopped"
                svc_evidence_parts.append(
                    f"{display_name} ({label}):\n"
                    f"  Status: {status_text}\n"
                    f"  Start Type: {start_type}"
                )
            else:
                svc_evidence_parts.append(f"{label}: Service not found")

        if vss_disabled or swprv_disabled:
            disabled_names = []
            if vss_disabled:
                disabled_names.append("VSS")
            if swprv_disabled:
                disabled_names.append("SWPRV")

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Volume Shadow Copy Service Disabled",
                description=(
                    f"The {' and '.join(disabled_names)} service(s) "
                    f"{'is' if len(disabled_names) == 1 else 'are'} disabled. "
                    f"Disabling VSS prevents the creation of shadow copies, "
                    f"which are essential for backup and recovery. Ransomware "
                    f"frequently disables VSS before encrypting files."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="VSS/SWPRV Services",
                evidence="\n\n".join(svc_evidence_parts),
                recommendation=(
                    "Re-enable the VSS and SWPRV services (set Start Type to "
                    "Manual or Automatic). Investigate why the services were "
                    "disabled and check for signs of ransomware activity."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1490/",
                ],
            ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="VSS Service Configuration",
                description="VSS and SWPRV services are not disabled.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="VSS/SWPRV Services",
                evidence="\n\n".join(svc_evidence_parts),
                recommendation="No action required.",
                references=[
                    "https://attack.mitre.org/techniques/T1490/",
                ],
            ))

        # Enumerate existing shadow copies
        shadow_result = run_ps(
            "Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | "
            "Select-Object ID, VolumeName, InstallDate, DeviceObject, "
            "ServiceMachine, @{Name='SizeGB';Expression={"
            "[math]::Round($_.Count / 1GB, 2)}}",
            timeout=20,
            as_json=True,
        )

        shadow_copies: list[dict] = []
        if shadow_result.success and shadow_result.json_output:
            data = shadow_result.json_output
            if isinstance(data, dict):
                shadow_copies = [data]
            elif isinstance(data, list):
                shadow_copies = data

        if shadow_copies:
            evidence_lines = []
            for sc in shadow_copies:
                evidence_lines.append(
                    f"Shadow Copy: {sc.get('ID', 'Unknown')}\n"
                    f"  Volume: {sc.get('VolumeName', 'Unknown')}\n"
                    f"  Created: {sc.get('InstallDate', 'Unknown')}\n"
                    f"  Device: {sc.get('DeviceObject', 'Unknown')}"
                )
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Shadow Copies Found",
                description=(
                    f"{len(shadow_copies)} shadow copy/copies found on the system. "
                    f"Shadow copies provide backup and recovery capability."
                ),
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="Shadow Copies",
                evidence="\n\n".join(evidence_lines),
                recommendation=(
                    "Verify shadow copies are being created on a regular schedule."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1490/",
                ],
            ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="No Shadow Copies Found",
                description=(
                    "No volume shadow copies exist on the system. This may "
                    "indicate shadow copies were deleted (vssadmin delete "
                    "shadows), have never been configured, or VSS is disabled."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="Shadow Copies",
                evidence="Win32_ShadowCopy query returned no results.",
                recommendation=(
                    "Configure System Restore or scheduled shadow copies. "
                    "If shadow copies previously existed, investigate whether "
                    "they were intentionally or maliciously deleted."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1490/",
                ],
            ))

        # Check for recent vssadmin delete commands in event logs
        vss_delete_result = run_ps(
            "Get-WinEvent -FilterHashtable @{LogName='Application'; "
            "ProviderName='VSS'; Level=2,3} -MaxEvents 20 "
            "-ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated, Id, LevelDisplayName, Message",
            timeout=15,
            as_json=True,
        )

        if vss_delete_result.success and vss_delete_result.json_output:
            vss_events = vss_delete_result.json_output
            if isinstance(vss_events, dict):
                vss_events = [vss_events]

            if vss_events:
                evidence_lines = []
                for evt in vss_events[:10]:
                    msg = str(evt.get("Message", ""))[:200]
                    evidence_lines.append(
                        f"Time: {evt.get('TimeCreated', 'Unknown')}\n"
                        f"  Event ID: {evt.get('Id', 'Unknown')}\n"
                        f"  Level: {evt.get('LevelDisplayName', 'Unknown')}\n"
                        f"  Message: {msg}"
                    )
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="VSS Warning/Error Events Found",
                    description=(
                        f"{len(vss_events)} VSS warning or error event(s) found "
                        f"in the Application log. These may indicate VSS failures "
                        f"or deliberate shadow copy manipulation."
                    ),
                    severity=Severity.LOW,
                    category=self.CATEGORY,
                    affected_item="VSS Events",
                    evidence="\n\n".join(evidence_lines),
                    recommendation=(
                        "Review VSS error events for signs of shadow copy deletion "
                        "or service disruption."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1490/",
                    ],
                ))

        return findings
