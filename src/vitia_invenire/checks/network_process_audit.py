"""NET-PROC-001: Network process and adapter audit.

Detects listening processes, raw sockets, promiscuous mode NICs,
NDIS filter drivers, packet capture libraries (npcap/winpcap),
and unexpected DNS listeners.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry, wmi_collector
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Processes that are expected to listen on network ports
_EXPECTED_LISTENERS: set[str] = {
    "system", "svchost.exe", "lsass.exe", "services.exe",
    "wininit.exe", "dns.exe", "w3svc.exe", "httpd.exe",
    "spoolsv.exe", "searchindexer.exe", "msdtc.exe",
    "sqlservr.exe", "mysqld.exe", "postgres.exe",
    "iisexpress.exe", "dfsrs.exe", "dfssvc.exe",
    "smss.exe", "csrss.exe", "winlogon.exe",
}


class NetworkProcessAuditCheck(BaseCheck):
    """Detect suspicious network-related processes and adapters."""

    CHECK_ID = "NET-PROC-001"
    NAME = "Network Process and Adapter Audit"
    DESCRIPTION = (
        "Detects listening processes, raw sockets, promiscuous mode "
        "network adapters, NDIS filter drivers, packet capture libraries "
        "(npcap/winpcap), and DNS listeners on port 53."
    )
    CATEGORY = Category.NETWORK
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        self._check_listening_processes(findings)
        self._check_packet_capture_libraries(findings)
        self._check_ndis_filter_drivers(findings)
        self._check_dns_listeners(findings)
        self._check_promiscuous_mode(findings)

        return findings

    def _check_listening_processes(self, findings: list[Finding]) -> None:
        """Enumerate listening processes and flag unexpected ones."""
        result = run_ps(
            "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
            "ForEach-Object { "
            "$proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; "
            "@{ "
            "LocalAddress=$_.LocalAddress; "
            "LocalPort=$_.LocalPort; "
            "OwningProcess=$_.OwningProcess; "
            "ProcessName=if($proc){$proc.Name}else{'Unknown'}; "
            "ProcessPath=if($proc){$proc.Path}else{''} "
            "} }",
            timeout=30,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Failed to enumerate listening processes",
                description=f"Get-NetTCPConnection failed: {result.error or 'unknown'}",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Listening Processes",
                evidence=result.output[:500] if result.output else "No output",
                recommendation="Run with appropriate privileges.",
            ))
            return

        listeners = result.json_output
        if isinstance(listeners, dict):
            listeners = [listeners]

        unexpected_count = 0
        total_listeners = len(listeners)

        # Build context inventory for the report
        listener_inventory = []
        for l in listeners:
            listener_inventory.append({
                "address": f"{l.get('LocalAddress', '')}:{l.get('LocalPort', '')}",
                "process": str(l.get("ProcessName", "Unknown")),
                "pid": l.get("OwningProcess", 0),
                "path": str(l.get("ProcessPath", "")),
            })
        self.context = {
            "total_listeners": total_listeners,
            "listeners": listener_inventory,
        }

        for listener in listeners:
            local_addr = str(listener.get("LocalAddress", ""))
            local_port = listener.get("LocalPort", 0)
            proc_name = str(listener.get("ProcessName", "Unknown"))
            proc_path = str(listener.get("ProcessPath", ""))
            pid = listener.get("OwningProcess", 0)

            try:
                port_int = int(local_port)
            except (ValueError, TypeError):
                port_int = 0

            proc_lower = proc_name.lower()
            if proc_lower not in _EXPECTED_LISTENERS and proc_lower != "unknown":
                unexpected_count += 1

                # Determine if this is a high-risk listener
                # External-facing listeners on all interfaces (0.0.0.0 or ::)
                is_all_interfaces = local_addr in ("0.0.0.0", "::", "[::]")

                severity = Severity.MEDIUM
                if is_all_interfaces and port_int < 1024:
                    severity = Severity.HIGH

                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Unexpected listener: {proc_name} on port {port_int}",
                    description=(
                        f"Process '{proc_name}' (PID {pid}) is listening on "
                        f"{local_addr}:{port_int} and is not in the expected listeners list. "
                        f"{'Listening on all interfaces.' if is_all_interfaces else 'Listening on specific interface.'}"
                    ),
                    severity=severity,
                    category=self.CATEGORY,
                    affected_item=f"{local_addr}:{port_int}",
                    evidence=(
                        f"Process: {proc_name} (PID {pid})\n"
                        f"Path: {proc_path}\n"
                        f"Listening: {local_addr}:{port_int}"
                    ),
                    recommendation=(
                        f"Investigate why '{proc_name}' is listening on port {port_int}. "
                        "Determine if this is legitimate."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1571/",
                    ],
                ))

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Listening process enumeration summary",
            description=(
                f"Found {total_listeners} listening ports, "
                f"{unexpected_count} from unexpected processes."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Listening Processes",
            evidence=f"Total listeners: {total_listeners}, Unexpected: {unexpected_count}",
            recommendation="Review listening processes regularly.",
        ))

    def _check_packet_capture_libraries(self, findings: list[Finding]) -> None:
        """Check for packet capture libraries (npcap, winpcap) via registry and loaded DLLs."""
        # Check npcap via registry
        npcap_path = r"SOFTWARE\Npcap"
        npcap_vals = registry.read_key(registry.HKEY_LOCAL_MACHINE, npcap_path)

        if npcap_vals:
            evidence_lines = [f"{v.name} = {v.data}" for v in npcap_vals]
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="Npcap packet capture library installed",
                description=(
                    "Npcap is installed on this system. While Npcap is a legitimate "
                    "packet capture library, it enables promiscuous mode network "
                    "monitoring and can be used for credential sniffing."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Npcap",
                evidence="\n".join(evidence_lines),
                recommendation=(
                    "Verify Npcap is required (e.g., for Wireshark, Nmap). "
                    "Remove if not needed."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1040/",
                ],
            ))

        # Check winpcap via registry
        winpcap_path = r"SOFTWARE\WinPcap"
        winpcap_vals = registry.read_key(registry.HKEY_LOCAL_MACHINE, winpcap_path)

        if winpcap_vals:
            evidence_lines = [f"{v.name} = {v.data}" for v in winpcap_vals]
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WinPcap packet capture library installed",
                description=(
                    "The legacy WinPcap library is installed. WinPcap is outdated and "
                    "no longer maintained. It enables raw packet capture and can be "
                    "used for network sniffing attacks."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="WinPcap",
                evidence="\n".join(evidence_lines),
                recommendation=(
                    "Replace WinPcap with Npcap if packet capture is needed, "
                    "or remove entirely if not required."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1040/",
                ],
            ))

        # Check for loaded packet capture DLLs via running processes
        dll_result = run_ps(
            "Get-Process | ForEach-Object { "
            "try { "
            "$_.Modules | Where-Object { "
            "$_.ModuleName -match 'wpcap|npcap|packet\\.dll|npf\\.sys' "
            "} | ForEach-Object { "
            "@{ ProcessName=$_.ToString(); ModuleName=$_.ModuleName; FileName=$_.FileName; PID=$_.BaseAddress } "
            "} } catch {} }",
            timeout=30,
            as_json=True,
        )

        if dll_result.success and dll_result.json_output is not None:
            dll_data = dll_result.json_output
            if isinstance(dll_data, dict):
                dll_data = [dll_data]

            if dll_data:
                dll_evidence = "\n".join(
                    f"Process: {d.get('ProcessName', 'Unknown')}, "
                    f"Module: {d.get('ModuleName', 'Unknown')}, "
                    f"File: {d.get('FileName', 'Unknown')}"
                    for d in dll_data
                )
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title="Packet capture DLLs loaded in running processes",
                    description=(
                        f"Found {len(dll_data)} process(es) with packet capture "
                        "libraries loaded. These processes can capture raw network traffic."
                    ),
                    severity=Severity.MEDIUM,
                    category=self.CATEGORY,
                    affected_item="Packet Capture DLLs",
                    evidence=dll_evidence,
                    recommendation="Verify these processes are legitimate tools.",
                ))

    def _check_ndis_filter_drivers(self, findings: list[Finding]) -> None:
        """Check for NDIS filter drivers that may intercept network traffic."""
        ndis_rows = wmi_collector.query(
            "Win32_SystemDriver",
            properties=["Name", "DisplayName", "PathName", "State", "StartMode"],
            where="ServiceType='Kernel Driver' AND State='Running'",
        )

        ndis_keywords = ["ndis", "filter", "intercept", "inspect", "packet", "network filter"]
        ndis_drivers: list[dict] = []

        for row in ndis_rows:
            name = str(row.get("Name", "")).lower()
            display = str(row.get("DisplayName", "")).lower()
            combined = f"{name} {display}"

            if any(kw in combined for kw in ndis_keywords):
                # Skip known Microsoft NDIS drivers
                ms_ndis = ["ndis.sys", "ndisuio", "ndiswan", "ndistapi",
                           "ndisvirtualbus", "ndproxy", "netbt"]
                if not any(ms in name for ms in ms_ndis):
                    ndis_drivers.append(row)

        if ndis_drivers:
            evidence_lines = [
                f"{d.get('DisplayName', d.get('Name', 'Unknown'))}: "
                f"{d.get('PathName', 'Unknown')} (State: {d.get('State', 'Unknown')})"
                for d in ndis_drivers
            ]
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"Non-Microsoft NDIS filter drivers detected ({len(ndis_drivers)})",
                description=(
                    "NDIS filter drivers intercept network traffic at the driver level. "
                    "While some are legitimate (VPN, firewall), they can also be used "
                    "for traffic interception or manipulation."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="NDIS Filter Drivers",
                evidence="\n".join(evidence_lines),
                recommendation="Verify all NDIS filter drivers are from trusted sources.",
                references=[
                    "https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ndis-filter-drivers",
                ],
            ))

    def _check_dns_listeners(self, findings: list[Finding]) -> None:
        """Check for processes listening on DNS port 53."""
        result = run_ps(
            "Get-NetTCPConnection -LocalPort 53 -State Listen -ErrorAction SilentlyContinue | "
            "ForEach-Object { "
            "$proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; "
            "@{ "
            "LocalAddress=$_.LocalAddress; "
            "ProcessName=if($proc){$proc.Name}else{'Unknown'}; "
            "ProcessPath=if($proc){$proc.Path}else{''}; "
            "PID=$_.OwningProcess "
            "} }",
            timeout=15,
            as_json=True,
        )

        # Also check UDP port 53
        udp_result = run_ps(
            "Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue | "
            "ForEach-Object { "
            "$proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; "
            "@{ "
            "LocalAddress=$_.LocalAddress; "
            "Protocol='UDP'; "
            "ProcessName=if($proc){$proc.Name}else{'Unknown'}; "
            "ProcessPath=if($proc){$proc.Path}else{''}; "
            "PID=$_.OwningProcess "
            "} }",
            timeout=15,
            as_json=True,
        )

        dns_listeners: list[dict] = []

        for res in [result, udp_result]:
            if res.success and res.json_output is not None:
                data = res.json_output
                if isinstance(data, dict):
                    data = [data]
                dns_listeners.extend(data)

        if dns_listeners:
            for listener in dns_listeners:
                proc_name = str(listener.get("ProcessName", "Unknown"))
                proc_path = str(listener.get("ProcessPath", ""))
                local_addr = str(listener.get("LocalAddress", ""))
                pid = listener.get("PID", 0)
                protocol = str(listener.get("Protocol", "TCP"))

                # dns.exe is the only expected DNS listener on a non-DC
                is_expected = proc_name.lower() in ("dns", "dns.exe", "system")

                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"DNS listener detected: {proc_name} on port 53/{protocol}",
                    description=(
                        f"Process '{proc_name}' (PID {pid}) is listening on DNS "
                        f"port 53 ({protocol}). {'This is expected on a DNS server.' if is_expected else 'Unexpected DNS listeners may indicate DNS tunneling, DNS hijacking, or a rogue DNS server.'}"
                    ),
                    severity=Severity.INFO if is_expected else Severity.CRITICAL,
                    category=self.CATEGORY,
                    affected_item=f"{local_addr}:53/{protocol}",
                    evidence=(
                        f"Process: {proc_name} (PID {pid})\n"
                        f"Path: {proc_path}\n"
                        f"Listening: {local_addr}:53/{protocol}"
                    ),
                    recommendation=(
                        "No action needed." if is_expected else
                        f"Investigate immediately why '{proc_name}' is listening on DNS port 53. "
                        "This may indicate DNS tunneling for data exfiltration."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1071/004/",
                    ],
                ))

    def _check_promiscuous_mode(self, findings: list[Finding]) -> None:
        """Check for network adapters in promiscuous mode."""
        result = run_ps(
            "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | "
            "ForEach-Object { "
            "$adapter = $_; "
            "$adv = Get-NetAdapterAdvancedProperty -Name $adapter.Name "
            "-RegistryKeyword '*MonitorMode' -ErrorAction SilentlyContinue; "
            "@{ "
            "Name=$adapter.Name; "
            "InterfaceDescription=$adapter.InterfaceDescription; "
            "MacAddress=$adapter.MacAddress; "
            "Status=$adapter.Status.ToString(); "
            "MonitorMode=if($adv){$adv.RegistryValue}else{'NotSet'} "
            "} }",
            timeout=20,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            return

        adapters = result.json_output
        if isinstance(adapters, dict):
            adapters = [adapters]

        for adapter in adapters:
            name = str(adapter.get("Name", "Unknown"))
            desc = str(adapter.get("InterfaceDescription", ""))
            mac = str(adapter.get("MacAddress", ""))
            monitor = str(adapter.get("MonitorMode", "NotSet"))

            if monitor not in ("NotSet", "0", ""):
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Network adapter in monitor/promiscuous mode: {name}",
                    description=(
                        f"Network adapter '{name}' ({desc}) has monitor mode enabled. "
                        "This allows capturing all network traffic on the segment, "
                        "not just traffic destined for this host."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=f"Adapter: {name}",
                    evidence=(
                        f"Adapter: {name}\n"
                        f"Description: {desc}\n"
                        f"MAC: {mac}\n"
                        f"Monitor Mode: {monitor}"
                    ),
                    recommendation=(
                        "Disable monitor/promiscuous mode unless required for "
                        "legitimate network monitoring."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1040/",
                    ],
                ))
