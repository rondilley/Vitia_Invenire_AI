"""NET-CONN-001: Active network connections analysis.

Enumerates active TCP connections via psutil and flags connections
on known C2/backdoor ports, as well as external connections from
unexpected processes.
"""

from __future__ import annotations

import importlib.resources
import json

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Processes that are expected to make external connections
_EXPECTED_NETWORK_PROCESSES: set[str] = {
    "svchost.exe",
    "system",
    "lsass.exe",
    "services.exe",
    "msedge.exe",
    "chrome.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "iexplore.exe",
    "microsoftedge.exe",
    "microsoftedgecp.exe",
    "onedrive.exe",
    "outlook.exe",
    "teams.exe",
    "slack.exe",
    "spotify.exe",
    "steam.exe",
    "discord.exe",
    "searchhost.exe",
    "searchui.exe",
    "runtimebroker.exe",
    "backgroundtaskhost.exe",
    "msedgewebview2.exe",
    "windowspackagemanagertaskhost.exe",
    "wuauclt.exe",
    "windows update",
    "microsoftupdate",
    "mpcmdrun.exe",
    "dropbox.exe",
    "googledrivesync.exe",
    "code.exe",
    "devenv.exe",
    "winstore.app",
    "settingssynchost.exe",
}


def _load_suspicious_ports() -> dict[int, dict[str, str]]:
    """Load suspicious ports data from the JSON data file."""
    port_map: dict[int, dict[str, str]] = {}
    try:
        ref = importlib.resources.files("vitia_invenire.data").joinpath("suspicious_ports.json")
        raw = ref.read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(data, list):
            for entry in data:
                port_num = entry.get("port")
                if port_num is not None:
                    port_map[int(port_num)] = {
                        "name": str(entry.get("name", "")),
                        "description": str(entry.get("description", "")),
                    }
    except (FileNotFoundError, json.JSONDecodeError, TypeError, AttributeError):
        return port_map
    return port_map


class NetworkConnectionsCheck(BaseCheck):
    """Analyze active network connections for suspicious activity."""

    CHECK_ID = "NET-CONN-001"
    NAME = "Network Connections Audit"
    DESCRIPTION = (
        "Enumerates active TCP connections and flags connections on "
        "known C2/backdoor ports and external connections from "
        "unexpected processes."
    )
    CATEGORY = Category.NETWORK
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        suspicious_ports = _load_suspicious_ports()

        # Use PowerShell Get-NetTCPConnection for reliable enumeration
        result = run_ps(
            "Get-NetTCPConnection -State Established,Listen -ErrorAction SilentlyContinue | "
            "ForEach-Object { "
            "$proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; "
            "@{ "
            "LocalAddress=$_.LocalAddress; "
            "LocalPort=$_.LocalPort; "
            "RemoteAddress=$_.RemoteAddress; "
            "RemotePort=$_.RemotePort; "
            "State=$_.State.ToString(); "
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
                title="Failed to enumerate network connections",
                description=f"Connection enumeration failed: {result.error or 'unknown error'}",
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="Network Connections",
                evidence=result.output[:500] if result.output else "No output",
                recommendation="Run with appropriate privileges.",
            ))
            return findings

        connections = result.json_output
        if isinstance(connections, dict):
            connections = [connections]

        total_conns = len(connections)
        c2_port_hits = 0
        unexpected_process_hits = 0

        for conn in connections:
            local_addr = str(conn.get("LocalAddress", ""))
            local_port = conn.get("LocalPort", 0)
            remote_addr = str(conn.get("RemoteAddress", ""))
            remote_port = conn.get("RemotePort", 0)
            state = str(conn.get("State", "Unknown"))
            proc_name = str(conn.get("ProcessName", "Unknown"))
            proc_path = str(conn.get("ProcessPath", ""))
            pid = conn.get("OwningProcess", 0)

            try:
                local_port_int = int(local_port)
            except (ValueError, TypeError):
                local_port_int = 0

            try:
                remote_port_int = int(remote_port)
            except (ValueError, TypeError):
                remote_port_int = 0

            conn_str = f"{local_addr}:{local_port_int} -> {remote_addr}:{remote_port_int}"

            # Check if remote port matches known C2 ports
            if remote_port_int in suspicious_ports:
                port_info = suspicious_ports[remote_port_int]
                c2_port_hits += 1
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Connection to known C2 port {remote_port_int} ({port_info['name']})",
                    description=(
                        f"Process '{proc_name}' (PID {pid}) has an active connection "
                        f"to {remote_addr} on port {remote_port_int}, which is associated "
                        f"with {port_info['name']}: {port_info['description']}."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=conn_str,
                    evidence=(
                        f"Connection: {conn_str}\n"
                        f"State: {state}\n"
                        f"Process: {proc_name} (PID {pid})\n"
                        f"Process Path: {proc_path}\n"
                        f"Port Info: {port_info['name']} - {port_info['description']}"
                    ),
                    recommendation=(
                        f"Investigate the connection from '{proc_name}' to port {remote_port_int}. "
                        "Determine if this is legitimate traffic."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1571/",
                    ],
                ))

            # Check if local listening port matches known C2 ports
            if state == "Listen" and local_port_int in suspicious_ports:
                port_info = suspicious_ports[local_port_int]
                c2_port_hits += 1
                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"Listening on known C2 port {local_port_int} ({port_info['name']})",
                    description=(
                        f"Process '{proc_name}' (PID {pid}) is listening on port "
                        f"{local_port_int}, which is associated with {port_info['name']}: "
                        f"{port_info['description']}."
                    ),
                    severity=Severity.HIGH,
                    category=self.CATEGORY,
                    affected_item=f"{local_addr}:{local_port_int}",
                    evidence=(
                        f"Listening: {local_addr}:{local_port_int}\n"
                        f"Process: {proc_name} (PID {pid})\n"
                        f"Process Path: {proc_path}\n"
                        f"Port Info: {port_info['name']} - {port_info['description']}"
                    ),
                    recommendation=(
                        f"Investigate why '{proc_name}' is listening on port {local_port_int}."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1571/",
                    ],
                ))

            # Check for external connections from unexpected processes
            if state == "Established" and remote_addr not in ("127.0.0.1", "::1", "0.0.0.0"):
                proc_lower = proc_name.lower()
                if proc_lower not in _EXPECTED_NETWORK_PROCESSES and proc_lower != "unknown":
                    # Check if it looks like an internal address
                    is_internal = (
                        remote_addr.startswith("10.") or
                        remote_addr.startswith("192.168.") or
                        remote_addr.startswith("172.16.") or
                        remote_addr.startswith("172.17.") or
                        remote_addr.startswith("172.18.") or
                        remote_addr.startswith("172.19.") or
                        remote_addr.startswith("172.2") or
                        remote_addr.startswith("172.3") or
                        remote_addr.startswith("fe80:") or
                        remote_addr.startswith("fd")
                    )

                    if not is_internal:
                        unexpected_process_hits += 1
                        findings.append(Finding(
                            check_id=self.CHECK_ID,
                            title=f"Unexpected external connection: {proc_name}",
                            description=(
                                f"Process '{proc_name}' (PID {pid}) has an external "
                                f"connection to {remote_addr}:{remote_port_int} that is "
                                "not in the expected network processes list."
                            ),
                            severity=Severity.MEDIUM,
                            category=self.CATEGORY,
                            affected_item=conn_str,
                            evidence=(
                                f"Connection: {conn_str}\n"
                                f"State: {state}\n"
                                f"Process: {proc_name} (PID {pid})\n"
                                f"Process Path: {proc_path}"
                            ),
                            recommendation=(
                                f"Verify the external connection from '{proc_name}' is legitimate. "
                                "Investigate the destination address and purpose."
                            ),
                            references=[
                                "https://attack.mitre.org/techniques/T1071/",
                            ],
                        ))

        # Summary
        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="Network connections audit summary",
            description=(
                f"Analyzed {total_conns} TCP connections. "
                f"{c2_port_hits} on known C2/suspicious ports, "
                f"{unexpected_process_hits} unexpected external connections."
            ),
            severity=Severity.INFO,
            category=self.CATEGORY,
            affected_item="Network Connections",
            evidence=(
                f"Total connections: {total_conns}\n"
                f"C2 port matches: {c2_port_hits}\n"
                f"Unexpected processes: {unexpected_process_hits}"
            ),
            recommendation="Monitor network connections regularly.",
        ))

        return findings
