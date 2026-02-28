"""WPAD-001: WPAD, LLMNR, NetBIOS, and mDNS Configuration Audit.

Checks Web Proxy Auto-Discovery (WPAD), Link-Local Multicast Name
Resolution (LLMNR), NetBIOS over TCP/IP, and mDNS settings. These
name resolution protocols are commonly exploited for man-in-the-middle
attacks and credential relay.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import registry
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity

# Registry paths
_LLMNR_PATH = "SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient"
_WPAD_PATH = "SYSTEM\\CurrentControlSet\\Services\\WinHttpAutoProxySvc"
_NETBIOS_PATH = "SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces"
_MDNS_PATH = "SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters"


class WPADLLMNRCheck(BaseCheck):
    """Audit WPAD, LLMNR, NetBIOS, and mDNS configuration."""

    CHECK_ID = "WPAD-001"
    NAME = "WPAD/LLMNR/NetBIOS/mDNS Audit"
    DESCRIPTION = (
        "Checks WPAD proxy auto-discovery, LLMNR, NetBIOS over TCP/IP, "
        "and mDNS settings. These protocols are common targets for "
        "man-in-the-middle and credential relay attacks."
    )
    CATEGORY = Category.NETWORK
    REQUIRES_ADMIN = False

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Check LLMNR status via registry
        # EnableMulticast: 0 = disabled, 1 = enabled (or not set = enabled)
        llmnr_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _LLMNR_PATH, "EnableMulticast"
        )

        llmnr_enabled = True  # Default is enabled
        if llmnr_val is not None:
            llmnr_enabled = llmnr_val.data != 0

        if llmnr_enabled:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="LLMNR Is Enabled",
                description=(
                    "Link-Local Multicast Name Resolution (LLMNR) is enabled. "
                    "LLMNR responds to multicast name queries on the local "
                    "network, which allows attackers to intercept and respond "
                    "with poisoned answers to capture NTLMv2 hashes via tools "
                    "like Responder."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="LLMNR Configuration",
                evidence=(
                    f"HKLM\\{_LLMNR_PATH}\\EnableMulticast: "
                    f"{llmnr_val.data if llmnr_val else 'Not set (default=enabled)'}"
                ),
                recommendation=(
                    "Disable LLMNR via Group Policy: Computer Configuration > "
                    "Administrative Templates > Network > DNS Client > "
                    "Turn off multicast name resolution = Enabled. "
                    "Or set HKLM\\{path}\\EnableMulticast = 0.".format(
                        path=_LLMNR_PATH
                    )
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1557/001/",
                    "https://www.sternsecurity.com/blog/local-network-attacks-llmnr-and-nbt-ns-poisoning",
                ],
            ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="LLMNR Is Disabled",
                description="LLMNR is disabled via Group Policy or registry.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="LLMNR Configuration",
                evidence=f"HKLM\\{_LLMNR_PATH}\\EnableMulticast = 0",
                recommendation="No action required. LLMNR is properly disabled.",
                references=[
                    "https://attack.mitre.org/techniques/T1557/001/",
                ],
            ))

        # Check NetBIOS over TCP/IP status
        # NodeType in DNSClient: 1=B-node, 2=P-node, 4=M-node, 8=H-node
        # NetbiosOptions per interface: 0=default, 1=enabled, 2=disabled
        netbios_result = run_ps(
            "Get-NetAdapter -Physical -ErrorAction SilentlyContinue | "
            "ForEach-Object { "
            "  $config = $_ | Get-NetAdapterBinding -ComponentId ms_netbt "
            "    -ErrorAction SilentlyContinue; "
            "  $wmi = Get-CimInstance Win32_NetworkAdapterConfiguration "
            "    -Filter \"InterfaceIndex=$($_.InterfaceIndex)\" "
            "    -ErrorAction SilentlyContinue; "
            "  [PSCustomObject]@{ "
            "    Name = $_.Name; "
            "    NetBTEnabled = if ($config) { $config.Enabled } else { $null }; "
            "    TcpipNetbiosOptions = if ($wmi) { $wmi.TcpipNetbiosOptions } else { $null } "
            "  } "
            "}",
            timeout=15,
            as_json=True,
        )

        netbios_enabled_ifaces: list[str] = []
        netbios_evidence: list[str] = []

        if netbios_result.success and netbios_result.json_output:
            ifaces = netbios_result.json_output
            if isinstance(ifaces, dict):
                ifaces = [ifaces]

            for iface in ifaces:
                name = str(iface.get("Name", "Unknown"))
                nbt_enabled = iface.get("NetBTEnabled")
                nbt_options = iface.get("TcpipNetbiosOptions")

                # TcpipNetbiosOptions: 0=Default(DHCP), 1=Enabled, 2=Disabled
                is_enabled = True
                if nbt_options == 2:
                    is_enabled = False
                elif nbt_enabled is False:
                    is_enabled = False

                options_desc = {0: "Default (DHCP)", 1: "Enabled", 2: "Disabled"}
                opt_text = options_desc.get(nbt_options, str(nbt_options))

                netbios_evidence.append(
                    f"  {name}: NetBIOS={opt_text}"
                )

                if is_enabled:
                    netbios_enabled_ifaces.append(name)

        if netbios_enabled_ifaces:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="NetBIOS Over TCP/IP Enabled",
                description=(
                    f"NetBIOS over TCP/IP is enabled on {len(netbios_enabled_ifaces)} "
                    f"interface(s). NetBIOS Name Service (NBNS/NBT-NS) is "
                    f"vulnerable to the same poisoning attacks as LLMNR and "
                    f"can be used by tools like Responder to capture NTLMv2 "
                    f"hashes."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="NetBIOS over TCP/IP",
                evidence="\n".join(netbios_evidence),
                recommendation=(
                    "Disable NetBIOS over TCP/IP on all network interfaces: "
                    "Network adapter properties > IPv4 > Advanced > WINS > "
                    "Disable NetBIOS over TCP/IP. Or configure via DHCP "
                    "option 001 (NetBIOS node type = 0x02)."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1557/001/",
                ],
            ))

        # Check WPAD configuration
        # Check WinHTTP Auto-Proxy Service
        wpad_svc = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _WPAD_PATH, "Start"
        )

        # Check Internet Settings for auto-detect
        auto_detect = registry.read_value(
            registry.HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            "AutoDetect",
        )

        auto_config_url = registry.read_value(
            registry.HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            "AutoConfigURL",
        )

        wpad_enabled = False
        wpad_evidence_parts: list[str] = []

        if wpad_svc is not None:
            # Start: 2=Automatic, 3=Manual, 4=Disabled
            svc_states = {2: "Automatic", 3: "Manual", 4: "Disabled"}
            svc_state = svc_states.get(wpad_svc.data, str(wpad_svc.data))
            wpad_evidence_parts.append(f"WinHttpAutoProxySvc Start: {svc_state}")

        if auto_detect is not None:
            wpad_evidence_parts.append(f"AutoDetect: {auto_detect.data}")
            if auto_detect.data == 1:
                wpad_enabled = True
        else:
            wpad_evidence_parts.append("AutoDetect: Not set (default may vary)")

        if auto_config_url is not None:
            wpad_evidence_parts.append(f"AutoConfigURL: {auto_config_url.data}")
            if auto_config_url.data:
                pac_url = str(auto_config_url.data).lower()
                if "wpad" in pac_url:
                    wpad_enabled = True

        if wpad_enabled:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WPAD Auto-Discovery Is Enabled",
                description=(
                    "Web Proxy Auto-Discovery (WPAD) is enabled. WPAD "
                    "automatically configures proxy settings by querying "
                    "for wpad.dat files via DNS and LLMNR/NBT-NS. Attackers "
                    "can serve a malicious WPAD configuration to redirect "
                    "and intercept all HTTP traffic."
                ),
                severity=Severity.MEDIUM,
                category=self.CATEGORY,
                affected_item="WPAD Configuration",
                evidence="\n".join(wpad_evidence_parts),
                recommendation=(
                    "Disable WPAD auto-detection unless specifically required. "
                    "Set AutoDetect to 0 in Internet Settings. If a proxy is "
                    "needed, configure it explicitly via Group Policy rather "
                    "than using auto-detection."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1557/001/",
                    "https://www.praetorian.com/blog/a-]guide-to-attacking-wpad/",
                ],
            ))
        else:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="WPAD Auto-Discovery Status",
                description="WPAD auto-detection does not appear to be actively enabled.",
                severity=Severity.INFO,
                category=self.CATEGORY,
                affected_item="WPAD Configuration",
                evidence="\n".join(wpad_evidence_parts) if wpad_evidence_parts else "No WPAD configuration found.",
                recommendation="No action required.",
                references=[
                    "https://attack.mitre.org/techniques/T1557/001/",
                ],
            ))

        # Check mDNS configuration
        mdns_val = registry.read_value(
            registry.HKEY_LOCAL_MACHINE, _MDNS_PATH, "EnableMDNS"
        )

        mdns_enabled = True  # Default on Windows 10+
        if mdns_val is not None:
            mdns_enabled = mdns_val.data != 0

        if mdns_enabled:
            findings.append(Finding(
                check_id=self.CHECK_ID,
                title="mDNS Is Enabled",
                description=(
                    "Multicast DNS (mDNS) is enabled. mDNS can be used for "
                    "local network name resolution poisoning similar to LLMNR. "
                    "While less commonly exploited, it provides another avenue "
                    "for name resolution attacks."
                ),
                severity=Severity.LOW,
                category=self.CATEGORY,
                affected_item="mDNS Configuration",
                evidence=(
                    f"HKLM\\{_MDNS_PATH}\\EnableMDNS: "
                    f"{mdns_val.data if mdns_val else 'Not set (default=enabled on Win10+)'}"
                ),
                recommendation=(
                    "Consider disabling mDNS if not needed by setting "
                    "EnableMDNS to 0 in the DNS Client Parameters registry."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1557/001/",
                ],
            ))

        return findings
