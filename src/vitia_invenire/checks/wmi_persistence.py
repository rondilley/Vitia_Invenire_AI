"""WMI-001: WMI event subscription persistence detection.

Queries __EventFilter, __EventConsumer, and __FilterToConsumerBinding
in the root\\subscription namespace to detect WMI-based persistence
mechanisms commonly used by malware and APT groups.
"""

from __future__ import annotations

from vitia_invenire.checks.base import BaseCheck
from vitia_invenire.collectors import wmi_collector
from vitia_invenire.collectors.powershell import run_ps
from vitia_invenire.models import Category, Finding, Severity


class WmiPersistenceCheck(BaseCheck):
    """Detect WMI event subscription-based persistence mechanisms."""

    CHECK_ID = "WMI-001"
    NAME = "WMI Persistence Detection"
    DESCRIPTION = (
        "Queries WMI event filters, consumers, and bindings in the "
        "root\\subscription namespace. WMI event subscriptions are a "
        "fileless persistence technique used by advanced malware."
    )
    CATEGORY = Category.PERSISTENCE
    REQUIRES_ADMIN = True

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        filters = self._query_event_filters(findings)
        consumers = self._query_event_consumers(findings)
        bindings = self._query_bindings(findings)

        if filters or consumers or bindings:
            self._correlate_findings(findings, filters, consumers, bindings)

        return findings

    def _query_event_filters(self, findings: list[Finding]) -> list[dict]:
        """Query __EventFilter objects in root\\subscription."""
        result = run_ps(
            "Get-CimInstance -Namespace 'root\\subscription' "
            "-ClassName '__EventFilter' -ErrorAction SilentlyContinue | "
            "Select-Object Name, Query, QueryLanguage, EventNamespace, "
            "@{N='CreatorSID';E={if($_.CreatorSID){[System.Security.Principal.SecurityIdentifier]::new($_.CreatorSID,0).Value}else{'Unknown'}}}",
            timeout=30,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            return []

        filters = result.json_output
        if isinstance(filters, dict):
            filters = [filters]

        for f in filters:
            name = str(f.get("Name", "Unknown"))
            query = str(f.get("Query", ""))
            query_lang = str(f.get("QueryLanguage", "WQL"))
            event_ns = str(f.get("EventNamespace", ""))
            creator_sid = str(f.get("CreatorSID", "Unknown"))

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"WMI event filter detected: {name}",
                description=(
                    f"A WMI event filter named '{name}' was found in the "
                    "root\\subscription namespace. WMI event filters define "
                    "trigger conditions for persistent event subscriptions."
                ),
                severity=Severity.CRITICAL,
                category=self.CATEGORY,
                affected_item=f"WMI EventFilter: {name}",
                evidence=(
                    f"Name: {name}\n"
                    f"Query: {query}\n"
                    f"Query Language: {query_lang}\n"
                    f"Event Namespace: {event_ns}\n"
                    f"Creator SID: {creator_sid}"
                ),
                recommendation=(
                    "Investigate this WMI event filter. If unauthorized, remove it: "
                    f"Get-CimInstance -Namespace 'root\\subscription' -ClassName '__EventFilter' "
                    f"-Filter \"Name='{name}'\" | Remove-CimInstance"
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1546/003/",
                    "https://learn.microsoft.com/en-us/windows/win32/wmisdk/monitoring-events",
                ],
            ))

        return filters

    def _query_event_consumers(self, findings: list[Finding]) -> list[dict]:
        """Query __EventConsumer subclasses in root\\subscription."""
        all_consumers: list[dict] = []

        # Query CommandLineEventConsumer
        cmd_result = run_ps(
            "Get-CimInstance -Namespace 'root\\subscription' "
            "-ClassName 'CommandLineEventConsumer' -ErrorAction SilentlyContinue | "
            "Select-Object Name, CommandLineTemplate, ExecutablePath, WorkingDirectory, "
            "@{N='ConsumerType';E={'CommandLineEventConsumer'}}, "
            "@{N='CreatorSID';E={if($_.CreatorSID){[System.Security.Principal.SecurityIdentifier]::new($_.CreatorSID,0).Value}else{'Unknown'}}}",
            timeout=30,
            as_json=True,
        )

        if cmd_result.success and cmd_result.json_output is not None:
            cmd_consumers = cmd_result.json_output
            if isinstance(cmd_consumers, dict):
                cmd_consumers = [cmd_consumers]

            for c in cmd_consumers:
                name = str(c.get("Name", "Unknown"))
                cmd_template = str(c.get("CommandLineTemplate", ""))
                exe_path = str(c.get("ExecutablePath", ""))
                consumer_type = "CommandLineEventConsumer"
                creator_sid = str(c.get("CreatorSID", "Unknown"))

                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"WMI command-line consumer detected: {name}",
                    description=(
                        f"A CommandLineEventConsumer named '{name}' will execute a "
                        "command when its associated event filter triggers. This is "
                        "a common fileless persistence and lateral movement technique."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.CATEGORY,
                    affected_item=f"WMI CommandLineConsumer: {name}",
                    evidence=(
                        f"Name: {name}\n"
                        f"Type: {consumer_type}\n"
                        f"Command Template: {cmd_template}\n"
                        f"Executable Path: {exe_path}\n"
                        f"Creator SID: {creator_sid}"
                    ),
                    recommendation=(
                        f"Investigate and remove if unauthorized: "
                        f"Get-CimInstance -Namespace 'root\\subscription' "
                        f"-ClassName 'CommandLineEventConsumer' -Filter \"Name='{name}'\" | "
                        "Remove-CimInstance"
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1546/003/",
                    ],
                ))
                c["_consumer_type"] = consumer_type
                all_consumers.append(c)

        # Query ActiveScriptEventConsumer
        script_result = run_ps(
            "Get-CimInstance -Namespace 'root\\subscription' "
            "-ClassName 'ActiveScriptEventConsumer' -ErrorAction SilentlyContinue | "
            "Select-Object Name, ScriptingEngine, ScriptText, ScriptFileName, "
            "@{N='ConsumerType';E={'ActiveScriptEventConsumer'}}, "
            "@{N='CreatorSID';E={if($_.CreatorSID){[System.Security.Principal.SecurityIdentifier]::new($_.CreatorSID,0).Value}else{'Unknown'}}}",
            timeout=30,
            as_json=True,
        )

        if script_result.success and script_result.json_output is not None:
            script_consumers = script_result.json_output
            if isinstance(script_consumers, dict):
                script_consumers = [script_consumers]

            for c in script_consumers:
                name = str(c.get("Name", "Unknown"))
                engine = str(c.get("ScriptingEngine", ""))
                script_text = str(c.get("ScriptText", ""))[:500]
                script_file = str(c.get("ScriptFileName", ""))
                creator_sid = str(c.get("CreatorSID", "Unknown"))

                findings.append(Finding(
                    check_id=self.CHECK_ID,
                    title=f"WMI active script consumer detected: {name}",
                    description=(
                        f"An ActiveScriptEventConsumer named '{name}' will execute "
                        f"a {engine} script when its associated event filter triggers. "
                        "Script-based WMI consumers are a highly suspicious persistence mechanism."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.CATEGORY,
                    affected_item=f"WMI ActiveScriptConsumer: {name}",
                    evidence=(
                        f"Name: {name}\n"
                        f"Scripting Engine: {engine}\n"
                        f"Script File: {script_file}\n"
                        f"Script Text (truncated): {script_text}\n"
                        f"Creator SID: {creator_sid}"
                    ),
                    recommendation=(
                        f"Investigate and remove if unauthorized. "
                        "ActiveScriptEventConsumer is especially dangerous."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1546/003/",
                    ],
                ))
                c["_consumer_type"] = "ActiveScriptEventConsumer"
                all_consumers.append(c)

        return all_consumers

    def _query_bindings(self, findings: list[Finding]) -> list[dict]:
        """Query __FilterToConsumerBinding objects in root\\subscription."""
        result = run_ps(
            "Get-CimInstance -Namespace 'root\\subscription' "
            "-ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue | "
            "Select-Object @{N='FilterName';E={$_.Filter.Name}}, "
            "@{N='ConsumerName';E={$_.Consumer.Name}}, "
            "@{N='FilterPath';E={$_.Filter.ToString()}}, "
            "@{N='ConsumerPath';E={$_.Consumer.ToString()}}, "
            "@{N='CreatorSID';E={if($_.CreatorSID){[System.Security.Principal.SecurityIdentifier]::new($_.CreatorSID,0).Value}else{'Unknown'}}}",
            timeout=30,
            as_json=True,
        )

        if not result.success or result.json_output is None:
            return []

        bindings = result.json_output
        if isinstance(bindings, dict):
            bindings = [bindings]

        for b in bindings:
            filter_name = str(b.get("FilterName", "Unknown"))
            consumer_name = str(b.get("ConsumerName", "Unknown"))
            filter_path = str(b.get("FilterPath", ""))
            consumer_path = str(b.get("ConsumerPath", ""))
            creator_sid = str(b.get("CreatorSID", "Unknown"))

            findings.append(Finding(
                check_id=self.CHECK_ID,
                title=f"WMI filter-to-consumer binding: {filter_name} -> {consumer_name}",
                description=(
                    f"A WMI binding connects event filter '{filter_name}' to "
                    f"consumer '{consumer_name}'. This completes a persistent "
                    "event subscription that will execute automatically."
                ),
                severity=Severity.CRITICAL,
                category=self.CATEGORY,
                affected_item=f"WMI Binding: {filter_name} -> {consumer_name}",
                evidence=(
                    f"Filter: {filter_name} ({filter_path})\n"
                    f"Consumer: {consumer_name} ({consumer_path})\n"
                    f"Creator SID: {creator_sid}"
                ),
                recommendation=(
                    "Remove the binding to break the persistence chain: "
                    f"Get-CimInstance -Namespace 'root\\subscription' "
                    f"-ClassName '__FilterToConsumerBinding' | "
                    "Where-Object {{ $_.Filter.Name -eq '{filter_name}' }} | "
                    "Remove-CimInstance"
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1546/003/",
                ],
            ))

        return bindings

    def _correlate_findings(
        self,
        findings: list[Finding],
        filters: list[dict],
        consumers: list[dict],
        bindings: list[dict],
    ) -> None:
        """Provide a summary correlating all WMI persistence components."""
        summary_lines: list[str] = [
            f"Event Filters: {len(filters)}",
            f"Event Consumers: {len(consumers)}",
            f"Filter-Consumer Bindings: {len(bindings)}",
        ]

        for f in filters:
            summary_lines.append(f"  Filter '{f.get('Name', '?')}': {f.get('Query', 'N/A')}")

        for c in consumers:
            ctype = c.get("_consumer_type", "Unknown")
            cmd = c.get("CommandLineTemplate", c.get("ScriptText", "N/A"))
            if isinstance(cmd, str) and len(cmd) > 200:
                cmd = cmd[:200] + "..."
            summary_lines.append(f"  Consumer '{c.get('Name', '?')}' ({ctype}): {cmd}")

        findings.append(Finding(
            check_id=self.CHECK_ID,
            title="WMI persistence subscription summary",
            description=(
                f"Found {len(filters)} event filter(s), {len(consumers)} consumer(s), "
                f"and {len(bindings)} binding(s) in root\\subscription. "
                "Any WMI event subscription indicates persistent code execution "
                "that survives reboots and operates without files on disk."
            ),
            severity=Severity.CRITICAL,
            category=self.CATEGORY,
            affected_item="WMI Event Subscriptions",
            evidence="\n".join(summary_lines),
            recommendation=(
                "Investigate all WMI event subscriptions immediately. "
                "Remove unauthorized subscriptions. Legitimate enterprise tools "
                "(SCCM, SCOM) may create these, but they should be verified."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1546/003/",
                "https://www.fireeye.com/blog/threat-research/2016/08/wmi_vs_wmi_monitor.html",
            ],
        ))
