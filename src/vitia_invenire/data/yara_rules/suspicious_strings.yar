/*
    Vitia Invenire - Suspicious String Detection Rules
    Detects indicators that are suspicious but not definitively malicious,
    including encoded commands, credential harvesting patterns, obfuscation,
    and persistence mechanisms.
*/

rule Suspicious_PowerShell_EncodedCommand
{
    meta:
        description = "Detects Base64-encoded PowerShell command execution patterns"
        severity = "HIGH"
        category = "obfuscation"

    strings:
        // PowerShell encoded command flags
        $enc_1 = "-EncodedCommand" ascii wide nocase
        $enc_2 = "-enc " ascii wide nocase
        $enc_3 = "-ec " ascii wide nocase
        $enc_4 = "-encodedcommand" ascii wide nocase
        // PowerShell bypass flags commonly combined with encoded commands
        $bypass_1 = "-ExecutionPolicy Bypass" ascii wide nocase
        $bypass_2 = "-ep bypass" ascii wide nocase
        $bypass_3 = "-nop -w hidden" ascii wide nocase
        $bypass_4 = "-WindowStyle Hidden" ascii wide nocase
        // PowerShell download cradles in encoded form (common base64 fragments)
        $dl_1 = "SQBFAFgA" ascii  // IEX in UTF-16LE base64
        $dl_2 = "aQBlAHgA" ascii  // iex in UTF-16LE base64
        $dl_3 = "SQBFAF" ascii    // partial IE in UTF-16LE base64
        $dl_4 = "JABjAGwA" ascii  // $cl in UTF-16LE base64 (common variable start)

    condition:
        any of ($enc_*) and (any of ($bypass_*) or any of ($dl_*))
}

rule Suspicious_PowerShell_Download_Cradle
{
    meta:
        description = "Detects PowerShell download and execute patterns"
        severity = "HIGH"
        category = "download"

    strings:
        // Direct download cradles
        $dl_1 = "Net.WebClient" ascii wide nocase
        $dl_2 = "DownloadString(" ascii wide nocase
        $dl_3 = "DownloadFile(" ascii wide nocase
        $dl_4 = "DownloadData(" ascii wide nocase
        $dl_5 = "Invoke-WebRequest" ascii wide nocase
        $dl_6 = "wget " ascii wide nocase
        $dl_7 = "curl " ascii wide nocase
        $dl_8 = "Start-BitsTransfer" ascii wide nocase
        // Execution after download
        $exec_1 = "Invoke-Expression" ascii wide nocase
        $exec_2 = "IEX(" ascii wide nocase
        $exec_3 = "IEX " ascii wide nocase
        $exec_4 = "| IEX" ascii wide nocase
        $exec_5 = "|IEX" ascii wide nocase
        // Reflection-based loading
        $reflect_1 = "[System.Reflection.Assembly]::Load" ascii wide nocase
        $reflect_2 = "Reflection.Assembly" ascii wide nocase

    condition:
        (any of ($dl_*) and any of ($exec_*)) or
        (any of ($dl_*) and any of ($reflect_*))
}

rule Suspicious_Credential_Harvesting
{
    meta:
        description = "Detects patterns associated with credential harvesting and dumping"
        severity = "HIGH"
        category = "credential_theft"

    strings:
        // LSASS access patterns
        $lsass_1 = "lsass.exe" ascii wide nocase
        $lsass_2 = "MiniDumpWriteDump" ascii wide
        $lsass_3 = "procdump" ascii wide nocase
        $lsass_4 = "comsvcs.dll" ascii wide
        $lsass_5 = "sekurlsa" ascii wide nocase
        // SAM/SYSTEM registry hive extraction
        $reg_1 = "reg save HKLM\\SAM" ascii wide nocase
        $reg_2 = "reg save HKLM\\SYSTEM" ascii wide nocase
        $reg_3 = "reg save HKLM\\SECURITY" ascii wide nocase
        // NTDS.dit access (Domain Controller)
        $ntds_1 = "ntds.dit" ascii wide nocase
        $ntds_2 = "ntdsutil" ascii wide nocase
        // Shadow copy abuse for credential extraction
        $vss_1 = "vssadmin create shadow" ascii wide nocase
        $vss_2 = "GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" ascii wide nocase
        // Windows credential manager
        $cred_1 = "Windows\\Credentials" ascii wide nocase
        $cred_2 = "vaultcmd" ascii wide nocase

    condition:
        ($lsass_1 and ($lsass_2 or $lsass_4)) or
        ($lsass_3 and $lsass_1) or
        2 of ($reg_*) or
        all of ($ntds_*) or
        all of ($vss_*) or
        ($lsass_5)
}

rule Suspicious_Script_Obfuscation
{
    meta:
        description = "Detects common script obfuscation techniques in PowerShell, VBS, and batch files"
        severity = "HIGH"
        category = "obfuscation"

    strings:
        // PowerShell string concatenation obfuscation
        $ps_obf_1 = "'+'" ascii wide
        $ps_obf_2 = "\"+\"" ascii wide
        $ps_obf_3 = "[char]" ascii wide nocase
        $ps_obf_4 = "-join" ascii wide nocase
        $ps_obf_5 = "-replace" ascii wide nocase
        // PowerShell tick obfuscation (backtick in keywords)
        $ps_tick_1 = "N`e`w`-`O`b`j`e`c`t" ascii wide
        $ps_tick_2 = "I`n`v`o`k`e" ascii wide
        // Environment variable obfuscation in cmd
        $cmd_obf_1 = "%COMSPEC%" ascii wide nocase
        $cmd_obf_2 = "cmd /v /c" ascii wide nocase
        $cmd_obf_3 = "set __=" ascii wide
        // VBScript obfuscation
        $vbs_obf_1 = "Chr(" ascii wide nocase
        $vbs_obf_2 = "Execute(" ascii wide nocase
        $vbs_obf_3 = "ExecuteGlobal(" ascii wide nocase
        // String reversal technique
        $reverse_1 = "-join[char[]]" ascii wide nocase
        $reverse_2 = "[array]::reverse" ascii wide nocase

    condition:
        (4 of ($ps_obf_*)) or
        any of ($ps_tick_*) or
        ($cmd_obf_2 and $cmd_obf_3) or
        ($vbs_obf_1 and ($vbs_obf_2 or $vbs_obf_3)) or
        any of ($reverse_*)
}

rule Suspicious_WMI_Persistence
{
    meta:
        description = "Detects WMI event subscription persistence mechanism patterns"
        severity = "HIGH"
        category = "persistence"

    strings:
        // WMI event subscription classes
        $wmi_1 = "__EventFilter" ascii wide
        $wmi_2 = "__EventConsumer" ascii wide
        $wmi_3 = "__FilterToConsumerBinding" ascii wide
        $wmi_4 = "CommandLineEventConsumer" ascii wide
        $wmi_5 = "ActiveScriptEventConsumer" ascii wide
        // WMI subscription creation methods
        $create_1 = "Set-WmiInstance" ascii wide nocase
        $create_2 = "Create(" ascii wide
        $create_3 = "Register-WmiEvent" ascii wide nocase
        // WMI query patterns for persistence triggers
        $query_1 = "SELECT * FROM __InstanceModificationEvent" ascii wide nocase
        $query_2 = "TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'" ascii wide nocase
        $query_3 = "Win32_LocalTime" ascii wide nocase

    condition:
        (2 of ($wmi_*) and any of ($create_*)) or
        (any of ($wmi_*) and any of ($query_*)) or
        ($wmi_4 or $wmi_5)
}

rule Suspicious_Registry_Persistence
{
    meta:
        description = "Detects registry-based persistence mechanism manipulation"
        severity = "HIGH"
        category = "persistence"

    strings:
        // Common autorun registry locations
        $key_1 = "CurrentVersion\\Run" ascii wide nocase
        $key_2 = "CurrentVersion\\RunOnce" ascii wide nocase
        $key_3 = "CurrentVersion\\Policies\\Explorer\\Run" ascii wide nocase
        $key_4 = "CurrentVersion\\Explorer\\Shell Folders" ascii wide nocase
        $key_5 = "CurrentVersion\\Windows\\Load" ascii wide nocase
        $key_6 = "CurrentVersion\\Winlogon" ascii wide nocase
        $key_7 = "Environment\\UserInitMprLogonScript" ascii wide nocase
        // Image File Execution Options (debugger hijacking)
        $ifeo_1 = "Image File Execution Options" ascii wide nocase
        $ifeo_2 = "Debugger" ascii wide nocase
        // Registry modification commands
        $mod_1 = "reg add" ascii wide nocase
        $mod_2 = "Set-ItemProperty" ascii wide nocase
        $mod_3 = "New-ItemProperty" ascii wide nocase
        $mod_4 = "RegSetValueEx" ascii wide

    condition:
        (any of ($key_*) and any of ($mod_*)) or
        ($ifeo_1 and $ifeo_2 and any of ($mod_*))
}

rule Suspicious_AMSI_ETW_Bypass
{
    meta:
        description = "Detects attempts to bypass AMSI or ETW security monitoring"
        severity = "HIGH"
        category = "defense_evasion"

    strings:
        // AMSI bypass patterns
        $amsi_1 = "AmsiInitFailed" ascii wide
        $amsi_2 = "amsi.dll" ascii wide nocase
        $amsi_3 = "AmsiScanBuffer" ascii wide
        $amsi_4 = "AmsiUtils" ascii wide
        $amsi_5 = "amsiContext" ascii wide
        // ETW patching patterns
        $etw_1 = "EtwEventWrite" ascii wide
        $etw_2 = "NtTraceEvent" ascii wide
        // Specific bypass technique strings
        $bypass_1 = "SetProcessMitigationPolicy" ascii wide
        $bypass_2 = "VirtualProtect" ascii wide
        $bypass_3 = { C3 }  // ret instruction (single byte, used in patching)
        // PowerShell AMSI bypass fragments
        $ps_amsi_1 = "[Ref].Assembly.GetType" ascii wide
        $ps_amsi_2 = "System.Management.Automation.AmsiUtils" ascii wide

    condition:
        ($amsi_2 and ($amsi_3 or $amsi_4) and $bypass_2) or
        ($etw_1 and $bypass_2) or
        ($ps_amsi_1 and $ps_amsi_2)
}

rule Suspicious_Scheduled_Task_Creation
{
    meta:
        description = "Detects suspicious scheduled task creation patterns for persistence"
        severity = "HIGH"
        category = "persistence"

    strings:
        // schtasks command creation
        $schtasks_1 = "schtasks /create" ascii wide nocase
        $schtasks_2 = "schtasks.exe /create" ascii wide nocase
        // Scheduled task via COM/PowerShell
        $com_1 = "Schedule.Service" ascii wide
        $com_2 = "Register-ScheduledTask" ascii wide nocase
        $com_3 = "New-ScheduledTaskAction" ascii wide nocase
        // Task action targets (suspicious executables)
        $target_1 = "powershell" ascii wide nocase
        $target_2 = "cmd.exe" ascii wide nocase
        $target_3 = "mshta" ascii wide nocase
        $target_4 = "wscript" ascii wide nocase
        $target_5 = "cscript" ascii wide nocase
        $target_6 = "rundll32" ascii wide nocase
        $target_7 = "regsvr32" ascii wide nocase
        // Triggers indicating persistence
        $trigger_1 = "/sc onlogon" ascii wide nocase
        $trigger_2 = "/sc onstart" ascii wide nocase
        $trigger_3 = "/sc onidle" ascii wide nocase

    condition:
        (($schtasks_1 or $schtasks_2) and any of ($target_*)) or
        (($schtasks_1 or $schtasks_2) and any of ($trigger_*)) or
        ($com_1 and any of ($target_*))
}
