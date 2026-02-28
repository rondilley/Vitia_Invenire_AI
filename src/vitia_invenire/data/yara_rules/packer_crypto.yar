/*
    Vitia Invenire - Packer and Crypter Detection Rules
    Detects packed, encrypted, or obfuscated executables that may indicate
    evasion attempts. Includes UPX, common crypter patterns, and entropy-based
    indicators.
*/

import "pe"
import "math"

rule UPX_Packed_Executable
{
    meta:
        description = "Detects executables packed with UPX (Ultimate Packer for eXecutables)"
        severity = "MEDIUM"
        category = "packer"

    strings:
        // UPX section names
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX2" ascii
        // UPX signature in PE overlay
        $upx_sig = "UPX!" ascii
        // UPX decompression stub patterns
        $stub_1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
        $stub_2 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C 24 }

    condition:
        uint16(0) == 0x5A4D and
        (
            ($upx0 and $upx1) or
            $upx_sig or
            any of ($stub_*)
        )
}

rule ASPack_Packed_Executable
{
    meta:
        description = "Detects executables packed with ASPack"
        severity = "MEDIUM"
        category = "packer"

    strings:
        // ASPack section name
        $aspack = ".aspack" ascii
        $adata = ".adata" ascii
        // ASPack entry point signatures
        $ep_1 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B8 ?? ?? ?? ?? 03 C5 }
        $ep_2 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }

    condition:
        uint16(0) == 0x5A4D and
        (
            ($aspack or $adata) or
            any of ($ep_*)
        )
}

rule Themida_WinLicense_Packed
{
    meta:
        description = "Detects executables packed with Themida or WinLicense protector"
        severity = "HIGH"
        category = "packer"

    strings:
        // Themida section names
        $section_1 = ".themida" ascii
        $section_2 = ".winlice" ascii
        $section_3 = "WinLicen" ascii
        // Themida VM entry patterns
        $vm_1 = { 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 }
        // Themida anti-debug strings
        $anti_1 = "OutputDebugStringA" ascii
        $anti_2 = "IsDebuggerPresent" ascii
        $anti_3 = "NtQueryInformationProcess" ascii
        $anti_4 = "CheckRemoteDebuggerPresent" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            any of ($section_*) or
            ($vm_1 and 3 of ($anti_*))
        )
}

rule VMProtect_Packed
{
    meta:
        description = "Detects executables protected with VMProtect virtualization"
        severity = "HIGH"
        category = "packer"

    strings:
        // VMProtect section names
        $vmp_1 = ".vmp0" ascii
        $vmp_2 = ".vmp1" ascii
        $vmp_3 = ".vmp2" ascii
        // VMProtect signature
        $sig_1 = "VMProtect" ascii wide
        $sig_2 = "VMProtect begin" ascii
        $sig_3 = "VMProtect end" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            any of ($vmp_*) or
            2 of ($sig_*)
        )
}

rule High_Entropy_PE_Section
{
    meta:
        description = "Detects PE files with abnormally high entropy sections indicating encryption or compression"
        severity = "MEDIUM"
        category = "packer"

    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_sections > 0 and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].raw_data_size > 1024 and
            math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.5
        )
}

rule Suspicious_PE_Section_Names
{
    meta:
        description = "Detects PE files with non-standard section names commonly used by packers and crypters"
        severity = "MEDIUM"
        category = "packer"

    strings:
        // Common packer/crypter section names
        $s_1 = ".ndata" ascii
        $s_2 = ".packed" ascii
        $s_3 = ".crypt" ascii
        $s_4 = ".enigma" ascii
        $s_5 = ".petite" ascii
        $s_6 = ".shrink" ascii
        $s_7 = ".mpress" ascii
        $s_8 = ".perplex" ascii
        $s_9 = "UPX" ascii
        $s_10 = ".yP" ascii
        $s_11 = ".kkrunchy" ascii
        $s_12 = "nsp0" ascii
        $s_13 = "nsp1" ascii

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule DotNet_Obfuscator_Indicators
{
    meta:
        description = "Detects .NET executables processed by common obfuscators"
        severity = "MEDIUM"
        category = "packer"

    strings:
        // ConfuserEx indicators
        $confuser_1 = "ConfuserEx" ascii wide
        $confuser_2 = "Confuser.Core" ascii wide
        // .NET Reactor indicators
        $reactor_1 = ".NET Reactor" ascii wide
        $reactor_2 = "Eziriz" ascii wide
        // SmartAssembly indicators
        $smart_1 = "SmartAssembly" ascii wide
        $smart_2 = "{" ascii wide
        // Dotfuscator indicators
        $dotfusc_1 = "Dotfuscator" ascii wide
        $dotfusc_2 = "PreEmptive" ascii wide
        // Obfuscar indicator
        $obfuscar = "Obfuscar" ascii wide
        // Generic .NET metadata stripping indicator (empty type/method names)
        $empty_meta = { 00 00 00 00 00 00 00 00 00 00 }

    condition:
        uint16(0) == 0x5A4D and
        (
            any of ($confuser_*) or
            any of ($reactor_*) or
            any of ($smart_*) or
            any of ($dotfusc_*) or
            $obfuscar
        )
}

rule MPRESS_Packed_Executable
{
    meta:
        description = "Detects executables packed with MPRESS packer"
        severity = "MEDIUM"
        category = "packer"

    strings:
        // MPRESS section names
        $section_1 = ".MPRESS1" ascii
        $section_2 = ".MPRESS2" ascii
        // MPRESS signature
        $sig = "MPRESS" ascii

    condition:
        uint16(0) == 0x5A4D and
        (
            ($section_1 and $section_2) or
            ($sig and any of ($section_*))
        )
}

rule Suspicious_Resource_Payload
{
    meta:
        description = "Detects PE files with suspiciously large or high-entropy resources that may contain embedded payloads"
        severity = "MEDIUM"
        category = "packer"

    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_resources > 0 and
        for any i in (0..pe.number_of_resources - 1) : (
            pe.resources[i].length > 100000 and
            math.entropy(pe.resources[i].offset, pe.resources[i].length) > 7.0
        )
}

rule XOR_Encoded_PE_Payload
{
    meta:
        description = "Detects XOR-encoded PE files embedded within other files (common crypter technique)"
        severity = "HIGH"
        category = "packer"

    strings:
        // XOR-encoded MZ header with common single-byte keys
        $xor_mz_01 = { 4C 5B }  // MZ XOR 0x01
        $xor_mz_0f = { 42 55 }  // MZ XOR 0x0F
        $xor_mz_1a = { 57 40 }  // MZ XOR 0x1A
        $xor_mz_55 = { 18 0F }  // MZ XOR 0x55
        $xor_mz_aa = { E7 F0 }  // MZ XOR 0xAA
        $xor_mz_ff = { B2 A5 }  // MZ XOR 0xFF
        // XOR-encoded "This program" string (common PE stub) with key 0x01
        $xor_stub_01 = { 55 69 68 72 21 71 73 6E 66 73 60 6C }

    condition:
        any of ($xor_mz_*) or
        $xor_stub_01
}
