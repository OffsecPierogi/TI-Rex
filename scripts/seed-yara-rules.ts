import "dotenv/config";
import { prisma } from "../src/lib/db";

interface RuleSeed {
  name: string;
  description: string;
  rule: string;
  category: "ransomware" | "rat" | "stealer" | "apt-tool" | "packer" | "webshell";
  author: string;
  reference: string;
  tags: string[];
  severity: "low" | "medium" | "high" | "critical";
  malwareNames?: string[];
  techniqueExternalId?: string;
}

const RULES: RuleSeed[] = [
  // =========================================================================
  // RANSOMWARE
  // =========================================================================
  {
    name: "Ransomware_LockBit_EncryptedMarker",
    description: "Detects LockBit ransomware by encrypted file extension markers and ransom note strings dropped during encryption.",
    category: "ransomware",
    author: "TrustedSec Threat Intel",
    reference: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a",
    tags: ["lockbit", "ransomware", "extortion"],
    severity: "critical",
    malwareNames: ["LockBit"],
    techniqueExternalId: "T1486",
    rule: `rule Ransomware_LockBit_EncryptedMarker : ransomware lockbit {
    meta:
        description = "Detects LockBit ransomware encrypted file markers and ransom note strings"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a"
        severity = "critical"

    strings:
        $note1 = "Restore-My-Files.txt" ascii wide
        $note2 = "~~Ransomed.txt" ascii wide
        $note3 = "LockBit_Ransomware.hta" ascii wide
        $marker1 = ".lockbit" ascii wide nocase
        $marker2 = ".lock3d" ascii wide nocase
        $mutex = "Global\\LocalLockBitMutex" ascii wide
        $cfg1 = { 4C 6F 63 6B 42 69 74 20 33 2E 30 } // "LockBit 3.0"

    condition:
        uint16(0) == 0x5A4D and 2 of ($note*, $marker*) or $mutex or $cfg1
}`,
  },
  {
    name: "Ransomware_BlackCat_ALPHV_Rust",
    description: "Detects BlackCat/ALPHV ransomware based on Rust-compiled binary characteristics and unique config strings.",
    category: "ransomware",
    author: "TrustedSec Threat Intel",
    reference: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-264a",
    tags: ["blackcat", "alphv", "ransomware", "rust"],
    severity: "critical",
    malwareNames: ["BlackCat"],
    techniqueExternalId: "T1486",
    rule: `rule Ransomware_BlackCat_ALPHV_Rust : ransomware blackcat {
    meta:
        description = "Detects BlackCat/ALPHV ransomware Rust binary and config markers"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-264a"
        severity = "critical"

    strings:
        $rust1 = "panicked at" ascii
        $rust2 = "alphv_encrypt" ascii
        $cfg1 = "\"extension\":" ascii
        $cfg2 = "\"note_file_name\":" ascii
        $cfg3 = "\"note_full_text\":" ascii
        $ransom1 = "ALPHV" ascii wide
        $ransom2 = "BlackCat" ascii wide

    condition:
        uint16(0) == 0x5A4D and ($rust1 and $rust2) or (2 of ($cfg*)) or (any of ($ransom*))
}`,
  },
  {
    name: "Ransomware_Conti_ConfigPattern",
    description: "Detects Conti ransomware configuration blocks, mutex names, and characteristic encryption markers.",
    category: "ransomware",
    author: "TrustedSec Threat Intel",
    reference: "https://www.cisa.gov/news-events/alerts/2021/09/22/conti-ransomware",
    tags: ["conti", "ransomware", "ryuk"],
    severity: "critical",
    malwareNames: ["Conti"],
    techniqueExternalId: "T1486",
    rule: `rule Ransomware_Conti_ConfigPattern : ransomware conti {
    meta:
        description = "Detects Conti ransomware configuration and encryption markers"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://www.cisa.gov/news-events/alerts/2021/09/22/conti-ransomware"
        severity = "critical"

    strings:
        $mutex = "kjkbmusop9iqkamvcrewuyy777" ascii wide
        $note = "CONTI_README.txt" ascii wide
        $cfg1 = { 70 75 62 6C 69 63 5F 6B 65 79 } // "public_key"
        $pdb = "conti_v3.pdb" ascii nocase
        $ext = ".CONTI" ascii wide nocase
        $net1 = "srv-1" ascii wide
        $net2 = "srv-2" ascii wide

    condition:
        uint16(0) == 0x5A4D and (any of ($mutex, $note, $pdb, $ext)) or (2 of ($net*) and $cfg1)
}`,
  },
  {
    name: "Ransomware_REvil_Sodinokibi",
    description: "Detects REvil/Sodinokibi ransomware by registry key patterns and encryption configuration markers.",
    category: "ransomware",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0496/",
    tags: ["revil", "sodinokibi", "ransomware", "gvt"],
    severity: "critical",
    malwareNames: ["REvil"],
    techniqueExternalId: "T1486",
    rule: `rule Ransomware_REvil_Sodinokibi : ransomware revil {
    meta:
        description = "Detects REvil/Sodinokibi ransomware registry and encryption markers"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0496/"
        severity = "critical"

    strings:
        $reg1 = "SOFTWARE\\\\BlackLivesMatter" ascii wide nocase
        $reg2 = "SOFTWARE\\\\WOW6432Node\\\\BlackLivesMatter" ascii wide nocase
        $ext_pattern = { 52 61 6E 64 6F 6D 45 78 74 } // "RandomExt"
        $note = "readme-" ascii wide nocase
        $tor = ".onion" ascii wide
        $pk = "pk" ascii
        $sk = "sk" ascii

    condition:
        uint16(0) == 0x5A4D and (any of ($reg*)) or ($ext_pattern and $note and $tor)
}`,
  },
  {
    name: "Ransomware_BlackBasta_Strings",
    description: "Detects Black Basta ransomware by characteristic strings and ransom note patterns.",
    category: "ransomware",
    author: "TrustedSec Threat Intel",
    reference: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a",
    tags: ["blackbasta", "ransomware"],
    severity: "critical",
    malwareNames: ["Black Basta"],
    techniqueExternalId: "T1486",
    rule: `rule Ransomware_BlackBasta_Strings : ransomware blackbasta {
    meta:
        description = "Detects Black Basta ransomware characteristic strings"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a"
        severity = "critical"

    strings:
        $note = "readme.txt" ascii wide nocase
        $ext = ".basta" ascii wide nocase
        $mutex = "dsajdhas.0" ascii wide
        $str1 = "Your data are stolen and encrypted" ascii wide
        $str2 = "aazsbsgya.onion" ascii wide
        $icon = "Fkdjslagjahd" ascii wide

    condition:
        uint16(0) == 0x5A4D and 2 of them
}`,
  },
  {
    name: "Ransomware_Royal_Dropper",
    description: "Detects Royal ransomware loader and dropper characteristics including callback URL patterns.",
    category: "ransomware",
    author: "TrustedSec Threat Intel",
    reference: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a",
    tags: ["royal", "ransomware"],
    severity: "critical",
    malwareNames: ["Royal"],
    techniqueExternalId: "T1486",
    rule: `rule Ransomware_Royal_Dropper : ransomware royal {
    meta:
        description = "Detects Royal ransomware loader characteristics"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a"
        severity = "critical"

    strings:
        $note = "README.TXT" ascii wide
        $ext = ".royal" ascii wide nocase
        $str1 = "royal_u" ascii wide
        $str2 = "royal_r" ascii wide
        $onion = ".onion" ascii wide
        $wmi = "Win32_ShadowCopy" ascii wide

    condition:
        uint16(0) == 0x5A4D and (any of ($ext, $str1, $str2)) and $note
}`,
  },
  {
    name: "Ransomware_Clop_WebShell",
    description: "Detects Cl0p ransomware web shell variants used during initial access and data exfiltration phases.",
    category: "ransomware",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0611/",
    tags: ["clop", "ransomware", "webshell", "moveit"],
    severity: "critical",
    malwareNames: ["Clop"],
    techniqueExternalId: "T1190",
    rule: `rule Ransomware_Clop_WebShell : ransomware clop webshell {
    meta:
        description = "Detects Cl0p ransomware web shell used for initial access"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0611/"
        severity = "critical"

    strings:
        $webshell1 = "Chopper" ascii wide nocase
        $clop1 = "Cl0p" ascii wide nocase
        $clop2 = "ClopReadMe.txt" ascii wide
        $moveit = "MOVEit" ascii wide
        $shell_cmd = "cmd.exe /c" ascii wide nocase
        $php_exec = "<?php @eval" ascii nocase

    condition:
        ($php_exec and $shell_cmd) or ($clop1 and $clop2) or ($moveit and $webshell1)
}`,
  },

  // =========================================================================
  // RATS / BACKDOORS
  // =========================================================================
  {
    name: "RAT_CobaltStrike_Beacon_Patterns",
    description: "Detects Cobalt Strike beacon payloads using default named pipe patterns, shellcode markers, and config block signatures.",
    category: "rat",
    author: "TrustedSec Threat Intel",
    reference: "https://www.cobaltstrike.com/help-beacon",
    tags: ["cobaltstrike", "beacon", "c2", "namedpipe"],
    severity: "critical",
    techniqueExternalId: "T1055",
    rule: `rule RAT_CobaltStrike_Beacon_Patterns : rat cobaltstrike c2 {
    meta:
        description = "Detects Cobalt Strike beacon by named pipes, shellcode, and config markers"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://www.cobaltstrike.com/help-beacon"
        severity = "critical"

    strings:
        $pipe1 = "\\\\.\\pipe\\msagent_" ascii wide
        $pipe2 = "\\\\.\\pipe\\status_" ascii wide
        $pipe3 = "\\\\.\\pipe\\postex_ssh_" ascii wide
        $cfg_marker = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 }
        $sleep_mask = { 48 31 C0 48 89 45 ?? 48 31 C0 }
        $watermark = "cobaltstrike" ascii wide nocase
        $beacon_dll = "beacon.dll" ascii wide nocase

    condition:
        any of ($pipe*) or $cfg_marker or ($sleep_mask and $watermark) or $beacon_dll
}`,
  },
  {
    name: "RAT_Meterpreter_Staging",
    description: "Detects Metasploit Meterpreter staging patterns and reflective DLL injection signatures.",
    category: "rat",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0250/",
    tags: ["metasploit", "meterpreter", "shellcode", "rdll"],
    severity: "high",
    techniqueExternalId: "T1055.001",
    rule: `rule RAT_Meterpreter_Staging : rat metasploit meterpreter {
    meta:
        description = "Detects Metasploit Meterpreter staging and reflective DLL injection"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0250/"
        severity = "high"

    strings:
        $rdll = "ReflectiveLoader" ascii wide
        $meterp1 = "metsrv.dll" ascii wide nocase
        $meterp2 = "metsrv.x64.dll" ascii wide nocase
        $stage = { 4D 5A 41 52 55 48 89 E5 48 81 EC }
        $ext_api = "ext_server_" ascii wide
        $channel = "channel_interact" ascii wide

    condition:
        $rdll or $stage or 2 of ($meterp*, $ext_api, $channel)
}`,
  },
  {
    name: "RAT_PlugX_HeaderPattern",
    description: "Detects PlugX RAT by its characteristic header patterns, config structures, and export names.",
    category: "rat",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0013/",
    tags: ["plugx", "rat", "apt", "china"],
    severity: "high",
    malwareNames: ["PlugX"],
    techniqueExternalId: "T1055",
    rule: `rule RAT_PlugX_HeaderPattern : rat plugx apt {
    meta:
        description = "Detects PlugX RAT header patterns and config structures"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0013/"
        severity = "high"

    strings:
        $hdr1 = { 58 4E 54 00 } // "XNT\x00" PlugX magic
        $hdr2 = { 68 58 00 00 00 } // PlugX alt header
        $export1 = "Loader" ascii wide
        $export2 = "Restart" ascii wide
        $cfg_key = { 50 6C 75 67 58 } // "PlugX"
        $dll = "PLUGX.dll" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and (any of ($hdr*) or $dll or (2 of ($export*, $cfg_key)))
}`,
  },
  {
    name: "RAT_ShadowPad_EncryptedConfig",
    description: "Detects ShadowPad modular backdoor by encrypted config block markers and plugin loading patterns.",
    category: "rat",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0596/",
    tags: ["shadowpad", "rat", "apt", "china", "modular"],
    severity: "critical",
    malwareNames: ["ShadowPad"],
    techniqueExternalId: "T1055",
    rule: `rule RAT_ShadowPad_EncryptedConfig : rat shadowpad apt {
    meta:
        description = "Detects ShadowPad modular backdoor encrypted config and plugin patterns"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0596/"
        severity = "critical"

    strings:
        $magic = { 73 68 61 64 6F 77 70 61 64 } // "shadowpad"
        $plugin_hdr = { 00 00 00 00 ?? ?? ?? ?? 00 10 00 00 }
        $export_init = "PluginInit" ascii
        $export_stop = "PluginStop" ascii
        $cfg_xor = { 8B 45 ?? 33 45 ?? 89 45 ?? 83 45 ?? 04 }

    condition:
        uint16(0) == 0x5A4D and ($magic or ($export_init and $export_stop) or ($plugin_hdr and $cfg_xor))
}`,
  },
  {
    name: "RAT_AsyncRAT_DotNet",
    description: "Detects AsyncRAT .NET remote access trojan by mutex, namespace, and configuration strings.",
    category: "rat",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0650/",
    tags: ["asyncrat", "rat", "dotnet", "c2"],
    severity: "high",
    malwareNames: ["AsyncRAT"],
    techniqueExternalId: "T1219",
    rule: `rule RAT_AsyncRAT_DotNet : rat asyncrat dotnet {
    meta:
        description = "Detects AsyncRAT .NET RAT by mutex and configuration strings"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0650/"
        severity = "high"

    strings:
        $mutex = "AsyncMutex_6SI8OkPnk" ascii wide
        $ns = "AsyncRAT" ascii wide
        $cfg1 = "Ports" ascii wide
        $cfg2 = "Hosts" ascii wide
        $cfg3 = "Version" ascii wide
        $antivm = "VBOX" ascii wide nocase
        $install = "InstallDir" ascii wide

    condition:
        $mutex or ($ns and 3 of ($cfg*, $antivm, $install))
}`,
  },
  {
    name: "RAT_QuasarRAT_DotNet",
    description: "Detects QuasarRAT .NET open source remote access trojan by namespace strings and config markers.",
    category: "rat",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0262/",
    tags: ["quasar", "rat", "dotnet", "opensource"],
    severity: "high",
    malwareNames: ["QuasarRAT"],
    techniqueExternalId: "T1219",
    rule: `rule RAT_QuasarRAT_DotNet : rat quasar dotnet {
    meta:
        description = "Detects QuasarRAT .NET RAT by namespace and config markers"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0262/"
        severity = "high"

    strings:
        $ns1 = "Quasar.Client" ascii wide
        $ns2 = "Quasar.Server" ascii wide
        $ns3 = "xRAT" ascii wide
        $cfg_key = "QSR_MUTEX_" ascii wide
        $export1 = "Client.exe" ascii wide
        $keylog = "KeyLog" ascii wide
        $host = "RECONNECTDELAY" ascii wide

    condition:
        any of ($ns*) or ($cfg_key and $keylog) or ($host and $export1)
}`,
  },

  // =========================================================================
  // STEALERS / LOADERS
  // =========================================================================
  {
    name: "Stealer_Emotet_MacroLoader",
    description: "Detects Emotet loader and macro downloader patterns used in Office document phishing campaigns.",
    category: "stealer",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0367/",
    tags: ["emotet", "loader", "macro", "phishing", "banking"],
    severity: "high",
    malwareNames: ["Emotet"],
    techniqueExternalId: "T1566.001",
    rule: `rule Stealer_Emotet_MacroLoader : stealer emotet loader {
    meta:
        description = "Detects Emotet macro loader and downloader patterns"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0367/"
        severity = "high"

    strings:
        $vba1 = "AutoOpen" ascii wide nocase
        $vba2 = "Document_Open" ascii wide nocase
        $ps_dl = "powershell" ascii wide nocase
        $iwr = "Invoke-WebRequest" ascii wide nocase
        $url_pattern = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[a-zA-Z0-9\/]{8,}/
        $obf1 = "Chr(" ascii wide nocase
        $obf2 = "Shell" ascii wide

    condition:
        (any of ($vba*)) and ($ps_dl or $iwr or $url_pattern) and any of ($obf*)
}`,
  },
  {
    name: "Stealer_QakBot_DLLLoader",
    description: "Detects QakBot/QBot banking trojan DLL loading patterns and registry persistence strings.",
    category: "stealer",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0650/",
    tags: ["qakbot", "qbot", "banking", "dll", "loader"],
    severity: "high",
    malwareNames: ["QakBot"],
    techniqueExternalId: "T1055.001",
    rule: `rule Stealer_QakBot_DLLLoader : stealer qakbot banking {
    meta:
        description = "Detects QakBot DLL loading and registry persistence patterns"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0650/"
        severity = "high"

    strings:
        $mutex = "Global\\{" ascii wide
        $reg = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $export1 = "DllRegisterServer" ascii wide
        $str1 = "qbot" ascii wide nocase
        $str2 = "qakbot" ascii wide nocase
        $inj1 = "explorer.exe" ascii wide nocase
        $bot_id = { 51 62 6F 74 } // "Qbot"

    condition:
        uint16(0) == 0x5A4D and ($bot_id or any of ($str*)) and ($mutex or $reg or $inj1)
}`,
  },
  {
    name: "Stealer_IcedID_Loader",
    description: "Detects IcedID (BokBot) banking trojan loader by characteristic config and network patterns.",
    category: "stealer",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0483/",
    tags: ["icedid", "bokbot", "banking", "loader"],
    severity: "high",
    malwareNames: ["IcedID"],
    techniqueExternalId: "T1055",
    rule: `rule Stealer_IcedID_Loader : stealer icedid banking {
    meta:
        description = "Detects IcedID banking trojan loader characteristics"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0483/"
        severity = "high"

    strings:
        $gzip_hdr = { 1F 8B 08 }
        $cfg1 = "Bot_ID" ascii wide nocase
        $cfg2 = "License_ID" ascii wide nocase
        $backconnect = "/loader32" ascii wide nocase
        $ua = "Mozilla/4.0" ascii wide
        $cookie_grab = "document.cookie" ascii wide

    condition:
        ($cfg1 and $cfg2) or ($backconnect and $ua) or ($cookie_grab and $gzip_hdr)
}`,
  },
  {
    name: "Stealer_RedLine_DotNet",
    description: "Detects RedLine Stealer .NET infostealer by namespace strings and credential harvesting targets.",
    category: "stealer",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0684/",
    tags: ["redline", "stealer", "infostealer", "dotnet", "credentials"],
    severity: "high",
    malwareNames: ["RedLine Stealer"],
    techniqueExternalId: "T1555",
    rule: `rule Stealer_RedLine_DotNet : stealer redline infostealer {
    meta:
        description = "Detects RedLine Stealer .NET credential harvesting patterns"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0684/"
        severity = "high"

    strings:
        $ns1 = "RedLine" ascii wide
        $ns2 = "StealerLib" ascii wide
        $target1 = "Telegram" ascii wide
        $target2 = "Discord" ascii wide
        $target3 = "\\Login Data" ascii wide
        $cfg1 = "IP:Port" ascii wide
        $cfg2 = "BuildID" ascii wide
        $wallet = "wallet.dat" ascii wide nocase

    condition:
        $ns1 or ($ns2 and any of ($target*)) or (2 of ($cfg*, $wallet))
}`,
  },
  {
    name: "Stealer_Raccoon_v2",
    description: "Detects Raccoon Stealer v2 by C2 communication patterns and credential stealing targets.",
    category: "stealer",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0650/",
    tags: ["raccoon", "stealer", "infostealer", "credentials"],
    severity: "high",
    malwareNames: ["Raccoon Stealer"],
    techniqueExternalId: "T1555",
    rule: `rule Stealer_Raccoon_v2 : stealer raccoon infostealer {
    meta:
        description = "Detects Raccoon Stealer v2 C2 and credential harvesting patterns"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0650/"
        severity = "high"

    strings:
        $cfg1 = "machineId" ascii wide
        $cfg2 = "racconf" ascii wide nocase
        $steal1 = "CryptoWallets" ascii wide
        $steal2 = "Autofill" ascii wide
        $steal3 = "Cookies" ascii wide
        $ua = "raccoon" ascii wide nocase
        $mutex = "racco" ascii wide nocase

    condition:
        ($cfg2 and any of ($steal*)) or ($ua and 2 of ($cfg*, $steal*)) or ($mutex and $cfg1)
}`,
  },

  // =========================================================================
  // APT TOOLS
  // =========================================================================
  {
    name: "APTTool_Mimikatz_Exports",
    description: "Detects Mimikatz credential dumping tool by export names, PDB paths, and characteristic strings.",
    category: "apt-tool",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0002/",
    tags: ["mimikatz", "credential-dump", "lsass", "kerberos"],
    severity: "critical",
    malwareNames: ["Mimikatz"],
    techniqueExternalId: "T1003.001",
    rule: `rule APTTool_Mimikatz_Exports : apt-tool mimikatz credentials {
    meta:
        description = "Detects Mimikatz by export names, PDB, and credential dumping strings"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0002/"
        severity = "critical"

    strings:
        $pdb = "mimikatz.pdb" ascii nocase
        $export1 = "sekurlsa::logonpasswords" ascii wide nocase
        $export2 = "lsadump::dcsync" ascii wide nocase
        $export3 = "privilege::debug" ascii wide nocase
        $str1 = "mimikatz" ascii wide nocase
        $str2 = "Benjamin DELPY" ascii wide
        $str3 = "SekurLSA" ascii wide
        $lsass = "lsass.exe" ascii wide

    condition:
        $pdb or (2 of ($export*)) or ($str1 and any of ($str2, $str3)) or ($str2 and $lsass)
}`,
  },
  {
    name: "APTTool_LaZagne_CredHarvest",
    description: "Detects LaZagne Python credential harvesting framework by module names and target application strings.",
    category: "apt-tool",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0349/",
    tags: ["lazagne", "credentials", "python", "harvesting"],
    severity: "high",
    malwareNames: ["LaZagne"],
    techniqueExternalId: "T1555",
    rule: `rule APTTool_LaZagne_CredHarvest : apt-tool lazagne credentials {
    meta:
        description = "Detects LaZagne credential harvesting framework"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0349/"
        severity = "high"

    strings:
        $py1 = "lazagne" ascii wide nocase
        $module1 = "mozilla" ascii wide nocase
        $module2 = "chromium" ascii wide nocase
        $module3 = "winscp" ascii wide nocase
        $module4 = "putty" ascii wide nocase
        $main_func = "run_lazagne" ascii wide
        $output = "passwords found" ascii wide nocase

    condition:
        $py1 or ($main_func and any of ($module*)) or (3 of ($module*) and $output)
}`,
  },
  {
    name: "APTTool_Impacket_Scripts",
    description: "Detects Impacket Python framework scripts used for lateral movement and credential operations.",
    category: "apt-tool",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0357/",
    tags: ["impacket", "lateral-movement", "smb", "python"],
    malwareNames: ["Impacket"],
    severity: "high",
    techniqueExternalId: "T1021.002",
    rule: `rule APTTool_Impacket_Scripts : apt-tool impacket lateral-movement {
    meta:
        description = "Detects Impacket framework scripts for lateral movement"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0357/"
        severity = "high"

    strings:
        $imp1 = "impacket" ascii wide nocase
        $imp2 = "from impacket" ascii nocase
        $script1 = "secretsdump" ascii wide nocase
        $script2 = "psexec" ascii wide nocase
        $script3 = "wmiexec" ascii wide nocase
        $script4 = "smbexec" ascii wide nocase
        $smb = "SMBConnection" ascii wide

    condition:
        $imp1 or $imp2 or (2 of ($script*)) or ($smb and any of ($script*))
}`,
  },
  {
    name: "APTTool_SharpHound_BloodHound",
    description: "Detects SharpHound/BloodHound Active Directory collection tool by namespace and collection method strings.",
    category: "apt-tool",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0521/",
    tags: ["sharphound", "bloodhound", "active-directory", "recon"],
    severity: "high",
    techniqueExternalId: "T1087.002",
    rule: `rule APTTool_SharpHound_BloodHound : apt-tool sharphound bloodhound ad-recon {
    meta:
        description = "Detects SharpHound BloodHound AD collection tool"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0521/"
        severity = "high"

    strings:
        $ns1 = "SharpHound" ascii wide
        $ns2 = "BloodHound" ascii wide
        $ns3 = "Sharphound3" ascii wide
        $method1 = "CollectionMethod" ascii wide
        $method2 = "DCOnly" ascii wide
        $method3 = "GPOLocalGroup" ascii wide
        $output = "BloodHound.zip" ascii wide nocase
        $ldap = "LDAP://" ascii wide nocase

    condition:
        any of ($ns*) or (2 of ($method*) and $ldap) or ($output and $method1)
}`,
  },
  {
    name: "APTTool_Rubeus_Kerberos",
    description: "Detects Rubeus Kerberos attack toolkit by namespace strings and attack method names.",
    category: "apt-tool",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0556/",
    tags: ["rubeus", "kerberos", "active-directory", "ticket"],
    severity: "critical",
    techniqueExternalId: "T1558.003",
    rule: `rule APTTool_Rubeus_Kerberos : apt-tool rubeus kerberos {
    meta:
        description = "Detects Rubeus Kerberos attack toolkit"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0556/"
        severity = "critical"

    strings:
        $ns = "Rubeus" ascii wide
        $cmd1 = "kerberoast" ascii wide nocase
        $cmd2 = "asreproast" ascii wide nocase
        $cmd3 = "ptt" ascii wide
        $cmd4 = "golden" ascii wide nocase
        $cmd5 = "s4u" ascii wide
        $ticket = "aes256_cts_hmac_sha1" ascii wide nocase
        $tgt = "krbtgt" ascii wide nocase

    condition:
        $ns and (any of ($cmd*) or $ticket) or (2 of ($cmd*) and $tgt)
}`,
  },

  // =========================================================================
  // PACKERS / CRYPTERS
  // =========================================================================
  {
    name: "Packer_UPX_Compressed_PE",
    description: "Detects UPX-packed PE executables by magic bytes and section names.",
    category: "packer",
    author: "TrustedSec Threat Intel",
    reference: "https://upx.github.io/",
    tags: ["upx", "packer", "compressed", "pe"],
    severity: "medium",
    techniqueExternalId: "T1027.002",
    rule: `rule Packer_UPX_Compressed_PE : packer upx compressed {
    meta:
        description = "Detects UPX-packed PE by magic bytes and section names"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://upx.github.io/"
        severity = "medium"

    strings:
        $upx_magic = "UPX!" ascii
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $mz = { 4D 5A }

    condition:
        $mz at 0 and $upx_magic and ($upx0 or $upx1)
}`,
  },
  {
    name: "Packer_VMProtect_Indicators",
    description: "Detects VMProtect obfuscation by section names and virtualization engine markers.",
    category: "packer",
    author: "TrustedSec Threat Intel",
    reference: "https://vmpsoft.com/",
    tags: ["vmprotect", "packer", "obfuscation", "virtualization"],
    severity: "medium",
    techniqueExternalId: "T1027.009",
    rule: `rule Packer_VMProtect_Indicators : packer vmprotect obfuscation {
    meta:
        description = "Detects VMProtect obfuscation by section names and VM markers"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://vmpsoft.com/"
        severity = "medium"

    strings:
        $section1 = ".vmp0" ascii
        $section2 = ".vmp1" ascii
        $section3 = ".vmp2" ascii
        $marker = "VMProtect" ascii wide nocase
        $handler = { C7 45 FC 56 4D 50 00 } // "VMP\x00"

    condition:
        uint16(0) == 0x5A4D and (2 of ($section*) or ($marker and any of ($section*)) or $handler)
}`,
  },
  {
    name: "Packer_Themida_Protected",
    description: "Detects Themida-protected executables by section names and anti-analysis markers.",
    category: "packer",
    author: "TrustedSec Threat Intel",
    reference: "https://www.oreans.com/themida.php",
    tags: ["themida", "packer", "anti-analysis", "protection"],
    severity: "medium",
    techniqueExternalId: "T1027.002",
    rule: `rule Packer_Themida_Protected : packer themida anti-analysis {
    meta:
        description = "Detects Themida-protected PE by section names and markers"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://www.oreans.com/themida.php"
        severity = "medium"

    strings:
        $section = ".themida" ascii nocase
        $marker1 = "Themida" ascii wide nocase
        $marker2 = "WinLicense" ascii wide nocase
        $anti_dbg = { 64 A1 30 00 00 00 8B 40 10 85 C0 }
        $nt_hdr = { 50 45 00 00 }

    condition:
        uint16(0) == 0x5A4D and ($section or any of ($marker*) or ($anti_dbg and $nt_hdr))
}`,
  },
  {
    name: "Packer_DotNet_Obfuscated",
    description: "Detects heavily obfuscated .NET assemblies by identifying common obfuscator markers and namespace patterns.",
    category: "packer",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/techniques/T1027/",
    tags: ["dotnet", "obfuscation", "packer", "confuserex"],
    severity: "medium",
    techniqueExternalId: "T1027",
    rule: `rule Packer_DotNet_Obfuscated : packer dotnet obfuscation {
    meta:
        description = "Detects obfuscated .NET assemblies by obfuscator markers"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1027/"
        severity = "medium"

    strings:
        $dotnet = { 4D 5A 90 00 03 00 00 00 }
        $confuser = "ConfuserEx" ascii wide nocase
        $dnguard = "DNGuard" ascii wide nocase
        $dotfuscator = "Dotfuscator" ascii wide nocase
        $smartassembly = "SmartAssembly" ascii wide nocase
        $obf_ns = /[A-Z][a-zA-Z]{0,2}\.[A-Z][a-zA-Z]{0,2}\.[A-Z][a-zA-Z]{0,2}/ wide

    condition:
        $dotnet at 0 and (any of ($confuser, $dnguard, $dotfuscator, $smartassembly) or #obf_ns > 20)
}`,
  },

  // =========================================================================
  // WEBSHELLS
  // =========================================================================
  {
    name: "Webshell_ChinaChopper_PHP",
    description: "Detects China Chopper PHP webshell variants by eval patterns and one-liner structures.",
    category: "webshell",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0020/",
    tags: ["webshell", "chinachopper", "php", "apt"],
    techniqueExternalId: "T1505.003",
    severity: "critical",
    rule: `rule Webshell_ChinaChopper_PHP : webshell chinachopper php {
    meta:
        description = "Detects China Chopper PHP webshell variants"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0020/"
        severity = "critical"

    strings:
        $chopper1 = "<?php @eval($_POST[" ascii nocase
        $chopper2 = "<?php @eval($_REQUEST[" ascii nocase
        $chopper3 = "<?php assert($_POST[" ascii nocase
        $chopper4 = "@eval(base64_decode(" ascii nocase
        $one_liner = /^\<\?php\s+\@(eval|assert|system|exec)\(\$_(POST|GET|REQUEST|COOKIE)/ nocase

    condition:
        any of ($chopper*) or $one_liner
}`,
  },
  {
    name: "Webshell_Generic_PHP",
    description: "Detects generic PHP webshell patterns including command execution and file operation functions.",
    category: "webshell",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/techniques/T1505/003/",
    tags: ["webshell", "php", "generic", "backdoor"],
    techniqueExternalId: "T1505.003",
    severity: "high",
    rule: `rule Webshell_Generic_PHP : webshell php generic {
    meta:
        description = "Detects generic PHP webshell command execution patterns"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        severity = "high"

    strings:
        $exec1 = "system(" ascii nocase
        $exec2 = "passthru(" ascii nocase
        $exec3 = "shell_exec(" ascii nocase
        $exec4 = "popen(" ascii nocase
        $user_input1 = "$_GET[" ascii
        $user_input2 = "$_POST[" ascii
        $user_input3 = "$_REQUEST[" ascii
        $php_tag = "<?php" ascii nocase

    condition:
        $php_tag and any of ($exec*) and any of ($user_input*)
}`,
  },
  {
    name: "Webshell_ASPX_Generic",
    description: "Detects generic ASPX webshell patterns including command execution and file upload functionality.",
    category: "webshell",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/techniques/T1505/003/",
    tags: ["webshell", "aspx", "dotnet", "iis"],
    techniqueExternalId: "T1505.003",
    severity: "high",
    rule: `rule Webshell_ASPX_Generic : webshell aspx dotnet {
    meta:
        description = "Detects generic ASPX webshell command execution patterns"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        severity = "high"

    strings:
        $aspx_tag = "<%@" ascii
        $exec1 = "Process.Start(" ascii wide nocase
        $exec2 = "cmd.exe" ascii wide nocase
        $exec3 = "Runtime.exec(" ascii wide nocase
        $request1 = "Request[\"" ascii wide
        $request2 = "Request.Form[" ascii wide
        $eval = "Assembly.Load(" ascii wide nocase

    condition:
        $aspx_tag and (any of ($exec*)) and (any of ($request*) or $eval)
}`,
  },
  {
    name: "Webshell_Godzilla_Java",
    description: "Detects Godzilla Java/JSP webshell framework by characteristic base64 decryption and eval patterns.",
    category: "webshell",
    author: "TrustedSec Threat Intel",
    reference: "https://github.com/BeichenDream/Godzilla",
    tags: ["godzilla", "webshell", "java", "jsp"],
    techniqueExternalId: "T1505.003",
    severity: "critical",
    rule: `rule Webshell_Godzilla_Java : webshell godzilla java jsp {
    meta:
        description = "Detects Godzilla Java/JSP webshell framework"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://github.com/BeichenDream/Godzilla"
        severity = "critical"

    strings:
        $godzilla1 = "Godzilla" ascii wide nocase
        $jsp_crypto = "javax.crypto.Cipher" ascii wide
        $payload = "getParameter" ascii wide
        $aes = "AES/CBC/NoPadding" ascii wide
        $decrypt = "Base64.getDecoder" ascii wide
        $classloader = "ClassLoader" ascii wide

    condition:
        $godzilla1 or ($jsp_crypto and $payload and $aes) or ($decrypt and $classloader and $payload)
}`,
  },
  {
    name: "Webshell_ReGeorg_Tunnel",
    description: "Detects ReGeorg tunnel webshell used for HTTP tunneling through compromised web servers.",
    category: "webshell",
    author: "TrustedSec Threat Intel",
    reference: "https://github.com/sensepost/reGeorg",
    tags: ["regeorg", "webshell", "tunnel", "proxy"],
    techniqueExternalId: "T1090",
    severity: "high",
    rule: `rule Webshell_ReGeorg_Tunnel : webshell regeorg tunnel {
    meta:
        description = "Detects ReGeorg HTTP tunnel webshell"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://github.com/sensepost/reGeorg"
        severity = "high"

    strings:
        $regeorg1 = "reGeorg" ascii wide nocase
        $cmd_connect = "CONNECT" ascii wide
        $socket = "targetHost" ascii wide
        $port = "targetPort" ascii wide
        $status_ok = "georg says, 'All seems fine'" ascii
        $mark = "Georg" ascii wide

    condition:
        $regeorg1 or $status_ok or ($cmd_connect and $socket and $port and $mark)
}`,
  },

  // =========================================================================
  // ADDITIONAL APT TOOLS
  // =========================================================================
  {
    name: "APTTool_PsExec_Lateral",
    description: "Detects PsExec remote execution tool usage patterns for lateral movement detection.",
    category: "apt-tool",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0029/",
    tags: ["psexec", "lateral-movement", "sysinternals", "execution"],
    severity: "medium",
    techniqueExternalId: "T1569.002",
    rule: `rule APTTool_PsExec_Lateral : apt-tool psexec lateral-movement {
    meta:
        description = "Detects PsExec remote execution tool for lateral movement"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0029/"
        severity = "medium"

    strings:
        $psexec = "PSEXESVC" ascii wide
        $svc = "psexesvc.exe" ascii wide nocase
        $pipe = "\\\\.\\pipe\\psexec" ascii wide nocase
        $str1 = "Sysinternals" ascii wide nocase
        $str2 = "PsExec" ascii wide
        $remote = "\\\\%s\\ADMIN$" ascii wide

    condition:
        $psexec or $svc or $pipe or ($str1 and $str2 and $remote)
}`,
  },
  {
    name: "APTTool_NetSh_PortForward",
    description: "Detects netsh portproxy commands used by attackers for persistent port forwarding tunnels.",
    category: "apt-tool",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/techniques/T1090/001/",
    tags: ["netsh", "portforward", "tunnel", "persistence"],
    severity: "medium",
    techniqueExternalId: "T1090.001",
    rule: `rule APTTool_NetSh_PortForward : apt-tool portforward tunnel {
    meta:
        description = "Detects netsh portproxy commands for port forwarding"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1090/001/"
        severity = "medium"

    strings:
        $netsh = "netsh" ascii wide nocase
        $portproxy = "portproxy" ascii wide nocase
        $add_v4 = "add v4tov4" ascii wide nocase
        $listenport = "listenport" ascii wide nocase
        $connectport = "connectport" ascii wide nocase

    condition:
        $netsh and $portproxy and ($add_v4 or ($listenport and $connectport))
}`,
  },
  {
    name: "RAT_CobaltStrike_SleepMask",
    description: "Detects Cobalt Strike sleep masking feature used to hide beacon in memory during sleep cycles.",
    category: "rat",
    author: "TrustedSec Threat Intel",
    reference: "https://www.cobaltstrike.com/blog/beacon-object-files-lox/",
    tags: ["cobaltstrike", "sleepmask", "evasion", "memory"],
    severity: "critical",
    techniqueExternalId: "T1055",
    rule: `rule RAT_CobaltStrike_SleepMask : rat cobaltstrike evasion {
    meta:
        description = "Detects Cobalt Strike sleep masking technique"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://www.cobaltstrike.com/blog/beacon-object-files-lox/"
        severity = "critical"

    strings:
        $sleep_mask1 = { 48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 }
        $sleep_mask2 = "sleep_mask" ascii wide nocase
        $beacon_gate = "BeaconGate" ascii wide nocase
        $indirect_syscall = { 4C 8B D1 B8 ?? 00 00 00 0F 05 C3 }
        $ekko = "RtlCreateTimer" ascii wide

    condition:
        any of ($sleep_mask*, $beacon_gate, $indirect_syscall, $ekko)
}`,
  },
  {
    name: "Stealer_AgentTesla_Keylogger",
    description: "Detects Agent Tesla keylogger/stealer by SMTP exfiltration patterns and keylogging strings.",
    category: "stealer",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0331/",
    tags: ["agenttesla", "keylogger", "stealer", "smtp", "dotnet"],
    severity: "high",
    techniqueExternalId: "T1056.001",
    rule: `rule Stealer_AgentTesla_Keylogger : stealer agenttesla keylogger {
    meta:
        description = "Detects Agent Tesla keylogger SMTP exfiltration and keylogging strings"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0331/"
        severity = "high"

    strings:
        $ns1 = "AgentTesla" ascii wide
        $smtp = "smtp.gmail.com" ascii wide nocase
        $keylog1 = "GetAsyncKeyState" ascii wide
        $keylog2 = "SetWindowsHookEx" ascii wide
        $exfil = "Exfil" ascii wide nocase
        $clipboard = "Clipboard" ascii wide
        $browser = "Opera\\Local AppData" ascii wide

    condition:
        $ns1 or ($smtp and any of ($keylog*)) or (any of ($keylog*) and any of ($exfil, $clipboard, $browser))
}`,
  },
  {
    name: "Ransomware_Akira_Patterns",
    description: "Detects Akira ransomware by characteristic extension, ransom note, and encryption markers.",
    category: "ransomware",
    author: "TrustedSec Threat Intel",
    reference: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a",
    tags: ["akira", "ransomware"],
    severity: "critical",
    techniqueExternalId: "T1486",
    rule: `rule Ransomware_Akira_Patterns : ransomware akira {
    meta:
        description = "Detects Akira ransomware extension and ransom note markers"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a"
        severity = "critical"

    strings:
        $ext = ".akira" ascii wide nocase
        $note = "akira_readme.txt" ascii wide nocase
        $onion = "akiralkzxzqtu5e" ascii wide
        $str1 = "Akira" ascii wide
        $wmi = "SELECT * FROM Win32_ShadowCopy" ascii wide

    condition:
        uint16(0) == 0x5A4D and (any of ($ext, $note, $onion)) or ($str1 and $wmi)
}`,
  },
  {
    name: "APTTool_Certutil_Abuse",
    description: "Detects certutil.exe abuse for downloading payloads and decoding base64-encoded malware.",
    category: "apt-tool",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/techniques/T1140/",
    tags: ["certutil", "lolbin", "download", "decode"],
    severity: "medium",
    techniqueExternalId: "T1140",
    rule: `rule APTTool_Certutil_Abuse : apt-tool lolbin certutil {
    meta:
        description = "Detects certutil abuse for download and base64 decode"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1140/"
        severity = "medium"

    strings:
        $certutil = "certutil" ascii wide nocase
        $urlcache = "urlcache" ascii wide nocase
        $decode = "-decode" ascii wide nocase
        $encode = "-encode" ascii wide nocase
        $split = "-split" ascii wide nocase
        $url = /https?:\/\// ascii wide

    condition:
        $certutil and ($urlcache or ($decode and $url) or ($encode and $split))
}`,
  },
  {
    name: "Webshell_Hafnium_ASPX",
    description: "Detects HAFNIUM Exchange webshells dropped via ProxyLogon exploitation.",
    category: "webshell",
    author: "TrustedSec Threat Intel",
    reference: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-062a",
    tags: ["hafnium", "webshell", "exchange", "proxylogon"],
    techniqueExternalId: "T1505.003",
    severity: "critical",
    rule: `rule Webshell_Hafnium_ASPX : webshell hafnium exchange {
    meta:
        description = "Detects HAFNIUM Exchange webshells from ProxyLogon exploitation"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-062a"
        severity = "critical"

    strings:
        $aspx = "<%@" ascii
        $cmd_arg = "Request.QueryString[" ascii wide
        $cmd_exec = "Process.Start" ascii wide
        $exchange_path = "\\inetpub\\wwwroot\\aspnet_client" ascii wide nocase
        $str1 = "Chopper" ascii wide nocase
        $str2 = "shell.aspx" ascii wide nocase
        $http_resp = "Response.Write" ascii wide

    condition:
        $aspx and $cmd_arg and $cmd_exec and ($exchange_path or $str1 or $str2 or $http_resp)
}`,
  },
  {
    name: "Stealer_Vidar_Stealer",
    description: "Detects Vidar infostealer by C2 Telegram channel patterns and browser credential targeting.",
    category: "stealer",
    author: "TrustedSec Threat Intel",
    reference: "https://attack.mitre.org/software/S0556/",
    tags: ["vidar", "stealer", "infostealer", "telegram"],
    severity: "high",
    techniqueExternalId: "T1555.003",
    rule: `rule Stealer_Vidar_Stealer : stealer vidar infostealer {
    meta:
        description = "Detects Vidar infostealer Telegram C2 and credential targeting"
        author = "TrustedSec Threat Intel"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/software/S0556/"
        severity = "high"

    strings:
        $tg = "api.telegram.org" ascii wide nocase
        $cfg1 = "MaxConnections" ascii wide
        $steal1 = "\\Login Data" ascii wide
        $steal2 = "\\Cookies" ascii wide
        $steal3 = "\\Web Data" ascii wide
        $ftp = "FileZilla" ascii wide nocase
        $wallet1 = "Exodus" ascii wide nocase
        $wallet2 = "Electrum" ascii wide nocase

    condition:
        ($tg and any of ($steal*)) or (3 of ($steal*, $ftp, $wallet*, $cfg*))
}`,
  },

  // =========================================================================
  // DRAGONFORCE / BACKDOOR.TURN
  // =========================================================================
  {
    name: "RAT_BackdoorTurn_TeamsRelay",
    description: "Detects Backdoor.Turn, a Go-based RAT used by DragonForce that abuses Microsoft Teams TURN relay servers for C2. Identifies TURN relay auth strings, anonymous token acquisition, and QUIC tunnel setup patterns.",
    category: "rat",
    author: "TrustedSec Threat Intel",
    reference: "https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor",
    tags: ["dragonforce", "backdoor-turn", "teams", "turn-relay", "c2", "rat"],
    severity: "critical",
    techniqueExternalId: "T1102",
    rule: `rule RAT_BackdoorTurn_TeamsRelay : rat dragonforce c2 {
    meta:
        description = "Detects Backdoor.Turn RAT abusing Microsoft Teams TURN relays for C2"
        author = "TrustedSec Threat Intel"
        date = "2026-06-24"
        reference = "https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor"
        severity = "critical"

    strings:
        $turn1 = "turn.teams.microsoft.com" ascii wide
        $turn2 = "relay.teams.microsoft.com" ascii wide
        $turn3 = "turn3.teams.microsoft.com" ascii wide
        $skype1 = "api.skype.com" ascii wide
        $skype2 = "edge.skype.com" ascii wide
        $token1 = "anonymousToken" ascii wide
        $token2 = "visitor" ascii wide
        $quic1 = "quic-go" ascii wide
        $quic2 = "QUIC" ascii wide
        $go_build = "Go build" ascii
        $vbox1 = "vboxrt.dll" ascii wide nocase
        $vbox2 = "DbgView64" ascii wide nocase
        $cmd1 = "cmd.exe /c" ascii wide
        $ldap1 = "LDAP://" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($turn*, $skype*) and any of ($token*)) or
            (any of ($turn*) and any of ($quic*) and $go_build) or
            ($vbox1 and $vbox2 and any of ($turn*, $skype*))
        )
}`,
  },
  {
    name: "Ransomware_DragonForce_Payload",
    description: "Detects DragonForce ransomware payloads based on ContiV3/LockBit variants with DragonForce-specific ransom note markers and encryption configuration strings.",
    category: "ransomware",
    author: "TrustedSec Threat Intel",
    reference: "https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-dragonforce",
    tags: ["dragonforce", "ransomware", "conti", "lockbit", "extortion"],
    severity: "critical",
    techniqueExternalId: "T1486",
    rule: `rule Ransomware_DragonForce_Payload : ransomware dragonforce {
    meta:
        description = "Detects DragonForce ransomware payload variants"
        author = "TrustedSec Threat Intel"
        date = "2026-06-24"
        reference = "https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-dragonforce"
        severity = "critical"

    strings:
        $note1 = "DragonForce" ascii wide nocase
        $note2 = "DragonLeaks" ascii wide nocase
        $note3 = ".dragonforce" ascii wide nocase
        $tor1 = ".onion" ascii wide
        $enc1 = "vssadmin delete shadows" ascii wide nocase
        $enc2 = "bcdedit /set" ascii wide nocase
        $enc3 = "wbadmin delete catalog" ascii wide nocase
        $edr1 = "TerminateProcess" ascii wide
        $edr2 = "NtTerminateProcess" ascii wide
        $mutex1 = "Global\\" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($note*) and $tor1) or
            (any of ($note*) and 2 of ($enc*)) or
            (any of ($note*) and any of ($edr*) and any of ($enc*))
        )
}`,
  },
  {
    name: "Tool_AbyssWorker_EDRKiller",
    description: "Detects the Abyss Worker malicious kernel driver used by DragonForce for EDR/AV process termination. Masquerades as a Palo Alto Networks driver.",
    category: "apt-tool",
    author: "TrustedSec Threat Intel",
    reference: "https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor",
    tags: ["dragonforce", "byovd", "edr-killer", "kernel-driver", "abyss-worker"],
    severity: "critical",
    techniqueExternalId: "T1562.001",
    rule: `rule Tool_AbyssWorker_EDRKiller : tool dragonforce byovd {
    meta:
        description = "Detects Abyss Worker driver used by DragonForce for EDR termination"
        author = "TrustedSec Threat Intel"
        date = "2026-06-24"
        reference = "https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor"
        severity = "critical"

    strings:
        $s1 = "AbyssWorker" ascii wide nocase
        $s2 = "Palo Alto Networks" ascii wide
        $ioctl1 = "DeviceIoControl" ascii wide
        $kill1 = "ZwTerminateProcess" ascii wide
        $kill2 = "PsTerminateSystemThread" ascii wide
        $hash1 = "8284c8676cc22c4b2e66826ac16986da7ddecba1f2776b16771be17bfdc45dc2"
        $hash2 = "65ab49119c845801f29a57e8aa177146b2ffbd289d4278109b146f933380f951"

    condition:
        uint16(0) == 0x5A4D and
        (
            ($s1 and $s2) or
            ($s2 and any of ($kill*) and $ioctl1) or
            any of ($hash*)
        )
}`,
  },
];

async function findMalware(names: string[]): Promise<string | undefined> {
  for (const name of names) {
    const m = await prisma.malware.findFirst({
      where: {
        OR: [
          { name: { contains: name } },
          { aliases: { contains: name } },
        ],
      },
    });
    if (m) return m.id;
  }
  return undefined;
}

async function findTechnique(externalId: string): Promise<string | undefined> {
  const t = await prisma.technique.findFirst({ where: { externalId } });
  return t?.id;
}

async function main() {
  console.log("Seeding YARA rules...");
  let created = 0;
  let updated = 0;

  for (const seed of RULES) {
    const malwareId = seed.malwareNames ? await findMalware(seed.malwareNames) : undefined;
    const techniqueId = seed.techniqueExternalId ? await findTechnique(seed.techniqueExternalId) : undefined;

    const data = {
      description: seed.description,
      rule: seed.rule,
      category: seed.category,
      author: seed.author,
      reference: seed.reference,
      tags: seed.tags.join(","),
      severity: seed.severity,
      malwareId: malwareId ?? null,
      techniqueId: techniqueId ?? null,
    };

    const existing = await prisma.yaraRule.findUnique({ where: { name: seed.name } });
    if (existing) {
      await prisma.yaraRule.update({ where: { name: seed.name }, data });
      updated++;
    } else {
      await prisma.yaraRule.create({ data: { name: seed.name, ...data } });
      created++;
    }
  }

  console.log(`Done. Created: ${created}, Updated: ${updated}`);
  await prisma.$disconnect();
}

main().catch((e) => {
  console.error(e);
  prisma.$disconnect();
  process.exit(1);
});
