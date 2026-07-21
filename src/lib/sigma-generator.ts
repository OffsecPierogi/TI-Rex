import { createHash } from "node:crypto";

export interface SigmaRule {
  title: string;
  id: string;
  status: "experimental";
  level: "medium" | "high" | "critical";
  description: string;
  references: string[];
  author: string;
  date: string;
  tags: string[];
  logsource: {
    category?: string;
    product?: string;
    service?: string;
  };
  detection: {
    selection: Record<string, string | string[]>;
    condition: string;
  };
  falsepositives: string[];
}

export interface CommandAnalysis {
  executorFamily: "powershell" | "cmd" | "bash" | "manual";
  matchedPatterns: string[];
  extractedKeywords: string[];
  levelReason: string;
  tacticTag: string | null;
  selectionField: string;
  selectionMode: "contains|all" | "contains" | "endswith";
}

const TACTIC_MAP: Record<string, string> = {
  T1001: "exfiltration",
  T1003: "credential-access",
  T1005: "collection",
  T1007: "discovery",
  T1008: "command-and-control",
  T1010: "discovery",
  T1012: "discovery",
  T1014: "defense-evasion",
  T1016: "discovery",
  T1018: "discovery",
  T1021: "lateral-movement",
  T1027: "defense-evasion",
  T1033: "discovery",
  T1036: "defense-evasion",
  T1037: "persistence",
  T1040: "credential-access",
  T1041: "exfiltration",
  T1046: "discovery",
  T1047: "execution",
  T1048: "exfiltration",
  T1049: "discovery",
  T1053: "execution",
  T1055: "defense-evasion",
  T1056: "collection",
  T1057: "discovery",
  T1059: "execution",
  T1068: "privilege-escalation",
  T1069: "discovery",
  T1070: "defense-evasion",
  T1071: "command-and-control",
  T1072: "lateral-movement",
  T1074: "collection",
  T1078: "defense-evasion",
  T1082: "discovery",
  T1083: "discovery",
  T1087: "discovery",
  T1090: "command-and-control",
  T1098: "persistence",
  T1105: "command-and-control",
  T1106: "execution",
  T1110: "credential-access",
  T1112: "defense-evasion",
  T1113: "collection",
  T1119: "collection",
  T1120: "discovery",
  T1123: "collection",
  T1125: "collection",
  T1127: "defense-evasion",
  T1129: "execution",
  T1132: "command-and-control",
  T1134: "privilege-escalation",
  T1135: "discovery",
  T1136: "persistence",
  T1137: "persistence",
  T1140: "defense-evasion",
  T1176: "persistence",
  T1185: "collection",
  T1187: "credential-access",
  T1190: "initial-access",
  T1197: "defense-evasion",
  T1199: "initial-access",
  T1200: "initial-access",
  T1201: "discovery",
  T1202: "defense-evasion",
  T1203: "execution",
  T1204: "execution",
  T1207: "defense-evasion",
  T1210: "lateral-movement",
  T1211: "defense-evasion",
  T1212: "credential-access",
  T1213: "collection",
  T1216: "defense-evasion",
  T1217: "discovery",
  T1218: "defense-evasion",
  T1219: "command-and-control",
  T1220: "defense-evasion",
  T1221: "defense-evasion",
  T1222: "defense-evasion",
  T1480: "defense-evasion",
  T1482: "discovery",
  T1484: "defense-evasion",
  T1485: "impact",
  T1486: "impact",
  T1489: "impact",
  T1490: "impact",
  T1491: "impact",
  T1496: "impact",
  T1497: "defense-evasion",
  T1498: "impact",
  T1499: "impact",
  T1505: "persistence",
  T1518: "discovery",
  T1525: "persistence",
  T1526: "discovery",
  T1528: "credential-access",
  T1529: "impact",
  T1530: "collection",
  T1531: "impact",
  T1537: "exfiltration",
  T1538: "discovery",
  T1539: "credential-access",
  T1543: "persistence",
  T1546: "persistence",
  T1547: "persistence",
  T1548: "privilege-escalation",
  T1550: "lateral-movement",
  T1552: "credential-access",
  T1553: "defense-evasion",
  T1555: "credential-access",
  T1556: "credential-access",
  T1557: "credential-access",
  T1558: "credential-access",
  T1559: "execution",
  T1560: "collection",
  T1561: "impact",
  T1562: "defense-evasion",
  T1563: "lateral-movement",
  T1564: "defense-evasion",
  T1565: "impact",
  T1566: "initial-access",
  T1567: "exfiltration",
  T1568: "command-and-control",
  T1569: "execution",
  T1570: "lateral-movement",
  T1571: "command-and-control",
  T1572: "command-and-control",
  T1573: "command-and-control",
  T1574: "persistence",
  T1578: "defense-evasion",
  T1580: "discovery",
  T1583: "resource-development",
  T1584: "resource-development",
  T1585: "resource-development",
  T1586: "resource-development",
  T1587: "resource-development",
  T1588: "resource-development",
  T1589: "reconnaissance",
  T1590: "reconnaissance",
  T1591: "reconnaissance",
  T1592: "reconnaissance",
  T1593: "reconnaissance",
  T1594: "reconnaissance",
  T1595: "reconnaissance",
  T1596: "reconnaissance",
  T1597: "reconnaissance",
  T1598: "reconnaissance",
  T1599: "defense-evasion",
  T1600: "defense-evasion",
  T1601: "defense-evasion",
  T1602: "collection",
  T1606: "credential-access",
  T1608: "resource-development",
  T1609: "execution",
  T1610: "defense-evasion",
  T1611: "privilege-escalation",
  T1612: "resource-development",
  T1613: "discovery",
  T1614: "discovery",
  T1615: "discovery",
  T1619: "discovery",
  T1620: "defense-evasion",
  T1621: "credential-access",
  T1622: "defense-evasion",
  T1647: "defense-evasion",
  T1648: "execution",
  T1649: "credential-access",
  T1650: "resource-development",
  T1651: "execution",
  T1652: "discovery",
  T1653: "persistence",
  T1654: "discovery",
  T1656: "defense-evasion",
  T1657: "impact",
  T1659: "command-and-control",
};

const PS_SUSPICIOUS_PATTERNS: Array<[RegExp, string]> = [
  [/Invoke-Expression|IEX\b/i, "IEX"],
  [/Invoke-WebRequest|iwr\b/i, "Invoke-WebRequest"],
  [/Invoke-Mimikatz/i, "Invoke-Mimikatz"],
  [/Invoke-ReflectivePEInjection/i, "Invoke-ReflectivePEInjection"],
  [/Invoke-Shellcode/i, "Invoke-Shellcode"],
  [/Invoke-WmiMethod|Invoke-CimMethod/i, "Invoke-WmiMethod"],
  [/New-Object\s+Net\.WebClient|New-Object\s+System\.Net\.WebClient/i, "New-Object Net.WebClient"],
  [/\.DownloadString\s*\(/i, "DownloadString"],
  [/\.DownloadFile\s*\(/i, "DownloadFile"],
  [/\-EncodedCommand|\-enc\b/i, "-EncodedCommand"],
  [/\[System\.Convert\]::FromBase64String/i, "FromBase64String"],
  [/\[Reflection\.Assembly\]|Assembly\.Load/i, "[Reflection.Assembly]"],
  [/Add-Type\s+-AssemblyName\s+System\.Windows\.Forms/i, "Add-Type"],
  [/Add-Type\s+-TypeDefinition/i, "Add-Type -TypeDefinition"],
  [/Start-Process\s+-WindowStyle\s+Hidden/i, "Start-Process -WindowStyle Hidden"],
  [/Get-WmiObject|gwmi\b/i, "Get-WmiObject"],
  [/\$env:TEMP|\$env:APPDATA|\$env:PUBLIC/i, "env:TEMP/APPDATA/PUBLIC"],
  [/Set-MpPreference/i, "Set-MpPreference"],
  [/Disable-WindowsOptionalFeature/i, "Disable-WindowsOptionalFeature"],
  [/Net\.Sockets\.TcpClient/i, "Net.Sockets.TcpClient"],
  [/\[System\.Runtime\.InteropServices\.Marshal\]/i, "[Runtime.InteropServices.Marshal]"],
  [/VirtualAlloc|WriteProcessMemory|CreateRemoteThread/i, "VirtualAlloc/WriteProcessMemory"],
  [/sekurlsa|lsadump|kerberos/i, "mimikatz module"],
  [/mimikatz/i, "mimikatz"],
  [/procdump|lsass/i, "lsass dump"],
  [/\-nop\b|\-noprofile\b/i, "-noprofile"],
  [/\-windowstyle\s+hidden/i, "-windowstyle hidden"],
  [/\-exec\s+bypass/i, "-exec bypass"],
  [/reg\s+add|reg\s+delete|reg\s+export/i, "reg"],
  [/sc\.exe\s+create|sc\s+create/i, "sc create"],
  [/schtasks/i, "schtasks"],
  [/Compress-Archive|Expand-Archive/i, "Archive cmdlet"],
  [/ConvertTo-SecureString/i, "ConvertTo-SecureString"],
  [/Get-Credential/i, "Get-Credential"],
  [/netsh/i, "netsh"],
  [/whoami|hostname/i, "whoami/hostname"],
  [/ipconfig|arp\s+-a|route\s+print/i, "network recon"],
  [/net\s+user|net\s+group|net\s+localgroup/i, "net user/group"],
  [/nltest/i, "nltest"],
  [/dsquery|dsget/i, "dsquery"],
];

const CMD_SUSPICIOUS_PATTERNS: Array<[RegExp, string]> = [
  [/certutil/i, "certutil"],
  [/bitsadmin/i, "bitsadmin"],
  [/wmic/i, "wmic"],
  [/reg\s+add|reg\s+delete|reg\s+query|reg\s+export/i, "reg"],
  [/net\s+user|net\s+group|net\s+localgroup|net\s+share|net\s+use/i, "net"],
  [/nltest/i, "nltest"],
  [/dsquery|dsget/i, "dsquery"],
  [/schtasks/i, "schtasks"],
  [/sc\s+create|sc\s+config|sc\s+start|sc\s+stop/i, "sc"],
  [/netsh/i, "netsh"],
  [/at\s+\d{2}:\d{2}/i, "at"],
  [/vssadmin/i, "vssadmin"],
  [/bcdedit/i, "bcdedit"],
  [/icacls|cacls|takeown/i, "icacls/takeown"],
  [/xcopy|robocopy/i, "xcopy/robocopy"],
  [/forfiles/i, "forfiles"],
  [/cmd\s+\/c|cmd\.exe\s+\/c/i, "cmd /c"],
  [/powershell\s+-/i, "powershell inline"],
  [/mshta|wscript|cscript/i, "script host"],
  [/regsvr32|regsvcs|regasm/i, "COM registration abuse"],
  [/rundll32/i, "rundll32"],
  [/msiexec/i, "msiexec"],
  [/curl|wget/i, "curl/wget"],
  [/ftp\s+-s/i, "ftp script"],
  [/whoami|hostname/i, "whoami/hostname"],
  [/ipconfig|arp\s+-a|route\s+print|netstat/i, "network recon"],
  [/tasklist|taskkill/i, "tasklist/taskkill"],
  [/dir\s+\/s|dir\s+\/b|dir\s+\/a/i, "dir enum"],
  [/findstr/i, "findstr"],
  [/type\s+.*\\passwords?|type\s+.*\\cred/i, "credential file read"],
  [/mimikatz/i, "mimikatz"],
];

const BASH_SUSPICIOUS_PATTERNS: Array<[RegExp, string]> = [
  [/curl\s/i, "curl"],
  [/wget\s/i, "wget"],
  [/\bnc\b|\bncat\b|\bnetcat\b/i, "netcat"],
  [/python[23]?\s+-[cm]/i, "python -c/-m"],
  [/perl\s+-e/i, "perl -e"],
  [/ruby\s+-e/i, "ruby -e"],
  [/base64\s+-d|base64\s+--decode/i, "base64 decode"],
  [/openssl\s+enc/i, "openssl enc"],
  [/openssl\s+s_client/i, "openssl s_client"],
  [/awk\s+'.*system\(/i, "awk system"],
  [/\/bin\/sh\s+-i|\/bin\/bash\s+-i/i, "/bin/sh -i"],
  [/chmod\s+[0-7]*[46][0-7]{2}|chmod\s+[ugo]*[+]s/i, "setuid chmod"],
  [/chown\s+root/i, "chown root"],
  [/crontab\s+-e|crontab\s+-l|echo.*cron/i, "crontab"],
  [/\/etc\/passwd|\/etc\/shadow/i, "/etc/passwd or shadow"],
  [/\/etc\/sudoers/i, "/etc/sudoers"],
  [/ssh-keygen|authorized_keys/i, "ssh key manipulation"],
  [/find\s+.*\-perm\s+-[0-9]*4[0-9]*/i, "find suid"],
  [/find\s+.*\-perm\s+-[0-9]*2[0-9]*/i, "find sgid"],
  [/msfvenom|msfconsole/i, "metasploit"],
  [/nmap\b/i, "nmap"],
  [/tcpdump/i, "tcpdump"],
  [/strace/i, "strace"],
  [/pkexec/i, "pkexec"],
  [/sudo\s+-l|sudo\s+-ll/i, "sudo -l"],
  [/ldapsearch/i, "ldapsearch"],
  [/socat/i, "socat"],
  [/mkfifo/i, "mkfifo"],
  [/tar\s+.*[zj]xf|tar\s+--extract/i, "tar extract"],
  [/cat\s+.*passwords?|cat\s+.*\.key|cat\s+.*\.pem/i, "credential file read"],
  [/dd\s+if=/i, "dd"],
  [/rsync\s+-a|rsync\s+-r/i, "rsync"],
  [/scp\s+-r|scp\s+-P/i, "scp"],
  [/useradd|adduser|groupadd/i, "useradd"],
  [/iptables\s+-F|ufw\s+disable/i, "firewall disable"],
  [/shred|wipe|srm/i, "secure delete"],
  [/history\s+-c|rm\s+~\/\.bash_history/i, "history wipe"],
];

function extractExecutable(cmd: string, patterns: Array<[RegExp, string]>): string[] {
  const matched: string[] = [];
  for (const [re, label] of patterns) {
    if (re.test(cmd)) {
      if (!matched.includes(label)) matched.push(label);
    }
  }
  return matched;
}

function determineTechniqePrefix(techniqueId: string): string {
  const base = techniqueId.split(".")[0];
  return base;
}

function getTacticTag(techniqueId: string): string | null {
  const base = determineTechniqePrefix(techniqueId);
  const tactic = TACTIC_MAP[base];
  return tactic ?? null;
}

function buildTags(techniqueId: string, tactic: string | null): string[] {
  const tags: string[] = [];
  const normalized = techniqueId.toLowerCase().replace(".", ".");
  tags.push(`attack.${normalized}`);
  if (tactic) {
    tags.push(`attack.${tactic}`);
  }
  return tags;
}

function determineLevel(
  techniqueId: string,
  elevationRequired: boolean,
): { level: "medium" | "high" | "critical"; reason: string } {
  const base = determineTechniqePrefix(techniqueId);

  if (base === "T1003") {
    return { level: "critical", reason: "Credential access technique (T1003) — OS credential dumping" };
  }
  if (base.startsWith("T1558") || base.startsWith("T1555") || base.startsWith("T1552")) {
    return { level: "critical", reason: `Credential access technique (${base})` };
  }
  if (base.startsWith("T1070") || base.startsWith("T1562")) {
    return { level: "high", reason: `Defense evasion technique (${base})` };
  }
  if (elevationRequired) {
    return { level: "high", reason: "Command requires elevated privileges" };
  }
  return { level: "medium", reason: "Default severity for this technique category" };
}

export function analyzeCommand(test: {
  name: string;
  techniqueId: string;
  description: string;
  executor: string;
  command: string;
  platforms: string;
  elevationRequired: boolean;
}): CommandAnalysis {
  const exec = test.executor.toLowerCase();
  let executorFamily: CommandAnalysis["executorFamily"];
  let matchedPatterns: string[];
  let selectionField: string;
  let selectionMode: CommandAnalysis["selectionMode"];

  if (exec === "powershell") {
    executorFamily = "powershell";
    matchedPatterns = extractExecutable(test.command, PS_SUSPICIOUS_PATTERNS);
    selectionField = "CommandLine|contains|all";
    selectionMode = "contains|all";
  } else if (exec === "command_prompt") {
    executorFamily = "cmd";
    matchedPatterns = extractExecutable(test.command, CMD_SUSPICIOUS_PATTERNS);
    selectionField = "CommandLine|contains";
    selectionMode = "contains";
  } else if (exec === "bash" || exec === "sh") {
    executorFamily = "bash";
    matchedPatterns = extractExecutable(test.command, BASH_SUSPICIOUS_PATTERNS);
    selectionField = "CommandLine|contains";
    selectionMode = "contains";
  } else {
    executorFamily = "manual";
    matchedPatterns = [];
    selectionField = "CommandLine|contains";
    selectionMode = "contains";
  }

  const extractedKeywords = extractKeywordsFromCommand(test.command, executorFamily);
  const { level: _level, reason: levelReason } = determineLevel(test.techniqueId, test.elevationRequired);
  const tacticTag = getTacticTag(test.techniqueId);

  return {
    executorFamily,
    matchedPatterns,
    extractedKeywords,
    levelReason,
    tacticTag,
    selectionField,
    selectionMode,
  };
}

function extractKeywordsFromCommand(command: string, family: CommandAnalysis["executorFamily"]): string[] {
  const keywords: string[] = [];

  if (family === "powershell") {
    const cmdlets = command.match(/(?:Invoke|Get|Set|New|Remove|Start|Stop|Add|Import|Export|Enable|Disable|Write|Read|Out|Select|Where|Sort|Group|Measure|Test|Register|Unregister|ConvertTo|ConvertFrom|Copy|Move|Rename|Clear|Update|Publish|Send|Receive|Connect|Disconnect|Enter|Exit|Find|Install|Uninstall|Save|Use|Wait|Show|Hide|Lock|Unlock|Push|Pop|Format|Compare|Split|Join|Protect|Unprotect|Mount|Dismount|Suspend|Resume|Reset)-[A-Za-z]+/g);
    if (cmdlets) {
      const unique = [...new Set(cmdlets)].slice(0, 5);
      keywords.push(...unique);
    }

    const dotnetTypes = command.match(/\[(?:System\.)?(?:Net\.WebClient|Convert|Runtime\.InteropServices\.[A-Za-z]+|Reflection\.Assembly)\]/g);
    if (dotnetTypes) keywords.push(...dotnetTypes.slice(0, 3));

    const envVars = command.match(/\$env:[A-Z_]+/gi);
    if (envVars) keywords.push(...[...new Set(envVars)].slice(0, 3));

  } else if (family === "cmd") {
    const exeMatches = command.match(/\b(?:certutil|bitsadmin|wmic|reg|net|nltest|dsquery|dsget|schtasks|netsh|sc|vssadmin|bcdedit|icacls|mshta|wscript|cscript|regsvr32|regsvcs|regasm|rundll32|msiexec|tasklist|taskkill|findstr|forfiles|xcopy|robocopy|curl|wget|ftp|msiexec|whoami|hostname|ipconfig|arp|route|netstat|nslookup|mimikatz)\b/gi);
    if (exeMatches) keywords.push(...[...new Set(exeMatches.map((e) => e.toLowerCase()))].slice(0, 5));

  } else if (family === "bash") {
    const binaries = command.match(/\b(?:curl|wget|nc|ncat|netcat|python[23]?|perl|ruby|openssl|awk|sed|base64|find|nmap|tcpdump|ldapsearch|socat|mkfifo|useradd|adduser|crontab|ssh-keygen|dd|rsync|scp|iptables|ufw|shred|wipe|strace|pkexec|sudo|chmod|chown|msfvenom|msfconsole)\b/g);
    if (binaries) keywords.push(...[...new Set(binaries)].slice(0, 6));
  }

  if (keywords.length === 0) {
    const words = command
      .replace(/[#"'\n\r\t]/g, " ")
      .split(/\s+/)
      .filter((w) => w.length > 3 && !/^\$/.test(w) && !/^\{/.test(w))
      .slice(0, 5);
    keywords.push(...words);
  }

  return keywords;
}

function makeDeterministicUUID(techniqueId: string, name: string): string {
  const input = `${techniqueId}::${name}`;
  const hash = createHash("sha1").update(input).digest("hex");
  const p1 = hash.substring(0, 8);
  const p2 = hash.substring(8, 12);
  const p3 = "4" + hash.substring(13, 16);
  const variant = (parseInt(hash[16], 16) & 0x3 | 0x8).toString(16);
  const p4 = variant + hash.substring(17, 20);
  const p5 = hash.substring(20, 32);
  return `${p1}-${p2}-${p3}-${p4}-${p5}`;
}

function buildLogSource(
  executorFamily: CommandAnalysis["executorFamily"],
  command: string,
): SigmaRule["logsource"] {
  switch (executorFamily) {
    case "powershell": {
      const useScriptLog =
        /Invoke-Expression|IEX\b|\-EncodedCommand|\-enc\b|\.DownloadString|FromBase64String/i.test(command);
      return useScriptLog
        ? { product: "windows", service: "powershell" }
        : { category: "process_creation", product: "windows" };
    }
    case "cmd":
      return { category: "process_creation", product: "windows" };
    case "bash":
      return { category: "process_creation", product: "linux" };
    default:
      return { category: "process_creation", product: "windows" };
  }
}

function buildSelection(
  executorFamily: CommandAnalysis["executorFamily"],
  keywords: string[],
  matchedPatterns: string[],
  command: string,
): Record<string, string | string[]> {
  const safeKeywords = keywords.slice(0, 6).map(sanitizeForYamlValue);
  const allTerms = [...new Set([...matchedPatterns.slice(0, 4), ...safeKeywords])].filter(Boolean);

  if (executorFamily === "powershell") {
    if (command.includes("powershell") || command.toLowerCase().includes("powershell")) {
      const selection: Record<string, string | string[]> = {
        "Image|endswith": "\\powershell.exe",
      };
      if (allTerms.length > 0) {
        selection["CommandLine|contains|all"] = allTerms.length === 1 ? allTerms[0] : allTerms;
      }
      return selection;
    }
    const selection: Record<string, string | string[]> = {};
    if (allTerms.length > 0) {
      selection["CommandLine|contains|all"] = allTerms.length === 1 ? allTerms[0] : allTerms;
    } else {
      selection["Image|endswith"] = "\\powershell.exe";
    }
    return selection;
  }

  if (executorFamily === "cmd") {
    const exes = detectCmdExecutables(command);
    const selection: Record<string, string | string[]> = {};
    if (exes.length > 0) {
      selection["Image|endswith"] = exes.length === 1 ? exes[0] : exes;
    }
    const terms = allTerms.filter((t) => t.length > 2);
    if (terms.length > 0) {
      selection["CommandLine|contains"] = terms.length === 1 ? terms[0] : terms;
    }
    if (Object.keys(selection).length === 0) {
      selection["Image|endswith"] = "\\cmd.exe";
    }
    return selection;
  }

  if (executorFamily === "bash") {
    const binaries = detectBashBinaries(command);
    const selection: Record<string, string | string[]> = {};
    if (binaries.length > 0) {
      selection["Image|endswith"] = binaries.length === 1 ? binaries[0] : binaries;
    }
    const terms = allTerms.filter((t) => t.length > 2);
    if (terms.length > 0) {
      selection["CommandLine|contains"] = terms.length === 1 ? terms[0] : terms;
    }
    if (Object.keys(selection).length === 0) {
      selection["CommandLine|contains"] = allTerms.length > 0 ? allTerms : ["/bin/sh", "/bin/bash"];
    }
    return selection;
  }

  const fragments = command
    .split(/\s+/)
    .filter((w) => w.length > 4 && !w.startsWith("$") && !w.startsWith("{") && !w.includes("\\"))
    .slice(0, 4)
    .map(sanitizeForYamlValue);
  return {
    "CommandLine|contains": fragments.length === 1 ? fragments[0] : (fragments.length > 0 ? fragments : ["<generic>"])
  };
}

function detectCmdExecutables(command: string): string[] {
  const knownExes = [
    "certutil", "bitsadmin", "wmic", "nltest", "dsquery", "schtasks",
    "mshta", "wscript", "cscript", "regsvr32", "regsvcs", "regasm",
    "rundll32", "msiexec", "tasklist", "taskkill", "forfiles", "vssadmin", "bcdedit",
  ];
  const found: string[] = [];
  for (const exe of knownExes) {
    if (new RegExp(`\\b${exe}\\b`, "i").test(command)) {
      found.push(`\\${exe}.exe`);
    }
  }
  return found.slice(0, 3);
}

function detectBashBinaries(command: string): string[] {
  const knownBins = [
    "curl", "wget", "nc", "ncat", "python3", "python", "perl", "ruby",
    "openssl", "nmap", "tcpdump", "ldapsearch", "socat",
    "msfvenom", "msfconsole", "pkexec",
  ];
  const found: string[] = [];
  for (const bin of knownBins) {
    if (new RegExp(`\\b${bin}\\b`, "i").test(command)) {
      found.push(`/${bin}`);
    }
  }
  return found.slice(0, 3);
}

function sanitizeForYamlValue(s: string): string {
  return s.replace(/[\n\r\t]/g, " ").trim();
}

export function generateSigmaRule(test: {
  name: string;
  techniqueId: string;
  description: string;
  executor: string;
  command: string;
  platforms: string;
  elevationRequired: boolean;
}): SigmaRule {
  const analysis = analyzeCommand(test);
  const { level, reason: _reason } = determineLevel(test.techniqueId, test.elevationRequired);
  const id = makeDeterministicUUID(test.techniqueId, test.name);
  const tags = buildTags(test.techniqueId, analysis.tacticTag);
  const logsource = buildLogSource(analysis.executorFamily, test.command);
  const selection = buildSelection(
    analysis.executorFamily,
    analysis.extractedKeywords,
    analysis.matchedPatterns,
    test.command,
  );

  const today = new Date();
  const date = `${today.getFullYear()}/${String(today.getMonth() + 1).padStart(2, "0")}/${String(today.getDate()).padStart(2, "0")}`;

  const titlePrefix =
    analysis.executorFamily === "powershell" ? "Suspicious PowerShell" :
    analysis.executorFamily === "cmd" ? "Suspicious CMD" :
    analysis.executorFamily === "bash" ? "Suspicious Shell" :
    "Suspicious Process";

  return {
    title: `${titlePrefix} - ${test.name}`.slice(0, 100),
    id,
    status: "experimental",
    level,
    description: `Detects execution matching Atomic Red Team test: ${test.name}. Technique ${test.techniqueId}: ${test.description.slice(0, 200)}`,
    references: [
      `https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/${test.techniqueId}`,
      `https://attack.mitre.org/techniques/${test.techniqueId.replace(".", "/")}/`,
    ],
    author: "Atomic Red Team / TrustedSec",
    date,
    tags,
    logsource,
    detection: {
      selection,
      condition: "selection",
    },
    falsepositives: [
      "Legitimate administrative activity",
      "Security testing and red team exercises",
      "Authorized penetration tests",
    ],
  };
}

function yamlString(value: string): string {
  if (value === "") return "''";
  const needsQuoting =
    value.includes(":") ||
    value.includes("#") ||
    value.includes("'") ||
    value.includes('"') ||
    value.startsWith("-") ||
    value.startsWith("*") ||
    value.startsWith("&") ||
    value.startsWith("!") ||
    value.startsWith("|") ||
    value.startsWith(">") ||
    value.startsWith(" ") ||
    value.endsWith(" ") ||
    value.includes("\n");

  if (!needsQuoting) return value;
  return `'${value.replace(/'/g, "''")}'`;
}

function yamlStringOrList(value: string | string[], indent: number): string {
  const pad = " ".repeat(indent);
  if (typeof value === "string") {
    return yamlString(value);
  }
  return "\n" + value.map((v) => `${pad}  - ${yamlString(v)}`).join("\n");
}

export function sigmaToYaml(rule: SigmaRule): string {
  const lines: string[] = [];

  lines.push(`title: ${yamlString(rule.title)}`);
  lines.push(`id: ${rule.id}`);
  lines.push(`status: ${rule.status}`);
  lines.push(`level: ${rule.level}`);
  lines.push(`description: ${yamlString(rule.description)}`);
  lines.push(`references:`);
  for (const ref of rule.references) {
    lines.push(`  - ${yamlString(ref)}`);
  }
  lines.push(`author: ${yamlString(rule.author)}`);
  lines.push(`date: ${rule.date}`);
  lines.push(`tags:`);
  for (const tag of rule.tags) {
    lines.push(`  - ${tag}`);
  }
  lines.push(`logsource:`);
  if (rule.logsource.category) lines.push(`  category: ${rule.logsource.category}`);
  if (rule.logsource.product) lines.push(`  product: ${rule.logsource.product}`);
  if (rule.logsource.service) lines.push(`  service: ${rule.logsource.service}`);
  lines.push(`detection:`);
  lines.push(`  selection:`);
  for (const [key, value] of Object.entries(rule.detection.selection)) {
    const rendered = yamlStringOrList(value, 4);
    if (rendered.startsWith("\n")) {
      lines.push(`    ${key}:${rendered}`);
    } else {
      lines.push(`    ${key}: ${rendered}`);
    }
  }
  lines.push(`  condition: ${rule.detection.condition}`);
  lines.push(`falsepositives:`);
  for (const fp of rule.falsepositives) {
    lines.push(`  - ${yamlString(fp)}`);
  }

  return lines.join("\n");
}
