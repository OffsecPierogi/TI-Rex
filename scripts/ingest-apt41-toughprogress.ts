import { prisma } from "../src/lib/db";

// APT41 TOUGHPROGRESS Campaign — Google Threat Intelligence Group (GTIG)
// Source: https://cloud.google.com/blog/topics/threat-intelligence/apt41-innovative-tactics
// Date: 2025 (published by Google Cloud Security)

async function main() {
  console.log("=== Ingesting APT41 TOUGHPROGRESS Campaign ===\n");

  // ── Find APT41 actor ──────────────────────────────────────────────────
  const apt41 = await prisma.threatActor.findFirst({
    where: { OR: [{ name: "APT41" }, { aliases: { contains: "APT41" } }] },
  });
  if (!apt41) {
    console.log("APT41 actor not found in DB — run MITRE ingestion first");
    return;
  }
  console.log(`Found APT41: ${apt41.id}`);

  // Update APT41 aliases to include HOODOO
  const currentAliases: string[] = JSON.parse(apt41.aliases || "[]");
  if (!currentAliases.includes("HOODOO")) {
    currentAliases.push("HOODOO");
    await prisma.threatActor.update({
      where: { id: apt41.id },
      data: { aliases: JSON.stringify(currentAliases) },
    });
    console.log("  Added HOODOO alias to APT41");
  }

  // ── Create malware entries ────────────────────────────────────────────
  const malwareEntries = [
    {
      name: "TOUGHPROGRESS",
      description:
        "Windows backdoor used by APT41 that uses Google Calendar API for command-and-control. The final payload stage in a multi-stage infection chain (PLUSDROP → PLUSINJECT → TOUGHPROGRESS). Implements multiple obfuscation techniques including register-based indirect calls, dynamic address arithmetic with intentional 64-bit register overflow, and function dispatch tables. Shellcode is embedded in the .pdata section encrypted with a 16-byte XOR key, decompressed via LZNT1. C2 communication uses Google Calendar events — commands are retrieved from hardcoded calendar dates, results are posted back as encrypted event descriptions using a layered XOR encryption scheme with LZNT1 compression.",
      type: "backdoor",
    },
    {
      name: "PLUSDROP",
      description:
        "DLL dropper used by APT41 as the first stage in the TOUGHPROGRESS infection chain. Disguised as a JPG file (7.jpg), loaded via rundll32.exe with the exported function 'plus'. Decrypts a companion file (6.jpg) using a hardcoded 16-byte XOR key, decompresses the result with LZNT1, and executes the next stage (PLUSINJECT) entirely in memory with no disk artifacts.",
      type: "dropper",
    },
    {
      name: "PLUSINJECT",
      description:
        "Second-stage malware used by APT41 in the TOUGHPROGRESS infection chain. Performs process hollowing on a legitimate svchost.exe process and injects the TOUGHPROGRESS backdoor payload. Operates entirely in memory to avoid endpoint detection.",
      type: "loader",
    },
    {
      name: "PLUSBED",
      description:
        "Additional stage component used by APT41 alongside PLUSDROP in the TOUGHPROGRESS campaign. Uses API hashing for function resolution with hardcoded hash values. References ntdll.dll for low-level operations.",
      type: "loader",
    },
  ];

  let malwareCreated = 0;
  for (const entry of malwareEntries) {
    const existing = await prisma.malware.findFirst({ where: { name: entry.name } });
    if (existing) {
      console.log(`  Malware exists: ${entry.name}`);
      continue;
    }

    const stixId = `malware--custom-${entry.name.toLowerCase()}`;
    const externalId = `S${String(9100 + malwareCreated).padStart(4, "0")}`;

    await prisma.malware.create({
      data: {
        stixId,
        externalId,
        name: entry.name,
        description: entry.description,
        aliases: "[]",
        type: entry.type,
        platforms: "Windows",
        url: "https://cloud.google.com/blog/topics/threat-intelligence/apt41-innovative-tactics",
      },
    });
    console.log(`  Created malware: ${entry.name} (${externalId})`);
    malwareCreated++;
  }

  // ── IOCs ──────────────────────────────────────────────────────────────
  const iocs = [
    // File hashes
    { type: "sha256", value: "469b534bec827be03c0823e72e7b4da0b84f53199040705da203986ef154406a", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 TOUGHPROGRESS delivery archive (出境海關申報清單.zip)" },
    { type: "md5", value: "876fb1b0275a653c4210aaf01c2698ec", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 TOUGHPROGRESS delivery ZIP archive" },
    { type: "sha256", value: "3b88b3efbdc86383ee9738c92026b8931ce1c13cd75cd1cda2fa302791c2c4fb", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 TOUGHPROGRESS LNK launcher (申報物品清單.pdf.lnk)" },
    { type: "md5", value: "65da1a9026cf171a5a7779bc5ee45fb1", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 TOUGHPROGRESS LNK file masquerading as PDF" },
    { type: "sha256", value: "50124174a4ac0d65bf8b6fd66f538829d1589edc73aa7cf36502e57aa5513360", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 PLUSDROP encrypted payload (6.jpg)" },
    { type: "md5", value: "1ca609e207edb211c8b9566ef35043b6", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 PLUSDROP encrypted payload disguised as JPG" },
    { type: "sha256", value: "151257e9dfda476cdafd9983266ad3255104d72a66f9265caa8417a5fe1df5d7", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 PLUSDROP DLL dropper (7.jpg)" },
    { type: "md5", value: "2ec4eeeabb8f6c2970dcbffdcdbd60e3", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 PLUSDROP DLL dropper disguised as JPG" },
    { type: "md5", value: "dccbb41af2fcf78d56ea3de8f3d1a12c", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 TOUGHPROGRESS XML-based dropper variant" },
    { type: "md5", value: "39a46d7f1ef9b9a5e40860cd5f646b9d", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 PLUSBED additional stage component" },
    { type: "md5", value: "9492022a939d4c727a5fa462590dc0dd", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 PLUSDROP dropper variant" },

    // Delivery domains (Cloudflare Workers)
    { type: "domain", value: "word.msapp.workers.dev", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 malware delivery via Cloudflare Workers" },
    { type: "domain", value: "cloud.msapp.workers.dev", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 malware delivery via Cloudflare Workers" },

    // TryCloudflare tunnel domains
    { type: "domain", value: "term-restore-satisfied-hence.trycloudflare.com", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 payload delivery via TryCloudflare tunnel" },
    { type: "domain", value: "ways-sms-pmc-shareholders.trycloudflare.com", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 payload delivery via TryCloudflare tunnel" },

    // InfinityFree hosting
    { type: "domain", value: "resource.infinityfreeapp.com", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 malware hosting on InfinityFree free hosting" },
    { type: "domain", value: "pubs.infinityfreeapp.com", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 malware hosting on InfinityFree free hosting" },

    // URL shorteners used for phishing delivery
    { type: "url", value: "hxxps://lihi[.]cc/6dekU", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 spearphishing link (lihi.cc shortener)" },
    { type: "url", value: "hxxps://lihi[.]cc/v3OyQ", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 spearphishing link (lihi.cc shortener)" },
    { type: "url", value: "hxxps://lihi[.]cc/5nlgd", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 spearphishing link (lihi.cc shortener)" },
    { type: "url", value: "hxxps://lihi[.]cc/edcOv", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 spearphishing link (lihi.cc shortener)" },
    { type: "url", value: "hxxps://lihi[.]cc/4z5sh", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 spearphishing link (lihi.cc shortener)" },
    { type: "url", value: "hxxps://tinyurl[.]com/mr42t4yv", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 spearphishing link (TinyURL shortener)" },
    { type: "url", value: "hxxps://tinyurl[.]com/hycev3y7", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 spearphishing link (TinyURL shortener)" },
    { type: "url", value: "hxxps://tinyurl[.]com/mpa2c5wj", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 spearphishing link (TinyURL shortener)" },
    { type: "url", value: "hxxps://tinyurl[.]com/3wnz46pv", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 spearphishing link (TinyURL shortener)" },
    { type: "url", value: "hxxps://my5353[.]com/ppOH5", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 spearphishing link (my5353 shortener)" },
    { type: "url", value: "hxxps://my5353[.]com/nWyTf", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 spearphishing link (my5353 shortener)" },
    { type: "url", value: "hxxps://my5353[.]com/fPUcX", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 spearphishing link (my5353 shortener)" },
    { type: "url", value: "hxxps://my5353[.]com/ZwEkm", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 spearphishing link (my5353 shortener)" },
    { type: "url", value: "hxxps://my5353[.]com/vEWiT", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 spearphishing link (my5353 shortener)" },
    { type: "url", value: "hxxps://reurl[.]cc/WNr2Xy", source: "Google GTIG APT41 TOUGHPROGRESS", description: "APT41 spearphishing link (reurl.cc shortener)" },

    // YARA rule references
    { type: "yara", value: "G_Backdoor_TOUGHPROGRESS_LNK_1", source: "Google GTIG APT41 TOUGHPROGRESS", description: "YARA rule for TOUGHPROGRESS LNK launcher detection" },
    { type: "yara", value: "G_Dropper_PLUSDROP_1", source: "Google GTIG APT41 TOUGHPROGRESS", description: "YARA rule for PLUSDROP dropper DLL detection" },
    { type: "yara", value: "G_Dropper_TOUGHPROGRESS_XML_1", source: "Google GTIG APT41 TOUGHPROGRESS", description: "YARA rule for TOUGHPROGRESS XML-based dropper" },
    { type: "yara", value: "G_Dropper_PLUSBED_2", source: "Google GTIG APT41 TOUGHPROGRESS", description: "YARA rule for PLUSBED additional stage component" },
  ];

  let iocCreated = 0;
  for (const ioc of iocs) {
    const existing = await prisma.iOC.findFirst({
      where: { type: ioc.type, value: ioc.value },
    });
    if (existing) continue;

    await prisma.iOC.create({
      data: {
        type: ioc.type,
        value: ioc.value,
        source: ioc.source,
        description: ioc.description,
        firstSeen: new Date(),
      },
    });
    iocCreated++;
  }
  console.log(`\n  IOCs created: ${iocCreated} (of ${iocs.length})`);

  // ── YARA Rules ────────────────────────────────────────────────────────
  const yaraRules = [
    {
      name: "G_Backdoor_TOUGHPROGRESS_LNK_1",
      description: "Detects APT41 TOUGHPROGRESS campaign LNK file that launches PLUSDROP DLL via rundll32. Looks for LNK magic bytes, rundll32 execution string, the specific DLL export path, and PDF masquerading markers.",
      category: "apt-tool",
      severity: "critical" as const,
      author: "Google GTIG",
      reference: "https://cloud.google.com/blog/topics/threat-intelligence/apt41-innovative-tactics",
      techniqueExternalId: "T1204.002",
      rule: `rule G_Backdoor_TOUGHPROGRESS_LNK_1 {
    meta:
        author = "GTIG"
        date_created = "2025-04-29"
        md5 = "65da1a9026cf171a5a7779bc5ee45fb1"
        description = "APT41 TOUGHPROGRESS LNK launcher"
        rev = 1
    strings:
        $marker = { 4C 00 00 00 }
        $str1 = "rundll32.exe" ascii wide
        $str2 = ".\\\\image\\\\7.jpg,plus" wide
        $str3 = "%PDF-1"
        $str4 = "PYL="
    condition:
        $marker at 0 and all of them
}`,
    },
    {
      name: "G_Dropper_PLUSDROP_1",
      description: "Detects APT41 PLUSDROP dropper DLL used in the TOUGHPROGRESS campaign. Identifies the XOR decryption and LZNT1 decompression routine used to unpack the next stage payload from an encrypted companion file.",
      category: "apt-tool",
      severity: "critical" as const,
      author: "Google GTIG",
      reference: "https://cloud.google.com/blog/topics/threat-intelligence/apt41-innovative-tactics",
      techniqueExternalId: "T1140",
      rule: `rule G_Dropper_PLUSDROP_1 {
    meta:
        author = "GTIG"
        date_created = "2025-04-29"
        md5 = "9492022a939d4c727a5fa462590dc0dd"
        description = "APT41 PLUSDROP DLL dropper"
        rev = 1
    strings:
        $decrypt_and_launch_payload = { 48 8B ?? 83 ?? 0F 0F B6 ?? ?? ??
30 04 ?? 48 FF ?? 49 3B ?? 72 ?? 80 [1-5] 00 75 ?? B? 5B 55 D2 56 [0-8] E8
[4-32] 33 ?? 33 ?? FF D? [0-4] FF D? }
    condition:
        uint16(0) == 0x5a4d and all of them
}`,
    },
    {
      name: "G_Dropper_TOUGHPROGRESS_XML_1",
      description: "Detects APT41 TOUGHPROGRESS XML-based dropper variant that uses embedded .NET code to load PLUSDROP DLL. Identifies Base64 decoding, VirtualAlloc, Marshal.Copy, and DllImport patterns within a non-PE file over 500KB.",
      category: "apt-tool",
      severity: "critical" as const,
      author: "Google GTIG",
      reference: "https://cloud.google.com/blog/topics/threat-intelligence/apt41-innovative-tactics",
      techniqueExternalId: "T1059.001",
      rule: `rule G_Dropper_TOUGHPROGRESS_XML_1 {
    meta:
        author = "GTIG"
        description = "XML lure file used to launch a PLUSDROP dll"
        md5 = "dccbb41af2fcf78d56ea3de8f3d1a12c"
    strings:
        $str1 = "System.Convert.FromBase64String"
        $str2 = "VirtualAlloc"
        $str3 = ".InteropServices.Marshal.Copy"
        $str4 = ".DllImport"
        $str5 = "kernel32.dll"
        $str6 = "powrprof.dll"
        $str7 = ".Marshal.GetDelegateForFunctionPointer"
    condition:
        uint16(0) != 0x5A4D and all of them and filesize > 500KB and
filesize < 5MB
}`,
    },
    {
      name: "G_Dropper_PLUSBED_2",
      description: "Detects APT41 PLUSBED component used alongside PLUSDROP in the TOUGHPROGRESS campaign. Identifies API hash resolution constants and ntdll.dll string construction patterns in a non-PE binary.",
      category: "apt-tool",
      severity: "high" as const,
      author: "Google GTIG",
      reference: "https://cloud.google.com/blog/topics/threat-intelligence/apt41-innovative-tactics",
      techniqueExternalId: "T1055.012",
      rule: `rule G_Dropper_PLUSBED_2 {
    meta:
        author = "GTIG"
        date_created = "2025-04-29"
        md5 = "39a46d7f1ef9b9a5e40860cd5f646b9d"
        description = "APT41 PLUSBED additional stage"
        rev = 1
    strings:
        $api1 = { BA 54 B8 B9 1A }
        $api2 = { BA 78 1F 20 7F }
        $api3 = { BA 62 34 89 5E }
        $api4 = { BA 65 62 10 4B }
        $api5 = { C7 44 24 34 6E 74 64 6C 66 C7 44 24 38 6C 00 FF D0 }
    condition:
        uint16(0) != 0x5A4D and all of them
}`,
    },
  ];

  let yaraCreated = 0;
  for (const rule of yaraRules) {
    const existing = await prisma.yaraRule.findFirst({ where: { name: rule.name } });
    if (existing) { console.log(`  YARA exists: ${rule.name}`); continue; }

    let techniqueId: string | null = null;
    if (rule.techniqueExternalId) {
      const tech = await prisma.technique.findFirst({ where: { externalId: rule.techniqueExternalId } });
      if (tech) techniqueId = tech.id;
    }

    const malwareMatch = await prisma.malware.findFirst({ where: { name: "TOUGHPROGRESS" } });

    await prisma.yaraRule.create({
      data: {
        name: rule.name,
        description: rule.description,
        rule: rule.rule,
        category: rule.category,
        severity: rule.severity,
        author: rule.author,
        reference: rule.reference,
        techniqueId,
        malwareId: malwareMatch?.id || null,
      },
    });
    console.log(`  Created YARA: ${rule.name}`);
    yaraCreated++;
  }

  // ── Detection Rules ───────────────────────────────────────────────────
  const detections = [
    {
      name: "APT41 TOUGHPROGRESS — rundll32 JPG DLL Sideload",
      description: "Detects APT41 TOUGHPROGRESS infection chain where rundll32.exe loads a DLL disguised as a JPG file from an image subdirectory with the exported function 'plus'. This is the initial execution vector for the PLUSDROP dropper.",
      language: "sigma",
      techniqueExternalId: "T1218.011",
      category: "execution",
      severity: "critical",
      source: "Google GTIG APT41 TOUGHPROGRESS Campaign",
      query: `title: APT41 TOUGHPROGRESS rundll32 JPG DLL Sideload
id: apt41-toughprogress-rundll32-jpg
status: experimental
level: critical
description: Detects rundll32.exe loading a DLL disguised as JPG with export function 'plus'
author: TrustedSec Threat Intel (based on Google GTIG research)
date: 2025/04/29
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/apt41-innovative-tactics
tags:
    - attack.execution
    - attack.t1218.011
    - attack.defense_evasion
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\rundll32.exe'
        CommandLine|contains|all:
            - '.jpg'
            - ',plus'
    selection_path:
        CommandLine|contains:
            - '\\image\\'
            - '/image/'
    condition: selection and selection_path
falsepositives:
    - Unlikely in legitimate use
`,
    },
    {
      name: "APT41 TOUGHPROGRESS — Google Calendar API C2 Communication",
      description: "Detects potential TOUGHPROGRESS C2 communication via Google Calendar API from non-browser processes. APT41 uses Calendar events to send commands and receive exfiltrated data, making traffic blend with legitimate Google API usage.",
      language: "sigma",
      techniqueExternalId: "T1102.002",
      category: "c2",
      severity: "high",
      source: "Google GTIG APT41 TOUGHPROGRESS Campaign",
      query: `title: Google Calendar API C2 Communication from Non-Browser Process
id: apt41-toughprogress-gcal-c2
status: experimental
level: high
description: Detects non-browser processes communicating with Google Calendar API, potential TOUGHPROGRESS C2
author: TrustedSec Threat Intel (based on Google GTIG research)
date: 2025/04/29
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/apt41-innovative-tactics
tags:
    - attack.command_and_control
    - attack.t1102.002
    - attack.t1071.001
logsource:
    category: proxy
    product: any
detection:
    selection:
        c-uri|contains: 'googleapis.com/calendar/v3/calendars'
    filter_browsers:
        process_name:
            - 'chrome.exe'
            - 'msedge.exe'
            - 'firefox.exe'
            - 'brave.exe'
            - 'iexplore.exe'
    condition: selection and not filter_browsers
falsepositives:
    - Legitimate calendar integrations from non-browser apps
    - Google Workspace sync tools
`,
    },
    {
      name: "APT41 TOUGHPROGRESS — Process Hollowing into svchost.exe",
      description: "Detects potential PLUSINJECT process hollowing where svchost.exe is spawned by a non-standard parent process. In the TOUGHPROGRESS chain, PLUSINJECT creates a suspended svchost.exe process and injects the TOUGHPROGRESS backdoor payload.",
      language: "sigma",
      techniqueExternalId: "T1055.012",
      category: "defense-evasion",
      severity: "critical",
      source: "Google GTIG APT41 TOUGHPROGRESS Campaign",
      query: `title: Suspicious svchost.exe Process Hollowing (APT41 PLUSINJECT)
id: apt41-plusinject-svchost-hollowing
status: experimental
level: critical
description: Detects svchost.exe spawned by non-standard parent, indicating potential process hollowing
author: TrustedSec Threat Intel (based on Google GTIG research)
date: 2025/04/29
references:
    - https://cloud.google.com/blog/topics/threat-intelligence/apt41-innovative-tactics
tags:
    - attack.defense_evasion
    - attack.t1055.012
    - attack.privilege_escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\svchost.exe'
    filter_legitimate_parents:
        ParentImage|endswith:
            - '\\services.exe'
            - '\\MsMpEng.exe'
            - '\\svchost.exe'
    condition: selection and not filter_legitimate_parents
falsepositives:
    - Some system management tools may spawn svchost.exe
`,
    },
  ];

  let detCreated = 0;
  for (const det of detections) {
    const existing = await prisma.detectionRule.findFirst({ where: { name: det.name } });
    if (existing) { console.log(`  Detection exists: ${det.name}`); continue; }

    let techniqueId: string | null = null;
    if (det.techniqueExternalId) {
      const tech = await prisma.technique.findFirst({ where: { externalId: det.techniqueExternalId } });
      if (tech) techniqueId = tech.id;
    }

    await prisma.detectionRule.create({
      data: {
        name: det.name,
        description: det.description,
        query: det.query,
        language: det.language,
        techniqueId,
        category: det.category,
        source: det.source,
        severity: det.severity,
      },
    });
    console.log(`  Created detection: ${det.name}`);
    detCreated++;
  }

  // ── Summary ───────────────────────────────────────────────────────────
  console.log(`\n=== APT41 TOUGHPROGRESS Ingestion Complete ===`);
  console.log(`  Malware entries: ${malwareCreated}`);
  console.log(`  IOCs: ${iocCreated}`);
  console.log(`  YARA rules: ${yaraCreated}`);
  console.log(`  Detection rules: ${detCreated}`);
}

main().catch(console.error).finally(() => process.exit(0));
