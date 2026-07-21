import { prisma } from "../src/lib/db";

const C2_PROFILES = [
  {
    name: "Cobalt Strike",
    description:
      "Commercial adversary simulation platform. Most widely observed C2 framework in real-world intrusions. Supports beacon payloads, Malleable C2 profiles, and extensive post-exploitation.",
    platforms: ["Windows", "Linux", "macOS"],
    c2Category: "commercial",
    license: "Commercial ($5,900/operator/year)",
    languages: ["Java", "C"],
    keyFeatures: [
      "Malleable C2 profiles",
      "Beacon payload",
      "BOF (Beacon Object Files)",
      "SOCKS proxy",
      "Named pipe pivoting",
      "DNS beaconing",
    ],
    techniques: [
      "T1071.001",
      "T1059.001",
      "T1055",
      "T1070.004",
      "T1027",
      "T1105",
      "T1572",
      "T1090",
      "T1573.002",
      "T1021.002",
      "T1053.005",
      "T1218.011",
      "T1547.001",
      "T1003.001",
      "T1558.003",
      "T1550.002",
    ],
  },
  {
    name: "Sliver",
    description:
      "Open-source adversary emulation framework by BishopFox. Growing adoption as Cobalt Strike alternative. Supports multiple C2 protocols and implant types.",
    platforms: ["Windows", "Linux", "macOS"],
    c2Category: "open-source",
    license: "GPLv3 (Free)",
    languages: ["Go"],
    keyFeatures: [
      "mTLS/HTTP(S)/DNS/WireGuard C2",
      "Multiplayer mode",
      "Stager payloads",
      "Process injection",
      "Armory extensions",
    ],
    techniques: [
      "T1071.001",
      "T1071.004",
      "T1059.001",
      "T1055",
      "T1105",
      "T1572",
      "T1573.002",
      "T1027",
      "T1140",
      "T1082",
      "T1083",
      "T1057",
    ],
  },
  {
    name: "Mythic",
    description:
      "Open-source C2 framework with modular agent architecture. Each agent is a separate project enabling community contributions. Web-based UI.",
    platforms: ["Windows", "Linux", "macOS"],
    c2Category: "open-source",
    license: "BSD-3 (Free)",
    languages: ["Go", "Python"],
    keyFeatures: [
      "Modular agent architecture",
      "Web UI",
      "Encrypted comms",
      "Dynamic payload generation",
      "SOCKS5 proxy",
      "P2P agents",
    ],
    techniques: [
      "T1071.001",
      "T1059",
      "T1055",
      "T1105",
      "T1573",
      "T1090",
      "T1027",
      "T1036",
      "T1106",
    ],
  },
  {
    name: "Havoc",
    description:
      "Modern open-source C2 framework. Demon agent with indirect syscalls, sleep obfuscation, and extensive evasion. Rising in red team use.",
    platforms: ["Windows", "Linux"],
    c2Category: "open-source",
    license: "GPLv3 (Free)",
    languages: ["C", "Go", "Python"],
    keyFeatures: [
      "Indirect syscalls",
      "Sleep obfuscation (Ekko/Zilean)",
      "Shellcode injection",
      "Token manipulation",
      "BOF support",
      "Custom agents",
    ],
    techniques: [
      "T1055",
      "T1134",
      "T1106",
      "T1027",
      "T1497.001",
      "T1059.001",
      "T1071.001",
      "T1573.002",
      "T1105",
      "T1070",
    ],
  },
  {
    name: "Brute Ratel C4",
    description:
      "Commercial C2 built for advanced adversary simulation. Designed specifically to evade EDR/AV. Uses legitimate Windows APIs for evasion.",
    platforms: ["Windows"],
    c2Category: "commercial",
    license: "Commercial ($2,500/user/year)",
    languages: ["C", "C++"],
    keyFeatures: [
      "Badger payload",
      "Syscall obfuscation",
      "ETW/AMSI patching",
      "SMB/TCP/HTTP/DOH channels",
      "LDAP sentinel",
      "Debug API abuse",
    ],
    techniques: [
      "T1055",
      "T1562.001",
      "T1106",
      "T1027",
      "T1071.001",
      "T1071.004",
      "T1573.002",
      "T1134",
      "T1003",
      "T1059.001",
    ],
  },
  {
    name: "Metasploit Framework",
    description:
      "Industry-standard open-source penetration testing framework. Massive module library. Meterpreter agent for post-exploitation. msfvenom supports polymorphic encoding (shikata_ga_nai), custom templates, staged/stageless payloads, and evasion modules that bypass most AV/EDR when tuned.",
    platforms: ["Windows", "Linux", "macOS"],
    c2Category: "open-source",
    license: "BSD (Free) / Commercial (Pro)",
    languages: ["Ruby", "C"],
    keyFeatures: [
      "2000+ exploit modules",
      "Meterpreter agent",
      "msfvenom payload generation",
      "Polymorphic encoding (shikata_ga_nai)",
      "Evasion modules",
      "Staged/stageless payloads",
      "Multi-handler",
      "Post modules",
      "Pivoting",
    ],
    techniques: [
      "T1059",
      "T1055",
      "T1105",
      "T1071.001",
      "T1573",
      "T1003",
      "T1082",
      "T1083",
      "T1057",
      "T1021",
      "T1190",
      "T1210",
    ],
  },
  {
    name: "Covenant",
    description:
      ".NET-based C2 framework. Grunt implants. Good for Windows/.NET environments. Development has slowed but still used.",
    platforms: ["Windows"],
    c2Category: "open-source",
    license: "GPLv3 (Free)",
    languages: ["C#", ".NET"],
    keyFeatures: [
      ".NET implants (Grunts)",
      "Task-based operations",
      "Encrypted C2",
      "Bridge listeners",
      "SharpSploit integration",
    ],
    techniques: [
      "T1059.001",
      "T1071.001",
      "T1573",
      "T1055",
      "T1105",
      "T1027",
      "T1218.011",
      "T1003.001",
    ],
  },
  {
    name: "Posh C2",
    description:
      "PowerShell-based C2 with proxy-aware agents. Simple setup. Focused on Windows post-exploitation via PowerShell.",
    platforms: ["Windows", "Linux"],
    c2Category: "open-source",
    license: "BSD-3 (Free)",
    languages: ["Python", "PowerShell"],
    keyFeatures: [
      "PowerShell implants",
      "Proxy-aware",
      "Daisy-chaining",
      "Sharp modules",
      "AMSI bypass",
    ],
    techniques: [
      "T1059.001",
      "T1071.001",
      "T1573",
      "T1105",
      "T1027",
      "T1562.001",
      "T1082",
    ],
  },
  {
    name: "Nighthawk",
    description:
      "Commercial advanced C2 by MDSec. Designed for stealth with advanced evasion techniques. Used in high-end red team operations.",
    platforms: ["Windows"],
    c2Category: "commercial",
    license: "Commercial (invite-only)",
    languages: ["C", "C++"],
    keyFeatures: [
      "Indirect syscalls",
      "Sleep masking",
      "AMSI/ETW bypass",
      "Custom reflective loader",
      "Malleable profiles",
      "BOF support",
    ],
    techniques: [
      "T1055",
      "T1106",
      "T1562.001",
      "T1027",
      "T1497.001",
      "T1071.001",
      "T1573.002",
      "T1134",
      "T1070",
    ],
  },
  {
    name: "Empire",
    description:
      "Post-exploitation and adversary emulation framework. PowerShell and Python agents. Originally PowerShell Empire, now maintained by BC Security.",
    platforms: ["Windows", "Linux", "macOS"],
    c2Category: "open-source",
    license: "BSD-3 (Free)",
    languages: ["Python", "PowerShell", "C#"],
    keyFeatures: [
      "PowerShell/Python/C# agents (stagers)",
      "Malleable C2",
      "Module library",
      "Credential harvesting",
      "AMSI bypass",
    ],
    techniques: [
      "T1059.001",
      "T1059.006",
      "T1071.001",
      "T1573",
      "T1055",
      "T1105",
      "T1003",
      "T1027",
      "T1562.001",
      "T1082",
      "T1083",
    ],
  },
  {
    name: "Backdoor.Turn",
    description:
      "Custom Go-based RAT used by DragonForce (Hackledorb). First known malware to abuse Microsoft Teams TURN relay servers for C2. Obtains anonymous Teams visitor tokens to tunnel QUIC sessions through legitimate Microsoft infrastructure, making C2 traffic indistinguishable from normal Teams calls. Network-level C2 channel is extremely evasive, but the implant itself has known IOCs, documented DLL sideloading patterns, and publicly disclosed hashes.",
    platforms: ["Windows"],
    c2Category: "custom-malware",
    license: "Threat Actor Custom (DragonForce/Hackledorb)",
    languages: ["Go"],
    keyFeatures: [
      "Microsoft Teams TURN relay abuse",
      "Anonymous visitor token auth",
      "QUIC tunneling over port 443",
      "LDAP/AD enumeration",
      "Network scanning with TLS cert capture",
      "Browser credential theft",
      "DLL sideloading via VirtualBox",
      "BYOVD EDR killer",
    ],
    techniques: [
      "T1090.002",
      "T1071.001",
      "T1102",
      "T1573",
      "T1105",
      "T1574.002",
      "T1562.001",
      "T1059",
      "T1087",
      "T1018",
      "T1555",
      "T1003",
    ],
  },
  {
    name: "Merlin",
    description:
      "Open-source Go-based C2 framework that leverages HTTP/2 and HTTP/3 (QUIC) for agent communication. Designed for post-exploitation with a focus on using modern transport protocols to evade network inspection.",
    platforms: ["Windows", "Linux", "macOS"],
    c2Category: "open-source",
    license: "GPLv3 (Free)",
    languages: ["Go"],
    keyFeatures: [
      "HTTP/2 and HTTP/3 (QUIC) C2 channels",
      "OPAQUE authenticated key exchange",
      "JA3 hash evasion",
      "Cross-platform agents",
      "Encrypted JWT messaging",
      "Modular post-exploitation commands",
    ],
    techniques: [
      "T1071.001",
      "T1105",
      "T1573",
      "T1059",
      "T1082",
      "T1083",
      "T1057",
      "T1027",
      "T1140",
    ],
  },
  {
    name: "Pupy",
    description:
      "Open-source cross-platform RAT and post-exploitation framework written in Python and C. Supports reflective loading entirely in memory with no disk artifacts. Agents run on Windows, Linux, macOS, and Android.",
    platforms: ["Windows", "Linux", "macOS", "Android"],
    c2Category: "open-source",
    license: "BSD-3 (Free)",
    languages: ["Python", "C"],
    keyFeatures: [
      "Reflective in-memory loading",
      "Transport flexibility (TCP, SSL, HTTP, obfs3)",
      "All-in-memory execution (no disk)",
      "Interactive Python shell",
      "Module library (keylogger, screenshot, persistence)",
      "Cross-platform agents including Android",
    ],
    techniques: [
      "T1055",
      "T1059.006",
      "T1071.001",
      "T1573",
      "T1105",
      "T1082",
      "T1083",
      "T1057",
      "T1056.001",
      "T1113",
      "T1547.001",
      "T1027",
    ],
  },
  {
    name: "SilverC2",
    description:
      "Open-source Python-based C2 framework (distinct from BishopFox Sliver). Lightweight command-and-control with a focus on simplicity and extensibility for red team engagements.",
    platforms: ["Windows", "Linux"],
    c2Category: "open-source",
    license: "MIT (Free)",
    languages: ["Python"],
    keyFeatures: [
      "Python-based server and agents",
      "HTTP/HTTPS C2 channels",
      "Task-based command execution",
      "File upload/download",
      "Modular plugin system",
    ],
    techniques: [
      "T1071.001",
      "T1059",
      "T1105",
      "T1573",
      "T1082",
      "T1083",
      "T1027",
    ],
  },
  {
    name: "Deimos",
    description:
      "Open-source Go-based C2 framework focused on simplicity and stealth. Supports encrypted communications and is designed for red team operators who need a lightweight, extensible C2 solution.",
    platforms: ["Windows", "Linux"],
    c2Category: "open-source",
    license: "GPLv3 (Free)",
    languages: ["Go"],
    keyFeatures: [
      "Go-based cross-platform agents",
      "AES-encrypted C2 communications",
      "HTTP/HTTPS listeners",
      "File transfer capabilities",
      "Command execution",
      "Lightweight footprint",
    ],
    techniques: [
      "T1071.001",
      "T1573",
      "T1059",
      "T1105",
      "T1082",
      "T1083",
      "T1027",
    ],
  },
  {
    name: "Villain",
    description:
      "Open-source Python-based reverse shell handler and C2 framework. Generates Windows/Linux payloads and handles multiple reverse shell sessions with HoaxShell integration for evading Windows Defender.",
    platforms: ["Windows", "Linux"],
    c2Category: "open-source",
    license: "MIT (Free)",
    languages: ["Python"],
    keyFeatures: [
      "HoaxShell integration (Windows Defender evasion)",
      "Multi-session reverse shell handler",
      "Payload generation (PowerShell, cmd)",
      "Encrypted shell sessions",
      "Shell session sharing between operators",
      "Auto-obfuscation of payloads",
    ],
    techniques: [
      "T1059.001",
      "T1059.003",
      "T1071.001",
      "T1573",
      "T1105",
      "T1027",
      "T1562.001",
      "T1082",
    ],
  },
  {
    name: "Ninja",
    description:
      "Open-source C2 framework designed for red team operations. Created by ahmedkhlief, it provides a web-based interface for managing agents and executing post-exploitation tasks with focus on stealth.",
    platforms: ["Windows", "Linux"],
    c2Category: "open-source",
    license: "MIT (Free)",
    languages: ["Python", "C#"],
    keyFeatures: [
      "Web-based management interface",
      "Encrypted C2 channels",
      "Agent management dashboard",
      "Post-exploitation modules",
      "File exfiltration",
      "Persistence mechanisms",
    ],
    techniques: [
      "T1071.001",
      "T1573",
      "T1059",
      "T1105",
      "T1082",
      "T1083",
      "T1547.001",
      "T1027",
    ],
  },
  {
    name: "Manjusaka",
    description:
      "Chinese-origin open-source C2 framework with a Rust-based implant and Go-based server. Observed in real-world APT operations as a Cobalt Strike alternative. Supports Windows and Linux implants with RAT capabilities.",
    platforms: ["Windows", "Linux"],
    c2Category: "open-source",
    license: "Open-source (Free, leaked)",
    languages: ["Rust", "Go"],
    keyFeatures: [
      "Rust-based implant for evasion",
      "Go-based C2 server",
      "File management and exfiltration",
      "Browser credential harvesting",
      "Arbitrary command execution",
      "Screenshot capture",
      "Network discovery",
    ],
    techniques: [
      "T1071.001",
      "T1059",
      "T1105",
      "T1573",
      "T1082",
      "T1083",
      "T1555",
      "T1113",
      "T1018",
      "T1027",
    ],
  },
  {
    name: "Alchimist",
    description:
      "Chinese-origin C2 framework discovered by Cisco Talos in 2022. Written in Go with a web-based management interface. Targets Windows, Linux, and macOS via Insekt RAT implants. Observed in active campaigns.",
    platforms: ["Windows", "Linux", "macOS"],
    c2Category: "open-source",
    license: "Open-source (Free, discovered in-the-wild)",
    languages: ["Go"],
    keyFeatures: [
      "Web-based C2 interface (GoTTY)",
      "Insekt RAT implant",
      "Cross-platform payload generation",
      "Built-in exploit integration",
      "PowerShell payload delivery",
      "SSH/crontab persistence on Linux",
    ],
    techniques: [
      "T1071.001",
      "T1059.001",
      "T1059.004",
      "T1105",
      "T1573",
      "T1082",
      "T1053.003",
      "T1547.001",
      "T1190",
      "T1027",
    ],
  },
  {
    name: "Poseidon",
    description:
      "Open-source Mythic C2 agent written in Go, targeting macOS and Linux. Part of the Mythic ecosystem. Supports configurable C2 profiles and rich post-exploitation capabilities on Unix-based systems.",
    platforms: ["macOS", "Linux"],
    c2Category: "open-source",
    license: "BSD-3 (Free)",
    languages: ["Go"],
    keyFeatures: [
      "Mythic agent architecture",
      "macOS keychain access",
      "SSH credential harvesting",
      "Process listing and injection",
      "File browser",
      "Configurable HTTP C2 profiles",
      "SOCKS5 proxy support",
    ],
    techniques: [
      "T1071.001",
      "T1059.004",
      "T1105",
      "T1573",
      "T1082",
      "T1083",
      "T1057",
      "T1555.001",
      "T1090",
      "T1027",
    ],
  },
  {
    name: "Caldera",
    description:
      "MITRE's own open-source adversary emulation platform. Automates adversary behavior mapped to ATT&CK. Used for automated red team exercises, purple team assessments, and security testing.",
    platforms: ["Windows", "Linux", "macOS"],
    c2Category: "open-source",
    license: "Apache-2.0 (Free)",
    languages: ["Python", "Go"],
    keyFeatures: [
      "ATT&CK-mapped adversary profiles",
      "Automated adversary emulation",
      "Sandcat/Manx agents",
      "Plugin architecture",
      "Fact/relationship tracking",
      "Planner-based autonomous operations",
      "REST API",
    ],
    techniques: [
      "T1059",
      "T1059.001",
      "T1059.004",
      "T1105",
      "T1082",
      "T1083",
      "T1057",
      "T1071.001",
      "T1027",
      "T1003",
      "T1018",
      "T1053.005",
    ],
  },
  {
    name: "Koadic",
    description:
      "Open-source Windows post-exploitation rootkit that uses JScript/VBScript for payload delivery. Operates similarly to Meterpreter/Powershell Empire but lives entirely in the Windows Script Host. COM-based execution.",
    platforms: ["Windows"],
    c2Category: "open-source",
    license: "Apache-2.0 (Free)",
    languages: ["Python", "JScript", "VBScript"],
    keyFeatures: [
      "Windows Script Host-based implants",
      "COM object execution",
      "JScript/VBScript stagers",
      "Credential harvesting",
      "Fileless execution",
      "Zombie (implant) management",
    ],
    techniques: [
      "T1059.005",
      "T1059.007",
      "T1071.001",
      "T1105",
      "T1082",
      "T1003",
      "T1055",
      "T1218.005",
      "T1027",
      "T1547.001",
    ],
  },
  {
    name: "SILENTTRINITY",
    description:
      "Open-source post-exploitation agent powered by IronPython and C#/.NET. Uses embedded Python runtime via .NET for in-memory execution. Designed to bypass application whitelisting and script-based detections.",
    platforms: ["Windows"],
    c2Category: "open-source",
    license: "GPLv3 (Free)",
    languages: ["Python", "C#", ".NET"],
    keyFeatures: [
      "IronPython-based in-memory execution",
      "Boo language scripting",
      ".NET runtime abuse",
      "AMSI bypass",
      "Dynamic module loading",
      "Encrypted C2 (HTTP/HTTPS)",
    ],
    techniques: [
      "T1059.006",
      "T1071.001",
      "T1573",
      "T1055",
      "T1105",
      "T1027",
      "T1562.001",
      "T1106",
      "T1082",
      "T1003",
    ],
  },
  {
    name: "Nimplant",
    description:
      "Open-source lightweight C2 implant written in Nim. Compiles to native binaries with small footprint. Leverages Nim's cross-compilation for generating payloads that evade signature-based detection.",
    platforms: ["Windows", "Linux"],
    c2Category: "open-source",
    license: "MIT (Free)",
    languages: ["Nim", "Python"],
    keyFeatures: [
      "Nim-based native implant",
      "Small binary footprint",
      "HTTP/HTTPS C2 channels",
      "Inline .NET assembly execution",
      "Shellcode execution",
      "File operations",
      "Python-based server",
    ],
    techniques: [
      "T1071.001",
      "T1573",
      "T1059",
      "T1105",
      "T1082",
      "T1083",
      "T1055",
      "T1027",
      "T1106",
    ],
  },
  {
    name: "HardHat",
    description:
      "Open-source C#-based C2 framework designed for red team operations. Features a Blazor web UI, encrypted communications, and modular implant architecture. Supports multiple implant types and pivoting.",
    platforms: ["Windows", "Linux"],
    c2Category: "open-source",
    license: "GPLv3 (Free)",
    languages: ["C#", ".NET"],
    keyFeatures: [
      "Blazor web-based UI",
      "Multiple implant types (Engineer)",
      "Encrypted C2 (AES/RSA)",
      "Pivot listeners",
      "Inline assembly execution",
      "SOCKS4a proxy",
      "Credential harvesting",
    ],
    techniques: [
      "T1071.001",
      "T1573",
      "T1059.001",
      "T1055",
      "T1105",
      "T1090",
      "T1003",
      "T1082",
      "T1027",
      "T1106",
    ],
  },
];

// Synthetic IDs for new C2 tools not in MITRE
const SYNTHETIC_EXTERNAL_ID_START = 2001;

async function main() {
  console.log("Seeding C2 framework profiles...\n");

  let created = 0;
  let updated = 0;
  let techniquesMapped = 0;
  let techniquesSkipped = 0;

  for (let i = 0; i < C2_PROFILES.length; i++) {
    const profile = C2_PROFILES[i];

    // Build c2 metadata object for aliases field
    const c2Meta = JSON.stringify({
      c2: true,
      c2Category: profile.c2Category,
      license: profile.license,
      languages: profile.languages,
      keyFeatures: profile.keyFeatures,
    });

    // Look up existing tool by name (case-sensitive, MITRE uses exact names)
    let tool = await prisma.tool.findFirst({
      where: { name: profile.name },
    });

    if (tool) {
      // Update existing tool with c2 metadata — preserve externalId/stixId from MITRE
      tool = await prisma.tool.update({
        where: { id: tool.id },
        data: {
          aliases: c2Meta,
          platforms: JSON.stringify(profile.platforms),
          // Description: only override if ours is more detailed
          description:
            profile.description.length > (tool.description?.length ?? 0)
              ? profile.description
              : tool.description,
        },
      });
      console.log(`  Updated existing: ${profile.name} (${tool.externalId})`);
      updated++;
    } else {
      // Create new tool with synthetic IDs
      const syntheticExternalId = `C2${String(SYNTHETIC_EXTERNAL_ID_START + i).padStart(3, "0")}`;
      const syntheticStixId = `tool--c2-${profile.name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")}`;

      tool = await prisma.tool.create({
        data: {
          stixId: syntheticStixId,
          externalId: syntheticExternalId,
          name: profile.name,
          description: profile.description,
          aliases: c2Meta,
          platforms: JSON.stringify(profile.platforms),
          url: "",
          deprecated: false,
          revoked: false,
        },
      });
      console.log(`  Created: ${profile.name} (${syntheticExternalId})`);
      created++;
    }

    // Map techniques
    for (const techExternalId of profile.techniques) {
      const technique = await prisma.technique.findFirst({
        where: { externalId: techExternalId },
      });

      if (!technique) {
        console.log(`    Skipping unknown technique: ${techExternalId}`);
        techniquesSkipped++;
        continue;
      }

      await prisma.toolTechnique.upsert({
        where: {
          toolId_techniqueId: {
            toolId: tool.id,
            techniqueId: technique.id,
          },
        },
        update: {},
        create: {
          toolId: tool.id,
          techniqueId: technique.id,
        },
      });
      techniquesMapped++;
    }
  }

  console.log(`
Done:
  ${created} C2 profiles created
  ${updated} C2 profiles updated
  ${techniquesMapped} technique mappings ensured
  ${techniquesSkipped} techniques skipped (not in DB)
`);
}

main().catch(console.error).finally(() => process.exit(0));
