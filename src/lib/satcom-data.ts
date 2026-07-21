export interface SatcomAttack {
  id: string;
  name: string;
  date: string;
  attribution: string;
  nation: string;
  description: string;
  impact: string;
}

export interface SatcomActor {
  id: string;
  name: string;
  aliases: string[];
  nation: string;
  agency: string;
  description: string;
  satcomActivity: string;
}

export interface SatcomResearch {
  id: string;
  researcher: string;
  org: string;
  year: string;
  title: string;
  description: string;
  significance: string;
  cost?: string;
}

export interface GnssStat {
  label: string;
  value: string;
  detail: string;
}

export interface SatcomAdvisory {
  id: string;
  issuer: string;
  title: string;
  date: string;
  description: string;
}

export interface SatcomFramework {
  id: string;
  name: string;
  org: string;
  description: string;
}

export const SATCOM_ATTACKS: SatcomAttack[] = [
  {
    id: "acidrain",
    name: "Viasat / AcidRain",
    date: "February 24, 2022",
    attribution: "Sandworm (APT44)",
    nation: "Russia",
    description:
      "On the day Russia invaded Ukraine, attackers compromised Viasat's KA-SAT network management infrastructure by exploiting a VPN appliance vulnerability, then pushed AcidRain wiper malware to approximately 45,000 satellite modems across Europe, bricking them. SentinelOne discovered AcidRain and noted code overlap with VPNFilter, a 2018 GRU-attributed router malware. EU and Five Eyes formally attributed the attack to Russian military intelligence (GRU).",
    impact:
      "~45,000 modems bricked across Europe. 5,800 Enercon wind turbines in Germany lost remote monitoring. Collateral damage across multiple EU nations.",
  },
  {
    id: "acidpour",
    name: "AcidPour",
    date: "March 2024",
    attribution: "Sandworm subcluster",
    nation: "Russia",
    description:
      "An evolved Linux wiper variant of AcidRain identified by SentinelOne. AcidPour added destructive capabilities targeting UBI (Unsorted Block Image) and Device Mapper logic, expanding its reach to RAID arrays, NAS, SAN, and ICS/IoT devices. CERT-UA attributed its deployment against four Ukrainian telecom providers to a Sandworm subcluster.",
    impact:
      "Four Ukrainian telecom providers disrupted. Expanded wiper capabilities to RAID, NAS, SAN, and ICS/IoT targets.",
  },
  {
    id: "salt-typhoon",
    name: "Salt Typhoon SATCOM Campaign",
    date: "2024–2025",
    attribution: "Salt Typhoon",
    nation: "China",
    description:
      "Chinese state-sponsored group compromised at least nine major US telecoms including AT&T, Verizon, T-Mobile, Lumen, and Charter in a massive espionage campaign targeting approximately 80 nations and 600+ organizations. Viasat confirmed it was among those breached. By mid-2025, the campaign extended specifically to satellite communications providers, with attackers abusing remote management links tied to ground infrastructure.",
    impact:
      "9+ US telecoms compromised. 80+ nations, 600+ organizations targeted. SATCOM ground infrastructure breached.",
  },
];

export const SATCOM_ACTORS: SatcomActor[] = [
  {
    id: "sandworm",
    name: "Sandworm",
    aliases: ["APT44", "Seashell Blizzard", "Voodoo Bear"],
    nation: "Russia",
    agency: "GRU Unit 74455",
    description:
      "The most prolific SATCOM-focused threat actor. Responsible for the Viasat/AcidRain attack and linked to AcidPour. Also deployed Cyclops Blink and SwiftSlicer wiper. Compromised eleven Ukrainian telecom providers between May–September 2023.",
    satcomActivity:
      "AcidRain wiper (2022), AcidPour wiper (2024), 11 Ukrainian telco compromises (2023), Cyclops Blink (2022)",
  },
  {
    id: "turla",
    name: "Turla",
    aliases: ["Venomous Bear", "Waterbug", "Snake"],
    nation: "Russia",
    agency: "FSB",
    description:
      "Pioneered satellite-link hijacking for C2 communications. Turla monitored downstream-only DVB-S satellite internet connections, identified active IP addresses, and hijacked them to hide C2 traffic. Targeted government, military, embassy, and research entities across the Middle East and Africa.",
    satcomActivity:
      "DVB-S satellite link hijacking for C2 (disclosed by Kaspersky 2015). Technique remains conceptually relevant to modern DVB-S eavesdropping attacks.",
  },
  {
    id: "salt-typhoon",
    name: "Salt Typhoon",
    aliases: ["GhostEmperor", "FamousSparrow"],
    nation: "China",
    agency: "MSS-linked",
    description:
      "Expanded from terrestrial telecom espionage into SATCOM providers in 2024–2025. Compromised 9+ US telecoms and extended to satellite communications ground infrastructure.",
    satcomActivity:
      "Telecom/SATCOM espionage across 80+ nations, 600+ orgs (2024–2025). Viasat ground infrastructure breached.",
  },
  {
    id: "apt28",
    name: "Fancy Bear",
    aliases: ["APT28", "Sofacy", "Forest Blizzard"],
    nation: "Russia",
    agency: "GRU Unit 26165",
    description:
      "In 2024, OpenAI and Microsoft revealed that Fancy Bear used LLMs to research satellite communications protocols, radar systems, and space technologies, indicating active intelligence-gathering for potential SATCOM-targeting operations.",
    satcomActivity:
      "LLM-assisted reconnaissance of SATCOM protocols and radar systems (2024). Active intelligence-gathering for space-targeting operations.",
  },
  {
    id: "lazarus",
    name: "Lazarus Group",
    aliases: ["HIDDEN COBRA", "Zinc", "Diamond Sleet"],
    nation: "North Korea",
    agency: "RGB",
    description:
      "Targeted European aerospace, military, and defense companies between September–December 2023. North Korea has demonstrated SATCOM and GPS jamming capabilities with escalating GPS jamming incidents against South Korea.",
    satcomActivity:
      "European aerospace targeting (Sep–Dec 2023). GPS jamming escalation: 23 incidents in 2022 to 533 in H1 2024.",
  },
  {
    id: "ta455",
    name: "TA455",
    aliases: ["Tortoiseshell"],
    nation: "Iran",
    agency: "IRGC-linked",
    description:
      "IRGC-directed cyber campaigns targeting aerospace and satellite infrastructure for intelligence collection and social engineering. Conducted aerospace-sector espionage campaigns from September 2023 onward using techniques shared with North Korean threat actors.",
    satcomActivity:
      "Aerospace/satellite infrastructure espionage (2023+). Technique overlap with North Korean actors.",
  },
];

export const SATCOM_RESEARCH: SatcomResearch[] = [
  {
    id: "pavur",
    researcher: "James Pavur",
    org: "University of Oxford",
    year: "2019–2021",
    title: "Secrets in the Sky — DVB-S Satellite Eavesdropping",
    description:
      "Using ~$300 of consumer satellite TV equipment, demonstrated interception of terabytes of real-world satellite traffic from major organizations. Found that many SATCOM providers did not encrypt below the application layer, enabling passive eavesdropping from thousands of miles away with zero detection risk.",
    significance:
      "First large-scale demonstration that consumer equipment can intercept live satellite traffic. Published at WiSec 2019. DPhil thesis covers the full attack surface.",
    cost: "$300",
  },
  {
    id: "santamarta",
    researcher: "Ruben Santamarta",
    org: "IOActive",
    year: "2014–2022",
    title: "SATCOM Terminal Firmware Exploitation",
    description:
      "Reverse-engineered firmware from Harris, Hughes, Thuraya, Cobham, JRC, and Iridium terminals. Found 100% of in-scope devices exploitable: hardcoded credentials, backdoors, undocumented protocols, weak encryption. Demonstrated remote compromise of in-flight airplane WiFi/SATCOM from the ground.",
    significance:
      "IOActive warned for nine years that these vulnerability classes remained unaddressed. The Viasat attack in 2022 validated those warnings.",
  },
  {
    id: "wouters",
    researcher: "Lennert Wouters",
    org: "KU Leuven",
    year: "2022",
    title: "Starlink Terminal Fault Injection",
    description:
      "Demonstrated a voltage fault injection attack on a Starlink user terminal using a $25 custom modchip (Raspberry Pi microcontroller + flash + voltage regulator). The glitch targeted the first bootloader (burned into the SoC, non-updatable), allowing patched firmware and root access.",
    significance:
      "Proved physical access to Starlink terminals yields root. First bootloader is non-updatable, making the attack permanent. SpaceX acknowledged via bug bounty.",
    cost: "$25",
  },
  {
    id: "ucsd",
    researcher: "Aaron Schulman & Nadia Heninger",
    org: "UC San Diego",
    year: "2025",
    title: "Don't Look Up — GEO Satellite Eavesdropping",
    description:
      "Using $800 of off-the-shelf equipment, found that close to half of intercepted GEO satellite communications were unencrypted. Captured cleartext cellular backhaul (calls, texts), military asset tracking, ICS job scheduling, utility infrastructure data, corporate/banking network traffic, and in-flight airline passenger activity.",
    significance:
      "Distinguished Paper at ACM CCS 2025. Most current validation that the DVB-S eavesdropping threat Pavur identified in 2019 persists at scale six years later.",
    cost: "$800",
  },
  {
    id: "hackasat",
    researcher: "US Air Force Research Lab / Space Force",
    org: "Hack-A-Sat Competition",
    year: "2020–2024",
    title: "Hack-A-Sat CTF — Live Satellite Hacking",
    description:
      "Annual competition progressively escalating in scope. In 2023 (Hack-A-Sat 4), teams hacked a live on-orbit cubesat named Moonlighter for the first time. Italian team mHACKeroni won first place ($50,000), achieving full satellite control in under 90 minutes.",
    significance:
      "First public demonstration of hacking a live satellite in orbit. Proves practical exploitability of space systems.",
  },
];

export const GNSS_STATS: GnssStat[] = [
  {
    label: "GPS Signal Loss Increase",
    value: "220%",
    detail: "Increase in GPS signal loss events from 2021 to 2024 (IATA data)",
  },
  {
    label: "Daily Spoofing Events",
    value: "~700",
    detail: "Jamming/spoofing events per day recorded in 2024",
  },
  {
    label: "Baltic Sea Incidents",
    value: "46,000",
    detail: "GPS interference incidents over the Baltic Sea (Aug 2023 – Apr 2024)",
  },
  {
    label: "Flights Affected Daily",
    value: "1,100+",
    detail: "Flights per day affected by GPS interference by August 2024",
  },
  {
    label: "Vessels Disrupted",
    value: "3,000+",
    detail: "Vessels disrupted in Persian Gulf in under two weeks (June 2025)",
  },
];

export const SATCOM_ADVISORIES: SatcomAdvisory[] = [
  {
    id: "cisa-aa22",
    issuer: "CISA / FBI",
    title: "AA22-076A — Strengthening Cybersecurity of SATCOM Networks",
    date: "March 2022 (updated May 2022)",
    description:
      "Issued in direct response to the Viasat attack. Recommended MFA, least privilege, default credential changes, log monitoring, network segmentation, and incident response planning for all SATCOM operators. May 2022 update formally attributed the KA-SAT attack to Russian state-sponsored actors.",
  },
  {
    id: "cisa-space-2024",
    issuer: "CISA",
    title: "Recommendations to Space System Operators",
    date: "June 2024",
    description:
      "Dedicated guidance document for improving cybersecurity across space system operations, extending beyond the 2022 SATCOM-specific advisory to cover the broader space ecosystem.",
  },
  {
    id: "nist-2023",
    issuer: "NIST",
    title: "IR 8401 / 8270 / 8441 — Satellite Cybersecurity Frameworks",
    date: "2023",
    description:
      "Three publications applying the NIST CSF to satellite operations: IR 8401 (ground segment command & control), IR 8270 (commercial satellite operations), IR 8441 (hybrid satellite networks with multi-operator constellations).",
  },
  {
    id: "enisa-leo",
    issuer: "ENISA",
    title: "LEO Satcom Cybersecurity Assessment",
    date: "February 2024",
    description:
      "EU-focused assessment providing 125 cybersecurity controls across 35 sub-categories for LEO constellations, covering design through decommissioning phases.",
  },
  {
    id: "enisa-space-2025",
    issuer: "ENISA",
    title: "Space Threat Landscape 2025",
    date: "March 2025",
    description:
      "First dedicated ENISA space threat landscape report. Identifies weak cryptographic practices, software misconfigurations, insecure supply chains, and operational resilience gaps as top threats.",
  },
  {
    id: "nis2",
    issuer: "European Union",
    title: "NIS2 Directive — Space as High Criticality Sector",
    date: "January 2025",
    description:
      "Classifies space as a \"high criticality\" sector requiring mandatory cybersecurity obligations and incident reporting. First regulatory framework imposing compliance requirements on space operators.",
  },
  {
    id: "csis-2025",
    issuer: "CSIS",
    title: "2025 Space Threat Assessment",
    date: "April 2025",
    description:
      "Annual assessment finding that cyberattacks, jamming, spoofing, and unfriendly behaviors in space have become \"commonplace\" and rarely trigger escalatory responses.",
  },
];

export const SATCOM_FRAMEWORKS: SatcomFramework[] = [
  {
    id: "sparta",
    name: "SPARTA v3.2",
    org: "Aerospace Corporation",
    description:
      "The primary space-specific threat framework and ATT&CK-equivalent for space systems. Defines and categorizes TTPs for spacecraft compromise via both cyber and traditional counterspace means. Covers ground segment, link segment, and space segment with countermeasures mapped to NIST CSF functions. Used by DoD, intelligence community, and commercial satellite operators.",
  },
  {
    id: "attack-ics",
    name: "MITRE ATT&CK for ICS",
    org: "MITRE",
    description:
      "The closest official MITRE framework for SATCOM, with 83 techniques covering the overlap between satellite systems and ICS in terms of real-time performance, reliability, and safety criticality. Relevant techniques include Remote Services (T0886), Exploitation of Remote Services (T0866), Denial of Service (T0814), and Loss of View/Control (T0829/T0827).",
  },
  {
    id: "sat-attack",
    name: "Sat-ATT&CK",
    org: "Academic (MDPI Aerospace, 2025)",
    description:
      "A proposed academic extension of MITRE ATT&CK for ICS specifically tailored for satellite networks. Integrates unique satellite attributes: open RF channels, dynamic topology, space-ground collaboration, and orbital mechanics constraints. Validated by modeling real incidents including the Viasat attack.",
  },
];

export const KEY_TAKEAWAYS: string[] = [
  "The encryption gap persists — nearly half of GEO satellite links remain unencrypted in 2025 (UCSD CCS paper), six years after Pavur first demonstrated the problem.",
  "Ground segment is always the entry point — every major real-world attack (Viasat, Salt Typhoon) entered through ground infrastructure (VPN appliances, management interfaces), not the space segment.",
  "GNSS spoofing has gone from theoretical to operationally catastrophic — 220% increase in GPS signal loss, 700 daily incidents, airline incidents, and mass maritime disruption.",
  "Regulatory pressure has arrived — the EU NIS2 Directive, NIST satellite frameworks, and ENISA reports mean compliance obligations now exist where there were none before.",
  "SPARTA is the operational framework — for anyone doing threat modeling or red-teaming of satellite systems, SPARTA from Aerospace Corporation is the current standard, not generic ATT&CK.",
];

const NATION_COLORS: Record<string, string> = {
  Russia: "bg-red-900/50 text-red-400",
  China: "bg-amber-900/50 text-amber-400",
  "North Korea": "bg-purple-900/50 text-purple-400",
  Iran: "bg-emerald-900/50 text-emerald-400",
};

export function getNationStyle(nation: string): string {
  return NATION_COLORS[nation] ?? "bg-zinc-800 text-zinc-400";
}

const ISSUER_COLORS: Record<string, string> = {
  "CISA / FBI": "bg-blue-900/50 text-blue-400",
  CISA: "bg-blue-900/50 text-blue-400",
  NIST: "bg-cyan-900/50 text-cyan-400",
  ENISA: "bg-indigo-900/50 text-indigo-400",
  "European Union": "bg-indigo-900/50 text-indigo-400",
  CSIS: "bg-violet-900/50 text-violet-400",
};

export function getIssuerStyle(issuer: string): string {
  return ISSUER_COLORS[issuer] ?? "bg-zinc-800 text-zinc-400";
}
