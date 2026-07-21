export interface ThreatSpotlight {
  group: string;
  aliases: string[];
  firstSeen: string;
  model: string;
  description: string;
  notableTTPs: { name: string; detail: string; mitre?: string }[];
  notableAttacks: { target: string; date: string; impact: string }[];
  c2Detail: {
    name: string;
    description: string;
    steps: string[];
    whyItWorks: string[];
    iocs: { type: string; value: string }[];
  };
  affiliates: { name: string; role: string }[];
  cves: { id: string; driver: string; use: string }[];
}

export const DRAGONFORCE_SPOTLIGHT: ThreatSpotlight = {
  group: "DragonForce",
  aliases: ["Hackledorb"],
  firstSeen: "August 2023",
  model: "Ransomware-as-a-Service (Cartel)",
  description:
    "DragonForce is a RaaS operation tracked by Symantec as Hackledorb. Launched in August 2023 using leaked LockBit 3.0 builders, they transitioned to a cartel model in March 2025 allowing affiliates to white-label payloads. They operate DragonLeaks for double extortion and have absorbed rival groups including BlackLock and RansomHub affiliates. DragonForce is the first group confirmed to weaponize Microsoft Teams TURN relay servers for covert C2 via their custom Backdoor.Turn implant.",

  notableTTPs: [
    {
      name: "TURN Relay C2 (Backdoor.Turn)",
      detail:
        "Custom Go RAT that tunnels C2 through Microsoft Teams TURN relay servers using anonymous visitor tokens and QUIC sessions. Traffic is indistinguishable from legitimate Teams calls.",
      mitre: "T1102, T1090.002, T1071.001",
    },
    {
      name: "DLL Sideloading",
      detail:
        "Delivers Backdoor.Turn via renamed VirtualBox executable (DbgView64.exe) that loads malicious vboxrt.dll.",
      mitre: "T1574.002",
    },
    {
      name: "BYOVD EDR Termination",
      detail:
        "Deploys 4+ vulnerable signed drivers plus a custom Abyss Worker kernel driver to kill EDR/AV at the kernel level.",
      mitre: "T1562.001",
    },
    {
      name: "Cartel White-Labeling",
      detail:
        "Affiliates operate under their own branding (Devman, Mamona/Global) while using DragonForce infrastructure.",
    },
    {
      name: "ESXi Targeting",
      detail:
        "Encrypts VMware ESXi virtual machines at the hypervisor layer to maximize blast radius.",
      mitre: "T1486",
    },
    {
      name: "Post-Ransomware Persistence",
      detail:
        "Deploys Backdoor.Turn after ransomware for long-term access, potential re-entry, or access resale.",
      mitre: "T1090.002",
    },
  ],

  notableAttacks: [
    { target: "Ohio Lottery", date: "Late 2023", impact: "600+ GB data stolen" },
    { target: "Marks & Spencer", date: "Apr-May 2025", impact: "Est. £300M ($400M) cost, via Scattered Spider affiliate" },
    { target: "Co-op", date: "May 2025", impact: "Est. £206M ($277M) revenue loss" },
    { target: "Harrods", date: "May 2025", impact: "Confirmed cyberattack" },
    { target: "U.S. Services Firm", date: "Dec 2025 - Feb 2026", impact: "First confirmed Backdoor.Turn deployment, 1-2 month dwell time" },
  ],

  c2Detail: {
    name: "Backdoor.Turn — Microsoft Teams TURN Relay C2",
    description:
      "First known in-the-wild malware to abuse Microsoft Teams TURN (Traversal Using Relays around NAT) servers for command and control. TURN is used by Teams/Zoom/Meet to relay encrypted media when direct connections fail. Backdoor.Turn exploits this by obtaining anonymous visitor tokens to tunnel QUIC sessions through Microsoft infrastructure.",
    steps: [
      "Obtains anonymous Teams visitor token from Microsoft Skype identity services — no credentials or active meeting required",
      "Authenticates to a legitimate Microsoft TURN relay server and requests a relay allocation",
      "Establishes a QUIC session through the TURN relay to the attacker's actual C2 server",
      "All C2 traffic flows through Microsoft infrastructure over TLS/port 443, encrypted end-to-end",
    ],
    whyItWorks: [
      "Traffic destinations are legitimate Microsoft Teams IPs — typically allowlisted in firewalls",
      "Microsoft recommends excluding Teams domains from TLS inspection and adding to split-tunnel VPNs",
      "All traffic is encrypted (QUIC/TLS) preventing content inspection",
      "No anomalous ports — everything runs over port 443",
      "Standard threat intel blocklists and IDS signatures cannot flag Microsoft infrastructure",
    ],
    iocs: [
      { type: "SHA-256", value: "821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6" },
      { type: "SHA-256", value: "048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c" },
      { type: "SHA-256 (Ransomware)", value: "e45b18c93d187aac5c4486f57483bc87580e15def82a312bfb377ff16eb96b22" },
      { type: "SHA-256 (DLL)", value: "f174c19902523dcf005fa044b6598403a5e5c0a5982398d1bc0dcc5ec1cd351b" },
      { type: "SHA-256 (Abyss Worker)", value: "8284c8676cc22c4b2e66826ac16986da7ddecba1f2776b16771be17bfdc45dc2" },
      { type: "C2 IP", value: "62.164.177.25" },
      { type: "Staging URL", value: "http://192.36.27.51/TechSupV18Fix3.zip" },
      { type: "C2 Domain", value: "turnkeyaiagents.com" },
      { type: "C2 Domain", value: "socialbizsolutions.com" },
      { type: "C2 Domain", value: "projetosmecanicos.com.br" },
      { type: "C2 Domain", value: "safefire.jo" },
      { type: "C2 Domain", value: "glanz-gmbh.de" },
    ],
  },

  affiliates: [
    { name: "Scattered Spider", role: "Initial access via social engineering of helpdesks (M&S, Co-op). Four suspects arrested July 2025." },
    { name: "BlackLock", role: "Leak site defaced by DragonForce; members absorbed into cartel." },
    { name: "RansomHub", role: "Infrastructure went offline April 2025; DragonForce claims they joined the cartel." },
  ],

  cves: [
    { id: "CVE-2023-52271", driver: "wsftprm.sys (Topaz Antifraud)", use: "BYOVD EDR termination" },
    { id: "CVE-2025-61155", driver: "Gamedriverx64.sys (Tower of Fantasy)", use: "BYOVD EDR termination" },
    { id: "CVE-2025-1055", driver: "K7RKScan.sys (K7 Security)", use: "BYOVD EDR termination" },
  ],
};
