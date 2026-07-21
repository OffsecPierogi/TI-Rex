import { prisma } from "../src/lib/db";

const APT_COUNTRIES: Record<string, { country: string; motivations: string[] }> = {
  // --- Russia (GRU, FSB, SVR) ---
  "APT28": { country: "Russia", motivations: ["espionage", "disruption"] },
  "APT29": { country: "Russia", motivations: ["espionage", "intelligence-gathering"] },
  "Sandworm Team": { country: "Russia", motivations: ["disruption", "sabotage", "espionage"] },
  "Turla": { country: "Russia", motivations: ["espionage", "intelligence-gathering"] },
  "Gamaredon Group": { country: "Russia", motivations: ["espionage"] },
  "Ember Bear": { country: "Russia", motivations: ["disruption", "espionage"] },
  "Star Blizzard": { country: "Russia", motivations: ["espionage", "credential-theft"] },
  "Indrik Spider": { country: "Russia", motivations: ["financial-gain", "ransomware"] },
  "Wizard Spider": { country: "Russia", motivations: ["financial-gain", "ransomware"] },
  "TEMP.Veles": { country: "Russia", motivations: ["sabotage", "ics-targeting"] },
  "Dragonfly": { country: "Russia", motivations: ["espionage", "ics-targeting"] },
  "Nomadic Octopus": { country: "Russia", motivations: ["espionage"] },

  // --- China (MSS, PLA, contractors) ---
  "APT1": { country: "China", motivations: ["espionage", "ip-theft"] },
  "APT3": { country: "China", motivations: ["espionage", "ip-theft"] },
  "APT10": { country: "China", motivations: ["espionage", "ip-theft"] },
  "APT17": { country: "China", motivations: ["espionage"] },
  "APT19": { country: "China", motivations: ["espionage"] },
  "APT27": { country: "China", motivations: ["espionage", "ip-theft"] },
  "APT30": { country: "China", motivations: ["espionage"] },
  "APT31": { country: "China", motivations: ["espionage"] },
  "APT40": { country: "China", motivations: ["espionage", "ip-theft"] },
  "APT41": { country: "China", motivations: ["espionage", "financial-gain"] },
  "Mustang Panda": { country: "China", motivations: ["espionage"] },
  "Chimera": { country: "China", motivations: ["espionage", "ip-theft"] },
  "Winnti Group": { country: "China", motivations: ["espionage", "financial-gain"] },
  "HAFNIUM": { country: "China", motivations: ["espionage"] },
  "Volt Typhoon": { country: "China", motivations: ["pre-positioning", "critical-infrastructure"] },
  "Salt Typhoon": { country: "China", motivations: ["espionage", "telecom-targeting"] },
  "Flax Typhoon": { country: "China", motivations: ["espionage"] },
  "Ke3chang": { country: "China", motivations: ["espionage"] },
  "GALLIUM": { country: "China", motivations: ["espionage", "telecom-targeting"] },
  "BlackTech": { country: "China", motivations: ["espionage"] },
  "Naikon": { country: "China", motivations: ["espionage"] },
  "admin@338": { country: "China", motivations: ["espionage"] },
  "menuPass": { country: "China", motivations: ["espionage", "ip-theft"] },
  "Threat Group-3390": { country: "China", motivations: ["espionage"] },
  "BRONZE BUTLER": { country: "China", motivations: ["espionage", "ip-theft"] },
  "Putter Panda": { country: "China", motivations: ["espionage"] },
  "TEMP.Periscope": { country: "China", motivations: ["espionage"] },
  "Tonto Team": { country: "China", motivations: ["espionage"] },

  // --- North Korea (RGB, Lazarus umbrella) ---
  "Lazarus Group": { country: "North Korea", motivations: ["financial-gain", "espionage", "disruption"] },
  "Kimsuky": { country: "North Korea", motivations: ["espionage", "credential-theft"] },
  "Andariel": { country: "North Korea", motivations: ["financial-gain", "espionage"] },
  "APT37": { country: "North Korea", motivations: ["espionage"] },
  "APT38": { country: "North Korea", motivations: ["financial-gain"] },
  "APT43": { country: "North Korea", motivations: ["espionage", "financial-gain", "crypto-theft"] },
  "TEMP.Hermit": { country: "North Korea", motivations: ["espionage", "financial-gain"] },

  // --- Iran (MOIS, IRGC) ---
  "APT33": { country: "Iran", motivations: ["espionage", "disruption"] },
  "APT34": { country: "Iran", motivations: ["espionage"] },
  "APT35": { country: "Iran", motivations: ["espionage"] },
  "APT39": { country: "Iran", motivations: ["espionage", "surveillance"] },
  "APT42": { country: "Iran", motivations: ["espionage", "surveillance"] },
  "MuddyWater": { country: "Iran", motivations: ["espionage"] },
  "OilRig": { country: "Iran", motivations: ["espionage"] },
  "Magic Hound": { country: "Iran", motivations: ["espionage"] },
  "Cleaver": { country: "Iran", motivations: ["espionage", "disruption"] },
  "Moses Staff": { country: "Iran", motivations: ["disruption", "hacktivism"] },
  "Agrius": { country: "Iran", motivations: ["disruption", "wiper"] },
  "HEXANE": { country: "Iran", motivations: ["espionage"] },
  "Leafminer": { country: "Iran", motivations: ["espionage"] },
  "CopyKittens": { country: "Iran", motivations: ["espionage"] },
  "Fox Kitten": { country: "Iran", motivations: ["espionage", "ransomware"] },

  // --- Vietnam ---
  "APT32": { country: "Vietnam", motivations: ["espionage"] },

  // --- India ---
  "Patchwork": { country: "India", motivations: ["espionage"] },
  "Sidewinder": { country: "India", motivations: ["espionage"] },
  "BITTER": { country: "India", motivations: ["espionage"] },
  "Donot Team": { country: "India", motivations: ["espionage"] },

  // --- Pakistan ---
  "Transparent Tribe": { country: "Pakistan", motivations: ["espionage"] },

  // --- Financially-motivated groups with known attribution ---
  "FIN6": { country: "Russia", motivations: ["financial-gain"] },
  "FIN7": { country: "Russia", motivations: ["financial-gain"] },
  "FIN8": { country: "Russia", motivations: ["financial-gain"] },
  "FIN11": { country: "Russia", motivations: ["financial-gain", "ransomware"] },
  "FIN12": { country: "Russia", motivations: ["ransomware"] },
  "FIN13": { country: "Mexico", motivations: ["financial-gain"] },
  "TA505": { country: "Russia", motivations: ["financial-gain", "ransomware"] },
  "Scattered Spider": { country: "USA", motivations: ["financial-gain", "extortion"] },

  // --- Turkey ---
  "Sea Turtle": { country: "Turkey", motivations: ["espionage"] },

  // --- Lebanon ---
  "Volatile Cedar": { country: "Lebanon", motivations: ["espionage"] },
  "Dark Caracal": { country: "Lebanon", motivations: ["espionage", "surveillance"] },

  // --- China (additional) ---
  "APT5": { country: "China", motivations: ["espionage"] },
  "APT12": { country: "China", motivations: ["espionage"] },
  "APT16": { country: "China", motivations: ["espionage"] },
  "APT18": { country: "China", motivations: ["espionage"] },
  "Aquatic Panda": { country: "China", motivations: ["espionage"] },
  "Axiom": { country: "China", motivations: ["espionage"] },
  "BackdoorDiplomacy": { country: "China", motivations: ["espionage"] },
  "Cinnamon Tempest": { country: "China", motivations: ["financial-gain", "ransomware"] },
  "Daggerfly": { country: "China", motivations: ["espionage"] },
  "Deep Panda": { country: "China", motivations: ["espionage"] },
  "DragonOK": { country: "China", motivations: ["espionage"] },
  "Earth Lusca": { country: "China", motivations: ["espionage", "financial-gain"] },
  "Elderwood": { country: "China", motivations: ["espionage"] },
  "Lotus Blossom": { country: "China", motivations: ["espionage"] },
  "LuminousMoth": { country: "China", motivations: ["espionage"] },
  "MirrorFace": { country: "China", motivations: ["espionage"] },
  "Moafee": { country: "China", motivations: ["espionage"] },
  "Mofang": { country: "China", motivations: ["espionage"] },
  "PLATINUM": { country: "China", motivations: ["espionage"] },
  "PittyTiger": { country: "China", motivations: ["espionage"] },
  "Rancor": { country: "China", motivations: ["espionage"] },
  "RedEcho": { country: "China", motivations: ["espionage"] },
  "Suckfly": { country: "China", motivations: ["espionage"] },
  "Thrip": { country: "China", motivations: ["espionage"] },
  "ToddyCat": { country: "China", motivations: ["espionage"] },
  "Tropic Trooper": { country: "China", motivations: ["espionage"] },
  "UNC3886": { country: "China", motivations: ["espionage"] },
  "Velvet Ant": { country: "China", motivations: ["espionage"] },
  "Whitefly": { country: "China", motivations: ["espionage"] },
  "Aoqin Dragon": { country: "China", motivations: ["espionage"] },

  // --- Iran (additional) ---
  "CURIUM": { country: "Iran", motivations: ["espionage"] },
  "CyberAv3ngers": { country: "Iran", motivations: ["sabotage", "hacktivism"] },
  "DarkHydrus": { country: "Iran", motivations: ["espionage"] },
  "Ferocious Kitten": { country: "Iran", motivations: ["espionage", "surveillance"] },
  "POLONIUM": { country: "Iran", motivations: ["espionage"] },
  "Silent Librarian": { country: "Iran", motivations: ["espionage", "credential-theft"] },
  "UNC788": { country: "Iran", motivations: ["espionage"] },
  "VOID MANTICORE": { country: "Iran", motivations: ["sabotage", "hacktivism"] },
  "Windshift": { country: "Iran", motivations: ["espionage", "surveillance"] },

  // --- Russia (additional) ---
  "ALLANITE": { country: "Russia", motivations: ["espionage"] },
  "Winter Vivern": { country: "Russia", motivations: ["espionage"] },
  "Strider": { country: "Russia", motivations: ["espionage"] },

  // --- North Korea (additional) ---
  "AppleJeus": { country: "North Korea", motivations: ["financial-gain"] },
  "Contagious Interview": { country: "North Korea", motivations: ["financial-gain", "espionage"] },
  "Moonstone Sleet": { country: "North Korea", motivations: ["financial-gain", "espionage"] },

  // --- South Korea ---
  "Darkhotel": { country: "South Korea", motivations: ["espionage"] },

  // --- Palestine ---
  "Molerats": { country: "Palestine", motivations: ["espionage"] },

  // --- Pakistan (additional) ---
  "Confucius": { country: "Pakistan", motivations: ["espionage"] },
  "Gorgon Group": { country: "Pakistan", motivations: ["espionage", "financial-gain"] },
  "SideCopy": { country: "Pakistan", motivations: ["espionage"] },

  // --- UAE ---
  "Stealth Falcon": { country: "UAE", motivations: ["espionage", "surveillance"] },

  // --- Brazil ---
  "Poseidon Group": { country: "Brazil", motivations: ["financial-gain"] },
  "Malteiro": { country: "Brazil", motivations: ["financial-gain"] },

  // --- USA ---
  "Equation": { country: "USA", motivations: ["espionage"] },

  // --- Belarus ---
  "MoustachedBouncer": { country: "Belarus", motivations: ["espionage"] },

  // --- Financially-motivated groups (additional known attributions) ---
  "Carbanak": { country: "Russia", motivations: ["financial-gain"] },
  "Cobalt Group": { country: "Russia", motivations: ["financial-gain"] },
  "LAPSUS$": { country: "United Kingdom", motivations: ["financial-gain", "hacktivism"] },
  "GOLD SOUTHFIELD": { country: "Russia", motivations: ["financial-gain", "ransomware"] },
  "BlackByte": { country: "Russia", motivations: ["financial-gain", "ransomware"] },
  "Storm-0501": { country: "Russia", motivations: ["financial-gain", "ransomware"] },
  "Storm-1811": { country: "Russia", motivations: ["financial-gain"] },
  "Mustard Tempest": { country: "Russia", motivations: ["financial-gain"] },
  "Silence": { country: "Russia", motivations: ["financial-gain"] },
  "RTM": { country: "Russia", motivations: ["financial-gain"] },
  "SilverTerrier": { country: "Nigeria", motivations: ["financial-gain", "BEC"] },
  "EXOTIC LILY": { country: "Russia", motivations: ["financial-gain", "initial-access-broker"] },
  "TA551": { country: "Russia", motivations: ["financial-gain", "malware-distribution"] },
  "TA577": { country: "Russia", motivations: ["financial-gain", "malware-distribution"] },
  "TA578": { country: "Russia", motivations: ["financial-gain"] },
  "Blue Mockingbird": { country: "Russia", motivations: ["financial-gain", "cryptomining"] },
  "WIRTE": { country: "Palestine", motivations: ["espionage"] },
  "Evilnum": { country: "Russia", motivations: ["financial-gain"] },
  "DarkVishnya": { country: "Russia", motivations: ["financial-gain"] },

  // --- Best-judgment attributions (high-confidence public intel) ---
  "PROMETHIUM": { country: "Turkey", motivations: ["espionage"] },
  "Machete": { country: "Venezuela", motivations: ["espionage"] },
  "Scarlet Mimic": { country: "China", motivations: ["espionage"] },
  "IndigoZebra": { country: "China", motivations: ["espionage"] },
  "Higaisa": { country: "South Korea", motivations: ["espionage"] },
  "RedCurl": { country: "Russia", motivations: ["espionage"] },
  "GCMAN": { country: "Russia", motivations: ["financial-gain"] },
};

interface CustomActor {
  name: string;
  aliases: string[];
  description: string;
  country: string | null;
  motivations: string[];
}

const CUSTOM_ACTORS: CustomActor[] = [
  {
    name: "DragonForce",
    aliases: ["Hackledorb"],
    description:
      "Ransomware-as-a-Service operation first observed August 2023. Uses leaked LockBit 3.0 and ContiV3 builders. Transitioned to a cartel model in March 2025 allowing affiliates to white-label payloads (Devman, Mamona/Global). Operates DragonLeaks for double extortion. First group to weaponize Microsoft Teams TURN relay servers for covert C2 via custom Backdoor.Turn implant (Go-based RAT). Uses BYOVD for EDR termination with Abyss Worker kernel driver. Notable attacks: Marks & Spencer (est. £300M), Co-op (est. £206M), Ohio Lottery (600+ GB). Scattered Spider operates as DragonForce affiliate for initial access via social engineering.",
    country: null,
    motivations: ["financial-gain", "ransomware", "extortion"],
  },
  {
    name: "LockBit",
    aliases: ["LockBit 2.0", "LockBit 3.0", "LockBit Black", "LockBit Green"],
    description:
      "Most prolific ransomware-as-a-service (RaaS) operation globally from 2019-2024. Responsible for over 1,700 attacks in the US alone. Developed three major versions with LockBit 3.0 (Black) including anti-analysis and self-spreading capabilities. Operation Cronos (Feb 2024) disrupted infrastructure but group attempted comeback. Operator LockBitSupp identified as Dmitry Khoroshev (May 2024). Pioneered bug bounty program for ransomware. Known for triple extortion: encryption, data theft, and DDoS threats.",
    country: "Russia",
    motivations: ["financial-gain", "ransomware", "extortion"],
  },
  {
    name: "ALPHV BlackCat",
    aliases: ["BlackCat", "ALPHV", "Noberus"],
    description:
      "First major ransomware written in Rust, active since November 2021. Operated by former DarkSide/BlackMatter affiliates. Notable for sophisticated cross-platform payloads (Windows, Linux, ESXi). Conducted exit scam in March 2024 after $22M Change Healthcare ransom payment. Pioneered searchable leak sites and SEC complaint filing as extortion leverage. Known victims include MGM Resorts ($100M+ impact), Reddit, Western Digital.",
    country: "Russia",
    motivations: ["financial-gain", "ransomware", "extortion"],
  },
  {
    name: "REvil",
    aliases: ["Sodinokibi", "GandCrab successor", "GOLD SOUTHFIELD"],
    description:
      "High-profile ransomware-as-a-service operation active 2019-2022, successor to GandCrab. Conducted Kaseya VSA supply chain attack (July 2021) affecting 1,500+ organizations. Also hit JBS Foods ($11M ransom), Quanta Computer (Apple supplier). Pioneered DLS-based double extortion at scale. Infrastructure seized by Russia's FSB in January 2022 with multiple arrests. Affiliates transitioned to BlackCat, Hive, and other operations.",
    country: "Russia",
    motivations: ["financial-gain", "ransomware", "extortion"],
  },
  {
    name: "DarkSide",
    aliases: ["BlackMatter", "Carbon Spider"],
    description:
      "Ransomware group responsible for the Colonial Pipeline attack (May 2021) causing US fuel shortage and state of emergency. Rebranded to BlackMatter after law enforcement pressure. Operated as RaaS with strict targeting rules (no hospitals, critical infrastructure—which they violated). Shut down November 2021 with operators moving to ALPHV/BlackCat. Estimated $90M+ in Bitcoin ransom payments.",
    country: "Russia",
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "Hive",
    aliases: ["Hive Ransomware Group"],
    description:
      "Ransomware-as-a-service operation active June 2021 to January 2023. Targeted 1,500+ victims across 80+ countries, extorting $100M+ in ransom. Known for targeting healthcare and critical infrastructure including Costa Rica's public health service. FBI secretly infiltrated Hive's network for 7 months, providing 300+ decryption keys to victims. Infrastructure seized in coordinated multinational operation (Jan 2023).",
    country: null,
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "Clop",
    aliases: ["Cl0p", "TA505 affiliate", "FIN11 affiliate", "GOLD TAHOE"],
    description:
      "Ransomware group specializing in mass exploitation of zero-day vulnerabilities in file transfer platforms. Responsible for MOVEit Transfer exploitation (CVE-2023-34362) affecting 2,700+ organizations including Shell, BBC, US government agencies. Previously exploited GoAnywhere MFT (CVE-2023-0669) and Accellion FTA (CVE-2021-27101). Uniquely focuses on data theft and extortion without deploying encryption in many campaigns. Estimated $75M+ from MOVEit campaign alone.",
    country: "Russia",
    motivations: ["financial-gain", "ransomware", "data-theft"],
  },
  {
    name: "Royal",
    aliases: ["BlackSuit", "Royal Ransomware", "Zeon"],
    description:
      "Ransomware operation active September 2022, rebranded to BlackSuit in mid-2024. Composed of former Conti members (Team 2). Demands range from $1M to $11M. Targets critical infrastructure including healthcare. Uses callback phishing, RDP compromise, and malvertising for initial access. Distinctive for not operating as RaaS—directly conducts attacks. CISA reports $275M+ in ransom demands.",
    country: "Russia",
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "Conti",
    aliases: ["Conti Team", "Ryuk successor", "Gold Ulrick"],
    description:
      "Major ransomware operation active 2020-2022, successor to Ryuk. Operated by Wizard Spider (Russia). Responsible for 1,000+ attacks including Costa Rica government (May 2022, national emergency declared). Internal chats leaked February 2022 after pro-Russia Ukraine stance, revealing organizational structure of 100+ members. Disbanded May 2022 with members dispersing to Royal/BlackSuit, BlackBasta, Karakurt, Quantum, and others.",
    country: "Russia",
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "Black Basta",
    aliases: ["BlackBasta"],
    description:
      "Ransomware-as-a-service operation active since April 2022, linked to former Conti members. Over 500 victims globally by 2024. Uses QakBot, Pikabot, and DarkGate for initial access. Known for rapid encryption (under 2 hours from initial access). Targets critical infrastructure, healthcare, and manufacturing. Chat logs leaked February 2025 revealing internal conflicts and Russian ties. Estimated $100M+ in ransom payments received.",
    country: "Russia",
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "Rhysida",
    aliases: ["Vice Society successor"],
    description:
      "Ransomware group active since May 2023, believed to be successor or rebrand of Vice Society. Targets education, healthcare, manufacturing, and government sectors. Notable attacks include British Library (Oct 2023, 600GB stolen), Prospect Medical Holdings, Chilean Army, City of Columbus. Uses phishing, VPN exploitation, and Cobalt Strike for intrusion. Operates double extortion with auction-style leak site.",
    country: null,
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "BianLian",
    aliases: ["BianLian Ransomware"],
    description:
      "Ransomware group active since June 2022. Shifted from double extortion (encryption + data theft) to pure data extortion in January 2023 after Avast released free decryptor. Targets critical infrastructure, professional services, healthcare. Uses ProxyShell, RDP, and stolen credentials for access. Known for SonicWall VPN and TeamCity exploitation. CISA advisory AA23-136A details TTPs.",
    country: null,
    motivations: ["financial-gain", "ransomware", "data-theft"],
  },
  {
    name: "Vice Society",
    aliases: ["DEV-0832"],
    description:
      "Ransomware group active since mid-2021, primarily targeting education sector (disproportionate attacks on K-12 schools). Uses multiple ransomware families including custom variants, HelloKitty, Zeppelin, and RedAlert. Notable for LAUSD (Los Angeles Unified School District) attack in September 2022. Believed to have rebranded to Rhysida in 2023. Microsoft tracks as DEV-0832.",
    country: null,
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "Cuba Ransomware",
    aliases: ["COLDDRAW", "Tropical Scorpius"],
    description:
      "Ransomware group active since December 2019. Compromised 100+ entities worldwide, demanding $145M+ and receiving $60M+ in ransom. Uses BUGHATCH downloader, WEDGECUT reconnaissance tool, Cobalt Strike, and Metasploit. Exploits Microsoft Exchange vulnerabilities (ProxyShell, ProxyLogon) for initial access. CISA advisories AA22-335A and AA23-075A detail TTPs. Not affiliated with the nation of Cuba.",
    country: "Russia",
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "Hunters International",
    aliases: ["Hunters Intl"],
    description:
      "Ransomware-as-a-service operation active since October 2023, acquired Hive ransomware source code and infrastructure after FBI takedown. Claimed to have purchased code rather than being a rebrand. Rapidly grew to one of the most active groups by 2024. Targets healthcare, manufacturing, and government. Uses Rust-based payloads derived from Hive codebase. Operates data leak site for double extortion.",
    country: null,
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "NoEscape",
    aliases: ["Avaddon successor"],
    description:
      "Ransomware-as-a-service operation active May-December 2023. Built new Rust-based ransomware from scratch (not based on leaked builders). Conducted exit scam in December 2023, stealing affiliates' funds. Affiliates migrated to LockBit and other operations. Known for targeting Linux/ESXi alongside Windows. Short-lived but demonstrated increasingly professionalized RaaS economics.",
    country: "Russia",
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "Cactus",
    aliases: ["Cactus Ransomware"],
    description:
      "Ransomware group active since March 2023. Distinctive for self-encrypting its own binary to evade antivirus detection. Exploits Fortinet VPN vulnerabilities (CVE-2023-38035) and QLIK Sense (CVE-2023-41266) for initial access. Uses Chisel, SoftPerfect Network Scanner, and Splashtop for lateral movement. Targets large enterprises in manufacturing, tech, and professional services. Double extortion with data leak site.",
    country: null,
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "8Base",
    aliases: ["8Base Ransomware", "EightBase"],
    description:
      "Ransomware group active since March 2022, surged in mid-2023. Uses Phobos ransomware variant with SmokeLoader for delivery. Targets small and medium businesses globally. Operates double extortion leak site. Claims to be 'honest and simple pentesters' despite conducting destructive ransomware attacks. Uses SystemBC and Cobalt Strike for C2.",
    country: null,
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "Snatch",
    aliases: ["Snatch Team"],
    description:
      "Ransomware group active since 2018. Pioneered technique of rebooting Windows into Safe Mode to bypass security products before encryption. Targets manufacturing, IT, and government sectors. Operates as both ransomware operator and data extortion marketplace, sometimes listing data from other groups. Known for prolonged dwell time (weeks to months) before deployment.",
    country: "Russia",
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "AvosLocker",
    aliases: ["Avos"],
    description:
      "Ransomware-as-a-service operation active since June 2021. Used legitimate tools like AnyDesk and PDQ Deploy during attacks. CISA/FBI joint advisory AA23-284A details TTPs. Targeted critical infrastructure including financial services and government. Cross-platform payloads for Windows and Linux/ESXi. Operations diminished after law enforcement actions in late 2023.",
    country: "Russia",
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "Ragnar Locker",
    aliases: ["Ragnar_Locker", "Viking Spider"],
    description:
      "Ransomware group active since December 2019. Distinctive for deploying ransomware inside a VirtualBox VM to evade endpoint protection. Targeted critical infrastructure including Energias de Portugal (10TB stolen), Capcom, and CWT. Leader arrested in Paris October 2023, infrastructure seized in coordinated Europol operation across 6 countries. One of the first groups to use VM-based evasion techniques.",
    country: "Russia",
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "Phobos",
    aliases: ["Phobos Ransomware"],
    description:
      "Ransomware family active since 2018, distributed through multiple affiliates. Derived from Dharma/CrySis ransomware family. Primarily targets small and medium businesses via exposed RDP services. Low ransom demands ($1K-$50K) but extremely high volume. CISA advisory AA24-060A details TTPs. Admin Evgenii Ptitsyn indicted November 2024. Frequently used by 8Base and other groups as payload.",
    country: "Russia",
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "Trigona",
    aliases: ["Trigona Ransomware"],
    description:
      "Ransomware group active October 2022 to October 2023. Exploited Microsoft SQL Server vulnerabilities for initial access. Used CLR assemblies for payload deployment. Ukrainian Cyber Alliance hacked and wiped Trigona's servers in October 2023, publishing exfiltrated data. Short-lived but demonstrated sophisticated SQL Server exploitation chains.",
    country: "Russia",
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "Qilin",
    aliases: ["Agenda", "Qilin Ransomware"],
    description:
      "Ransomware-as-a-service operation active since July 2022. Rebranded from Agenda ransomware. Written in Rust and Go with cross-platform capabilities. Notable for attacking Synnovis pathology services (June 2024) disrupting London NHS hospitals and causing blood test delays. Operates aggressive affiliate program with 80-85% revenue share. Targets healthcare, education, and manufacturing.",
    country: "Russia",
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "Fog",
    aliases: ["Fog Ransomware"],
    description:
      "Ransomware group active since May 2024. Primarily targets US education and recreation sectors. Exploits compromised VPN credentials (SonicWall) for initial access. Uses pass-the-hash attacks and deploys via PsExec. Rapid encryption with short dwell times. Named for .fog and .flocked file extensions appended to encrypted files. Growing threat to higher education institutions.",
    country: null,
    motivations: ["financial-gain", "ransomware"],
  },
  {
    name: "RansomHub",
    aliases: ["RansomHub RaaS"],
    description:
      "Ransomware-as-a-service operation emerged February 2024, quickly became one of the most prolific groups. Believed to incorporate former ALPHV/BlackCat and NoEscape affiliates. Offers 90% affiliate payout—highest in the RaaS market. Uses EDRKillShifter for endpoint protection bypass. Notable victims include Change Healthcare (after ALPHV exit scam), Christie's auction house, Frontier Communications. CISA advisory details TTPs.",
    country: null,
    motivations: ["financial-gain", "ransomware", "extortion"],
  },
  {
    name: "Karakurt",
    aliases: ["Karakurt Lair", "Karakurt Team", "DEV-0530"],
    description:
      "Data extortion group active since June 2021, linked to Conti syndicate. Focuses exclusively on data theft and extortion without deploying encryption. Steals data and threatens to publish or sell it. Known for contacting victims' employees, partners, and customers directly to pressure payment. CISA/FBI advisory AA22-152A details TTPs. Ransom demands range from $25K to $13M. Operates as Conti's data extortion arm.",
    country: "Russia",
    motivations: ["financial-gain", "data-theft", "extortion"],
  },
];

async function main() {
  console.log("Updating APT country attributions and motivations...");
  let updated = 0;
  let notFound = 0;

  for (const [name, info] of Object.entries(APT_COUNTRIES)) {
    const actor = await prisma.threatActor.findFirst({
      where: {
        OR: [
          { name },
          { aliases: { contains: name } },
        ],
      },
    });

    if (actor) {
      await prisma.threatActor.update({
        where: { id: actor.id },
        data: {
          country: info.country,
          motivations: JSON.stringify(info.motivations),
        },
      });
      updated++;
    } else {
      notFound++;
    }
  }

  console.log(`\nUpdated ${updated} actors, ${notFound} not found in DB`);

  // Create custom actors not from MITRE ATT&CK
  console.log("\nSeeding custom threat actors...");
  let created = 0;

  const maxExtId = await prisma.threatActor.findFirst({
    where: { externalId: { startsWith: "G9" } },
    orderBy: { externalId: "desc" },
    select: { externalId: true },
  });
  let nextId = maxExtId ? parseInt(maxExtId.externalId.slice(1), 10) + 1 : 9000;

  for (const actor of CUSTOM_ACTORS) {
    const existing = await prisma.threatActor.findFirst({
      where: {
        OR: [
          { name: actor.name },
          { aliases: { contains: actor.name } },
        ],
      },
    });

    if (existing) {
      await prisma.threatActor.update({
        where: { id: existing.id },
        data: {
          aliases: JSON.stringify(actor.aliases),
          description: actor.description,
          country: actor.country,
          motivations: JSON.stringify(actor.motivations),
        },
      });
      console.log(`  Updated: ${actor.name}`);
      updated++;
    } else {
      const syntheticId = `intrusion-set--custom-${actor.name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
      const externalId = `G${String(nextId).padStart(4, "0")}`;
      nextId++;
      await prisma.threatActor.create({
        data: {
          stixId: syntheticId,
          externalId,
          name: actor.name,
          aliases: JSON.stringify(actor.aliases),
          description: actor.description,
          country: actor.country,
          motivations: JSON.stringify(actor.motivations),
          url: "",
          matrix: "enterprise-attack",
        },
      });
      console.log(`  Created: ${actor.name} (${externalId})`);
      created++;
    }
  }

  // Link custom actors to ransomware category
  const ransomwareCat = await prisma.category.findUnique({ where: { slug: "ransomware" } });
  if (ransomwareCat) {
    for (const actor of CUSTOM_ACTORS) {
      if (!actor.motivations.includes("ransomware")) continue;
      const dbActor = await prisma.threatActor.findFirst({ where: { name: actor.name } });
      if (!dbActor) continue;
      await prisma.categoryActor.upsert({
        where: { categoryId_actorId: { categoryId: ransomwareCat.id, actorId: dbActor.id } },
        update: {},
        create: { categoryId: ransomwareCat.id, actorId: dbActor.id },
      });
      console.log(`  Linked ${actor.name} → ransomware category`);
    }
  }

  const countryCounts = await prisma.threatActor.groupBy({
    by: ["country"],
    _count: true,
    where: { country: { not: null } },
    orderBy: { _count: { country: "desc" } },
  });

  console.log(`\n${updated} actors updated, ${created} custom actors created`);
  console.log("\nActors by country:");
  for (const c of countryCounts) {
    console.log(`  ${c.country ?? "Unknown"}: ${c._count}`);
  }
}

main().catch(console.error).finally(() => process.exit(0));
