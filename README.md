# TI-Rex — Threat Intelligence Platform

TI-Rex is a self-hosted threat intelligence platform built on Next.js 16, PostgreSQL, and Prisma. It aggregates data from over a dozen public and optional sources — MITRE ATT&CK, CISA KEV, NVD, EPSS, AlienVault OTX, abuse.ch (ThreatFox, Feodo Tracker, URLhaus), SigmaHQ, YARA-Rules, Atomic Red Team, Malpedia, RTFM, and 17 RSS/Atom threat feeds — into a single searchable interface. It tracks 190+ APT groups with country attributions and CVE exploitation links, 850+ malware families with C2 framework profiles, 1,800+ executable attack simulations, 3,000+ Sigma detection rules, and a live IOC database with optional enrichment from VirusTotal, AbuseIPDB, Shodan, and Hybrid Analysis sandboxing.

The platform ships with 30+ modules including a CVE tracker with EPSS exploit probability and CVSS scoring, an ATT&CK detection coverage heatmap, an IOC watchlist with webhook alerting, STIX 2.1 export, ATT&CK Navigator layer generation, a Sigma rule auto-generator, ransomware group intelligence, geopolitical threat maps, purple team coverage analysis, threat modeling workspace, and a full-text search across all entities. Everything is cross-linked — click an APT to see their techniques, exploited CVEs, malware, and IOCs; click a CVE to see which threat actors exploit it and its EPSS/CVSS scores.

Data ingestion runs automatically via a built-in scheduler (default 6 hours, configurable from the settings page) that clones repos, fetches APIs, scores CVEs, matches watchlist IOCs, and prunes stale records — no cron jobs or external setup required. The 30-step pipeline can also be triggered manually from the UI, via API (`POST /api/update`), or from the CLI with `npx tsx scripts/update-all.ts`. API keys for VirusTotal, OTX, AbuseIPDB, Shodan, Hybrid Analysis, and NVD are optional but unlock additional enrichment and faster ingestion. See `.env.example` for all configuration options.

<img width="1694" height="773" alt="image" src="https://github.com/user-attachments/assets/8a8490ea-7531-423c-907f-f238b4b1607f" />

<img width="1251" height="517" alt="image" src="https://github.com/user-attachments/assets/0dba9d24-f0be-4a1b-abbf-2d1a4f32e847" />

<img width="1268" height="799" alt="image" src="https://github.com/user-attachments/assets/3c13e5c0-77fd-498a-9576-438d15cea257" />

<img width="1245" height="565" alt="image" src="https://github.com/user-attachments/assets/c021821e-2567-49d5-8379-8c98d6233e30" />

## Install

```bash
git clone https://github.com/OffsecPierogi/TI-Rex.git
cd TI-Rex
chmod +x install.sh
./install.sh
```

The install script will set up your `.env`, PostgreSQL (via Docker or existing), dependencies, and database schema. It then asks whether to ingest threat data:

- **Fast mode (~2 min)** — ingests core data (MITRE ATT&CK, Atomic Red Team, CISA KEV, categories, detections, IOCs, YARA rules, Sigma rules, C2 profiles, threat feeds, and more). Skips slow rate-limited APIs (NVD CVSS enrichment, Malpedia actor enrichment, Supply Chain advisories). The built-in scheduler automatically backfills these on the first cycle after you start the app — no manual action needed.
- **Full mode (10-15 min)** — ingests everything including NVD, Malpedia, and Supply Chain in one shot. Slower due to external API rate limits.

After install, start the app with `npm run dev` (development) or `npm start` (production). The first user to register at `http://localhost:3000/register` becomes Admin. Data auto-refreshes every 6 hours by default (configurable in Settings).

## Important Notes

- **Database credentials**: The default PostgreSQL credentials (`tirex:tirex`) are for local development only. Change `DATABASE_URL` in `.env` for any production or network-exposed deployment.
- **AUTH_SECRET**: Must be set to a random string of 32+ characters or registration/login will fail. The install script generates this automatically — if setting up manually, run `openssl rand -base64 32` and paste the result into `.env`.
- **NVD API key**: CVE ingestion works without a key but is heavily rate-limited (5 requests per 30 seconds). A free API key from [NVD](https://nvd.nist.gov/developers/request-an-api-key) gives 10x faster ingestion. Set `NVD_API_KEY` in `.env`.

## References & Data Sources

TI-Rex aggregates and normalizes data from the following public projects and APIs. All credit to the original maintainers.

| Source | Description |
|--------|-------------|
| [MITRE ATT&CK](https://attack.mitre.org/) | Enterprise adversary tactics, techniques, and procedures (STIX 2.1) |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Library of executable attack simulations mapped to ATT&CK |
| [SigmaHQ](https://github.com/SigmaHQ/sigma) | Community detection rules in the Sigma format |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known Exploited Vulnerabilities catalog with confirmed active exploitation |
| [NVD](https://nvd.nist.gov/) | National Vulnerability Database — CVE details, CVSS scores, CPE data |
| [EPSS](https://www.first.org/epss/) | Exploit Prediction Scoring System — daily exploit probability scores |
| [ThreatFox (abuse.ch)](https://threatfox.abuse.ch/) | IOCs tagged by malware family — IPs, domains, URLs, hashes |
| [Feodo Tracker (abuse.ch)](https://feodotracker.abuse.ch/) | Active botnet C2 server tracking |
| [URLhaus (abuse.ch)](https://urlhaus.abuse.ch/) | Malicious URL collection for malware distribution |
| [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) | Malware descriptions, actor attribution, and YARA rules |
| [AlienVault OTX](https://otx.alienvault.com/) | Open Threat Exchange — community IOC pulses |
| [RTFM](https://github.com/leostat/rtfm) | Red Team Field Manual — offensive commands with technique mapping |
| [YARA-Rules](https://github.com/Yara-Rules/rules) | Community YARA rules for malware detection |
| [Neo23x0 signature-base](https://github.com/Neo23x0/signature-base) | YARA and Sigma signatures from Florian Roth |
| [ReversingLabs YARA Rules](https://github.com/reversinglabs/reversinglabs-yara-rules) | YARA rules from ReversingLabs threat research |
| [VirusTotal](https://www.virustotal.com/) | File, IP, and domain reputation lookups (optional, requires free API key) |
| [Hybrid Analysis](https://www.hybrid-analysis.com/) | Sandbox detonation and behavioral analysis (optional, requires free API key) |
| [AbuseIPDB](https://www.abuseipdb.com/) | IP reputation and abuse reports (optional, requires free API key) |
| [Shodan](https://www.shodan.io/) | Internet-wide host and port intelligence (optional, requires free API key) |

Threat feed articles are aggregated from: CrowdStrike, BleepingComputer, The Hacker News, Cisco Talos, Unit 42 (Palo Alto), SentinelOne Labs, Microsoft Security, Recorded Future, Proofpoint, Krebs on Security, Red Canary, Volexity, Elastic Security Labs, WeLiveSecurity (ESET), GuidePoint Security, Huntress, and Google Threat Intelligence.
