import "dotenv/config";
import { ensureRepo } from "./utils/git-clone";
import { execSync } from "child_process";
import { join } from "path";

const SCRIPTS_DIR = __dirname;

const REPOS = [
  { url: "https://github.com/mitre/cti.git", name: "cti" },
  { url: "https://github.com/redcanaryco/atomic-red-team.git", name: "atomic-red-team" },
  { url: "https://github.com/SigmaHQ/sigma.git", name: "sigma" },
  { url: "https://github.com/leostat/rtfm.git", name: "rtfm" },
  { url: "https://github.com/Yara-Rules/rules.git", name: "yara-rules" },
  { url: "https://github.com/Neo23x0/signature-base.git", name: "signature-base" },
  { url: "https://github.com/reversinglabs/reversinglabs-yara-rules.git", name: "reversinglabs-yara" },
];

function runScript(name: string) {
  const scriptPath = join(SCRIPTS_DIR, name);
  console.log(`\n${"=".repeat(60)}\nRunning ${name}...\n${"=".repeat(60)}`);
  execSync(`npx tsx "${scriptPath}"`, {
    cwd: join(SCRIPTS_DIR, ".."),
    stdio: "inherit",
    timeout: 600_000,
    env: { ...process.env },
  });
}

async function main() {
  console.log("=== TI-Rex — Full Update ===\n");
  const start = Date.now();

  console.log("Step 1: Cloning / updating data repos...");
  for (const repo of REPOS) {
    try {
      ensureRepo(repo.url, repo.name);
    } catch (err) {
      console.error(`  Failed to clone/pull ${repo.name}:`, err);
    }
  }

  console.log("\nStep 2: MITRE ATT&CK ingestion...");
  runScript("ingest-mitre.ts");

  console.log("\nStep 3: Atomic Red Team ingestion...");
  runScript("ingest-atomic.ts");

  console.log("\nStep 4: CISA KEV ingestion...");
  runScript("ingest-kev.ts");

  console.log("\nStep 5: Seeding categories...");
  runScript("seed-categories.ts");

  console.log("\nStep 6: Applying category rules...");
  runScript("apply-categories.ts");

  console.log("\nStep 7: Seeding detection rules...");
  runScript("seed-detections.ts");

  console.log("\nStep 8: APT country attributions...");
  runScript("seed-apt-countries.ts");

  console.log("\nStep 9: Seeding IOCs...");
  runScript("seed-iocs.ts");

  console.log("\nStep 10: Auto-attribute countries from STIX...");
  runScript("auto-attribute-countries.ts");

  console.log("\nStep 11: OTX threat intel...");
  try { runScript("ingest-otx.ts"); } catch { console.log("  OTX ingestion skipped or failed"); }

  console.log("\nStep 12: Malpedia enrichment...");
  try { runScript("ingest-malpedia.ts"); } catch { console.log("  Malpedia enrichment skipped or failed"); }

  console.log("\nStep 13: Actor-malware relationships...");
  runScript("ingest-actor-malware.ts");

  console.log("\nStep 14: Malware classification...");
  runScript("classify-malware.ts");

  console.log("\nStep 15: C2 framework profiles...");
  try { runScript("seed-c2-profiles.ts"); } catch { console.log("  C2 profiles skipped or failed"); }

  console.log("\nStep 16: YARA rule library...");
  try { runScript("seed-yara-rules.ts"); } catch { console.log("  YARA rules skipped or failed"); }

  console.log("\nStep 17: Threat feeds...");
  try { runScript("ingest-feeds.ts"); } catch { console.log("  Feed ingestion skipped or failed"); }

  console.log("\nStep 18: APT report collection (blackorbird)...");
  try { runScript("ingest-apt-report.ts"); } catch { console.log("  APT report ingestion skipped or failed"); }

  console.log("\nStep 19: ThreatFox IOC feed (abuse.ch)...");
  try { runScript("ingest-threatfox.ts"); } catch { console.log("  ThreatFox ingestion skipped or failed"); }

  console.log("\nStep 20: Feodo Tracker C2 feed (abuse.ch)...");
  try { runScript("ingest-feodo.ts"); } catch { console.log("  Feodo Tracker ingestion skipped or failed"); }

  console.log("\nStep 21: URLhaus malicious URLs (abuse.ch)...");
  try { runScript("ingest-urlhaus.ts"); } catch { console.log("  URLhaus ingestion skipped or failed"); }

  console.log("\nStep 22: SigmaHQ detection rules...");
  try { runScript("ingest-sigma.ts"); } catch { console.log("  SigmaHQ ingestion skipped or failed"); }

  console.log("\nStep 23: RTFM offensive commands...");
  try { runScript("ingest-rtfm.ts"); } catch { console.log("  RTFM ingestion skipped or failed"); }

  console.log("\nStep 24: YARA-Rules community rules...");
  try { runScript("ingest-yara-rules.ts"); } catch { console.log("  YARA-Rules ingestion skipped or failed"); }

  console.log("\nStep 25: IOC retention pruning...");
  try { runScript("prune-iocs.ts"); } catch { console.log("  IOC pruning skipped or failed"); }

  console.log("\nStep 26: EPSS score ingestion...");
  try { runScript("ingest-epss.ts"); } catch { console.log("  EPSS ingestion skipped or failed"); }

  console.log("\nStep 27: NVD CVSS enrichment...");
  try { runScript("ingest-nvd.ts"); } catch { console.log("  NVD enrichment skipped or failed"); }

  console.log("\nStep 28: Actor-CVE linking...");
  try { runScript("link-actor-cves.ts"); } catch { console.log("  Actor-CVE linking skipped or failed"); }

  console.log("\nStep 29: Watchlist IOC matching...");
  try { runScript("watchlist-match.ts"); } catch { console.log("  Watchlist matching skipped or failed"); }

  console.log("\nStep 30: Pruning old NVD CVEs...");
  try { runScript("prune-old-cves.ts"); } catch { console.log("  CVE pruning skipped or failed"); }

  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  console.log(`\n=== Full update complete in ${elapsed}s ===`);
}

main().catch(console.error);
