import "dotenv/config";
import { ensureRepo } from "./utils/git-clone";
import { execSync } from "child_process";
import { join } from "path";

const FAST_MODE = process.argv.includes("--fast");
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

// Scripts that hit rate-limited external APIs and take minutes to complete.
// Skipped in --fast mode (first install) — the scheduler backfills them automatically.
const SLOW_SCRIPTS = new Set([
  "ingest-malpedia.ts",
  "ingest-nvd.ts",
  "ingest-supply-chain.ts",
]);

function tryRun(name: string, label: string) {
  if (FAST_MODE && SLOW_SCRIPTS.has(name)) {
    console.log(`  Skipped (--fast) — will run on next scheduled update`);
    return;
  }
  try {
    runScript(name);
  } catch {
    console.log(`  ${label} skipped or failed`);
  }
}

async function main() {
  console.log(`=== TI-Rex — ${FAST_MODE ? "Quick Install" : "Full Update"} ===\n`);
  if (FAST_MODE) {
    console.log("Fast mode: skipping slow API enrichment (Malpedia, NVD, Supply Chain).");
    console.log("These will run automatically on the first scheduled update.\n");
  }
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
  tryRun("ingest-otx.ts", "OTX ingestion");

  console.log("\nStep 12: Malpedia enrichment...");
  tryRun("ingest-malpedia.ts", "Malpedia enrichment");

  console.log("\nStep 13: Actor-malware relationships...");
  runScript("ingest-actor-malware.ts");

  console.log("\nStep 14: Malware classification...");
  runScript("classify-malware.ts");

  console.log("\nStep 15: C2 framework profiles...");
  tryRun("seed-c2-profiles.ts", "C2 profiles");

  console.log("\nStep 16: YARA rule library...");
  tryRun("seed-yara-rules.ts", "YARA rules");

  console.log("\nStep 17: Threat feeds...");
  tryRun("ingest-feeds.ts", "Feed ingestion");

  console.log("\nStep 18: APT report collection (blackorbird)...");
  tryRun("ingest-apt-report.ts", "APT report ingestion");

  console.log("\nStep 19: ThreatFox IOC feed (abuse.ch)...");
  tryRun("ingest-threatfox.ts", "ThreatFox ingestion");

  console.log("\nStep 20: Feodo Tracker C2 feed (abuse.ch)...");
  tryRun("ingest-feodo.ts", "Feodo Tracker ingestion");

  console.log("\nStep 21: URLhaus malicious URLs (abuse.ch)...");
  tryRun("ingest-urlhaus.ts", "URLhaus ingestion");

  console.log("\nStep 22: SigmaHQ detection rules...");
  tryRun("ingest-sigma.ts", "SigmaHQ ingestion");

  console.log("\nStep 23: RTFM offensive commands...");
  tryRun("ingest-rtfm.ts", "RTFM ingestion");

  console.log("\nStep 24: YARA-Rules community rules...");
  tryRun("ingest-yara-rules.ts", "YARA-Rules ingestion");

  console.log("\nStep 25: IOC retention pruning...");
  tryRun("prune-iocs.ts", "IOC pruning");

  console.log("\nStep 26: EPSS score ingestion...");
  tryRun("ingest-epss.ts", "EPSS ingestion");

  console.log("\nStep 27: NVD CVSS enrichment...");
  tryRun("ingest-nvd.ts", "NVD enrichment");

  console.log("\nStep 28: Actor-CVE linking...");
  tryRun("link-actor-cves.ts", "Actor-CVE linking");

  console.log("\nStep 29: Watchlist IOC matching...");
  tryRun("watchlist-match.ts", "Watchlist matching");

  console.log("\nStep 30: Supply chain advisory tracking...");
  tryRun("ingest-supply-chain.ts", "Supply chain ingestion");

  console.log("\nStep 31: Pruning old NVD CVEs...");
  tryRun("prune-old-cves.ts", "CVE pruning");

  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  console.log(`\n=== ${FAST_MODE ? "Quick install" : "Full update"} complete in ${elapsed}s ===`);
  if (FAST_MODE) {
    console.log("Remaining enrichment (Malpedia, NVD, Supply Chain) will run on the first scheduled update.");
  }
}

main().catch(console.error);
