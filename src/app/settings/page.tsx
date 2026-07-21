import { prisma } from "@/lib/db";
import { requireAuth } from "@/lib/auth";
import { UpdateButton } from "@/components/settings/UpdateButton";
import { AutoRefresh } from "@/components/settings/AutoRefresh";
import { getAutoRefreshConfig, getIocRetentionConfig } from "@/actions/settings";
import { IocRetention } from "@/components/settings/IocRetention";
import { UserManagement } from "@/components/settings/UserManagement";

export default async function SettingsPage() {
  const currentUser = await requireAuth();
  const isAdmin = currentUser.role === "ADMIN";

  const users = isAdmin
    ? await prisma.user.findMany({
        select: { id: true, email: true, name: true, role: true, createdAt: true },
        orderBy: { createdAt: "asc" },
      })
    : [];

  const counts = await Promise.all([
    prisma.tactic.count(),
    prisma.technique.count(),
    prisma.threatActor.count(),
    prisma.malware.count(),
    prisma.tool.count(),
    prisma.campaign.count(),
    prisma.procedure.count(),
    prisma.atomicTest.count(),
    prisma.advisory.count(),
    prisma.iOC.count(),
    prisma.category.count(),
    prisma.detectionRule.count(),
    prisma.feedItem.count(),
    prisma.offensiveCommand.count(),
  ]);

  const labels = [
    "Tactics", "Techniques", "Threat Actors", "Malware", "Tools",
    "Campaigns", "Procedures", "Atomic Tests", "Advisories", "IOCs", "Categories",
    "Detection Rules", "Feed Items", "Offensive Commands",
  ];

  const DATA_SOURCES = [
    { name: "MITRE ATT&CK", type: "live", method: "Git pull", desc: "Techniques, tactics, actors, malware, campaigns, procedures" },
    { name: "Atomic Red Team", type: "live", method: "Git pull", desc: "1,800+ attack simulation tests with real commands" },
    { name: "CISA KEV", type: "live", method: "JSON API", desc: "Known exploited vulnerabilities with ransomware tagging" },
    { name: "ThreatFox (abuse.ch)", type: "live", method: "JSON export", desc: "Live IOCs — IPs, domains, URLs, hashes by malware family" },
    { name: "Feodo Tracker (abuse.ch)", type: "live", method: "JSON API", desc: "Active botnet C2 servers — Dridex, Emotet, TrickBot, QakBot" },
    { name: "URLhaus (abuse.ch)", type: "live", method: "JSON export", desc: "Malicious URLs used for malware distribution" },
    { name: "SigmaHQ", type: "live", method: "Git pull", desc: "Community Sigma detection rules (3,000+)" },
    { name: "AlienVault OTX", type: "live", method: "REST API", desc: "IOCs from subscribed pulses and APT searches (needs OTX_API_KEY)" },
    { name: "Malpedia", type: "live", method: "REST API", desc: "Malware family enrichment and actor country data" },
    { name: "Threat Feeds (RSS)", type: "live", method: "RSS/Atom", desc: "17 vendor blogs — CrowdStrike, Talos, Unit 42, SentinelOne, Huntress, Google TI, etc." },
    { name: "Ransomware Groups", type: "seed", method: "Static seed", desc: "52 ransomware groups with detailed profiles" },
    { name: "C2 Framework Profiles", type: "seed", method: "Static seed", desc: "25 C2 frameworks — Cobalt Strike, Sliver, Havoc, etc." },
    { name: "YARA Rule Library", type: "seed", method: "Static seed", desc: "47 curated YARA rules mapped to malware families" },
    { name: "YARA-Rules Community", type: "live", method: "Git pull", desc: "3,200+ community YARA rules (YARA-Rules/rules)" },
    { name: "Neo23x0 Signature Base", type: "live", method: "Git pull", desc: "5,700+ YARA rules — APT, crimeware, exploits, webshells (Florian Roth)" },
    { name: "ReversingLabs YARA", type: "live", method: "Git pull", desc: "1,200+ YARA rules — ransomware, backdoors, trojans (MIT)" },
    { name: "RTFM (leostat)", type: "live", method: "Git pull", desc: "500+ red team commands with tags, references, and technique mapping" },
  ];

  const autoRefreshConfig = await getAutoRefreshConfig();
  const iocRetentionConfig = await getIocRetentionConfig();

  const updates = await prisma.updateLog.findMany({
    orderBy: { startedAt: "desc" },
    take: 20,
  });

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-sm text-[var(--text-secondary)]">Database stats and update management</p>
      </div>

      {isAdmin && (
        <UserManagement
          users={users.map((u) => ({ ...u, createdAt: u.createdAt.toISOString() }))}
          currentUserId={currentUser.id}
        />
      )}

      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Database Statistics</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {labels.map((label, i) => (
            <div key={label} className="p-3 bg-[var(--bg-tertiary)] rounded-lg">
              <div className="text-xl font-bold">{counts[i].toLocaleString()}</div>
              <div className="text-xs text-[var(--text-secondary)]">{label}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Data Sources</h2>
        <p className="text-sm text-[var(--text-secondary)] mb-4">
          {DATA_SOURCES.filter(s => s.type === "live").length} live feeds updated automatically on each refresh.
          {" "}{DATA_SOURCES.filter(s => s.type === "seed").length} static seed sources.
        </p>
        <div className="space-y-2">
          {DATA_SOURCES.map((src) => (
            <div key={src.name} className="flex items-start gap-3 p-2.5 bg-[var(--bg-tertiary)] rounded-lg">
              <span className={`badge shrink-0 mt-0.5 ${
                src.type === "live"
                  ? "bg-green-900/50 text-green-400"
                  : "bg-zinc-800 text-zinc-400"
              }`}>
                {src.type === "live" ? "LIVE" : "SEED"}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">{src.name}</span>
                  <span className="text-[10px] text-[var(--text-secondary)]">{src.method}</span>
                </div>
                <p className="text-xs text-[var(--text-secondary)] mt-0.5">{src.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-2">Update Data</h2>
        <p className="text-sm text-[var(--text-secondary)] mb-4">
          Runs the full 25-step update pipeline: pulls MITRE ATT&CK, Atomic Red Team, SigmaHQ, RTFM, and YARA-Rules repos,
          fetches CISA KEV, ThreatFox IOCs, Feodo Tracker C2s, URLhaus URLs, OTX pulses, Malpedia data,
          threat feeds, and applies all categorization rules.
        </p>
        <UpdateButton />
        <details className="mt-4">
          <summary className="text-xs text-[var(--text-secondary)] cursor-pointer hover:text-[var(--text-primary)] transition-colors">
            CLI &amp; API alternatives
          </summary>
          <div className="mt-3 space-y-2">
            <p className="text-xs text-[var(--text-secondary)]">Run from the terminal:</p>
            <pre className="code-block">npx tsx scripts/update-all.ts</pre>
            <p className="text-xs text-[var(--text-secondary)] mt-2">Or trigger via HTTP POST:</p>
            <pre className="code-block">curl -X POST http://localhost:3000/api/update</pre>
          </div>
        </details>
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-2">Auto-Refresh</h2>
        <p className="text-sm text-[var(--text-secondary)] mb-4">
          Automatically refresh threat intelligence data on a schedule.
          When enabled, the dashboard will trigger an update when the configured interval has elapsed.
        </p>
        <AutoRefresh
          initialHours={autoRefreshConfig.hours}
          initialLastUpdate={autoRefreshConfig.lastUpdate}
        />
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-2">IOC Retention</h2>
        <p className="text-sm text-[var(--text-secondary)] mb-4">
          Automatically prune stale IOCs older than the retention window to keep the database lean.
          Advisory-linked IOCs (CISA KEV) are always preserved.
        </p>
        <IocRetention
          initialDays={iocRetentionConfig.days}
          lastPruned={iocRetentionConfig.lastPruned}
          lastPrunedCount={iocRetentionConfig.lastPrunedCount}
          currentIocCount={counts[9]}
        />
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Update History</h2>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-[var(--text-secondary)] text-xs">
              <th className="pb-2">Source</th>
              <th className="pb-2">Status</th>
              <th className="pb-2">Records</th>
              <th className="pb-2">Started</th>
              <th className="pb-2">Completed</th>
              <th className="pb-2">Error</th>
            </tr>
          </thead>
          <tbody>
            {updates.map((u) => (
              <tr key={u.id} className="table-row">
                <td className="py-2">{u.source}</td>
                <td className="py-2">
                  <span className={`badge ${
                    u.status === "success" ? "bg-green-900/50 text-green-400" :
                    u.status === "error" ? "bg-red-900/50 text-red-400" :
                    "bg-yellow-900/50 text-yellow-400"
                  }`}>
                    {u.status}
                  </span>
                </td>
                <td className="py-2">{u.recordsProcessed.toLocaleString()}</td>
                <td className="py-2 text-[var(--text-secondary)]">{u.startedAt.toLocaleString()}</td>
                <td className="py-2 text-[var(--text-secondary)]">{u.completedAt?.toLocaleString() ?? "—"}</td>
                <td className="py-2 text-red-400 text-xs truncate max-w-xs">{u.errorMessage ?? ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
