type ActorReport = {
  reportType: "actor";
  generatedAt: string;
  actor: {
    externalId: string;
    name: string;
    aliases: string[];
    country: string | null;
    description: string | null;
    motivations: string[];
    url: string | null;
    categories: { slug: string; name: string }[];
  };
  techniques: {
    externalId: string;
    name: string;
    count: number;
    tactics: string[];
    hasTests: boolean;
    hasDetections: boolean;
  }[];
  malware: { externalId: string; name: string; type: string | null }[];
  campaigns: { name: string; description: string | null; firstSeen: string | null; lastSeen: string | null }[];
  atomicTests: { name: string; executor: string; platforms: string[]; technique: { externalId: string } }[];
  detectionRules: { name: string; language: string; severity: string | null; technique: { externalId: string } | null }[];
  coverage: {
    totalTechniques: number;
    techniquesWithTests: number;
    techniquesWithDetections: number;
    detectionCoverage: number;
    testCoverage: number;
  };
};

type MalwareReport = {
  reportType: "malware";
  generatedAt: string;
  malware: {
    externalId: string;
    name: string;
    aliases: string[];
    description: string | null;
    type: string | null;
    platforms: string[];
    url: string | null;
  };
  techniques: {
    externalId: string;
    name: string;
    tactics: string[];
    hasTests: boolean;
    hasDetections: boolean;
  }[];
  actors: { externalId: string; name: string; country: string | null }[];
  atomicTests: { name: string; executor: string; platforms: string[]; technique: { externalId: string } }[];
  detectionRules: { name: string; language: string; severity: string | null; technique: { externalId: string } | null }[];
  coverage: {
    totalTechniques: number;
    techniquesWithTests: number;
    techniquesWithDetections: number;
    detectionCoverage: number;
    testCoverage: number;
  };
};

type TechniqueReport = {
  reportType: "technique";
  generatedAt: string;
  technique: {
    externalId: string;
    name: string;
    description: string | null;
    platforms: string[];
    dataSources: string[];
    detection: string | null;
    isSubtechnique: boolean;
    url: string | null;
    parent: { externalId: string; name: string } | null;
    children: { externalId: string; name: string }[];
    tactics: { name: string; shortName: string }[];
    categories: { name: string }[];
  };
  procedures: {
    description: string | null;
    actor: { name: string } | null;
    malware: { name: string } | null;
    tool: { name: string } | null;
    campaign: { name: string } | null;
  }[];
  atomicTests: { name: string; executor: string; platforms: string[]; elevationRequired: boolean }[];
  detectionRules: { name: string; language: string; severity: string | null }[];
  coverage: { procedureCount: number; atomicTestCount: number; detectionRuleCount: number };
};

type CategoryReport = {
  reportType: "category";
  generatedAt: string;
  category: { slug: string; name: string; description: string | null };
  techniques: {
    externalId: string;
    name: string;
    isSubtechnique: boolean;
    procedureCount: number;
    atomicTestCount: number;
    detectionCount: number;
  }[];
  actors: { externalId: string; name: string; country: string | null; procedureCount: number }[];
  coverage: {
    totalTechniques: number;
    techniquesWithTests: number;
    techniquesWithDetections: number;
    techniquesWithoutDetections: number;
    detectionCoverage: number;
    testCoverage: number;
  };
};

type ReportData = ActorReport | MalwareReport | TechniqueReport | CategoryReport;

function bar(pct: number): string {
  const filled = Math.round(pct / 5);
  return `[${"#".repeat(filled)}${"-".repeat(20 - filled)}] ${pct}%`;
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
}

function actorMarkdown(data: ActorReport): string {
  const { actor, techniques, malware, campaigns, detectionRules, coverage } = data;
  const gaps = techniques.filter((t) => !t.hasDetections);

  let md = `# Threat Intelligence Report: ${actor.name}\n\n`;
  md += `**Report Type:** Threat Actor | **Generated:** ${formatDate(data.generatedAt)} | **Classification:** UNCLASSIFIED\n\n`;
  md += `---\n\n`;

  md += `## Executive Summary\n\n`;
  md += `| Field | Value |\n|-------|-------|\n`;
  md += `| MITRE ID | ${actor.externalId} |\n`;
  if (actor.country) md += `| Country | ${actor.country} |\n`;
  if (actor.motivations.length > 0) md += `| Motivations | ${actor.motivations.join(", ")} |\n`;
  if (actor.aliases.length > 0) md += `| Aliases | ${actor.aliases.join(", ")} |\n`;
  if (actor.categories.length > 0) md += `| Categories | ${actor.categories.map((c) => c.name).join(", ")} |\n`;
  if (actor.url) md += `| Reference | ${actor.url} |\n`;
  md += `\n`;
  if (actor.description) md += `> ${actor.description.replace(/\n/g, "\n> ")}\n\n`;

  md += `## Coverage Assessment\n\n`;
  md += `| Metric | Value |\n|--------|-------|\n`;
  md += `| Total Techniques | ${coverage.totalTechniques} |\n`;
  md += `| Malware Tools | ${malware.length} |\n`;
  md += `| Campaigns | ${campaigns.length} |\n`;
  md += `| Detection Coverage | ${coverage.detectionCoverage}% |\n`;
  md += `| Test Coverage | ${coverage.testCoverage}% |\n\n`;
  md += `**Detection Coverage:** ${bar(coverage.detectionCoverage)}\n`;
  md += `**Test Coverage:**      ${bar(coverage.testCoverage)}\n\n`;

  md += `## Techniques Used (${techniques.length})\n\n`;
  md += `| ID | Name | Tactics | Tests | Detections |\n`;
  md += `|----|------|---------|-------|------------|\n`;
  for (const t of techniques) {
    md += `| ${t.externalId} | ${t.name} | ${t.tactics.join(", ")} | ${t.hasTests ? "Yes" : "No"} | ${t.hasDetections ? "Yes" : "**GAP**"} |\n`;
  }
  md += `\n`;

  if (malware.length > 0) {
    md += `## Associated Malware (${malware.length})\n\n`;
    md += `| ID | Name | Type |\n|----|------|------|\n`;
    for (const m of malware) md += `| ${m.externalId} | ${m.name} | ${m.type ?? "—"} |\n`;
    md += `\n`;
  }

  if (campaigns.length > 0) {
    md += `## Campaigns (${campaigns.length})\n\n`;
    for (const c of campaigns) {
      md += `### ${c.name}\n`;
      if (c.firstSeen || c.lastSeen) md += `*${c.firstSeen ? formatDate(c.firstSeen) : "?"} — ${c.lastSeen ? formatDate(c.lastSeen) : "ongoing"}*\n\n`;
      if (c.description) md += `${c.description.slice(0, 500)}\n\n`;
    }
  }

  if (gaps.length > 0) {
    md += `## Detection Gaps (${gaps.length})\n\n`;
    md += `The following techniques have no associated detection rules:\n\n`;
    for (const t of gaps) md += `- [ ] **${t.externalId}** — ${t.name} (${t.tactics.join(", ")})\n`;
    md += `\n`;
  }

  if (detectionRules.length > 0) {
    md += `## Detection Rules (${detectionRules.length})\n\n`;
    md += `| Rule | Technique | Language | Severity |\n|------|-----------|----------|----------|\n`;
    for (const r of detectionRules) {
      md += `| ${r.name} | ${r.technique?.externalId ?? "—"} | ${r.language} | ${r.severity ?? "—"} |\n`;
    }
    md += `\n`;
  }

  md += `## Recommendations\n\n`;
  if (coverage.detectionCoverage < 50) md += `- **PRIORITY:** Detection coverage is below 50%. Create SIEM rules for uncovered techniques.\n`;
  if (coverage.testCoverage < 50) md += `- **WARNING:** Less than 50% of techniques have atomic tests. Run Atomic Red Team exercises.\n`;
  if (gaps.length > 0) md += `- ${gaps.length} techniques lack detection rules. See Detection Gaps section.\n`;
  md += `- Monitor threat intel feeds for new campaigns attributed to ${actor.name}.\n`;
  if (actor.url) md += `- Review MITRE ATT&CK page: ${actor.url}\n`;
  md += `\n`;

  md += `## Appendix: Technique IDs\n\n`;
  md += `\`${techniques.map((t) => t.externalId).join("`, `")}\`\n`;

  return md;
}

function malwareMarkdown(data: MalwareReport): string {
  const { malware, techniques, actors, detectionRules, coverage } = data;
  const gaps = techniques.filter((t) => !t.hasDetections);

  let md = `# Threat Intelligence Report: ${malware.name}\n\n`;
  md += `**Report Type:** Malware | **Generated:** ${formatDate(data.generatedAt)} | **Classification:** UNCLASSIFIED\n\n`;
  md += `---\n\n`;

  md += `## Executive Summary\n\n`;
  md += `| Field | Value |\n|-------|-------|\n`;
  md += `| MITRE ID | ${malware.externalId} |\n`;
  if (malware.type) md += `| Type | ${malware.type} |\n`;
  if (malware.platforms.length > 0) md += `| Platforms | ${malware.platforms.join(", ")} |\n`;
  if (malware.aliases.length > 0) md += `| Aliases | ${malware.aliases.join(", ")} |\n`;
  if (malware.url) md += `| Reference | ${malware.url} |\n`;
  md += `\n`;
  if (malware.description) md += `> ${malware.description.replace(/\n/g, "\n> ")}\n\n`;

  md += `## Coverage Assessment\n\n`;
  md += `| Metric | Value |\n|--------|-------|\n`;
  md += `| Total Techniques | ${coverage.totalTechniques} |\n`;
  md += `| Associated Actors | ${actors.length} |\n`;
  md += `| Detection Coverage | ${coverage.detectionCoverage}% |\n`;
  md += `| Test Coverage | ${coverage.testCoverage}% |\n\n`;
  md += `**Detection Coverage:** ${bar(coverage.detectionCoverage)}\n`;
  md += `**Test Coverage:**      ${bar(coverage.testCoverage)}\n\n`;

  md += `## Techniques Used (${techniques.length})\n\n`;
  md += `| ID | Name | Tactics | Tests | Detections |\n`;
  md += `|----|------|---------|-------|------------|\n`;
  for (const t of techniques) {
    md += `| ${t.externalId} | ${t.name} | ${t.tactics.join(", ")} | ${t.hasTests ? "Yes" : "No"} | ${t.hasDetections ? "Yes" : "**GAP**"} |\n`;
  }
  md += `\n`;

  if (actors.length > 0) {
    md += `## Associated Threat Actors (${actors.length})\n\n`;
    md += `| ID | Name | Country |\n|----|------|----------|\n`;
    for (const a of actors) md += `| ${a.externalId} | ${a.name} | ${a.country ?? "—"} |\n`;
    md += `\n`;
  }

  if (gaps.length > 0) {
    md += `## Detection Gaps (${gaps.length})\n\n`;
    for (const t of gaps) md += `- [ ] **${t.externalId}** — ${t.name}\n`;
    md += `\n`;
  }

  if (detectionRules.length > 0) {
    md += `## Detection Rules (${detectionRules.length})\n\n`;
    md += `| Rule | Technique | Language | Severity |\n|------|-----------|----------|----------|\n`;
    for (const r of detectionRules) {
      md += `| ${r.name} | ${r.technique?.externalId ?? "—"} | ${r.language} | ${r.severity ?? "—"} |\n`;
    }
    md += `\n`;
  }

  md += `## Recommendations\n\n`;
  if (gaps.length > 0) md += `- **PRIORITY:** ${gaps.length} techniques lack detection rules.\n`;
  if (malware.url) md += `- Review MITRE ATT&CK page: ${malware.url}\n`;
  md += `\n`;

  md += `## Appendix: Technique IDs\n\n`;
  md += `\`${techniques.map((t) => t.externalId).join("`, `")}\`\n`;

  return md;
}

function techniqueMarkdown(data: TechniqueReport): string {
  const { technique, procedures, atomicTests, detectionRules, coverage } = data;

  let md = `# Threat Intelligence Report: ${technique.externalId} — ${technique.name}\n\n`;
  md += `**Report Type:** Technique | **Generated:** ${formatDate(data.generatedAt)} | **Classification:** UNCLASSIFIED\n\n`;
  md += `---\n\n`;

  md += `## Executive Summary\n\n`;
  md += `| Field | Value |\n|-------|-------|\n`;
  md += `| MITRE ID | ${technique.externalId} |\n`;
  md += `| Tactics | ${technique.tactics.map((t) => t.name).join(", ")} |\n`;
  md += `| Platforms | ${technique.platforms.join(", ")} |\n`;
  if (technique.isSubtechnique) md += `| Type | Sub-technique |\n`;
  if (technique.parent) md += `| Parent | ${technique.parent.externalId} — ${technique.parent.name} |\n`;
  if (technique.categories.length > 0) md += `| Categories | ${technique.categories.map((c) => c.name).join(", ")} |\n`;
  if (technique.dataSources.length > 0) md += `| Data Sources | ${technique.dataSources.join(", ")} |\n`;
  if (technique.url) md += `| Reference | ${technique.url} |\n`;
  md += `\n`;
  if (technique.description) md += `> ${technique.description.slice(0, 1000).replace(/\n/g, "\n> ")}\n\n`;

  md += `## Stats\n\n`;
  md += `| Metric | Value |\n|--------|-------|\n`;
  md += `| Procedures | ${coverage.procedureCount} |\n`;
  md += `| Atomic Tests | ${coverage.atomicTestCount} |\n`;
  md += `| Detection Rules | ${coverage.detectionRuleCount} |\n\n`;

  if (technique.detection) {
    md += `## Detection Guidance\n\n`;
    md += `${technique.detection}\n\n`;
  }

  if (technique.children.length > 0) {
    md += `## Sub-Techniques (${technique.children.length})\n\n`;
    for (const c of technique.children) md += `- **${c.externalId}** — ${c.name}\n`;
    md += `\n`;
  }

  if (procedures.length > 0) {
    md += `## Who Uses This (${procedures.length})\n\n`;
    for (const p of procedures.slice(0, 50)) {
      const source = p.actor?.name ?? p.malware?.name ?? p.tool?.name ?? p.campaign?.name ?? "Unknown";
      md += `- **${source}**: ${p.description?.slice(0, 200) ?? "—"}\n`;
    }
    md += `\n`;
  }

  if (atomicTests.length > 0) {
    md += `## Atomic Tests (${atomicTests.length})\n\n`;
    md += `| Name | Executor | Platforms | Elevated |\n|------|----------|-----------|----------|\n`;
    for (const t of atomicTests) {
      md += `| ${t.name} | ${t.executor} | ${t.platforms.join(", ")} | ${t.elevationRequired ? "Yes" : "No"} |\n`;
    }
    md += `\n`;
  }

  if (detectionRules.length > 0) {
    md += `## Detection Rules (${detectionRules.length})\n\n`;
    md += `| Rule | Language | Severity |\n|------|----------|----------|\n`;
    for (const r of detectionRules) {
      md += `| ${r.name} | ${r.language} | ${r.severity ?? "—"} |\n`;
    }
    md += `\n`;
  }

  md += `## Recommendations\n\n`;
  if (coverage.detectionRuleCount === 0) md += `- **PRIORITY:** No detection rules exist. Creating SIEM detections should be a priority.\n`;
  if (coverage.atomicTestCount === 0) md += `- **WARNING:** No atomic tests linked. Develop custom red team exercises.\n`;
  if (technique.url) md += `- Review MITRE ATT&CK page: ${technique.url}\n`;
  md += `\n`;

  return md;
}

function categoryMarkdown(data: CategoryReport): string {
  const { category, techniques, actors, coverage } = data;
  const gaps = techniques.filter((t) => t.detectionCount === 0);

  let md = `# Threat Intelligence Report: ${category.name} Category\n\n`;
  md += `**Report Type:** Category | **Generated:** ${formatDate(data.generatedAt)} | **Classification:** UNCLASSIFIED\n\n`;
  md += `---\n\n`;

  md += `## Executive Summary\n\n`;
  if (category.description) md += `> ${category.description}\n\n`;

  md += `## Coverage Assessment\n\n`;
  md += `| Metric | Value |\n|--------|-------|\n`;
  md += `| Total Techniques | ${coverage.totalTechniques} |\n`;
  md += `| Threat Actors | ${actors.length} |\n`;
  md += `| With Detection Rules | ${coverage.techniquesWithDetections} |\n`;
  md += `| With Atomic Tests | ${coverage.techniquesWithTests} |\n`;
  md += `| Without Detections | ${coverage.techniquesWithoutDetections} |\n\n`;
  md += `**Detection Coverage:** ${bar(coverage.detectionCoverage)}\n`;
  md += `**Test Coverage:**      ${bar(coverage.testCoverage)}\n\n`;

  md += `## Techniques (${techniques.length})\n\n`;
  md += `| ID | Name | Procedures | Tests | Detections |\n`;
  md += `|----|------|------------|-------|------------|\n`;
  for (const t of techniques) {
    md += `| ${t.externalId} | ${t.name} | ${t.procedureCount} | ${t.atomicTestCount > 0 ? "Yes" : "No"} | ${t.detectionCount > 0 ? "Yes" : "**GAP**"} |\n`;
  }
  md += `\n`;

  if (actors.length > 0) {
    md += `## Threat Actors (${actors.length})\n\n`;
    md += `| ID | Name | Country | Procedures |\n|----|------|---------|------------|\n`;
    for (const a of actors) md += `| ${a.externalId} | ${a.name} | ${a.country ?? "—"} | ${a.procedureCount} |\n`;
    md += `\n`;
  }

  if (gaps.length > 0) {
    md += `## Detection Gaps (${gaps.length})\n\n`;
    for (const t of gaps) md += `- [ ] **${t.externalId}** — ${t.name} (${t.procedureCount} procedures)\n`;
    md += `\n`;
  }

  md += `## Recommendations\n\n`;
  if (coverage.detectionCoverage < 50) md += `- **PRIORITY:** Detection coverage below 50%. Focus on high-procedure-count techniques.\n`;
  if (coverage.testCoverage < 50) md += `- **WARNING:** Less than half of techniques have atomic tests.\n`;
  md += `- Sort by procedure count and prioritize detection rule creation for high-frequency techniques.\n`;
  md += `\n`;

  return md;
}

export function reportToMarkdown(data: ReportData): string {
  switch (data.reportType) {
    case "actor":
      return actorMarkdown(data as ActorReport);
    case "malware":
      return malwareMarkdown(data as MalwareReport);
    case "technique":
      return techniqueMarkdown(data as TechniqueReport);
    case "category":
      return categoryMarkdown(data as CategoryReport);
    default:
      return `# Report\n\nUnsupported report type.\n`;
  }
}
