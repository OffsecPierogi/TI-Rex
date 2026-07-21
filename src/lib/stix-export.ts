import * as crypto from "crypto";

const STIX_NAMESPACE = "threat-intel-dashboard";

function deterministicUuid(input: string): string {
  const hash = crypto.createHash("md5").update(input).digest("hex");
  return [
    hash.slice(0, 8),
    hash.slice(8, 12),
    "5" + hash.slice(13, 16),
    ((parseInt(hash.slice(16, 18), 16) & 0x3f) | 0x80).toString(16).padStart(2, "0") + hash.slice(18, 20),
    hash.slice(20, 32),
  ].join("-");
}

function stixId(type: string, entityStixId: string | null | undefined, fallback: string): string {
  if (entityStixId && entityStixId.startsWith(type + "--")) return entityStixId;
  if (entityStixId && entityStixId.includes("--")) return `${type}--${entityStixId.split("--")[1]}`;
  return `${type}--${deterministicUuid(STIX_NAMESPACE + ":" + fallback)}`;
}

function parseJsonField(val: string | null | undefined): string[] {
  if (!val) return [];
  try {
    return JSON.parse(val);
  } catch {
    return [];
  }
}

function buildExternalRef(externalId: string, url: string | null | undefined) {
  const ref: Record<string, string> = { source_name: "mitre-attack", external_id: externalId };
  if (url) ref.url = url;
  return ref;
}

export function sourceIdentity() {
  return {
    type: "identity" as const,
    spec_version: "2.1" as const,
    id: `identity--${deterministicUuid(STIX_NAMESPACE + ":source")}`,
    name: "TI-Rex",
    identity_class: "system",
    created: new Date().toISOString(),
    modified: new Date().toISOString(),
  };
}

interface ActorInput {
  id: string;
  stixId: string;
  externalId: string;
  name: string;
  description: string;
  aliases?: string | null;
  country?: string | null;
  motivations?: string | null;
  url: string;
  createdAt: Date;
  updatedAt: Date;
  procedures?: ProcedureInput[];
}

interface ProcedureInput {
  id: string;
  stixId: string;
  actorId?: string | null;
  malwareId?: string | null;
  toolId?: string | null;
  campaignId?: string | null;
  techniqueId: string;
  description: string;
  technique?: { stixId: string; externalId: string } | null;
  actor?: { stixId: string } | null;
  malware?: { stixId: string } | null;
  tool?: { stixId: string } | null;
  campaign?: { stixId: string } | null;
}

export function actorToStix(actor: ActorInput) {
  const objects: Record<string, unknown>[] = [];
  const aliases = parseJsonField(actor.aliases);

  const intrusion: Record<string, unknown> = {
    type: "intrusion-set",
    spec_version: "2.1",
    id: stixId("intrusion-set", actor.stixId, actor.externalId),
    name: actor.name,
    description: actor.description,
    created: actor.createdAt.toISOString(),
    modified: actor.updatedAt.toISOString(),
    external_references: [buildExternalRef(actor.externalId, actor.url)],
  };
  if (aliases.length > 0) intrusion.aliases = aliases;
  const motivations = parseJsonField(actor.motivations);
  if (motivations.length > 0) {
    intrusion.primary_motivation = motivations[0];
    if (motivations.length > 1) intrusion.secondary_motivations = motivations.slice(1);
  }
  if (actor.country) intrusion.x_country = actor.country;
  objects.push(intrusion);

  if (actor.procedures) {
    for (const proc of actor.procedures) {
      objects.push(...procedureToStix(proc));
    }
  }

  return objects;
}

interface MalwareInput {
  id: string;
  stixId: string;
  externalId: string;
  name: string;
  description: string;
  type?: string | null;
  aliases?: string | null;
  platforms?: string | null;
  url: string;
  createdAt: Date;
  updatedAt: Date;
}

export function malwareToStix(malware: MalwareInput) {
  const aliases = parseJsonField(malware.aliases);
  const stix: Record<string, unknown> = {
    type: "malware",
    spec_version: "2.1",
    id: stixId("malware", malware.stixId, malware.externalId),
    name: malware.name,
    description: malware.description,
    is_family: true,
    created: malware.createdAt.toISOString(),
    modified: malware.updatedAt.toISOString(),
    external_references: [buildExternalRef(malware.externalId, malware.url)],
  };
  if (malware.type) stix.malware_types = [malware.type.toLowerCase()];
  if (aliases.length > 0) stix.aliases = aliases;
  return [stix];
}

interface TechniqueInput {
  id: string;
  stixId: string;
  externalId: string;
  name: string;
  description: string;
  platforms: string;
  isSubtechnique: boolean;
  url: string;
  createdAt: Date;
  updatedAt: Date;
  tactics?: { tactic: { shortName: string } }[];
}

export function techniqueToStix(technique: TechniqueInput) {
  const stix: Record<string, unknown> = {
    type: "attack-pattern",
    spec_version: "2.1",
    id: stixId("attack-pattern", technique.stixId, technique.externalId),
    name: technique.name,
    description: technique.description,
    created: technique.createdAt.toISOString(),
    modified: technique.updatedAt.toISOString(),
    external_references: [buildExternalRef(technique.externalId, technique.url)],
  };
  if (technique.tactics && technique.tactics.length > 0) {
    stix.kill_chain_phases = technique.tactics.map((tt) => ({
      kill_chain_name: "mitre-attack",
      phase_name: tt.tactic.shortName,
    }));
  }
  return [stix];
}

interface IocInput {
  id: string;
  type: string;
  value: string;
  source: string;
  description?: string | null;
  firstSeen?: Date | null;
  createdAt: Date;
}

function iocPattern(type: string, value: string): string {
  const escaped = value.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
  switch (type.toLowerCase()) {
    case "ip":
    case "ipv4":
    case "ip-addr":
    case "ipv4-addr":
      return `[ipv4-addr:value = '${escaped}']`;
    case "ipv6":
    case "ipv6-addr":
      return `[ipv6-addr:value = '${escaped}']`;
    case "domain":
    case "domain-name":
      return `[domain-name:value = '${escaped}']`;
    case "url":
      return `[url:value = '${escaped}']`;
    case "hash":
    case "md5":
    case "sha1":
    case "sha256":
    case "file-hash": {
      const len = value.replace(/[^a-fA-F0-9]/g, "").length;
      if (len === 32) return `[file:hashes.MD5 = '${escaped}']`;
      if (len === 40) return `[file:hashes.'SHA-1' = '${escaped}']`;
      if (len === 64) return `[file:hashes.'SHA-256' = '${escaped}']`;
      return `[file:hashes.MD5 = '${escaped}']`;
    }
    case "email":
    case "email-addr":
      return `[email-addr:value = '${escaped}']`;
    default:
      return `[artifact:payload_bin = '${escaped}']`;
  }
}

export function iocToStix(ioc: IocInput) {
  const validFrom = (ioc.firstSeen ?? ioc.createdAt).toISOString();
  const stix: Record<string, unknown> = {
    type: "indicator",
    spec_version: "2.1",
    id: `indicator--${deterministicUuid(STIX_NAMESPACE + ":ioc:" + ioc.id)}`,
    name: `${ioc.type}: ${ioc.value}`,
    description: ioc.description || `IOC from ${ioc.source}`,
    pattern: iocPattern(ioc.type, ioc.value),
    pattern_type: "stix",
    valid_from: validFrom,
    created: ioc.createdAt.toISOString(),
    modified: ioc.createdAt.toISOString(),
  };
  return [stix];
}

export function procedureToStix(proc: ProcedureInput) {
  const objects: Record<string, unknown>[] = [];

  let sourceRef: string | null = null;
  if (proc.actorId && proc.actor) {
    sourceRef = stixId("intrusion-set", proc.actor.stixId, proc.actorId);
  } else if (proc.malwareId && proc.malware) {
    sourceRef = stixId("malware", proc.malware.stixId, proc.malwareId);
  } else if (proc.toolId && proc.tool) {
    sourceRef = stixId("tool", proc.tool.stixId, proc.toolId);
  } else if (proc.campaignId && proc.campaign) {
    sourceRef = stixId("campaign", proc.campaign.stixId, proc.campaignId);
  }

  const targetRef = proc.technique
    ? stixId("attack-pattern", proc.technique.stixId, proc.technique.externalId)
    : `attack-pattern--${deterministicUuid(STIX_NAMESPACE + ":" + proc.techniqueId)}`;

  if (sourceRef) {
    objects.push({
      type: "relationship",
      spec_version: "2.1",
      id: stixId("relationship", proc.stixId, proc.id),
      relationship_type: "uses",
      description: proc.description,
      source_ref: sourceRef,
      target_ref: targetRef,
    });
  }

  return objects;
}

export function buildBundle(objects: Record<string, unknown>[]) {
  const seen = new Set<string>();
  const deduped = objects.filter((obj) => {
    const id = obj.id as string;
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });

  return {
    type: "bundle" as const,
    id: `bundle--${deterministicUuid(STIX_NAMESPACE + ":bundle:" + Date.now())}`,
    objects: [sourceIdentity(), ...deduped],
  };
}
