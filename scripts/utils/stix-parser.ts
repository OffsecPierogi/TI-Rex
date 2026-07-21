import { readFileSync } from "fs";

export interface StixObject {
  id: string;
  type: string;
  name?: string;
  description?: string;
  aliases?: string[];
  external_references?: Array<{
    source_name: string;
    external_id?: string;
    url?: string;
  }>;
  kill_chain_phases?: Array<{
    kill_chain_name: string;
    phase_name: string;
  }>;
  x_mitre_platforms?: string[];
  x_mitre_data_sources?: string[];
  x_mitre_detection?: string;
  x_mitre_is_subtechnique?: boolean;
  x_mitre_shortname?: string;
  x_mitre_deprecated?: boolean;
  revoked?: boolean;
  relationship_type?: string;
  source_ref?: string;
  target_ref?: string;
  first_seen?: string;
  last_seen?: string;
  [key: string]: unknown;
}

export interface StixBundle {
  objects: StixObject[];
}

export function loadStixBundle(filePath: string): StixBundle {
  const raw = readFileSync(filePath, "utf-8");
  return JSON.parse(raw);
}

export function getExternalId(obj: StixObject): string | null {
  const ref = obj.external_references?.find(
    (r) => r.source_name === "mitre-attack"
  );
  return ref?.external_id ?? null;
}

export function getExternalUrl(obj: StixObject): string {
  const ref = obj.external_references?.find(
    (r) => r.source_name === "mitre-attack"
  );
  return ref?.url ?? "";
}

export function filterByType(bundle: StixBundle, type: string): StixObject[] {
  return bundle.objects.filter(
    (o) => o.type === type && !o.revoked && !o.x_mitre_deprecated
  );
}

export function filterByTypeIncludeAll(bundle: StixBundle, type: string): StixObject[] {
  return bundle.objects.filter((o) => o.type === type);
}
