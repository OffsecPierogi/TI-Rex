import { prisma } from "../src/lib/db";

const CATEGORIES = [
  { slug: "active-directory", name: "Active Directory", description: "Techniques targeting AD environments: Kerberoasting, DCSync, GPO abuse, LDAP recon, etc.", color: "#3b82f6" },
  { slug: "cloud", name: "Cloud", description: "Cloud infrastructure attacks: AWS, Azure, GCP credential theft, metadata abuse, IAM escalation.", color: "#06b6d4" },
  { slug: "external", name: "External", description: "External-facing attack surface: web apps, VPNs, RDP, phishing, initial access brokers.", color: "#f59e0b" },
  { slug: "satcom", name: "SATCOM", description: "Satellite communications targeting: VSAT, GPS spoofing, satellite ground station attacks.", color: "#8b5cf6" },
  { slug: "ot-ics", name: "OT / ICS", description: "Operational technology and industrial control systems: SCADA, PLCs, HMI, Modbus/DNP3.", color: "#ef4444" },
  { slug: "healthcare", name: "Healthcare", description: "Hospital and healthcare targeting: medical devices, HL7/DICOM, EHR systems, patient data.", color: "#10b981" },
  { slug: "ransomware", name: "Ransomware", description: "Ransomware operations: encryption, double extortion, RaaS, data leak sites.", color: "#dc2626" },
  { slug: "malware", name: "Malware", description: "Malware families: RATs, loaders, stealers, wipers, implants, bootkits.", color: "#a855f7" },
  { slug: "c2-red-team", name: "C2 / Red Team", description: "Command & control frameworks and red team tooling: Cobalt Strike, Sliver, Havoc, Mythic, etc.", color: "#f97316" },
  { slug: "container-k8s", name: "Container / K8s", description: "Docker, Kubernetes, and container orchestration attacks: pod escape, kubelet abuse, image poisoning, service account exploitation.", color: "#0ea5e9" },
  { slug: "social-engineering", name: "Social Engineering", description: "Social engineering campaigns: phishing, vishing, smishing, BEC, pretexting, impersonation, MFA fatigue.", color: "#ec4899" },
  { slug: "supply-chain", name: "Supply Chain", description: "Software supply chain attacks: compromised packages, dependency confusion, CI/CD poisoning, code signing abuse.", color: "#facc15" },
];

async function main() {
  for (const cat of CATEGORIES) {
    await prisma.category.upsert({
      where: { slug: cat.slug },
      update: { name: cat.name, description: cat.description, color: cat.color },
      create: cat,
    });
  }
  console.log(`Seeded ${CATEGORIES.length} categories`);
}

main().catch(console.error).finally(() => process.exit(0));
