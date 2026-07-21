export interface StackComponent {
  id: string;
  name: string;
  category: "cloud" | "infrastructure" | "identity" | "endpoint" | "network" | "container" | "application" | "data";
  platforms: string[];
  techniqueKeywords: string[];
  techniqueIds: string[];
  actorKeywords: string[];
}

export const STACK_COMPONENTS: StackComponent[] = [
  {
    id: "azure", name: "Azure", category: "cloud",
    platforms: ["Azure AD"],
    techniqueKeywords: ["azure", "cloud", "saas"],
    techniqueIds: ["T1078.004", "T1087.004", "T1069.003", "T1538", "T1580", "T1619", "T1537"],
    actorKeywords: ["azure", "cloud"],
  },
  {
    id: "aks", name: "Azure Kubernetes Service", category: "container",
    platforms: ["Containers"],
    techniqueKeywords: ["kubernetes", "container", "pod", "kubelet", "etcd", "helm"],
    techniqueIds: ["T1610", "T1611", "T1613", "T1609"],
    actorKeywords: ["kubernetes", "container"],
  },
  {
    id: "aws", name: "AWS", category: "cloud",
    platforms: [],
    techniqueKeywords: ["aws", "amazon", "ec2", "s3", "iam", "lambda"],
    techniqueIds: ["T1078.004", "T1087.004", "T1069.003", "T1538", "T1580", "T1619"],
    actorKeywords: ["aws", "amazon"],
  },
  {
    id: "gcp", name: "Google Cloud", category: "cloud",
    platforms: ["Google Workspace"],
    techniqueKeywords: ["gcp", "google cloud", "gke"],
    techniqueIds: ["T1078.004", "T1087.004", "T1069.003"],
    actorKeywords: ["google cloud"],
  },
  {
    id: "kubernetes", name: "Kubernetes", category: "container",
    platforms: ["Containers"],
    techniqueKeywords: ["kubernetes", "k8s", "container", "pod", "kubectl", "kubelet", "etcd", "kube-proxy"],
    techniqueIds: ["T1610", "T1611", "T1613", "T1609", "T1552.007"],
    actorKeywords: ["kubernetes"],
  },
  {
    id: "docker", name: "Docker", category: "container",
    platforms: ["Containers"],
    techniqueKeywords: ["docker", "container", "dockerfile"],
    techniqueIds: ["T1610", "T1611", "T1613", "T1609", "T1612"],
    actorKeywords: ["docker", "container"],
  },
  {
    id: "windows", name: "Windows", category: "endpoint",
    platforms: ["Windows"],
    techniqueKeywords: ["windows", "powershell", "cmd", "registry", "wmi"],
    techniqueIds: [],
    actorKeywords: [],
  },
  {
    id: "linux", name: "Linux", category: "endpoint",
    platforms: ["Linux"],
    techniqueKeywords: ["linux", "bash", "cron", "systemd", "ssh"],
    techniqueIds: [],
    actorKeywords: [],
  },
  {
    id: "macos", name: "macOS", category: "endpoint",
    platforms: ["macOS"],
    techniqueKeywords: ["macos", "apple", "launchd", "mach-o"],
    techniqueIds: [],
    actorKeywords: [],
  },
  {
    id: "active-directory", name: "Active Directory", category: "identity",
    platforms: ["Windows"],
    techniqueKeywords: ["active directory", "domain controller", "kerberos", "ldap", "ntlm", "group policy"],
    techniqueIds: ["T1558", "T1558.003", "T1558.001", "T1003.006", "T1207", "T1484", "T1087.002", "T1069.002"],
    actorKeywords: ["active directory", "domain"],
  },
  {
    id: "azure-ad", name: "Entra ID / Azure AD", category: "identity",
    platforms: ["Azure AD"],
    techniqueKeywords: ["azure ad", "entra", "oauth", "saml", "conditional access"],
    techniqueIds: ["T1078.004", "T1550.001", "T1528", "T1606.002"],
    actorKeywords: ["azure ad", "entra"],
  },
  {
    id: "okta", name: "Okta", category: "identity",
    platforms: ["SaaS"],
    techniqueKeywords: ["okta", "sso", "saml", "oauth"],
    techniqueIds: ["T1078.004", "T1550.001", "T1528"],
    actorKeywords: ["okta"],
  },
  {
    id: "office365", name: "Microsoft 365", category: "application",
    platforms: ["Office Suite", "Windows"],
    techniqueKeywords: ["office 365", "exchange", "sharepoint", "teams", "outlook"],
    techniqueIds: ["T1114.002", "T1137", "T1534", "T1199"],
    actorKeywords: ["office 365", "exchange"],
  },
  {
    id: "network", name: "Network Infrastructure", category: "network",
    platforms: ["Network"],
    techniqueKeywords: ["network", "firewall", "router", "switch", "vpn", "proxy"],
    techniqueIds: ["T1557", "T1040", "T1090", "T1572", "T1571"],
    actorKeywords: [],
  },
  {
    id: "web-app", name: "Web Applications", category: "application",
    platforms: [],
    techniqueKeywords: ["web", "http", "api", "injection", "xss", "ssrf"],
    techniqueIds: ["T1190", "T1059.007", "T1203"],
    actorKeywords: [],
  },
  {
    id: "database", name: "Databases", category: "data",
    platforms: [],
    techniqueKeywords: ["database", "sql", "mongodb", "redis"],
    techniqueIds: ["T1505.001", "T1213"],
    actorKeywords: [],
  },
  {
    id: "ci-cd", name: "CI/CD Pipelines", category: "application",
    platforms: [],
    techniqueKeywords: ["ci/cd", "pipeline", "jenkins", "github actions", "gitlab", "supply chain"],
    techniqueIds: ["T1195.002", "T1195.001", "T1072"],
    actorKeywords: ["supply chain"],
  },
];

export interface IndustryProfile {
  id: string;
  name: string;
  description: string;
  primaryThreats: string[];
  actorCountries: string[];
  actorKeywords: string[];
  techniqueCategories: string[];
  techniqueKeywords: string[];
  keyRisks: string[];
  compliance: string[];
}

export const INDUSTRY_PROFILES: IndustryProfile[] = [
  {
    id: "financial", name: "Financial Services",
    description: "Banks, insurance, fintech, trading platforms, payment processors",
    primaryThreats: ["Ransomware", "Business Email Compromise", "Credential Theft", "ATM/POS Malware", "SWIFT Attacks"],
    actorCountries: ["Russia", "North Korea", "China", "Iran"],
    actorKeywords: ["financial", "banking", "swift", "payment", "monetary"],
    techniqueCategories: ["ransomware", "social-engineering"],
    techniqueKeywords: ["financial", "banking", "credential", "wire transfer", "payment"],
    keyRisks: ["Wire fraud via BEC", "Ransomware-driven data extortion", "SWIFT payment manipulation", "Credential harvesting for banking portals", "Supply chain compromise of financial software"],
    compliance: ["PCI-DSS", "SOX", "GLBA", "FFIEC"],
  },
  {
    id: "healthcare", name: "Healthcare",
    description: "Hospitals, pharmaceutical companies, medical device manufacturers, health insurers",
    primaryThreats: ["Ransomware", "PHI Exfiltration", "Medical Device Exploitation", "Supply Chain"],
    actorCountries: ["Russia", "China", "North Korea", "Iran"],
    actorKeywords: ["health", "hospital", "medical", "pharmaceutical", "vaccine"],
    techniqueCategories: ["ransomware"],
    techniqueKeywords: ["health", "medical", "hospital", "patient", "pharmaceutical"],
    keyRisks: ["Ransomware disrupting patient care", "PHI theft for fraud/extortion", "Medical device compromise", "Research IP theft (pharma)", "Third-party vendor compromise"],
    compliance: ["HIPAA", "HITECH", "FDA 21 CFR Part 11"],
  },
  {
    id: "government", name: "Government & Public Sector",
    description: "Federal, state, local agencies, military, intelligence, critical infrastructure oversight",
    primaryThreats: ["Espionage", "Destructive Attacks", "Supply Chain", "Credential Theft", "Insider Threat"],
    actorCountries: ["China", "Russia", "North Korea", "Iran"],
    actorKeywords: ["government", "military", "defense", "intelligence", "espionage", "agency"],
    techniqueCategories: ["apt"],
    techniqueKeywords: ["government", "espionage", "classified", "intelligence", "policy"],
    keyRisks: ["Nation-state espionage for policy intelligence", "Destructive attacks on critical infrastructure", "Supply chain compromise (SolarWinds-style)", "Credential theft for persistent access", "Insider threat exploitation"],
    compliance: ["FedRAMP", "FISMA", "NIST 800-53", "CMMC", "ITAR"],
  },
  {
    id: "energy", name: "Energy & Utilities",
    description: "Oil & gas, electric utilities, water treatment, nuclear, renewable energy",
    primaryThreats: ["ICS/SCADA Attacks", "Destructive Malware", "Espionage", "Ransomware"],
    actorCountries: ["Russia", "China", "Iran", "North Korea"],
    actorKeywords: ["energy", "power", "grid", "pipeline", "utility", "ics", "scada", "oil", "gas"],
    techniqueCategories: [],
    techniqueKeywords: ["ics", "scada", "industrial", "plc", "operational technology", "power grid"],
    keyRisks: ["ICS/SCADA manipulation causing physical damage", "Ransomware halting operations", "Espionage on energy policy/reserves", "Wiper malware (Industroyer/CrashOverride)", "Supply chain targeting of ICS vendors"],
    compliance: ["NERC CIP", "TSA Pipeline Security", "IEC 62443", "NIST CSF"],
  },
  {
    id: "manufacturing", name: "Manufacturing",
    description: "Industrial manufacturing, automotive, aerospace, defense contractors",
    primaryThreats: ["IP Theft", "Ransomware", "ICS/OT Compromise", "Supply Chain"],
    actorCountries: ["China", "Russia", "North Korea"],
    actorKeywords: ["manufacturing", "industrial", "automotive", "aerospace", "defense contractor"],
    techniqueCategories: ["ransomware"],
    techniqueKeywords: ["manufacturing", "industrial", "supply chain", "intellectual property"],
    keyRisks: ["IP theft of designs and processes", "Ransomware disrupting production lines", "OT/ICS compromise in factories", "Supply chain manipulation", "Defense contractor targeting for classified data"],
    compliance: ["CMMC", "ITAR", "ISO 27001", "IEC 62443"],
  },
  {
    id: "technology", name: "Technology",
    description: "Software companies, cloud providers, MSPs, semiconductor firms, SaaS platforms",
    primaryThreats: ["Supply Chain", "Source Code Theft", "Zero-Day Exploitation", "Cloud Compromise"],
    actorCountries: ["China", "Russia", "North Korea"],
    actorKeywords: ["technology", "software", "cloud", "saas", "semiconductor", "msp"],
    techniqueCategories: [],
    techniqueKeywords: ["software", "source code", "repository", "cloud", "api", "supply chain"],
    keyRisks: ["Supply chain attacks via software updates", "Source code and IP theft", "Zero-day exploitation for downstream access", "Cloud infrastructure compromise", "MSP compromise for customer access"],
    compliance: ["SOC 2", "ISO 27001", "GDPR", "CCPA"],
  },
  {
    id: "retail", name: "Retail & E-Commerce",
    description: "Brick-and-mortar retail, e-commerce platforms, payment processors",
    primaryThreats: ["POS Malware", "Magecart/Skimming", "Credential Stuffing", "Ransomware"],
    actorCountries: ["Russia", "China", "North Korea"],
    actorKeywords: ["retail", "ecommerce", "payment", "point of sale", "magecart"],
    techniqueCategories: ["ransomware", "social-engineering"],
    techniqueKeywords: ["payment", "credit card", "point of sale", "ecommerce"],
    keyRisks: ["POS/web skimming for payment card theft", "Credential stuffing against customer accounts", "Ransomware during peak shopping periods", "Gift card fraud and loyalty abuse", "Supply chain attacks on e-commerce platforms"],
    compliance: ["PCI-DSS", "GDPR", "CCPA", "SOC 2"],
  },
  {
    id: "education", name: "Education & Research",
    description: "Universities, K-12, research institutions, online learning platforms",
    primaryThreats: ["Ransomware", "Research IP Theft", "Credential Theft", "Espionage"],
    actorCountries: ["China", "Iran", "Russia", "North Korea"],
    actorKeywords: ["university", "education", "research", "academic"],
    techniqueCategories: ["ransomware"],
    techniqueKeywords: ["education", "university", "research", "academic", "student"],
    keyRisks: ["Ransomware disrupting operations", "Research IP and grant data theft", "Student/staff PII exfiltration", "Foreign espionage targeting research programs", "Phishing targeting .edu domains"],
    compliance: ["FERPA", "GDPR", "NIST 800-171"],
  },
  {
    id: "telecom", name: "Telecommunications",
    description: "Mobile carriers, ISPs, satellite communications, telecom equipment manufacturers",
    primaryThreats: ["Espionage", "SS7/Diameter Exploitation", "Supply Chain", "5G Infrastructure"],
    actorCountries: ["China", "Russia", "Iran"],
    actorKeywords: ["telecom", "carrier", "mobile", "5g", "satellite", "isp"],
    techniqueCategories: [],
    techniqueKeywords: ["telecom", "mobile", "carrier", "network", "5g", "satellite"],
    keyRisks: ["Call/SMS interception for espionage", "SS7/Diameter protocol exploitation", "5G infrastructure supply chain compromise", "Customer data theft at scale", "Network manipulation for surveillance"],
    compliance: ["FCC", "CPNI", "GDPR", "ISO 27011"],
  },
];

export const CATEGORY_LABELS: Record<string, string> = {
  cloud: "Cloud",
  container: "Container",
  identity: "Identity",
  endpoint: "Endpoint",
  network: "Network",
  application: "Application",
  data: "Data",
  infrastructure: "Infrastructure",
};

export const CATEGORY_COLORS: Record<string, string> = {
  cloud: "bg-sky-900/50 text-sky-400",
  container: "bg-violet-900/50 text-violet-400",
  identity: "bg-amber-900/50 text-amber-400",
  endpoint: "bg-emerald-900/50 text-emerald-400",
  network: "bg-cyan-900/50 text-cyan-400",
  application: "bg-pink-900/50 text-pink-400",
  data: "bg-orange-900/50 text-orange-400",
  infrastructure: "bg-zinc-700 text-zinc-300",
};
