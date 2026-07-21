import { prisma } from "../src/lib/db";

// ---------------------------------------------------------------------------
// Detection rule seed data — real, working queries for TrustedSec researchers
// ---------------------------------------------------------------------------

interface RuleSeed {
  name: string;
  description: string;
  query: string;
  language: "kql" | "sigma" | "splunk" | "yara" | "snort";
  techniqueExternalId?: string;
  category: string;
  source: string;
  severity: "low" | "medium" | "high" | "critical";
  tags: string[];
}

const RULES: RuleSeed[] = [
  // =========================================================================
  // ACTIVE DIRECTORY
  // =========================================================================
  {
    name: "Kerberoasting - RC4 TGS Request",
    description:
      "Detects Kerberoasting activity by identifying TGS requests using RC4 encryption (0x17) for service tickets, excluding machine accounts. Attackers request RC4-encrypted service tickets to crack offline.",
    query: `SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"
| where ServiceName !in ("krbtgt", "kadmin")
| where TargetUserName !endswith "$"
| extend AccountDomain = split(TargetUserName, "@")[1]
| project TimeGenerated, Computer, TargetUserName, ServiceName,
          TicketEncryptionType, IpAddress, AccountDomain
| summarize RequestCount = count(), DistinctServices = dcount(ServiceName),
            ServiceList = make_set(ServiceName, 50)
            by TargetUserName, IpAddress, bin(TimeGenerated, 5m)
| where DistinctServices >= 3
| sort by RequestCount desc`,
    language: "kql",
    techniqueExternalId: "T1558.003",
    category: "active-directory",
    source: "Microsoft Sentinel",
    severity: "high",
    tags: ["kerberoasting", "credential-access", "rc4", "tgs-request"],
  },

  {
    name: "DCSync Attack Detection",
    description:
      "Detects DCSync attacks by monitoring for DS-Replication-Get-Changes and DS-Replication-Get-Changes-All operations via Event ID 4662. Filters out legitimate domain controller replication.",
    query: `SecurityEvent
| where EventID == 4662
| where OperationType == "Object Access"
| where Properties has "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    or Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    or Properties has "89e95b76-444d-4c62-991a-0facbeda640c"
| where SubjectUserName !endswith "$"
| where SubjectUserName !in ("MSOL_", "AAD_")
| project TimeGenerated, Computer, SubjectUserName, SubjectDomainName,
          ObjectName, ObjectType, Properties
| join kind=leftanti (
    // Exclude known domain controllers
    SecurityEvent
    | where EventID == 4662
    | where SubjectUserName endswith "$"
    | distinct SubjectUserName
) on SubjectUserName
| sort by TimeGenerated desc`,
    language: "kql",
    techniqueExternalId: "T1003.006",
    category: "active-directory",
    source: "Microsoft Sentinel",
    severity: "critical",
    tags: ["dcsync", "credential-access", "replication", "domain-controller"],
  },

  {
    name: "AS-REP Roasting Detection",
    description:
      "Detects AS-REP Roasting by identifying Kerberos AS requests (4768) with pre-authentication disabled (PreAuthType 0) and RC4 encryption. Attackers target accounts without Kerberos pre-auth to crack passwords offline.",
    query: `SecurityEvent
| where EventID == 4768
| where PreAuthType == "0"
| where TicketEncryptionType == "0x17"
| where TargetUserName !endswith "$"
| where Status == "0x0"
| project TimeGenerated, Computer, TargetUserName, TargetDomainName,
          IpAddress, TicketEncryptionType, PreAuthType
| summarize AttemptCount = count(), DistinctAccounts = dcount(TargetUserName),
            AccountList = make_set(TargetUserName, 50)
            by IpAddress, bin(TimeGenerated, 10m)
| sort by AttemptCount desc`,
    language: "kql",
    techniqueExternalId: "T1558.004",
    category: "active-directory",
    source: "Microsoft Sentinel",
    severity: "high",
    tags: ["asreproast", "credential-access", "pre-auth", "kerberos"],
  },

  {
    name: "Pass-the-Hash Detection",
    description:
      "Sigma rule to detect Pass-the-Hash attacks by identifying NTLM authentication with logon type 9 (NewCredentials) and logon process seclogo, which is characteristic of PTH tools like mimikatz.",
    query: `title: Pass-the-Hash Activity
id: f8d98d6c-7a07-4d74-b064-dd4a3c244528
status: stable
level: high
description: Detects Pass-the-Hash attack patterns via NTLM logon type 9 with seclogo process
author: TrustedSec
date: 2024/06/01
modified: 2025/01/15
references:
  - https://attack.mitre.org/techniques/T1550/002/
  - https://www.trustedsec.com
tags:
  - attack.lateral_movement
  - attack.t1550.002
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 9
    LogonProcessName: seclogo
    AuthenticationPackageName: Negotiate
  filter_system:
    TargetUserName|endswith: '$'
  condition: selection and not filter_system
falsepositives:
  - Legitimate use of runas /netonly
  - Some management tools using NTLM type 9`,
    language: "sigma",
    techniqueExternalId: "T1550.002",
    category: "active-directory",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["pass-the-hash", "lateral-movement", "ntlm", "mimikatz"],
  },

  {
    name: "LDAP Reconnaissance Activity",
    description:
      "Detects LDAP-based reconnaissance by monitoring for high-volume LDAP queries from non-DC sources, often indicative of tools like BloodHound, ADRecon, or SharpHound.",
    query: `DeviceNetworkEvents
| where RemotePort == 389 or RemotePort == 636 or RemotePort == 3268
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName !in ("dns.exe", "Microsoft.ActiveDirectory.WebServices.exe",
                                         "svchost.exe", "lsass.exe", "dsac.exe")
| summarize ConnectionCount = count(),
            DistinctTargets = dcount(RemoteIP),
            TargetList = make_set(RemoteIP, 20)
            by DeviceName, InitiatingProcessFileName,
               InitiatingProcessAccountName, bin(Timestamp, 5m)
| where ConnectionCount > 50 or DistinctTargets > 3
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessAccountName, ConnectionCount, DistinctTargets, TargetList
| sort by ConnectionCount desc`,
    language: "kql",
    techniqueExternalId: "T1018",
    category: "active-directory",
    source: "Microsoft Defender for Endpoint",
    severity: "medium",
    tags: ["ldap", "reconnaissance", "bloodhound", "sharphound"],
  },

  {
    name: "Golden Ticket Detection",
    description:
      "Sigma rule detecting Golden Ticket usage by identifying TGS requests where the TGT was issued with anomalous properties -- specifically where the ticket lifetime exceeds domain policy or where the domain field mismatches.",
    query: `title: Potential Golden Ticket Usage
id: a3e2a817-9b4f-4e1b-8f5a-7d6c3e2f1a90
status: experimental
level: critical
description: >
  Detects potential Golden Ticket usage by identifying TGS service ticket
  requests with anomalous TGT characteristics including impossible ticket
  lifetimes and domain field inconsistencies.
author: TrustedSec
date: 2024/08/01
modified: 2025/03/01
references:
  - https://attack.mitre.org/techniques/T1558/001/
  - https://adsecurity.org/?p=1640
tags:
  - attack.credential_access
  - attack.t1558.001
logsource:
  product: windows
  service: security
detection:
  selection_tgs:
    EventID: 4769
    Status: '0x0'
  filter_machine:
    TargetUserName|endswith: '$'
  filter_service:
    ServiceName:
      - 'krbtgt'
      - 'kadmin'
  selection_anomaly:
    EventID: 4769
    TicketEncryptionType:
      - '0x17'
      - '0x12'
  selection_4672:
    EventID: 4672
  condition: (selection_tgs and selection_anomaly and not filter_machine and not filter_service)
falsepositives:
  - Legitimate TGT renewals during Kerberos delegation`,
    language: "sigma",
    techniqueExternalId: "T1558.001",
    category: "active-directory",
    source: "TrustedSec Custom",
    severity: "critical",
    tags: ["golden-ticket", "credential-access", "kerberos", "persistence"],
  },

  {
    name: "Group Policy Modification",
    description:
      "Splunk query detecting unauthorized Group Policy Object modifications which may indicate an attacker establishing persistence or pushing malicious configurations across the domain.",
    query: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=5136
  ObjectClass="groupPolicyContainer"
| eval ModifiedAttribute=case(
    AttributeLDAPDisplayName=="gPCFileSysPath", "GPO File Path",
    AttributeLDAPDisplayName=="versionNumber", "Version Number",
    AttributeLDAPDisplayName=="gPCMachineExtensionNames", "Machine Extensions",
    AttributeLDAPDisplayName=="gPCUserExtensionNames", "User Extensions",
    1==1, AttributeLDAPDisplayName)
| stats count min(_time) as firstTime max(_time) as lastTime
    values(ModifiedAttribute) as ModifiedAttributes
    values(AttributeValue) as NewValues
    dc(ObjectDN) as DistinctGPOs
    by SubjectUserName, SubjectDomainName, ObjectDN, Computer
| where SubjectUserName!="SYSTEM"
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"),
       lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| rename SubjectUserName as User, ObjectDN as GPO_DN
| sort - count`,
    language: "splunk",
    techniqueExternalId: "T1484.001",
    category: "active-directory",
    source: "Splunk Security Essentials",
    severity: "high",
    tags: ["gpo", "group-policy", "persistence", "domain-dominance"],
  },

  {
    name: "DCShadow Attack Detection",
    description:
      "Detects DCShadow attacks by identifying rogue domain controller registration through monitoring for nTDSDSA object creation and SPNs associated with DC replication being added to non-DC computer accounts.",
    query: `SecurityEvent
| where EventID in (4742, 5137, 5141)
| where (EventID == 4742 and ServicePrincipalNames has "E3514235-4B06-11D1-AB04-00C04FC2DCD2")
    or (EventID == 5137 and ObjectClass == "nTDSDSA")
    or (EventID == 5141 and ObjectClass == "nTDSDSA")
| project TimeGenerated, Computer, EventID, SubjectUserName,
          TargetUserName, ServicePrincipalNames, ObjectDN, ObjectClass
| extend AlertType = case(
    EventID == 4742, "SPN_Modification_for_DC_Replication",
    EventID == 5137, "nTDSDSA_Object_Created",
    EventID == 5141, "nTDSDSA_Object_Deleted",
    "Unknown")
| summarize Events = count(), AlertTypes = make_set(AlertType)
            by SubjectUserName, bin(TimeGenerated, 1m)
| where Events >= 2
| sort by TimeGenerated desc`,
    language: "kql",
    techniqueExternalId: "T1207",
    category: "active-directory",
    source: "Microsoft Sentinel",
    severity: "critical",
    tags: ["dcshadow", "defense-evasion", "domain-controller", "rogue-dc"],
  },

  // =========================================================================
  // CLOUD
  // =========================================================================
  {
    name: "Azure AD Suspicious Sign-In Properties",
    description:
      "Detects suspicious Azure AD sign-ins with unusual properties such as unfamiliar locations, anonymous IP addresses, or atypical device/browser combinations that may indicate credential compromise.",
    query: `SigninLogs
| where ResultType == 0
| where RiskLevelDuringSignIn in ("medium", "high")
    or RiskState == "atRisk"
| mv-expand parse_json(AuthenticationDetails)
| extend AuthMethod = tostring(AuthenticationDetails.authenticationMethod),
         AuthSuccess = tobool(AuthenticationDetails.succeeded)
| where AuthSuccess == true
| extend City = tostring(LocationDetails.city),
         State = tostring(LocationDetails.state),
         Country = tostring(LocationDetails.countryOrRegion),
         Latitude = toreal(LocationDetails.geoCoordinates.latitude),
         Longitude = toreal(LocationDetails.geoCoordinates.longitude)
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,
          City, State, Country, UserAgent, DeviceDetail,
          RiskLevelDuringSignIn, RiskState, ConditionalAccessStatus,
          AuthMethod, AuthenticationRequirement
| summarize SignInCount = count(),
            DistinctIPs = dcount(IPAddress),
            DistinctCities = dcount(City),
            Apps = make_set(AppDisplayName, 10),
            IPs = make_set(IPAddress, 10)
            by UserPrincipalName, bin(TimeGenerated, 1h)
| where DistinctIPs > 2 or DistinctCities > 1
| sort by SignInCount desc`,
    language: "kql",
    techniqueExternalId: "T1078.004",
    category: "cloud",
    source: "Microsoft Sentinel",
    severity: "high",
    tags: ["azure-ad", "suspicious-signin", "cloud-identity", "risk-detection"],
  },

  {
    name: "Azure Privilege Escalation - Role Assignment",
    description:
      "Detects Azure AD privilege escalation by monitoring for role assignments, particularly for high-privilege roles like Global Administrator, Privileged Role Administrator, and Application Administrator.",
    query: `AuditLogs
| where OperationName has_any ("Add member to role", "Add eligible member to role",
                                "Add scoped member to role")
| where Result == "success"
| mv-expand TargetResources
| extend TargetUser = tostring(TargetResources.userPrincipalName),
         RoleName = tostring(parse_json(tostring(
             TargetResources.modifiedProperties))[1].newValue)
| where RoleName has_any ("Global Administrator", "Privileged Role Administrator",
                           "Application Administrator", "Exchange Administrator",
                           "Security Administrator", "User Access Administrator",
                           "Contributor", "Owner")
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, InitiatedBy, TargetUser, OperationName,
          RoleName, CorrelationId, Category
| sort by TimeGenerated desc`,
    language: "kql",
    techniqueExternalId: "T1098.003",
    category: "cloud",
    source: "Microsoft Sentinel",
    severity: "critical",
    tags: ["azure-ad", "privilege-escalation", "role-assignment", "iam"],
  },

  {
    name: "AWS CloudTrail - Unauthorized IAM User Creation",
    description:
      "Detects IAM user creation in AWS via CloudTrail, focusing on users created outside of approved automation pipelines. Correlates with console login and access key creation events.",
    query: `AWSCloudTrail
| where EventName == "CreateUser"
| where SourceIpAddress != "cloudformation.amazonaws.com"
    and SourceIpAddress != "terraform.amazonaws.com"
| extend NewUser = tostring(parse_json(RequestParameters).userName),
         Creator = UserIdentityPrincipalId,
         CreatorArn = UserIdentityArn,
         AccountId = RecipientAccountId
| project TimeGenerated, NewUser, Creator, CreatorArn,
          SourceIpAddress, UserAgent, AccountId, AWSRegion
| join kind=leftouter (
    AWSCloudTrail
    | where EventName in ("CreateAccessKey", "CreateLoginProfile")
    | extend TargetUser = tostring(parse_json(RequestParameters).userName)
    | project AccessKeyTime = TimeGenerated, EventName, TargetUser
) on $left.NewUser == $right.TargetUser
| sort by TimeGenerated desc`,
    language: "kql",
    techniqueExternalId: "T1136.003",
    category: "cloud",
    source: "Microsoft Sentinel - AWS Connector",
    severity: "high",
    tags: ["aws", "iam", "user-creation", "cloudtrail"],
  },

  {
    name: "Cloud Service Discovery Detection",
    description:
      "Sigma rule detecting cloud service enumeration activities commonly used during reconnaissance phase by attackers to map available cloud resources.",
    query: `title: Cloud Service Discovery via CLI Tools
id: 8b3e7d4a-c1f2-4a5b-9e6d-3f8c2a1b5e7d
status: experimental
level: medium
description: >
  Detects cloud service discovery and enumeration using CLI tools
  such as az, aws, gcloud, and common cloud enumeration scripts.
author: TrustedSec
date: 2024/10/01
modified: 2025/02/15
references:
  - https://attack.mitre.org/techniques/T1526/
tags:
  - attack.discovery
  - attack.t1526
logsource:
  category: process_creation
  product: windows
detection:
  selection_azure:
    CommandLine|contains:
      - 'az account list'
      - 'az resource list'
      - 'az vm list'
      - 'az storage account list'
      - 'az keyvault list'
      - 'az ad app list'
      - 'az role assignment list'
  selection_aws:
    CommandLine|contains:
      - 'aws sts get-caller-identity'
      - 'aws iam list-users'
      - 'aws s3 ls'
      - 'aws ec2 describe-instances'
      - 'aws lambda list-functions'
      - 'aws rds describe-db-instances'
  selection_gcloud:
    CommandLine|contains:
      - 'gcloud projects list'
      - 'gcloud compute instances list'
      - 'gcloud iam service-accounts list'
      - 'gcloud storage ls'
  selection_tools:
    Image|endswith:
      - '\\ScoutSuite\\scout.py'
      - '\\Prowler\\prowler'
      - '\\enumerate-iam.py'
      - '\\cloud_enum.py'
  condition: 1 of selection_*
falsepositives:
  - Legitimate cloud administration
  - CI/CD pipeline operations`,
    language: "sigma",
    techniqueExternalId: "T1526",
    category: "cloud",
    source: "TrustedSec Custom",
    severity: "medium",
    tags: ["cloud-discovery", "enumeration", "azure-cli", "aws-cli"],
  },

  {
    name: "Azure Key Vault Anomalous Access",
    description:
      "Detects anomalous access patterns to Azure Key Vault secrets, keys, and certificates including bulk secret retrieval, access from unusual IPs, and operations by newly created service principals.",
    query: `AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("SecretGet", "SecretList", "KeyGet", "KeyList",
                           "CertificateGet", "CertificateList",
                           "VaultGet", "SecretBackup", "KeyDecrypt")
| extend Caller = identity_claim_unique_name_s,
         CallerIP = CallerIPAddress,
         VaultName = Resource,
         Operation = OperationName
| summarize OperationCount = count(),
            DistinctOps = dcount(OperationName),
            DistinctVaults = dcount(Resource),
            Operations = make_set(OperationName, 20),
            Vaults = make_set(Resource, 10)
            by Caller, CallerIP, bin(TimeGenerated, 15m)
| where OperationCount > 20
    or DistinctOps > 4
    or DistinctVaults > 2
| sort by OperationCount desc`,
    language: "kql",
    category: "cloud",
    source: "Microsoft Sentinel",
    severity: "high",
    tags: ["azure", "keyvault", "secrets", "credential-access"],
  },

  {
    name: "Impossible Travel Detection",
    description:
      "Detects impossible travel scenarios where a user authenticates from two geographically distant locations within a timeframe that makes physical travel impossible, suggesting credential compromise.",
    query: `let velocity_threshold_kmh = 900; // faster than commercial flight
let time_window = 60m;
SigninLogs
| where ResultType == 0
| extend Latitude = toreal(LocationDetails.geoCoordinates.latitude),
         Longitude = toreal(LocationDetails.geoCoordinates.longitude),
         City = tostring(LocationDetails.city),
         Country = tostring(LocationDetails.countryOrRegion)
| where isnotempty(Latitude) and isnotempty(Longitude)
| sort by UserPrincipalName, TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated, 1),
         PrevLat = prev(Latitude, 1),
         PrevLong = prev(Longitude, 1),
         PrevCity = prev(City, 1),
         PrevCountry = prev(Country, 1),
         PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser
| extend TimeDiffMinutes = datetime_diff('minute', TimeGenerated, PrevTime)
| where TimeDiffMinutes > 0 and TimeDiffMinutes < time_window / 1m
| extend Distance_km = geo_distance_2points(Longitude, Latitude, PrevLong, PrevLat) / 1000.0
| extend Velocity_kmh = Distance_km / (TimeDiffMinutes / 60.0)
| where Velocity_kmh > velocity_threshold_kmh and Distance_km > 500
| project TimeGenerated, UserPrincipalName, IPAddress,
          City, Country, PrevCity, PrevCountry,
          Distance_km = round(Distance_km, 0),
          TimeDiffMinutes, Velocity_kmh = round(Velocity_kmh, 0)
| sort by Velocity_kmh desc`,
    language: "kql",
    category: "cloud",
    source: "Microsoft Sentinel",
    severity: "high",
    tags: ["impossible-travel", "identity", "credential-compromise", "geolocation"],
  },

  {
    name: "AWS S3 Bucket Enumeration and Exfiltration",
    description:
      "Splunk query to detect S3 bucket enumeration and potential data exfiltration by identifying unusual ListBucket, GetObject, and HeadBucket operations, especially from unfamiliar principals or IPs.",
    query: `index=aws sourcetype=aws:cloudtrail
  (eventName=ListBuckets OR eventName=ListObjects OR eventName=GetObject
   OR eventName=HeadBucket OR eventName=GetBucketAcl OR eventName=GetBucketPolicy)
| eval is_sensitive=case(
    match(requestParameters.bucketName, "(backup|secret|confidential|prod|private|pii)"), "yes",
    1==1, "no")
| stats count as api_calls
    dc(requestParameters.bucketName) as distinct_buckets
    values(requestParameters.bucketName) as bucket_names
    values(eventName) as operations
    min(_time) as firstTime max(_time) as lastTime
    by userIdentity.arn, sourceIPAddress
| where distinct_buckets > 5 OR (is_sensitive="yes" AND api_calls > 10)
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"),
       lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| rename "userIdentity.arn" as caller_arn, sourceIPAddress as src_ip
| sort - distinct_buckets`,
    language: "splunk",
    techniqueExternalId: "T1619",
    category: "cloud",
    source: "Splunk Security Content",
    severity: "medium",
    tags: ["aws", "s3", "enumeration", "data-exfiltration"],
  },

  // =========================================================================
  // RANSOMWARE
  // =========================================================================
  {
    name: "Volume Shadow Copy Deletion",
    description:
      "Sigma rule detecting deletion of Volume Shadow Copies, a key precursor to ransomware encryption. Monitors for vssadmin, wmic, and PowerShell-based shadow copy deletion commands.",
    query: `title: Volume Shadow Copy Deletion
id: c947b146-0abc-4f87-9c64-b17e9d7b54a1
status: stable
level: critical
description: >
  Detects deletion of volume shadow copies commonly performed by
  ransomware prior to file encryption to prevent recovery.
author: TrustedSec
date: 2024/03/01
modified: 2025/04/01
references:
  - https://attack.mitre.org/techniques/T1490/
tags:
  - attack.impact
  - attack.t1490
logsource:
  category: process_creation
  product: windows
detection:
  selection_vssadmin:
    Image|endswith: '\\vssadmin.exe'
    CommandLine|contains|all:
      - 'delete'
      - 'shadows'
  selection_wmic_shadowcopy:
    Image|endswith: '\\wmic.exe'
    CommandLine|contains|all:
      - 'shadowcopy'
      - 'delete'
  selection_powershell_vss:
    CommandLine|contains:
      - 'Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete()}'
      - 'Get-CimInstance Win32_ShadowCopy | Remove-CimInstance'
      - 'gwmi Win32_Shadowcopy | % { $_.Delete() }'
  selection_diskshadow:
    Image|endswith: '\\diskshadow.exe'
    CommandLine|contains: 'delete shadows all'
  condition: 1 of selection_*
falsepositives:
  - Legitimate backup operations (very rare to delete all shadows)
  - System maintenance scripts`,
    language: "sigma",
    techniqueExternalId: "T1490",
    category: "ransomware",
    source: "Sigma Community Rules",
    severity: "critical",
    tags: ["ransomware", "shadow-copy", "vssadmin", "impact"],
  },

  {
    name: "Mass File Encryption Detection",
    description:
      "Detects potential ransomware encryption activity by monitoring for processes that rename or modify a large number of files in a short timeframe, particularly with known ransomware extensions.",
    query: `DeviceFileEvents
| where ActionType in ("FileRenamed", "FileModified", "FileCreated")
| where Timestamp > ago(15m)
| extend FileExtension = tostring(split(FileName, ".")[-1])
| extend IsRansomwareExt = FileExtension in (
    "encrypted", "enc", "locked", "crypto", "crypt",
    "ransom", "zzz", "aaa", "abc", "xyz", "bbb",
    "micro", "locky", "cerber", "zepto", "odin",
    "thor", "aesir", "WNCRY", "wcry", "wncrypt",
    "ROGER", "CONTI", "LOCKBIT", "hive", "play",
    "akira", "royal", "blackcat", "alphv")
| summarize FileCount = count(),
            RansomwareExtCount = countif(IsRansomwareExt),
            DistinctExtensions = dcount(FileExtension),
            DistinctFolders = dcount(FolderPath),
            Extensions = make_set(FileExtension, 20),
            SampleFiles = make_set(FileName, 10)
            by DeviceName, InitiatingProcessFileName,
               InitiatingProcessAccountName, bin(Timestamp, 1m)
| where FileCount > 100 and (RansomwareExtCount > 10 or DistinctFolders > 5)
| sort by FileCount desc`,
    language: "kql",
    techniqueExternalId: "T1486",
    category: "ransomware",
    source: "Microsoft Defender for Endpoint",
    severity: "critical",
    tags: ["ransomware", "encryption", "file-modification", "impact"],
  },

  {
    name: "BCDEdit Boot Configuration Modification",
    description:
      "Sigma rule detecting BCDEdit commands used to disable recovery features. Ransomware commonly modifies boot configuration to prevent Safe Mode recovery and disable Windows Error Recovery.",
    query: `title: BCDEdit Boot Configuration Tampering
id: 1f11e2b0-7e3a-4c9d-b5f8-6a2d4e8c3f91
status: stable
level: high
description: >
  Detects use of bcdedit.exe to modify boot configuration settings
  commonly abused by ransomware to prevent system recovery.
author: TrustedSec
date: 2024/05/01
modified: 2025/02/01
references:
  - https://attack.mitre.org/techniques/T1490/
tags:
  - attack.impact
  - attack.t1490
logsource:
  category: process_creation
  product: windows
detection:
  selection_bcdedit:
    Image|endswith: '\\bcdedit.exe'
  selection_disable_recovery:
    CommandLine|contains:
      - 'recoveryenabled no'
      - 'bootstatuspolicy ignoreallfailures'
      - 'safeboot minimal'
      - 'safeboot network'
  selection_delete:
    CommandLine|contains:
      - '/delete'
      - '/deletevalue'
  condition: selection_bcdedit and (selection_disable_recovery or selection_delete)
falsepositives:
  - Legitimate IT administration modifying boot settings
  - System deployment scripts`,
    language: "sigma",
    techniqueExternalId: "T1490",
    category: "ransomware",
    source: "Sigma Community Rules",
    severity: "high",
    tags: ["ransomware", "bcdedit", "boot-config", "recovery-disabled"],
  },

  {
    name: "Service Stop Commands - Pre-Encryption",
    description:
      "Splunk query detecting rapid stopping of critical services (databases, backups, AV, security agents) which is a common ransomware pre-encryption behavior.",
    query: `index=wineventlog sourcetype="WinEventLog:System" EventCode=7036
  (Message="*stopped*" OR Message="*entering the stopped state*")
| eval service_name=Service_Name
| eval is_critical=case(
    match(service_name, "(?i)(sql|mysql|oracle|postgres|mongo)"), "database",
    match(service_name, "(?i)(backup|veeam|acronis|shadow|vss)"), "backup",
    match(service_name, "(?i)(defender|symantec|mcafee|crowdstrike|sentinel|carbon)"), "security",
    match(service_name, "(?i)(exchange|iis|apache|nginx|tomcat)"), "infrastructure",
    1==1, "other")
| where is_critical!="other"
| stats count as stopped_count
    dc(service_name) as distinct_services
    values(service_name) as services_stopped
    values(is_critical) as service_categories
    by host, _time span=5m
| where stopped_count >= 3
| sort - stopped_count`,
    language: "splunk",
    techniqueExternalId: "T1489",
    category: "ransomware",
    source: "Splunk Security Content",
    severity: "critical",
    tags: ["ransomware", "service-stop", "pre-encryption", "impact"],
  },

  {
    name: "Ransomware Note Creation Patterns",
    description:
      "Detects the creation of ransomware notes by monitoring for file creation events matching known ransom note filenames and patterns across multiple directories.",
    query: `DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName matches regex @"(?i)(readme.*\\.txt|decrypt.*\\.txt|restore.*\\.txt|how.?to.?decrypt|how.?to.?recover|ransom.?note|!.*read.?me|warning\\.txt|recovery.?instructions|unlock.?files|your.?files|decrypt.?instructions|#.*readme|RECOVER.*FILES)"
    or FileName in~ ("DECRYPT-FILES.txt", "HOW-TO-DECRYPT.txt",
                      "README-ENCRYPTED.txt", "_readme.txt",
                      "RECOVER-FILES.html", "!Read_Me.txt",
                      "Restore-My-Files.txt", "HOW_TO_RECOVER_DATA.html",
                      "ALPHV-README.txt", "readme-warning.txt")
| summarize NoteCount = count(),
            DistinctNoteNames = dcount(FileName),
            DistinctFolders = dcount(FolderPath),
            NoteNames = make_set(FileName, 20),
            Folders = make_set(FolderPath, 10)
            by DeviceName, InitiatingProcessFileName,
               InitiatingProcessAccountName, bin(Timestamp, 5m)
| where NoteCount > 3 or DistinctFolders > 2
| sort by NoteCount desc`,
    language: "kql",
    category: "ransomware",
    source: "Microsoft Defender for Endpoint",
    severity: "critical",
    tags: ["ransomware", "ransom-note", "file-creation", "indicator"],
  },

  {
    name: "WMIC Shadowcopy Delete",
    description:
      "Sigma rule specifically targeting WMIC-based shadow copy deletion, a highly specific indicator of ransomware activity used by Conti, REvil, LockBit, and others.",
    query: `title: WMIC Shadow Copy Deletion
id: e19e4ab8-7d3c-4f1a-8b5e-2c6d9f4a3e71
status: stable
level: critical
description: >
  Detects WMIC-based deletion of shadow copies, a technique
  commonly used by ransomware including Conti, REvil, and LockBit.
author: TrustedSec
date: 2024/04/15
modified: 2025/01/10
references:
  - https://attack.mitre.org/techniques/T1490/
tags:
  - attack.impact
  - attack.t1490
logsource:
  category: process_creation
  product: windows
detection:
  selection_wmic:
    Image|endswith: '\\wmic.exe'
    CommandLine|contains|all:
      - 'shadowcopy'
      - 'delete'
  selection_wmic_path:
    Image|endswith: '\\wmic.exe'
    CommandLine|contains:
      - 'path Win32_ShadowCopy delete'
      - 'path Win32_ShadowCopy where'
  selection_powershell_wmi:
    CommandLine|contains|all:
      - 'Win32_ShadowCopy'
      - 'Delete()'
  condition: 1 of selection_*
falsepositives:
  - Very unlikely in legitimate use`,
    language: "sigma",
    category: "ransomware",
    source: "TrustedSec Custom",
    severity: "critical",
    tags: ["ransomware", "wmic", "shadow-copy", "impact"],
  },

  // =========================================================================
  // C2 / RED TEAM
  // =========================================================================
  {
    name: "Cobalt Strike Default Named Pipes",
    description:
      "Sigma rule detecting Cobalt Strike default named pipe patterns used for inter-process communication during beacon operations. Covers default and commonly observed pipe names.",
    query: `title: Cobalt Strike Named Pipe Detection
id: d5601f8c-b6a1-4cd7-8c3f-e15d3a4b9c27
status: stable
level: critical
description: >
  Detects Cobalt Strike default and commonly used named pipes
  for beacon communication, lateral movement, and post-exploitation.
author: TrustedSec
date: 2024/02/01
modified: 2025/05/01
references:
  - https://research.nccgroup.com/2021/06/15/cobalt-strike-pipe-patterns/
  - https://labs.withsecure.com/publications/detecting-cobalt-strike-default-modules
tags:
  - attack.command_and_control
  - attack.execution
  - attack.t1071
logsource:
  product: windows
  category: pipe_created
detection:
  selection_default:
    PipeName|startswith:
      - '\\\\MSSE-'
      - '\\\\msagent_'
      - '\\\\postex_'
      - '\\\\postex_ssh_'
      - '\\\\status_'
      - '\\\\mojo.5688.8052'
  selection_smb_beacon:
    PipeName|re: '\\\\\\\\[a-f0-9]{7,10}'
  selection_lateral:
    PipeName:
      - '\\\\wkssvc'
      - '\\\\ntsvcs'
      - '\\\\DserNamePipe'
      - '\\\\SearchTextHarvester'
      - '\\\\mypipe-f'
      - '\\\\mypipe-h'
      - '\\\\win_svc'
      - '\\\\UIA_PIPE'
  condition: 1 of selection_*
falsepositives:
  - Some legitimate software may use similar pipe naming patterns
  - Custom Cobalt Strike profiles will not match defaults`,
    language: "sigma",
    category: "c2-red-team",
    source: "TrustedSec Custom",
    severity: "critical",
    tags: ["cobalt-strike", "named-pipes", "c2", "beacon"],
  },

  {
    name: "DNS Beaconing Detection",
    description:
      "Detects DNS-based C2 beaconing by identifying periodic DNS queries with high entropy subdomain labels, consistent timing intervals, and TXT record lookups to uncommon domains -- characteristic of DNS tunneling tools like dnscat2, Cobalt Strike DNS, and iodine.",
    query: `DnsEvents
| where QueryType in ("A", "AAAA", "TXT", "CNAME", "MX")
| extend SubdomainParts = split(Name, ".")
| extend SubdomainLabel = tostring(SubdomainParts[0]),
         BaseDomain = strcat(tostring(SubdomainParts[-2]), ".", tostring(SubdomainParts[-1]))
| extend LabelLength = strlen(SubdomainLabel)
| where LabelLength > 20
| summarize QueryCount = count(),
            DistinctSubdomains = dcount(SubdomainLabel),
            AvgLabelLength = avg(LabelLength),
            TxtCount = countif(QueryType == "TXT"),
            TimeSpan = datetime_diff('minute', max(TimeGenerated), min(TimeGenerated)),
            SampleQueries = make_set(Name, 5)
            by BaseDomain, ClientIP, bin(TimeGenerated, 1h)
| where DistinctSubdomains > 20
    and AvgLabelLength > 25
| extend BeaconScore = DistinctSubdomains * 0.4 + AvgLabelLength * 0.3 + TxtCount * 0.3
| where BeaconScore > 15
| sort by BeaconScore desc`,
    language: "kql",
    techniqueExternalId: "T1071.004",
    category: "c2-red-team",
    source: "Microsoft Sentinel",
    severity: "high",
    tags: ["dns-beaconing", "c2", "dns-tunneling", "dnscat2"],
  },

  {
    name: "Suspicious PowerShell Download Cradle",
    description:
      "Sigma rule detecting common PowerShell download cradle patterns used by attackers for initial payload delivery including IEX, Invoke-Expression, Net.WebClient, and reflection-based techniques.",
    query: `title: PowerShell Download Cradle Detection
id: 3a7e9d2c-8b4f-4c6a-9d5e-1f3b7c8a2e64
status: stable
level: high
description: >
  Detects PowerShell download cradle patterns commonly used for
  malware delivery, C2 stager execution, and fileless attacks.
author: TrustedSec
date: 2024/01/15
modified: 2025/04/20
references:
  - https://attack.mitre.org/techniques/T1059/001/
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection_process:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
  selection_download:
    CommandLine|contains:
      - 'Net.WebClient'
      - 'DownloadString'
      - 'DownloadFile'
      - 'DownloadData'
      - 'Invoke-WebRequest'
      - 'iwr '
      - 'wget '
      - 'curl '
      - 'Start-BitsTransfer'
      - 'Net.Sockets.TCPClient'
      - '[System.Net.HttpWebRequest]'
      - 'Invoke-RestMethod'
      - 'irm '
  selection_exec:
    CommandLine|contains:
      - 'IEX'
      - 'Invoke-Expression'
      - 'Invoke-Command'
      - '.Invoke('
      - '| iex'
      - '|iex'
      - 'FromBase64String'
      - '[Convert]::FromBase64'
      - '-EncodedCommand'
      - '-enc '
      - '-ec '
  selection_reflection:
    CommandLine|contains:
      - '[Reflection.Assembly]::Load'
      - '[System.Reflection.Assembly]::Load'
      - 'Assembly.Load'
      - 'Unsafe.AsPointer'
  condition: selection_process and (selection_download and selection_exec) or (selection_process and selection_reflection)
falsepositives:
  - Legitimate admin scripts downloading packages
  - Chocolatey and package managers
  - SCCM/Intune deployment scripts`,
    language: "sigma",
    techniqueExternalId: "T1059.001",
    category: "c2-red-team",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["powershell", "download-cradle", "execution", "fileless"],
  },

  {
    name: "Cobalt Strike Default SSL Certificate",
    description:
      "Snort rule detecting the default Cobalt Strike HTTPS beacon SSL certificate properties. The default certificate uses specific serial number, issuer, and subject patterns that remain surprisingly common in the wild.",
    query: `alert tls $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET MALWARE Cobalt Strike Default SSL/TLS Certificate Detected";
  flow:established,to_server;
  tls.cert_subject;
  content:"O=cobaltstrike";
  content:"OU=AdvancedPenTesting";
  reference:url,blog.didierstevens.com/2021/06/07/update-cobalt-strike-certificates/;
  classtype:trojan-activity;
  sid:2033850;
  rev:3;
  metadata:created_at 2024_01_15, updated_at 2025_03_01;
)

alert tls $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET MALWARE Cobalt Strike Default Self-Signed Certificate Serial";
  flow:established,to_server;
  tls.cert_serial;
  content:"8B B0 18 5A 3E 56 12 1E E1 62 E3 E4 FA 47 06 6C";
  reference:url,research.nccgroup.com/2021/06/15/cobalt-strike-pipe-patterns/;
  classtype:trojan-activity;
  sid:2033851;
  rev:2;
  metadata:created_at 2024_01_15, updated_at 2025_03_01;
)`,
    language: "snort",
    category: "c2-red-team",
    source: "Emerging Threats",
    severity: "critical",
    tags: ["cobalt-strike", "ssl-cert", "c2", "network-detection"],
  },

  {
    name: "Process Injection via CreateRemoteThread",
    description:
      "Detects potential process injection using CreateRemoteThread by identifying cross-process thread creation events, excluding known legitimate sources such as antivirus and debugging tools.",
    query: `DeviceEvents
| where ActionType == "CreateRemoteThreadApiCall"
| where InitiatingProcessFileName != FileName
| where InitiatingProcessFileName !in (
    "MsMpEng.exe", "csrss.exe", "svchost.exe", "services.exe",
    "WerFault.exe", "wuauclt.exe", "backgroundTaskHost.exe",
    "SearchIndexer.exe", "devenv.exe", "msvsmon.exe",
    "taskhostw.exe", "sihost.exe", "RuntimeBroker.exe")
| where FileName !in ("svchost.exe", "RuntimeBroker.exe")
| extend TargetProcess = FileName,
         SourceProcess = InitiatingProcessFileName,
         SourcePID = InitiatingProcessId,
         SourceCmdLine = InitiatingProcessCommandLine,
         SourceUser = InitiatingProcessAccountName
| project Timestamp, DeviceName, SourceProcess, SourcePID,
          SourceCmdLine, SourceUser, TargetProcess,
          InitiatingProcessFolderPath, FolderPath
| summarize InjectionCount = count(),
            DistinctTargets = dcount(TargetProcess),
            Targets = make_set(TargetProcess, 10)
            by DeviceName, SourceProcess, SourceUser, bin(Timestamp, 5m)
| where InjectionCount >= 1
| sort by InjectionCount desc`,
    language: "kql",
    techniqueExternalId: "T1055.001",
    category: "c2-red-team",
    source: "Microsoft Defender for Endpoint",
    severity: "high",
    tags: ["process-injection", "createremotethread", "defense-evasion", "execution"],
  },

  {
    name: "Sliver C2 Framework Indicators",
    description:
      "Sigma rule detecting indicators of the Sliver C2 framework including default implant behaviors, named pipe patterns, and process characteristics.",
    query: `title: Sliver C2 Framework Indicators
id: 7c2d1e8f-4a5b-3c6d-9e7f-1b2a8d5c4e63
status: experimental
level: high
description: >
  Detects indicators associated with the Sliver C2 framework including
  default named pipes, process behavior, and network patterns.
author: TrustedSec
date: 2024/07/01
modified: 2025/05/15
references:
  - https://github.com/BishopFox/sliver
  - https://sliver.sh/
tags:
  - attack.command_and_control
  - attack.execution
logsource:
  product: windows
  category: process_creation
detection:
  selection_suspicious_go:
    Image|endswith:
      - '.exe'
    Description|contains:
      - 'Go build ID'
    ParentImage|endswith:
      - '\\explorer.exe'
      - '\\cmd.exe'
      - '\\powershell.exe'
  selection_pipe:
    PipeName|startswith:
      - '\\\\sliver'
      - '\\\\sliverpivot'
  selection_dns:
    CommandLine|contains:
      - '_domainkey'
      - '.1.v.'
      - '.2.v.'
  selection_mtls_port:
    DestinationPort:
      - 8888
      - 31337
  condition: 1 of selection_*
falsepositives:
  - Legitimate Go applications
  - Other tools using similar port numbers`,
    language: "sigma",
    category: "c2-red-team",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["sliver", "c2", "bishopfox", "red-team"],
  },

  // =========================================================================
  // OT / ICS
  // =========================================================================
  {
    name: "Modbus Function Code Scan Detection",
    description:
      "Snort rules detecting Modbus TCP function code scanning -- where an attacker sends multiple different function codes to a PLC/RTU to enumerate supported functions. This is a common ICS reconnaissance technique.",
    query: `alert tcp any any -> $ICS_NET 502 (
  msg:"ICS SCAN Modbus Read Coils Function Code 0x01";
  flow:established,to_server;
  content:"|00 00|";
  offset:2;
  depth:2;
  content:"|01|";
  offset:7;
  depth:1;
  classtype:attempted-recon;
  sid:1100001;
  rev:2;
  metadata:created_at 2024_06_01, updated_at 2025_02_01;
)

alert tcp any any -> $ICS_NET 502 (
  msg:"ICS SCAN Modbus Write Multiple Coils Function Code 0x0F";
  flow:established,to_server;
  content:"|00 00|";
  offset:2;
  depth:2;
  content:"|0F|";
  offset:7;
  depth:1;
  classtype:attempted-admin;
  sid:1100002;
  rev:2;
  metadata:created_at 2024_06_01, updated_at 2025_02_01;
)

alert tcp any any -> $ICS_NET 502 (
  msg:"ICS SCAN Modbus Write Single Register Function Code 0x06";
  flow:established,to_server;
  content:"|00 00|";
  offset:2;
  depth:2;
  content:"|06|";
  offset:7;
  depth:1;
  classtype:attempted-admin;
  sid:1100003;
  rev:2;
  metadata:created_at 2024_06_01, updated_at 2025_02_01;
)

alert tcp any any -> $ICS_NET 502 (
  msg:"ICS SCAN Modbus Diagnostics Function Code 0x08";
  flow:established,to_server;
  content:"|00 00|";
  offset:2;
  depth:2;
  content:"|08|";
  offset:7;
  depth:1;
  classtype:attempted-recon;
  sid:1100004;
  rev:2;
  metadata:created_at 2024_06_01, updated_at 2025_02_01;
)`,
    language: "snort",
    category: "ot-ics",
    source: "Custom ICS/OT Signatures",
    severity: "high",
    tags: ["modbus", "ics", "ot", "scada", "function-code-scan"],
  },

  {
    name: "Engineering Workstation Suspicious Process",
    description:
      "Sigma rule detecting execution of suspicious processes on engineering workstations that typically only run HMI/SCADA software. Unusual process execution on these systems may indicate compromise.",
    query: `title: Suspicious Process on Engineering Workstation
id: 4e8d7c2a-1b5f-3a6e-9c4d-7f2b8a5e1d93
status: experimental
level: high
description: >
  Detects execution of processes atypical for ICS/SCADA engineering
  workstations including scripting engines, remote access tools,
  and reconnaissance utilities.
author: TrustedSec
date: 2024/09/01
modified: 2025/03/15
references:
  - https://attack.mitre.org/matrices/ics/
tags:
  - attack.execution
  - attack.initial_access
logsource:
  category: process_creation
  product: windows
detection:
  selection_scripting:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
      - '\\cscript.exe'
      - '\\wscript.exe'
      - '\\mshta.exe'
      - '\\python.exe'
      - '\\python3.exe'
  selection_recon:
    Image|endswith:
      - '\\nmap.exe'
      - '\\masscan.exe'
      - '\\arp.exe'
      - '\\net.exe'
      - '\\nltest.exe'
      - '\\nbtstat.exe'
      - '\\netstat.exe'
  selection_remote:
    Image|endswith:
      - '\\psexec.exe'
      - '\\psexec64.exe'
      - '\\putty.exe'
      - '\\plink.exe'
      - '\\teamviewer.exe'
      - '\\anydesk.exe'
      - '\\vnc.exe'
  selection_transfer:
    Image|endswith:
      - '\\certutil.exe'
      - '\\bitsadmin.exe'
      - '\\curl.exe'
      - '\\wget.exe'
    CommandLine|contains:
      - 'http'
      - 'ftp'
      - 'urlcache'
  condition: 1 of selection_*
falsepositives:
  - Legitimate engineering tool updates
  - Authorized remote maintenance sessions`,
    language: "sigma",
    category: "ot-ics",
    source: "TrustedSec ICS Practice",
    severity: "high",
    tags: ["ics", "ot", "engineering-workstation", "scada", "anomaly"],
  },

  {
    name: "OPC-UA Anomalous Connection Detection",
    description:
      "Detects anomalous OPC-UA connections on port 4840 from non-standard sources, potential unauthorized SCADA/HMI access, and new clients not seen in the baseline period.",
    query: `DeviceNetworkEvents
| where RemotePort == 4840 or LocalPort == 4840
| where ActionType in ("ConnectionSuccess", "InboundConnectionAccepted")
| extend Direction = iff(LocalPort == 4840, "inbound", "outbound")
| summarize ConnectionCount = count(),
            DistinctSources = dcount(RemoteIP),
            DistinctDestinations = dcount(LocalIP),
            Sources = make_set(RemoteIP, 20),
            Processes = make_set(InitiatingProcessFileName, 10)
            by DeviceName, Direction, bin(Timestamp, 1h)
| join kind=leftanti (
    // Baseline of known OPC-UA clients from past 14 days
    DeviceNetworkEvents
    | where Timestamp > ago(14d) and Timestamp < ago(1d)
    | where RemotePort == 4840 or LocalPort == 4840
    | summarize by RemoteIP, DeviceName
    | extend IsBaseline = true
) on DeviceName
| where DistinctSources > 0
| extend AlertReason = case(
    ConnectionCount > 100, "High connection volume",
    DistinctSources > 3, "Multiple source IPs",
    true, "New OPC-UA client")
| sort by ConnectionCount desc`,
    language: "kql",
    category: "ot-ics",
    source: "Microsoft Defender for IoT",
    severity: "high",
    tags: ["opc-ua", "ics", "ot", "scada", "industrial"],
  },

  // =========================================================================
  // EXTERNAL
  // =========================================================================
  {
    name: "Brute Force Authentication Detection",
    description:
      "Detects brute force attacks by monitoring for multiple failed authentication attempts followed by a success from the same source, covering both on-premises and cloud sign-in events.",
    query: `let threshold_failures = 10;
let threshold_time = 10m;
union SigninLogs, SecurityEvent
| extend NormalizedUser = coalesce(UserPrincipalName, TargetUserName),
         NormalizedIP = coalesce(IPAddress, IpAddress),
         NormalizedResult = case(
             ResultType == "0" or EventID == 4624, "Success",
             EventID == 4625 or toint(ResultType) > 0, "Failure",
             "Unknown")
| where NormalizedResult in ("Success", "Failure")
| summarize FailureCount = countif(NormalizedResult == "Failure"),
            SuccessCount = countif(NormalizedResult == "Success"),
            DistinctUsers = dcount(NormalizedUser),
            TargetUsers = make_set(NormalizedUser, 20),
            FirstAttempt = min(TimeGenerated),
            LastAttempt = max(TimeGenerated)
            by NormalizedIP, bin(TimeGenerated, threshold_time)
| where FailureCount >= threshold_failures
| extend BruteForceSuccess = iff(SuccessCount > 0, "Yes - COMPROMISED", "No")
| project TimeGenerated, NormalizedIP, FailureCount, SuccessCount,
          BruteForceSuccess, DistinctUsers, TargetUsers,
          FirstAttempt, LastAttempt
| sort by FailureCount desc`,
    language: "kql",
    techniqueExternalId: "T1110",
    category: "external",
    source: "Microsoft Sentinel",
    severity: "high",
    tags: ["brute-force", "credential-access", "authentication", "initial-access"],
  },

  {
    name: "Web Shell Detection",
    description:
      "Sigma rule detecting web shell deployment and execution by monitoring for suspicious process creation by web server processes (IIS, Apache, Nginx, Tomcat) and creation of script files in web directories.",
    query: `title: Web Shell Execution Detection
id: 5c9e8b7a-2d4f-1a3e-6c8b-9f5d2a7e4c31
status: stable
level: critical
description: >
  Detects web shell activity by identifying suspicious child processes
  spawned by web server processes, indicative of command execution
  through an uploaded web shell.
author: TrustedSec
date: 2024/04/01
modified: 2025/05/10
references:
  - https://attack.mitre.org/techniques/T1505/003/
  - https://www.microsoft.com/en-us/security/blog/2021/02/11/web-shell-attacks-continue-to-rise/
tags:
  - attack.persistence
  - attack.t1505.003
logsource:
  category: process_creation
  product: windows
detection:
  selection_webserver_parent:
    ParentImage|endswith:
      - '\\w3wp.exe'
      - '\\httpd.exe'
      - '\\nginx.exe'
      - '\\apache.exe'
      - '\\tomcat.exe'
      - '\\java.exe'
      - '\\php-cgi.exe'
      - '\\php.exe'
      - '\\node.exe'
  selection_suspicious_child:
    Image|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
      - '\\pwsh.exe'
      - '\\csc.exe'
      - '\\certutil.exe'
      - '\\bitsadmin.exe'
      - '\\whoami.exe'
      - '\\net.exe'
      - '\\net1.exe'
      - '\\ipconfig.exe'
      - '\\systeminfo.exe'
      - '\\tasklist.exe'
      - '\\ping.exe'
      - '\\nslookup.exe'
  selection_encoded:
    CommandLine|contains:
      - '-enc'
      - 'FromBase64'
      - 'hidden'
      - '-nop'
      - '-w hidden'
  condition: selection_webserver_parent and (selection_suspicious_child or selection_encoded)
falsepositives:
  - Legitimate CGI scripts
  - Web-based management consoles`,
    language: "sigma",
    techniqueExternalId: "T1505.003",
    category: "external",
    source: "TrustedSec Custom",
    severity: "critical",
    tags: ["webshell", "persistence", "initial-access", "web-server"],
  },

  {
    name: "SQL Injection Attack Detection",
    description:
      "Snort rules detecting common SQL injection patterns in HTTP traffic including UNION-based, error-based, blind, and time-based injection attempts.",
    query: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
  msg:"WEB-ATTACKS SQL Injection - UNION SELECT attempt";
  flow:established,to_server;
  http_uri;
  content:"UNION";
  nocase;
  content:"SELECT";
  nocase;
  distance:0;
  pcre:"/UNION[\\s\\v]+(?:ALL[\\s\\v]+)?SELECT/Ui";
  classtype:web-application-attack;
  sid:2100001;
  rev:3;
  metadata:created_at 2024_03_01, updated_at 2025_04_01;
)

alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
  msg:"WEB-ATTACKS SQL Injection - Time-Based Blind (WAITFOR)";
  flow:established,to_server;
  http_uri;
  content:"WAITFOR";
  nocase;
  content:"DELAY";
  nocase;
  distance:0;
  pcre:"/WAITFOR[\\s\\v]+DELAY[\\s\\v]+[\\x27\\x22]/Ui";
  classtype:web-application-attack;
  sid:2100002;
  rev:2;
  metadata:created_at 2024_03_01, updated_at 2025_04_01;
)

alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
  msg:"WEB-ATTACKS SQL Injection - Boolean Blind (OR 1=1)";
  flow:established,to_server;
  http_uri;
  pcre:"/[\\x27\\x22]\\s*(OR|AND)\\s*[\\x27\\x22]?\\d+[\\x27\\x22]?\\s*=\\s*[\\x27\\x22]?\\d+/Ui";
  classtype:web-application-attack;
  sid:2100003;
  rev:2;
  metadata:created_at 2024_03_01, updated_at 2025_04_01;
)

alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
  msg:"WEB-ATTACKS SQL Injection - Stacked Queries (semicolon + command)";
  flow:established,to_server;
  http_uri;
  pcre:"/;\\s*(DROP|ALTER|INSERT|UPDATE|DELETE|CREATE|EXEC|EXECUTE)\\s/Ui";
  classtype:web-application-attack;
  sid:2100004;
  rev:2;
  metadata:created_at 2024_03_01, updated_at 2025_04_01;
)`,
    language: "snort",
    category: "external",
    source: "Custom IDS Signatures",
    severity: "high",
    tags: ["sql-injection", "web-attack", "owasp", "injection"],
  },

  {
    name: "Suspicious OAuth Application Consent",
    description:
      "Detects suspicious OAuth application consent grants in Azure AD that may indicate consent phishing -- where an attacker tricks a user into granting permissions to a malicious application.",
    query: `AuditLogs
| where OperationName == "Consent to application"
| where Result == "success"
| mv-expand TargetResources
| extend AppName = tostring(TargetResources.displayName),
         AppId = tostring(TargetResources.id)
| mv-expand parse_json(tostring(TargetResources.modifiedProperties))
| extend PropertyName = tostring(parse_json(tostring(
             TargetResources.modifiedProperties))[0].displayName),
         ConsentType = tostring(parse_json(tostring(
             TargetResources.modifiedProperties))[0].newValue)
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName),
         ConsentedByIP = tostring(InitiatedBy.user.ipAddress)
| where ConsentType has_any ("AllPrincipals", "Directory.ReadWrite.All",
                              "Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All",
                              "User.ReadWrite.All", "Contacts.ReadWrite")
| project TimeGenerated, ConsentedBy, ConsentedByIP, AppName, AppId,
          ConsentType, OperationName, CorrelationId
| sort by TimeGenerated desc`,
    language: "kql",
    category: "external",
    source: "Microsoft Sentinel",
    severity: "high",
    tags: ["oauth", "consent-phishing", "azure-ad", "application-abuse"],
  },

  // =========================================================================
  // MALWARE
  // =========================================================================
  {
    name: "Generic PE Packer Detection",
    description:
      "YARA rule detecting common PE packer signatures including UPX, Themida, VMProtect, ASPack, and custom packers. Packed executables in unexpected locations are a strong malware indicator.",
    query: `rule generic_pe_packer_detection
{
    meta:
        author = "TrustedSec"
        description = "Detects common PE packers used to obfuscate malware"
        date = "2024-06-01"
        modified = "2025-04-15"
        reference = "https://attack.mitre.org/techniques/T1027/002/"
        severity = "medium"

    strings:
        // UPX signatures
        $upx_header = { 55 50 58 30 00 00 00 }
        $upx_marker = "UPX!" ascii
        $upx_section = ".UPX" ascii

        // Themida / WinLicense
        $themida_1 = ".themida" ascii
        $themida_2 = ".winlice" ascii

        // VMProtect
        $vmprotect_1 = ".vmp0" ascii
        $vmprotect_2 = ".vmp1" ascii
        $vmprotect_3 = ".vmp2" ascii

        // ASPack
        $aspack_1 = ".aspack" ascii
        $aspack_2 = ".adata" ascii

        // MPRESS
        $mpress_1 = ".MPRESS1" ascii
        $mpress_2 = ".MPRESS2" ascii

        // Enigma Protector
        $enigma = ".enigma" ascii

        // Custom packer indicators - high entropy sections with unusual names
        $custom_1 = { 60 E8 00 00 00 00 5D }
        $custom_2 = { 9C 60 E8 00 00 00 00 }

        // Anti-debug / anti-analysis common in packed samples
        $anti_1 = "IsDebuggerPresent" ascii
        $anti_2 = "NtQueryInformationProcess" ascii
        $anti_3 = "CheckRemoteDebuggerPresent" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (
            any of ($upx_*) or
            any of ($themida_*) or
            any of ($vmprotect_*) or
            any of ($aspack_*) or
            any of ($mpress_*) or
            $enigma or
            (any of ($custom_*) and any of ($anti_*)) or
            (2 of ($anti_*) and
             math.entropy(0, filesize) > 7.0)
        )
}`,
    language: "yara",
    category: "malware",
    source: "TrustedSec Malware Analysis",
    severity: "medium",
    tags: ["packer", "upx", "vmprotect", "themida", "obfuscation"],
  },

  {
    name: "Suspicious DLL Side-Loading",
    description:
      "Sigma rule detecting DLL side-loading by monitoring for known vulnerable executables loading DLLs from non-standard paths. Attackers abuse legitimate signed binaries to load malicious DLLs.",
    query: `title: DLL Side-Loading via Known Vulnerable Executables
id: 9a2c6e1d-3b7f-4d5a-8e2c-1f6b9d4a7c53
status: stable
level: high
description: >
  Detects DLL side-loading using known vulnerable signed executables
  that load DLLs from their working directory rather than System32.
author: TrustedSec
date: 2024/06/15
modified: 2025/04/01
references:
  - https://attack.mitre.org/techniques/T1574/002/
  - https://hijacklibs.net/
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1574.002
logsource:
  category: image_load
  product: windows
detection:
  selection_vulnerable_exe:
    Image|endswith:
      - '\\OneDriveStandaloneUpdater.exe'
      - '\\WerFaultSecure.exe'
      - '\\DismHost.exe'
      - '\\MpCmdRun.exe'
      - '\\SearchProtocolHost.exe'
      - '\\consent.exe'
      - '\\dxcap.exe'
      - '\\Taskmgr.exe'
  filter_legitimate_paths:
    ImageLoaded|startswith:
      - 'C:\\Windows\\System32\\'
      - 'C:\\Windows\\SysWOW64\\'
      - 'C:\\Windows\\WinSxS\\'
      - 'C:\\Program Files\\'
      - 'C:\\Program Files (x86)\\'
  selection_suspicious_path:
    ImageLoaded|contains:
      - '\\Users\\'
      - '\\Temp\\'
      - '\\ProgramData\\'
      - '\\AppData\\'
      - '\\Downloads\\'
      - '\\Desktop\\'
      - '\\Public\\'
  condition: selection_vulnerable_exe and selection_suspicious_path and not filter_legitimate_paths
falsepositives:
  - Portable applications loading DLLs from user directories
  - Development environments`,
    language: "sigma",
    techniqueExternalId: "T1574.002",
    category: "malware",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["dll-sideloading", "defense-evasion", "persistence", "hijack"],
  },

  {
    name: "LOLBin Execution Detection",
    description:
      "Detects Living-off-the-Land Binary (LOLBin) execution with suspicious command-line parameters, focusing on binaries commonly abused for proxy execution, download, and defense evasion.",
    query: `DeviceProcessEvents
| where FileName in~ ("certutil.exe", "mshta.exe", "regsvr32.exe",
                        "rundll32.exe", "msbuild.exe", "installutil.exe",
                        "cmstp.exe", "wmic.exe", "msxsl.exe", "ieexec.exe",
                        "pcalua.exe", "forfiles.exe", "presentationhost.exe",
                        "bash.exe", "scriptrunner.exe", "syncappvpublishingserver.exe",
                        "hh.exe", "infdefaultinstall.exe", "dnscmd.exe",
                        "mavinject.exe", "msiexec.exe", "explorer.exe",
                        "xwizard.exe", "odbcconf.exe")
| where ProcessCommandLine has_any (
    "http://", "https://", "ftp://",
    "/urlcache", "/f ", "javascript:", "vbscript:",
    "/i:http", "scrobj.dll", "comsvcs.dll",
    "-decode", "-encode", "-encodehex",
    "invoke-", "downloadstring", "downloadfile",
    "regsvr32 /s /n /u /i:",
    "msiexec /q /i http",
    "/c calc", "/c powershell",
    "DelegateExecute", "mshta vbscript:",
    "pcalua -a", "forfiles /p")
| extend LOLBin = FileName,
         Technique = case(
             FileName =~ "certutil.exe", "T1218 + T1105",
             FileName =~ "mshta.exe", "T1218.005",
             FileName =~ "regsvr32.exe", "T1218.010",
             FileName =~ "rundll32.exe", "T1218.011",
             FileName =~ "msbuild.exe", "T1127.001",
             FileName =~ "installutil.exe", "T1218.004",
             FileName =~ "cmstp.exe", "T1218.003",
             FileName =~ "wmic.exe", "T1218",
             "T1218")
| project Timestamp, DeviceName, AccountName, LOLBin, Technique,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FolderPath
| sort by Timestamp desc`,
    language: "kql",
    techniqueExternalId: "T1218",
    category: "malware",
    source: "Microsoft Defender for Endpoint",
    severity: "high",
    tags: ["lolbin", "living-off-the-land", "defense-evasion", "proxy-execution"],
  },

  {
    name: "Certutil Download and Decode",
    description:
      "Sigma rule detecting the abuse of certutil.exe for downloading files from remote URLs and decoding Base64-encoded payloads -- a common malware delivery technique.",
    query: `title: Certutil Download and Decode Activity
id: 6b8a2d5c-9e3f-4a7b-1c6d-8f2e5a4b3c71
status: stable
level: high
description: >
  Detects certutil.exe abuse for downloading files from URLs and
  decoding Base64-encoded payloads, commonly used for malware delivery.
author: TrustedSec
date: 2024/03/20
modified: 2025/03/10
references:
  - https://attack.mitre.org/techniques/T1105/
  - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
tags:
  - attack.command_and_control
  - attack.defense_evasion
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection_certutil:
    Image|endswith: '\\certutil.exe'
  selection_download:
    CommandLine|contains:
      - 'urlcache'
      - '-urlcache'
      - '/urlcache'
      - 'URL'
    CommandLine|contains:
      - 'http'
      - 'ftp'
  selection_decode:
    CommandLine|contains:
      - '-decode'
      - '/decode'
      - '-decodehex'
      - '/decodehex'
  selection_split:
    CommandLine|contains:
      - '-split'
      - '/split'
  condition: selection_certutil and (selection_download or selection_decode or selection_split)
falsepositives:
  - Legitimate certificate operations
  - System administrators using certutil for troubleshooting`,
    language: "sigma",
    techniqueExternalId: "T1105",
    category: "malware",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["certutil", "download", "decode", "lolbin", "ingress-tool-transfer"],
  },

  // =========================================================================
  // HEALTHCARE
  // =========================================================================
  {
    name: "DICOM Service Anomalous Access",
    description:
      "Detects anomalous access to DICOM (Digital Imaging and Communications in Medicine) services on port 104/11112, including connections from non-medical workstations, unusual hours, or high-volume query patterns that may indicate data exfiltration.",
    query: `DeviceNetworkEvents
| where RemotePort in (104, 11112) or LocalPort in (104, 11112)
| where ActionType in ("ConnectionSuccess", "InboundConnectionAccepted")
| extend IsDICOMServer = (LocalPort in (104, 11112)),
         ConnectionDirection = iff(LocalPort in (104, 11112), "inbound", "outbound")
| extend HourOfDay = hourofday(Timestamp),
         DayOfWeek = dayofweek(Timestamp),
         IsAfterHours = hourofday(Timestamp) < 6 or hourofday(Timestamp) > 20,
         IsWeekend = dayofweek(Timestamp) in (0d, 6d)
| summarize ConnectionCount = count(),
            DistinctSources = dcount(RemoteIP),
            Sources = make_set(RemoteIP, 20),
            DistinctProcesses = dcount(InitiatingProcessFileName),
            Processes = make_set(InitiatingProcessFileName, 10),
            AfterHoursCount = countif(IsAfterHours),
            WeekendCount = countif(IsWeekend)
            by DeviceName, ConnectionDirection, bin(Timestamp, 1h)
| where ConnectionCount > 50
    or DistinctSources > 5
    or AfterHoursCount > 10
    or (IsAfterHours and ConnectionCount > 5)
| extend RiskScore = ConnectionCount * 0.3 + DistinctSources * 5.0 +
                     AfterHoursCount * 2.0 + WeekendCount * 3.0
| sort by RiskScore desc`,
    language: "kql",
    category: "healthcare",
    source: "Custom Healthcare Security",
    severity: "high",
    tags: ["dicom", "healthcare", "medical-imaging", "pacs", "hipaa"],
  },

  {
    name: "HL7 Interface Suspicious Commands",
    description:
      "Sigma rule detecting suspicious activity on HL7 (Health Level 7) interfaces including unusual message types, queries for bulk patient data, and command injection attempts via HL7 segments.",
    query: `title: Suspicious HL7 Interface Activity
id: 2f7a9c4e-6d8b-3a1f-5c7e-4b9d2a8f6e13
status: experimental
level: high
description: >
  Detects suspicious activity on HL7 interfaces including unusual
  message patterns that may indicate unauthorized access to patient
  data or tampering with medical systems.
author: TrustedSec Healthcare Practice
date: 2024/11/01
modified: 2025/05/01
references:
  - https://www.hl7.org/implement/standards/
  - https://www.hhs.gov/hipaa/index.html
tags:
  - attack.collection
  - attack.exfiltration
logsource:
  category: application
  product: hl7_interface_engine
detection:
  selection_bulk_query:
    Message|contains:
      - 'QBP^Q22'
      - 'QBP^Q23'
      - 'QBP^Z99'
      - 'QRY^A19'
    MessageCount|gt: 50
  selection_suspicious_segment:
    Message|contains:
      - 'MSH|^~\\&|UNKNOWN'
      - 'MSH|^~\\&|TEST'
      - 'MSH|^~\\&|HACK'
    Message|re: 'MSH\\|.{0,200}(;|\\||<|>|\\$\\(|\\x00)'
  selection_unusual_source:
    SendingApplication|contains:
      - 'UNKNOWN'
      - 'TEST'
      - 'DEBUG'
      - 'ADMIN'
    SendingFacility: ''
  selection_pid_enum:
    Message|contains: 'PID|'
    EventType: 'QBP'
  condition: 1 of selection_*
falsepositives:
  - Legitimate bulk data migration
  - Interface testing during maintenance windows
  - New system integration setup`,
    language: "sigma",
    category: "healthcare",
    source: "TrustedSec Healthcare Practice",
    severity: "high",
    tags: ["hl7", "healthcare", "medical-records", "hipaa", "ehr"],
  },
  // =========================================================================
  // CONTAINER / KUBERNETES
  // =========================================================================
  {
    name: "Kubernetes Exec into Pod",
    description:
      "Detects kubectl exec commands used to get a shell inside a running pod. Attackers use this for lateral movement and container escape.",
    query: `SecurityEvent
| where ProcessCommandLine has "kubectl" and ProcessCommandLine has "exec"
| where ProcessCommandLine has_any ("-it", "--stdin", "/bin/sh", "/bin/bash", "cmd.exe")
| project TimeGenerated, Computer, Account, ProcessCommandLine
| sort by TimeGenerated desc`,
    language: "kql",
    techniqueExternalId: "T1609",
    category: "container-k8s",
    source: "Microsoft Defender for Cloud",
    severity: "high",
    tags: ["kubernetes", "kubectl", "exec", "container", "lateral-movement"],
  },
  {
    name: "Privileged Container Deployment",
    description:
      "Detects creation of privileged containers or containers with host namespace access. These allow container escape and full host compromise.",
    query: `title: Privileged Container Created
id: k8s-privileged-container
status: stable
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    objectRef.resource: pods
  privilege_check:
    requestObject.spec.containers[].securityContext.privileged: true
  hostpid:
    requestObject.spec.hostPID: true
  hostnetwork:
    requestObject.spec.hostNetwork: true
  condition: selection and (privilege_check or hostpid or hostnetwork)
level: critical
falsepositives:
  - Legitimate system pods (kube-system)
  - Monitoring daemonsets like Falco or Datadog`,
    language: "sigma",
    techniqueExternalId: "T1611",
    category: "container-k8s",
    source: "Kubernetes Threat Matrix",
    severity: "critical",
    tags: ["kubernetes", "privileged", "container-escape", "host-access"],
  },
  {
    name: "Container Image from Untrusted Registry",
    description:
      "Detects container images pulled from registries outside the organization's allowed list. Attackers deploy malicious images to establish persistence.",
    query: `title: Untrusted Container Registry Pull
id: k8s-untrusted-registry
status: experimental
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: create
    objectRef.resource: pods
  filter_trusted:
    requestObject.spec.containers[].image|startswith:
      - 'gcr.io/'
      - 'docker.io/library/'
      - 'mcr.microsoft.com/'
      - 'registry.k8s.io/'
  condition: selection and not filter_trusted
level: high
falsepositives:
  - Developer testing with custom registries
  - Third-party vendor images`,
    language: "sigma",
    techniqueExternalId: "T1610",
    category: "container-k8s",
    source: "Kubernetes Threat Matrix",
    severity: "high",
    tags: ["kubernetes", "container", "image", "supply-chain", "registry"],
  },
  {
    name: "Kubernetes Service Account Token Access",
    description:
      "Detects processes reading the default service account token from the projected volume mount. Attackers steal these tokens to authenticate to the Kubernetes API.",
    query: `KubeAuditLogs
| where RequestURI has "/api/v1/namespaces/"
| where Verb in ("get", "list", "watch")
| where ObjectRef has "secrets" or ObjectRef has "serviceaccounts"
| where UserAgent !has "kube-controller" and UserAgent !has "kube-scheduler"
| project TimeGenerated, SourceIPs, UserAgent, Verb, RequestURI, ResponseStatus
| sort by TimeGenerated desc`,
    language: "kql",
    category: "container-k8s",
    source: "Microsoft Defender for Cloud",
    severity: "high",
    tags: ["kubernetes", "service-account", "token-theft", "api-abuse"],
  },
  {
    name: "Docker Socket Mount Detection",
    description:
      "Detects containers mounting the Docker socket, which allows full control of the host Docker daemon and is a common container escape vector.",
    query: `ContainerInventory
| where ContainerHostname != ""
| where Ports has "docker.sock" or Image has "docker.sock"
| union (
  ContainerLog
  | where LogEntry has "/var/run/docker.sock"
)
| project TimeGenerated, ContainerID, Name, Image, LogEntry
| sort by TimeGenerated desc`,
    language: "kql",
    techniqueExternalId: "T1611",
    category: "container-k8s",
    source: "Microsoft Defender for Cloud",
    severity: "critical",
    tags: ["docker", "socket", "container-escape", "privilege-escalation"],
  },
  {
    name: "Kubernetes CronJob Creation",
    description:
      "Detects creation of Kubernetes CronJobs which attackers use for persistence by scheduling recurring malicious containers.",
    query: `KubeAuditLogs
| where Verb == "create" and ObjectRef has "cronjobs"
| where UserAgent !has "kube-controller"
| project TimeGenerated, SourceIPs, User, ObjectRef, RequestObject
| sort by TimeGenerated desc`,
    language: "kql",
    category: "container-k8s",
    source: "Microsoft Defender for Cloud",
    severity: "medium",
    tags: ["kubernetes", "cronjob", "persistence", "scheduling"],
  },
  // =========================================================================
  // SOCIAL ENGINEERING
  // =========================================================================
  {
    name: "MFA Fatigue / Push Bombing Detection",
    description:
      "Detects repeated MFA push notification denials followed by an approval, indicating MFA fatigue attacks where the user eventually approves to stop the notifications.",
    query: `SigninLogs
| where ResultType == 50074 or ResultType == 500121
| summarize
    DeniedCount = countif(Status.additionalDetails == "MFA denied"),
    ApprovedCount = countif(Status.additionalDetails == "MFA completed"),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where DeniedCount >= 5 and ApprovedCount >= 1
| project UserPrincipalName, IPAddress, DeniedCount, ApprovedCount, FirstAttempt, LastAttempt`,
    language: "kql",
    techniqueExternalId: "T1621",
    category: "social-engineering",
    source: "Microsoft Sentinel Community",
    severity: "critical",
    tags: ["mfa-fatigue", "push-bombing", "credential-access", "entra-id"],
  },
  {
    name: "OAuth Consent Phishing Detection",
    description:
      "Detects suspicious OAuth application consent grants, a technique where attackers trick users into granting permissions to malicious applications.",
    query: `AuditLogs
| where OperationName == "Consent to application"
| where Result == "success"
| extend AppId = tostring(TargetResources[0].id)
| extend AppName = tostring(TargetResources[0].displayName)
| extend Permissions = tostring(AdditionalDetails[4].value)
| where Permissions has_any ("Mail.Read", "Mail.ReadWrite", "Files.ReadWrite.All", "User.ReadWrite.All")
| project TimeGenerated, InitiatedBy, AppName, AppId, Permissions
| sort by TimeGenerated desc`,
    language: "kql",
    techniqueExternalId: "T1566.002",
    category: "social-engineering",
    source: "Microsoft Sentinel Community",
    severity: "high",
    tags: ["oauth", "consent-phishing", "application-abuse", "entra-id"],
  },
  {
    name: "Phishing Email with Suspicious Attachment",
    description:
      "Detects inbound emails with attachment types commonly used in phishing campaigns: ISO, VHD, OneNote, and HTML smuggling files.",
    query: `title: Phishing Attachment - Suspicious File Types
id: phishing-sus-attachments
status: stable
logsource:
  product: mail
  service: exchange
detection:
  selection:
    Direction: Inbound
  suspicious_ext:
    AttachmentFileType|endswith:
      - '.iso'
      - '.vhd'
      - '.vhdx'
      - '.img'
      - '.one'
      - '.onenote'
      - '.htm'
      - '.html'
      - '.svg'
      - '.wsf'
      - '.lnk'
  condition: selection and suspicious_ext
level: high
falsepositives:
  - Legitimate shared disk images
  - Internal OneNote attachments`,
    language: "sigma",
    techniqueExternalId: "T1566.001",
    category: "social-engineering",
    source: "Sigma Community Rules",
    severity: "high",
    tags: ["phishing", "attachment", "email", "initial-access"],
  },
  {
    name: "Business Email Compromise - Inbox Rule Creation",
    description:
      "Detects creation of email forwarding or deletion rules that attackers set after compromising mailboxes to maintain access and hide evidence.",
    query: `OfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where Parameters has_any ("ForwardTo", "RedirectTo", "DeleteMessage", "MoveToFolder")
| extend RuleName = tostring(parse_json(Parameters)[0].Value)
| extend ForwardTo = tostring(parse_json(Parameters)[1].Value)
| project TimeGenerated, UserId, Operation, RuleName, ForwardTo, ClientIP
| sort by TimeGenerated desc`,
    language: "kql",
    techniqueExternalId: "T1534",
    category: "social-engineering",
    source: "Microsoft Sentinel Community",
    severity: "high",
    tags: ["bec", "inbox-rule", "email-forwarding", "persistence"],
  },
  {
    name: "Credential Harvesting Page Detection",
    description:
      "Detects access to known credential harvesting infrastructure based on URL patterns and suspicious login page redirects.",
    query: `index=proxy sourcetype=squid OR sourcetype=bluecoat
| where (url LIKE "%/login%" OR url LIKE "%/signin%" OR url LIKE "%/auth%")
| where NOT (url LIKE "%microsoft.com%" OR url LIKE "%google.com%" OR url LIKE "%okta.com%")
| where (url LIKE "%.xyz%" OR url LIKE "%.top%" OR url LIKE "%.buzz%" OR url LIKE "%.tk%" OR url LIKE "%bit.ly%")
| stats count by src_ip, url, dest_ip
| where count > 0
| sort - count`,
    language: "splunk",
    techniqueExternalId: "T1598.003",
    category: "social-engineering",
    source: "Splunk Security Essentials",
    severity: "medium",
    tags: ["credential-harvesting", "phishing-page", "proxy", "url-filtering"],
  },
  {
    name: "QR Code Phishing (Quishing) Detection",
    description:
      "Detects emails containing QR code images with no other links, a technique to bypass email security gateways that don't scan images.",
    query: `EmailEvents
| where EmailDirection == "Inbound"
| join kind=inner (
    EmailAttachmentInfo
    | where FileType in ("png", "jpg", "jpeg", "gif", "bmp")
) on NetworkMessageId
| where UrlCount == 0 and AttachmentCount >= 1
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, AttachmentCount, FileName
| sort by TimeGenerated desc`,
    language: "kql",
    category: "social-engineering",
    source: "Microsoft Defender for Office 365",
    severity: "medium",
    tags: ["quishing", "qr-code", "phishing", "email", "image-based"],
  },

  // =========================================================================
  // TURN RELAY C2 / DRAGONFORCE
  // =========================================================================
  {
    name: "Microsoft Teams TURN Relay C2 - Anomalous Anonymous Token Request",
    description:
      "Detects anonymous visitor token requests to Microsoft Skype/Teams identity services that may indicate Backdoor.Turn or similar malware abusing TURN relay infrastructure for C2. DragonForce uses anonymous tokens to establish QUIC sessions through Teams TURN servers.",
    query: `title: Teams TURN Relay Anonymous Token Abuse
status: experimental
description: Detects processes requesting anonymous Teams visitor tokens, indicative of Backdoor.Turn TURN relay C2
references:
    - https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor
author: TrustedSec Threat Intel
date: 2026/06/24
logsource:
    category: proxy
    product: any
detection:
    selection_url:
        cs-uri|contains:
            - 'api.skype.com'
            - 'teams.microsoft.com/api'
            - 'edge.skype.com'
    selection_anonymous:
        cs-uri|contains:
            - 'visitor'
            - 'anonymousToken'
            - 'anonymous-join'
    filter_browser:
        c-useragent|contains:
            - 'Mozilla'
            - 'Chrome'
            - 'Edge'
            - 'Teams'
    condition: selection_url and selection_anonymous and not filter_browser
level: high
falsepositives:
    - Custom Teams integration bots
    - Legitimate automation using Teams APIs`,
    language: "sigma",
    techniqueExternalId: "T1102",
    category: "c2-evasion",
    source: "TrustedSec Threat Intel",
    severity: "high",
    tags: ["dragonforce", "turn-relay", "teams", "backdoor-turn", "c2"],
  },
  {
    name: "TURN Relay C2 - Unusual QUIC/UDP to Microsoft Relay IPs",
    description:
      "Detects anomalous QUIC or UDP traffic patterns to Microsoft Teams TURN relay IP ranges from non-browser processes. Backdoor.Turn establishes QUIC sessions through TURN relays for covert C2.",
    query: `DeviceNetworkEvents
| where RemotePort in (443, 3478, 3479, 3480, 3481)
| where RemoteUrl has_any ("turn.teams.microsoft.com", "relay.teams.microsoft.com",
                            "turn3.teams.microsoft.com", "13.107.64", "52.112.")
| where InitiatingProcessFileName !in~
    ("teams.exe", "ms-teams.exe", "msedge.exe", "chrome.exe", "firefox.exe",
     "outlook.exe", "microsoftteams.exe", "teams", "slack.exe")
| where InitiatingProcessFileName !endswith ".dll"
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          RemoteUrl, RemotePort, RemoteIP, Protocol
| summarize ConnectionCount = count(),
            DistinctRemoteIPs = dcount(RemoteIP),
            Processes = make_set(InitiatingProcessFileName)
            by DeviceName, InitiatingProcessFolderPath, bin(TimeGenerated, 1h)
| where ConnectionCount >= 5
| sort by ConnectionCount desc`,
    language: "kql",
    techniqueExternalId: "T1090.002",
    category: "c2-evasion",
    source: "Microsoft Defender for Endpoint",
    severity: "critical",
    tags: ["dragonforce", "turn-relay", "quic", "teams", "backdoor-turn", "c2"],
  },
  {
    name: "Backdoor.Turn - DLL Sideloading via VirtualBox Binary",
    description:
      "Detects DLL sideloading pattern used by DragonForce where a renamed VirtualBox executable (DbgView64.exe) loads a malicious vboxrt.dll. This is the delivery mechanism for Backdoor.Turn.",
    query: `title: Backdoor.Turn VirtualBox DLL Sideloading
status: experimental
description: Detects DLL sideloading via renamed VirtualBox binary loading malicious vboxrt.dll
references:
    - https://www.security.com/threat-intelligence/dragonforce-msteams-backdoor
author: TrustedSec Threat Intel
date: 2026/06/24
logsource:
    category: image_load
    product: windows
detection:
    selection_dll:
        ImageLoaded|endswith: '\\vboxrt.dll'
    filter_legitimate:
        ImageLoaded|contains:
            - '\\Oracle\\VirtualBox\\'
            - '\\Program Files\\Oracle\\'
    selection_process:
        Image|endswith:
            - '\\DbgView64.exe'
            - '\\DbgView.exe'
    condition: (selection_dll and not filter_legitimate) or (selection_dll and selection_process)
level: critical
falsepositives:
    - Portable VirtualBox installations`,
    language: "sigma",
    techniqueExternalId: "T1574.002",
    category: "c2-evasion",
    source: "TrustedSec Threat Intel",
    severity: "critical",
    tags: ["dragonforce", "dll-sideloading", "virtualbox", "backdoor-turn"],
  },
  {
    name: "DragonForce BYOVD EDR Killer - Vulnerable Driver Loading",
    description:
      "Detects loading of known vulnerable drivers used by DragonForce for BYOVD-based EDR/AV termination, including Topaz Antifraud, Tower of Fantasy, K7 Security, and Huawei audio drivers.",
    query: `DeviceEvents
| where ActionType == "DriverLoad"
| where SHA256 in~
    ("b6628d201c2a68d2a3de2a87de7a5acfe21b101a97928e1c8d5c82102d967383",
     "b16e217cdca19e00c1b68bdfb28ead53b20adeabd6edcd91542f9fbf48942877",
     "252a8bb2eb9c96c5e6cc7cab822e2ed0d508032f9350351221781684e86c03ab",
     "8a4033425d36cd99fe23e6faef9764fbf555f362ebdb5b72379342fbbe4c5531",
     "087f002df0a02c8c74f3ba5cd99cf29fb9efff38bf57b3d808e34a5dd4200dd2")
| extend DriverName = FileName
| where DriverName has_any ("wsftprm.sys", "Gamedriverx64.sys", "K7RKScan.sys",
                             "HWAuidoOs2Ec.sys")
| project TimeGenerated, DeviceName, DriverName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated desc`,
    language: "kql",
    techniqueExternalId: "T1562.001",
    category: "defense-evasion",
    source: "Microsoft Defender for Endpoint",
    severity: "critical",
    tags: ["dragonforce", "byovd", "edr-killer", "vulnerable-driver", "defense-evasion"],
  },

  // =========================================================================
  // CREDENTIAL ACCESS
  // =========================================================================
  {
    name: "LSASS Memory Dump via Procdump or Task Manager",
    description:
      "Detects LSASS credential dumping using procdump, comsvcs.dll MiniDump, or Task Manager. Attackers target lsass.exe to extract NTLM hashes and Kerberos tickets from memory.",
    query: `title: LSASS Memory Dump Detection
id: 7a8b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d
status: stable
level: critical
description: >
  Detects credential dumping from LSASS process memory using common
  tools and techniques including procdump, comsvcs.dll, and direct
  process access patterns.
author: TrustedSec
date: 2024/05/15
modified: 2025/06/01
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://www.trustedsec.com
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_procdump:
    Image|endswith: '\\\\procdump.exe'
    CommandLine|contains:
      - 'lsass'
  selection_procdump64:
    Image|endswith: '\\\\procdump64.exe'
    CommandLine|contains:
      - 'lsass'
  selection_comsvcs:
    Image|endswith: '\\\\rundll32.exe'
    CommandLine|contains|all:
      - 'comsvcs.dll'
      - 'MiniDump'
  selection_taskmgr:
    Image|endswith: '\\\\taskmgr.exe'
    CommandLine|contains:
      - 'lsass'
  selection_nanodump:
    CommandLine|contains:
      - 'nanodump'
      - 'NanoDump'
  condition: 1 of selection_*
falsepositives:
  - Legitimate debugging by system administrators
  - Crash dump collection tools`,
    language: "sigma",
    techniqueExternalId: "T1003.001",
    category: "credential-access",
    source: "TrustedSec Custom",
    severity: "critical",
    tags: ["lsass", "credential-dumping", "procdump", "mimikatz", "comsvcs"],
  },

  {
    name: "LSASS Access via Direct System Calls",
    description:
      "Detects suspicious access to the LSASS process using direct syscalls or NTAPI calls, which bypass user-mode API hooks used by EDR solutions. Common in tools like NanoDump and direct syscall implants.",
    query: `DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in (
    "MsMpEng.exe", "csrss.exe", "svchost.exe", "lsass.exe",
    "services.exe", "wininit.exe", "WerFault.exe",
    "MpCmdRun.exe", "SenseIR.exe", "SenseCE.exe")
| where InitiatingProcessFolderPath !startswith "C:\\\\Program Files\\\\Windows Defender"
| where InitiatingProcessFolderPath !startswith "C:\\\\ProgramData\\\\Microsoft\\\\Windows Defender"
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessAccountName, InitiatingProcessIntegrityLevel
| summarize AccessCount = count(),
            Processes = make_set(InitiatingProcessFileName, 10)
            by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 5m)
| sort by AccessCount desc`,
    language: "kql",
    techniqueExternalId: "T1003.001",
    category: "credential-access",
    source: "Microsoft Defender for Endpoint",
    severity: "critical",
    tags: ["lsass", "credential-access", "direct-syscall", "edr-evasion"],
  },

  {
    name: "SAM Registry Hive Extraction",
    description:
      "Sigma rule detecting extraction of SAM, SYSTEM, and SECURITY registry hives using reg.exe save or esentutl.exe. Attackers extract these hives to crack local account passwords offline.",
    query: `title: SAM Registry Hive Extraction
id: 2b4c6d8e-0a1b-3c4d-5e6f-7a8b9c0d1e2f
status: stable
level: critical
description: >
  Detects extraction of SAM, SYSTEM, and SECURITY registry hives
  using built-in Windows tools for offline credential cracking.
author: TrustedSec
date: 2024/06/01
modified: 2025/05/15
references:
  - https://attack.mitre.org/techniques/T1003/002/
tags:
  - attack.credential_access
  - attack.t1003.002
logsource:
  category: process_creation
  product: windows
detection:
  selection_reg_save:
    Image|endswith: '\\\\reg.exe'
    CommandLine|contains:
      - 'save'
      - 'export'
    CommandLine|contains:
      - 'HKLM\\\\SAM'
      - 'HKLM\\\\SYSTEM'
      - 'HKLM\\\\SECURITY'
      - 'hklm\\\\sam'
      - 'hklm\\\\system'
      - 'hklm\\\\security'
  selection_esentutl:
    Image|endswith: '\\\\esentutl.exe'
    CommandLine|contains:
      - 'ntds.dit'
      - 'SAM'
      - 'SYSTEM'
      - 'SECURITY'
  selection_shadow_copy:
    CommandLine|contains|all:
      - 'copy'
      - '\\\\Windows\\\\System32\\\\config\\\\'
    CommandLine|contains:
      - 'SAM'
      - 'SYSTEM'
      - 'SECURITY'
  condition: 1 of selection_*
falsepositives:
  - Legitimate backup operations
  - Disaster recovery procedures`,
    language: "sigma",
    techniqueExternalId: "T1003.002",
    category: "credential-access",
    source: "TrustedSec Custom",
    severity: "critical",
    tags: ["sam", "registry-hive", "credential-access", "offline-cracking"],
  },

  {
    name: "Credential File Harvesting",
    description:
      "Detects access to common credential storage files such as browser password databases, SSH keys, cloud credential files, and password manager databases.",
    query: `DeviceFileEvents
| where ActionType in ("FileAccessed", "FileRead", "FileModified")
| where FileName in~ (
    "Login Data", "logins.json", "key3.db", "key4.db", "cookies.sqlite",
    "id_rsa", "id_ed25519", "id_ecdsa", "known_hosts", "authorized_keys",
    "credentials", "credentials.json", ".aws/credentials",
    "accessTokens.json", "azureProfile.json", "TokenCache.dat",
    "KeePass.config.xml", "Database.kdbx",
    "ntds.dit", "NTDS.dit")
    or FolderPath has_any (
    "\\\\.ssh\\\\", "\\\\Vault\\\\", "\\\\Credentials\\\\",
    "\\\\.azure\\\\", "\\\\.aws\\\\", "\\\\.gcloud\\\\")
| where InitiatingProcessFileName !in (
    "explorer.exe", "SearchIndexer.exe", "MsMpEng.exe",
    "svchost.exe", "chrome.exe", "firefox.exe", "msedge.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FileName, FolderPath,
          InitiatingProcessAccountName
| summarize FileCount = count(),
            DistinctFiles = dcount(FileName),
            Files = make_set(FileName, 20)
            by DeviceName, InitiatingProcessFileName,
               InitiatingProcessAccountName, bin(Timestamp, 10m)
| where DistinctFiles >= 3
| sort by DistinctFiles desc`,
    language: "kql",
    techniqueExternalId: "T1552.001",
    category: "credential-access",
    source: "Microsoft Defender for Endpoint",
    severity: "high",
    tags: ["credential-harvesting", "browser-passwords", "ssh-keys", "cloud-credentials"],
  },

  {
    name: "NTDS.dit Active Directory Database Extraction",
    description:
      "Detects extraction of the NTDS.dit Active Directory database using ntdsutil, volume shadow copies, or direct copy operations. This contains all domain password hashes.",
    query: `index=wineventlog sourcetype="WinEventLog:Security"
  (EventCode=4688 OR EventCode=1)
  (CommandLine="*ntdsutil*" OR CommandLine="*ifm*" OR CommandLine="*create full*"
   OR CommandLine="*vssadmin*create*shadow*"
   OR CommandLine="*copy*ntds.dit*"
   OR CommandLine="*esentutl*ntds*")
| eval technique=case(
    match(CommandLine, "(?i)ntdsutil"), "ntdsutil_ifm",
    match(CommandLine, "(?i)vssadmin"), "shadow_copy",
    match(CommandLine, "(?i)esentutl"), "esentutl_copy",
    match(CommandLine, "(?i)copy.*ntds"), "direct_copy",
    1==1, "unknown")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(CommandLine) as commands
    values(technique) as techniques
    by host, user, ParentProcessName
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"),
       lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| sort - count`,
    language: "splunk",
    techniqueExternalId: "T1003.003",
    category: "credential-access",
    source: "Splunk Security Content",
    severity: "critical",
    tags: ["ntds", "active-directory", "credential-dumping", "domain-dominance"],
  },

  {
    name: "Windows Credential Manager Access",
    description:
      "Sigma rule detecting access to Windows Credential Manager vaults via vaultcmd.exe or cmdkey.exe, which attackers use to enumerate and extract stored credentials.",
    query: `title: Windows Credential Manager Enumeration
id: 3c5d7e9f-1a2b-4c6d-8e0f-2a3b5c7d9e1f
status: stable
level: medium
description: >
  Detects enumeration of Windows Credential Manager using vaultcmd
  or cmdkey to list stored credentials for RDP, web, and network resources.
author: TrustedSec
date: 2024/07/01
modified: 2025/04/15
references:
  - https://attack.mitre.org/techniques/T1555/004/
tags:
  - attack.credential_access
  - attack.t1555.004
logsource:
  category: process_creation
  product: windows
detection:
  selection_vaultcmd:
    Image|endswith: '\\\\vaultcmd.exe'
    CommandLine|contains:
      - '/list'
      - '/listcreds'
      - '/listproperties'
  selection_cmdkey:
    Image|endswith: '\\\\cmdkey.exe'
    CommandLine|contains:
      - '/list'
  selection_credman_dir:
    CommandLine|contains:
      - 'Credentials\\\\'
      - 'Vault\\\\'
      - 'Protect\\\\S-1-'
  condition: 1 of selection_*
falsepositives:
  - System administrators checking stored credentials
  - Credential management scripts`,
    language: "sigma",
    techniqueExternalId: "T1555.004",
    category: "credential-access",
    source: "TrustedSec Custom",
    severity: "medium",
    tags: ["credential-manager", "vaultcmd", "cmdkey", "credential-access"],
  },

  // =========================================================================
  // PERSISTENCE
  // =========================================================================
  {
    name: "Scheduled Task Creation for Persistence",
    description:
      "Detects creation of scheduled tasks via schtasks.exe or the Task Scheduler API with suspicious attributes such as execution from temp directories, encoded commands, or network paths.",
    query: `title: Suspicious Scheduled Task Creation
id: 4d6e8f0a-2b3c-5d7e-9f1a-3b4c6d8e0f2a
status: stable
level: high
description: >
  Detects scheduled task creation with suspicious attributes commonly
  used for persistence by malware and red team tools.
author: TrustedSec
date: 2024/04/01
modified: 2025/05/20
references:
  - https://attack.mitre.org/techniques/T1053/005/
tags:
  - attack.persistence
  - attack.execution
  - attack.t1053.005
logsource:
  category: process_creation
  product: windows
detection:
  selection_schtasks:
    Image|endswith: '\\\\schtasks.exe'
    CommandLine|contains: '/create'
  selection_suspicious_path:
    CommandLine|contains:
      - '\\\\Temp\\\\'
      - '\\\\tmp\\\\'
      - '\\\\AppData\\\\Local\\\\Temp'
      - '\\\\ProgramData\\\\'
      - '\\\\Users\\\\Public\\\\'
      - '%APPDATA%'
      - '%TEMP%'
  selection_suspicious_cmd:
    CommandLine|contains:
      - 'powershell'
      - 'cmd /c'
      - 'mshta'
      - 'rundll32'
      - 'regsvr32'
      - 'certutil'
      - 'bitsadmin'
      - '-enc '
      - '-EncodedCommand'
      - 'FromBase64'
      - 'http://'
      - 'https://'
  condition: selection_schtasks and (selection_suspicious_path or selection_suspicious_cmd)
falsepositives:
  - Software installation scripts
  - Legitimate update mechanisms`,
    language: "sigma",
    techniqueExternalId: "T1053.005",
    category: "persistence",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["scheduled-task", "persistence", "schtasks", "execution"],
  },

  {
    name: "Registry Run Key Persistence",
    description:
      "Detects modification of registry Run and RunOnce keys used for persistence. Monitors for additions by non-standard processes that execute on user logon or system boot.",
    query: `DeviceRegistryEvents
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has_any (
    "\\\\CurrentVersion\\\\Run",
    "\\\\CurrentVersion\\\\RunOnce",
    "\\\\CurrentVersion\\\\RunServices",
    "\\\\CurrentVersion\\\\RunServicesOnce",
    "\\\\CurrentVersion\\\\Explorer\\\\User Shell Folders",
    "\\\\CurrentVersion\\\\Explorer\\\\Shell Folders",
    "\\\\CurrentVersion\\\\Winlogon\\\\Shell",
    "\\\\CurrentVersion\\\\Winlogon\\\\Userinit",
    "\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run")
| where InitiatingProcessFileName !in (
    "explorer.exe", "msiexec.exe", "setup.exe", "TiWorker.exe",
    "TrustedInstaller.exe", "svchost.exe", "OneDriveSetup.exe")
| extend RegistryValue = RegistryValueData
| where RegistryValue has_any (
    "powershell", "cmd.exe", "mshta", "rundll32", "regsvr32",
    "certutil", "wscript", "cscript", "\\\\Temp\\\\", "\\\\tmp\\\\",
    "AppData", "ProgramData", "http://", "https://")
    or RegistryValue !startswith "C:\\\\Program Files"
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessAccountName
| sort by Timestamp desc`,
    language: "kql",
    techniqueExternalId: "T1547.001",
    category: "persistence",
    source: "Microsoft Defender for Endpoint",
    severity: "high",
    tags: ["registry", "run-key", "persistence", "autostart"],
  },

  {
    name: "Startup Folder Persistence",
    description:
      "Sigma rule detecting the placement of files in Windows Startup folders for persistence. Monitors both user-specific and common startup directories for suspicious file types.",
    query: `title: Startup Folder File Drop
id: 5e7f9a1b-3c4d-6e8f-0a2b-4c5d7e9f1a3b
status: stable
level: high
description: >
  Detects files placed in Windows Startup folders for user logon
  persistence, including scripts, executables, and shortcut files.
author: TrustedSec
date: 2024/08/15
modified: 2025/06/01
references:
  - https://attack.mitre.org/techniques/T1547/001/
tags:
  - attack.persistence
  - attack.t1547.001
logsource:
  category: file_event
  product: windows
detection:
  selection_startup_path:
    TargetFilename|contains:
      - '\\\\Start Menu\\\\Programs\\\\Startup\\\\'
      - '\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\'
  selection_file_types:
    TargetFilename|endswith:
      - '.exe'
      - '.dll'
      - '.bat'
      - '.cmd'
      - '.vbs'
      - '.vbe'
      - '.js'
      - '.jse'
      - '.wsf'
      - '.wsh'
      - '.ps1'
      - '.lnk'
      - '.hta'
      - '.scr'
  condition: selection_startup_path and selection_file_types
falsepositives:
  - Legitimate application installers adding startup entries
  - IT deployment tools`,
    language: "sigma",
    techniqueExternalId: "T1547.001",
    category: "persistence",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["startup-folder", "persistence", "autostart", "file-drop"],
  },

  {
    name: "WMI Event Subscription Persistence",
    description:
      "Detects WMI event subscription creation used for persistence. Attackers create WMI event filters and consumers that execute payloads when specific system events occur.",
    query: `DeviceEvents
| where ActionType in ("WmiBindEventFilterToConsumer",
                        "WmiCreateEventConsumer",
                        "WmiCreateEventFilter")
| where InitiatingProcessFileName !in (
    "svchost.exe", "msiexec.exe", "ccmexec.exe",
    "TiWorker.exe", "MpCmdRun.exe")
| project Timestamp, DeviceName, ActionType,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          InitiatingProcessAccountName,
          AdditionalFields
| extend WMIDetails = parse_json(AdditionalFields)
| summarize EventCount = count(),
            Actions = make_set(ActionType, 10)
            by DeviceName, InitiatingProcessFileName,
               InitiatingProcessAccountName, bin(Timestamp, 5m)
| sort by EventCount desc`,
    language: "kql",
    techniqueExternalId: "T1546.003",
    category: "persistence",
    source: "Microsoft Defender for Endpoint",
    severity: "high",
    tags: ["wmi", "event-subscription", "persistence", "fileless"],
  },

  {
    name: "COM Object Hijacking",
    description:
      "Sigma rule detecting COM object hijacking by monitoring for modifications to CLSID registry entries that redirect COM object loading to attacker-controlled DLLs.",
    query: `title: COM Object Hijacking Detection
id: 6f8a0b2c-4d5e-7f9a-1b3c-5d6e8f0a2b4c
status: experimental
level: high
description: >
  Detects COM object hijacking by identifying suspicious modifications
  to CLSID InprocServer32 and LocalServer32 registry keys that redirect
  COM object instantiation to malicious binaries.
author: TrustedSec
date: 2024/09/01
modified: 2025/05/01
references:
  - https://attack.mitre.org/techniques/T1546/015/
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1546.015
logsource:
  category: registry_set
  product: windows
detection:
  selection_clsid:
    TargetObject|contains:
      - '\\\\CLSID\\\\'
      - '\\\\Classes\\\\CLSID\\\\'
    TargetObject|endswith:
      - '\\\\InprocServer32\\\\(Default)'
      - '\\\\LocalServer32\\\\(Default)'
      - '\\\\InprocServer32\\\\'
      - '\\\\LocalServer32\\\\'
  filter_legitimate:
    Details|startswith:
      - 'C:\\\\Windows\\\\System32\\\\'
      - 'C:\\\\Windows\\\\SysWOW64\\\\'
      - 'C:\\\\Program Files\\\\'
      - 'C:\\\\Program Files (x86)\\\\'
  selection_suspicious:
    Details|contains:
      - '\\\\Users\\\\'
      - '\\\\Temp\\\\'
      - '\\\\AppData\\\\'
      - '\\\\ProgramData\\\\'
      - '\\\\Downloads\\\\'
  condition: selection_clsid and selection_suspicious and not filter_legitimate
falsepositives:
  - Software installation to non-standard paths
  - Portable applications`,
    language: "sigma",
    techniqueExternalId: "T1546.015",
    category: "persistence",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["com-hijacking", "clsid", "persistence", "privilege-escalation"],
  },

  {
    name: "DLL Search Order Hijacking via Phantom DLL",
    description:
      "Detects DLL search order hijacking where a malicious DLL is placed in the application directory to be loaded before the legitimate system DLL. Monitors for DLL loads from non-standard paths.",
    query: `index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7
| where (ImageLoaded LIKE "%\\\\Users\\\\%" OR ImageLoaded LIKE "%\\\\Temp\\\\%"
         OR ImageLoaded LIKE "%\\\\ProgramData\\\\%" OR ImageLoaded LIKE "%\\\\AppData\\\\%")
| where NOT (ImageLoaded LIKE "%\\\\Program Files\\\\%" OR ImageLoaded LIKE "%\\\\Windows\\\\%")
| eval dll_name=mvindex(split(ImageLoaded, "\\\\"), -1)
| where dll_name IN ("version.dll", "winhttp.dll", "dbghelp.dll", "dbgcore.dll",
                      "WTSAPI32.dll", "wbemcomn.dll", "crypt32.dll", "netapi32.dll",
                      "userenv.dll", "dwmapi.dll", "uxtheme.dll", "propsys.dll",
                      "profapi.dll", "cryptsp.dll", "msasn1.dll")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(Image) as loading_processes
    values(ImageLoaded) as loaded_dlls
    by host, User, dll_name
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"),
       lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| where count > 0
| sort - count`,
    language: "splunk",
    techniqueExternalId: "T1574.001",
    category: "persistence",
    source: "Splunk Security Content",
    severity: "high",
    tags: ["dll-hijacking", "search-order", "persistence", "defense-evasion"],
  },

  {
    name: "Windows Service Creation for Persistence",
    description:
      "Detects creation of new Windows services via sc.exe or the Service Control Manager that may indicate persistence establishment. Focuses on services with suspicious binary paths.",
    query: `title: Suspicious Windows Service Installation
id: 7a9b1c3d-5e6f-8a0b-2c4d-6e7f9a1b3c5d
status: stable
level: high
description: >
  Detects new Windows service creation with suspicious binary paths
  commonly used for persistence and privilege escalation.
author: TrustedSec
date: 2024/03/15
modified: 2025/04/10
references:
  - https://attack.mitre.org/techniques/T1543/003/
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1543.003
logsource:
  product: windows
  service: system
detection:
  selection_event:
    EventID: 7045
  selection_suspicious_path:
    ImagePath|contains:
      - '\\\\Temp\\\\'
      - '\\\\tmp\\\\'
      - '\\\\Users\\\\Public\\\\'
      - '\\\\AppData\\\\'
      - '\\\\ProgramData\\\\'
      - '%COMSPEC%'
      - 'cmd.exe /c'
      - 'powershell'
      - 'mshta'
      - 'rundll32'
      - 'regsvr32'
      - 'http://'
      - 'https://'
  condition: selection_event and selection_suspicious_path
falsepositives:
  - Legitimate software installation
  - Third-party management agents`,
    language: "sigma",
    techniqueExternalId: "T1543.003",
    category: "persistence",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["service-creation", "persistence", "privilege-escalation", "sc.exe"],
  },

  // =========================================================================
  // PRIVILEGE ESCALATION
  // =========================================================================
  {
    name: "Token Manipulation - Token Impersonation",
    description:
      "Detects access token manipulation techniques including token duplication and impersonation. Attackers use these to escalate privileges by stealing tokens from higher-privileged processes.",
    query: `DeviceEvents
| where ActionType in ("OpenProcessApiCall", "DuplicateTokenApiCall")
| where InitiatingProcessIntegrityLevel in ("Medium", "MediumPlus")
| where AdditionalFields has "SeImpersonatePrivilege"
    or AdditionalFields has "SeAssignPrimaryTokenPrivilege"
| where InitiatingProcessFileName !in (
    "svchost.exe", "services.exe", "lsass.exe", "csrss.exe",
    "MsMpEng.exe", "WerFault.exe", "taskhostw.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          FileName, ActionType, AdditionalFields
| summarize ActionCount = count(),
            Actions = make_set(ActionType, 10),
            TargetProcesses = make_set(FileName, 10)
            by DeviceName, InitiatingProcessFileName,
               InitiatingProcessAccountName, bin(Timestamp, 5m)
| where ActionCount >= 2
| sort by ActionCount desc`,
    language: "kql",
    techniqueExternalId: "T1134.001",
    category: "privilege-escalation",
    source: "Microsoft Defender for Endpoint",
    severity: "high",
    tags: ["token-manipulation", "impersonation", "privilege-escalation", "potato"],
  },

  {
    name: "UAC Bypass via Eventvwr.exe",
    description:
      "Sigma rule detecting UAC bypass using eventvwr.exe and mscfile registry hijacking. This technique allows medium-integrity processes to spawn high-integrity processes without a UAC prompt.",
    query: `title: UAC Bypass via Event Viewer (mscfile)
id: 8b0c2d4e-6f7a-9b1c-3d5e-7f8a0b2c4d6e
status: stable
level: critical
description: >
  Detects UAC bypass using eventvwr.exe registry hijacking where the
  default handler for .msc files is modified to execute an arbitrary command
  at high integrity.
author: TrustedSec
date: 2024/05/01
modified: 2025/06/10
references:
  - https://attack.mitre.org/techniques/T1548/002/
  - https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
tags:
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1548.002
logsource:
  category: registry_set
  product: windows
detection:
  selection_eventvwr:
    TargetObject|endswith:
      - '\\\\mscfile\\\\shell\\\\open\\\\command\\\\(Default)'
      - '\\\\ms-settings\\\\shell\\\\open\\\\command\\\\(Default)'
  selection_fodhelper:
    TargetObject|endswith:
      - '\\\\ms-settings\\\\Shell\\\\Open\\\\command\\\\DelegateExecute'
  selection_computerdefaults:
    TargetObject|contains: '\\\\ms-settings\\\\shell\\\\open\\\\command'
    Details|contains:
      - 'cmd'
      - 'powershell'
      - 'mshta'
  condition: 1 of selection_*
falsepositives:
  - Very unlikely in legitimate use`,
    language: "sigma",
    techniqueExternalId: "T1548.002",
    category: "privilege-escalation",
    source: "TrustedSec Custom",
    severity: "critical",
    tags: ["uac-bypass", "eventvwr", "fodhelper", "privilege-escalation"],
  },

  {
    name: "Named Pipe Impersonation - Potato Attacks",
    description:
      "Detects named pipe impersonation attacks (JuicyPotato, SweetPotato, PrintSpoofer, GodPotato) where a local service account impersonates a privileged token through NTLM authentication over named pipes.",
    query: `DeviceProcessEvents
| where FileName in~ ("JuicyPotato.exe", "JuicyPotatoNG.exe",
                        "SweetPotato.exe", "PrintSpoofer.exe",
                        "PrintSpoofer64.exe", "GodPotato.exe",
                        "SharpEfsPotato.exe", "RoguePotato.exe",
                        "CoercedPotato.exe")
    or ProcessCommandLine has_any (
    "JuicyPotato", "SweetPotato", "PrintSpoofer",
    "GodPotato", "RoguePotato", "SharpEfsPotato",
    "EfsPotato", "CoercedPotato")
    or (ProcessCommandLine has "CreateProcessWithToken"
        and ProcessCommandLine has_any ("-p cmd", "-p powershell"))
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FolderPath
| sort by Timestamp desc`,
    language: "kql",
    techniqueExternalId: "T1134.001",
    category: "privilege-escalation",
    source: "Microsoft Defender for Endpoint",
    severity: "critical",
    tags: ["potato-attack", "named-pipe", "impersonation", "privilege-escalation"],
  },

  {
    name: "Print Spooler Exploitation (PrintNightmare)",
    description:
      "Detects exploitation of the Print Spooler service (CVE-2021-34527, CVE-2021-1675) by monitoring for suspicious DLL loads by spoolsv.exe and abnormal printer driver installations.",
    query: `title: PrintNightmare Exploitation Detection
id: 9c1d3e5f-7a8b-0c2d-4e6f-8a9b1c3d5e7f
status: stable
level: critical
description: >
  Detects potential PrintNightmare exploitation by monitoring for
  suspicious DLL loads by the print spooler service and unauthorized
  printer driver installations.
author: TrustedSec
date: 2024/02/15
modified: 2025/03/01
references:
  - https://attack.mitre.org/techniques/T1068/
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
tags:
  - attack.privilege_escalation
  - attack.t1068
logsource:
  category: image_load
  product: windows
detection:
  selection_spoolsv:
    Image|endswith: '\\\\spoolsv.exe'
  selection_dll_path:
    ImageLoaded|contains:
      - '\\\\Windows\\\\System32\\\\spool\\\\drivers\\\\x64\\\\3\\\\'
      - '\\\\Windows\\\\System32\\\\spool\\\\drivers\\\\W32X86\\\\3\\\\'
  filter_known:
    ImageLoaded|endswith:
      - '\\\\UNIDRV.DLL'
      - '\\\\unidrvui.dll'
      - '\\\\PrintConfig.dll'
      - '\\\\PSCRIPT5.DLL'
  selection_unsigned:
    Signed: 'false'
  condition: selection_spoolsv and selection_dll_path and selection_unsigned and not filter_known
falsepositives:
  - Legitimate third-party printer driver installations`,
    language: "sigma",
    techniqueExternalId: "T1068",
    category: "privilege-escalation",
    source: "TrustedSec Custom",
    severity: "critical",
    tags: ["printnightmare", "print-spooler", "cve-2021-34527", "privilege-escalation"],
  },

  {
    name: "Unquoted Service Path Exploitation",
    description:
      "Detects potential exploitation of unquoted service paths where an attacker places a malicious executable in a directory that gets resolved before the intended service binary.",
    query: `index=wineventlog sourcetype="WinEventLog:System" EventCode=7045
| regex ImagePath="^[A-Za-z]:\\\\[^\\\"]+\\s[^\\\"]+\\\\.+\\.exe"
| where NOT match(ImagePath, "^\\\"")
| where NOT match(ImagePath, "^[A-Za-z]:\\\\Windows\\\\")
| eval path_parts=split(ImagePath, "\\\\")
| eval service_dir=mvjoin(mvindex(path_parts, 0, mvcount(path_parts)-2), "\\\\")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(ImagePath) as service_paths
    values(ServiceName) as service_names
    by host
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"),
       lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| sort - count`,
    language: "splunk",
    techniqueExternalId: "T1574.009",
    category: "privilege-escalation",
    source: "Splunk Security Content",
    severity: "medium",
    tags: ["unquoted-path", "service-path", "privilege-escalation", "persistence"],
  },

  // =========================================================================
  // DEFENSE EVASION
  // =========================================================================
  {
    name: "AMSI Bypass Detection",
    description:
      "Detects attempts to bypass the Antimalware Scan Interface (AMSI) through common PowerShell techniques including amsiInitFailed patching, reflection-based disabling, and amsi.dll manipulation.",
    query: `title: AMSI Bypass Attempt Detection
id: 0a2b4c6d-8e0f-1a3b-5c7d-9e0f2a4b6c8d
status: stable
level: critical
description: >
  Detects common AMSI bypass techniques used by attackers and red teams
  to disable PowerShell script scanning and execute malicious content
  without detection.
author: TrustedSec
date: 2024/06/01
modified: 2025/06/15
references:
  - https://attack.mitre.org/techniques/T1562/001/
tags:
  - attack.defense_evasion
  - attack.t1562.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_powershell:
    Image|endswith:
      - '\\\\powershell.exe'
      - '\\\\pwsh.exe'
  selection_amsi_bypass:
    CommandLine|contains:
      - 'amsiInitFailed'
      - 'AmsiUtils'
      - 'amsiContext'
      - 'AmsiScanBuffer'
      - 'amsi.dll'
      - 'SetValue($null,$true)'
      - 'Bypass.AMSI'
      - 'Disable-Amsi'
      - 'am]si'
      - 'a]msiI]ni'
  selection_scriptblock:
    ScriptBlockText|contains:
      - 'amsiInitFailed'
      - '[Runtime.InteropServices.Marshal]'
      - 'AmsiScanBuffer'
      - 'VirtualProtect'
  condition: (selection_powershell and selection_amsi_bypass) or selection_scriptblock
falsepositives:
  - Security tool testing
  - AMSI debugging`,
    language: "sigma",
    techniqueExternalId: "T1562.001",
    category: "defense-evasion",
    source: "TrustedSec Custom",
    severity: "critical",
    tags: ["amsi", "bypass", "defense-evasion", "powershell", "antimalware"],
  },

  {
    name: "ETW Patching and Tampering",
    description:
      "Detects attempts to patch or disable Event Tracing for Windows (ETW) through API hooking, provider disabling, or direct memory patching. This blinds security tools that depend on ETW telemetry.",
    query: `DeviceEvents
| where ActionType == "TamperingAttempt"
    or (ActionType == "RegistryValueSet"
        and RegistryKey has "Microsoft\\\\Windows\\\\CurrentVersion\\\\WINEVT")
| union (
    DeviceProcessEvents
    | where ProcessCommandLine has_any (
        "EtwEventWrite",
        "NtTraceEvent",
        "logman stop",
        "logman delete",
        "wevtutil cl",
        "wevtutil sl /e:false",
        "Set-EtwTraceProvider",
        "Remove-EtwTraceProvider",
        "auditpol /set /subcategory",
        "auditpol /clear")
    | where ProcessCommandLine !has "auditpol /get"
)
| project Timestamp, DeviceName, ActionType,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, RegistryKey, RegistryValueData
| sort by Timestamp desc`,
    language: "kql",
    techniqueExternalId: "T1562.006",
    category: "defense-evasion",
    source: "Microsoft Defender for Endpoint",
    severity: "critical",
    tags: ["etw", "tampering", "defense-evasion", "telemetry-blind"],
  },

  {
    name: "Timestomping Detection via Sysmon",
    description:
      "Sigma rule detecting file timestamp modification (timestomping) used to evade forensic timeline analysis. Monitors for Sysmon Event ID 2 (FileCreateTime changed) with suspicious patterns.",
    query: `title: File Timestamp Modification (Timestomping)
id: 1b3c5d7e-9f0a-2b4c-6d8e-0f1a3b5c7d9e
status: stable
level: high
description: >
  Detects file creation time modification (timestomping) used to
  blend malware with legitimate files and evade forensic analysis.
author: TrustedSec
date: 2024/07/15
modified: 2025/05/10
references:
  - https://attack.mitre.org/techniques/T1070/006/
tags:
  - attack.defense_evasion
  - attack.t1070.006
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 2
  filter_trusted:
    Image|startswith:
      - 'C:\\\\Windows\\\\System32\\\\'
      - 'C:\\\\Windows\\\\SysWOW64\\\\'
      - 'C:\\\\Program Files\\\\'
      - 'C:\\\\Program Files (x86)\\\\'
    Image|endswith:
      - '\\\\svchost.exe'
      - '\\\\msiexec.exe'
      - '\\\\TiWorker.exe'
      - '\\\\setup.exe'
      - '\\\\chrome.exe'
      - '\\\\msedge.exe'
  filter_time_diff:
    Image|endswith:
      - '\\\\explorer.exe'
  condition: selection and not filter_trusted and not filter_time_diff
falsepositives:
  - File synchronization tools
  - Archive extraction tools preserving timestamps`,
    language: "sigma",
    techniqueExternalId: "T1070.006",
    category: "defense-evasion",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["timestomping", "defense-evasion", "forensic-evasion", "t1070"],
  },

  {
    name: "Indicator Removal - Event Log Clearing",
    description:
      "Detects clearing of Windows event logs using wevtutil, PowerShell Clear-EventLog, or the Event Log service recording a log clear event (1102).",
    query: `index=wineventlog (sourcetype="WinEventLog:Security" EventCode=1102)
  OR (sourcetype="WinEventLog:System" EventCode=104)
  OR (sourcetype="WinEventLog:Security" EventCode=4688
      (CommandLine="*wevtutil*cl*" OR CommandLine="*Clear-EventLog*"
       OR CommandLine="*Clear-WinEvent*" OR CommandLine="*Remove-EventLog*"))
| eval clear_method=case(
    EventCode==1102, "Security_Log_Cleared",
    EventCode==104, "System_Log_Cleared",
    match(CommandLine, "(?i)wevtutil"), "wevtutil_clear",
    match(CommandLine, "(?i)Clear-EventLog"), "PowerShell_Clear",
    1==1, "unknown")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(clear_method) as methods
    values(CommandLine) as commands
    by host, user
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"),
       lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| sort - count`,
    language: "splunk",
    techniqueExternalId: "T1070.001",
    category: "defense-evasion",
    source: "Splunk Security Content",
    severity: "high",
    tags: ["event-log-clearing", "indicator-removal", "defense-evasion", "anti-forensics"],
  },

  {
    name: "Process Hollowing Detection",
    description:
      "Detects process hollowing where a legitimate process is created in a suspended state, its memory is unmapped and replaced with malicious code. Identifies processes created with CREATE_SUSPENDED flag followed by memory write operations.",
    query: `DeviceProcessEvents
| where ActionType == "ProcessCreated"
| where InitiatingProcessFileName !in ("smss.exe", "csrss.exe", "services.exe", "svchost.exe")
| where FileName in~ ("svchost.exe", "explorer.exe", "RuntimeBroker.exe",
                        "dllhost.exe", "SearchProtocolHost.exe", "consent.exe",
                        "notepad.exe", "calc.exe", "mspaint.exe")
| where FolderPath !startswith "C:\\\\Windows\\\\System32"
    and FolderPath !startswith "C:\\\\Windows\\\\SysWOW64"
    and FolderPath !startswith "C:\\\\Windows\\\\explorer.exe"
| extend ParentChild = strcat(InitiatingProcessFileName, " -> ", FileName)
| project Timestamp, DeviceName, ParentChild, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, ProcessCommandLine,
          AccountName
| sort by Timestamp desc`,
    language: "kql",
    techniqueExternalId: "T1055.012",
    category: "defense-evasion",
    source: "Microsoft Defender for Endpoint",
    severity: "critical",
    tags: ["process-hollowing", "injection", "defense-evasion", "masquerading"],
  },

  {
    name: "Disable Windows Defender via Registry or Command",
    description:
      "Sigma rule detecting attempts to disable Windows Defender through registry modifications, PowerShell cmdlets, or group policy changes.",
    query: `title: Windows Defender Tamper Attempt
id: 2c4d6e8f-0a1b-3c5d-7e9f-1a2b4c6d8e0f
status: stable
level: critical
description: >
  Detects attempts to disable or tamper with Windows Defender through
  registry, PowerShell, or command-line modifications.
author: TrustedSec
date: 2024/04/01
modified: 2025/06/01
references:
  - https://attack.mitre.org/techniques/T1562/001/
tags:
  - attack.defense_evasion
  - attack.t1562.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_powershell:
    CommandLine|contains:
      - 'Set-MpPreference -DisableRealtimeMonitoring $true'
      - 'Set-MpPreference -DisableBehaviorMonitoring $true'
      - 'Set-MpPreference -DisableBlockAtFirstSeen $true'
      - 'Set-MpPreference -DisableIOAVProtection $true'
      - 'Set-MpPreference -DisableScriptScanning $true'
      - 'Set-MpPreference -ExclusionPath'
      - 'Set-MpPreference -ExclusionProcess'
      - 'Set-MpPreference -ExclusionExtension'
  selection_reg:
    Image|endswith: '\\\\reg.exe'
    CommandLine|contains|all:
      - 'Windows Defender'
      - 'DisableAntiSpyware'
    CommandLine|contains:
      - 'add'
      - '1'
  selection_sc:
    Image|endswith: '\\\\sc.exe'
    CommandLine|contains:
      - 'WinDefend'
      - 'stop'
      - 'disabled'
  condition: 1 of selection_*
falsepositives:
  - Legitimate IT administration for troubleshooting
  - Automated deployment scripts`,
    language: "sigma",
    techniqueExternalId: "T1562.001",
    category: "defense-evasion",
    source: "TrustedSec Custom",
    severity: "critical",
    tags: ["defender", "tamper", "disable-av", "defense-evasion"],
  },

  {
    name: "Parent PID Spoofing Detection",
    description:
      "Detects parent PID spoofing where a process is created with a fake parent process to evade process tree analysis. Identifies inconsistencies between the reported parent and actual creator.",
    query: `DeviceProcessEvents
| where InitiatingProcessParentFileName != ""
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe",
                        "rundll32.exe", "regsvr32.exe", "mshta.exe")
| where InitiatingProcessFileName !in (
    "explorer.exe", "svchost.exe", "services.exe", "winlogon.exe",
    "RuntimeBroker.exe", "sihost.exe", "taskhostw.exe")
| where InitiatingProcessFileName !endswith ".msi"
| extend SuspiciousParent = case(
    InitiatingProcessFileName =~ "svchost.exe" and FileName =~ "powershell.exe", "svchost_to_powershell",
    InitiatingProcessFileName =~ "dllhost.exe" and FileName =~ "cmd.exe", "dllhost_to_cmd",
    InitiatingProcessFileName =~ "WmiPrvSE.exe" and FileName =~ "powershell.exe", "wmi_to_powershell",
    "legitimate")
| where SuspiciousParent != "legitimate"
| project Timestamp, DeviceName, SuspiciousParent, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AccountName
| sort by Timestamp desc`,
    language: "kql",
    techniqueExternalId: "T1134.004",
    category: "defense-evasion",
    source: "Microsoft Defender for Endpoint",
    severity: "high",
    tags: ["ppid-spoofing", "parent-pid", "defense-evasion", "process-tree"],
  },

  // =========================================================================
  // DISCOVERY
  // =========================================================================
  {
    name: "Internal Network Scanning Detection",
    description:
      "Detects internal network scanning activity by monitoring for processes making connections to many distinct internal IPs on common service ports within a short timeframe.",
    query: `DeviceNetworkEvents
| where RemotePort in (21, 22, 23, 25, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 5985, 8080, 8443)
| where RemoteIPType == "Private"
| where ActionType == "ConnectionSuccess" or ActionType == "ConnectionAttempt"
| where InitiatingProcessFileName !in (
    "svchost.exe", "MsMpEng.exe", "System", "dns.exe",
    "lsass.exe", "spoolsv.exe")
| summarize DistinctIPs = dcount(RemoteIP),
            DistinctPorts = dcount(RemotePort),
            ConnectionCount = count(),
            Ports = make_set(RemotePort, 20),
            SampleIPs = make_set(RemoteIP, 20)
            by DeviceName, InitiatingProcessFileName,
               InitiatingProcessAccountName, bin(Timestamp, 5m)
| where DistinctIPs > 20 or (DistinctIPs > 5 and DistinctPorts > 3)
| extend ScanType = case(
    DistinctPorts == 1 and DistinctIPs > 20, "Horizontal_Scan",
    DistinctPorts > 5 and DistinctIPs <= 5, "Vertical_Scan",
    DistinctPorts > 3 and DistinctIPs > 5, "Network_Sweep",
    "General_Scan")
| sort by DistinctIPs desc`,
    language: "kql",
    techniqueExternalId: "T1046",
    category: "discovery",
    source: "Microsoft Defender for Endpoint",
    severity: "medium",
    tags: ["network-scan", "reconnaissance", "port-scan", "discovery"],
  },

  {
    name: "Active Directory Enumeration Tools",
    description:
      "Sigma rule detecting execution of common AD enumeration tools including BloodHound, SharpHound, ADRecon, PowerView, and other domain reconnaissance utilities.",
    query: `title: AD Enumeration Tool Execution
id: 3d5e7f9a-1b2c-4d6e-8f0a-2b3c5d7e9f1a
status: stable
level: high
description: >
  Detects execution of known Active Directory enumeration and
  reconnaissance tools used during the discovery phase of an attack.
author: TrustedSec
date: 2024/08/01
modified: 2025/05/15
references:
  - https://attack.mitre.org/techniques/T1087/002/
tags:
  - attack.discovery
  - attack.t1087.002
logsource:
  category: process_creation
  product: windows
detection:
  selection_tools:
    Image|endswith:
      - '\\\\SharpHound.exe'
      - '\\\\BloodHound.exe'
      - '\\\\ADRecon.exe'
      - '\\\\PingCastle.exe'
      - '\\\\ldapdomaindump'
      - '\\\\windapsearch'
      - '\\\\ADFind.exe'
      - '\\\\dsquery.exe'
      - '\\\\adfind.exe'
  selection_powershell_modules:
    CommandLine|contains:
      - 'Import-Module.*PowerView'
      - 'Import-Module.*Recon'
      - 'Get-DomainUser'
      - 'Get-DomainGroup'
      - 'Get-DomainComputer'
      - 'Get-DomainController'
      - 'Get-DomainTrust'
      - 'Get-NetUser'
      - 'Get-NetGroup'
      - 'Get-NetComputer'
      - 'Find-LocalAdminAccess'
      - 'Invoke-UserHunter'
      - 'Invoke-ShareFinder'
      - 'Invoke-ACLScanner'
  selection_sharphound_cmdline:
    CommandLine|contains:
      - '-CollectionMethod All'
      - '--CollectionMethods'
      - 'Invoke-BloodHound'
      - 'SharpHound.ps1'
  condition: 1 of selection_*
falsepositives:
  - Authorized penetration testing
  - IT security assessments`,
    language: "sigma",
    techniqueExternalId: "T1087.002",
    category: "discovery",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["bloodhound", "sharphound", "ad-enumeration", "powerview", "discovery"],
  },

  {
    name: "Cloud Resource Discovery - Azure/AWS Enumeration",
    description:
      "Detects cloud resource enumeration patterns in Azure and AWS that may indicate post-compromise reconnaissance, including listing subscriptions, resource groups, VMs, storage, and IAM resources.",
    query: `AzureActivity
| where OperationNameValue has_any (
    "Microsoft.Resources/subscriptions/read",
    "Microsoft.Resources/subscriptions/resourceGroups/read",
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Storage/storageAccounts/listKeys/action",
    "Microsoft.KeyVault/vaults/read",
    "Microsoft.KeyVault/vaults/secrets/read",
    "Microsoft.Authorization/roleAssignments/read",
    "Microsoft.ManagedIdentity/userAssignedIdentities/read")
| summarize OperationCount = count(),
            DistinctOps = dcount(OperationNameValue),
            Operations = make_set(OperationNameValue, 20),
            DistinctResources = dcount(ResourceId)
            by Caller, CallerIpAddress, bin(TimeGenerated, 15m)
| where DistinctOps >= 4 and OperationCount >= 10
| extend EnumerationScore = DistinctOps * 3 + DistinctResources * 2
| sort by EnumerationScore desc`,
    language: "kql",
    techniqueExternalId: "T1580",
    category: "discovery",
    source: "Microsoft Sentinel",
    severity: "medium",
    tags: ["cloud-discovery", "azure", "enumeration", "resource-mapping"],
  },

  {
    name: "System Information Discovery Commands",
    description:
      "Splunk query detecting execution of multiple system information discovery commands in rapid succession, a pattern commonly seen during automated post-exploitation reconnaissance.",
    query: `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
  (CommandLine="*systeminfo*" OR CommandLine="*hostname*" OR CommandLine="*whoami*"
   OR CommandLine="*net user*" OR CommandLine="*net group*" OR CommandLine="*net localgroup*"
   OR CommandLine="*ipconfig*" OR CommandLine="*arp -a*" OR CommandLine="*route print*"
   OR CommandLine="*netstat -ano*" OR CommandLine="*tasklist*" OR CommandLine="*sc query*"
   OR CommandLine="*wmic os get*" OR CommandLine="*wmic process*" OR CommandLine="*nltest*"
   OR CommandLine="*gpresult*" OR CommandLine="*dsquery*" OR CommandLine="*qwinsta*")
| bin _time span=5m
| stats count as cmd_count
    dc(CommandLine) as distinct_commands
    values(CommandLine) as commands
    values(ParentProcessName) as parent_processes
    by host, user, _time
| where distinct_commands >= 5
| sort - distinct_commands`,
    language: "splunk",
    techniqueExternalId: "T1082",
    category: "discovery",
    source: "Splunk Security Content",
    severity: "medium",
    tags: ["system-discovery", "reconnaissance", "post-exploitation", "enumeration"],
  },

  // =========================================================================
  // LATERAL MOVEMENT
  // =========================================================================
  {
    name: "PsExec Remote Execution Detection",
    description:
      "Detects PsExec usage for lateral movement by monitoring for the PSEXESVC service installation, named pipe creation, and characteristic process creation patterns on remote systems.",
    query: `title: PsExec Remote Execution
id: 4e6f8a0b-2c3d-5e7f-9a1b-3c4d6e8f0a2b
status: stable
level: high
description: >
  Detects PsExec and similar remote execution tools by identifying
  service installation, named pipe creation, and process execution
  patterns characteristic of PsExec-based lateral movement.
author: TrustedSec
date: 2024/03/01
modified: 2025/04/15
references:
  - https://attack.mitre.org/techniques/T1021/002/
tags:
  - attack.lateral_movement
  - attack.execution
  - attack.t1021.002
logsource:
  product: windows
  service: system
detection:
  selection_service:
    EventID: 7045
    ServiceName:
      - 'PSEXESVC'
      - 'csexec'
      - 'PAExec'
      - 'RemCom'
  selection_pipe:
    EventID: 17
    PipeName|startswith:
      - '\\\\PSEXESVC'
      - '\\\\csexecsvc'
      - '\\\\PAExec'
      - '\\\\RemCom'
  condition: 1 of selection_*
falsepositives:
  - Legitimate remote administration
  - SCCM or Intune remote operations`,
    language: "sigma",
    techniqueExternalId: "T1021.002",
    category: "lateral-movement",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["psexec", "lateral-movement", "remote-execution", "smb"],
  },

  {
    name: "WMI Remote Process Creation",
    description:
      "Detects remote process creation via WMI (Windows Management Instrumentation), a common lateral movement technique that uses DCOM to execute commands on remote systems.",
    query: `DeviceProcessEvents
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe",
                        "mshta.exe", "rundll32.exe", "regsvr32.exe",
                        "cscript.exe", "wscript.exe")
| where InitiatingProcessCommandLine has "WmiPrvSE"
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, AccountName,
          InitiatingProcessAccountName, FolderPath
| summarize ProcessCount = count(),
            DistinctProcesses = dcount(FileName),
            Commands = make_set(ProcessCommandLine, 10)
            by DeviceName, AccountName, bin(Timestamp, 5m)
| sort by ProcessCount desc`,
    language: "kql",
    techniqueExternalId: "T1047",
    category: "lateral-movement",
    source: "Microsoft Defender for Endpoint",
    severity: "high",
    tags: ["wmi", "lateral-movement", "remote-execution", "wmiprvse"],
  },

  {
    name: "DCOM Lateral Movement Detection",
    description:
      "Detects lateral movement via DCOM (Distributed Component Object Model) by monitoring for MMC20.Application, ShellWindows, ShellBrowserWindow, and Excel.Application DCOM objects used for remote code execution.",
    query: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("mmc.exe", "excel.exe",
                                         "outlook.exe", "explorer.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe",
                        "mshta.exe", "rundll32.exe")
| where InitiatingProcessCommandLine has_any (
    "-Embedding", "MMC20.Application", "ShellWindows",
    "ShellBrowserWindow", "Excel.Application",
    "Outlook.Application", "VisualStudio.DTE")
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          AccountName, FolderPath
| sort by Timestamp desc`,
    language: "kql",
    techniqueExternalId: "T1021.003",
    category: "lateral-movement",
    source: "Microsoft Defender for Endpoint",
    severity: "high",
    tags: ["dcom", "lateral-movement", "mmc20", "remote-execution"],
  },

  {
    name: "WinRM Remote Execution Detection",
    description:
      "Sigma rule detecting remote command execution via WinRM (Windows Remote Management) including Invoke-Command, Enter-PSSession, and winrs.exe for lateral movement.",
    query: `title: WinRM Remote Execution Detection
id: 5f7a9b1c-3d4e-6f8a-0b2c-4d5e7f9a1b3c
status: stable
level: high
description: >
  Detects WinRM-based remote command execution used for lateral
  movement including PowerShell Remoting and winrs.exe.
author: TrustedSec
date: 2024/05/15
modified: 2025/05/01
references:
  - https://attack.mitre.org/techniques/T1021/006/
tags:
  - attack.lateral_movement
  - attack.t1021.006
logsource:
  category: process_creation
  product: windows
detection:
  selection_winrs:
    Image|endswith: '\\\\winrs.exe'
    CommandLine|contains:
      - '-r:'
      - '/r:'
  selection_pssession:
    CommandLine|contains:
      - 'Enter-PSSession'
      - 'Invoke-Command'
      - 'New-PSSession'
    CommandLine|contains:
      - '-ComputerName'
      - '-Session'
      - '-ConnectionUri'
  selection_wsmprovhost:
    ParentImage|endswith: '\\\\wsmprovhost.exe'
    Image|endswith:
      - '\\\\cmd.exe'
      - '\\\\powershell.exe'
      - '\\\\pwsh.exe'
  condition: 1 of selection_*
falsepositives:
  - Legitimate remote administration via PowerShell
  - Configuration management tools (DSC, Ansible)`,
    language: "sigma",
    techniqueExternalId: "T1021.006",
    category: "lateral-movement",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["winrm", "lateral-movement", "powershell-remoting", "remote-execution"],
  },

  {
    name: "RDP Hijacking via tscon.exe",
    description:
      "Detects RDP session hijacking using tscon.exe, which allows an attacker with SYSTEM privileges to take over a disconnected RDP session without credentials.",
    query: `DeviceProcessEvents
| where FileName =~ "tscon.exe"
| where ProcessCommandLine matches regex @"tscon\\s+\\d+\\s+/dest:"
| extend SourceSession = extract(@"tscon\\s+(\\d+)", 1, ProcessCommandLine),
         DestSession = extract(@"/dest:(\\S+)", 1, ProcessCommandLine)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          SourceSession, DestSession, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| sort by Timestamp desc`,
    language: "kql",
    techniqueExternalId: "T1563.002",
    category: "lateral-movement",
    source: "Microsoft Defender for Endpoint",
    severity: "critical",
    tags: ["rdp-hijacking", "tscon", "session-hijack", "lateral-movement"],
  },

  {
    name: "SSH Lateral Movement on Linux",
    description:
      "Detects SSH-based lateral movement from Linux hosts by monitoring for SSH client connections from non-interactive processes or unusual parent-child process trees that suggest automated lateral movement.",
    query: `index=linux sourcetype="syslog" OR sourcetype="linux:audit"
  (process="ssh" OR process="sshpass" OR process="plink")
| where NOT (parent_process="sshd" OR parent_process="bash" OR parent_process="systemd")
| eval is_automated=case(
    match(process_args, "-o StrictHostKeyChecking=no"), "yes",
    match(process_args, "-o UserKnownHostsFile=/dev/null"), "yes",
    match(process_args, "sshpass"), "yes",
    match(process_args, "-i /tmp/"), "yes",
    1==1, "no")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(process_args) as commands
    dc(dest_host) as distinct_targets
    values(dest_host) as targets
    by src_host, user, is_automated
| where count > 3 OR is_automated="yes"
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"),
       lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| sort - distinct_targets`,
    language: "splunk",
    techniqueExternalId: "T1021.004",
    category: "lateral-movement",
    source: "Splunk Security Content",
    severity: "high",
    tags: ["ssh", "lateral-movement", "linux", "automated-ssh"],
  },

  // =========================================================================
  // COLLECTION / EXFILTRATION
  // =========================================================================
  {
    name: "Archive Collection via Compression Tools",
    description:
      "Detects data staging via compression utilities that create archives of sensitive data prior to exfiltration. Monitors for rar, 7z, zip, and tar commands targeting sensitive directories.",
    query: `title: Data Staging via Archive Compression
id: 6a8b0c2d-4e5f-7a9b-1c3d-5e6f8a0b2c4d
status: stable
level: high
description: >
  Detects data staging via compression utilities creating archives
  from sensitive directories as a precursor to exfiltration.
author: TrustedSec
date: 2024/09/01
modified: 2025/06/01
references:
  - https://attack.mitre.org/techniques/T1560/001/
tags:
  - attack.collection
  - attack.t1560.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_tools:
    Image|endswith:
      - '\\\\rar.exe'
      - '\\\\7z.exe'
      - '\\\\7za.exe'
      - '\\\\WinRAR.exe'
      - '\\\\zip.exe'
      - '\\\\tar.exe'
  selection_sensitive_paths:
    CommandLine|contains:
      - '\\\\Documents\\\\'
      - '\\\\Desktop\\\\'
      - '\\\\Downloads\\\\'
      - '\\\\Finance\\\\'
      - '\\\\HR\\\\'
      - '\\\\Confidential\\\\'
      - '\\\\Accounting\\\\'
      - '\\\\Legal\\\\'
      - '\\\\Contracts\\\\'
      - '*.pst'
      - '*.ost'
      - '*.docx'
      - '*.xlsx'
      - '*.pdf'
  selection_password:
    CommandLine|contains:
      - '-p'
      - '-hp'
      - '--password'
      - '-mem=AES256'
  condition: selection_tools and (selection_sensitive_paths or selection_password)
falsepositives:
  - Legitimate backup operations
  - User archiving personal files`,
    language: "sigma",
    techniqueExternalId: "T1560.001",
    category: "collection",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["archive", "compression", "data-staging", "exfiltration-prep"],
  },

  {
    name: "Clipboard Data Collection",
    description:
      "Detects clipboard monitoring and data collection by identifying processes that access clipboard APIs or PowerShell cmdlets used to read clipboard contents systematically.",
    query: `DeviceProcessEvents
| where ProcessCommandLine has_any (
    "Get-Clipboard", "GetClipboardData",
    "System.Windows.Forms.Clipboard",
    "System.Windows.Clipboard",
    "win32clipboard", "xclip", "xsel",
    "pbpaste", "clip.exe /out")
| where InitiatingProcessFileName !in (
    "explorer.exe", "rdpclip.exe", "svchost.exe",
    "SearchHost.exe", "mstsc.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, AccountName
| sort by Timestamp desc`,
    language: "kql",
    techniqueExternalId: "T1115",
    category: "collection",
    source: "Microsoft Defender for Endpoint",
    severity: "medium",
    tags: ["clipboard", "collection", "data-theft", "monitoring"],
  },

  {
    name: "DNS Exfiltration Detection",
    description:
      "Detects data exfiltration over DNS by identifying high-volume DNS queries with unusually long subdomain labels to a single base domain, characteristic of DNS tunneling tools like dnscat2, iodine, and dns2tcp.",
    query: `DnsEvents
| where QueryType in ("A", "AAAA", "TXT", "MX", "CNAME")
| extend SubdomainParts = split(Name, ".")
| extend LabelCount = array_length(SubdomainParts)
| where LabelCount >= 3
| extend SubdomainLabel = tostring(SubdomainParts[0]),
         BaseDomain = strcat(tostring(SubdomainParts[-2]), ".", tostring(SubdomainParts[-1]))
| extend LabelLength = strlen(SubdomainLabel),
         QueryLength = strlen(Name)
| where LabelLength > 30 or QueryLength > 80
| summarize QueryCount = count(),
            DistinctSubdomains = dcount(SubdomainLabel),
            TotalDataBytes = sum(QueryLength),
            AvgLabelLength = avg(LabelLength),
            MaxLabelLength = max(LabelLength),
            TxtQueries = countif(QueryType == "TXT"),
            TimeSpanMinutes = datetime_diff('minute', max(TimeGenerated), min(TimeGenerated))
            by BaseDomain, ClientIP, bin(TimeGenerated, 1h)
| where DistinctSubdomains > 50
    and AvgLabelLength > 30
| extend ExfilScore = DistinctSubdomains * 0.3 + TotalDataBytes * 0.001 + TxtQueries * 0.5
| where ExfilScore > 30
| sort by ExfilScore desc`,
    language: "kql",
    techniqueExternalId: "T1048.003",
    category: "exfiltration",
    source: "Microsoft Sentinel",
    severity: "high",
    tags: ["dns-exfiltration", "dns-tunneling", "data-exfil", "covert-channel"],
  },

  {
    name: "Cloud Storage Exfiltration Detection",
    description:
      "Detects potential data exfiltration to cloud storage services by monitoring for unusual upload volumes to services like Dropbox, Google Drive, OneDrive personal, Mega, and file sharing sites.",
    query: `index=proxy sourcetype=squid OR sourcetype=bluecoat
  (url LIKE "%dropbox.com/upload%" OR url LIKE "%drive.google.com/upload%"
   OR url LIKE "%onedrive.live.com%" OR url LIKE "%mega.nz%"
   OR url LIKE "%wetransfer.com%" OR url LIKE "%sendspace.com%"
   OR url LIKE "%mediafire.com/upload%" OR url LIKE "%file.io%"
   OR url LIKE "%transfer.sh%" OR url LIKE "%gofile.io%"
   OR url LIKE "%anonfiles.com%")
  http_method=POST
| stats sum(bytes_out) as total_bytes_out
    count as upload_count
    dc(url) as distinct_urls
    values(url) as upload_urls
    by src_ip, user, _time span=1h
| eval total_mb=round(total_bytes_out/1024/1024, 2)
| where total_mb > 50 OR upload_count > 20
| sort - total_mb`,
    language: "splunk",
    techniqueExternalId: "T1567.002",
    category: "exfiltration",
    source: "Splunk Security Content",
    severity: "high",
    tags: ["cloud-exfiltration", "data-theft", "file-sharing", "upload"],
  },

  {
    name: "Large Data Transfer to External IP",
    description:
      "Detects unusually large outbound data transfers that may indicate data exfiltration. Monitors for sustained high-volume connections to external IP addresses.",
    query: `DeviceNetworkEvents
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName !in (
    "OneDrive.exe", "Teams.exe", "ms-teams.exe", "outlook.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "svchost.exe",
    "MicrosoftEdgeUpdate.exe", "WindowsUpdate.exe")
| summarize TotalBytesSent = sum(SentBytes),
            ConnectionCount = count(),
            DistinctIPs = dcount(RemoteIP),
            DestIPs = make_set(RemoteIP, 10),
            Processes = make_set(InitiatingProcessFileName, 10)
            by DeviceName, InitiatingProcessAccountName,
               bin(Timestamp, 1h)
| extend TotalMB = round(TotalBytesSent / 1048576.0, 2)
| where TotalMB > 500 or (ConnectionCount > 100 and TotalMB > 100)
| sort by TotalMB desc`,
    language: "kql",
    techniqueExternalId: "T1048",
    category: "exfiltration",
    source: "Microsoft Defender for Endpoint",
    severity: "high",
    tags: ["data-exfiltration", "large-transfer", "outbound", "network"],
  },

  // =========================================================================
  // IMPACT
  // =========================================================================
  {
    name: "Firmware and Boot Sector Tampering",
    description:
      "Detects potential firmware or boot sector tampering by monitoring for suspicious use of dd, flashrom, or direct disk access utilities that could indicate destructive attacks targeting system firmware.",
    query: `title: Firmware and Boot Sector Modification Attempt
id: 7b9c1d3e-5f6a-8b0c-2d4e-6f7a9b1c3d5e
status: experimental
level: critical
description: >
  Detects attempts to modify system firmware, MBR, or boot sectors
  using low-level disk access tools, which may indicate destructive
  wiper malware or firmware-level persistence.
author: TrustedSec
date: 2024/10/01
modified: 2025/06/01
references:
  - https://attack.mitre.org/techniques/T1495/
tags:
  - attack.impact
  - attack.t1495
logsource:
  category: process_creation
  product: windows
detection:
  selection_disk_access:
    Image|endswith:
      - '\\\\dd.exe'
      - '\\\\rawwrite.exe'
    CommandLine|contains:
      - '\\\\.\\\\PhysicalDrive'
      - '\\\\.\\\\PhysicalMemory'
      - 'if=/dev/'
      - 'of=/dev/'
  selection_bcdedit_destroy:
    Image|endswith: '\\\\bcdedit.exe'
    CommandLine|contains:
      - '/deletevalue'
      - '/delete {bootmgr}'
      - '/set {default} bootsequence'
  selection_bootsect:
    Image|endswith:
      - '\\\\bootsect.exe'
      - '\\\\mbr.exe'
  condition: 1 of selection_*
falsepositives:
  - Disk imaging for forensics
  - System recovery operations`,
    language: "sigma",
    techniqueExternalId: "T1495",
    category: "impact",
    source: "TrustedSec Custom",
    severity: "critical",
    tags: ["firmware", "boot-sector", "wiper", "destructive"],
  },

  {
    name: "Inhibit System Recovery",
    description:
      "Detects multiple system recovery inhibition techniques executed together, a strong indicator of imminent ransomware deployment or wiper activity.",
    query: `DeviceProcessEvents
| where ProcessCommandLine has_any (
    "vssadmin delete shadows",
    "wmic shadowcopy delete",
    "bcdedit /set {default} recoveryenabled no",
    "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
    "wbadmin delete catalog",
    "wbadmin delete systemstatebackup",
    "Disable-ComputerRestore",
    "schtasks /delete /tn",
    "net stop VSS",
    "net stop swprv",
    "net stop wbengine")
| summarize CommandCount = count(),
            DistinctCommands = dcount(ProcessCommandLine),
            Commands = make_set(ProcessCommandLine, 20),
            Processes = make_set(FileName, 10)
            by DeviceName, AccountName, bin(Timestamp, 10m)
| where DistinctCommands >= 2
| extend ThreatLevel = case(
    DistinctCommands >= 4, "CRITICAL - Imminent ransomware",
    DistinctCommands >= 2, "HIGH - Recovery inhibition",
    "Medium")
| sort by DistinctCommands desc`,
    language: "kql",
    techniqueExternalId: "T1490",
    category: "impact",
    source: "Microsoft Defender for Endpoint",
    severity: "critical",
    tags: ["recovery-inhibition", "ransomware", "wiper", "destructive", "impact"],
  },

  {
    name: "System Shutdown or Reboot Command",
    description:
      "Detects unexpected system shutdown or forced reboot commands that may be part of a destructive attack or ransomware campaign forcing restart for boot-level encryption.",
    query: `title: Suspicious System Shutdown or Reboot
id: 8c0d2e4f-6a7b-9c1d-3e5f-7a8b0c2d4e6f
status: stable
level: medium
description: >
  Detects forced shutdown or reboot commands that may indicate
  destructive activity or forced restart for bootlocker ransomware.
author: TrustedSec
date: 2024/11/01
modified: 2025/05/15
references:
  - https://attack.mitre.org/techniques/T1529/
tags:
  - attack.impact
  - attack.t1529
logsource:
  category: process_creation
  product: windows
detection:
  selection_shutdown:
    Image|endswith: '\\\\shutdown.exe'
    CommandLine|contains:
      - '/s'
      - '/r'
      - '/f'
      - '-s'
      - '-r'
      - '-f'
  selection_psshutdown:
    Image|endswith:
      - '\\\\psshutdown.exe'
      - '\\\\psshutdown64.exe'
  selection_wmic:
    Image|endswith: '\\\\wmic.exe'
    CommandLine|contains:
      - 'os where'
      - 'reboot'
      - 'shutdown'
  filter_planned:
    CommandLine|contains:
      - '/t 3600'
      - '/t 7200'
      - '/c "Planned'
      - '/d p:4:1'
  condition: (selection_shutdown or selection_psshutdown or selection_wmic) and not filter_planned
falsepositives:
  - Scheduled maintenance reboots
  - Windows Update forced restarts`,
    language: "sigma",
    techniqueExternalId: "T1529",
    category: "impact",
    source: "TrustedSec Custom",
    severity: "medium",
    tags: ["shutdown", "reboot", "impact", "destructive"],
  },

  // =========================================================================
  // LINUX-SPECIFIC
  // =========================================================================
  {
    name: "Linux Reverse Shell Detection",
    description:
      "Detects common reverse shell techniques on Linux systems including bash, python, perl, netcat, and socat reverse shells. These are used for initial access and lateral movement.",
    query: `index=linux sourcetype="syslog" OR sourcetype="linux:audit"
  (process="bash" OR process="sh" OR process="python" OR process="python3"
   OR process="perl" OR process="ruby" OR process="php" OR process="nc"
   OR process="ncat" OR process="socat" OR process="openssl")
| where match(process_args, "(?i)(/dev/tcp/|/dev/udp/|bash -i|sh -i)")
   OR match(process_args, "(?i)(nc -e|nc -c|ncat -e|socat.*exec)")
   OR match(process_args, "(?i)(python.*socket.*connect|python.*pty\\.spawn)")
   OR match(process_args, "(?i)(perl.*socket.*INET|ruby.*TCPSocket)")
   OR match(process_args, "(?i)(php.*fsockopen|php.*exec.*sh)")
   OR match(process_args, "(?i)(mkfifo|mknod.*p.*nc)")
   OR match(process_args, "(?i)(openssl.*s_client.*connect)")
| eval shell_type=case(
    match(process_args, "/dev/tcp"), "bash_dev_tcp",
    match(process_args, "nc -e|ncat -e"), "netcat",
    match(process_args, "python.*socket"), "python",
    match(process_args, "perl.*socket"), "perl",
    match(process_args, "socat.*exec"), "socat",
    match(process_args, "mkfifo"), "fifo_pipe",
    match(process_args, "openssl"), "openssl",
    1==1, "other")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(process_args) as commands
    values(shell_type) as types
    by host, user
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"),
       lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| sort - count`,
    language: "splunk",
    techniqueExternalId: "T1059.004",
    category: "linux",
    source: "Splunk Security Content",
    severity: "critical",
    tags: ["reverse-shell", "linux", "netcat", "bash", "initial-access"],
  },

  {
    name: "Linux Cron Persistence",
    description:
      "Sigma rule detecting creation or modification of cron jobs used for persistence on Linux systems. Monitors crontab modifications and direct file creation in cron directories.",
    query: `title: Linux Cron Job Persistence
id: 9d1e3f5a-7b8c-0d2e-4f6a-8b9c1d3e5f7a
status: stable
level: high
description: >
  Detects creation or modification of cron jobs and crontab files
  used for persistence on Linux systems, including entries that
  execute scripts from suspicious locations.
author: TrustedSec
date: 2024/08/15
modified: 2025/05/20
references:
  - https://attack.mitre.org/techniques/T1053/003/
tags:
  - attack.persistence
  - attack.execution
  - attack.t1053.003
logsource:
  product: linux
  category: process_creation
detection:
  selection_crontab:
    Image|endswith:
      - '/crontab'
    CommandLine|contains:
      - '-e'
      - '-l'
  selection_cron_write:
    TargetFilename|startswith:
      - '/etc/cron.d/'
      - '/etc/cron.daily/'
      - '/etc/cron.hourly/'
      - '/etc/cron.weekly/'
      - '/etc/cron.monthly/'
      - '/var/spool/cron/'
      - '/var/spool/cron/crontabs/'
  selection_suspicious_content:
    CommandLine|contains:
      - 'curl'
      - 'wget'
      - '/dev/tcp/'
      - 'base64'
      - '/tmp/'
      - 'chmod +x'
      - 'bash -c'
      - 'python -c'
  condition: selection_crontab or selection_cron_write or (selection_crontab and selection_suspicious_content)
falsepositives:
  - Legitimate system administration
  - Package manager cron job installation`,
    language: "sigma",
    techniqueExternalId: "T1053.003",
    category: "linux",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["cron", "persistence", "linux", "scheduled-task"],
  },

  {
    name: "SSH Key Theft and Unauthorized Access",
    description:
      "Detects theft of SSH private keys and unauthorized SSH key deployment by monitoring for access to .ssh directories, copying of identity files, and addition of unauthorized authorized_keys entries.",
    query: `index=linux sourcetype="syslog" OR sourcetype="linux:audit"
  (
    (action="open" OR action="read" OR action="access")
    (path="*/.ssh/id_rsa" OR path="*/.ssh/id_ed25519" OR path="*/.ssh/id_ecdsa"
     OR path="*/.ssh/id_dsa" OR path="*/.ssh/authorized_keys"
     OR path="*/.ssh/known_hosts" OR path="*/.ssh/config")
  )
  OR
  (
    (process="cp" OR process="scp" OR process="rsync" OR process="cat")
    (process_args="*id_rsa*" OR process_args="*id_ed25519*"
     OR process_args="*authorized_keys*" OR process_args="*/.ssh/*")
  )
  OR
  (
    process="ssh-keygen" process_args="-y"
  )
| eval action_type=case(
    match(path, "id_rsa|id_ed25519|id_ecdsa|id_dsa") AND action="read", "key_theft",
    match(path, "authorized_keys") AND (action="write" OR action="open"), "key_injection",
    match(process_args, "id_rsa|id_ed25519") AND process="scp", "key_exfil",
    1==1, "ssh_access")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(path) as files_accessed
    values(process) as processes
    values(action_type) as action_types
    by host, user
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"),
       lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| sort - count`,
    language: "splunk",
    techniqueExternalId: "T1552.004",
    category: "linux",
    source: "Splunk Security Content",
    severity: "high",
    tags: ["ssh-key", "credential-theft", "linux", "persistence"],
  },

  {
    name: "Container Escape via Host Mount",
    description:
      "Detects container escape attempts via host filesystem mounts, nsenter, and privileged container breakout techniques. Monitors for access to host namespaces and sensitive host paths from within containers.",
    query: `title: Container Escape Detection
id: 0e2f4a6b-8c9d-1e3f-5a7b-9c0d2e4f6a8b
status: experimental
level: critical
description: >
  Detects container escape attempts including host mount abuse,
  nsenter usage, and exploitation of privileged container capabilities
  to access the underlying host system.
author: TrustedSec
date: 2024/10/15
modified: 2025/06/01
references:
  - https://attack.mitre.org/techniques/T1611/
tags:
  - attack.privilege_escalation
  - attack.t1611
logsource:
  product: linux
  category: process_creation
detection:
  selection_nsenter:
    Image|endswith: '/nsenter'
    CommandLine|contains:
      - '--target 1'
      - '-t 1'
      - '--mount'
      - '--pid'
      - '--net'
  selection_chroot:
    Image|endswith: '/chroot'
    CommandLine|contains:
      - '/host'
      - '/proc/1/root'
  selection_mount:
    CommandLine|contains:
      - 'mount -t proc'
      - 'mount -o bind /host'
      - 'mount /dev/sda'
      - 'mount /dev/vda'
  selection_cgroup_escape:
    CommandLine|contains:
      - 'release_agent'
      - 'cgroup/release_agent'
      - 'notify_on_release'
  selection_host_access:
    CommandLine|contains:
      - '/proc/1/root'
      - '/proc/sysrq-trigger'
      - '/proc/1/ns/'
      - 'core_pattern'
  condition: 1 of selection_*
falsepositives:
  - Container management tools
  - Debugging privileged containers`,
    language: "sigma",
    techniqueExternalId: "T1611",
    category: "linux",
    source: "TrustedSec Custom",
    severity: "critical",
    tags: ["container-escape", "nsenter", "chroot", "privileged-container", "linux"],
  },

  {
    name: "Linux Kernel Module Loading",
    description:
      "Detects suspicious kernel module loading on Linux systems using insmod or modprobe from non-standard paths, which may indicate rootkit installation or kernel-level persistence.",
    query: `index=linux sourcetype="syslog" OR sourcetype="linux:audit"
  (process="insmod" OR process="modprobe" OR process="modinfo")
| where NOT match(process_args, "^/lib/modules/")
| where NOT match(process_args, "(nf_conntrack|ip_tables|iptable|overlay|br_netfilter|bonding)")
| eval is_suspicious=case(
    match(process_args, "/tmp/"), "temp_path",
    match(process_args, "/dev/shm/"), "shared_memory",
    match(process_args, "/home/"), "home_directory",
    match(process_args, "/var/tmp/"), "var_tmp",
    match(process_args, "\\.ko$"), "kernel_object",
    1==1, "standard")
| where is_suspicious != "standard"
| stats count min(_time) as firstTime max(_time) as lastTime
    values(process_args) as modules
    values(is_suspicious) as load_locations
    by host, user
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"),
       lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| sort - count`,
    language: "splunk",
    techniqueExternalId: "T1547.006",
    category: "linux",
    source: "Splunk Security Content",
    severity: "critical",
    tags: ["kernel-module", "rootkit", "linux", "persistence"],
  },

  {
    name: "Linux Suspicious File Download and Execution",
    description:
      "Detects the common attack pattern on Linux of downloading a file with curl/wget and immediately executing it, often used for initial access and malware deployment.",
    query: `title: Linux Download and Execute Pattern
id: 1f3a5b7c-9d0e-2f4a-6b8c-0d1e3f5a7b9c
status: stable
level: high
description: >
  Detects download-and-execute patterns on Linux using curl/wget piped
  to bash/sh, or download followed by chmod and execution from /tmp.
author: TrustedSec
date: 2024/09/15
modified: 2025/06/10
references:
  - https://attack.mitre.org/techniques/T1059/004/
tags:
  - attack.execution
  - attack.t1059.004
logsource:
  product: linux
  category: process_creation
detection:
  selection_pipe_exec:
    CommandLine|contains:
      - 'curl|bash'
      - 'curl|sh'
      - 'wget|bash'
      - 'wget|sh'
      - 'curl -s|bash'
      - 'wget -q|sh'
      - 'curl -sSL|bash'
  selection_download_exec:
    CommandLine|contains:
      - 'curl -o /tmp/'
      - 'wget -O /tmp/'
      - 'curl -o /dev/shm/'
      - 'wget -O /dev/shm/'
    CommandLine|contains:
      - '&& chmod'
      - '&& bash'
      - '&& sh'
      - '; chmod'
      - '; bash'
  selection_base64_decode:
    CommandLine|contains:
      - 'base64 -d|bash'
      - 'base64 -d|sh'
      - 'base64 --decode|bash'
  condition: 1 of selection_*
falsepositives:
  - Installation scripts from trusted vendors
  - Ansible/Chef/Puppet bootstrap scripts`,
    language: "sigma",
    techniqueExternalId: "T1059.004",
    category: "linux",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["download-execute", "linux", "curl", "wget", "initial-access"],
  },

  // =========================================================================
  // CLOUD-SPECIFIC
  // =========================================================================
  {
    name: "Azure Service Principal Abuse",
    description:
      "Detects suspicious service principal activity in Azure AD including new credential additions, permission grants, and authentication from unusual locations that may indicate compromised application credentials.",
    query: `AuditLogs
| where OperationName has_any (
    "Add service principal credentials",
    "Update application - Certificates and secrets management",
    "Add app role assignment to service principal",
    "Add delegated permission grant",
    "Add application")
| where Result == "success"
| mv-expand TargetResources
| extend AppName = tostring(TargetResources.displayName),
         AppId = tostring(TargetResources.id),
         ModifiedProps = tostring(TargetResources.modifiedProperties)
| extend InitiatedBy = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName))
| extend InitiatedByIP = coalesce(
    tostring(InitiatedBy.user.ipAddress),
    tostring(InitiatedBy.app.ipAddress))
| project TimeGenerated, InitiatedBy, InitiatedByIP, OperationName,
          AppName, AppId, ModifiedProps, CorrelationId
| summarize OperationCount = count(),
            DistinctOps = dcount(OperationName),
            Operations = make_set(OperationName, 10),
            Apps = make_set(AppName, 10)
            by InitiatedBy, InitiatedByIP, bin(TimeGenerated, 1h)
| where DistinctOps >= 2 or OperationCount >= 3
| sort by OperationCount desc`,
    language: "kql",
    techniqueExternalId: "T1098.001",
    category: "cloud",
    source: "Microsoft Sentinel",
    severity: "high",
    tags: ["azure-ad", "service-principal", "credential-abuse", "application"],
  },

  {
    name: "AWS IAM Privilege Escalation Paths",
    description:
      "Detects AWS IAM privilege escalation attempts including creation of new IAM policies, assumption of roles with broader permissions, and attachment of administrator policies.",
    query: `index=aws sourcetype=aws:cloudtrail
  (eventName=CreatePolicy OR eventName=CreatePolicyVersion
   OR eventName=AttachUserPolicy OR eventName=AttachRolePolicy
   OR eventName=AttachGroupPolicy OR eventName=PutUserPolicy
   OR eventName=PutRolePolicy OR eventName=PutGroupPolicy
   OR eventName=AddUserToGroup OR eventName=CreateRole
   OR eventName=UpdateAssumeRolePolicy)
| eval is_admin_policy=if(match(requestParameters.policyArn,
    "(AdministratorAccess|IAMFullAccess|PowerUserAccess)"), "yes", "no")
| eval is_wildcard=if(match(requestParameters.policyDocument,
    "\\*"), "yes", "no")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(eventName) as actions
    dc(eventName) as distinct_actions
    values(requestParameters.policyArn) as policies
    values(requestParameters.roleName) as roles
    by userIdentity.arn, sourceIPAddress
| where distinct_actions >= 2 OR is_admin_policy="yes" OR is_wildcard="yes"
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"),
       lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| rename "userIdentity.arn" as caller_arn, sourceIPAddress as src_ip
| sort - distinct_actions`,
    language: "splunk",
    techniqueExternalId: "T1098",
    category: "cloud",
    source: "Splunk Security Content",
    severity: "high",
    tags: ["aws", "iam", "privilege-escalation", "policy-abuse"],
  },

  {
    name: "AWS S3 Bucket Policy Modification for Public Access",
    description:
      "Detects modifications to S3 bucket policies or ACLs that expose data publicly, a technique used for data exposure or establishing exfiltration channels.",
    query: `AWSCloudTrail
| where EventName in ("PutBucketPolicy", "PutBucketAcl",
                        "PutBucketPublicAccessBlock",
                        "DeleteBucketPolicy", "DeleteBucketPublicAccessBlock")
| where ResponseElements has "Success" or ErrorCode == ""
| extend BucketName = tostring(parse_json(RequestParameters).bucketName),
         CallerArn = UserIdentityArn,
         CallerIP = SourceIpAddress
| extend PolicyContent = tostring(parse_json(RequestParameters).policy)
| extend IsPublic = PolicyContent has "*" and PolicyContent has "Allow"
| project TimeGenerated, CallerArn, CallerIP, EventName, BucketName,
          IsPublic, UserAgent, AWSRegion
| sort by TimeGenerated desc`,
    language: "kql",
    techniqueExternalId: "T1530",
    category: "cloud",
    source: "Microsoft Sentinel - AWS Connector",
    severity: "critical",
    tags: ["aws", "s3", "public-access", "data-exposure", "bucket-policy"],
  },

  {
    name: "Instance Metadata Service (IMDS) Credential Theft",
    description:
      "Detects access to cloud instance metadata services (IMDS) from unexpected processes, a technique used to steal temporary credentials assigned to cloud instances.",
    query: `DeviceNetworkEvents
| where RemoteIP == "169.254.169.254"
    or RemoteUrl has "169.254.169.254"
| where RemotePort in (80, 443)
| where InitiatingProcessFileName !in (
    "cloud-init", "waagent", "WindowsAzureGuestAgent.exe",
    "WaAppAgent.exe", "Monitoring", "collectd",
    "amazon-ssm-agent", "google_guest_agent")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteUrl,
          InitiatingProcessAccountName, RemoteIP
| summarize AccessCount = count(),
            Processes = make_set(InitiatingProcessFileName, 10),
            Commands = make_set(InitiatingProcessCommandLine, 10)
            by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 15m)
| where AccessCount >= 1
| sort by AccessCount desc`,
    language: "kql",
    techniqueExternalId: "T1552.005",
    category: "cloud",
    source: "Microsoft Defender for Endpoint",
    severity: "high",
    tags: ["imds", "metadata", "credential-theft", "cloud", "aws", "azure", "gcp"],
  },

  {
    name: "Azure Managed Identity Abuse",
    description:
      "Detects suspicious use of Azure Managed Identities including token requests from unexpected processes, cross-resource access patterns, and bulk operations using managed identity credentials.",
    query: `AzureActivity
| where Authorization has "managedIdentity"
    or Caller has "managedIdentity"
| where OperationNameValue has_any (
    "Microsoft.KeyVault/vaults/secrets/read",
    "Microsoft.Storage/storageAccounts/listKeys/action",
    "Microsoft.Sql/servers/databases/read",
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Resources/deployments/write")
| summarize OperationCount = count(),
            DistinctOps = dcount(OperationNameValue),
            DistinctResources = dcount(ResourceId),
            Operations = make_set(OperationNameValue, 20),
            Resources = make_set(ResourceId, 10)
            by Caller, CallerIpAddress, bin(TimeGenerated, 15m)
| where DistinctOps >= 3 or DistinctResources >= 5
| sort by DistinctResources desc`,
    language: "kql",
    techniqueExternalId: "T1078.004",
    category: "cloud",
    source: "Microsoft Sentinel",
    severity: "high",
    tags: ["azure", "managed-identity", "credential-abuse", "cloud-identity"],
  },

  {
    name: "Azure Conditional Access Policy Modification",
    description:
      "Detects modification or deletion of Azure AD Conditional Access policies which could weaken authentication controls to facilitate unauthorized access.",
    query: `AuditLogs
| where OperationName has_any (
    "Update conditional access policy",
    "Delete conditional access policy",
    "Add conditional access policy")
| where Result == "success"
| mv-expand TargetResources
| extend PolicyName = tostring(TargetResources.displayName),
         PolicyId = tostring(TargetResources.id)
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
         InitiatedByIP = tostring(InitiatedBy.user.ipAddress)
| extend ModifiedProps = parse_json(tostring(TargetResources.modifiedProperties))
| project TimeGenerated, InitiatedBy, InitiatedByIP, OperationName,
          PolicyName, PolicyId, ModifiedProps, CorrelationId
| sort by TimeGenerated desc`,
    language: "kql",
    techniqueExternalId: "T1556",
    category: "cloud",
    source: "Microsoft Sentinel",
    severity: "critical",
    tags: ["conditional-access", "azure-ad", "policy-modification", "defense-weakening"],
  },

  // =========================================================================
  // ADDITIONAL CREDENTIAL ACCESS / EXECUTION
  // =========================================================================
  {
    name: "Kerberoasting via Rubeus",
    description:
      "Detects Rubeus tool execution for Kerberoasting, AS-REP roasting, and Kerberos ticket manipulation. Rubeus is a common red team tool for Kerberos abuse.",
    query: `DeviceProcessEvents
| where ProcessCommandLine has_any (
    "Rubeus.exe", "Rubeus ",
    "kerberoast", "asreproast",
    "s4u", "renew", "tgtdeleg",
    "createnetonly", "ptt",
    "harvest", "triage", "klist",
    "dump /service:krbtgt")
| where ProcessCommandLine has_any (
    "/user:", "/domain:", "/dc:",
    "/outfile:", "/format:",
    "/enctype:", "/spn:",
    "/ticket:", "/ptt")
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FolderPath
| sort by Timestamp desc`,
    language: "kql",
    techniqueExternalId: "T1558.003",
    category: "credential-access",
    source: "Microsoft Defender for Endpoint",
    severity: "critical",
    tags: ["rubeus", "kerberoasting", "credential-access", "kerberos"],
  },

  {
    name: "Windows Credential Dumping via PowerShell",
    description:
      "Detects PowerShell-based credential dumping techniques including Invoke-Mimikatz, Invoke-NinjaCopy for NTDS.dit, and PowerShell-based LSASS access.",
    query: `title: PowerShell Credential Dumping
id: 2a4b6c8d-0e1f-3a5b-7c9d-1e2f4a6b8c0d
status: stable
level: critical
description: >
  Detects PowerShell-based credential dumping techniques and tools
  commonly used during post-exploitation.
author: TrustedSec
date: 2024/05/01
modified: 2025/06/01
references:
  - https://attack.mitre.org/techniques/T1003/
tags:
  - attack.credential_access
  - attack.t1003
logsource:
  category: process_creation
  product: windows
detection:
  selection_powershell:
    Image|endswith:
      - '\\\\powershell.exe'
      - '\\\\pwsh.exe'
  selection_cred_tools:
    CommandLine|contains:
      - 'Invoke-Mimikatz'
      - 'Invoke-NinjaCopy'
      - 'Invoke-DCSync'
      - 'Invoke-Kerberoast'
      - 'Get-GPPPassword'
      - 'Get-GPPAutologon'
      - 'Invoke-SessionGopher'
      - 'Out-Minidump'
      - 'Get-VaultCredential'
      - 'Get-CachedGPPPassword'
      - 'Invoke-TokenManipulation'
      - 'Invoke-CredentialInjection'
      - 'Get-Keystrokes'
  condition: selection_powershell and selection_cred_tools
falsepositives:
  - Authorized penetration testing
  - Security tool validation`,
    language: "sigma",
    techniqueExternalId: "T1003",
    category: "credential-access",
    source: "TrustedSec Custom",
    severity: "critical",
    tags: ["powershell", "credential-dumping", "mimikatz", "invoke-mimikatz"],
  },

  {
    name: "DPAPI Master Key Extraction",
    description:
      "Detects access to DPAPI master keys which protect Windows credentials, browser passwords, and encrypted data. Attackers extract these keys to decrypt protected data offline.",
    query: `DeviceFileEvents
| where ActionType in ("FileAccessed", "FileRead")
| where FolderPath has "Microsoft\\\\Protect\\\\S-1-"
    or FolderPath has "Microsoft\\\\Crypto\\\\RSA\\\\S-1-"
    or FolderPath has "Microsoft\\\\Credentials\\\\"
| where InitiatingProcessFileName !in (
    "lsass.exe", "svchost.exe", "System",
    "SearchIndexer.exe", "MsMpEng.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FileName, FolderPath,
          InitiatingProcessAccountName
| summarize FileCount = count(),
            Files = make_set(FileName, 20),
            Processes = make_set(InitiatingProcessFileName, 10)
            by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 5m)
| where FileCount >= 2
| sort by FileCount desc`,
    language: "kql",
    techniqueExternalId: "T1555.003",
    category: "credential-access",
    source: "Microsoft Defender for Endpoint",
    severity: "high",
    tags: ["dpapi", "master-key", "credential-access", "browser-passwords"],
  },

  {
    name: "Suspicious MSHTA Execution",
    description:
      "Detects suspicious mshta.exe execution patterns commonly used for defense evasion and code execution, including inline VBScript/JScript and remote HTA file loading.",
    query: `title: Suspicious MSHTA Execution
id: 3b5c7d9e-1f2a-4b6c-8d0e-2f3a5b7c9d1e
status: stable
level: high
description: >
  Detects mshta.exe executing inline scripts, remote HTA files,
  or being used as a proxy for code execution to bypass application
  whitelisting controls.
author: TrustedSec
date: 2024/04/15
modified: 2025/05/01
references:
  - https://attack.mitre.org/techniques/T1218/005/
tags:
  - attack.defense_evasion
  - attack.execution
  - attack.t1218.005
logsource:
  category: process_creation
  product: windows
detection:
  selection_mshta:
    Image|endswith: '\\\\mshta.exe'
  selection_inline:
    CommandLine|contains:
      - 'vbscript:'
      - 'javascript:'
      - '.Run'
      - '.ShellExecute'
      - 'GetObject'
      - 'script:'
  selection_remote:
    CommandLine|contains:
      - 'http://'
      - 'https://'
      - 'ftp://'
      - '\\\\\\\\'
  selection_encoded:
    CommandLine|contains:
      - 'FromBase64'
      - 'decode'
  condition: selection_mshta and (selection_inline or selection_remote or selection_encoded)
falsepositives:
  - Legitimate HTA applications (rare in modern environments)
  - Legacy enterprise applications`,
    language: "sigma",
    techniqueExternalId: "T1218.005",
    category: "defense-evasion",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["mshta", "defense-evasion", "execution", "lolbin", "hta"],
  },

  {
    name: "Windows Event Log Tampering via wevtutil",
    description:
      "Detects clearing or disabling of specific Windows event logs using wevtutil.exe to remove evidence of attacker activity.",
    query: `DeviceProcessEvents
| where FileName =~ "wevtutil.exe"
| where ProcessCommandLine has_any (
    " cl ", " clear-log ", " sl ", " set-log ",
    " /e:false", " el ", " enum-logs ")
| where ProcessCommandLine has_any (
    "Security", "System", "Application",
    "Microsoft-Windows-Sysmon", "PowerShell",
    "Windows PowerShell", "Microsoft-Windows-TerminalServices",
    "Microsoft-Windows-TaskScheduler")
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| sort by Timestamp desc`,
    language: "kql",
    techniqueExternalId: "T1070.001",
    category: "defense-evasion",
    source: "Microsoft Defender for Endpoint",
    severity: "high",
    tags: ["event-log", "tampering", "wevtutil", "indicator-removal"],
  },

  {
    name: "Suspicious Scheduled Task via COM Handler",
    description:
      "Sigma rule detecting scheduled task creation using COM handlers for stealth, which avoids showing a visible command line in Task Scheduler while still executing arbitrary code.",
    query: `title: Scheduled Task COM Handler Abuse
id: 4c6d8e0f-2a3b-5c7d-9e1f-3a4b6c8d0e2f
status: experimental
level: high
description: >
  Detects creation of scheduled tasks that use COM handlers for execution,
  a technique that hides the actual command being run from casual inspection
  of the Task Scheduler.
author: TrustedSec
date: 2024/11/15
modified: 2025/06/01
references:
  - https://attack.mitre.org/techniques/T1053/005/
tags:
  - attack.persistence
  - attack.t1053.005
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4698
  selection_com:
    TaskContent|contains:
      - '<ComHandler>'
      - 'ClassId'
      - '{E6D18A1B'
      - 'COMAction'
  filter_known:
    TaskContent|contains:
      - 'Microsoft\\\\Windows\\\\UpdateOrchestrator'
      - 'Microsoft\\\\Windows\\\\TaskScheduler'
      - 'Microsoft\\\\Windows\\\\WindowsUpdate'
  condition: selection and selection_com and not filter_known
falsepositives:
  - Some legitimate software uses COM-based scheduled tasks`,
    language: "sigma",
    techniqueExternalId: "T1053.005",
    category: "persistence",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["scheduled-task", "com-handler", "persistence", "stealth"],
  },

  {
    name: "PowerShell Constrained Language Mode Bypass",
    description:
      "Detects attempts to bypass PowerShell Constrained Language Mode (CLM), which is enforced by AppLocker and WDAC. Attackers bypass CLM to execute unrestricted PowerShell for post-exploitation.",
    query: `DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "__PSLockDownPolicy",
    "FullLanguage",
    "ConstrainedLanguage",
    "System.Management.Automation.Runspaces",
    "PowerShell.Create()",
    "RunspaceFactory",
    "InitialSessionState",
    "Add-Type -TypeDefinition",
    "Invoke-CimMethod",
    "[System.Management.Automation.Language.FullLanguageMode]")
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| sort by Timestamp desc`,
    language: "kql",
    techniqueExternalId: "T1059.001",
    category: "defense-evasion",
    source: "Microsoft Defender for Endpoint",
    severity: "high",
    tags: ["powershell", "clm-bypass", "constrained-language", "defense-evasion"],
  },

  {
    name: "Potential Credential Access via Web Browser Debug Port",
    description:
      "Detects launching of web browsers with remote debugging enabled, which allows extraction of cookies, saved passwords, and session tokens through the debug protocol.",
    query: `title: Browser Remote Debugging for Credential Access
id: 5d7e9f0a-1b2c-4d6e-8f0a-2b3c5d7e9f1a
status: experimental
level: high
description: >
  Detects web browsers launched with remote debugging ports enabled,
  which allows external tools to extract cookies, passwords, and
  session tokens through the Chrome DevTools Protocol.
author: TrustedSec
date: 2025/01/15
modified: 2025/06/15
references:
  - https://attack.mitre.org/techniques/T1539/
tags:
  - attack.credential_access
  - attack.t1539
logsource:
  category: process_creation
  product: windows
detection:
  selection_browser:
    Image|endswith:
      - '\\\\chrome.exe'
      - '\\\\msedge.exe'
      - '\\\\firefox.exe'
      - '\\\\brave.exe'
  selection_debug:
    CommandLine|contains:
      - '--remote-debugging-port='
      - '--remote-debugging-address='
      - '--remote-allow-origins=*'
      - '-start-debugger-server'
  filter_devtools:
    ParentImage|endswith:
      - '\\\\code.exe'
      - '\\\\devenv.exe'
      - '\\\\idea64.exe'
  condition: selection_browser and selection_debug and not filter_devtools
falsepositives:
  - Web developers using browser debugging
  - Automated testing frameworks (Selenium, Puppeteer)`,
    language: "sigma",
    techniqueExternalId: "T1539",
    category: "credential-access",
    source: "TrustedSec Custom",
    severity: "high",
    tags: ["browser-debug", "cookie-theft", "credential-access", "session-hijack"],
  },

  {
    name: "Suspicious Use of Certutil for ADS Writing",
    description:
      "Detects use of certutil.exe to write data into Alternate Data Streams (ADS), a technique used to hide malicious payloads within the NTFS filesystem without affecting visible file content.",
    query: `DeviceProcessEvents
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has ":"
| where ProcessCommandLine has_any (
    "-urlcache -split -f",
    "-encode",
    "-decode",
    "-verifyctl")
| where ProcessCommandLine matches regex @"[A-Za-z]:\\\\[^:]+:[^\\s]+"
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FolderPath
| sort by Timestamp desc`,
    language: "kql",
    techniqueExternalId: "T1564.004",
    category: "defense-evasion",
    source: "Microsoft Defender for Endpoint",
    severity: "high",
    tags: ["certutil", "ads", "alternate-data-stream", "defense-evasion", "hidden"],
  },

  // =========================================================================
  // NETWORK DETECTION (Snort / Suricata)
  // =========================================================================

  // --- C2 Beaconing Patterns ---

  {
    name: "HTTP Beacon Interval Detection",
    description:
      "Detects regular HTTP beaconing patterns indicative of C2 communication. Identifies repeated connections to the same host at consistent intervals with small response bodies, characteristic of implant check-ins.",
    query: `alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET MALWARE Possible HTTP C2 Beacon - Consistent Interval Check-in";
  flow:established,to_server;
  http_method;
  content:"GET";
  http_uri;
  content:"/";
  depth:1;
  http_header;
  content:"Accept|3a 20|*/*";
  threshold:type both, track by_src, count 10, seconds 600;
  classtype:trojan-activity;
  sid:3000001;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1071.001",
    category: "c2-red-team",
    source: "Custom IDS Signatures",
    severity: "high",
    tags: ["c2", "beaconing", "http", "command-and-control"],
  },

  {
    name: "DNS Tunneling Detection - Long Queries",
    description:
      "Detects DNS tunneling by identifying DNS queries with unusually long subdomain labels (>50 characters), which is characteristic of tools like iodine, dnscat2, and dns2tcp that encode data in DNS queries.",
    query: `alert udp $HOME_NET any -> any 53 (
  msg:"ET MALWARE DNS Tunneling - Excessive Subdomain Length";
  content:"|01 00 00 01|";
  offset:2;
  depth:4;
  dns.query;
  pcre:"/^[a-z0-9\-]{50,}\\.([a-z0-9\-]+\\.){1,5}[a-z]{2,}$/i";
  threshold:type both, track by_src, count 20, seconds 60;
  classtype:trojan-activity;
  sid:3000002;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1572",
    category: "c2-red-team",
    source: "Custom IDS Signatures",
    severity: "high",
    tags: ["dns-tunneling", "c2", "exfiltration", "covert-channel"],
  },

  {
    name: "ICMP Tunneling Detection - Large Payloads",
    description:
      "Detects ICMP tunneling by identifying ICMP echo requests with abnormally large payloads (>100 bytes of data). Normal pings contain minimal data; large payloads indicate covert data channels via tools like icmpsh or ptunnel.",
    query: `alert icmp $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET MALWARE ICMP Tunneling - Oversized Echo Request Payload";
  itype:8;
  dsize:>100;
  threshold:type both, track by_src, count 10, seconds 30;
  classtype:trojan-activity;
  sid:3000003;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1095",
    category: "c2-red-team",
    source: "Custom IDS Signatures",
    severity: "medium",
    tags: ["icmp-tunnel", "c2", "covert-channel", "protocol-abuse"],
  },

  {
    name: "Known Malicious C2 User-Agent Strings",
    description:
      "Detects HTTP traffic using user-agent strings associated with known C2 frameworks and offensive tools including Cobalt Strike default WinINet, Empire, PoshC2, and Mythic default profiles.",
    query: `alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET MALWARE Cobalt Strike Default WinINet User-Agent";
  flow:established,to_server;
  http_header;
  content:"User-Agent|3a 20|Mozilla/5.0 (compatible|3b| MSIE 9.0|3b| Windows NT 6.1|3b| WOW64|3b| Trident/5.0)";
  fast_pattern;
  classtype:trojan-activity;
  sid:3000004;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET MALWARE PoshC2 Default User-Agent Detected";
  flow:established,to_server;
  http_header;
  content:"User-Agent|3a 20|Mozilla/5.0 (Windows NT 10.0|3b| Win64|3b| x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36";
  fast_pattern;
  classtype:trojan-activity;
  sid:3000005;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1071.001",
    category: "c2-red-team",
    source: "Emerging Threats",
    severity: "high",
    tags: ["c2", "user-agent", "cobalt-strike", "poshc2", "network-detection"],
  },

  // --- Exploit Traffic ---

  {
    name: "EternalBlue SMB Exploit Attempt",
    description:
      "Detects MS17-010 EternalBlue exploit attempts by identifying the characteristic SMB transaction request with the specific named pipe and tree connect patterns used by the exploit to trigger the buffer overflow in srv.sys.",
    query: `alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (
  msg:"ET EXPLOIT MS17-010 EternalBlue SMB Exploit Attempt";
  flow:established,to_server;
  content:"|FF|SMB|25 00 00 00 00|";
  offset:4;
  depth:9;
  content:"|00 00 00 00 00 00 00 00 00 00|";
  distance:0;
  within:10;
  content:"|23 00|";
  distance:56;
  within:2;
  reference:cve,2017-0144;
  reference:url,docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-010;
  classtype:attempted-admin;
  sid:3000006;
  rev:2;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1210",
    category: "external",
    source: "Emerging Threats",
    severity: "critical",
    tags: ["eternalblue", "ms17-010", "smb", "exploit", "wannacry"],
  },

  {
    name: "ProxyLogon SSRF Exploit Attempt (CVE-2021-26855)",
    description:
      "Detects ProxyLogon exploitation attempts against Microsoft Exchange by identifying the Server-Side Request Forgery via autodiscover endpoint with cookies targeting internal Exchange backend.",
    query: `alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
  msg:"ET EXPLOIT Microsoft Exchange ProxyLogon SSRF (CVE-2021-26855)";
  flow:established,to_server;
  http_uri;
  content:"/autodiscover/autodiscover.json";
  nocase;
  content:"/mapi/";
  nocase;
  distance:0;
  http_header;
  content:"X-BEResource";
  nocase;
  reference:cve,2021-26855;
  reference:url,www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/;
  classtype:web-application-attack;
  sid:3000007;
  rev:2;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1190",
    category: "external",
    source: "Emerging Threats",
    severity: "critical",
    tags: ["proxylogon", "exchange", "ssrf", "cve-2021-26855", "hafnium"],
  },

  {
    name: "ProxyShell Exchange Exploit Attempt (CVE-2021-34473)",
    description:
      "Detects ProxyShell exploitation attempts against Exchange by identifying the autodiscover path traversal used to access arbitrary backend URLs combined with encoded PowerShell mailbox export commands.",
    query: `alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
  msg:"ET EXPLOIT Microsoft Exchange ProxyShell Path Traversal (CVE-2021-34473)";
  flow:established,to_server;
  http_uri;
  content:"/autodiscover/autodiscover.json";
  nocase;
  content:"@";
  distance:0;
  content:"/powershell";
  nocase;
  distance:0;
  reference:cve,2021-34473;
  reference:url,peterjson.medium.com/reproducing-the-proxyshell-pwn2own-exploit-37e39fefb930;
  classtype:web-application-attack;
  sid:3000008;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1190",
    category: "external",
    source: "Emerging Threats",
    severity: "critical",
    tags: ["proxyshell", "exchange", "path-traversal", "cve-2021-34473"],
  },

  {
    name: "Log4Shell JNDI Injection Attempt (CVE-2021-44228)",
    description:
      "Detects Log4Shell exploitation attempts by identifying JNDI lookup strings in HTTP request headers and URIs. Covers common obfuscation patterns including nested lookups like ${lower:j} used to bypass WAFs.",
    query: `alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
  msg:"ET EXPLOIT Apache Log4j JNDI Injection Attempt (CVE-2021-44228)";
  flow:established,to_server;
  http_header;
  content:"\${";
  fast_pattern;
  content:"jndi";
  nocase;
  distance:0;
  content:":";
  distance:0;
  pcre:"/\\$\\{[^}]*(?:j|\\$\\{[^}]*j)[^}]*n[^}]*d[^}]*i[^}]*:/i";
  reference:cve,2021-44228;
  reference:url,logging.apache.org/log4j/2.x/security.html;
  classtype:attempted-admin;
  sid:3000009;
  rev:3;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)

alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
  msg:"ET EXPLOIT Log4j JNDI Injection in URI (CVE-2021-44228)";
  flow:established,to_server;
  http_uri;
  content:"\${";
  content:"jndi";
  nocase;
  distance:0;
  reference:cve,2021-44228;
  classtype:attempted-admin;
  sid:3000010;
  rev:2;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1190",
    category: "external",
    source: "Emerging Threats",
    severity: "critical",
    tags: ["log4shell", "log4j", "jndi", "cve-2021-44228", "rce"],
  },

  {
    name: "Spring4Shell RCE Exploit Attempt (CVE-2022-22965)",
    description:
      "Detects Spring4Shell exploitation by identifying HTTP requests that manipulate the classLoader via Spring parameter binding to modify Tomcat logging configuration, enabling webshell deployment.",
    query: `alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
  msg:"ET EXPLOIT Spring4Shell RCE - ClassLoader Manipulation (CVE-2022-22965)";
  flow:established,to_server;
  http_uri;
  content:"class.module.classLoader";
  nocase;
  fast_pattern;
  pcre:"/class\\.module\\.classLoader\\.resources\\.context\\.parent\\.pipeline/i";
  reference:cve,2022-22965;
  reference:url,spring.io/blog/2022/03/31/spring-framework-rce-early-announcement;
  classtype:web-application-attack;
  sid:3000011;
  rev:2;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1190",
    category: "external",
    source: "Emerging Threats",
    severity: "critical",
    tags: ["spring4shell", "spring-framework", "cve-2022-22965", "rce", "webshell"],
  },

  // --- Malware Callbacks ---

  {
    name: "Cobalt Strike Malleable C2 Default Profile",
    description:
      "Detects Cobalt Strike HTTP C2 traffic using the default malleable profile which submits beacon data as a Base64-encoded cookie named SESSIONID and receives tasks in jQuery-disguised responses.",
    query: `alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET MALWARE Cobalt Strike Default HTTP Beacon Profile";
  flow:established,to_server;
  http_uri;
  content:"/jquery-3.";
  depth:12;
  content:".slim.min.js";
  distance:0;
  http_header;
  content:"Cookie|3a 20|SESSIONID=";
  fast_pattern;
  pcre:"/SESSIONID=[A-Za-z0-9+\\/]{40,}={0,2}/";
  reference:url,hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/;
  classtype:trojan-activity;
  sid:3000012;
  rev:2;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1071.001",
    category: "c2-red-team",
    source: "Emerging Threats",
    severity: "critical",
    tags: ["cobalt-strike", "malleable-c2", "beacon", "http-profile"],
  },

  {
    name: "Metasploit Reverse TCP Shell",
    description:
      "Detects Metasploit framework reverse TCP shell connections by identifying the characteristic stage1 shellcode loader pattern that appears at the start of the TCP session when meterpreter is delivered.",
    query: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET MALWARE Metasploit Meterpreter Reverse TCP Shell Stager";
  flow:established,to_server;
  content:"|6A 0A 5F 68|";
  depth:4;
  content:"|FF D5 97 68|";
  distance:0;
  within:20;
  reference:url,www.rapid7.com/db/modules/exploit/multi/handler;
  classtype:trojan-activity;
  sid:3000013;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1059",
    category: "c2-red-team",
    source: "Emerging Threats",
    severity: "critical",
    tags: ["metasploit", "meterpreter", "reverse-shell", "stager"],
  },

  {
    name: "RAT Traffic - AsyncRAT Communication Pattern",
    description:
      "Detects AsyncRAT C2 communication by identifying the characteristic TLS ClientHello with specific JA3 hash and packet size patterns. AsyncRAT is a widely used open-source RAT distributed via phishing campaigns.",
    query: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET MALWARE AsyncRAT C2 Communication Pattern";
  flow:established,to_server;
  content:"|16 03 01|";
  depth:3;
  content:"|01|";
  offset:5;
  depth:1;
  dsize:<200;
  threshold:type both, track by_src, count 5, seconds 60;
  reference:url,github.com/NYAN-x-CAT/AsyncRAT-C-Sharp;
  classtype:trojan-activity;
  sid:3000014;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1219",
    category: "malware",
    source: "Custom IDS Signatures",
    severity: "high",
    tags: ["asyncrat", "rat", "trojan", "c2-callback"],
  },

  {
    name: "Cobalt Strike DNS Beacon",
    description:
      "Detects Cobalt Strike DNS beacon by identifying the characteristic DNS TXT query patterns with encoded data in subdomain labels. DNS beacons use predictable prefix patterns and base64-like encoding in queries.",
    query: `alert udp $HOME_NET any -> any 53 (
  msg:"ET MALWARE Cobalt Strike DNS Beacon - TXT Query Pattern";
  content:"|01 00 00 01|";
  offset:2;
  depth:4;
  dns.query;
  pcre:"/^(?:api|cdn|www|post|stage)\\.[a-z0-9]{8,}\\.(?:[a-z0-9-]+\\.){1,3}[a-z]{2,}$/i";
  content:"|00 10 00 01|";
  classtype:trojan-activity;
  sid:3000015;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1071.004",
    category: "c2-red-team",
    source: "Custom IDS Signatures",
    severity: "critical",
    tags: ["cobalt-strike", "dns-beacon", "c2", "dns-c2"],
  },

  // --- Data Exfiltration ---

  {
    name: "Data Exfiltration via Large DNS TXT Responses",
    description:
      "Detects potential data exfiltration via DNS by identifying DNS TXT responses with abnormally large payloads (>500 bytes). Attackers use DNS TXT records to exfiltrate data in chunks, bypassing firewalls that allow DNS.",
    query: `alert udp any 53 -> $HOME_NET any (
  msg:"ET EXFIL Data Exfiltration via Large DNS TXT Response";
  content:"|84 00|";
  offset:2;
  depth:2;
  content:"|00 10 00 01|";
  dsize:>500;
  threshold:type both, track by_dst, count 10, seconds 120;
  classtype:bad-unknown;
  sid:3000016;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1048.003",
    category: "collection-exfiltration",
    source: "Custom IDS Signatures",
    severity: "high",
    tags: ["exfiltration", "dns-txt", "data-theft", "covert-channel"],
  },

  {
    name: "HTTP POST Data Exfiltration to Uncommon Ports",
    description:
      "Detects potential data exfiltration via HTTP POST requests to non-standard ports (not 80/443/8080/8443). Attackers frequently use uncommon ports for POST-based exfiltration to avoid proxy inspection.",
    query: `alert tcp $HOME_NET any -> $EXTERNAL_NET ![$HTTP_PORTS,443,8443] (
  msg:"ET EXFIL HTTP POST to Uncommon Port - Possible Data Exfiltration";
  flow:established,to_server;
  content:"POST ";
  depth:5;
  content:"Content-Length|3a 20|";
  pcre:"/Content-Length:\\s*[1-9]\\d{5,}/";
  classtype:bad-unknown;
  sid:3000017;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1048.001",
    category: "collection-exfiltration",
    source: "Custom IDS Signatures",
    severity: "medium",
    tags: ["exfiltration", "http-post", "uncommon-port", "data-theft"],
  },

  {
    name: "Base64 Encoded Data in HTTP URI",
    description:
      "Detects potential data exfiltration or C2 communication using Base64-encoded payloads embedded in HTTP URIs. Long Base64 strings in URLs are unusual in legitimate traffic and indicate encoded commands or stolen data.",
    query: `alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET EXFIL Suspicious Base64-Encoded Data in HTTP URI";
  flow:established,to_server;
  http_uri;
  pcre:"/\\/[A-Za-z0-9+\\/]{100,}={0,2}(?:\\&|$|\\?)/";
  urilen:>150;
  classtype:bad-unknown;
  sid:3000018;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1132.001",
    category: "collection-exfiltration",
    source: "Custom IDS Signatures",
    severity: "medium",
    tags: ["exfiltration", "base64", "encoded-data", "url-encoding"],
  },

  // --- Lateral Movement Traffic ---

  {
    name: "PsExec SMB Service Installation",
    description:
      "Detects PsExec-style lateral movement by identifying the creation of the PSEXESVC service over SMB named pipes. PsExec writes a service binary to ADMIN$ and starts it remotely via the Service Control Manager.",
    query: `alert tcp $HOME_NET any -> $HOME_NET 445 (
  msg:"ET LATERAL PsExec Service Installation via SMB";
  flow:established,to_server;
  content:"|FF|SMB|25|";
  offset:4;
  depth:5;
  content:"PSEXESVC";
  nocase;
  fast_pattern;
  classtype:attempted-admin;
  sid:3000019;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)

alert tcp $HOME_NET any -> $HOME_NET 445 (
  msg:"ET LATERAL Impacket smbexec Service Installation via SMB";
  flow:established,to_server;
  content:"|FF|SMB|25|";
  offset:4;
  depth:5;
  content:"BTOBTO";
  nocase;
  classtype:attempted-admin;
  sid:3000020;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1021.002",
    category: "lateral-movement",
    source: "Custom IDS Signatures",
    severity: "high",
    tags: ["psexec", "smb", "lateral-movement", "service-installation", "impacket"],
  },

  {
    name: "WMI Remote Execution over DCOM",
    description:
      "Detects WMI-based remote code execution over DCOM by identifying DCE/RPC bind requests to the IWbemServices interface UUID. Attackers use WMI via DCOM (port 135 + dynamic high ports) for fileless lateral movement.",
    query: `alert tcp $HOME_NET any -> $HOME_NET 135 (
  msg:"ET LATERAL WMI Remote Execution - IWbemServices Bind Request";
  flow:established,to_server;
  content:"|05 00 0B|";
  depth:3;
  content:"|A8 F4 0B 6E 6C D1 11 88 22 00 AA 00 4B A9 0B|";
  fast_pattern;
  classtype:attempted-admin;
  sid:3000021;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1047",
    category: "lateral-movement",
    source: "Custom IDS Signatures",
    severity: "high",
    tags: ["wmi", "dcom", "lateral-movement", "dce-rpc", "fileless"],
  },

  {
    name: "DCE/RPC Remote Service Manager Abuse",
    description:
      "Detects abuse of the Windows Service Control Manager (SVCCTL) via DCE/RPC for remote service creation, commonly used by tools like sc.exe, PsExec, and Impacket for lateral movement.",
    query: `alert tcp $HOME_NET any -> $HOME_NET any (
  msg:"ET LATERAL DCE/RPC SVCCTL CreateServiceW - Remote Service Creation";
  flow:established,to_server;
  content:"|05 00 00|";
  depth:3;
  content:"|0C 00|";
  offset:22;
  depth:2;
  content:"|67 45 23 01 AB EF CD AB|";
  classtype:attempted-admin;
  sid:3000022;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1021.002",
    category: "lateral-movement",
    source: "Custom IDS Signatures",
    severity: "high",
    tags: ["dce-rpc", "svcctl", "service-creation", "lateral-movement"],
  },

  {
    name: "Pass-the-Hash NTLM Authentication Anomaly",
    description:
      "Detects potential pass-the-hash attacks by identifying NTLM authentication over SMB with NTLMv2 response but empty LMv2 response (all zeros), which is characteristic of PTH tools like mimikatz sekurlsa::pth.",
    query: `alert tcp $HOME_NET any -> $HOME_NET 445 (
  msg:"ET LATERAL Pass-the-Hash - Empty LM Response in NTLMSSP Auth";
  flow:established,to_server;
  content:"NTLMSSP";
  content:"|03 00 00 00|";
  distance:0;
  within:4;
  content:"|00 00 00 00 00 00 00 00|";
  distance:4;
  within:8;
  classtype:attempted-admin;
  sid:3000023;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1550.002",
    category: "lateral-movement",
    source: "Custom IDS Signatures",
    severity: "critical",
    tags: ["pass-the-hash", "ntlm", "smb", "mimikatz", "credential-abuse"],
  },

  // --- Credential Theft ---

  {
    name: "LDAP Cleartext Simple Bind Credential Exposure",
    description:
      "Detects LDAP simple bind operations transmitted in cleartext over port 389, exposing credentials on the wire. Simple binds send passwords unencrypted unless TLS is used, making them vulnerable to sniffing.",
    query: `alert tcp $HOME_NET any -> any 389 (
  msg:"ET CREDENTIAL LDAP Cleartext Simple Bind - Password Exposure";
  flow:established,to_server;
  content:"|30|";
  depth:1;
  content:"|60|";
  within:10;
  content:"|80|";
  within:20;
  pcre:"/\\x30.+\\x60.+\\x02\\x01.+\\x04.{1,256}\\x80.{1,256}/s";
  classtype:attempted-user;
  sid:3000024;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1110",
    category: "credential-access",
    source: "Custom IDS Signatures",
    severity: "high",
    tags: ["ldap", "cleartext", "credential-exposure", "simple-bind"],
  },

  {
    name: "Kerberoasting TGS-REP Traffic Pattern",
    description:
      "Detects potential Kerberoasting by identifying Kerberos TGS-REP responses with RC4 (etype 23) encrypted service tickets. Monitoring network-level TGS responses supplements event log detections for environments without Windows audit logging.",
    query: `alert tcp any 88 -> $HOME_NET any (
  msg:"ET CREDENTIAL Kerberos TGS-REP with RC4 Encryption (Kerberoasting)";
  flow:established,to_client;
  content:"|A0 03 02 01 05|";
  content:"|A0 03 02 01 0D|";
  distance:0;
  within:20;
  content:"|17|";
  distance:0;
  within:30;
  threshold:type both, track by_dst, count 5, seconds 60;
  classtype:credential-theft;
  sid:3000025;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1558.003",
    category: "credential-access",
    source: "Custom IDS Signatures",
    severity: "high",
    tags: ["kerberoasting", "tgs-rep", "rc4", "kerberos", "credential-theft"],
  },

  {
    name: "NTLM Relay Attack Indicator",
    description:
      "Detects potential NTLM relay attacks by identifying NTLMSSP authentication messages being forwarded between two internal hosts, where the same NTLMSSP challenge appears on separate connections -- characteristic of tools like ntlmrelayx and Responder.",
    query: `alert tcp $HOME_NET any -> $HOME_NET 445 (
  msg:"ET CREDENTIAL NTLM Relay - NTLMSSP Challenge Forwarding Indicator";
  flow:established,to_server;
  content:"NTLMSSP";
  content:"|01 00 00 00|";
  distance:0;
  within:4;
  content:"|B2 B3|";
  distance:8;
  within:4;
  threshold:type both, track by_src, count 3, seconds 10;
  classtype:credential-theft;
  sid:3000026;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1557.001",
    category: "credential-access",
    source: "Custom IDS Signatures",
    severity: "critical",
    tags: ["ntlm-relay", "ntlmssp", "responder", "credential-theft", "mitm"],
  },

  // --- Scanning / Reconnaissance ---

  {
    name: "TCP Port Scan Detection - SYN Sweep",
    description:
      "Detects TCP SYN port scanning by identifying a single source sending SYN packets to multiple destination ports on the same host within a short window. Covers both horizontal and vertical scan patterns used by nmap and masscan.",
    query: `alert tcp $EXTERNAL_NET any -> $HOME_NET any (
  msg:"ET SCAN TCP SYN Port Scan Detected";
  flags:S,12;
  threshold:type both, track by_src, count 30, seconds 10;
  classtype:attempted-recon;
  sid:3000027;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1046",
    category: "discovery",
    source: "Custom IDS Signatures",
    severity: "medium",
    tags: ["port-scan", "syn-scan", "nmap", "recon", "network-scanning"],
  },

  {
    name: "SMB Share Enumeration Detection",
    description:
      "Detects SMB share enumeration by identifying NetShareEnumAll requests over SMB/DCE-RPC (SRVSVC). Attackers use net view, CrackMapExec, and other tools to enumerate accessible shares for lateral movement and data discovery.",
    query: `alert tcp $HOME_NET any -> $HOME_NET 445 (
  msg:"ET SCAN SMB NetShareEnumAll - Share Enumeration";
  flow:established,to_server;
  content:"|FF|SMB|25|";
  offset:4;
  depth:5;
  content:"\\PIPE\\srvsvc";
  nocase;
  content:"|0F 00|";
  distance:0;
  within:20;
  classtype:attempted-recon;
  sid:3000028;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1135",
    category: "discovery",
    source: "Custom IDS Signatures",
    severity: "medium",
    tags: ["smb-enum", "share-enumeration", "recon", "crackmapexec", "net-view"],
  },

  {
    name: "SNMP Community String Brute Force",
    description:
      "Detects SNMP community string brute-force attempts by identifying a high volume of SNMP GetRequest packets from a single source, indicating tools like onesixtyone or snmpwalk scanning for weak community strings.",
    query: `alert udp $EXTERNAL_NET any -> $HOME_NET 161 (
  msg:"ET SCAN SNMP Community String Brute Force Attempt";
  content:"|30|";
  depth:1;
  content:"|A0|";
  within:20;
  threshold:type both, track by_src, count 50, seconds 30;
  classtype:attempted-recon;
  sid:3000029;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1046",
    category: "discovery",
    source: "Custom IDS Signatures",
    severity: "medium",
    tags: ["snmp", "brute-force", "community-string", "recon", "onesixtyone"],
  },

  // --- Protocol Anomalies ---

  {
    name: "TLS Certificate Anomaly - Self-Signed with Short Validity",
    description:
      "Detects TLS connections using self-signed certificates with very short validity periods (<7 days), which is characteristic of dynamically generated C2 certificates from frameworks like Cobalt Strike, Metasploit, and Covenant.",
    query: `alert tls $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET ANOMALY TLS Self-Signed Certificate with Short Validity Period";
  flow:established,to_server;
  tls.cert_issuer;
  tls.cert_subject;
  tls_cert_notbefore;
  tls_cert_notafter;
  lua:check_cert_validity_short;
  classtype:bad-unknown;
  sid:3000030;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1587.003",
    category: "defense-evasion",
    source: "Custom IDS Signatures",
    severity: "medium",
    tags: ["tls-anomaly", "self-signed", "certificate", "c2-infrastructure"],
  },

  {
    name: "HTTP CONNECT Method Tunneling Abuse",
    description:
      "Detects abuse of the HTTP CONNECT method to establish tunnels through proxies to non-standard destination ports. Attackers use CONNECT tunneling to bypass network controls and route C2 traffic through legitimate proxy infrastructure.",
    query: `alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET ANOMALY HTTP CONNECT Tunnel to Non-Standard Port";
  flow:established,to_server;
  http_method;
  content:"CONNECT";
  http_uri;
  pcre:"/^[^:]+:(?!443|80|8080|8443)\\d+$/";
  classtype:bad-unknown;
  sid:3000031;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1090.002",
    category: "defense-evasion",
    source: "Custom IDS Signatures",
    severity: "medium",
    tags: ["http-connect", "tunneling", "proxy-abuse", "protocol-anomaly"],
  },

  {
    name: "DNS Query Length Anomaly - Possible Tunneling",
    description:
      "Detects DNS queries with abnormally long total query names (>180 bytes), which far exceeds the typical 20-40 byte domain length. Excessive query lengths strongly indicate DNS tunneling for data exfiltration or C2.",
    query: `alert udp $HOME_NET any -> any 53 (
  msg:"ET ANOMALY Abnormally Long DNS Query - Possible Tunneling";
  content:"|01 00 00 01|";
  offset:2;
  depth:4;
  dns.query;
  pcre:"/^.{180,}/";
  threshold:type both, track by_src, count 5, seconds 60;
  classtype:bad-unknown;
  sid:3000032;
  rev:1;
  metadata:created_at 2025_06_01, updated_at 2025_06_01;
)`,
    language: "snort",
    techniqueExternalId: "T1572",
    category: "defense-evasion",
    source: "Custom IDS Signatures",
    severity: "high",
    tags: ["dns-anomaly", "query-length", "tunneling", "exfiltration"],
  },
];

// ---------------------------------------------------------------------------
// Main seed function
// ---------------------------------------------------------------------------
async function main() {
  console.log("=== Detection Rule Seed Script ===\n");

  // 1. Collect all unique technique externalIds from the rules
  const externalIds = [
    ...new Set(
      RULES.map((r) => r.techniqueExternalId).filter(Boolean) as string[]
    ),
  ];

  console.log(`Looking up ${externalIds.length} MITRE ATT&CK techniques...`);

  // 2. Batch-fetch all techniques in one query
  const techniques = await prisma.technique.findMany({
    where: { externalId: { in: externalIds } },
    select: { id: true, externalId: true, name: true },
  });

  const techMap = new Map(techniques.map((t) => [t.externalId, t.id]));

  // Report any missing techniques
  const missing = externalIds.filter((eid) => !techMap.has(eid));
  if (missing.length > 0) {
    console.warn(
      `  WARNING: ${missing.length} technique(s) not found in DB (rules will be created without link):`,
      missing
    );
  } else {
    console.log(`  All ${externalIds.length} techniques resolved.`);
  }

  // 3. Upsert each rule (findFirst + create/update since no unique constraint)
  let created = 0;
  let updated = 0;

  for (const rule of RULES) {
    const techniqueId = rule.techniqueExternalId
      ? techMap.get(rule.techniqueExternalId) ?? null
      : null;

    const existing = await prisma.detectionRule.findFirst({
      where: {
        name: rule.name,
        language: rule.language,
      },
    });

    const data = {
      name: rule.name,
      description: rule.description,
      query: rule.query,
      language: rule.language,
      techniqueId,
      category: rule.category,
      source: rule.source,
      severity: rule.severity,
      tags: JSON.stringify(rule.tags),
    };

    if (existing) {
      await prisma.detectionRule.update({
        where: { id: existing.id },
        data,
      });
      updated++;
    } else {
      await prisma.detectionRule.create({ data });
      created++;
    }
  }

  console.log(
    `\nSeeded ${RULES.length} detection rules (${created} created, ${updated} updated).\n`
  );

  // 4. Print summary counts
  const categoryCounts: Record<string, number> = {};
  const languageCounts: Record<string, number> = {};
  for (const rule of RULES) {
    categoryCounts[rule.category] = (categoryCounts[rule.category] || 0) + 1;
    languageCounts[rule.language] = (languageCounts[rule.language] || 0) + 1;
  }

  console.log("Rules per category:");
  for (const [cat, count] of Object.entries(categoryCounts).sort(
    (a, b) => b[1] - a[1]
  )) {
    console.log(`  ${cat.padEnd(22)} ${count}`);
  }

  console.log("\nRules per language:");
  for (const [lang, count] of Object.entries(languageCounts).sort(
    (a, b) => b[1] - a[1]
  )) {
    console.log(`  ${lang.padEnd(10)} ${count}`);
  }

  console.log("\nDone.");
  await prisma.$disconnect();
}

main()
  .catch((err) => {
    console.error("Seed failed:", err);
    process.exit(1);
  })
  .finally(() => process.exit(0));
