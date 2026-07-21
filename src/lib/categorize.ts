import { prisma } from "./db";

interface CategoryRule {
  slug: string;
  techniquePatterns: RegExp[];
  platformPatterns: RegExp[];
  actorPatterns: RegExp[];
  descriptionPatterns: RegExp[];
}

const RULES: CategoryRule[] = [
  {
    slug: "active-directory",
    techniquePatterns: [
      /T1558/, /T1003/, /T1087\.001/, /T1087\.002/, /T1069\.001/, /T1069\.002/,
      /T1482/, /T1484/, /T1207/, /T1556/, /T1187/, /T1557/,
      /T1550\.002/, /T1550\.003/, /T1134/, /T1098\.001/, /T1098\.002/,
      /T1078\.002/, /T1136\.001/, /T1136\.002/, /T1110\.001/, /T1110\.002/, /T1110\.003/,
      /T1021\.002/, /T1021\.006/, /T1047/, /T1053\.005/, /T1543\.003/,
      /T1574\.007/, /T1574\.012/,
    ],
    platformPatterns: [/windows/i],
    actorPatterns: [],
    descriptionPatterns: [
      /active directory/i, /domain controller/i, /kerbero/i, /LDAP/i, /DCSync/i,
      /group policy/i, /GPO/i, /NTDS/i, /NTLM/i, /pass.the.hash/i, /pass.the.ticket/i,
      /golden ticket/i, /silver ticket/i, /domain admin/i, /BloodHound/i, /SharpHound/i,
      /trust relationship/i, /forest/i, /domain trust/i, /SID.History/i, /AdminSDHolder/i,
      /DPAPI/i, /LSASS/i, /SAM database/i, /Security Account Manager/i, /net.exe/i,
      /dsquery/i, /nltest/i, /adfind/i, /PowerView/i, /Rubeus/i, /Certify/i,
      /AD CS/i, /certificate.servic/i, /ADCS/i, /unconstrained delegation/i,
      /constrained delegation/i, /resource.based/i, /RBCD/i, /shadow credential/i,
      /msDS-KeyCredentialLink/i, /DACL/i, /ACL abuse/i, /WriteDacl/i, /GenericAll/i,
      /GenericWrite/i, /ForceChangePassword/i, /DCOM/i, /WinRM/i, /PSRemoting/i,
    ],
  },
  {
    slug: "cloud",
    techniquePatterns: [
      /T1078\.004/, /T1538/, /T1580/, /T1619/, /T1552\.005/, /T1098\.003/,
      /T1078\.001/, /T1136\.003/, /T1087\.004/, /T1069\.003/, /T1526/,
      /T1530/, /T1537/, /T1550\.001/, /T1213\.003/, /T1110\.004/,
      /T1621/, /T1556\.006/, /T1556\.007/, /T1556\.009/,
    ],
    platformPatterns: [/azure/i, /aws/i, /gcp/i, /saas/i, /office.365/i, /iaas/i, /identity provider/i, /google workspace/i],
    actorPatterns: [
      /volt typhoon/i, /salt typhoon/i, /flax typhoon/i, /hafnium/i, /midnight blizzard/i,
      /scattered spider/i, /star blizzard/i, /apt29/i, /apt41/i,
    ],
    descriptionPatterns: [
      /cloud/i, /AWS/i, /Azure/i, /GCP/i, /S3 bucket/i, /IAM/i, /metadata service/i,
      /instance metadata/i, /IMDS/i, /cloud.shell/i, /tenant/i, /service principal/i,
      /managed identity/i, /lambda/i, /cloud.trail/i, /cloud.watch/i,
      /Office 365/i, /Microsoft 365/i, /Entra/i, /Azure AD/i, /AAD/i,
      /Google Workspace/i, /GCP project/i, /EC2/i, /ECS/i, /EKS/i, /AKS/i,
      /Kubernetes/i, /container registry/i, /cloud function/i, /cloud run/i,
      /federation/i, /SAML/i, /OAuth/i, /SPN/i, /app registration/i,
      /conditional access/i, /PIM/i, /Privileged Identity/i,
      /storage account/i, /blob/i, /cloud storage/i, /cloud.log/i,
      /VPC/i, /security group/i, /cloud.formation/i, /terraform/i, /ARM template/i,
    ],
  },
  {
    slug: "external",
    techniquePatterns: [/T1190/, /T1133/, /T1566/, /T1598/, /T1189/, /T1195/, /T1199/],
    platformPatterns: [],
    actorPatterns: [],
    descriptionPatterns: [
      /phish/i, /exploit public/i, /VPN/i, /external.facing/i, /web.shell/i,
      /spearphish/i, /drive.by/i, /watering.hole/i, /initial access broker/i,
      /remote desktop/i, /RDP/i, /brute.force/i,
    ],
  },
  {
    slug: "satcom",
    techniquePatterns: [],
    platformPatterns: [],
    actorPatterns: [/viasat/i, /turla/i],
    descriptionPatterns: [
      /satellite/i, /SATCOM/i, /VSAT/i, /GPS/i, /ground station/i, /transponder/i,
    ],
  },
  {
    slug: "ot-ics",
    techniquePatterns: [],
    platformPatterns: [],
    actorPatterns: [/sandworm/i, /xenotime/i, /triton/i, /chernovite/i, /electrum/i],
    descriptionPatterns: [
      /ICS/i, /SCADA/i, /PLC/i, /HMI/i, /Modbus/i, /DNP3/i, /OPC/i,
      /industrial control/i, /operational technology/i, /safety.instrument/i,
      /engineering workstation/i, /RTU/i,
    ],
  },
  {
    slug: "healthcare",
    techniquePatterns: [
      /T1486/, /T1490/, /T1489/, /T1021/, /T1078/, /T1570/,
      /T1048/, /T1136/, /T1059/, /T1055/, /T1003/, /T1560/,
    ],
    platformPatterns: [],
    actorPatterns: [
      /lockbit/i, /blackcat/i, /alphv/i, /noberus/i, /conti/i, /ryuk/i,
      /wizard spider/i, /revil/i, /sodinokibi/i, /darkside/i, /blackmatter/i,
      /hive/i, /royal/i, /blacksuit/i, /clop/i, /cl0p/i, /rhysida/i,
      /bianlian/i, /vice society/i, /hunters international/i, /daixin/i,
      /black basta/i, /blackbasta/i, /blackbyte/i, /karakurt/i,
      /akira/i, /phobos/i, /dharma/i, /medusa/i, /inc ransom/i,
      /fog ransom/i, /ransomhub/i, /qilin/i, /play\b/i, /8base/i,
      /lazarus/i, /hidden cobra/i, /andariel/i, /apt41/i, /fin12/i,
      /storm.0501/i, /scattered spider/i, /lapsus/i,
    ],
    descriptionPatterns: [
      /hospital/i, /healthcare/i, /medical.device/i, /HL7/i, /DICOM/i, /EHR/i,
      /HIPAA/i, /HITECH/i, /patient.(data|record|care|information|portal|monitor)/i,
      /pharma/i, /health.system/i, /health.sector/i, /healthcare.provider/i,
      /medical.center/i, /medical.record/i, /medical.imaging/i,
      /clinical/i, /clinic/i, /biotech/i, /life.sciences/i,
      /vaccine/i, /telehealth/i, /telemedicine/i, /electronic.health/i,
      /protected.health.information/i, /\bPHI\b/, /\bFDA\b/,
    ],
  },
  {
    slug: "ransomware",
    techniquePatterns: [/T1486/, /T1490/, /T1489/, /T1491\.002/],
    platformPatterns: [],
    actorPatterns: [
      /lockbit/i, /blackcat/i, /alphv/i, /noberus/i, /conti/i, /ryuk/i, /revil/i, /sodinokibi/i,
      /darkside/i, /blackmatter/i, /hive/i, /royal/i, /blacksuit/i, /clop/i, /cl0p/i,
      /play/i, /akira/i, /black basta/i, /blackbasta/i, /maze/i, /ragnar/i, /babuk/i, /cuba/i,
      /rhysida/i, /bianlian/i, /vice society/i, /hunters international/i, /noescape/i,
      /cactus/i, /8base/i, /eightbase/i, /snatch/i, /avoslocker/i, /phobos/i, /dharma/i,
      /trigona/i, /qilin/i, /agenda/i, /fog ransom/i, /ransomhub/i, /karakurt/i,
      /dragonforce/i, /hackledorb/i, /medusa/i, /inc ransom/i, /blackbyte/i,
    ],
    descriptionPatterns: [
      /ransom/i, /encrypt.*files/i, /double extortion/i, /data leak site/i,
      /\.onion/i, /victim.*pay/i, /decryption key/i, /raas/i, /ransomware.as.a.service/i,
      /data extortion/i, /leak site/i, /triple extortion/i, /exit scam/i,
    ],
  },
  {
    slug: "malware",
    techniquePatterns: [/T1059/, /T1055/, /T1027/, /T1140/, /T1036/, /T1071/, /T1105/],
    platformPatterns: [],
    actorPatterns: [],
    descriptionPatterns: [
      /malware/i, /trojan/i, /RAT/i, /loader/i, /stealer/i, /wiper/i, /implant/i,
      /bootkit/i, /rootkit/i, /backdoor/i, /dropper/i, /payload/i, /shellcode/i,
      /beacon/i, /C2 channel/i,
    ],
  },
  {
    slug: "c2-red-team",
    techniquePatterns: [/T1071/, /T1572/, /T1573/, /T1095/, /T1132/, /T1001/, /T1102/],
    platformPatterns: [],
    actorPatterns: [],
    descriptionPatterns: [
      /cobalt strike/i, /sliver/i, /havoc/i, /mythic/i, /metasploit/i, /meterpreter/i,
      /command.and.control/i, /C2/i, /brute ratel/i, /nighthawk/i, /covenant/i,
      /empire/i, /pupy/i, /poshc2/i, /merlin/i, /silver/i,
    ],
  },
  {
    slug: "container-k8s",
    techniquePatterns: [
      /T1610/, /T1612/, /T1613/, /T1609/, /T1611/,
    ],
    platformPatterns: [/containers/i, /kubernetes/i],
    actorPatterns: [
      /team tnt/i, /teamtnt/i, /siloscape/i, /hildegard/i, /kinsing/i,
      /scarleteel/i, /dero/i,
    ],
    descriptionPatterns: [
      /kubernetes/i, /k8s/i, /docker/i, /container/i, /pod/i, /kubelet/i,
      /kubectl/i, /kube.api/i, /kube.proxy/i, /etcd/i, /helm/i,
      /container.escape/i, /container.breakout/i, /privileged.container/i,
      /service.account.token/i, /cluster.?admin/i, /namespace/i,
      /daemon.?set/i, /cron.?job/i, /init.?container/i, /sidecar/i,
      /image.pull/i, /container.registr/i, /harbor/i, /containerd/i, /cri.?o/i,
      /runc/i, /cgroup/i, /seccomp/i, /apparmor/i, /pod.security/i,
      /node.?port/i, /load.?balancer/i, /ingress/i, /service.?mesh/i, /istio/i,
      /envoy/i, /linkerd/i, /calico/i, /cilium/i,
      /AKS/i, /EKS/i, /GKE/i, /OpenShift/i, /Rancher/i, /k3s/i,
      /admission.?control/i, /opa/i, /gatekeeper/i, /falco/i,
      /cryptomin/i, /crypto.?jack/i, /mine.?pool/i,
    ],
  },
  {
    slug: "social-engineering",
    techniquePatterns: [
      /T1566/, /T1598/, /T1534/, /T1585/, /T1586/, /T1656/,
      /T1566\.001/, /T1566\.002/, /T1566\.003/, /T1566\.004/,
      /T1598\.001/, /T1598\.002/, /T1598\.003/, /T1598\.004/,
      /T1204\.001/, /T1204\.002/, /T1204\.003/,
    ],
    platformPatterns: [],
    actorPatterns: [
      /scattered spider/i, /star blizzard/i, /kimsuky/i, /lazarus/i,
      /midnight blizzard/i, /ocean lotus/i, /charming kitten/i,
      /phosphorus/i, /nobelium/i, /lapsus/i,
    ],
    descriptionPatterns: [
      /phish/i, /spearphish/i, /social engineer/i, /pretexting/i,
      /vishing/i, /smishing/i, /business email compromise/i, /BEC/i,
      /impersonat/i, /spoof.*email/i, /email.*spoof/i,
      /MFA.?fatigue/i, /MFA.?bomb/i, /MFA.?push/i, /MFA.?flood/i,
      /prompt.?bomb/i, /credential.?harvest/i, /login.?page/i,
      /consent.?phish/i, /OAuth.?phish/i, /QR.?phish/i, /quish/i,
      /watering.?hole/i, /malicious.?link/i, /malicious.?attach/i,
      /lure/i, /decoy/i, /social.media.*recon/i,
      /callback.?phish/i, /voice.?phish/i, /deepfake/i, /AI.?generated/i,
    ],
  },
];

function matchesAny(text: string, patterns: RegExp[]): boolean {
  return patterns.some((p) => p.test(text));
}

export async function categorizeTechniques() {
  const categories = await prisma.category.findMany();
  const catMap = new Map(categories.map((c) => [c.slug, c.id]));
  const techniques = await prisma.technique.findMany();
  let linkCount = 0;

  for (const tech of techniques) {
    for (const rule of RULES) {
      const catId = catMap.get(rule.slug);
      if (!catId) continue;

      const matches =
        matchesAny(tech.externalId, rule.techniquePatterns) ||
        matchesAny(tech.platforms, rule.platformPatterns) ||
        matchesAny(tech.description, rule.descriptionPatterns);

      if (matches) {
        const existing = await prisma.categoryTechnique.findUnique({
          where: { categoryId_techniqueId: { categoryId: catId, techniqueId: tech.id } },
        });
        if (!existing) {
          await prisma.categoryTechnique.create({
            data: { categoryId: catId, techniqueId: tech.id },
          });
          linkCount++;
        }
      }
    }
  }
  return linkCount;
}

export async function categorizeActors() {
  const categories = await prisma.category.findMany();
  const catMap = new Map(categories.map((c) => [c.slug, c.id]));
  const actors = await prisma.threatActor.findMany();
  let linkCount = 0;

  for (const actor of actors) {
    const searchText = `${actor.name} ${actor.aliases ?? ""} ${actor.description}`;
    for (const rule of RULES) {
      const catId = catMap.get(rule.slug);
      if (!catId) continue;

      const matches =
        matchesAny(searchText, rule.actorPatterns) ||
        matchesAny(searchText, rule.descriptionPatterns);

      if (matches) {
        const existing = await prisma.categoryActor.findUnique({
          where: { categoryId_actorId: { categoryId: catId, actorId: actor.id } },
        });
        if (!existing) {
          await prisma.categoryActor.create({
            data: { categoryId: catId, actorId: actor.id },
          });
          linkCount++;
        }
      }
    }
  }
  return linkCount;
}
