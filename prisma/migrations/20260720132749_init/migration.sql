-- CreateEnum
CREATE TYPE "Role" AS ENUM ('READER', 'EDITOR', 'ADMIN');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT,
    "hashedPassword" TEXT NOT NULL,
    "role" "Role" NOT NULL DEFAULT 'READER',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Session" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Tactic" (
    "id" TEXT NOT NULL,
    "stixId" TEXT NOT NULL,
    "externalId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "shortName" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "matrix" TEXT NOT NULL,
    "orderIndex" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Tactic_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Technique" (
    "id" TEXT NOT NULL,
    "stixId" TEXT NOT NULL,
    "externalId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "platforms" TEXT NOT NULL,
    "dataSources" TEXT,
    "detection" TEXT,
    "isSubtechnique" BOOLEAN NOT NULL DEFAULT false,
    "parentId" TEXT,
    "matrix" TEXT NOT NULL,
    "deprecated" BOOLEAN NOT NULL DEFAULT false,
    "revoked" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Technique_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TacticTechnique" (
    "tacticId" TEXT NOT NULL,
    "techniqueId" TEXT NOT NULL,

    CONSTRAINT "TacticTechnique_pkey" PRIMARY KEY ("tacticId","techniqueId")
);

-- CreateTable
CREATE TABLE "ThreatActor" (
    "id" TEXT NOT NULL,
    "stixId" TEXT NOT NULL,
    "externalId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "aliases" TEXT,
    "description" TEXT NOT NULL,
    "country" TEXT,
    "motivations" TEXT,
    "url" TEXT NOT NULL,
    "matrix" TEXT NOT NULL,
    "deprecated" BOOLEAN NOT NULL DEFAULT false,
    "revoked" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ThreatActor_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Procedure" (
    "id" TEXT NOT NULL,
    "stixId" TEXT NOT NULL,
    "actorId" TEXT,
    "campaignId" TEXT,
    "malwareId" TEXT,
    "toolId" TEXT,
    "techniqueId" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Procedure_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AtomicTest" (
    "id" TEXT NOT NULL,
    "guid" TEXT NOT NULL,
    "techniqueId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "platforms" TEXT NOT NULL,
    "executor" TEXT NOT NULL,
    "command" TEXT NOT NULL,
    "cleanupCommand" TEXT,
    "inputArguments" TEXT,
    "elevationRequired" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AtomicTest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Campaign" (
    "id" TEXT NOT NULL,
    "stixId" TEXT NOT NULL,
    "externalId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "firstSeen" TIMESTAMP(3),
    "lastSeen" TIMESTAMP(3),
    "url" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Campaign_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CampaignActor" (
    "campaignId" TEXT NOT NULL,
    "actorId" TEXT NOT NULL,

    CONSTRAINT "CampaignActor_pkey" PRIMARY KEY ("campaignId","actorId")
);

-- CreateTable
CREATE TABLE "Malware" (
    "id" TEXT NOT NULL,
    "stixId" TEXT NOT NULL,
    "externalId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "aliases" TEXT,
    "description" TEXT NOT NULL,
    "type" TEXT,
    "platforms" TEXT,
    "url" TEXT NOT NULL,
    "deprecated" BOOLEAN NOT NULL DEFAULT false,
    "revoked" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Malware_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MalwareTechnique" (
    "malwareId" TEXT NOT NULL,
    "techniqueId" TEXT NOT NULL,

    CONSTRAINT "MalwareTechnique_pkey" PRIMARY KEY ("malwareId","techniqueId")
);

-- CreateTable
CREATE TABLE "Tool" (
    "id" TEXT NOT NULL,
    "stixId" TEXT NOT NULL,
    "externalId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "aliases" TEXT,
    "description" TEXT NOT NULL,
    "platforms" TEXT,
    "url" TEXT NOT NULL,
    "deprecated" BOOLEAN NOT NULL DEFAULT false,
    "revoked" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Tool_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ToolTechnique" (
    "toolId" TEXT NOT NULL,
    "techniqueId" TEXT NOT NULL,

    CONSTRAINT "ToolTechnique_pkey" PRIMARY KEY ("toolId","techniqueId")
);

-- CreateTable
CREATE TABLE "ActorMalware" (
    "actorId" TEXT NOT NULL,
    "malwareId" TEXT NOT NULL,

    CONSTRAINT "ActorMalware_pkey" PRIMARY KEY ("actorId","malwareId")
);

-- CreateTable
CREATE TABLE "Category" (
    "id" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "color" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Category_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CategoryTechnique" (
    "categoryId" TEXT NOT NULL,
    "techniqueId" TEXT NOT NULL,
    "isManualOverride" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "CategoryTechnique_pkey" PRIMARY KEY ("categoryId","techniqueId")
);

-- CreateTable
CREATE TABLE "CategoryActor" (
    "categoryId" TEXT NOT NULL,
    "actorId" TEXT NOT NULL,
    "isManualOverride" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "CategoryActor_pkey" PRIMARY KEY ("categoryId","actorId")
);

-- CreateTable
CREATE TABLE "Advisory" (
    "id" TEXT NOT NULL,
    "advisoryId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "severity" TEXT,
    "cveId" TEXT,
    "vendorProject" TEXT,
    "product" TEXT,
    "dateAdded" TIMESTAMP(3),
    "dueDate" TIMESTAMP(3),
    "knownRansomware" BOOLEAN NOT NULL DEFAULT false,
    "url" TEXT,
    "rawJson" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Advisory_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IOC" (
    "id" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "advisoryId" TEXT,
    "description" TEXT,
    "firstSeen" TIMESTAMP(3),
    "lastSeen" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IOC_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DetectionRule" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "query" TEXT NOT NULL,
    "language" TEXT NOT NULL,
    "techniqueId" TEXT,
    "category" TEXT,
    "source" TEXT,
    "severity" TEXT,
    "tags" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DetectionRule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SandboxAnalysis" (
    "id" TEXT NOT NULL,
    "indicator" TEXT NOT NULL,
    "indicatorType" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "malicious" INTEGER NOT NULL DEFAULT 0,
    "suspicious" INTEGER NOT NULL DEFAULT 0,
    "harmless" INTEGER NOT NULL DEFAULT 0,
    "undetected" INTEGER NOT NULL DEFAULT 0,
    "score" INTEGER NOT NULL DEFAULT 0,
    "verdict" TEXT,
    "malwareFamily" TEXT,
    "tags" TEXT,
    "fileType" TEXT,
    "fileSize" INTEGER,
    "fileName" TEXT,
    "sha256" TEXT,
    "md5" TEXT,
    "sha1" TEXT,
    "ssdeep" TEXT,
    "firstSeen" TIMESTAMP(3),
    "lastSeen" TIMESTAMP(3),
    "techniques" TEXT,
    "rawJson" TEXT,
    "iocId" TEXT,
    "fetchedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SandboxAnalysis_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UpdateLog" (
    "id" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "recordsProcessed" INTEGER NOT NULL DEFAULT 0,
    "recordsCreated" INTEGER NOT NULL DEFAULT 0,
    "recordsUpdated" INTEGER NOT NULL DEFAULT 0,
    "errorMessage" TEXT,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "UpdateLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "YaraRule" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "rule" TEXT NOT NULL,
    "category" TEXT,
    "author" TEXT,
    "reference" TEXT,
    "tags" TEXT,
    "malwareId" TEXT,
    "techniqueId" TEXT,
    "severity" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "YaraRule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AppSetting" (
    "key" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AppSetting_pkey" PRIMARY KEY ("key")
);

-- CreateTable
CREATE TABLE "FeedItem" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "author" TEXT,
    "summary" TEXT,
    "content" TEXT,
    "imageUrl" TEXT,
    "publishedAt" TIMESTAMP(3),
    "fetchedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "tags" TEXT,

    CONSTRAINT "FeedItem_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ActorFeedItem" (
    "actorId" TEXT NOT NULL,
    "feedItemId" TEXT NOT NULL,

    CONSTRAINT "ActorFeedItem_pkey" PRIMARY KEY ("actorId","feedItemId")
);

-- CreateTable
CREATE TABLE "OffensiveCommand" (
    "id" TEXT NOT NULL,
    "command" TEXT NOT NULL,
    "description" TEXT,
    "author" TEXT,
    "source" TEXT NOT NULL,
    "tags" TEXT,
    "references" TEXT,
    "platform" TEXT,
    "techniqueId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OffensiveCommand_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_email_idx" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "Session_token_key" ON "Session"("token");

-- CreateIndex
CREATE INDEX "Session_token_idx" ON "Session"("token");

-- CreateIndex
CREATE INDEX "Session_userId_idx" ON "Session"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "Tactic_stixId_key" ON "Tactic"("stixId");

-- CreateIndex
CREATE UNIQUE INDEX "Tactic_externalId_key" ON "Tactic"("externalId");

-- CreateIndex
CREATE INDEX "Tactic_matrix_idx" ON "Tactic"("matrix");

-- CreateIndex
CREATE UNIQUE INDEX "Technique_stixId_key" ON "Technique"("stixId");

-- CreateIndex
CREATE UNIQUE INDEX "Technique_externalId_key" ON "Technique"("externalId");

-- CreateIndex
CREATE INDEX "Technique_externalId_idx" ON "Technique"("externalId");

-- CreateIndex
CREATE INDEX "Technique_parentId_idx" ON "Technique"("parentId");

-- CreateIndex
CREATE INDEX "Technique_matrix_idx" ON "Technique"("matrix");

-- CreateIndex
CREATE UNIQUE INDEX "ThreatActor_stixId_key" ON "ThreatActor"("stixId");

-- CreateIndex
CREATE UNIQUE INDEX "ThreatActor_externalId_key" ON "ThreatActor"("externalId");

-- CreateIndex
CREATE INDEX "ThreatActor_name_idx" ON "ThreatActor"("name");

-- CreateIndex
CREATE UNIQUE INDEX "Procedure_stixId_key" ON "Procedure"("stixId");

-- CreateIndex
CREATE INDEX "Procedure_actorId_idx" ON "Procedure"("actorId");

-- CreateIndex
CREATE INDEX "Procedure_techniqueId_idx" ON "Procedure"("techniqueId");

-- CreateIndex
CREATE INDEX "Procedure_malwareId_idx" ON "Procedure"("malwareId");

-- CreateIndex
CREATE INDEX "Procedure_toolId_idx" ON "Procedure"("toolId");

-- CreateIndex
CREATE UNIQUE INDEX "AtomicTest_guid_key" ON "AtomicTest"("guid");

-- CreateIndex
CREATE INDEX "AtomicTest_techniqueId_idx" ON "AtomicTest"("techniqueId");

-- CreateIndex
CREATE INDEX "AtomicTest_executor_idx" ON "AtomicTest"("executor");

-- CreateIndex
CREATE UNIQUE INDEX "Campaign_stixId_key" ON "Campaign"("stixId");

-- CreateIndex
CREATE UNIQUE INDEX "Campaign_externalId_key" ON "Campaign"("externalId");

-- CreateIndex
CREATE UNIQUE INDEX "Malware_stixId_key" ON "Malware"("stixId");

-- CreateIndex
CREATE UNIQUE INDEX "Malware_externalId_key" ON "Malware"("externalId");

-- CreateIndex
CREATE UNIQUE INDEX "Tool_stixId_key" ON "Tool"("stixId");

-- CreateIndex
CREATE UNIQUE INDEX "Tool_externalId_key" ON "Tool"("externalId");

-- CreateIndex
CREATE INDEX "ActorMalware_malwareId_idx" ON "ActorMalware"("malwareId");

-- CreateIndex
CREATE UNIQUE INDEX "Category_slug_key" ON "Category"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "Advisory_advisoryId_key" ON "Advisory"("advisoryId");

-- CreateIndex
CREATE INDEX "Advisory_type_idx" ON "Advisory"("type");

-- CreateIndex
CREATE INDEX "Advisory_cveId_idx" ON "Advisory"("cveId");

-- CreateIndex
CREATE INDEX "IOC_type_value_idx" ON "IOC"("type", "value");

-- CreateIndex
CREATE INDEX "IOC_advisoryId_idx" ON "IOC"("advisoryId");

-- CreateIndex
CREATE INDEX "DetectionRule_language_idx" ON "DetectionRule"("language");

-- CreateIndex
CREATE INDEX "DetectionRule_techniqueId_idx" ON "DetectionRule"("techniqueId");

-- CreateIndex
CREATE INDEX "DetectionRule_category_idx" ON "DetectionRule"("category");

-- CreateIndex
CREATE INDEX "SandboxAnalysis_indicator_idx" ON "SandboxAnalysis"("indicator");

-- CreateIndex
CREATE INDEX "SandboxAnalysis_iocId_idx" ON "SandboxAnalysis"("iocId");

-- CreateIndex
CREATE UNIQUE INDEX "SandboxAnalysis_indicator_source_key" ON "SandboxAnalysis"("indicator", "source");

-- CreateIndex
CREATE INDEX "UpdateLog_source_startedAt_idx" ON "UpdateLog"("source", "startedAt");

-- CreateIndex
CREATE UNIQUE INDEX "YaraRule_name_key" ON "YaraRule"("name");

-- CreateIndex
CREATE INDEX "YaraRule_category_idx" ON "YaraRule"("category");

-- CreateIndex
CREATE INDEX "YaraRule_malwareId_idx" ON "YaraRule"("malwareId");

-- CreateIndex
CREATE INDEX "YaraRule_techniqueId_idx" ON "YaraRule"("techniqueId");

-- CreateIndex
CREATE UNIQUE INDEX "FeedItem_url_key" ON "FeedItem"("url");

-- CreateIndex
CREATE INDEX "FeedItem_source_publishedAt_idx" ON "FeedItem"("source", "publishedAt");

-- CreateIndex
CREATE INDEX "FeedItem_publishedAt_idx" ON "FeedItem"("publishedAt");

-- CreateIndex
CREATE INDEX "ActorFeedItem_feedItemId_idx" ON "ActorFeedItem"("feedItemId");

-- CreateIndex
CREATE INDEX "OffensiveCommand_source_idx" ON "OffensiveCommand"("source");

-- CreateIndex
CREATE INDEX "OffensiveCommand_platform_idx" ON "OffensiveCommand"("platform");

-- CreateIndex
CREATE UNIQUE INDEX "OffensiveCommand_command_source_key" ON "OffensiveCommand"("command", "source");

-- AddForeignKey
ALTER TABLE "Session" ADD CONSTRAINT "Session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Technique" ADD CONSTRAINT "Technique_parentId_fkey" FOREIGN KEY ("parentId") REFERENCES "Technique"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TacticTechnique" ADD CONSTRAINT "TacticTechnique_tacticId_fkey" FOREIGN KEY ("tacticId") REFERENCES "Tactic"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TacticTechnique" ADD CONSTRAINT "TacticTechnique_techniqueId_fkey" FOREIGN KEY ("techniqueId") REFERENCES "Technique"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Procedure" ADD CONSTRAINT "Procedure_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "ThreatActor"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Procedure" ADD CONSTRAINT "Procedure_campaignId_fkey" FOREIGN KEY ("campaignId") REFERENCES "Campaign"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Procedure" ADD CONSTRAINT "Procedure_malwareId_fkey" FOREIGN KEY ("malwareId") REFERENCES "Malware"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Procedure" ADD CONSTRAINT "Procedure_toolId_fkey" FOREIGN KEY ("toolId") REFERENCES "Tool"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Procedure" ADD CONSTRAINT "Procedure_techniqueId_fkey" FOREIGN KEY ("techniqueId") REFERENCES "Technique"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AtomicTest" ADD CONSTRAINT "AtomicTest_techniqueId_fkey" FOREIGN KEY ("techniqueId") REFERENCES "Technique"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CampaignActor" ADD CONSTRAINT "CampaignActor_campaignId_fkey" FOREIGN KEY ("campaignId") REFERENCES "Campaign"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CampaignActor" ADD CONSTRAINT "CampaignActor_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "ThreatActor"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MalwareTechnique" ADD CONSTRAINT "MalwareTechnique_malwareId_fkey" FOREIGN KEY ("malwareId") REFERENCES "Malware"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MalwareTechnique" ADD CONSTRAINT "MalwareTechnique_techniqueId_fkey" FOREIGN KEY ("techniqueId") REFERENCES "Technique"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ToolTechnique" ADD CONSTRAINT "ToolTechnique_toolId_fkey" FOREIGN KEY ("toolId") REFERENCES "Tool"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ToolTechnique" ADD CONSTRAINT "ToolTechnique_techniqueId_fkey" FOREIGN KEY ("techniqueId") REFERENCES "Technique"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorMalware" ADD CONSTRAINT "ActorMalware_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "ThreatActor"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorMalware" ADD CONSTRAINT "ActorMalware_malwareId_fkey" FOREIGN KEY ("malwareId") REFERENCES "Malware"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CategoryTechnique" ADD CONSTRAINT "CategoryTechnique_categoryId_fkey" FOREIGN KEY ("categoryId") REFERENCES "Category"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CategoryTechnique" ADD CONSTRAINT "CategoryTechnique_techniqueId_fkey" FOREIGN KEY ("techniqueId") REFERENCES "Technique"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CategoryActor" ADD CONSTRAINT "CategoryActor_categoryId_fkey" FOREIGN KEY ("categoryId") REFERENCES "Category"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CategoryActor" ADD CONSTRAINT "CategoryActor_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "ThreatActor"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IOC" ADD CONSTRAINT "IOC_advisoryId_fkey" FOREIGN KEY ("advisoryId") REFERENCES "Advisory"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DetectionRule" ADD CONSTRAINT "DetectionRule_techniqueId_fkey" FOREIGN KEY ("techniqueId") REFERENCES "Technique"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SandboxAnalysis" ADD CONSTRAINT "SandboxAnalysis_iocId_fkey" FOREIGN KEY ("iocId") REFERENCES "IOC"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "YaraRule" ADD CONSTRAINT "YaraRule_malwareId_fkey" FOREIGN KEY ("malwareId") REFERENCES "Malware"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "YaraRule" ADD CONSTRAINT "YaraRule_techniqueId_fkey" FOREIGN KEY ("techniqueId") REFERENCES "Technique"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorFeedItem" ADD CONSTRAINT "ActorFeedItem_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "ThreatActor"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorFeedItem" ADD CONSTRAINT "ActorFeedItem_feedItemId_fkey" FOREIGN KEY ("feedItemId") REFERENCES "FeedItem"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OffensiveCommand" ADD CONSTRAINT "OffensiveCommand_techniqueId_fkey" FOREIGN KEY ("techniqueId") REFERENCES "Technique"("id") ON DELETE SET NULL ON UPDATE CASCADE;
