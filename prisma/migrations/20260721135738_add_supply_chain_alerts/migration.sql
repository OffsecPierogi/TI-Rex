-- CreateTable
CREATE TABLE "SupplyChainAlert" (
    "id" TEXT NOT NULL,
    "ecosystem" TEXT NOT NULL,
    "packageName" TEXT NOT NULL,
    "versions" TEXT,
    "severity" TEXT,
    "summary" TEXT NOT NULL,
    "details" TEXT,
    "aliases" TEXT,
    "url" TEXT,
    "publishedAt" TIMESTAMP(3),
    "withdrawnAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SupplyChainAlert_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "SupplyChainAlert_ecosystem_idx" ON "SupplyChainAlert"("ecosystem");

-- CreateIndex
CREATE INDEX "SupplyChainAlert_severity_idx" ON "SupplyChainAlert"("severity");

-- CreateIndex
CREATE INDEX "SupplyChainAlert_publishedAt_idx" ON "SupplyChainAlert"("publishedAt");

-- CreateIndex
CREATE UNIQUE INDEX "SupplyChainAlert_ecosystem_packageName_summary_key" ON "SupplyChainAlert"("ecosystem", "packageName", "summary");
