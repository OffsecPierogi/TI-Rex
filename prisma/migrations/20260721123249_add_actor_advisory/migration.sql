-- CreateTable
CREATE TABLE "ActorAdvisory" (
    "actorId" TEXT NOT NULL,
    "advisoryId" TEXT NOT NULL,

    CONSTRAINT "ActorAdvisory_pkey" PRIMARY KEY ("actorId","advisoryId")
);

-- CreateIndex
CREATE INDEX "ActorAdvisory_advisoryId_idx" ON "ActorAdvisory"("advisoryId");

-- AddForeignKey
ALTER TABLE "ActorAdvisory" ADD CONSTRAINT "ActorAdvisory_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "ThreatActor"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ActorAdvisory" ADD CONSTRAINT "ActorAdvisory_advisoryId_fkey" FOREIGN KEY ("advisoryId") REFERENCES "Advisory"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
