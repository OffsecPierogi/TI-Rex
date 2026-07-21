-- AlterTable
ALTER TABLE "Advisory" ADD COLUMN     "cvssScore" DOUBLE PRECISION,
ADD COLUMN     "cvssVector" TEXT,
ADD COLUMN     "epssPercentile" DOUBLE PRECISION,
ADD COLUMN     "epssScore" DOUBLE PRECISION,
ADD COLUMN     "lastModifiedDate" TIMESTAMP(3),
ADD COLUMN     "publishedDate" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "Watchlist" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "webhookUrl" TEXT,
    "userId" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Watchlist_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WatchlistItem" (
    "id" TEXT NOT NULL,
    "watchlistId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "description" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WatchlistItem_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WatchlistAlert" (
    "id" TEXT NOT NULL,
    "watchlistId" TEXT NOT NULL,
    "itemId" TEXT NOT NULL,
    "matchSource" TEXT NOT NULL,
    "matchDetail" TEXT,
    "iocId" TEXT,
    "read" BOOLEAN NOT NULL DEFAULT false,
    "notifiedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WatchlistAlert_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Watchlist_userId_idx" ON "Watchlist"("userId");

-- CreateIndex
CREATE INDEX "WatchlistItem_type_value_idx" ON "WatchlistItem"("type", "value");

-- CreateIndex
CREATE UNIQUE INDEX "WatchlistItem_watchlistId_type_value_key" ON "WatchlistItem"("watchlistId", "type", "value");

-- CreateIndex
CREATE INDEX "WatchlistAlert_watchlistId_read_idx" ON "WatchlistAlert"("watchlistId", "read");

-- CreateIndex
CREATE INDEX "WatchlistAlert_createdAt_idx" ON "WatchlistAlert"("createdAt");

-- CreateIndex
CREATE INDEX "Advisory_epssScore_idx" ON "Advisory"("epssScore");

-- AddForeignKey
ALTER TABLE "Watchlist" ADD CONSTRAINT "Watchlist_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WatchlistItem" ADD CONSTRAINT "WatchlistItem_watchlistId_fkey" FOREIGN KEY ("watchlistId") REFERENCES "Watchlist"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WatchlistAlert" ADD CONSTRAINT "WatchlistAlert_watchlistId_fkey" FOREIGN KEY ("watchlistId") REFERENCES "Watchlist"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "WatchlistAlert" ADD CONSTRAINT "WatchlistAlert_itemId_fkey" FOREIGN KEY ("itemId") REFERENCES "WatchlistItem"("id") ON DELETE CASCADE ON UPDATE CASCADE;
