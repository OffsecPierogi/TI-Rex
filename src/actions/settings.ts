"use server";

import { prisma } from "@/lib/db";
import { requireRole } from "@/lib/auth";
import { revalidatePath } from "next/cache";

export interface AutoRefreshConfig {
  hours: number;
  lastUpdate: string | null;
}

export async function getAutoRefreshConfig(): Promise<AutoRefreshConfig> {
  const setting = await prisma.appSetting.findUnique({
    where: { key: "autoRefreshHours" },
  });

  const lastSuccessful = await prisma.updateLog.findFirst({
    where: {
      status: "success",
      completedAt: { not: null },
    },
    orderBy: { completedAt: "desc" },
    select: { completedAt: true },
  });

  return {
    hours: setting ? (parseInt(setting.value, 10) || 0) : 0,
    lastUpdate: lastSuccessful?.completedAt?.toISOString() ?? null,
  };
}

export async function setAutoRefreshConfig(hours: number): Promise<void> {
  await requireRole("ADMIN");
  await prisma.appSetting.upsert({
    where: { key: "autoRefreshHours" },
    update: { value: String(hours) },
    create: { key: "autoRefreshHours", value: String(hours) },
  });

  revalidatePath("/settings");
}

export interface IocRetentionConfig {
  days: number;
  lastPruned: string | null;
  lastPrunedCount: number;
}

export async function getIocRetentionConfig(): Promise<IocRetentionConfig> {
  const setting = await prisma.appSetting.findUnique({
    where: { key: "iocRetentionDays" },
  });

  const lastPruned = await prisma.appSetting.findUnique({
    where: { key: "iocLastPruned" },
  });

  const lastCount = await prisma.appSetting.findUnique({
    where: { key: "iocLastPrunedCount" },
  });

  return {
    days: setting ? (parseInt(setting.value, 10) || 0) : 90,
    lastPruned: lastPruned?.value ?? null,
    lastPrunedCount: lastCount ? (parseInt(lastCount.value, 10) || 0) : 0,
  };
}

export async function setIocRetentionDays(days: number): Promise<void> {
  await requireRole("ADMIN");
  await prisma.appSetting.upsert({
    where: { key: "iocRetentionDays" },
    update: { value: String(days) },
    create: { key: "iocRetentionDays", value: String(days) },
  });

  revalidatePath("/settings");
}

export async function pruneStaleIocs(): Promise<{ deleted: number }> {
  await requireRole("ADMIN");
  const setting = await prisma.appSetting.findUnique({
    where: { key: "iocRetentionDays" },
  });
  const days = setting ? (parseInt(setting.value, 10) || 0) : 90;
  if (days === 0) return { deleted: 0 };

  const cutoff = new Date(Date.now() - days * 86_400_000);

  const staleIocs = await prisma.iOC.findMany({
    where: {
      createdAt: { lt: cutoff },
      advisoryId: null,
    },
    select: { id: true },
  });

  if (staleIocs.length === 0) return { deleted: 0 };

  const ids = staleIocs.map((i) => i.id);

  await prisma.sandboxAnalysis.deleteMany({
    where: { iocId: { in: ids } },
  });

  const result = await prisma.iOC.deleteMany({
    where: { id: { in: ids } },
  });

  const now = new Date().toISOString();
  await prisma.appSetting.upsert({
    where: { key: "iocLastPruned" },
    update: { value: now },
    create: { key: "iocLastPruned", value: now },
  });
  await prisma.appSetting.upsert({
    where: { key: "iocLastPrunedCount" },
    update: { value: String(result.count) },
    create: { key: "iocLastPrunedCount", value: String(result.count) },
  });

  revalidatePath("/settings");
  return { deleted: result.count };
}
