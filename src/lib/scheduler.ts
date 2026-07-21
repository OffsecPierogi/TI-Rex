import { spawn } from "child_process";
import { join } from "path";

const DEFAULT_REFRESH_HOURS = 6;
const CHECK_INTERVAL_MS = 5 * 60 * 1000;

let running = false;

async function getRefreshConfig() {
  const { prisma } = await import("./db");

  const setting = await prisma.appSetting.findUnique({
    where: { key: "autoRefreshHours" },
  });

  const hours = setting ? parseInt(setting.value, 10) || 0 : DEFAULT_REFRESH_HOURS;

  const lastRun = await prisma.updateLog.findFirst({
    where: { source: "full-update", status: "success", completedAt: { not: null } },
    orderBy: { completedAt: "desc" },
    select: { completedAt: true },
  });

  return { hours, lastCompleted: lastRun?.completedAt ?? null };
}

async function logUpdate(status: "running" | "success" | "error", errorMessage?: string) {
  const { prisma } = await import("./db");
  if (status === "running") {
    return prisma.updateLog.create({
      data: { source: "full-update", status: "running" },
    });
  }

  const latest = await prisma.updateLog.findFirst({
    where: { source: "full-update", status: "running" },
    orderBy: { startedAt: "desc" },
  });
  if (latest) {
    await prisma.updateLog.update({
      where: { id: latest.id },
      data: { status, completedAt: new Date(), errorMessage },
    });
  }
}

function runUpdate(): Promise<void> {
  return new Promise((resolve, reject) => {
    const scriptPath = join(process.cwd(), "scripts", "update-all.ts");
    const child = spawn("npx", ["tsx", scriptPath], {
      cwd: process.cwd(),
      stdio: "inherit",
      env: { ...process.env },
    });

    child.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`update-all exited with code ${code}`));
    });

    child.on("error", reject);
  });
}

async function tick() {
  if (running) return;

  try {
    const { hours, lastCompleted } = await getRefreshConfig();
    if (hours <= 0) return;

    const intervalMs = hours * 3600 * 1000;
    const elapsed = lastCompleted ? Date.now() - lastCompleted.getTime() : Infinity;

    if (elapsed < intervalMs) return;

    running = true;
    console.log(`[scheduler] Starting full update (last: ${lastCompleted?.toISOString() ?? "never"}, interval: ${hours}h)`);

    await logUpdate("running");
    await runUpdate();
    await logUpdate("success");

    console.log("[scheduler] Full update complete");
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[scheduler] Update failed:", msg);
    await logUpdate("error", msg).catch(() => {});
  } finally {
    running = false;
  }
}

export function startScheduler() {
  console.log("[scheduler] Initialized — checking every 5 minutes");
  setTimeout(() => tick(), 30_000);
  setInterval(() => tick(), CHECK_INTERVAL_MS);
}
