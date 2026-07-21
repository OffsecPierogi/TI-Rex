import { NextResponse } from "next/server";
import { execSync } from "child_process";
import { join } from "path";
import { getSession } from "@/lib/auth";

const COOLDOWN_SECONDS = 60;

let isRunning = false;
let lastCompletedAt = 0;

export async function POST() {
  const user = await getSession();
  if (!user) {
    return NextResponse.json({ status: "error", message: "Authentication required" }, { status: 401 });
  }
  if (user.role !== "ADMIN") {
    return NextResponse.json({ status: "error", message: "Admin role required" }, { status: 403 });
  }

  if (isRunning) {
    return NextResponse.json(
      { status: "error", message: "An update is already in progress. Please wait for it to complete." },
      { status: 429, headers: { "Retry-After": "60" } },
    );
  }

  const now = Date.now();
  const elapsed = (now - lastCompletedAt) / 1000;
  if (lastCompletedAt > 0 && elapsed < COOLDOWN_SECONDS) {
    const remaining = Math.ceil(COOLDOWN_SECONDS - elapsed);
    return NextResponse.json(
      { status: "error", message: `Update cooldown active. Try again in ${remaining} seconds.` },
      { status: 429, headers: { "Retry-After": String(remaining) } },
    );
  }

  isRunning = true;
  try {
    const scriptPath = join(process.cwd(), "scripts", "update-all.ts");
    execSync(`npx tsx "${scriptPath}"`, {
      cwd: process.cwd(),
      timeout: 600_000,
      stdio: "pipe",
    });
    lastCompletedAt = Date.now();
    return NextResponse.json({ status: "success" });
  } catch (err) {
    lastCompletedAt = Date.now();
    return NextResponse.json(
      { status: "error", message: String(err) },
      { status: 500 },
    );
  } finally {
    isRunning = false;
  }
}
