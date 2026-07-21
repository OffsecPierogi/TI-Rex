import { execSync } from "child_process";
import { existsSync } from "fs";
import { join } from "path";

const DATA_DIR = join(__dirname, "..", "..", "data", "sources");

export function ensureRepo(repoUrl: string, name: string): string {
  const targetDir = join(DATA_DIR, name);
  if (existsSync(join(targetDir, ".git"))) {
    console.log(`[git] Pulling latest for ${name}...`);
    execSync("git pull --ff-only", { cwd: targetDir, stdio: "pipe" });
  } else {
    console.log(`[git] Cloning ${name} (shallow)...`);
    execSync(`git clone --depth=1 "${repoUrl}" "${targetDir}"`, { stdio: "pipe" });
  }
  return targetDir;
}
