import { prisma } from "../src/lib/db";
import { join } from "path";
import { existsSync, readdirSync, readFileSync } from "fs";
import * as yaml from "js-yaml";

const ATOMIC_DIR = join(__dirname, "..", "data", "sources", "atomic-red-team", "atomics");

interface AtomicTest {
  name: string;
  description: string;
  supported_platforms?: string[];
  executor?: {
    name: string;
    command?: string;
    cleanup_command?: string;
    elevation_required?: boolean;
  };
  input_arguments?: Record<string, { description: string; type: string; default: string }>;
}

interface AtomicYaml {
  attack_technique: string;
  display_name: string;
  atomic_tests: AtomicTest[];
}

async function main() {
  if (!existsSync(ATOMIC_DIR)) {
    console.log(`[skip] Atomic Red Team not found at ${ATOMIC_DIR}`);
    console.log("Run: git clone --depth=1 https://github.com/redcanaryco/atomic-red-team data/sources/atomic-red-team");
    return;
  }

  const logEntry = await prisma.updateLog.create({
    data: { source: "atomic-red-team", status: "running" },
  });

  try {
    const dirs = readdirSync(ATOMIC_DIR).filter((d) => d.startsWith("T"));
    let totalTests = 0;
    let skipped = 0;

    for (const dir of dirs) {
      const yamlPath = join(ATOMIC_DIR, dir, `${dir}.yaml`);
      if (!existsSync(yamlPath)) continue;

      const raw = readFileSync(yamlPath, "utf-8");
      let doc: AtomicYaml;
      try {
        doc = yaml.load(raw) as AtomicYaml;
      } catch {
        continue;
      }

      if (!doc?.atomic_tests) continue;

      const techniqueExtId = doc.attack_technique;
      const technique = await prisma.technique.findFirst({
        where: { externalId: techniqueExtId },
      });

      if (!technique) {
        skipped++;
        continue;
      }

      for (let i = 0; i < doc.atomic_tests.length; i++) {
        const test = doc.atomic_tests[i];
        if (!test.executor?.command) continue;

        const guid = `${techniqueExtId}-${i}`;
        let command = test.executor.command;

        if (test.input_arguments) {
          for (const [key, arg] of Object.entries(test.input_arguments)) {
            command = command.replaceAll(`#{${key}}`, arg.default);
          }
        }

        await prisma.atomicTest.upsert({
          where: { guid },
          update: {
            name: test.name,
            description: test.description ?? "",
            platforms: JSON.stringify(test.supported_platforms ?? []),
            executor: test.executor.name,
            command,
            cleanupCommand: test.executor.cleanup_command ?? null,
            inputArguments: test.input_arguments ? JSON.stringify(test.input_arguments) : null,
            elevationRequired: test.executor.elevation_required ?? false,
          },
          create: {
            guid,
            techniqueId: technique.id,
            name: test.name,
            description: test.description ?? "",
            platforms: JSON.stringify(test.supported_platforms ?? []),
            executor: test.executor.name,
            command,
            cleanupCommand: test.executor.cleanup_command ?? null,
            inputArguments: test.input_arguments ? JSON.stringify(test.input_arguments) : null,
            elevationRequired: test.executor.elevation_required ?? false,
          },
        });
        totalTests++;
      }
    }

    console.log(`\n=== Atomic Red Team Ingestion Complete ===`);
    console.log(`Tests ingested: ${totalTests}, Techniques skipped (not in DB): ${skipped}`);

    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: {
        status: "success",
        recordsProcessed: totalTests,
        completedAt: new Date(),
      },
    });
  } catch (err) {
    console.error("Atomic ingestion failed:", err);
    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: { status: "error", errorMessage: String(err), completedAt: new Date() },
    });
    throw err;
  }
}

main().catch(console.error).finally(() => process.exit(0));
