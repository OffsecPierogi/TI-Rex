import { categorizeTechniques, categorizeActors } from "../src/lib/categorize";

async function main() {
  console.log("Applying category rules...");
  const techLinks = await categorizeTechniques();
  console.log(`  Created ${techLinks} technique-category links`);
  const actorLinks = await categorizeActors();
  console.log(`  Created ${actorLinks} actor-category links`);
  console.log("Done.");
}

main().catch(console.error).finally(() => process.exit(0));
