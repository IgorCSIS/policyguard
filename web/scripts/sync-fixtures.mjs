/**
 * Copy the rule pack and the sample log into the demo's public folder.
 *
 * The Python package owns both files. Committing a second copy under web/
 * would mean the demo could drift from what the CLI enforces, and the whole
 * argument this project makes is that the two agree. So the copies are
 * generated, git-ignored, and rebuilt before every dev run and every build.
 */

import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const WEB = dirname(dirname(fileURLToPath(import.meta.url)));
const REPO = dirname(WEB);
const TARGET = join(WEB, "public");

const FIXTURES = [
  [join(REPO, "policies", "baseline.json"), join(TARGET, "baseline.json")],
  [join(REPO, "samples", "office-auth.log"), join(TARGET, "office-auth.log")],
];

mkdirSync(TARGET, { recursive: true });
for (const [from, to] of FIXTURES) {
  copyFileSync(from, to);
  console.log(`synced ${from.replace(REPO + "/", "")} -> web/public/`);
}
