/**
 * Prove the TypeScript port and the Python package agree.
 *
 * The Python package is the source of truth for rule semantics. This file is
 * the reason that claim is worth anything: it runs the CLI and the browser
 * engine over the same rule pack and the same log, then compares every field
 * of every verdict. The first difference fails the run with both values
 * printed, so a drifting port is a build failure and not a surprise during a
 * demo.
 *
 * Run it with `npm run parity` from web/. It imports the TypeScript directly
 * using Node's type stripping rather than compiling it first, so there is no
 * build output to keep in step with the sources. It needs python3 on PATH; if
 * there is none it says so and exits non-zero rather than quietly passing.
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { PolicyEngine } from "../src/lib/engine.ts";
import { parseRulePack } from "../src/lib/rules.ts";

const WEB = dirname(dirname(fileURLToPath(import.meta.url)));
const REPO = dirname(WEB);
const POLICY = join(REPO, "policies", "baseline.json");
const SAMPLE = join(REPO, "samples", "office-auth.log");

/** Print a failure and stop. */
function fail(message) {
  console.error(`Parity check failed: ${message}`);
  process.exit(1);
}

/** Run the Python CLI and return its JSON report. */
function loadPythonReport() {
  let raw;
  try {
    raw = execFileSync("python3", ["-m", "policyguard", SAMPLE, "-p", POLICY, "--json"], {
      cwd: REPO,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
    });
  } catch (error) {
    fail(`could not run the Python CLI (${error.message})`);
  }
  try {
    return JSON.parse(raw);
  } catch (error) {
    fail(`the Python CLI did not print valid JSON (${error.message})`);
  }
}

const pack = parseRulePack(JSON.parse(readFileSync(POLICY, "utf8")));
const ours = new PolicyEngine(pack).classifyText(readFileSync(SAMPLE, "utf8"));
const theirs = loadPythonReport();

if (ours.verdicts.length !== theirs.verdicts.length) {
  fail(
    `TypeScript classified ${ours.verdicts.length} lines, Python classified ${theirs.verdicts.length}`,
  );
}

const FIELDS = [
  "line",
  "raw",
  "decision",
  "ruleId",
  "ruleLabel",
  "severity",
  "pathText",
  "reason",
  "source",
];

for (let i = 0; i < ours.verdicts.length; i += 1) {
  const mine = ours.verdicts[i];
  const yours = theirs.verdicts[i];
  for (const field of FIELDS) {
    if (mine[field] !== yours[field]) {
      fail(
        `line ${yours.line}, field ${field}\n` +
          `  TypeScript: ${JSON.stringify(mine[field])}\n` +
          `  Python:     ${JSON.stringify(yours[field])}`,
      );
    }
  }
  if (JSON.stringify(mine.path) !== JSON.stringify(yours.path)) {
    fail(
      `line ${yours.line}, state path\n` +
        `  TypeScript: ${JSON.stringify(mine.path)}\n` +
        `  Python:     ${JSON.stringify(yours.path)}`,
    );
  }
}

for (const decision of ["allow", "alert", "ignore"]) {
  if (ours.counts[decision] !== theirs.counts[decision]) {
    fail(`${decision} count: TypeScript ${ours.counts[decision]}, Python ${theirs.counts[decision]}`);
  }
}

const summary = ["allow", "alert", "ignore"]
  .map((decision) => `${theirs.counts[decision]} ${decision}`)
  .join(", ");
console.log(
  `Parity OK: ${ours.verdicts.length} verdicts identical in TypeScript and Python (${summary}).`,
);
