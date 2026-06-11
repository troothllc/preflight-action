#!/usr/bin/env node
/**
 * Trooth Pre-Flight CLI
 * Copyright (c) 2026 Trooth, LLC.
 *
 * Usage:
 *   terraform plan -out tf.plan && terraform show -json tf.plan > plan.json
 *   npx trooth-preflight plan.json            # human report (advisory, exit 0)
 *   npx trooth-preflight plan.json --json      # emit the Compliance Delta as JSON
 *   npx trooth-preflight plan.json --strict     # exit 1 if verdict is "fail" (CI gate)
 *   npx trooth-preflight plan.json --md > out.md  # markdown (PR comment)
 *
 * Advisory by default (fail-open, exit 0). Trooth never applies changes.
 */
import { readFileSync } from "node:fs";
import { runPreflight } from "./engine.mjs";
import { toText, toMarkdown } from "./format.mjs";

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith("--"));
const flag = (f) => args.includes(f);

if (!file) {
  console.error("Usage: trooth-preflight <terraform-plan.json> [--json|--md|--strict]");
  process.exit(2);
}

let plan;
try {
  plan = JSON.parse(readFileSync(file, "utf8"));
} catch (e) {
  console.error(`Could not read/parse ${file}: ${e.message}`);
  process.exit(2);
}

const delta = runPreflight(plan);

if (flag("--json")) process.stdout.write(JSON.stringify(delta, null, 2) + "\n");
else if (flag("--md")) process.stdout.write(toMarkdown(delta) + "\n");
else process.stdout.write(toText(delta) + "\n");

// Advisory by default; --strict turns a failing verdict into a non-zero exit (CI gate).
process.exit(flag("--strict") && delta.verdict === "fail" ? 1 : 0);
