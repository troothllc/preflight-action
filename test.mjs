/** Trooth Pre-Flight — engine tests. Run: node test.mjs */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { runPreflight, collectResources } from "./engine.mjs";

const __dir = dirname(fileURLToPath(import.meta.url));
const plan = JSON.parse(readFileSync(join(__dir, "__fixtures__/sample-plan.json"), "utf8"));
const delta = runPreflight(plan);

let pass = 0, fail = 0;
const ck = (n, c, x = "") => { (c ? pass++ : fail++); console.log((c ? "PASS" : "FAIL") + "  " + n + (c ? "" : "  >> " + x)); };
const ids = delta.findings.map((f) => f.checkId);
const has = (id) => ids.includes(id);
const flaggedResources = (id) => delta.findings.filter((f) => f.checkId === id).map((f) => f.resource);

ck("collected 9 managed resources", collectResources(plan).length === 9, String(collectResources(plan).length));
ck("verdict is fail (criticals present)", delta.verdict === "fail", delta.verdict);

ck("catches public S3 bucket", has("S3_PUBLIC_ACCESS") && flaggedResources("S3_PUBLIC_ACCESS").includes("aws_s3_bucket.public_logs"));
ck("catches unencrypted S3 bucket", has("S3_ENCRYPTION_AT_REST") && flaggedResources("S3_ENCRYPTION_AT_REST").includes("aws_s3_bucket.public_logs"));
ck("does NOT flag encrypted secure_data bucket", !flaggedResources("S3_ENCRYPTION_AT_REST").includes("aws_s3_bucket.secure_data"));
ck("catches unencrypted RDS", has("RDS_ENCRYPTION_AT_REST") && flaggedResources("RDS_ENCRYPTION_AT_REST").includes("aws_db_instance.main"));
ck("catches public RDS", has("RDS_NOT_PUBLIC") && flaggedResources("RDS_NOT_PUBLIC").includes("aws_db_instance.main"));
ck("does NOT flag the good replica db", !flaggedResources("RDS_ENCRYPTION_AT_REST").includes("aws_db_instance.replica") && !flaggedResources("RDS_NOT_PUBLIC").includes("aws_db_instance.replica"));
ck("catches unencrypted EBS", has("EBS_ENCRYPTION_AT_REST"));
ck("catches open SSH security group", has("SG_NO_OPEN_ADMIN") && flaggedResources("SG_NO_OPEN_ADMIN").includes("aws_security_group.web"));
ck("catches wildcard IAM admin", has("IAM_NO_WILDCARD_ADMIN"));
ck("catches HTTP load balancer listener", has("LB_HTTPS_IN_TRANSIT"));
ck("catches unencrypted CloudWatch log group", has("CLOUDWATCH_LOG_ENCRYPTION"));

ck("every finding carries a Fix-It", delta.findings.every((f) => f.fix && f.fix.length > 10));
ck("every finding maps to SOC 2", delta.findings.every((f) => f.frameworks.soc2 && f.frameworks.soc2.length > 0));
ck("framework rollup lists failing SOC 2 controls", delta.frameworkCoverage.soc2.failing.length > 0);
ck("framework rollup lists failing EU AI Act articles", delta.frameworkCoverage.eu_ai_act.failing.includes("Art.15"));
ck("score is a number 0-100", typeof delta.score === "number" && delta.score >= 0 && delta.score <= 100, String(delta.score));
ck("critical findings counted", delta.summary.bySeverity.critical >= 2, JSON.stringify(delta.summary.bySeverity));

console.log("\n--- DELTA SUMMARY ---");
console.log("verdict:", delta.verdict, "| score:", delta.score, "| findings:", delta.summary.fail, "| pass:", delta.summary.pass, "| n/a:", delta.summary.notApplicable);
console.log("by severity:", JSON.stringify(delta.summary.bySeverity));
console.log("SOC2 failing:", delta.frameworkCoverage.soc2.failing.join(", "));
console.log("\n" + pass + " passed, " + fail + " failed");
process.exit(fail ? 1 : 0);
