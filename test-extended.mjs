/** Trooth Pre-Flight — extended tests (v1.1): adapters, new checks, Fix-It patches, drift. Run: node test-extended.mjs */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { runPreflight, detectDrift } from "./engine.mjs";

const __dir = dirname(fileURLToPath(import.meta.url));
const load = (p) => JSON.parse(readFileSync(join(__dir, p), "utf8"));
let pass = 0, fail = 0;
const ck = (n, c, x = "") => { (c ? pass++ : fail++); console.log((c ? "PASS" : "FAIL") + "  " + n + (c ? "" : "  >> " + x)); };
const ids = (d) => d.findings.map((f) => f.checkId);

// --- 1. Terraform base still works + now carries Fix-It patches ---
const tf = runPreflight(load("__fixtures__/sample-plan.json"));
ck("TF format detected", tf.format === "terraform", tf.format);
ck("TF every finding has a patch", tf.findings.every((f) => f.patch && f.patch.length > 5), JSON.stringify(tf.findings.find(f=>!f.patch)?.checkId));
const rdsEnc = tf.findings.find((f) => f.checkId === "RDS_ENCRYPTION_AT_REST");
ck("TF RDS patch contains storage_encrypted = true", /storage_encrypted = true/.test(rdsEnc.patch), rdsEnc.patch);
ck("TF framework rollup now includes HIPAA", tf.frameworkCoverage.hipaa.failing.length > 0, JSON.stringify(tf.frameworkCoverage.hipaa));

// --- 2. Pulumi adapter ---
const pl = runPreflight(load("__fixtures__/pulumi-preview.json"));
ck("Pulumi format detected", pl.format === "pulumi", pl.format);
ck("Pulumi catches RDS encryption", ids(pl).includes("RDS_ENCRYPTION_AT_REST"));
ck("Pulumi catches RDS public", ids(pl).includes("RDS_NOT_PUBLIC"));
ck("Pulumi catches public S3", ids(pl).includes("S3_PUBLIC_ACCESS"));

// --- 3. CloudFormation adapter ---
const cf = runPreflight(load("__fixtures__/cfn-template.json"));
ck("CFN format detected", cf.format === "cloudformation", cf.format);
ck("CFN catches RDS encryption", ids(cf).includes("RDS_ENCRYPTION_AT_REST"));
ck("CFN catches RDS public", ids(cf).includes("RDS_NOT_PUBLIC"));
ck("CFN catches EBS encryption", ids(cf).includes("EBS_ENCRYPTION_AT_REST"));
ck("CFN catches open security group (ingress remap)", ids(cf).includes("SG_NO_OPEN_ADMIN"));

// --- 4. Multi-cloud: GCP / Azure / Kubernetes ---
const mc = runPreflight(load("__fixtures__/multicloud-plan.json"));
ck("GCP public storage caught", ids(mc).includes("GCP_STORAGE_NOT_PUBLIC"));
ck("GCP public Cloud SQL caught", ids(mc).includes("GCP_SQL_NOT_PUBLIC"));
ck("GCP open firewall caught", ids(mc).includes("GCP_FIREWALL_NO_OPEN_ADMIN"));
ck("Azure insecure storage caught", ids(mc).includes("AZURE_STORAGE_SECURE"));
ck("Azure open NSG caught", ids(mc).includes("AZURE_NSG_NO_OPEN_ADMIN"));
ck("K8s privileged container caught", ids(mc).includes("K8S_NO_PRIVILEGED"));
ck("K8s host network caught", ids(mc).includes("K8S_NO_HOST_NETWORK"));
ck("Multi-cloud rollup includes NIST AI RMF", mc.frameworkCoverage.nist_ai_rmf.checked.length > 0);

// --- 5. Drift detection ---
const intent = { planned_values: { root_module: { resources: [
  { address: "aws_db_instance.main", type: "aws_db_instance", name: "main", values: { storage_encrypted: true, publicly_accessible: false } },
  { address: "aws_s3_bucket.data", type: "aws_s3_bucket", name: "data", values: { acl: "private" } },
] } } };
const live = [
  { address: "aws_db_instance.main", type: "aws_db_instance", name: "main", values: { storage_encrypted: false, publicly_accessible: false } }, // drift!
  // aws_s3_bucket.data is MISSING in prod
];
const drift = detectDrift(intent, live);
ck("drift detected (not in sync)", drift.inSync === false, JSON.stringify(drift));
ck("drift catches storage_encrypted change", drift.drift.some((d) => d.attribute === "storage_encrypted" && d.intended === true && d.actual === false));
ck("drift catches resource missing in prod", drift.drift.some((d) => d.kind === "missing_in_prod" && d.address === "aws_s3_bucket.data"));

const synced = detectDrift(intent, [
  { address: "aws_db_instance.main", type: "aws_db_instance", name: "main", values: { storage_encrypted: true, publicly_accessible: false } },
  { address: "aws_s3_bucket.data", type: "aws_s3_bucket", name: "data", values: { acl: "private" } },
]);
ck("no drift when prod matches intent", synced.inSync === true, JSON.stringify(synced.drift));

console.log("\n--- summary ---");
console.log("Pulumi findings:", pl.summary.fail, "| CFN findings:", cf.summary.fail, "| multicloud findings:", mc.summary.fail);
console.log("\n" + pass + " passed, " + fail + " failed");
process.exit(fail ? 1 : 0);
