/**
 * Trooth Pre-Flight — Compliance-as-Code engine (v1.1)
 * Copyright (c) 2026 Trooth, LLC. All rights reserved.
 *
 * Analyzes the RESOLVED INTENT of infrastructure — Terraform plan JSON,
 * Pulumi `preview --json`, or CloudFormation/CDK templates — against the control
 * catalog (SOC 2 / ISO 27001 / EU AI Act / NIST AI RMF / HIPAA) and emits a
 * signed-ready "Compliance Delta" with a Fix-It code patch per finding. Also
 * detects DRIFT between declared intent and a read-only production snapshot.
 *
 * ADVISORY ONLY. Trooth never applies changes; Git history is the rollback.
 * No environment access is required to scan intent.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dir = dirname(fileURLToPath(import.meta.url));
export function loadControls() {
  return JSON.parse(readFileSync(join(__dir, "controls.json"), "utf8"));
}

// ---------------------------------------------------------------------------
// Key normalization: camelCase (Pulumi) / PascalCase (CloudFormation) -> snake
// ---------------------------------------------------------------------------
const toSnake = (s) => s.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2").toLowerCase();
function deepSnake(v) {
  if (Array.isArray(v)) return v.map(deepSnake);
  if (v && typeof v === "object") {
    const o = {};
    for (const [k, val] of Object.entries(v)) o[toSnake(k)] = deepSnake(val);
    return o;
  }
  return v;
}

// ---------------------------------------------------------------------------
// Adapters — normalize each IaC format to [{ address, type, name, values }]
// ---------------------------------------------------------------------------
function fromTerraform(plan) {
  const out = [];
  const walk = (m) => {
    if (!m) return;
    for (const r of m.resources || []) { if (r.mode === "data") continue; out.push({ address: r.address, type: r.type, name: r.name, values: r.values || {} }); }
    for (const c of m.child_modules || []) walk(c);
  };
  if (plan?.planned_values?.root_module) walk(plan.planned_values.root_module);
  if (out.length === 0 && Array.isArray(plan?.resource_changes)) {
    for (const rc of plan.resource_changes) { const a = rc.change?.after; if (a && rc.mode !== "data") out.push({ address: rc.address, type: rc.type, name: rc.name, values: a }); }
  }
  return out;
}

// Pulumi resource URN type -> Terraform-style type
const PULUMI_TYPE = {
  "aws:s3/bucket:bucket": "aws_s3_bucket", "aws:s3/bucketv2:bucketv2": "aws_s3_bucket",
  "aws:rds/instance:instance": "aws_db_instance",
  "aws:ec2/securitygroup:securitygroup": "aws_security_group",
  "aws:ebs/volume:volume": "aws_ebs_volume",
  "aws:iam/policy:policy": "aws_iam_policy",
  "aws:lb/listener:listener": "aws_lb_listener", "aws:alb/listener:listener": "aws_lb_listener",
  "aws:cloudwatch/loggroup:loggroup": "aws_cloudwatch_log_group",
  "gcp:storage/bucket:bucket": "google_storage_bucket",
  "gcp:storage/bucketiammember:bucketiammember": "google_storage_bucket_iam_member",
  "gcp:sql/databaseinstance:databaseinstance": "google_sql_database_instance",
  "gcp:compute/firewall:firewall": "google_compute_firewall",
  "azure:storage/account:account": "azurerm_storage_account",
  "azure:network/networksecurityrule:networksecurityrule": "azurerm_network_security_rule",
  "kubernetes:apps/v1:deployment": "kubernetes_deployment",
  "kubernetes:core/v1:pod": "kubernetes_pod",
};
function fromPulumi(preview) {
  const steps = preview.steps || preview.diagnostics || [];
  const out = [];
  for (const s of steps) {
    const st = s.newState || s.new_state || s.state;
    if (!st || !st.type) continue;
    if (["delete", "read"].includes(s.op)) continue;
    const tfType = PULUMI_TYPE[String(st.type).toLowerCase()] || ("pulumi:" + st.type);
    const inputs = st.inputs || st.outputs || {};
    out.push({ address: st.urn || `${tfType}.${st.id || "res"}`, type: tfType, name: (st.urn || "").split("::").pop() || st.id, values: deepSnake(inputs) });
  }
  return out;
}

// CloudFormation resource type -> Terraform-style type
const CFN_TYPE = {
  "aws::s3::bucket": "aws_s3_bucket",
  "aws::rds::dbinstance": "aws_db_instance",
  "aws::ec2::securitygroup": "aws_security_group",
  "aws::ec2::volume": "aws_ebs_volume",
  "aws::iam::policy": "aws_iam_policy", "aws::iam::managedpolicy": "aws_iam_policy",
  "aws::elasticloadbalancingv2::listener": "aws_lb_listener",
  "aws::logs::loggroup": "aws_cloudwatch_log_group",
};
function fromCloudFormation(tpl) {
  const out = [];
  const resources = tpl.Resources || tpl.resources || {};
  for (const [logicalId, res] of Object.entries(resources)) {
    const tfType = CFN_TYPE[String(res.Type || "").toLowerCase()];
    if (!tfType) continue;
    let values = deepSnake(res.Properties || {});
    // Targeted remaps for structured fields
    if (tfType === "aws_security_group" && Array.isArray(values.security_group_ingress)) {
      values.ingress = values.security_group_ingress.map((i) => ({ from_port: i.from_port, to_port: i.to_port, cidr_blocks: [i.cidr_ip].filter(Boolean) }));
    }
    if (tfType === "aws_db_instance") {
      if (values.storage_encrypted === undefined && res.Properties?.StorageEncrypted !== undefined) values.storage_encrypted = res.Properties.StorageEncrypted;
      if (values.publicly_accessible === undefined && res.Properties?.PubliclyAccessible !== undefined) values.publicly_accessible = res.Properties.PubliclyAccessible;
    }
    if (tfType === "aws_iam_policy" && res.Properties?.PolicyDocument) values.policy = res.Properties.PolicyDocument; // keep original casing for policy doc
    out.push({ address: `${tfType}.${logicalId}`, type: tfType, name: logicalId, values });
  }
  return out;
}

/** Auto-detect the IaC format and normalize to resources. */
export function normalize(input) {
  if (!input || typeof input !== "object") return { format: "unknown", resources: [] };
  if (input.planned_values || input.resource_changes || input.format_version) return { format: "terraform", resources: fromTerraform(input) };
  if (Array.isArray(input.steps) || input.deployment) return { format: "pulumi", resources: fromPulumi(input) };
  if (input.Resources || input.AWSTemplateFormatVersion) return { format: "cloudformation", resources: fromCloudFormation(input) };
  return { format: "unknown", resources: [] };
}

// Back-compat: collectResources(plan) for Terraform
export function collectResources(plan) { return normalize(plan).resources; }

// ---------------------------------------------------------------------------
// Detectors
// ---------------------------------------------------------------------------
const cidrsOpen = (arr) => Array.isArray(arr) && arr.some((c) => c === "0.0.0.0/0" || c === "::/0");
const portCovers = (f, t, p) => Number(f) <= p && p <= Number(t);
const ci = (obj, key) => obj?.[key] ?? obj?.[key.charAt(0).toUpperCase() + key.slice(1)];

const DETECTORS = {
  S3_ENCRYPTION_AT_REST(r) {
    const sse = new Set(r.filter((x) => x.type === "aws_s3_bucket_server_side_encryption_configuration").map((x) => x.values.bucket));
    return r.filter((x) => x.type === "aws_s3_bucket").filter((x) => {
      const inline = Array.isArray(x.values.server_side_encryption_configuration) && x.values.server_side_encryption_configuration.length > 0;
      return !inline && !sse.has(x.values.bucket) && !sse.has(x.values.id);
    }).map((x) => ({ address: x.address, detail: "No server-side encryption configured for this bucket." }));
  },
  S3_PUBLIC_ACCESS(r) {
    const f = [];
    for (const x of r) {
      if ((x.type === "aws_s3_bucket_acl" || x.type === "aws_s3_bucket") && ["public-read", "public-read-write"].includes(x.values.acl)) f.push({ address: x.address, detail: `Bucket ACL is "${x.values.acl}".` });
      if (x.type === "aws_s3_bucket_public_access_block") { const v = x.values; if (!(v.block_public_acls && v.block_public_policy && v.ignore_public_acls && v.restrict_public_buckets)) f.push({ address: x.address, detail: "Public access block does not enable all four protections." }); }
    }
    return f;
  },
  RDS_ENCRYPTION_AT_REST: (r) => r.filter((x) => x.type === "aws_db_instance" && x.values.storage_encrypted !== true).map((x) => ({ address: x.address, detail: "storage_encrypted is not true." })),
  RDS_NOT_PUBLIC: (r) => r.filter((x) => x.type === "aws_db_instance" && x.values.publicly_accessible === true).map((x) => ({ address: x.address, detail: "publicly_accessible is true." })),
  EBS_ENCRYPTION_AT_REST: (r) => r.filter((x) => x.type === "aws_ebs_volume" && x.values.encrypted !== true).map((x) => ({ address: x.address, detail: "encrypted is not true." })),
  SG_NO_OPEN_ADMIN(r) {
    const f = [];
    for (const x of r) {
      if (x.type === "aws_security_group") for (const ing of x.values.ingress || []) if (cidrsOpen(ing.cidr_blocks) && (portCovers(ing.from_port, ing.to_port, 22) || portCovers(ing.from_port, ing.to_port, 3389))) f.push({ address: x.address, detail: `Ingress ${ing.from_port}-${ing.to_port} open to 0.0.0.0/0 (SSH/RDP).` });
      if (x.type === "aws_security_group_rule" && x.values.type === "ingress" && cidrsOpen(x.values.cidr_blocks) && (portCovers(x.values.from_port, x.values.to_port, 22) || portCovers(x.values.from_port, x.values.to_port, 3389))) f.push({ address: x.address, detail: `Ingress rule ${x.values.from_port}-${x.values.to_port} open to 0.0.0.0/0.` });
    }
    return f;
  },
  IAM_NO_WILDCARD_ADMIN(r) {
    const f = [];
    for (const x of r) {
      if (!["aws_iam_policy", "aws_iam_role_policy"].includes(x.type)) continue;
      let doc; try { doc = typeof x.values.policy === "string" ? JSON.parse(x.values.policy) : x.values.policy; } catch { continue; }
      const stmtsRaw = ci(doc, "statement");
      const stmts = Array.isArray(stmtsRaw) ? stmtsRaw : stmtsRaw ? [stmtsRaw] : [];
      for (const s of stmts) {
        if (ci(s, "effect") !== "Allow") continue;
        const a = [].concat(ci(s, "action") || []); const re = [].concat(ci(s, "resource") || []);
        if (a.includes("*") && re.includes("*")) { f.push({ address: x.address, detail: "Statement allows Action:* on Resource:* (full admin)." }); break; }
      }
    }
    return f;
  },
  LB_HTTPS_IN_TRANSIT: (r) => r.filter((x) => x.type === "aws_lb_listener" && String(x.values.protocol).toUpperCase() === "HTTP").map((x) => ({ address: x.address, detail: "Listener protocol is HTTP (unencrypted in transit)." })),
  CLOUDWATCH_LOG_ENCRYPTION: (r) => r.filter((x) => x.type === "aws_cloudwatch_log_group" && !x.values.kms_key_id).map((x) => ({ address: x.address, detail: "Log group has no kms_key_id." })),
  GCP_STORAGE_NOT_PUBLIC(r) {
    const f = [];
    for (const x of r) {
      if (["google_storage_bucket_iam_member", "google_storage_bucket_iam_binding"].includes(x.type)) {
        const members = [].concat(x.values.member || x.values.members || []);
        if (members.some((m) => m === "allUsers" || m === "allAuthenticatedUsers")) f.push({ address: x.address, detail: `Grants ${members.join(", ")} (public).` });
      }
    }
    return f;
  },
  GCP_SQL_NOT_PUBLIC(r) {
    const f = [];
    for (const x of r.filter((y) => y.type === "google_sql_database_instance")) {
      const ipc = (x.values.settings && [].concat(x.values.settings)[0]?.ip_configuration) || x.values.ip_configuration;
      const cfg = Array.isArray(ipc) ? ipc[0] : ipc;
      const nets = [].concat(cfg?.authorized_networks || []);
      if (cfg?.ipv4_enabled === true && nets.some((n) => (n.value || n) === "0.0.0.0/0")) f.push({ address: x.address, detail: "Public IPv4 with 0.0.0.0/0 authorized network." });
    }
    return f;
  },
  GCP_FIREWALL_NO_OPEN_ADMIN(r) {
    const f = [];
    for (const x of r.filter((y) => y.type === "google_compute_firewall")) {
      if (!cidrsOpen(x.values.source_ranges)) continue;
      const allow = [].concat(x.values.allow || []);
      for (const a of allow) { const ports = [].concat(a.ports || []); if (ports.some((p) => String(p) === "22" || String(p) === "3389" || String(p).includes("22"))) f.push({ address: x.address, detail: "source_ranges 0.0.0.0/0 allows SSH/RDP." }); }
    }
    return f;
  },
  AZURE_STORAGE_SECURE(r) {
    return r.filter((x) => x.type === "azurerm_storage_account").filter((x) => x.values.enable_https_traffic_only === false || x.values.allow_blob_public_access === true || x.values.allow_nested_items_to_be_public === true)
      .map((x) => ({ address: x.address, detail: "Storage account allows public blobs or non-HTTPS traffic." }));
  },
  AZURE_NSG_NO_OPEN_ADMIN(r) {
    return r.filter((x) => x.type === "azurerm_network_security_rule").filter((x) => {
      const v = x.values; const src = v.source_address_prefix;
      const open = src === "*" || src === "Internet" || src === "0.0.0.0/0";
      const dport = String(v.destination_port_range || "");
      return v.access === "Allow" && String(v.direction) === "Inbound" && open && (dport === "22" || dport === "3389" || dport === "*");
    }).map((x) => ({ address: x.address, detail: `Allows inbound ${x.values.destination_port_range} from ${x.values.source_address_prefix}.` }));
  },
  K8S_NO_PRIVILEGED(r) {
    const f = [];
    for (const x of r) {
      if (!["kubernetes_deployment", "kubernetes_pod", "kubernetes_deployment_v1", "kubernetes_pod_v1"].includes(x.type)) continue;
      const json = JSON.stringify(x.values || {});
      if (/"privileged"\s*:\s*true/.test(json)) f.push({ address: x.address, detail: "A container runs with privileged = true." });
    }
    return f;
  },
  K8S_NO_HOST_NETWORK(r) {
    const f = [];
    for (const x of r) {
      if (!["kubernetes_deployment", "kubernetes_pod", "kubernetes_deployment_v1", "kubernetes_pod_v1"].includes(x.type)) continue;
      if (/"host_network"\s*:\s*true/.test(JSON.stringify(x.values || {}))) f.push({ address: x.address, detail: "Pod spec uses host_network = true." });
    }
    return f;
  },
};

// ---------------------------------------------------------------------------
// Fix-It — generate a concrete remediation code patch per finding
// ---------------------------------------------------------------------------
const nameOf = (addr) => (addr || "resource").split(".").pop().replace(/[^a-zA-Z0-9_]/g, "_") || "this";
const PATCHERS = {
  S3_ENCRYPTION_AT_REST: (a) => `resource "aws_s3_bucket_server_side_encryption_configuration" "${nameOf(a)}_sse" {\n  bucket = aws_s3_bucket.${nameOf(a)}.id\n  rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" } }\n}`,
  S3_PUBLIC_ACCESS: (a) => `resource "aws_s3_bucket_public_access_block" "${nameOf(a)}_pab" {\n  bucket                  = aws_s3_bucket.${nameOf(a)}.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}`,
  RDS_ENCRYPTION_AT_REST: (a) => `resource "aws_db_instance" "${nameOf(a)}" {\n  # ...existing config...\n  storage_encrypted = true\n}`,
  RDS_NOT_PUBLIC: (a) => `resource "aws_db_instance" "${nameOf(a)}" {\n  # ...existing config...\n  publicly_accessible = false\n}`,
  EBS_ENCRYPTION_AT_REST: (a) => `resource "aws_ebs_volume" "${nameOf(a)}" {\n  # ...existing config...\n  encrypted = true\n}`,
  SG_NO_OPEN_ADMIN: (a) => `# In aws_security_group.${nameOf(a)}, replace the open admin ingress:\ningress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = "tcp"\n  cidr_blocks = [var.admin_cidr]   # e.g. your VPN range, NOT 0.0.0.0/0\n}`,
  IAM_NO_WILDCARD_ADMIN: (a) => `# Scope aws_iam_policy.${nameOf(a)} to least privilege:\n# "Action": ["s3:GetObject","s3:PutObject"],\n# "Resource": ["arn:aws:s3:::your-bucket/*"]`,
  LB_HTTPS_IN_TRANSIT: (a) => `resource "aws_lb_listener" "${nameOf(a)}" {\n  # ...existing config...\n  protocol          = "HTTPS"\n  port              = 443\n  certificate_arn   = var.acm_certificate_arn\n  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"\n}`,
  CLOUDWATCH_LOG_ENCRYPTION: (a) => `resource "aws_cloudwatch_log_group" "${nameOf(a)}" {\n  # ...existing config...\n  kms_key_id = aws_kms_key.logs.arn\n}`,
  GCP_STORAGE_NOT_PUBLIC: (a) => `# Remove the public IAM grant on ${nameOf(a)} and enforce:\nresource "google_storage_bucket" "${nameOf(a)}" {\n  uniform_bucket_level_access = true\n  public_access_prevention    = "enforced"\n}`,
  GCP_SQL_NOT_PUBLIC: (a) => `resource "google_sql_database_instance" "${nameOf(a)}" {\n  settings { ip_configuration { ipv4_enabled = false } }  # use private IP\n}`,
  GCP_FIREWALL_NO_OPEN_ADMIN: (a) => `resource "google_compute_firewall" "${nameOf(a)}" {\n  # ...existing config...\n  source_ranges = [var.admin_cidr]   # not 0.0.0.0/0\n}`,
  AZURE_STORAGE_SECURE: (a) => `resource "azurerm_storage_account" "${nameOf(a)}" {\n  # ...existing config...\n  enable_https_traffic_only       = true\n  allow_nested_items_to_be_public = false\n}`,
  AZURE_NSG_NO_OPEN_ADMIN: (a) => `# In azurerm_network_security_rule.${nameOf(a)}: set source_address_prefix to your admin range, not "*"/"Internet".`,
  K8S_NO_PRIVILEGED: (a) => `# In ${nameOf(a)} container security_context:\nsecurity_context { privileged = false; allow_privilege_escalation = false }`,
  K8S_NO_HOST_NETWORK: (a) => `# In ${nameOf(a)} pod spec: host_network = false`,
};

const SEV = { critical: 4, high: 3, medium: 2, low: 1 };

export function runPreflight(input, controls = loadControls()) {
  const norm = normalize(input);
  const resources = norm.resources;
  const findings = [], passed = [], na = [];
  for (const check of controls.checks) {
    const matching = resources.filter((r) => check.resourceTypes.includes(r.type));
    if (matching.length === 0) { na.push(check.id); continue; }
    const fails = DETECTORS[check.id] ? DETECTORS[check.id](resources) : [];
    if (fails.length === 0) passed.push(check.id);
    else for (const f of fails) findings.push({
      checkId: check.id, title: check.title, severity: check.severity, resource: f.address,
      detail: f.detail, frameworks: check.frameworks, fix: check.fix,
      patch: PATCHERS[check.id] ? PATCHERS[check.id](f.address) : null,
    });
  }
  findings.sort((a, b) => SEV[b.severity] - SEV[a.severity]);
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) bySeverity[f.severity]++;
  const evaluated = passed.length + new Set(findings.map((f) => f.checkId)).size;
  const score = evaluated === 0 ? null : Math.round((passed.length / evaluated) * 100);
  const verdict = bySeverity.critical + bySeverity.high > 0 ? "fail" : findings.length > 0 ? "warn" : "pass";

  const FW_KEYS = ["soc2", "iso27001", "eu_ai_act", "nist_ai_rmf", "hipaa"];
  const fw = {}; for (const k of FW_KEYS) fw[k] = { c: new Set(), x: new Set() };
  for (const check of controls.checks) {
    if (na.includes(check.id)) continue;
    const failing = findings.some((f) => f.checkId === check.id);
    for (const k of FW_KEYS) (check.frameworks[k] || []).forEach((c) => { fw[k].c.add(c); if (failing) fw[k].x.add(c); });
  }
  const frameworkCoverage = {}; for (const k of FW_KEYS) frameworkCoverage[k] = { checked: [...fw[k].c].sort(), failing: [...fw[k].x].sort() };

  return {
    tool: "trooth-preflight", catalogVersion: controls._meta.version, format: norm.format,
    generatedAt: new Date().toISOString(), planResourceCount: resources.length,
    verdict, score, summary: { pass: passed.length, fail: findings.length, notApplicable: na.length, bySeverity },
    findings, passedChecks: passed, notApplicableChecks: na, frameworkCoverage,
    disclaimer: "Advisory. Analyzes declared infrastructure intent, not live production state. Trooth never applies changes.",
  };
}

// ---------------------------------------------------------------------------
// Drift — compare declared intent against a read-only production snapshot
// ---------------------------------------------------------------------------
// Security-relevant attributes whose "secure" value matters.
const DRIFT_ATTRS = {
  aws_db_instance: ["storage_encrypted", "publicly_accessible"],
  aws_s3_bucket: ["acl"],
  aws_ebs_volume: ["encrypted"],
  aws_lb_listener: ["protocol"],
  azurerm_storage_account: ["enable_https_traffic_only", "allow_blob_public_access"],
  google_sql_database_instance: ["ipv4_enabled"],
};
/**
 * @param intentInput  IaC plan (any supported format) = what SHOULD be deployed
 * @param liveSnapshot array of { address?, type, name?, values } = read-only prod state
 */
export function detectDrift(intentInput, liveSnapshot) {
  const intent = normalize(intentInput).resources;
  const live = Array.isArray(liveSnapshot) ? liveSnapshot : normalize(liveSnapshot).resources;
  const liveByAddr = new Map(); const liveByTypeName = new Map();
  for (const r of live) { if (r.address) liveByAddr.set(r.address, r); liveByTypeName.set(`${r.type}.${r.name}`, r); }
  const drift = [];
  for (const r of intent) {
    const match = liveByAddr.get(r.address) || liveByTypeName.get(`${r.type}.${r.name}`);
    if (!match) { drift.push({ address: r.address, type: r.type, kind: "missing_in_prod", detail: "Declared in code but not found in the production snapshot." }); continue; }
    for (const attr of DRIFT_ATTRS[r.type] || []) {
      if (r.values[attr] !== undefined && match.values[attr] !== undefined && r.values[attr] !== match.values[attr]) {
        drift.push({ address: r.address, type: r.type, attribute: attr, intended: r.values[attr], actual: match.values[attr], kind: "config_drift", detail: `${attr}: code says ${JSON.stringify(r.values[attr])}, production is ${JSON.stringify(match.values[attr])}.` });
      }
    }
  }
  return {
    tool: "trooth-preflight-drift", generatedAt: new Date().toISOString(),
    intentResourceCount: intent.length, liveResourceCount: live.length,
    inSync: drift.length === 0, driftCount: drift.length, drift,
    disclaimer: "Read-only drift check. Compares declared intent to a production snapshot; Trooth never modifies production.",
  };
}
