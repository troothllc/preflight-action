/**
 * Trooth Pre-Flight — Compliance-as-Code engine
 * Copyright (c) 2026 Trooth, LLC. All rights reserved.
 *
 * Analyzes the RESOLVED INTENT of infrastructure (a `terraform show -json` plan)
 * against the control catalog, mapped to SOC 2 / ISO 27001 / EU AI Act, and emits
 * a signed-ready "Compliance Delta" with a Fix-It remediation per finding.
 *
 * ADVISORY ONLY. Trooth never applies changes. The engineer merges the suggested
 * patch; Git history is the rollback. No environment access is required — we read
 * the plan, not the live cloud. (Honest-claims: this proves declared intent, not
 * production state; pair with read-only drift to attest production.)
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dir = dirname(fileURLToPath(import.meta.url));

export function loadControls() {
  return JSON.parse(readFileSync(join(__dir, "controls.json"), "utf8"));
}

/** Flatten a `terraform show -json` plan into [{address, type, values}]. */
export function collectResources(plan) {
  const out = [];
  const walkModule = (m) => {
    if (!m) return;
    for (const r of m.resources || []) {
      if (r.mode === "data") continue; // data sources aren't provisioned
      out.push({ address: r.address, type: r.type, name: r.name, values: r.values || {} });
    }
    for (const c of m.child_modules || []) walkModule(c);
  };
  if (plan?.planned_values?.root_module) {
    walkModule(plan.planned_values.root_module);
  }
  // Fallback: resource_changes (post-apply "after" values)
  if (out.length === 0 && Array.isArray(plan?.resource_changes)) {
    for (const rc of plan.resource_changes) {
      const after = rc.change?.after;
      if (after && rc.mode !== "data") out.push({ address: rc.address, type: rc.type, name: rc.name, values: after });
    }
  }
  return out;
}

const cidrsOpen = (arr) => Array.isArray(arr) && arr.some((c) => c === "0.0.0.0/0" || c === "::/0");
const portCovers = (from, to, p) => Number(from) <= p && p <= Number(to);

// Detector per check id. Returns array of failing resources: {address, detail}.
const DETECTORS = {
  S3_ENCRYPTION_AT_REST(resources) {
    const sseTargets = new Set(
      resources
        .filter((r) => r.type === "aws_s3_bucket_server_side_encryption_configuration")
        .map((r) => r.values.bucket),
    );
    return resources
      .filter((r) => r.type === "aws_s3_bucket")
      .filter((r) => {
        const inline = Array.isArray(r.values.server_side_encryption_configuration) && r.values.server_side_encryption_configuration.length > 0;
        const external = sseTargets.has(r.values.bucket) || sseTargets.has(r.values.id);
        return !inline && !external;
      })
      .map((r) => ({ address: r.address, detail: "No server-side encryption configured for this bucket." }));
  },
  S3_PUBLIC_ACCESS(resources) {
    const fails = [];
    for (const r of resources) {
      if (r.type === "aws_s3_bucket_acl" && ["public-read", "public-read-write"].includes(r.values.acl)) {
        fails.push({ address: r.address, detail: `Bucket ACL is "${r.values.acl}".` });
      }
      if (r.type === "aws_s3_bucket" && ["public-read", "public-read-write"].includes(r.values.acl)) {
        fails.push({ address: r.address, detail: `Bucket ACL is "${r.values.acl}".` });
      }
      if (r.type === "aws_s3_bucket_public_access_block") {
        const v = r.values;
        const allOn = v.block_public_acls && v.block_public_policy && v.ignore_public_acls && v.restrict_public_buckets;
        if (!allOn) fails.push({ address: r.address, detail: "Public access block does not enable all four protections." });
      }
    }
    return fails;
  },
  RDS_ENCRYPTION_AT_REST(resources) {
    return resources
      .filter((r) => r.type === "aws_db_instance" && r.values.storage_encrypted !== true)
      .map((r) => ({ address: r.address, detail: "storage_encrypted is not true." }));
  },
  RDS_NOT_PUBLIC(resources) {
    return resources
      .filter((r) => r.type === "aws_db_instance" && r.values.publicly_accessible === true)
      .map((r) => ({ address: r.address, detail: "publicly_accessible is true." }));
  },
  EBS_ENCRYPTION_AT_REST(resources) {
    return resources
      .filter((r) => r.type === "aws_ebs_volume" && r.values.encrypted !== true)
      .map((r) => ({ address: r.address, detail: "encrypted is not true." }));
  },
  SG_NO_OPEN_ADMIN(resources) {
    const fails = [];
    for (const r of resources) {
      if (r.type === "aws_security_group") {
        for (const ing of r.values.ingress || []) {
          if (cidrsOpen(ing.cidr_blocks) && (portCovers(ing.from_port, ing.to_port, 22) || portCovers(ing.from_port, ing.to_port, 3389))) {
            fails.push({ address: r.address, detail: `Ingress ${ing.from_port}-${ing.to_port} open to 0.0.0.0/0 (SSH/RDP).` });
          }
        }
      }
      if (r.type === "aws_security_group_rule" && r.values.type === "ingress" && cidrsOpen(r.values.cidr_blocks)) {
        if (portCovers(r.values.from_port, r.values.to_port, 22) || portCovers(r.values.from_port, r.values.to_port, 3389)) {
          fails.push({ address: r.address, detail: `Ingress rule ${r.values.from_port}-${r.values.to_port} open to 0.0.0.0/0.` });
        }
      }
    }
    return fails;
  },
  IAM_NO_WILDCARD_ADMIN(resources) {
    const fails = [];
    for (const r of resources) {
      if (!["aws_iam_policy", "aws_iam_role_policy"].includes(r.type)) continue;
      let doc;
      try { doc = typeof r.values.policy === "string" ? JSON.parse(r.values.policy) : r.values.policy; } catch { continue; }
      const stmts = Array.isArray(doc?.Statement) ? doc.Statement : doc?.Statement ? [doc.Statement] : [];
      for (const s of stmts) {
        if (s.Effect !== "Allow") continue;
        const acts = [].concat(s.Action || []);
        const ress = [].concat(s.Resource || []);
        if (acts.includes("*") && ress.includes("*")) {
          fails.push({ address: r.address, detail: "Statement allows Action:* on Resource:* (full admin)." });
          break;
        }
      }
    }
    return fails;
  },
  LB_HTTPS_IN_TRANSIT(resources) {
    return resources
      .filter((r) => r.type === "aws_lb_listener" && String(r.values.protocol).toUpperCase() === "HTTP")
      .map((r) => ({ address: r.address, detail: "Listener protocol is HTTP (unencrypted in transit)." }));
  },
  CLOUDWATCH_LOG_ENCRYPTION(resources) {
    return resources
      .filter((r) => r.type === "aws_cloudwatch_log_group" && !r.values.kms_key_id)
      .map((r) => ({ address: r.address, detail: "Log group has no kms_key_id." }));
  },
};

const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

/** Run the full Pre-Flight scan. Returns the Compliance Delta. */
export function runPreflight(plan, controls = loadControls()) {
  const resources = collectResources(plan);
  const findings = [];
  const passed = [];
  const notApplicable = [];

  for (const check of controls.checks) {
    const matching = resources.filter((r) => check.resourceTypes.includes(r.type));
    if (matching.length === 0) { notApplicable.push(check.id); continue; }
    const det = DETECTORS[check.id];
    const fails = det ? det(resources) : [];
    if (fails.length === 0) {
      passed.push(check.id);
    } else {
      for (const f of fails) {
        findings.push({
          checkId: check.id,
          title: check.title,
          severity: check.severity,
          resource: f.address,
          detail: f.detail,
          frameworks: check.frameworks,
          fix: check.fix,
        });
      }
    }
  }

  findings.sort((a, b) => SEV_ORDER[b.severity] - SEV_ORDER[a.severity]);

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) bySeverity[f.severity]++;

  const evaluated = passed.length + new Set(findings.map((f) => f.checkId)).size;
  const score = evaluated === 0 ? null : Math.round((passed.length / evaluated) * 100);
  const verdict = bySeverity.critical + bySeverity.high > 0 ? "fail" : findings.length > 0 ? "warn" : "pass";

  // Framework rollup — which controls were touched and which are failing.
  const fw = { soc2: { checked: new Set(), failing: new Set() }, iso27001: { checked: new Set(), failing: new Set() }, eu_ai_act: { checked: new Set(), failing: new Set() } };
  const apply = (check, set) => { for (const k of Object.keys(fw)) (check.frameworks[k] || []).forEach((c) => fw[k][set].add(c)); };
  for (const check of controls.checks) {
    if (notApplicable.includes(check.id)) continue;
    apply(check, "checked");
    if (findings.some((f) => f.checkId === check.id)) apply(check, "failing");
  }
  const fwOut = {};
  for (const k of Object.keys(fw)) fwOut[k] = { checked: [...fw[k].checked].sort(), failing: [...fw[k].failing].sort() };

  return {
    tool: "trooth-preflight",
    catalogVersion: controls._meta.version,
    generatedAt: new Date().toISOString(),
    planResourceCount: resources.length,
    verdict,
    score,
    summary: {
      pass: passed.length,
      fail: findings.length,
      notApplicable: notApplicable.length,
      bySeverity,
    },
    findings,
    passedChecks: passed,
    notApplicableChecks: notApplicable,
    frameworkCoverage: fwOut,
    disclaimer: "Advisory. Analyzes declared infrastructure intent, not live production state. Trooth never applies changes.",
  };
}
