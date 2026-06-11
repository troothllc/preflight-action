/** Trooth Pre-Flight — render a Compliance Delta as Markdown (PR comment) or terminal text. */

const ICON = { critical: "🔴", high: "🟠", medium: "🟡", low: "⚪" };
const VERDICT = { pass: "✅ PASS", warn: "🟡 ADVISORY", fail: "🔴 ACTION NEEDED" };

export function toMarkdown(delta) {
  const s = delta.summary;
  const lines = [];
  lines.push(`### ${VERDICT[delta.verdict] || delta.verdict} · Trooth Pre-Flight`);
  lines.push("");
  lines.push(`**Score ${delta.score ?? "—"}/100** · ${s.pass} passing · ${s.fail} to fix · ${s.notApplicable} n/a · scanned ${delta.planResourceCount} resources (declared intent).`);
  lines.push("");
  if (delta.findings.length) {
    lines.push("| | Control | Resource | Frameworks | Fix |");
    lines.push("|---|---|---|---|---|");
    for (const f of delta.findings) {
      const fw = [
        ...(f.frameworks.soc2 || []).map((c) => `SOC2 ${c}`),
        ...(f.frameworks.eu_ai_act || []).map((c) => `EU-AI ${c}`),
      ].join(", ");
      lines.push(`| ${ICON[f.severity]} | **${f.title}** | \`${f.resource}\` | ${fw} | ${f.fix} |`);
    }
    lines.push("");
  } else {
    lines.push("All evaluated infrastructure controls pass. 🎉");
    lines.push("");
  }
  const fw = delta.frameworkCoverage;
  lines.push(`<sub>SOC 2 controls failing: ${fw.soc2.failing.join(", ") || "none"} · ISO 27001: ${fw.iso27001.failing.join(", ") || "none"} · EU AI Act: ${fw.eu_ai_act.failing.join(", ") || "none"}</sub>`);
  lines.push("");
  lines.push(`<sub>${delta.disclaimer} Powered by Trooth OS — Compliance-as-Code.</sub>`);
  return lines.join("\n");
}

export function toText(delta) {
  const s = delta.summary;
  const out = [];
  out.push(`Trooth Pre-Flight — ${(VERDICT[delta.verdict] || delta.verdict).replace(/[^\x00-\x7F]/g, "").trim()}`);
  out.push(`Score ${delta.score ?? "—"}/100  |  ${s.pass} pass  ${s.fail} fix  ${s.notApplicable} n/a  |  ${delta.planResourceCount} resources`);
  out.push("");
  for (const f of delta.findings) {
    out.push(`[${f.severity.toUpperCase()}] ${f.title}`);
    out.push(`   resource: ${f.resource}`);
    out.push(`   ${f.detail}`);
    out.push(`   frameworks: SOC2 ${(f.frameworks.soc2 || []).join("/")}  ISO ${(f.frameworks.iso27001 || []).join("/")}  EU-AI ${(f.frameworks.eu_ai_act || []).join("/")}`);
    out.push(`   fix: ${f.fix}`);
    out.push("");
  }
  if (!delta.findings.length) out.push("All evaluated controls pass.");
  out.push(delta.disclaimer);
  return out.join("\n");
}
