import { evaluateRecruiterThreat } from "../packages/core/src/threat-intel.js";

async function main() {
  const target = process.argv[2];
  const message = process.argv[3];

  if (!target) {
    console.error("Usage: pnpm exec tsx scripts/screen-threat.ts <domain-or-email> [message-text]");
    process.exit(1);
  }

  console.log(`\n🛡️ Screening recruiter target: ${target}...\n`);
  const report = await evaluateRecruiterThreat({
    domainOrEmail: target,
    messageText: message,
  });

  console.log("=== THREAT REPORT ===");
  console.log(`Target:           ${report.target}`);
  console.log(`Risk Level:       ${report.riskLevel.toUpperCase()}`);
  console.log(`Is Threat:        ${report.isThreat ? "🚨 YES (HIGH RISK)" : "✅ NO (CLEAN)"}`);
  console.log(`Score:            ${report.score} / 1.0`);

  if (report.domainInfo?.rdapAvailable) {
    console.log(`Domain Age:       ${report.domainInfo.ageDays ?? "Unknown"} days (Registered: ${report.domainInfo.registeredAt?.slice(0, 10) ?? "N/A"})`);
    console.log(`Registrar:        ${report.domainInfo.registrar ?? "Unknown"}`);
  }

  if (report.flags.length > 0) {
    console.log("\nFlags Triggered:");
    report.flags.forEach((f) => console.log(`  ⚠️  ${f}`));
  }

  if (report.recommendations.length > 0) {
    console.log("\nRecommendations:");
    report.recommendations.forEach((r) => console.log(`  👉 ${r}`));
  }
  console.log("\n");
}

main().catch(console.error);
