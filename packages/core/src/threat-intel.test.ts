import { describe, expect, it } from "vitest";
import {
  extractDomain,
  analyzeContagiousInterviewText,
  evaluateRecruiterThreat,
  KNOWN_THREAT_IOCS,
} from "./threat-intel.js";

describe("threat-intel", () => {
  it("extracts domains accurately from various input shapes", () => {
    expect(extractDomain("jemm@nindar.com")).toBe("nindar.com");
    expect(extractDomain("https://sub.evil.corp/apply")).toBe("sub.evil.corp");
    expect(extractDomain("evil.com")).toBe("evil.com");
    expect(extractDomain("https://www.google.com/test")).toBe("google.com");
  });

  it("identifies confirmed blacklisted threat actors immediately", async () => {
    const report = await evaluateRecruiterThreat({
      domainOrEmail: "jemm@nindar.com",
      senderName: "Jemm Depositar",
    });

    expect(report.isThreat).toBe(true);
    expect(report.riskLevel).toBe("critical");
    expect(report.score).toBe(1.0);
    expect(report.flags.some((f) => f.includes("BLACKLIST MATCH"))).toBe(true);
    expect(report.recommendations.some((r) => r.includes("DO NOT REPLY"))).toBe(true);
  });

  it("detects contagious interview red flags in message text", () => {
    const maliciousMsg =
      "Hi! We love your background. Please clone this repo https://github.com/fake-org/test-task and run npm install to complete our take-home assessment.";
    const analysis = analyzeContagiousInterviewText(maliciousMsg);

    expect(analysis.threatHits).toBeGreaterThan(0);
    expect(analysis.flags.some((f) => f.includes("npm install") || f.includes("clone"))).toBe(true);
  });

  it("flags young domains from RDAP mock data as critical risk", async () => {
    const report = await evaluateRecruiterThreat(
      { domainOrEmail: "brand-new-recruiter.io" },
      {
        domainInfoOverride: {
          domain: "brand-new-recruiter.io",
          registeredAt: new Date(Date.now() - 10 * 86400 * 1000).toISOString(),
          ageDays: 10,
          registrar: "Namecheap",
          rdapAvailable: true,
        },
      }
    );

    expect(report.score).toBeGreaterThanOrEqual(0.7);
    expect(report.flags.some((f) => f.includes("only 10 days old"))).toBe(true);
  });

  it("treats established safe domains with standard verification", async () => {
    const report = await evaluateRecruiterThreat(
      { domainOrEmail: "recruiting@supabase.com" },
      {
        domainInfoOverride: {
          domain: "supabase.com",
          registeredAt: "2019-01-01T00:00:00Z",
          ageDays: 2000,
          registrar: "Cloudflare",
          rdapAvailable: true,
        },
      }
    );

    expect(report.isThreat).toBe(false);
    expect(report.riskLevel).toBe("safe");
  });
});
