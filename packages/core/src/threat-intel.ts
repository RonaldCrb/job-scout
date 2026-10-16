import { log as rootLog } from "@job-scout/shared";

const log = rootLog.child({ scope: "threat-intel" });

export type ThreatRiskLevel = "safe" | "low" | "medium" | "high" | "critical";

export type DomainInfo = {
  domain: string;
  registeredAt?: string;
  ageDays?: number;
  registrar?: string;
  rdapAvailable: boolean;
};

export type ThreatEvaluation = {
  target: string;
  normalizedDomain?: string;
  riskLevel: ThreatRiskLevel;
  isThreat: boolean;
  score: number; // 0.0 (clean) to 1.0 (dangerous)
  flags: string[];
  recommendations: string[];
  domainInfo?: DomainInfo;
};

/**
 * Confirmed threat IOCs flagged by peer engineering networks (e.g. Lazarus,
 * TraderTraitor, "Contagious Interview" campaigns targeting Web3/DevOps engineers).
 */
export const KNOWN_THREAT_IOCS: Array<{
  pattern: string;
  type: "domain" | "sender" | "keyword";
  name: string;
  details: string;
}> = [
  {
    pattern: "nindar.com",
    type: "domain",
    name: "Jemm Depositar / Nindar shell",
    details: "Confirmed Contagious Interview campaign targeting Exodus/Web3 SREs. Delivers malicious npm/pip repo.",
  },
  {
    pattern: "jemm depositar",
    type: "sender",
    name: "Jemm Depositar alias",
    details: "Known malicious recruiter profile on LinkedIn.",
  },
];

export const FREE_EMAIL_PROVIDERS = new Set([
  "gmail.com",
  "yahoo.com",
  "hotmail.com",
  "outlook.com",
  "proton.me",
  "protonmail.com",
  "icloud.com",
  "zoho.com",
  "aol.com",
]);

export function extractDomain(input: string): string | null {
  const trimmed = input.trim().toLowerCase();
  if (trimmed.includes("@")) {
    const parts = trimmed.split("@");
    return parts[parts.length - 1] || null;
  }
  try {
    const url = trimmed.startsWith("http") ? new URL(trimmed) : new URL(`https://${trimmed}`);
    return url.hostname.replace(/^www\./, "");
  } catch {
    // If not a full URL, attempt bare domain regex
    const m = trimmed.match(/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}/i);
    return m ? m[0] : null;
  }
}

/**
 * Query public RDAP for domain registration age.
 * Free, non-authenticated, standard IETF protocol.
 */
export async function queryDomainRdap(domain: string, timeoutMs = 4000): Promise<DomainInfo> {
  const cleanDomain = domain.toLowerCase().trim();
  const info: DomainInfo = { domain: cleanDomain, rdapAvailable: false };

  try {
    const ctrl = new AbortController();
    const timeout = setTimeout(() => ctrl.abort(), timeoutMs);

    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(cleanDomain)}`, {
      headers: { Accept: "application/rdap+json, application/json" },
      signal: ctrl.signal,
    });
    clearTimeout(timeout);

    if (!res.ok) {
      log.debug("rdap.not_ok", { domain: cleanDomain, status: res.status });
      return info;
    }

    const data = (await res.json()) as Record<string, unknown>;
    info.rdapAvailable = true;

    // Events list contains registration date
    const events = (data.events || []) as Array<{ eventAction?: string; eventDate?: string }>;
    const regEvent = events.find(
      (e) => e.eventAction === "registration" || e.eventAction === "created"
    );

    if (regEvent?.eventDate) {
      info.registeredAt = regEvent.eventDate;
      const regTime = new Date(regEvent.eventDate).getTime();
      if (!Number.isNaN(regTime)) {
        info.ageDays = Math.floor((Date.now() - regTime) / (1000 * 60 * 60 * 24));
      }
    }

    // Entities often contain registrar
    const entities = (data.entities || []) as Array<{ roles?: string[]; vcardArray?: unknown }>;
    const regEntity = entities.find((e) => (e.roles || []).includes("registrar"));
    if (regEntity && Array.isArray(regEntity.vcardArray)) {
      // vCard format: ["vcard", [["fn", {}, "text", "Namecheap"], ...]]
      const entries = (regEntity.vcardArray[1] || []) as unknown[];
      const fnEntry = entries.find((entry) => Array.isArray(entry) && entry[0] === "fn") as unknown[];
      if (fnEntry && typeof fnEntry[3] === "string") {
        info.registrar = fnEntry[3];
      }
    }

    return info;
  } catch (err: unknown) {
    log.debug("rdap.query_error", { domain: cleanDomain, err: err instanceof Error ? err.message : String(err) });
    return info;
  }
}

/**
 * Heuristics for "Contagious Interview" attacks.
 * Attackers lure engineers with high comp, then request them to clone external repos
 * containing post-install lifecycle backdoors or download meeting helpers.
 */
export function analyzeContagiousInterviewText(text: string): { flags: string[]; threatHits: number } {
  const flags: string[] = [];
  const lower = text.toLowerCase();

  // Pattern 1: Code execution requests before human screen
  const codeExecutionTriggers = [
    "npm run",
    "npm install",
    "pnpm install",
    "cargo build",
    "pip install",
    "docker run",
    "clone the repo",
    "clone this repo",
    "test assessment repo",
    "run the test suite",
    "git clone",
  ];
  for (const t of codeExecutionTriggers) {
    if (lower.includes(t)) {
      flags.push(`Suspicious early code execution request: "${t}"`);
    }
  }

  // Pattern 2: Fake meeting software / executable downloads
  const downloadTriggers = [
    ".dmg",
    ".pkg",
    ".exe",
    ".zip",
    "zoom-update",
    "webex-patch",
    "download the client",
    "meeting audio plugin",
  ];
  for (const t of downloadTriggers) {
    if (lower.includes(t)) {
      flags.push(`Suspicious executable download lure: "${t}"`);
    }
  }

  // Pattern 3: Urgent / evasive unverified company references
  if (lower.includes("confidential client") && lower.includes("take-home")) {
    flags.push("Unverified anonymous client combined with take-home test");
  }

  return { flags, threatHits: flags.length };
}

/**
 * Master threat evaluation engine.
 * Computes a weighted risk score and actionable advisory.
 */
export async function evaluateRecruiterThreat(
  input: {
    domainOrEmail: string;
    messageText?: string;
    senderName?: string;
  },
  options?: { skipRdap?: boolean; domainInfoOverride?: DomainInfo }
): Promise<ThreatEvaluation> {
  const { domainOrEmail, messageText, senderName } = input;
  const domain = extractDomain(domainOrEmail);
  const flags: string[] = [];
  const recommendations: string[] = [];
  let score = 0.0;

  // 1. Blacklist Check
  if (domain) {
    const domainMatch = KNOWN_THREAT_IOCS.find(
      (ioc) => ioc.type === "domain" && domain.endsWith(ioc.pattern.toLowerCase())
    );
    if (domainMatch) {
      score += 1.0;
      flags.push(`CONFIRMED BLACKLIST MATCH: ${domainMatch.name} (${domainMatch.details})`);
      recommendations.push("DO NOT REPLY. Block sender immediately.");
      recommendations.push("Never clone repos or click links associated with this domain.");
      return {
        target: domainOrEmail,
        normalizedDomain: domain,
        riskLevel: "critical",
        isThreat: true,
        score: 1.0,
        flags,
        recommendations,
      };
    }
  }

  if (senderName) {
    const sLower = senderName.toLowerCase();
    const senderMatch = KNOWN_THREAT_IOCS.find(
      (ioc) => ioc.type === "sender" && sLower.includes(ioc.pattern.toLowerCase())
    );
    if (senderMatch) {
      score += 0.9;
      flags.push(`CONFIRMED BLACKLISTED SENDER: ${senderMatch.name}`);
      recommendations.push("Known malicious recruiter identity. Block immediately.");
    }
  }

  // 2. Free Email Provider Warning
  if (domain && FREE_EMAIL_PROVIDERS.has(domain)) {
    score += 0.3;
    flags.push(`Unsolicited recruiter using generic public email provider (@${domain})`);
    recommendations.push("Legitimate corporate recruiters typically contact from enterprise corporate domains.");
  }

  // 3. Domain Age via RDAP
  let domainInfo: DomainInfo | undefined = options?.domainInfoOverride;
  if (domain && !domainInfo && !options?.skipRdap && !FREE_EMAIL_PROVIDERS.has(domain)) {
    domainInfo = await queryDomainRdap(domain);
  }

  if (domainInfo?.rdapAvailable && domainInfo.ageDays != null) {
    if (domainInfo.ageDays < 30) {
      score += 0.7;
      flags.push(`CRITICAL: Domain is only ${domainInfo.ageDays} days old (registered ${domainInfo.registeredAt?.slice(0, 10)})`);
      recommendations.push("High probability of disposable phishing shell. Do not execute code.");
    } else if (domainInfo.ageDays < 180) {
      score += 0.4;
      flags.push(`WARNING: Domain is relatively fresh (${domainInfo.ageDays} days old)`);
      recommendations.push("Verify company presence on LinkedIn, GitHub, and corporate registry before engaging.");
    } else {
      recommendations.push(`Domain has established age (${Math.floor(domainInfo.ageDays / 365)}y+ registered).`);
    }
  }

  // 4. Message Content Heuristics
  if (messageText) {
    const contentAnalysis = analyzeContagiousInterviewText(messageText);
    for (const f of contentAnalysis.flags) {
      flags.push(f);
      score += 0.35;
    }
  }

  // Cap score at 1.0
  score = Math.min(1.0, Math.round(score * 100) / 100);

  let riskLevel: ThreatRiskLevel = "safe";
  if (score >= 0.75) riskLevel = "critical";
  else if (score >= 0.5) riskLevel = "high";
  else if (score >= 0.3) riskLevel = "medium";
  else if (score > 0.05) riskLevel = "low";

  const isThreat = score >= 0.5;

  if (!isThreat && recommendations.length === 0) {
    recommendations.push("No obvious indicators of compromise detected. Standard verification applies.");
  }

  return {
    target: domainOrEmail,
    normalizedDomain: domain ?? undefined,
    riskLevel,
    isThreat,
    score,
    flags,
    recommendations,
    domainInfo,
  };
}
