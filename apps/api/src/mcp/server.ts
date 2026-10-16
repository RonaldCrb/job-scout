import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { and, desc, eq, sql } from "drizzle-orm";
import { companies, getDb, positions, timelineEvents, type EvaluationKind } from "@job-scout/db";
import {
  addEvent,
  archivePosition,
  currentJdText,
  discoverySummary,
  enqueueDueBoardScans,
  enqueueJob,
  getCompany,
  getEvaluation,
  getPositionDetail,
  getProfile,
  intakeUrl,
  listChangesSince,
  listCompanies,
  listDiscovery,
  listPositions,
  reconcileCareerOps,
  ReconcileInput,
  patchPosition,
  refreshPosition,
  runEvaluate,
  runJdReview,
  runMaterials,
  runTriage,
  refreshStaleTriage,
  RefreshStaleTriageInput,
  runListingClassify,
  stampCareerOps,
  upsertFromJob,
  usageSummary,
  retryFailedLlm,
  LlmGateError,
  getCurrentMaterial,
  listEvents,
  briefOf,
  triageBriefOf,
  mcpCalls,
  mcpDuration,
  jevStatus,
  recentDecisions,
  previewDecision,
} from "@job-scout/core";
import { log as rootLog } from "@job-scout/shared";
import { env } from "../env.js";
import { text } from "./result.js";
import { workQueue, WorkQueueInput } from "./work-queue.js";

type ToolCtx = { authInfo?: { clientId?: string; scopes?: string[] }; http?: { authInfo?: { clientId?: string; scopes?: string[] } } };
const agentOf = (ctx: ToolCtx) => ctx.http?.authInfo?.clientId || ctx.authInfo?.clientId || "mcp-client";

const errText = (e: unknown) => text({ error: e instanceof Error ? e.message : String(e), code: e instanceof LlmGateError ? e.code : undefined }, true);

async function resolvePositionId(idOrSlug?: string, q?: string) {
  if (idOrSlug) {
    const p = await getPositionDetail(idOrSlug);
    if (p) return p;
  }
  if (q) {
    const r = await listPositions({ q, pageSize: "1" });
    if (r.items[0]) return getPositionDetail(r.items[0].id);
  }
  return null;
}

const mcpLog = rootLog.child({ scope: "mcp" });

/** Wrap every registerTool handler with a counter, a latency histogram and one JSON log line. */
function instrumentTools(server: McpServer) {
  const original = server.registerTool.bind(server);
  type Handler = (...args: unknown[]) => Promise<{ isError?: boolean } | unknown> | { isError?: boolean } | unknown;
  (server as unknown as { registerTool: (name: string, cfg: unknown, handler: Handler) => unknown }).registerTool = (name, cfg, handler) =>
    (original as unknown as (name: string, cfg: unknown, handler: Handler) => unknown)(name, cfg, async (...args: unknown[]) => {
      const t0 = Date.now();
      try {
        const out = (await handler(...args)) as { isError?: boolean };
        const status = out?.isError ? "error" : "ok";
        const ms = Date.now() - t0;
        mcpCalls.labels({ tool: name, status }).inc();
        mcpDuration.labels({ tool: name }).observe(ms / 1000);
        mcpLog[status === "ok" ? "info" : "warn"]("mcp.tool", { tool: name, status, ms, args: compactArgs(args[0]) });
        return out;
      } catch (e) {
        const ms = Date.now() - t0;
        mcpCalls.labels({ tool: name, status: "throw" }).inc();
        mcpDuration.labels({ tool: name }).observe(ms / 1000);
        mcpLog.error("mcp.tool", { tool: name, status: "throw", ms, args: compactArgs(args[0]), err: e });
        throw e;
      }
    });
}
function compactArgs(a: unknown): unknown {
  if (!a || typeof a !== "object") return undefined;
  const s = JSON.stringify(a);
  return s.length > 300 ? s.slice(0, 300) + "…" : a;
}

/**
 * job-scout MCP. Keeps the original 22 tool names (semantics mapped onto the
 * current pipeline) and adds the sync tools used by the career-ops skill.
 */
export function createJobScoutMcpServer() {
  const server = new McpServer({ name: "job-scout", version: env.version });
  instrumentTools(server);

  server.registerTool(
    "server_info",
    { title: "Server info", description: "job-scout identity, version, endpoints, LLM status.", inputSchema: z.object({}), annotations: { readOnlyHint: true } },
    async () => text({ name: "job-scout", version: env.version, publicBaseUrl: env.publicBaseUrl, mcp: `${env.publicBaseUrl}/mcp`, api: `${env.publicBaseUrl}/api/v1`, llm: await usageSummary(24) }),
  );

  server.registerTool(
    "market_summary",
    { title: "Pipeline + radar summary", description: "Counts by status/verdict, discovery lanes for the last N hours, LLM usage.", inputSchema: { hours: z.number().int().min(1).max(720).optional() }, annotations: { readOnlyHint: true } },
    async (a) => {
      const db = await getDb();
      const counts = await db.select({ status: positions.status, verdict: positions.triageVerdict, c: sql<number>`count(*)::int` }).from(positions).groupBy(positions.status, positions.triageVerdict);
      return text({ positions: counts, discovery: await discoverySummary(a.hours ?? 24), llm: await usageSummary(a.hours ?? 24) });
    },
  );

  server.registerTool(
    "list_positions",
    {
      title: "List positions",
      description: "Slim rows. Filters: status (comma list, 'hot', 'active', 'all' incl. archived), verdict (pass|marginal|fail|none), q, company, minScore, sort (updated_desc|score_desc|company|status|first_seen_desc|last_changed_desc), includeArchived. Cursor pagination via nextCursor.",
      inputSchema: {
        status: z.string().optional(),
        verdict: z.string().optional(),
        q: z.string().optional(),
        company: z.string().optional(),
        minScore: z.number().optional(),
        sort: z.string().optional(),
        includeArchived: z.boolean().optional(),
        includeDuplicates: z.boolean().optional(),
        collapseFamilies: z.boolean().optional(),
        listingStatus: z.string().optional(),
        geoClass: z.string().optional(),
        staleProfile: z.boolean().optional(),
        pageSize: z.number().int().min(1).max(200).optional(),
        cursor: z.string().optional(),
        page: z.number().int().positive().optional(),
      },
      annotations: { readOnlyHint: true },
    },
    async (a) => {
      const r = await listPositions({
        status: a.status,
        verdict: a.verdict,
        q: a.q,
        company: a.company,
        minScore: a.minScore != null ? String(a.minScore) : undefined,
        sort: a.sort,
        includeArchived: a.includeArchived ? "true" : undefined,
        includeDuplicates: a.includeDuplicates ? "true" : undefined,
        collapseFamilies: a.collapseFamilies ? "true" : undefined,
        listingStatus: a.listingStatus,
        geoClass: a.geoClass,
        staleProfile: a.staleProfile ? "true" : undefined,
        pageSize: String(a.pageSize ?? 50),
        cursor: a.cursor,
        page: a.page ? String(a.page) : undefined,
      });
      return text({ items: r.items, total: r.total, nextCursor: r.nextCursor });
    },
  );

  server.registerTool(
    "get_position",
    { title: "Get position", description: "Full detail: company, current JD text, revisions, evaluations, materials.", inputSchema: { idOrSlug: z.string(), includeJd: z.boolean().optional() }, annotations: { readOnlyHint: true } },
    async (a) => {
      const p = await getPositionDetail(a.idOrSlug);
      if (!p) return text({ error: "not found" }, true);
      if (a.includeJd === false && p.jd) p.jd = { ...p.jd, descriptionText: `(${p.jd.descriptionText?.length ?? 0} chars, omitted)` };
      return text(p);
    },
  );

  server.registerTool(
    "scout_context",
    { title: "Scout context pack", description: "Everything needed to reason about one role: position, triage JSON, JD text, latest evaluation summary, profile brief.", inputSchema: { positionId: z.string().optional(), slug: z.string().optional(), q: z.string().optional() }, annotations: { readOnlyHint: true } },
    async (a) => {
      const p = await resolvePositionId(a.positionId || a.slug, a.q);
      if (!p) return text({ error: "not found" }, true);
      const profile = await getProfile();
      const ev = await getEvaluation(p.id, "evaluate");
      return text({ position: { ...p, jd: undefined }, jdText: await currentJdText(p.id), triage: p.triageJson, evaluation: ev ? { id: ev.id, model: ev.model, summary: ev.json, createdAt: ev.createdAt } : null, brief: triageBriefOf(profile) });
    },
  );

  server.registerTool(
    "update_position",
    { title: "Update position", description: "PATCH status, priority, notes, nextAction, resumeSurface, watchEnabled, appliedAt.", inputSchema: { idOrSlug: z.string(), status: z.string().optional(), priority: z.string().optional(), notes: z.string().optional(), nextAction: z.string().optional(), resumeSurface: z.string().optional(), watchEnabled: z.boolean().optional(), appliedAt: z.string().optional() } },
    async ({ idOrSlug, ...patch }, ctx) => {
      try {
        const p = await patchPosition(idOrSlug, patch, agentOf(ctx as ToolCtx));
        return p ? text(p) : text({ error: "not found" }, true);
      } catch (e) {
        return errText(e);
      }
    },
  );

  server.registerTool(
    "set_position_status",
    { title: "Set status", description: "Set pipeline status (triaged|review|materials|applied|screen|interview|offer|rejected|skip|archived). archived requires reason.", inputSchema: { idOrSlug: z.string(), status: z.string(), reason: z.string().optional() } },
    async (a, ctx) => {
      try {
        if (a.status === "archived") return text(await archivePosition(a.idOrSlug, a.reason || "mcp", agentOf(ctx as ToolCtx)));
        const p = await patchPosition(a.idOrSlug, { status: a.status }, agentOf(ctx as ToolCtx));
        return p ? text(p) : text({ error: "not found" }, true);
      } catch (e) {
        return errText(e);
      }
    },
  );

  server.registerTool(
    "set_match_override",
    { title: "Skip / unskip", description: "v1 compat: label=human_skip archives the position; label=match moves it to review.", inputSchema: { idOrSlug: z.string(), label: z.enum(["match", "human_skip"]) } },
    async (a, ctx) => {
      const actor = agentOf(ctx as ToolCtx);
      return text(a.label === "human_skip" ? await archivePosition(a.idOrSlug, "human_skip", actor) : await patchPosition(a.idOrSlug, { status: "review" }, actor));
    },
  );

  server.registerTool(
    "work_queue",
    { title: "Work queue", description: "Compact decision lanes with profile freshness. Use lane and page to read more; pagination reports totals and nextPage for each lane. Use get_position for full details.", inputSchema: WorkQueueInput, annotations: { readOnlyHint: true } },
    async (a) => text(await workQueue(a)),
  );

  server.registerTool(
    "list_eval_inbox",
    { title: "Eval inbox", description: "v1 compat: positions in review with no evaluation yet.", inputSchema: z.object({}), annotations: { readOnlyHint: true } },
    async () => {
      const rows = await listPositions({ status: "review,triaged", verdict: "pass", actionable: "true", collapseFamilies: "true", withoutEvaluation: "true", sort: "score_desc", pageSize: "50" });
      return text(rows.items);
    },
  );

  server.registerTool(
    "write_resume_eval",
    { title: "Write external eval", description: "Store an evaluation produced outside job-scout (career-ops) as an `evaluate` record and stamp careerOps metadata.", inputSchema: { idOrSlug: z.string(), score: z.number(), summary: z.string(), reasons: z.array(z.string()).optional(), markdown: z.string().optional(), source: z.string().optional() } },
    async (a, ctx) => {
      const p = await getPositionDetail(a.idOrSlug);
      if (!p) return text({ error: "not found" }, true);
      const db = await getDb();
      const { evaluations, id } = await import("@job-scout/db");
      const evId = id("ev");
      await db.insert(evaluations).values({ id: evId, positionId: p.id, companyId: p.companyId, kind: "evaluate", model: a.source || "career-ops", markdown: a.markdown || a.summary, json: { score: a.score, verdict: a.score >= 3.5 ? "apply" : a.score >= 3 ? "consider" : "skip", headline: a.summary, strengths: a.reasons || [], gaps: [], questionsToAsk: [], resumeAngle: "" } });
      await addEvent({ positionId: p.id, kind: "evaluate", title: `External eval ${a.score.toFixed(1)}`, body: a.summary, actor: agentOf(ctx as ToolCtx), metadata: { evaluationId: evId } });
      return text({ evaluationId: evId });
    },
  );

  server.registerTool(
    "list_discovery",
    { title: "Discovery feed", description: "lane=passed|filtered|marginal|all, hours, q, reason prefix (title_exclude, geo_block, stale...). Cursor pagination.", inputSchema: { lane: z.string().optional(), hours: z.number().optional(), q: z.string().optional(), reason: z.string().optional(), pageSize: z.number().int().min(1).max(200).optional(), cursor: z.string().optional() }, annotations: { readOnlyHint: true } },
    async (a) => {
      const r = await listDiscovery({ lane: a.lane, hours: a.hours != null ? String(a.hours) : undefined, q: a.q, reason: a.reason, pageSize: String(a.pageSize ?? 50), cursor: a.cursor });
      return text({ items: r.items, total: r.total, nextCursor: r.nextCursor });
    },
  );

  server.registerTool(
    "run_discovery_radar",
    { title: "Run discovery", description: "Enqueue board scans for due boards (all=true forces every enabled board).", inputSchema: { all: z.boolean().optional(), limit: z.number().int().min(1).max(500).optional() } },
    async (a) => text(await enqueueDueBoardScans({ all: a.all, limit: a.limit })),
  );

  server.registerTool(
    "promote_discovery",
    { title: "Promote discovery row", description: "Create a position from a discovery row (by id or url) and run triage.", inputSchema: { id: z.string().optional(), url: z.string().optional(), company: z.string().optional() } },
    async (a) => {
      try {
        let url = a.url;
        let company = a.company;
        if (a.id) {
          const db = await getDb();
          const { discoveryFeed } = await import("@job-scout/db");
          const row = (await db.select().from(discoveryFeed).where(eq(discoveryFeed.id, a.id)).limit(1))[0];
          if (!row?.url) return text({ error: "discovery row not found or has no url" }, true);
          url = row.url;
          company = company || row.company || undefined;
        }
        if (!url) return text({ error: "id or url required" }, true);
        const r = await intakeUrl(url, { companyName: company });
        return text({ position: r.position, created: r.created, triageJobId: r.triageJobId });
      } catch (e) {
        return errText(e);
      }
    },
  );

  server.registerTool(
    "list_companies",
    { title: "List companies", description: "Companies with position counts.", inputSchema: { q: z.string().optional(), withPositions: z.boolean().optional(), pageSize: z.number().int().min(1).max(200).optional() }, annotations: { readOnlyHint: true } },
    async (a) => text(await listCompanies({ q: a.q, withPositions: a.withPositions ? "true" : undefined, pageSize: String(a.pageSize ?? 50) })),
  );
  server.registerTool(
    "get_company",
    { title: "Get company", description: "Company detail with positions and latest research.", inputSchema: { idOrSlug: z.string() }, annotations: { readOnlyHint: true } },
    async (a) => {
      const r = await getCompany(a.idOrSlug);
      return r ? text(r) : text({ error: "not found" }, true);
    },
  );

  server.registerTool(
    "intake",
    { title: "Intake URL", description: "Create/refresh a position from a job URL; queues triage. Returns the position.", inputSchema: { url: z.string(), company: z.string().optional(), status: z.enum(["triaged", "review"]).optional() } },
    async (a) => {
      try {
        const r = await intakeUrl(a.url, { companyName: a.company, status: a.status });
        return text({ position: r.position, created: r.created, triageJobId: r.triageJobId });
      } catch (e) {
        return errText(e);
      }
    },
  );
  server.registerTool(
    "refresh_jd",
    { title: "Refresh JD", description: "Re-fetch the ATS page and record a revision if it changed.", inputSchema: { idOrSlug: z.string() } },
    async (a) => {
      try {
        return text(await refreshPosition(a.idOrSlug, "mcp"));
      } catch (e) {
        return errText(e);
      }
    },
  );

  server.registerTool(
    "get_profile",
    { title: "Get profile", description: "Operator profile (identity, resume, surfaces, brief).", inputSchema: z.object({}), annotations: { readOnlyHint: true } },
    async () => text(await getProfile()),
  );
  server.registerTool(
    "get_identity",
    { title: "Get identity", description: "identity + master resume + scout brief markdown only.", inputSchema: z.object({}), annotations: { readOnlyHint: true } },
    async () => {
      const p = await getProfile();
      return text({ identityMarkdown: p.identityMarkdown, masterResumeMarkdown: p.masterResumeMarkdown, masterCoverMarkdown: p.masterCoverMarkdown, scoutBrief: briefOf(p), resumeSurfaces: p.resumeSurfaces });
    },
  );

  server.registerTool(
    "list_activity",
    { title: "List activity", description: "Timeline events, optionally for one position.", inputSchema: { idOrSlug: z.string().optional(), limit: z.number().int().min(1).max(200).optional() }, annotations: { readOnlyHint: true } },
    async (a) => {
      if (a.idOrSlug) {
        const p = await getPositionDetail(a.idOrSlug);
        if (!p) return text({ error: "not found" }, true);
        return text(await listEvents(p.id, a.limit ?? 50));
      }
      const db = await getDb();
      return text(await db.select().from(timelineEvents).orderBy(desc(timelineEvents.occurredAt)).limit(a.limit ?? 50));
    },
  );
  server.registerTool(
    "log_activity",
    { title: "Log activity", description: "Append a timeline note to a position (or global when no position).", inputSchema: { idOrSlug: z.string().optional(), title: z.string(), body: z.string().optional(), kind: z.string().optional() } },
    async (a, ctx) => {
      const p = a.idOrSlug ? await getPositionDetail(a.idOrSlug) : null;
      if (a.idOrSlug && !p) return text({ error: "not found" }, true);
      return text({ id: await addEvent({ positionId: p?.id ?? null, kind: a.kind || "note", title: a.title, body: a.body, actor: agentOf(ctx as ToolCtx) }) });
    },
  );

  // ---- newer tools --------------------------------------------------------

  server.registerTool(
    "refresh_stale_triage",
    { title: "Refresh stale decision scores", description: "Preview up to 25 stale PASS decision candidates. Set dryRun=false to queue score-only refreshes using the current profile; preserves pipeline stages and sends no notifications.", inputSchema: RefreshStaleTriageInput.shape },
    async (a) => { try { return text(await refreshStaleTriage(a)); } catch (e) { return errText(e); } },
  );

  server.registerTool(
    "run_llm",
    { title: "Run LLM operation", description: "Run triage|evaluate|materials|jd_review|form_answers synchronously on a position (uses Settings > AI model). Returns the result.", inputSchema: { idOrSlug: z.string(), operation: z.enum(["triage", "evaluate", "materials", "jd_review", "form_answers", "listing_classify"]), force: z.boolean().optional() } },
    async (a) => {
      const p = await getPositionDetail(a.idOrSlug);
      if (!p) return text({ error: "not found" }, true);
      try {
        const r =
          a.operation === "triage"
            ? await runTriage(p.id, { force: a.force })
            : a.operation === "evaluate"
              ? await runEvaluate(p.id)
              : a.operation === "materials"
                ? await runMaterials(p.id)
                : a.operation === "form_answers"
                  ? await (await import("@job-scout/core")).runFormAnswers(p.id)
                  : a.operation === "listing_classify"
                    ? await runListingClassify(p.id)
                    : await runJdReview(p.id);
        return text(r);
      } catch (e) {
        return errText(e);
      }
    },
  );

  server.registerTool(
    "list_questions",
    { title: "List application questions", description: "ATS form prompts and drafted answers for a position.", inputSchema: { idOrSlug: z.string() }, annotations: { readOnlyHint: true } },
    async (a) => {
      const p = await getPositionDetail(a.idOrSlug);
      if (!p) return text({ error: "not found" }, true);
      const { listQuestions } = await import("@job-scout/core");
      return text(await listQuestions(p.id));
    },
  );
  server.registerTool(
    "update_question",
    { title: "Update application question", description: "Set answer and/or status (open|answered|skipped).", inputSchema: { id: z.string(), answer: z.string().optional(), status: z.string().optional() } },
    async (a) => {
      const { patchQuestion } = await import("@job-scout/core");
      const row = await patchQuestion(a.id, { answer: a.answer, status: a.status });
      return row ? text(row) : text({ error: "not found" }, true);
    },
  );

  server.registerTool(
    "get_evaluation",
    { title: "Get evaluation", description: "Latest evaluation markdown+json for a position. kind=evaluate|jd_review|company_research.", inputSchema: { idOrSlug: z.string(), kind: z.enum(["evaluate", "jd_review", "company_research"]).optional() }, annotations: { readOnlyHint: true } },
    async (a) => {
      const p = await getPositionDetail(a.idOrSlug);
      if (!p) return text({ error: "not found" }, true);
      const e = await getEvaluation(p.id, (a.kind || "evaluate") as EvaluationKind);
      return e ? text(e) : text({ error: "no evaluation yet" }, true);
    },
  );

  server.registerTool(
    "get_materials",
    { title: "Get current materials", description: "Current resume + cover markdown for a position.", inputSchema: { idOrSlug: z.string() }, annotations: { readOnlyHint: true } },
    async (a) => {
      const p = await getPositionDetail(a.idOrSlug);
      if (!p) return text({ error: "not found" }, true);
      const [resume, cover] = await Promise.all([getCurrentMaterial(p.id, "resume"), getCurrentMaterial(p.id, "cover")]);
      return text({ resume: resume ? { id: resume.id, version: resume.version, markdown: resume.bodyMarkdown, model: resume.model } : null, cover: cover ? { id: cover.id, version: cover.version, markdown: cover.bodyMarkdown, model: cover.model } : null });
    },
  );

  server.registerTool(
    "retry_failed_llm",
    {
      title: "Retry failed LLM jobs",
      description:
        "Re-enqueue the latest failed LLM ops in a time window. scope=failed_and_missing also triages open positions with no successful triage. Does not re-run successful evaluate/materials.",
      inputSchema: {
        hours: z.number().int().min(1).max(168).optional(),
        scope: z.enum(["failed", "failed_and_missing"]).optional(),
        operations: z.array(z.string()).optional(),
        limit: z.number().int().min(1).max(500).optional(),
      },
    },
    async (a) => text(await retryFailedLlm(a)),
  );

  server.registerTool(
    "list_changes",
    { title: "List changes since", description: "Positions and evaluations updated after an ISO timestamp — the primitive the career-ops sync uses.", inputSchema: { since: z.string(), limit: z.number().int().min(1).max(500).optional() }, annotations: { readOnlyHint: true } },
    async (a) => {
      const d = new Date(a.since);
      if (Number.isNaN(d.getTime())) return text({ error: "since must be ISO" }, true);
      return text(await listChangesSince(d, a.limit ?? 200));
    },
  );

  server.registerTool(
    "upsert_career_ops_stamp",
    { title: "Stamp career-ops link", description: "Store the career-ops tracker id/score/status/report path on a position (metadata.careerOps).", inputSchema: { idOrSlug: z.string(), trackerId: z.string().optional(), score: z.number().optional(), status: z.string().optional(), reportPath: z.string().optional(), pdfPath: z.string().optional(), jdPath: z.string().optional() } },
    async ({ idOrSlug, ...stamp }) => {
      const r = await stampCareerOps(idOrSlug, stamp);
      return r ? text(r) : text({ error: "not found" }, true);
    },
  );

  server.registerTool(
    "reconcile_career_ops",
    { title: "Reconcile career-ops export", description: "Bulk URL-first reconciliation. Dry run by default; exact title fallback only without URL and when unique. Report existence is supplied by the client that owns the files; otherwise unverified.", inputSchema: ReconcileInput },
    async (a) => text(await reconcileCareerOps(a)),
  );

  server.registerTool(
    "list_career_ops_stamps",
    { title: "List career-ops stamps", description: "All positions that carry a careerOps stamp (id, slug, url, stamp).", inputSchema: z.object({}), annotations: { readOnlyHint: true } },
    async () => {
      const db = await getDb();
      const rows = await db
        .select({ id: positions.id, slug: positions.slug, title: positions.title, status: positions.status, primaryUrl: positions.primaryUrl, company: companies.name, careerOps: sql<Record<string, unknown>>`${positions.metadata}->'careerOps'` })
        .from(positions)
        .innerJoin(companies, eq(positions.companyId, companies.id))
        .where(and(sql`${positions.metadata} ? 'careerOps'`))
        .limit(1000);
      return text(rows);
    },
  );

  server.registerTool(
    "create_position_from_career_ops",
    { title: "Create from career-ops", description: "Create a position for a tracker row that job-scout does not know. Fetches the URL when reachable; falls back to a manual record.", inputSchema: { url: z.string(), company: z.string(), role: z.string(), score: z.number().optional(), status: z.string().optional(), reportPath: z.string().optional(), trackerId: z.string().optional() } },
    async (a) => {
      try {
        let position;
        try {
          position = (await intakeUrl(a.url, { companyName: a.company, status: "review" })).position;
        } catch {
          const r = await upsertFromJob({ provider: "other", title: a.role, company: a.company, url: a.url, listingStatus: "unknown" }, { source: "career-ops", companyName: a.company, status: "review" });
          position = r.position;
        }
        if (!position) throw new Error("position missing");
        const mapped = mapCareerOpsStatus(a.status);
        const patch: Record<string, unknown> = {};
        if (mapped && mapped !== position.status) patch.status = mapped;
        // Workday/landing pages often yield no title from the fetch: the tracker role is the truth then.
        if (!position.title?.trim()) patch.title = a.role;
        if (Object.keys(patch).length) await patchPosition(position.id, patch, "career-ops");
        const stamp = await stampCareerOps(position.id, { trackerId: a.trackerId, score: a.score, status: a.status, reportPath: a.reportPath });
        return text({ position: await getPositionDetail(position.id), stamp });
      } catch (e) {
        return errText(e);
      }
    },
  );

  server.registerTool(
    "list_processes",
    {
      title: "List live processes",
      description: "Positions in applied/screen/interview/offer with round timeline, nextAction, last/next round. The process desk.",
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    async () => {
      const { listProcesses } = await import("@job-scout/core");
      return text(await listProcesses());
    },
  );

  server.registerTool(
    "list_all_interviews",
    {
      title: "List all interview rounds",
      description: "Desk of every round across positions. Slim (no transcript bodies). lane=upcoming|completed|needs_brief|all. Use get_interview for the corpus.",
      inputSchema: { lane: z.string().optional(), q: z.string().optional(), stage: z.string().optional() },
      annotations: { readOnlyHint: true },
    },
    async (a) => {
      const { listAllInterviews } = await import("@job-scout/core");
      return text(await listAllInterviews({ lane: a.lane, q: a.q, stage: a.stage }));
    },
  );

  server.registerTool(
    "list_interviews",
    {
      title: "List interviews",
      description: "Interview rounds for a position (screen, hiring manager, technical). Slim: metadata + char counts, not transcript bodies. Use get_interview for the corpus.",
      inputSchema: { idOrSlug: z.string() },
      annotations: { readOnlyHint: true },
    },
    async (a) => {
      const p = await getPositionDetail(a.idOrSlug);
      if (!p) return text({ error: "not found" }, true);
      const { listInterviews } = await import("@job-scout/core");
      return text(await listInterviews(p.id));
    },
  );

  server.registerTool(
    "get_interview",
    {
      title: "Get one interview round",
      description: "Full round: notes, review, transcript, AI brief vs JD/company pack.",
      inputSchema: { idOrSlug: z.string(), interviewId: z.string() },
      annotations: { readOnlyHint: true },
    },
    async (a) => {
      const p = await getPositionDetail(a.idOrSlug);
      if (!p) return text({ error: "not found" }, true);
      const { getInterview } = await import("@job-scout/core");
      const row = await getInterview(p.id, a.interviewId);
      return row ? text(row) : text({ error: "not found" }, true);
    },
  );

  server.registerTool(
    "upsert_interview",
    {
      title: "Create or update an interview round",
      description:
        "Store a screen/interview: stage, interviewer, outcome, notes, review, transcript. If transcriptMarkdown is set, queues an AI brief against the JD and company pack unless skipBrief=true. Pass id to patch an existing round.",
      inputSchema: {
        idOrSlug: z.string(),
        id: z.string().optional(),
        stage: z.string().optional(),
        title: z.string().optional(),
        interviewerName: z.string().optional(),
        interviewerRole: z.string().optional(),
        scheduledAt: z.string().optional(),
        occurredAt: z.string().optional(),
        durationSeconds: z.number().optional(),
        status: z.string().optional(),
        outcome: z.string().optional(),
        notes: z.string().optional(),
        notesMarkdown: z.string().optional(),
        reviewMarkdown: z.string().optional(),
        transcriptMarkdown: z.string().optional(),
        transcriptSource: z.string().optional(),
        sourcePath: z.string().optional(),
        skipBrief: z.boolean().optional(),
      },
    },
    async (a) => {
      const p = await getPositionDetail(a.idOrSlug);
      if (!p) return text({ error: "not found" }, true);
      const { addInterview, patchInterview } = await import("@job-scout/core");
      const input = {
        stage: a.stage,
        title: a.title,
        interviewerName: a.interviewerName,
        interviewerRole: a.interviewerRole,
        scheduledAt: a.scheduledAt,
        occurredAt: a.occurredAt,
        durationSeconds: a.durationSeconds,
        status: a.status,
        outcome: a.outcome,
        notes: a.notes,
        notesMarkdown: a.notesMarkdown,
        reviewMarkdown: a.reviewMarkdown,
        transcriptMarkdown: a.transcriptMarkdown,
        transcriptSource: a.transcriptSource,
        sourcePath: a.sourcePath,
        skipBrief: a.skipBrief,
      };
      try {
        if (a.id) {
          const row = await patchInterview(p.id, a.id, input);
          return row ? text(row) : text({ error: "not found" }, true);
        }
        return text(await addInterview(p.id, input));
      } catch (e) {
        return errText(e);
      }
    },
  );

  server.registerTool(
    "brief_interview",
    {
      title: "AI-brief an interview",
      description:
        "Run (or queue) the interview_brief model: reasoned view of this round vs the JD, company pack, and candidate identity. Default queues a worker job; sync=true runs in-process.",
      inputSchema: { idOrSlug: z.string(), interviewId: z.string(), sync: z.boolean().optional() },
    },
    async (a) => {
      const p = await getPositionDetail(a.idOrSlug);
      if (!p) return text({ error: "not found" }, true);
      const { enqueueInterviewBrief, runInterviewBrief } = await import("@job-scout/core");
      try {
        if (a.sync) return text(await runInterviewBrief(p.id, a.interviewId));
        const q = await enqueueInterviewBrief(p.id, a.interviewId);
        return q ? text({ jobId: q.id, deduped: q.deduped }) : text({ error: "not found" }, true);
      } catch (e) {
        return errText(e);
      }
    },
  );

  server.registerTool("jev_status", { title: "Jev settings and usage", description: "Read decision settings, credential availability and today's usage. Does not call a model.", inputSchema: {}, annotations: { readOnlyHint: true } }, async () => text(await jevStatus()));
  server.registerTool("jev_history", { title: "Jev decision history", description: "Read recent decision summaries and feedback for a position. Does not call a model.", inputSchema: { positionId: z.string().optional(), limit: z.number().int().min(1).max(20).default(5) }, annotations: { readOnlyHint: true } }, async a => text((await recentDecisions(a.positionId)).slice(0, a.limit).map(({ result, ...run }) => ({ ...run, usage: result ? { inputTokens: result.inputTokens, cost: result.cost, latencyMs: result.latencyMs } : null }))));
  server.registerTool("jev_preview", { title: "Preview a Jev decision", description: "Run a job-fit, ranking, or draft check using saved Jev settings. Sends job/profile evidence and, for draft checks, the draft to OpenRouter. Consumes the Jev request budget and records a result; leaves positions and approvals unchanged.", inputSchema: { positionId: z.string(), recipe: z.enum(["triage", "ranking", "evaluation_check", "materials_check"]), fresh: z.boolean().default(false) }, annotations: { readOnlyHint: false, destructiveHint: false } }, async a => {
    try { const run = await previewDecision(a.recipe, a.positionId, a.fresh); return text(run, run.status !== "ok"); }
    catch { return text({ error: "Jev could not run this preview. Check the saved settings, request budget and available source material." }, true); }
  });

  server.registerTool(
    "screen_recruiter_threat",
    {
      title: "Screen recruiter threat",
      description:
        "Screen an inbound recruiter, email, domain, or message text against confirmed IOC threat blacklists, domain registration age (RDAP), disposable email detectors, and 'Contagious Interview' social engineering patterns.",
      inputSchema: {
        domainOrEmail: z.string(),
        senderName: z.string().optional(),
        messageText: z.string().optional(),
      },
      annotations: { readOnlyHint: true },
    },
    async (a) => {
      const { evaluateRecruiterThreat } = await import("@job-scout/core");
      try {
        const report = await evaluateRecruiterThreat({
          domainOrEmail: a.domainOrEmail,
          senderName: a.senderName,
          messageText: a.messageText,
        });
        return text(report);
      } catch (e) {
        return errText(e);
      }
    },
  );

  server.registerTool(
    "list_linkedin_dms",
    {
      title: "List LinkedIn DMs",
      description:
        "Inspect active LinkedIn messaging threads and recent messages from the local desktop session, with automatic threat screening on inbound senders.",
      inputSchema: {
        autoScreenThreats: z.boolean().optional(),
      },
      annotations: { readOnlyHint: true },
    },
    async (a) => {
      const { readLinkedInMessages } = await import("@job-scout/core");
      try {
        const feed = await readLinkedInMessages({ autoScreenThreats: a.autoScreenThreats });
        return text(feed);
      } catch (e) {
        return errText(e);
      }
    },
  );

  return server;
}

/** career-ops tracker statuses -> job-scout statuses */
export function mapCareerOpsStatus(s?: string | null): string | null {
  if (!s) return null;
  const k = s.toLowerCase().trim();
  const table: Record<string, string> = {
    "to apply": "review",
    "to-apply": "review",
    evaluated: "review",
    applied: "applied",
    screen: "screen",
    screening: "screen",
    interview: "interview",
    interviewing: "interview",
    offer: "offer",
    rejected: "rejected",
    declined: "rejected",
    ghosted: "rejected",
    skip: "skip",
    skipped: "skip",
    withdrawn: "skip",
  };
  return table[k] ?? null;
}
