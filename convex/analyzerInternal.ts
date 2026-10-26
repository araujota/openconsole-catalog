import { v } from "convex/values";
import { internalMutation, internalQuery } from "./_generated/server";
import { sha256Hex } from "./lib/security";

const finding = v.object({
  ruleId: v.string(), severity: v.union(v.literal("info"), v.literal("low"), v.literal("medium"), v.literal("high"), v.literal("critical")),
  confidence: v.union(v.literal("verified"), v.literal("high"), v.literal("medium"), v.literal("low")),
  publicationEffect: v.union(v.literal("none"), v.literal("review"), v.literal("block"), v.literal("inconclusive")),
  file: v.string(), fileOffset: v.union(v.number(), v.null()), virtualAddress: v.union(v.number(), v.null()),
  evidenceHash: v.string(), explanation: v.string(), remediation: v.string(),
});

export const acquire = internalMutation({
  args: { jobId: v.id("analysisJobs"), leaseToken: v.string() },
  returns: v.union(v.null(), v.object({
    generation: v.number(), storageId: v.id("_storage"), submissionId: v.id("submissions"),
  })),
  handler: async (ctx, args) => {
    const job = await ctx.db.get("analysisJobs", args.jobId);
    const now = Date.now();
    if (job === null || job.state === "complete" || job.state === "failed" ||
        (job.state === "leased" && (job.leaseExpiresAtMs ?? 0) > now)) return null;
    const submission = await ctx.db.get("submissions", job.submissionId);
    if (submission === null || !["uploaded", "analyzing"].includes(submission.state)) return null;
    await ctx.db.patch("analysisJobs", job._id, {
      state: "leased", stage: "analyzing", attempts: job.attempts + 1,
      leaseTokenHash: await sha256Hex(args.leaseToken), leaseExpiresAtMs: now + 5 * 60 * 1000, updatedAtMs: now,
    });
    await ctx.db.patch("submissions", submission._id, { state: "analyzing", updatedAtMs: now });
    return { generation: job.generation, storageId: submission.storageId, submissionId: submission._id };
  },
});

export const trustedKey = internalQuery({
  args: { keyId: v.string() },
  returns: v.union(v.null(), v.object({ publicKeyBase64: v.string() })),
  handler: async (ctx, args) => {
    const key = await ctx.db.query("publisherKeys").withIndex("by_key_id", (q) => q.eq("keyId", args.keyId)).unique();
    return key?.status === "trusted" ? { publicKeyBase64: key.publicKeyBase64 } : null;
  },
});

export const complete = internalMutation({
  args: {
    jobId: v.id("analysisJobs"), generation: v.number(), leaseTokenHash: v.string(),
    report: v.object({
      verdict: v.union(v.literal("accepted"), v.literal("rejected"), v.literal("inconclusive")),
      publicationAllowed: v.boolean(), bundleId: v.union(v.string(), v.null()), bundleSha256: v.string(),
      publisherKeyId: v.union(v.string(), v.null()), gameId: v.union(v.string(), v.null()),
      gameVersion: v.union(v.string(), v.null()), title: v.optional(v.string()), developer: v.optional(v.string()),
      description: v.optional(v.string()), compatibility: v.optional(v.array(v.string())),
      analyzerVersion: v.string(), ruleSetVersion: v.string(), reportDigest: v.string(),
      normalizedReport: v.string(), findings: v.array(finding),
    }),
  },
  returns: v.boolean(),
  handler: async (ctx, args) => {
    const job = await ctx.db.get("analysisJobs", args.jobId);
    if (job === null || job.state !== "leased" || job.generation !== args.generation || job.leaseTokenHash !== args.leaseTokenHash) return false;
    if (args.report.normalizedReport.length > 512 * 1024 || args.report.findings.length > 256) throw new Error("ANALYSIS_REPORT_LIMIT");
    const prior = await ctx.db.query("analysisReports").withIndex("by_submission_id", (q) => q.eq("submissionId", job.submissionId)).unique();
    if (prior !== null) return prior.reportDigest === args.report.reportDigest;
    const reportId = await ctx.db.insert("analysisReports", {
      submissionId: job.submissionId, jobId: job._id, verdict: args.report.verdict,
      publicationAllowed: args.report.publicationAllowed, bundleId: args.report.bundleId ?? undefined,
      bundleSha256: args.report.bundleSha256, publisherKeyId: args.report.publisherKeyId ?? undefined,
      gameId: args.report.gameId ?? undefined, gameVersion: args.report.gameVersion ?? undefined,
      title: args.report.title, developer: args.report.developer, description: args.report.description,
      compatibility: args.report.compatibility, analyzerVersion: args.report.analyzerVersion,
      ruleSetVersion: args.report.ruleSetVersion, reportDigest: args.report.reportDigest,
      findingCount: args.report.findings.length, normalizedReport: args.report.normalizedReport,
      createdAtMs: Date.now(),
    });
    for (let ordinal = 0; ordinal < args.report.findings.length; ordinal++) {
      const item = args.report.findings[ordinal];
      await ctx.db.insert("analysisFindings", {
        reportId, ordinal, ruleId: item.ruleId, severity: item.severity, confidence: item.confidence,
        publicationEffect: item.publicationEffect, file: item.file,
        fileOffset: item.fileOffset ?? undefined, virtualAddress: item.virtualAddress ?? undefined,
        evidenceHash: item.evidenceHash, explanation: item.explanation, remediation: item.remediation,
      });
    }
    const now = Date.now();
    await ctx.db.patch("analysisJobs", job._id, {
      state: "complete", stage: "complete", leaseTokenHash: undefined, leaseExpiresAtMs: undefined, updatedAtMs: now,
    });
    await ctx.db.patch("submissions", job.submissionId, {
      state: args.report.verdict, updatedAtMs: now,
      terminalCode: args.report.verdict === "accepted" ? undefined : `ANALYSIS_${args.report.verdict.toUpperCase()}`,
      terminalMessage: args.report.verdict === "accepted" ? undefined : "See the normalized analyzer report for findings.",
    });
    return true;
  },
});

export const fail = internalMutation({
  args: { jobId: v.id("analysisJobs"), generation: v.number(), leaseTokenHash: v.string(), message: v.string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    const job = await ctx.db.get("analysisJobs", args.jobId);
    if (job?.state !== "leased" || job.generation !== args.generation || job.leaseTokenHash !== args.leaseTokenHash) return null;
    const now = Date.now();
    await ctx.db.patch("analysisJobs", job._id, { state: "failed", stage: "failed", failureClass: "ANALYZER_INTERNAL", updatedAtMs: now });
    await ctx.db.patch("submissions", job.submissionId, { state: "failed", terminalCode: "ANALYZER_INTERNAL", terminalMessage: args.message.slice(0, 240), updatedAtMs: now });
    return null;
  },
});
