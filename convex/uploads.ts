import { v } from "convex/values";
import { mutation, query, type MutationCtx, type QueryCtx } from "./_generated/server";
import {
  MAX_BUNDLE_BYTES,
  MAX_SESSION_BYTES,
  MAX_SESSION_UPLOADS,
  SESSION_TTL_MS,
  fail,
  newSecret,
  requirePublicId,
  sha256Hex,
} from "./lib/security";

const stateValidator = v.union(
  v.literal("uploaded"), v.literal("analyzing"), v.literal("accepted"),
  v.literal("rejected"), v.literal("inconclusive"), v.literal("published"),
  v.literal("withdrawn"), v.literal("failed"),
);

async function authorizedSession(ctx: MutationCtx | QueryCtx, publicId: string, token: string) {
  requirePublicId(publicId, "Upload session");
  const session = await ctx.db.query("uploadSessions").withIndex("by_public_id", (q) => q.eq("publicId", publicId)).unique();
  if (session === null || session.secretHash !== await sha256Hex(token)) {
    fail("UPLOAD_SESSION_DENIED", "Upload session credentials are invalid.");
  }
  return session;
}

export const createSession = mutation({
  args: {},
  returns: v.object({ publicId: v.string(), token: v.string(), expiresAtMs: v.number() }),
  handler: async (ctx) => {
    const now = Date.now();
    const publicId = newSecret();
    const token = newSecret();
    const expiresAtMs = now + SESSION_TTL_MS;
    await ctx.db.insert("uploadSessions", {
      publicId,
      secretHash: await sha256Hex(token),
      state: "open",
      createdAtMs: now,
      expiresAtMs,
      uploadCount: 0,
      byteCount: 0,
    });
    return { publicId, token, expiresAtMs };
  },
});

export const generateUploadUrl = mutation({
  args: { sessionPublicId: v.string(), token: v.string(), declaredSize: v.number() },
  returns: v.string(),
  handler: async (ctx, args) => {
    const session = await authorizedSession(ctx, args.sessionPublicId, args.token);
    if (session.state !== "open" || session.expiresAtMs <= Date.now()) {
      fail("UPLOAD_SESSION_EXPIRED", "Create a new upload session and retry.");
    }
    if (!Number.isSafeInteger(args.declaredSize) || args.declaredSize < 1 || args.declaredSize > MAX_BUNDLE_BYTES) {
      fail("UPLOAD_SIZE_LIMIT", `Bundles must be between 1 and ${MAX_BUNDLE_BYTES} bytes.`);
    }
    if (session.uploadCount >= MAX_SESSION_UPLOADS ||
        session.byteCount + args.declaredSize > MAX_SESSION_BYTES || session.pendingStorageId !== undefined) {
      fail("UPLOAD_QUOTA", "This session has reached its upload or outstanding-blob quota.");
    }
    return await ctx.storage.generateUploadUrl();
  },
});

export const claimUpload = mutation({
  args: {
    sessionPublicId: v.string(), token: v.string(), storageId: v.id("_storage"),
    declaredSize: v.number(),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const session = await authorizedSession(ctx, args.sessionPublicId, args.token);
    if (session.state !== "open" || session.expiresAtMs <= Date.now()) {
      fail("UPLOAD_SESSION_EXPIRED", "The uploaded blob was not claimed before session expiry.");
    }
    if (session.pendingStorageId !== undefined) {
      if (session.pendingStorageId === args.storageId && session.pendingDeclaredSize === args.declaredSize) return null;
      fail("UPLOAD_ALREADY_CLAIMED", "This session already owns a different pending blob.");
    }
    const metadata = await ctx.db.system.get("_storage", args.storageId);
    if (metadata === null) fail("UPLOAD_BLOB_MISSING", "The uploaded blob does not exist.");
    if (!Number.isSafeInteger(args.declaredSize) || args.declaredSize < 1 ||
        args.declaredSize > MAX_BUNDLE_BYTES || metadata.size !== args.declaredSize) {
      await ctx.storage.delete(args.storageId);
      fail("UPLOAD_SIZE_MISMATCH", "Uploaded bytes do not match the declared size.");
    }
    if (session.uploadCount >= MAX_SESSION_UPLOADS || session.byteCount + metadata.size > MAX_SESSION_BYTES) {
      await ctx.storage.delete(args.storageId);
      fail("UPLOAD_QUOTA", "This upload exceeds the session quota.");
    }
    await ctx.db.patch("uploadSessions", session._id, {
      pendingStorageId: args.storageId,
      pendingDeclaredSize: args.declaredSize,
      uploadCount: session.uploadCount + 1,
      byteCount: session.byteCount + metadata.size,
    });
    return null;
  },
});

export const status = query({
  args: { submissionPublicId: v.string(), sessionPublicId: v.string(), token: v.string() },
  returns: v.object({
    publicId: v.string(), state: stateValidator, stage: v.union(v.string(), v.null()),
    updatedAtMs: v.number(), terminalCode: v.union(v.string(), v.null()),
    terminalMessage: v.union(v.string(), v.null()), reportDigest: v.union(v.string(), v.null()),
    verdict: v.union(v.literal("accepted"), v.literal("rejected"), v.literal("inconclusive"), v.null()),
  }),
  handler: async (ctx, args) => {
    const session = await authorizedSession(ctx, args.sessionPublicId, args.token);
    const submission = await ctx.db.query("submissions").withIndex("by_public_id", (q) =>
      q.eq("publicId", requirePublicId(args.submissionPublicId, "Submission"))).unique();
    if (submission === null || submission.uploadSessionId !== session._id) {
      fail("UPLOAD_SUBMISSION_NOT_FOUND", "No submission belongs to this upload session.");
    }
    const job = await ctx.db.query("analysisJobs").withIndex("by_submission_id_and_generation", (q) =>
      q.eq("submissionId", submission._id)).order("desc").first();
    const report = await ctx.db.query("analysisReports").withIndex("by_submission_id", (q) =>
      q.eq("submissionId", submission._id)).unique();
    return {
      publicId: submission.publicId,
      state: submission.state,
      stage: job?.stage ?? null,
      updatedAtMs: submission.updatedAtMs,
      terminalCode: submission.terminalCode ?? null,
      terminalMessage: submission.terminalMessage ?? null,
      reportDigest: report?.reportDigest ?? null,
      verdict: report?.verdict ?? null,
    };
  },
});

const findingValidator = v.object({
  ruleId: v.string(), severity: v.union(v.literal("info"), v.literal("low"), v.literal("medium"), v.literal("high"), v.literal("critical")),
  confidence: v.union(v.literal("verified"), v.literal("high"), v.literal("medium"), v.literal("low")),
  publicationEffect: v.union(v.literal("none"), v.literal("review"), v.literal("block"), v.literal("inconclusive")),
  file: v.string(), fileOffset: v.union(v.number(), v.null()), virtualAddress: v.union(v.number(), v.null()),
  evidenceHash: v.string(), explanation: v.string(), remediation: v.string(),
});

export const report = query({
  args: { submissionPublicId: v.string(), sessionPublicId: v.string(), token: v.string() },
  returns: v.union(v.null(), v.object({
    verdict: v.union(v.literal("accepted"), v.literal("rejected"), v.literal("inconclusive")),
    publicationAllowed: v.boolean(), analyzerVersion: v.string(), ruleSetVersion: v.string(),
    reportDigest: v.string(), bundleSha256: v.string(), findings: v.array(findingValidator),
    notice: v.string(),
  })),
  handler: async (ctx, args) => {
    const session = await authorizedSession(ctx, args.sessionPublicId, args.token);
    const submission = await ctx.db.query("submissions").withIndex("by_public_id", (q) =>
      q.eq("publicId", requirePublicId(args.submissionPublicId, "Submission"))).unique();
    if (submission === null || submission.uploadSessionId !== session._id) {
      fail("UPLOAD_SUBMISSION_NOT_FOUND", "No submission belongs to this upload session.");
    }
    const report = await ctx.db.query("analysisReports").withIndex("by_submission_id", (q) =>
      q.eq("submissionId", submission._id)).unique();
    if (report === null) return null;
    const findings = await ctx.db.query("analysisFindings").withIndex("by_report_id_and_ordinal", (q) =>
      q.eq("reportId", report._id)).take(256);
    return {
      verdict: report.verdict, publicationAllowed: report.publicationAllowed,
      analyzerVersion: report.analyzerVersion, ruleSetVersion: report.ruleSetVersion,
      reportDigest: report.reportDigest, bundleSha256: report.bundleSha256,
      findings: findings.map((item) => ({
        ruleId: item.ruleId, severity: item.severity, confidence: item.confidence,
        publicationEffect: item.publicationEffect, file: item.file,
        fileOffset: item.fileOffset ?? null, virtualAddress: item.virtualAddress ?? null,
        evidenceHash: item.evidenceHash, explanation: item.explanation, remediation: item.remediation,
      })),
      notice: "Static analysis is not a sandbox or proof of safety; accepted EFI code remains trusted native firmware code.",
    };
  },
});
