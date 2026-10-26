import { v } from "convex/values";
import { internalMutation, internalQuery } from "./_generated/server";
import { internal } from "./_generated/api";
import { fail, requireFileName, requireHexSha256, requirePublicId } from "./lib/security";

const contextValidator = v.union(v.null(), v.object({
  sessionId: v.id("uploadSessions"), submissionId: v.union(v.id("submissions"), v.null()),
  submissionPublicId: v.union(v.string(), v.null()), storageId: v.id("_storage"),
  declaredSize: v.number(), declaredSha256: v.union(v.string(), v.null()),
}));

export const getFinalizationContext = internalQuery({
  args: {
    sessionPublicId: v.string(), tokenHash: v.string(), idempotencyKey: v.string(),
    declaredSha256: v.string(),
  },
  returns: contextValidator,
  handler: async (ctx, args) => {
    const session = await ctx.db.query("uploadSessions").withIndex("by_public_id", (q) =>
      q.eq("publicId", requirePublicId(args.sessionPublicId, "Upload session"))).unique();
    if (session === null || session.secretHash !== args.tokenHash) return null;
    const prior = await ctx.db.query("submissions").withIndex("by_upload_session_id_and_idempotency_key", (q) =>
      q.eq("uploadSessionId", session._id).eq("idempotencyKey", args.idempotencyKey)).unique();
    if (prior !== null) {
      return { sessionId: session._id, submissionId: prior._id, submissionPublicId: prior.publicId,
        storageId: prior.storageId, declaredSize: prior.declaredSize, declaredSha256: prior.declaredSha256 };
    }
    if (session.state !== "open" || session.expiresAtMs <= Date.now() ||
        session.pendingStorageId === undefined || session.pendingDeclaredSize === undefined) return null;
    return { sessionId: session._id, submissionId: null, submissionPublicId: null,
      storageId: session.pendingStorageId, declaredSize: session.pendingDeclaredSize,
      declaredSha256: requireHexSha256(args.declaredSha256) };
  },
});

export const commitFinalization = internalMutation({
  args: {
    sessionId: v.id("uploadSessions"), storageId: v.id("_storage"), idempotencyKey: v.string(),
    originalFileName: v.string(), declaredSize: v.number(), declaredSha256: v.string(),
    verifiedSize: v.number(), verifiedSha256: v.string(), submissionPublicId: v.string(),
  },
  returns: v.object({ submissionPublicId: v.string(), state: v.literal("uploaded") }),
  handler: async (ctx, args) => {
    const prior = await ctx.db.query("submissions").withIndex("by_upload_session_id_and_idempotency_key", (q) =>
      q.eq("uploadSessionId", args.sessionId).eq("idempotencyKey", args.idempotencyKey)).unique();
    if (prior !== null) return { submissionPublicId: prior.publicId, state: "uploaded" as const };
    const session = await ctx.db.get("uploadSessions", args.sessionId);
    if (session === null || session.state !== "open" || session.pendingStorageId !== args.storageId ||
        session.expiresAtMs <= Date.now()) fail("UPLOAD_FINALIZE_RACE", "Upload session changed before finalization.");
    const now = Date.now();
    const submissionId = await ctx.db.insert("submissions", {
      publicId: requirePublicId(args.submissionPublicId, "Submission"), uploadSessionId: args.sessionId,
      storageId: args.storageId, state: "uploaded", originalFileName: requireFileName(args.originalFileName),
      declaredSize: args.declaredSize, declaredSha256: requireHexSha256(args.declaredSha256),
      verifiedSize: args.verifiedSize, verifiedSha256: requireHexSha256(args.verifiedSha256),
      idempotencyKey: requirePublicId(args.idempotencyKey, "Idempotency key"),
      createdAtMs: now, updatedAtMs: now,
    });
    const jobId = await ctx.db.insert("analysisJobs", {
      submissionId, state: "queued", generation: 1, stage: "queued",
      analyzerVersion: "0.1.0-service", ruleSetVersion: "2026-10-25.1-service", attempts: 0,
      createdAtMs: now, updatedAtMs: now,
    });
    await ctx.db.patch("uploadSessions", session._id, {
      state: "finalized", pendingStorageId: undefined, pendingDeclaredSize: undefined,
    });
    await ctx.scheduler.runAfter(0, internal.analyzerWorker.run, { jobId });
    return { submissionPublicId: args.submissionPublicId, state: "uploaded" as const };
  },
});

export const discardPending = internalMutation({
  args: { sessionId: v.id("uploadSessions"), storageId: v.id("_storage"), code: v.string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    const session = await ctx.db.get("uploadSessions", args.sessionId);
    if (session?.pendingStorageId === args.storageId) {
      await ctx.storage.delete(args.storageId);
      await ctx.db.patch("uploadSessions", session._id, {
        pendingStorageId: undefined, pendingDeclaredSize: undefined,
      });
    }
    void args.code;
    return null;
  },
});

export const expireSessions = internalMutation({
  args: {},
  returns: v.object({ expired: v.number(), deletedBlobs: v.number() }),
  handler: async (ctx) => {
    const nowMs = Date.now();
    const sessions = await ctx.db.query("uploadSessions").withIndex("by_state_and_expires_at_ms", (q) =>
      q.eq("state", "open").lte("expiresAtMs", nowMs)).take(50);
    let deletedBlobs = 0;
    for (const session of sessions) {
      if (session.pendingStorageId !== undefined) {
        await ctx.storage.delete(session.pendingStorageId);
        deletedBlobs += 1;
      }
      await ctx.db.patch("uploadSessions", session._id, {
        state: "expired", pendingStorageId: undefined, pendingDeclaredSize: undefined,
      });
    }
    return { expired: sessions.length, deletedBlobs };
  },
});
