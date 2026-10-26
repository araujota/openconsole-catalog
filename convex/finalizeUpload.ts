import { ConvexError, v } from "convex/values";
import { action } from "./_generated/server";
import { internal } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import { MAX_BUNDLE_BYTES, newSecret, requireFileName, requireHexSha256, requirePublicId, sha256Hex } from "./lib/security";

export const finalize = action({
  args: {
    sessionPublicId: v.string(), token: v.string(), idempotencyKey: v.string(),
    originalFileName: v.string(), declaredSha256: v.string(),
  },
  returns: v.object({ submissionPublicId: v.string(), state: v.literal("uploaded") }),
  handler: async (ctx, args): Promise<{ submissionPublicId: string; state: "uploaded" }> => {
    const sessionPublicId = requirePublicId(args.sessionPublicId, "Upload session");
    const idempotencyKey = requirePublicId(args.idempotencyKey, "Idempotency key");
    const originalFileName = requireFileName(args.originalFileName);
    const declaredSha256 = requireHexSha256(args.declaredSha256);
    const context: null | {
      sessionId: Id<"uploadSessions">;
      submissionId: Id<"submissions"> | null;
      submissionPublicId: string | null;
      storageId: Id<"_storage">;
      declaredSize: number;
      declaredSha256: string | null;
    } = await ctx.runQuery(internal.uploadInternal.getFinalizationContext, {
      sessionPublicId, tokenHash: await sha256Hex(args.token), idempotencyKey, declaredSha256,
    });
    if (context === null) {
      throw new ConvexError({ code: "UPLOAD_FINALIZE_DENIED", message: "Session expired, credentials failed, or no blob was claimed." });
    }
    if (context.submissionId !== null && context.submissionPublicId !== null) {
      if (context.declaredSha256 !== declaredSha256) {
        throw new ConvexError({ code: "UPLOAD_IDEMPOTENCY_CONFLICT", message: "That idempotency key was already used with different bytes." });
      }
      return { submissionPublicId: context.submissionPublicId, state: "uploaded" as const };
    }
    const blob = await ctx.storage.get(context.storageId);
    if (blob === null || blob.size < 1 || blob.size > MAX_BUNDLE_BYTES || blob.size !== context.declaredSize) {
      await ctx.runMutation(internal.uploadInternal.discardPending, {
        sessionId: context.sessionId, storageId: context.storageId, code: "UPLOAD_SIZE_MISMATCH",
      });
      throw new ConvexError({ code: "UPLOAD_SIZE_MISMATCH", message: "Persisted blob size does not match the claimed upload." });
    }
    const verifiedSha256 = await sha256Hex(await blob.arrayBuffer());
    if (verifiedSha256 !== declaredSha256) {
      await ctx.runMutation(internal.uploadInternal.discardPending, {
        sessionId: context.sessionId, storageId: context.storageId, code: "UPLOAD_DIGEST_MISMATCH",
      });
      throw new ConvexError({ code: "UPLOAD_DIGEST_MISMATCH", message: "SHA-256 mismatch; the uploaded bytes were discarded." });
    }
    return await ctx.runMutation(internal.uploadInternal.commitFinalization, {
      sessionId: context.sessionId, storageId: context.storageId, idempotencyKey,
      originalFileName, declaredSize: context.declaredSize, declaredSha256,
      verifiedSize: blob.size, verifiedSha256, submissionPublicId: newSecret(),
    });
  },
});
