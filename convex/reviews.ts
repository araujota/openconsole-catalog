import { v } from "convex/values";
import { env, mutation, type MutationCtx } from "./_generated/server";
import { fail } from "./lib/security";
import { sha256Hex } from "./lib/security";

async function requireReviewer(ctx: MutationCtx): Promise<string> {
  const identity = await ctx.auth.getUserIdentity();
  const allowed = new Set((env.OPENCONSOLE_REVIEWERS ?? "").split(",").map((item) => item.trim()).filter(Boolean));
  if (identity === null || !allowed.has(identity.tokenIdentifier)) {
    fail("REVIEWER_REQUIRED", "This operation requires a configured reviewer identity.");
  }
  return identity.tokenIdentifier;
}

function requiredText(value: string | undefined, field: string): string {
  const result = value?.trim();
  if (!result) fail("PUBLICATION_METADATA_MISSING", `Accepted report is missing ${field}.`);
  return result;
}

export const trustPublisher = mutation({
  args: { keyId: v.string(), displayName: v.string(), publicKeyBase64: v.string() },
  returns: v.id("publisherKeys"),
  handler: async (ctx, args) => {
    const reviewerIdentity = await requireReviewer(ctx);
    let raw: Uint8Array;
    try { raw = Uint8Array.from(atob(args.publicKeyBase64), (character) => character.charCodeAt(0)); }
    catch { fail("PUBLISHER_KEY_ENCODING", "Publisher key must be canonical base64."); }
    if (raw!.length !== 57 || await sha256Hex(new Uint8Array(raw!).buffer) !== args.keyId.toLowerCase()) {
      fail("PUBLISHER_KEY_ID", "Publisher key ID must equal SHA-256 of the 57-byte Ed448 public key.");
    }
    const existing = await ctx.db.query("publisherKeys").withIndex("by_key_id", (q) => q.eq("keyId", args.keyId.toLowerCase())).unique();
    const now = Date.now();
    if (existing !== null) {
      await ctx.db.patch("publisherKeys", existing._id, {
        displayName: args.displayName.trim(), publicKeyBase64: args.publicKeyBase64,
        status: "trusted", reviewedAtMs: now, reviewerIdentity,
      });
      return existing._id;
    }
    return await ctx.db.insert("publisherKeys", {
      keyId: args.keyId.toLowerCase(), displayName: args.displayName.trim(),
      publicKeyBase64: args.publicKeyBase64, status: "trusted", createdAtMs: now,
      reviewedAtMs: now, reviewerIdentity,
    });
  },
});

export const publish = mutation({
  args: { submissionId: v.id("submissions"), reason: v.string() },
  returns: v.object({ releaseId: v.id("releases"), gameId: v.string(), version: v.string() }),
  handler: async (ctx, args) => {
    const reviewerIdentity = await requireReviewer(ctx);
    const submission = await ctx.db.get("submissions", args.submissionId);
    if (submission === null || submission.state !== "accepted") {
      fail("PUBLICATION_STATE", "Only an accepted submission can be published.");
    }
    const report = await ctx.db.query("analysisReports").withIndex("by_submission_id", (q) =>
      q.eq("submissionId", submission._id)).unique();
    if (report === null || report.verdict !== "accepted" || !report.publicationAllowed) {
      fail("PUBLICATION_REPORT", "Publication requires an accepted, publication-eligible report.");
    }
    const gameId = requiredText(report.gameId, "game ID");
    const version = requiredText(report.gameVersion, "version");
    const publisherKeyId = requiredText(report.publisherKeyId, "publisher key ID");
    const title = requiredText(report.title, "title");
    const developer = requiredText(report.developer, "developer");
    const publisher = await ctx.db.query("publisherKeys").withIndex("by_key_id", (q) =>
      q.eq("keyId", publisherKeyId)).unique();
    if (publisher === null || publisher.status !== "trusted") {
      fail("PUBLICATION_PUBLISHER_UNTRUSTED", "The signing key is not trusted for catalog publication.");
    }
    const existingRelease = await ctx.db.query("releases").withIndex("by_game_id_and_version", (q) =>
      q.eq("gameId", gameId).eq("version", version)).unique();
    if (existingRelease !== null) {
      if (existingRelease.submissionId === submission._id && existingRelease.publicationState === "published") {
        return { releaseId: existingRelease._id, gameId, version };
      }
      fail("PUBLICATION_VERSION_EXISTS", "This game version already has a provenance record.");
    }
    const now = Date.now();
    let game = await ctx.db.query("games").withIndex("by_game_id", (q) => q.eq("gameId", gameId)).unique();
    if (game !== null && game.publisherKeyId !== publisherKeyId) {
      fail("PUBLICATION_PUBLISHER_MISMATCH", "A game identity cannot change publisher keys through upload.");
    }
    if (game === null) {
      const gameDocumentId = await ctx.db.insert("games", {
        gameId, title, searchKey: title.toLocaleLowerCase(), searchText: `${title} ${developer}`,
        developer, description: report.description ?? "", publisherKeyId, createdAtMs: now, updatedAtMs: now,
      });
      game = (await ctx.db.get("games", gameDocumentId))!;
    }
    const releaseId = await ctx.db.insert("releases", {
      gameId, gameDocumentId: game._id, submissionId: submission._id, reportId: report._id,
      storageId: submission.storageId, version, publicationState: "published", title,
      searchKey: title.toLocaleLowerCase(), searchText: `${title} ${developer}`,
      developer, description: report.description ?? "", bundleId: requiredText(report.bundleId, "bundle ID"),
      bundleSha256: report.bundleSha256, bundleSize: submission.verifiedSize ?? submission.declaredSize,
      publisherKeyId, analyzerVersion: report.analyzerVersion, ruleSetVersion: report.ruleSetVersion,
      compatibility: report.compatibility ?? [], publishedAtMs: now,
    });
    if (game.currentReleaseId !== undefined) {
      const prior = await ctx.db.get("releases", game.currentReleaseId);
      if (prior !== null && prior.publicationState === "published") {
        await ctx.db.patch("releases", prior._id, { publicationState: "superseded" });
      }
    }
    await ctx.db.patch("games", game._id, {
      title, searchKey: title.toLocaleLowerCase(), searchText: `${title} ${developer}`,
      developer, description: report.description ?? "", currentReleaseId: releaseId, updatedAtMs: now,
    });
    await ctx.db.patch("submissions", submission._id, { state: "published", updatedAtMs: now });
    await ctx.db.insert("reviews", {
      submissionId: submission._id, releaseId, reviewerIdentity, decision: "publish",
      reason: args.reason.trim(), createdAtMs: now,
    });
    return { releaseId, gameId, version };
  },
});

export const reject = mutation({
  args: { submissionId: v.id("submissions"), reason: v.string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    const reviewerIdentity = await requireReviewer(ctx);
    const submission = await ctx.db.get("submissions", args.submissionId);
    if (submission === null || !["accepted", "inconclusive"].includes(submission.state)) {
      fail("REVIEW_STATE", "Only an accepted or inconclusive submission can be rejected by review.");
    }
    const now = Date.now();
    await ctx.db.patch("submissions", submission._id, {
      state: "rejected", updatedAtMs: now, terminalCode: "REVIEW_REJECTED",
      terminalMessage: args.reason.trim(),
    });
    await ctx.db.insert("reviews", {
      submissionId: submission._id, reviewerIdentity, decision: "reject",
      reason: args.reason.trim(), createdAtMs: now,
    });
    return null;
  },
});

export const withdraw = mutation({
  args: { releaseId: v.id("releases"), reason: v.string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    const reviewerIdentity = await requireReviewer(ctx);
    const release = await ctx.db.get("releases", args.releaseId);
    if (release === null || release.publicationState !== "published") {
      fail("WITHDRAWAL_STATE", "Only a currently published release can be withdrawn.");
    }
    const now = Date.now();
    await ctx.db.patch("releases", release._id, {
      publicationState: "withdrawn", withdrawnAtMs: now, withdrawalReason: args.reason.trim(),
    });
    const game = await ctx.db.get("games", release.gameDocumentId);
    if (game?.currentReleaseId === release._id) {
      await ctx.db.patch("games", game._id, { currentReleaseId: undefined, updatedAtMs: now });
    }
    await ctx.db.patch("submissions", release.submissionId, { state: "withdrawn", updatedAtMs: now });
    await ctx.db.insert("reviews", {
      submissionId: release.submissionId, releaseId: release._id, reviewerIdentity,
      decision: "withdraw", reason: args.reason.trim(), createdAtMs: now,
    });
    return null;
  },
});
