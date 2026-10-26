import { paginationOptsValidator, paginationResultValidator } from "convex/server";
import { v } from "convex/values";
import { query } from "./_generated/server";
import type { Id } from "./_generated/dataModel";
import { fail } from "./lib/security";

const publicationState = v.union(
  v.literal("draft"), v.literal("published"), v.literal("withdrawn"), v.literal("superseded"),
);
const releaseSummary = v.object({
  releaseId: v.id("releases"), gameId: v.string(), title: v.string(), developer: v.string(),
  version: v.string(), description: v.string(), bundleSize: v.number(), bundleSha256: v.string(),
  publisherKeyId: v.string(), analyzerVersion: v.string(), ruleSetVersion: v.string(),
  compatibility: v.array(v.string()), publishedAtMs: v.union(v.number(), v.null()),
});

function summary(release: {
  _id: Id<"releases">; gameId: string; title: string; developer: string; version: string; description: string;
  bundleSize: number; bundleSha256: string; publisherKeyId: string; analyzerVersion: string;
  ruleSetVersion: string; compatibility: string[]; publishedAtMs?: number;
}) {
  return {
    releaseId: release._id, gameId: release.gameId, title: release.title, developer: release.developer,
    version: release.version, description: release.description, bundleSize: release.bundleSize,
    bundleSha256: release.bundleSha256, publisherKeyId: release.publisherKeyId,
    analyzerVersion: release.analyzerVersion, ruleSetVersion: release.ruleSetVersion,
    compatibility: release.compatibility, publishedAtMs: release.publishedAtMs ?? null,
  };
}

export const list = query({
  args: {
    paginationOpts: paginationOptsValidator,
    search: v.optional(v.string()),
    publisherKeyId: v.optional(v.string()),
  },
  returns: paginationResultValidator(releaseSummary),
  handler: async (ctx, args) => {
    if (args.search !== undefined && args.publisherKeyId !== undefined) {
      fail("CATALOG_FILTER_CONFLICT", "Search and publisher filters must be paginated separately.");
    }
    const page = args.search !== undefined && args.search.trim() !== ""
      ? await ctx.db.query("releases").withSearchIndex("search_title", (q) =>
          q.search("searchText", args.search!.trim()).eq("publicationState", "published"))
        .paginate(args.paginationOpts)
      : args.publisherKeyId !== undefined
        ? await ctx.db.query("releases").withIndex("by_publisher_key_id_and_publication_state", (q) =>
            q.eq("publisherKeyId", args.publisherKeyId!).eq("publicationState", "published"))
          .order("desc").paginate(args.paginationOpts)
        : await ctx.db.query("releases").withIndex("by_publication_state_and_published_at_ms", (q) =>
            q.eq("publicationState", "published"))
          .order("desc").paginate(args.paginationOpts);
    return { ...page, page: page.page.map(summary) };
  },
});

export const detail = query({
  args: { gameId: v.string() },
  returns: v.union(v.null(), v.object({
    gameId: v.string(), title: v.string(), developer: v.string(), description: v.string(),
    publisherKeyId: v.string(), currentRelease: releaseSummary,
    versions: v.array(v.object({
      releaseId: v.id("releases"), version: v.string(), publicationState,
      publishedAtMs: v.union(v.number(), v.null()), bundleSha256: v.string(),
    })),
  })),
  handler: async (ctx, args) => {
    const game = await ctx.db.query("games").withIndex("by_game_id", (q) => q.eq("gameId", args.gameId)).unique();
    if (game === null || game.currentReleaseId === undefined) return null;
    const current = await ctx.db.get("releases", game.currentReleaseId);
    if (current === null || current.publicationState !== "published") return null;
    const versions = await ctx.db.query("releases").withIndex("by_game_document_id_and_publication_state", (q) =>
      q.eq("gameDocumentId", game._id)).order("desc").take(50);
    return {
      gameId: game.gameId, title: game.title, developer: game.developer,
      description: game.description, publisherKeyId: game.publisherKeyId,
      currentRelease: summary(current),
      versions: versions.map((release) => ({
        releaseId: release._id, version: release.version, publicationState: release.publicationState,
        publishedAtMs: release.publishedAtMs ?? null, bundleSha256: release.bundleSha256,
      })),
    };
  },
});

export const download = query({
  args: { releaseId: v.id("releases") },
  returns: v.object({
    url: v.string(), gameId: v.string(), version: v.string(), bundleId: v.string(),
    expectedSize: v.number(), expectedSha256: v.string(), publisherKeyId: v.string(),
    analyzerVersion: v.string(), ruleSetVersion: v.string(), reportDigest: v.string(),
    verdict: v.literal("accepted"), publicationState: v.literal("published"),
    trustNotice: v.string(),
  }),
  handler: async (ctx, args) => {
    const release = await ctx.db.get("releases", args.releaseId);
    if (release === null || release.publicationState !== "published") {
      fail("CATALOG_RELEASE_UNAVAILABLE", "This release is not currently downloadable.");
    }
    const report = await ctx.db.get("analysisReports", release.reportId);
    if (report === null || report.verdict !== "accepted" || !report.publicationAllowed) {
      fail("CATALOG_PROVENANCE_INVALID", "The accepted analyzer report is unavailable.");
    }
    const url = await ctx.storage.getUrl(release.storageId);
    if (url === null) fail("CATALOG_BLOB_MISSING", "The published bundle is unavailable from storage.");
    return {
      url, gameId: release.gameId, version: release.version, bundleId: release.bundleId,
      expectedSize: release.bundleSize, expectedSha256: release.bundleSha256,
      publisherKeyId: release.publisherKeyId, analyzerVersion: release.analyzerVersion,
      ruleSetVersion: release.ruleSetVersion, reportDigest: report.reportDigest,
      verdict: "accepted" as const, publicationState: "published" as const,
      trustNotice: "Analysis is not a sandbox; signatures identify a publisher, not code correctness. Physical firmware compatibility depends on declared evidence.",
    };
  },
});
