import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

const publisherStatus = v.union(v.literal("pending"), v.literal("trusted"), v.literal("revoked"));
const uploadSessionState = v.union(v.literal("open"), v.literal("finalized"), v.literal("expired"));
const submissionState = v.union(
  v.literal("uploaded"), v.literal("analyzing"), v.literal("accepted"),
  v.literal("rejected"), v.literal("inconclusive"), v.literal("published"),
  v.literal("withdrawn"), v.literal("failed"),
);
const jobState = v.union(v.literal("queued"), v.literal("leased"), v.literal("complete"), v.literal("failed"));
const verdict = v.union(v.literal("accepted"), v.literal("rejected"), v.literal("inconclusive"));
const severity = v.union(
  v.literal("info"), v.literal("low"), v.literal("medium"),
  v.literal("high"), v.literal("critical"),
);
const confidence = v.union(v.literal("verified"), v.literal("high"), v.literal("medium"), v.literal("low"));
const publicationEffect = v.union(
  v.literal("none"), v.literal("review"), v.literal("block"), v.literal("inconclusive"),
);
const publicationState = v.union(
  v.literal("draft"), v.literal("published"), v.literal("withdrawn"), v.literal("superseded"),
);

export default defineSchema({
  publisherKeys: defineTable({
    keyId: v.string(), displayName: v.string(), publicKeyBase64: v.string(),
    status: publisherStatus, createdAtMs: v.number(), reviewedAtMs: v.optional(v.number()),
    reviewerIdentity: v.optional(v.string()),
  }).index("by_key_id", ["keyId"]).index("by_status_and_created_at_ms", ["status", "createdAtMs"]),

  uploadSessions: defineTable({
    publicId: v.string(), secretHash: v.string(), state: uploadSessionState,
    createdAtMs: v.number(), expiresAtMs: v.number(), uploadCount: v.number(), byteCount: v.number(),
    pendingStorageId: v.optional(v.id("_storage")),
    pendingDeclaredSize: v.optional(v.number()),
  }).index("by_public_id", ["publicId"]).index("by_state_and_expires_at_ms", ["state", "expiresAtMs"]),

  submissions: defineTable({
    publicId: v.string(), uploadSessionId: v.id("uploadSessions"), storageId: v.id("_storage"),
    state: submissionState, originalFileName: v.string(), declaredSize: v.number(),
    declaredSha256: v.string(), verifiedSize: v.optional(v.number()),
    verifiedSha256: v.optional(v.string()), createdAtMs: v.number(), updatedAtMs: v.number(),
    idempotencyKey: v.string(),
    terminalCode: v.optional(v.string()), terminalMessage: v.optional(v.string()),
  }).index("by_public_id", ["publicId"])
    .index("by_upload_session_id_and_created_at_ms", ["uploadSessionId", "createdAtMs"])
    .index("by_upload_session_id_and_idempotency_key", ["uploadSessionId", "idempotencyKey"])
    .index("by_state_and_updated_at_ms", ["state", "updatedAtMs"]),

  analysisJobs: defineTable({
    submissionId: v.id("submissions"), state: jobState, generation: v.number(), stage: v.string(),
    analyzerVersion: v.string(), ruleSetVersion: v.string(), attempts: v.number(),
    leaseTokenHash: v.optional(v.string()), leaseExpiresAtMs: v.optional(v.number()),
    createdAtMs: v.number(), updatedAtMs: v.number(), failureClass: v.optional(v.string()),
  }).index("by_submission_id_and_generation", ["submissionId", "generation"])
    .index("by_state_and_updated_at_ms", ["state", "updatedAtMs"])
    .index("by_state_and_lease_expires_at_ms", ["state", "leaseExpiresAtMs"]),

  analysisReports: defineTable({
    submissionId: v.id("submissions"), jobId: v.id("analysisJobs"), verdict,
    publicationAllowed: v.boolean(), bundleId: v.optional(v.string()), bundleSha256: v.string(),
    publisherKeyId: v.optional(v.string()), gameId: v.optional(v.string()), gameVersion: v.optional(v.string()),
    title: v.optional(v.string()), developer: v.optional(v.string()), description: v.optional(v.string()),
    compatibility: v.optional(v.array(v.string())),
    analyzerVersion: v.string(), ruleSetVersion: v.string(), reportDigest: v.string(),
    findingCount: v.number(), normalizedReport: v.string(), createdAtMs: v.number(),
  }).index("by_submission_id", ["submissionId"])
    .index("by_report_digest", ["reportDigest"])
    .index("by_verdict_and_created_at_ms", ["verdict", "createdAtMs"]),

  analysisFindings: defineTable({
    reportId: v.id("analysisReports"), ordinal: v.number(), ruleId: v.string(), severity,
    confidence, publicationEffect, file: v.string(), fileOffset: v.optional(v.number()),
    virtualAddress: v.optional(v.number()), evidenceHash: v.string(), explanation: v.string(),
    remediation: v.string(),
  }).index("by_report_id_and_ordinal", ["reportId", "ordinal"])
    .index("by_report_id_and_severity", ["reportId", "severity"]),

  games: defineTable({
    gameId: v.string(), title: v.string(), searchKey: v.string(), searchText: v.string(),
    developer: v.string(), description: v.string(), publisherKeyId: v.string(),
    currentReleaseId: v.optional(v.id("releases")), createdAtMs: v.number(), updatedAtMs: v.number(),
  }).index("by_game_id", ["gameId"])
    .index("by_search_key", ["searchKey"])
    .index("by_publisher_key_id_and_updated_at_ms", ["publisherKeyId", "updatedAtMs"])
    .searchIndex("search_title", { searchField: "searchText" }),

  releases: defineTable({
    gameId: v.string(), gameDocumentId: v.id("games"), submissionId: v.id("submissions"),
    reportId: v.id("analysisReports"), storageId: v.id("_storage"), version: v.string(),
    publicationState, title: v.string(), searchKey: v.string(), developer: v.string(),
    searchText: v.string(), description: v.string(), bundleId: v.string(), bundleSha256: v.string(), bundleSize: v.number(),
    publisherKeyId: v.string(), analyzerVersion: v.string(), ruleSetVersion: v.string(),
    compatibility: v.array(v.string()), publishedAtMs: v.optional(v.number()),
    withdrawnAtMs: v.optional(v.number()), withdrawalReason: v.optional(v.string()),
  }).index("by_game_id_and_version", ["gameId", "version"])
    .index("by_game_document_id_and_publication_state", ["gameDocumentId", "publicationState"])
    .index("by_publication_state_and_published_at_ms", ["publicationState", "publishedAtMs"])
    .index("by_publication_state_and_search_key", ["publicationState", "searchKey"])
    .index("by_publisher_key_id_and_publication_state", ["publisherKeyId", "publicationState"])
    .searchIndex("search_title", { searchField: "searchText", filterFields: ["publicationState"] }),

  reviews: defineTable({
    submissionId: v.id("submissions"), releaseId: v.optional(v.id("releases")),
    reviewerIdentity: v.string(),
    decision: v.union(v.literal("publish"), v.literal("reject"), v.literal("withdraw")),
    reason: v.string(), createdAtMs: v.number(),
  }).index("by_submission_id_and_created_at_ms", ["submissionId", "createdAtMs"])
    .index("by_reviewer_identity_and_created_at_ms", ["reviewerIdentity", "createdAtMs"]),
});
