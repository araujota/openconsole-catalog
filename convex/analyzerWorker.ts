"use node";

import { v } from "convex/values";
import { internalAction } from "./_generated/server";
import { internal } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import { newSecret, sha256Hex } from "./lib/security";
import { analyzeOpenConsoleBundle } from "../lib/openconsoleAnalyzer";

function bytesFromBase64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export const run = internalAction({
  args: { jobId: v.id("analysisJobs") },
  returns: v.null(),
  handler: async (ctx, args): Promise<null> => {
    const leaseToken = newSecret();
    const leaseTokenHash = await sha256Hex(leaseToken);
    const lease: null | { generation: number; storageId: Id<"_storage">; submissionId: Id<"submissions"> } =
      await ctx.runMutation(internal.analyzerInternal.acquire, { jobId: args.jobId, leaseToken });
    if (lease === null) return null;
    try {
      const blob = await ctx.storage.get(lease.storageId);
      if (blob === null) throw new Error("Persisted upload is missing.");
      const bytes = new Uint8Array(await blob.arrayBuffer());
      const keyId = bytes.length >= 112 ? bytesToHex(bytes.slice(80, 112)) : "";
      const trusted: null | { publicKeyBase64: string } = keyId
        ? await ctx.runQuery(internal.analyzerInternal.trustedKey, { keyId }) : null;
      const report = await analyzeOpenConsoleBundle(bytes, trusted ? bytesFromBase64(trusted.publicKeyBase64) : undefined);
      const normalizedReport = JSON.stringify(report);
      await ctx.runMutation(internal.analyzerInternal.complete, {
        jobId: args.jobId, generation: lease.generation, leaseTokenHash,
        report: {
          verdict: report.verdict, publicationAllowed: report.publicationAllowed,
          bundleId: report.bundleId, bundleSha256: report.bundleSha256,
          publisherKeyId: report.publisherKeyId, gameId: report.gameId, gameVersion: report.gameVersion,
          title: report.title, developer: report.developer, description: report.description,
          compatibility: report.compatibility, analyzerVersion: report.analyzerVersion,
          ruleSetVersion: report.ruleSetVersion, reportDigest: report.reportDigest,
          normalizedReport, findings: report.findings,
        },
      });
    } catch (error) {
      await ctx.runMutation(internal.analyzerInternal.fail, {
        jobId: args.jobId, generation: lease.generation, leaseTokenHash,
        message: error instanceof Error ? error.message : "Unknown analyzer failure",
      });
    }
    return null;
  },
});
