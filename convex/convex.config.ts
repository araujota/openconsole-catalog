import { defineApp } from "convex/server";
import { v } from "convex/values";

export default defineApp({
  env: {
    OPENCONSOLE_REVIEWERS: v.optional(v.string()),
  },
});
