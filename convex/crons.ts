import { cronJobs } from "convex/server";
import { internal } from "./_generated/api";

const crons = cronJobs();
crons.interval("expire abandoned upload sessions", { hours: 1 }, internal.uploadInternal.expireSessions, {
});

export default crons;
