/* eslint-disable */
/**
 * Generated `api` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type * as analyzerInternal from "../analyzerInternal.js";
import type * as analyzerWorker from "../analyzerWorker.js";
import type * as catalog from "../catalog.js";
import type * as crons from "../crons.js";
import type * as finalizeUpload from "../finalizeUpload.js";
import type * as lib_security from "../lib/security.js";
import type * as reviews from "../reviews.js";
import type * as uploadInternal from "../uploadInternal.js";
import type * as uploads from "../uploads.js";

import type {
  ApiFromModules,
  FilterApi,
  FunctionReference,
} from "convex/server";

declare const fullApi: ApiFromModules<{
  analyzerInternal: typeof analyzerInternal;
  analyzerWorker: typeof analyzerWorker;
  catalog: typeof catalog;
  crons: typeof crons;
  finalizeUpload: typeof finalizeUpload;
  "lib/security": typeof lib_security;
  reviews: typeof reviews;
  uploadInternal: typeof uploadInternal;
  uploads: typeof uploads;
}>;

/**
 * A utility for referencing Convex functions in your app's public API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = api.myModule.myFunction;
 * ```
 */
export declare const api: FilterApi<
  typeof fullApi,
  FunctionReference<any, "public">
>;

/**
 * A utility for referencing Convex functions in your app's internal API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = internal.myModule.myFunction;
 * ```
 */
export declare const internal: FilterApi<
  typeof fullApi,
  FunctionReference<any, "internal">
>;

export declare const components: {};
