import { ConvexError } from "convex/values";

export const MAX_BUNDLE_BYTES = 64 * 1024 * 1024;
export const MAX_SESSION_BYTES = 128 * 1024 * 1024;
export const MAX_SESSION_UPLOADS = 3;
export const SESSION_TTL_MS = 30 * 60 * 1000;

export function requireHexSha256(value: string): string {
  const normalized = value.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new ConvexError({ code: "UPLOAD_BAD_SHA256", message: "Expected a 64-character SHA-256 digest." });
  }
  return normalized;
}

export function requirePublicId(value: string, label: string): string {
  if (!/^[A-Za-z0-9_-]{20,128}$/.test(value)) {
    throw new ConvexError({ code: "UPLOAD_BAD_ID", message: `${label} is malformed.` });
  }
  return value;
}

export function requireFileName(value: string): string {
  if (value.length < 1 || value.length > 128 || !/^[A-Za-z0-9._-]+\.ocg$/i.test(value)) {
    throw new ConvexError({ code: "UPLOAD_BAD_FILENAME", message: "Choose a simple .ocg filename (letters, digits, dot, dash, underscore)." });
  }
  return value;
}

export async function sha256Hex(value: string | ArrayBuffer): Promise<string> {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : new Uint8Array(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function newSecret(): string {
  return `${crypto.randomUUID().replaceAll("-", "")}${crypto.randomUUID().replaceAll("-", "")}`;
}

export function fail(code: string, message: string): never {
  throw new ConvexError({ code, message });
}
