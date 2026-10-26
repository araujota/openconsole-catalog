import { ed448 } from "@noble/curves/ed448.js";

export const ANALYZER_VERSION = "0.1.0-service";
export const RULESET_VERSION = "2026-10-25.1-service";
const MAX_BUNDLE = 64 * 1024 * 1024;
const MAX_INDEX = 256 * 1024;
const MAX_FILE = 32 * 1024 * 1024;
const MAX_FINDINGS = 256;
const DOMAIN = new TextEncoder().encode("OPENCONSOLE-OCG2-SIGNED\0");
const SUPPORTED = new Set([
  "uefi.input.keyboard@1.0", "uefi.input.pointer@1.0", "openconsole.gles2@0.1",
  "openconsole.net@0.1", "openconsole.audio@0.2",
]);

type Effect = "none" | "review" | "block" | "inconclusive";
export type AnalyzerFinding = {
  ruleId: string; severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: "verified" | "high" | "medium" | "low"; publicationEffect: Effect;
  file: string; fileOffset: number | null; virtualAddress: number | null;
  evidenceHash: string; explanation: string; remediation: string;
};
export type AnalyzerReport = {
  schema: string; analyzerVersion: string; ruleSetVersion: string; bundleSha256: string;
  bundleSize: number; bundleId: string | null; publisherKeyId: string | null;
  gameId: string | null; gameVersion: string | null; title?: string; developer?: string;
  description?: string; compatibility?: string[]; verdict: "accepted" | "rejected" | "inconclusive";
  publicationAllowed: boolean; stages: Record<string, unknown>[]; findings: AnalyzerFinding[];
  notice: string; reportDigest: string;
};
type Entry = { path: string; role: number; data: Uint8Array };
type Section = { va: number; virtualSize: number; raw: number; rawSize: number; flags: number };

class ParseError extends Error {
  readonly code: string;
  readonly offset: number | null;
  constructor(code: string, offset: number | null = null) {
    super(code);
    this.code = code;
    this.offset = offset;
  }
}
const textDecoder = new TextDecoder("ascii", { fatal: true });
const view = (bytes: Uint8Array) => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
const u16 = (bytes: Uint8Array, at: number) => view(bytes).getUint16(at, true);
const u32 = (bytes: Uint8Array, at: number) => view(bytes).getUint32(at, true);
const u64 = (bytes: Uint8Array, at: number) => {
  const value = view(bytes).getBigUint64(at, true);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new ParseError("OCG2_OVERFLOW", at);
  return Number(value);
};
const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const concat = (...arrays: Uint8Array[]) => {
  const output = new Uint8Array(arrays.reduce((sum, item) => sum + item.length, 0));
  let offset = 0; for (const item of arrays) { output.set(item, offset); offset += item.length; } return output;
};
async function digest(bytes: Uint8Array) { return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(bytes)))); }
function equal(a: Uint8Array, b: Uint8Array) { return a.length === b.length && a.every((byte, i) => byte === b[i]); }
function slice(bytes: Uint8Array, start: number, length: number, code: string) {
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(length) || start < 0 || length < 0 || start > bytes.length - length) {
    throw new ParseError(code, start);
  }
  return bytes.slice(start, start + length);
}
function ascii(bytes: Uint8Array, code: string) { try { return textDecoder.decode(bytes); } catch { throw new ParseError(code); } }

function parseManifest(bytes: Uint8Array): Record<string, string | string[] | number | boolean> {
  if (bytes.length > 65536) throw new ParseError("OCG2_LIMIT");
  const fields: Record<string, string | string[] | number | boolean> = {};
  for (const source of ascii(bytes, "OCG2_MANIFEST_MISMATCH").split(/\r?\n/)) {
    const line = source.split("#", 1)[0].trim(); if (!line) continue;
    const match = /^([a-z_][a-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!match || fields[match[1]] !== undefined) throw new ParseError("OCG2_MANIFEST_MISMATCH");
    const [, key, raw] = match;
    if (/^"(?:[^"\\]|\\["\\nrt])*"$/.test(raw)) fields[key] = JSON.parse(raw);
    else if (/^\[(.*)\]$/.test(raw)) {
      const body = raw.slice(1, -1).trim();
      fields[key] = body ? body.split(",").map((item) => {
        const value = item.trim(); if (!/^"(?:[^"\\]|\\["\\nrt])*"$/.test(value)) throw new ParseError("OCG2_MANIFEST_MISMATCH");
        return JSON.parse(value) as string;
      }) : [];
    } else if (raw === "true" || raw === "false") fields[key] = raw === "true";
    else if (/^[0-9]+$/.test(raw)) fields[key] = Number(raw);
    else throw new ParseError("OCG2_MANIFEST_MISMATCH");
  }
  const required = ["format_version", "package_format", "id", "title", "version", "entry", "architecture",
    "required_capabilities", "optional_capabilities", "graphics_api", "accel", "min_graphics_abi"];
  if (required.some((key) => fields[key] === undefined) || fields.format_version !== "2.0" || fields.package_format !== "ocg2" ||
      fields.architecture !== "x64" || !["gop", "gles2"].includes(String(fields.graphics_api)) ||
      !["forbidden", "optional", "required"].includes(String(fields.accel)) ||
      !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(String(fields.id)) ||
      !/^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$/.test(String(fields.version))) throw new ParseError("OCG2_MANIFEST_MISMATCH");
  for (const key of ["required_capabilities", "optional_capabilities"] as const) {
    const capabilities = fields[key];
    if (!Array.isArray(capabilities) || capabilities.length > 32 || new Set(capabilities).size !== capabilities.length ||
        capabilities.some((item) => !/^[a-z][a-z0-9_.-]{0,63}@[0-9]+\.[0-9]+$/.test(item))) throw new ParseError("OCG2_MANIFEST_MISMATCH");
  }
  return fields;
}

async function parseBundle(bytes: Uint8Array) {
  if (bytes.length < 128 || bytes.length > MAX_BUNDLE) throw new ParseError("OCG2_LIMIT");
  if (ascii(bytes.slice(0, 4), "OCG2_BAD_MAGIC") !== "OCG2") throw new ParseError("OCG2_BAD_MAGIC");
  const headerSize = u32(bytes, 8), flags = u32(bytes, 12), indexLength = u64(bytes, 16), payloadLength = u64(bytes, 24);
  const fileCount = u32(bytes, 32), signatureAlgorithm = u16(bytes, 36), signatureLength = u16(bytes, 38), total = u64(bytes, 40);
  if (u16(bytes, 4) !== 2 || u16(bytes, 6) !== 0) throw new ParseError("OCG2_UNSUPPORTED_VERSION");
  if (headerSize !== 128 || flags !== 0 || signatureAlgorithm !== 1 || signatureLength !== 114 || bytes.slice(112, 128).some(Boolean)) throw new ParseError("OCG2_BAD_HEADER");
  if (indexLength > MAX_INDEX || fileCount > 256 || total !== 128 + 114 + indexLength + payloadLength || total !== bytes.length) throw new ParseError("OCG2_LENGTH_MISMATCH");
  const signature = slice(bytes, 128, 114, "OCG2_LENGTH_MISMATCH");
  const index = slice(bytes, 242, indexLength, "OCG2_LENGTH_MISMATCH");
  const payload = slice(bytes, 242 + indexLength, payloadLength, "OCG2_LENGTH_MISMATCH");
  const bundleId = bytes.slice(48, 80), keyId = bytes.slice(80, 112);
  if (await digest(index) !== hex(bundleId)) throw new ParseError("OCG2_INDEX_DIGEST");
  if (index.length < 80 || ascii(index.slice(0, 4), "OCG2_BAD_INDEX") !== "OCI2" || u16(index, 4) !== 2 || u16(index, 6) !== 0 || u32(index, 8) !== 80) throw new ParseError("OCG2_BAD_INDEX");
  const count = u32(index, 12), manifestIndex = u32(index, 16), gameLength = u32(index, 20), versionLength = u32(index, 24);
  const indexFlags = u32(index, 28), recordsLength = u64(index, 32), indexedPayload = u64(index, 40);
  if (count !== fileCount || indexFlags !== 0 || indexedPayload !== payloadLength || !equal(index.slice(48, 80), keyId)) throw new ParseError("OCG2_BAD_INDEX");
  const stringsEnd = 80 + gameLength + versionLength;
  if (stringsEnd + recordsLength !== index.length) throw new ParseError("OCG2_BAD_INDEX");
  const gameId = ascii(slice(index, 80, gameLength, "OCG2_BAD_INDEX"), "OCG2_BAD_INDEX");
  const version = ascii(slice(index, 80 + gameLength, versionLength, "OCG2_BAD_INDEX"), "OCG2_BAD_INDEX");
  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(gameId) || !/^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$/.test(version)) throw new ParseError("OCG2_BAD_INDEX");
  let cursor = stringsEnd, previousPath = "", previousEnd = 0; const folded = new Set<string>(); const entries: Entry[] = [];
  for (let i = 0; i < count; i++) {
    if (cursor > index.length - 56) throw new ParseError("OCG2_BAD_INDEX", cursor);
    const pathLength = u16(index, cursor), role = u16(index, cursor + 2), entryFlags = u32(index, cursor + 4);
    const offset = u64(index, cursor + 8), length = u64(index, cursor + 16), expectedDigest = index.slice(cursor + 24, cursor + 56); cursor += 56;
    const path = ascii(slice(index, cursor, pathLength, "OCG2_BAD_PATH"), "OCG2_BAD_PATH"); cursor += pathLength;
    if (!/^[A-Za-z0-9._/-]{1,240}$/.test(path) || path.split("/").some((part) => !part || part === "." || part === "..") ||
        /^(efi|games|\.openconsole)\//i.test(path) || /^openconsole-/i.test(path)) throw new ParseError("OCG2_BAD_PATH");
    if (entryFlags !== 0 || role < 1 || role > 5 || (i > 0 && path <= previousPath) || folded.has(path.toLowerCase())) throw new ParseError("OCG2_BAD_ROLE");
    if (offset !== previousEnd || length > MAX_FILE || offset > payload.length - length) throw new ParseError("OCG2_BAD_OFFSET");
    const data = payload.slice(offset, offset + length); if (await digest(data) !== hex(expectedDigest)) throw new ParseError("OCG2_BAD_DIGEST");
    entries.push({ path, role, data }); previousPath = path; previousEnd = offset + length; folded.add(path.toLowerCase());
  }
  if (cursor !== index.length || previousEnd !== payload.length || manifestIndex >= entries.length || entries[manifestIndex].role !== 1 || entries[manifestIndex].path !== "game.toml" || entries.filter((e) => e.role === 2).length !== 1) throw new ParseError("OCG2_BAD_ROLE");
  const manifest = parseManifest(entries[manifestIndex].data);
  if (manifest.id !== gameId || manifest.version !== version) throw new ParseError("OCG2_MANIFEST_MISMATCH");
  for (const [field, role] of [["entry", 2], ["jacket", 3], ["controls", 4]] as const) {
    const entry = entries.find((item) => item.role === role); if ((manifest[field] !== undefined) !== (entry !== undefined) || entry && manifest[field] !== entry.path) throw new ParseError("OCG2_MANIFEST_MISMATCH");
  }
  return { bundleId, keyId, signature, index, entries, manifest, gameId, version };
}

function parsePe(bytes: Uint8Array): Section[] {
  if (bytes.length < 64 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) throw new ParseError("PE_BAD_DOS");
  const pe = u32(bytes, 0x3c); if (pe > bytes.length - 24 || ascii(bytes.slice(pe, pe + 4), "PE_BAD_SIGNATURE") !== "PE\0\0") throw new ParseError("PE_BAD_SIGNATURE");
  const count = u16(bytes, pe + 6), optionalSize = u16(bytes, pe + 20), optional = pe + 24;
  if (u16(bytes, pe + 4) !== 0x8664) throw new ParseError("PE_BAD_MACHINE");
  if (count < 1 || count > 96 || optionalSize < 112 || optional > bytes.length - optionalSize || u16(bytes, optional) !== 0x20b || u16(bytes, optional + 68) !== 10) throw new ParseError("PE_BAD_OPTIONAL_HEADER");
  const entry = u32(bytes, optional + 16), imageSize = u32(bytes, optional + 56), headersSize = u32(bytes, optional + 60), table = optional + optionalSize;
  if (table > bytes.length - count * 40 || headersSize > bytes.length) throw new ParseError("PE_TRUNCATED_SECTIONS");
  const directoryCount = u32(bytes, optional + 108); if (directoryCount > 16 || optionalSize < 112 + directoryCount * 8) throw new ParseError("PE_BAD_DATA_DIRECTORIES");
  const sections: Section[] = []; let entryFound = false;
  for (let i = 0; i < count; i++) { const at = table + i * 40; const section = { virtualSize: u32(bytes, at + 8), va: u32(bytes, at + 12), rawSize: u32(bytes, at + 16), raw: u32(bytes, at + 20), flags: u32(bytes, at + 36) }; const span = Math.max(section.virtualSize, section.rawSize);
    if ((section.rawSize && section.raw > bytes.length - section.rawSize) || section.va > imageSize || span > imageSize - section.va) throw new ParseError("PE_BAD_SECTION_RANGE");
    if (section.va <= entry && entry < section.va + span && (section.flags & 0x20000000)) entryFound = true; sections.push(section); }
  if (!entryFound) throw new ParseError("PE_BAD_ENTRY_POINT");
  for (let i = 0; i < sections.length; i++) for (let j = i + 1; j < sections.length; j++) { const a = sections[i], b = sections[j];
    if (a.va < b.va + Math.max(b.virtualSize, b.rawSize) && b.va < a.va + Math.max(a.virtualSize, a.rawSize)) throw new ParseError("PE_OVERLAPPING_VIRTUAL_SECTIONS");
    if (a.rawSize && b.rawSize && a.raw < b.raw + b.rawSize && b.raw < a.raw + a.rawSize) throw new ParseError("PE_OVERLAPPING_RAW_SECTIONS"); }
  for (const [index, label, minimum] of [[1, "IMPORT", 20], [5, "RELOCATION", 8]] as const) if (index < directoryCount) { const rva = u32(bytes, optional + 112 + index * 8), size = u32(bytes, optional + 116 + index * 8); if ((rva === 0) !== (size === 0)) throw new ParseError(`PE_BAD_${label}_DIRECTORY`); if (rva) { const matches = sections.filter((s) => s.va <= rva && rva - s.va <= s.rawSize && size <= s.rawSize - (rva - s.va)); if (matches.length !== 1 || size < minimum) throw new ParseError(`PE_BAD_${label}_DIRECTORY`); } }
  return sections;
}

function canonicalJson(value: unknown): string { if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`; if (value && typeof value === "object") return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, val]) => `${JSON.stringify(key)}:${canonicalJson(val)}`).join(",")}}`; return JSON.stringify(value); }

function validateAssets(entries: Entry[]) {
  const namedKeys = new Set(["enter", "escape", "space", "left", "right", "up", "down", "mouse.left", "mouse.right"]);
  for (const entry of entries) {
    if (entry.role === 3) {
      if (entry.data.length > 1024 * 1024) throw new ParseError("OCJ1_LIMIT");
      if (entry.data.length < 8 || ascii(entry.data.slice(0, 4), "OCJ1_MAGIC") !== "OCJ1") throw new ParseError("OCJ1_MAGIC");
      const width = u16(entry.data, 4), height = u16(entry.data, 6);
      if (width < 1 || width > 512 || height < 1 || height > 512) throw new ParseError("OCJ1_DIMENSIONS");
      if (entry.data.length !== 8 + width * height * 4) throw new ParseError("OCJ1_LENGTH");
    } else if (entry.role === 4) {
      if (entry.data.length > 16384) throw new ParseError("CONTROLS_LIMIT");
      const seen = new Set<string>();
      for (const source of ascii(entry.data, "CONTROLS_ENCODING").split(/\r?\n/)) {
        const line = source.split("#", 1)[0].trim(); if (!line) continue;
        const match = /^([a-z][a-z0-9_.-]{0,63})\s*=\s*"([^"\\]*)"$/.exec(line);
        if (!match) throw new ParseError("CONTROLS_SYNTAX");
        if (seen.has(match[1])) throw new ParseError("CONTROLS_DUPLICATE"); seen.add(match[1]);
        if (!(namedKeys.has(match[2]) || (match[2].length === 1 && match[2].charCodeAt(0) >= 0x20 && match[2].charCodeAt(0) <= 0x7e))) throw new ParseError("CONTROLS_KEY");
      }
    }
  }
}

export async function analyzeOpenConsoleBundle(blob: Uint8Array, trustedPublicKey?: Uint8Array): Promise<AnalyzerReport> {
  const base: Record<string, unknown> = { schema: "openconsole.analyzer.report.v1", analyzerVersion: ANALYZER_VERSION, ruleSetVersion: RULESET_VERSION,
    bundleSha256: await digest(blob), bundleSize: blob.length, bundleId: null, publisherKeyId: null, gameId: null, gameVersion: null };
  const findings: AnalyzerFinding[] = [], stages: Record<string, unknown>[] = [];
  const add = async (ruleId: string, severity: AnalyzerFinding["severity"], confidence: AnalyzerFinding["confidence"], publicationEffect: Effect, explanation: string, remediation: string, file = "<bundle>", fileOffset: number | null = null, virtualAddress: number | null = null, evidence: Uint8Array = new Uint8Array()) => {
    if (findings.length >= MAX_FINDINGS) throw new ParseError("ANALYSIS_FINDING_LIMIT");
    findings.push({ ruleId, severity, confidence, publicationEffect, file, fileOffset, virtualAddress, evidenceHash: await digest(evidence.slice(0, 32)), explanation, remediation });
  };
  const finish = async (): Promise<AnalyzerReport> => { findings.sort((a, b) => `${a.ruleId}\0${a.file}\0${a.fileOffset ?? -1}\0${a.virtualAddress ?? -1}\0${a.evidenceHash}`.localeCompare(`${b.ruleId}\0${b.file}\0${b.fileOffset ?? -1}\0${b.virtualAddress ?? -1}\0${b.evidenceHash}`)); const effects = new Set(findings.map((item) => item.publicationEffect)); const verdict = effects.has("block") ? "rejected" : effects.has("inconclusive") ? "inconclusive" : "accepted"; Object.assign(base, { verdict, publicationAllowed: verdict === "accepted", stages, findings, notice: "Static analysis is not a sandbox or proof of safety; accepted EFI code remains trusted native firmware code." }); base.reportDigest = await digest(new TextEncoder().encode(canonicalJson(base))); return base as unknown as AnalyzerReport; };
  let bundle: Awaited<ReturnType<typeof parseBundle>>;
  try { bundle = await parseBundle(blob); stages.push({ name: "container", status: "passed" }); }
  catch (error) { const parsed = error as ParseError; await add("OCSA-CONTAINER-INVALID", "critical", "verified", "block", `OCG2 validation failed with ${parsed.code}.`, "Rebuild the bundle with the matching OpenConsole pack tool.", "<bundle>", parsed.offset, null, blob.slice(parsed.offset ?? 0)); stages.push({ name: "container", status: "failed", code: parsed.code }); return finish(); }
  Object.assign(base, { bundleId: hex(bundle.bundleId), publisherKeyId: hex(bundle.keyId), gameId: bundle.gameId, gameVersion: bundle.version,
    title: String(bundle.manifest.title), developer: String(bundle.manifest.developer ?? "Unknown developer"), description: String(bundle.manifest.description ?? ""), compatibility: [...(bundle.manifest.required_capabilities as string[])].sort() });
  if (!trustedPublicKey || await digest(trustedPublicKey) !== hex(bundle.keyId)) { await add("OCSA-SIGNATURE-UNTRUSTED", "high", "verified", "inconclusive", "The bundle is signed, but its publisher key is absent from the trust snapshot.", "Analyze with an explicit trusted publisher key or complete publisher review."); stages.push({ name: "signature", status: "untrusted" }); }
  else { const valid = ed448.verify(bundle.signature, concat(DOMAIN, blob.slice(0, 128), bundle.index), trustedPublicKey); if (!valid) { await add("OCSA-SIGNATURE-INVALID", "critical", "verified", "block", "The publisher signature did not verify.", "Sign the canonical bundle with the matching Ed448 private key."); stages.push({ name: "signature", status: "failed", code: "OCG2_BAD_SIGNATURE" }); } else stages.push({ name: "signature", status: "passed" }); }
  try { validateAssets(bundle.entries); stages.push({ name: "manifest-assets", status: "passed" }); }
  catch (error) { const parsed = error as ParseError; await add("OCSA-ASSET-INVALID", "high", "verified", "block", `Manifest or asset validation failed with ${parsed.code}.`, "Correct the named package asset and rebuild the bundle."); stages.push({ name: "manifest-assets", status: "failed", code: parsed.code }); return finish(); }
  const installedPrefix = `\\EFI\\OpenConsole\\State\\Games\\${bundle.gameId}\\slot-a\\package\\`;
  const invalidInstalled = bundle.entries.filter((entry) => installedPrefix.length + entry.path.length >= 192);
  const extractedBytes = bundle.entries.reduce((total, entry) => total + entry.data.length, 0);
  if (invalidInstalled.length || extractedBytes > MAX_BUNDLE) {
    await add("OCSA-INSTALLED-TREE-INVALID", "high", "verified", "block", "The authenticated package cannot be projected into the bounded installed-game tree.", "Shorten package paths and keep extracted content within the documented installation limits.", invalidInstalled[0]?.path ?? "<bundle>");
    stages.push({ name: "installed-tree", status: "failed", code: invalidInstalled.length ? "INSTALL_PATH_LIMIT" : "INSTALL_SIZE_LIMIT" });
    return finish();
  }
  stages.push({ name: "installed-tree", status: "passed", projectedFiles: bundle.entries.length, projectedBytes: extractedBytes });
  const required = bundle.manifest.required_capabilities as string[], optional = bundle.manifest.optional_capabilities as string[];
  const unsupportedRequired = required.filter((item) => !SUPPORTED.has(item)).sort(), unsupportedOptional = optional.filter((item) => !SUPPORTED.has(item)).sort();
  for (const capability of unsupportedRequired) await add("OCSA-CAPABILITY-REQUIRED-UNSUPPORTED", "high", "verified", "block", `Required capability ${capability} is outside this platform snapshot.`, "Target a supported version or publish with a matching platform profile.", "game.toml", null, null, new TextEncoder().encode(capability));
  for (const capability of unsupportedOptional) await add("OCSA-CAPABILITY-OPTIONAL-UNSUPPORTED", "info", "verified", "none", `Optional capability ${capability} is outside this platform snapshot.`, "Provide a graceful fallback when the capability is absent.", "game.toml", null, null, new TextEncoder().encode(capability));
  stages.push({ name: "compatibility", status: unsupportedRequired.length ? "failed" : "passed", unsupportedRequired, unsupportedOptional });
  const executable = bundle.entries.find((item) => item.role === 2)!; let sections: Section[];
  try { sections = parsePe(executable.data); stages.push({ name: "pe-coff", status: "passed" }); }
  catch (error) { const parsed = error as ParseError; await add("OCSA-PE-INVALID", "critical", "verified", "block", `The x64 EFI application failed PE/COFF validation: ${parsed.code}.`, "Link a bounded PE32+ x64 EFI application with subsystem 10 and a valid executable entry point.", executable.path, null, null, executable.data); stages.push({ name: "pe-coff", status: "failed", code: parsed.code }); return finish(); }
  try { const execSections = sections.filter((section) => section.flags & 0x20000000); if (execSections.length > 32 || execSections.reduce((n, section) => n + section.rawSize, 0) > 8 * 1024 * 1024) throw new ParseError("ANALYSIS_EXECUTABLE_LIMIT");
    for (const section of execSections) { if (section.flags & 0x80000000) await add("OCSA-PE-WRITABLE-EXECUTABLE", "critical", "verified", "block", "A PE section is simultaneously writable and executable.", "Separate mutable data from executable code and relink the EFI application.", executable.path, section.raw, section.va, executable.data.slice(section.raw)); const body = executable.data.slice(section.raw, section.raw + section.rawSize);
      for (let local = 0; local < body.length; local++) {
        const byte = body[local], offset = section.raw + local, va = section.va + local;
        if ((byte >= 0xe4 && byte <= 0xef) || (byte >= 0x6c && byte <= 0x6f)) {
          await add("OCSA-X64-DIRECT-IO", "critical", "low", "block", "Conservative executable-byte policy found a direct port-I/O opcode candidate.", "Use a declared OpenConsole protocol or UEFI protocol instead of direct port I/O; host analysis will confirm instruction boundaries.", executable.path, offset, va, body.slice(local, local + 15));
        } else if (byte === 0xfa || byte === 0xfb || byte === 0xf4) {
          await add("OCSA-X64-PRIVILEGED", "critical", "low", "block", "Conservative executable-byte policy found a CLI, STI, or HLT opcode candidate.", "Remove privileged processor-state manipulation; host analysis will confirm instruction boundaries.", executable.path, offset, va, body.slice(local, local + 15));
        } else if (byte === 0x0f && local + 2 < body.length && (body[local + 1] === 0x20 || body[local + 1] === 0x22) && (body[local + 2] & 0xc0) === 0xc0) {
          await add("OCSA-X64-CONTROL-REGISTER", "critical", "low", "block", "Conservative executable-byte policy found a control-register access candidate.", "Do not access x86 control registers from a game; host analysis will confirm instruction boundaries.", executable.path, offset, va, body.slice(local, local + 15));
        }
      }
    }
    const rules: [string, string, AnalyzerFinding["severity"], Effect, string, string][] = [["SetVariable", "OCSA-UEFI-VARIABLE-WRITE", "critical", "block", "Firmware-variable mutation indicator found.", "Games must not mutate firmware variables."], ["ResetSystem", "OCSA-UEFI-RESET", "critical", "block", "System-reset service indicator found.", "Return to the parent instead of resetting the host."], ["WriteFile", "OCSA-FILESYSTEM-WRITE", "high", "block", "Filesystem-write indicator found.", "Keep games read-only; use a future parent-mediated save protocol."], ["EFI_DRIVER_BINDING_PROTOCOL", "OCSA-DRIVER-BINDING", "critical", "block", "Driver-binding protocol indicator found in an application.", "Package drivers separately under platform policy."], ["ExitBootServices", "OCSA-LIFECYCLE-EXIT-BOOT-SERVICES", "critical", "block", "ExitBootServices lifecycle indicator found.", "A game must return under the parent's existing boot-services lifecycle."], ["SetWatchdogTimer", "OCSA-LIFECYCLE-WATCHDOG", "high", "block", "Direct watchdog manipulation indicator found.", "Leave watchdog and recovery policy under parent control."], ["InstallProtocolInterface", "OCSA-LIFECYCLE-PROTOCOL-INSTALL", "medium", "review", "Protocol installation can outlive the game generation.", "Use parent-provided generation-scoped protocols and uninstall owned resources before return."], ["LoadImage", "OCSA-LIFECYCLE-IMAGE-LOAD", "high", "review", "Nested EFI image loading indicator found.", "Declare and justify child loading; normally return launch control to the parent."]];
    for (const [marker, rule, severity, effect, explanation, remediation] of rules) for (const encoded of [new TextEncoder().encode(marker), new Uint8Array([...marker].flatMap((character) => [character.charCodeAt(0), 0]))]) for (let at = find(executable.data, encoded); at >= 0; at = find(executable.data, encoded, at + 1)) await add(rule, severity, "medium", effect, explanation, remediation, executable.path, at, 0, executable.data.slice(at));
    if (!required.some((item) => item.startsWith("openconsole.net@"))) for (const marker of ["EFI_HTTP_PROTOCOL", "EFI_TCP4_PROTOCOL", "EFI_UDP4_PROTOCOL", "http://", "https://"]) { const needle = new TextEncoder().encode(marker.toLowerCase()); for (let at = findAsciiCaseInsensitive(executable.data, needle); at >= 0; at = findAsciiCaseInsensitive(executable.data, needle, at + 1)) await add("OCSA-NETWORK-UNDECLARED", "high", "medium", "block", "Network-use indicator is present without a required network capability.", "Declare the versioned openconsole.net capability or remove network use.", executable.path, at, 0, executable.data.slice(at)); }
    stages.push({ name: "machine-code-indicators", status: "passed" });
  } catch (error) { await add("OCSA-ANALYSIS-BUDGET", "high", "verified", "inconclusive", (error as Error).message, "Reduce executable size/complexity or request manual review.", executable.path); stages.push({ name: "machine-code-indicators", status: "limit" }); }
  return finish();
}

function find(haystack: Uint8Array, needle: Uint8Array, from = 0): number { outer: for (let i = from; i <= haystack.length - needle.length; i++) { for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer; return i; } return -1; }
function findAsciiCaseInsensitive(haystack: Uint8Array, needle: Uint8Array, from = 0): number { outer: for (let i = from; i <= haystack.length - needle.length; i++) { for (let j = 0; j < needle.length; j++) { const byte = haystack[i + j]; const folded = byte >= 65 && byte <= 90 ? byte + 32 : byte; if (folded !== needle[j]) continue outer; } return i; } return -1; }
