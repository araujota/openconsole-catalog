import assert from "node:assert/strict";
import test from "node:test";
import { runtimeCatalog, runtimes } from "../../lib/runtimes.ts";

test("runtime catalog is architecture-explicit and preserves legacy x64 metadata", () => {
  assert.equal(runtimeCatalog.schema, "openconsole.runtime-releases.v2");
  assert.equal(runtimeCatalog.defaultArchitecture, "x64");
  assert.equal(runtimeCatalog.legacyX64.developmentImage, runtimes.x64.artifact);
  assert.equal(runtimes.x64.bootFile, "EFI/BOOT/BOOTX64.EFI");
  assert.equal(runtimes.arm64.bootFile, "EFI/BOOT/BOOTAA64.EFI");
  assert.match(runtimes.arm64.repository, /openconsole-arm64$/);
  assert.match(runtimes.arm64.artifactUrl, /openconsole-arm64-0\.1\.0-aavmf-preview\.1\.fat$/);
  assert.equal(runtimes.arm64.bytes, 64 * 1024 * 1024);
  assert.match(runtimes.arm64.sha256, /^[0-9a-f]{64}$/);
  assert.match(runtimes.arm64.limitations.join(" "), /networking/i);
  assert.match(runtimes.arm64.limitations.join(" "), /GPU acceleration/i);
});
