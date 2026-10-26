import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { analyzeOpenConsoleBundle } from "../../lib/openconsoleAnalyzer.ts";

const TEST_PUBLIC_KEY = Buffer.from(
  "2pGLo+V/3KAyb0bH7IQ7qPyw1X+hXyWIpXuunfVYIQNR5+FVgbJEWcCnzeHoNVgtcXwGmepy6MkA",
  "base64",
);

async function fixture() {
  return Buffer.from((await readFile("tests/fixtures/signal-runner-1.0.1.ocg.b64", "utf8")).trim(), "base64");
}

test("shared analyzer is deterministic and accepts a trusted fixture", async () => {
  const bundle = await fixture();
  const first = await analyzeOpenConsoleBundle(bundle, TEST_PUBLIC_KEY);
  const second = await analyzeOpenConsoleBundle(bundle, TEST_PUBLIC_KEY);
  assert.equal(first.verdict, "accepted");
  assert.equal(first.gameId, "analyzer-fixture");
  assert.equal(first.title, "Signal Runner");
  assert.equal(first.reportDigest, second.reportDigest);
  assert.deepEqual(first, second);
  assert.equal(first.stages.some((stage) => stage.name === "installed-tree" && stage.status === "passed"), true);
});

test("shared analyzer never accepts malformed or untrusted bytes", async () => {
  const malformed = await analyzeOpenConsoleBundle(new TextEncoder().encode("not OCG2"), TEST_PUBLIC_KEY);
  assert.equal(malformed.verdict, "rejected");
  assert.equal(malformed.findings[0].ruleId, "OCSA-CONTAINER-INVALID");
  const untrusted = await analyzeOpenConsoleBundle(await fixture());
  assert.equal(untrusted.verdict, "inconclusive");
  assert.equal(untrusted.publicationAllowed, false);
});
