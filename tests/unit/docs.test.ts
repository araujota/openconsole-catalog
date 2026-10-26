import assert from "node:assert/strict";
import test from "node:test";
import { CATALOG_REPO, DOC_VERSION, RUNTIME_REPO, docs, docsBySlug, groups } from "../../lib/docs.ts";

test("documentation index is stable, complete, and searchable", () => {
  assert.equal(DOC_VERSION, "v0.1");
  assert.equal(docsBySlug.size, docs.length);
  assert.ok(docs.length >= 12);
  assert.ok(groups.includes("Runtime"));
  assert.match(docsBySlug.get("agents")!.sections[0].body[0], /no operating system/i);
  assert.match(docsBySlug.get("security-status")!.summary, /threat/i);
});

test("public repository links are distinct and canonical", () => {
  assert.equal(RUNTIME_REPO, "https://github.com/araujota/openconsole");
  assert.equal(CATALOG_REPO, "https://github.com/araujota/openconsole-catalog");
  assert.notEqual(RUNTIME_REPO, CATALOG_REPO);
});
