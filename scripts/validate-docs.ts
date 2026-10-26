// SPDX-License-Identifier: Apache-2.0
import { existsSync } from "node:fs";
import { docs, DOC_VERSION, RUNTIME_REPO, CATALOG_REPO } from "../lib/docs.ts";

const failures: string[] = [];
const slugs = new Set<string>();
for (const page of docs) {
  if (!/^[a-z0-9-]+$/.test(page.slug) || slugs.has(page.slug)) failures.push(`invalid or duplicate slug: ${page.slug}`);
  slugs.add(page.slug);
  if (!page.title || !page.summary || page.sections.length === 0) failures.push(`incomplete page: ${page.slug}`);
  const ids = new Set<string>();
  for (const section of page.sections) {
    if (!section.title || section.body.length === 0 || ids.has(section.id)) failures.push(`invalid section: ${page.slug}#${section.id}`);
    ids.add(section.id);
  }
}
for (const required of ["overview", "quickstart", "manifest", "ocg2", "runtime-services", "signing-analysis", "agents", "contribute"]) if (!slugs.has(required)) failures.push(`missing required page: ${required}`);
const allText = JSON.stringify(docs);
for (const phrase of ["no operating system", "trusted native", "not a sandbox", "OVMF", "not yet claimed"]) if (!allText.toLowerCase().includes(phrase.toLowerCase())) failures.push(`missing limitation language: ${phrase}`);
const integrationRoot = new URL("../../", import.meta.url);
if (existsSync(new URL("examples", integrationRoot))) for (const path of ["../../release-version.json", "../../examples", "../../include", "../../tools/ocg2.py", "../../tools/openconsole_analyzer.py"]) if (!existsSync(new URL(path, import.meta.url))) failures.push(`missing repository path: ${path}`);
if (DOC_VERSION !== "v0.1" || !RUNTIME_REPO.endsWith("/openconsole") || !CATALOG_REPO.endsWith("/openconsole-catalog")) failures.push("version or canonical repository mismatch");
if (failures.length) { console.error(failures.join("\n")); process.exit(1); }
console.log(`PASS: ${docs.length} version-confined documentation pages, paths, identifiers, and limitation language`);
