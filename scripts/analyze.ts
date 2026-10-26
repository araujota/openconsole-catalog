import { readFile } from "node:fs/promises";
import { analyzeOpenConsoleBundle } from "../lib/openconsoleAnalyzer.ts";

const [, , bundlePath, publicKeyPath] = process.argv;
if (!bundlePath || process.argv.length > 4) {
  console.error("usage: npm run analyze -- BUNDLE.ocg [ED448_PUBLIC_KEY.raw]");
  process.exitCode = 64;
} else {
  try {
    const bundle = new Uint8Array(await readFile(bundlePath));
    const publicKey = publicKeyPath ? new Uint8Array(await readFile(publicKeyPath)) : undefined;
    const report = await analyzeOpenConsoleBundle(bundle, publicKey);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    process.exitCode = report.verdict === "accepted" ? 0 : 2;
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 3;
  }
}
