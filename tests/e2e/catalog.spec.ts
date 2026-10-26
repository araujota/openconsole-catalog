import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

test("browse, search, inspect provenance, and reach publisher intake", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "We have to go where they can’t follow." })).toBeVisible();
  await expect(page.getByText("A console you carry.")).toBeVisible();
  await page.getByRole("button", { name: "Games", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Games for a machine with no operating system." })).toBeVisible();
  const game = page.getByRole("button", { name: /Signal Runner/ });
  await expect(game).toBeVisible();
  await page.screenshot({ path: "test-results/catalog-home.png", fullPage: true });

  await page.getByRole("textbox", { name: "Search games by title" }).fill("no-such-game");
  await expect(page.getByRole("heading", { name: "No matching releases" })).toBeVisible();
  await page.getByRole("textbox", { name: "Search games by title" }).fill("Signal");
  await expect(game).toBeVisible();
  await game.click();

  const dialog = page.getByRole("dialog", { name: "Signal Runner" });
  await expect(dialog.getByText("accepted analysis")).toBeVisible();
  await expect(dialog.getByText("Bundle SHA-256")).toBeVisible();
  const expectedDigest = await dialog.locator("dt", { hasText: "Bundle SHA-256" }).locator("+ dd").innerText();
  const downloadPromise = page.waitForEvent("download");
  await dialog.getByRole("button", { name: "Download verified bundle" }).click();
  const download = await downloadPromise;
  const downloadedPath = await download.path();
  expect(downloadedPath).not.toBeNull();
  const actualDigest = createHash("sha256").update(await readFile(downloadedPath!)).digest("hex");
  expect(actualDigest).toBe(expectedDigest);
  await page.getByRole("button", { name: "Close game details" }).click();

  await page.getByRole("button", { name: "Submit" }).click();
  await expect(page.getByRole("heading", { name: "Analyze an OCG2 bundle" })).toBeVisible();
  await expect(page.getByText("Drop a signed .ocg bundle")).toBeVisible();
});

test("runtime downloads distinguish x64 and ARM64 without autodetection", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Download the suitcase EFI" })).toBeVisible();
  await expect(page.getByText("x64 / AMD64", { exact: true })).toBeVisible();
  await expect(page.getByText("ARM64 / AArch64", { exact: true })).toBeVisible();
  await expect(page.getByText("EFI/BOOT/BOOTX64.EFI", { exact: true })).toBeVisible();
  await expect(page.getByText("EFI/BOOT/BOOTAA64.EFI", { exact: true })).toBeVisible();
  const metadata = await page.request.get("/downloads.json");
  expect(metadata.ok()).toBeTruthy();
  const catalog = await metadata.json();
  expect(catalog.runtimes.arm64.repository).toContain("openconsole-arm64");
  expect(catalog.legacyX64.developmentImage).toBe(catalog.runtimes.x64.artifact);
});

test("versioned documentation is navigable, searchable, and agent-readable", async ({ page, request }) => {
  await page.goto("/docs");
  await expect(page.getByRole("heading", { name: "Build games beneath the operating system." })).toBeVisible();
  await page.getByRole("textbox", { name: "Search documentation" }).fill("network");
  await expect(page.getByRole("link", { name: "Input, graphics, network, and audio", exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Input, graphics, network, and audio", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Networking and HTTP" })).toBeVisible();
  await expect(page.getByText(/cannot make ordinary desktop HTTP calls/)).toBeVisible();
  const llms = await request.get("/llms.txt");
  expect(llms.ok()).toBeTruthy();
  expect(await llms.text()).toContain("no operating system");
  const versions = await request.get("/docs/versions.json");
  expect(versions.ok()).toBeTruthy();
  expect((await versions.json()).current).toBe("v0.1");
});

test("upload survives refresh and renders terminal analysis", async ({ page }) => {
  const encoded = await readFile("tests/fixtures/signal-runner-1.0.1.ocg.b64", "utf8");
  const bundle = Buffer.from(encoded.trim(), "base64");
  await page.goto("/");
  await page.getByRole("button", { name: "Submit" }).click();
  await page.locator('input[type="file"]').setInputFiles({ name: "signal-runner.ocg", mimeType: "application/octet-stream", buffer: bundle });
  await page.getByRole("button", { name: "Upload and analyze" }).click();
  await expect(page.getByText("accepted", { exact: true }).first()).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText("No findings in this service ruleset.")).toBeVisible();
  await page.reload();
  await page.getByRole("button", { name: "Submit" }).click();
  await expect(page.getByText("accepted", { exact: true }).first()).toBeVisible({ timeout: 10_000 });
});

test("client rejects the wrong extension and has no serious accessibility violations", async ({ page }) => {
  await page.goto("/");
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations.filter((violation) => ["serious", "critical"].includes(violation.impact ?? ""))).toEqual([]);
  await page.getByRole("button", { name: "Submit" }).click();
  await page.locator('input[type="file"]').setInputFiles({ name: "not-a-bundle.txt", mimeType: "text/plain", buffer: Buffer.from("bad") });
  await page.getByRole("button", { name: "Upload and analyze" }).click();
  await expect(page.getByText("Choose an .ocg bundle.", { exact: true })).toBeVisible();
});
