import { defineConfig } from "@playwright/test";
import { lstatSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const outputRoot = resolve(packageRoot, "output/playwright/medusa-makepay");
const testMatch =
  process.env.MAKEPAY_E2E_TEST_MATCH || "medusa-storefront.spec.mjs";
const allowedTestMatches = new Set([
  "medusa-storefront.spec.mjs",
  "real-sandbox.spec.mjs",
]);
if (!allowedTestMatches.has(testMatch)) {
  throw new Error(
    "Playwright E2E test selection must use an exact allowed filename.",
  );
}
const explicitRealSandbox = process.env.MAKEPAY_E2E_REAL_SANDBOX === "1";
if (explicitRealSandbox && testMatch !== "real-sandbox.spec.mjs") {
  throw new Error(
    "The real sandbox flag requires the exact real-sandbox.spec.mjs selection.",
  );
}
const realSandbox =
  explicitRealSandbox || testMatch === "real-sandbox.spec.mjs";
const manualOAuth = process.env.MAKEPAY_E2E_MANUAL_OAUTH === "1";
const localDiagnostics = process.env.MAKEPAY_E2E_LOCAL_DIAGNOSTICS === "1";
const captureRequested = process.env.MAKEPAY_E2E_CAPTURE === "1";
const playwrightCompletionReceipt =
  process.env.MAKEPAY_E2E_PLAYWRIGHT_COMPLETION_RECEIPT;

if (localDiagnostics && process.env.CI) {
  throw new Error("Local Playwright diagnostics are forbidden when CI is set.");
}
if (localDiagnostics && realSandbox) {
  throw new Error(
    "Local Playwright diagnostics are disabled for the real OAuth sandbox.",
  );
}
if (
  (realSandbox || captureRequested) &&
  (!playwrightCompletionReceipt ||
    !isAbsolute(playwrightCompletionReceipt))
) {
  throw new Error(
    "Captured or real-sandbox Playwright runs require an absolute parent-owned completion receipt.",
  );
}

let playwrightOutputDirectory = resolve(outputRoot, "results");
if (realSandbox) {
  const receiptParent = dirname(playwrightCompletionReceipt);
  const parentEntry = lstatSync(receiptParent);
  if (
    parentEntry.isSymbolicLink() ||
    !parentEntry.isDirectory() ||
    (parentEntry.mode & 0o077) !== 0 ||
    (typeof process.getuid === "function" &&
      parentEntry.uid !== process.getuid())
  ) {
    throw new Error(
      "The real-sandbox Playwright completion receipt must live in a private parent-owned directory.",
    );
  }
  const canonicalParent = realpathSync(receiptParent);
  const fromPackage = relative(packageRoot, canonicalParent);
  if (
    !fromPackage ||
    (!fromPackage.startsWith("..") && !isAbsolute(fromPackage))
  ) {
    throw new Error(
      "Real-sandbox Playwright results must live outside the package workspace.",
    );
  }
  playwrightOutputDirectory = resolve(canonicalParent, "playwright-results");
}

const reporters = [["list"]];
if (localDiagnostics) {
  reporters.push([
    "html",
    { open: "never", outputFolder: resolve(outputRoot, "report") },
  ]);
}
if (playwrightCompletionReceipt) {
  reporters.push([
    "json",
    { outputFile: playwrightCompletionReceipt },
  ]);
}

export default defineConfig({
  expect: { timeout: 15_000 },
  forbidOnly: true,
  fullyParallel: false,
  outputDir: playwrightOutputDirectory,
  reporter: reporters,
  retries: 0,
  testDir: ".",
  testMatch,
  timeout: realSandbox ? 20 * 60_000 : 10 * 60_000,
  use: {
    baseURL: process.env.MAKEPAY_E2E_STOREFRONT_URL,
    channel: manualOAuth ? "chrome" : undefined,
    headless: manualOAuth ? false : undefined,
    ignoreHTTPSErrors: !realSandbox,
    storageState: process.env.MAKEPAY_E2E_STORAGE_STATE || undefined,
    screenshot: localDiagnostics ? "only-on-failure" : "off",
    trace: localDiagnostics ? "retain-on-failure" : "off",
    video: "off",
    viewport: { height: 900, width: 1440 },
  },
  workers: 1,
});
