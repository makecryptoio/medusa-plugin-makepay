import { createHash, randomUUID } from "node:crypto";
import {
  lstat,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

const forbiddenText = [
  /codex/i,
  /chatgpt/i,
  /unhandled runtime error/i,
  /application error/i,
  /something went wrong/i,
  /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/,
  /\b(?:access|refresh)_[A-Za-z0-9_-]{16,}\b/i,
  /\b(?:npm|sbp|vcp)_[A-Za-z0-9_-]{16,}\b/,
  /key[_ -]?secret\s*[:=]\s*\S+/i,
  /webhook[_ -]?secret\s*[:=]\s*\S+/i,
];

const provenancePackages = ["plugin", "sdk"];
const provenanceFields = ["sha256", "version"];
const evidenceSchemaVersion = 3;
const completionCheckNames = [
  "artifactInstallVerified",
  "childProcessesTerminated",
  "controlPlanesClosed",
  "foregroundWorkQuiesced",
  "oauthDisconnected",
  "paymentLinksArchived",
  "playwrightScenarioCompleted",
  "postgresStopped",
  "runtimeLogsPublished",
  "runtimeSecretsScrubbed",
  "temporaryWorkspaceDispositionAccepted",
];
const deterministicCompletionCheckNames = [
  "artifactInstallVerified",
  "childProcessesTerminated",
  "controlPlanesClosed",
  "foregroundWorkQuiesced",
  "playwrightScenarioCompleted",
  "postgresStopped",
  "runtimeLogsPublished",
  "runtimeSecretsScrubbed",
  "temporaryWorkspaceDispositionAccepted",
];
const completionAttestationFields = [
  "acceptedAt",
  "checks",
  "evidenceDigest",
  "mode",
  "runId",
  "scenario",
  "status",
];
const manifestFields = [
  "approvedOrigins",
  "artifactProvenance",
  "completionAttestation",
  "correlation",
  "evidence",
  "mode",
  "runId",
  "schemaVersion",
];
const evidenceFields = [
  "artifactProvenance",
  "capturedAt",
  "correlation",
  "docsReview",
  "expectedPath",
  "filename",
  "mode",
  "origin",
  "pathname",
  "requiredTestIds",
  "requiredTexts",
  "runId",
  "sha256",
  "title",
  "url",
  "viewport",
  "visualReview",
];
const correlationFields = [
  "amount",
  "checkoutPath",
  "companyId",
  "currency",
  "customerEmail",
  "medusaStatus",
  "orderId",
  "paymentLinkUid",
  "providerStatus",
];
const sensitiveManifestText = forbiddenText.slice(5);
const packageVersion =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

function hasExactKeys(value, expected) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...expected].sort())
  );
}

export function validateArtifactProvenance(
  value,
  label = "Artifact provenance",
) {
  if (!hasExactKeys(value, provenancePackages)) {
    throw new Error(`${label} must contain exactly plugin and sdk records.`);
  }

  const result = {};
  for (const packageName of provenancePackages) {
    const record = value[packageName];
    if (!hasExactKeys(record, provenanceFields)) {
      throw new Error(
        `${label}.${packageName} must contain exactly sha256 and version.`,
      );
    }
    if (!/^[a-f0-9]{64}$/.test(record.sha256)) {
      throw new Error(
        `${label}.${packageName}.sha256 must be a lowercase SHA-256 digest.`,
      );
    }
    if (
      typeof record.version !== "string" ||
      record.version.trim() !== record.version ||
      !packageVersion.test(record.version)
    ) {
      throw new Error(
        `${label}.${packageName}.version must be an exact semantic version.`,
      );
    }
    result[packageName] = {
      sha256: record.sha256,
      version: record.version,
    };
  }
  return result;
}

export function artifactProvenanceEquals(left, right) {
  try {
    const validatedLeft = validateArtifactProvenance(left);
    const validatedRight = validateArtifactProvenance(right);
    return provenancePackages.every(
      (packageName) =>
        validatedLeft[packageName].sha256 ===
          validatedRight[packageName].sha256 &&
        validatedLeft[packageName].version ===
          validatedRight[packageName].version,
    );
  } catch {
    return false;
  }
}

function playwrightSpecs(report) {
  const specs = [];
  const visit = (suites) => {
    for (const suite of suites || []) {
      specs.push(...(suite.specs || []));
      visit(suite.suites);
    }
  };
  visit(report?.suites);
  return specs;
}

function validatePlaywrightReport(
  report,
  { expectedCount, expectedFile, label },
) {
  const specs = playwrightSpecs(report);
  const stats = report?.stats || {};
  if (
    specs.length !== expectedCount ||
    specs.some((spec) => {
      const testResult = spec?.tests?.[0];
      const lastRun = testResult?.results?.at(-1);
      return (
        basename(spec.file || "") !== expectedFile ||
        spec.ok !== true ||
        spec.tests?.length !== 1 ||
        testResult.status !== "expected" ||
        lastRun?.status !== "passed"
      );
    }) ||
    stats.expected !== expectedCount ||
    (stats.skipped || 0) !== 0 ||
    (stats.unexpected || 0) !== 0 ||
    (stats.flaky || 0) !== 0 ||
    (report?.errors || []).length !== 0
  ) {
    throw new Error(`The exact ${label} did not complete successfully.`);
  }
  return true;
}

export function validateRealSandboxPlaywrightReport(report) {
  return validatePlaywrightReport(report, {
    expectedCount: 1,
    expectedFile: "real-sandbox.spec.mjs",
    label: "real-sandbox Playwright scenario",
  });
}

export function validateDeterministicPlaywrightReport(report) {
  return validatePlaywrightReport(report, {
    expectedCount: 2,
    expectedFile: "medusa-storefront.spec.mjs",
    label: "deterministic Playwright scenario",
  });
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

function assertNoSensitiveManifestText(value, label) {
  if (typeof value === "string") {
    if (sensitiveManifestText.some((pattern) => pattern.test(value))) {
      throw new Error(`${label} contains secret-like text.`);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      assertNoSensitiveManifestText(entry, `${label}[${index}]`),
    );
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) {
      assertNoSensitiveManifestText(entry, `${label}.${key}`);
    }
  }
}

export function validateEvidenceReview(review, kind) {
  if (hasExactKeys(review, ["status"]) && review.status === "pending") return;
  const fields =
    kind === "docs"
      ? [
          "caption",
          "publishedImage",
          "publishedImageSha256",
          "receiptDocument",
          "receiptSha256",
          "renderedDocument",
          "renderedSha256",
          "reviewedAt",
          "reviewedSha256",
          "reviewer",
          "sourceFilename",
          "sourceSha256",
          "status",
        ]
      : ["reviewedAt", "reviewedSha256", "reviewer", "status"];
  if (
    !hasExactKeys(review, fields) ||
    review.status !== "approved" ||
    typeof review.reviewer !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9 ._@()+-]{2,79}$/.test(review.reviewer) ||
    !/^[a-f0-9]{64}$/.test(review.reviewedSha256) ||
    (kind === "docs" &&
      (!/^[a-f0-9]{64}$/.test(review.renderedSha256) ||
        !/^[a-f0-9]{64}$/.test(review.publishedImageSha256) ||
        !/^[a-f0-9]{64}$/.test(review.receiptSha256) ||
        !/^[a-f0-9]{64}$/.test(review.sourceSha256) ||
        typeof review.caption !== "string" ||
        review.caption.trim() !== review.caption ||
        review.caption.length < 10 ||
        review.caption.length > 500 ||
        typeof review.sourceFilename !== "string" ||
        !/^[a-z0-9][a-z0-9-]*\.png$/.test(review.sourceFilename) ||
        typeof review.publishedImage !== "string" ||
        !/^\/images\/documentation\/apps\/medusa\/[a-z0-9][a-z0-9-]*\.png$/.test(
          review.publishedImage,
        ) ||
        typeof review.receiptDocument !== "string" ||
        !review.receiptDocument ||
        isAbsolute(review.receiptDocument) ||
        review.receiptDocument
          .split(/[\\/]/)
          .some((segment) => !segment || segment === "..") ||
        /[?#]/.test(review.receiptDocument) ||
        typeof review.renderedDocument !== "string" ||
        !review.renderedDocument ||
        isAbsolute(review.renderedDocument) ||
        review.renderedDocument
          .split(/[\\/]/)
          .some((segment) => !segment || segment === "..") ||
        /[?#]/.test(review.renderedDocument)))
  ) {
    throw new Error(`Evidence ${kind} review is malformed or unsafe.`);
  }
  const reviewedAt = new Date(review.reviewedAt);
  if (
    Number.isNaN(reviewedAt.getTime()) ||
    reviewedAt.toISOString() !== review.reviewedAt
  ) {
    throw new Error(`Evidence ${kind} review timestamp is invalid.`);
  }
  assertNoSensitiveManifestText(review, `Evidence ${kind} review`);
}

function validateManifestShape(manifest, label) {
  if (
    !hasExactKeys(manifest, manifestFields) ||
    !manifest.approvedOrigins ||
    typeof manifest.approvedOrigins !== "object" ||
    Array.isArray(manifest.approvedOrigins) ||
    !Array.isArray(manifest.evidence)
  ) {
    throw new Error(
      `${label} contains unknown or missing manifest fields.`,
    );
  }
  for (const entry of manifest.evidence) {
    if (
      !hasExactKeys(entry, evidenceFields) ||
      !hasExactKeys(entry.viewport, ["height", "width"]) ||
      entry.viewport.width !== 1440 ||
      entry.viewport.height !== 900 ||
      !Array.isArray(entry.requiredTestIds) ||
      !Array.isArray(entry.requiredTexts) ||
      typeof entry.expectedPath !== "string" ||
      /[?#]/.test(entry.expectedPath)
    ) {
      throw new Error(
        `${label} contains unknown or missing entry fields (${entry.filename}).`,
      );
    }
    validateEvidenceReview(entry.visualReview, "visual");
    validateEvidenceReview(entry.docsReview, "docs");
  }
  assertNoSensitiveManifestText(manifest, `${label} manifest`);
}

function validateRealSandboxManifestShape(manifest) {
  validateManifestShape(manifest, "Real-sandbox evidence");
  if (
    !hasExactKeys(manifest.approvedOrigins, ["backend", "checkout"]) ||
    !hasExactKeys(manifest.correlation, correlationFields)
  ) {
    throw new Error(
      "Real-sandbox evidence contains unknown or missing manifest fields.",
    );
  }
  if (
    typeof manifest.correlation.checkoutPath !== "string" ||
    /[?#]/.test(manifest.correlation.checkoutPath)
  ) {
    throw new Error("Real-sandbox evidence checkout path must be query-free.");
  }
  for (const entry of manifest.evidence) {
    if (!hasExactKeys(entry.correlation, correlationFields)) {
      throw new Error(
        `Real-sandbox evidence contains unknown or missing entry fields (${entry.filename}).`,
      );
    }
  }
}

function validateDeterministicManifestShape(manifest) {
  validateManifestShape(manifest, "Deterministic evidence");
  if (
    !hasExactKeys(manifest.approvedOrigins, []) ||
    manifest.correlation !== null ||
    manifest.evidence.some((entry) => entry.correlation !== null)
  ) {
    throw new Error(
      "Deterministic evidence must not contain sandbox origins or payment correlation.",
    );
  }
}

function completionEvidenceEntry(entry) {
  const {
    docsReview: _docsReview,
    visualReview: _visualReview,
    ...immutable
  } = entry;
  return immutable;
}

function evidenceCompletionDigest(manifest) {
  const payload = canonicalize({
    approvedOrigins: manifest.approvedOrigins || {},
    artifactProvenance: manifest.artifactProvenance,
    correlation: manifest.correlation || null,
    evidence: [...manifest.evidence]
      .sort((left, right) =>
        String(left.filename).localeCompare(String(right.filename)),
      )
      .map(completionEvidenceEntry),
    mode: manifest.mode,
    runId: manifest.runId,
    schemaVersion: manifest.schemaVersion,
  });
  return createHash("sha256").update(JSON.stringify(payload)).digest("hex");
}

function validateCanonicalEvidenceUrls(manifest) {
  for (const entry of manifest.evidence) {
    let url;
    try {
      url = new URL(entry.url);
    } catch {
      throw new Error(
        `Evidence completion contains an invalid URL (${entry.filename}).`,
      );
    }
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      entry.url !== `${url.origin}${url.pathname}` ||
      entry.origin !== url.origin ||
      entry.pathname !== url.pathname
    ) {
      throw new Error(
        `Evidence completion URL must be canonical and query-free (${entry.filename}).`,
      );
    }
  }
}

function validateCompletionChecks(checks) {
  if (!hasExactKeys(checks, completionCheckNames)) {
    throw new Error(
      "Evidence completion checks are incomplete or contain unknown fields.",
    );
  }
  for (const name of completionCheckNames) {
    if (checks[name] !== true) {
      throw new Error(`Evidence completion check did not pass: ${name}.`);
    }
  }
  return Object.fromEntries(completionCheckNames.map((name) => [name, true]));
}

function validateDeterministicCompletionChecks(checks) {
  if (!hasExactKeys(checks, deterministicCompletionCheckNames)) {
    throw new Error(
      "Deterministic evidence completion checks are incomplete or contain unknown fields.",
    );
  }
  for (const name of deterministicCompletionCheckNames) {
    if (checks[name] !== true) {
      throw new Error(
        `Deterministic evidence completion check did not pass: ${name}.`,
      );
    }
  }
  return Object.fromEntries(
    deterministicCompletionCheckNames.map((name) => [name, true]),
  );
}

export function validateEvidenceRunCompletion(manifest) {
  if (
    !manifest ||
    manifest.schemaVersion !== evidenceSchemaVersion ||
    !["deterministic", "real-sandbox"].includes(manifest.mode) ||
    typeof manifest.runId !== "string" ||
    !manifest.runId ||
    !Array.isArray(manifest.evidence) ||
    !manifest.evidence.length
  ) {
    throw new Error("Evidence has no valid completed-run manifest.");
  }
  const realSandbox = manifest.mode === "real-sandbox";
  if (realSandbox) validateRealSandboxManifestShape(manifest);
  else validateDeterministicManifestShape(manifest);
  validateArtifactProvenance(
    manifest.artifactProvenance,
    "Completed evidence artifact provenance",
  );
  validateCanonicalEvidenceUrls(manifest);
  for (const entry of manifest.evidence) {
    if (
      entry.mode !== manifest.mode ||
      entry.runId !== manifest.runId ||
      !artifactProvenanceEquals(
        entry.artifactProvenance,
        manifest.artifactProvenance,
      )
    ) {
      throw new Error(
        `Completed evidence entry provenance mismatch (${entry.filename}).`,
      );
    }
  }

  const attestation = manifest.completionAttestation;
  if (!hasExactKeys(attestation, completionAttestationFields)) {
    throw new Error(
      `${realSandbox ? "Real-sandbox" : "Deterministic"} evidence is pending parent-harness run acceptance.`,
    );
  }
  const expectedScenario = realSandbox
    ? "real-sandbox-playwright"
    : "deterministic-playwright";
  if (
    attestation.status !== "accepted" ||
    attestation.scenario !== expectedScenario ||
    attestation.mode !== manifest.mode ||
    attestation.runId !== manifest.runId ||
    !/^[a-f0-9]{64}$/.test(attestation.evidenceDigest)
  ) {
    throw new Error(
      `${realSandbox ? "Real-sandbox" : "Deterministic"} evidence completion attestation is invalid.`,
    );
  }
  if (realSandbox) validateCompletionChecks(attestation.checks);
  else validateDeterministicCompletionChecks(attestation.checks);

  const acceptedAt = new Date(attestation.acceptedAt);
  if (
    Number.isNaN(acceptedAt.getTime()) ||
    acceptedAt.toISOString() !== attestation.acceptedAt
  ) {
    throw new Error("Evidence completion timestamp is invalid.");
  }
  for (const entry of manifest.evidence) {
    const capturedAt = new Date(entry.capturedAt);
    if (
      Number.isNaN(capturedAt.getTime()) ||
      capturedAt.toISOString() !== entry.capturedAt ||
      capturedAt.getTime() > acceptedAt.getTime()
    ) {
      throw new Error(
        `Evidence was not captured before post-run acceptance (${entry.filename}).`,
      );
    }
  }
  if (attestation.evidenceDigest !== evidenceCompletionDigest(manifest)) {
    throw new Error(
      "Evidence changed after parent-harness run acceptance.",
    );
  }
  return attestation;
}

async function writeJsonAtomically(path, value) {
  const temporaryPath = join(
    dirname(path),
    `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`,
  );
  try {
    await writeFile(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, {
      flag: "wx",
      mode: 0o600,
    });
    await rename(temporaryPath, path);
  } finally {
    await rm(temporaryPath, { force: true });
  }
}

export async function attestEvidenceRunCompletion({
  artifactProvenance,
  checks,
  cleanupReceipt,
  manifestPath,
  runId,
}) {
  const path = resolve(manifestPath);
  const entry = await lstat(path);
  if (
    entry.isSymbolicLink() ||
    !entry.isFile() ||
    entry.nlink !== 1 ||
    (typeof process.getuid === "function" && entry.uid !== process.getuid())
  ) {
    throw new Error(
      "Evidence completion requires an owner-controlled regular manifest.",
    );
  }
  const manifest = JSON.parse(await readFile(path, "utf8"));
  validateRealSandboxManifestShape(manifest);
  if (
    !hasExactKeys(cleanupReceipt, ["accepted", "installations"]) ||
    cleanupReceipt.accepted !== true ||
    !Array.isArray(cleanupReceipt.installations) ||
    cleanupReceipt.installations.length !== 2
  ) {
    throw new Error("Real-sandbox cleanup receipt is incomplete.");
  }
  const installationReceipts = new Map();
  for (const receipt of cleanupReceipt.installations) {
    if (
      !hasExactKeys(receipt, [
        "archivedPaymentLinkUids",
        "disconnected",
        "installation",
        "localDiscoveryKnown",
        "pendingNativeCount",
        "pendingNativeKnown",
        "unresolvedCount",
      ]) ||
      !["a", "b"].includes(receipt.installation) ||
      installationReceipts.has(receipt.installation) ||
      !Array.isArray(receipt.archivedPaymentLinkUids) ||
      receipt.archivedPaymentLinkUids.length === 0 ||
      new Set(receipt.archivedPaymentLinkUids).size !==
        receipt.archivedPaymentLinkUids.length ||
      receipt.archivedPaymentLinkUids.some(
        (uid) => !/^[A-Za-z0-9_-]{1,200}$/.test(uid),
      ) ||
      receipt.disconnected !== true ||
      receipt.localDiscoveryKnown !== true ||
      receipt.pendingNativeKnown !== true ||
      receipt.pendingNativeCount !== 0 ||
      receipt.unresolvedCount !== 0
    ) {
      throw new Error("Real-sandbox installation cleanup receipt is invalid.");
    }
    installationReceipts.set(receipt.installation, receipt);
  }
  if (
    installationReceipts.size !== 2 ||
    !installationReceipts
      .get("a")
      ?.archivedPaymentLinkUids.includes(manifest.correlation.paymentLinkUid)
  ) {
    throw new Error(
      "Real-sandbox cleanup did not archive the screenshot-correlated payment link.",
    );
  }

  const provenance = validateArtifactProvenance(
    artifactProvenance,
    "Harness artifact provenance",
  );
  if (
    manifest.schemaVersion !== evidenceSchemaVersion ||
    manifest.mode !== "real-sandbox" ||
    manifest.runId !== runId ||
    !artifactProvenanceEquals(manifest.artifactProvenance, provenance) ||
    !Array.isArray(manifest.evidence) ||
    !manifest.evidence.length ||
    manifest.completionAttestation !== null
  ) {
    throw new Error(
      "Evidence manifest cannot receive post-run harness acceptance.",
    );
  }
  validateCanonicalEvidenceUrls(manifest);
  for (const evidence of manifest.evidence) {
    if (
      evidence.mode !== manifest.mode ||
      evidence.runId !== manifest.runId ||
      !artifactProvenanceEquals(evidence.artifactProvenance, provenance)
    ) {
      throw new Error(
        `Evidence entry cannot receive harness acceptance (${evidence.filename}).`,
      );
    }
  }

  manifest.completionAttestation = {
    acceptedAt: new Date().toISOString(),
    checks: validateCompletionChecks(checks),
    evidenceDigest: evidenceCompletionDigest(manifest),
    mode: manifest.mode,
    runId: manifest.runId,
    scenario: "real-sandbox-playwright",
    status: "accepted",
  };
  validateEvidenceRunCompletion(manifest);
  await writeJsonAtomically(path, manifest);
  return manifest.completionAttestation;
}

export async function attestDeterministicEvidenceRunCompletion({
  artifactProvenance,
  checks,
  manifestPath,
  playwrightReport,
  runId,
}) {
  validateDeterministicPlaywrightReport(playwrightReport);
  const path = resolve(manifestPath);
  const entry = await lstat(path);
  if (
    entry.isSymbolicLink() ||
    !entry.isFile() ||
    entry.nlink !== 1 ||
    (typeof process.getuid === "function" && entry.uid !== process.getuid())
  ) {
    throw new Error(
      "Deterministic evidence completion requires an owner-controlled regular manifest.",
    );
  }
  const manifest = JSON.parse(await readFile(path, "utf8"));
  validateDeterministicManifestShape(manifest);
  const provenance = validateArtifactProvenance(
    artifactProvenance,
    "Harness artifact provenance",
  );
  if (
    manifest.schemaVersion !== evidenceSchemaVersion ||
    manifest.mode !== "deterministic" ||
    manifest.runId !== runId ||
    !artifactProvenanceEquals(manifest.artifactProvenance, provenance) ||
    !manifest.evidence.length ||
    manifest.completionAttestation !== null
  ) {
    throw new Error(
      "Deterministic evidence manifest cannot receive parent-harness run acceptance.",
    );
  }
  validateCanonicalEvidenceUrls(manifest);
  for (const evidence of manifest.evidence) {
    if (
      evidence.mode !== manifest.mode ||
      evidence.runId !== manifest.runId ||
      !artifactProvenanceEquals(evidence.artifactProvenance, provenance)
    ) {
      throw new Error(
        `Deterministic evidence entry cannot receive parent-harness acceptance (${evidence.filename}).`,
      );
    }
  }

  manifest.completionAttestation = {
    acceptedAt: new Date().toISOString(),
    checks: validateDeterministicCompletionChecks(checks),
    evidenceDigest: evidenceCompletionDigest(manifest),
    mode: manifest.mode,
    runId: manifest.runId,
    scenario: "deterministic-playwright",
    status: "accepted",
  };
  validateEvidenceRunCompletion(manifest);
  await writeJsonAtomically(path, manifest);
  return manifest.completionAttestation;
}

async function assertLandmarkCaptured(locator, label, viewport, evidenceName) {
  const proof = await locator.evaluate(
    (element, expectedViewport) => {
      const rect = element.getBoundingClientRect();
      const left = Math.max(0, rect.left);
      const right = Math.min(expectedViewport.width, rect.right);
      const top = Math.max(0, rect.top);
      const bottom = Math.min(expectedViewport.height, rect.bottom);
      const intersectsViewport =
        rect.width > 0 &&
        rect.height > 0 &&
        right > left &&
        bottom > top &&
        rect.right > 0 &&
        rect.bottom > 0 &&
        rect.left < expectedViewport.width &&
        rect.top < expectedViewport.height;
      if (!intersectsViewport) {
        return { intersectsViewport: false, unobscured: false };
      }
      const x = left + (right - left) / 2;
      const y = top + (bottom - top) / 2;
      const hit = document.elementFromPoint(x, y);
      return {
        intersectsViewport: true,
        unobscured: Boolean(
          hit && (hit === element || element.contains(hit)),
        ),
      };
    },
    viewport,
  );
  if (proof?.intersectsViewport !== true) {
    throw new Error(
      `Evidence landmark is outside the capture viewport (${evidenceName}: ${label}).`,
    );
  }
  if (proof.unobscured !== true) {
    throw new Error(
      `Evidence landmark is obscured at capture (${evidenceName}: ${label}).`,
    );
  }
}

export async function captureEvidence({
  approvedOrigins,
  artifactProvenance,
  correlation,
  expectedPath,
  expectedOrigin,
  expectedTitle,
  mode = "deterministic",
  name,
  outputDirectory,
  page,
  requiredTestIds = [],
  requiredTexts = [],
  runId,
}) {
  const provenance = validateArtifactProvenance(
    artifactProvenance,
    "Evidence artifact provenance",
  );
  if (!new Set(["deterministic", "real-sandbox"]).has(mode)) {
    throw new Error(`Unsupported evidence mode: ${mode}`);
  }
  if (page.context().pages().length !== 1) {
    throw new Error("Evidence capture requires exactly one browser tab.");
  }
  const url = new URL(page.url());
  if (url.username || url.password) {
    throw new Error(`Evidence URL contains credentials (${name}).`);
  }
  if (expectedOrigin && url.origin !== new URL(expectedOrigin).origin) {
    throw new Error(`Evidence origin mismatch for ${name}: ${url.origin}`);
  }
  if (
    typeof expectedPath === "string"
      ? url.pathname !== expectedPath
      : !expectedPath.test(url.pathname)
  ) {
    throw new Error(`Evidence URL mismatch for ${name}: ${url.pathname}`);
  }
  const title = await page.title();
  if (expectedTitle && !expectedTitle.test(title)) {
    throw new Error(`Evidence title mismatch for ${name}: ${title}`);
  }
  const textLandmarks = [];
  for (const text of requiredTexts) {
    const locator = page
      .getByText(text, { exact: false })
      // Responsive pages can keep a hidden desktop/mobile duplicate before
      // the visible landmark in DOM order. Restrict the locator itself so
      // `.first()` cannot wait forever on that hidden duplicate.
      .filter({ visible: true })
      .first();
    await locator.waitFor({ state: "visible", timeout: 15_000 });
    textLandmarks.push({ label: `text ${String(text)}`, locator });
  }
  const testIdLandmarks = [];
  for (const testId of requiredTestIds) {
    const locator = page.getByTestId(testId);
    await locator.waitFor({ state: "visible", timeout: 15_000 });
    testIdLandmarks.push({ label: `test id ${testId}`, locator });
  }
  if (requiredTestIds.length) {
    await page.getByTestId(requiredTestIds[0]).scrollIntoViewIfNeeded();
  }
  const bodyText = await page.locator("body").innerText();
  for (const forbidden of forbiddenText) {
    if (forbidden.test(bodyText)) {
      throw new Error(
        `Evidence contains forbidden text ${forbidden} (${name}).`,
      );
    }
  }
  const visibleInputs = page.locator("input:visible, textarea:visible");
  for (let index = 0; index < (await visibleInputs.count()); index += 1) {
    const value = await visibleInputs
      .nth(index)
      .inputValue()
      .catch(() => "");
    for (const forbidden of forbiddenText) {
      if (value && forbidden.test(value)) {
        throw new Error(
          `Evidence contains a forbidden visible field value (${name}).`,
        );
      }
    }
  }
  if (await page.locator("[data-nextjs-dialog-overlay]").count()) {
    throw new Error(`Next.js development overlay is visible (${name}).`);
  }
  const loading = page.getByText(/loading…|loading\.\.\./i);
  for (let index = 0; index < (await loading.count()); index += 1) {
    if (await loading.nth(index).isVisible()) {
      throw new Error(`Loading state is still visible (${name}).`);
    }
  }

  const viewport = page.viewportSize();
  if (!viewport || viewport.width !== 1440 || viewport.height !== 900) {
    throw new Error(`Evidence viewport must be 1440x900 (${name}).`);
  }
  const assertAllLandmarksCaptured = async () => {
    for (const landmark of [...textLandmarks, ...testIdLandmarks]) {
      await assertLandmarkCaptured(
        landmark.locator,
        landmark.label,
        viewport,
        name,
      );
    }
  };
  await assertAllLandmarksCaptured();

  const directory = resolve(outputDirectory);
  await mkdir(directory, { recursive: true });
  const imagePath = join(directory, `${name}.png`);
  try {
    await page.screenshot({ animations: "disabled", path: imagePath });
    await assertAllLandmarksCaptured();
  } catch (error) {
    await rm(imagePath, { force: true });
    throw error;
  }
  const image = await readFile(imagePath);
  const entry = {
    artifactProvenance: provenance,
    capturedAt: new Date().toISOString(),
    correlation: correlation || null,
    docsReview: { status: "pending" },
    expectedPath: String(expectedPath),
    filename: basename(imagePath),
    mode,
    origin: url.origin,
    pathname: url.pathname,
    requiredTestIds,
    requiredTexts: requiredTexts.map(String),
    runId,
    sha256: createHash("sha256").update(image).digest("hex"),
    title,
    // OAuth state, hosted-checkout tokens, and other query values are never
    // release evidence. Keep only the canonical browser origin and pathname.
    url: `${url.origin}${url.pathname}`,
    viewport,
    visualReview: { status: "pending" },
  };
  const manifestPath = join(directory, "manifest.json");
  let manifest = {
    approvedOrigins: approvedOrigins || {},
    artifactProvenance: provenance,
    completionAttestation: null,
    correlation: correlation || null,
    evidence: [],
    mode,
    runId,
    schemaVersion: evidenceSchemaVersion,
  };
  try {
    const existing = JSON.parse(await readFile(manifestPath, "utf8"));
    if (
      existing.schemaVersion === evidenceSchemaVersion &&
      existing.runId === runId &&
      existing.mode === mode &&
      artifactProvenanceEquals(existing.artifactProvenance, provenance)
    ) {
      manifest = existing;
    }
  } catch {}
  if (manifest.mode !== mode || manifest.runId !== runId) {
    throw new Error("Evidence manifest mode or run ID changed during capture.");
  }
  if (
    correlation &&
    manifest.correlation &&
    JSON.stringify(manifest.correlation) !== JSON.stringify(correlation)
  ) {
    throw new Error("Evidence correlation changed during capture.");
  }
  if (
    approvedOrigins &&
    manifest.approvedOrigins &&
    JSON.stringify(manifest.approvedOrigins) !== JSON.stringify(approvedOrigins)
  ) {
    throw new Error("Evidence approved origins changed during capture.");
  }
  manifest.runId = runId;
  manifest.mode = mode;
  manifest.schemaVersion = evidenceSchemaVersion;
  manifest.artifactProvenance = provenance;
  manifest.completionAttestation = null;
  manifest.correlation = correlation || manifest.correlation || null;
  manifest.approvedOrigins = approvedOrigins || manifest.approvedOrigins || {};
  manifest.evidence = [
    ...manifest.evidence.filter(
      (candidate) => candidate.filename !== entry.filename,
    ),
    entry,
  ];
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return { entry, imagePath, manifestPath };
}
