import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { deflateSync } from "node:zlib";

import {
  attestDeterministicEvidenceRunCompletion,
  attestEvidenceRunCompletion,
  captureEvidence,
  validateDeterministicPlaywrightReport,
  validateEvidenceReview,
  validateEvidenceRunCompletion,
  validateRealSandboxPlaywrightReport,
} from "./e2e/support/evidence.mjs";

const execFileAsync = promisify(execFile);
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const screenshotGate = join(packageRoot, "tests/e2e/screenshot-gate.mjs");
const runId = "medusa-e2e-2026-07-23T00-00-00-000Z-0123456789abcdef";
const artifactProvenance = {
  plugin: { sha256: "a".repeat(64), version: "1.0.0" },
  sdk: { sha256: "b".repeat(64), version: "0.4.0" },
};
const correlation = {
  amount: 20,
  checkoutPath: "/payment/pay_e2e_completion",
  companyId: "company_sandbox",
  currency: "EUR",
  customerEmail: `makepay-real-sandbox+${runId}@example.com`,
  medusaStatus: "pending",
  orderId: "order_completion",
  paymentLinkUid: "pay_e2e_completion",
  providerStatus: "pending",
};
const approvedOrigins = {
  backend: "https://backend-sandbox.example",
  checkout: "https://checkout-sandbox.example",
};
const documentationBindings = {
  "connected-makepay-settings.png": {
    caption:
      "Medusa Admin MakePay settings connected to a sandbox company with OAuth and installation webhook health.",
    publicPath:
      "/images/documentation/apps/medusa/connected-makepay-settings.png",
  },
  "makepay-payments-list.png": {
    caption:
      "Medusa Admin MakePay payment list showing the installation-scoped local payment projection.",
    publicPath: "/images/documentation/apps/medusa/makepay-payments-list.png",
  },
  "makepay-order-widget.png": {
    caption:
      "Medusa order details showing the MakePay payment widget and read-only reconciliation controls.",
    publicPath: "/images/documentation/apps/medusa/makepay-order-widget.png",
  },
  "makepay-sandbox-checkout.png": {
    caption:
      "MakePay sandbox hosted checkout opened from the Medusa storefront order flow.",
    publicPath:
      "/images/documentation/apps/medusa/makepay-sandbox-checkout.png",
  },
};
const completionChecks = {
  artifactInstallVerified: true,
  childProcessesTerminated: true,
  controlPlanesClosed: true,
  foregroundWorkQuiesced: true,
  oauthDisconnected: true,
  paymentLinksArchived: true,
  playwrightScenarioCompleted: true,
  postgresStopped: true,
  runtimeLogsPublished: true,
  runtimeSecretsScrubbed: true,
  temporaryWorkspaceDispositionAccepted: true,
};
const deterministicCompletionChecks = {
  artifactInstallVerified: true,
  childProcessesTerminated: true,
  controlPlanesClosed: true,
  foregroundWorkQuiesced: true,
  playwrightScenarioCompleted: true,
  postgresStopped: true,
  runtimeLogsPublished: true,
  runtimeSecretsScrubbed: true,
  temporaryWorkspaceDispositionAccepted: true,
};
const cleanupReceipt = {
  accepted: true,
  installations: [
    {
      archivedPaymentLinkUids: [correlation.paymentLinkUid],
      disconnected: true,
      installation: "a",
      localDiscoveryKnown: true,
      pendingNativeCount: 0,
      pendingNativeKnown: true,
      unresolvedCount: 0,
    },
    {
      archivedPaymentLinkUids: ["pay_e2e_installation_b"],
      disconnected: true,
      installation: "b",
      localDiscoveryKnown: true,
      pendingNativeCount: 0,
      pendingNativeKnown: true,
      unresolvedCount: 0,
    },
  ],
};

function successfulPlaywrightReport() {
  return {
    errors: [],
    stats: { expected: 1, flaky: 0, skipped: 0, unexpected: 0 },
    suites: [
      {
        specs: [
          {
            file: "tests/e2e/real-sandbox.spec.mjs",
            ok: true,
            tests: [
              {
                results: [{ status: "passed" }],
                status: "expected",
              },
            ],
          },
        ],
        suites: [],
      },
    ],
  };
}

function successfulDeterministicPlaywrightReport() {
  return {
    errors: [],
    stats: { expected: 2, flaky: 0, skipped: 0, unexpected: 0 },
    suites: [
      {
        specs: [0, 1].map(() => ({
          file: "tests/e2e/medusa-storefront.spec.mjs",
          ok: true,
          tests: [
            {
              results: [{ status: "passed" }],
              status: "expected",
            },
          ],
        })),
        suites: [],
      },
    ],
  };
}

const testCrcTable = new Uint32Array(256);
for (let value = 0; value < 256; value += 1) {
  let crc = value;
  for (let bit = 0; bit < 8; bit += 1) {
    crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
  }
  testCrcTable[value] = crc >>> 0;
}

function testCrc32(buffer) {
  let crc = 0xffffffff;
  for (const value of buffer) {
    crc = testCrcTable[(crc ^ value) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const typeBuffer = Buffer.from(type, "ascii");
  const result = Buffer.alloc(data.length + 12);
  result.writeUInt32BE(data.length, 0);
  typeBuffer.copy(result, 4);
  data.copy(result, 8);
  result.writeUInt32BE(
    testCrc32(Buffer.concat([typeBuffer, data])),
    8 + data.length,
  );
  return result;
}

function pngFixture(width = 1440, height = 900, marker = 1) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 6;
  const rowLength = width * 4 + 1;
  const row = Buffer.alloc(rowLength);
  for (let column = 0; column < width; column += 1) {
    const band = Math.floor((column * 16) / width);
    const offset = 1 + column * 4;
    row[offset] = (band * 17 + marker) & 0xff;
    row[offset + 1] = (band * 37 + marker * 3) & 0xff;
    row[offset + 2] = (band * 67 + marker * 7) & 0xff;
    row[offset + 3] = 255;
  }
  const pixels = Buffer.alloc(rowLength * height);
  for (let line = 0; line < height; line += 1) {
    row.copy(pixels, line * rowLength);
  }
  return Buffer.concat([
    Buffer.from("89504e470d0a1a0a", "hex"),
    pngChunk("IHDR", header),
    pngChunk("IDAT", deflateSync(pixels)),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

function transparentPngFixture(width = 1440, height = 900) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 6;
  return Buffer.concat([
    Buffer.from("89504e470d0a1a0a", "hex"),
    pngChunk("IHDR", header),
    pngChunk("IDAT", deflateSync(Buffer.alloc((width * 4 + 1) * height))),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

function pngFixtureWithMetadata(width, height, marker, metadata) {
  const image = pngFixture(width, height, marker);
  return Buffer.concat([
    image.subarray(0, -12),
    pngChunk("tEXt", Buffer.from(`review-note\0${metadata}`, "utf8")),
    image.subarray(-12),
  ]);
}

function fixtureMarker(filename) {
  return (
    {
      "connected-makepay-settings.png": 1,
      "makepay-sandbox-checkout.png": 2,
      "makepay-payments-list.png": 3,
      "makepay-order-widget.png": 4,
    }[filename] || 1
  );
}

function evidenceEntry({
  filename,
  origin,
  pathname,
  requiredTestIds = [],
  requiredTexts,
  title,
}) {
  const image = pngFixture(1440, 900, fixtureMarker(filename));
  return {
    artifactProvenance,
    capturedAt: "2026-07-23T00:00:00.000Z",
    correlation: structuredClone(correlation),
    docsReview: { status: "pending" },
    expectedPath: pathname,
    filename,
    mode: "real-sandbox",
    origin,
    pathname,
    requiredTestIds,
    requiredTexts,
    runId,
    sha256: createHash("sha256").update(image).digest("hex"),
    title,
    url: `${origin}${pathname}`,
    viewport: { height: 900, width: 1440 },
    visualReview: { status: "pending" },
  };
}

function realSandboxManifest() {
  return {
    approvedOrigins,
    artifactProvenance,
    completionAttestation: null,
    correlation: structuredClone(correlation),
    evidence: [
      evidenceEntry({
        filename: "connected-makepay-settings.png",
        origin: approvedOrigins.backend,
        pathname: "/app/settings/makepay",
        requiredTestIds: ["makepay-settings-page"],
        requiredTexts: ["MakePay", "Disconnect", "Healthy", "MakeCrypto OAuth"],
        title: "Medusa",
      }),
      evidenceEntry({
        filename: "makepay-sandbox-checkout.png",
        origin: approvedOrigins.checkout,
        pathname: correlation.checkoutPath,
        requiredTexts: ["Sandbox mode", "Do not send real funds", "20 EUR"],
        title: "MakePay",
      }),
      evidenceEntry({
        filename: "makepay-payments-list.png",
        origin: approvedOrigins.backend,
        pathname: "/app/makepay",
        requiredTestIds: ["makepay-payments-page"],
        requiredTexts: ["MakePay payments", correlation.paymentLinkUid],
        title: "Medusa",
      }),
      evidenceEntry({
        filename: "makepay-order-widget.png",
        origin: approvedOrigins.backend,
        pathname: `/app/orders/${correlation.orderId}`,
        requiredTestIds: ["makepay-order-widget"],
        requiredTexts: [
          "MakePay",
          correlation.paymentLinkUid,
          "Automated refunds aren't supported",
        ],
        title: "Medusa",
      }),
    ],
    mode: "real-sandbox",
    runId,
    schemaVersion: 3,
  };
}

function deterministicManifest() {
  const manifest = realSandboxManifest();
  manifest.approvedOrigins = {};
  manifest.correlation = null;
  manifest.mode = "deterministic";
  for (const entry of manifest.evidence) {
    entry.correlation = null;
    entry.mode = "deterministic";
  }
  const checkout = manifest.evidence.find(
    (entry) => entry.filename === "makepay-sandbox-checkout.png",
  );
  checkout.requiredTestIds = ["sandbox-checkout", "start-payment"];
  return manifest;
}

async function writeGateFixture(directory, manifest = realSandboxManifest()) {
  await mkdir(directory, { recursive: true });
  for (const entry of manifest.evidence) {
    await writeFile(
      join(directory, entry.filename),
      pngFixture(1440, 900, fixtureMarker(entry.filename)),
    );
  }
  const manifestPath = join(directory, "manifest.json");
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
    mode: 0o600,
  });
  return manifestPath;
}

async function writePublishedImages(
  directory,
  manifest = realSandboxManifest(),
) {
  const appRoot = join(directory, "makecrypto");
  const publicRoot = join(appRoot, "public");
  const imageDirectory = join(publicRoot, "images/documentation/apps/medusa");
  await mkdir(imageDirectory, { recursive: true });
  const docsDirectory = join(appRoot, "content/documentation/apps");
  await mkdir(docsDirectory, { recursive: true });
  await writeFile(
    join(appRoot, "package.json"),
    `${JSON.stringify({ name: "@makeswap/makecrypto" }, null, 2)}\n`,
  );
  await writeFile(
    join(docsDirectory, "medusa.mdx"),
    Object.entries(documentationBindings)
      .map(
        ([filename, binding]) =>
          `<figure data-makepay-medusa-evidence="${filename}"><img src="${binding.publicPath}" alt="${binding.caption}" /><figcaption>${binding.caption}</figcaption></figure>`,
      )
      .join("\n"),
  );
  const paths = new Map();
  for (const entry of manifest.evidence) {
    const path = join(imageDirectory, entry.filename);
    await writeFile(path, await readFile(join(directory, entry.filename)));
    paths.set(entry.filename, path);
  }
  return {
    docsSource: join(docsDirectory, "medusa.mdx"),
    paths,
    publicRoot,
  };
}

async function officialPublicationMockEnvironment(directory, publicRoot) {
  const modulePath = join(directory, "official-publication-fetch-mock.mjs");
  await writeFile(
    modulePath,
    `import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const officialOrigin = "https://www.makecrypto.io";
const publicRoot = process.env.MAKEPAY_TEST_PUBLISHED_ROOT;
globalThis.fetch = async (input, init = {}) => {
  const url = new URL(String(input));
  if (url.origin !== officialOrigin || init.redirect !== "manual") {
    throw new Error("Unexpected official-publication request");
  }
  const isDocumentation =
    url.pathname === "/documentation/makepay/apps/medusa";
  const path = isDocumentation
    ? join(dirname(publicRoot), "content/documentation/apps/medusa.mdx")
    : join(publicRoot, url.pathname.replace(/^\\/+/, ""));
  const bytes = await readFile(path);
  const expectedType = isDocumentation ? "text/html" : "image/png";
  const contentType =
    process.env.MAKEPAY_TEST_BAD_PUBLICATION_PATH === url.pathname
      ? "text/plain"
      : expectedType;
  return {
    arrayBuffer: async () =>
      bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
    headers: new Headers({
      "content-length": String(bytes.length),
      "content-type": contentType,
    }),
    status: 200,
    text: async () => bytes.toString("utf8"),
    url: url.href,
  };
};
`,
    { mode: 0o600 },
  );
  return {
    ...process.env,
    MAKEPAY_TEST_PUBLISHED_ROOT: publicRoot,
    NODE_OPTIONS: [
      process.env.NODE_OPTIONS,
      `--import=${pathToFileURL(modulePath).href}`,
    ]
      .filter(Boolean)
      .join(" "),
  };
}

async function writeDocumentationReceipt({
  directory,
  filename,
  manifestPath,
  marker = 1,
}) {
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const entry = manifest.evidence.find(
    (candidate) => candidate.filename === filename,
  );
  const binding = documentationBindings[filename];
  const docsSource = await readFile(
    join(directory, "makecrypto/content/documentation/apps/medusa.mdx"),
  );
  const reviewDirectory = join(directory, "review-artifacts");
  await mkdir(reviewDirectory, { recursive: true });
  const basename = filename.replace(/\.png$/, "");
  const renderedDocument = join(reviewDirectory, `${basename}-rendered.png`);
  const rendered = pngFixture(1440, 960, marker);
  await writeFile(renderedDocument, rendered);
  const receipt = {
    caption: binding.caption,
    currentSrcPath: binding.publicPath,
    documentContentType: "text/html",
    documentOrigin: "http://127.0.0.1:3022",
    docsSourceSha256: createHash("sha256").update(docsSource).digest("hex"),
    documentPath: "/documentation/makepay/apps/medusa",
    documentRedirected: false,
    documentResponseSha256: "c".repeat(64),
    documentStatus: 200,
    manifestEvidenceDigest: manifest.completionAttestation.evidenceDigest,
    manifestRunId: manifest.runId,
    publicPath: binding.publicPath,
    renderedDocument: relative(directory, renderedDocument).replaceAll(
      "\\",
      "/",
    ),
    renderedSha256: createHash("sha256").update(rendered).digest("hex"),
    responseContentType: "image/png",
    responseSha256: entry.sha256,
    responseStatus: 200,
    schemaVersion: 2,
    sourceFilename: filename,
    sourceSha256: entry.sha256,
    viewport: { height: 960, width: 1440 },
  };
  const receiptPath = join(reviewDirectory, `${basename}-receipt.json`);
  await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
  return { receiptPath, renderedDocument };
}

test("real-sandbox gate requires post-run cleanup acceptance and binds it to the evidence", async () => {
  const directory = await mkdtemp(join(tmpdir(), "makepay-evidence-gate-"));
  try {
    const manifestPath = await writeGateFixture(directory);
    await assert.rejects(
      execFileAsync(process.execPath, [
        screenshotGate,
        "--manifest",
        manifestPath,
        "--check",
        "candidate",
      ]),
      /pending parent-harness run acceptance/i,
    );

    const rejectedChecks = {
      ...completionChecks,
      paymentLinksArchived: false,
    };
    await assert.rejects(
      attestEvidenceRunCompletion({
        artifactProvenance,
        checks: rejectedChecks,
        cleanupReceipt,
        manifestPath,
        runId,
      }),
      /paymentLinksArchived/i,
    );
    assert.equal(
      JSON.parse(await readFile(manifestPath, "utf8")).completionAttestation,
      null,
    );

    await attestEvidenceRunCompletion({
      artifactProvenance,
      checks: completionChecks,
      cleanupReceipt,
      manifestPath,
      runId,
    });
    const accepted = JSON.parse(await readFile(manifestPath, "utf8"));
    assert.equal(validateEvidenceRunCompletion(accepted).status, "accepted");
    const gate = await execFileAsync(process.execPath, [
      screenshotGate,
      "--manifest",
      manifestPath,
      "--check",
      "candidate",
    ]);
    assert.match(gate.stdout, /candidate gate passed/i);

    accepted.evidence[0].title = "Changed after cleanup";
    await writeFile(manifestPath, `${JSON.stringify(accepted, null, 2)}\n`);
    await assert.rejects(
      execFileAsync(process.execPath, [
        screenshotGate,
        "--manifest",
        manifestPath,
        "--check",
        "candidate",
      ]),
      /changed after parent-harness run acceptance/i,
    );
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test("Playwright completion requires exactly one passed real-sandbox scenario", () => {
  assert.equal(
    validateRealSandboxPlaywrightReport(successfulPlaywrightReport()),
    true,
  );
  const skipped = successfulPlaywrightReport();
  skipped.stats.expected = 0;
  skipped.stats.skipped = 1;
  skipped.suites[0].specs[0].tests[0].status = "skipped";
  assert.throws(
    () => validateRealSandboxPlaywrightReport(skipped),
    /did not complete successfully/i,
  );
  const wrongSpec = successfulPlaywrightReport();
  wrongSpec.suites[0].specs[0].file = "tests/e2e/another.spec.mjs";
  assert.throws(
    () => validateRealSandboxPlaywrightReport(wrongSpec),
    /did not complete successfully/i,
  );
  const lateFailure = successfulPlaywrightReport();
  lateFailure.stats.expected = 0;
  lateFailure.stats.unexpected = 1;
  lateFailure.suites[0].specs[0].ok = false;
  lateFailure.suites[0].specs[0].tests[0].results[0].status = "failed";
  assert.throws(
    () => validateRealSandboxPlaywrightReport(lateFailure),
    /did not complete successfully/i,
  );

  assert.equal(
    validateDeterministicPlaywrightReport(
      successfulDeterministicPlaywrightReport(),
    ),
    true,
  );
  const incompleteDeterministic = successfulDeterministicPlaywrightReport();
  incompleteDeterministic.stats.expected = 1;
  incompleteDeterministic.suites[0].specs.pop();
  assert.throws(
    () => validateDeterministicPlaywrightReport(incompleteDeterministic),
    /did not complete successfully/i,
  );
});

test("deterministic candidate evidence requires parent-verified Playwright completion and remains QA-only", async () => {
  const directory = await mkdtemp(join(tmpdir(), "makepay-evidence-qa-"));
  try {
    const manifest = deterministicManifest();
    const manifestPath = await writeGateFixture(directory, manifest);
    await assert.rejects(
      execFileAsync(process.execPath, [
        screenshotGate,
        "--manifest",
        manifestPath,
        "--check",
        "candidate",
      ]),
      /pending parent-harness run acceptance/i,
    );
    await assert.rejects(
      attestEvidenceRunCompletion({
        artifactProvenance,
        checks: completionChecks,
        cleanupReceipt,
        manifestPath,
        runId,
      }),
      /Real-sandbox evidence|cannot receive post-run harness acceptance/i,
    );
    const failedReport = successfulDeterministicPlaywrightReport();
    failedReport.stats.expected = 1;
    failedReport.stats.unexpected = 1;
    failedReport.suites[0].specs[1].ok = false;
    failedReport.suites[0].specs[1].tests[0].status = "unexpected";
    failedReport.suites[0].specs[1].tests[0].results[0].status = "failed";
    await assert.rejects(
      attestDeterministicEvidenceRunCompletion({
        artifactProvenance,
        checks: deterministicCompletionChecks,
        manifestPath,
        playwrightReport: failedReport,
        runId,
      }),
      /did not complete successfully/i,
    );
    await assert.rejects(
      attestDeterministicEvidenceRunCompletion({
        artifactProvenance,
        checks: {
          ...deterministicCompletionChecks,
          runtimeSecretsScrubbed: false,
        },
        manifestPath,
        playwrightReport: successfulDeterministicPlaywrightReport(),
        runId,
      }),
      /runtimeSecretsScrubbed/i,
    );
    assert.equal(
      JSON.parse(await readFile(manifestPath, "utf8")).completionAttestation,
      null,
    );
    await attestDeterministicEvidenceRunCompletion({
      artifactProvenance,
      checks: deterministicCompletionChecks,
      manifestPath,
      playwrightReport: successfulDeterministicPlaywrightReport(),
      runId,
    });
    const accepted = JSON.parse(await readFile(manifestPath, "utf8"));
    assert.equal(validateEvidenceRunCompletion(accepted).status, "accepted");
    const candidate = await execFileAsync(process.execPath, [
      screenshotGate,
      "--manifest",
      manifestPath,
      "--check",
      "candidate",
    ]);
    assert.match(candidate.stdout, /candidate gate passed/i);
    await assert.rejects(
      execFileAsync(process.execPath, [
        screenshotGate,
        "--manifest",
        manifestPath,
        "--check",
        "release",
      ]),
      /QA-only/i,
    );
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test("cleanup receipt must cover both installations and the correlated link", async () => {
  const directory = await mkdtemp(join(tmpdir(), "makepay-evidence-receipt-"));
  try {
    const manifestPath = await writeGateFixture(directory);
    const incomplete = structuredClone(cleanupReceipt);
    incomplete.installations[0].archivedPaymentLinkUids = [
      "pay_e2e_wrong_correlation",
    ];
    await assert.rejects(
      attestEvidenceRunCompletion({
        artifactProvenance,
        checks: completionChecks,
        cleanupReceipt: incomplete,
        manifestPath,
        runId,
      }),
      /screenshot-correlated payment link/i,
    );
    assert.equal(
      JSON.parse(await readFile(manifestPath, "utf8")).completionAttestation,
      null,
    );
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test("manifest and review allowlists reject secret or path smuggling", async () => {
  const directory = await mkdtemp(join(tmpdir(), "makepay-evidence-shape-"));
  try {
    const manifest = realSandboxManifest();
    manifest.correlation.oauthState = "oauth-state-must-not-persist";
    const manifestPath = await writeGateFixture(directory, manifest);
    await assert.rejects(
      attestEvidenceRunCompletion({
        artifactProvenance,
        checks: completionChecks,
        cleanupReceipt,
        manifestPath,
        runId,
      }),
      /unknown or missing manifest fields/i,
    );
    assert.throws(
      () =>
        validateEvidenceReview(
          {
            reviewedAt: "2026-07-23T00:00:01.000Z",
            reviewedSha256: "c".repeat(64),
            reviewer: `npm_${"x".repeat(24)}`,
            status: "approved",
          },
          "visual",
        ),
      /secret-like|malformed or unsafe/i,
    );
    assert.throws(
      () =>
        validateEvidenceReview(
          {
            renderedDocument: "/private/rendered.png",
            renderedSha256: "d".repeat(64),
            reviewedAt: "2026-07-23T00:00:01.000Z",
            reviewedSha256: "c".repeat(64),
            reviewer: "Named release reviewer",
            status: "approved",
          },
          "docs",
        ),
      /malformed or unsafe/i,
    );
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test("candidate gate fully decodes PNG evidence", async () => {
  const directory = await mkdtemp(join(tmpdir(), "makepay-evidence-png-"));
  try {
    const manifest = realSandboxManifest();
    const truncated = pngFixture().subarray(0, 24);
    manifest.evidence[0].sha256 = createHash("sha256")
      .update(truncated)
      .digest("hex");
    const manifestPath = await writeGateFixture(directory, manifest);
    await writeFile(join(directory, manifest.evidence[0].filename), truncated);
    await attestEvidenceRunCompletion({
      artifactProvenance,
      checks: completionChecks,
      cleanupReceipt,
      manifestPath,
      runId,
    });
    await assert.rejects(
      execFileAsync(process.execPath, [
        screenshotGate,
        "--manifest",
        manifestPath,
        "--check",
        "candidate",
      ]),
      /not a PNG|truncated|incomplete/i,
    );
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test("candidate gate rejects transparent and duplicate source images", async () => {
  const transparentDirectory = await mkdtemp(
    join(tmpdir(), "makepay-evidence-transparent-"),
  );
  const duplicateDirectory = await mkdtemp(
    join(tmpdir(), "makepay-evidence-duplicate-"),
  );
  try {
    const transparentManifest = realSandboxManifest();
    const transparent = transparentPngFixture();
    transparentManifest.evidence[0].sha256 = createHash("sha256")
      .update(transparent)
      .digest("hex");
    const transparentManifestPath = await writeGateFixture(
      transparentDirectory,
      transparentManifest,
    );
    await writeFile(
      join(transparentDirectory, transparentManifest.evidence[0].filename),
      transparent,
    );
    await attestEvidenceRunCompletion({
      artifactProvenance,
      checks: completionChecks,
      cleanupReceipt,
      manifestPath: transparentManifestPath,
      runId,
    });
    await assert.rejects(
      execFileAsync(process.execPath, [
        screenshotGate,
        "--manifest",
        transparentManifestPath,
        "--check",
        "candidate",
      ]),
      /transparent|blank|meaningful visual content/i,
    );

    const duplicateManifest = realSandboxManifest();
    const duplicatePixels = pngFixtureWithMetadata(
      1440,
      900,
      fixtureMarker(duplicateManifest.evidence[0].filename),
      "different-file-bytes",
    );
    duplicateManifest.evidence[1].sha256 = createHash("sha256")
      .update(duplicatePixels)
      .digest("hex");
    const duplicateManifestPath = await writeGateFixture(
      duplicateDirectory,
      duplicateManifest,
    );
    await writeFile(
      join(duplicateDirectory, duplicateManifest.evidence[1].filename),
      duplicatePixels,
    );
    await attestEvidenceRunCompletion({
      artifactProvenance,
      checks: completionChecks,
      cleanupReceipt,
      manifestPath: duplicateManifestPath,
      runId,
    });
    await assert.rejects(
      execFileAsync(process.execPath, [
        screenshotGate,
        "--manifest",
        duplicateManifestPath,
        "--check",
        "candidate",
      ]),
      /visually distinct decoded source images/i,
    );
  } finally {
    await rm(transparentDirectory, { force: true, recursive: true });
    await rm(duplicateDirectory, { force: true, recursive: true });
  }
});

test("portable reviewed bundle passes the complete release gate", async () => {
  const directory = await mkdtemp(join(tmpdir(), "makepay-evidence-release-"));
  try {
    const manifestPath = await writeGateFixture(directory);
    await attestEvidenceRunCompletion({
      artifactProvenance,
      checks: completionChecks,
      cleanupReceipt,
      manifestPath,
      runId,
    });
    const publishedImages = await writePublishedImages(directory);
    const releaseFilenames = realSandboxManifest().evidence.map(
      (entry) => entry.filename,
    );
    for (const [index, filename] of releaseFilenames.entries()) {
      await execFileAsync(process.execPath, [
        screenshotGate,
        "--manifest",
        manifestPath,
        "--approve-visual",
        filename,
        "--reviewer",
        "Named release reviewer",
        "--check",
        "candidate",
      ]);
      const { receiptPath } = await writeDocumentationReceipt({
        directory,
        filename,
        manifestPath,
        marker: index + 1,
      });
      await execFileAsync(process.execPath, [
        screenshotGate,
        "--manifest",
        manifestPath,
        "--approve-docs",
        filename,
        "--docs-receipt",
        receiptPath,
        "--published-root",
        publishedImages.publicRoot,
        "--reviewer",
        "Named documentation reviewer",
        "--check",
        "candidate",
      ]);
    }

    const releaseArguments = [
      screenshotGate,
      "--manifest",
      manifestPath,
      "--backend-origin",
      approvedOrigins.backend,
      "--checkout-origin",
      approvedOrigins.checkout,
      "--plugin-sha256",
      artifactProvenance.plugin.sha256,
      "--plugin-version",
      artifactProvenance.plugin.version,
      "--sdk-sha256",
      artifactProvenance.sdk.sha256,
      "--sdk-version",
      artifactProvenance.sdk.version,
      "--check",
      "release",
    ];
    await assert.rejects(
      execFileAsync(process.execPath, releaseArguments),
      /published-root/i,
    );
    releaseArguments.splice(
      releaseArguments.length - 2,
      0,
      "--published-root",
      publishedImages.publicRoot,
    );
    const publicationEnvironment = await officialPublicationMockEnvironment(
      directory,
      publishedImages.publicRoot,
    );
    const release = await execFileAsync(process.execPath, releaseArguments, {
      env: publicationEnvironment,
    });
    assert.match(release.stdout, /release gate passed/i);
    await assert.rejects(
      execFileAsync(process.execPath, releaseArguments, {
        env: {
          ...publicationEnvironment,
          MAKEPAY_TEST_BAD_PUBLICATION_PATH:
            documentationBindings["makepay-order-widget.png"].publicPath,
        },
      }),
      /did not serve.*directly/i,
    );
    const reviewed = JSON.parse(await readFile(manifestPath, "utf8"));
    assert.equal(
      reviewed.evidence.every(
        (entry) =>
          !isAbsolute(entry.docsReview.renderedDocument) &&
          entry.docsReview.renderedDocument.startsWith("review-artifacts/") &&
          entry.docsReview.sourceFilename === entry.filename &&
          entry.docsReview.sourceSha256 === entry.sha256 &&
          entry.docsReview.publishedImageSha256 === entry.sha256 &&
          entry.docsReview.publishedImage ===
            documentationBindings[entry.filename].publicPath &&
          entry.docsReview.caption ===
            documentationBindings[entry.filename].caption,
      ),
      true,
    );
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test("docs approval requires the exact published image and rejects binding tampering", async () => {
  const directory = await mkdtemp(join(tmpdir(), "makepay-evidence-docs-"));
  try {
    const manifestPath = await writeGateFixture(directory);
    await attestEvidenceRunCompletion({
      artifactProvenance,
      checks: completionChecks,
      cleanupReceipt,
      manifestPath,
      runId,
    });
    const filename = "connected-makepay-settings.png";
    await execFileAsync(process.execPath, [
      screenshotGate,
      "--manifest",
      manifestPath,
      "--approve-visual",
      filename,
      "--reviewer",
      "Named release reviewer",
      "--check",
      "candidate",
    ]);
    const reviewDirectory = join(directory, "review-artifacts");
    await mkdir(reviewDirectory);
    const publishedImages = await writePublishedImages(directory);
    const publishedImage = publishedImages.paths.get(filename);
    const { receiptPath } = await writeDocumentationReceipt({
      directory,
      filename,
      manifestPath,
    });

    await assert.rejects(
      execFileAsync(process.execPath, [
        screenshotGate,
        "--manifest",
        manifestPath,
        "--approve-docs",
        filename,
        "--docs-receipt",
        receiptPath,
        "--reviewer",
        "Named documentation reviewer",
        "--check",
        "candidate",
      ]),
      /--published-root/i,
    );

    await rm(publishedImage);
    await symlink(join(directory, filename), publishedImage);
    await assert.rejects(
      execFileAsync(process.execPath, [
        screenshotGate,
        "--manifest",
        manifestPath,
        "--approve-docs",
        filename,
        "--docs-receipt",
        receiptPath,
        "--published-root",
        publishedImages.publicRoot,
        "--reviewer",
        "Named documentation reviewer",
        "--check",
        "candidate",
      ]),
      /regular non-symlink/i,
    );
    await rm(publishedImage);
    await writeFile(publishedImage, pngFixture(1440, 900, 99));
    await assert.rejects(
      execFileAsync(process.execPath, [
        screenshotGate,
        "--manifest",
        manifestPath,
        "--approve-docs",
        filename,
        "--docs-receipt",
        receiptPath,
        "--published-root",
        publishedImages.publicRoot,
        "--reviewer",
        "Named documentation reviewer",
        "--check",
        "candidate",
      ]),
      /does not byte-match/i,
    );

    await writeFile(publishedImage, pngFixture());
    await execFileAsync(process.execPath, [
      screenshotGate,
      "--manifest",
      manifestPath,
      "--approve-docs",
      filename,
      "--docs-receipt",
      receiptPath,
      "--published-root",
      publishedImages.publicRoot,
      "--reviewer",
      "Named documentation reviewer",
      "--check",
      "candidate",
    ]);
    const approved = JSON.parse(await readFile(manifestPath, "utf8"));
    const tampered = structuredClone(approved);
    tampered.evidence.find(
      (entry) => entry.filename === filename,
    ).docsReview.caption = "A different unrelated documentation caption.";
    await writeFile(manifestPath, `${JSON.stringify(tampered, null, 2)}\n`);
    await assert.rejects(
      execFileAsync(process.execPath, [
        screenshotGate,
        "--manifest",
        manifestPath,
        "--check",
        "candidate",
      ]),
      /not bound to its selected evidence image and caption/i,
    );

    await writeFile(manifestPath, `${JSON.stringify(approved, null, 2)}\n`);
    const releaseArguments = [
      screenshotGate,
      "--manifest",
      manifestPath,
      "--check",
      "release",
      "--published-root",
      publishedImages.publicRoot,
      "--backend-origin",
      approvedOrigins.backend,
      "--checkout-origin",
      approvedOrigins.checkout,
      "--plugin-sha256",
      artifactProvenance.plugin.sha256,
      "--plugin-version",
      artifactProvenance.plugin.version,
      "--sdk-sha256",
      artifactProvenance.sdk.sha256,
      "--sdk-version",
      artifactProvenance.sdk.version,
    ];
    const publicationEnvironment = await officialPublicationMockEnvironment(
      directory,
      publishedImages.publicRoot,
    );
    await writeFile(publishedImage, pngFixture(1440, 900, 99));
    await assert.rejects(
      execFileAsync(process.execPath, releaseArguments, {
        env: publicationEnvironment,
      }),
      /does not byte-match/i,
    );
    await writeFile(publishedImage, pngFixture());

    const docsSource = await readFile(publishedImages.docsSource);
    await writeFile(
      publishedImages.docsSource,
      Buffer.concat([docsSource, Buffer.from("\nChanged after review.\n")]),
    );
    await assert.rejects(
      execFileAsync(process.execPath, releaseArguments, {
        env: publicationEnvironment,
      }),
      /changed after review/i,
    );
    await writeFile(publishedImages.docsSource, docsSource);

    const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
    receipt.responseContentType = "text/html";
    await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
    await assert.rejects(
      execFileAsync(process.execPath, releaseArguments, {
        env: publicationEnvironment,
      }),
      /verification receipt is not bound|receipt changed/i,
    );
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test("approval CLI rejects unknown arguments and mixed review actions", async () => {
  const directory = await mkdtemp(join(tmpdir(), "makepay-evidence-cli-"));
  try {
    const manifestPath = await writeGateFixture(directory);
    await assert.rejects(
      execFileAsync(process.execPath, [
        screenshotGate,
        "--manifest",
        manifestPath,
        "--rendered-document",
        "unbound.png",
        "--check",
        "candidate",
      ]),
      /unknown argument/i,
    );
    await assert.rejects(
      execFileAsync(process.execPath, [
        screenshotGate,
        "--manifest",
        manifestPath,
        "--approve-visual",
        "connected-makepay-settings.png",
        "--approve-docs",
        "makepay-payments-list.png",
        "--reviewer",
        "Named release reviewer",
        "--check",
        "candidate",
      ]),
      /exactly one visual or documentation entry/i,
    );
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test("trusted publishing renders the hard-coded official documentation", async () => {
  const [workflow, renderingGate] = await Promise.all([
    readFile(join(packageRoot, ".github/workflows/publish.yml"), "utf8"),
    readFile(
      join(packageRoot, "tests/e2e/official-documentation-gate.mjs"),
      "utf8",
    ),
  ]);
  assert.match(workflow, /playwright install --with-deps chromium/);
  assert.match(workflow, /node tests\/e2e\/official-documentation-gate\.mjs/);
  assert.match(
    workflow,
    /npm publish "\.\/release-candidate\/\$\{filename\}"/,
  );
  assert.doesNotMatch(
    workflow,
    /npm publish "release-candidate\/\$\{filename\}"/,
  );
  assert.equal(
    (workflow.match(/node-version: 24\.18\.0/g) || []).length,
    2,
  );
  assert.match(workflow, /test "\$\(node --version\)" = "v24\.18\.0"/);
  assert.match(workflow, /test "\$\(npm --version\)" = "11\.16\.0"/);
  assert.match(renderingGate, /https:\/\/www\.makecrypto\.io/);
  assert.match(renderingGate, /chromium\.launch/);
  assert.match(renderingGate, /elementFromPoint/);
  assert.match(renderingGate, /effectiveOpacity/);
  assert.match(renderingGate, /meanChannelDifference/);
  assert.match(renderingGate, /response\.body\(\)/);
  assert.match(
    workflow,
    /Revalidate live documentation after release approval[\s\S]*official-documentation-gate\.mjs[\s\S]*Publish candidate with npm trusted publishing/,
  );
});

test("capture stores canonical path evidence without URL query or fragment values", async () => {
  const directory = await mkdtemp(join(tmpdir(), "makepay-evidence-query-"));
  const queryValue = "oauth_state_must_not_enter_manifest";
  const fragmentValue = "hosted_token_must_not_enter_manifest";
  const page = {
    context: () => ({ pages: () => [page] }),
    getByTestId: () => ({
      scrollIntoViewIfNeeded: async () => {},
      waitFor: async () => {},
    }),
    getByText: () => {
      const locator = {
        count: async () => 0,
        filter: (options) => {
          assert.deepEqual(options, { visible: true });
          return locator;
        },
        first: () => ({
          evaluate: async () => ({
            intersectsViewport: true,
            unobscured: true,
          }),
          waitFor: async (options) => {
            assert.deepEqual(options, {
              state: "visible",
              timeout: 15_000,
            });
          },
        }),
        nth: () => ({ isVisible: async () => false }),
      };
      return locator;
    },
    locator: (selector) => {
      if (selector === "body") {
        return { innerText: async () => "Publication-safe sandbox" };
      }
      return { count: async () => 0 };
    },
    screenshot: async ({ path }) => writeFile(path, pngFixture()),
    title: async () => "MakePay",
    url: () =>
      `https://checkout-sandbox.example/payment/pay_e2e_completion?state=${queryValue}#${fragmentValue}`,
    viewportSize: () => ({ height: 900, width: 1440 }),
  };

  try {
    const result = await captureEvidence({
      artifactProvenance,
      expectedOrigin: approvedOrigins.checkout,
      expectedPath: correlation.checkoutPath,
      expectedTitle: /makepay/i,
      mode: "deterministic",
      name: "makepay-sandbox-checkout",
      outputDirectory: directory,
      page,
      requiredTexts: ["Sandbox mode", "Do not send real funds"],
      runId,
    });
    const serialized = await readFile(result.manifestPath, "utf8");
    const manifest = JSON.parse(serialized);
    assert.equal(
      manifest.evidence[0].url,
      `${approvedOrigins.checkout}${correlation.checkoutPath}`,
    );
    assert.equal(serialized.includes(queryValue), false);
    assert.equal(serialized.includes(fragmentValue), false);
    assert.equal(manifest.completionAttestation, null);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test("capture rejects required text and test-id landmarks outside or obscured in the viewport", async () => {
  const cases = [
    {
      idProof: { intersectsViewport: true, unobscured: true },
      name: "offscreen-text",
      requiredTestIds: [],
      requiredTexts: ["Sandbox mode"],
      textProof: { intersectsViewport: false, unobscured: false },
      error: /outside the capture viewport/i,
    },
    {
      idProof: { intersectsViewport: true, unobscured: false },
      name: "obscured-test-id",
      requiredTestIds: ["sandbox-checkout"],
      requiredTexts: [],
      textProof: { intersectsViewport: true, unobscured: true },
      error: /obscured at capture/i,
    },
    {
      idProof: { intersectsViewport: true, unobscured: true },
      name: "obscured-during-capture",
      requiredTestIds: [],
      requiredTexts: ["Sandbox mode"],
      textProof: (() => {
        let evaluations = 0;
        return () => ({
          intersectsViewport: true,
          unobscured: (evaluations += 1) === 1,
        });
      })(),
      error: /obscured at capture/i,
    },
  ];

  for (const fixture of cases) {
    const directory = await mkdtemp(
      join(tmpdir(), `makepay-evidence-${fixture.name}-`),
    );
    const locator = (proof) => {
      const value = {
        count: async () => 0,
        evaluate: async () =>
          typeof proof === "function" ? proof() : proof,
        filter: () => value,
        first: () => value,
        nth: () => ({ isVisible: async () => false }),
        scrollIntoViewIfNeeded: async () => {},
        waitFor: async () => {},
      };
      return value;
    };
    const page = {
      context: () => ({ pages: () => [page] }),
      getByTestId: () => locator(fixture.idProof),
      getByText: () => locator(fixture.textProof),
      locator: (selector) =>
        selector === "body"
          ? { innerText: async () => "Publication-safe sandbox" }
          : { count: async () => 0 },
      screenshot: async ({ path }) => writeFile(path, pngFixture()),
      title: async () => "MakePay",
      url: () =>
        "https://checkout-sandbox.example/payment/pay_e2e_completion",
      viewportSize: () => ({ height: 900, width: 1440 }),
    };

    try {
      await assert.rejects(
        captureEvidence({
          artifactProvenance,
          expectedOrigin: approvedOrigins.checkout,
          expectedPath: correlation.checkoutPath,
          expectedTitle: /makepay/i,
          mode: "deterministic",
          name: fixture.name,
          outputDirectory: directory,
          page,
          requiredTestIds: fixture.requiredTestIds,
          requiredTexts: fixture.requiredTexts,
          runId,
        }),
        fixture.error,
      );
      await assert.rejects(
        readFile(join(directory, `${fixture.name}.png`)),
        { code: "ENOENT" },
      );
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  }
});
