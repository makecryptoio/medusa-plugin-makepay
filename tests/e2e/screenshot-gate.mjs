import { createHash } from "node:crypto";
import { lstat, readFile, realpath, writeFile } from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
} from "node:path";
import { inflateSync } from "node:zlib";

import {
  artifactProvenanceEquals,
  validateArtifactProvenance,
  validateEvidenceReview,
  validateEvidenceRunCompletion,
} from "./support/evidence.mjs";
import {
  loadReleaseEvidenceCampaign,
} from "./support/release-evidence-campaign.mjs";

const filenames = [
  "connected-makepay-settings.png",
  "makepay-sandbox-checkout.png",
  "makepay-payments-list.png",
  "makepay-order-widget.png",
];
const officialDocumentationOrigin = "https://www.makecrypto.io";
const officialDocumentationPath = "/documentation/makepay/apps/medusa";

const documentationEvidence = new Map([
  [
    "connected-makepay-settings.png",
    {
      caption:
        "Medusa Admin MakePay settings connected to a sandbox company with OAuth and installation webhook health.",
      publicPath:
        "/images/documentation/apps/medusa/connected-makepay-settings.png",
    },
  ],
  [
    "makepay-payments-list.png",
    {
      caption:
        "Medusa Admin MakePay payment list showing the installation-scoped local payment projection.",
      publicPath: "/images/documentation/apps/medusa/makepay-payments-list.png",
    },
  ],
  [
    "makepay-order-widget.png",
    {
      caption:
        "Medusa order details showing the MakePay payment widget and read-only reconciliation controls.",
      publicPath: "/images/documentation/apps/medusa/makepay-order-widget.png",
    },
  ],
  [
    "makepay-sandbox-checkout.png",
    {
      caption:
        "MakePay sandbox hosted checkout opened from the Medusa storefront order flow.",
      publicPath:
        "/images/documentation/apps/medusa/makepay-sandbox-checkout.png",
    },
  ],
]);

const deterministicEvidence = new Map([
  [
    "connected-makepay-settings.png",
    {
      path: /^\/app\/settings\/makepay$/,
      testId: "makepay-settings-page",
      texts: [/Disconnect/i],
    },
  ],
  [
    "makepay-sandbox-checkout.png",
    {
      path: /^\/payment\/pay_e2e_/,
      testId: "sandbox-checkout",
      texts: [/Do not send real funds/i],
    },
  ],
  [
    "makepay-payments-list.png",
    {
      path: /^\/app\/makepay$/,
      testId: "makepay-payments-page",
      texts: [/MakePay payments/i],
    },
  ],
  [
    "makepay-order-widget.png",
    {
      path: /^\/app\/orders\/[^/]+$/,
      testId: "makepay-order-widget",
      texts: [/MakePay/i],
    },
  ],
]);

const realSandboxEvidence = new Map([
  [
    "connected-makepay-settings.png",
    {
      origin: "backend",
      path: /^\/app\/settings\/makepay$/,
      testId: "makepay-settings-page",
      texts: [/Disconnect/i, /Healthy/i, /MakeCrypto OAuth/i],
    },
  ],
  [
    "makepay-sandbox-checkout.png",
    {
      origin: "checkout",
      path: /^\/.+/,
      texts: [/sandbox mode/i, /do not send real funds/i, /20/, /EUR/i],
    },
  ],
  [
    "makepay-payments-list.png",
    {
      origin: "backend",
      path: /^\/app\/makepay$/,
      testId: "makepay-payments-page",
      texts: [/MakePay payments/i],
    },
  ],
  [
    "makepay-order-widget.png",
    {
      origin: "backend",
      path: /^\/app\/orders\/[^/]+$/,
      testId: "makepay-order-widget",
      texts: [/MakePay/i, /automated refunds aren.t supported/i],
    },
  ],
]);

const allowedArguments = new Set([
  "approve-docs",
  "approve-visual",
  "backend-origin",
  "campaign",
  "check",
  "checkout-origin",
  "docs-receipt",
  "manifest",
  "plugin-sha256",
  "plugin-version",
  "published-root",
  "reviewer",
  "sdk-sha256",
  "sdk-version",
]);
const documentationReceiptFields = [
  "caption",
  "currentSrcPath",
  "documentContentType",
  "documentOrigin",
  "docsSourceSha256",
  "documentPath",
  "documentRedirected",
  "documentResponseSha256",
  "documentStatus",
  "manifestEvidenceDigest",
  "manifestRunId",
  "publicPath",
  "renderedDocument",
  "renderedSha256",
  "responseContentType",
  "responseSha256",
  "responseStatus",
  "schemaVersion",
  "sourceFilename",
  "sourceSha256",
  "viewport",
];

function parseArgs(argv) {
  const result = { check: "candidate" };
  const seen = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (!key.startsWith("--")) throw new Error(`Unexpected argument: ${key}`);
    const name = key.slice(2);
    if (!allowedArguments.has(name)) {
      throw new Error(`Unknown argument: ${key}`);
    }
    if (seen.has(name)) throw new Error(`Duplicate argument: ${key}`);
    if (index + 1 >= argv.length || argv[index + 1].startsWith("--")) {
      throw new Error(`Missing value for argument: ${key}`);
    }
    seen.add(name);
    result[name] = argv[index + 1];
    index += 1;
  }
  return result;
}

function hasExactKeys(value, expected) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...expected].sort())
  );
}

const pngSignature = Buffer.from("89504e470d0a1a0a", "hex");
const crcTable = new Uint32Array(256);
for (let value = 0; value < 256; value += 1) {
  let crc = value;
  for (let bit = 0; bit < 8; bit += 1) {
    crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
  }
  crcTable[value] = crc >>> 0;
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const value of buffer) {
    crc = crcTable[(crc ^ value) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngSize(buffer) {
  if (buffer.length < 45 || !buffer.subarray(0, 8).equals(pngSignature)) {
    throw new Error("Evidence file is not a PNG image");
  }
  let offset = 8;
  let dimensions;
  let ended = false;
  let sawIdat = false;
  const compressed = [];
  while (offset < buffer.length) {
    if (offset + 12 > buffer.length) {
      throw new Error("Evidence PNG has a truncated chunk");
    }
    const length = buffer.readUInt32BE(offset);
    const typeStart = offset + 4;
    const dataStart = typeStart + 4;
    const dataEnd = dataStart + length;
    const chunkEnd = dataEnd + 4;
    if (length > 32 * 1024 * 1024 || chunkEnd > buffer.length) {
      throw new Error("Evidence PNG has an invalid chunk length");
    }
    const typeBytes = buffer.subarray(typeStart, dataStart);
    const type = typeBytes.toString("ascii");
    if (!/^[A-Za-z]{4}$/.test(type)) {
      throw new Error("Evidence PNG has an invalid chunk type");
    }
    const data = buffer.subarray(dataStart, dataEnd);
    if (
      crc32(Buffer.concat([typeBytes, data])) !== buffer.readUInt32BE(dataEnd)
    ) {
      throw new Error(`Evidence PNG has an invalid ${type} checksum`);
    }

    if (!dimensions) {
      if (type !== "IHDR" || length !== 13) {
        throw new Error("Evidence PNG must begin with one IHDR chunk");
      }
      const width = data.readUInt32BE(0);
      const height = data.readUInt32BE(4);
      const bitDepth = data[8];
      const colorType = data[9];
      if (
        !width ||
        !height ||
        bitDepth !== 8 ||
        ![0, 2, 4, 6].includes(colorType) ||
        data[10] !== 0 ||
        data[11] !== 0 ||
        data[12] !== 0
      ) {
        throw new Error("Evidence PNG has an unsupported IHDR");
      }
      dimensions = { bitDepth, colorType, height, width };
    } else if (type === "IHDR") {
      throw new Error("Evidence PNG contains multiple IHDR chunks");
    } else if (type === "IDAT") {
      sawIdat = true;
      compressed.push(data);
    } else if (type === "IEND") {
      if (length !== 0 || !sawIdat || chunkEnd !== buffer.length) {
        throw new Error("Evidence PNG has an invalid IEND chunk");
      }
      ended = true;
    } else if (typeBytes[0] >= 65 && typeBytes[0] <= 90 && type !== "PLTE") {
      throw new Error(`Evidence PNG uses unsupported critical chunk ${type}`);
    }
    offset = chunkEnd;
  }
  if (!dimensions || !ended) {
    throw new Error("Evidence PNG is incomplete");
  }

  const channels = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 }[dimensions.colorType];
  const rowBytes = Math.ceil(
    (dimensions.width * channels * dimensions.bitDepth) / 8,
  );
  const expectedLength = (rowBytes + 1) * dimensions.height;
  if (expectedLength > 64 * 1024 * 1024) {
    throw new Error("Evidence PNG expands beyond its size limit");
  }
  let pixels;
  try {
    pixels = inflateSync(Buffer.concat(compressed), {
      maxOutputLength: expectedLength + 1,
    });
  } catch {
    throw new Error("Evidence PNG pixel data cannot be decoded");
  }
  if (pixels.length !== expectedLength) {
    throw new Error("Evidence PNG pixel data has an invalid length");
  }
  const decoded = Buffer.alloc(rowBytes * dimensions.height);
  const paeth = (left, up, upperLeft) => {
    const estimate = left + up - upperLeft;
    const leftDistance = Math.abs(estimate - left);
    const upDistance = Math.abs(estimate - up);
    const upperLeftDistance = Math.abs(estimate - upperLeft);
    if (leftDistance <= upDistance && leftDistance <= upperLeftDistance) {
      return left;
    }
    return upDistance <= upperLeftDistance ? up : upperLeft;
  };
  for (let row = 0; row < dimensions.height; row += 1) {
    const sourceOffset = row * (rowBytes + 1);
    const filter = pixels[sourceOffset];
    if (filter > 4) {
      throw new Error("Evidence PNG uses an invalid row filter");
    }
    const targetOffset = row * rowBytes;
    for (let column = 0; column < rowBytes; column += 1) {
      const raw = pixels[sourceOffset + 1 + column];
      const left =
        column >= channels ? decoded[targetOffset + column - channels] : 0;
      const up = row > 0 ? decoded[targetOffset - rowBytes + column] : 0;
      const upperLeft =
        row > 0 && column >= channels
          ? decoded[targetOffset - rowBytes + column - channels]
          : 0;
      let predictor = 0;
      if (filter === 1) predictor = left;
      if (filter === 2) predictor = up;
      if (filter === 3) predictor = Math.floor((left + up) / 2);
      if (filter === 4) predictor = paeth(left, up, upperLeft);
      decoded[targetOffset + column] = (raw + predictor) & 0xff;
    }
  }

  let visiblePixels = 0;
  let minimumChannel = 255;
  let maximumChannel = 0;
  const colorBuckets = new Set();
  const pixelCount = dimensions.width * dimensions.height;
  for (let offset = 0; offset < decoded.length; offset += channels) {
    const grayscale = dimensions.colorType === 0 || dimensions.colorType === 4;
    const red = decoded[offset];
    const green = grayscale ? red : decoded[offset + 1];
    const blue = grayscale ? red : decoded[offset + 2];
    const alpha =
      dimensions.colorType === 4
        ? decoded[offset + 1]
        : dimensions.colorType === 6
          ? decoded[offset + 3]
          : 255;
    if (alpha < 16) continue;
    visiblePixels += 1;
    minimumChannel = Math.min(minimumChannel, red, green, blue);
    maximumChannel = Math.max(maximumChannel, red, green, blue);
    colorBuckets.add((red >> 5) * 64 + (green >> 5) * 8 + (blue >> 5));
  }
  if (
    visiblePixels / pixelCount < 0.5 ||
    maximumChannel - minimumChannel < 24 ||
    colorBuckets.size < 8
  ) {
    throw new Error(
      "Evidence PNG is transparent, blank, or lacks meaningful visual content",
    );
  }
  return {
    height: dimensions.height,
    pixelSha256: sha256(decoded),
    width: dimensions.width,
  };
}

function sha256(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

function cleanOrigin(value, label, requireHttps = false) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} is not a valid URL origin`);
  }
  if (
    (requireHttps && url.protocol !== "https:") ||
    (!requireHttps && !["http:", "https:"].includes(url.protocol)) ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    throw new Error(
      `${label} must be a clean ${requireHttps ? "HTTPS " : ""}origin`,
    );
  }
  return url.origin;
}

async function reviewArtifactPath(manifestPath, value) {
  if (
    typeof value !== "string" ||
    !value ||
    isAbsolute(value) ||
    value.split(/[\\/]/).some((segment) => !segment || segment === "..") ||
    /[?#]/.test(value)
  ) {
    throw new Error(
      "Rendered review artifacts must use a safe manifest-relative path",
    );
  }
  const root = dirname(manifestPath);
  const target = resolve(root, value);
  const fromRoot = relative(root, target);
  if (!fromRoot || fromRoot.startsWith("..") || isAbsolute(fromRoot)) {
    throw new Error("Rendered review artifact escapes the evidence directory");
  }
  const entry = await lstat(target);
  if (entry.isSymbolicLink() || !entry.isFile() || entry.nlink !== 1) {
    throw new Error(
      "Rendered review artifact must be a regular non-symlink file",
    );
  }
  const [canonicalRoot, canonicalTarget] = await Promise.all([
    realpath(root),
    realpath(target),
  ]);
  const canonicalRelative = relative(canonicalRoot, canonicalTarget);
  if (
    !canonicalRelative ||
    canonicalRelative.startsWith("..") ||
    isAbsolute(canonicalRelative)
  ) {
    throw new Error("Rendered review artifact escapes the evidence directory");
  }
  return { relativePath: fromRoot.replaceAll("\\", "/"), target };
}

async function publishedImagePath(value, selected, expected) {
  if (typeof value !== "string" || !value) {
    throw new Error(
      "A canonical MakeCrypto public root is required for docs approval",
    );
  }
  const root = resolve(value);
  const rootEntry = await lstat(root);
  if (
    rootEntry.isSymbolicLink() ||
    !rootEntry.isDirectory() ||
    basename(root) !== "public" ||
    (typeof process.getuid === "function" && rootEntry.uid !== process.getuid())
  ) {
    throw new Error(
      "The MakeCrypto public root must be an owner-controlled regular directory",
    );
  }
  const canonicalRoot = await realpath(root);
  const appRoot = dirname(root);
  const [packageEntry, docsSourceEntry] = await Promise.all([
    lstat(join(appRoot, "package.json")),
    lstat(join(appRoot, "content/documentation/apps/medusa.mdx")),
  ]);
  if (
    packageEntry.isSymbolicLink() ||
    !packageEntry.isFile() ||
    packageEntry.nlink !== 1 ||
    docsSourceEntry.isSymbolicLink() ||
    !docsSourceEntry.isFile() ||
    docsSourceEntry.nlink !== 1 ||
    (typeof process.getuid === "function" &&
      (packageEntry.uid !== process.getuid() ||
        docsSourceEntry.uid !== process.getuid()))
  ) {
    throw new Error(
      "The MakeCrypto package and Medusa documentation source must be owner-controlled regular files",
    );
  }
  const packageManifest = JSON.parse(
    await readFile(join(appRoot, "package.json"), "utf8"),
  );
  const docsSource = await readFile(
    join(appRoot, "content/documentation/apps/medusa.mdx"),
  );
  const docsText = docsSource.toString("utf8");
  if (
    packageManifest.name !== "@makeswap/makecrypto" ||
    !docsText.includes(`data-makepay-medusa-evidence="${selected.filename}"`) ||
    !docsText.includes(`src="${expected.publicPath}"`) ||
    !docsText.includes(`alt="${expected.caption}"`)
  ) {
    throw new Error(
      `The exact MakeCrypto Medusa figure/caption is missing for ${selected.filename}`,
    );
  }
  const target = resolve(root, `.${expected.publicPath}`);
  const entry = await lstat(target);
  if (
    entry.isSymbolicLink() ||
    !entry.isFile() ||
    entry.nlink !== 1 ||
    (typeof process.getuid === "function" && entry.uid !== process.getuid())
  ) {
    throw new Error(
      "Published documentation image must be an owner-controlled regular non-symlink file",
    );
  }
  const canonicalTarget = await realpath(target);
  const fromRoot = relative(canonicalRoot, canonicalTarget);
  if (
    !fromRoot ||
    fromRoot.startsWith("..") ||
    isAbsolute(fromRoot) ||
    fromRoot.replaceAll("\\", "/") !== expected.publicPath.replace(/^\/+/, "")
  ) {
    throw new Error(
      `Published documentation image escapes the canonical public root: ${selected.filename}`,
    );
  }
  const image = await readFile(target);
  if (sha256(image) !== selected.sha256) {
    throw new Error(
      `Published documentation image does not byte-match ${selected.filename}`,
    );
  }
  const size = pngSize(image);
  if (size.width !== 1440 || size.height !== 900) {
    throw new Error(
      `Published documentation image must decode at 1440x900: ${selected.filename}`,
    );
  }
  return { docsSourceSha256: sha256(docsSource), image };
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizedHtmlText(value) {
  return value
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/\s+/g, " ")
    .trim();
}

async function fetchOfficialPublication(pathname, contentType) {
  const url = `${officialDocumentationOrigin}${pathname}`;
  const response = await fetch(url, {
    headers: {
      accept: contentType,
      "cache-control": "no-cache, no-store",
      pragma: "no-cache",
    },
    redirect: "manual",
  });
  const responseType = (response.headers.get("content-type") || "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (
    response.url !== url ||
    response.status !== 200 ||
    responseType !== contentType
  ) {
    throw new Error(
      `Official MakeCrypto publication did not serve ${pathname} directly as ${contentType}`,
    );
  }
  return response;
}

async function validateOfficialDocumentationPublication(manifest) {
  const documentationResponse = await fetchOfficialPublication(
    officialDocumentationPath,
    "text/html",
  );
  const contentLength = Number(
    documentationResponse.headers.get("content-length") || 0,
  );
  if (
    !Number.isFinite(contentLength) ||
    contentLength < 0 ||
    contentLength > 5 * 1024 * 1024
  ) {
    throw new Error("Official MakeCrypto Medusa documentation is too large");
  }
  const documentation = await documentationResponse.text();
  if (Buffer.byteLength(documentation) > 5 * 1024 * 1024) {
    throw new Error("Official MakeCrypto Medusa documentation is too large");
  }

  for (const entry of manifest.evidence) {
    const expected = documentationEvidence.get(entry.filename);
    if (!expected) {
      throw new Error(
        `No official documentation binding is defined for ${entry.filename}`,
      );
    }
    const figureMatches = [
      ...documentation.matchAll(
        new RegExp(
          `<figure\\b[^>]*\\bdata-makepay-medusa-evidence=(["'])${escapeRegExp(entry.filename)}\\1[^>]*>[\\s\\S]*?<\\/figure>`,
          "gi",
        ),
      ),
    ];
    if (figureMatches.length !== 1) {
      throw new Error(
        `Official MakeCrypto documentation does not render exactly one figure for ${entry.filename}`,
      );
    }
    const figure = figureMatches[0][0];
    const image = figure.match(/<img\b[^>]*>/i)?.[0] || "";
    const caption = figure.match(
      /<figcaption\b[^>]*>([\s\S]*?)<\/figcaption>/i,
    )?.[1];
    if (
      !new RegExp(
        `\\bsrc=(["'])${escapeRegExp(expected.publicPath)}\\1`,
        "i",
      ).test(image) ||
      !new RegExp(
        `\\balt=(["'])${escapeRegExp(expected.caption)}\\1`,
        "i",
      ).test(image) ||
      caption === undefined ||
      normalizedHtmlText(caption) !== expected.caption
    ) {
      throw new Error(
        `Official MakeCrypto documentation figure is not bound to ${entry.filename}`,
      );
    }

    const imageResponse = await fetchOfficialPublication(
      expected.publicPath,
      "image/png",
    );
    const imageLength = Number(
      imageResponse.headers.get("content-length") || 0,
    );
    if (
      !Number.isFinite(imageLength) ||
      imageLength < 0 ||
      imageLength > 32 * 1024 * 1024
    ) {
      throw new Error(
        `Official MakeCrypto image is too large: ${entry.filename}`,
      );
    }
    const imageBytes = Buffer.from(await imageResponse.arrayBuffer());
    if (
      imageBytes.length > 32 * 1024 * 1024 ||
      sha256(imageBytes) !== entry.sha256
    ) {
      throw new Error(
        `Official MakeCrypto image does not byte-match ${entry.filename}`,
      );
    }
    const dimensions = pngSize(imageBytes);
    if (dimensions.width !== 1440 || dimensions.height !== 900) {
      throw new Error(
        `Official MakeCrypto image must decode at 1440x900: ${entry.filename}`,
      );
    }
  }
}

async function loadDocumentationReceipt({
  completionBinding,
  entry,
  manifest,
  manifestPath,
  receiptDocument,
}) {
  const receiptArtifact = await reviewArtifactPath(
    manifestPath,
    receiptDocument,
  );
  if (
    !receiptArtifact.relativePath.startsWith("review-artifacts/") ||
    !receiptArtifact.relativePath.endsWith(".json")
  ) {
    throw new Error(
      "Documentation verification receipt must be a review-artifacts JSON file",
    );
  }
  const receiptBytes = await readFile(receiptArtifact.target);
  let receipt;
  try {
    receipt = JSON.parse(receiptBytes.toString("utf8"));
  } catch {
    throw new Error("Documentation verification receipt is not valid JSON");
  }
  const expected = documentationEvidence.get(entry.filename);
  if (
    !expected ||
    !hasExactKeys(receipt, documentationReceiptFields) ||
    !hasExactKeys(receipt.viewport, ["height", "width"]) ||
    receipt.schemaVersion !== 2 ||
    receipt.sourceFilename !== entry.filename ||
    receipt.sourceSha256 !== entry.sha256 ||
    receipt.caption !== expected.caption ||
    receipt.publicPath !== expected.publicPath ||
    receipt.currentSrcPath !== expected.publicPath ||
    receipt.documentContentType !== "text/html" ||
    receipt.documentOrigin !== "http://127.0.0.1:3022" ||
    receipt.documentPath !== "/documentation/makepay/apps/medusa" ||
    receipt.documentRedirected !== false ||
    receipt.documentStatus !== 200 ||
    !/^[a-f0-9]{64}$/.test(receipt.documentResponseSha256) ||
    receipt.responseStatus !== 200 ||
    receipt.responseContentType !== "image/png" ||
    receipt.responseSha256 !== entry.sha256 ||
    receipt.manifestRunId !== manifest.runId ||
    receipt.manifestEvidenceDigest !== completionBinding.evidenceDigest ||
    !/^[a-f0-9]{64}$/.test(receipt.docsSourceSha256) ||
    !/^[a-f0-9]{64}$/.test(receipt.renderedSha256) ||
    receipt.viewport.width !== 1440 ||
    receipt.viewport.height !== 960
  ) {
    throw new Error(
      `Documentation verification receipt is not bound to ${entry.filename}`,
    );
  }
  const renderedArtifact = await reviewArtifactPath(
    manifestPath,
    receipt.renderedDocument,
  );
  if (
    !renderedArtifact.relativePath.startsWith("review-artifacts/") ||
    !renderedArtifact.relativePath.endsWith(".png")
  ) {
    throw new Error(
      "Rendered documentation must be a review-artifacts PNG file",
    );
  }
  const rendered = await readFile(renderedArtifact.target);
  if (
    sha256(rendered) !== receipt.renderedSha256 ||
    receipt.renderedSha256 === entry.sha256
  ) {
    throw new Error(
      `Rendered documentation is stale or reuses the source image: ${entry.filename}`,
    );
  }
  const renderedSize = pngSize(rendered);
  if (renderedSize.width !== 1440 || renderedSize.height !== 960) {
    throw new Error(
      "Rendered documentation must be a 1440x960 browser-page PNG",
    );
  }
  return {
    receipt,
    receiptDocument: receiptArtifact.relativePath,
    receiptSha256: sha256(receiptBytes),
    renderedDocument: renderedArtifact.relativePath,
  };
}

async function validateDocumentationBinding(
  entry,
  manifest,
  manifestPath,
  completionBinding,
) {
  if (entry.docsReview?.status !== "approved") return;
  const expected = documentationEvidence.get(entry.filename);
  const receipt = await loadDocumentationReceipt({
    completionBinding,
    entry,
    manifest,
    manifestPath,
    receiptDocument: entry.docsReview.receiptDocument,
  });
  const acceptedAt = new Date(completionBinding.acceptedAt);
  const visualReviewedAt = new Date(entry.visualReview?.reviewedAt);
  const docsReviewedAt = new Date(entry.docsReview.reviewedAt);
  if (
    !expected ||
    entry.docsReview.sourceFilename !== entry.filename ||
    entry.docsReview.sourceSha256 !== entry.sha256 ||
    entry.docsReview.reviewedSha256 !== entry.sha256 ||
    entry.docsReview.publishedImage !== expected.publicPath ||
    entry.docsReview.publishedImageSha256 !== entry.sha256 ||
    entry.docsReview.caption !== expected.caption ||
    entry.docsReview.receiptDocument !== receipt.receiptDocument ||
    entry.docsReview.receiptSha256 !== receipt.receiptSha256 ||
    entry.docsReview.renderedDocument !== receipt.renderedDocument ||
    entry.docsReview.renderedSha256 !== receipt.receipt.renderedSha256 ||
    entry.docsReview.renderedSha256 === entry.sha256 ||
    Number.isNaN(acceptedAt.getTime()) ||
    Number.isNaN(visualReviewedAt.getTime()) ||
    Number.isNaN(docsReviewedAt.getTime()) ||
    visualReviewedAt.getTime() < acceptedAt.getTime() ||
    docsReviewedAt.getTime() < visualReviewedAt.getTime()
  ) {
    throw new Error(
      `Rendered documentation review is not bound to its selected evidence image and caption: ${entry.filename}`,
    );
  }
}

function validateCorrelation(correlation) {
  if (!correlation || typeof correlation !== "object") {
    throw new Error("Real-sandbox evidence is missing payment correlation");
  }
  const requiredText = [
    "checkoutPath",
    "companyId",
    "customerEmail",
    "medusaStatus",
    "orderId",
    "paymentLinkUid",
    "providerStatus",
  ];
  for (const key of requiredText) {
    if (typeof correlation[key] !== "string" || !correlation[key].trim()) {
      throw new Error(`Real-sandbox correlation is missing ${key}`);
    }
  }
  if (
    Number(correlation.amount) !== 20 ||
    correlation.currency !== "EUR" ||
    !correlation.checkoutPath.startsWith("/") ||
    correlation.checkoutPath.includes("?") ||
    correlation.checkoutPath.includes("#") ||
    !/^order_[A-Za-z0-9]+$/.test(correlation.orderId) ||
    !/^makepay-real-sandbox\+[^@]+@example\.com$/.test(
      correlation.customerEmail,
    )
  ) {
    throw new Error("Real-sandbox payment correlation is invalid");
  }
  const terminal = new Set([
    "canceled",
    "cancelled",
    "complete",
    "expired",
    "failed",
    "paid",
    "refunded",
  ]);
  if (
    terminal.has(correlation.providerStatus.toLowerCase()) ||
    terminal.has(correlation.medusaStatus.toLowerCase())
  ) {
    throw new Error(
      "Real-sandbox screenshot evidence must remain unpaid and nonterminal",
    );
  }
}

function includesLandmark(values, pattern) {
  return values.some((value) => pattern.test(String(value)));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args["approve-visual"] && args["approve-docs"]) {
    throw new Error(
      "Approve exactly one visual or documentation entry per invocation",
    );
  }
  if (!args.manifest || !["candidate", "release"].includes(args.check)) {
    throw new Error(
      "Usage: node screenshot-gate.mjs --manifest output/.../manifest.json --check candidate|release [--approve-visual NAME | --approve-docs NAME --docs-receipt FILE --published-root DIRECTORY] [release provenance/origin arguments]",
    );
  }
  const manifestPath = resolve(args.manifest);
  const manifestEntry = await lstat(manifestPath);
  if (
    manifestEntry.isSymbolicLink() ||
    !manifestEntry.isFile() ||
    manifestEntry.nlink !== 1 ||
    (typeof process.getuid === "function" &&
      manifestEntry.uid !== process.getuid())
  ) {
    throw new Error(
      "Evidence manifest must be an owner-controlled, non-linked regular file",
    );
  }
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  if (
    manifest.schemaVersion !== 3 ||
    !["deterministic", "real-sandbox"].includes(manifest.mode) ||
    !manifest.runId ||
    !Array.isArray(manifest.evidence) ||
    !manifest.evidence.length
  ) {
    throw new Error("Evidence manifest is empty, outdated, or malformed");
  }
  const manifestProvenance = validateArtifactProvenance(
    manifest.artifactProvenance,
    "Evidence manifest artifact provenance",
  );
  if (args.check === "release" && manifest.mode !== "real-sandbox") {
    throw new Error(
      "Deterministic fixture screenshots are QA-only; release evidence must come from a real-sandbox run.",
    );
  }
  if (args.check === "release" && !args["published-root"]) {
    throw new Error(
      "Release evidence requires --published-root for current MakeCrypto source and image revalidation.",
    );
  }
  const completionBinding = args.campaign
    ? await loadReleaseEvidenceCampaign({
        campaignPath: resolve(args.campaign),
        manifestPath,
      })
    : validateEvidenceRunCompletion(manifest);

  let releaseProvenance = null;
  if (args.check === "release") {
    const provenanceArguments = [
      "plugin-sha256",
      "plugin-version",
      "sdk-sha256",
      "sdk-version",
    ];
    const missing = provenanceArguments.filter((name) => !args[name]);
    if (missing.length) {
      throw new Error(
        `Release evidence requires independent artifact provenance arguments: ${missing.map((name) => `--${name}`).join(", ")}`,
      );
    }
    releaseProvenance = validateArtifactProvenance(
      {
        plugin: {
          sha256: args["plugin-sha256"],
          version: args["plugin-version"],
        },
        sdk: {
          sha256: args["sdk-sha256"],
          version: args["sdk-version"],
        },
      },
      "Release artifact provenance",
    );
    if (!artifactProvenanceEquals(releaseProvenance, manifestProvenance)) {
      throw new Error(
        "Release artifact provenance does not match the evidence manifest",
      );
    }
  }

  const requiredEvidence =
    manifest.mode === "real-sandbox"
      ? realSandboxEvidence
      : deterministicEvidence;
  const present = new Set(manifest.evidence.map((entry) => entry.filename));
  if (
    manifest.evidence.length !== filenames.length ||
    present.size !== filenames.length ||
    filenames.some((filename) => !present.has(filename)) ||
    new Set(manifest.evidence.map((entry) => entry.sha256)).size !==
      filenames.length
  ) {
    throw new Error(
      `Evidence must contain exactly four distinct images: ${filenames.join(", ")}`,
    );
  }

  let approvedOrigins = {};
  if (manifest.mode === "real-sandbox") {
    validateCorrelation(manifest.correlation);
    approvedOrigins = {
      backend: cleanOrigin(
        manifest.approvedOrigins?.backend,
        "Manifest backend origin",
        true,
      ),
      checkout: cleanOrigin(
        manifest.approvedOrigins?.checkout,
        "Manifest checkout origin",
        true,
      ),
    };
    if (approvedOrigins.backend === approvedOrigins.checkout) {
      throw new Error(
        "Backend and MakePay checkout evidence origins must be distinct",
      );
    }
    if (args.check === "release") {
      if (!args["backend-origin"] || !args["checkout-origin"]) {
        throw new Error(
          "Release evidence requires --backend-origin and --checkout-origin from the approved sandbox run.",
        );
      }
      if (
        cleanOrigin(args["backend-origin"], "Approved backend origin", true) !==
          approvedOrigins.backend ||
        cleanOrigin(
          args["checkout-origin"],
          "Approved checkout origin",
          true,
        ) !== approvedOrigins.checkout
      ) {
        throw new Error(
          "Release evidence origins do not match the approved sandbox run",
        );
      }
    }
  }

  const sourcePixelHashes = [];
  for (const entry of manifest.evidence) {
    if (!/^[a-z0-9][a-z0-9-]*\.png$/.test(entry.filename)) {
      throw new Error(`Unsafe evidence filename: ${entry.filename}`);
    }
    if (entry.mode !== manifest.mode || entry.runId !== manifest.runId) {
      throw new Error(`Evidence provenance mismatch: ${entry.filename}`);
    }
    const entryProvenance = validateArtifactProvenance(
      entry.artifactProvenance,
      `Evidence artifact provenance (${entry.filename})`,
    );
    if (!artifactProvenanceEquals(entryProvenance, manifestProvenance)) {
      throw new Error(
        `Evidence artifact provenance mismatch: ${entry.filename}`,
      );
    }
    if (
      releaseProvenance &&
      !artifactProvenanceEquals(entryProvenance, releaseProvenance)
    ) {
      throw new Error(
        `Evidence artifact provenance does not match release arguments: ${entry.filename}`,
      );
    }
    const imagePath = join(dirname(manifestPath), entry.filename);
    const imageEntry = await lstat(imagePath);
    if (
      imageEntry.isSymbolicLink() ||
      !imageEntry.isFile() ||
      imageEntry.nlink !== 1 ||
      (typeof process.getuid === "function" &&
        imageEntry.uid !== process.getuid())
    ) {
      throw new Error(
        `Evidence image must be an owner-controlled, non-linked regular file: ${entry.filename}`,
      );
    }
    const image = await readFile(imagePath);
    if (sha256(image) !== entry.sha256) {
      throw new Error(`Evidence hash mismatch: ${entry.filename}`);
    }
    const size = pngSize(image);
    if (size.width !== 1440 || size.height !== 900) {
      throw new Error(`Evidence must be 1440x900: ${entry.filename}`);
    }
    if (entry.viewport?.width !== 1440 || entry.viewport?.height !== 900) {
      throw new Error(
        `Evidence manifest viewport must be 1440x900: ${entry.filename}`,
      );
    }
    sourcePixelHashes.push(size.pixelSha256);
    const url = new URL(entry.url);
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
        `Evidence URL is not canonical and query-free: ${entry.filename}`,
      );
    }
    const expected = requiredEvidence.get(entry.filename);
    if (!expected || !expected.path.test(url.pathname)) {
      throw new Error(`Evidence route mismatch: ${entry.filename}`);
    }
    if (expected.testId && !entry.requiredTestIds?.includes(expected.testId)) {
      throw new Error(`Evidence test landmark mismatch: ${entry.filename}`);
    }
    if (
      expected.texts.some(
        (pattern) => !includesLandmark(entry.requiredTexts || [], pattern),
      )
    ) {
      throw new Error(`Evidence text landmarks mismatch: ${entry.filename}`);
    }
    if (
      !entry.title ||
      (entry.requiredTexts?.length || 0) +
        (entry.requiredTestIds?.length || 0) <
        2
    ) {
      throw new Error(`Evidence landmarks are incomplete: ${entry.filename}`);
    }

    if (manifest.mode === "real-sandbox") {
      if (
        url.protocol !== "https:" ||
        url.origin !== approvedOrigins[expected.origin] ||
        JSON.stringify(entry.correlation) !==
          JSON.stringify(manifest.correlation)
      ) {
        throw new Error(
          `Real-sandbox evidence correlation mismatch: ${entry.filename}`,
        );
      }
      if (
        entry.filename === "makepay-sandbox-checkout.png" &&
        url.pathname !== manifest.correlation.checkoutPath
      ) {
        throw new Error(
          "Hosted checkout evidence does not match the correlated payment link",
        );
      }
      if (
        entry.filename === "makepay-payments-list.png" &&
        !entry.requiredTexts.includes(manifest.correlation.paymentLinkUid)
      ) {
        throw new Error(
          "Payment-list evidence is not correlated to the captured link",
        );
      }
      if (
        entry.filename === "makepay-order-widget.png" &&
        (!entry.requiredTexts.includes(manifest.correlation.paymentLinkUid) ||
          url.pathname !== `/app/orders/${manifest.correlation.orderId}`)
      ) {
        throw new Error(
          "Order-widget evidence is not correlated to the captured order",
        );
      }
    }
    await validateDocumentationBinding(
      entry,
      manifest,
      manifestPath,
      completionBinding,
    );
  }
  if (new Set(sourcePixelHashes).size !== filenames.length) {
    throw new Error(
      "Evidence must contain four visually distinct decoded source images",
    );
  }
  const approvedDocumentation = manifest.evidence.filter(
    (entry) => entry.docsReview?.status === "approved",
  );
  if (
    new Set(
      approvedDocumentation.map((entry) => entry.docsReview.receiptDocument),
    ).size !== approvedDocumentation.length ||
    new Set(
      approvedDocumentation.map((entry) => entry.docsReview.renderedDocument),
    ).size !== approvedDocumentation.length ||
    new Set(
      approvedDocumentation.map((entry) => entry.docsReview.renderedSha256),
    ).size !== approvedDocumentation.length
  ) {
    throw new Error(
      "Documentation reviews must use unique receipts and rendered artifacts",
    );
  }

  const selected =
    args["approve-visual"] || args["approve-docs"]
      ? manifest.evidence.find(
          (entry) =>
            entry.filename === args["approve-visual"] ||
            entry.filename === args["approve-docs"] ||
            entry.filename.replace(/\.png$/, "") === args["approve-visual"] ||
            entry.filename.replace(/\.png$/, "") === args["approve-docs"],
        )
      : null;
  if (args["approve-visual"] || args["approve-docs"]) {
    if (!selected) throw new Error("Requested evidence entry was not found");
    if (!args.reviewer || args.reviewer.toLowerCase() === "automation") {
      throw new Error("A named human/Codex visual reviewer is required");
    }
    const approval = {
      reviewedAt: new Date().toISOString(),
      reviewedSha256: selected.sha256,
      reviewer: args.reviewer,
      status: "approved",
    };
    if (args["approve-visual"]) {
      selected.visualReview = approval;
      validateEvidenceReview(selected.visualReview, "visual");
    }
    if (args["approve-docs"]) {
      if (!args["docs-receipt"] || !args["published-root"]) {
        throw new Error(
          "--docs-receipt and --published-root are required for the docs embedding review",
        );
      }
      if (
        selected.visualReview?.status !== "approved" ||
        selected.visualReview.reviewedSha256 !== selected.sha256
      ) {
        throw new Error(
          "The selected source screenshot needs original-resolution approval before docs approval",
        );
      }
      const expected = documentationEvidence.get(selected.filename);
      if (!expected) {
        throw new Error(
          `No documentation binding is defined for ${selected.filename}`,
        );
      }
      const published = await publishedImagePath(
        args["published-root"],
        selected,
        expected,
      );
      const receiptArtifact = await reviewArtifactPath(
        manifestPath,
        relative(
          dirname(manifestPath),
          resolve(args["docs-receipt"]),
        ).replaceAll("\\", "/"),
      );
      const receipt = await loadDocumentationReceipt({
        completionBinding,
        entry: selected,
        manifest,
        manifestPath,
        receiptDocument: receiptArtifact.relativePath,
      });
      if (receipt.receipt.docsSourceSha256 !== published.docsSourceSha256) {
        throw new Error(
          `Documentation receipt was not generated from the reviewed MakeCrypto source: ${selected.filename}`,
        );
      }
      if (
        manifest.evidence.some(
          (entry) =>
            entry !== selected &&
            entry.docsReview?.status === "approved" &&
            (entry.docsReview.receiptDocument === receipt.receiptDocument ||
              entry.docsReview.renderedDocument === receipt.renderedDocument ||
              entry.docsReview.renderedSha256 ===
                receipt.receipt.renderedSha256),
        )
      ) {
        throw new Error(
          "Documentation reviews must use unique receipts and rendered artifacts",
        );
      }
      selected.docsReview = {
        ...approval,
        caption: expected.caption,
        publishedImage: expected.publicPath,
        publishedImageSha256: sha256(published.image),
        receiptDocument: receipt.receiptDocument,
        receiptSha256: receipt.receiptSha256,
        renderedDocument: receipt.renderedDocument,
        renderedSha256: receipt.receipt.renderedSha256,
        sourceFilename: selected.filename,
        sourceSha256: selected.sha256,
      };
      validateEvidenceReview(selected.docsReview, "docs");
      await validateDocumentationBinding(
        selected,
        manifest,
        manifestPath,
        completionBinding,
      );
    }
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  }

  if (args.check === "release") {
    for (const entry of manifest.evidence) {
      const reviews = [
        ["original-resolution visual", entry.visualReview],
        ["rendered documentation", entry.docsReview],
      ];
      for (const [name, review] of reviews) {
        if (
          review?.status !== "approved" ||
          review.reviewedSha256 !== entry.sha256 ||
          !review.reviewer ||
          !review.reviewedAt
        ) {
          throw new Error(`${name} review is incomplete: ${entry.filename}`);
        }
      }
      const expected = documentationEvidence.get(entry.filename);
      if (!expected) {
        throw new Error(
          `No documentation binding is defined for ${entry.filename}`,
        );
      }
      const published = await publishedImagePath(
        args["published-root"],
        entry,
        expected,
      );
      const documentationBinding = await loadDocumentationReceipt({
        completionBinding,
        entry,
        manifest,
        manifestPath,
        receiptDocument: entry.docsReview.receiptDocument,
      });
      if (
        documentationBinding.receipt.docsSourceSha256 !==
        published.docsSourceSha256
      ) {
        throw new Error(
          `Published MakeCrypto documentation changed after review: ${entry.filename}`,
        );
      }
      const artifact = await reviewArtifactPath(
        manifestPath,
        entry.docsReview.renderedDocument,
      );
      const rendered = await readFile(artifact.target);
      if (sha256(rendered) !== entry.docsReview.renderedSha256) {
        throw new Error(
          `Rendered documentation changed after review: ${entry.filename}`,
        );
      }
      const receiptArtifact = await reviewArtifactPath(
        manifestPath,
        entry.docsReview.receiptDocument,
      );
      const receipt = await readFile(receiptArtifact.target);
      if (sha256(receipt) !== entry.docsReview.receiptSha256) {
        throw new Error(
          `Documentation verification receipt changed after review: ${entry.filename}`,
        );
      }
    }
    await validateOfficialDocumentationPublication(manifest);
  }

  console.log(
    `Screenshot evidence ${args.check} gate passed (${manifest.mode}; ${manifest.evidence.length} image(s)).`,
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
