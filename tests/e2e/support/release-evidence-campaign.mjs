import { createHash } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

import {
  artifactProvenanceEquals,
  evidenceCompletionDigest,
  validateArtifactProvenance,
  validateEvidenceRunCompletion,
  validatePendingRealSandboxEvidenceManifest,
} from "./evidence.mjs";

const campaignFields = [
  "acceptanceDigest",
  "acceptedAt",
  "artifactProvenance",
  "cleanupReceipt",
  "deterministicRun",
  "evidenceDigest",
  "realRun",
  "releaseVersion",
  "reviewer",
  "schemaVersion",
  "strategy",
];
const realRunFields = [
  "artifacts",
  "completed",
  "failure",
  "lastVerifiedCheckpoint",
  "manifest",
];
const artifactFields = ["path", "role", "sha256"];
const fileReferenceFields = ["path", "sha256"];
const cleanupReferenceFields = ["method", "path", "sha256"];
const cleanupReceiptFields = [
  "accepted",
  "activeTokenCount",
  "guardedResetCompleted",
  "installations",
  "method",
  "mutationSecretCount",
  "pluginDisconnectCompleted",
  "runId",
  "schemaVersion",
];
const cleanupInstallationFields = [
  "appDeleted",
  "grantRevoked",
  "installation",
  "paymentLinkUids",
  "subscriptionDisabled",
  "subscriptionHistorical",
];
const requiredArtifactRoles = new Set([
  "old-signer-failure-log",
  "old-signer-start-source",
  "real-backend-a-log",
  "real-backend-b-log",
  "real-sandbox-event-helper-source",
  "real-sandbox-spec-source",
]);
const oneTimeV100Campaign = {
  artifactProvenance: {
    plugin: {
      sha256:
        "f89250fe8f2bb90c9be381496d171da7f864598d32719518c6f3b99e044d775c",
      version: "1.0.0",
    },
    sdk: {
      sha256:
        "b597fc487f3be8829655505d5bbc2966eb02b80421ca6cf8a57d9a507d324672",
      version: "0.4.0",
    },
  },
  artifacts: new Map([
    [
      "old-signer-failure-log",
      {
        path: "campaign/real-08-59/old-installation-b-signer.log",
        sha256:
          "3ea87e78f6d834e542293249d4450d1b1db95e8de23ecf05ef0c70186bd6ecea",
      },
    ],
    [
      "old-signer-start-source",
      {
        path: "campaign/real-08-59/start-old-signer-pre-fix.txt",
        sha256:
          "af641120727ef63692090fdf1c6efd188f6944b72ff201bcb2eb98d4d4a215b3",
      },
    ],
    [
      "real-backend-a-log",
      {
        path: "campaign/real-08-59/backend.log",
        sha256:
          "56075fd715d7dcbe7c6f35473094511d4d1e9064c49bd7edca89c34bf8dd1678",
      },
    ],
    [
      "real-backend-b-log",
      {
        path: "campaign/real-08-59/backend-installation-b.log",
        sha256:
          "76265bb76fb47c05131cffe56c58dcdac0febaf521d3c2da32b9af71234f95a0",
      },
    ],
    [
      "real-sandbox-event-helper-source",
      {
        path: "campaign/real-08-59/real-sandbox-event-helper.mjs",
        sha256:
          "1fe13c91e0525bc506e4c4de77c075d51f24a601d19496a13df64ffc66ec5949",
      },
    ],
    [
      "real-sandbox-spec-source",
      {
        path: "campaign/real-08-59/real-sandbox.spec.mjs",
        sha256:
          "ad2705bafd54bbd78641a1ce84dc3cd57490899bb132d223a1372d2fb4850076",
      },
    ],
  ]),
  deterministic: {
    acceptedAt: "2026-07-27T10:03:49.614Z",
    evidenceDigest:
      "784fefd0d98f26bff6c3f8999e36543d5ef6147bdc69ad3de451e637db0a7d77",
    manifestPath: "campaign/deterministic/manifest.json",
    manifestSha256:
      "d9ae608e468208c977ad4498f6a43c5b18822d4354c32acf07da996419bb4b97",
    runId: "medusa-e2e-2026-07-27T09-55-59-699Z-d9270ffd7b55d590",
  },
  evidenceDigest:
    "a644e5c9fbfb1bfb4aeec33a325fd0c733b612267debfce10991db934d40da8d",
  paymentLinkUid: "06ft5maz2m8zegw7hfb4n0mss6",
  realManifestPath: "manifest.json",
  realRunId:
    "medusa-e2e-2026-07-27T08-59-45-191Z-184868869b5e3f12",
};
const sha256Pattern = /^[a-f0-9]{64}$/;
const safeSegmentPattern = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const safePaymentLinkUid = /^[A-Za-z0-9_-]{1,200}$/;
const secretLikePatterns = [
  /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/,
  /(?:access|refresh)[_-]?token["']?\s*[:=]\s*["'][A-Za-z0-9._-]{16,}/i,
  /\b(?:npm|sbp|vcp)_[A-Za-z0-9_-]{16,}\b/,
  /(?:key|webhook)[_-]?secret\s*[:=]\s*\S{12,}/i,
];

function hasExactKeys(value, expected) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...expected].sort())
  );
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

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function releaseEvidenceCampaignDigest(campaign) {
  if (!campaign || typeof campaign !== "object" || Array.isArray(campaign)) {
    throw new Error("Release evidence campaign is malformed.");
  }
  const { acceptanceDigest: _acceptanceDigest, ...payload } = campaign;
  return sha256(JSON.stringify(canonicalize(payload)));
}

function validateTimestamp(value, label) {
  const timestamp = new Date(value);
  if (
    typeof value !== "string" ||
    Number.isNaN(timestamp.getTime()) ||
    timestamp.toISOString() !== value
  ) {
    throw new Error(`${label} timestamp is invalid.`);
  }
  return timestamp;
}

function validateFileReference(reference, label, fields = fileReferenceFields) {
  if (
    !hasExactKeys(reference, fields) ||
    typeof reference.path !== "string" ||
    !reference.path ||
    isAbsolute(reference.path) ||
    reference.path.includes("\\") ||
    /[?#\0]/.test(reference.path) ||
    reference.path
      .split("/")
      .some(
        (segment) =>
          !segment ||
          segment === "." ||
          segment === ".." ||
          !safeSegmentPattern.test(segment),
      ) ||
    !sha256Pattern.test(reference.sha256)
  ) {
    throw new Error(`${label} file reference is malformed or unsafe.`);
  }
  return reference;
}

async function readOwnerControlledFile(path, label) {
  const resolvedPath = resolve(path);
  const entry = await lstat(resolvedPath);
  if (
    entry.isSymbolicLink() ||
    !entry.isFile() ||
    entry.nlink !== 1 ||
    (typeof process.getuid === "function" && entry.uid !== process.getuid())
  ) {
    throw new Error(`${label} must be an owner-controlled regular file.`);
  }
  return { bytes: await readFile(resolvedPath), path: resolvedPath };
}

async function rejectSymlinkPathComponents(root, referencePath, label) {
  let current = resolve(root);
  const rootEntry = await lstat(current);
  if (rootEntry.isSymbolicLink() || !rootEntry.isDirectory()) {
    throw new Error(
      `${label} must not traverse a linked campaign directory.`,
    );
  }
  for (const segment of referencePath.split("/")) {
    current = resolve(current, segment);
    const entry = await lstat(current);
    if (entry.isSymbolicLink()) {
      throw new Error(
        `${label} must not traverse a linked campaign directory.`,
      );
    }
  }
}

async function readCampaignFile(root, reference, label) {
  validateFileReference(reference, label, Object.keys(reference).sort());
  await rejectSymlinkPathComponents(root, reference.path, label);
  const target = resolve(root, reference.path);
  const fromRoot = relative(root, target);
  if (
    !fromRoot ||
    fromRoot === ".." ||
    fromRoot.startsWith(`..${sep}`) ||
    isAbsolute(fromRoot)
  ) {
    throw new Error(`${label} must stay inside the campaign directory.`);
  }
  const file = await readOwnerControlledFile(target, label);
  const realRoot = await realpath(root);
  const realTarget = await realpath(target);
  const fromRealRoot = relative(realRoot, realTarget);
  if (
    !fromRealRoot ||
    fromRealRoot === ".." ||
    fromRealRoot.startsWith(`..${sep}`) ||
    isAbsolute(fromRealRoot)
  ) {
    throw new Error(`${label} must not traverse a linked campaign directory.`);
  }
  if (sha256(file.bytes) !== reference.sha256) {
    throw new Error(`${label} changed after campaign acceptance.`);
  }
  return { ...file, realPath: realTarget };
}

async function validateManifestImages(manifest, manifestPath, label) {
  const directory = dirname(manifestPath);
  const seen = new Set();
  for (const entry of manifest.evidence) {
    if (
      typeof entry.filename !== "string" ||
      !/^[a-z0-9][a-z0-9-]*\.png$/.test(entry.filename) ||
      seen.has(entry.filename) ||
      !sha256Pattern.test(entry.sha256)
    ) {
      throw new Error(`${label} contains an unsafe or duplicate image.`);
    }
    seen.add(entry.filename);
    const image = await readOwnerControlledFile(
      resolve(directory, entry.filename),
      `${label} image ${entry.filename}`,
    );
    if (sha256(image.bytes) !== entry.sha256) {
      throw new Error(`${label} image changed: ${entry.filename}.`);
    }
  }
}

function jsonLogEntries(bytes) {
  return bytes
    .toString("utf8")
    .split(/\r?\n/)
    .flatMap((line) => {
      if (!line.startsWith("{")) return [];
      try {
        return [JSON.parse(line)];
      } catch {
        return [];
      }
    });
}

function validatePinnedArtifactSemantics(role, bytes) {
  if (role === "old-signer-failure-log") {
    const text = bytes.toString("utf8");
    if (
      !text.includes(
        "Error running script: ENOENT: no such file or directory, chmod '[redacted]'",
      ) ||
      !text.includes('"functionName":"async serveInMemorySigner"') ||
      !text.includes('"functionName":"async realSandboxEventHelper"')
    ) {
      throw new Error(
        "Pinned old-signer failure evidence does not prove the recorded harness-only failure.",
      );
    }
    return;
  }
  const expectedStatuses =
    role === "real-backend-a-log"
      ? [200, 401, 400, 400, 400]
      : role === "real-backend-b-log"
        ? [200, 400, 400, 401]
        : null;
  if (!expectedStatuses) return;
  const webhooks = jsonLogEntries(bytes).filter(
    (entry) => entry.path === "/hooks/makepay/makepay_makepay",
  );
  if (
    JSON.stringify(webhooks.map((entry) => entry.status)) !==
      JSON.stringify(expectedStatuses) ||
    webhooks.some(
      (entry) =>
        entry.method !== "POST" ||
        entry.user_agent !== "makepay-medusa-real-sandbox-e2e/1.0.0",
    )
  ) {
    throw new Error(
      `Pinned ${role} does not prove the expected installation-scoped webhook routing sequence.`,
    );
  }
}

function validateCleanupReceipt(receipt, realManifest) {
  if (
    !hasExactKeys(receipt, cleanupReceiptFields) ||
    receipt.schemaVersion !== 1 ||
    receipt.method !== "guarded-production-reset" ||
    receipt.accepted !== true ||
    receipt.guardedResetCompleted !== true ||
    receipt.pluginDisconnectCompleted !== false ||
    receipt.runId !== realManifest.runId ||
    receipt.activeTokenCount !== 0 ||
    receipt.mutationSecretCount !== 0 ||
    !Array.isArray(receipt.installations) ||
    receipt.installations.length !== 2
  ) {
    throw new Error("Cumulative release cleanup receipt is incomplete.");
  }
  const installations = new Map();
  for (const installation of receipt.installations) {
    if (
      !hasExactKeys(installation, cleanupInstallationFields) ||
      !["a", "b"].includes(installation.installation) ||
      installations.has(installation.installation) ||
      installation.appDeleted !== true ||
      installation.grantRevoked !== true ||
      installation.subscriptionDisabled !== true ||
      installation.subscriptionHistorical !== true ||
      !Array.isArray(installation.paymentLinkUids) ||
      installation.paymentLinkUids.length === 0 ||
      new Set(installation.paymentLinkUids).size !==
        installation.paymentLinkUids.length ||
      installation.paymentLinkUids.some(
        (uid) => typeof uid !== "string" || !safePaymentLinkUid.test(uid),
      )
    ) {
      throw new Error(
        "Cumulative release installation cleanup receipt is invalid.",
      );
    }
    installations.set(installation.installation, installation);
  }
  if (
    installations.size !== 2 ||
    !installations
      .get("a")
      ?.paymentLinkUids.includes(realManifest.correlation.paymentLinkUid)
  ) {
    throw new Error(
      "Cumulative release cleanup did not archive the screenshot-correlated payment link.",
    );
  }
}

export async function loadReleaseEvidenceCampaign({
  campaignPath,
  manifestPath,
}) {
  const campaignFile = await readOwnerControlledFile(
    campaignPath,
    "Release evidence campaign",
  );
  let campaign;
  try {
    campaign = JSON.parse(campaignFile.bytes.toString("utf8"));
  } catch {
    throw new Error("Release evidence campaign is not valid JSON.");
  }
  if (
    !hasExactKeys(campaign, campaignFields) ||
    campaign.schemaVersion !== 1 ||
    campaign.strategy !== "cumulative-real-plus-deterministic" ||
    campaign.releaseVersion !== "1.0.0" ||
    campaign.artifactProvenance?.plugin?.version !== "1.0.0" ||
    typeof campaign.reviewer !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9 ._@()+-]{2,79}$/.test(campaign.reviewer) ||
    campaign.reviewer.toLowerCase() === "automation" ||
    !sha256Pattern.test(campaign.evidenceDigest) ||
    !sha256Pattern.test(campaign.acceptanceDigest)
  ) {
    throw new Error(
      "Only a named, accepted v1.0.0 cumulative release evidence campaign is allowed.",
    );
  }
  const acceptedAt = validateTimestamp(
    campaign.acceptedAt,
    "Release evidence campaign acceptance",
  );
  if (campaign.acceptanceDigest !== releaseEvidenceCampaignDigest(campaign)) {
    throw new Error("Release evidence campaign changed after acceptance.");
  }
  const provenance = validateArtifactProvenance(
    campaign.artifactProvenance,
    "Release evidence campaign artifact provenance",
  );
  if (
    campaign.evidenceDigest !== oneTimeV100Campaign.evidenceDigest ||
    !artifactProvenanceEquals(
      provenance,
      oneTimeV100Campaign.artifactProvenance,
    )
  ) {
    throw new Error(
      "Release evidence campaign is not the reviewed one-time v1.0.0 campaign.",
    );
  }
  if (
    !hasExactKeys(campaign.realRun, realRunFields) ||
    campaign.realRun.completed !== false ||
    campaign.realRun.lastVerifiedCheckpoint !==
      "cross-installation-webhook-isolation" ||
    campaign.realRun.failure !== "test-harness-old-signer-socket-race" ||
    !Array.isArray(campaign.realRun.artifacts) ||
    campaign.realRun.artifacts.length !== requiredArtifactRoles.size ||
    !hasExactKeys(campaign.deterministicRun, ["manifest"]) ||
    !hasExactKeys(campaign.cleanupReceipt, cleanupReferenceFields) ||
    campaign.cleanupReceipt.method !== "guarded-production-reset"
  ) {
    throw new Error(
      "Release evidence campaign may not claim completion beyond the verified real-run checkpoint.",
    );
  }
  if (
    campaign.realRun.manifest?.path !==
      oneTimeV100Campaign.realManifestPath ||
    campaign.deterministicRun.manifest?.path !==
      oneTimeV100Campaign.deterministic.manifestPath ||
    campaign.deterministicRun.manifest?.sha256 !==
      oneTimeV100Campaign.deterministic.manifestSha256
  ) {
    throw new Error(
      "Release evidence campaign is not bound to the reviewed one-time manifests.",
    );
  }

  const root = dirname(campaignFile.path);
  validateFileReference(
    campaign.realRun.manifest,
    "Real-run manifest",
  );
  const realManifestFile = await readCampaignFile(
    root,
    campaign.realRun.manifest,
    "Real-run manifest",
  );
  if (
    (await realpath(resolve(manifestPath))) !==
    (await realpath(realManifestFile.path))
  ) {
    throw new Error(
      "Release evidence campaign is not bound to the selected real manifest.",
    );
  }
  let realManifest;
  try {
    realManifest = JSON.parse(realManifestFile.bytes.toString("utf8"));
  } catch {
    throw new Error("Real-run campaign manifest is not valid JSON.");
  }
  const pending = validatePendingRealSandboxEvidenceManifest(realManifest);
  if (
    realManifest.runId !== oneTimeV100Campaign.realRunId ||
    realManifest.correlation?.paymentLinkUid !==
      oneTimeV100Campaign.paymentLinkUid ||
    campaign.evidenceDigest !== pending.evidenceDigest ||
    !artifactProvenanceEquals(provenance, pending.artifactProvenance)
  ) {
    throw new Error(
      "Release evidence campaign does not match the immutable real evidence.",
    );
  }
  await validateManifestImages(
    realManifest,
    realManifestFile.path,
    "Real-run campaign manifest",
  );

  const artifactRoles = new Set();
  const canonicalArtifactPaths = new Set();
  for (const artifact of campaign.realRun.artifacts) {
    validateFileReference(artifact, "Real-run artifact", artifactFields);
    const expectedArtifact = oneTimeV100Campaign.artifacts.get(artifact.role);
    if (
      !requiredArtifactRoles.has(artifact.role) ||
      artifactRoles.has(artifact.role) ||
      artifact.path !== expectedArtifact?.path ||
      artifact.sha256 !== expectedArtifact?.sha256
    ) {
      throw new Error(
        "Release evidence campaign has missing, duplicate, or unreviewed real-run artifacts.",
      );
    }
    artifactRoles.add(artifact.role);
    const file = await readCampaignFile(root, artifact, artifact.role);
    if (canonicalArtifactPaths.has(file.realPath)) {
      throw new Error(
        "Release evidence campaign artifacts must have distinct canonical files.",
      );
    }
    canonicalArtifactPaths.add(file.realPath);
    if (file.bytes.length === 0) {
      throw new Error(`Release evidence artifact is empty: ${artifact.role}.`);
    }
    const text = file.bytes.toString("utf8");
    if (
      text.includes("\0") ||
      secretLikePatterns.some((pattern) => pattern.test(text))
    ) {
      throw new Error(
        `Release evidence artifact is not safely scrubbed: ${artifact.role}.`,
      );
    }
    validatePinnedArtifactSemantics(artifact.role, file.bytes);
  }
  if (artifactRoles.size !== requiredArtifactRoles.size) {
    throw new Error("Release evidence campaign is missing real-run artifacts.");
  }

  validateFileReference(
    campaign.deterministicRun.manifest,
    "Deterministic manifest",
  );
  const deterministicManifestFile = await readCampaignFile(
    root,
    campaign.deterministicRun.manifest,
    "Deterministic manifest",
  );
  let deterministicManifest;
  try {
    deterministicManifest = JSON.parse(
      deterministicManifestFile.bytes.toString("utf8"),
    );
  } catch {
    throw new Error("Deterministic campaign manifest is not valid JSON.");
  }
  const deterministicAcceptance =
    validateEvidenceRunCompletion(deterministicManifest);
  if (
    deterministicManifest.mode !== "deterministic" ||
    deterministicAcceptance.status !== "accepted" ||
    deterministicManifest.runId !== oneTimeV100Campaign.deterministic.runId ||
    deterministicAcceptance.runId !==
      oneTimeV100Campaign.deterministic.runId ||
    deterministicAcceptance.acceptedAt !==
      oneTimeV100Campaign.deterministic.acceptedAt ||
    deterministicAcceptance.evidenceDigest !==
      oneTimeV100Campaign.deterministic.evidenceDigest ||
    !artifactProvenanceEquals(
      deterministicManifest.artifactProvenance,
      oneTimeV100Campaign.artifactProvenance,
    ) ||
    validateTimestamp(
      deterministicAcceptance.acceptedAt,
      "Deterministic campaign",
    ).getTime() > acceptedAt.getTime()
  ) {
    throw new Error(
      "Cumulative release campaign requires accepted deterministic evidence with matching provenance.",
    );
  }
  await validateManifestImages(
    deterministicManifest,
    deterministicManifestFile.path,
    "Deterministic campaign manifest",
  );

  validateFileReference(
    campaign.cleanupReceipt,
    "Cleanup receipt",
    cleanupReferenceFields,
  );
  const cleanupFile = await readCampaignFile(
    root,
    campaign.cleanupReceipt,
    "Cleanup receipt",
  );
  let cleanupReceipt;
  try {
    cleanupReceipt = JSON.parse(cleanupFile.bytes.toString("utf8"));
  } catch {
    throw new Error("Cumulative release cleanup receipt is not valid JSON.");
  }
  validateCleanupReceipt(cleanupReceipt, realManifest);

  for (const entry of realManifest.evidence) {
    if (
      validateTimestamp(
        entry.capturedAt,
        `Real evidence ${entry.filename}`,
      ).getTime() > acceptedAt.getTime()
    ) {
      throw new Error(
        `Real evidence was captured after campaign acceptance: ${entry.filename}.`,
      );
    }
  }

  return {
    acceptedAt: campaign.acceptedAt,
    artifactProvenance: provenance,
    evidenceDigest: campaign.evidenceDigest,
    realRunId: realManifest.runId,
    releaseVersion: campaign.releaseVersion,
    reviewer: campaign.reviewer,
    status: "accepted",
    strategy: campaign.strategy,
  };
}
