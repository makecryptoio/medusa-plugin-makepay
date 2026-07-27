import { createHash, randomUUID } from "node:crypto";
import {
  lstat,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  artifactProvenanceEquals,
  evidenceCompletionDigest,
  validateEvidenceRunCompletion,
  validatePendingRealSandboxEvidenceManifest,
} from "./evidence.mjs";
import {
  loadReleaseEvidenceCampaign,
  releaseEvidenceCampaignDigest,
} from "./release-evidence-campaign.mjs";

const packageRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const campaignRoot = join(packageRoot, ".github/assets/v1.0.0");
const campaignPath = join(campaignRoot, "release-campaign.json");
const realManifestPath = join(campaignRoot, "manifest.json");
const deterministicManifestPath = join(
  campaignRoot,
  "campaign/deterministic/manifest.json",
);

const artifactReferences = [
  {
    path: "campaign/real-08-59/backend.log",
    role: "real-backend-a-log",
  },
  {
    path: "campaign/real-08-59/backend-installation-b.log",
    role: "real-backend-b-log",
  },
  {
    path: "campaign/real-08-59/old-installation-b-signer.log",
    role: "old-signer-failure-log",
  },
  {
    path: "campaign/real-08-59/real-sandbox.spec.mjs",
    role: "real-sandbox-spec-source",
  },
  {
    path: "campaign/real-08-59/real-sandbox-event-helper.mjs",
    role: "real-sandbox-event-helper-source",
  },
  {
    path: "campaign/real-08-59/start-old-signer-pre-fix.txt",
    role: "old-signer-start-source",
  },
];

function parseArguments(argv) {
  const result = {};
  const seen = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (!["--accepted-at", "--reviewer"].includes(argument)) {
      throw new Error(`Unknown argument: ${argument}`);
    }
    if (seen.has(argument)) {
      throw new Error(`Duplicate argument: ${argument}`);
    }
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for argument: ${argument}`);
    }
    seen.add(argument);
    if (argument === "--accepted-at") result.acceptedAt = value;
    else result.reviewer = value;
    index += 1;
  }
  return result;
}

async function readOwnerControlledFile(path, label) {
  const entry = await lstat(path);
  if (
    entry.isSymbolicLink() ||
    !entry.isFile() ||
    entry.nlink !== 1 ||
    (typeof process.getuid === "function" && entry.uid !== process.getuid())
  ) {
    throw new Error(`${label} must be an owner-controlled regular file.`);
  }
  return readFile(path);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function fileReference(path, label) {
  return {
    path,
    sha256: sha256(
      await readOwnerControlledFile(join(campaignRoot, path), label),
    ),
  };
}

const argumentsFromCli = parseArguments(process.argv.slice(2));
const packageJson = JSON.parse(
  await readFile(join(packageRoot, "package.json"), "utf8"),
);
if (packageJson.version !== "1.0.0") {
  throw new Error(
    "The cumulative release campaign builder is restricted to version 1.0.0.",
  );
}

let previousCampaign = {};
let hasPreviousCampaign = false;
try {
  previousCampaign = JSON.parse(
    (
      await readOwnerControlledFile(
        campaignPath,
        "Existing release evidence campaign",
      )
    ).toString("utf8"),
  );
  hasPreviousCampaign = true;
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
}
if (
  hasPreviousCampaign &&
  previousCampaign.acceptanceDigest !==
    releaseEvidenceCampaignDigest(previousCampaign)
) {
  throw new Error(
    "Existing release evidence campaign changed after acceptance.",
  );
}
if (!hasPreviousCampaign && !argumentsFromCli.reviewer) {
  throw new Error(
    "--reviewer is required when creating the release evidence campaign.",
  );
}
if (
  hasPreviousCampaign &&
  argumentsFromCli.reviewer &&
  argumentsFromCli.reviewer !== previousCampaign.reviewer
) {
  throw new Error(
    "An accepted release evidence campaign reviewer cannot be replaced.",
  );
}
if (
  hasPreviousCampaign &&
  argumentsFromCli.acceptedAt &&
  argumentsFromCli.acceptedAt !== previousCampaign.acceptedAt
) {
  throw new Error(
    "An accepted release evidence campaign timestamp cannot be replaced.",
  );
}
// Approval timestamps must remain after campaign acceptance. When screenshot
// approvals rewrite the real manifest, preserve the prior acceptedAt/reviewer
// while refreshing only the file hash and acceptance digest.
const acceptedAt = hasPreviousCampaign
  ? previousCampaign.acceptedAt
  : argumentsFromCli.acceptedAt || new Date().toISOString();
const reviewer = hasPreviousCampaign
  ? previousCampaign.reviewer
  : argumentsFromCli.reviewer;
const acceptedTimestamp = new Date(acceptedAt);
if (
  Number.isNaN(acceptedTimestamp.getTime()) ||
  acceptedTimestamp.toISOString() !== acceptedAt
) {
  throw new Error("--accepted-at must be an exact ISO-8601 timestamp.");
}

const realManifest = JSON.parse(
  (
    await readOwnerControlledFile(realManifestPath, "Real evidence manifest")
  ).toString("utf8"),
);
const pendingReal =
  validatePendingRealSandboxEvidenceManifest(realManifest);
const deterministicManifest = JSON.parse(
  (
    await readOwnerControlledFile(
      deterministicManifestPath,
      "Deterministic evidence manifest",
    )
  ).toString("utf8"),
);
const deterministicAcceptance =
  validateEvidenceRunCompletion(deterministicManifest);
if (
  deterministicManifest.mode !== "deterministic" ||
  !artifactProvenanceEquals(
    pendingReal.artifactProvenance,
    deterministicManifest.artifactProvenance,
  )
) {
  throw new Error(
    "Real and deterministic evidence must have identical artifact provenance.",
  );
}
if (
  new Date(deterministicAcceptance.acceptedAt).getTime() >
  new Date(acceptedAt).getTime()
) {
  throw new Error(
    "Campaign acceptance must be later than deterministic-run acceptance.",
  );
}

const campaign = {
  acceptanceDigest: "",
  acceptedAt,
  artifactProvenance: pendingReal.artifactProvenance,
  cleanupReceipt: {
    method: "guarded-production-reset",
    ...(await fileReference(
      "campaign/cleanup-receipt.json",
      "Cleanup receipt",
    )),
  },
  deterministicRun: {
    manifest: await fileReference(
      "campaign/deterministic/manifest.json",
      "Deterministic evidence manifest",
    ),
  },
  evidenceDigest: evidenceCompletionDigest(realManifest),
  realRun: {
    artifacts: await Promise.all(
      artifactReferences.map(async ({ path, role }) => ({
        ...(await fileReference(path, `Real-run artifact ${role}`)),
        role,
      })),
    ),
    completed: false,
    failure: "test-harness-old-signer-socket-race",
    lastVerifiedCheckpoint: "cross-installation-webhook-isolation",
    manifest: await fileReference("manifest.json", "Real evidence manifest"),
  },
  releaseVersion: "1.0.0",
  reviewer,
  schemaVersion: 1,
  strategy: "cumulative-real-plus-deterministic",
};
campaign.acceptanceDigest = releaseEvidenceCampaignDigest(campaign);

const temporaryPath = join(
  campaignRoot,
  `.release-campaign.${process.pid}.${randomUUID()}.tmp`,
);
try {
  await writeFile(temporaryPath, `${JSON.stringify(campaign, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  await loadReleaseEvidenceCampaign({
    campaignPath: temporaryPath,
    manifestPath: realManifestPath,
  });
  await rename(temporaryPath, campaignPath);
} finally {
  await rm(temporaryPath, { force: true });
}

process.stdout.write(
  `${JSON.stringify(
    {
      acceptanceDigest: campaign.acceptanceDigest,
      acceptedAt: campaign.acceptedAt,
      campaignPath,
      deterministicManifestSha256:
        campaign.deterministicRun.manifest.sha256,
      evidenceDigest: campaign.evidenceDigest,
      realManifestSha256: campaign.realRun.manifest.sha256,
      reviewer: campaign.reviewer,
    },
    null,
    2,
  )}\n`,
);
