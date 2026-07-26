import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign,
  verify,
} from "node:crypto";

const ENCRYPTED_VALUE_VERSION = "v1";

function base64Url(input: Buffer | string): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function fromBase64Url(input: string): Buffer {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(
    normalized + "=".repeat((4 - (normalized.length % 4)) % 4),
    "base64",
  );
}

export function parseEncryptionKey(value: string | undefined): Buffer {
  if (!value) {
    throw new Error(
      "MakePay OAuth requires `encryptionKey` (a base64-encoded 32-byte key).",
    );
  }

  const key = Buffer.from(value, "base64");
  if (key.length !== 32 || key.toString("base64") !== value) {
    throw new Error(
      "MakePay `encryptionKey` must be a canonical base64-encoded 32-byte value.",
    );
  }

  return key;
}

export function encryptSecret(
  plaintext: string,
  key: Buffer,
  context: string,
): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(context));
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return [
    ENCRYPTED_VALUE_VERSION,
    iv.toString("base64"),
    tag.toString("base64"),
    ciphertext.toString("base64"),
  ].join(".");
}

export function decryptSecret(
  envelope: string,
  key: Buffer,
  context: string,
): string {
  const [version, ivText, tagText, ciphertextText, extra] = envelope.split(".");
  if (
    version !== ENCRYPTED_VALUE_VERSION ||
    !ivText ||
    !tagText ||
    !ciphertextText ||
    extra
  ) {
    throw new Error("Invalid MakePay encrypted value.");
  }

  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(ivText, "base64"),
  );
  decipher.setAAD(Buffer.from(context));
  decipher.setAuthTag(Buffer.from(tagText, "base64"));

  return Buffer.concat([
    decipher.update(Buffer.from(ciphertextText, "base64")),
    decipher.final(),
  ]).toString("utf8");
}

export function randomOpaqueToken(bytes = 32): string {
  return base64Url(randomBytes(bytes));
}

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function createPkceChallenge(verifier: string): string {
  return base64Url(createHash("sha256").update(verifier).digest());
}

export type MakePayDpopKeyPair = {
  privateKeyPem: string;
  publicJwk: {
    kty: "EC";
    crv: "P-256";
    x: string;
    y: string;
  };
  thumbprint: string;
};

function normalizeDpopPublicJwk(publicJwk: JsonWebKey): {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
} {
  if (
    publicJwk.kty !== "EC" ||
    publicJwk.crv !== "P-256" ||
    !publicJwk.x ||
    !publicJwk.y
  ) {
    throw new Error("MakePay DPoP keys must use the P-256 elliptic curve.");
  }

  return {
    crv: "P-256",
    kty: "EC",
    x: publicJwk.x,
    y: publicJwk.y,
  };
}

function dpopJwkThumbprint(publicJwk: {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
}): string {
  return base64Url(
    createHash("sha256").update(JSON.stringify(publicJwk)).digest(),
  );
}

export function dpopThumbprintFromPrivateKey(privateKeyPem: string): string {
  const publicJwk = normalizeDpopPublicJwk(
    createPublicKey(privateKeyPem).export({ format: "jwk" }),
  );
  return dpopJwkThumbprint(publicJwk);
}

export function createDpopKeyPair(): MakePayDpopKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const normalized = normalizeDpopPublicJwk(
    publicKey.export({ format: "jwk" }),
  );
  const thumbprint = dpopJwkThumbprint(normalized);

  return {
    privateKeyPem: privateKey
      .export({ format: "pem", type: "pkcs8" })
      .toString(),
    publicJwk: normalized,
    thumbprint,
  };
}

export function createDpopProof(input: {
  privateKey: string;
  method: string;
  url: string;
  accessToken?: string;
}): string {
  const privateKey = createPrivateKey(input.privateKey);
  const publicJwk = createPublicKey(input.privateKey).export({ format: "jwk" });
  const header = base64Url(
    JSON.stringify({ alg: "ES256", jwk: publicJwk, typ: "dpop+jwt" }),
  );
  const url = new URL(input.url);
  url.hash = "";
  url.search = "";
  const payload: Record<string, unknown> = {
    htm: input.method.toUpperCase(),
    htu: url.toString(),
    iat: Math.floor(Date.now() / 1000),
    jti: randomUUID(),
  };
  if (input.accessToken) {
    payload.ath = base64Url(
      createHash("sha256").update(input.accessToken).digest(),
    );
  }

  const encodedPayload = base64Url(JSON.stringify(payload));
  const signingInput = `${header}.${encodedPayload}`;
  const signature = sign("sha256", Buffer.from(signingInput), {
    dsaEncoding: "ieee-p1363",
    key: privateKey,
  });
  return `${signingInput}.${base64Url(signature)}`;
}

export function decodeJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("MakePay returned an invalid OAuth access token.");
  }
  const parsed = JSON.parse(fromBase64Url(parts[1]).toString("utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("MakePay returned an invalid OAuth access token payload.");
  }
  return parsed as Record<string, unknown>;
}

export async function verifyOAuthAccessToken(input: {
  token: string;
  issuer: string;
  audience: string;
  expectedClientId: string;
  expectedDpopThumbprint: string;
  expectedScopes?: readonly string[];
  allowExpiredForIdempotentReplay?: boolean;
  fetchImpl: typeof fetch;
  jwksUri?: string;
}): Promise<Record<string, unknown>> {
  const [encodedHeader, encodedPayload, encodedSignature] =
    input.token.split(".");
  if (!encodedHeader || !encodedPayload || !encodedSignature) {
    throw new Error("MakePay returned a malformed OAuth access token.");
  }
  const header = JSON.parse(fromBase64Url(encodedHeader).toString("utf8")) as {
    alg?: string;
    kid?: string;
    typ?: string;
  };
  if (header.alg !== "RS256" || header.typ !== "at+jwt" || !header.kid) {
    throw new Error("MakePay returned an OAuth token with invalid headers.");
  }

  const issuer = input.issuer.replace(/\/+$/, "");
  const jwksResponse = await input.fetchImpl(
    input.jwksUri ?? `${issuer}/oauth/jwks.json`,
    {
      headers: { accept: "application/json" },
      redirect: "manual",
    },
  );
  if (!jwksResponse.ok) {
    throw new Error("Unable to verify the MakePay OAuth signing key.");
  }
  const jwks = (await jwksResponse.json()) as {
    keys?: Array<Record<string, unknown> & { kid?: string }>;
  };
  const jwk = jwks.keys?.find((candidate) => candidate.kid === header.kid);
  if (!jwk) {
    throw new Error("MakePay OAuth signing key was not found.");
  }
  if (
    jwk.kty !== "RSA" ||
    (jwk.alg !== undefined && jwk.alg !== "RS256") ||
    (jwk.use !== undefined && jwk.use !== "sig") ||
    (jwk.key_ops !== undefined &&
      (!Array.isArray(jwk.key_ops) || !jwk.key_ops.includes("verify")))
  ) {
    throw new Error("MakePay OAuth signing key is not valid for RS256 verification.");
  }
  const valid = verify(
    "RSA-SHA256",
    Buffer.from(`${encodedHeader}.${encodedPayload}`),
    createPublicKey({ format: "jwk", key: jwk as never }),
    fromBase64Url(encodedSignature),
  );
  if (!valid) {
    throw new Error("MakePay OAuth access token signature is invalid.");
  }

  const claims = decodeJwtPayload(input.token);
  const now = Math.floor(Date.now() / 1000);
  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  const cnf = claims.cnf as Record<string, unknown> | undefined;
  const signedScopes =
    typeof claims.scope === "string" && claims.scope.trim()
      ? claims.scope.trim().split(/\s+/)
      : [];
  const normalizedSignedScopes = [...new Set(signedScopes)].sort();
  const normalizedExpectedScopes = input.expectedScopes
    ? [...new Set(input.expectedScopes)].sort()
    : undefined;
  const scopesInvalid =
    normalizedExpectedScopes !== undefined &&
    (signedScopes.length !== normalizedSignedScopes.length ||
      normalizedSignedScopes.length !== normalizedExpectedScopes.length ||
      normalizedSignedScopes.some(
        (scope, index) => scope !== normalizedExpectedScopes[index],
      ));
  if (
    claims.iss !== issuer ||
    !audience.includes(input.audience.replace(/\/+$/, "")) ||
    claims.client_id !== input.expectedClientId ||
    cnf?.jkt !== input.expectedDpopThumbprint ||
    scopesInvalid ||
    typeof claims.iat !== "number" ||
    !Number.isFinite(claims.iat) ||
    claims.iat > now + 30 ||
    typeof claims.exp !== "number" ||
    !Number.isFinite(claims.exp) ||
    claims.exp <= claims.iat ||
    (!input.allowExpiredForIdempotentReplay && claims.exp <= now) ||
    (claims.nbf !== undefined &&
      (typeof claims.nbf !== "number" ||
        !Number.isFinite(claims.nbf) ||
        claims.nbf > now + 30))
  ) {
    throw new Error("MakePay OAuth access token claims are invalid.");
  }

  return claims;
}
