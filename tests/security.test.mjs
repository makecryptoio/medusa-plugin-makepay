import assert from "node:assert/strict";
import {
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import test from "node:test";

import {
  createDpopKeyPair,
  createDpopProof,
  createPkceChallenge,
  decodeJwtPayload,
  decryptSecret,
  encryptSecret,
  parseEncryptionKey,
  verifyOAuthAccessToken,
} from "../src/modules/makepay/crypto.ts";

function base64Url(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function decodeBase64Url(value) {
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

test("OAuth secrets require a 32-byte key and authenticated context", () => {
  const encodedKey = Buffer.alloc(32, 7).toString("base64");
  const key = parseEncryptionKey(encodedKey);
  const first = encryptSecret("refresh-token", key, "connection:one");
  const second = encryptSecret("refresh-token", key, "connection:one");

  assert.notEqual(first, second, "AES-GCM must use a fresh IV");
  assert.equal(decryptSecret(first, key, "connection:one"), "refresh-token");
  assert.throws(() => decryptSecret(first, key, "connection:two"));
  assert.throws(() => parseEncryptionKey(Buffer.alloc(31).toString("base64")));
  assert.throws(() => parseEncryptionKey(` ${encodedKey}`), /canonical base64/);
  assert.throws(() => parseEncryptionKey(`${encodedKey}\n`), /canonical base64/);
  assert.throws(
    () => parseEncryptionKey(encodedKey.replace(/=+$/, "")),
    /canonical base64/,
  );
  assert.throws(() => parseEncryptionKey(`${encodedKey}=`), /canonical base64/);
  const slashKey = Buffer.alloc(32, 255).toString("base64");
  assert.throws(
    () => parseEncryptionKey(slashKey.replaceAll("/", "_")),
    /canonical base64/,
  );
});

test("PKCE challenge follows the RFC 7636 S256 test vector", () => {
  assert.equal(
    createPkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  );
});

test("DPoP proofs bind method, URL, key, and access token", () => {
  const keyPair = createDpopKeyPair();
  const token = createDpopProof({
    accessToken: "access-token",
    method: "post",
    privateKey: keyPair.privateKeyPem,
    url: "https://api.example.test/resource?not-bound=true#ignored",
  });
  const [headerPart, payloadPart, signaturePart] = token.split(".");
  const header = JSON.parse(decodeBase64Url(headerPart));
  const payload = JSON.parse(decodeBase64Url(payloadPart));

  assert.equal(header.typ, "dpop+jwt");
  assert.equal(header.alg, "ES256");
  assert.equal(payload.htm, "POST");
  assert.equal(payload.htu, "https://api.example.test/resource");
  assert.ok(payload.ath);
  assert.ok(payload.jti);
  assert.equal(
    verify(
      "sha256",
      Buffer.from(`${headerPart}.${payloadPart}`),
      {
        dsaEncoding: "ieee-p1363",
        key: createPublicKey({ format: "jwk", key: header.jwk }),
      },
      decodeBase64Url(signaturePart),
    ),
    true,
  );
});

test("OAuth access token validation rejects wrong claims", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const header = base64Url(
    JSON.stringify({ alg: "RS256", kid: "test-key", typ: "at+jwt" }),
  );
  const claims = {
    aud: "https://makecrypto.test/api/partner/v1",
    client_id: "client_test",
    cnf: { jkt: "thumbprint_test" },
    exp: Math.floor(Date.now() / 1000) + 300,
    iat: Math.floor(Date.now() / 1000),
    iss: "https://makecrypto.test",
    sub: "company_test",
  };
  const payload = base64Url(JSON.stringify(claims));
  const signature = sign(
    "RSA-SHA256",
    Buffer.from(`${header}.${payload}`),
    privateKey,
  );
  const token = `${header}.${payload}.${base64Url(signature)}`;
  const publicJwk = publicKey.export({ format: "jwk" });
  const fetchImpl = async () =>
    new Response(
      JSON.stringify({ keys: [{ ...publicJwk, kid: "test-key", use: "sig" }] }),
      { headers: { "content-type": "application/json" } },
    );

  const verified = await verifyOAuthAccessToken({
    audience: "https://makecrypto.test/api/partner/v1",
    expectedClientId: "client_test",
    expectedDpopThumbprint: "thumbprint_test",
    fetchImpl,
    issuer: "https://makecrypto.test",
    token,
  });
  assert.equal(verified.sub, "company_test");
  assert.equal(decodeJwtPayload(token).client_id, "client_test");

  await assert.rejects(
    verifyOAuthAccessToken({
      audience: "https://makecrypto.test/wrong",
      expectedClientId: "client_test",
      expectedDpopThumbprint: "thumbprint_test",
      fetchImpl,
      issuer: "https://makecrypto.test",
      token,
    }),
    /claims are invalid/,
  );
});

test("expired OAuth access tokens are accepted only for exact idempotent replay verification", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const publicJwk = publicKey.export({ format: "jwk" });
  const now = Math.floor(Date.now() / 1000);
  const fetchImpl = async () =>
    new Response(
      JSON.stringify({
        keys: [{ ...publicJwk, kid: "recovery-key", use: "sig" }],
      }),
      { headers: { "content-type": "application/json" } },
    );
  const tokenWithExpiry = (exp) => {
    const header = base64Url(
      JSON.stringify({ alg: "RS256", kid: "recovery-key", typ: "at+jwt" }),
    );
    const payload = base64Url(
      JSON.stringify({
        aud: "https://makecrypto.test/api/partner/v1",
        client_id: "client_test",
        cnf: { jkt: "thumbprint_test" },
        exp,
        iat: Math.min(now - 180, exp - 600),
        iss: "https://makecrypto.test",
        scope: "company:read makepay:webhooks:read",
        sub: "company_test",
      }),
    );
    const signature = sign(
      "RSA-SHA256",
      Buffer.from(`${header}.${payload}`),
      privateKey,
    );
    return `${header}.${payload}.${base64Url(signature)}`;
  };
  const verifyToken = (token, allowExpiredForIdempotentReplay = false) =>
    verifyOAuthAccessToken({
      allowExpiredForIdempotentReplay,
      audience: "https://makecrypto.test/api/partner/v1",
      expectedClientId: "client_test",
      expectedDpopThumbprint: "thumbprint_test",
      expectedScopes: ["makepay:webhooks:read", "company:read"],
      fetchImpl,
      issuer: "https://makecrypto.test",
      token,
    });

  await assert.rejects(
    verifyToken(tokenWithExpiry(now - 1)),
    /claims are invalid/,
  );
  assert.equal(
    (await verifyToken(tokenWithExpiry(now - 31 * 24 * 60 * 60), true)).exp,
    now - 31 * 24 * 60 * 60,
  );
  assert.equal((await verifyToken(tokenWithExpiry(now + 30))).exp, now + 30);

  await assert.rejects(
    verifyOAuthAccessToken({
      allowExpiredForIdempotentReplay: true,
      audience: "https://makecrypto.test/api/partner/v1",
      expectedClientId: "client_test",
      expectedDpopThumbprint: "thumbprint_test",
      expectedScopes: ["company:read", "makepay:webhooks:write"],
      fetchImpl,
      issuer: "https://makecrypto.test",
      token: tokenWithExpiry(now - 31 * 24 * 60 * 60),
    }),
    /claims are invalid/,
  );
});

test("OAuth access token validation rejects malformed time claims", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const publicJwk = publicKey.export({ format: "jwk" });
  const now = Math.floor(Date.now() / 1000);
  const baseClaims = {
    aud: "https://makecrypto.test/api/partner/v1",
    client_id: "client_test",
    cnf: { jkt: "thumbprint_test" },
    exp: now + 300,
    iat: now,
    iss: "https://makecrypto.test",
    sub: "company_test",
  };
  const fetchImpl = async () =>
    new Response(
      JSON.stringify({
        keys: [
          {
            ...publicJwk,
            alg: "RS256",
            key_ops: ["verify"],
            kid: "test-key",
            use: "sig",
          },
        ],
      }),
      { headers: { "content-type": "application/json" } },
    );

  const verifyClaims = async (claims, rawPayload = JSON.stringify(claims)) => {
    const header = base64Url(
      JSON.stringify({ alg: "RS256", kid: "test-key", typ: "at+jwt" }),
    );
    const payload = base64Url(rawPayload);
    const signature = sign(
      "RSA-SHA256",
      Buffer.from(`${header}.${payload}`),
      privateKey,
    );
    return verifyOAuthAccessToken({
      audience: "https://makecrypto.test/api/partner/v1",
      expectedClientId: "client_test",
      expectedDpopThumbprint: "thumbprint_test",
      fetchImpl,
      issuer: "https://makecrypto.test",
      token: `${header}.${payload}.${base64Url(signature)}`,
    });
  };

  for (const claims of [
    { ...baseClaims, iat: "not-a-number" },
    { ...baseClaims, exp: "not-a-number" },
    { ...baseClaims, nbf: "not-a-number" },
    { ...baseClaims, nbf: null },
  ]) {
    await assert.rejects(verifyClaims(claims), /claims are invalid/);
  }

  for (const [claim, exponent] of [
    ["iat", "1e400"],
    ["exp", "1e400"],
    ["nbf", "-1e400"],
  ]) {
    const claims = { ...baseClaims, [claim]: 0 };
    const rawPayload = JSON.stringify(claims).replace(
      `"${claim}":0`,
      `"${claim}":${exponent}`,
    );
    await assert.rejects(
      verifyClaims(claims, rawPayload),
      /claims are invalid/,
    );
  }
});

test("OAuth access token validation rejects JWKS keys not usable for RS256 verification", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const publicJwk = publicKey.export({ format: "jwk" });
  const now = Math.floor(Date.now() / 1000);
  const header = base64Url(
    JSON.stringify({ alg: "RS256", kid: "test-key", typ: "at+jwt" }),
  );
  const payload = base64Url(
    JSON.stringify({
      aud: "https://makecrypto.test/api/partner/v1",
      client_id: "client_test",
      cnf: { jkt: "thumbprint_test" },
      exp: now + 300,
      iat: now,
      iss: "https://makecrypto.test",
      sub: "company_test",
    }),
  );
  const signature = sign(
    "RSA-SHA256",
    Buffer.from(`${header}.${payload}`),
    privateKey,
  );
  const token = `${header}.${payload}.${base64Url(signature)}`;

  for (const overrides of [
    { kty: "EC" },
    { alg: "RS512" },
    { use: "enc" },
    { key_ops: ["sign"] },
    { key_ops: "verify" },
  ]) {
    const fetchImpl = async () =>
      new Response(
        JSON.stringify({
          keys: [
            {
              ...publicJwk,
              alg: "RS256",
              key_ops: ["verify"],
              kid: "test-key",
              use: "sig",
              ...overrides,
            },
          ],
        }),
        { headers: { "content-type": "application/json" } },
      );

    await assert.rejects(
      verifyOAuthAccessToken({
        audience: "https://makecrypto.test/api/partner/v1",
        expectedClientId: "client_test",
        expectedDpopThumbprint: "thumbprint_test",
        fetchImpl,
        issuer: "https://makecrypto.test",
        token,
      }),
      /signing key is not valid for RS256 verification/,
    );
  }
});
