import {
  createHash,
  createHmac,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign as signValue,
  timingSafeEqual,
  verify as verifySignature,
} from "node:crypto";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { pathToFileURL } from "node:url";

const JSON_HEADERS = {
  "cache-control": "no-store",
  "content-type": "application/json; charset=utf-8",
};

const CANONICAL_OAUTH_STATUSES = new Set([
  "awaiting_deposit",
  "cancelled",
  "complete",
  "deposit_received",
  "expired",
  "failed",
  "pending",
  "quoted",
  "sending",
  "swapping",
  "underpaid",
]);

const nowSeconds = () => Math.floor(Date.now() / 1000);
const randomId = (prefix) => `${prefix}_${randomBytes(12).toString("hex")}`;
const base64url = (value) =>
  Buffer.from(value)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
const sha256Base64url = (value) =>
  base64url(createHash("sha256").update(value).digest());

function json(res, status, body, headers = {}) {
  res.writeHead(status, { ...JSON_HEADERS, ...headers });
  res.end(JSON.stringify(body));
}

function html(res, status, body) {
  res.writeHead(status, {
    "cache-control": "no-store",
    "content-security-policy": "default-src 'self'; style-src 'unsafe-inline'",
    "content-type": "text/html; charset=utf-8",
  });
  res.end(body);
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 1_000_000) {
      throw Object.assign(new Error("Request body too large"), { status: 413 });
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function parseJson(buffer) {
  if (!buffer.length) return {};
  return JSON.parse(buffer.toString("utf8"));
}

function asRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : {};
}

function firstText(...values) {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) return value.trim();
    if (typeof value === "number" && Number.isFinite(value)) {
      return String(value);
    }
  }
  return null;
}

// Exact deterministic mirror of MakeCrypto's deployed
// serializeMakePayPartnerPaymentLink. Keep the payload for backwards
// compatibility while exposing the fields used by the SDK at the top level.
function serializeMakePayPartnerPaymentLink(value) {
  const paymentLink = asRecord(value);
  const payload = asRecord(paymentLink.payload);
  const amount = firstText(
    payload.amount,
    payload.fiatAmount,
    payload.fiat_amount,
    payload.amountUsd,
    payload.amount_usd,
  );

  return {
    ...paymentLink,
    amount,
    fiatAmount: amount,
    fiatCurrency: firstText(
      payload.fiatCurrency,
      payload.fiat_currency,
      payload.displayCurrency,
      payload.display_currency,
    ),
    currency: firstText(payload.currency, payload.settlementCurrency),
    asset: firstText(payload.asset),
    title: firstText(payload.title),
    label: firstText(payload.label, payload.title),
    description: firstText(payload.description),
    orderId: firstText(payload.orderId, payload.order_id),
    customerEmail: firstText(
      payload.customerEmail,
      payload.customer_email,
      payload.clientEmail,
      payload.client_email,
    ),
    clientId: firstText(payload.clientId, payload.client_id),
    metadata: asRecord(payload.metadata),
    payload,
    latestSession: paymentLink.latestSession ?? null,
    timelineEvents: Array.isArray(paymentLink.timelineEvents)
      ? paymentLink.timelineEvents
      : [],
  };
}

function paymentLinkResponseRecord(link, overrides = {}) {
  const current = { ...link, ...overrides };
  return {
    createdAt: current.createdAt,
    id: current.uid,
    latestSession: current.latestSession ?? null,
    payload: current.payload,
    publicUrl: current.publicUrl,
    status: current.status,
    timelineEvents: current.timelineEvents ?? [],
    uid: current.uid,
    updatedAt: current.updatedAt ?? current.createdAt,
  };
}

function serializePaymentLink(link, overrides) {
  return serializeMakePayPartnerPaymentLink(
    paymentLinkResponseRecord(link, overrides),
  );
}

function canonicalDeliveryGroupId({
  destinationId,
  link,
  paymentSessionId,
  status,
  subscription,
}) {
  const identity = {
    version: 1,
    destinationId,
    type: "makepay.payment.status_changed",
    companyId: link.companyId,
    grantId: link.grantId,
    subscriptionId: subscription.id,
    installationId: link.installationId,
    paymentLinkUid: link.uid,
    makePaySessionId: paymentSessionId,
    status,
    fiatAmount: String(link.amount),
    fiatCurrency: String(link.fiatCurrency).toUpperCase(),
  };
  return `mpwhgrp_${createHash("sha256")
    .update(JSON.stringify(identity), "utf8")
    .digest("hex")}`;
}

function parseJwt(jwt) {
  const parts = String(jwt || "").split(".");
  if (parts.length !== 3) throw new Error("Malformed DPoP proof");
  return {
    header: JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")),
    payload: JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")),
    signature: Buffer.from(parts[2], "base64url"),
    signingInput: Buffer.from(`${parts[0]}.${parts[1]}`),
  };
}

function jwkThumbprint(jwk) {
  if (!jwk || jwk.kty !== "EC" || jwk.crv !== "P-256") {
    throw new Error("DPoP requires an EC P-256 public JWK");
  }
  return sha256Base64url(
    JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }),
  );
}

function safeEqualText(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

function normalizedHtu(value) {
  const url = new URL(value);
  url.hash = "";
  url.search = "";
  return url.href;
}

function verifyDpop({ proof, method, url, accessToken, seenJti }) {
  const parsed = parseJwt(proof);
  if (parsed.header.typ !== "dpop+jwt" || parsed.header.alg !== "ES256") {
    throw new Error("Invalid DPoP header");
  }
  const key = createPublicKey({ format: "jwk", key: parsed.header.jwk });
  const valid = verifySignature(
    "sha256",
    parsed.signingInput,
    { dsaEncoding: "ieee-p1363", key },
    parsed.signature,
  );
  if (!valid) throw new Error("Invalid DPoP signature");
  if (parsed.payload.htm !== method.toUpperCase()) {
    throw new Error("DPoP htm mismatch");
  }
  if (parsed.payload.htu !== normalizedHtu(url)) {
    throw new Error("DPoP htu mismatch");
  }
  if (
    !Number.isInteger(parsed.payload.iat) ||
    Math.abs(nowSeconds() - parsed.payload.iat) > 300
  ) {
    throw new Error("DPoP proof is outside the allowed time window");
  }
  if (!parsed.payload.jti || seenJti.has(parsed.payload.jti)) {
    throw new Error("DPoP jti is missing or has already been used");
  }
  if (accessToken) {
    const expectedAth = sha256Base64url(accessToken);
    if (!safeEqualText(parsed.payload.ath, expectedAth)) {
      throw new Error("DPoP ath mismatch");
    }
  } else if (parsed.payload.ath) {
    throw new Error("DPoP ath must be omitted without an access token");
  }
  seenJti.add(parsed.payload.jti);
  return { jwk: parsed.header.jwk, jkt: jwkThumbprint(parsed.header.jwk) };
}

function requestUrl(req, origin) {
  return new URL(req.url || "/", origin);
}

function paymentPath(pathname) {
  const prefixes = [
    "/api/partner/v1/makepay/payment-links",
    "/api/partner/v1/payment-links",
  ];
  for (const prefix of prefixes) {
    if (pathname === prefix) return { uid: null };
    if (pathname.startsWith(`${prefix}/`)) {
      return { uid: decodeURIComponent(pathname.slice(prefix.length + 1)) };
    }
  }
  const companyMatch = pathname.match(
    /^\/api\/partner\/v1\/companies\/([^/]+)\/payment-links(?:\/([^/]+))?$/,
  );
  if (companyMatch) {
    return {
      companyId: decodeURIComponent(companyMatch[1]),
      uid: companyMatch[2] ? decodeURIComponent(companyMatch[2]) : null,
    };
  }
  return null;
}

function subscriptionPath(pathname) {
  return [
    "/api/partner/v1/makepay/webhook-subscriptions/current",
    "/api/partner/v1/webhook-subscriptions/current",
  ].includes(pathname);
}

function redactBody(value, key = "") {
  const sensitiveKeys = new Set([
    "access_token",
    "authorization",
    "client_secret",
    "code",
    "code_verifier",
    "keySecret",
    "password",
    "refresh_token",
    "signingSecret",
    "token",
    "webhookSecret",
  ]);
  if (sensitiveKeys.has(key)) return "[redacted]";
  if (Array.isArray(value)) return value.map((item) => redactBody(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([childKey, childValue]) => [
        childKey,
        redactBody(childValue, childKey),
      ]),
    );
  }
  return value;
}

function redactRequest(req, url, body) {
  return {
    at: new Date().toISOString(),
    body: redactBody(body),
    hasApiKey: Boolean(
      req.headers["x-makecrypto-key-id"] ||
      req.headers["x-makecrypto-key-secret"],
    ),
    hasAuthorization: Boolean(req.headers.authorization),
    hasDpop: Boolean(req.headers.dpop),
    idempotencyKey: req.headers["idempotency-key"] || null,
    method: req.method,
    pathname: url.pathname,
    responseStatus: null,
  };
}

function publicSubscription(subscription) {
  if (!subscription) return null;
  const { signingSecret: _signingSecret, ...safeSubscription } = subscription;
  return safeSubscription;
}

function publicState(state) {
  return {
    installations: [...state.installations.values()].map((installation) => ({
      clientId: installation.clientId,
      companyId: installation.companyId,
      platform: installation.platform,
      redirectUri: installation.redirectUri,
      siteUrl: installation.siteUrl,
    })),
    links: [...state.links.values()],
    linkReadOverrides: [...state.linkReadOverrides.entries()].map(
      ([uid, override]) => ({
        fields: Object.keys(override.values).sort(),
        remaining: override.remaining,
        uid,
      }),
    ),
    nativeResetResponseLosses: state.nativeResetResponseLosses,
    preparedWebhookCount: state.preparedWebhooks.size,
    requests: state.requests,
    subscriptions: [...state.subscriptions.entries()].map(
      ([grantId, subscription]) => ({
        grantId,
        ...publicSubscription(subscription),
      }),
    ),
    webhookAttempts: state.webhookAttempts,
    workflowLatches: [...state.workflowLatches.entries()].map(
      ([uid, latch]) => ({
        held: latch.held,
        hits: latch.hits,
        uid,
      }),
    ),
  };
}

export function createMakePayContractServer(options = {}) {
  const host = options.host || "127.0.0.1";
  const controlToken = options.controlToken || randomId("control");
  const apiKeyId = options.apiKeyId || "e2e_key_id";
  const apiKeySecret = options.apiKeySecret || "e2e_key_secret";
  const webhookSecret = options.webhookSecret || "e2e_webhook_secret";
  const companyId = options.companyId || "company_e2e_sandbox";
  const oauthScopes = [
    "company:read",
    "makepay:payment-links:read",
    "makepay:payment-links:write",
    "makepay:webhooks:read",
    "makepay:webhooks:write",
  ];
  const oauthKid = "makepay-e2e-rs256";
  const oauthKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const oauthPublicJwk = {
    ...oauthKeys.publicKey.export({ format: "jwk" }),
    alg: "RS256",
    kid: oauthKid,
    use: "sig",
  };
  const state = {
    accessTokens: new Map(),
    authorizationCodes: new Map(),
    grantIdsByInstallation: new Map(),
    idempotency: new Map(),
    installations: new Map(),
    links: new Map(),
    linkReadOverrides: new Map(),
    nativeResetResponseLosses: 0,
    paymentSessionIds: new Map(),
    preparedWebhooks: new Map(),
    refreshLatch: {
      armed: false,
      held: false,
      hits: 0,
      waiters: [],
    },
    refreshTokens: new Map(),
    resetReceipts: new Map(),
    requests: [],
    seenJti: new Set(),
    subscriptions: new Map(),
    webhookMutationReceipts: new Map(),
    deliveryGroups: new Map(),
    webhookAttempts: [],
    workflowLatches: new Map(),
  };
  // Retain the pre-grant fixture accessor for the SDK contract test while the
  // canonical state is the grant-scoped subscriptions map.
  Object.defineProperty(state, "subscription", {
    enumerable: false,
    get() {
      return (
        state.subscriptions.get("grant_api_key_e2e") ||
        state.subscriptions.values().next().value ||
        null
      );
    },
  });
  let origin;

  function refreshLatchState() {
    return {
      armed: state.refreshLatch.armed,
      held: state.refreshLatch.held,
      hits: state.refreshLatch.hits,
    };
  }

  function releaseRefreshLatch() {
    state.refreshLatch.held = false;
    const waiters = state.refreshLatch.waiters.splice(0);
    for (const resolve of waiters) resolve();
    return refreshLatchState();
  }

  function disarmRefreshLatch() {
    releaseRefreshLatch();
    state.refreshLatch.armed = false;
    return refreshLatchState();
  }

  function resetRefreshLatch() {
    disarmRefreshLatch();
    state.refreshLatch.hits = 0;
  }

  async function waitAtRefreshLatch() {
    if (!state.refreshLatch.armed) return;
    state.refreshLatch.hits += 1;
    if (!state.refreshLatch.held) return;
    await new Promise((resolve) => state.refreshLatch.waiters.push(resolve));
  }

  function reset() {
    state.accessTokens.clear();
    state.authorizationCodes.clear();
    state.grantIdsByInstallation.clear();
    state.idempotency.clear();
    state.installations.clear();
    state.links.clear();
    state.linkReadOverrides.clear();
    state.nativeResetResponseLosses = 0;
    state.paymentSessionIds.clear();
    state.preparedWebhooks.clear();
    resetRefreshLatch();
    state.refreshTokens.clear();
    state.resetReceipts.clear();
    state.requests.length = 0;
    state.seenJti.clear();
    state.subscriptions.clear();
    state.webhookMutationReceipts.clear();
    state.deliveryGroups.clear();
    state.webhookAttempts.length = 0;
    state.workflowLatches.clear();
  }

  function authenticate(req, url) {
    const keyId = req.headers["x-makecrypto-key-id"];
    const keySecret = req.headers["x-makecrypto-key-secret"];
    if (keyId || keySecret) {
      if (
        !safeEqualText(keyId, apiKeyId) ||
        !safeEqualText(keySecret, apiKeySecret)
      ) {
        throw Object.assign(new Error("Invalid API key"), { status: 401 });
      }
      if (req.headers.authorization || req.headers.dpop) {
        throw Object.assign(
          new Error("Mixed API key and OAuth authentication"),
          {
            status: 400,
          },
        );
      }
      return {
        companyId,
        dpopJkt: null,
        grantId: "grant_api_key_e2e",
        installationId: "installation_api_key_e2e",
        mode: "api-key",
      };
    }

    const authorization = String(req.headers.authorization || "");
    const [scheme, token] = authorization.split(" ", 2);
    const tokenRecord = state.accessTokens.get(token);
    if (
      !tokenRecord ||
      tokenRecord.revoked ||
      tokenRecord.expiresAt <= nowSeconds()
    ) {
      throw Object.assign(new Error("Invalid or expired access token"), {
        status: 401,
      });
    }
    if (scheme !== "DPoP") {
      throw Object.assign(new Error("OAuth authentication is required"), {
        status: 401,
      });
    }
    const verified = verifyDpop({
      accessToken: token,
      method: req.method,
      proof: req.headers.dpop,
      seenJti: state.seenJti,
      url: url.href,
    });
    if (verified.jkt !== tokenRecord.dpopJkt) {
      throw Object.assign(new Error("Access token DPoP key mismatch"), {
        status: 401,
      });
    }
    return {
      companyId: tokenRecord.companyId,
      dpopJkt: verified.jkt,
      grantId: tokenRecord.grantId,
      installationId: tokenRecord.installationId,
      mode: "oauth",
    };
  }

  function signAccessToken(installation, expiresAt, grantId) {
    const header = base64url(
      JSON.stringify({ alg: "RS256", kid: oauthKid, typ: "at+jwt" }),
    );
    const issuedAt = nowSeconds();
    const payload = base64url(
      JSON.stringify({
        aud: `${origin}/api/partner/v1`,
        client_id: installation.clientId,
        cnf: { jkt: installation.dpopJkt },
        company_id: installation.companyId,
        company_name: "E2E Merchant",
        exp: expiresAt,
        grant_id: grantId,
        iat: issuedAt,
        installation_id: installation.clientId,
        iss: origin,
        nbf: issuedAt - 1,
        scope: oauthScopes.join(" "),
        sub: "user_e2e_merchant",
      }),
    );
    const input = `${header}.${payload}`;
    const signature = signValue(
      "RSA-SHA256",
      Buffer.from(input),
      oauthKeys.privateKey,
    );
    return `${input}.${base64url(signature)}`;
  }

  function issueTokens(installation, familyId = randomId("family"), grantId) {
    grantId =
      grantId ||
      state.grantIdsByInstallation.get(installation.clientId) ||
      randomId("grant");
    state.grantIdsByInstallation.set(installation.clientId, grantId);
    const expiresAt = nowSeconds() + 3600;
    const accessToken = signAccessToken(installation, expiresAt, grantId);
    const refreshToken = randomId("refresh");
    const access = {
      companyId: installation.companyId,
      dpopJkt: installation.dpopJkt,
      expiresAt,
      familyId,
      grantId,
      installationId: installation.clientId,
      revoked: false,
    };
    state.accessTokens.set(accessToken, access);
    state.refreshTokens.set(refreshToken, {
      ...access,
      clientId: installation.clientId,
      installationId: installation.clientId,
      rotated: false,
    });
    return {
      access_token: accessToken,
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: oauthScopes.join(" "),
      token_type: "DPoP",
    };
  }

  async function deliverWebhookFixture(fixture) {
    const { attemptRecord, body, destination, headers, remoteStatus } = fixture;
    if (remoteStatus) {
      const link = state.links.get(remoteStatus.uid);
      if (!link) throw new Error(`Unknown payment link ${remoteStatus.uid}`);
      state.paymentSessionIds.set(remoteStatus.uid, remoteStatus.sessionId);
      link.latestSession = {
        id: remoteStatus.sessionId,
        status: remoteStatus.status,
      };
    }
    state.webhookAttempts.push(attemptRecord);
    const response = await fetch(destination, {
      body,
      headers,
      method: "POST",
    });
    attemptRecord.responseStatus = response.status;
    const responseText = await response.text();
    if (!response.ok) {
      throw new Error(
        `Webhook callback failed (${response.status}): ${responseText}`,
      );
    }
    return {
      deliveryGroupId: attemptRecord.deliveryGroupId,
      deliveryId: attemptRecord.deliveryId,
      responseStatus: response.status,
      responseText,
    };
  }

  async function emitWebhook({
    amount,
    attempt = 1,
    bodyDeliveryId,
    callbackUrl,
    defer = false,
    eventCreatedAt,
    deliveryId = randomUUID(),
    deliveryGroupId,
    failWorkflowOnce = false,
    invalidSignature = false,
    legacyData,
    legacyProductionShape = false,
    orderDisplayId,
    orderId,
    sessionId,
    status,
    uid,
    updateRemoteStatus = true,
  }) {
    const link = state.links.get(uid);
    if (!link) throw new Error(`Unknown payment link ${uid}`);
    if (link.authMode === "oauth" && !CANONICAL_OAUTH_STATUSES.has(status)) {
      throw new Error(`Unsupported canonical OAuth webhook status: ${status}`);
    }
    const makePaySessionId =
      state.paymentSessionIds.get(uid) || randomId("mpses");
    if (failWorkflowOnce) {
      // Keep completion reads non-terminal until the test has observed the
      // synchronous callback's durable delivery/projection state, then
      // release the latch and redeliver exactly as a provider would after a
      // retryable callback response.
      state.workflowLatches.set(uid, { held: true, hits: 0 });
    }
    const subscription = state.subscriptions.get(link.grantId);
    if (link.authMode === "oauth" && !subscription) {
      throw new Error("No OAuth webhook subscription is configured");
    }
    deliveryGroupId ??=
      link.authMode === "oauth"
        ? canonicalDeliveryGroupId({
            destinationId: `oauth:${subscription.id}`,
            link,
            paymentSessionId: makePaySessionId,
            status,
            subscription,
          })
        : randomId("mpwhgrp");
    if (
      link.authMode === "oauth" &&
      !/^mpwhgrp_[a-f0-9]{64}$/.test(deliveryGroupId)
    ) {
      throw new Error(
        `Invalid canonical OAuth delivery group: ${deliveryGroupId}`,
      );
    }
    const destination =
      callbackUrl ||
      (link.authMode === "oauth"
        ? subscription?.callbackUrl
        : link.webhookUrl || subscription?.callbackUrl);
    if (!destination) throw new Error("No webhook callback URL is configured");
    let webhookBody;
    if (link.authMode === "oauth") {
      const medusaSessionId = link.metadata?.medusaSessionId;
      if (
        !link.companyId ||
        !link.grantId ||
        !link.installationId ||
        !subscription.id ||
        !subscription.signingSecret ||
        !medusaSessionId ||
        !link.amount ||
        !link.fiatCurrency ||
        !makePaySessionId
      ) {
        throw new Error("OAuth webhook correlation fields are incomplete");
      }
      let stable = state.deliveryGroups.get(deliveryGroupId);
      if (!stable) {
        stable = {
          companyId: link.companyId,
          createdAt: eventCreatedAt || new Date().toISOString(),
          grantId: link.grantId,
          installationId: link.installationId,
          paymentLink: {
            uid,
            fiatAmount: String(link.amount),
            fiatCurrency: link.fiatCurrency,
            metadata: {
              medusaSessionId,
              medusaOrderId:
                orderId === undefined
                  ? link.metadata?.medusaOrderId || null
                  : orderId,
              medusaOrderDisplayId:
                orderDisplayId === undefined
                  ? link.metadata?.medusaOrderDisplayId || null
                  : orderDisplayId,
              medusaProviderId: "makepay",
            },
          },
          session: { id: makePaySessionId, settlement: null },
          status,
          subscriptionId: subscription.id,
          uid,
        };
        state.deliveryGroups.set(deliveryGroupId, stable);
      } else if (stable.uid !== uid || stable.status !== status) {
        throw new Error("Delivery group was reused for a different event");
      }
      webhookBody = {
        schemaVersion: "medusa.v1",
        deliveryId,
        deliveryGroupId,
        type: "makepay.payment.status_changed",
        createdAt: stable.createdAt,
        status: stable.status,
        companyId: stable.companyId,
        grantId: stable.grantId,
        subscriptionId: stable.subscriptionId,
        installationId: stable.installationId,
        paymentLink: stable.paymentLink,
        session: stable.session,
      };
    } else if (legacyProductionShape) {
      const payload = asRecord(link.payload);
      webhookBody = {
        createdAt: eventCreatedAt || new Date().toISOString(),
        data: asRecord(legacyData),
        deliveryId: bodyDeliveryId || deliveryId,
        event: { trigger: null, type: "status_changed" },
        paymentLink: {
          amount: firstText(payload.amount) || null,
          asset: firstText(payload.asset) || null,
          clientEmail:
            firstText(
              payload.clientEmail,
              payload.client_email,
              payload.receiptEmail,
              payload.receipt_email,
            ) || null,
          clientId: firstText(payload.clientId, payload.client_id) || null,
          currency: firstText(payload.currency) || null,
          description: firstText(payload.description) || null,
          expiresAt: link.expiresAt || null,
          id: link.id || link.uid,
          label: firstText(payload.label) || null,
          merchantOrderId: firstText(payload.orderId, payload.order_id) || null,
          publicUrl: link.publicUrl,
          status: link.status,
          uid,
        },
        session: {
          channelId: null,
          compositeChannelId: null,
          depositAddress: null,
          destinationAddress: null,
          errorMessage: null,
          expectedBuyAmount: null,
          expiresAt: null,
          id: makePaySessionId,
          invoiceAmount: String(amount ?? link.amount),
          invoiceAsset: firstText(payload.currency) || null,
          previousStatus: status === "complete" ? "sending" : null,
          requiredSellAmount: null,
          resolutionStatus: null,
          selectedSellAsset: null,
          settlement: null,
          settlementAmount: null,
          sourceChain: null,
          status,
        },
        type: "makepay.payment.status_changed",
      };
    } else {
      webhookBody = {
        deliveryId,
        event: { type: "status_changed" },
        paymentLink: {
          amount: String(amount ?? link.amount),
          fiatCurrency: link.fiatCurrency,
          metadata: {
            ...link.metadata,
            medusaInstallationId: link.installationId,
            medusaProviderId: "makepay",
            medusaSessionId:
              sessionId ||
              link.metadata?.medusaSessionId ||
              link.metadata?.session_id,
            session_id:
              sessionId ||
              link.metadata?.medusaSessionId ||
              link.metadata?.session_id,
            source: "medusa",
          },
          uid,
        },
        session: {
          invoiceAmount: String(amount ?? link.amount),
          status,
        },
        type: "makepay.payment.status_changed",
      };
    }
    const body = JSON.stringify(webhookBody);
    const timestamp = nowSeconds();
    const signingSecret =
      link.authMode === "oauth"
        ? subscription?.signingSecret || webhookSecret
        : link.webhookUrl
          ? webhookSecret
          : subscription?.signingSecret || webhookSecret;
    const signature = createHmac("sha256", signingSecret)
      .update(`${timestamp}.${body}`)
      .digest("hex");
    const attemptRecord = {
      attempt: Number(attempt),
      bodySha256: createHash("sha256").update(body).digest("hex"),
      deliveryGroupId,
      deliveryId,
      responseStatus: null,
      status,
      uid,
    };
    const fixture = {
      attemptRecord,
      body,
      destination,
      headers: {
        "content-type": "application/json",
        "user-agent": "makepay-e2e-contract-server/1.0",
        "x-makepay-attempt": String(attempt),
        "x-makepay-delivery-group-id": deliveryGroupId,
        "x-makepay-delivery-id": deliveryId,
        "x-makepay-event": "makepay.payment.status_changed",
        "x-makepay-origin": "sandbox",
        "x-makepay-signature": `t=${timestamp},v1=${
          invalidSignature ? "0".repeat(64) : signature
        }`,
      },
      remoteStatus: updateRemoteStatus
        ? { sessionId: makePaySessionId, status, uid }
        : null,
    };
    if (defer) {
      const preparedId = randomUUID();
      state.preparedWebhooks.set(preparedId, fixture);
      return { deliveryGroupId, deliveryId, preparedId };
    }
    return deliverWebhookFixture(fixture);
  }

  const handleRequest = async (req, res) => {
    const url = requestUrl(req, origin);
    let bodyBuffer = Buffer.alloc(0);
    let body = {};
    try {
      if (!["GET", "HEAD"].includes(req.method || "GET")) {
        bodyBuffer = await readBody(req);
        const contentType = String(req.headers["content-type"] || "");
        body = contentType.includes("application/x-www-form-urlencoded")
          ? Object.fromEntries(new URLSearchParams(bodyBuffer.toString("utf8")))
          : parseJson(bodyBuffer);
      }
      if (!url.pathname.startsWith("/__e2e")) {
        const requestAudit = redactRequest(req, url, body);
        state.requests.push(requestAudit);
        res.once("finish", () => {
          requestAudit.responseStatus = res.statusCode;
        });
      }

      if (url.pathname === "/health") {
        return json(res, 200, { mode: "sandbox-contract", ok: true });
      }

      if (
        url.pathname === "/.well-known/oauth-authorization-server" &&
        req.method === "GET"
      ) {
        return json(res, 200, {
          authorization_endpoint: `${origin}/oauth/authorize`,
          authorization_response_iss_parameter_supported: true,
          grant_types_supported: ["authorization_code", "refresh_token"],
          issuer: origin,
          jwks_uri: `${origin}/oauth/jwks.json`,
          native_installation_endpoint: `${origin}/oauth/native/installations`,
          response_types_supported: ["code"],
          token_endpoint: `${origin}/oauth/token`,
          token_endpoint_auth_methods_supported: ["none"],
        });
      }

      if (url.pathname === "/oauth/jwks.json" && req.method === "GET") {
        return json(res, 200, { keys: [oauthPublicJwk] });
      }

      if (url.pathname.startsWith("/__e2e")) {
        if (!safeEqualText(req.headers["x-e2e-control-token"], controlToken)) {
          return json(res, 404, { error: "not_found" });
        }
        if (url.pathname === "/__e2e/state" && req.method === "GET") {
          return json(res, 200, publicState(state));
        }
        if (url.pathname === "/__e2e/reset" && req.method === "POST") {
          reset();
          return json(res, 200, { ok: true });
        }
        if (
          url.pathname === "/__e2e/oauth-refresh-latch/state" &&
          req.method === "GET"
        ) {
          return json(res, 200, refreshLatchState());
        }
        if (
          url.pathname === "/__e2e/oauth-refresh-latch/arm" &&
          req.method === "POST"
        ) {
          resetRefreshLatch();
          state.refreshLatch.armed = true;
          state.refreshLatch.held = true;
          return json(res, 200, refreshLatchState());
        }
        if (
          url.pathname === "/__e2e/oauth-refresh-latch/release" &&
          req.method === "POST"
        ) {
          return json(res, 200, releaseRefreshLatch());
        }
        if (
          url.pathname === "/__e2e/oauth-refresh-latch/disarm" &&
          req.method === "POST"
        ) {
          return json(res, 200, disarmRefreshLatch());
        }
        if (
          url.pathname === "/__e2e/native-reset-response-loss" &&
          req.method === "POST"
        ) {
          const count = Number(body.count);
          if (!Number.isInteger(count) || count < 0 || count > 3) {
            return json(res, 400, { error: "invalid_response_loss_count" });
          }
          state.nativeResetResponseLosses = count;
          return json(res, 200, { count, ok: true });
        }
        if (url.pathname === "/__e2e/deliver" && req.method === "POST") {
          const preparedId = firstText(body.preparedId);
          const fixture = preparedId
            ? state.preparedWebhooks.get(preparedId)
            : undefined;
          if (!preparedId || !fixture) {
            return json(res, 404, { error: "prepared_webhook_not_found" });
          }
          state.preparedWebhooks.delete(preparedId);
          const result = await deliverWebhookFixture(fixture);
          return json(res, 200, { ok: true, ...result });
        }
        if (
          url.pathname === "/__e2e/workflow-latch/release" &&
          req.method === "POST"
        ) {
          const latch = state.workflowLatches.get(body.uid);
          if (!latch) {
            return json(res, 404, { error: "workflow_latch_not_found" });
          }
          latch.held = false;
          return json(res, 200, {
            held: latch.held,
            hits: latch.hits,
            ok: true,
            uid: body.uid,
          });
        }
        if (
          url.pathname === "/__e2e/link-read-override" &&
          req.method === "POST"
        ) {
          const uid = firstText(body.uid);
          if (!uid || !state.links.has(uid)) {
            return json(res, 404, { error: "payment_link_not_found" });
          }
          if (body.action === "clear") {
            state.linkReadOverrides.delete(uid);
            return json(res, 200, { cleared: true, uid });
          }
          const reads = Number(body.reads);
          if (!Number.isInteger(reads) || reads < 1 || reads > 100) {
            return json(res, 400, { error: "invalid_override_read_count" });
          }
          const values = {};
          for (const field of ["amount", "fiatCurrency", "status"]) {
            if (Object.hasOwn(body, field)) {
              const value = firstText(body[field]);
              if (!value) {
                return json(res, 400, { error: "invalid_override_value" });
              }
              values[field] = value;
            }
          }
          if (!Object.keys(values).length) {
            return json(res, 400, { error: "missing_override_fields" });
          }
          state.linkReadOverrides.set(uid, { remaining: reads, values });
          return json(res, 200, {
            fields: Object.keys(values).sort(),
            remaining: reads,
            uid,
          });
        }
        if (url.pathname === "/__e2e/emit" && req.method === "POST") {
          const result = await emitWebhook(body);
          return json(res, 200, { ok: true, ...result });
        }
        return json(res, 404, { error: "not_found" });
      }

      if (
        url.pathname === "/oauth/native/installations" &&
        req.method === "DELETE"
      ) {
        const clientId = url.searchParams.get("client_id");
        const idempotencyKey = req.headers["idempotency-key"];
        const receiptKey =
          clientId && idempotencyKey
            ? `native-reset:${clientId}:${idempotencyKey}`
            : null;
        const resetReceipt = receiptKey
          ? state.resetReceipts.get(receiptKey)
          : undefined;
        if (resetReceipt) {
          const authorization = String(req.headers.authorization || "");
          const [scheme, token] = authorization.split(" ", 2);
          const verified = verifyDpop({
            accessToken: token,
            method: req.method,
            proof: req.headers.dpop,
            seenJti: state.seenJti,
            url: url.href,
          });
          if (
            scheme !== "DPoP" ||
            createHash("sha256").update(String(token)).digest("hex") !==
              resetReceipt.accessTokenHash ||
            verified.jkt !== resetReceipt.dpopJkt
          ) {
            return json(res, 401, { error: "invalid_reset_receipt_proof" });
          }
          if (state.nativeResetResponseLosses > 0) {
            state.nativeResetResponseLosses -= 1;
            res.destroy();
            return;
          }
          return json(res, 200, resetReceipt.body, {
            "idempotent-replayed": "true",
          });
        }
        if (
          typeof idempotencyKey !== "string" ||
          !/^[A-Za-z0-9_-]{8,200}$/.test(idempotencyKey)
        ) {
          return json(res, 400, { error: "invalid_idempotency_key" });
        }
        const authorization = String(req.headers.authorization || "");
        const [, accessToken] = authorization.split(" ", 2);
        const accessTokenRecord = state.accessTokens.get(accessToken);
        const auth = authenticate(req, url);
        const installation = state.installations.get(clientId);
        if (!installation || installation.clientId !== auth.installationId) {
          return json(res, 404, { error: "native_installation_not_found" });
        }
        const preservedWebhookSubscriptionIds = [
          ...state.subscriptions.values(),
        ]
          .filter(
            (subscription) =>
              subscription.installationId === installation.clientId,
          )
          .map((subscription) => subscription.id)
          .sort();
        for (const subscription of state.subscriptions.values()) {
          if (subscription.installationId === installation.clientId) {
            subscription.status = "disabled";
          }
        }
        installation.dpopJkt = null;
        installation.pendingDpopJkt = null;
        installation.reset = true;
        state.grantIdsByInstallation.delete(installation.clientId);
        for (const access of state.accessTokens.values()) {
          if (access.installationId === installation.clientId) {
            access.revoked = true;
          }
        }
        for (const refresh of state.refreshTokens.values()) {
          if (refresh.installationId === installation.clientId) {
            refresh.revoked = true;
          }
        }
        for (const [code, authorization] of state.authorizationCodes) {
          if (authorization.clientId === clientId) {
            state.authorizationCodes.delete(code);
          }
        }
        const responseBody = {
          client_id: clientId,
          historicalDeliveryPreserved: true,
          preservedWebhookSubscriptionIds,
          reset: true,
          resetMutationId: randomUUID(),
          signingSecretChanged: false,
        };
        state.resetReceipts.set(receiptKey, {
          accessTokenHash: createHash("sha256")
            .update(String(accessToken))
            .digest("hex"),
          body: responseBody,
          dpopJkt: accessTokenRecord.dpopJkt,
        });
        if (state.nativeResetResponseLosses > 0) {
          state.nativeResetResponseLosses -= 1;
          res.destroy();
          return;
        }
        return json(res, 200, responseBody);
      }

      if (
        url.pathname === "/oauth/native/installations" &&
        req.method === "POST"
      ) {
        const verified = verifyDpop({
          method: "POST",
          proof: req.headers.dpop,
          seenJti: state.seenJti,
          url: url.href,
        });
        for (const required of [
          "platform",
          "registrationId",
          "siteUrl",
          "redirectUri",
          "dpopJkt",
          "pluginVersion",
          "medusaVersion",
        ]) {
          if (!body[required]) {
            return json(res, 400, { error: `missing_${required}` });
          }
        }
        let siteUrl;
        try {
          siteUrl = new URL(body.siteUrl);
        } catch {
          siteUrl = null;
        }
        const loopback =
          siteUrl &&
          ["127.0.0.1", "localhost", "[::1]"].includes(siteUrl.hostname);
        if (
          body.platform !== "medusa" ||
          body.dpopJkt !== verified.jkt ||
          !/^[A-Za-z0-9_-]{43}$/.test(body.registrationId) ||
          !siteUrl ||
          body.siteUrl !== siteUrl.origin ||
          (siteUrl.protocol !== "https:" &&
            !(siteUrl.protocol === "http:" && loopback)) ||
          body.redirectUri !== `${siteUrl.origin}/makepay/oauth/callback`
        ) {
          return json(res, 400, { error: "invalid_native_installation" });
        }
        const existing = [...state.installations.values()].find(
          (candidate) =>
            candidate.platform === body.platform &&
            candidate.registrationId === body.registrationId,
        );
        let installation = existing;
        let status = 200;
        if (existing) {
          if (existing.siteUrl !== body.siteUrl) {
            return json(res, 409, { error: "registration_identity_mismatch" });
          }
          if (!existing.reset) {
            if (!req.headers["dpop-previous"]) {
              return json(res, 401, { error: "previous_dpop_required" });
            }
            const previous = verifyDpop({
              method: "POST",
              proof: req.headers["dpop-previous"],
              seenJti: state.seenJti,
              url: url.href,
            });
            if (previous.jkt !== existing.dpopJkt) {
              return json(res, 401, { error: "invalid_previous_dpop_key" });
            }
          }
          if (existing.reset) {
            existing.dpopJkt = verified.jkt;
            existing.pendingDpopJkt = null;
          } else {
            existing.pendingDpopJkt = verified.jkt;
          }
          existing.redirectUri = body.redirectUri;
          existing.reset = false;
        } else {
          const id = randomId("installation");
          const clientId = randomId("client");
          installation = {
            clientId,
            companyId,
            dpopJkt: verified.jkt,
            id,
            pendingDpopJkt: null,
            platform: body.platform,
            registrationId: body.registrationId,
            redirectUri: body.redirectUri,
            reset: false,
            siteUrl: body.siteUrl,
          };
          state.installations.set(clientId, installation);
          status = 201;
        }
        return json(res, status, {
          client_id: installation.clientId,
          client_type: "public",
          dpop_bound: true,
          registration_id: installation.registrationId,
          redirect_uri: installation.redirectUri,
          scopes: oauthScopes,
          ...(status === 201 ? { status: "active" } : {}),
        });
      }

      if (url.pathname === "/oauth/authorize" && req.method === "GET") {
        const clientId = url.searchParams.get("client_id");
        const installation = state.installations.get(clientId);
        const redirectUri = url.searchParams.get("redirect_uri");
        const stateParam = url.searchParams.get("state");
        const challenge = url.searchParams.get("code_challenge");
        const requestedDpopJkt = url.searchParams.get("dpop_jkt");
        if (
          !installation ||
          redirectUri !== installation.redirectUri ||
          url.searchParams.get("response_type") !== "code" ||
          url.searchParams.get("code_challenge_method") !== "S256" ||
          !requestedDpopJkt ||
          (requestedDpopJkt !== installation.dpopJkt &&
            requestedDpopJkt !== installation.pendingDpopJkt) ||
          url.searchParams.get("resource") !== `${origin}/api/partner/v1` ||
          oauthScopes.some(
            (scope) =>
              !String(url.searchParams.get("scope") || "")
                .split(/\s+/)
                .includes(scope),
          ) ||
          !stateParam ||
          !challenge
        ) {
          return json(res, 400, { error: "invalid_authorization_request" });
        }
        if (url.searchParams.get("decision")) {
          const target = new URL(redirectUri);
          target.searchParams.set("state", stateParam);
          target.searchParams.set("iss", origin);
          if (url.searchParams.get("decision") === "deny") {
            target.searchParams.set("error", "access_denied");
          } else {
            if (
              installation.pendingDpopJkt &&
              requestedDpopJkt === installation.pendingDpopJkt
            ) {
              for (const access of state.accessTokens.values()) {
                if (access.installationId === installation.clientId) {
                  access.revoked = true;
                }
              }
              for (const refresh of state.refreshTokens.values()) {
                if (refresh.installationId === installation.clientId) {
                  refresh.revoked = true;
                }
              }
              installation.dpopJkt = installation.pendingDpopJkt;
              installation.pendingDpopJkt = null;
            }
            const code = randomId("code");
            state.authorizationCodes.set(code, {
              challenge,
              clientId,
              dpopJkt: requestedDpopJkt,
              redirectUri,
              used: false,
            });
            target.searchParams.set("code", code);
          }
          res.writeHead(302, { location: target.href });
          return res.end();
        }
        const escapedApprove = `${url.href}&decision=approve`.replaceAll(
          "&",
          "&amp;",
        );
        const escapedDeny = `${url.href}&decision=deny`.replaceAll(
          "&",
          "&amp;",
        );
        return html(
          res,
          200,
          `<!doctype html><html><head><title>MakePay sandbox consent</title></head><body><main><h1>Connect Medusa to MakePay</h1><p>Sandbox merchant: E2E Merchant</p><p>No real funds are accepted by this contract server.</p><a data-testid="approve" href="${escapedApprove}">Approve</a><a data-testid="deny" href="${escapedDeny}">Deny</a></main></body></html>`,
        );
      }

      if (url.pathname === "/oauth/token" && req.method === "POST") {
        const verified = verifyDpop({
          method: "POST",
          proof: req.headers.dpop,
          seenJti: state.seenJti,
          url: url.href,
        });
        const tokenIdempotencyKey = req.headers["idempotency-key"];
        if (
          typeof tokenIdempotencyKey !== "string" ||
          !/^medusa-token-[A-Za-z0-9_-]{43}$/.test(tokenIdempotencyKey)
        ) {
          return json(res, 400, { error: "invalid_idempotency_key" });
        }
        const credential =
          body.grant_type === "authorization_code"
            ? body.code
            : body.refresh_token;
        const tokenReceiptKey = `token:${body.grant_type}:${createHash("sha256")
          .update(String(credential || ""))
          .digest("hex")}:${tokenIdempotencyKey}`;
        if (body.grant_type === "authorization_code") {
          const record = state.authorizationCodes.get(body.code);
          if (
            !record ||
            record.clientId !== body.client_id ||
            record.redirectUri !== body.redirect_uri ||
            body.resource !== `${origin}/api/partner/v1` ||
            sha256Base64url(body.code_verifier || "") !== record.challenge
          ) {
            return json(res, 400, { error: "invalid_grant" });
          }
          const installation = state.installations.get(record.clientId);
          if (
            !installation ||
            record.dpopJkt !== verified.jkt ||
            installation.dpopJkt !== verified.jkt
          ) {
            return json(res, 400, { error: "invalid_dpop_key" });
          }
          if (state.idempotency.has(tokenReceiptKey)) {
            return json(res, 200, state.idempotency.get(tokenReceiptKey), {
              "idempotent-replayed": "true",
            });
          }
          if (record.used) {
            return json(res, 400, { error: "invalid_grant" });
          }
          record.used = true;
          const tokenBody = issueTokens(installation);
          state.idempotency.set(tokenReceiptKey, tokenBody);
          return json(res, 200, tokenBody);
        }
        if (body.grant_type === "refresh_token") {
          const refresh = state.refreshTokens.get(body.refresh_token);
          if (
            !refresh ||
            refresh.revoked ||
            body.client_id !== refresh.clientId ||
            body.resource !== `${origin}/api/partner/v1`
          ) {
            return json(res, 400, { error: "invalid_grant" });
          }
          if (refresh.dpopJkt !== verified.jkt) {
            return json(res, 400, { error: "invalid_dpop_key" });
          }
          if (state.idempotency.has(tokenReceiptKey)) {
            return json(res, 200, state.idempotency.get(tokenReceiptKey), {
              "idempotent-replayed": "true",
            });
          }
          if (refresh.rotated) {
            return json(res, 400, { error: "invalid_grant" });
          }
          const installation = state.installations.get(refresh.clientId);
          if (
            !installation ||
            installation.dpopJkt !== refresh.dpopJkt
          ) {
            return json(res, 400, { error: "invalid_grant" });
          }
          await waitAtRefreshLatch();
          if (refresh.revoked || refresh.rotated) {
            return json(res, 400, { error: "invalid_grant" });
          }
          refresh.rotated = true;
          const tokenBody = issueTokens(
            installation,
            refresh.familyId,
            refresh.grantId,
          );
          state.idempotency.set(tokenReceiptKey, tokenBody);
          return json(res, 200, tokenBody);
        }
        return json(res, 400, { error: "unsupported_grant_type" });
      }

      if (url.pathname === "/oauth/revoke" && req.method === "POST") {
        const token = body.token;
        const refresh = state.refreshTokens.get(token);
        if (refresh) {
          for (const access of state.accessTokens.values()) {
            if (access.familyId === refresh.familyId) access.revoked = true;
          }
          for (const candidate of state.refreshTokens.values()) {
            if (candidate.familyId === refresh.familyId)
              candidate.revoked = true;
          }
          const subscription = state.subscriptions.get(refresh.grantId);
          if (subscription) subscription.status = "disabled";
        }
        return json(res, 200, { ok: true });
      }

      if (subscriptionPath(url.pathname)) {
        const auth = authenticate(req, url);
        const currentSubscription =
          state.subscriptions.get(auth.grantId) || null;
        if (req.method === "GET") {
          return json(res, 200, {
            companyId: auth.companyId,
            subscription: publicSubscription(currentSubscription),
          });
        }
        if (req.method === "PUT") {
          const idempotencyKey = req.headers["idempotency-key"];
          const scopedIdempotencyKey = idempotencyKey
            ? `webhook:${auth.grantId}:${idempotencyKey}`
            : null;
          const priorReceipt = scopedIdempotencyKey
            ? state.webhookMutationReceipts.get(scopedIdempotencyKey)
            : undefined;
          if (priorReceipt) {
            if (priorReceipt.expiresAt <= Date.now()) {
              return json(res, 409, {
                error: "idempotency_receipt_expired",
              });
            }
            if (priorReceipt.dpopJkt !== auth.dpopJkt) {
              return json(res, 409, {
                error: "idempotency_key_dpop_mismatch",
              });
            }
            return json(res, 200, priorReceipt.responseBody, {
              "idempotent-replayed": "true",
            });
          }
          const callbackUrl =
            body.url || body.endpointUrl || body.callbackUrl || body.webhookUrl;
          if (!callbackUrl)
            return json(res, 400, { error: "missing_callback_url" });
          const subscription = {
            callbackUrl,
            companyId: auth.companyId,
            grantId: auth.grantId,
            id: currentSubscription?.id || randomId("subscription"),
            installationId: auth.installationId,
            status: "active",
            signingSecret:
              !currentSubscription || body.rotateSecret === true
                ? state.subscriptions.size === 0 && !currentSubscription
                  ? webhookSecret
                  : randomId("e2e_webhook_secret")
                : currentSubscription.signingSecret,
          };
          state.subscriptions.set(auth.grantId, subscription);
          const responseBody = {
            companyId: auth.companyId,
            created: !currentSubscription,
            ok: true,
            signingSecret: subscription.signingSecret,
            subscription: publicSubscription(subscription),
          };
          if (scopedIdempotencyKey) {
            state.webhookMutationReceipts.set(scopedIdempotencyKey, {
              dpopJkt: auth.dpopJkt,
              expiresAt: Date.now() + 10 * 60 * 1000,
              responseBody,
            });
          }
          return json(res, 200, responseBody);
        }
        if (req.method === "DELETE") {
          if (!currentSubscription) {
            return json(res, 404, { error: "webhook_subscription_not_found" });
          }
          currentSubscription.status = "disabled";
          return json(res, 200, {
            companyId: auth.companyId,
            historicalDeliveryPreserved: true,
            ok: true,
            signingSecretChanged: false,
            subscription: publicSubscription(currentSubscription),
          });
        }
      }

      const match = paymentPath(url.pathname);
      if (match) {
        const auth = authenticate(req, url);
        if (match.companyId && match.companyId !== auth.companyId) {
          return json(res, 403, { error: "wrong_company" });
        }
        if (!match.uid && req.method === "POST") {
          const requestPayload = body.payload || body;
          if (requestPayload.sandbox === false) {
            return json(res, 400, { error: "e2e_requires_sandbox" });
          }
          const idempotencyKey = req.headers["idempotency-key"];
          const scopedIdempotencyKey = idempotencyKey
            ? `${auth.grantId}:${idempotencyKey}`
            : null;
          if (
            scopedIdempotencyKey &&
            state.idempotency.has(scopedIdempotencyKey)
          ) {
            return json(res, 200, state.idempotency.get(scopedIdempotencyKey));
          }
          const uid = randomId("pay_e2e");
          const subscription = state.subscriptions.get(auth.grantId);
          if (auth.mode === "oauth" && subscription?.status !== "active") {
            return json(res, 409, { error: "webhook_subscription_inactive" });
          }
          const amount = String(requestPayload.amount);
          const fiatCurrency = String(
            requestPayload.fiatCurrency || "EUR",
          ).toUpperCase();
          const payload = {
            ...requestPayload,
            amount,
            fiatCurrency,
            metadata: asRecord(requestPayload.metadata),
            sandbox: true,
          };
          const link = {
            amount,
            authMode: auth.mode,
            companyId: auth.companyId,
            createdAt: new Date().toISOString(),
            fiatCurrency,
            grantId: auth.grantId,
            installationId: auth.installationId,
            metadata: payload.metadata,
            payload,
            publicUrl: `${origin}/payment/${uid}`,
            failureUrl: requestPayload.failureUrl || null,
            returnUrl: requestPayload.returnUrl || null,
            sandbox: true,
            status: body.status || "active",
            successUrl: requestPayload.successUrl || null,
            uid,
            webhookSubscriptionId: subscription?.id || null,
            webhookUrl: requestPayload.webhookUrl || null,
          };
          state.links.set(uid, link);
          state.paymentSessionIds.set(uid, randomId("mpses"));
          const responseBody = {
            companyId: auth.companyId,
            ok: true,
            paymentRequestEmailError: null,
            paymentRequestEmailSent: false,
            paymentLink: serializePaymentLink(link),
          };
          if (scopedIdempotencyKey) {
            state.idempotency.set(scopedIdempotencyKey, responseBody);
          }
          return json(res, 201, responseBody);
        }
        if (!match.uid && req.method === "GET") {
          return json(res, 200, {
            companyId: auth.companyId,
            paymentLinks: [...state.links.values()]
              .filter((link) => link.grantId === auth.grantId)
              .map((link) => serializePaymentLink(link)),
          });
        }
        const link = state.links.get(match.uid);
        if (!link) return json(res, 404, { error: "payment_link_not_found" });
        if (link.grantId !== auth.grantId) {
          return json(res, 404, { error: "payment_link_not_found" });
        }
        if (req.method === "GET") {
          const workflowLatch = state.workflowLatches.get(link.uid);
          const readOverride = state.linkReadOverrides.get(link.uid);
          const values = readOverride?.values || {};
          const payload =
            values.amount || values.fiatCurrency
              ? {
                  ...link.payload,
                  ...(values.amount ? { amount: values.amount } : {}),
                  ...(values.fiatCurrency
                    ? { fiatCurrency: values.fiatCurrency }
                    : {}),
                }
              : link.payload;
          const status = workflowLatch?.held
            ? "processing"
            : values.status || link.latestSession?.status;
          const overrides = {
            ...(payload !== link.payload ? { payload } : {}),
            ...(status
              ? { latestSession: { ...link.latestSession, status } }
              : {}),
          };
          if (workflowLatch?.held) {
            workflowLatch.hits += 1;
          }
          if (readOverride) {
            readOverride.remaining -= 1;
            if (readOverride.remaining <= 0) {
              state.linkReadOverrides.delete(link.uid);
            }
          }
          return json(res, 200, {
            companyId: auth.companyId,
            paymentLink: serializePaymentLink(
              link,
              Object.keys(overrides).length ? overrides : undefined,
            ),
          });
        }
        if (["PATCH", "PUT"].includes(req.method || "")) {
          if (body.status === "archived") {
            if (link.status === "archived") {
              return json(res, 409, {
                archiveEligibility: "already_archived",
                errorCode: "payment_link_already_archived",
              });
            }
            if (link.latestSession || link.sessionCreationClaimed) {
              return json(res, 409, {
                archiveEligibility: "session_started",
                errorCode: "payment_link_has_session",
                latestSession: link.latestSession ?? null,
                sessionCreationClaimed: Boolean(link.sessionCreationClaimed),
              });
            }
            link.status = "archived";
            link.timelineEvents = [];
            return json(res, 200, {
              archiveEligibility: "no_session",
              archivedWithNoSession: true,
              companyId: auth.companyId,
              latestSession: null,
              ok: true,
              paymentLink: serializePaymentLink(link, {
                latestSession: null,
                timelineEvents: [],
              }),
              sessionCreationClaimed: false,
            });
          }
          const mutableFields = [
            "failureUrl",
            "returnUrl",
            "status",
            "successUrl",
            "webhookUrl",
          ];
          for (const key of mutableFields) {
            if (Object.hasOwn(body, key)) {
              link[key] = body[key];
              if (key !== "status") {
                link.payload = { ...link.payload, [key]: body[key] };
              }
            }
          }
          const { metadata } = body;
          if (metadata && typeof metadata === "object") {
            link.metadata = { ...link.metadata, ...metadata };
            link.payload = { ...link.payload, metadata: link.metadata };
          }
          return json(res, 200, {
            companyId: auth.companyId,
            paymentLink: serializePaymentLink(link),
          });
        }
      }

      const hostedMatch = url.pathname.match(/^\/payment\/([^/]+)$/);
      if (hostedMatch && req.method === "GET") {
        const link = state.links.get(decodeURIComponent(hostedMatch[1]));
        if (!link) return html(res, 404, "<h1>Payment link not found</h1>");
        return html(
          res,
          200,
          `<!doctype html><html><head><title>MakePay sandbox checkout</title></head><body><main data-testid="sandbox-checkout"><h1>Pay ${link.amount} ${link.fiatCurrency}</h1><strong>Sandbox mode</strong><p>Demo payment instructions only. Do not send real funds.</p><form method="post" action="/payment/${link.uid}/start"><button data-testid="start-payment" type="submit">Start sandbox payment</button></form></main></body></html>`,
        );
      }

      const startMatch = url.pathname.match(/^\/payment\/([^/]+)\/start$/);
      if (startMatch && req.method === "POST") {
        const link = state.links.get(decodeURIComponent(startMatch[1]));
        if (!link) return html(res, 404, "<h1>Payment link not found</h1>");
        link.latestSession = {
          id: state.paymentSessionIds.get(link.uid),
          status: "awaiting_deposit",
        };
        const subscription = state.subscriptions.get(link.grantId);
        const hasCallback =
          link.authMode === "oauth"
            ? Boolean(subscription?.callbackUrl)
            : Boolean(link.webhookUrl || subscription?.callbackUrl);
        if (hasCallback) {
          await emitWebhook({ status: "awaiting_deposit", uid: link.uid });
        }
        return html(
          res,
          200,
          `<!doctype html><html><head><title>MakePay sandbox instructions</title></head><body><main data-testid="sandbox-instructions"><h1>Sandbox payment instructions</h1><code data-testid="sandbox-address">SANDBOX-DO-NOT-SEND-BTC-USDT-${link.uid}</code><p>Do not send cryptocurrency. This address can never settle a real payment.</p></main></body></html>`,
        );
      }

      return json(res, 404, { error: "not_found" });
    } catch (error) {
      const status = Number(error.status) || 400;
      return json(res, status, { error: error.message || "request_failed" });
    }
  };
  const server = options.tls
    ? createHttpsServer(options.tls, handleRequest)
    : createHttpServer(handleRequest);
  let closePromise;

  function closeContract() {
    resetRefreshLatch();
    closePromise ??= new Promise((resolve, reject) => {
      server.close((error) => {
        if (error && error.code !== "ERR_SERVER_NOT_RUNNING") reject(error);
        else resolve();
      });
      // A failed browser assertion can leave pooled keep-alive connections
      // open. They contain no state that must outlive the fixture process.
      server.closeAllConnections?.();
    });
    return closePromise;
  }

  return {
    apiKeyId,
    apiKeySecret,
    close: closeContract,
    controlToken,
    emitWebhook,
    get origin() {
      return origin;
    },
    reset,
    start: () =>
      new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(options.port || 0, host, () => {
          server.off("error", reject);
          const address = server.address();
          origin = `${options.tls ? "https" : "http"}://${host}:${address.port}`;
          resolve(origin);
        });
      }),
    state,
    webhookSecret,
  };
}

async function runStandalone() {
  const contract = createMakePayContractServer({
    apiKeyId: process.env.MAKEPAY_E2E_KEY_ID,
    apiKeySecret: process.env.MAKEPAY_E2E_KEY_SECRET,
    controlToken: process.env.MAKEPAY_E2E_CONTROL_TOKEN,
    host: process.env.MAKEPAY_E2E_CONTRACT_HOST,
    port: Number(process.env.MAKEPAY_E2E_CONTRACT_PORT || 43110),
    webhookSecret: process.env.MAKEPAY_E2E_WEBHOOK_SECRET,
  });
  await contract.start();
  process.stdout.write(
    `${JSON.stringify({ mode: "sandbox-contract", origin: contract.origin })}\n`,
  );
  const stop = async () => {
    await contract.close();
    process.exit(0);
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  runStandalone().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
