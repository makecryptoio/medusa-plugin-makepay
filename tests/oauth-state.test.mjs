import assert from "node:assert/strict";
import { createHash, createHmac, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import { MakePayError } from "@makecrypto/makepay";

import { MAKEPAY_OAUTH_SCOPES } from "../src/modules/makepay/constants.ts";
import {
  createDpopKeyPair,
  decryptSecret,
  encryptSecret,
  sha256,
} from "../src/modules/makepay/crypto.ts";
import MakePayModuleService, {
  makePayWebhookRotationIdempotencyKey,
} from "../src/modules/makepay/service.ts";

function base64Url(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function dpopProofThumbprint(proof) {
  const [encodedHeader] = String(proof || "").split(".");
  assert.ok(encodedHeader, "DPoP proof header is required");
  const header = JSON.parse(
    Buffer.from(encodedHeader, "base64url").toString("utf8"),
  );
  assert.equal(header.alg, "ES256");
  assert.equal(header.typ, "dpop+jwt");
  assert.equal(header.jwk?.crv, "P-256");
  assert.equal(header.jwk?.kty, "EC");
  assert.equal(typeof header.jwk?.x, "string");
  assert.equal(typeof header.jwk?.y, "string");
  return base64Url(
    createHash("sha256")
      .update(
        JSON.stringify({
          crv: header.jwk.crv,
          kty: header.jwk.kty,
          x: header.jwk.x,
          y: header.jwk.y,
        }),
      )
      .digest(),
  );
}

function createService(overrides = {}) {
  const service = Object.create(MakePayModuleService.prototype);
  service.providerConfigurationRegistered_ = true;
  service.options_ = {
    authMode: "oauth",
    backendUrl: "https://api.shop.test",
    encryptionKey: Buffer.alloc(32, 3).toString("base64"),
    oauthApiUrl: "https://api.makecrypto.test",
    oauthIssuerUrl: "https://makecrypto.test",
    lockingProvider: "makepay-postgres",
    providerId: "makepay",
    storefrontReturnUrl: "https://shop.test/order/confirmed",
    ...overrides.options,
  };
  service.logger_ = { warn() {} };
  service.hasUndrainedPayments = async () => false;
  service.lockingService = () => ({
    execute: async (_key, job) => job(),
  });
  return service;
}

function discoveryResponse(url) {
  if (
    url !== "https://makecrypto.test/.well-known/oauth-authorization-server"
  ) {
    return undefined;
  }

  return new Response(
    JSON.stringify({
      authorization_endpoint: "https://makecrypto.test/oauth/authorize",
      authorization_response_iss_parameter_supported: true,
      issuer: "https://makecrypto.test",
      jwks_uri: "https://makecrypto.test/oauth/jwks.json",
      native_installation_endpoint:
        "https://makecrypto.test/oauth/native/installations",
      token_endpoint: "https://makecrypto.test/oauth/token",
    }),
    { headers: { "content-type": "application/json" } },
  );
}

test("webhook rotation idempotency is stable per OAuth attempt and unique across reconnects", () => {
  const base = {
    dpopThumbprint: "jkt_same",
    grantId: "grant_same",
    installationId: "installation_same",
  };
  const first = makePayWebhookRotationIdempotencyKey({
    ...base,
    oauthAttemptId: "mpost_attempt_1",
  });
  assert.equal(
    first,
    makePayWebhookRotationIdempotencyKey({
      ...base,
      oauthAttemptId: "mpost_attempt_1",
    }),
  );
  assert.notEqual(
    first,
    makePayWebhookRotationIdempotencyKey({
      ...base,
      oauthAttemptId: "mpost_attempt_2",
    }),
  );
  assert.notEqual(
    first,
    makePayWebhookRotationIdempotencyKey({
      ...base,
      dpopThumbprint: "jkt_replaced",
      oauthAttemptId: "mpost_attempt_1",
    }),
  );
  assert.match(first, /^medusa-webhook-[a-f0-9]{40}$/);
});

test("pending webhook rotation replays across response loss and permits an endpoint change", async () => {
  const service = createService({
    options: { backendUrl: "https://new-api.shop.test" },
  });
  const idempotencyKey = makePayWebhookRotationIdempotencyKey({
    dpopThumbprint: "jkt_rotation",
    grantId: "grant_rotation",
    installationId: "installation_rotation",
    oauthAttemptId: "mpost_rotation",
  });
  const connection = {
    company_id: "company_rotation",
    grant_id: "grant_rotation",
    id: "mpcon_rotation",
    installation_id: "installation_rotation",
    metadata: {
      dpop_thumbprint: "jkt_rotation",
      webhook_rotation: {
        company_id: "company_rotation",
        dpop_thumbprint: "jkt_rotation",
        endpoint_url: "https://new-api.shop.test/hooks/makepay/makepay_makepay",
        grant_id: "grant_rotation",
        idempotency_key: idempotencyKey,
        installation_id: "installation_rotation",
        oauth_attempt_id: "mpost_rotation",
      },
    },
    provider_id: "makepay",
    webhook_url: "https://new-api.shop.test/hooks/makepay/makepay_makepay",
  };
  const credential = {
    company_id: "company_rotation",
    encrypted_signing_secret: "old-encrypted-value",
    endpoint_url: "https://old-tunnel.example/hooks/makepay/makepay_makepay",
    grant_id: "grant_rotation",
    id: "mpwsub_rotation",
    installation_id: "installation_rotation",
    provider_id: "makepay",
    status: "active",
    subscription_id: "subscription_rotation",
  };
  const attempts = [];
  let responseLost = true;
  service.connectionRecord = async () => connection;
  service.createClient = async () => ({
    async upsertCurrentWebhookSubscription(payload, options) {
      attempts.push({ options, payload });
      if (responseLost) {
        responseLost = false;
        throw new TypeError("simulated committed response loss");
      }
      return {
        signingSecret: "rotated-secret",
        subscription: { id: "subscription_rotation" },
      };
    },
  });
  service.generated = () => ({
    listMakePayWebhookSubscriptions: async (filters = {}) =>
      (!filters.subscription_id ||
        filters.subscription_id === credential.subscription_id) &&
      (!filters.status || filters.status === credential.status)
        ? [credential]
        : [],
    updateMakePayConnections: async (update) => {
      const { metadata, ...fields } = update;
      Object.assign(connection, fields);
      if (metadata) {
        // Mirror Medusa's generated JSON update behavior: metadata is merged,
        // so lifecycle fields must use explicit null tombstones to be cleared.
        connection.metadata = { ...connection.metadata, ...metadata };
      }
      return connection;
    },
    updateMakePayWebhookSubscriptions: async (update) => {
      Object.assign(credential, update);
      return credential;
    },
  });

  await assert.rejects(
    service.recoverPendingWebhookRotation(
      {
        ...connection,
        metadata: {
          ...connection.metadata,
          dpop_thumbprint: "jkt_replaced",
        },
      },
      { alreadyLocked: true },
    ),
    /pending webhook rotation metadata is invalid/i,
  );

  await assert.rejects(
    service.recoverPendingWebhookRotation(connection, { alreadyLocked: true }),
    /response loss/i,
  );
  assert.ok(connection.metadata.webhook_rotation);
  const recovered = await service.recoverPendingWebhookRotation(connection, {
    alreadyLocked: true,
  });
  assert.equal(recovered.status, "connected");
  assert.equal(recovered.metadata.webhook_rotation, null);
  assert.equal(credential.endpoint_url, connection.webhook_url);
  assert.equal(credential.status, "active");
  assert.deepEqual(
    attempts.map((attempt) => attempt.options.idempotencyKey),
    [idempotencyKey, idempotencyKey],
  );
  const encryptionKey = Buffer.alloc(32, 3);
  assert.equal(
    decryptSecret(
      credential.encrypted_signing_secret,
      encryptionKey,
      "webhook-subscription:mpwsub_rotation:signing-secret",
    ),
    "rotated-secret",
  );
  assert.equal(
    decryptSecret(
      recovered.encrypted_webhook_secret,
      encryptionKey,
      "connection:mpcon_rotation:webhook-secret",
    ),
    "rotated-secret",
  );
});

test("webhook rotation recovery acquires its connection lock exactly once", async () => {
  const service = createService();
  const connection = {
    access_token_expires_at: new Date(Date.now() + 300_000),
    id: "mpcon_lock_once",
    metadata: {},
  };
  const locks = [];
  service.connectionRecord = async () => connection;
  service.withDistributedLock = async (key, job, timeout) => {
    locks.push({ key, timeout });
    return job();
  };

  assert.equal(
    await service.recoverPendingWebhookRotation(connection),
    connection,
  );
  assert.deepEqual(locks, [
    { key: "makepay-oauth-connection:mpcon_lock_once", timeout: 30 },
  ]);

  assert.equal(
    await service.recoverPendingWebhookRotation(connection, {
      alreadyLocked: true,
    }),
    connection,
  );
  assert.equal(
    locks.length,
    1,
    "a caller already holding the connection lock must never self-reacquire it",
  );
});

test("expired exact refresh recovery permits OAuth restart without changing the pending webhook mutation", async () => {
  const service = createService();
  const encryptionKey = Buffer.alloc(32, 3);
  const dpop = createDpopKeyPair();
  const refreshToken = "refresh-before-ambiguous-rotation";
  const registrationId = base64Url(Buffer.alloc(32, 7));
  const webhookUrl = "https://api.shop.test/hooks/makepay/makepay_makepay";
  const webhookIdempotencyKey = makePayWebhookRotationIdempotencyKey({
    dpopThumbprint: dpop.thumbprint,
    grantId: "grant_recovery",
    installationId: "client_recovery",
    oauthAttemptId: "mpost_original_recovery",
  });
  const connection = {
    access_token_expires_at: new Date(Date.now() + 300_000),
    client_id: "client_recovery",
    company_id: "company_recovery",
    encrypted_access_token: "unused-by-test-credentials",
    encrypted_dpop_private_key: encryptSecret(
      dpop.privateKeyPem,
      encryptionKey,
      "connection:mpcon_recovery:dpop",
    ),
    encrypted_refresh_token: "unused-by-test-credentials",
    encrypted_registration_id: encryptSecret(
      registrationId,
      encryptionKey,
      "connection:mpcon_recovery:registration-id",
    ),
    grant_id: "grant_recovery",
    id: "mpcon_recovery",
    installation_id: "client_recovery",
    metadata: {
      dpop_thumbprint: dpop.thumbprint,
      webhook_rotation: {
        company_id: "company_recovery",
        dpop_thumbprint: dpop.thumbprint,
        endpoint_url: webhookUrl,
        grant_id: "grant_recovery",
        idempotency_key: webhookIdempotencyKey,
        installation_id: "client_recovery",
        oauth_attempt_id: "mpost_original_recovery",
      },
    },
    provider_id: "makepay",
    status: "error",
    webhook_status: "error",
    webhook_url: webhookUrl,
  };
  const states = [];
  let tokenRequests = 0;
  let registrationRequests = 0;
  service.connectionRecord = async () => connection;
  service.oauthCredentials = async () => ({
    accessToken: "access-before-ambiguous-rotation",
    connection,
    expiresAt: new Date(connection.access_token_expires_at),
    privateKey: dpop.privateKeyPem,
    refreshToken,
  });
  service.discoverOAuth = async () => ({
    authorizationEndpoint: "https://makecrypto.test/oauth/authorize",
    jwksUri: "https://makecrypto.test/oauth/jwks.json",
    nativeInstallationEndpoint:
      "https://makecrypto.test/oauth/native/installations",
    tokenEndpoint: "https://makecrypto.test/oauth/token",
  });
  service.generated = () => ({
    createMakePayOAuthStates: async (input) => {
      states.push({ ...input, created_at: new Date() });
      return input;
    },
    listMakePayOAuthStates: async () => states,
    listMakePayPaymentProjections: async () => [],
    updateMakePayConnections: async (update) => {
      Object.assign(connection, update);
      return connection;
    },
    updateMakePayOAuthStates: async (update) => {
      const state = states.find((candidate) => candidate.id === update.id);
      Object.assign(state, update);
      return state;
    },
  });
  service.fetch_ = async (url, init) => {
    if (url === "https://makecrypto.test/oauth/token") {
      tokenRequests += 1;
      return new Response(JSON.stringify({ error: "invalid_grant" }), {
        headers: {
          "content-type": "application/json",
          "oauth-token-recovery": "expired",
        },
        status: 400,
      });
    }
    assert.equal(url, "https://makecrypto.test/oauth/native/installations");
    registrationRequests += 1;
    const payload = JSON.parse(init.body);
    assert.equal(payload.registrationId, registrationId);
    assert.match(init.headers["dpop-previous"], /^[^.]+\.[^.]+\.[^.]+$/);
    return new Response(
      JSON.stringify({
        client_id: "client_recovery",
        registration_id: registrationId,
        scopes: [...MAKEPAY_OAUTH_SCOPES],
      }),
      { headers: { "content-type": "application/json" } },
    );
  };

  await assert.rejects(
    service.performRefresh(connection.id),
    (error) => error?.name === "OAuthTokenRecoveryExpiredError",
  );
  const terminalAttempt = connection.metadata.refresh_attempt;
  assert.equal(terminalAttempt.recovery_expired, true);
  assert.equal(terminalAttempt.credential_fingerprint, sha256(refreshToken));
  assert.match(
    terminalAttempt.idempotency_key,
    /^medusa-token-[A-Za-z0-9_-]{43}$/,
  );

  const started = await service.startOAuth();
  assert.equal(
    new URL(started.authorization_url).origin,
    "https://makecrypto.test",
  );
  assert.equal(tokenRequests, 1);
  assert.equal(registrationRequests, 1);
  assert.equal(
    connection.metadata.webhook_rotation.idempotency_key,
    webhookIdempotencyKey,
  );
});

test("OAuth readiness fails closed when the configured webhook callback changes", async () => {
  const service = createService({
    options: { backendUrl: "https://new-api.shop.test" },
  });
  const connection = {
    access_token_expires_at: new Date(Date.now() + 300_000),
    encrypted_access_token: "encrypted-access",
    encrypted_dpop_private_key: "encrypted-dpop",
    encrypted_webhook_secret: "encrypted-webhook",
    id: "mpcon_config_drift",
    metadata: {},
    scopes: [...MAKEPAY_OAUTH_SCOPES],
    status: "connected",
    webhook_status: "healthy",
    webhook_subscription_id: "subscription_config_drift",
    webhook_url: "https://old-tunnel.example/hooks/makepay/makepay_makepay",
  };
  service.connectionRecord = async () => connection;

  const view = await service.getConnectionView();
  assert.equal(view.connected, false);
  assert.equal(view.reconnect_required, true);
  assert.equal(view.status, "error");
  assert.equal(view.webhook.configured, false);
  assert.equal(view.webhook.status, "error");
  assert.match(view.last_error, /callback configuration changed.*reconnect/i);
  await assert.rejects(
    service.oauthCredentials(true, true),
    /webhook subscription is healthy/i,
  );
});

test("connection view exposes reconnect only for terminal OAuth refresh failure", async () => {
  const service = createService();
  const connection = {
    access_token_expires_at: new Date(Date.now() + 300_000),
    encrypted_access_token: "encrypted-access",
    encrypted_dpop_private_key: "encrypted-dpop",
    encrypted_refresh_token: "encrypted-refresh",
    encrypted_webhook_secret: "encrypted-webhook",
    id: "mpcon_refresh_action",
    metadata: {
      refresh_attempt: {
        credential_fingerprint: "refresh-fingerprint",
        failure: "terminal",
        idempotency_key: `medusa-token-${"a".repeat(43)}`,
      },
    },
    scopes: [...MAKEPAY_OAUTH_SCOPES],
    status: "error",
    webhook_status: "healthy",
    webhook_subscription_id: "subscription_refresh_action",
    webhook_url: "https://api.shop.test/hooks/makepay/makepay_makepay",
  };
  service.connectionRecord = async () => connection;

  const terminal = await service.getConnectionView();
  assert.equal(terminal.connected, false);
  assert.equal(terminal.reconnect_required, true);

  connection.metadata.refresh_attempt.failure = "retryable";
  const retryable = await service.getConnectionView();
  assert.equal(retryable.connected, false);
  assert.equal(retryable.reconnect_required, false);

  service.connectionRecord = async () => undefined;
  const firstTime = await service.getConnectionView();
  assert.equal(firstTime.status, "disconnected");
  assert.equal(firstTime.reconnect_required, false);
});

test("OAuth start creates a ten-minute, hashed, encrypted PKCE transaction", async () => {
  const service = createService();
  let registration;
  let pending;

  service.fetch_ = async (url, init) => {
    const discovery = discoveryResponse(url);
    if (discovery) return discovery;
    registration = { body: JSON.parse(init.body), headers: init.headers, url };
    return new Response(
      JSON.stringify({
        client_id: "client_medusa",
        registration_id: registration.body.registrationId,
        scopes: [...MAKEPAY_OAUTH_SCOPES],
      }),
      { headers: { "content-type": "application/json" } },
    );
  };
  service.generated = () => ({
    createMakePayOAuthStates: async (input) => {
      pending = input;
      return input;
    },
    listMakePayConnections: async () => [],
    listMakePayOAuthStates: async () => [],
    updateMakePayOAuthStates: async (update) => {
      pending = { ...pending, ...update };
      return pending;
    },
  });

  const before = Date.now();
  const result = await service.startOAuth();
  const after = Date.now();
  const authorization = new URL(result.authorization_url);

  assert.equal(
    registration.url,
    "https://makecrypto.test/oauth/native/installations",
  );
  assert.match(registration.headers.dpop, /^[^.]+\.[^.]+\.[^.]+$/);
  assert.equal(registration.body.platform, "medusa");
  assert.match(registration.body.registrationId, /^[A-Za-z0-9_-]{43}$/);
  assert.match(registration.body.dpopJkt, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(registration.body.pluginVersion, "1.0.1");
  assert.equal(registration.body.siteUrl, "https://api.shop.test");
  assert.equal(
    registration.body.redirectUri,
    "https://api.shop.test/makepay/oauth/callback",
  );
  assert.equal(authorization.origin, "https://makecrypto.test");
  assert.equal(authorization.searchParams.get("client_id"), "client_medusa");
  assert.equal(authorization.searchParams.get("code_challenge_method"), "S256");
  assert.equal(
    authorization.searchParams.get("scope"),
    MAKEPAY_OAUTH_SCOPES.join(" "),
  );
  assert.ok(authorization.searchParams.get("state"));
  assert.notEqual(pending.state_hash, authorization.searchParams.get("state"));
  assert.equal(pending.client_id, "client_medusa");
  assert.match(pending.encrypted_code_verifier, /^v1\./);
  assert.match(pending.encrypted_dpop_private_key, /^v1\./);
  assert.match(pending.encrypted_registration_id, /^v1\./);
  assert.ok(new Date(result.expires_at).getTime() >= before + 599_000);
  assert.ok(new Date(result.expires_at).getTime() <= after + 601_000);
});

test("disconnect invalidates a pending OAuth callback without a live connection", async () => {
  for (const existingConnection of [
    undefined,
    {
      encrypted_access_token: null,
      id: "mpcon_disconnected",
      metadata: {},
      provider_id: "makepay",
      scopes: [],
      status: "disconnected",
      webhook_status: "missing",
      webhook_url: "https://api.shop.test/hooks/makepay/makepay_makepay",
    },
  ]) {
    const service = createService();
    const states = [];
    let tokenRequests = 0;

    service.connectionRecord = async () => existingConnection;
    service.fetch_ = async (url, init) => {
      const discovery = discoveryResponse(url);
      if (discovery) return discovery;
      if (url === "https://makecrypto.test/oauth/native/installations") {
        const registration = JSON.parse(init.body);
        return new Response(
          JSON.stringify({
            client_id: "client_disconnect_pending",
            registration_id: registration.registrationId,
            scopes: [...MAKEPAY_OAUTH_SCOPES],
          }),
          { headers: { "content-type": "application/json" } },
        );
      }
      tokenRequests += 1;
      throw new Error("delayed callback must not reach the token endpoint");
    };
    service.generated = () => ({
      createMakePayOAuthStates: async (input) => {
        states.push(input);
        return input;
      },
      deleteMakePayOAuthStates: async (ids) => {
        const deleted = new Set(Array.isArray(ids) ? ids : [ids]);
        for (let index = states.length - 1; index >= 0; index -= 1) {
          if (deleted.has(states[index].id)) states.splice(index, 1);
        }
      },
      listMakePayOAuthStates: async (filters = {}) =>
        states.filter(
          (state) =>
            (!filters.provider_id ||
              state.provider_id === filters.provider_id) &&
            (!filters.state_hash || state.state_hash === filters.state_hash),
        ),
      updateMakePayOAuthStates: async (update) => {
        const state = states.find((candidate) => candidate.id === update.id);
        Object.assign(state, update);
        return state;
      },
    });

    const started = await service.startOAuth();
    const state = new URL(started.authorization_url).searchParams.get("state");
    assert.ok(state);
    assert.equal(states.length, 1);

    const disconnected = await service.disconnectOAuth();
    assert.equal(disconnected.status, "disconnected");
    assert.equal(states.length, 0);

    await assert.rejects(
      service.finishOAuth({
        code: "delayed-authorization-code",
        iss: "https://makecrypto.test",
        state,
      }),
      /invalid, expired, or already used/i,
    );
    assert.equal(tokenRequests, 0);
  }
});

test("disconnect invalidates and deletes every paginated OAuth state", async () => {
  const service = createService();
  const states = Array.from({ length: 25 }, (_, index) => ({
    consumed_at: null,
    created_at: new Date(1_000 + index),
    encrypted_authorization_code: `code-${index}`,
    encrypted_dpop_private_key: `staged-key-${index}`,
    id: `mpost_paginated_${String(index).padStart(2, "0")}`,
    provider_id: "makepay",
    token_exchange_id: `exchange-${index}`,
  }));
  const deletedBatchSizes = [];
  let invalidated = 0;

  service.connectionRecord = async () => undefined;
  service.generated = () => ({
    deleteMakePayOAuthStates: async (ids) => {
      deletedBatchSizes.push(ids.length);
      const deleted = new Set(ids);
      for (let index = states.length - 1; index >= 0; index -= 1) {
        if (deleted.has(states[index].id)) states.splice(index, 1);
      }
    },
    listMakePayOAuthStates: async (_filters, options = {}) =>
      states.slice(options.skip ?? 0, (options.skip ?? 0) + options.take),
    updateMakePayOAuthStates: async (update) => {
      const state = states.find((candidate) => candidate.id === update.id);
      Object.assign(state, update);
      invalidated += 1;
      return state;
    },
  });

  const disconnected = await service.disconnectOAuth();

  assert.equal(disconnected.status, "disconnected");
  assert.equal(invalidated, 25);
  assert.deepEqual(deletedBatchSizes, [20, 5]);
  assert.equal(states.length, 0);
});

test("disconnect invalidates pending OAuth callbacks before retryable remote cleanup", async () => {
  for (const initialStatus of ["connected", "disconnect_pending"]) {
    const service = createService();
    const encryptionKey = Buffer.alloc(32, 3);
    const connectionId = `mpcon_disconnect_${initialStatus}`;
    const dpop = createDpopKeyPair();
    const priorNativeMutationId =
      initialStatus === "disconnect_pending" ? "n".repeat(43) : undefined;
    const priorWebhookMutationId =
      initialStatus === "disconnect_pending" ? "w".repeat(43) : undefined;
    const connection = {
      access_token_expires_at: new Date(Date.now() + 300_000),
      client_id: `client_disconnect_${initialStatus}`,
      company_id: "company_disconnect",
      encrypted_access_token: encryptSecret(
        "access-disconnect",
        encryptionKey,
        `connection:${connectionId}:access-token`,
      ),
      encrypted_dpop_private_key: encryptSecret(
        dpop.privateKeyPem,
        encryptionKey,
        `connection:${connectionId}:dpop`,
      ),
      encrypted_refresh_token: encryptSecret(
        "refresh-disconnect",
        encryptionKey,
        `connection:${connectionId}:refresh-token`,
      ),
      grant_id: "grant_disconnect",
      id: connectionId,
      installation_id: `client_disconnect_${initialStatus}`,
      metadata: {
        ...(priorNativeMutationId
          ? { disconnect_native_reset_mutation_id: priorNativeMutationId }
          : {}),
        ...(priorWebhookMutationId
          ? { disconnect_webhook_mutation_id: priorWebhookMutationId }
          : {}),
        dpop_thumbprint: dpop.thumbprint,
      },
      provider_id: "makepay",
      scopes: [...MAKEPAY_OAUTH_SCOPES],
      status: initialStatus,
      webhook_status: "healthy",
      webhook_url: "https://api.shop.test/hooks/makepay/makepay_makepay",
    };
    const stateValue = `state-disconnect-${initialStatus}`;
    const recoveryStateValue = `state-disconnect-recovery-${initialStatus}`;
    const states = [
      {
        consumed_at: null,
        encrypted_dpop_private_key: "staged-key-proof",
        expires_at: new Date(Date.now() + 60_000),
        id: `mpost_disconnect_${initialStatus}`,
        provider_id: "makepay",
        state_hash: sha256(stateValue),
      },
      {
        consumed_at: new Date(Date.now() - 1_000),
        encrypted_authorization_code: "staged-authorization-code",
        encrypted_dpop_private_key: "staged-recovery-key-proof",
        expires_at: new Date(Date.now() + 60_000),
        id: `mpost_disconnect_recovery_${initialStatus}`,
        provider_id: "makepay",
        state_hash: sha256(recoveryStateValue),
        token_exchange_id: "staged-token-exchange-id",
      },
    ];
    let discoveryRequests = 0;

    service.connectionRecord = async () => connection;
    service.discoverOAuth = async () => {
      discoveryRequests += 1;
      throw new Error("simulated installation-reset outage");
    };
    service.generated = () => ({
      deleteMakePayOAuthStates: async (ids) => {
        const deleted = new Set(Array.isArray(ids) ? ids : [ids]);
        for (let index = states.length - 1; index >= 0; index -= 1) {
          if (deleted.has(states[index].id)) states.splice(index, 1);
        }
      },
      listMakePayOAuthStates: async (filters = {}) =>
        states.filter(
          (state) =>
            (!filters.provider_id ||
              state.provider_id === filters.provider_id) &&
            (!filters.state_hash || state.state_hash === filters.state_hash),
        ),
      listMakePayWebhookSubscriptions: async () => [],
      updateMakePayOAuthStates: async (update) => {
        const state = states.find((candidate) => candidate.id === update.id);
        Object.assign(state, update);
        return state;
      },
      updateMakePayConnections: async (update) => {
        const { metadata, ...fields } = update;
        Object.assign(connection, fields);
        if (metadata) {
          connection.metadata = { ...connection.metadata, ...metadata };
        }
        return connection;
      },
    });

    const pendingDisconnect = await service.disconnectOAuth();
    assert.equal(pendingDisconnect.status, "disconnect_pending");
    assert.equal(states.length, 2);
    assert.ok(states.every((state) => state.consumed_at));
    assert.ok(
      states.every((state) => state.encrypted_authorization_code == null),
    );
    assert.ok(states.every((state) => state.token_exchange_id == null));
    assert.equal(states[0].encrypted_dpop_private_key, "staged-key-proof");
    assert.equal(
      states[1].encrypted_dpop_private_key,
      "staged-recovery-key-proof",
    );
    assert.equal(discoveryRequests, 1);
    assert.match(
      connection.metadata.disconnect_native_reset_mutation_id,
      /^[A-Za-z0-9_-]{43}$/,
    );
    assert.match(
      connection.metadata.disconnect_webhook_mutation_id,
      /^[A-Za-z0-9_-]{43}$/,
    );
    if (priorNativeMutationId && priorWebhookMutationId) {
      assert.equal(
        connection.metadata.disconnect_native_reset_mutation_id,
        priorNativeMutationId,
      );
      assert.equal(
        connection.metadata.disconnect_webhook_mutation_id,
        priorWebhookMutationId,
      );
    }

    await assert.rejects(
      service.finishOAuth({
        code: "delayed-authorization-code",
        iss: "https://makecrypto.test",
        state: stateValue,
      }),
      /invalid, expired, or already used/i,
    );
    await assert.rejects(
      service.finishOAuth({
        code: "delayed-recovery-authorization-code",
        iss: "https://makecrypto.test",
        state: recoveryStateValue,
      }),
      /invalid, expired, or already used/i,
    );
    assert.equal(discoveryRequests, 1);
  }
});

test("OAuth start fails closed if the server omits a required scope", async () => {
  const service = createService();
  let pending;
  service.fetch_ = async (url, init) =>
    discoveryResponse(url) ??
    new Response(
      JSON.stringify({
        client_id: "client_medusa",
        registration_id: JSON.parse(init.body).registrationId,
        scopes: MAKEPAY_OAUTH_SCOPES.filter(
          (scope) => scope !== "makepay:webhooks:write",
        ),
      }),
      { headers: { "content-type": "application/json" } },
    );
  service.generated = () => ({
    createMakePayOAuthStates: async (input) => {
      pending = input;
      return input;
    },
    listMakePayConnections: async () => [],
    listMakePayOAuthStates: async () => [],
    updateMakePayOAuthStates: async (update) => {
      pending = { ...pending, ...update };
      return pending;
    },
  });

  await assert.rejects(service.startOAuth(), /missing required scopes/i);
});

test("OAuth callback rejects consumed and expired state before token exchange", async () => {
  for (const pending of [
    {
      consumed_at: new Date(),
      expires_at: new Date(Date.now() + 60_000),
    },
    {
      consumed_at: null,
      expires_at: new Date(Date.now() - 1),
    },
  ]) {
    const service = createService();
    let fetched = false;
    service.fetch_ = async () => {
      fetched = true;
      throw new Error("token endpoint must not be reached");
    };
    service.generated = () => ({
      listMakePayOAuthStates: async () => [pending],
      updateMakePayOAuthStates: async () => pending,
    });

    await assert.rejects(
      service.finishOAuth({ code: "code", state: "state" }),
      /invalid, expired, or already used/i,
    );
    assert.equal(fetched, false);
  }
});

test("OAuth callback atomically commits recovery material and retries one exact token exchange", async () => {
  const service = createService();
  const encryptionKey = Buffer.alloc(32, 3);
  const dpop = createDpopKeyPair();
  const stateValue = "state-atomic-code-recovery";
  const authorizationCode = "authorization-code-atomic-recovery";
  const pendingId = "mpost_atomic_code_recovery";
  const pending = {
    client_id: "client_atomic_code_recovery",
    consumed_at: null,
    dpop_thumbprint: dpop.thumbprint,
    encrypted_authorization_code: null,
    encrypted_code_verifier: encryptSecret(
      "verifier-atomic-code-recovery",
      encryptionKey,
      `oauth-state:${pendingId}:verifier`,
    ),
    encrypted_dpop_private_key: encryptSecret(
      dpop.privateKeyPem,
      encryptionKey,
      `oauth-state:${pendingId}:dpop`,
    ),
    encrypted_registration_id: encryptSecret(
      base64Url(Buffer.alloc(32, 17)),
      encryptionKey,
      `oauth-state:${pendingId}:registration-id`,
    ),
    expires_at: new Date(Date.now() + 300_000),
    id: pendingId,
    provider_id: "makepay",
    redirect_uri: "https://api.shop.test/makepay/oauth/callback",
    state_hash: sha256(stateValue),
    token_exchange_id: null,
  };
  const tokenRequests = [];
  const stateUpdates = [];
  let failFirstStateCommit = true;

  service.connectionRecord = async () => undefined;
  service.discoverOAuth = async () => ({
    tokenEndpoint: "https://makecrypto.test/oauth/token",
  });
  service.generated = () => ({
    listMakePayOAuthStates: async (filters = {}) =>
      (!filters.state_hash || filters.state_hash === pending.state_hash) &&
      (!filters.provider_id || filters.provider_id === pending.provider_id)
        ? [pending]
        : [],
    updateMakePayOAuthStates: async (update) => {
      stateUpdates.push(structuredClone(update));
      if (failFirstStateCommit) {
        failFirstStateCommit = false;
        throw new Error("simulated atomic state commit failure");
      }
      Object.assign(pending, update);
      return pending;
    },
  });
  service.fetch_ = async (url, init) => {
    assert.equal(url, "https://makecrypto.test/oauth/token");
    tokenRequests.push({
      body: Object.fromEntries(new URLSearchParams(String(init.body))),
      idempotencyKey: new Headers(init.headers).get("idempotency-key"),
    });
    return new Response(JSON.stringify({ error: "temporarily_unavailable" }), {
      headers: { "content-type": "application/json" },
      status: 503,
    });
  };

  const callback = {
    code: authorizationCode,
    iss: "https://makecrypto.test",
    state: stateValue,
  };
  await assert.rejects(
    service.finishOAuth(callback),
    /simulated atomic state commit failure/i,
  );
  assert.equal(tokenRequests.length, 0);
  assert.equal(pending.consumed_at, null);
  assert.equal(pending.encrypted_authorization_code, null);
  assert.equal(pending.token_exchange_id, null);
  assert.ok(stateUpdates[0].consumed_at);
  assert.match(stateUpdates[0].encrypted_authorization_code, /^v1\./);
  assert.match(
    stateUpdates[0].token_exchange_id,
    /^medusa-token-[A-Za-z0-9_-]{43}$/,
  );

  await assert.rejects(
    service.finishOAuth(callback),
    /token exchange failed/i,
  );
  assert.ok(pending.consumed_at);
  assert.equal(
    decryptSecret(
      pending.encrypted_authorization_code,
      encryptionKey,
      `oauth-state:${pendingId}:authorization-code`,
    ),
    authorizationCode,
  );
  assert.match(
    pending.token_exchange_id,
    /^medusa-token-[A-Za-z0-9_-]{43}$/,
  );

  await assert.rejects(
    service.finishOAuth(callback),
    /token exchange failed/i,
  );
  assert.equal(tokenRequests.length, 2);
  assert.deepEqual(
    tokenRequests.map((request) => request.body.code),
    [authorizationCode, authorizationCode],
  );
  assert.deepEqual(
    tokenRequests.map((request) => request.idempotencyKey),
    [pending.token_exchange_id, pending.token_exchange_id],
  );
});

test("expired exact code recovery retires the callback and retains key proof for reconnect", async () => {
  const service = createService();
  const encryptionKey = Buffer.alloc(32, 3);
  const oldDpop = createDpopKeyPair();
  const registeredDpop = createDpopKeyPair();
  const registrationId = base64Url(Buffer.alloc(32, 9));
  const stateValue = "state-with-expired-token-recovery";
  const authorizationCode = "authorization-code-with-lost-response";
  const oldStateId = "mpost_expired_code_recovery";
  const webhookUrl = "https://api.shop.test/hooks/makepay/makepay_makepay";
  const webhookIdempotencyKey = makePayWebhookRotationIdempotencyKey({
    dpopThumbprint: oldDpop.thumbprint,
    grantId: "grant_code_recovery",
    installationId: "client_code_recovery",
    oauthAttemptId: "mpost_pending_webhook",
  });
  const oldState = {
    client_id: "client_code_recovery",
    consumed_at: new Date(),
    dpop_thumbprint: registeredDpop.thumbprint,
    encrypted_authorization_code: encryptSecret(
      authorizationCode,
      encryptionKey,
      `oauth-state:${oldStateId}:authorization-code`,
    ),
    encrypted_code_verifier: encryptSecret(
      "code-verifier",
      encryptionKey,
      `oauth-state:${oldStateId}:verifier`,
    ),
    encrypted_dpop_private_key: encryptSecret(
      registeredDpop.privateKeyPem,
      encryptionKey,
      `oauth-state:${oldStateId}:dpop`,
    ),
    encrypted_registration_id: encryptSecret(
      registrationId,
      encryptionKey,
      `oauth-state:${oldStateId}:registration-id`,
    ),
    expires_at: new Date(Date.now() + 300_000),
    id: oldStateId,
    provider_id: "makepay",
    redirect_uri: "https://api.shop.test/makepay/oauth/callback",
    state_hash: sha256(stateValue),
    token_exchange_id: `medusa-token-${"b".repeat(43)}`,
  };
  const states = [oldState];
  const connection = {
    access_token_expires_at: new Date(Date.now() - 1),
    client_id: "client_code_recovery",
    company_id: "company_code_recovery",
    encrypted_access_token: "old-access",
    encrypted_dpop_private_key: encryptSecret(
      oldDpop.privateKeyPem,
      encryptionKey,
      "connection:mpcon_code_recovery:dpop",
    ),
    encrypted_refresh_token: "old-refresh",
    encrypted_registration_id: encryptSecret(
      registrationId,
      encryptionKey,
      "connection:mpcon_code_recovery:registration-id",
    ),
    grant_id: "grant_code_recovery",
    id: "mpcon_code_recovery",
    installation_id: "client_code_recovery",
    metadata: {
      dpop_thumbprint: oldDpop.thumbprint,
      webhook_rotation: {
        company_id: "company_code_recovery",
        dpop_thumbprint: oldDpop.thumbprint,
        endpoint_url: webhookUrl,
        grant_id: "grant_code_recovery",
        idempotency_key: webhookIdempotencyKey,
        installation_id: "client_code_recovery",
        oauth_attempt_id: "mpost_pending_webhook",
      },
    },
    provider_id: "makepay",
    status: "error",
    webhook_status: "error",
    webhook_url: webhookUrl,
  };
  let tokenRequests = 0;
  let registrationRequests = 0;
  service.connectionRecord = async () => connection;
  service.discoverOAuth = async () => ({
    authorizationEndpoint: "https://makecrypto.test/oauth/authorize",
    jwksUri: "https://makecrypto.test/oauth/jwks.json",
    nativeInstallationEndpoint:
      "https://makecrypto.test/oauth/native/installations",
    tokenEndpoint: "https://makecrypto.test/oauth/token",
  });
  service.generated = () => ({
    createMakePayOAuthStates: async (input) => {
      states.push({ ...input, created_at: new Date() });
      return input;
    },
    listMakePayOAuthStates: async (filters = {}) =>
      states.filter(
        (state) =>
          !filters.state_hash || state.state_hash === filters.state_hash,
      ),
    listMakePayPaymentProjections: async () => [],
    updateMakePayConnections: async (update) => {
      Object.assign(connection, update);
      return connection;
    },
    updateMakePayOAuthStates: async (update) => {
      const state = states.find((candidate) => candidate.id === update.id);
      Object.assign(state, update);
      return state;
    },
  });
  service.fetch_ = async (url, init) => {
    if (url === "https://makecrypto.test/oauth/token") {
      tokenRequests += 1;
      return new Response(JSON.stringify({ error: "invalid_grant" }), {
        headers: {
          "content-type": "application/json",
          "oauth-token-recovery": "expired",
        },
        status: 400,
      });
    }
    assert.equal(url, "https://makecrypto.test/oauth/native/installations");
    registrationRequests += 1;
    if (registrationRequests === 1) {
      return new Response(
        JSON.stringify({ error: "previous_proof_required" }),
        {
          headers: { "content-type": "application/json" },
          status: 409,
        },
      );
    }
    const payload = JSON.parse(init.body);
    return new Response(
      JSON.stringify({
        client_id: "client_code_recovery",
        registration_id: payload.registrationId,
        scopes: [...MAKEPAY_OAUTH_SCOPES],
      }),
      { headers: { "content-type": "application/json" } },
    );
  };

  await assert.rejects(
    service.finishOAuth({
      code: authorizationCode,
      iss: "https://makecrypto.test",
      state: stateValue,
    }),
    (error) => error?.name === "OAuthTokenRecoveryExpiredError",
  );
  assert.equal(tokenRequests, 1);
  assert.equal(oldState.encrypted_authorization_code, null);
  assert.equal(oldState.token_exchange_id, null);
  assert.equal(
    connection.metadata.oauth_token_recovery_expired,
    "authorization_code",
  );
  assert.equal(connection.status, "error");
  assert.equal(
    connection.metadata.webhook_rotation.idempotency_key,
    webhookIdempotencyKey,
  );

  const restarted = await service.startOAuth();
  assert.equal(
    new URL(restarted.authorization_url).searchParams.get("client_id"),
    "client_code_recovery",
  );
  assert.equal(tokenRequests, 1);
  assert.equal(registrationRequests, 2);
  assert.ok(
    states.some((state) => state.id !== oldStateId && !state.consumed_at),
  );
});

test("concurrent refreshes share one in-process rotation", async () => {
  const service = createService();
  let calls = 0;
  let release;
  const blocked = new Promise((resolve) => {
    release = resolve;
  });
  service.performRefresh = async () => {
    calls += 1;
    await blocked;
  };
  service.connectionRecord = async () => undefined;
  service.lockingService = () => ({
    execute: async (_key, job) => job(),
  });

  const first = service.refreshOAuth("connection_refresh_test");
  const second = service.refreshOAuth("connection_refresh_test");
  await Promise.resolve();
  assert.equal(calls, 1);
  release();
  await Promise.all([first, second]);
  assert.equal(calls, 1);
});

test("an OAuth installation renews after more than 30 days idle without reconnecting", async () => {
  const service = createService();
  const encryptionKey = Buffer.alloc(32, 3);
  const connection = {
    access_token_expires_at: new Date(Date.now() - 31 * 24 * 60 * 60 * 1000),
    encrypted_access_token: encryptSecret(
      "access-stale",
      encryptionKey,
      "connection:mpcon_idle:access-token",
    ),
    encrypted_dpop_private_key: encryptSecret(
      "private-key",
      encryptionKey,
      "connection:mpcon_idle:dpop",
    ),
    encrypted_refresh_token: encryptSecret(
      "refresh-durable",
      encryptionKey,
      "connection:mpcon_idle:refresh-token",
    ),
    id: "mpcon_idle",
    status: "connected",
  };
  let refreshCalls = 0;
  service.connectionRecord = async () => connection;
  service.refreshOAuth = async (connectionId) => {
    refreshCalls += 1;
    assert.equal(connectionId, connection.id);
    connection.access_token_expires_at = new Date(Date.now() + 600_000);
    connection.encrypted_access_token = encryptSecret(
      "access-renewed",
      encryptionKey,
      "connection:mpcon_idle:access-token",
    );
  };

  const credentials = await service.oauthCredentials(true, false);

  assert.equal(refreshCalls, 1);
  assert.equal(credentials.accessToken, "access-renewed");
  assert.equal(credentials.refreshToken, "refresh-durable");
  assert.equal(credentials.connection.status, "connected");
  assert.ok(credentials.expiresAt.getTime() > Date.now());
});

test("synthetic issuer compatibility: refresh adopts only a locally bound staged DPoP key after an exact DPoP rejection", async () => {
  // Production MakeCrypto revokes predecessor refresh families when consent
  // promotes a staged key. This fixture intentionally models an issuer that
  // instead permits the predecessor token to be rebound to that staged key.
  const issuer = "https://makecrypto.test";
  const audience = `${issuer}/api/partner/v1`;
  const tokenEndpoint = `${issuer}/oauth/token`;
  const jwksUri = `${issuer}/oauth/jwks.json`;
  const encryptionKey = Buffer.alloc(32, 3);
  const connectionDpop = createDpopKeyPair();
  const promotedDpop = createDpopKeyPair();
  const { privateKey: signingKey, publicKey: verificationKey } =
    generateKeyPairSync("rsa", { modulusLength: 2048 });
  const now = Math.floor(Date.now() / 1000);
  const connectionId = "mpcon_promoted_before_callback";
  const stateId = "mpost_promoted_before_callback";
  const callbackUrl = "https://api.shop.test/makepay/oauth/callback";
  const registrationId = base64Url(Buffer.alloc(32, 17));
  const identity = {
    clientId: "client_promoted_before_callback",
    companyId: "company_promoted_before_callback",
    grantId: "grant_promoted_before_callback",
    installationId: "installation_promoted_before_callback",
  };
  const header = base64Url(
    JSON.stringify({ alg: "RS256", kid: "promoted-key-test", typ: "at+jwt" }),
  );
  const payload = base64Url(
    JSON.stringify({
      aud: audience,
      client_id: identity.clientId,
      cnf: { jkt: promotedDpop.thumbprint },
      company_id: identity.companyId,
      exp: now + 600,
      grant_id: identity.grantId,
      iat: now,
      installation_id: identity.installationId,
      iss: issuer,
      scope: MAKEPAY_OAUTH_SCOPES.join(" "),
    }),
  );
  const accessToken = `${header}.${payload}.${base64Url(
    sign("RSA-SHA256", Buffer.from(`${header}.${payload}`), signingKey),
  )}`;
  const connection = {
    access_token_expires_at: new Date(Date.now() - 1_000),
    client_id: identity.clientId,
    company_id: identity.companyId,
    encrypted_access_token: encryptSecret(
      "expired-access-token",
      encryptionKey,
      `connection:${connectionId}:access-token`,
    ),
    encrypted_dpop_private_key: encryptSecret(
      connectionDpop.privateKeyPem,
      encryptionKey,
      `connection:${connectionId}:dpop`,
    ),
    encrypted_refresh_token: encryptSecret(
      "refresh-before-key-promotion",
      encryptionKey,
      `connection:${connectionId}:refresh-token`,
    ),
    encrypted_registration_id: encryptSecret(
      registrationId,
      encryptionKey,
      `connection:${connectionId}:registration-id`,
    ),
    grant_id: identity.grantId,
    id: connectionId,
    installation_id: identity.installationId,
    metadata: { dpop_thumbprint: connectionDpop.thumbprint },
    provider_id: "makepay",
    status: "disconnect_pending",
  };
  const foreignClientDpop = createDpopKeyPair();
  const foreignCallbackDpop = createDpopKeyPair();
  const foreignRegistrationDpop = createDpopKeyPair();
  const stagedState = ({
    clientId = identity.clientId,
    dpop,
    id,
    redirectUri = callbackUrl,
    registration = registrationId,
  }) => ({
    client_id: clientId,
    dpop_thumbprint: dpop.thumbprint,
    encrypted_dpop_private_key: encryptSecret(
      dpop.privateKeyPem,
      encryptionKey,
      `oauth-state:${id}:dpop`,
    ),
    encrypted_registration_id: encryptSecret(
      registration,
      encryptionKey,
      `oauth-state:${id}:registration-id`,
    ),
    id,
    provider_id: "makepay",
    redirect_uri: redirectUri,
  });
  const states = [
    stagedState({ dpop: promotedDpop, id: stateId }),
    stagedState({
      clientId: "client_from_another_installation",
      dpop: foreignClientDpop,
      id: "mpost_foreign_client",
    }),
    stagedState({
      dpop: foreignCallbackDpop,
      id: "mpost_foreign_callback",
      redirectUri: "https://other-shop.test/makepay/oauth/callback",
    }),
    stagedState({
      dpop: foreignRegistrationDpop,
      id: "mpost_foreign_registration",
      registration: base64Url(Buffer.alloc(32, 18)),
    }),
  ];
  const refreshRequests = [];
  const successfulRefreshBody = {
    access_token: accessToken,
    expires_in: 600,
    refresh_token: "refresh-after-key-promotion",
    scope: MAKEPAY_OAUTH_SCOPES.join(" "),
    token_type: "DPoP",
  };
  let committedResponseLost = false;
  const service = createService();
  service.oauthConfig = () => ({
    audience,
    callbackUrl,
    encryptionKey,
    issuer,
  });
  service.discoverOAuth = async () => ({ jwksUri, tokenEndpoint });
  service.connectionRecord = async () => connection;
  service.generated = () => ({
    listMakePayOAuthStates: async (_filters = {}, config = {}) => {
      const skip = Number(config.skip || 0);
      const take = Number(config.take || states.length);
      return states.slice(skip, skip + take);
    },
    updateMakePayConnections: async (update) => {
      const { metadata, ...fields } = update;
      Object.assign(connection, fields);
      if (metadata) connection.metadata = { ...connection.metadata, ...metadata };
      return connection;
    },
  });
  service.fetch_ = async (url, init = {}) => {
    if (url === jwksUri) {
      return new Response(
        JSON.stringify({
          keys: [
            {
              ...verificationKey.export({ format: "jwk" }),
              kid: "promoted-key-test",
              use: "sig",
            },
          ],
        }),
        { headers: { "content-type": "application/json" } },
      );
    }
    assert.equal(url, tokenEndpoint);
    refreshRequests.push({
      idempotencyKey: new Headers(init.headers).get("idempotency-key"),
      thumbprint: dpopProofThumbprint(new Headers(init.headers).get("dpop")),
    });
    if (committedResponseLost) {
      return new Response(JSON.stringify(successfulRefreshBody), {
        headers: {
          "content-type": "application/json",
          "idempotent-replayed": "true",
        },
      });
    }
    if (refreshRequests.at(-1).thumbprint !== promotedDpop.thumbprint) {
      return new Response(JSON.stringify({ error: "invalid_dpop_key" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }
    committedResponseLost = true;
    throw new TypeError(
      "simulated committed staged-key refresh response loss",
    );
  };

  await assert.rejects(
    service.performRefresh(connectionId),
    /committed staged-key refresh response loss/i,
  );
  assert.equal(connection.metadata.refresh_attempt.failure, "retryable");

  await service.performRefresh(connectionId);

  assert.deepEqual(
    refreshRequests.map((request) => request.thumbprint),
    [
      connectionDpop.thumbprint,
      promotedDpop.thumbprint,
      connectionDpop.thumbprint,
    ],
  );
  assert.equal(
    new Set(refreshRequests.map((request) => request.idempotencyKey)).size,
    1,
  );
  assert.equal(connection.metadata.dpop_thumbprint, promotedDpop.thumbprint);
  assert.equal(
    decryptSecret(
      connection.encrypted_dpop_private_key,
      encryptionKey,
      `connection:${connectionId}:dpop`,
    ),
    promotedDpop.privateKeyPem,
  );
  assert.equal(
    decryptSecret(
      connection.encrypted_refresh_token,
      encryptionKey,
      `connection:${connectionId}:refresh-token`,
    ),
    "refresh-after-key-promotion",
  );
  assert.equal(connection.status, "disconnect_pending");
});

test("synthetic issuer compatibility: refresh does not probe an abandoned staged DPoP key when the connected key is accepted", async () => {
  const issuer = "https://makecrypto.test";
  const audience = `${issuer}/api/partner/v1`;
  const tokenEndpoint = `${issuer}/oauth/token`;
  const jwksUri = `${issuer}/oauth/jwks.json`;
  const encryptionKey = Buffer.alloc(32, 3);
  const connectionDpop = createDpopKeyPair();
  const abandonedDpop = createDpopKeyPair();
  const { privateKey: signingKey, publicKey: verificationKey } =
    generateKeyPairSync("rsa", { modulusLength: 2048 });
  const now = Math.floor(Date.now() / 1000);
  const connectionId = "mpcon_abandoned_staged_key";
  const stateId = "mpost_abandoned_staged_key";
  const identity = {
    clientId: "client_abandoned_staged_key",
    companyId: "company_abandoned_staged_key",
    grantId: "grant_abandoned_staged_key",
    installationId: "installation_abandoned_staged_key",
  };
  const header = base64Url(
    JSON.stringify({ alg: "RS256", kid: "fallback-key-test", typ: "at+jwt" }),
  );
  const payload = base64Url(
    JSON.stringify({
      aud: audience,
      client_id: identity.clientId,
      cnf: { jkt: connectionDpop.thumbprint },
      company_id: identity.companyId,
      exp: now + 600,
      grant_id: identity.grantId,
      iat: now,
      installation_id: identity.installationId,
      iss: issuer,
      scope: MAKEPAY_OAUTH_SCOPES.join(" "),
    }),
  );
  const accessToken = `${header}.${payload}.${base64Url(
    sign("RSA-SHA256", Buffer.from(`${header}.${payload}`), signingKey),
  )}`;
  const connection = {
    access_token_expires_at: new Date(Date.now() - 1_000),
    client_id: identity.clientId,
    company_id: identity.companyId,
    encrypted_access_token: encryptSecret(
      "expired-access-token",
      encryptionKey,
      `connection:${connectionId}:access-token`,
    ),
    encrypted_dpop_private_key: encryptSecret(
      connectionDpop.privateKeyPem,
      encryptionKey,
      `connection:${connectionId}:dpop`,
    ),
    encrypted_refresh_token: encryptSecret(
      "refresh-with-abandoned-staged-key",
      encryptionKey,
      `connection:${connectionId}:refresh-token`,
    ),
    grant_id: identity.grantId,
    id: connectionId,
    installation_id: identity.installationId,
    metadata: { dpop_thumbprint: connectionDpop.thumbprint },
    provider_id: "makepay",
    status: "connected",
  };
  const service = createService();
  const refreshRequests = [];
  service.oauthConfig = () => ({ audience, encryptionKey, issuer });
  service.discoverOAuth = async () => ({ jwksUri, tokenEndpoint });
  service.connectionRecord = async () => connection;
  service.generated = () => ({
    listMakePayOAuthStates: async (_filters = {}, config = {}) =>
      Number(config.skip || 0) === 0
        ? [
            {
              dpop_thumbprint: abandonedDpop.thumbprint,
              encrypted_dpop_private_key: encryptSecret(
                abandonedDpop.privateKeyPem,
                encryptionKey,
                `oauth-state:${stateId}:dpop`,
              ),
              id: stateId,
              provider_id: "makepay",
            },
          ]
        : [],
    updateMakePayConnections: async (update) => {
      const { metadata, ...fields } = update;
      Object.assign(connection, fields);
      if (metadata) connection.metadata = { ...connection.metadata, ...metadata };
      return connection;
    },
  });
  service.fetch_ = async (url, init = {}) => {
    if (url === jwksUri) {
      return new Response(
        JSON.stringify({
          keys: [
            {
              ...verificationKey.export({ format: "jwk" }),
              kid: "fallback-key-test",
              use: "sig",
            },
          ],
        }),
        { headers: { "content-type": "application/json" } },
      );
    }
    assert.equal(url, tokenEndpoint);
    const thumbprint = dpopProofThumbprint(
      new Headers(init.headers).get("dpop"),
    );
    refreshRequests.push({
      idempotencyKey: new Headers(init.headers).get("idempotency-key"),
      thumbprint,
    });
    assert.equal(thumbprint, connectionDpop.thumbprint);
    return new Response(
      JSON.stringify({
        access_token: accessToken,
        expires_in: 600,
        refresh_token: "refresh-after-fallback",
        scope: MAKEPAY_OAUTH_SCOPES.join(" "),
        token_type: "DPoP",
      }),
      { headers: { "content-type": "application/json" } },
    );
  };

  await service.performRefresh(connectionId);

  assert.deepEqual(
    refreshRequests.map((request) => request.thumbprint),
    [connectionDpop.thumbprint],
  );
  assert.equal(
    new Set(refreshRequests.map((request) => request.idempotencyKey)).size,
    1,
  );
  assert.equal(connection.metadata.dpop_thumbprint, connectionDpop.thumbprint);
  assert.equal(
    decryptSecret(
      connection.encrypted_refresh_token,
      encryptionKey,
      `connection:${connectionId}:refresh-token`,
    ),
    "refresh-after-fallback",
  );
});

test("synthetic issuer compatibility: a staged-key history read outage remains retryable after an exact DPoP rejection", async () => {
  const encryptionKey = Buffer.alloc(32, 3);
  const connectionDpop = createDpopKeyPair();
  const connectionId = "mpcon_staged_history_outage";
  const connection = {
    access_token_expires_at: new Date(Date.now() - 1_000),
    client_id: "client_staged_history_outage",
    encrypted_access_token: encryptSecret(
      "expired-access-token",
      encryptionKey,
      `connection:${connectionId}:access-token`,
    ),
    encrypted_dpop_private_key: encryptSecret(
      connectionDpop.privateKeyPem,
      encryptionKey,
      `connection:${connectionId}:dpop`,
    ),
    encrypted_refresh_token: encryptSecret(
      "refresh-staged-history-outage",
      encryptionKey,
      `connection:${connectionId}:refresh-token`,
    ),
    encrypted_registration_id: encryptSecret(
      base64Url(Buffer.alloc(32, 19)),
      encryptionKey,
      `connection:${connectionId}:registration-id`,
    ),
    id: connectionId,
    metadata: { dpop_thumbprint: connectionDpop.thumbprint },
    provider_id: "makepay",
    status: "disconnect_pending",
  };
  const service = createService();
  service.connectionRecord = async () => connection;
  service.discoverOAuth = async () => ({
    tokenEndpoint: "https://makecrypto.test/oauth/token",
  });
  service.generated = () => ({
    listMakePayOAuthStates: async () => {
      throw new Error("simulated state-store outage");
    },
    updateMakePayConnections: async (update) => {
      const { metadata, ...fields } = update;
      Object.assign(connection, fields);
      if (metadata) connection.metadata = { ...connection.metadata, ...metadata };
      return connection;
    },
  });
  service.fetch_ = async () =>
    new Response(JSON.stringify({ error: "invalid_dpop_proof" }), {
      status: 401,
      headers: { "content-type": "application/json" },
    });

  await assert.rejects(
    service.performRefresh(connectionId),
    /staged-key recovery is temporarily unavailable/i,
  );

  assert.equal(connection.status, "disconnect_pending");
  assert.equal(connection.metadata.refresh_attempt.failure, "retryable");
  assert.match(
    connection.metadata.refresh_attempt.idempotency_key,
    /^medusa-token-[A-Za-z0-9_-]{43}$/,
  );
});

test("a host restart recovers a 31-day-old committed rotation and immediately rotates its successor", async () => {
  const issuer = "https://makecrypto.test";
  const audience = `${issuer}/api/partner/v1`;
  const tokenEndpoint = `${issuer}/oauth/token`;
  const jwksUri = `${issuer}/oauth/jwks.json`;
  const encryptionKey = Buffer.alloc(32, 3);
  const {
    privateKey: historicalSigningKey,
    publicKey: historicalVerificationKey,
  } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const {
    privateKey: currentSigningKey,
    publicKey: currentVerificationKey,
  } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const dpop = createDpopKeyPair();
  const now = Math.floor(Date.now() / 1000);
  const connectionId = "connection_crash_recovery";
  const identity = {
    clientId: "client_crash_recovery",
    companyId: "company_crash_recovery",
    grantId: "grant_crash_recovery",
    installationId: "installation_crash_recovery",
  };
  const signedAccessToken = ({ exp, iat, kid, signingKey }) => {
    const header = base64Url(
      JSON.stringify({ alg: "RS256", kid, typ: "at+jwt" }),
    );
    const payload = base64Url(
      JSON.stringify({
        aud: audience,
        client_id: identity.clientId,
        cnf: { jkt: dpop.thumbprint },
        company_id: identity.companyId,
        exp,
        grant_id: identity.grantId,
        iat,
        installation_id: identity.installationId,
        iss: issuer,
        scope: MAKEPAY_OAUTH_SCOPES.join(" "),
      }),
    );
    return `${header}.${payload}.${base64Url(
      sign("RSA-SHA256", Buffer.from(`${header}.${payload}`), signingKey),
    )}`;
  };
  const expiredAccessToken = signedAccessToken({
    exp: now - 31 * 24 * 60 * 60,
    iat: now - 31 * 24 * 60 * 60 - 600,
    kid: "crash-recovery-retired",
    signingKey: historicalSigningKey,
  });
  const freshAccessToken = signedAccessToken({
    exp: now + 600,
    iat: now,
    kid: "crash-recovery-current",
    signingKey: currentSigningKey,
  });
  const predecessorRefreshToken = "refresh-before-crash";
  const recoveredSuccessor = "refresh-recovered-successor";
  const freshSuccessor = "refresh-fresh-successor";
  const originalAttempt = `medusa-token-${"r".repeat(43)}`;
  const connection = {
    access_token_expires_at: new Date((now - 31 * 24 * 60 * 60) * 1000),
    client_id: identity.clientId,
    company_id: identity.companyId,
    encrypted_access_token: encryptSecret(
      "access-before-crash",
      encryptionKey,
      `connection:${connectionId}:access-token`,
    ),
    encrypted_dpop_private_key: encryptSecret(
      dpop.privateKeyPem,
      encryptionKey,
      `connection:${connectionId}:dpop`,
    ),
    encrypted_refresh_token: encryptSecret(
      predecessorRefreshToken,
      encryptionKey,
      `connection:${connectionId}:refresh-token`,
    ),
    grant_id: identity.grantId,
    id: connectionId,
    installation_id: identity.installationId,
    metadata: {
      dpop_thumbprint: dpop.thumbprint,
      refresh_attempt: {
        credential_fingerprint: sha256(predecessorRefreshToken),
        idempotency_key: originalAttempt,
      },
    },
    status: "connected",
  };
  const service = createService();
  const updates = [];
  const tokenRequests = [];
  service.oauthConfig = () => ({ audience, encryptionKey, issuer });
  service.discoverOAuth = async () => ({ jwksUri, tokenEndpoint });
  service.connectionRecord = async () => connection;
  service.generated = () => ({
    updateMakePayConnections: async (update) => {
      updates.push(structuredClone(update));
      Object.assign(connection, update);
      return connection;
    },
  });
  service.fetch_ = async (url, init = {}) => {
    if (url === jwksUri) {
      return new Response(
        JSON.stringify({
          keys: [
            {
              ...currentVerificationKey.export({ format: "jwk" }),
              kid: "crash-recovery-current",
              use: "sig",
            },
            {
              ...historicalVerificationKey.export({ format: "jwk" }),
              kid: "crash-recovery-retired",
              use: "sig",
            },
          ],
        }),
        { headers: { "content-type": "application/json" } },
      );
    }
    assert.equal(url, tokenEndpoint);
    const request = Object.fromEntries(
      new URLSearchParams(String(init.body)).entries(),
    );
    tokenRequests.push({
      idempotencyKey: new Headers(init.headers).get("idempotency-key"),
      refreshToken: request.refresh_token,
    });
    if (tokenRequests.length === 1) {
      return new Response(
        JSON.stringify({
          access_token: expiredAccessToken,
          expires_in: 600,
          refresh_token: recoveredSuccessor,
          scope: MAKEPAY_OAUTH_SCOPES.join(" "),
          token_type: "DPoP",
        }),
        {
          headers: {
            "content-type": "application/json",
            "idempotent-replayed": "true",
          },
        },
      );
    }
    assert.equal(
      decryptSecret(
        connection.encrypted_refresh_token,
        encryptionKey,
        `connection:${connectionId}:refresh-token`,
      ),
      recoveredSuccessor,
      "the replayed successor must commit locally before another rotation",
    );
    return new Response(
      JSON.stringify({
        access_token: freshAccessToken,
        expires_in: 600,
        refresh_token: freshSuccessor,
        scope: MAKEPAY_OAUTH_SCOPES.join(" "),
        token_type: "DPoP",
      }),
      { headers: { "content-type": "application/json" } },
    );
  };

  await service.performRefresh(connectionId);

  assert.deepEqual(
    tokenRequests.map((request) => request.refreshToken),
    [predecessorRefreshToken, recoveredSuccessor],
  );
  assert.equal(tokenRequests[0].idempotencyKey, originalAttempt);
  assert.notEqual(tokenRequests[1].idempotencyKey, originalAttempt);
  assert.equal(
    decryptSecret(
      connection.encrypted_refresh_token,
      encryptionKey,
      `connection:${connectionId}:refresh-token`,
    ),
    freshSuccessor,
  );
  assert.equal(
    decryptSecret(
      connection.encrypted_access_token,
      encryptionKey,
      `connection:${connectionId}:access-token`,
    ),
    freshAccessToken,
  );
  assert.equal(connection.metadata.refresh_attempt, null);
  assert.ok(new Date(connection.access_token_expires_at).getTime() > Date.now());
  assert.equal(connection.status, "connected");
  assert.equal(
    updates.filter((update) => update.encrypted_refresh_token).length,
    2,
  );
});

test("a transient 503 refresh failure retries later, restores readiness, and durably rotates before an API failure", async () => {
  const issuer = "https://makecrypto.test";
  const apiBaseUrl = "https://api.makecrypto.test";
  const audience = `${issuer}/api/partner/v1`;
  const tokenEndpoint = `${issuer}/oauth/token`;
  const jwksUri = `${issuer}/oauth/jwks.json`;
  const webhookUrl = "https://api.shop.test/hooks/makepay/makepay_makepay";
  const encryptionKey = Buffer.alloc(32, 3);
  const { privateKey: signingKey, publicKey: verificationKey } =
    generateKeyPairSync("rsa", { modulusLength: 2048 });
  const dpop = createDpopKeyPair();
  const abandonedDpop = createDpopKeyPair();
  const header = base64Url(
    JSON.stringify({ alg: "RS256", kid: "durable-refresh", typ: "at+jwt" }),
  );
  const payload = base64Url(
    JSON.stringify({
      aud: audience,
      client_id: "client_durable_refresh",
      cnf: { jkt: dpop.thumbprint },
      company_id: "company_durable_refresh",
      exp: Math.floor(Date.now() / 1000) + 300,
      grant_id: "grant_durable_refresh",
      iat: Math.floor(Date.now() / 1000),
      installation_id: "installation_durable_refresh",
      iss: issuer,
      scope: MAKEPAY_OAUTH_SCOPES.join(" "),
    }),
  );
  const refreshedAccessToken = `${header}.${payload}.${base64Url(
    sign("RSA-SHA256", Buffer.from(`${header}.${payload}`), signingKey),
  )}`;
  const connection = {
    access_token_expires_at: new Date(Date.now() + 300_000),
    client_id: "client_durable_refresh",
    company_id: "company_durable_refresh",
    encrypted_access_token: encryptSecret(
      "access-old",
      encryptionKey,
      "connection:connection_durable_refresh:access-token",
    ),
    encrypted_dpop_private_key: encryptSecret(
      dpop.privateKeyPem,
      encryptionKey,
      "connection:connection_durable_refresh:dpop",
    ),
    encrypted_refresh_token: encryptSecret(
      "refresh-old",
      encryptionKey,
      "connection:connection_durable_refresh:refresh-token",
    ),
    encrypted_webhook_secret: "encrypted-webhook-secret",
    grant_id: "grant_durable_refresh",
    id: "connection_durable_refresh",
    installation_id: "installation_durable_refresh",
    metadata: { dpop_thumbprint: dpop.thumbprint },
    status: "connected",
    webhook_status: "healthy",
    webhook_subscription_id: "subscription_durable_refresh",
    webhook_url: webhookUrl,
  };
  const service = createService();
  const updates = [];
  let apiRequests = 0;
  let refreshRequests = 0;
  let stagedHistoryReads = 0;
  service.oauthConfig = () => ({
    apiBaseUrl,
    audience,
    encryptionKey,
    issuer,
    webhookUrl,
  });
  service.discoverOAuth = async () => ({ jwksUri, tokenEndpoint });
  service.connectionRecord = async () => connection;
  service.generated = () => ({
    listMakePayOAuthStates: async () => {
      stagedHistoryReads += 1;
      return [
        {
          dpop_thumbprint: abandonedDpop.thumbprint,
          encrypted_dpop_private_key: encryptSecret(
            abandonedDpop.privateKeyPem,
            encryptionKey,
            "oauth-state:mpost_transient_503:dpop",
          ),
          id: "mpost_transient_503",
          provider_id: "makepay",
        },
      ];
    },
    updateMakePayConnections: async (update) => {
      updates.push(update);
      Object.assign(connection, update);
      return connection;
    },
  });
  service.fetch_ = async (input, init = {}) => {
    const url = String(input);
    if (url === tokenEndpoint) {
      refreshRequests += 1;
      if (refreshRequests === 1) {
        return new Response(JSON.stringify({ error: "server_error" }), {
          headers: { "content-type": "application/json" },
          status: 503,
        });
      }
      return new Response(
        JSON.stringify({
          access_token: refreshedAccessToken,
          expires_in: 300,
          refresh_token: "refresh-rotated",
          scope: MAKEPAY_OAUTH_SCOPES.join(" "),
          token_type: "DPoP",
        }),
        { headers: { "content-type": "application/json" } },
      );
    }
    if (url === jwksUri) {
      return new Response(
        JSON.stringify({
          keys: [
            {
              ...verificationKey.export({ format: "jwk" }),
              kid: "durable-refresh",
              use: "sig",
            },
          ],
        }),
        { headers: { "content-type": "application/json" } },
      );
    }
    assert.equal(url, `${apiBaseUrl}/api/partner/v1/makepay/payment-links`);
    apiRequests += 1;
    const authorization = new Headers(init.headers).get("authorization");
    if (apiRequests === 1) {
      assert.equal(authorization, "DPoP access-old");
      return new Response(JSON.stringify({ error: "expired_token" }), {
        headers: { "content-type": "application/json" },
        status: 401,
      });
    }
    assert.equal(authorization, `DPoP ${refreshedAccessToken}`);
    return new Response(JSON.stringify({ error: "provider_unavailable" }), {
      headers: { "content-type": "application/json" },
      status: 503,
    });
  };

  const client = await service.createClient();
  await assert.rejects(
    client.createPaymentLink(
      { amount: "1.00", currency: "EUR" },
      { idempotencyKey: "durable-refresh-failure" },
    ),
    (error) => error instanceof MakePayError && error.status === 401,
  );

  assert.equal(refreshRequests, 1);
  assert.equal(stagedHistoryReads, 0);
  assert.equal(apiRequests, 1);
  assert.equal(connection.status, "connected");
  assert.equal(connection.last_error, "MakePay OAuth refresh failed.");
  assert.equal(connection.metadata.refresh_attempt.failure, "retryable");
  assert.equal(
    decryptSecret(
      connection.encrypted_refresh_token,
      encryptionKey,
      "connection:connection_durable_refresh:refresh-token",
    ),
    "refresh-old",
  );

  // Simulate a database row stranded by the prerelease behavior, before
  // refresh failures gained an explicit retryable/terminal marker. The next
  // ordinary checkout request must reuse its durable attempt before enforcing
  // readiness.
  connection.status = "error";
  delete connection.metadata.refresh_attempt.failure;
  await assert.rejects(
    client.createPaymentLink(
      { amount: "1.00", currency: "EUR" },
      { idempotencyKey: "durable-refresh-failure" },
    ),
    (error) => error instanceof MakePayError && error.status === 503,
  );

  assert.equal(refreshRequests, 2);
  assert.equal(stagedHistoryReads, 0);
  assert.equal(apiRequests, 2);
  assert.equal(connection.status, "connected");
  assert.equal(connection.last_error, null);
  assert.equal(connection.metadata.refresh_attempt, null);
  assert.equal(
    decryptSecret(
      connection.encrypted_refresh_token,
      encryptionKey,
      "connection:connection_durable_refresh:refresh-token",
    ),
    "refresh-rotated",
  );
  assert.ok(
    updates.some((update) => update.encrypted_refresh_token),
    "the rotation must commit before the retried API request can fail",
  );
});

test("legacy refresh recovery rejects terminal, unrelated, disconnecting, and mismatched rows", async () => {
  const encryptionKey = Buffer.alloc(32, 3);
  const connectionId = "connection_legacy_refresh_guard";
  const refreshToken = "refresh-legacy-transient";
  const webhookUrl = "https://api.shop.test/hooks/makepay/makepay_makepay";
  const baseConnection = {
    access_token_expires_at: new Date(Date.now() + 300_000),
    encrypted_access_token: encryptSecret(
      "access-legacy",
      encryptionKey,
      `connection:${connectionId}:access-token`,
    ),
    encrypted_dpop_private_key: encryptSecret(
      "private-key-legacy",
      encryptionKey,
      `connection:${connectionId}:dpop`,
    ),
    encrypted_refresh_token: encryptSecret(
      refreshToken,
      encryptionKey,
      `connection:${connectionId}:refresh-token`,
    ),
    encrypted_webhook_secret: "encrypted-webhook-secret",
    id: connectionId,
    last_error: "MakePay OAuth refresh failed.",
    metadata: {
      refresh_attempt: {
        credential_fingerprint: sha256(refreshToken),
        idempotency_key: `medusa-token-${"a".repeat(43)}`,
      },
    },
    status: "error",
    webhook_status: "healthy",
    webhook_subscription_id: "subscription_legacy_refresh_guard",
    webhook_url: webhookUrl,
  };
  const cases = [
    [
      "terminal invalid_grant/revocation",
      (connection) => {
        connection.metadata.refresh_attempt.failure = "terminal";
      },
    ],
    [
      "expired terminal replay recovery",
      (connection) => {
        connection.metadata.refresh_attempt.recovery_expired = true;
      },
    ],
    [
      "unrelated connection error",
      (connection) => {
        connection.last_error = "MakePay webhook subscription setup failed.";
      },
    ],
    [
      "disconnect intent",
      (connection) => {
        connection.metadata.disconnect_native_reset_mutation_id =
          "disconnect-in-progress";
      },
    ],
    [
      "malformed idempotency key",
      (connection) => {
        connection.metadata.refresh_attempt.idempotency_key =
          "medusa-token-malformed";
      },
    ],
    [
      "mismatched refresh credential",
      (connection) => {
        connection.metadata.refresh_attempt.credential_fingerprint = sha256(
          "a-different-refresh-token",
        );
      },
    ],
  ];

  for (const [label, mutate] of cases) {
    const connection = structuredClone(baseConnection);
    mutate(connection);
    const service = createService();
    let refreshCalls = 0;
    service.oauthConfig = () => ({ encryptionKey, webhookUrl });
    service.connectionRecord = async () => connection;
    service.refreshOAuth = async () => {
      refreshCalls += 1;
    };

    await assert.rejects(
      service.oauthCredentials(false, true),
      /checkout is unavailable/i,
      label,
    );
    assert.equal(refreshCalls, 0, `${label} must not trigger token refresh`);
  }
});

test("a truncated successful refresh response replays with the same durable idempotency key", async () => {
  const issuer = "https://makecrypto.test";
  const audience = `${issuer}/api/partner/v1`;
  const tokenEndpoint = `${issuer}/oauth/token`;
  const jwksUri = `${issuer}/oauth/jwks.json`;
  const encryptionKey = Buffer.alloc(32, 3);
  const { privateKey: signingKey, publicKey: verificationKey } =
    generateKeyPairSync("rsa", { modulusLength: 2048 });
  const dpop = createDpopKeyPair();
  const header = base64Url(
    JSON.stringify({ alg: "RS256", kid: "refresh-replay", typ: "at+jwt" }),
  );
  const payload = base64Url(
    JSON.stringify({
      aud: audience,
      client_id: "client_refresh_replay",
      cnf: { jkt: dpop.thumbprint },
      company_id: "company_refresh_replay",
      exp: Math.floor(Date.now() / 1000) + 300,
      grant_id: "grant_refresh_replay",
      iat: Math.floor(Date.now() / 1000),
      installation_id: "installation_refresh_replay",
      iss: issuer,
      scope: MAKEPAY_OAUTH_SCOPES.join(" "),
    }),
  );
  const refreshedAccessToken = `${header}.${payload}.${base64Url(
    sign("RSA-SHA256", Buffer.from(`${header}.${payload}`), signingKey),
  )}`;
  const connection = {
    client_id: "client_refresh_replay",
    company_id: "company_refresh_replay",
    encrypted_refresh_token: encryptSecret(
      "refresh-before-replay",
      encryptionKey,
      "connection:connection_refresh_replay:refresh-token",
    ),
    grant_id: "grant_refresh_replay",
    id: "connection_refresh_replay",
    installation_id: "installation_refresh_replay",
    metadata: { dpop_thumbprint: dpop.thumbprint },
    status: "connected",
  };
  const service = createService();
  const idempotencyKeys = [];
  let refreshRequests = 0;

  service.oauthConfig = () => ({
    audience,
    encryptionKey,
    issuer,
  });
  service.discoverOAuth = async () => ({ jwksUri, tokenEndpoint });
  service.oauthCredentials = async () => ({
    accessToken: "access-before-replay",
    connection,
    expiresAt: new Date(Date.now() - 1),
    privateKey: dpop.privateKeyPem,
    refreshToken: "refresh-before-replay",
  });
  service.connectionRecord = async () => connection;
  service.generated = () => ({
    updateMakePayConnections: async (update) => {
      Object.assign(connection, update);
      return connection;
    },
  });
  service.fetch_ = async (url, init = {}) => {
    if (url === tokenEndpoint) {
      refreshRequests += 1;
      idempotencyKeys.push(
        new Headers(init.headers).get("idempotency-key"),
      );
      if (refreshRequests === 1) {
        return new Response('{"access_token":', {
          headers: { "content-type": "application/json" },
          status: 200,
        });
      }
      return new Response(
        JSON.stringify({
          access_token: refreshedAccessToken,
          expires_in: 300,
          refresh_token: "refresh-after-replay",
          scope: MAKEPAY_OAUTH_SCOPES.join(" "),
          token_type: "DPoP",
        }),
        {
          headers: {
            "content-type": "application/json",
            "idempotent-replayed": "true",
          },
          status: 200,
        },
      );
    }
    assert.equal(url, jwksUri);
    return new Response(
      JSON.stringify({
        keys: [
          {
            ...verificationKey.export({ format: "jwk" }),
            kid: "refresh-replay",
            use: "sig",
          },
        ],
      }),
      { headers: { "content-type": "application/json" } },
    );
  };

  await assert.rejects(
    service.performRefresh(connection.id),
    /OAuth refresh failed/i,
  );
  assert.equal(connection.status, "connected");
  assert.equal(connection.metadata.refresh_attempt.failure, "retryable");

  await service.performRefresh(connection.id);

  assert.equal(refreshRequests, 2);
  assert.match(idempotencyKeys[0], /^medusa-token-[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(idempotencyKeys, [idempotencyKeys[0], idempotencyKeys[0]]);
  assert.equal(connection.status, "connected");
  assert.equal(connection.last_error, null);
  assert.equal(connection.metadata.refresh_attempt, null);
  assert.equal(
    decryptSecret(
      connection.encrypted_refresh_token,
      encryptionKey,
      "connection:connection_refresh_replay:refresh-token",
    ),
    "refresh-after-replay",
  );
});

test("a parseable incomplete 2xx refresh response remains replayable with the same durable idempotency key", async () => {
  const issuer = "https://makecrypto.test";
  const audience = `${issuer}/api/partner/v1`;
  const tokenEndpoint = `${issuer}/oauth/token`;
  const encryptionKey = Buffer.alloc(32, 3);
  const dpop = createDpopKeyPair();
  const connection = {
    client_id: "client_incomplete_refresh",
    id: "connection_incomplete_refresh",
    metadata: { dpop_thumbprint: dpop.thumbprint },
    status: "connected",
  };
  const service = createService();
  const idempotencyKeys = [];

  service.oauthConfig = () => ({ audience, encryptionKey, issuer });
  service.discoverOAuth = async () => ({ tokenEndpoint });
  service.oauthCredentials = async () => ({
    accessToken: "access-before-incomplete-response",
    connection,
    expiresAt: new Date(Date.now() - 1),
    privateKey: dpop.privateKeyPem,
    refreshToken: "refresh-before-incomplete-response",
  });
  service.connectionRecord = async () => connection;
  service.generated = () => ({
    updateMakePayConnections: async (update) => {
      const { metadata, ...fields } = update;
      Object.assign(connection, fields);
      if (metadata) connection.metadata = { ...connection.metadata, ...metadata };
      return connection;
    },
  });
  service.fetch_ = async (url, init = {}) => {
    assert.equal(url, tokenEndpoint);
    idempotencyKeys.push(
      new Headers(init.headers).get("idempotency-key"),
    );
    return new Response(
      JSON.stringify({
        access_token: "receipt-was-committed-but-this-body-is-incomplete",
        expires_in: 300,
        token_type: "DPoP",
      }),
      {
        headers: { "content-type": "application/json" },
        status: 200,
      },
    );
  };

  await assert.rejects(
    service.performRefresh(connection.id),
    /OAuth refresh failed/i,
  );
  assert.equal(connection.status, "connected");
  assert.equal(connection.metadata.refresh_attempt.failure, "retryable");

  await assert.rejects(
    service.performRefresh(connection.id),
    /OAuth refresh failed/i,
  );
  assert.equal(idempotencyKeys.length, 2);
  assert.match(idempotencyKeys[0], /^medusa-token-[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(idempotencyKeys, [idempotencyKeys[0], idempotencyKeys[0]]);
  assert.equal(connection.status, "connected");
  assert.equal(connection.metadata.refresh_attempt.failure, "retryable");
});

test("invalid_grant makes a refresh token terminal and prevents another issuer request", async () => {
  const issuer = "https://makecrypto.test";
  const audience = `${issuer}/api/partner/v1`;
  const tokenEndpoint = `${issuer}/oauth/token`;
  const encryptionKey = Buffer.alloc(32, 3);
  const dpop = createDpopKeyPair();
  const stagedDpop = createDpopKeyPair();
  const connection = {
    client_id: "client_terminal_refresh",
    id: "connection_terminal_refresh",
    metadata: { dpop_thumbprint: dpop.thumbprint },
    status: "connected",
  };
  const service = createService();
  let refreshRequests = 0;
  let stagedHistoryReads = 0;

  service.oauthConfig = () => ({ audience, encryptionKey, issuer });
  service.discoverOAuth = async () => ({ tokenEndpoint });
  service.oauthCredentials = async () => ({
    accessToken: "access-old",
    connection,
    expiresAt: new Date(Date.now() - 1),
    privateKey: dpop.privateKeyPem,
    refreshToken: "refresh-revoked",
  });
  service.connectionRecord = async () => connection;
  service.generated = () => ({
    listMakePayOAuthStates: async () => {
      stagedHistoryReads += 1;
      return [
        {
          dpop_thumbprint: stagedDpop.thumbprint,
          encrypted_dpop_private_key: encryptSecret(
            stagedDpop.privateKeyPem,
            encryptionKey,
            "oauth-state:mpost_terminal_refresh:dpop",
          ),
          id: "mpost_terminal_refresh",
          provider_id: "makepay",
        },
      ];
    },
    updateMakePayConnections: async (update) => {
      Object.assign(connection, update);
      return connection;
    },
  });
  service.fetch_ = async (url) => {
    assert.equal(url, tokenEndpoint);
    refreshRequests += 1;
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      headers: { "content-type": "application/json" },
      status: 400,
    });
  };

  await assert.rejects(
    service.performRefresh(connection.id),
    /OAuth refresh failed/i,
  );
  assert.equal(refreshRequests, 1);
  assert.equal(stagedHistoryReads, 0);
  assert.equal(connection.status, "error");
  assert.equal(connection.last_error, "MakePay OAuth refresh failed.");
  assert.equal(connection.metadata.refresh_attempt.failure, "terminal");

  await assert.rejects(
    service.performRefresh(connection.id),
    /no longer refreshable/i,
  );
  assert.equal(
    refreshRequests,
    1,
    "a terminal refresh credential must not be submitted again",
  );
  assert.equal(stagedHistoryReads, 0);
});

test("OAuth refresh rejects missing or mismatched installation identity", async () => {
  const issuer = "https://makecrypto.test";
  const audience = `${issuer}/api/partner/v1`;
  const tokenEndpoint = `${issuer}/oauth/token`;
  const jwksUri = `${issuer}/oauth/jwks.json`;
  const { privateKey: signingKey, publicKey: verificationKey } =
    generateKeyPairSync("rsa", { modulusLength: 2048 });
  const dpop = createDpopKeyPair();

  function accessToken(installationId) {
    const header = base64Url(
      JSON.stringify({ alg: "RS256", kid: "refresh-test", typ: "at+jwt" }),
    );
    const claims = {
      aud: audience,
      client_id: "client_refresh",
      cnf: { jkt: dpop.thumbprint },
      company_id: "company_refresh",
      exp: Math.floor(Date.now() / 1000) + 300,
      grant_id: "grant_refresh",
      iat: Math.floor(Date.now() / 1000),
      iss: issuer,
      scope: MAKEPAY_OAUTH_SCOPES.join(" "),
      ...(installationId === undefined
        ? {}
        : { installation_id: installationId }),
    };
    const payload = base64Url(JSON.stringify(claims));
    const jwtSignature = sign(
      "RSA-SHA256",
      Buffer.from(`${header}.${payload}`),
      signingKey,
    );
    return `${header}.${payload}.${base64Url(jwtSignature)}`;
  }

  for (const refreshedInstallationId of [undefined, "installation_other"]) {
    const service = createService();
    const encryptionKey = Buffer.alloc(32, 3);
    const connection = {
      client_id: "client_refresh",
      company_id: "company_refresh",
      encrypted_refresh_token: encryptSecret(
        "refresh-old",
        encryptionKey,
        "connection:connection_refresh:refresh-token",
      ),
      grant_id: "grant_refresh",
      id: "connection_refresh",
      installation_id: "installation_refresh",
      metadata: { dpop_thumbprint: dpop.thumbprint },
    };
    const updates = [];
    service.oauthConfig = () => ({ audience, encryptionKey, issuer });
    service.discoverOAuth = async () => ({
      jwksUri,
      tokenEndpoint,
    });
    service.oauthCredentials = async () => ({
      accessToken: "access-old",
      connection,
      expiresAt: new Date(Date.now() - 1),
      privateKey: dpop.privateKeyPem,
      refreshToken: "refresh-old",
    });
    service.connectionRecord = async () => connection;
    service.generated = () => ({
      updateMakePayConnections: async (update) => {
        updates.push(update);
        Object.assign(connection, update);
        return connection;
      },
    });
    service.fetch_ = async (url) => {
      if (url === tokenEndpoint) {
        return new Response(
          JSON.stringify({
            access_token: accessToken(refreshedInstallationId),
            expires_in: 300,
            refresh_token: "refresh-rotated",
            scope: MAKEPAY_OAUTH_SCOPES.join(" "),
            token_type: "DPoP",
          }),
          { headers: { "content-type": "application/json" } },
        );
      }
      assert.equal(url, jwksUri);
      return new Response(
        JSON.stringify({
          keys: [
            {
              ...verificationKey.export({ format: "jwk" }),
              kid: "refresh-test",
              use: "sig",
            },
          ],
        }),
        { headers: { "content-type": "application/json" } },
      );
    };

    await assert.rejects(
      service.performRefresh("connection_refresh"),
      /different grant/i,
    );
    assert.equal(updates.at(-1).status, "error");
    assert.match(updates.at(-1).last_error, /different grant/i);
    assert.equal(
      updates.some((update) => update.status === "connected"),
      false,
    );
  }
});

test("OAuth refresh preserves disconnect intent and caps local expiry to the signed JWT", async () => {
  const issuer = "https://makecrypto.test";
  const audience = `${issuer}/api/partner/v1`;
  const tokenEndpoint = `${issuer}/oauth/token`;
  const jwksUri = `${issuer}/oauth/jwks.json`;
  const { privateKey: signingKey, publicKey: verificationKey } =
    generateKeyPairSync("rsa", { modulusLength: 2048 });
  const dpop = createDpopKeyPair();
  const encryptionKey = Buffer.alloc(32, 3);
  const signedExpiry = Math.floor(Date.now() / 1000) + 90;
  const header = base64Url(
    JSON.stringify({ alg: "RS256", kid: "refresh-expiry", typ: "at+jwt" }),
  );
  const payload = base64Url(
    JSON.stringify({
      aud: audience,
      client_id: "client_refresh",
      cnf: { jkt: dpop.thumbprint },
      company_id: "company_refresh",
      exp: signedExpiry,
      grant_id: "grant_refresh",
      iat: Math.floor(Date.now() / 1000),
      installation_id: "installation_refresh",
      iss: issuer,
      scope: MAKEPAY_OAUTH_SCOPES.join(" "),
    }),
  );
  const accessToken = `${header}.${payload}.${base64Url(
    sign("RSA-SHA256", Buffer.from(`${header}.${payload}`), signingKey),
  )}`;
  const connection = {
    client_id: "client_refresh",
    company_id: "company_refresh",
    encrypted_refresh_token: encryptSecret(
      "refresh-old",
      encryptionKey,
      "connection:connection_refresh:refresh-token",
    ),
    grant_id: "grant_refresh",
    id: "connection_refresh",
    installation_id: "installation_refresh",
    metadata: {
      disconnect_native_reset_mutation_id: "disconnect-stable",
      dpop_thumbprint: dpop.thumbprint,
    },
    status: "disconnect_pending",
  };
  const updates = [];
  const service = createService();
  service.oauthConfig = () => ({ audience, encryptionKey, issuer });
  service.discoverOAuth = async () => ({ jwksUri, tokenEndpoint });
  service.oauthCredentials = async () => ({
    accessToken: "access-old",
    connection,
    expiresAt: new Date(Date.now() - 1),
    privateKey: dpop.privateKeyPem,
    refreshToken: "refresh-old",
  });
  service.connectionRecord = async () => connection;
  service.generated = () => ({
    updateMakePayConnections: async (update) => {
      updates.push({
        ...update,
        metadata:
          update.metadata === undefined
            ? undefined
            : structuredClone(update.metadata),
      });
      Object.assign(connection, update);
      return connection;
    },
  });
  service.fetch_ = async (url) => {
    if (url === tokenEndpoint) {
      return new Response(
        JSON.stringify({
          access_token: accessToken,
          expires_in: 600,
          refresh_token: "refresh-rotated",
          scope: MAKEPAY_OAUTH_SCOPES.join(" "),
          token_type: "DPoP",
        }),
        { headers: { "content-type": "application/json" } },
      );
    }
    assert.equal(url, jwksUri);
    return new Response(
      JSON.stringify({
        keys: [
          {
            ...verificationKey.export({ format: "jwk" }),
            kid: "refresh-expiry",
            use: "sig",
          },
        ],
      }),
      { headers: { "content-type": "application/json" } },
    );
  };

  await service.performRefresh(connection.id);

  assert.equal(connection.status, "disconnect_pending");
  assert.equal(
    connection.metadata.disconnect_native_reset_mutation_id,
    "disconnect-stable",
  );
  assert.equal(connection.metadata.refresh_attempt, null);
  assert.equal(
    new Date(connection.access_token_expires_at).getTime(),
    signedExpiry * 1000,
  );
  assert.equal(
    updates.some((update) => update.status === "connected"),
    false,
    "a stale refresh completion must not overwrite disconnect_pending",
  );
});

test("starting OAuth after an abandoned state expires proves possession of the previous key", async () => {
  const service = createService();
  const registrations = [];
  const states = [];
  let installationRegistered = false;

  service.fetch_ = async (url, init) => {
    const discovery = discoveryResponse(url);
    if (discovery) return discovery;
    registrations.push({
      body: JSON.parse(init.body),
      headers: init.headers,
      url,
    });
    if (installationRegistered && !init.headers["dpop-previous"]) {
      return new Response(
        JSON.stringify({ error: "previous_proof_required" }),
        {
          headers: { "content-type": "application/json" },
          status: 409,
        },
      );
    }
    installationRegistered = true;
    return new Response(
      JSON.stringify({
        client_id: "client_medusa",
        registration_id: registrations.at(-1).body.registrationId,
        scopes: [...MAKEPAY_OAUTH_SCOPES],
      }),
      { headers: { "content-type": "application/json" } },
    );
  };
  service.generated = () => ({
    createMakePayOAuthStates: async (input) => {
      states.push(input);
      return input;
    },
    listMakePayConnections: async () => [],
    listMakePayOAuthStates: async () => states.slice(-1),
    updateMakePayOAuthStates: async (update) => {
      const state = states.find((entry) => entry.id === update.id);
      Object.assign(state, update);
      return state;
    },
  });

  const first = await service.startOAuth();
  states[0].expires_at = new Date(Date.now() - 1);
  const second = await service.startOAuth();

  assert.notEqual(first.authorization_url, second.authorization_url);
  assert.equal(registrations.length, 3);
  assert.equal(registrations[0].headers["dpop-previous"], undefined);
  assert.equal(registrations[1].headers["dpop-previous"], undefined);
  assert.match(
    registrations[2].headers["dpop-previous"],
    /^[^.]+\.[^.]+\.[^.]+$/,
  );
  assert.equal(
    registrations[0].body.registrationId,
    registrations[1].body.registrationId,
  );
  assert.equal(
    registrations[1].body.registrationId,
    registrations[2].body.registrationId,
  );
  assert.notEqual(
    states[0].encrypted_dpop_private_key,
    states[1].encrypted_dpop_private_key,
  );
});

test("OAuth registration recovers when rotation succeeded but its response was lost", async () => {
  const service = createService();
  const states = [];
  const registrations = [];
  let serverHasRotatedKey = false;

  service.fetch_ = async (url, init) => {
    const discovery = discoveryResponse(url);
    if (discovery) return discovery;
    registrations.push({
      body: JSON.parse(init.body),
      headers: init.headers,
    });
    if (!serverHasRotatedKey) {
      serverHasRotatedKey = true;
      throw new TypeError("simulated response loss");
    }
    if (!init.headers["dpop-previous"]) {
      return new Response(
        JSON.stringify({ error: "previous_proof_required" }),
        {
          headers: { "content-type": "application/json" },
          status: 409,
        },
      );
    }
    return new Response(
      JSON.stringify({
        client_id: "client_recovered",
        registration_id: registrations.at(-1).body.registrationId,
        scopes: [...MAKEPAY_OAUTH_SCOPES],
      }),
      { headers: { "content-type": "application/json" } },
    );
  };
  service.generated = () => ({
    createMakePayOAuthStates: async (input) => {
      states.push(input);
      return input;
    },
    listMakePayConnections: async () => [],
    listMakePayOAuthStates: async () => states.slice(-1),
    updateMakePayOAuthStates: async (update) => {
      const state = states.find((entry) => entry.id === update.id);
      Object.assign(state, update);
      return state;
    },
  });

  await assert.rejects(service.startOAuth(), /could not be reached/i);
  assert.equal(states[0].client_id, "registration_pending");

  const recovered = await service.startOAuth();
  const authorization = new URL(recovered.authorization_url);

  assert.equal(registrations.length, 3);
  assert.equal(registrations[1].headers["dpop-previous"], undefined);
  assert.match(
    registrations[2].headers["dpop-previous"],
    /^[^.]+\.[^.]+\.[^.]+$/,
  );
  assert.equal(
    registrations[0].body.registrationId,
    registrations[1].body.registrationId,
  );
  assert.equal(
    registrations[1].body.registrationId,
    registrations[2].body.registrationId,
  );
  assert.equal(states[1].client_id, "client_recovered");
  assert.equal(authorization.searchParams.get("client_id"), "client_recovered");
});

test("OAuth registration exhausts history beyond 20 states using the exact accepted DPoP key", async () => {
  const service = createService();
  const encryptionKey = Buffer.alloc(32, 3);
  const registrationId = base64Url(Buffer.alloc(32, 13));
  const acceptedKey = createDpopKeyPair();
  const staleConnectionKey = createDpopKeyPair();
  const decoyKeys = Array.from({ length: 23 }, () => createDpopKeyPair());
  const historicalKeys = [acceptedKey, ...decoyKeys, decoyKeys[5]];
  const states = historicalKeys.map((key, index) => {
    const id = `mpost_history_${String(index).padStart(2, "0")}`;
    return {
      client_id: "client_history",
      consumed_at: new Date("2026-07-23T00:00:00.000Z"),
      created_at: new Date(Date.UTC(2026, 6, 23, 0, 0, index)),
      dpop_thumbprint: key.thumbprint,
      encrypted_code_verifier: encryptSecret(
        `verifier-${index}`,
        encryptionKey,
        `oauth-state:${id}:verifier`,
      ),
      encrypted_dpop_private_key: encryptSecret(
        key.privateKeyPem,
        encryptionKey,
        `oauth-state:${id}:dpop`,
      ),
      encrypted_registration_id: encryptSecret(
        registrationId,
        encryptionKey,
        `oauth-state:${id}:registration-id`,
      ),
      expires_at: new Date("2026-07-23T00:10:00.000Z"),
      id,
      provider_id: "makepay",
      redirect_uri: "https://api.shop.test/makepay/oauth/callback",
      state_hash: `history-state-${index}`,
    };
  });
  const staleConnection = {
    encrypted_dpop_private_key: encryptSecret(
      staleConnectionKey.privateKeyPem,
      encryptionKey,
      "connection:mpcon_history:dpop",
    ),
    encrypted_registration_id: encryptSecret(
      registrationId,
      encryptionKey,
      "connection:mpcon_history:registration-id",
    ),
    id: "mpcon_history",
    metadata: { dpop_thumbprint: staleConnectionKey.thumbprint },
    provider_id: "makepay",
    status: "error",
  };
  const attemptedPreviousKeys = [];
  const recoveryPages = [];

  service.connectionRecord = async () => staleConnection;
  service.fetch_ = async (url, init) => {
    const discovery = discoveryResponse(url);
    if (discovery) return discovery;

    const previousProof = init.headers["dpop-previous"];
    const previousThumbprint = previousProof
      ? dpopProofThumbprint(previousProof)
      : undefined;
    attemptedPreviousKeys.push(previousThumbprint);
    if (previousThumbprint !== acceptedKey.thumbprint) {
      return new Response(
        JSON.stringify({ error: "previous_proof_required" }),
        {
          headers: { "content-type": "application/json" },
          status: 401,
        },
      );
    }

    const payload = JSON.parse(init.body);
    return new Response(
      JSON.stringify({
        client_id: "client_history",
        registration_id: payload.registrationId,
        scopes: [...MAKEPAY_OAUTH_SCOPES],
      }),
      { headers: { "content-type": "application/json" } },
    );
  };
  service.generated = () => ({
    createMakePayOAuthStates: async (input) => {
      states.push({ ...input, created_at: new Date() });
      return input;
    },
    listMakePayOAuthStates: async (filters = {}, config = {}) => {
      const filtered = states
        .filter(
          (state) =>
            (!filters.provider_id ||
              state.provider_id === filters.provider_id) &&
            (!filters.state_hash || state.state_hash === filters.state_hash),
        )
        .sort((left, right) => {
          const created =
            new Date(right.created_at).getTime() -
            new Date(left.created_at).getTime();
          return created || String(right.id).localeCompare(String(left.id));
        });
      const skip = Number(config.skip) || 0;
      const take = Number(config.take) || filtered.length;
      if (take === 20) recoveryPages.push({ skip, take });
      return filtered.slice(skip, skip + take);
    },
    updateMakePayOAuthStates: async (update) => {
      const state = states.find((entry) => entry.id === update.id);
      Object.assign(state, update);
      return state;
    },
  });

  const started = await service.startOAuth();
  assert.equal(
    new URL(started.authorization_url).searchParams.get("client_id"),
    "client_history",
  );
  assert.deepEqual(recoveryPages, [
    { skip: 0, take: 20 },
    { skip: 20, take: 20 },
  ]);

  const newestFirstDeduplicated = [
    ...new Map(
      [...historicalKeys]
        .reverse()
        .map((key) => [key.thumbprint, key.thumbprint]),
    ).values(),
  ];
  assert.deepEqual(attemptedPreviousKeys, [
    staleConnectionKey.thumbprint,
    ...newestFirstDeduplicated,
  ]);
  assert.equal(attemptedPreviousKeys.at(-1), acceptedKey.thumbprint);
  assert.equal(
    attemptedPreviousKeys.filter(
      (thumbprint) => thumbprint === decoyKeys[5].thumbprint,
    ).length,
    1,
    "duplicate historical private keys must be attempted only once",
  );
});

test("OAuth refresh fails closed without Medusa distributed locking", async () => {
  const service = createService();
  service.lockingService = () => undefined;

  await assert.rejects(
    service.refreshOAuth("connection_without_lock"),
    /requires Medusa's locking module/i,
  );
});

test("OAuth webhook preflight verifies HMAC, tolerance, and signed lock identity", async () => {
  const service = createService({ options: { webhookToleranceSeconds: 60 } });
  const secret = "preflight_webhook_secret";
  const deliveryGroupId = `mpwhgrp_${"a".repeat(64)}`;
  const rawBody = Buffer.from(
    JSON.stringify({
      deliveryGroupId,
      paymentLink: { uid: "pay_preflight" },
      schemaVersion: "medusa.v1",
    }),
  );
  service.getWebhookSecret = async () => secret;
  const signature = (body, timestamp = Math.floor(Date.now() / 1000)) =>
    `t=${timestamp},v1=${createHmac("sha256", secret)
      .update(`${timestamp}.`)
      .update(body)
      .digest("hex")}`;

  assert.deepEqual(
    await service.verifyWebhookSignature(
      rawBody,
      signature(rawBody),
      deliveryGroupId,
    ),
    { deliveryGroupId, paymentLinkUid: "pay_preflight" },
  );
  const wrongSchemaBody = Buffer.from(
    JSON.stringify({
      deliveryGroupId,
      paymentLink: { uid: "pay_preflight" },
      schemaVersion: "medusa.v2",
    }),
  );

  for (const [body, signed, group, expectedStatus] of [
    [rawBody, "t=1,v1=00", deliveryGroupId, 401],
    [
      rawBody,
      signature(rawBody, Math.floor(Date.now() / 1000) - 61),
      deliveryGroupId,
      401,
    ],
    [Buffer.from("{"), signature(Buffer.from("{")), deliveryGroupId, 400],
    [wrongSchemaBody, signature(wrongSchemaBody), deliveryGroupId, 400],
    [rawBody, signature(rawBody), `mpwhgrp_${"b".repeat(64)}`, 400],
  ]) {
    await assert.rejects(
      service.verifyWebhookSignature(body, signed, group),
      (error) =>
        error instanceof MakePayError && error.status === expectedStatus,
    );
  }
});

test("synchronous OAuth webhooks hold a payment-scoped lock through processing", async () => {
  const service = createService();
  const deliveryGroupId = `mpwhgrp_${"a".repeat(64)}`;
  const paymentLinkUid = "pay_webhook_lock";
  const locks = [];
  service.withDistributedLock = async (key, job, timeout) => {
    locks.push({ key, timeout });
    return job();
  };

  assert.equal(
    await service.withWebhookDeliveryLock(
      { deliveryGroupId, paymentLinkUid },
      async () => "processed",
    ),
    "processed",
  );
  assert.deepEqual(locks, [
    {
      key: `makepay-payment-effects:${sha256(paymentLinkUid)}`,
      timeout: 30,
    },
  ]);
  await assert.rejects(
    service.withWebhookDeliveryLock(
      { deliveryGroupId: "untrusted-lock-key", paymentLinkUid },
      async () => {},
    ),
    /delivery identity is invalid/i,
  );
});
