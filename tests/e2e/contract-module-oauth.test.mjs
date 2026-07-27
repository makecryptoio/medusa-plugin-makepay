import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import test from "node:test";

import { decryptSecret, sha256 } from "../../src/modules/makepay/crypto.ts";
import MakePayModuleService from "../../src/modules/makepay/service.ts";
import MakePayProviderService from "../../src/providers/makepay/services/makepay-provider.ts";
import { createMakePayContractServer } from "./support/makepay-contract-server.mjs";

test("module OAuth flow interoperates with the MakePay contract", async () => {
  const contract = createMakePayContractServer();
  await contract.start();

  const states = [];
  const connections = [];
  const webhookSubscriptions = [];
  const service = Object.create(MakePayModuleService.prototype);
  service.options_ = {
    authMode: "oauth",
    backendUrl: "http://127.0.0.1:9000",
    encryptionKey: randomBytes(32).toString("base64"),
    lockingProvider: "makepay-postgres",
    oauthApiUrl: contract.origin,
    oauthIssuerUrl: contract.origin,
    providerId: "makepay",
    storefrontReturnUrl: "http://127.0.0.1:8000/dk/makepay/return",
  };
  service.fetch_ = fetch;
  service.logger_ = { warn() {} };
  service.lockingService = () => ({
    execute: async (_key, job) => job(),
  });
  service.generated = () => ({
    createMakePayConnections: async (input) => {
      connections.push({ ...input });
      return input;
    },
    createMakePayOAuthStates: async (input) => {
      states.push({ ...input, created_at: new Date() });
      return input;
    },
    createMakePayWebhookSubscriptions: async (input) => {
      webhookSubscriptions.push({ ...input });
      return input;
    },
    listMakePayConnections: async (filters = {}) =>
      connections.filter(
        (connection) =>
          !filters.provider_id ||
          connection.provider_id === filters.provider_id,
      ),
    listMakePayOAuthStates: async (filters = {}) =>
      states.filter(
        (state) =>
          (!filters.provider_id || state.provider_id === filters.provider_id) &&
          (!filters.state_hash || state.state_hash === filters.state_hash),
      ),
    listMakePayPaymentProjections: async (_filters = {}, options = {}) => {
      assert.equal(options.take, 1);
      assert.deepEqual(options.order, { id: "ASC" });
      return [];
    },
    listMakePayWebhookSubscriptions: async (filters = {}) =>
      webhookSubscriptions.filter(
        (subscription) =>
          (!filters.provider_id ||
            subscription.provider_id === filters.provider_id) &&
          (!filters.subscription_id ||
            subscription.subscription_id === filters.subscription_id) &&
          (!filters.status || subscription.status === filters.status),
      ),
    deleteMakePayOAuthStates: async () => {
      states.length = 0;
    },
    updateMakePayConnections: async (input) => {
      const connection = connections.find(
        (candidate) => candidate.id === input.id,
      );
      assert.ok(connection, `Unknown connection ${input.id}`);
      Object.assign(connection, input);
      return connection;
    },
    updateMakePayOAuthStates: async (input) => {
      const state = states.find((candidate) => candidate.id === input.id);
      assert.ok(state, `Unknown OAuth state ${input.id}`);
      Object.assign(state, input);
      return state;
    },
    updateMakePayWebhookSubscriptions: async (input) => {
      const subscription = webhookSubscriptions.find(
        (candidate) => candidate.id === input.id,
      );
      assert.ok(subscription, `Unknown webhook subscription ${input.id}`);
      Object.assign(subscription, input);
      return subscription;
    },
  });
  // Exercise the production provider/module configuration handshake instead of
  // bypassing it by mutating the module's private registration flag.
  new MakePayProviderService({ makepayIntegration: service }, service.options_);
  try {
    const started = await service.startOAuth();
    const consent = new URL(started.authorization_url);
    consent.searchParams.set("decision", "approve");
    const authorizationResponse = await fetch(consent, { redirect: "manual" });
    assert.equal(authorizationResponse.status, 302);
    const callback = new URL(authorizationResponse.headers.get("location"));

    await service.finishOAuth({
      code: callback.searchParams.get("code"),
      iss: callback.searchParams.get("iss"),
      state: callback.searchParams.get("state"),
    });

    assert.equal(connections.length, 1);
    assert.equal(connections[0].auth_mode, "oauth");
    assert.equal(connections[0].status, "connected");
    assert.equal(connections[0].webhook_status, "healthy");
    assert.ok(connections[0].webhook_subscription_id);
    const stableSubscriptionId = connections[0].webhook_subscription_id;
    assert.equal(webhookSubscriptions.length, 1);
    assert.equal(webhookSubscriptions[0].status, "active");
    assert.equal(
      webhookSubscriptions[0].subscription_id,
      connections[0].webhook_subscription_id,
    );
    assert.equal(contract.state.subscriptions.size, 1);
    assert.equal(
      [...contract.state.subscriptions.values()][0].callbackUrl,
      "http://127.0.0.1:9000/hooks/makepay/makepay_makepay",
    );

    const encryptionKey = Buffer.from(service.options_.encryptionKey, "base64");
    const initialDpopThumbprint = connections[0].metadata.dpop_thumbprint;
    const initialWebhookSecret = decryptSecret(
      connections[0].encrypted_webhook_secret,
      encryptionKey,
      `connection:${connections[0].id}:webhook-secret`,
    );
    const ambiguousReconnect = await service.startOAuth();
    const ambiguousConsent = new URL(ambiguousReconnect.authorization_url);
    ambiguousConsent.searchParams.set("decision", "approve");
    const ambiguousAuthorizationResponse = await fetch(ambiguousConsent, {
      redirect: "manual",
    });
    assert.equal(ambiguousAuthorizationResponse.status, 302);
    const ambiguousCallback = new URL(
      ambiguousAuthorizationResponse.headers.get("location"),
    );
    let loseWebhookRotationResponse = true;
    service.fetch_ = async (input, init) => {
      const response = await fetch(input, init);
      const requestUrl = new URL(
        typeof input === "string" || input instanceof URL ? input : input.url,
      );
      if (
        loseWebhookRotationResponse &&
        init?.method === "PUT" &&
        requestUrl.pathname ===
          "/api/partner/v1/makepay/webhook-subscriptions/current"
      ) {
        loseWebhookRotationResponse = false;
        await response.arrayBuffer();
        throw new Error("simulated webhook rotation response loss");
      }
      return response;
    };
    await assert.rejects(
      service.finishOAuth({
        code: ambiguousCallback.searchParams.get("code"),
        iss: ambiguousCallback.searchParams.get("iss"),
        state: ambiguousCallback.searchParams.get("state"),
      }),
      /webhook subscription setup failed/i,
    );
    assert.equal(connections[0].status, "error");
    assert.equal(webhookSubscriptions[0].status, "historical");
    assert.equal(
      decryptSecret(
        webhookSubscriptions[0].encrypted_signing_secret,
        encryptionKey,
        `webhook-subscription:${webhookSubscriptions[0].id}:signing-secret`,
      ),
      initialWebhookSecret,
      "the last known webhook credential must be historical before rotation",
    );
    const ambiguousDpopThumbprint = connections[0].metadata.dpop_thumbprint;
    assert.notEqual(ambiguousDpopThumbprint, initialDpopThumbprint);
    const ambiguousRotationKey =
      connections[0].metadata.webhook_rotation.idempotency_key;
    const ambiguousReceiptKey = `webhook:${connections[0].grant_id}:${ambiguousRotationKey}`;
    const ambiguousReceipt =
      contract.state.webhookMutationReceipts.get(ambiguousReceiptKey);
    assert.ok(ambiguousReceipt);
    assert.equal(ambiguousReceipt.dpopJkt, ambiguousDpopThumbprint);
    assert.notEqual(
      ambiguousReceipt.responseBody.signingSecret,
      initialWebhookSecret,
    );
    ambiguousReceipt.expiresAt = Date.now() - 1;

    const refreshToken = decryptSecret(
      connections[0].encrypted_refresh_token,
      encryptionKey,
      `connection:${connections[0].id}:refresh-token`,
    );
    connections[0].access_token_expires_at = new Date(0);
    connections[0].metadata = {
      ...connections[0].metadata,
      refresh_attempt: {
        credential_fingerprint: sha256(refreshToken),
        idempotency_key: `medusa-token-${randomBytes(32).toString("base64url")}`,
        recovery_expired: true,
      },
    };
    service.fetch_ = fetch;
    const recoveryReconnect = await service.startOAuth();
    const recoveryConsent = new URL(recoveryReconnect.authorization_url);
    recoveryConsent.searchParams.set("decision", "approve");
    const recoveryAuthorizationResponse = await fetch(recoveryConsent, {
      redirect: "manual",
    });
    assert.equal(recoveryAuthorizationResponse.status, 302);
    const recoveryCallback = new URL(
      recoveryAuthorizationResponse.headers.get("location"),
    );
    await service.finishOAuth({
      code: recoveryCallback.searchParams.get("code"),
      iss: recoveryCallback.searchParams.get("iss"),
      state: recoveryCallback.searchParams.get("state"),
    });
    assert.equal(connections[0].status, "connected");
    assert.equal(connections[0].webhook_status, "healthy");
    assert.equal(connections[0].metadata.webhook_rotation, null);
    const webhookRotationRequests = contract.state.requests.filter(
      (request) =>
        request.method === "PUT" &&
        request.pathname ===
          "/api/partner/v1/makepay/webhook-subscriptions/current",
    );
    assert.equal(
      webhookRotationRequests.filter(
        (request) => request.idempotencyKey === ambiguousRotationKey,
      ).length,
      1,
      "a new consent must not replay an expired prior-state rotation",
    );
    const freshRotationKey = webhookRotationRequests.at(-1).idempotencyKey;
    assert.notEqual(freshRotationKey, ambiguousRotationKey);
    const freshReceipt = contract.state.webhookMutationReceipts.get(
      `webhook:${connections[0].grant_id}:${freshRotationKey}`,
    );
    assert.ok(freshReceipt);
    assert.equal(freshReceipt.dpopJkt, connections[0].metadata.dpop_thumbprint);
    assert.notEqual(freshReceipt.dpopJkt, ambiguousReceipt.dpopJkt);
    assert.equal(
      decryptSecret(
        connections[0].encrypted_webhook_secret,
        encryptionKey,
        `connection:${connections[0].id}:webhook-secret`,
      ),
      freshReceipt.responseBody.signingSecret,
      "the fresh rotation secret must be durably known after reconnect",
    );
    assert.equal(
      connections[0].webhook_subscription_id,
      stableSubscriptionId,
      "secret rotation keeps the grant-scoped subscription identity stable",
    );
    assert.equal(webhookSubscriptions.length, 1);
    assert.equal(webhookSubscriptions[0].status, "active");
    assert.equal(
      decryptSecret(
        webhookSubscriptions[0].encrypted_signing_secret,
        encryptionKey,
        `webhook-subscription:${webhookSubscriptions[0].id}:signing-secret`,
      ),
      freshReceipt.responseBody.signingSecret,
      "the stable local credential row must contain the current S2 secret",
    );

    const retryDeliveryGroupId = `mpwhgrp_${"c".repeat(64)}`;
    const retryPaymentLinkUid = "payment_stable_subscription_retry";
    const retryBody = Buffer.from(
      JSON.stringify({
        companyId: connections[0].company_id,
        deliveryGroupId: retryDeliveryGroupId,
        deliveryId: "delivery_stable_subscription_retry",
        grantId: connections[0].grant_id,
        installationId: connections[0].installation_id,
        paymentLink: { uid: retryPaymentLinkUid },
        schemaVersion: "medusa.v1",
        status: "complete",
        subscriptionId: stableSubscriptionId,
      }),
    );
    service.projectionByUid = async (uid) =>
      uid === retryPaymentLinkUid
        ? {
            auth_mode: "oauth",
            company_id: connections[0].company_id,
            grant_id: connections[0].grant_id,
            installation_id: connections[0].installation_id,
            payment_link_uid: retryPaymentLinkUid,
            provider_id: "makepay",
            webhook_subscription_id: stableSubscriptionId,
          }
        : undefined;
    const signRetry = (secret) => {
      const timestamp = Math.floor(Date.now() / 1000);
      return `t=${timestamp},v1=${createHmac("sha256", secret)
        .update(`${timestamp}.`)
        .update(retryBody)
        .digest("hex")}`;
    };
    let acceptedRetryDeliveries = 0;
    const receiveRetry = async (secret) => {
      try {
        await service.verifyWebhookSignature(
          retryBody,
          signRetry(secret),
          retryDeliveryGroupId,
        );
        acceptedRetryDeliveries += 1;
        return 200;
      } catch (error) {
        return error?.status;
      }
    };
    assert.equal(
      await receiveRetry(ambiguousReceipt.responseBody.signingSecret),
      401,
      "an in-flight S1 signature must fail after stable-ID rotation",
    );
    assert.equal(
      await receiveRetry(freshReceipt.responseBody.signingSecret),
      200,
      "the durable retry re-signed with S2 must succeed",
    );
    assert.equal(acceptedRetryDeliveries, 1);

    let loseRefreshResponse = true;
    service.fetch_ = async (input, init) => {
      const response = await fetch(input, init);
      const requestUrl = new URL(
        typeof input === "string" || input instanceof URL ? input : input.url,
      );
      const form =
        init?.body instanceof URLSearchParams ? init.body : undefined;
      if (
        loseRefreshResponse &&
        requestUrl.pathname === "/oauth/token" &&
        form?.get("grant_type") === "refresh_token"
      ) {
        loseRefreshResponse = false;
        await response.arrayBuffer();
        throw new Error("simulated refresh response loss");
      }
      return response;
    };
    await assert.rejects(
      service.performRefresh(connections[0].id),
      /refresh response loss/i,
    );
    assert.equal(connections[0].status, "connected");
    assert.equal(connections[0].last_error, "MakePay OAuth refresh failed.");
    assert.equal(connections[0].metadata.refresh_attempt.failure, "retryable");
    const refreshAttemptKey =
      connections[0].metadata.refresh_attempt.idempotency_key;
    await service.performRefresh(connections[0].id);
    assert.equal(connections[0].status, "connected");
    assert.equal(connections[0].last_error, null);
    assert.equal(connections[0].metadata.refresh_attempt, null);
    const refreshRequests = contract.state.requests.filter(
      (request) =>
        request.method === "POST" &&
        request.pathname === "/oauth/token" &&
        request.idempotencyKey === refreshAttemptKey,
    );
    assert.equal(refreshRequests.length, 2);
    assert.equal(
      refreshRequests[0].idempotencyKey,
      refreshRequests[1].idempotencyKey,
    );

    const clientId = connections[0].client_id;
    let nativeResetResponsesToLose = 2;
    service.fetch_ = async (input, init) => {
      const response = await fetch(input, init);
      const requestUrl = new URL(
        typeof input === "string" || input instanceof URL ? input : input.url,
      );
      if (
        nativeResetResponsesToLose > 0 &&
        init?.method === "DELETE" &&
        requestUrl.pathname === "/oauth/native/installations"
      ) {
        nativeResetResponsesToLose -= 1;
        await response.arrayBuffer();
        throw new Error("simulated native-reset response loss");
      }
      return response;
    };

    const pendingDisconnect = await service.disconnectOAuth();
    assert.equal(pendingDisconnect.status, "disconnect_pending");
    assert.ok(connections[0].encrypted_access_token);
    assert.ok(connections[0].encrypted_refresh_token);
    assert.ok(connections[0].encrypted_dpop_private_key);
    assert.ok(connections[0].metadata.disconnect_native_reset_mutation_id);
    assert.ok(connections[0].metadata.disconnect_webhook_mutation_id);
    assert.equal(contract.state.installations.get(clientId)?.reset, true);
    assert.ok(states.length > 0);
    assert.ok(states.every((state) => state.consumed_at));
    assert.ok(
      states.every((state) => state.encrypted_authorization_code == null),
    );
    assert.ok(states.every((state) => state.token_exchange_id == null));
    assert.ok(states.every((state) => state.encrypted_dpop_private_key));

    const disconnected = await service.disconnectOAuth();
    assert.equal(disconnected.status, "disconnected");
    assert.equal(states.length, 0);
    assert.equal(connections[0].encrypted_access_token, null);
    assert.equal(connections[0].encrypted_refresh_token, null);
    assert.equal(connections[0].encrypted_dpop_private_key, null);
    assert.equal(connections[0].encrypted_webhook_secret, null);
    assert.equal(webhookSubscriptions.length, 1);
    assert.equal(webhookSubscriptions[0].status, "historical");
    assert.ok(webhookSubscriptions[0].encrypted_signing_secret);
    assert.equal(
      decryptSecret(
        webhookSubscriptions[0].encrypted_signing_secret,
        encryptionKey,
        `webhook-subscription:${webhookSubscriptions[0].id}:signing-secret`,
      ),
      freshReceipt.responseBody.signingSecret,
      "disconnect without secret rotation retains S2 for old links",
    );
    assert.equal(contract.state.installations.has(clientId), true);
    assert.equal(contract.state.installations.get(clientId)?.reset, true);
    assert.equal(contract.state.subscriptions.size, 1);
    assert.equal(
      [...contract.state.subscriptions.values()][0].status,
      "disabled",
    );
    assert.equal(
      [...contract.state.subscriptions.values()][0].signingSecret,
      freshReceipt.responseBody.signingSecret,
      "server disconnect must not rotate the stable subscription secret",
    );
    assert.equal(states.length, 0);
    const resetRequests = contract.state.requests.filter(
      (request) =>
        request.method === "DELETE" &&
        request.pathname === "/oauth/native/installations",
    );
    assert.equal(
      resetRequests.length,
      3,
      "disconnect must replay the same native reset after response loss",
    );
    assert.equal(
      resetRequests[0].idempotencyKey,
      resetRequests[1].idempotencyKey,
    );
    assert.equal(
      resetRequests[1].idempotencyKey,
      resetRequests[2].idempotencyKey,
    );
    assert.equal(contract.state.resetReceipts.size, 1);
    assert.equal(
      contract.state.requests.filter(
        (request) =>
          request.method === "DELETE" &&
          request.pathname ===
            "/api/partner/v1/makepay/webhook-subscriptions/current",
      ).length,
      1,
      "disconnect retry must not disable the webhook twice",
    );
    assert.equal(
      contract.state.requests.some(
        (request) => request.pathname === "/oauth/revoke",
      ),
      false,
      "native disconnect must not make a second token-revocation request",
    );

    const firstDisconnectResetKey = resetRequests[0].idempotencyKey;
    const firstDisconnectWebhookKey = contract.state.requests.find(
      (request) =>
        request.method === "DELETE" &&
        request.pathname ===
          "/api/partner/v1/makepay/webhook-subscriptions/current",
    ).idempotencyKey;

    const restarted = await service.startOAuth();
    const secondConsent = new URL(restarted.authorization_url);
    secondConsent.searchParams.set("decision", "approve");
    const secondAuthorizationResponse = await fetch(secondConsent, {
      redirect: "manual",
    });
    assert.equal(secondAuthorizationResponse.status, 302);
    const secondCallback = new URL(
      secondAuthorizationResponse.headers.get("location"),
    );
    await service.finishOAuth({
      code: secondCallback.searchParams.get("code"),
      iss: secondCallback.searchParams.get("iss"),
      state: secondCallback.searchParams.get("state"),
    });
    assert.equal(connections[0].status, "connected");
    assert.equal(connections[0].webhook_status, "healthy");

    const predecessorRefreshToken = decryptSecret(
      connections[0].encrypted_refresh_token,
      encryptionKey,
      `connection:${connections[0].id}:refresh-token`,
    );
    const predecessorRefresh =
      contract.state.refreshTokens.get(predecessorRefreshToken);
    assert.ok(predecessorRefresh);
    assert.equal(predecessorRefresh.revoked, false);

    // Consent promotes the staged installation key and revokes every token
    // bound to its predecessor. Losing the callback is therefore terminal for
    // the retained connection; disconnect must not probe the staged key with
    // an already-revoked predecessor refresh token.
    const lostCallbackReconnect = await service.startOAuth();
    const lostCallbackConsent = new URL(
      lostCallbackReconnect.authorization_url,
    );
    lostCallbackConsent.searchParams.set("decision", "approve");
    const lostCallbackAuthorizationResponse = await fetch(
      lostCallbackConsent,
      {
        redirect: "manual",
      },
    );
    assert.equal(lostCallbackAuthorizationResponse.status, 302);
    assert.equal(
      predecessorRefresh.revoked,
      true,
      "consent promotion must revoke the predecessor refresh family",
    );
    const resetRequestCountBeforeTerminalDisconnect =
      contract.state.requests.filter(
        (request) =>
          request.method === "DELETE" &&
          request.pathname === "/oauth/native/installations",
      ).length;
    const webhookDeleteCountBeforeTerminalDisconnect =
      contract.state.requests.filter(
        (request) =>
          request.method === "DELETE" &&
          request.pathname ===
            "/api/partner/v1/makepay/webhook-subscriptions/current",
      ).length;
    const refreshRequestCountBeforeTerminalDisconnect =
      contract.state.requests.filter(
        (request) =>
          request.method === "POST" &&
          request.pathname === "/oauth/token" &&
          request.body.grant_type === "refresh_token",
      ).length;
    connections[0].access_token_expires_at = new Date(0);
    const terminalDisconnect = await service.disconnectOAuth();
    assert.equal(terminalDisconnect.status, "disconnect_pending");
    assert.match(terminalDisconnect.last_error, /reconnect/i);
    assert.equal(
      connections[0].metadata.refresh_attempt.failure,
      "terminal",
    );
    assert.ok(connections[0].encrypted_access_token);
    assert.ok(connections[0].encrypted_refresh_token);
    assert.ok(connections[0].encrypted_dpop_private_key);
    assert.ok(states.length > 0);
    assert.ok(states.every((state) => state.consumed_at));
    assert.ok(states.every((state) => state.encrypted_dpop_private_key));
    const terminalDisconnectRefreshRequests = contract.state.requests
      .filter(
        (request) =>
          request.method === "POST" &&
          request.pathname === "/oauth/token" &&
          request.body.grant_type === "refresh_token",
      )
      .slice(refreshRequestCountBeforeTerminalDisconnect);
    assert.equal(
      terminalDisconnectRefreshRequests.length,
      1,
      "a revoked predecessor refresh must terminate before staged-key fallback",
    );
    assert.equal(terminalDisconnectRefreshRequests[0].responseStatus, 400);
    assert.equal(
      contract.state.requests.filter(
        (request) =>
          request.method === "DELETE" &&
          request.pathname === "/oauth/native/installations",
      ).length,
      resetRequestCountBeforeTerminalDisconnect,
    );
    assert.equal(
      contract.state.requests.filter(
        (request) =>
          request.method === "DELETE" &&
          request.pathname ===
            "/api/partner/v1/makepay/webhook-subscriptions/current",
      ).length,
      webhookDeleteCountBeforeTerminalDisconnect,
    );

    // The retained lost-callback key proves the next native registration.
    // Fresh consent then establishes a new grant that can be disconnected
    // cleanly.
    const retainedStateCount = states.length;
    const replacementReconnect = await service.startOAuth();
    const replacementConsent = new URL(replacementReconnect.authorization_url);
    replacementConsent.searchParams.set("decision", "approve");
    const replacementAuthorizationResponse = await fetch(replacementConsent, {
      redirect: "manual",
    });
    assert.equal(replacementAuthorizationResponse.status, 302);
    const replacementCallback = new URL(
      replacementAuthorizationResponse.headers.get("location"),
    );
    await service.finishOAuth({
      code: replacementCallback.searchParams.get("code"),
      iss: replacementCallback.searchParams.get("iss"),
      state: replacementCallback.searchParams.get("state"),
    });
    assert.equal(connections[0].status, "connected");
    assert.equal(connections[0].webhook_status, "healthy");
    assert.equal(connections[0].metadata.refresh_attempt, null);
    assert.ok(states.length > retainedStateCount);

    const secondDisconnected = await service.disconnectOAuth();
    assert.equal(secondDisconnected.status, "disconnected");
    assert.equal(states.length, 0);
    assert.equal(connections[0].encrypted_access_token, null);
    assert.equal(connections[0].encrypted_refresh_token, null);
    assert.equal(connections[0].encrypted_dpop_private_key, null);
    const allResetRequests = contract.state.requests.filter(
      (request) =>
        request.method === "DELETE" &&
        request.pathname === "/oauth/native/installations",
    );
    assert.equal(allResetRequests.length, 4);
    assert.notEqual(
      allResetRequests.at(-1).idempotencyKey,
      firstDisconnectResetKey,
      "a completed reconnect must allocate a fresh reset mutation identity",
    );
    assert.equal(contract.state.resetReceipts.size, 2);
    const allWebhookDeletes = contract.state.requests.filter(
      (request) =>
        request.method === "DELETE" &&
        request.pathname ===
          "/api/partner/v1/makepay/webhook-subscriptions/current",
    );
    assert.equal(allWebhookDeletes.length, 2);
    assert.notEqual(
      allWebhookDeletes.at(-1).idempotencyKey,
      firstDisconnectWebhookKey,
      "a completed reconnect must allocate a fresh webhook-disable identity",
    );
  } finally {
    await contract.close();
  }
});
