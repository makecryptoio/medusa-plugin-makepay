import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";

import {
  MedusaError,
  Modules,
  PaymentActions,
  PaymentSessionStatus,
} from "@medusajs/framework/utils";
import { MedusaModule } from "@medusajs/framework/modules-sdk";

import { createMakePayContractServer } from "./e2e/support/makepay-contract-server.mjs";
import { MAKEPAY_MODULE } from "../src/modules/makepay/constants.ts";
import MakePayModuleService from "../src/modules/makepay/service.ts";
import MakePayProviderService from "../src/providers/makepay/services/makepay-provider.ts";
import {
  getDefaultMakePayOAuthAudience,
  getAuthoritativeMakePayProviderStatus,
  makePaySecurityConfigurationFingerprint,
} from "../src/providers/makepay/utils.ts";

function signature(rawBody, secret, timestamp = Math.floor(Date.now() / 1000)) {
  const digest = createHmac("sha256", secret)
    .update(`${timestamp}.${rawBody}`)
    .digest("hex");
  return `t=${timestamp},v1=${digest}`;
}

function compatibleModule(authMode, overrides = {}) {
  return {
    authMode,
    providerId: "makepay",
    async assertAuthModeTransitionAllowed() {},
    hasSynchronousWebhookAuthority() {
      return false;
    },
    async projectionBySession() {
      return undefined;
    },
    registerPaymentProviderConfiguration() {},
    async withPaymentInitiationGuard(job) {
      return job();
    },
    ...overrides,
  };
}

function actualModule(options) {
  const service = Object.create(MakePayModuleService.prototype);
  service.options_ = options;
  service.providerConfigurationRegistered_ = false;
  return service;
}

test("official OAuth defaults preserve the established protected-resource identifier", () => {
  assert.equal(
    getDefaultMakePayOAuthAudience("https://www.makecrypto.io"),
    "https://makecrypto.io/api/partner/v1",
  );
  assert.equal(
    getDefaultMakePayOAuthAudience("https://issuer.makecrypto.test/"),
    "https://issuer.makecrypto.test/api/partner/v1",
  );

  const service = actualModule({
    authMode: "oauth",
    backendUrl: "https://api.shop.test",
    encryptionKey: Buffer.alloc(32, 7).toString("base64"),
    storefrontReturnUrl: "https://shop.test/payment/return",
  });
  assert.equal(
    service.oauthConfig().audience,
    "https://makecrypto.io/api/partner/v1",
  );
});

test("provider creates a safe pending order session and reconciles completion", async () => {
  const contract = createMakePayContractServer();
  await contract.start();
  const projections = new Map();
  const deliveries = [];
  const moduleService = compatibleModule("api_key", {
    async getInstallationContext() {
      return {
        companyId: "company_contract",
        installationId: "installation_contract",
      };
    },
    async projectionByUid(uid) {
      return projections.get(uid);
    },
    async projectionBySession(sessionId) {
      return [...projections.values()].find(
        (projection) => projection.session_id === sessionId,
      );
    },
    async reconcileProjectionFromResponse(projection, response) {
      const paymentLink = response.paymentLink ?? response;
      const providerStatus = getAuthoritativeMakePayProviderStatus({
        paymentLink,
        session: paymentLink.latestSession ?? paymentLink.session,
      });
      if (providerStatus === "conflicting_terminal") {
        throw new Error(
          "MakePay returned conflicting authoritative terminal states.",
        );
      }
      projection.provider_status = providerStatus;
      return projection;
    },
    async recordWebhook(input) {
      deliveries.push(input);
      return deliveries.filter(
        (delivery) => delivery.deliveryId === input.deliveryId,
      ).length > 1
        ? "retry"
        : "accepted";
    },
    async upsertProjection(projection) {
      const stored = { ...projection, provider_id: "makepay" };
      projections.set(stored.payment_link_uid, stored);
      return stored;
    },
  });

  try {
    const provider = new MakePayProviderService(
      { makepayIntegration: moduleService },
      {
        authMode: "api_key",
        backendUrl: "https://api.shop.test",
        baseUrl: contract.origin,
        checkoutBaseUrl: contract.origin,
        keyId: contract.apiKeyId,
        keySecret: contract.apiKeySecret,
        settlementCurrency: "USDT",
        storefrontReturnUrl: "https://shop.test/order/makepay-return",
        webhookToleranceSeconds: 60,
        webhookSecret: contract.webhookSecret,
      },
    );

    const initiated = await provider.initiatePayment({
      amount: { numeric: 12.34 },
      context: {
        customer: { email: "buyer@example.test", id: "cus_test" },
        idempotency_key: "idem_provider",
      },
      currency_code: "usd",
      data: {
        customer_email: " guest@example.test ",
        failureUrl: "https://attacker.example/failure",
        failure_url: "https://attacker.example/failure-snake",
        returnUrl: "https://attacker.example/return",
        return_url: "https://attacker.example/return-snake",
        session_id: "ps_provider",
        successUrl: "https://attacker.example/success",
        success_url: "https://attacker.example/success-snake",
      },
    });

    assert.equal(
      initiated.status,
      PaymentSessionStatus.PENDING_AUTHORIZATION ??
        PaymentSessionStatus.PENDING,
    );
    assert.equal(initiated.data.status, "pending_authorization");
    assert.equal(initiated.data.session_id, "ps_provider");
    assert.equal(initiated.data.fiat_currency, "USD");
    assert.ok(initiated.data.return_state);
    assert.deepEqual(initiated.data.next_action, {
      type: "redirect",
      url: initiated.data.public_url,
    });
    assert.equal(initiated.data.paymentLink, undefined);
    assert.equal(initiated.data.raw_response, undefined);
    assert.equal(initiated.data.customer_email, undefined);
    assert.equal(
      projections.get(initiated.id).company_id,
      "company_e2e_sandbox",
    );
    assert.equal(
      projections.get(initiated.id).customer_email,
      "guest@example.test",
    );
    assert.match(
      projections.get(initiated.id).return_state_hash,
      /^[a-f0-9]{64}$/,
    );

    const createRequest = contract.state.requests.find(
      (request) =>
        request.method === "POST" &&
        request.pathname.endsWith("/payment-links"),
    );
    assert.match(
      createRequest.idempotencyKey,
      /^medusa-makepay-create-[a-f0-9]{64}$/,
    );
    const remoteLink = contract.state.links.get(initiated.id);
    assert.equal(remoteLink.metadata.medusaInstallationId, undefined);
    assert.equal(remoteLink.metadata.medusaSessionId, "ps_provider");
    assert.match(
      createRequest.body.payload.returnUrl,
      /^https:\/\/api\.shop\.test\/makepay\/checkout\/return\?state=/,
    );
    assert.equal(
      createRequest.body.payload.successUrl,
      createRequest.body.payload.returnUrl,
    );
    assert.equal(
      createRequest.body.payload.failureUrl,
      createRequest.body.payload.returnUrl,
    );
    assert.equal(
      JSON.stringify(createRequest.body).includes("attacker.example"),
      false,
    );
    assert.equal(
      createRequest.body.payload.customerEmail,
      "guest@example.test",
    );

    const createCount = contract.state.requests.filter(
      (request) =>
        request.method === "POST" &&
        request.pathname.endsWith("/payment-links"),
    ).length;
    const repeated = await provider.initiatePayment({
      amount: { numeric: 12.34 },
      context: { idempotency_key: "idem_provider_repeat" },
      currency_code: "usd",
      data: initiated.data,
    });
    assert.equal(repeated.id, initiated.id);
    await assert.rejects(
      provider.initiatePayment({
        amount: { numeric: 12.35 },
        context: { idempotency_key: "idem_provider_reprice" },
        currency_code: "usd",
        data: initiated.data,
      }),
      /MakePay keeps one immutable payment-link UID per Medusa payment session\. Create a new payment session\./,
    );
    assert.equal(
      contract.state.requests.filter(
        (request) =>
          request.method === "POST" &&
          request.pathname.endsWith("/payment-links"),
      ).length,
      createCount,
    );

    remoteLink.payload.status = "complete";
    remoteLink.payload.type = "complete";
    remoteLink.payload.metadata.status = "complete";
    delete remoteLink.status;
    delete remoteLink.latestSession;
    const originalGetPaymentLink = provider.apiKeyClient_.getPaymentLink.bind(
      provider.apiKeyClient_,
    );
    provider.apiKeyClient_.getPaymentLink = async (uid) => ({
      ...(await originalGetPaymentLink(uid)),
      latestSession: { status: "complete" },
      session: { status: "complete" },
    });

    const missingAuthoritativeStatus = await provider.getPaymentStatus({
      data: initiated.data,
    });
    assert.equal(
      missingAuthoritativeStatus.status,
      PaymentSessionStatus.PENDING,
    );
    assert.equal(missingAuthoritativeStatus.data.status, "pending");

    remoteLink.status = "active";
    remoteLink.latestSession = { id: "mpses_provider", status: "pending" };
    const pendingStatus = await provider.getPaymentStatus({
      data: initiated.data,
    });
    assert.equal(pendingStatus.status, PaymentSessionStatus.PENDING);
    assert.equal(pendingStatus.data.status, "pending");

    const pendingAuthorization = await provider.authorizePayment({
      data: initiated.data,
    });
    assert.equal(
      pendingAuthorization.status,
      PaymentSessionStatus.PENDING_AUTHORIZATION,
    );
    assert.equal(pendingAuthorization.data.status, "pending");

    const pendingRetrieval = await provider.retrievePayment({
      data: initiated.data,
    });
    assert.equal(pendingRetrieval.data.status, "pending");
    await assert.rejects(
      provider.capturePayment({ data: initiated.data }),
      /not complete/i,
      "merchant payload status/type must not authorize capture",
    );

    remoteLink.status = "failed";
    remoteLink.latestSession = { id: "mpses_provider", status: "complete" };
    for (const operation of [
      () => provider.getPaymentStatus({ data: initiated.data }),
      () => provider.retrievePayment({ data: initiated.data }),
      () => provider.capturePayment({ data: initiated.data }),
    ]) {
      await assert.rejects(
        operation(),
        /conflicting authoritative terminal states/i,
      );
    }

    remoteLink.status = "active";
    remoteLink.latestSession = { id: "mpses_provider", status: "complete" };
    const captured = await provider.capturePayment({ data: initiated.data });
    assert.equal(captured.data.status, "captured");

    await assert.rejects(
      provider.refundPayment({ amount: 1, data: initiated.data }),
      (error) => {
        assert.equal(MedusaError.isMedusaError(error), true);
        assert.equal(error.type, MedusaError.Types.NOT_ALLOWED);
        assert.match(error.message, /refunds are not supported/i);
        return true;
      },
    );

    const webhookBody = JSON.stringify({
      createdAt: new Date().toISOString(),
      data: {},
      deliveryId: "delivery_provider",
      event: { trigger: null, type: "status_changed" },
      paymentLink: {
        amount: "12.34",
        currency: "USDT",
        merchantOrderId: remoteLink.payload.orderId,
        status: remoteLink.status,
        uid: initiated.id,
      },
      session: {
        id: remoteLink.latestSession.id,
        invoiceAmount: "12.34",
        status: "complete",
      },
      type: "makepay.payment.status_changed",
    });
    const webhook = await provider.getWebhookActionAndData({
      data: JSON.parse(webhookBody),
      headers: {
        "x-makepay-delivery-group-id": "delivery_group_provider",
        "x-makepay-signature": signature(webhookBody, contract.webhookSecret),
      },
      rawData: webhookBody,
    });
    assert.equal(webhook.action, PaymentActions.SUCCESSFUL);
    assert.equal(deliveries.length, 1);
    assert.equal(deliveries[0].amount, "12.34");
    assert.equal(deliveries[0].currency, "USD");
    assert.equal(deliveries[0].sessionId, "ps_provider");
    assert.equal(deliveries[0].uid, initiated.id);
    assert.match(deliveries[0].deliveryId, /^legacy_[a-f0-9]{64}$/);

    const retryWebhookBody = JSON.stringify({
      ...JSON.parse(webhookBody),
      attempt: 2,
      deliveryId: "delivery_attempt_2",
    });
    const retryWebhook = await provider.getWebhookActionAndData({
      data: JSON.parse(retryWebhookBody),
      headers: {
        "x-makepay-delivery-group-id": "delivery_group_provider",
        "x-makepay-signature": signature(
          retryWebhookBody,
          contract.webhookSecret,
        ),
      },
      rawData: retryWebhookBody,
    });
    assert.equal(retryWebhook.action, PaymentActions.SUCCESSFUL);
    assert.equal(deliveries.length, 2);
    assert.equal(deliveries[1].deliveryId, deliveries[0].deliveryId);
    assert.equal(deliveries[1].payloadHash, deliveries[0].payloadHash);

    const malformedV1Body = JSON.stringify({
      ...JSON.parse(webhookBody),
      schemaVersion: "medusa.v1",
    });
    const malformedV1 = await provider.getWebhookActionAndData({
      data: JSON.parse(malformedV1Body),
      headers: {
        "x-makepay-signature": signature(
          malformedV1Body,
          contract.webhookSecret,
        ),
      },
      rawData: malformedV1Body,
    });
    assert.equal(
      malformedV1.action,
      PaymentActions.NOT_SUPPORTED,
      "recognized v1 must never downgrade to the permissive legacy parser",
    );

    await assert.rejects(
      provider.getWebhookActionAndData({
        data: JSON.parse(webhookBody),
        headers: {
          "x-makepay-signature": signature(
            webhookBody,
            contract.webhookSecret,
            Math.floor(Date.now() / 1000) - 61,
          ),
        },
        rawData: webhookBody,
      }),
      /invalid.*signature/i,
    );
  } finally {
    await contract.close();
  }
});

test("API-key mode never accepts grant-scoped medusa.v1 webhook envelopes", async () => {
  const webhookSecret = "legacy_company_webhook_secret";
  let recordCalls = 0;
  const provider = new MakePayProviderService(
    {
      makepayIntegration: compatibleModule("api_key", {
        async recordWebhook() {
          recordCalls += 1;
          return "accepted";
        },
      }),
    },
    {
      authMode: "api_key",
      keyId: "key_legacy",
      keySecret: "secret_legacy",
      webhookSecret,
    },
  );
  const base = {
    companyId: "company_legacy",
    createdAt: new Date().toISOString(),
    deliveryGroupId: `mpwhgrp_${"c".repeat(64)}`,
    deliveryId: "delivery_legacy_v1",
    grantId: "grant_must_not_apply_to_api_key",
    installationId: "installation_must_not_apply_to_api_key",
    paymentLink: {
      fiatAmount: "12.34",
      fiatCurrency: "USD",
      metadata: {
        medusaOrderDisplayId: null,
        medusaOrderId: null,
        medusaProviderId: "makepay",
        medusaSessionId: "ps_legacy_v1",
      },
      uid: "link_legacy_v1",
    },
    schemaVersion: "medusa.v1",
    session: { id: "mpses_legacy_v1", settlement: null },
    subscriptionId: "subscription_must_not_apply_to_api_key",
    type: "makepay.payment.status_changed",
  };

  for (const status of ["complete", "failed", "cancelled"]) {
    const event = { ...base, status };
    const rawData = JSON.stringify(event);
    const result = await provider.getWebhookActionAndData({
      data: event,
      headers: {
        "x-makepay-delivery-group-id": event.deliveryGroupId,
        "x-makepay-delivery-id": event.deliveryId,
        "x-makepay-event": event.type,
        "x-makepay-signature": signature(rawData, webhookSecret),
      },
      rawData,
    });
    assert.equal(result.action, PaymentActions.NOT_SUPPORTED);
  }
  assert.equal(recordCalls, 0);
});

test("a captured 0.2 payment is recovered without running capture twice", async (t) => {
  const uid = "pay_legacy_migrated";
  const paymentSessionId = "payses_legacy_migrated";
  const makePaySessionId = "mpses_legacy_migrated";
  const merchantOrderId = "cart_legacy_migrated";
  const remoteResponse = {
    companyId: "company_legacy_migrated",
    paymentLink: {
      amount: "12.34",
      fiatAmount: "12.34",
      fiatCurrency: "USD",
      id: uid,
      latestSession: { id: makePaySessionId, status: "complete" },
      metadata: {
        medusaOrderDisplayId: null,
        medusaOrderId: null,
        medusaProviderId: "makepay",
        medusaSessionId: paymentSessionId,
      },
      orderId: merchantOrderId,
      payload: {
        amount: "12.34",
        currency: "USDT",
        fiatCurrency: "USD",
        metadata: {
          medusaOrderDisplayId: null,
          medusaOrderId: null,
          medusaProviderId: "makepay",
          medusaSessionId: paymentSessionId,
        },
        orderId: merchantOrderId,
      },
      publicUrl: `https://pay.makecrypto.test/payment/${uid}`,
      status: "active",
      uid,
    },
  };
  const historicalSessionData = {
    paymentLink: {
      ...remoteResponse.paymentLink,
      internal_debug_response: "legacy field must not be projected",
    },
    session_id: paymentSessionId,
  };
  let listPaymentsCalls = 0;
  const paymentModule = {
    async listPayments(filters, config) {
      listPaymentsCalls += 1;
      assert.deepEqual(filters, { payment_session_id: paymentSessionId });
      assert.deepEqual(config, { relations: ["captures"], take: 10 });
      return [
        {
          amount: "12.34",
          canceled_at: null,
          captured_amount: "12.34",
          captured_at: new Date(),
          captures: [{ amount: "12.34" }],
          currency_code: "USD",
          id: "pay_core_legacy_migrated",
          provider_id: "pp_makepay_makepay",
        },
      ];
    },
    async retrievePaymentSession(id) {
      assert.equal(id, paymentSessionId);
      return {
        amount: "12.34",
        currency_code: "USD",
        data: historicalSessionData,
        id: paymentSessionId,
        provider_id: "pp_makepay_makepay",
      };
    },
  };
  t.mock.method(MedusaModule, "getModuleInstance", (moduleName) =>
    moduleName === "payment" ? paymentModule : undefined,
  );

  let projection;
  let recordCalls = 0;
  const moduleService = compatibleModule("api_key", {
    async projectionBySession() {
      return undefined;
    },
    async projectionByUid() {
      return undefined;
    },
    async recordWebhook(_input, _applyTerminalFailure, findSuccessfulPayment) {
      recordCalls += 1;
      const captured = await findSuccessfulPayment();
      assert.deepEqual(captured, { paymentId: "pay_core_legacy_migrated" });
      return "duplicate";
    },
    async upsertProjection(input) {
      projection = { id: "mppay_legacy_migrated", ...input };
      return projection;
    },
  });
  const webhookSecret = "legacy-migration-webhook-secret";
  const provider = new MakePayProviderService(
    { makepayIntegration: moduleService },
    {
      authMode: "api_key",
      baseUrl: "https://api.makecrypto.test",
      checkoutBaseUrl: "https://pay.makecrypto.test",
      keyId: "legacy_key_id",
      keySecret: "legacy_key_secret",
      webhookSecret,
      webhookToleranceSeconds: 60,
    },
  );
  provider.apiKeyClient_.getPaymentLink = async () => remoteResponse;

  const rawBody = JSON.stringify({
    paymentLink: {
      amount: "12.34",
      currency: "USDT",
      merchantOrderId,
      status: "active",
      uid,
    },
    session: { id: makePaySessionId, status: "complete" },
    type: "makepay.payment.status_changed",
  });
  const action = await provider.getWebhookActionAndData({
    data: JSON.parse(rawBody),
    headers: {
      "x-makepay-signature": signature(rawBody, webhookSecret),
    },
    rawData: rawBody,
  });

  assert.equal(action.action, PaymentActions.NOT_SUPPORTED);
  assert.deepEqual(action.data, {
    amount: "12.34",
    session_id: paymentSessionId,
  });
  assert.equal(recordCalls, 1);
  assert.equal(listPaymentsCalls, 1);
  assert.equal(projection.auth_mode, "api_key");
  assert.equal(projection.payment_link_uid, uid);
  assert.equal(projection.session_id, paymentSessionId);
  assert.deepEqual(projection.metadata, { migrated_from: "0.2.x" });
  assert.equal(
    JSON.stringify(projection).includes("internal_debug_response"),
    false,
  );
});

test("API-key checkout preserves configured legacy return queries and ignores session overrides", async () => {
  const contract = createMakePayContractServer();
  await contract.start();
  try {
    const provider = new MakePayProviderService(
      {},
      {
        authMode: "api_key",
        baseUrl: contract.origin,
        checkoutBaseUrl: contract.origin,
        failureUrl: "https://shop.test/payment/failed?source=makepay",
        keyId: contract.apiKeyId,
        keySecret: contract.apiKeySecret,
        returnUrl: "https://shop.test/payment/return?source=makepay",
        successUrl: "https://shop.test/payment/success?source=makepay",
        webhookSecret: contract.webhookSecret,
      },
    );

    await provider.initiatePayment({
      amount: { numeric: 7.5 },
      context: { idempotency_key: "idem_legacy_return_urls" },
      currency_code: "usd",
      data: {
        failureUrl: "https://attacker.example/failure",
        failure_url: "https://attacker.example/failure-snake",
        returnUrl: "https://attacker.example/return",
        return_url: "https://attacker.example/return-snake",
        session_id: "ps_legacy_return_urls",
        successUrl: "https://attacker.example/success",
        success_url: "https://attacker.example/success-snake",
      },
    });

    const request = contract.state.requests
      .filter(
        (candidate) =>
          candidate.method === "POST" &&
          candidate.pathname.endsWith("/payment-links"),
      )
      .at(-1);
    assert.equal(
      request.body.payload.returnUrl,
      "https://shop.test/payment/return?source=makepay",
    );
    assert.equal(
      request.body.payload.successUrl,
      "https://shop.test/payment/success?source=makepay",
    );
    assert.equal(
      request.body.payload.failureUrl,
      "https://shop.test/payment/failed?source=makepay",
    );
    assert.equal(
      JSON.stringify(request.body).includes("attacker.example"),
      false,
    );
  } finally {
    await contract.close();
  }
});

test("provider-only API-key cancellation remains canceled after retrieval", async () => {
  const contract = createMakePayContractServer();
  await contract.start();
  try {
    const provider = new MakePayProviderService(
      {},
      {
        authMode: "api_key",
        baseUrl: contract.origin,
        checkoutBaseUrl: contract.origin,
        keyId: contract.apiKeyId,
        keySecret: contract.apiKeySecret,
        webhookSecret: contract.webhookSecret,
      },
    );
    const initiated = await provider.initiatePayment({
      amount: { numeric: 8.25 },
      context: { idempotency_key: "idem_provider_only_cancel" },
      currency_code: "usd",
      data: { session_id: "ps_provider_only_cancel" },
    });

    const canceled = await provider.cancelPayment({ data: initiated.data });
    assert.equal(canceled.data.status, "canceled");
    const retrieved = await provider.retrievePayment({ data: canceled.data });
    assert.equal(retrieved.data.status, "canceled");
    const status = await provider.getPaymentStatus({ data: canceled.data });
    assert.equal(status.status, PaymentSessionStatus.CANCELED);
  } finally {
    await contract.close();
  }
});

test("provider-only API-key retries reuse the immutable payment link", async () => {
  const contract = createMakePayContractServer();
  await contract.start();
  try {
    const provider = new MakePayProviderService(
      {},
      {
        authMode: "api_key",
        baseUrl: contract.origin,
        checkoutBaseUrl: contract.origin,
        keyId: contract.apiKeyId,
        keySecret: contract.apiKeySecret,
        webhookSecret: contract.webhookSecret,
      },
    );
    const initiated = await provider.initiatePayment({
      amount: { numeric: 8.25 },
      context: { idempotency_key: "idem_provider_only_retry" },
      currency_code: "usd",
      data: { session_id: "ps_provider_only_retry" },
    });
    const retried = await provider.initiatePayment({
      amount: { numeric: 8.25 },
      context: { idempotency_key: "idem_provider_only_retry" },
      currency_code: "usd",
      data: initiated.data,
    });

    assert.equal(retried.id, initiated.id);
    assert.equal(
      retried.status,
      PaymentSessionStatus.PENDING_AUTHORIZATION,
    );
    assert.equal(retried.data.return_state, initiated.data.return_state);
    assert.equal(
      contract.state.requests.filter(
        (request) =>
          request.method === "POST" &&
          request.pathname.endsWith("/payment-links"),
      ).length,
      1,
    );

    await assert.rejects(
      provider.initiatePayment({
        amount: { numeric: 8.26 },
        context: { idempotency_key: "idem_provider_only_retry" },
        currency_code: "usd",
        data: initiated.data,
      }),
      /correlation failed/i,
    );
    assert.equal(
      contract.state.requests.filter(
        (request) =>
          request.method === "POST" &&
          request.pathname.endsWith("/payment-links"),
      ).length,
      1,
    );
  } finally {
    await contract.close();
  }
});

test("funded in-flight links cannot be canceled or repriced", async () => {
  const contract = createMakePayContractServer();
  await contract.start();
  try {
    const provider = new MakePayProviderService(
      {},
      {
        authMode: "api_key",
        baseUrl: contract.origin,
        checkoutBaseUrl: contract.origin,
        keyId: contract.apiKeyId,
        keySecret: contract.apiKeySecret,
        webhookSecret: contract.webhookSecret,
      },
    );
    const initiated = await provider.initiatePayment({
      amount: { numeric: 12.34 },
      context: { idempotency_key: "idem_funded_mutation_guard" },
      currency_code: "usd",
      data: { session_id: "ps_funded_mutation_guard" },
    });
    const remoteLink = contract.state.links.get(initiated.id);
    const initialCreates = contract.state.requests.filter(
      (request) =>
        request.method === "POST" &&
        request.pathname.endsWith("/payment-links"),
    ).length;

    for (const providerStatus of [
      "deposit_received",
      "swapping",
      "sending",
      "underpaid",
    ]) {
      remoteLink.status = "active";
      remoteLink.latestSession = {
        id: `mpses_${providerStatus}`,
        status: providerStatus,
      };
      await assert.rejects(
        provider.cancelPayment({ data: initiated.data }),
        /funds may have entered processing/i,
        providerStatus,
      );
      await assert.rejects(
        provider.updatePayment({
          amount: { numeric: 13.34 },
          context: {
            idempotency_key: `idem_reprice_${providerStatus}`,
          },
          currency_code: "usd",
          data: initiated.data,
        }),
        /cannot reprice an issued payment link/i,
        providerStatus,
      );
    }

    assert.equal(
      contract.state.requests.some(
        (request) =>
          request.method === "PATCH" &&
          request.pathname.endsWith(`/payment-links/${initiated.id}`),
      ),
      false,
    );
    assert.equal(
      contract.state.requests.filter(
        (request) =>
          request.method === "POST" &&
          request.pathname.endsWith("/payment-links"),
      ).length,
      initialCreates,
    );

    remoteLink.status = "active";
    remoteLink.latestSession = {
      id: "mpses_late_complete",
      status: "complete",
    };
    const lateStatus = await provider.getPaymentStatus({
      data: initiated.data,
    });
    assert.equal(lateStatus.status, PaymentSessionStatus.CAPTURED);
    const lateCapture = await provider.capturePayment({
      data: initiated.data,
    });
    assert.equal(lateCapture.data.status, "captured");
  } finally {
    await contract.close();
  }
});

test("OAuth provider refuses to start without the integration module", () => {
  assert.throws(
    () =>
      new MakePayProviderService(
        {},
        {
          authMode: "oauth",
          backendUrl: "https://api.shop.test",
          encryptionKey: Buffer.alloc(32, 2).toString("base64"),
          lockingProvider: "makepay-postgres",
          storefrontReturnUrl: "https://shop.test/order/makepay-return",
        },
      ),
    /makepayIntegration.*module/i,
  );
});

test("OAuth provider falls back to the global module when its Awilix cradle throws", async (t) => {
  let childLookupCount = 0;
  let projection;
  let fallbackResponse;
  const moduleService = compatibleModule("oauth", {
    async createClient() {
      return {
        async createPaymentLink(payload) {
          fallbackResponse = {
            companyId: "company_fallback",
            paymentLink: {
              amount: payload.amount,
              fiatCurrency: payload.fiatCurrency,
              metadata: payload.metadata,
              publicUrl: "https://pay.makecrypto.test/payment/link_fallback",
              status: "active",
              uid: "link_fallback",
            },
          };
          return fallbackResponse;
        },
        async getPaymentLink() {
          return fallbackResponse;
        },
      };
    },
    async getInstallationContext() {
      return {
        companyId: "company_fallback",
        grantId: "grant_fallback",
        installationId: "installation_fallback",
        webhookSubscriptionId: "subscription_fallback",
      };
    },
    async upsertProjection(value) {
      projection = value;
      return value;
    },
  });
  const globalLookups = [];
  t.mock.method(MedusaModule, "getModuleInstance", (moduleName) => {
    globalLookups.push(moduleName);
    return moduleName === MAKEPAY_MODULE ? moduleService : undefined;
  });
  const throwingCradle = new Proxy(
    {},
    {
      get(_target, property) {
        if (property === MAKEPAY_MODULE) {
          childLookupCount += 1;
          const error = new Error(`Could not resolve '${String(property)}'.`);
          error.name = "AwilixResolutionError";
          throw error;
        }
        return undefined;
      },
    },
  );
  const provider = new MakePayProviderService(throwingCradle, {
    authMode: "oauth",
    backendUrl: "https://api.shop.test",
    encryptionKey: Buffer.alloc(32, 2).toString("base64"),
    lockingProvider: "makepay-postgres",
    checkoutBaseUrl: "https://pay.makecrypto.test",
    storefrontReturnUrl: "https://shop.test/order/makepay-return",
  });

  const initiated = await provider.initiatePayment({
    amount: { numeric: 12.34 },
    context: { idempotency_key: "idem_global_fallback" },
    currency_code: "usd",
    data: { session_id: "ps_global_fallback" },
  });

  assert.equal(initiated.id, "link_fallback");
  assert.equal(projection.payment_link_uid, "link_fallback");
  assert.ok(childLookupCount >= 1);
  assert.ok(globalLookups.length >= 1);
  assert.ok(globalLookups.every((moduleName) => moduleName === MAKEPAY_MODULE));
});

test("OAuth completion fast path requires the exact synchronous webhook authority", async () => {
  const data = {
    amount: "12.34",
    fiat_currency: "USD",
    payment_link_uid: "link_authority",
    public_url: "https://pay.makecrypto.test/payment/link_authority",
    session_id: "ps_authority",
    status: "pending_authorization",
  };
  const projection = {
    amount: "12.34",
    auth_mode: "oauth",
    company_id: "company_authority",
    currency: "USD",
    grant_id: "grant_authority",
    installation_id: "installation_authority",
    payment_link_uid: "link_authority",
    provider_id: "makepay",
    provider_status: "complete",
    session_id: "ps_authority",
    webhook_subscription_id: "subscription_authority",
  };
  let authority = false;
  let remoteReads = 0;
  let installationContext = {
    companyId: projection.company_id,
    grantId: projection.grant_id,
    installationId: projection.installation_id,
    webhookSubscriptionId: projection.webhook_subscription_id,
  };
  const moduleService = compatibleModule("oauth", {
    async createClient() {
      return {
        async getPaymentLink() {
          remoteReads += 1;
          return {
            companyId: projection.company_id,
            paymentLink: {
              fiatAmount: projection.amount,
              fiatCurrency: projection.currency,
              latestSession: { id: "mpses_authority", status: "complete" },
              metadata: {
                medusaOrderDisplayId: null,
                medusaOrderId: null,
                medusaProviderId: "makepay",
                medusaSessionId: projection.session_id,
              },
              status: "active",
              uid: projection.payment_link_uid,
            },
          };
        },
      };
    },
    async getInstallationContext() {
      return installationContext;
    },
    hasSynchronousWebhookAuthority(input) {
      return (
        authority &&
        input.paymentLinkUid === projection.payment_link_uid &&
        input.sessionId === projection.session_id &&
        String(input.amount) === projection.amount &&
        input.currency === projection.currency
      );
    },
    async projectionByUid() {
      return projection;
    },
    async reconcileProjectionFromResponse() {
      return projection;
    },
  });
  const provider = new MakePayProviderService(
    { makepayIntegration: moduleService },
    {
      authMode: "oauth",
      backendUrl: "https://api.shop.test",
      encryptionKey: Buffer.alloc(32, 2).toString("base64"),
      lockingProvider: "makepay-postgres",
      storefrontReturnUrl: "https://shop.test/order/makepay-return",
    },
  );

  const outside = await provider.authorizePayment({ data });
  assert.equal(outside.status, PaymentSessionStatus.CAPTURED);
  assert.equal(remoteReads, 1, "outside the capability must read MakePay");

  authority = true;
  installationContext = {
    ...installationContext,
    grantId: "grant_reconnected",
    webhookSubscriptionId: "subscription_reconnected",
  };
  const inside = await provider.capturePayment({ data });
  assert.equal(inside.data.status, "captured");
  assert.equal(remoteReads, 1, "the exact capability may use the projection");

  for (const mismatch of [
    { payment_link_uid: "link_other" },
    { session_id: "ps_other" },
    { amount: "12.35" },
    { fiat_currency: "EUR" },
  ]) {
    await assert.rejects(
      provider.capturePayment({ data: { ...data, ...mismatch } }),
      /connection changed|correlation|not found/i,
    );
  }
  assert.equal(remoteReads, 1);
});

test("completion fast path checks the provider/module security handshake", async () => {
  const moduleService = compatibleModule("oauth", {
    hasSynchronousWebhookAuthority() {
      return true;
    },
  });
  const provider = new MakePayProviderService(
    { makepayIntegration: moduleService },
    {
      authMode: "oauth",
      backendUrl: "https://api.shop.test",
      encryptionKey: Buffer.alloc(32, 2).toString("base64"),
      lockingProvider: "makepay-postgres",
      storefrontReturnUrl: "https://shop.test/order/makepay-return",
    },
  );
  moduleService.providerId = "different-provider";
  const data = {
    amount: "12.34",
    fiat_currency: "USD",
    payment_link_uid: "link_mismatch",
    session_id: "ps_mismatch",
  };
  await assert.rejects(
    provider.authorizePayment({ data }),
    /configuration do not match/i,
  );
  await assert.rejects(
    provider.capturePayment({ data }),
    /configuration do not match/i,
  );
});

test("OAuth checkout requires a complete, stable installation routing tuple", async () => {
  const completeContext = {
    companyId: "company_oauth",
    grantId: "grant_oauth",
    installationId: "installation_oauth",
    webhookSubscriptionId: "subscription_oauth",
  };
  const input = {
    amount: { numeric: 12.34 },
    context: { idempotency_key: "idem_oauth_race" },
    currency_code: "usd",
    data: { session_id: "ps_oauth_race" },
  };
  const options = {
    authMode: "oauth",
    backendUrl: "https://api.shop.test",
    checkoutBaseUrl: "https://pay.makecrypto.test",
    encryptionKey: Buffer.alloc(32, 2).toString("base64"),
    lockingProvider: "makepay-postgres",
    storefrontReturnUrl: "https://shop.test/order/makepay-return",
  };

  for (const missingKey of Object.keys(completeContext)) {
    let createCalls = 0;
    const incompleteContext = { ...completeContext };
    delete incompleteContext[missingKey];
    const provider = new MakePayProviderService(
      {
        makepayIntegration: compatibleModule("oauth", {
          async createClient() {
            createCalls += 1;
            throw new Error("payment link creation must not be reached");
          },
          async getInstallationContext() {
            return incompleteContext;
          },
        }),
      },
      options,
    );

    await assert.rejects(
      provider.initiatePayment(input),
      /healthy grant-scoped webhook subscription/i,
    );
    assert.equal(createCalls, 0, `created a link without ${missingKey}`);
  }

  const contexts = [
    completeContext,
    { ...completeContext, grantId: "grant_reconnected" },
  ];
  let projectionWrites = 0;
  let raceResponse;
  const raceProvider = new MakePayProviderService(
    {
      makepayIntegration: compatibleModule("oauth", {
        async createClient() {
          return {
            async createPaymentLink(payload) {
              raceResponse = {
                companyId: "company_oauth",
                paymentLink: {
                  amount: payload.amount,
                  fiatCurrency: payload.fiatCurrency,
                  metadata: payload.metadata,
                  publicUrl: "https://pay.makecrypto.test/payment/link_race",
                  status: "active",
                  uid: "link_race",
                },
              };
              return raceResponse;
            },
            async getPaymentLink() {
              return raceResponse;
            },
          };
        },
        async getInstallationContext() {
          return contexts.shift();
        },
        async upsertProjection() {
          projectionWrites += 1;
        },
      }),
    },
    options,
  );

  await assert.rejects(
    raceProvider.initiatePayment(input),
    /connection changed while checkout was being created/i,
  );
  assert.equal(projectionWrites, 0);
});

test("OAuth webhooks require the exact medusa.v1 envelope and grant routing", async () => {
  const webhookSecret = "oauth-webhook-secret";
  const recorded = [];
  const projection = {
    amount: "12.34",
    company_id: "company_oauth",
    currency: "USD",
    grant_id: "grant_oauth",
    installation_id: "installation_oauth",
    order_display_id: null,
    order_id: null,
    payment_link_uid: "link_oauth",
    session_id: "ps_oauth",
    webhook_subscription_id: "subscription_oauth",
  };
  let installationContext = {
    companyId: "company_oauth",
    grantId: "grant_oauth",
    installationId: "installation_oauth",
    webhookSubscriptionId: "subscription_oauth",
  };
  let recordResult = "accepted";
  const moduleService = compatibleModule("oauth", {
    async getInstallationContext() {
      return installationContext;
    },
    async getWebhookSecret() {
      return webhookSecret;
    },
    async projectionByUid(uid) {
      return uid === projection.payment_link_uid ? projection : undefined;
    },
    async recordWebhook(input) {
      recorded.push(input);
      return recordResult;
    },
  });
  const provider = new MakePayProviderService(
    { makepayIntegration: moduleService },
    {
      authMode: "oauth",
      backendUrl: "https://api.shop.test",
      encryptionKey: Buffer.alloc(32, 2).toString("base64"),
      lockingProvider: "makepay-postgres",
      storefrontReturnUrl: "https://shop.test/order/makepay-return",
      webhookToleranceSeconds: 60,
    },
  );
  const canonicalEvent = {
    schemaVersion: "medusa.v1",
    deliveryId: "delivery_oauth_attempt_1",
    deliveryGroupId: `mpwhgrp_${"a".repeat(64)}`,
    type: "makepay.payment.status_changed",
    createdAt: new Date().toISOString(),
    status: "complete",
    companyId: "company_oauth",
    grantId: "grant_oauth",
    subscriptionId: "subscription_oauth",
    installationId: "installation_oauth",
    paymentLink: {
      uid: "link_oauth",
      fiatAmount: "12.34",
      fiatCurrency: "USD",
      metadata: {
        medusaSessionId: "ps_oauth",
        medusaOrderId: null,
        medusaOrderDisplayId: null,
        medusaProviderId: "makepay",
      },
    },
    // This is MakePay's remote session ID. It must never replace the Medusa
    // payment-session ID carried in the immutable link metadata.
    session: {
      id: "makepay_remote_session",
      settlement: {
        classification: "matched",
        phase: "sent",
        settledAmount: "12.34",
        settledAsset: "USDT",
      },
    },
  };

  async function deliver(
    event,
    deliveryGroupId = event.deliveryGroupId,
    headerOverrides = {},
  ) {
    const rawBody = JSON.stringify(event);
    return provider.getWebhookActionAndData({
      data: event,
      headers: {
        "x-makepay-delivery-id": event.deliveryId,
        "x-makepay-delivery-group-id": deliveryGroupId,
        "x-makepay-event": event.type,
        "x-makepay-signature": signature(rawBody, webhookSecret),
        ...headerOverrides,
      },
      rawData: rawBody,
    });
  }

  const accepted = await deliver(canonicalEvent);
  assert.equal(accepted.action, PaymentActions.SUCCESSFUL);
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0].sessionId, "ps_oauth");
  assert.notEqual(recorded[0].sessionId, canonicalEvent.session.id);
  assert.equal(recorded[0].companyId, "company_oauth");
  assert.equal(recorded[0].grantId, "grant_oauth");
  assert.equal(recorded[0].installationId, "installation_oauth");
  assert.equal(recorded[0].subscriptionId, "subscription_oauth");
  assert.equal(recorded[0].deliveryId, canonicalEvent.deliveryGroupId);

  recordResult = "duplicate";
  const durableDuplicate = await deliver(canonicalEvent);
  assert.equal(
    durableDuplicate.action,
    PaymentActions.NOT_SUPPORTED,
    "a valid durable duplicate must not rerun the workflow",
  );
  assert.equal(durableDuplicate.data.session_id, "ps_oauth");
  assert.equal(String(durableDuplicate.data.amount), "12.34");
  for (const [index, status] of ["failed", "cancelled"].entries()) {
    const terminalDuplicate = await deliver({
      ...canonicalEvent,
      deliveryGroupId: `mpwhgrp_${String(index + 11).padStart(64, "a")}`,
      deliveryId: `delivery_terminal_duplicate_${index}`,
      status,
    });
    assert.equal(terminalDuplicate.action, PaymentActions.NOT_SUPPORTED);
    assert.equal(terminalDuplicate.data.session_id, "ps_oauth");
    assert.equal(String(terminalDuplicate.data.amount), "12.34");
  }
  recordResult = "accepted";

  const malformedEvents = [
    {
      ...canonicalEvent,
      paymentLink: {
        ...canonicalEvent.paymentLink,
        metadata: {
          ...canonicalEvent.paymentLink.metadata,
          unexpected: "must-fail-closed",
        },
      },
    },
    { ...canonicalEvent, grantId: "grant_wrong" },
    { ...canonicalEvent, subscriptionId: "subscription_wrong" },
    {
      ...canonicalEvent,
      status: "failed",
      session: {
        ...canonicalEvent.session,
        status: "complete",
      },
    },
    {
      ...canonicalEvent,
      session: {
        ...canonicalEvent.session,
        settlement: {
          classification: "matched",
          phase: "sent",
          settledAmount: "12.34",
          settledAsset: "USDT",
          unexpected: "must-fail-closed",
        },
      },
    },
  ];
  for (const event of malformedEvents) {
    assert.equal((await deliver(event)).action, PaymentActions.NOT_SUPPORTED);
  }
  assert.equal(
    (await deliver(canonicalEvent, "delivery_group_wrong")).action,
    PaymentActions.NOT_SUPPORTED,
  );
  assert.equal(
    (
      await deliver(canonicalEvent, canonicalEvent.deliveryGroupId, {
        "x-makepay-delivery-id": "delivery_wrong",
      })
    ).action,
    PaymentActions.NOT_SUPPORTED,
  );
  assert.equal(
    (
      await deliver(canonicalEvent, canonicalEvent.deliveryGroupId, {
        "x-makepay-event": "status_changed",
      })
    ).action,
    PaymentActions.NOT_SUPPORTED,
  );
  installationContext = {
    ...installationContext,
    grantId: "grant_reconnected",
  };
  assert.equal(
    (await deliver(canonicalEvent)).action,
    PaymentActions.SUCCESSFUL,
  );
  installationContext = {
    ...installationContext,
    grantId: "grant_oauth",
  };

  const correlatedAt = new Date();
  projection.created_at = new Date(correlatedAt.getTime() - 10_000);
  projection.order_id = "order_correlated";
  projection.order_display_id = "1042";
  projection.order_correlated_at = correlatedAt;
  const prepatchWithPositiveSkew = {
    ...canonicalEvent,
    createdAt: new Date(correlatedAt.getTime() + 30_000).toISOString(),
    deliveryGroupId: `mpwhgrp_${"d".repeat(64)}`,
    deliveryId: "delivery_prepatch_order",
  };
  assert.equal(
    (await deliver(prepatchWithPositiveSkew)).action,
    PaymentActions.SUCCESSFUL,
    "a signed snapshot created just before correlation survives bounded clock skew",
  );
  assert.equal(recorded.at(-1).createdAt, prepatchWithPositiveSkew.createdAt);
  assert.equal(
    (
      await deliver({
        ...prepatchWithPositiveSkew,
        createdAt: new Date(correlatedAt.getTime() + 61_000).toISOString(),
        deliveryGroupId: `mpwhgrp_${"e".repeat(64)}`,
        deliveryId: "delivery_after_order_correlation",
      })
    ).action,
    PaymentActions.NOT_SUPPORTED,
  );
  assert.equal(
    (
      await deliver({
        ...prepatchWithPositiveSkew,
        createdAt: new Date(
          projection.created_at.getTime() - 61_000,
        ).toISOString(),
        deliveryGroupId: `mpwhgrp_${"1".repeat(64)}`,
        deliveryId: "delivery_before_payment_lifecycle",
      })
    ).action,
    PaymentActions.NOT_SUPPORTED,
  );
  for (const metadata of [
    {
      ...canonicalEvent.paymentLink.metadata,
      medusaOrderId: "order_wrong",
    },
    {
      ...canonicalEvent.paymentLink.metadata,
      medusaOrderDisplayId: "9999",
      medusaOrderId: "order_correlated",
    },
  ]) {
    assert.equal(
      (
        await deliver({
          ...prepatchWithPositiveSkew,
          deliveryGroupId: `mpwhgrp_${"f".repeat(64)}`,
          deliveryId: `delivery_wrong_order_${metadata.medusaOrderId}_${metadata.medusaOrderDisplayId}`,
          paymentLink: { ...canonicalEvent.paymentLink, metadata },
        })
      ).action,
      PaymentActions.NOT_SUPPORTED,
    );
  }

  for (const status of [
    "authorized",
    "requires_capture",
    "refunded",
    "error",
    "declined",
    "canceled",
  ]) {
    assert.equal(
      (await deliver({ ...canonicalEvent, status })).action,
      PaymentActions.NOT_SUPPORTED,
      `unexpected OAuth webhook status was accepted: ${status}`,
    );
  }
  assert.equal(recorded.length, 6);
});

test("provider and plugin module require one exact security configuration", async () => {
  const apiOptions = {
    authMode: "api_key",
    backendUrl: "https://api.shop.test",
    baseUrl: "https://api.makecrypto.test",
    checkoutBaseUrl: "https://pay.shop.test",
    keyId: "key_exact",
    keySecret: "secret_exact",
    lockingProvider: "makepay-postgres",
    storefrontReturnUrl: "https://shop.test/payment/return",
    webhookSecret: "webhook_exact",
  };
  const matchingApiModule = actualModule({ ...apiOptions });
  new MakePayProviderService(
    { makepayIntegration: matchingApiModule },
    apiOptions,
  );
  assert.equal(matchingApiModule.providerConfigurationRegistered_, true);
  assert.equal(await matchingApiModule.getWebhookSecret(), "webhook_exact");

  for (const mismatch of [
    { keyId: "key_other" },
    { keySecret: "secret_other" },
    { webhookSecret: "webhook_other" },
    { baseUrl: "https://api-other.makecrypto.test" },
    { checkoutBaseUrl: "https://pay-other.shop.test" },
    { backendUrl: "https://api-other.shop.test" },
    { storefrontReturnUrl: "https://shop.test/other-return" },
    { lockingProvider: "makepay-other-postgres" },
  ]) {
    const module = actualModule({ ...apiOptions, ...mismatch });
    assert.throws(
      () =>
        new MakePayProviderService({ makepayIntegration: module }, apiOptions),
      /configuration do not match/i,
    );
    assert.equal(module.providerConfigurationRegistered_, false);
  }

  const oauthOptions = {
    authMode: "oauth",
    backendUrl: "https://api.shop.test",
    checkoutBaseUrl: "https://pay.shop.test",
    encryptionKey: Buffer.alloc(32, 7).toString("base64"),
    lockingProvider: "makepay-postgres",
    oauthApiUrl: "https://api.makecrypto.test",
    oauthAudience: "https://issuer.makecrypto.test/api/partner/v1",
    oauthIssuerUrl: "https://issuer.makecrypto.test",
    storefrontReturnUrl: "https://shop.test/payment/return",
  };
  const matchingOAuthModule = actualModule({ ...oauthOptions });
  new MakePayProviderService(
    { makepayIntegration: matchingOAuthModule },
    oauthOptions,
  );
  assert.equal(matchingOAuthModule.providerConfigurationRegistered_, true);

  for (const mismatch of [
    {
      authMode: "api_key",
      keyId: "key",
      keySecret: "secret",
      webhookSecret: "webhook",
    },
    { encryptionKey: Buffer.alloc(32, 8).toString("base64") },
    { oauthIssuerUrl: "https://issuer-other.makecrypto.test" },
    { oauthApiUrl: "https://api-other.makecrypto.test" },
    { oauthAudience: "https://issuer.makecrypto.test/other" },
    { checkoutBaseUrl: "https://pay-other.shop.test" },
    { backendUrl: "https://api-other.shop.test" },
    { storefrontReturnUrl: "https://shop.test/other-return" },
    { lockingProvider: "makepay-other-postgres" },
  ]) {
    const module = actualModule({ ...oauthOptions, ...mismatch });
    assert.throws(
      () =>
        new MakePayProviderService(
          { makepayIntegration: module },
          oauthOptions,
        ),
      /configuration do not match/i,
    );
    assert.equal(module.providerConfigurationRegistered_, false);
  }
});

test("Admin OAuth lazily resolves the configured provider before its first checkout", async (t) => {
  const options = {
    authMode: "oauth",
    backendUrl: "https://lazy-api.shop.test",
    checkoutBaseUrl: "https://lazy-pay.shop.test",
    encryptionKey: Buffer.alloc(32, 11).toString("base64"),
    lockingProvider: "makepay-postgres",
    oauthApiUrl: "https://lazy-api.makecrypto.test",
    oauthAudience: "https://lazy-issuer.makecrypto.test/api/partner/v1",
    oauthIssuerUrl: "https://lazy-issuer.makecrypto.test",
    storefrontReturnUrl: "https://lazy-shop.test/payment/return",
  };
  const moduleService = actualModule(options);
  const fingerprint = makePaySecurityConfigurationFingerprint(options);
  Reflect.get(
    globalThis,
    Symbol.for(
      "@makecrypto/medusa-plugin-makepay/registered-provider-configurations",
    ),
  )?.delete(fingerprint);
  let providerResolutions = 0;
  t.mock.method(MedusaModule, "getModuleInstance", (moduleName) =>
    moduleName === Modules.PAYMENT
      ? {
          async listPaymentMethods(filters) {
            providerResolutions += 1;
            assert.deepEqual(filters, {
              context: {},
              provider_id: "pp_makepay_makepay",
            });
            new MakePayProviderService(
              { makepayIntegration: moduleService },
              options,
            );
            return [];
          },
        }
      : undefined,
  );

  await moduleService.assertProviderConfigurationRegistered();
  assert.equal(providerResolutions, 1);
  assert.equal(moduleService.providerConfigurationRegistered_, true);
});

test("Admin OAuth rejects a stale global fingerprint without a current payment module", async (t) => {
  const options = {
    authMode: "oauth",
    backendUrl: "https://stale-api.shop.test",
    checkoutBaseUrl: "https://stale-pay.shop.test",
    encryptionKey: Buffer.alloc(32, 12).toString("base64"),
    lockingProvider: "makepay-postgres",
    oauthApiUrl: "https://stale-api.makecrypto.test",
    oauthAudience: "https://stale-issuer.makecrypto.test/api/partner/v1",
    oauthIssuerUrl: "https://stale-issuer.makecrypto.test",
    storefrontReturnUrl: "https://stale-shop.test/payment/return",
  };
  const moduleService = actualModule(options);
  const fingerprint = makePaySecurityConfigurationFingerprint(options);
  Reflect.get(
    globalThis,
    Symbol.for(
      "@makecrypto/medusa-plugin-makepay/registered-provider-configurations",
    ),
  )?.add(fingerprint);
  t.mock.method(MedusaModule, "getModuleInstance", () => undefined);

  await assert.rejects(
    () => moduleService.assertProviderConfigurationRegistered(),
    /does not match a registered payment provider/i,
  );
  assert.equal(moduleService.providerConfigurationRegistered_, false);
});

test("Admin OAuth rejects a stale matching fingerprint when the current provider configuration differs", async (t) => {
  const options = {
    authMode: "oauth",
    backendUrl: "https://mismatch-api.shop.test",
    checkoutBaseUrl: "https://mismatch-pay.shop.test",
    encryptionKey: Buffer.alloc(32, 13).toString("base64"),
    lockingProvider: "makepay-postgres",
    oauthApiUrl: "https://mismatch-api.makecrypto.test",
    oauthAudience: "https://mismatch-issuer.makecrypto.test/api/partner/v1",
    oauthIssuerUrl: "https://mismatch-issuer.makecrypto.test",
    storefrontReturnUrl: "https://mismatch-shop.test/payment/return",
  };
  const moduleService = actualModule(options);
  const fingerprint = makePaySecurityConfigurationFingerprint(options);
  Reflect.get(
    globalThis,
    Symbol.for(
      "@makecrypto/medusa-plugin-makepay/registered-provider-configurations",
    ),
  )?.add(fingerprint);
  t.mock.method(MedusaModule, "getModuleInstance", (moduleName) =>
    moduleName === Modules.PAYMENT
      ? {
          async listPaymentMethods() {
            new MakePayProviderService(
              { makepayIntegration: moduleService },
              {
                ...options,
                oauthAudience:
                  "https://different-issuer.makecrypto.test/api/partner/v1",
              },
            );
            return [];
          },
        }
      : undefined,
  );

  await assert.rejects(
    () => moduleService.assertProviderConfigurationRegistered(),
    /configuration do not match/i,
  );
  assert.equal(moduleService.providerConfigurationRegistered_, false);
});
