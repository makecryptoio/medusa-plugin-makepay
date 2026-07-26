import assert from "node:assert/strict";
import test from "node:test";

import { MedusaError } from "@medusajs/framework/utils";

import { GET as checkoutReturn } from "../src/api/makepay/checkout/return/route.ts";
import { GET as checkoutStatus } from "../src/api/store/makepay/checkout-status/route.ts";
import { MAKEPAY_MODULE } from "../src/modules/makepay/constants.ts";
import MakePayModuleService from "../src/modules/makepay/service.ts";

function webhookHarness(initialProjection) {
  let projection = {
    auth_mode: "oauth",
    company_id: "company_1",
    grant_id: "grant_1",
    installation_id: "installation_1",
    provider_id: "makepay",
    webhook_subscription_id: "subscription_1",
    ...initialProjection,
  };
  const deliveries = [];
  const lockCalls = [];
  const rowLocks = [];
  const service = Object.create(MakePayModuleService.prototype);
  service.providerConfigurationRegistered_ = true;

  service.options_ = {
    authMode: "oauth",
    lockingProvider: "makepay-postgres",
  };
  service.lockingService = () => ({
    execute: async (key, job, options) => {
      lockCalls.push({ key, options });
      return job();
    },
  });
  service.baseRepository_ = {
    transaction: async (job) =>
      job({
        execute: async (sql, parameters) => {
          rowLocks.push({ parameters, sql });
        },
        id: "transaction_test",
      }),
  };
  service.generated = () => ({
    createMakePayWebhookDeliveries: async (delivery) => {
      if (
        deliveries.some((entry) => entry.delivery_id === delivery.delivery_id)
      ) {
        throw new Error("unique delivery");
      }
      deliveries.push({ ...delivery });
      return delivery;
    },
    listMakePayWebhookDeliveries: async ({ delivery_id }) =>
      deliveries.filter((entry) => entry.delivery_id === delivery_id),
    listMakePayPaymentProjections: async ({ payment_link_uid }) =>
      projection.payment_link_uid === payment_link_uid ? [projection] : [],
    updateMakePayPaymentProjections: async (update) => {
      projection = { ...projection, ...update };
      return projection;
    },
  });

  return {
    deliveries,
    lockCalls,
    projection: () => projection,
    rowLocks,
    service,
  };
}

const validWebhook = {
  amount: "12.34",
  companyId: "company_1",
  currency: "USD",
  deliveryId: "delivery_1",
  eventType: "makepay.payment.status_changed",
  grantId: "grant_1",
  installationId: "installation_1",
  payloadHash: "payload_hash",
  providerStatus: "complete",
  sessionId: "ps_1",
  subscriptionId: "subscription_1",
  uid: "pay_1",
};

test("webhook deliveries are correlated and processed exactly once", async () => {
  const harness = webhookHarness({
    amount: "12.34",
    currency: "USD",
    id: "projection_1",
    payment_link_uid: "pay_1",
    provider_status: "pending",
    session_id: "ps_1",
  });

  assert.equal(await harness.service.recordWebhook(validWebhook), "accepted");
  assert.equal(
    await harness.service.recordWebhook(
      validWebhook,
      undefined,
      async () => false,
    ),
    "in_progress",
  );
  assert.equal(harness.deliveries.length, 1);
  assert.equal(harness.projection().provider_status, "complete");
  assert.equal(harness.projection().medusa_status, "processing");
  assert.equal(
    await harness.service.recordWebhook(validWebhook, undefined, async () => ({
      paymentId: "pay_core_1",
    })),
    "duplicate",
  );
  assert.equal(harness.projection().medusa_status, "paid");
  assert.equal(harness.lockCalls.length, 3);
  assert.deepEqual(harness.lockCalls[0], {
    key: "makepay-payment-effects:6ec81111d581d10d7725c768ec7408574fb3bc895f76ec93e678dd3d469db8cf",
    options: { provider: "makepay-postgres", timeout: 30 },
  });
  assert.equal(harness.rowLocks.length, 4);
  assert.match(harness.rowLocks[0].sql, /FOR UPDATE/);
});

test("successful webhook authority is exact, synchronous, and cannot escape its delivery callback", async () => {
  const harness = webhookHarness({
    amount: "12.34",
    currency: "USD",
    id: "projection_authority",
    payment_link_uid: "pay_1",
    provider_status: "pending",
    session_id: "ps_1",
  });
  const deliveryGroupId = `mpwhgrp_${"b".repeat(64)}`;
  const exact = {
    amount: "12.34",
    currency: "USD",
    paymentLinkUid: "pay_1",
    sessionId: "ps_1",
  };

  assert.equal(harness.service.hasSynchronousWebhookAuthority(exact), false);
  await harness.service.withWebhookDeliveryLock(
    { deliveryGroupId, paymentLinkUid: "pay_1" },
    async () => {
      assert.equal(
        await harness.service.recordWebhook({
          ...validWebhook,
          deliveryId: "delivery_authority",
          payloadHash: "payload_authority",
        }),
        "accepted",
      );
      assert.equal(harness.service.hasSynchronousWebhookAuthority(exact), true);
      for (const mismatch of [
        { paymentLinkUid: "pay_other" },
        { sessionId: "ps_other" },
        { amount: "12.35" },
        { currency: "EUR" },
      ]) {
        assert.equal(
          harness.service.hasSynchronousWebhookAuthority({
            ...exact,
            ...mismatch,
          }),
          false,
        );
      }
    },
  );
  assert.equal(harness.service.hasSynchronousWebhookAuthority(exact), false);
});

test("OAuth webhook routing identifiers are bounded before value-derived database queries", async () => {
  const service = Object.create(MakePayModuleService.prototype);
  service.providerConfigurationRegistered_ = true;
  service.options_ = {
    authMode: "oauth",
    backendUrl: "https://api.shop.test",
    encryptionKey: Buffer.alloc(32, 4).toString("base64"),
    providerId: "makepay",
    storefrontReturnUrl: "https://shop.test/order/confirmed",
  };
  service.connectionRecord = async () => undefined;
  let projectionQueries = 0;
  service.projectionByUid = async () => {
    projectionQueries += 1;
    return undefined;
  };
  service.generated = () => ({
    listMakePayWebhookSubscriptions: async () => {
      throw new Error("credential query must not be reached");
    },
  });
  const valid = {
    companyId: "company_1",
    grantId: "grant_1",
    installationId: "installation_1",
    paymentLink: { uid: "pay_1" },
    subscriptionId: "subscription_1",
  };

  for (const mutate of [
    (event) => (event.paymentLink.uid = "x".repeat(201)),
    (event) => (event.companyId = "x".repeat(201)),
    (event) => (event.grantId = "x".repeat(201)),
    (event) => (event.installationId = "x".repeat(201)),
    (event) => (event.subscriptionId = "x".repeat(201)),
    (event) => (event.grantId = "grant\u0000query"),
  ]) {
    const event = structuredClone(valid);
    mutate(event);
    await assert.rejects(
      service.getWebhookSecret(JSON.stringify(event)),
      (error) =>
        error?.status === 400 && /invalid makepay webhook/i.test(error.message),
    );
  }
  assert.equal(projectionQueries, 0);
});

test("projection upsert cannot rewrite immutable routing or correlation identity", async () => {
  const existing = {
    amount: "12.34",
    auth_mode: "oauth",
    company_id: "company_old",
    currency: "USD",
    grant_id: "grant_old",
    id: "mppay_immutable",
    installation_id: "installation_stable",
    order_display_id: null,
    order_id: null,
    payment_id: null,
    payment_link_uid: "pay_immutable",
    provider_id: "makepay",
    return_state_hash: "state_hash",
    session_id: "ps_immutable",
    webhook_subscription_id: "subscription_old",
  };
  const service = Object.create(MakePayModuleService.prototype);
  service.providerConfigurationRegistered_ = true;
  service.options_ = { authMode: "oauth", providerId: "makepay" };
  service.connectionRecord = async () => ({
    company_id: "company_new",
    grant_id: "grant_new",
    installation_id: "installation_stable",
    webhook_subscription_id: "subscription_new",
  });
  let updates = 0;
  service.generated = () => ({
    listMakePayPaymentProjections: async (filter) =>
      filter.session_id === existing.session_id ||
      filter.payment_link_uid === existing.payment_link_uid
        ? [existing]
        : [],
    updateMakePayPaymentProjections: async () => {
      updates += 1;
      throw new Error("immutable upsert must not update");
    },
  });
  const exact = { ...existing };

  assert.equal(await service.upsertProjection(exact), existing);
  for (const mutation of [
    { amount: "12.35" },
    { currency: "EUR" },
    { company_id: "company_new" },
    { grant_id: "grant_new" },
    { installation_id: "installation_new" },
    { webhook_subscription_id: "subscription_new" },
    { return_state_hash: "other_state" },
    { order_id: "order_injected" },
    { order_display_id: "999" },
    { payment_id: "pay_core_injected" },
  ]) {
    await assert.rejects(
      service.upsertProjection({ ...exact, ...mutation }),
      /cannot mutate.*routing or correlation identity/i,
    );
  }
  await assert.rejects(
    service.upsertProjection({
      amount: exact.amount,
      currency: exact.currency,
      payment_link_uid: exact.payment_link_uid,
      return_state_hash: exact.return_state_hash,
      session_id: exact.session_id,
    }),
    /cannot mutate.*routing or correlation identity/i,
    "omitting routing after reconnect must not adopt the new grant",
  );
  assert.equal(updates, 0);
});

test("order correlation stores the server-verified guest email", async () => {
  let projection = {
    amount: "20",
    auth_mode: "oauth",
    company_id: "company_order",
    currency: "EUR",
    customer_email: null,
    grant_id: "grant_order",
    id: "mppay_order",
    installation_id: "installation_order",
    payment_link_uid: "link_order",
    provider_id: "makepay",
    session_id: "payses_order",
    webhook_subscription_id: "subscription_order",
  };
  const updates = [];
  const service = Object.create(MakePayModuleService.prototype);
  service.providerConfigurationRegistered_ = true;
  service.options_ = {
    adminPath: "/app",
    authMode: "oauth",
    backendUrl: "https://api.shop.test",
    providerId: "makepay",
  };
  service.projectionBySession = async () => projection;
  service.withConfiguredPaymentEffectsLock = async (_uid, job) => job();
  service.assertStableProjectionOAuthRouting = async () => {};
  service.createClient = async () => ({
    async updatePaymentLink(uid, update) {
      assert.equal(uid, "link_order");
      return {
        paymentLink: {
          metadata: {
            medusaInstallationId: update.metadata.medusaInstallationId,
            medusaOrderDisplayId: update.metadata.medusaOrderDisplayId,
            medusaOrderId: update.metadata.medusaOrderId,
            medusaProviderId: "makepay",
            medusaSessionId: "payses_order",
          },
          uid,
        },
      };
    },
  });
  service.withProjectionRowLock = async (_uid, job) =>
    job(projection, { transactionManager: "test" });
  service.generated = () => ({
    async updateMakePayPaymentProjections(update) {
      updates.push(update);
      projection = { ...projection, ...update };
      return projection;
    },
  });

  await service.correlateOrder({
    customerEmail: " guest@example.test ",
    orderDisplayId: "42",
    orderId: "order_guest",
    paymentId: "pay_guest",
    sessionId: "payses_order",
  });

  assert.equal(updates.length, 1);
  assert.equal(updates[0].customer_email, "guest@example.test");
  assert.equal(updates[0].order_id, "order_guest");
  assert.equal(updates[0].order_display_id, "42");
  assert.equal(updates[0].payment_id, "pay_guest");
});

test("externally verified success redeliveries are durable no-ops", async () => {
  const harness = webhookHarness({
    amount: "12.34",
    currency: "USD",
    id: "projection_1",
    medusa_status: "processing",
    payment_link_uid: "pay_1",
    provider_status: "complete",
    session_id: "ps_1",
  });

  assert.equal(
    await harness.service.recordWebhook(validWebhook, undefined, async () => ({
      paymentId: "pay_core_1",
    })),
    "duplicate",
  );
  assert.equal(
    await harness.service.recordWebhook({
      ...validWebhook,
      deliveryId: "delivery_2",
      payloadHash: "payload_hash_2",
    }),
    "duplicate",
  );
  assert.equal(harness.deliveries.length, 2);
  assert.equal(harness.projection().provider_status, "complete");
  assert.equal(harness.projection().medusa_status, "paid");
});

test("large decimal mismatches cannot alias through IEEE-754 coercion", async () => {
  const harness = webhookHarness({
    amount: "9007199254740993.01",
    currency: "USD",
    id: "projection_large",
    payment_link_uid: "pay_large",
    provider_status: "pending",
    session_id: "ps_large",
  });

  assert.equal(
    await harness.service.recordWebhook({
      ...validWebhook,
      amount: "9007199254740993.02",
      deliveryId: "delivery_large",
      sessionId: "ps_large",
      uid: "pay_large",
    }),
    "rejected",
  );
  assert.equal(harness.deliveries.length, 0);
  assert.equal(harness.projection().provider_status, "pending");
});

test("terminal failure intent commits before its idempotent Medusa callback", async () => {
  const harness = webhookHarness({
    amount: "12.34",
    currency: "USD",
    id: "projection_1",
    medusa_status: "pending_authorization",
    payment_link_uid: "pay_1",
    provider_status: "pending",
    session_id: "ps_1",
  });
  let callbackCalls = 0;
  const failureWebhook = {
    ...validWebhook,
    deliveryId: "delivery_failure",
    providerStatus: "failed",
  };

  const result = await harness.service.recordWebhook(
    failureWebhook,
    async () => {
      callbackCalls += 1;
      assert.equal(harness.deliveries.length, 1);
      assert.equal(harness.projection().provider_status, "failed");
      assert.equal(harness.projection().medusa_status, "pending_authorization");
      return "failed";
    },
  );

  assert.equal(result, "accepted");
  assert.equal(callbackCalls, 1);
  assert.equal(harness.deliveries.length, 1);
  assert.equal(harness.projection().provider_status, "failed");
  assert.equal(harness.projection().medusa_status, "failed");

  assert.equal(
    await harness.service.recordWebhook(failureWebhook, async () => {
      callbackCalls += 1;
      return "failed";
    }),
    "duplicate",
  );
  assert.equal(callbackCalls, 2);
  assert.equal(harness.deliveries.length, 1);
});

test("webhook correlation rejects wrong routing, session, amount, currency, or UID", async () => {
  const harness = webhookHarness({
    amount: "12.34",
    currency: "USD",
    id: "projection_1",
    medusa_status: "paid",
    payment_link_uid: "pay_1",
    provider_status: "pending",
    session_id: "ps_1",
  });

  for (const mismatch of [
    { companyId: "company_wrong" },
    { grantId: "grant_wrong" },
    { installationId: "installation_wrong" },
    { subscriptionId: "subscription_wrong" },
    { sessionId: "ps_wrong" },
    { amount: "12.35" },
    { currency: "EUR" },
    { uid: "pay_wrong" },
  ]) {
    assert.equal(
      await harness.service.recordWebhook({ ...validWebhook, ...mismatch }),
      "rejected",
    );
  }

  assert.equal(harness.deliveries.length, 0);
  assert.equal(harness.projection().provider_status, "pending");
});

test("signed pre-correlation snapshots allow only missing order fields within bounded skew", async () => {
  const correlatedAt = new Date();
  const projection = {
    amount: "12.34",
    created_at: new Date(correlatedAt.getTime() - 10_000),
    currency: "USD",
    id: "projection_order_race",
    order_correlated_at: correlatedAt,
    order_display_id: "1042",
    order_id: "order_correlated",
    payment_link_uid: "pay_1",
    provider_status: "pending",
    session_id: "ps_1",
  };
  const accepted = webhookHarness(projection);
  accepted.service.options_.webhookToleranceSeconds = 60;
  assert.equal(
    await accepted.service.recordWebhook({
      ...validWebhook,
      createdAt: new Date(correlatedAt.getTime() + 30_000).toISOString(),
      deliveryId: "delivery_prepatch_skew",
      payloadHash: "payload_prepatch_skew",
    }),
    "accepted",
  );

  for (const mismatch of [
    { createdAt: new Date(correlatedAt.getTime() + 61_000).toISOString() },
    {
      createdAt: new Date(
        projection.created_at.getTime() - 61_000,
      ).toISOString(),
    },
    { createdAt: "not-an-iso-date" },
    {
      createdAt: new Date(correlatedAt.getTime() - 1_000).toISOString(),
      orderId: "order_wrong",
    },
    {
      createdAt: new Date(correlatedAt.getTime() - 1_000).toISOString(),
      orderDisplayId: "9999",
      orderId: "order_correlated",
    },
  ]) {
    const rejected = webhookHarness(projection);
    rejected.service.options_.webhookToleranceSeconds = 60;
    assert.equal(
      await rejected.service.recordWebhook({
        ...validWebhook,
        ...mismatch,
        deliveryId: `delivery_order_reject_${JSON.stringify(mismatch)}`,
        payloadHash: `payload_order_reject_${JSON.stringify(mismatch)}`,
      }),
      "rejected",
    );
  }
});

test("a successful terminal payment cannot regress", async () => {
  const harness = webhookHarness({
    amount: "12.34",
    currency: "USD",
    id: "projection_1",
    payment_link_uid: "pay_1",
    provider_status: "complete",
    session_id: "ps_1",
  });

  assert.equal(
    await harness.service.recordWebhook({
      ...validWebhook,
      deliveryId: "delivery_failure",
      providerStatus: "failed",
    }),
    "rejected",
  );
  assert.equal(
    await harness.service.recordWebhook({
      ...validWebhook,
      deliveryId: "delivery_stale",
      providerStatus: "pending",
    }),
    "rejected",
  );
  assert.equal(harness.deliveries.length, 0);
  assert.equal(harness.projection().provider_status, "complete");
});

test("checkout return stays pending until Medusa capture is durable", async () => {
  const service = Object.create(MakePayModuleService.prototype);
  service.logger_ = { warn() {} };
  const projection = {
    order_display_id: "1001",
    order_id: "order_1",
    payment_link_uid: "link_1",
    provider_status: "complete",
    session_id: "ps_1",
    updated_at: new Date("2026-07-19T00:00:00.000Z"),
  };
  service.projectionByReturnState = async () => projection;
  service.reconcileProjection = async (record) => record;

  projection.medusa_status = "processing";
  assert.deepEqual(await service.checkoutStatus("return_state"), {
    payment: {
      status: "pending_authorization",
      updated_at: "2026-07-19T00:00:00.000Z",
    },
    terminal: false,
  });

  projection.medusa_status = "paid";
  const captured = await service.checkoutStatus("return_state");
  assert.equal(captured.payment.status, "paid");
  assert.equal(captured.terminal, true);
});

test("repeated cancellation preserves atomic late-settlement proof", async () => {
  const harness = webhookHarness({
    amount: "12.34",
    currency: "USD",
    id: "projection_cancel_proof",
    late_settlement_safe: true,
    medusa_status: "canceled",
    payment_link_uid: "pay_cancel_proof",
    provider_status: "cancelled",
    session_id: "ps_cancel_proof",
  });

  await harness.service.markCanceledPayment({
    paymentLinkUid: "pay_cancel_proof",
    sessionId: "ps_cancel_proof",
  });

  assert.equal(harness.projection().late_settlement_safe, true);
  assert.equal(harness.projection().medusa_status, "canceled");
});

test("public checkout routes suppress caching and referrer disclosure", async () => {
  const service = {
    async checkoutStatus() {
      return {
        payment: {
          status: "paid",
          updated_at: "2026-07-19T00:00:00.000Z",
        },
        terminal: true,
      };
    },
    async storefrontReturnUrl() {
      return "https://shop.test/order/makepay-return?makepay_state=opaque";
    },
  };
  const request = {
    query: { state: "opaque" },
    scope: {
      resolve(name) {
        assert.equal(name, MAKEPAY_MODULE);
        return service;
      },
    },
  };
  const response = () => ({
    body: undefined,
    headers: {},
    location: undefined,
    statusCode: 200,
    json(body) {
      this.body = body;
      return this;
    },
    redirect(statusCode, location) {
      this.statusCode = statusCode;
      this.location = location;
      return this;
    },
    setHeader(name, value) {
      this.headers[String(name).toLowerCase()] = value;
      return this;
    },
    status(statusCode) {
      this.statusCode = statusCode;
      return this;
    },
  });

  const statusResponse = response();
  await checkoutStatus(request, statusResponse);
  assert.deepEqual(statusResponse.headers, {
    "cache-control": "no-store, private",
    pragma: "no-cache",
    "referrer-policy": "no-referrer",
  });
  assert.deepEqual(statusResponse.body, {
    payment: {
      status: "paid",
      updated_at: "2026-07-19T00:00:00.000Z",
    },
    terminal: true,
  });

  const returnResponse = response();
  await checkoutReturn(request, returnResponse);
  assert.deepEqual(returnResponse.headers, statusResponse.headers);
  assert.equal(returnResponse.statusCode, 303);
  assert.equal(
    returnResponse.location,
    "https://shop.test/order/makepay-return?makepay_state=opaque",
  );
});

test("OAuth reconciliation accepts nested legacy responses only under a stable installation tuple", async () => {
  const service = Object.create(MakePayModuleService.prototype);
  service.providerConfigurationRegistered_ = true;
  service.options_ = {
    authMode: "oauth",
    checkoutBaseUrl: "https://makepay.test",
  };
  const routing = {
    companyId: "company_reconcile",
    grantId: "grant_reconcile",
    installationId: "installation_reconcile",
    webhookSubscriptionId: "subscription_reconcile",
  };
  let routingReads = 0;
  service.getInstallationContext = async () => {
    routingReads += 1;
    return { ...routing };
  };
  service.createClient = async () => ({
    async getPaymentLink() {
      return {
        companyId: "company_reconcile",
        paymentLink: {
          latestSession: { id: "mpses_reconcile", status: "pending" },
          payload: {
            amount: "12.340",
            fiatCurrency: "usd",
            status: "complete",
            type: "complete",
            metadata: {
              medusaInstallationId: "installation_reconcile",
              medusaProviderId: "makepay",
              medusaSessionId: "payses_reconcile",
              status: "complete",
              type: "complete",
            },
          },
          publicUrl: "https://makepay.test/payment/pay_reconcile",
          status: "active",
          uid: "pay_reconcile",
        },
      };
    },
  });
  let updated;
  let projection;
  service.generated = () => ({
    listMakePayPaymentProjections: async () => [projection],
    updateMakePayPaymentProjections: async (input) => {
      updated = input;
      return input;
    },
  });
  projection = {
    amount: "12.34",
    auth_mode: "oauth",
    company_id: "company_reconcile",
    currency: "USD",
    grant_id: "grant_reconcile",
    id: "projection_reconcile",
    installation_id: "installation_reconcile",
    medusa_status: "pending_authorization",
    payment_link_uid: "pay_reconcile",
    provider_id: "makepay",
    provider_status: "active",
    public_url: null,
    session_id: "payses_reconcile",
    webhook_subscription_id: "subscription_reconcile",
  };
  service.baseRepository_ = {
    transaction: async (job) => job({ execute: async () => undefined }),
  };

  await service.reconcileProjection(projection);
  assert.equal(routingReads, 2);
  assert.equal(
    updated.provider_status,
    "pending",
    "merchant payload status/type must not override the real session status",
  );
  assert.equal(
    updated.public_url,
    "https://makepay.test/payment/pay_reconcile",
  );

  let call = 0;
  service.getInstallationContext = async () => {
    call += 1;
    return call === 1
      ? { ...routing }
      : { ...routing, grantId: "grant_rotated" };
  };
  await assert.rejects(
    service.reconcileProjection(projection),
    /connection changed during payment reconciliation/i,
  );
});

test("complete alone may promote a prior unsuccessful terminal state", async () => {
  const terminalStatuses = ["complete", "failed", "expired", "cancelled"];
  for (const current of terminalStatuses) {
    for (const incoming of terminalStatuses) {
      if (incoming === current) continue;
      const harness = webhookHarness({
        amount: "12.34",
        currency: "USD",
        id: `projection_${current}_${incoming}`,
        medusa_status:
          current === "complete"
            ? "paid"
            : current === "failed"
              ? "failed"
              : "canceled",
        payment_link_uid: "pay_1",
        provider_status: current,
        session_id: "ps_1",
      });
      const result = await harness.service.recordWebhook({
        ...validWebhook,
        deliveryId: `delivery_${current}_${incoming}`,
        providerStatus: incoming,
      });
      if (current !== "complete" && incoming === "complete") {
        assert.equal(result, "accepted");
        assert.equal(harness.projection().provider_status, "complete");
        assert.equal(harness.deliveries.length, 1);
      } else {
        assert.equal(result, "rejected");
        assert.equal(harness.projection().provider_status, current);
        assert.equal(harness.deliveries.length, 0);
      }
    }
  }
});

test("an abandoned success claim uses its own lease and can be reclaimed", async () => {
  const oldClaim = new Date(Date.now() - 5 * 60_000);
  const harness = webhookHarness({
    amount: "12.34",
    currency: "USD",
    effect_claimed_at: oldClaim,
    id: "projection_stale_claim",
    last_synced_at: new Date(),
    medusa_status: "processing",
    payment_link_uid: "pay_1",
    provider_status: "complete",
    session_id: "ps_1",
  });
  harness.deliveries.push({
    delivery_id: validWebhook.deliveryId,
    payload_hash: validWebhook.payloadHash,
    payment_link_uid: validWebhook.uid,
    provider_status: validWebhook.providerStatus,
    session_id: validWebhook.sessionId,
  });

  assert.equal(
    await harness.service.recordWebhook(
      validWebhook,
      undefined,
      async () => undefined,
    ),
    "retry",
  );
  assert.notEqual(harness.projection().effect_claimed_at, oldClaim);
  assert.equal(
    await harness.service.recordWebhook(validWebhook, undefined, async () => ({
      paymentId: "pay_core_stale",
    })),
    "duplicate",
  );
  assert.equal(harness.projection().medusa_status, "paid");
  assert.equal(harness.projection().effect_claimed_at, null);
});

test("a distinct success delivery group honors and can reclaim the payment lease", async () => {
  const projection = (effectClaimedAt) => ({
    amount: "12.34",
    currency: "USD",
    effect_claimed_at: effectClaimedAt,
    id: "projection_delivery_group_claim",
    medusa_status: "processing",
    payment_link_uid: "pay_1",
    provider_status: "complete",
    session_id: "ps_1",
  });

  const fresh = webhookHarness(projection(new Date()));
  assert.equal(
    await fresh.service.recordWebhook(
      {
        ...validWebhook,
        deliveryId: "delivery_fresh_group",
        payloadHash: "payload_fresh_group",
      },
      undefined,
      async () => undefined,
    ),
    "in_progress",
  );
  assert.equal(fresh.deliveries.length, 1);

  const oldClaim = new Date(Date.now() - 5 * 60_000);
  const stale = webhookHarness(projection(oldClaim));
  assert.equal(
    await stale.service.recordWebhook(
      {
        ...validWebhook,
        deliveryId: "delivery_stale_group",
        payloadHash: "payload_stale_group",
      },
      undefined,
      async () => undefined,
    ),
    "retry",
  );
  assert.equal(stale.deliveries.length, 1);
  assert.notEqual(stale.projection().effect_claimed_at, oldClaim);
});

test("mode-history checks are bounded and API-key transitions require locking", async () => {
  const service = Object.create(MakePayModuleService.prototype);
  service.providerConfigurationRegistered_ = true;
  service.options_ = {
    authMode: "api_key",
    keyId: "key",
    keySecret: "secret",
    providerId: "makepay",
    webhookSecret: "webhook",
  };
  let projectionQueries = 0;
  service.generated = () => ({
    listMakePayConnections: async () => [],
    listMakePayOAuthStates: async () => [],
    listMakePayPaymentProjections: async (_filters, config) => {
      projectionQueries += 1;
      assert.equal(config.take, 1);
      return [{ auth_mode: "oauth" }];
    },
  });
  let jobs = 0;
  await assert.rejects(
    service.withPaymentInitiationGuard(async () => {
      jobs += 1;
    }),
    /requires distributed locking after OAuth/i,
  );
  assert.equal(projectionQueries, 1);
  assert.equal(jobs, 0);

  let existenceQueries = 0;
  service.generated = () => ({
    listMakePayPaymentProjections: async (filters, config) => {
      existenceQueries += 1;
      assert.equal(filters.auth_mode, "oauth");
      assert.equal(config.take, 1);
      assert.deepEqual(config.order, { id: "ASC" });
      return [];
    },
  });
  assert.equal(await service.hasUndrainedPaymentsForMode("oauth"), false);
  assert.equal(existenceQueries, 1);
});

test("pending payments block auth-mode transitions with a safe client error", async () => {
  const service = Object.create(MakePayModuleService.prototype);
  service.options_ = { authMode: "api_key", providerId: "makepay" };
  service.generated = () => ({
    listMakePayPaymentProjections: async (filters, config) => {
      assert.equal(filters.auth_mode, "oauth");
      assert.equal(filters.provider_id, "makepay");
      assert.equal(config.take, 1);
      return [{ auth_mode: "oauth" }];
    },
  });

  await assert.rejects(service.assertAuthModeTransitionAllowed(), (error) => {
    assert.equal(MedusaError.isMedusaError(error), true);
    assert.equal(error.type, MedusaError.Types.NOT_ALLOWED);
    assert.match(error.message, /pending oauth payment/i);
    assert.match(error.message, /restore oauth mode/i);
    return true;
  });
});

test("live OAuth authorization state blocks checkout in either authentication mode", async () => {
  const service = Object.create(MakePayModuleService.prototype);
  service.providerConfigurationRegistered_ = true;
  service.options_ = {
    authMode: "oauth",
    backendUrl: "https://api.shop.test",
    encryptionKey: Buffer.alloc(32, 7).toString("base64"),
    lockingProvider: "makepay-postgres",
    providerId: "makepay",
    storefrontReturnUrl: "https://shop.test/order/makepay-return",
  };
  service.hasUndrainedPayments = async () => false;
  service.lockingService = () => ({
    execute: async (_key, job) => job(),
  });
  let live = true;
  service.generated = () => ({
    listMakePayOAuthStates: async () =>
      live
        ? [{ consumed_at: null, expires_at: new Date(Date.now() + 60_000) }]
        : [{ consumed_at: null, expires_at: new Date(Date.now() - 1) }],
  });
  service.connectionRecord = async () => ({
    encrypted_access_token: "encrypted",
    encrypted_webhook_secret: "encrypted",
    status: "connected",
    webhook_url: "https://api.shop.test/hooks/makepay/makepay_makepay",
    webhook_status: "healthy",
  });
  let jobs = 0;
  await assert.rejects(
    service.withPaymentInitiationGuard(async () => {
      jobs += 1;
    }),
    /authorization is pending/i,
  );
  assert.equal(jobs, 0);
  live = false;
  await service.withPaymentInitiationGuard(async () => {
    jobs += 1;
  });
  assert.equal(jobs, 1);

  service.options_ = {
    authMode: "api_key",
    keyId: "key",
    keySecret: "secret",
    lockingProvider: "makepay-postgres",
    providerId: "makepay",
    webhookSecret: "webhook",
  };
  live = true;
  await assert.rejects(
    service.withPaymentInitiationGuard(async () => {
      jobs += 1;
    }),
    /authorization is pending/i,
  );
  assert.equal(jobs, 1);
});

test("state-only OAuth history requires locking before API-key checkout", async () => {
  const service = Object.create(MakePayModuleService.prototype);
  service.providerConfigurationRegistered_ = true;
  service.options_ = {
    authMode: "api_key",
    keyId: "key",
    keySecret: "secret",
    providerId: "makepay",
    webhookSecret: "webhook",
  };
  service.generated = () => ({
    listMakePayConnections: async () => [],
    listMakePayOAuthStates: async (_filters, config) => {
      assert.equal(config.take, 1);
      return [{ id: "mpstate_history" }];
    },
    listMakePayPaymentProjections: async () => [],
  });
  let jobs = 0;
  await assert.rejects(
    service.withPaymentInitiationGuard(async () => {
      jobs += 1;
    }),
    /requires distributed locking after OAuth/i,
  );
  assert.equal(jobs, 0);
});

test("a delayed captured event is idempotent after a safe mode switch", async () => {
  const service = Object.create(MakePayModuleService.prototype);
  service.options_ = { authMode: "api_key", providerId: "makepay" };
  const projection = {
    auth_mode: "oauth",
    id: "projection_delayed",
    medusa_status: "paid",
    payment_id: "pay_core_delayed",
    payment_link_uid: "pay_delayed",
    provider_id: "makepay",
    provider_status: "complete",
    session_id: "ps_delayed",
  };
  let updates = 0;
  service.projectionBySession = async () => projection;
  service.baseRepository_ = {
    transaction: async (job) => job({ execute: async () => undefined }),
  };
  service.generated = () => ({
    listMakePayPaymentProjections: async () => [projection],
    updateMakePayPaymentProjections: async () => {
      updates += 1;
    },
  });
  await service.markCapturedPayment({
    paymentId: "pay_core_delayed",
    sessionId: "ps_delayed",
  });
  assert.equal(updates, 0);
});
