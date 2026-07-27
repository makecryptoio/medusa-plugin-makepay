import assert from "node:assert/strict";
import test from "node:test";

import { MakePayError } from "@makecrypto/makepay";
import { processPaymentWorkflowId } from "@medusajs/medusa/core-flows";
import { Modules, PaymentActions } from "@medusajs/framework/utils";

import middlewares, {
  MAKEPAY_WEBHOOK_BODY_LIMIT,
  routeLegacyMakePayWebhook,
} from "../src/api/middlewares.ts";
import { POST } from "../src/api/hooks/makepay/[provider]/route.ts";
import { MAKEPAY_MODULE } from "../src/modules/makepay/constants.ts";

function responseHarness() {
  return {
    body: undefined,
    statusCode: 200,
    json(body) {
      this.body = body;
      return this;
    },
    status(statusCode) {
      this.statusCode = statusCode;
      return this;
    },
  };
}

function requestHarness({
  deliveryGroupId = `mpwhgrp_${"a".repeat(64)}`,
  makepay,
  payment,
  provider = "makepay_makepay",
  rawBody = Buffer.from('{"schemaVersion":"medusa.v1"}'),
  workflow,
}) {
  const moduleService = makepay ?? {
    authMode: "oauth",
    providerId: "makepay",
    async hasUndrainedPaymentsForMode() {
      return false;
    },
    async verifyWebhookSignature(_rawBody, _signature, deliveryGroupId) {
      return { deliveryGroupId, paymentLinkUid: "pay_route" };
    },
    async withWebhookDeliveryLock(_identity, job) {
      return job();
    },
    async projectionByUid() {
      return {
        amount: "12.34",
        currency: "USD",
        payment_link_uid: "pay_route",
        session_id: "ps_webhook_route",
      };
    },
    async markCapturedPayment() {},
    async releaseSuccessfulPaymentClaim() {},
  };
  return {
    body: { schemaVersion: "medusa.v1" },
    headers: {
      "x-makepay-delivery-group-id": deliveryGroupId,
      "x-makepay-signature": "signed-test-value",
    },
    params: { provider },
    rawBody,
    scope: {
      resolve(name) {
        if (name === MAKEPAY_MODULE) return moduleService;
        if (name === Modules.PAYMENT) return payment;
        if (name === Modules.WORKFLOW_ENGINE) return workflow;
        throw new Error(`Unexpected dependency: ${name}`);
      },
    },
  };
}

test("MakePay webhook middleware preserves a bounded raw body only on the exact POST route", () => {
  assert.equal(MAKEPAY_WEBHOOK_BODY_LIMIT, "64kb");
  assert.equal(middlewares.routes.length, 10);
  assert.equal(middlewares.routes[0].matcher, "/admin/makepay*");
  const oauthWebhook = middlewares.routes.find(
    (route) => route.matcher === "/hooks/makepay/:provider",
  );
  assert.deepEqual(oauthWebhook, {
    bodyParser: { preserveRawBody: true, sizeLimit: "64kb" },
    matcher: "/hooks/makepay/:provider",
    methods: ["POST"],
    middlewares: [],
  });
  const legacyWebhook = middlewares.routes.find(
    (route) => route.matcher === "/hooks/payment/makepay_makepay",
  );
  assert.equal(
    legacyWebhook.matcher,
    "/hooks/payment/makepay_makepay",
  );
  assert.deepEqual(legacyWebhook.bodyParser, {
    preserveRawBody: true,
    sizeLimit: "64kb",
  });
  assert.deepEqual(legacyWebhook.methods, ["POST"]);
  assert.strictEqual(
    legacyWebhook.middlewares[0],
    routeLegacyMakePayWebhook,
  );
});

test("legacy Medusa payment hook is synchronously owned only for exact MakePay", async () => {
  let nextCalls = 0;
  const next = () => {
    nextCalls += 1;
  };

  const oauthResponse = responseHarness();
  await routeLegacyMakePayWebhook(
    requestHarness({ payment: {}, workflow: {} }),
    oauthResponse,
    next,
  );
  assert.equal(oauthResponse.statusCode, 404);
  assert.deepEqual(oauthResponse.body, { message: "Not found." });
  assert.equal(nextCalls, 0);

  const apiKeyResponse = responseHarness();
  await routeLegacyMakePayWebhook(
    requestHarness({
      makepay: {
        authMode: "api_key",
        providerId: "makepay",
        async verifyWebhookSignature() {
          throw new MakePayError("invalid", { status: 401 });
        },
      },
      payment: {},
      workflow: {},
    }),
    apiKeyResponse,
    next,
  );
  assert.equal(apiKeyResponse.statusCode, 401);
  assert.equal(nextCalls, 0);

  await routeLegacyMakePayWebhook(
    requestHarness({
      makepay: { authMode: "oauth", providerId: "makepay" },
      payment: {},
      provider: "stripe_stripe",
      workflow: {},
    }),
    responseHarness(),
    next,
  );
  assert.equal(nextCalls, 1);

  const customProviderResponse = responseHarness();
  await routeLegacyMakePayWebhook(
    requestHarness({
      makepay: {
        authMode: "oauth",
        providerId: "custom",
        async hasUndrainedPaymentsForMode() {
          return false;
        },
      },
      payment: {},
      provider: "makepay_custom",
      workflow: {},
    }),
    customProviderResponse,
    next,
  );
  assert.equal(customProviderResponse.statusCode, 404);
  assert.equal(nextCalls, 1);

  await routeLegacyMakePayWebhook(
    {
      params: { provider: "stripe_stripe" },
      scope: {
        resolve() {
          throw new Error("not registered");
        },
      },
    },
    responseHarness(),
    next,
  );
  assert.equal(nextCalls, 2);

  const unavailableMakePay = responseHarness();
  await routeLegacyMakePayWebhook(
    {
      params: { provider: "makepay_makepay" },
      scope: {
        resolve() {
          throw new Error("temporarily unavailable");
        },
      },
    },
    unavailableMakePay,
    next,
  );
  assert.equal(unavailableMakePay.statusCode, 503);
  assert.deepEqual(unavailableMakePay.body, {
    message: "MakePay webhook processing unavailable.",
  });
  assert.equal(nextCalls, 2);
});

test("wrong-mode callbacks retry until the prior mode is drained, then disappear", async () => {
  let undrained = true;
  const oauthModule = {
    authMode: "oauth",
    providerId: "makepay",
    async hasUndrainedPaymentsForMode(mode) {
      assert.equal(mode, "api_key");
      return undrained;
    },
  };
  const legacyRequest = requestHarness({
    makepay: oauthModule,
    payment: {},
    workflow: {},
  });
  const retryLegacy = responseHarness();
  await routeLegacyMakePayWebhook(legacyRequest, retryLegacy, () => {
    throw new Error("exact MakePay callback must not fall through");
  });
  assert.equal(retryLegacy.statusCode, 503);

  undrained = false;
  const drainedLegacy = responseHarness();
  await routeLegacyMakePayWebhook(legacyRequest, drainedLegacy, () => {
    throw new Error("exact MakePay callback must not fall through");
  });
  assert.equal(drainedLegacy.statusCode, 404);

  undrained = true;
  const apiKeyModule = {
    authMode: "api_key",
    providerId: "makepay",
    async hasUndrainedPaymentsForMode(mode) {
      assert.equal(mode, "oauth");
      return undrained;
    },
  };
  const oauthRequest = requestHarness({
    makepay: apiKeyModule,
    payment: {},
    workflow: {},
  });
  const retryOauth = responseHarness();
  await POST(oauthRequest, retryOauth);
  assert.equal(retryOauth.statusCode, 503);

  undrained = false;
  const drainedOauth = responseHarness();
  await POST(oauthRequest, drainedOauth);
  assert.equal(drainedOauth.statusCode, 404);
});

test("MakePay webhook route fails closed before provider side effects", async () => {
  let paymentCalls = 0;
  const payment = {
    async getWebhookActionAndData() {
      paymentCalls += 1;
      return { action: PaymentActions.NOT_SUPPORTED };
    },
  };
  const workflow = {
    async run() {
      throw new Error("workflow must not run");
    },
  };
  let earlyPreflightCalls = 0;
  let earlyLockCalls = 0;
  const earlyMakepay = {
    authMode: "oauth",
    providerId: "makepay",
    async verifyWebhookSignature() {
      earlyPreflightCalls += 1;
    },
    async withWebhookDeliveryLock() {
      earlyLockCalls += 1;
    },
  };
  const missingSignature = requestHarness({
    makepay: earlyMakepay,
    payment,
    workflow,
  });
  delete missingSignature.headers["x-makepay-signature"];
  const malformedDeliveryGroup = requestHarness({
    deliveryGroupId: "untrusted-group",
    makepay: earlyMakepay,
    payment,
    workflow,
  });

  for (const [request, expectedStatus] of [
    [
      requestHarness({
        makepay: {
          authMode: "api_key",
          providerId: "makepay",
          async hasUndrainedPaymentsForMode() {
            return false;
          },
        },
        payment,
        workflow,
      }),
      404,
    ],
    [requestHarness({ payment, provider: "stripe_stripe", workflow }), 400],
    [requestHarness({ payment, rawBody: null, workflow }), 400],
    [missingSignature, 401],
    [malformedDeliveryGroup, 400],
    [
      requestHarness({
        payment,
        rawBody: Buffer.alloc(64 * 1024 + 1),
        workflow,
      }),
      413,
    ],
  ]) {
    const response = responseHarness();
    await POST(request, response);
    assert.equal(response.statusCode, expectedStatus);
    assert.deepEqual(response.body, {
      message:
        expectedStatus === 404 ? "Not found." : "Invalid MakePay webhook.",
    });
  }
  assert.equal(paymentCalls, 0);
  assert.equal(earlyPreflightCalls, 0);
  assert.equal(earlyLockCalls, 0);

  const invalidCorrelation = responseHarness();
  await POST(requestHarness({ payment, workflow }), invalidCorrelation);
  assert.equal(invalidCorrelation.statusCode, 400);
  assert.deepEqual(invalidCorrelation.body, {
    message: "Invalid MakePay webhook.",
  });
  assert.equal(paymentCalls, 1);

  for (const status of [400, 401]) {
    let lockCalls = 0;
    const makepay = {
      authMode: "oauth",
      providerId: "makepay",
      async verifyWebhookSignature() {
        throw new MakePayError(
          "invalid signed body using whsec_must_not_leak",
          { status },
        );
      },
      async withWebhookDeliveryLock() {
        lockCalls += 1;
      },
    };
    const invalidSignature = responseHarness();
    await POST(
      requestHarness({ makepay, payment, workflow }),
      invalidSignature,
    );
    assert.equal(invalidSignature.statusCode, status);
    assert.deepEqual(invalidSignature.body, {
      message: "Invalid MakePay webhook.",
    });
    assert.doesNotMatch(
      JSON.stringify(invalidSignature.body),
      /whsec|signature/i,
    );
    assert.equal(lockCalls, 0, "invalid signatures must not acquire a lock");
  }

  let unavailableLockCalls = 0;
  const unavailableMakepay = {
    authMode: "oauth",
    providerId: "makepay",
    async verifyWebhookSignature() {
      throw new Error("database secret lookup failed");
    },
    async withWebhookDeliveryLock() {
      unavailableLockCalls += 1;
    },
  };
  const unavailableSecret = responseHarness();
  await POST(
    requestHarness({ makepay: unavailableMakepay, payment, workflow }),
    unavailableSecret,
  );
  assert.equal(unavailableSecret.statusCode, 503);
  assert.equal(unavailableLockCalls, 0);

  let rotationLockCalls = 0;
  const rotatingMakepay = {
    authMode: "oauth",
    providerId: "makepay",
    async verifyWebhookSignature(_rawBody, _signature, deliveryGroupId) {
      return { deliveryGroupId, paymentLinkUid: "pay_rotated_secret" };
    },
    async withWebhookDeliveryLock(_identity, job) {
      rotationLockCalls += 1;
      return job();
    },
  };
  payment.getWebhookActionAndData = async () => {
    throw new MakePayError("secret rotated after preflight", { status: 401 });
  };
  const rotatedSecret = responseHarness();
  await POST(
    requestHarness({ makepay: rotatingMakepay, payment, workflow }),
    rotatedSecret,
  );
  assert.equal(rotatedSecret.statusCode, 401);
  assert.equal(rotationLockCalls, 1);

  payment.getWebhookActionAndData = async () => {
    throw new Error("database password must not leak");
  };
  const infrastructureFailure = responseHarness();
  await POST(requestHarness({ payment, workflow }), infrastructureFailure);
  assert.equal(infrastructureFailure.statusCode, 503);
  assert.deepEqual(infrastructureFailure.body, {
    message: "MakePay webhook processing unavailable.",
  });
});

test("concurrent delivery groups for one payment serialize and cannot double-capture", async () => {
  let lockTail = Promise.resolve();
  const lockIdentities = [];
  const makepay = {
    authMode: "oauth",
    providerId: "makepay",
    async verifyWebhookSignature(_rawBody, _signature, deliveryGroupId) {
      return { deliveryGroupId, paymentLinkUid: "pay_concurrent" };
    },
    withWebhookDeliveryLock(identity, job) {
      lockIdentities.push(identity);
      const current = lockTail.then(job);
      lockTail = current.catch(() => undefined);
      return current;
    },
    async projectionByUid() {
      return {
        amount: "12.34",
        currency: "USD",
        payment_link_uid: "pay_concurrent",
        session_id: "ps_concurrent",
      };
    },
    async markCapturedPayment() {},
    async releaseSuccessfulPaymentClaim() {},
  };
  let captured = false;
  let paymentCalls = 0;
  const payment = {
    async getWebhookActionAndData() {
      paymentCalls += 1;
      return captured
        ? {
            action: PaymentActions.NOT_SUPPORTED,
            data: { amount: "12.34", session_id: "ps_concurrent" },
          }
        : {
            action: PaymentActions.SUCCESSFUL,
            data: { amount: "12.34", session_id: "ps_concurrent" },
          };
    },
    async listPayments() {
      return captured
        ? [
            {
              amount: "12.34",
              canceled_at: null,
              captured_amount: "12.34",
              captured_at: new Date(),
              captures: [{ amount: "12.34" }],
              currency_code: "USD",
              id: "pay_core_concurrent",
              provider_id: "pp_makepay_makepay",
            },
          ]
        : [];
    },
  };
  let releaseWorkflow;
  let workflowStarted;
  const enteredWorkflow = new Promise((resolve) => {
    workflowStarted = resolve;
  });
  const workflowGate = new Promise((resolve) => {
    releaseWorkflow = resolve;
  });
  let workflowCalls = 0;
  const workflow = {
    async run() {
      workflowCalls += 1;
      workflowStarted();
      await workflowGate;
      captured = true;
    },
  };
  const firstRequest = requestHarness({ makepay, payment, workflow });
  const secondRequest = requestHarness({
    deliveryGroupId: `mpwhgrp_${"b".repeat(64)}`,
    makepay,
    payment,
    workflow,
  });
  const firstResponse = responseHarness();
  const secondResponse = responseHarness();

  const first = POST(firstRequest, firstResponse);
  await enteredWorkflow;
  const second = POST(secondRequest, secondResponse);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(paymentCalls, 1);
  assert.equal(workflowCalls, 1);

  releaseWorkflow();
  await Promise.all([first, second]);
  assert.equal(firstResponse.statusCode, 200);
  assert.equal(secondResponse.statusCode, 200);
  assert.equal(paymentCalls, 2);
  assert.equal(workflowCalls, 1);
  assert.deepEqual(
    lockIdentities.map((identity) => identity.paymentLinkUid),
    ["pay_concurrent", "pay_concurrent"],
  );
  assert.notEqual(
    lockIdentities[0].deliveryGroupId,
    lockIdentities[1].deliveryGroupId,
  );
});

test("MakePay webhook retries workflow failures and acknowledges only synchronous completion", async () => {
  const rawBody = Buffer.from('{"deliveryGroupId":"stable-delivery"}');
  const paymentInputs = [];
  let action = PaymentActions.SUCCESSFUL;
  const processed = {
    get action() {
      return action;
    },
    data: { amount: "12.34", session_id: "ps_webhook_route" },
  };
  const payment = {
    async getWebhookActionAndData(input) {
      paymentInputs.push(input);
      return processed;
    },
  };
  const workflowCalls = [];
  let failWorkflow = true;
  let captured = false;
  const workflow = {
    async run(id, input) {
      workflowCalls.push({ id, input });
      if (failWorkflow) {
        throw new Error("database password must not leak");
      }
      captured = true;
    },
  };
  const request = requestHarness({ payment, rawBody, workflow });
  payment.listPayments = async () =>
    captured
      ? [
          {
            amount: "12.34",
            canceled_at: null,
            captured_amount: "12.34",
            captured_at: new Date(),
            captures: [{ amount: "12.34" }],
            currency_code: "USD",
            id: "pay_core_route",
            provider_id: "pp_makepay_makepay",
          },
        ]
      : [];

  const firstAttempt = responseHarness();
  await POST(request, firstAttempt);
  assert.equal(firstAttempt.statusCode, 503);
  assert.deepEqual(firstAttempt.body, {
    message: "MakePay webhook processing unavailable.",
  });
  assert.doesNotMatch(JSON.stringify(firstAttempt.body), /database|password/i);

  failWorkflow = false;
  const retry = responseHarness();
  await POST(request, retry);
  assert.equal(retry.statusCode, 200);
  assert.deepEqual(retry.body, { received: true });
  assert.equal(paymentInputs.length, 2);
  assert.equal(paymentInputs[0].provider, "makepay_makepay");
  assert.strictEqual(paymentInputs[0].payload.rawData, rawBody);
  assert.deepEqual(
    workflowCalls.map((call) => call.id),
    [processPaymentWorkflowId, processPaymentWorkflowId],
  );
  assert.strictEqual(workflowCalls[1].input.input, processed);

  action = PaymentActions.PENDING;
  const pending = responseHarness();
  await POST(request, pending);
  assert.equal(pending.statusCode, 200);
  assert.equal(workflowCalls.length, 2);

  action = PaymentActions.NOT_SUPPORTED;
  const durableDuplicate = responseHarness();
  await POST(request, durableDuplicate);
  assert.equal(durableDuplicate.statusCode, 200);
  assert.deepEqual(durableDuplicate.body, { received: true });

  for (const sideEffectAction of [
    PaymentActions.CANCELED,
    PaymentActions.FAILED,
    PaymentActions.PENDING_AUTHORIZATION,
    PaymentActions.REQUIRES_MORE,
  ]) {
    action = sideEffectAction;
    const response = responseHarness();
    await POST(request, response);
    assert.equal(response.statusCode, 200);
  }
  assert.equal(
    workflowCalls.length,
    2,
    "provider-owned terminal side effects must not invoke the payment workflow",
  );
});
