import assert from "node:assert/strict";
import test from "node:test";

import {
  ContainerRegistrationKeys,
  Modules,
} from "@medusajs/framework/utils";

import makePayPaymentCapturedHandler from "../src/subscribers/makepay-payment-captured.ts";
import { MAKEPAY_MODULE } from "../src/modules/makepay/constants.ts";

function harness(
  captureAmount,
  { paymentAmount = "12.34", paymentCurrency = "USD" } = {},
) {
  const marked = [];
  const payment = {
    amount: paymentAmount,
    canceled_at: null,
    captured_amount: captureAmount,
    captured_at: new Date(),
    captures: [{ amount: captureAmount }],
    currency_code: paymentCurrency,
    id: "pay_subscriber",
    payment_session_id: "payses_subscriber",
    provider_id: "pp_makepay_makepay",
  };
  const services = {
    [ContainerRegistrationKeys.QUERY]: {
      async graph() {
        return { data: [payment] };
      },
    },
    [MAKEPAY_MODULE]: {
      providerId: "makepay",
      async markCapturedPayment(input) {
        marked.push(input);
      },
      async projectionBySession(sessionId) {
        assert.equal(sessionId, "payses_subscriber");
        return {
          amount: "12.34",
          currency: "USD",
          provider_id: "makepay",
          provider_status: "complete",
          session_id: sessionId,
        };
      },
    },
    [Modules.PAYMENT]: {
      async listPayments(filters, config) {
        assert.deepEqual(filters, {
          payment_session_id: "payses_subscriber",
        });
        assert.deepEqual(config, { relations: ["captures"], take: 10 });
        return [payment];
      },
    },
  };
  return {
    container: {
      resolve(name) {
        return services[name];
      },
    },
    marked,
  };
}

test("captured subscriber ignores a partial capture", async () => {
  const { container, marked } = harness("5.00");
  await makePayPaymentCapturedHandler({
    container,
    event: { data: { id: "pay_subscriber" } },
  });
  assert.deepEqual(marked, []);
});

test("captured subscriber marks only an exactly fully captured payment", async () => {
  const { container, marked } = harness("12.34");
  await makePayPaymentCapturedHandler({
    container,
    event: { data: { id: "pay_subscriber" } },
  });
  assert.deepEqual(marked, [
    {
      paymentId: "pay_subscriber",
      sessionId: "payses_subscriber",
    },
  ]);
});

test("captured subscriber rejects wrong amount and currency", async () => {
  for (const { captureAmount, options } of [
    {
      captureAmount: "12.35",
      options: { paymentAmount: "12.35" },
    },
    {
      captureAmount: "12.34",
      options: { paymentCurrency: "EUR" },
    },
  ]) {
    const { container, marked } = harness(captureAmount, options);
    await makePayPaymentCapturedHandler({
      container,
      event: { data: { id: "pay_subscriber" } },
    });
    assert.deepEqual(marked, []);
  }
});
