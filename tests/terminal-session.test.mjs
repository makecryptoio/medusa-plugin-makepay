import assert from "node:assert/strict";
import test from "node:test";

import { PaymentSessionStatus } from "@medusajs/framework/utils";

import { applyTerminalPaymentSessionState } from "../src/lib/terminal-session.ts";

const expectation = {
  amount: "12.34",
  currency: "USD",
  paymentLinkUid: "link_terminal",
  providerId: "pp_makepay_makepay",
};

function paymentModule(overrides = {}) {
  let status = "pending_authorization";
  let updates = 0;
  const session = {
    amount: "12.34",
    currency_code: "USD",
    data: {
      amount: "12.34",
      fiat_currency: "USD",
      payment_link_uid: "link_terminal",
      session_id: "payses_terminal",
    },
    id: "payses_terminal",
    metadata: {},
    provider_id: "pp_makepay_makepay",
    get status() {
      return status;
    },
    ...overrides,
  };
  return {
    get updates() {
      return updates;
    },
    async retrievePaymentSession() {
      return session;
    },
    async updatePaymentSession(input) {
      updates += 1;
      status = input.status;
      return session;
    },
  };
}

test("terminal session mutation verifies the complete payment correlation", async () => {
  const module = paymentModule();
  assert.equal(
    await applyTerminalPaymentSessionState(
      module,
      "payses_terminal",
      "failed",
      expectation,
    ),
    "failed",
  );
  assert.equal(module.updates, 1);
  assert.equal(
    String((await module.retrievePaymentSession()).status).toLowerCase(),
    String(PaymentSessionStatus.ERROR).toLowerCase(),
  );
});

test("terminal session mutation rejects every mismatched authority field", async () => {
  for (const overrides of [
    { id: "payses_other" },
    { provider_id: "pp_stripe_stripe" },
    { amount: "12.35" },
    { currency_code: "EUR" },
    {
      data: {
        amount: "12.34",
        fiat_currency: "USD",
        payment_link_uid: "link_other",
        session_id: "payses_terminal",
      },
    },
    {
      data: {
        amount: "12.34",
        fiat_currency: "USD",
        payment_link_uid: "link_terminal",
        session_id: "payses_other",
      },
    },
  ]) {
    const module = paymentModule(overrides);
    await assert.rejects(
      applyTerminalPaymentSessionState(
        module,
        "payses_terminal",
        "canceled",
        expectation,
      ),
      /correlation failed/i,
    );
    assert.equal(module.updates, 0);
  }
});
