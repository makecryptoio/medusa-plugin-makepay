import assert from "node:assert/strict";
import test from "node:test";

import {
  arePaymentAmountsEqual,
  buildProviderData,
  getAmountFromWebhook,
  getAuthoritativeMakePayProviderStatus,
  getPaymentLinkAmount,
  getPaymentLinkFiatCurrency,
  getPaymentLinkFromResponse,
  getSafeHostedPaymentUrl,
  getSessionIdFromWebhook,
  mapMakePayStateToPaymentSessionStatus,
  mapMakePayWebhookToPaymentAction,
  shouldRefreshPaymentLinkForUpdate,
  validateMakePayProviderOptions,
} from "../src/providers/makepay/utils.ts";

test("hosted checkout URLs accept only the exact trusted origin and UID path", () => {
  for (const origin of ["https://makepay.io", "https://www.makepay.io"]) {
    assert.equal(
      getSafeHostedPaymentUrl(`${origin}/payment/pay_hosted`, "pay_hosted"),
      `${origin}/payment/pay_hosted`,
    );
  }

  for (const url of [
    "https://evilmakepay.io/payment/pay_hosted",
    "https://checkout.makepay.io/payment/pay_hosted",
    "https://makepay.io.evil.example/payment/pay_hosted",
    "https://www.makepay.io/payment/pay_other",
    "https://www.makepay.io/payment/pay_hosted?continue=1",
    "https://www.makepay.io/payment/pay_hosted#complete",
  ]) {
    assert.equal(getSafeHostedPaymentUrl(url, "pay_hosted"), undefined, url);
  }

  assert.equal(
    getSafeHostedPaymentUrl(
      "https://sandbox-payments.example/payment/pay_hosted",
      "pay_hosted",
      "https://sandbox-payments.example",
    ),
    "https://sandbox-payments.example/payment/pay_hosted",
  );
  assert.equal(
    getSafeHostedPaymentUrl(
      "https://www.makepay.io/payment/pay_hosted",
      "pay_hosted",
      "https://sandbox-payments.example",
    ),
    undefined,
  );
});

test("provider validation preserves API keys and accepts complete OAuth options", () => {
  assert.doesNotThrow(() =>
    validateMakePayProviderOptions({
      keyId: "key_id",
      keySecret: "key_secret",
      webhookSecret: "webhook_secret",
    }),
  );

  assert.doesNotThrow(() =>
    validateMakePayProviderOptions({
      authMode: "oauth",
      backendUrl: "https://api.shop.test",
      encryptionKey: Buffer.alloc(32, 1).toString("base64"),
      lockingProvider: "makepay-postgres",
      storefrontReturnUrl: "https://shop.test/order/confirmed",
    }),
  );

  assert.throws(
    () =>
      validateMakePayProviderOptions({
        authMode: "oauth",
        backendUrl: "https://api.shop.test",
        lockingProvider: "makepay-postgres",
        storefrontReturnUrl: "https://shop.test/order/confirmed",
      }),
    /encryptionKey/,
  );
});

test("provider URL validation preserves safe legacy queries and rejects unsafe destinations", () => {
  const credentials = {
    keyId: "key_id",
    keySecret: "key_secret",
    webhookSecret: "webhook_secret",
  };
  assert.doesNotThrow(() =>
    validateMakePayProviderOptions({
      ...credentials,
      failureUrl: "https://shop.test/payment/failed?source=makepay",
      returnUrl: "https://shop.test/payment/return?source=makepay",
      successUrl: "https://shop.test/payment/success?source=makepay",
    }),
  );
  assert.doesNotThrow(() =>
    validateMakePayProviderOptions({
      ...credentials,
      returnUrl: "http://127.0.0.1:8000/payment/return?source=makepay",
    }),
  );

  for (const [key, value] of [
    ["returnUrl", "https://user:password@shop.test/payment/return"],
    ["successUrl", "https://shop.test/payment/success#trusted-looking"],
    ["failureUrl", "http://shop.test/payment/failed"],
    ["baseUrl", "https://api.makecrypto.test/v1"],
    ["checkoutBaseUrl", "https://checkout.makepay.test?tenant=shop"],
  ]) {
    assert.throws(
      () => validateMakePayProviderOptions({ ...credentials, [key]: value }),
      new RegExp(`\\b${key}\\b`),
      `${key} accepted an unsafe URL`,
    );
  }
});

test("MakePay statuses map to Medusa pending authorization and terminal states", () => {
  for (const status of ["active", "created", "open", "unpaid"]) {
    assert.equal(
      mapMakePayStateToPaymentSessionStatus({ status }),
      "pending_authorization",
      status,
    );
  }
  for (const status of ["quoted", "deposit", "swap", "send", "underpaid"]) {
    assert.equal(
      mapMakePayStateToPaymentSessionStatus({ status }),
      "pending",
      status,
    );
  }
  for (const status of [
    "quoted",
    "awaiting_deposit",
    "pending",
    "deposit_received",
    "swapping",
    "sending",
    "underpaid",
  ]) {
    assert.equal(
      mapMakePayStateToPaymentSessionStatus({
        paymentLink: { status: "active" },
        session: { status },
      }),
      "pending",
      `active link must not override session progress ${status}`,
    );
  }
  assert.equal(
    mapMakePayStateToPaymentSessionStatus({
      paymentLink: { status: "active" },
    }),
    "pending_authorization",
  );
  assert.equal(
    mapMakePayStateToPaymentSessionStatus({
      latestSession: { status: "complete" },
    }),
    "captured",
  );
  assert.equal(
    mapMakePayStateToPaymentSessionStatus({ status: "expired" }),
    "canceled",
  );
  assert.equal(
    mapMakePayStateToPaymentSessionStatus({ status: "archived" }),
    "canceled",
  );
  assert.equal(
    getAuthoritativeMakePayProviderStatus({
      paymentLink: { status: "archived" },
      session: { status: "complete" },
    }),
    "complete",
  );
  for (const status of [
    "deposit_received",
    "swapping",
    "sending",
    "underpaid",
  ]) {
    assert.equal(
      getAuthoritativeMakePayProviderStatus({
        paymentLink: { status: "archived" },
        session: { status },
      }),
      status,
      `archival must not hide funded session state ${status}`,
    );
    assert.equal(
      mapMakePayStateToPaymentSessionStatus({
        paymentLink: { status: "archived" },
        session: { status },
      }),
      "pending",
      status,
    );
  }
  assert.equal(
    getAuthoritativeMakePayProviderStatus({
      paymentLink: { status: "archived" },
      session: { status: "pending" },
    }),
    "pending",
  );
  assert.equal(
    mapMakePayStateToPaymentSessionStatus({ status: "failed" }),
    "error",
  );

  assert.equal(
    mapMakePayWebhookToPaymentAction({ session: { status: "complete" } }),
    "captured",
  );
  assert.equal(
    mapMakePayWebhookToPaymentAction({ session: { status: "failed" } }),
    "failed",
  );
  assert.equal(
    mapMakePayWebhookToPaymentAction({ session: { status: "expired" } }),
    "canceled",
  );

  for (const alias of [
    "authorized",
    "requires_capture",
    "refunded",
    "error",
    "declined",
    "canceled",
    "paid",
    "completed",
    "confirmed",
    "succeeded",
    "success",
    "captured",
    "settled",
    "payment.paid",
  ]) {
    assert.equal(
      mapMakePayStateToPaymentSessionStatus({ status: alias }),
      "pending",
      `${alias} must not capture without exact complete`,
    );
    assert.equal(
      mapMakePayWebhookToPaymentAction({ session: { status: alias } }),
      "not_supported",
      `${alias} must not emit a successful webhook action`,
    );
  }
  assert.equal(
    mapMakePayWebhookToPaymentAction({
      paymentLink: { status: "failed" },
      session: { status: "complete" },
    }),
    "not_supported",
  );
});

test("storefront provider data is a public allowlist", () => {
  const data = buildProviderData({
    amount: "12.34",
    checkoutBaseUrl: "https://makepay.test",
    existing: {
      access_token: "must-not-survive",
      raw_response: { private: true },
      refresh_token: "must-not-survive",
      return_state: "opaque-return-state",
    },
    fiatCurrency: "USD",
    paymentLink: {
      amount: "12.34",
      fiatCurrency: "USD",
      metadata: { private: "must-not-survive" },
      publicUrl: "https://makepay.test/payment/pay_test",
      uid: "pay_test",
    },
    sessionId: "ps_test",
    status: "pending_authorization",
  });

  assert.deepEqual(data, {
    amount: "12.34",
    fiat_currency: "USD",
    next_action: {
      type: "redirect",
      url: "https://makepay.test/payment/pay_test",
    },
    payment_link_uid: "pay_test",
    public_url: "https://makepay.test/payment/pay_test",
    return_state: "opaque-return-state",
    session_id: "ps_test",
    status: "pending_authorization",
  });
  assert.equal(JSON.stringify(data).includes("must-not-survive"), false);
});

test("payment-link responses normalize the landed serializer and nested legacy payload", () => {
  const payload = {
    amount: "12.340",
    fiatCurrency: "usd",
    metadata: {
      medusaProviderId: "makepay",
      medusaSessionId: "payses_response",
    },
  };
  const landed = getPaymentLinkFromResponse({
    companyId: "company_response",
    paymentLink: {
      amount: "12.34",
      fiatAmount: "12.3400",
      fiatCurrency: "USD",
      metadata: { ...payload.metadata },
      payload,
      publicUrl: "https://makepay.test/payment/pay_response",
      uid: "pay_response",
    },
  });
  assert.equal(landed.amount, "12.34");
  assert.equal(landed.fiatAmount, "12.34");
  assert.equal(landed.fiatCurrency, "USD");
  assert.deepEqual(landed.metadata, payload.metadata);

  const nestedOnly = getPaymentLinkFromResponse({
    paymentLink: {
      payload,
      publicUrl: "https://makepay.test/payment/pay_legacy",
      uid: "pay_legacy",
    },
  });
  assert.equal(getPaymentLinkAmount(nestedOnly), "12.340");
  assert.equal(getPaymentLinkFiatCurrency(nestedOnly), "USD");
  assert.deepEqual(nestedOnly.metadata, payload.metadata);
  assert.equal(buildProviderData({ paymentLink: nestedOnly }).amount, "12.340");
  assert.doesNotThrow(() =>
    getPaymentLinkFromResponse({
      paymentLink: {
        amount: "12.340",
        fiatAmount: "12.34",
        fiatCurrency: "USD",
        payload: {
          ...payload,
          // The landed serializer intentionally treats payload.amount and
          // payload.fiatCurrency as canonical over retained legacy aliases.
          displayCurrency: "EUR",
          fiatAmount: "999.00",
        },
      },
    }),
  );

  assert.throws(
    () =>
      getPaymentLinkFromResponse({
        paymentLink: {
          amount: "12.34",
          payload: { ...payload, amount: "12.35" },
        },
      }),
    /conflicting fiat amounts/i,
  );
  assert.throws(
    () =>
      getPaymentLinkFromResponse({
        paymentLink: {
          fiatCurrency: "USD",
          payload: { ...payload, fiatCurrency: "EUR" },
        },
      }),
    /conflicting fiat currencies/i,
  );
  assert.throws(
    () =>
      getPaymentLinkFromResponse({
        paymentLink: {
          metadata: { medusaSessionId: "payses_flat" },
          payload: {
            ...payload,
            metadata: { medusaSessionId: "payses_nested" },
          },
        },
      }),
    /conflicting medusaSessionId metadata/i,
  );
});

test("webhook correlation never invents a missing amount", () => {
  const event = {
    paymentLink: {
      amount: "19.50",
      metadata: { session_id: "ps_webhook" },
    },
    session: { status: "complete" },
  };
  assert.equal(getSessionIdFromWebhook(event), "ps_webhook");
  assert.equal(getAmountFromWebhook(event), "19.50");
  assert.equal(
    getAmountFromWebhook({ session: { status: "complete" } }),
    undefined,
  );
});

test("updates compare decimal values and flag issued-link mismatches", () => {
  assert.equal(arePaymentAmountsEqual("12.340", 12.34), true);
  assert.equal(
    arePaymentAmountsEqual("9007199254740993.010", "9007199254740993.01"),
    true,
  );
  assert.equal(
    arePaymentAmountsEqual("9007199254740993.01", "9007199254740993.02"),
    false,
  );
  assert.equal(
    arePaymentAmountsEqual(Number.MAX_SAFE_INTEGER + 1, "9007199254740992"),
    false,
  );
  assert.equal(
    shouldRefreshPaymentLinkForUpdate({
      currentData: { amount: "12.34", fiatCurrency: "USD", status: "active" },
      nextAmount: "12.34",
      nextCurrencyCode: "usd",
    }),
    false,
  );
  assert.equal(
    shouldRefreshPaymentLinkForUpdate({
      currentData: { amount: "12.34", fiatCurrency: "USD", status: "active" },
      nextAmount: "12.35",
      nextCurrencyCode: "USD",
    }),
    true,
  );
});
