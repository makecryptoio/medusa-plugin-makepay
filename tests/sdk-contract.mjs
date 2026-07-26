import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";

import { MakePayClient, parseMakePayWebhook } from "@makecrypto/makepay";

import { createMakePayContractServer } from "./e2e/support/makepay-contract-server.mjs";

const contract = createMakePayContractServer();
await contract.start();

try {
  const client = new MakePayClient({
    baseUrl: contract.origin,
    keyId: contract.apiKeyId,
    keySecret: contract.apiKeySecret,
  });

  const created = await client.createPaymentLink(
    {
      amount: "12.34",
      currency: "USDT",
      fiatCurrency: "USD",
      metadata: {
        medusaInstallationId: "installation_contract",
        medusaProviderId: "makepay",
        medusaSessionId: "ps_contract",
      },
    },
    { idempotencyKey: "idem_contract", sendPaymentRequestEmail: false },
  );

  assert.equal(created.paymentLink.amount, "12.34");
  assert.equal(created.paymentLink.fiatCurrency, "USD");
  assert.equal(contract.state.requests.at(-1)?.idempotencyKey, "idem_contract");
  assert.equal(contract.state.requests.at(-1)?.hasApiKey, true);

  const correlated = await client.updatePaymentLink(
    created.paymentLink.uid,
    {
      metadata: {
        medusaAdminUrl: "https://admin.shop.test/app/orders/order_contract",
        medusaInstallationId: "installation_contract",
        medusaOrderDisplayId: "1001",
        medusaOrderId: "order_contract",
      },
    },
    { idempotencyKey: "idem_correlation" },
  );
  assert.equal(
    correlated.paymentLink.metadata?.medusaOrderId,
    "order_contract",
  );

  const createdSubscription = await client.upsertCurrentWebhookSubscription(
    {
      events: ["makepay.payment.status_changed"],
      url: "https://api.shop.test/hooks/payment/makepay_makepay",
    },
    { idempotencyKey: "idem_subscription" },
  );
  assert.equal(createdSubscription.signingSecret, contract.webhookSecret);
  assert.equal(
    contract.state.subscription.callbackUrl,
    "https://api.shop.test/hooks/payment/makepay_makepay",
  );

  const readSubscription = await client.getCurrentWebhookSubscription();
  assert.equal(readSubscription.signingSecret, undefined);
  assert.equal(
    readSubscription.subscription?.id,
    contract.state.subscription.id,
  );

  const deliveryGroupId = `mpwhgrp_${createHash("sha256")
    .update("sdk-canonical-delivery-group")
    .digest("hex")}`;
  const canonicalWebhook = {
    schemaVersion: "medusa.v1",
    deliveryId: "delivery_contract",
    deliveryGroupId,
    type: "makepay.payment.status_changed",
    createdAt: new Date().toISOString(),
    status: "complete",
    companyId: "company_contract",
    grantId: "grant_contract",
    subscriptionId: "subscription_contract",
    installationId: "installation_contract",
    paymentLink: {
      uid: created.paymentLink.uid,
      fiatAmount: "12.34",
      fiatCurrency: "USD",
      metadata: {
        medusaSessionId: "ps_contract",
        medusaOrderId: "order_contract",
        medusaOrderDisplayId: "1001",
        medusaProviderId: "makepay",
      },
    },
    session: { id: "makepay_session_contract", settlement: null },
  };
  const webhookBody = JSON.stringify(canonicalWebhook);
  const timestamp = Math.floor(Date.now() / 1000);
  const webhookSignature = `t=${timestamp},v1=${createHmac(
    "sha256",
    contract.webhookSecret,
  )
    .update(`${timestamp}.${webhookBody}`)
    .digest("hex")}`;
  const parsed = parseMakePayWebhook(
    webhookBody,
    webhookSignature,
    contract.webhookSecret,
  );
  assert.equal(parsed.deliveryId, "delivery_contract");
  assert.equal(parsed.deliveryGroupId, deliveryGroupId);
  assert.equal(parsed.status, "complete");
  assert.equal(parsed.paymentLink.metadata.medusaOrderId, "order_contract");
  assert.deepEqual(Object.keys(parsed.session).sort(), ["id", "settlement"]);

  const retryWebhook = {
    ...canonicalWebhook,
    deliveryId: "delivery_contract_retry",
  };
  const retryWebhookBody = JSON.stringify(retryWebhook);
  const retryWebhookSignature = `t=${timestamp},v1=${createHmac(
    "sha256",
    contract.webhookSecret,
  )
    .update(`${timestamp}.${retryWebhookBody}`)
    .digest("hex")}`;
  const parsedRetry = parseMakePayWebhook(
    retryWebhookBody,
    retryWebhookSignature,
    contract.webhookSecret,
  );
  const { deliveryId: firstDeliveryId, ...stableFirst } = parsed;
  const { deliveryId: retryDeliveryId, ...stableRetry } = parsedRetry;
  assert.equal(firstDeliveryId, "delivery_contract");
  assert.equal(retryDeliveryId, "delivery_contract_retry");
  assert.deepEqual(stableRetry, stableFirst);

  assert.throws(
    () => parseMakePayWebhook(webhookBody, webhookSignature, "whsec_wrong"),
    /signature/i,
  );

  const staleTimestamp = timestamp - 301;
  const staleSignature = `t=${staleTimestamp},v1=${createHmac(
    "sha256",
    contract.webhookSecret,
  )
    .update(`${staleTimestamp}.${webhookBody}`)
    .digest("hex")}`;
  assert.throws(
    () =>
      parseMakePayWebhook(webhookBody, staleSignature, contract.webhookSecret, {
        toleranceSeconds: 300,
      }),
    /signature/i,
  );
  assert.doesNotThrow(() =>
    parseMakePayWebhook(webhookBody, staleSignature, contract.webhookSecret, {
      toleranceSeconds: 400,
    }),
  );

  await client.deleteCurrentWebhookSubscription({
    idempotencyKey: "idem_subscription_delete",
  });

  console.log("MakePay SDK HTTP and signed-webhook contract verified.");
} finally {
  await contract.close();
}
