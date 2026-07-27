import { expect, test } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { request as httpRequest } from "node:http";
import { captureEvidence } from "./support/evidence.mjs";
import { selectPurchasableProductOptions } from "./support/storefront-product-options.mjs";

const backendUrl = process.env.MAKEPAY_E2E_BACKEND_URL;
const secondBackendUrl = process.env.MAKEPAY_E2E_SECOND_BACKEND_URL;
const storefrontUrl = process.env.MAKEPAY_E2E_STOREFRONT_URL;
const contractUrl = process.env.MAKEPAY_E2E_CONTRACT_URL;
const controlToken = process.env.MAKEPAY_E2E_CONTROL_TOKEN;
const publishableKey = process.env.MAKEPAY_E2E_PUBLISHABLE_KEY;
const adminEmail = process.env.MAKEPAY_E2E_ADMIN_EMAIL;
const adminPassword = process.env.MAKEPAY_E2E_ADMIN_PASSWORD;
const apiKeyBackendUrl = process.env.MAKEPAY_E2E_API_KEY_BACKEND_URL;
const apiKeyPublishableKey = process.env.MAKEPAY_E2E_API_KEY_PUBLISHABLE_KEY;
const apiKeyAdminToken = process.env.MAKEPAY_E2E_API_KEY_ADMIN_TOKEN;
const apiKeyControlSocket = process.env.MAKEPAY_E2E_API_KEY_CONTROL_SOCKET;
const oauthControlSocket = process.env.MAKEPAY_E2E_OAUTH_CONTROL_SOCKET;
const runId = process.env.MAKEPAY_E2E_RUN_ID;
const capture = process.env.MAKEPAY_E2E_CAPTURE === "1";
const artifactProvenance = {
  plugin: {
    sha256: process.env.MAKEPAY_E2E_PLUGIN_SHA256,
    version: process.env.MAKEPAY_E2E_PLUGIN_VERSION,
  },
  sdk: {
    sha256: process.env.MAKEPAY_E2E_SDK_SHA256,
    version: process.env.MAKEPAY_E2E_SDK_VERSION,
  },
};
const makePayWebhookPath = "/hooks/makepay/makepay_makepay";
const evidenceDirectory =
  process.env.MAKEPAY_E2E_EVIDENCE_DIR ||
  "output/playwright/medusa-makepay/evidence";

for (const [name, value] of Object.entries({
  adminEmail,
  adminPassword,
  apiKeyAdminToken,
  apiKeyBackendUrl,
  apiKeyControlSocket,
  apiKeyPublishableKey,
  backendUrl,
  contractUrl,
  controlToken,
  oauthControlSocket,
  pluginSha256: artifactProvenance.plugin.sha256,
  pluginVersion: artifactProvenance.plugin.version,
  publishableKey,
  runId,
  secondBackendUrl,
  sdkSha256: artifactProvenance.sdk.sha256,
  sdkVersion: artifactProvenance.sdk.version,
  storefrontUrl,
})) {
  if (!value)
    throw new Error(`Missing required E2E environment variable: ${name}`);
}
if (apiKeyControlSocket === oauthControlSocket) {
  throw new Error("OAuth and API-key E2E controls must use different sockets.");
}

async function responseJson(response, label) {
  const text = await response.text();
  if (!response.ok()) {
    throw new Error(
      `${label} failed (${response.status()}): ${text.slice(0, 400)}`,
    );
  }
  return text ? JSON.parse(text) : {};
}

async function adminToken(request) {
  const response = await request.post(`${backendUrl}/auth/user/emailpass`, {
    data: { email: adminEmail, password: adminPassword },
  });
  const body = await responseJson(response, "Admin authentication");
  if (!body.token)
    throw new Error("Medusa admin authentication returned no token");
  return body.token;
}

async function findSingleAdminOrderByEmail(
  request,
  token,
  email,
  label,
  targetBackendUrl = backendUrl,
) {
  let matching = [];
  await expect
    .poll(async () => {
      const result = await responseJson(
        await request.get(
          `${targetBackendUrl}/admin/orders?q=${encodeURIComponent(email)}&limit=5&fields=id,display_id,email,total,status,payment_status`,
          { headers: { authorization: `Bearer ${token}` } },
        ),
        label,
      );
      matching = (result.orders || []).filter(
        (candidate) => candidate.email === email,
      );
      return matching.length;
    })
    .toBe(1);
  return matching[0];
}

async function enableMakePayForEurope(
  request,
  token,
  targetBackendUrl = backendUrl,
  targetPublishableKey = publishableKey,
) {
  const headers = { authorization: `Bearer ${token}` };
  const regions = await responseJson(
    await request.get(
      `${targetBackendUrl}/admin/regions?limit=100&fields=%2Bpayment_providers.*`,
      { headers },
    ),
    "List regions",
  );
  const region = regions.regions?.find(
    (candidate) => candidate.name === "Europe",
  );
  if (!region)
    throw new Error("The official seed did not create the Europe region");
  const current = (region.payment_providers || []).map((provider) =>
    typeof provider === "string" ? provider : provider.id,
  );
  if (!current.includes("pp_makepay_makepay")) {
    await responseJson(
      await request.post(`${targetBackendUrl}/admin/regions/${region.id}`, {
        data: { payment_providers: [...current, "pp_makepay_makepay"] },
        headers,
      }),
      "Enable MakePay in Europe",
    );
  }
  const providers = await responseJson(
    await request.get(
      `${targetBackendUrl}/store/payment-providers?region_id=${region.id}`,
      {
        headers: { "x-publishable-api-key": targetPublishableKey },
      },
    ),
    "List storefront payment providers",
  );
  expect(providers.payment_providers.map((provider) => provider.id)).toContain(
    "pp_makepay_makepay",
  );
  return region;
}

async function contractState(request) {
  return responseJson(
    await request.get(`${contractUrl}/__e2e/state`, {
      headers: { "x-e2e-control-token": controlToken },
    }),
    "Read MakePay contract state",
  );
}

async function waitForLinkOrderCorrelation(request, uid, order) {
  expect(order.display_id).toBeTruthy();
  await expect
    .poll(async () => {
      const state = await contractState(request);
      const correlated = state.links.find((candidate) => candidate.uid === uid);
      return correlated
        ? {
            orderDisplayId: correlated.metadata?.medusaOrderDisplayId,
            orderId: correlated.metadata?.medusaOrderId,
          }
        : null;
    })
    .toEqual({
      orderDisplayId: String(order.display_id),
      orderId: order.id,
    });
}

async function emit(request, data) {
  const response = await emitResponse(request, data);
  return responseJson(response, `Emit ${data.status} webhook`);
}

async function emitResponse(request, data) {
  return request.post(`${contractUrl}/__e2e/emit`, {
    data,
    headers: { "x-e2e-control-token": controlToken },
  });
}

async function prepareWebhook(request, data) {
  return responseJson(
    await emitResponse(request, { ...data, defer: true }),
    `Prepare ${data.status} webhook`,
  );
}

async function deliverPreparedWebhook(request, preparedId) {
  return responseJson(
    await request.post(`${contractUrl}/__e2e/deliver`, {
      data: { preparedId },
      headers: { "x-e2e-control-token": controlToken },
    }),
    "Deliver prepared webhook",
  );
}

async function armNativeResetResponseLoss(request, count) {
  return responseJson(
    await request.post(`${contractUrl}/__e2e/native-reset-response-loss`, {
      data: { count },
      headers: { "x-e2e-control-token": controlToken },
    }),
    "Arm native reset response loss",
  );
}

async function oauthRefreshLatch(request, action) {
  const method = action === "state" ? "GET" : "POST";
  return responseJson(
    await request.fetch(
      `${contractUrl}/__e2e/oauth-refresh-latch/${action}`,
      {
        headers: { "x-e2e-control-token": controlToken },
        method,
      },
    ),
    `${action} OAuth refresh latch`,
  );
}

function oauthRefreshRequestCount(state) {
  return (state.requests || []).filter(
    (entry) =>
      entry.method === "POST" &&
      entry.pathname === "/oauth/token" &&
      entry.body?.grant_type === "refresh_token",
  ).length;
}

function canonicalDeliveryGroupId() {
  return `mpwhgrp_${randomUUID().replaceAll("-", "")}${randomUUID().replaceAll("-", "")}`;
}

function expectSynchronousWebhookReceived(receipt) {
  expect(receipt.responseStatus).toBe(200);
  expect(JSON.parse(receipt.responseText)).toEqual({ received: true });
}

async function releaseWorkflowLatch(request, uid) {
  return responseJson(
    await request.post(`${contractUrl}/__e2e/workflow-latch/release`, {
      data: { uid },
      headers: { "x-e2e-control-token": controlToken },
    }),
    "Release MakePay workflow latch",
  );
}

async function setLinkReadOverride(request, uid, values) {
  return responseJson(
    await request.post(`${contractUrl}/__e2e/link-read-override`, {
      data: { ...values, action: "set", uid },
      headers: { "x-e2e-control-token": controlToken },
    }),
    "Set bounded MakePay payment-link read override",
  );
}

async function clearLinkReadOverride(request, uid) {
  return responseJson(
    await request.post(`${contractUrl}/__e2e/link-read-override`, {
      data: { action: "clear", uid },
      headers: { "x-e2e-control-token": controlToken },
    }),
    "Clear bounded MakePay payment-link read override",
  );
}

function restrictedMedusaControl(socketPath, label, input) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(input);
    if (Buffer.byteLength(body) > 128 * 1024) {
      reject(new Error(`Restricted ${label} helper request is too large.`));
      return;
    }
    const controlRequest = httpRequest(
      {
        headers: {
          "content-length": Buffer.byteLength(body),
          "content-type": "application/json",
        },
        method: "POST",
        path: "/control",
        socketPath,
      },
      (response) => {
        const chunks = [];
        let length = 0;
        response.on("data", (chunk) => {
          length += chunk.length;
          if (length > 1024 * 1024) {
            controlRequest.destroy(
              new Error(`Restricted ${label} helper response is too large.`),
            );
            return;
          }
          chunks.push(chunk);
        });
        response.once("error", reject);
        response.once("end", () => {
          if (response.statusCode !== 200) {
            reject(new Error(`Restricted ${label} helper rejected the action.`));
            return;
          }
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
          } catch {
            reject(new Error(`Restricted ${label} helper returned invalid JSON.`));
          }
        });
      },
    );
    controlRequest.setTimeout(30_000, () => {
      controlRequest.destroy(
        new Error(`Restricted ${label} helper exceeded its time limit.`),
      );
    });
    controlRequest.once("error", reject);
    controlRequest.end(body);
  });
}

function oauthMedusaControl(input) {
  return restrictedMedusaControl(oauthControlSocket, "OAuth Medusa", input);
}

function apiKeyControl(input) {
  return restrictedMedusaControl(apiKeyControlSocket, "API-key Medusa", input);
}

async function assertAdminAuthBoundaries(request, token) {
  const before = await contractState(request);
  const probes = [
    ["GET", "/admin/makepay/connection"],
    ["POST", "/admin/makepay/oauth/start"],
    ["POST", "/admin/makepay/disconnect"],
    ["GET", "/admin/makepay/payments"],
    ["GET", "/admin/makepay/payments/mpay_e2e_missing"],
    ["POST", "/admin/makepay/payments/mpay_e2e_missing/reconcile"],
    ["GET", "/admin/makepay/orders/order_e2e_missing"],
  ];
  for (const [method, pathname] of probes) {
    const response = await request.fetch(`${backendUrl}${pathname}`, {
      method,
    });
    expect(
      response.status(),
      `${method} ${pathname} must require an authenticated Medusa Admin actor`,
    ).toBe(401);
  }
  const headers = { authorization: `Bearer ${token}` };
  const connection = await responseJson(
    await request.get(`${backendUrl}/admin/makepay/connection`, { headers }),
    "Read authenticated disconnected MakePay baseline",
  );
  expect(connection.connection).toMatchObject({
    connected: false,
    status: "disconnected",
  });
  const payments = await responseJson(
    await request.get(`${backendUrl}/admin/makepay/payments`, { headers }),
    "Read authenticated empty MakePay payment baseline",
  );
  expect(payments.payments || []).toHaveLength(0);
  const after = await contractState(request);
  expect(after.requests).toHaveLength(before.requests.length);
}

async function loginToAdmin(page) {
  await page.goto(`${backendUrl}/app`);
  const email = page.getByRole("textbox", { name: "Email" });
  const authenticatedNavigation = page
    .getByRole("link", { name: /orders|products/i })
    .first();
  await expect(email.or(authenticatedNavigation).first()).toBeVisible();
  if (await email.isVisible()) {
    await email.fill(adminEmail);
    await page.getByPlaceholder("Password").fill(adminPassword);
    const authentication = page.waitForResponse(
      (response) =>
        response.url() === `${backendUrl}/auth/user/emailpass` &&
        response.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Continue with Email" }).click();
    expect((await authentication).ok()).toBe(true);
  }
  await expect(page.locator("body")).toContainText(
    /orders|products|dashboard/i,
  );
}

async function connectOAuth(page, request, token) {
  await page.goto(`${backendUrl}/app/settings/makepay`);
  await expect(page.getByTestId("makepay-settings-page")).toBeVisible();
  const connect = page.getByRole("button", {
    name: /connect makepay|reconnect/i,
  });
  const disconnect = page.getByRole("button", { name: "Disconnect" });
  await expect(connect.or(disconnect).first()).toBeVisible();
  if (await connect.isVisible()) {
    const oauthStart = page.waitForResponse(
      (response) =>
        response.url() === `${backendUrl}/admin/makepay/oauth/start` &&
        response.request().method() === "POST",
    );
    await connect.click();
    expect((await oauthStart).ok()).toBe(true);
    await page.waitForURL(
      new RegExp(
        `^${contractUrl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/oauth/authorize`,
      ),
    );
    await expect(
      page.getByText("Sandbox merchant: E2E Merchant"),
    ).toBeVisible();
    await page.getByTestId("approve").click();
    await page.waitForURL(
      (url) =>
        url.origin === new URL(backendUrl).origin &&
        url.pathname === "/app/settings/makepay",
    );
  }
  try {
    await expect
      .poll(async () => {
        const result = await responseJson(
          await request.get(`${backendUrl}/admin/makepay/connection`, {
            headers: { authorization: `Bearer ${token}` },
          }),
          "Read connected MakePay installation",
        );
        return {
          connected: result.connection?.connected,
          status: result.connection?.status,
          webhook: result.connection?.webhook?.status,
        };
      })
      .toEqual({ connected: true, status: "connected", webhook: "healthy" });
  } catch (error) {
    const diagnostic = await contractState(request).catch(() => ({
      requests: [],
    }));
    const requestSequence = (diagnostic.requests || [])
      .slice(-12)
      .map(
        ({ method, pathname, responseStatus }) =>
          `${method} ${pathname} -> ${responseStatus ?? "unfinished"}`,
      )
      .join("; ");
    throw new Error(
      `MakePay OAuth did not become healthy. Sanitized contract sequence: ${requestSequence || "unavailable"}. ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  await expect(disconnect).toBeVisible();

  const state = await contractState(request);
  const activeSubscriptions = state.subscriptions.filter(
    (subscription) => subscription.status === "active",
  );
  expect(activeSubscriptions).toHaveLength(1);
  expect(
    state.subscriptions.every((subscription) =>
      ["active", "disabled"].includes(subscription.status),
    ),
  ).toBe(true);
  const callback = new URL(activeSubscriptions[0].callbackUrl);
  expect(callback.origin).toBe(new URL(backendUrl).origin);
  expect(callback.pathname).toBe(makePayWebhookPath);
  expect(callback.search).toBe("");
  expect(callback.hash).toBe("");
}

async function assertPackedWebhookRouteBoundaries(request) {
  const wrongProvider = await request.post(
    `${backendUrl}/hooks/makepay/not_makepay`,
    {
      data: { schemaVersion: "medusa.v1" },
      headers: { "x-makepay-signature": "t=0,v1=invalid" },
    },
  );
  expect(wrongProvider.status()).toBe(400);
  expect(await wrongProvider.json()).toEqual({
    message: "Invalid MakePay webhook.",
  });

  const unknownPayment = await request.post(
    `${backendUrl}${makePayWebhookPath}`,
    {
      data: { schemaVersion: "medusa.v1" },
      headers: {
        "x-makepay-delivery-group-id": `mpwhgrp_${"a".repeat(64)}`,
        "x-makepay-signature": "t=0,v1=invalid",
      },
    },
  );
  // OAuth secret selection is scoped to a known local payment projection.
  // An unknown routing envelope must fail before signature verification.
  expect(unknownPayment.status()).toBe(400);
  expect(await unknownPayment.json()).toEqual({
    message: "Invalid MakePay webhook.",
  });

  const oversized = await request.post(`${backendUrl}${makePayWebhookPath}`, {
    data: { padding: "x".repeat(65 * 1024) },
  });
  expect(oversized.status()).toBe(413);
}

const buyerEmail = (scenario) =>
  `makepay-medusa-e2e+${runId}-${scenario}@example.com`.toLowerCase();

async function createApiKeyStoreCheckout(
  request,
  region,
  scenario,
  { exerciseTransitionRecovery = false, refreshBeforeComplete = false } = {},
) {
  const headers = { "x-publishable-api-key": apiKeyPublishableKey };
  const jsonHeaders = {
    ...headers,
    "content-type": "application/json",
  };
  const products = await responseJson(
    await request.get(
      `${apiKeyBackendUrl}/store/products?region_id=${encodeURIComponent(region.id)}&limit=20&fields=id,title,*variants`,
      { headers },
    ),
    "List seeded API-key storefront products",
  );
  const product = (products.products || []).find(
    (candidate) => candidate.title === "Medusa T-Shirt",
  );
  const variant = product?.variants?.[0];
  expect(
    variant?.id,
    "The official seed must expose a product variant",
  ).toBeTruthy();

  let cart = (
    await responseJson(
      await request.post(`${apiKeyBackendUrl}/store/carts`, {
        data: { region_id: region.id },
        headers: jsonHeaders,
      }),
      "Create API-key storefront cart",
    )
  ).cart;
  cart = (
    await responseJson(
      await request.post(
        `${apiKeyBackendUrl}/store/carts/${cart.id}/line-items`,
        {
          data: { quantity: 1, variant_id: variant.id },
          headers: jsonHeaders,
        },
      ),
      "Add seeded line item to API-key storefront cart",
    )
  ).cart;
  const address = {
    address_1: "1 Medusa Way",
    city: "Copenhagen",
    country_code: "dk",
    first_name: "Ada",
    last_name: "API Key",
    phone: "+4512345678",
    postal_code: "2100",
  };
  const email = buyerEmail(`api-key-${scenario}`);
  cart = (
    await responseJson(
      await request.post(`${apiKeyBackendUrl}/store/carts/${cart.id}`, {
        data: {
          billing_address: address,
          email,
          shipping_address: address,
        },
        headers: jsonHeaders,
      }),
      "Address API-key storefront cart",
    )
  ).cart;
  const shipping = await responseJson(
    await request.get(
      `${apiKeyBackendUrl}/store/shipping-options?cart_id=${encodeURIComponent(cart.id)}`,
      { headers },
    ),
    "List API-key storefront shipping options",
  );
  const shippingOption = shipping.shipping_options?.[0];
  expect(
    shippingOption?.id,
    "The official seed must expose a cart shipping option",
  ).toBeTruthy();
  cart = (
    await responseJson(
      await request.post(
        `${apiKeyBackendUrl}/store/carts/${cart.id}/shipping-methods`,
        {
          data: { option_id: shippingOption.id },
          headers: jsonHeaders,
        },
      ),
      "Select API-key storefront shipping method",
    )
  ).cart;
  const collection = await responseJson(
    await request.post(`${apiKeyBackendUrl}/store/payment-collections`, {
      data: { cart_id: cart.id },
      headers: jsonHeaders,
    }),
    "Create API-key storefront payment collection",
  );
  const paymentSessionUrl = `${apiKeyBackendUrl}/store/payment-collections/${collection.payment_collection.id}/payment-sessions`;
  const paymentSessionRequest = () =>
    request.post(paymentSessionUrl, {
      data: {
        data: { cart_id: cart.id },
        provider_id: "pp_makepay_makepay",
      },
      headers: jsonHeaders,
    });
  let paymentSessionResponse = await paymentSessionRequest();
  if (exerciseTransitionRecovery) {
    expect(paymentSessionResponse.ok()).toBe(false);
    expect(paymentSessionResponse.status()).toBe(400);
    const transitionError = await paymentSessionResponse.json();
    expect(transitionError.type).toBe("not_allowed");
    expect(transitionError.message).toMatch(
      /pending oauth payment|restore oauth mode/i,
    );
    const beforeRecovery = await contractState(request);
    expect(
      beforeRecovery.links.filter(
        (candidate) => candidate.authMode === "api-key",
      ),
    ).toHaveLength(0);
    expect(
      await apiKeyControl({ action: "resolve-oauth-transition-fixture" }),
    ).toEqual({ resolved: true });
    paymentSessionResponse = await paymentSessionRequest();
  }
  let paymentCollection = (
    await responseJson(
      paymentSessionResponse,
      "Initialize API-key MakePay payment session",
    )
  ).payment_collection;
  let session = (paymentCollection.payment_sessions || []).find(
    (candidate) => candidate.provider_id === "pp_makepay_makepay",
  );
  expect(session?.status).toBe("pending_authorization");
  const previousSession = refreshBeforeComplete ? session : null;
  let preRefreshTotal = null;
  if (refreshBeforeComplete) {
    const lineItem = cart.items?.[0];
    preRefreshTotal = Number(cart.total);
    expect(Number.isFinite(preRefreshTotal)).toBe(true);
    expect(
      lineItem?.id,
      "The refreshed cart must retain its line item",
    ).toBeTruthy();
    cart = (
      await responseJson(
        await request.post(
          `${apiKeyBackendUrl}/store/carts/${cart.id}/line-items/${lineItem.id}`,
          {
            data: { quantity: 2 },
            headers: jsonHeaders,
          },
        ),
        "Refresh API-key cart total",
      )
    ).cart;
    cart = (
      await responseJson(
        await request.get(
          `${apiKeyBackendUrl}/store/carts/${cart.id}?fields=%2Bpayment_collection.payment_sessions`,
          { headers },
        ),
        "Retrieve refreshed API-key cart",
      )
    ).cart;
    expect(Number(cart.total)).toBeGreaterThan(preRefreshTotal);
    expect(
      Number(
        cart.items?.find((item) => item.id === lineItem.id)?.quantity,
      ),
    ).toBe(2);
    expect(
      cart.payment_collection?.payment_sessions || [],
      "Medusa cart refresh must delete every prior payment session",
    ).toHaveLength(0);
    expect(cart.payment_collection?.id).toBe(paymentCollection.id);
    paymentCollection = (
      await responseJson(
        await request.post(
          `${apiKeyBackendUrl}/store/payment-collections/${cart.payment_collection.id}/payment-sessions`,
          {
            data: {
              data: { cart_id: cart.id },
              provider_id: "pp_makepay_makepay",
            },
            headers: jsonHeaders,
          },
        ),
        "Initialize refreshed API-key MakePay payment session",
      )
    ).payment_collection;
    const sessions = (paymentCollection.payment_sessions || []).filter(
      (candidate) => candidate.provider_id === "pp_makepay_makepay",
    );
    expect(sessions).toHaveLength(1);
    session = sessions[0];
    expect(session.status).toBe("pending_authorization");
    expect(session.id).not.toBe(previousSession.id);
  }
  const completion = await responseJson(
    await request.post(`${apiKeyBackendUrl}/store/carts/${cart.id}/complete`, {
      headers: jsonHeaders,
    }),
    "Complete pending API-key storefront order",
  );
  expect(completion.type).toBe("order");
  expect(completion.order?.email).toBe(email);
  return {
    cart,
    email,
    order: completion.order,
    preRefreshTotal,
    previousSession,
    session,
  };
}

async function assertPendingAuthorizationCartSession(page, request) {
  const cookies = await page.context().cookies(storefrontUrl);
  const cartId = cookies.find(
    (cookie) => cookie.name === "_medusa_cart_id",
  )?.value;
  expect(
    cartId,
    "The official storefront must retain its Medusa cart ID",
  ).toBeTruthy();
  const result = await responseJson(
    await request.get(
      `${backendUrl}/store/carts/${encodeURIComponent(cartId)}`,
      { headers: { "x-publishable-api-key": publishableKey } },
    ),
    "Read the real Medusa cart payment session",
  );
  const makePaySessions = (
    result.cart?.payment_collection?.payment_sessions || []
  ).filter((session) => session.provider_id === "pp_makepay_makepay");
  expect(makePaySessions).toHaveLength(1);
  expect(makePaySessions[0].status).toBe("pending_authorization");
  return { cartId, session: makePaySessions[0] };
}

async function completeStorefrontCheckout(
  page,
  request,
  scenario = "captured",
  { beforeSubmitOrder } = {},
) {
  await page.goto(`${storefrontUrl}/dk/store`);
  const productLink = page
    .getByRole("link", { name: /Medusa T-Shirt/ })
    .first();
  await Promise.all([page.waitForURL(/\/dk\/products\//), productLink.click()]);
  await expect(
    page
      .getByTestId("product-title")
      .filter({ hasText: "Medusa T-Shirt" })
      .first(),
  ).toBeVisible();
  await selectPurchasableProductOptions(page);
  const productEndpoint = new URL(page.url());
  const [addToCartResponse] = await Promise.all([
    page.waitForResponse(
      (response) => {
        const responseUrl = new URL(response.url());
        return (
          response.request().method() === "POST" &&
          responseUrl.origin === productEndpoint.origin &&
          responseUrl.pathname === productEndpoint.pathname
        );
      },
    ),
    page.getByTestId("add-product-button").click(),
  ]);
  expect(addToCartResponse.ok()).toBe(true);
  await expect
    .poll(async () => {
      const cookies = await page.context().cookies(storefrontUrl);
      return cookies.some(
        (cookie) => cookie.name === "_medusa_cart_id" && Boolean(cookie.value),
      );
    })
    .toBe(true);
  await page.goto(`${storefrontUrl}/dk/cart`);
  await expect(page.getByTestId("product-row")).toHaveCount(1);
  await page.getByTestId("checkout-button").click();

  await page.getByTestId("shipping-first-name-input").fill("Ada");
  await page.getByTestId("shipping-last-name-input").fill("Test");
  await page.getByTestId("shipping-address-input").fill("1 Medusa Way");
  await page.getByTestId("shipping-postal-code-input").fill("2100");
  await page.getByTestId("shipping-city-input").fill("Copenhagen");
  await page.getByTestId("shipping-country-select").selectOption("dk");
  await page.getByTestId("shipping-email-input").fill(buyerEmail(scenario));
  await page.getByTestId("shipping-phone-input").fill("+4512345678");
  const billingSame = page.getByTestId("billing-address-checkbox");
  if (!(await billingSame.isChecked())) await billingSame.check();
  await page.getByTestId("submit-address-button").click();

  await expect(page.getByTestId("delivery-options-container")).toBeVisible();
  await page.getByTestId("delivery-option-radio").first().click();
  await page.getByTestId("submit-delivery-option-button").click();
  await expect(page.getByText("MakePay", { exact: true })).toBeVisible();
  await page.getByText("MakePay", { exact: true }).click();
  await page.getByTestId("submit-payment-button").click();
  await expect(page.getByTestId("payment-method-summary")).toContainText(
    "MakePay",
  );
  const pending = await assertPendingAuthorizationCartSession(page, request);
  await expect(page.locator("body")).toContainText(
    /€20\.00|EUR 20\.00|20\.00 €/,
  );
  if (beforeSubmitOrder) await beforeSubmitOrder(pending);
  await page.getByTestId("submit-order-button").click();
  await page.waitForURL(
    new RegExp(
      `^${contractUrl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/payment/`,
    ),
  );
}

test.describe.serial("MakePay on the official Medusa 2.17.2 starter", () => {
  test("OAuth, hosted checkout, signed capture, idempotency, and Admin UI", async ({
    page,
    request,
  }) => {
    const consoleErrors = [];
    const token = await adminToken(request);
    await assertAdminAuthBoundaries(request, token);
    await loginToAdmin(page);
    page.on("console", (message) => {
      if (message.type() === "error") consoleErrors.push(message.text());
    });
    await connectOAuth(page, request, token);
    await assertPackedWebhookRouteBoundaries(request);
    await enableMakePayForEurope(request, token);

    if (capture) {
      await captureEvidence({
        artifactProvenance,
        expectedPath: "/app/settings/makepay",
        expectedTitle: /medusa/i,
        name: "connected-makepay-settings",
        outputDirectory: evidenceDirectory,
        page,
        requiredTestIds: ["makepay-settings-page"],
        requiredTexts: ["MakePay", "Disconnect"],
        runId,
      });
    }

    await completeStorefrontCheckout(page, request, "captured");
    await expect(page.getByTestId("sandbox-checkout")).toBeVisible();
    await expect(
      page.getByText("Demo payment instructions only. Do not send real funds."),
    ).toBeVisible();
    await expect(page.locator("body")).toContainText(/Pay 20(?:\.0+)? EUR/);

    if (capture) {
      await captureEvidence({
        artifactProvenance,
        expectedPath: /\/payment\/pay_e2e_/,
        expectedTitle: /makepay sandbox checkout/i,
        name: "makepay-sandbox-checkout",
        outputDirectory: evidenceDirectory,
        page,
        requiredTestIds: ["sandbox-checkout", "start-payment"],
        requiredTexts: ["Sandbox mode", "Do not send real funds"],
        runId,
      });
    }

    const beforeStart = await contractState(request);
    expect(beforeStart.links).toHaveLength(1);
    const link = beforeStart.links[0];
    expect(Number(link.amount)).toBe(20);
    expect(link.fiatCurrency).toBe("EUR");
    expect(link.metadata.medusaSessionId).toBeTruthy();
    expect(link.metadata.medusaProviderId).toBe("makepay");
    expect(link.metadata).not.toHaveProperty("session_id");

    const initialProjectionResult = await responseJson(
      await request.get(
        `${backendUrl}/admin/makepay/payments?q=${encodeURIComponent(link.uid)}&limit=10`,
        { headers: { authorization: `Bearer ${token}` } },
      ),
      "Read initial MakePay projection",
    );
    const initialProjections = (initialProjectionResult.payments || []).filter(
      (projection) => projection.payment_link_uid === link.uid,
    );
    expect(initialProjections).toHaveLength(1);
    expect(initialProjections[0].session_id).toBe(
      link.metadata.medusaSessionId,
    );
    expect(initialProjections[0].medusa_status).toBe("pending_authorization");
    expect(initialProjections[0].provider_status).toBe("active");

    const order = await findSingleAdminOrderByEmail(
      request,
      token,
      buyerEmail("captured"),
      "Find captured Medusa order",
    );
    expect(
      order,
      "Order must exist before the hosted checkout can be shown",
    ).toBeTruthy();
    expect(Number(order.total)).toBe(20);
    await waitForLinkOrderCorrelation(request, link.uid, order);

    const checkoutState = new URL(link.returnUrl).searchParams.get("state");
    expect(checkoutState).toBeTruthy();
    const refreshRequestsBeforeRace = oauthRefreshRequestCount(
      await contractState(request),
    );
    expect(await oauthRefreshLatch(request, "arm")).toEqual({
      armed: true,
      held: true,
      hits: 0,
    });
    let latchReleased = false;
    let latchDisarmed = false;
    let primaryStatusRequest;
    let secondaryStatusRequest;
    const primaryStatusAbort = new AbortController();
    const secondaryStatusAbort = new AbortController();
    try {
      const expiredCredential = await oauthMedusaControl({
        action: "expire-oauth-access-token",
      });
      expect(
        Date.parse(expiredCredential.expiredExpiresAt),
      ).toBeLessThan(Date.now());
      expect(
        Date.parse(expiredCredential.previousExpiresAt),
      ).toBeGreaterThan(Date.parse(expiredCredential.expiredExpiresAt));

      const checkoutStatusPath = `/store/makepay/checkout-status?state=${encodeURIComponent(checkoutState)}`;
      primaryStatusRequest = fetch(`${backendUrl}${checkoutStatusPath}`, {
        headers: {
          accept: "application/json",
          "x-publishable-api-key": publishableKey,
        },
        signal: AbortSignal.any([
          primaryStatusAbort.signal,
          AbortSignal.timeout(45_000),
        ]),
      });
      void primaryStatusRequest.catch(() => undefined);
      await expect
        .poll(async () => {
          const latch = await oauthRefreshLatch(request, "state");
          return { held: latch.held, hits: latch.hits };
        })
        .toEqual({ held: true, hits: 1 });

      secondaryStatusRequest = fetch(
        `${secondBackendUrl}${checkoutStatusPath}`,
        {
          headers: {
            accept: "application/json",
            "x-publishable-api-key": publishableKey,
          },
          signal: AbortSignal.any([
            secondaryStatusAbort.signal,
            AbortSignal.timeout(45_000),
          ]),
        },
      );
      void secondaryStatusRequest.catch(() => undefined);
      await expect
        .poll(() =>
          oauthMedusaControl({ action: "oauth-refresh-lock-state" }),
        )
        .toEqual({ granted: 1, waiting: 1 });
      const releasedLatch = await oauthRefreshLatch(request, "release");
      latchReleased = true;
      expect(releasedLatch).toEqual({
        armed: true,
        held: false,
        hits: 1,
      });

      const [primaryStatusResponse, secondaryStatusResponse] =
        await Promise.all([primaryStatusRequest, secondaryStatusRequest]);
      expect(primaryStatusResponse.status).toBe(200);
      expect(secondaryStatusResponse.status).toBe(200);
      for (const response of [
        primaryStatusResponse,
        secondaryStatusResponse,
      ]) {
        expect(response.headers.get("cache-control")).toBe(
          "no-store, private",
        );
        expect(response.headers.get("pragma")).toBe("no-cache");
        expect(response.headers.get("referrer-policy")).toBe("no-referrer");
      }
      const [primaryStatus, secondaryStatus] = await Promise.all([
        primaryStatusResponse.json(),
        secondaryStatusResponse.json(),
      ]);
      for (const statusResult of [primaryStatus, secondaryStatus]) {
        expect(Object.keys(statusResult).sort()).toEqual([
          "payment",
          "terminal",
        ]);
        expect(Object.keys(statusResult.payment).sort()).toEqual([
          "status",
          "updated_at",
        ]);
      }
      expect(primaryStatus.payment?.status).toBe("pending_authorization");
      expect(secondaryStatus.payment?.status).toBe("pending_authorization");
      expect(await oauthRefreshLatch(request, "state")).toEqual({
        armed: true,
        held: false,
        hits: 1,
      });
      expect(
        oauthRefreshRequestCount(await contractState(request)),
      ).toBe(refreshRequestsBeforeRace + 1);

      const refreshedConnection = await responseJson(
        await request.get(`${backendUrl}/admin/makepay/connection`, {
          headers: { authorization: `Bearer ${token}` },
        }),
        "Read MakePay connection after cross-process refresh",
      );
      expect(refreshedConnection.connection).toMatchObject({
        connected: true,
        status: "connected",
        webhook: { status: "healthy" },
      });
      expect(
        Date.parse(refreshedConnection.connection.access_token_expires_at),
      ).toBeGreaterThan(Date.parse(expiredCredential.previousExpiresAt));
      expect(await oauthRefreshLatch(request, "disarm")).toEqual({
        armed: false,
        held: false,
        hits: 1,
      });
      latchDisarmed = true;

      const refreshRequestsBeforePersistenceCheck = oauthRefreshRequestCount(
        await contractState(request),
      );
      const secondExpiredCredential = await oauthMedusaControl({
        action: "expire-oauth-access-token",
      });
      const secondRefreshResponse = await fetch(
        `${backendUrl}${checkoutStatusPath}`,
        {
          headers: {
            accept: "application/json",
            "x-publishable-api-key": publishableKey,
          },
          signal: AbortSignal.timeout(45_000),
        },
      );
      expect(secondRefreshResponse.status).toBe(200);
      expect((await secondRefreshResponse.json()).payment?.status).toBe(
        "pending_authorization",
      );
      await expect
        .poll(async () =>
          oauthRefreshRequestCount(await contractState(request)),
        )
        .toBe(refreshRequestsBeforePersistenceCheck + 1);
      const twiceRefreshedConnection = await responseJson(
        await request.get(`${backendUrl}/admin/makepay/connection`, {
          headers: { authorization: `Bearer ${token}` },
        }),
        "Read MakePay connection after persisted refresh-token rotation",
      );
      expect(twiceRefreshedConnection.connection).toMatchObject({
        connected: true,
        status: "connected",
        webhook: { status: "healthy" },
      });
      expect(
        Date.parse(
          twiceRefreshedConnection.connection.access_token_expires_at,
        ),
      ).toBeGreaterThanOrEqual(
        Date.parse(secondExpiredCredential.previousExpiresAt),
      );
    } finally {
      if (!latchReleased) {
        await oauthRefreshLatch(request, "release").catch(() => undefined);
      }
      if (!latchDisarmed) {
        await oauthRefreshLatch(request, "disarm").catch(() => undefined);
      }
      primaryStatusAbort.abort();
      secondaryStatusAbort.abort();
      await Promise.allSettled(
        [primaryStatusRequest, secondaryStatusRequest].filter(Boolean),
      );
    }

    const invalidDeliveryId = `oauth-invalid-${randomUUID()}`;
    const invalidResponse = await emitResponse(request, {
      deliveryId: invalidDeliveryId,
      invalidSignature: true,
      status: "quoted",
      uid: link.uid,
      updateRemoteStatus: false,
    });
    expect(invalidResponse.status()).toBe(400);
    expect(await invalidResponse.text()).toMatch(
      /webhook callback failed \(401\)/i,
    );
    expect(
      (await contractState(request)).webhookAttempts.find(
        (attempt) => attempt.deliveryId === invalidDeliveryId,
      )?.responseStatus,
    ).toBe(401);

    const beforeLegacyProbe = await contractState(request);
    const beforeLegacyLink = beforeLegacyProbe.links.find(
      (candidate) => candidate.uid === link.uid,
    );
    const legacyDeliveryId = `legacy-oauth-route-${runId}`;
    const legacyRoute = await emitResponse(request, {
      callbackUrl: `${backendUrl}/hooks/payment/makepay_makepay`,
      deliveryId: legacyDeliveryId,
      status: "quoted",
      uid: link.uid,
      updateRemoteStatus: false,
    });
    expect(legacyRoute.status()).toBe(400);
    expect(await legacyRoute.text()).toMatch(
      /webhook callback failed \(404\)/i,
    );
    const afterLegacyProbe = await contractState(request);
    const rejectedLegacyAttempt = afterLegacyProbe.webhookAttempts.find(
      (attempt) => attempt.deliveryId === legacyDeliveryId,
    );
    expect(rejectedLegacyAttempt?.responseStatus).toBe(404);
    expect(
      afterLegacyProbe.links.find((candidate) => candidate.uid === link.uid)
        ?.latestSession,
    ).toEqual(beforeLegacyLink?.latestSession);

    const projectionAfterLegacyProbe = await responseJson(
      await request.get(
        `${backendUrl}/admin/makepay/payments?q=${encodeURIComponent(link.uid)}&limit=10`,
        { headers: { authorization: `Bearer ${token}` } },
      ),
      "Read MakePay projection after rejected legacy OAuth callback",
    );
    expect(projectionAfterLegacyProbe.payments?.[0]).toMatchObject({
      medusa_status: "pending_authorization",
      provider_status: "active",
    });
    const orderAfterLegacyProbe = await responseJson(
      await request.get(
        `${backendUrl}/admin/orders/${order.id}?fields=+payment_collections.payments.captures.*`,
        { headers: { authorization: `Bearer ${token}` } },
      ),
      "Read order after rejected legacy OAuth callback",
    );
    expect(
      (orderAfterLegacyProbe.order.payment_collections || []).flatMap(
        (collection) =>
          (collection.payments || []).flatMap(
            (payment) => payment.captures || [],
          ),
      ),
    ).toHaveLength(0);

    await page.getByTestId("start-payment").click();
    await expect(page.getByTestId("sandbox-address")).toContainText(
      "SANDBOX-DO-NOT-SEND",
    );
    await expect(page.locator("body")).toContainText(
      "Do not send cryptocurrency",
    );

    const deliveryAttemptIds = [randomUUID(), randomUUID(), randomUUID()];
    await expect(
      oauthMedusaControl({ action: "snapshot", uid: link.uid }),
    ).rejects.toThrow(/rejected the action/i);
    expect(
      await oauthMedusaControl({ action: "capture-failure-status" }),
    ).toEqual({
      armed: false,
      failureCount: 0,
      fixtureObjectCount: 0,
      matchedAttemptCount: 0,
    });
    const armedOAuthCaptureFailure = await oauthMedusaControl({
      action: "arm-capture-failure-once",
      sessionId: link.metadata.medusaSessionId,
    });
    expect(armedOAuthCaptureFailure).toMatchObject({
      armed: true,
      failureCount: 0,
      fixtureObjectCount: 4,
      matchedAttemptCount: 0,
      targetSessionId: link.metadata.medusaSessionId,
    });
    const firstAttempt = await emitResponse(request, {
      attempt: 1,
      deliveryId: deliveryAttemptIds[0],
      failWorkflowOnce: true,
      status: "complete",
      uid: link.uid,
    });
    expect(firstAttempt.status()).toBe(400);
    expect(await firstAttempt.text()).toMatch(
      /webhook callback failed \(503\)/i,
    );
    const heldAttemptState = await contractState(request);
    const heldAttempt = heldAttemptState.webhookAttempts.find(
      (attempt) => attempt.deliveryId === deliveryAttemptIds[0],
    );
    expect(heldAttempt).toBeTruthy();
    expect(heldAttempt.responseStatus).toBe(503);
    const deliveryGroupId = heldAttempt.deliveryGroupId;
    expect(deliveryGroupId).toMatch(/^mpwhgrp_[a-f0-9]{64}$/);

    let oauthCaptureFailureStatus;
    await expect
      .poll(
        async () => {
          const [result, captureFailureStatus] = await Promise.all([
            responseJson(
              await request.get(
                `${backendUrl}/admin/makepay/payments?q=${encodeURIComponent(link.uid)}&limit=10`,
                { headers: { authorization: `Bearer ${token}` } },
              ),
              "Read MakePay projection after injected workflow failure",
            ),
            oauthMedusaControl({ action: "capture-failure-status" }),
          ]);
          oauthCaptureFailureStatus = captureFailureStatus;
          const projection = result.payments?.[0];
          return projection
            ? {
                failureCount: captureFailureStatus.failureCount,
                medusaStatus: projection.medusa_status,
                matchedAttemptCount:
                  captureFailureStatus.matchedAttemptCount,
                providerStatus: projection.provider_status,
              }
            : null;
        },
        { timeout: 30_000 },
      )
      .toEqual({
        failureCount: 1,
        medusaStatus: "pending_authorization",
        matchedAttemptCount: 1,
        providerStatus: "complete",
      });
    expect(oauthCaptureFailureStatus).toMatchObject({
      armed: true,
      failureCount: 1,
      fixtureObjectCount: 4,
      matchedAttemptCount: 1,
    });
    expect(
      await oauthMedusaControl({ action: "disarm-capture-failure" }),
    ).toEqual({
      armed: false,
      failureCount: 0,
      fixtureObjectCount: 0,
      matchedAttemptCount: 0,
    });

    const beforeReturnState = await contractState(request);
    const beforeReturnLatch = beforeReturnState.workflowLatches.find(
      (candidate) => candidate.uid === link.uid,
    );
    expect(beforeReturnLatch).toMatchObject({ held: true });
    // The failed terminal callback already performs an authoritative MakePay
    // read. The return flow must add another read while the latch remains held.
    const hitsBeforeReturn = beforeReturnLatch?.hits;
    expect(Number.isInteger(hitsBeforeReturn)).toBe(true);
    expect(hitsBeforeReturn).toBeGreaterThanOrEqual(1);

    expect(link.returnUrl).toBeTruthy();
    const returnState = new URL(link.returnUrl).searchParams.get("state");
    expect(returnState).toBeTruthy();
    await page.goto(link.returnUrl);
    await expect(page.getByTestId("makepay-return-page")).toBeVisible();
    await expect(page.getByTestId("makepay-return-page")).toContainText(
      "Confirming your MakePay payment",
    );
    await page.waitForTimeout(2500);
    await expect(page).toHaveURL(/\/makepay\/return(?:\?|$)/);
    expect(new URL(page.url()).searchParams.has("makepay_state")).toBe(false);
    await expect
      .poll(async () => {
        const state = await contractState(request);
        return state.workflowLatches.find(
          (candidate) => candidate.uid === link.uid,
        )?.hits;
      })
      .toBeGreaterThan(hitsBeforeReturn);
    const heldState = await contractState(request);
    const heldLatch = heldState.workflowLatches.find(
      (candidate) => candidate.uid === link.uid,
    );
    expect(heldLatch).toMatchObject({ held: true });
    expect(heldLatch?.hits).toBeGreaterThan(hitsBeforeReturn);

    const beforeRetryOrder = await responseJson(
      await request.get(
        `${backendUrl}/admin/orders/${order.id}?fields=+payment_collections.payments.captures.*`,
        { headers: { authorization: `Bearer ${token}` } },
      ),
      "Retrieve order after injected workflow failure",
    );
    const beforeRetryPayments =
      beforeRetryOrder.order.payment_collections?.flatMap(
        (collection) => collection.payments || [],
      ) || [];
    expect(
      beforeRetryPayments.flatMap((payment) => payment.captures || []),
    ).toHaveLength(0);

    const release = await releaseWorkflowLatch(request, link.uid);
    expect(release).toMatchObject({ held: false, ok: true, uid: link.uid });

    const concurrentResults = await Promise.all([
      emit(request, {
        attempt: 2,
        deliveryGroupId,
        deliveryId: deliveryAttemptIds[1],
        status: "complete",
        uid: link.uid,
      }),
      emit(request, {
        attempt: 3,
        callbackUrl: `${secondBackendUrl}${makePayWebhookPath}`,
        deliveryGroupId,
        deliveryId: deliveryAttemptIds[2],
        status: "complete",
        uid: link.uid,
      }),
      request.post(
        `${backendUrl}/admin/makepay/payments/${initialProjections[0].id}/reconcile`,
        { headers: { authorization: `Bearer ${token}` } },
      ),
    ]);
    await responseJson(
      concurrentResults[2],
      "Concurrent Admin MakePay reconciliation",
    );
    const afterRetries = await contractState(request);
    const retryAttempts = afterRetries.webhookAttempts.filter(
      (attempt) => attempt.deliveryGroupId === deliveryGroupId,
    );
    expect(retryAttempts).toHaveLength(3);
    expect(
      new Set(retryAttempts.map((attempt) => attempt.deliveryId)).size,
    ).toBe(3);
    expect(
      new Set(retryAttempts.map((attempt) => attempt.deliveryGroupId)),
    ).toEqual(new Set([deliveryGroupId]));
    expect(
      retryAttempts
        .map(({ attempt, responseStatus }) => ({ attempt, responseStatus }))
        .sort((left, right) => left.attempt - right.attempt),
    ).toEqual([
      { attempt: 1, responseStatus: 503 },
      { attempt: 2, responseStatus: 200 },
      { attempt: 3, responseStatus: 200 },
    ]);
    await page.waitForURL(new RegExp(`/dk/order/${order.id}/confirmed`), {
      timeout: 60_000,
    });
    await expect(page.locator("body")).toContainText(
      /thank you|order confirmed/i,
    );

    await page.goto(`${backendUrl}/app/makepay`);
    await expect(page.getByTestId("makepay-payments-page")).toBeVisible();
    await expect(page.locator("body")).toContainText(link.uid);
    await expect(page.locator("body")).toContainText(/captured|complete/i);

    if (capture) {
      await captureEvidence({
        artifactProvenance,
        expectedPath: "/app/makepay",
        expectedTitle: /medusa/i,
        name: "makepay-payments-list",
        outputDirectory: evidenceDirectory,
        page,
        requiredTestIds: [
          "makepay-payments-page",
          "makepay-sidebar-logo",
        ],
        requiredTexts: ["MakePay payments", link.uid],
        runId,
      });
    }

    await page.goto(`${backendUrl}/app/orders/${order.id}`);
    await expect(page.getByTestId("makepay-order-widget")).toBeVisible();
    await expect(page.getByTestId("makepay-order-widget")).toContainText(
      link.uid,
    );
    await expect(page.getByTestId("makepay-order-widget")).toContainText(
      /captured|complete/i,
    );
    await expect(page.getByTestId("makepay-order-widget")).toContainText(
      /automated refunds aren't supported/i,
    );
    await expect(page.getByTestId("makepay-order-widget")).toContainText(
      /verify.*off-platform.*refund.*settled/i,
    );

    if (capture) {
      await captureEvidence({
        artifactProvenance,
        expectedPath: new RegExp(`/app/orders/${order.id}$`),
        expectedTitle: /medusa/i,
        name: "makepay-order-widget",
        outputDirectory: evidenceDirectory,
        page,
        requiredTestIds: ["makepay-order-widget"],
        requiredTexts: [
          "MakePay",
          link.uid,
          "Automated refunds aren't supported",
        ],
        runId,
      });
    }

    await setLinkReadOverride(request, link.uid, {
      reads: 20,
      status: "pending",
    });
    await page.goto(link.returnUrl);
    await expect
      .poll(() => {
        const current = new URL(page.url());
        return {
          hasMakePayState: current.searchParams.has("makepay_state"),
          pathname: current.pathname,
        };
      })
      .toEqual({
        hasMakePayState: false,
        pathname: "/dk/makepay/return",
      });
    await expect(page.getByTestId("makepay-return-page")).toContainText(
      "Payment confirmed. Open your order history or confirmation email for details.",
    );
    await expect(page.locator("body")).not.toContainText(order.id);
    await expect(page.locator("body")).not.toContainText(link.uid);
    const staleReturnReadState = await contractState(request);
    const staleReturnOverride = staleReturnReadState.linkReadOverrides.find(
      (candidate) => candidate.uid === link.uid,
    );
    expect(staleReturnOverride?.remaining ?? 0).toBeLessThan(20);
    await clearLinkReadOverride(request, link.uid);
    const projectionAfterStaleReturn = await responseJson(
      await request.get(
        `${backendUrl}/admin/makepay/payments?q=${encodeURIComponent(link.uid)}&limit=10`,
        { headers: { authorization: `Bearer ${token}` } },
      ),
      "Read terminal projection after stale return reconciliation",
    );
    expect(projectionAfterStaleReturn.payments?.[0]).toMatchObject({
      medusa_status: "paid",
      provider_status: "complete",
    });

    const staleTerminal = await emitResponse(request, {
      deliveryId: `delivery-regression-${runId}`,
      status: "failed",
      uid: link.uid,
    });
    expect(staleTerminal.status()).toBe(400);
    expect(await staleTerminal.text()).toMatch(
      /webhook callback failed \(400\)/i,
    );
    const staleTerminalState = await contractState(request);
    const staleTerminalAttempt = staleTerminalState.webhookAttempts.find(
      (attempt) => attempt.deliveryId === `delivery-regression-${runId}`,
    );
    expect(staleTerminalAttempt?.responseStatus).toBe(400);
    const staleTerminalProjection = await responseJson(
      await request.get(
        `${backendUrl}/admin/makepay/payments?q=${encodeURIComponent(link.uid)}&limit=10`,
        { headers: { authorization: `Bearer ${token}` } },
      ),
      "Read MakePay projection after stale terminal webhook",
    );
    expect(staleTerminalProjection.payments?.[0]).toMatchObject({
      medusa_status: "paid",
      provider_status: "complete",
    });
    await page.goto(`${backendUrl}/app/orders/${order.id}`);
    await expect(page.getByTestId("makepay-order-widget")).toContainText(
      /captured|complete/i,
    );

    const duplicateCheck = await responseJson(
      await request.get(
        `${backendUrl}/admin/orders/${order.id}?fields=+payment_collections.payments.*`,
        {
          headers: { authorization: `Bearer ${token}` },
        },
      ),
      "Retrieve captured order",
    );
    const payments = duplicateCheck.order.payment_collections?.flatMap(
      (collection) => collection.payments || [],
    );
    expect(payments).toHaveLength(1);
    const captures = payments[0]?.captures || [];
    expect(captures).toHaveLength(1);

    const refundResponse = await request.post(
      `${backendUrl}/admin/payments/${payments[0].id}/refund`,
      {
        data: { amount: 5, note: "MakePay E2E unsupported refund check" },
        headers: { authorization: `Bearer ${token}` },
      },
    );
    expect(refundResponse.ok()).toBe(false);
    expect(await refundResponse.text()).toMatch(
      /refunds are not supported|does not expose a merchant refund api/i,
    );
    const paymentAfterRefund = await responseJson(
      await request.get(
        `${backendUrl}/admin/payments/${payments[0].id}?fields=%2Brefunds.*%2C%2Bcaptures.*`,
        { headers: { authorization: `Bearer ${token}` } },
      ),
      "Retrieve payment after unsupported refund",
    );
    expect(paymentAfterRefund.payment.refunds || []).toHaveLength(0);
    expect(paymentAfterRefund.payment.captures || []).toHaveLength(1);

    let preparedRace;
    let raceLink;
    let raceProjectionCreatedAt;
    await completeStorefrontCheckout(page, request, "pre-correlation", {
      beforeSubmitOrder: async ({ session }) => {
        const beforeOrderState = await contractState(request);
        raceLink = beforeOrderState.links.find(
          (candidate) => candidate.metadata?.medusaSessionId === session.id,
        );
        expect(raceLink).toBeTruthy();
        expect(raceLink.metadata?.medusaOrderId ?? null).toBeNull();
        const projectionResult = await responseJson(
          await request.get(
            `${backendUrl}/admin/makepay/payments?q=${encodeURIComponent(raceLink.uid)}&limit=10`,
            { headers: { authorization: `Bearer ${token}` } },
          ),
          "Read pre-correlation MakePay projection",
        );
        const projection = projectionResult.payments?.find(
          (candidate) => candidate.payment_link_uid === raceLink.uid,
        );
        expect(projection?.created_at).toBeTruthy();
        raceProjectionCreatedAt = projection.created_at;
        preparedRace = await prepareWebhook(request, {
          deliveryGroupId: canonicalDeliveryGroupId(),
          orderDisplayId: null,
          orderId: null,
          status: "complete",
          uid: raceLink.uid,
        });
        expect(preparedRace.preparedId).toBeTruthy();
        expect((await contractState(request)).preparedWebhookCount).toBe(1);
      },
    });
    const raceOrder = await findSingleAdminOrderByEmail(
      request,
      token,
      buyerEmail("pre-correlation"),
      "Find pre-correlation Medusa order",
    );
    await waitForLinkOrderCorrelation(request, raceLink.uid, raceOrder);
    const raceNegativeEvents = [
      {
        eventCreatedAt: new Date(
          new Date(raceProjectionCreatedAt).getTime() - 61_000,
        ).toISOString(),
        orderDisplayId: null,
        orderId: null,
      },
      {
        eventCreatedAt: new Date(Date.now() + 61_000).toISOString(),
        orderDisplayId: null,
        orderId: null,
      },
      {
        eventCreatedAt: "not-an-iso-date",
        orderDisplayId: null,
        orderId: null,
      },
      {
        orderDisplayId: String(raceOrder.display_id),
        orderId: "order_wrong_e2e",
      },
      {
        orderDisplayId: "999999",
        orderId: raceOrder.id,
      },
    ];
    for (const [index, negative] of raceNegativeEvents.entries()) {
      const rejected = await emitResponse(request, {
        deliveryGroupId: canonicalDeliveryGroupId(),
        deliveryId: `pre-correlation-rejected-${index}-${randomUUID()}`,
        status: "complete",
        uid: raceLink.uid,
        updateRemoteStatus: false,
        ...negative,
      });
      expect(rejected.status()).toBe(400);
      expect(await rejected.text()).toMatch(/webhook callback failed \(400\)/i);
    }
    const raceBeforeDelivery = await responseJson(
      await request.get(
        `${backendUrl}/admin/orders/${raceOrder.id}?fields=%2Bpayment_collections.payment_sessions.*%2C%2Bpayment_collections.payments.captures.*`,
        { headers: { authorization: `Bearer ${token}` } },
      ),
      "Read order after rejected pre-correlation events",
    );
    expect(
      (raceBeforeDelivery.order.payment_collections || []).flatMap(
        (collection) => collection.payments || [],
      ),
    ).toHaveLength(0);
    const deliveredRace = await deliverPreparedWebhook(
      request,
      preparedRace.preparedId,
    );
    expectSynchronousWebhookReceived(deliveredRace);
    expect((await contractState(request)).preparedWebhookCount).toBe(0);
    await expect
      .poll(async () => {
        const result = await responseJson(
          await request.get(
            `${backendUrl}/admin/orders/${raceOrder.id}?fields=%2Bpayment_collections.payment_sessions.*%2C%2Bpayment_collections.payments.captures.*`,
            { headers: { authorization: `Bearer ${token}` } },
          ),
          "Read captured pre-correlation order",
        );
        const collections = result.order.payment_collections || [];
        const racePayments = collections.flatMap(
          (collection) => collection.payments || [],
        );
        return {
          captures: racePayments.flatMap((payment) => payment.captures || [])
            .length,
          payments: racePayments.length,
        };
      })
      .toEqual({ captures: 1, payments: 1 });
    const duplicateRace = await emit(request, {
      deliveryGroupId: preparedRace.deliveryGroupId,
      deliveryId: `pre-correlation-duplicate-${randomUUID()}`,
      status: "complete",
      uid: raceLink.uid,
    });
    expectSynchronousWebhookReceived(duplicateRace);
    const raceRegression = await emitResponse(request, {
      deliveryGroupId: canonicalDeliveryGroupId(),
      deliveryId: `pre-correlation-regression-${randomUUID()}`,
      status: "failed",
      uid: raceLink.uid,
      updateRemoteStatus: false,
    });
    expect(raceRegression.status()).toBe(400);
    const raceFinal = await responseJson(
      await request.get(
        `${backendUrl}/admin/orders/${raceOrder.id}?fields=%2Bpayment_collections.payments.captures.*`,
        { headers: { authorization: `Bearer ${token}` } },
      ),
      "Read final pre-correlation order",
    );
    const raceFinalPayments = (
      raceFinal.order.payment_collections || []
    ).flatMap((collection) => collection.payments || []);
    expect(raceFinalPayments).toHaveLength(1);
    expect(raceFinalPayments[0].captures || []).toHaveLength(1);

    const terminalScenarios = [];
    for (const status of ["failed", "cancelled", "expired"]) {
      await completeStorefrontCheckout(page, request, status);
      const scenarioState = await contractState(request);
      const scenarioLink = scenarioState.links.at(-1);
      expect(scenarioLink.uid).not.toBe(link.uid);

      const terminalOrder = await findSingleAdminOrderByEmail(
        request,
        token,
        buyerEmail(status),
        `Find ${status} Medusa order`,
      );
      expect(terminalOrder).toBeTruthy();
      await waitForLinkOrderCorrelation(
        request,
        scenarioLink.uid,
        terminalOrder,
      );
      const terminalLinkCount = scenarioState.links.length;
      await emit(request, {
        deliveryId: `delivery-${status}-${runId}`,
        status,
        uid: scenarioLink.uid,
      });

      await expect
        .poll(
          async () => {
            const result = await responseJson(
              await request.get(
                `${backendUrl}/admin/makepay/payments?q=${encodeURIComponent(scenarioLink.uid)}&limit=10`,
                { headers: { authorization: `Bearer ${token}` } },
              ),
              `Read ${status} MakePay projection`,
            );
            const projection = result.payments?.[0];
            return projection
              ? {
                  medusaStatus: projection.medusa_status,
                  providerStatus: projection.provider_status,
                }
              : null;
          },
          { timeout: 30_000 },
        )
        .toEqual({
          medusaStatus: status === "failed" ? "failed" : "canceled",
          providerStatus: status,
        });

      const terminalDetails = await responseJson(
        await request.get(
          `${backendUrl}/admin/orders/${terminalOrder.id}?fields=%2Bpayment_collections.payment_sessions.*%2C%2Bpayment_collections.payments.captures.*%2C%2Bfulfillments.*`,
          { headers: { authorization: `Bearer ${token}` } },
        ),
        `Retrieve ${status} order details`,
      );
      const terminalCollections =
        terminalDetails.order.payment_collections || [];
      const terminalSessions = terminalCollections
        .flatMap((collection) => collection.payment_sessions || [])
        .filter((session) => session.provider_id === "pp_makepay_makepay");
      expect(terminalSessions).toHaveLength(1);
      expect(terminalSessions[0].status).toBe(
        status === "failed" ? "error" : "canceled",
      );
      expect(terminalSessions[0].data?.payment_link_uid).toBe(scenarioLink.uid);
      const terminalPayments = terminalCollections.flatMap(
        (collection) => collection.payments || [],
      );
      expect(
        terminalPayments.flatMap((payment) => payment.captures || []),
      ).toHaveLength(0);
      expect(terminalDetails.order.fulfillments || []).toHaveLength(0);
      const afterTerminalState = await contractState(request);
      expect(afterTerminalState.links).toHaveLength(terminalLinkCount);
      const unchangedTerminalLink = afterTerminalState.links.find(
        (candidate) => candidate.uid === scenarioLink.uid,
      );
      expect(unchangedTerminalLink).toBeTruthy();
      expect(unchangedTerminalLink.status).not.toBe("archived");
      terminalScenarios.push({
        link: unchangedTerminalLink,
        order: terminalOrder,
        session: terminalSessions[0],
        status,
      });
    }

    await page.goto(`${backendUrl}/app/settings/makepay`);
    const beforeDisconnectState = await contractState(request);
    const beforeResetRequests = beforeDisconnectState.requests.filter(
      (entry) =>
        entry.method === "DELETE" &&
        entry.pathname === "/oauth/native/installations",
    );
    expect(await armNativeResetResponseLoss(request, 2)).toEqual({
      count: 2,
      ok: true,
    });
    page.once("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: "Disconnect" }).click();
    await expect(
      page.getByRole("button", { name: "Retry disconnect" }),
    ).toBeVisible();
    const pendingDisconnectState = await contractState(request);
    const disconnectRequestTrace = pendingDisconnectState.requests
      .slice(-12)
      .map(({ method, pathname, responseStatus }) => ({
        method,
        pathname,
        responseStatus,
      }));
    expect(
      pendingDisconnectState.nativeResetResponseLosses,
      `Disconnect stopped before consuming the armed native-reset losses. Recent sanitized MakePay requests: ${JSON.stringify(disconnectRequestTrace)}`,
    ).toBe(0);
    const pendingResetRequests = pendingDisconnectState.requests.filter(
      (entry) =>
        entry.method === "DELETE" &&
        entry.pathname === "/oauth/native/installations",
    );
    expect(pendingResetRequests).toHaveLength(beforeResetRequests.length + 2);
    const lostResetRequests = pendingResetRequests.slice(
      beforeResetRequests.length,
    );
    expect(
      new Set(lostResetRequests.map((entry) => entry.idempotencyKey)).size,
    ).toBe(1);
    const retryDisconnectResponse = page.waitForResponse(
      (response) =>
        response.url() === `${backendUrl}/admin/makepay/disconnect` &&
        response.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Retry disconnect" }).click();
    expect((await retryDisconnectResponse).ok()).toBe(true);
    await expect(
      page.getByRole("button", {
        name: "Retry disconnect",
        exact: true,
      }),
    ).toBeHidden();
    await expect(
      page.getByRole("button", { name: "Connect MakePay", exact: true }),
    ).toBeVisible();
    const disconnectedState = await contractState(request);
    const completedResetRequests = disconnectedState.requests.filter(
      (entry) =>
        entry.method === "DELETE" &&
        entry.pathname === "/oauth/native/installations",
    );
    expect(completedResetRequests).toHaveLength(beforeResetRequests.length + 3);
    expect(
      new Set(
        completedResetRequests
          .slice(beforeResetRequests.length)
          .map((entry) => entry.idempotencyKey),
      ).size,
    ).toBe(1);
    await connectOAuth(page, request, token);
    await expect(
      page.getByRole("button", { name: "Disconnect" }),
    ).toBeVisible();

    const beforeHistoricalCompletion = await contractState(request);
    expect(
      beforeHistoricalCompletion.subscriptions.filter(
        (subscription) => subscription.status === "disabled",
      ).length,
    ).toBeGreaterThanOrEqual(1);
    expect(
      beforeHistoricalCompletion.subscriptions.filter(
        (subscription) => subscription.status === "active",
      ),
    ).toHaveLength(1);
    const historicalLinkCount = beforeHistoricalCompletion.links.length;
    for (const scenario of terminalScenarios) {
      const historicalGroup = canonicalDeliveryGroupId();
      const completed = await emit(request, {
        deliveryGroupId: historicalGroup,
        deliveryId: `historical-${scenario.status}-complete-${randomUUID()}`,
        status: "complete",
        uid: scenario.link.uid,
      });
      expectSynchronousWebhookReceived(completed);
      await expect
        .poll(async () => {
          const result = await responseJson(
            await request.get(
              `${backendUrl}/admin/orders/${scenario.order.id}?fields=%2Bpayment_collections.payment_sessions.*%2C%2Bpayment_collections.payments.*%2C%2Bpayment_collections.payments.captures.*`,
              { headers: { authorization: `Bearer ${token}` } },
            ),
            `Read late ${scenario.status} settlement order`,
          );
          const collections = result.order.payment_collections || [];
          const latePayments = collections.flatMap(
            (collection) => collection.payments || [],
          );
          const lateSessions = collections
            .flatMap((collection) => collection.payment_sessions || [])
            .filter((session) => session.provider_id === "pp_makepay_makepay");
          return {
            captures: latePayments.flatMap((payment) => payment.captures || [])
              .length,
            paymentStatus: result.order.payment_status,
            payments: latePayments.length,
            sessionStatus: lateSessions[0]?.status,
            sessionUid: lateSessions[0]?.data?.payment_link_uid,
            sessions: lateSessions.length,
          };
        })
        .toEqual({
          captures: 1,
          paymentStatus: "captured",
          payments: 1,
          sessionStatus: "authorized",
          sessionUid: scenario.link.uid,
          sessions: 1,
        });
      const duplicateHistorical = await emit(request, {
        attempt: 2,
        deliveryGroupId: historicalGroup,
        deliveryId: `historical-${scenario.status}-duplicate-${randomUUID()}`,
        status: "complete",
        uid: scenario.link.uid,
      });
      expectSynchronousWebhookReceived(duplicateHistorical);
      const regression = await emitResponse(request, {
        deliveryGroupId: canonicalDeliveryGroupId(),
        deliveryId: `historical-${scenario.status}-regression-${randomUUID()}`,
        status: scenario.status,
        uid: scenario.link.uid,
        updateRemoteStatus: false,
      });
      expect(regression.status()).toBe(400);
      const finalProjection = await responseJson(
        await request.get(
          `${backendUrl}/admin/makepay/payments?q=${encodeURIComponent(scenario.link.uid)}&limit=10`,
          { headers: { authorization: `Bearer ${token}` } },
        ),
        `Read final late ${scenario.status} projection`,
      );
      expect(finalProjection.payments?.[0]).toMatchObject({
        medusa_status: "paid",
        payment_link_uid: scenario.link.uid,
        provider_status: "complete",
        session_id: scenario.session.id,
      });
      const unchangedOrder = await responseJson(
        await request.get(
          `${backendUrl}/admin/orders/${scenario.order.id}?fields=%2Bpayment_collections.payments.captures.*`,
          { headers: { authorization: `Bearer ${token}` } },
        ),
        `Read deduplicated late ${scenario.status} order`,
      );
      const unchangedPayments = (
        unchangedOrder.order.payment_collections || []
      ).flatMap((collection) => collection.payments || []);
      expect(unchangedPayments).toHaveLength(1);
      expect(unchangedPayments[0].captures || []).toHaveLength(1);
    }
    const afterHistoricalCompletion = await contractState(request);
    expect(afterHistoricalCompletion.links).toHaveLength(historicalLinkCount);
    for (const scenario of terminalScenarios) {
      expect(
        afterHistoricalCompletion.links.find(
          (candidate) => candidate.uid === scenario.link.uid,
        )?.uid,
      ).toBe(scenario.link.uid);
    }

    const relevantConsoleErrors = consoleErrors.filter(
      (message) => !/favicon|Failed to load resource.*404/i.test(message),
    );
    expect(relevantConsoleErrors).toEqual([]);
  });

  test("legacy inferred API-key mode, sparse webhooks, immutable sessions, and cancellation guards", async ({
    request,
  }) => {
    const region = await enableMakePayForEurope(
      request,
      apiKeyAdminToken,
      apiKeyBackendUrl,
      apiKeyPublishableKey,
    );
    const checkout = await createApiKeyStoreCheckout(
      request,
      region,
      "captured",
      { exerciseTransitionRecovery: true },
    );
    const stateAfterCheckout = await contractState(request);
    let link = stateAfterCheckout.links.find(
      (candidate) =>
        candidate.authMode === "api-key" &&
        candidate.metadata?.medusaSessionId === checkout.session.id,
    );
    expect(link, "API-key checkout must create one MakePay link").toBeTruthy();
    await waitForLinkOrderCorrelation(request, link.uid, checkout.order);
    link = (await contractState(request)).links.find(
      (candidate) => candidate.uid === link.uid,
    );
    expect(link).toBeTruthy();
    expect(link.payload.currency).toBe("USDT");
    expect(link.fiatCurrency).toBe("EUR");
    expect(link.metadata.medusaOrderId).toBe(checkout.order.id);

    const apiCreateAudit = stateAfterCheckout.requests
      .filter(
        (entry) =>
          entry.method === "POST" &&
          entry.pathname.endsWith("/makepay/payment-links"),
      )
      .at(-1);
    expect(apiCreateAudit).toMatchObject({
      hasApiKey: true,
      hasAuthorization: false,
      hasDpop: false,
      responseStatus: 201,
    });

    const initial = await apiKeyControl({
      action: "snapshot",
      orderId: checkout.order.id,
      sessionId: checkout.session.id,
      uid: link.uid,
    });
    expect(initial).toMatchObject({
      captureCount: 0,
      orderCount: 1,
      paymentCount: 0,
      projectionCount: 1,
      sessionCount: 1,
    });
    expect(initial.staleOAuthConnections).toEqual([
      {
        companyId: "company_e2e_stale_oauth",
        grantId: "grant_e2e_stale_oauth",
        installationId: "installation_e2e_stale_oauth",
        providerId: "makepay",
        subscriptionId: "subscription_e2e_stale_oauth",
      },
    ]);
    expect(initial.projection).toMatchObject({
      authMode: "api_key",
      companyId: link.companyId,
      currency: "EUR",
      grantId: null,
      installationId: null,
      medusaStatus: "pending_authorization",
      providerStatus: "active",
      sessionId: checkout.session.id,
      subscriptionId: null,
      uid: link.uid,
    });
    expect(initial.projection.companyId).not.toBe(
      initial.staleOAuthConnections[0].companyId,
    );
    expect(initial.selectedSession).toMatchObject({
      paymentLinkUid: link.uid,
      status: "pending_authorization",
    });

    const customProbeBaseline = await contractState(request);
    const customProbeIds = Array.from(
      { length: 5 },
      () => `api-key-custom-${randomUUID()}`,
    );
    for (const deliveryId of customProbeIds) {
      const customRoute = await emitResponse(request, {
        callbackUrl: `${apiKeyBackendUrl}${makePayWebhookPath}`,
        deliveryId,
        legacyProductionShape: true,
        status: "complete",
        uid: link.uid,
        updateRemoteStatus: false,
      });
      expect(customRoute.status()).toBe(400);
      expect(await customRoute.text()).toMatch(
        /webhook callback failed \(404\)/i,
      );
    }
    const customProbeState = await contractState(request);
    expect(
      customProbeState.webhookAttempts
        .filter((attempt) => customProbeIds.includes(attempt.deliveryId))
        .map((attempt) => attempt.responseStatus),
    ).toEqual([404, 404, 404, 404, 404]);
    expect(customProbeState.requests).toHaveLength(
      customProbeBaseline.requests.length,
    );
    const afterCustomProbe = await apiKeyControl({
      action: "snapshot",
      orderId: checkout.order.id,
      sessionId: checkout.session.id,
      uid: link.uid,
    });
    expect(afterCustomProbe).toMatchObject({
      captureCount: 0,
      orderCount: 1,
      paymentCount: 0,
      projectionCount: 1,
      sessionCount: 1,
    });
    expect(afterCustomProbe.deliveryCount).toBe(initial.deliveryCount);
    expect(afterCustomProbe.projection).toMatchObject({
      medusaStatus: "pending_authorization",
      providerStatus: "active",
      uid: link.uid,
    });

    const invalidDeliveryId = `api-key-invalid-${randomUUID()}`;
    const invalidResponse = await emitResponse(request, {
      callbackUrl: `${apiKeyBackendUrl}/hooks/payment/makepay_makepay`,
      deliveryId: invalidDeliveryId,
      invalidSignature: true,
      legacyProductionShape: true,
      status: "complete",
      uid: link.uid,
      updateRemoteStatus: false,
    });
    expect(invalidResponse.status()).toBe(400);
    expect(await invalidResponse.text()).toMatch(
      /webhook callback failed \(401\)/i,
    );
    expect(
      (await contractState(request)).webhookAttempts.find(
        (attempt) => attempt.deliveryId === invalidDeliveryId,
      )?.responseStatus,
    ).toBe(401);
    const afterInvalid = await apiKeyControl({
      action: "snapshot",
      sessionId: checkout.session.id,
      uid: link.uid,
    });
    expect(afterInvalid.captureCount).toBe(0);
    expect(afterInvalid.projection).toMatchObject({
      medusaStatus: "pending_authorization",
      providerStatus: "active",
    });

    const maliciousReceipt = await emit(request, {
      callbackUrl: `${apiKeyBackendUrl}/hooks/payment/makepay_makepay`,
      deliveryId: `api-key-unsigned-status-${randomUUID()}`,
      legacyData: { status: "complete" },
      legacyProductionShape: true,
      status: "pending",
      uid: link.uid,
    });
    expectSynchronousWebhookReceived(maliciousReceipt);
    const afterMaliciousStatus = await apiKeyControl({
      action: "snapshot",
      sessionId: checkout.session.id,
      uid: link.uid,
    });
    expect(afterMaliciousStatus.captureCount).toBe(0);
    expect(afterMaliciousStatus.selectedSession.status).toBe(
      "pending_authorization",
    );

    await setLinkReadOverride(request, link.uid, {
      amount: "999.99",
      fiatCurrency: "USD",
      reads: 100,
    });
    const wrongReadResponse = await emitResponse(request, {
      callbackUrl: `${apiKeyBackendUrl}/hooks/payment/makepay_makepay`,
      deliveryGroupId: `legacy-api-wrong-${randomUUID()}`,
      deliveryId: `api-key-wrong-read-${randomUUID()}`,
      legacyProductionShape: true,
      status: "complete",
      uid: link.uid,
    });
    expect(wrongReadResponse.status()).toBe(400);
    expect(await wrongReadResponse.text()).toMatch(
      /webhook callback failed \(503\)/i,
    );
    await expect
      .poll(
        async () => {
          const current = await contractState(request);
          return (
            current.linkReadOverrides.find(
              (candidate) => candidate.uid === link.uid,
            )?.remaining ?? 0
          );
        },
        { timeout: 30_000 },
      )
      .toBeLessThan(100);
    const afterWrongRead = await apiKeyControl({
      action: "snapshot",
      sessionId: checkout.session.id,
      uid: link.uid,
    });
    expect(afterWrongRead.captureCount).toBe(0);
    expect(afterWrongRead.selectedSession.status).toBe("pending_authorization");
    await clearLinkReadOverride(request, link.uid);

    const semanticDeliveryId = `api-key-semantic-${randomUUID()}`;
    const semanticCreatedAt = new Date().toISOString();
    const stableGroup = `legacy-api-stable-${randomUUID()}`;
    const prePaidReplayBase = {
      bodyDeliveryId: semanticDeliveryId,
      callbackUrl: `${apiKeyBackendUrl}/hooks/payment/makepay_makepay`,
      eventCreatedAt: semanticCreatedAt,
      legacyProductionShape: true,
      status: "complete",
      uid: link.uid,
    };
    let captured;
    let capturedPayment;
    let beforeCaptureDeliveryCount;
    try {
      const armed = await apiKeyControl({
        action: "arm-capture-failure-once",
        sessionId: checkout.session.id,
      });
      expect(armed).toMatchObject({
        armed: true,
        failureCount: 0,
        fixtureObjectCount: 4,
        matchedAttemptCount: 0,
        targetSessionId: checkout.session.id,
      });

      const scopeControlCheckout = await createApiKeyStoreCheckout(
        request,
        region,
        "capture-fault-scope-control",
      );
      const scopeControlState = await contractState(request);
      const scopeControlLink = scopeControlState.links.find(
        (candidate) =>
          candidate.authMode === "api-key" &&
          candidate.metadata?.medusaSessionId ===
            scopeControlCheckout.session.id,
      );
      expect(scopeControlLink).toBeTruthy();
      await waitForLinkOrderCorrelation(
        request,
        scopeControlLink.uid,
        scopeControlCheckout.order,
      );
      const scopeControlReceipt = await emit(request, {
        callbackUrl: `${apiKeyBackendUrl}/hooks/payment/makepay_makepay`,
        deliveryGroupId: `legacy-api-fault-scope-${randomUUID()}`,
        deliveryId: `api-key-fault-scope-${randomUUID()}`,
        legacyProductionShape: true,
        status: "complete",
        uid: scopeControlLink.uid,
      });
      expectSynchronousWebhookReceived(scopeControlReceipt);
      const scopeControlCaptured = await apiKeyControl({
        action: "snapshot",
        orderId: scopeControlCheckout.order.id,
        sessionId: scopeControlCheckout.session.id,
        uid: scopeControlLink.uid,
      });
      expect(scopeControlCaptured).toMatchObject({
        captureCount: 1,
        orderCount: 1,
        paymentCount: 1,
      });
      expect(scopeControlCaptured.projection).toMatchObject({
        medusaStatus: "paid",
        providerStatus: "complete",
      });
      expect(
        await apiKeyControl({ action: "capture-failure-status" }),
      ).toMatchObject({
        armed: true,
        failureCount: 0,
        fixtureObjectCount: 4,
        matchedAttemptCount: 0,
      });
      const scopeControlOrder = await findSingleAdminOrderByEmail(
        request,
        apiKeyAdminToken,
        scopeControlCheckout.email,
        "Read unrelated order through the armed capture fault",
        apiKeyBackendUrl,
      );
      expect(scopeControlOrder.payment_status).toBe("captured");

      beforeCaptureDeliveryCount = scopeControlCaptured.deliveryCount;
      const failedCaptureHeaderId = `api-key-fail-once-${randomUUID()}`;
      const failedCaptureResponse = await emitResponse(request, {
        ...prePaidReplayBase,
        deliveryGroupId: stableGroup,
        deliveryId: failedCaptureHeaderId,
      });
      expect(failedCaptureResponse.status()).toBe(400);
      expect(await failedCaptureResponse.text()).toMatch(
        /webhook callback failed \(503\)/i,
      );
      expect(
        (await contractState(request)).webhookAttempts.find(
          (attempt) => attempt.deliveryId === failedCaptureHeaderId,
        )?.responseStatus,
      ).toBe(503);

      let failedCaptureSnapshot;
      let firedStatus;
      await expect
        .poll(async () => {
          [failedCaptureSnapshot, firedStatus] = await Promise.all([
            apiKeyControl({
              action: "snapshot",
              orderId: checkout.order.id,
              sessionId: checkout.session.id,
              uid: link.uid,
            }),
            apiKeyControl({ action: "capture-failure-status" }),
          ]);
          const targetPayment = failedCaptureSnapshot.payments.find(
            (payment) => payment.sessionId === checkout.session.id,
          );
          const targetCaptureCount = failedCaptureSnapshot.captures.filter(
            (captureRecord) => captureRecord.paymentId === targetPayment?.id,
          ).length;
          return {
            captureCount: failedCaptureSnapshot.captureCount,
            deliveryCount: failedCaptureSnapshot.deliveryCount,
            effectClaimedAt:
              failedCaptureSnapshot.projection?.effectClaimedAt ?? null,
            failureCount: firedStatus.failureCount,
            matchedAttemptCount: firedStatus.matchedAttemptCount,
            medusaStatus: failedCaptureSnapshot.projection?.medusaStatus,
            providerStatus: failedCaptureSnapshot.projection?.providerStatus,
            targetCaptureCount,
          };
        })
        .toEqual({
          captureCount: 1,
          deliveryCount: beforeCaptureDeliveryCount + 1,
          effectClaimedAt: null,
          failureCount: 1,
          matchedAttemptCount: 1,
          medusaStatus: "pending_authorization",
          providerStatus: "complete",
          targetCaptureCount: 0,
        });
      const failedOrder = await findSingleAdminOrderByEmail(
        request,
        apiKeyAdminToken,
        checkout.email,
        "Read unpaid order after the injected capture failure",
        apiKeyBackendUrl,
      );
      expect(failedOrder.payment_status).not.toBe("captured");

      const redeliveryHeaderIds = [
        `api-key-redelivery-${randomUUID()}`,
        `api-key-prepaid-mutated-${randomUUID()}`,
      ];
      const [captureReceipt, concurrentMutatedHeaderReceipt] =
        await Promise.all([
          emit(request, {
            ...prePaidReplayBase,
            deliveryGroupId: stableGroup,
            deliveryId: redeliveryHeaderIds[0],
          }),
          emit(request, {
            ...prePaidReplayBase,
            deliveryGroupId: `legacy-api-prepaid-mutated-${randomUUID()}`,
            deliveryId: redeliveryHeaderIds[1],
          }),
        ]);
      expectSynchronousWebhookReceived(captureReceipt);
      expectSynchronousWebhookReceived(concurrentMutatedHeaderReceipt);
      const semanticAttempts = (await contractState(request)).webhookAttempts
        .filter((attempt) =>
          [failedCaptureHeaderId, ...redeliveryHeaderIds].includes(
            attempt.deliveryId,
          ),
        )
        .map((attempt) => attempt.bodySha256);
      expect(semanticAttempts).toHaveLength(3);
      expect(new Set(semanticAttempts).size).toBe(1);

      captured = await apiKeyControl({
        action: "snapshot",
        orderId: checkout.order.id,
        sessionId: checkout.session.id,
        uid: link.uid,
      });
      capturedPayment = captured.payments.find(
        (payment) => payment.sessionId === checkout.session.id,
      );
      const targetCaptures = captured.captures.filter(
        (captureRecord) => captureRecord.paymentId === capturedPayment?.id,
      );
      expect(targetCaptures).toHaveLength(1);
      expect(captured).toMatchObject({
        captureCount: 2,
        orderCount: 1,
        paymentCount: 2,
      });
      expect(captured.deliveryCount).toBe(failedCaptureSnapshot.deliveryCount);
      const finalFaultStatus = await apiKeyControl({
        action: "capture-failure-status",
      });
      expect(finalFaultStatus).toMatchObject({
        armed: true,
        failureCount: 1,
        fixtureObjectCount: 4,
      });
      expect(finalFaultStatus.matchedAttemptCount).toBeGreaterThanOrEqual(2);
    } finally {
      expect(await apiKeyControl({ action: "disarm-capture-failure" })).toEqual(
        {
          armed: false,
          failureCount: 0,
          fixtureObjectCount: 0,
          matchedAttemptCount: 0,
        },
      );
    }

    expect(captured.orderCount).toBe(1);
    expect(captured.projection).toMatchObject({
      authMode: "api_key",
      currency: "EUR",
      medusaStatus: "paid",
      providerStatus: "complete",
      uid: link.uid,
    });
    expect(captured.selectedSession).toMatchObject({
      paymentLinkUid: link.uid,
      status: "authorized",
    });
    expect(capturedPayment).toBeTruthy();
    expect(capturedPayment.capturedAt).toBeTruthy();
    expect(capturedPayment.canceledAt).toBeNull();

    const replayBase = {
      bodyDeliveryId: semanticDeliveryId,
      callbackUrl: `${apiKeyBackendUrl}/hooks/payment/makepay_makepay`,
      eventCreatedAt: semanticCreatedAt,
      legacyProductionShape: true,
      status: "complete",
      uid: link.uid,
    };
    const stableReplay = await emit(request, {
      ...replayBase,
      deliveryGroupId: stableGroup,
      deliveryId: `api-key-replay-same-group-${randomUUID()}`,
    });
    const mutatedHeaderReplay = await emit(request, {
      ...replayBase,
      deliveryGroupId: `legacy-api-mutated-${randomUUID()}`,
      deliveryId: `api-key-replay-mutated-header-${randomUUID()}`,
    });
    expectSynchronousWebhookReceived(stableReplay);
    expectSynchronousWebhookReceived(mutatedHeaderReplay);
    const afterReplays = await apiKeyControl({
      action: "snapshot",
      orderId: checkout.order.id,
      paymentId: capturedPayment.id,
      sessionId: checkout.session.id,
      uid: link.uid,
    });
    expect(afterReplays.captureCount).toBe(captured.captureCount);
    expect(afterReplays.deliveryCount).toBe(captured.deliveryCount);
    expect(afterReplays.selectedPayment).toMatchObject({
      canceledAt: null,
      capturedAt: capturedPayment.capturedAt,
    });

    const beforeCapturedMutations = await contractState(request);
    const linkPath = `/api/partner/v1/makepay/payment-links/${link.uid}`;
    const beforeArchiveCount = beforeCapturedMutations.requests.filter(
      (entry) => entry.method === "PATCH" && entry.pathname === linkPath,
    ).length;
    const beforeReadCount = beforeCapturedMutations.requests.filter(
      (entry) => entry.method === "GET" && entry.pathname === linkPath,
    ).length;
    expect(
      await apiKeyControl({
        action: "cancel-payment",
        paymentId: capturedPayment.id,
      }),
    ).toEqual({ error: "operation_rejected", ok: false });
    expect(
      await apiKeyControl({
        action: "delete-session",
        sessionId: checkout.session.id,
      }),
    ).toEqual({ error: "operation_rejected", ok: false });
    const afterCapturedMutations = await apiKeyControl({
      action: "snapshot",
      paymentId: capturedPayment.id,
      sessionId: checkout.session.id,
      uid: link.uid,
    });
    expect(afterCapturedMutations.captureCount).toBe(captured.captureCount);
    expect(afterCapturedMutations.selectedPayment.canceledAt).toBeNull();
    expect(afterCapturedMutations.selectedSession.id).toBe(checkout.session.id);
    const afterCapturedContractState = await contractState(request);
    expect(
      afterCapturedContractState.requests.filter(
        (entry) => entry.method === "PATCH" && entry.pathname === linkPath,
      ),
    ).toHaveLength(beforeArchiveCount);
    // An exact durable Medusa capture is sufficient to reject destructive
    // cancellation locally; neither operation should depend on a remote read.
    expect(
      afterCapturedContractState.requests.filter(
        (entry) => entry.method === "GET" && entry.pathname === linkPath,
      ).length,
    ).toBe(beforeReadCount);

    const refreshedCheckout = await createApiKeyStoreCheckout(
      request,
      region,
      "immutable-session-refresh",
      { refreshBeforeComplete: true },
    );
    expect(refreshedCheckout.previousSession).toBeTruthy();
    let refreshState = await contractState(request);
    const archivedLink = refreshState.links.find(
      (candidate) =>
        candidate.authMode === "api-key" &&
        candidate.metadata?.medusaSessionId ===
          refreshedCheckout.previousSession.id,
    );
    const refreshedLink = refreshState.links.find(
      (candidate) =>
        candidate.authMode === "api-key" &&
        candidate.metadata?.medusaSessionId === refreshedCheckout.session.id,
    );
    expect(archivedLink).toBeTruthy();
    expect(refreshedLink).toBeTruthy();
    expect(archivedLink.uid).not.toBe(refreshedLink.uid);
    expect(Number(archivedLink.amount)).toBe(
      refreshedCheckout.preRefreshTotal,
    );
    expect(archivedLink.status).toBe("archived");
    expect(refreshedLink.status).toBe("active");
    expect(
      refreshState.links.filter((candidate) =>
        [archivedLink.uid, refreshedLink.uid].includes(candidate.uid),
      ),
    ).toHaveLength(2);
    await waitForLinkOrderCorrelation(
      request,
      refreshedLink.uid,
      refreshedCheckout.order,
    );
    const refreshedAmount = Number(refreshedCheckout.cart.total);
    expect(Number.isFinite(refreshedAmount)).toBe(true);
    expect(refreshedAmount).toBeGreaterThan(0);
    expect(Number(refreshedLink.amount)).toBe(refreshedAmount);
    expect(refreshedCheckout.cart.currency_code).toMatch(/^[a-z]{3}$/i);
    const refreshedCurrency =
      refreshedCheckout.cart.currency_code.toUpperCase();
    expect(refreshedLink.fiatCurrency).toBe(refreshedCurrency);
    expect(Number(refreshedCheckout.order.total)).toBe(refreshedAmount);
    const refreshedAmountText = refreshedAmount.toFixed(2);
    const sameValueUpdate = await apiKeyControl({
      action: "update-session",
      amount: refreshedAmountText,
      currency: refreshedCurrency,
      sessionId: refreshedCheckout.session.id,
    });
    expect(sameValueUpdate).toMatchObject({ ok: true });
    expect(sameValueUpdate.result.paymentLinkUid).toBe(refreshedLink.uid);
    const mismatchedCurrency =
      refreshedCurrency === "USD" ? "EUR" : "USD";
    for (const mismatch of [
      {
        amount: (refreshedAmount + 1).toFixed(2),
        currency: refreshedCurrency,
      },
      { amount: refreshedAmountText, currency: mismatchedCurrency },
    ]) {
      expect(
        await apiKeyControl({
          action: "update-session",
          sessionId: refreshedCheckout.session.id,
          ...mismatch,
        }),
      ).toEqual({ error: "operation_rejected", ok: false });
    }
    refreshState = await contractState(request);
    expect(
      refreshState.links.filter((candidate) =>
        [archivedLink.uid, refreshedLink.uid].includes(candidate.uid),
      ),
    ).toHaveLength(2);
    expect(
      refreshState.links.find((candidate) => candidate.uid === archivedLink.uid)
        ?.status,
    ).toBe("archived");
    expect(
      refreshState.links.find(
        (candidate) => candidate.uid === refreshedLink.uid,
      )?.status,
    ).toBe("active");
    const archivedSnapshot = await apiKeyControl({
      action: "snapshot",
      sessionId: refreshedCheckout.previousSession.id,
      uid: archivedLink.uid,
    });
    expect(archivedSnapshot.selectedSession).toBeNull();
    expect(archivedSnapshot.projection).toMatchObject({
      lateSettlementSafe: true,
      medusaStatus: "canceled",
      providerStatus: "cancelled",
      uid: archivedLink.uid,
    });
    const refreshedSnapshot = await apiKeyControl({
      action: "snapshot",
      orderId: refreshedCheckout.order.id,
      sessionId: refreshedCheckout.session.id,
      uid: refreshedLink.uid,
    });
    expect(refreshedSnapshot.selectedSession).toMatchObject({
      paymentLinkUid: refreshedLink.uid,
      status: "pending_authorization",
    });
    expect(Number(refreshedSnapshot.selectedSession.amount)).toBe(
      refreshedAmount,
    );
    expect(refreshedSnapshot.selectedSession.currency.toUpperCase()).toBe(
      refreshedCurrency,
    );
    expect(
      refreshedSnapshot.sessions.filter((candidate) =>
        [
          refreshedCheckout.previousSession.id,
          refreshedCheckout.session.id,
        ].includes(candidate.id),
      ),
    ).toEqual([expect.objectContaining({ id: refreshedCheckout.session.id })]);
    const refreshCaptureReceipt = await emit(request, {
      callbackUrl: `${apiKeyBackendUrl}/hooks/payment/makepay_makepay`,
      deliveryGroupId: `legacy-api-refresh-${randomUUID()}`,
      deliveryId: `api-key-refresh-complete-${randomUUID()}`,
      legacyProductionShape: true,
      status: "complete",
      uid: refreshedLink.uid,
    });
    expectSynchronousWebhookReceived(refreshCaptureReceipt);
    const refreshCaptured = await apiKeyControl({
      action: "snapshot",
      orderId: refreshedCheckout.order.id,
      sessionId: refreshedCheckout.session.id,
      uid: refreshedLink.uid,
    });
    expect(refreshCaptured.captureCount).toBe(captured.captureCount + 1);
    expect(refreshCaptured.orderCount).toBe(1);
    expect(refreshCaptured.selectedSession).toMatchObject({
      paymentLinkUid: refreshedLink.uid,
      status: "authorized",
    });
    expect(refreshCaptured.projection).toMatchObject({
      medusaStatus: "paid",
      providerStatus: "complete",
      uid: refreshedLink.uid,
    });

    const pendingDelete = await createApiKeyStoreCheckout(
      request,
      region,
      "pending-delete",
    );
    const beforeDeleteState = await contractState(request);
    const pendingDeleteLink = beforeDeleteState.links.find(
      (candidate) =>
        candidate.authMode === "api-key" &&
        candidate.metadata?.medusaSessionId === pendingDelete.session.id,
    );
    expect(pendingDeleteLink).toBeTruthy();
    await waitForLinkOrderCorrelation(
      request,
      pendingDeleteLink.uid,
      pendingDelete.order,
    );
    expect(
      await apiKeyControl({
        action: "delete-session",
        sessionId: pendingDelete.session.id,
      }),
    ).toMatchObject({ ok: true });
    const afterDeleteState = await contractState(request);
    expect(
      afterDeleteState.links.find(
        (candidate) => candidate.uid === pendingDeleteLink.uid,
      )?.status,
    ).toBe("archived");
    const deletedSnapshot = await apiKeyControl({
      action: "snapshot",
      orderId: pendingDelete.order.id,
      sessionId: pendingDelete.session.id,
      uid: pendingDeleteLink.uid,
    });
    expect(deletedSnapshot.selectedSession).toBeNull();
    expect(deletedSnapshot.projection).toMatchObject({
      lateSettlementSafe: true,
      medusaStatus: "canceled",
      providerStatus: "cancelled",
      uid: pendingDeleteLink.uid,
    });
    const pendingOrder = await findSingleAdminOrderByEmail(
      request,
      apiKeyAdminToken,
      pendingDelete.email,
      "Read pending order after MakePay session deletion",
      apiKeyBackendUrl,
    );
    expect(pendingOrder.status).toBe("pending");
    expect(pendingOrder.payment_status).not.toBe("captured");

    for (const status of ["failed", "cancelled", "expired"]) {
      const terminalCheckout = await createApiKeyStoreCheckout(
        request,
        region,
        `terminal-${status}`,
      );
      const beforeTerminal = await contractState(request);
      const terminalLink = beforeTerminal.links.find(
        (candidate) =>
          candidate.authMode === "api-key" &&
          candidate.metadata?.medusaSessionId === terminalCheckout.session.id,
      );
      expect(terminalLink).toBeTruthy();
      const terminalReceipt = await emit(request, {
        callbackUrl: `${apiKeyBackendUrl}/hooks/payment/makepay_makepay`,
        deliveryGroupId: `legacy-api-terminal-${status}-${randomUUID()}`,
        deliveryId: `api-key-terminal-${status}-${randomUUID()}`,
        legacyProductionShape: true,
        status,
        uid: terminalLink.uid,
      });
      expectSynchronousWebhookReceived(terminalReceipt);
      const terminalSnapshot = await apiKeyControl({
        action: "snapshot",
        orderId: terminalCheckout.order.id,
        sessionId: terminalCheckout.session.id,
        uid: terminalLink.uid,
      });
      expect(terminalSnapshot.projection).toMatchObject({
        medusaStatus: status === "failed" ? "failed" : "canceled",
        providerStatus: status,
      });
      expect(terminalSnapshot.selectedSession?.status).toBe(
        status === "failed" ? "error" : "canceled",
      );
      expect(terminalSnapshot.captureCount).toBe(refreshCaptured.captureCount);
      expect(terminalSnapshot.selectedSession.paymentLinkUid).toBe(
        terminalLink.uid,
      );
      const afterTerminal = await contractState(request);
      expect(afterTerminal.links).toHaveLength(beforeTerminal.links.length);
      expect(
        afterTerminal.links.find(
          (candidate) => candidate.uid === terminalLink.uid,
        )?.status,
      ).not.toBe("archived");
    }
  });
});
