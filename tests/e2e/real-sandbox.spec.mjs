import { expect, test } from "@playwright/test";
import { chmod, readFile, rename, rm, stat } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { captureEvidence } from "./support/evidence.mjs";
import { waitForOAuthConnection } from "./support/oauth-connection-readiness.mjs";
import { validateRealSandboxCompanyDirectory } from "./support/real-sandbox-company.mjs";
import { selectPurchasableProductOptions } from "./support/storefront-product-options.mjs";

const backendUrl = process.env.MAKEPAY_E2E_BACKEND_URL;
const secondBackendUrl = process.env.MAKEPAY_E2E_SECOND_BACKEND_URL;
const backendInternalUrl = process.env.MAKEPAY_E2E_BACKEND_INTERNAL_URL;
const secondBackendInternalUrl =
  process.env.MAKEPAY_E2E_SECOND_BACKEND_INTERNAL_URL;
const storefrontUrl = process.env.MAKEPAY_E2E_STOREFRONT_URL;
const credentialsPath = process.env.MAKEPAY_E2E_REAL_CREDENTIALS_FILE;
const controlSocket = process.env.MAKEPAY_E2E_CONTROL_SOCKET;
const runId = process.env.MAKEPAY_E2E_RUN_ID;
const checkoutOrigin = process.env.MAKEPAY_E2E_CHECKOUT_ORIGIN;
const oauthIssuerOrigin = process.env.MAKEPAY_E2E_REAL_OAUTH_ISSUER_URL;
const sandboxCompanyId = process.env.MAKEPAY_E2E_SANDBOX_COMPANY_ID;
const sandboxCompanyName = process.env.MAKEPAY_E2E_SANDBOX_COMPANY_NAME;
const capture = process.env.MAKEPAY_E2E_CAPTURE === "1";
const manualOAuth = process.env.MAKEPAY_E2E_MANUAL_OAUTH === "1";
const storageStatePath = process.env.MAKEPAY_E2E_STORAGE_STATE;
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
const evidenceDirectory =
  process.env.MAKEPAY_E2E_EVIDENCE_DIR ||
  "output/playwright/medusa-makepay/evidence";
const expectedScopes = [
  "company:read",
  "makepay:payment-links:read",
  "makepay:payment-links:write",
  "makepay:webhooks:read",
  "makepay:webhooks:write",
];
const chromeNetworkErrorUrl = "chrome-error://chromewebdata/";

if (!credentialsPath) {
  throw new Error("Missing restricted real-sandbox credentials file.");
}
const credentialsStat = await stat(credentialsPath);
if (
  !credentialsStat.isFile() ||
  (credentialsStat.mode & 0o777) !== 0o600 ||
  (typeof process.getuid === "function" &&
    credentialsStat.uid !== process.getuid())
) {
  throw new Error(
    "Real-sandbox credentials must be an owner-controlled 0600 file.",
  );
}
const credentials = JSON.parse(await readFile(credentialsPath, "utf8"));
const installationA = {
  adminEmail: credentials.a?.adminEmail,
  adminPassword: credentials.a?.adminPassword,
  adminToken: credentials.a?.adminToken,
  apiUrl: backendInternalUrl,
  backendUrl,
  controlInstallation: "a",
  name: "installation A",
  publishableKey: credentials.a?.publishableKey,
};
const installationB = {
  adminEmail: credentials.b?.adminEmail,
  adminPassword: credentials.b?.adminPassword,
  adminToken: credentials.b?.adminToken,
  apiUrl: secondBackendInternalUrl,
  backendUrl: secondBackendUrl,
  controlInstallation: "b",
  name: "installation B",
  publishableKey: credentials.b?.publishableKey,
};

for (const [name, value] of Object.entries({
  backendUrl,
  backendInternalUrl,
  checkoutOrigin,
  controlSocket,
  oauthIssuerOrigin,
  pluginSha256: artifactProvenance.plugin.sha256,
  pluginVersion: artifactProvenance.plugin.version,
  runId,
  sandboxCompanyId,
  sandboxCompanyName,
  secondBackendUrl,
  secondBackendInternalUrl,
  sdkSha256: artifactProvenance.sdk.sha256,
  sdkVersion: artifactProvenance.sdk.version,
  storefrontUrl,
  ...Object.fromEntries(
    [installationA, installationB].flatMap((installation) =>
      [
        "adminEmail",
        "adminPassword",
        "adminToken",
        "apiUrl",
        "publishableKey",
      ].map((key) => [`${installation.name}.${key}`, installation[key]]),
    ),
  ),
})) {
  if (!value)
    throw new Error(`Missing required real-sandbox variable: ${name}`);
}

if (
  capture &&
  process.env.MAKEPAY_E2E_SCREENSHOT_PUBLICATION_ACK !==
    "PUBLIC_SANDBOX_DATA_ONLY"
) {
  throw new Error(
    "Real screenshot capture requires MAKEPAY_E2E_SCREENSHOT_PUBLICATION_ACK=PUBLIC_SANDBOX_DATA_ONLY.",
  );
}

async function json(response, label) {
  const text = await response.text();
  if (!response.ok()) {
    throw new Error(`${label} failed (${response.status()}).`);
  }
  return text ? JSON.parse(text) : {};
}

async function gotoDisposableTunnel(page, url) {
  let lastError;

  for (let attempt = 1; attempt <= 5; attempt += 1) {
    try {
      const response = await page.goto(url, {
        timeout: 60_000,
        waitUntil: "domcontentloaded",
      });
      const bodyText = (await page.locator("body").textContent()) || "";
      const transientServerFailure =
        (response?.status() || 0) >= 500 ||
        /Application error: a server-side exception|Bad gateway|Error 5(?:02|03|04)/i.test(
          bodyText,
        );
      if (!transientServerFailure) return response;
      lastError = new Error(
        "The disposable tunnel returned a transient server response.",
      );
      if (attempt === 5) throw lastError;
    } catch (error) {
      lastError = error;
      const message = String(error);
      const transientTunnelFailure =
        error?.name === "TimeoutError" ||
        /Timeout \d+ms exceeded/i.test(message) ||
        /net::ERR_(?:ABORTED|CONNECTION_CLOSED|CONNECTION_RESET|CONNECTION_TIMED_OUT|HTTP2_PROTOCOL_ERROR|NAME_NOT_RESOLVED|NETWORK_CHANGED|TIMED_OUT|TUNNEL_CONNECTION_FAILED)/.test(
          message,
        ) ||
        message.includes(
          "The disposable tunnel returned a transient server response.",
        );
      if (!transientTunnelFailure || attempt === 5) throw error;
      await page
        .goto("about:blank", { timeout: 10_000, waitUntil: "commit" })
        .catch(() => {});
    }
    await page.waitForTimeout(attempt * 2_000);
  }

  throw lastError;
}

async function tokenAndRegion(request, installation) {
  const headers = { authorization: `Bearer ${installation.adminToken}` };
  const regions = await json(
    await request.get(
      `${installation.apiUrl}/admin/regions?limit=100&fields=%2Bpayment_providers.*`,
      { headers },
    ),
    `List regions for ${installation.name}`,
  );
  const region = regions.regions.find(
    (candidate) => candidate.name === "Europe",
  );
  if (!region)
    throw new Error("The official seed did not create the Europe region");
  const providers = (region.payment_providers || []).map((provider) =>
    typeof provider === "string" ? provider : provider.id,
  );
  if (!providers.includes("pp_makepay_makepay")) {
    await json(
      await request.post(`${installation.apiUrl}/admin/regions/${region.id}`, {
        data: { payment_providers: [...providers, "pp_makepay_makepay"] },
        headers,
      }),
      `Enable MakePay for ${installation.name}`,
    );
  }
  return { headers, region };
}

async function findSingleAdminOrderByEmail(
  request,
  installation,
  headers,
  email,
) {
  let matching = [];
  await expect
    .poll(async () => {
      const result = await json(
        await request.get(
          `${installation.apiUrl}/admin/orders?q=${encodeURIComponent(email)}&limit=5&fields=id,email,total`,
          { headers },
        ),
        "Find the real sandbox Medusa order",
      );
      matching = (result.orders || []).filter(
        (candidate) => candidate.email === email,
      );
      return matching.length;
    })
    .toBe(1);
  return matching[0];
}

async function login(page, installation) {
  let email;
  let authenticatedNavigation;
  let lastError;
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    await gotoDisposableTunnel(page, `${installation.backendUrl}/app`);
    email = page.getByRole("textbox", { name: "Email" });
    authenticatedNavigation = page
      .getByRole("link", { name: /orders|products/i })
      .first();
    try {
      await expect(email.or(authenticatedNavigation).first()).toBeVisible({
        timeout: 15_000,
      });
      lastError = undefined;
      break;
    } catch (error) {
      lastError = error;
      if (attempt === 5) throw error;
      await page
        .goto("about:blank", { timeout: 10_000, waitUntil: "commit" })
        .catch(() => {});
      await page.waitForTimeout(attempt * 2_000);
    }
  }
  if (lastError) throw lastError;
  if (!email || !authenticatedNavigation) {
    throw new Error(
      `Admin navigation did not initialize for ${installation.name}`,
    );
  }
  if (await email.isVisible()) {
    await email.fill(installation.adminEmail);
    await page.getByPlaceholder("Password").fill(installation.adminPassword);
    const authentication = page.waitForResponse(
      (response) =>
        response.url() === `${installation.backendUrl}/auth/user/emailpass` &&
        response.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Continue with Email" }).click();
    expect((await authentication).ok()).toBe(true);
  }
  await expect(page.locator("body")).toContainText(
    /orders|products|dashboard/i,
  );
}

async function refreshStoredIssuerSession(page) {
  if (manualOAuth) return;
  if (!storageStatePath) {
    throw new Error("Stored OAuth mode requires a browser storage-state path.");
  }

  const issuer = new URL(oauthIssuerOrigin);
  const signIn = new URL("/auth/sign-in", issuer);
  signIn.searchParams.set("next", "/home");
  await page.goto(signIn.href, { waitUntil: "domcontentloaded" });
  await page.waitForURL(
    (url) => url.origin === issuer.origin && url.pathname.startsWith("/home"),
    { timeout: 60_000 },
  );

  const refreshedPath = `${storageStatePath}.${runId}.tmp`;
  await rm(refreshedPath, { force: true });
  try {
    await page.context().storageState({ path: refreshedPath });
    await chmod(refreshedPath, 0o600);
    const refreshed = JSON.parse(await readFile(refreshedPath, "utf8"));
    const unsafeCookie = refreshed.cookies?.find(
      (cookie) =>
        typeof cookie?.domain !== "string" ||
        cookie.domain.replace(/^\./, "").toLowerCase() !==
          issuer.hostname.toLowerCase(),
    );
    const unsafeOrigin = refreshed.origins?.find((entry) => {
      try {
        return new URL(entry?.origin).origin !== issuer.origin;
      } catch {
        return true;
      }
    });
    const indexedDbState = refreshed.origins?.some(
      (entry) => Array.isArray(entry?.indexedDB) && entry.indexedDB.length,
    );
    if (
      !Array.isArray(refreshed.cookies) ||
      !Array.isArray(refreshed.origins) ||
      unsafeCookie ||
      unsafeOrigin ||
      indexedDbState
    ) {
      throw new Error(
        "Refreshed sandbox OAuth state escaped the approved issuer.",
      );
    }
    await rename(refreshedPath, storageStatePath);
    await chmod(storageStatePath, 0o600);
  } finally {
    await rm(refreshedPath, { force: true });
  }
}

async function assertConfiguredCompanyIsSandbox(page) {
  const directoryUrl = new URL("/api/partner/v1/companies", oauthIssuerOrigin);
  let response;
  try {
    response = await page.context().request.get(directoryUrl.href, {
      failOnStatusCode: false,
      headers: { accept: "application/json" },
      maxRedirects: 0,
    });
  } catch {
    throw new Error(
      "The OAuth issuer sandbox-company preflight request failed.",
    );
  }
  if (!response.ok() || response.url() !== directoryUrl.href) {
    throw new Error(
      "The OAuth issuer did not authorize the sandbox-company preflight.",
    );
  }

  let directory;
  try {
    directory = await response.json();
  } catch {
    throw new Error(
      "The OAuth issuer returned an invalid sandbox-company directory.",
    );
  }
  if (
    validateRealSandboxCompanyDirectory(directory, {
      companyId: sandboxCompanyId,
      companyName: sandboxCompanyName,
    }) !== "sandbox-confirmed"
  ) {
    throw new Error(
      "The configured OAuth company was not uniquely confirmed as a sandbox company.",
    );
  }
}

async function waitForOAuthSettingsReturn(page, installation) {
  const settingsUrl = new URL("/app/settings/makepay", installation.backendUrl);

  await page.waitForURL(
    (url) =>
      url.href === chromeNetworkErrorUrl ||
      (url.origin === settingsUrl.origin &&
        url.pathname === settingsUrl.pathname),
    { timeout: 60_000 },
  );

  if (page.url() !== chromeNetworkErrorUrl) {
    if (new URL(page.url()).searchParams.get("makepay_error") === "1") {
      throw new Error("MakePay OAuth callback reported an error.");
    }
    return;
  }

  const response = await page.goto(settingsUrl.href, {
    timeout: 60_000,
    waitUntil: "domcontentloaded",
  });
  if (
    !response ||
    !response.ok() ||
    response.url() !== settingsUrl.href ||
    page.url() !== settingsUrl.href
  ) {
    throw new Error(
      "OAuth return network-error recovery did not reach the exact installation settings URL.",
    );
  }
}

async function connectSandboxOAuth(
  page,
  request,
  installation,
  headers,
  { reconnect = false } = {},
) {
  const issuerOrigin = new URL(oauthIssuerOrigin).origin;
  await gotoDisposableTunnel(
    page,
    `${installation.backendUrl}/app/settings/makepay`,
  );
  await expect(page.getByTestId("makepay-settings-page")).toBeVisible();
  const connect = page.getByRole("button", {
    name: /connect makepay|reconnect/i,
  });
  const disconnect = page.getByRole("button", { name: "Disconnect" });
  await expect(connect.or(disconnect).first()).toBeVisible();
  if (reconnect || !(await disconnect.isVisible())) {
    if (reconnect) {
      await expect(
        page.getByRole("button", { name: "Reconnect" }),
      ).toBeVisible();
    }
    const callbackUrl = new URL(
      "/makepay/oauth/callback",
      installation.backendUrl,
    );
    let issuerInteractionClosed = false;
    const callbackOutcome = page
      .waitForResponse(
        (response) => {
          const url = new URL(response.url());
          return (
            response.request().method() === "GET" &&
            url.origin === callbackUrl.origin &&
            url.pathname === callbackUrl.pathname
          );
        },
        { timeout: manualOAuth ? 15 * 60_000 : 60_000 },
      )
      .then(
        (response) => {
          issuerInteractionClosed = true;
          return { kind: "callback", response };
        },
        (error) => ({ error, kind: "callback-error" }),
      );
    const issuerNavigation = page
      .waitForURL((url) => url.origin === issuerOrigin, {
        timeout: manualOAuth ? 15 * 60_000 : 60_000,
      })
      .then(
        () => ({ kind: "issuer" }),
        (error) => ({ error, kind: "issuer-error" }),
      );

    await connect.click();
    let firstOutcome = await Promise.race([callbackOutcome, issuerNavigation]);
    if (firstOutcome.kind === "issuer-error") {
      throw firstOutcome.error;
    }

    // In manual mode the user signs into the dedicated sandbox account and
    // completes 2FA in this fresh headed context. The harness never reads or
    // persists those credentials. A user may also select/approve the company
    // while Playwright is waiting; race every issuer-side step against the
    // callback so that successful manual consent cannot leave a stale locator
    // waiting on the returned Medusa settings page.
    if (firstOutcome.kind === "issuer") {
      const settingsUrl = new URL(
        "/app/settings/makepay",
        installation.backendUrl,
      );
      const issuerReturnOutcome = page
        .waitForURL(
          (url) =>
            url.href === chromeNetworkErrorUrl ||
            (url.origin === settingsUrl.origin &&
              url.pathname === settingsUrl.pathname),
          { timeout: manualOAuth ? 15 * 60_000 : 60_000 },
        )
        .then(
          () => {
            issuerInteractionClosed = true;
            return { kind: "issuer-return" };
          },
          (error) => ({ error, kind: "issuer-return-error" }),
        );
      const isIssuerInteractionActive = () => {
        if (issuerInteractionClosed) return false;
        try {
          return new URL(page.url()).origin === issuerOrigin;
        } catch {
          return false;
        }
      };
      const abandonedIssuerInteraction = () => ({
        kind: "issuer-abandoned",
      });
      const issuerInteraction = (async () => {
        await expect(page.locator("body")).toContainText(sandboxCompanyName, {
          timeout: manualOAuth ? 15 * 60_000 : 60_000,
        });
        if (!isIssuerInteractionActive()) {
          return abandonedIssuerInteraction();
        }
        await expect(page.locator("body")).toContainText(/sandbox/i);
        if (!isIssuerInteractionActive()) {
          return abandonedIssuerInteraction();
        }
        await assertConfiguredCompanyIsSandbox(page);
        if (!isIssuerInteractionActive()) {
          return abandonedIssuerInteraction();
        }
        const companyChoice = page.locator('select[name="company_id"]');
        await expect(companyChoice).toBeVisible();
        if (!isIssuerInteractionActive()) {
          return abandonedIssuerInteraction();
        }
        const companyChoiceElement = await companyChoice.elementHandle();
        if (!isIssuerInteractionActive()) {
          return abandonedIssuerInteraction();
        }
        if (!companyChoiceElement) {
          throw new Error("The sandbox company selector disappeared.");
        }
        if (!isIssuerInteractionActive()) {
          return abandonedIssuerInteraction();
        }
        await companyChoiceElement.selectOption(sandboxCompanyId);
        if (!isIssuerInteractionActive()) {
          return abandonedIssuerInteraction();
        }
        expect(await companyChoiceElement.inputValue()).toBe(sandboxCompanyId);
        if (!isIssuerInteractionActive()) {
          return abandonedIssuerInteraction();
        }
        const approveButton = page.getByRole("button", {
          name: /approve|authorize|connect/i,
        });
        await expect(approveButton).toBeVisible();
        if (!isIssuerInteractionActive()) {
          return abandonedIssuerInteraction();
        }
        const approveButtonElement = await approveButton.elementHandle();
        if (!isIssuerInteractionActive()) {
          return abandonedIssuerInteraction();
        }
        if (!approveButtonElement) {
          throw new Error("The sandbox approval button disappeared.");
        }
        if (!isIssuerInteractionActive()) {
          return abandonedIssuerInteraction();
        }
        await approveButtonElement.click({ timeout: 15_000 });
        if (!isIssuerInteractionActive()) {
          return abandonedIssuerInteraction();
        }
        return { kind: "issuer-interaction" };
      })().then(
        (outcome) => {
          issuerInteractionClosed = true;
          return outcome;
        },
        (error) => {
          issuerInteractionClosed = true;
          return { error, kind: "issuer-interaction-error" };
        },
      );
      firstOutcome = await Promise.race([
        callbackOutcome,
        issuerInteraction,
        issuerReturnOutcome,
      ]);
      issuerInteractionClosed = true;
      if (firstOutcome.kind === "issuer-interaction") {
        firstOutcome = await Promise.race([
          callbackOutcome,
          issuerReturnOutcome,
        ]);
      }
      if (
        firstOutcome.kind === "callback-error" ||
        firstOutcome.kind === "issuer-interaction-error" ||
        firstOutcome.kind === "issuer-abandoned" ||
        firstOutcome.kind === "issuer-return-error"
      ) {
        const interactionFailure = firstOutcome;
        const recoveryOutcomes = [
          new Promise((resolvePromise) => {
            setTimeout(() => resolvePromise(interactionFailure), 5_000);
          }),
        ];
        if (firstOutcome.kind !== "callback-error") {
          recoveryOutcomes.push(callbackOutcome);
        }
        if (firstOutcome.kind !== "issuer-return-error") {
          recoveryOutcomes.push(issuerReturnOutcome);
        }
        firstOutcome = await Promise.race(recoveryOutcomes);
      }
    }

    let callbackResponse =
      firstOutcome.kind === "callback" ? firstOutcome.response : undefined;
    if (!callbackResponse) {
      await waitForOAuthConnection(
        async () => {
          const reconciled = await json(
            await request.get(
              `${installation.apiUrl}/admin/makepay/connection`,
              { headers },
            ),
            `Reconcile the MakePay OAuth callback for ${installation.name}`,
          );
          return reconciled.connection;
        },
        {
          companyId: sandboxCompanyId,
          expectedScopes,
          timeout: 60_000,
        },
      );
      await gotoDisposableTunnel(
        page,
        `${installation.backendUrl}/app/settings/makepay`,
      );
    }

    // Preserve the sandbox-only gate even when the user completed consent
    // before Playwright reached the company selector.
    await assertConfiguredCompanyIsSandbox(page);
    if (callbackResponse) {
      const callbackLocation = callbackResponse.headers().location;
      const expectedCallbackLocation = new URL(
        "/app/settings/makepay?makepay_connected=1",
        installation.backendUrl,
      );
      if (
        callbackResponse.status() !== 303 ||
        !callbackLocation ||
        new URL(callbackLocation, callbackUrl).href !==
          expectedCallbackLocation.href
      ) {
        throw new Error(
          "MakePay OAuth callback did not complete successfully.",
        );
      }
      await waitForOAuthSettingsReturn(page, installation);
    }
  }

  await expect(disconnect).toBeVisible();
  const connection = await waitForOAuthConnection(
    async () => {
      const response = await json(
        await request.get(`${installation.apiUrl}/admin/makepay/connection`, {
          headers,
        }),
        `Read MakePay connection for ${installation.name}`,
      );
      return response.connection;
    },
    {
      companyId: sandboxCompanyId,
      expectedScopes,
      timeout: 60_000,
    },
  );
  return connection;
}

function control(input) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(input);
    const request = httpRequest(
      {
        headers: {
          "content-length": Buffer.byteLength(body),
          "content-type": "application/json",
        },
        method: "POST",
        path: "/control",
        socketPath: controlSocket,
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.once("error", reject);
        response.once("end", () => {
          try {
            const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            if (response.statusCode !== 200) {
              reject(
                new Error("Restricted real-sandbox helper rejected an action."),
              );
              return;
            }
            resolve(parsed);
          } catch {
            reject(
              new Error(
                "Restricted real-sandbox helper returned invalid JSON.",
              ),
            );
          }
        });
      },
    );
    request.once("error", reject);
    request.end(body);
  });
}

async function listPayments(request, installation, headers, query) {
  const result = await json(
    await request.get(
      `${installation.apiUrl}/admin/makepay/payments?q=${encodeURIComponent(query)}&limit=20`,
      { headers },
    ),
    `List ${installation.name} MakePay projections`,
  );
  return result.payments || result.items || [];
}

async function findSinglePayment(request, installation, headers, email) {
  let payment;
  await expect
    .poll(
      async () => {
        const matching = (
          await listPayments(request, installation, headers, email)
        ).filter((record) => record.customer_email === email);
        payment = matching.length === 1 ? matching[0] : undefined;
        return matching.length;
      },
      { timeout: 45_000 },
    )
    .toBe(1);
  return payment;
}

async function expectProjectionStatus(
  request,
  installation,
  headers,
  uid,
  status,
) {
  await expect
    .poll(
      async () => {
        const matching = (
          await listPayments(request, installation, headers, uid)
        ).filter((record) => record.payment_link_uid === uid);
        return matching.length === 1
          ? String(matching[0].provider_status)
          : undefined;
      },
      { timeout: 45_000 },
    )
    .toBe(status);
}

async function expectProjectionState(
  request,
  installation,
  headers,
  uid,
  expected,
) {
  let payment;
  await expect
    .poll(
      async () => {
        const matching = (
          await listPayments(request, installation, headers, uid)
        ).filter((record) => record.payment_link_uid === uid);
        payment = matching.length === 1 ? matching[0] : undefined;
        return payment
          ? {
              hasPaymentId: Boolean(payment.payment_id),
              medusaStatus: String(payment.medusa_status),
              providerStatus: String(payment.provider_status),
            }
          : null;
      },
      { timeout: 60_000 },
    )
    .toEqual(expected);
  return payment;
}

async function captureCount(request, installation, headers, orderId) {
  const result = await json(
    await request.get(
      `${installation.apiUrl}/admin/orders/${orderId}?fields=%2Bpayment_collections.payments.captures.*`,
      { headers },
    ),
    `Read captures for ${installation.name}`,
  );
  return (result.order?.payment_collections || []).reduce(
    (total, collection) =>
      total +
      (collection.payments || []).reduce(
        (paymentTotal, payment) =>
          paymentTotal + (payment.captures || []).length,
        0,
      ),
    0,
  );
}

async function orderPaymentState(
  request,
  installation,
  headers,
  orderId,
) {
  const result = await json(
    await request.get(
      `${installation.apiUrl}/admin/orders/${orderId}?fields=id,status,payment_status`,
      { headers },
    ),
    `Read payment state for ${installation.name}`,
  );
  return {
    paymentStatus: String(result.order?.payment_status ?? ""),
    status: String(result.order?.status ?? ""),
  };
}

async function createPendingStoreOrder(
  request,
  installation,
  region,
  headers,
  buyerEmail,
) {
  const storeHeaders = {
    "x-publishable-api-key": installation.publishableKey,
  };
  const products = await json(
    await request.get(
      `${installation.apiUrl}/store/products?region_id=${encodeURIComponent(region.id)}&limit=100&fields=id,title,*variants`,
      { headers: storeHeaders },
    ),
    `List seeded products for ${installation.name}`,
  );
  const product = products.products?.find(
    (candidate) => candidate.title === "Medusa T-Shirt",
  );
  const variant = product?.variants?.[0];
  expect(
    variant?.id,
    `${installation.name} seeded product variant`,
  ).toBeTruthy();

  let cart = (
    await json(
      await request.post(`${installation.apiUrl}/store/carts`, {
        data: { region_id: region.id },
        headers: storeHeaders,
      }),
      `Create cart for ${installation.name}`,
    )
  ).cart;
  cart = (
    await json(
      await request.post(
        `${installation.apiUrl}/store/carts/${cart.id}/line-items`,
        {
          data: { quantity: 1, variant_id: variant.id },
          headers: storeHeaders,
        },
      ),
      `Add seeded product for ${installation.name}`,
    )
  ).cart;
  const address = {
    address_1: "1 Medusa Way",
    city: "Copenhagen",
    country_code: "dk",
    first_name: "Ada",
    last_name: "Sandbox",
    phone: "+4512345678",
    postal_code: "2100",
  };
  cart = (
    await json(
      await request.post(`${installation.apiUrl}/store/carts/${cart.id}`, {
        data: {
          billing_address: address,
          email: buyerEmail,
          shipping_address: address,
        },
        headers: storeHeaders,
      }),
      `Address cart for ${installation.name}`,
    )
  ).cart;
  const options = await json(
    await request.get(
      `${installation.apiUrl}/store/shipping-options?cart_id=${encodeURIComponent(cart.id)}`,
      { headers: storeHeaders },
    ),
    `List shipping options for ${installation.name}`,
  );
  expect(options.shipping_options?.length).toBeGreaterThan(0);
  cart = (
    await json(
      await request.post(
        `${installation.apiUrl}/store/carts/${cart.id}/shipping-methods`,
        {
          data: { option_id: options.shipping_options[0].id },
          headers: storeHeaders,
        },
      ),
      `Select shipping for ${installation.name}`,
    )
  ).cart;
  const collection = await json(
    await request.post(`${installation.apiUrl}/store/payment-collections`, {
      data: { cart_id: cart.id },
      headers: storeHeaders,
    }),
    `Create payment collection for ${installation.name}`,
  );
  const initialized = await json(
    await request.post(
      `${installation.apiUrl}/store/payment-collections/${collection.payment_collection.id}/payment-sessions`,
      {
        data: {
          data: { customer_email: buyerEmail },
          provider_id: "pp_makepay_makepay",
        },
        headers: storeHeaders,
      },
    ),
    `Create MakePay payment session for ${installation.name}`,
  );
  const sessions = (
    initialized.payment_collection?.payment_sessions || []
  ).filter((session) => session.provider_id === "pp_makepay_makepay");
  expect(sessions).toHaveLength(1);
  expect(sessions[0].status).toBe("pending_authorization");
  const preOrderPayment = await findSinglePayment(
    request,
    installation,
    headers,
    buyerEmail,
  );
  expect(preOrderPayment.customer_email).toBe(buyerEmail);
  expect(preOrderPayment.session_id).toBe(sessions[0].id);
  expect(preOrderPayment.order_id ?? null).toBeNull();
  expect(preOrderPayment.company_id).toBe(sandboxCompanyId);
  expect(
    await control({
      action: "track-payment-link",
      installation: installation.controlInstallation,
      uid: preOrderPayment.payment_link_uid,
    }),
  ).toEqual({
    tracked: true,
    uid: preOrderPayment.payment_link_uid,
  });

  const completed = await json(
    await request.post(
      `${installation.apiUrl}/store/carts/${cart.id}/complete`,
      { headers: storeHeaders },
    ),
    `Complete pending order for ${installation.name}`,
  );
  expect(completed.type).toBe("order");
  expect(completed.order?.id).toBeTruthy();
  let payment;
  await expect
    .poll(
      async () => {
        payment = await findSinglePayment(
          request,
          installation,
          headers,
          buyerEmail,
        );
        return payment.order_id;
      },
      {
        message: `Wait for MakePay order correlation for ${installation.name}`,
        timeout: 60_000,
      },
    )
    .toBe(completed.order.id);
  expect(payment.medusa_status).toBe("pending_authorization");
  expect(payment.provider_status).toBe("active");
  expect(Number(payment.amount)).toBe(20);
  expect(payment.currency).toBe("EUR");
  expect(payment.order_id).toBe(completed.order.id);
  expect(payment.payment_link_uid).toBe(preOrderPayment.payment_link_uid);
  expect(payment.session_id).toBe(preOrderPayment.session_id);
  expect(payment.company_id).toBe(sandboxCompanyId);
  expect(
    await control({
      action: "track-payment-link",
      installation: installation.controlInstallation,
      uid: payment.payment_link_uid,
    }),
  ).toEqual({ tracked: true, uid: payment.payment_link_uid });
  return { cart, order: completed.order, payment };
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
  const result = await json(
    await request.get(
      `${backendInternalUrl}/store/carts/${encodeURIComponent(cartId)}`,
      {
        headers: {
          "x-publishable-api-key": installationA.publishableKey,
        },
      },
    ),
    "Read the real sandbox Medusa cart payment session",
  );
  const makePaySessions = (
    result.cart?.payment_collection?.payment_sessions || []
  ).filter((session) => session.provider_id === "pp_makepay_makepay");
  expect(makePaySessions).toHaveLength(1);
  expect(makePaySessions[0].status).toBe("pending_authorization");
  return makePaySessions[0];
}

test("real MakePay sandbox OAuth and hosted checkout smoke (strictly no funds)", async ({
  page,
  request,
}) => {
  await refreshStoredIssuerSession(page);
  const { headers, region } = await tokenAndRegion(request, installationA);
  const { headers: secondHeaders, region: secondRegion } = await tokenAndRegion(
    request,
    installationB,
  );
  const buyerEmail = `makepay-real-sandbox+${runId}@example.com`.toLowerCase();
  const secondBuyerEmail =
    `makepay-real-sandbox+${runId}-installation-b@example.com`.toLowerCase();
  const backendOrigin = new URL(backendUrl).origin;
  const approvedCheckoutOrigin = new URL(checkoutOrigin).origin;

  await login(page, installationA);
  const connection = await connectSandboxOAuth(
    page,
    request,
    installationA,
    headers,
  );
  const initialA = await control({ action: "snapshot", installation: "a" });
  await login(page, installationB);
  await connectSandboxOAuth(page, request, installationB, secondHeaders);
  const initialB = await control({ action: "snapshot", installation: "b" });

  for (const [installation, snapshot] of [
    [installationA, initialA],
    [installationB, initialB],
  ]) {
    expect(snapshot.connection.connected).toBe(true);
    expect(snapshot.connection.status).toBe("connected");
    expect(snapshot.connection.webhookStatus).toBe("healthy");
    expect(snapshot.connection.companyId).toBe(sandboxCompanyId);
    expect(snapshot.context.companyId).toBe(sandboxCompanyId);
    expect(snapshot.connection.clientId).toBe(snapshot.context.installationId);
    expect(snapshot.connection.callbackUrl).toBe(
      `${new URL(installation.backendUrl).origin}/hooks/makepay/makepay_makepay`,
    );
    expect(snapshot.remoteSubscription.callbackUrl).toBe(
      snapshot.connection.callbackUrl,
    );
    expect(snapshot.remoteSubscription.id).toBe(
      snapshot.context.subscriptionId,
    );
    expect(snapshot.subscriptionReadOmittedSecret).toBe(true);
    for (const value of [
      snapshot.connection.clientId,
      snapshot.context.installationId,
      snapshot.context.grantId,
      snapshot.context.subscriptionId,
    ]) {
      expect(value).toBeTruthy();
    }
  }
  expect(initialA.connection.clientId).not.toBe(initialB.connection.clientId);
  expect(initialA.context.installationId).not.toBe(
    initialB.context.installationId,
  );
  expect(initialA.context.grantId).not.toBe(initialB.context.grantId);
  expect(initialA.context.subscriptionId).not.toBe(
    initialB.context.subscriptionId,
  );

  const initialBOrder = await createPendingStoreOrder(
    request,
    installationB,
    secondRegion,
    secondHeaders,
    secondBuyerEmail,
  );

  await gotoDisposableTunnel(page, `${storefrontUrl}/dk/store`);
  const productLink = page
    .getByRole("link", { name: /Medusa T-Shirt/ })
    .first();
  const productHref = await productLink.getAttribute("href");
  expect(productHref).toMatch(/^\/dk\/products\//);
  await gotoDisposableTunnel(
    page,
    new URL(productHref, storefrontUrl).toString(),
  );
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
      { timeout: 60_000 },
    ),
    page.getByTestId("add-product-button").click({ timeout: 60_000 }),
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
  await gotoDisposableTunnel(page, `${storefrontUrl}/dk/cart`);
  await expect(page.getByTestId("product-row")).toHaveCount(1);
  await page.getByTestId("checkout-button").click();
  await page.getByTestId("shipping-first-name-input").fill("Ada");
  await page.getByTestId("shipping-last-name-input").fill("Sandbox");
  await page.getByTestId("shipping-address-input").fill("1 Medusa Way");
  await page.getByTestId("shipping-postal-code-input").fill("2100");
  await page.getByTestId("shipping-city-input").fill("Copenhagen");
  await page.getByTestId("shipping-country-select").selectOption("dk");
  await page.getByTestId("shipping-email-input").fill(buyerEmail);
  const sameBilling = page.getByTestId("billing-address-checkbox");
  if (!(await sameBilling.isChecked())) await sameBilling.check();
  await page.getByTestId("submit-address-button").click();
  await page.getByTestId("delivery-option-radio").first().click();
  await page.getByTestId("submit-delivery-option-button").click();
  await page.getByText("MakePay", { exact: true }).click();
  await page.getByTestId("submit-payment-button").click();
  await expect(page.getByTestId("payment-method-summary")).toContainText(
    "MakePay",
  );
  const pendingSession = await assertPendingAuthorizationCartSession(
    page,
    request,
  );
  const preOrderPayment = await findSinglePayment(
    request,
    installationA,
    headers,
    buyerEmail,
  );
  expect(preOrderPayment.customer_email).toBe(buyerEmail);
  expect(preOrderPayment.session_id).toBe(pendingSession.id);
  expect(preOrderPayment.order_id ?? null).toBeNull();
  expect(preOrderPayment.company_id).toBe(sandboxCompanyId);
  expect(
    await control({
      action: "track-payment-link",
      installation: "a",
      uid: preOrderPayment.payment_link_uid,
    }),
  ).toEqual({
    tracked: true,
    uid: preOrderPayment.payment_link_uid,
  });
  await expect(page.locator("body")).toContainText(
    /€20\.00|EUR 20\.00|20\.00 €/,
  );
  await page.getByTestId("submit-order-button").click();
  await page.waitForURL((url) => url.origin === approvedCheckoutOrigin);

  // This is the hard no-funds boundary: verify the untouched hosted sandbox
  // page and stop before choosing an asset, opening a wallet, copying an
  // address, or attempting an on-chain payment.
  await expect(page.locator("body")).toContainText(/sandbox mode/i);
  await expect(page.locator("body")).toContainText(/do not send real funds/i);
  await expect(page.locator("body")).toContainText(
    /20(?:\.0+)?\s*EUR|EUR\s*20(?:\.0+)?/i,
  );
  const hostedUrl = new URL(page.url());
  expect(hostedUrl.origin).toBe(approvedCheckoutOrigin);

  let payment;
  await expect
    .poll(async () => {
      const payments = await json(
        await request.get(
          `${backendInternalUrl}/admin/makepay/payments?q=${encodeURIComponent(buyerEmail)}&limit=20`,
          { headers },
        ),
        "Find the real sandbox MakePay projection",
      );
      const matching = (payments.payments || payments.items || []).filter(
        (record) => record.customer_email === buyerEmail,
      );
      payment = matching.length === 1 ? matching[0] : undefined;
      return payment
        ? {
            amount: Number(payment.amount),
            companyId: payment.company_id,
            currency: payment.currency,
            hasOrder: Boolean(payment.order_id),
            hasPublicUrl: Boolean(payment.public_url),
            hasUid: Boolean(payment.payment_link_uid),
            medusaStatus: payment.medusa_status,
            providerStatus: payment.provider_status,
          }
        : null;
    })
    .toEqual({
      amount: 20,
      companyId: sandboxCompanyId,
      currency: "EUR",
      hasOrder: true,
      hasPublicUrl: true,
      hasUid: true,
      medusaStatus: "pending_authorization",
      providerStatus: "active",
    });
  expect(payment.payment_link_uid).toBe(preOrderPayment.payment_link_uid);
  expect(payment.session_id).toBe(preOrderPayment.session_id);
  expect(
    await control({
      action: "track-payment-link",
      installation: "a",
      uid: payment.payment_link_uid,
    }),
  ).toEqual({ tracked: true, uid: payment.payment_link_uid });
  await expect(
    control({
      action: "snapshot",
      installation: "a",
      uid: {
        operation: "force-oauth-refresh-read-smoke",
        paymentLinkUid: payment.payment_link_uid,
        runId: `${runId}-foreign`,
      },
    }),
  ).rejects.toThrow(/rejected an action/i);
  expect(
    await control({
      action: "snapshot",
      installation: "a",
      uid: {
        operation: "force-oauth-refresh-read-smoke",
        paymentLinkUid: payment.payment_link_uid,
        runId,
      },
    }),
  ).toEqual({
    accessCredentialPersisted: true,
    authenticatedReadCompleted: true,
    connectionIdentityStable: true,
    connectionStillHealthy: true,
    dpopCredentialStable: true,
    expiryAdvanced: true,
    forcedOnlyLocalExpiry: true,
    metadataStable: true,
    refreshAttemptCleared: true,
    refreshCredentialRotatedAndPersisted: true,
    remoteReadOmittedSecrets: true,
    remoteSubscriptionStable: true,
    webhookCredentialStable: true,
  });

  const order = await findSingleAdminOrderByEmail(
    request,
    installationA,
    headers,
    buyerEmail,
  );
  expect(payment.order_id).toBe(order.id);
  expect(Number(order.total)).toBe(20);

  const projectedCheckout = new URL(payment.public_url);
  expect(projectedCheckout.origin).toBe(approvedCheckoutOrigin);
  expect(projectedCheckout.pathname).toBe(hostedUrl.pathname);
  const terminalStatuses = new Set([
    "canceled",
    "cancelled",
    "complete",
    "expired",
    "failed",
    "paid",
    "refunded",
  ]);
  expect(
    terminalStatuses.has(String(payment.provider_status).toLowerCase()),
  ).toBe(false);
  expect(
    terminalStatuses.has(String(payment.medusa_status).toLowerCase()),
  ).toBe(false);

  const correlation = {
    amount: String(payment.amount),
    checkoutPath: hostedUrl.pathname,
    companyId: sandboxCompanyId,
    currency: "EUR",
    customerEmail: buyerEmail,
    medusaStatus: String(payment.medusa_status),
    orderId: order.id,
    paymentLinkUid: payment.payment_link_uid,
    providerStatus: String(payment.provider_status),
  };
  const approvedOrigins = {
    backend: backendOrigin,
    checkout: approvedCheckoutOrigin,
  };

  expect(
    (await listPayments(request, installationA, headers, secondBuyerEmail))
      .length,
  ).toBe(0);
  expect(
    (await listPayments(request, installationB, secondHeaders, buyerEmail))
      .length,
  ).toBe(0);
  expect(
    (
      await listPayments(
        request,
        installationA,
        headers,
        payment.payment_link_uid,
      )
    ).filter((record) => record.payment_link_uid === payment.payment_link_uid),
  ).toHaveLength(1);
  expect(
    (
      await listPayments(
        request,
        installationB,
        secondHeaders,
        initialBOrder.payment.payment_link_uid,
      )
    ).filter(
      (record) =>
        record.payment_link_uid === initialBOrder.payment.payment_link_uid,
    ),
  ).toHaveLength(1);

  if (capture) {
    await captureEvidence({
      approvedOrigins,
      artifactProvenance,
      correlation,
      expectedOrigin: approvedCheckoutOrigin,
      expectedPath: hostedUrl.pathname,
      expectedTitle: /makepay/i,
      mode: "real-sandbox",
      name: "makepay-sandbox-checkout",
      outputDirectory: evidenceDirectory,
      page,
      requiredTexts: [
        /sandbox mode/i,
        /do not send real funds/i,
        /20(?:\.0+)?\s*EUR|EUR\s*20(?:\.0+)?/i,
      ],
      runId,
    });

    await gotoDisposableTunnel(page, `${backendUrl}/app/settings/makepay`);
    await expect(page.getByTestId("makepay-settings-page")).toBeVisible();
    await captureEvidence({
      approvedOrigins,
      artifactProvenance,
      correlation,
      expectedOrigin: backendOrigin,
      expectedPath: "/app/settings/makepay",
      expectedTitle: /medusa/i,
      mode: "real-sandbox",
      name: "connected-makepay-settings",
      outputDirectory: evidenceDirectory,
      page,
      requiredTestIds: ["makepay-settings-page"],
      requiredTexts: [
        "MakePay",
        "Disconnect",
        sandboxCompanyName,
        "MakeCrypto OAuth",
        "Healthy",
      ],
      runId,
    });

    await gotoDisposableTunnel(page, `${backendUrl}/app/makepay`);
    await expect(page.getByTestId("makepay-payments-page")).toBeVisible();
    await page
      .getByRole("searchbox", { name: "Search MakePay payments" })
      .fill(payment.payment_link_uid);
    await expect(page.getByTestId("makepay-payments-page")).toContainText(
      payment.payment_link_uid,
    );
    await captureEvidence({
      approvedOrigins,
      artifactProvenance,
      correlation,
      expectedOrigin: backendOrigin,
      expectedPath: "/app/makepay",
      expectedTitle: /medusa/i,
      mode: "real-sandbox",
      name: "makepay-payments-list",
      outputDirectory: evidenceDirectory,
      page,
      requiredTestIds: [
        "makepay-payments-page",
        "makepay-sidebar-logo",
      ],
      requiredTexts: [
        "MakePay payments",
        payment.payment_link_uid,
        buyerEmail,
        /€20\.00|EUR 20(?:\.00)?|20(?:\.00)? €/,
      ],
      runId,
    });

    await gotoDisposableTunnel(page, `${backendUrl}/app/orders/${order.id}`);
    await expect(page.getByTestId("makepay-order-widget")).toBeVisible();
    await captureEvidence({
      approvedOrigins,
      artifactProvenance,
      correlation,
      expectedOrigin: backendOrigin,
      expectedPath: `/app/orders/${order.id}`,
      expectedTitle: /medusa/i,
      mode: "real-sandbox",
      name: "makepay-order-widget",
      outputDirectory: evidenceDirectory,
      page,
      requiredTestIds: ["makepay-order-widget"],
      requiredTexts: [
        "MakePay",
        payment.payment_link_uid,
        /€20\.00|EUR 20(?:\.00)?|20(?:\.00)? €/,
        /automated refunds aren.t supported/i,
      ],
      runId,
    });
  }

  const beforeLegacyRoute = await control({
    action: "snapshot",
    installation: "a",
    uid: payment.payment_link_uid,
  });
  expect(await captureCount(request, installationA, headers, order.id)).toBe(0);
  const legacyRouteFixture = await control({
    action: "prepare",
    installation: "a",
    status: "pending",
    uid: payment.payment_link_uid,
  });
  const legacyRouteResult = await control({
    action: "post-legacy-fixture",
    fixtureId: legacyRouteFixture.fixtureId,
    installation: "a",
    target: "a",
  });
  expect(legacyRouteResult.responseStatus).toBe(404);
  const afterLegacyRoute = await control({
    action: "snapshot",
    installation: "a",
    uid: payment.payment_link_uid,
  });
  expect(afterLegacyRoute).toEqual(beforeLegacyRoute);
  expect(await captureCount(request, installationA, headers, order.id)).toBe(0);

  const acceptedA = await control({
    action: "deliver",
    installation: "a",
    status: "quoted",
    target: "a",
    uid: payment.payment_link_uid,
  });
  expect(acceptedA.responseStatus).toBe(200);
  await expectProjectionStatus(
    request,
    installationA,
    headers,
    payment.payment_link_uid,
    "quoted",
  );
  await expectProjectionStatus(
    request,
    installationB,
    secondHeaders,
    initialBOrder.payment.payment_link_uid,
    "active",
  );

  const acceptedB = await control({
    action: "deliver",
    installation: "b",
    status: "quoted",
    target: "b",
    uid: initialBOrder.payment.payment_link_uid,
  });
  expect(acceptedB.responseStatus).toBe(200);
  await expectProjectionStatus(
    request,
    installationB,
    secondHeaders,
    initialBOrder.payment.payment_link_uid,
    "quoted",
  );

  const crossA = await control({
    action: "prepare",
    installation: "a",
    status: "pending",
    uid: payment.payment_link_uid,
  });
  // A foreign installation has no matching projection/routing tuple, so the
  // webhook is rejected before that installation's signing secret is loaded.
  expect(
    (
      await control({
        action: "post-fixture",
        fixtureId: crossA.fixtureId,
        installation: "a",
        target: "b",
      })
    ).responseStatus,
  ).toBe(400);
  expect(
    (
      await control({
        action: "resign-fixture",
        fixtureId: crossA.fixtureId,
        installation: "b",
        target: "a",
      })
    ).responseStatus,
  ).toBe(401);
  expect(
    (
      await control({
        action: "resign-fixture",
        fixtureId: crossA.fixtureId,
        installation: "b",
        target: "b",
      })
    ).responseStatus,
  ).toBe(400);

  const crossB = await control({
    action: "prepare",
    installation: "b",
    status: "pending",
    uid: initialBOrder.payment.payment_link_uid,
  });
  expect(
    (
      await control({
        action: "post-fixture",
        fixtureId: crossB.fixtureId,
        installation: "b",
        target: "a",
      })
    ).responseStatus,
  ).toBe(400);
  expect(
    (
      await control({
        action: "resign-fixture",
        fixtureId: crossB.fixtureId,
        installation: "a",
        target: "b",
      })
    ).responseStatus,
  ).toBe(401);
  expect(
    (
      await control({
        action: "resign-fixture",
        fixtureId: crossB.fixtureId,
        installation: "a",
        target: "a",
      })
    ).responseStatus,
  ).toBe(400);
  expect(
    (
      await control({
        action: "resign-fixture-without-routing",
        fixtureId: crossA.fixtureId,
        installation: "a",
        target: "a",
      })
    ).responseStatus,
  ).toBe(400);
  await expectProjectionStatus(
    request,
    installationA,
    headers,
    payment.payment_link_uid,
    "quoted",
  );
  await expectProjectionStatus(
    request,
    installationB,
    secondHeaders,
    initialBOrder.payment.payment_link_uid,
    "quoted",
  );
  expect(await captureCount(request, installationA, headers, order.id)).toBe(0);
  expect(
    await captureCount(
      request,
      installationB,
      secondHeaders,
      initialBOrder.order.id,
    ),
  ).toBe(0);
  const oldBFixture = await control({
    action: "prepare",
    installation: "b",
    status: "pending",
    uid: initialBOrder.payment.payment_link_uid,
  });
  expect((await control({ action: "start-old-b-signer" })).ready).toBe(true);
  const stableTuple = (snapshot) => ({
    connection: snapshot.connection,
    context: snapshot.context,
    remoteSubscription: snapshot.remoteSubscription,
    subscriptionReadOmittedSecret: snapshot.subscriptionReadOmittedSecret,
  });
  const aBeforeBReconnect = stableTuple(
    await control({ action: "snapshot", installation: "a" }),
  );
  const archivedInitialB = await control({
    action: "archive-payment-link",
    installation: "b",
    uid: initialBOrder.payment.payment_link_uid,
  });
  expect(archivedInitialB).toMatchObject({
    archived: true,
    localProjection: true,
    medusaStatus: "canceled",
    providerStatus: "cancelled",
    remoteStatus: "archived",
    uid: initialBOrder.payment.payment_link_uid,
  });
  await expectProjectionStatus(
    request,
    installationB,
    secondHeaders,
    initialBOrder.payment.payment_link_uid,
    "cancelled",
  );

  await login(page, installationB);
  await connectSandboxOAuth(page, request, installationB, secondHeaders, {
    reconnect: true,
  });
  const reconnectedB = await control({
    action: "snapshot",
    installation: "b",
  });
  expect(reconnectedB.connection.connected).toBe(true);
  expect(reconnectedB.connection.webhookStatus).toBe("healthy");
  expect(reconnectedB.connection.companyId).toBe(sandboxCompanyId);
  expect(reconnectedB.connection.callbackUrl).toBe(
    `${new URL(secondBackendUrl).origin}/hooks/makepay/makepay_makepay`,
  );
  expect(reconnectedB.remoteSubscription.callbackUrl).toBe(
    reconnectedB.connection.callbackUrl,
  );
  expect(reconnectedB.remoteSubscription.id).toBe(
    reconnectedB.context.subscriptionId,
  );
  expect(reconnectedB.subscriptionReadOmittedSecret).toBe(true);
  expect(reconnectedB.connection.clientId).not.toBe(
    initialA.connection.clientId,
  );
  expect(reconnectedB.context.installationId).not.toBe(
    initialA.context.installationId,
  );
  expect(
    stableTuple(await control({ action: "snapshot", installation: "a" })),
  ).toEqual(aBeforeBReconnect);

  const oldBResult = await control({
    action: "post-fixture",
    fixtureId: oldBFixture.fixtureId,
    installation: "b",
    target: "b",
  });
  expect(oldBResult.responseStatus).toBe(400);
  await expectProjectionStatus(
    request,
    installationB,
    secondHeaders,
    initialBOrder.payment.payment_link_uid,
    "cancelled",
  );

  const bRoutingChanged =
    initialB.context.grantId !== reconnectedB.context.grantId ||
    initialB.context.installationId !== reconnectedB.context.installationId ||
    initialB.context.subscriptionId !== reconnectedB.context.subscriptionId;
  expect(bRoutingChanged).toBe(true);
  const currentBOrder = await createPendingStoreOrder(
    request,
    installationB,
    secondRegion,
    secondHeaders,
    `makepay-real-sandbox+${runId}-installation-b-reconnected@example.com`.toLowerCase(),
  );
  const currentBFixture = await control({
    action: "prepare",
    installation: "b",
    status: "pending",
    uid: currentBOrder.payment.payment_link_uid,
  });
  const staleSecretResult = await control({
    action: "old-b-signer-deliver",
    fixtureId: currentBFixture.fixtureId,
  });
  expect(staleSecretResult.responseStatus).toBe(401);
  await expectProjectionStatus(
    request,
    installationB,
    secondHeaders,
    currentBOrder.payment.payment_link_uid,
    "active",
  );
  const currentBResult = await control({
    action: "post-fixture",
    fixtureId: currentBFixture.fixtureId,
    installation: "b",
    target: "b",
  });
  expect(currentBResult.responseStatus).toBe(200);
  await expectProjectionStatus(
    request,
    installationB,
    secondHeaders,
    currentBOrder.payment.payment_link_uid,
    "pending",
  );
  expect((await control({ action: "stop-old-b-signer" })).stopped).toBe(true);

  const stableRetry = await control({
    action: "prepare",
    installation: "a",
    status: "pending",
    uid: payment.payment_link_uid,
  });
  const firstAttempt = await control({
    action: "post-fixture",
    fixtureId: stableRetry.fixtureId,
    installation: "a",
    target: "a",
  });
  expect(firstAttempt.responseStatus).toBe(200);
  await expectProjectionStatus(
    request,
    installationA,
    headers,
    payment.payment_link_uid,
    "pending",
  );
  const retryAttempt = await control({
    action: "post-fixture",
    fixtureId: stableRetry.fixtureId,
    installation: "a",
    target: "a",
  });
  expect(retryAttempt.responseStatus).toBe(200);
  expect(retryAttempt.deliveryGroupId).toBe(firstAttempt.deliveryGroupId);
  expect(retryAttempt.deliveryId).toBe(firstAttempt.deliveryId);
  expect(
    stableTuple(await control({ action: "snapshot", installation: "a" })),
  ).toEqual(aBeforeBReconnect);
  expect(await captureCount(request, installationA, headers, order.id)).toBe(0);
  expect(
    await captureCount(
      request,
      installationB,
      secondHeaders,
      currentBOrder.order.id,
    ),
  ).toBe(0);

  const returnState = String(pendingSession.data?.return_state || "");
  expect(returnState).toMatch(/^[A-Za-z0-9_-]{32,200}$/);
  const hostedReturnUrl = new URL(
    "/makepay/checkout/return",
    new URL(backendUrl).origin,
  );
  hostedReturnUrl.searchParams.set("state", returnState);
  expect(
    await control({
      action: "assert-hosted-return",
      expectedReturnUrl: hostedReturnUrl.href,
      installation: "a",
      state: returnState,
      uid: payment.payment_link_uid,
    }),
  ).toEqual({
    configured: true,
    failureUrlMatches: true,
    returnUrlMatches: true,
    stateCorrelated: true,
    successUrlMatches: true,
  });

  const failedBefore = await control({
    action: "snapshot",
    installation: "b",
    uid: currentBOrder.payment.payment_link_uid,
  });
  const failedFixture = await control({
    action: "prepare-terminal-fixture",
    installation: "b",
    status: "failed",
    uid: currentBOrder.payment.payment_link_uid,
  });
  const failedFirst = await control({
    action: "post-terminal-fixture",
    fixtureId: failedFixture.fixtureId,
    installation: "b",
    target: "b",
  });
  expect(failedFirst).toMatchObject({
    deliveryGroupId: failedFixture.deliveryGroupId,
    deliveryId: failedFixture.deliveryId,
    responseStatus: 200,
    status: "failed",
    uid: currentBOrder.payment.payment_link_uid,
  });
  await expectProjectionState(
    request,
    installationB,
    secondHeaders,
    currentBOrder.payment.payment_link_uid,
    {
      hasPaymentId: false,
      medusaStatus: "failed",
      providerStatus: "failed",
    },
  );
  expect(
    await captureCount(
      request,
      installationB,
      secondHeaders,
      currentBOrder.order.id,
    ),
  ).toBe(0);
  await expect
    .poll(async () => {
      const snapshot = await control({
        action: "snapshot",
        installation: "b",
        uid: currentBOrder.payment.payment_link_uid,
      });
      return snapshot.deliveryCount;
    })
    .toBe(failedBefore.deliveryCount + 1);
  const failedDuplicate = await control({
    action: "post-terminal-fixture",
    fixtureId: failedFixture.fixtureId,
    installation: "b",
    target: "b",
  });
  expect(failedDuplicate).toMatchObject({
    deliveryGroupId: failedFirst.deliveryGroupId,
    deliveryId: failedFirst.deliveryId,
    responseStatus: 200,
    status: "failed",
  });
  expect(
    (
      await control({
        action: "snapshot",
        installation: "b",
        uid: currentBOrder.payment.payment_link_uid,
      })
    ).deliveryCount,
  ).toBe(failedBefore.deliveryCount + 1);
  expect(
    (
      await control({
        action: "deliver",
        installation: "b",
        status: "pending",
        target: "b",
        uid: currentBOrder.payment.payment_link_uid,
      })
    ).responseStatus,
  ).toBe(200);
  await expectProjectionState(
    request,
    installationB,
    secondHeaders,
    currentBOrder.payment.payment_link_uid,
    {
      hasPaymentId: false,
      medusaStatus: "failed",
      providerStatus: "failed",
    },
  );
  const failedOrderState = await orderPaymentState(
    request,
    installationB,
    secondHeaders,
    currentBOrder.order.id,
  );
  expect(failedOrderState.status).toBe("pending");
  expect(failedOrderState.paymentStatus).not.toBe("captured");

  const completeBefore = await control({
    action: "snapshot",
    installation: "a",
    uid: payment.payment_link_uid,
  });
  const completeFixture = await control({
    action: "prepare-terminal-fixture",
    installation: "a",
    status: "complete",
    uid: payment.payment_link_uid,
  });
  const completeFirst = await control({
    action: "post-terminal-fixture",
    fixtureId: completeFixture.fixtureId,
    installation: "a",
    target: "a",
  });
  expect(completeFirst).toMatchObject({
    deliveryGroupId: completeFixture.deliveryGroupId,
    deliveryId: completeFixture.deliveryId,
    responseStatus: 200,
    status: "complete",
    uid: payment.payment_link_uid,
  });
  await expectProjectionState(
    request,
    installationA,
    headers,
    payment.payment_link_uid,
    {
      hasPaymentId: true,
      medusaStatus: "paid",
      providerStatus: "complete",
    },
  );
  await expect
    .poll(() => captureCount(request, installationA, headers, order.id), {
      timeout: 60_000,
    })
    .toBe(1);
  await expect
    .poll(
      () => orderPaymentState(request, installationA, headers, order.id),
      { timeout: 60_000 },
    )
    .toEqual({
      paymentStatus: "captured",
      status: "pending",
    });
  await expect
    .poll(async () => {
      const snapshot = await control({
        action: "snapshot",
        installation: "a",
        uid: payment.payment_link_uid,
      });
      return snapshot.deliveryCount;
    })
    .toBe(completeBefore.deliveryCount + 1);
  const completeDuplicate = await control({
    action: "post-terminal-fixture",
    fixtureId: completeFixture.fixtureId,
    installation: "a",
    target: "a",
  });
  expect(completeDuplicate).toMatchObject({
    deliveryGroupId: completeFirst.deliveryGroupId,
    deliveryId: completeFirst.deliveryId,
    responseStatus: 200,
    status: "complete",
  });
  expect(
    (
      await control({
        action: "snapshot",
        installation: "a",
        uid: payment.payment_link_uid,
      })
    ).deliveryCount,
  ).toBe(completeBefore.deliveryCount + 1);
  expect(await captureCount(request, installationA, headers, order.id)).toBe(1);
  expect(
    (
      await control({
        action: "deliver",
        installation: "a",
        status: "pending",
        target: "a",
        uid: payment.payment_link_uid,
      })
    ).responseStatus,
  ).toBe(200);
  await expectProjectionState(
    request,
    installationA,
    headers,
    payment.payment_link_uid,
    {
      hasPaymentId: true,
      medusaStatus: "paid",
      providerStatus: "complete",
    },
  );
  expect(await captureCount(request, installationA, headers, order.id)).toBe(1);

  const checkoutStatus = await json(
    await request.get(
      `${backendInternalUrl}/store/makepay/checkout-status?state=${encodeURIComponent(returnState)}`,
      {
        headers: {
          "x-publishable-api-key": installationA.publishableKey,
        },
      },
    ),
    "Verify the completed MakePay storefront return state",
  );
  expect(checkoutStatus).toEqual({
    payment: {
      status: "paid",
      updated_at: expect.any(String),
    },
    terminal: true,
  });
  // The sandbox cannot complete without funds, so simulate only the hosted
  // provider's final navigation to the exact return URL already verified on
  // the real payment link. Medusa still performs the server-side status check
  // and the storefront still performs its normal verified-return redirect.
  await page.goto(hostedReturnUrl.href);
  await page.waitForURL(new RegExp(`/dk/order/${order.id}/confirmed(?:\\?|$)`), {
    timeout: 60_000,
  });
  expect(new URL(page.url()).origin).toBe(new URL(storefrontUrl).origin);
  await expect(page.locator("body")).toContainText(
    /thank you|order confirmed/i,
  );

  const archivedB = await control({
    action: "archive-all-payment-links",
    installation: "b",
  });
  expect(archivedB.unresolved).toEqual([]);
  expect(archivedB.verified).toEqual(
    expect.arrayContaining([
      initialBOrder.payment.payment_link_uid,
      currentBOrder.payment.payment_link_uid,
    ]),
  );
  const archivedA = await control({
    action: "archive-all-payment-links",
    installation: "a",
  });
  expect(archivedA.unresolved).toEqual([]);
  expect(archivedA.verified).toContain(payment.payment_link_uid);
  await expectProjectionStatus(
    request,
    installationA,
    headers,
    payment.payment_link_uid,
    "complete",
  );
  await expectProjectionStatus(
    request,
    installationB,
    secondHeaders,
    currentBOrder.payment.payment_link_uid,
    "failed",
  );
  expect(await captureCount(request, installationA, headers, order.id)).toBe(1);
  expect(
    await captureCount(
      request,
      installationB,
      secondHeaders,
      currentBOrder.order.id,
    ),
  ).toBe(0);

  expect(connection.company_id).toBe(sandboxCompanyId);
  // The runner owns final disconnect after it has stopped every HTTP mutator,
  // performed one last remote enumeration, and independently re-verified all
  // run-owned links. Disconnecting here would erase the credentials required
  // to close a create-before-projection interruption window.
});
