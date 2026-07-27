import assert from "node:assert/strict";
import {
  createHash,
  createHmac,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign as signValue,
} from "node:crypto";
import { createServer } from "node:http";
import { createMakePayContractServer } from "./support/makepay-contract-server.mjs";
import { realSandboxHelperTest } from "./support/real-sandbox-event-helper.mjs";

const base64url = (value) =>
  Buffer.from(value)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");

const sha256 = (value) =>
  base64url(createHash("sha256").update(value).digest());

function decodeJwtPayload(token) {
  const parts = String(token).split(".");
  assert.equal(parts.length, 3, "expected a compact JWT");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

function signer() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const jwk = publicKey.export({ format: "jwk" });
  const jkt = sha256(
    JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }),
  );
  return {
    jkt,
    proof({ accessToken, method, url }) {
      const header = base64url(
        JSON.stringify({ alg: "ES256", jwk, typ: "dpop+jwt" }),
      );
      const payload = base64url(
        JSON.stringify({
          ...(accessToken ? { ath: sha256(accessToken) } : {}),
          htm: method.toUpperCase(),
          htu: url,
          iat: Math.floor(Date.now() / 1000),
          jti: randomUUID(),
        }),
      );
      const input = `${header}.${payload}`;
      const signature = signValue("sha256", Buffer.from(input), {
        dsaEncoding: "ieee-p1363",
        key: privateKey,
      });
      return `${input}.${base64url(signature)}`;
    },
  };
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  return `http://127.0.0.1:${address.port}`;
}

async function close(server) {
  await new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
}

async function connectOauthInstallation({
  contract,
  dpop,
  expectedRegistrationStatus = 201,
  registrationId = base64url(randomBytes(32)),
  redirectUri,
  siteUrl,
  state,
}) {
  const installationUrl = `${contract.origin}/oauth/native/installations`;
  const installationResponse = await fetch(installationUrl, {
    body: JSON.stringify({
      dpopJkt: dpop.jkt,
      medusaVersion: "2.17.2",
      platform: "medusa",
      pluginVersion: "1.0.0",
      registrationId,
      redirectUri,
      siteUrl,
    }),
    headers: {
      "content-type": "application/json",
      dpop: dpop.proof({ method: "POST", url: installationUrl }),
    },
    method: "POST",
  });
  assert.equal(installationResponse.status, expectedRegistrationStatus);
  const installation = await installationResponse.json();
  assert.equal(installation.registration_id, registrationId);

  const verifier = base64url(randomBytes(48));
  const authorizeUrl = new URL("/oauth/authorize", contract.origin);
  authorizeUrl.searchParams.set("client_id", installation.client_id);
  authorizeUrl.searchParams.set("code_challenge", sha256(verifier));
  authorizeUrl.searchParams.set("code_challenge_method", "S256");
  authorizeUrl.searchParams.set("dpop_jkt", dpop.jkt);
  authorizeUrl.searchParams.set("redirect_uri", redirectUri);
  authorizeUrl.searchParams.set(
    "resource",
    `${contract.origin}/api/partner/v1`,
  );
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("scope", installation.scopes.join(" "));
  authorizeUrl.searchParams.set("state", state);
  authorizeUrl.searchParams.set("decision", "approve");
  const authorizeResponse = await fetch(authorizeUrl, { redirect: "manual" });
  assert.equal(authorizeResponse.status, 302);
  const callback = new URL(authorizeResponse.headers.get("location"));
  assert.equal(callback.searchParams.get("state"), state);
  assert.equal(callback.searchParams.get("iss"), contract.origin);

  const tokenUrl = `${contract.origin}/oauth/token`;
  const tokenResponse = await fetch(tokenUrl, {
    body: new URLSearchParams({
      client_id: installation.client_id,
      code: callback.searchParams.get("code"),
      code_verifier: verifier,
      grant_type: "authorization_code",
      redirect_uri: redirectUri,
      resource: `${contract.origin}/api/partner/v1`,
    }),
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      dpop: dpop.proof({ method: "POST", url: tokenUrl }),
      "idempotency-key": `medusa-token-${base64url(randomBytes(32))}`,
    },
    method: "POST",
  });
  assert.equal(tokenResponse.status, 200);
  return { installation, registrationId, tokens: await tokenResponse.json() };
}

function refreshSmokeService({ afterThumbprint = "thumbprint_stable" } = {}) {
  const runId = "medusa-e2e-refresh-helper-0123456789abcdef";
  const paymentLinkUid = "refresh_helper_link";
  const context = {
    companyId: "company_refresh_helper",
    grantId: "grant_refresh_helper",
    installationId: "installation_refresh_helper",
    webhookSubscriptionId: "subscription_refresh_helper",
  };
  const webhookUrl = "https://merchant.example/makepay/webhook";
  let connection = {
    access_token_expires_at: new Date(Date.now() + 10 * 60_000),
    auth_mode: "oauth",
    client_id: context.installationId,
    company_id: context.companyId,
    connected_at: new Date().toISOString(),
    encrypted_access_token: "access_envelope_before",
    encrypted_dpop_private_key: "dpop_envelope_before",
    encrypted_refresh_token: "refresh_envelope_before",
    encrypted_webhook_secret: "webhook_envelope",
    grant_id: context.grantId,
    id: "connection_refresh_helper",
    installation_id: context.installationId,
    last_error: null,
    metadata: { dpop_thumbprint: "thumbprint_stable" },
    provider_id: "makepay",
    status: "connected",
    webhook_status: "healthy",
    webhook_subscription_id: context.webhookSubscriptionId,
    webhook_url: webhookUrl,
  };
  const snapshot = () => ({
    ...connection,
    metadata: { ...connection.metadata },
  });
  const service = {
    authMode: "oauth",
    providerId: "makepay",
    createClient: async () => ({
      getCurrentWebhookSubscription: async () => {
        connection = {
          ...connection,
          access_token_expires_at: new Date(Date.now() + 10 * 60_000),
          encrypted_access_token: "access_envelope_after",
          // AES-256-GCM rewraps the same DPoP key with a fresh nonce.
          encrypted_dpop_private_key: "dpop_envelope_after",
          encrypted_refresh_token: "refresh_envelope_after",
          metadata: { dpop_thumbprint: afterThumbprint },
        };
        return {
          companyId: context.companyId,
          subscription: {
            id: context.webhookSubscriptionId,
            url: webhookUrl,
          },
        };
      },
    }),
    getInstallationContext: async () => context,
    listMakePayConnections: async () => [snapshot()],
    projectionByUid: async (uid) => ({
      auth_mode: "oauth",
      company_id: context.companyId,
      customer_email: `makepay-real-sandbox+${runId}@example.com`,
      grant_id: context.grantId,
      installation_id: context.installationId,
      payment_link_uid: uid,
      provider_id: "makepay",
      session_id: "session_refresh_helper",
      webhook_subscription_id: context.webhookSubscriptionId,
    }),
    updateMakePayConnections: async (update) => {
      assert.equal(update.id, connection.id);
      connection = {
        ...connection,
        access_token_expires_at: update.access_token_expires_at,
      };
    },
  };
  return {
    request: { paymentLinkUid, runId },
    service,
  };
}

async function main() {
  const stableRefresh = refreshSmokeService();
  const stableRefreshResult =
    await realSandboxHelperTest.forceOAuthRefreshReadSmoke(
      stableRefresh.service,
      stableRefresh.request,
    );
  assert.equal(stableRefreshResult.dpopCredentialStable, true);
  assert.equal(stableRefreshResult.authenticatedReadCompleted, true);

  const changedThumbprintRefresh = refreshSmokeService({
    afterThumbprint: "thumbprint_changed",
  });
  await assert.rejects(
    () =>
      realSandboxHelperTest.forceOAuthRefreshReadSmoke(
        changedThumbprintRefresh.service,
        changedThumbprintRefresh.request,
      ),
    (error) => {
      assert.match(String(error?.message), /dpopCredentialStable/);
      assert.doesNotMatch(String(error?.message), /dpop_envelope/);
      return true;
    },
  );

  const cleanupRunId = "medusa-e2e-2026-07-19T00-00-00-000Z-0123456789abcdef";
  const cleanupEmails = realSandboxHelperTest.runOwnedEmails(cleanupRunId);
  assert.equal(
    cleanupEmails.has(
      `makepay-real-sandbox+${cleanupRunId}2@example.com`.toLowerCase(),
    ),
    false,
  );
  const validEmptyEnumeration =
    await realSandboxHelperTest.listAllRemotePaymentLinks(
      {
        listPaymentLinks: async () => ({
          companyId: "company_cleanup",
          paymentLinks: [],
        }),
      },
      "company_cleanup",
    );
  assert.deepEqual(validEmptyEnumeration.paymentLinks, []);
  await assert.rejects(() =>
    realSandboxHelperTest.listAllRemotePaymentLinks(
      {
        listPaymentLinks: async () => ({ companyId: "company_cleanup" }),
      },
      "company_cleanup",
    ),
  );
  await assert.rejects(() =>
    realSandboxHelperTest.listAllRemotePaymentLinks(
      {
        listPaymentLinks: async () => ({
          companyId: "company_foreign",
          paymentLinks: [],
        }),
      },
      "company_cleanup",
    ),
  );
  await assert.rejects(() =>
    realSandboxHelperTest.listAllRemotePaymentLinks(
      {
        listPaymentLinks: async () => ({
          companyId: "company_cleanup",
          hasMore: true,
          paymentLinks: [],
        }),
      },
      "company_cleanup",
    ),
  );
  const cleanupContext = {
    companyId: "company_cleanup",
    grantId: "grant_cleanup",
    installationId: "installation_cleanup",
    webhookSubscriptionId: "subscription_cleanup",
  };
  const cleanupService = (paymentLink) => ({
    createClient: async () => ({
      listPaymentLinks: async () => ({
        companyId: cleanupContext.companyId,
        paymentLinks: [paymentLink],
      }),
    }),
    getInstallationContext: async () => cleanupContext,
    listPaymentViews: async () => ({ count: 0, payments: [] }),
  });
  const unrelatedMalformed = await realSandboxHelperTest.cleanupCandidates(
    cleanupService({
      customerEmail: "unrelated@example.com",
      metadata: {},
      uid: "link_unrelated",
    }),
    cleanupRunId,
  );
  assert.deepEqual(unrelatedMalformed.remoteCandidates, []);
  await assert.rejects(() =>
    realSandboxHelperTest.cleanupCandidates(
      cleanupService({
        customerEmail: [...cleanupEmails][0],
        metadata: {},
        uid: "link_owned_but_malformed",
      }),
      cleanupRunId,
    ),
  );
  const ownedProjection = {
    authMode: "oauth",
    companyId: cleanupContext.companyId,
    customerEmail: [...cleanupEmails][0],
    grantId: cleanupContext.grantId,
    installationId: cleanupContext.installationId,
    sessionId: "payses_cleanup",
    subscriptionId: cleanupContext.webhookSubscriptionId,
    uid: "link_owned_without_remote_email",
  };
  const ownedRemoteWithoutEmail = {
    companyId: cleanupContext.companyId,
    paymentLink: {
      metadata: {
        medusaInstallationId: cleanupContext.installationId,
        medusaProviderId: "makepay",
        medusaSessionId: ownedProjection.sessionId,
      },
      uid: ownedProjection.uid,
    },
  };
  assert.equal(
    realSandboxHelperTest.remoteRunOwnedLink(
      ownedRemoteWithoutEmail,
      {
        context: cleanupContext,
        ownedEmails: cleanupEmails,
        ownedProjection,
        uid: ownedProjection.uid,
      },
    ).link.uid,
    ownedProjection.uid,
  );
  for (const mismatchedProjection of [
    { ...ownedProjection, uid: "link_foreign" },
    { ...ownedProjection, sessionId: "payses_foreign" },
  ]) {
    assert.throws(() =>
      realSandboxHelperTest.remoteRunOwnedLink(
        ownedRemoteWithoutEmail,
        {
          context: cleanupContext,
          ownedEmails: cleanupEmails,
          ownedProjection: mismatchedProjection,
          uid: ownedProjection.uid,
        },
      ),
    );
  }
  assert.throws(() =>
    realSandboxHelperTest.remoteRunOwnedLink(
      {
        ...ownedRemoteWithoutEmail,
        paymentLink: {
          ...ownedRemoteWithoutEmail.paymentLink,
          customerEmail: "unrelated@example.com",
        },
      },
      {
        context: cleanupContext,
        ownedEmails: cleanupEmails,
        ownedProjection,
        uid: ownedProjection.uid,
      },
    ),
  );
  const boundaryProjectionRecord = {
    amount: "20",
    auth_mode: ownedProjection.authMode,
    company_id: ownedProjection.companyId,
    currency: "EUR",
    customer_email: ownedProjection.customerEmail,
    grant_id: ownedProjection.grantId,
    installation_id: ownedProjection.installationId,
    medusa_status: "pending_authorization",
    order_display_id: null,
    order_id: null,
    payment_id: null,
    payment_link_uid: ownedProjection.uid,
    provider_id: "makepay",
    provider_status: "active",
    session_id: ownedProjection.sessionId,
    webhook_subscription_id: ownedProjection.subscriptionId,
  };
  const boundaryCleanup = await realSandboxHelperTest.cleanupCandidates(
    {
      createClient: async () => ({
        listPaymentLinks: async () => ({
          companyId: cleanupContext.companyId,
          paymentLinks: [ownedRemoteWithoutEmail.paymentLink],
        }),
      }),
      getInstallationContext: async () => cleanupContext,
      listPaymentViews: async (query) => {
        assert.equal(query.limit, 100);
        assert.match(query.q, /^makepay-real-sandbox\+medusa-e2e-/);
        return {
          count: 1,
          payments: [boundaryProjectionRecord],
        };
      },
      projectionByUid: async (uid) => {
        assert.equal(uid, ownedProjection.uid);
        return boundaryProjectionRecord;
      },
    },
    cleanupRunId,
  );
  assert.equal(boundaryCleanup.candidates.length, 1);
  assert.deepEqual(boundaryCleanup.remoteCandidates, []);
  assert.deepEqual(
    {
      authMode: boundaryCleanup.candidates[0].authMode,
      companyId: boundaryCleanup.candidates[0].companyId,
      customerEmail: boundaryCleanup.candidates[0].customerEmail,
      grantId: boundaryCleanup.candidates[0].grantId,
      installationId: boundaryCleanup.candidates[0].installationId,
      sessionId: boundaryCleanup.candidates[0].sessionId,
      subscriptionId: boundaryCleanup.candidates[0].subscriptionId,
      uid: boundaryCleanup.candidates[0].uid,
    },
    ownedProjection,
  );
  assert.equal(
    realSandboxHelperTest.remoteRunOwnedLink(
      ownedRemoteWithoutEmail,
      {
        context: cleanupContext,
        ownedEmails: cleanupEmails,
        ownedProjection: boundaryCleanup.candidates[0],
        uid: ownedProjection.uid,
      },
    ).link.uid,
    ownedProjection.uid,
  );

  const terminalProjectionRecord = {
    ...boundaryProjectionRecord,
    id: "projection_terminal",
    order_display_id: "1001",
    order_id: "order_terminal",
  };
  assert.equal(
    realSandboxHelperTest.assertRunOwnedTerminalProjection(
      terminalProjectionRecord,
      cleanupContext,
      ownedProjection.uid,
      cleanupRunId,
    ).orderId,
    "order_terminal",
  );
  for (const status of ["complete", "failed"]) {
    const event = realSandboxHelperTest.canonicalEvent(
      terminalProjectionRecord,
      cleanupContext,
      status,
      realSandboxHelperTest.terminalFixtureStatuses,
    );
    assert.equal(event.status, status);
    assert.equal(event.paymentLink.uid, ownedProjection.uid);
    assert.equal(
      event.paymentLink.metadata.medusaSessionId,
      ownedProjection.sessionId,
    );
    assert.equal(event.paymentLink.metadata.medusaOrderId, "order_terminal");
  }
  assert.throws(() =>
    realSandboxHelperTest.canonicalEvent(
      terminalProjectionRecord,
      cleanupContext,
      "pending",
      realSandboxHelperTest.terminalFixtureStatuses,
    ),
  );
  assert.throws(() =>
    realSandboxHelperTest.canonicalEvent(
      terminalProjectionRecord,
      cleanupContext,
      "complete",
      realSandboxHelperTest.noFundsStatuses,
    ),
  );
  for (const invalidTerminalProjection of [
    { ...terminalProjectionRecord, customer_email: "unrelated@example.com" },
    { ...terminalProjectionRecord, order_id: null },
    { ...terminalProjectionRecord, payment_id: "pay_already_created" },
    { ...terminalProjectionRecord, medusa_status: "paid" },
  ]) {
    assert.throws(() =>
      realSandboxHelperTest.assertRunOwnedTerminalProjection(
        invalidTerminalProjection,
        cleanupContext,
        ownedProjection.uid,
        cleanupRunId,
      ),
    );
  }

  const returnState =
    "terminal-return-state-0123456789abcdefghijklmnopqrstuvwxyz";
  const expectedReturnUrl = `https://medusa-sandbox.example/makepay/checkout/return?state=${returnState}`;
  const remoteTerminalLink = {
    ...ownedRemoteWithoutEmail,
    paymentLink: {
      ...ownedRemoteWithoutEmail.paymentLink,
      failureUrl: expectedReturnUrl,
      returnUrl: expectedReturnUrl,
      successUrl: expectedReturnUrl,
    },
  };
  const returnService = {
    createClient: async () => ({
      getPaymentLink: async () => remoteTerminalLink,
    }),
    getInstallationContext: async () => cleanupContext,
    projectionByReturnState: async (state) =>
      state === returnState ? terminalProjectionRecord : undefined,
    projectionByUid: async (uid) =>
      uid === ownedProjection.uid ? terminalProjectionRecord : undefined,
  };
  assert.deepEqual(
    await realSandboxHelperTest.assertHostedReturnConfiguration(
      returnService,
      {
        expectedReturnUrl,
        runId: cleanupRunId,
        state: returnState,
        uid: ownedProjection.uid,
      },
    ),
    {
      configured: true,
      failureUrlMatches: true,
      returnUrlMatches: true,
      stateCorrelated: true,
      successUrlMatches: true,
    },
  );
  await assert.rejects(() =>
    realSandboxHelperTest.assertHostedReturnConfiguration(returnService, {
      expectedReturnUrl: expectedReturnUrl.replace(
        "medusa-sandbox.example",
        "unrelated.example",
      ),
      runId: cleanupRunId,
      state: returnState,
      uid: ownedProjection.uid,
    }),
  );

  const webhookDeliveries = [];
  const webhookSecret = "e2e_webhook_secret";
  const webhookSecrets = new Map([["/hook-a", webhookSecret]]);
  const webhookReceiver = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString("utf8");
    const signatureHeader = String(req.headers["x-makepay-signature"] || "");
    const signatureParts = Object.fromEntries(
      signatureHeader.split(",").map((part) => part.split("=", 2)),
    );
    const receiverSecret = webhookSecrets.get(req.url);
    assert.ok(receiverSecret, `No signing secret registered for ${req.url}`);
    const expected = createHmac("sha256", receiverSecret)
      .update(`${signatureParts.t}.${raw}`)
      .digest("hex");
    assert.equal(signatureParts.v1, expected);
    webhookDeliveries.push({
      attempt: req.headers["x-makepay-attempt"],
      body: JSON.parse(raw),
      deliveryGroupId: req.headers["x-makepay-delivery-group-id"],
      deliveryId: req.headers["x-makepay-delivery-id"],
      pathname: req.url,
    });
    res.writeHead(200).end("ok");
  });
  const webhookOrigin = await listen(webhookReceiver);

  const contract = createMakePayContractServer({ webhookSecret });
  await contract.start();
  const dpop = signer();

  try {
    const health = await fetch(`${contract.origin}/health`).then((res) =>
      res.json(),
    );
    assert.deepEqual(health, { mode: "sandbox-contract", ok: true });

    contract.state.idempotency.set("stale-token-receipt", {});
    contract.state.resetReceipts.set("stale-reset-receipt", {});
    contract.state.subscriptions.set("stale-subscription", {});
    contract.state.webhookMutationReceipts.set("stale-webhook-receipt", {});
    contract.state.deliveryGroups.set("stale-delivery", {});
    contract.state.preparedWebhooks.set("stale-prepared-delivery", {});
    contract.state.webhookAttempts.push({ deliveryId: "stale-attempt" });
    contract.state.nativeResetResponseLosses = 2;
    contract.reset();
    for (const collection of [
      contract.state.idempotency,
      contract.state.resetReceipts,
      contract.state.subscriptions,
      contract.state.webhookMutationReceipts,
      contract.state.deliveryGroups,
      contract.state.preparedWebhooks,
    ]) {
      assert.equal(collection.size, 0);
    }
    assert.equal(contract.state.webhookAttempts.length, 0);
    assert.equal(contract.state.nativeResetResponseLosses, 0);

    const redirectUri = "http://127.0.0.1:9000/makepay/oauth/callback";
    const installationUrl = `${contract.origin}/oauth/native/installations`;
    const registrationId = base64url(randomBytes(32));
    const nativeRegistrationBody = {
      dpopJkt: dpop.jkt,
      medusaVersion: "2.17.2",
      platform: "medusa",
      pluginVersion: "1.0.0",
      registrationId,
      redirectUri,
      siteUrl: "http://127.0.0.1:9000",
    };
    for (const invalidRegistrationBody of [
      Object.fromEntries(
        Object.entries(nativeRegistrationBody).filter(
          ([key]) => key !== "registrationId",
        ),
      ),
      { ...nativeRegistrationBody, registrationId: "too-short" },
    ]) {
      const invalidRegistration = await fetch(installationUrl, {
        body: JSON.stringify(invalidRegistrationBody),
        headers: {
          "content-type": "application/json",
          dpop: dpop.proof({ method: "POST", url: installationUrl }),
        },
        method: "POST",
      });
      assert.equal(invalidRegistration.status, 400);
    }
    const installationResponse = await fetch(installationUrl, {
      body: JSON.stringify(nativeRegistrationBody),
      headers: {
        "content-type": "application/json",
        dpop: dpop.proof({ method: "POST", url: installationUrl }),
      },
      method: "POST",
    });
    assert.equal(installationResponse.status, 201);
    const installation = await installationResponse.json();
    assert.equal(installation.client_type, "public");
    assert.equal(installation.dpop_bound, true);
    assert.equal(installation.registration_id, registrationId);
    assert.ok(installation.scopes.includes("makepay:webhooks:write"));

    const verifier = base64url(randomBytes(48));
    const state = "oauth-state-e2e";
    const authorizeUrl = new URL("/oauth/authorize", contract.origin);
    authorizeUrl.searchParams.set("client_id", installation.client_id);
    authorizeUrl.searchParams.set("code_challenge", sha256(verifier));
    authorizeUrl.searchParams.set("code_challenge_method", "S256");
    authorizeUrl.searchParams.set("dpop_jkt", dpop.jkt);
    authorizeUrl.searchParams.set("redirect_uri", redirectUri);
    authorizeUrl.searchParams.set(
      "resource",
      `${contract.origin}/api/partner/v1`,
    );
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("scope", installation.scopes.join(" "));
    authorizeUrl.searchParams.set("state", state);
    authorizeUrl.searchParams.set("decision", "approve");
    const authorizeResponse = await fetch(authorizeUrl, { redirect: "manual" });
    assert.equal(authorizeResponse.status, 302);
    const callback = new URL(authorizeResponse.headers.get("location"));
    assert.equal(callback.searchParams.get("state"), state);
    assert.equal(callback.searchParams.get("iss"), contract.origin);
    const code = callback.searchParams.get("code");
    assert.ok(code);

    const tokenUrl = `${contract.origin}/oauth/token`;
    const tokenResponse = await fetch(tokenUrl, {
      body: new URLSearchParams({
        client_id: installation.client_id,
        code,
        code_verifier: verifier,
        grant_type: "authorization_code",
        redirect_uri: redirectUri,
        resource: `${contract.origin}/api/partner/v1`,
      }),
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: dpop.proof({ method: "POST", url: tokenUrl }),
        "idempotency-key": `medusa-token-${base64url(randomBytes(32))}`,
      },
      method: "POST",
    });
    assert.equal(tokenResponse.status, 200);
    const tokens = await tokenResponse.json();
    assert.equal(tokens.token_type, "DPoP");
    const tokenClaims = decodeJwtPayload(tokens.access_token);
    assert.equal(tokenClaims.installation_id, installation.client_id);

    const subscriptionUrl = `${contract.origin}/api/partner/v1/makepay/webhook-subscriptions/current`;
    const subscriptionResponse = await fetch(subscriptionUrl, {
      body: JSON.stringify({
        active: true,
        events: ["makepay.payment.status_changed"],
        url: `${webhookOrigin}/hook-a`,
      }),
      headers: {
        authorization: `DPoP ${tokens.access_token}`,
        "content-type": "application/json",
        dpop: dpop.proof({
          accessToken: tokens.access_token,
          method: "PUT",
          url: subscriptionUrl,
        }),
      },
      method: "PUT",
    });
    assert.equal(subscriptionResponse.status, 200);
    const subscription = await subscriptionResponse.json();
    assert.equal(subscription.signingSecret, webhookSecret);

    const paymentLinksUrl = `${contract.origin}/api/partner/v1/makepay/payment-links`;
    const createResponse = await fetch(paymentLinksUrl, {
      body: JSON.stringify({
        sendPaymentRequestEmail: false,
        status: "active",
        payload: {
          amount: "20.00",
          currency: "USDT",
          fiatCurrency: "EUR",
          metadata: {
            arbitraryInjectedField: "must-not-propagate",
            medusaProviderId: "makepay",
            medusaSessionId: "payses_e2e",
          },
        },
      }),
      headers: {
        authorization: `DPoP ${tokens.access_token}`,
        "content-type": "application/json",
        dpop: dpop.proof({
          accessToken: tokens.access_token,
          method: "POST",
          url: paymentLinksUrl,
        }),
        "idempotency-key": "medusa-e2e-link",
      },
      method: "POST",
    });
    assert.equal(createResponse.status, 201);
    const created = await createResponse.json();
    assert.equal(created.companyId, tokenClaims.company_id);
    assert.equal(created.paymentLink.amount, "20.00");
    assert.equal(created.paymentLink.fiatAmount, "20.00");
    assert.equal(created.paymentLink.fiatCurrency, "EUR");
    assert.equal(created.paymentLink.currency, "USDT");
    assert.equal(created.paymentLink.payload.amount, "20.00");
    assert.equal(created.paymentLink.payload.fiatCurrency, "EUR");
    assert.equal(created.paymentLink.payload.sandbox, true);
    assert.deepEqual(
      created.paymentLink.metadata,
      created.paymentLink.payload.metadata,
    );
    for (const privateRoutingKey of [
      "companyId",
      "grantId",
      "installationId",
      "webhookSubscriptionId",
    ]) {
      assert.equal(privateRoutingKey in created.paymentLink, false);
    }

    const secondDpop = signer();
    const secondConnection = await connectOauthInstallation({
      contract,
      dpop: secondDpop,
      redirectUri: "http://127.0.0.1:9002/makepay/oauth/callback",
      siteUrl: "http://127.0.0.1:9002",
      state: "oauth-state-e2e-b",
    });
    const secondTokenClaims = decodeJwtPayload(
      secondConnection.tokens.access_token,
    );
    assert.notEqual(
      secondConnection.installation.client_id,
      installation.client_id,
    );
    const secondSubscriptionResponse = await fetch(subscriptionUrl, {
      body: JSON.stringify({
        active: true,
        events: ["makepay.payment.status_changed"],
        rotateSecret: true,
        url: `${webhookOrigin}/hook-b`,
      }),
      headers: {
        authorization: `DPoP ${secondConnection.tokens.access_token}`,
        "content-type": "application/json",
        dpop: secondDpop.proof({
          accessToken: secondConnection.tokens.access_token,
          method: "PUT",
          url: subscriptionUrl,
        }),
      },
      method: "PUT",
    });
    assert.equal(secondSubscriptionResponse.status, 200);
    const secondSubscription = await secondSubscriptionResponse.json();
    assert.notEqual(secondSubscription.signingSecret, webhookSecret);
    webhookSecrets.set("/hook-b", secondSubscription.signingSecret);

    const secondCreateResponse = await fetch(paymentLinksUrl, {
      body: JSON.stringify({
        payload: {
          amount: "21.00",
          currency: "USDT",
          fiatCurrency: "EUR",
          metadata: {
            medusaProviderId: "makepay",
            medusaSessionId: "payses_e2e_b",
          },
        },
      }),
      headers: {
        authorization: `DPoP ${secondConnection.tokens.access_token}`,
        "content-type": "application/json",
        dpop: secondDpop.proof({
          accessToken: secondConnection.tokens.access_token,
          method: "POST",
          url: paymentLinksUrl,
        }),
        // Deliberately identical to installation A: idempotency is grant-scoped.
        "idempotency-key": "medusa-e2e-link",
      },
      method: "POST",
    });
    assert.equal(secondCreateResponse.status, 201);
    const secondCreated = await secondCreateResponse.json();
    assert.notEqual(secondCreated.paymentLink.uid, created.paymentLink.uid);
    assert.notEqual(secondTokenClaims.grant_id, tokenClaims.grant_id);
    assert.notEqual(
      secondTokenClaims.installation_id,
      tokenClaims.installation_id,
    );
    assert.equal(secondCreated.companyId, secondTokenClaims.company_id);
    assert.equal("grantId" in secondCreated.paymentLink, false);

    const listWithQuery = await fetch(`${paymentLinksUrl}?limit=10`, {
      headers: {
        authorization: `DPoP ${tokens.access_token}`,
        dpop: dpop.proof({
          accessToken: tokens.access_token,
          method: "GET",
          // RFC 9449 excludes query and fragment from htu.
          url: paymentLinksUrl,
        }),
      },
    });
    assert.equal(listWithQuery.status, 200);
    const firstList = await listWithQuery.json();
    assert.equal(firstList.companyId, tokenClaims.company_id);
    assert.deepEqual(
      firstList.paymentLinks.map((link) => link.uid),
      [created.paymentLink.uid],
    );

    const secondListResponse = await fetch(`${paymentLinksUrl}?limit=10`, {
      headers: {
        authorization: `DPoP ${secondConnection.tokens.access_token}`,
        dpop: secondDpop.proof({
          accessToken: secondConnection.tokens.access_token,
          method: "GET",
          url: paymentLinksUrl,
        }),
      },
    });
    assert.equal(secondListResponse.status, 200);
    const secondList = await secondListResponse.json();
    assert.equal(secondList.companyId, secondTokenClaims.company_id);
    assert.deepEqual(
      secondList.paymentLinks.map((link) => link.uid),
      [secondCreated.paymentLink.uid],
    );

    const detailUrl = `${paymentLinksUrl}/${created.paymentLink.uid}`;
    const detailResponse = await fetch(detailUrl, {
      headers: {
        authorization: `DPoP ${tokens.access_token}`,
        dpop: dpop.proof({
          accessToken: tokens.access_token,
          method: "GET",
          url: detailUrl,
        }),
      },
    });
    assert.equal(detailResponse.status, 200);
    const detail = await detailResponse.json();
    assert.deepEqual(Object.keys(detail).sort(), ["companyId", "paymentLink"]);
    assert.equal(detail.paymentLink.amount, detail.paymentLink.payload.amount);
    assert.equal(
      detail.paymentLink.fiatCurrency,
      detail.paymentLink.payload.fiatCurrency,
    );

    const patchResponse = await fetch(detailUrl, {
      body: JSON.stringify({ status: "paused" }),
      headers: {
        authorization: `DPoP ${tokens.access_token}`,
        "content-type": "application/json",
        dpop: dpop.proof({
          accessToken: tokens.access_token,
          method: "PATCH",
          url: detailUrl,
        }),
        "idempotency-key": "medusa-e2e-pause-link",
      },
      method: "PATCH",
    });
    assert.equal(patchResponse.status, 200);
    const patched = await patchResponse.json();
    assert.deepEqual(Object.keys(patched).sort(), ["companyId", "paymentLink"]);
    assert.equal(patched.paymentLink.status, "paused");
    assert.deepEqual(patched.paymentLink.payload, created.paymentLink.payload);

    const bearerBypass = await fetch(paymentLinksUrl, {
      headers: {
        authorization: `Bearer ${tokens.access_token}`,
      },
    });
    assert.equal(bearerBypass.status, 401);
    const wrongDpopKey = await fetch(paymentLinksUrl, {
      headers: {
        authorization: `DPoP ${tokens.access_token}`,
        dpop: secondDpop.proof({
          accessToken: tokens.access_token,
          method: "GET",
          url: paymentLinksUrl,
        }),
      },
    });
    assert.equal(wrongDpopKey.status, 401);

    const hosted = await fetch(created.paymentLink.publicUrl).then((res) =>
      res.text(),
    );
    assert.match(hosted, /Do not send real funds/);
    const started = await fetch(`${created.paymentLink.publicUrl}/start`, {
      method: "POST",
    }).then((res) => res.text());
    assert.match(started, /SANDBOX-DO-NOT-SEND/);
    assert.equal(webhookDeliveries.at(-1).pathname, "/hook-a");
    assert.equal(webhookDeliveries.at(-1).body.status, "awaiting_deposit");
    assert.ok(webhookDeliveries.at(-1).body.session.id.startsWith("mpses_"));
    const firstDefaultDelivery = webhookDeliveries.at(-1);
    await contract.emitWebhook({
      status: "awaiting_deposit",
      uid: created.paymentLink.uid,
    });
    const retriedDefaultDelivery = webhookDeliveries.at(-1);
    assert.equal(
      retriedDefaultDelivery.body.deliveryGroupId,
      firstDefaultDelivery.body.deliveryGroupId,
    );
    assert.notEqual(
      retriedDefaultDelivery.body.deliveryId,
      firstDefaultDelivery.body.deliveryId,
    );

    const preparedDeliveryCount = webhookDeliveries.length;
    const prepared = await contract.emitWebhook({
      defer: true,
      deliveryGroupId: `mpwhgrp_${"b".repeat(64)}`,
      eventCreatedAt: "2026-07-19T00:00:00.000Z",
      orderDisplayId: null,
      orderId: null,
      status: "quoted",
      uid: created.paymentLink.uid,
      updateRemoteStatus: false,
    });
    assert.equal(webhookDeliveries.length, preparedDeliveryCount);
    assert.equal(contract.state.preparedWebhooks.size, 1);
    const deliveredPrepared = await fetch(`${contract.origin}/__e2e/deliver`, {
      body: JSON.stringify({ preparedId: prepared.preparedId }),
      headers: {
        "content-type": "application/json",
        "x-e2e-control-token": contract.controlToken,
      },
      method: "POST",
    });
    assert.equal(deliveredPrepared.status, 200);
    assert.equal(contract.state.preparedWebhooks.size, 0);
    assert.equal(webhookDeliveries.length, preparedDeliveryCount + 1);
    assert.equal(
      webhookDeliveries.at(-1).body.createdAt,
      "2026-07-19T00:00:00.000Z",
    );
    assert.equal(
      webhookDeliveries.at(-1).body.paymentLink.metadata.medusaOrderId,
      null,
    );

    const capturedDeliveryGroupId = `mpwhgrp_${"c".repeat(64)}`;
    await contract.emitWebhook({
      attempt: 2,
      deliveryGroupId: capturedDeliveryGroupId,
      deliveryId: "00000000-0000-4000-8000-000000000002",
      failWorkflowOnce: true,
      status: "complete",
      uid: created.paymentLink.uid,
    });
    const canonicalDelivery = webhookDeliveries.at(-1);
    assert.equal(
      canonicalDelivery.body.deliveryId,
      "00000000-0000-4000-8000-000000000002",
    );
    assert.equal(
      canonicalDelivery.body.deliveryGroupId,
      capturedDeliveryGroupId,
    );
    assert.equal(canonicalDelivery.attempt, "2");
    assert.equal(
      canonicalDelivery.deliveryGroupId,
      canonicalDelivery.body.deliveryGroupId,
    );
    assert.equal(
      canonicalDelivery.deliveryId,
      canonicalDelivery.body.deliveryId,
    );
    assert.deepEqual(Object.keys(canonicalDelivery.body).sort(), [
      "companyId",
      "createdAt",
      "deliveryGroupId",
      "deliveryId",
      "grantId",
      "installationId",
      "paymentLink",
      "schemaVersion",
      "session",
      "status",
      "subscriptionId",
      "type",
    ]);
    assert.deepEqual(Object.keys(canonicalDelivery.body.paymentLink).sort(), [
      "fiatAmount",
      "fiatCurrency",
      "metadata",
      "uid",
    ]);
    assert.deepEqual(
      Object.keys(canonicalDelivery.body.paymentLink.metadata).sort(),
      [
        "medusaOrderDisplayId",
        "medusaOrderId",
        "medusaProviderId",
        "medusaSessionId",
      ],
    );
    assert.deepEqual(Object.keys(canonicalDelivery.body.session).sort(), [
      "id",
      "settlement",
    ]);
    assert.equal(canonicalDelivery.body.session.settlement, null);
    assert.equal(canonicalDelivery.body.schemaVersion, "medusa.v1");
    assert.equal(canonicalDelivery.body.status, "complete");
    assert.equal(canonicalDelivery.body.installationId, installation.client_id);
    assert.equal(
      canonicalDelivery.body.installationId,
      tokenClaims.installation_id,
    );
    assert.equal(canonicalDelivery.body.grantId, tokenClaims.grant_id);
    assert.equal(
      canonicalDelivery.body.subscriptionId,
      subscription.subscription.id,
    );
    assert.equal(
      canonicalDelivery.body.paymentLink.metadata.medusaSessionId,
      "payses_e2e",
    );
    assert.equal(
      canonicalDelivery.body.paymentLink.metadata.medusaOrderId,
      null,
    );
    assert.equal(
      canonicalDelivery.body.paymentLink.metadata.medusaOrderDisplayId,
      null,
    );
    assert.equal(
      canonicalDelivery.body.paymentLink.metadata.medusaProviderId,
      "makepay",
    );
    assert.notEqual(canonicalDelivery.body.session.id, "payses_e2e");
    assert.equal(
      JSON.stringify(canonicalDelivery.body).includes("arbitraryInjectedField"),
      false,
    );
    assert.equal(canonicalDelivery.pathname, "/hook-a");

    const paymentLinkUrl = `${paymentLinksUrl}/${created.paymentLink.uid}`;
    const retrieveHeldLink = async () => {
      const response = await fetch(paymentLinkUrl, {
        headers: {
          authorization: `DPoP ${tokens.access_token}`,
          dpop: dpop.proof({
            accessToken: tokens.access_token,
            method: "GET",
            url: paymentLinkUrl,
          }),
        },
      });
      assert.equal(response.status, 200);
      return response.json();
    };
    assert.equal(
      (await retrieveHeldLink()).paymentLink.latestSession.status,
      "processing",
    );
    assert.equal(
      (await retrieveHeldLink()).paymentLink.latestSession.status,
      "processing",
    );
    const heldPublicState = await fetch(`${contract.origin}/__e2e/state`, {
      headers: { "x-e2e-control-token": contract.controlToken },
    }).then((response) => response.json());
    assert.deepEqual(heldPublicState.workflowLatches, [
      { held: true, hits: 2, uid: created.paymentLink.uid },
    ]);
    const releasedLatch = await fetch(
      `${contract.origin}/__e2e/workflow-latch/release`,
      {
        body: JSON.stringify({ uid: created.paymentLink.uid }),
        headers: {
          "content-type": "application/json",
          "x-e2e-control-token": contract.controlToken,
        },
        method: "POST",
      },
    );
    assert.equal(releasedLatch.status, 200);
    assert.equal(
      (await retrieveHeldLink()).paymentLink.latestSession.status,
      "complete",
    );

    const setReadOverride = await fetch(
      `${contract.origin}/__e2e/link-read-override`,
      {
        body: JSON.stringify({
          amount: "999.99",
          fiatCurrency: "USD",
          reads: 2,
          status: "pending",
          uid: created.paymentLink.uid,
        }),
        headers: {
          "content-type": "application/json",
          "x-e2e-control-token": contract.controlToken,
        },
        method: "POST",
      },
    );
    assert.equal(setReadOverride.status, 200);
    assert.deepEqual(await setReadOverride.json(), {
      fields: ["amount", "fiatCurrency", "status"],
      remaining: 2,
      uid: created.paymentLink.uid,
    });
    for (const remaining of [1, 0]) {
      const overridden = (await retrieveHeldLink()).paymentLink;
      assert.equal(overridden.amount, "999.99");
      assert.equal(overridden.fiatAmount, "999.99");
      assert.equal(overridden.fiatCurrency, "USD");
      assert.equal(overridden.latestSession.status, "pending");
      const overrideState = await fetch(`${contract.origin}/__e2e/state`, {
        headers: { "x-e2e-control-token": contract.controlToken },
      }).then((response) => response.json());
      assert.equal(
        overrideState.linkReadOverrides[0]?.remaining ?? 0,
        remaining,
      );
    }
    const restored = (await retrieveHeldLink()).paymentLink;
    assert.equal(restored.amount, "20.00");
    assert.equal(restored.fiatCurrency, "EUR");
    assert.equal(restored.latestSession.status, "complete");

    await contract.emitWebhook({
      attempt: 3,
      deliveryGroupId: capturedDeliveryGroupId,
      deliveryId: "00000000-0000-4000-8000-000000000003",
      status: "complete",
      uid: created.paymentLink.uid,
    });
    const retriedCanonicalDelivery = webhookDeliveries.at(-1);
    const stableFirstBody = { ...canonicalDelivery.body };
    const stableRetryBody = { ...retriedCanonicalDelivery.body };
    delete stableFirstBody.deliveryId;
    delete stableRetryBody.deliveryId;
    assert.deepEqual(stableRetryBody, stableFirstBody);
    assert.notEqual(
      retriedCanonicalDelivery.body.deliveryId,
      canonicalDelivery.body.deliveryId,
    );

    for (const alias of [
      "paid",
      "succeeded",
      "captured",
      "settled",
      "confirmed",
      "authorized",
      "requires_capture",
      "error",
      "declined",
      "canceled",
      "refunded",
    ]) {
      await assert.rejects(
        contract.emitWebhook({
          deliveryId: randomUUID(),
          status: alias,
          uid: created.paymentLink.uid,
        }),
        /Unsupported canonical OAuth webhook status/,
      );
    }
    await assert.rejects(
      contract.emitWebhook({
        deliveryGroupId: "mpwhgrp_too_short",
        deliveryId: randomUUID(),
        status: "complete",
        uid: created.paymentLink.uid,
      }),
      /Invalid canonical OAuth delivery group/,
    );

    const secondStarted = await fetch(
      `${secondCreated.paymentLink.publicUrl}/start`,
      { method: "POST" },
    ).then((res) => res.text());
    assert.match(secondStarted, /SANDBOX-DO-NOT-SEND/);
    assert.equal(webhookDeliveries.at(-1).pathname, "/hook-b");

    const rotatedSecondSubscriptionResponse = await fetch(subscriptionUrl, {
      body: JSON.stringify({
        active: true,
        events: ["makepay.payment.status_changed"],
        rotateSecret: true,
        url: `${webhookOrigin}/hook-b-rotated`,
      }),
      headers: {
        authorization: `DPoP ${secondConnection.tokens.access_token}`,
        "content-type": "application/json",
        dpop: secondDpop.proof({
          accessToken: secondConnection.tokens.access_token,
          method: "PUT",
          url: subscriptionUrl,
        }),
      },
      method: "PUT",
    });
    assert.equal(rotatedSecondSubscriptionResponse.status, 200);
    const rotatedSecondSubscription =
      await rotatedSecondSubscriptionResponse.json();
    assert.equal(rotatedSecondSubscription.created, false);
    assert.notEqual(
      rotatedSecondSubscription.signingSecret,
      secondSubscription.signingSecret,
    );
    webhookSecrets.set(
      "/hook-b-rotated",
      rotatedSecondSubscription.signingSecret,
    );

    await contract.emitWebhook({
      deliveryId: "delivery-a-after-b-rotation",
      status: "complete",
      uid: created.paymentLink.uid,
    });
    assert.equal(webhookDeliveries.at(-1).pathname, "/hook-a");
    await contract.emitWebhook({
      deliveryId: "delivery-b-after-rotation",
      status: "complete",
      uid: secondCreated.paymentLink.uid,
    });
    assert.equal(webhookDeliveries.at(-1).pathname, "/hook-b-rotated");

    const firstSubscriptionResponse = await fetch(subscriptionUrl, {
      headers: {
        authorization: `DPoP ${tokens.access_token}`,
        dpop: dpop.proof({
          accessToken: tokens.access_token,
          method: "GET",
          url: subscriptionUrl,
        }),
      },
    });
    assert.equal(firstSubscriptionResponse.status, 200);
    const firstSubscription = await firstSubscriptionResponse.json();
    assert.equal(
      firstSubscription.subscription.callbackUrl,
      `${webhookOrigin}/hook-a`,
    );
    assert.equal("signingSecret" in firstSubscription.subscription, false);

    const disabledSecondSubscriptionResponse = await fetch(subscriptionUrl, {
      headers: {
        authorization: `DPoP ${secondConnection.tokens.access_token}`,
        dpop: secondDpop.proof({
          accessToken: secondConnection.tokens.access_token,
          method: "DELETE",
          url: subscriptionUrl,
        }),
      },
      method: "DELETE",
    });
    assert.equal(disabledSecondSubscriptionResponse.status, 200);
    const disabledSecondSubscription =
      await disabledSecondSubscriptionResponse.json();
    assert.equal(disabledSecondSubscription.historicalDeliveryPreserved, true);
    assert.equal(disabledSecondSubscription.signingSecretChanged, false);
    assert.equal(disabledSecondSubscription.subscription.status, "disabled");
    assert.equal(
      "signingSecret" in disabledSecondSubscription.subscription,
      false,
    );

    const secondDisconnectUrl = new URL(installationUrl);
    secondDisconnectUrl.searchParams.set(
      "client_id",
      secondConnection.installation.client_id,
    );
    const secondDisconnectResponse = await fetch(secondDisconnectUrl, {
      headers: {
        authorization: `DPoP ${secondConnection.tokens.access_token}`,
        dpop: secondDpop.proof({
          accessToken: secondConnection.tokens.access_token,
          method: "DELETE",
          // RFC 9449 excludes the client_id query from htu.
          url: installationUrl,
        }),
        "idempotency-key": `medusa-native-reset-${randomUUID()}`,
      },
      method: "DELETE",
    });
    assert.equal(secondDisconnectResponse.status, 200);

    await contract.emitWebhook({
      deliveryId: "delivery-a-after-b-disconnect",
      status: "complete",
      uid: created.paymentLink.uid,
    });
    assert.equal(webhookDeliveries.at(-1).pathname, "/hook-a");
    await contract.emitWebhook({
      deliveryId: "delivery-b-after-disconnect",
      status: "complete",
      uid: secondCreated.paymentLink.uid,
    });
    assert.equal(webhookDeliveries.at(-1).pathname, "/hook-b-rotated");
    const revokedSecondList = await fetch(paymentLinksUrl, {
      headers: {
        authorization: `DPoP ${secondConnection.tokens.access_token}`,
        dpop: secondDpop.proof({
          accessToken: secondConnection.tokens.access_token,
          method: "GET",
          url: paymentLinksUrl,
        }),
      },
    });
    assert.equal(revokedSecondList.status, 401);

    const reconnectedDpop = signer();
    const reconnectedSecond = await connectOauthInstallation({
      contract,
      dpop: reconnectedDpop,
      expectedRegistrationStatus: 200,
      registrationId: secondConnection.registrationId,
      redirectUri: "http://127.0.0.1:9002/makepay/oauth/callback",
      siteUrl: "http://127.0.0.1:9002",
      state: "oauth-state-e2e-b-reconnected",
    });
    const reconnectedTokenClaims = decodeJwtPayload(
      reconnectedSecond.tokens.access_token,
    );
    const reconnectedSubscriptionResponse = await fetch(subscriptionUrl, {
      body: JSON.stringify({
        active: true,
        events: ["makepay.payment.status_changed"],
        rotateSecret: true,
        url: `${webhookOrigin}/hook-b-reconnected`,
      }),
      headers: {
        authorization: `DPoP ${reconnectedSecond.tokens.access_token}`,
        "content-type": "application/json",
        dpop: reconnectedDpop.proof({
          accessToken: reconnectedSecond.tokens.access_token,
          method: "PUT",
          url: subscriptionUrl,
        }),
      },
      method: "PUT",
    });
    assert.equal(reconnectedSubscriptionResponse.status, 200);
    const reconnectedSubscription =
      await reconnectedSubscriptionResponse.json();
    webhookSecrets.set(
      "/hook-b-reconnected",
      reconnectedSubscription.signingSecret,
    );
    const reconnectedCreateResponse = await fetch(paymentLinksUrl, {
      body: JSON.stringify({
        payload: {
          amount: "22.00",
          fiatCurrency: "EUR",
          metadata: {
            medusaProviderId: "makepay",
            medusaSessionId: "payses_e2e_b_reconnected",
          },
        },
      }),
      headers: {
        authorization: `DPoP ${reconnectedSecond.tokens.access_token}`,
        "content-type": "application/json",
        dpop: reconnectedDpop.proof({
          accessToken: reconnectedSecond.tokens.access_token,
          method: "POST",
          url: paymentLinksUrl,
        }),
        "idempotency-key": "medusa-e2e-link",
      },
      method: "POST",
    });
    assert.equal(reconnectedCreateResponse.status, 201);
    const reconnectedCreated = await reconnectedCreateResponse.json();
    assert.notEqual(
      reconnectedTokenClaims.grant_id,
      secondTokenClaims.grant_id,
    );
    assert.equal(
      reconnectedSecond.installation.client_id,
      secondConnection.installation.client_id,
    );
    assert.equal(
      reconnectedSecond.installation.registration_id,
      secondConnection.registrationId,
    );
    assert.equal(
      reconnectedTokenClaims.installation_id,
      secondTokenClaims.installation_id,
    );
    const oldSecondLinkUrl = `${paymentLinksUrl}/${secondCreated.paymentLink.uid}`;
    const oldSecondLink = await fetch(oldSecondLinkUrl, {
      headers: {
        authorization: `DPoP ${reconnectedSecond.tokens.access_token}`,
        dpop: reconnectedDpop.proof({
          accessToken: reconnectedSecond.tokens.access_token,
          method: "GET",
          url: oldSecondLinkUrl,
        }),
      },
    });
    assert.equal(oldSecondLink.status, 404);
    const reconnectedListResponse = await fetch(paymentLinksUrl, {
      headers: {
        authorization: `DPoP ${reconnectedSecond.tokens.access_token}`,
        dpop: reconnectedDpop.proof({
          accessToken: reconnectedSecond.tokens.access_token,
          method: "GET",
          url: paymentLinksUrl,
        }),
      },
    });
    assert.equal(reconnectedListResponse.status, 200);
    const reconnectedList = await reconnectedListResponse.json();
    assert.deepEqual(
      reconnectedList.paymentLinks.map((link) => link.uid),
      [reconnectedCreated.paymentLink.uid],
    );
    await contract.emitWebhook({
      deliveryId: "delivery-a-after-b-reconnect",
      status: "complete",
      uid: created.paymentLink.uid,
    });
    assert.equal(webhookDeliveries.at(-1).pathname, "/hook-a");
    await contract.emitWebhook({
      deliveryId: "delivery-b-after-reconnect",
      status: "complete",
      uid: reconnectedCreated.paymentLink.uid,
    });
    assert.equal(webhookDeliveries.at(-1).pathname, "/hook-b-reconnected");

    const apiKeyResponse = await fetch(paymentLinksUrl, {
      body: JSON.stringify({
        payload: {
          amount: "10.00",
          clientId: "customer_api_key",
          currency: "USDT",
          fiatCurrency: "EUR",
          metadata: { session_id: "payses_api_key" },
          orderId: "cart_api_key",
          webhookUrl: `${webhookOrigin}/hook-api-key`,
        },
      }),
      headers: {
        "content-type": "application/json",
        "x-makecrypto-key-id": contract.apiKeyId,
        "x-makecrypto-key-secret": contract.apiKeySecret,
      },
      method: "POST",
    });
    assert.equal(apiKeyResponse.status, 201);
    const apiKeyCreated = await apiKeyResponse.json();
    webhookSecrets.set("/hook-api-key", webhookSecret);
    await contract.emitWebhook({
      deliveryId: "10000000-0000-4000-8000-000000000001",
      status: "complete",
      uid: apiKeyCreated.paymentLink.uid,
    });
    const legacyDelivery = webhookDeliveries.at(-1);
    assert.equal(legacyDelivery.pathname, "/hook-api-key");
    assert.deepEqual(Object.keys(legacyDelivery.body).sort(), [
      "deliveryId",
      "event",
      "paymentLink",
      "session",
      "type",
    ]);
    assert.equal("schemaVersion" in legacyDelivery.body, false);
    assert.equal(
      legacyDelivery.body.paymentLink.metadata.session_id,
      "payses_api_key",
    );

    const exactLegacyReceipt = await contract.emitWebhook({
      deliveryId: "10000000-0000-4000-8000-000000000002",
      legacyProductionShape: true,
      status: "complete",
      uid: apiKeyCreated.paymentLink.uid,
    });
    const exactLegacyDelivery = webhookDeliveries.at(-1);
    assert.equal(exactLegacyReceipt.responseText, "ok");
    assert.deepEqual(Object.keys(exactLegacyDelivery.body).sort(), [
      "createdAt",
      "data",
      "deliveryId",
      "event",
      "paymentLink",
      "session",
      "type",
    ]);
    assert.equal("companyId" in exactLegacyDelivery.body, false);
    assert.equal("installationId" in exactLegacyDelivery.body, false);
    assert.equal("schemaVersion" in exactLegacyDelivery.body, false);
    assert.equal("metadata" in exactLegacyDelivery.body.paymentLink, false);
    assert.equal("fiatCurrency" in exactLegacyDelivery.body.paymentLink, false);
    assert.equal(exactLegacyDelivery.body.paymentLink.amount, "10.00");
    assert.equal(exactLegacyDelivery.body.paymentLink.currency, "USDT");
    assert.equal(
      exactLegacyDelivery.body.paymentLink.merchantOrderId,
      "cart_api_key",
    );
    assert.equal(exactLegacyDelivery.body.session.status, "complete");

    const unsafeResponse = await fetch(paymentLinksUrl, {
      body: JSON.stringify({ payload: { amount: 1, sandbox: false } }),
      headers: {
        "content-type": "application/json",
        "x-makecrypto-key-id": contract.apiKeyId,
        "x-makecrypto-key-secret": contract.apiKeySecret,
      },
      method: "POST",
    });
    assert.equal(unsafeResponse.status, 400);

    const refreshResponse = await fetch(tokenUrl, {
      body: new URLSearchParams({
        client_id: installation.client_id,
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        resource: `${contract.origin}/api/partner/v1`,
      }),
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: dpop.proof({ method: "POST", url: tokenUrl }),
        "idempotency-key": `medusa-token-${base64url(randomBytes(32))}`,
      },
      method: "POST",
    });
    assert.equal(refreshResponse.status, 200);
    const replayResponse = await fetch(tokenUrl, {
      body: new URLSearchParams({
        client_id: installation.client_id,
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
        resource: `${contract.origin}/api/partner/v1`,
      }),
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: dpop.proof({ method: "POST", url: tokenUrl }),
        "idempotency-key": `medusa-token-${base64url(randomBytes(32))}`,
      },
      method: "POST",
    });
    assert.equal(replayResponse.status, 400);

    const oauthCreate = contract.state.requests.find(
      (request) =>
        request.pathname.endsWith("/payment-links") &&
        request.hasAuthorization &&
        request.hasDpop,
    );
    assert.ok(oauthCreate, "OAuth payment-link request was not recorded");
    assert.equal(oauthCreate.hasApiKey, false);
    const apiKeyCreate = contract.state.requests.find(
      (request) =>
        request.pathname.endsWith("/payment-links") && request.hasApiKey,
    );
    assert.ok(apiKeyCreate, "API-key payment-link request was not recorded");
    assert.equal(apiKeyCreate.hasAuthorization, false);

    const publicState = await fetch(`${contract.origin}/__e2e/state`, {
      headers: { "x-e2e-control-token": contract.controlToken },
    }).then((response) => response.text());
    assert.equal(publicState.includes(tokens.access_token), false);
    assert.equal(publicState.includes(tokens.refresh_token), false);
    assert.equal(
      publicState.includes(rotatedSecondSubscription.signingSecret),
      false,
    );
    assert.equal(
      publicState.includes(reconnectedSubscription.signingSecret),
      false,
    );
    assert.match(publicState, /\[redacted\]/);
    const parsedPublicState = JSON.parse(publicState);
    assert.deepEqual(
      parsedPublicState.subscriptions.map((entry) => entry.grantId).sort(),
      [
        tokenClaims.grant_id,
        secondTokenClaims.grant_id,
        reconnectedTokenClaims.grant_id,
      ].sort(),
    );
    assert.equal(
      parsedPublicState.subscriptions.find(
        (entry) => entry.grantId === secondTokenClaims.grant_id,
      )?.status,
      "disabled",
    );

    const replacementDpop = signer();
    const replacementBody = {
      ...nativeRegistrationBody,
      dpopJkt: replacementDpop.jkt,
    };
    const missingPrevious = await fetch(installationUrl, {
      body: JSON.stringify(replacementBody),
      headers: {
        "content-type": "application/json",
        dpop: replacementDpop.proof({ method: "POST", url: installationUrl }),
      },
      method: "POST",
    });
    assert.equal(missingPrevious.status, 401);

    const wrongPreviousDpop = signer();
    const wrongPrevious = await fetch(installationUrl, {
      body: JSON.stringify(replacementBody),
      headers: {
        "content-type": "application/json",
        dpop: replacementDpop.proof({ method: "POST", url: installationUrl }),
        "dpop-previous": wrongPreviousDpop.proof({
          method: "POST",
          url: installationUrl,
        }),
      },
      method: "POST",
    });
    assert.equal(wrongPrevious.status, 401);

    const replacementProof = replacementDpop.proof({
      method: "POST",
      url: installationUrl,
    });
    const previousProof = dpop.proof({
      method: "POST",
      url: installationUrl,
    });
    const replacementHeaders = {
      "content-type": "application/json",
      dpop: replacementProof,
      "dpop-previous": previousProof,
    };
    const reregistration = await fetch(installationUrl, {
      body: JSON.stringify(replacementBody),
      headers: replacementHeaders,
      method: "POST",
    });
    assert.equal(reregistration.status, 200);
    const reregistered = await reregistration.json();
    assert.equal(reregistered.client_id, installation.client_id);
    assert.equal(reregistered.registration_id, registrationId);
    assert.equal("status" in reregistered, false);

    const replayedReregistration = await fetch(installationUrl, {
      body: JSON.stringify(replacementBody),
      headers: replacementHeaders,
      method: "POST",
    });
    assert.equal(replayedReregistration.status, 400);

    const mismatchedSiteDpop = signer();
    const mismatchedSite = await fetch(installationUrl, {
      body: JSON.stringify({
        ...nativeRegistrationBody,
        dpopJkt: mismatchedSiteDpop.jkt,
        redirectUri: "http://127.0.0.1:9010/makepay/oauth/callback",
        siteUrl: "http://127.0.0.1:9010",
      }),
      headers: {
        "content-type": "application/json",
        dpop: mismatchedSiteDpop.proof({
          method: "POST",
          url: installationUrl,
        }),
        "dpop-previous": replacementDpop.proof({
          method: "POST",
          url: installationUrl,
        }),
      },
      method: "POST",
    });
    assert.equal(mismatchedSite.status, 409);

    console.log("MakePay OAuth/API/webhook contract server verified.");
  } finally {
    await contract.close();
    await close(webhookReceiver);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
