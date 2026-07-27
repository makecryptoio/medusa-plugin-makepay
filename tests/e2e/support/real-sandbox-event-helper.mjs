import { createHash, createHmac, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { chmod, readFile, rm, writeFile } from "node:fs/promises";
import { Modules } from "@medusajs/framework/utils";

const MAX_CONTROL_BODY_BYTES = 128 * 1024;
const PROVIDER_ID = "makepay";
const EVENT_TYPE = "makepay.payment.status_changed";
const REFRESH_SMOKE_OPERATION = "force-oauth-refresh-read-smoke";
const noFundsStatuses = new Set(["quoted", "pending"]);
const terminalFixtureStatuses = new Set(["complete", "failed"]);
const fixtureStatuses = new Set([
  ...noFundsStatuses,
  ...terminalFixtureStatuses,
]);
const safeSecretMetadataFields = new Set([
  "secretcreatedat",
  "secretlast4",
  "secretupdatedat",
]);

function text(value, label) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`Missing ${label}.`);
  }
  return value.trim();
}

function serviceFrom(container) {
  try {
    const service = container.resolve("makepayIntegration");
    if (service) return service;
  } catch {}
  throw new Error("The packed MakePay integration service is unavailable.");
}

function paymentModuleFrom(container) {
  const service = container.resolve(Modules.PAYMENT);
  if (!service) throw new Error("Medusa's payment module is unavailable.");
  return service;
}

function safeProjection(record) {
  if (!record) return null;
  return {
    amount: String(record.amount ?? ""),
    authMode: record.auth_mode ?? null,
    companyId: record.company_id ?? null,
    currency: String(record.currency ?? ""),
    customerEmail: record.customer_email ?? null,
    grantId: record.grant_id ?? null,
    installationId: record.installation_id ?? null,
    medusaStatus: record.medusa_status ?? null,
    orderDisplayId: record.order_display_id ?? null,
    orderId: record.order_id ?? null,
    paymentId: record.payment_id ?? null,
    providerStatus: String(record.provider_status ?? ""),
    sessionId: record.session_id ?? null,
    subscriptionId: record.webhook_subscription_id ?? null,
    uid: String(record.payment_link_uid ?? ""),
  };
}

function safeRunId(value) {
  const runId = text(value, "E2E run ID");
  if (!/^medusa-e2e-[A-Za-z0-9._-]+$/.test(runId)) {
    throw new Error("Invalid E2E run ID.");
  }
  return runId;
}

function runOwnedEmails(runId) {
  const prefix = `makepay-real-sandbox+${safeRunId(runId)}`.toLowerCase();
  return new Set([
    `${prefix}@example.com`,
    `${prefix}-installation-b@example.com`,
    `${prefix}-installation-b-reconnected@example.com`,
  ]);
}

function refreshSmokeRequest(value) {
  if (value === undefined || value === null || typeof value === "string") {
    return undefined;
  }
  if (
    typeof value !== "object" ||
    Array.isArray(value) ||
    value.operation !== REFRESH_SMOKE_OPERATION ||
    Object.keys(value).sort().join(",") !== "operation,paymentLinkUid,runId"
  ) {
    throw new Error("Invalid OAuth refresh-smoke request.");
  }
  const paymentLinkUid = text(value.paymentLinkUid, "payment-link UID");
  if (!/^[A-Za-z0-9_-]{1,200}$/.test(paymentLinkUid)) {
    throw new Error("Invalid OAuth refresh-smoke payment-link UID.");
  }
  return {
    paymentLinkUid,
    runId: safeRunId(value.runId),
  };
}

function assertOwnedProjection(projection, context, uid) {
  const safe = safeProjection(projection);
  if (
    safe?.authMode !== "oauth" ||
    safe.uid !== uid ||
    !safe.sessionId ||
    !safe.companyId ||
    !safe.grantId ||
    !safe.installationId ||
    !safe.subscriptionId ||
    safe.companyId !== context.companyId ||
    safe.grantId !== context.grantId ||
    safe.installationId !== context.installationId ||
    safe.subscriptionId !== context.webhookSubscriptionId
  ) {
    throw new Error(
      "The cleanup payment link is not owned by this installation.",
    );
  }
  return safe;
}

function assertRunOwnedTerminalProjection(projection, context, uid, runId) {
  const safe = assertOwnedProjection(projection, context, uid);
  if (
    !runOwnedEmails(runId).has(String(safe.customerEmail ?? "").toLowerCase()) ||
    !safe.orderId ||
    !safe.orderDisplayId ||
    !safe.sessionId ||
    !safe.amount ||
    !safe.currency ||
    safe.paymentId ||
    !["active", "quoted", "pending"].includes(
      String(safe.providerStatus).toLowerCase(),
    ) ||
    String(safe.medusaStatus).toLowerCase() !== "pending_authorization"
  ) {
    throw new Error(
      "The terminal fixture requires a correlated, unpaid payment owned by this E2E run.",
    );
  }
  return safe;
}

function connectionMetadata(connection) {
  return connection?.metadata &&
    typeof connection.metadata === "object" &&
    !Array.isArray(connection.metadata)
    ? connection.metadata
    : {};
}

function normalizedConnectionMetadata(connection) {
  return Object.fromEntries(
    Object.entries(connectionMetadata(connection))
      // Medusa persists explicit null tombstones when a merged JSON lifecycle
      // field is cleared. Null and absence are equivalent for this stability
      // check; a non-null pending mutation must still fail the smoke test.
      .filter(([, value]) => value !== null)
      .sort(([left], [right]) => left.localeCompare(right)),
  );
}

async function singleOAuthConnection(service) {
  const connections = await service.listMakePayConnections(
    { provider_id: PROVIDER_ID },
    { take: 2 },
  );
  if (
    !Array.isArray(connections) ||
    connections.length !== 1 ||
    connections[0]?.auth_mode !== "oauth" ||
    connections[0]?.provider_id !== PROVIDER_ID
  ) {
    throw new Error(
      "The OAuth refresh smoke requires one MakePay OAuth connection.",
    );
  }
  return connections[0];
}

function assertRefreshableConnection(connection, context) {
  const expiresAt = new Date(connection?.access_token_expires_at).getTime();
  if (
    !connection?.id ||
    connection.status !== "connected" ||
    connection.webhook_status !== "healthy" ||
    connection.client_id !== context.installationId ||
    connection.company_id !== context.companyId ||
    connection.grant_id !== context.grantId ||
    connection.installation_id !== context.installationId ||
    connection.webhook_subscription_id !== context.webhookSubscriptionId ||
    !connection.connected_at ||
    !connection.webhook_url ||
    !connection.encrypted_access_token ||
    !connection.encrypted_refresh_token ||
    !connection.encrypted_dpop_private_key ||
    !connection.encrypted_webhook_secret ||
    !Number.isFinite(expiresAt) ||
    connectionMetadata(connection).refresh_attempt != null
  ) {
    throw new Error(
      "The OAuth connection is not a healthy, refreshable E2E connection.",
    );
  }
  return expiresAt;
}

async function forceOAuthRefreshReadSmoke(service, request) {
  if (service.authMode !== "oauth" || service.providerId !== PROVIDER_ID) {
    throw new Error("The OAuth refresh smoke is unavailable in this mode.");
  }
  const [before, context, projection] = await Promise.all([
    singleOAuthConnection(service),
    service.getInstallationContext(),
    service.projectionByUid(request.paymentLinkUid),
  ]);
  const owned = assertOwnedProjection(
    projection,
    context,
    request.paymentLinkUid,
  );
  if (
    projection?.provider_id !== PROVIDER_ID ||
    !runOwnedEmails(request.runId).has(
      String(owned.customerEmail ?? "").toLowerCase(),
    )
  ) {
    throw new Error(
      "The OAuth refresh smoke requires a payment owned by this E2E run.",
    );
  }
  assertRefreshableConnection(before, context);

  const stableIdentity = {
    clientId: before.client_id,
    companyId: before.company_id,
    connectedAt: String(before.connected_at),
    grantId: before.grant_id,
    installationId: before.installation_id,
    subscriptionId: before.webhook_subscription_id,
    webhookUrl: before.webhook_url,
  };
  const priorCredentials = {
    access: String(before.encrypted_access_token),
    dpop: String(before.encrypted_dpop_private_key),
    refresh: String(before.encrypted_refresh_token),
    webhook: String(before.encrypted_webhook_secret),
  };
  const priorDpopThumbprint = String(
    connectionMetadata(before).dpop_thumbprint ?? "",
  );
  const priorMetadata = JSON.stringify(normalizedConnectionMetadata(before));

  await service.updateMakePayConnections({
    access_token_expires_at: new Date(Date.now() - 60_000),
    id: before.id,
  });
  const forced = await singleOAuthConnection(service);
  const forcedOnlyLocalExpiry =
    String(forced.id) === String(before.id) &&
    forced.client_id === stableIdentity.clientId &&
    forced.company_id === stableIdentity.companyId &&
    String(forced.connected_at) === stableIdentity.connectedAt &&
    forced.grant_id === stableIdentity.grantId &&
    forced.installation_id === stableIdentity.installationId &&
    forced.webhook_subscription_id === stableIdentity.subscriptionId &&
    forced.webhook_url === stableIdentity.webhookUrl &&
    forced.status === before.status &&
    forced.webhook_status === before.webhook_status &&
    forced.last_error === before.last_error &&
    String(forced.encrypted_access_token) === priorCredentials.access &&
    String(forced.encrypted_refresh_token) === priorCredentials.refresh &&
    String(forced.encrypted_dpop_private_key) === priorCredentials.dpop &&
    String(forced.encrypted_webhook_secret) === priorCredentials.webhook &&
    JSON.stringify(normalizedConnectionMetadata(forced)) === priorMetadata &&
    new Date(forced.access_token_expires_at).getTime() <= Date.now();
  if (!forcedOnlyLocalExpiry) {
    throw new Error("The local OAuth access-token expiry was not forced.");
  }

  // This is intentionally a read-only merchant operation. Building the
  // authenticated request forces the plugin's normal pre-expiry refresh path.
  const client = await service.createClient({
    allowRefreshRetry: true,
    refreshIfExpiring: true,
  });
  const remote = await client.getCurrentWebhookSubscription();
  const after = await singleOAuthConnection(service);
  const afterExpiry = new Date(after.access_token_expires_at).getTime();
  const subscription = remote?.subscription;
  const remoteSubscriptionId = String(
    subscription?.id ?? subscription?.uid ?? "",
  );
  const remoteCallbackUrl = String(
    subscription?.url ?? subscription?.callbackUrl ?? "",
  );
  const identityStable =
    String(after.id) === String(before.id) &&
    after.client_id === stableIdentity.clientId &&
    after.company_id === stableIdentity.companyId &&
    String(after.connected_at) === stableIdentity.connectedAt &&
    after.grant_id === stableIdentity.grantId &&
    after.installation_id === stableIdentity.installationId &&
    after.webhook_subscription_id === stableIdentity.subscriptionId &&
    after.webhook_url === stableIdentity.webhookUrl;
  const result = {
    accessCredentialPersisted:
      String(after.encrypted_access_token) !== priorCredentials.access,
    authenticatedReadCompleted:
      remote?.companyId === stableIdentity.companyId &&
      remoteSubscriptionId === stableIdentity.subscriptionId &&
      remoteCallbackUrl === stableIdentity.webhookUrl,
    connectionIdentityStable: identityStable,
    connectionStillHealthy:
      after.status === "connected" &&
      after.webhook_status === "healthy" &&
      after.last_error == null,
    dpopCredentialStable:
      Boolean(after.encrypted_dpop_private_key) &&
      Boolean(priorDpopThumbprint) &&
      String(connectionMetadata(after).dpop_thumbprint ?? "") ===
        priorDpopThumbprint,
    expiryAdvanced:
      Number.isFinite(afterExpiry) && afterExpiry > Date.now() + 60_000,
    forcedOnlyLocalExpiry,
    metadataStable:
      JSON.stringify(normalizedConnectionMetadata(after)) === priorMetadata,
    refreshAttemptCleared:
      connectionMetadata(after).refresh_attempt == null,
    refreshCredentialRotatedAndPersisted:
      String(after.encrypted_refresh_token) !== priorCredentials.refresh,
    remoteSubscriptionStable:
      remoteSubscriptionId === stableIdentity.subscriptionId &&
      remoteCallbackUrl === stableIdentity.webhookUrl,
    remoteReadOmittedSecrets: !containsSecretField(remote),
    webhookCredentialStable:
      String(after.encrypted_webhook_secret) === priorCredentials.webhook,
  };
  if (Object.values(result).some((value) => value !== true)) {
    const failedChecks = Object.entries(result)
      .filter(([, value]) => value !== true)
      .map(([key]) => key)
      .join(", ");
    throw new Error(
      `The OAuth refresh smoke did not preserve the connected installation: ${failedChecks}.`,
    );
  }
  return result;
}

function verifiedRemoteLink(response, expected) {
  const link = response?.paymentLink;
  if (
    !link ||
    String(link.uid ?? "") !== expected.uid ||
    String(link.status ?? "").toLowerCase() !== "archived" ||
    !expected.companyId ||
    response.companyId !== expected.companyId
  ) {
    throw new Error("MakePay did not independently confirm link archival.");
  }
  return link;
}

function remoteRunOwnedLink(
  response,
  { context, ownedEmails, ownedProjection, uid },
) {
  const link = response?.paymentLink;
  const payload = link?.payload ?? {};
  const metadata = link?.metadata ?? payload.metadata ?? {};
  const customerEmail = String(
    link?.customerEmail ??
      payload.customerEmail ??
      payload.customer_email ??
      "",
  ).toLowerCase();
  const projectionCustomerEmail = String(
    ownedProjection?.customerEmail ?? "",
  ).toLowerCase();
  const remoteSessionId = String(metadata.medusaSessionId ?? "");
  const projectionIdentityMatches =
    !ownedProjection ||
    (ownedProjection.authMode === "oauth" &&
      ownedProjection.uid === uid &&
      ownedProjection.sessionId === remoteSessionId &&
      ownedProjection.companyId === context.companyId &&
      ownedProjection.grantId === context.grantId &&
      ownedProjection.installationId === context.installationId &&
      ownedProjection.subscriptionId === context.webhookSubscriptionId);
  const customerIdentityIsOwned = customerEmail
    ? ownedEmails.has(customerEmail)
    : Boolean(ownedProjection) &&
      projectionIdentityMatches &&
      ownedEmails.has(projectionCustomerEmail);
  if (
    !link ||
    String(link.uid ?? "") !== uid ||
    !projectionIdentityMatches ||
    !customerIdentityIsOwned ||
    metadata.medusaInstallationId !== context.installationId ||
    metadata.medusaProviderId !== PROVIDER_ID ||
    !/^payses_[\w-]+$/.test(remoteSessionId) ||
    !context.companyId ||
    response.companyId !== context.companyId
  ) {
    throw new Error("The remote payment link is not owned by this E2E run.");
  }
  return { link, metadata };
}

async function archiveCleanupPaymentLink({ container, runId, service, uid }) {
  const ownedEmails = runOwnedEmails(runId);
  const [projection, context] = await Promise.all([
    service.projectionByUid(uid),
    service.getInstallationContext(),
  ]);
  const client = await service.createClient();
  const initialRemote = await client.getPaymentLink(uid);
  const owned = projection
    ? assertOwnedProjection(projection, context, uid)
    : undefined;
  remoteRunOwnedLink(initialRemote, {
    context,
    ownedEmails,
    ownedProjection: owned,
    uid,
  });
  if (
    owned &&
    !ownedEmails.has(String(owned.customerEmail ?? "").toLowerCase())
  ) {
    throw new Error("The cleanup payment link is not owned by this E2E run.");
  }
  const ownedProviderStatus = String(
    owned?.providerStatus ?? "",
  ).toLowerCase();
  const ownedMedusaStatus = String(owned?.medusaStatus ?? "").toLowerCase();
  const preserveTerminalProjection =
    (ownedProviderStatus === "complete" && ownedMedusaStatus === "paid") ||
    (ownedProviderStatus === "failed" && ownedMedusaStatus === "failed");
  const archiveRemote = async () => {
    const idempotencyKey = `medusa-e2e-archive-${createHash("sha256")
      .update(`${runId}:${context.installationId}:${context.grantId}:${uid}`)
      .digest("hex")}`;
    let current = await client.getPaymentLink(uid);
    if (
      String(current?.paymentLink?.status ?? "").toLowerCase() !== "archived"
    ) {
      try {
        await client.updatePaymentLink(
          uid,
          { status: "archived" },
          { idempotencyKey },
        );
      } catch {
        current = await client.getPaymentLink(uid);
        if (
          String(current?.paymentLink?.status ?? "").toLowerCase() !==
          "archived"
        ) {
          await client.updatePaymentLink(
            uid,
            { status: "archived" },
            { idempotencyKey },
          );
        }
      }
    }
    verifiedRemoteLink(await client.getPaymentLink(uid), {
      companyId: context.companyId,
      uid,
    });
  };

  if (preserveTerminalProjection) {
    // The signed no-funds fixture is authoritative only inside Medusa. Archive
    // the still-unpaid remote sandbox link, but never rewrite the locally
    // verified paid/failed terminal projection during cleanup.
    await archiveRemote();
  } else if (
    !owned ||
    String(owned.providerStatus).toLowerCase() !== "cancelled" ||
    String(owned.medusaStatus).toLowerCase() !== "canceled"
  ) {
    if (owned?.paymentId) {
      await paymentModuleFrom(container).cancelPayment(owned.paymentId);
    } else {
      await archiveRemote();
      if (owned) {
        await service.markCanceledPayment({
          paymentLinkUid: uid,
          sessionId: owned.sessionId,
        });
      }
    }
  }

  const [updated, remote] = await Promise.all([
    service.projectionByUid(uid),
    client.getPaymentLink(uid),
  ]);
  const verified = updated
    ? assertOwnedProjection(updated, context, uid)
    : undefined;
  verifiedRemoteLink(remote, {
    companyId: context.companyId,
    uid,
  });
  const expectedProviderStatus = preserveTerminalProjection
    ? ownedProviderStatus
    : "cancelled";
  const expectedMedusaStatus = preserveTerminalProjection
    ? ownedMedusaStatus
    : "canceled";
  if (
    verified &&
    (String(verified.providerStatus).toLowerCase() !==
      expectedProviderStatus ||
      String(verified.medusaStatus).toLowerCase() !== expectedMedusaStatus)
  ) {
    throw new Error("Local payment terminal state was not preserved.");
  }
  return {
    archived: true,
    localProjection: Boolean(verified),
    medusaStatus: verified ? expectedMedusaStatus : null,
    providerStatus: verified ? expectedProviderStatus : null,
    remoteStatus: "archived",
    routing: {
      companyId: context.companyId,
      grantId: context.grantId,
      installationId: context.installationId,
      subscriptionId: context.webhookSubscriptionId,
    },
    uid,
  };
}

async function listAllRemotePaymentLinks(client, companyId) {
  const links = [];
  const seen = new Set();
  let cursor;
  let offset = 0;
  for (let page = 0; page < 10; page += 1) {
    const response = await client.listPaymentLinks({
      ...(cursor ? { cursor } : { offset }),
      limit: 100,
    });
    if (
      response?.companyId !== companyId ||
      !Array.isArray(response?.paymentLinks)
    ) {
      throw new Error("Remote cleanup enumeration returned an invalid page.");
    }
    for (const link of response.paymentLinks) {
      const uid = String(link?.uid ?? "");
      if (!uid || seen.has(uid)) {
        throw new Error("Remote cleanup pagination is not stable.");
      }
      seen.add(uid);
      links.push(link);
    }
    const declaredTotal = Number(response.count ?? response.total);
    if (
      Number.isFinite(declaredTotal) &&
      (!Number.isSafeInteger(declaredTotal) || declaredTotal < links.length)
    ) {
      throw new Error("Remote cleanup pagination total is invalid.");
    }
    const nextCursor =
      response.nextCursor ?? response.next_cursor ?? response.cursor?.next;
    const hasMore = response.hasMore ?? response.has_more;
    const completeByTotal =
      Number.isSafeInteger(declaredTotal) && declaredTotal === links.length;
    const completeByPage =
      (!Number.isSafeInteger(declaredTotal) ||
        declaredTotal === links.length) &&
      response.paymentLinks.length < 100 &&
      hasMore !== true &&
      !nextCursor;
    if (completeByTotal || completeByPage) {
      if (hasMore === true || nextCursor) {
        throw new Error("Remote cleanup pagination is contradictory.");
      }
      return { companyId, paymentLinks: links };
    }
    if (typeof nextCursor === "string" && nextCursor) {
      cursor = nextCursor;
    } else {
      offset += response.paymentLinks.length;
    }
  }
  throw new Error("Remote cleanup enumeration exceeded its page limit.");
}

async function cleanupCandidates(service, runId) {
  const ownedEmails = runOwnedEmails(runId);
  const marker = `makepay-real-sandbox+${safeRunId(runId)}`.toLowerCase();
  const [listed, context, client] = await Promise.all([
    service.listPaymentViews({ limit: 100, q: marker }),
    service.getInstallationContext(),
    service.createClient(),
  ]);
  const remote = await listAllRemotePaymentLinks(client, context.companyId);
  if (
    !Array.isArray(listed?.payments) ||
    !Number.isSafeInteger(listed?.count) ||
    listed.count < listed.payments.length ||
    listed.count > 100
  ) {
    throw new Error(
      "Local cleanup enumeration is invalid or exceeds its limit.",
    );
  }
  const candidates = [];
  for (const payment of listed.payments) {
    if (
      payment.auth_mode !== "oauth" ||
      !ownedEmails.has(String(payment.customer_email ?? "").toLowerCase())
    ) {
      continue;
    }
    const projection = await service.projectionByUid(payment.payment_link_uid);
    const safe = safeProjection(projection);
    if (
      safe?.companyId === context.companyId &&
      safe.grantId === context.grantId &&
      safe.installationId === context.installationId &&
      safe.subscriptionId === context.webhookSubscriptionId
    ) {
      candidates.push(
        assertOwnedProjection(projection, context, payment.payment_link_uid),
      );
    }
  }
  const remoteLinks = remote.paymentLinks;
  const remoteCandidates = [];
  for (const link of remoteLinks) {
    const uid = String(link?.uid ?? "");
    const customerEmail = String(
      link?.customerEmail ??
        link?.payload?.customerEmail ??
        link?.payload?.customer_email ??
        "",
    ).toLowerCase();
    if (!ownedEmails.has(customerEmail)) continue;
    remoteRunOwnedLink(
      { companyId: remote.companyId, paymentLink: link },
      { context, ownedEmails, uid },
    );
    remoteCandidates.push({
      authMode: "oauth",
      companyId: context.companyId,
      customerEmail,
      grantId: context.grantId,
      installationId: context.installationId,
      subscriptionId: context.webhookSubscriptionId,
      uid,
    });
  }
  return { candidates, remoteCandidates };
}

async function disconnectCleanupInstallation(service) {
  const connection = await service.disconnectOAuth();
  if (
    connection?.connected !== false ||
    connection?.status !== "disconnected"
  ) {
    throw new Error("OAuth disconnect was not confirmed.");
  }
  return { connected: false, status: "disconnected" };
}

async function cleanupConnectionView(service) {
  const connection = await service.getConnectionView();
  if (
    connection?.auth_mode !== "oauth" ||
    typeof connection.connected !== "boolean" ||
    !["connected", "disconnect_pending", "disconnected", "error"].includes(
      connection.status,
    )
  ) {
    throw new Error("OAuth cleanup connection state is invalid.");
  }
  return {
    connected: connection.connected,
    status: connection.status,
  };
}

function containsSecretField(value, seen = new Set()) {
  if (!value || typeof value !== "object" || seen.has(value)) return false;
  seen.add(value);
  if (Array.isArray(value)) {
    return value.some((entry) => containsSecretField(entry, seen));
  }
  return Object.entries(value).some(([key, nested]) => {
    const normalized = key.replaceAll(/[-_]/g, "").toLowerCase();
    return (
      (normalized.includes("secret") &&
        !safeSecretMetadataFields.has(normalized)) ||
      containsSecretField(nested, seen)
    );
  });
}

async function safeSnapshot(service, uid) {
  const [connection, context, projection, subscriptionRead, deliveries] =
    await Promise.all([
      service.getConnectionView(),
      service.getInstallationContext(),
      uid ? service.projectionByUid(uid) : Promise.resolve(undefined),
      service
        .createClient()
        .then((client) => client.getCurrentWebhookSubscription()),
      uid
        ? service.listMakePayWebhookDeliveries(
            { payment_link_uid: uid },
            { take: 100 },
          )
        : Promise.resolve([]),
    ]);
  return {
    connection: {
      callbackUrl: connection.webhook?.callback_url ?? null,
      clientId: connection.client_id ?? null,
      companyId: connection.company_id ?? null,
      connected: connection.connected === true,
      status: connection.status,
      webhookStatus: connection.webhook?.status ?? null,
    },
    context: {
      companyId: context.companyId ?? null,
      grantId: context.grantId ?? null,
      installationId: context.installationId ?? null,
      subscriptionId: context.webhookSubscriptionId ?? null,
    },
    deliveryCount: deliveries.length,
    projection: safeProjection(projection),
    remoteSubscription: {
      callbackUrl:
        subscriptionRead.subscription?.url ??
        subscriptionRead.subscription?.callbackUrl ??
        null,
      id:
        subscriptionRead.subscription?.id ??
        subscriptionRead.subscription?.uid ??
        null,
    },
    subscriptionReadOmittedSecret: !containsSecretField(subscriptionRead),
  };
}

function remoteHostedReturnValue(link, camel, snake) {
  const payload =
    link?.payload && typeof link.payload === "object" ? link.payload : {};
  const value =
    link?.[camel] ?? link?.[snake] ?? payload?.[camel] ?? payload?.[snake];
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

async function assertHostedReturnConfiguration(
  service,
  { expectedReturnUrl, runId, state, uid },
) {
  const expectedState = text(state, "checkout return state");
  if (!/^[A-Za-z0-9_-]{32,200}$/.test(expectedState)) {
    throw new Error("Invalid checkout return state.");
  }
  const expected = new URL(text(expectedReturnUrl, "hosted return URL"));
  if (
    expected.protocol !== "https:" ||
    expected.username ||
    expected.password ||
    expected.hash ||
    expected.pathname !== "/makepay/checkout/return" ||
    expected.searchParams.size !== 1 ||
    expected.searchParams.get("state") !== expectedState
  ) {
    throw new Error("The expected hosted return URL is invalid.");
  }
  const [projection, stateProjection, context, client] = await Promise.all([
    service.projectionByUid(uid),
    service.projectionByReturnState(expectedState),
    service.getInstallationContext(),
    service.createClient(),
  ]);
  const owned = assertRunOwnedTerminalProjection(
    projection,
    context,
    uid,
    runId,
  );
  const remote = await client.getPaymentLink(uid);
  const { link } = remoteRunOwnedLink(remote, {
    context,
    ownedEmails: runOwnedEmails(runId),
    ownedProjection: owned,
    uid,
  });
  if (
    !stateProjection ||
    stateProjection.id !== projection.id ||
    stateProjection.payment_link_uid !== uid
  ) {
    throw new Error(
      "The checkout return state does not identify the expected payment.",
    );
  }
  const configuredUrls = [
    remoteHostedReturnValue(link, "returnUrl", "return_url"),
    remoteHostedReturnValue(link, "successUrl", "success_url"),
    remoteHostedReturnValue(link, "failureUrl", "failure_url"),
  ];
  if (configuredUrls.some((value) => value !== expected.href)) {
    throw new Error(
      "The hosted payment link does not use the configured Medusa return URL.",
    );
  }
  return {
    configured: true,
    failureUrlMatches: true,
    returnUrlMatches: true,
    stateCorrelated: true,
    successUrlMatches: true,
  };
}

function canonicalEvent(projection, context, status, allowed) {
  if (!allowed.has(status)) {
    throw new Error("The requested signed event status is not allowed.");
  }
  const safe = safeProjection(projection);
  if (
    !safe?.uid ||
    !safe.sessionId ||
    !safe.amount ||
    !safe.currency ||
    !context.companyId ||
    !context.grantId ||
    !context.installationId ||
    !context.webhookSubscriptionId ||
    safe.companyId !== context.companyId ||
    safe.grantId !== context.grantId ||
    safe.installationId !== context.installationId ||
    safe.subscriptionId !== context.webhookSubscriptionId
  ) {
    throw new Error(
      "The local OAuth payment projection is incomplete or stale.",
    );
  }
  const nonce = randomUUID();
  const deliveryGroupId = `mpwhgrp_${createHash("sha256")
    .update(
      JSON.stringify([
        safe.uid,
        safe.sessionId,
        context.grantId,
        context.webhookSubscriptionId,
        status,
        nonce,
      ]),
    )
    .digest("hex")}`;
  return {
    schemaVersion: "medusa.v1",
    deliveryId: `mpwhdel_${nonce.replaceAll("-", "")}`,
    deliveryGroupId,
    type: EVENT_TYPE,
    createdAt: new Date().toISOString(),
    status,
    companyId: context.companyId,
    grantId: context.grantId,
    subscriptionId: context.webhookSubscriptionId,
    installationId: context.installationId,
    paymentLink: {
      uid: safe.uid,
      fiatAmount: safe.amount,
      fiatCurrency: safe.currency.toUpperCase(),
      metadata: {
        medusaSessionId: safe.sessionId,
        medusaOrderId: safe.orderId,
        medusaOrderDisplayId: safe.orderDisplayId,
        medusaProviderId: PROVIDER_ID,
      },
    },
    session: {
      id: `mpses_e2e_${randomUUID().replaceAll("-", "")}`,
      settlement: null,
    },
  };
}

function signedHeaders(body, event, secret) {
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = createHmac("sha256", secret)
    .update(`${timestamp}.${body}`)
    .digest("hex");
  return {
    "content-type": "application/json",
    "user-agent": "makepay-medusa-real-sandbox-e2e/1.0.1",
    "x-makepay-attempt": "1",
    "x-makepay-delivery-group-id": event.deliveryGroupId,
    "x-makepay-delivery-id": event.deliveryId,
    "x-makepay-event": event.type,
    "x-makepay-origin": "sandbox",
    "x-makepay-signature": `t=${timestamp},v1=${signature}`,
  };
}

function assertFixture(fixture, allowed = fixtureStatuses) {
  if (
    !fixture ||
    typeof fixture.body !== "string" ||
    !fixture.headers ||
    typeof fixture.headers !== "object"
  ) {
    throw new Error("The signed webhook fixture is invalid.");
  }
  const event = JSON.parse(fixture.body);
  if (
    event.schemaVersion !== "medusa.v1" ||
    event.type !== EVENT_TYPE ||
    !allowed.has(event.status) ||
    fixture.headers["x-makepay-delivery-id"] !== event.deliveryId ||
    fixture.headers["x-makepay-delivery-group-id"] !== event.deliveryGroupId ||
    fixture.headers["x-makepay-event"] !== event.type
  ) {
    throw new Error("The signed webhook fixture is not canonical.");
  }
  return event;
}

async function postFixture(callbackUrl, fixture, allowed = fixtureStatuses) {
  assertFixture(fixture, allowed);
  const response = await fetch(callbackUrl, {
    body: fixture.body,
    headers: fixture.headers,
    method: "POST",
    redirect: "manual",
  });
  await response.arrayBuffer();
  return { responseStatus: response.status };
}

async function fixtureFor(service, uid, status, allowed = noFundsStatuses) {
  const [projection, context, secret] = await Promise.all([
    service.projectionByUid(uid),
    service.getInstallationContext(),
    service.getWebhookSecret(),
  ]);
  const event = canonicalEvent(projection, context, status, allowed);
  const body = JSON.stringify(event);
  return {
    body,
    headers: signedHeaders(body, event, secret),
  };
}

async function terminalFixtureFor(service, uid, status, runId) {
  const [projection, context, secret] = await Promise.all([
    service.projectionByUid(uid),
    service.getInstallationContext(),
    service.getWebhookSecret(),
  ]);
  assertRunOwnedTerminalProjection(projection, context, uid, runId);
  const event = canonicalEvent(
    projection,
    context,
    status,
    terminalFixtureStatuses,
  );
  const body = JSON.stringify(event);
  return {
    body,
    headers: signedHeaders(body, event, secret),
  };
}

function receipt(event, responseStatus) {
  return {
    deliveryGroupId: event.deliveryGroupId,
    deliveryId: event.deliveryId,
    responseStatus,
    status: event.status,
    uid: event.paymentLink.uid,
  };
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function writeRestricted(path, value) {
  await writeFile(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
}

async function readControlBody(request) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > MAX_CONTROL_BODY_BYTES) {
      throw new Error("Signer request exceeds the size limit.");
    }
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function serveInMemorySigner(service, socketPath, callbackUrl) {
  const secret = await service.getWebhookSecret();
  await rm(socketPath, { force: true });
  const server = createServer(async (request, response) => {
    try {
      if (request.method !== "POST" || request.url !== "/deliver") {
        response.writeHead(404).end();
        return;
      }
      const input = await readControlBody(request);
      const fixture = input?.fixture;
      const event = assertFixture(fixture, noFundsStatuses);
      const headers = signedHeaders(fixture.body, event, secret);
      const delivered = await postFixture(callbackUrl, {
        body: fixture.body,
        headers,
      }, noFundsStatuses);
      response
        .writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify(receipt(event, delivered.responseStatus)));
    } catch {
      response
        .writeHead(400, { "content-type": "application/json" })
        .end(JSON.stringify({ message: "Old signer delivery failed." }));
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.off("error", reject);
      resolve();
    });
  });
  await chmod(socketPath, 0o600);
  await new Promise((resolve) => {
    const close = () => server.close(() => resolve());
    process.once("SIGINT", close);
    process.once("SIGTERM", close);
  });
  await rm(socketPath, { force: true });
}

export const realSandboxHelperTest = Object.freeze({
  assertFixture,
  assertHostedReturnConfiguration,
  assertRunOwnedTerminalProjection,
  canonicalEvent,
  cleanupCandidates,
  forceOAuthRefreshReadSmoke,
  listAllRemotePaymentLinks,
  noFundsStatuses,
  refreshSmokeRequest,
  remoteRunOwnedLink,
  runOwnedEmails,
  terminalFixtureStatuses,
});

export default async function realSandboxEventHelper({ container, args }) {
  const [inputPath, outputPath] = args;
  if (!inputPath || !outputPath) {
    throw new Error("Restricted input and output paths are required.");
  }
  const input = await readJson(inputPath);
  const service = serviceFrom(container);

  if (input.action === "serve-signer") {
    await writeRestricted(outputPath, { ready: true });
    await serveInMemorySigner(
      service,
      text(input.socketPath, "signer socket path"),
      text(input.callbackUrl, "signer callback URL"),
    );
    return;
  }

  let result;
  if (input.action === "snapshot") {
    const refreshRequest = refreshSmokeRequest(input.uid);
    result = refreshRequest
      ? await forceOAuthRefreshReadSmoke(service, refreshRequest)
      : await safeSnapshot(service, input.uid);
  } else if (input.action === "connection-view") {
    result = await cleanupConnectionView(service);
  } else if (input.action === "list-cleanup-candidates") {
    result = await cleanupCandidates(service, input.runId);
  } else if (input.action === "archive-payment-link") {
    result = await archiveCleanupPaymentLink({
      container,
      runId: input.runId,
      service,
      uid: text(input.uid, "payment-link UID"),
    });
  } else if (input.action === "disconnect-oauth") {
    result = await disconnectCleanupInstallation(service);
  } else if (input.action === "assert-hosted-return") {
    result = await assertHostedReturnConfiguration(service, {
      expectedReturnUrl: input.expectedReturnUrl,
      runId: input.runId,
      state: input.state,
      uid: text(input.uid, "payment-link UID"),
    });
  } else if (input.action === "prepare") {
    const fixture = await fixtureFor(
      service,
      text(input.uid, "payment-link UID"),
      text(input.status, "event status"),
      noFundsStatuses,
    );
    await writeRestricted(text(input.fixturePath, "fixture path"), fixture);
    result = receipt(assertFixture(fixture, noFundsStatuses), null);
  } else if (input.action === "prepare-terminal-fixture") {
    const fixture = await terminalFixtureFor(
      service,
      text(input.uid, "payment-link UID"),
      text(input.status, "event status"),
      safeRunId(input.runId),
    );
    await writeRestricted(text(input.fixturePath, "fixture path"), fixture);
    result = receipt(assertFixture(fixture, terminalFixtureStatuses), null);
  } else if (input.action === "deliver") {
    const fixture = await fixtureFor(
      service,
      text(input.uid, "payment-link UID"),
      text(input.status, "event status"),
      noFundsStatuses,
    );
    const event = assertFixture(fixture, noFundsStatuses);
    const delivered = await postFixture(
      text(input.callbackUrl, "callback URL"),
      fixture,
      noFundsStatuses,
    );
    result = receipt(event, delivered.responseStatus);
  } else if (input.action === "post-terminal-fixture") {
    const fixture = await readJson(text(input.fixturePath, "fixture path"));
    const event = assertFixture(fixture, terminalFixtureStatuses);
    const delivered = await postFixture(
      text(input.callbackUrl, "callback URL"),
      fixture,
      terminalFixtureStatuses,
    );
    result = receipt(event, delivered.responseStatus);
  } else if (
    input.action === "post-fixture" ||
    input.action === "resign-fixture" ||
    input.action === "resign-fixture-without-routing"
  ) {
    const fixture = await readJson(text(input.fixturePath, "fixture path"));
    const event = assertFixture(fixture, noFundsStatuses);
    let toPost = fixture;
    let postedEvent = event;
    if (input.action !== "post-fixture") {
      if (input.action === "resign-fixture-without-routing") {
        postedEvent = { ...event };
        delete postedEvent.grantId;
        delete postedEvent.installationId;
        delete postedEvent.subscriptionId;
      }
      const body = JSON.stringify(postedEvent);
      toPost = {
        body,
        headers: signedHeaders(
          body,
          postedEvent,
          await service.getWebhookSecret(),
        ),
      };
    }
    const delivered = await postFixture(
      text(input.callbackUrl, "callback URL"),
      toPost,
      noFundsStatuses,
    );
    result = receipt(postedEvent, delivered.responseStatus);
  } else {
    throw new Error("Unsupported real-sandbox helper action.");
  }

  await writeRestricted(outputPath, result);
}
