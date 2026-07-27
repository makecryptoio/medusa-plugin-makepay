import { createHmac, randomBytes } from "node:crypto";

import type { BigNumberInput } from "@medusajs/framework/types";
import type { MakePayPaymentLinkResponse } from "@makecrypto/makepay";

import type {
  MakePayPaymentAction,
  MakePayPaymentSessionStatus,
  MakePayProviderData,
  MakePayProviderOptions,
  NormalizedMakePayProviderOptions,
} from "./types.js";

const DEFAULT_SETTLEMENT_CURRENCY = "USDT";
const DEFAULT_EXPIRATION_TIME = "12h";
const MAKECRYPTO_OAUTH_ISSUER = "https://www.makecrypto.io";
const MAKECRYPTO_OAUTH_RESOURCE = "https://makecrypto.io/api/partner/v1";
const CONFIGURATION_FINGERPRINT_KEY_SYMBOL = Symbol.for(
  "@makecrypto/medusa-plugin-makepay/configuration-fingerprint-key",
);

function configurationFingerprintKey(): Buffer {
  const existing = Reflect.get(
    globalThis,
    CONFIGURATION_FINGERPRINT_KEY_SYMBOL,
  );
  if (Buffer.isBuffer(existing) && existing.length === 32) {
    return existing;
  }

  const created = randomBytes(32);
  Reflect.set(globalThis, CONFIGURATION_FINGERPRINT_KEY_SYMBOL, created);
  return created;
}

function fingerprintUrl(value: unknown, fallback?: string): string | null {
  const text = getText(value) ?? fallback;
  if (!text) return null;
  try {
    return new URL(text).toString();
  } catch {
    return text;
  }
}

export function getDefaultMakePayOAuthAudience(issuer: string): string {
  const normalizedIssuer = issuer.replace(/\/+$/, "");
  return normalizedIssuer === MAKECRYPTO_OAUTH_ISSUER
    ? MAKECRYPTO_OAUTH_RESOURCE
    : `${normalizedIssuer}/api/partner/v1`;
}

export function makePaySecurityConfigurationFingerprint(
  options: Partial<MakePayProviderOptions> | NormalizedMakePayProviderOptions,
): string {
  const authMode = options.authMode === "oauth" ? "oauth" : "api_key";
  const issuer = fingerprintUrl(
    options.oauthIssuerUrl,
    MAKECRYPTO_OAUTH_ISSUER,
  )!;
  const baseUrl = fingerprintUrl(options.baseUrl, "https://www.makecrypto.io")!;
  return createHmac("sha256", configurationFingerprintKey())
    .update(
      JSON.stringify({
        adminPath: getText(options.adminPath) ?? "/app",
        authMode,
        backendUrl: fingerprintUrl(options.backendUrl),
        baseUrl,
        checkoutBaseUrl: fingerprintUrl(
          options.checkoutBaseUrl,
          "https://makepay.io",
        ),
        encryptionKey: getText(options.encryptionKey) ?? null,
        expirationTime:
          getText(options.expirationTime) ?? DEFAULT_EXPIRATION_TIME,
        failureUrl: fingerprintUrl(options.failureUrl),
        keyId: getText(options.keyId) ?? null,
        keySecret: getText(options.keySecret) ?? null,
        lockingProvider: getText(options.lockingProvider) ?? null,
        oauthApiUrl: fingerprintUrl(options.oauthApiUrl, baseUrl),
        oauthAudience:
          getText(options.oauthAudience) ??
          getDefaultMakePayOAuthAudience(issuer),
        oauthIssuerUrl: issuer,
        providerId: getText(options.providerId) ?? "makepay",
        returnUrl: fingerprintUrl(options.returnUrl),
        settlementCurrency:
          getText(options.settlementCurrency) ?? DEFAULT_SETTLEMENT_CURRENCY,
        storefrontReturnUrl: fingerprintUrl(options.storefrontReturnUrl),
        successUrl: fingerprintUrl(options.successUrl),
        webhookSecret: getText(options.webhookSecret) ?? null,
        webhookToleranceSeconds: options.webhookToleranceSeconds ?? null,
      }),
    )
    .digest("hex");
}

const CAPTURED_STATUSES = new Set(["complete"]);

const CANCELED_STATUSES = new Set(["cancelled", "expired"]);

const FUNDED_IN_FLIGHT_STATUSES = new Set([
  "deposit_received",
  "sending",
  "swapping",
  "underpaid",
]);

const FAILED_STATUSES = new Set(["failed"]);

const PENDING_AUTHORIZATION_STATUSES = new Set([
  "active",
  "created",
  "open",
  "pending_authorization",
  "unpaid",
]);

const PENDING_STATUSES = new Set([
  "awaiting_deposit",
  "deposit_received",
  "pending",
  "quoted",
  "sending",
  "swapping",
  "underpaid",
]);

const WEBHOOK_RECORD_KEYS = [
  "data",
  "payload",
  "event",
  "session",
  "latestSession",
  "payment",
  "paymentLink",
  "payment_link",
  "link",
] as const;

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * A payment-link snapshot at the provider boundary. Authenticated partner-v1
 * responses use the SDK's complete shape, while legacy API-key serializers can
 * be sparse; every field is therefore validated before use.
 */
export type MakePayPaymentLinkSnapshot = Record<string, unknown>;

export function getText(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== ""
    ? value.trim()
    : undefined;
}

export function getNumberOrText(value: unknown): string | number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === "string" && value.trim() !== "") {
    return value.trim();
  }

  return undefined;
}

export function normalizeProviderOptions(
  options: MakePayProviderOptions,
): NormalizedMakePayProviderOptions {
  validateMakePayProviderOptions(options);

  return {
    ...options,
    authMode: options.authMode === "oauth" ? "oauth" : "api_key",
    settlementCurrency:
      getText(options.settlementCurrency) ?? DEFAULT_SETTLEMENT_CURRENCY,
    expirationTime: getText(options.expirationTime) ?? DEFAULT_EXPIRATION_TIME,
    providerId: getText(options.providerId) ?? "makepay",
  };
}

export function validateMakePayProviderOptions(
  options: Partial<MakePayProviderOptions> | null | undefined,
): asserts options is MakePayProviderOptions {
  if (!isRecord(options)) {
    throw new Error("MakePay provider options are required.");
  }

  if (
    options.authMode !== undefined &&
    options.authMode !== "api_key" &&
    options.authMode !== "oauth"
  ) {
    throw new Error("MakePay `authMode` must be either `api_key` or `oauth`.");
  }

  const adminPath = getText(options.adminPath);
  if (
    adminPath &&
    (!adminPath.startsWith("/") ||
      adminPath.startsWith("//") ||
      adminPath.includes("..") ||
      /[?#\\]/.test(adminPath))
  ) {
    throw new Error("MakePay `adminPath` must be a safe absolute URL path.");
  }

  if (getText(options.providerId) && options.providerId !== "makepay") {
    throw new Error(
      "MakePay 1.0.x supports only providerId `makepay` (pp_makepay_makepay).",
    );
  }

  if (
    options.webhookToleranceSeconds !== undefined &&
    (!Number.isInteger(options.webhookToleranceSeconds) ||
      options.webhookToleranceSeconds < 1 ||
      options.webhookToleranceSeconds > 900)
  ) {
    throw new Error(
      "MakePay `webhookToleranceSeconds` must be an integer from 1 through 900.",
    );
  }

  for (const [keyName, value, originOnly] of [
    ["baseUrl", options.baseUrl, true],
    ["checkoutBaseUrl", options.checkoutBaseUrl, true],
    ["backendUrl", options.backendUrl, true],
    ["storefrontReturnUrl", options.storefrontReturnUrl, false],
    ["oauthIssuerUrl", options.oauthIssuerUrl, true],
    ["oauthApiUrl", options.oauthApiUrl, true],
    ["returnUrl", options.returnUrl, false],
    ["successUrl", options.successUrl, false],
    ["failureUrl", options.failureUrl, false],
  ] as const) {
    if (!value) continue;
    try {
      const url = new URL(String(value));
      const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(
        url.hostname,
      );
      if (
        (url.protocol !== "https:" &&
          !(url.protocol === "http:" && loopback)) ||
        url.username ||
        url.password ||
        url.hash ||
        (originOnly && (url.pathname !== "/" || Boolean(url.search)))
      ) {
        throw new Error();
      }
    } catch {
      throw new Error(
        `MakePay option \`${keyName}\` must be a safe HTTPS URL.`,
      );
    }
  }
  if (
    options.authMode !== "oauth" &&
    Boolean(getText(options.backendUrl)) !==
      Boolean(getText(options.storefrontReturnUrl))
  ) {
    throw new Error(
      "MakePay API-key hosted returns require both `backendUrl` and `storefrontReturnUrl`.",
    );
  }

  if (options.authMode === "oauth") {
    for (const key of [
      "backendUrl",
      "storefrontReturnUrl",
      "encryptionKey",
      "lockingProvider",
    ] as const) {
      if (!getText(options[key])) {
        throw new Error(`Required MakePay OAuth option \`${key}\` is missing.`);
      }
    }
    const key = Buffer.from(String(options.encryptionKey), "base64");
    if (key.length !== 32 || key.toString("base64") !== options.encryptionKey) {
      throw new Error(
        "MakePay `encryptionKey` must be a canonical base64-encoded 32-byte value.",
      );
    }
    const lockingProvider = getText(options.lockingProvider);
    if (
      lockingProvider === "in-memory" ||
      lockingProvider === "locking-in-memory"
    ) {
      throw new Error(
        "MakePay `lockingProvider` must select a distributed Medusa locking provider.",
      );
    }
    return;
  }

  for (const key of ["keyId", "keySecret", "webhookSecret"] as const) {
    if (!getText(options[key])) {
      throw new Error(
        `Required MakePay provider option \`${key}\` is missing.`,
      );
    }
  }
}

export function normalizeAmountValue(amount: BigNumberInput): string | number {
  if (typeof amount === "number" || typeof amount === "string") {
    return amount;
  }

  if (isRecord(amount)) {
    const raw = isRecord(amount.raw) ? amount.raw.value : undefined;
    const value =
      getNumberOrText(raw) ??
      getNumberOrText(amount.value) ??
      getNumberOrText(amount.numeric);

    if (value !== undefined) {
      return value;
    }
  }

  throw new Error("MakePay could not normalize the Medusa payment amount.");
}

export function getNestedRecord(
  source: Record<string, unknown>,
  key: string,
): Record<string, unknown> | undefined {
  return isRecord(source[key]) ? source[key] : undefined;
}

const PAYMENT_LINK_CORRELATION_METADATA_KEYS = [
  "medusaInstallationId",
  "medusaOrderDisplayId",
  "medusaOrderId",
  "medusaProviderId",
  "medusaSessionId",
] as const;

function normalizedPaymentLinkAmount(
  paymentLink: Record<string, unknown>,
): string | number | undefined {
  const payload = getNestedRecord(paymentLink, "payload");
  const nestedAmount =
    getNumberOrText(payload?.amount) ??
    getNumberOrText(payload?.fiatAmount) ??
    getNumberOrText(payload?.fiat_amount);
  const candidates = [
    getNumberOrText(paymentLink.amount),
    getNumberOrText(paymentLink.fiatAmount),
    getNumberOrText(paymentLink.fiat_amount),
    nestedAmount,
  ].filter((value): value is string | number => value !== undefined);
  const amount = candidates[0];
  if (
    amount !== undefined &&
    candidates.some((candidate) => !arePaymentAmountsEqual(amount, candidate))
  ) {
    throw new Error(
      "MakePay payment-link response contains conflicting fiat amounts.",
    );
  }
  return (
    amount ??
    getNumberOrText(paymentLink.amountUsd) ??
    getNumberOrText(paymentLink.amount_usd) ??
    getNumberOrText(payload?.amountUsd) ??
    getNumberOrText(payload?.amount_usd)
  );
}

function normalizedPaymentLinkFiatCurrency(
  paymentLink: Record<string, unknown>,
): string | undefined {
  const payload = getNestedRecord(paymentLink, "payload");
  const nestedCurrency =
    getText(payload?.fiatCurrency) ??
    getText(payload?.fiat_currency) ??
    getText(payload?.displayCurrency) ??
    getText(payload?.display_currency);
  const candidates = [
    getText(paymentLink.fiatCurrency),
    getText(paymentLink.fiat_currency),
    nestedCurrency,
  ].filter((value): value is string => value !== undefined);
  const currency = candidates[0]?.toUpperCase();
  if (
    currency &&
    candidates.some((candidate) => candidate.toUpperCase() !== currency)
  ) {
    throw new Error(
      "MakePay payment-link response contains conflicting fiat currencies.",
    );
  }
  return currency;
}

function normalizedPaymentLinkMetadata(
  paymentLink: Record<string, unknown>,
): Record<string, unknown> | undefined {
  const flat = getNestedRecord(paymentLink, "metadata");
  const nested = getNestedRecord(
    getNestedRecord(paymentLink, "payload") ?? {},
    "metadata",
  );
  if (!flat && !nested) return undefined;

  for (const key of PAYMENT_LINK_CORRELATION_METADATA_KEYS) {
    if (
      flat &&
      nested &&
      Object.hasOwn(flat, key) &&
      Object.hasOwn(nested, key) &&
      flat[key] !== nested[key]
    ) {
      throw new Error(
        `MakePay payment-link response contains conflicting ${key} metadata.`,
      );
    }
  }
  return { ...nested, ...flat };
}

export function normalizeMakePayPaymentLink(
  value: Record<string, unknown>,
): MakePayPaymentLinkSnapshot {
  const amount = normalizedPaymentLinkAmount(value);
  const fiatCurrency = normalizedPaymentLinkFiatCurrency(value);
  const metadata = normalizedPaymentLinkMetadata(value);
  return {
    ...value,
    ...(amount === undefined ? {} : { amount, fiatAmount: amount }),
    ...(fiatCurrency ? { fiatCurrency } : {}),
    ...(metadata ? { metadata } : {}),
  };
}

export function getPaymentLinkFromResponse(
  response: MakePayPaymentLinkResponse | Record<string, unknown>,
): MakePayPaymentLinkSnapshot {
  const data = getNestedRecord(response, "data");

  for (const source of [response, data]) {
    if (!source) {
      continue;
    }

    if (isRecord(source.paymentLink)) {
      return normalizeMakePayPaymentLink(source.paymentLink);
    }

    if (isRecord(source.payment_link)) {
      return normalizeMakePayPaymentLink(source.payment_link);
    }

    if (isRecord(source.link)) {
      return normalizeMakePayPaymentLink(source.link);
    }
  }

  return {};
}

export function getPaymentLinkUid(data: unknown): string | undefined {
  if (!isRecord(data)) {
    return undefined;
  }

  const link =
    getNestedRecord(data, "paymentLink") ??
    getNestedRecord(data, "payment_link") ??
    getNestedRecord(data, "link");

  return (
    getText(data.payment_link_uid) ??
    getText(data.paymentLinkUid) ??
    getText(data.payment_link_id) ??
    getText(data.uid) ??
    getText(data.id) ??
    getText(link?.uid) ??
    getText(link?.id)
  );
}

export function getSafeExternalUrl(value: unknown): string | undefined {
  const text = getText(value);
  if (!text) return undefined;
  try {
    const url = new URL(text);
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (
      (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) ||
      url.username ||
      url.password
    ) {
      return undefined;
    }
    return url.toString();
  } catch {
    return undefined;
  }
}

export function getPaymentLinkUrl(
  link: MakePayPaymentLinkSnapshot,
): string | undefined {
  return getSafeExternalUrl(
    getText(link.publicUrl) ??
      getText(link.checkoutUrl) ??
      getText(link.public_url) ??
      getText(link.checkout_url) ??
      getText(link.url),
  );
}

export function getSafeHostedPaymentUrl(
  value: unknown,
  paymentLinkUid: string,
  checkoutBaseUrl = "https://makepay.io",
): string | undefined {
  const safe = getSafeExternalUrl(value);
  if (!safe) return undefined;
  try {
    const url = new URL(safe);
    const configured = new URL(checkoutBaseUrl);
    const trustedOrigins = new Set([configured.origin]);
    if (
      configured.origin === "https://makepay.io" ||
      configured.origin === "https://www.makepay.io"
    ) {
      trustedOrigins.add("https://makepay.io");
      trustedOrigins.add("https://www.makepay.io");
    }
    if (
      !trustedOrigins.has(url.origin) ||
      url.search ||
      url.hash ||
      url.pathname !== `/payment/${encodeURIComponent(paymentLinkUid)}`
    ) {
      return undefined;
    }
    return url.toString();
  } catch {
    return undefined;
  }
}

export function getPaymentLinkAmount(
  data: unknown,
): string | number | undefined {
  if (!isRecord(data)) {
    return undefined;
  }

  const link =
    getNestedRecord(data, "paymentLink") ??
    getNestedRecord(data, "payment_link") ??
    getNestedRecord(data, "link");

  if (link) return normalizedPaymentLinkAmount(link);
  return (
    normalizedPaymentLinkAmount(data) ?? getNumberOrText(data.payment_amount)
  );
}

export function getPaymentLinkFiatCurrency(data: unknown): string | undefined {
  if (!isRecord(data)) {
    return undefined;
  }

  const link =
    getNestedRecord(data, "paymentLink") ??
    getNestedRecord(data, "payment_link") ??
    getNestedRecord(data, "link");

  if (link) return normalizedPaymentLinkFiatCurrency(link);
  return normalizedPaymentLinkFiatCurrency(data);
}

export function getSessionIdFromData(data: unknown): string | undefined {
  if (!isRecord(data)) {
    return undefined;
  }

  const metadata = getNestedRecord(data, "metadata");

  return (
    getText(data.session_id) ??
    getText(data.sessionId) ??
    getText(metadata?.session_id) ??
    getText(metadata?.medusaSessionId)
  );
}

export function getSessionIdFromWebhook(event: unknown): string | undefined {
  for (const record of collectWebhookRecords(event, {
    includeMetadata: true,
  })) {
    const sessionId =
      getText(record.session_id) ??
      getText(record.sessionId) ??
      getText(record.medusaSessionId);

    if (sessionId) {
      return sessionId;
    }
  }

  return undefined;
}

function getCorrelatedWebhookText(
  event: unknown,
  keys: readonly string[],
): string | undefined {
  for (const record of collectWebhookRecords(event, {
    includeMetadata: true,
  })) {
    for (const key of keys) {
      const value = getText(record[key]);
      if (value) return value;
    }
  }
  return undefined;
}

export function getCompanyIdFromWebhook(event: unknown): string | undefined {
  return getCorrelatedWebhookText(event, ["companyId", "company_id"]);
}

export function getInstallationIdFromWebhook(
  event: unknown,
): string | undefined {
  return getCorrelatedWebhookText(event, [
    "installationId",
    "installation_id",
    "medusaInstallationId",
  ]);
}

export function getOrderIdFromWebhook(event: unknown): string | undefined {
  return getCorrelatedWebhookText(event, [
    "medusaOrderId",
    "orderId",
    "order_id",
  ]);
}

export function getOrderDisplayIdFromWebhook(
  event: unknown,
): string | undefined {
  return getCorrelatedWebhookText(event, [
    "medusaOrderDisplayId",
    "orderDisplayId",
    "order_display_id",
  ]);
}

export function getAmountFromWebhook(
  event: unknown,
): string | number | undefined {
  for (const record of collectWebhookRecords(event)) {
    const explicitFiatAmount =
      getNumberOrText(record.fiatAmount) ?? getNumberOrText(record.fiat_amount);
    if (explicitFiatAmount !== undefined) return explicitFiatAmount;

    for (const key of ["paymentLink", "payment_link", "link"] as const) {
      const link = getNestedRecord(record, key);
      const linkAmount = link
        ? (getNumberOrText(link.fiatAmount) ??
          getNumberOrText(link.fiat_amount) ??
          getNumberOrText(link.amount))
        : undefined;
      if (linkAmount !== undefined) return linkAmount;
    }
  }

  return undefined;
}

export function collectStatusValues(input: unknown): string[] {
  const values: string[] = [];

  for (const record of collectWebhookRecords(input)) {
    for (const statusKey of ["status", "paymentStatus", "state", "type"]) {
      const value = getText(record[statusKey]);
      if (value) {
        values.push(value.toLowerCase());
      }
    }
  }

  return values;
}

export function getMakePayProviderStatus(input: unknown): string {
  const statuses = collectStatusValues(input);
  if (
    statuses.includes("complete") &&
    statuses.some(
      (status) => CANCELED_STATUSES.has(status) || FAILED_STATUSES.has(status),
    )
  ) {
    return "conflicting_terminal";
  }
  for (const group of [
    CAPTURED_STATUSES,
    CANCELED_STATUSES,
    FAILED_STATUSES,
    PENDING_STATUSES,
  ]) {
    const match = statuses.find((status) => group.has(status));
    if (match) return match;
  }
  if (statuses.includes("archived")) return "archived";
  const pendingAuthorization = statuses.find((status) =>
    PENDING_AUTHORIZATION_STATUSES.has(status),
  );
  if (pendingAuthorization) return pendingAuthorization;
  return "pending";
}

/**
 * Resolve the provider status from MakePay's authoritative lifecycle fields.
 *
 * Payment-link payload and metadata are merchant-controlled and retained in
 * API responses for backwards compatibility, so they must not participate in
 * capture or payment-status decisions.
 */
export function getAuthoritativeMakePayProviderStatus(input: {
  paymentLink?: unknown;
  session?: unknown;
}): string {
  const paymentLink = isRecord(input.paymentLink)
    ? input.paymentLink
    : undefined;
  const session = isRecord(input.session) ? input.session : undefined;
  const statuses = [
    getText(paymentLink?.status)?.toLowerCase(),
    getText(session?.status)?.toLowerCase(),
  ].filter((status): status is string => Boolean(status));
  const paymentLinkStatus = getText(paymentLink?.status)?.toLowerCase();
  const sessionStatus = getText(session?.status)?.toLowerCase();

  // Archiving prevents a new payer transfer only when no session/channel ever
  // existed. Historical integrations could archive after quote creation, so
  // any recognized authenticated session lifecycle outranks the link status.
  if (paymentLinkStatus === "archived") {
    if (
      sessionStatus &&
      (CAPTURED_STATUSES.has(sessionStatus) ||
        CANCELED_STATUSES.has(sessionStatus) ||
        FAILED_STATUSES.has(sessionStatus) ||
        FUNDED_IN_FLIGHT_STATUSES.has(sessionStatus) ||
        PENDING_STATUSES.has(sessionStatus) ||
        PENDING_AUTHORIZATION_STATUSES.has(sessionStatus))
    ) {
      return sessionStatus;
    }
    return "archived";
  }
  const terminalClasses = new Set<string>();

  for (const status of statuses) {
    if (CAPTURED_STATUSES.has(status)) terminalClasses.add("captured");
    if (CANCELED_STATUSES.has(status)) terminalClasses.add("canceled");
    if (FAILED_STATUSES.has(status)) terminalClasses.add("failed");
  }

  if (terminalClasses.size > 1) {
    return "conflicting_terminal";
  }

  for (const group of [
    CAPTURED_STATUSES,
    CANCELED_STATUSES,
    FAILED_STATUSES,
    PENDING_STATUSES,
    PENDING_AUTHORIZATION_STATUSES,
  ]) {
    const match = statuses.find((status) => group.has(status));
    if (match) return match;
  }

  return "pending";
}

export function collectWebhookRecords(
  input: unknown,
  options: { includeMetadata?: boolean } = {},
): Record<string, unknown>[] {
  if (!isRecord(input)) {
    return [];
  }

  const records: Record<string, unknown>[] = [];
  const seen = new Set<Record<string, unknown>>();
  const keys = options.includeMetadata
    ? [...WEBHOOK_RECORD_KEYS, "metadata"]
    : WEBHOOK_RECORD_KEYS;

  const visit = (record: Record<string, unknown>, depth: number): void => {
    if (seen.has(record)) {
      return;
    }

    seen.add(record);
    records.push(record);

    if (depth <= 0) {
      return;
    }

    for (const key of keys) {
      const nested = getNestedRecord(record, key);
      if (nested) {
        visit(nested, depth - 1);
      }
    }
  };

  visit(input, 4);

  return records;
}

export function mapMakePayStateToPaymentSessionStatus(
  input: unknown,
): MakePayPaymentSessionStatus {
  const statuses = collectStatusValues(input);

  if (
    statuses.some((status) => CAPTURED_STATUSES.has(status)) &&
    !statuses.some(
      (status) => CANCELED_STATUSES.has(status) || FAILED_STATUSES.has(status),
    )
  ) {
    return "captured";
  }

  if (statuses.some((status) => CANCELED_STATUSES.has(status))) {
    return "canceled";
  }

  if (statuses.some((status) => FAILED_STATUSES.has(status))) {
    return "error";
  }

  if (statuses.some((status) => PENDING_STATUSES.has(status))) {
    return "pending";
  }

  if (statuses.includes("archived")) {
    return "canceled";
  }

  if (statuses.some((status) => PENDING_AUTHORIZATION_STATUSES.has(status))) {
    return "pending_authorization";
  }

  return "pending";
}

export function mapMakePayWebhookToPaymentAction(
  event: unknown,
): MakePayPaymentAction {
  const statuses = collectStatusValues(event);

  if (
    statuses.some((status) => CAPTURED_STATUSES.has(status)) &&
    !statuses.some(
      (status) => CANCELED_STATUSES.has(status) || FAILED_STATUSES.has(status),
    )
  ) {
    return "captured";
  }

  if (statuses.includes("complete")) {
    return "not_supported";
  }

  if (statuses.some((status) => CANCELED_STATUSES.has(status))) {
    return "canceled";
  }

  if (statuses.some((status) => FAILED_STATUSES.has(status))) {
    return "failed";
  }

  if (
    statuses.includes("archived") &&
    !statuses.some((status) => FUNDED_IN_FLIGHT_STATUSES.has(status))
  ) {
    return "canceled";
  }

  if (statuses.some((status) => PENDING_AUTHORIZATION_STATUSES.has(status))) {
    return "pending";
  }

  if (statuses.some((status) => PENDING_STATUSES.has(status))) {
    return "pending";
  }

  return "not_supported";
}

export function shouldRefreshPaymentLinkForUpdate(input: {
  currentData: unknown;
  nextAmount: BigNumberInput;
  nextCurrencyCode: string;
}): boolean {
  if (collectStatusValues(input.currentData).includes("archived")) {
    return true;
  }
  const status = mapMakePayStateToPaymentSessionStatus(input.currentData);

  if (status === "captured") {
    return false;
  }

  if (status === "canceled" || status === "error") {
    return true;
  }

  const currentAmount = getPaymentLinkAmount(input.currentData);
  const currentCurrency = getPaymentLinkFiatCurrency(input.currentData);

  if (
    currentAmount !== undefined &&
    !arePaymentAmountsEqual(
      currentAmount,
      normalizeAmountValue(input.nextAmount),
    )
  ) {
    return true;
  }

  return (
    currentCurrency !== undefined &&
    currentCurrency.toUpperCase() !== input.nextCurrencyCode.toUpperCase()
  );
}

export function canonicalPaymentAmount(
  value: string | number,
): string | undefined {
  if (typeof value === "number") {
    if (
      !Number.isFinite(value) ||
      value < 0 ||
      (Number.isInteger(value) && !Number.isSafeInteger(value))
    ) {
      return undefined;
    }
  }
  const text = String(value).trim();
  // Payment amounts use plain, non-negative decimal notation. Reject exponent
  // notation and ambiguous leading-zero forms instead of IEEE-754 coercion.
  const match = /^(0|[1-9]\d*)(?:\.(\d+))?$/.exec(text);
  if (!match) return undefined;
  const fraction = (match[2] ?? "").replace(/0+$/, "");
  return fraction ? `${match[1]}.${fraction}` : match[1];
}

export function arePaymentAmountsEqual(
  left: string | number,
  right: string | number,
): boolean {
  const leftDecimal = canonicalPaymentAmount(left);
  const rightDecimal = canonicalPaymentAmount(right);
  return (
    leftDecimal !== undefined &&
    rightDecimal !== undefined &&
    leftDecimal === rightDecimal
  );
}

export function buildProviderData(input: {
  existing?: Record<string, unknown>;
  paymentLink: MakePayPaymentLinkSnapshot;
  sessionId?: string;
  status?: MakePayPaymentSessionStatus;
  amount?: string | number;
  fiatCurrency?: string;
  returnState?: string;
  checkoutBaseUrl?: string;
}): MakePayProviderData {
  const existing = input.existing ?? {};
  const paymentLink = normalizeMakePayPaymentLink(
    input.paymentLink as Record<string, unknown>,
  );
  const uid =
    getText(paymentLink.uid) ??
    getText(paymentLink.id) ??
    getPaymentLinkUid(existing);
  const remoteUrl = getPaymentLinkUrl(paymentLink);
  const url = uid
    ? getSafeHostedPaymentUrl(remoteUrl, uid, input.checkoutBaseUrl)
    : undefined;
  const status =
    input.status ??
    (getText(existing.status) as MakePayPaymentSessionStatus | undefined) ??
    mapMakePayStateToPaymentSessionStatus(paymentLink);
  const amount =
    input.amount ??
    getPaymentLinkAmount(paymentLink) ??
    getNumberOrText(input.existing?.amount);
  const fiatCurrency =
    input.fiatCurrency ??
    getPaymentLinkFiatCurrency(paymentLink) ??
    getText(input.existing?.fiat_currency) ??
    getText(input.existing?.fiatCurrency);

  return {
    amount,
    fiat_currency: fiatCurrency,
    payment_link_uid: uid,
    public_url: url,
    session_id: input.sessionId ?? getSessionIdFromData(existing),
    status,
    return_state: input.returnState ?? getText(existing.return_state),
    next_action: url
      ? {
          type: "redirect",
          url,
        }
      : undefined,
  };
}

export function getPaymentLinkUidFromWebhook(
  event: unknown,
): string | undefined {
  for (const record of collectWebhookRecords(event, {
    includeMetadata: true,
  })) {
    const uid =
      getText(record.payment_link_uid) ??
      getText(record.paymentLinkUid) ??
      getText(record.uid);
    if (uid) return uid;
  }
  return undefined;
}

export function getCurrencyFromWebhook(event: unknown): string | undefined {
  for (const record of collectWebhookRecords(event)) {
    const explicitFiatCurrency =
      getText(record.fiatCurrency) ?? getText(record.fiat_currency);
    if (explicitFiatCurrency) return explicitFiatCurrency.toUpperCase();

    for (const key of ["paymentLink", "payment_link", "link"] as const) {
      const link = getNestedRecord(record, key);
      const linkCurrency = link
        ? (getText(link.fiatCurrency) ?? getText(link.fiat_currency))
        : undefined;
      if (linkCurrency) return linkCurrency.toUpperCase();
    }
  }
  return undefined;
}

export function getWebhookEventType(event: unknown): string | undefined {
  if (!isRecord(event)) return undefined;
  return getText(event.type) ?? getText(getNestedRecord(event, "event")?.type);
}
