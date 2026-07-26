import { randomUUID, timingSafeEqual } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";

import {
  MakePayClient,
  MakePayError,
  parseMakePayWebhook,
  type MakePayPaymentLinkResponse,
  type MakePayPaymentLinkUpdate,
} from "@makecrypto/makepay";
import type {
  ILockingModule,
  IPaymentModuleService,
  Logger,
} from "@medusajs/framework/types";
import { MedusaModule } from "@medusajs/framework/modules-sdk";
import { MedusaError, MedusaService, Modules } from "@medusajs/framework/utils";

import type { MakePayProviderOptions } from "../../providers/makepay/types.js";
import { terminalSessionUpdateContext } from "../../lib/terminal-session.js";
import {
  arePaymentAmountsEqual,
  getMakePayProviderStatus,
  getDefaultMakePayOAuthAudience,
  getNestedRecord,
  getPaymentLinkAmount,
  getPaymentLinkFiatCurrency,
  getPaymentLinkFromResponse,
  getPaymentLinkUrl,
  getSafeHostedPaymentUrl,
  getText,
  isRecord,
  mapMakePayStateToPaymentSessionStatus,
  makePaySecurityConfigurationFingerprint,
  validateMakePayProviderOptions,
} from "../../providers/makepay/utils.js";
import {
  createDpopKeyPair,
  createDpopProof,
  createPkceChallenge,
  decodeJwtPayload,
  decryptSecret,
  dpopThumbprintFromPrivateKey,
  encryptSecret,
  parseEncryptionKey,
  randomOpaqueToken,
  sha256,
  verifyOAuthAccessToken,
} from "./crypto.js";
import {
  MAKEPAY_DEFAULT_PROVIDER_ID,
  MAKEPAY_OAUTH_SCOPES,
} from "./constants.js";
import {
  MakePayConnection,
  MakePayOAuthState,
  MakePayPaymentProjection,
  MakePayWebhookDelivery,
  MakePayWebhookSubscription,
} from "./models/index.js";
import type {
  MakePayConnectionView,
  MakePayModuleOptions,
  MakePayOAuthTokenResponse,
  MakePayPaymentView,
} from "./types.js";

type RecordShape = Record<string, unknown>;

const REGISTERED_PROVIDER_CONFIGURATIONS_SYMBOL = Symbol.for(
  "@makecrypto/medusa-plugin-makepay/registered-provider-configurations",
);

function registeredProviderConfigurations(): Set<string> {
  const existing = Reflect.get(
    globalThis,
    REGISTERED_PROVIDER_CONFIGURATIONS_SYMBOL,
  );
  if (existing instanceof Set) {
    return existing as Set<string>;
  }

  const created = new Set<string>();
  Reflect.set(globalThis, REGISTERED_PROVIDER_CONFIGURATIONS_SYMBOL, created);
  return created;
}

type WebhookRecordInput = {
  amount: string | number;
  companyId?: string;
  createdAt?: string;
  currency?: string;
  deliveryId: string;
  eventType?: string;
  grantId?: string;
  installationId?: string;
  orderDisplayId?: string;
  orderId?: string;
  payloadHash: string;
  providerStatus: string;
  sessionId: string;
  subscriptionId?: string;
  uid: string;
};

type WebhookRecordResult =
  | "accepted"
  | "duplicate"
  | "in_progress"
  | "retry"
  | "rejected";

type SynchronousWebhookAuthority = {
  active: boolean;
  amount?: string | number;
  currency?: string;
  paymentLinkUid: string;
  sessionId?: string;
};

function boundedWebhookRoutingId(
  value: unknown,
  maximumLength: number,
): string | undefined {
  const text = getText(value);
  if (
    !text ||
    text.length > maximumLength ||
    /[\u0000-\u001f\u007f]/.test(text)
  ) {
    return undefined;
  }
  return text;
}

export function makePayWebhookRotationIdempotencyKey(input: {
  dpopThumbprint: string;
  grantId: string;
  installationId: string;
  oauthAttemptId: string;
}): string {
  return `medusa-webhook-${sha256(
    `${input.installationId}:${input.grantId}:${input.oauthAttemptId}:${input.dpopThumbprint}`,
  ).slice(0, 40)}`;
}

type GeneratedMethods = {
  listMakePayConnections(
    filters?: RecordShape,
    config?: RecordShape,
  ): Promise<RecordShape[]>;
  createMakePayConnections(data: RecordShape): Promise<RecordShape>;
  updateMakePayConnections(data: RecordShape): Promise<RecordShape>;
  listMakePayOAuthStates(
    filters?: RecordShape,
    config?: RecordShape,
  ): Promise<RecordShape[]>;
  createMakePayOAuthStates(data: RecordShape): Promise<RecordShape>;
  updateMakePayOAuthStates(data: RecordShape): Promise<RecordShape>;
  deleteMakePayOAuthStates(ids: string | string[]): Promise<void>;
  listMakePayPaymentProjections(
    filters?: RecordShape,
    config?: RecordShape,
    sharedContext?: RecordShape,
  ): Promise<RecordShape[]>;
  listAndCountMakePayPaymentProjections(
    filters?: RecordShape,
    config?: RecordShape,
  ): Promise<[RecordShape[], number]>;
  createMakePayPaymentProjections(data: RecordShape): Promise<RecordShape>;
  updateMakePayPaymentProjections(
    data: RecordShape,
    sharedContext?: RecordShape,
  ): Promise<RecordShape>;
  listMakePayWebhookDeliveries(
    filters?: RecordShape,
    config?: RecordShape,
    sharedContext?: RecordShape,
  ): Promise<RecordShape[]>;
  createMakePayWebhookDeliveries(
    data: RecordShape,
    sharedContext?: RecordShape,
  ): Promise<RecordShape>;
  listMakePayWebhookSubscriptions(
    filters?: RecordShape,
    config?: RecordShape,
  ): Promise<RecordShape[]>;
  createMakePayWebhookSubscriptions(data: RecordShape): Promise<RecordShape>;
  updateMakePayWebhookSubscriptions(data: RecordShape): Promise<RecordShape>;
};

type OAuthCredentials = {
  accessToken: string;
  refreshToken?: string;
  privateKey: string;
  expiresAt: Date;
  connection: RecordShape;
};

type OAuthDpopKeyCandidate = {
  privateKey: string;
  thumbprint: string;
};

type OAuthDiscovery = {
  authorizationEndpoint: string;
  issuer: string;
  jwksUri: string;
  nativeInstallationEndpoint: string;
  tokenEndpoint: string;
};

const TERMINAL_SUCCESS = new Set(["complete"]);
const TERMINAL_CANCELED = new Set(["expired", "cancelled"]);
const TERMINAL_FAILED = new Set(["failed"]);
const TERMINAL_FAILURE = new Set([...TERMINAL_CANCELED, ...TERMINAL_FAILED]);
const MAKEPAY_SESSION_STATUSES = new Set([
  "quoted",
  "awaiting_deposit",
  "pending",
  "deposit_received",
  "swapping",
  "sending",
  "underpaid",
  "complete",
  "failed",
  "expired",
  "cancelled",
]);
const SUCCESS_CLAIM_LEASE_MS = 120_000;
const OAUTH_REGISTRATION_RECOVERY_PAGE_SIZE = 20;
const OAUTH_REFRESH_ERROR = "MakePay OAuth refresh failed.";
const OAUTH_REFRESH_FAILURE_RETRYABLE = "retryable";
const OAUTH_REFRESH_FAILURE_TERMINAL = "terminal";

function isRetryableOAuthRefreshResponse(
  response: Response,
  body: RecordShape,
): boolean {
  const error = getText(body.error)?.toLowerCase();
  return (
    response.status === 408 ||
    response.status === 425 ||
    response.status === 429 ||
    response.status >= 500 ||
    error === "server_error" ||
    error === "temporarily_unavailable"
  );
}

function isDpopBindingMismatchResponse(
  response: Response,
  body: RecordShape,
): boolean {
  const error = getText(body.error)?.toLowerCase();
  return (
    (response.status === 400 || response.status === 401) &&
    (error === "invalid_dpop_proof" || error === "invalid_dpop_key")
  );
}

function terminalClass(status: string): "success" | "failure" | undefined {
  if (TERMINAL_SUCCESS.has(status)) return "success";
  if (TERMINAL_FAILURE.has(status)) return "failure";
  return undefined;
}

type TerminalProviderStatus = "complete" | "failed" | "expired" | "cancelled";

function terminalIdentity(status: string): TerminalProviderStatus | undefined {
  if (
    status === "complete" ||
    status === "failed" ||
    status === "expired" ||
    status === "cancelled"
  ) {
    return status;
  }
  return undefined;
}

const STATUS_FILTERS: Record<string, string[]> = {
  complete: ["complete"],
  pending: [
    "active",
    "created",
    "open",
    "unpaid",
    "pending",
    "quoted",
    "awaiting_deposit",
    "deposit_received",
    "swapping",
    "sending",
    "underpaid",
  ],
  failed: ["failed"],
  cancelled: ["cancelled"],
  expired: ["expired"],
};

const refreshPromises = new Map<string, Promise<void>>();

function asDate(value: unknown): Date | undefined {
  if (value instanceof Date && Number.isFinite(value.getTime())) {
    return value;
  }
  if (typeof value === "string" || typeof value === "number") {
    const parsed = new Date(value);
    return Number.isFinite(parsed.getTime()) ? parsed : undefined;
  }
  return undefined;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string")
    : [];
}

function iso(value: unknown): string | undefined {
  return asDate(value)?.toISOString();
}

function normalizeOrigin(
  value: string,
  label: string,
  options: { originOnly?: boolean } = {},
): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`MakePay ${label} must be an absolute URL.`);
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error(`MakePay ${label} must use HTTPS.`);
  }
  if (
    url.username ||
    url.password ||
    url.hash ||
    (options.originOnly && url.search)
  ) {
    throw new Error(
      `MakePay ${label} must not include credentials, a query, or a fragment.`,
    );
  }
  if (options.originOnly && url.pathname !== "/") {
    throw new Error(`MakePay ${label} must be an origin without a path.`);
  }
  return url.toString().replace(/\/+$/, "");
}

function responseError(body: unknown, fallback: string): string {
  // OAuth/API error descriptions are controlled by a remote system and may
  // contain reflected request material. Never persist or return them through
  // Admin APIs.
  void body;
  return fallback;
}

class OAuthTokenRecoveryExpiredError extends Error {
  constructor() {
    super(
      "MakePay OAuth token recovery expired. Reconnect MakePay to continue.",
    );
    this.name = "OAuthTokenRecoveryExpiredError";
  }
}

function normalizeAdminPath(value: unknown): string {
  const text = getText(value) ?? "/app";
  if (
    !text.startsWith("/") ||
    text.startsWith("//") ||
    text.includes("..") ||
    /[?#\\]/.test(text)
  ) {
    throw new Error("MakePay `adminPath` must be a safe absolute URL path.");
  }
  return text.replace(/\/+$/, "") || "/";
}

function statusFromProjection(
  record: RecordShape,
): "pending_authorization" | "paid" | "failed" | "canceled" {
  const status = String(record.provider_status ?? "").toLowerCase();
  // A remote `complete` observation is necessary but not sufficient. Only the
  // Medusa capture workflow (or its capture subscriber) may publish `paid` to
  // the storefront, which keeps return-before-webhook flows fail closed.
  if (TERMINAL_SUCCESS.has(status)) {
    return String(record.medusa_status ?? "").toLowerCase() === "paid"
      ? "paid"
      : "pending_authorization";
  }
  if (TERMINAL_CANCELED.has(status)) return "canceled";
  if (TERMINAL_FAILED.has(status)) return "failed";
  return "pending_authorization";
}

function medusaStatusForProvider(
  providerStatus: string,
  current?: string,
): string {
  const normalized = providerStatus.toLowerCase();
  const existing = current?.toLowerCase();
  if (existing === "paid") return "paid";
  if (TERMINAL_SUCCESS.has(normalized)) return "processing";
  if (TERMINAL_CANCELED.has(normalized)) return "canceled";
  if (TERMINAL_FAILED.has(normalized)) return "failed";
  return mapMakePayStateToPaymentSessionStatus({ status: normalized }) ===
    "pending"
    ? "pending"
    : "pending_authorization";
}

function medusaStatusForReconciliation(
  providerStatus: string,
  current?: string,
): string {
  const existing = current?.toLowerCase();
  if (existing === "paid") return "paid";
  // A remote terminal observation is not proof that Medusa's core payment
  // workflow or terminal session mutation has run. Preserve the local state so
  // a later webhook (or explicit Admin reconciliation) can perform that side
  // effect exactly once.
  if (terminalClass(providerStatus.toLowerCase())) {
    return existing ?? "pending_authorization";
  }
  return "pending_authorization";
}

export default class MakePayModuleService extends MedusaService({
  MakePayConnection,
  MakePayOAuthState,
  MakePayPaymentProjection,
  MakePayWebhookDelivery,
  MakePayWebhookSubscription,
}) {
  protected readonly logger_: Logger | Console;
  protected readonly options_: MakePayModuleOptions;
  protected readonly fetch_: typeof fetch;
  private oauthDiscovery_?: Promise<OAuthDiscovery>;
  private paymentEffectsContext_?: AsyncLocalStorage<Set<string>>;
  private webhookAuthorityContext_?: AsyncLocalStorage<SynchronousWebhookAuthority>;
  private providerConfigurationRegistered_ = false;

  constructor(
    { logger }: { logger?: Logger },
    options: MakePayModuleOptions = {},
  ) {
    super(...arguments);
    validateMakePayProviderOptions(options);
    this.logger_ = logger ?? console;
    this.options_ = options;
    this.fetch_ = options.fetch ?? globalThis.fetch;
    if (!this.fetch_) {
      throw new Error("MakePay requires a fetch implementation.");
    }
    if (options.authMode === "oauth") {
      // Validate security-critical OAuth configuration at module startup rather
      // than waiting for the first checkout or callback request.
      this.oauthConfig();
      this.lockingProviderId(true);
    }
  }

  private generated(): GeneratedMethods {
    return this as unknown as GeneratedMethods;
  }

  get providerId(): string {
    return getText(this.options_.providerId) ?? MAKEPAY_DEFAULT_PROVIDER_ID;
  }

  get authMode(): "api_key" | "oauth" {
    return this.options_.authMode === "oauth" ? "oauth" : "api_key";
  }

  private get configurationFingerprint(): string {
    return makePaySecurityConfigurationFingerprint(this.options_);
  }

  registerPaymentProviderConfiguration(fingerprint: string): void {
    const expected = Buffer.from(this.configurationFingerprint, "hex");
    const supplied = Buffer.from(fingerprint, "hex");
    if (
      expected.length !== supplied.length ||
      !timingSafeEqual(expected, supplied)
    ) {
      throw new Error(
        "MakePay provider and plugin module configuration do not match.",
      );
    }
    this.providerConfigurationRegistered_ = true;
    registeredProviderConfigurations().add(this.configurationFingerprint);
  }

  private async assertProviderConfigurationRegistered(): Promise<void> {
    if (this.providerConfigurationRegistered_ === true) {
      return;
    }

    const loaded = MedusaModule.getModuleInstance(Modules.PAYMENT) as
      | IPaymentModuleService
      | Record<string, unknown>
      | undefined;
    const paymentModule = loaded
      ? (((loaded as Record<string, unknown>)[Modules.PAYMENT] ??
          loaded) as IPaymentModuleService)
      : undefined;
    if (typeof paymentModule?.listPaymentMethods !== "function") {
      throw new Error(
        "MakePay plugin module configuration does not match a registered payment provider.",
      );
    }
    // Medusa registers payment providers lazily. Resolve the configured
    // provider through the public payment-module API before requiring the
    // constructor handshake, so Admin OAuth can be the first MakePay action
    // in a newly started process. Every new module instance performs this
    // lookup; a process-global fingerprint alone must never authorize it.
    await paymentModule.listPaymentMethods({
      context: {},
      provider_id: `pp_makepay_${this.providerId}`,
    });

    if (
      !registeredProviderConfigurations().has(this.configurationFingerprint)
    ) {
      throw new Error(
        "MakePay plugin module configuration does not match a registered payment provider.",
      );
    }
    this.providerConfigurationRegistered_ = true;
  }

  get reconciliationEnabled(): boolean {
    return Boolean(this.lockingProviderId(false) && this.lockingService());
  }

  private async hasUndrainedPayments(
    authMode: "api_key" | "oauth",
  ): Promise<boolean> {
    const payments = await this.generated().listMakePayPaymentProjections(
      {
        auth_mode: authMode,
        provider_id: this.providerId,
        $or: [
          {
            provider_status: {
              $nin: ["complete", "archived", "cancelled"],
            },
          },
          { medusa_status: null, provider_status: "complete" },
          { medusa_status: { $ne: "paid" }, provider_status: "complete" },
          {
            late_settlement_safe: false,
            provider_status: { $in: ["archived", "cancelled"] },
          },
          {
            medusa_status: null,
            provider_status: { $in: ["archived", "cancelled"] },
          },
          {
            medusa_status: { $ne: "canceled" },
            provider_status: { $in: ["archived", "cancelled"] },
          },
        ],
      },
      { order: { id: "ASC" }, take: 1 },
    );
    return payments.length > 0;
  }

  async hasUndrainedPaymentsForMode(
    authMode: "api_key" | "oauth",
  ): Promise<boolean> {
    return this.hasUndrainedPayments(authMode);
  }

  async assertAuthModeTransitionAllowed(): Promise<void> {
    const oppositeMode = this.authMode === "oauth" ? "api_key" : "oauth";
    if (await this.hasUndrainedPayments(oppositeMode)) {
      throw new MedusaError(
        MedusaError.Types.NOT_ALLOWED,
        `MakePay cannot switch to ${this.authMode} while a pending ${oppositeMode} payment exists. Restore ${oppositeMode} mode and resolve or cancel it first.`,
      );
    }
  }

  private async hasLiveOAuthState(): Promise<boolean> {
    const states = await this.generated().listMakePayOAuthStates(
      { provider_id: this.providerId },
      { order: { created_at: "DESC" }, take: 100 },
    );
    return states.some(
      (state) =>
        !state.consumed_at &&
        (asDate(state.expires_at)?.getTime() ?? 0) > Date.now(),
    );
  }

  get adminPath(): string {
    return normalizeAdminPath(this.options_.adminPath);
  }

  private lockingProviderId(required = false): string | undefined {
    const provider = getText(
      (this.options_ as Partial<MakePayProviderOptions>).lockingProvider,
    );
    if (!provider) {
      if (required) {
        throw new Error(
          "MakePay OAuth requires `lockingProvider` configured with a distributed Medusa locking provider (for example `makepay-postgres`).",
        );
      }
      return undefined;
    }
    if (provider === "in-memory" || provider === "locking-in-memory") {
      throw new Error(
        "MakePay `lockingProvider` must not select Medusa's in-memory provider.",
      );
    }
    return provider;
  }

  private async withDistributedLock<T>(
    key: string,
    job: () => Promise<T>,
    timeout = 15,
  ): Promise<T> {
    const locking = this.lockingService();
    if (!locking) {
      throw new Error(
        "MakePay OAuth requires Medusa's locking module with a distributed provider.",
      );
    }
    return locking.execute(key, job, {
      provider: this.lockingProviderId(true),
      timeout,
    });
  }

  private paymentEffectsLockKey(paymentLinkUid: string): string {
    const uid = getText(paymentLinkUid);
    if (!uid || uid.length > 200) {
      throw new Error("MakePay payment-link identity is invalid.");
    }
    return `makepay-payment-effects:${sha256(uid)}`;
  }

  private async withPaymentEffectsLock<T>(
    paymentLinkUid: string,
    job: () => Promise<T>,
  ): Promise<T> {
    const key = this.paymentEffectsLockKey(paymentLinkUid);
    const context =
      this.paymentEffectsContext_ ??
      (this.paymentEffectsContext_ = new AsyncLocalStorage<Set<string>>());
    const held = context.getStore();
    if (held?.has(key)) return job();
    return this.withDistributedLock(
      key,
      () => {
        const next = new Set(held);
        next.add(key);
        return context.run(next, job);
      },
      30,
    );
  }

  private async withConfiguredPaymentEffectsLock<T>(
    paymentLinkUid: string,
    job: () => Promise<T>,
  ): Promise<T> {
    return this.lockingProviderId(false)
      ? this.withPaymentEffectsLock(paymentLinkUid, job)
      : job();
  }

  private async withProjectionRowLock<T>(
    paymentLinkUid: string,
    job: (
      projection: RecordShape | undefined,
      sharedContext: RecordShape,
    ) => Promise<T>,
  ): Promise<T> {
    const uid = getText(paymentLinkUid);
    if (!uid || uid.length > 200) {
      throw new Error("MakePay projection payment-link identity is invalid.");
    }
    const repository = (
      this as unknown as {
        baseRepository_?: {
          transaction<R>(task: (manager: unknown) => Promise<R>): Promise<R>;
        };
      }
    ).baseRepository_;
    if (!repository) {
      throw new Error(
        "MakePay projection transaction repository is unavailable.",
      );
    }
    return repository.transaction(async (transactionManager) => {
      const manager = transactionManager as {
        execute?: (sql: string, parameters?: unknown[]) => Promise<unknown>;
      };
      if (typeof manager.execute !== "function") {
        throw new Error(
          "MakePay projection transaction manager cannot acquire a row lock.",
        );
      }
      await manager.execute(
        "SELECT id FROM makepay_payment_projection WHERE payment_link_uid = ? FOR UPDATE",
        [uid],
      );
      const sharedContext = { transactionManager };
      const [projection] = await this.generated().listMakePayPaymentProjections(
        { payment_link_uid: uid },
        { take: 1 },
        sharedContext,
      );
      return job(projection, sharedContext);
    });
  }

  async verifyWebhookSignature(
    rawBody: Buffer,
    signature: string,
    deliveryGroupId?: string,
  ): Promise<{ deliveryGroupId: string; paymentLinkUid: string }> {
    const secret = await this.getWebhookSecret(rawBody);
    const event = parseMakePayWebhook<RecordShape>(rawBody, signature, secret, {
      toleranceSeconds: (this.options_ as Partial<MakePayProviderOptions>)
        .webhookToleranceSeconds,
    });
    const paymentLink =
      event.paymentLink &&
      typeof event.paymentLink === "object" &&
      !Array.isArray(event.paymentLink)
        ? (event.paymentLink as RecordShape)
        : undefined;
    const paymentLinkUid = getText(paymentLink?.uid);
    if (this.authMode === "api_key") {
      if (!paymentLinkUid || paymentLinkUid.length > 200) {
        throw new MakePayError("Invalid MakePay webhook routing identity.", {
          status: 400,
        });
      }
      return {
        deliveryGroupId: `mpwhgrp_${sha256(rawBody.toString("utf8"))}`,
        paymentLinkUid,
      };
    }
    if (
      event.schemaVersion !== "medusa.v1" ||
      getText(event.deliveryGroupId) !== deliveryGroupId ||
      !deliveryGroupId ||
      !/^mpwhgrp_[a-f0-9]{64}$/.test(deliveryGroupId) ||
      !paymentLinkUid ||
      paymentLinkUid.length > 200
    ) {
      throw new MakePayError("Invalid MakePay webhook routing identity.", {
        status: 400,
      });
    }
    return { deliveryGroupId, paymentLinkUid };
  }

  async withWebhookDeliveryLock<T>(
    identity: { deliveryGroupId: string; paymentLinkUid: string },
    job: () => Promise<T>,
  ): Promise<T> {
    if (
      !/^mpwhgrp_[a-f0-9]{64}$/.test(identity.deliveryGroupId) ||
      !getText(identity.paymentLinkUid) ||
      identity.paymentLinkUid.length > 200
    ) {
      throw new Error("MakePay webhook delivery identity is invalid.");
    }
    if (!this.lockingProviderId(false)) {
      if (this.authMode === "oauth") {
        throw new Error(
          "MakePay OAuth webhooks require a distributed locking provider.",
        );
      }
      return job();
    }
    if (this.authMode !== "oauth") {
      return this.withPaymentEffectsLock(identity.paymentLinkUid, job);
    }
    const context =
      this.webhookAuthorityContext_ ??
      (this.webhookAuthorityContext_ =
        new AsyncLocalStorage<SynchronousWebhookAuthority>());
    const authority: SynchronousWebhookAuthority = {
      active: true,
      paymentLinkUid: identity.paymentLinkUid,
    };
    return this.withPaymentEffectsLock(identity.paymentLinkUid, () =>
      context.run(authority, async () => {
        try {
          return await job();
        } finally {
          authority.active = false;
          authority.amount = undefined;
          authority.currency = undefined;
          authority.sessionId = undefined;
        }
      }),
    );
  }

  hasSynchronousWebhookAuthority(input: {
    amount: string | number;
    currency: string;
    paymentLinkUid: string;
    sessionId: string;
  }): boolean {
    const authority = this.webhookAuthorityContext_?.getStore();
    return Boolean(
      this.authMode === "oauth" &&
      authority?.active === true &&
      authority.paymentLinkUid === input.paymentLinkUid &&
      authority.sessionId === input.sessionId &&
      authority.currency?.toUpperCase() === input.currency.toUpperCase() &&
      authority.amount !== undefined &&
      arePaymentAmountsEqual(authority.amount, input.amount),
    );
  }

  adminSettingsPath(query?: "connected" | "error"): string {
    const path = `${this.adminPath === "/" ? "" : this.adminPath}/settings/makepay`;
    if (query === "connected") return `${path}?makepay_connected=1`;
    if (query === "error") return `${path}?makepay_error=1`;
    return path;
  }

  private checkoutReturnConfig() {
    const options = this.options_ as Partial<MakePayProviderOptions>;
    const backendUrlValue = getText(options.backendUrl);
    const storefrontReturnUrlValue = getText(options.storefrontReturnUrl);
    if (!backendUrlValue || !storefrontReturnUrlValue) {
      throw new Error(
        "MakePay hosted return handling requires `backendUrl` and `storefrontReturnUrl`.",
      );
    }
    return {
      backendUrl: normalizeOrigin(backendUrlValue, "backendUrl", {
        originOnly: true,
      }),
      storefrontReturnUrl: normalizeOrigin(
        storefrontReturnUrlValue,
        "storefrontReturnUrl",
      ),
    };
  }

  private oauthConfig() {
    if (this.authMode !== "oauth") {
      throw new Error("MakePay OAuth is not enabled for this installation.");
    }
    const options = this.options_ as Partial<MakePayProviderOptions>;
    const { backendUrl, storefrontReturnUrl } = this.checkoutReturnConfig();
    const issuer = normalizeOrigin(
      getText(options.oauthIssuerUrl) ?? "https://www.makecrypto.io",
      "oauthIssuerUrl",
      { originOnly: true },
    );
    const apiBaseUrl = normalizeOrigin(
      getText(options.oauthApiUrl) ??
        getText(options.baseUrl) ??
        "https://www.makecrypto.io",
      "oauthApiUrl",
      { originOnly: true },
    );
    const audience = (
      getText(options.oauthAudience) ?? getDefaultMakePayOAuthAudience(issuer)
    ).replace(/\/+$/, "");
    return {
      apiBaseUrl,
      audience,
      backendUrl,
      callbackUrl: `${backendUrl}/makepay/oauth/callback`,
      encryptionKey: parseEncryptionKey(options.encryptionKey),
      issuer,
      storefrontReturnUrl,
      webhookUrl: `${backendUrl}/hooks/makepay/makepay_${this.providerId}`,
    };
  }

  private async discoverOAuth(): Promise<OAuthDiscovery> {
    if (this.oauthDiscovery_) return this.oauthDiscovery_;
    const config = this.oauthConfig();
    this.oauthDiscovery_ = (async () => {
      const metadataUrl = `${config.issuer}/.well-known/oauth-authorization-server`;
      const response = await this.fetch_(metadataUrl, {
        headers: { accept: "application/json" },
        redirect: "manual",
      });
      if (!response.ok) {
        throw new Error("MakePay OAuth discovery failed.");
      }
      const metadata = (await response.json()) as RecordShape;
      if (metadata.issuer !== config.issuer) {
        throw new Error(
          "MakePay OAuth discovery returned an unexpected issuer.",
        );
      }
      if (metadata.authorization_response_iss_parameter_supported !== true) {
        throw new Error(
          "MakePay OAuth discovery does not support issuer-bound authorization responses.",
        );
      }
      const endpoint = (field: string): string => {
        const value = getText(metadata[field]);
        if (!value) {
          throw new Error(`MakePay OAuth discovery omitted ${field}.`);
        }
        let url: URL;
        try {
          url = new URL(value);
        } catch {
          throw new Error(
            `MakePay OAuth discovery returned an invalid ${field}.`,
          );
        }
        if (
          url.origin !== config.issuer ||
          url.username ||
          url.password ||
          url.search ||
          url.hash
        ) {
          throw new Error(
            `MakePay OAuth discovery returned an unsafe ${field}.`,
          );
        }
        return url.toString().replace(/\/+$/, "");
      };
      return {
        authorizationEndpoint: endpoint("authorization_endpoint"),
        issuer: config.issuer,
        jwksUri: endpoint("jwks_uri"),
        nativeInstallationEndpoint: endpoint("native_installation_endpoint"),
        tokenEndpoint: endpoint("token_endpoint"),
      };
    })().catch((error) => {
      this.oauthDiscovery_ = undefined;
      throw error;
    });
    return this.oauthDiscovery_;
  }

  private async connectionRecord(): Promise<RecordShape | undefined> {
    const [connection] = await this.generated().listMakePayConnections(
      { provider_id: this.providerId },
      { take: 1 },
    );
    return connection;
  }

  private webhookCallbackMatchesConfiguration(
    connection: RecordShape,
  ): boolean {
    return getText(connection.webhook_url) === this.oauthConfig().webhookUrl;
  }

  private canRecoverRetryableOAuthRefresh(connection: RecordShape): boolean {
    const metadata = isRecord(connection.metadata) ? connection.metadata : {};
    const refreshAttempt = isRecord(metadata.refresh_attempt)
      ? metadata.refresh_attempt
      : undefined;
    const refreshFailure = getText(refreshAttempt?.failure);
    const legacyAttemptWithoutFailureMarker =
      refreshAttempt !== undefined && !Reflect.has(refreshAttempt, "failure");
    if (
      connection.status === "error" &&
      getText(connection.last_error) === OAUTH_REFRESH_ERROR &&
      (refreshFailure === OAUTH_REFRESH_FAILURE_RETRYABLE ||
        legacyAttemptWithoutFailureMarker) &&
      refreshAttempt?.recovery_expired !== true &&
      !getText(metadata.disconnect_native_reset_mutation_id) &&
      !getText(metadata.disconnect_native_reset_receipt_id) &&
      !getText(metadata.disconnect_webhook_mutation_id) &&
      connection.webhook_status === "healthy" &&
      this.webhookCallbackMatchesConfiguration(connection) &&
      Boolean(connection.encrypted_webhook_secret) &&
      Boolean(getText(connection.webhook_subscription_id)) &&
      !this.pendingWebhookRotation(connection)
    ) {
      const connectionId = getText(connection.id);
      const encryptedRefreshToken = getText(
        connection.encrypted_refresh_token,
      );
      const credentialFingerprint = getText(
        refreshAttempt?.credential_fingerprint,
      );
      const idempotencyKey = getText(refreshAttempt?.idempotency_key);
      if (
        !connectionId ||
        !encryptedRefreshToken ||
        !credentialFingerprint ||
        !idempotencyKey ||
        !/^medusa-token-[A-Za-z0-9_-]{43}$/.test(idempotencyKey)
      ) {
        return false;
      }
      try {
        const refreshToken = decryptSecret(
          encryptedRefreshToken,
          this.oauthConfig().encryptionKey,
          `connection:${connectionId}:refresh-token`,
        );
        return sha256(refreshToken) === credentialFingerprint;
      } catch {
        return false;
      }
    }
    return false;
  }

  async getConnectionView(): Promise<MakePayConnectionView> {
    if (this.authMode === "api_key") {
      const configured = Boolean(
        getText((this.options_ as RecordShape).keyId) &&
        getText((this.options_ as RecordShape).keySecret) &&
        getText((this.options_ as RecordShape).webhookSecret),
      );
      return {
        auth_mode: "api_key",
        connected: configured,
        reconnect_required: false,
        scopes: [],
        status: configured ? "connected" : "error",
        webhook: {
          configured: Boolean(
            getText((this.options_ as RecordShape).webhookSecret),
          ),
          status: configured ? "healthy" : "missing",
        },
      };
    }

    const connection = await this.connectionRecord();
    if (!connection) {
      return {
        auth_mode: "oauth",
        connected: false,
        reconnect_required: false,
        scopes: [],
        status: "disconnected",
        webhook: { configured: false, status: "missing" },
      };
    }
    const webhookCallbackMatches =
      this.webhookCallbackMatchesConfiguration(connection);
    const connectionMetadata = isRecord(connection.metadata)
      ? connection.metadata
      : {};
    const refreshAttempt = isRecord(connectionMetadata.refresh_attempt)
      ? connectionMetadata.refresh_attempt
      : undefined;
    const reconnectRequired =
      connection.status !== "disconnect_pending" &&
      (!webhookCallbackMatches ||
        getText(refreshAttempt?.failure) === OAUTH_REFRESH_FAILURE_TERMINAL ||
        refreshAttempt?.recovery_expired === true);
    const configuredStatus =
      connection.status === "connected" ||
      connection.status === "disconnect_pending" ||
      connection.status === "error"
        ? connection.status
        : "disconnected";

    return {
      access_token_expires_at: iso(connection.access_token_expires_at),
      auth_mode: "oauth",
      client_id: getText(connection.client_id),
      company_id: getText(connection.company_id),
      company_name: getText(connection.company_name),
      connected:
        connection.status === "connected" &&
        webhookCallbackMatches &&
        Boolean(connection.encrypted_access_token),
      reconnect_required: reconnectRequired,
      connected_at: iso(connection.connected_at),
      last_error: webhookCallbackMatches
        ? getText(connection.last_error)
        : "MakePay webhook callback configuration changed. Reconnect MakePay.",
      scopes: asStringArray(connection.scopes),
      status:
        configuredStatus === "connected" && !webhookCallbackMatches
          ? "error"
          : configuredStatus,
      updated_at: iso(connection.updated_at),
      webhook: {
        callback_url: getText(connection.webhook_url),
        configured: Boolean(
          connection.status === "connected" &&
          webhookCallbackMatches &&
          connection.encrypted_webhook_secret &&
          getText(connection.webhook_subscription_id),
        ),
        last_error: webhookCallbackMatches
          ? getText(connection.webhook_last_error)
          : "MakePay webhook callback configuration changed. Reconnect MakePay.",
        status: !webhookCallbackMatches
          ? "error"
          : connection.webhook_status === "healthy" ||
              connection.webhook_status === "error"
            ? connection.webhook_status
            : "missing",
      },
    };
  }

  async startOAuth(): Promise<{
    authorization_url: string;
    expires_at: string;
  }> {
    await this.assertProviderConfigurationRegistered();
    if (this.authMode !== "oauth") {
      throw new Error("MakePay OAuth start is unavailable in API-key mode.");
    }
    return this.withDistributedLock(
      `makepay-oauth-lifecycle:${this.providerId}`,
      () => this.startOAuthWithinLifecycleLock(),
      30,
    );
  }

  private async startOAuthWithinLifecycleLock(): Promise<{
    authorization_url: string;
    expires_at: string;
  }> {
    await this.assertAuthModeTransitionAllowed();
    if (await this.hasLiveOAuthState()) {
      throw new Error(
        "MakePay OAuth connection is already awaiting authorization.",
      );
    }
    let existingConnection = await this.connectionRecord();
    const existingMetadata = isRecord(existingConnection?.metadata)
      ? existingConnection.metadata
      : {};
    const codeExchangeRecoveryExpired =
      existingMetadata.oauth_token_recovery_expired === "authorization_code";
    if (
      existingConnection &&
      this.pendingWebhookRotation(existingConnection) &&
      !codeExchangeRecoveryExpired
    ) {
      try {
        existingConnection =
          await this.recoverPendingWebhookRotation(existingConnection);
      } catch (error) {
        if (!(error instanceof OAuthTokenRecoveryExpiredError)) throw error;
        const current = await this.connectionRecord();
        if (
          !current ||
          current.id !== existingConnection.id ||
          !this.pendingWebhookRotation(current)
        ) {
          throw new Error(
            "MakePay OAuth connection changed during token recovery.",
          );
        }
        // Keep the exact pending webhook mutation. The replacement consent
        // must resolve to the same routing tuple before it may be replayed.
        existingConnection = current;
      }
    }
    const config = this.oauthConfig();
    const discovery = await this.discoverOAuth();
    const keyPair = createDpopKeyPair();
    const registrationUrl = discovery.nativeInstallationEndpoint;
    const existing = existingConnection;
    // Consent can promote any staged key before the callback reaches Medusa.
    // Keep paging until exhaustion: a fixed recent-state window can exclude
    // the only key able to prove possession after a lost callback.
    const registrationHistory: RecordShape[] = [];
    for (let skip = 0; ; skip += OAUTH_REGISTRATION_RECOVERY_PAGE_SIZE) {
      const page = await this.generated().listMakePayOAuthStates(
        { provider_id: this.providerId },
        {
          order: { created_at: "DESC", id: "DESC" },
          skip,
          take: OAUTH_REGISTRATION_RECOVERY_PAGE_SIZE,
        },
      );
      registrationHistory.push(...page);
      if (page.length < OAUTH_REGISTRATION_RECOVERY_PAGE_SIZE) break;
    }
    const state = randomOpaqueToken(32);
    const verifier = randomOpaqueToken(64);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    const pendingId = `mpost_${randomUUID().replace(/-/g, "")}`;
    let registrationId = existing?.encrypted_registration_id
      ? decryptSecret(
          String(existing.encrypted_registration_id),
          config.encryptionKey,
          `connection:${String(existing.id)}:registration-id`,
        )
      : undefined;
    if (!registrationId) {
      const priorRegistration = registrationHistory.find(
        (registration) => registration.encrypted_registration_id,
      );
      if (priorRegistration) {
        registrationId = decryptSecret(
          String(priorRegistration.encrypted_registration_id),
          config.encryptionKey,
          `oauth-state:${String(priorRegistration.id)}:registration-id`,
        );
      }
    }
    registrationId ??= randomOpaqueToken(32);
    if (!/^[A-Za-z0-9_-]{43}$/.test(registrationId)) {
      throw new Error("MakePay native registration identity is invalid.");
    }
    // Persist possession of the proposed key before registration. If the
    // server rotates the installation key but the response is lost, a later
    // Connect attempt can prove possession of this abandoned key.
    await this.generated().createMakePayOAuthStates({
      id: pendingId,
      client_id: "registration_pending",
      dpop_thumbprint: keyPair.thumbprint,
      encrypted_code_verifier: encryptSecret(
        verifier,
        config.encryptionKey,
        `oauth-state:${pendingId}:verifier`,
      ),
      encrypted_dpop_private_key: encryptSecret(
        keyPair.privateKeyPem,
        config.encryptionKey,
        `oauth-state:${pendingId}:dpop`,
      ),
      encrypted_registration_id: encryptSecret(
        registrationId,
        config.encryptionKey,
        `oauth-state:${pendingId}:registration-id`,
      ),
      expires_at: expiresAt,
      provider_id: this.providerId,
      redirect_uri: config.callbackUrl,
      state_hash: sha256(state),
    });

    const activeKey = existing?.encrypted_dpop_private_key
      ? decryptSecret(
          String(existing.encrypted_dpop_private_key),
          config.encryptionKey,
          `connection:${String(existing.id)}:dpop`,
        )
      : undefined;
    const previousKeys: Array<string | undefined> = [];
    const seenPreviousKeys = new Set<string | undefined>();
    const abandonedKeys = registrationHistory
      .filter((registration) => registration.encrypted_dpop_private_key)
      .map((registration) =>
        decryptSecret(
          String(registration.encrypted_dpop_private_key),
          config.encryptionKey,
          `oauth-state:${String(registration.id)}:dpop`,
        ),
      );
    for (const candidate of [activeKey, ...abandonedKeys, undefined]) {
      if (seenPreviousKeys.has(candidate)) continue;
      seenPreviousKeys.add(candidate);
      previousKeys.push(candidate);
    }
    const registrationPayload = JSON.stringify({
      dpopJkt: keyPair.thumbprint,
      medusaVersion: getText(this.options_.medusaVersion) ?? "2.17.2+",
      platform: "medusa",
      pluginVersion: "1.0.0",
      registrationId,
      redirectUri: config.callbackUrl,
      siteUrl: new URL(config.backendUrl).origin,
    });
    let registrationBody: RecordShape = {};
    let registrationStatus = 0;
    for (const [index, previousKey] of previousKeys.entries()) {
      const headers: Record<string, string> = {
        accept: "application/json",
        "content-type": "application/json",
        dpop: createDpopProof({
          privateKey: keyPair.privateKeyPem,
          method: "POST",
          url: registrationUrl,
        }),
      };
      if (previousKey) {
        headers["dpop-previous"] = createDpopProof({
          privateKey: previousKey,
          method: "POST",
          url: registrationUrl,
        });
      }
      let response: Response;
      try {
        response = await this.fetch_(registrationUrl, {
          body: registrationPayload,
          headers,
          method: "POST",
          redirect: "manual",
        });
      } catch {
        await this.generated().updateMakePayOAuthStates({
          id: pendingId,
          consumed_at: new Date(),
        });
        throw new Error(
          "MakePay native OAuth registration could not be reached.",
        );
      }
      registrationStatus = response.status;
      registrationBody = (await response
        .json()
        .catch(() => ({}))) as RecordShape;
      if (
        response.ok &&
        getText(registrationBody.client_id) &&
        getText(registrationBody.registration_id) === registrationId
      ) {
        break;
      }
      const canRetryPreviousProof =
        [401, 403, 409].includes(response.status) &&
        index < previousKeys.length - 1;
      if (!canRetryPreviousProof) break;
    }
    if (
      !getText(registrationBody.client_id) ||
      getText(registrationBody.registration_id) !== registrationId
    ) {
      void registrationStatus;
      await this.generated().updateMakePayOAuthStates({
        id: pendingId,
        consumed_at: new Date(),
      });
      throw new Error("MakePay native OAuth registration failed.");
    }
    await this.generated().updateMakePayOAuthStates({
      id: pendingId,
      client_id: String(registrationBody.client_id),
    });
    const allowedScopes = asStringArray(registrationBody.scopes);
    const missingScopes = MAKEPAY_OAUTH_SCOPES.filter(
      (scope) => !allowedScopes.includes(scope),
    );
    if (missingScopes.length) {
      await this.generated().updateMakePayOAuthStates({
        id: pendingId,
        consumed_at: new Date(),
      });
      throw new Error(
        `MakePay OAuth registration is missing required scopes: ${missingScopes.join(", ")}.`,
      );
    }

    const authorizationUrl = new URL(discovery.authorizationEndpoint);
    authorizationUrl.searchParams.set("response_type", "code");
    authorizationUrl.searchParams.set(
      "client_id",
      String(registrationBody.client_id),
    );
    authorizationUrl.searchParams.set("redirect_uri", config.callbackUrl);
    authorizationUrl.searchParams.set("scope", MAKEPAY_OAUTH_SCOPES.join(" "));
    authorizationUrl.searchParams.set(
      "code_challenge",
      createPkceChallenge(verifier),
    );
    authorizationUrl.searchParams.set("code_challenge_method", "S256");
    authorizationUrl.searchParams.set("dpop_jkt", keyPair.thumbprint);
    authorizationUrl.searchParams.set("resource", config.audience);
    authorizationUrl.searchParams.set("state", state);

    return {
      authorization_url: authorizationUrl.toString(),
      expires_at: expiresAt.toISOString(),
    };
  }

  async finishOAuth(input: {
    code?: string;
    error?: string;
    errorDescription?: string;
    iss?: string;
    state?: string;
  }): Promise<void> {
    await this.assertProviderConfigurationRegistered();
    if (!input.state) {
      throw new Error("MakePay OAuth callback is missing state.");
    }
    const stateHash = sha256(input.state);
    await this.withDistributedLock(
      `makepay-oauth-lifecycle:${this.providerId}`,
      () =>
        this.withDistributedLock(`makepay-oauth-state:${stateHash}`, () =>
          this.finishOAuthWithLockedState(
            { ...input, state: input.state as string },
            stateHash,
          ),
        ),
      30,
    );
  }

  private async finishOAuthWithLockedState(
    input: {
      code?: string;
      error?: string;
      errorDescription?: string;
      iss?: string;
      state: string;
    },
    stateHash: string,
  ): Promise<void> {
    const config = this.oauthConfig();
    const [pending] = await this.generated().listMakePayOAuthStates(
      { provider_id: this.providerId, state_hash: stateHash },
      { take: 1 },
    );
    if (
      !pending ||
      (pending.consumed_at &&
        (!pending.encrypted_authorization_code ||
          !getText(pending.token_exchange_id))) ||
      !asDate(pending.expires_at) ||
      asDate(pending.expires_at)!.getTime() <= Date.now()
    ) {
      throw new Error(
        "MakePay OAuth state is invalid, expired, or already used.",
      );
    }
    const stateWasConsumed = Boolean(pending.consumed_at);
    await this.assertAuthModeTransitionAllowed();
    const existingConnection = await this.connectionRecord();
    const consumeRejectedState = async (): Promise<void> => {
      if (!stateWasConsumed) {
        await this.generated().updateMakePayOAuthStates({
          id: pending.id,
          consumed_at: new Date(),
        });
      }
    };

    // RFC 9207 issuer identification prevents authorization-server mix-up.
    // Rejected callbacks still consume state so an attacker cannot turn a
    // failed callback into a reusable transaction.
    if (input.iss !== config.issuer) {
      await consumeRejectedState();
      throw new Error("MakePay OAuth callback issuer is missing or invalid.");
    }
    if (input.error) {
      await consumeRejectedState();
      throw new Error("MakePay OAuth authorization was not completed.");
    }
    if (!input.code) {
      await consumeRejectedState();
      throw new Error("MakePay OAuth callback is missing code.");
    }

    let authorizationCode: string;
    let tokenExchangeId = getText(pending.token_exchange_id);
    if (stateWasConsumed) {
      if (!pending.encrypted_authorization_code || !tokenExchangeId) {
        throw new Error(
          "MakePay OAuth state is invalid, expired, or already used.",
        );
      }
      authorizationCode = decryptSecret(
        String(pending.encrypted_authorization_code),
        config.encryptionKey,
        `oauth-state:${String(pending.id)}:authorization-code`,
      );
      if (authorizationCode !== input.code) {
        throw new Error(
          "MakePay OAuth state is invalid, expired, or already used.",
        );
      }
    } else {
      authorizationCode = input.code;
      tokenExchangeId = `medusa-token-${randomOpaqueToken(32)}`;
      await this.generated().updateMakePayOAuthStates({
        consumed_at: new Date(),
        encrypted_authorization_code: encryptSecret(
          authorizationCode,
          config.encryptionKey,
          `oauth-state:${String(pending.id)}:authorization-code`,
        ),
        id: pending.id,
        token_exchange_id: tokenExchangeId,
      });
    }
    if (!/^medusa-token-[A-Za-z0-9_-]{43}$/.test(tokenExchangeId)) {
      throw new Error("MakePay OAuth token exchange recovery is invalid.");
    }

    const privateKey = decryptSecret(
      String(pending.encrypted_dpop_private_key),
      config.encryptionKey,
      `oauth-state:${String(pending.id)}:dpop`,
    );
    const verifier = decryptSecret(
      String(pending.encrypted_code_verifier),
      config.encryptionKey,
      `oauth-state:${String(pending.id)}:verifier`,
    );
    if (!pending.encrypted_registration_id) {
      throw new Error("MakePay OAuth registration identity is missing.");
    }
    const registrationId = decryptSecret(
      String(pending.encrypted_registration_id),
      config.encryptionKey,
      `oauth-state:${String(pending.id)}:registration-id`,
    );
    const discovery = await this.discoverOAuth();
    const tokenUrl = discovery.tokenEndpoint;
    const form = new URLSearchParams({
      client_id: String(pending.client_id),
      code: authorizationCode,
      code_verifier: verifier,
      grant_type: "authorization_code",
      redirect_uri: String(pending.redirect_uri),
      resource: config.audience,
    });
    const tokenResponse = await this.fetch_(tokenUrl, {
      body: form,
      headers: {
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
        dpop: createDpopProof({ privateKey, method: "POST", url: tokenUrl }),
        "idempotency-key": tokenExchangeId,
      },
      method: "POST",
      redirect: "manual",
    });
    const tokenBody = (await tokenResponse
      .json()
      .catch(() => ({}))) as unknown as MakePayOAuthTokenResponse & RecordShape;
    const expiresIn = Number(tokenBody.expires_in);
    const tokenResponseIsReplay =
      tokenResponse.headers.get("idempotent-replayed") === "true";
    const recoveryExpired =
      tokenResponse.status === 400 &&
      getText(tokenBody.error) === "invalid_grant" &&
      tokenResponse.headers.get("oauth-token-recovery")?.toLowerCase() ===
        "expired";
    if (
      !tokenResponse.ok ||
      !getText(tokenBody.access_token) ||
      !getText(tokenBody.refresh_token) ||
      getText(tokenBody.token_type)?.toLowerCase() !== "dpop" ||
      !Number.isFinite(expiresIn) ||
      expiresIn <= 0
    ) {
      if (recoveryExpired) {
        await this.generated().updateMakePayOAuthStates({
          encrypted_authorization_code: null,
          id: pending.id,
          token_exchange_id: null,
        });
        if (existingConnection) {
          const metadata = isRecord(existingConnection.metadata)
            ? existingConnection.metadata
            : {};
          await this.generated().updateMakePayConnections({
            id: existingConnection.id,
            last_error:
              "MakePay OAuth token recovery expired. Reconnect MakePay.",
            metadata: {
              ...metadata,
              oauth_token_recovery_expired: "authorization_code",
            },
            status: "error",
          });
        }
        throw new OAuthTokenRecoveryExpiredError();
      }
      throw new Error(
        responseError(tokenBody, "MakePay OAuth token exchange failed."),
      );
    }
    const claims = await verifyOAuthAccessToken({
      allowExpiredForIdempotentReplay: tokenResponseIsReplay,
      audience: config.audience,
      expectedClientId: String(pending.client_id),
      expectedDpopThumbprint: String(pending.dpop_thumbprint),
      expectedScopes: MAKEPAY_OAUTH_SCOPES,
      fetchImpl: this.fetch_,
      issuer: config.issuer,
      jwksUri: discovery.jwksUri,
      token: tokenBody.access_token,
    });
    const companyId = getText(claims.company_id);
    const grantId = getText(claims.grant_id);
    const accessTokenExpiryMs = Math.min(
      Date.now() + expiresIn * 1000,
      Number(claims.exp) * 1000,
    );
    // Native installations are identified by the immutable OAuth client_id.
    // `sub` identifies the authorizing principal and must never be used for
    // webhook routing or installation correlation.
    const installationId = String(pending.client_id);
    if (
      !companyId ||
      !grantId ||
      !Number.isFinite(accessTokenExpiryMs) ||
      getText(claims.installation_id) !== installationId
    ) {
      throw new Error(
        "MakePay OAuth token did not identify its company, grant, and installation.",
      );
    }
    const scopes = (getText(tokenBody.scope) ?? "")
      .split(/\s+/)
      .filter(Boolean);
    const missingScopes = MAKEPAY_OAUTH_SCOPES.filter(
      (scope) => !scopes.includes(scope),
    );
    const unknownScopes = scopes.filter(
      (scope) => !MAKEPAY_OAUTH_SCOPES.includes(scope as never),
    );
    if (missingScopes.length || unknownScopes.length) {
      throw new Error("MakePay consent returned an invalid scope set.");
    }

    const prior = await this.connectionRecord();
    const connectionId = String(
      prior?.id ?? `mpcon_${randomUUID().replace(/-/g, "")}`,
    );
    const webhookRotationKey = makePayWebhookRotationIdempotencyKey({
      dpopThumbprint: String(pending.dpop_thumbprint),
      grantId,
      installationId,
      oauthAttemptId: String(pending.id),
    });
    const connectionInput: RecordShape = {
      access_token_expires_at: new Date(accessTokenExpiryMs),
      auth_mode: "oauth",
      client_id: String(pending.client_id),
      company_id: companyId,
      company_name: getText(claims.company_name) ?? null,
      connected_at: new Date(),
      encrypted_access_token: encryptSecret(
        tokenBody.access_token,
        config.encryptionKey,
        `connection:${connectionId}:access-token`,
      ),
      encrypted_dpop_private_key: encryptSecret(
        privateKey,
        config.encryptionKey,
        `connection:${connectionId}:dpop`,
      ),
      encrypted_registration_id: encryptSecret(
        registrationId,
        config.encryptionKey,
        `connection:${connectionId}:registration-id`,
      ),
      encrypted_refresh_token: tokenBody.refresh_token
        ? encryptSecret(
            tokenBody.refresh_token,
            config.encryptionKey,
            `connection:${connectionId}:refresh-token`,
          )
        : null,
      encrypted_webhook_secret: null,
      grant_id: grantId,
      id: connectionId,
      installation_id: installationId,
      last_error: null,
      metadata: {
        disconnect_native_reset_mutation_id: null,
        disconnect_native_reset_receipt_id: null,
        disconnect_webhook_mutation_id: null,
        dpop_thumbprint: pending.dpop_thumbprint,
        oauth_token_recovery_expired: null,
        refresh_attempt: null,
        webhook_rotation: {
          company_id: companyId,
          dpop_thumbprint: pending.dpop_thumbprint,
          endpoint_url: config.webhookUrl,
          grant_id: grantId,
          idempotency_key: webhookRotationKey,
          installation_id: installationId,
          oauth_attempt_id: String(pending.id),
        },
      },
      provider_id: this.providerId,
      scopes,
      status: "error",
      webhook_last_error: "MakePay webhook subscription setup is pending.",
      webhook_subscription_id: null,
      webhook_status: "error",
      webhook_url: config.webhookUrl,
    };
    await this.withDistributedLock(
      `makepay-oauth-connection:${connectionId}`,
      async () => {
        const lockedPrior = await this.connectionRecord();
        if (
          (prior && lockedPrior?.id !== prior.id) ||
          (!prior && lockedPrior)
        ) {
          throw new Error(
            "MakePay OAuth connection changed during token exchange.",
          );
        }
        if (lockedPrior) {
          await this.preserveCurrentWebhookCredential(
            lockedPrior,
            "historical",
          );
          const lockedMetadata = isRecord(lockedPrior.metadata)
            ? lockedPrior.metadata
            : {};
          const {
            disconnect_native_reset_mutation_id: _oldNativeReset,
            disconnect_native_reset_receipt_id: _oldResetReceipt,
            disconnect_webhook_mutation_id: _oldWebhookDisconnect,
            oauth_token_recovery_expired: _oldTokenRecovery,
            refresh_attempt: _oldRefreshAttempt,
            webhook_rotation: _oldWebhookRotation,
            ...preservedMetadata
          } = lockedMetadata;
          void _oldNativeReset;
          void _oldResetReceipt;
          void _oldWebhookDisconnect;
          void _oldTokenRecovery;
          void _oldRefreshAttempt;
          void _oldWebhookRotation;
          connectionInput.encrypted_webhook_secret =
            lockedPrior.encrypted_webhook_secret ?? null;
          connectionInput.webhook_subscription_id =
            lockedPrior.webhook_subscription_id ?? null;
          connectionInput.metadata = {
            ...preservedMetadata,
            // Medusa merges JSON fields during generated updates. Explicit
            // null tombstones are required; merely omitting an old key leaves
            // it in PostgreSQL and can replay a completed lifecycle mutation.
            disconnect_native_reset_mutation_id: null,
            disconnect_native_reset_receipt_id: null,
            disconnect_webhook_mutation_id: null,
            oauth_token_recovery_expired: null,
            refresh_attempt: null,
            ...(connectionInput.metadata as RecordShape),
          };
          await this.generated().updateMakePayConnections(connectionInput);
        } else {
          await this.generated().createMakePayConnections(connectionInput);
        }

        try {
          let current = await this.connectionRecord();
          if (!current || current.id !== connectionId) {
            throw new Error(
              "MakePay OAuth connection changed during webhook setup.",
            );
          }
          const currentExpiry = asDate(current.access_token_expires_at);
          if (
            !currentExpiry ||
            currentExpiry.getTime() <= Date.now() + 30_000
          ) {
            await this.performRefresh(connectionId);
            current = await this.connectionRecord();
            if (!current || current.id !== connectionId) {
              throw new Error(
                "MakePay OAuth connection changed during token recovery.",
              );
            }
          }
          await this.recoverPendingWebhookRotation(current, {
            allowRefreshRetry: false,
            alreadyLocked: true,
          });
          await this.generated().updateMakePayOAuthStates({
            encrypted_authorization_code: null,
            id: pending.id,
            token_exchange_id: null,
          });
        } catch (error) {
          void error;
          await this.generated().updateMakePayConnections({
            id: connectionId,
            last_error: "MakePay webhook subscription setup failed.",
            status: "error",
            webhook_last_error: "MakePay webhook subscription setup failed.",
            webhook_status: "error",
          });
          throw new Error("MakePay webhook subscription setup failed.");
        }
      },
      30,
    );
  }

  async disconnectOAuth(): Promise<MakePayConnectionView> {
    await this.assertProviderConfigurationRegistered();
    if (this.authMode !== "oauth") {
      throw new Error(
        "MakePay OAuth disconnect is unavailable in API-key mode.",
      );
    }
    return this.withDistributedLock(
      `makepay-oauth-lifecycle:${this.providerId}`,
      () => this.disconnectOAuthWithinLifecycleLock(),
      30,
    );
  }

  private async oauthStatesForProvider(): Promise<RecordShape[]> {
    const states: RecordShape[] = [];
    for (let skip = 0; ; skip += OAUTH_REGISTRATION_RECOVERY_PAGE_SIZE) {
      const page = await this.generated().listMakePayOAuthStates(
        { provider_id: this.providerId },
        {
          order: { created_at: "ASC", id: "ASC" },
          skip,
          take: OAUTH_REGISTRATION_RECOVERY_PAGE_SIZE,
        },
      );
      states.push(...page);
      if (page.length < OAUTH_REGISTRATION_RECOVERY_PAGE_SIZE) break;
    }
    return states;
  }

  private async invalidateOAuthStatesForProvider(): Promise<void> {
    const oauthStates = await this.oauthStatesForProvider();
    const invalidatedAt = new Date();
    for (const state of oauthStates) {
      await this.generated().updateMakePayOAuthStates({
        consumed_at: state.consumed_at ?? invalidatedAt,
        encrypted_authorization_code: null,
        id: String(state.id),
        token_exchange_id: null,
      });
    }
  }

  private async deleteOAuthStatesForProvider(): Promise<void> {
    const oauthStates = await this.oauthStatesForProvider();
    for (
      let offset = 0;
      offset < oauthStates.length;
      offset += OAUTH_REGISTRATION_RECOVERY_PAGE_SIZE
    ) {
      await this.generated().deleteMakePayOAuthStates(
        oauthStates
          .slice(offset, offset + OAUTH_REGISTRATION_RECOVERY_PAGE_SIZE)
          .map((state) => String(state.id)),
      );
    }
  }

  private async disconnectOAuthWithinLifecycleLock(): Promise<MakePayConnectionView> {
    // Reject every outstanding callback immediately, but retain its staged
    // DPoP key until the remote installation reset succeeds. Consent can
    // promote a staged key before the callback returns, so deleting this
    // recovery history early can make a retrying disconnect non-revocable.
    await this.invalidateOAuthStatesForProvider();
    const connection = await this.connectionRecord();
    if (!connection) {
      await this.deleteOAuthStatesForProvider();
      return this.getConnectionView();
    }
    if (
      connection.status === "disconnected" &&
      !connection.encrypted_access_token
    ) {
      await this.deleteOAuthStatesForProvider();
      return this.getConnectionView();
    }
    const disconnectIntent = await this.withDistributedLock(
      `makepay-oauth-connection:${String(connection.id)}`,
      async () => {
        const current = await this.connectionRecord();
        if (!current || current.id !== connection.id) {
          throw new Error(
            "MakePay OAuth connection changed during disconnect.",
          );
        }
        await this.preserveCurrentWebhookCredential(current, "active");
        const metadata = isRecord(current.metadata) ? current.metadata : {};
        const disconnectMutationId =
          getText(metadata.disconnect_webhook_mutation_id) ??
          randomOpaqueToken();
        const nativeResetMutationId =
          getText(metadata.disconnect_native_reset_mutation_id) ??
          randomOpaqueToken(32);
        const wasDisconnectPending = current.status === "disconnect_pending";
        await this.generated().updateMakePayConnections({
          id: current.id,
          last_error: null,
          metadata: {
            ...metadata,
            disconnect_native_reset_mutation_id: nativeResetMutationId,
            disconnect_webhook_mutation_id: disconnectMutationId,
          },
          status: "disconnect_pending",
        });
        return {
          disconnectMutationId,
          nativeResetIdempotencyKey: `medusa-native-reset-${sha256(
            `${String(current.id)}:${nativeResetMutationId}`,
          ).slice(0, 40)}`,
          wasDisconnectPending,
        };
      },
      30,
    );
    const {
      disconnectMutationId,
      nativeResetIdempotencyKey,
      wasDisconnectPending,
    } = disconnectIntent;

    try {
      let preparedConnection = await this.connectionRecord();
      if (!preparedConnection || preparedConnection.id !== connection.id) {
        throw new Error("MakePay OAuth connection changed during disconnect.");
      }
      if (this.pendingWebhookRotation(preparedConnection)) {
        preparedConnection =
          await this.recoverPendingWebhookRotation(preparedConnection);
      }
      await this.withDistributedLock(
        `makepay-oauth-connection:${String(connection.id)}`,
        async () => {
          const current = await this.connectionRecord();
          if (!current || current.id !== connection.id) {
            throw new Error(
              "MakePay OAuth connection changed during disconnect.",
            );
          }
          const clientId = getText(current.client_id);
          if (!clientId) {
            throw new Error("MakePay OAuth connection client ID is missing.");
          }
          let stableCurrent = current;
          if (this.pendingWebhookRotation(stableCurrent)) {
            throw new Error(
              "MakePay webhook rotation changed during disconnect.",
            );
          }
          const expectedSubscriptionId = getText(
            stableCurrent.webhook_subscription_id,
          );
          const knownCredentials =
            await this.generated().listMakePayWebhookSubscriptions(
              {
                installation_id: getText(stableCurrent.installation_id),
                provider_id: this.providerId,
              },
              { take: 1000 },
            );
          const expectedPreservedIds = [
            ...new Set(
              [
                ...knownCredentials.map((credential) =>
                  getText(credential.subscription_id),
                ),
                expectedSubscriptionId,
              ].filter((value): value is string => Boolean(value)),
            ),
          ].sort();
          if (!wasDisconnectPending && expectedSubscriptionId) {
            const expiresAt = asDate(stableCurrent.access_token_expires_at);
            if (!expiresAt || expiresAt.getTime() <= Date.now() + 30_000) {
              await this.performRefresh(String(stableCurrent.id));
              stableCurrent = (await this.connectionRecord()) ?? stableCurrent;
            }
            const client = await this.createClient({
              allowRefreshRetry: false,
              allowUnreadyOAuth: true,
              refreshIfExpiring: false,
            });
            const disabled = await (
              client as unknown as {
                deleteCurrentWebhookSubscription(options: {
                  idempotencyKey: string;
                }): Promise<RecordShape>;
              }
            ).deleteCurrentWebhookSubscription({
              idempotencyKey: `medusa-webhook-disconnect-${sha256(
                `${String(stableCurrent.id)}:${disconnectMutationId}`,
              ).slice(0, 40)}`,
            });
            const disabledSubscription = isRecord(disabled.subscription)
              ? disabled.subscription
              : undefined;
            if (
              disabled.historicalDeliveryPreserved !== true ||
              disabled.signingSecretChanged !== false ||
              getText(disabledSubscription?.id) !== expectedSubscriptionId ||
              getText(disabledSubscription?.status) !== "disabled"
            ) {
              throw new Error(
                "MakePay webhook disable did not preserve historical delivery.",
              );
            }
            await this.preserveCurrentWebhookCredential(
              stableCurrent,
              "historical",
            );
          }
          if (!wasDisconnectPending && !expectedSubscriptionId) {
            const expiresAt = asDate(stableCurrent.access_token_expires_at);
            if (!expiresAt || expiresAt.getTime() <= Date.now() + 30_000) {
              await this.performRefresh(String(stableCurrent.id));
              stableCurrent = (await this.connectionRecord()) ?? stableCurrent;
            }
          }
          const discovery = await this.discoverOAuth();
          const resetUrl = new URL(discovery.nativeInstallationEndpoint);
          resetUrl.searchParams.set("client_id", clientId);
          const requestReset = async () => {
            const credentials = await this.oauthCredentials(false, false);
            return this.fetch_(resetUrl, {
              headers: {
                accept: "application/json",
                authorization: `DPoP ${credentials.accessToken}`,
                dpop: createDpopProof({
                  accessToken: credentials.accessToken,
                  method: "DELETE",
                  privateKey: credentials.privateKey,
                  url: resetUrl.toString(),
                }),
                "idempotency-key": nativeResetIdempotencyKey,
              },
              method: "DELETE",
              redirect: "manual",
            });
          };
          let resetResponse: Response;
          try {
            resetResponse = await requestReset();
          } catch {
            resetResponse = await requestReset();
          }
          if (resetResponse.status >= 500) {
            resetResponse = await requestReset();
          }
          if (wasDisconnectPending && resetResponse.status === 401) {
            // A receipt replay is checked by MakeCrypto before access-token
            // revocation. A 401 therefore means no matching receipt was found;
            // refresh and retry the same mutation rather than inferring reset.
            await this.performRefresh(String(stableCurrent.id));
            stableCurrent = (await this.connectionRecord()) ?? stableCurrent;
            resetResponse = await requestReset();
          }
          const resetBody = (await resetResponse
            .json()
            .catch(() => ({}))) as RecordShape;
          const preservedIds = Array.isArray(
            resetBody.preservedWebhookSubscriptionIds,
          )
            ? resetBody.preservedWebhookSubscriptionIds.filter(
                (value): value is string => typeof value === "string",
              )
            : [];
          const serverResetMutationId = getText(resetBody.resetMutationId);
          const stableMetadata = isRecord(stableCurrent.metadata)
            ? stableCurrent.metadata
            : {};
          const priorServerResetMutationId = getText(
            stableMetadata.disconnect_native_reset_receipt_id,
          );
          preservedIds.sort();
          if (
            !resetResponse.ok ||
            getText(resetBody.client_id) !== clientId ||
            resetBody.reset !== true ||
            resetBody.historicalDeliveryPreserved !== true ||
            resetBody.signingSecretChanged !== false ||
            !serverResetMutationId ||
            !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
              serverResetMutationId,
            ) ||
            (priorServerResetMutationId !== undefined &&
              priorServerResetMutationId !== serverResetMutationId) ||
            preservedIds.length !== expectedPreservedIds.length ||
            preservedIds.some(
              (value, index) => value !== expectedPreservedIds[index],
            )
          ) {
            throw new Error(
              `MakePay installation reset failed (HTTP ${resetResponse.status}).`,
            );
          }
          if (expectedSubscriptionId) {
            await this.preserveCurrentWebhookCredential(
              stableCurrent,
              "historical",
            );
          }
          await this.generated().updateMakePayConnections({
            id: stableCurrent.id,
            metadata: {
              ...stableMetadata,
              disconnect_native_reset_receipt_id: serverResetMutationId,
            },
          });
        },
      );
    } catch (error) {
      let reconnectRequired = false;
      try {
        const failedConnection = await this.connectionRecord();
        const failedMetadata = isRecord(failedConnection?.metadata)
          ? failedConnection.metadata
          : {};
        const failedRefreshAttempt = isRecord(
          failedMetadata.refresh_attempt,
        )
          ? failedMetadata.refresh_attempt
          : undefined;
        reconnectRequired =
          getText(failedRefreshAttempt?.failure) ===
            OAUTH_REFRESH_FAILURE_TERMINAL ||
          failedRefreshAttempt?.recovery_expired === true;
      } catch {
        // Preserve the retryable disconnect intent even if its diagnostic
        // reread is temporarily unavailable.
      }
      await this.generated().updateMakePayConnections({
        id: connection.id,
        last_error: reconnectRequired
          ? "MakePay OAuth authorization is no longer refreshable. Reconnect MakePay to replace it."
          : error instanceof Error && /HTTP \d+/.test(error.message)
            ? error.message
            : "MakePay installation reset could not be completed.",
        status: "disconnect_pending",
      });
      return this.getConnectionView();
    }

    await this.withDistributedLock(
      `makepay-oauth-connection:${String(connection.id)}`,
      async () => {
        const completedConnection = await this.connectionRecord();
        if (!completedConnection || completedConnection.id !== connection.id) {
          throw new Error(
            "MakePay OAuth connection changed after installation reset.",
          );
        }
        const completedMetadata = isRecord(completedConnection.metadata)
          ? completedConnection.metadata
          : {};
        const {
          disconnect_native_reset_mutation_id: _completedNativeReset,
          disconnect_native_reset_receipt_id: _completedResetReceipt,
          disconnect_webhook_mutation_id: _completedWebhookDisconnect,
          refresh_attempt: _completedRefresh,
          ...retainedMetadata
        } = completedMetadata;
        void _completedNativeReset;
        void _completedResetReceipt;
        void _completedWebhookDisconnect;
        void _completedRefresh;
        await this.generated().updateMakePayConnections({
          access_token_expires_at: null,
          encrypted_access_token: null,
          encrypted_dpop_private_key: null,
          encrypted_refresh_token: null,
          encrypted_webhook_secret: null,
          id: connection.id,
          last_error: null,
          metadata: {
            ...retainedMetadata,
            disconnect_native_reset_mutation_id: null,
            disconnect_native_reset_receipt_id: null,
            disconnect_webhook_mutation_id: null,
            oauth_token_recovery_expired: null,
            refresh_attempt: null,
            webhook_rotation: null,
          },
          status: "disconnected",
          webhook_last_error: null,
          webhook_subscription_id: null,
          webhook_status: "missing",
        });
      },
      30,
    );
    await this.deleteOAuthStatesForProvider();
    return this.getConnectionView();
  }

  private async oauthCredentials(
    refreshIfExpiring = true,
    requireReady = true,
  ): Promise<OAuthCredentials> {
    const config = this.oauthConfig();
    let connection = await this.connectionRecord();
    if (
      !connection ||
      !connection.encrypted_access_token ||
      !connection.encrypted_dpop_private_key
    ) {
      throw new Error(
        "MakePay OAuth is not connected. Connect it in Medusa Admin settings.",
      );
    }
    const connectionId = String(connection.id);
    if (requireReady && this.canRecoverRetryableOAuthRefresh(connection)) {
      await this.refreshOAuth(connectionId, true);
      const recovered = await this.connectionRecord();
      if (
        !recovered ||
        String(recovered.id) !== connectionId ||
        !recovered.encrypted_access_token ||
        !recovered.encrypted_dpop_private_key
      ) {
        throw new Error(
          "MakePay OAuth connection changed during refresh recovery.",
        );
      }
      connection = recovered;
    }
    if (
      requireReady &&
      (connection.status !== "connected" ||
        connection.webhook_status !== "healthy" ||
        !this.webhookCallbackMatchesConfiguration(connection) ||
        !connection.encrypted_webhook_secret ||
        !getText(connection.webhook_subscription_id))
    ) {
      throw new Error(
        "MakePay OAuth checkout is unavailable until its webhook subscription is healthy.",
      );
    }
    const expiresAt = asDate(connection.access_token_expires_at);
    if (!expiresAt) {
      throw new Error("MakePay OAuth token expiry is missing.");
    }
    if (refreshIfExpiring && expiresAt.getTime() <= Date.now() + 30_000) {
      await this.refreshOAuth(connectionId);
      connection = (await this.connectionRecord())!;
    }

    return {
      accessToken: decryptSecret(
        String(connection.encrypted_access_token),
        config.encryptionKey,
        `connection:${connectionId}:access-token`,
      ),
      connection,
      expiresAt: asDate(connection.access_token_expires_at)!,
      privateKey: decryptSecret(
        String(connection.encrypted_dpop_private_key),
        config.encryptionKey,
        `connection:${connectionId}:dpop`,
      ),
      refreshToken: connection.encrypted_refresh_token
        ? decryptSecret(
            String(connection.encrypted_refresh_token),
            config.encryptionKey,
            `connection:${connectionId}:refresh-token`,
          )
        : undefined,
    };
  }

  private lockingService(): ILockingModule | undefined {
    const loaded = MedusaModule.getModuleInstance(Modules.LOCKING) as
      | Record<string, unknown>
      | ILockingModule
      | undefined;
    if (!loaded) return undefined;
    return ((loaded as Record<string, unknown>)[Modules.LOCKING] ??
      loaded) as ILockingModule;
  }

  private async refreshOAuth(
    connectionId: string,
    force = false,
  ): Promise<void> {
    const inFlight = refreshPromises.get(connectionId);
    if (inFlight) return inFlight;
    const refresh = this.withDistributedLock(
      `makepay-oauth-connection:${connectionId}`,
      async () => {
        const current = await this.connectionRecord();
        const expiresAt = asDate(current?.access_token_expires_at);
        if (!force && expiresAt && expiresAt.getTime() > Date.now() + 30_000) {
          return;
        }
        await this.performRefresh(connectionId);
      },
    ).finally(() => {
      refreshPromises.delete(connectionId);
    });
    refreshPromises.set(connectionId, refresh);
    return refresh;
  }

  private connectionRefreshDpopKeyCandidate(
    credentials: OAuthCredentials,
  ): OAuthDpopKeyCandidate {
    const connectionMetadata = isRecord(credentials.connection.metadata)
      ? credentials.connection.metadata
      : {};
    const expectedConnectionThumbprint = getText(
      connectionMetadata.dpop_thumbprint,
    );
    const actualConnectionThumbprint = dpopThumbprintFromPrivateKey(
      credentials.privateKey,
    );
    if (
      !expectedConnectionThumbprint ||
      expectedConnectionThumbprint !== actualConnectionThumbprint
    ) {
      throw new Error("MakePay OAuth connection DPoP key is invalid.");
    }

    return {
      privateKey: credentials.privateKey,
      thumbprint: actualConnectionThumbprint,
    };
  }

  private async stagedRefreshDpopKeyCandidates(
    credentials: OAuthCredentials,
    connectionCandidate: OAuthDpopKeyCandidate,
  ): Promise<OAuthDpopKeyCandidate[]> {
    const config = this.oauthConfig();
    const connectionId = getText(credentials.connection.id);
    const connectionClientId = getText(credentials.connection.client_id);
    const encryptedConnectionRegistrationId = getText(
      credentials.connection.encrypted_registration_id,
    );
    if (
      !connectionId ||
      !connectionClientId ||
      !config.callbackUrl ||
      !encryptedConnectionRegistrationId
    ) {
      throw new Error(
        "MakePay OAuth connection registration identity is invalid.",
      );
    }
    const connectionRegistrationId = decryptSecret(
      encryptedConnectionRegistrationId,
      config.encryptionKey,
      `connection:${connectionId}:registration-id`,
    );
    const connectionRegistrationIdBytes = Buffer.from(
      connectionRegistrationId,
      "utf8",
    );
    const candidates: OAuthDpopKeyCandidate[] = [];
    const seenThumbprints = new Set<string>([
      connectionCandidate.thumbprint,
    ]);
    const addCandidate = (candidate: OAuthDpopKeyCandidate) => {
      if (seenThumbprints.has(candidate.thumbprint)) return;
      seenThumbprints.add(candidate.thumbprint);
      candidates.push(candidate);
    };

    // Native consent can promote a newly registered installation key before
    // the browser callback reaches Medusa. Bind retained rows to the current
    // immutable client, callback, and sealed registration identity before
    // using their keys. Keep eligible recovery keys newest-first; this method
    // is called only after the issuer explicitly rejects the durable
    // connection key's DPoP binding.
    const states = (await this.oauthStatesForProvider()).reverse();
    for (const state of states) {
      const stateId = getText(state.id);
      const expectedThumbprint = getText(state.dpop_thumbprint);
      const encryptedPrivateKey = getText(
        state.encrypted_dpop_private_key,
      );
      const encryptedRegistrationId = getText(
        state.encrypted_registration_id,
      );
      if (
        !stateId ||
        getText(state.client_id) !== connectionClientId ||
        getText(state.redirect_uri) !== config.callbackUrl ||
        !expectedThumbprint ||
        !encryptedPrivateKey ||
        !encryptedRegistrationId
      ) {
        continue;
      }

      try {
        const registrationId = decryptSecret(
          encryptedRegistrationId,
          config.encryptionKey,
          `oauth-state:${stateId}:registration-id`,
        );
        const registrationIdBytes = Buffer.from(registrationId, "utf8");
        if (
          registrationIdBytes.length !==
            connectionRegistrationIdBytes.length ||
          !timingSafeEqual(
            registrationIdBytes,
            connectionRegistrationIdBytes,
          )
        ) {
          continue;
        }
        const privateKey = decryptSecret(
          encryptedPrivateKey,
          config.encryptionKey,
          `oauth-state:${stateId}:dpop`,
        );
        const actualThumbprint = dpopThumbprintFromPrivateKey(privateKey);
        if (actualThumbprint !== expectedThumbprint) continue;
        addCandidate({ privateKey, thumbprint: actualThumbprint });
      } catch {
        // A corrupt historical recovery row must never replace the verified
        // connection key or prevent trying another independently sealed row.
      }
    }

    return candidates;
  }

  private async performRefresh(
    connectionId: string,
    replayRecoveryDepth = 0,
  ): Promise<void> {
    const config = this.oauthConfig();
    const discovery = await this.discoverOAuth();
    const credentials = await this.oauthCredentials(false, false);
    if (
      !credentials.refreshToken ||
      !getText(credentials.connection.client_id)
    ) {
      throw new Error("MakePay OAuth refresh token is missing.");
    }
    const refreshFingerprint = sha256(credentials.refreshToken);
    const connectionMetadata = isRecord(credentials.connection.metadata)
      ? credentials.connection.metadata
      : {};
    const pendingRefresh = isRecord(connectionMetadata.refresh_attempt)
      ? connectionMetadata.refresh_attempt
      : undefined;
    if (pendingRefresh?.recovery_expired === true) {
      const terminalFingerprint = getText(
        pendingRefresh.credential_fingerprint,
      );
      const terminalIdempotencyKey = getText(pendingRefresh.idempotency_key);
      if (
        terminalFingerprint !== refreshFingerprint ||
        !terminalIdempotencyKey ||
        !/^medusa-token-[A-Za-z0-9_-]{43}$/.test(terminalIdempotencyKey)
      ) {
        throw new Error(
          "MakePay OAuth terminal refresh recovery metadata is invalid.",
        );
      }
      throw new OAuthTokenRecoveryExpiredError();
    }
    if (getText(pendingRefresh?.failure) === OAUTH_REFRESH_FAILURE_TERMINAL) {
      throw new Error(
        "MakePay OAuth authorization is no longer refreshable. Reconnect MakePay.",
      );
    }
    let refreshIdempotencyKey = getText(pendingRefresh?.idempotency_key);
    if (
      getText(pendingRefresh?.credential_fingerprint) !== refreshFingerprint ||
      !refreshIdempotencyKey ||
      !/^medusa-token-[A-Za-z0-9_-]{43}$/.test(refreshIdempotencyKey)
    ) {
      refreshIdempotencyKey = `medusa-token-${randomOpaqueToken(32)}`;
      await this.generated().updateMakePayConnections({
        id: connectionId,
        metadata: {
          ...connectionMetadata,
          refresh_attempt: {
            credential_fingerprint: refreshFingerprint,
            idempotency_key: refreshIdempotencyKey,
          },
        },
      });
    }
    const tokenUrl = discovery.tokenEndpoint;
    const refreshAttempt = (
      failure?:
        | typeof OAUTH_REFRESH_FAILURE_RETRYABLE
        | typeof OAUTH_REFRESH_FAILURE_TERMINAL,
    ): RecordShape => ({
      credential_fingerprint: refreshFingerprint,
      idempotency_key: refreshIdempotencyKey,
      ...(failure ? { failure } : {}),
    });
    const retryableRefreshLastError =
      credentials.connection.status === "connected" ||
      getText(credentials.connection.last_error) === OAUTH_REFRESH_ERROR
        ? OAUTH_REFRESH_ERROR
        : (getText(credentials.connection.last_error) ?? OAUTH_REFRESH_ERROR);
    const connectionDpopCandidate =
      this.connectionRefreshDpopKeyCandidate(credentials);
    const dpopCandidates = [connectionDpopCandidate];
    let stagedCandidatesLoaded = false;
    const loadStagedCandidates = async () => {
      if (stagedCandidatesLoaded) return;
      stagedCandidatesLoaded = true;
      try {
        dpopCandidates.push(
          ...(await this.stagedRefreshDpopKeyCandidates(
            credentials,
            connectionDpopCandidate,
          )),
        );
      } catch {
        await this.generated().updateMakePayConnections({
          id: connectionId,
          last_error: retryableRefreshLastError,
          metadata: {
            ...connectionMetadata,
            refresh_attempt: refreshAttempt(OAUTH_REFRESH_FAILURE_RETRYABLE),
          },
        });
        throw new Error(
          "MakePay OAuth staged-key recovery is temporarily unavailable.",
        );
      }
    };
    let response: Response | undefined;
    let responseBodyUnreadable = false;
    let body: RecordShape = {};
    let selectedDpopCandidate: OAuthDpopKeyCandidate | undefined;
    for (const [index, candidate] of dpopCandidates.entries()) {
      try {
        response = await this.fetch_(tokenUrl, {
          body: new URLSearchParams({
            client_id: String(credentials.connection.client_id),
            grant_type: "refresh_token",
            refresh_token: credentials.refreshToken,
            resource: config.audience,
          }),
          headers: {
            accept: "application/json",
            "content-type": "application/x-www-form-urlencoded",
            dpop: createDpopProof({
              privateKey: candidate.privateKey,
              method: "POST",
              url: tokenUrl,
            }),
            "idempotency-key": refreshIdempotencyKey,
          },
          method: "POST",
          redirect: "manual",
        });
      } catch (error) {
        await this.generated().updateMakePayConnections({
          id: connectionId,
          last_error: retryableRefreshLastError,
          metadata: {
            ...connectionMetadata,
            refresh_attempt: refreshAttempt(OAUTH_REFRESH_FAILURE_RETRYABLE),
          },
        });
        throw error;
      }

      responseBodyUnreadable = false;
      body = {};
      try {
        const parsedBody: unknown = await response.json();
        if (!isRecord(parsedBody)) {
          responseBodyUnreadable = true;
        } else {
          body = parsedBody;
        }
      } catch {
        responseBodyUnreadable = true;
      }

      if (
        isDpopBindingMismatchResponse(response, body)
      ) {
        await loadStagedCandidates();
        if (index < dpopCandidates.length - 1) continue;
      }
      selectedDpopCandidate = candidate;
      break;
    }
    if (!response || !selectedDpopCandidate) {
      throw new Error("MakePay OAuth refresh has no usable DPoP key.");
    }
    const responseIsReplay =
      response.headers.get("idempotent-replayed") === "true";
    const accessToken = getText(body.access_token);
    if (responseIsReplay && accessToken) {
      const replayClaims = decodeJwtPayload(accessToken);
      const replayCnf = isRecord(replayClaims.cnf)
        ? replayClaims.cnf
        : undefined;
      const replayDpopThumbprint = getText(replayCnf?.jkt);
      if (
        replayDpopThumbprint &&
        replayDpopThumbprint !== selectedDpopCandidate.thumbprint
      ) {
        await loadStagedCandidates();
        const replayCandidate = dpopCandidates.find(
          (candidate) => candidate.thumbprint === replayDpopThumbprint,
        );
        if (replayCandidate) selectedDpopCandidate = replayCandidate;
      }
    }
    const expiresIn = Number(body.expires_in);
    const rotatedRefreshToken = getText(body.refresh_token);
    const recoveryExpired =
      response.status === 400 &&
      getText(body.error) === "invalid_grant" &&
      response.headers.get("oauth-token-recovery")?.toLowerCase() === "expired";
    const explicitOAuthError = getText(body.error);
    const retryableFailure =
      !recoveryExpired &&
      ((response.ok && (responseBodyUnreadable || !explicitOAuthError)) ||
        isRetryableOAuthRefreshResponse(response, body));
    const returnedScopes = getText(body.scope)?.split(/\s+/).filter(Boolean);
    const invalidReturnedScopes =
      returnedScopes &&
      (MAKEPAY_OAUTH_SCOPES.some((scope) => !returnedScopes.includes(scope)) ||
        returnedScopes.some(
          (scope) => !MAKEPAY_OAUTH_SCOPES.includes(scope as never),
        ));
    if (
      !response.ok ||
      !accessToken ||
      getText(body.token_type)?.toLowerCase() !== "dpop" ||
      !rotatedRefreshToken ||
      rotatedRefreshToken === credentials.refreshToken ||
      !Number.isFinite(expiresIn) ||
      expiresIn <= 0 ||
      invalidReturnedScopes
    ) {
      await this.generated().updateMakePayConnections({
        id: connectionId,
        last_error: recoveryExpired
          ? "MakePay OAuth durable refresh recovery receipt is unavailable. Reconnect MakePay."
          : retryableFailure
            ? retryableRefreshLastError
            : responseError(body, OAUTH_REFRESH_ERROR),
        metadata: {
          ...connectionMetadata,
          refresh_attempt: {
            ...refreshAttempt(
              retryableFailure
                ? OAUTH_REFRESH_FAILURE_RETRYABLE
                : OAUTH_REFRESH_FAILURE_TERMINAL,
            ),
            ...(recoveryExpired ? { recovery_expired: true } : {}),
          },
        },
        ...(retryableFailure ? {} : { status: "error" }),
      });
      if (recoveryExpired) throw new OAuthTokenRecoveryExpiredError();
      throw new Error(responseError(body, OAUTH_REFRESH_ERROR));
    }
    const current = await this.connectionRecord();
    if (!current || current.id !== connectionId) {
      throw new Error("MakePay OAuth connection changed during refresh.");
    }
    const currentRefresh = current.encrypted_refresh_token
      ? decryptSecret(
          String(current.encrypted_refresh_token),
          config.encryptionKey,
          `connection:${connectionId}:refresh-token`,
        )
      : undefined;
    if (currentRefresh !== credentials.refreshToken) {
      return;
    }
    const currentMetadata = isRecord(current.metadata) ? current.metadata : {};
    const currentRefreshAttempt = isRecord(currentMetadata.refresh_attempt)
      ? currentMetadata.refresh_attempt
      : undefined;
    if (
      getText(currentRefreshAttempt?.idempotency_key) !==
        refreshIdempotencyKey ||
      getText(currentRefreshAttempt?.credential_fingerprint) !==
        refreshFingerprint
    ) {
      throw new Error("MakePay OAuth refresh attempt changed unexpectedly.");
    }
    const refreshedClaims = await verifyOAuthAccessToken({
      allowExpiredForIdempotentReplay: responseIsReplay,
      audience: config.audience,
      expectedClientId: String(current.client_id),
      expectedDpopThumbprint: selectedDpopCandidate.thumbprint,
      expectedScopes: MAKEPAY_OAUTH_SCOPES,
      fetchImpl: this.fetch_,
      issuer: config.issuer,
      jwksUri: discovery.jwksUri,
      token: accessToken,
    });
    if (
      getText(refreshedClaims.company_id) !== getText(current.company_id) ||
      getText(refreshedClaims.grant_id) !== getText(current.grant_id) ||
      getText(refreshedClaims.installation_id) !==
        getText(current.installation_id)
    ) {
      await this.generated().updateMakePayConnections({
        id: connectionId,
        last_error: "MakePay OAuth refresh returned a different grant.",
        metadata: {
          ...currentMetadata,
          refresh_attempt: refreshAttempt(OAUTH_REFRESH_FAILURE_TERMINAL),
        },
        status: "error",
      });
      throw new Error("MakePay OAuth refresh returned a different grant.");
    }
    const refreshedExpiryMs = Math.min(
      Date.now() + expiresIn * 1000,
      Number(refreshedClaims.exp) * 1000,
    );
    if (!Number.isFinite(refreshedExpiryMs)) {
      throw new Error(
        "MakePay OAuth refresh returned an expired access token.",
      );
    }
    const { refresh_attempt: _completedRefresh, ...nextMetadata } =
      currentMetadata;
    void _completedRefresh;
    const retryableRefreshRecovered =
      this.canRecoverRetryableOAuthRefresh(current);
    const clearRefreshError =
      current.last_error == null ||
      (getText(current.last_error) === OAUTH_REFRESH_ERROR &&
        getText(currentRefreshAttempt?.failure) !==
          OAUTH_REFRESH_FAILURE_TERMINAL);
    await this.generated().updateMakePayConnections({
      access_token_expires_at: new Date(refreshedExpiryMs),
      encrypted_access_token: encryptSecret(
        accessToken,
        config.encryptionKey,
        `connection:${connectionId}:access-token`,
      ),
      encrypted_dpop_private_key: encryptSecret(
        selectedDpopCandidate.privateKey,
        config.encryptionKey,
        `connection:${connectionId}:dpop`,
      ),
      encrypted_refresh_token: encryptSecret(
        rotatedRefreshToken,
        config.encryptionKey,
        `connection:${connectionId}:refresh-token`,
      ),
      id: connectionId,
      last_error: clearRefreshError ? null : current.last_error,
      metadata: {
        ...nextMetadata,
        dpop_thumbprint: selectedDpopCandidate.thumbprint,
        refresh_attempt: null,
      },
      status: retryableRefreshRecovered ? "connected" : current.status,
    });
    if (refreshedExpiryMs <= Date.now() + 30_000) {
      if (!responseIsReplay || replayRecoveryDepth >= 1) {
        throw new Error(
          "MakePay OAuth refresh returned an expired access token.",
        );
      }
      await this.performRefresh(connectionId, replayRecoveryDepth + 1);
    }
  }

  async createClient(
    options: {
      allowRefreshRetry?: boolean;
      allowUnreadyOAuth?: boolean;
      refreshIfExpiring?: boolean;
    } = {},
  ): Promise<MakePayClient> {
    await this.assertProviderConfigurationRegistered();
    if (this.authMode === "api_key") {
      const options = this.options_ as RecordShape;
      const keyId = getText(options.keyId);
      const keySecret = getText(options.keySecret);
      if (!keyId || !keySecret) {
        throw new Error("MakePay API key credentials are not configured.");
      }
      return new MakePayClient({
        baseUrl: getText(options.baseUrl),
        checkoutBaseUrl: getText(options.checkoutBaseUrl),
        fetch: this.fetch_,
        keyId,
        keySecret,
      });
    }

    const service = this;
    const oauth = this.oauthConfig();
    return new MakePayClient({
      // The OAuth provider contract is supplied by @makecrypto/makepay >=0.4.0.
      authProvider: {
        async getAuthorization(request: {
          method: string;
          retry: boolean;
          url: string;
        }) {
          const credentials = await service.oauthCredentials(
            options.refreshIfExpiring ?? true,
            !options.allowUnreadyOAuth,
          );
          return {
            accessToken: credentials.accessToken,
            dpopProof: createDpopProof({
              accessToken: credentials.accessToken,
              privateKey: credentials.privateKey,
              method: request.method,
              url: request.url,
            }),
            tokenType: "DPoP" as const,
          };
        },
        async refreshAuthorization() {
          if (options.allowRefreshRetry === false) {
            throw new Error(
              "MakePay OAuth refresh retry is unavailable inside a serialized connection transition.",
            );
          }
          const connection = await service.connectionRecord();
          if (!connection) throw new Error("MakePay OAuth is not connected.");
          await service.refreshOAuth(String(connection.id), true);
        },
      },
      baseUrl: oauth.apiBaseUrl,
      checkoutBaseUrl: getText((this.options_ as RecordShape).checkoutBaseUrl),
      fetch: this.fetch_,
    } as never);
  }

  async getWebhookSecret(rawBody?: Buffer | string): Promise<string> {
    await this.assertProviderConfigurationRegistered();
    if (this.authMode === "api_key") {
      const secret = getText((this.options_ as RecordShape).webhookSecret);
      if (!secret) throw new Error("MakePay webhook secret is not configured.");
      return secret;
    }
    const config = this.oauthConfig();
    const connection = await this.connectionRecord();
    if (rawBody !== undefined) {
      const serialized = Buffer.isBuffer(rawBody)
        ? rawBody.toString("utf8")
        : String(rawBody);
      if (!serialized || Buffer.byteLength(serialized, "utf8") > 64 * 1024) {
        throw new MakePayError("Invalid MakePay webhook.", { status: 400 });
      }
      let untrusted: RecordShape;
      try {
        const parsed = JSON.parse(serialized) as unknown;
        if (!isRecord(parsed)) throw new Error("invalid");
        untrusted = parsed;
      } catch {
        throw new MakePayError("Invalid MakePay webhook.", { status: 400 });
      }
      const paymentLink = getNestedRecord(untrusted, "paymentLink");
      // These values are not authenticated until after the credential lookup.
      // Bound them before allowing any value-derived database query.
      const uid = boundedWebhookRoutingId(paymentLink?.uid, 200);
      const companyId = boundedWebhookRoutingId(untrusted.companyId, 200);
      const grantId = boundedWebhookRoutingId(untrusted.grantId, 200);
      const installationId = boundedWebhookRoutingId(
        untrusted.installationId,
        200,
      );
      const subscriptionId = boundedWebhookRoutingId(
        untrusted.subscriptionId,
        200,
      );
      if (
        !uid ||
        !companyId ||
        !grantId ||
        !installationId ||
        !subscriptionId
      ) {
        throw new MakePayError("Invalid MakePay webhook.", { status: 400 });
      }
      const projection = await this.projectionByUid(uid);
      if (
        !projection ||
        projection.auth_mode !== "oauth" ||
        projection.provider_id !== this.providerId ||
        projection.company_id !== companyId ||
        projection.grant_id !== grantId ||
        projection.installation_id !== installationId ||
        projection.webhook_subscription_id !== subscriptionId
      ) {
        throw new MakePayError("Invalid MakePay webhook.", { status: 400 });
      }
      const credentials =
        await this.generated().listMakePayWebhookSubscriptions(
          { provider_id: this.providerId, subscription_id: subscriptionId },
          { take: 2 },
        );
      if (credentials.length > 1) {
        throw new MakePayError("Invalid MakePay webhook.", { status: 400 });
      }
      const credential = credentials[0];
      if (credential) {
        if (
          credential.company_id !== companyId ||
          credential.grant_id !== grantId ||
          credential.installation_id !== installationId ||
          !credential.encrypted_signing_secret
        ) {
          throw new MakePayError("Invalid MakePay webhook.", { status: 400 });
        }
        return decryptSecret(
          String(credential.encrypted_signing_secret),
          config.encryptionKey,
          `webhook-subscription:${String(credential.id)}:signing-secret`,
        );
      }
      // Upgrade compatibility: the first webhook after migration can still use
      // the current connection row before its credential is backfilled.
      if (
        connection?.company_id === companyId &&
        connection?.grant_id === grantId &&
        connection?.installation_id === installationId &&
        connection?.webhook_subscription_id === subscriptionId &&
        connection.encrypted_webhook_secret
      ) {
        return decryptSecret(
          String(connection.encrypted_webhook_secret),
          config.encryptionKey,
          `connection:${String(connection.id)}:webhook-secret`,
        );
      }
      throw new MakePayError("Invalid MakePay webhook.", { status: 400 });
    }
    if (
      connection?.status !== "connected" ||
      connection.webhook_status !== "healthy" ||
      !connection.encrypted_webhook_secret ||
      !getText(connection.webhook_subscription_id)
    ) {
      throw new Error("MakePay OAuth webhook subscription is not configured.");
    }
    return decryptSecret(
      String(connection.encrypted_webhook_secret),
      config.encryptionKey,
      `connection:${String(connection.id)}:webhook-secret`,
    );
  }

  private pendingWebhookRotation(connection: RecordShape):
    | {
        companyId: string;
        dpopThumbprint: string;
        endpointUrl: string;
        grantId: string;
        idempotencyKey: string;
        installationId: string;
        oauthAttemptId: string;
      }
    | undefined {
    const metadata = isRecord(connection.metadata) ? connection.metadata : {};
    const pending = isRecord(metadata.webhook_rotation)
      ? metadata.webhook_rotation
      : undefined;
    if (!pending) return undefined;
    const value = {
      companyId: getText(pending.company_id),
      dpopThumbprint: getText(pending.dpop_thumbprint),
      endpointUrl: getText(pending.endpoint_url),
      grantId: getText(pending.grant_id),
      idempotencyKey: getText(pending.idempotency_key),
      installationId: getText(pending.installation_id),
      oauthAttemptId: getText(pending.oauth_attempt_id),
    };
    if (
      !value.companyId ||
      !value.dpopThumbprint ||
      !value.endpointUrl ||
      !value.grantId ||
      !value.idempotencyKey ||
      !value.installationId ||
      !value.oauthAttemptId ||
      !/^medusa-webhook-[a-f0-9]{40}$/.test(value.idempotencyKey) ||
      value.idempotencyKey !==
        makePayWebhookRotationIdempotencyKey({
          dpopThumbprint: value.dpopThumbprint,
          grantId: value.grantId,
          installationId: value.installationId,
          oauthAttemptId: value.oauthAttemptId,
        }) ||
      value.companyId !== getText(connection.company_id) ||
      value.dpopThumbprint !== getText(metadata.dpop_thumbprint) ||
      value.grantId !== getText(connection.grant_id) ||
      value.installationId !== getText(connection.installation_id) ||
      value.endpointUrl !== getText(connection.webhook_url)
    ) {
      throw new Error("MakePay pending webhook rotation metadata is invalid.");
    }
    return value as {
      companyId: string;
      dpopThumbprint: string;
      endpointUrl: string;
      grantId: string;
      idempotencyKey: string;
      installationId: string;
      oauthAttemptId: string;
    };
  }

  private async recoverPendingWebhookRotation(
    connection: RecordShape,
    options: {
      allowRefreshRetry?: boolean;
      alreadyLocked?: boolean;
    } = {},
  ): Promise<RecordShape> {
    if (options.alreadyLocked) {
      return this.recoverPendingWebhookRotationLocked(connection, options);
    }
    const expiresAt = asDate(connection.access_token_expires_at);
    const metadata = isRecord(connection.metadata) ? connection.metadata : {};
    const refreshAttempt = isRecord(metadata.refresh_attempt)
      ? metadata.refresh_attempt
      : undefined;
    const terminalRefreshRecovery = refreshAttempt?.recovery_expired === true;
    if (
      terminalRefreshRecovery ||
      (expiresAt && expiresAt.getTime() <= Date.now() + 30_000)
    ) {
      await this.refreshOAuth(String(connection.id), terminalRefreshRecovery);
      connection = (await this.connectionRecord()) ?? connection;
    }
    return this.withDistributedLock(
      `makepay-oauth-connection:${String(connection.id)}`,
      async () => {
        const current = await this.connectionRecord();
        if (!current || current.id !== connection.id) {
          throw new Error(
            "MakePay OAuth connection changed during webhook recovery.",
          );
        }
        return this.recoverPendingWebhookRotationLocked(current, {
          allowRefreshRetry: false,
        });
      },
      30,
    );
  }

  private async recoverPendingWebhookRotationLocked(
    connection: RecordShape,
    options: { allowRefreshRetry?: boolean } = {},
  ): Promise<RecordShape> {
    const pending = this.pendingWebhookRotation(connection);
    if (!pending) return connection;
    const client = await this.createClient({
      allowRefreshRetry: options.allowRefreshRetry,
      allowUnreadyOAuth: true,
      refreshIfExpiring: false,
    });
    const subscription = await (
      client as unknown as {
        upsertCurrentWebhookSubscription(
          payload: RecordShape,
          options?: { idempotencyKey?: string },
        ): Promise<RecordShape>;
      }
    ).upsertCurrentWebhookSubscription(
      {
        active: true,
        description: "MakePay for Medusa",
        events: ["makepay.payment.*"],
        metadata: {
          installationId: pending.installationId,
          platform: "medusa",
          providerId: this.providerId,
        },
        rotateSecret: true,
        url: pending.endpointUrl,
      },
      { idempotencyKey: pending.idempotencyKey },
    );
    const signingSecret = getText(subscription.signingSecret);
    const subscriptionRecord = isRecord(subscription.subscription)
      ? subscription.subscription
      : undefined;
    const subscriptionId =
      getText(subscriptionRecord?.id) ?? getText(subscriptionRecord?.uid);
    if (!signingSecret || !subscriptionId) {
      throw new Error(
        "MakePay did not return the new webhook subscription identity and signing secret.",
      );
    }
    const current = await this.connectionRecord();
    const currentPending = current
      ? this.pendingWebhookRotation(current)
      : undefined;
    if (
      !current ||
      current.id !== connection.id ||
      currentPending?.idempotencyKey !== pending.idempotencyKey
    ) {
      throw new Error("MakePay OAuth connection changed during webhook setup.");
    }
    await this.persistWebhookSubscriptionCredential({
      companyId: pending.companyId,
      endpointUrl: pending.endpointUrl,
      grantId: pending.grantId,
      installationId: pending.installationId,
      signingSecret,
      status: "active",
      subscriptionId,
    });
    const metadata = isRecord(current.metadata) ? current.metadata : {};
    const { webhook_rotation: _completedRotation, ...nextMetadata } = metadata;
    void _completedRotation;
    return this.generated().updateMakePayConnections({
      encrypted_webhook_secret: encryptSecret(
        signingSecret,
        this.oauthConfig().encryptionKey,
        `connection:${String(current.id)}:webhook-secret`,
      ),
      id: current.id,
      last_error: null,
      metadata: {
        ...nextMetadata,
        webhook_rotation: null,
      },
      status:
        current.status === "disconnect_pending"
          ? "disconnect_pending"
          : "connected",
      webhook_last_error: null,
      webhook_status: "healthy",
      webhook_subscription_id: subscriptionId,
    });
  }

  private async persistWebhookSubscriptionCredential(input: {
    companyId: string;
    endpointUrl: string;
    grantId: string;
    installationId: string;
    signingSecret: string;
    status: "active" | "historical";
    subscriptionId: string;
  }): Promise<RecordShape> {
    const config = this.oauthConfig();
    const generated = this.generated();
    const [existing] = await generated.listMakePayWebhookSubscriptions(
      {
        provider_id: this.providerId,
        subscription_id: input.subscriptionId,
      },
      { take: 1 },
    );
    const id = String(
      existing?.id ?? `mpwsub_${randomUUID().replace(/-/g, "")}`,
    );
    if (
      existing &&
      (existing.company_id !== input.companyId ||
        existing.grant_id !== input.grantId ||
        existing.installation_id !== input.installationId)
    ) {
      throw new Error(
        "MakePay webhook subscription identity cannot change routing ownership.",
      );
    }
    if (input.status === "active") {
      const active = await generated.listMakePayWebhookSubscriptions(
        { provider_id: this.providerId, status: "active" },
        { take: 100 },
      );
      for (const credential of active) {
        if (credential.id !== id) {
          await generated.updateMakePayWebhookSubscriptions({
            id: credential.id,
            rotated_at: new Date(),
            status: "historical",
          });
        }
      }
    }
    const data: RecordShape = {
      company_id: input.companyId,
      encrypted_signing_secret: encryptSecret(
        input.signingSecret,
        config.encryptionKey,
        `webhook-subscription:${id}:signing-secret`,
      ),
      endpoint_url: input.endpointUrl,
      grant_id: input.grantId,
      id,
      installation_id: input.installationId,
      metadata: {},
      provider_id: this.providerId,
      rotated_at: existing ? new Date() : null,
      status: input.status,
      subscription_id: input.subscriptionId,
    };
    return existing
      ? generated.updateMakePayWebhookSubscriptions(data)
      : generated.createMakePayWebhookSubscriptions(data);
  }

  private async preserveCurrentWebhookCredential(
    connection: RecordShape,
    status: "active" | "historical",
  ): Promise<void> {
    const config = this.oauthConfig();
    const subscriptionId = getText(connection.webhook_subscription_id);
    const companyId = getText(connection.company_id);
    const grantId = getText(connection.grant_id);
    const installationId = getText(connection.installation_id);
    const endpointUrl = getText(connection.webhook_url);
    if (
      !subscriptionId ||
      !companyId ||
      !grantId ||
      !installationId ||
      !endpointUrl ||
      !connection.encrypted_webhook_secret
    ) {
      return;
    }
    const signingSecret = decryptSecret(
      String(connection.encrypted_webhook_secret),
      config.encryptionKey,
      `connection:${String(connection.id)}:webhook-secret`,
    );
    await this.persistWebhookSubscriptionCredential({
      companyId,
      endpointUrl,
      grantId,
      installationId,
      signingSecret,
      status,
      subscriptionId,
    });
  }

  async getInstallationContext(): Promise<{
    companyId?: string;
    grantId?: string;
    installationId?: string;
    webhookSubscriptionId?: string;
  }> {
    const connection = await this.connectionRecord();
    return {
      companyId: getText(connection?.company_id),
      grantId: getText(connection?.grant_id),
      installationId: getText(connection?.installation_id),
      webhookSubscriptionId: getText(connection?.webhook_subscription_id),
    };
  }

  async withPaymentInitiationGuard<T>(job: () => Promise<T>): Promise<T> {
    await this.assertProviderConfigurationRegistered();
    if (this.authMode === "api_key" && !this.lockingProviderId(false)) {
      const [oauthHistory, oauthStateHistory, connection] = await Promise.all([
        this.generated().listMakePayPaymentProjections(
          { auth_mode: "oauth", provider_id: this.providerId },
          { take: 1 },
        ),
        this.generated().listMakePayOAuthStates(
          { provider_id: this.providerId },
          { take: 1 },
        ),
        this.connectionRecord(),
      ]);
      if (oauthHistory.length || oauthStateHistory.length || connection) {
        throw new Error(
          "MakePay API-key checkout requires distributed locking after OAuth has been configured.",
        );
      }
      await this.assertAuthModeTransitionAllowed();
      return job();
    }
    return this.withDistributedLock(
      `makepay-oauth-lifecycle:${this.providerId}`,
      async () => {
        await this.assertAuthModeTransitionAllowed();
        if (await this.hasLiveOAuthState()) {
          throw new Error(
            "MakePay checkout is paused while OAuth connection authorization is pending.",
          );
        }
        if (this.authMode === "oauth") {
          const connection = await this.connectionRecord();
          if (
            connection?.status !== "connected" ||
            connection.webhook_status !== "healthy" ||
            !this.webhookCallbackMatchesConfiguration(connection) ||
            !connection.encrypted_access_token ||
            !connection.encrypted_webhook_secret
          ) {
            throw new Error(
              "MakePay OAuth checkout requires a stable connected installation.",
            );
          }
        }
        return job();
      },
      30,
    );
  }

  async upsertProjection(input: RecordShape): Promise<RecordShape> {
    await this.assertProviderConfigurationRegistered();
    const sessionId = getText(input.session_id);
    const uid = getText(input.payment_link_uid);
    if (!sessionId || !uid) {
      throw new Error(
        "MakePay projection requires session and payment-link IDs.",
      );
    }
    if (input.auth_mode !== undefined && input.auth_mode !== this.authMode) {
      throw new Error(
        "MakePay provider and plugin module authentication modes do not match.",
      );
    }
    if (
      input.provider_id !== undefined &&
      input.provider_id !== this.providerId
    ) {
      throw new Error(
        "MakePay provider and plugin module provider IDs do not match.",
      );
    }
    const [[existingBySession], [existingByUid]] = await Promise.all([
      this.generated().listMakePayPaymentProjections(
        { session_id: sessionId },
        { take: 1 },
      ),
      this.generated().listMakePayPaymentProjections(
        { payment_link_uid: uid },
        { take: 1 },
      ),
    ]);
    if (
      existingBySession &&
      existingByUid &&
      existingBySession.id !== existingByUid.id
    ) {
      throw new Error(
        "MakePay payment-link and Medusa session projections conflict.",
      );
    }
    const existing = existingBySession ?? existingByUid;
    const connection =
      this.authMode === "oauth" ? await this.connectionRecord() : undefined;
    const data: RecordShape = {
      ...input,
      auth_mode: this.authMode,
      company_id: input.company_id ?? connection?.company_id ?? null,
      grant_id: input.grant_id ?? connection?.grant_id ?? null,
      installation_id:
        input.installation_id ?? connection?.installation_id ?? null,
      provider_id: this.providerId,
      webhook_subscription_id:
        input.webhook_subscription_id ??
        connection?.webhook_subscription_id ??
        null,
    };
    const routingFields = [
      getText(data.grant_id),
      getText(data.installation_id),
      getText(data.webhook_subscription_id),
    ];
    const dataAmount = data.amount;
    const dataCurrency = getText(data.currency);
    if (
      (typeof dataAmount !== "string" && typeof dataAmount !== "number") ||
      !dataCurrency ||
      (this.authMode === "oauth" &&
        (!getText(data.company_id) || routingFields.some((value) => !value))) ||
      (this.authMode === "api_key" &&
        routingFields.some((value) => Boolean(value)))
    ) {
      throw new Error(
        "MakePay projection routing ownership does not match its authentication mode.",
      );
    }
    if (existing) {
      const sameNullableText = (left: unknown, right: unknown) =>
        (getText(left) ?? null) === (getText(right) ?? null);
      if (
        existing.auth_mode !== this.authMode ||
        existing.provider_id !== this.providerId ||
        getText(existing.session_id) !== sessionId
      ) {
        throw new Error(
          "MakePay cannot replace a projection created by another authentication mode or provider.",
        );
      }
      if (getText(existing.payment_link_uid) !== uid) {
        throw new Error(
          "MakePay keeps one immutable payment-link UID per Medusa payment session. Create a new payment session.",
        );
      }
      if (
        !sameNullableText(existing.company_id, data.company_id) ||
        !sameNullableText(existing.grant_id, data.grant_id) ||
        !sameNullableText(existing.installation_id, data.installation_id) ||
        !sameNullableText(
          existing.webhook_subscription_id,
          data.webhook_subscription_id,
        ) ||
        !arePaymentAmountsEqual(String(existing.amount), dataAmount) ||
        String(existing.currency).toUpperCase() !==
          dataCurrency.toUpperCase() ||
        !sameNullableText(existing.return_state_hash, data.return_state_hash) ||
        (getText(data.order_id) !== undefined &&
          !sameNullableText(existing.order_id, data.order_id)) ||
        (getText(data.order_display_id) !== undefined &&
          !sameNullableText(
            existing.order_display_id,
            data.order_display_id,
          )) ||
        (getText(data.payment_id) !== undefined &&
          !sameNullableText(existing.payment_id, data.payment_id))
      ) {
        throw new Error(
          "MakePay cannot mutate an existing payment projection's routing or correlation identity.",
        );
      }
      // Terminal state, capture identity, order correlation, and routing have
      // dedicated locked transitions. An idempotent upsert therefore returns
      // the immutable row instead of widening this write surface.
      return existing;
    }
    return this.generated().createMakePayPaymentProjections(data);
  }

  async projectionByUid(uid: string): Promise<RecordShape | undefined> {
    const [payment] = await this.generated().listMakePayPaymentProjections(
      { payment_link_uid: uid },
      { take: 1 },
    );
    return payment;
  }

  async projectionBySession(
    sessionId: string,
  ): Promise<RecordShape | undefined> {
    const [payment] = await this.generated().listMakePayPaymentProjections(
      { session_id: sessionId },
      { take: 1 },
    );
    return payment;
  }

  async projectionByReturnState(
    state: string,
  ): Promise<RecordShape | undefined> {
    const [payment] = await this.generated().listMakePayPaymentProjections(
      { return_state_hash: sha256(state) },
      { take: 1 },
    );
    return payment;
  }

  toPaymentView(record: RecordShape): MakePayPaymentView {
    return {
      amount: String(record.amount ?? ""),
      auth_mode: record.auth_mode === "oauth" ? "oauth" : "api_key",
      company_id: getText(record.company_id),
      grant_id: getText(record.grant_id),
      created_at: iso(record.created_at) ?? new Date(0).toISOString(),
      currency: String(record.currency ?? ""),
      customer_email: getText(record.customer_email),
      dashboard_url: getText(record.dashboard_url),
      id: String(record.id),
      last_synced_at: iso(record.last_synced_at),
      medusa_status: getText(record.medusa_status),
      order_display_id: getText(record.order_display_id),
      order_id: getText(record.order_id),
      payment_id: getText(record.payment_id),
      payment_link_uid: String(record.payment_link_uid),
      provider_status: String(record.provider_status),
      public_url: getText(record.public_url),
      session_id: getText(record.session_id),
      updated_at: iso(record.updated_at) ?? new Date(0).toISOString(),
      webhook_subscription_id: getText(record.webhook_subscription_id),
    };
  }

  async listPaymentViews(input: {
    limit?: number;
    offset?: number;
    q?: string;
    status?: string;
  }): Promise<{
    payments: MakePayPaymentView[];
    count: number;
    limit: number;
    offset: number;
  }> {
    const limit = Math.min(Math.max(Number(input.limit) || 20, 1), 100);
    const offset = Math.max(Number(input.offset) || 0, 0);
    const status =
      input.status && input.status !== "all" ? input.status : undefined;
    const statusValues = status
      ? (STATUS_FILTERS[status] ?? [status])
      : undefined;
    const filters: RecordShape = statusValues
      ? { provider_status: { $in: statusValues } }
      : {};
    const query = input.q?.trim().slice(0, 100);
    if (query) {
      const pattern = `%${query.replace(/[%_\\]/g, "\\$&")}%`;
      filters.$or = [
        { payment_link_uid: { $ilike: pattern } },
        { session_id: { $ilike: pattern } },
        { order_id: { $ilike: pattern } },
        { order_display_id: { $ilike: pattern } },
        { customer_email: { $ilike: pattern } },
      ];
    }
    const [records, count] =
      await this.generated().listAndCountMakePayPaymentProjections(filters, {
        order: { created_at: "DESC" },
        skip: offset,
        take: limit,
      });
    return {
      count,
      limit,
      offset,
      payments: records.map((record) => this.toPaymentView(record)),
    };
  }

  async getPaymentView(id: string): Promise<MakePayPaymentView | undefined> {
    const [record] = await this.generated().listMakePayPaymentProjections(
      { id },
      { take: 1 },
    );
    return record ? this.toPaymentView(record) : undefined;
  }

  async getOrderPaymentView(
    orderId: string,
  ): Promise<MakePayPaymentView | undefined> {
    const [record] = await this.generated().listMakePayPaymentProjections(
      { order_id: orderId },
      { order: { created_at: "DESC" }, take: 1 },
    );
    return record ? this.toPaymentView(record) : undefined;
  }

  async reconcileProjection(
    idOrRecord: string | RecordShape,
  ): Promise<RecordShape> {
    const record =
      typeof idOrRecord === "string"
        ? (
            await this.generated().listMakePayPaymentProjections(
              { id: idOrRecord },
              { take: 1 },
            )
          )[0]
        : idOrRecord;
    if (!record) throw new Error("MakePay payment was not found.");
    if (
      record.auth_mode !== this.authMode ||
      record.provider_id !== this.providerId
    ) {
      throw new Error(
        "MakePay payment belongs to another authentication mode or provider.",
      );
    }
    const expectedOAuthRouting =
      this.authMode === "oauth"
        ? {
            companyId: getText(record.company_id),
            grantId: getText(record.grant_id),
            installationId: getText(record.installation_id),
            webhookSubscriptionId: getText(record.webhook_subscription_id),
          }
        : undefined;
    await this.assertStableProjectionOAuthRouting(expectedOAuthRouting);
    const client = await this.createClient();
    let response: MakePayPaymentLinkResponse;
    try {
      response = await client.getPaymentLink(String(record.payment_link_uid));
    } catch {
      throw new Error("MakePay payment reconciliation failed.");
    }
    return this.reconcileProjectionFromResponse(
      record,
      response,
      expectedOAuthRouting,
    );
  }

  private async assertStableProjectionOAuthRouting(
    expected:
      | {
          companyId?: string;
          grantId?: string;
          installationId?: string;
          webhookSubscriptionId?: string;
        }
      | undefined,
  ): Promise<void> {
    if (!expected) return;
    if (
      !expected.companyId ||
      !expected.grantId ||
      !expected.installationId ||
      !expected.webhookSubscriptionId
    ) {
      throw new Error(
        "MakePay reconciliation projection is missing OAuth routing identity.",
      );
    }
    const current = await this.getInstallationContext();
    if (
      current.companyId !== expected.companyId ||
      current.grantId !== expected.grantId ||
      current.installationId !== expected.installationId ||
      current.webhookSubscriptionId !== expected.webhookSubscriptionId
    ) {
      throw new Error(
        "MakePay OAuth connection changed during payment reconciliation.",
      );
    }
  }

  async reconcileProjectionFromResponse(
    record: RecordShape,
    response: MakePayPaymentLinkResponse,
    expectedOAuthRouting = this.authMode === "oauth"
      ? {
          companyId: getText(record.company_id),
          grantId: getText(record.grant_id),
          installationId: getText(record.installation_id),
          webhookSubscriptionId: getText(record.webhook_subscription_id),
        }
      : undefined,
  ): Promise<RecordShape> {
    await this.assertStableProjectionOAuthRouting(expectedOAuthRouting);
    const link = getPaymentLinkFromResponse(response);
    const uid = getText(link.uid) ?? getText(link.id);
    const remoteAmount = getPaymentLinkAmount(response);
    const remoteCurrency = getPaymentLinkFiatCurrency(response);
    const metadata = isRecord(link.metadata) ? link.metadata : {};
    const responseRecord = response as unknown as RecordShape;
    const remoteCompanyId = getText(responseRecord.companyId);
    const assertRemoteMatchesProjection = (candidate: RecordShape) => {
      if (
        candidate.id !== record.id ||
        candidate.auth_mode !== this.authMode ||
        uid !== candidate.payment_link_uid
      ) {
        throw new Error(
          "MakePay reconciliation returned a mismatched payment link.",
        );
      }
      if (
        remoteAmount === undefined ||
        !arePaymentAmountsEqual(remoteAmount, String(candidate.amount))
      ) {
        throw new Error("MakePay reconciliation amount does not match Medusa.");
      }
      if (
        !remoteCurrency ||
        remoteCurrency.toUpperCase() !==
          String(candidate.currency).toUpperCase()
      ) {
        throw new Error(
          "MakePay reconciliation currency does not match Medusa.",
        );
      }
      if (
        candidate.company_id &&
        (!remoteCompanyId || remoteCompanyId !== candidate.company_id)
      ) {
        throw new Error(
          "MakePay reconciliation company does not match Medusa.",
        );
      }
      if (
        candidate.installation_id &&
        getText(metadata.medusaInstallationId) !== candidate.installation_id
      ) {
        throw new Error(
          "MakePay reconciliation installation does not match Medusa.",
        );
      }
      if (getText(metadata.medusaSessionId) !== candidate.session_id) {
        throw new Error(
          "MakePay reconciliation session does not match Medusa.",
        );
      }
      if (getText(metadata.medusaProviderId) !== this.providerId) {
        throw new Error(
          "MakePay reconciliation provider does not match Medusa.",
        );
      }
      if (
        candidate.order_id &&
        getText(metadata.medusaOrderId) !== candidate.order_id
      ) {
        throw new Error("MakePay reconciliation order does not match Medusa.");
      }
      if (
        candidate.order_display_id &&
        getText(metadata.medusaOrderDisplayId) !== candidate.order_display_id
      ) {
        throw new Error(
          "MakePay reconciliation order display ID does not match Medusa.",
        );
      }
      if (
        expectedOAuthRouting &&
        (getText(candidate.company_id) !== expectedOAuthRouting.companyId ||
          getText(candidate.grant_id) !== expectedOAuthRouting.grantId ||
          getText(candidate.installation_id) !==
            expectedOAuthRouting.installationId ||
          getText(candidate.webhook_subscription_id) !==
            expectedOAuthRouting.webhookSubscriptionId)
      ) {
        throw new Error(
          "MakePay OAuth projection changed during payment reconciliation.",
        );
      }
    };
    assertRemoteMatchesProjection(record);
    const latestSession =
      getNestedRecord(link as RecordShape, "latestSession") ??
      getNestedRecord(link as RecordShape, "session");
    // Merchant-controlled payment-link payload keys must never participate in
    // reconciliation status selection. Only the serializer's link lifecycle
    // and the current MakePay session status are authoritative.
    const nextStatus = getMakePayProviderStatus({
      paymentLink: { status: getText(link.status) },
      session: { status: getText(latestSession?.status) },
    });
    if (nextStatus === "conflicting_terminal") {
      throw new Error(
        "MakePay reconciliation returned conflicting terminal states.",
      );
    }
    return this.withProjectionRowLock(
      String(record.payment_link_uid),
      async (current, sharedContext) => {
        if (!current) throw new Error("MakePay payment was not found.");
        assertRemoteMatchesProjection(current);
        const currentStatus = String(current.provider_status).toLowerCase();
        const currentTerminal = terminalIdentity(currentStatus);
        const nextTerminal = terminalIdentity(nextStatus);
        if (
          currentTerminal &&
          nextTerminal !== currentTerminal &&
          !(currentTerminal !== "complete" && nextTerminal === "complete")
        ) {
          return current;
        }
        const safePublicUrl = getSafeHostedPaymentUrl(
          getPaymentLinkUrl(link),
          String(current.payment_link_uid),
          getText((this.options_ as RecordShape).checkoutBaseUrl),
        );
        return this.generated().updateMakePayPaymentProjections(
          {
            id: current.id,
            last_synced_at: new Date(),
            medusa_status: medusaStatusForReconciliation(
              nextStatus,
              getText(current.medusa_status),
            ),
            provider_status: nextStatus,
            public_url: safePublicUrl ?? null,
          },
          sharedContext,
        );
      },
    );
  }

  async reconcilePaymentView(id: string): Promise<MakePayPaymentView> {
    return this.toPaymentView(await this.reconcileProjection(id));
  }

  async reconcileAndProcessPaymentView(
    id: string,
    processSuccessful: (
      payment: MakePayPaymentView,
    ) => Promise<{ paymentId: string }>,
    processTerminal?: (
      payment: MakePayPaymentView,
      action: "canceled" | "failed",
    ) => Promise<"canceled" | "failed" | undefined>,
  ): Promise<MakePayPaymentView> {
    const [initial] = await this.generated().listMakePayPaymentProjections(
      { id },
      { take: 1 },
    );
    if (!initial) throw new Error("MakePay payment was not found.");
    return this.withPaymentEffectsLock(
      String(initial.payment_link_uid),
      async () => {
        let payment = await this.reconcilePaymentView(id);
        if (
          payment.provider_status.toLowerCase() === "complete" &&
          payment.medusa_status !== "paid" &&
          payment.session_id
        ) {
          const captured = await processSuccessful(payment);
          await this.markCapturedPayment({
            paymentId: captured.paymentId,
            sessionId: payment.session_id,
          });
          payment = (await this.getPaymentView(payment.id))!;
        } else if (
          processTerminal &&
          payment.session_id &&
          payment.medusa_status !== "paid" &&
          (payment.provider_status.toLowerCase() === "failed" ||
            TERMINAL_CANCELED.has(payment.provider_status.toLowerCase()))
        ) {
          const action =
            payment.provider_status.toLowerCase() === "failed"
              ? "failed"
              : "canceled";
          const applied = await processTerminal(payment, action);
          if (!applied) {
            throw new Error(
              "MakePay reconciliation could not apply the terminal Medusa session state.",
            );
          }
          await this.markReconciledTerminal(payment, applied);
          payment = (await this.getPaymentView(payment.id))!;
        }
        return payment;
      },
    );
  }

  private async markReconciledTerminal(
    payment: MakePayPaymentView,
    medusaStatus: "canceled" | "failed",
  ): Promise<void> {
    await this.withProjectionRowLock(
      payment.payment_link_uid,
      async (projection, sharedContext) => {
        const providerStatus = String(
          projection?.provider_status ?? "",
        ).toLowerCase();
        const expectedMedusaStatus =
          providerStatus === "failed"
            ? "failed"
            : TERMINAL_CANCELED.has(providerStatus)
              ? "canceled"
              : undefined;
        if (
          !projection ||
          projection.id !== payment.id ||
          projection.auth_mode !== this.authMode ||
          projection.provider_id !== this.providerId ||
          projection.session_id !== payment.session_id ||
          expectedMedusaStatus !== medusaStatus ||
          String(projection.medusa_status).toLowerCase() === "paid"
        ) {
          throw new Error(
            "MakePay payment changed during terminal reconciliation.",
          );
        }
        await this.generated().updateMakePayPaymentProjections(
          {
            id: projection.id,
            effect_claimed_at: null,
            medusa_status: medusaStatus,
          },
          sharedContext,
        );
      },
    );
  }

  async checkoutStatus(state: string) {
    let record = await this.projectionByReturnState(state);
    if (!record) return undefined;
    try {
      record = await this.reconcileProjection(record);
    } catch {
      this.logger_.warn?.("MakePay return reconciliation failed.");
    }
    const status = statusFromProjection(record);
    return {
      payment: {
        status,
        updated_at: iso(record.updated_at) ?? new Date().toISOString(),
      },
      terminal: status !== "pending_authorization",
    };
  }

  async storefrontReturnUrl(state: string): Promise<string> {
    const config = this.checkoutReturnConfig();
    const status = await this.checkoutStatus(state);
    if (!status) throw new Error("MakePay checkout state was not found.");
    const redirect = new URL(config.storefrontReturnUrl);
    redirect.searchParams.set("makepay_state", state);
    return redirect.toString();
  }

  async recordWebhook(
    input: WebhookRecordInput,
    applyTerminalFailure?: () => Promise<"canceled" | "failed" | undefined>,
    findSuccessfulPayment?: () => Promise<{ paymentId: string } | undefined>,
    prepareSuccessfulSession?: () => Promise<boolean>,
  ): Promise<WebhookRecordResult> {
    await this.assertProviderConfigurationRegistered();
    if (
      this.authMode === "oauth" &&
      (input.eventType !== "makepay.payment.status_changed" ||
        !input.companyId ||
        !input.grantId ||
        !input.installationId ||
        !input.subscriptionId ||
        !MAKEPAY_SESSION_STATUSES.has(input.providerStatus))
    ) {
      return "rejected";
    }
    const job = async (): Promise<WebhookRecordResult> => {
      let result = await this.recordWebhookTransaction(input);
      if (result === "rejected") return result;
      const nextTerminal = terminalClass(input.providerStatus);
      if (nextTerminal === "failure") {
        if (!applyTerminalFailure) {
          throw new Error(
            "MakePay terminal failure processing requires an idempotent Medusa session update.",
          );
        }
        const appliedState = await applyTerminalFailure();
        if (!appliedState) {
          throw new Error(
            "MakePay could not apply the terminal Medusa session state.",
          );
        }
        await this.markWebhookEffectApplied(input, appliedState);
        return result;
      }
      if (nextTerminal === "success" && findSuccessfulPayment) {
        const captured = await findSuccessfulPayment();
        if (captured) {
          await this.markWebhookEffectApplied(
            input,
            "paid",
            captured.paymentId,
          );
          result = "duplicate";
        } else if (
          prepareSuccessfulSession &&
          !(await prepareSuccessfulSession())
        ) {
          throw new Error(
            "MakePay could not prepare the Medusa payment session for a late successful settlement.",
          );
        }
      }
      if (
        nextTerminal === "success" &&
        (result === "accepted" || result === "retry")
      ) {
        const authority = this.webhookAuthorityContext_?.getStore();
        if (
          authority?.active === true &&
          authority.paymentLinkUid === input.uid &&
          input.currency
        ) {
          authority.amount = input.amount;
          authority.currency = input.currency;
          authority.sessionId = input.sessionId;
        }
      }
      return result;
    };
    const provider = this.lockingProviderId(this.authMode === "oauth");
    if (!provider) {
      // Legacy API-key configurations keep working without a new module
      // option; the projection row is still locked transactionally below.
      return job();
    }
    const locking = this.lockingService();
    if (!locking) {
      throw new Error(
        "MakePay webhook processing requires Medusa's locking module.",
      );
    }
    return this.withPaymentEffectsLock(input.uid, job);
  }

  private async recordWebhookTransaction(
    input: WebhookRecordInput,
  ): Promise<WebhookRecordResult> {
    return this.withProjectionRowLock(input.uid, (projection, sharedContext) =>
      this.recordWebhookWithinTransaction(input, projection, sharedContext),
    );
  }

  private async recordWebhookWithinTransaction(
    input: WebhookRecordInput,
    projection: RecordShape | undefined,
    sharedContext: RecordShape,
  ): Promise<WebhookRecordResult> {
    const createdAt = input.createdAt ? asDate(input.createdAt) : undefined;
    const projectionCreatedAt = asDate(projection?.created_at);
    const correlatedAt = asDate(projection?.order_correlated_at);
    const correlationClockSkewMs =
      Math.min(
        Math.max(
          Number(
            (this.options_ as Partial<MakePayProviderOptions>)
              .webhookToleranceSeconds ?? 60,
          ),
          0,
        ),
        60,
      ) * 1000;
    const predatesOrderCorrelation = Boolean(
      projection?.order_id &&
      !input.orderId &&
      !input.orderDisplayId &&
      createdAt &&
      projectionCreatedAt &&
      correlatedAt &&
      createdAt.getTime() >=
        projectionCreatedAt.getTime() - correlationClockSkewMs &&
      createdAt.getTime() <= correlatedAt.getTime() + correlationClockSkewMs,
    );
    const oauthRoutingMismatch =
      this.authMode === "oauth" &&
      (!projection ||
        projection.company_id !== input.companyId ||
        projection.grant_id !== input.grantId ||
        projection.installation_id !== input.installationId ||
        projection.webhook_subscription_id !== input.subscriptionId);
    if (
      !projection ||
      projection.auth_mode !== this.authMode ||
      projection.session_id !== input.sessionId ||
      !arePaymentAmountsEqual(String(projection.amount), input.amount) ||
      !input.currency ||
      String(projection.currency).toUpperCase() !==
        input.currency.toUpperCase() ||
      (projection.company_id && projection.company_id !== input.companyId) ||
      (projection.installation_id &&
        projection.installation_id !== input.installationId) ||
      oauthRoutingMismatch ||
      (projection.order_id &&
        projection.order_id !== input.orderId &&
        !predatesOrderCorrelation) ||
      (projection.order_display_id &&
        projection.order_display_id !== input.orderDisplayId &&
        !predatesOrderCorrelation)
    ) {
      return "rejected";
    }
    const currentStatus = String(projection.provider_status).toLowerCase();
    const currentTerminal = terminalIdentity(currentStatus);
    const nextTerminal = terminalIdentity(input.providerStatus);
    if (
      currentTerminal &&
      nextTerminal !== currentTerminal &&
      !(currentTerminal !== "complete" && nextTerminal === "complete")
    ) {
      return "rejected";
    }
    const [duplicate] = await this.generated().listMakePayWebhookDeliveries(
      { delivery_id: input.deliveryId },
      { take: 1 },
      sharedContext,
    );
    if (duplicate) {
      const isSameDelivery =
        duplicate.payload_hash === input.payloadHash &&
        duplicate.payment_link_uid === input.uid &&
        duplicate.session_id === input.sessionId &&
        String(duplicate.provider_status).toLowerCase() ===
          input.providerStatus.toLowerCase();
      if (!isSameDelivery) return "rejected";
      if (
        nextTerminal === "failed" ||
        nextTerminal === "expired" ||
        nextTerminal === "cancelled"
      ) {
        return "duplicate";
      }
      if (nextTerminal === "complete") {
        const medusaStatus = String(projection.medusa_status).toLowerCase();
        if (medusaStatus === "paid") {
          return "duplicate";
        }
        if (medusaStatus === "processing") {
          const claimedAt =
            asDate(projection.effect_claimed_at)?.getTime() ?? 0;
          if (Date.now() - claimedAt < SUCCESS_CLAIM_LEASE_MS) {
            return "in_progress";
          }
        }
        await this.generated().updateMakePayPaymentProjections(
          {
            id: projection.id,
            effect_claimed_at: new Date(),
            last_synced_at: new Date(),
            medusa_status: "processing",
          },
          sharedContext,
        );
        return "retry";
      }
      return "duplicate";
    }
    if (currentTerminal && nextTerminal === currentTerminal) {
      const medusaStatus = String(projection.medusa_status).toLowerCase();
      const terminalEffectApplied =
        currentTerminal === "complete"
          ? medusaStatus === "paid"
          : currentTerminal === "failed"
            ? medusaStatus === "failed"
            : medusaStatus === "canceled";
      if (terminalEffectApplied) {
        await this.generated().createMakePayWebhookDeliveries(
          {
            delivery_id: input.deliveryId,
            event_type: input.eventType ?? null,
            payload_hash: input.payloadHash,
            payment_link_uid: input.uid,
            processed_at: new Date(),
            provider_status: input.providerStatus,
            session_id: input.sessionId,
          },
          sharedContext,
        );
        return "duplicate";
      }
      if (currentTerminal === "complete" && medusaStatus === "processing") {
        await this.generated().createMakePayWebhookDeliveries(
          {
            delivery_id: input.deliveryId,
            event_type: input.eventType ?? null,
            payload_hash: input.payloadHash,
            payment_link_uid: input.uid,
            processed_at: new Date(),
            provider_status: input.providerStatus,
            session_id: input.sessionId,
          },
          sharedContext,
        );
        const claimedAt = asDate(projection.effect_claimed_at)?.getTime() ?? 0;
        if (Date.now() - claimedAt < SUCCESS_CLAIM_LEASE_MS) {
          return "in_progress";
        }
        await this.generated().updateMakePayPaymentProjections(
          {
            id: projection.id,
            effect_claimed_at: new Date(),
            last_synced_at: new Date(),
            medusa_status: "processing",
          },
          sharedContext,
        );
        return "retry";
      }
    }
    await this.generated().createMakePayWebhookDeliveries(
      {
        delivery_id: input.deliveryId,
        event_type: input.eventType ?? null,
        payload_hash: input.payloadHash,
        payment_link_uid: input.uid,
        processed_at: new Date(),
        provider_status: input.providerStatus,
        session_id: input.sessionId,
      },
      sharedContext,
    );
    await this.generated().updateMakePayPaymentProjections(
      {
        id: projection.id,
        effect_claimed_at: nextTerminal === "complete" ? new Date() : null,
        last_synced_at: new Date(),
        medusa_status:
          nextTerminal === "failed" ||
          nextTerminal === "expired" ||
          nextTerminal === "cancelled"
            ? (getText(projection.medusa_status) ?? "pending_authorization")
            : medusaStatusForProvider(
                input.providerStatus,
                getText(projection.medusa_status),
              ),
        provider_status: input.providerStatus,
      },
      sharedContext,
    );
    return "accepted";
  }

  private async markWebhookEffectApplied(
    input: WebhookRecordInput,
    medusaStatus: "canceled" | "failed" | "paid",
    paymentId?: string,
  ): Promise<void> {
    await this.withProjectionRowLock(
      input.uid,
      async (projection, sharedContext) => {
        if (!projection) throw new Error("MakePay payment was not found.");
        const currentTerminal = terminalIdentity(
          String(projection.provider_status).toLowerCase(),
        );
        const expectedTerminal =
          medusaStatus === "paid"
            ? "complete"
            : medusaStatus === "failed"
              ? "failed"
              : terminalIdentity(input.providerStatus);
        if (
          currentTerminal !== expectedTerminal ||
          currentTerminal !== terminalIdentity(input.providerStatus)
        ) {
          throw new Error(
            "MakePay payment changed while its Medusa side effect was applied.",
          );
        }
        if (
          medusaStatus !== "paid" &&
          String(projection.medusa_status).toLowerCase() === "paid"
        ) {
          throw new Error("MakePay cannot regress a paid Medusa payment.");
        }
        await this.generated().updateMakePayPaymentProjections(
          {
            id: projection.id,
            effect_claimed_at: null,
            medusa_status: medusaStatus,
            ...(paymentId ? { payment_id: paymentId } : {}),
          },
          sharedContext,
        );
      },
    );
  }

  async releaseSuccessfulPaymentClaim(input: {
    paymentLinkUid: string;
    sessionId: string;
  }): Promise<void> {
    await this.withProjectionRowLock(
      input.paymentLinkUid,
      async (projection, sharedContext) => {
        if (
          !projection ||
          projection.auth_mode !== this.authMode ||
          projection.session_id !== input.sessionId ||
          terminalIdentity(String(projection.provider_status).toLowerCase()) !==
            "complete" ||
          String(projection.medusa_status).toLowerCase() !== "processing"
        ) {
          return;
        }
        await this.generated().updateMakePayPaymentProjections(
          {
            id: projection.id,
            effect_claimed_at: null,
            medusa_status: "pending_authorization",
          },
          sharedContext,
        );
      },
    );
  }

  async markCapturedPayment(input: {
    paymentId: string;
    sessionId: string;
  }): Promise<void> {
    const projection = await this.projectionBySession(input.sessionId);
    if (!projection) return;
    await this.withProjectionRowLock(
      String(projection.payment_link_uid),
      async (current, sharedContext) => {
        if (String(current?.medusa_status).toLowerCase() === "paid") {
          if (
            current?.payment_id === input.paymentId &&
            current?.session_id === input.sessionId &&
            String(current?.provider_status).toLowerCase() === "complete"
          ) {
            return;
          }
          throw new Error("MakePay captured payment identity does not match.");
        }
        if (
          !current ||
          current.auth_mode !== this.authMode ||
          current.session_id !== input.sessionId
        ) {
          throw new Error("MakePay capture projection does not match.");
        }
        if (String(current.provider_status).toLowerCase() !== "complete") {
          throw new Error(
            "MakePay cannot mark a non-complete projection as paid.",
          );
        }
        await this.generated().updateMakePayPaymentProjections(
          {
            id: current.id,
            effect_claimed_at: null,
            medusa_status: "paid",
            payment_id: input.paymentId,
          },
          sharedContext,
        );
      },
    );
  }

  async markCanceledPayment(input: {
    lateSettlementSafe?: boolean;
    paymentLinkUid: string;
    sessionId: string;
  }): Promise<void> {
    await this.withProjectionRowLock(
      input.paymentLinkUid,
      async (projection, sharedContext) => {
        if (
          !projection ||
          projection.auth_mode !== this.authMode ||
          projection.session_id !== input.sessionId
        ) {
          throw new Error("MakePay cancellation projection does not match.");
        }
        if (
          String(projection.provider_status).toLowerCase() === "complete" ||
          String(projection.medusa_status).toLowerCase() === "paid"
        ) {
          throw new Error("MakePay cannot cancel a completed payment.");
        }
        await this.generated().updateMakePayPaymentProjections(
          {
            id: projection.id,
            effect_claimed_at: null,
            late_settlement_safe:
              projection.late_settlement_safe === true ||
              input.lateSettlementSafe === true,
            last_synced_at: new Date(),
            medusa_status: "canceled",
            provider_status: "cancelled",
          },
          sharedContext,
        );
      },
    );
  }

  async correlateOrder(input: {
    customerEmail?: string;
    orderId: string;
    orderDisplayId?: string;
    paymentId?: string;
    sessionId: string;
  }): Promise<void> {
    await this.assertProviderConfigurationRegistered();
    const initial = await this.projectionBySession(input.sessionId);
    if (!initial) return;
    if (
      initial.auth_mode !== this.authMode ||
      initial.provider_id !== this.providerId
    ) {
      throw new Error(
        "MakePay order correlation belongs to another authentication mode or provider.",
      );
    }
    const customerEmail = getText(input.customerEmail);
    if (
      customerEmail &&
      (customerEmail.length > 320 ||
        /[\u0000-\u001f\u007f]/.test(customerEmail))
    ) {
      throw new Error("MakePay order correlation email is invalid.");
    }
    const uid = String(initial.payment_link_uid);
    await this.withConfiguredPaymentEffectsLock(uid, async () => {
      const projection = await this.projectionBySession(input.sessionId);
      if (
        !projection ||
        projection.payment_link_uid !== uid ||
        projection.auth_mode !== this.authMode ||
        projection.provider_id !== this.providerId
      ) {
        throw new Error("MakePay order correlation projection changed.");
      }
      const expectedOAuthRouting =
        this.authMode === "oauth"
          ? {
              companyId: getText(projection.company_id),
              grantId: getText(projection.grant_id),
              installationId: getText(projection.installation_id),
              webhookSubscriptionId: getText(
                projection.webhook_subscription_id,
              ),
            }
          : undefined;
      await this.assertStableProjectionOAuthRouting(expectedOAuthRouting);
      try {
        const client = await this.createClient();
        const update: MakePayPaymentLinkUpdate = {
          metadata: {
            medusaAdminUrl: getText((this.options_ as RecordShape).backendUrl)
              ? `${String((this.options_ as RecordShape).backendUrl).replace(
                  /\/+$/,
                  "",
                )}${this.adminPath === "/" ? "" : this.adminPath}/orders/${encodeURIComponent(
                  input.orderId,
                )}`
              : undefined,
            medusaInstallationId: getText(projection.installation_id),
            medusaOrderDisplayId: input.orderDisplayId,
            medusaOrderId: input.orderId,
          },
        };
        const response = await client.updatePaymentLink(uid, update, {
          idempotencyKey: `medusa-order-${sha256(
            JSON.stringify([uid, input.orderId]),
          )}`,
        });
        const link = getPaymentLinkFromResponse(response);
        const metadata = isRecord(link.metadata) ? link.metadata : {};
        if (
          (getText(link.uid) ?? getText(link.id)) !== uid ||
          getText(metadata.medusaSessionId) !== input.sessionId ||
          getText(metadata.medusaProviderId) !== this.providerId ||
          getText(metadata.medusaOrderId) !== input.orderId ||
          (input.orderDisplayId &&
            getText(metadata.medusaOrderDisplayId) !== input.orderDisplayId) ||
          (projection.installation_id &&
            getText(metadata.medusaInstallationId) !==
              projection.installation_id)
        ) {
          throw new Error("MakePay order correlation response mismatched.");
        }
      } catch {
        this.logger_.warn?.("MakePay order correlation failed.");
        throw new Error("MakePay order correlation failed.");
      }
      await this.withProjectionRowLock(uid, async (current, sharedContext) => {
        if (
          !current ||
          current.session_id !== input.sessionId ||
          current.auth_mode !== this.authMode ||
          current.provider_id !== this.providerId
        ) {
          throw new Error("MakePay order correlation projection changed.");
        }
        await this.generated().updateMakePayPaymentProjections(
          {
            id: current.id,
            customer_email:
              customerEmail ?? current.customer_email ?? null,
            order_correlated_at: new Date(),
            order_display_id: input.orderDisplayId ?? null,
            order_id: input.orderId,
            payment_id: input.paymentId ?? current.payment_id ?? null,
          },
          sharedContext,
        );
      });
    });
  }
}

export function getMakePayModuleOptions(
  options: MakePayModuleOptions,
): MakePayModuleOptions {
  return options;
}

export function paymentStatusFromRemote(input: unknown): string {
  return mapMakePayStateToPaymentSessionStatus(input);
}

export { decodeJwtPayload };
