import { createHmac } from "node:crypto";

import {
  MakePayClient,
  MakePayError,
  parseMakePayWebhook,
  type MakePayPaymentLinkPayload,
  type MakePayPaymentLinkResponse,
} from "@makecrypto/makepay";
import type {
  AuthorizePaymentInput,
  AuthorizePaymentOutput,
  CancelPaymentInput,
  CancelPaymentOutput,
  CapturePaymentInput,
  CapturePaymentOutput,
  DeletePaymentInput,
  DeletePaymentOutput,
  GetPaymentStatusInput,
  GetPaymentStatusOutput,
  InitiatePaymentInput,
  InitiatePaymentOutput,
  IPaymentModuleService,
  ProviderWebhookPayload,
  RefundPaymentInput,
  RefundPaymentOutput,
  RetrievePaymentInput,
  RetrievePaymentOutput,
  UpdatePaymentInput,
  UpdatePaymentOutput,
  WebhookActionResult,
} from "@medusajs/framework/types";
import { MedusaModule } from "@medusajs/framework/modules-sdk";
import {
  AbstractPaymentProvider,
  MedusaError,
  Modules,
  PaymentActions,
  PaymentSessionStatus,
} from "@medusajs/framework/utils";

import {
  MAKEPAY_MODULE,
  MAKEPAY_PROVIDER_IDENTIFIER,
} from "../../../modules/makepay/constants.js";
import { sha256 } from "../../../modules/makepay/crypto.js";
import { findFullyCapturedPayment } from "../../../lib/payment-state.js";
import {
  applyTerminalPaymentSessionState,
  isLateSuccessfulSessionUpdateContext,
  prepareLateSuccessfulPaymentSession,
  terminalSessionStateFromContext,
  terminalSessionUpdateContext,
} from "../../../lib/terminal-session.js";
import type MakePayModuleService from "../../../modules/makepay/service.js";
import type {
  MakePayPaymentAction,
  MakePayPaymentSessionStatus,
  MakePayProviderData,
  MakePayProviderOptions,
  NormalizedMakePayProviderOptions,
} from "../types.js";
import {
  arePaymentAmountsEqual,
  buildProviderData,
  canonicalPaymentAmount,
  getAmountFromWebhook,
  getAuthoritativeMakePayProviderStatus,
  getCompanyIdFromWebhook,
  getCurrencyFromWebhook,
  getInstallationIdFromWebhook,
  getMakePayProviderStatus,
  getNestedRecord,
  getNumberOrText,
  getPaymentLinkAmount,
  getPaymentLinkFiatCurrency,
  getPaymentLinkFromResponse,
  getPaymentLinkUid,
  getPaymentLinkUidFromWebhook,
  getPaymentLinkUrl,
  getSafeHostedPaymentUrl,
  getSafeExternalUrl,
  getOrderDisplayIdFromWebhook,
  getOrderIdFromWebhook,
  getSessionIdFromData,
  getSessionIdFromWebhook,
  getText,
  getWebhookEventType,
  isRecord,
  mapMakePayStateToPaymentSessionStatus,
  makePaySecurityConfigurationFingerprint,
  mapMakePayWebhookToPaymentAction,
  type MakePayPaymentLinkSnapshot,
  normalizeAmountValue,
  normalizeProviderOptions,
  shouldRefreshPaymentLinkForUpdate,
  validateMakePayProviderOptions,
} from "../utils.js";

const DEFAULT_PAYMENT_DESCRIPTION =
  "Hosted MakePay checkout for a Medusa payment session.";

function normalizeCustomerEmail(value: unknown): string | undefined {
  const email = getText(value);
  if (
    email &&
    (email.length > 320 || /[\u0000-\u001f\u007f]/.test(email))
  ) {
    throw new Error("MakePay customer email is invalid.");
  }
  return email;
}

type CanonicalMedusaWebhookStatus =
  | "quoted"
  | "awaiting_deposit"
  | "pending"
  | "deposit_received"
  | "swapping"
  | "sending"
  | "underpaid"
  | "complete"
  | "failed"
  | "expired"
  | "cancelled";

type CanonicalMedusaWebhookSettlement = {
  phase: "pending" | "processing" | "sending" | "sent";
  settledAmount: string | null;
  settledAsset: string | null;
  classification: "unknown" | "matched" | "underpaid" | "overpaid" | null;
};

type CanonicalMedusaWebhook = {
  schemaVersion: "medusa.v1";
  deliveryId: string;
  deliveryGroupId: string;
  type: "makepay.payment.status_changed";
  createdAt: string;
  status: CanonicalMedusaWebhookStatus;
  companyId: string;
  grantId: string;
  subscriptionId: string;
  installationId: string;
  paymentLink: {
    uid: string;
    fiatAmount: string;
    fiatCurrency: string;
    metadata: {
      medusaSessionId: string;
      medusaOrderId: string | null;
      medusaOrderDisplayId: string | null;
      medusaProviderId: string;
    };
  };
  session: {
    id: string;
    settlement: CanonicalMedusaWebhookSettlement | null;
  };
};

type LegacyMakePayWebhook = {
  amount: string | number;
  currency: string;
  eventType: string;
  makepaySessionId: string;
  merchantOrderId: string;
  providerStatus: string;
  uid: string;
};

const CANONICAL_WEBHOOK_STATUSES = new Set<CanonicalMedusaWebhookStatus>([
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

const CANONICAL_SETTLEMENT_PHASES = new Set([
  "pending",
  "processing",
  "sending",
  "sent",
]);

const CANONICAL_SETTLEMENT_CLASSIFICATIONS = new Set([
  "unknown",
  "matched",
  "underpaid",
  "overpaid",
]);

const MAKEPAY_UNPAID_START_STATUSES = new Set([
  "active",
  "created",
  "open",
  "unpaid",
  "pending",
  "quoted",
  "awaiting_deposit",
]);

const CANONICAL_WEBHOOK_KEYS = [
  "schemaVersion",
  "deliveryId",
  "deliveryGroupId",
  "type",
  "createdAt",
  "status",
  "companyId",
  "grantId",
  "subscriptionId",
  "installationId",
  "paymentLink",
  "session",
] as const;

function hasExactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
): boolean {
  const expected = new Set(keys);
  const actual = Object.keys(value);
  return (
    actual.length === expected.size && actual.every((key) => expected.has(key))
  );
}

function exactText(value: unknown, maximumLength = 200): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximumLength &&
    value.trim() === value
  );
}

function nullableExactText(
  value: unknown,
  maximumLength = 200,
): value is string | null {
  return value === null || exactText(value, maximumLength);
}

function canonicalIsoTimestamp(value: unknown): value is string {
  if (!exactText(value, 64)) return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value;
}

function canonicalSettlement(
  value: unknown,
): value is CanonicalMedusaWebhookSettlement | null {
  if (value === null) return true;
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      "phase",
      "settledAmount",
      "settledAsset",
      "classification",
    ])
  ) {
    return false;
  }
  return (
    typeof value.phase === "string" &&
    CANONICAL_SETTLEMENT_PHASES.has(value.phase) &&
    (value.settledAmount === null ||
      (exactText(value.settledAmount, 100) &&
        /^(?:0|[1-9]\d*)(?:\.\d+)?$/.test(value.settledAmount))) &&
    nullableExactText(value.settledAsset, 200) &&
    (value.classification === null ||
      (typeof value.classification === "string" &&
        CANONICAL_SETTLEMENT_CLASSIFICATIONS.has(value.classification)))
  );
}

function canonicalWebhookAction(
  status: CanonicalMedusaWebhookStatus,
): MakePayPaymentAction {
  if (status === "complete") return "captured";
  if (status === "failed") return "failed";
  if (status === "expired" || status === "cancelled") return "canceled";
  return "pending";
}

function exactLegacyWebhook(
  event: Record<string, unknown>,
): LegacyMakePayWebhook | undefined {
  const paymentLink = isRecord(event.paymentLink)
    ? event.paymentLink
    : undefined;
  const session = isRecord(event.session) ? event.session : undefined;
  const eventType = getText(event.type);
  const uid = getText(paymentLink?.uid);
  const merchantOrderId = getText(paymentLink?.merchantOrderId);
  const currency = getText(paymentLink?.currency);
  const amountValue = paymentLink?.amount;
  const amount =
    typeof amountValue === "string" || typeof amountValue === "number"
      ? amountValue
      : undefined;
  const paymentLinkStatus = getText(paymentLink?.status);
  const sessionStatus = getText(session?.status);
  const makepaySessionId = getText(session?.id);
  if (
    !eventType?.startsWith("makepay.payment.") ||
    !uid ||
    !merchantOrderId ||
    !currency ||
    !makepaySessionId ||
    amount === undefined ||
    !canonicalPaymentAmount(amount) ||
    !paymentLinkStatus ||
    !sessionStatus
  ) {
    return undefined;
  }
  const providerStatus = getAuthoritativeMakePayProviderStatus({
    paymentLink: { status: paymentLinkStatus },
    session: { status: sessionStatus },
  });
  if (providerStatus === "conflicting_terminal") return undefined;
  return {
    amount,
    currency,
    eventType,
    makepaySessionId,
    merchantOrderId,
    providerStatus,
    uid,
  };
}

function canonicalMedusaWebhook(
  event: Record<string, unknown>,
): CanonicalMedusaWebhook | undefined {
  if (!hasExactKeys(event, CANONICAL_WEBHOOK_KEYS)) return undefined;
  const paymentLink = isRecord(event.paymentLink)
    ? event.paymentLink
    : undefined;
  const metadata =
    paymentLink && isRecord(paymentLink.metadata)
      ? paymentLink.metadata
      : undefined;
  const session = isRecord(event.session) ? event.session : undefined;
  if (
    event.schemaVersion !== "medusa.v1" ||
    event.type !== "makepay.payment.status_changed" ||
    !exactText(event.deliveryId) ||
    !exactText(event.deliveryGroupId, 73) ||
    !/^mpwhgrp_[a-f0-9]{64}$/.test(event.deliveryGroupId) ||
    !canonicalIsoTimestamp(event.createdAt) ||
    typeof event.status !== "string" ||
    !CANONICAL_WEBHOOK_STATUSES.has(
      event.status as CanonicalMedusaWebhookStatus,
    ) ||
    !exactText(event.companyId) ||
    !exactText(event.grantId) ||
    !exactText(event.subscriptionId) ||
    !exactText(event.installationId) ||
    !paymentLink ||
    !hasExactKeys(paymentLink, [
      "uid",
      "fiatAmount",
      "fiatCurrency",
      "metadata",
    ]) ||
    !exactText(paymentLink.uid) ||
    !exactText(paymentLink.fiatAmount, 100) ||
    !/^(0|[1-9]\d*)(?:\.\d+)?$/.test(paymentLink.fiatAmount) ||
    !/[1-9]/.test(paymentLink.fiatAmount) ||
    !exactText(paymentLink.fiatCurrency, 3) ||
    !/^[A-Z]{3}$/.test(paymentLink.fiatCurrency) ||
    !metadata ||
    !hasExactKeys(metadata, [
      "medusaSessionId",
      "medusaOrderId",
      "medusaOrderDisplayId",
      "medusaProviderId",
    ]) ||
    !exactText(metadata.medusaSessionId) ||
    !nullableExactText(metadata.medusaOrderId) ||
    !nullableExactText(metadata.medusaOrderDisplayId, 120) ||
    metadata.medusaProviderId !== MAKEPAY_PROVIDER_IDENTIFIER ||
    !session ||
    !hasExactKeys(session, ["id", "settlement"]) ||
    !exactText(session.id) ||
    !canonicalSettlement(session.settlement)
  ) {
    return undefined;
  }
  return event as unknown as CanonicalMedusaWebhook;
}

type ModuleService = Pick<
  MakePayModuleService,
  | "authMode"
  | "assertAuthModeTransitionAllowed"
  | "createClient"
  | "getInstallationContext"
  | "getWebhookSecret"
  | "hasSynchronousWebhookAuthority"
  | "markCanceledPayment"
  | "projectionByUid"
  | "projectionBySession"
  | "providerId"
  | "registerPaymentProviderConfiguration"
  | "recordWebhook"
  | "reconcileProjection"
  | "reconcileProjectionFromResponse"
  | "upsertProjection"
  | "withPaymentInitiationGuard"
>;

class MakePayProviderService extends AbstractPaymentProvider<MakePayProviderOptions> {
  static identifier = MAKEPAY_PROVIDER_IDENTIFIER;

  protected readonly apiKeyClient_?: MakePayClient;
  protected readonly options_: NormalizedMakePayProviderOptions;
  protected readonly container_: Record<string, unknown>;

  static validateOptions(options: MakePayProviderOptions): void {
    validateMakePayProviderOptions(options);
  }

  constructor(
    container: Record<string, unknown>,
    options: MakePayProviderOptions,
  ) {
    super(container, options);
    this.container_ = container;
    this.options_ = normalizeProviderOptions(options);

    if (this.options_.authMode === "api_key") {
      this.apiKeyClient_ = new MakePayClient({
        baseUrl: this.options_.baseUrl,
        checkoutBaseUrl: this.options_.checkoutBaseUrl,
        fetch: this.options_.fetch,
        keyId: this.options_.keyId!,
        keySecret: this.options_.keySecret!,
      });
    } else if (!this.moduleService()) {
      throw new Error(
        "MakePay OAuth requires the plugin's `makepayIntegration` module. Add the package to `plugins` and run `medusa db:migrate`.",
      );
    }
    this.assertModuleConfiguration(this.moduleService());
  }

  private createOperation(input: {
    amount: InitiatePaymentInput["amount"];
    currencyCode: string;
    data?: Record<string, unknown>;
    sessionId: string;
  }): { idempotencyKey: string; returnState: string } {
    const normalizedAmount = canonicalPaymentAmount(
      normalizeAmountValue(input.amount),
    );
    if (!normalizedAmount) {
      throw new Error("MakePay payment amount is invalid.");
    }
    const fingerprint = sha256(
      JSON.stringify({
        // The remote creation identity is immutable for one Medusa payment
        // session. Mutable request fields deliberately stay out of
        // the key: concurrent callers with different amounts/currencies must
        // conflict against one server-side idempotency record, never create
        // two independently payable UIDs.
        providerId: this.options_.providerId,
        sessionId: input.sessionId,
        version: 3,
      }),
    );
    const idempotencyKey = `medusa-makepay-create-${fingerprint}`;
    const secret =
      this.options_.authMode === "oauth"
        ? this.options_.encryptionKey!
        : this.options_.keySecret!;
    const returnState = createHmac("sha256", secret)
      .update(idempotencyKey)
      .digest("base64url");
    return { idempotencyKey, returnState };
  }

  private assertPaymentLinkSnapshot(
    response: MakePayPaymentLinkResponse,
    expected: {
      amount: string | number;
      companyId?: string;
      currency: string;
      installationId?: string;
      orderDisplayId?: string;
      orderId?: string;
      sessionId: string;
      uid: string;
    },
  ): { paymentLink: MakePayPaymentLinkSnapshot; providerStatus: string } {
    const paymentLink = getPaymentLinkFromResponse(response);
    const uid = getText(paymentLink.uid) ?? getText(paymentLink.id);
    const amount = getPaymentLinkAmount(response);
    const currency = getPaymentLinkFiatCurrency(response);
    const metadata = isRecord(paymentLink.metadata)
      ? paymentLink.metadata
      : undefined;
    const companyId = getText(
      (response as unknown as Record<string, unknown>).companyId,
    );
    const hostedUrl = getPaymentLinkUrl(paymentLink);
    if (
      uid !== expected.uid ||
      amount === undefined ||
      !arePaymentAmountsEqual(amount, expected.amount) ||
      !currency ||
      currency.toUpperCase() !== expected.currency.toUpperCase() ||
      getText(metadata?.medusaSessionId) !== expected.sessionId ||
      getText(metadata?.medusaProviderId) !== this.options_.providerId ||
      (this.options_.authMode === "api_key" && !companyId) ||
      (expected.companyId && companyId !== expected.companyId) ||
      (expected.installationId &&
        getText(metadata?.medusaInstallationId) !== expected.installationId) ||
      (expected.orderId &&
        getText(metadata?.medusaOrderId) !== expected.orderId) ||
      (expected.orderDisplayId &&
        getText(metadata?.medusaOrderDisplayId) !== expected.orderDisplayId) ||
      (hostedUrl &&
        !getSafeHostedPaymentUrl(
          hostedUrl,
          expected.uid,
          this.options_.checkoutBaseUrl,
        ))
    ) {
      throw new Error("MakePay payment-link correlation failed.");
    }
    const providerStatus = getAuthoritativeMakePayProviderStatus({
      paymentLink,
      session:
        getNestedRecord(paymentLink, "latestSession") ??
        getNestedRecord(paymentLink, "session"),
    });
    if (providerStatus === "conflicting_terminal") {
      throw new Error(
        "MakePay returned conflicting authoritative terminal states.",
      );
    }
    return { paymentLink, providerStatus };
  }

  async initiatePayment({
    amount,
    currency_code,
    data,
    context,
  }: InitiatePaymentInput): Promise<InitiatePaymentOutput> {
    const moduleService = this.moduleService();
    this.assertModuleConfiguration(moduleService);
    const job = () =>
      this.initiatePaymentWithinLifecycleLock({
        amount,
        context,
        currency_code,
        data,
      });
    return moduleService
      ? moduleService.withPaymentInitiationGuard(job)
      : job();
  }

  private async initiatePaymentWithinLifecycleLock({
    amount,
    currency_code,
    data,
    context,
  }: InitiatePaymentInput): Promise<InitiatePaymentOutput> {
    const sessionId = this.getSessionId(data, context?.idempotency_key);
    const operation = this.createOperation({
      amount,
      currencyCode: currency_code,
      data,
      sessionId,
    });
    const returnState = operation.returnState;
    const moduleService = this.moduleService();
    this.assertModuleConfiguration(moduleService);
    await moduleService?.assertAuthModeTransitionAllowed();
    const priorUid = getPaymentLinkUid(data);
    const [projectionByUid, projectionBySession] = await Promise.all([
      priorUid ? moduleService?.projectionByUid(priorUid) : undefined,
      moduleService?.projectionBySession(sessionId),
    ]);
    if (
      projectionByUid &&
      projectionBySession &&
      projectionByUid.id !== projectionBySession.id
    ) {
      throw new Error(
        "MakePay payment-link and Medusa session projections conflict.",
      );
    }
    const priorProjection = projectionByUid ?? projectionBySession;
    if (
      priorProjection &&
      (priorProjection.auth_mode !== this.options_.authMode ||
        priorProjection.provider_id !== this.options_.providerId ||
        priorProjection.session_id !== sessionId)
    ) {
      throw new Error(
        "MakePay replacement payment does not match its existing projection.",
      );
    }
    if (
      !moduleService &&
      this.options_.authMode === "api_key" &&
      priorUid
    ) {
      const reuseReturnState = getText(data?.return_state);
      if (!reuseReturnState || reuseReturnState !== returnState) {
        throw new Error(
          "MakePay keeps one immutable payment-link UID per Medusa payment session. Create a new payment session.",
        );
      }
      const existingResponse = await this.remoteCall(
        "MakePay existing payment-link verification failed.",
        () =>
          this.apiKeyClient_!.getPaymentLink(priorUid),
      );
      const { paymentLink, providerStatus } = this.assertPaymentLinkSnapshot(
        existingResponse,
        {
          amount: normalizeAmountValue(amount),
          currency: currency_code,
          sessionId,
          uid: priorUid,
        },
      );
      const mappedStatus = mapMakePayStateToPaymentSessionStatus({
        status: providerStatus,
      });
      const sessionStatus =
        mappedStatus === "pending" ? "pending_authorization" : mappedStatus;
      const providerData = buildProviderData({
        amount: normalizeAmountValue(amount),
        checkoutBaseUrl: this.options_.checkoutBaseUrl,
        existing: data,
        fiatCurrency: currency_code,
        paymentLink,
        returnState: reuseReturnState,
        sessionId,
        status: sessionStatus,
      });
      return {
        data: providerData,
        id: priorUid,
        status: this.toPaymentSessionStatus(sessionStatus),
      };
    }
    const installation =
      this.options_.authMode === "oauth"
        ? await moduleService!.getInstallationContext()
        : undefined;
    if (
      this.options_.authMode === "oauth" &&
      (!installation?.companyId ||
        !installation.grantId ||
        !installation.installationId ||
        !installation.webhookSubscriptionId)
    ) {
      throw new Error(
        "MakePay OAuth checkout requires a healthy grant-scoped webhook subscription.",
      );
    }
    if (priorProjection) {
      const projectionUid = getText(priorProjection.payment_link_uid);
      const reuseReturnState =
        getText(data?.return_state) ?? (!priorUid ? returnState : undefined);
      if (
        !projectionUid ||
        (priorUid && priorUid !== projectionUid) ||
        !arePaymentAmountsEqual(
          String(priorProjection.amount),
          normalizeAmountValue(amount),
        ) ||
        String(priorProjection.currency).toUpperCase() !==
          currency_code.toUpperCase() ||
        !reuseReturnState ||
        sha256(reuseReturnState) !== priorProjection.return_state_hash
      ) {
        throw new Error(
          "MakePay keeps one immutable payment-link UID per Medusa payment session. Create a new payment session.",
        );
      }
      const existingResponse = await this.remoteCall(
        "MakePay existing payment-link verification failed.",
        () => (this.client()).then((client) => client.getPaymentLink(projectionUid)),
      );
      const { paymentLink, providerStatus } = this.assertPaymentLinkSnapshot(
        existingResponse,
        {
          amount: String(priorProjection.amount),
          companyId:
            installation?.companyId ?? getText(priorProjection.company_id),
          currency: String(priorProjection.currency),
          installationId:
            installation?.installationId ??
            getText(priorProjection.installation_id),
          orderDisplayId: getText(priorProjection.order_display_id),
          orderId: getText(priorProjection.order_id),
          sessionId,
          uid: projectionUid,
        },
      );
      const mappedStatus = mapMakePayStateToPaymentSessionStatus({
        status: providerStatus,
      });
      const sessionStatus =
        mappedStatus === "pending" ? "pending_authorization" : mappedStatus;
      const providerData = buildProviderData({
        amount: String(priorProjection.amount),
        checkoutBaseUrl: this.options_.checkoutBaseUrl,
        existing: data,
        fiatCurrency: String(priorProjection.currency),
        paymentLink,
        returnState: reuseReturnState,
        sessionId,
        status: sessionStatus,
      });
      return {
        data: providerData,
        id: projectionUid,
        status: this.toPaymentSessionStatus(sessionStatus),
      };
    }
    const payload = this.buildPaymentLinkPayload({
      amount,
      context,
      currencyCode: currency_code,
      data,
      installationId: installation?.installationId,
      returnState,
      sessionId,
    });
    const client = await this.client();
    const response = await this.remoteCall(
      "MakePay payment-link creation failed.",
      () =>
        client.createPaymentLink(payload, {
          idempotencyKey: operation.idempotencyKey,
          sendPaymentRequestEmail: false,
          status: "active",
        }),
    );
    const createdPaymentLink = getPaymentLinkFromResponse(response);
    const uid =
      getText(createdPaymentLink.uid) ?? getText(createdPaymentLink.id);

    if (!uid) {
      throw new Error("MakePay did not return a hosted checkout URL.");
    }
    const authoritativeResponse = await this.remoteCall(
      "MakePay payment-link verification failed.",
      () => client.getPaymentLink(uid),
    );
    const { paymentLink, providerStatus } = this.assertPaymentLinkSnapshot(
      authoritativeResponse,
      {
        amount: payload.amount,
        companyId: installation?.companyId,
        currency: currency_code,
        installationId: installation?.installationId,
        sessionId,
        uid,
      },
    );
    const url = getPaymentLinkUrl(paymentLink);
    if (!url) {
      throw new Error("MakePay did not return a hosted checkout URL.");
    }
    if (!MAKEPAY_UNPAID_START_STATUSES.has(providerStatus)) {
      throw new Error("MakePay created a payment link in an unsafe state.");
    }
    if (this.options_.authMode === "oauth") {
      const currentInstallation = await moduleService!.getInstallationContext();
      if (
        currentInstallation.companyId !== installation!.companyId ||
        currentInstallation.grantId !== installation!.grantId ||
        currentInstallation.installationId !== installation!.installationId ||
        currentInstallation.webhookSubscriptionId !==
          installation!.webhookSubscriptionId
      ) {
        throw new Error(
          "MakePay OAuth connection changed while checkout was being created. Retry the payment session.",
        );
      }
    }
    const providerData = buildProviderData({
      amount: payload.amount,
      checkoutBaseUrl: this.options_.checkoutBaseUrl,
      existing: data,
      fiatCurrency: currency_code.toUpperCase(),
      paymentLink,
      returnState,
      sessionId,
      status: "pending_authorization",
    });

    await moduleService?.upsertProjection({
      amount: String(payload.amount),
      auth_mode: this.options_.authMode,
      company_id:
        installation?.companyId ??
        getText(
          (authoritativeResponse as unknown as Record<string, unknown>)
            .companyId,
        ) ??
        null,
      grant_id: installation?.grantId ?? null,
      installation_id: installation?.installationId ?? null,
      currency: currency_code.toUpperCase(),
      customer_email: getText(payload.customerEmail) ?? null,
      dashboard_url:
        getSafeExternalUrl(paymentLink.dashboardUrl) ??
        getSafeExternalUrl(paymentLink.adminUrl) ??
        null,
      metadata: {
        medusaProviderId: this.options_.providerId,
        source: "medusa",
      },
      payment_link_uid: uid,
      medusa_status: "pending_authorization",
      order_display_id: null,
      order_id: null,
      payment_id: null,
      provider_status: providerStatus,
      public_url: url,
      return_state_hash: sha256(returnState),
      session_id: sessionId,
      webhook_subscription_id: installation?.webhookSubscriptionId ?? null,
    });

    return {
      data: providerData,
      id: uid,
      status: this.toPaymentSessionStatus("pending_authorization"),
    };
  }

  async authorizePayment({
    data,
  }: AuthorizePaymentInput): Promise<AuthorizePaymentOutput> {
    const locallyVerified = await this.locallyVerifiedCompletePayment(data);
    if (locallyVerified) {
      return {
        data: locallyVerified,
        status: this.toPaymentSessionStatus("captured"),
      };
    }
    const providerData = await this.retrieveProviderData(data);
    const status = this.normalizedProviderDataStatus(providerData);
    return {
      data: providerData,
      status: this.toPaymentSessionStatus(
        status === "pending" ? "pending_authorization" : status,
      ),
    };
  }

  async getPaymentStatus({
    data,
  }: GetPaymentStatusInput): Promise<GetPaymentStatusOutput> {
    const providerData = await this.retrieveProviderData(data);
    return {
      data: providerData,
      status: this.toPaymentSessionStatus(
        this.normalizedProviderDataStatus(providerData),
      ),
    };
  }

  async retrievePayment({
    data,
  }: RetrievePaymentInput): Promise<RetrievePaymentOutput> {
    return { data: await this.retrieveProviderData(data) };
  }

  async updatePayment({
    amount,
    currency_code,
    data,
    context,
  }: UpdatePaymentInput): Promise<UpdatePaymentOutput> {
    const terminalState = terminalSessionStateFromContext(context);
    const lateSuccessfulSession = isLateSuccessfulSessionUpdateContext(context);
    if (terminalState || lateSuccessfulSession) {
      const uid = getPaymentLinkUid(data);
      const sessionId = getSessionIdFromData(data);
      const moduleService = this.moduleService();
      const projection =
        uid && moduleService ? await moduleService.projectionByUid(uid) : undefined;
      const providerStatus = String(
        projection?.provider_status ?? "",
      ).toLowerCase();
      const terminalMatches = lateSuccessfulSession
        ? providerStatus === "complete"
        : terminalState === "failed"
          ? providerStatus === "failed"
          : providerStatus === "cancelled" || providerStatus === "expired";
      if (
        !uid ||
        !sessionId ||
        !projection ||
        projection.auth_mode !== this.options_.authMode ||
        projection.session_id !== sessionId ||
        !terminalMatches ||
        !arePaymentAmountsEqual(
          String(projection.amount),
          normalizeAmountValue(amount),
        ) ||
        String(projection.currency).toUpperCase() !==
          currency_code.toUpperCase()
      ) {
        throw new Error(
          "MakePay rejected an unauthenticated terminal session update.",
        );
      }
      const status = lateSuccessfulSession
        ? "pending_authorization"
        : terminalState === "failed"
          ? "error"
          : "canceled";
      return {
        data: buildProviderData({
          checkoutBaseUrl: this.options_.checkoutBaseUrl,
          existing: data,
          paymentLink: data ?? {},
          status,
        }),
        status: this.toPaymentSessionStatus(status),
      };
    }
    const uid = getPaymentLinkUid(data);
    if (!uid) {
      return this.initiatePayment({
        amount,
        context,
        currency_code,
        data,
      }) as Promise<UpdatePaymentOutput>;
    }

    const { data: providerData, providerStatus } =
      await this.retrieveProviderResult(data);
    if (providerStatus === "complete") {
      const currentAmount = getPaymentLinkAmount(providerData);
      const currentCurrency = getPaymentLinkFiatCurrency(providerData);
      if (
        currentAmount === undefined ||
        !arePaymentAmountsEqual(currentAmount, normalizeAmountValue(amount)) ||
        !currentCurrency ||
        currentCurrency.toUpperCase() !== currency_code.toUpperCase()
      ) {
        throw new Error("MakePay cannot reprice a completed payment.");
      }
      return {
        data: providerData,
        status: this.toPaymentSessionStatus("captured"),
      };
    }
    if (
      shouldRefreshPaymentLinkForUpdate({
        currentData: providerData,
        nextAmount: amount,
        nextCurrencyCode: currency_code,
      })
    ) {
      void context;
      void providerStatus;
      throw new Error(
        "MakePay cannot reprice an issued payment link. Create a new Medusa payment session.",
      );
    }

    return {
      data: providerData,
      status: this.toPaymentSessionStatus(
        this.normalizedProviderDataStatus(providerData),
      ),
    };
  }

  async capturePayment({
    data,
  }: CapturePaymentInput): Promise<CapturePaymentOutput> {
    if (!getPaymentLinkUid(data)) {
      throw new Error(
        "MakePay cannot capture a payment without a payment-link UID.",
      );
    }
    const locallyVerified = await this.locallyVerifiedCompletePayment(data);
    if (locallyVerified) return { data: locallyVerified };
    const { data: providerData, providerStatus } =
      await this.retrieveProviderResult(data);
    if (providerStatus !== "complete") {
      throw new Error("MakePay cannot capture a payment that is not complete.");
    }
    return { data: providerData };
  }

  async cancelPayment({
    data,
  }: CancelPaymentInput): Promise<CancelPaymentOutput> {
    const sessionId = getSessionIdFromData(data);
    const paymentModule = this.paymentModule();
    if (sessionId && paymentModule) {
      const captured = await findFullyCapturedPayment(paymentModule, {
        amount: getPaymentLinkAmount(data),
        currency: getPaymentLinkFiatCurrency(data),
        providerId: `pp_${MAKEPAY_PROVIDER_IDENTIFIER}_${this.options_.providerId}`,
        sessionId,
      });
      if (captured) {
        throw new Error("MakePay cannot cancel a captured Medusa payment.");
      }
    }
    const { data: current, providerStatus } =
      await this.retrieveProviderResult(data);
    if (providerStatus === "complete") {
      throw new Error("MakePay cannot cancel a completed payment.");
    }
    if (["archived", "cancelled", "expired"].includes(providerStatus)) {
      const canceled = buildProviderData({
        checkoutBaseUrl: this.options_.checkoutBaseUrl,
        existing: current,
        paymentLink: current,
        status: "canceled",
      });
      const currentSessionId = getSessionIdFromData(canceled);
      const paymentLinkUid = getPaymentLinkUid(canceled);
      if (currentSessionId && paymentLinkUid) {
        await this.moduleService()?.markCanceledPayment({
          paymentLinkUid,
          sessionId: currentSessionId,
        });
      }
      return { data: canceled };
    }
    if (!MAKEPAY_UNPAID_START_STATUSES.has(providerStatus)) {
      throw new Error(
        "MakePay cannot cancel a payment after funds may have entered processing.",
      );
    }
    return { data: await this.archivePaymentLink(current) };
  }

  async deletePayment(input: DeletePaymentInput): Promise<DeletePaymentOutput> {
    return this.cancelPayment(input);
  }

  async refundPayment(
    _input: RefundPaymentInput,
  ): Promise<RefundPaymentOutput> {
    throw new MedusaError(
      MedusaError.Types.NOT_ALLOWED,
      "MakePay refunds are not supported because MakePay does not expose a merchant refund API.",
    );
  }

  async getWebhookActionAndData(
    webhookData: ProviderWebhookPayload["payload"],
  ): Promise<WebhookActionResult> {
    this.assertModuleConfiguration(this.moduleService());
    const { canonical, event, versionedEnvelope } =
      await this.parseWebhookPayload(webhookData);
    if (
      (versionedEnvelope && !canonical) ||
      (this.options_.authMode === "api_key" && versionedEnvelope) ||
      (this.options_.authMode === "oauth" && !canonical)
    ) {
      return { action: this.toPaymentAction("not_supported") };
    }
    if (!canonical) {
      return this.getLegacyWebhookActionAndData(event);
    }
    const action = canonical
      ? canonicalWebhookAction(canonical.status)
      : mapMakePayWebhookToPaymentAction(event);
    const sessionId =
      canonical?.paymentLink.metadata.medusaSessionId ??
      getSessionIdFromWebhook(event);
    const uid =
      canonical?.paymentLink.uid ?? getPaymentLinkUidFromWebhook(event);
    const amount =
      canonical?.paymentLink.fiatAmount ?? getAmountFromWebhook(event);
    if (
      action === "not_supported" ||
      !sessionId ||
      !uid ||
      amount === undefined
    ) {
      return { action: this.toPaymentAction("not_supported") };
    }

    if (canonical) {
      const deliveryIdHeader = getText(
        this.getHeader(webhookData.headers, "x-makepay-delivery-id"),
      );
      const deliveryGroupHeader = getText(
        this.getHeader(webhookData.headers, "x-makepay-delivery-group-id"),
      );
      const eventHeader = getText(
        this.getHeader(webhookData.headers, "x-makepay-event"),
      );
      if (
        deliveryIdHeader !== canonical.deliveryId ||
        deliveryGroupHeader !== canonical.deliveryGroupId ||
        eventHeader !== canonical.type
      ) {
        return { action: this.toPaymentAction("not_supported") };
      }
    }

    const moduleService = this.moduleService();
    if (moduleService) {
      const projection = await moduleService.projectionByUid(uid);
      const currency =
        canonical?.paymentLink.fiatCurrency ?? getCurrencyFromWebhook(event);
      const companyId = canonical?.companyId ?? getCompanyIdFromWebhook(event);
      const grantId = canonical?.grantId;
      const installationId =
        canonical?.installationId ?? getInstallationIdFromWebhook(event);
      const subscriptionId = canonical?.subscriptionId;
      const orderId =
        canonical?.paymentLink.metadata.medusaOrderId ??
        getOrderIdFromWebhook(event);
      const orderDisplayId =
        canonical?.paymentLink.metadata.medusaOrderDisplayId ??
        getOrderDisplayIdFromWebhook(event);
      const canonicalCreatedAt = canonical
        ? new Date(canonical.createdAt)
        : undefined;
      const orderCorrelatedAt = projection?.order_correlated_at
        ? new Date(String(projection.order_correlated_at))
        : undefined;
      const projectionCreatedAt = projection?.created_at
        ? new Date(String(projection.created_at))
        : undefined;
      const configuredWebhookTolerance = Number(
        this.options_.webhookToleranceSeconds ?? 60,
      );
      const correlationClockSkewMs =
        (Number.isFinite(configuredWebhookTolerance)
          ? Math.min(Math.max(configuredWebhookTolerance, 0), 60)
          : 60) * 1000;
      const predatesOrderCorrelation = Boolean(
        canonical &&
          projection?.order_id &&
          !orderId &&
          !orderDisplayId &&
          canonicalCreatedAt &&
          Number.isFinite(canonicalCreatedAt.getTime()) &&
          projectionCreatedAt &&
          Number.isFinite(projectionCreatedAt.getTime()) &&
          orderCorrelatedAt &&
          Number.isFinite(orderCorrelatedAt.getTime()) &&
          canonicalCreatedAt.getTime() >=
            projectionCreatedAt.getTime() - correlationClockSkewMs &&
          canonicalCreatedAt.getTime() <=
            orderCorrelatedAt.getTime() + correlationClockSkewMs,
      );
      const oauthRoutingMismatch =
        this.options_.authMode === "oauth" &&
        (!projection ||
          projection.company_id !== companyId ||
          projection.grant_id !== grantId ||
          projection.installation_id !== installationId ||
          projection.webhook_subscription_id !== subscriptionId);
      if (
        !projection ||
        projection.session_id !== sessionId ||
        !arePaymentAmountsEqual(String(projection.amount), amount) ||
        !currency ||
        String(projection.currency).toUpperCase() !== currency.toUpperCase() ||
        (projection.company_id && projection.company_id !== companyId) ||
        (projection.installation_id &&
          projection.installation_id !== installationId) ||
        oauthRoutingMismatch ||
        (projection.order_id &&
          projection.order_id !== orderId &&
          !predatesOrderCorrelation) ||
        (projection.order_display_id &&
          projection.order_display_id !== orderDisplayId &&
          !predatesOrderCorrelation)
      ) {
        return { action: this.toPaymentAction("not_supported") };
      }
      const providerStatus =
        canonical?.status ?? getMakePayProviderStatus(event);
      const deliveryGroupHeader = getText(
        this.getHeader(webhookData.headers, "x-makepay-delivery-group-id"),
      );
      const stableDeliveryGroupId =
        canonical?.deliveryGroupId ??
        deliveryGroupHeader ??
        getText(event.deliveryGroupId) ??
        getText(event.delivery_group_id);
      const deliveryId =
        stableDeliveryGroupId ??
        `legacy_${sha256(
          JSON.stringify([
            uid,
            sessionId,
            String(amount),
            currency,
            providerStatus,
          ]),
        )}`;
      const correlationHash = sha256(
        JSON.stringify({
          amount: String(amount),
          companyId,
          createdAt: canonical?.createdAt,
          currency,
          grantId,
          installationId,
          makepaySessionId: canonical?.session.id,
          orderDisplayId,
          orderId,
          providerStatus,
          sessionId,
          subscriptionId,
          uid,
        }),
      );
      const result = await moduleService.recordWebhook(
        {
          amount,
          companyId,
          createdAt: canonical?.createdAt,
          currency,
          deliveryId,
          eventType: getWebhookEventType(event),
          grantId,
          payloadHash: correlationHash,
          providerStatus,
          sessionId,
          installationId,
          orderDisplayId,
          orderId,
          subscriptionId,
          uid,
        },
        action === "failed" || action === "canceled"
          ? () =>
              this.updateTerminalPaymentSession(
                sessionId,
                action,
                uid,
                amount,
                currency!,
              )
          : undefined,
        action === "captured"
          ? () => this.findCapturedPayment(sessionId, amount, currency)
          : undefined,
        action === "captured"
          ? () =>
              this.prepareSuccessfulPaymentSession(
                sessionId,
                uid,
                amount,
                currency!,
              )
          : undefined,
      );
      if (result === "rejected") {
        return { action: this.toPaymentAction("not_supported") };
      }
      if (result === "in_progress") {
        throw new Error("MakePay payment processing is still in progress.");
      }
      if (result === "duplicate") {
        return {
          action: this.toPaymentAction("not_supported"),
          data: { amount, session_id: sessionId },
        };
      }
    }

    return {
      action: this.toPaymentAction(action),
      data: { amount, session_id: sessionId },
    };
  }

  private async getLegacyWebhookActionAndData(
    event: Record<string, unknown>,
  ): Promise<WebhookActionResult> {
    const legacy = exactLegacyWebhook(event);
    if (!legacy) {
      return { action: this.toPaymentAction("not_supported") };
    }
    const client = await this.client();
    const response = await this.remoteCall(
      "MakePay legacy payment verification failed.",
      () => client.getPaymentLink(legacy.uid),
    );
    const remoteLink = getPaymentLinkFromResponse(response);
    const remotePayload = getNestedRecord(remoteLink, "payload");
    const remoteMetadata = isRecord(remoteLink.metadata)
      ? remoteLink.metadata
      : undefined;
    const remoteLatestSession =
      getNestedRecord(remoteLink, "latestSession") ??
      getNestedRecord(remoteLink, "session");
    const remoteMerchantOrderId =
      getText(remoteLink.orderId) ??
      getText(remoteLink.order_id) ??
      getText(remotePayload?.orderId) ??
      getText(remotePayload?.order_id);
    const remotePayloadAmount = getNumberOrText(remotePayload?.amount);
    const remoteSettlementCurrency = getText(remotePayload?.currency);
    const remoteMakePaySessionId = getText(remoteLatestSession?.id);
    if (
      remoteMerchantOrderId !== legacy.merchantOrderId ||
      remotePayloadAmount === undefined ||
      !arePaymentAmountsEqual(remotePayloadAmount, legacy.amount) ||
      !remoteSettlementCurrency ||
      remoteSettlementCurrency.toUpperCase() !== legacy.currency.toUpperCase() ||
      remoteMakePaySessionId !== legacy.makepaySessionId
    ) {
      throw new Error("MakePay legacy webhook correlation failed.");
    }

    const moduleService = this.moduleService();
    let projection = await moduleService?.projectionByUid(legacy.uid);
    let amount: string | number;
    let companyId: string | undefined;
    let currency: string;
    let orderDisplayId: string | undefined;
    let orderId: string | undefined;
    let providerStatus: string;
    let sessionId: string;
    if (projection) {
      if (projection.auth_mode !== "api_key") {
        throw new Error(
          "MakePay legacy webhook belongs to another authentication mode.",
        );
      }
      const snapshot = this.assertPaymentLinkSnapshot(response, {
        amount: String(projection.amount),
        companyId: getText(projection.company_id),
        currency: String(projection.currency),
        sessionId: String(projection.session_id),
        uid: legacy.uid,
      });
      if (
        snapshot.providerStatus !== legacy.providerStatus
      ) {
        throw new Error("MakePay legacy webhook snapshot is inconsistent.");
      }
      const reconciled = await moduleService!.reconcileProjectionFromResponse(
        projection,
        response,
      );
      if (String(reconciled.provider_status) !== snapshot.providerStatus) {
        throw new Error("MakePay legacy webhook is stale or reordered.");
      }
      amount = String(reconciled.amount);
      companyId = getText(reconciled.company_id);
      currency = String(reconciled.currency);
      orderDisplayId = getText(reconciled.order_display_id);
      orderId = getText(reconciled.order_id);
      providerStatus = snapshot.providerStatus;
      sessionId = String(reconciled.session_id);
    } else {
      const remoteAmount = getPaymentLinkAmount(response);
      const remoteCurrency = getPaymentLinkFiatCurrency(response);
      const remoteMedusaSessionId = getText(remoteMetadata?.medusaSessionId);
      if (
        remoteAmount === undefined ||
        !remoteCurrency ||
        !remoteMedusaSessionId ||
        getText(remoteMetadata?.medusaProviderId) !== this.options_.providerId
      ) {
        throw new Error(
          "MakePay legacy webhook response is missing Medusa correlation.",
        );
      }
      const snapshot = this.assertPaymentLinkSnapshot(response, {
        amount: remoteAmount,
        currency: remoteCurrency,
        sessionId: remoteMedusaSessionId,
        uid: legacy.uid,
      });
      if (
        snapshot.providerStatus !== legacy.providerStatus
      ) {
        throw new Error("MakePay legacy webhook snapshot is inconsistent.");
      }
      const paymentModule = this.paymentModule();
      if (!paymentModule) {
        throw new Error(
          "MakePay cannot recover a legacy payment without Medusa's payment module.",
        );
      }
      const paymentSession = await paymentModule.retrievePaymentSession(
        remoteMedusaSessionId,
      );
      const paymentSessionData = isRecord(paymentSession.data)
        ? paymentSession.data
        : undefined;
      let paymentSessionAmount: string | number;
      try {
        paymentSessionAmount = normalizeAmountValue(paymentSession.amount);
      } catch {
        throw new Error(
          "MakePay legacy payment-session amount could not be verified.",
        );
      }
      if (
        paymentSession.id !== remoteMedusaSessionId ||
        paymentSession.provider_id !==
          `pp_${MAKEPAY_PROVIDER_IDENTIFIER}_${this.options_.providerId}` ||
        getPaymentLinkUid(paymentSessionData) !== legacy.uid ||
        getSessionIdFromData(paymentSessionData) !== remoteMedusaSessionId ||
        !arePaymentAmountsEqual(paymentSessionAmount, remoteAmount) ||
        String(paymentSession.currency_code).toUpperCase() !==
          remoteCurrency.toUpperCase()
      ) {
        throw new Error(
          "MakePay legacy payment-session correlation failed.",
        );
      }
      amount = remoteAmount;
      companyId = getText(
        (response as unknown as Record<string, unknown>).companyId,
      );
      currency = remoteCurrency;
      orderDisplayId = getText(remoteMetadata?.medusaOrderDisplayId);
      orderId = getText(remoteMetadata?.medusaOrderId);
      providerStatus = snapshot.providerStatus;
      sessionId = remoteMedusaSessionId;
      if (moduleService) {
        const existingSessionProjection =
          await moduleService.projectionBySession(sessionId);
        if (
          existingSessionProjection &&
          existingSessionProjection.payment_link_uid !== legacy.uid
        ) {
          throw new Error(
            "MakePay legacy payment session is already linked to another payment.",
          );
        }
        projection = await moduleService.upsertProjection({
          amount: String(amount),
          auth_mode: "api_key",
          company_id: companyId ?? null,
          currency: currency.toUpperCase(),
          customer_email: null,
          dashboard_url:
            getSafeExternalUrl(remoteLink.dashboardUrl) ??
            getSafeExternalUrl(remoteLink.adminUrl) ??
            null,
          grant_id: null,
          installation_id: null,
          medusa_status: "pending_authorization",
          metadata: { migrated_from: "0.2.x" },
          order_display_id: orderDisplayId ?? null,
          order_id: orderId ?? null,
          payment_link_uid: legacy.uid,
          provider_status: providerStatus,
          public_url:
            getSafeHostedPaymentUrl(
              getPaymentLinkUrl(remoteLink),
              legacy.uid,
              this.options_.checkoutBaseUrl,
            ) ?? null,
          return_state_hash: null,
          session_id: sessionId,
          webhook_subscription_id: null,
        });
      }
    }

    const bodyPaymentLink = getNestedRecord(event, "paymentLink");
    const bodyMetadata = getNestedRecord(bodyPaymentLink ?? {}, "metadata");
    const bodyCompanyId = getText(event.companyId);
    const bodyFiatCurrency =
      getText(bodyPaymentLink?.fiatCurrency) ??
      getText(bodyPaymentLink?.fiat_currency);
    if (
      (bodyCompanyId && bodyCompanyId !== companyId) ||
      (bodyFiatCurrency && bodyFiatCurrency.toUpperCase() !== currency) ||
      (getText(bodyMetadata?.medusaSessionId) &&
        getText(bodyMetadata?.medusaSessionId) !== sessionId) ||
      (getText(bodyMetadata?.medusaOrderId) &&
        getText(bodyMetadata?.medusaOrderId) !== orderId) ||
      (getText(bodyMetadata?.medusaOrderDisplayId) &&
        getText(bodyMetadata?.medusaOrderDisplayId) !== orderDisplayId) ||
      (getText(bodyMetadata?.medusaProviderId) &&
        getText(bodyMetadata?.medusaProviderId) !== this.options_.providerId) ||
      (getText(bodyMetadata?.medusaInstallationId) &&
        getText(bodyMetadata?.medusaInstallationId) !==
          getText(remoteMetadata?.medusaInstallationId))
    ) {
      throw new Error("MakePay legacy webhook optional correlation failed.");
    }

    const action =
      providerStatus === "complete"
        ? "captured"
        : providerStatus === "failed"
          ? "failed"
          : providerStatus === "expired" || providerStatus === "cancelled"
            ? "canceled"
            : MAKEPAY_UNPAID_START_STATUSES.has(providerStatus) ||
                [
                  "deposit_received",
                  "swapping",
                  "sending",
                  "underpaid",
                ].includes(providerStatus)
              ? "pending"
              : "not_supported";
    if (action === "not_supported") {
      return { action: this.toPaymentAction("not_supported") };
    }
    if (moduleService) {
      const correlationHash = sha256(
        JSON.stringify({
          amount: canonicalPaymentAmount(amount),
          companyId,
          currency,
          eventType: legacy.eventType,
          makepaySessionId: legacy.makepaySessionId,
          orderDisplayId,
          orderId,
          providerStatus,
          settlementCurrency: legacy.currency.toUpperCase(),
          sessionId,
          uid: legacy.uid,
        }),
      );
      const result = await moduleService.recordWebhook(
        {
          amount,
          companyId,
          currency,
          deliveryId: `legacy_${correlationHash}`,
          eventType: legacy.eventType,
          orderDisplayId,
          orderId,
          payloadHash: correlationHash,
          providerStatus,
          sessionId,
          uid: legacy.uid,
        },
        action === "failed" || action === "canceled"
          ? () =>
              this.updateTerminalPaymentSession(
                sessionId,
                action,
                legacy.uid,
                amount,
                currency,
              )
          : undefined,
        action === "captured"
          ? () => this.findCapturedPayment(sessionId, amount, currency)
          : undefined,
        action === "captured"
          ? () =>
              this.prepareSuccessfulPaymentSession(
                sessionId,
                legacy.uid,
                amount,
                currency,
              )
          : undefined,
      );
      if (result === "rejected") {
        return { action: this.toPaymentAction("not_supported") };
      }
      if (result === "in_progress") {
        throw new Error("MakePay payment processing is still in progress.");
      }
      if (result === "duplicate") {
        return {
          action: this.toPaymentAction("not_supported"),
          data: { amount, session_id: sessionId },
        };
      }
    }
    return {
      action: this.toPaymentAction(action),
      data: { amount, session_id: sessionId },
    };
  }

  private buildPaymentLinkPayload(input: {
    amount: InitiatePaymentInput["amount"];
    currencyCode: string;
    data?: Record<string, unknown>;
    context?: InitiatePaymentInput["context"];
    installationId?: string;
    orderCorrelation?: {
      orderDisplayId?: string;
      orderId?: string;
    };
    returnState: string;
    sessionId: string;
  }): MakePayPaymentLinkPayload {
    const customer = input.context?.customer;
    const title =
      getText(input.data?.title) ??
      getText(input.data?.payment_description) ??
      `Medusa payment ${input.sessionId}`;
    const managedReturnUrl =
      this.options_.backendUrl && this.options_.storefrontReturnUrl
        ? `${this.options_.backendUrl.replace(/\/+$/, "")}/makepay/checkout/return?state=${encodeURIComponent(
            input.returnState,
          )}`
        : undefined;
    const returnUrl = managedReturnUrl ?? this.options_.returnUrl;
    const successUrl =
      managedReturnUrl ?? this.options_.successUrl ?? returnUrl;
    const failureUrl =
      managedReturnUrl ?? this.options_.failureUrl ?? returnUrl;
    const clientId =
      getText(input.data?.client_id) ??
      getText(customer?.id) ??
      getText(customer?.email);
    const customerEmail =
      normalizeCustomerEmail(input.data?.customer_email) ??
      normalizeCustomerEmail(customer?.email);

    return {
      amount: normalizeAmountValue(input.amount),
      clientId,
      currency: this.options_.settlementCurrency,
      customerEmail,
      description:
        getText(input.data?.description) ?? DEFAULT_PAYMENT_DESCRIPTION,
      expirationTime: this.options_.expirationTime,
      failureUrl,
      fiatCurrency: input.currencyCode.toUpperCase(),
      metadata: {
        medusaAdminUrl:
          input.orderCorrelation?.orderId && this.options_.backendUrl
            ? `${this.options_.backendUrl.replace(/\/+$/, "")}${
                this.options_.adminPath === "/"
                  ? ""
                  : (this.options_.adminPath ?? "/app")
              }/orders/${encodeURIComponent(input.orderCorrelation.orderId)}`
            : undefined,
        medusaInstallationId: input.installationId,
        medusaOrderDisplayId: input.orderCorrelation?.orderDisplayId ?? null,
        medusaOrderId: input.orderCorrelation?.orderId ?? null,
        medusaProviderId: this.options_.providerId,
        medusaSessionId: input.sessionId,
      },
      orderId:
        input.orderCorrelation?.orderId ??
        getText(input.data?.order_id) ??
        getText(input.data?.cart_id) ??
        input.sessionId,
      returnUrl,
      successUrl,
      title,
    };
  }

  private async retrieveProviderData(
    data: Record<string, unknown> | undefined,
  ): Promise<MakePayProviderData> {
    return (await this.retrieveProviderResult(data)).data;
  }

  private async locallyVerifiedCompletePayment(
    data: Record<string, unknown> | undefined,
  ): Promise<MakePayProviderData | undefined> {
    const uid = getPaymentLinkUid(data);
    const sessionId = getSessionIdFromData(data);
    const amount = getPaymentLinkAmount(data);
    const currency = getPaymentLinkFiatCurrency(data);
    const moduleService = this.moduleService();
    if (!uid || !sessionId || amount === undefined || !currency || !moduleService) {
      return undefined;
    }
    this.assertModuleConfiguration(moduleService);
    if (
      !moduleService.hasSynchronousWebhookAuthority({
        amount,
        currency,
        paymentLinkUid: uid,
        sessionId,
      })
    ) {
      return undefined;
    }
    const projection = await moduleService.projectionByUid(uid);
    if (
      !projection ||
      projection.auth_mode !== this.options_.authMode ||
      projection.provider_id !== this.options_.providerId ||
      projection.session_id !== sessionId ||
      String(projection.provider_status).toLowerCase() !== "complete" ||
      !arePaymentAmountsEqual(String(projection.amount), amount) ||
      String(projection.currency).toUpperCase() !== currency.toUpperCase()
    ) {
      return undefined;
    }
    return buildProviderData({
      amount: String(projection.amount),
      checkoutBaseUrl: this.options_.checkoutBaseUrl,
      existing: data,
      fiatCurrency: String(projection.currency),
      paymentLink: data ?? {},
      sessionId,
      status: "captured",
    });
  }

  private async retrieveProviderResult(
    data: Record<string, unknown> | undefined,
  ): Promise<{ data: MakePayProviderData; providerStatus: string }> {
    this.assertModuleConfiguration(this.moduleService());
    const uid = getPaymentLinkUid(data);
    if (!uid) {
      return {
        data: buildProviderData({
          checkoutBaseUrl: this.options_.checkoutBaseUrl,
          existing: data,
          paymentLink: {},
        }),
        providerStatus: "missing",
      };
    }
    const moduleService = this.moduleService();
    const projection = await moduleService?.projectionByUid(uid);
    if (projection && projection.auth_mode !== this.options_.authMode) {
      throw new Error(
        "MakePay payment belongs to a different authentication mode.",
      );
    }
    if (projection && this.options_.authMode === "oauth") {
      const installation = await moduleService!.getInstallationContext();
      if (
        installation.companyId !== projection.company_id ||
        installation.grantId !== projection.grant_id ||
        installation.installationId !== projection.installation_id ||
        installation.webhookSubscriptionId !==
          projection.webhook_subscription_id
      ) {
        throw new Error(
          "MakePay OAuth connection changed during payment retrieval.",
        );
      }
    }
    const response = await this.remoteCall(
      "MakePay payment retrieval failed.",
      async () => (await this.client()).getPaymentLink(uid),
    );
    let providerStatus: string;
    if (projection) {
      const reconciled = await moduleService!.reconcileProjectionFromResponse(
        projection,
        response,
      );
      providerStatus = String(reconciled.provider_status).toLowerCase();
    } else {
      const expectedAmount = getPaymentLinkAmount(data);
      const expectedCurrency = getPaymentLinkFiatCurrency(data);
      const sessionId = getSessionIdFromData(data);
      if (
        expectedAmount === undefined ||
        !expectedCurrency ||
        !sessionId
      ) {
        throw new Error(
          "MakePay payment data is missing required correlation fields.",
        );
      }
      ({ providerStatus } = this.assertPaymentLinkSnapshot(response, {
        amount: expectedAmount,
        currency: expectedCurrency,
        sessionId,
        uid,
      }));
    }
    const merged = this.mergeProviderResponse(data, response, providerStatus);
    return { data: merged, providerStatus };
  }

  private mergeProviderResponse(
    data: Record<string, unknown> | undefined,
    response: MakePayPaymentLinkResponse,
    statusOverride?: string,
  ): MakePayProviderData {
    const paymentLink = getPaymentLinkFromResponse(response);
    const sessionId =
      getSessionIdFromData(data) ??
      getSessionIdFromWebhook(response) ??
      getSessionIdFromWebhook(paymentLink);
    const latestSession =
      getNestedRecord(paymentLink, "latestSession") ??
      getNestedRecord(paymentLink, "session");
    const providerStatus =
      statusOverride ??
      getAuthoritativeMakePayProviderStatus({
        paymentLink,
        session: latestSession,
      });
    if (providerStatus === "conflicting_terminal") {
      throw new Error(
        "MakePay returned conflicting authoritative terminal states.",
      );
    }
    return buildProviderData({
      checkoutBaseUrl: this.options_.checkoutBaseUrl,
      existing: data,
      paymentLink,
      sessionId,
      status: mapMakePayStateToPaymentSessionStatus({ status: providerStatus }),
    });
  }

  private async archivePaymentLink(
    data: Record<string, unknown> | undefined,
  ): Promise<MakePayProviderData> {
    const uid = getPaymentLinkUid(data);
    if (!uid) {
      return buildProviderData({
        checkoutBaseUrl: this.options_.checkoutBaseUrl,
        existing: data,
        paymentLink: {},
      });
    }
    // Re-read the authenticated lifecycle for correlation, then rely on the
    // server's atomic no-session claim. Status alone is never archival proof:
    // quoted/awaiting-deposit links may already expose payable coordinates.
    const { data: current, providerStatus: currentProviderStatus } =
      await this.retrieveProviderResult(data);
    if (!MAKEPAY_UNPAID_START_STATUSES.has(currentProviderStatus)) {
      throw new Error(
        "MakePay cannot archive a payment after funds may have entered processing.",
      );
    }
    const amount = getPaymentLinkAmount(current);
    const currency = getPaymentLinkFiatCurrency(current);
    const sessionId = getSessionIdFromData(current);
    if (amount === undefined || !currency || !sessionId) {
      throw new Error("MakePay payment archival correlation is incomplete.");
    }
    const moduleService = this.moduleService();
    const projection = await moduleService?.projectionByUid(uid);
    let response: MakePayPaymentLinkResponse;
    try {
      response = await (await this.client()).updatePaymentLink(
        uid,
        { status: "archived" },
        { idempotencyKey: `medusa-archive-${uid}` },
      );
    } catch (error) {
      if (error instanceof MakePayError && error.status === 409) {
        throw new Error(
          "MakePay cannot archive this payment because a payment session or channel has started.",
        );
      }
      if (error instanceof MakePayError) {
        throw new Error("MakePay payment archival failed.");
      }
      throw error;
    }
    const responseEnvelope = response as unknown as Record<string, unknown>;
    if (
      responseEnvelope.archiveEligibility !== "no_session" ||
      responseEnvelope.archivedWithNoSession !== true ||
      !Object.hasOwn(responseEnvelope, "latestSession") ||
      responseEnvelope.latestSession !== null ||
      responseEnvelope.sessionCreationClaimed !== false
    ) {
      throw new Error(
        "MakePay did not provide atomic no-session archival proof.",
      );
    }
    const snapshot = this.assertPaymentLinkSnapshot(response, {
      amount,
      companyId: getText(projection?.company_id),
      currency,
      installationId: getText(projection?.installation_id),
      orderDisplayId: getText(projection?.order_display_id),
      orderId: getText(projection?.order_id),
      sessionId,
      uid,
    });
    const paymentLink = snapshot.paymentLink;
    if (snapshot.providerStatus === "complete") {
      throw new Error("MakePay cannot archive a completed payment.");
    }
    if (String(paymentLink.status).toLowerCase() !== "archived") {
      throw new Error("MakePay did not confirm payment-link archival.");
    }
    if (
      !Object.hasOwn(paymentLink, "latestSession") ||
      paymentLink.latestSession !== null
    ) {
      throw new Error(
        "MakePay atomic archival proof contained payment-session history.",
      );
    }
    const canceled = buildProviderData({
      checkoutBaseUrl: this.options_.checkoutBaseUrl,
      existing: this.mergeProviderResponse(current, response),
      paymentLink,
      status: "canceled",
    });
    const canceledSessionId = getSessionIdFromData(canceled);
    if (canceledSessionId) {
      await moduleService?.markCanceledPayment({
        lateSettlementSafe: true,
        paymentLinkUid: uid,
        sessionId: canceledSessionId,
      });
    }
    return canceled;
  }

  private async parseWebhookPayload(
    webhookData: ProviderWebhookPayload["payload"],
  ): Promise<{
    canonical?: CanonicalMedusaWebhook;
    event: Record<string, unknown>;
    versionedEnvelope: boolean;
  }> {
    const signature = this.getHeader(
      webhookData.headers,
      "x-makepay-signature",
    );
    const raw =
      webhookData.rawData ??
      (webhookData.data ? JSON.stringify(webhookData.data) : undefined);
    if (!raw) throw new Error("MakePay webhook raw body is required.");
    const rawBody = Buffer.isBuffer(raw) ? raw.toString("utf8") : String(raw);
    const secret =
      this.options_.authMode === "oauth"
        ? await this.requireModuleService().getWebhookSecret(rawBody)
        : this.options_.webhookSecret!;
    const parsed = parseMakePayWebhook<unknown>(rawBody, signature, secret, {
      toleranceSeconds: this.options_.webhookToleranceSeconds,
    });
    if (!isRecord(parsed)) {
      throw new Error("MakePay webhook body must be a JSON object.");
    }
    const event = parsed;
    const versionedEnvelope = Object.hasOwn(event, "schemaVersion");
    return {
      canonical:
        event.schemaVersion === "medusa.v1"
          ? canonicalMedusaWebhook(event)
          : undefined,
      event,
      versionedEnvelope,
    };
  }

  private async client(): Promise<MakePayClient> {
    const moduleService = this.moduleService();
    this.assertModuleConfiguration(moduleService);
    return this.apiKeyClient_ ?? moduleService!.createClient();
  }

  private async remoteCall<T>(
    message: string,
    job: () => Promise<T>,
  ): Promise<T> {
    try {
      return await job();
    } catch (error) {
      if (error instanceof MakePayError) {
        throw new Error(message);
      }
      throw error;
    }
  }

  private assertModuleConfiguration(
    moduleService: ModuleService | undefined,
  ): void {
    if (
      moduleService &&
      (moduleService.authMode !== this.options_.authMode ||
        moduleService.providerId !== this.options_.providerId)
    ) {
      throw new Error(
        "MakePay provider and plugin module configuration do not match.",
      );
    }
    moduleService?.registerPaymentProviderConfiguration(
      makePaySecurityConfigurationFingerprint(this.options_),
    );
  }

  private moduleService(): ModuleService | undefined {
    let injected: ModuleService | undefined;
    try {
      injected = this.container_[MAKEPAY_MODULE] as ModuleService | undefined;
    } catch {
      // Payment providers receive an Awilix cradle proxy. Reading a module
      // that is registered only in Medusa's global module registry throws
      // instead of returning undefined, so continue to the supported fallback.
    }
    if (injected) return injected;
    const loaded = MedusaModule.getModuleInstance(MAKEPAY_MODULE) as
      Record<string, unknown> | ModuleService | undefined;
    if (!loaded) return undefined;
    try {
      return ((loaded as Record<string, unknown>)[MAKEPAY_MODULE] ??
        loaded) as ModuleService;
    } catch {
      return loaded as ModuleService;
    }
  }

  private requireModuleService(): ModuleService {
    const service = this.moduleService();
    if (!service) {
      throw new Error(
        "MakePay OAuth requires the `makepayIntegration` module and its migrations.",
      );
    }
    return service;
  }

  private paymentModule(): IPaymentModuleService | undefined {
    const loaded = MedusaModule.getModuleInstance(Modules.PAYMENT) as
      Record<string, unknown> | IPaymentModuleService | undefined;
    if (!loaded) return undefined;
    return ((loaded as Record<string, unknown>)[Modules.PAYMENT] ??
      loaded) as IPaymentModuleService;
  }

  private async updateTerminalPaymentSession(
    sessionId: string,
    action: "failed" | "canceled",
    paymentLinkUid: string,
    amount: string | number,
    currency: string,
  ): Promise<"failed" | "canceled" | undefined> {
    const paymentModule = this.paymentModule();
    if (!paymentModule) {
      throw new Error(
        "MakePay could not update the terminal session because Medusa's payment module is unavailable.",
      );
    }
    return applyTerminalPaymentSessionState(paymentModule, sessionId, action, {
      amount,
      currency,
      paymentLinkUid,
      providerId: `pp_${MAKEPAY_PROVIDER_IDENTIFIER}_${this.options_.providerId}`,
    });
  }

  private async findCapturedPayment(
    sessionId: string,
    amount?: string | number,
    currency?: string,
  ): Promise<{ paymentId: string } | undefined> {
    const paymentModule = this.paymentModule();
    if (!paymentModule) return undefined;
    const payment = await findFullyCapturedPayment(paymentModule, {
      amount,
      currency,
      providerId: `pp_${MAKEPAY_PROVIDER_IDENTIFIER}_${this.options_.providerId}`,
      sessionId,
    });
    return payment ? { paymentId: payment.id } : undefined;
  }

  private async prepareSuccessfulPaymentSession(
    sessionId: string,
    paymentLinkUid: string,
    amount: string | number,
    currency: string,
  ): Promise<boolean> {
    const paymentModule = this.paymentModule();
    if (!paymentModule) {
      throw new Error(
        "MakePay could not prepare the late successful session because Medusa's payment module is unavailable.",
      );
    }
    return prepareLateSuccessfulPaymentSession(paymentModule, sessionId, {
      amount,
      currency,
      paymentLinkUid,
      providerId: `pp_${MAKEPAY_PROVIDER_IDENTIFIER}_${this.options_.providerId}`,
    });
  }

  private getHeader(
    headers: Record<string, unknown>,
    name: string,
  ): string | undefined {
    const direct = headers[name];
    if (typeof direct === "string") return direct;
    const lowerName = name.toLowerCase();
    for (const [key, value] of Object.entries(headers)) {
      if (key.toLowerCase() === lowerName) {
        if (Array.isArray(value)) {
          return typeof value[0] === "string" ? value[0] : undefined;
        }
        return typeof value === "string" ? value : undefined;
      }
    }
    return undefined;
  }

  private getSessionId(
    data: Record<string, unknown> | undefined,
    fallback?: string,
  ): string {
    const sessionId =
      getSessionIdFromData(data) ??
      getText(data?.session_id) ??
      getText(data?.id) ??
      getText(fallback);
    if (!sessionId) {
      throw new Error(
        "MakePay requires a Medusa payment session ID in data.session_id.",
      );
    }
    return sessionId;
  }

  private toPaymentSessionStatus(
    status: MakePayPaymentSessionStatus,
  ): (typeof PaymentSessionStatus)[keyof typeof PaymentSessionStatus] {
    switch (status) {
      case "captured":
        return PaymentSessionStatus.CAPTURED;
      case "canceled":
        return PaymentSessionStatus.CANCELED;
      case "error":
        return PaymentSessionStatus.ERROR;
      case "pending_authorization":
        return ((PaymentSessionStatus as unknown as Record<string, string>)
          .PENDING_AUTHORIZATION ?? PaymentSessionStatus.PENDING) as never;
      case "pending":
      default:
        return PaymentSessionStatus.PENDING;
    }
  }

  private normalizedProviderDataStatus(
    data: MakePayProviderData,
  ): MakePayPaymentSessionStatus {
    const status = data.status;
    if (
      status === "captured" ||
      status === "pending" ||
      status === "pending_authorization" ||
      status === "error" ||
      status === "canceled"
    ) {
      return status;
    }
    return mapMakePayStateToPaymentSessionStatus(data);
  }

  private toPaymentAction(
    action: MakePayPaymentAction,
  ): (typeof PaymentActions)[keyof typeof PaymentActions] {
    switch (action) {
      case "captured":
        return PaymentActions.SUCCESSFUL;
      case "failed":
        return PaymentActions.FAILED;
      case "pending":
        return PaymentActions.PENDING;
      case "canceled":
        return PaymentActions.CANCELED;
      case "not_supported":
      default:
        return PaymentActions.NOT_SUPPORTED;
    }
  }
}

export default MakePayProviderService;
