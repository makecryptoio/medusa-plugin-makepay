import type { BigNumberInput } from "@medusajs/framework/types";
import type {
  MakePayPaymentLink,
  MakePayPaymentLinkResponse,
} from "@makecrypto/makepay";

import type {
  MakePayPaymentAction,
  MakePayPaymentSessionStatus,
  MakePayProviderData,
  MakePayProviderOptions,
} from "./types.js";

const DEFAULT_SETTLEMENT_CURRENCY = "USDT";
const DEFAULT_EXPIRATION_TIME = "12h";

const CAPTURED_STATUSES = new Set([
  "paid",
  "complete",
  "completed",
  "confirmed",
  "succeeded",
  "success",
  "captured",
  "settled",
  "payment.paid",
]);

const AUTHORIZED_STATUSES = new Set(["authorized", "requires_capture"]);

const CANCELED_STATUSES = new Set([
  "canceled",
  "cancelled",
  "expired",
  "archived",
  "void",
  "payment.expired",
  "payment_cancelled_by_payer",
  "payment_request_expired",
  "quote_expired",
]);

const FAILED_STATUSES = new Set([
  "failed",
  "error",
  "declined",
  "rejected",
  "refunded",
  "payment.failed",
]);

const REQUIRES_MORE_STATUSES = new Set([
  "active",
  "created",
  "open",
  "unpaid",
  "requires_more",
  "requires_action",
  "requires_payment_method",
]);

const PENDING_STATUSES = new Set([
  "pending",
  "processing",
  "waiting",
  "channel_created",
  "quote_created",
  "quote_refreshed",
  "settlement_updated",
  "status_changed",
]);

const WEBHOOK_CANCELED_EVENTS = new Set([
  "payment_request_expired",
  "quote_expired",
  "payment_cancelled_by_payer",
]);

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

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
): MakePayProviderOptions {
  validateMakePayProviderOptions(options);

  return {
    ...options,
    settlementCurrency:
      getText(options.settlementCurrency) ?? DEFAULT_SETTLEMENT_CURRENCY,
    expirationTime: getText(options.expirationTime) ?? DEFAULT_EXPIRATION_TIME,
  };
}

export function validateMakePayProviderOptions(
  options: Partial<MakePayProviderOptions> | null | undefined,
): asserts options is MakePayProviderOptions {
  if (!isRecord(options)) {
    throw new Error("MakePay provider options are required.");
  }

  for (const key of ["keyId", "keySecret", "webhookSecret"] as const) {
    if (!getText(options[key])) {
      throw new Error(`Required MakePay provider option \`${key}\` is missing.`);
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

export function getPaymentLinkFromResponse(
  response: MakePayPaymentLinkResponse | Record<string, unknown>,
): MakePayPaymentLink {
  if (isRecord(response.paymentLink)) {
    return response.paymentLink as MakePayPaymentLink;
  }

  if (isRecord(response.payment_link)) {
    return response.payment_link as MakePayPaymentLink;
  }

  if (isRecord(response.link)) {
    return response.link as MakePayPaymentLink;
  }

  return {};
}

export function getPaymentLinkUid(data: unknown): string | undefined {
  if (!isRecord(data)) {
    return undefined;
  }

  const link = getNestedRecord(data, "paymentLink");

  return (
    getText(data.payment_link_uid) ??
    getText(data.paymentLinkUid) ??
    getText(data.payment_link_id) ??
    getText(data.id) ??
    getText(link?.uid) ??
    getText(link?.id)
  );
}

export function getPaymentLinkUrl(link: MakePayPaymentLink): string | undefined {
  return (
    getText(link.publicUrl) ??
    getText(link.checkoutUrl) ??
    getText(link.url)
  );
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
  if (!isRecord(event)) {
    return undefined;
  }

  const paymentLink = getNestedRecord(event, "paymentLink");
  const payment = getNestedRecord(event, "payment");
  const data = getNestedRecord(event, "data");
  const linkPayload = paymentLink ? getNestedRecord(paymentLink, "payload") : undefined;
  const linkMetadata = paymentLink ? getNestedRecord(paymentLink, "metadata") : undefined;
  const payloadMetadata = linkPayload
    ? getNestedRecord(linkPayload, "metadata")
    : undefined;
  const paymentMetadata = payment ? getNestedRecord(payment, "metadata") : undefined;

  return (
    getText(data?.session_id) ??
    getText(data?.medusaSessionId) ??
    getText(linkMetadata?.session_id) ??
    getText(linkMetadata?.medusaSessionId) ??
    getText(payloadMetadata?.session_id) ??
    getText(payloadMetadata?.medusaSessionId) ??
    getText(paymentMetadata?.session_id) ??
    getText(paymentMetadata?.medusaSessionId)
  );
}

export function getAmountFromWebhook(event: unknown): string | number | undefined {
  if (!isRecord(event)) {
    return undefined;
  }

  const session = getNestedRecord(event, "session");
  const paymentLink = getNestedRecord(event, "paymentLink");
  const payment = getNestedRecord(event, "payment");
  const data = getNestedRecord(event, "data");

  return (
    getNumberOrText(session?.invoiceAmount) ??
    getNumberOrText(session?.expectedBuyAmount) ??
    getNumberOrText(payment?.amount) ??
    getNumberOrText(payment?.fiatAmount) ??
    getNumberOrText(paymentLink?.amount) ??
    getNumberOrText(data?.amount)
  );
}

export function collectStatusValues(input: unknown): string[] {
  if (!isRecord(input)) {
    return [];
  }

  const values: string[] = [];
  const nestedKeys = ["paymentLink", "payment", "session", "data"];

  for (const key of ["status", "paymentStatus", "state", "type"]) {
    const value = getText(input[key]);
    if (value) {
      values.push(value.toLowerCase());
    }
  }

  for (const key of nestedKeys) {
    const record = getNestedRecord(input, key);
    if (!record) {
      continue;
    }

    for (const statusKey of ["status", "paymentStatus", "state", "type"]) {
      const value = getText(record[statusKey]);
      if (value) {
        values.push(value.toLowerCase());
      }
    }
  }

  const event = getNestedRecord(input, "event");
  const eventType = getText(event?.type);
  if (eventType) {
    values.push(eventType.toLowerCase());
  }

  return values;
}

export function mapMakePayStateToPaymentSessionStatus(
  input: unknown,
): MakePayPaymentSessionStatus {
  const statuses = collectStatusValues(input);

  if (statuses.some((status) => CAPTURED_STATUSES.has(status))) {
    return "captured";
  }

  if (statuses.some((status) => AUTHORIZED_STATUSES.has(status))) {
    return "authorized";
  }

  if (statuses.some((status) => CANCELED_STATUSES.has(status))) {
    return "canceled";
  }

  if (statuses.some((status) => FAILED_STATUSES.has(status))) {
    return "error";
  }

  if (statuses.some((status) => REQUIRES_MORE_STATUSES.has(status))) {
    return "requires_more";
  }

  if (statuses.some((status) => PENDING_STATUSES.has(status))) {
    return "pending";
  }

  return "pending";
}

export function mapMakePayWebhookToPaymentAction(
  event: unknown,
): MakePayPaymentAction {
  const statuses = collectStatusValues(event);

  if (statuses.some((status) => CAPTURED_STATUSES.has(status))) {
    return "captured";
  }

  if (statuses.some((status) => AUTHORIZED_STATUSES.has(status))) {
    return "authorized";
  }

  if (
    statuses.some(
      (status) =>
        CANCELED_STATUSES.has(status) || WEBHOOK_CANCELED_EVENTS.has(status),
    )
  ) {
    return "canceled";
  }

  if (statuses.some((status) => FAILED_STATUSES.has(status))) {
    return "failed";
  }

  if (statuses.some((status) => REQUIRES_MORE_STATUSES.has(status))) {
    return "requires_more";
  }

  if (statuses.some((status) => PENDING_STATUSES.has(status))) {
    return "pending";
  }

  return "not_supported";
}

export function buildProviderData(input: {
  existing?: Record<string, unknown>;
  paymentLink: MakePayPaymentLink;
  sessionId?: string;
  status?: MakePayPaymentSessionStatus;
}): MakePayProviderData {
  const uid = getText(input.paymentLink.uid) ?? getText(input.paymentLink.id);
  const url = getPaymentLinkUrl(input.paymentLink);
  const status =
    input.status ?? mapMakePayStateToPaymentSessionStatus(input.paymentLink);

  return {
    ...(input.existing ?? {}),
    id: uid,
    payment_link_uid: uid,
    paymentLinkUid: uid,
    public_url: url,
    checkout_url: url,
    session_id: input.sessionId,
    status,
    paymentLink: input.paymentLink,
    next_action: url
      ? {
          type: "redirect",
          url,
        }
      : undefined,
  };
}
