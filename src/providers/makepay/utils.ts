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
  const data = getNestedRecord(response, "data");

  for (const source of [response, data]) {
    if (!source) {
      continue;
    }

    if (isRecord(source.paymentLink)) {
      return source.paymentLink as MakePayPaymentLink;
    }

    if (isRecord(source.payment_link)) {
      return source.payment_link as MakePayPaymentLink;
    }

    if (isRecord(source.link)) {
      return source.link as MakePayPaymentLink;
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

export function getPaymentLinkUrl(link: MakePayPaymentLink): string | undefined {
  return (
    getText(link.publicUrl) ??
    getText(link.checkoutUrl) ??
    getText(link.public_url) ??
    getText(link.checkout_url) ??
    getText(link.url)
  );
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

  return (
    getNumberOrText(data.amount) ??
    getNumberOrText(data.payment_amount) ??
    getNumberOrText(link?.amount) ??
    getNumberOrText(link?.amountUsd)
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

  return (
    getText(data.fiat_currency) ??
    getText(data.fiatCurrency) ??
    getText(link?.fiatCurrency) ??
    getText(link?.fiat_currency)
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
  for (const record of collectWebhookRecords(event, { includeMetadata: true })) {
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

export function getAmountFromWebhook(event: unknown): string | number | undefined {
  for (const record of collectWebhookRecords(event)) {
    const amount =
      getNumberOrText(record.invoiceAmount) ??
      getNumberOrText(record.expectedBuyAmount) ??
      getNumberOrText(record.fiatAmount) ??
      getNumberOrText(record.amount) ??
      getNumberOrText(record.amountUsd) ??
      getNumberOrText(record.totalAmount);

    if (amount !== undefined) {
      return amount;
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

export function shouldRefreshPaymentLinkForUpdate(input: {
  currentData: unknown;
  nextAmount: BigNumberInput;
  nextCurrencyCode: string;
}): boolean {
  const status = mapMakePayStateToPaymentSessionStatus(input.currentData);

  if (status === "captured" || status === "authorized") {
    return false;
  }

  if (status === "canceled" || status === "error") {
    return true;
  }

  const currentAmount = getPaymentLinkAmount(input.currentData);
  const currentCurrency = getPaymentLinkFiatCurrency(input.currentData);

  if (
    currentAmount !== undefined &&
    !arePaymentAmountsEqual(currentAmount, normalizeAmountValue(input.nextAmount))
  ) {
    return true;
  }

  return (
    currentCurrency !== undefined &&
    currentCurrency.toUpperCase() !== input.nextCurrencyCode.toUpperCase()
  );
}

export function arePaymentAmountsEqual(
  left: string | number,
  right: string | number,
): boolean {
  const leftText = String(left).trim();
  const rightText = String(right).trim();

  if (leftText === rightText) {
    return true;
  }

  const leftNumber = Number(leftText);
  const rightNumber = Number(rightText);

  return (
    Number.isFinite(leftNumber) &&
    Number.isFinite(rightNumber) &&
    leftNumber === rightNumber
  );
}

export function buildProviderData(input: {
  existing?: Record<string, unknown>;
  paymentLink: MakePayPaymentLink;
  sessionId?: string;
  status?: MakePayPaymentSessionStatus;
  amount?: string | number;
  fiatCurrency?: string;
}): MakePayProviderData {
  const uid = getText(input.paymentLink.uid) ?? getText(input.paymentLink.id);
  const url = getPaymentLinkUrl(input.paymentLink);
  const status =
    input.status ?? mapMakePayStateToPaymentSessionStatus(input.paymentLink);
  const amount =
    input.amount ??
    getNumberOrText(input.paymentLink.amount) ??
    getNumberOrText(input.existing?.amount);
  const fiatCurrency =
    input.fiatCurrency ??
    getText(input.paymentLink.fiatCurrency) ??
    getText(input.paymentLink.fiat_currency) ??
    getText(input.existing?.fiat_currency) ??
    getText(input.existing?.fiatCurrency);

  return {
    ...(input.existing ?? {}),
    id: uid,
    amount,
    fiat_currency: fiatCurrency,
    fiatCurrency,
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
