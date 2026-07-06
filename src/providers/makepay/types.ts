export type MakePayExpirationTime =
  | "15m"
  | "1h"
  | "12h"
  | "24h"
  | "72h"
  | "never"
  | string;

export type MakePayProviderOptions = {
  keyId: string;
  keySecret: string;
  webhookSecret: string;
  baseUrl?: string;
  checkoutBaseUrl?: string;
  settlementCurrency?: string;
  expirationTime?: MakePayExpirationTime;
  returnUrl?: string;
  successUrl?: string;
  failureUrl?: string;
  webhookToleranceSeconds?: number;
  fetch?: typeof fetch;
};

export type NormalizedMakePayProviderOptions = Required<
  Pick<
    MakePayProviderOptions,
    "keyId" | "keySecret" | "webhookSecret" | "settlementCurrency" | "expirationTime"
  >
> &
  Pick<
    MakePayProviderOptions,
    | "baseUrl"
    | "checkoutBaseUrl"
    | "returnUrl"
    | "successUrl"
    | "failureUrl"
    | "webhookToleranceSeconds"
    | "fetch"
  >;

export type MakePayProviderData = Record<string, unknown> & {
  id?: string;
  amount?: string | number;
  fiat_currency?: string;
  fiatCurrency?: string;
  payment_link_uid?: string;
  public_url?: string;
  checkout_url?: string;
  session_id?: string;
  status?: string;
  next_action?: {
    type: "redirect";
    url: string;
  };
};

export type MakePayPaymentSessionStatus =
  | "authorized"
  | "captured"
  | "pending"
  | "requires_more"
  | "error"
  | "canceled";

export type MakePayPaymentAction =
  | "authorized"
  | "captured"
  | "failed"
  | "pending"
  | "requires_more"
  | "canceled"
  | "not_supported";
