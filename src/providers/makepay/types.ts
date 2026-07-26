export type MakePayExpirationTime =
  | "15m"
  | "1h"
  | "12h"
  | "24h"
  | "72h"
  | "never"
  | string;

export type MakePayAuthMode = "api_key" | "oauth";

export type MakePayCommonOptions = {
  authMode?: MakePayAuthMode;
  baseUrl?: string;
  checkoutBaseUrl?: string;
  settlementCurrency?: string;
  expirationTime?: MakePayExpirationTime;
  returnUrl?: string;
  successUrl?: string;
  failureUrl?: string;
  webhookToleranceSeconds?: number;
  fetch?: typeof fetch;
  /** Public origin of the Medusa backend, such as https://api.shop.test. */
  backendUrl?: string;
  /** Storefront destination after MakePay has been reconciled server-side. */
  storefrontReturnUrl?: string;
  /** MakeCrypto OAuth issuer. Defaults to https://www.makecrypto.io. */
  oauthIssuerUrl?: string;
  /**
   * OAuth resource/audience. The official MakeCrypto resource defaults to
   * https://makecrypto.io/api/partner/v1; custom issuers derive
   * `<issuer>/api/partner/v1`.
   */
  oauthAudience?: string;
  /** MakeCrypto OAuth/API origin. Defaults to `baseUrl` or the SDK default. */
  oauthApiUrl?: string;
  /** Base64-encoded 32-byte key used only for OAuth material at rest. */
  encryptionKey?: string;
  /**
   * Raw Medusa locking-provider id used for cross-process OAuth and webhook
   * serialization. Configure a distributed provider such as
   * `makepay-postgres`; the in-memory provider is intentionally rejected.
   */
  lockingProvider?: string;
  /** Stable provider configuration id. Defaults to `makepay`. */
  providerId?: string;
  /** Optional installation display name shown during OAuth consent. */
  siteName?: string;
  /** Medusa Admin base path. Defaults to `/app`. */
  adminPath?: string;
  /** Reported to MakeCrypto during native installation registration. */
  medusaVersion?: string;
};

export type MakePayApiKeyProviderOptions = MakePayCommonOptions & {
  authMode?: "api_key";
  keyId: string;
  keySecret: string;
  webhookSecret: string;
};

export type MakePayOAuthProviderOptions = MakePayCommonOptions & {
  authMode: "oauth";
  backendUrl: string;
  storefrontReturnUrl: string;
  encryptionKey: string;
  lockingProvider: string;
  keyId?: never;
  keySecret?: never;
  webhookSecret?: never;
};

export type MakePayProviderOptions =
  | MakePayApiKeyProviderOptions
  | MakePayOAuthProviderOptions;

export type NormalizedMakePayProviderOptions = MakePayCommonOptions & {
  authMode: MakePayAuthMode;
  settlementCurrency: string;
  expirationTime: MakePayExpirationTime;
  providerId: string;
  keyId?: string;
  keySecret?: string;
  webhookSecret?: string;
  backendUrl?: string;
  storefrontReturnUrl?: string;
  encryptionKey?: string;
};

export type MakePayProviderData = Record<string, unknown> & {
  amount?: string | number;
  fiat_currency?: string;
  payment_link_uid?: string;
  public_url?: string;
  session_id?: string;
  status?: string;
  return_state?: string;
  next_action?: {
    type: "redirect";
    url: string;
  };
};

export type MakePayPaymentSessionStatus =
  | "captured"
  | "pending"
  | "pending_authorization"
  | "error"
  | "canceled";

export type MakePayPaymentAction =
  | "captured"
  | "failed"
  | "pending"
  | "canceled"
  | "not_supported";
