declare module "@makecrypto/makepay" {
  export type MakePayPaymentLinkPayload = {
    title?: string;
    description?: string;
    amount: string | number;
    currency?: string;
    fiatCurrency?: string;
    orderId?: string;
    customerEmail?: string;
    clientId?: string;
    returnUrl?: string;
    successUrl?: string;
    failureUrl?: string;
    expirationTime?: string;
    metadata?: Record<string, unknown>;
    [key: string]: unknown;
  };

  export type MakePayPaymentLink = {
    id?: string;
    uid?: string;
    publicUrl?: string;
    checkoutUrl?: string;
    url?: string;
    status?: string;
    amount?: string | number | null;
    currency?: string | null;
    metadata?: Record<string, unknown>;
    payload?: Record<string, unknown>;
    [key: string]: unknown;
  };

  export type MakePayPaymentLinkResponse = {
    paymentLink?: MakePayPaymentLink;
    payment_link?: MakePayPaymentLink;
    [key: string]: unknown;
  };

  export class MakePayClient {
    constructor(options: {
      baseUrl?: string;
      checkoutBaseUrl?: string;
      keyId: string;
      keySecret: string;
      fetch?: typeof fetch;
    });

    createPaymentLink(
      payload: MakePayPaymentLinkPayload,
      options?: {
        status?: "active" | "paused" | "archived";
        sendPaymentRequestEmail?: boolean;
      },
    ): Promise<MakePayPaymentLinkResponse>;

    getPaymentLink(uid: string): Promise<MakePayPaymentLinkResponse>;

    updatePaymentLink(
      uid: string,
      updates: { status: "active" | "paused" | "archived" },
    ): Promise<MakePayPaymentLinkResponse>;
  }

  export function parseMakePayWebhook<T = Record<string, unknown>>(
    rawBody: string | Buffer,
    signatureHeader: string | null | undefined,
    secret: string,
    options?: { toleranceSeconds?: number },
  ): T;
}

declare module "@medusajs/framework/types" {
  export type BigNumberInput =
    | string
    | number
    | {
        value?: string | number;
        numeric?: number;
        raw?: { value?: string | number };
        [key: string]: unknown;
      };

  export type PaymentCustomerDTO = {
    id: string;
    email: string;
    company_name?: string | null;
    first_name?: string | null;
    last_name?: string | null;
    phone?: string | null;
    billing_address?: Record<string, unknown> | null;
    [key: string]: unknown;
  };

  export type PaymentProviderContext = {
    account_holder?: { data: Record<string, unknown> };
    customer?: PaymentCustomerDTO;
    idempotency_key?: string;
    [key: string]: unknown;
  };

  export type InitiatePaymentInput = {
    amount: BigNumberInput;
    currency_code: string;
    data?: Record<string, unknown>;
    context?: PaymentProviderContext;
  };

  export type InitiatePaymentOutput = {
    id: string;
    data?: Record<string, unknown>;
    status?: string;
  };

  export type AuthorizePaymentInput = {
    data?: Record<string, unknown>;
  };

  export type AuthorizePaymentOutput = {
    data?: Record<string, unknown>;
    status?: string;
  };

  export type CancelPaymentInput = {
    data?: Record<string, unknown>;
  };

  export type CancelPaymentOutput = {
    data?: Record<string, unknown>;
  };

  export type CapturePaymentInput = {
    data?: Record<string, unknown>;
  };

  export type CapturePaymentOutput = {
    data?: Record<string, unknown>;
  };

  export type DeletePaymentInput = CancelPaymentInput;
  export type DeletePaymentOutput = CancelPaymentOutput;

  export type GetPaymentStatusInput = {
    data?: Record<string, unknown>;
  };

  export type GetPaymentStatusOutput = {
    data?: Record<string, unknown>;
    status?: string;
  };

  export type RefundPaymentInput = {
    amount: BigNumberInput;
    data?: Record<string, unknown>;
  };

  export type RefundPaymentOutput = {
    data?: Record<string, unknown>;
  };

  export type RetrievePaymentInput = {
    data?: Record<string, unknown>;
  };

  export type RetrievePaymentOutput = {
    data?: Record<string, unknown>;
  };

  export type UpdatePaymentInput = {
    amount: BigNumberInput;
    currency_code: string;
    data?: Record<string, unknown>;
    context?: PaymentProviderContext;
  };

  export type UpdatePaymentOutput = {
    data?: Record<string, unknown>;
    status?: string;
  };

  export type ProviderWebhookPayload = {
    payload: {
      data?: Record<string, unknown>;
      rawData?: string | Buffer;
      headers: Record<string, string | string[] | undefined>;
    };
  };

  export type WebhookActionResult =
    | {
        action: string;
        data?: {
          session_id: string;
          amount: string | number;
        };
      }
    | { action: string };
}

declare module "@medusajs/framework/utils" {
  export abstract class AbstractPaymentProvider<
    TConfig = Record<string, unknown>,
  > {
    protected readonly container: Record<string, unknown>;
    protected readonly config: TConfig;
    protected constructor(
      cradle: Record<string, unknown>,
      config?: TConfig,
    );
    static identifier: string;
  }

  export const PaymentSessionStatus: {
    AUTHORIZED: "authorized";
    CAPTURED: "captured";
    PENDING: "pending";
    REQUIRES_MORE: "requires_more";
    ERROR: "error";
    CANCELED: "canceled";
  };

  export const PaymentActions: {
    AUTHORIZED: "authorized";
    SUCCESSFUL: "captured";
    FAILED: "failed";
    PENDING: "pending";
    REQUIRES_MORE: "requires_more";
    CANCELED: "canceled";
    NOT_SUPPORTED: "not_supported";
  };

  export const Modules: {
    PAYMENT: string;
  };

  export function ModuleProvider(
    moduleName: string,
    config: { services: unknown[] },
  ): unknown;
}
