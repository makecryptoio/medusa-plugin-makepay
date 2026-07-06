import {
  MakePayClient,
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
  ProviderWebhookPayload,
  RefundPaymentInput,
  RefundPaymentOutput,
  RetrievePaymentInput,
  RetrievePaymentOutput,
  UpdatePaymentInput,
  UpdatePaymentOutput,
  WebhookActionResult,
} from "@medusajs/framework/types";
import {
  AbstractPaymentProvider,
  PaymentActions,
  PaymentSessionStatus,
} from "@medusajs/framework/utils";

import type {
  MakePayPaymentAction,
  MakePayPaymentSessionStatus,
  MakePayProviderData,
  MakePayProviderOptions,
  NormalizedMakePayProviderOptions,
} from "../types.js";
import {
  buildProviderData,
  getAmountFromWebhook,
  getNestedRecord,
  getPaymentLinkFromResponse,
  getPaymentLinkUid,
  getPaymentLinkUrl,
  getSessionIdFromData,
  getSessionIdFromWebhook,
  getText,
  isRecord,
  mapMakePayStateToPaymentSessionStatus,
  mapMakePayWebhookToPaymentAction,
  normalizeAmountValue,
  normalizeProviderOptions,
  shouldRefreshPaymentLinkForUpdate,
  validateMakePayProviderOptions,
} from "../utils.js";

const MAKEPAY_PROVIDER_IDENTIFIER = "makepay";
const DEFAULT_PAYMENT_DESCRIPTION =
  "Hosted MakePay checkout for a Medusa payment session.";

class MakePayProviderService extends AbstractPaymentProvider<MakePayProviderOptions> {
  static identifier = MAKEPAY_PROVIDER_IDENTIFIER;

  protected readonly client_: MakePayClient;
  protected readonly options_: NormalizedMakePayProviderOptions;

  static validateOptions(options: MakePayProviderOptions): void {
    validateMakePayProviderOptions(options);
  }

  constructor(
    container: Record<string, unknown>,
    options: MakePayProviderOptions,
  ) {
    super(container, options);

    this.options_ = normalizeProviderOptions(
      options,
    ) as NormalizedMakePayProviderOptions;
    this.client_ = new MakePayClient({
      baseUrl: this.options_.baseUrl,
      checkoutBaseUrl: this.options_.checkoutBaseUrl,
      fetch: this.options_.fetch,
      keyId: this.options_.keyId,
      keySecret: this.options_.keySecret,
    });
  }

  async initiatePayment({
    amount,
    currency_code,
    data,
    context,
  }: InitiatePaymentInput): Promise<InitiatePaymentOutput> {
    const sessionId = this.getSessionId(data, context?.idempotency_key);
    const payload = this.buildPaymentLinkPayload({
      amount,
      context,
      currencyCode: currency_code,
      data,
      sessionId,
    });

    const response = await this.client_.createPaymentLink(payload, {
      sendPaymentRequestEmail: false,
      status: "active",
    });
    const paymentLink = getPaymentLinkFromResponse(response);
    const uid = getText(paymentLink.uid) ?? getText(paymentLink.id);
    const url = getPaymentLinkUrl(paymentLink);

    if (!uid || !url) {
      throw new Error("MakePay did not return a hosted checkout URL.");
    }

    return {
      id: uid,
      data: buildProviderData({
        amount: payload.amount,
        existing: data,
        fiatCurrency: currency_code.toUpperCase(),
        paymentLink,
        sessionId,
        status: "requires_more",
      }),
      status: this.toPaymentSessionStatus("requires_more"),
    };
  }

  async authorizePayment({
    data,
  }: AuthorizePaymentInput): Promise<AuthorizePaymentOutput> {
    const providerData = await this.retrieveProviderData(data);

    return {
      data: providerData,
      status: this.toPaymentSessionStatus(
        mapMakePayStateToPaymentSessionStatus(providerData),
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
        mapMakePayStateToPaymentSessionStatus(providerData),
      ),
    };
  }

  async retrievePayment({
    data,
  }: RetrievePaymentInput): Promise<RetrievePaymentOutput> {
    return {
      data: await this.retrieveProviderData(data),
    };
  }

  async updatePayment({
    amount,
    currency_code,
    data,
    context,
  }: UpdatePaymentInput): Promise<UpdatePaymentOutput> {
    const uid = getPaymentLinkUid(data);
    if (!uid) {
      return this.initiatePayment({
        amount,
        context,
        currency_code,
        data,
      }) as Promise<UpdatePaymentOutput>;
    }

    const providerData = await this.retrieveProviderData(data);
    if (
      shouldRefreshPaymentLinkForUpdate({
        currentData: providerData,
        nextAmount: amount,
        nextCurrencyCode: currency_code,
      })
    ) {
      await this.archivePaymentLink(providerData);

      return this.initiatePayment({
        amount,
        context,
        currency_code,
        data: providerData,
      }) as Promise<UpdatePaymentOutput>;
    }

    return {
      data: providerData,
      status: this.toPaymentSessionStatus(
        mapMakePayStateToPaymentSessionStatus(providerData),
      ),
    };
  }

  async capturePayment({
    data,
  }: CapturePaymentInput): Promise<CapturePaymentOutput> {
    return {
      data: data ?? {},
    };
  }

  async cancelPayment({
    data,
  }: CancelPaymentInput): Promise<CancelPaymentOutput> {
    return {
      data: await this.archivePaymentLink(data),
    };
  }

  async deletePayment(input: DeletePaymentInput): Promise<DeletePaymentOutput> {
    return this.cancelPayment(input);
  }

  async refundPayment(
    _input: RefundPaymentInput,
  ): Promise<RefundPaymentOutput> {
    throw new Error(
      "MakePay refunds are not supported by the Medusa provider in v1.",
    );
  }

  async getWebhookActionAndData(
    webhookData: ProviderWebhookPayload["payload"],
  ): Promise<WebhookActionResult> {
    const event = this.parseWebhookPayload(webhookData);
    const action = mapMakePayWebhookToPaymentAction(event);

    if (action === "not_supported") {
      return {
        action: this.toPaymentAction(action),
      };
    }

    const sessionId = getSessionIdFromWebhook(event);
    if (!sessionId) {
      return {
        action: this.toPaymentAction("not_supported"),
      };
    }

    return {
      action: this.toPaymentAction(action),
      data: {
        amount: getAmountFromWebhook(event) ?? 0,
        session_id: sessionId,
      },
    };
  }

  private buildPaymentLinkPayload(input: {
    amount: InitiatePaymentInput["amount"];
    currencyCode: string;
    data?: Record<string, unknown>;
    context?: InitiatePaymentInput["context"];
    sessionId: string;
  }): MakePayPaymentLinkPayload {
    const metadata = isRecord(input.data?.metadata) ? input.data.metadata : {};
    const customer = input.context?.customer;
    const title =
      getText(input.data?.title) ??
      getText(input.data?.payment_description) ??
      `Medusa payment ${input.sessionId}`;
    const returnUrl = getText(input.data?.return_url) ?? this.options_.returnUrl;
    const successUrl =
      getText(input.data?.success_url) ??
      this.options_.successUrl ??
      returnUrl;
    const failureUrl =
      getText(input.data?.failure_url) ??
      this.options_.failureUrl ??
      returnUrl;
    const clientId =
      getText(input.data?.client_id) ??
      getText(customer?.id) ??
      getText(customer?.email);
    const customerEmail =
      getText(input.data?.customer_email) ?? getText(customer?.email);

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
        ...metadata,
        medusaProviderId: MAKEPAY_PROVIDER_IDENTIFIER,
        medusaSessionId: input.sessionId,
        session_id: input.sessionId,
        source: "medusa",
      },
      orderId:
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
    const uid = getPaymentLinkUid(data);
    if (!uid) {
      return data ?? {};
    }

    const response = await this.client_.getPaymentLink(uid);
    return this.mergeProviderResponse(data, response);
  }

  private mergeProviderResponse(
    data: Record<string, unknown> | undefined,
    response: MakePayPaymentLinkResponse,
  ): MakePayProviderData {
    const paymentLink = getPaymentLinkFromResponse(response);
    const sessionId =
      getSessionIdFromData(data) ??
      getSessionIdFromWebhook(response) ??
      getSessionIdFromWebhook(paymentLink);
    const latestSession =
      getNestedRecord(response, "latestSession") ??
      getNestedRecord(response, "session") ??
      getNestedRecord(paymentLink, "latestSession") ??
      getNestedRecord(paymentLink, "session");

    return {
      ...buildProviderData({
        existing: data,
        paymentLink,
        sessionId,
        status: mapMakePayStateToPaymentSessionStatus({
          paymentLink,
          session: latestSession,
        }),
      }),
      latestSession,
      rawResponse: response,
    };
  }

  private async archivePaymentLink(
    data: Record<string, unknown> | undefined,
  ): Promise<MakePayProviderData> {
    const uid = getPaymentLinkUid(data);
    if (!uid) {
      return data ?? {};
    }

    const response = await this.client_.updatePaymentLink(uid, {
      status: "archived",
    });

    return this.mergeProviderResponse(data, response);
  }

  private parseWebhookPayload(
    webhookData: ProviderWebhookPayload["payload"],
  ): Record<string, unknown> {
    const signature = this.getHeader(
      webhookData.headers,
      "x-makepay-signature",
    );
    const rawBody =
      webhookData.rawData ??
      (webhookData.data ? JSON.stringify(webhookData.data) : undefined);

    if (!rawBody) {
      throw new Error("MakePay webhook raw body is required.");
    }

    return parseMakePayWebhook<Record<string, unknown>>(
      rawBody,
      signature,
      this.options_.webhookSecret,
      {
        toleranceSeconds: this.options_.webhookToleranceSeconds,
      },
    );
  }

  private getHeader(
    headers: Record<string, string | string[] | undefined>,
    name: string,
  ): string | undefined {
    const direct = headers[name];
    if (typeof direct === "string") {
      return direct;
    }

    const lowerName = name.toLowerCase();
    for (const [key, value] of Object.entries(headers)) {
      if (key.toLowerCase() !== lowerName) {
        continue;
      }

      return Array.isArray(value) ? value[0] : value;
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
      case "authorized":
        return PaymentSessionStatus.AUTHORIZED;
      case "captured":
        return PaymentSessionStatus.CAPTURED;
      case "canceled":
        return PaymentSessionStatus.CANCELED;
      case "error":
        return PaymentSessionStatus.ERROR;
      case "requires_more":
        return PaymentSessionStatus.REQUIRES_MORE;
      case "pending":
      default:
        return PaymentSessionStatus.PENDING;
    }
  }

  private toPaymentAction(
    action: MakePayPaymentAction,
  ): (typeof PaymentActions)[keyof typeof PaymentActions] {
    switch (action) {
      case "authorized":
        return PaymentActions.AUTHORIZED;
      case "captured":
        return PaymentActions.SUCCESSFUL;
      case "failed":
        return PaymentActions.FAILED;
      case "pending":
        return PaymentActions.PENDING;
      case "requires_more":
        return PaymentActions.REQUIRES_MORE;
      case "canceled":
        return PaymentActions.CANCELED;
      case "not_supported":
      default:
        return PaymentActions.NOT_SUPPORTED;
    }
  }
}

export default MakePayProviderService;
