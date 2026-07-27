import Medusa, { type FetchArgs } from "@medusajs/js-sdk";

import type {
  MakePayConnectionResponse,
  MakePayOAuthStartResponse,
  MakePayPaymentResponse,
  MakePayPaymentsQuery,
  MakePayPaymentsResponse,
} from "../types.js";
import { redactSensitiveText } from "./format.js";

const sdk = new Medusa({
  baseUrl: __BACKEND_URL__,
  auth: {
    type: "session",
  },
});

export const makePayQueryKeys = {
  all: ["makepay"] as const,
  connection: () => [...makePayQueryKeys.all, "connection"] as const,
  payments: (query: MakePayPaymentsQuery) =>
    [...makePayQueryKeys.all, "payments", query] as const,
  payment: (id: string) => [...makePayQueryKeys.all, "payment", id] as const,
  order: (orderId: string) =>
    [...makePayQueryKeys.all, "order", orderId] as const,
};

const fetchAdmin = <T>(path: string, init?: FetchArgs) =>
  sdk.client.fetch<T>(path, init);

export const makePayAdmin = {
  getConnection: () =>
    fetchAdmin<MakePayConnectionResponse>("/admin/makepay/connection"),

  startOAuth: () =>
    fetchAdmin<MakePayOAuthStartResponse>("/admin/makepay/oauth/start", {
      method: "POST",
    }),

  disconnect: () =>
    fetchAdmin<MakePayConnectionResponse>("/admin/makepay/disconnect", {
      method: "POST",
    }),

  listPayments: (query: MakePayPaymentsQuery) =>
    fetchAdmin<MakePayPaymentsResponse>("/admin/makepay/payments", {
      query: {
        limit: query.limit,
        offset: query.offset,
        ...(query.q ? { q: query.q } : {}),
        ...(query.status ? { status: query.status } : {}),
      },
    }),

  getPayment: (id: string) =>
    fetchAdmin<MakePayPaymentResponse>(
      `/admin/makepay/payments/${encodeURIComponent(id)}`,
    ),

  getOrderPayment: (orderId: string) =>
    fetchAdmin<MakePayPaymentResponse>(
      `/admin/makepay/orders/${encodeURIComponent(orderId)}`,
    ),

  reconcilePayment: (id: string) =>
    fetchAdmin<MakePayPaymentResponse>(
      `/admin/makepay/payments/${encodeURIComponent(id)}/reconcile`,
      { method: "POST" },
    ),
};

export const getErrorMessage = (error: unknown) => {
  if (error instanceof Error && error.message.trim()) {
    return redactSensitiveText(error.message);
  }

  return "MakePay couldn't complete the request. Please try again.";
};
