import { ContainerRegistrationKeys } from "@medusajs/framework/utils";

import { MAKEPAY_MODULE } from "../modules/makepay/constants.js";
import type MakePayModuleService from "../modules/makepay/service.js";

type OrderPlacedEvent = {
  data: { id: string };
};

type SubscriberContainer = {
  resolve<T = unknown>(name: string): T;
};

/** Correlate the pre-order hosted link after Medusa creates the pending order. */
export default async function makePayOrderPlacedHandler({
  event,
  container,
}: {
  event: OrderPlacedEvent;
  container: SubscriberContainer;
}) {
  const service = container.resolve<MakePayModuleService>(MAKEPAY_MODULE);
  const query = container.resolve<{
    graph(input: Record<string, unknown>): Promise<{
      data: Array<Record<string, unknown>>;
    }>;
  }>(ContainerRegistrationKeys.QUERY);
  const result = await query.graph({
    entity: "order",
    fields: [
      "id",
      "display_id",
      "email",
      "payment_collections.payment_sessions.id",
      "payment_collections.payment_sessions.provider_id",
      "payment_collections.payments.id",
      "payment_collections.payments.payment_session_id",
      "payment_collections.payments.provider_id",
    ],
    filters: { id: event.data.id },
  });
  const order = result.data[0];
  if (!order) return;
  const collections = Array.isArray(order.payment_collections)
    ? (order.payment_collections as Array<Record<string, unknown>>)
    : [];
  for (const collection of collections) {
    const sessions = Array.isArray(collection.payment_sessions)
      ? (collection.payment_sessions as Array<Record<string, unknown>>)
      : [];
    const payments = Array.isArray(collection.payments)
      ? (collection.payments as Array<Record<string, unknown>>)
      : [];
    for (const session of sessions) {
      if (String(session.provider_id ?? "") !== "pp_makepay_makepay") {
        continue;
      }
      const payment = payments.find(
        (candidate) => candidate.payment_session_id === session.id,
      );
      await service.correlateOrder({
        customerEmail:
          typeof order.email === "string" ? order.email : undefined,
        orderDisplayId:
          order.display_id === undefined ? undefined : String(order.display_id),
        orderId: String(order.id),
        paymentId: payment?.id ? String(payment.id) : undefined,
        sessionId: String(session.id),
      });
    }
  }
}

export const config = {
  context: { subscriberId: "makepay-order-placed" },
  event: "order.placed",
};
