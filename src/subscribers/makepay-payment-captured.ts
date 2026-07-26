import {
  ContainerRegistrationKeys,
  Modules,
  PaymentEvents,
} from "@medusajs/framework/utils";
import type { IPaymentModuleService } from "@medusajs/framework/types";

import { findFullyCapturedPayment } from "../lib/payment-state.js";
import { MAKEPAY_MODULE } from "../modules/makepay/constants.js";
import type MakePayModuleService from "../modules/makepay/service.js";

type SubscriberContainer = {
  resolve<T = unknown>(name: string): T;
};

/** Mark the projection paid only after Medusa's capture workflow succeeds. */
export default async function makePayPaymentCapturedHandler({
  event,
  container,
}: {
  event: { data: { id: string } };
  container: SubscriberContainer;
}) {
  const query = container.resolve<{
    graph(input: Record<string, unknown>): Promise<{
      data: Array<Record<string, unknown>>;
    }>;
  }>(ContainerRegistrationKeys.QUERY);
  const { data } = await query.graph({
    entity: "payment",
    fields: ["id", "payment_session_id", "provider_id"],
    filters: { id: event.data.id },
  });
  const payment = data[0];
  if (
    !payment ||
    String(payment.provider_id ?? "") !== "pp_makepay_makepay" ||
    !payment.payment_session_id
  ) {
    return;
  }
  const makepay = container.resolve<MakePayModuleService>(MAKEPAY_MODULE);
  const sessionId = String(payment.payment_session_id);
  const projection = await makepay.projectionBySession(sessionId);
  if (!projection || projection.provider_id !== makepay.providerId) {
    return;
  }
  const captured = await findFullyCapturedPayment(
    container.resolve<IPaymentModuleService>(Modules.PAYMENT),
    {
      amount: String(projection.amount),
      currency: String(projection.currency),
      providerId: "pp_makepay_makepay",
      sessionId,
    },
  );
  if (!captured || captured.id !== String(payment.id)) {
    return;
  }
  await makepay.markCapturedPayment({
    paymentId: captured.id,
    sessionId,
  });
}

export const config = {
  context: { subscriberId: "makepay-payment-captured" },
  event: PaymentEvents.CAPTURED,
};
