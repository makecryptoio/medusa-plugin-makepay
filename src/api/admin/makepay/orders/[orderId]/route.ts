import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http";

import { resolveMakePayService } from "../../../../lib/makepay.js";

export async function GET(req: MedusaRequest, res: MedusaResponse) {
  const payment = await resolveMakePayService(req).getOrderPaymentView(
    req.params.orderId,
  );
  res.json({ payment: payment ?? null });
}
