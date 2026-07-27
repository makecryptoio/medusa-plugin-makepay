import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http";

import { resolveMakePayService } from "../../../../lib/makepay.js";

export async function GET(req: MedusaRequest, res: MedusaResponse) {
  const payment = await resolveMakePayService(req).getPaymentView(
    req.params.id,
  );
  if (!payment) {
    res.status(404).json({ message: "MakePay payment was not found." });
    return;
  }
  res.json({ payment });
}
