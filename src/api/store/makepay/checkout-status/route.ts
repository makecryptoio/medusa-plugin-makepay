import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http";

import { queryText, resolveMakePayService } from "../../../lib/makepay.js";

export async function GET(req: MedusaRequest, res: MedusaResponse) {
  res.setHeader("cache-control", "no-store, private");
  res.setHeader("pragma", "no-cache");
  res.setHeader("referrer-policy", "no-referrer");
  const state = queryText((req.query as Record<string, unknown>).state);
  if (!state) {
    res.status(400).json({ message: "MakePay checkout state is required." });
    return;
  }
  const result = await resolveMakePayService(req).checkoutStatus(state);
  if (!result) {
    res.status(404).json({ message: "MakePay checkout state was not found." });
    return;
  }
  res.json(result);
}
