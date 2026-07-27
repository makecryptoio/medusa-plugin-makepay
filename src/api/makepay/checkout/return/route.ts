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
  try {
    const redirectUrl =
      await resolveMakePayService(req).storefrontReturnUrl(state);
    res.redirect(303, redirectUrl);
  } catch (error) {
    if (error instanceof Error && /not found/i.test(error.message)) {
      res.status(404).json({ message: error.message });
      return;
    }
    throw error;
  }
}
