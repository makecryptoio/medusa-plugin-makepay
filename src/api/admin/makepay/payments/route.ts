import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http";

import { queryText, resolveMakePayService } from "../../../lib/makepay.js";

export async function GET(req: MedusaRequest, res: MedusaResponse) {
  const query = req.query as Record<string, unknown>;
  res.json(
    await resolveMakePayService(req).listPaymentViews({
      limit: Number(queryText(query.limit)) || undefined,
      offset: Number(queryText(query.offset)) || undefined,
      q: queryText(query.q),
      status: queryText(query.status),
    }),
  );
}
