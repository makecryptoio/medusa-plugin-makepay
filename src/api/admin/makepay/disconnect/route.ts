import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http";

import { resolveMakePayService } from "../../../lib/makepay.js";

export async function POST(req: MedusaRequest, res: MedusaResponse) {
  const service = resolveMakePayService(req);
  res.json({
    capabilities: {
      api_key: true,
      oauth: service.authMode === "oauth",
      reconcile: service.reconciliationEnabled,
      refunds: false,
    },
    connection: await service.disconnectOAuth(),
  });
}
