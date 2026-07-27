import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http";

import { resolveMakePayService } from "../../../../lib/makepay.js";

export async function POST(req: MedusaRequest, res: MedusaResponse) {
  res.json(await resolveMakePayService(req).startOAuth());
}
