import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http";

import { queryText, resolveMakePayService } from "../../../lib/makepay.js";

export async function GET(req: MedusaRequest, res: MedusaResponse) {
  const query = req.query as Record<string, unknown>;
  const service = resolveMakePayService(req);
  try {
    await service.finishOAuth({
      code: queryText(query.code),
      error: queryText(query.error),
      errorDescription: queryText(query.error_description),
      iss: queryText(query.iss),
      state: queryText(query.state),
    });
    res.redirect(303, service.adminSettingsPath("connected"));
  } catch {
    const logger = req.scope.resolve<{ error(message: string): void }>(
      "logger",
    );
    logger.error("MakePay OAuth callback failed; see connection diagnostics.");
    res.redirect(303, service.adminSettingsPath("error"));
  }
}
