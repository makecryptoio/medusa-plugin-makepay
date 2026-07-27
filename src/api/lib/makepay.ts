import type { MedusaRequest } from "@medusajs/framework/http";

import { MAKEPAY_MODULE } from "../../modules/makepay/constants.js";
import type MakePayModuleService from "../../modules/makepay/service.js";

export function resolveMakePayService(
  req: MedusaRequest,
): MakePayModuleService {
  try {
    return req.scope.resolve<MakePayModuleService>(MAKEPAY_MODULE);
  } catch {
    throw new Error(
      "The MakePay integration module is not configured. Add the plugin and run `medusa db:migrate`.",
    );
  }
}

export function queryText(value: unknown): string | undefined {
  if (Array.isArray(value)) value = value[0];
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unexpected MakePay error.";
}
