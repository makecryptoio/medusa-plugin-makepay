import { ModuleProvider, Modules } from "@medusajs/framework/utils";

import { MakePayProviderService } from "./services/index.js";

export { MakePayProviderService } from "./services/index.js";
export type {
  MakePayProviderOptions,
  NormalizedMakePayProviderOptions,
} from "./types.js";

export default ModuleProvider(Modules.PAYMENT, {
  services: [MakePayProviderService],
});
