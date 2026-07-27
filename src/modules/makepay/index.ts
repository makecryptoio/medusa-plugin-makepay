import { Module } from "@medusajs/framework/utils";

import { MAKEPAY_MODULE } from "./constants.js";
import MakePayModuleService from "./service.js";

export { MAKEPAY_MODULE } from "./constants.js";
export { default as MakePayModuleService } from "./service.js";
export type {
  MakePayConnectionView,
  MakePayModuleOptions,
  MakePayPaymentView,
} from "./types.js";

export default Module(MAKEPAY_MODULE, {
  service: MakePayModuleService,
});
