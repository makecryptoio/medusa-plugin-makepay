import {
  authenticate,
  defineMiddlewares,
  type MedusaNextFunction,
  type MedusaRequest,
  type MedusaResponse,
  type MiddlewareRoute,
} from "@medusajs/framework/http";
import { PolicyOperation } from "@medusajs/framework/utils";

import { resolveMakePayService } from "./lib/makepay.js";
import { processMakePayWebhook } from "./hooks/makepay/[provider]/route.js";

export const MAKEPAY_WEBHOOK_BODY_LIMIT = "64kb";

/**
 * MakePay Admin routes deliberately reuse Medusa's core RBAC resources. This
 * keeps custom pages aligned with the permissions that protect the equivalent
 * Store, Payment, Capture, and Order operations in the built-in Admin API.
 */
export const MAKEPAY_ADMIN_ROUTE_POLICIES: MiddlewareRoute[] = [
  {
    matcher: "/admin/makepay/connection",
    methods: ["GET"],
    policies: [{ resource: "store", operation: PolicyOperation.read }],
  },
  {
    matcher: "/admin/makepay/oauth/start",
    methods: ["POST"],
    policies: [{ resource: "store", operation: PolicyOperation.update }],
  },
  {
    matcher: "/admin/makepay/disconnect",
    methods: ["POST"],
    policies: [{ resource: "store", operation: PolicyOperation.update }],
  },
  {
    matcher: "/admin/makepay/payments",
    methods: ["GET"],
    policies: [{ resource: "payment", operation: PolicyOperation.read }],
  },
  {
    matcher: "/admin/makepay/payments/:id",
    methods: ["GET"],
    policies: [{ resource: "payment", operation: PolicyOperation.read }],
  },
  {
    matcher: "/admin/makepay/payments/:id/reconcile",
    methods: ["POST"],
    policies: [
      { resource: "payment", operation: PolicyOperation.read },
      { resource: "capture", operation: PolicyOperation.create },
    ],
  },
  {
    matcher: "/admin/makepay/orders/:orderId",
    methods: ["GET"],
    policies: [{ resource: "order", operation: PolicyOperation.read }],
  },
];

export async function routeLegacyMakePayWebhook(
  req: MedusaRequest,
  res: MedusaResponse,
  next: MedusaNextFunction,
): Promise<void> {
  const requestedProvider = String(req.params.provider ?? "");
  if (requestedProvider && !requestedProvider.startsWith("makepay_")) {
    next();
    return;
  }
  try {
    const makepay = resolveMakePayService(req);
    const expectedProvider = `makepay_${makepay.providerId}`;
    if (requestedProvider && requestedProvider !== expectedProvider) {
      res.status(404).json({ message: "Not found." });
      return;
    }
    if (makepay.authMode === "oauth") {
      if (await makepay.hasUndrainedPaymentsForMode("api_key")) {
        res.status(503).json({
          message: "MakePay webhook processing unavailable.",
        });
      } else {
        res.status(404).json({ message: "Not found." });
      }
      return;
    }
    await processMakePayWebhook(req, res, {
      allowApiKey: true,
      provider: requestedProvider || expectedProvider,
    });
    return;
  } catch {
    res
      .status(503)
      .json({ message: "MakePay webhook processing unavailable." });
    return;
  }
}

export default defineMiddlewares({
  routes: [
    {
      matcher: "/admin/makepay*",
      middlewares: [authenticate("user", ["session", "bearer", "api-key"])],
    },
    ...MAKEPAY_ADMIN_ROUTE_POLICIES,
    {
      bodyParser: {
        preserveRawBody: true,
        sizeLimit: MAKEPAY_WEBHOOK_BODY_LIMIT,
      },
      matcher: "/hooks/makepay/:provider",
      methods: ["POST"],
    },
    {
      bodyParser: {
        preserveRawBody: true,
        sizeLimit: MAKEPAY_WEBHOOK_BODY_LIMIT,
      },
      matcher: "/hooks/payment/makepay_makepay",
      methods: ["POST"],
      middlewares: [routeLegacyMakePayWebhook],
    },
  ],
});
