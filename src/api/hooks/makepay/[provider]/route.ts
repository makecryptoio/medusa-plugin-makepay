import { processPaymentWorkflowId } from "@medusajs/medusa/core-flows";
import { MakePayError } from "@makecrypto/makepay";
import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http";
import type {
  IPaymentModuleService,
  IWorkflowEngineService,
  WebhookActionResult,
} from "@medusajs/framework/types";
import { Modules, PaymentActions } from "@medusajs/framework/utils";

import { findFullyCapturedPayment } from "../../../../lib/payment-state.js";
import { resolveMakePayService } from "../../../lib/makepay.js";

const MAX_RAW_BODY_BYTES = 64 * 1024;
const RETRYABLE_ERROR = { message: "MakePay webhook processing unavailable." };
const INVALID_WEBHOOK = { message: "Invalid MakePay webhook." };

type ProcessingResult =
  { kind: "invalid"; status: 400 | 401 } | { kind: "received" };

const WORKFLOW_ACTIONS = new Set<WebhookActionResult["action"]>([
  PaymentActions.AUTHORIZED,
  PaymentActions.SUCCESSFUL,
]);

const PROVIDER_SIDE_EFFECT_ACTIONS = new Set<WebhookActionResult["action"]>([
  PaymentActions.CANCELED,
  PaymentActions.FAILED,
  PaymentActions.PENDING,
  PaymentActions.PENDING_AUTHORIZATION,
  PaymentActions.REQUIRES_MORE,
]);

function sendInvalid(res: MedusaResponse, status = 400): void {
  res.status(status).json(INVALID_WEBHOOK);
}

function sendRetryable(res: MedusaResponse): void {
  res.status(503).json(RETRYABLE_ERROR);
}

function sendNotFound(res: MedusaResponse): void {
  res.status(404).json({ message: "Not found." });
}

function headerText(
  headers: Record<string, unknown>,
  name: string,
): string | undefined {
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== name) continue;
    const first = Array.isArray(value) ? value[0] : value;
    return typeof first === "string" && first.trim() ? first.trim() : undefined;
  }
  return undefined;
}

/**
 * Process MakePay webhooks synchronously so MakePay receives success only
 * after Medusa's standard payment workflow has durably completed.
 */
export async function processMakePayWebhook(
  req: MedusaRequest,
  res: MedusaResponse,
  options: { allowApiKey?: boolean; provider?: string } = {},
) {
  let expectedProvider: string;
  let makepay;
  try {
    makepay = resolveMakePayService(req);
    expectedProvider = `makepay_${makepay.providerId}`;
  } catch {
    sendRetryable(res);
    return;
  }

  if ((options.provider ?? req.params.provider) !== expectedProvider) {
    sendInvalid(res);
    return;
  }

  if (makepay.authMode !== "oauth" && !options.allowApiKey) {
    try {
      if (await makepay.hasUndrainedPaymentsForMode("oauth")) {
        sendRetryable(res);
      } else {
        sendNotFound(res);
      }
    } catch {
      sendRetryable(res);
    }
    return;
  }

  if (!Buffer.isBuffer(req.rawBody) || req.rawBody.length === 0) {
    sendInvalid(res);
    return;
  }
  if (req.rawBody.length > MAX_RAW_BODY_BYTES) {
    sendInvalid(res, 413);
    return;
  }

  const suppliedDeliveryGroupId = headerText(
    req.headers as Record<string, unknown>,
    "x-makepay-delivery-group-id",
  );
  if (
    makepay.authMode === "oauth" &&
    (!suppliedDeliveryGroupId ||
      !/^mpwhgrp_[a-f0-9]{64}$/.test(suppliedDeliveryGroupId))
  ) {
    sendInvalid(res);
    return;
  }
  const signature = headerText(
    req.headers as Record<string, unknown>,
    "x-makepay-signature",
  );
  if (!signature) {
    sendInvalid(res, 401);
    return;
  }

  let lockIdentity: { deliveryGroupId: string; paymentLinkUid: string };
  try {
    lockIdentity = await makepay.verifyWebhookSignature(
      req.rawBody,
      signature,
      suppliedDeliveryGroupId,
    );
  } catch (error) {
    if (
      error instanceof MakePayError &&
      (error.status === 400 || error.status === 401)
    ) {
      sendInvalid(res, error.status);
      return;
    }
    sendRetryable(res);
    return;
  }

  let result: ProcessingResult;
  try {
    result = await makepay.withWebhookDeliveryLock(lockIdentity, async () => {
      const payment = req.scope.resolve<IPaymentModuleService>(Modules.PAYMENT);
      let processed: WebhookActionResult;
      try {
        processed = await payment.getWebhookActionAndData({
          payload: {
            data: req.body as Record<string, unknown>,
            headers: req.headers,
            rawData: req.rawBody,
          },
          provider: expectedProvider,
        });
      } catch (error) {
        if (
          error instanceof MakePayError &&
          (error.status === 400 || error.status === 401)
        ) {
          return { kind: "invalid", status: error.status };
        }
        throw error;
      }

      if (processed.action === PaymentActions.NOT_SUPPORTED) {
        if (processed.data?.session_id) {
          // The provider returns correlated data only for a durable duplicate.
          return { kind: "received" };
        }
        return { kind: "invalid", status: 400 };
      }

      if (!processed.data?.session_id) {
        return { kind: "invalid", status: 400 };
      }

      if (PROVIDER_SIDE_EFFECT_ACTIONS.has(processed.action)) {
        return { kind: "received" };
      }

      if (!WORKFLOW_ACTIONS.has(processed.action)) {
        return { kind: "invalid", status: 400 };
      }

      const workflowEngine = req.scope.resolve<IWorkflowEngineService>(
        Modules.WORKFLOW_ENGINE,
      );
      try {
        await workflowEngine.run(processPaymentWorkflowId, {
          input: processed,
        });
        const projection = await makepay.projectionByUid(
          lockIdentity.paymentLinkUid,
        );
        if (
          !projection ||
          projection.session_id !== processed.data.session_id
        ) {
          throw new Error("MakePay payment projection changed during capture.");
        }
        const captured = await findFullyCapturedPayment(payment, {
          amount: String(projection.amount),
          currency: String(projection.currency),
          providerId: `pp_${expectedProvider}`,
          sessionId: String(projection.session_id),
        });
        if (!captured) {
          throw new Error("MakePay did not produce a captured Medusa payment.");
        }
        await makepay.markCapturedPayment({
          paymentId: captured.id,
          sessionId: String(projection.session_id),
        });
      } catch (error) {
        await makepay.releaseSuccessfulPaymentClaim({
          paymentLinkUid: lockIdentity.paymentLinkUid,
          sessionId: String(processed.data.session_id),
        });
        throw error;
      }
      return { kind: "received" };
    });
  } catch {
    // Unknown provider, workflow, locking, and infrastructure failures retry.
    sendRetryable(res);
    return;
  }

  if (result.kind === "invalid") {
    sendInvalid(res, result.status);
    return;
  }

  res.status(200).json({ received: true });
}

export async function POST(req: MedusaRequest, res: MedusaResponse) {
  return processMakePayWebhook(req, res);
}
