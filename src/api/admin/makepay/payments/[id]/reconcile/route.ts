import { processPaymentWorkflowId } from "@medusajs/medusa/core-flows";
import type {
  IPaymentModuleService,
  IWorkflowEngineService,
} from "@medusajs/framework/types";
import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http";
import { Modules, PaymentActions } from "@medusajs/framework/utils";

import { findFullyCapturedPayment } from "../../../../../../lib/payment-state.js";
import {
  applyTerminalPaymentSessionState,
  prepareLateSuccessfulPaymentSession,
} from "../../../../../../lib/terminal-session.js";
import { resolveMakePayService } from "../../../../../lib/makepay.js";

export async function POST(req: MedusaRequest, res: MedusaResponse) {
  try {
    const service = resolveMakePayService(req);
    if (!service.reconciliationEnabled) {
      res.status(409).json({
        message:
          "MakePay reconciliation requires a configured distributed locking provider.",
      });
      return;
    }
    const existing = await service.getPaymentView(req.params.id);
    if (!existing) {
      res.status(404).json({ message: "MakePay payment was not found." });
      return;
    }
    if (existing.auth_mode !== service.authMode) {
      res.status(409).json({
        message:
          "MakePay payment belongs to a different authentication mode. Restore that mode before reconciliation.",
      });
      return;
    }
    const payment = await service.reconcileAndProcessPaymentView(
      req.params.id,
      async (candidate) => {
        const paymentModule = req.scope.resolve<IPaymentModuleService>(
          Modules.PAYMENT,
        );
        const expectation = {
          amount: candidate.amount,
          currency: candidate.currency,
          providerId: `pp_makepay_${service.providerId}`,
          sessionId: candidate.session_id!,
        };
        let captured = await findFullyCapturedPayment(
          paymentModule,
          expectation,
        );
        if (!captured) {
          const prepared = await prepareLateSuccessfulPaymentSession(
            paymentModule,
            candidate.session_id!,
            {
              amount: candidate.amount,
              currency: candidate.currency,
              paymentLinkUid: candidate.payment_link_uid,
              providerId: `pp_makepay_${service.providerId}`,
            },
          );
          if (!prepared) {
            throw new Error(
              "MakePay reconciliation could not prepare the Medusa payment session.",
            );
          }
          const workflowEngine = req.scope.resolve<IWorkflowEngineService>(
            Modules.WORKFLOW_ENGINE,
          );
          await workflowEngine.run(processPaymentWorkflowId, {
            input: {
              action: PaymentActions.SUCCESSFUL,
              data: {
                amount: candidate.amount,
                session_id: candidate.session_id,
              },
            },
          });
          captured = await findFullyCapturedPayment(
            paymentModule,
            expectation,
          );
          if (!captured) {
            throw new Error(
              "MakePay reconciliation did not produce a captured Medusa payment.",
            );
          }
        }
        return { paymentId: captured.id };
      },
      async (candidate, action) => {
        const paymentModule = req.scope.resolve<IPaymentModuleService>(
          Modules.PAYMENT,
        );
        return applyTerminalPaymentSessionState(
          paymentModule,
          candidate.session_id!,
          action,
          {
            amount: candidate.amount,
            currency: candidate.currency,
            paymentLinkUid: candidate.payment_link_uid,
            providerId: `pp_makepay_${service.providerId}`,
          },
        );
      },
    );
    res.json({ payment });
  } catch (error) {
    if (error instanceof Error && /not found/i.test(error.message)) {
      res.status(404).json({ message: error.message });
      return;
    }
    throw error;
  }
}
