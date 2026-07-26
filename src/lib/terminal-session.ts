import type { IPaymentModuleService } from "@medusajs/framework/types";
import { PaymentSessionStatus } from "@medusajs/framework/utils";

import {
  arePaymentAmountsEqual,
  getPaymentLinkUid,
  getSessionIdFromData,
  isRecord,
  normalizeAmountValue,
} from "../providers/makepay/utils.js";

export type MakePayTerminalSessionState = "canceled" | "failed";

const MAKEPAY_TERMINAL_SESSION_STATE = Symbol(
  "makepay-terminal-session-state",
);
const MAKEPAY_LATE_SUCCESS_SESSION = Symbol(
  "makepay-late-success-session",
);

/** JSON/API callers cannot forge this in-process symbol identity. */
export function terminalSessionUpdateContext(
  state: MakePayTerminalSessionState,
): Record<PropertyKey, unknown> {
  return { [MAKEPAY_TERMINAL_SESSION_STATE]: state };
}

export function terminalSessionStateFromContext(
  context: unknown,
): MakePayTerminalSessionState | undefined {
  if (!context || typeof context !== "object") return undefined;
  const state = (context as Record<PropertyKey, unknown>)[
    MAKEPAY_TERMINAL_SESSION_STATE
  ];
  return state === "canceled" || state === "failed" ? state : undefined;
}

/** In-process capability used only after a fully correlated MakePay `complete`. */
export function lateSuccessfulSessionUpdateContext(): Record<
  PropertyKey,
  unknown
> {
  return { [MAKEPAY_LATE_SUCCESS_SESSION]: true };
}

export function isLateSuccessfulSessionUpdateContext(
  context: unknown,
): boolean {
  return Boolean(
    context &&
      typeof context === "object" &&
      (context as Record<PropertyKey, unknown>)[MAKEPAY_LATE_SUCCESS_SESSION] ===
        true,
  );
}

function assertPaymentSessionCorrelation(
  session: Awaited<ReturnType<IPaymentModuleService["retrievePaymentSession"]>>,
  sessionId: string,
  expectation: {
    amount: string | number;
    currency: string;
    paymentLinkUid: string;
    providerId: string;
  },
): Record<string, unknown> {
  const data = isRecord(session.data) ? session.data : undefined;
  let amount: string | number;
  try {
    amount = normalizeAmountValue(session.amount);
  } catch {
    throw new Error("MakePay payment-session amount is invalid.");
  }
  if (
    session.id !== sessionId ||
    session.provider_id !== expectation.providerId ||
    !data ||
    !arePaymentAmountsEqual(amount, expectation.amount) ||
    String(session.currency_code).toUpperCase() !==
      expectation.currency.toUpperCase() ||
    getPaymentLinkUid(data) !== expectation.paymentLinkUid ||
    getSessionIdFromData(data) !== sessionId
  ) {
    throw new Error("MakePay payment-session correlation failed.");
  }
  return data;
}

export async function applyTerminalPaymentSessionState(
  paymentModule: IPaymentModuleService,
  sessionId: string,
  action: MakePayTerminalSessionState,
  expectation: {
    amount: string | number;
    currency: string;
    paymentLinkUid: string;
    providerId: string;
  },
): Promise<MakePayTerminalSessionState | undefined> {
  const session = await paymentModule.retrievePaymentSession(sessionId);
  const data = assertPaymentSessionCorrelation(
    session,
    sessionId,
    expectation,
  );

  const currentStatus = String(session.status).toLowerCase();
  const targetStatus =
    action === "canceled"
      ? String(PaymentSessionStatus.CANCELED).toLowerCase()
      : String(PaymentSessionStatus.ERROR).toLowerCase();
  if (currentStatus === targetStatus) return action;
  if (
    !["pending", "pending_authorization", "requires_more"].includes(
      currentStatus,
    )
  ) {
    return undefined;
  }
  await paymentModule.updatePaymentSession({
    amount: session.amount,
    context: terminalSessionUpdateContext(action),
    currency_code: session.currency_code,
    data,
    id: session.id,
    metadata: session.metadata ?? {},
    status:
      action === "canceled"
        ? PaymentSessionStatus.CANCELED
        : PaymentSessionStatus.ERROR,
  });
  const updated = await paymentModule.retrievePaymentSession(sessionId);
  if (String(updated.status).toLowerCase() !== targetStatus) {
    throw new Error(
      "MakePay terminal processing did not update the Medusa payment session.",
    );
  }
  return action;
}

/**
 * MakePay can settle an already expired/cancelled/failed quote after a late
 * transfer. Re-open only the exactly correlated Medusa session, immediately
 * before running Medusa's standard successful-payment workflow.
 */
export async function prepareLateSuccessfulPaymentSession(
  paymentModule: IPaymentModuleService,
  sessionId: string,
  expectation: {
    amount: string | number;
    currency: string;
    paymentLinkUid: string;
    providerId: string;
  },
): Promise<boolean> {
  const session = await paymentModule.retrievePaymentSession(sessionId);
  const data = assertPaymentSessionCorrelation(
    session,
    sessionId,
    expectation,
  );
  const currentStatus = String(session.status).toLowerCase();
  if (
    [
      "authorized",
      "pending",
      "pending_authorization",
      "requires_more",
    ].includes(currentStatus)
  ) {
    return true;
  }
  if (
    ![
      String(PaymentSessionStatus.CANCELED).toLowerCase(),
      String(PaymentSessionStatus.ERROR).toLowerCase(),
    ].includes(currentStatus)
  ) {
    return false;
  }
  await paymentModule.updatePaymentSession({
    amount: session.amount,
    context: lateSuccessfulSessionUpdateContext(),
    currency_code: session.currency_code,
    data,
    id: session.id,
    metadata: session.metadata ?? {},
    status: PaymentSessionStatus.PENDING_AUTHORIZATION,
  });
  const updated = await paymentModule.retrievePaymentSession(sessionId);
  return (
    String(updated.status).toLowerCase() ===
    String(PaymentSessionStatus.PENDING_AUTHORIZATION).toLowerCase()
  );
}
