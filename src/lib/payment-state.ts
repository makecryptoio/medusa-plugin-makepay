import type {
  IPaymentModuleService,
  PaymentDTO,
} from "@medusajs/framework/types";

import {
  arePaymentAmountsEqual,
  normalizeAmountValue,
} from "../providers/makepay/utils.js";

export type CapturedPaymentExpectation = {
  amount?: string | number;
  currency?: string;
  providerId: string;
  sessionId: string;
};

function paymentAmount(payment: PaymentDTO): string | number | undefined {
  try {
    return normalizeAmountValue(payment.amount as never);
  } catch {
    return undefined;
  }
}

function sumCaptureAmounts(payment: PaymentDTO): string | undefined {
  if (!payment.captures?.length) return undefined;
  const decimals: string[] = [];
  for (const capture of payment.captures) {
    try {
      const normalized = String(normalizeAmountValue(capture.amount as never));
      if (!/^(0|[1-9]\d*)(?:\.\d+)?$/.test(normalized)) return undefined;
      decimals.push(normalized);
    } catch {
      return undefined;
    }
  }
  const scale = Math.max(
    ...decimals.map((value) => value.split(".")[1]?.length ?? 0),
  );
  let total = 0n;
  for (const value of decimals) {
    const [whole, fraction = ""] = value.split(".");
    total += BigInt(`${whole}${fraction.padEnd(scale, "0")}`);
  }
  if (!scale) return total.toString();
  const padded = total.toString().padStart(scale + 1, "0");
  const whole = padded.slice(0, -scale);
  const fraction = padded.slice(-scale).replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole;
}

/**
 * Medusa 2.17.x keeps an auto-captured PaymentSession in `authorized` state.
 * The linked Payment is therefore the authoritative capture record.
 */
export async function findFullyCapturedPayment(
  paymentModule: IPaymentModuleService,
  expectation: CapturedPaymentExpectation,
): Promise<PaymentDTO | undefined> {
  const payments = await paymentModule.listPayments(
    { payment_session_id: expectation.sessionId },
    { relations: ["captures"], take: 10 },
  );
  const matching = payments.filter((payment) => {
    if (
      payment.provider_id !== expectation.providerId ||
      !payment.captured_at ||
      payment.canceled_at
    ) {
      return false;
    }
    if (
      expectation.currency &&
      payment.currency_code.toUpperCase() !== expectation.currency.toUpperCase()
    ) {
      return false;
    }
    const amount = paymentAmount(payment);
    const expectedAmount = expectation.amount ?? amount;
    if (
      expectedAmount === undefined ||
      amount === undefined ||
      !arePaymentAmountsEqual(amount, expectedAmount)
    ) {
      return false;
    }
    const capturedTotal = sumCaptureAmounts(payment);
    if (
      capturedTotal === undefined ||
      !arePaymentAmountsEqual(capturedTotal, expectedAmount)
    ) {
      return false;
    }
    if (
      payment.captured_amount !== undefined
    ) {
      try {
        if (
          !arePaymentAmountsEqual(
            normalizeAmountValue(payment.captured_amount as never),
            expectedAmount,
          )
        ) {
          return false;
        }
      } catch {
        return false;
      }
    }
    return true;
  });
  if (matching.length > 1) {
    throw new Error(
      "MakePay found multiple captured Medusa payments for one session.",
    );
  }
  return matching[0];
}
