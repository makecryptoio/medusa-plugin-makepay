import { chmod, readFile, writeFile } from "node:fs/promises";
import { Modules } from "@medusajs/framework/utils";

function requiredText(value, label, pattern) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`Missing ${label}.`);
  }
  const normalized = value.trim();
  if (pattern && !pattern.test(normalized)) {
    throw new Error(`Invalid ${label}.`);
  }
  return normalized;
}

function paymentModuleFrom(container) {
  const service = container.resolve(Modules.PAYMENT);
  if (!service) throw new Error("Medusa's payment module is unavailable.");
  return service;
}

function makePayServiceFrom(container) {
  const service = container.resolve("makepayIntegration");
  if (!service) throw new Error("The packed MakePay module is unavailable.");
  return service;
}

function orderModuleFrom(container) {
  const service = container.resolve(Modules.ORDER);
  if (!service) throw new Error("Medusa's order module is unavailable.");
  return service;
}

function amountText(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === "object" && value && "value" in value) {
    return String(value.value);
  }
  return String(value);
}

function paymentLinkUid(data) {
  if (!data || typeof data !== "object") return null;
  return (
    data.payment_link_uid ??
    data.paymentLinkUid ??
    data.payment_link_id ??
    data.uid ??
    data.id ??
    null
  );
}

function safeProjection(record) {
  if (!record) return null;
  return {
    amount: amountText(record.amount),
    authMode: record.auth_mode ?? null,
    companyId: record.company_id ?? null,
    currency: String(record.currency ?? ""),
    effectClaimedAt: record.effect_claimed_at ?? null,
    grantId: record.grant_id ?? null,
    id: String(record.id ?? ""),
    installationId: record.installation_id ?? null,
    lastSyncedAt: record.last_synced_at ?? null,
    lateSettlementSafe: record.late_settlement_safe === true,
    medusaStatus: record.medusa_status ?? null,
    orderDisplayId: record.order_display_id ?? null,
    orderId: record.order_id ?? null,
    providerStatus: String(record.provider_status ?? ""),
    sessionId: record.session_id ?? null,
    subscriptionId: record.webhook_subscription_id ?? null,
    uid: String(record.payment_link_uid ?? ""),
  };
}

function safeSession(record) {
  if (!record) return null;
  return {
    amount: amountText(record.amount),
    authorizedAt: record.authorized_at ?? null,
    currency: String(record.currency_code ?? ""),
    id: String(record.id ?? ""),
    paymentId: record.payment?.id ?? record.payment_id ?? null,
    paymentLinkUid: paymentLinkUid(record.data),
    providerId: String(record.provider_id ?? ""),
    status: String(record.status ?? ""),
  };
}

function safePayment(record) {
  if (!record) return null;
  return {
    amount: amountText(record.amount),
    canceledAt: record.canceled_at ?? null,
    capturedAt: record.captured_at ?? null,
    currency: String(record.currency_code ?? ""),
    id: String(record.id ?? ""),
    sessionId: record.payment_session_id ?? record.payment_session?.id ?? null,
  };
}

function safeCapture(record) {
  return {
    amount: amountText(record.amount),
    id: String(record.id ?? ""),
    paymentId: record.payment_id ?? record.payment?.id ?? null,
  };
}

function safeOrder(record) {
  return {
    canceledAt: record.canceled_at ?? null,
    email: record.email ?? null,
    id: String(record.id ?? ""),
    status: String(record.status ?? ""),
  };
}

async function optionalRecord(task) {
  try {
    return await task();
  } catch {
    return null;
  }
}

async function snapshot(container, input = {}) {
  const paymentModule = paymentModuleFrom(container);
  const makePayService = makePayServiceFrom(container);
  const orderModule = orderModuleFrom(container);
  const sessions = await paymentModule.listPaymentSessions(
    { provider_id: "pp_makepay_makepay" },
    { relations: ["payment"], take: 100 },
  );
  const sessionIds = new Set(sessions.map((session) => session.id));
  const payments = (await paymentModule.listPayments({}, { take: 100 })).filter(
    (payment) =>
      sessionIds.has(
        payment.payment_session_id ?? payment.payment_session?.id ?? "",
      ),
  );
  const paymentIds = new Set(payments.map((payment) => payment.id));
  const captures = (await paymentModule.listCaptures({}, { take: 100 })).filter(
    (capture) =>
      paymentIds.has(capture.payment_id ?? capture.payment?.id ?? ""),
  );
  const connections = await makePayService.listMakePayConnections(
    {},
    { take: 100 },
  );
  const deliveries = await makePayService.listMakePayWebhookDeliveries(
    {},
    { take: 100 },
  );
  const projections = await makePayService.listMakePayPaymentProjections(
    {},
    { take: 100 },
  );
  const orderFilters = input.orderId
    ? { id: [requiredText(input.orderId, "order ID", /^order_[\w-]+$/)] }
    : input.email
      ? { email: requiredText(input.email, "order email") }
      : {};
  const orders = await orderModule.listOrders(orderFilters, { take: 100 });
  const selectedSession = input.sessionId
    ? await optionalRecord(() =>
        paymentModule.retrievePaymentSession(
          requiredText(
            input.sessionId,
            "payment session ID",
            /^payses_[\w-]+$/,
          ),
          { relations: ["payment"] },
        ),
      )
    : null;
  const selectedPayment = input.paymentId
    ? await optionalRecord(() =>
        paymentModule.retrievePayment(
          requiredText(input.paymentId, "payment ID", /^pay_[\w-]+$/),
        ),
      )
    : null;
  const selectedProjection = input.uid
    ? await makePayService.projectionByUid(
        requiredText(input.uid, "payment-link UID", /^pay_[\w-]+$/),
      )
    : input.sessionId
      ? await makePayService.projectionBySession(input.sessionId)
      : null;

  return {
    captureCount: captures.length,
    captures: captures.map(safeCapture),
    deliveryCount: deliveries.length,
    deliveries: deliveries.map((delivery) => ({
      sessionId: delivery.session_id ?? null,
      status: delivery.provider_status ?? null,
      uid: delivery.payment_link_uid ?? null,
    })),
    orderCount: orders.length,
    orders: orders.map(safeOrder),
    paymentCount: payments.length,
    payments: payments.map(safePayment),
    projection: safeProjection(selectedProjection),
    projectionCount: projections.length,
    selectedPayment: safePayment(selectedPayment),
    selectedSession: safeSession(selectedSession),
    sessionCount: sessions.length,
    sessions: sessions.map(safeSession),
    staleOAuthConnections: connections
      .filter((connection) => connection.auth_mode === "oauth")
      .map((connection) => ({
        companyId: connection.company_id ?? null,
        grantId: connection.grant_id ?? null,
        installationId: connection.installation_id ?? null,
        providerId: connection.provider_id ?? null,
        subscriptionId: connection.webhook_subscription_id ?? null,
      })),
  };
}

async function attempted(operation) {
  try {
    return { ok: true, result: await operation() };
  } catch {
    return { error: "operation_rejected", ok: false };
  }
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function writeRestricted(path, value) {
  await writeFile(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
}

export default async function apiKeyMedusaHelper({ container, args }) {
  const [inputPath, outputPath] = args;
  if (!inputPath || !outputPath) {
    throw new Error("Restricted input and output paths are required.");
  }
  const input = await readJson(inputPath);
  const paymentModule = paymentModuleFrom(container);
  let result;

  if (input.action === "snapshot") {
    result = await snapshot(container, input);
  } else if (input.action === "update-session") {
    const sessionId = requiredText(
      input.sessionId,
      "payment session ID",
      /^payses_[\w-]+$/,
    );
    const amount = requiredText(
      input.amount,
      "payment amount",
      /^(?:0|[1-9]\d*)(?:\.\d{1,2})?$/,
    );
    const currency = requiredText(
      input.currency,
      "payment currency",
      /^[A-Za-z]{3}$/,
    ).toLowerCase();
    result = await attempted(async () => {
      const current = await paymentModule.retrievePaymentSession(sessionId);
      const updated = await paymentModule.updatePaymentSession({
        amount,
        context: current.context ?? undefined,
        currency_code: currency,
        data: current.data ?? {},
        id: sessionId,
        metadata: current.metadata ?? undefined,
      });
      return safeSession(updated);
    });
  } else if (input.action === "cancel-payment") {
    const paymentId = requiredText(
      input.paymentId,
      "payment ID",
      /^pay_[\w-]+$/,
    );
    result = await attempted(async () =>
      safePayment(await paymentModule.cancelPayment(paymentId)),
    );
  } else if (input.action === "delete-session") {
    const sessionId = requiredText(
      input.sessionId,
      "payment session ID",
      /^payses_[\w-]+$/,
    );
    result = await attempted(async () => {
      await paymentModule.deletePaymentSession(sessionId);
      return { deleted: true, sessionId };
    });
  } else {
    throw new Error("Unsupported API-key helper action.");
  }

  await writeRestricted(outputPath, result);
}
