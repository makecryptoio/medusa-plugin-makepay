import type {
  MakePayConnection,
  MakePayConnectionStatus,
  MakePayWebhookStatus,
} from "../types.js";

export type BadgeColor =
  "green" | "red" | "blue" | "orange" | "grey" | "purple";

const SUCCESS_STATUSES = new Set(["captured", "complete", "paid"]);

const ERROR_STATUSES = new Set([
  "canceled",
  "cancelled",
  "error",
  "expired",
  "failed",
]);

const PENDING_STATUSES = new Set([
  "active",
  "awaiting_deposit",
  "deposit",
  "deposit_received",
  "pending",
  "pending_authorization",
  "processing",
  "quoted",
  "requires_more",
  "send",
  "swap",
  "underpaid",
]);

export const statusColor = (status?: string): BadgeColor => {
  const normalized = status?.trim().toLowerCase() ?? "";

  if (SUCCESS_STATUSES.has(normalized)) {
    return "green";
  }

  if (ERROR_STATUSES.has(normalized)) {
    return "red";
  }

  if (PENDING_STATUSES.has(normalized)) {
    return "orange";
  }

  return normalized ? "blue" : "grey";
};

export const connectionStatusColor = (
  status: MakePayConnectionStatus,
): BadgeColor => {
  if (status === "connected") {
    return "green";
  }

  if (status === "error") {
    return "red";
  }

  if (status === "disconnect_pending") {
    return "orange";
  }

  return "grey";
};

export const oauthConnectionActionLabel = (
  connection: Pick<MakePayConnection, "connected" | "reconnect_required">,
) =>
  connection.connected || connection.reconnect_required
    ? "Reconnect"
    : "Connect MakePay";

export const webhookStatusColor = (
  status: MakePayWebhookStatus,
): BadgeColor => {
  if (status === "healthy") {
    return "green";
  }

  if (status === "error") {
    return "red";
  }

  return "orange";
};

export const humanizeStatus = (status?: string) => {
  if (!status?.trim()) {
    return "Unknown";
  }

  return status
    .trim()
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
};

export const formatMoney = (amount: string, currency: string) => {
  const numericAmount = Number(amount);
  const normalizedCurrency = currency.trim().toUpperCase();

  if (
    !Number.isFinite(numericAmount) ||
    !/^[A-Z]{3}$/.test(normalizedCurrency)
  ) {
    return `${amount} ${normalizedCurrency || currency}`.trim();
  }

  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency: normalizedCurrency,
    }).format(numericAmount);
  } catch {
    return `${amount} ${normalizedCurrency}`;
  }
};

export const formatDateTime = (value?: string) => {
  if (!value) {
    return "—";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "—";
  }

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
};

const SENSITIVE_FIELD_NAME =
  "(?:access[_ -]?token|refresh[_ -]?token|id[_ -]?token|client[_ -]?secret|key[_ -]?secret|api[_ -]?secret|webhook[_ -]?secret|signing[_ -]?secret|code[_ -]?verifier|dpop(?:[_ -]?proof)?|private[_ -]?key|authorization)";

const JSON_DOUBLE_QUOTED_SECRET = new RegExp(
  `(\"${SENSITIVE_FIELD_NAME}\"\\s*:\\s*)\"(?:\\\\.|[^\"\\\\])*\"`,
  "gi",
);
const JSON_SINGLE_QUOTED_SECRET = new RegExp(
  `('${SENSITIVE_FIELD_NAME}'\\s*:\\s*)'(?:\\\\.|[^'\\\\])*'`,
  "gi",
);
const QUOTED_SECRET = new RegExp(
  `\\b(${SENSITIVE_FIELD_NAME})\\b\\s*[:=]\\s*([\"'])(?:\\\\.|(?!\\2).)*\\2`,
  "gi",
);
const UNQUOTED_SECRET = new RegExp(
  `\\b(${SENSITIVE_FIELD_NAME})\\b\\s*[:=]\\s*([^\\s,;&}]+)`,
  "gi",
);

export const redactSensitiveText = (value: string) =>
  value
    .replace(JSON_DOUBLE_QUOTED_SECRET, '$1"[redacted]"')
    .replace(JSON_SINGLE_QUOTED_SECRET, "$1'[redacted]'")
    .replace(
      /\bauthorization\b\s*[:=]\s*(?:bearer|dpop)\s+[^\s,;&]+/gi,
      "authorization=[redacted]",
    )
    .replace(QUOTED_SECRET, "$1=[redacted]")
    .replace(UNQUOTED_SECRET, "$1=[redacted]")
    .replace(
      /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
      "[redacted token]",
    )
    .slice(0, 500);

export const safeExternalUrl = (value?: string) => {
  if (!value) {
    return undefined;
  }

  try {
    const url = new URL(value);
    if (url.username || url.password) {
      return undefined;
    }
    const isSecure = url.protocol === "https:";
    const isLocalHttp =
      url.protocol === "http:" &&
      ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);

    if (!isSecure && !isLocalHttp) {
      return undefined;
    }

    return url.toString();
  } catch {
    return undefined;
  }
};

export const safeOAuthRedirect = (value: string) => {
  try {
    const url = new URL(value);
    if (url.username || url.password) {
      return undefined;
    }
    const isSecure = url.protocol === "https:";
    const isLocalHttp =
      url.protocol === "http:" &&
      ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);

    if (!isSecure && !isLocalHttp) {
      return undefined;
    }

    return url.toString();
  } catch {
    return undefined;
  }
};
