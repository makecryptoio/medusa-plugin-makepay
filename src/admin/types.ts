export type MakePayAuthMode = "api_key" | "oauth";

export type MakePayConnectionStatus =
  "connected" | "disconnected" | "disconnect_pending" | "error";

export type MakePayWebhookStatus = "healthy" | "missing" | "error";

export type MakePayWebhookSummary = {
  configured: boolean;
  status: MakePayWebhookStatus;
  callback_url?: string;
  last_error?: string;
};

export type MakePayConnection = {
  auth_mode: MakePayAuthMode;
  status: MakePayConnectionStatus;
  connected: boolean;
  reconnect_required: boolean;
  company_id?: string;
  company_name?: string;
  client_id?: string;
  scopes: string[];
  access_token_expires_at?: string;
  connected_at?: string;
  updated_at?: string;
  last_error?: string;
  webhook: MakePayWebhookSummary;
};

export type MakePayCapabilities = {
  oauth: boolean;
  api_key: true;
  reconcile: boolean;
  refunds: false;
};

export type MakePayConnectionResponse = {
  connection: MakePayConnection;
  capabilities: MakePayCapabilities;
};

export type MakePayOAuthStartResponse = {
  authorization_url: string;
  expires_at: string;
};

export type MakePayPayment = {
  auth_mode: MakePayAuthMode;
  id: string;
  payment_link_uid: string;
  session_id?: string;
  payment_id?: string;
  order_id?: string;
  order_display_id?: string;
  customer_email?: string;
  amount: string;
  currency: string;
  provider_status: string;
  medusa_status?: string;
  public_url?: string;
  dashboard_url?: string;
  company_id?: string;
  created_at: string;
  updated_at: string;
  last_synced_at?: string;
};

export type MakePayPaymentsResponse = {
  payments: MakePayPayment[];
  count: number;
  limit: number;
  offset: number;
};

export type MakePayPaymentResponse = {
  payment: MakePayPayment | null;
};

export type MakePayPaymentsQuery = {
  q?: string;
  status?: string;
  limit: number;
  offset: number;
};
