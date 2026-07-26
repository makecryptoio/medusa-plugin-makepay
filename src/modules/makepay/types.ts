import type { MakePayProviderOptions } from "../../providers/makepay/types.js";

export type MakePayModuleOptions = Partial<MakePayProviderOptions>;

export type MakePayConnectionView = {
  auth_mode: "api_key" | "oauth";
  status: "connected" | "disconnected" | "disconnect_pending" | "error";
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
  webhook: {
    configured: boolean;
    status: "healthy" | "missing" | "error";
    callback_url?: string;
    last_error?: string;
  };
};

export type MakePayPaymentView = {
  auth_mode: "api_key" | "oauth";
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
  grant_id?: string;
  webhook_subscription_id?: string;
  created_at: string;
  updated_at: string;
  last_synced_at?: string;
};

export type MakePayOAuthTokenResponse = {
  access_token: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  token_type?: "Bearer" | "DPoP" | string;
};
