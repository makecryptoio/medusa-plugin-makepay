import { model } from "@medusajs/framework/utils";

const MakePayPaymentProjection = model
  .define(
    {
      name: "MakePayPaymentProjection",
      tableName: "makepay_payment_projection",
    },
    {
      id: model.id({ prefix: "mppay" }).primaryKey(),
      auth_mode: model.enum(["api_key", "oauth"]),
      provider_id: model.text(),
      installation_id: model.text().nullable(),
      company_id: model.text().nullable(),
      grant_id: model.text().nullable(),
      webhook_subscription_id: model.text().nullable(),
      payment_link_uid: model.text(),
      session_id: model.text(),
      payment_id: model.text().nullable(),
      order_id: model.text().nullable(),
      order_display_id: model.text().nullable(),
      order_correlated_at: model.dateTime().nullable(),
      customer_email: model.text().nullable(),
      amount: model.text(),
      currency: model.text(),
      provider_status: model.text(),
      medusa_status: model.text().nullable(),
      public_url: model.text().nullable(),
      dashboard_url: model.text().nullable(),
      return_state_hash: model.text().nullable(),
      last_synced_at: model.dateTime().nullable(),
      effect_claimed_at: model.dateTime().nullable(),
      late_settlement_safe: model.boolean().default(false),
      metadata: model.json().default({}),
    },
  )
  .indexes([
    {
      name: "IDX_makepay_projection_uid",
      on: ["payment_link_uid"],
      unique: true,
    },
    {
      name: "IDX_makepay_projection_session",
      on: ["session_id"],
      unique: true,
    },
    {
      name: "IDX_makepay_projection_return_state",
      on: ["return_state_hash"],
      unique: true,
    },
    {
      name: "IDX_makepay_projection_grant_subscription",
      on: ["grant_id", "webhook_subscription_id"],
    },
    { name: "IDX_makepay_projection_order", on: ["order_id"] },
    { name: "IDX_makepay_projection_status", on: ["provider_status"] },
    {
      name: "IDX_makepay_projection_provider_auth_status",
      on: ["provider_id", "auth_mode", "provider_status", "medusa_status"],
    },
    {
      name: "IDX_makepay_projection_undrained",
      on: ["provider_id", "auth_mode", "id"],
      where:
        "deleted_at IS NULL AND (provider_status NOT IN ('complete', 'archived', 'cancelled') OR (provider_status = 'complete' AND (medusa_status IS NULL OR medusa_status <> 'paid')) OR (provider_status IN ('archived', 'cancelled') AND (late_settlement_safe IS FALSE OR medusa_status IS NULL OR medusa_status <> 'canceled')))",
    },
  ])
  .checks([
    {
      name: "makepay_payment_projection_routing_owner_check",
      expression: (columns) =>
        `((${columns.auth_mode} = 'oauth' AND ${columns.company_id} IS NOT NULL AND ${columns.grant_id} IS NOT NULL AND ${columns.installation_id} IS NOT NULL AND ${columns.webhook_subscription_id} IS NOT NULL) OR (${columns.auth_mode} = 'api_key' AND ${columns.grant_id} IS NULL AND ${columns.installation_id} IS NULL AND ${columns.webhook_subscription_id} IS NULL))`,
    },
  ]);

export default MakePayPaymentProjection;
