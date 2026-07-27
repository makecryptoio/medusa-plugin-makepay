import { model } from "@medusajs/framework/utils";

const MakePayConnection = model
  .define(
    { name: "MakePayConnection", tableName: "makepay_connection" },
    {
      id: model.id({ prefix: "mpcon" }).primaryKey(),
      provider_id: model.text(),
      installation_id: model.text(),
      auth_mode: model.enum(["api_key", "oauth"]),
      status: model.enum([
        "connected",
        "disconnected",
        "disconnect_pending",
        "error",
      ]),
      client_id: model.text().nullable(),
      company_id: model.text().nullable(),
      company_name: model.text().nullable(),
      grant_id: model.text().nullable(),
      webhook_subscription_id: model.text().nullable(),
      scopes: model.array().default([]),
      encrypted_access_token: model.text().nullable(),
      encrypted_refresh_token: model.text().nullable(),
      encrypted_dpop_private_key: model.text().nullable(),
      encrypted_registration_id: model.text().nullable(),
      encrypted_webhook_secret: model.text().nullable(),
      access_token_expires_at: model.dateTime().nullable(),
      connected_at: model.dateTime().nullable(),
      webhook_url: model.text().nullable(),
      webhook_status: model
        .enum(["healthy", "missing", "error"])
        .default("missing"),
      webhook_last_error: model.text().nullable(),
      last_error: model.text().nullable(),
      metadata: model.json().default({}),
    },
  )
  .indexes([
    {
      name: "IDX_makepay_connection_provider",
      on: ["provider_id"],
      unique: true,
    },
    {
      name: "IDX_makepay_connection_installation",
      on: ["installation_id"],
      unique: true,
    },
  ]);

export default MakePayConnection;
