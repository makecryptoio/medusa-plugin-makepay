import { model } from "@medusajs/framework/utils";

/**
 * Durable verification credentials for current and historical grant-scoped
 * webhook destinations. Rows survive OAuth disconnect/token revocation so a
 * late settlement for an already-issued payment link remains verifiable.
 */
const MakePayWebhookSubscription = model
  .define(
    {
      name: "MakePayWebhookSubscription",
      tableName: "makepay_webhook_subscription",
    },
    {
      id: model.id({ prefix: "mpwsub" }).primaryKey(),
      provider_id: model.text(),
      subscription_id: model.text(),
      company_id: model.text(),
      grant_id: model.text(),
      installation_id: model.text(),
      encrypted_signing_secret: model.text(),
      endpoint_url: model.text(),
      status: model.enum(["active", "historical"]),
      rotated_at: model.dateTime().nullable(),
      metadata: model.json().default({}),
    },
  )
  .indexes([
    {
      name: "IDX_makepay_webhook_subscription_remote",
      on: ["provider_id", "subscription_id"],
      unique: true,
    },
    {
      name: "IDX_makepay_webhook_subscription_routing",
      on: ["grant_id", "installation_id", "subscription_id"],
    },
  ]);

export default MakePayWebhookSubscription;
