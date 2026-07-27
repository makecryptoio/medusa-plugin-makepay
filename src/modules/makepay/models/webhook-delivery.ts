import { model } from "@medusajs/framework/utils";

const MakePayWebhookDelivery = model
  .define(
    {
      name: "MakePayWebhookDelivery",
      tableName: "makepay_webhook_delivery",
    },
    {
      id: model.id({ prefix: "mpwh" }).primaryKey(),
      delivery_id: model.text(),
      payment_link_uid: model.text(),
      session_id: model.text(),
      event_type: model.text().nullable(),
      provider_status: model.text(),
      payload_hash: model.text(),
      processed_at: model.dateTime(),
    },
  )
  .indexes([
    {
      name: "IDX_makepay_webhook_delivery_id",
      on: ["delivery_id"],
      unique: true,
    },
    { name: "IDX_makepay_webhook_delivery_uid", on: ["payment_link_uid"] },
  ]);

export default MakePayWebhookDelivery;
