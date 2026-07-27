import { model } from "@medusajs/framework/utils";

const MakePayOAuthState = model
  .define(
    { name: "MakePayOAuthState", tableName: "makepay_oauth_state" },
    {
      id: model.id({ prefix: "mpost" }).primaryKey(),
      provider_id: model.text(),
      state_hash: model.text(),
      client_id: model.text(),
      redirect_uri: model.text(),
      encrypted_code_verifier: model.text(),
      encrypted_dpop_private_key: model.text(),
      encrypted_registration_id: model.text(),
      encrypted_authorization_code: model.text().nullable(),
      token_exchange_id: model.text().nullable(),
      dpop_thumbprint: model.text(),
      expires_at: model.dateTime(),
      consumed_at: model.dateTime().nullable(),
    },
  )
  .indexes([
    {
      name: "IDX_makepay_oauth_state_hash",
      on: ["state_hash"],
      unique: true,
    },
    { name: "IDX_makepay_oauth_state_expiry", on: ["expires_at"] },
  ]);

export default MakePayOAuthState;
