import { Migration } from "@medusajs/framework/mikro-orm/migrations";

/**
 * Additive schema for OAuth credentials and the storefront-safe MakePay index.
 * Secrets in these tables are AES-256-GCM envelopes, never plaintext values.
 */
export class Migration20260719000100 extends Migration {
  async up(): Promise<void> {
    this.addSql(`
      CREATE TABLE IF NOT EXISTS "makepay_connection" (
        "id" TEXT NOT NULL,
        "provider_id" TEXT NOT NULL,
        "installation_id" TEXT NOT NULL,
        "auth_mode" TEXT CHECK ("auth_mode" IN ('api_key', 'oauth')) NOT NULL,
        "status" TEXT CHECK ("status" IN ('connected', 'disconnected', 'disconnect_pending', 'error')) NOT NULL,
        "client_id" TEXT NULL,
        "company_id" TEXT NULL,
        "company_name" TEXT NULL,
        "grant_id" TEXT NULL,
        "webhook_subscription_id" TEXT NULL,
        "scopes" JSONB NOT NULL DEFAULT '[]'::jsonb,
        "encrypted_access_token" TEXT NULL,
        "encrypted_refresh_token" TEXT NULL,
        "encrypted_dpop_private_key" TEXT NULL,
        "encrypted_registration_id" TEXT NULL,
        "encrypted_webhook_secret" TEXT NULL,
        "access_token_expires_at" TIMESTAMPTZ NULL,
        "connected_at" TIMESTAMPTZ NULL,
        "webhook_url" TEXT NULL,
        "webhook_status" TEXT CHECK ("webhook_status" IN ('healthy', 'missing', 'error')) NOT NULL DEFAULT 'missing',
        "webhook_last_error" TEXT NULL,
        "last_error" TEXT NULL,
        "metadata" JSONB NOT NULL DEFAULT '{}'::jsonb,
        "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        "deleted_at" TIMESTAMPTZ NULL,
        CONSTRAINT "makepay_connection_pkey" PRIMARY KEY ("id")
      );
      CREATE UNIQUE INDEX IF NOT EXISTS "IDX_makepay_connection_provider" ON "makepay_connection" ("provider_id") WHERE "deleted_at" IS NULL;
      CREATE UNIQUE INDEX IF NOT EXISTS "IDX_makepay_connection_installation" ON "makepay_connection" ("installation_id") WHERE "deleted_at" IS NULL;

      CREATE TABLE IF NOT EXISTS "makepay_oauth_state" (
        "id" TEXT NOT NULL,
        "provider_id" TEXT NOT NULL,
        "state_hash" TEXT NOT NULL,
        "client_id" TEXT NOT NULL,
        "redirect_uri" TEXT NOT NULL,
        "encrypted_code_verifier" TEXT NOT NULL,
        "encrypted_dpop_private_key" TEXT NOT NULL,
        "encrypted_registration_id" TEXT NOT NULL,
        "encrypted_authorization_code" TEXT NULL,
        "token_exchange_id" TEXT NULL,
        "dpop_thumbprint" TEXT NOT NULL,
        "expires_at" TIMESTAMPTZ NOT NULL,
        "consumed_at" TIMESTAMPTZ NULL,
        "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        "deleted_at" TIMESTAMPTZ NULL,
        CONSTRAINT "makepay_oauth_state_pkey" PRIMARY KEY ("id")
      );
      CREATE UNIQUE INDEX IF NOT EXISTS "IDX_makepay_oauth_state_hash" ON "makepay_oauth_state" ("state_hash") WHERE "deleted_at" IS NULL;
      CREATE INDEX IF NOT EXISTS "IDX_makepay_oauth_state_expiry" ON "makepay_oauth_state" ("expires_at") WHERE "deleted_at" IS NULL;

      CREATE TABLE IF NOT EXISTS "makepay_payment_projection" (
        "id" TEXT NOT NULL,
        "auth_mode" TEXT CHECK ("auth_mode" IN ('api_key', 'oauth')) NOT NULL,
        "provider_id" TEXT NOT NULL,
        "installation_id" TEXT NULL,
        "company_id" TEXT NULL,
        "grant_id" TEXT NULL,
        "webhook_subscription_id" TEXT NULL,
        "payment_link_uid" TEXT NOT NULL,
        "session_id" TEXT NOT NULL,
        "payment_id" TEXT NULL,
        "order_id" TEXT NULL,
        "order_display_id" TEXT NULL,
        "order_correlated_at" TIMESTAMPTZ NULL,
        "customer_email" TEXT NULL,
        "amount" TEXT NOT NULL,
        "currency" TEXT NOT NULL,
        "provider_status" TEXT NOT NULL,
        "medusa_status" TEXT NULL,
        "public_url" TEXT NULL,
        "dashboard_url" TEXT NULL,
        "return_state_hash" TEXT NULL,
        "last_synced_at" TIMESTAMPTZ NULL,
        "effect_claimed_at" TIMESTAMPTZ NULL,
        "late_settlement_safe" BOOLEAN NOT NULL DEFAULT FALSE,
        "metadata" JSONB NOT NULL DEFAULT '{}'::jsonb,
        "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        "deleted_at" TIMESTAMPTZ NULL,
        CONSTRAINT "makepay_payment_projection_pkey" PRIMARY KEY ("id"),
        CONSTRAINT "makepay_payment_projection_routing_owner_check" CHECK (
          ("auth_mode" = 'oauth'
            AND "company_id" IS NOT NULL
            AND "grant_id" IS NOT NULL
            AND "installation_id" IS NOT NULL
            AND "webhook_subscription_id" IS NOT NULL)
          OR
          ("auth_mode" = 'api_key'
            AND "grant_id" IS NULL
            AND "installation_id" IS NULL
            AND "webhook_subscription_id" IS NULL)
        )
      );
      CREATE UNIQUE INDEX IF NOT EXISTS "IDX_makepay_projection_uid" ON "makepay_payment_projection" ("payment_link_uid") WHERE "deleted_at" IS NULL;
      CREATE UNIQUE INDEX IF NOT EXISTS "IDX_makepay_projection_session" ON "makepay_payment_projection" ("session_id") WHERE "deleted_at" IS NULL;
      CREATE UNIQUE INDEX IF NOT EXISTS "IDX_makepay_projection_return_state" ON "makepay_payment_projection" ("return_state_hash") WHERE "return_state_hash" IS NOT NULL AND "deleted_at" IS NULL;
      CREATE INDEX IF NOT EXISTS "IDX_makepay_projection_order" ON "makepay_payment_projection" ("order_id") WHERE "deleted_at" IS NULL;
      CREATE INDEX IF NOT EXISTS "IDX_makepay_projection_status" ON "makepay_payment_projection" ("provider_status") WHERE "deleted_at" IS NULL;
      CREATE INDEX IF NOT EXISTS "IDX_makepay_projection_provider_auth_status" ON "makepay_payment_projection" ("provider_id", "auth_mode", "provider_status", "medusa_status") WHERE "deleted_at" IS NULL;
      CREATE INDEX IF NOT EXISTS "IDX_makepay_projection_undrained" ON "makepay_payment_projection" ("provider_id", "auth_mode", "id") WHERE deleted_at IS NULL AND (provider_status NOT IN ('complete', 'archived', 'cancelled') OR (provider_status = 'complete' AND (medusa_status IS NULL OR medusa_status <> 'paid')) OR (provider_status IN ('archived', 'cancelled') AND (late_settlement_safe IS FALSE OR medusa_status IS NULL OR medusa_status <> 'canceled')));
      CREATE INDEX IF NOT EXISTS "IDX_makepay_projection_grant_subscription" ON "makepay_payment_projection" ("grant_id", "webhook_subscription_id") WHERE "deleted_at" IS NULL;

      CREATE TABLE IF NOT EXISTS "makepay_webhook_subscription" (
        "id" TEXT NOT NULL,
        "provider_id" TEXT NOT NULL,
        "subscription_id" TEXT NOT NULL,
        "company_id" TEXT NOT NULL,
        "grant_id" TEXT NOT NULL,
        "installation_id" TEXT NOT NULL,
        "encrypted_signing_secret" TEXT NOT NULL,
        "endpoint_url" TEXT NOT NULL,
        "status" TEXT CHECK ("status" IN ('active', 'historical')) NOT NULL,
        "rotated_at" TIMESTAMPTZ NULL,
        "metadata" JSONB NOT NULL DEFAULT '{}'::jsonb,
        "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        "deleted_at" TIMESTAMPTZ NULL,
        CONSTRAINT "makepay_webhook_subscription_pkey" PRIMARY KEY ("id")
      );
      CREATE UNIQUE INDEX IF NOT EXISTS "IDX_makepay_webhook_subscription_remote" ON "makepay_webhook_subscription" ("provider_id", "subscription_id") WHERE "deleted_at" IS NULL;
      CREATE INDEX IF NOT EXISTS "IDX_makepay_webhook_subscription_routing" ON "makepay_webhook_subscription" ("grant_id", "installation_id", "subscription_id") WHERE "deleted_at" IS NULL;
      CREATE INDEX IF NOT EXISTS "IDX_makepay_webhook_subscription_deleted_at" ON "makepay_webhook_subscription" ("deleted_at") WHERE "deleted_at" IS NULL;

      CREATE TABLE IF NOT EXISTS "makepay_webhook_delivery" (
        "id" TEXT NOT NULL,
        "delivery_id" TEXT NOT NULL,
        "payment_link_uid" TEXT NOT NULL,
        "session_id" TEXT NOT NULL,
        "event_type" TEXT NULL,
        "provider_status" TEXT NOT NULL,
        "payload_hash" TEXT NOT NULL,
        "processed_at" TIMESTAMPTZ NOT NULL,
        "created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        "updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        "deleted_at" TIMESTAMPTZ NULL,
        CONSTRAINT "makepay_webhook_delivery_pkey" PRIMARY KEY ("id")
      );
      CREATE UNIQUE INDEX IF NOT EXISTS "IDX_makepay_webhook_delivery_id" ON "makepay_webhook_delivery" ("delivery_id") WHERE "deleted_at" IS NULL;
      CREATE INDEX IF NOT EXISTS "IDX_makepay_webhook_delivery_uid" ON "makepay_webhook_delivery" ("payment_link_uid") WHERE "deleted_at" IS NULL;
    `);
  }

  async down(): Promise<void> {
    this.addSql('DROP TABLE IF EXISTS "makepay_webhook_delivery" CASCADE;');
    this.addSql('DROP TABLE IF EXISTS "makepay_webhook_subscription" CASCADE;');
    this.addSql('DROP TABLE IF EXISTS "makepay_payment_projection" CASCADE;');
    this.addSql('DROP TABLE IF EXISTS "makepay_oauth_state" CASCADE;');
    this.addSql('DROP TABLE IF EXISTS "makepay_connection" CASCADE;');
  }
}
