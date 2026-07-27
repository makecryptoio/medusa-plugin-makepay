import { Migration } from "@medusajs/framework/mikro-orm/migrations";

/**
 * Converge installations that recorded the provisional Migration005 before
 * stable native-registration identity, late-settlement safety, and durable
 * historical webhook credentials were added.
 */
export class Migration20260719000600 extends Migration {
  async up(): Promise<void> {
    this.addSql(`
      ALTER TABLE "makepay_connection"
        ADD COLUMN IF NOT EXISTS "encrypted_registration_id" TEXT NULL;

      ALTER TABLE "makepay_oauth_state"
        ADD COLUMN IF NOT EXISTS "encrypted_registration_id" TEXT NULL,
        ADD COLUMN IF NOT EXISTS "encrypted_authorization_code" TEXT NULL,
        ADD COLUMN IF NOT EXISTS "token_exchange_id" TEXT NULL;

      -- Old pending authorization transactions cannot satisfy the new native
      -- registration identity contract and must never be accepted.
      DELETE FROM "makepay_oauth_state"
      WHERE "encrypted_registration_id" IS NULL;

      ALTER TABLE "makepay_oauth_state"
        ALTER COLUMN "encrypted_registration_id" SET NOT NULL;

      ALTER TABLE "makepay_payment_projection"
        ADD COLUMN IF NOT EXISTS "late_settlement_safe" BOOLEAN NOT NULL DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS "order_correlated_at" TIMESTAMPTZ NULL;

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
      CREATE UNIQUE INDEX IF NOT EXISTS "IDX_makepay_webhook_subscription_remote"
        ON "makepay_webhook_subscription" ("provider_id", "subscription_id")
        WHERE "deleted_at" IS NULL;
      CREATE INDEX IF NOT EXISTS "IDX_makepay_webhook_subscription_routing"
        ON "makepay_webhook_subscription" ("grant_id", "installation_id", "subscription_id")
        WHERE "deleted_at" IS NULL;
      CREATE INDEX IF NOT EXISTS "IDX_makepay_webhook_subscription_deleted_at"
        ON "makepay_webhook_subscription" ("deleted_at")
        WHERE "deleted_at" IS NULL;

      DROP INDEX IF EXISTS "IDX_makepay_projection_undrained";
      CREATE INDEX "IDX_makepay_projection_undrained"
        ON "makepay_payment_projection" ("provider_id", "auth_mode", "id")
        WHERE deleted_at IS NULL AND (
          provider_status NOT IN ('complete', 'archived', 'cancelled')
          OR (provider_status = 'complete' AND (
            medusa_status IS NULL OR medusa_status <> 'paid'
          ))
          OR (provider_status IN ('archived', 'cancelled') AND (
            late_settlement_safe IS FALSE
            OR medusa_status IS NULL
            OR medusa_status <> 'canceled'
          ))
        );
    `);
  }

  async down(): Promise<void> {
    // These additive objects are also owned by the current Migration001. A
    // reverse-one deploy must retain payment routing and verification history.
  }
}
