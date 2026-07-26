import { Migration } from "@medusajs/framework/mikro-orm/migrations";

/**
 * Converge databases that already ran every pre-release migration before
 * projection authentication ownership became explicit.
 */
export class Migration20260719000500 extends Migration {
  async up(): Promise<void> {
    this.addSql(`
      ALTER TABLE "makepay_connection"
        ADD COLUMN IF NOT EXISTS "webhook_subscription_id" TEXT NULL,
        ADD COLUMN IF NOT EXISTS "encrypted_registration_id" TEXT NULL;

      ALTER TABLE "makepay_oauth_state"
        ADD COLUMN IF NOT EXISTS "encrypted_registration_id" TEXT NULL,
        ADD COLUMN IF NOT EXISTS "encrypted_authorization_code" TEXT NULL,
        ADD COLUMN IF NOT EXISTS "token_exchange_id" TEXT NULL;

      ALTER TABLE "makepay_payment_projection"
        ADD COLUMN IF NOT EXISTS "auth_mode" TEXT NULL,
        ADD COLUMN IF NOT EXISTS "grant_id" TEXT NULL,
        ADD COLUMN IF NOT EXISTS "webhook_subscription_id" TEXT NULL,
        ADD COLUMN IF NOT EXISTS "effect_claimed_at" TIMESTAMPTZ NULL,
        ADD COLUMN IF NOT EXISTS "order_correlated_at" TIMESTAMPTZ NULL,
        ADD COLUMN IF NOT EXISTS "late_settlement_safe" BOOLEAN NOT NULL DEFAULT FALSE;

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

      DO $makepay_projection_auth_mode$
      BEGIN
        IF EXISTS (
          SELECT 1
          FROM "makepay_payment_projection"
          WHERE "auth_mode" IS NOT NULL
            AND "auth_mode" NOT IN ('api_key', 'oauth')
        ) THEN
          RAISE EXCEPTION 'makepay_payment_projection contains an unknown auth_mode';
        END IF;

        IF EXISTS (
          SELECT 1
          FROM "makepay_payment_projection"
          WHERE num_nonnulls(
            "grant_id",
            "installation_id",
            "webhook_subscription_id"
          ) NOT IN (0, 3)
        ) THEN
          RAISE EXCEPTION 'makepay_payment_projection contains an incomplete OAuth routing tuple';
        END IF;

        IF EXISTS (
          SELECT 1
          FROM "makepay_payment_projection"
          WHERE ("auth_mode" = 'oauth' AND num_nonnulls(
              "grant_id",
              "installation_id",
              "webhook_subscription_id"
            ) <> 3)
            OR ("auth_mode" = 'api_key' AND num_nonnulls(
              "grant_id",
              "installation_id",
              "webhook_subscription_id"
            ) <> 0)
        ) THEN
          RAISE EXCEPTION 'makepay_payment_projection auth_mode conflicts with its routing tuple';
        END IF;
      END
      $makepay_projection_auth_mode$;

      UPDATE "makepay_payment_projection"
      SET "auth_mode" = CASE
        WHEN num_nonnulls(
          "grant_id",
          "installation_id",
          "webhook_subscription_id"
        ) = 3 THEN 'oauth'
        ELSE 'api_key'
      END
      WHERE "auth_mode" IS NULL;

      ALTER TABLE "makepay_payment_projection"
        ALTER COLUMN "auth_mode" SET NOT NULL;
      ALTER TABLE "makepay_payment_projection"
        DROP CONSTRAINT IF EXISTS "makepay_payment_projection_auth_mode_check";
      ALTER TABLE "makepay_payment_projection"
        ADD CONSTRAINT "makepay_payment_projection_auth_mode_check"
        CHECK ("auth_mode" IN ('api_key', 'oauth'));
      ALTER TABLE "makepay_payment_projection"
        DROP CONSTRAINT IF EXISTS "makepay_payment_projection_routing_owner_check";
      ALTER TABLE "makepay_payment_projection"
        ADD CONSTRAINT "makepay_payment_projection_routing_owner_check" CHECK (
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
        );

      DROP INDEX IF EXISTS "IDX_makepay_projection_provider_auth_status";
      CREATE INDEX "IDX_makepay_projection_provider_auth_status"
        ON "makepay_payment_projection" (
          "provider_id",
          "auth_mode",
          "provider_status",
          "medusa_status"
        )
        WHERE "deleted_at" IS NULL;

      DROP INDEX IF EXISTS "IDX_makepay_projection_undrained";
      CREATE INDEX "IDX_makepay_projection_undrained"
        ON "makepay_payment_projection" (
          "provider_id",
          "auth_mode",
          "id"
        )
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
    // Migration001 in the released chain owns the converged columns,
    // constraints, and indexes above. A destructive rollback here would leave
    // the Migration001-004 schema missing its declared routing indexes and
    // turn the public wrong-mode webhook guard back into an O(n) scan.
  }
}
