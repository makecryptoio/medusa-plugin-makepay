import { Migration } from "@medusajs/framework/mikro-orm/migrations";

/**
 * Harden pre-release projection installs that may already have run the first
 * additive migration while the 1.0.0 schema was under test.
 */
export class Migration20260719000200 extends Migration {
  async up(): Promise<void> {
    this.addSql(`
      ALTER TABLE "makepay_payment_projection"
        ADD COLUMN IF NOT EXISTS "auth_mode" TEXT NULL,
        ADD COLUMN IF NOT EXISTS "grant_id" TEXT NULL,
        ADD COLUMN IF NOT EXISTS "webhook_subscription_id" TEXT NULL;
      UPDATE "makepay_payment_projection"
      SET "auth_mode" = CASE
        WHEN "grant_id" IS NOT NULL
          AND "installation_id" IS NOT NULL
          AND "webhook_subscription_id" IS NOT NULL
        THEN 'oauth'
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
      CREATE INDEX IF NOT EXISTS "IDX_makepay_projection_grant_subscription"
        ON "makepay_payment_projection" ("grant_id", "webhook_subscription_id")
        WHERE "deleted_at" IS NULL;
    `);
  }

  async down(): Promise<void> {
    // Migration001 now owns the converged additive routing columns and index.
    // Removing them here would break the routing-owner constraint and destroy
    // payment ownership metadata on a reverse migration, so rollback preserves
    // the additive schema intentionally.
  }
}
