import { Migration } from "@medusajs/framework/mikro-orm/migrations";

/**
 * Medusa models are soft deletable. Declare the standard partial indexes that
 * MikroORM expects for active-row lookups so the checked-in migrations and
 * runtime model metadata remain schema-convergent.
 */
export class Migration20260719000400 extends Migration {
  async up(): Promise<void> {
    this.addSql(
      'CREATE INDEX IF NOT EXISTS "IDX_makepay_connection_deleted_at" ON "makepay_connection" ("deleted_at") WHERE deleted_at IS NULL;',
    );
    this.addSql(
      'CREATE INDEX IF NOT EXISTS "IDX_makepay_oauth_state_deleted_at" ON "makepay_oauth_state" ("deleted_at") WHERE deleted_at IS NULL;',
    );
    this.addSql(
      'CREATE INDEX IF NOT EXISTS "IDX_makepay_payment_projection_deleted_at" ON "makepay_payment_projection" ("deleted_at") WHERE deleted_at IS NULL;',
    );
    this.addSql(
      'CREATE INDEX IF NOT EXISTS "IDX_makepay_webhook_delivery_deleted_at" ON "makepay_webhook_delivery" ("deleted_at") WHERE deleted_at IS NULL;',
    );
  }

  async down(): Promise<void> {
    this.addSql(
      'DROP INDEX IF EXISTS "IDX_makepay_webhook_delivery_deleted_at";',
    );
    this.addSql(
      'DROP INDEX IF EXISTS "IDX_makepay_payment_projection_deleted_at";',
    );
    this.addSql('DROP INDEX IF EXISTS "IDX_makepay_oauth_state_deleted_at";');
    this.addSql('DROP INDEX IF EXISTS "IDX_makepay_connection_deleted_at";');
  }
}
