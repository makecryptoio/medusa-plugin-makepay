import { Migration } from "@medusajs/framework/mikro-orm/migrations";

/**
 * Medusa's `model.array()` persists a PostgreSQL TEXT[] value. The original
 * additive migration declared this column as JSONB, which made MikroORM send
 * a PostgreSQL array literal to a JSONB column during the first OAuth connect.
 * Preserve any pre-release rows while bringing the database in line with the
 * model. Fresh and already-migrated databases both run this migration safely.
 */
export class Migration20260719000300 extends Migration {
  async up(): Promise<void> {
    this.addSql(`
      DO $makepay_scopes$
      DECLARE
        scopes_data_type TEXT;
        scopes_udt_name TEXT;
      BEGIN
        SELECT "data_type", "udt_name"
          INTO scopes_data_type, scopes_udt_name
        FROM "information_schema"."columns"
        WHERE "table_schema" = current_schema()
          AND "table_name" = 'makepay_connection'
          AND "column_name" = 'scopes';

        IF scopes_data_type = 'jsonb' THEN
          IF EXISTS (
            SELECT 1
            FROM "makepay_connection"
            WHERE jsonb_typeof("scopes") <> 'array'
          ) OR EXISTS (
            SELECT 1
            FROM "makepay_connection" AS connection,
              LATERAL jsonb_array_elements(connection."scopes") AS scope(value)
            WHERE jsonb_typeof(scope.value) <> 'string'
          ) THEN
            RAISE EXCEPTION 'makepay_connection.scopes contains invalid JSONB data';
          END IF;

          ALTER TABLE "makepay_connection"
            ADD COLUMN "scopes_text_array" TEXT[] NOT NULL DEFAULT '{}'::TEXT[];

          UPDATE "makepay_connection" AS connection
          SET "scopes_text_array" = ARRAY(
            SELECT jsonb_array_elements_text(connection."scopes")
          );

          ALTER TABLE "makepay_connection" DROP COLUMN "scopes";
          ALTER TABLE "makepay_connection"
            RENAME COLUMN "scopes_text_array" TO "scopes";
        ELSIF scopes_data_type = 'ARRAY' AND scopes_udt_name = '_text' THEN
          NULL;
        ELSIF scopes_data_type IS NULL THEN
          RAISE EXCEPTION 'makepay_connection.scopes column is missing';
        ELSE
          RAISE EXCEPTION
            'makepay_connection.scopes has unsupported database type % (%)',
            scopes_data_type,
            scopes_udt_name;
        END IF;
      END
      $makepay_scopes$;
    `);
  }

  async down(): Promise<void> {
    this.addSql(`
      DO $makepay_scopes$
      DECLARE
        scopes_data_type TEXT;
        scopes_udt_name TEXT;
      BEGIN
        SELECT "data_type", "udt_name"
          INTO scopes_data_type, scopes_udt_name
        FROM "information_schema"."columns"
        WHERE "table_schema" = current_schema()
          AND "table_name" = 'makepay_connection'
          AND "column_name" = 'scopes';

        IF scopes_data_type = 'ARRAY' AND scopes_udt_name = '_text' THEN
          ALTER TABLE "makepay_connection"
            ADD COLUMN "scopes_jsonb" JSONB NOT NULL DEFAULT '[]'::JSONB;

          UPDATE "makepay_connection"
          SET "scopes_jsonb" = to_jsonb("scopes");

          ALTER TABLE "makepay_connection" DROP COLUMN "scopes";
          ALTER TABLE "makepay_connection"
            RENAME COLUMN "scopes_jsonb" TO "scopes";
        ELSIF scopes_data_type = 'jsonb' THEN
          NULL;
        ELSIF scopes_data_type IS NULL THEN
          RAISE EXCEPTION 'makepay_connection.scopes column is missing';
        ELSE
          RAISE EXCEPTION
            'makepay_connection.scopes has unsupported database type % (%)',
            scopes_data_type,
            scopes_udt_name;
        END IF;
      END
      $makepay_scopes$;
    `);
  }
}
