import assert from "node:assert/strict";
import test from "node:test";

import { Migration20260719000200 } from "../src/modules/makepay/migrations/Migration20260719000200.ts";
import { Migration20260719000500 } from "../src/modules/makepay/migrations/Migration20260719000500.ts";
import { Migration20260719000600 } from "../src/modules/makepay/migrations/Migration20260719000600.ts";

test("Migration002 rollback preserves routing columns now owned by Migration001", async () => {
  const statements = [];
  const migration = Object.create(Migration20260719000200.prototype);
  migration.addSql = (sql) => statements.push(sql);

  await migration.down();

  assert.deepEqual(statements, []);
});

test("Migration005 rollback preserves converged indexes now owned by Migration001", async () => {
  const statements = [];
  const migration = Object.create(Migration20260719000500.prototype);
  migration.addSql = (sql) => statements.push(sql);

  await migration.down();

  assert.deepEqual(statements, []);
});

test("Migration006 converges an already-recorded provisional Migration005 schema", async () => {
  const statements = [];
  const migration = Object.create(Migration20260719000600.prototype);
  migration.addSql = (sql) => statements.push(sql);

  await migration.up();

  assert.equal(statements.length, 1);
  const sql = statements[0];
  for (const required of [
    'ADD COLUMN IF NOT EXISTS "encrypted_registration_id"',
    'ADD COLUMN IF NOT EXISTS "encrypted_authorization_code"',
    'ADD COLUMN IF NOT EXISTS "token_exchange_id"',
    'ADD COLUMN IF NOT EXISTS "encrypted_authorization_code"',
    'ADD COLUMN IF NOT EXISTS "token_exchange_id"',
    'ADD COLUMN IF NOT EXISTS "late_settlement_safe"',
    'ADD COLUMN IF NOT EXISTS "order_correlated_at"',
    'ADD COLUMN IF NOT EXISTS "order_correlated_at"',
    'CREATE TABLE IF NOT EXISTS "makepay_webhook_subscription"',
    '"IDX_makepay_webhook_subscription_remote"',
    '"IDX_makepay_webhook_subscription_routing"',
    '"IDX_makepay_webhook_subscription_deleted_at"',
    '"IDX_makepay_projection_undrained"',
    'ALTER COLUMN "encrypted_registration_id" SET NOT NULL',
  ]) {
    assert.match(
      sql,
      new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
    );
  }
  assert.match(sql, /DELETE FROM "makepay_oauth_state"/);
});

test("Migration006 rollback preserves late-settlement and signing history", async () => {
  const statements = [];
  const migration = Object.create(Migration20260719000600.prototype);
  migration.addSql = (sql) => statements.push(sql);

  await migration.down();

  assert.deepEqual(statements, []);
});
