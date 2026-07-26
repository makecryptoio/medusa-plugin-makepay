import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const temporaryDirectory = mkdtempSync(join(tmpdir(), "makepay-medusa-"));
const appDirectory = join(temporaryDirectory, "app");
const packDirectory = join(temporaryDirectory, "pack");
const medusaExecutable = join(
  appDirectory,
  "node_modules",
  ".bin",
  process.platform === "win32" ? "medusa.cmd" : "medusa",
);
const schemaAuditPath = join(appDirectory, "makepay-schema-audit.mjs");
const databaseUrl = process.env.DATABASE_URL;
const sdkTarball = process.env.MAKEPAY_SDK_TARBALL;

if (!databaseUrl) {
  throw new Error(
    "DATABASE_URL is required for the packed Medusa integration test. " +
      "See docs/local-e2e.md.",
  );
}

function run(command, args, options = {}) {
  execFileSync(command, args, {
    cwd: options.cwd ?? packageRoot,
    env: { ...process.env, ...options.env },
    stdio: "inherit",
  });
}

function parseNpmPackOutput(output) {
  for (
    let index = output.lastIndexOf("[");
    index >= 0;
    index = output.lastIndexOf("[", index - 1)
  ) {
    try {
      const value = JSON.parse(output.slice(index).trim());
      if (
        Array.isArray(value) &&
        typeof value[0]?.filename === "string" &&
        Array.isArray(value[0]?.files)
      ) {
        return value;
      }
    } catch {}
  }
  throw new Error("npm pack did not emit a valid package JSON payload");
}

try {
  mkdirSync(appDirectory, { recursive: true });
  mkdirSync(packDirectory, { recursive: true });
  const packOutput = execFileSync(
    "npm",
    ["pack", "--json", "--pack-destination", packDirectory],
    { cwd: packageRoot, encoding: "utf8" },
  );
  const [{ filename }] = parseNpmPackOutput(packOutput);
  const pluginTarball = join(packDirectory, filename);
  const pluginPackage = JSON.parse(
    readFileSync(join(packageRoot, "package.json"), "utf8"),
  );

  writeFileSync(
    join(appDirectory, "package.json"),
    JSON.stringify(
      {
        name: "makepay-medusa-packed-integration",
        private: true,
        dependencies: {
          "@swc/core": "^1.7.28",
          "@medusajs/admin-sdk": "2.17.2",
          "@medusajs/cli": "2.17.2",
          "@medusajs/dashboard": "2.17.2",
          "@medusajs/draft-order": "2.17.2",
          "@medusajs/framework": "2.17.2",
          "@medusajs/icons": "2.17.2",
          "@medusajs/js-sdk": "2.17.2",
          "@medusajs/medusa": "2.17.2",
          "@medusajs/ui": "4.1.19",
          "@makecrypto/makepay": sdkTarball
            ? `file:${resolve(sdkTarball)}`
            : "0.4.0",
          "@tanstack/react-query": "5.64.2",
          jiti: "^2.0.0",
          react: "18.3.1",
          "react-dom": "18.3.1",
          "react-router-dom": "6.30.4",
          "ts-node": "^10.9.2",
          typescript: "^5.6.2",
        },
      },
      null,
      2,
    ) + "\n",
  );

  writeFileSync(
    join(appDirectory, "medusa-config.ts"),
    `import { defineConfig, Modules } from "@medusajs/framework/utils"

const providerOptions = {
  authMode: "api_key" as const,
  keyId: "integration_key_id",
  keySecret: "integration_key_secret",
  webhookSecret: "integration_webhook_secret",
  lockingProvider: "makepay-postgres",
  settlementCurrency: "USDT",
}

export default defineConfig({
  projectConfig: {
    databaseUrl: process.env.DATABASE_URL!,
    http: {
      jwtSecret: "integration_jwt_secret",
      cookieSecret: "integration_cookie_secret",
      storeCors: "http://localhost:8000",
      adminCors: "http://localhost:7001",
      authCors: "http://localhost:7001,http://localhost:8000",
    },
  },
  plugins: [
    {
      resolve: "@makecrypto/medusa-plugin-makepay",
      options: providerOptions,
    },
  ],
  modules: [
    {
      resolve: "@medusajs/medusa/locking",
      options: {
        providers: [
          {
            resolve: "@medusajs/medusa/locking-postgres",
            id: "makepay-postgres",
            is_default: true,
          },
        ],
      },
    },
    {
      resolve: "@medusajs/medusa/payment",
      options: {
        providers: [
          {
            resolve: "@makecrypto/medusa-plugin-makepay/providers/makepay",
            id: "makepay",
            options: providerOptions,
          },
        ],
      },
    },
  ],
})
`,
  );

  writeFileSync(
    join(appDirectory, "tsconfig.json"),
    JSON.stringify(
      {
        compilerOptions: {
          esModuleInterop: true,
          module: "Node16",
          moduleResolution: "Node16",
          resolveJsonModule: true,
          skipLibCheck: true,
          target: "ES2022",
        },
      },
      null,
      2,
    ) + "\n",
  );

  writeFileSync(
    schemaAuditPath,
    `import assert from "node:assert/strict"
import { createRequire } from "node:module"
import { dirname, join } from "node:path"
import { pathToFileURL } from "node:url"
import { MikroORM } from "@medusajs/framework/mikro-orm/postgresql"
import { toMikroORMEntity } from "@medusajs/framework/utils"

const databaseUrl = process.env.DATABASE_URL
assert.ok(databaseUrl, "DATABASE_URL is required")
const require = createRequire(import.meta.url)
const pluginRoot = dirname(
  require.resolve("@makecrypto/medusa-plugin-makepay/package.json")
)
const modelRoot = join(
  pluginRoot,
  ".medusa",
  "server",
  "src",
  "modules",
  "makepay",
  "models"
)
const modelFiles = [
  "connection.js",
  "oauth-state.js",
  "payment-projection.js",
  "webhook-delivery.js",
  "webhook-subscription.js",
]
const models = await Promise.all(
  modelFiles.map(async (file) =>
    (await import(pathToFileURL(join(modelRoot, file)).href)).default
  )
)
const entities = models.map((model) => toMikroORMEntity(model))
const orm = await MikroORM.init({
  clientUrl: databaseUrl,
  debug: false,
  discovery: { warnWhenNoEntities: false },
  entities,
})

async function assertConvergent(label) {
  const sql = await orm.getSchemaGenerator().getUpdateSchemaSQL({
    dropTables: false,
    safe: true,
  })
  const actionable = sql
    .replace(/^\\s*set names ['"]utf8['"];\\s*/i, "")
    .trim()
  assert.equal(actionable, "", label + ":\\n" + sql)
}

try {
  await assertConvergent("MakePay fresh model/migration schema drift")

  if (process.env.MAKEPAY_TEST_PRE_006 === "1") {
    const connection = orm.em.getConnection()
    await connection.execute(
      [
        'DROP INDEX IF EXISTS "IDX_makepay_projection_undrained";',
        'DROP TABLE IF EXISTS "makepay_webhook_subscription" CASCADE;',
        'ALTER TABLE "makepay_connection" DROP COLUMN IF EXISTS "encrypted_registration_id";',
        'ALTER TABLE "makepay_oauth_state" DROP COLUMN IF EXISTS "encrypted_registration_id", DROP COLUMN IF EXISTS "encrypted_authorization_code", DROP COLUMN IF EXISTS "token_exchange_id";',
        'ALTER TABLE "makepay_payment_projection" DROP COLUMN IF EXISTS "late_settlement_safe", DROP COLUMN IF EXISTS "order_correlated_at";',
        "INSERT INTO makepay_oauth_state (id, provider_id, state_hash, client_id, redirect_uri, encrypted_code_verifier, encrypted_dpop_private_key, dpop_thumbprint, expires_at) VALUES ('mpost_pre006', 'makepay', 'pre006_state_hash', 'pre006_client', 'https://shop.test/oauth/callback', 'encrypted_verifier', 'encrypted_dpop', 'pre006_thumbprint', NOW() + INTERVAL '10 minutes');",
      ].join("\\n"),
    )

    const migrationPath = join(
      pluginRoot,
      ".medusa",
      "server",
      "src",
      "modules",
      "makepay",
      "migrations",
      "Migration20260719000600.js",
    )
    const { Migration20260719000600 } = await import(
      pathToFileURL(migrationPath).href
    )
    const statements = []
    const migration = Object.create(Migration20260719000600.prototype)
    migration.addSql = (sql) => statements.push(sql)
    await migration.up()
    assert.equal(statements.length, 1)
    await connection.execute(statements[0])

    const staleStates = await connection.execute(
      "SELECT COUNT(*)::int AS count FROM makepay_oauth_state WHERE id = 'mpost_pre006';",
    )
    assert.equal(staleStates[0].count, 0)
    await assertConvergent(
      "MakePay provisional Migration005 to Migration006 schema drift",
    )
    console.log(
      "MakePay provisional Migration005 schema converges through Migration006.",
    )
  }

  console.log(
    "MakePay packed model/migration schema is convergent.",
  )
} finally {
  await orm.close(true)
}
`,
  );

  run("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund"], {
    cwd: appDirectory,
  });
  run(
    "npm",
    [
      "install",
      "--save-exact",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      `file:${pluginTarball}`,
    ],
    {
      cwd: appDirectory,
    },
  );

  const installedPackage = JSON.parse(
    readFileSync(
      join(
        appDirectory,
        "node_modules/@makecrypto/medusa-plugin-makepay/package.json",
      ),
      "utf8",
    ),
  );
  assert.equal(installedPackage.version, pluginPackage.version);

  const installedConfig = readFileSync(
    join(appDirectory, "medusa-config.ts"),
    "utf8",
  );
  assert.match(installedConfig, /@medusajs\/medusa\/locking-postgres/);
  assert.match(installedConfig, /lockingProvider:\s*"makepay-postgres"/);

  run(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      'await import("@makecrypto/medusa-plugin-makepay/providers/makepay")',
    ],
    { cwd: appDirectory },
  );

  run(medusaExecutable, ["db:migrate"], {
    cwd: appDirectory,
    env: { DATABASE_URL: databaseUrl },
  });
  run(medusaExecutable, ["db:migrate"], {
    cwd: appDirectory,
    env: { DATABASE_URL: databaseUrl },
  });
  run(process.execPath, [schemaAuditPath], {
    cwd: appDirectory,
    env: { DATABASE_URL: databaseUrl, MAKEPAY_TEST_PRE_006: "1" },
  });
  run(medusaExecutable, ["build"], {
    cwd: appDirectory,
    env: { DATABASE_URL: databaseUrl },
  });

  console.log(
    `Installed and built ${pluginPackage.name}@${pluginPackage.version} in Medusa 2.17.2.`,
  );
} finally {
  rmSync(temporaryDirectory, { force: true, recursive: true });
}
