import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstatSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { build as viteBuild } from "vite";

const packageRoot = fileURLToPath(new URL("..", import.meta.url));
const temporaryDirectory = mkdtempSync(join(tmpdir(), "makepay-package-"));
const officialIconSha256 =
  "6bfd99a9fd6d7aa6965de6a00351b2b6783079c8a4f3df481b55a90a4f56be74";
const officialSidebarIconSha256 =
  "f947e8fe1a03d7c80064f670f34f173029f5fe99b7b81feda87ae1a16eab1fc3";

function assertOfficialIcon(bytes, label) {
  assert.ok(
    bytes.subarray(0, 8).equals(Buffer.from("89504e470d0a1a0a", "hex")),
    `${label} is not a PNG`,
  );
  assert.equal(bytes.readUInt32BE(16), 512, `${label} width is not 512px`);
  assert.equal(bytes.readUInt32BE(20), 512, `${label} height is not 512px`);
  assert.equal(
    createHash("sha256").update(bytes).digest("hex"),
    officialIconSha256,
    `${label} is not the reviewed official MakePay mark`,
  );
}

function assertOfficialSidebarIcon(bytes, label) {
  assert.ok(
    bytes.subarray(0, 2).equals(Buffer.from("ffd8", "hex")),
    `${label} is not a JPEG`,
  );
  assert.ok(
    bytes.subarray(-2).equals(Buffer.from("ffd9", "hex")),
    `${label} has no JPEG end marker`,
  );
  assert.equal(
    createHash("sha256").update(bytes).digest("hex"),
    officialSidebarIconSha256,
    `${label} is not the reviewed MakePay sidebar mark`,
  );
}

function normalizeTarget(target) {
  return target.replace(/^\.\//, "");
}

function generatedServerInventory() {
  const inventory = new Set([
    ".medusa/server/src/admin/index.cjs",
    ".medusa/server/src/admin/index.js",
  ]);
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const absolute = join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error(`source tree contains a symbolic link (${absolute})`);
      }
      if (entry.isDirectory()) {
        if (absolute !== join(packageRoot, "src/admin")) visit(absolute);
        continue;
      }
      if (
        !entry.isFile() ||
        !/\.(?:ts|tsx)$/.test(entry.name) ||
        entry.name.endsWith(".d.ts")
      ) {
        continue;
      }
      const source = relative(packageRoot, absolute).replaceAll("\\", "/");
      const stem = source.replace(/\.(?:ts|tsx)$/, "");
      inventory.add(`.medusa/server/${stem}.d.ts`);
      inventory.add(`.medusa/server/${stem}.js`);
    }
  };
  visit(join(packageRoot, "src"));
  return inventory;
}

function assertExactInventory(actual, expected) {
  const unexpected = [...actual].filter((path) => !expected.has(path)).sort();
  const missing = [...expected].filter((path) => !actual.has(path)).sort();
  assert.deepEqual(
    { missing, unexpected },
    { missing: [], unexpected: [] },
    "packed artifact inventory differs from the source-derived allowlist",
  );
}

function assertRegularNonExecutableFile(file, absolutePath) {
  assert.equal(file.mode, 0o644, `packed file has unsafe mode (${file.path})`);
  assert.ok(
    lstatSync(absolutePath).isFile(),
    `packed entry is not a regular file (${file.path})`,
  );
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
  const pkg = JSON.parse(
    readFileSync(join(packageRoot, "package.json"), "utf8"),
  );

  assert.equal(pkg.name, "@makecrypto/medusa-plugin-makepay");
  assert.equal(pkg.version, "1.0.0");
  assert.match(pkg.engines?.node ?? "", />=\s*22/);
  assert.match(pkg.peerDependencies?.["@medusajs/framework"] ?? "", /2\.17\.2/);
  assert.match(pkg.peerDependencies?.["@medusajs/medusa"] ?? "", /2\.17\.2/);
  assert.match(pkg.peerDependencies?.["react-router-dom"] ?? "", /6\.30\.4/);
  assert.equal(pkg.dependencies?.["@makecrypto/makepay"], "0.4.0");
  assert.match(
    pkg.scripts?.check ?? "",
    /npm run typecheck/,
    "release check must run an explicit TypeScript no-emit gate",
  );
  assert.equal(
    pkg.scripts?.prepack,
    "npm run build",
    "npm pack must build the official plugin layout from a clean checkout",
  );
  assert.ok(
    pkg.exports?.["./admin"],
    "package must export its Admin extension",
  );
  assert.ok(
    pkg.exports?.["./providers/makepay"],
    "package must preserve the MakePay provider subpath",
  );
  assert.equal(
    pkg.exports?.["./.medusa/server/src/modules/*"],
    "./.medusa/server/src/modules/*/index.js",
    "Medusa's plugin loader must be able to resolve compiled module definitions",
  );

  const readme = readFileSync(join(packageRoot, "README.md"), "utf8");
  assert.match(readme, /lockingProvider:\s*"makepay-postgres"/);
  assert.match(readme, /@medusajs\/medusa\/locking-postgres/);
  assert.match(readme, /missing or resolves to Medusa's in-memory provider/);
  assert.match(readme, /hooks\/makepay\/makepay_makepay/);
  assert.match(readme, /hooks\/payment\/makepay_makepay/);
  for (const screenshot of [
    "connected-makepay-settings",
    "makepay-payments-list",
    "makepay-order-widget",
    "makepay-sandbox-checkout",
  ]) {
    const url =
      `https://raw.githubusercontent.com/makepay-apps/medusa-plugin-makepay/` +
      `v1.0.0/.github/assets/v1.0.0/${screenshot}.png`;
    assert.equal(
      readme.split(url).length - 1,
      1,
      `README must predeclare exactly one stable ${screenshot} evidence URL`,
    );
  }
  const localE2E = readFileSync(join(packageRoot, "docs/local-e2e.md"), "utf8");
  for (const releaseProvenanceArgument of [
    "--plugin-sha256",
    "--plugin-version",
    "--sdk-sha256",
    "--sdk-version",
  ]) {
    assert.ok(
      localE2E.includes(releaseProvenanceArgument),
      `local E2E release command is missing ${releaseProvenanceArgument}`,
    );
  }
  for (const workflowPath of [
    ".github/workflows/ci.yml",
    ".github/workflows/publish.yml",
  ]) {
    const workflow = readFileSync(join(packageRoot, workflowPath), "utf8");
    const actionReferences = workflow
      .split(/\r?\n/)
      .filter((line) => /^\s*uses:/.test(line));
    assert.ok(actionReferences.length, `${workflowPath} uses no actions`);
    for (const reference of actionReferences) {
      assert.match(
        reference,
        /^\s*uses:\s+[^\s@]+@[a-f0-9]{40}\s+#\s+v\d+\.\d+\.\d+\s*$/,
        `${workflowPath} contains an unpinned or uncommented action reference`,
      );
    }
  }

  const output = execFileSync(
    "npm",
    ["pack", "--json", "--pack-destination", temporaryDirectory],
    { cwd: packageRoot, encoding: "utf8" },
  );
  const [{ filename, files }] = parseNpmPackOutput(output);
  const paths = new Set(files.map((file) => file.path));
  const allowedRootFiles = new Set([
    "CHANGELOG.md",
    "LICENSE",
    "MIGRATING.md",
    "README.md",
    "RELEASE.md",
    "SECURITY.md",
    "package.json",
  ]);
  const allowedAssets = new Set([
    "assets/README.md",
    "assets/makepay-medusa-icon.png",
  ]);
  execFileSync(
    "tar",
    ["-xzf", join(temporaryDirectory, filename), "-C", temporaryDirectory],
    { cwd: packageRoot },
  );
  const packedRoot = join(temporaryDirectory, "package");
  const expectedPaths = generatedServerInventory();
  for (const path of allowedRootFiles) expectedPaths.add(path);
  for (const path of allowedAssets) expectedPaths.add(path);
  expectedPaths.add("docs/local-e2e.md");
  expectedPaths.add("docs/storefront.md");
  assertExactInventory(paths, expectedPaths);

  for (const injected of [
    ".medusa/server/src/api/admin/injected/route.js",
    ".medusa/server/postinstall.sh",
    ".medusa/server/src/providers/makepay/services/stale-output.js",
  ]) {
    assert.throws(
      () => assertExactInventory(new Set([...paths, injected]), expectedPaths),
      /source-derived allowlist/,
      `negative inventory fixture was accepted (${injected})`,
    );
  }
  assert.throws(
    () =>
      assertRegularNonExecutableFile(
        { mode: 0o755, path: ".medusa/server/src/index.js" },
        join(packedRoot, ".medusa/server/src/index.js"),
      ),
    /unsafe mode/,
    "negative executable-mode fixture was accepted",
  );
  assert.throws(
    () =>
      assertRegularNonExecutableFile(
        { mode: 0o644, path: ".medusa/server/src" },
        join(packedRoot, ".medusa/server/src"),
      ),
    /not a regular file/,
    "negative non-file fixture was accepted",
  );

  for (const required of [
    ".medusa/server/src/admin/index.cjs",
    ".medusa/server/src/admin/index.js",
    ".medusa/server/src/api/admin/makepay/payments/route.js",
    ".medusa/server/src/api/hooks/makepay/[provider]/route.js",
    ".medusa/server/src/api/makepay/oauth/callback/route.js",
    ".medusa/server/src/api/middlewares.js",
    ".medusa/server/src/api/store/makepay/checkout-status/route.js",
    ".medusa/server/src/modules/makepay/migrations/Migration20260719000100.js",
    ".medusa/server/src/modules/makepay/migrations/Migration20260719000200.js",
    ".medusa/server/src/modules/makepay/migrations/Migration20260719000300.js",
    ".medusa/server/src/modules/makepay/migrations/Migration20260719000400.js",
    ".medusa/server/src/modules/makepay/migrations/Migration20260719000500.js",
    ".medusa/server/src/modules/makepay/migrations/Migration20260719000600.js",
    ".medusa/server/src/modules/makepay/models/webhook-subscription.js",
    ".medusa/server/src/providers/makepay/index.js",
    ".medusa/server/src/subscribers/makepay-order-placed.js",
    ".medusa/server/src/subscribers/makepay-payment-captured.js",
    "assets/makepay-medusa-icon.png",
    "CHANGELOG.md",
    "docs/local-e2e.md",
    "docs/storefront.md",
    "LICENSE",
    "MIGRATING.md",
    "README.md",
    "package.json",
  ]) {
    assert.ok(paths.has(required), `packed artifact is missing ${required}`);
  }

  const sourceIcon = readFileSync(
    join(packageRoot, "assets/makepay-medusa-icon.png"),
  );
  const packedIcon = readFileSync(
    join(packedRoot, "assets/makepay-medusa-icon.png"),
  );
  assertOfficialIcon(sourceIcon, "source package icon");
  assertOfficialIcon(packedIcon, "packed package icon");
  assert.deepEqual(packedIcon, sourceIcon, "packed package icon changed bytes");

  const adminBundle = readFileSync(
    join(packedRoot, ".medusa/server/src/admin/index.js"),
    "utf8",
  );
  const sidebarIcon = readFileSync(
    join(packageRoot, "src/admin/assets/makepay-sidebar-icon.jpg"),
  );
  assertOfficialSidebarIcon(sidebarIcon, "source Admin sidebar icon");
  assert.ok(
    adminBundle.includes(sidebarIcon.toString("base64")),
    "Admin bundle does not contain the reviewed MakePay sidebar mark",
  );
  for (const marker of [
    "/admin/makepay",
    "MakePay payments",
    "makepay-sidebar-logo",
    "order.details.side.after",
    "settings/makepay",
  ]) {
    assert.ok(
      adminBundle.includes(marker),
      `Admin bundle is missing ${marker}`,
    );
  }

  globalThis.__BACKEND_URL__ = "http://127.0.0.1:9000";
  const require = createRequire(import.meta.url);
  assert.equal(
    require.resolve("@makecrypto/medusa-plugin-makepay/.medusa/server/src/modules/makepay"),
    join(packageRoot, ".medusa/server/src/modules/makepay/index.js"),
  );
  const rootModule = await import(pkg.name);
  const providerModule = await import(`${pkg.name}/providers/makepay`);
  const makePayModule = await import(`${pkg.name}/modules/makepay`);
  assert.equal(typeof rootModule.default, "object");
  assert.equal(typeof providerModule.default, "object");
  assert.equal(typeof makePayModule.default, "object");

  const adminSpecifier = `${pkg.name}/admin`;
  const virtualAdminEntry = "\0makepay-admin-export-check";
  const browserAdminBuild = await viteBuild({
    build: {
      minify: false,
      rollupOptions: {
        external(id) {
          return (
            id !== adminSpecifier &&
            !id.startsWith(".") &&
            !id.startsWith("/") &&
            !id.startsWith("virtual:") &&
            !id.startsWith("\0")
          );
        },
        input: "virtual:makepay-admin-export-check",
        onwarn(warning, warn) {
          if (warning.code !== "MODULE_LEVEL_DIRECTIVE") warn(warning);
        },
      },
      write: false,
    },
    configFile: false,
    define: {
      __BACKEND_URL__: JSON.stringify("http://127.0.0.1:9000"),
    },
    logLevel: "silent",
    plugins: [
      {
        load(id) {
          if (id !== virtualAdminEntry) return undefined;
          return `import admin from ${JSON.stringify(adminSpecifier)};
globalThis.__makePayAdminExport = {
  routes: admin.routeModule.routes.map((route) => route.path),
  zones: admin.widgetModule.widgets.flatMap((widget) => widget.zone),
};`;
        },
        name: "makepay-admin-export-check",
        resolveId(id) {
          return id === "virtual:makepay-admin-export-check"
            ? virtualAdminEntry
            : undefined;
        },
      },
    ],
    root: packageRoot,
  });
  const browserAdminCode = (
    Array.isArray(browserAdminBuild) ? browserAdminBuild : [browserAdminBuild]
  )
    .flatMap((build) => build.output)
    .filter((output) => output.type === "chunk")
    .map((output) => output.code)
    .join("\n");
  assert.match(browserAdminCode, /settings\/makepay/);
  assert.match(browserAdminCode, /order\.details\.side\.after/);

  const adminCommonJs = require(adminSpecifier);
  assert.deepEqual(
    adminCommonJs.routeModule.routes.map((route) => route.path).sort(),
    ["/makepay", "/settings/makepay"],
  );
  assert.deepEqual(adminCommonJs.widgetModule.widgets[0].zone, [
    "order.details.side.after",
  ]);

  for (const file of paths) {
    const packedPath = join(packedRoot, file);
    assertRegularNonExecutableFile(
      files.find((entry) => entry.path === file),
      packedPath,
    );
    assert.ok(
      file.startsWith(".medusa/server/") ||
        file.startsWith("docs/") ||
        allowedRootFiles.has(file) ||
        allowedAssets.has(file),
      `packed artifact contains an unexpected file (${file})`,
    );
    if (file.startsWith("docs/")) {
      assert.match(
        file,
        /^docs\/(?:local-e2e|storefront)\.md$/,
        `packed artifact contains an unexpected documentation file (${file})`,
      );
    }
    if (file.startsWith("assets/")) {
      assert.ok(
        allowedAssets.has(file),
        `packed artifact contains an unreviewed asset (${file})`,
      );
    }
    assert.doesNotMatch(
      file,
      /(^|\/)(\.env(?:\.|$)|\.git(?:\/|$)|tests?(?:\/|$))/i,
    );
    assert.doesNotMatch(
      file,
      /\.map$/i,
      `source map must not be published (${file})`,
    );
    assert.doesNotMatch(file, /\.(?:jwk|key|pem)$/i);
    assert.doesNotMatch(
      file,
      /(?:credentials|customer-data|secrets?)\.(?:json|txt)$/i,
    );
    if (/\.(?:c|m)?js$/.test(file)) {
      const source = readFileSync(packedPath, "utf8");
      assert.doesNotMatch(
        source,
        /sourceMappingURL=/,
        `packed JavaScript must not contain a source map (${file})`,
      );
    }
    if (/\.(?:c|m)?js$|\.(?:json|md|txt|d\.ts)$/.test(file)) {
      const source = readFileSync(packedPath, "utf8");
      assert.doesNotMatch(
        source,
        /(?:npm|sbp|vcp)_[A-Za-z0-9]{20,}/,
        `packed file contains a credential-shaped token (${file})`,
      );
      assert.doesNotMatch(
        source,
        /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
        `packed file contains private key material (${file})`,
      );
    }
  }

  const exportedTargets = [];
  for (const value of Object.values(pkg.exports)) {
    if (typeof value === "string") {
      exportedTargets.push(value);
      continue;
    }
    if (value && typeof value === "object") {
      exportedTargets.push(
        ...Object.values(value).filter((target) => typeof target === "string"),
      );
    }
  }

  for (const target of exportedTargets) {
    if (target.includes("*")) {
      continue;
    }
    const normalizedTarget = normalizeTarget(target);
    assert.ok(
      paths.has(normalizedTarget),
      `export target ${target} is missing from the packed artifact`,
    );
    assert.deepEqual(
      readFileSync(join(packedRoot, normalizedTarget)),
      readFileSync(join(packageRoot, normalizedTarget)),
      `packed export target ${target} differs from the tested build output`,
    );
  }

  for (const [specifier, expectedTarget] of [
    [
      `${pkg.name}/providers/makepay/services`,
      ".medusa/server/src/providers/makepay/services/index.js",
    ],
    [
      `${pkg.name}/.medusa/server/src/modules/makepay/models`,
      ".medusa/server/src/modules/makepay/models/index.js",
    ],
    [
      `${pkg.name}/modules/makepay/models`,
      ".medusa/server/src/modules/makepay/models/index.js",
    ],
  ]) {
    assert.equal(
      require.resolve(specifier),
      join(packageRoot, expectedTarget),
      `wildcard export ${specifier} does not resolve to its packed target`,
    );
    assert.ok(
      paths.has(expectedTarget),
      `wildcard export ${specifier} target is missing from the packed artifact`,
    );
    assert.deepEqual(
      readFileSync(join(packedRoot, expectedTarget)),
      readFileSync(join(packageRoot, expectedTarget)),
      `packed wildcard target ${expectedTarget} differs from the tested build output`,
    );
  }

  assert.ok(
    files.every((file) => Number.isInteger(file.size) && file.size >= 0),
    "npm did not report deterministic file sizes",
  );
  assert.ok(filename.endsWith("-1.0.0.tgz"), `unexpected tarball ${filename}`);

  console.log(`Verified ${filename} (${files.length} files).`);
} finally {
  rmSync(temporaryDirectory, { force: true, recursive: true });
}
