import { spawn, spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createWriteStream } from "node:fs";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import {
  createServer as createHttpServer,
  request as httpRequest,
} from "node:http";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
} from "node:path";
import { StringDecoder } from "node:string_decoder";
import { fileURLToPath } from "node:url";
import { stripVTControlCharacters } from "node:util";
import { gunzipSync, gzipSync } from "node:zlib";
import { createMakePayContractServer } from "../tests/e2e/support/makepay-contract-server.mjs";
import {
  attestDeterministicEvidenceRunCompletion,
  attestEvidenceRunCompletion,
  validateDeterministicPlaywrightReport,
  validateRealSandboxPlaywrightReport,
} from "../tests/e2e/support/evidence.mjs";
import { patchOfficialStorefront } from "../tests/e2e/support/patch-storefront.mjs";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const argv = new Set(process.argv.slice(2));
const realSandbox = argv.has("--real-sandbox");
const keep = argv.has("--keep");
const skipBrowser = argv.has("--skip-browser");
const localDiagnostics = argv.has("--local-diagnostics");
const captureRequested = process.env.MAKEPAY_E2E_CAPTURE === "1";
const sanitizerSelfTest = argv.has("--self-test-sanitizer");
const signalWorkerArgument = [...argv].find((value) =>
  value.startsWith("--self-test-signal-worker="),
);
const signalWorkerStage = signalWorkerArgument?.split("=", 2)[1];
const runId = `medusa-e2e-${new Date().toISOString().replace(/[:.]/g, "-")}-${randomBytes(8).toString("hex")}`;
const realSandboxOwnedEmails = new Set([
  `makepay-real-sandbox+${runId}@example.com`.toLowerCase(),
  `makepay-real-sandbox+${runId}-installation-b@example.com`.toLowerCase(),
  `makepay-real-sandbox+${runId}-installation-b-reconnected@example.com`.toLowerCase(),
]);
const adminEmail = `admin+${runId}@example.com`;
const adminPassword = `E2E-${randomUUID()}-aA1!`;
const secondAdminEmail = `admin+${runId}-installation-b@example.com`;
const secondAdminPassword = `E2E-${randomUUID()}-bB2!`;
const apiKeyAdminEmail = `admin+${runId}-api-key@example.com`;
const apiKeyAdminPassword = `E2E-${randomUUID()}-cC3!`;
const encryptionKey = randomBytes(32).toString("base64");
const secondEncryptionKey = randomBytes(32).toString("base64");
const controlToken = randomBytes(32).toString("hex");
const runtimeSecrets = new Set([
  adminPassword,
  secondAdminPassword,
  apiKeyAdminPassword,
  controlToken,
  encryptionKey,
  secondEncryptionKey,
]);

function registerRuntimeSecret(value) {
  if (typeof value === "string" && value) runtimeSecrets.add(value);
}

const childEnvironmentAllowlist = new Set([
  "CI",
  "FORCE_COLOR",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "LOGNAME",
  "NO_COLOR",
  "PATH",
  "PLAYWRIGHT_BROWSERS_PATH",
  "SHELL",
  "TEMP",
  "TERM",
  "TMP",
  "TMPDIR",
  "TZ",
  "USER",
]);
let isolatedChildHome;
let isolatedNpmCache;
let isolatedNpmGlobalconfig;
let isolatedNpmUserconfig;

function childEnvironment(overrides = {}) {
  const env = {};
  for (const key of childEnvironmentAllowlist) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  env.FORCE_COLOR = "0";
  env.NO_COLOR = "1";
  if (isolatedChildHome) {
    env.HOME = isolatedChildHome;
    env.XDG_CACHE_HOME = join(isolatedChildHome, ".cache");
    env.XDG_CONFIG_HOME = join(isolatedChildHome, ".config");
  }
  if (isolatedNpmCache) {
    env.NPM_CONFIG_CACHE = isolatedNpmCache;
    env.npm_config_cache = isolatedNpmCache;
  }
  if (isolatedNpmUserconfig) {
    env.NPM_CONFIG_USERCONFIG = isolatedNpmUserconfig;
    env.npm_config_userconfig = isolatedNpmUserconfig;
  }
  if (isolatedNpmGlobalconfig) {
    env.NPM_CONFIG_GLOBALCONFIG = isolatedNpmGlobalconfig;
    env.npm_config_globalconfig = isolatedNpmGlobalconfig;
  }
  for (const [key, value] of Object.entries(overrides)) {
    if (value !== undefined && value !== null) env[key] = String(value);
  }
  return env;
}

async function resolveExternalNpmCache(root) {
  const configured = process.env.MAKEPAY_E2E_NPM_CACHE_DIR;
  if (!configured) return undefined;
  if (!isAbsolute(configured)) {
    throw new Error("MAKEPAY_E2E_NPM_CACHE_DIR must be an absolute path.");
  }
  registerRuntimeSecret(configured);

  let entry;
  try {
    entry = await lstat(configured);
  } catch {
    throw new Error(
      "MAKEPAY_E2E_NPM_CACHE_DIR must reference an existing directory.",
    );
  }
  if (
    entry.isSymbolicLink() ||
    !entry.isDirectory() ||
    (entry.mode & 0o077) !== 0 ||
    (typeof process.getuid === "function" && entry.uid !== process.getuid())
  ) {
    throw new Error(
      "MAKEPAY_E2E_NPM_CACHE_DIR must be an owner-controlled private directory.",
    );
  }

  const [canonicalCache, canonicalRoot] = await Promise.all([
    realpath(configured),
    realpath(root),
  ]);
  if (canonicalCache !== resolve(configured)) {
    throw new Error(
      "MAKEPAY_E2E_NPM_CACHE_DIR must not contain symbolic path components.",
    );
  }
  const fromRoot = relative(canonicalRoot, canonicalCache);
  if (!fromRoot || (!fromRoot.startsWith("..") && !isAbsolute(fromRoot))) {
    throw new Error(
      "MAKEPAY_E2E_NPM_CACHE_DIR must be outside the fresh E2E workspace.",
    );
  }
  return canonicalCache;
}

async function prepareIsolatedChildHome(
  root,
  { allowExternalNpmCache = false } = {},
) {
  isolatedChildHome = join(root, "child-home");
  const externalNpmCache = allowExternalNpmCache
    ? await resolveExternalNpmCache(root)
    : undefined;
  isolatedNpmCache = externalNpmCache || join(root, "npm-cache");
  isolatedNpmGlobalconfig = join(isolatedChildHome, ".npm-globalrc");
  isolatedNpmUserconfig = join(isolatedChildHome, ".npmrc");
  const setupTasks = [
    mkdir(join(isolatedChildHome, ".cache"), {
      mode: 0o700,
      recursive: true,
    }),
    mkdir(join(isolatedChildHome, ".config"), {
      mode: 0o700,
      recursive: true,
    }),
  ];
  if (!externalNpmCache) {
    setupTasks.push(mkdir(isolatedNpmCache, { mode: 0o700, recursive: true }));
  }
  await Promise.all(setupTasks);
  await chmod(isolatedChildHome, 0o700);
  if (!externalNpmCache) await chmod(isolatedNpmCache, 0o700);
  await Promise.all([
    writeFile(isolatedNpmGlobalconfig, "", { mode: 0o600 }),
    writeFile(isolatedNpmUserconfig, "", { mode: 0o600 }),
  ]);
  await Promise.all([
    chmod(isolatedNpmGlobalconfig, 0o600),
    chmod(isolatedNpmUserconfig, 0o600),
  ]);
  registerRuntimeSecret(isolatedChildHome);
  registerRuntimeSecret(isolatedNpmCache);
  registerRuntimeSecret(isolatedNpmGlobalconfig);
  registerRuntimeSecret(isolatedNpmUserconfig);
  if (externalNpmCache) log("Using the configured private npm cache.");
}
const childProcesses = new Set();
const foregroundProcesses = new Set();
const mutationProcesses = new Set();
const mutationPorts = new Set();
const supportsProcessGroups = process.platform !== "win32";
const defaultOutputRoot = join(
  packageRoot,
  "output",
  "playwright",
  "medusa-makepay",
);
const runtimeDirectory = join(defaultOutputRoot, "runtime", runId);
let postgres;
let secondPostgres;
let apiKeyPostgres;
let contract;
let contractCaPath;
let temporaryRoot;
let activeProjectRoot;
let activeProjectOwned = false;
let realSandboxControl;
let oauthControl;
let apiKeyControl;
let realSandboxCredentialsPath;
let realSandboxCleanupTargets = [];
let deterministicEvidenceCompletion;
let realSandboxEvidenceCompletion;
let playwrightCompletionReceiptPath;
let realSandboxPlaywrightResultsPath;
let oldSigner;
let completed = false;
let cleanupPromise;
let receivedSignal;
let actionsQuiesced = false;
let ownedOutputRoot;
let disposablePostgresRemovalSafe = true;

function log(message) {
  process.stdout.write(
    `[makepay-e2e] ${sanitizeRuntimeLog(String(message))}\n`,
  );
}

function assertBrowserRunMode({
  capture = captureRequested,
  diagnostics = localDiagnostics,
  real = realSandbox,
  skip = skipBrowser,
} = {}) {
  if (skip && (capture || diagnostics || real)) {
    throw new Error(
      "--skip-browser is setup-only and cannot be combined with real-sandbox, capture, or local diagnostics.",
    );
  }
  return true;
}

function browserCompletionSummary({
  capture = captureRequested,
  real = realSandbox,
  skip = skipBrowser,
} = {}) {
  if (skip) {
    return [
      "Browser scenario explicitly skipped; setup, build, and service checks passed only.",
    ];
  }
  const messages = [
    real
      ? "All requested local Medusa scenario checks passed; post-run cleanup acceptance is pending."
      : "All requested local Medusa checks passed.",
  ];
  if (capture) {
    messages.push(
      "Screenshot candidates were generated. Inspect each PNG at original resolution, approve visual review, render the documentation, then approve the docs review before release.",
    );
  }
  return messages;
}

function parentHarnessRunAccepted({
  completedRun,
  exitCode,
  finalCleanupPassed,
  primaryCleanupPassed,
  signal,
}) {
  return (
    completedRun === true &&
    !signal &&
    primaryCleanupPassed === true &&
    finalCleanupPassed === true &&
    (exitCode === undefined || exitCode === 0)
  );
}

function commandExists(command) {
  return (
    spawnSync(command, ["--version"], {
      env: childEnvironment(),
      stdio: "ignore",
    }).status === 0
  );
}

function findPostgresBinary(name) {
  if (commandExists(name)) return name;
  for (const directory of [
    "/opt/homebrew/opt/postgresql@17/bin",
    "/opt/homebrew/opt/postgresql@16/bin",
    "/usr/local/opt/postgresql@17/bin",
    "/usr/local/opt/postgresql@16/bin",
  ]) {
    const candidate = join(directory, name);
    if (
      spawnSync(candidate, ["--version"], {
        env: childEnvironment(),
        stdio: "ignore",
      }).status === 0
    ) {
      return candidate;
    }
  }
  return null;
}

const MAX_TERMINAL_BOX_BYTES = 128 * 1024;
const TERMINAL_BOX_START = /┌[─━═-]{3,}┐/u;
const TERMINAL_BOX_END = /└[─━═-]{3,}┘/u;

function createSanitizedRecordCollector(onRecord) {
  const decoder = new StringDecoder("utf8");
  let carry = "";
  let terminalBox = "";
  let terminalBoxBytes = 0;
  let terminalBoxOverflow = false;
  let insideTerminalBox = false;
  let ended = false;

  const finishTerminalBox = (unterminated = false) => {
    if (terminalBoxOverflow) {
      onRecord("[redacted oversized terminal box]\n", {
        forcedRedaction: true,
      });
    } else if (unterminated) {
      onRecord("[redacted unterminated terminal box]\n", {
        forcedRedaction: true,
      });
    } else {
      onRecord(terminalBox, { forcedRedaction: false });
    }
    terminalBox = "";
    terminalBoxBytes = 0;
    terminalBoxOverflow = false;
    insideTerminalBox = false;
  };

  const appendTerminalBox = (record) => {
    if (terminalBoxOverflow) return;
    terminalBoxBytes += Buffer.byteLength(record);
    if (terminalBoxBytes > MAX_TERMINAL_BOX_BYTES) {
      terminalBox = "";
      terminalBoxOverflow = true;
      return;
    }
    terminalBox += record;
  };

  const processRecord = (record) => {
    const structure = stripVTControlCharacters(record);
    if (!insideTerminalBox && TERMINAL_BOX_START.test(structure)) {
      insideTerminalBox = true;
    }
    if (!insideTerminalBox) {
      onRecord(record, { forcedRedaction: false });
      return;
    }

    appendTerminalBox(record);
    if (TERMINAL_BOX_END.test(structure)) {
      finishTerminalBox();
    }
  };

  const processDecoded = (value) => {
    carry += value;
    let boundary;
    while ((boundary = carry.indexOf("\n")) !== -1) {
      processRecord(carry.slice(0, boundary + 1));
      carry = carry.slice(boundary + 1);
    }
  };

  return {
    end() {
      if (ended) return;
      ended = true;
      processDecoded(decoder.end());
      if (carry) processRecord(carry);
      carry = "";
      if (insideTerminalBox) finishTerminalBox(true);
    },
    write(chunk) {
      if (ended) return;
      processDecoded(decoder.write(chunk));
    },
  };
}

function run(command, args, options = {}) {
  if (actionsQuiesced && options.cleanup !== true) {
    return Promise.reject(
      new Error("The E2E harness is quiescing and rejects new work."),
    );
  }
  return new Promise((resolvePromise, reject) => {
    const sensitiveFlags = new Set([
      "--api-key",
      "--authorization",
      "--client-secret",
      "--cookie",
      "--credentials-file",
      "--db-url",
      "--database-url",
      "--dbname",
      "--dpop",
      "--encryption-key",
      "--password",
      "--private-key",
      "--publishable-key",
      "--refresh-token",
      "--key-secret",
      "--storage-state",
      "--token",
      "--webhook-secret",
    ]);
    const printableArgs = args.map((arg, index) => {
      if (index > 0 && sensitiveFlags.has(args[index - 1])) {
        return "[redacted]";
      }
      const assignment = [...sensitiveFlags].find((flag) =>
        arg.startsWith(`${flag}=`),
      );
      return assignment ? `${assignment}=[redacted]` : arg;
    });
    log(`${basename(command)} ${printableArgs.join(" ")}`);
    const child = spawn(command, args, {
      cwd: options.cwd || packageRoot,
      detached: supportsProcessGroups,
      env: childEnvironment(options.env),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let timedOut = false;
    let timeout;
    if (Number.isFinite(options.timeoutMs) && options.timeoutMs > 0) {
      timeout = setTimeout(() => {
        timedOut = true;
        try {
          if (supportsProcessGroups) process.kill(-child.pid, "SIGKILL");
          else child.kill("SIGKILL");
        } catch (error) {
          if (error?.code !== "ESRCH") {
            process.stderr.write(
              `[makepay-e2e] ${sanitizeRuntimeLog(`Timed process cleanup warning: ${error.message}`)}\n`,
            );
          }
        }
      }, options.timeoutMs);
      timeout.unref?.();
    }
    foregroundProcesses.add(child);
    let stdout = "";
    let stderr = "";
    {
      const collect = (stream, append, emit, { rawCapture = false } = {}) => {
        const collector = createSanitizedRecordCollector(
          (value, { forcedRedaction }) => {
            const safe = forcedRedaction
              ? value
              : sanitizeRuntimeLog(value);
            append(rawCapture && !forcedRedaction ? value : safe);
            emit(safe);
            options.onOutput?.(safe);
          },
        );
        stream.on("data", (chunk) => {
          collector.write(chunk);
        });
        stream.once("end", () => {
          collector.end();
        });
      };
      collect(
        child.stdout,
        (value) => {
          if (options.capture) stdout += value;
        },
        (value) => {
          if (!options.capture) process.stdout.write(value);
        },
        {
          rawCapture:
            options.capture === true && options.sanitizeCapture === false,
        },
      );
      collect(
        child.stderr,
        (value) => {
          if (options.capture) stderr += value;
        },
        (value) => {
          if (!options.capture) process.stderr.write(value);
        },
      );
    }
    child.once("error", (error) => {
      if (timeout) clearTimeout(timeout);
      foregroundProcesses.delete(child);
      reject(error);
    });
    child.once("close", (code, signal) => {
      if (timeout) clearTimeout(timeout);
      foregroundProcesses.delete(child);
      if (timedOut) {
        reject(new Error(`${command} exceeded its bounded execution time.`));
      } else if (code === 0) resolvePromise({ stderr, stdout });
      else {
        reject(
          new Error(
            `${command} exited with ${code ?? signal}${stderr ? `: ${stderr.slice(-1000)}` : ""}`,
          ),
        );
      }
    });
  });
}

async function startProcess(
  command,
  args,
  {
    cleanup = false,
    cwd,
    env,
    inspectOutput,
    logPath,
    mutator = false,
    mutatorPort,
    onOutput,
  },
) {
  if (actionsQuiesced && !cleanup) {
    throw new Error("The E2E harness is quiescing and rejects new work.");
  }
  const output = createWriteStream(logPath, { flags: "a", mode: 0o600 });
  const outputClosed = new Promise((resolvePromise) => {
    output.once("close", resolvePromise);
    output.once("error", resolvePromise);
  });
  const child = spawn(command, args, {
    cwd,
    detached: supportsProcessGroups,
    env: childEnvironment(env),
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.makePayOutputClosed = outputClosed;
  let openStreams = 2;
  const retainSanitized = (stream) => {
    let finished = false;
    const collector = createSanitizedRecordCollector(
      (value, { forcedRedaction }) => {
        inspectOutput?.(value);
        const safe = forcedRedaction ? value : sanitizeRuntimeLog(value);
        output.write(safe);
        onOutput?.(safe);
      },
    );
    const finish = () => {
      if (finished) return;
      finished = true;
      collector.end();
      openStreams -= 1;
      if (openStreams === 0) output.end();
    };
    stream.on("data", (chunk) => {
      collector.write(chunk);
    });
    stream.once("error", (error) => {
      const safe = sanitizeRuntimeLog(`${error.stack || error}\n`);
      output.write(safe);
      onOutput?.(safe);
      finish();
    });
    stream.once("end", finish);
    stream.once("close", finish);
  };
  retainSanitized(child.stdout);
  retainSanitized(child.stderr);
  childProcesses.add(child);
  if (mutator) {
    mutationProcesses.add(child);
    if (mutatorPort) mutationPorts.add(mutatorPort);
  }
  child.once("close", () => {
    if (supportsProcessGroups) {
      try {
        // A persistent wrapper must not leave descendants behind after its
        // leader exits. Kill immediately, before its PGID can be reused.
        process.kill(-child.pid, "SIGKILL");
      } catch (error) {
        if (error?.code !== "ESRCH") {
          log(
            `Process-group close warning for PID ${child.pid}: ${error.message}`,
          );
        }
      }
    }
    childProcesses.delete(child);
    mutationProcesses.delete(child);
  });
  child.once("error", (error) => {
    const safe = sanitizeRuntimeLog(`${error.stack || error}\n`);
    output.write(safe);
    onOutput?.(safe);
  });
  return child;
}

async function freePort(preferred) {
  const bind = (port, host) =>
    new Promise((resolvePromise, reject) => {
      const server = createNetServer();
      server.once("error", reject);
      server.listen(port, host, () => {
        const address = server.address();
        const boundPort = address.port;
        server.close((error) =>
          error ? reject(error) : resolvePromise(boundPort),
        );
      });
    });

  const port = await bind(preferred || 0, "127.0.0.1");
  if (preferred) {
    try {
      await bind(preferred, "::");
    } catch (error) {
      if (
        !["EADDRNOTAVAIL", "EAFNOSUPPORT", "EPROTONOSUPPORT"].includes(
          error?.code,
        )
      ) {
        throw error;
      }
    }
  }
  return port;
}

async function assertServicePortsAvailable(ports) {
  for (const port of ports) {
    try {
      await freePort(port);
    } catch (error) {
      if (error?.code === "EADDRINUSE") {
        throw new Error(`Required local E2E port ${port} is already in use.`);
      }
      throw error;
    }
  }
}

async function waitForUrl(url, label, timeoutMs = 120_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, { redirect: "manual" });
      if (response.status < 500) return;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 500));
  }
  throw new Error(`${label} did not become ready: ${lastError || url}`);
}

async function upsertEnv(path, values) {
  let source = "";
  try {
    source = await readFile(path, "utf8");
  } catch {}
  const lines = source.split(/\r?\n/).filter(Boolean);
  for (const [key, value] of Object.entries(values)) {
    const prefix = `${key}=`;
    const index = lines.findIndex((line) => line.startsWith(prefix));
    const line = `${prefix}${value}`;
    if (index === -1) lines.push(line);
    else lines[index] = line;
  }
  await writeFile(path, `${lines.join("\n")}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
}

function readEnvValue(source, key) {
  const line = source
    .split(/\r?\n/)
    .find((candidate) => candidate.startsWith(`${key}=`));
  return line?.slice(key.length + 1).trim();
}

function assertE2EDatabaseUrl(value, name) {
  const database = new URL(value);
  const loopback = new Set(["127.0.0.1", "::1", "[::1]", "localhost"]);
  let databaseName = "";
  try {
    databaseName = decodeURIComponent(database.pathname).replace(/^\/+/, "");
  } catch {}
  if (
    !new Set(["postgres:", "postgresql:"]).has(database.protocol) ||
    !loopback.has(database.hostname) ||
    Boolean(database.search) ||
    Boolean(database.hash) ||
    !/e2e/i.test(databaseName) ||
    databaseName.includes("/")
  ) {
    throw new Error(
      `${name} must be a loopback database whose name contains \`e2e\`; remote and ordinary development databases are refused.`,
    );
  }
  registerRuntimeSecret(value);
  registerRuntimeSecret(database.password);
  if (database.password) {
    registerRuntimeSecret(decodeURIComponent(database.password));
  }
  return database.toString();
}

async function startPostgres(
  root,
  { databaseEnvName = "MAKEPAY_E2E_DATABASE_URL", installation = "a" } = {},
) {
  if (process.env[databaseEnvName]) {
    const databaseUrl = assertE2EDatabaseUrl(
      process.env[databaseEnvName],
      databaseEnvName,
    );
    log(
      `Using the explicitly supplied installation ${installation.toUpperCase()} E2E database URL; caller owns cleanup.`,
    );
    return {
      databaseUrl,
      external: true,
    };
  }
  if (
    realSandbox &&
    installation === "b" &&
    process.env.MAKEPAY_E2E_DATABASE_URL
  ) {
    throw new Error(
      "A reusable real-sandbox run requires a distinct MAKEPAY_E2E_SECOND_DATABASE_URL for installation B.",
    );
  }
  if (
    realSandbox &&
    installation === "a" &&
    process.env.MAKEPAY_E2E_SECOND_DATABASE_URL
  ) {
    throw new Error(
      "MAKEPAY_E2E_SECOND_DATABASE_URL cannot be used without MAKEPAY_E2E_DATABASE_URL.",
    );
  }
  const initdb = findPostgresBinary("initdb");
  const pgCtl = findPostgresBinary("pg_ctl");
  const createdb = findPostgresBinary("createdb");
  if (!initdb || !pgCtl || !createdb) {
    throw new Error(
      "PostgreSQL 16+ command-line tools are required. On macOS install `postgresql@16` with Homebrew; this harness starts an isolated cluster and never a global service.",
    );
  }
  const dataDirectory = join(root, `postgres-${installation}`);
  const logPath = join(root, "runtime-raw", `postgres-${installation}.log`);
  const port = await freePort();
  await run(initdb, [
    "--pgdata",
    dataDirectory,
    "--auth=trust",
    "--encoding=UTF8",
    "--no-locale",
    "--username=postgres",
  ]);
  const instance = {
    databaseUrl: undefined,
    dataDirectory,
    external: false,
    pgCtl,
  };
  disposablePostgresRemovalSafe = false;
  // Publish the descriptor before the daemon starts so a signal in the small
  // pg_ctl/createdb window can still stop the isolated cluster.
  if (installation === "b") secondPostgres = instance;
  else if (installation === "api_key") apiKeyPostgres = instance;
  else postgres = instance;
  await run(pgCtl, [
    "--pgdata",
    dataDirectory,
    "--log",
    logPath,
    "--options",
    `-h 127.0.0.1 -p ${port}`,
    "start",
  ]);
  const database = `makepay_medusa_e2e_${installation}_${Date.now()}`;
  await run(createdb, [
    "--host",
    "127.0.0.1",
    "--port",
    String(port),
    "--username",
    "postgres",
    database,
  ]);
  instance.databaseUrl = `postgres://postgres@127.0.0.1:${port}/${database}`;
  return instance;
}

async function stopPostgres(instance) {
  if (!instance || instance.external) return;
  await run(
    instance.pgCtl,
    ["--pgdata", instance.dataDirectory, "stop", "--mode", "fast"],
    {
      cleanup: actionsQuiesced,
      timeoutMs: actionsQuiesced ? 15_000 : undefined,
    },
  );
  const status = spawnSync(
    instance.pgCtl,
    ["--pgdata", instance.dataDirectory, "status"],
    { env: childEnvironment(), stdio: "ignore" },
  ).status;
  if (status !== 3) {
    throw new Error(
      status === 0
        ? "The disposable PostgreSQL process is still running."
        : "The disposable PostgreSQL stop state could not be proven.",
    );
  }
}

async function physicalDatabaseIdentity(databaseUrl) {
  const psql = findPostgresBinary("psql");
  if (!psql) {
    throw new Error(
      "psql is required to prove that real-sandbox databases A and B are distinct.",
    );
  }
  const result = await run(
    psql,
    [
      "--dbname",
      databaseUrl,
      "--tuples-only",
      "--no-align",
      "--set",
      "ON_ERROR_STOP=1",
      "--command",
      "SELECT current_database() || '|' || COALESCE(inet_server_addr()::text, 'local') || '|' || inet_server_port();",
    ],
    {
      capture: true,
      cleanup: actionsQuiesced,
      sanitizeCapture: true,
      timeoutMs: actionsQuiesced ? 15_000 : undefined,
    },
  );
  const identity = result.stdout.trim();
  if (!/^[^|]+\|[^|]+\|\d+$/.test(identity)) {
    throw new Error("PostgreSQL returned an invalid database identity.");
  }
  const [databaseName] = identity.split("|", 1);
  const expectedDatabaseName = decodeURIComponent(
    new URL(databaseUrl).pathname,
  ).replace(/^\/+/, "");
  if (databaseName !== expectedDatabaseName) {
    throw new Error(
      "PostgreSQL physical identity does not match the guarded E2E database name.",
    );
  }
  return identity;
}

async function assertExternalDatabaseEmpty(databaseUrl, label) {
  const psql = findPostgresBinary("psql");
  if (!psql) {
    throw new Error(
      `psql is required to validate the empty ${label} database.`,
    );
  }
  const result = await run(
    psql,
    [
      "--dbname",
      databaseUrl,
      "--tuples-only",
      "--no-align",
      "--set",
      "ON_ERROR_STOP=1",
      "--command",
      `WITH user_namespaces AS (
         SELECT oid FROM pg_namespace
         WHERE nspname NOT IN ('pg_catalog', 'information_schema')
           AND nspname !~ '^pg_toast'
       )
       SELECT
         (SELECT COUNT(*) FROM pg_class
          WHERE relnamespace IN (SELECT oid FROM user_namespaces)
            AND relkind IN ('r', 'p', 'v', 'm', 'S', 'f'))
         +
         (SELECT COUNT(*) FROM pg_proc
          WHERE pronamespace IN (SELECT oid FROM user_namespaces))
         +
         (SELECT COUNT(*) FROM pg_trigger t
          JOIN pg_class c ON c.oid = t.tgrelid
          WHERE c.relnamespace IN (SELECT oid FROM user_namespaces)
            AND NOT t.tgisinternal);`,
    ],
    {
      capture: true,
      cleanup: actionsQuiesced,
      sanitizeCapture: true,
      timeoutMs: actionsQuiesced ? 15_000 : undefined,
    },
  );
  if (result.stdout.trim() !== "0") {
    throw new Error(
      `${label} must be an empty disposable E2E database; existing user tables, sequences, functions, views, or triggers are refused.`,
    );
  }
}

async function seedStaleOAuthConnection(databaseUrl) {
  const psql = findPostgresBinary("psql");
  if (!psql) {
    throw new Error(
      "psql is required to seed the stale OAuth isolation fixture.",
    );
  }
  await run(
    psql,
    [
      "--dbname",
      databaseUrl,
      "--set",
      "ON_ERROR_STOP=1",
      "--command",
      `DO $makepay_scopes_type$
       DECLARE
         scopes_data_type TEXT;
         scopes_udt_name TEXT;
       BEGIN
         SELECT data_type, udt_name
           INTO scopes_data_type, scopes_udt_name
         FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND table_name = 'makepay_connection'
           AND column_name = 'scopes';
         IF scopes_data_type <> 'ARRAY' OR scopes_udt_name <> '_text' THEN
           RAISE EXCEPTION
             'makepay_connection.scopes must be TEXT[], got % (%)',
             scopes_data_type,
             scopes_udt_name;
         END IF;
       END
       $makepay_scopes_type$;
       INSERT INTO makepay_connection
        (id, provider_id, installation_id, auth_mode, status, client_id,
         company_id, company_name, grant_id, scopes, webhook_subscription_id,
         webhook_status, metadata)
       VALUES
        ('mpcon_e2e_stale_oauth', 'makepay', 'installation_e2e_stale_oauth',
         'oauth', 'connected', 'client_e2e_stale_oauth',
         'company_e2e_stale_oauth', 'Stale OAuth fixture',
         'grant_e2e_stale_oauth', '{}'::text[],
         'subscription_e2e_stale_oauth', 'healthy', '{}'::jsonb);
       INSERT INTO makepay_payment_projection
        (id, auth_mode, provider_id, installation_id, company_id, grant_id,
         webhook_subscription_id, payment_link_uid, session_id, amount,
         currency, provider_status, medusa_status, metadata)
       VALUES
        ('mppay_e2e_pending_oauth_transition', 'oauth', 'makepay',
         'installation_e2e_stale_oauth', 'company_e2e_stale_oauth',
         'grant_e2e_stale_oauth', 'subscription_e2e_stale_oauth',
         'pay_e2e_pending_oauth_transition',
         'payses_e2e_pending_oauth_transition', '1.00', 'EUR',
         'active', 'pending_authorization', '{}'::jsonb);`,
    ],
    { capture: true, sanitizeCapture: true },
  );
  log(
    "Seeded non-secret stale OAuth routing and pending-transition fixtures in the isolated API-key database.",
  );
}

async function expireOAuthAccessToken(databaseUrl) {
  const guardedDatabaseUrl = assertE2EDatabaseUrl(
    databaseUrl,
    "OAuth refresh-lock E2E database URL",
  );
  const psql = findPostgresBinary("psql");
  if (!psql) {
    throw new Error(
      "psql is required to expire the OAuth access-token fixture.",
    );
  }
  const expired = await run(
    psql,
    [
      "--dbname",
      guardedDatabaseUrl,
      "--tuples-only",
      "--no-align",
      "--quiet",
      "--set",
      "ON_ERROR_STOP=1",
      "--command",
      `WITH eligible AS MATERIALIZED (
         SELECT id, access_token_expires_at
         FROM makepay_connection
         WHERE provider_id = 'makepay'
           AND auth_mode = 'oauth'
           AND status = 'connected'
           AND webhook_status = 'healthy'
           AND encrypted_access_token IS NOT NULL
           AND encrypted_refresh_token IS NOT NULL
           AND encrypted_dpop_private_key IS NOT NULL
           AND access_token_expires_at > NOW() + INTERVAL '30 seconds'
           AND deleted_at IS NULL
         FOR UPDATE
       ),
       single_eligible AS (
         SELECT MIN(id) AS id,
                MIN(access_token_expires_at) AS previous_expires_at
         FROM eligible
         HAVING COUNT(*) = 1
       ),
       expired AS (
         UPDATE makepay_connection AS connection
         SET access_token_expires_at = NOW() - INTERVAL '5 minutes',
             updated_at = NOW()
         FROM single_eligible
         WHERE connection.id = single_eligible.id
         RETURNING single_eligible.previous_expires_at,
                   connection.access_token_expires_at
       )
       SELECT previous_expires_at::text || '|' ||
              access_token_expires_at::text
       FROM expired;`,
    ],
    { capture: true, sanitizeCapture: true },
  );
  const expiredRows = expired.stdout
    .trim()
    .split("\n")
    .map((value) => value.trim())
    .filter(Boolean);
  const [previousExpiresAt, expiredExpiresAt, ...unexpectedFields] = (
    expiredRows[0] || ""
  ).split("|");
  if (
    expiredRows.length !== 1 ||
    unexpectedFields.length ||
    !previousExpiresAt ||
    !expiredExpiresAt
  ) {
    throw new Error(
      "OAuth refresh-lock fixture requires exactly one healthy connected OAuth credential with a future access-token expiry.",
    );
  }
  return {
    expiredExpiresAt: new Date(expiredExpiresAt).toISOString(),
    previousExpiresAt: new Date(previousExpiresAt).toISOString(),
  };
}

function medusaPostgresLockHash(value) {
  let hash = 5381;
  for (let index = value.length; index--; ) {
    hash = (hash * 33) ^ value.charCodeAt(index);
  }
  return hash >>> 0;
}

async function oauthRefreshLockState(databaseUrl) {
  const guardedDatabaseUrl = assertE2EDatabaseUrl(
    databaseUrl,
    "OAuth refresh-lock E2E database URL",
  );
  const psql = findPostgresBinary("psql");
  if (!psql) {
    throw new Error("psql is required to inspect the OAuth refresh lock.");
  }
  const connection = await run(
    psql,
    [
      "--dbname",
      guardedDatabaseUrl,
      "--tuples-only",
      "--no-align",
      "--quiet",
      "--set",
      "ON_ERROR_STOP=1",
      "--command",
      `SELECT id
       FROM makepay_connection
       WHERE provider_id = 'makepay'
         AND auth_mode = 'oauth'
         AND status = 'connected'
         AND webhook_status = 'healthy'
         AND deleted_at IS NULL;`,
    ],
    { capture: true, sanitizeCapture: true },
  );
  const connectionIds = connection.stdout
    .trim()
    .split("\n")
    .map((value) => value.trim())
    .filter(Boolean);
  if (
    connectionIds.length !== 1 ||
    !/^mpcon_[A-Za-z0-9_-]+$/.test(connectionIds[0])
  ) {
    throw new Error(
      "OAuth refresh-lock inspection requires exactly one healthy connection.",
    );
  }
  const lockKey = medusaPostgresLockHash(
    `makepay-oauth-connection:${connectionIds[0]}`,
  );
  const locks = await run(
    psql,
    [
      "--dbname",
      guardedDatabaseUrl,
      "--tuples-only",
      "--no-align",
      "--quiet",
      "--set",
      "ON_ERROR_STOP=1",
      "--command",
      `SELECT
         COUNT(*) FILTER (WHERE granted)::text || '|' ||
         COUNT(*) FILTER (WHERE NOT granted)::text
       FROM pg_locks
       WHERE locktype = 'advisory'
         AND database = (
           SELECT oid FROM pg_database WHERE datname = current_database()
         )
         AND classid = 0::oid
         AND objid = ${lockKey}::oid
         AND objsubid = 1;`,
    ],
    { capture: true, sanitizeCapture: true },
  );
  const [granted, waiting, ...unexpectedFields] = locks.stdout
    .trim()
    .split("|");
  if (
    unexpectedFields.length ||
    !/^\d+$/.test(granted || "") ||
    !/^\d+$/.test(waiting || "")
  ) {
    throw new Error("PostgreSQL returned an invalid OAuth lock snapshot.");
  }
  return { granted: Number(granted), waiting: Number(waiting) };
}

async function resolveOAuthTransitionFixture(databaseUrl) {
  const psql = findPostgresBinary("psql");
  if (!psql) {
    throw new Error(
      "psql is required to resolve the OAuth transition fixture.",
    );
  }
  await run(
    psql,
    [
      "--dbname",
      databaseUrl,
      "--set",
      "ON_ERROR_STOP=1",
      "--command",
      `UPDATE makepay_payment_projection
       SET provider_status = 'cancelled', medusa_status = 'canceled',
           deleted_at = NOW(), updated_at = NOW()
       WHERE id = 'mppay_e2e_pending_oauth_transition'
         AND auth_mode = 'oauth' AND deleted_at IS NULL;`,
    ],
    { capture: true, sanitizeCapture: true },
  );
  return { resolved: true };
}

async function captureFailureStatus(databaseUrl) {
  const psql = findPostgresBinary("psql");
  if (!psql) {
    throw new Error("psql is required to inspect the capture-failure fixture.");
  }
  const result = await run(
    psql,
    [
      "--dbname",
      databaseUrl,
      "--tuples-only",
      "--no-align",
      "--field-separator=|",
      "--set",
      "ON_ERROR_STOP=1",
      "--command",
      `SELECT
         (to_regclass('public.makepay_e2e_capture_fault') IS NOT NULL)::int,
         (to_regclass('public.makepay_e2e_capture_fault_seq') IS NOT NULL)::int,
         EXISTS (
           SELECT 1 FROM pg_proc p
           JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'public'
             AND p.proname = 'makepay_e2e_capture_fault_once'
             AND p.pronargs = 0
         )::int,
         EXISTS (
           SELECT 1 FROM pg_trigger t
           JOIN pg_class c ON c.oid = t.tgrelid
           JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'public' AND c.relname = 'capture'
             AND t.tgname = 'makepay_e2e_capture_fault_once'
             AND NOT t.tgisinternal
         )::int,
         COALESCE((
           SELECT last_value FROM pg_sequences
           WHERE schemaname = 'public'
             AND sequencename = 'makepay_e2e_capture_fault_seq'
         ), 0);`,
    ],
    {
      capture: true,
      cleanup: actionsQuiesced,
      sanitizeCapture: true,
      timeoutMs: actionsQuiesced ? 15_000 : undefined,
    },
  );
  const fields = result.stdout.trim().split("|");
  if (
    fields.length !== 5 ||
    !fields.slice(0, 4).every((field) => field === "0" || field === "1") ||
    !/^\d+$/.test(fields[4])
  ) {
    throw new Error("The capture-failure fixture returned invalid status.");
  }
  const fixtureObjectCount = fields
    .slice(0, 4)
    .reduce((total, field) => total + Number(field), 0);
  const matchedAttemptCount = Number(fields[4]);
  return {
    armed: fixtureObjectCount === 4,
    failureCount: matchedAttemptCount > 0 ? 1 : 0,
    fixtureObjectCount,
    matchedAttemptCount,
  };
}

async function armCaptureFailureOnce(databaseUrl, sessionId, ownerRunId) {
  if (!/^payses_[\w-]+$/.test(sessionId || "")) {
    throw new Error("The capture-failure fixture requires a valid session ID.");
  }
  if (!/^medusa-e2e-[A-Za-z0-9-]+$/.test(ownerRunId || "")) {
    throw new Error("The capture-failure fixture requires a valid run owner.");
  }
  const before = await captureFailureStatus(databaseUrl);
  if (before.fixtureObjectCount !== 0) {
    throw new Error("The capture-failure fixture is already present.");
  }
  const psql = findPostgresBinary("psql");
  if (!psql) {
    throw new Error("psql is required to arm the capture-failure fixture.");
  }
  await run(
    psql,
    [
      "--dbname",
      databaseUrl,
      "--set",
      "ON_ERROR_STOP=1",
      "--command",
      `BEGIN;
       DO $guard$
       BEGIN
         IF current_schema() <> 'public' THEN
           RAISE EXCEPTION 'capture-failure fixture requires the public schema';
         END IF;
         IF NOT EXISTS (
           SELECT 1 FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'public' AND c.relname = 'capture'
             AND c.relkind = 'r'
         ) OR NOT EXISTS (
           SELECT 1 FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'public' AND c.relname = 'payment'
             AND c.relkind = 'r'
         ) OR NOT EXISTS (
           SELECT 1 FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'public' AND c.relname = 'payment_session'
             AND c.relkind = 'r'
         ) THEN
           RAISE EXCEPTION 'capture-failure fixture schema guard failed';
         END IF;
         IF NOT EXISTS (
           SELECT 1 FROM pg_attribute
           WHERE attrelid = 'public.capture'::regclass
             AND attname = 'payment_id' AND atttypid = 'text'::regtype
             AND attnum > 0 AND NOT attisdropped
         ) OR NOT EXISTS (
           SELECT 1 FROM pg_attribute
           WHERE attrelid = 'public.payment'::regclass
             AND attname = 'id' AND atttypid = 'text'::regtype
             AND attnum > 0 AND NOT attisdropped
         ) OR NOT EXISTS (
           SELECT 1 FROM pg_attribute
           WHERE attrelid = 'public.payment'::regclass
             AND attname = 'payment_session_id'
             AND atttypid = 'text'::regtype
             AND attnum > 0 AND NOT attisdropped
         ) OR NOT EXISTS (
           SELECT 1 FROM pg_attribute
           WHERE attrelid = 'public.payment'::regclass
             AND attname = 'provider_id' AND atttypid = 'text'::regtype
             AND attnum > 0 AND NOT attisdropped
         ) OR NOT EXISTS (
           SELECT 1 FROM pg_attribute
           WHERE attrelid = 'public.payment_session'::regclass
             AND attname = 'id' AND atttypid = 'text'::regtype
             AND attnum > 0 AND NOT attisdropped
         ) OR NOT EXISTS (
           SELECT 1 FROM pg_attribute
           WHERE attrelid = 'public.payment_session'::regclass
             AND attname = 'provider_id' AND atttypid = 'text'::regtype
             AND attnum > 0 AND NOT attisdropped
         ) THEN
           RAISE EXCEPTION 'capture-failure fixture column guard failed';
         END IF;
         IF to_regclass('public.makepay_e2e_capture_fault') IS NOT NULL
           OR to_regclass('public.makepay_e2e_capture_fault_seq') IS NOT NULL
           OR EXISTS (
             SELECT 1 FROM pg_proc p
             JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'public'
               AND p.proname = 'makepay_e2e_capture_fault_once'
           ) OR EXISTS (
             SELECT 1 FROM pg_trigger t
             JOIN pg_class c ON c.oid = t.tgrelid
             JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'public' AND c.relname = 'capture'
               AND t.tgname = 'makepay_e2e_capture_fault_once'
               AND NOT t.tgisinternal
           ) THEN
           RAISE EXCEPTION 'capture-failure fixture objects already exist';
         END IF;
       END
       $guard$;
       CREATE TABLE public.makepay_e2e_capture_fault (
         singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
         owner_run_id TEXT NOT NULL,
         target_session TEXT NOT NULL,
         target_provider TEXT NOT NULL CHECK (
           target_provider = 'pp_makepay_makepay'
         )
       );
       INSERT INTO public.makepay_e2e_capture_fault
         (singleton, owner_run_id, target_session, target_provider)
       VALUES (
         TRUE,
         current_setting('makepay.e2e_owner_run_id'),
         current_setting('makepay.e2e_target_session'),
         'pp_makepay_makepay'
       );
       DO $target_guard$
       BEGIN
         IF (
           SELECT COUNT(*)
           FROM public.payment_session ps
           JOIN public.makepay_e2e_capture_fault f
             ON f.target_session = ps.id
           WHERE ps.provider_id = f.target_provider
             AND ps.deleted_at IS NULL
         ) <> 1 THEN
           RAISE EXCEPTION 'capture-failure target session guard failed';
         END IF;
       END
       $target_guard$;
       CREATE SEQUENCE public.makepay_e2e_capture_fault_seq
         AS BIGINT MINVALUE 1 START 1 NO CYCLE;
       CREATE FUNCTION public.makepay_e2e_capture_fault_once()
       RETURNS TRIGGER
       LANGUAGE plpgsql
       SECURITY INVOKER
       SET search_path = pg_catalog, public
       AS $fault$
       DECLARE
         is_target BOOLEAN;
         matched_attempt BIGINT;
       BEGIN
         SELECT EXISTS (
           SELECT 1
           FROM public.payment p
           JOIN public.makepay_e2e_capture_fault f
             ON f.target_session = p.payment_session_id
            AND f.target_provider = p.provider_id
           WHERE p.id = NEW.payment_id AND p.deleted_at IS NULL
         ) INTO is_target;
         IF is_target THEN
           matched_attempt := nextval(
             'public.makepay_e2e_capture_fault_seq'::regclass
           );
           IF matched_attempt = 1 THEN
             RAISE EXCEPTION USING
               ERRCODE = 'P0001',
               MESSAGE = 'MakePay E2E one-shot capture failure';
           END IF;
         END IF;
         RETURN NEW;
       END
       $fault$;
       CREATE TRIGGER makepay_e2e_capture_fault_once
       BEFORE INSERT ON public.capture
       FOR EACH ROW EXECUTE FUNCTION public.makepay_e2e_capture_fault_once();
       COMMIT;`,
    ],
    {
      capture: true,
      env: {
        PGOPTIONS: `-c makepay.e2e_owner_run_id=${ownerRunId} -c makepay.e2e_target_session=${sessionId}`,
      },
      sanitizeCapture: true,
    },
  );
  const status = await captureFailureStatus(databaseUrl);
  if (
    !status.armed ||
    status.fixtureObjectCount !== 4 ||
    status.matchedAttemptCount !== 0
  ) {
    throw new Error("The capture-failure fixture did not arm cleanly.");
  }
  return { ...status, targetSessionId: sessionId };
}

async function disarmCaptureFailure(databaseUrl, ownerRunId) {
  if (!/^medusa-e2e-[A-Za-z0-9-]+$/.test(ownerRunId || "")) {
    throw new Error("The capture-failure cleanup requires a valid run owner.");
  }
  const before = await captureFailureStatus(databaseUrl);
  if (before.fixtureObjectCount === 0) return before;
  const psql = findPostgresBinary("psql");
  if (!psql) {
    throw new Error("psql is required to disarm the capture-failure fixture.");
  }
  await run(
    psql,
    [
      "--dbname",
      databaseUrl,
      "--set",
      "ON_ERROR_STOP=1",
      "--command",
      `DO $drop_fixture$
       DECLARE
         fixture_owner TEXT;
       BEGIN
         IF to_regclass('public.makepay_e2e_capture_fault') IS NULL THEN
           RAISE EXCEPTION 'capture-failure fixture is not owned by this run';
         END IF;
         EXECUTE
           'SELECT owner_run_id FROM public.makepay_e2e_capture_fault WHERE singleton = TRUE'
           INTO fixture_owner;
         IF fixture_owner IS DISTINCT FROM current_setting(
           'makepay.e2e_owner_run_id'
         ) THEN
           RAISE EXCEPTION 'capture-failure fixture owner mismatch';
         END IF;
         IF to_regclass('public.capture') IS NOT NULL THEN
           EXECUTE 'DROP TRIGGER IF EXISTS makepay_e2e_capture_fault_once ON public.capture';
         END IF;
         EXECUTE 'DROP FUNCTION IF EXISTS public.makepay_e2e_capture_fault_once()';
         EXECUTE 'DROP TABLE public.makepay_e2e_capture_fault';
         EXECUTE 'DROP SEQUENCE IF EXISTS public.makepay_e2e_capture_fault_seq';
       END
       $drop_fixture$;`,
    ],
    {
      capture: true,
      cleanup: actionsQuiesced,
      env: {
        PGOPTIONS: `-c makepay.e2e_owner_run_id=${ownerRunId}`,
      },
      sanitizeCapture: true,
      timeoutMs: actionsQuiesced ? 15_000 : undefined,
    },
  );
  const status = await captureFailureStatus(databaseUrl);
  if (status.fixtureObjectCount !== 0) {
    throw new Error("The capture-failure fixture was not fully removed.");
  }
  return status;
}

function assertSha256(value, name) {
  if (!/^[a-f0-9]{64}$/.test(value || "")) {
    throw new Error(`${name} must be a lowercase SHA-256 digest.`);
  }
  return value;
}

async function manifestFromTarball(tarball, label) {
  const result = await run("tar", ["-xOf", tarball, "package/package.json"], {
    capture: true,
    sanitizeCapture: false,
  });
  let manifest;
  try {
    manifest = JSON.parse(result.stdout);
  } catch {
    throw new Error(`${label} tarball has no valid package manifest.`);
  }
  return manifest;
}

const sha256Bytes = (value) => createHash("sha256").update(value).digest("hex");

function artifactPathAllowlist(packageName) {
  if (packageName === "@makecrypto/makepay") {
    return new Set([
      "package/LICENSE",
      "package/README.md",
      "package/dist/index.d.ts",
      "package/dist/index.js",
      "package/package.json",
    ]);
  }
  if (packageName !== "@makecrypto/medusa-plugin-makepay") {
    throw new Error("No artifact path allowlist exists for this package.");
  }
  const paths = new Set([
    "package/CHANGELOG.md",
    "package/LICENSE",
    "package/MIGRATING.md",
    "package/README.md",
    "package/RELEASE.md",
    "package/SECURITY.md",
    "package/assets/README.md",
    "package/assets/makepay-medusa-icon.png",
    "package/docs/local-e2e.md",
    "package/docs/storefront.md",
    "package/package.json",
    "package/.medusa/server/src/admin/index.cjs",
    "package/.medusa/server/src/admin/index.js",
  ]);
  const serverModules = [
    "api/admin/makepay/connection/route",
    "api/admin/makepay/disconnect/route",
    "api/admin/makepay/oauth/start/route",
    "api/admin/makepay/orders/[orderId]/route",
    "api/admin/makepay/payments/[id]/reconcile/route",
    "api/admin/makepay/payments/[id]/route",
    "api/admin/makepay/payments/route",
    "api/hooks/makepay/[provider]/route",
    "api/lib/makepay",
    "api/makepay/checkout/return/route",
    "api/makepay/oauth/callback/route",
    "api/middlewares",
    "api/store/makepay/checkout-status/route",
    "index",
    "lib/payment-state",
    "lib/terminal-session",
    "modules/makepay/constants",
    "modules/makepay/crypto",
    "modules/makepay/index",
    "modules/makepay/migrations/Migration20260719000100",
    "modules/makepay/migrations/Migration20260719000200",
    "modules/makepay/migrations/Migration20260719000300",
    "modules/makepay/migrations/Migration20260719000400",
    "modules/makepay/migrations/Migration20260719000500",
    "modules/makepay/migrations/Migration20260719000600",
    "modules/makepay/models/connection",
    "modules/makepay/models/index",
    "modules/makepay/models/oauth-state",
    "modules/makepay/models/payment-projection",
    "modules/makepay/models/webhook-delivery",
    "modules/makepay/models/webhook-subscription",
    "modules/makepay/service",
    "modules/makepay/types",
    "providers/makepay/index",
    "providers/makepay/services/index",
    "providers/makepay/services/makepay-provider",
    "providers/makepay/types",
    "providers/makepay/utils",
    "subscribers/makepay-order-placed",
    "subscribers/makepay-payment-captured",
  ];
  for (const modulePath of serverModules) {
    paths.add(`package/.medusa/server/src/${modulePath}.d.ts`);
    paths.add(`package/.medusa/server/src/${modulePath}.js`);
  }
  return paths;
}

function tarText(field, label) {
  const zero = field.indexOf(0);
  const end = zero === -1 ? field.length : zero;
  if (
    zero !== -1 &&
    !field.subarray(zero).every((value) => value === 0 || value === 32)
  ) {
    throw new Error(`${label} archive contains an invalid tar string.`);
  }
  return field.subarray(0, end).toString("utf8");
}

function tarOctal(field, label) {
  if (field[0] & 0x80) {
    throw new Error(`${label} archive uses unsupported binary tar numbers.`);
  }
  const text = field.toString("ascii").replaceAll("\0", "").trim();
  if (!/^[0-7]+$/.test(text || "0")) {
    throw new Error(`${label} archive contains an invalid tar number.`);
  }
  return Number.parseInt(text || "0", 8);
}

function inspectArtifactArchive(bytes, packageName, label) {
  if (bytes.length > 20 * 1024 * 1024) {
    throw new Error(`${label} compressed artifact is unexpectedly large.`);
  }
  let archive;
  try {
    archive = gunzipSync(bytes, { maxOutputLength: 64 * 1024 * 1024 });
  } catch {
    throw new Error(`${label} artifact is not a bounded gzip tar archive.`);
  }
  const allowed = artifactPathAllowlist(packageName);
  const seen = new Set();
  const normalizedSeen = new Set();
  let offset = 0;
  let totalSize = 0;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((value) => value === 0)) {
      if (!archive.subarray(offset).every((value) => value === 0)) {
        throw new Error(`${label} archive has data after its tar terminator.`);
      }
      break;
    }
    const storedChecksum = tarOctal(header.subarray(148, 156), label);
    let calculatedChecksum = 0;
    for (let index = 0; index < header.length; index += 1) {
      calculatedChecksum += index >= 148 && index < 156 ? 32 : header[index];
    }
    if (storedChecksum !== calculatedChecksum) {
      throw new Error(`${label} archive contains an invalid tar checksum.`);
    }
    const name = tarText(header.subarray(0, 100), label);
    const prefix = tarText(header.subarray(345, 500), label);
    const path = prefix ? `${prefix}/${name}` : name;
    const type = header[156];
    const linkName = tarText(header.subarray(157, 257), label);
    const mode = tarOctal(header.subarray(100, 108), label);
    const size = tarOctal(header.subarray(124, 136), label);
    if ((type !== 0 && type !== 48) || linkName) {
      throw new Error(
        `${label} archive may contain only regular, non-linked files.`,
      );
    }
    if ((mode & 0o7777) !== 0o644) {
      throw new Error(`${label} archive files must have exact mode 0644.`);
    }
    const safeCharacters =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._@/[]()-";
    const segments = path.split("/");
    if (
      !path.startsWith("package/") ||
      path.startsWith("/") ||
      path.includes("\\") ||
      ![...path].every((character) => safeCharacters.includes(character)) ||
      segments.some(
        (segment) => !segment || segment === "." || segment === "..",
      )
    ) {
      throw new Error(`${label} archive contains an unsafe path.`);
    }
    const normalized = path.normalize("NFC").toLowerCase();
    if (seen.has(path) || normalizedSeen.has(normalized)) {
      throw new Error(
        `${label} archive contains a duplicate or case-colliding path.`,
      );
    }
    if (!allowed.has(path)) {
      throw new Error(`${label} archive contains unexpected path ${path}.`);
    }
    if (!Number.isSafeInteger(size) || size > 16 * 1024 * 1024) {
      throw new Error(`${label} archive contains an oversized file.`);
    }
    seen.add(path);
    normalizedSeen.add(normalized);
    totalSize += size;
    if (totalSize > 64 * 1024 * 1024) {
      throw new Error(`${label} archive expands beyond its size limit.`);
    }
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  if (offset > archive.length || seen.size !== allowed.size) {
    throw new Error(
      `${label} archive does not match its exact path allowlist.`,
    );
  }
  for (const path of allowed) {
    if (!seen.has(path)) {
      throw new Error(`${label} archive is missing required path ${path}.`);
    }
  }
}

function tarFixture(entries) {
  const blocks = [];
  const writeText = (header, value, start, length) => {
    Buffer.from(value).copy(header, start, 0, Math.min(length, value.length));
  };
  const writeOctal = (header, value, start, length) => {
    writeText(
      header,
      `${value.toString(8).padStart(length - 1, "0")}\0`,
      start,
      length,
    );
  };
  for (const entry of entries) {
    const body = Buffer.from(entry.body || "");
    const header = Buffer.alloc(512);
    writeText(header, entry.path, 0, 100);
    writeOctal(header, entry.mode ?? 0o644, 100, 8);
    writeOctal(header, 0, 108, 8);
    writeOctal(header, 0, 116, 8);
    writeOctal(header, entry.declaredSize ?? body.length, 124, 12);
    writeOctal(header, 0, 136, 12);
    header.fill(32, 148, 156);
    header[156] = (entry.type || "0").charCodeAt(0);
    if (entry.linkName) writeText(header, entry.linkName, 157, 100);
    writeText(header, "ustar\0", 257, 6);
    writeText(header, "00", 263, 2);
    let checksum = 0;
    for (const value of header) checksum += value;
    writeText(header, `${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8);
    blocks.push(header, body);
    const padding = (512 - (body.length % 512)) % 512;
    if (padding) blocks.push(Buffer.alloc(padding));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

async function assertPrivateArtifactCopy(path, expectedSha256, label) {
  const file = await stat(path);
  if (
    !file.isFile() ||
    (file.mode & 0o777) !== 0o400 ||
    (typeof process.getuid === "function" && file.uid !== process.getuid())
  ) {
    throw new Error(
      `${label} private artifact copy must be an owner-controlled 0400 regular file.`,
    );
  }
  const digest = await sha256File(path);
  if (digest !== expectedSha256) {
    throw new Error(
      `${label} private artifact copy changed after verification.`,
    );
  }
  return digest;
}

async function snapshotArtifactBytes({
  expectedSha256,
  label,
  privateRoot,
  source,
}) {
  registerRuntimeSecret(resolve(source));
  const canonicalSource = await realpath(source);
  registerRuntimeSecret(canonicalSource);
  const sourceStat = await stat(canonicalSource);
  if (!sourceStat.isFile()) {
    throw new Error(`${label} tarball is not a regular file.`);
  }

  // A single read defines the exact bytes we attest and later install. Any
  // source-path replacement before/during this read either produces the
  // expected bytes or fails the supplied digest; the original mutable path is
  // never used again.
  const bytes = await readFile(canonicalSource);
  const digest = sha256Bytes(bytes);
  if (
    expectedSha256 &&
    digest !== assertSha256(expectedSha256, `${label} hash`)
  ) {
    throw new Error(`${label} tarball does not match its expected SHA-256.`);
  }

  const privateDirectory = join(privateRoot, "verified-artifacts");
  await mkdir(privateDirectory, { mode: 0o700, recursive: true });
  await chmod(privateDirectory, 0o700);
  const slug = label.toLowerCase().replace(/[^a-z0-9]+/g, "-");
  const privatePath = join(
    privateDirectory,
    `${slug}-${randomUUID().replaceAll("-", "")}.tgz`,
  );
  registerRuntimeSecret(privatePath);
  await writeFile(privatePath, bytes, { flag: "wx", mode: 0o400 });
  await chmod(privatePath, 0o400);
  await assertPrivateArtifactCopy(privatePath, digest, label);
  return { bytes, digest, privatePath };
}

async function artifactFromTarball({
  expectedName,
  expectedSha256,
  expectedVersion,
  label,
  tarball,
}) {
  const { bytes, digest, privatePath } = await snapshotArtifactBytes({
    expectedSha256,
    label,
    privateRoot: temporaryRoot,
    source: tarball,
  });
  inspectArtifactArchive(bytes, expectedName, label);
  const manifest = await manifestFromTarball(privatePath, label);
  if (manifest.name !== expectedName || manifest.version !== expectedVersion) {
    throw new Error(
      `${label} tarball must contain ${expectedName}@${expectedVersion}.`,
    );
  }
  await assertPrivateArtifactCopy(privatePath, digest, label);
  log(`${label} artifact sha256: ${digest}`);
  return { sha256: digest, tarball: privatePath, version: manifest.version };
}

async function packPlugin(root) {
  const suppliedTarball = process.env.MAKEPAY_PLUGIN_TARBALL;
  if (suppliedTarball) {
    if (!process.env.MAKEPAY_PLUGIN_TARBALL_SHA256) {
      throw new Error(
        "MAKEPAY_PLUGIN_TARBALL_SHA256 is required with MAKEPAY_PLUGIN_TARBALL.",
      );
    }
    return artifactFromTarball({
      expectedName: "@makecrypto/medusa-plugin-makepay",
      expectedSha256: process.env.MAKEPAY_PLUGIN_TARBALL_SHA256,
      expectedVersion: "1.0.0",
      label: "Packed plugin",
      tarball: suppliedTarball,
    });
  }
  await run("npm", ["run", "build"]);
  const packDirectory = join(root, "pack");
  await mkdir(packDirectory, { recursive: true });
  const result = await run(
    "npm",
    ["pack", "--ignore-scripts", "--json", "--pack-destination", packDirectory],
    { capture: true, sanitizeCapture: false },
  );
  const [{ filename }] = JSON.parse(result.stdout);
  const tarball = join(packDirectory, filename);
  return artifactFromTarball({
    expectedName: "@makecrypto/medusa-plugin-makepay",
    expectedSha256: process.env.MAKEPAY_PLUGIN_TARBALL_SHA256,
    expectedVersion: "1.0.0",
    label: "Packed plugin",
    tarball,
  });
}

async function sha256File(path) {
  return createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
}

async function installedPackageRoot(projectRoot, packageName) {
  const segments = packageName.split("/");
  for (const nodeModules of [
    join(projectRoot, "apps/backend/node_modules"),
    join(projectRoot, "node_modules"),
  ]) {
    const candidate = join(nodeModules, ...segments);
    try {
      await readFile(join(candidate, "package.json"));
      return candidate;
    } catch {}
  }
  throw new Error(`Installed artifact proof could not locate ${packageName}.`);
}

async function verifyInstalledTarball({
  files,
  label,
  packageName,
  projectRoot,
  root,
  tarball,
}) {
  const extractionDirectory = join(root, "artifact-proof", label);
  await rm(extractionDirectory, { force: true, recursive: true });
  await mkdir(extractionDirectory, { recursive: true });
  await run("tar", ["-xzf", tarball, "-C", extractionDirectory], {
    capture: true,
  });
  const packedRoot = join(extractionDirectory, "package");
  const installedRoot = await installedPackageRoot(projectRoot, packageName);
  for (const relativePath of files) {
    const packedHash = await sha256File(join(packedRoot, relativePath));
    const installedHash = await sha256File(join(installedRoot, relativePath));
    if (packedHash !== installedHash) {
      throw new Error(
        `Installed ${label} artifact differs from its packed tarball at ${relativePath}.`,
      );
    }
    log(`Installed ${label} proof ${relativePath}: sha256 ${installedHash}`);
  }
}

async function createLocalTlsCertificate(root) {
  if (!commandExists("openssl")) {
    throw new Error(
      "OpenSSL is required to create the loopback HTTPS OAuth fixture",
    );
  }
  const keyPath = join(root, "contract-server.key.pem");
  const certPath = join(root, "contract-server.cert.pem");
  await run(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      keyPath,
      "-out",
      certPath,
      "-days",
      "1",
      "-subj",
      "/CN=localhost",
      "-addext",
      "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ],
    { capture: true },
  );
  return {
    cert: await readFile(certPath),
    certPath,
    key: await readFile(keyPath),
  };
}

const PROJECT_MARKER_NAME = ".makepay-e2e-project.json";

function pathIsStrictlyInside(parent, candidate) {
  const path = relative(parent, candidate);
  return (
    path !== "" &&
    path !== ".." &&
    !path.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) &&
    !isAbsolute(path)
  );
}

async function pathExists(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

const OUTPUT_MARKER_NAME = ".makepay-e2e-output.json";
const OUTPUT_MARKER_KIND = "makepay-medusa-e2e-output";
const allowedOutputRootEntries = new Set([
  OUTPUT_MARKER_NAME,
  "evidence",
  "report",
  "results",
  "runtime",
]);

function assertOwner(entry, label) {
  if (typeof process.getuid === "function" && entry.uid !== process.getuid()) {
    throw new Error(`${label} is not owned by the current user.`);
  }
}

async function assertSymlinkFreeOutputTree(path, label) {
  const entry = await lstat(path);
  assertOwner(entry, label);
  if (entry.isSymbolicLink()) {
    throw new Error(`${label} cannot contain symbolic links.`);
  }
  if (entry.isDirectory()) {
    for (const name of await readdir(path)) {
      await assertSymlinkFreeOutputTree(join(path, name), `${label}/${name}`);
    }
    return;
  }
  if (!entry.isFile()) {
    throw new Error(`${label} may contain only directories and regular files.`);
  }
}

async function validateOwnedOutputRoot(outputRoot) {
  const rootEntry = await lstat(outputRoot);
  if (rootEntry.isSymbolicLink() || !rootEntry.isDirectory()) {
    throw new Error("The MakePay E2E output root must be a real directory.");
  }
  assertOwner(rootEntry, "The MakePay E2E output root");
  const canonicalRoot = await realpath(outputRoot);
  const markerPath = join(canonicalRoot, OUTPUT_MARKER_NAME);
  const markerEntry = await lstat(markerPath);
  if (
    markerEntry.isSymbolicLink() ||
    !markerEntry.isFile() ||
    (markerEntry.mode & 0o777) !== 0o600
  ) {
    throw new Error(
      "The MakePay E2E output root requires an owner-controlled 0600 marker.",
    );
  }
  assertOwner(markerEntry, "The MakePay E2E output marker");
  const marker = JSON.parse(await readFile(markerPath, "utf8"));
  if (
    marker?.canonicalRoot !== canonicalRoot ||
    marker?.kind !== OUTPUT_MARKER_KIND ||
    marker?.schemaVersion !== 1
  ) {
    throw new Error("The MakePay E2E output ownership marker is invalid.");
  }
  return canonicalRoot;
}

async function initializeOwnedOutputRoot(ownerRoot = packageRoot) {
  const ownerEntry = await lstat(ownerRoot);
  if (ownerEntry.isSymbolicLink() || !ownerEntry.isDirectory()) {
    throw new Error(
      "The package root for E2E output must be a real directory.",
    );
  }
  assertOwner(ownerEntry, "The package root for E2E output");
  const canonicalOwner = await realpath(ownerRoot);
  let current = canonicalOwner;
  for (const segment of ["output", "playwright", "medusa-makepay"]) {
    current = join(current, segment);
    if (!(await pathExists(current))) {
      await mkdir(current, { mode: 0o700 });
    }
    const entry = await lstat(current);
    if (entry.isSymbolicLink() || !entry.isDirectory()) {
      throw new Error(
        "The package-owned E2E output path cannot traverse a symbolic link or non-directory.",
      );
    }
    assertOwner(entry, "The package-owned E2E output path");
    const canonical = await realpath(current);
    if (!pathIsStrictlyInside(canonicalOwner, canonical)) {
      throw new Error("The package-owned E2E output path escapes the package.");
    }
  }

  const outputRoot = current;
  const markerPath = join(outputRoot, OUTPUT_MARKER_NAME);
  if (!(await pathExists(markerPath))) {
    for (const name of await readdir(outputRoot)) {
      if (!allowedOutputRootEntries.has(name)) {
        throw new Error(
          `Refusing to claim an E2E output root containing unknown entry ${name}.`,
        );
      }
      await assertSymlinkFreeOutputTree(
        join(outputRoot, name),
        `The existing E2E output entry ${name}`,
      );
    }
    await writeFile(
      markerPath,
      `${JSON.stringify({
        canonicalRoot: outputRoot,
        kind: OUTPUT_MARKER_KIND,
        schemaVersion: 1,
      })}\n`,
      { flag: "wx", mode: 0o600 },
    );
    await chmod(markerPath, 0o600);
  }
  await chmod(outputRoot, 0o700);
  return validateOwnedOutputRoot(outputRoot);
}

function assertAllowedOutputRelativePath(relativePath) {
  if (
    relativePath === "evidence" ||
    relativePath === "report" ||
    relativePath === "results" ||
    /^runtime\/medusa-e2e-[A-Za-z0-9._-]+$/.test(relativePath)
  ) {
    return;
  }
  throw new Error(
    "The requested E2E output path is not an owned harness leaf.",
  );
}

async function prepareOwnedOutputPath(
  outputRoot,
  relativePath,
  { recreate = true, reset = true } = {},
) {
  const canonicalRoot = await validateOwnedOutputRoot(outputRoot);
  assertAllowedOutputRelativePath(relativePath);
  const target = join(canonicalRoot, relativePath);
  if (!pathIsStrictlyInside(canonicalRoot, target)) {
    throw new Error("The requested E2E output path escapes its owned root.");
  }
  let existing = canonicalRoot;
  for (const segment of relativePath.split("/")) {
    existing = join(existing, segment);
    if (!(await pathExists(existing))) break;
    const entry = await lstat(existing);
    if (entry.isSymbolicLink()) {
      throw new Error(
        `The E2E output ${relativePath} traverses a symbolic link.`,
      );
    }
    assertOwner(entry, `The E2E output ${relativePath}`);
    const canonical = await realpath(existing);
    if (!pathIsStrictlyInside(canonicalRoot, canonical)) {
      throw new Error(`The E2E output ${relativePath} escapes its owned root.`);
    }
  }
  if (await pathExists(target)) {
    await assertSymlinkFreeOutputTree(target, `The E2E output ${relativePath}`);
    if (reset) await rm(target, { force: true, recursive: true });
  }
  if (!recreate) return target;

  let current = canonicalRoot;
  for (const segment of relativePath.split("/")) {
    current = join(current, segment);
    if (!(await pathExists(current))) await mkdir(current, { mode: 0o700 });
    const entry = await lstat(current);
    if (entry.isSymbolicLink() || !entry.isDirectory()) {
      throw new Error(
        `The E2E output ${relativePath} traverses a symbolic link or non-directory.`,
      );
    }
    assertOwner(entry, `The E2E output ${relativePath}`);
    const canonical = await realpath(current);
    if (!pathIsStrictlyInside(canonicalRoot, canonical)) {
      throw new Error(`The E2E output ${relativePath} escapes its owned root.`);
    }
  }
  await chmod(target, 0o700);
  return target;
}

async function assertNoProjectNpmrc(root, label) {
  for (const relativePath of [
    ".npmrc",
    "apps/backend/.npmrc",
    "apps/storefront/.npmrc",
  ]) {
    if (await pathExists(join(root, relativePath))) {
      throw new Error(
        `${label} contains ${relativePath}; project npm configuration is forbidden in the isolated E2E harness.`,
      );
    }
  }
}

async function removeKnownGeneratedProjectNpmrc(root) {
  const npmrcPath = join(root, ".npmrc");
  if (!(await pathExists(npmrcPath))) return;
  const quarantinedPath = join(
    root,
    `.makepay-e2e-generator-npmrc-${randomUUID()}`,
  );
  await rename(npmrcPath, quarantinedPath);
  const entry = await lstat(quarantinedPath);
  assertOwner(entry, "The generated Medusa .npmrc");
  if (
    entry.isSymbolicLink() ||
    !entry.isFile() ||
    entry.size !== Buffer.byteLength("auto-install-peers=true\n") ||
    (entry.mode & 0o111) !== 0
  ) {
    throw new Error(
      "The generated Medusa .npmrc is not the reviewed inert template file.",
    );
  }
  const contents = await readFile(quarantinedPath, "utf8");
  if (contents !== "auto-install-peers=true\n") {
    throw new Error(
      "The generated Medusa .npmrc is not the reviewed inert template file.",
    );
  }
  await rm(quarantinedPath);
  log("Removed the reviewed generator-only auto-install-peers .npmrc.");
}

function validateMedusaFixtureManifests({ backend, root, storefront }) {
  const forbiddenLifecycle = /^(?:pre|post)?(?:install|uninstall)$|^prepare$/;
  for (const [label, manifest] of [
    ["root", root],
    ["backend", backend],
    ["storefront", storefront],
  ]) {
    const unsafe = Object.keys(manifest.scripts || {}).find((name) =>
      forbiddenLifecycle.test(name),
    );
    if (unsafe) {
      throw new Error(
        `The reusable Medusa ${label} fixture contains forbidden lifecycle script ${unsafe}.`,
      );
    }
  }
  if (
    root.name !== "medusa-app" ||
    !Array.isArray(root.workspaces) ||
    !root.workspaces.includes("apps/**") ||
    !root.workspaces.includes("!apps/backend/.medusa/**") ||
    backend.name !== "@dtc/backend" ||
    backend.dependencies?.["@medusajs/framework"] !== "2.17.2" ||
    backend.dependencies?.["@medusajs/medusa"] !== "2.17.2" ||
    backend.dependencies?.["@medusajs/cli"] !== "2.17.2" ||
    storefront.name !== "@dtc/storefront" ||
    storefront.dependencies?.["@medusajs/js-sdk"] !== "2.17.2"
  ) {
    throw new Error(
      "The reusable fixture is not the pinned official Medusa 2.17.2 project.",
    );
  }
}

async function assertProjectWritablePathOwned(projectRoot, relativePath) {
  let current = projectRoot;
  for (const segment of relativePath.split("/")) {
    current = join(current, segment);
    if (!(await pathExists(current))) break;
    const entry = await lstat(current);
    const canonical = await realpath(current);
    if (
      entry.isSymbolicLink() ||
      !pathIsStrictlyInside(projectRoot, canonical)
    ) {
      throw new Error(
        `The reusable Medusa fixture writable path ${relativePath} escapes its owned root.`,
      );
    }
  }
}

async function writeProjectOwnershipMarker(projectRoot) {
  const canonicalRoot = await realpath(projectRoot);
  const markerPath = join(canonicalRoot, PROJECT_MARKER_NAME);
  await writeFile(
    markerPath,
    `${JSON.stringify({
      canonicalRoot,
      kind: "makepay-medusa-e2e-project",
      schemaVersion: 1,
    })}\n`,
    { flag: "wx", mode: 0o600 },
  );
  await chmod(markerPath, 0o600);
}

async function validateReusableProjectRoot(value) {
  const requestedRoot = resolve(value);
  const requestedStat = await lstat(requestedRoot);
  if (requestedStat.isSymbolicLink()) {
    throw new Error("MAKEPAY_E2E_PROJECT_ROOT cannot be a symbolic link.");
  }
  const [projectRoot, temporaryBase] = await Promise.all([
    realpath(requestedRoot),
    realpath(tmpdir()),
  ]);
  if (
    !pathIsStrictlyInside(temporaryBase, projectRoot) ||
    !/e2e/i.test(projectRoot)
  ) {
    throw new Error(
      "MAKEPAY_E2E_PROJECT_ROOT must resolve inside the canonical temporary directory and contain `e2e`.",
    );
  }

  const markerPath = join(projectRoot, PROJECT_MARKER_NAME);
  const markerStat = await lstat(markerPath);
  if (
    markerStat.isSymbolicLink() ||
    !markerStat.isFile() ||
    (markerStat.mode & 0o777) !== 0o600 ||
    (typeof process.getuid === "function" &&
      markerStat.uid !== process.getuid())
  ) {
    throw new Error(
      "The reusable Medusa fixture requires an owner-controlled 0600 harness marker.",
    );
  }
  const marker = JSON.parse(await readFile(markerPath, "utf8"));
  if (
    marker?.kind !== "makepay-medusa-e2e-project" ||
    marker?.schemaVersion !== 1 ||
    marker?.canonicalRoot !== projectRoot
  ) {
    throw new Error("The reusable Medusa fixture ownership marker is invalid.");
  }

  for (const relativePath of [
    "apps",
    "apps/backend",
    "apps/storefront",
    "package.json",
    "apps/backend/package.json",
    "apps/storefront/package.json",
  ]) {
    const path = join(projectRoot, relativePath);
    const entry = await lstat(path);
    const canonicalEntry = await realpath(path);
    if (
      entry.isSymbolicLink() ||
      !pathIsStrictlyInside(projectRoot, canonicalEntry)
    ) {
      throw new Error(
        `The reusable Medusa fixture contains an unsafe ${relativePath} path.`,
      );
    }
  }
  await assertNoProjectNpmrc(projectRoot, "The reusable Medusa fixture");
  for (const relativePath of [
    "apps/backend/.env",
    "apps/storefront/.env.local",
  ]) {
    if (await pathExists(join(projectRoot, relativePath))) {
      throw new Error(
        `The reusable Medusa fixture contains preexisting ${relativePath}; only a scrubbed harness-owned fixture may be reused.`,
      );
    }
  }
  validateMedusaFixtureManifests({
    backend: JSON.parse(
      await readFile(join(projectRoot, "apps/backend/package.json"), "utf8"),
    ),
    root: JSON.parse(await readFile(join(projectRoot, "package.json"), "utf8")),
    storefront: JSON.parse(
      await readFile(join(projectRoot, "apps/storefront/package.json"), "utf8"),
    ),
  });
  for (const relativePath of [
    "package-lock.json",
    "node_modules",
    "apps/backend/node_modules",
    "apps/backend/.env",
    "apps/backend/medusa-config.ts",
    "apps/storefront/.env.local",
    "apps/storefront/src/lib/constants.tsx",
    "apps/storefront/src/lib/data/cart.ts",
    "apps/storefront/src/lib/data/cookies.ts",
    "apps/storefront/src/modules/checkout/components/payment/index.tsx",
    "apps/storefront/src/modules/checkout/components/payment-button/index.tsx",
    "apps/storefront/src/app/[countryCode]/(main)/makepay/return/page.tsx",
  ]) {
    await assertProjectWritablePathOwned(projectRoot, relativePath);
  }
  return projectRoot;
}

function officialGeneratorNpmEnvironment() {
  return {
    NPM_CONFIG_AUDIT: "false",
    NPM_CONFIG_FETCH_RETRIES: "6",
    NPM_CONFIG_FETCH_RETRY_FACTOR: "2",
    NPM_CONFIG_FETCH_RETRY_MAXTIMEOUT: "60000",
    NPM_CONFIG_FETCH_RETRY_MINTIMEOUT: "10000",
    NPM_CONFIG_FUND: "false",
    NPM_CONFIG_MAXSOCKETS: "5",
    NPM_CONFIG_PREFER_OFFLINE: "true",
  };
}

async function scaffoldProject(root, databaseUrl) {
  const existing = process.env.MAKEPAY_E2E_PROJECT_ROOT;
  if (existing) {
    const projectRoot = await validateReusableProjectRoot(existing);
    log(`Reusing generated Medusa project: ${projectRoot}`);
    return projectRoot;
  }
  const projectName = "medusa-app";
  await run(
    "npx",
    [
      "--yes",
      "create-medusa-app@2.17.2",
      projectName,
      "--directory-path",
      root,
      "--db-url",
      databaseUrl,
      "--seed",
      "--with-nextjs-starter",
      "--no-browser",
      "--use-npm",
      "--version",
      "2.17.2",
    ],
    {
      cwd: root,
      env: officialGeneratorNpmEnvironment(),
    },
  );
  const projectRoot = await realpath(join(root, projectName));
  await Promise.all([
    rm(join(projectRoot, "apps/backend/.env"), { force: true }),
    rm(join(projectRoot, "apps/storefront/.env.local"), { force: true }),
  ]);
  await removeKnownGeneratedProjectNpmrc(projectRoot);
  await assertNoProjectNpmrc(projectRoot, "The generated Medusa fixture");
  await writeProjectOwnershipMarker(projectRoot);
  return validateReusableProjectRoot(projectRoot);
}

async function resolveSdkArtifact(root) {
  let tarball = process.env.MAKEPAY_SDK_TARBALL;
  if (tarball && !process.env.MAKEPAY_SDK_TARBALL_SHA256) {
    throw new Error(
      "MAKEPAY_SDK_TARBALL_SHA256 is required with MAKEPAY_SDK_TARBALL.",
    );
  }
  if (!tarball) {
    const packDirectory = join(root, "sdk-pack");
    await mkdir(packDirectory, { recursive: true });
    const result = await run(
      "npm",
      [
        "pack",
        "@makecrypto/makepay@0.4.0",
        "--ignore-scripts",
        "--json",
        "--pack-destination",
        packDirectory,
      ],
      { capture: true, sanitizeCapture: false },
    );
    const [{ filename }] = JSON.parse(result.stdout);
    tarball = join(packDirectory, filename);
  }
  return artifactFromTarball({
    expectedName: "@makecrypto/makepay",
    expectedSha256: process.env.MAKEPAY_SDK_TARBALL_SHA256,
    expectedVersion: "0.4.0",
    label: "Packed SDK",
    tarball,
  });
}

async function installAndPatch(projectRoot, pluginArtifact) {
  const sdkArtifact = await resolveSdkArtifact(temporaryRoot);
  await Promise.all([
    assertPrivateArtifactCopy(
      pluginArtifact.tarball,
      pluginArtifact.sha256,
      "Packed plugin",
    ),
    assertPrivateArtifactCopy(
      sdkArtifact.tarball,
      sdkArtifact.sha256,
      "Packed SDK",
    ),
  ]);
  // Reusable fixtures can retain the same package version from a prior packed
  // artifact. Uninstall it completely so npm cannot treat different 1.0.0
  // tarball bytes as already satisfied, then resolve the fresh artifacts.
  await run(
    "npm",
    [
      "uninstall",
      "@makecrypto/makepay",
      "@makecrypto/medusa-plugin-makepay",
      "--workspace=@dtc/backend",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
    ],
    { cwd: projectRoot },
  );
  await run(
    "npm",
    [
      "install",
      "--save-exact",
      "--workspace=@dtc/backend",
      sdkArtifact.tarball,
      pluginArtifact.tarball,
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
    ],
    { cwd: projectRoot },
  );
  await Promise.all([
    assertPrivateArtifactCopy(
      pluginArtifact.tarball,
      pluginArtifact.sha256,
      "Packed plugin",
    ),
    assertPrivateArtifactCopy(
      sdkArtifact.tarball,
      sdkArtifact.sha256,
      "Packed SDK",
    ),
  ]);
  await verifyInstalledTarball({
    files: [
      "package.json",
      ".medusa/server/src/index.js",
      ".medusa/server/src/api/hooks/makepay/[provider]/route.js",
      ".medusa/server/src/api/middlewares.js",
      ".medusa/server/src/modules/makepay/migrations/Migration20260719000300.js",
      ".medusa/server/src/modules/makepay/migrations/Migration20260719000400.js",
      ".medusa/server/src/modules/makepay/migrations/Migration20260719000500.js",
      ".medusa/server/src/modules/makepay/migrations/Migration20260719000600.js",
      ".medusa/server/src/modules/makepay/models/webhook-subscription.js",
    ],
    label: "plugin",
    packageName: "@makecrypto/medusa-plugin-makepay",
    projectRoot,
    root: temporaryRoot,
    tarball: pluginArtifact.tarball,
  });
  await verifyInstalledTarball({
    files: ["package.json", "dist/index.js"],
    label: "SDK",
    packageName: "@makecrypto/makepay",
    projectRoot,
    root: temporaryRoot,
    tarball: sdkArtifact.tarball,
  });
  await Promise.all([
    assertPrivateArtifactCopy(
      pluginArtifact.tarball,
      pluginArtifact.sha256,
      "Packed plugin",
    ),
    assertPrivateArtifactCopy(
      sdkArtifact.tarball,
      sdkArtifact.sha256,
      "Packed SDK",
    ),
  ]);
  await copyFile(
    join(packageRoot, "tests/e2e/fixtures/medusa-config.ts"),
    join(projectRoot, "apps/backend/medusa-config.ts"),
  );
  await patchOfficialStorefront(projectRoot);
  return {
    plugin: {
      sha256: pluginArtifact.sha256,
      version: pluginArtifact.version,
    },
    sdk: { sha256: sdkArtifact.sha256, version: sdkArtifact.version },
  };
}

async function startQuickTunnel(port, root, name) {
  if (!commandExists("cloudflared")) {
    throw new Error(
      "cloudflared is required for the real sandbox OAuth/webhook smoke test",
    );
  }
  const logPath = join(temporaryRoot, "runtime-raw", `${name}-tunnel.log`);
  let publicUrl;
  const child = await startProcess(
    "cloudflared",
    ["tunnel", "--no-autoupdate", "--url", `http://127.0.0.1:${port}`],
    {
      cwd: root,
      env: {},
      inspectOutput: (value) => {
        const match = stripVTControlCharacters(value).match(
          /https:\/\/[a-z0-9-]+\.trycloudflare\.com/i,
        );
        if (match && !publicUrl) {
          publicUrl = match[0];
          registerRuntimeSecret(publicUrl);
        }
      },
      logPath,
    },
  );
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    if (publicUrl) return publicUrl;
    if (child.exitCode !== null)
      throw new Error(`cloudflared ${name} tunnel exited early`);
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 250));
  }
  throw new Error(`cloudflared ${name} tunnel did not produce a public URL`);
}

async function assertRealSandboxGuard() {
  const required = {
    MAKEPAY_PLUGIN_TARBALL: process.env.MAKEPAY_PLUGIN_TARBALL,
    MAKEPAY_PLUGIN_TARBALL_SHA256: process.env.MAKEPAY_PLUGIN_TARBALL_SHA256,
    MAKEPAY_SDK_TARBALL: process.env.MAKEPAY_SDK_TARBALL,
    MAKEPAY_SDK_TARBALL_SHA256: process.env.MAKEPAY_SDK_TARBALL_SHA256,
    MAKEPAY_E2E_REAL_API_URL: process.env.MAKEPAY_E2E_REAL_API_URL,
    MAKEPAY_E2E_REAL_CHECKOUT_URL: process.env.MAKEPAY_E2E_REAL_CHECKOUT_URL,
    MAKEPAY_E2E_REAL_OAUTH_ISSUER_URL:
      process.env.MAKEPAY_E2E_REAL_OAUTH_ISSUER_URL,
    MAKEPAY_E2E_SANDBOX_COMPANY_ID: process.env.MAKEPAY_E2E_SANDBOX_COMPANY_ID,
    MAKEPAY_E2E_SANDBOX_COMPANY_NAME:
      process.env.MAKEPAY_E2E_SANDBOX_COMPANY_NAME,
  };
  if (
    process.env.MAKEPAY_E2E_REAL_SANDBOX !== "1" ||
    process.env.MAKEPAY_E2E_NO_FUNDS_ACK !== "SANDBOX_DO_NOT_SEND_FUNDS"
  ) {
    throw new Error(
      "Real sandbox smoke is locked. Set MAKEPAY_E2E_REAL_SANDBOX=1 and MAKEPAY_E2E_NO_FUNDS_ACK=SANDBOX_DO_NOT_SEND_FUNDS. The test never sends cryptocurrency.",
    );
  }
  if (localDiagnostics) {
    throw new Error(
      "--local-diagnostics is disabled for the real OAuth sandbox because browser diagnostics can retain authorization URLs.",
    );
  }
  if (keep) {
    throw new Error(
      "--keep is disabled for the real OAuth sandbox; disposable databases and workspaces are always deleted.",
    );
  }
  if (process.env.MAKEPAY_E2E_PROJECT_ROOT) {
    throw new Error(
      "Reusable Medusa projects are forbidden for the real OAuth sandbox.",
    );
  }
  if (
    process.env.MAKEPAY_E2E_DATABASE_URL ||
    process.env.MAKEPAY_E2E_SECOND_DATABASE_URL ||
    process.env.MAKEPAY_E2E_API_KEY_DATABASE_URL
  ) {
    throw new Error(
      "Reusable databases are forbidden for the real sandbox; the harness always creates two disposable isolated PostgreSQL clusters.",
    );
  }
  const missing = Object.entries(required).filter(([, value]) => !value);
  if (missing.length) {
    throw new Error(
      `Missing real sandbox variables: ${missing.map(([key]) => key).join(", ")}`,
    );
  }
  for (const key of [
    "MAKEPAY_E2E_REAL_API_URL",
    "MAKEPAY_E2E_REAL_CHECKOUT_URL",
    "MAKEPAY_E2E_REAL_OAUTH_ISSUER_URL",
  ]) {
    const url = new URL(process.env[key]);
    if (
      url.protocol !== "https:" ||
      url.pathname !== "/" ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    ) {
      throw new Error(
        `${key} must be a clean HTTPS URL without credentials, query, or fragment`,
      );
    }
  }
  const manualOAuth = process.env.MAKEPAY_E2E_MANUAL_OAUTH === "1";
  const suppliedStorageState = process.env.MAKEPAY_E2E_STORAGE_STATE;
  if (manualOAuth === Boolean(suppliedStorageState)) {
    throw new Error(
      "Choose exactly one real-sandbox login mode: MAKEPAY_E2E_MANUAL_OAUTH=1 or MAKEPAY_E2E_STORAGE_STATE, never both.",
    );
  }
  if (manualOAuth) return { manualOAuth: true, storageState: "" };

  registerRuntimeSecret(resolve(suppliedStorageState));
  const storageState = await realpath(suppliedStorageState);
  registerRuntimeSecret(storageState);
  const repositoryRelativePath = relative(packageRoot, storageState);
  if (
    repositoryRelativePath === "" ||
    (!repositoryRelativePath.startsWith("..") &&
      !repositoryRelativePath.startsWith(
        `..${process.platform === "win32" ? "\\" : "/"}`,
      ))
  ) {
    throw new Error(
      "Sandbox OAuth browser storage state must stay outside the repository.",
    );
  }
  const storageStateStat = await stat(storageState);
  if (
    !storageStateStat.isFile() ||
    (storageStateStat.mode & 0o777) !== 0o600 ||
    (typeof process.getuid === "function" &&
      storageStateStat.uid !== process.getuid())
  ) {
    throw new Error(
      "Sandbox OAuth storage state must be an owner-controlled regular file with mode 0600.",
    );
  }
  const parsedStorageState = JSON.parse(await readFile(storageState, "utf8"));
  if (
    !parsedStorageState ||
    !Array.isArray(parsedStorageState.cookies) ||
    !Array.isArray(parsedStorageState.origins)
  ) {
    throw new Error(
      "Sandbox OAuth storage state is not valid Playwright JSON.",
    );
  }
  const issuer = new URL(process.env.MAKEPAY_E2E_REAL_OAUTH_ISSUER_URL);
  const unsafeCookie = parsedStorageState.cookies.find(
    (cookie) =>
      !cookie ||
      typeof cookie.domain !== "string" ||
      cookie.domain.replace(/^\./, "").toLowerCase() !==
        issuer.hostname.toLowerCase(),
  );
  const unsafeOrigin = parsedStorageState.origins.find((entry) => {
    try {
      return new URL(entry?.origin).origin !== issuer.origin;
    } catch {
      return true;
    }
  });
  if (unsafeCookie || unsafeOrigin) {
    throw new Error(
      "Sandbox OAuth storage state may contain cookies and origins only for the approved OAuth issuer.",
    );
  }
  if (
    parsedStorageState.origins.some(
      (origin) => Array.isArray(origin?.indexedDB) && origin.indexedDB.length,
    )
  ) {
    throw new Error(
      "Sandbox OAuth storage state must not contain IndexedDB records.",
    );
  }
  for (const cookie of parsedStorageState.cookies) {
    if (typeof cookie?.value === "string" && cookie.value) {
      registerRuntimeSecret(cookie.value);
    }
  }
  for (const origin of parsedStorageState.origins) {
    for (const entry of origin?.localStorage || []) {
      if (typeof entry?.value === "string" && entry.value) {
        registerRuntimeSecret(entry.value);
      }
    }
  }
  return { manualOAuth: false, storageState };
}

async function resetEvidenceDirectory(value) {
  const directory = resolve(value);
  const outputRoot = ownedOutputRoot || (await initializeOwnedOutputRoot());
  const repositoryEvidence = join(outputRoot, "evidence");
  if (directory !== repositoryEvidence) {
    throw new Error(
      "MAKEPAY_E2E_EVIDENCE_DIR must be the exact package-owned evidence directory because capture clears it recursively.",
    );
  }
  return prepareOwnedOutputPath(outputRoot, "evidence");
}

async function readPlaywrightCompletion(path, mode) {
  const entry = await lstat(path);
  if (
    entry.isSymbolicLink() ||
    !entry.isFile() ||
    entry.size <= 0 ||
    entry.size > 5 * 1024 * 1024
  ) {
    throw new Error(
      "Playwright completion receipt is not a bounded regular file.",
    );
  }
  assertOwner(entry, "The Playwright completion receipt");
  const report = JSON.parse(await readFile(path, "utf8"));
  if (mode === "real-sandbox") {
    validateRealSandboxPlaywrightReport(report);
  } else {
    validateDeterministicPlaywrightReport(report);
  }
  return report;
}

async function configureBackend({
  backendPublicUrl,
  backendUrl,
  databaseUrl,
  encryptionKey: installationEncryptionKey,
  makePayApiUrl,
  makePayCheckoutUrl,
  oauthIssuerUrl,
  persist = true,
  projectRoot,
  storefrontPublicUrl,
  storefrontUrl,
}) {
  const backendEnvPath = join(projectRoot, "apps/backend/.env");
  const values = {
    ADMIN_CORS: `${backendUrl},${backendPublicUrl}`,
    AUTH_CORS: `${backendUrl},${backendPublicUrl},${storefrontUrl},${storefrontPublicUrl}`,
    COOKIE_SECRET: randomBytes(32).toString("hex"),
    DATABASE_URL: databaseUrl,
    JWT_SECRET: randomBytes(32).toString("hex"),
    MAKEPAY_API_URL: makePayApiUrl,
    MAKEPAY_AUTH_MODE: "oauth",
    MAKEPAY_BACKEND_URL: backendPublicUrl,
    MAKEPAY_CHECKOUT_URL: makePayCheckoutUrl,
    MAKEPAY_ENCRYPTION_KEY: installationEncryptionKey,
    MAKEPAY_OAUTH_ISSUER_URL: oauthIssuerUrl,
    MAKEPAY_STOREFRONT_RETURN_URL: `${storefrontPublicUrl}/dk/makepay/return`,
    // create-medusa-app can seed a loopback MEDUSA_BACKEND_URL. Override it
    // before the Admin production build so extensions use the HTTPS tunnel
    // origin during the real-sandbox run instead of a mixed-content request.
    MEDUSA_BACKEND_URL: backendPublicUrl,
    STORE_CORS: `${storefrontUrl},${storefrontPublicUrl}`,
  };
  registerRuntimeSecret(values.COOKIE_SECRET);
  registerRuntimeSecret(values.JWT_SECRET);
  registerRuntimeSecret(values.MAKEPAY_ENCRYPTION_KEY);
  if (persist) await upsertEnv(backendEnvPath, values);
  return values;
}

async function configureApiKeyBackend({
  apiKeyId,
  apiKeySecret,
  backendUrl,
  databaseUrl,
  makePayApiUrl,
  makePayCheckoutUrl,
  webhookSecret,
}) {
  const values = {
    ADMIN_CORS: backendUrl,
    AUTH_CORS: backendUrl,
    COOKIE_SECRET: randomBytes(32).toString("hex"),
    DATABASE_URL: databaseUrl,
    JWT_SECRET: randomBytes(32).toString("hex"),
    MAKEPAY_API_URL: makePayApiUrl,
    // The fixture selector intentionally omits authMode from plugin/provider
    // options, proving backwards-compatible API-key inference from credentials.
    MAKEPAY_AUTH_MODE: "legacy_api_key",
    MAKEPAY_CHECKOUT_URL: makePayCheckoutUrl,
    MAKEPAY_KEY_ID: apiKeyId,
    MAKEPAY_KEY_SECRET: apiKeySecret,
    MAKEPAY_WEBHOOK_SECRET: webhookSecret,
    STORE_CORS: backendUrl,
  };
  for (const secret of [
    values.COOKIE_SECRET,
    values.JWT_SECRET,
    values.MAKEPAY_KEY_SECRET,
    values.MAKEPAY_WEBHOOK_SECRET,
  ]) {
    registerRuntimeSecret(secret);
  }
  return values;
}

async function configureStorefront({
  backendPublicUrl,
  makePayCheckoutUrl,
  projectRoot,
  publishableKey,
}) {
  const storefrontEnvPath = join(projectRoot, "apps/storefront/.env.local");
  await upsertEnv(storefrontEnvPath, {
    NEXT_PUBLIC_MAKEPAY_CHECKOUT_ORIGIN: new URL(makePayCheckoutUrl).origin,
    NEXT_PUBLIC_MEDUSA_BACKEND_URL: backendPublicUrl,
    NEXT_PUBLIC_MEDUSA_PUBLISHABLE_KEY: publishableKey,
  });
}

async function resetReusableMakePayState(databaseUrl) {
  const psql = findPostgresBinary("psql");
  if (!psql) {
    throw new Error(
      "psql is required when reusing MAKEPAY_E2E_DATABASE_URL so stale encrypted MakePay state can be removed safely.",
    );
  }
  await run(
    psql,
    [
      "--dbname",
      databaseUrl,
      "--set",
      "ON_ERROR_STOP=1",
      "--command",
      "TRUNCATE makepay_webhook_delivery, makepay_webhook_subscription, makepay_payment_projection, makepay_oauth_state, makepay_connection;",
    ],
    { capture: true },
  );
  log(
    "Cleared stale MakePay-only state from the reusable loopback E2E database.",
  );
}

async function buildBackendAndMigrate({
  adminEmail: userEmail,
  adminPassword: userPassword,
  build = true,
  env,
  projectRoot,
  resetMakePayState,
  seed = false,
}) {
  const backend = join(projectRoot, "apps/backend");
  await run("npx", ["--no-install", "medusa", "db:migrate"], {
    cwd: backend,
    env,
  });
  if (resetMakePayState) await resetReusableMakePayState(env.DATABASE_URL);
  if (seed) {
    const legacySeedPath = join(backend, "src/scripts/seed.ts");
    const migrationSeedPath = join(
      backend,
      "src/migration-scripts/initial-data-seed.ts",
    );
    if (await pathExists(legacySeedPath)) {
      await run(
        "npx",
        ["--no-install", "medusa", "exec", "./src/scripts/seed.ts"],
        {
          cwd: backend,
          env,
        },
      );
    } else if (await pathExists(migrationSeedPath)) {
      log(
        "Official Medusa initial data was applied by db:migrate; no legacy seed.ts is present.",
      );
    } else {
      throw new Error(
        "The official Medusa project contains neither src/scripts/seed.ts nor src/migration-scripts/initial-data-seed.ts.",
      );
    }
  }
  await run(
    "npx",
    [
      "--no-install",
      "medusa",
      "user",
      "--email",
      userEmail,
      "--password",
      userPassword,
    ],
    { cwd: backend, env },
  );
  if (build) {
    await run("npx", ["--no-install", "medusa", "build"], {
      cwd: backend,
      env,
    });
  }
}

async function preserveBuiltBackend(projectRoot, installation) {
  const source = join(projectRoot, "apps/backend/.medusa/server");
  const destination = join(
    projectRoot,
    `apps/backend/.medusa/server-installation-${installation}`,
  );
  await rm(destination, { force: true, recursive: true });
  await rename(source, destination);
  return destination;
}

async function buildStorefront(projectRoot, env) {
  await run("npx", ["--no-install", "next", "build"], {
    cwd: join(projectRoot, "apps/storefront"),
    env,
  });
}

async function fetchJson(url, options, label) {
  const response = await fetch(url, options);
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`${label} failed (${response.status}).`);
  }
  return text ? JSON.parse(text) : {};
}

async function createPublishableKey(
  backendUrl,
  userEmail = adminEmail,
  userPassword = adminPassword,
) {
  const authentication = await fetchJson(
    `${backendUrl}/auth/user/emailpass`,
    {
      body: JSON.stringify({ email: userEmail, password: userPassword }),
      headers: { "content-type": "application/json" },
      method: "POST",
    },
    "Admin authentication",
  );
  registerRuntimeSecret(authentication.token);
  const headers = {
    authorization: `Bearer ${authentication.token}`,
    "content-type": "application/json",
  };
  const salesChannels = await fetchJson(
    `${backendUrl}/admin/sales-channels?limit=100`,
    { headers },
    "List sales channels",
  );
  const ids = (salesChannels.sales_channels || []).map((channel) => channel.id);
  if (!ids.length)
    throw new Error("The official seed created no sales channel");
  const created = await fetchJson(
    `${backendUrl}/admin/api-keys`,
    {
      body: JSON.stringify({
        title: `MakePay E2E ${runId}`,
        type: "publishable",
      }),
      headers,
      method: "POST",
    },
    "Create publishable API key",
  );
  const apiKey = created.api_key;
  if (!apiKey?.id || !apiKey.token) {
    throw new Error(
      "Medusa did not return the newly-created publishable API key",
    );
  }
  registerRuntimeSecret(apiKey.token);
  await fetchJson(
    `${backendUrl}/admin/api-keys/${apiKey.id}/sales-channels`,
    {
      body: JSON.stringify({ add: ids }),
      headers,
      method: "POST",
    },
    "Scope publishable API key to seeded sales channels",
  );
  return { adminToken: authentication.token, publishableKey: apiKey.token };
}

async function writeRestrictedJson(path, value) {
  await writeFile(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
}

async function readControlRequest(request) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > 128 * 1024) {
      throw new Error("Restricted control request exceeds the size limit.");
    }
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function unixJsonRequest(socketPath, pathname, value) {
  return new Promise((resolvePromise, reject) => {
    const body = JSON.stringify(value);
    const request = httpRequest(
      {
        headers: {
          "content-length": Buffer.byteLength(body),
          "content-type": "application/json",
        },
        method: "POST",
        path: pathname,
        socketPath,
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.once("error", reject);
        response.once("end", () => {
          try {
            const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            if (response.statusCode !== 200) {
              reject(new Error("Restricted helper rejected the request."));
              return;
            }
            resolvePromise(parsed);
          } catch {
            reject(new Error("Restricted helper returned invalid JSON."));
          }
        });
      },
    );
    request.once("error", reject);
    request.end(body);
  });
}

async function waitForSocket(path, child, label) {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    if (child?.exitCode !== null) {
      throw new Error(
        `${label} exited before its restricted socket was ready.`,
      );
    }
    try {
      const socket = await stat(path);
      if (socket.isSocket() && (socket.mode & 0o777) === 0o600) return;
    } catch {}
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
  }
  throw new Error(`${label} restricted socket did not become ready.`);
}

async function stopChild(child) {
  if (!child || child.exitCode !== null || child.signalCode) return;
  try {
    if (supportsProcessGroups) process.kill(-child.pid, "SIGTERM");
    else child.kill("SIGTERM");
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
  await new Promise((resolvePromise) => {
    if (child.exitCode !== null || child.signalCode) {
      resolvePromise();
      return;
    }
    const timeout = setTimeout(resolvePromise, 5_000);
    child.once("exit", () => {
      clearTimeout(timeout);
      resolvePromise();
    });
  });
}

async function listenOnRestrictedControlSocket(server, name) {
  // Unix-domain socket paths are limited to roughly 104 bytes on macOS. The
  // E2E workspace can intentionally live under a long, persistent TMPDIR, so
  // keep only the ephemeral control socket in a short, private /tmp leaf.
  const socketBase = process.platform === "win32" ? tmpdir() : "/tmp";
  const socketDirectory = await mkdtemp(join(socketBase, "mpe2e-"));
  registerRuntimeSecret(socketDirectory);
  await chmod(socketDirectory, 0o700);
  const directoryEntry = await lstat(socketDirectory);
  assertOwner(directoryEntry, "The E2E control-socket directory");
  if (!directoryEntry.isDirectory() || directoryEntry.isSymbolicLink()) {
    await rm(socketDirectory, { force: true, recursive: true });
    throw new Error(
      "The E2E control-socket directory is not a private directory.",
    );
  }
  const socketPath = join(await realpath(socketDirectory), `${name}.sock`);
  registerRuntimeSecret(socketPath);
  try {
    await new Promise((resolvePromise, reject) => {
      server.once("error", reject);
      server.listen(socketPath, () => {
        server.off("error", reject);
        resolvePromise();
      });
    });
    await chmod(socketPath, 0o600);
    return { socketDirectory, socketPath };
  } catch (error) {
    await new Promise((resolvePromise) => {
      if (!server.listening) {
        resolvePromise();
        return;
      }
      server.close(() => resolvePromise());
    });
    await rm(socketDirectory, { force: true, recursive: true });
    throw error;
  }
}

async function startRealSandboxControl({ installations }) {
  const fixtureDirectory = join(temporaryRoot, "real-sandbox-fixtures");
  const ledgerPath = join(temporaryRoot, "real-sandbox-payment-links.json");
  const helperPath = join(
    packageRoot,
    "tests/e2e/support/real-sandbox-event-helper.mjs",
  );
  const fixtures = new Map();
  registerRuntimeSecret(fixtureDirectory);
  await mkdir(fixtureDirectory, { mode: 0o700, recursive: true });
  await chmod(fixtureDirectory, 0o700);
  const ledger = new Map();
  let ledgerQueue = Promise.resolve();

  const ledgerKey = (entry) =>
    `${entry.installation}:${entry.grantId}:${entry.uid}`;
  const persistLedger = async (records) => {
    const temporaryLedgerPath = `${ledgerPath}.${randomUUID().replaceAll("-", "")}.tmp`;
    const entries = [...records.values()].sort((left, right) =>
      ledgerKey(left).localeCompare(ledgerKey(right)),
    );
    await writeFile(
      temporaryLedgerPath,
      `${JSON.stringify({
        entries,
        kind: "makepay-real-sandbox-payment-link-ledger",
        runId,
        schemaVersion: 1,
      })}\n`,
      { flag: "wx", mode: 0o600 },
    );
    await chmod(temporaryLedgerPath, 0o600);
    await rename(temporaryLedgerPath, ledgerPath);
    await chmod(ledgerPath, 0o600);
  };
  const mutateLedger = (mutation) => {
    const operation = ledgerQueue.then(async () => {
      const draft = new Map(
        [...ledger.entries()].map(([key, entry]) => [key, { ...entry }]),
      );
      const result = await mutation(draft);
      await persistLedger(draft);
      ledger.clear();
      for (const [key, entry] of draft) ledger.set(key, entry);
      return result;
    });
    ledgerQueue = operation.catch(() => {});
    return operation;
  };
  await persistLedger(ledger);

  const installation = (name) => {
    if (!Object.hasOwn(installations, name)) {
      throw new Error("Unknown real-sandbox installation.");
    }
    return installations[name];
  };

  const invoke = async (name, input, { cleanup = false } = {}) => {
    const target = installation(name);
    const id = randomUUID().replaceAll("-", "");
    const inputPath = join(fixtureDirectory, `input-${id}.json`);
    const outputPath = join(fixtureDirectory, `output-${id}.json`);
    registerRuntimeSecret(inputPath);
    registerRuntimeSecret(outputPath);
    await writeRestrictedJson(inputPath, input);
    try {
      await run(
        "npx",
        ["--no-install", "medusa", "exec", helperPath, inputPath, outputPath],
        {
          capture: true,
          cleanup,
          cwd: target.backendRoot,
          env: target.env,
          sanitizeCapture: true,
          timeoutMs: cleanup ? 45_000 : undefined,
        },
      );
      return JSON.parse(await readFile(outputPath, "utf8"));
    } finally {
      await Promise.all([
        rm(inputPath, { force: true }),
        rm(outputPath, { force: true }),
      ]);
    }
  };

  const assertPaymentLinkUid = (value) => {
    const uid = String(value || "");
    if (!/^[A-Za-z0-9_-]{1,200}$/.test(uid)) {
      throw new Error("Invalid real-sandbox payment-link UID.");
    }
    return uid;
  };

  const entryFromProjection = (name, projection, context) => {
    const uid = assertPaymentLinkUid(projection?.uid);
    if (
      projection?.authMode !== "oauth" ||
      !realSandboxOwnedEmails.has(
        String(projection.customerEmail || "").toLowerCase(),
      ) ||
      !projection.companyId ||
      !projection.grantId ||
      !projection.installationId ||
      !projection.subscriptionId ||
      projection.companyId !== context?.companyId ||
      projection.grantId !== context?.grantId ||
      projection.installationId !== context?.installationId ||
      projection.subscriptionId !== context?.subscriptionId
    ) {
      throw new Error(
        "The real-sandbox payment link is not owned by the current installation context.",
      );
    }
    return {
      archivedVerifiedAt: null,
      companyId: projection.companyId,
      grantId: projection.grantId,
      installation: name,
      installationId: projection.installationId,
      subscriptionId: projection.subscriptionId,
      uid,
    };
  };

  const recordEntry = async (entry) =>
    mutateLedger((draft) => {
      const key = ledgerKey(entry);
      const existing = draft.get(key);
      draft.set(key, {
        ...entry,
        archivedVerifiedAt:
          existing?.archivedVerifiedAt ?? entry.archivedVerifiedAt ?? null,
      });
      return draft.get(key);
    });

  const trackPaymentLink = async (name, value, options = {}) => {
    const uid = assertPaymentLinkUid(value);
    const snapshot = await invoke(name, { action: "snapshot", uid }, options);
    const entry = entryFromProjection(
      name,
      snapshot?.projection,
      snapshot?.context,
    );
    await recordEntry(entry);
    return { tracked: true, uid };
  };

  const markArchived = async (name, result) => {
    const uid = assertPaymentLinkUid(result?.uid);
    const localTerminalState = [
      ["cancelled", "canceled"],
      ["complete", "paid"],
      ["failed", "failed"],
    ].some(
      ([providerStatus, medusaStatus]) =>
        result?.providerStatus === providerStatus &&
        result?.medusaStatus === medusaStatus,
    );
    if (
      result?.archived !== true ||
      result?.remoteStatus !== "archived" ||
      (result?.localProjection !== false && !localTerminalState)
    ) {
      throw new Error("Payment-link archival verification was incomplete.");
    }
    const routing = result.routing || {};
    return mutateLedger((draft) => {
      const key = `${name}:${routing.grantId}:${uid}`;
      const entry = draft.get(key);
      if (
        !entry ||
        entry.companyId !== routing.companyId ||
        entry.installationId !== routing.installationId ||
        entry.subscriptionId !== routing.subscriptionId
      ) {
        throw new Error(
          "Payment-link archival did not match its durable routing tuple.",
        );
      }
      entry.archivedVerifiedAt = new Date().toISOString();
      draft.set(key, entry);
      return entry;
    });
  };

  const archivePaymentLink = async (name, value, options = {}) => {
    const uid = assertPaymentLinkUid(value);
    await trackPaymentLink(name, uid, options);
    return archiveTrackedPaymentLink(name, uid, options);
  };

  const archiveTrackedPaymentLink = async (name, value, options = {}) => {
    const uid = assertPaymentLinkUid(value);
    const result = await invoke(
      name,
      { action: "archive-payment-link", runId, uid },
      options,
    );
    await markArchived(name, result);
    return result;
  };

  const archiveAll = async (name, options = {}) => {
    const discovered = await invoke(
      name,
      { action: "list-cleanup-candidates", runId },
      options,
    );
    for (const projection of [
      ...(discovered?.candidates || []),
      ...(discovered?.remoteCandidates || []),
    ]) {
      await recordEntry(
        entryFromProjection(name, projection, {
          companyId: projection.companyId,
          grantId: projection.grantId,
          installationId: projection.installationId,
          subscriptionId: projection.subscriptionId,
        }),
      );
    }
    const unresolved = [];
    const verified = [];
    for (const entry of [...ledger.values()].filter(
      (candidate) => candidate.installation === name,
    )) {
      if (entry.archivedVerifiedAt) {
        verified.push(entry.uid);
        continue;
      }
      try {
        const result = await archiveTrackedPaymentLink(
          name,
          entry.uid,
          options,
        );
        verified.push(result.uid);
      } catch {
        unresolved.push({
          grantId: entry.grantId,
          installationId: entry.installationId,
          subscriptionId: entry.subscriptionId,
          uid: entry.uid,
        });
      }
    }
    return {
      unresolved,
      verified: [...new Set(verified)].sort(),
    };
  };

  const readLedger = async () => {
    await ledgerQueue;
    const stored = JSON.parse(await readFile(ledgerPath, "utf8"));
    if (
      stored?.kind !== "makepay-real-sandbox-payment-link-ledger" ||
      stored?.schemaVersion !== 1 ||
      stored?.runId !== runId ||
      !Array.isArray(stored.entries)
    ) {
      throw new Error("The real-sandbox payment-link ledger is invalid.");
    }
    return stored.entries;
  };

  const prepareFixture = async (name, uid, status) => {
    const fixtureId = randomUUID().replaceAll("-", "");
    const fixturePath = join(fixtureDirectory, `signed-${fixtureId}.json`);
    registerRuntimeSecret(fixturePath);
    const result = await invoke(name, {
      action: "prepare",
      fixturePath,
      status,
      uid,
    });
    fixtures.set(fixtureId, fixturePath);
    return { fixtureId, ...result };
  };

  const prepareTerminalFixture = async (name, uid, status) => {
    const fixtureId = randomUUID().replaceAll("-", "");
    const fixturePath = join(
      fixtureDirectory,
      `signed-terminal-${fixtureId}.json`,
    );
    registerRuntimeSecret(fixturePath);
    const result = await invoke(name, {
      action: "prepare-terminal-fixture",
      fixturePath,
      runId,
      status,
      uid,
    });
    fixtures.set(fixtureId, fixturePath);
    return { fixtureId, ...result };
  };

  const fixturePath = (fixtureId) => {
    const path = fixtures.get(fixtureId);
    if (!path) throw new Error("Unknown signed webhook fixture.");
    return path;
  };

  const startOldSigner = async () => {
    if (oldSigner?.child?.exitCode === null) {
      throw new Error("The old installation-B signer is already active.");
    }
    const target = installation("b");
    const signerId = randomUUID().replaceAll("-", "");
    const signerSocketPath = join(
      temporaryRoot,
      `old-b-signer-${signerId}.sock`,
    );
    registerRuntimeSecret(signerSocketPath);
    const inputPath = join(fixtureDirectory, `signer-${signerId}.json`);
    const outputPath = join(fixtureDirectory, `signer-${signerId}.ready.json`);
    registerRuntimeSecret(inputPath);
    registerRuntimeSecret(outputPath);
    await writeRestrictedJson(inputPath, {
      action: "serve-signer",
      callbackUrl: target.callbackUrl,
      socketPath: signerSocketPath,
    });
    const child = await startProcess(
      "npx",
      ["--no-install", "medusa", "exec", helperPath, inputPath, outputPath],
      {
        cwd: target.backendRoot,
        env: target.env,
        logPath: join(
          temporaryRoot,
          "runtime-raw",
          "old-installation-b-signer.log",
        ),
        mutator: true,
      },
    );
    oldSigner = {
      child,
      inputPath,
      outputPath,
      socketPath: signerSocketPath,
    };
    await waitForSocket(signerSocketPath, child, "Old installation-B signer");
    await Promise.all([
      rm(inputPath, { force: true }),
      rm(outputPath, { force: true }),
    ]);
    return { ready: true };
  };

  const handler = async (input) => {
    const action = input?.action;
    if (action === "track-payment-link") {
      return trackPaymentLink(input.installation, input.uid);
    }
    if (action === "archive-payment-link") {
      return archivePaymentLink(input.installation, input.uid);
    }
    if (action === "archive-all-payment-links") {
      return archiveAll(input.installation);
    }
    if (action === "snapshot") {
      return invoke(input.installation, {
        action,
        uid: input.uid || undefined,
      });
    }
    if (action === "prepare") {
      return prepareFixture(
        input.installation,
        String(input.uid || ""),
        String(input.status || ""),
      );
    }
    if (action === "prepare-terminal-fixture") {
      return prepareTerminalFixture(
        input.installation,
        String(input.uid || ""),
        String(input.status || ""),
      );
    }
    if (action === "assert-hosted-return") {
      return invoke(input.installation, {
        action,
        expectedReturnUrl: String(input.expectedReturnUrl || ""),
        runId,
        state: String(input.state || ""),
        uid: String(input.uid || ""),
      });
    }
    if (action === "deliver") {
      return invoke(input.installation, {
        action,
        callbackUrl: installation(input.target).callbackUrl,
        status: String(input.status || ""),
        uid: String(input.uid || ""),
      });
    }
    if (action === "post-legacy-fixture") {
      return invoke(input.installation, {
        action: "post-fixture",
        callbackUrl: installation(input.target).legacyCallbackUrl,
        fixturePath: fixturePath(String(input.fixtureId || "")),
      });
    }
    if (action === "post-terminal-fixture") {
      return invoke(input.installation, {
        action,
        callbackUrl: installation(input.target).callbackUrl,
        fixturePath: fixturePath(String(input.fixtureId || "")),
      });
    }
    if (
      action === "post-fixture" ||
      action === "resign-fixture" ||
      action === "resign-fixture-without-routing"
    ) {
      return invoke(input.installation, {
        action,
        callbackUrl: installation(input.target).callbackUrl,
        fixturePath: fixturePath(String(input.fixtureId || "")),
      });
    }
    if (action === "start-old-b-signer") {
      return startOldSigner();
    }
    if (action === "old-b-signer-deliver") {
      if (!oldSigner?.socketPath) {
        throw new Error("The old installation-B signer is not active.");
      }
      const fixture = JSON.parse(
        await readFile(fixturePath(String(input.fixtureId || "")), "utf8"),
      );
      return unixJsonRequest(oldSigner.socketPath, "/deliver", { fixture });
    }
    if (action === "stop-old-b-signer") {
      await stopChild(oldSigner?.child);
      if (oldSigner?.socketPath) {
        await rm(oldSigner.socketPath, { force: true });
      }
      oldSigner = undefined;
      return { stopped: true };
    }
    throw new Error("Unsupported real-sandbox control action.");
  };

  const server = createHttpServer(async (request, response) => {
    try {
      if (request.method !== "POST" || request.url !== "/control") {
        response.writeHead(404).end();
        return;
      }
      if (actionsQuiesced) {
        throw new Error("The real-sandbox control plane is quiesced.");
      }
      const result = await handler(await readControlRequest(request));
      response
        .writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify(result));
    } catch (error) {
      log(
        `Restricted real-sandbox helper rejected an action: ${sanitizeRuntimeLog(error instanceof Error ? error.message : "unknown error")}`,
      );
      response
        .writeHead(400, { "content-type": "application/json" })
        .end(JSON.stringify({ message: "Restricted helper action failed." }));
    }
  });
  const { socketDirectory, socketPath } = await listenOnRestrictedControlSocket(
    server,
    "real",
  );
  return {
    async archiveAll(installationName) {
      assertForegroundQuiesced();
      return archiveAll(installationName, { cleanup: true });
    },
    async disconnect(installationName) {
      assertForegroundQuiesced();
      const result = await invoke(
        installationName,
        { action: "disconnect-oauth" },
        { cleanup: true },
      );
      if (result?.connected !== false || result?.status !== "disconnected") {
        throw new Error("Restricted helper did not confirm OAuth disconnect.");
      }
      return result;
    },
    async connectionView(installationName) {
      assertForegroundQuiesced();
      const result = await invoke(
        installationName,
        { action: "connection-view" },
        { cleanup: true },
      );
      if (
        typeof result?.connected !== "boolean" ||
        !["connected", "disconnect_pending", "disconnected", "error"].includes(
          result?.status,
        )
      ) {
        throw new Error(
          "Restricted helper returned an invalid OAuth connection state.",
        );
      }
      return result;
    },
    async close() {
      await stopChild(oldSigner?.child).catch(() => {});
      oldSigner = undefined;
      await new Promise((resolvePromise) =>
        server.close(() => resolvePromise()),
      );
      await Promise.all([
        rm(socketDirectory, { force: true, recursive: true }),
        rm(fixtureDirectory, { force: true, recursive: true }),
      ]);
    },
    readLedger,
    socketPath,
  };
}

const deterministicMedusaControlProfiles = Object.freeze({
  oauth: Object.freeze({
    allowApiKeyActions: false,
    fixtureDirectoryName: "oauth-control-fixtures",
    label: "OAuth",
    socketName: "oauth",
  }),
  "api-key": Object.freeze({
    allowApiKeyActions: true,
    fixtureDirectoryName: "api-key-control-fixtures",
    label: "API-key",
    socketName: "api",
  }),
});

function deterministicMedusaControlProfile(profile) {
  const configuration = deterministicMedusaControlProfiles[profile];
  if (!configuration) {
    throw new Error("Unsupported deterministic Medusa control profile.");
  }
  return configuration;
}

async function startMedusaControl({ backendRoot, env, profile }) {
  const configuration = deterministicMedusaControlProfile(profile);
  const fixtureDirectory = join(
    temporaryRoot,
    configuration.fixtureDirectoryName,
  );
  const helperPath = join(
    packageRoot,
    "tests/e2e/support/api-key-medusa-helper.mjs",
  );
  let captureFailureOwned = false;
  let actionQueue = Promise.resolve();
  let closing = false;
  registerRuntimeSecret(fixtureDirectory);
  await mkdir(fixtureDirectory, { mode: 0o700, recursive: true });
  await chmod(fixtureDirectory, 0o700);

  const invoke = async (input) => {
    const id = randomUUID().replaceAll("-", "");
    const inputPath = join(fixtureDirectory, `input-${id}.json`);
    const outputPath = join(fixtureDirectory, `output-${id}.json`);
    registerRuntimeSecret(inputPath);
    registerRuntimeSecret(outputPath);
    await writeRestrictedJson(inputPath, input);
    try {
      await run(
        "npx",
        ["--no-install", "medusa", "exec", helperPath, inputPath, outputPath],
        {
          capture: true,
          cwd: backendRoot,
          env,
          sanitizeCapture: true,
        },
      );
      return JSON.parse(await readFile(outputPath, "utf8"));
    } finally {
      await Promise.all([
        rm(inputPath, { force: true }),
        rm(outputPath, { force: true }),
      ]);
    }
  };

  const handler = async (input) => {
    const action = input?.action;
    if (configuration.allowApiKeyActions) {
      if (action === "snapshot") {
        return invoke({
          action,
          email: input.email || undefined,
          orderId: input.orderId || undefined,
          paymentId: input.paymentId || undefined,
          sessionId: input.sessionId || undefined,
          uid: input.uid || undefined,
        });
      }
      if (action === "update-session") {
        return invoke({
          action,
          amount: input.amount,
          currency: input.currency,
          sessionId: input.sessionId,
        });
      }
      if (action === "cancel-payment") {
        return invoke({ action, paymentId: input.paymentId });
      }
      if (action === "delete-session") {
        return invoke({ action, sessionId: input.sessionId });
      }
      if (action === "resolve-oauth-transition-fixture") {
        return resolveOAuthTransitionFixture(env.DATABASE_URL);
      }
    }
    if (
      !configuration.allowApiKeyActions &&
      action === "expire-oauth-access-token"
    ) {
      return expireOAuthAccessToken(env.DATABASE_URL);
    }
    if (
      !configuration.allowApiKeyActions &&
      action === "oauth-refresh-lock-state"
    ) {
      return oauthRefreshLockState(env.DATABASE_URL);
    }
    if (action === "arm-capture-failure-once") {
      if (captureFailureOwned) {
        throw new Error("The capture-failure fixture is already run-owned.");
      }
      captureFailureOwned = true;
      try {
        return await armCaptureFailureOnce(
          env.DATABASE_URL,
          input.sessionId,
          runId,
        );
      } catch (error) {
        const status = await captureFailureStatus(env.DATABASE_URL).catch(
          () => undefined,
        );
        if (status?.fixtureObjectCount === 0) captureFailureOwned = false;
        throw error;
      }
    }
    if (action === "capture-failure-status") {
      return captureFailureStatus(env.DATABASE_URL);
    }
    if (action === "disarm-capture-failure") {
      if (!captureFailureOwned) {
        throw new Error("No run-owned capture-failure fixture is armed.");
      }
      const result = await disarmCaptureFailure(env.DATABASE_URL, runId);
      captureFailureOwned = false;
      return result;
    }
    throw new Error(
      `Unsupported ${configuration.label} Medusa control action.`,
    );
  };

  const enqueueAction = (action) => {
    if (closing) {
      throw new Error(
        `The ${configuration.label} Medusa control plane is closing.`,
      );
    }
    const result = actionQueue.then(action);
    actionQueue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  };

  const server = createHttpServer(async (request, response) => {
    try {
      if (request.method !== "POST" || request.url !== "/control") {
        response.writeHead(404).end();
        return;
      }
      if (actionsQuiesced) {
        throw new Error(
          `The ${configuration.label} Medusa control plane is quiesced.`,
        );
      }
      const input = await readControlRequest(request);
      const result = await enqueueAction(() => handler(input));
      response
        .writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify(result));
    } catch (error) {
      log(
        `Restricted ${configuration.label} Medusa helper rejected an action: ${sanitizeRuntimeLog(error instanceof Error ? error.message : "unknown error")}`,
      );
      response
        .writeHead(400, { "content-type": "application/json" })
        .end(JSON.stringify({ message: "Restricted helper action failed." }));
    }
  });
  const { socketDirectory, socketPath } = await listenOnRestrictedControlSocket(
    server,
    configuration.socketName,
  );
  return {
    async close() {
      const failures = [];
      closing = true;
      try {
        await new Promise((resolvePromise, reject) =>
          server.close((error) => (error ? reject(error) : resolvePromise())),
        );
      } catch (error) {
        failures.push(error);
      }
      await actionQueue;
      if (captureFailureOwned) {
        try {
          await disarmCaptureFailure(env.DATABASE_URL, runId);
          captureFailureOwned = false;
        } catch (error) {
          failures.push(error);
        }
      }
      const removalResults = await Promise.allSettled([
        rm(socketDirectory, { force: true, recursive: true }),
        rm(fixtureDirectory, { force: true, recursive: true }),
      ]);
      failures.push(
        ...removalResults
          .filter((result) => result.status === "rejected")
          .map((result) => result.reason),
      );
      if (failures.length > 0) {
        throw new AggregateError(
          failures,
          `Failed to close the ${configuration.label} Medusa control plane.`,
        );
      }
    },
    socketPath,
  };
}

async function pendingOAuthRegistrations(databaseUrl) {
  const psql = findPostgresBinary("psql");
  if (!psql) return { count: 0, identifiers: [], unknown: true };
  try {
    const result = await run(
      psql,
      [
        "--dbname",
        databaseUrl,
        "--tuples-only",
        "--no-align",
        "--set",
        "ON_ERROR_STOP=1",
        "--command",
        "SELECT COUNT(*) || '|' || COALESCE(string_agg(DISTINCT client_id, ','), '') FROM makepay_oauth_state WHERE consumed_at IS NULL AND deleted_at IS NULL;",
      ],
      {
        capture: true,
        cleanup: true,
        sanitizeCapture: true,
        timeoutMs: 10_000,
      },
    );
    const [countText, identifiers = ""] = result.stdout.trim().split("|", 2);
    const count = Number.parseInt(countText, 10);
    return {
      count: Number.isFinite(count) ? count : 0,
      identifiers: identifiers.split(",").filter(Boolean),
      unknown: false,
    };
  } catch {
    return { count: 0, identifiers: [], unknown: true };
  }
}

async function localOAuthFootprintState(databaseUrl) {
  const psql = findPostgresBinary("psql");
  if (!psql) {
    return {
      connectionCount: 0,
      oauthStateCount: 0,
      subscriptionCount: 0,
      unknown: true,
    };
  }
  try {
    const result = await run(
      psql,
      [
        "--dbname",
        databaseUrl,
        "--tuples-only",
        "--no-align",
        "--set",
        "ON_ERROR_STOP=1",
        "--command",
        `SELECT
           (SELECT COUNT(*) FROM makepay_connection
            WHERE provider_id = 'makepay' AND deleted_at IS NULL) || '|' ||
           (SELECT COUNT(*) FROM makepay_oauth_state
            WHERE provider_id = 'makepay' AND deleted_at IS NULL) || '|' ||
           (SELECT COUNT(*) FROM makepay_webhook_subscription
            WHERE provider_id = 'makepay' AND deleted_at IS NULL);`,
      ],
      {
        capture: true,
        cleanup: true,
        sanitizeCapture: true,
        timeoutMs: 10_000,
      },
    );
    const counts = result.stdout.trim().split("|");
    if (counts.length !== 3 || counts.some((value) => !/^\d+$/.test(value))) {
      throw new Error("PostgreSQL returned invalid OAuth cleanup counts.");
    }
    return {
      connectionCount: Number(counts[0]),
      oauthStateCount: Number(counts[1]),
      subscriptionCount: Number(counts[2]),
      unknown: false,
    };
  } catch {
    return {
      connectionCount: 0,
      oauthStateCount: 0,
      subscriptionCount: 0,
      unknown: true,
    };
  }
}

async function localRealSandboxPaymentState(databaseUrl) {
  const psql = findPostgresBinary("psql");
  if (!psql) return { payments: [], unknown: true };
  const emailA = `makepay-real-sandbox+${runId}@example.com`;
  const emailB = `makepay-real-sandbox+${runId}-installation-b@example.com`;
  const emailBReconnected = `makepay-real-sandbox+${runId}-installation-b-reconnected@example.com`;
  try {
    const result = await run(
      psql,
      [
        "--dbname",
        databaseUrl,
        "--tuples-only",
        "--no-align",
        "--field-separator=|",
        "--set",
        "ON_ERROR_STOP=1",
        "--command",
        `SELECT payment_link_uid, provider_status, medusa_status,
                COALESCE(grant_id, ''), COALESCE(installation_id, ''),
                COALESCE(webhook_subscription_id, '')
         FROM makepay_payment_projection
         WHERE auth_mode = 'oauth' AND deleted_at IS NULL
           AND customer_email IS NOT NULL
           AND lower(customer_email) IN (
             lower(current_setting('makepay.e2e_email_a')),
             lower(current_setting('makepay.e2e_email_b')),
             lower(current_setting('makepay.e2e_email_b_reconnected'))
           )
         ORDER BY payment_link_uid;`,
      ],
      {
        capture: true,
        cleanup: true,
        env: {
          PGOPTIONS: [
            `-c makepay.e2e_email_a=${emailA}`,
            `-c makepay.e2e_email_b=${emailB}`,
            `-c makepay.e2e_email_b_reconnected=${emailBReconnected}`,
          ].join(" "),
        },
        sanitizeCapture: true,
        timeoutMs: 10_000,
      },
    );
    const payments = result.stdout
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [
          uid,
          providerStatus,
          medusaStatus,
          grantId,
          installationId,
          subscriptionId,
        ] = line.split("|");
        if (
          !/^[A-Za-z0-9_-]{1,200}$/.test(uid || "") ||
          [
            providerStatus,
            medusaStatus,
            grantId,
            installationId,
            subscriptionId,
          ].some((value) => value === undefined || value.includes("|"))
        ) {
          throw new Error("PostgreSQL returned an invalid cleanup projection.");
        }
        return {
          grantId,
          installationId,
          medusaStatus,
          providerStatus,
          subscriptionId,
          uid,
        };
      });
    return { payments, unknown: false };
  } catch {
    return { payments: [], unknown: true };
  }
}

function isPristineDisconnectedSandboxInstallation({
  connection,
  footprint,
  ledgerEntries,
  local,
  pending,
}) {
  return (
    connection?.connected === false &&
    connection?.status === "disconnected" &&
    footprint?.unknown === false &&
    footprint.connectionCount === 0 &&
    footprint.oauthStateCount === 0 &&
    footprint.subscriptionCount === 0 &&
    pending?.unknown === false &&
    pending.count === 0 &&
    local?.unknown === false &&
    Array.isArray(local.payments) &&
    local.payments.length === 0 &&
    Array.isArray(ledgerEntries) &&
    ledgerEntries.length === 0
  );
}

const resolvedArchivedSandboxPaymentStates = new Set([
  "cancelled:canceled",
  "complete:paid",
  "failed:failed",
]);

function isResolvedArchivedSandboxPayment(payment, verifiedKeys) {
  const providerStatus = String(payment?.providerStatus ?? "").toLowerCase();
  const medusaStatus = String(payment?.medusaStatus ?? "").toLowerCase();
  const grantId = String(payment?.grantId ?? "");
  const uid = String(payment?.uid ?? "");
  return (
    resolvedArchivedSandboxPaymentStates.has(
      `${providerStatus}:${medusaStatus}`,
    ) && verifiedKeys.has(`${grantId}:${uid}`)
  );
}

async function cleanupRealSandboxInstallations() {
  if (!realSandbox) return null;
  if (
    realSandboxCleanupTargets.length !== 2 ||
    new Set(realSandboxCleanupTargets.map((target) => target.installation))
      .size !== 2 ||
    !realSandboxCleanupTargets.every((target) =>
      ["a", "b"].includes(target.installation),
    )
  ) {
    throw new Error(
      "Real-sandbox cleanup requires exactly installations A and B.",
    );
  }
  assertForegroundQuiesced();
  const blockers = [];
  const installationReceipts = [];
  for (const target of realSandboxCleanupTargets) {
    const pendingBeforeCleanup = await pendingOAuthRegistrations(
      target.databaseUrl,
    );
    const [footprint, local] = await Promise.all([
      localOAuthFootprintState(target.databaseUrl),
      localRealSandboxPaymentState(target.databaseUrl),
    ]);
    let connection;
    let archiveResult = { unresolved: [], verified: [] };
    let ledgerEntries = [];
    try {
      if (realSandboxControl) {
        [connection, ledgerEntries] = await Promise.all([
          realSandboxControl.connectionView(target.installation),
          realSandboxControl
            .readLedger()
            .then((entries) =>
              entries.filter(
                (entry) => entry.installation === target.installation,
              ),
            ),
        ]);
      }
    } catch {
      archiveResult = {
        unresolved: [{ uid: "discovery-unavailable" }],
        verified: [],
      };
    }
    const pristineDisconnected = isPristineDisconnectedSandboxInstallation({
      connection,
      footprint,
      ledgerEntries,
      local,
      pending: pendingBeforeCleanup,
    });
    let disconnected = pristineDisconnected;
    const disconnectedWithNoRemoteCredentials =
      connection?.connected === false &&
      connection?.status === "disconnected" &&
      footprint.unknown === false &&
      footprint.connectionCount === 0;
    if (
      !pristineDisconnected &&
      !disconnectedWithNoRemoteCredentials &&
      realSandboxControl
    ) {
      try {
        archiveResult = await realSandboxControl.archiveAll(
          target.installation,
        );
        ledgerEntries = (await realSandboxControl.readLedger()).filter(
          (entry) => entry.installation === target.installation,
        );
      } catch {
        archiveResult = {
          unresolved: [{ uid: "discovery-unavailable" }],
          verified: [],
        };
      }
    }
    const verifiedKeys = new Set(
      ledgerEntries
        .filter((entry) => entry.archivedVerifiedAt)
        .map((entry) => `${entry.grantId}:${entry.uid}`),
    );
    const unresolved = [
      ...archiveResult.unresolved,
      ...ledgerEntries
        .filter((entry) => !entry.archivedVerifiedAt)
        .map((entry) => ({
          grantId: entry.grantId,
          installationId: entry.installationId,
          subscriptionId: entry.subscriptionId,
          uid: entry.uid,
        })),
      ...local.payments
        .filter(
          (payment) =>
            !isResolvedArchivedSandboxPayment(payment, verifiedKeys),
        )
        .map((payment) => ({
          grantId: payment.grantId,
          installationId: payment.installationId,
          subscriptionId: payment.subscriptionId,
          uid: payment.uid,
        })),
    ];
    const uniqueUnresolved = [
      ...new Map(
        unresolved.map((entry) => [
          `${entry.grantId || "unknown"}:${entry.uid}`,
          entry,
        ]),
      ).values(),
    ];
    const linksClean = !local.unknown && uniqueUnresolved.length === 0;

    const safeIdentifiers = ledgerEntries
      .flatMap((entry) => [
        entry.companyId,
        entry.grantId,
        entry.installationId,
        entry.subscriptionId,
      ])
      .filter(Boolean);
    if (
      linksClean &&
      realSandboxControl &&
      !disconnectedWithNoRemoteCredentials
    ) {
      try {
        const result = await realSandboxControl.disconnect(target.installation);
        disconnected =
          result?.connected === false && result?.status === "disconnected";
      } catch {}
    }

    const pending = await pendingOAuthRegistrations(target.databaseUrl);
    installationReceipts.push({
      archivedPaymentLinkUids: [
        ...new Set(
          ledgerEntries
            .filter((entry) => entry.archivedVerifiedAt)
            .map((entry) => entry.uid),
        ),
      ].sort(),
      disconnected,
      installation: target.installation,
      localDiscoveryKnown: !local.unknown,
      pendingNativeCount: pending.unknown ? -1 : pending.count,
      pendingNativeKnown: !pending.unknown,
      unresolvedCount: uniqueUnresolved.length,
    });
    if (!linksClean || !disconnected || pending.count > 0 || pending.unknown) {
      const linkBlockers = uniqueUnresolved
        .map(
          (entry) => `${entry.uid}${entry.grantId ? `@${entry.grantId}` : ""}`,
        )
        .join(",");
      blockers.push(
        `${target.label} (links=${local.unknown ? "discovery-unknown" : linksClean ? "archived-and-resolved" : linkBlockers || "unverified"}, disconnect=${disconnected ? "confirmed" : "unconfirmed"}, pending-native=${pending.unknown ? "unknown" : pending.count}${[...new Set([...safeIdentifiers, ...pending.identifiers])].length ? `, safe-ids=${[...new Set([...safeIdentifiers, ...pending.identifiers])].join(",")}` : ""})`,
      );
    }
  }
  if (blockers.length) {
    process.exitCode = 1;
    process.stderr.write(
      sanitizeRuntimeLog(
        `[makepay-e2e] MANUAL CLEANUP BLOCKER: verify/remove the sandbox Connected App and webhook subscription for ${blockers.join(
          "; ",
        )} before release. A native registration abandoned before OAuth consent can require Connected Apps/support cleanup.\n`,
      ),
    );
    throw new Error(
      "Real-sandbox payment-link archival and OAuth cleanup were not fully verified.",
    );
  }
  return {
    accepted: true,
    installations: installationReceipts.sort((left, right) =>
      left.installation.localeCompare(right.installation),
    ),
  };
}

async function settleCleanupStages(stages, { report = true } = {}) {
  let passed = true;
  for (const [label, task] of stages) {
    try {
      await task();
    } catch (error) {
      passed = false;
      if (report) {
        process.exitCode = 1;
        log(
          `${label} cleanup warning: ${error instanceof Error ? error.message : "unknown failure"}`,
        );
      }
    }
  }
  return passed;
}

function orderedMutationCleanupStages({ quiesce, remoteCleanup, terminate }) {
  let quiesced = false;
  return [
    [
      "Foreground browser and mutator quiescence",
      async () => {
        await quiesce();
        quiesced = true;
      },
    ],
    [
      "Payment-link archival and remote OAuth revocation",
      async () => {
        if (!quiesced) {
          throw new Error(
            "Remote cleanup was blocked because foreground work did not quiesce.",
          );
        }
        await remoteCleanup();
      },
    ],
    ["Child process termination", terminate],
  ];
}

function childIsAlive(child) {
  return child && child.exitCode === null && !child.signalCode;
}

async function terminateProcessSet(processes) {
  const signal = (child, name) => {
    try {
      if (supportsProcessGroups && child?.pid) process.kill(-child.pid, name);
      else if (childIsAlive(child)) child.kill(name);
    } catch (error) {
      if (error?.code !== "ESRCH") {
        log(`Process cleanup warning for PID ${child.pid}: ${error.message}`);
      }
    }
  };
  const snapshot = new Set([...processes].filter((child) => child?.pid));
  for (const child of snapshot) signal(child, "SIGTERM");
  await new Promise((resolvePromise) => setTimeout(resolvePromise, 500));
  for (const child of snapshot) signal(child, "SIGKILL");
  await Promise.all(
    [...snapshot].map(
      (child) =>
        new Promise((resolvePromise) => {
          if (child.exitCode !== null || child.signalCode) {
            resolvePromise();
            return;
          }
          const timeout = setTimeout(resolvePromise, 5_000);
          child.once("exit", () => {
            clearTimeout(timeout);
            resolvePromise();
          });
        }),
    ),
  );
  await Promise.all(
    [...snapshot].map((child) => child.makePayOutputClosed).filter(Boolean),
  );
  return [...snapshot].filter((child) => {
    if (!supportsProcessGroups) return childIsAlive(child);
    try {
      process.kill(-child.pid, 0);
      return true;
    } catch (error) {
      if (error?.code === "ESRCH") return false;
      throw error;
    }
  });
}

async function quiesceForegroundWork() {
  actionsQuiesced = true;
  const survivors = [
    ...(await terminateProcessSet(foregroundProcesses)),
    ...(await terminateProcessSet(mutationProcesses)),
  ];
  for (const child of [...foregroundProcesses]) {
    if (!childIsAlive(child)) foregroundProcesses.delete(child);
  }
  if (survivors.length || [...foregroundProcesses].some(childIsAlive)) {
    throw new Error("Foreground browser/mutator work could not be quiesced.");
  }
  for (const child of [...mutationProcesses]) {
    if (!childIsAlive(child)) mutationProcesses.delete(child);
  }
  if ([...mutationProcesses].some(childIsAlive)) {
    throw new Error("Background request mutators could not be quiesced.");
  }
  for (const port of mutationPorts) {
    await freePort(port);
  }
}

function assertForegroundQuiesced() {
  if (
    !actionsQuiesced ||
    [...foregroundProcesses].some(childIsAlive) ||
    [...mutationProcesses].some(childIsAlive)
  ) {
    throw new Error(
      "Remote cleanup is forbidden while foreground mutator work is active.",
    );
  }
}

async function terminateChildren() {
  const survivors = await terminateProcessSet(
    new Set([...childProcesses, ...foregroundProcesses]),
  );
  for (const child of [...childProcesses]) {
    if (!childIsAlive(child)) childProcesses.delete(child);
  }
  for (const child of [...foregroundProcesses]) {
    if (!childIsAlive(child)) foregroundProcesses.delete(child);
  }
  for (const child of [...mutationProcesses]) {
    if (!childIsAlive(child)) mutationProcesses.delete(child);
  }
  if (
    survivors.length ||
    [...childProcesses, ...foregroundProcesses, ...mutationProcesses].some(
      childIsAlive,
    )
  ) {
    throw new Error("Child process termination could not be verified.");
  }
}

function sanitizeRuntimeLog(source) {
  let sanitized = stripVTControlCharacters(String(source))
    .replace(/\u001B\][^\u0007]*(?:\u0007|\u001B\\)/g, "")
    .replace(/\u001B\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, "")
    .replace(
      /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
      "[redacted-jwt]",
    )
    .replace(
      /https:\/\/[a-z0-9-]+\.trycloudflare\.com/gi,
      "[redacted-tunnel-url]",
    )
    .replace(/(https?:\/\/)[^/\s"'<>?#@]+@/gi, "$1[redacted]@")
    .replace(
      /(https?:\/\/[^\s"'<>?#]+)[?#][^\s"'<>│┃║]+(?:(?:[ \t]*(?:[│┃║][ \t]*(?:\n)?[ \t]*){2})[A-Za-z0-9._~!$&'()*+,;=:@/?%+#-]+(?=[ \t]*[│┃║]))*/gi,
      "$1?[redacted]",
    )
    .replace(/(https?:\/\/[^\s"'<>?#]+)(?:[?#][^\s"'<>]*)/gi, "$1?[redacted]")
    .replace(
      /([?&](?:code|state|makepay_state|error_description)=)[^&\s"']+/gi,
      "$1[redacted]",
    )
    .replace(
      /\b(authorization|cookie|proxy-authorization|set-cookie|x-makepay-signature)\b(["']?\s*[:=]\s*)[^\r\n]+/gi,
      "$1$2[redacted]",
    )
    .replace(
      /\b(access[_-]?token|refresh[_-]?token|id[_-]?token|token|api[_-]?key|publishable[_-]?key|client[_-]?secret|code[_-]?verifier|authorization[_-]?code|code|oauth[_-]?state|makepay[_-]?state|state|dpop(?:[_-]?proof)?|private[_-]?key|webhook[_-]?secret|signing[_-]?secret|cookie[_-]?secret|jwt[_-]?secret|encryption[_-]?key|password)\b["']?(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^,;\s]+)/gi,
      "$1$2[redacted]",
    );
  for (const secret of [
    ...runtimeSecrets,
    process.env.MAKEPAY_E2E_DATABASE_URL,
    process.env.MAKEPAY_E2E_SECOND_DATABASE_URL,
    process.env.MAKEPAY_E2E_API_KEY_DATABASE_URL,
    postgres?.databaseUrl,
    secondPostgres?.databaseUrl,
    apiKeyPostgres?.databaseUrl,
  ]) {
    if (secret) sanitized = sanitized.replaceAll(secret, "[redacted]");
  }
  return sanitized;
}

async function publishSanitizedRuntimeLogs(options = {}) {
  const rawDirectory =
    options.rawDirectory ??
    (temporaryRoot ? join(temporaryRoot, "runtime-raw") : undefined);
  if (!rawDirectory) return;
  try {
    const outputRoot =
      options.outputRoot ??
      ownedOutputRoot ??
      (await initializeOwnedOutputRoot(packageRoot));
    const canonicalOutputRoot = await validateOwnedOutputRoot(outputRoot);
    const destinationDirectory = resolve(
      options.destinationDirectory ?? runtimeDirectory,
    );
    const destinationRelative = relative(
      canonicalOutputRoot,
      destinationDirectory,
    )
      .split(process.platform === "win32" ? "\\" : "/")
      .join("/");
    assertAllowedOutputRelativePath(destinationRelative);
    await prepareOwnedOutputPath(canonicalOutputRoot, destinationRelative, {
      reset: false,
    });
    let names = [];
    try {
      names = await readdir(rawDirectory);
    } catch {
      return;
    }
    for (const name of names) {
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]*\.log$/.test(name)) continue;
      const sourcePath = join(rawDirectory, name);
      const sourceEntry = await lstat(sourcePath).catch(() => undefined);
      if (
        !sourceEntry ||
        sourceEntry.isSymbolicLink() ||
        !sourceEntry.isFile()
      ) {
        continue;
      }
      assertOwner(sourceEntry, `The raw E2E log ${name}`);
      const source = await readFile(sourcePath, "utf8").catch(() => undefined);
      if (source === undefined) continue;
      const destinationPath = join(destinationDirectory, name);
      if (await pathExists(destinationPath)) {
        const destinationEntry = await lstat(destinationPath);
        if (destinationEntry.isSymbolicLink() || !destinationEntry.isFile()) {
          throw new Error(
            `The retained E2E log ${name} is not an owned regular file.`,
          );
        }
        assertOwner(destinationEntry, `The retained E2E log ${name}`);
        await rm(destinationPath, { force: true });
      }
      await writeFile(destinationPath, sanitizeRuntimeLog(source), {
        flag: "wx",
        mode: 0o600,
      });
      await chmod(destinationPath, 0o600);
    }
  } finally {
    await rm(rawDirectory, { force: true, recursive: true });
  }
}

async function scrubPlaywrightArtifacts() {
  await Promise.all(
    [playwrightCompletionReceiptPath, realSandboxPlaywrightResultsPath]
      .filter(Boolean)
      .map((path) => rm(path, { force: true, recursive: true })),
  );
}

async function scrubRuntimeSecrets() {
  const paths = [
    activeProjectOwned &&
      activeProjectRoot &&
      join(activeProjectRoot, "apps/backend/.env"),
    activeProjectOwned &&
      activeProjectRoot &&
      join(activeProjectRoot, "apps/storefront/.env.local"),
    contractCaPath,
    temporaryRoot && join(temporaryRoot, "contract-server.key.pem"),
    temporaryRoot && join(temporaryRoot, "real-sandbox-fixtures"),
    temporaryRoot && join(temporaryRoot, "real-sandbox-control.sock"),
    temporaryRoot && join(temporaryRoot, "oauth-control.sock"),
    temporaryRoot && join(temporaryRoot, "oauth-control-fixtures"),
    temporaryRoot && join(temporaryRoot, "api-key-control.sock"),
    temporaryRoot && join(temporaryRoot, "api-key-control-fixtures"),
    realSandboxCredentialsPath,
    oldSigner?.socketPath,
  ].filter(Boolean);
  await Promise.all([
    scrubPlaywrightArtifacts(),
    ...paths.map((path) => rm(path, { force: true, recursive: true })),
  ]);
}

async function runSignalCleanupWorker() {
  if (
    !new Set([
      "manual-consent",
      "connect-a",
      "connect-b",
      "link-create",
      "webhook",
      "reconnect",
      "delayed-create",
    ]).has(signalWorkerStage)
  ) {
    throw new Error("Invalid signal self-test worker stage.");
  }
  const sentinel = process.env.MAKEPAY_E2E_SIGNAL_SENTINEL;
  if (!sentinel || !isAbsolute(sentinel)) {
    throw new Error("Signal self-test worker requires an absolute sentinel.");
  }
  registerRuntimeSecret(sentinel);
  temporaryRoot = await mkdtemp(join(tmpdir(), "makepay-signal-worker-"));
  await mkdir(join(temporaryRoot, "runtime-raw"), {
    mode: 0o700,
    recursive: true,
  });
  await prepareIsolatedChildHome(temporaryRoot);
  ownedOutputRoot = await initializeOwnedOutputRoot(packageRoot);
  await prepareOwnedOutputPath(ownedOutputRoot, `runtime/${runId}`);
  await writeRestrictedJson(join(temporaryRoot, "stage.json"), {
    connected: signalWorkerStage.includes("connect"),
    linkObserved: signalWorkerStage === "link-create",
    pendingConsent: signalWorkerStage === "manual-consent",
    reconnecting: signalWorkerStage === "reconnect",
    stage: signalWorkerStage,
    webhookInFlight: signalWorkerStage === "webhook",
  });
  await startProcess(
    process.execPath,
    [
      "-e",
      'const fs = require("node:fs"); setTimeout(() => fs.writeFileSync(process.argv[1], "late"), 1500); setInterval(() => {}, 1000);',
      sentinel,
    ],
    {
      cwd: temporaryRoot,
      env: {},
      logPath: join(temporaryRoot, "runtime-raw", "mutator.log"),
      mutator: true,
    },
  );
  log(`SIGNAL_WORKER_READY ${signalWorkerStage}`);
  await new Promise(() => {});
}

async function runSignalWorkerMatrix(root) {
  const scriptPath = fileURLToPath(import.meta.url);
  for (const stage of [
    "manual-consent",
    "connect-a",
    "connect-b",
    "link-create",
    "webhook",
    "reconnect",
    "delayed-create",
  ]) {
    for (const signal of ["SIGINT", "SIGTERM"]) {
      const sentinel = join(
        root,
        `signal-${stage}-${signal.toLowerCase()}.txt`,
      );
      const child = spawn(
        process.execPath,
        [scriptPath, `--self-test-signal-worker=${stage}`],
        {
          cwd: packageRoot,
          env: childEnvironment({ MAKEPAY_E2E_SIGNAL_SENTINEL: sentinel }),
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      let output = "";
      const ready = new Promise((resolvePromise, reject) => {
        const timeout = setTimeout(
          () =>
            reject(new Error("Signal self-test worker did not become ready.")),
          10_000,
        );
        const inspect = (chunk) => {
          output += chunk.toString("utf8");
          if (output.includes(`SIGNAL_WORKER_READY ${stage}`)) {
            clearTimeout(timeout);
            resolvePromise();
          }
        };
        child.stdout.on("data", inspect);
        child.stderr.on("data", inspect);
        child.once("error", reject);
        child.once("close", (code) => {
          if (!output.includes(`SIGNAL_WORKER_READY ${stage}`)) {
            clearTimeout(timeout);
            reject(
              new Error(`Signal self-test worker exited early (${code}).`),
            );
          }
        });
      });
      try {
        await ready;
        const completion = new Promise((resolvePromise, reject) => {
          const timeout = setTimeout(() => {
            child.kill("SIGKILL");
            reject(
              new Error("Signal self-test cleanup exceeded its deadline."),
            );
          }, 15_000);
          child.once("close", (code, closeSignal) => {
            clearTimeout(timeout);
            resolvePromise({ code, signal: closeSignal });
          });
        });
        child.kill(signal);
        const result = await completion;
        assert.equal(result.signal, null);
        assert.equal(result.code, signal === "SIGINT" ? 130 : 143);
        assert.doesNotMatch(output, /MANUAL CLEANUP BLOCKER/i);
        await new Promise((resolvePromise) =>
          setTimeout(resolvePromise, stage === "delayed-create" ? 1_600 : 100),
        );
        assert.equal(await pathExists(sentinel), false);
      } finally {
        if (child.exitCode === null && !child.signalCode) child.kill("SIGKILL");
      }
    }
  }
}

async function runSanitizerSelfTest() {
  assert.match(runId, /^medusa-e2e-.+-[a-f0-9]{16}$/);
  assert.deepEqual(officialGeneratorNpmEnvironment(), {
    NPM_CONFIG_AUDIT: "false",
    NPM_CONFIG_FETCH_RETRIES: "6",
    NPM_CONFIG_FETCH_RETRY_FACTOR: "2",
    NPM_CONFIG_FETCH_RETRY_MAXTIMEOUT: "60000",
    NPM_CONFIG_FETCH_RETRY_MINTIMEOUT: "10000",
    NPM_CONFIG_FUND: "false",
    NPM_CONFIG_MAXSOCKETS: "5",
    NPM_CONFIG_PREFER_OFFLINE: "true",
  });
  assert.equal(
    assertBrowserRunMode({
      capture: false,
      diagnostics: false,
      real: false,
      skip: true,
    }),
    true,
  );
  for (const unsafeSkipMode of [
    { capture: true, diagnostics: false, real: false, skip: true },
    { capture: false, diagnostics: true, real: false, skip: true },
    { capture: false, diagnostics: false, real: true, skip: true },
  ]) {
    assert.throws(
      () => assertBrowserRunMode(unsafeSkipMode),
      /skip-browser is setup-only/i,
    );
  }
  const skippedSummary = browserCompletionSummary({
    capture: false,
    real: false,
    skip: true,
  }).join("\n");
  assert.match(skippedSummary, /browser scenario explicitly skipped/i);
  assert.doesNotMatch(
    skippedSummary,
    /all requested.*checks passed|screenshot candidates/i,
  );
  const acceptedParentRun = {
    completedRun: true,
    exitCode: 0,
    finalCleanupPassed: true,
    primaryCleanupPassed: true,
    signal: undefined,
  };
  assert.equal(parentHarnessRunAccepted(acceptedParentRun), true);
  for (const rejectedParentRun of [
    { ...acceptedParentRun, completedRun: false },
    { ...acceptedParentRun, exitCode: 1 },
    { ...acceptedParentRun, finalCleanupPassed: false },
    { ...acceptedParentRun, primaryCleanupPassed: false },
    { ...acceptedParentRun, signal: "SIGTERM" },
  ]) {
    assert.equal(parentHarnessRunAccepted(rejectedParentRun), false);
  }
  const oauthControlProfile = deterministicMedusaControlProfile("oauth");
  const apiKeyControlProfile = deterministicMedusaControlProfile("api-key");
  assert.equal(oauthControlProfile.allowApiKeyActions, false);
  assert.equal(apiKeyControlProfile.allowApiKeyActions, true);
  assert.notEqual(
    oauthControlProfile.fixtureDirectoryName,
    apiKeyControlProfile.fixtureDirectoryName,
  );
  assert.notEqual(
    oauthControlProfile.socketName,
    apiKeyControlProfile.socketName,
  );
  assert.throws(
    () => deterministicMedusaControlProfile("unsupported"),
    /unsupported deterministic Medusa control profile/i,
  );
  const pristineSandboxInstallation = {
    connection: { connected: false, status: "disconnected" },
    footprint: {
      connectionCount: 0,
      oauthStateCount: 0,
      subscriptionCount: 0,
      unknown: false,
    },
    ledgerEntries: [],
    local: { payments: [], unknown: false },
    pending: { count: 0, unknown: false },
  };
  assert.equal(
    isPristineDisconnectedSandboxInstallation(pristineSandboxInstallation),
    true,
  );
  assert.equal(
    isPristineDisconnectedSandboxInstallation({
      ...pristineSandboxInstallation,
      pending: { count: 1, unknown: false },
    }),
    false,
  );
  assert.equal(
    isPristineDisconnectedSandboxInstallation({
      ...pristineSandboxInstallation,
      footprint: {
        ...pristineSandboxInstallation.footprint,
        connectionCount: 1,
      },
    }),
    false,
  );
  assert.equal(
    isPristineDisconnectedSandboxInstallation({
      ...pristineSandboxInstallation,
      footprint: {
        ...pristineSandboxInstallation.footprint,
        oauthStateCount: 1,
      },
    }),
    false,
  );
  assert.equal(
    isPristineDisconnectedSandboxInstallation({
      ...pristineSandboxInstallation,
      footprint: {
        ...pristineSandboxInstallation.footprint,
        subscriptionCount: 1,
      },
    }),
    false,
  );
  assert.equal(
    isPristineDisconnectedSandboxInstallation({
      ...pristineSandboxInstallation,
      local: { payments: [], unknown: true },
    }),
    false,
  );
  assert.equal(
    isPristineDisconnectedSandboxInstallation({
      ...pristineSandboxInstallation,
      ledgerEntries: [{ uid: "unresolved" }],
    }),
    false,
  );
  const archivedSandboxPaymentKey = "grant_terminal:link_terminal";
  const archivedSandboxPayment = {
    grantId: "grant_terminal",
    uid: "link_terminal",
  };
  const verifiedArchivedSandboxPaymentKeys = new Set([
    archivedSandboxPaymentKey,
  ]);
  for (const [providerStatus, medusaStatus] of [
    ["cancelled", "canceled"],
    ["complete", "paid"],
    ["failed", "failed"],
  ]) {
    assert.equal(
      isResolvedArchivedSandboxPayment(
        {
          ...archivedSandboxPayment,
          medusaStatus,
          providerStatus,
        },
        verifiedArchivedSandboxPaymentKeys,
      ),
      true,
    );
  }
  for (const candidate of [
    {
      ...archivedSandboxPayment,
      medusaStatus: "pending_authorization",
      providerStatus: "pending",
    },
    {
      ...archivedSandboxPayment,
      medusaStatus: "paid",
      providerStatus: "failed",
    },
    {
      ...archivedSandboxPayment,
      medusaStatus: "canceled",
      providerStatus: "complete",
    },
  ]) {
    assert.equal(
      isResolvedArchivedSandboxPayment(
        candidate,
        verifiedArchivedSandboxPaymentKeys,
      ),
      false,
    );
  }
  assert.equal(
    isResolvedArchivedSandboxPayment(
      {
        ...archivedSandboxPayment,
        medusaStatus: "paid",
        providerStatus: "complete",
      },
      new Set(),
    ),
    false,
  );
  const secret = `split-secret-${randomUUID()}`;
  const jwt =
    "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzYW5pdGl6ZXItdGVzdCJ9.c2lnbmF0dXJlLWZvci1zYW5pdGl6ZXI";
  const queryUrl =
    "https://issuer.example/oauth/authorize?code=must-not-escape#fragment";
  const wrappedInviteFragments = [
    "eyJ3cmFwcGVkLWhlYWRlci1zZW50aW5lbA",
    ".eyJ3cmFwcGVkLXBheWxvYWQtc2VudGluZWw",
    ".d3JhcHBlZC1zaWduYXR1cmUtc2VudGluZWw",
  ];
  const wrappedInviteBase = "http://localhost:9000/app/invite";
  const safeBoxUrl = "https://docs.example/medusa";
  const safeBoxRow = "Safe following row";
  const outsideBoxSentinel = "outside-base64url-sentinel";
  const boxTop = `┌${"─".repeat(78)}┐`;
  const boxBottom = `└${"─".repeat(78)}┘`;
  const newlineInviteBox = [
    `\u001b]0;invite-title\u0007\u001b[36m${boxTop}`,
    `│ ${wrappedInviteBase}?token=${wrappedInviteFragments[0]} │`,
    `│ ${wrappedInviteFragments[1]} │`,
    `│ ${wrappedInviteFragments[2]}&first_run=true │`,
    `│ ${safeBoxRow} ${safeBoxUrl} │`,
    `${boxBottom}\u001b[0m`,
    outsideBoxSentinel,
  ].join("\n");
  const cursorInviteBox = newlineInviteBox
    .split("\n")
    .slice(0, -1)
    .join("")
    .concat(`\n${outsideBoxSentinel}\n`);

  const sanitizeCollected = (value, oneByteChunks = false) => {
    let output = "";
    const collector = createSanitizedRecordCollector(
      (record, { forcedRedaction }) => {
        output += forcedRedaction ? record : sanitizeRuntimeLog(record);
      },
    );
    const bytes = Buffer.from(value, "utf8");
    if (oneByteChunks) {
      for (let index = 0; index < bytes.length; index += 1) {
        collector.write(bytes.subarray(index, index + 1));
      }
    } else {
      collector.write(bytes);
    }
    collector.end();
    return output;
  };
  const assertWrappedInviteSanitized = (output) => {
    assert.match(output, /http:\/\/localhost:9000\/app\/invite\?\[redacted\]/);
    for (const fragment of wrappedInviteFragments) {
      assert.equal(output.includes(fragment), false);
    }
    assert.match(output, new RegExp(safeBoxRow));
    assert.match(output, new RegExp(safeBoxUrl.replaceAll("/", "\\/")));
    assert.match(output, new RegExp(outsideBoxSentinel));
    assert.equal(output.includes("\u001b"), false);
    assert.doesNotMatch(output, /[\u0000-\u0008\u000b-\u001f\u007f]/);
  };
  assertWrappedInviteSanitized(sanitizeCollected(newlineInviteBox, true));
  assertWrappedInviteSanitized(sanitizeCollected(cursorInviteBox, true));
  assert.match(
    sanitizeCollected(
      `${boxTop}\n│ ${safeBoxUrl} │\n${boxBottom}\n${outsideBoxSentinel}\n`,
      true,
    ),
    new RegExp(`${safeBoxUrl.replaceAll("/", "\\/")}.*${outsideBoxSentinel}`, "s"),
  );
  const unterminatedBoxSentinel = "unterminated-box-secret-sentinel";
  const unterminatedOutput = sanitizeCollected(
    `${boxTop}\n│ ${wrappedInviteBase}?token=${unterminatedBoxSentinel}`,
    true,
  );
  assert.match(unterminatedOutput, /\[redacted unterminated terminal box\]/);
  assert.equal(unterminatedOutput.includes(unterminatedBoxSentinel), false);
  const oversizedBoxSentinel = "oversized-box-secret-sentinel";
  const oversizedOutput = sanitizeCollected(
    `${boxTop}\n│ ${wrappedInviteBase}?token=${oversizedBoxSentinel}${"A".repeat(MAX_TERMINAL_BOX_BYTES)}`,
  );
  assert.match(oversizedOutput, /\[redacted oversized terminal box\]/);
  assert.equal(oversizedOutput.includes(oversizedBoxSentinel), false);
  assert.equal(
    realSandboxOwnedEmails.has(
      `makepay-real-sandbox+${runId}2@example.com`.toLowerCase(),
    ),
    false,
  );
  assert.equal(
    realSandboxOwnedEmails.has(
      `makepay-real-sandbox+${runId}-installation-b@example.com`.toLowerCase(),
    ),
    true,
  );
  registerRuntimeSecret(secret);
  const root = await mkdtemp(join(tmpdir(), "makepay-sanitizer-e2e-"));
  temporaryRoot = root;
  let selfTestOAuthControl;
  let selfTestApiKeyControl;
  try {
    selfTestOAuthControl = await startMedusaControl({
      backendRoot: root,
      env: { DATABASE_URL: "postgresql://127.0.0.1/makepay_e2e_oauth" },
      profile: "oauth",
    });
    selfTestApiKeyControl = await startMedusaControl({
      backendRoot: root,
      env: { DATABASE_URL: "postgresql://127.0.0.1/makepay_e2e_api_key" },
      profile: "api-key",
    });
    assert.notEqual(
      selfTestOAuthControl.socketPath,
      selfTestApiKeyControl.socketPath,
    );
    assert.equal(
      (await stat(selfTestOAuthControl.socketPath)).mode & 0o777,
      0o600,
    );
    assert.equal(
      (await stat(selfTestApiKeyControl.socketPath)).mode & 0o777,
      0o600,
    );
    await assert.rejects(
      unixJsonRequest(selfTestOAuthControl.socketPath, "/control", {
        action: "snapshot",
      }),
      /restricted helper rejected the request/i,
    );
    await assert.rejects(
      unixJsonRequest(selfTestApiKeyControl.socketPath, "/control", {
        action: "unsupported",
      }),
      /restricted helper rejected the request/i,
    );
  } finally {
    const controlCleanup = await Promise.allSettled([
      selfTestOAuthControl?.close(),
      selfTestApiKeyControl?.close(),
    ]);
    const cleanupFailure = controlCleanup.find(
      (result) => result.status === "rejected",
    );
    if (cleanupFailure?.status === "rejected") {
      throw cleanupFailure.reason;
    }
  }
  const priorOwnedOutputRoot = ownedOutputRoot;
  const outputFixturePackage = join(root, "owned-output-package");
  await mkdir(outputFixturePackage, { mode: 0o700 });
  ownedOutputRoot = await initializeOwnedOutputRoot(outputFixturePackage);
  const ambientHome = join(root, "ambient-home");
  const priorAmbientSecret = process.env.MAKEPAY_FAKE_AMBIENT_SECRET;
  const priorHome = process.env.HOME;
  const priorNpmGlobalconfig = process.env.NPM_CONFIG_GLOBALCONFIG;
  const priorNpmToken = process.env.NPM_TOKEN;
  await mkdir(ambientHome, { mode: 0o700, recursive: true });
  await mkdir(join(root, "runtime-raw"), { mode: 0o700, recursive: true });
  await writeFile(join(ambientHome, ".npmrc"), `_authToken=${secret}\n`, {
    mode: 0o600,
  });
  const ambientGlobalconfig = join(ambientHome, "global.npmrc");
  await writeFile(
    ambientGlobalconfig,
    `registry=https://registry.invalid/sentinel/\n//registry.invalid/:_authToken=${secret}\n`,
    { mode: 0o600 },
  );
  process.env.HOME = ambientHome;
  process.env.MAKEPAY_FAKE_AMBIENT_SECRET = secret;
  process.env.NPM_CONFIG_GLOBALCONFIG = ambientGlobalconfig;
  process.env.NPM_TOKEN = secret;
  registerRuntimeSecret(ambientHome);
  await prepareIsolatedChildHome(root);
  assert.equal((await stat(isolatedChildHome)).mode & 0o777, 0o700);
  assert.equal((await stat(isolatedNpmGlobalconfig)).mode & 0o777, 0o600);
  assert.equal((await stat(isolatedNpmUserconfig)).mode & 0o777, 0o600);
  assert.equal(await readFile(isolatedNpmGlobalconfig, "utf8"), "");
  assert.equal(await readFile(isolatedNpmUserconfig, "utf8"), "");
  const npmRegistry = await run("npm", ["config", "get", "registry"], {
    capture: true,
  });
  assert.doesNotMatch(npmRegistry.stdout, /registry\.invalid|sentinel/i);
  assert.equal(npmRegistry.stdout.includes(secret), false);

  const projectNpmrcFixture = join(root, "project-npmrc-e2e");
  await mkdir(projectNpmrcFixture, { recursive: true });
  await writeFile(
    join(projectNpmrcFixture, ".npmrc"),
    `registry=https://registry.invalid/project-sentinel/\n_authToken=${secret}\n`,
  );
  await assert.rejects(() =>
    assertNoProjectNpmrc(projectNpmrcFixture, "Self-test project"),
  );
  const generatedNpmrcFixture = join(root, "generated-npmrc-e2e");
  await mkdir(generatedNpmrcFixture, { recursive: true });
  await writeFile(
    join(generatedNpmrcFixture, ".npmrc"),
    "auto-install-peers=true\n",
  );
  await removeKnownGeneratedProjectNpmrc(generatedNpmrcFixture);
  await assertNoProjectNpmrc(
    generatedNpmrcFixture,
    "Sanitized generated fixture",
  );
  const generatedWrongNpmrcFixture = join(root, "generated-wrong-npmrc-e2e");
  await mkdir(generatedWrongNpmrcFixture, { recursive: true });
  await writeFile(
    join(generatedWrongNpmrcFixture, ".npmrc"),
    "x".repeat(Buffer.byteLength("auto-install-peers=true\n")),
  );
  await assert.rejects(
    () => removeKnownGeneratedProjectNpmrc(generatedWrongNpmrcFixture),
    /reviewed inert template file/,
  );
  const generatedSymlinkNpmrcFixture = join(
    root,
    "generated-symlink-npmrc-e2e",
  );
  await mkdir(generatedSymlinkNpmrcFixture, { recursive: true });
  await symlink(packageRoot, join(generatedSymlinkNpmrcFixture, ".npmrc"));
  await assert.rejects(
    () => removeKnownGeneratedProjectNpmrc(generatedSymlinkNpmrcFixture),
    /reviewed inert template file/,
  );

  assert.equal(
    pathIsStrictlyInside("/tmp/makepay-e2e", "/tmp/makepay-e2e-escape"),
    false,
  );
  const symlinkGuardRoot = join(root, "symlink-project-guard");
  await mkdir(symlinkGuardRoot, { recursive: true });
  const symlinkProject = join(symlinkGuardRoot, "project-e2e-link");
  await symlink(packageRoot, symlinkProject);
  assert.equal(
    pathIsStrictlyInside(
      await realpath(tmpdir()),
      await realpath(symlinkProject),
    ),
    false,
  );
  const safeFixtureManifests = {
    backend: {
      dependencies: {
        "@medusajs/cli": "2.17.2",
        "@medusajs/framework": "2.17.2",
        "@medusajs/medusa": "2.17.2",
      },
      name: "@dtc/backend",
      scripts: {},
    },
    root: {
      name: "medusa-app",
      scripts: {},
      workspaces: ["apps/**", "!apps/backend/.medusa/**"],
    },
    storefront: {
      dependencies: { "@medusajs/js-sdk": "2.17.2" },
      name: "@dtc/storefront",
      scripts: {},
    },
  };
  validateMedusaFixtureManifests(safeFixtureManifests);
  assert.throws(() =>
    validateMedusaFixtureManifests({
      ...safeFixtureManifests,
      backend: {
        ...safeFixtureManifests.backend,
        scripts: { postinstall: "touch /tmp/makepay-must-not-run" },
      },
    }),
  );

  const sdkFixtureEntries = [
    "package/LICENSE",
    "package/README.md",
    "package/dist/index.d.ts",
    "package/dist/index.js",
    "package/package.json",
  ].map((path) => ({ body: path, path }));
  const validSdkArchive = tarFixture(sdkFixtureEntries);
  inspectArtifactArchive(
    validSdkArchive,
    "@makecrypto/makepay",
    "Valid SDK fixture",
  );
  for (const path of [
    "package/../escape",
    "/package/escape",
    "package\\escape",
  ]) {
    assert.throws(() =>
      inspectArtifactArchive(
        tarFixture([{ body: "unsafe", path }]),
        "@makecrypto/makepay",
        "Unsafe path fixture",
      ),
    );
  }
  for (const type of ["1", "2", "3", "4", "6"]) {
    assert.throws(() =>
      inspectArtifactArchive(
        tarFixture([
          {
            linkName: type === "1" || type === "2" ? "package/LICENSE" : "",
            path: "package/LICENSE",
            type,
          },
        ]),
        "@makecrypto/makepay",
        "Nonregular fixture",
      ),
    );
  }
  assert.throws(() =>
    inspectArtifactArchive(
      tarFixture([{ path: "package/LICENSE" }, { path: "package/LICENSE" }]),
      "@makecrypto/makepay",
      "Duplicate fixture",
    ),
  );
  assert.throws(() =>
    inspectArtifactArchive(
      tarFixture([
        { path: "package/README.md" },
        { path: "package/readme.md" },
      ]),
      "@makecrypto/makepay",
      "Case collision fixture",
    ),
  );
  assert.throws(() =>
    inspectArtifactArchive(
      tarFixture([...sdkFixtureEntries, { path: "package/unexpected.js" }]),
      "@makecrypto/makepay",
      "Unexpected entry fixture",
    ),
  );
  assert.throws(() =>
    inspectArtifactArchive(
      tarFixture(sdkFixtureEntries.slice(1)),
      "@makecrypto/makepay",
      "Missing entry fixture",
    ),
  );
  assert.throws(() =>
    inspectArtifactArchive(
      tarFixture([
        {
          declaredSize: 16 * 1024 * 1024 + 1,
          path: "package/LICENSE",
        },
      ]),
      "@makecrypto/makepay",
      "Oversized fixture",
    ),
  );
  for (const mode of [0o755, 0o666, 0o4644]) {
    assert.throws(() =>
      inspectArtifactArchive(
        tarFixture([{ mode, path: "package/LICENSE" }]),
        "@makecrypto/makepay",
        "Unsafe mode fixture",
      ),
    );
  }
  const corruptTar = gunzipSync(validSdkArchive);
  corruptTar[0] ^= 1;
  assert.throws(() =>
    inspectArtifactArchive(
      gzipSync(corruptTar),
      "@makecrypto/makepay",
      "Checksum fixture",
    ),
  );
  assert.throws(() =>
    inspectArtifactArchive(
      gzipSync(Buffer.concat([gunzipSync(validSdkArchive), Buffer.from([1])])),
      "@makecrypto/makepay",
      "Trailing data fixture",
    ),
  );
  const traversalSentinel = join(root, "archive-must-not-escape.txt");
  assert.equal(await pathExists(traversalSentinel), false);

  const mutableArtifact = join(root, "mutable-artifact.tgz");
  const trustedArtifactBytes = Buffer.from("trusted-artifact-bytes");
  const trustedArtifactHash = sha256Bytes(trustedArtifactBytes);
  await writeFile(mutableArtifact, trustedArtifactBytes);
  const privateArtifact = await snapshotArtifactBytes({
    expectedSha256: trustedArtifactHash,
    label: "Artifact swap self-test",
    privateRoot: root,
    source: mutableArtifact,
  });
  await writeFile(mutableArtifact, "source-path-was-swapped");
  await assertPrivateArtifactCopy(
    privateArtifact.privatePath,
    trustedArtifactHash,
    "Artifact swap self-test",
  );
  const replacementArtifact = join(root, "replacement-artifact.tgz");
  await writeFile(replacementArtifact, "replaced-private-copy", {
    mode: 0o400,
  });
  await rename(replacementArtifact, privateArtifact.privatePath);
  await assert.rejects(() =>
    assertPrivateArtifactCopy(
      privateArtifact.privatePath,
      trustedArtifactHash,
      "Artifact swap self-test",
    ),
  );
  for (const value of [
    "postgresql://localhost/makepay_e2e?host=/tmp/override",
    "postgresql://localhost/makepay_e2e?hostaddr=203.0.113.10",
    "postgresql://localhost/makepay_e2e?dbname=production",
    "postgresql://localhost/makepay_e2e?service=production",
    "postgresql://localhost/makepay_e2e#host=remote",
  ]) {
    assert.throws(() => assertE2EDatabaseUrl(value, "SELF_TEST_DATABASE"));
  }
  assert.match(
    assertE2EDatabaseUrl(
      "postgresql://localhost/makepay_e2e_sanitizer",
      "SELF_TEST_DATABASE",
    ),
    /makepay_e2e_sanitizer/,
  );
  const unsafeEvidenceDirectory = join(root, "unrelated-e2e-evidence");
  const unsafeEvidenceSentinel = join(unsafeEvidenceDirectory, "keep.txt");
  await mkdir(unsafeEvidenceDirectory, { recursive: true });
  await writeFile(unsafeEvidenceSentinel, "keep");
  await assert.rejects(() => resetEvidenceDirectory(unsafeEvidenceDirectory));
  assert.equal(await readFile(unsafeEvidenceSentinel, "utf8"), "keep");

  const ownedRuntimeRelative = "runtime/medusa-e2e-output-self-test";
  const ownedRuntime = await prepareOwnedOutputPath(
    ownedOutputRoot,
    ownedRuntimeRelative,
  );
  await writeFile(join(ownedRuntime, "replace.txt"), "replace");
  await prepareOwnedOutputPath(ownedOutputRoot, ownedRuntimeRelative);
  assert.equal(await pathExists(join(ownedRuntime, "replace.txt")), false);

  const externalRuntime = join(root, "external-runtime-sentinel");
  const externalRuntimeLeaf = join(
    externalRuntime,
    "medusa-e2e-symlink-sentinel",
  );
  const externalRuntimeSentinel = join(externalRuntimeLeaf, "keep.txt");
  await mkdir(externalRuntimeLeaf, { recursive: true });
  await writeFile(externalRuntimeSentinel, "keep");
  await rm(join(ownedOutputRoot, "runtime"), {
    force: true,
    recursive: true,
  });
  await symlink(externalRuntime, join(ownedOutputRoot, "runtime"));
  await assert.rejects(() =>
    prepareOwnedOutputPath(
      ownedOutputRoot,
      "runtime/medusa-e2e-symlink-sentinel",
    ),
  );
  assert.equal(await readFile(externalRuntimeSentinel, "utf8"), "keep");
  await rm(join(ownedOutputRoot, "runtime"), { force: true });

  const externalEvidence = join(root, "external-evidence-sentinel");
  const externalEvidenceSentinel = join(externalEvidence, "keep.txt");
  await mkdir(externalEvidence, { recursive: true });
  await writeFile(externalEvidenceSentinel, "keep");
  await symlink(externalEvidence, join(ownedOutputRoot, "evidence"));
  await assert.rejects(() =>
    resetEvidenceDirectory(join(ownedOutputRoot, "evidence")),
  );
  assert.equal(await readFile(externalEvidenceSentinel, "utf8"), "keep");
  await rm(join(ownedOutputRoot, "evidence"), { force: true });

  for (const [index, relativeSymlink] of [
    "output",
    "output/playwright",
    "output/playwright/medusa-makepay",
  ].entries()) {
    const packageFixture = join(root, `output-ancestor-package-${index}`);
    const external = join(root, `output-ancestor-external-${index}`);
    const sentinel = join(external, "keep.txt");
    const symlinkPath = join(packageFixture, relativeSymlink);
    await mkdir(dirname(symlinkPath), { recursive: true });
    await mkdir(external, { recursive: true });
    await writeFile(sentinel, "keep");
    await symlink(external, symlinkPath);
    await assert.rejects(() => initializeOwnedOutputRoot(packageFixture));
    assert.equal(await readFile(sentinel, "utf8"), "keep");
  }

  const publicationRuntime = await prepareOwnedOutputPath(
    ownedOutputRoot,
    "runtime/medusa-e2e-publication-self-test",
  );
  const externalLog = join(root, "external-publication.log");
  await writeFile(externalLog, "keep");
  await symlink(externalLog, join(publicationRuntime, "danger.log"));
  const symlinkRawDirectory = join(root, "raw-publication-symlink");
  await mkdir(symlinkRawDirectory, { recursive: true });
  await writeFile(join(symlinkRawDirectory, "danger.log"), "safe");
  await assert.rejects(() =>
    publishSanitizedRuntimeLogs({
      destinationDirectory: publicationRuntime,
      outputRoot: ownedOutputRoot,
      rawDirectory: symlinkRawDirectory,
    }),
  );
  assert.equal(await readFile(externalLog, "utf8"), "keep");
  assert.equal(await pathExists(symlinkRawDirectory), false);
  await rm(join(publicationRuntime, "danger.log"), { force: true });

  const wrappedRawDirectory = join(root, "raw-publication-wrapped-invite");
  await mkdir(wrappedRawDirectory, { mode: 0o700 });
  await writeFile(
    join(wrappedRawDirectory, "wrapped-invite.log"),
    newlineInviteBox,
    { mode: 0o600 },
  );
  await publishSanitizedRuntimeLogs({
    destinationDirectory: publicationRuntime,
    outputRoot: ownedOutputRoot,
    rawDirectory: wrappedRawDirectory,
  });
  const publishedWrappedInvite = await readFile(
    join(publicationRuntime, "wrapped-invite.log"),
    "utf8",
  );
  assertWrappedInviteSanitized(publishedWrappedInvite);
  assert.equal(await pathExists(wrappedRawDirectory), false);

  const rawFailureDirectory = join(root, "raw-publication-failure");
  const destinationBlocker = join(root, "destination-is-a-file");
  await mkdir(rawFailureDirectory, { recursive: true });
  await writeFile(join(rawFailureDirectory, "secret.log"), secret, {
    mode: 0o600,
  });
  await writeFile(destinationBlocker, "not a directory");
  await assert.rejects(() =>
    publishSanitizedRuntimeLogs({
      destinationDirectory: destinationBlocker,
      rawDirectory: rawFailureDirectory,
    }),
  );
  await assert.rejects(() => stat(rawFailureDirectory), { code: "ENOENT" });

  const isolationProgram = [
    'const fs = require("node:fs");',
    "if (process.env.NPM_TOKEN || process.env.MAKEPAY_FAKE_AMBIENT_SECRET) process.exit(21);",
    'const npmrc = fs.readFileSync(`${process.env.HOME}/.npmrc`, "utf8");',
    'if (npmrc.includes("_authToken") || process.env.HOME === process.env.AMBIENT_HOME) process.exit(22);',
    'process.stdout.write("isolated-home\\n");',
  ].join("\n");
  const foregroundIsolation = await run(
    process.execPath,
    ["-e", isolationProgram],
    { capture: true },
  );
  assert.match(foregroundIsolation.stdout, /isolated-home/);
  const synchronousIsolation = spawnSync(
    process.execPath,
    ["-e", isolationProgram],
    {
      cwd: packageRoot,
      encoding: "utf8",
      env: childEnvironment({ AMBIENT_HOME: ambientHome }),
    },
  );
  assert.equal(synchronousIsolation.status, 0);
  assert.match(synchronousIsolation.stdout, /isolated-home/);
  const childProgram = [
    "const secret = process.env.SPLIT_SECRET;",
    "const decorated = `${secret.slice(0, 5)}\\u001b[31m${secret.slice(5, 8)}\\u0001${secret.slice(8, 11)}\\r\\u001b]0;ignored\\u0007${secret.slice(11)}\\u001b[0m`;",
    "const hyperlink = `\\u001b]8;;https://issuer.example/oauth/authorize?state=${secret}\\u0007safe-link\\u001b]8;;\\u0007`;",
    `const wrappedInvite = ${JSON.stringify(cursorInviteBox)};`,
    "const value = `${decorated} ${hyperlink} https://issuer.example/oauth/authorize?code=must-not-escape#fragment eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzYW5pdGl6ZXItdGVzdCJ9.c2lnbmF0dXJlLWZvci1zYW5pdGl6ZXI\\n${wrappedInvite}`;",
    "process.stdout.write(value.slice(0, 11));",
    "setTimeout(() => process.stdout.write(value.slice(11, 37)), 5);",
    "setTimeout(() => process.stdout.write(`${value.slice(37)}\\n`), 10);",
  ].join("\n");
  let commandOutput = "";
  const originalWrite = process.stdout.write;
  process.stdout.write = function captureWrite(chunk, encoding, callback) {
    commandOutput += String(chunk);
    if (typeof encoding === "function") encoding();
    else if (typeof callback === "function") callback();
    return true;
  };
  let captured;
  try {
    log(`direct ${secret} ${queryUrl} ${jwt} api_key=${secret}`);
    captured = await run(
      process.execPath,
      ["-e", childProgram, "--", `--token=${secret}`],
      {
        capture: true,
        env: { SPLIT_SECRET: secret },
      },
    );
  } finally {
    process.stdout.write = originalWrite;
  }
  assert.equal(commandOutput.includes(secret), false);
  assert.equal(commandOutput.includes("must-not-escape"), false);
  assert.equal(commandOutput.includes("#fragment"), false);
  assert.equal(commandOutput.includes(jwt), false);
  assert.match(commandOutput, /\[redacted\]/);
  assert.equal(captured.stdout.includes(secret), false);
  assert.equal(captured.stdout.includes("must-not-escape"), false);
  assert.equal(captured.stdout.includes("#fragment"), false);
  assert.equal(captured.stdout.includes(jwt), false);
  for (const fragment of wrappedInviteFragments) {
    assert.equal(captured.stdout.includes(fragment), false);
  }
  assert.match(captured.stdout, new RegExp(safeBoxRow));
  assert.match(captured.stdout, new RegExp(outsideBoxSentinel));
  assert.equal(captured.stdout.includes("\u001b"), false);
  assert.doesNotMatch(captured.stdout, /[\u0000-\u0008\u000b-\u001f\u007f]/);
  assert.match(captured.stdout, /\[redacted\]/);
  assert.match(captured.stdout, /\[redacted-jwt\]/);

  const failingProgram = [
    "const secret = process.env.SPLIT_SECRET;",
    "const decorated = `${secret.slice(0, 5)}\\u001b[31m${secret.slice(5, 8)}\\u0001${secret.slice(8, 11)}\\r${secret.slice(11)}\\u001b[0m`;",
    "const hyperlink = `\\u001b]8;;https://issuer.example/oauth/authorize?state=${secret}\\u0007safe-link\\u001b]8;;\\u0007`;",
    `const wrappedInvite = ${JSON.stringify(cursorInviteBox)};`,
    "const value = `${decorated} ${hyperlink} https://issuer.example/oauth/authorize?code=must-not-escape#fragment eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzYW5pdGl6ZXItdGVzdCJ9.c2lnbmF0dXJlLWZvci1zYW5pdGl6ZXI\\n${wrappedInvite}`;",
    "process.stderr.write(value.slice(0, 13));",
    "setTimeout(() => process.stderr.write(value.slice(13, 41)), 5);",
    "setTimeout(() => { process.stderr.write(value.slice(41)); process.exitCode = 7; }, 10);",
  ].join("\n");
  let failureMessage = "";
  try {
    await run(process.execPath, ["-e", failingProgram], {
      capture: true,
      env: { SPLIT_SECRET: secret },
    });
    assert.fail("The failing sanitizer child unexpectedly passed.");
  } catch (error) {
    failureMessage = String(error?.message || error);
  }
  assert.equal(failureMessage.includes(secret), false);
  assert.equal(failureMessage.includes("must-not-escape"), false);
  assert.equal(failureMessage.includes("#fragment"), false);
  assert.equal(failureMessage.includes(jwt), false);
  for (const fragment of wrappedInviteFragments) {
    assert.equal(failureMessage.includes(fragment), false);
  }
  assert.match(failureMessage, new RegExp(safeBoxRow));
  assert.match(failureMessage, new RegExp(outsideBoxSentinel));
  assert.equal(failureMessage.includes("\u001b"), false);
  assert.doesNotMatch(failureMessage, /[\u0000-\u0008\u000b-\u001f\u007f]/);
  assert.match(failureMessage, /\[redacted\]/);

  const logPath = join(root, "child.log");
  {
    const backgroundProgram = `${isolationProgram}\n${childProgram}`;
    const child = await startProcess(
      process.execPath,
      ["-e", backgroundProgram],
      {
        cwd: packageRoot,
        env: { AMBIENT_HOME: ambientHome, SPLIT_SECRET: secret },
        logPath,
      },
    );
    await new Promise((resolvePromise, reject) => {
      child.once("error", reject);
      child.once("close", resolvePromise);
    });
    await child.makePayOutputClosed;
    const retained = await readFile(logPath, "utf8");
    assert.equal((await stat(logPath)).mode & 0o777, 0o600);
    assert.match(retained, /isolated-home/);
    assert.equal(retained.includes(secret), false);
    assert.equal(retained.includes("must-not-escape"), false);
    assert.equal(retained.includes("#fragment"), false);
    assert.equal(retained.includes(jwt), false);
    for (const fragment of wrappedInviteFragments) {
      assert.equal(retained.includes(fragment), false);
    }
    assert.match(retained, new RegExp(safeBoxRow));
    assert.match(retained, new RegExp(outsideBoxSentinel));
    assert.equal(retained.includes("\u001b"), false);
    assert.doesNotMatch(retained, /[\u0000-\u0008\u000b-\u001f\u007f]/);
    assert.match(retained, /\[redacted\]/);
    assert.match(retained, /\[redacted-jwt\]/);
  }

  const diagnostics = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `import(${JSON.stringify(join(packageRoot, "tests/e2e/playwright.config.mjs"))})`,
    ],
    {
      cwd: packageRoot,
      encoding: "utf8",
      env: childEnvironment({
        CI: "true",
        MAKEPAY_E2E_LOCAL_DIAGNOSTICS: "1",
        MAKEPAY_E2E_TEST_MATCH: "medusa-storefront.spec.mjs",
      }),
    },
  );
  assert.notEqual(diagnostics.status, 0);
  const diagnosticsOutput = sanitizeRuntimeLog(
    `${diagnostics.stdout || ""}${diagnostics.stderr || ""}`,
  );
  assert.match(diagnosticsOutput, /forbidden when CI is set/i);
  const wildcardReal = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `import(${JSON.stringify(join(packageRoot, "tests/e2e/playwright.config.mjs"))})`,
    ],
    {
      cwd: packageRoot,
      encoding: "utf8",
      env: childEnvironment({
        MAKEPAY_E2E_LOCAL_DIAGNOSTICS: "1",
        MAKEPAY_E2E_REAL_SANDBOX: "1",
        MAKEPAY_E2E_TEST_MATCH: "**/real-sandbox.spec.mjs",
      }),
    },
  );
  assert.notEqual(wildcardReal.status, 0);
  assert.match(
    sanitizeRuntimeLog(
      `${wildcardReal.stdout || ""}${wildcardReal.stderr || ""}`,
    ),
    /exact allowed filename/i,
  );
  const exactRealDiagnostics = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `import(${JSON.stringify(join(packageRoot, "tests/e2e/playwright.config.mjs"))})`,
    ],
    {
      cwd: packageRoot,
      encoding: "utf8",
      env: childEnvironment({
        CI: "",
        MAKEPAY_E2E_LOCAL_DIAGNOSTICS: "1",
        MAKEPAY_E2E_REAL_SANDBOX: "1",
        MAKEPAY_E2E_TEST_MATCH: "real-sandbox.spec.mjs",
      }),
    },
  );
  assert.notEqual(exactRealDiagnostics.status, 0);
  assert.match(
    sanitizeRuntimeLog(
      `${exactRealDiagnostics.stdout || ""}${exactRealDiagnostics.stderr || ""}`,
    ),
    /disabled for the real OAuth sandbox/i,
  );
  const temporaryPlaywrightReceipt = join(
    root,
    "playwright-completion.json",
  );
  const temporaryRealConfig = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `const config = (await import(${JSON.stringify(join(packageRoot, "tests/e2e/playwright.config.mjs"))})).default; process.stdout.write(config.outputDir);`,
    ],
    {
      cwd: packageRoot,
      encoding: "utf8",
      env: childEnvironment({
        MAKEPAY_E2E_PLAYWRIGHT_COMPLETION_RECEIPT:
          temporaryPlaywrightReceipt,
        MAKEPAY_E2E_REAL_SANDBOX: "1",
        MAKEPAY_E2E_TEST_MATCH: "real-sandbox.spec.mjs",
      }),
    },
  );
  assert.equal(temporaryRealConfig.status, 0);
  const expectedTemporaryResults = join(
    await realpath(root),
    "playwright-results",
  );
  assert.equal(temporaryRealConfig.stdout, expectedTemporaryResults);
  assert.equal(
    pathIsStrictlyInside(packageRoot, expectedTemporaryResults),
    false,
  );

  for (const invalidReceipt of ["", "relative-playwright-receipt.json"]) {
    const invalidReceiptConfig = spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `import(${JSON.stringify(join(packageRoot, "tests/e2e/playwright.config.mjs"))})`,
      ],
      {
        cwd: packageRoot,
        encoding: "utf8",
        env: childEnvironment({
          MAKEPAY_E2E_PLAYWRIGHT_COMPLETION_RECEIPT: invalidReceipt,
          MAKEPAY_E2E_REAL_SANDBOX: "1",
          MAKEPAY_E2E_TEST_MATCH: "real-sandbox.spec.mjs",
        }),
      },
    );
    assert.notEqual(invalidReceiptConfig.status, 0);
    assert.match(
      sanitizeRuntimeLog(
        `${invalidReceiptConfig.stdout || ""}${invalidReceiptConfig.stderr || ""}`,
      ),
      /absolute parent-owned completion receipt/i,
    );
  }

  const priorPlaywrightReceiptPath = playwrightCompletionReceiptPath;
  const priorPlaywrightResultsPath = realSandboxPlaywrightResultsPath;
  playwrightCompletionReceiptPath = temporaryPlaywrightReceipt;
  realSandboxPlaywrightResultsPath = expectedTemporaryResults;
  await mkdir(realSandboxPlaywrightResultsPath, {
    mode: 0o700,
    recursive: true,
  });
  const oauthArtifactSentinel = `oauth-state-${randomUUID()}`;
  await Promise.all([
    writeFile(playwrightCompletionReceiptPath, '{"accepted":false}\n', {
      mode: 0o600,
    }),
    writeFile(
      join(realSandboxPlaywrightResultsPath, "error-context.md"),
      `https://issuer.example/oauth/authorize?state=${oauthArtifactSentinel}\n`,
      { mode: 0o600 },
    ),
  ]);
  await scrubPlaywrightArtifacts();
  assert.equal(await pathExists(playwrightCompletionReceiptPath), false);
  assert.equal(await pathExists(realSandboxPlaywrightResultsPath), false);
  assert.equal(await pathExists(root), true);
  playwrightCompletionReceiptPath = priorPlaywrightReceiptPath;
  realSandboxPlaywrightResultsPath = priorPlaywrightResultsPath;

  for (const signalStage of [
    "manual-consent",
    "post-connect",
    "post-link",
    "webhook",
  ]) {
    const events = [];
    const state = {
      connected: signalStage !== "manual-consent",
      linkActive: signalStage === "post-link" || signalStage === "webhook",
      mutatorActive: true,
      pendingRegistration: signalStage === "manual-consent",
      servicesActive: true,
    };
    const passed = await settleCleanupStages(
      orderedMutationCleanupStages({
        quiesce: async () => {
          events.push("quiesce");
          state.mutatorActive = false;
        },
        remoteCleanup: async () => {
          events.push("remote");
          assert.equal(state.mutatorActive, false);
          assert.equal(state.servicesActive, true);
          state.linkActive = false;
          state.connected = false;
          state.pendingRegistration = false;
        },
        terminate: async () => {
          events.push("terminate");
          assert.equal(state.linkActive, false);
          assert.equal(state.connected, false);
          assert.equal(state.pendingRegistration, false);
          state.servicesActive = false;
        },
      }),
      { report: false },
    );
    assert.equal(passed, true);
    assert.deepEqual(events, ["quiesce", "remote", "terminate"]);
  }

  {
    const events = [];
    const passed = await settleCleanupStages(
      orderedMutationCleanupStages({
        quiesce: async () => {
          events.push("quiesce-failed");
          throw new Error("injected quiesce failure");
        },
        remoteCleanup: async () => events.push("unsafe-remote"),
        terminate: async () => events.push("terminate"),
      }),
      { report: false },
    );
    assert.equal(passed, false);
    assert.deepEqual(events, ["quiesce-failed", "terminate"]);
  }

  await runSignalWorkerMatrix(root);

  const delayedMutationSentinel = join(root, "delayed-mutation.txt");
  const delayedMutationLog = join(root, "delayed-mutation.log");
  await startProcess(
    process.execPath,
    [
      "-e",
      'const fs = require("node:fs"); setTimeout(() => fs.writeFileSync(process.argv[1], "late"), 1200); setInterval(() => {}, 1000);',
      delayedMutationSentinel,
    ],
    {
      cwd: root,
      env: {},
      logPath: delayedMutationLog,
      mutator: true,
    },
  );
  await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
  await quiesceForegroundWork();
  await new Promise((resolvePromise) => setTimeout(resolvePromise, 1_300));
  assert.equal(await pathExists(delayedMutationSentinel), false);
  await assert.rejects(() =>
    run(process.execPath, ["-e", 'process.stdout.write("unsafe")'], {
      capture: true,
    }),
  );
  const cleanupCommand = await run(
    process.execPath,
    ["-e", 'process.stdout.write("cleanup-ok")'],
    { capture: true, cleanup: true, timeoutMs: 2_000 },
  );
  assert.equal(cleanupCommand.stdout, "cleanup-ok");
  await assert.rejects(() =>
    run(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
      capture: true,
      cleanup: true,
      timeoutMs: 250,
    }),
  );
  actionsQuiesced = false;

  const cleanupMarkers = [];
  assert.equal(
    await settleCleanupStages(
      [
        ["injected failure", async () => Promise.reject(new Error(secret))],
        ["required scrub", async () => cleanupMarkers.push("scrubbed")],
        ["required removal", async () => cleanupMarkers.push("removed")],
      ],
      { report: false },
    ),
    false,
  );
  assert.deepEqual(cleanupMarkers, ["scrubbed", "removed"]);
  const postgresCleanupMarkers = [];
  const postgresCleanupPassed = await settleCleanupStages(
    [
      [
        "PostgreSQL clusters",
        async () => {
          const results = await Promise.allSettled([
            stopPostgres({
              dataDirectory: join(root, "missing-postgres-data"),
              external: false,
              pgCtl: process.execPath,
            }),
            (async () => {
              postgresCleanupMarkers.push("second-stop-attempted");
              await stopPostgres({ external: true });
            })(),
          ]);
          const rejected = results.find(
            (result) => result.status === "rejected",
          );
          if (rejected?.status === "rejected") throw rejected.reason;
          disposablePostgresRemovalSafe = true;
        },
      ],
      [
        "Secret-file scrub",
        async () => postgresCleanupMarkers.push("scrubbed"),
      ],
      [
        "Temporary workspace removal",
        async () => postgresCleanupMarkers.push("removed"),
      ],
    ],
    { report: false },
  );
  const simulatedCleanupExitCode = postgresCleanupPassed ? 0 : 1;
  assert.equal(simulatedCleanupExitCode, 1);
  assert.deepEqual(postgresCleanupMarkers, [
    "second-stop-attempted",
    "scrubbed",
    "removed",
  ]);
  if (priorAmbientSecret === undefined)
    delete process.env.MAKEPAY_FAKE_AMBIENT_SECRET;
  else process.env.MAKEPAY_FAKE_AMBIENT_SECRET = priorAmbientSecret;
  if (priorNpmToken === undefined) delete process.env.NPM_TOKEN;
  else process.env.NPM_TOKEN = priorNpmToken;
  if (priorNpmGlobalconfig === undefined)
    delete process.env.NPM_CONFIG_GLOBALCONFIG;
  else process.env.NPM_CONFIG_GLOBALCONFIG = priorNpmGlobalconfig;
  if (priorHome === undefined) delete process.env.HOME;
  else process.env.HOME = priorHome;
  ownedOutputRoot = priorOwnedOutputRoot;
  log(
    "Sanitizer, child isolation, DB/deletion guards, cleanup continuation, and Playwright diagnostics guards passed.",
  );
}

async function main() {
  assertBrowserRunMode();
  if (localDiagnostics && process.env.CI) {
    throw new Error("--local-diagnostics is forbidden when CI is set.");
  }
  const realSandboxLogin = realSandbox
    ? await assertRealSandboxGuard()
    : { manualOAuth: false, storageState: "" };
  const backendPort = Number(process.env.MAKEPAY_E2E_BACKEND_PORT || 9000);
  const secondBackendPort = Number(
    process.env.MAKEPAY_E2E_SECOND_BACKEND_PORT || 9001,
  );
  const apiKeyBackendPort = Number(
    process.env.MAKEPAY_E2E_API_KEY_BACKEND_PORT || 9002,
  );
  const storefrontPort = Number(
    process.env.MAKEPAY_E2E_STOREFRONT_PORT || 8000,
  );
  const requiredPorts = realSandbox
    ? [backendPort, secondBackendPort, storefrontPort]
    : [backendPort, secondBackendPort, apiKeyBackendPort, storefrontPort];
  if (
    !requiredPorts.every(
      (port) => Number.isInteger(port) && port > 0 && port <= 65535,
    ) ||
    new Set(requiredPorts).size !== requiredPorts.length
  ) {
    throw new Error(
      "All requested Medusa backend and storefront ports must be distinct valid TCP ports.",
    );
  }
  await assertServicePortsAvailable(requiredPorts);
  ownedOutputRoot = await initializeOwnedOutputRoot(packageRoot);
  await prepareOwnedOutputPath(ownedOutputRoot, `runtime/${runId}`);
  if (!localDiagnostics) {
    await Promise.all([
      prepareOwnedOutputPath(ownedOutputRoot, "results", {
        recreate: false,
      }),
      prepareOwnedOutputPath(ownedOutputRoot, "report", {
        recreate: false,
      }),
    ]);
  }
  temporaryRoot = await mkdtemp(join(tmpdir(), "makepay-medusa-e2e-"));
  if (realSandbox || captureRequested) {
    playwrightCompletionReceiptPath = join(
      temporaryRoot,
      "playwright-completion.json",
    );
    registerRuntimeSecret(playwrightCompletionReceiptPath);
  }
  if (realSandbox) {
    realSandboxPlaywrightResultsPath = join(
      temporaryRoot,
      "playwright-results",
    );
    await mkdir(realSandboxPlaywrightResultsPath, {
      mode: 0o700,
      recursive: true,
    });
    await chmod(realSandboxPlaywrightResultsPath, 0o700);
    registerRuntimeSecret(realSandboxPlaywrightResultsPath);
  }
  await mkdir(join(temporaryRoot, "runtime-raw"), {
    mode: 0o700,
    recursive: true,
  });
  await prepareIsolatedChildHome(temporaryRoot, {
    allowExternalNpmCache: true,
  });
  await assertNoProjectNpmrc(packageRoot, "The plugin workspace");
  log(`Run ID: ${runId}`);
  log(`Temporary workspace: ${temporaryRoot}`);
  postgres = await startPostgres(temporaryRoot, { installation: "a" });
  const primaryIdentity = await physicalDatabaseIdentity(postgres.databaseUrl);
  if (realSandbox) {
    secondPostgres = await startPostgres(temporaryRoot, {
      databaseEnvName: "MAKEPAY_E2E_SECOND_DATABASE_URL",
      installation: "b",
    });
    const secondaryIdentity = await physicalDatabaseIdentity(
      secondPostgres.databaseUrl,
    );
    if (primaryIdentity === secondaryIdentity) {
      throw new Error(
        "Real-sandbox installations A and B must use distinct databases.",
      );
    }
  } else {
    apiKeyPostgres = await startPostgres(temporaryRoot, {
      databaseEnvName: "MAKEPAY_E2E_API_KEY_DATABASE_URL",
      installation: "api_key",
    });
    const apiKeyIdentity = await physicalDatabaseIdentity(
      apiKeyPostgres.databaseUrl,
    );
    if (primaryIdentity === apiKeyIdentity) {
      throw new Error(
        "OAuth and API-key deterministic installations must use distinct databases.",
      );
    }
    if (apiKeyPostgres.external) {
      await assertExternalDatabaseEmpty(
        apiKeyPostgres.databaseUrl,
        "API-key E2E",
      );
    }
  }
  const pluginArtifact = await packPlugin(temporaryRoot);
  const projectRoot = await scaffoldProject(
    temporaryRoot,
    postgres.databaseUrl,
  );
  activeProjectRoot = projectRoot;
  activeProjectOwned = true;
  const artifactProvenance = await installAndPatch(projectRoot, pluginArtifact);

  await assertServicePortsAvailable(requiredPorts);
  const backendUrl = `http://127.0.0.1:${backendPort}`;
  const secondBackendUrl = `http://127.0.0.1:${secondBackendPort}`;
  const apiKeyBackendUrl = `http://127.0.0.1:${apiKeyBackendPort}`;
  const storefrontUrl = `http://127.0.0.1:${storefrontPort}`;

  let backendPublicUrl = backendUrl;
  let secondBackendPublicUrl = secondBackendUrl;
  let storefrontPublicUrl = storefrontUrl;
  let makePayApiUrl;
  let makePayCheckoutUrl;
  let oauthIssuerUrl;
  if (realSandbox) {
    backendPublicUrl = await startQuickTunnel(
      backendPort,
      temporaryRoot,
      "backend",
    );
    secondBackendPublicUrl = await startQuickTunnel(
      secondBackendPort,
      temporaryRoot,
      "backend-installation-b",
    );
    storefrontPublicUrl = await startQuickTunnel(
      storefrontPort,
      temporaryRoot,
      "storefront",
    );
    makePayApiUrl = process.env.MAKEPAY_E2E_REAL_API_URL;
    makePayCheckoutUrl = process.env.MAKEPAY_E2E_REAL_CHECKOUT_URL;
    oauthIssuerUrl = process.env.MAKEPAY_E2E_REAL_OAUTH_ISSUER_URL;
    registerRuntimeSecret(backendPublicUrl);
    registerRuntimeSecret(secondBackendPublicUrl);
    registerRuntimeSecret(storefrontPublicUrl);
  } else {
    const tls = await createLocalTlsCertificate(temporaryRoot);
    contractCaPath = tls.certPath;
    contract = createMakePayContractServer({
      controlToken,
      tls: { cert: tls.cert, key: tls.key },
    });
    await contract.start();
    makePayApiUrl = contract.origin;
    makePayCheckoutUrl = contract.origin;
    oauthIssuerUrl = contract.origin;
  }

  const loopbackInsecureCookieOverride = realSandbox ? "0" : "1";
  const runtimeEnv = {
    DATABASE_URL: postgres.databaseUrl,
    MAKEPAY_E2E_LOOPBACK_INSECURE_COOKIES: loopbackInsecureCookieOverride,
    NODE_ENV: "production",
    ...(contractCaPath ? { NODE_EXTRA_CA_CERTS: contractCaPath } : {}),
    PORT: String(backendPort),
  };
  const configuredBackendEnv = await configureBackend({
    backendPublicUrl,
    backendUrl,
    databaseUrl: postgres.databaseUrl,
    encryptionKey,
    makePayApiUrl,
    makePayCheckoutUrl,
    oauthIssuerUrl,
    projectRoot,
    storefrontPublicUrl,
    storefrontUrl,
  });
  Object.assign(runtimeEnv, configuredBackendEnv);
  await buildBackendAndMigrate({
    adminEmail,
    adminPassword,
    env: runtimeEnv,
    projectRoot,
    resetMakePayState: postgres.external,
  });

  let builtBackend = join(projectRoot, "apps/backend/.medusa/server");
  let secondBuiltBackend = builtBackend;
  let secondRuntimeEnv;
  let apiKeyBuiltBackend = builtBackend;
  let apiKeyRuntimeEnv;
  if (realSandbox) {
    builtBackend = await preserveBuiltBackend(projectRoot, "a");
    secondRuntimeEnv = {
      DATABASE_URL: secondPostgres.databaseUrl,
      MAKEPAY_E2E_LOOPBACK_INSECURE_COOKIES: loopbackInsecureCookieOverride,
      NODE_ENV: "production",
      PORT: String(secondBackendPort),
    };
    Object.assign(
      secondRuntimeEnv,
      await configureBackend({
        backendPublicUrl: secondBackendPublicUrl,
        backendUrl: secondBackendUrl,
        databaseUrl: secondPostgres.databaseUrl,
        encryptionKey: secondEncryptionKey,
        makePayApiUrl,
        makePayCheckoutUrl,
        oauthIssuerUrl,
        persist: false,
        projectRoot,
        storefrontPublicUrl,
        storefrontUrl,
      }),
    );
    await buildBackendAndMigrate({
      adminEmail: secondAdminEmail,
      adminPassword: secondAdminPassword,
      env: secondRuntimeEnv,
      projectRoot,
      resetMakePayState: secondPostgres.external,
      seed: !secondPostgres.external,
    });
    secondBuiltBackend = await preserveBuiltBackend(projectRoot, "b");
  } else {
    apiKeyRuntimeEnv = {
      DATABASE_URL: apiKeyPostgres.databaseUrl,
      MAKEPAY_E2E_LOOPBACK_INSECURE_COOKIES: loopbackInsecureCookieOverride,
      NODE_ENV: "production",
      PORT: String(apiKeyBackendPort),
      ...(contractCaPath ? { NODE_EXTRA_CA_CERTS: contractCaPath } : {}),
    };
    Object.assign(
      apiKeyRuntimeEnv,
      await configureApiKeyBackend({
        apiKeyId: contract.apiKeyId,
        apiKeySecret: contract.apiKeySecret,
        backendUrl: apiKeyBackendUrl,
        databaseUrl: apiKeyPostgres.databaseUrl,
        makePayApiUrl,
        makePayCheckoutUrl,
        webhookSecret: contract.webhookSecret,
      }),
    );
    await buildBackendAndMigrate({
      adminEmail: apiKeyAdminEmail,
      adminPassword: apiKeyAdminPassword,
      build: false,
      env: apiKeyRuntimeEnv,
      projectRoot,
      resetMakePayState: false,
      seed: true,
    });
    await seedStaleOAuthConnection(apiKeyPostgres.databaseUrl);
  }

  await startProcess("npx", ["--no-install", "medusa", "start"], {
    cwd: builtBackend,
    env: runtimeEnv,
    logPath: join(temporaryRoot, "runtime-raw", "backend.log"),
    mutator: true,
    mutatorPort: backendPort,
  });
  await waitForUrl(`${backendUrl}/health`, "Medusa backend");
  await startProcess("npx", ["--no-install", "medusa", "start"], {
    cwd: secondBuiltBackend,
    env: realSandbox
      ? secondRuntimeEnv
      : { ...runtimeEnv, PORT: String(secondBackendPort) },
    logPath: join(
      temporaryRoot,
      "runtime-raw",
      realSandbox ? "backend-installation-b.log" : "backend-secondary.log",
    ),
    mutator: true,
    mutatorPort: secondBackendPort,
  });
  await waitForUrl(
    `${secondBackendUrl}/health`,
    realSandbox ? "installation B Medusa backend" : "secondary Medusa backend",
  );
  if (!realSandbox) {
    await startProcess("npx", ["--no-install", "medusa", "start"], {
      cwd: apiKeyBuiltBackend,
      env: apiKeyRuntimeEnv,
      logPath: join(temporaryRoot, "runtime-raw", "backend-api-key.log"),
      mutator: true,
      mutatorPort: apiKeyBackendPort,
    });
    await waitForUrl(`${apiKeyBackendUrl}/health`, "API-key Medusa backend");
  }
  const primaryKeys = await createPublishableKey(backendUrl);
  const publishableKey = primaryKeys.publishableKey;
  const secondKeys = realSandbox
    ? await createPublishableKey(
        secondBackendUrl,
        secondAdminEmail,
        secondAdminPassword,
      )
    : { adminToken: "", publishableKey: "" };
  const secondPublishableKey = secondKeys.publishableKey;
  const apiKeyKeys = !realSandbox
    ? await createPublishableKey(
        apiKeyBackendUrl,
        apiKeyAdminEmail,
        apiKeyAdminPassword,
      )
    : { adminToken: "", publishableKey: "" };
  if (realSandbox) {
    realSandboxCleanupTargets = [
      {
        adminToken: primaryKeys.adminToken,
        backendUrl,
        databaseUrl: postgres.databaseUrl,
        installation: "a",
        label: "installation A",
      },
      {
        adminToken: secondKeys.adminToken,
        backendUrl: secondBackendUrl,
        databaseUrl: secondPostgres.databaseUrl,
        installation: "b",
        label: "installation B",
      },
    ];
    realSandboxCredentialsPath = join(
      temporaryRoot,
      "real-sandbox-playwright-credentials.json",
    );
    registerRuntimeSecret(realSandboxCredentialsPath);
    await writeRestrictedJson(realSandboxCredentialsPath, {
      a: {
        adminEmail,
        adminPassword,
        adminToken: primaryKeys.adminToken,
        publishableKey,
      },
      b: {
        adminEmail: secondAdminEmail,
        adminPassword: secondAdminPassword,
        adminToken: secondKeys.adminToken,
        publishableKey: secondPublishableKey,
      },
    });
    realSandboxControl = await startRealSandboxControl({
      installations: {
        a: {
          backendRoot: builtBackend,
          callbackUrl: `${backendPublicUrl}/hooks/makepay/makepay_makepay`,
          env: runtimeEnv,
          legacyCallbackUrl: `${backendPublicUrl}/hooks/payment/makepay_makepay`,
        },
        b: {
          backendRoot: secondBuiltBackend,
          callbackUrl: `${secondBackendPublicUrl}/hooks/makepay/makepay_makepay`,
          env: secondRuntimeEnv,
          legacyCallbackUrl: `${secondBackendPublicUrl}/hooks/payment/makepay_makepay`,
        },
      },
    });
    registerRuntimeSecret(realSandboxControl.socketPath);
  }
  await configureStorefront({
    backendPublicUrl,
    makePayCheckoutUrl,
    projectRoot,
    publishableKey,
  });
  const storefrontRuntimeEnv = {
    MAKEPAY_E2E_LOOPBACK_INSECURE_COOKIES: loopbackInsecureCookieOverride,
    MEDUSA_BACKEND_URL: backendUrl,
    NODE_ENV: "production",
  };
  await buildStorefront(projectRoot, storefrontRuntimeEnv);
  await startProcess(
    "npx",
    ["--no-install", "next", "start", "-p", String(storefrontPort)],
    {
      cwd: join(projectRoot, "apps/storefront"),
      env: storefrontRuntimeEnv,
      logPath: join(temporaryRoot, "runtime-raw", "storefront.log"),
      mutator: true,
      mutatorPort: storefrontPort,
    },
  );
  await waitForUrl(storefrontUrl, "Next.js storefront");

  if (!realSandbox) {
    oauthControl = await startMedusaControl({
      backendRoot: builtBackend,
      env: runtimeEnv,
      profile: "oauth",
    });
    registerRuntimeSecret(oauthControl.socketPath);
    apiKeyControl = await startMedusaControl({
      backendRoot: apiKeyBuiltBackend,
      env: apiKeyRuntimeEnv,
      profile: "api-key",
    });
    registerRuntimeSecret(apiKeyControl.socketPath);
  }

  if (!skipBrowser) {
    if (!realSandboxLogin.manualOAuth) {
      await run("npx", ["--no-install", "playwright", "install", "chromium"], {
        capture: true,
        cwd: packageRoot,
        onOutput: (value) => process.stdout.write(value),
        sanitizeCapture: true,
      });
    }
    const spec = realSandbox
      ? "real-sandbox.spec.mjs"
      : "medusa-storefront.spec.mjs";
    const evidenceDirectory =
      process.env.MAKEPAY_E2E_EVIDENCE_DIR ||
      join(packageRoot, "output/playwright/medusa-makepay/evidence");
    const preparedEvidenceDirectory =
      process.env.MAKEPAY_E2E_CAPTURE === "1"
        ? await resetEvidenceDirectory(evidenceDirectory)
        : resolve(evidenceDirectory);
    if (realSandbox && process.env.MAKEPAY_E2E_CAPTURE === "1") {
      realSandboxEvidenceCompletion = {
        artifactProvenance,
        artifactInstallVerified: true,
        manifestPath: join(preparedEvidenceDirectory, "manifest.json"),
        playwrightScenarioCompleted: false,
        runId,
      };
    }
    await run(
      "npx",
      [
        "--no-install",
        "playwright",
        "test",
        `tests/e2e/${spec}`,
        "--config=tests/e2e/playwright.config.mjs",
      ],
      {
        cwd: packageRoot,
        env: {
          MAKEPAY_E2E_ADMIN_EMAIL: realSandbox ? "" : adminEmail,
          MAKEPAY_E2E_ADMIN_PASSWORD: realSandbox ? "" : adminPassword,
          MAKEPAY_E2E_API_KEY_ADMIN_TOKEN: realSandbox
            ? ""
            : apiKeyKeys.adminToken,
          MAKEPAY_E2E_API_KEY_BACKEND_URL: realSandbox ? "" : apiKeyBackendUrl,
          MAKEPAY_E2E_API_KEY_CONTROL_SOCKET: realSandbox
            ? ""
            : apiKeyControl.socketPath,
          MAKEPAY_E2E_API_KEY_PUBLISHABLE_KEY: realSandbox
            ? ""
            : apiKeyKeys.publishableKey,
          MAKEPAY_E2E_BACKEND_URL: backendPublicUrl,
          MAKEPAY_E2E_BACKEND_INTERNAL_URL: realSandbox ? backendUrl : "",
          MAKEPAY_E2E_SECOND_ADMIN_EMAIL: "",
          MAKEPAY_E2E_SECOND_ADMIN_PASSWORD: "",
          MAKEPAY_E2E_SECOND_BACKEND_URL: realSandbox
            ? secondBackendPublicUrl
            : secondBackendUrl,
          MAKEPAY_E2E_SECOND_BACKEND_INTERNAL_URL: realSandbox
            ? secondBackendUrl
            : "",
          MAKEPAY_E2E_SECOND_PUBLISHABLE_KEY: "",
          MAKEPAY_E2E_CAPTURE: process.env.MAKEPAY_E2E_CAPTURE || "0",
          MAKEPAY_E2E_CHECKOUT_ORIGIN: new URL(makePayCheckoutUrl).origin,
          MAKEPAY_E2E_CONTRACT_URL: contract?.origin || "",
          MAKEPAY_E2E_CONTROL_TOKEN: realSandbox ? "" : controlToken,
          MAKEPAY_E2E_CONTROL_SOCKET: realSandbox
            ? realSandboxControl.socketPath
            : "",
          MAKEPAY_E2E_EVIDENCE_DIR: preparedEvidenceDirectory,
          MAKEPAY_E2E_MANUAL_OAUTH: realSandboxLogin.manualOAuth ? "1" : "0",
          MAKEPAY_E2E_LOCAL_DIAGNOSTICS: localDiagnostics ? "1" : "0",
          MAKEPAY_E2E_PUBLISHABLE_KEY: realSandbox ? "" : publishableKey,
          MAKEPAY_E2E_PLUGIN_SHA256: artifactProvenance.plugin.sha256,
          MAKEPAY_E2E_PLUGIN_VERSION: artifactProvenance.plugin.version,
          MAKEPAY_E2E_PLAYWRIGHT_COMPLETION_RECEIPT:
            playwrightCompletionReceiptPath || "",
          MAKEPAY_E2E_REAL_SANDBOX: realSandbox ? "1" : "0",
          MAKEPAY_E2E_REAL_CREDENTIALS_FILE: realSandboxCredentialsPath || "",
          MAKEPAY_E2E_REAL_OAUTH_ISSUER_URL:
            process.env.MAKEPAY_E2E_REAL_OAUTH_ISSUER_URL || "",
          MAKEPAY_E2E_RUN_ID: runId,
          MAKEPAY_E2E_SDK_SHA256: artifactProvenance.sdk.sha256,
          MAKEPAY_E2E_SDK_VERSION: artifactProvenance.sdk.version,
          MAKEPAY_E2E_SANDBOX_COMPANY_ID:
            process.env.MAKEPAY_E2E_SANDBOX_COMPANY_ID || "",
          MAKEPAY_E2E_SANDBOX_COMPANY_NAME:
            process.env.MAKEPAY_E2E_SANDBOX_COMPANY_NAME || "",
          MAKEPAY_E2E_STOREFRONT_URL: storefrontPublicUrl,
          MAKEPAY_E2E_SCREENSHOT_PUBLICATION_ACK:
            process.env.MAKEPAY_E2E_SCREENSHOT_PUBLICATION_ACK || "",
          MAKEPAY_E2E_STORAGE_STATE: realSandboxLogin.storageState,
          MAKEPAY_E2E_TEST_MATCH: spec,
          ...(realSandbox
            ? {}
            : {
                MAKEPAY_E2E_OAUTH_CONTROL_SOCKET: oauthControl.socketPath,
              }),
          ...(contractCaPath ? { NODE_EXTRA_CA_CERTS: contractCaPath } : {}),
        },
        capture: true,
        onOutput: (value) => process.stdout.write(value),
        sanitizeCapture: true,
      },
    );
    const playwrightReport = playwrightCompletionReceiptPath
      ? await readPlaywrightCompletion(
          playwrightCompletionReceiptPath,
          realSandbox ? "real-sandbox" : "deterministic",
        )
      : undefined;
    if (realSandboxEvidenceCompletion) {
      realSandboxEvidenceCompletion.playwrightScenarioCompleted = true;
    } else if (captureRequested) {
      deterministicEvidenceCompletion = {
        artifactProvenance,
        artifactInstallVerified: true,
        manifestPath: join(preparedEvidenceDirectory, "manifest.json"),
        playwrightReport,
        playwrightScenarioCompleted: true,
        runId,
      };
    }
  }
  for (const message of browserCompletionSummary()) log(message);
  if (skipBrowser) return;
  completed = true;
}

async function cleanupOnce() {
  let primaryCleanupPassed = false;
  let finalCleanupPassed = false;
  let realSandboxCleanupReceipt;
  const completionChecks = {
    artifactInstallVerified:
      (realSandboxEvidenceCompletion?.artifactInstallVerified ??
        deterministicEvidenceCompletion?.artifactInstallVerified) === true,
    childProcessesTerminated: false,
    controlPlanesClosed: false,
    foregroundWorkQuiesced: false,
    oauthDisconnected: false,
    paymentLinksArchived: false,
    playwrightScenarioCompleted:
      (realSandboxEvidenceCompletion?.playwrightScenarioCompleted ??
        deterministicEvidenceCompletion?.playwrightScenarioCompleted) === true,
    postgresStopped: false,
    runtimeLogsPublished: false,
    runtimeSecretsScrubbed: false,
    temporaryWorkspaceDispositionAccepted: false,
  };
  try {
    primaryCleanupPassed = await settleCleanupStages([
      ...orderedMutationCleanupStages({
        quiesce: async () => {
          await quiesceForegroundWork();
          completionChecks.foregroundWorkQuiesced = true;
        },
        remoteCleanup: async () => {
          realSandboxCleanupReceipt = await cleanupRealSandboxInstallations();
          if (realSandbox) {
            if (realSandboxCleanupReceipt?.accepted !== true) {
              throw new Error(
                "Real-sandbox cleanup returned no accepted receipt.",
              );
            }
            completionChecks.paymentLinksArchived = true;
            completionChecks.oauthDisconnected = true;
          }
        },
        terminate: async () => {
          await terminateChildren();
          completionChecks.childProcessesTerminated = true;
        },
      }),
      [
        "Real-sandbox control socket",
        async () => {
          if (realSandboxControl) await realSandboxControl.close();
          realSandboxControl = undefined;
        },
      ],
      [
        "Deterministic Medusa capture fixtures and control sockets",
        async () => {
          const cleanupTasks = [];
          if (oauthControl) cleanupTasks.push(oauthControl.close());
          if (apiKeyControl) cleanupTasks.push(apiKeyControl.close());
          const results = await Promise.allSettled(cleanupTasks);
          oauthControl = undefined;
          apiKeyControl = undefined;
          const rejected = results.find(
            (result) => result.status === "rejected",
          );
          if (rejected?.status === "rejected") throw rejected.reason;
          completionChecks.controlPlanesClosed = true;
        },
      ],
      [
        "Contract server",
        async () => {
          if (contract) await contract.close();
          contract = undefined;
        },
      ],
      [
        "PostgreSQL clusters",
        async () => {
          const results = await Promise.allSettled([
            stopPostgres(postgres),
            stopPostgres(secondPostgres),
            stopPostgres(apiKeyPostgres),
          ]);
          const rejected = results.find(
            (result) => result.status === "rejected",
          );
          if (rejected?.status === "rejected") throw rejected.reason;
          disposablePostgresRemovalSafe = true;
          completionChecks.postgresStopped = true;
        },
      ],
      [
        "Sanitized runtime log publication",
        async () => {
          await publishSanitizedRuntimeLogs();
          completionChecks.runtimeLogsPublished = true;
        },
      ],
    ]);
  } finally {
    finalCleanupPassed = await settleCleanupStages([
      [
        "Secret-file scrub",
        async () => {
          await scrubRuntimeSecrets();
          completionChecks.runtimeSecretsScrubbed = true;
        },
      ],
      [
        "Temporary workspace removal",
        async () => {
          if (temporaryRoot && !disposablePostgresRemovalSafe) {
            process.exitCode = 1;
            process.stderr.write(
              sanitizeRuntimeLog(
                `[makepay-e2e] MANUAL CLEANUP BLOCKER: disposable PostgreSQL stop was not proven; retained PGDATA at ${temporaryRoot}. Stop that isolated cluster before removing the directory.\n`,
              ),
            );
          } else if (temporaryRoot && !keep) {
            await rm(temporaryRoot, { force: true, recursive: true });
          } else if (temporaryRoot) {
            log(`Kept scrubbed temporary workspace: ${temporaryRoot}`);
          }
          completionChecks.temporaryWorkspaceDispositionAccepted = true;
        },
      ],
    ]);
  }
  const parentRunAccepted = parentHarnessRunAccepted({
    completedRun: completed,
    exitCode: process.exitCode,
    finalCleanupPassed,
    primaryCleanupPassed,
    signal: receivedSignal,
  });
  if (realSandboxEvidenceCompletion && parentRunAccepted) {
    await attestEvidenceRunCompletion({
      artifactProvenance: realSandboxEvidenceCompletion.artifactProvenance,
      checks: completionChecks,
      cleanupReceipt: realSandboxCleanupReceipt,
      manifestPath: realSandboxEvidenceCompletion.manifestPath,
      runId: realSandboxEvidenceCompletion.runId,
    });
    log(
      "Real-sandbox screenshot evidence accepted after full scenario, archival, OAuth disconnect, and harness cleanup.",
    );
  } else if (deterministicEvidenceCompletion && parentRunAccepted) {
    await attestDeterministicEvidenceRunCompletion({
      artifactProvenance:
        deterministicEvidenceCompletion.artifactProvenance,
      checks: {
        artifactInstallVerified: completionChecks.artifactInstallVerified,
        childProcessesTerminated: completionChecks.childProcessesTerminated,
        controlPlanesClosed: completionChecks.controlPlanesClosed,
        foregroundWorkQuiesced: completionChecks.foregroundWorkQuiesced,
        playwrightScenarioCompleted:
          completionChecks.playwrightScenarioCompleted,
        postgresStopped: completionChecks.postgresStopped,
        runtimeLogsPublished: completionChecks.runtimeLogsPublished,
        runtimeSecretsScrubbed: completionChecks.runtimeSecretsScrubbed,
        temporaryWorkspaceDispositionAccepted:
          completionChecks.temporaryWorkspaceDispositionAccepted,
      },
      manifestPath: deterministicEvidenceCompletion.manifestPath,
      playwrightReport: deterministicEvidenceCompletion.playwrightReport,
      runId: deterministicEvidenceCompletion.runId,
    });
    log(
      "Deterministic screenshot evidence accepted after the complete scenario and parent-harness cleanup.",
    );
  }
}

function cleanup() {
  cleanupPromise ??= cleanupOnce();
  return cleanupPromise;
}

function handleSignal(signal) {
  if (receivedSignal) return;
  receivedSignal = signal;
  process.exitCode = signal === "SIGINT" ? 130 : 143;
  void cleanup().finally(() => process.exit(process.exitCode));
}

process.once("SIGINT", () => handleSignal("SIGINT"));
process.once("SIGTERM", () => handleSignal("SIGTERM"));

(signalWorkerStage
  ? runSignalCleanupWorker()
  : sanitizerSelfTest
    ? runSanitizerSelfTest()
    : main()
)
  .catch((error) => {
    const message = error instanceof Error ? error.message : "E2E run failed.";
    process.stderr.write(`[makepay-e2e] ${sanitizeRuntimeLog(message)}\n`);
    if (!receivedSignal) process.exitCode = 1;
  })
  .finally(() =>
    cleanup().catch((error) => {
      process.exitCode = 1;
      process.stderr.write(
        `[makepay-e2e] ${sanitizeRuntimeLog(
          error instanceof Error ? error.message : "Cleanup failed.",
        )}\n`,
      );
    }),
  );
