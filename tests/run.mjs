import assert from "node:assert/strict";
import { createHmac, timingSafeEqual } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const sourceRoot = join(__dirname, "..");
const packageRoot = join(sourceRoot, "node_modules");

function writeRuntimeStub(path, source) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, source);
}

function installRuntimeStubs() {
  rmSync(packageRoot, { force: true, recursive: true });

  writeRuntimeStub(
    join(packageRoot, "@medusajs/framework/package.json"),
    JSON.stringify(
      {
        exports: {
          "./utils": "./utils.js",
        },
        type: "module",
      },
      null,
      2,
    ),
  );
  writeRuntimeStub(
    join(packageRoot, "@medusajs/framework/utils.js"),
    `
export class AbstractPaymentProvider {
  constructor(container, config) {
    this.container = container
    this.config = config
  }
}
export const PaymentSessionStatus = {
  AUTHORIZED: "authorized",
  CAPTURED: "captured",
  PENDING: "pending",
  REQUIRES_MORE: "requires_more",
  ERROR: "error",
  CANCELED: "canceled",
}
export const PaymentActions = {
  AUTHORIZED: "authorized",
  SUCCESSFUL: "captured",
  FAILED: "failed",
  PENDING: "pending",
  REQUIRES_MORE: "requires_more",
  CANCELED: "canceled",
  NOT_SUPPORTED: "not_supported",
}
export const Modules = { PAYMENT: "payment" }
export function ModuleProvider(moduleName, config) {
  return { moduleName, ...config }
}
`,
  );

  writeRuntimeStub(
    join(packageRoot, "@makecrypto/makepay/package.json"),
    JSON.stringify(
      {
        exports: {
          ".": "./index.js",
        },
        type: "module",
      },
      null,
      2,
    ),
  );
  writeRuntimeStub(
    join(packageRoot, "@makecrypto/makepay/index.js"),
    `
import { createHmac, timingSafeEqual } from "node:crypto"

export const makePayClientCalls = []

export class MakePayClient {
  constructor(options) {
    this.options = options
    makePayClientCalls.push({ type: "constructor", options })
  }

  async createPaymentLink(payload, options = {}) {
    makePayClientCalls.push({ type: "createPaymentLink", payload, options, clientOptions: this.options })

    if (this.options.fetch) {
      await this.options.fetch(new Request(
        new URL("/api/partner/v1/makepay/payment-links", this.options.baseUrl || "https://www.makecrypto.io"),
        {
          method: "POST",
          headers: {
            accept: "application/json",
            "content-type": "application/json",
            "x-makecrypto-key-id": this.options.keyId,
            "x-makecrypto-key-secret": this.options.keySecret,
          },
          body: JSON.stringify({
            status: options.status ?? "active",
            sendPaymentRequestEmail: options.sendPaymentRequestEmail ?? false,
            payload,
          }),
        },
      ))
    }

    return {
      paymentLink: {
        uid: "pay_123",
        publicUrl: "https://makepay.io/payment/pay_123",
        status: "active",
        amount: payload.amount,
        metadata: payload.metadata,
      },
    }
  }

  async getPaymentLink(uid) {
    makePayClientCalls.push({ type: "getPaymentLink", uid })
    return globalThis.__makepayGetPaymentLinkResponse ?? {
      paymentLink: {
        uid,
        publicUrl: \`https://makepay.io/payment/\${uid}\`,
        status: "active",
      },
    }
  }

  async updatePaymentLink(uid, updates) {
    makePayClientCalls.push({ type: "updatePaymentLink", uid, updates })
    return {
      paymentLink: {
        uid,
        publicUrl: \`https://makepay.io/payment/\${uid}\`,
        status: updates.status,
      },
    }
  }
}

export function parseMakePayWebhook(rawBody, signatureHeader, secret) {
  if (!signatureHeader) {
    throw new Error("Invalid MakePay webhook signature.")
  }

  const body = Buffer.isBuffer(rawBody) ? rawBody.toString("utf8") : String(rawBody)
  const parts = Object.fromEntries(signatureHeader.split(",").map((part) => part.trim().split("=", 2)))
  const timestamp = Number(parts.t)
  const signature = parts.v1
  const expected = createHmac("sha256", secret).update(\`\${timestamp}.\${body}\`).digest("hex")
  const actualBuffer = Buffer.from(signature || "", "hex")
  const expectedBuffer = Buffer.from(expected, "hex")

  if (actualBuffer.length !== expectedBuffer.length || !timingSafeEqual(actualBuffer, expectedBuffer)) {
    throw new Error("Invalid MakePay webhook signature.")
  }

  return JSON.parse(body)
}
`,
  );
}

function signWebhook(rawBody, secret) {
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = createHmac("sha256", secret)
    .update(`${timestamp}.${rawBody}`)
    .digest("hex");

  return `t=${timestamp},v1=${signature}`;
}

async function main() {
  installRuntimeStubs();

  try {
    const pkg = JSON.parse(
      readFileSync(join(sourceRoot, "package.json"), "utf8"),
    );
    assert.equal(pkg.name, "@makecrypto/medusa-plugin-makepay");
    assert.equal(
      pkg.exports["./providers/makepay"].types,
      "./dist/providers/makepay/index.d.ts",
    );
    for (const keyword of [
      "medusa-plugin",
      "medusa-v2",
      "medusa-plugin-integration",
      "medusa-plugin-payment",
      "makepay",
      "makecrypto",
    ]) {
      assert.ok(pkg.keywords.includes(keyword), `missing keyword ${keyword}`);
    }

    const moduleUrl = pathToFileURL(
      join(sourceRoot, "dist/providers/makepay/index.js"),
    );
    const makePayUrl = pathToFileURL(
      join(packageRoot, "@makecrypto/makepay/index.js"),
    );
    const { default: providerModule, MakePayProviderService } = await import(
      moduleUrl.href
    );
    const { makePayClientCalls } = await import(makePayUrl.href);

    assert.equal(providerModule.moduleName, "payment");
    assert.equal(providerModule.services[0], MakePayProviderService);
    assert.throws(
      () => MakePayProviderService.validateOptions({ keyId: "kid" }),
      /keySecret/,
    );
    MakePayProviderService.validateOptions({
      keyId: "kid",
      keySecret: "secret",
      webhookSecret: "whsec",
    });

    let capturedRequest;
    const provider = new MakePayProviderService(
      {},
      {
        baseUrl: "https://api.test",
        checkoutBaseUrl: "https://checkout.test",
        keyId: "kid",
        keySecret: "secret",
        settlementCurrency: "USDT",
        webhookSecret: "whsec",
        fetch: async (request) => {
          capturedRequest = {
            body: await request.json(),
            headers: request.headers,
            method: request.method,
            url: request.url,
          };

          return new Response(JSON.stringify({ ok: true }), { status: 200 });
        },
      },
    );

    const initiated = await provider.initiatePayment({
      amount: { numeric: 12.34 },
      context: {
        customer: {
          email: "buyer@example.com",
          id: "cus_123",
        },
        idempotency_key: "idem_123",
      },
      currency_code: "usd",
      data: {
        metadata: {
          cart_id: "cart_123",
        },
        return_url: "https://shop.example/order",
        session_id: "ps_123",
      },
    });

    assert.equal(initiated.id, "pay_123");
    assert.equal(initiated.status, "requires_more");
    assert.equal(initiated.data.payment_link_uid, "pay_123");
    assert.deepEqual(initiated.data.next_action, {
      type: "redirect",
      url: "https://makepay.io/payment/pay_123",
    });
    assert.equal(capturedRequest.method, "POST");
    assert.equal(
      capturedRequest.url,
      "https://api.test/api/partner/v1/makepay/payment-links",
    );
    assert.equal(capturedRequest.headers.get("x-makecrypto-key-id"), "kid");
    assert.equal(
      capturedRequest.headers.get("x-makecrypto-key-secret"),
      "secret",
    );
    assert.equal(capturedRequest.body.payload.amount, 12.34);
    assert.equal(capturedRequest.body.payload.fiatCurrency, "USD");
    assert.equal(capturedRequest.body.payload.currency, "USDT");
    assert.equal(capturedRequest.body.payload.metadata.session_id, "ps_123");
    assert.equal(capturedRequest.body.payload.metadata.source, "medusa");

    for (const [response, expected] of [
      [
        { paymentLink: { uid: "pay_1", status: "active" } },
        "requires_more",
      ],
      [
        {
          paymentLink: { uid: "pay_1", status: "active" },
          latestSession: { status: "complete" },
        },
        "captured",
      ],
      [
        { paymentLink: { uid: "pay_1", status: "expired" } },
        "canceled",
      ],
      [
        {
          paymentLink: { uid: "pay_1", status: "active" },
          latestSession: { status: "failed" },
        },
        "error",
      ],
      [
        { paymentLink: { uid: "pay_1", status: "payment.failed" } },
        "error",
      ],
      [
        { paymentLink: { uid: "pay_1", status: "mystery" } },
        "pending",
      ],
    ]) {
      globalThis.__makepayGetPaymentLinkResponse = response;
      const status = await provider.getPaymentStatus({
        data: {
          payment_link_uid: "pay_1",
          session_id: "ps_1",
        },
      });
      assert.equal(status.status, expected);
    }

    const archived = await provider.cancelPayment({
      data: {
        payment_link_uid: "pay_cancel",
        session_id: "ps_cancel",
      },
    });
    assert.equal(archived.data.payment_link_uid, "pay_cancel");
    assert.equal(archived.data.status, "canceled");
    assert.ok(
      makePayClientCalls.some(
        (call) =>
          call.type === "updatePaymentLink" &&
          call.uid === "pay_cancel" &&
          call.updates.status === "archived",
      ),
    );

    await assert.rejects(
      () =>
        provider.refundPayment({
          amount: 1,
          data: {
            payment_link_uid: "pay_123",
          },
        }),
      /refunds are not supported/,
    );

    const rawWebhook = JSON.stringify({
      event: {
        type: "status_changed",
      },
      paymentLink: {
        amount: "12.34",
        metadata: {
          session_id: "ps_123",
        },
        uid: "pay_123",
      },
      session: {
        invoiceAmount: "12.34",
        status: "complete",
      },
      type: "makepay.payment.status_changed",
    });
    const webhook = await provider.getWebhookActionAndData({
      data: JSON.parse(rawWebhook),
      headers: {
        "X-MakePay-Signature": signWebhook(rawWebhook, "whsec"),
      },
      rawData: rawWebhook,
    });
    assert.equal(webhook.action, "captured");
    assert.equal(webhook.data.session_id, "ps_123");
    assert.equal(webhook.data.amount, "12.34");

    await assert.rejects(
      () =>
        provider.getWebhookActionAndData({
          data: JSON.parse(rawWebhook),
          headers: {
            "x-makepay-signature": signWebhook(rawWebhook, "wrong"),
          },
          rawData: rawWebhook,
        }),
      /Invalid MakePay webhook signature/,
    );

    console.log("MakePay Medusa provider source verified.");
  } finally {
    rmSync(packageRoot, { force: true, recursive: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
