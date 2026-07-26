import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { POST } from "../src/api/admin/makepay/payments/[id]/reconcile/route.ts";
import { MAKEPAY_MODULE } from "../src/modules/makepay/constants.ts";

test("Admin reconciliation rejects a payment from the inactive auth mode", async () => {
  let reconciliationCalls = 0;
  const resolvedKeys = [];
  const service = {
    authMode: "oauth",
    reconciliationEnabled: true,
    async getPaymentView(id) {
      assert.equal(id, "projection_api_key");
      return { auth_mode: "api_key", id };
    },
    async reconcileAndProcessPaymentView() {
      reconciliationCalls += 1;
      throw new Error("reconciliation must not run across auth modes");
    },
  };
  const req = {
    params: { id: "projection_api_key" },
    scope: {
      resolve(key) {
        resolvedKeys.push(key);
        if (key === MAKEPAY_MODULE) return service;
        throw new Error(`Unexpected scope resolution: ${key}`);
      },
    },
  };
  const response = {
    body: undefined,
    statusCode: 200,
    json(body) {
      this.body = body;
      return this;
    },
    status(statusCode) {
      this.statusCode = statusCode;
      return this;
    },
  };

  await POST(req, response);

  assert.equal(response.statusCode, 409);
  assert.deepEqual(response.body, {
    message:
      "MakePay payment belongs to a different authentication mode. Restore that mode before reconciliation.",
  });
  assert.equal(reconciliationCalls, 0);
  assert.deepEqual(resolvedKeys, [MAKEPAY_MODULE]);
});

test("order widget exposes reconciliation only for the active auth mode", async () => {
  const source = await readFile(
    new URL("../src/admin/widgets/order-makepay-widget.tsx", import.meta.url),
    "utf8",
  );

  assert.match(
    source,
    /connectionQuery\.data\?\.capabilities\.reconcile === true\s*&&\s*payment\?\.auth_mode === connectionQuery\.data\.connection\.auth_mode/,
  );
  assert.match(source, /\{payment && canReconcile && \(/);
  assert.match(source, /onClick=\{\(\) => reconcileMutation\.mutate\(payment\.id\)\}/);
});
