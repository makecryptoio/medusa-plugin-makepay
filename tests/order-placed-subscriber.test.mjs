import assert from "node:assert/strict";
import test from "node:test";

import { ContainerRegistrationKeys } from "@medusajs/framework/utils";

import { MAKEPAY_MODULE } from "../src/modules/makepay/constants.ts";
import makePayOrderPlacedHandler from "../src/subscribers/makepay-order-placed.ts";

test("order placement correlates the server-verified guest email", async () => {
  const correlations = [];
  const services = {
    [ContainerRegistrationKeys.QUERY]: {
      async graph(input) {
        assert.equal(input.entity, "order");
        assert.deepEqual(input.filters, { id: "order_guest" });
        assert.equal(input.fields.includes("email"), true);
        return {
          data: [
            {
              display_id: 42,
              email: "guest@example.test",
              id: "order_guest",
              payment_collections: [
                {
                  payment_sessions: [
                    {
                      id: "payses_guest",
                      provider_id: "pp_makepay_makepay",
                    },
                  ],
                  payments: [
                    {
                      id: "pay_guest",
                      payment_session_id: "payses_guest",
                      provider_id: "pp_makepay_makepay",
                    },
                  ],
                },
              ],
            },
          ],
        };
      },
    },
    [MAKEPAY_MODULE]: {
      async correlateOrder(input) {
        correlations.push(input);
      },
    },
  };

  await makePayOrderPlacedHandler({
    container: {
      resolve(name) {
        return services[name];
      },
    },
    event: { data: { id: "order_guest" } },
  });

  assert.deepEqual(correlations, [
    {
      customerEmail: "guest@example.test",
      orderDisplayId: "42",
      orderId: "order_guest",
      paymentId: "pay_guest",
      sessionId: "payses_guest",
    },
  ]);
});
