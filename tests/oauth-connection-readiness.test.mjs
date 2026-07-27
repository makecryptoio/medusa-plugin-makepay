import assert from "node:assert/strict";
import test from "node:test";

import {
  oauthConnectionReadiness,
  waitForOAuthConnection,
} from "./e2e/support/oauth-connection-readiness.mjs";

const expected = {
  companyId: "company_demo",
  expectedScopes: ["makepay:webhooks:write", "company:read"],
};

test("OAuth readiness is exact and sorts scopes deterministically", () => {
  assert.deepEqual(
    oauthConnectionReadiness(
      {
        company_id: expected.companyId,
        connected: true,
        scopes: ["company:read", "makepay:webhooks:write"],
        status: "connected",
        webhook: { status: "healthy" },
      },
      expected,
    ),
    {
      company_id: expected.companyId,
      connected: true,
      scopes: ["company:read", "makepay:webhooks:write"],
      status: "connected",
      webhook: "healthy",
    },
  );
});

test("OAuth callback recovery waits through the committed pending row", async () => {
  let reads = 0;
  const ready = {
    company_id: expected.companyId,
    connected: true,
    scopes: ["company:read", "makepay:webhooks:write"],
    status: "connected",
    webhook: { status: "healthy" },
  };

  const connection = await waitForOAuthConnection(
    async () => {
      reads += 1;
      if (reads === 1) {
        return {
          ...ready,
          connected: false,
          status: "error",
          webhook: { status: "error" },
        };
      }
      return ready;
    },
    { ...expected, timeout: 1_000 },
  );

  assert.equal(reads, 2);
  assert.equal(connection, ready);
});
