import assert from "node:assert/strict";
import test from "node:test";

import {
  connectionStatusColor,
  humanizeStatus,
  oauthConnectionActionLabel,
  redactSensitiveText,
  safeExternalUrl,
  safeOAuthRedirect,
  statusColor,
} from "../src/admin/lib/format.ts";

test("Admin links allow HTTPS and local development without credentials", () => {
  assert.equal(
    safeExternalUrl("https://www.makepay.io/payment/pay_test"),
    "https://www.makepay.io/payment/pay_test",
  );
  assert.equal(
    safeExternalUrl("http://localhost:9000/payment/pay_test"),
    "http://localhost:9000/payment/pay_test",
  );
  assert.equal(
    safeExternalUrl("http://[::1]:9000/payment/pay_test"),
    "http://[::1]:9000/payment/pay_test",
  );
  assert.equal(
    safeExternalUrl("http://makepay.test/payment/pay_test"),
    undefined,
  );
  assert.equal(safeExternalUrl("javascript:alert(1)"), undefined);
  assert.equal(
    safeExternalUrl("https://user:password@makepay.test"),
    undefined,
  );
  assert.equal(
    safeOAuthRedirect("http://makecrypto.test/oauth/authorize"),
    undefined,
  );
});

test("Admin status and error formatting is safe and consistent", () => {
  assert.equal(statusColor("complete"), "green");
  assert.equal(statusColor("pending_authorization"), "orange");
  assert.equal(statusColor("failed"), "red");
  assert.equal(connectionStatusColor("disconnect_pending"), "orange");
  assert.equal(
    humanizeStatus("pending_authorization"),
    "Pending Authorization",
  );
  assert.equal(
    redactSensitiveText(
      "access_token=eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.signature webhook_secret=whsec_test",
    ),
    "access_token=[redacted] webhook_secret=[redacted]",
  );
});

test("Admin distinguishes first-time setup, retryable outages, and terminal reconnects", () => {
  assert.equal(
    oauthConnectionActionLabel({
      connected: false,
      reconnect_required: false,
    }),
    "Connect MakePay",
  );
  assert.equal(
    oauthConnectionActionLabel({
      connected: false,
      reconnect_required: true,
    }),
    "Reconnect",
  );
  assert.equal(
    oauthConnectionActionLabel({
      connected: true,
      reconnect_required: false,
    }),
    "Reconnect",
  );
});

test("Admin error redaction covers nested JSON OAuth and webhook secrets", () => {
  assert.equal(
    redactSensitiveText(
      JSON.stringify({
        authorization: "DPoP proof-value",
        nested: {
          access_token: "access-value",
          refresh_token: "refresh-value",
          webhook_secret: "webhook-value",
        },
      }),
    ),
    '{"authorization":"[redacted]","nested":{"access_token":"[redacted]","refresh_token":"[redacted]","webhook_secret":"[redacted]"}}',
  );
  assert.equal(
    redactSensitiveText(
      "client_secret='client-value' dpop_proof: \"proof-value\" signing-secret=signing-value",
    ),
    "client_secret=[redacted] dpop_proof=[redacted] signing-secret=[redacted]",
  );
});
