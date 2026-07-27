import assert from "node:assert/strict";
import test from "node:test";

import { extractCreatedQuickTunnelUrl } from "./e2e/support/quick-tunnel.mjs";

test("quick-tunnel output requires the successful creation marker", () => {
  assert.equal(
    extractCreatedQuickTunnelUrl(
      'failed to request quick Tunnel: Post "https://api.trycloudflare.com/tunnel": context deadline exceeded',
    ),
    undefined,
  );
});

test("quick-tunnel output returns only the generated public hostname", () => {
  const output = [
    "Requesting new quick Tunnel on trycloudflare.com...",
    "Your quick Tunnel has been created! Visit it at:",
    "https://demo-generated-host.trycloudflare.com",
  ].join("\n");

  assert.equal(
    extractCreatedQuickTunnelUrl(output),
    "https://demo-generated-host.trycloudflare.com",
  );
});

test("quick-tunnel output does not reuse an URL before the marker", () => {
  const output = [
    "https://unrelated-host.trycloudflare.com",
    "Your quick Tunnel has been created! Visit it at:",
  ].join("\n");

  assert.equal(extractCreatedQuickTunnelUrl(output), undefined);
});
