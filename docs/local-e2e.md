# Local end-to-end test

This runbook verifies the packed npm artifact in a real Medusa 2.17.2 backend
and storefront. It deliberately uses an isolated PostgreSQL database and a
public HTTPS tunnel for OAuth/webhooks. Do not use production customer data or
spend cryptocurrency.

## Prerequisites

- Node.js 22 or 24 and npm
- PostgreSQL 16+
- `cloudflared`
- A MakeCrypto sandbox merchant/company administrator
- The official Medusa Next.js starter configured for the local backend

## Pack and install

From this repository:

```bash
npm ci
npm run check
mkdir -p .artifacts
npm pack --pack-destination .artifacts
```

Install the resulting `.tgz` in a clean Medusa 2.17.2 backend. Do not use an
`npm link` or workspace reference: the test must exercise only files that npm
will publish.

```bash
npm install --save-exact /absolute/path/to/makecrypto-medusa-plugin-makepay-1.0.1.tgz
```

Create a fresh database, configure the plugin as shown in the README, including
`@medusajs/medusa/locking-postgres` with ID `makepay-postgres` and
`lockingProvider: "makepay-postgres"` in the shared plugin/provider options,
and run:

```bash
npx medusa db:migrate
npm run build
npm run start
```

The repository's `npm run test:integration` performs the corresponding
packed-artifact install, migration, and build smoke test automatically against
`DATABASE_URL`. Its generated Medusa application also enables the PostgreSQL
locking provider so the published configuration is exercised rather than only
type-checked.

## Public HTTPS callback

With the Medusa backend running on port 9000:

```bash
cloudflared tunnel --url http://127.0.0.1:9000
```

Copy the generated `https://…trycloudflare.com` origin into `backendUrl`,
restart Medusa, and begin OAuth from **Settings → MakePay**. The URL is
temporary; repeat the connection if the tunnel hostname changes. Do not expose
an Admin instance with default credentials.

Confirm all of the following before checkout:

- The settings page reports the expected sandbox company and granted scopes.
- The OAuth webhook callback is configured and healthy at
  `/hooks/makepay/makepay_makepay` for the default provider ID.
- The MakePay provider is enabled for the test region.
- The storefront uses a publishable API key that is allowed for that region.

## Order scenario

1. Add a synthetic product to the official storefront and complete customer,
   address, delivery, and region selection.
2. Select MakePay and submit the order once.
3. Verify the awaiting-payment order exists in Medusa Admin before the browser
   leaves for MakePay.
4. Verify the hosted page's UID, amount, and fiat currency match the order.
5. Use the deterministic signed contract fixture to post a completion event to
   `/hooks/makepay/makepay_makepay`; the MakePay sandbox currently has no
   no-funds terminal payment simulator.
6. Hold the first successful-payment workflow after the provider has durably
   recorded the event. Verify the callback returns a generic `503`, release the
   hold, and post the exact same stable delivery group again. The retry must
   return `2xx`, change the order to paid/captured exactly once, and a later
   duplicate must remain a `2xx` no-op. OAuth processing is synchronous; do not
   add a fixed wait for Medusa's generic webhook queue.
7. Verify `/app/makepay`, the order detail widget, and core Medusa payment
   details show the same amount and state.
8. Return through the backend callback and verify the storefront obtains the
   paid state from `/store/makepay/checkout-status`, not from URL claims.

Repeat with failed, canceled, expired, invalid-signature, reordered, and
duplicate events. After each unsuccessful terminal state, deliver an exactly
correlated signed `complete` for the same immutable UID and session. Assert
that the standard Medusa payment workflow captures the original payment once,
the projection becomes complete/paid, a duplicate creates no second capture,
and later failed/canceled/expired events cannot downgrade it. Also cover
return-before-webhook, webhook-before-return, closed-browser, OAuth token
refresh, disconnect/reconnect, and API-key mode.
The OAuth callback must return the generic invalid-webhook body with `401` for
a missing, stale, or bad signature and `400` for a correctly signed schema,
routing, self-contained correlation, or terminal-regression failure. Secret
lookup, locking, infrastructure, and workflow failures must return the generic
retryable `503` body. While OAuth is connected and API-key projections are
drained, posting the same request to `/hooks/payment/makepay_makepay` must
return `404` before Medusa enqueues it. Seed an undrained API-key projection
and verify the wrong-mode route returns `503`; a failure/cancellation side
effect alone must leave it at `503`. Resolve it with exact `complete` plus
Medusa paid, or with an atomically proven no-session archive plus Medusa
canceled, and verify the route changes to `404`. Repeat the inverse check for
the OAuth callback while API-key mode is active.
The API-key compatibility case continues to use
`/hooks/payment/makepay_makepay`, but plugin middleware intercepts it before
Medusa's generic payment-webhook queue. Exercise the same synchronous failure
contract as OAuth: invalid signatures and malformed signed bodies are generic
`4xx`, while an unavailable/mismatched authoritative MakePay snapshot or a
transient/workflow failure is `503`; the corrected or identical redelivery
succeeds exactly once.
Verify that only a signed legacy event whose server-fetched payment-link
snapshot matches amount, currency, UID, session, and status can affect Medusa.
Caller-supplied delivery-group headers must not control legacy deduplication; a
semantically identical authenticated event is a no-op after the first terminal
effect.

Connect two isolated Medusa installations to the same sandbox company. Assert
that each subscription targets its own HTTPS
`/hooks/makepay/makepay_<providerId>` endpoint, a payment created by one
installation is delivered only to that installation, and rotating or
reconnecting one does not affect the other's subscription. Rotate and then
disconnect one installation after it has issued a link; a signed late event
from its prior subscription must verify only against that link's exact local
projection and encrypted historical credential, without exposing that secret
or routing the event to the other installation.

Exercise the order-metadata patch race with a deferred, pre-signed canonical
event. After local order correlation, an event with both order IDs absent may
proceed only when its creation time is inside the closed projection-to-order
lifecycle window (including at most 60 seconds of clock skew). Too-old,
after-boundary, malformed-date, and wrong non-empty order-ID fixtures must fail
closed. Never write the signed body or signing secret to the E2E output.

## Screenshot evidence

Screenshots are release artifacts, not substitutes for assertions. The browser
captures the four candidate views while their shared unpaid order still
exists, but the candidates remain unaccepted until the complete Playwright
scenario and the parent harness cleanup both pass:

1. Connected MakePay settings.
2. MakePay payments list.
3. MakePay order-detail widget.
4. Hosted MakePay sandbox checkout opened from the storefront.

For each image, assert the expected browser URL and visible page landmarks
before capture. Every declared text and test-ID landmark must intersect the
1440x900 viewport and be unobscured at its center hit point immediately before
and after the screenshot, then inspect the saved image at original resolution.
Reject it if it contains Codex/chat UI, DevTools, credentials, access tokens,
real customer data, or an unrelated page. The README intentionally declares
fixed
`v1.0.0/.github/assets/v1.0.0/` image URLs before capture so the packed npm
artifact can be frozen first. Do not change those links or any packed file
after the real run; add the approved image bytes only under the npm-excluded
`.github/assets/v1.0.0/` path.

Release screenshots must come from the opt-in real-sandbox run. Deterministic
contract screenshots are useful for UI regression diagnosis, but the release
gate rejects them. Use only a dedicated, publication-safe sandbox company and
fixed `example.com` buyer data. Supply clean HTTPS endpoints with placeholders
replaced by the approved sandbox values, plus exactly one login mode:

```bash
export MAKEPAY_E2E_REAL_SANDBOX=1
export MAKEPAY_E2E_NO_FUNDS_ACK=SANDBOX_DO_NOT_SEND_FUNDS
export MAKEPAY_E2E_REAL_API_URL=https://approved-makecrypto-api.example
export MAKEPAY_E2E_REAL_CHECKOUT_URL=https://approved-makepay-checkout.example
export MAKEPAY_E2E_REAL_OAUTH_ISSUER_URL=https://approved-oauth-issuer.example
export MAKEPAY_E2E_SANDBOX_COMPANY_ID=company_sandbox_id
export MAKEPAY_E2E_SANDBOX_COMPANY_NAME='Publication-safe Sandbox Merchant'
export MAKEPAY_PLUGIN_TARBALL=/absolute/path/to/makecrypto-medusa-plugin-makepay-1.0.1.tgz
export MAKEPAY_PLUGIN_TARBALL_SHA256=64_lowercase_hex_plugin_sha256
export MAKEPAY_SDK_TARBALL=/absolute/path/to/makecrypto-makepay-0.4.0.tgz
export MAKEPAY_SDK_TARBALL_SHA256=64_lowercase_hex_sdk_sha256

# Choose this owner-only file outside the repository OR manual OAuth below.
export MAKEPAY_E2E_STORAGE_STATE=/absolute/path/outside/repository/sandbox-storage-state.json
unset MAKEPAY_E2E_MANUAL_OAUTH

export MAKEPAY_E2E_CAPTURE=1
export MAKEPAY_E2E_SCREENSHOT_PUBLICATION_ACK=PUBLIC_SANDBOX_DATA_ONLY
npm run test:e2e:real-sandbox
npm run test:e2e:screenshots
```

The real run accepts either an owner-only (`0600`) Playwright storage-state
file for the dedicated sandbox login or manual OAuth in a fresh headed Chrome
context. For manual OAuth, keep the same required sandbox variables above and
replace only the login-mode selection:

```bash
export MAKEPAY_E2E_MANUAL_OAUTH=1
unset MAKEPAY_E2E_STORAGE_STATE
npm run test:e2e:real-sandbox
```

Manual mode never attaches to a personal Chrome profile and never reads or
persists the password or 2FA value. Complete login and consent in the opened
window. The test stops on the untouched hosted sandbox page before selecting
an asset, opening a wallet, displaying/copying a deposit address, or sending
funds.

After the hosted-page and screenshot assertions, the restricted backend helper
creates deterministic, signed `failed` and `complete` webhook fixtures only
for the two correlated payments owned by that run. These fixtures do not
change the remote MakePay payment status and cannot select an asset, open a
wallet, create/copy a deposit address, or move funds. The run must prove that
`failed` leaves the order uncaptured, `complete` produces exactly one Medusa
capture, duplicate delivery is a no-op, a later pending event cannot regress
either terminal state, and the exact return URL configured on the hosted link
rechecks server-side status before redirecting the browser to the confirmed
storefront order. Remote sandbox links are then archived while the verified
local terminal projections remain intact.

Real-sandbox Playwright results and automatic failure context are written only
inside the private temporary workspace beside the parent-owned completion
receipt. The cleanup path deletes both regardless of `--keep` or whether the
wider workspace must be retained; only separately sanitized runtime logs may
be published under repository output.

The storage-state file must be a regular file owned by the current user, have
mode `0600`, live outside the repository, and contain only cookies/origins for
the approved OAuth issuer. The runner rejects missing or simultaneous login
modes, endpoint URLs with credentials/query/fragment, and storage state from
another site.

The candidate gate verifies image hashes, dimensions, captured URLs, and page
landmarks; it also requires one company/payment/order/amount/currency
correlation across all four images. Both capture modes start with a pending
completion attestation. The parent harness accepts deterministic QA candidates
only after the exact complete two-test Playwright report and parent-owned
process/database/log/secret/workspace cleanup pass, so a partial or
cleanup-interrupted manifest cannot pass the candidate gate. For real-sandbox
evidence, only the parent harness can atomically replace the pending value with
a digest-bound release-run acceptance after the entire Playwright scenario,
payment-link archival, OAuth disconnect, process/database shutdown, secret
scrubbing, and workspace disposition succeed. A test failure, signal, cleanup
warning, or post-acceptance evidence change therefore blocks both candidate
and release gates. The manifest stores only URL origins and paths—never OAuth
state, hosted-checkout query values, or runtime secrets. Deterministic
acceptance remains QA-only and never receives release-run acceptance. The gate
cannot perform visual judgment. After viewing one PNG at original resolution,
record that review in a repository checkout (repeat for all four):

```bash
node tests/e2e/screenshot-gate.mjs \
  --manifest output/playwright/medusa-makepay/evidence/manifest.json \
  --approve-visual connected-makepay-settings \
  --reviewer 'Named original-resolution reviewer' \
  --check candidate
```

Copy only approved images byte-for-byte to
`apps/makecrypto/public/images/documentation/apps/medusa/`. Run the MakeCrypto
documentation Playwright test with `MAKEPAY_MEDUSA_EVIDENCE_REQUIRED=1`,
`MAKEPAY_MEDUSA_EVIDENCE_MANIFEST` set to this manifest, and
`MAKEPAY_MEDUSA_DOCS_REVIEW_DIR` set to its `review-artifacts` directory. The
test fails closed unless each final HTTP response is an unredirected `200
image/png`, its bytes match the manifest SHA-256, it decodes at 1440x900, its
exact caption and `currentSrc` match, and a unique 1440x960 rendered-page PNG
and bound receipt are written. Evidence mode rejects an external documentation
base URL and starts a fresh server from the reviewed MakeCrypto checkout; the
document response itself must be an unredirected local `200 text/html`.

```bash
cd /absolute/path/to/makeswap/apps/makecrypto
MAKEPAY_MEDUSA_EVIDENCE_REQUIRED=1 \
MAKEPAY_MEDUSA_EVIDENCE_MANIFEST=/absolute/path/to/plugin/output/playwright/medusa-makepay/evidence/manifest.json \
MAKEPAY_MEDUSA_DOCS_REVIEW_DIR=/absolute/path/to/plugin/output/playwright/medusa-makepay/evidence/review-artifacts \
pnpm test:docs-ui
```

Inspect that rendered page at original resolution, then record the second
review with:

```bash
node tests/e2e/screenshot-gate.mjs \
  --manifest output/playwright/medusa-makepay/evidence/manifest.json \
  --approve-docs connected-makepay-settings \
  --docs-receipt output/playwright/medusa-makepay/evidence/review-artifacts/docs-connected-makepay-settings-receipt.json \
  --published-root /absolute/path/to/makeswap/apps/makecrypto/public \
  --reviewer 'Named rendered-docs reviewer' \
  --check candidate
```

The receipt and rendered PNG must be regular non-symlink files inside the
evidence directory. The public root must belong to the MakeCrypto package, and
the published image must be an owner-controlled byte match for the selected
source. The gate binds the receipt to the accepted run digest, source
filename/hash, exact caption/public path, served response, docs source hash,
viewport, and rendered hash. The manifest records only portable relative paths
and digests. Finally require:

```bash
node tests/e2e/screenshot-gate.mjs \
  --manifest output/playwright/medusa-makepay/evidence/manifest.json \
  --published-root /absolute/path/to/makeswap/apps/makecrypto/public \
  --backend-origin https://the-exact-backend-tunnel.example \
  --checkout-origin https://the-approved-makepay-sandbox.example \
  --plugin-sha256 "$PLUGIN_SHA256" \
  --plugin-version 1.0.1 \
  --sdk-sha256 "$SDK_SHA256" \
  --sdk-version 0.4.0 \
  --check release
```

Set `PLUGIN_SHA256` and `SDK_SHA256` from an independent hash of the exact
tarballs installed by the real run; do not copy them from the evidence
manifest. The origins must exactly match the approved real run. Release fails
for a deterministic manifest, missing or invalid post-run harness acceptance,
artifact-provenance mismatch, a query-bearing URL, missing correlation, or a
changed image/receipt/rendered-document hash or MakeCrypto source/public image.
Release also fetches the hard-coded official `https://www.makecrypto.io`
Medusa documentation and all four images with redirects disabled, requiring
the exact figures, captions, MIME types, dimensions, and manifest byte hashes.
The trusted-publishing workflow also renders that official page in Chromium
and requires every figure to be decoded, visible, in-viewport, unobscured, and
free of runtime errors. No screenshot is publication-ready until the scenario
and cleanup acceptance succeed and all four original-resolution images and
their rendered documentation have been inspected and approved.

Deploy the reviewed MakeCrypto documentation before creating the plugin tag.
For the tagged npm release, copy the complete approved evidence bundle
(manifest, four PNGs, and relative `review-artifacts`) without rewriting it to
`.github/assets/v1.0.0/`. Snapshot the reviewed MakeCrypto `package.json`,
`content/documentation/apps/medusa.mdx`, and four public images below
`.github/assets/v1.0.0/makecrypto/`, preserving their paths. Configure the
repository variables
`MAKEPAY_EVIDENCE_BACKEND_ORIGIN` and `MAKEPAY_EVIDENCE_CHECKOUT_ORIGIN` from
the independently approved run. The trusted-publishing workflow downloads and
hashes the registry SDK again, hashes the exact plugin candidate, and reruns
the release gate against that committed bundle before npm publication.
