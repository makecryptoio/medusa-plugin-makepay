# Medusa 2.17.2 end-to-end harness

This harness installs the packed npm artifact into a freshly generated official
Medusa application and Next.js starter. It never uses `npm link`, a workspace
reference, or source imports from this repository.

## Deterministic run

Prerequisites are Node.js 22+ and PostgreSQL 16+ command-line tools (`initdb`,
`pg_ctl`, and `createdb`). The runner creates a temporary trust-only PostgreSQL
cluster bound to `127.0.0.1`, chooses a fresh database, and stops and removes it
at the end. It does not start or alter a system PostgreSQL service.

Install Chromium once, then run:

```bash
npx playwright install chromium
npm run test:e2e:medusa
```

The default run:

1. builds and packs this package;
2. scaffolds `create-medusa-app@2.17.2` with the official storefront and seed;
3. installs the tarball in `@dtc/backend`;
4. applies the version-checked MakePay storefront integration fixture;
5. migrates and builds the backend and storefront;
6. connects through a local OAuth/PKCE/DPoP contract server;
7. creates the seeded EUR 20 order in the browser;
8. verifies the hosted sandbox page and fake address;
9. injects one post-projection Medusa workflow failure, verifies the projection
   is durable while the order still has zero captures, then retries against two
   backend processes with one stable delivery-group ID and distinct attempt
   UUIDs;
10. exercises the configured `@medusajs/medusa/locking-postgres` provider and
    verifies the retries produce exactly one capture;
11. checks the Admin payments page and order widget;
12. prepares a signed `complete` before order correlation, rejects too-old,
    too-new, malformed, and wrong-order variants, then delivers the frozen
    in-window event and verifies exactly one capture;
13. creates fresh `failed`, `cancelled`, and `expired` orders, verifies they
    have no capture or fulfillment, disconnects with two simulated native-reset
    response losses, and recovers by replaying the same reset receipt;
14. reconnects with rotated OAuth credentials and verifies the preserved
    historical signing credentials can upgrade each original terminal session
    to paid exactly once without changing its payment-link UID; and
15. mutates an API-key cart through the Medusa store API, verifies the native
    refresh safely archives the old link/session, initiates one new session and
    UID, rejects same-session repricing, and captures only the replacement.

The suite also attempts a EUR 5 Medusa refund and verifies the provider's
explicit manual-refund boundary leaves no refund record.

Failed runs retain the temporary project and logs automatically; `--keep` also
retains a successful run. A
pre-generated project may be supplied with `MAKEPAY_E2E_PROJECT_ROOT`; pair it
with the database it was seeded against using `MAKEPAY_E2E_DATABASE_URL`.
`--skip-browser` is only a deterministic, no-capture setup/build/service smoke;
it is rejected for real-sandbox, screenshot-capture, and local-diagnostics
runs and never represents scenario acceptance.

The contract fixture alone is fast and has no PostgreSQL/browser dependency:

```bash
npm run test:e2e:contract
```

Before `@makecrypto/makepay@0.4.x` is published, set
`MAKEPAY_SDK_TARBALL=/absolute/path/to/makecrypto-makepay-0.4.0.tgz` together
with `MAKEPAY_SDK_TARBALL_SHA256=<independently-computed-lowercase-sha256>`. The
runner verifies and installs that exact packed SDK into the generated backend
before the packed plugin. Release/CI runs leave both unset and verify the
registry dependency.

To test an already-frozen plugin candidate instead of repacking the working
tree, set `MAKEPAY_PLUGIN_TARBALL` and its independently computed
`MAKEPAY_PLUGIN_TARBALL_SHA256`. The runner verifies the package name, exact
version, and digest before installation.

## Strict no-funds boundary

The deterministic contract server accepts only sandbox links and emits only
addresses prefixed `SANDBOX-DO-NOT-SEND-`. It refuses a link payload that asks
for `sandbox: false`.

The opt-in real MakePay smoke is allowed to perform only these operations:

- connect OAuth to a dedicated sandbox company;
- create/list/archive a sandbox payment link;
- open the hosted sandbox checkout and verify its amount and warning;
- stop before selecting an asset, opening a wallet, copying a deposit address,
  or sending cryptocurrency.

It must not send any cryptocurrency, use a non-sandbox company, interpret a
fake address as paid, or attempt an on-chain settlement/refund. Captured,
failed, canceled, duplicate, stale, and reordered webhooks are deterministic
signed simulations, not evidence of real MakePay settlement. Automated refunds
are not claimed because MakePay currently exposes no general refund API.

The real smoke is locked behind all of the following:

```bash
export MAKEPAY_E2E_REAL_SANDBOX=1
export MAKEPAY_E2E_NO_FUNDS_ACK=SANDBOX_DO_NOT_SEND_FUNDS
export MAKEPAY_E2E_REAL_API_URL=https://your-approved-makecrypto-api.example
export MAKEPAY_E2E_REAL_CHECKOUT_URL=https://your-approved-makepay-checkout.example
export MAKEPAY_E2E_REAL_OAUTH_ISSUER_URL=https://your-approved-oauth-issuer.example
export MAKEPAY_E2E_SANDBOX_COMPANY_ID=company_sandbox_id
export MAKEPAY_E2E_SANDBOX_COMPANY_NAME='Sandbox Merchant Name'
export MAKEPAY_PLUGIN_TARBALL=/absolute/path/to/makecrypto-medusa-plugin-makepay-1.0.1.tgz
export MAKEPAY_PLUGIN_TARBALL_SHA256=64_lowercase_hex_plugin_sha256
export MAKEPAY_SDK_TARBALL=/absolute/path/to/makecrypto-makepay-0.4.0.tgz
export MAKEPAY_SDK_TARBALL_SHA256=64_lowercase_hex_sdk_sha256
export MAKEPAY_E2E_STORAGE_STATE=/absolute/path/to/sandbox-login-storage-state.json
npm run test:e2e:real-sandbox
```

The runner creates separate temporary Cloudflare tunnels for the backend and
storefront. The storage-state file must contain only a dedicated sandbox test
login, stay outside the repository, and be owner-only (`0600`). Alternatively,
unset it and set `MAKEPAY_E2E_MANUAL_OAUTH=1`; Playwright opens a fresh headed
Chrome context for manual login/2FA and never attaches to a personal profile.

Every run-owned sandbox payment-link UID and OAuth routing tuple is recorded in
an atomically replaced, owner-only ledger as soon as its local projection is
observed. Before reconnecting installation B, the test archives its old link,
GET-verifies `archived`, and verifies the local projection is
`cancelled`/`canceled`. Final disconnect is deliberately owned by the runner:
it first stops Playwright, the storefront, and both Medusa HTTP processes so no
in-flight request can create another link; then a restricted `medusa exec`
helper enumerates both local projections and remote links using the exact
run-owned `example.com` emails, archives and independently re-reads each link,
verifies local cancellation, and only then disconnects OAuth. A missing remote
enumeration, unresolved UID, unknown database state, or unconfirmed disconnect
is a release-blocking `MANUAL CLEANUP BLOCKER`; the runner leaves credentials
available rather than revoking the only grant that can complete archival.

`SIGINT` and `SIGTERM` use the same ordered cleanup path with bounded helper
deadlines. `SIGKILL` or machine loss cannot be caught; if that happens, use the
safe IDs in the retained ledger to verify archival before release. Harness
evidence and sanitized runtime logs live under the marker-owned
`output/playwright/medusa-makepay` tree. Real-sandbox Playwright results,
including automatic failure context, live only beside the parent-owned
completion receipt in the private temporary workspace and are deleted even
when the wider workspace must be retained. Any symlink, foreign owner, invalid
marker, or unknown top-level entry makes recursive cleanup fail closed.

## Screenshot evidence gate

Deterministic screenshots are optional QA diagnostics and are captured only
after the relevant assertions. They are not release evidence:

```bash
MAKEPAY_E2E_CAPTURE=1 npm run test:e2e:medusa
```

Release candidates require the real-sandbox command and an explicit assertion
that the dedicated company and synthetic data are safe to publish:

```bash
export MAKEPAY_E2E_CAPTURE=1
export MAKEPAY_E2E_SCREENSHOT_PUBLICATION_ACK=PUBLIC_SANDBOX_DATA_ONLY
npm run test:e2e:real-sandbox
```

Candidates are written under `output/playwright/medusa-makepay/evidence`. The
manifest stores provenance, canonical origin/path (never query or fragment),
title, viewport, landmarks, run ID, a shared payment correlation, timestamp,
and SHA-256. During Playwright it carries a pending completion attestation.
For deterministic QA captures, the parent harness verifies the exact complete
two-test Playwright report plus process, database, log, secret, and workspace
cleanup before adding a digest-bound QA acceptance; a partial or
cleanup-interrupted manifest cannot pass the candidate gate. Only after the
full real-sandbox scenario passes and the parent harness
successfully verifies payment-link archival, OAuth disconnect, process and
database shutdown, secret scrubbing, log publication, and workspace
disposition does the harness atomically add a digest-bound acceptance. A
mid-test manifest, failed or signal-interrupted run, cleanup warning, or
evidence change after acceptance fails the candidate and release gates.
Deterministic acceptance remains QA-only and can never satisfy the release
gate.
The images are browser page screenshots at exactly 1440x900; the harness never
takes an operating-system, terminal, Codex, or chat capture. Immediately
before and after each screenshot, every declared text and test-ID landmark must
intersect the 1440x900 viewport and pass a center-point hit test showing it is
not covered by another element.

Before release, each candidate has two independent review gates:

1. Open the PNG at original resolution (for Codex, use `view_image`) and reject
   it for unrelated UI, stale/loading/error state, clipping, real customer data,
   credentials, or a mismatch with its intended caption. Then record the visual
   approval with `screenshot-gate.mjs --approve-visual`.
2. Copy the approved image byte-for-byte into MakeCrypto's Medusa public image
   directory. Run the MakeCrypto documentation Playwright evidence test in
   fail-closed manifest mode. It verifies the final image response, MIME type,
   SHA-256, decoded dimensions, exact caption, and `currentSrc`, then writes one
   1440x960 rendered-page PNG and one bound JSON receipt per image. Evidence
   mode rejects external/reused servers and requires an unredirected local `200
text/html` document response from the reviewed checkout. Inspect that
   rendered result and record `--approve-docs` with its receipt.

For example, after those two inspections:

```bash
node tests/e2e/screenshot-gate.mjs \
  --manifest output/playwright/medusa-makepay/evidence/manifest.json \
  --approve-visual connected-makepay-settings \
  --reviewer 'Codex original-resolution QA' \
  --check candidate

node tests/e2e/screenshot-gate.mjs \
  --manifest output/playwright/medusa-makepay/evidence/manifest.json \
  --approve-docs connected-makepay-settings \
  --docs-receipt output/playwright/medusa-makepay/evidence/review-artifacts/docs-connected-makepay-settings-receipt.json \
  --published-root /absolute/path/to/makeswap/apps/makecrypto/public \
  --reviewer 'Codex rendered-docs QA' \
  --check candidate
```

The receipt and rendered review PNG must be unique, regular, non-symlink files
inside the evidence directory. The published image must be an owner-controlled
regular file below the canonical MakeCrypto public root and must byte-match the
selected source screenshot. The gate also binds the receipt to the accepted run
digest, exact source filename/hash, caption, public path, served response, docs
source hash, viewport, and rendered-page hash. The manifest persists only
portable relative artifact paths and digests.

Finally run:

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
installed tarballs rather than from the manifest. The release gate fails for
deterministic provenance, missing or invalid post-run harness acceptance,
artifact/origin/correlation mismatch, query-bearing URLs, an incomplete
review, any PNG/rendered-doc hash change, or a changed local MakeCrypto
source/public image. Release also fetches the hard-coded official
`https://www.makecrypto.io` Medusa page and all four images with redirects
disabled, and requires exact figures, captions, MIME types, dimensions, and
manifest byte hashes. The trusted-publishing workflow additionally renders
that hard-coded official page in Chromium and requires every figure to be
decoded, visible, in-viewport, unobscured, and free of runtime errors. Candidate
images are never copied automatically into `assets/`.

Deploy the reviewed MakeCrypto documentation before tagging. Copy the complete
approved evidence bundle unchanged to `.github/assets/v1.0.0/`. Also snapshot
the reviewed MakeCrypto `package.json`,
`content/documentation/apps/medusa.mdx`, and four public images below
`.github/assets/v1.0.0/makecrypto/`, preserving their paths. Configure the
independent repository variables
`MAKEPAY_EVIDENCE_BACKEND_ORIGIN` and
`MAKEPAY_EVIDENCE_CHECKOUT_ORIGIN`. The npm trusted-publishing workflow blocks
unless the committed manifest, images, relative review artifacts, exact plugin
candidate, and freshly downloaded registry SDK all pass the release gate.
