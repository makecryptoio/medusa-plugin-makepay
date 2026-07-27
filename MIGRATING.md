# Migrating from 0.2.0 to 1.0.0

Version 1.0.0 is the first stable release and intentionally follows 0.2.0; no
intervening package versions were published. This migration is additive, but
it raises the minimum Node.js and Medusa versions and changes the
hosted-payment lifecycle.

## Before upgrading

1. Upgrade the Medusa backend and Admin to 2.17.2 or newer, but remain on
   Medusa 2.x. Use Node.js 22 or newer; CI tests Node.js 22 and 24.
2. Back up the Medusa database and record the currently enabled MakePay
   provider ID. The default remains `pp_makepay_makepay`.
3. Drain every 0.2.0 MakePay link before deploying 1.0.0. Confirm that it is
   paid in Medusa or that MakePay can prove no remote payment session can still
   settle; a failed, expired, or cancelled label alone is not enough. The
   additive migration does not bulk-backfill local projections for pre-1.0.0
   sessions. A narrowly authenticated fallback can recover an exact default
   API-key link from its signed callback, authoritative MakePay snapshot, and
   matching Medusa payment session, but custom provider IDs or incomplete
   legacy metadata do not qualify. This recovery path is defense in depth, not
   a substitute for the required pre-upgrade drain.
4. Keep the existing MakePay API credentials available until the first 1.0.0
   checkout has passed in API-key mode or OAuth has connected successfully.
5. Generate a dedicated encryption key for this Medusa installation:

   ```bash
   openssl rand -base64 32
   ```

   Store it in the backend secret manager as `MAKEPAY_ENCRYPTION_KEY`. Losing
   this value makes stored OAuth credentials unreadable. Reusing it between
   unrelated environments weakens isolation.

Version 1.0.0 supports only `providers[].id: "makepay"`, producing
`pp_makepay_makepay`. Drain payment sessions from a custom 0.2.0 provider ID,
change the configuration to `makepay`, and enable `pp_makepay_makepay` on each
region before opening checkout. One plugin registration does not support
multiple independent MakePay connections. Registration only makes the provider
available for region configuration; it does not enable any region
automatically. After changing region providers, invalidate the storefront's
cached provider response, retrieve the cart again, and reload or re-enter
checkout. Update or recreate the cart only if `cart.region.id` is not a region
you enabled.

Version 1.0.0 also validates the hosted redirect origin. If MakePay issued
0.2.0 links on a merchant-branded payment domain, set `checkoutBaseUrl` to that
exact HTTPS origin before upgrading. Leave it unset only when returned links
use `https://makepay.io` or `https://www.makepay.io`. Paths, query strings,
fragments, credentials, lookalike domains, and unexpected subdomains are not
valid `checkoutBaseUrl` values.

## Upgrade

Install the exact version and update the plugin configuration described in the
[README](./README.md):

```bash
npm install --save-exact @makecrypto/medusa-plugin-makepay@1.0.0
npx medusa db:migrate
npm run build
```

OAuth also requires Medusa's PostgreSQL locking provider. Add this module and
pass the same provider ID in both the plugin and payment-provider options:

```ts
const makePayOptions = {
  authMode: "oauth" as const,
  // backendUrl, storefrontReturnUrl, encryptionKey, ...
  lockingProvider: "makepay-postgres",
};

const modules = [
  {
    resolve: "@medusajs/medusa/locking",
    options: {
      providers: [
        {
          resolve: "@medusajs/medusa/locking-postgres",
          id: "makepay-postgres",
          is_default: true,
        },
      ],
    },
  },
  // Payment Module with options: makePayOptions
];
```

`@medusajs/medusa/locking-postgres` is included with Medusa. Do not install a
similarly named standalone package. Version 1.0.0 refuses OAuth startup when
`lockingProvider` is omitted or points to the in-memory provider, because that
cannot serialize token refresh across backend processes. Run `medusa
db:migrate` after adding the module so its lock table and the plugin's additive
tables exist before traffic reaches the upgraded backend.

Run migrations once for each environment before serving traffic with the new
package. The migration adds MakePay connection, OAuth state, payment
projection, webhook-delivery, and historical webhook-subscription tables; it
does not rewrite core Medusa orders or payments. Later additive migrations
bind OAuth projections to their grant-scoped webhook subscription, retain the
encrypted verification credential for an already-issued link across a safe
disconnect or rotation, and align the connection scope column with Medusa's
PostgreSQL `text[]` model. Run the complete migration set even if a prerelease
build previously created the MakePay tables; existing JSON-array scope values
are preserved during that conversion.

## Choose an authentication mode

- **OAuth:** Configure the public backend and storefront return URLs and the
  encryption key plus the PostgreSQL locking provider, start Medusa, then
  visit **Settings → MakePay → Connect**.
  Complete consent as a MakeCrypto company administrator.
- **API key:** Keep `MAKEPAY_KEY_ID`, `MAKEPAY_KEY_SECRET`, and
  `MAKEPAY_WEBHOOK_SECRET`. Omitting `authMode` while those values are present
  preserves 0.2.0's credential-based mode selection. Explicit
  `authMode: "api_key"` is clearer. A `lockingProvider` is optional for this
  compatibility mode only while the installation has no stored OAuth
  authorization state, connection, or payment history. Configuring the PostgreSQL provider
  adds cross-process payment-effect serialization and enables safe Admin
  reconciliation; API-key checkout requires it after OAuth has been
  configured.

An official Medusa OAuth connection has no inactivity expiry. Its access token
is deliberately short-lived and rotates automatically under the distributed
lock, including when the store first makes a request after more than 30 days
offline. Treat the access-token timestamp as the next renewal time, not as a
reason to reconnect. Explicit disconnect, revocation, security reset,
refresh-token reuse, or loss of the complete refresh family still ends access.

Reconnect key rotation is staged. The new private key is persisted before
registration; registration proves possession of that submitted key, and a
replacement also requires proof from the currently accepted key. Abandoning
consent leaves the old token family usable. If a pending replacement key is
lost, the accepted previous key can authorize another replacement. Completing
consent binds the grant to the new key and revokes the complete old access and
refresh-token family.

If consent completes but its browser callback never reaches Medusa, that
revoked old family cannot be refreshed. Keep the connection row and use the
Admin **Reconnect** action; retained registration keys allow a fresh consent
to replace the authorization. A pending disconnect exposes both **Retry
disconnect** and **Reconnect** for this reason.

Admin also distinguishes an ordinary terminal refresh failure from a
temporary issuer or network outage. A terminal failure is shown as
**Reconnect required** with **Reconnect** as the primary action. A retryable
failure remains eligible for automatic recovery and is not presented as
first-time setup or as requiring reconnect.

Do not change a connected installation from OAuth to API-key mode while it has
undrained OAuth-created links. Pending links and complete links without a paid
Medusa payment are undrained. A failed, expired, or ordinarily cancelled link
that ever had a remote payment session is also intentionally undrained because
an exact `complete` can still arrive after late settlement; recording only the
Medusa failure/cancellation side effect is insufficient. A link is safe only
after exact `complete` plus Medusa paid, or after MakePay atomically proves it
was archived before any remote payment session existed and Medusa records it
canceled. A pre-0.4 installation without distributed locking must stop every
backend worker and enter maintenance before its first mode transition;
configure the PostgreSQL lock before restarting. If an emergency switch
already happened, restore the OAuth connection for an authenticated redelivery
before creating a new API-key payment attempt.

OAuth requires a public HTTPS callback and webhook URL. For local testing, use
the tunnel procedure in [Local end-to-end testing](./docs/local-e2e.md); never
publish a development server without its normal authentication controls.

## Webhook callback paths

OAuth connections in 1.0.0 automatically provision the plugin-owned,
synchronous callback. With the default provider ID it is:

```text
https://your-medusa-backend.example/hooks/makepay/makepay_makepay
```

The callback returns `2xx` only after the correlated provider update and, for
successful payments, Medusa's standard payment workflow have completed.
Transient provider, database, or workflow failures return a generic `503` so
MakePay can redeliver the stable delivery group without causing a second
capture. If an OAuth connection was created with a prerelease version that
registered `/hooks/payment/...`, reconnect it after upgrading so MakeCrypto
stores the new callback. Version 1.0.0 returns `404` for the legacy MakePay
callback while OAuth mode is active and API-key projections are drained. If a
forced switch left an API-key projection undrained, the inactive callback
returns `503` instead, preserving redelivery until API-key mode is restored and
the payment is resolved. The OAuth callback has the same `503`-until-drained,
then-`404` behavior if the current configuration is API-key mode.

Existing API-key integrations keep their original callback:

```text
https://your-medusa-backend.example/hooks/payment/makepay_makepay
```

Version 1.0.0 preserves that URL, but plugin middleware now intercepts MakePay
callbacks before Medusa's generic payment-webhook handler. Signature and
correlation validation, local projection updates, and required Medusa payment
effects complete synchronously. A `2xx` response therefore means the
correlated effects completed. Invalid signatures and malformed signed bodies
receive a generic `4xx`. An unavailable or mismatched authoritative MakePay
snapshot, or a transient database, locking, or workflow failure, receives a
generic `503` for upstream redelivery while no payment effect is applied. Keep
MakePay redelivery and projection monitoring enabled.

## Storefront behavior change

In 0.2.0, hosted checkout returned `requires_more`. Version 1.0.0 uses
`pending_authorization`: the storefront completes the cart first, Medusa
creates an awaiting-payment order, and the browser then follows the public
`next_action.url`. Update custom storefronts using
[the hosted-checkout example](./docs/storefront.md).

Only public checkout data remains in `payment_session.data`. Code that read
the former `paymentLink`, `raw_response`, or `latest_session` objects must use
the authenticated Admin endpoints or the limited storefront checkout-status
endpoint instead. The duplicate 0.2.0 aliases were also removed: use
`payment_link_uid` instead of `id`/`paymentLinkUid`, `public_url` or
`next_action.url` instead of `checkout_url`, and `fiat_currency` instead of
`fiatCurrency`.

Version 1.0.0 also ignores per-session `data.return_url`, `data.success_url`,
and `data.failure_url` (including camel-case variants). This prevents
storefront-controlled session data from overriding server-approved redirect
destinations. Configure the provider-level URL options, or preferably the
managed `backendUrl` plus `storefrontReturnUrl`, in backend configuration.
Provider-level legacy return/success/failure URLs may retain their query
parameters, but they must now be absolute HTTPS URLs (loopback HTTP is allowed
for tests) without embedded credentials or fragments.

Version 0.2.0 also forwarded arbitrary `PaymentSession.data.metadata` fields to
MakePay. Version 1.0.0 intentionally sends only its server-generated Medusa
correlation metadata so untrusted or secret session fields cannot become part
of a payment link or signed callback. Keep merchant-specific data on the
Medusa order (or another authenticated local record) and do not depend on
custom MakePay link metadata after upgrading.

Each new Medusa payment session now owns one immutable MakePay payment-link
UID. Finalize items, discounts, shipping, region, and currency before creating
the session. If any value affecting the total or currency changes, retrieve
the refreshed cart and initiate a new Medusa payment session. Do not call a
provider update to reprice or replace the issued UID. Medusa's 2.17.2 JS SDK
accepts the complete cart object as the first argument to
`initiatePaymentSession`.

## Refund limitation

MakePay does not expose a safe merchant-initiated refund API in version 1.0.0.
Automated provider refund calls therefore return an explicit unsupported error
and create no Medusa refund record. The custom MakePay Admin views do not offer
a refund action; handle any required return through the merchant support and
accounting workflow, and do not mark it refunded in Medusa until settlement has
actually been returned.

## Verify and roll back

Before opening checkout to customers, verify provider enablement for every
region, invalidate any cached provider list, retrieve the cart again, and run
one complete sandbox order. Confirm that the order exists before redirect, one
signed webhook marks it paid exactly once, and the MakePay row and order widget
agree. For OAuth, also force one transient workflow failure,
verify the synchronous callback returns `503`, redeliver the same stable group,
and verify that the retry returns `2xx` with exactly one capture. Then test an
exact, signed `complete` after each of `failed`, `expired`, and `cancelled`:
only the original session and UID may be reopened, the order must be captured
once, and later unsuccessful events must not downgrade it.

Rolling application code back to 0.2.0 does not require dropping the new
tables. Leave additive tables in place so OAuth and delivery history are not
destroyed, and retain the encryption key while an already-issued link can still
settle. API-key mode can be used as an operational fallback only after every
OAuth-created link is safely drained as described above.

Before moving any existing no-lock API-key installation to OAuth, stop all
0.2.0/no-lock workers, drain all links, run the migrations, and deploy one
consistent distributed `lockingProvider` configuration to every backend
worker. Do not roll API-key/no-lock and OAuth/locked workers concurrently.
