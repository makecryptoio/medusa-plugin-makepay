# MakePay for Medusa

[![npm version](https://img.shields.io/npm/v/@makecrypto/medusa-plugin-makepay.svg)](https://www.npmjs.com/package/@makecrypto/medusa-plugin-makepay)
[![CI](https://github.com/makepay-apps/medusa-plugin-makepay/actions/workflows/ci.yml/badge.svg)](https://github.com/makepay-apps/medusa-plugin-makepay/actions/workflows/ci.yml)

<p align="center">
  <img src="./assets/makepay-medusa-icon.png" alt="MakePay icon" width="96" height="96" />
</p>

Official MakePay hosted cryptocurrency payments for Medusa v2. One package
contains the payment provider, MakeCrypto OAuth connection, database module,
API routes, and Medusa Admin pages/widgets—there is no separate Admin package.

Version 1.0.0 supports:

- MakeCrypto OAuth with PKCE, DPoP-bound tokens, automatic refresh, and a
  grant-scoped webhook subscription.
- The original MakePay API-key configuration as a compatibility mode.
- Medusa's `pending_authorization` flow, so the order exists before the shopper
  is redirected to hosted checkout.
- A read-only MakePay payment list, connection settings, order-detail widget,
  and server-side payment reconciliation in Medusa Admin.

Automated refunds are not supported because MakePay does not currently expose
a merchant refund API.

## Admin and checkout preview

These release-verified views come from a real MakeCrypto/MakePay sandbox using
synthetic customer data. No cryptocurrency is sent.

| Connected OAuth settings                                                                                                                                                            | MakePay payment list                                                                                                                                               |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| ![Connected MakePay OAuth settings in Medusa Admin](https://raw.githubusercontent.com/makepay-apps/medusa-plugin-makepay/v1.0.0/.github/assets/v1.0.0/connected-makepay-settings.png) | ![MakePay payment list in Medusa Admin](https://raw.githubusercontent.com/makepay-apps/medusa-plugin-makepay/v1.0.0/.github/assets/v1.0.0/makepay-payments-list.png) |

| Order payment widget                                                                                                                                              | Hosted sandbox checkout                                                                                                                                          |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ![MakePay order widget in Medusa Admin](https://raw.githubusercontent.com/makepay-apps/medusa-plugin-makepay/v1.0.0/.github/assets/v1.0.0/makepay-order-widget.png) | ![MakePay hosted sandbox checkout](https://raw.githubusercontent.com/makepay-apps/medusa-plugin-makepay/v1.0.0/.github/assets/v1.0.0/makepay-sandbox-checkout.png) |

## Requirements

- Node.js 22 or newer (CI tests Node.js 22 and 24)
- Medusa 2.17.2 or newer within the 2.x release line
- PostgreSQL, as required by Medusa
- Medusa's Locking Module enabled (OAuth token rotation fails closed without it)
- A [MakeCrypto](https://makecrypto.io) company with MakePay enabled
- A public HTTPS Medusa backend URL for production OAuth and webhooks

Upgrading from 0.2.0? Read [MIGRATING.md](./MIGRATING.md) before installing.

## Install

```bash
npm install --save-exact @makecrypto/medusa-plugin-makepay@1.0.0
```

The package must be registered twice in `medusa-config.ts`: as a plugin so
Medusa discovers its module, migrations, APIs, and Admin extensions; and as a
provider under the Payment Module.

## OAuth configuration (recommended)

Generate a unique encryption key for each environment and keep it in the
backend secret manager:

```bash
openssl rand -base64 32
```

```ts
// medusa-config.ts
import { defineConfig, Modules } from "@medusajs/framework/utils";

const makePayOptions = {
  authMode: "oauth" as const,
  backendUrl: process.env.MEDUSA_BACKEND_URL!,
  storefrontReturnUrl: `${process.env.STOREFRONT_URL!}/order/makepay-return`,
  encryptionKey: process.env.MAKEPAY_ENCRYPTION_KEY!,
  lockingProvider: "makepay-postgres",
  settlementCurrency: process.env.MAKEPAY_SETTLEMENT_CURRENCY || "USDT",
  expirationTime: "12h",
  siteName: "My Medusa store",
};

export default defineConfig({
  plugins: [
    {
      resolve: "@makecrypto/medusa-plugin-makepay",
      options: makePayOptions,
    },
  ],
  modules: [
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
    {
      resolve: "@medusajs/medusa/payment",
      options: {
        providers: [
          {
            resolve: "@makecrypto/medusa-plugin-makepay/providers/makepay",
            id: "makepay",
            options: makePayOptions,
          },
        ],
      },
    },
  ],
});
```

The [PostgreSQL locking provider](https://docs.medusajs.com/resources/infrastructure-modules/locking/postgres)
is bundled with `@medusajs/medusa`; do not install a separate locking-provider
package. OAuth startup fails when
`lockingProvider` is missing or resolves to Medusa's in-memory provider. A
distributed lock is required so concurrent workers cannot refresh or rotate
the same OAuth token family at the same time. The same
`lockingProvider: "makepay-postgres"` value must reach both the plugin and the
payment provider options, as the shared `makePayOptions` object does above.
In API-key mode it is optional only for a pure legacy installation with no
stored OAuth authorization state, connection, or payment history. Configuring it adds
cross-process payment-effect serialization and enables safe Admin
reconciliation; API-key checkout requires it after OAuth has been configured.

An official Medusa OAuth connection has no inactivity expiry. Its short-lived
access token is rotated transparently under the distributed lock, including
when the store first wakes after being offline for more than 30 days. The
connection remains usable until the merchant disconnects it, MakeCrypto
revokes its installation or token family, or a security reset invalidates the
grant. `access_token_expires_at` is therefore the next automatic renewal time,
not the connection's expiry date; do not build reconnect prompts around it.

Reconnect key rotation is staged to avoid downtime. The plugin durably saves
the proposed private key before registration, proves possession of that key,
and uses the currently accepted key to authorize a replacement. Closing or
rejecting the consent screen leaves the old token family usable. If a pending
replacement key is lost, the accepted previous key can register another one;
successful consent binds the new key and revokes the complete old access and
refresh-token family.

If consent succeeds but the browser callback never completes, MakeCrypto may
have revoked that old family before Medusa received the replacement tokens.
The old authorization cannot be refreshed back into existence. The retained
registration keys let **Reconnect** register and complete a fresh consent
without deleting the connection row. If a disconnect is already pending,
Admin intentionally offers both **Retry disconnect** and **Reconnect**; finish
the reconnect first, then disconnect again if the store should remain
disconnected.

Apply the additive plugin migration before starting the upgraded backend:

```bash
npx medusa db:migrate
```

Then:

1. Open Medusa Admin at **Settings → MakePay**.
2. Select **Connect MakePay** and complete company selection and consent.
3. Confirm the settings page reports the correct company and a healthy
   webhook.
4. Before building or deploying the storefront, open **Settings → Regions**,
   edit every region the storefront uses, and enable `pp_makepay_makepay`
   under **Payment Providers**, then save the region.
5. Verify each region with the storefront's publishable key:

   ```bash
   curl --fail --silent --show-error \
     -H "x-publishable-api-key: $MEDUSA_PUBLISHABLE_KEY" \
     "$MEDUSA_BACKEND_URL/store/payment-providers?region_id=$REGION_ID"
   ```

   Do not continue until the response includes `pp_makepay_makepay`.

Registering the package and payment provider only makes MakePay available for
region configuration; it does not enable MakePay on any region automatically.
The provider lookup uses the current cart's `region.id`, so retrieve the cart
again and confirm it belongs to a region you edited. Reload or re-enter
checkout after enabling the provider. Recreate or update the cart only if its
region is wrong or the shopper changed country/region.

The official Medusa Next.js starter fetches payment providers with
`force-cache`. If MakePay was enabled after the starter's first build or
request, trigger a clean storefront rebuild/redeploy with its generated Next
data cache invalidated. In local development, stop the storefront before
clearing its generated `.next` cache and restarting it. In production, use the
hosting platform's clean rebuild/redeploy or cache-invalidation workflow;
never delete cache files from a running instance.

The OAuth connection automatically provisions its grant-scoped subscription
with this plugin-owned callback (for the default provider ID):

```text
https://your-medusa-backend.example/hooks/makepay/makepay_makepay
```

Do not replace it with Medusa's generic payment webhook route. The MakePay
route verifies and correlates the event, applies provider-owned terminal
updates, and runs Medusa's standard successful-payment workflow synchronously.
It returns `2xx` only after that work has completed. A transient provider,
database, or workflow failure returns a generic `503`, allowing MakePay to
redeliver the same stable delivery group safely. In OAuth mode, the plugin
normally returns `404` from `/hooks/payment/makepay_<providerId>` before Medusa
can enqueue it. If an API-key projection is still undrained after a forced
mode switch, it returns `503` instead so the event can be redelivered after the
previous mode is restored.

OAuth requests only company read, MakePay payment-link read/write, and MakePay
webhook read/write scopes. Tokens, the DPoP private key, and webhook secret are
encrypted with AES-256-GCM and are never returned to Admin or the storefront.
The encryption key is not recoverable from the database; losing it requires a
fresh connection.

Production OAuth discovery defaults to `https://www.makecrypto.io`. Leave the
issuer/API overrides unset outside tests. If a test environment uses an
override, use the issuer's exact, non-redirecting origin: an apex-to-`www`
redirect changes DPoP `htu` and causes proof validation to fail closed.

## API-key compatibility mode

Use this mode for an existing 0.2.0 deployment or as a planned fallback after
all OAuth-created hosted links are safely drained under the rules below. Keep
the plugin and provider registrations from the OAuth example but use these
options:

```ts
const makePayOptions = {
  authMode: "api_key" as const,
  keyId: process.env.MAKEPAY_KEY_ID!,
  keySecret: process.env.MAKEPAY_KEY_SECRET!,
  webhookSecret: process.env.MAKEPAY_WEBHOOK_SECRET!,
  lockingProvider: "makepay-postgres",
  backendUrl: process.env.MEDUSA_BACKEND_URL,
  storefrontReturnUrl: process.env.STOREFRONT_URL
    ? `${process.env.STOREFRONT_URL}/order/makepay-return`
    : undefined,
  settlementCurrency: process.env.MAKEPAY_SETTLEMENT_CURRENCY || "USDT",
  expirationTime: "12h",
};
```

Omitting `authMode` while `keyId`, `keySecret`, and `webhookSecret` are present
also selects API-key mode for backward compatibility; those three credentials
remain sufficient for a pure legacy installation that has never configured
OAuth. Keep the recommended `lockingProvider` to serialize payment effects
across backend workers and enable Admin reconciliation. It becomes required
for API-key checkout after any OAuth authorization state, connection, or payment history exists.
Configure this exact signed callback in MakePay developer settings:

```text
https://your-medusa-backend.example/hooks/payment/makepay_makepay
```

Do not switch an active OAuth installation to API-key mode while it has an
undrained hosted link. This includes a pending link, a completed link whose
Medusa payment is not yet paid, and a failed, expired, or cancelled link that
ever had a remote payment session: funds can still settle late. Applying only
the Medusa failure/cancellation side effect does not drain that history. A link
is safe for a mode transition only after exact `complete` plus Medusa paid, or
after MakePay atomically proves that it archived the link before any payment
session existed and Medusa records it canceled. If a switch was forced,
restore OAuth to process a redelivery before creating a fresh API-key payment
attempt.

Version 1.0.0 supports the exact provider configuration ID `makepay` only.
Keep `providers[].id` as `makepay` and omit `makePayOptions.providerId` (or set
it to the same value), producing `pp_makepay_makepay`. Custom or multiple
MakePay provider IDs are rejected because one plugin registration owns one
connection and webhook identity.

Version 1.0.0 preserves this URL but intercepts MakePay callbacks before
Medusa's generic payment-webhook handler. It verifies the signature, fetches
and correlates the hosted link, serializes the payment effects, and runs the
required Medusa workflow synchronously. The route returns `2xx` only after the
correlated effects complete. Invalid signatures and malformed signed bodies
fail with a generic `4xx`. An unavailable or mismatched authoritative MakePay
snapshot, or a transient database, locking, or workflow failure, returns a
generic `503` so MakePay can redeliver while no payment effect is applied. Keep
upstream redelivery enabled and monitor the local payment projection for
reconciliation.

## Options

| Option                                  | Mode           | Description                                                                                                                                                          |
| --------------------------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `authMode`                              | both           | `oauth` or `api_key`; inferred as `api_key` only when legacy credentials are supplied.                                                                               |
| `backendUrl`                            | both           | Public Medusa backend origin. Required for OAuth; optional in API-key mode for the managed return flow. HTTPS is required except localhost.                          |
| `storefrontReturnUrl`                   | both           | Storefront destination after the backend validates the opaque return state. Required for OAuth; optional with the managed API-key return flow.                       |
| `encryptionKey`                         | OAuth          | Base64-encoded 32-byte AES key. Keep it stable and server-only.                                                                                                      |
| `lockingProvider`                       | both           | ID of a distributed Medusa locking provider. Required for OAuth and API-key checkout after OAuth history; optional only for a pure legacy API-key installation.      |
| `keyId`                                 | API key        | MakePay API key ID.                                                                                                                                                  |
| `keySecret`                             | API key        | MakePay API key secret.                                                                                                                                              |
| `webhookSecret`                         | API key        | Signing secret for the configured callback.                                                                                                                          |
| `settlementCurrency`                    | both           | Settlement asset sent to MakePay. Default: `USDT`.                                                                                                                   |
| `expirationTime`                        | both           | Hosted-link expiry such as `15m`, `1h`, `12h`, `24h`, `72h`, or `never`. Default: `12h`.                                                                             |
| `checkoutBaseUrl`                       | both           | Exact hosted MakePay origin. Leave unset for `makepay.io`/`www.makepay.io`; set it to an approved merchant-branded origin when MakePay returns links on that domain. |
| `baseUrl`                               | both           | MakeCrypto API origin override. Used directly in API-key mode and as the OAuth API fallback when `oauthApiUrl` is omitted; leave overrides unset in production.      |
| `oauthIssuerUrl`                        | OAuth          | MakeCrypto OAuth issuer override for contract/local testing.                                                                                                         |
| `oauthApiUrl`                           | OAuth          | MakeCrypto OAuth/API origin override for contract/local testing.                                                                                                     |
| `oauthAudience`                         | OAuth          | OAuth resource audience override; normally leave unset. The official resource ID defaults to `https://makecrypto.io/api/partner/v1`.                                 |
| `providerId`                            | both           | Reserved compatibility option; omit it or set the only supported 1.0.0 value, `makepay`.                                                                             |
| `adminPath`                             | both/Admin     | Medusa Admin base path used for OAuth callback redirects and order links. Default: `/app`; use the configured Admin path if customized.                              |
| `siteName`, `medusaVersion`             | OAuth          | Non-brand installation and version metadata used for support and Connected Apps presentation; official MakePay branding is template-controlled.                      |
| `webhookToleranceSeconds`               | both           | Maximum signed-webhook timestamp age.                                                                                                                                |
| `returnUrl`, `successUrl`, `failureUrl` | API key/legacy | Server-configured HTTPS checkout destinations when the managed backend return is not configured; query parameters are supported.                                     |

Never put API credentials, OAuth tokens, the encryption key, or webhook
secrets in `NEXT_PUBLIC_*` variables.

Hosted redirect URLs are accepted only when their origin exactly matches the
canonical MakePay origins or the configured `checkoutBaseUrl`, and their path
is exactly `/payment/<payment-link-uid>`. Lookalike domains, unexpected
subdomains, ports, query strings, fragments, or a different UID fail closed.

## Storefront flow

The payment session exposes only a public, whitelisted redirect action and an
opaque return state:

```ts
paymentSession.data.next_action;
// { type: "redirect", url: "https://www.makepay.io/payment/..." }
```

Finalize the cart's contents, delivery, and totals before initiating the
MakePay payment session. With the Medusa 2.17.2 JS SDK, pass the complete cart
object to `initiatePaymentSession`, not a payment collection ID. For guest
checkout, pass the validated cart email as
`data: cart.email ? { customer_email: cart.email } : undefined`; Medusa 2.17.2
doesn't add it to the provider context. The plugin uses it for server-side
MakePay/Admin correlation and does not expose it in the returned payment-session
data. One Medusa payment session owns one immutable MakePay UID, so an issued
link cannot be repriced or replaced in place. If the total or currency changes,
retrieve the refreshed cart and initiate a new payment session.

The API order is: initiate the MakePay payment session, validate its public
`next_action`, complete the cart, persist the returned awaiting-payment order
ID, and only then redirect to `next_action.url`. MakePay returns through the
backend route, which reconciles server-to-server and redirects the browser to
`storefrontReturnUrl` with an opaque per-payment `makepay_state`. The return
page must remove that state from the address bar immediately and send
`Referrer-Policy: no-referrer`.

The storefront return page may retrieve limited, correlated status from:

```http
GET /store/makepay/checkout-status?state=<opaque-state>
```

The state remains resolvable while its local payment projection is retained so
a customer can safely return after delayed settlement. Treat it as bearer-like
checkout material even though the public response contains only payment status
and update-time fields.

The response has this shape:

```json
{
  "payment": {
    "status": "paid",
    "updated_at": "2026-07-19T12:00:00.000Z"
  },
  "terminal": true
}
```

The valid limited statuses are `pending_authorization`, `paid`, `failed`, and
`canceled`. The public endpoint intentionally exposes no order, customer,
session, or MakePay-link identifiers. Navigate only with the order ID saved by
the storefront before redirecting. A browser return or query-string claim is
never proof of payment;
the signed MakePay webhook is the normal source of the paid transition. See
[the complete storefront example](./docs/storefront.md).

## Medusa Admin

After the package is registered and the Admin is rebuilt:

- `/app/settings/makepay` shows OAuth/API-key state, company, granted scopes,
  the next automatic access-token renewal, and webhook health. Secrets are
  never displayed.
- `/app/makepay` lists only locally projected payments for this Medusa
  installation, with search, status filters, pagination, and safe external
  links.
- `order.details.side.after` shows MakePay information on an order and offers a
  safe server-side reconciliation action when the configured distributed lock
  makes that capability available. The custom views are otherwise read-only.

Medusa's core order payment section remains the source for generic payment,
capture, and refund presentation. MakePay's widget adds provider-specific
context without replacing core Admin UI.

In OAuth mode, **Settings → MakePay** provides **Connect MakePay** for
first-time setup or a completed disconnect and **Reconnect** plus
**Disconnect** when connected. A terminal refresh failure changes the primary
action to **Reconnect** and shows a **Reconnect required** notice even though
the connection is no longer usable. A retryable issuer or network outage keeps
the normal attention state and automatic retry path; it is not mislabeled as a
new connection or a required reconnect. API-key mode has no OAuth connection
to revoke: it is configured server-side, so Admin reports its status but never
displays, accepts, or disconnects its credentials. To stop using API-key mode,
remove its credentials or provider configuration from the backend
configuration and restart the backend. Secrets never belong in Admin.

OAuth **Disconnect** first revokes the remote installation and token family.
If that remote operation is temporarily unavailable, the connection remains in
`disconnect_pending`, encrypted credentials are not silently discarded, and
Admin offers **Retry disconnect**. Checkout remains unavailable until the
disconnect finishes or the installation is reconnected. If the remote reset
succeeded but its response was lost, Retry disconnect replays the same durable
mutation and validates MakeCrypto's reset receipt before clearing anything. A
terminal revoked-family error cannot be fixed by retrying the old refresh
token; use the adjacent **Reconnect** action, which retains the staged
registration proof and replaces the authorization. A
successful disconnect wipes the active OAuth tokens, DPoP key, and connection
secret. A separate encrypted historical subscription credential remains only
so a late or redelivered event for an already-issued, exactly correlated
payment can still be authenticated; it is never returned through Admin.
Remotely, the subscription is barred from association with new links but its
endpoint and signing identity remain available for limited canonical status
events from those old links. Keep the encryption key, plugin tables, and
MakePay webhook endpoint `/hooks/makepay/makepay_makepay` available until every
issued link is safely drained; disconnect is not permission to discard
settlement-verification history.

## Webhook and status behavior

- Only MakePay's exact raw `complete` processor state becomes successful.
  Similar-looking aliases such as `paid`, `completed`, or `captured` are not
  accepted as proof of payment, and other conflicting terminal states are
  rejected.
- A newly created `active`, `open`, or unpaid hosted session is pending
  authorization so Medusa can create the order before redirecting.
- Quote/deposit/swap/send and underpaid states map to Medusa's ordinary pending
  state. A `processing` settlement phase may accompany one of those canonical
  states, but raw processor status `processing` is not accepted by itself.
- Exact `failed` becomes failed; exact `expired`/`cancelled` become canceled.
  Aliases such as `error` or `canceled` fail closed.
- An exactly correlated, signed `complete` may supersede an earlier `failed`,
  `expired`, or `cancelled` event when funds settle late. The plugin reopens
  only that same Medusa session and runs the standard successful-payment
  workflow exactly once. Once paid, no later event may downgrade the payment.
- A `refunded` processor event is not part of the accepted canonical schema and
  fails closed; it does not create a Medusa refund or change a captured
  payment. Reconcile it manually because MakePay exposes no merchant refund API
  to this provider.
- OAuth subscriptions post to the synchronous
  `/hooks/makepay/makepay_<providerId>` route. A successful or authorized event
  is acknowledged only after Medusa's standard payment workflow completes;
  transient failures receive a generic `503` and may be retried.
- A callback for the inactive authentication mode returns `503` while that
  mode still has an undrained payment projection, preserving redelivery after
  a forced switch. Once the prior mode is fully drained, its route returns
  `404`. The legacy `/hooks/payment/makepay_<providerId>` URL remains enabled
  for active API-key compatibility only.
- Failed, expired, and ordinary webhook-cancelled links with a remote payment
  session remain undrained because an exact late `complete` can still settle.
  Only complete/paid or an atomically proven no-session archive/cancellation
  is safe to drain for an authentication-mode transition.
- On both MakePay routes, a missing, invalid, or stale signature receives a
  generic `401`. A correctly signed event with invalid schema, routing, or
  self-contained OAuth correlation receives a generic `400`. Responses never
  echo signature, secret, or infrastructure details. In API-key mode, an
  unavailable or mismatched authoritative provider/session snapshot receives
  `503`, as does a transient database, locking, or workflow failure, so a
  possibly recoverable event is redelivered rather than acknowledged.
- OAuth stable delivery-group IDs are authenticated by the webhook signature
  and stored uniquely; a valid duplicate is acknowledged as a no-op. The
  legacy API-key handler ignores caller-supplied delivery-group identity and,
  only after signature verification plus a server-side link snapshot, derives
  deduplication from the correlated payment semantics. Correlation mismatches,
  missing amounts, wrong currency/session/UID, and terminal-state regressions
  fail closed.
- A canonical OAuth event created during the brief order-metadata patch race
  may omit both order identifiers only inside a closed lifecycle window from
  projection creation through order correlation, with at most 60 seconds of
  clock skew. Every other identity must match exactly; a wrong non-empty order
  ID never receives this exception.

Canceling an unpaid Medusa session archives its hosted link only when MakePay
can prove that no payment session was created remotely; an attempt that may
already have funds in processing is not canceled. Capture first rechecks that
MakePay completed. Refund calls return an explicit unsupported error rather
than pretending that funds moved.

## Development and real local testing

```bash
npm ci
npm run check
```

`npm run check` type-checks/builds the complete plugin, runs unit/security and
contract tests, and inspects the npm artifact. `npm run test:integration`
installs the packed tarball into Medusa 2.17.2, runs its migration, and builds
the clean application against `DATABASE_URL`.

For real OAuth, an official Next.js storefront, deterministic signed terminal
events, and the screenshot-verification rules, follow
[docs/local-e2e.md](./docs/local-e2e.md). The sandbox fixture never requests or
accepts real cryptocurrency.

## Troubleshooting

- **OAuth button reports missing module:** register the package in `plugins`,
  not only as a Payment Module provider, then run `npx medusa db:migrate`.
- **OAuth callback rejected:** ensure `backendUrl` is the exact public HTTPS
  origin used at connection time. Reconnect if a temporary tunnel hostname
  changed.
- **OAuth refresh reports a missing lock:** restore Medusa's Locking Module;
  distributed refresh serialization is required and is not downgraded to an
  unsafe process-only lock.
- **The access-token time is in the past:** this does not mean the connection
  expired. The next authenticated MakePay request renews it automatically. If
  renewal fails, keep the encrypted connection row and retry after the issuer
  or network recovers; reconnect only for an explicit revocation or the
  terminal recovery condition below.
- **OAuth token recovery unavailable:** an authorization-code response exceeded
  its one-time setup window, or the durable recovery record for a committed
  refresh was missing or damaged. Official Medusa refresh responses otherwise
  remain recoverable until their successor token is safely persisted and used,
  even after a long process outage. Select **Reconnect MakePay** only for this
  terminal condition. Do not delete the connection row, encryption key, or
  historical payment records; checkout stays unavailable until reconnect
  completes.
- **Webhook is unhealthy:** reconnect to provision a fresh grant-scoped
  subscription, and confirm the OAuth callback at
  `/hooks/makepay/makepay_makepay` is publicly reachable. An OAuth connection
  made with a prerelease build that used `/hooks/payment/...` must be
  reconnected once so MakeCrypto stores the synchronous callback.
- **API-key callback returns `503`:** confirm the configured callback is
  `/hooks/payment/makepay_makepay`, inspect backend/provider availability and
  the MakePay projection, then allow MakePay to redeliver or reconcile the
  payment. A `2xx` response means the correlated synchronous effects completed.
- **Provider not visible at checkout:** in **Settings → Regions**, edit the
  cart's region and enable `pp_makepay_makepay` under **Payment Providers**.
  Confirm `GET /store/payment-providers?region_id=<region_id>` includes it when
  called with the storefront publishable key. The official Next.js starter
  force-caches this list; if it was cached before MakePay was enabled, perform
  a clean rebuild/redeploy with the generated Next data cache invalidated. Do
  not delete cache files from a running production instance. Retrieve the cart
  again and reload or re-enter checkout; update/recreate it only if
  `cart.region.id` is not one of the regions you enabled.
- **Checkout says `Failed to fetch`:** test backend health from the storefront
  runtime and verify its Medusa backend URL, DNS, TLS, tunnel, and process
  state. If health succeeds, check the exact cart region with
  `/store/payment-providers`; if that endpoint includes MakePay but the UI does
  not, invalidate the provider cache and retrieve the cart again. If selection
  is visible but session initiation still fails, inspect the payment-session
  HTTP response and Medusa backend logs and confirm the OAuth/API-key
  connection is healthy. The official Next.js starter performs this work
  server-side, so browser CORS is not its likely cause. A custom storefront
  that calls Medusa directly from the browser must also use HTTPS without
  mixed content and include its origin in Medusa `storeCors`.
- **Order stays awaiting payment:** inspect the MakePay row and webhook health,
  then use reconciliation. Do not manually mark an order paid based on the
  browser URL.
- **Cart changed after MakePay selection:** retrieve the refreshed cart and
  initiate a new Medusa payment session. Do not update the issued session to
  reprice its MakePay UID. If the prior attempt may contain funds, reconcile it
  before offering another payment attempt.
- **OAuth data cannot decrypt:** restore the original
  `MAKEPAY_ENCRYPTION_KEY`; otherwise disconnect/revoke the Connected App and
  create a fresh connection.

Security issues should be reported privately as described in
[SECURITY.md](./SECURITY.md).
