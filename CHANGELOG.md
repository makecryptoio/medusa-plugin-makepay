# Changelog

All notable changes to this package are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## [1.0.1] - 2026-07-27

### Documentation

- Clarified that installation requires a fully configured, active
  [MakePay merchant account](https://makepay.io/) rather than linking the
  prerequisite to the MakeCrypto corporate site.

## [1.0.0] - 2026-07-25

`1.0.0` is the first stable release and intentionally follows the previously
published `0.2.0`. No intervening package versions were published.

### Added

- Native MakeCrypto OAuth connection with PKCE, DPoP-bound rotating tokens,
  encrypted local credentials, and an API-key compatibility mode.
- Per-installation MakePay webhook subscriptions, encrypted historical
  verification credentials for already-issued links, and durable delivery
  deduplication.
- A synchronous, bounded OAuth webhook endpoint that acknowledges successful
  payments only after Medusa's standard payment workflow completes and returns
  a retryable response for transient failures.
- Local payment projections, OAuth state, connection, and webhook-delivery
  database models with additive migrations.
- MakePay settings and payment-list pages for Medusa Admin, plus an order
  detail widget, branded Extensions-sidebar icon, and read-only payment
  reconciliation.
- Hosted-checkout return and limited storefront status endpoints.
- Node.js 22 and 24 CI, packed-artifact validation, and Medusa 2.17.2
  integration coverage.

### Changed

- The minimum supported Medusa version is 2.17.2 and the minimum Node.js
  version is 22.
- OAuth installations require an explicitly configured distributed Medusa
  Locking Module provider; the in-memory default is rejected.
- Newly initiated hosted sessions use Medusa's `pending_authorization` payment
  lifecycle so the order exists before the shopper leaves for MakePay.
- Every Medusa payment session owns one immutable MakePay payment-link UID;
  amount or currency changes require a fresh Medusa session instead of an
  in-place reprice or replacement.
- Storefront-visible payment-session data is restricted to public checkout
  fields; raw MakePay API responses are no longer persisted there.
- Remote revocation failures retain encrypted connection material in a
  retryable `disconnect_pending` state instead of claiming a local disconnect.
- An authorization-code or refresh token response that can no longer be
  recovered fails closed and requires an explicit reconnect instead of
  reusing uncertain token authority.
- OAuth subscriptions use `/hooks/makepay/makepay_<providerId>`; the legacy
  `/hooks/payment/makepay_<providerId>` callback remains available for API-key
  installations.
- API-key installations retain `/hooks/payment/...`, but plugin middleware now
  validates and applies MakePay callbacks synchronously before Medusa's generic
  queue. OAuth mode rejects that legacy URL, so signed replays cannot bypass
  synchronous serialization.
- Package exports and build output now follow Medusa's official plugin layout,
  while preserving the original root and provider entry points.

### Security

- OAuth tokens, DPoP keys, webhook secrets, and PKCE material are encrypted
  with AES-256-GCM using an operator-supplied key.
- Webhooks are correlated to the expected installation, payment session,
  order, amount, currency, and company before they may change payment state.
- Disconnect invalidates every pending or recoverable OAuth callback while
  retaining staged DPoP possession proof until the remote installation reset
  is durably confirmed.
- Refresh recovery can adopt an integrity-checked staged DPoP key when the
  issuer rejects the connected key's binding but still permits rotation or
  replays a staged-bound success; it never treats a revoked family as
  refreshable.
- Only the exact MakePay `complete` processor state can enter the successful
  workflow. An exactly correlated late `complete` may supersede an earlier
  unsuccessful terminal event, but a paid payment can never regress.
- npm publication uses a protected GitHub environment and npm trusted
  publishing rather than a repository token.
- Published JavaScript has inline source maps removed, and the tarball gate
  rejects credential-shaped content and unexpected files.

### Known limitations

- Merchant-initiated refunds are not available because MakePay does not yet
  expose a safe merchant refund API. The Admin integration is read-only aside
  from reconciliation.

## [0.2.0] - 2026-07-06

- Added the initial Medusa v2 hosted-checkout payment provider with API-key
  authentication and signed webhook handling.

[1.0.1]: https://www.npmjs.com/package/@makecrypto/medusa-plugin-makepay/v/1.0.1
[1.0.0]: https://github.com/makepay-apps/medusa-plugin-makepay/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/makepay-apps/medusa-plugin-makepay/releases/tag/v0.2.0
