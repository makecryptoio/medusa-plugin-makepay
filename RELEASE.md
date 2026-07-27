# Release Policy

Releases are performed only by MakePay by MakeCrypto maintainers. Public
repositories accept issues and pull requests, but maintainers control release
approval, versioning, tagging, and package publishing.

## Required gates

Before tagging a release:

1. Merge a reviewed, conflict-free pull request into protected `main`.
2. Require the Node.js 22/24 quality matrix, packed Medusa 2.17.2 integration,
   and packed official-storefront browser jobs to pass.
3. Run the opt-in real MakeCrypto OAuth/MakePay sandbox smoke through public
   HTTPS tunnels. It may create and archive a sandbox link, but it must stop
   before selecting an asset, opening a wallet, or sending funds. Use the
   deterministic signed contract for paid and unsuccessful terminal events.
   Assert that the complete cart initiates one MakePay session, Medusa creates
   and returns the `pending_authorization` order, and the storefront persists
   that order ID before the browser navigates to hosted checkout.
   Assert that the OAuth subscription targets
   `/hooks/makepay/makepay_makepay`, a forced transient workflow failure gets a
   generic `503`, retrying the same stable delivery group succeeds, and exactly
   one Medusa capture exists. Verify API-key compatibility separately through
   `/hooks/payment/makepay_makepay`. For both callback modes, verify that
   bad/stale signatures return a generic `401` and malformed signed
   schema/routing failures return a generic `400`. Verify an API-key
   authoritative-snapshot mismatch and an injected transient/workflow failure
   return `503` before a corrected or identical redelivery succeeds exactly
   once.
   Force each wrong-mode callback with an undrained prior-mode projection and
   verify `503`; a failed/canceled Medusa side effect alone must remain `503`.
   Resolve it through exact `complete` plus Medusa paid, or through an atomic
   no-session archive plus Medusa canceled, and then verify the same callback
   returns `404`. Deliver exact, correlated `complete` after each failed,
   expired, and cancelled case; the original immutable session/UID must capture
   exactly once and later unsuccessful events must not downgrade it. None of
   those responses may expose secrets. The API-key URL is retained for
   compatibility, but 1.0.0 intercepts MakePay callbacks and completes their
   validation and correlated effects synchronously.
   Connect two isolated Medusa installations to the same sandbox company and
   verify subscription isolation. Rotate and disconnect one after issuing a
   link; its old limited canonical event must verify only for that exact local
   projection using the historical credential, while no new link can be
   associated with the old subscription. Replaying disconnect after a lost
   response must resume the same durable reset operation.
   Defer one exact signed event created before the remote order-metadata patch
   until after local order correlation. It may omit both order IDs only inside
   the bounded lifecycle window; too-old, after-boundary, malformed, and wrong
   non-empty order identities must fail closed.
   Verify the official Medusa no-inactivity-expiry invariant with either a
   connection that refreshes after more than 30 days without reconnecting, or
   equivalent production-issuer evidence: deployed issue and rotate paths must
   pin the official Medusa template and store the live current refresh
   successor with infinite expiry; recovery must pin that template and
   validate/replay the already-stored current successor and receipt; cleanup
   must preserve that current family; and the frozen plugin must pass a forced
   local access-expiry refresh against those exact production paths. The latter
   smoke must attest that the
   successor is current, unrevoked, unconsumed, in the same family and DPoP/
   grant/installation/company binding, and that `oauth.token_refreshed` was
   recorded. Access-token expiry is only the next renewal time. Verify other
   OAuth templates still fail closed at their configured refresh-token expiry,
   and that explicit disconnect, revocation, security reset, refresh-token
   reuse, or loss of the complete refresh family ends Medusa access.
   Exercise native registration with a DPoP proof matching the submitted key.
   A replacement must also require proof from the currently accepted key.
   Abandoning consent must leave the old token family usable, and the accepted
   previous key must be able to replace a lost pending key. Successful consent
   must bind the new key and revoke the complete old access and refresh-token
   family.
   Attempt an automated Medusa refund and require a clear unsupported error,
   no provider-side settlement mutation, and no Medusa refund record.
4. Require the screenshot release gate for exactly four reviewed artifacts:
   connected settings, payments list, order widget, and hosted MakePay sandbox
   checkout. Each image needs both original-resolution and rendered-docs
   approval; candidate-only images are not release evidence. The manifest must
   declare `real-sandbox`, match the approved HTTPS backend/checkout origins,
   contain one cross-page payment correlation, and contain no query strings.
   Deterministic-fixture screenshots are QA-only and cannot pass this gate.
   Placeholder comments are not evidence: do not tag, publish, or promote while
   any of the four real-sandbox images is absent from the rendered release
   documentation or its generated documentation index is stale.
5. Verify the package version and changelog, run `npm run check` from a clean
   checkout, and inspect the `npm pack --dry-run --json` allowlist.
6. Verify OAuth fails closed without the configured distributed Locking Module.
   Verify a pure legacy API-key installation still starts with only its three
   credentials and reports Admin reconciliation unavailable without a
   distributed provider. Verify API-key checkout fails closed without locking
   after OAuth history exists, and enables reconciliation plus cross-process
   payment-effect serialization when `lockingProvider` is configured.
7. Verify one Medusa session creates one immutable MakePay UID. Retry ambiguous
   creation through that session without creating a second link, reject an
   in-place amount/currency reprice, and create a fresh Medusa session only
   after the cart is refreshed.
8. Confirm the MakeCrypto OAuth/API prerequisite release is deployed before a
   plugin version that depends on it.
9. Create the protected `v<package-version>` tag on the exact merge commit.

## Safe real-sandbox environment

The opt-in real smoke is fail-closed. Use placeholder-free values for the
approved dedicated sandbox, never production company data, and select exactly
one login mode:

```bash
export MAKEPAY_E2E_REAL_SANDBOX=1
export MAKEPAY_E2E_NO_FUNDS_ACK=SANDBOX_DO_NOT_SEND_FUNDS
export MAKEPAY_E2E_REAL_API_URL=https://approved-makecrypto-api.example
export MAKEPAY_E2E_REAL_CHECKOUT_URL=https://approved-makepay-checkout.example
export MAKEPAY_E2E_REAL_OAUTH_ISSUER_URL=https://approved-oauth-issuer.example
export MAKEPAY_E2E_SANDBOX_COMPANY_ID=company_sandbox_id
export MAKEPAY_E2E_SANDBOX_COMPANY_NAME='Publication-safe Sandbox Merchant'
export MAKEPAY_PLUGIN_TARBALL=/absolute/path/to/makecrypto-medusa-plugin-makepay-1.0.0.tgz
export MAKEPAY_PLUGIN_TARBALL_SHA256=64_lowercase_hex_plugin_sha256
export MAKEPAY_SDK_TARBALL=/absolute/path/to/makecrypto-makepay-0.4.0.tgz
export MAKEPAY_SDK_TARBALL_SHA256=64_lowercase_hex_sdk_sha256

# Option A: owner-only Playwright state outside the repository.
export MAKEPAY_E2E_STORAGE_STATE=/absolute/path/outside/repository/sandbox-storage-state.json
unset MAKEPAY_E2E_MANUAL_OAUTH

# Option B: instead, unset storage state and use a fresh headed login.
# unset MAKEPAY_E2E_STORAGE_STATE
# export MAKEPAY_E2E_MANUAL_OAUTH=1

npm run test:e2e:real-sandbox
```

Use `MAKEPAY_E2E_CAPTURE=1` and
`MAKEPAY_E2E_SCREENSHOT_PUBLICATION_ACK=PUBLIC_SANDBOX_DATA_ONLY` only when the
dedicated company and synthetic `example.com` order are safe to publish. The
storage-state option must be an owner-controlled `0600` file outside the
repository containing only the approved issuer's cookies/origins. See
`docs/local-e2e.md` for capture review and screenshot release commands.

## 1.0.0 dependency sequence

`@makecrypto/medusa-plugin-makepay@1.0.0` depends on the exact
`@makecrypto/makepay@0.4.0`. Publish SDK `0.4.0` to `next`, install and smoke the
exact registry artifact, and only then promote that same SDK version to
`latest`. Do not merge or tag the plugin while its lockfile still resolves an
older SDK or a local tarball.

After SDK promotion, regenerate `package-lock.json` from the public registry,
verify its root package is `1.0.0` and its SDK dependency is exactly `0.4.0`,
then run `npm ci` and every gate below from that clean install. Local `file:`
tarball or workspace entries are useful before the SDK release but must never
enter the reviewed plugin lockfile.

The `publish.yml` workflow must be configured as this package's npm trusted
publisher and protected by the `npm-next` GitHub environment. It uses a
GitHub-hosted Node.js 24 runner with `id-token: write`; no `NPM_TOKEN` is stored
in the repository or workflow. npm generates provenance automatically for a
public package published this way.

Verify one trusted-publisher release before revoking any bootstrap credential,
then revoke the long-lived npm token supplied for this migration. Do not copy
that token into Actions, repository variables, logs, or documentation.

The tag workflow publishes the immutable version with the `next` dist-tag.
Install that exact registry artifact into the clean Medusa test environment
and repeat the smoke/order checks before promotion.

## Promotion

npm trusted publishing authorizes `npm publish`, not general commands such as
`npm dist-tag`. Promote the already-tested version from `next` to `latest`
through npmjs.com with a maintainer's interactive authentication. If CLI
promotion is unavoidable, use a short-lived package-scoped granular token and
revoke it immediately; never save the supplied or another long-lived token in
GitHub.

Record the final package integrity, provenance, Git tag, release URL, and test
result in the GitHub release notes.

## Failure and rollback

- Before promotion, leave `latest` unchanged and publish a corrected version.
- If `1.0.0` fails after promotion, move `latest` back to `0.2.0`, deprecate
  `1.0.0` with a useful message, and publish the correction as `1.0.1`. Do not
  unpublish an artifact that consumers may already have installed.
- Leave additive database tables in place during an application rollback.
- Version bumps are made only when maintainers intend to publish; npm versions
  and Git tags are immutable.

Package-manager credentials, signing keys, customer data, and publish tokens
must never be committed. Protected branch, environment, and tag rules must
remain enabled for `main`, `npm-next`, and release tags.
