# MakePay for Medusa

[![npm version](https://img.shields.io/npm/v/@makecrypto/medusa-plugin-makepay.svg)](https://www.npmjs.com/package/@makecrypto/medusa-plugin-makepay)
[![CI](https://github.com/makecryptoio/medusa-plugin-makepay/actions/workflows/ci.yml/badge.svg)](https://github.com/makecryptoio/medusa-plugin-makepay/actions/workflows/ci.yml)

<p align="center">
  <img src="./assets/makepay-medusa-icon.svg" alt="MakePay icon" width="96" height="96" />
</p>

Official MakePay payment provider for Medusa v2. The provider creates hosted
MakePay checkout links for Medusa payment sessions and reconciles payment
status through signed MakePay webhooks.

## Install

```bash
npm install @makecrypto/medusa-plugin-makepay
```

## Configure

Register MakePay as a provider under the Medusa Payment Module:

```ts
// medusa-config.ts
import { defineConfig, Modules } from "@medusajs/framework/utils";

export default defineConfig({
  modules: [
    {
      resolve: "@medusajs/medusa/payment",
      options: {
        providers: [
          {
            resolve: "@makecrypto/medusa-plugin-makepay/providers/makepay",
            id: "makepay",
            options: {
              keyId: process.env.MAKEPAY_KEY_ID!,
              keySecret: process.env.MAKEPAY_KEY_SECRET!,
              webhookSecret: process.env.MAKEPAY_WEBHOOK_SECRET!,
              settlementCurrency:
                process.env.MAKEPAY_SETTLEMENT_CURRENCY || "USDT",
              expirationTime: "12h",
            },
          },
        ],
      },
    },
  ],
});
```

The default Medusa payment webhook URL for the provider is:

```txt
/hooks/payment/makepay_makepay
```

Configure that URL in MakePay developer settings and store the generated
webhook secret as `MAKEPAY_WEBHOOK_SECRET`.

## Options

| Option | Required | Description |
| --- | --- | --- |
| `keyId` | yes | MakePay API key ID. |
| `keySecret` | yes | MakePay API key secret. |
| `webhookSecret` | yes | MakePay webhook signing secret. |
| `baseUrl` | no | MakeCrypto API base URL. Defaults to production. |
| `checkoutBaseUrl` | no | MakePay hosted checkout base URL. Defaults to production. |
| `settlementCurrency` | no | Settlement symbol sent to MakePay. Defaults to `USDT`. |
| `expirationTime` | no | Hosted link expiration. Defaults to `12h`. |
| `returnUrl` | no | Fallback return URL for MakePay checkout. |
| `successUrl` | no | Success return URL for MakePay checkout. |
| `failureUrl` | no | Failure return URL for MakePay checkout. |

## Storefront flow

`initiatePayment` returns provider data with a hosted checkout URL:

```ts
paymentSession.data.next_action
// { type: "redirect", url: "https://makepay.io/payment/..." }
```

Redirect shoppers to that URL, then use MakePay webhooks to update the Medusa
payment session when the payment is completed, canceled, or failed.

## Development

```bash
npm ci
npm run check
```

`npm run check` builds the TypeScript provider, runs the unit tests, and
verifies the npm package contents with `npm pack --dry-run`.
