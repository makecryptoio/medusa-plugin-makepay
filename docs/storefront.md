# Hosted checkout in a storefront

MakePay 1.0.0 uses Medusa's `pending_authorization` lifecycle. The important
ordering is:

1. Initiate `pp_makepay_makepay` for the complete cart.
2. Read and validate the public MakePay `next_action` from that payment
   session.
3. Complete the cart. Medusa creates an order that is awaiting payment.
4. Persist the returned order ID locally, then navigate to `next_action.url`.
5. On return, ask the plugin's limited status endpoint for the authoritative
   state. Never treat query-string text such as `success=true` as proof of
   payment.

## Enable MakePay for every storefront region

Do this before building or deploying the storefront:

1. In Medusa Admin, open **Settings → Regions**.
2. Edit every region used by storefront carts.
3. Under **Payment Providers**, enable `pp_makepay_makepay` and save.
4. Verify each region directly with the storefront's publishable key:

   ```bash
   curl --fail --silent --show-error \
     -H "x-publishable-api-key: $MEDUSA_PUBLISHABLE_KEY" \
     "$MEDUSA_BACKEND_URL/store/payment-providers?region_id=$REGION_ID"
   ```

   The response must include `pp_makepay_makepay`.

Registering the package and payment provider does not enable MakePay on any
region automatically. The Store API lookup uses the current cart's
`region.id`. After changing region providers, retrieve that cart again and
reload or re-enter checkout. Recreate or update it only when the cart belongs
to a different region or the shopper changed country/region.

The official Medusa Next.js starter fetches this provider list with
`force-cache`. If MakePay was enabled after the starter's first build or
request, use a clean rebuild/redeploy that invalidates its generated Next data
cache. For local development, stop the storefront, clear its generated `.next`
cache, and restart it. For production, use the hosting platform's clean
rebuild/redeploy or cache-invalidation workflow; never delete cache files from
a running instance.

The official starter performs Medusa requests server-side, so browser CORS is
not the likely cause of its `Failed to fetch` errors. A custom storefront that
uses the Medusa SDK directly in the browser must serve compatible HTTPS
origins, avoid mixed content, and include its origin in Medusa `storeCors`.

## Framework-neutral example

The example assumes an initialized `@medusajs/js-sdk` client. Adapt the UI and
storage mechanism to your framework; do not move the secret backend plugin
configuration into storefront environment variables.

```ts
const PROVIDER_ID = "pp_makepay_makepay";
const MAKEPAY_CHECKOUT_ORIGIN = process.env.NEXT_PUBLIC_MAKEPAY_CHECKOUT_ORIGIN;

export async function startMakePayCheckout(cart: StoreCart) {
  const collection = cart.payment_collection;
  const session = collection?.payment_sessions?.find(
    (candidate) => candidate.provider_id === PROVIDER_ID,
  );
  const nextAction = session?.data?.next_action as
    { type?: unknown; url?: unknown } | undefined;
  const returnState = session?.data?.return_state;

  if (
    nextAction?.type !== "redirect" ||
    typeof nextAction.url !== "string" ||
    typeof returnState !== "string" ||
    !returnState
  ) {
    throw new Error("MakePay did not return a valid hosted-checkout URL");
  }
  const checkoutUrl = new URL(nextAction.url);
  if (
    checkoutUrl.protocol !== "https:" ||
    !MAKEPAY_CHECKOUT_ORIGIN ||
    checkoutUrl.origin !== MAKEPAY_CHECKOUT_ORIGIN
  ) {
    throw new Error("MakePay returned an unexpected hosted-checkout origin");
  }

  const result = await sdk.store.cart.complete(cart.id);

  if (result.type !== "order") {
    throw new Error(result.error?.message || "The order could not be created");
  }

  const countryCode = cart.shipping_address?.country_code?.toLowerCase();
  if (!countryCode) {
    throw new Error("The MakePay order is missing its storefront country");
  }

  sessionStorage.setItem("makepay_order_id", result.order.id);
  sessionStorage.setItem("makepay_return_state", returnState);
  sessionStorage.setItem("makepay_country_code", countryCode);
  window.location.assign(checkoutUrl.href);
}
```

Set `NEXT_PUBLIC_MAKEPAY_CHECKOUT_ORIGIN` to the exact public hosted-checkout
origin for the environment (for example, `https://www.makepay.io` in production).
This value is an origin allowlist, not a credential. Do not derive it from the
returned URL itself.

Finalize the cart's contents, delivery, and totals before initiating the
MakePay payment session. Medusa JS SDK 2.17.2 expects the complete cart object
here, not a payment-collection ID:

```ts
const { cart } = await sdk.store.cart.retrieve(cartId, {
  fields: "+payment_collection.payment_sessions",
});

await sdk.store.payment.initiatePaymentSession(cart, {
  // Medusa 2.17.2 doesn't add a guest cart's email to the provider context.
  // Pass it explicitly so MakePay and the local Admin projection can correlate
  // the link even if the browser closes before cart completion.
  data: cart.email ? { customer_email: cart.email } : undefined,
  provider_id: "pp_makepay_makepay",
});

const { cart: cartWithMakePay } = await sdk.store.cart.retrieve(cartId, {
  fields: "+payment_collection.payment_sessions",
});

await startMakePayCheckout(cartWithMakePay);
```

One Medusa payment session owns one immutable MakePay payment-link UID. Never
update an issued session to change its amount or currency. If the cart total or
currency changes, retrieve the refreshed cart and initiate a new payment
session; Medusa deletes the prior active session as part of that workflow. If
the old MakePay attempt may already have funds in processing and cannot be
canceled safely, stop checkout and reconcile that attempt instead of creating a
second link.

For guest checkout, pass the already-validated cart email as
`data.customer_email`, as above. The plugin uses it only for server-side
MakePay/local Admin correlation and does not copy it into the storefront-readable
payment-session data it returns.

## Return page

MakePay returns through the backend route
`/makepay/checkout/return?state=<opaque-state>`. The plugin rechecks the link
server-side and redirects to the configured storefront return URL while
preserving the opaque state. The storefront may then request:

```http
GET /store/makepay/checkout-status?state=<opaque-state>
```

The endpoint exposes only the limited Medusa status and update time. It
intentionally returns no order, customer, payment-link, session, or provider
identifiers. Render **Awaiting payment** for a pending response and poll with
bounded backoff; webhook delivery, not the browser redirect, is the normal
source of the paid transition. Stop polling on a terminal paid, failed, or
canceled state.

### Next.js App Router example

The following return page is the flow exercised against the official Medusa
Next.js starter. Adapt only the final order-confirmation route if your
storefront uses a different path:

```tsx
"use client";

import { useEffect, useState } from "react";

type MakePayCheckoutStatus = {
  payment: {
    status: "pending_authorization" | "paid" | "failed" | "canceled";
    updated_at: string;
  };
  terminal: boolean;
};

const MAX_ATTEMPTS = 30;

const retryDelay = (attempt: number) =>
  Math.min(1_000 * 2 ** Math.min(attempt, 3), 5_000);

const removeStateFromAddressBar = () => {
  const current = new URL(window.location.href);
  current.searchParams.delete("makepay_state");
  window.history.replaceState(
    window.history.state,
    "",
    `${current.pathname}${current.search}${current.hash}`,
  );
};

export default function MakePayReturnPage() {
  const [message, setMessage] = useState(
    "Confirming your MakePay payment…",
  );

  useEffect(() => {
    const currentUrl = new URL(window.location.href);
    const queryState = currentUrl.searchParams.get("makepay_state");
    const state =
      queryState || sessionStorage.getItem("makepay_return_state");

    if (!state) {
      setMessage("The MakePay return state is missing.");
      return;
    }

    // Persist before stripping the URL so development lifecycle replay can
    // recover the state without restarting from useSearchParams changes.
    sessionStorage.setItem("makepay_return_state", state);
    removeStateFromAddressBar();

    let stopped = false;
    let timer: number | undefined;
    const controller = new AbortController();

    const schedule = (attempt: number) => {
      if (attempt >= MAX_ATTEMPTS) {
        setMessage(
          "Your payment is still pending. You can safely close this page.",
        );
        return;
      }

      timer = window.setTimeout(
        () => void poll(attempt),
        retryDelay(attempt),
      );
    };

    async function poll(attempt: number): Promise<void> {
      try {
        const backend = process.env.NEXT_PUBLIC_MEDUSA_BACKEND_URL;
        if (!backend) {
          throw new Error("The Medusa backend URL is not configured.");
        }

        const endpoint = new URL(
          "/store/makepay/checkout-status",
          backend,
        );
        endpoint.searchParams.set("state", state);
        const publishableKey =
          process.env.NEXT_PUBLIC_MEDUSA_PUBLISHABLE_KEY;
        const response = await fetch(endpoint, {
          cache: "no-store",
          headers: publishableKey
            ? { "x-publishable-api-key": publishableKey }
            : undefined,
          signal: controller.signal,
        });

        if (response.status === 404) {
          sessionStorage.removeItem("makepay_return_state");
          setMessage("This MakePay return state is invalid.");
          return;
        }
        if (!response.ok) {
          throw new Error("Unable to verify the MakePay payment.");
        }

        const result = (await response.json()) as MakePayCheckoutStatus;
        if (!result.payment || typeof result.payment.status !== "string") {
          throw new Error("MakePay returned an invalid checkout status.");
        }

        if (result.payment.status === "paid") {
          const storedOrderId =
            sessionStorage.getItem("makepay_order_id");
          const countryCode =
            sessionStorage.getItem("makepay_country_code");
          sessionStorage.removeItem("makepay_return_state");
          if (!storedOrderId || !countryCode) {
            setMessage(
              "Payment confirmed. Open your order history or confirmation email for details.",
            );
            return;
          }

          sessionStorage.removeItem("makepay_order_id");
          sessionStorage.removeItem("makepay_country_code");
          window.location.replace(
            `/${encodeURIComponent(countryCode)}/order/${encodeURIComponent(storedOrderId)}/confirmed`,
          );
          return;
        }

        if (
          result.payment.status === "failed" ||
          result.payment.status === "canceled"
        ) {
          sessionStorage.removeItem("makepay_return_state");
          setMessage(
            `MakePay payment ${result.payment.status}. Return to checkout to try again.`,
          );
          return;
        }

        schedule(attempt + 1);
      } catch (error) {
        if (
          stopped ||
          (error instanceof DOMException && error.name === "AbortError")
        ) {
          return;
        }
        if (attempt + 1 >= MAX_ATTEMPTS) {
          setMessage(
            "MakePay status is temporarily unavailable. Check your order history before trying again.",
          );
          return;
        }
        schedule(attempt + 1);
      }
    }

    void poll(0);

    return () => {
      stopped = true;
      controller.abort();
      if (timer !== undefined) {
        window.clearTimeout(timer);
      }
    };
  }, []);

  return (
    <main className="content-container py-16">
      <h1>MakePay payment</h1>
      <p role="status">{message}</p>
    </main>
  );
}
```

The empty dependency array and direct browser-state read keep this a
mount-scoped effect instead of restarting it for `useSearchParams` lifecycle
changes. Saving the state before URL cleanup keeps development lifecycle replay
safe.

The endpoint returns `404` for an unknown state. A successful response always
contains a non-null `payment`; it never uses `payment: null` as a pending
signal. Configure the return document itself to send
`Referrer-Policy: no-referrer` (for example, Next.js route metadata
`{ referrer: "no-referrer" }`). The plugin also marks the backend return and
status responses `no-store`, but that does not replace the storefront
document's own referrer policy.

Crypto settlement can arrive after a link was reported failed, expired, or
cancelled. A later exactly correlated, signed `complete` can therefore upgrade
the same order to paid; paid never regresses to an unsuccessful state. If the
return page has stopped polling, the customer's normal order-history view
should still surface that server-side transition.

The opaque state remains resolvable while its local payment projection is
retained so delayed settlement and a later browser return still work. Treat it
as bearer-like checkout material: avoid analytics capture, do not write it to
application logs, and remove it from the address bar immediately after reading
it into memory. Navigate to the confirmed order only from the order ID stored
before leaving the storefront; never recover an order ID from the public status
response.

## Recovery cases

- **Browser closed on MakePay:** the signed webhook still updates the order;
  the customer can find it in order history.
- **Return before webhook:** show awaiting payment and poll the status endpoint.
- **Webhook before return:** the first status request returns the paid state.
- **Canceled or expired link:** keep the order unpaid and offer a new cart or
  payment attempt only after the original attempt is safe to leave; do not
  mark it paid from return parameters. A late signed settlement for that exact
  session may still move the original order to paid.
- **Network uncertainty during link creation:** retain the cart and retry
  through the same Medusa session so the provider can reconcile its
  idempotency key.
