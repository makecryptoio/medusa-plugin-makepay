import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

function replaceOnce(source, search, replacement, label) {
  const first = source.indexOf(search);
  if (first === -1) throw new Error(`Starter patch anchor not found: ${label}`);
  if (source.indexOf(search, first + search.length) !== -1) {
    throw new Error(`Starter patch anchor is ambiguous: ${label}`);
  }
  return (
    source.slice(0, first) + replacement + source.slice(first + search.length)
  );
}

async function patchFile(path, patches) {
  let source = await readFile(path, "utf8");
  for (const patch of patches) {
    if (source.includes(patch.replacement)) continue;
    const searches = Array.isArray(patch.search)
      ? patch.search
      : [patch.search];
    const search = searches.find((candidate) => source.includes(candidate));
    if (!search) {
      throw new Error(`Starter patch anchor not found: ${patch.label}`);
    }
    source = replaceOnce(source, search, patch.replacement, patch.label);
  }
  await writeFile(path, source);
}

async function removeLegacyMakePayPaymentButton(path) {
  const source = await readFile(path, "utf8");
  const componentStart = "const MakePayPaymentButton = ({";
  const stripeStart = "const StripePaymentButton = ({";
  const currentMarker =
    'sessionStorage.setItem("makepay_return_state", returnState)';
  const componentOffsets = [];
  for (
    let offset = source.indexOf(componentStart);
    offset !== -1;
    offset = source.indexOf(componentStart, offset + componentStart.length)
  ) {
    componentOffsets.push(offset);
  }

  if (source.includes(currentMarker)) {
    if (componentOffsets.length !== 1) {
      throw new Error(
        "Official storefront contains duplicate MakePay payment buttons.",
      );
    }
    return;
  }
  if (componentOffsets.length === 0) return;
  if (componentOffsets.length !== 1) {
    throw new Error(
      "Official storefront contains ambiguous legacy MakePay payment buttons.",
    );
  }

  const start = componentOffsets[0];
  const end = source.indexOf(stripeStart, start + componentStart.length);
  if (end === -1) {
    throw new Error(
      "Legacy MakePay payment button has no Stripe component boundary.",
    );
  }
  await writeFile(path, source.slice(0, start) + source.slice(end));
}

export async function patchOfficialStorefront(projectRoot) {
  const root = resolve(projectRoot);
  const storefront = join(root, "apps/storefront");
  const backendPackage = JSON.parse(
    await readFile(join(root, "apps/backend/package.json"), "utf8"),
  );
  if (backendPackage.dependencies?.["@medusajs/framework"] !== "2.17.2") {
    throw new Error(
      "The checked storefront patch only supports the official Medusa 2.17.2 starter.",
    );
  }

  await patchFile(join(storefront, "src/lib/config.ts"), [
    {
      label: "server-only Medusa backend origin",
      search: `if (process.env.NEXT_PUBLIC_MEDUSA_BACKEND_URL) {
  MEDUSA_BACKEND_URL = process.env.NEXT_PUBLIC_MEDUSA_BACKEND_URL
}`,
      replacement: `if (process.env.MEDUSA_BACKEND_URL) {
  MEDUSA_BACKEND_URL = process.env.MEDUSA_BACKEND_URL
} else if (process.env.NEXT_PUBLIC_MEDUSA_BACKEND_URL) {
  MEDUSA_BACKEND_URL = process.env.NEXT_PUBLIC_MEDUSA_BACKEND_URL
}`,
    },
  ]);

  await patchFile(join(storefront, "src/lib/constants.tsx"), [
    {
      label: "MakePay payment information",
      search: `  pp_system_default: {
    title: "Manual Payment",
    icon: <CreditCard />,
  },
  // Add more payment providers here`,
      replacement: `  pp_system_default: {
    title: "Manual Payment",
    icon: <CreditCard />,
  },
  pp_makepay_makepay: {
    title: "MakePay",
    icon: <CreditCard />,
  },
  // Add more payment providers here`,
    },
    {
      label: "MakePay provider predicate",
      search: `export const isManual = (providerId?: string) => {
  return providerId?.startsWith("pp_system_default")
}

// Add currencies`,
      replacement: `export const isManual = (providerId?: string) => {
  return providerId?.startsWith("pp_system_default")
}

export const isMakePay = (providerId?: string) => {
  return providerId === "pp_makepay_makepay"
}

// Add currencies`,
    },
  ]);

  await patchFile(
    join(storefront, "src/modules/checkout/components/payment/index.tsx"),
    [
      {
        label: "asynchronous active MakePay session",
        search: [
          `  const activeSession = cart.payment_collection?.payment_sessions?.find(
    (paymentSession) => paymentSession.status === "pending"
  )`,
          `  const activeSession = cart.payment_collection?.payment_sessions?.find(
    (paymentSession) =>
      paymentSession.status === "pending" ||
      paymentSession.status === "requires_more"
  )`,
        ],
        replacement: `  const activeSession = cart.payment_collection?.payment_sessions?.find(
    (paymentSession) =>
      paymentSession.status === "pending" ||
      paymentSession.status === "requires_more" ||
      paymentSession.status === "pending_authorization"
  )`,
      },
      {
        label: "run-owned MakePay guest email",
        search: `      if (!checkActiveSession) {
        await initiatePaymentSession(cart, {
          provider_id: selectedPaymentMethod,
        })
      }`,
        replacement: `      if (!checkActiveSession) {
        await initiatePaymentSession(cart, {
          data:
            selectedPaymentMethod === "pp_makepay_makepay" && cart.email
              ? { customer_email: cart.email }
              : undefined,
          provider_id: selectedPaymentMethod,
        })
      }`,
      },
    ],
  );

  const buttonPath = join(
    storefront,
    "src/modules/checkout/components/payment-button/index.tsx",
  );
  await removeLegacyMakePayPaymentButton(buttonPath);
  await patchFile(buttonPath, [
    {
      label: "MakePay button imports",
      search: `import { isManual, isStripeLike } from "@lib/constants"
import { placeOrder } from "@lib/data/cart"`,
      replacement: `import { isMakePay, isManual, isStripeLike } from "@lib/constants"
import { completeMakePayOrder, placeOrder } from "@lib/data/cart"`,
    },
    {
      label: "MakePay button switch",
      search: `    case isManual(paymentSession?.provider_id):
      return (
        <ManualTestPaymentButton notReady={notReady} data-testid={dataTestId} />
      )
    default:`,
      replacement: `    case isManual(paymentSession?.provider_id):
      return (
        <ManualTestPaymentButton notReady={notReady} data-testid={dataTestId} />
      )
    case isMakePay(paymentSession?.provider_id):
      return (
        <MakePayPaymentButton
          cart={cart}
          notReady={notReady}
          data-testid={dataTestId}
        />
      )
    default:`,
    },
    {
      label: "MakePay hosted checkout button",
      search: `const StripePaymentButton = ({`,
      replacement: `const MakePayPaymentButton = ({
  cart,
  notReady,
  "data-testid": dataTestId,
}: {
  cart: HttpTypes.StoreCart
  notReady: boolean
  "data-testid"?: string
}) => {
  const [submitting, setSubmitting] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const paymentSession = cart.payment_collection?.payment_sessions?.find(
    (session) => isMakePay(session.provider_id)
  )

  const handlePayment = async () => {
    setSubmitting(true)
    setErrorMessage(null)
    try {
      const nextAction = paymentSession?.data?.next_action as
        | { type?: string; url?: string }
        | undefined
      const returnState = paymentSession?.data?.return_state
      if (
        nextAction?.type !== "redirect" ||
        !nextAction.url ||
        typeof returnState !== "string" ||
        !returnState
      ) {
        throw new Error("MakePay did not return a hosted checkout URL.")
      }
      const checkoutUrl = new URL(nextAction.url)
      const allowedOrigin = process.env.NEXT_PUBLIC_MAKEPAY_CHECKOUT_ORIGIN
      if (!allowedOrigin || checkoutUrl.origin !== new URL(allowedOrigin).origin) {
        throw new Error("MakePay returned an unexpected checkout origin.")
      }

      const order = await completeMakePayOrder(cart.id)
      sessionStorage.setItem("makepay_order_id", order.orderId)
      sessionStorage.setItem("makepay_country_code", order.countryCode)
      sessionStorage.setItem("makepay_return_state", returnState)
      window.location.assign(checkoutUrl.href)
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : String(error))
      setSubmitting(false)
    }
  }

  return (
    <>
      <Button
        disabled={notReady || !paymentSession}
        isLoading={submitting}
        onClick={handlePayment}
        size="large"
        data-testid={dataTestId}
      >
        Place order with MakePay
      </Button>
      <ErrorMessage
        error={errorMessage}
        data-testid="makepay-payment-error-message"
      />
    </>
  )
}

const StripePaymentButton = ({`,
    },
  ]);

  await patchFile(join(storefront, "src/lib/data/cart.ts"), [
    {
      label: "non-redirecting hosted payment completion",
      search: `/**
 * Places an order for a cart. If no cart ID is provided, it will use the cart ID from the cookies.`,
      replacement: `/**
 * Completes a cart before redirecting to a hosted payment page. The returned
 * order ID is retained by the browser so the MakePay return page can navigate
 * to the standard order confirmation after a verified server-side status check.
 */
export async function completeMakePayOrder(cartId?: string) {
  const id = cartId || (await getCartId())
  if (!id) throw new Error("No existing cart found when placing an order")

  const headers = { ...(await getAuthHeaders()) }
  const result = await sdk.store.cart.complete(id, {}, headers).catch(medusaError)
  if (result?.type !== "order") {
    throw new Error("Medusa did not create the MakePay order")
  }

  const countryCode =
    result.order.shipping_address?.country_code?.toLowerCase() || "dk"
  const cartCacheTag = await getCacheTag("carts")
  const orderCacheTag = await getCacheTag("orders")
  revalidateTag(cartCacheTag)
  revalidateTag(orderCacheTag)
  removeCartId()
  return { countryCode, orderId: result.order.id }
}

/**
 * Places an order for a cart. If no cart ID is provided, it will use the cart ID from the cookies.`,
    },
  ]);

  await patchFile(join(storefront, "src/lib/data/cookies.ts"), [
    {
      label: "loopback-only cart cookie transport",
      search: `export const setCartId = async (cartId: string) => {
  const cookies = await nextCookies()
  cookies.set("_medusa_cart_id", cartId, {
    maxAge: 60 * 60 * 24 * 7,
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
  })
}`,
      replacement: `export const setCartId = async (cartId: string) => {
  const cookies = await nextCookies()
  cookies.set("_medusa_cart_id", cartId, {
    maxAge: 60 * 60 * 24 * 7,
    httpOnly: true,
    sameSite: "strict",
    secure:
      process.env.MAKEPAY_E2E_LOOPBACK_INSECURE_COOKIES === "1"
        ? false
        : process.env.NODE_ENV === "production",
  })
}`,
    },
  ]);

  const returnDirectory = join(
    storefront,
    "src/app/[countryCode]/(main)/makepay/return",
  );
  await mkdir(returnDirectory, { recursive: true });
  await writeFile(
    join(returnDirectory, "page.tsx"),
    `"use client"

import { useEffect, useState } from "react"

const terminalSuccess = new Set(["paid"])
const terminalFailure = new Set(["canceled", "expired", "failed"])

export default function MakePayReturnPage() {
  const [message, setMessage] = useState("Confirming your MakePay payment…")

  useEffect(() => {
    const current = new URL(window.location.href)
    const urlState = current.searchParams.get("makepay_state")
    const state =
      urlState ||
      sessionStorage.getItem("makepay_return_state")
    if (!state) {
      setMessage("The MakePay return state is missing.")
      return
    }
    if (urlState) {
      current.searchParams.delete("makepay_state")
      window.history.replaceState(
        window.history.state,
        "",
        \`\${current.pathname}\${current.search}\${current.hash}\`
      )
    }
    let stopped = false
    let attempts = 0
    const check = async () => {
      attempts += 1
      const backend = process.env.NEXT_PUBLIC_MEDUSA_BACKEND_URL
      const publishableKey = process.env.NEXT_PUBLIC_MEDUSA_PUBLISHABLE_KEY
      const response = await fetch(
        \`\${backend}/store/makepay/checkout-status?state=\${encodeURIComponent(state)}\`,
        {
          cache: "no-store",
          headers: { "x-publishable-api-key": publishableKey || "" },
        }
      )
      if (!response.ok) throw new Error("Unable to verify the MakePay payment.")
      const result = await response.json()
      const payment = result.payment || result
      // The backend exposes "paid" only after raw MakePay "complete" has also
      // completed Medusa's capture workflow. Provider aliases are insufficient.
      const status = String(payment.status || "").toLowerCase()
      if (terminalSuccess.has(status)) {
        const orderId = sessionStorage.getItem("makepay_order_id")
        const countryCode = sessionStorage.getItem("makepay_country_code")
        sessionStorage.removeItem("makepay_return_state")
        if (!orderId || !countryCode) {
          setMessage(
            "Payment confirmed. Open your order history or confirmation email for details."
          )
          return
        }
        sessionStorage.removeItem("makepay_order_id")
        sessionStorage.removeItem("makepay_country_code")
        window.location.replace(
          \`/\${encodeURIComponent(countryCode)}/order/\${encodeURIComponent(orderId)}/confirmed\`
        )
        return
      }
      if (terminalFailure.has(status)) {
        sessionStorage.removeItem("makepay_return_state")
        setMessage(\`MakePay payment \${status}. Return to checkout to try again.\`)
        return
      }
      if (!stopped && attempts < 30) window.setTimeout(check, 2000)
      else setMessage("Your payment is still pending. You can safely close this page.")
    }
    check().catch((error) => setMessage(error.message))
    return () => {
      stopped = true
    }
  }, [])

  return (
    <main className="content-container py-16" data-testid="makepay-return-page">
      <h1 className="text-2xl-semi mb-4">MakePay payment</h1>
      <p role="status">{message}</p>
</main>
  )
}
`,
  );
  await writeFile(
    join(returnDirectory, "layout.tsx"),
    `import type { Metadata } from "next"
import type { ReactNode } from "react"

export const metadata: Metadata = {
  referrer: "no-referrer",
}

export default function MakePayReturnLayout({
  children,
}: {
  children: ReactNode
}) {
  return children
}
`,
  );
}

async function main() {
  const projectRoot = process.argv[2];
  if (!projectRoot) {
    throw new Error(
      "Usage: node patch-storefront.mjs /path/to/generated/project",
    );
  }
  await patchOfficialStorefront(projectRoot);
  console.log(
    "Patched official Medusa 2.17.2 storefront for MakePay hosted checkout.",
  );
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
