import { defineConfig, loadEnv } from "@medusajs/framework/utils";

loadEnv(process.env.NODE_ENV || "development", process.cwd());

const configuredAuthMode = process.env.MAKEPAY_AUTH_MODE || "oauth";
const legacyApiKeyInference = configuredAuthMode === "legacy_api_key";
const apiKeyMode = configuredAuthMode === "api_key" || legacyApiKeyInference;

const sharedOptions = !apiKeyMode
  ? {
      authMode: "oauth" as const,
      backendUrl: process.env.MAKEPAY_BACKEND_URL!,
      baseUrl: process.env.MAKEPAY_API_URL!,
      checkoutBaseUrl: process.env.MAKEPAY_CHECKOUT_URL!,
      encryptionKey: process.env.MAKEPAY_ENCRYPTION_KEY!,
      expirationTime: "12h",
      lockingProvider: "makepay-postgres",
      oauthIssuerUrl: process.env.MAKEPAY_OAUTH_ISSUER_URL!,
      settlementCurrency: "USDT",
      storefrontReturnUrl: process.env.MAKEPAY_STOREFRONT_RETURN_URL!,
    }
  : {
      ...(legacyApiKeyInference ? {} : { authMode: "api_key" as const }),
      baseUrl: process.env.MAKEPAY_API_URL!,
      checkoutBaseUrl: process.env.MAKEPAY_CHECKOUT_URL!,
      expirationTime: "12h",
      keyId: process.env.MAKEPAY_KEY_ID!,
      keySecret: process.env.MAKEPAY_KEY_SECRET!,
      lockingProvider: "makepay-postgres",
      settlementCurrency: "USDT",
      webhookSecret: process.env.MAKEPAY_WEBHOOK_SECRET!,
    };

export default defineConfig({
  projectConfig: {
    // The deterministic production build runs on loopback HTTP. The runner
    // explicitly disables Secure only for that disposable fixture; the real
    // HTTPS sandbox path keeps production cookie transport semantics.
    cookieOptions: {
      sameSite: "lax",
      secure:
        process.env.MAKEPAY_E2E_LOOPBACK_INSECURE_COOKIES === "1"
          ? false
          : true,
    },
    databaseUrl: process.env.DATABASE_URL!,
    http: {
      adminCors: process.env.ADMIN_CORS!,
      authCors: process.env.AUTH_CORS!,
      cookieSecret: process.env.COOKIE_SECRET!,
      jwtSecret: process.env.JWT_SECRET!,
      storeCors: process.env.STORE_CORS!,
    },
  },
  plugins: [
    {
      options: sharedOptions,
      resolve: "@makecrypto/medusa-plugin-makepay",
    },
  ],
  modules: [
    {
      options: {
        providers: [
          {
            id: "makepay-postgres",
            is_default: true,
            resolve: "@medusajs/medusa/locking-postgres",
          },
        ],
      },
      resolve: "@medusajs/medusa/locking",
    },
    {
      options: {
        providers: [
          {
            id: "makepay",
            options: sharedOptions,
            resolve: "@makecrypto/medusa-plugin-makepay/providers/makepay",
          },
        ],
      },
      resolve: "@medusajs/medusa/payment",
    },
  ],
});
