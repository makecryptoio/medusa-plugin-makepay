export const MAKEPAY_MODULE = "makepayIntegration";
export const MAKEPAY_PROVIDER_IDENTIFIER = "makepay";
export const MAKEPAY_DEFAULT_PROVIDER_ID = "makepay";

export const MAKEPAY_OAUTH_SCOPES = [
  "company:read",
  "makepay:payment-links:read",
  "makepay:payment-links:write",
  "makepay:webhooks:read",
  "makepay:webhooks:write",
] as const;
