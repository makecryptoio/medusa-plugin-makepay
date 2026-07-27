import { expect } from "@playwright/test";

function normalizedScopes(scopes) {
  return Array.isArray(scopes)
    ? scopes.filter((scope) => typeof scope === "string").sort()
    : [];
}

export function oauthConnectionReadiness(
  connection,
  { companyId, expectedScopes },
) {
  return {
    company_id: connection?.company_id ?? null,
    connected: connection?.connected === true,
    scopes: normalizedScopes(connection?.scopes),
    status: connection?.status ?? null,
    webhook: connection?.webhook?.status ?? null,
  };
}

export async function waitForOAuthConnection(
  readConnection,
  { companyId, expectedScopes, timeout = 60_000 },
) {
  let connection;
  await expect
    .poll(
      async () => {
        connection = await readConnection();
        return oauthConnectionReadiness(connection, {
          companyId,
          expectedScopes,
        });
      },
      {
        intervals: [100, 250, 500, 1_000],
        timeout,
      },
    )
    .toEqual({
      company_id: companyId,
      connected: true,
      scopes: normalizedScopes(expectedScopes),
      status: "connected",
      webhook: "healthy",
    });
  return connection;
}
