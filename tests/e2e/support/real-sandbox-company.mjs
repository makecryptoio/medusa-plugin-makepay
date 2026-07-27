const exactKeys = (value, expected) =>
  value &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  JSON.stringify(Object.keys(value).sort()) ===
    JSON.stringify([...expected].sort());

export function validateRealSandboxCompanyDirectory(
  payload,
  { companyId, companyName },
) {
  if (
    typeof companyId !== "string" ||
    !companyId ||
    typeof companyName !== "string" ||
    !companyName ||
    !exactKeys(payload, ["companies"]) ||
    !Array.isArray(payload.companies)
  ) {
    return "invalid-directory";
  }

  const matches = payload.companies.filter(
    (company) =>
      company &&
      typeof company === "object" &&
      !Array.isArray(company) &&
      company.id === companyId,
  );
  if (matches.length !== 1) return "company-missing-or-ambiguous";

  const company = matches[0];
  if (company.name !== companyName) return "company-name-mismatch";
  if (
    !exactKeys(company.settings, ["allowPersonalWorkspace", "sandboxMode"]) ||
    typeof company.settings.allowPersonalWorkspace !== "boolean" ||
    typeof company.settings.sandboxMode !== "boolean"
  ) {
    return "invalid-sandbox-settings";
  }
  return company.settings.sandboxMode
    ? "sandbox-confirmed"
    : "sandbox-disabled";
}
