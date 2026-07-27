import assert from "node:assert/strict";
import test from "node:test";

import { validateRealSandboxCompanyDirectory } from "./e2e/support/real-sandbox-company.mjs";

const companyId = "company_sandbox";
const companyName = "Example Sandbox Merchant";
const input = { companyId, companyName };

function directory(overrides = {}) {
  return {
    companies: [
      {
        id: companyId,
        name: companyName,
        settings: {
          allowPersonalWorkspace: false,
          sandboxMode: true,
        },
        ...overrides,
      },
    ],
  };
}

test("real-sandbox company preflight accepts only the authoritative sandbox shape", () => {
  assert.equal(
    validateRealSandboxCompanyDirectory(directory(), input),
    "sandbox-confirmed",
  );
  assert.equal(
    validateRealSandboxCompanyDirectory(
      directory({
        settings: {
          allowPersonalWorkspace: false,
          sandboxMode: false,
        },
      }),
      input,
    ),
    "sandbox-disabled",
  );
  assert.equal(
    validateRealSandboxCompanyDirectory(
      directory({
        settings: {
          allow_personal_workspace: false,
          sandbox_mode: true,
        },
      }),
      input,
    ),
    "invalid-sandbox-settings",
  );
});

test("real-sandbox company preflight fails closed for missing or ambiguous identity", () => {
  assert.equal(
    validateRealSandboxCompanyDirectory(
      {
        companies: [directory().companies[0], directory().companies[0]],
      },
      input,
    ),
    "company-missing-or-ambiguous",
  );
  assert.equal(
    validateRealSandboxCompanyDirectory(
      directory({ name: "Different Merchant" }),
      input,
    ),
    "company-name-mismatch",
  );
  assert.equal(
    validateRealSandboxCompanyDirectory(
      {
        companies: directory().companies,
        sandbox_mode: true,
      },
      input,
    ),
    "invalid-directory",
  );
});
