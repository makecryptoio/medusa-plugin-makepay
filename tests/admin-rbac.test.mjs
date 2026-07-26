import assert from "node:assert/strict";
import test from "node:test";

import {
  errorHandler,
  wrapWithPoliciesCheck,
} from "@medusajs/framework/http";
import { ContainerRegistrationKeys } from "@medusajs/framework/utils";

import middlewares, {
  MAKEPAY_ADMIN_ROUTE_POLICIES,
} from "../src/api/middlewares.ts";

const expectedPolicies = [
  ["GET", "/admin/makepay/connection", ["store:read"]],
  ["POST", "/admin/makepay/oauth/start", ["store:update"]],
  ["POST", "/admin/makepay/disconnect", ["store:update"]],
  ["GET", "/admin/makepay/payments", ["payment:read"]],
  ["GET", "/admin/makepay/payments/:id", ["payment:read"]],
  [
    "POST",
    "/admin/makepay/payments/:id/reconcile",
    ["payment:read", "capture:create"],
  ],
  ["GET", "/admin/makepay/orders/:orderId", ["order:read"]],
];

function actionKeys(policies) {
  return policies.flatMap(({ operation, resource }) =>
    (Array.isArray(operation) ? operation : [operation]).map(
      (candidate) => `${resource}:${candidate}`,
    ),
  );
}

function fakeContainer(rolePolicies) {
  const logger = { error() {}, info() {} };
  return {
    resolve(name, options = {}) {
      if (name === ContainerRegistrationKeys.FEATURE_FLAG_ROUTER) {
        return { isFeatureEnabled: (flag) => flag === "rbac" };
      }
      if (name === ContainerRegistrationKeys.QUERY) {
        return {
          async graph({ filters }) {
            const policies = rolePolicies.get(filters.id) ?? [];
            return {
              data: [
                {
                  id: filters.id,
                  policies: policies.map((policy, index) => ({
                    id: `${filters.id}_${index}`,
                    ...policy,
                  })),
                },
              ],
            };
          },
        };
      }
      if (name === ContainerRegistrationKeys.LOGGER) return logger;
      if (options.allowUnregistered) return undefined;
      throw new Error(`Unexpected dependency: ${name}`);
    },
  };
}

async function exercisePolicy({ actor, policies, rolePolicies }) {
  let handled = false;
  let policyError;
  const scope = fakeContainer(rolePolicies);
  const request = {
    auth_context: {
      actor_id: actor.id,
      actor_type: actor.type,
      app_metadata: { roles: actor.roleId ? [actor.roleId] : [] },
    },
    path: "/admin/makepay/test",
    scope,
    ...(actor.apiKey ? { secret_key_context: { created_by: actor.id } } : {}),
  };
  const checked = wrapWithPoliciesCheck(
    () => {
      handled = true;
    },
    policies,
  );
  await checked(request, {}, (error) => {
    policyError = error;
  });
  if (!policyError) return { handled, status: 200 };

  const response = {
    body: undefined,
    statusCode: undefined,
    json(body) {
      this.body = body;
      return this;
    },
    status(statusCode) {
      this.statusCode = statusCode;
      return this;
    },
  };
  errorHandler()(policyError, request, response, () => {});
  return { body: response.body, handled, status: response.statusCode };
}

test("every MakePay Admin method/path has an exact Medusa RBAC policy", () => {
  assert.deepEqual(
    MAKEPAY_ADMIN_ROUTE_POLICIES.map((route) => [
      route.methods[0],
      route.matcher,
      actionKeys(route.policies),
    ]),
    expectedPolicies,
  );
  assert.deepEqual(
    middlewares.routes
      .filter((route) => route.policies)
      .map((route) => [route.methods[0], route.matcher]),
    expectedPolicies.map(([method, matcher]) => [method, matcher]),
  );
});

test("RBAC returns 403 for restricted users and API keys and permits authorized roles", async () => {
  const paymentRead = { operation: "read", resource: "payment" };
  const captureCreate = { operation: "create", resource: "capture" };
  const storeUpdate = { operation: "update", resource: "store" };
  const roles = new Map([
    ["role_payment_reader", [paymentRead]],
    ["role_reconciler", [paymentRead, captureCreate]],
    ["role_store_admin", [storeUpdate]],
  ]);
  const reconcile = MAKEPAY_ADMIN_ROUTE_POLICIES.find(
    (route) => route.matcher === "/admin/makepay/payments/:id/reconcile",
  );
  const oauthStart = MAKEPAY_ADMIN_ROUTE_POLICIES.find(
    (route) => route.matcher === "/admin/makepay/oauth/start",
  );

  const restrictedUser = await exercisePolicy({
    actor: { id: "user_reader", roleId: "role_payment_reader", type: "user" },
    policies: oauthStart.policies,
    rolePolicies: roles,
  });
  assert.equal(restrictedUser.status, 403);
  assert.equal(restrictedUser.body.type, "forbidden");
  assert.equal(restrictedUser.handled, false);

  const restrictedApiKey = await exercisePolicy({
    actor: {
      apiKey: true,
      id: "apk_reader",
      roleId: "role_payment_reader",
      type: "user",
    },
    policies: reconcile.policies,
    rolePolicies: roles,
  });
  assert.equal(restrictedApiKey.status, 403);
  assert.equal(restrictedApiKey.body.type, "forbidden");
  assert.equal(restrictedApiKey.handled, false);

  const secretAdminApiKey = await exercisePolicy({
    actor: {
      apiKey: true,
      id: "apk_secret",
      type: "api-key",
    },
    policies: reconcile.policies,
    rolePolicies: roles,
  });
  assert.equal(secretAdminApiKey.status, 403);
  assert.equal(secretAdminApiKey.body.type, "forbidden");
  assert.equal(secretAdminApiKey.handled, false);

  const authorizedReconciler = await exercisePolicy({
    actor: {
      id: "user_reconciler",
      roleId: "role_reconciler",
      type: "user",
    },
    policies: reconcile.policies,
    rolePolicies: roles,
  });
  assert.deepEqual(authorizedReconciler, { handled: true, status: 200 });

  const authorizedStoreAdmin = await exercisePolicy({
    actor: {
      id: "user_store_admin",
      roleId: "role_store_admin",
      type: "user",
    },
    policies: oauthStart.policies,
    rolePolicies: roles,
  });
  assert.deepEqual(authorizedStoreAdmin, { handled: true, status: 200 });
});
