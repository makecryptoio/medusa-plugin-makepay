import assert from "node:assert/strict";
import test from "node:test";

import {
  firstPurchasableOptionCombination,
  optionCombinations,
} from "./e2e/support/storefront-product-options.mjs";

test("storefront option combinations preserve deterministic cartesian order", () => {
  assert.deepEqual(optionCombinations([["S", "M"], ["Black", "White"]]), [
    ["S", "Black"],
    ["S", "White"],
    ["M", "Black"],
    ["M", "White"],
  ]);
  assert.deepEqual(optionCombinations([["S"], []]), []);
});

test("storefront selection accepts the first purchasable combination", async () => {
  const attempted = [];
  const selected = await firstPurchasableOptionCombination(
    [
      ["S", "M"],
      ["Black", "White"],
    ],
    async (combination) => {
      attempted.push(combination);
      return combination.join("/") === "M/Black";
    },
  );

  assert.deepEqual(selected, ["M", "Black"]);
  assert.deepEqual(attempted, [
    ["S", "Black"],
    ["S", "White"],
    ["M", "Black"],
  ]);
});

test("storefront selection fails closed when no combination is purchasable", async () => {
  assert.equal(
    await firstPurchasableOptionCombination(
      [
        ["S", "M"],
        ["Black"],
      ],
      async () => false,
    ),
    null,
  );
});
