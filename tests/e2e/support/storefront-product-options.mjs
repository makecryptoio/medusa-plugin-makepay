import { expect } from "@playwright/test";

export function optionCombinations(optionGroups) {
  if (
    !Array.isArray(optionGroups) ||
    optionGroups.some(
      (group) =>
        !Array.isArray(group) ||
        group.length === 0 ||
        group.some((value) => typeof value !== "string" || !value.trim()),
    )
  ) {
    return [];
  }

  return optionGroups.reduce(
    (combinations, group) =>
      combinations.flatMap((combination) =>
        group.map((value) => [...combination, value.trim()]),
      ),
    [[]],
  );
}

export async function firstPurchasableOptionCombination(
  optionGroups,
  isPurchasable,
) {
  for (const combination of optionCombinations(optionGroups)) {
    if (await isPurchasable([...combination])) {
      return combination;
    }
  }
  return null;
}

export async function selectPurchasableProductOptions(page) {
  const groups = page.getByTestId("product-options");
  await expect(groups.first()).toBeVisible({ timeout: 60_000 });
  const groupCount = await groups.count();
  expect(groupCount).toBeGreaterThan(0);

  const optionGroups = [];
  for (let groupIndex = 0; groupIndex < groupCount; groupIndex += 1) {
    const buttons = groups.nth(groupIndex).getByTestId("option-button");
    await expect(buttons.first()).toBeEnabled({ timeout: 60_000 });
    const values = (await buttons.allTextContents())
      .map((value) => value.trim())
      .filter(Boolean);
    expect(values.length).toBeGreaterThan(0);
    expect(new Set(values).size).toBe(values.length);
    optionGroups.push(values);
  }

  const addButton = page.getByTestId("add-product-button");
  let lastButtonText = "";
  const selected = await firstPurchasableOptionCombination(
    optionGroups,
    async (combination) => {
      try {
        await expect(async () => {
          for (
            let groupIndex = 0;
            groupIndex < combination.length;
            groupIndex += 1
          ) {
            const option = page
              .getByTestId("product-options")
              .nth(groupIndex)
              .getByRole("button", {
                exact: true,
                name: combination[groupIndex],
              });
            await expect(option).toBeEnabled({ timeout: 2_000 });
            await option.click();
          }

          for (
            let groupIndex = 0;
            groupIndex < combination.length;
            groupIndex += 1
          ) {
            await expect(
              page
                .getByTestId("product-options")
                .nth(groupIndex)
                .getByRole("button", {
                  exact: true,
                  name: combination[groupIndex],
                }),
            ).toHaveClass(/border-ui-border-interactive/, {
              timeout: 2_000,
            });
          }

          await expect(addButton).toHaveText("Add to cart", {
            timeout: 2_000,
          });
          await expect(addButton).toBeEnabled({ timeout: 2_000 });
        }).toPass({
          intervals: [250, 500, 1_000],
          timeout: 5_000,
        });
        return true;
      } catch {
        lastButtonText = String((await addButton.textContent()) ?? "").trim();
        return false;
      }
    },
  );

  if (!selected) {
    throw new Error(
      `Pinned Medusa product exposes no purchasable option combination (last button: ${lastButtonText || "unknown"}).`,
    );
  }

  await expect(addButton).toHaveText("Add to cart");
  await expect(addButton).toBeEnabled();
  return selected;
}
