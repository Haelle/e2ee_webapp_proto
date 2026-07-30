import { expect, test } from '@playwright/test';

test('home page renders the login card title', async ({ page }) => {
	await page.goto('/');
	await expect(page.getByText('Notes chiffrées')).toBeVisible();
});
