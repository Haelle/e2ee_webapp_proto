/**
 * End-to-end happy path against a LIVE backend (FastAPI + Postgres on :8000):
 * enrol two members, found a group, write a note, coopt the second member — all
 * driven through the real browser crypto. The group composition shown is the
 * client-side chain replay (the authority, SPEC §13), not the server's view.
 *
 * Guarded: only runs when E2E_BACKEND is set (CI's default smoke has no backend).
 *   E2E_BACKEND=1 pnpm test:e2e
 */
import { expect, test } from '@playwright/test';

const uniq = Date.now().toString(36);
const A = `A-${uniq}`;
const B = `B-${uniq}`;

test.skip(!process.env.E2E_BACKEND, 'requires FastAPI+Postgres on :8000');

test('enrol → found → note → coopt, with client-side chain authority', async ({ page }) => {
	const enrol = async (mat: string) => {
		await page.goto('/');
		await page.getByLabel('Matricule').fill(mat);
		await page.getByLabel('Passphrase').fill(`pw-${mat}`);
		await page.getByRole('button', { name: "S'enrôler" }).click();
		await expect(page.getByText('Enrôlement réussi')).toBeVisible();
	};

	await enrol(A);
	await enrol(B);

	// Login as A → groups list.
	await page.goto('/');
	await page.getByLabel('Matricule').fill(A);
	await page.getByLabel('Passphrase').fill(`pw-${A}`);
	await page.getByRole('button', { name: 'Se connecter' }).click();
	await expect(page).toHaveURL(/\/groups$/);

	// Found a group → group detail, chain verified, A is the sole member.
	await page.getByLabel('Nom').fill(`demo-${uniq}`);
	await page.getByRole('button', { name: 'Fonder' }).click();
	await expect(page).toHaveURL(/\/groups\/[0-9a-f-]+$/);
	await expect(page.getByText('chaîne vérifiée')).toBeVisible();
	await expect(page.getByText(`${A} (vous)`)).toBeVisible();

	// Write a note (sealed client-side, decrypted back into the list).
	await page.getByLabel('Titre').fill('hello');
	await page.getByLabel('Contenu').fill('secret-body');
	await page.getByRole('button', { name: 'Créer' }).click();
	await expect(page.getByText('hello')).toBeVisible();

	// Coopt B → B appears in the (chain-derived) composition, chain still valid.
	await page.getByLabel('Coopter (matricule)').fill(B);
	await page.getByRole('button', { name: 'Coopter' }).click();
	// B now appears in the (chain-derived) composition list, exact match.
	await expect(page.getByText(B, { exact: true })).toBeVisible();
	await expect(page.getByText('chaîne vérifiée')).toBeVisible();
});
