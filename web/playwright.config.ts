import { defineConfig } from '@playwright/test';

// Builds the SPA and serves it with `vite preview`, then runs the smoke test
// against it. No backend is required — the home page renders offline.
export default defineConfig({
	testDir: 'e2e',
	use: {
		baseURL: 'http://localhost:4173'
	},
	webServer: {
		command: 'pnpm build && pnpm preview --port 4173',
		port: 4173,
		reuseExistingServer: !process.env.CI,
		timeout: 120_000
	}
});
