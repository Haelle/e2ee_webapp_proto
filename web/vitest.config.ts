import { defineConfig } from 'vitest/config';

// Unit tests for pure crypto/replay logic — no SvelteKit, no backend.
export default defineConfig({
	test: {
		environment: 'node',
		include: ['src/**/*.test.ts'],
		testTimeout: 20000
	}
});
