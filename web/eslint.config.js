import js from '@eslint/js';
import svelte from 'eslint-plugin-svelte';
import globals from 'globals';
import ts from 'typescript-eslint';

export default ts.config(
	js.configs.recommended,
	...ts.configs.recommended,
	...svelte.configs.recommended,
	{
		languageOptions: {
			globals: { ...globals.browser, ...globals.node }
		}
	},
	{
		files: ['**/*.svelte', '**/*.svelte.ts', '**/*.svelte.js'],
		languageOptions: {
			parserOptions: { parser: ts.parser }
		}
	},
	{
		// Interop avec des bibliothèques crypto non typées (age, libsodium, cbor-x) :
		// `any` y est parfois inévitable et volontairement localisé au module crypto/.
		rules: {
			'@typescript-eslint/no-explicit-any': 'off',
			'@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
			// SPA sans base path : la navigation interne vers des chemins statiques
			// n'a pas besoin de resolve(). À réactiver si un base path est introduit.
			'svelte/no-navigation-without-resolve': 'off'
		}
	},
	{
		// Composants générés par shadcn-svelte : vendored, non linter.
		ignores: [
			'build/',
			'.svelte-kit/',
			'dist/',
			'node_modules/',
			'src/lib/components/ui/**'
		]
	}
);
