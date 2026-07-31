<script lang="ts">
	import { goto } from '$app/navigation';
	import * as Card from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import * as api from '$lib/api/client';
	import { createKeyblob, signChallenge, unlockKeyblob } from '$lib/crypto';
	import { startSession } from '$lib/stores/session';

	let matricule = $state('');
	let passphrase = $state('');
	let busy = $state(false);
	let error = $state('');
	let info = $state('');

	function reset() {
		error = '';
		info = '';
	}

	function fail(e: unknown) {
		error = e instanceof Error ? e.message : String(e);
	}

	async function login() {
		reset();
		if (!matricule || !passphrase) {
			error = 'Matricule et passphrase requis.';
			return;
		}
		busy = true;
		try {
			// Ed25519 challenge/response → session cookie. Signing the challenge
			// needs the Ed25519 key, so the (public, encrypted) keyblob is fetched
			// and unlocked between the challenge and the verify.
			const nonce = await api.challenge(matricule);
			const wrappedSeed = await api.getKeyblob(matricule);
			const kb = await unlockKeyblob(passphrase, wrappedSeed);
			const sig = await signChallenge(kb.ed25519Sk, nonce);
			await api.verify(matricule, sig);

			// The session cookie is now set → fetch this member's active key id and
			// age recipient (needed to sign grants and rewrap epoch envelopes).
			const me = await api.getMemberInfo(matricule);
			startSession({
				matricule,
				keyId: me.keyId,
				ageRecipient: me.ageRecipient,
				ageIdentity: kb.ageIdentity,
				ed25519Sk: kb.ed25519Sk
			});
			await goto('/groups');
		} catch (e) {
			fail(e);
		} finally {
			busy = false;
		}
	}

	async function enrol() {
		reset();
		if (!matricule || !passphrase) {
			error = 'Matricule et passphrase requis.';
			return;
		}
		busy = true;
		try {
			// Everything secret is generated client-side; the server only receives
			// public parts and the passphrase-wrapped keyblob (SPEC §10).
			const kb = await createKeyblob(passphrase);
			await api.enroll({
				matricule,
				displayName: matricule,
				ageRecipient: kb.ageRecipient,
				ed25519Pub: kb.ed25519Pub,
				wrappedSeed: kb.wrappedSeed
			});
			info = 'Enrôlement réussi. Vous pouvez vous connecter.';
		} catch (e) {
			fail(e);
		} finally {
			busy = false;
		}
	}
</script>

<div class="flex min-h-screen items-center justify-center bg-background p-4">
	<Card.Root class="w-full max-w-sm">
		<Card.Header>
			<Card.Title>Notes chiffrées</Card.Title>
			<Card.Description>Chiffrement de bout en bout par groupe.</Card.Description>
		</Card.Header>
		<Card.Content>
			<form
				class="flex flex-col gap-4"
				onsubmit={(e) => {
					e.preventDefault();
					login();
				}}
			>
				<div class="flex flex-col gap-2">
					<Label for="matricule">Matricule</Label>
					<Input id="matricule" bind:value={matricule} autocomplete="username" disabled={busy} />
				</div>
				<div class="flex flex-col gap-2">
					<Label for="passphrase">Passphrase</Label>
					<Input
						id="passphrase"
						type="password"
						bind:value={passphrase}
						autocomplete="current-password"
						disabled={busy}
					/>
				</div>

				{#if error}
					<p class="text-sm text-destructive" role="alert">{error}</p>
				{/if}
				{#if info}
					<p class="text-sm text-muted-foreground">{info}</p>
				{/if}

				<div class="flex gap-2">
					<Button type="submit" class="flex-1" disabled={busy}>Se connecter</Button>
					<Button type="button" variant="outline" class="flex-1" disabled={busy} onclick={enrol}>
						S'enrôler
					</Button>
				</div>
			</form>
		</Card.Content>
	</Card.Root>
</div>
