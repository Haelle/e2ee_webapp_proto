<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import * as Card from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import * as api from '$lib/api/client';
	import { foundGroup } from '$lib/group';
	import { endSession, session } from '$lib/stores/session';

	let groups = $state<api.GroupSummary[]>([]);
	let name = $state('');
	let error = $state('');
	let busy = $state(false);

	function fail(e: unknown) {
		error = e instanceof Error ? e.message : String(e);
	}

	onMount(() => {
		if ($session) load();
	});

	async function load() {
		error = '';
		busy = true;
		try {
			groups = await api.getGroups();
		} catch (e) {
			fail(e);
		} finally {
			busy = false;
		}
	}

	async function create() {
		if (!name) return;
		error = '';
		busy = true;
		try {
			const id = await foundGroup(name);
			name = '';
			await goto(`/groups/${id}`);
		} catch (e) {
			fail(e);
			busy = false;
		}
	}

	function logout() {
		endSession();
		goto('/');
	}
</script>

<div class="mx-auto flex min-h-screen max-w-2xl flex-col gap-6 p-4">
	<header class="flex items-center justify-between">
		<h1 class="text-xl font-semibold">Groupes</h1>
		{#if $session}
			<div class="flex items-center gap-3">
				<span class="text-sm text-muted-foreground">{$session.matricule}</span>
				<Button variant="outline" size="sm" onclick={logout}>Se déconnecter</Button>
			</div>
		{/if}
	</header>

	{#if !$session}
		<Card.Root>
			<Card.Header>
				<Card.Title>Session requise</Card.Title>
				<Card.Description>Connectez-vous pour accéder à vos groupes.</Card.Description>
			</Card.Header>
			<Card.Content>
				<Button onclick={() => goto('/')}>Aller à la connexion</Button>
			</Card.Content>
		</Card.Root>
	{:else}
		{#if error}
			<p class="text-sm text-destructive" role="alert">{error}</p>
		{/if}

		<Card.Root>
			<Card.Header>
				<Card.Title>Nouveau groupe</Card.Title>
				<Card.Description>Vous en devenez le fondateur (déclaration « found »).</Card.Description>
			</Card.Header>
			<Card.Content>
				<form
					class="flex items-end gap-2"
					onsubmit={(e) => {
						e.preventDefault();
						create();
					}}
				>
					<div class="flex flex-1 flex-col gap-2">
						<Label for="name">Nom</Label>
						<Input id="name" bind:value={name} disabled={busy} />
					</div>
					<Button type="submit" disabled={busy || !name}>Fonder</Button>
				</form>
			</Card.Content>
		</Card.Root>

		<section class="flex flex-col gap-2">
			<h2 class="text-sm font-medium text-muted-foreground">
				Vue serveur (indicative — l'autorité est le rejeu de chaîne)
			</h2>
			{#if groups.length === 0}
				<p class="text-sm text-muted-foreground">Aucun groupe.</p>
			{:else}
				<ul class="flex flex-col gap-2">
					{#each groups as g (g.id)}
						<li>
							<Button variant="outline" class="w-full justify-start" onclick={() => goto(`/groups/${g.id}`)}>
								{g.name}
							</Button>
						</li>
					{/each}
				</ul>
			{/if}
		</section>
	{/if}
</div>
