<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import * as Card from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import * as api from '$lib/api/client';
	import { openEpoch, openNote, sealNote } from '$lib/crypto';
	import { endSession, gkKey, putGk, session } from '$lib/stores/session';

	interface DecodedNote {
		id: string;
		epoch_n: number;
		readable: boolean;
		title: string;
		body: string;
	}

	let groups = $state<api.GroupSummary[]>([]);
	let selectedGroup = $state<string | null>(null);
	let currentEpoch = $state<number | null>(null);
	let notes = $state<DecodedNote[]>([]);
	let title = $state('');
	let body = $state('');
	let error = $state('');
	let busy = $state(false);

	function fail(e: unknown) {
		error = e instanceof Error ? e.message : String(e);
	}

	onMount(() => {
		if ($session) loadGroups();
	});

	async function loadGroups() {
		error = '';
		busy = true;
		try {
			groups = await api.getGroups();
			if (groups.length > 0) await selectGroup(groups[0].id);
		} catch (e) {
			fail(e);
		} finally {
			busy = false;
		}
	}

	async function selectGroup(groupId: string) {
		const s = $session;
		if (!s) return;
		error = '';
		busy = true;
		try {
			selectedGroup = groupId;

			// Open every epoch envelope this member can decrypt → GKs in memory.
			const epochs = await api.getEpochs(groupId);
			currentEpoch = epochs.length > 0 ? Math.max(...epochs.map((e) => e.n)) : null;
			for (const e of epochs) {
				try {
					putGk(groupId, e.n, await openEpoch(s.ageIdentity, e.gkEnvelope));
				} catch {
					/* epoch this member has no access to — expected */
				}
			}

			await loadNotes(groupId);
		} catch (e) {
			fail(e);
		} finally {
			busy = false;
		}
	}

	async function loadNotes(groupId: string) {
		const s = $session;
		if (!s) return;
		const raw = await api.getNotes(groupId);
		const decoded: DecodedNote[] = [];
		for (const n of raw) {
			const gk = s.gks.get(gkKey(groupId, n.epoch_n));
			if (!gk) {
				decoded.push({ id: n.id, epoch_n: n.epoch_n, readable: false, title: '', body: '' });
				continue;
			}
			try {
				const content = await openNote(gk, n);
				decoded.push({ id: n.id, epoch_n: n.epoch_n, readable: true, ...content });
			} catch {
				decoded.push({ id: n.id, epoch_n: n.epoch_n, readable: false, title: '', body: '' });
			}
		}
		notes = decoded;
	}

	async function createNote() {
		const s = $session;
		if (!s || selectedGroup === null || currentEpoch === null) return;
		error = '';
		busy = true;
		try {
			const gk = s.gks.get(gkKey(selectedGroup, currentEpoch));
			if (!gk) throw new Error("Pas de clé de groupe pour l'époque courante.");

			// The payload AAD binds to the note id (SPEC §6): mint the UUID here,
			// seal with it, then upload it in the POST body.
			const id = crypto.randomUUID();
			const { wrappedCek, payload } = await sealNote(gk, id, selectedGroup, currentEpoch, {
				title,
				body
			});
			await api.postNote({ id, groupId: selectedGroup, epochN: currentEpoch, wrappedCek, payload });

			title = '';
			body = '';
			await loadNotes(selectedGroup);
		} catch (e) {
			fail(e);
		} finally {
			busy = false;
		}
	}

	function logout() {
		endSession();
		goto('/');
	}
</script>

<div class="mx-auto flex min-h-screen max-w-3xl flex-col gap-6 p-4">
	<header class="flex items-center justify-between">
		<h1 class="text-xl font-semibold">Notes</h1>
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
				<Card.Description>Connectez-vous pour déchiffrer vos notes.</Card.Description>
			</Card.Header>
			<Card.Content>
				<Button onclick={() => goto('/')}>Aller à la connexion</Button>
			</Card.Content>
		</Card.Root>
	{:else}
		{#if error}
			<p class="text-sm text-destructive" role="alert">{error}</p>
		{/if}

		{#if groups.length > 1}
			<div class="flex flex-wrap gap-2">
				{#each groups as g (g.id)}
					<Button
						variant={g.id === selectedGroup ? 'default' : 'outline'}
						size="sm"
						disabled={busy}
						onclick={() => selectGroup(g.id)}
					>
						{g.name}
					</Button>
				{/each}
			</div>
		{/if}

		<Card.Root>
			<Card.Header>
				<Card.Title>Nouvelle note</Card.Title>
				<Card.Description>
					{#if currentEpoch !== null}
						Époque courante : {currentEpoch}
					{:else}
						Aucune époque accessible.
					{/if}
				</Card.Description>
			</Card.Header>
			<Card.Content>
				<form
					class="flex flex-col gap-3"
					onsubmit={(e) => {
						e.preventDefault();
						createNote();
					}}
				>
					<div class="flex flex-col gap-2">
						<Label for="title">Titre</Label>
						<Input id="title" bind:value={title} disabled={busy} />
					</div>
					<div class="flex flex-col gap-2">
						<Label for="body">Contenu</Label>
						<Input id="body" bind:value={body} disabled={busy} />
					</div>
					<Button type="submit" disabled={busy || currentEpoch === null || !title}>
						Enregistrer
					</Button>
				</form>
			</Card.Content>
		</Card.Root>

		{#if notes.length === 0}
			<p class="text-sm text-muted-foreground">Aucune note.</p>
		{:else}
			<ul class="flex flex-col gap-3">
				{#each notes as n (n.id)}
					<li>
						<Card.Root>
							<Card.Header>
								<Card.Title>
									{n.readable ? n.title || '(sans titre)' : '🔒 Illisible'}
								</Card.Title>
								<Card.Description>Époque {n.epoch_n}</Card.Description>
							</Card.Header>
							{#if n.readable}
								<Card.Content>
									<p class="whitespace-pre-wrap text-sm">{n.body}</p>
								</Card.Content>
							{/if}
						</Card.Root>
					</li>
				{/each}
			</ul>
		{/if}
	{/if}
</div>
