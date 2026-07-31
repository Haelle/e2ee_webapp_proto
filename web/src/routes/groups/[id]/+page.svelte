<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { get } from 'svelte/store';
	import { goto } from '$app/navigation';
	import * as Card from '$lib/components/ui/card';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import * as api from '$lib/api/client';
	import { openNote, sealNote } from '$lib/crypto';
	import type { ReplayResult } from '$lib/crypto/replay';
	import { coopt, loadGroup, removeMember } from '$lib/group';
	import { endSession, gkKey, session } from '$lib/stores/session';

	interface DecodedNote {
		id: string;
		epoch_n: number;
		readable: boolean;
		title: string;
		body: string;
	}

	// Route is `[id]`, so the param is always present.
	const groupId = get(page).params.id as string;

	let replay = $state<ReplayResult | null>(null);
	let currentEpoch = $state<number | null>(null);
	let notes = $state<DecodedNote[]>([]);
	let newcomer = $state('');
	let title = $state('');
	let body = $state('');
	let editingId = $state<string | null>(null);
	let error = $state('');
	let busy = $state(false);

	const members = $derived(replay ? [...replay.members].sort() : []);

	function fail(e: unknown) {
		error = e instanceof Error ? e.message : String(e);
	}

	onMount(() => {
		if ($session) reload();
	});

	async function reload() {
		if (!$session) return;
		error = '';
		busy = true;
		try {
			const res = await loadGroup(groupId);
			replay = res.replay;
			currentEpoch = res.currentEpoch;
			await loadNotes();
		} catch (e) {
			fail(e);
		} finally {
			busy = false;
		}
	}

	async function loadNotes() {
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

	function resetForm() {
		title = '';
		body = '';
		editingId = null;
	}

	function startEdit(n: DecodedNote) {
		editingId = n.id;
		title = n.title;
		body = n.body;
	}

	async function saveNote() {
		const s = $session;
		if (!s || currentEpoch === null) return;
		error = '';
		busy = true;
		try {
			const gk = s.gks.get(gkKey(groupId, currentEpoch));
			if (!gk) throw new Error("Pas de clé de groupe pour l'époque courante.");
			// Edit re-seals under the current epoch (the AAD binds note id + epoch).
			const id = editingId ?? crypto.randomUUID();
			const { wrappedCek, payload } = await sealNote(gk, id, groupId, currentEpoch, { title, body });
			if (editingId) {
				await api.patchNote(id, { wrappedCek, payload, epochN: currentEpoch });
			} else {
				await api.postNote({ id, groupId, epochN: currentEpoch, wrappedCek, payload });
			}
			resetForm();
			await loadNotes();
		} catch (e) {
			fail(e);
		} finally {
			busy = false;
		}
	}

	async function doCoopt() {
		if (!newcomer) return;
		error = '';
		busy = true;
		try {
			await coopt(groupId, newcomer);
			newcomer = '';
			await reload();
		} catch (e) {
			fail(e);
			busy = false;
		}
	}

	async function doRemove(matricule: string) {
		error = '';
		busy = true;
		try {
			await removeMember(groupId, matricule);
			await reload();
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

<div class="mx-auto flex min-h-screen max-w-3xl flex-col gap-6 p-4">
	<header class="flex items-center justify-between">
		<div class="flex items-center gap-2">
			<Button variant="ghost" size="sm" onclick={() => goto('/groups')}>← Groupes</Button>
			<h1 class="text-xl font-semibold">Groupe</h1>
			{#if currentEpoch !== null}
				<span class="text-sm text-muted-foreground">époque {currentEpoch}</span>
			{/if}
		</div>
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
			</Card.Header>
			<Card.Content>
				<Button onclick={() => goto('/')}>Aller à la connexion</Button>
			</Card.Content>
		</Card.Root>
	{:else}
		{#if error}
			<p class="text-sm text-destructive" role="alert">{error}</p>
		{/if}

		<!-- Composition = autorité (rejeu de chaîne), pas la vue serveur (SPEC §13). -->
		<Card.Root>
			<Card.Header>
				<Card.Title class="flex items-center gap-2">
					Composition
					{#if replay}
						{#if replay.valid}
							<span class="rounded bg-green-600/15 px-2 py-0.5 text-xs text-green-700"
								>chaîne vérifiée</span
							>
						{:else}
							<span class="rounded bg-destructive/15 px-2 py-0.5 text-xs text-destructive"
								>chaîne invalide</span
							>
						{/if}
					{/if}
				</Card.Title>
				<Card.Description>Reconstruite depuis la chaîne signée (l'autorité).</Card.Description>
			</Card.Header>
			<Card.Content class="flex flex-col gap-3">
				{#if replay && !replay.valid}
					<p class="text-sm text-destructive">{replay.error}</p>
				{/if}
				<ul class="flex flex-col gap-1">
					{#each members as m (m)}
						<li class="flex items-center justify-between">
							<span class="text-sm">{m}{m === $session.matricule ? ' (vous)' : ''}</span>
							{#if m !== $session.matricule}
								<Button
									variant="ghost"
									size="sm"
									disabled={busy}
									onclick={() => doRemove(m)}
								>
									Radier
								</Button>
							{/if}
						</li>
					{/each}
				</ul>

				<form
					class="flex items-end gap-2"
					onsubmit={(e) => {
						e.preventDefault();
						doCoopt();
					}}
				>
					<div class="flex flex-1 flex-col gap-2">
						<Label for="newcomer">Coopter (matricule)</Label>
						<Input id="newcomer" bind:value={newcomer} disabled={busy} />
					</div>
					<Button type="submit" disabled={busy || !newcomer}>Coopter</Button>
				</form>

				{#if replay}
					<details class="text-xs text-muted-foreground">
						<summary class="cursor-pointer">Trace de vérification ({replay.steps.length} maillons)</summary>
						<ul class="mt-2 flex flex-col gap-1">
							{#each replay.steps as st (st.seq)}
								<li>
									#{st.seq} {st.action} {st.subject}
									— signé par {st.signer ?? '?'}
									{st.prevOk ? '· prev✓' : '· prev✗'}
									{st.sigOk ? 'sig✓' : 'sig✗'}
									{st.policyOk ? 'pol✓' : 'pol✗'}
									{st.envOk ? 'env✓' : 'env✗'}
								</li>
							{/each}
						</ul>
					</details>
				{/if}
			</Card.Content>
		</Card.Root>

		<!-- Notes -->
		<Card.Root>
			<Card.Header>
				<Card.Title>{editingId ? 'Modifier la note' : 'Nouvelle note'}</Card.Title>
				<Card.Description>
					{#if currentEpoch !== null}Scellée sous l'époque {currentEpoch}.{:else}Aucune époque accessible.{/if}
				</Card.Description>
			</Card.Header>
			<Card.Content>
				<form
					class="flex flex-col gap-3"
					onsubmit={(e) => {
						e.preventDefault();
						saveNote();
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
					<div class="flex gap-2">
						<Button type="submit" disabled={busy || currentEpoch === null || !title}>
							{editingId ? 'Enregistrer' : 'Créer'}
						</Button>
						{#if editingId}
							<Button type="button" variant="outline" disabled={busy} onclick={resetForm}>
								Annuler
							</Button>
						{/if}
					</div>
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
							<Card.Header class="flex-row items-start justify-between">
								<div>
									<Card.Title>{n.readable ? n.title || '(sans titre)' : '🔒 Illisible'}</Card.Title>
									<Card.Description>époque {n.epoch_n}</Card.Description>
								</div>
								{#if n.readable}
									<Button variant="ghost" size="sm" disabled={busy} onclick={() => startEdit(n)}>
										Modifier
									</Button>
								{/if}
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
