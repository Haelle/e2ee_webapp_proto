/**
 * High-level group operations (SPEC §10) — genesis, cooptation, radiation, and
 * loading a group (chain replay + opening the epochs one can decrypt).
 *
 * These orchestrate crypto/ + api/ + the session store. Membership always comes
 * from {@link replayChain} (the authority), never the server's group view.
 */
import { get } from 'svelte/store';
import * as api from '$lib/api/client';
import { blake2b256, buildStmt, newGk, openEpoch, sealEpoch, signStmt } from '$lib/crypto';
import { replayChain, type ReplayResult } from '$lib/crypto/replay';
import { gkKey, putGk, session, type SessionState } from '$lib/stores/session';

function requireSession(): SessionState {
	const s = get(session);
	if (!s) throw new Error('session requise');
	return s;
}

function nowTs(): number {
	return Math.floor(Date.now() / 1000);
}

/** Next seq + prev hash (computed client-side from the last stmt bytes). */
async function chainHead(grants: api.Grant[]): Promise<{ seq: number; prev: Uint8Array | null }> {
	if (grants.length === 0) return { seq: 0, prev: null };
	const last = grants.reduce((a, b) => (a.seq >= b.seq ? a : b));
	return { seq: last.seq + 1, prev: await blake2b256(last.stmt) };
}

/** age recipients for a set of matricules (server exposes the public material). */
async function recipientsFor(matricules: Iterable<string>): Promise<string[]> {
	const out: string[] = [];
	for (const m of matricules) out.push((await api.getMemberInfo(m)).ageRecipient);
	return out;
}

export interface LoadedGroup {
	epochs: api.Epoch[];
	currentEpoch: number | null;
	replay: ReplayResult;
}

/**
 * Load a group: replay its chain (→ authoritative members + verification trace)
 * and open every epoch envelope this member can decrypt into the session.
 */
export async function loadGroup(groupId: string): Promise<LoadedGroup> {
	const s = requireSession();
	const [epochs, grants] = await Promise.all([api.getEpochs(groupId), api.getGrants(groupId)]);

	const envByEpoch = new Map(epochs.map((e) => [e.n, e.gkEnvelope]));
	const replay = await replayChain(grants, envByEpoch);

	for (const e of epochs) {
		try {
			putGk(groupId, e.n, await openEpoch(s.ageIdentity, e.gkEnvelope));
		} catch {
			/* epoch this member cannot decrypt — expected (SPEC §11.2) */
		}
	}
	const currentEpoch = epochs.length ? Math.max(...epochs.map((e) => e.n)) : null;
	return { epochs, currentEpoch, replay };
}

/** Genesis (SPEC §10): create the group, seal epoch 0 to the founder, sign `found`. */
export async function foundGroup(name: string): Promise<string> {
	const s = requireSession();
	const groupId = crypto.randomUUID();
	await api.createGroup(groupId, name);

	const gk = await newGk();
	const envelope = await sealEpoch(gk, [s.ageRecipient]);
	const stmt = await buildStmt({
		groupId,
		action: 'found',
		epoch: 0,
		subject: s.matricule,
		keyId: s.keyId,
		gkEnvelope: envelope,
		prevHash: null,
		ts: nowTs()
	});
	const sig = await signStmt(s.ed25519Sk, stmt);
	await api.postEpoch(groupId, { n: 0, gkEnvelope: envelope, seq: 0, stmt, sig, signerKeyId: s.keyId });
	putGk(groupId, 0, gk);
	return groupId;
}

/**
 * Cooptation (SPEC §10): re-encode the CURRENT epoch envelope toward all members
 * plus the newcomer, sign `add`, PUT it. Notes are untouched — the newcomer gets
 * the current epoch onward, not deep history (unless old epochs are rewrapped).
 */
export async function coopt(groupId: string, newcomerMatricule: string): Promise<void> {
	const s = requireSession();
	const grants = await api.getGrants(groupId);
	const envByEpoch = new Map((await api.getEpochs(groupId)).map((e) => [e.n, e.gkEnvelope]));
	const replay = await replayChain(grants, envByEpoch);
	if (!replay.valid) throw new Error(`chaîne invalide : ${replay.error}`);

	const currentEpoch = Math.max(...envByEpoch.keys());
	const gk = s.gks.get(gkKey(groupId, currentEpoch));
	if (!gk) throw new Error("pas de clé de groupe pour l'époque courante");
	if (replay.members.has(newcomerMatricule)) throw new Error('déjà membre');

	const newcomer = await api.getMemberInfo(newcomerMatricule);
	const recipients = [...(await recipientsFor(replay.members)), newcomer.ageRecipient];
	const envelope = await sealEpoch(gk, recipients);

	const { seq, prev } = await chainHead(grants);
	const stmt = await buildStmt({
		groupId,
		action: 'add',
		epoch: currentEpoch,
		subject: newcomerMatricule,
		keyId: newcomer.keyId,
		gkEnvelope: envelope,
		prevHash: prev,
		ts: nowTs()
	});
	const sig = await signStmt(s.ed25519Sk, stmt);
	await api.putEpoch(groupId, currentEpoch, {
		gkEnvelope: envelope,
		seq,
		stmt,
		sig,
		signerKeyId: s.keyId
	});
}

/**
 * Radiation (SPEC §10): fresh GK, NEW epoch sealed to the remaining members
 * only, sign `remove`. Prior epochs stay readable by the departing member — the
 * expected behaviour, not a defect.
 */
export async function removeMember(groupId: string, departing: string): Promise<void> {
	const s = requireSession();
	const grants = await api.getGrants(groupId);
	const epochs = await api.getEpochs(groupId);
	const envByEpoch = new Map(epochs.map((e) => [e.n, e.gkEnvelope]));
	const replay = await replayChain(grants, envByEpoch);
	if (!replay.valid) throw new Error(`chaîne invalide : ${replay.error}`);
	if (!replay.members.has(departing)) throw new Error('pas membre');

	const remaining = new Set(replay.members);
	remaining.delete(departing);
	const newEpoch = Math.max(...envByEpoch.keys()) + 1;

	const gk = await newGk();
	const envelope = await sealEpoch(gk, await recipientsFor(remaining));

	const { seq, prev } = await chainHead(grants);
	const stmt = await buildStmt({
		groupId,
		action: 'remove',
		epoch: newEpoch,
		subject: departing,
		keyId: null,
		gkEnvelope: envelope,
		prevHash: prev,
		ts: nowTs()
	});
	const sig = await signStmt(s.ed25519Sk, stmt);
	await api.postEpoch(groupId, { n: newEpoch, gkEnvelope: envelope, seq, stmt, sig, signerKeyId: s.keyId });
	putGk(groupId, newEpoch, gk);
}
