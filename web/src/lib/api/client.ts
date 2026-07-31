/**
 * Typed API client (SPEC §8). Binary fields travel as base64 strings inside
 * JSON; this module decodes them back to `Uint8Array` at the boundary so the
 * rest of the app never sees base64. Session is a `httpOnly` cookie, hence
 * `credentials: 'include'` on every request.
 *
 * The server view is *indicative only* (SPEC §13): group membership is the
 * client's authority via chain replay, never these responses.
 */
import { fromBase64, toBase64 } from './base64';

const BASE_URL =
	(import.meta.env.VITE_API_URL as string | undefined) ?? 'http://localhost:8000';

export class ApiError extends Error {
	constructor(
		public status: number,
		message: string
	) {
		super(message);
		this.name = 'ApiError';
	}
}

async function request<T>(
	method: string,
	path: string,
	body?: unknown
): Promise<{ status: number; data: T }> {
	const res = await fetch(`${BASE_URL}${path}`, {
		method,
		credentials: 'include',
		headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
		body: body !== undefined ? JSON.stringify(body) : undefined
	});
	if (!res.ok) {
		let detail = res.statusText;
		try {
			const err = await res.json();
			detail = err.detail ?? err.message ?? detail;
		} catch {
			/* non-JSON error body */
		}
		throw new ApiError(res.status, detail);
	}
	// 204 No Content and other empty bodies.
	if (res.status === 204 || res.headers.get('content-length') === '0') {
		return { status: res.status, data: undefined as T };
	}
	const text = await res.text();
	const data = text ? (JSON.parse(text) as T) : (undefined as T);
	return { status: res.status, data };
}

// --------------------------------------------------------------------------- //
// Wire types (base64 blobs) and decoded domain types.
// --------------------------------------------------------------------------- //

export interface GroupSummary {
	id: string;
	name: string;
}

export interface Epoch {
	n: number;
	gkEnvelope: Uint8Array;
}

export interface Grant {
	seq: number;
	stmt: Uint8Array;
	sig: Uint8Array;
	signerKeyId: string;
	signerEd25519Pub: Uint8Array;
	signerMatricule: string;
	hash: Uint8Array;
}

export interface Note {
	id: string;
	group_id: string;
	epoch_n: number;
	author_id: string;
	wrapped_cek: Uint8Array;
	payload: Uint8Array;
	created_at: string;
	updated_at: string;
}

export interface EnrollBody {
	matricule: string;
	displayName: string;
	ageRecipient: string;
	ed25519Pub: Uint8Array;
	wrappedSeed: Uint8Array;
}

export interface MemberInfo {
	matricule: string;
	displayName: string;
	ageRecipient: string;
	ed25519Pub: Uint8Array;
	keyId: string;
}

// --------------------------------------------------------------------------- //
// Auth (SPEC §8) — Ed25519 challenge/response, no server-side password.
// --------------------------------------------------------------------------- //

export async function challenge(matricule: string): Promise<Uint8Array> {
	const { data } = await request<{ nonce: string }>('POST', '/auth/challenge', { matricule });
	return fromBase64(data.nonce);
}

export async function verify(matricule: string, sig: Uint8Array): Promise<void> {
	await request<void>('POST', '/auth/verify', { matricule, sig: toBase64(sig) });
}

/**
 * The passphrase-wrapped keyblob for a matricule. Public (encrypted) and
 * session-free: it bootstraps login — the Ed25519 key needed to answer the
 * auth challenge lives inside it, so it must be fetchable before the cookie.
 */
export async function getKeyblob(matricule: string): Promise<Uint8Array> {
	const { data } = await request<{ wrapped_seed: string }>(
		'GET',
		`/members/${encodeURIComponent(matricule)}/keyblob`
	);
	return fromBase64(data.wrapped_seed);
}

// --------------------------------------------------------------------------- //
// Members / enrolment.
// --------------------------------------------------------------------------- //

export async function enroll(body: EnrollBody): Promise<{ member_id: string; key_id: string }> {
	const { data } = await request<{ member_id: string; key_id: string }>('POST', '/members', {
		matricule: body.matricule,
		display_name: body.displayName,
		age_recipient: body.ageRecipient,
		ed25519_pub: toBase64(body.ed25519Pub),
		wrapped_seed: toBase64(body.wrappedSeed)
	});
	return data;
}

/** Public material of a member (age recipient, ed25519 pub, active key id). */
export async function getMemberInfo(matricule: string): Promise<MemberInfo> {
	const { data } = await request<{
		matricule: string;
		display_name: string;
		age_recipient: string;
		ed25519_pub: string;
		key_id: string;
	}>('GET', `/members/${encodeURIComponent(matricule)}`);
	return {
		matricule: data.matricule,
		displayName: data.display_name,
		ageRecipient: data.age_recipient,
		ed25519Pub: fromBase64(data.ed25519_pub),
		keyId: data.key_id
	};
}

// --------------------------------------------------------------------------- //
// Groups / epochs / grants.
// --------------------------------------------------------------------------- //

export async function getGroups(): Promise<GroupSummary[]> {
	const { data } = await request<GroupSummary[]>('GET', '/groups');
	return data;
}

/** Genesis: the client mints the group UUID so the `found` stmt can reference it. */
export async function createGroup(id: string, name: string): Promise<GroupSummary> {
	const { data } = await request<GroupSummary>('POST', '/groups', { id, name });
	return data;
}

export async function getEpochs(groupId: string): Promise<Epoch[]> {
	const { data } = await request<{ n: number; gk_envelope: string }[]>(
		'GET',
		`/groups/${groupId}/epochs`
	);
	return data.map((e) => ({ n: e.n, gkEnvelope: fromBase64(e.gk_envelope) }));
}

export async function postEpoch(
	groupId: string,
	epoch: {
		n: number;
		gkEnvelope: Uint8Array;
		seq: number;
		stmt: Uint8Array;
		sig: Uint8Array;
		signerKeyId: string;
	}
): Promise<void> {
	await request<void>('POST', `/groups/${groupId}/epochs`, {
		n: epoch.n,
		gk_envelope: toBase64(epoch.gkEnvelope),
		seq: epoch.seq,
		stmt: toBase64(epoch.stmt),
		sig: toBase64(epoch.sig),
		signer_key_id: epoch.signerKeyId
	});
}

/** Cooptation: rewrite an existing epoch envelope in place + append the grant. */
export async function putEpoch(
	groupId: string,
	n: number,
	epoch: { gkEnvelope: Uint8Array; seq: number; stmt: Uint8Array; sig: Uint8Array; signerKeyId: string }
): Promise<void> {
	await request<void>('PUT', `/groups/${groupId}/epochs/${n}`, {
		gk_envelope: toBase64(epoch.gkEnvelope),
		seq: epoch.seq,
		stmt: toBase64(epoch.stmt),
		sig: toBase64(epoch.sig),
		signer_key_id: epoch.signerKeyId
	});
}

export async function getGrants(groupId: string): Promise<Grant[]> {
	const { data } = await request<
		{
			seq: number;
			stmt: string;
			sig: string;
			signer_key_id: string;
			signer_ed25519_pub: string;
			signer_matricule: string;
			hash: string;
		}[]
	>('GET', `/groups/${groupId}/grants`);
	return data.map((g) => ({
		seq: g.seq,
		stmt: fromBase64(g.stmt),
		sig: fromBase64(g.sig),
		signerKeyId: g.signer_key_id,
		signerEd25519Pub: fromBase64(g.signer_ed25519_pub),
		signerMatricule: g.signer_matricule,
		hash: fromBase64(g.hash)
	}));
}

export async function postGrant(
	groupId: string,
	grant: { seq: number; stmt: Uint8Array; sig: Uint8Array; signerKeyId: string }
): Promise<void> {
	await request<void>('POST', `/groups/${groupId}/grants`, {
		seq: grant.seq,
		stmt: toBase64(grant.stmt),
		sig: toBase64(grant.sig),
		signer_key_id: grant.signerKeyId
	});
}

// --------------------------------------------------------------------------- //
// Notes. POST requires a client-generated UUID `id`: the payload AAD binds to
// the note id (SPEC §6), so the client mints it, seals with it, then uploads.
// --------------------------------------------------------------------------- //

export async function getNotes(groupId: string): Promise<Note[]> {
	const { data } = await request<
		{
			id: string;
			group_id: string;
			epoch_n: number;
			author_id: string;
			wrapped_cek: string;
			payload: string;
			created_at: string;
			updated_at: string;
		}[]
	>('GET', `/notes?group_id=${encodeURIComponent(groupId)}`);
	return data.map((n) => ({
		id: n.id,
		group_id: n.group_id,
		epoch_n: n.epoch_n,
		author_id: n.author_id,
		wrapped_cek: fromBase64(n.wrapped_cek),
		payload: fromBase64(n.payload),
		created_at: n.created_at,
		updated_at: n.updated_at
	}));
}

export async function postNote(note: {
	id: string;
	groupId: string;
	epochN: number;
	wrappedCek: Uint8Array;
	payload: Uint8Array;
}): Promise<{ id: string }> {
	const { data } = await request<{ id: string }>('POST', '/notes', {
		id: note.id,
		group_id: note.groupId,
		epoch_n: note.epochN,
		wrapped_cek: toBase64(note.wrappedCek),
		payload: toBase64(note.payload)
	});
	return data;
}

export async function patchNote(
	noteId: string,
	note: { wrappedCek: Uint8Array; payload: Uint8Array; epochN: number }
): Promise<void> {
	await request<void>('PATCH', `/notes/${noteId}`, {
		wrapped_cek: toBase64(note.wrappedCek),
		payload: toBase64(note.payload),
		epoch_n: note.epochN
	});
}
