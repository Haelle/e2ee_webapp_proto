/**
 * Client-side chain replay (SPEC §7) — THE AUTHORITY.
 *
 * Group membership is reconstructed here, from the signed grant chain, and never
 * trusted from the server's indicative view (SPEC §13). This mirrors
 * `lot0/model.py::replay_chain`.
 *
 * Trust note: the signer of each statement is resolved to a matricule via the
 * chain's own `key_id → subject` bindings (established by `found`/`add`), NOT via
 * the server-provided `signerMatricule`. So a statement signed by a non-member
 * is rejected here even if the server accepted it and mislabels the signer
 * (SPEC test §11.4). The ed25519 public key for a key_id is taken from the
 * server (public material, enrolled out of band — SPEC §2, §8).
 */
import { Decoder } from 'cbor-x';
import type { Grant } from '$lib/api/client';
import { blake2b256 } from './index';
import { bytesEqual, bytesToUuid } from './bytes';
import { getSodium } from './sodium';

const stmtDecoder = new Decoder({ useRecords: false, mapsAsObjects: true });

interface DecodedStmt {
	v: number;
	group: Uint8Array;
	action: 'found' | 'add' | 'remove';
	epoch: number;
	subject: string;
	key_id: Uint8Array | null;
	env: Uint8Array;
	prev: Uint8Array | null;
	ts: number;
}

export interface ReplayStep {
	seq: number;
	action: string;
	subject: string;
	/** signer resolved from the chain bindings (null = unknown key_id). */
	signer: string | null;
	prevOk: boolean;
	sigOk: boolean;
	policyOk: boolean;
	envOk: boolean;
}

export interface ReplayResult {
	/** True iff every check passed for every link. */
	valid: boolean;
	/** Human-readable reason for the first failure, else null. */
	error: string | null;
	/** The reconstructed set of member matricules (authoritative when valid). */
	members: Set<string>;
	/** Per-link verification trace, for display. */
	steps: ReplayStep[];
}

/**
 * Replay a group's grant chain against its stored epoch envelopes. Stops at the
 * first broken link (like the reference), but always returns the steps computed
 * so far so the UI can show exactly where — and why — it broke.
 */
export async function replayChain(
	grants: Grant[],
	envelopeForEpoch: Map<number, Uint8Array>
): Promise<ReplayResult> {
	const sodium = await getSodium();
	const ordered = [...grants].sort((a, b) => a.seq - b.seq);

	// The epoch envelope is rewritten in place on cooptation (SPEC §5); only the
	// LAST statement targeting an epoch pins the currently-stored envelope.
	const decoded = ordered.map((g) => stmtDecoder.decode(g.stmt) as DecodedStmt);
	const latestSeqForEpoch = new Map<number, number>();
	ordered.forEach((g, i) => {
		const ep = decoded[i].epoch;
		latestSeqForEpoch.set(ep, Math.max(latestSeqForEpoch.get(ep) ?? -1, g.seq));
	});

	const members = new Set<string>();
	const bindings = new Map<string, string>(); // key_id (uuid) → matricule
	const steps: ReplayStep[] = [];
	let prevHash: Uint8Array | null = null;
	let error: string | null = null;

	for (let i = 0; i < ordered.length; i++) {
		const g = ordered[i];
		const s = decoded[i];
		const signer = g.signerKeyId ? (bindings.get(g.signerKeyId) ?? null) : null;

		const prevOk = bytesEqual(s.prev, prevHash);
		const sigOk = sigVerify(sodium, g.sig, g.stmt, g.signerEd25519Pub);
		// Policy: beyond the founding link, the signer must be a current member.
		const policyOk = g.seq === 0 ? true : signer !== null && members.has(signer);
		const env = envelopeForEpoch.get(s.epoch);
		const isLatest = latestSeqForEpoch.get(s.epoch) === g.seq;
		const envOk =
			env !== undefined && (!isLatest || bytesEqual(s.env, await blake2b256(env)));

		steps.push({
			seq: g.seq,
			action: s.action,
			subject: s.subject,
			signer,
			prevOk,
			sigOk,
			policyOk,
			envOk
		});

		if (!prevOk) error = `seq ${g.seq} : chaînage rompu (prev)`;
		else if (!sigOk) error = `seq ${g.seq} : signature invalide`;
		else if (!policyOk) error = `seq ${g.seq} : signataire non membre (${signer ?? 'inconnu'})`;
		else if (env === undefined) error = `seq ${g.seq} : enveloppe d'époque absente`;
		else if (!envOk) error = `seq ${g.seq} : env ne correspond pas à l'enveloppe stockée`;

		if (error) return { valid: false, error, members, steps };

		// apply
		if (s.action === 'found' || s.action === 'add') {
			members.add(s.subject);
			if (s.key_id) bindings.set(bytesToUuid(s.key_id), s.subject);
		} else if (s.action === 'remove') {
			members.delete(s.subject);
		}
		prevHash = await blake2b256(g.stmt);
	}

	return { valid: true, error: null, members, steps };
}

function sigVerify(
	sodium: Awaited<ReturnType<typeof getSodium>>,
	sig: Uint8Array,
	msg: Uint8Array,
	pub: Uint8Array
): boolean {
	try {
		return sodium.crypto_sign_verify_detached(sig, msg, pub);
	} catch {
		return false;
	}
}
