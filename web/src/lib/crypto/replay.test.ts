/**
 * Client-side chain replay = the authority (SPEC §7). These tests are the
 * browser-side equivalents of lot0 §11.4 (non-member rejected) and §11.5
 * (tampered stmt breaks the chain), plus the env-binding check.
 */
import { generateIdentity, identityToRecipient } from 'age-encryption';
import { describe, expect, it } from 'vitest';
import type { Grant } from '$lib/api/client';
import { buildStmt, sealEpoch, signStmt, newGk, type GrantAction } from './index';
import { blake2b256 } from './index';
import { replayChain } from './replay';
import { getSodium } from './sodium';

interface Member {
	matricule: string;
	keyId: string;
	ageIdentity: string;
	ageRecipient: string;
	ed25519Sk: Uint8Array;
	ed25519Pub: Uint8Array;
}

// Build identities directly (age identity + Ed25519 keypair) — skip the
// passphrase/scrypt keyblob wrap, which is deliberately slow and not needed here.
async function member(matricule: string): Promise<Member> {
	const sodium = await getSodium();
	const ageIdentity = await generateIdentity();
	const ageRecipient = await identityToRecipient(ageIdentity);
	const seed = sodium.randombytes_buf(sodium.crypto_sign_SEEDBYTES);
	const kp = sodium.crypto_sign_seed_keypair(seed);
	return {
		matricule,
		keyId: crypto.randomUUID(),
		ageIdentity,
		ageRecipient,
		ed25519Sk: seed,
		ed25519Pub: kp.publicKey
	};
}

/** Build a signed grant + return {grant, hash} so the next link can chain. */
async function link(
	seq: number,
	signer: Member,
	fields: {
		groupId: string;
		action: GrantAction;
		epoch: number;
		subject: string;
		keyId: string | null;
		envelope: Uint8Array;
		prev: Uint8Array | null;
	}
): Promise<{ grant: Grant; hash: Uint8Array }> {
	const stmt = await buildStmt({
		groupId: fields.groupId,
		action: fields.action,
		epoch: fields.epoch,
		subject: fields.subject,
		keyId: fields.keyId,
		gkEnvelope: fields.envelope,
		prevHash: fields.prev,
		ts: seq
	});
	const sig = await signStmt(signer.ed25519Sk, stmt);
	const hash = await blake2b256(stmt);
	return {
		grant: {
			seq,
			stmt,
			sig,
			signerKeyId: signer.keyId,
			signerEd25519Pub: signer.ed25519Pub,
			signerMatricule: signer.matricule,
			hash
		},
		hash
	};
}

/** A valid 2-link chain: A founds, A coopts B into epoch 0 (envelope rewritten). */
async function foundAndCoopt(a: Member, b: Member) {
	const groupId = crypto.randomUUID();
	const gk = await newGk();
	const envFound = await sealEpoch(gk, [a.ageRecipient]);
	const envAdd = await sealEpoch(gk, [a.ageRecipient, b.ageRecipient]); // rewritten epoch 0

	const l0 = await link(0, a, {
		groupId,
		action: 'found',
		epoch: 0,
		subject: a.matricule,
		keyId: a.keyId,
		envelope: envFound,
		prev: null
	});
	const l1 = await link(1, a, {
		groupId,
		action: 'add',
		epoch: 0,
		subject: b.matricule,
		keyId: b.keyId,
		envelope: envAdd,
		prev: l0.hash
	});
	return { groupId, gk, envAdd, l0, l1 };
}

describe('replayChain', () => {
	it('reconstructs membership from a valid chain', async () => {
		const a = await member('MAT-A');
		const b = await member('MAT-B');
		const { envAdd, l0, l1 } = await foundAndCoopt(a, b);

		const res = await replayChain([l0.grant, l1.grant], new Map([[0, envAdd]]));
		expect(res.valid).toBe(true);
		expect([...res.members].sort()).toEqual(['MAT-A', 'MAT-B']);
	});

	it('rejects a statement signed by a non-member (§11.4)', async () => {
		const a = await member('MAT-A');
		const b = await member('MAT-B');
		const eve = await member('MAT-E'); // never added to the group
		const { groupId, gk, l0 } = await foundAndCoopt(a, b);

		// Eve signs an `add` — the server might accept it, the replay must not.
		const envelope = await sealEpoch(gk, [a.ageRecipient, b.ageRecipient]);
		const bad = await link(1, eve, {
			groupId,
			action: 'add',
			epoch: 0,
			subject: b.matricule,
			keyId: b.keyId,
			envelope,
			prev: l0.hash
		});
		const res = await replayChain([l0.grant, bad.grant], new Map([[0, envelope]]));
		expect(res.valid).toBe(false);
		expect(res.error).toMatch(/non membre/);
	});

	it('breaks when a stored statement is tampered (§11.5)', async () => {
		const a = await member('MAT-A');
		const b = await member('MAT-B');
		const { envAdd, l0, l1 } = await foundAndCoopt(a, b);

		const tampered = { ...l1.grant, stmt: new Uint8Array(l1.grant.stmt) };
		tampered.stmt[tampered.stmt.length - 1] ^= 0x01;

		const res = await replayChain([l0.grant, tampered], new Map([[0, envAdd]]));
		expect(res.valid).toBe(false);
	});

	it('rejects when the stored envelope does not match the pinned env', async () => {
		const a = await member('MAT-A');
		const b = await member('MAT-B');
		const { gk, l0, l1 } = await foundAndCoopt(a, b);

		// Swap in a different envelope than the one the `add` statement pinned.
		const other = await sealEpoch(gk, [a.ageRecipient]);
		const res = await replayChain([l0.grant, l1.grant], new Map([[0, other]]));
		expect(res.valid).toBe(false);
		expect(res.error).toMatch(/env/);
	});
});
