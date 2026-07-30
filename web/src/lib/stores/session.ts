// In-memory-only session store (SPEC §9). No localStorage, no IndexedDB — close
// the tab and everything is gone; the passphrase must be re-entered. Holds the
// unlocked secrets and the group keys derived from epoch envelopes.
import { writable } from 'svelte/store';

export interface SessionState {
	matricule: string;
	ageIdentity: string;
	/** 32-byte Ed25519 seed. */
	ed25519Sk: Uint8Array;
	/** GK per group+epoch, keyed by `${groupId}:${epoch}`. */
	gks: Map<string, Uint8Array>;
}

export const session = writable<SessionState | null>(null);

export function gkKey(groupId: string, epoch: number): string {
	return `${groupId}:${epoch}`;
}

/** Start a new authenticated session with an unlocked keyblob. */
export function startSession(matricule: string, ageIdentity: string, ed25519Sk: Uint8Array): void {
	session.set({ matricule, ageIdentity, ed25519Sk, gks: new Map() });
}

/** Record a group key for a given group+epoch. */
export function putGk(groupId: string, epoch: number, gk: Uint8Array): void {
	session.update((s) => {
		if (!s) return s;
		s.gks.set(gkKey(groupId, epoch), gk);
		return s;
	});
}

/** Drop all secrets from memory. */
export function endSession(): void {
	session.set(null);
}
