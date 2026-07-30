// Single libsodium (sumo build) instance, lazily awaited. All AEAD, Ed25519 and
// blake2b operations go through this — no home-grown primitives (SPEC §4).
import sodium from 'libsodium-wrappers-sumo';

let readyPromise: Promise<typeof sodium> | null = null;

export async function getSodium(): Promise<typeof sodium> {
	if (!readyPromise) {
		readyPromise = sodium.ready.then(() => sodium);
	}
	return readyPromise;
}
