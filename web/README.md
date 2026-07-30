# web — E2EE group-notes frontend (SvelteKit SPA)

Iteration 1 scaffold for the SvelteKit client of the end-to-end-encrypted
group-notes demo (SPEC lot 2). The whole app is a browser-only SPA: secrets are
generated, unlocked and used entirely client-side, and the server only ever
holds opaque blobs.

## Stack (exact installed versions)

| Purpose | Package | Version |
|---|---|---|
| Framework | `svelte` | 5.56.8 |
| Kit | `@sveltejs/kit` | 2.70.2 |
| Build | `vite` | 8.2.0 |
| SPA adapter | `@sveltejs/adapter-static` | 3.0.10 |
| Svelte/Vite plugin | `@sveltejs/vite-plugin-svelte` | 7.2.0 |
| Language | `typescript` | 6.0.3 |
| CSS | `tailwindcss` / `@tailwindcss/vite` | 4.3.3 |
| UI kit | `shadcn-svelte` (CLI) | 1.4.2 |
| UI primitives | `bits-ui` | 2.18.1 |
| Icons | `@lucide/svelte` | 1.28.0 |
| age (keyblob + epoch envelopes) | `age-encryption` | **0.3.0** (pinned) |
| AEAD / Ed25519 / blake2b | `libsodium-wrappers-sumo` | **0.8.4** (pinned) |
| Signed statements | `cbor-x` | **1.6.5** (pinned) |
| E2E tests | `@playwright/test` | 1.62.1 |
| Type check | `svelte-check` | 4.7.4 |

The three crypto libraries are pinned to exact versions (SPEC §4 — "épingler les
versions dès le premier commit"). `pnpm-lock.yaml` locks everything else.

## Running

```sh
pnpm install
pnpm dev            # vite dev --host --port 5173
pnpm build          # static SPA → ./build  (green; the deliverable check)
pnpm preview        # serve the production build
pnpm check          # svelte-check (0 errors)
pnpm test:e2e       # Playwright smoke test (builds + previews, then asserts)
```

The backend does not need to be running to build or to load the home page.
API base URL comes from `VITE_API_URL` (default `http://localhost:8000`).

Playwright needs a browser binary the first time: `pnpm exec playwright install chromium`.

## SPA mode

- `@sveltejs/adapter-static` with `fallback: 'index.html'`, configured inline in
  `vite.config.ts` (this SvelteKit version takes the kit config directly on the
  `sveltekit()` plugin — there is no `svelte.config.js`).
- `src/routes/+layout.ts` sets `ssr = false` and `prerender = false`.

## Crypto module — `src/lib/crypto/` (SPEC §9)

The **only** code that touches secrets. The rest of the app deals in cleartext
objects. Byte formats mirror the reference Python implementation (`lot0/model.py`)
so the offline recovery tool (`lot0/recover.py`) stays wire-compatible.

- `index.ts` — the four SPEC §9 functions plus grant-chain helpers:
  - `unlockKeyblob(passphrase, wrappedSeed)` → `{ ageIdentity, ed25519Sk }`
  - `openEpoch(ageIdentity, envelope)` → 32-byte GK
  - `sealNote(gk, noteId, groupId, epoch, content)` → `{ wrappedCek, payload }`
  - `openNote(gk, note)` → `{ title, body }`
  - `createKeyblob(passphrase)` (enrolment), `buildStmt`, `signStmt`, `blake2b256`,
    `signChallenge`
- `bytes.ts` — hex, UUID→16 raw bytes, `epochBE32` (`struct.pack(">i", …)`),
  concat, utf8.
- `sodium.ts` — single awaited `libsodium-wrappers-sumo` (sumo) instance.

Byte-format rules honoured: `wrapped_cek`/`payload` = `nonce(24) || ct`;
`noteIdBytes`/`groupIdBytes` = 16 raw UUID bytes; payload AAD =
`noteId || groupId || epochBE32`; keyblob JSON `ed25519_sk` is the 32-byte Ed25519
**seed as hex** (matching `bytes(SigningKey).hex()`); `env` field = `blake2b256(gk_envelope)`.

In-memory session store: `src/lib/stores/session.ts` — `{ matricule, ageIdentity,
ed25519Sk, gks: Map<"groupId:epoch", Uint8Array> }`. No localStorage/IndexedDB.

API client: `src/lib/api/client.ts` (+ `base64.ts` helpers). Binary fields cross
the wire as base64 and are decoded to `Uint8Array` at the boundary.

## Deviations (read before extending)

1. **`age-encryption` API (v0.3.0).** This version exposes `Encrypter` /
   `Decrypter` classes plus `generateIdentity()` / `identityToRecipient()` —
   there is no top-level `encrypt`/`decrypt` function like older majors.
   - passphrase (keyblob): `new Encrypter().setPassphrase(p)` /
     `new Decrypter().addPassphrase(p)`.
   - recipients (epoch): `new Encrypter().addRecipient(age1…)` /
     `new Decrypter().addIdentity('AGE-SECRET-KEY-1…')`.
   - `generateIdentity()` returns the `AGE-SECRET-KEY-1…` string; identities and
     recipients are passed as strings (no armor for binary blobs, per SPEC §13).

2. **`cbor-x` encoder options — NOT the library defaults.** The task said "default
   options", but cbor-x's defaults break interop with Python `cbor2`: they emit a
   record-structure tag (`0xd9dfff`) and wrap `Uint8Array` in tag 64. Neither is
   decodable by `cbor2`. To produce byte-for-byte identical CBOR to the Python
   reference (verified against `cbor2` during development) the statement encoder
   uses `{ useRecords: false, tagUint8Array: false, variableMapSize: true }`.
   Wire-compatibility with the recovery tool (SPEC §7/§11) takes priority over the
   literal "defaults" wording. We still sign and store the *exact* bytes produced —
   never re-encoded.

3. **Login ordering.** Signing the Ed25519 challenge needs the key, which lives in
   the keyblob. So login does: `POST /auth/challenge` → `GET /me/keyblob` →
   `unlockKeyblob` → sign nonce → `POST /auth/verify`. The keyblob is fetched
   before `verify` (it is public because it is encrypted, SPEC §8).

4. **`POST /notes` carries a client-generated `id`.** The payload AAD binds to the
   note id (SPEC §6), so the `/notes` screen mints `crypto.randomUUID()`, seals
   with it, then includes it in the POST body.

5. **shadcn-svelte + Tailwind installed manually.** The `sv` CLI refuses to run on
   a dirty git tree (we must not commit), so Tailwind v4 and the shadcn theme in
   `src/app.css` were wired by hand; components (`button`, `input`, `card`,
   `label`) were added with the `shadcn-svelte` CLI (`--preset b0`, neutral base).

## Left for a later iteration

- `buildStmt` / `signStmt` / `blake2b256` are implemented but not yet wired into
  screens (cooptation, epoch rotation, chain replay / `replayChain` — SPEC §7/§10).
- GK is kept as raw bytes; SPEC §9 wants it imported as a non-extractable
  `CryptoKey` with the source buffer zeroed.
- Notes screen is a minimal list + create form (no edit/PATCH UI yet); group
  membership is not yet reconstructed from the signed chain (server view only).
