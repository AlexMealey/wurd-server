# YubiKey vaults (wurd-server + ../wurd)

**Total: about 7 hours.** Server work comes first (steps 1–3, about 3.5 h), then the frontend and docs (steps 4–6, about 3.5 h).

## Context

Right now a vault opens with one thing: the token `wurd_<id>_<secret>`. The server derives a KEK from the token and the pepper, then unwraps the vault key (`src/Users.php`). This plan adds YubiKeys:

- **Create:** a new vault comes with a YubiKey. The token is still issued, and the UI presents it as the recovery key.
- **Secure:** add or remove YubiKeys on an existing vault.
- **Use:** unlock with the YubiKey alone (PIN and touch). No token is needed.

Decisions you made:
- **Token OR YubiKey.** The vault key is wrapped once for the token (as today) and once for each YubiKey. Either one opens the vault.
- **PIN + touch** (`userVerification: 'required'`, used everywhere). This keeps the hmac-secret output stable, because YubiKeys derive a different secret with the PIN than without it.
- **Server vault only.** `.wurd` exports stay password-only.

How it works: the browser can only reach a YubiKey through **WebAuthn**. The **PRF extension** (the YubiKey's `hmac-secret`) gives a 32-byte secret that is unique to each credential, and that secret becomes key material. The browser sends it to the server once per unlock, together with a signed assertion. The server checks the signature, unwraps the vault key and issues a short-lived **session token**, so you don't touch the key on every request.

## Crypto and data (server)

These are fixed formats: once vaults use them, they can't change.

- **Per-key KEK:** `ikm = HMAC-SHA256(pepper, prf)`, then `kek = HKDF(ikm, salt_key, "wurd yubikey v1")`. The vault key is wrapped with XChaCha20-Poly1305, using the additional data `"wurd vault key|{userId}|key|{keyId}"`. As today, a copy of `/data` opens nothing without the pepper.
- **Session token:** `wurds_<16 hex id>_<64 hex secret>`, built like a user token. `verifier = HKDF(ikm, salt, "wurd session v1")` and `kek = HKDF(ikm, salt, "wurd session key v1")`. The vault key is wrapped with the additional data `"wurd vault key|{userId}|session|{sessionId}"`. Sessions expire 8 hours after creation, and the expiry doesn't slide.
- **Challenge (stateless):** `nonce(16) ‖ expiresAt(8, big-endian) ‖ HMAC(HKDF(pepper, "wurd challenge v1"), nonce‖expiresAt)`, sent as base64url and valid for 5 minutes. A challenge is single-use: using it inserts the nonce into `used_challenges`, and a primary-key clash means a replay. Issuing a challenge writes nothing, so the unauthenticated endpoint needs no rate limit.
- **PRF salt (client constant):** `TextEncoder('wurd vault key v1')`. It must never change.
- **New tables** in `Store::setUp()` (`src/Store.php:43`):
  - `credentials (id hex16 PK, user_id, credential_id TEXT UNIQUE, name, rp_id, public_key BLOB, sign_count, salt, wrapped_key, created_at, last_used_at)`
  - `sessions (id hex16 PK, user_id, key_id, salt, verifier, wrapped_key, created_at, expires_at INTEGER)`
  - `used_challenges (nonce BLOB PK, expires_at INTEGER)`

## API additions

| Method | Path | Auth | Body → response |
|---|---|---|---|
| POST | `/api/challenge` | none | → `{challenge}` |
| POST | `/api/session` | none (the assertion is the proof) | `{assertion}` → `201 {token, expiresAt}` |
| DELETE | `/api/session` | session | → `204` |
| GET | `/api/keys` | token or session | → `{user:{id}, keys:[{id, name, rpId, createdAt, lastUsedAt}]}` |
| POST | `/api/keys` | token, or a **fresh** session | `{name, credential:{id, publicKey, transports}, assertion}` → `201` key |
| DELETE | `/api/keys/{hex16}` | token, or a **fresh** session | → `204`, and revokes that key's sessions |

- **`assertion`** is `{credentialId, clientDataJSON, authenticatorData, signature, userHandle, prf}`, every field base64url.
- **Fresh** means token auth, or a session created at most 10 minutes ago. Anything else gets `403 "Unlock again to change keys"`. This stops a stolen session from quietly adding its own key and keeping access.
- **Limits:** at most 10 keys per vault, and key names follow the same rules as file names, at most 64 bytes.
- **Rate limit:** failed `POST /api/session` attempts count against the existing per-IP `auth_failures` limit.

## Steps

### Server (`/home/lalex/Projects/wurd-server`)

1. **Shared key helpers + tables (30 min).** Move `derive`, `wrap` and `unwrap` out of `src/Users.php:137-164` into a new `src/Keys.php`, with the HKDF info strings and the additional data as parameters. `Users` keeps its exact strings (`"wurd token v2"`, `"wurd vault key v2"`, `"wurd vault key|{id}"`), so existing vaults keep working unchanged. Add the three tables. **Done when** the token flow still connects, lists, uploads and downloads.
2. **`src/WebAuthn.php` (1.5 h).** It provides `challenge()`, `consumeChallenge()`, base64url helpers, `checkPublicKey(spki)` (EC P-256 only, via `openssl_pkey_get_details`) and `verifyAssertion(key row, assertion)`. That last function checks:
   1. clientData: `type === 'webauthn.get'`, a valid challenge, `crossOrigin !== true`, and an origin of `https://<rp_id>[:port]` or `http://localhost[:port]`.
   2. authData: at least 37 bytes, `rpIdHash === sha256(rp_id)`, and the UP (0x01) and UV (0x04) flags set.
   3. signCount: if either the stored or the new count is above 0, the new one must be higher.
   4. `openssl_verify(authData . sha256(clientDataJSON), sig, PEM(spki), SHA256) === 1`. The signature uses ES256 only, which every YubiKey 5 supports. `openssl` and `sodium` are both in the image (checked).
   5. `userHandle`, if present, equals the user ID.
3. **`src/Credentials.php`, `src/Sessions.php` and routes (1.5 h).**
   - `Credentials`:
     - `list`
     - `register`: verifies the proof assertion against the SPKI the client sent, takes `rp_id` from the origin host (a hostname, never an IP address), and wraps the vault key under the PRF KEK.
     - `remove`
     - `unlock`: finds the key by `credential_id`, verifies the assertion, then unwraps. A wrong PRF fails the AEAD and returns `401`.
   - `Sessions`: `create`, `authenticate` (an unknown ID still costs one derivation, as `Users::authenticate` does) and `revoke`. Expired rows are deleted whenever a session is created.
   - `src/Auth.php`: split out `limit($ip)` and `fail($ip)`, and send `wurds_` bearers to `Sessions`. `User` gains `fresh`.
   - `src/Http.php`: add `jsonBody(16 KiB max)`.
   - `public/index.php`: add the routes and the `require`s.
   - The PRF output and secrets are wiped with `sodium_memzero` and marked `#[\SensitiveParameter]`, and request bodies are never logged.

### Frontend (`/home/lalex/Projects/wurd`) + docs

4. **`js/util.js` + `js/server.js` (1 h).**
   - `js/util.js`: add `bytesToBase64Url` and `base64UrlToBytes`.
   - `js/server.js`:
     - `keysSupported()`: `PublicKeyCredential`, a secure context, and a hostname that isn't an IP address.
     - `unlockWithKey(url, opts)`: fetches a challenge, then calls `credentials.get` with no `allowCredentials`, so a discoverable key gets picked, plus UV required, `hints:['security-key']` and PRF `eval`. It then POSTs `/session`, and the connection becomes `{url, token, kind:'session', expiresAt}`.
     - `addKey(name)`: does `GET /keys` and a challenge, then `credentials.create` with `residentKey:'required'`, `authenticatorAttachment:'cross-platform'`, ES256, `excludeCredentials`, `prf:{}`. It requires `prf.enabled` and a non-null `getPublicKey()`, then calls `credentials.get` on the new key for the PRF and POSTs `/keys`. That's two touches.
     - `removeKey(id)` and `listKeys()`.
     - A `401` on a session connection drops it and calls an `onDisconnect` callback.
     - `disconnect()` sends `DELETE /session`, best effort.
     - `loadConnection()` ignores expired sessions.
5. **Vault tab UI (1.5 h).**
   - `index.html` server form: add an **Unlock with YubiKey** button next to Connect, and a **Create a vault with a YubiKey** button next to Request a token. The create flow is `requestToken` → `connect` → `addKey`, then the token is shown in `#token-reveal`, worded as the recovery key.
   - When connected, show a **YubiKeys** list (the `recent-list` card pattern from `renderServerFile`, `js/app.js:634`) with a name field and an **Add a YubiKey** button.
   - `syncServerPanel()` (`js/app.js:694`) shows "Unlocked with your YubiKey until 18:30" for a session.
   - Error handling reuses `setServerError` and `notify`. The YubiKey UI stays hidden when `!keysSupported()`.
   - Minimal CSS in `css/app.css`.
6. **Docs (30 min).**
   - README: a YubiKey section (requirements, recovery = the token, register two keys), the new API rows, and the note that LAN mode needs a host *name* (e.g. `wurd.lan`), not an IP address.
   - `PLAN.md` Authentication section.
   - The `WURD_HOST` comment in `.env.example`.

## Known limits (go in the README)

- **Keys are tied to the hostname.** A key registered at `localhost` doesn't work at `https://wurd.lan:8443`. Register it again there; each registration counts as one more key.
- **No YubiKeys on IP-address hosts or `file://` pages.** Browsers refuse WebAuthn there.
- **The browser and the key must support PRF with security keys.** This is checked at runtime. A failed registration can leave an unused passkey on the YubiKey, which can be removed in Yubico Authenticator.
- **The token stays a full key** (the OR model). Anyone holding it can still open the vault.

## Verification

There's no test suite in the repo (`tests/smoke.sh` was deleted), so these checks are manual.

1. Run `docker compose build && docker compose up -d`, then `curl -s localhost:8026/api/health` should return `{"ok":true}`. Run `php -l` on each new file inside the container.
2. Check the API with curl:
   - `POST /api/challenge` returns a challenge.
   - Junk `POST /api/session` gets `401`, and the 11th attempt gets `429`.
   - `GET /api/keys` with a token returns `"keys":[]`.
   - The old token's list, upload and download still work.
3. In Chrome or Edge on Windows with a YubiKey 5 at `http://localhost:8026`: Create a vault with a YubiKey (PIN, two touches) → the token appears → Disconnect → **Unlock with YubiKey** without the token → save, open and delete files.
4. Connect with the token alone and check that the same files appear. Add a second key, remove the first, and check that its session ends. Reload with "Stay connected" and check that the session survives. With the session lifetime temporarily set to 2 minutes, check that the panel asks you to unlock again.
5. Inspect the volume's SQLite: there's a `credentials` row per key and no PRF or plaintext anywhere, `users.wrapped_key` is unchanged, and expired `sessions` get cleared.
