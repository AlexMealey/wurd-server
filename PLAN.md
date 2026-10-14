# Wurd Server: plan

An optional storage backend for the Wurd editor in `../wurd`. It stores document files and hands them back. Nothing else.

## Core idea

The browser already does every conversion and every encryption. The server stays a **dumb file store**:

- It never opens, parses, converts or previews a document. That removes the riskiest attack surface (XXE, zip bombs, macro and parser bugs).
- An encrypted `.wurd` file reaches the server already encrypted. The server never sees the plaintext or the password.
- Without a server configured, Wurd works exactly as it does today.

Stack: plain PHP 8.5 and SQLite (`pdo_sqlite` ships in the official image). No Composer, no framework, no third-party PHP code. Roughly 400 to 500 lines of PHP.

## Deployment modes

| Mode | Command | URL | Notes |
|---|---|---|---|
| **Local** (recommended) | `docker compose up -d` | `http://localhost:8026` | Port bound to `127.0.0.1` only. `localhost` counts as a secure context, so Web Crypto works over plain HTTP. |
| **LAN** | `docker compose --profile tls up -d` | `https://<host>:8443` | Caddy terminates TLS with its internal CA. Trust its root certificate once per client. The PHP container is no longer published. |
| **Internet** | LAN mode plus a real domain (Caddy gets a Let's Encrypt cert) | `https://wurd.example.com` | Discouraged. Prefer reaching LAN mode over a VPN (WireGuard, Tailscale). If you do it anyway: long token, save sensitive documents as `.wurd` only, keep backups. |

HTTPS is **required** for LAN, for two reasons:

1. The token would otherwise cross the network in clear text.
2. Browsers disable Web Crypto on `http://192.168.x.x`. That breaks `.wurd` files and password-protected `.odt` files.

### Same origin by default

The container serves the frontend too: `../wurd` is bind-mounted read-only, and `/api/*` goes to PHP. Frontend and API share one origin, so there is no CORS to configure.

Opening Wurd from `file://` still works. That needs an explicit opt-in: `WURD_ALLOWED_ORIGINS=null`.

## API

Everything sits under `/api`. Every route except `/api/health` needs `Authorization: Bearer <token>`. Errors come back as `{"error": "<message>"}`.

| Method | Path | Request | Success response |
|---|---|---|---|
| GET | `/api/health` | none | `200 {"ok":true}` (no version info, to avoid fingerprinting) |
| GET | `/api/files` | none | `200 [{id, name, format, size, rev, updatedAt}]`, newest first |
| POST | `/api/files` | raw bytes in the body, `X-File-Name: <percent-encoded UTF-8>` | `201` + metadata, `ETag: "<rev>"` |
| GET | `/api/files/{id}` | none | `200` raw bytes, `ETag`, sent as an attachment |
| PUT | `/api/files/{id}` | raw bytes, `If-Match: "<rev>"` (required), optional `X-File-Name` to rename | `200` + metadata, or `412` if the file changed elsewhere |
| DELETE | `/api/files/{id}` | `If-Match: "<rev>"` (required) | `204` |

**Why these choices:**

- **Raw request bodies, not multipart or base64.** In JS this is just `fetch(url, { method, body: blob })`. In PHP the body streams from `php://input` straight to disk.
- **The file name goes in a header, not the query string.** Query strings end up in access logs, and document names can be sensitive.
- **`If-Match` is required on every change** to an existing file. Two tabs, or two people, can never silently overwrite each other.

**Status codes:** `400` bad name or format, `401` bad token, `404` not found, `411` missing length, `412` version conflict, `413` too large, `415` content doesn't match its extension, `428` missing `If-Match`, `429` too many failed logins, `507` quota full.

## Storage

All persistent data lives in one Docker volume mounted at `/data`:

```
/data/wurd.sqlite        metadata (WAL mode)
/data/files/<id>         file contents, named by ID only
/data/tmp/               uploads in progress
```

```sql
CREATE TABLE files (
  id         TEXT PRIMARY KEY,   -- 32 hex chars from random_bytes(16)
  name       TEXT NOT NULL,      -- display name with extension, e.g. "Report.docx"
  format     TEXT NOT NULL,      -- docx | odt | doc | html | txt | wurd
  size       INTEGER NOT NULL,
  rev        INTEGER NOT NULL,   -- +1 on every write; used as the ETag
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE auth_failures (ip TEXT NOT NULL, at INTEGER NOT NULL);
```

Every write is atomic:

1. Stream the body to `/data/tmp/<random>`.
2. Call `fsync`.
3. Inside `BEGIN IMMEDIATE`, check the `If-Match` revision.
4. `rename()` the temp file over `/data/files/<id>`.
5. Update the row and commit.

## Security

### Authentication

- One bearer token, read from `WURD_TOKEN` or from `WURD_TOKEN_FILE` (for Docker secrets). Generate it with `openssl rand -hex 32`.
- **Fail closed.** If the token is missing or shorter than 32 characters, the entrypoint exits with a clear message. The server never runs open.
- Tokens are compared with `hash_equals()` on SHA-256 digests, so the check takes constant time whatever the token length.
- No cookies and no sessions, which makes CSRF impossible.
- 10 failed attempts from one IP in 10 minutes returns `429`. Behind Caddy, `mod_remoteip` trusts `X-Forwarded-For` only from the compose network's subnet.

### Input

- **IDs** must match `^[0-9a-f]{32}$` before anything touches the disk. User-supplied names are never used as paths.
- **Names** must:
  - be valid UTF-8
  - contain no control characters, `/` or `\`
  - be at most 200 bytes
  - end in one of: `docx`, `odt`, `doc`, `html`, `txt`, `wurd` (`htm` is normalised to `html`)
- **Size:** `Content-Length` is required. The cap is `WURD_MAX_FILE_MB` (default 25). Apache's `LimitRequestBody` enforces it, and so does a byte counter while streaming.
- **Quotas:** `WURD_MAX_TOTAL_MB` (default 1024) and `WURD_MAX_FILES` (default 5000). Going over either returns `507`.
- **Content checks** (sanity only): `docx` and `odt` must start with `PK\x03\x04`. `wurd` must be a JSON object with `"wurd":"encrypted-document"`. `doc` must be OLE (`D0 CF 11 E0`) or text, since Wurd's own `.doc` export is HTML-based.

### Output

- **Downloads** are always sent with:
  - `Content-Type: application/octet-stream`
  - `Content-Disposition: attachment; filename*=UTF-8''...`

  A stored `.html` file can therefore never render on the server's origin, so no stored XSS.
- **Every response** carries `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
- **API responses** also carry `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; sandbox`.
- **Frontend files** get this CSP:

  ```
  default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline';
  img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; object-src 'none';
  base-uri 'none'; form-action 'none'; frame-ancestors 'none'
  ```

  `wasm-unsafe-eval` is there for hash-wasm's Argon2id (encrypted LibreOffice files). `unsafe-inline` styles are there because documents carry `style` attributes. Check the CSP against the real app before shipping it.
- **Errors** return a generic message to the client. Details go to the stderr log only. The `Authorization` header and request bodies are never logged.

### CORS

CORS only matters when the frontend is not served from the container.

- `WURD_ALLOWED_ORIGINS` is an exact-match list and is empty by default.
- No wildcard, and never `Access-Control-Allow-Credentials`.
- Allowed methods: `GET POST PUT DELETE`.
- Allowed headers: `Authorization Content-Type If-Match X-File-Name`.
- Exposed header: `ETag`.
- `null` (for `file://` pages) must be listed explicitly. Sandboxed iframes on any site also send `null`, but the token is still required.

### PHP and Apache hardening

- **`php.ini`:**
  - `expose_php=Off`, `display_errors=Off`, `log_errors=On`
  - `allow_url_fopen=Off`, `allow_url_include=Off`
  - `file_uploads=Off`, `enable_post_data_reading=Off`
  - `open_basedir=/app:/data:/tmp`
  - `disable_functions=exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec`
  - `memory_limit=64M` (bodies stream, they are never held in memory)
- **Apache:**
  - `ServerTokens Prod`, `ServerSignature Off`, `TraceEnable Off`
  - `AllowOverride None`, `Options -Indexes`, `Listen 8026`
  - The PHP engine is switched off for the frontend directory, so only `/app/public/index.php` can ever execute.
- **Container:**
  - Image: `php:8.5-apache`, pinned by digest.
  - Runs as `www-data`.
  - `read_only: true`, with tmpfs for `/tmp` and `/var/run/apache2`.
  - `cap_drop: [ALL]`, `no-new-privileges`, plus memory and pids limits.
  - Writable volume at `/data` only.

## Files

```
wurd-server/
├── Dockerfile
├── compose.yaml          wurd service (local) + caddy service (profile: tls)
├── .env.example          WURD_TOKEN, limits, WURD_ALLOWED_ORIGINS, WURD_FRONTEND_DIR=../wurd
├── docker/
│   ├── apache.conf       frontend static + /api -> index.php, headers, body limit, remoteip
│   ├── php.ini           hardening
│   ├── entrypoint.sh     validate config (fail closed), init /data, exec apache
│   └── Caddyfile         TLS profile
├── public/index.php      front controller + route table
├── src/
│   ├── Config.php        env/secret loading and validation
│   ├── Http.php          request parsing, JSON/error responses, security + CORS headers
│   ├── Auth.php          bearer check, failure rate limit
│   └── Store.php         SQLite + files, name/content validation, quotas, If-Match
├── tests/smoke.sh        curl tests against a running container
└── README.md             setup per mode, backup/restore, token rotation
```

## Build order

| # | Step | Done when | Estimate |
|---|---|---|---|
| 1 | Docker skeleton: Dockerfile, compose, apache.conf, php.ini, entrypoint | `curl localhost:8026/api/health` returns `{"ok":true}`, and the frontend loads at `/`, read-only and non-root | 45 min |
| 2 | Config + Auth | missing token stops the container; wrong token gets `401`; 11th failure gets `429` | 30 min |
| 3 | Store + file endpoints | create, list, get, update and delete round-trip; `412` and `428` behave correctly | 1.5 h |
| 4 | `tests/smoke.sh` | every security rule above has a passing test (traversal names, bad IDs, `413`, octet-stream + nosniff on download, rejected origins) | 1 h |
| 5 | TLS profile + README | LAN mode reachable over HTTPS from a second machine; backup and restore documented | 45 min |
| 6 | Frontend integration in `../wurd` (separate repo) | see below | 2 to 3 h |

## Frontend changes (`../wurd`)

The frontend stays offline-first and keeps using classic scripts, so `file://` still works.

1. **New `js/server.js`:** `Wurd.server.{list, get, create, update, remove}`. It's a `fetch` wrapper that adds the token and turns HTTP errors into `Wurd.UserError` messages.
2. **"Server" section in the Vault tab:** URL (defaults to `location.origin` when served over http(s)), token, Connect, Disconnect. The token lives in `localStorage` for that origin.
3. **Recent tab:** the hard-coded demo cards are replaced by the `GET /api/files` list. Clicking a card wraps the bytes in a `new File([blob], name)` and passes it to the existing `openFile()`, so it goes through the same sanitising path as a local file.
4. **Save:** if the document came from the server (or was saved there), Save does a `PUT` with `If-Match`. On `412`, the user is told and offered "Save as a new copy". Otherwise Save still downloads, as today.
5. **Export As:** gains a destination choice, "Download" or "Save to server", shown only when a server is connected. App state tracks `serverFile = { id, rev }`, cleared by New and by opening a local file.

## Out of scope for v1

Multi-user accounts, version history, folders, share links, server-side conversion or previews, search.

## Decisions to confirm

1. **Single shared token.** Everyone with the token sees every file. Per-user accounts would roughly double the size.
2. **Serve the frontend from the container** (same origin), rather than an API-only server with CORS.
3. **Files on disk named by opaque ID** (safest), rather than readable names in a host folder (easier to browse, but means handling paths).
4. **`php:8.5-apache` plus an optional Caddy sidecar for TLS**, rather than FrankenPHP: one container with built-in HTTPS, but less familiar.
