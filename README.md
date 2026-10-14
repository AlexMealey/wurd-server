# wurd-server

An optional storage backend for the [Wurd](../wurd) editor. Each user gets their own token and their own vault of documents, stored encrypted with a key that only their token unlocks.

The browser does every conversion. The server never opens, parses or converts a document, and an encrypted `.wurd` file reaches it already encrypted. Without a server, Wurd works exactly as before.

- **Stack:** PHP 8.5 + Apache + SQLite, in one container. No Composer packages, no framework.
- **Recommended:** run it on the same machine as your browser, or on your LAN. Hosting it on the Internet is possible, but discouraged.

## Run it on this machine (recommended)

```sh
cp .env.example .env
chmod 600 .env
docker compose up -d
```

1. Open http://localhost:8026. Wurd is served from `../wurd` (set `WURD_FRONTEND_DIR` to change it).
2. In Wurd, open the **Vault** tab and select **Request a token**. Copy the token somewhere safe: it's shown once, and it's the only key to your files.
3. Connect with it. Tick **Remember address** to keep the address on this device, and **Stay connected in this tab** to survive a page reload. The token itself is never stored beyond the tab.

The port is bound to `127.0.0.1`, so nothing else on the network can reach it.

## Run it on a LAN

HTTPS is required on a LAN, for two reasons:

- The token would otherwise cross the network in clear text.
- Browsers turn off Web Crypto on `http://192.168.x.x`, which breaks `.wurd` files and password-protected `.odt` files.

Caddy provides the HTTPS:

1. In `.env`, set `WURD_HOST` to the name or IP address other devices use, e.g. `WURD_HOST=192.168.1.10`.
2. Start it:
   ```sh
   docker compose --profile tls up -d
   ```
3. Export Caddy's root certificate:
   ```sh
   docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt wurd-root.crt
   ```
4. Install `wurd-root.crt` as a trusted root certificate on each device.
5. Open `https://<WURD_HOST>:8443` on each device.

`http://localhost:8026` keeps working on the server machine itself.

## On the Internet (discouraged)

**Prefer a VPN** (WireGuard, Tailscale) to a LAN-mode server instead.

If you do publish it:

1. Set `WURD_HOST` to your domain and `WURD_TLS` to your email address. Caddy then gets a Let's Encrypt certificate.
2. Set `WURD_TLS_PORT=443`.
3. Save sensitive documents as `.wurd` only.
4. Keep backups.

## Settings (`.env`)

| Variable | Default | |
|---|---|---|
| `WURD_FRONTEND_DIR` | `../wurd` | Served read-only at `/`. |
| `WURD_PORT` | `8026` | Local port, bound to `127.0.0.1`. |
| `WURD_MAX_FILE_MB` | `25` | Largest single file. |
| `WURD_MAX_TOTAL_MB` | `1024` | Total storage, across all users. |
| `WURD_MAX_FILES` | `5000` | Number of files, across all users. |
| `WURD_ALLOWED_ORIGINS` | empty | Origins allowed to call the API from another page: `null` for Wurd opened from `file://`, or e.g. `http://localhost:8000`. Not needed when Wurd is opened from this server. |
| `WURD_HOST`, `WURD_TLS`, `WURD_TLS_PORT` | `localhost`, `internal`, `8443` | LAN/Internet mode. |
| `WURD_SUBNET`, `WURD_PROXY_IP` | `172.29.84.0/24`, `.10` | The Docker network between Caddy and Wurd. Change both if the subnet clashes. |

## API

Every route except `/api/health` and `/api/tokens` needs `Authorization: Bearer <token>`, and only ever sees that token's own files: another user's file ID gets `404`. Errors come back as `{"error": "..."}`.

| Method | Path | Request | Response |
|---|---|---|---|
| GET | `/api/health` | | `{"ok":true}` |
| POST | `/api/tokens` | | `201` + `{"token": "wurd_<id>_<secret>"}`: a new user with an empty vault. Shown once. |
| GET | `/api/files` | | `[{id, name, format, size, rev, updatedAt}]`, newest first |
| POST | `/api/files` | file bytes; `X-File-Name: <percent-encoded name>` | `201` + metadata, `ETag: "1"` |
| GET | `/api/files/{id}` | | file bytes, `ETag`, always as an `application/octet-stream` attachment |
| PUT | `/api/files/{id}` | file bytes; `If-Match: "<rev>"`; optional `X-File-Name` to rename | metadata, new `ETag`; `412` if the file changed since `<rev>` |
| DELETE | `/api/files/{id}` | `If-Match: "<rev>"` | `204` |

**Accepted extensions:** `.docx`, `.odt`, `.doc`, `.html`/`.htm`, `.txt`, `.wurd`.

**Other status codes:**

| Code | Meaning |
|---|---|
| `400` | Bad name |
| `401` | Bad token |
| `411` | No `Content-Length` |
| `413` | Too large |
| `415` | Contents don't match the extension |
| `428` | `If-Match` missing |
| `429` | 10 wrong tokens from one IP in 10 minutes, or 5 token requests from one IP in an hour |
| `507` | Quota full |

## Security

The design is in [PLAN.md](PLAN.md). In short:

- **Per-user tokens.** Anyone who can reach the server can request a token (5 per IP per hour), which is why it listens on `127.0.0.1` by default. The database keeps only a salted HKDF-SHA256 verifier of each token, never the token itself.
- **Encrypted at rest.** Each file is encrypted with XChaCha20-Poly1305 (libsodium secretstream) under a key derived from its owner's token on every request and never stored. Plaintext never reaches the disk, and a file that was changed on disk fails to download rather than returning wrong bytes.
- **Lost token, lost files.** Nobody, including the server's admin, can decrypt a vault without its token. A new token opens a new, empty vault.
- **Same origin.** The frontend and API share one origin, so no CORS is needed.
- **Downloads can't run.** Stored files are only ever sent as opaque downloads, so a stored `.html` file can't run on this origin.
- **Names never touch the disk.** Files are stored under random IDs, and file names are never used as paths.
- **Locked-down container.** It runs as `www-data` with a read-only filesystem, all capabilities dropped and `no-new-privileges`. The only writable place is the `/data` volume.
- **Hardened PHP.** Shell and URL functions are disabled, `open_basedir` is set, and errors only go to the log.

## Tests

```sh
docker build -t wurd-server . && tests/smoke.sh
```

This starts a throwaway container and checks the API and every security rule.

## Backup and restore

All state is in the `wurd_wurd-data` volume.

```sh
# Back up
docker run --rm -v wurd_wurd-data:/data:ro -v "$PWD":/backup alpine tar czf /backup/wurd-backup.tgz -C /data .

# Restore (stop the server first)
docker compose down
docker run --rm -v wurd_wurd-data:/data -v "$PWD":/backup alpine sh -c 'tar xzf /backup/wurd-backup.tgz -C /data && chown -R 33:33 /data'
docker compose up -d
```

## Upgrading from the single shared token

`WURD_TOKEN` is no longer used and can be removed from `.env`. Files stored before the upgrade have no owner and aren't encrypted, so no token can see them. Download any you need with the old version first. To clear them out, start with an empty volume:

```sh
docker compose down
docker volume rm wurd_wurd-data
docker compose up -d
```
