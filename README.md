# wurd-server

An optional storage backend for the [Wurd](../wurd) editor. It stores document files and hands them back.

The browser does every conversion and every encryption. The server never opens, parses or converts a document, and an encrypted `.wurd` file reaches it already encrypted. Without a server, Wurd works exactly as before.

- **Stack:** PHP 8.5 + Apache + SQLite, in one container. No Composer packages, no framework.
- **Recommended:** run it on the same machine as your browser, or on your LAN. Hosting it on the Internet is possible, but discouraged.

## Run it on this machine (recommended)

```sh
cp .env.example .env
chmod 600 .env
sed -i "s/^WURD_TOKEN=.*/WURD_TOKEN=$(openssl rand -hex 32)/" .env
docker compose up -d
```

1. Open http://localhost:8026. Wurd is served from `../wurd` (set `WURD_FRONTEND_DIR` to change it).
2. In Wurd, open the **Vault** tab and connect using the token from `.env`.

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
| `WURD_TOKEN` | none (required) | At least 32 characters. The server won't start without it. |
| `WURD_TOKEN_FILE` | | Read the token from a file (Docker secrets) instead. |
| `WURD_FRONTEND_DIR` | `../wurd` | Served read-only at `/`. |
| `WURD_PORT` | `8026` | Local port, bound to `127.0.0.1`. |
| `WURD_MAX_FILE_MB` | `25` | Largest single file. |
| `WURD_MAX_TOTAL_MB` | `1024` | Total storage. |
| `WURD_MAX_FILES` | `5000` | Number of files. |
| `WURD_ALLOWED_ORIGINS` | empty | Origins allowed to call the API from another page: `null` for Wurd opened from `file://`, or e.g. `http://localhost:8000`. Not needed when Wurd is opened from this server. |
| `WURD_HOST`, `WURD_TLS`, `WURD_TLS_PORT` | `localhost`, `internal`, `8443` | LAN/Internet mode. |
| `WURD_SUBNET`, `WURD_PROXY_IP` | `172.29.84.0/24`, `.10` | The Docker network between Caddy and Wurd. Change both if the subnet clashes. |

## API

Every route except `/api/health` needs `Authorization: Bearer <token>`. Errors come back as `{"error": "..."}`.

| Method | Path | Request | Response |
|---|---|---|---|
| GET | `/api/health` | | `{"ok":true}` |
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
| `429` | 10 wrong tokens from one IP in 10 minutes |
| `507` | Quota full |

## Security

The design is in [PLAN.md](PLAN.md). In short:

- **No open mode.** Without a valid token, the server won't start.
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

## Rotating the token

1. Put a new token in `.env`.
2. Run `docker compose up -d`.
3. Reconnect each device in Wurd's Vault tab.
