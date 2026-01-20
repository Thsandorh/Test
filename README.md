# Realtime Sync Database

Self-hosted realtime sync database with REST + WebSocket APIs, per-user authorization rules, and a secured admin dashboard.
It behaves like a lightweight, Firestore-style store: users write data into collections/keys and subscribe to realtime updates.

## Features

- REST + WebSocket realtime sync.
- Per-user access rules enforced by JWT.
- Rate limiting, audit logging, and token revocation.
- Soft deletes, TTL expiry, delta sync (`updated_since`), and bulk upserts.
- Admin dashboard with exports and IP allowlisting.
- Export endpoints for JSON/CSV snapshots.
- Health endpoint with basic metrics.

## Quick Start

```bash
npm install
export JWT_SECRET="change-this-long-secret"
export ADMIN_API_KEY="change-this-admin-key"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="strong-password"
node server.js
```

Optional CORS allowlist:

```bash
export CORS_ALLOW_ORIGINS="https://app.example.com,https://tv.example.com"
```

Optional admin IP allowlist:

```bash
export ADMIN_IP_ALLOWLIST="203.0.113.10,203.0.113.11"
```

## Auth & Security

- All client endpoints require a Bearer JWT.
- Tokens are tied to a `user_id` and enforced on every request.
- Token revocation uses a server-side revocation list.
- Admin endpoints require `X-Admin-Api-Key`.
- Admin dashboard uses Basic Auth + optional IP allowlist.
- Prefer HTTPS in production and keep secrets out of the repo.

### Issue a token (admin)

```bash
curl -X POST http://localhost:8000/v1/admin/users \
  -H 'Content-Type: application/json' \
  -H 'X-Admin-Api-Key: change-this-admin-key' \
  -d '{"user_id":"u1","display_name":"Alex"}'
```

Response contains a `token` and `jti`:

```
Authorization: Bearer <token>
```

### Rotate a token (admin)

```bash
curl -X POST http://localhost:8000/v1/admin/users/u1/rotate \
  -H 'X-Admin-Api-Key: change-this-admin-key'
```

### Revoke a token (admin)

```bash
curl -X POST http://localhost:8000/v1/admin/tokens/revoke \
  -H 'Content-Type: application/json' \
  -H 'X-Admin-Api-Key: change-this-admin-key' \
  -d '{"jti":"<token-jti>","exp":1717171717}'
```

## Data API (JWT required)

### Upsert data

```bash
curl -X POST http://localhost:8000/v1/data \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -H 'X-Conflict-Policy: last_write_wins' \
  -d '{"user_id":"u1","collection":"profile","key":"theme","value":{"mode":"dark"}}'
```

Supported conflict policies:

- `last_write_wins` (default)
- `server_time`
- `max_numeric`

### Bulk upsert

```bash
curl -X POST http://localhost:8000/v1/data/bulk \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"user_id":"u1","items":[{"collection":"profile","key":"theme","value":{"mode":"dark"}}]}'
```

### List data (delta sync)

```bash
curl -X GET "http://localhost:8000/v1/data/u1/profile?updated_since=2024-01-01T00:00:00.000Z" \
  -H 'Authorization: Bearer <token>'
```

Pagination:

```
/v1/data/u1/profile?limit=100&cursor=<base64>
```

### Soft delete data

```bash
curl -X DELETE http://localhost:8000/v1/data/u1/profile/theme \
  -H 'Authorization: Bearer <token>'
```

## Devices (optional)

Register a device for presence/tracking:

```bash
curl -X POST http://localhost:8000/v1/devices/register \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"user_id":"u1","device_id":"tv-1","name":"Living Room"}'
```

## Realtime WebSocket

Connect:

```bash
wscat -c "ws://localhost:8000?token=<token>"
```

Example payloads:

```json
{"type":"data.updated","data":{"user_id":"u1","collection":"profile","key":"theme","value":{"mode":"dark"},"updated_at":"..."}}
```

```json
{"type":"data.deleted","data":{"user_id":"u1","collection":"profile","key":"theme","deleted_at":"..."}}
```

## Admin API

Quick stats and recent activity:

```bash
curl http://localhost:8000/admin/data \
  -H 'X-Admin-Api-Key: change-this-admin-key'
```

Exports:

- `GET /admin/export/users.json`
- `GET /admin/export/data.json`
- `GET /admin/export/audit.csv`

## Admin Dashboard

Visit:

```
http://localhost:8000/admin
```

Uses Basic Auth (`ADMIN_USERNAME` / `ADMIN_PASSWORD`) and optional `ADMIN_IP_ALLOWLIST`.

## Health Endpoint

```bash
curl http://localhost:8000/health
```

## Data Model

Each record is stored as:

```json
{
  "user_id": "u1",
  "collection": "profile",
  "key": "theme",
  "value": { "mode": "dark" },
  "updated_at": "2024-01-01T12:34:56.000Z",
  "deleted_at": null
}
```

## Environment Variables

- `JWT_SECRET` (required)
- `ADMIN_API_KEY` (required)
- `ADMIN_USERNAME` / `ADMIN_PASSWORD`
- `ADMIN_IP_ALLOWLIST`
- `CORS_ALLOW_ORIGINS`
- `RATE_LIMIT_PER_MIN`
- `ADMIN_RATE_LIMIT_PER_MIN`
- `TOKEN_TTL_SECONDS`
- `AUDIT_LOG_TTL_DAYS`
- `CLEANUP_INTERVAL_MS`
- `DB_PATH`

## Notes

- SQLite file is `data.db` by default.
- For production, run behind HTTPS and set strong secrets.
- If you see merge conflicts in `.gitignore`, `README.md`, or `templates/admin.html`, keep the latest versions from this repository and re-run your push.
