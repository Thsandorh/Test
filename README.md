# Film Sync API

Egyszeru, sajat hosztolasu realtime szinkron a filmnezos apphoz.
SQLite + FastAPI + WebSocket, hogy a telefon/TV/tablabees kozott azonnal frissuljon:
- filmnezesi pozicio
- kedvencek
- beallitasok
- eszkoz regisztracio

A rendszer JWT alapu hitelesitest hasznal (Firestore-szeru szabalyokkal), es van vedett admin felulet.

## Inditas

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export JWT_SECRET="egy-nagyon-hosszu-titok"
export ADMIN_API_KEY="admin-api-kulcs"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="eros-jelszo"
uvicorn app:app --host 0.0.0.0 --port 8000
```

Opcionalis CORS:

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
