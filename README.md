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

## Auth es biztonsag

- Minden kliens hivas JWT-vel vedett (Bearer token).
- A token a `user_id`-hoz kotott, es a szerver ellenorzi, hogy a path vagy payload user_id megegyezik.
- A token visszavonhato `token_version` rotacioval.

### Token kiadas admin kulccsal

```bash
curl -X POST http://localhost:8000/v1/admin/users \
  -H 'Content-Type: application/json' \
  -H 'X-Admin-Api-Key: admin-api-kulcs' \
  -d '{"user_id":"u1","display_name":"Andris"}'
```

Valaszban kapsz `token` mezot, ezt add at a kliensnek:

```
Authorization: Bearer <token>
```

Token rotalas:

```bash
curl -X POST http://localhost:8000/v1/admin/users/u1/rotate \
  -H 'X-Admin-Api-Key: admin-api-kulcs'
```

## API parancsok (JWT-vel)

### Eszkoz regisztracio
```bash
curl -X POST http://localhost:8000/v1/devices/register \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"user_id":"u1","device_id":"tv-1","name":"Living Room TV"}'
```

### Film pozicio mentese
```bash
curl -X POST http://localhost:8000/v1/progress \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"user_id":"u1","film_id":"film-42","position_seconds":120,"duration_seconds":5400,"device_id":"tv-1"}'
```

### Kedvenc beallitasa
```bash
curl -X POST http://localhost:8000/v1/favorites \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"user_id":"u1","film_id":"film-42","favorite":true}'
```

### Beallitas mentese
```bash
curl -X POST http://localhost:8000/v1/settings \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"user_id":"u1","key":"autoplay","value":true}'
```

## Realtime szinkron (WebSocket)

Kapcsolodas:

```bash
wscat -c "ws://localhost:8000/ws/u1?token=<token>"
```

Minden frissitesnel automatikus uzenet jon peldaul:

```json
{"type":"progress.updated","data":{"user_id":"u1","film_id":"film-42","position_seconds":120,"duration_seconds":5400,"device_id":"tv-1","updated_at":"..."}}
```

## Admin felulet

A vedett admin dashboard a kovetkezo cimen erheto el:

```
http://localhost:8000/admin
```

A bongeszo Basic Auth-ot ker (ADMIN_USERNAME / ADMIN_PASSWORD). Innen ellenorizheted a felhasznalokat, eszkozoket es frissiteseket.

## Megjegyzesek

- A data.db lokalis SQLite fajlban tarolja az adatokat.
- Ha kesobb skala kell, konnyen atirhato PostgreSQL-re.
- A biztonsaghoz minimum a JWT_SECRET es az admin kulcs legyen hosszura, es csak HTTPS-en hasznald.
