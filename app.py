from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBasic, HTTPBasicCredentials, HTTPBearer
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.requests import Request

DB_PATH = "data.db"
JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_ISSUER = os.getenv("JWT_ISSUER", "film-sync")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "film-clients")
JWT_EXPIRES_SECONDS = int(os.getenv("JWT_EXPIRES_SECONDS", "2592000"))  # 30 days
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
CORS_ALLOW_ORIGINS = [origin.strip() for origin in os.getenv("CORS_ALLOW_ORIGINS", "").split(",") if origin.strip()]

app = FastAPI(title="Film Sync API", version="1.1.0")
templates = Jinja2Templates(directory="templates")
security_bearer = HTTPBearer()
security_basic = HTTPBasic()

if CORS_ALLOW_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ALLOW_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "X-Admin-Api-Key"],
    )

conn = sqlite3.connect(DB_PATH, check_same_thread=False)
conn.row_factory = sqlite3.Row
lock = threading.Lock()


class ProgressUpsert(BaseModel):
    user_id: str
    film_id: str
    position_seconds: int = Field(ge=0)
    duration_seconds: int = Field(ge=0)
    device_id: Optional[str] = None


class FavoriteUpsert(BaseModel):
    user_id: str
    film_id: str
    favorite: bool


class SettingUpsert(BaseModel):
    user_id: str
    key: str
    value: Any


class DeviceRegister(BaseModel):
    user_id: str
    device_id: str
    name: str


connections: Dict[str, List[WebSocket]] = {}


@dataclass(frozen=True)
class UserContext:
    user_id: str
    token_version: int


class TokenIssueRequest(BaseModel):
    user_id: str
    display_name: Optional[str] = None


class TokenIssueResponse(BaseModel):
    token: str
    expires_at: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    with lock:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                display_name TEXT,
                token_version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS watch_progress (
                user_id TEXT NOT NULL,
                film_id TEXT NOT NULL,
                position_seconds INTEGER NOT NULL,
                duration_seconds INTEGER NOT NULL,
                device_id TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (user_id, film_id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS favorites (
                user_id TEXT NOT NULL,
                film_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (user_id, film_id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                user_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (user_id, key),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.commit()


def ensure_user(user_id: str, display_name: Optional[str] = None) -> None:
    with lock:
        conn.execute(
            "INSERT OR IGNORE INTO users (id, display_name, created_at) VALUES (?, ?, ?)",
            (user_id, display_name, utc_now()),
        )
        conn.commit()


def get_user_token_version(user_id: str) -> int:
    with lock:
        row = conn.execute(
            "SELECT token_version FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return int(row["token_version"])


def row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def require_jwt_configured() -> None:
    if not JWT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT secret not configured",
        )


def create_token(user_id: str, token_version: int) -> TokenIssueResponse:
    require_jwt_configured()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=JWT_EXPIRES_SECONDS)
    payload = {
        "sub": user_id,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "exp": int(expires_at.timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "token_version": token_version,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return TokenIssueResponse(token=token, expires_at=expires_at.isoformat())


def decode_token(token: str) -> UserContext:
    require_jwt_configured()
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
    user_id = payload.get("sub")
    token_version = payload.get("token_version")
    if not user_id or not isinstance(token_version, int):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    current_version = get_user_token_version(user_id)
    if current_version != token_version:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")
    return UserContext(user_id=user_id, token_version=token_version)


def require_admin_api_key(request: Request) -> None:
    if not ADMIN_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin API key not configured",
        )
    provided = request.headers.get("X-Admin-Api-Key")
    if not provided or not secrets_compare(provided, ADMIN_API_KEY):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin API key")


def secrets_compare(value: str, expected: str) -> bool:
    return secrets.compare_digest(value, expected)


def require_basic_admin(credentials: HTTPBasicCredentials = Depends(security_basic)) -> None:
    if not (ADMIN_USERNAME and ADMIN_PASSWORD):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin credentials not configured",
        )
    valid = secrets_compare(credentials.username, ADMIN_USERNAME) and secrets_compare(
        credentials.password, ADMIN_PASSWORD
    )
    if not valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin credentials")


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_bearer),
) -> UserContext:
    return decode_token(credentials.credentials)


def require_matching_user(user_id: str, ctx: UserContext) -> None:
    if user_id != ctx.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden for this user")


def require_payload_user(user_id: str, ctx: UserContext) -> None:
    if user_id != ctx.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User mismatch")


async def broadcast(user_id: str, event_type: str, data: Dict[str, Any]) -> None:
    payload = {"type": event_type, "data": data}
    if user_id not in connections:
        return
    stale: List[WebSocket] = []
    for ws in connections[user_id]:
        try:
            await ws.send_json(payload)
        except Exception:
            stale.append(ws)
    if stale:
        for ws in stale:
            connections[user_id].remove(ws)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/v1/ping")
def ping() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/admin/users", response_model=TokenIssueResponse)
def admin_create_user(payload: TokenIssueRequest, request: Request) -> TokenIssueResponse:
    require_admin_api_key(request)
    ensure_user(payload.user_id, payload.display_name)
    token_version = get_user_token_version(payload.user_id)
    return create_token(payload.user_id, token_version)


@app.post("/v1/admin/users/{user_id}/rotate", response_model=TokenIssueResponse)
def admin_rotate_token(user_id: str, request: Request) -> TokenIssueResponse:
    require_admin_api_key(request)
    with lock:
        conn.execute(
            "UPDATE users SET token_version = token_version + 1 WHERE id = ?",
            (user_id,),
        )
        conn.commit()
    token_version = get_user_token_version(user_id)
    return create_token(user_id, token_version)


@app.get("/v1/admin/users")
def admin_list_users(request: Request) -> List[Dict[str, Any]]:
    require_admin_api_key(request)
    with lock:
        rows = conn.execute(
            "SELECT id, display_name, token_version, created_at FROM users ORDER BY created_at DESC"
        ).fetchall()
    return [row_to_dict(row) for row in rows]


@app.post("/v1/devices/register")
async def register_device(
    payload: DeviceRegister, ctx: UserContext = Depends(get_current_user)
) -> Dict[str, Any]:
    require_payload_user(payload.user_id, ctx)
    ensure_user(payload.user_id)
    now = utc_now()
    with lock:
        conn.execute(
            """
            INSERT INTO devices (id, user_id, name, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                user_id=excluded.user_id,
                name=excluded.name,
                updated_at=excluded.updated_at
            """,
            (payload.device_id, payload.user_id, payload.name, now, now),
        )
        conn.commit()
    response = {
        "device_id": payload.device_id,
        "user_id": payload.user_id,
        "name": payload.name,
        "updated_at": now,
    }
    await broadcast(payload.user_id, "device.registered", response)
    return response


@app.get("/v1/devices/{user_id}")
def list_devices(user_id: str, ctx: UserContext = Depends(get_current_user)) -> List[Dict[str, Any]]:
    require_matching_user(user_id, ctx)
    with lock:
        rows = conn.execute(
            "SELECT * FROM devices WHERE user_id = ? ORDER BY updated_at DESC",
            (user_id,),
        ).fetchall()
    return [row_to_dict(row) for row in rows]


@app.post("/v1/progress")
async def upsert_progress(
    payload: ProgressUpsert, ctx: UserContext = Depends(get_current_user)
) -> Dict[str, Any]:
    require_payload_user(payload.user_id, ctx)
    ensure_user(payload.user_id)
    now = utc_now()
    with lock:
        conn.execute(
            """
            INSERT INTO watch_progress
                (user_id, film_id, position_seconds, duration_seconds, device_id, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, film_id) DO UPDATE SET
                position_seconds=excluded.position_seconds,
                duration_seconds=excluded.duration_seconds,
                device_id=excluded.device_id,
                updated_at=excluded.updated_at
            """,
            (
                payload.user_id,
                payload.film_id,
                payload.position_seconds,
                payload.duration_seconds,
                payload.device_id,
                now,
            ),
        )
        conn.commit()
    response = {
        "user_id": payload.user_id,
        "film_id": payload.film_id,
        "position_seconds": payload.position_seconds,
        "duration_seconds": payload.duration_seconds,
        "device_id": payload.device_id,
        "updated_at": now,
    }
    await broadcast(payload.user_id, "progress.updated", response)
    return response


@app.get("/v1/progress/{user_id}")
def list_progress(user_id: str, ctx: UserContext = Depends(get_current_user)) -> List[Dict[str, Any]]:
    require_matching_user(user_id, ctx)
    with lock:
        rows = conn.execute(
            """
            SELECT * FROM watch_progress
            WHERE user_id = ?
            ORDER BY updated_at DESC
            """,
            (user_id,),
        ).fetchall()
    return [row_to_dict(row) for row in rows]


@app.get("/v1/progress/{user_id}/{film_id}")
def get_progress(
    user_id: str, film_id: str, ctx: UserContext = Depends(get_current_user)
) -> Dict[str, Any]:
    require_matching_user(user_id, ctx)
    with lock:
        row = conn.execute(
            "SELECT * FROM watch_progress WHERE user_id = ? AND film_id = ?",
            (user_id, film_id),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Progress not found")
    return row_to_dict(row)


@app.post("/v1/favorites")
async def upsert_favorite(
    payload: FavoriteUpsert, ctx: UserContext = Depends(get_current_user)
) -> Dict[str, Any]:
    require_payload_user(payload.user_id, ctx)
    ensure_user(payload.user_id)
    if payload.favorite:
        now = utc_now()
        with lock:
            conn.execute(
                """
                INSERT INTO favorites (user_id, film_id, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id, film_id) DO NOTHING
                """,
                (payload.user_id, payload.film_id, now),
            )
            conn.commit()
        response = {
            "user_id": payload.user_id,
            "film_id": payload.film_id,
            "favorite": True,
            "updated_at": now,
        }
        await broadcast(payload.user_id, "favorite.added", response)
        return response

    with lock:
        conn.execute(
            "DELETE FROM favorites WHERE user_id = ? AND film_id = ?",
            (payload.user_id, payload.film_id),
        )
        conn.commit()
    response = {
        "user_id": payload.user_id,
        "film_id": payload.film_id,
        "favorite": False,
        "updated_at": utc_now(),
    }
    await broadcast(payload.user_id, "favorite.removed", response)
    return response


@app.get("/v1/favorites/{user_id}")
def list_favorites(user_id: str, ctx: UserContext = Depends(get_current_user)) -> List[Dict[str, Any]]:
    require_matching_user(user_id, ctx)
    with lock:
        rows = conn.execute(
            """
            SELECT user_id, film_id, created_at FROM favorites
            WHERE user_id = ?
            ORDER BY created_at DESC
            """,
            (user_id,),
        ).fetchall()
    return [row_to_dict(row) for row in rows]


@app.post("/v1/settings")
async def upsert_setting(
    payload: SettingUpsert, ctx: UserContext = Depends(get_current_user)
) -> Dict[str, Any]:
    require_payload_user(payload.user_id, ctx)
    ensure_user(payload.user_id)
    now = utc_now()
    value_text = json.dumps(payload.value, ensure_ascii=False)
    with lock:
        conn.execute(
            """
            INSERT INTO settings (user_id, key, value, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id, key) DO UPDATE SET
                value=excluded.value,
                updated_at=excluded.updated_at
            """,
            (payload.user_id, payload.key, value_text, now),
        )
        conn.commit()
    response = {
        "user_id": payload.user_id,
        "key": payload.key,
        "value": payload.value,
        "updated_at": now,
    }
    await broadcast(payload.user_id, "setting.updated", response)
    return response


@app.get("/v1/settings/{user_id}")
def list_settings(user_id: str, ctx: UserContext = Depends(get_current_user)) -> List[Dict[str, Any]]:
    require_matching_user(user_id, ctx)
    with lock:
        rows = conn.execute(
            """
            SELECT user_id, key, value, updated_at FROM settings
            WHERE user_id = ?
            ORDER BY key ASC
            """,
            (user_id,),
        ).fetchall()
    return [
        {
            "user_id": row["user_id"],
            "key": row["key"],
            "value": json.loads(row["value"]),
            "updated_at": row["updated_at"],
        }
        for row in rows
    ]


@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str) -> None:
    token = websocket.query_params.get("token", "")
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    try:
        ctx = decode_token(token)
    except HTTPException:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    if ctx.user_id != user_id:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    await websocket.accept()
    connections.setdefault(user_id, []).append(websocket)
    await websocket.send_json({"type": "hello", "data": {"user_id": user_id}})
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connections[user_id].remove(websocket)
        if not connections[user_id]:
            del connections[user_id]


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(
    request: Request, _: None = Depends(require_basic_admin)
) -> HTMLResponse:
    with lock:
        users = conn.execute(
            "SELECT id, display_name, created_at FROM users ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
        devices = conn.execute(
            "SELECT id, user_id, name, updated_at FROM devices ORDER BY updated_at DESC LIMIT 50"
        ).fetchall()
        progress = conn.execute(
            """
            SELECT user_id, film_id, position_seconds, duration_seconds, updated_at
            FROM watch_progress
            ORDER BY updated_at DESC
            LIMIT 50
            """
        ).fetchall()
        favorites = conn.execute(
            "SELECT user_id, film_id, created_at FROM favorites ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
        settings = conn.execute(
            "SELECT user_id, key, updated_at FROM settings ORDER BY updated_at DESC LIMIT 50"
        ).fetchall()
    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "users": users,
            "devices": devices,
            "progress": progress,
            "favorites": favorites,
            "settings": settings,
        },
    )
