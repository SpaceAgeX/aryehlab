from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles


BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"

AUTH_USERNAME = os.environ.get("TIMELAPSE_AUTH_USERNAME", "admin")
AUTH_PASSWORD_HASH = os.environ.get("TIMELAPSE_AUTH_PASSWORD_HASH", "")
SESSION_SECRET = os.environ.get("TIMELAPSE_SESSION_SECRET", "")
SESSION_COOKIE = "timelapse_session"
SESSION_DOMAIN = ".aryehlab.com"
SESSION_SECONDS = 7 * 24 * 60 * 60
PASSWORD_HASHER = PasswordHasher()

LOGIN_ATTEMPTS: dict[str, list[float]] = {}
LOGIN_ATTEMPTS_LOCK = threading.Lock()
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_MAX_ATTEMPTS = 5

app = FastAPI(title="Aryeh Lab")
app.mount("/public", StaticFiles(directory=PUBLIC_DIR), name="public")


def encode_token_part(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_token_part(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def create_session_token() -> str:
    payload = json.dumps(
        {
            "username": AUTH_USERNAME,
            "expires_at": int(time.time()) + SESSION_SECONDS,
            "csrf": secrets.token_urlsafe(32),
        },
        separators=(",", ":"),
    ).encode("utf-8")
    encoded_payload = encode_token_part(payload)
    signature = hmac.new(
        SESSION_SECRET.encode("utf-8"),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{encoded_payload}.{encode_token_part(signature)}"


def read_session_token(token: str | None) -> dict | None:
    if not token or not SESSION_SECRET:
        return None
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
        expected_signature = hmac.new(
            SESSION_SECRET.encode("utf-8"),
            encoded_payload.encode("ascii"),
            hashlib.sha256,
        ).digest()
        supplied_signature = decode_token_part(encoded_signature)
        if not hmac.compare_digest(expected_signature, supplied_signature):
            return None

        payload = json.loads(decode_token_part(encoded_payload))
        if payload.get("username") != AUTH_USERNAME:
            return None
        if int(payload.get("expires_at", 0)) <= time.time():
            return None
        if not isinstance(payload.get("csrf"), str):
            return None
        return payload
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def safe_destination(value: str | None, default: str = "/dashboard") -> str:
    if not value:
        return default
    parsed = urlparse(value)
    if not parsed.scheme and not parsed.netloc and value.startswith("/"):
        return value
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme == "https" and (
        hostname == "aryehlab.com"
        or hostname.endswith(".aryehlab.com")
    ):
        return value
    return default


def client_address(request: Request) -> str:
    return (
        request.headers.get("cf-connecting-ip")
        or (request.client.host if request.client else "unknown")
    )


def login_is_rate_limited(address: str) -> bool:
    cutoff = time.time() - LOGIN_WINDOW_SECONDS
    with LOGIN_ATTEMPTS_LOCK:
        attempts = [
            attempt
            for attempt in LOGIN_ATTEMPTS.get(address, [])
            if attempt >= cutoff
        ]
        LOGIN_ATTEMPTS[address] = attempts
        return len(attempts) >= LOGIN_MAX_ATTEMPTS


@app.get("/", include_in_schema=False)
async def index(request: Request):
    if read_session_token(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(
            safe_destination(request.query_params.get("next")),
            status_code=303,
        )
    return FileResponse(PUBLIC_DIR / "index.html")


@app.post("/login", include_in_schema=False)
async def login(request: Request):
    address = client_address(request)
    body = (await request.body()).decode("utf-8", errors="replace")
    fields = parse_qs(body, keep_blank_values=True)
    username = fields.get("username", [""])[0]
    password = fields.get("password", [""])[0]
    destination = safe_destination(fields.get("next", [""])[0])

    if login_is_rate_limited(address):
        return RedirectResponse("/?error=locked", status_code=303)

    password_matches = False
    try:
        password_matches = PASSWORD_HASHER.verify(
            AUTH_PASSWORD_HASH,
            password,
        )
    except (VerifyMismatchError, InvalidHashError):
        pass

    if username != AUTH_USERNAME or not password_matches:
        with LOGIN_ATTEMPTS_LOCK:
            LOGIN_ATTEMPTS.setdefault(address, []).append(time.time())
        return RedirectResponse("/?error=invalid", status_code=303)

    with LOGIN_ATTEMPTS_LOCK:
        LOGIN_ATTEMPTS.pop(address, None)

    response = RedirectResponse(destination, status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        create_session_token(),
        max_age=SESSION_SECONDS,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        domain=SESSION_DOMAIN,
    )
    return response


@app.get("/dashboard", include_in_schema=False)
async def dashboard(request: Request):
    if not read_session_token(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse("/?next=/dashboard", status_code=303)
    return FileResponse(PUBLIC_DIR / "dashboard.html")


@app.get("/logout", include_in_schema=False)
async def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        domain=SESSION_DOMAIN,
        secure=True,
        httponly=True,
        samesite="lax",
    )
    return response


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "online"}
