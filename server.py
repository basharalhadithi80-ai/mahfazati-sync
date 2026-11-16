#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wallet sync server — محفظتي (v1.2)
====================================
Account + vault sync backend for the Card Wallet app.
Pure Python standard library only (http.server + sqlite3) — no packages
to install, runs anywhere with Python 3.8+.

What it stores:
  users    : email (unique), scrypt password hash, vault_blob, vault_salt,
             vault_updated (epoch ms), created_at
  sessions : token, email, expires_at (30 days, sliding refresh on use)
  login_attempts : per-email failed-login counter (5 fails / 5 min -> 429)

Privacy model — the server NEVER sees card data:
  * vault_blob / vault_salt are opaque Base64 strings. The app encrypts the
    vault JSON on the phone with AES/GCM and a key derived from the
    ACCOUNT PASSWORD (PBKDF2-HMAC-SHA256, 100k iterations). The server
    stores the blob and hands it back; it cannot decrypt it, and it never
    receives the password in any form except the login/register hash check.
  * Passwords are stored as scrypt hashes (salted). Passwords, tokens,
    blobs and salts are NEVER logged — logs carry method/path/status only
    (query strings are stripped, so tokens never appear in logs).

API:
  GET  /health                    -> {"ok": true}
  GET  /                          -> short status page (Arabic)
  POST /api/register {email, password}            -> {token}
  POST /api/login    {email, password}            -> {token}
  POST /api/vault    {token, blob, salt, updated} -> {ok: true}
  GET  /api/vault?token=...                      -> {blob, salt, updated}
  POST /api/password {token, old_password, new_password} -> {ok: true}

Run:
  PORT=8000 python3 server.py
  (DB file wallet.db is created next to this script on first run.)

FREE-TIER CAVEAT (Render): the free tier sleeps after ~15 min idle and
its filesystem is ephemeral — the salon DB was wiped this way on
2026-11-04. The phone stays the primary copy of the cards; the server
copy is re-uploaded from the phone on the next sync, so a wipe is
recoverable as long as the phone still has the cards. The app also
offers a manual encrypted backup export/import as the safety net.
"""
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "wallet.db"))
PORT = int(os.environ.get("PORT", "8000"))
MAX_BODY = 1 * 1024 * 1024  # 1 MB — a vault blob is a few KB at most

TOKEN_TTL = 30 * 24 * 3600          # 30 days, sliding refresh on use
MAX_LOGIN_FAILS = 5
LOGIN_WINDOW = 5 * 60               # 5 minutes

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DB_LOCK = threading.Lock()


def now():
    return int(time.time())


# ---------- database ----------

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        " email TEXT PRIMARY KEY,"
        " pw_hash TEXT NOT NULL,"
        " vault_blob TEXT,"
        " vault_salt TEXT,"
        " vault_updated INTEGER,"
        " created_at INTEGER NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS sessions ("
        " token TEXT PRIMARY KEY,"
        " email TEXT NOT NULL,"
        " expires_at INTEGER NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS login_attempts ("
        " email TEXT PRIMARY KEY,"
        " fails INTEGER NOT NULL,"
        " window_start INTEGER NOT NULL)"
    )
    return conn


# ---------- passwords ----------

def hash_password(password):
    salt = os.urandom(16)
    dk = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32
    )
    return salt.hex() + ":" + dk.hex()


def check_password(password, stored):
    try:
        salt_hex, hash_hex = stored.split(":", 1)
        dk = hashlib.scrypt(
            password.encode("utf-8"), salt=bytes.fromhex(salt_hex),
            n=16384, r=8, p=1, dklen=32,
        )
        return dk.hex() == hash_hex
    except (ValueError, TypeError):
        return False


# ---------- sessions ----------

def new_token(email):
    token = secrets.token_hex(32)
    conn = db()
    try:
        conn.execute(
            "INSERT INTO sessions (token, email, expires_at) VALUES (?, ?, ?)",
            (token, email, now() + TOKEN_TTL),
        )
        conn.commit()
    finally:
        conn.close()
    return token


def auth_email(token):
    """Returns the email for a valid, unexpired token (sliding refresh), else None."""
    if not token:
        return None
    conn = db()
    try:
        row = conn.execute(
            "SELECT email, expires_at FROM sessions WHERE token = ?", (token,)
        ).fetchone()
        if row is None or row[1] < now():
            return None
        conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE token = ?",
            (now() + TOKEN_TTL, token),
        )
        conn.commit()
        return row[0]
    finally:
        conn.close()


def delete_token(token):
    conn = db()
    try:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
    finally:
        conn.close()


# ---------- login rate limit ----------

def login_allowed(email):
    conn = db()
    try:
        row = conn.execute(
            "SELECT fails, window_start FROM login_attempts WHERE email = ?",
            (email,),
        ).fetchone()
        if row is None:
            return True
        fails, start = row
        if now() - start > LOGIN_WINDOW:
            return True
        return fails < MAX_LOGIN_FAILS
    finally:
        conn.close()


def record_login_fail(email):
    with DB_LOCK:
        conn = db()
        try:
            row = conn.execute(
                "SELECT fails, window_start FROM login_attempts WHERE email = ?",
                (email,),
            ).fetchone()
            if row is None or now() - row[1] > LOGIN_WINDOW:
                conn.execute(
                    "INSERT INTO login_attempts (email, fails, window_start)"
                    " VALUES (?, 1, ?) ON CONFLICT(email) DO UPDATE"
                    " SET fails = 1, window_start = excluded.window_start",
                    (email, now()),
                )
            else:
                conn.execute(
                    "UPDATE login_attempts SET fails = fails + 1 WHERE email = ?",
                    (email,),
                )
            conn.commit()
        finally:
            conn.close()


def clear_login_fails(email):
    conn = db()
    try:
        conn.execute("DELETE FROM login_attempts WHERE email = ?", (email,))
        conn.commit()
    finally:
        conn.close()


# ---------- users / vault ----------

def get_user(email):
    conn = db()
    try:
        return conn.execute(
            "SELECT email, pw_hash, vault_blob, vault_salt, vault_updated"
            " FROM users WHERE email = ?",
            (email,),
        ).fetchone()
    finally:
        conn.close()


def create_user(email, password):
    with DB_LOCK:
        conn = db()
        try:
            if get_user(email) is not None:
                return False
            conn.execute(
                "INSERT INTO users (email, pw_hash, created_at) VALUES (?, ?, ?)",
                (email, hash_password(password), now()),
            )
            conn.commit()
            return True
        finally:
            conn.close()


def set_password(email, new_password):
    with DB_LOCK:
        conn = db()
        try:
            conn.execute(
                "UPDATE users SET pw_hash = ? WHERE email = ?",
                (hash_password(new_password), email),
            )
            conn.execute("DELETE FROM sessions WHERE email = ?", (email,))
            conn.commit()
        finally:
            conn.close()


def save_vault(email, blob, salt, updated):
    with DB_LOCK:
        conn = db()
        try:
            conn.execute(
                "UPDATE users SET vault_blob = ?, vault_salt = ?, vault_updated = ?"
                " WHERE email = ?",
                (blob, salt, updated, email),
            )
            conn.commit()
        finally:
            conn.close()


# ---------- HTTP ----------

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # logs carry method/path/status only
        pass

    def _log(self, status):
        # Path only, query string stripped — tokens never appear in logs.
        print(f"{self.command} {urlparse(self.path).path} -> {status}", flush=True)

    def _send_json(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self._log(status)

    def _send_text(self, status, text):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self._log(status)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send_text(200, (
                "<html lang=\"ar\" dir=\"rtl\"><body style=\"font-family:sans-serif;text-align:center;padding-top:60px\">"
                "<h1>سيرفر مزامنة محفظتي شغال ✓</h1>"
                "<p>الفحص: <a href=\"/health\">/health</a></p>"
                "</body></html>"
            ))
            return
        if path == "/health":
            self._send_json(200, {"ok": True})
            return
        if path == "/api/vault":
            token = parse_qs(urlparse(self.path).query).get("token", [None])[0]
            email = auth_email(token)
            if email is None:
                self._send_json(401, {"error": "bad or expired token"})
                return
            user = get_user(email)
            if user is None or user[2] is None:
                self._send_json(404, {"error": "no vault stored yet"})
                return
            self._send_json(200, {
                "blob": user[2],
                "salt": user[3] or "",
                "updated": str(user[4] or 0),
            })
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        data = self._read_json()
        if data is None:
            self._send_json(400, {"error": "invalid JSON"})
            return

        if path == "/api/register":
            email = (data.get("email") or "").strip().lower()
            password = data.get("password") or ""
            if not EMAIL_RE.match(email):
                self._send_json(400, {"error": "invalid email"})
                return
            if len(password) < 8:
                self._send_json(400, {"error": "password too short (min 8)"})
                return
            if not create_user(email, password):
                self._send_json(409, {"error": "email already registered"})
                return
            self._send_json(200, {"token": new_token(email)})
            return

        if path == "/api/login":
            email = (data.get("email") or "").strip().lower()
            password = data.get("password") or ""
            if not login_allowed(email):
                self._send_json(429, {"error": "too many failed attempts, try later"})
                return
            user = get_user(email)
            if user is None or not check_password(password, user[1]):
                record_login_fail(email)
                self._send_json(401, {"error": "wrong email or password"})
                return
            clear_login_fails(email)
            self._send_json(200, {"token": new_token(email)})
            return

        if path == "/api/vault":
            email = auth_email(data.get("token"))
            if email is None:
                self._send_json(401, {"error": "bad or expired token"})
                return
            blob = data.get("blob")
            salt = data.get("salt")
            updated = data.get("updated")
            if not isinstance(blob, str) or not blob:
                self._send_json(400, {"error": "blob required"})
                return
            if not isinstance(salt, str):
                self._send_json(400, {"error": "salt required"})
                return
            try:
                updated_int = int(updated)
            except (TypeError, ValueError):
                self._send_json(400, {"error": "updated required"})
                return
            save_vault(email, blob, salt, updated_int)
            self._send_json(200, {"ok": True})
            return

        if path == "/api/password":
            email = auth_email(data.get("token"))
            if email is None:
                self._send_json(401, {"error": "bad or expired token"})
                return
            old = data.get("old_password") or ""
            new = data.get("new_password") or ""
            user = get_user(email)
            if user is None or not check_password(old, user[1]):
                self._send_json(401, {"error": "wrong old password"})
                return
            if len(new) < 8:
                self._send_json(400, {"error": "password too short (min 8)"})
                return
            set_password(email, new)
            self._send_json(200, {"ok": True})
            return

        self._send_json(404, {"error": "not found"})


if __name__ == "__main__":
    db().close()  # create tables on first run
    print(f"Wallet sync server on 0.0.0.0:{PORT} (db: {DB_PATH})")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
