#!/usr/bin/env python3
"""
VENUE LOCK - servidor (substitui Blynk / gateway Java).

  GET  /                         PWA (Início, Dispositivos, Conta)
  WS   /ws/esp?u=<usuario>       ESP-01S (auth HMAC com o secret da conta)
  WS   /ws/ui?s=<sessao>         eventos ao vivo do PWA
  POST /api/login                {username, password} -> {token}
  *    /api/...                  Authorization: Bearer <token>

Dependência: aiohttp>=3.9   (pip install aiohttp)
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import hashlib
import hmac
import ipaddress
import itertools
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import unicodedata
import csv
import io
import shutil
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from typing import Any

try:
    from aiohttp import WSCloseCode, WSMsgType, web
except ImportError:
    sys.stderr.write("aiohttp não instalado: pip install 'aiohttp>=3.9'\n")
    sys.exit(2)

VERSION = "3.0.0"
LOG = logging.getLogger("venuelock")

USER_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")
UUID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")
HEX32_RE = re.compile(r"^[0-9a-f]{32}$")
FWVER_RE = re.compile(r"^[0-9A-Za-z._-]{1,20}$")
FW_TAG_RE = re.compile(rb"VLFW:([0-9A-Za-z._-]{1,20}):END")
OTA_RETRY_S = 3600
MAX_FW_BYTES = 1024 * 1024
ACTIONS = ("release", "lock", "unlock", "reboot")
POLICIES = ("release", "hold")
SESSION_TTL = 30 * 86400
CMD_TIMEOUT = 6.0
CMD_IDS = itertools.count(1)
TZ = ZoneInfo(os.environ.get("VENUELOCK_TZ", "America/Sao_Paulo"))
TELEGRAM_API = os.environ.get("VENUELOCK_TELEGRAM_API", "https://api.telegram.org")
ROLES = ("admin", "owner", "operator")
SCHED_ACTIONS = ("block", "unblock", "lock", "unlock")
DEFAULT_ALERTS = {"offline_min": 5, "unlocked_min": 30, "refused": True, "ota_fail": True,
                  "memory": True, "reboot": True, "server": True}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, pw_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0, secret TEXT NOT NULL UNIQUE, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  uuid TEXT NOT NULL, name TEXT NOT NULL, policy TEXT NOT NULL DEFAULT 'release',
  grace_s INTEGER NOT NULL DEFAULT 60, release_ms INTEGER NOT NULL DEFAULT 5000,
  pin TEXT NOT NULL, egress_ok INTEGER NOT NULL DEFAULT 0, armed INTEGER NOT NULL DEFAULT 1,
  fw TEXT, ip TEXT, host TEXT, rssi INTEGER, boot TEXT, created_at REAL NOT NULL, last_seen REAL,
  UNIQUE(user_id, uuid));
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  ts REAL NOT NULL, kind TEXT NOT NULL, source TEXT NOT NULL, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_events ON events(device_id, ts DESC);
CREATE TABLE IF NOT EXISTS outages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  started REAL NOT NULL, ended REAL, reason TEXT);
CREATE INDEX IF NOT EXISTS ix_outages ON outages(device_id, started DESC);
CREATE TABLE IF NOT EXISTS user_devices (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, device_id));
CREATE TABLE IF NOT EXISTS schedules (
  id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE, action TEXT NOT NULL, hhmm TEXT NOT NULL,
  days INTEGER NOT NULL DEFAULT 127, enabled INTEGER NOT NULL DEFAULT 1, last_run TEXT, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS firmware (
  version TEXT PRIMARY KEY, md5 TEXT NOT NULL, size INTEGER NOT NULL, created_at REAL NOT NULL,
  published INTEGER NOT NULL DEFAULT 0);
"""

# colunas adicionadas após a v2.0.0 (migração automática de bancos antigos)
DEVICE_MIGRATIONS = [
    ("api_token", "TEXT"),
    ("open_value", "TEXT NOT NULL DEFAULT '1'"),
    ("auto_update", "INTEGER NOT NULL DEFAULT 1"),
    ("ota_ver", "TEXT"),
    ("ota_at", "REAL"),
    ("blocked", "INTEGER NOT NULL DEFAULT 0"),
    ("heap", "INTEGER"),
    ("heap_min", "INTEGER"),
    ("maxblk", "INTEGER"),
    ("uptime", "INTEGER"),
    ("beta", "INTEGER NOT NULL DEFAULT 0"),
    ("armed_at", "REAL"),
    ("unlock_alerted", "INTEGER NOT NULL DEFAULT 0"),
    ("mem_alerted", "INTEGER NOT NULL DEFAULT 0"),
]
USER_MIGRATIONS = [
    ("role", "TEXT"),
    ("parent_id", "INTEGER"),
    ("telegram_token", "TEXT"),
    ("telegram_chat", "TEXT"),
    ("alert_cfg", "TEXT"),
]
OUTAGE_MIGRATIONS = [("alerted", "INTEGER NOT NULL DEFAULT 0")]
FIRMWARE_MIGRATIONS = [
    ("stage", "TEXT NOT NULL DEFAULT 'todos'"),   # 'teste' = só dispositivos de teste recebem
    ("rollback", "INTEGER NOT NULL DEFAULT 0"),   # 1 = volta de versão autorizada (permite versão menor)
]


# ----------------------------------------------------------------------------- utils
def fail(cls: type[web.HTTPException], msg: str) -> web.HTTPException:
    return cls(text=json.dumps({"error": msg}), content_type="application/json")


def role_of(user: dict) -> str:
    return user.get("role") or ("admin" if user.get("is_admin") else "owner")


def hmac_hex(key: bytes, msg: str) -> str:
    return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()


def device_key(secret: str, uuid: str) -> bytes:
    return hmac.new(secret.encode(), f"dev:{uuid}".encode(), hashlib.sha256).digest()


def hash_pw(pw: str) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${h.hex()}"


def check_pw(pw: str, stored: str) -> bool:
    try:
        _, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1, dklen=32)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(calc.hex(), h)


def new_api_token() -> str:
    return secrets.token_urlsafe(24)  # 32 caracteres, mesmo formato do token Blynk


def host_slug(name: str, uuid: str) -> str:
    """Endereço local do ESP (<slug>.local). Mesma regra do firmware (mdnsName)."""
    t = unicodedata.normalize("NFKD", name or "").encode("ascii", "ignore").decode().lower()
    t = re.sub(r"[^a-z0-9]+", "-", t).strip("-")[:32].strip("-")
    return t or uuid.replace("_", "-")


def new_pin() -> str:
    return f"{secrets.randbelow(10**8):08d}"


def validate_pw(pw: Any) -> str:
    if not isinstance(pw, str) or not 6 <= len(pw) <= 128:
        raise ValueError("senha deve ter entre 6 e 128 caracteres")
    return pw


def setup_logging(verbosity: int, as_json: bool) -> None:
    class J(logging.Formatter):
        def format(self, r):
            d = {"ts": round(r.created, 3), "level": r.levelname, "msg": r.getMessage()}
            if r.exc_info:
                d["exc"] = self.formatException(r.exc_info)
            return json.dumps(d, ensure_ascii=False)

    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(J() if as_json else logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
    logging.basicConfig(level=logging.DEBUG if verbosity > 0 else logging.INFO, handlers=[h], force=True)
    logging.getLogger("aiohttp.access").setLevel(logging.INFO if verbosity > 1 else logging.WARNING)


# ----------------------------------------------------------------------------- storage
class Store:
    def __init__(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.path = os.path.abspath(path)
        self._lock = threading.Lock()
        self._c: sqlite3.Connection | None = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._c.row_factory = sqlite3.Row
        self._c.execute("PRAGMA journal_mode=WAL")
        self._c.execute("PRAGMA foreign_keys=ON")
        self._c.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        cols = {r["name"] for r in self.q("PRAGMA table_info(devices)")}
        for col, ddl in DEVICE_MIGRATIONS:
            if col not in cols:
                self.x(f"ALTER TABLE devices ADD COLUMN {col} {ddl}")
                LOG.info("banco migrado: devices.%s", col)
        for table, migs in (("firmware", FIRMWARE_MIGRATIONS), ("users", USER_MIGRATIONS), ("outages", OUTAGE_MIGRATIONS)):
            tcols = {r["name"] for r in self.q(f"PRAGMA table_info({table})")}
            for col, ddl in migs:
                if col not in tcols:
                    self.x(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
                    LOG.info("banco migrado: %s.%s", table, col)
        self.x("UPDATE users SET role = CASE WHEN is_admin=1 THEN 'admin' ELSE 'owner' END WHERE role IS NULL")
        for r in self.q("SELECT id FROM devices WHERE api_token IS NULL"):
            self.x("UPDATE devices SET api_token=? WHERE id=?", (new_api_token(), r["id"]))
        self.x("CREATE UNIQUE INDEX IF NOT EXISTS ix_api_token ON devices(api_token)")

    def q(self, sql: str, p: tuple = ()) -> list[dict]:
        with self._lock:
            if self._c is None:
                raise RuntimeError("banco fechado")
            return [dict(r) for r in self._c.execute(sql, p).fetchall()]

    def one(self, sql: str, p: tuple = ()) -> dict | None:
        r = self.q(sql, p)
        return r[0] if r else None

    def x(self, sql: str, p: tuple = ()) -> tuple[int, int]:
        with self._lock:
            if self._c is None:
                raise RuntimeError("banco fechado")
            cur = self._c.execute(sql, p)
            return cur.lastrowid or 0, cur.rowcount

    def close(self) -> None:
        with self._lock:
            if self._c is not None:
                self._c.close()
                self._c = None

    # users / sessions
    def create_user(self, username: str, pw: str, is_admin: bool) -> dict:
        uid, _ = self.x("INSERT INTO users(username,pw_hash,is_admin,secret,created_at) VALUES(?,?,?,?,?)",
                        (username, hash_pw(pw), int(is_admin), secrets.token_urlsafe(30), time.time()))
        return self.one("SELECT * FROM users WHERE id=?", (uid,))

    def user_by_name(self, name: str) -> dict | None:
        return self.one("SELECT * FROM users WHERE username=?", (name,))

    def new_session(self, uid: int) -> str:
        tok = secrets.token_urlsafe(32)
        self.x("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)", (tok, uid, time.time() + SESSION_TTL))
        self.x("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
        return tok

    def session_user(self, tok: str) -> dict | None:
        return self.one("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id "
                        "WHERE s.token=? AND s.expires_at>?", (tok, time.time()))

    # devices
    def device(self, did: int) -> dict | None:
        return self.one("SELECT * FROM devices WHERE id=?", (did,))

    def device_by_uuid(self, uid: int, uuid: str) -> dict | None:
        return self.one("SELECT * FROM devices WHERE user_id=? AND uuid=?", (uid, uuid))

    def create_device(self, uid: int, uuid: str, armed: int) -> dict:
        did, _ = self.x("INSERT INTO devices(user_id,uuid,name,pin,armed,created_at,api_token) VALUES(?,?,?,?,?,?,?)",
                        (uid, uuid, uuid, new_pin(), armed, time.time(), new_api_token()))
        return self.device(did)

    def device_by_api_token(self, tok: str) -> dict | None:
        return self.one("SELECT * FROM devices WHERE api_token=?", (tok,))

    def devices_for(self, user: dict) -> list[dict]:
        base = "SELECT d.*, u.username AS owner FROM devices d JOIN users u ON u.id=d.user_id"
        r = role_of(user)
        if r == "admin":
            return self.q(base + " ORDER BY d.name")
        if r == "operator":
            return self.q(base + " JOIN user_devices ud ON ud.device_id=d.id WHERE ud.user_id=? ORDER BY d.name",
                          (user["id"],))
        return self.q(base + " WHERE d.user_id=? ORDER BY d.name", (user["id"],))

    def sees(self, user: dict, d: dict) -> bool:
        r = role_of(user)
        if r == "admin" or d["user_id"] == user["id"]:
            return True
        return r == "operator" and bool(self.one("SELECT 1 FROM user_devices WHERE user_id=? AND device_id=?",
                                                 (user["id"], d["id"])))

    def get_meta(self, key: str, default: str = "") -> str:
        r = self.one("SELECT value FROM meta WHERE key=?", (key,))
        return r["value"] if r else default

    def set_meta(self, key: str, value: str) -> None:
        self.x("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def set_armed(self, did: int, armed: int) -> None:
        """Atualiza o estado trancado/destrancado e marca quando mudou (alerta de 'destrancada há X min')."""
        d = self.device(did)
        if d is None:
            return
        if d["armed"] != armed or d["armed_at"] is None:
            self.update_device(did, armed=armed, armed_at=time.time(), unlock_alerted=0)

    def update_device(self, did: int, **f: Any) -> None:
        allowed = {"name", "policy", "grace_s", "release_ms", "pin", "egress_ok", "armed",
                   "fw", "ip", "host", "rssi", "boot", "last_seen",
                   "api_token", "open_value", "auto_update", "ota_ver", "ota_at", "blocked",
                   "heap", "heap_min", "maxblk", "uptime", "beta",
                   "armed_at", "unlock_alerted", "mem_alerted"}
        if set(f) - allowed:
            raise ValueError(f"campos inválidos: {set(f) - allowed}")
        if f:
            self.x(f"UPDATE devices SET {', '.join(k + '=?' for k in f)} WHERE id=?", (*f.values(), did))

    def event(self, did: int, kind: str, source: str, detail: str | None = None, ts: float | None = None) -> None:
        self.x("INSERT INTO events(device_id,ts,kind,source,detail) VALUES(?,?,?,?,?)",
               (did, ts or time.time(), kind, source, detail))

    def open_outage(self, did: int, reason: str) -> None:
        if not self.one("SELECT id FROM outages WHERE device_id=? AND ended IS NULL", (did,)):
            self.x("INSERT INTO outages(device_id,started,reason) VALUES(?,?,?)", (did, time.time(), reason))

    def close_outage(self, did: int) -> None:
        self.x("UPDATE outages SET ended=? WHERE device_id=? AND ended IS NULL", (time.time(), did))


# ----------------------------------------------------------------------------- live hub
class DevConn:
    def __init__(self, ws: web.WebSocketResponse, did: int, dkey: bytes, cn: str) -> None:
        self.ws, self.did, self.dkey, self.cn = ws, did, dkey, cn
        self.q = 0
        self.pending: dict[int, asyncio.Future] = {}
        self.live: dict[str, Any] = {}
        self.since = time.time()

    async def send_signed(self, payload: dict) -> None:
        self.q += 1
        p = json.dumps({"q": self.q, **payload}, separators=(",", ":"), ensure_ascii=False)
        await self.ws.send_json({"t": "x", "p": p, "s": hmac_hex(self.dkey, f"{self.cn}|{p}")})


class Hub:
    def __init__(self) -> None:
        self.conns: dict[int, DevConn] = {}
        self.uis: dict[web.WebSocketResponse, dict] = {}

    def view(self, d: dict) -> dict:
        v = {k: d[k] for k in ("id", "uuid", "name", "policy", "grace_s", "release_ms", "pin", "egress_ok",
                               "armed", "fw", "ip", "host", "rssi", "boot", "last_seen", "created_at",
                               "api_token", "open_value", "auto_update", "blocked",
                               "heap", "heap_min", "maxblk", "uptime", "beta")}
        v["owner"] = d.get("owner")
        v["host"] = host_slug(d["name"], d["uuid"])  # nome.local acompanha o nome do app
        c = self.conns.get(d["id"])
        v["online"] = c is not None
        v["online_since"] = c.since if c else None
        v["relay"] = c.live.get("relay") if c else None
        v["free"] = c.live.get("free") if c else None
        return v

    async def push(self, store: Store, did: int) -> None:
        d = store.one("SELECT d.*, u.username AS owner FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=?", (did,))
        if d is None:
            return
        msg = {"type": "device", "device": self.view(d)}
        for ws, user in list(self.uis.items()):
            if store.sees(user, d):
                with contextlib.suppress(ConnectionError, RuntimeError):
                    await ws.send_json(msg)

    async def push_removed(self, did: int) -> None:
        for ws in list(self.uis):
            with contextlib.suppress(ConnectionError, RuntimeError):
                await ws.send_json({"type": "removed", "id": did})


STORE = web.AppKey("store", Store)
HUB = web.AppKey("hub", Hub)
FAILS = web.AppKey("fails", dict)
FWDIR = web.AppKey("fwdir", str)


def cfg_payload(d: dict) -> dict:
    return {"k": "cfg", "name": d["name"], "policy": d["policy"], "grace": d["grace_s"],
            "rel": d["release_ms"], "pin": d["pin"], "egress": d["egress_ok"], "blk": d["blocked"]}


# ----------------------------------------------------------------------------- auth
def current_user(request: web.Request) -> dict:
    auth = request.headers.get("Authorization", "")
    tok = auth[7:].strip() if auth.startswith("Bearer ") else ""
    user = request.app[STORE].session_user(tok) if tok else None
    if user is None:
        raise fail(web.HTTPUnauthorized, "sessão inválida")
    return user


def owned_device(request: web.Request, manage: bool = True) -> tuple[dict, dict]:
    """manage=True: só admin/dono (ajustes). manage=False: operador da loja também (comandos e registros)."""
    user = current_user(request)
    st = request.app[STORE]
    d = st.device(int(request.match_info["id"]))
    if d is None or not st.sees(user, d):
        raise fail(web.HTTPNotFound, "dispositivo não encontrado")
    if manage and role_of(user) == "operator":
        raise fail(web.HTTPForbidden, "operador não pode alterar ajustes")
    return user, d


def require_manager(request: web.Request) -> dict:
    u = current_user(request)
    if role_of(u) == "operator":
        raise fail(web.HTTPForbidden, "apenas administrador ou dono da conta")
    return u


async def body_json(request: web.Request) -> dict:
    if not request.can_read_body:
        return {}
    try:
        b = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise fail(web.HTTPBadRequest, "JSON inválido") from None
    if not isinstance(b, dict):
        raise fail(web.HTTPBadRequest, "corpo deve ser objeto JSON")
    return b


def client_ip(request: web.Request) -> str:
    remote = request.remote or ""
    fwd = request.headers.get("X-Forwarded-For", "")
    try:
        ip = ipaddress.ip_address(remote)
        trusted = ip.is_private or ip.is_loopback
    except ValueError:
        trusted = False
    return fwd.split(",")[0].strip() if fwd and trusted else remote


@web.middleware
async def errors_mw(request: web.Request, handler):
    try:
        return await handler(request)
    except web.HTTPException:
        raise
    except ValueError as exc:
        raise fail(web.HTTPBadRequest, str(exc)) from None
    except Exception:
        LOG.exception("erro em %s %s", request.method, request.path)
        raise fail(web.HTTPInternalServerError, "erro interno") from None


# ----------------------------------------------------------------------------- account API
async def h_login(request: web.Request) -> web.Response:
    ip = client_ip(request)
    fails: dict = request.app[FAILS]
    now = time.time()
    fails[ip] = [t for t in fails.get(ip, []) if now - t < 600]
    if len(fails[ip]) >= 10:
        raise fail(web.HTTPTooManyRequests, "muitas tentativas; aguarde 10 minutos")
    b = await body_json(request)
    user = request.app[STORE].user_by_name(str(b.get("username", "")).strip().lower())
    if user is None or not check_pw(str(b.get("password", "")), user["pw_hash"]):
        fails[ip].append(now)
        LOG.warning("login falhou para %r de %s", b.get("username"), ip)
        raise fail(web.HTTPUnauthorized, "usuário ou senha inválidos")
    fails.pop(ip, None)
    return web.json_response({"token": request.app[STORE].new_session(user["id"])})


async def h_logout(request: web.Request) -> web.Response:
    current_user(request)
    request.app[STORE].x("DELETE FROM sessions WHERE token=?", (request.headers["Authorization"][7:].strip(),))
    return web.json_response({"ok": True})


async def h_me(request: web.Request) -> web.Response:
    u = current_user(request)
    r = role_of(u)
    return web.json_response({"username": u["username"], "is_admin": r == "admin", "role": r,
                              "secret": None if r == "operator" else u["secret"]})


async def h_password(request: web.Request) -> web.Response:
    u = current_user(request)
    b = await body_json(request)
    if not check_pw(str(b.get("old", "")), u["pw_hash"]):
        raise fail(web.HTTPForbidden, "senha atual incorreta")
    request.app[STORE].x("UPDATE users SET pw_hash=? WHERE id=?", (hash_pw(validate_pw(b.get("new"))), u["id"]))
    return web.json_response({"ok": True})


async def h_rotate_secret(request: web.Request) -> web.Response:
    u = require_manager(request)
    sec = secrets.token_urlsafe(30)
    request.app[STORE].x("UPDATE users SET secret=? WHERE id=?", (sec, u["id"]))
    hub = request.app[HUB]
    for d in request.app[STORE].q("SELECT id FROM devices WHERE user_id=?", (u["id"],)):
        c = hub.conns.get(d["id"])
        if c:
            await c.ws.close(code=4004, message=b"secret rotacionado")
    LOG.warning("secret rotacionado para %s", u["username"])
    return web.json_response({"secret": sec})


def user_view(st: Store, u: dict) -> dict:
    devs = [r["device_id"] for r in st.q("SELECT device_id FROM user_devices WHERE user_id=?", (u["id"],))]
    return {"id": u["id"], "username": u["username"], "role": role_of(u), "created_at": u["created_at"],
            "parent_id": u.get("parent_id"), "devices": devs}


def manageable_user(request: web.Request, me: dict) -> dict:
    st = request.app[STORE]
    t = st.one("SELECT * FROM users WHERE id=?", (int(request.match_info["uid"]),))
    if t is None or t["id"] == me["id"] or (role_of(me) != "admin" and t.get("parent_id") != me["id"]):
        raise fail(web.HTTPNotFound, "usuário não encontrado")
    return t


def check_device_ids(st: Store, me: dict, ids: Any) -> list[int]:
    if not isinstance(ids, list):
        raise ValueError("devices deve ser uma lista")
    allowed = {d["id"] for d in st.devices_for(me)}
    out = []
    for i in ids:
        if not isinstance(i, int) or i not in allowed:
            raise ValueError(f"dispositivo {i} não pertence à sua conta")
        out.append(i)
    return out


async def h_users(request: web.Request) -> web.Response:
    """Admin vê/cria todos; dono cria operadores (funcionários) só com as portas dele."""
    me = require_manager(request)
    st = request.app[STORE]
    if request.method == "GET":
        rows = st.q("SELECT * FROM users ORDER BY username") if role_of(me) == "admin" else \
            st.q("SELECT * FROM users WHERE parent_id=? ORDER BY username", (me["id"],))
        return web.json_response({"users": [user_view(st, u) for u in rows if u["id"] != me["id"]]})
    b = await body_json(request)
    name = str(b.get("username", "")).strip().lower()
    if not USER_RE.match(name):
        raise ValueError("usuário: 3-32 caracteres a-z 0-9 _ . -")
    if st.user_by_name(name):
        raise fail(web.HTTPConflict, "usuário já existe")
    role = b.get("role", "operator")
    if role not in ROLES or (role != "operator" and role_of(me) != "admin"):
        raise fail(web.HTTPForbidden, "você só pode criar operadores")
    devs = check_device_ids(st, me, b.get("devices", [])) if role == "operator" else []
    nu = st.create_user(name, validate_pw(b.get("password")), role == "admin")
    st.x("UPDATE users SET role=?, parent_id=? WHERE id=?", (role, me["id"] if role == "operator" else None, nu["id"]))
    for d in devs:
        st.x("INSERT OR IGNORE INTO user_devices(user_id,device_id) VALUES(?,?)", (nu["id"], d))
    LOG.info("usuário %s (%s) criado por %s", name, role, me["username"])
    return web.json_response(user_view(st, st.one("SELECT * FROM users WHERE id=?", (nu["id"],))), status=201)


async def h_user_patch(request: web.Request) -> web.Response:
    me = require_manager(request)
    st = request.app[STORE]
    t = manageable_user(request, me)
    b = await body_json(request)
    if "password" in b:
        st.x("UPDATE users SET pw_hash=? WHERE id=?", (hash_pw(validate_pw(b["password"])), t["id"]))
        st.x("DELETE FROM sessions WHERE user_id=?", (t["id"],))
    if "devices" in b:
        devs = check_device_ids(st, me, b["devices"])
        st.x("DELETE FROM user_devices WHERE user_id=?", (t["id"],))
        for d in devs:
            st.x("INSERT OR IGNORE INTO user_devices(user_id,device_id) VALUES(?,?)", (t["id"], d))
    return web.json_response(user_view(st, st.one("SELECT * FROM users WHERE id=?", (t["id"],))))


async def h_user_delete(request: web.Request) -> web.Response:
    me = require_manager(request)
    st = request.app[STORE]
    t = manageable_user(request, me)
    if st.one("SELECT 1 FROM devices WHERE user_id=? LIMIT 1", (t["id"],)):
        raise fail(web.HTTPConflict, "este usuário é dono de dispositivos: remova-os antes")
    st.x("DELETE FROM users WHERE id=?", (t["id"],))
    return web.json_response({"deleted": t["id"]})


# ----------------------------------------------------------------------------- device API
async def h_devices(request: web.Request) -> web.Response:
    u = current_user(request)
    hub = request.app[HUB]
    return web.json_response({"devices": [hub.view(d) for d in request.app[STORE].devices_for(u)]})


async def h_device_patch(request: web.Request) -> web.Response:
    _, d = owned_device(request)
    b = await body_json(request)
    f: dict[str, Any] = {}
    if "name" in b:
        name = str(b["name"]).strip()
        if not 1 <= len(name) <= 32:
            raise ValueError("nome: 1-32 caracteres")
        f["name"] = name
    if "egress_ok" in b:
        f["egress_ok"] = 1 if b["egress_ok"] else 0
    if "auto_update" in b:
        f["auto_update"] = 1 if b["auto_update"] else 0
    if "beta" in b:
        f["beta"] = 1 if b["beta"] else 0
    if "blocked" in b:
        f["blocked"] = 1 if b["blocked"] else 0
    if "open_value" in b:
        if str(b["open_value"]) not in ("0", "1"):
            raise ValueError("open_value deve ser 0 ou 1")
        f["open_value"] = str(b["open_value"])
    if "policy" in b:
        if b["policy"] not in POLICIES:
            raise ValueError(f"policy deve ser {POLICIES}")
        f["policy"] = b["policy"]
    if "grace_s" in b:
        g = int(b["grace_s"])
        if not 10 <= g <= 65535:
            raise ValueError("grace_s: 10 a 65535")
        f["grace_s"] = g
    if "release_ms" in b:
        r = int(b["release_ms"])
        if not 1000 <= r <= 60000:
            raise ValueError("release_ms: 1000 a 60000")
        f["release_ms"] = r
    if "pin" in b:
        pin = str(b["pin"]).strip()
        if not re.fullmatch(r"[0-9A-Za-z]{8,16}", pin):
            raise ValueError("PIN: 8 a 16 letras/números (também é a senha do Wi-Fi local)")
        f["pin"] = pin
    if not f:
        raise ValueError("nada para atualizar")
    egress = f.get("egress_ok", d["egress_ok"])
    if f.get("policy", d["policy"]) == "hold" and not egress:
        raise fail(web.HTTPConflict, "política 'manter trancado offline' exige saída livre por hardware confirmada")
    st, hub = request.app[STORE], request.app[HUB]
    st.update_device(d["id"], **f)
    if "blocked" in f and f["blocked"] != d["blocked"]:
        st.event(d["id"], "bloqueado" if f["blocked"] else "desbloqueado", "painel")
        f_log = {k: v for k, v in f.items() if k not in ("pin", "blocked")}
    else:
        f_log = {k: v for k, v in f.items() if k != "pin"}
    if f_log:
        st.event(d["id"], "config", "painel", json.dumps(f_log, ensure_ascii=False))
    nd = st.device(d["id"])
    c = hub.conns.get(d["id"])
    if c:
        await c.send_signed(cfg_payload(nd))
        if f.get("auto_update"):
            await maybe_ota(request.app, nd)
    await hub.push(st, d["id"])
    return web.json_response({"ok": True, "delivered": c is not None})


async def h_device_delete(request: web.Request) -> web.Response:
    _, d = owned_device(request)
    hub = request.app[HUB]
    c = hub.conns.get(d["id"])
    if c:
        await c.ws.close(code=4005, message=b"removido")
    request.app[STORE].x("DELETE FROM devices WHERE id=?", (d["id"],))
    await hub.push_removed(d["id"])
    return web.json_response({"deleted": d["id"]})


async def send_cmd(app: web.Application, d: dict, a: str, source: str, detail: str = "") -> str:
    """Envia comando assinado e espera o ACK. Retorna '' se ok, senão o motivo (offline/timeout/recusa)."""
    st, hub = app[STORE], app[HUB]
    c = hub.conns.get(d["id"])
    suffix = f" [{detail}]" if detail else ""
    if d.get("blocked") and a in ("release", "unlock"):
        st.event(d["id"], a, source, "recusado: bloqueado" + suffix)
        return "bloqueado"
    if c is None:
        st.event(d["id"], a, source, "recusado: offline" + suffix)
        return "offline"
    cid = next(CMD_IDS)
    fut = asyncio.get_running_loop().create_future()
    c.pending[cid] = fut
    try:
        await c.send_signed({"k": "cmd", "id": cid, "a": a})
        res = await asyncio.wait_for(fut, CMD_TIMEOUT)
    except (asyncio.TimeoutError, ConnectionError, RuntimeError) as exc:
        st.event(d["id"], a, source, f"sem confirmação ({type(exc).__name__})" + suffix)
        return "timeout"
    finally:
        c.pending.pop(cid, None)
    err = "" if res.get("ok") else str(res.get("e") or "erro")
    st.event(d["id"], a, source, ("ok" if not err else f"recusado: {err}") + suffix)
    LOG.info("cmd %s -> %s (%s): %s", a, d["uuid"], source, err or "ok")
    return err


async def h_cmd(request: web.Request) -> web.Response:
    u, d = owned_device(request, manage=False)
    b = await body_json(request)
    a = b.get("a")
    if a not in ACTIONS:
        raise ValueError(f"a deve ser um de {ACTIONS}")
    err = await send_cmd(request.app, d, a, f"app:{u['username']}")
    if err == "offline":
        raise fail(web.HTTPConflict, "dispositivo offline: use o acesso local (mesma rede Wi-Fi)")
    if err == "timeout":
        raise fail(web.HTTPGatewayTimeout, "dispositivo não confirmou o comando")
    if err == "bloqueado":
        raise fail(web.HTTPConflict, "porta bloqueada: desbloqueie para abrir")
    if err:
        raise fail(web.HTTPConflict, f"recusado pelo dispositivo: {err}")
    return web.json_response({"ok": True})


async def set_blocked_many(app: web.Application, devs: list[dict], on: bool, source: str) -> None:
    st, hub = app[STORE], app[HUB]
    val = 1 if on else 0
    for d in devs:
        if d["blocked"] != val:
            st.update_device(d["id"], blocked=val)
            st.event(d["id"], "bloqueado" if val else "desbloqueado", source)
        c = hub.conns.get(d["id"])
        if c:
            await c.send_signed(cfg_payload(st.device(d["id"])))
        await hub.push(st, d["id"])


async def h_bulk(request: web.Request) -> web.Response:
    """Comando geral: trancar/destrancar/liberar todas as portas do usuário de uma vez."""
    u = current_user(request)
    b = await body_json(request)
    a = b.get("a")
    if a not in ("lock", "unlock", "release", "block", "unblock"):
        raise ValueError("a deve ser lock, unlock, release, block ou unblock")
    st, hub = request.app[STORE], request.app[HUB]
    devs = st.devices_for(u)
    if a in ("block", "unblock"):
        await set_blocked_many(request.app, devs, a == "block", f"app:{u['username']} (geral)")
        online = [d["name"] for d in devs if d["id"] in hub.conns]
        LOG.warning("comando geral %s por %s (%d portas)", a, u["username"], len(devs))
        return web.json_response({"ok": len(devs), "total": len(devs),
                                  "offline": [d["name"] for d in devs if d["name"] not in online], "failed": []})
    results = await asyncio.gather(*(send_cmd(request.app, d, a, f"app:{u['username']} (geral)") for d in devs))
    out = [{"id": d["id"], "name": d["name"], "error": e} for d, e in zip(devs, results)]
    ok = sum(1 for r in out if not r["error"])
    LOG.warning("comando geral %s por %s: %d/%d ok", a, u["username"], ok, len(out))
    return web.json_response({"ok": ok, "total": len(out),
                              "offline": [r["name"] for r in out if r["error"] == "offline"],
                              "failed": [r["name"] for r in out if r["error"] and r["error"] != "offline"]})


async def h_regen_api_token(request: web.Request) -> web.Response:
    _, d = owned_device(request)
    st = request.app[STORE]
    st.update_device(d["id"], api_token=new_api_token())
    st.event(d["id"], "token_api", "painel", "token de integração regenerado")
    await request.app[HUB].push(st, d["id"])
    return web.json_response({"ok": True})


# ----------------------------------------------------------------------------- API compatível com Blynk
# O sistema (sistema.venuemarket.com.br) usa os campos "Host Verificação" e "Host Ativação".
# Basta trocar ny3.blynk.cloud pelo domínio do VENUE e o token pelo token de integração.
def blynk_err(msg: str) -> web.Response:
    return web.json_response({"error": {"message": msg}}, status=400)


def blynk_device(request: web.Request) -> dict | None:
    tok = request.query.get("token", "")
    return request.app[STORE].device_by_api_token(tok) if tok else None


async def h_blynk_update(request: web.Request) -> web.Response:
    d = blynk_device(request)
    if d is None:
        LOG.warning("blynk-api update: token inválido de %s", client_ip(request))
        return blynk_err("Invalid token.")
    params = [(k, v) for k, v in request.query.items() if k != "token"]
    raw = "&".join(f"{k}={v}" for k, v in params)[:80] or "sem parametro"
    opens = not params or any(v.strip().lower() in (d["open_value"], "true" if d["open_value"] == "1" else "false")
                              for _, v in params)
    if not opens:
        request.app[STORE].event(d["id"], "ignorado", "sistema", f"{raw} (libera com valor {d['open_value']})")
        return web.Response(text="")
    err = await send_cmd(request.app, d, "release", "sistema", raw)
    if err == "offline":
        return blynk_err("Device is offline.")
    if err == "bloqueado":
        return blynk_err("Device is blocked.")
    if err:
        return blynk_err(f"Device error: {err}")
    return web.Response(text="")


async def h_blynk_get(request: web.Request) -> web.Response:
    d = blynk_device(request)
    if d is None:
        return blynk_err("Invalid token.")
    c = request.app[HUB].conns.get(d["id"])
    if c is None:
        return blynk_err("Device is offline.")
    closed = "0" if d["open_value"] == "1" else "1"
    return web.Response(text=closed if c.live.get("relay") else d["open_value"])


async def h_blynk_connected(request: web.Request) -> web.Response:
    d = blynk_device(request)
    if d is None:
        return blynk_err("Invalid token.")
    return web.Response(text="true" if d["id"] in request.app[HUB].conns else "false")


# ----------------------------------------------------------------------------- firmware OTA
def ver_tuple(v: str | None) -> tuple:
    """'2.4.10' -> (2, 4, 10); partes não numéricas valem 0."""
    out = []
    for part in str(v or "").split("."):
        num = "".join(ch for ch in part if ch.isdigit())
        out.append(int(num) if num else 0)
    return tuple(out)


def published_fw(st: Store) -> dict | None:
    return st.one("SELECT * FROM firmware WHERE published=1")


async def maybe_ota(app: web.Application, d: dict, force: bool = False) -> str:
    """Envia ordem de atualização se o ESP estiver com versão diferente da publicada."""
    st, hub = app[STORE], app[HUB]
    c = hub.conns.get(d["id"])
    fw = published_fw(st)
    if c is None:
        return "offline"
    if fw is None:
        return "nenhum firmware publicado"
    if d["fw"] == fw["version"]:
        return "já atualizado"
    if ver_tuple(d["fw"]) > ver_tuple(fw["version"]) and not fw["rollback"]:
        return f"dispositivo já tem versão mais nova ({d['fw']})"
    if fw["stage"] == "teste" and not d["beta"] and not force:
        return "versão em teste: aguardando 'Liberar para todos'"
    if not force:
        if not d["auto_update"]:
            return "atualização automática desligada"
        if d["ota_ver"] == fw["version"] and d["ota_at"] and time.time() - d["ota_at"] < OTA_RETRY_S:
            return "aguardando nova tentativa"
    await c.send_signed({"k": "ota", "path": f"/fw/{fw['version']}.bin", "md5": fw["md5"], "ver": fw["version"],
                         "size": fw["size"]})
    st.update_device(d["id"], ota_ver=fw["version"], ota_at=time.time())
    st.event(d["id"], "ota_enviado", "servidor", f"{d['fw'] or '?'} -> {fw['version']}")
    LOG.info("ota %s: %s -> %s", d["uuid"], d["fw"], fw["version"])
    return ""


async def h_fw_list(request: web.Request) -> web.Response:
    u = current_user(request)
    if not u["is_admin"]:
        raise fail(web.HTTPForbidden, "apenas administradores")
    return web.json_response({"firmware": request.app[STORE].q(
        "SELECT version, md5, size, created_at, published, stage, rollback FROM firmware ORDER BY created_at DESC LIMIT 20")})


async def push_ota_all(app: web.Application) -> int:
    sent = 0
    for did in list(app[HUB].conns):
        d = app[STORE].device(did)
        if d and await maybe_ota(app, d) == "":
            sent += 1
    return sent


async def h_fw_publish(request: web.Request) -> web.Response:
    """Promove a versão em teste para todos, ou volta para uma versão anterior (rollback)."""
    u = current_user(request)
    if not u["is_admin"]:
        raise fail(web.HTTPForbidden, "apenas administradores")
    ver = request.match_info["ver"]
    st = request.app[STORE]
    fw = st.one("SELECT * FROM firmware WHERE version=?", (ver,))
    if fw is None or not os.path.isfile(os.path.join(request.app[FWDIR], f"{ver}.bin")):
        raise fail(web.HTTPNotFound, "versão não encontrada")
    b = await body_json(request)
    stage = b.get("stage", "todos")
    if stage not in ("teste", "todos"):
        raise ValueError("stage deve ser teste ou todos")
    cur = published_fw(st)
    rollback = 1 if cur and ver_tuple(ver) < ver_tuple(cur["version"]) else 0
    st.x("UPDATE firmware SET stage=?, rollback=? WHERE version=?", (stage, rollback, ver))
    st.x("UPDATE firmware SET published=(version=?)", (ver,))
    LOG.warning("firmware %s publicado (%s%s) por %s", ver, stage, ", VOLTA DE VERSÃO" if rollback else "", u["username"])
    sent = await push_ota_all(request.app)
    return web.json_response({"version": ver, "stage": stage, "rollback": bool(rollback), "sent": sent})


def store_firmware(st: Store, fwdir: str, data: bytes, stage: str | None = None) -> tuple[str, str]:
    """Valida, grava e publica um .bin do VENUE Lock. Retorna (versão, md5)."""
    if not 1024 < len(data) <= MAX_FW_BYTES or data[0] != 0xE9:
        raise ValueError("arquivo não é um firmware ESP8266 (.bin) válido")
    m = FW_TAG_RE.search(data)
    if m is None:
        raise ValueError("firmware sem a marca VLFW: não é o VENUE Lock (exporte o .bin do VENUE_Lock_v2)")
    ver = m.group(1).decode()
    md5 = hashlib.md5(data).hexdigest()
    os.makedirs(fwdir, exist_ok=True)
    path = os.path.join(fwdir, f"{ver}.bin")
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    st.x("INSERT INTO firmware(version,md5,size,created_at,published) VALUES(?,?,?,?,0) "
         "ON CONFLICT(version) DO UPDATE SET md5=excluded.md5, size=excluded.size, created_at=excluded.created_at",
         (ver, md5, len(data), time.time()))
    if stage not in ("teste", "todos"):
        # Com algum dispositivo de teste marcado, a versão nova vai primeiro só para ele
        stage = "teste" if st.one("SELECT id FROM devices WHERE beta=1 LIMIT 1") else "todos"
    st.x("UPDATE firmware SET stage=?, rollback=0 WHERE version=?", (stage, ver))
    st.x("UPDATE firmware SET published=(version=?)", (ver,))
    return ver, md5


async def ota_loop(app: web.Application) -> None:
    """A cada minuto, oferece a versão publicada aos ESPs online que estão desatualizados.
    Cobre firmware publicado pelo terminal (publish-fw) e novas tentativas após falha."""
    while True:
        await asyncio.sleep(60)
        try:
            st = app[STORE]
            for did in list(app[HUB].conns):
                d = st.device(did)
                if d:
                    await maybe_ota(app, d)
        except RuntimeError:
            return
        except Exception:
            LOG.exception("ota_loop")


async def h_fw_upload(request: web.Request) -> web.Response:
    u = current_user(request)
    if not u["is_admin"]:
        raise fail(web.HTTPForbidden, "apenas administradores")
    data = await request.read()
    st = request.app[STORE]
    ver, md5 = store_firmware(st, request.app[FWDIR], data)
    LOG.warning("firmware %s publicado por %s (%d bytes, md5 %s)", ver, u["username"], len(data), md5)
    sent = 0
    for did in list(request.app[HUB].conns):
        d = st.device(did)
        if d and await maybe_ota(request.app, d) == "":
            sent += 1
    return web.json_response({"version": ver, "md5": md5, "size": len(data), "sent": sent})


async def h_fw_file(request: web.Request) -> web.StreamResponse:
    ver = request.match_info["ver"]
    path = os.path.join(request.app[FWDIR], f"{ver}.bin")
    if not FWVER_RE.match(ver) or not os.path.isfile(path):
        raise web.HTTPNotFound()
    # O .bin contém o secret da conta: só entrega a um ESP que prove conhecê-lo.
    user = request.app[STORE].user_by_name(request.query.get("u", "").lower())
    uuid, tok = request.query.get("d", ""), request.query.get("t", "").lower()
    if user is None or not UUID_RE.match(uuid) or not hmac.compare_digest(
            hmac_hex(device_key(user["secret"], uuid), f"fw|{ver}"), tok):
        LOG.warning("download de firmware %s negado para %s", ver, client_ip(request))
        raise web.HTTPNotFound()
    return web.FileResponse(path, headers={"Content-Type": "application/octet-stream"})


async def h_device_ota(request: web.Request) -> web.Response:
    _, d = owned_device(request)
    why = await maybe_ota(request.app, d, force=True)
    if why:
        raise fail(web.HTTPConflict, why)
    return web.json_response({"ok": True})


# Categorias do log (filtro do app)
EVENT_CATS = {
    "acesso": ("release", "lock", "unlock", "ignorado"),
    "conexao": ("online", "offline", "srv_off", "queda_libera", "queda_fim", "ap_emerg", "boot"),
}


def period_args(request: web.Request) -> tuple[float, float, float | None, int]:
    """from/to (epoch, calculados no fuso do celular), before (cursor) e limit."""
    def num(name: str, default: float | None) -> float | None:
        v = request.query.get(name)
        if v in (None, ""):
            return default
        try:
            return float(v)
        except ValueError:
            raise ValueError(f"{name} inválido") from None
    lim = max(1, min(200, int(num("limit", 50))))
    return num("from", 0.0), num("to", 4102444800.0), num("before", None), lim


async def h_events(request: web.Request) -> web.Response:
    _, d = owned_device(request, manage=False)
    t_from, t_to, before, lim = period_args(request)
    sql = "SELECT ts, kind, source, detail FROM events WHERE device_id=? AND ts>=? AND ts<?"
    p: list[Any] = [d["id"], t_from, t_to]
    if before is not None:
        sql += " AND ts<?"
        p.append(before)
    cat = request.query.get("cat", "")
    if cat in EVENT_CATS:
        sql += f" AND kind IN ({','.join('?' * len(EVENT_CATS[cat]))})"
        p += EVENT_CATS[cat]
    elif cat == "sistema":
        kinds = EVENT_CATS["acesso"] + EVENT_CATS["conexao"]
        sql += f" AND kind NOT IN ({','.join('?' * len(kinds))})"
        p += kinds
    sql += " AND source != 'esp:app' ORDER BY ts DESC LIMIT ?"  # 'esp:app' = eco do ESP de um comando já registrado
    p.append(lim + 1)
    rows = request.app[STORE].q(sql, tuple(p))
    return web.json_response({"events": rows[:lim], "has_more": len(rows) > lim})


async def h_outages(request: web.Request) -> web.Response:
    u = current_user(request)
    t_from, t_to, before, lim = period_args(request)
    sql = ("SELECT o.device_id, d.name, o.started, o.ended, o.reason FROM outages o JOIN devices d ON d.id=o.device_id "
           "WHERE o.started>=? AND o.started<?")
    p: list[Any] = [t_from, t_to]
    ids = [d["id"] for d in request.app[STORE].devices_for(u)] or [-1]
    sql += f" AND o.device_id IN ({','.join('?' * len(ids))})"
    p += ids
    if request.query.get("device", "").isdigit():
        sql += " AND o.device_id=?"
        p.append(int(request.query["device"]))
    if before is not None:
        sql += " AND o.started<?"
        p.append(before)
    sql += " ORDER BY o.started DESC LIMIT ?"
    p.append(lim + 1)
    rows = request.app[STORE].q(sql, tuple(p))
    return web.json_response({"outages": rows[:lim], "has_more": len(rows) > lim})


# ----------------------------------------------------------------------------- ESP websocket
async def handle_esp_msg(app: web.Application, c: DevConn, m: dict) -> None:
    st, hub = app[STORE], app[HUB]
    t = m.get("t")
    if t == "ack":
        fut = c.pending.get(m.get("id"))
        if fut and not fut.done():
            fut.set_result(m)
    elif t == "st":
        c.live.update(relay=bool(m.get("relay")), free=bool(m.get("free")))
        st.set_armed(c.did, 1 if m.get("armed") else 0)
        st.update_device(c.did, last_seen=time.time())
        await hub.push(st, c.did)
    elif t == "ev":
        if m.get("src") == "app":
            return  # o servidor já registrou esse comando (evita linha duplicada no log)
        ago = max(0, min(int(m.get("ago", 0)), 30 * 86400 * 1000))
        st.event(c.did, str(m.get("k", "?"))[:24], f"esp:{str(m.get('src', '?'))[:16]}",
                 str(m.get("d", ""))[:120] or None, ts=time.time() - ago / 1000)
        if m.get("k") == "ota_falha" and "sem espaco" in str(m.get("d", "")):
            # Memória gravada com FS:64KB: OTA nunca vai caber. Para de tentar (cada tentativa desconecta).
            st.update_device(c.did, auto_update=0)
            st.event(c.did, "config", "servidor",
                     "atualização automática desligada: regrave por USB com Flash Size 1MB (FS:none)")
            LOG.warning("device %s sem espaço para OTA: atualização automática desligada", c.did)
            await hub.push(st, c.did)
    elif t == "otaerr":
        st.event(c.did, "ota_falha", "esp", str(m.get("e", ""))[:120])
    elif t == "ping":
        f: dict[str, Any] = {"last_seen": time.time(), "rssi": int(m.get("rssi", 0))}
        for key, col in (("heap", "heap"), ("heapmin", "heap_min"), ("maxblk", "maxblk"), ("up", "uptime")):
            if isinstance(m.get(key), int):
                f[col] = m[key]
        st.update_device(c.did, **f)


def apply_local_cfg(st: Store, did: int, lcfg: dict) -> dict:
    """Ajustes feitos no portal do ESP (Configurações avançadas) sobem para o servidor."""
    f: dict[str, Any] = {}
    try:
        if lcfg.get("policy") in POLICIES:
            f["policy"] = lcfg["policy"]
        if "grace" in lcfg and 10 <= int(lcfg["grace"]) <= 65535:
            f["grace_s"] = int(lcfg["grace"])
        if "rel" in lcfg and 1000 <= int(lcfg["rel"]) <= 60000:
            f["release_ms"] = int(lcfg["rel"])
        if "egress" in lcfg:
            f["egress_ok"] = 1 if lcfg["egress"] else 0
    except (TypeError, ValueError):
        return {}
    if f.get("policy") == "hold" and not f.get("egress_ok"):
        f["policy"] = "release"  # nunca aceita manter trancado sem saída livre
    if f:
        st.update_device(did, **f)
    return f


async def ws_esp(request: web.Request) -> web.WebSocketResponse:
    app = request.app
    st, hub = app[STORE], app[HUB]
    user = st.user_by_name(request.query.get("u", "").lower())
    if user is not None and role_of(user) == "operator":
        user = None
    if user is None:
        LOG.warning("esp: usuário desconhecido %r de %s", request.query.get("u"), client_ip(request))
        raise fail(web.HTTPUnauthorized, "usuário desconhecido")
    ws = web.WebSocketResponse(heartbeat=25, max_msg_size=8192)
    await ws.prepare(request)
    n = secrets.token_hex(16)
    await ws.send_json({"t": "auth", "n": n, "v": 1})
    try:
        first = await asyncio.wait_for(ws.receive(), timeout=15)
        hello = json.loads(first.data) if first.type == WSMsgType.TEXT else {}
    except (asyncio.TimeoutError, json.JSONDecodeError):
        hello = {}
    uuid, cn, mac = str(hello.get("uuid", "")), str(hello.get("cn", "")), str(hello.get("m", "")).lower()
    if hello.get("t") != "hello" or not UUID_RE.match(uuid) or not HEX32_RE.match(cn):
        await ws.close(code=4002, message=b"hello invalido")
        return ws
    dkey = device_key(user["secret"], uuid)
    if not hmac.compare_digest(hmac_hex(dkey, f"hello|{n}|{cn}"), mac):
        LOG.warning("esp %s/%s: assinatura inválida de %s (secret errado?)", user["username"], uuid, client_ip(request))
        await ws.close(code=4003, message=b"auth")
        return ws

    d = st.device_by_uuid(user["id"], uuid)
    if d is None:
        d = st.create_device(user["id"], uuid, 1 if hello.get("armed", True) else 0)
        st.event(d["id"], "registrado", "esp", f"conta {user['username']}")
        LOG.info("esp novo registrado: %s/%s", user["username"], uuid)
    did = d["id"]
    c = DevConn(ws, did, dkey, cn)
    old = hub.conns.get(did)
    hub.conns[did] = c
    if old:
        await old.ws.close(code=4000, message=b"substituido")
    await ws.send_json({"t": "ok", "m": hmac_hex(dkey, f"srv|{cn}|{n}"), "now": int(time.time())})
    c.live.update(relay=bool(hello.get("relay")), free=bool(hello.get("free")))
    ip = client_ip(request)
    st.update_device(did, fw=str(hello.get("fw", ""))[:24], ip=str(hello.get("ip", ip))[:45],
                     host=str(hello.get("host", ""))[:40], rssi=int(hello.get("rssi", 0)),
                     boot=str(hello.get("boot", ""))[:160], last_seen=time.time(), mem_alerted=0)
    st.set_armed(did, 1 if hello.get("armed") else 0)
    lcfg = hello.get("lcfg")
    if isinstance(lcfg, dict):
        applied = apply_local_cfg(st, did, lcfg)
        if applied:
            st.event(did, "config", "esp:portal", json.dumps(applied, ensure_ascii=False))
            LOG.info("esp %s/%s: ajustes do portal local aplicados %s", user["username"], uuid, applied)
    st.close_outage(did)
    if isinstance(hello.get("heap"), int):
        st.update_device(did, heap=hello["heap"], heap_min=hello["heap"], uptime=0,
                         maxblk=hello["maxblk"] if isinstance(hello.get("maxblk"), int) else None)
    otafree = hello.get("otafree")
    ota_txt = f" ota {int(otafree) // 1024} KB livres" if isinstance(otafree, int) else ""
    st.event(did, "online", "esp", f"ip {ip} fw {hello.get('fw', '?')} heap {hello.get('heap', '?')}{ota_txt} boot={hello.get('boot', '')}")
    if d["ota_ver"] and d["ota_ver"] == hello.get("fw") and d["fw"] != hello.get("fw"):
        st.event(did, "ota_ok", "esp", f"{d['fw']} -> {hello.get('fw')}")
    LOG.info("esp %s/%s online de %s", user["username"], uuid, ip)
    await c.send_signed(cfg_payload(st.device(did)))
    await maybe_ota(app, st.device(did))
    await hub.push(st, did)
    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    m = json.loads(msg.data)
                except json.JSONDecodeError:
                    continue
                if isinstance(m, dict):
                    await handle_esp_msg(app, c, m)
    finally:
        for fut in c.pending.values():
            if not fut.done():
                fut.set_exception(ConnectionError("desconectado"))
        if hub.conns.get(did) is c:
            del hub.conns[did]
            with contextlib.suppress(RuntimeError):
                if st.device(did):
                    st.update_device(did, last_seen=time.time())
                    st.open_outage(did, f"ws code={ws.close_code}")
                    st.event(did, "offline", "servidor", f"code={ws.close_code}")
                    await hub.push(st, did)
        LOG.info("esp %s/%s offline (code=%s)", user["username"], uuid, ws.close_code)
    return ws


async def ws_ui(request: web.Request) -> web.WebSocketResponse:
    user = request.app[STORE].session_user(request.query.get("s", ""))
    if user is None:
        raise fail(web.HTTPUnauthorized, "sessão inválida")
    ws = web.WebSocketResponse(heartbeat=25)
    await ws.prepare(request)
    hub = request.app[HUB]
    hub.uis[ws] = user
    try:
        await ws.send_json({"type": "snapshot", "devices": [hub.view(d) for d in request.app[STORE].devices_for(user)]})
        async for _ in ws:
            pass
    finally:
        hub.uis.pop(ws, None)
    return ws


# ----------------------------------------------------------------------------- agenda
DAY_NAMES = ("seg", "ter", "qua", "qui", "sex", "sáb", "dom")


def sched_view(st: Store, r: dict) -> dict:
    d = st.device(r["device_id"]) if r["device_id"] else None
    return {**r, "device_name": d["name"] if d else None, "days_list": [i for i in range(7) if r["days"] >> i & 1]}


async def h_schedules(request: web.Request) -> web.Response:
    me = require_manager(request)
    st = request.app[STORE]
    if request.method == "GET":
        rows = st.q("SELECT * FROM schedules ORDER BY hhmm") if role_of(me) == "admin" else \
            st.q("SELECT * FROM schedules WHERE owner_id=? ORDER BY hhmm", (me["id"],))
        return web.json_response({"schedules": [sched_view(st, r) for r in rows], "tz": str(TZ)})
    b = await body_json(request)
    action = b.get("action")
    if action not in SCHED_ACTIONS:
        raise ValueError(f"ação deve ser {SCHED_ACTIONS}")
    hhmm = str(b.get("hhmm", ""))
    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", hhmm):
        raise ValueError("horário no formato HH:MM")
    days = b.get("days", list(range(7)))
    if not isinstance(days, list) or not days or any(not isinstance(x, int) or not 0 <= x <= 6 for x in days):
        raise ValueError("dias: lista de 0 (seg) a 6 (dom)")
    dev = b.get("device_id")
    if dev is not None:
        check_device_ids(st, me, [dev])
    mask = sum(1 << x for x in set(days))
    sid, _ = st.x("INSERT INTO schedules(owner_id,device_id,action,hhmm,days,enabled,created_at) VALUES(?,?,?,?,?,1,?)",
                  (me["id"], dev, action, hhmm, mask, time.time()))
    return web.json_response(sched_view(st, st.one("SELECT * FROM schedules WHERE id=?", (sid,))), status=201)


def own_schedule(request: web.Request, me: dict) -> dict:
    r = request.app[STORE].one("SELECT * FROM schedules WHERE id=?", (int(request.match_info["sid"]),))
    if r is None or (role_of(me) != "admin" and r["owner_id"] != me["id"]):
        raise fail(web.HTTPNotFound, "agendamento não encontrado")
    return r


async def h_schedule_patch(request: web.Request) -> web.Response:
    me = require_manager(request)
    r = own_schedule(request, me)
    b = await body_json(request)
    if "enabled" in b:
        request.app[STORE].x("UPDATE schedules SET enabled=? WHERE id=?", (1 if b["enabled"] else 0, r["id"]))
    return web.json_response({"ok": True})


async def h_schedule_delete(request: web.Request) -> web.Response:
    me = require_manager(request)
    r = own_schedule(request, me)
    request.app[STORE].x("DELETE FROM schedules WHERE id=?", (r["id"],))
    return web.json_response({"deleted": r["id"]})


async def run_schedule(app: web.Application, r: dict) -> None:
    st = app[STORE]
    owner = st.one("SELECT * FROM users WHERE id=?", (r["owner_id"],))
    if owner is None:
        return
    devs = [st.device(r["device_id"])] if r["device_id"] else st.devices_for(owner)
    devs = [d for d in devs if d]
    label = f"agenda {r['hhmm']}"
    if r["action"] in ("block", "unblock"):
        await set_blocked_many(app, devs, r["action"] == "block", label)
    else:
        for d in devs:
            await send_cmd(app, d, r["action"], label)
    LOG.info("agenda %s %s executada em %d porta(s)", r["hhmm"], r["action"], len(devs))


async def schedule_loop(app: web.Application) -> None:
    """Confere a agenda a cada 20 s. Se o servidor estava fora no horário exato, executa em até 10 min."""
    while True:
        try:
            now = datetime.now(TZ)
            today = now.strftime("%Y-%m-%d")
            st = app[STORE]
            for r in st.q("SELECT * FROM schedules WHERE enabled=1 AND (last_run IS NULL OR last_run<>?)", (today,)):
                if not r["days"] >> now.weekday() & 1:
                    continue
                h, m = map(int, r["hhmm"].split(":"))
                at = now.replace(hour=h, minute=m, second=0, microsecond=0)
                if at <= now < at + timedelta(minutes=10):
                    st.x("UPDATE schedules SET last_run=? WHERE id=?", (today, r["id"]))
                    await run_schedule(app, r)
        except RuntimeError:
            return
        except Exception:
            LOG.exception("schedule_loop")
        await asyncio.sleep(20)


# ----------------------------------------------------------------------------- alertas (Telegram)
def alert_cfg(u: dict) -> dict:
    try:
        return {**DEFAULT_ALERTS, **json.loads(u.get("alert_cfg") or "{}")}
    except (TypeError, ValueError):
        return dict(DEFAULT_ALERTS)


def html_esc(t: str) -> str:
    return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


async def telegram_send(app: web.Application, token: str, chat: str, text: str) -> str:
    """Retorna '' se enviou, senão o motivo."""
    try:
        async with app[HTTP].post(f"{TELEGRAM_API}/bot{token}/sendMessage",
                                  json={"chat_id": chat, "text": text, "parse_mode": "HTML",
                                        "disable_web_page_preview": True}) as r:
            if r.status == 200:
                return ""
            d = await r.json(content_type=None)
            return str(d.get("description", f"HTTP {r.status}"))
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


def recipients(st: Store, d: dict | None) -> list[dict]:
    """Quem recebe alerta de um dispositivo: o dono e os administradores com Telegram configurado."""
    rows = st.q("SELECT * FROM users WHERE telegram_token IS NOT NULL AND telegram_token<>'' "
                "AND telegram_chat IS NOT NULL AND telegram_chat<>''")
    out = []
    for u in rows:
        r = role_of(u)
        if r == "admin" or (d is not None and r == "owner" and d["user_id"] == u["id"]):
            out.append(u)
    return out


async def notify(app: web.Application, d: dict | None, key: str, text: str) -> None:
    st = app[STORE]
    for u in recipients(st, d):
        cfg = alert_cfg(u)
        if key in cfg and not cfg[key]:
            continue
        err = await telegram_send(app, u["telegram_token"], u["telegram_chat"], text)
        if err:
            LOG.warning("alerta para %s falhou: %s", u["username"], err)


def fmt_dur(sec: float) -> str:
    sec = int(sec)
    if sec < 3600:
        return f"{sec // 60} min"
    if sec < 86400:
        return f"{sec // 3600} h {sec % 3600 // 60} min"
    return f"{sec // 86400} d {sec % 86400 // 3600} h"


NORMAL_BOOTS = ("Power On", "Software/System restart", "External System", "Deep-Sleep Wake")


async def alert_loop(app: web.Application) -> None:
    await asyncio.sleep(30)
    while True:
        try:
            await alert_tick(app)
        except RuntimeError:
            return
        except Exception:
            LOG.exception("alert_loop")
        await asyncio.sleep(20)


async def alert_tick(app: web.Application) -> None:
    st, hub = app[STORE], app[HUB]
    now = time.time()
    owners = {u["id"]: u for u in st.q("SELECT * FROM users")}

    def threshold(d: dict, key: str) -> float:
        u = owners.get(d["user_id"]) or {}
        return float(alert_cfg(u).get(key) or DEFAULT_ALERTS[key]) * 60

    # 1) porta offline há mais de X min / voltou
    for o in st.q("SELECT o.*, d.name, d.user_id FROM outages o JOIN devices d ON d.id=o.device_id "
                  "WHERE (o.ended IS NULL AND o.alerted=0) OR (o.ended IS NOT NULL AND o.alerted=1)"):
        d = st.device(o["device_id"])
        if d is None:
            continue
        if o["ended"] is None and now - o["started"] >= threshold(d, "offline_min"):
            st.x("UPDATE outages SET alerted=1 WHERE id=?", (o["id"],))
            await notify(app, d, "offline_min", f"🔴 <b>{html_esc(d['name'])}</b> está <b>offline</b> há "
                         f"{fmt_dur(now - o['started'])}.\nNo local: página .local, Wi-Fi VENUE-… ou botão físico.")
        elif o["ended"] is not None and o["alerted"] == 1:
            st.x("UPDATE outages SET alerted=2 WHERE id=?", (o["id"],))
            await notify(app, d, "offline_min", f"🟢 <b>{html_esc(d['name'])}</b> voltou após {fmt_dur(o['ended'] - o['started'])} offline.")
    # 2) destrancada há mais de X min
    for d in st.q("SELECT * FROM devices WHERE armed=0 AND unlock_alerted=0 AND armed_at IS NOT NULL"):
        if d["id"] in hub.conns and now - d["armed_at"] >= threshold(d, "unlocked_min"):
            st.update_device(d["id"], unlock_alerted=1)
            await notify(app, d, "unlocked_min", f"🟡 <b>{html_esc(d['name'])}</b> está <b>destrancada</b> há "
                         f"{fmt_dur(now - d['armed_at'])}.")
    # 3) memória baixa no ESP
    for d in st.q("SELECT * FROM devices WHERE heap_min IS NOT NULL AND heap_min<6000 AND mem_alerted=0"):
        st.update_device(d["id"], mem_alerted=1)
        await notify(app, d, "memory", f"🟠 <b>{html_esc(d['name'])}</b> com memória baixa ({d['heap_min']} bytes). "
                     "Se reiniciar sozinho, avise o suporte.")
    # 4) eventos: abertura recusada, falha de atualização, reinício inesperado
    last = int(st.get_meta("alert_last_event", "0") or 0)
    if last == 0:
        r = st.one("SELECT MAX(id) AS m FROM events")
        st.set_meta("alert_last_event", str(r["m"] or 0))
        return
    rows = st.q("SELECT * FROM events WHERE id>? ORDER BY id LIMIT 200", (last,))
    for e in rows:
        d = st.device(e["device_id"])
        if d is None:
            continue
        det = e["detail"] or ""
        if e["kind"] == "recusado_blq" or det.startswith("recusado: bloqueado"):
            await notify(app, d, "refused", f"🚫 Abertura <b>recusada</b> em <b>{html_esc(d['name'])}</b> (bloqueada). "
                         f"Origem: {html_esc(e['source'])}.")
        elif e["kind"] == "ota_falha":
            await notify(app, d, "ota_fail", f"⚠️ Atualização falhou em <b>{html_esc(d['name'])}</b>: {html_esc(det)}")
        elif e["kind"] == "boot" and det and not any(det.startswith(b) for b in NORMAL_BOOTS):
            await notify(app, d, "reboot", f"⚠️ <b>{html_esc(d['name'])}</b> reiniciou sozinho: {html_esc(det[:120])}")
    if rows:
        st.set_meta("alert_last_event", str(rows[-1]["id"]))
    # 5) saúde do servidor (1 aviso por dia por problema)
    today = datetime.now(TZ).strftime("%Y-%m-%d")
    for prob in server_problems(app):
        k = "srv_alert_" + prob["key"]
        if st.get_meta(k) != today:
            st.set_meta(k, today)
            await notify(app, None, "server", f"🖥️ Servidor VENUE: {html_esc(prob['msg'])}")


async def h_alerts(request: web.Request) -> web.Response:
    me = require_manager(request)
    st = request.app[STORE]
    if request.method == "GET":
        tok = me.get("telegram_token") or ""
        return web.json_response({"telegram_chat": me.get("telegram_chat") or "",
                                  "telegram_token_set": bool(tok), "telegram_token_hint": tok[-4:] if tok else "",
                                  "cfg": alert_cfg(me)})
    b = await body_json(request)
    if "telegram_token" in b and b["telegram_token"] is not None:
        tok = str(b["telegram_token"]).strip()
        if tok and not re.fullmatch(r"\d{5,15}:[A-Za-z0-9_-]{30,50}", tok):
            raise ValueError("token do bot inválido (formato 123456:ABC…)")
        st.x("UPDATE users SET telegram_token=? WHERE id=?", (tok or None, me["id"]))
    if "telegram_chat" in b:
        chat = str(b["telegram_chat"]).strip()
        if chat and not re.fullmatch(r"-?\d{3,20}|@[A-Za-z0-9_]{5,32}", chat):
            raise ValueError("chat id inválido (número, ex.: 123456789 ou -100…)")
        st.x("UPDATE users SET telegram_chat=? WHERE id=?", (chat or None, me["id"]))
    if isinstance(b.get("cfg"), dict):
        cfg = alert_cfg(me)
        for k, v in b["cfg"].items():
            if k in ("offline_min", "unlocked_min"):
                v = int(v)
                if not 1 <= v <= 1440:
                    raise ValueError(f"{k}: 1 a 1440 minutos")
                cfg[k] = v
            elif k in DEFAULT_ALERTS:
                cfg[k] = bool(v)
        st.x("UPDATE users SET alert_cfg=? WHERE id=?", (json.dumps(cfg), me["id"]))
    return web.json_response({"ok": True})


async def h_alerts_test(request: web.Request) -> web.Response:
    me = require_manager(request)
    u = request.app[STORE].one("SELECT * FROM users WHERE id=?", (me["id"],))
    if not u.get("telegram_token") or not u.get("telegram_chat"):
        raise fail(web.HTTPConflict, "configure o token do bot e o chat id")
    err = await telegram_send(request.app, u["telegram_token"], u["telegram_chat"],
                              "✅ VENUE LOCK: alertas configurados. Você vai receber os avisos aqui.")
    if err:
        raise fail(web.HTTPBadGateway, f"Telegram recusou: {err}")
    return web.json_response({"ok": True})


# ----------------------------------------------------------------------------- relatórios
SRC_GROUP = (("sistema", "sistema"), ("app:", "app"), ("esp:botao", "botao"), ("esp:local", "local"),
             ("esp:ap", "local"), ("agenda", "agenda"))


def src_group(src: str) -> str:
    for prefix, g in SRC_GROUP:
        if src.startswith(prefix):
            return g
    return "outro"


async def h_reports(request: web.Request) -> web.Response:
    u = current_user(request)
    st = request.app[STORE]
    t_from, t_to, _, _ = period_args(request)
    now = time.time()
    t_to = min(t_to, now)
    out = []
    for d in st.devices_for(u):
        start = max(t_from, d["created_at"])
        span = max(1.0, t_to - start)
        rel = {"sistema": 0, "app": 0, "botao": 0, "local": 0, "agenda": 0, "outro": 0}
        refused = locks = unlocks = 0
        for e in st.q("SELECT kind, source, detail FROM events WHERE device_id=? AND ts>=? AND ts<? "
                      "AND kind IN ('release','lock','unlock','recusado_blq') AND source<>'esp:app'",
                      (d["id"], start, t_to)):
            det = e["detail"] or ""
            if e["kind"] == "recusado_blq" or det.startswith("recusado"):
                refused += 1
            elif e["kind"] == "release" and not det.startswith("sem confirma"):
                rel[src_group(e["source"])] += 1
            elif e["kind"] == "lock":
                locks += 1
            elif e["kind"] == "unlock":
                unlocks += 1
        off = 0.0
        n_out = 0
        for o in st.q("SELECT started, ended FROM outages WHERE device_id=? AND (ended IS NULL OR ended>?) AND started<?",
                      (d["id"], start, t_to)):
            a, b2 = max(o["started"], start), min(o["ended"] or now, t_to)
            if b2 > a:
                off += b2 - a
                n_out += 1
        out.append({"id": d["id"], "name": d["name"], "releases": rel, "releases_total": sum(rel.values()),
                    "refused": refused, "locks": locks, "unlocks": unlocks, "outages": n_out,
                    "offline_s": round(off), "availability": round(100 * (1 - off / span), 2)})
    return web.json_response({"from": t_from, "to": t_to, "devices": out})


async def h_export_csv(request: web.Request) -> web.Response:
    u = current_user(request)
    st = request.app[STORE]
    t_from, t_to, _, _ = period_args(request)
    devs = {d["id"]: d for d in st.devices_for(u)}
    if request.query.get("device", "").isdigit():
        devs = {k: v for k, v in devs.items() if k == int(request.query["device"])}
    ids = list(devs) or [-1]
    rows = st.q(f"SELECT device_id, ts, kind, source, detail FROM events WHERE device_id IN ({','.join('?' * len(ids))}) "
                "AND ts>=? AND ts<? AND source<>'esp:app' ORDER BY ts", (*ids, t_from, t_to))
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["data", "hora", "dispositivo", "evento", "origem", "detalhe"])
    for r in rows[:100000]:
        dt = datetime.fromtimestamp(r["ts"], TZ)
        w.writerow([dt.strftime("%d/%m/%Y"), dt.strftime("%H:%M:%S"), devs[r["device_id"]]["name"],
                    r["kind"], r["source"], r["detail"] or ""])
    name = f"venue-registros-{datetime.now(TZ).strftime('%Y%m%d-%H%M')}.csv"
    return web.Response(body=("﻿" + buf.getvalue()).encode("utf-8"), content_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})


# ----------------------------------------------------------------------------- saúde / disponibilidade
STARTED_AT = time.time()


def server_status(app: web.Application) -> dict:
    st = app[STORE]
    data_dir = os.path.dirname(st.path)
    du = shutil.disk_usage(data_dir)
    backups = [os.path.join(data_dir, f) for f in os.listdir(data_dir) if f.startswith("backup-") and f.endswith(".db")]
    last_backup = max((os.path.getmtime(b) for b in backups), default=None)
    db_path = st.path
    devs = st.q("SELECT id, heap_min FROM devices")
    online = sum(1 for d in devs if d["id"] in app[HUB].conns)
    heaps = [d["heap_min"] for d in devs if d["heap_min"]]
    return {"version": VERSION, "uptime_s": round(time.time() - STARTED_AT),
            "disk_free_pct": round(100 * du.free / du.total, 1), "disk_free_gb": round(du.free / 2**30, 1),
            "db_mb": round(os.path.getsize(db_path) / 2**20, 2) if os.path.exists(db_path) else 0,
            "last_backup": last_backup, "devices": len(devs), "online": online,
            "lowest_heap": min(heaps) if heaps else None}


def server_problems(app: web.Application) -> list[dict]:
    s = server_status(app)
    out = []
    if s["disk_free_pct"] < 10:
        out.append({"key": "disk", "msg": f"disco quase cheio ({s['disk_free_pct']}% livre)"})
    if s["last_backup"] is None and time.time() - STARTED_AT > 26 * 3600:
        out.append({"key": "backup", "msg": "nenhum backup do banco encontrado"})
    elif s["last_backup"] and time.time() - s["last_backup"] > 26 * 3600:
        out.append({"key": "backup", "msg": f"último backup há {fmt_dur(time.time() - s['last_backup'])}"})
    return out


async def h_status(request: web.Request) -> web.Response:
    require_manager(request)
    return web.json_response({**server_status(request.app), "problems": server_problems(request.app)})


# ----------------------------------------------------------------------------- gravação pelo navegador
FLASH = web.AppKey("flash", dict)


async def h_flash_link(request: web.Request) -> web.Response:
    u = current_user(request)
    if role_of(u) != "admin":
        raise fail(web.HTTPForbidden, "apenas administradores")
    fw = published_fw(request.app[STORE])
    if fw is None:
        raise fail(web.HTTPConflict, "nenhum firmware publicado (rode o install.sh na VPS)")
    k = secrets.token_urlsafe(24)
    links = request.app[FLASH]
    for old in [x for x, v in links.items() if v["exp"] < time.time()]:
        links.pop(old, None)
    links[k] = {"ver": fw["version"], "exp": time.time() + 900}
    LOG.warning("link de gravação do firmware %s gerado por %s", fw["version"], u["username"])
    return web.json_response({"manifest": f"/flash/{k}/manifest.json", "version": fw["version"]})


def flash_entry(request: web.Request) -> dict:
    e = request.app[FLASH].get(request.match_info["k"])
    if e is None or e["exp"] < time.time():
        raise web.HTTPNotFound()
    return e


async def h_flash_manifest(request: web.Request) -> web.Response:
    e = flash_entry(request)
    return web.json_response({"name": "VENUE Lock", "version": e["ver"], "new_install_prompt_erase": True,
                              "builds": [{"chipFamily": "ESP8266", "parts": [{"path": "fw.bin", "offset": 0}]}]})


async def h_flash_bin(request: web.Request) -> web.StreamResponse:
    e = flash_entry(request)
    path = os.path.join(request.app[FWDIR], f"{e['ver']}.bin")
    if not os.path.isfile(path):
        raise web.HTTPNotFound()
    return web.FileResponse(path, headers={"Content-Type": "application/octet-stream", "Cache-Control": "no-store"})


# ----------------------------------------------------------------------------- static / app
PWA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pwa.html")


async def h_index(_: web.Request) -> web.Response:
    with open(PWA_PATH, encoding="utf-8") as f:
        return web.Response(text=f.read(), content_type="text/html", headers={"Cache-Control": "no-cache"})


async def h_manifest(_: web.Request) -> web.Response:
    return web.json_response({"name": "VENUE LOCK", "short_name": "VENUE", "start_url": "/", "display": "standalone",
                              "background_color": "#0b0e13", "theme_color": "#0b0e13",
                              "icons": [{"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml"}]})


async def h_icon(_: web.Request) -> web.Response:
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#0b0e13"/>'
           '<path d="M22 28v-6a10 10 0 0 1 20 0v6" fill="none" stroke="#4fd1b5" stroke-width="5"/>'
           '<rect x="16" y="28" width="32" height="24" rx="5" fill="#4fd1b5"/></svg>')
    return web.Response(text=svg, content_type="image/svg+xml")


# Service worker: o app abre mesmo sem internet e mostra o acesso local das portas
SW_JS = """
const C = "venue-v1";
self.addEventListener("install", e => { e.waitUntil(caches.open(C).then(c => c.addAll(["/", "/manifest.json", "/icon.svg"]))); self.skipWaiting(); });
self.addEventListener("activate", e => { e.waitUntil(caches.keys().then(k => Promise.all(k.filter(x => x !== C).map(x => caches.delete(x))))); self.clients.claim(); });
self.addEventListener("fetch", e => {
  const u = new URL(e.request.url);
  if (e.request.method !== "GET" || u.origin !== location.origin || u.pathname.startsWith("/api/") || u.pathname.startsWith("/ws/")) return;
  e.respondWith(fetch(e.request).then(r => { if (r.ok) { const cp = r.clone(); caches.open(C).then(c => c.put(e.request, cp)); } return r; })
    .catch(() => caches.match(e.request).then(r => r || caches.match("/"))));
});
"""


async def h_sw(_: web.Request) -> web.Response:
    return web.Response(text=SW_JS, content_type="application/javascript", headers={"Cache-Control": "no-cache"})


async def h_health(request: web.Request) -> web.Response:
    probs = server_problems(request.app)
    return web.json_response({"ok": True, "version": VERSION, "esp_online": len(request.app[HUB].conns),
                              "warnings": len(probs)})


OTA_TASK = web.AppKey("ota_task", asyncio.Task)
BG_TASKS = web.AppKey("bg_tasks", list)
HTTP = web.AppKey("http", object)


async def on_startup(app: web.Application) -> None:
    import aiohttp
    app[HTTP] = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15))
    app[OTA_TASK] = asyncio.create_task(ota_loop(app))
    app[BG_TASKS] = [asyncio.create_task(schedule_loop(app)), asyncio.create_task(alert_loop(app))]


async def on_shutdown(app: web.Application) -> None:
    app[OTA_TASK].cancel()
    for t in app[BG_TASKS]:
        t.cancel()
    with contextlib.suppress(Exception):
        await app[HTTP].close()
    hub = app[HUB]
    for ws in [c.ws for c in hub.conns.values()] + list(hub.uis):
        with contextlib.suppress(Exception):
            await ws.close(code=WSCloseCode.GOING_AWAY, message=b"servidor reiniciando")


async def on_cleanup(app: web.Application) -> None:
    app[STORE].close()


def build_app(store: Store, fwdir: str) -> web.Application:
    os.makedirs(fwdir, exist_ok=True)
    app = web.Application(middlewares=[errors_mw], client_max_size=MAX_FW_BYTES + 65536)
    app[STORE], app[HUB], app[FAILS], app[FWDIR], app[FLASH] = store, Hub(), {}, fwdir, {}
    app.on_startup.append(on_startup)
    app.on_shutdown.append(on_shutdown)
    app.on_cleanup.append(on_cleanup)
    r = app.router
    r.add_get("/", h_index)
    r.add_get("/manifest.json", h_manifest)
    r.add_get("/icon.svg", h_icon)
    r.add_get("/sw.js", h_sw)
    r.add_get("/health", h_health)
    r.add_get("/ws/esp", ws_esp)
    r.add_get("/ws/ui", ws_ui)
    r.add_post("/api/login", h_login)
    r.add_post("/api/logout", h_logout)
    r.add_get("/api/me", h_me)
    r.add_post("/api/me/password", h_password)
    r.add_post("/api/me/secret", h_rotate_secret)
    r.add_route("GET", "/api/users", h_users)
    r.add_route("POST", "/api/users", h_users)
    r.add_get("/api/devices", h_devices)
    r.add_patch(r"/api/devices/{id:\d+}", h_device_patch)
    r.add_delete(r"/api/devices/{id:\d+}", h_device_delete)
    r.add_post(r"/api/devices/{id:\d+}/cmd", h_cmd)
    r.add_post("/api/devices/bulk", h_bulk)
    r.add_get(r"/api/devices/{id:\d+}/events", h_events)
    r.add_get("/api/outages", h_outages)
    r.add_route("PATCH", r"/api/users/{uid:\d+}", h_user_patch)
    r.add_route("DELETE", r"/api/users/{uid:\d+}", h_user_delete)
    r.add_route("GET", "/api/schedules", h_schedules)
    r.add_route("POST", "/api/schedules", h_schedules)
    r.add_route("PATCH", r"/api/schedules/{sid:\d+}", h_schedule_patch)
    r.add_route("DELETE", r"/api/schedules/{sid:\d+}", h_schedule_delete)
    r.add_route("GET", "/api/alerts", h_alerts)
    r.add_route("PUT", "/api/alerts", h_alerts)
    r.add_post("/api/alerts/test", h_alerts_test)
    r.add_get("/api/reports", h_reports)
    r.add_get("/api/export.csv", h_export_csv)
    r.add_get("/api/status", h_status)
    r.add_post("/api/firmware/flashlink", h_flash_link)
    r.add_get("/flash/{k}/manifest.json", h_flash_manifest)
    r.add_get("/flash/{k}/fw.bin", h_flash_bin)
    r.add_post(r"/api/devices/{id:\d+}/apitoken", h_regen_api_token)
    r.add_post(r"/api/devices/{id:\d+}/ota", h_device_ota)
    r.add_get("/api/firmware", h_fw_list)
    r.add_post("/api/firmware", h_fw_upload)
    r.add_post("/api/firmware/{ver}/publish", h_fw_publish)
    r.add_get("/fw/{ver}.bin", h_fw_file)
    for path, handler in (("update", h_blynk_update), ("get", h_blynk_get), ("isHardwareConnected", h_blynk_connected)):
        r.add_route("GET", f"/external/api/{path}", handler)
        r.add_route("POST", f"/external/api/{path}", handler)
    return app


# ----------------------------------------------------------------------------- CLI
def cmd_serve(a: argparse.Namespace) -> int:
    st = Store(a.db)
    if not st.one("SELECT id FROM users LIMIT 1"):
        LOG.warning("nenhum usuário: crie com  python3 venuelock.py --db %s create-user <nome> --admin", a.db)
    LOG.info("VENUE LOCK %s em http://%s:%d (db=%s)", VERSION, a.host, a.port, a.db)
    try:
        web.run_app(build_app(st, os.path.join(os.path.dirname(os.path.abspath(a.db)), "fw")), host=a.host, port=a.port, print=None, access_log=logging.getLogger("aiohttp.access"))
    except OSError as exc:
        LOG.error("falha ao abrir %s:%d: %s", a.host, a.port, exc)
        return 1
    return 0


def read_password(given: str | None) -> str:
    if given:
        return validate_pw(given)
    p1 = getpass.getpass("Senha: ")
    if p1 != getpass.getpass("Repita: "):
        raise ValueError("senhas não conferem")
    return validate_pw(p1)


def cmd_create_user(a: argparse.Namespace) -> int:
    name = a.username.strip().lower()
    if not USER_RE.match(name):
        raise ValueError("usuário: 3-32 caracteres a-z 0-9 _ . -")
    st = Store(a.db)
    try:
        if st.user_by_name(name):
            raise ValueError("usuário já existe")
        u = st.create_user(name, read_password(a.password), a.admin)
        print(f"usuário={u['username']} admin={bool(u['is_admin'])} secret={u['secret']}")
    finally:
        st.close()
    return 0


def cmd_reset_password(a: argparse.Namespace) -> int:
    st = Store(a.db)
    try:
        u = st.user_by_name(a.username.lower())
        if not u:
            raise ValueError("usuário não encontrado")
        st.x("UPDATE users SET pw_hash=? WHERE id=?", (hash_pw(read_password(a.password)), u["id"]))
        st.x("DELETE FROM sessions WHERE user_id=?", (u["id"],))
        print("senha redefinida; sessões encerradas")
    finally:
        st.close()
    return 0


def cmd_publish_fw(a: argparse.Namespace) -> int:
    with open(a.path, "rb") as f:
        data = f.read()
    st = Store(a.db)
    try:
        ver, md5 = store_firmware(st, os.path.join(os.path.dirname(os.path.abspath(a.db)), "fw"), data)
    finally:
        st.close()
    st = Store(a.db)
    try:
        stage = st.one("SELECT stage FROM firmware WHERE version=?", (ver,))["stage"]
    finally:
        st.close()
    if stage == "teste":
        print(f"firmware {ver} publicado EM TESTE ({len(data)} bytes, md5 {md5}): só os dispositivos de teste "
              f"atualizam agora. Confira e depois toque em 'Liberar para todos' (app -> Conta -> Firmware).")
    else:
        print(f"firmware {ver} publicado ({len(data)} bytes, md5 {md5}); os ESPs online atualizam em até 1 minuto")
    return 0


def cmd_fw_known(a: argparse.Namespace) -> int:
    st = Store(a.db)
    try:
        return 0 if st.one("SELECT version FROM firmware WHERE version=?", (a.ver,)) else 1
    finally:
        st.close()


def cmd_fw_version(a: argparse.Namespace) -> int:
    st = Store(a.db)
    try:
        fw = published_fw(st)
    finally:
        st.close()
    print(fw["version"] if fw else "")
    return 0


def cmd_list(a: argparse.Namespace) -> int:
    st = Store(a.db)
    try:
        rows = st.q("SELECT d.id, u.username, d.uuid, d.name, d.policy, d.armed, d.ip, d.last_seen, d.pin "
                    "FROM devices d JOIN users u ON u.id=d.user_id ORDER BY u.username, d.name")
    finally:
        st.close()
    print(f"{'ID':>4} {'CONTA':<12} {'UUID':<20} {'NOME':<20} {'QUEDA':<8} {'ARM':>3} {'IP':<15} {'VISTO':<19} PIN")
    for r in rows:
        seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["last_seen"])) if r["last_seen"] else "-"
        print(f"{r['id']:>4} {r['username']:<12} {r['uuid']:<20} {r['name'][:20]:<20} {r['policy']:<8} "
              f"{r['armed']:>3} {r['ip'] or '-':<15} {seen:<19} {r['pin']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="venuelock", description="VENUE LOCK - servidor")
    p.add_argument("--db", default=os.environ.get("VENUELOCK_DB", "venuelock.db"))
    p.add_argument("-v", "--verbose", action="count", default=0)
    p.add_argument("--log-json", action="store_true")
    p.add_argument("--version", action="version", version=VERSION)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--host", default=os.environ.get("VENUELOCK_HOST", "127.0.0.1"))
    s.add_argument("--port", type=int, default=int(os.environ.get("VENUELOCK_PORT", "8080")))
    s.set_defaults(fn=cmd_serve)
    c = sub.add_parser("create-user")
    c.add_argument("username")
    c.add_argument("--admin", action="store_true")
    c.add_argument("--password", help="omita para digitar sem eco")
    c.set_defaults(fn=cmd_create_user)
    r = sub.add_parser("reset-password")
    r.add_argument("username")
    r.add_argument("--password")
    r.set_defaults(fn=cmd_reset_password)
    sub.add_parser("list").set_defaults(fn=cmd_list)
    pf = sub.add_parser("publish-fw", help="publica um .bin do VENUE Lock")
    pf.add_argument("path")
    pf.set_defaults(fn=cmd_publish_fw)
    sub.add_parser("fw-version", help="versão de firmware publicada").set_defaults(fn=cmd_fw_version)
    fk = sub.add_parser("fw-known", help="sai com 0 se a versão já foi compilada/publicada antes")
    fk.add_argument("ver")
    fk.set_defaults(fn=cmd_fw_known)
    a = p.parse_args(argv)
    setup_logging(a.verbose, a.log_json)
    try:
        return a.fn(a)
    except ValueError as exc:
        LOG.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
