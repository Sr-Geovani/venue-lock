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
from typing import Any

try:
    from aiohttp import WSCloseCode, WSMsgType, web
except ImportError:
    sys.stderr.write("aiohttp não instalado: pip install 'aiohttp>=3.9'\n")
    sys.exit(2)

VERSION = "2.5.2"
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
]


# ----------------------------------------------------------------------------- utils
def fail(cls: type[web.HTTPException], msg: str) -> web.HTTPException:
    return cls(text=json.dumps({"error": msg}), content_type="application/json")


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
        if user["is_admin"]:
            return self.q("SELECT d.*, u.username AS owner FROM devices d JOIN users u ON u.id=d.user_id ORDER BY d.name")
        return self.q("SELECT d.*, u.username AS owner FROM devices d JOIN users u ON u.id=d.user_id "
                      "WHERE d.user_id=? ORDER BY d.name", (user["id"],))

    def update_device(self, did: int, **f: Any) -> None:
        allowed = {"name", "policy", "grace_s", "release_ms", "pin", "egress_ok", "armed",
                   "fw", "ip", "host", "rssi", "boot", "last_seen",
                   "api_token", "open_value", "auto_update", "ota_ver", "ota_at"}
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
                               "api_token", "open_value", "auto_update")}
        v["owner"] = d.get("owner")
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
            if user["is_admin"] or user["id"] == d["user_id"]:
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
            "rel": d["release_ms"], "pin": d["pin"], "egress": d["egress_ok"]}


# ----------------------------------------------------------------------------- auth
def current_user(request: web.Request) -> dict:
    auth = request.headers.get("Authorization", "")
    tok = auth[7:].strip() if auth.startswith("Bearer ") else ""
    user = request.app[STORE].session_user(tok) if tok else None
    if user is None:
        raise fail(web.HTTPUnauthorized, "sessão inválida")
    return user


def owned_device(request: web.Request) -> tuple[dict, dict]:
    user = current_user(request)
    d = request.app[STORE].device(int(request.match_info["id"]))
    if d is None or (not user["is_admin"] and d["user_id"] != user["id"]):
        raise fail(web.HTTPNotFound, "dispositivo não encontrado")
    return user, d


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
    return web.json_response({"username": u["username"], "is_admin": bool(u["is_admin"]), "secret": u["secret"]})


async def h_password(request: web.Request) -> web.Response:
    u = current_user(request)
    b = await body_json(request)
    if not check_pw(str(b.get("old", "")), u["pw_hash"]):
        raise fail(web.HTTPForbidden, "senha atual incorreta")
    request.app[STORE].x("UPDATE users SET pw_hash=? WHERE id=?", (hash_pw(validate_pw(b.get("new"))), u["id"]))
    return web.json_response({"ok": True})


async def h_rotate_secret(request: web.Request) -> web.Response:
    u = current_user(request)
    sec = secrets.token_urlsafe(30)
    request.app[STORE].x("UPDATE users SET secret=? WHERE id=?", (sec, u["id"]))
    hub = request.app[HUB]
    for d in request.app[STORE].q("SELECT id FROM devices WHERE user_id=?", (u["id"],)):
        c = hub.conns.get(d["id"])
        if c:
            await c.ws.close(code=4004, message=b"secret rotacionado")
    LOG.warning("secret rotacionado para %s", u["username"])
    return web.json_response({"secret": sec})


async def h_users(request: web.Request) -> web.Response:
    u = current_user(request)
    if not u["is_admin"]:
        raise fail(web.HTTPForbidden, "apenas administradores")
    st = request.app[STORE]
    if request.method == "GET":
        return web.json_response({"users": st.q(
            "SELECT u.id, u.username, u.is_admin, u.created_at, COUNT(d.id) AS devices FROM users u "
            "LEFT JOIN devices d ON d.user_id=u.id GROUP BY u.id ORDER BY u.username")})
    b = await body_json(request)
    name = str(b.get("username", "")).strip().lower()
    if not USER_RE.match(name):
        raise ValueError("usuário: 3-32 caracteres a-z 0-9 _ . -")
    if st.user_by_name(name):
        raise fail(web.HTTPConflict, "usuário já existe")
    nu = st.create_user(name, validate_pw(b.get("password")), bool(b.get("is_admin")))
    return web.json_response({"id": nu["id"], "username": nu["username"]}, status=201)


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
    st.event(d["id"], "config", "painel", json.dumps({k: v for k, v in f.items() if k != "pin"}, ensure_ascii=False))
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
    u, d = owned_device(request)
    b = await body_json(request)
    a = b.get("a")
    if a not in ACTIONS:
        raise ValueError(f"a deve ser um de {ACTIONS}")
    err = await send_cmd(request.app, d, a, f"app:{u['username']}")
    if err == "offline":
        raise fail(web.HTTPConflict, "dispositivo offline: use o acesso local (mesma rede Wi-Fi)")
    if err == "timeout":
        raise fail(web.HTTPGatewayTimeout, "dispositivo não confirmou o comando")
    if err:
        raise fail(web.HTTPConflict, f"recusado pelo dispositivo: {err}")
    return web.json_response({"ok": True})


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
    if ver_tuple(d["fw"]) > ver_tuple(fw["version"]):
        return f"dispositivo já tem versão mais nova ({d['fw']})"
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
        "SELECT version, md5, size, created_at, published FROM firmware ORDER BY created_at DESC LIMIT 20")})


def store_firmware(st: Store, fwdir: str, data: bytes) -> tuple[str, str]:
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
    _, d = owned_device(request)
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
    if not u["is_admin"]:
        sql += " AND d.user_id=?"
        p.append(u["id"])
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
        st.update_device(c.did, armed=1 if m.get("armed") else 0, last_seen=time.time())
        await hub.push(st, c.did)
    elif t == "ev":
        if m.get("src") == "app":
            return  # o servidor já registrou esse comando (evita linha duplicada no log)
        ago = max(0, min(int(m.get("ago", 0)), 30 * 86400 * 1000))
        st.event(c.did, str(m.get("k", "?"))[:24], f"esp:{str(m.get('src', '?'))[:16]}",
                 str(m.get("d", ""))[:120] or None, ts=time.time() - ago / 1000)
    elif t == "otaerr":
        st.event(c.did, "ota_falha", "esp", str(m.get("e", ""))[:120])
    elif t == "ping":
        st.update_device(c.did, last_seen=time.time(), rssi=int(m.get("rssi", 0)))


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
                     boot=str(hello.get("boot", ""))[:160], armed=1 if hello.get("armed") else 0,
                     last_seen=time.time())
    lcfg = hello.get("lcfg")
    if isinstance(lcfg, dict):
        applied = apply_local_cfg(st, did, lcfg)
        if applied:
            st.event(did, "config", "esp:portal", json.dumps(applied, ensure_ascii=False))
            LOG.info("esp %s/%s: ajustes do portal local aplicados %s", user["username"], uuid, applied)
    st.close_outage(did)
    st.event(did, "online", "esp", f"ip {ip} fw {hello.get('fw', '?')} heap {hello.get('heap', '?')} boot={hello.get('boot', '')}")
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


async def h_health(request: web.Request) -> web.Response:
    return web.json_response({"ok": True, "version": VERSION, "esp_online": len(request.app[HUB].conns)})


OTA_TASK = web.AppKey("ota_task", asyncio.Task)


async def on_startup(app: web.Application) -> None:
    app[OTA_TASK] = asyncio.create_task(ota_loop(app))


async def on_shutdown(app: web.Application) -> None:
    app[OTA_TASK].cancel()
    hub = app[HUB]
    for ws in [c.ws for c in hub.conns.values()] + list(hub.uis):
        with contextlib.suppress(Exception):
            await ws.close(code=WSCloseCode.GOING_AWAY, message=b"servidor reiniciando")


async def on_cleanup(app: web.Application) -> None:
    app[STORE].close()


def build_app(store: Store, fwdir: str) -> web.Application:
    os.makedirs(fwdir, exist_ok=True)
    app = web.Application(middlewares=[errors_mw], client_max_size=MAX_FW_BYTES + 65536)
    app[STORE], app[HUB], app[FAILS], app[FWDIR] = store, Hub(), {}, fwdir
    app.on_startup.append(on_startup)
    app.on_shutdown.append(on_shutdown)
    app.on_cleanup.append(on_cleanup)
    r = app.router
    r.add_get("/", h_index)
    r.add_get("/manifest.json", h_manifest)
    r.add_get("/icon.svg", h_icon)
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
    r.add_get(r"/api/devices/{id:\d+}/events", h_events)
    r.add_get("/api/outages", h_outages)
    r.add_post(r"/api/devices/{id:\d+}/apitoken", h_regen_api_token)
    r.add_post(r"/api/devices/{id:\d+}/ota", h_device_ota)
    r.add_get("/api/firmware", h_fw_list)
    r.add_post("/api/firmware", h_fw_upload)
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
    print(f"firmware {ver} publicado ({len(data)} bytes, md5 {md5}); os ESPs online atualizam em até 1 minuto")
    return 0


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
