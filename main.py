# ============================================================
# ahbpanel 14.5.0
# Railway Ready
# Created By Ahb
# ============================================================
# ------------------------------------------------------------
# Auto-install dependencies (so main.py alone is enough on Railway)
# ------------------------------------------------------------
import importlib.util as _ilu
import subprocess as _sp
import sys as _sys

_REQUIRED = [
    ("fastapi", "fastapi"),
    ("uvicorn", "uvicorn"),
    ("httpx", "httpx"),
    ("aiofiles", "aiofiles"),
]
_missing = [pkg for mod, pkg in _REQUIRED if _ilu.find_spec(mod) is None]
if _missing:
    print("Installing missing packages:", ", ".join(_missing), flush=True)
    _cmd = [_sys.executable, "-m", "pip", "install", "--no-cache-dir", *_missing]
    try:
        _sp.check_call(_cmd)
    except Exception:
        _sp.check_call(_cmd + ["--break-system-packages"])

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import string
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote, parse_qs
import aiofiles
import httpx
import uvicorn
from fastapi import (
    FastAPI,
    Request,
    HTTPException,
    Depends,
)
from fastapi.responses import (
    Response,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
)
from fastapi.middleware.cors import CORSMiddleware

# ============================================================
# APP
# ============================================================

APP_NAME = "ahbpanel"
APP_VERSION = "14.5.0"

SUPPORT_USERNAME = "@ahb_panel"
SUPPORT_URL = "https://t.me/ahbpanel"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger(APP_NAME)

# ============================================================
# TIMEZONE
# ============================================================

try:
    from zoneinfo import ZoneInfo

    IRAN_TZ = ZoneInfo("Asia/Tehran")

except Exception:
    IRAN_TZ = None


# ============================================================
# RAILWAY
# ============================================================

PORT = int(
    os.environ.get(
        "PORT",
        "8000",
    )
)

DATA_DIR = Path(
    os.environ.get(
        "RAILWAY_VOLUME_MOUNT_PATH",
        os.environ.get(
            "DATA_DIR",
            "./data",
        ),
    )
)

DATA_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

DATA_FILE = DATA_DIR / "pixonpanel_state.json"
TG_FILE = DATA_DIR / "telegram_settings.json"

SECRET_FILE = DATA_DIR / "pixonpanel_secret.key"


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    docs_url=None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# LOCKS
# ============================================================

SAVE_LOCK = asyncio.Lock()
LINKS_LOCK = asyncio.Lock()
SUBS_LOCK = asyncio.Lock()
SESSIONS_LOCK = asyncio.Lock()


# ============================================================
# SECRET
# ============================================================

def load_or_create_secret() -> str:
    env_secret = os.environ.get("SECRET_KEY")

    if env_secret:
        return env_secret

    try:
        if SECRET_FILE.exists():
            existing = (
                SECRET_FILE
                .read_text(
                    encoding="utf-8"
                )
                .strip()
            )

            if existing:
                return existing

        generated = secrets.token_urlsafe(48)

        SECRET_FILE.write_text(
            generated,
            encoding="utf-8",
        )

        return generated

    except Exception as exc:
        logger.warning(
            "Could not persist SECRET_KEY: %s",
            exc,
        )

        return secrets.token_urlsafe(48)


SECRET_KEY = load_or_create_secret()


# ============================================================
# CONFIG
# ============================================================

CONFIG = {
    "port": PORT,
    "secret": SECRET_KEY,
    "host": os.environ.get(
        "RAILWAY_PUBLIC_DOMAIN",
        "localhost",
    ),
}


# ============================================================
# STATE
# ============================================================

LINKS: dict = {}
SUBS: dict = {}
SESSIONS: dict = {}
connections: dict = {}
CATEGORIES: dict = {}

stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}

error_logs = deque(maxlen=100)
activity_logs = deque(maxlen=250)

hourly_traffic = defaultdict(int)

http_client: httpx.AsyncClient | None = None


# ============================================================
# PROTOCOL
# ============================================================

PROTOCOLS = (
    "vless-ws",
    "xhttp-packet-up",
    "xhttp-stream-up",
    "xhttp-stream-one",
    "vmess-ws",
    "trojan-ws",
    "shadowsocks",
    "socks5",
    "http",
    "hysteria2",
    "tuic",
    "wireguard",
    "highspeed-demo",
    "gaming-lite-demo",
)

PROTOCOL_LABELS = {
    "vless-ws": "VLESS WebSocket ⭐",
    "xhttp-packet-up": "XHTTP Packet Up",
    "xhttp-stream-up": "XHTTP Stream Up",
    "xhttp-stream-one": "XHTTP Stream One",
    "vmess-ws": "VMess WebSocket",
    "trojan-ws": "Trojan WebSocket",
    "shadowsocks": "Shadowsocks",
    "socks5": "SOCKS5",
    "http": "HTTP Proxy",
    "hysteria2": "Hysteria 2",
    "tuic": "TUIC",
    "wireguard": "WireGuard",
    "highspeed-demo": "HighSpeed Upload/Download (دمو)",
    "gaming-lite-demo": "Gaming Lite (دمو)",
}

PROTOCOL_ALIASES = {
    "vmess": "vmess-ws", "trojan": "trojan-ws", "ss": "shadowsocks",
    "socks": "socks5", "hy2": "hysteria2", "hysteria": "hysteria2",
}

DEFAULT_PROTOCOL = "vless-ws"

FINGERPRINTS = (
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
)

DEFAULT_FINGERPRINT = "chrome"

DEFAULT_ALPN_BY_PROTOCOL = {
    "vless-ws": "http/1.1",
    "xhttp-packet-up": "h2,http/1.1",
    "xhttp-stream-up": "h2,http/1.1",
    "xhttp-stream-one": "h2,http/1.1",
}

DEFAULT_PORT = 443
MIN_PORT = 1
MAX_PORT = 65535

DEFAULT_SPEED_LIMIT = 0


def normalize_protocol(protocol: str | None) -> str:
    value = str(protocol or DEFAULT_PROTOCOL).strip().lower()
    value = PROTOCOL_ALIASES.get(value, value)
    return value if value in PROTOCOLS else DEFAULT_PROTOCOL


# ============================================================
# LOGGING
# ============================================================

def log_activity(
    kind: str,
    message: str,
    level: str = "info",
):
    activity_logs.append(
        {
            "kind": kind,
            "level": level,
            "message": message,
            "time": datetime.now().isoformat(),
        }
    )


# ============================================================
# HELPERS
# ============================================================

def escape_html(value) -> str:
    return (
        str(
            value
            if value is not None
            else ""
        )
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#039;")
    )


def safe_int(
    value,
    default=0,
    minimum=0,
    maximum=None,
):
    try:
        number = int(value)
    except Exception:
        number = default

    if number < minimum:
        number = minimum

    if maximum is not None and number > maximum:
        number = maximum

    return number


def safe_float(
    value,
    default=0.0,
    minimum=0.0,
):
    try:
        number = float(value)
    except Exception:
        number = default

    return max(
        minimum,
        number,
    )


def generate_uuid():
    value = secrets.token_hex(16)

    return (
        f"{value[:8]}-"
        f"{value[8:12]}-"
        f"{value[12:16]}-"
        f"{value[16:20]}-"
        f"{value[20:32]}"
    )


def random_config_name(existing=None):
    existing = existing or set()
    alphabet = string.ascii_lowercase + string.digits
    for _ in range(80):
        length = secrets.randbelow(6) + 8
        name = "".join(secrets.choice(alphabet) for _ in range(length))
        if name not in existing and name and not name[0].isdigit():
            return name
    return secrets.token_hex(6)

def sanitize_config_name(name: str) -> str:
    if not name:
        return random_config_name()
    cleaned = "".join(ch for ch in str(name) if ch.isascii() and ch.isalnum())
    if not cleaned or cleaned[0].isdigit():
        cleaned = ("a" + cleaned) if cleaned else random_config_name()
    return cleaned[:40]

def auto_config_name() -> str:
    return random_config_name()


def now_ir():
    if IRAN_TZ:
        return datetime.now(IRAN_TZ)

    return datetime.now()


def uptime():
    seconds = int(
        time.time()
        - stats["start_time"]
    )

    h = seconds // 3600

    m = (
        seconds
        % 3600
    ) // 60

    s = (
        seconds
        % 60
    )

    return (
        f"{h:02d}:"
        f"{m:02d}:"
        f"{s:02d}"
    )


def fmt_bytes(value: int):
    value = int(
        value or 0
    )

    if value < 1024:
        return f"{value} B"

    if value < 1024 ** 2:
        return (
            f"{value / 1024:.1f} KB"
        )

    if value < 1024 ** 3:
        return (
            f"{value / 1024 ** 2:.2f} MB"
        )

    return (
        f"{value / 1024 ** 3:.2f} GB"
    )


def parse_size_to_bytes(
    value: float,
    unit: str,
):
    if value <= 0:
        return 0

    unit = (
        unit
        or "GB"
    ).upper()

    if unit == "TB":
        return int(
            value
            * 1024 ** 4
        )

    if unit == "GB":
        return int(
            value
            * 1024 ** 3
        )

    if unit == "MB":
        return int(
            value
            * 1024 ** 2
        )

    if unit == "KB":
        return int(
            value
            * 1024
        )

    return int(value)


def parse_speed_to_bytes(
    value: float,
    unit: str,
):
    if value <= 0:
        return 0

    unit = (
        unit
        or "MBIT"
    ).upper()

    if unit == "MBIT":
        return int(
            value
            * 1024
            * 1024
            / 8
        )

    if unit == "KB":
        return int(
            value * 1024
        )

    if unit == "MB":
        return int(
            value
            * 1024
            * 1024
        )

    return int(value)


def is_link_expired(
    link: dict,
):
    expiry = link.get(
        "expires_at"
    )

    if not expiry:
        return False

    try:
        return (
            datetime.now()
            > datetime.fromisoformat(
                expiry
            )
        )

    except Exception:
        return False


def is_link_allowed(
    link: dict | None,
):
    if link is None:
        return False

    if not link.get(
        "active",
        True,
    ):
        return False

    if is_link_expired(link):
        return False

    limit = int(
        link.get(
            "limit_bytes",
            0,
        )
        or 0
    )

    used = int(
        link.get(
            "used_bytes",
            0,
        )
        or 0
    )

    if (
        limit > 0
        and used >= limit
    ):
        return False

    return True


def unique_ips_for_uuid(
    uuid: str,
):
    return {
        connection.get("ip")
        for connection in connections.values()
        if connection.get("uuid") == uuid
        and connection.get("ip")
    }


def client_ip(
    request: Request,
):
    forwarded = request.headers.get(
        "x-forwarded-for"
    )

    if forwarded:
        return (
            forwarded
            .split(",")[0]
            .strip()
        )

    real = request.headers.get(
        "x-real-ip"
    )

    if real:
        return real.strip()

    if request.client:
        return request.client.host

    return "unknown"


def is_ip_allowed(
    link: dict | None,
    uuid: str,
    ip: str,
):
    if link is None:
        return False

    limit = int(
        link.get(
            "ip_limit",
            0,
        )
        or 0
    )

    if limit <= 0:
        return True

    ips = unique_ips_for_uuid(uuid)

    if ip in ips:
        return True

    return len(ips) < limit


def get_host(
    request: Request | None = None,
) -> str:

    if request is not None:
        forwarded = request.headers.get(
            "x-forwarded-host"
        )

        normal = request.headers.get(
            "host"
        )

        host = (
            forwarded
            or normal
        )

        if host:
            host = host.split(":")[0].strip()

            CONFIG["host"] = host

            return host

    railway_domain = os.environ.get(
        "RAILWAY_PUBLIC_DOMAIN"
    )

    if railway_domain:
        return railway_domain

    return CONFIG["host"]


# ============================================================
# PASSWORD
# ============================================================

def hash_password(
    password: str,
) -> str:

    payload = (
        password
        + SECRET_KEY
    ).encode("utf-8")

    return hashlib.sha256(
        payload
    ).hexdigest()


# No default password — first-run setup required unless ADMIN_PASSWORD env is set
_env_pw = os.environ.get("ADMIN_PASSWORD", "").strip()
AUTH = {
    "password_hash": hash_password(_env_pw) if _env_pw else "",
    "password_configured": bool(_env_pw),
}

# Sub-admin accounts (panel operators with granular permissions)
ADMIN_ACCOUNTS: dict = {}
# session_token -> {"role": "owner"|"admin", "admin_id": str|None, "username": str}
SESSION_META: dict = {}

ALL_PERMS = (
    "dash", "configs", "create", "stats", "logs",
    "settings", "support", "telegram", "news", "admins",
)
DEFAULT_PERMS = {p: True for p in ALL_PERMS}


def default_admin_record(username: str, password: str, **kwargs) -> dict:
    return {
        "id": secrets.token_hex(8),
        "username": username.strip().lower(),
        "password_hash": hash_password(password),
        "label": kwargs.get("label") or username,
        "limit_bytes": int(kwargs.get("limit_bytes") or 0),
        "used_bytes": 0,
        "expires_at": kwargs.get("expires_at"),
        "active": True,
        "blocked": False,
        "permissions": {**DEFAULT_PERMS, **(kwargs.get("permissions") or {})},
        "created_at": datetime.now().isoformat(),
    }


def find_admin_by_username(username: str):
    u = (username or "").strip().lower()
    for aid, a in ADMIN_ACCOUNTS.items():
        if a.get("username") == u:
            return aid, a
    return None, None


def admin_is_valid(admin: dict) -> bool:
    if not admin or admin.get("blocked") or not admin.get("active", True):
        return False
    exp = admin.get("expires_at")
    if exp:
        try:
            if datetime.now() > datetime.fromisoformat(str(exp)):
                return False
        except Exception:
            pass
    limit = int(admin.get("limit_bytes") or 0)
    used = int(admin.get("used_bytes") or 0)
    if limit > 0 and used >= limit:
        return False
    return True



# ============================================================
# LOGIN BRUTE-FORCE PROTECTION
# ============================================================
# Maximum failed login attempts per IP inside the rolling window.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_LOCKOUT_SECONDS = 30 * 60  # 30 minutes lockout
LOGIN_MIN_PASSWORD_LENGTH = 6

LOGIN_FAILURES = defaultdict(deque)
LOGIN_LOCKED_UNTIL = {}


def _cleanup_login_state(ip: str, now: float | None = None):
    now = now if now is not None else time.time()

    locked_until = LOGIN_LOCKED_UNTIL.get(ip, 0)
    if locked_until and locked_until <= now:
        LOGIN_LOCKED_UNTIL.pop(ip, None)

    failures = LOGIN_FAILURES.get(ip)
    if not failures:
        return

    cutoff = now - LOGIN_WINDOW_SECONDS
    while failures and failures[0] <= cutoff:
        failures.popleft()

    if not failures:
        LOGIN_FAILURES.pop(ip, None)


def login_is_blocked(ip: str):
    now = time.time()
    _cleanup_login_state(ip, now)

    locked_until = LOGIN_LOCKED_UNTIL.get(ip, 0)
    if locked_until > now:
        return True, max(1, int(locked_until - now))

    return False, 0


def register_login_failure(ip: str):
    now = time.time()
    _cleanup_login_state(ip, now)

    failures = LOGIN_FAILURES.setdefault(ip, deque())
    failures.append(now)

    if len(failures) >= LOGIN_MAX_ATTEMPTS:
        LOGIN_LOCKED_UNTIL[ip] = now + LOGIN_LOCKOUT_SECONDS
        failures.clear()
        log_activity(
            "auth",
            f"IP به دلیل تلاش‌های متعدد ورود ناموفق به مدت {LOGIN_LOCKOUT_SECONDS // 60} دقیقه مسدود شد: {ip}",
            "err",
        )
        return True, LOGIN_LOCKOUT_SECONDS

    return False, max(0, LOGIN_MAX_ATTEMPTS - len(failures))


def clear_login_failures(ip: str):
    LOGIN_FAILURES.pop(ip, None)
    LOGIN_LOCKED_UNTIL.pop(ip, None)


# ============================================================
# SESSION
# ============================================================

SESSION_COOKIE = "pixonpanel_session"

SESSION_TTL = (
    60
    * 60
    * 24
    * 365
)


async def create_session(meta: dict | None = None) -> str:

    token = secrets.token_urlsafe(48)

    async with SESSIONS_LOCK:
        SESSIONS[token] = (
            time.time()
            + SESSION_TTL
        )
        SESSION_META[token] = meta or {"role": "owner", "admin_id": None, "username": "owner"}

    return token


async def is_valid_session(
    token: str | None,
) -> bool:

    if not token:
        return False

    async with SESSIONS_LOCK:

        expiry = SESSIONS.get(token)

        if expiry is None:
            return False

        if expiry < time.time():

            SESSIONS.pop(
                token,
                None,
            )

            return False

        return True


async def destroy_session(
    token: str | None,
):
    if not token:
        return

    async with SESSIONS_LOCK:
        SESSIONS.pop(
            token,
            None,
        )
        SESSION_META.pop(token, None)


def get_session_meta(token: str | None) -> dict:
    if not token:
        return {"role": "owner", "admin_id": None, "username": "owner", "permissions": {p: True for p in ALL_PERMS}}
    meta = dict(SESSION_META.get(token) or {"role": "owner", "admin_id": None, "username": "owner"})
    if meta.get("role") == "owner":
        meta["permissions"] = {p: True for p in ALL_PERMS}
    else:
        aid = meta.get("admin_id")
        admin = ADMIN_ACCOUNTS.get(aid or "") or {}
        meta["permissions"] = {p: bool((admin.get("permissions") or {}).get(p, False)) for p in ALL_PERMS}
        meta["blocked"] = bool(admin.get("blocked"))
    return meta


def require_perm(perm: str):
    async def _dep(request: Request, token=Depends(require_auth)):
        meta = get_session_meta(token)
        if meta.get("role") == "owner":
            return token
        if not (meta.get("permissions") or {}).get(perm):
            raise HTTPException(status_code=403, detail="دسترسی به این بخش مجاز نیست")
        return token
    return _dep


async def require_auth(
    request: Request,
):
    token = request.cookies.get(
        SESSION_COOKIE
    )

    if not await is_valid_session(
        token
    ):
        raise HTTPException(
            status_code=401,
            detail="unauthorized",
        )

    meta = get_session_meta(token)
    if meta.get("role") == "admin":
        aid = meta.get("admin_id")
        admin = ADMIN_ACCOUNTS.get(aid or "")
        if not admin_is_valid(admin or {}):
            await destroy_session(token)
            raise HTTPException(status_code=401, detail="حساب منقضی یا مسدود شده است")

    return token


def set_auth_cookie(
    response,
    request: Request,
    token: str,
):
    forwarded_proto = (
        request.headers
        .get(
            "x-forwarded-proto",
            "",
        )
        .lower()
    )

    is_https = (
        forwarded_proto == "https"
        or request.url.scheme == "https"
    )

    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        path="/",
        secure=is_https,
    )


# ============================================================
# VLESS LINK GENERATION
# ============================================================

def generate_vless_link(
    uuid: str, host: str, remark: str = "PXPanel",
    protocol: str = DEFAULT_PROTOCOL, fingerprint: str | None = None,
    alpn: str | None = None, port: int | None = None,
):
    protocol = normalize_protocol(protocol)
    fp = (fingerprint or DEFAULT_FINGERPRINT).strip().lower()
    if fp not in FINGERPRINTS: fp = DEFAULT_FINGERPRINT
    port_value = safe_int(port, DEFAULT_PORT, MIN_PORT, MAX_PORT)
    alpn_value = (alpn or DEFAULT_ALPN_BY_PROTOCOL.get(protocol, "http/1.1")).strip()
    label = quote(str(remark or "PXPanel"), safe="")
    if protocol == "vless-ws":
        q = {"encryption":"none","security":"tls","type":"ws","host":host,"path":f"/ws/{uuid}","sni":host,"fp":fp,"alpn":alpn_value}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/') }" for k,v in q.items()) + "#" + label
    if protocol.startswith("xhttp-"):
        mode = protocol.replace("xhttp-", "")
        q = {"encryption":"none","security":"tls","type":"xhttp","mode":mode,"host":host,"path":f"/xhttp-siz10/{mode}/{uuid}","sni":host,"fp":fp,"alpn":alpn_value}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/') }" for k,v in q.items()) + "#" + label
    if protocol == "vmess-ws":
        raw = {"v":"2","ps":remark,"add":host,"port":port_value,"id":uuid,"aid":0,"scy":"auto","net":"ws","type":"none","host":host,"path":f"/ws/{uuid}","tls":"tls","sni":host,"fp":fp}
        return "vmess://" + base64.b64encode(json.dumps(raw,separators=(",",":"),ensure_ascii=False).encode()).decode()
    if protocol == "trojan-ws":
        return f"trojan://{uuid}@{host}:{port_value}?security=tls&type=ws&host={quote(host)}&path={quote('/ws/'+uuid)}&sni={quote(host)}#{label}"
    if protocol == "shadowsocks":
        method = os.getenv("SS_METHOD", "aes-256-gcm")
        userinfo = base64.urlsafe_b64encode(f"{method}:{uuid}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{host}:{port_value}#{label}"
    if protocol == "socks5": return f"socks5://{uuid}:{uuid}@{host}:{port_value}#{label}"
    if protocol == "http": return f"http://{uuid}:{uuid}@{host}:{port_value}#{label}"
    if protocol == "hysteria2": return f"hysteria2://{uuid}@{host}:{port_value}/?sni={quote(host)}&insecure=0#{label}"
    if protocol == "tuic": return f"tuic://{uuid}:{uuid}@{host}:{port_value}?sni={quote(host)}&alpn=h3#{label}"
    if protocol == "wireguard": return f"wireguard://{uuid}@{host}:{port_value}?publicKey={uuid}#{label}"
    if protocol == "highspeed-demo":
        q = {"encryption":"none","security":"tls","type":"xhttp","mode":"stream-up","host":host,"path":f"/xhttp-siz10/stream-up/{uuid}","sni":host,"fp":fp,"alpn":"h2,http/1.1"}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/')}" for k,v in q.items()) + "#" + label
    if protocol == "gaming-lite-demo":
        return f"hysteria2://{uuid}@{host}:{port_value}/?sni={quote(host)}&insecure=0&obfs=salamander#{label}"
    return f"vless://{uuid}@{host}:{port_value}"

def vless_link_for_link(
    link: dict,
    uid: str,
    host: str,
):
    return generate_vless_link(
        uid,
        host,
        remark=str(link.get("label") or "Config"),
        protocol=link.get(
            "protocol",
            DEFAULT_PROTOCOL,
        ),
        fingerprint=link.get(
            "fingerprint",
            DEFAULT_FINGERPRINT,
        ),
        alpn=link.get(
            "alpn"
        ),
        port=link.get(
            "port",
            DEFAULT_PORT,
        ),
    )


def get_link_info(
    link: dict,
    uid: str,
    host: str,
):
    connected_count = len(unique_ips_for_uuid(uid))
    is_active = is_link_allowed(link)
    limit_b = int(link.get("limit_bytes", 0) or 0)
    used_b = int(link.get("used_bytes", 0) or 0)
    is_expired = is_link_expired(link) or (limit_b > 0 and used_b >= limit_b)
    if not is_active or is_expired:
        status_color = "red"
    elif connected_count > 0:
        status_color = "green"
    else:
        status_color = "gray"
    clean_ips = link.get("clean_ips") or []
    cfg_count = int(link.get("config_count") or 1)
    show_vless = len(clean_ips) <= 1 and cfg_count <= 1
    cat = CATEGORIES.get(str(link.get("category_id") or "0")) or {}
    return {
        "uuid": uid,
        "name": link.get("label", ""),
        "label": link.get("label", ""),
        "protocol": link.get("protocol", DEFAULT_PROTOCOL),
        "active": is_active,
        "used_bytes": used_b,
        "limit_bytes": limit_b,
        "expires_at": link.get("expires_at"),
        "ip_limit": int(link.get("ip_limit", 0) or 0),
        "speed_limit_bytes": int(link.get("speed_limit_bytes", 0) or 0),
        "connection_limit": int(link.get("connection_limit", 0) or 0),
        "fragment": link.get("fragment", "off"),
        "fingerprint": link.get("fingerprint", DEFAULT_FINGERPRINT),
        "alpn": link.get("alpn", ""),
        "port": link.get("port", DEFAULT_PORT),
        "note": link.get("note", ""),
        "clean_ips": clean_ips,
        "alarm_enabled": bool(link.get("alarm_enabled", False)),
        "category_id": str(link.get("category_id") or "0"),
        "sort_order": int(link.get("sort_order") or 0),
        "category_number": int(cat.get("number", 0)),
        "category_name": str(cat.get("name", "عمومی")),
        "config_count": cfg_count,
        "status_color": status_color,
        "connected_ips": connected_count,
        "show_vless": show_vless,
        "vless": vless_link_for_link(link, uid, host) if show_vless else "",
        "vless_full": vless_link_for_link(link, uid, host),
        "sub": f"https://{host}/sub/{uid}",
        "info": f"https://{host}/info/{uid}",
        "support": SUPPORT_USERNAME,
    }


# ============================================================
# PERSISTENCE
# ============================================================

async def load_state():

    global AUTH

    try:

        DATA_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        if not DATA_FILE.exists():
            return

        async with aiofiles.open(
            DATA_FILE,
            "r",
            encoding="utf-8",
        ) as file:
            raw = await file.read()

        data = json.loads(raw)

        LINKS.update(
            data.get(
                "links",
                {},
            )
        )

        SUBS.update(
            data.get(
                "subs",
                {},
            )
        )

        CATEGORIES.update(
            data.get(
                "categories",
                {},
            )
        )

        ADMIN_ACCOUNTS.clear()
        ADMIN_ACCOUNTS.update(data.get("admin_accounts") or {})

        stored_password = data.get(
            "password_hash"
        )

        if stored_password:
            AUTH["password_hash"] = stored_password
            AUTH["password_configured"] = True

        # Compatibility for older records
        for uid, link in LINKS.items():

            link.setdefault(
                "protocol",
                DEFAULT_PROTOCOL,
            )

            link.setdefault(
                "fingerprint",
                DEFAULT_FINGERPRINT,
            )

            link.setdefault(
                "alpn",
                "",
            )

            link.setdefault(
                "port",
                DEFAULT_PORT,
            )

            link.setdefault(
                "ip_limit",
                0,
            )

            link.setdefault(
                "speed_limit_bytes",
                0,
            )

            link.setdefault(
                "connection_limit",
                0,
            )

            link.setdefault(
                "fragment",
                "off",
            )

            link.setdefault(
                "used_bytes",
                0,
            )
            link.setdefault("clean_ips", [])
            link.setdefault("alarm_enabled", False)
            link.setdefault("category_id", "0")
            link.setdefault("config_count", 1)
            link.setdefault("sort_order", 0)
            link.setdefault("usage_history", [])

        logger.info(
            "State loaded: %d links / %d subscriptions",
            len(LINKS),
            len(SUBS),
        )

    except Exception as exc:

        logger.exception(
            "Could not load state: %s",
            exc,
        )


async def save_state():

    async with SAVE_LOCK:

        try:

            DATA_DIR.mkdir(
                parents=True,
                exist_ok=True,
            )

            payload = {
                "links":
                    dict(LINKS),

                "subs":
                    dict(SUBS),

                "categories":
                    dict(CATEGORIES),

                "admin_accounts":
                    dict(ADMIN_ACCOUNTS),

                "password_hash":
                    AUTH[
                        "password_hash"
                    ],

                "saved_at":
                    datetime.now().isoformat(),
            }

            temp_file = (
                DATA_FILE.with_suffix(
                    ".tmp"
                )
            )

            async with aiofiles.open(
                temp_file,
                "w",
                encoding="utf-8",
            ) as file:

                await file.write(
                    json.dumps(
                        payload,
                        ensure_ascii=False,
                        indent=2,
                    )
                )

            temp_file.replace(
                DATA_FILE
            )

        except Exception as exc:

            logger.exception(
                "Could not save state: %s",
                exc,
            )


# ============================================================
# DEFAULT LINK
# ============================================================

_default_link_created = False



async def ensure_default_categories():
    # گروه‌های پیش‌فرض ساخته نمی‌شوند — کاربر خودش می‌سازد
    return


async def ensure_default_link():

    global _default_link_created

    if _default_link_created:
        return

    async with LINKS_LOCK:

        if not any(
            item.get("is_default")
            for item in LINKS.values()
        ):

            digest = hashlib.sha256(
                (
                    "default"
                    + SECRET_KEY
                ).encode("utf-8")
            ).hexdigest()

            uid = (
                f"{digest[:8]}-"
                f"{digest[8:12]}-"
                f"{digest[12:16]}-"
                f"{digest[16:20]}-"
                f"{digest[20:32]}"
            )

            LINKS[uid] = {
                "label":
                    "لینک پیش‌فرض",

                "limit_bytes":
                    0,

                "used_bytes":
                    0,

                "created_at":
                    datetime.now().isoformat(),

                "active":
                    True,

                "expires_at":
                    None,

                "note":
                    "",

                "is_default":
                    True,

                "sub_id":
                    None,

                "protocol":
                    DEFAULT_PROTOCOL,

                "fingerprint":
                    DEFAULT_FINGERPRINT,

                "alpn":
                    "http/1.1",

                "port":
                    DEFAULT_PORT,

                "ip_limit":
                    0,

                "speed_limit_bytes":
                    DEFAULT_SPEED_LIMIT,

                "connection_limit":
                    0,

                "fragment":
                    "off",
            }

            asyncio.create_task(
                save_state()
            )

    _default_link_created = True


# ============================================================
# LINK MANAGEMENT
# ============================================================

async def make_link(
    label: str = "لینک جدید",
    limit_bytes: int = 0,
    expires_at: str | None = None,
    note: str = "",
    sub_id: str | None = None,
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str = DEFAULT_FINGERPRINT,
    alpn: str = "",
    port: int = DEFAULT_PORT,
    ip_limit: int = 0,
    speed_limit_bytes: int = 0,
    connection_limit: int = 0,
    fragment: str = "off",
    clean_ips=None,
    alarm_enabled: bool = False,
    category_id: str = "0",
    config_count: int = 1,
):

    protocol = normalize_protocol(protocol)

    fingerprint = (
        fingerprint
        or DEFAULT_FINGERPRINT
    ).strip().lower()

    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    if not (
        MIN_PORT
        <= port
        <= MAX_PORT
    ):
        port = DEFAULT_PORT

    uid = generate_uuid()

    record = {
        "label":
            sanitize_config_name((label or "").strip() or random_config_name()),

        "limit_bytes":
            max(
                0,
                int(limit_bytes),
            ),

        "used_bytes":
            0,

        "created_at":
            datetime.now().isoformat(),

        "active":
            True,

        "expires_at":
            expires_at,

        "note":
            (
                note
                or ""
            ).strip()[:500],

        "is_default":
            False,

        "sub_id":
            sub_id,

        "protocol":
            protocol,

        "fingerprint":
            fingerprint,

        "alpn":
            (
                alpn
                or ""
            ).strip()[:100],

        "port":
            port,

        "ip_limit":
            max(
                0,
                int(ip_limit),
            ),

        "speed_limit_bytes":
            max(
                0,
                int(speed_limit_bytes),
            ),

        "connection_limit":
            max(
                0,
                int(connection_limit),
            ),

        "fragment":
            (
                fragment
                or "off"
            ).strip().lower(),

        "security_profile": "balanced",
        "multi_login": False,
        "protocol_label": PROTOCOL_LABELS.get(protocol, protocol),
        "clean_ips": list(clean_ips or []),
        "alarm_enabled": bool(alarm_enabled),
        "category_id": str(category_id or "0"),
        "config_count": max(1, min(40, int(config_count or 1))),
        "usage_history": [],
    }

    async with LINKS_LOCK:
        LINKS[uid] = record

    if sub_id:

        async with SUBS_LOCK:

            if sub_id in SUBS:

                ids = SUBS[
                    sub_id
                ].setdefault(
                    "link_ids",
                    [],
                )

                if uid not in ids:
                    ids.append(uid)

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{record['label']}» "
            f"ساخته شد"
        ),
        "ok",
    )

    return uid, record


async def remove_link(
    uid: str,
):

    async with LINKS_LOCK:

        if uid not in LINKS:
            return None

        label = LINKS[
            uid
        ].get(
            "label",
            uid,
        )

        sub_id = LINKS[
            uid
        ].get(
            "sub_id"
        )

        del LINKS[uid]

    if sub_id:

        async with SUBS_LOCK:

            if sub_id in SUBS:

                ids = SUBS[
                    sub_id
                ].get(
                    "link_ids",
                    [],
                )

                if uid in ids:
                    ids.remove(uid)

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» "
            f"حذف شد"
        ),
        "warn",
    )

    return label


async def set_link_active(
    uid: str,
    active: bool,
):

    async with LINKS_LOCK:

        if uid not in LINKS:
            return None

        LINKS[
            uid
        ][
            "active"
        ] = bool(active)

        record = LINKS[uid]

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{record['label']}» "
            f"{'فعال' if active else 'غیرفعال'} شد"
        ),
        "ok"
        if active
        else "warn",
    )

    return record


# ============================================================
# SUB GROUPS
# ============================================================

async def create_sub_group(
    name: str = "گروه جدید",
    desc: str = "",
    password: str = "",
):

    name = (
        name
        or "گروه جدید"
    ).strip()[:60]

    desc = (
        desc
        or ""
    ).strip()[:200]

    password = (
        password
        or ""
    ).strip()

    sub_id = generate_uuid()

    uuid_key = secrets.token_urlsafe(16)

    record = {
        "name":
            name,

        "desc":
            desc,

        "password_hash":
            (
                hash_password(password)
                if password
                else None
            ),

        "uuid_key":
            uuid_key,

        "created_at":
            datetime.now().isoformat(),

        "link_ids":
            [],
    }

    async with SUBS_LOCK:
        SUBS[sub_id] = record

    await save_state()

    log_activity(
        "sub",
        (
            f"گروه "
            f"«{name}» "
            f"ساخته شد"
        ),
        "ok",
    )

    return (
        sub_id,
        record,
    )


async def set_link_sub(
    uid: str,
    sub_id: str | None,
):

    async with LINKS_LOCK:

        if uid not in LINKS:
            return False

        old_sub = LINKS[
            uid
        ].get(
            "sub_id"
        )

        label = LINKS[
            uid
        ].get(
            "label",
            uid,
        )

    if sub_id is not None:

        async with SUBS_LOCK:

            if sub_id not in SUBS:
                return False

    async with SUBS_LOCK:

        if (
            old_sub
            and old_sub in SUBS
        ):

            ids = SUBS[
                old_sub
            ].get(
                "link_ids",
                [],
            )

            if uid in ids:
                ids.remove(uid)

        if (
            sub_id
            and sub_id in SUBS
        ):

            ids = SUBS[
                sub_id
            ].setdefault(
                "link_ids",
                [],
            )

            if uid not in ids:
                ids.append(uid)

    async with LINKS_LOCK:

        if uid in LINKS:

            LINKS[
                uid
            ][
                "sub_id"
            ] = sub_id

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» "
            f"{'به گروه اضافه شد' if sub_id else 'از گروه خارج شد'}"
        ),
        "info",
    )

    return True


async def remove_sub_group(
    sub_id: str,
):

    async with SUBS_LOCK:

        if sub_id not in SUBS:
            return None

        name = SUBS[
            sub_id
        ].get(
            "name",
            sub_id,
        )

        del SUBS[sub_id]

    async with LINKS_LOCK:

        for link in LINKS.values():

            if (
                link.get("sub_id")
                == sub_id
            ):
                link["sub_id"] = None

    await save_state()

    log_activity(
        "sub",
        (
            f"گروه "
            f"«{name}» "
            f"حذف شد"
        ),
        "warn",
    )

    return name


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup():

    global http_client

    limits = httpx.Limits(
        max_connections=500,
        max_keepalive_connections=100,
    )

    timeout = httpx.Timeout(
        30.0,
        connect=10.0,
    )

    http_client = httpx.AsyncClient(
        limits=limits,
        timeout=timeout,
        follow_redirects=True,
    )

    await load_state()

    await ensure_default_categories()
    await ensure_default_link()

    log_activity(
        "system",
        (
            f"{APP_NAME} "
            f"v{APP_VERSION} "
            f"راه‌اندازی شد"
        ),
        "ok",
    )

    logger.info(
        "%s v%s started on 0.0.0.0:%s",
        APP_NAME,
        APP_VERSION,
        PORT,
    )

    logger.info(
        "Data directory: %s",
        DATA_DIR,
    )


@app.on_event("shutdown")
async def shutdown():

    await save_state()

    if http_client:
        await http_client.aclose()


# ============================================================
# LANDING
# ============================================================

LANDING_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">

<title>AHB PANEL</title>

<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>

<link
href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap"
rel="stylesheet">

<style>
*{
    box-sizing:border-box;
}

html,body{
    margin:0;
    min-height:100%;
}

body{
    min-height:100vh;
    display:flex;
    justify-content:center;
    align-items:center;
    padding:20px;
    color:#fff;
    font-family:"Vazirmatn",sans-serif;

    background:
        radial-gradient(
            circle at 15% 15%,
            rgba(37,99,235,.22),
            transparent 30%
        ),
        radial-gradient(
            circle at 85% 85%,
            rgba(59,130,246,.18),
            transparent 30%
        ),
        #07070a;
}

.card{
    width:100%;
    max-width:580px;
    padding:32px;
    border-radius:28px;

    border:1px solid rgba(255,255,255,.09);

    background:
        linear-gradient(
            145deg,
            rgba(255,255,255,.07),
            rgba(255,255,255,.025)
        );

    backdrop-filter:blur(28px) saturate(150%);

    box-shadow:
        0 30px 90px rgba(0,0,0,.45);
}

.brand{
    display:flex;
    align-items:center;
    gap:12px;
}

.logo{
    width:48px;
    height:48px;
    border-radius:15px;

    display:flex;
    justify-content:center;
    align-items:center;

    font-size:18px;
    font-weight:900;

    background:
        linear-gradient(
            135deg,
            #2563eb,
            #3b82f6
        );
}

.brand-name{
    font-size:17px;
    font-weight:900;
}

.version{
    margin-top:4px;
    font-size:11px;
    color:#60a5fa;
}

.status{
    display:inline-block;
    margin-top:23px;
    padding:7px 11px;
    border-radius:999px;

    color:#86efac;
    background:rgba(34,197,94,.07);
    border:1px solid rgba(34,197,94,.15);

    font-size:11px;
}

h1{
    margin:18px 0 0;
    font-size:28px;
    line-height:1.55;
}

.desc{
    margin-top:12px;
    color:rgba(255,255,255,.52);
    line-height:2;
    font-size:13px;
}

.path{
    margin-top:22px;
    padding:15px;
    border-radius:15px;

    background:rgba(0,0,0,.18);
    border:1px solid rgba(255,255,255,.07);

    direction:ltr;
    text-align:left;
    font-family:Consolas,monospace;
    color:#93c5fd;
}

.actions{
    display:flex;
    gap:10px;
    margin-top:20px;
}

.btn{
    flex:1;
    padding:13px;
    border-radius:14px;
    text-align:center;
    text-decoration:none;

    font-size:12px;
    font-weight:800;
}

.primary{
    color:#fff;
    background:
        linear-gradient(
            135deg,
            #2563eb,
            #3b82f6
        );
}

.secondary{
    color:#fff;
    background:rgba(255,255,255,.035);
    border:1px solid rgba(255,255,255,.08);
}

.footer{
    margin-top:22px;
    padding-top:16px;
    border-top:1px solid rgba(255,255,255,.07);

    display:flex;
    justify-content:space-between;

    font-size:10px;
    color:rgba(255,255,255,.35);
}

.support{
    color:#60a5fa;
    text-decoration:none;
}

@media(max-width:600px){
    .card{
        padding:24px;
        border-radius:22px;
    }

    h1{
        font-size:23px;
    }

    .actions{
        flex-direction:column;
    }
}

/* AhbPanel 13.0.1 responsive system */
html{scroll-behavior:smooth} body{overflow-x:hidden} button,input,select,textarea{touch-action:manipulation} .modal{overscroll-behavior:contain}
@media(max-width:900px){.container,.shell,.dashboard,.main,.content{max-width:100%!important;width:100%!important}.grid,.stats-grid,.cards-grid,.form-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}.sidebar{z-index:1000}}
@media(max-width:640px){body{padding:10px!important;font-size:14px}.grid,.stats-grid,.cards-grid,.form-grid{grid-template-columns:1fr!important}.card,.panel,.section,.modal{border-radius:18px!important}.modal{max-height:92vh;overflow:auto;padding:14px!important}.header,.topbar,.toolbar,.actions{flex-wrap:wrap!important}.header>* ,.topbar>*{max-width:100%}.btn,button{min-height:44px}.field input,.field select,.field textarea,input,select,textarea{min-height:44px;font-size:16px;max-width:100%}table{display:block;overflow-x:auto;white-space:nowrap}.link-row,.config-row{flex-direction:column!important;align-items:stretch!important}.brand-name{font-size:15px}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}

/* Toggle switch */
.switch{position:relative;display:inline-block;width:42px;height:24px;vertical-align:middle}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;inset:0;background:rgba(255,255,255,.12);border-radius:24px;transition:.2s}
.slider:before{position:absolute;content:"";height:18px;width:18px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.2s}
.switch input:checked+.slider{background:var(--green)}
.switch input:checked+.slider:before{transform:translateX(18px)}


.conn-badge{display:inline-flex;align-items:center;justify-content:center;min-width:22px;height:20px;padding:0 7px;border-radius:8px;font-size:10px;font-weight:800}
.conn-badge.green{background:rgba(34,197,94,.18);color:#4ade80}
.conn-badge.gray{background:rgba(148,163,184,.15);color:#94a3b8}
.conn-badge.orange{background:rgba(245,158,11,.18);color:#fbbf24}
.conn-badge.red{background:rgba(239,68,68,.18);color:#f87171}


.bottom-bulk{position:fixed;left:0;right:0;bottom:0;z-index:400;display:none;padding:12px 16px;background:var(--card);border-top:1px solid var(--card-b);backdrop-filter:blur(12px)}
.bottom-bulk.show{display:block}
.bottom-bulk-inner{max-width:960px;margin:0 auto;display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:center}
.bottom-bulk select{padding:8px 10px;border-radius:10px;border:1px solid var(--card-b);background:var(--input-bg);color:var(--t1);font-family:inherit;font-size:12px}

table th:first-child, table td:first-child{overflow:visible}
.cfg-chk{accent-color:var(--accent)}
#page-donate .page-title{width:100%}
</style>
</head>

<body>

<div class="card">

<div class="brand">

<div class="logo">P</div>

<div>
<div class="brand-name">
AHB Panel
</div>

<div class="version">
14.5.0
</div>
</div>

</div>

<div class="status">
● سیستم آنلاین و فعال است
</div>

<h1>
برای ورود به پنل
<br>
ابتدا وارد شوید
</h1>

<div class="desc">
این صفحه، درگاه عمومی AHB Panel است.
برای دسترسی به داشبورد مدیریت از مسیر ورود استفاده کنید.
</div>

<div class="path">
/login
</div>

<div class="actions">

<a
href="/login"
class="btn primary"
>
ورود به پنل
</a>

<a
href="https://t.me/ahb_panel"
target="_blank"
rel="noopener"
class="btn secondary"
>
پشتیبانی
</a>

</div>

<div class="footer">

<span>
AHB Panel · 14.5.0
</span>

<a
href="https://t.me/ahb_panel"
target="_blank"
class="support"
>
@ahb_panel
</a>

</div>

</div>


<div id="bottomBulkBar" class="bottom-bulk">
  <div class="bottom-bulk-inner">
    <span id="bulkCount">0 انتخاب</span>
    <select id="bulkGroup"></select>
    <button class="btn btn-sm" onclick="bulkMoveGroup()">انتقال به گروه</button>
    <button class="btn btn-sm btn-d" onclick="bulkDelete()">حذف انتخاب‌شده</button>
    <button class="btn btn-sm" onclick="clearSelection()">لغو</button>
  </div>
</div>
</body>
</html>
"""


@app.get(
    "/",
    response_class=HTMLResponse,
)
async def root(
    request: Request,
):

    if await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):
        return RedirectResponse(
            "/dashboard"
        )

    return HTMLResponse(
        LOGIN_HTML
    )


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():

    return {
        "status": "ok",
        "service": APP_NAME,
        "version": APP_VERSION,
        "connections": len(connections),
        "uptime": uptime(),
    }


# ============================================================
# LOGIN
# ============================================================

LOGIN_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ای اچ بی پنل</title>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{min-height:100%}
body{
  min-height:100vh;font-family:Vazirmatn,Tahoma,sans-serif;color:#f1f5f9;background:#04030f;
  display:flex;align-items:center;justify-content:center;padding:24px;overflow-x:hidden;position:relative;
}
#bg{position:fixed;inset:0;width:100%;height:100%;z-index:0;pointer-events:none}
.shell{position:relative;z-index:1;width:100%;max-width:1080px;display:flex;align-items:center;justify-content:space-between;gap:40px}

/* glass card (right side in RTL) */
.card{
  width:100%;max-width:400px;padding:28px 26px;border-radius:20px;flex-shrink:0;
  background:linear-gradient(160deg,rgba(18,20,40,.72),rgba(10,12,28,.62));
  backdrop-filter:blur(22px) saturate(150%);-webkit-backdrop-filter:blur(22px) saturate(150%);
  border:1px solid rgba(120,140,255,.18);
  box-shadow:0 30px 80px rgba(0,0,0,.6),inset 0 1px 0 rgba(255,255,255,.08);
}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:18px}
.logo{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;font-weight:800;font-size:18px;color:#fff;
  background:linear-gradient(135deg,#2f7bff,#1a57e8);box-shadow:0 0 18px rgba(47,123,255,.5)}
.brand-name{font-weight:800;font-size:14px;line-height:1.2}
.brand-ver{font-size:11px;color:#4ea0ff;direction:ltr;text-align:right}
h1{font-size:21px;font-weight:800;line-height:1.7;margin-bottom:8px}
.desc{font-size:12px;line-height:1.9;color:rgba(255,255,255,.55);margin-bottom:20px}
.field{position:relative;margin-bottom:12px}
.field input{
  width:100%;height:50px;padding:0 46px 0 44px;border-radius:12px;border:1px solid rgba(255,255,255,.1);
  background:rgba(5,6,20,.55);color:#fff;font-family:inherit;font-size:14px;outline:none;transition:.2s;
}
.field input::placeholder{color:rgba(255,255,255,.4)}
.field input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.18)}
.field .ic{position:absolute;right:15px;top:50%;transform:translateY(-50%);width:18px;height:18px;color:#cfd8ff;pointer-events:none;opacity:.85}
.field .eye{position:absolute;left:12px;top:50%;transform:translateY(-50%);width:28px;height:28px;padding:0;margin:0;
  display:grid;place-items:center;background:none;border:none;box-shadow:none;color:rgba(255,255,255,.55);cursor:pointer;border-radius:8px}
.field .eye:hover{color:#fff;background:none;box-shadow:none}
.field .eye svg{width:18px;height:18px}
label{display:block;font-size:12px;color:rgba(255,255,255,.6);margin:2px 2px 6px;font-weight:600}
button.cta{
  width:100%;height:50px;margin-top:8px;border:none;border-radius:12px;color:#fff;font-family:inherit;font-size:15px;font-weight:700;cursor:pointer;
  background:linear-gradient(100deg,#1a7bff,#4a5cff);box-shadow:0 8px 26px rgba(40,100,255,.4);transition:.2s;
}
button.cta:hover{filter:brightness(1.1);box-shadow:0 10px 30px rgba(60,110,255,.55)}
button.cta:disabled{opacity:.5;cursor:not-allowed}
.err,.error{display:none;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);color:#fca5a5;padding:10px 12px;border-radius:10px;font-size:12px;margin:10px 0}
.err.show{display:block}
.error{display:block}
.warn{background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.28);border-radius:12px;padding:12px;font-size:12px;line-height:1.85;color:#fbbf24;margin-bottom:16px}
.warn code{background:rgba(0,0,0,.35);padding:2px 6px;border-radius:6px;font-family:ui-monospace,monospace;color:#93c5fd}
.hidden{display:none}
.foot{text-align:center;margin-top:16px;font-size:11px;color:rgba(255,255,255,.4)}
.foot a{color:#4ea0ff;text-decoration:none}

/* hero (left side in RTL) */
.hero{flex:1;min-width:0;display:flex;flex-direction:column;align-items:center;text-align:center}
.wordmark{font-size:78px;font-weight:800;letter-spacing:2px;line-height:1;direction:ltr;
  background:linear-gradient(180deg,#5aa2ff,#4a3bff 70%,#7a4dff);-webkit-background-clip:text;background-clip:text;color:transparent;
  filter:drop-shadow(0 0 22px rgba(80,110,255,.55))}
.wm-sub{font-size:20px;letter-spacing:14px;color:#6aa7ff;margin-top:6px;direction:ltr;padding-left:14px}
.wm-ver{font-size:13px;color:#7ea4ff;margin-top:6px;direction:ltr}
.slogan{margin-top:150px;font-size:26px;font-weight:800;line-height:1.7;text-shadow:0 2px 18px rgba(0,0,0,.7)}
.chips{display:flex;gap:12px;margin-top:34px}
.chip{width:78px;padding:12px 6px 10px;border-radius:14px;background:rgba(10,12,32,.55);border:1px solid rgba(120,140,255,.18);
  backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);font-size:12px;color:#dbe4ff;display:flex;flex-direction:column;align-items:center;gap:6px}
.chip svg{width:22px;height:22px;color:#4ea0ff}


/* design 5: gradient + animation */
.waves .w{transform-box:fill-box;transform-origin:center}
.w1{animation:drift1 12s ease-in-out infinite alternate}
.w2{animation:drift2 15s ease-in-out infinite alternate}
.w3{animation:drift3 18s ease-in-out infinite alternate}
@keyframes drift1{to{transform:translate(-40px,-26px) rotate(-1.2deg)}}
@keyframes drift2{to{transform:translate(34px,-18px) rotate(1deg)}}
@keyframes drift3{to{transform:translate(-26px,-34px) rotate(-.8deg)}}
.card{
  border:1.5px solid transparent;
  background:linear-gradient(160deg,rgba(14,16,40,.9),rgba(8,10,28,.88)) padding-box,
             linear-gradient(135deg,#00c8ff,#6a45ff 55%,#ff2bd6) border-box;
  box-shadow:0 30px 80px rgba(0,0,0,.6),0 0 40px rgba(106,69,255,.28);
  animation:pulse 5s ease-in-out infinite alternate;
}
@keyframes pulse{to{box-shadow:0 30px 80px rgba(0,0,0,.6),0 0 60px rgba(255,43,214,.3)}}
button.cta{background:linear-gradient(100deg,#0a84ff,#6a45ff 55%,#d11cb8);background-size:200% 100%;
  box-shadow:0 8px 26px rgba(106,69,255,.45);transition:background-position .5s,box-shadow .2s}
button.cta:hover{background-position:100% 0;filter:none;box-shadow:0 10px 32px rgba(209,28,184,.5)}
.wordmark{font-size:84px;background:linear-gradient(180deg,#4aa8ff,#5b3cff 60%,#a23dff);-webkit-background-clip:text;background-clip:text;color:transparent}
.slogan{margin-top:90px;font-size:22px;font-weight:700}
.chips{margin-top:60px;gap:26px}
.chip{background:none;border:none;backdrop-filter:none;-webkit-backdrop-filter:none;width:auto;padding:0;font-size:12px;color:rgba(255,255,255,.75)}
.chip svg{width:26px;height:26px;color:#4ea0ff}

@media(max-width:860px){
  .hero{display:none}
  .shell{justify-content:center}
}
@media(prefers-reduced-motion:reduce){*{animation:none!important}}
</style>
</head>
<body>

<svg id="bg" viewBox="0 0 1600 900" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <defs>
    <linearGradient id="sky" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#050416"/><stop offset=".6" stop-color="#0b0a2e"/><stop offset="1" stop-color="#1a0f45"/>
    </linearGradient>
    <linearGradient id="wv" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="#1fa2ff"/><stop offset=".5" stop-color="#6a45ff"/><stop offset="1" stop-color="#ff2bd6"/>
    </linearGradient>
    <radialGradient id="g1" cx=".15" cy=".85" r=".6"><stop offset="0" stop-color="#2b6bff" stop-opacity=".45"/><stop offset="1" stop-color="#2b6bff" stop-opacity="0"/></radialGradient>
    <radialGradient id="g2" cx=".85" cy=".1" r=".5"><stop offset="0" stop-color="#9b3bff" stop-opacity=".3"/><stop offset="1" stop-color="#9b3bff" stop-opacity="0"/></radialGradient>
    <filter id="soft"><feGaussianBlur stdDeviation="9"/></filter>
  </defs>
  <rect width="1600" height="900" fill="url(#sky)"/>
  <rect width="1600" height="900" fill="url(#g1)"/>
  <rect width="1600" height="900" fill="url(#g2)"/>
  <g id="stars"></g>
  <g class="waves" fill="none" stroke="url(#wv)" stroke-linecap="round">
    <g class="w w1">
      <path d="M-150 760 C150 560 330 900 640 700 S1080 520 1750 720" stroke-width="22" opacity=".35" filter="url(#soft)"/>
      <path d="M-150 760 C150 560 330 900 640 700 S1080 520 1750 720" stroke-width="3" opacity=".95"/>
    </g>
    <g class="w w2">
      <path d="M-150 800 C180 620 360 930 700 740 S1120 580 1750 770" stroke-width="2" opacity=".7"/>
      <path d="M-150 830 C200 660 400 950 740 780 S1150 640 1750 810" stroke-width="1.5" opacity=".5"/>
    </g>
    <g class="w w3">
      <path d="M-150 700 C120 500 300 850 600 650 S1040 470 1750 650" stroke-width="1.5" opacity=".55"/>
      <path d="M-150 660 C100 470 290 800 580 610 S1020 430 1750 610" stroke-width="1" opacity=".4"/>
    </g>
  </g>
</svg>

<div class="shell">
  <div class="card">
    <div class="brand">
      <div class="logo">P</div>
      <div>
        <div class="brand-name">AHB Panel</div>
        <div class="brand-ver">14.5.0</div>
      </div>
    </div>

    <h1>برای ورود به پنل<br>ابتدا وارد شوید</h1>
    <div class="desc">این صفحه، درگاه عمومی AHB Panel است. برای دسترسی به داشبورد مدیریت از مسیر ورود استفاده کنید.</div>

    <div id="setupBox" class="hidden">
      <div class="warn">
        برای نگه‌داشتن داده‌ها روی Railway حتماً Volume با مسیر <code>/data</code> وصل کنید.
      </div>
      <div class="err" id="setupErr"></div>
      <label>رمز عبور پنل</label>
      <div class="field">
        <svg class="ic" viewBox="0 0 24 24" fill="currentColor"><path d="M17 8V7a5 5 0 0 0-10 0v1H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2h-1zM9 7a3 3 0 0 1 6 0v1H9V7z"/></svg>
        <input type="password" id="setupPw" placeholder="حداقل ۶ کاراکتر" autocomplete="new-password">
      </div>
      <label>تکرار رمز عبور</label>
      <div class="field">
        <svg class="ic" viewBox="0 0 24 24" fill="currentColor"><path d="M17 8V7a5 5 0 0 0-10 0v1H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2h-1zM9 7a3 3 0 0 1 6 0v1H9V7z"/></svg>
        <input type="password" id="setupPw2" placeholder="تکرار رمز" autocomplete="new-password">
      </div>
      <button type="button" class="cta" id="setupBtn" onclick="doSetup()">تنظیم رمز و ورود</button>
    </div>

    <div id="loginBox" class="hidden">
      <div class="err" id="loginErr"></div>
      <form id="loginForm">
        <div class="field">
          <svg class="ic" viewBox="0 0 24 24" fill="currentColor"><path d="M12 12a5 5 0 1 0 0-10 5 5 0 0 0 0 10zm0 2c-4.4 0-8 2.2-8 5v1h16v-1c0-2.8-3.6-5-8-5z"/></svg>
          <input type="text" id="loginUser" placeholder="نام کاربری / ایمیل (خالی = مالک پنل)" autocomplete="username">
        </div>
        <div class="field">
          <svg class="ic" viewBox="0 0 24 24" fill="currentColor"><path d="M17 8V7a5 5 0 0 0-10 0v1H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2h-1zM9 7a3 3 0 0 1 6 0v1H9V7z"/></svg>
          <input type="password" id="loginPw" placeholder="رمز عبور" autocomplete="current-password" required>
          <button type="button" class="eye" id="eyeBtn" aria-label="نمایش رمز">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
        </div>
        <button type="submit" class="cta" id="loginBtn">ورود به پنل</button>
      </form>
    </div>

    <div class="foot">AHB Panel · 14.5.0 · <a href="https://t.me/ahb_panel" target="_blank" rel="noopener">@ahb_panel</a></div>
  </div>

  <div class="hero">
    <div class="wordmark">AHB</div>
    <div class="wm-sub">PANEL</div>
    <div class="wm-ver">14.5.0</div>
    <div class="slogan">آینده مدیریت سرور<br>از اینجا شروع می‌شود</div>
    <div class="chips">
      <div class="chip"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M13 2 4 14h6l-1 8 9-12h-6z"/></svg>پایداری</div>
      <div class="chip"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="3"/><path d="M12 2v4M12 18v4M2 12h4M18 12h4M5 5l3 3M16 16l3 3M19 5l-3 3M8 16l-3 3"/></svg>سرعت</div>
      <div class="chip"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5z"/><path d="m9 12 2 2 4-4" stroke-linecap="round"/></svg>امنیت</div>
    </div>
  </div>
</div>

<script>
(function(){
  var g=document.getElementById('stars'),s=7,ns='http://www.w3.org/2000/svg';
  function r(){s=(s*16807)%2147483647;return s/2147483647}
  for(var i=0;i<110;i++){
    var c=document.createElementNS(ns,'circle');
    c.setAttribute('cx',(r()*1600).toFixed(0));c.setAttribute('cy',(r()*600).toFixed(0));
    c.setAttribute('r',(r()*1.3+.3).toFixed(2));c.setAttribute('fill','#fff');
    c.setAttribute('opacity',(r()*.6+.3).toFixed(2));g.appendChild(c);
  }
  var eb=document.getElementById('eyeBtn'),pw=document.getElementById('loginPw');
  eb.addEventListener('click',function(){pw.type=pw.type==='password'?'text':'password'});
})();
async function checkSetup(){
  try{
    const r=await fetch('/api/setup/status',{cache:'no-store'});
    const d=await r.json();
    if(d.needs_setup){
      document.getElementById('setupBox').classList.remove('hidden');
    }else{
      document.getElementById('loginBox').classList.remove('hidden');
      document.getElementById('loginPw').focus();
    }
  }catch(e){
    document.getElementById('loginBox').classList.remove('hidden');
  }
}
async function doSetup(){
  const pw=document.getElementById('setupPw').value;
  const pw2=document.getElementById('setupPw2').value;
  const err=document.getElementById('setupErr');
  err.classList.remove('show');
  if(pw.length<6){err.textContent='رمز حداقل ۶ کاراکتر';err.classList.add('show');return}
  if(pw!==pw2){err.textContent='تکرار رمز یکسان نیست';err.classList.add('show');return}
  const btn=document.getElementById('setupBtn');btn.disabled=true;
  try{
    const r=await fetch('/api/setup/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw,repeat_password:pw2})});
    const d=await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(d.detail||'خطا');
    location.href='/dashboard';
  }catch(e){
    err.textContent=e.message||'خطا';err.classList.add('show');
    btn.disabled=false;
  }
}
document.getElementById('loginForm').addEventListener('submit',async e=>{
  e.preventDefault();
  const err=document.getElementById('loginErr');
  err.classList.remove('show');
  const btn=document.getElementById('loginBtn');btn.disabled=true;
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
      password:document.getElementById('loginPw').value,
      username:document.getElementById('loginUser').value
    })});
    if(!r.ok){
      const d=await r.json().catch(()=>({}));
      throw new Error(d.detail||'رمز اشتباه است');
    }
    location.href='/dashboard';
  }catch(e){
    err.textContent=e.message;err.classList.add('show');
    btn.disabled=false;
  }
});
checkSetup();
</script>
</body>
</html>
"""




def login_error_html(
    message: str,
):
    safe_message = escape_html(
        message
    )

    return LOGIN_HTML.replace(
        "</form>",
        (
            f"""
            <div class="error">
                {safe_message}
            </div>
            </form>
            """
        ),
    )



# ============================================================
# FIRST-RUN SETUP
# ============================================================

@app.get("/api/setup/status")
async def setup_status():
    return {
        "password_configured": bool(AUTH.get("password_configured") and AUTH.get("password_hash")),
        "needs_setup": not bool(AUTH.get("password_configured") and AUTH.get("password_hash")),
    }


@app.post("/api/setup/password")
async def setup_password(request: Request):
    if AUTH.get("password_configured") and AUTH.get("password_hash"):
        raise HTTPException(status_code=400, detail="رمز قبلاً تنظیم شده است")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="اطلاعات نامعتبر")
    pw = str(body.get("password") or "")
    rp = str(body.get("repeat_password") or body.get("confirm") or "")
    if len(pw) < 6:
        raise HTTPException(status_code=400, detail="رمز باید حداقل ۶ کاراکتر باشد")
    if pw != rp:
        raise HTTPException(status_code=400, detail="تکرار رمز یکسان نیست")
    AUTH["password_hash"] = hash_password(pw)
    AUTH["password_configured"] = True
    await save_state()
    token = await create_session()
    response = JSONResponse({"ok": True, "message": "رمز تنظیم شد"})
    set_auth_cookie(response, request, token)
    log_activity("auth", "رمز اولیه پنل تنظیم شد", "ok")
    return response


@app.get(
    "/login",
    response_class=HTMLResponse,
)
async def login_page(
    request: Request,
):

    if await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):
        return RedirectResponse(
            "/dashboard"
        )

    return HTMLResponse(
        LOGIN_HTML
    )


@app.post("/login")
async def login_form(
    request: Request,
):
    if not (AUTH.get("password_configured") and AUTH.get("password_hash")):
        return HTMLResponse(login_error_html("ابتدا از صفحه ورود، رمز اولیه را تنظیم کنید"))


    try:

        content_type = (
            request.headers
            .get(
                "content-type",
                "",
            )
            .lower()
        )

        if "application/json" in content_type:

            body = await request.json()

            password = str(
                body.get(
                    "password",
                    "",
                )
            ).strip()

        else:

            raw = await request.body()

            parsed = parse_qs(
                raw.decode(
                    "utf-8",
                    errors="ignore",
                )
            )

            password = (
                parsed.get(
                    "password",
                    [""],
                )[0]
                .strip()
            )

    except Exception as exc:

        logger.exception(
            "Login parser error: %s",
            exc,
        )

        return HTMLResponse(
            login_error_html(
                "خطا در پردازش اطلاعات ورود."
            ),
            status_code=400,
        )

    ip = client_ip(request)

    blocked, retry_after = login_is_blocked(ip)
    if blocked:
        minutes = max(1, (retry_after + 59) // 60)
        return HTMLResponse(
            login_error_html(
                f"به دلیل تلاش‌های ناموفق متعدد، ورود موقتاً مسدود شده است. حدود {minutes} دقیقه دیگر دوباره تلاش کنید."
            ),
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )

    if not password:
        register_login_failure(ip)
        return HTMLResponse(
            login_error_html(
                "رمز عبور را وارد کنید."
            ),
            status_code=400,
        )

    if (
        hash_password(password)
        != AUTH["password_hash"]
    ):

        locked, value = register_login_failure(ip)
        if locked:
            return HTMLResponse(
                login_error_html(
                    "تعداد تلاش‌های ناموفق بیش از حد مجاز بود. این IP برای ۱۵ دقیقه مسدود شد."
                ),
                status_code=429,
                headers={"Retry-After": str(LOGIN_LOCKOUT_SECONDS)},
            )

        remaining = value
        log_activity(
            "auth",
            (
                f"تلاش ورود ناموفق از {ip}؛ "
                f"{remaining} تلاش باقی مانده"
            ),
            "err",
        )

        return HTMLResponse(
            login_error_html(
                f"رمز عبور اشتباه است. {remaining} تلاش دیگر باقی مانده است."
            ),
            status_code=401,
        )

    clear_login_failures(ip)

    token = await create_session()

    response = RedirectResponse(
        "/dashboard?login=1",
        status_code=303,
    )

    set_auth_cookie(
        response,
        request,
        token,
    )

    log_activity(
        "auth",
        (
            f"ورود موفق به پنل "
            f"از {client_ip(request)}"
        ),
        "ok",
    )

    return response


@app.post("/api/login")
async def api_login(request: Request):
    if not (AUTH.get("password_configured") and AUTH.get("password_hash")):
        raise HTTPException(status_code=400, detail="ابتدا رمز پنل را در راه‌اندازی تنظیم کنید")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر است")
    password = str(body.get("password", "")).strip()
    username = str(body.get("username", "")).strip().lower()
    ip = client_ip(request)
    blocked, retry_after = login_is_blocked(ip)
    if blocked:
        raise HTTPException(status_code=429, detail=f"ورود موقتاً مسدود است. حدود {max(1, (retry_after + 59) // 60)} دقیقه دیگر تلاش کنید.", headers={"Retry-After": str(retry_after)})
    if not password:
        register_login_failure(ip)
        raise HTTPException(status_code=400, detail="رمز عبور الزامی است")
    meta = {"role": "owner", "admin_id": None, "username": "owner"}
    ok = False
    if username and username not in ("owner", "admin", "root"):
        aid, admin = find_admin_by_username(username)
        if admin and admin.get("password_hash") == hash_password(password):
            if not admin_is_valid(admin):
                raise HTTPException(status_code=403, detail="حساب مسدود یا منقضی شده است")
            ok = True
            meta = {"role": "admin", "admin_id": aid, "username": username}
    else:
        if hash_password(password) == AUTH["password_hash"]:
            ok = True
    if not ok:
        locked, value = register_login_failure(ip)
        if locked:
            raise HTTPException(status_code=429, detail="تعداد تلاش بیش از حد. ۱۵ دقیقه صبر کنید.", headers={"Retry-After": str(LOGIN_LOCKOUT_SECONDS)})
        raise HTTPException(status_code=401, detail=f"نام کاربری یا رمز اشتباه است. {value} تلاش باقی‌مانده")
    clear_login_failures(ip)
    token = await create_session(meta)
    response = JSONResponse({"ok": True, "role": meta["role"], "username": meta["username"]})
    set_auth_cookie(response, request, token)
    log_activity("auth", f"ورود موفق ({meta['username']}) از {ip}", "ok")
    return response


@app.post("/api/logout")
async def api_logout(
    request: Request,
):

    await destroy_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    )

    response = JSONResponse(
        {
            "ok": True
        }
    )

    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
    )

    return response





# ============================================================
# CHANGE PASSWORD
# ============================================================

@app.post("/api/change-password")
async def api_change_password(
    request: Request,
    token=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="اطلاعات نامعتبر است",
        )

    current_password = str(
        body.get(
            "current_password",
            "",
        )
    )

    if (
        hash_password(current_password)
        != AUTH["password_hash"]
    ):
        raise HTTPException(
            status_code=400,
            detail="رمز فعلی اشتباه است",
        )

    new_password = str(
        body.get(
            "new_password",
            "",
        )
    )

    repeat_password = str(
        body.get(
            "repeat_password",
            "",
        )
    )

    if len(new_password) < 6:
        raise HTTPException(
            status_code=400,
            detail="رمز جدید باید حداقل ۶ کاراکتر باشد",
        )

    if new_password != repeat_password:
        raise HTTPException(
            status_code=400,
            detail="تکرار رمز عبور یکسان نیست",
        )

    AUTH[
        "password_hash"
    ] = hash_password(
        new_password
    )

    async with SESSIONS_LOCK:

        SESSIONS.clear()

        SESSIONS[token] = (
            time.time()
            + SESSION_TTL
        )

    await save_state()

    log_activity(
        "auth",
        "رمز عبور پنل تغییر کرد",
        "ok",
    )

    return {
        "ok": True
    }


# ============================================================
# CREATE LINK
# ============================================================

@app.post("/api/links")
async def create_link_api(
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()

        if not isinstance(body, dict):
            raise ValueError(
                "body is not object"
            )

    except Exception as exc:

        logger.exception(
            "Create link JSON error: %s",
            exc,
        )

        raise HTTPException(
            status_code=400,
            detail="اطلاعات ارسال‌شده معتبر نیست.",
        )

    limit_value = safe_float(
        body.get(
            "limit_value",
            0,
        )
    )

    limit_unit = str(
        body.get(
            "limit_unit",
            "GB",
        )
        or "GB"
    ).upper()

    limit_bytes = (
        0
        if limit_value <= 0
        else parse_size_to_bytes(
            limit_value,
            limit_unit,
        )
    )

    expires_days = safe_int(
        body.get(
            "expires_days",
            0,
        ),
        minimum=0,
    )

    expires_at = (
        (
            datetime.now()
            + timedelta(
                days=expires_days
            )
        ).isoformat()
        if expires_days > 0
        else None
    )

    port = safe_int(
        body.get(
            "port",
            DEFAULT_PORT,
        ),
        default=DEFAULT_PORT,
        minimum=MIN_PORT,
        maximum=MAX_PORT,
    )

    ip_limit = safe_int(
        body.get(
            "ip_limit",
            0,
        ),
        minimum=0,
    )

    speed_value = safe_float(
        body.get(
            "speed_limit_value",
            0,
        )
    )

    speed_unit = str(
        body.get(
            "speed_limit_unit",
            "MBIT",
        )
        or "MBIT"
    ).upper()

    speed_bytes = (
        0
        if speed_value <= 0
        else parse_speed_to_bytes(
            speed_value,
            speed_unit,
        )
    )

    connection_limit = safe_int(
        body.get(
            "connection_limit",
            0,
        ),
        minimum=0,
    )

    protocol = str(
        body.get(
            "protocol",
            DEFAULT_PROTOCOL,
        )
        or DEFAULT_PROTOCOL
    ).strip()

    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL

    fingerprint = str(
        body.get(
            "fingerprint",
            DEFAULT_FINGERPRINT,
        )
        or DEFAULT_FINGERPRINT
    ).strip().lower()

    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    fragment = str(
        body.get(
            "fragment",
            "off",
        )
        or "off"
    ).strip().lower()

    allowed_fragments = {
        "off",
        "safe",
        "balanced",
        "aggressive",
    }

    if fragment not in allowed_fragments:
        fragment = "off"

    raw_clean = body.get("clean_ips") or body.get("clean_ip") or ""
    if isinstance(raw_clean, list):
        clean_ips = [str(x).strip() for x in raw_clean if str(x).strip()]
    else:
        clean_ips = [x.strip() for x in str(raw_clean).replace(",", "\n").splitlines() if x.strip()]
    alarm_enabled = bool(body.get("alarm_enabled", False))
    category_id = str(body.get("category_id") or "0")
    if category_id not in CATEGORIES:
        category_id = "0"
    config_count = safe_int(body.get("config_count", 1), minimum=1, maximum=40)
    cat = CATEGORIES.get(category_id) or {}
    if cat.get("limit_bytes") and limit_bytes <= 0:
        limit_bytes = int(cat["limit_bytes"])
    if cat.get("expires_days") and expires_days <= 0:
        expires_days = int(cat["expires_days"])
        expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat() if expires_days > 0 else None
    if cat.get("connection_limit") and connection_limit <= 0:
        connection_limit = int(cat["connection_limit"])
    if cat.get("speed_limit_bytes") and speed_bytes <= 0:
        speed_bytes = int(cat["speed_limit_bytes"])
    if cat.get("ip_limit") and ip_limit <= 0:
        ip_limit = int(cat["ip_limit"])
    if cat.get("clean_ips") and not clean_ips:
        clean_ips = list(cat["clean_ips"])
    if cat.get("single_user"):
        if ip_limit == 0: ip_limit = 1
        if connection_limit == 0: connection_limit = 1
    label_val = body.get("label", "")
    if cat.get("random_name") or not str(label_val).strip():
        label_val = random_config_name()
    else:
        label_val = sanitize_config_name(str(label_val))

    uid, link = await make_link(
        label=label_val,
        limit_bytes=limit_bytes,
        expires_at=expires_at,
        note=body.get(
            "note",
            "",
        ),
        sub_id=body.get(
            "sub_id"
        ),
        protocol=protocol,
        fingerprint=fingerprint,
        alpn=body.get(
            "alpn",
            DEFAULT_ALPN_BY_PROTOCOL.get(
                protocol,
                "http/1.1",
            ),
        ),
        port=port,
        ip_limit=ip_limit,
        speed_limit_bytes=speed_bytes,
        connection_limit=connection_limit,
        fragment=fragment,
        clean_ips=clean_ips,
        alarm_enabled=alarm_enabled,
        category_id=category_id,
        config_count=config_count,
    )

    host = get_host(request)

    result = {
        **get_link_info(
            link,
            uid,
            host,
        ),
        "ok": True,
    }

    return result


# ============================================================
# AUTO CREATE
# ============================================================

@app.post("/api/links/auto")
async def create_auto_link(
    request: Request,
    _=Depends(require_auth),
):
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict): body = {}
    host = get_host(request)
    protocol = normalize_protocol(body.get("protocol", DEFAULT_PROTOCOL))
    profile = str(body.get("profile", "balanced")).strip().lower()
    profiles = {
        "normal": {"ip":0,"conn":0,"speed":0,"fp":"chrome","fragment":"off"},
        "balanced": {"ip":2,"conn":4,"speed":0,"fp":"chrome","fragment":"safe"},
        "gaming": {"ip":1,"conn":2,"speed":0,"fp":"chrome","fragment":"safe"},
        "maximum": {"ip":0,"conn":0,"speed":0,"fp":"randomized","fragment":"safe"},
    }
    cfg = profiles.get(profile, profiles["balanced"])
    config_count = safe_int(body.get("config_count", 1), minimum=1, maximum=40)
    uid, link = await make_link(
        label=auto_config_name(), limit_bytes=0, expires_at=None,
        ip_limit=cfg["ip"], speed_limit_bytes=cfg["speed"], connection_limit=cfg["conn"],
        note=f"Auto generated by PXPanel | profile={profile}",
        protocol=protocol, fingerprint=cfg["fp"],
        alpn=DEFAULT_ALPN_BY_PROTOCOL.get(protocol, ""), port=443, fragment=cfg["fragment"],
        config_count=config_count,
    )
    link["security_profile"] = profile
    result = {**get_link_info(link, uid, host), "ok": True, "profile": profile}
    log_activity("link", f"کانفیگ خودکار «{link['label']}» با {PROTOCOL_LABELS.get(protocol, protocol)} ساخته شد", "ok")
    return result


# ============================================================
# LIST LINKS
# ============================================================

@app.get("/api/protocols")
async def api_protocols(request: Request):
    require_auth(request)
    return {"protocols": [{"id": p, "label": PROTOCOL_LABELS.get(p, p)} for p in PROTOCOLS], "default": DEFAULT_PROTOCOL}


@app.get("/api/links")
async def list_links(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(request)

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    result = []

    for uid, link in snapshot.items():

        info = get_link_info(
            link,
            uid,
            host,
        )

        result.append(
            {
                **info,

                "created_at":
                    link.get(
                        "created_at"
                    ),

                "expired":
                    is_link_expired(
                        link
                    ),

                "sub_url":
                    f"https://{host}/sub/{uid}",

                "info_url":
                    f"https://{host}/info/{uid}",

                "connected_ips":
                    len(
                        unique_ips_for_uuid(
                            uid
                        )
                    ),
            }
        )

    result = sorted(
        result,
        key=lambda item: (
            -int(item.get("sort_order") or 0),
            str(item.get("created_at") or ""),
        ),
    )

    return {
        "links": result
    }


# ============================================================
# LINK INFO API
# ============================================================

@app.get("/api/links/{uid}/info")
async def link_info_api(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    async with LINKS_LOCK:

        link = LINKS.get(uid)

        if not link:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        snapshot = dict(link)

    host = get_host(request)

    return {
        "ok": True,
        **get_link_info(
            snapshot,
            uid,
            host,
        ),
    }


# ============================================================
# UPDATE LINK
# ============================================================



@app.post("/api/links/reorder")
async def reorder_links(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="JSON نامعتبر")
    order = body.get("order") or body.get("ids") or []
    if not isinstance(order, list):
        raise HTTPException(400, detail="order باید آرایه باشد")
    # first item = highest priority
    n = len(order)
    async with LINKS_LOCK:
        for i, uid in enumerate(order):
            uid = str(uid)
            if uid in LINKS:
                LINKS[uid]["sort_order"] = n - i
    await save_state()
    return {"ok": True, "count": n}


@app.post("/api/links/bulk-delete")
async def bulk_delete_links(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="JSON نامعتبر")
    ids = body.get("ids") or []
    if not isinstance(ids, list) or not ids:
        raise HTTPException(400, detail="ids خالی است")
    deleted = []
    for uid in ids:
        uid = str(uid)
        if uid in LINKS:
            await remove_link(uid)
            deleted.append(uid)
    log_activity("link", f"حذف گروهی {len(deleted)} کانفیگ", "warn")
    return {"ok": True, "deleted": len(deleted)}


@app.post("/api/links/bulk-category")
async def bulk_category(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="JSON نامعتبر")
    ids = body.get("ids") or []
    cid = str(body.get("category_id") or "0")
    if cid not in CATEGORIES:
        cid = "0"
    n = 0
    async with LINKS_LOCK:
        for uid in ids:
            uid = str(uid)
            if uid in LINKS:
                LINKS[uid]["category_id"] = cid
                n += 1
    await save_state()
    return {"ok": True, "updated": n}


@app.patch("/api/links/{uid}")
async def update_link(
    uid: str,
    request: Request,
    token=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="اطلاعات نامعتبر است",
        )

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=400,
            detail="اطلاعات نامعتبر است",
        )

    # برای همه: نام، یادداشت، پورت و تنظیمات فنی فقط نمایشی هستند
    for _k in (
        "label", "note", "port",
        "fingerprint", "alpn", "protocol", "fragment",
    ):
        body.pop(_k, None)

    async with LINKS_LOCK:

        if uid not in LINKS:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        link = LINKS[uid]

        old_sub = link.get(
            "sub_id"
        )

        label = link.get(
            "label",
            uid,
        )

        if "active" in body:
            link["active"] = bool(
                body["active"]
            )

        if "category_id" in body:
            cid = str(body.get("category_id") or "0")
            if cid not in CATEGORIES:
                cid = "0"
            link["category_id"] = cid

        if "sort_order" in body:
            try:
                link["sort_order"] = int(body.get("sort_order") or 0)
            except Exception:
                pass

        if "label" in body:

            value = str(
                body["label"]
            ).strip()

            if value:
                link["label"] = value[:60]

        if "note" in body:

            link["note"] = str(
                body.get(
                    "note",
                    "",
                )
            )[:500]

        if "reset_usage" in body:

            if body.get(
                "reset_usage"
            ):
                link[
                    "used_bytes"
                ] = 0


        if "limit_value" in body:

            value = safe_float(
                body.get(
                    "limit_value",
                    0,
                )
            )

            unit = str(
                body.get(
                    "limit_unit",
                    "GB",
                )
                or "GB"
            )

            link[
                "limit_bytes"
            ] = (
                0
                if value <= 0
                else parse_size_to_bytes(
                    value,
                    unit,
                )
            )

        if "expires_days" in body:

            days = safe_int(
                body.get(
                    "expires_days",
                    0,
                ),
                minimum=0,
            )

            link[
                "expires_at"
            ] = (
                (
                    datetime.now()
                    + timedelta(
                        days=days
                    )
                ).isoformat()
                if days > 0
                else None
            )

        if "fingerprint" in body:

            fingerprint = str(
                body.get(
                    "fingerprint",
                    DEFAULT_FINGERPRINT,
                )
            ).strip().lower()

            link[
                "fingerprint"
            ] = (
                fingerprint
                if fingerprint in FINGERPRINTS
                else DEFAULT_FINGERPRINT
            )

        if "alpn" in body:

            link["alpn"] = str(
                body.get(
                    "alpn",
                    "",
                )
            )[:100]

        if "port" in body:

            p = safe_int(
                body.get(
                    "port",
                    DEFAULT_PORT,
                ),
                default=DEFAULT_PORT,
                minimum=MIN_PORT,
                maximum=MAX_PORT,
            )

            link["port"] = p

        if "ip_limit" in body:

            link["ip_limit"] = safe_int(
                body.get(
                    "ip_limit",
                    0,
                ),
                minimum=0,
            )

        if "connection_limit" in body:

            link[
                "connection_limit"
            ] = safe_int(
                body.get(
                    "connection_limit",
                    0,
                ),
                minimum=0,
            )

        if "speed_limit_value" in body:

            speed_value = safe_float(
                body.get(
                    "speed_limit_value",
                    0,
                )
            )

            speed_unit = str(
                body.get(
                    "speed_limit_unit",
                    "MBIT",
                )
                or "MBIT"
            )

            link[
                "speed_limit_bytes"
            ] = (
                0
                if speed_value <= 0
                else parse_speed_to_bytes(
                    speed_value,
                    speed_unit,
                )
            )

        if "protocol" in body:

            protocol = str(
                body.get(
                    "protocol",
                    DEFAULT_PROTOCOL,
                )
            ).strip()

            link["protocol"] = (
                protocol
                if protocol in PROTOCOLS
                else DEFAULT_PROTOCOL
            )

        if "fragment" in body:

            fragment = str(
                body.get(
                    "fragment",
                    "off",
                )
                or "off"
            ).strip().lower()

            if fragment not in {
                "off",
                "safe",
                "balanced",
                "aggressive",
            }:
                fragment = "off"

            link["fragment"] = fragment

        if "sub_id" in body:

            link[
                "sub_id"
            ] = (
                body.get(
                    "sub_id"
                )
                or None
            )

        new_sub = body.get(
            "sub_id",
            "UNCHANGED",
        )

    if new_sub != "UNCHANGED":

        async with SUBS_LOCK:

            if (
                old_sub
                and old_sub in SUBS
            ):

                ids = SUBS[
                    old_sub
                ].get(
                    "link_ids",
                    [],
                )

                if uid in ids:
                    ids.remove(uid)

            if (
                new_sub
                and new_sub in SUBS
            ):

                ids = SUBS[
                    new_sub
                ].setdefault(
                    "link_ids",
                    [],
                )

                if uid not in ids:
                    ids.append(uid)

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» "
            f"ویرایش شد"
        ),
        "info",
    )

    return {
        "ok": True
    }


# ============================================================
# RESET USAGE
# ============================================================

@app.post(
    "/api/links/{uid}/reset-usage"
)
async def reset_link_usage(
    uid: str,
    _=Depends(require_auth),
):

    async with LINKS_LOCK:

        link = LINKS.get(uid)

        if not link:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        link["used_bytes"] = 0

        label = link.get(
            "label",
            uid,
        )

    await save_state()

    log_activity(
        "link",
        (
            f"مصرف کانفیگ "
            f"«{label}» ریست شد"
        ),
        "info",
    )

    return {
        "ok": True,
        "uuid": uid,
        "used_bytes": 0,
    }


# ============================================================
# LINK ACTION
# ============================================================

@app.post(
    "/api/links/{uid}/action"
)
async def link_action(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    action = str(
        body.get(
            "action",
            "",
        )
    ).strip().lower()

    if action == "reset":

        await reset_link_usage(
            uid,
            _
        )

        return {
            "ok": True,
            "action": "reset",
        }

    if action == "enable":

        result = await set_link_active(
            uid,
            True,
        )

        if result is None:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        return {
            "ok": True,
            "action": "enable",
        }

    if action == "disable":

        result = await set_link_active(
            uid,
            False,
        )

        if result is None:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        return {
            "ok": True,
            "action": "disable",
        }

    raise HTTPException(
        status_code=400,
        detail="unknown action",
    )


# ============================================================
# DELETE LINK
# ============================================================

@app.delete("/api/links/{uid}")
async def delete_link(
    uid: str,
    _=Depends(require_auth),
):

    label = await remove_link(uid)

    if label is None:
        raise HTTPException(
            status_code=404,
            detail="link not found",
        )

    return {
        "ok": True,
        "deleted": uid,
    }




def subscription_metadata_headers(used_bytes: int, limit_bytes: int, expires_at, host: str, info_url: str, title: str):
    """Standard subscription headers understood by v2rayNG/v2rayN/Hiddify and similar clients."""
    used_bytes = max(0, int(used_bytes or 0))
    limit_bytes = max(0, int(limit_bytes or 0))

    expire_unix = 0
    if expires_at:
        try:
            dt = datetime.fromisoformat(str(expires_at))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=IRAN_TZ) if IRAN_TZ else dt
            expire_unix = max(0, int(dt.timestamp()))
        except Exception:
            expire_unix = 0

    userinfo = f"upload=0; download={used_bytes}; total={limit_bytes}; expire={expire_unix}"

    return {
        "profile-title": quote(title, safe=""),
        "profile-web-page-url": info_url,
        "support-url": SUPPORT_URL,
        "profile-update-interval": "12",
        "subscription-userinfo": userinfo,
        "content-disposition": 'inline; filename="subscription.txt"',
    }

# ============================================================
# SINGLE SUB
# ============================================================

@app.get("/sub/{uuid}")
async def subscription_single(
    uuid: str,
    request: Request,
):

    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link):
        raise HTTPException(
            status_code=404,
            detail="not found or inactive",
        )

    host = get_host(request)
    clean_ips = link.get("clean_ips") or []
    used = int(link.get("used_bytes", 0) or 0)
    limit = int(link.get("limit_bytes", 0) or 0)
    remaining = max(0, limit - used) if limit > 0 else 0
    volume_text = f"{fmt_bytes(used)}/{fmt_bytes(limit)} (باقی {fmt_bytes(remaining)})" if limit > 0 else f"{fmt_bytes(used)}/∞"
    expires_at = link.get("expires_at")
    if expires_at:
        try:
            exp_dt = datetime.fromisoformat(str(expires_at))
            now_dt = datetime.now(exp_dt.tzinfo) if getattr(exp_dt, "tzinfo", None) else datetime.now()
            secs = int((exp_dt - now_dt).total_seconds())
            if secs <= 0:
                time_text = "منقضی"
            else:
                days, rem = divmod(secs, 86400)
                hours, rem = divmod(rem, 3600)
                mins = rem // 60
                time_text = f"{days}د {hours}س" if days else (f"{hours}س {mins}د" if hours else f"{mins}د")
        except Exception:
            time_text = str(expires_at)[:16]
    else:
        time_text = "∞"
    label = str(link.get("label") or "Config")
    stats_remark = f"{label} | {volume_text} | {time_text}"
    stats_line = generate_vless_link(uuid, "0.0.0.0", remark=stats_remark, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=link.get("port", DEFAULT_PORT))
    lines = [stats_line]
    used_names = set()
    cfg_count = max(1, min(40, int(link.get("config_count") or 1)))
    if clean_ips:
        hosts = list(clean_ips)
        while len(hosts) < cfg_count:
            hosts.extend(clean_ips)
        hosts = hosts[:cfg_count]
        for cip in hosts:
            name = random_config_name(used_names)
            used_names.add(name)
            lines.append(generate_vless_link(uuid, cip, remark=name, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=link.get("port", DEFAULT_PORT)))
    else:
        for i in range(cfg_count):
            name = random_config_name(used_names)
            used_names.add(name)
            lines.append(generate_vless_link(uuid, host, remark=name, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=link.get("port", DEFAULT_PORT)))
    content = base64.b64encode("\n".join(lines).encode()).decode()
    profile_title = f"0.0.0.0 | {stats_remark}"
    headers = subscription_metadata_headers(
        used,
        limit,
        link.get("expires_at"),
        host,
        f"https://{host}/info/{uuid}",
        profile_title,
    )

    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers=headers,
    )

# ============================================================
# SUB ALL
# ============================================================

@app.get("/sub-all")
async def subscription_all(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(request)

    async with LINKS_LOCK:

        lines = [
            vless_link_for_link(
                link,
                uid,
                host,
            )

            for uid, link
            in LINKS.items()

            if is_link_allowed(link)
        ]

    content = (
        base64
        .b64encode(
            "\n".join(
                lines
            ).encode()
        )
        .decode()
    )

    return Response(
        content=content,
        media_type="text/plain",
    )


# ============================================================
# INFO PAGE
# ============================================================

@app.get(
    "/info/{uid}",
    response_class=HTMLResponse,
)
async def info_page(
    uid: str,
    request: Request,
):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            return HTMLResponse(
                '<html lang="fa" dir="rtl"><body style="margin:0;background:#030712;color:#fff;font-family:sans-serif;padding:40px"><h2>کانفیگ پیدا نشد</h2></body></html>',
                status_code=404,
            )
        snapshot = dict(link)

    host = get_host(request)
    vless_url = vless_link_for_link(snapshot, uid, host)
    sub_url = f"https://{host}/sub/{uid}"

    used = int(snapshot.get("used_bytes", 0) or 0)
    limit = int(snapshot.get("limit_bytes", 0) or 0)
    if limit > 0:
        usage_percent = max(0, min(100, round((used / limit) * 100, 1)))
        remaining_value = fmt_bytes(max(0, limit - used))
        total_value = fmt_bytes(limit)
    else:
        usage_percent = 0
        remaining_value = "نامحدود"
        total_value = "نامحدود"

    expires_at = snapshot.get("expires_at")
    if expires_at:
        try:
            expiry_dt = datetime.fromisoformat(str(expires_at))
            now_dt = datetime.now(expiry_dt.tzinfo) if expiry_dt.tzinfo else datetime.now()
            seconds = int((expiry_dt - now_dt).total_seconds())
            if seconds <= 0:
                expiry_remaining = "منقضی شده"
            else:
                days, rem = divmod(seconds, 86400)
                hours, rem = divmod(rem, 3600)
                minutes, _ = divmod(rem, 60)
                expiry_remaining = (
                    f"{days} روز" if days else
                    f"{hours} ساعت" if hours else
                    f"{minutes} دقیقه"
                )
        except Exception:
            expiry_remaining = "نامشخص"
        expiry_display = str(expires_at)
    else:
        expiry_remaining = "نامحدود"
        expiry_display = "نامحدود"

    status_text = "فعال" if is_link_allowed(snapshot) else "غیرفعال"
    label = escape_html(snapshot.get("label", "AHB Panel"))
    uid_e = escape_html(uid)
    app_version = escape_html(str(APP_VERSION))
    used_e = escape_html(fmt_bytes(used))
    total_e = escape_html(total_value)
    remaining_e = escape_html(remaining_value)
    expiry_e = escape_html(expiry_display)
    expiry_remaining_e = escape_html(expiry_remaining)
    ip_limit = "نامحدود" if not snapshot.get("ip_limit", 0) else str(snapshot.get("ip_limit"))
    conn_limit = "نامحدود" if not snapshot.get("connection_limit", 0) else str(snapshot.get("connection_limit"))
    speed_limit = "نامحدود" if not snapshot.get("speed_limit_bytes", 0) else fmt_bytes(snapshot.get("speed_limit_bytes", 0)) + "/s"
    protocol = escape_html(snapshot.get("protocol", "vless-ws"))
    fingerprint = escape_html(snapshot.get("fingerprint", "chrome"))
    vless_e = escape_html(vless_url)
    sub_e = escape_html(sub_url)
    ring_offset = f"{339.29 - (339.29 * min(usage_percent, 100) / 100):.1f}"
    unique_ips = len(unique_ips_for_uuid(uid))

    info_html = f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#030817">
<title>{label} | AHB PANEL</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script>
<style>
*{{box-sizing:border-box}}
:root{{--bg:#020817;--card:rgba(8,20,43,.72);--card2:rgba(10,27,55,.62);--line:rgba(112,170,255,.15);--text:#f7fbff;--muted:#91a4c4;--blue:#2495ff;--purple:#a855f7;--pink:#ec4899;--green:#16e6a0}}
html,body{{margin:0;min-height:100%;background:var(--bg);color:var(--text);font-family:'Vazirmatn',system-ui,sans-serif}}
body{{overflow-x:hidden;background:radial-gradient(900px 500px at 10% -10%,rgba(0,145,255,.22),transparent 58%),radial-gradient(700px 500px at 100% 12%,rgba(183,50,255,.18),transparent 58%),radial-gradient(700px 500px at 55% 100%,rgba(0,220,175,.08),transparent 60%),#020817}}
body:before{{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.018) 1px,transparent 1px);background-size:42px 42px;mask-image:linear-gradient(to bottom,black,transparent 85%)}}
.wrap{{width:min(1120px,calc(100% - 24px));margin:auto;padding:22px 0 92px}}
.top{{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:18px}}
.brand{{display:flex;align-items:center;gap:12px}}
.brand-mark{{font-size:38px;line-height:1;font-weight:900;font-style:italic;letter-spacing:-4px;background:linear-gradient(110deg,#12a8ff,#6d72ff,#db3eff);-webkit-background-clip:text;background-clip:text;color:transparent;text-shadow:0 0 35px rgba(42,150,255,.25)}}
.brand-name{{font-size:12px;letter-spacing:4px;font-weight:900;color:#e8f1ff}}
.brand-sub{{font-size:10px;color:#8497b8;margin-top:2px}}
.top-actions{{display:flex;gap:8px}}
.icon-btn{{width:44px;height:44px;border-radius:15px;border:1px solid rgba(122,170,255,.13);background:rgba(9,24,51,.72);color:#b7c8e5;display:grid;place-items:center;backdrop-filter:blur(16px)}}
.card{{border:1px solid var(--line);background:linear-gradient(145deg,rgba(12,31,64,.82),rgba(5,16,36,.72));border-radius:25px;box-shadow:0 20px 80px rgba(0,0,0,.24);backdrop-filter:blur(20px)}}
.hero{{position:relative;overflow:hidden;padding:25px;background:radial-gradient(circle at 0% 100%,rgba(0,157,255,.34),transparent 48%),radial-gradient(circle at 100% 0%,rgba(208,37,255,.3),transparent 46%),linear-gradient(135deg,rgba(8,40,79,.92),rgba(21,10,59,.92))}}
.hero:after{{content:"";position:absolute;width:260px;height:260px;right:18%;top:-150px;border-radius:50%;background:rgba(255,255,255,.035);filter:blur(2px)}}
.hero-grid{{position:relative;z-index:1;display:grid;grid-template-columns:1fr 180px;gap:22px;align-items:center}}
.badge{{display:inline-flex;align-items:center;gap:7px;padding:8px 13px;border-radius:999px;background:linear-gradient(135deg,#10c98a,#06b981);color:#001b16;font-size:12px;font-weight:900;box-shadow:0 0 30px rgba(16,201,138,.18)}}
.hero h1{{margin:15px 0 5px;font-size:32px;line-height:1.2;font-weight:900}}
.hero-expire{{font-size:12px;color:#b5c4df}}
.vip{{margin-top:16px;display:inline-flex;align-items:center;gap:10px;padding:9px 14px;border-radius:14px;border:1px solid rgba(120,165,255,.18);background:rgba(4,14,34,.32);color:#c8d7f0;font-size:11px}}
.vip b{{padding:5px 10px;border-radius:10px;background:linear-gradient(135deg,#f7b733,#f59e0b);color:#211100}}
.ring{{width:154px;height:154px;position:relative;margin:auto}}
.ring svg{{width:100%;height:100%;transform:rotate(-90deg);filter:drop-shadow(0 0 9px rgba(15,232,166,.25))}}
.ring-track{{fill:none;stroke:rgba(255,255,255,.11);stroke-width:10}}
.ring-progress{{fill:none;stroke:url(#rg);stroke-width:10;stroke-linecap:round;stroke-dasharray:339.29;stroke-dashoffset:{ring_offset}}}
.ring-center{{position:absolute;inset:0;display:grid;place-items:center;text-align:center}}
.ring-number{{font-size:28px;font-weight:900}}
.ring-label{{font-size:10px;color:#9fb1ce;margin-top:3px}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:15px}}
.stat{{padding:19px 16px;border-radius:20px}}
.stat-icon{{width:39px;height:39px;border-radius:13px;display:grid;place-items:center;background:rgba(20,130,255,.11);color:#24a1ff;border:1px solid rgba(36,161,255,.15)}}
.stat:nth-child(2) .stat-icon{{color:#b06cff;background:rgba(168,85,247,.11);border-color:rgba(168,85,247,.15)}}
.stat:nth-child(3) .stat-icon{{color:#ffb52e;background:rgba(245,158,11,.11);border-color:rgba(245,158,11,.15)}}
.stat:nth-child(4) .stat-icon{{color:#ff56b5;background:rgba(236,72,153,.11);border-color:rgba(236,72,153,.15)}}
.stat-title{{margin-top:13px;font-size:11px;color:#8ea1c0}}
.stat-value{{margin-top:5px;font-size:18px;font-weight:900;word-break:break-word}}
.stat-small{{margin-top:3px;font-size:9px;color:#647998}}
.section{{margin-top:15px;padding:21px}}
.section-title{{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:16px}}
.section-title h2{{font-size:15px;margin:0;font-weight:900}}
.section-title span{{font-size:9px;color:#647998}}
.connection{{display:grid;grid-template-columns:1fr 230px;gap:18px}}
.fields{{display:grid;gap:9px}}
.field{{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 14px;border-radius:15px;background:rgba(3,12,29,.45);border:1px solid rgba(112,170,255,.08)}}
.field-label{{color:#7186a7;font-size:10px;white-space:nowrap}}
.field-value{{font-size:11px;font-weight:700;word-break:break-all;text-align:left;direction:ltr;color:#e5efff}}
.qr-box{{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:15px;border-radius:20px;background:rgba(3,12,29,.45);border:1px solid rgba(112,170,255,.08)}}
#qr-main{{background:#fff;border-radius:14px;padding:8px;line-height:0}}
#qr-main img{{display:block;width:150px;height:150px}}
.btn{{border:0;border-radius:13px;padding:11px 14px;font:inherit;font-size:11px;font-weight:900;cursor:pointer;color:white;background:linear-gradient(100deg,#078cff,#9844ff);box-shadow:0 9px 30px rgba(38,115,255,.18)}}
.btn.secondary{{background:linear-gradient(100deg,#8746ff,#d736ff)}}
.qr-btn{{width:100%;margin-top:10px}}
.link-row{{display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center;padding:12px;border-radius:16px;background:rgba(3,12,29,.45);border:1px solid rgba(112,170,255,.08);margin-top:10px}}
.link-text{{font-size:10px;line-height:1.8;color:#a5b7ff;word-break:break-all;direction:ltr;text-align:left;font-family:ui-monospace,Consolas,monospace}}
.servers{{display:grid;grid-template-columns:repeat(4,1fr);gap:11px}}
.server{{padding:14px;border-radius:17px;background:rgba(3,12,29,.48);border:1px solid rgba(112,170,255,.08);display:flex;align-items:center;justify-content:space-between;gap:8px}}
.server-main{{display:flex;align-items:center;gap:9px}}
.flag{{font-size:22px}}
.server-name{{font-size:11px;font-weight:800}}
.server-status{{margin-top:3px;font-size:9px;color:#12df99;display:flex;align-items:center;gap:5px}}
.server-status i{{width:5px;height:5px;border-radius:50%;background:#12df99;box-shadow:0 0 9px #12df99}}
.server-arrow{{color:#7890b5}}
.footer{{text-align:center;color:#687c9e;font-size:10px;padding:20px 0 7px}}
.bottom{{position:fixed;z-index:30;bottom:0;left:0;right:0;background:rgba(3,11,27,.9);border-top:1px solid rgba(100,155,240,.12);backdrop-filter:blur(22px)}}
.bottom-inner{{width:min(650px,100%);margin:auto;display:grid;grid-template-columns:repeat(4,1fr)}}
.nav{{padding:11px 6px 9px;text-align:center;color:#7890b5;font-size:9px;font-weight:700}}
.nav.active{{color:#39a8ff}}
.nav svg{{display:block;margin:0 auto 4px}}
.modal{{position:fixed;inset:0;z-index:100;display:none;align-items:center;justify-content:center;padding:18px;background:rgba(0,0,0,.78);backdrop-filter:blur(12px)}}
.modal.show{{display:flex}}
.modal-card{{width:min(360px,100%);padding:22px;border-radius:25px;background:#071126;border:1px solid rgba(112,170,255,.2);text-align:center}}
#qr-modal{{display:inline-block;background:white;padding:10px;border-radius:16px;line-height:0;margin:12px 0}}
@media(max-width:800px){{.hero-grid{{grid-template-columns:1fr 145px}}.connection{{grid-template-columns:1fr 205px}}.servers{{grid-template-columns:repeat(2,1fr)}}}}
@media(max-width:620px){{.wrap{{width:min(100% - 16px,1120px);padding-top:13px}}.brand-mark{{font-size:32px}}.hero{{padding:19px}}.hero-grid{{grid-template-columns:1fr;gap:14px}}.ring{{width:130px;height:130px;margin:0 auto}}.hero h1{{font-size:27px}}.stats{{grid-template-columns:repeat(2,1fr);gap:9px}}.stat{{padding:14px}}.stat-value{{font-size:15px}}.connection{{grid-template-columns:1fr}}.qr-box{{order:-1}}#qr-main img{{width:135px;height:135px}}.servers{{grid-template-columns:repeat(2,1fr)}}.section{{padding:16px}}.field{{align-items:flex-start;flex-direction:column;gap:5px}}.field-value{{width:100%}}.link-row{{grid-template-columns:1fr}}.link-row .btn{{width:100%}}}}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div class="brand">
      <div>
        <div class="brand-mark">AHB</div>
        <div class="brand-name">PANEL</div>
      </div>
      <div class="brand-sub">اتصال سریع، بدون محدودیت</div>
    </div>
    <div class="top-actions">
      <button class="icon-btn" aria-label="اعلان"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M10 21h4"/></svg></button>
      <button class="icon-btn" aria-label="منو"><svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M4 6h16M4 12h16M4 18h16"/></svg></button>
    </div>
  </header>

  <section class="card hero">
    <div class="hero-grid">
      <div>
        <span class="badge"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M20 6 9 17l-5-5"/></svg>{status_text} اشتراک</span>
        <h1>طرح ویژه</h1>
        <div class="hero-expire">تاریخ انقضا: <b>{expiry_e}</b></div>
        <div class="vip"><b>♛ VIP</b><span>دسترسی کامل به تمام سرورها</span></div>
      </div>
      <div class="ring">
        <svg viewBox="0 0 132 132" aria-label="درصد مصرف">
          <defs><linearGradient id="rg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#13e5a2"/><stop offset="1" stop-color="#07bdfd"/></linearGradient></defs>
          <circle class="ring-track" cx="66" cy="66" r="54"/>
          <circle class="ring-progress" cx="66" cy="66" r="54"/>
        </svg>
        <div class="ring-center"><div><div class="ring-number">{usage_percent}%</div><div class="ring-label">مصرف شده</div></div></div>
      </div>
    </div>
  </section>

  <section class="stats">
    <div class="card stat"><div class="stat-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M3 15a4 4 0 0 1 4-4h1a5 5 0 0 1 9.8-1A3.5 3.5 0 1 1 18 17H7a4 4 0 0 1-4-2z"/><path d="M12 12v7M9 16l3 3 3-3"/></svg></div><div class="stat-title">حجم مصرفی</div><div class="stat-value">{used_e}</div><div class="stat-small">از {total_e}</div></div>
    <div class="card stat"><div class="stat-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 19V5M7 10l5-5 5 5"/><path d="M5 19h14"/></svg></div><div class="stat-title">حجم باقیمانده</div><div class="stat-value">{remaining_e}</div><div class="stat-small">از {total_e}</div></div>
    <div class="card stat"><div class="stat-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></div><div class="stat-title">زمان باقی‌مانده</div><div class="stat-value">{expiry_remaining_e}</div><div class="stat-small">اشتراک فعلی</div></div>
    <div class="card stat"><div class="stat-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="m13 2-2 8H5l6 4-2 8 2-3 8-11h-6l2-6z"/></svg></div><div class="stat-title">سرعت اتصال</div><div class="stat-value">{escape_html(speed_limit)}</div><div class="stat-small">بدون محدودیت</div></div>
  </section>

  <section class="card section">
    <div class="section-title"><h2>اطلاعات اتصال</h2><span>Connection Info</span></div>
    <div class="connection">
      <div class="fields">
        <div class="field"><span class="field-label">نام کاربری</span><span class="field-value">{label}</span></div>
        <div class="field"><span class="field-label">شناسه</span><span class="field-value">{uid_e}</span></div>
        <div class="field"><span class="field-label">آدرس سرور</span><span class="field-value">{escape_html(host)}</span></div>
        <div class="field"><span class="field-label">پروتکل</span><span class="field-value">{protocol}</span></div>
        <div class="field"><span class="field-label">پورت</span><span class="field-value">{escape_html(snapshot.get("port", 443))}</span></div>
      </div>
      <div class="qr-box">
        <div id="qr-main"></div>
        <button class="btn qr-btn" type="button" onclick="openQr()">▦ &nbsp; دانلود QR Code</button>
      </div>
    </div>
  </section>

  <section class="card section">
    <div class="section-title"><h2>لینک اشتراک</h2><span>Subscription Link</span></div>
    <div class="link-row"><div class="link-text" id="subText">{sub_e}</div><button class="btn secondary" onclick="copyText('subText',this)">کپی لینک</button></div>
    <div class="link-row"><div class="link-text" id="vlessText">{vless_e}</div><button class="btn" onclick="copyText('vlessText',this)">کپی کانفیگ</button></div>
  </section>

  <section class="card section">
    <div class="section-title"><h2>سرورهای فعال</h2><span>{unique_ips} اتصال ثبت‌شده</span></div>
    <div class="servers">
      <div class="server"><div class="server-main"><span class="flag">🇮🇷</span><div><div class="server-name">ایران</div><div class="server-status"><i></i> فعال</div></div></div><span class="server-arrow">‹</span></div>
      <div class="server"><div class="server-main"><span class="flag">🇩🇪</span><div><div class="server-name">آلمان</div><div class="server-status"><i></i> فعال</div></div></div><span class="server-arrow">‹</span></div>
      <div class="server"><div class="server-main"><span class="flag">🇺🇸</span><div><div class="server-name">آمریکا</div><div class="server-status"><i></i> فعال</div></div></div><span class="server-arrow">‹</span></div>
      <div class="server"><div class="server-main"><span class="flag">🇹🇷</span><div><div class="server-name">ترکیه</div><div class="server-status"><i></i> فعال</div></div></div><span class="server-arrow">‹</span></div>
    </div>
  </section>

  <div class="footer">بهترین انتخاب برای اتصال پایدار &nbsp;·&nbsp; <b>AHB PANEL</b> &nbsp;·&nbsp; نسخه {app_version}</div>
</div>

<nav class="bottom"><div class="bottom-inner">
  <div class="nav"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m3 10 9-7 9 7v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"/><path d="M9 21v-7h6v7"/></svg>خانه</div>
  <div class="nav active"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="9"/><path d="M12 10v6M12 7h.01"/></svg>اطلاعات</div>
  <div class="nav"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z"/><path d="M19.4 15a1.8 1.8 0 0 0 .36 2l.05.05-1.42 1.42-.05-.05a1.8 1.8 0 0 0-2-.36 1.8 1.8 0 0 0-1.1 1.65v.08h-2v-.08a1.8 1.8 0 0 0-1.1-1.65 1.8 1.8 0 0 0-2 .36l-.05.05-1.42-1.42.05-.05a1.8 1.8 0 0 0 .36-2A1.8 1.8 0 0 0 7.4 14H7.33v-2h.08a1.8 1.8 0 0 0 1.65-1.1 1.8 1.8 0 0 0-.36-2l-.05-.05 1.42-1.42.05.05a1.8 1.8 0 0 0 2 .36A1.8 1.8 0 0 0 13.2 6.2v-.08h2v.08a1.8 1.8 0 0 0 1.1 1.65 1.8 1.8 0 0 0 2-.36l.05-.05 1.42 1.42-.05.05a1.8 1.8 0 0 0-.36 2 1.8 1.8 0 0 0 1.65 1.1h.08v2h-.08A1.8 1.8 0 0 0 19.4 15z"/></svg>تنظیمات</div>
  <div class="nav"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16v12H4z"/><path d="m4 5 8 6 8-6"/><path d="M8 20h8"/></svg>پشتیبانی</div>
</div></nav>

<div id="modal" class="modal" onclick="if(event.target===this)closeQr()"><div class="modal-card"><button class="icon-btn" style="margin-right:auto" onclick="closeQr()">✕</button><h3 style="margin:12px 0 4px">QR Code اتصال</h3><p style="font-size:10px;color:#7d90b0">با دوربین یا برنامه کلاینت اسکن کنید</p><div id="qr-modal"></div><div style="font-size:9px;color:#91a4c4;word-break:break-all;direction:ltr">{vless_e}</div></div></div>

<script>
const vlessUrl = {vless_url!r};
function copyText(id,btn){{const el=document.getElementById(id);if(!el)return;const text=el.textContent.trim();const done=()=>{{const old=btn.textContent;btn.textContent='✓ کپی شد';setTimeout(()=>btn.textContent=old,1400)}};if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(text).then(done).catch(()=>fallback(text,done));else fallback(text,done)}}
function fallback(text,done){{const t=document.createElement('textarea');t.value=text;t.style.position='fixed';t.style.opacity='0';document.body.appendChild(t);t.select();try{{document.execCommand('copy')}}catch(e){{}}document.body.removeChild(t);done()}}
function makeQr(id){{const box=document.getElementById(id);if(!box)return;box.innerHTML='';try{{const qr=qrcode(0,'L');qr.addData(vlessUrl);qr.make();box.innerHTML=qr.createImgTag(5,8)}}catch(e){{box.textContent='QR unavailable'}}}}
function openQr(){{document.getElementById('modal').classList.add('show');makeQr('qr-modal')}}
function closeQr(){{document.getElementById('modal').classList.remove('show')}}
makeQr('qr-main');
</script>
</body>
</html>"""
    return HTMLResponse(info_html)
# ============================================================
# SUB GROUP API
# ============================================================
# ============================================================

@app.post("/api/subs")
async def create_sub_api(
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    sub_id, sub = await create_sub_group(
        name=body.get(
            "name",
            "گروه جدید",
        ),
        desc=body.get(
            "desc",
            "",
        ),
        password=body.get(
            "password",
            "",
        ),
    )

    host = get_host(request)

    return {
        "sub_id":
            sub_id,

        **sub,

        "password_hash":
            None,

        "public_url":
            (
                f"https://{host}"
                f"/p/{sub['uuid_key']}"
            ),

        "sub_url":
            (
                f"https://{host}"
                f"/sub-group/{sub['uuid_key']}"
            ),
    }


@app.get("/api/subs")
async def list_subs_api(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(request)

    async with SUBS_LOCK:
        snapshot_subs = dict(SUBS)

    async with LINKS_LOCK:
        snapshot_links = dict(LINKS)

    result = []

    for sid, sub in snapshot_subs.items():

        link_ids = sub.get(
            "link_ids",
            [],
        )

        active_count = sum(
            1
            for lid in link_ids
            if is_link_allowed(
                snapshot_links.get(
                    lid
                )
            )
        )

        total_used = sum(
            snapshot_links[
                lid
            ].get(
                "used_bytes",
                0,
            )

            for lid in link_ids

            if lid in snapshot_links
        )

        result.append(
            {
                "sub_id":
                    sid,

                **sub,

                "password_hash":
                    None,

                "has_password":
                    sub.get(
                        "password_hash"
                    ) is not None,

                "links_count":
                    len(link_ids),

                "active_count":
                    active_count,

                "total_used_bytes":
                    total_used,

                "total_used_fmt":
                    fmt_bytes(
                        total_used
                    ),

                "public_url":
                    (
                        f"https://{host}"
                        f"/p/{sub['uuid_key']}"
                    ),

                "sub_url":
                    (
                        f"https://{host}"
                        f"/sub-group/{sub['uuid_key']}"
                    ),
            }
        )

    result.sort(
        key=lambda item:
            item.get(
                "created_at",
                "",
            ),
        reverse=True,
    )

    return {
        "subs": result
    }


@app.patch("/api/subs/{sub_id}")
async def update_sub_api(
    sub_id: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    async with SUBS_LOCK:

        if sub_id not in SUBS:
            raise HTTPException(
                status_code=404,
                detail="sub not found",
            )

        sub = SUBS[sub_id]

        if "name" in body:
            sub["name"] = str(
                body["name"]
            )[:60]

        if "desc" in body:
            sub["desc"] = str(
                body["desc"]
            )[:200]

        if "password" in body:

            password = str(
                body.get(
                    "password",
                    "",
                )
            ).strip()

            sub["password_hash"] = (
                hash_password(password)
                if password
                else None
            )

        if "link_ids" in body:

            sub["link_ids"] = list(
                body["link_ids"]
            )

    await save_state()

    return {
        "ok": True
    }


@app.delete("/api/subs/{sub_id}")
async def delete_sub_api(
    sub_id: str,
    _=Depends(require_auth),
):

    name = await remove_sub_group(
        sub_id
    )

    if name is None:
        raise HTTPException(
            status_code=404,
            detail="sub not found",
        )

    return {
        "ok": True,
        "deleted": sub_id,
    }


@app.post("/api/subs/{sub_id}/links")
async def assign_link_to_sub(
    sub_id: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    link_id = str(
        body.get(
            "link_id",
            "",
        )
    )

    action = str(
        body.get(
            "action",
            "add",
        )
    )

    if action == "add":

        success = await set_link_sub(
            link_id,
            sub_id,
        )

    else:

        success = await set_link_sub(
            link_id,
            None,
        )

    if not success:
        raise HTTPException(
            status_code=404,
            detail="link or sub not found",
        )

    return {
        "ok": True
    }


# ============================================================
# GROUP SUB
# ============================================================

@app.get("/sub-group/{uuid_key}")
async def sub_group_subscription(
    uuid_key: str,
    request: Request,
):

    async with SUBS_LOCK:

        sub = next(
            (
                item
                for item
                in SUBS.values()
                if item.get(
                    "uuid_key"
                ) == uuid_key
            ),
            None,
        )

    if not sub:
        raise HTTPException(
            status_code=404,
            detail="not found",
        )

    if sub.get(
        "password_hash"
    ):

        password = (
            request.query_params.get(
                "pw",
                "",
            )
        )

        if (
            hash_password(password)
            != sub["password_hash"]
        ):

            raise HTTPException(
                status_code=403,
                detail="wrong password",
            )

    host = get_host(request)

    async with LINKS_LOCK:

        lines = []

        for link_id in sub.get(
            "link_ids",
            [],
        ):

            link = LINKS.get(
                link_id
            )

            if (
                link
                and is_link_allowed(
                    link
                )
            ):

                lines.append(
                    vless_link_for_link(
                        link,
                        link_id,
                        host,
                    )
                )

    content = (
        base64
        .b64encode(
            "\n".join(
                lines
            ).encode()
        )
        .decode()
    )

    total_used = 0
    total_limit = 0
    expiries = []
    valid_ids = list(sub.get("link_ids", []))

    async with LINKS_LOCK:
        for link_id in valid_ids:
            link = LINKS.get(link_id)
            if not link or not is_link_allowed(link):
                continue
            total_used += int(link.get("used_bytes", 0) or 0)
            total_limit += int(link.get("limit_bytes", 0) or 0)
            if link.get("expires_at"):
                expiries.append(str(link.get("expires_at")))

    # For a group subscription, expose aggregate usage/expiry in standard headers.
    group_limit = total_limit if total_limit > 0 else 0
    group_expiry = None
    if expiries:
        try:
            group_expiry = min(
                expiries,
                key=lambda x: datetime.fromisoformat(x)
            )
        except Exception:
            group_expiry = expiries[0]

    group_volume_text = (
        f"{fmt_bytes(total_used)}/{fmt_bytes(group_limit)}"
        if group_limit > 0
        else f"{fmt_bytes(total_used)}/∞"
    )
    group_expiry_text = group_expiry or "∞"
    group_title = (
        f"0.0.0.0 | {group_volume_text} | {group_expiry_text} | "
        f"{sub['name']} | کانال تلگرام: ahbpanel"
    )
    headers = subscription_metadata_headers(
        total_used,
        group_limit,
        group_expiry,
        host,
        f"https://{host}/public-sub/{uuid_key}",
        group_title,
    )

    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers=headers,
    )


# ============================================================
# PUBLIC GROUP
# ============================================================

PUBLIC_SUB_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">

<head>
<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>
AHB Panel
</title>

<style>

*{
    box-sizing:border-box;
}

body{
    margin:0;
    min-height:100vh;

    display:flex;
    justify-content:center;
    align-items:center;

    padding:20px;

    font-family:Arial,sans-serif;

    color:#fff;

    background:
        radial-gradient(
            circle at top right,
            rgba(37,99,235,.17),
            transparent 30%
        ),
        #07070a;
}

.card{
    width:100%;
    max-width:560px;

    padding:28px;
    border-radius:25px;

    background:rgba(255,255,255,.045);

    border:
        1px solid
        rgba(255,255,255,.08);

    backdrop-filter:blur(25px);
}

h1{
    margin-top:0;
}

.text{
    color:rgba(255,255,255,.55);
    line-height:2;
    font-size:13px;
}

.url{
    margin-top:20px;
    padding:14px;

    border-radius:13px;

    background:rgba(0,0,0,.22);

    color:#93c5fd;

    direction:ltr;
    word-break:break-all;

    font-family:Consolas,monospace;
}

.support{
    display:inline-block;
    margin-top:18px;

    color:#60a5fa;
    text-decoration:none;
}

.version{
    color:#60a5fa;
    font-size:11px;
}

</style>
</head>

<body>

<div class="card">

<h1>
AHB Panel
</h1>

<div class="version">
14.5.0
</div>

<div class="text">
اشتراک شما آماده است.
</div>

<div
class="url"
id="subUrl"
></div>

<a
class="support"
href="https://t.me/ahb_panel"
target="_blank"
rel="noopener"
>
پشتیبانی @ahb_panel
</a>

</div>

<script>

const url =
    location.origin +
    location.pathname.replace(
        "/p/",
        "/sub-group/"
    );

document.getElementById(
    "subUrl"
).textContent = url;

</script>

</body>
</html>
"""


@app.get(
    "/p/{uuid_key}",
    response_class=HTMLResponse,
)
async def public_sub_page(
    uuid_key: str,
):

    async with SUBS_LOCK:

        exists = any(
            item.get(
                "uuid_key"
            ) == uuid_key
            for item in SUBS.values()
        )

    if not exists:

        return HTMLResponse(
            """
            <h2
            style="
            font-family:sans-serif;
            padding:40px;
            "
            >
            گروه پیدا نشد
            </h2>
            """,
            status_code=404,
        )

    return HTMLResponse(
        PUBLIC_SUB_HTML
    )


@app.get("/api/public/sub/{uuid_key}")
async def public_sub_data(
    uuid_key: str,
    request: Request,
):

    async with SUBS_LOCK:

        entry = next(
            (
                (
                    sid,
                    item,
                )

                for sid, item
                in SUBS.items()

                if item.get(
                    "uuid_key"
                ) == uuid_key
            ),
            None,
        )

    if not entry:
        raise HTTPException(
            status_code=404,
            detail="not found",
        )

    _, sub = entry

    has_password = (
        sub.get(
            "password_hash"
        ) is not None
    )

    if has_password:

        password = (
            request
            .query_params
            .get(
                "pw",
                "",
            )
        )

        if (
            hash_password(password)
            != sub[
                "password_hash"
            ]
        ):

            return JSONResponse(
                {
                    "locked": True,
                    "name":
                        sub["name"],
                }
            )

    host = get_host(request)

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    links_out = []

    active_connections = 0

    for link_id in sub.get(
        "link_ids",
        [],
    ):

        link = snapshot.get(
            link_id
        )

        if not link:
            continue

        allowed = is_link_allowed(
            link
        )

        connection_count = sum(
            1
            for item in connections.values()
            if item.get("uuid") == link_id
        )

        active_connections += (
            connection_count
        )

        links_out.append(
            {
                "uuid":
                    link_id,

                "label":
                    link.get(
                        "label"
                    ),

                "active":
                    allowed,

                "protocol":
                    link.get(
                        "protocol",
                        DEFAULT_PROTOCOL,
                    ),

                "used_bytes":
                    link.get(
                        "used_bytes",
                        0,
                    ),

                "used_fmt":
                    fmt_bytes(
                        link.get(
                            "used_bytes",
                            0,
                        )
                    ),

                "limit_bytes":
                    link.get(
                        "limit_bytes",
                        0,
                    ),

                "limit_fmt":
                    (
                        "∞"
                        if not link.get(
                            "limit_bytes",
                            0,
                        )
                        else fmt_bytes(
                            link[
                                "limit_bytes"
                            ]
                        )
                    ),

                "expires_at":
                    link.get(
                        "expires_at"
                    ),

                "vless_link":
                    vless_link_for_link(
                        link,
                        link_id,
                        host,
                    ),

                "sub_url":
                    (
                        f"https://{host}"
                        f"/sub/{link_id}"
                    ),

                "info_url":
                    (
                        f"https://{host}"
                        f"/info/{link_id}"
                    ),

                "connections":
                    connection_count,

                "ip_limit":
                    link.get(
                        "ip_limit",
                        0,
                    ),

                "speed_limit_bytes":
                    link.get(
                        "speed_limit_bytes",
                        0,
                    ),

                "connection_limit":
                    link.get(
                        "connection_limit",
                        0,
                    ),
            }
        )

    total_used = sum(
        item["used_bytes"]
        for item in links_out
    )

    return {
        "locked": False,

        "name":
            sub["name"],

        "desc":
            sub.get(
                "desc",
                "",
            ),

        "sub_url":
            (
                f"https://{host}"
                f"/sub-group/{uuid_key}"
            ),

        "active_connections":
            active_connections,

        "total_used_fmt":
            fmt_bytes(
                total_used
            ),

        "support":
            SUPPORT_USERNAME,

        "links":
            links_out,
    }




@app.post("/api/mix-sub")
async def mix_subscription(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    ids = body.get("link_ids") or []
    if not isinstance(ids, list) or len(ids) < 2:
        raise HTTPException(status_code=400, detail="حداقل ۲ کانفیگ انتخاب کنید")
    if len(ids) > 40:
        raise HTTPException(status_code=400, detail="حداکثر ۴۰ کانفیگ")
    host = get_host(request)
    lines = []
    used_names = set()
    total_used = 0
    total_limit = 0
    labels = []
    async with LINKS_LOCK:
        for lid in ids:
            link = LINKS.get(lid)
            if not link or not is_link_allowed(link):
                continue
            labels.append(str(link.get("label") or lid[:8]))
            total_used += int(link.get("used_bytes", 0) or 0)
            total_limit += int(link.get("limit_bytes", 0) or 0)
            name = random_config_name(used_names)
            used_names.add(name)
            lines.append(generate_vless_link(
                lid, host, remark=name,
                protocol=link.get("protocol", DEFAULT_PROTOCOL),
                fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT),
                alpn=link.get("alpn"),
                port=link.get("port", DEFAULT_PORT),
            ))
    if not lines:
        raise HTTPException(status_code=400, detail="هیچ کانفیگ معتبری انتخاب نشده")
    # stats first line
    vol = f"{fmt_bytes(total_used)}/{fmt_bytes(total_limit)}" if total_limit > 0 else f"{fmt_bytes(total_used)}/∞"
    mix_label = "Mix-" + random_config_name()[:6]
    stats = f"{mix_label} | {vol} | {len(lines)} configs"
    first = generate_vless_link(ids[0], "127.0.0.1", remark=stats, protocol="vless-ws")
    content = base64.b64encode(("\n".join([first] + lines)).encode()).decode()
    # store as a sub group for reuse
    sub_id, sub = await create_sub_group(name=mix_label, desc="مخلوط‌سازی کانفیگ‌ها")
    async with SUBS_LOCK:
        if sub_id in SUBS:
            SUBS[sub_id]["link_ids"] = list(ids)
    await save_state()
    return {
        "ok": True,
        "sub_url": f"https://{host}/sub-group/{sub['uuid_key']}",
        "name": mix_label,
        "count": len(lines),
        "content_preview": stats,
    }


@app.get("/api/categories")
async def list_categories(_=Depends(require_auth)):
    items = [{**cat, "id": cid} for cid, cat in CATEGORIES.items()]
    items.sort(key=lambda x: int(x.get("number", 0)))
    return {"categories": items}

@app.post("/api/categories")
async def create_category(request: Request, _=Depends(require_auth)):
    if len(CATEGORIES) >= 50:
        raise HTTPException(status_code=400, detail="حداکثر ۵۰ گروه")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    name = str(body.get("name") or "دسته جدید").strip()[:40]
    used = {int(x.get("number", 0)) for x in CATEGORIES.values()}
    num = 0
    while num in used:
        num += 1
    cid = str(num)
    limit_value = safe_float(body.get("limit_value", 0))
    limit_unit = str(body.get("limit_unit") or "GB").upper()
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    speed_value = safe_float(body.get("speed_limit_value", 0))
    speed_bytes = 0 if speed_value <= 0 else parse_speed_to_bytes(speed_value, "MBIT")
    raw_clean = body.get("clean_ips") or ""
    if isinstance(raw_clean, list):
        clean_ips = [str(x).strip() for x in raw_clean if str(x).strip()]
    else:
        clean_ips = [x.strip() for x in str(raw_clean).replace(",", "\n").splitlines() if x.strip()]
    record = {
        "id": cid, "name": name, "number": num,
        "limit_bytes": limit_bytes,
        "expires_days": safe_int(body.get("expires_days", 0), minimum=0),
        "connection_limit": safe_int(body.get("connection_limit", 0), minimum=0),
        "speed_limit_bytes": speed_bytes,
        "ip_limit": safe_int(body.get("ip_limit", 0), minimum=0),
        "clean_ips": clean_ips,
        "random_name": bool(body.get("random_name", False)),
        "single_user": bool(body.get("single_user", False)),
        "created_at": datetime.now().isoformat(),
    }
    CATEGORIES[cid] = record
    await save_state()
    return {"ok": True, **record}


@app.patch("/api/categories/{cid}")
async def update_category(cid: str, request: Request, _=Depends(require_auth)):
    if cid not in CATEGORIES:
        raise HTTPException(status_code=404, detail="یافت نشد")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    cat = CATEGORIES[cid]
    if "name" in body:
        cat["name"] = str(body.get("name") or cat["name"]).strip()[:40]
    if "limit_value" in body:
        lv = safe_float(body.get("limit_value", 0))
        unit = str(body.get("limit_unit") or "GB").upper()
        cat["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, unit)
    if "expires_days" in body:
        cat["expires_days"] = safe_int(body.get("expires_days", 0), minimum=0)
    if "connection_limit" in body:
        cat["connection_limit"] = safe_int(body.get("connection_limit", 0), minimum=0)
    if "speed_limit_value" in body:
        sv = safe_float(body.get("speed_limit_value", 0))
        cat["speed_limit_bytes"] = 0 if sv <= 0 else parse_speed_to_bytes(sv, "MBIT")
    if "ip_limit" in body:
        cat["ip_limit"] = safe_int(body.get("ip_limit", 0), minimum=0)
    if "clean_ips" in body:
        raw = body.get("clean_ips") or ""
        if isinstance(raw, list):
            cat["clean_ips"] = [str(x).strip() for x in raw if str(x).strip()]
        else:
            cat["clean_ips"] = [x.strip() for x in str(raw).replace(",", "\n").splitlines() if x.strip()]
    if "random_name" in body:
        cat["random_name"] = bool(body.get("random_name"))
    if "single_user" in body:
        cat["single_user"] = bool(body.get("single_user"))
    await save_state()
    return {"ok": True, **cat}

@app.delete("/api/categories/{cid}")
async def delete_category(cid: str, _=Depends(require_auth)):
    if cid not in CATEGORIES:
        raise HTTPException(status_code=404, detail="یافت نشد")
    del CATEGORIES[cid]
    for link in LINKS.values():
        if str(link.get("category_id")) == cid:
            link["category_id"] = "0"
    await save_state()
    return {"ok": True}

# ============================================================
# STATS
# ============================================================

@app.get("/stats")
async def get_stats(
    _=Depends(require_auth),
):

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    return {
        "service":
            APP_NAME,

        "version":
            APP_VERSION,

        "active_connections":
            len(connections),

        "total_traffic_mb":
            round(
                stats[
                    "total_bytes"
                ]
                / (
                    1024 ** 2
                ),
                2,
            ),

        "total_traffic_bytes":
            stats[
                "total_bytes"
            ],

        "total_requests":
            stats[
                "total_requests"
            ],

        "total_errors":
            stats[
                "total_errors"
            ],

        "uptime":
            uptime(),

        "timestamp":
            datetime.now().isoformat(),

        "hourly":
            dict(
                hourly_traffic
            ),

        "recent_errors":
            list(
                error_logs
            )[-10:],

        "links_count":
            len(snapshot),

        "active_links":
            sum(
                1
                for link
                in snapshot.values()
                if is_link_allowed(
                    link
                )
            ),

        "expired_links":
            sum(
                1
                for link
                in snapshot.values()
                if is_link_expired(
                    link
                )
            ),

        "subs_count":
            len(SUBS),
    }


@app.get("/api/activity")
async def get_activity(
    _=Depends(require_auth),
):

    return {
        "logs":
            list(
                activity_logs
            )[-150:]
    }


# ============================================================
# CONNECTIONS
# ============================================================

@app.get("/api/connections")
async def get_connections(
    _=Depends(require_auth),
):

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    grouped = {}

    for connection in connections.values():

        ip = connection.get(
            "ip",
            "نامشخص",
        )

        link = snapshot.get(
            connection.get(
                "uuid"
            )
        )

        label = (
            link.get(
                "label"
            )
            if link
            else "نامشخص"
        )

        group = grouped.get(ip)

        if group is None:

            group = {
                "ip":
                    ip,

                "sessions":
                    0,

                "bytes":
                    0,

                "labels":
                    set(),

                "transports":
                    set(),

                "first_connected_at":
                    connection.get(
                        "connected_at"
                    ),

                "last_connected_at":
                    connection.get(
                        "connected_at"
                    ),
            }

            grouped[ip] = group

        group["sessions"] += 1

        group["bytes"] += int(
            connection.get(
                "bytes",
                0,
            )
            or 0
        )

        group["labels"].add(
            label
        )

        group["transports"].add(
            connection.get(
                "transport",
                DEFAULT_PROTOCOL,
            )
        )

    result = []

    for group in grouped.values():

        result.append(
            {
                "ip":
                    group["ip"],

                "sessions":
                    group["sessions"],

                "labels":
                    sorted(
                        group["labels"]
                    ),

                "label":
                    (
                        " · ".join(
                            sorted(
                                group["labels"]
                            )
                        )
                        if group["labels"]
                        else "نامشخص"
                    ),

                "transports":
                    sorted(
                        group["transports"]
                    ),

                "bytes":
                    group["bytes"],

                "bytes_fmt":
                    fmt_bytes(
                        group["bytes"]
                    ),

                "connected_at":
                    group[
                        "first_connected_at"
                    ],

                "last_connected_at":
                    group[
                        "last_connected_at"
                    ],
            }
        )

    result.sort(
        key=lambda item:
            item.get(
                "last_connected_at"
            )
            or "",
        reverse=True,
    )

    return {
        "connections":
            result,

        "count":
            len(result),

        "raw_count":
            len(connections),
    }


# ============================================================
# OPTIONAL EXISTING PROJECT MODULES
# ============================================================

# ============================================================
# IMPORTANT:
# DO NOT REPLACE THIS VLESS CORE.
# ============================================================

try:

    from relay_vless import (
        RELAY_BUF,
        parse_vless_header,
        check_and_use,
        relay_ws_to_tcp,
        relay_tcp_to_ws,
        websocket_tunnel,
    )

    app.add_api_websocket_route(
        "/ws/{uuid}",
        websocket_tunnel,
    )

    logger.info(
        "VLESS relay loaded."
    )

except Exception as exc:

    logger.warning(
        "VLESS relay module unavailable: %s",
        exc,
    )


# ============================================================
# XHTTP
# ============================================================

try:

    from xhttp_siz10 import (
        router as xhttp_router
    )

    app.include_router(
        xhttp_router
    )

    logger.info(
        "XHTTP module loaded."
    )

except Exception as exc:

    logger.warning(
        "XHTTP module unavailable: %s",
        exc,
    )



# ============================================================

@app.get("/api/me")
async def api_me_info(request: Request, token=Depends(require_auth)):
    meta = get_session_meta(token)
    return {
        "ok": True,
        "role": meta.get("role"),
        "username": meta.get("username"),
        "permissions": meta.get("permissions") or {p: True for p in ALL_PERMS},
        "uptime": uptime(),
    }


@app.get("/api/admins")
async def api_admins_list(token=Depends(require_perm("admins"))):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    out = []
    for aid, a in ADMIN_ACCOUNTS.items():
        out.append({
            "id": aid,
            "username": a.get("username"),
            "label": a.get("label"),
            "limit_bytes": int(a.get("limit_bytes") or 0),
            "used_bytes": int(a.get("used_bytes") or 0),
            "expires_at": a.get("expires_at"),
            "active": bool(a.get("active", True)),
            "blocked": bool(a.get("blocked")),
            "permissions": a.get("permissions") or {},
            "created_at": a.get("created_at"),
            "valid": admin_is_valid(a),
        })
    out.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return {"admins": out}


@app.post("/api/admins")
async def api_admins_create(request: Request, token=Depends(require_perm("admins"))):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="JSON نامعتبر")
    username = str(body.get("username") or "").strip().lower()
    password = str(body.get("password") or "")
    repeat = str(body.get("repeat_password") or body.get("confirm") or "")
    if not username or len(username) < 3:
        raise HTTPException(400, detail="نام کاربری حداقل ۳ کاراکتر")
    if not username.isalnum():
        raise HTTPException(400, detail="نام کاربری فقط حروف و عدد انگلیسی")
    if username in ("owner", "admin", "root"):
        raise HTTPException(400, detail="این نام کاربری رزرو شده است")
    if find_admin_by_username(username)[0]:
        raise HTTPException(400, detail="نام کاربری تکراری است")
    if len(password) < 6:
        raise HTTPException(400, detail="رمز حداقل ۶ کاراکتر")
    if password != repeat:
        raise HTTPException(400, detail="تکرار رمز یکسان نیست")
    limit_value = safe_float(body.get("limit_value", 0))
    limit_unit = str(body.get("limit_unit") or "GB").upper()
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    days = safe_int(body.get("expires_days", 0), minimum=0)
    expires_at = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None
    perms_in = body.get("permissions") or {}
    permissions = {p: bool(perms_in.get(p, False)) for p in ALL_PERMS}
    rec = default_admin_record(username, password, limit_bytes=limit_bytes, expires_at=expires_at, permissions=permissions, label=body.get("label") or username)
    ADMIN_ACCOUNTS[rec["id"]] = rec
    await save_state()
    log_activity("admin", f"اکانت ادمین «{username}» ساخته شد", "ok")
    return {"ok": True, "id": rec["id"], "username": username}


@app.patch("/api/admins/{aid}")
async def api_admins_patch(aid: str, request: Request, token=Depends(require_perm("admins"))):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    if aid not in ADMIN_ACCOUNTS:
        raise HTTPException(404, detail="یافت نشد")
    body = await request.json()
    a = ADMIN_ACCOUNTS[aid]
    if "blocked" in body:
        a["blocked"] = bool(body["blocked"])
    if "active" in body:
        a["active"] = bool(body["active"])
    if "label" in body:
        a["label"] = str(body["label"])[:40]
    if "permissions" in body and isinstance(body["permissions"], dict):
        a["permissions"] = {p: bool(body["permissions"].get(p, False)) for p in ALL_PERMS}
    if "limit_value" in body:
        lv = safe_float(body.get("limit_value", 0))
        lu = str(body.get("limit_unit") or "GB").upper()
        a["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
    if "expires_days" in body:
        days = safe_int(body.get("expires_days", 0), minimum=0)
        a["expires_at"] = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None
    if body.get("password"):
        pw = str(body["password"])
        if len(pw) < 6:
            raise HTTPException(400, detail="رمز حداقل ۶ کاراکتر")
        a["password_hash"] = hash_password(pw)
    await save_state()
    log_activity("admin", f"اکانت ادمین «{a.get('username')}» ویرایش شد", "ok")
    return {"ok": True}


@app.delete("/api/admins/{aid}")
async def api_admins_delete(aid: str, token=Depends(require_perm("admins"))):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    a = ADMIN_ACCOUNTS.pop(aid, None)
    if not a:
        raise HTTPException(404, detail="یافت نشد")
    await save_state()
    log_activity("admin", f"اکانت ادمین «{a.get('username')}» حذف شد", "warn")
    return {"ok": True}


NEWS_FILE = Path(__file__).resolve().parent / "news.json"


@app.get("/api/news")
async def api_news(token=Depends(require_auth)):
    try:
        if NEWS_FILE.exists():
            data = json.loads(NEWS_FILE.read_text(encoding="utf-8"))
        else:
            data = {"enabled": False, "title": "", "message": "", "updated_at": ""}
        return {"ok": True, **data}
    except Exception as e:
        return {"ok": False, "enabled": False, "title": "", "message": str(e), "updated_at": ""}




# ============================================================
# BACKUP / RESTORE
# ============================================================


@app.get("/api/security/status")
async def security_status(token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک")
    now = time.time()
    locked = []
    for ip, until in list(LOGIN_LOCKED_UNTIL.items()):
        if until > now:
            locked.append({"ip": ip, "remaining_sec": int(until - now)})
    return {
        "ok": True,
        "max_attempts": LOGIN_MAX_ATTEMPTS,
        "window_seconds": LOGIN_WINDOW_SECONDS,
        "lockout_seconds": LOGIN_LOCKOUT_SECONDS,
        "locked_ips": locked,
        "tracked_ips": len(LOGIN_FAILURES),
    }


@app.post("/api/security/unlock")
async def security_unlock(request: Request, token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک")
    try:
        body = await request.json()
    except Exception:
        body = {}
    ip = str((body or {}).get("ip") or "").strip()
    if ip:
        LOGIN_FAILURES.pop(ip, None)
        LOGIN_LOCKED_UNTIL.pop(ip, None)
    else:
        LOGIN_FAILURES.clear()
        LOGIN_LOCKED_UNTIL.clear()
    log_activity("auth", f"رفع مسدودی brute-force ({ip or 'all'})", "ok")
    return {"ok": True}


@app.get("/api/backup/users")
async def backup_users(token=Depends(require_auth)):
    meta = get_session_meta(token)
    # owner always; admin needs settings perm
    if meta.get("role") != "owner":
        if not (meta.get("permissions") or {}).get("settings"):
            raise HTTPException(403, detail="دسترسی ندارید")
    payload = {
        "type": "ahbpanel_users_backup",
        "version": APP_VERSION,
        "created_at": datetime.now().isoformat(),
        "links": dict(LINKS),
        "subs": dict(SUBS),
        "categories": dict(CATEGORIES),
        "admin_accounts": dict(ADMIN_ACCOUNTS),
    }
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="ahbpanel-users-{datetime.now().strftime("%Y%m%d-%H%M%S")}.json"'
        },
    )


@app.get("/api/backup/bot")
async def backup_bot(token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        if not (meta.get("permissions") or {}).get("settings"):
            raise HTTPException(403, detail="دسترسی ندارید")
    data = {}
    try:
        if TG_FILE.exists():
            data = json.loads(TG_FILE.read_text(encoding="utf-8"))
    except Exception:
        data = {}
    payload = {
        "type": "ahbpanel_bot_backup",
        "version": APP_VERSION,
        "created_at": datetime.now().isoformat(),
        "telegram": data,
    }
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="ahbpanel-bot-{datetime.now().strftime("%Y%m%d-%H%M%S")}.json"'
        },
    )


@app.post("/api/restore/users")
async def restore_users(request: Request, token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="فایل JSON نامعتبر")
    if not isinstance(body, dict):
        raise HTTPException(400, detail="فرمت نامعتبر")
    # accept either wrapper or raw state
    links = body.get("links")
    if links is None and body.get("type") == "pxpanel_users_backup":
        raise HTTPException(400, detail="لینک‌ها در بک‌آپ نیست")
    if links is None:
        raise HTTPException(400, detail="فایل بک‌آپ کاربران نیست")
    if not isinstance(links, dict):
        raise HTTPException(400, detail="links نامعتبر")
    mode = str(body.get("mode") or "merge").lower()  # merge | replace
    async with LINKS_LOCK:
        if mode == "replace":
            LINKS.clear()
            SUBS.clear()
            CATEGORIES.clear()
            ADMIN_ACCOUNTS.clear()
        LINKS.update(links)
        if isinstance(body.get("subs"), dict):
            SUBS.update(body["subs"])
        if isinstance(body.get("categories"), dict):
            CATEGORIES.update(body["categories"])
        if isinstance(body.get("admin_accounts"), dict):
            ADMIN_ACCOUNTS.update(body["admin_accounts"])
        for uid, link in list(LINKS.items()):
            if not isinstance(link, dict):
                LINKS.pop(uid, None)
                continue
            link.setdefault("protocol", DEFAULT_PROTOCOL)
            link.setdefault("fingerprint", DEFAULT_FINGERPRINT)
            link.setdefault("used_bytes", 0)
            link.setdefault("active", True)
            link.setdefault("config_count", 1)
    await save_state()
    log_activity("backup", f"بازیابی کاربران ({mode}) — {len(links)} کانفیگ", "ok")
    return {"ok": True, "links": len(LINKS), "subs": len(SUBS), "mode": mode}


@app.post("/api/restore/bot")
async def restore_bot(request: Request, token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="فایل JSON نامعتبر")
    tg = body.get("telegram") if isinstance(body, dict) else None
    if tg is None and isinstance(body, dict) and (body.get("token") or body.get("admin_ids") is not None):
        tg = body
    if not isinstance(tg, dict):
        raise HTTPException(400, detail="فایل بک‌آپ ربات نیست")
    # merge with existing
    current = {}
    try:
        if TG_FILE.exists():
            current = json.loads(TG_FILE.read_text(encoding="utf-8"))
    except Exception:
        current = {}
    current.update({k: v for k, v in tg.items() if v is not None})
    TG_FILE.parent.mkdir(parents=True, exist_ok=True)
    TG_FILE.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8")
    # try activate
    try:
        from telegram_bot import configure_bot, start_bot, stop_bot, setup_webhook
        await stop_bot()
        configure_bot(current.get("token") or "", current.get("admin_ids") or "")
        host = get_host(request)
        if current.get("webhook") and host and host != "localhost":
            wh = f"https://{host}/telegram/webhook"
            await setup_webhook(wh)
            await start_bot(mode="webhook")
        else:
            await setup_webhook("")
            await start_bot(mode="polling")
    except Exception as exc:
        logger.warning("restore bot activate: %s", exc)
        log_activity("backup", f"بک‌آپ ربات ذخیره شد (فعال‌سازی: {exc})", "warn")
        return {"ok": True, "warning": str(exc)}
    log_activity("backup", "بازیابی تنظیمات ربات انجام شد", "ok")
    return {"ok": True, "message": "ربات بازیابی و فعال شد"}



# TELEGRAM SETTINGS API
# ============================================================

def load_tg_settings():
    try:
        if TG_FILE.exists():
            return json.loads(TG_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {
        "token": os.environ.get("TELEGRAM_BOT_TOKEN", "").strip(),
        "admin_ids": os.environ.get("TELEGRAM_ADMIN_IDS", "").strip(),
        "webhook": False,
        "enabled": False,
    }


def save_tg_settings(data: dict):
    TG_FILE.parent.mkdir(parents=True, exist_ok=True)
    TG_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


@app.get("/api/telegram/settings")
async def api_tg_get(_=Depends(require_auth)):
    s = load_tg_settings()
    token = s.get("token") or ""
    masked = (token[:8] + "…" + token[-4:]) if len(token) > 14 else ("••••" if token else "")
    return {
        "token_masked": masked,
        "has_token": bool(token),
        "admin_ids": s.get("admin_ids") or "",
        "webhook": bool(s.get("webhook")),
        "enabled": bool(s.get("enabled")),
    }


@app.post("/api/telegram/settings")
async def api_tg_save(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="invalid json")
    s = load_tg_settings()
    token = str(body.get("token") or "").strip()
    admin_ids = str(body.get("admin_ids") or "").strip()
    use_webhook = bool(body.get("webhook", True))
    if token:
        s["token"] = token
    if admin_ids is not None:
        s["admin_ids"] = admin_ids
    s["webhook"] = use_webhook
    s["enabled"] = True
    save_tg_settings(s)
    # apply runtime
    try:
        from telegram_bot import configure_bot, start_bot, stop_bot, setup_webhook
        await stop_bot()
        configure_bot(s.get("token") or "", s.get("admin_ids") or "")
        host = get_host(request)
        if use_webhook and host and host != "localhost":
            wh = f"https://{host}/telegram/webhook"
            ok = await setup_webhook(wh)
            s["webhook_url"] = wh
            s["webhook_ok"] = bool(ok)
            save_tg_settings(s)
            await start_bot(mode="webhook")
        else:
            await setup_webhook("")  # delete webhook -> polling
            await start_bot(mode="polling")
        log_activity("telegram", "ربات تلگرام پیکربندی و فعال شد", "ok")
        return {"ok": True, "webhook": use_webhook, "message": "ربات فعال شد"}
    except Exception as exc:
        logger.warning("telegram activate error: %s", exc)
        return {"ok": True, "warning": str(exc), "message": "تنظیمات ذخیره شد"}


@app.post("/telegram/webhook")
async def telegram_webhook(request: Request):
    try:
        from telegram_bot import process_update
        data = await request.json()
        await process_update(data)
    except Exception as exc:
        logger.warning("webhook error: %s", exc)
    return {"ok": True}


# ============================================================
# TELEGRAM
# ============================================================

try:

    from telegram_bot import (
        start_bot as _tg_start_bot,
        stop_bot as _tg_stop_bot,
    )

except Exception:

    async def _tg_start_bot():
        return None

    async def _tg_stop_bot():
        return None


@app.on_event("startup")
async def start_optional_telegram():

    try:

        await _tg_start_bot()

        logger.info(
            "Telegram module initialized."
        )

    except Exception as exc:

        logger.warning(
            "Telegram bot disabled/error: %s",
            exc,
        )


# ============================================================
# HTTP PROXY
# ============================================================

_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-encoding",
    "content-length",
}


@app.api_route(
    "/proxy/{target_url:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
    ],
)
async def http_proxy(
    target_url: str,
    request: Request,
):

    if not target_url.startswith("http"):
        target_url = (
            "https://"
            + target_url
        )

    if http_client is None:
        raise HTTPException(
            status_code=503,
            detail="HTTP client not ready",
        )

    try:

        body = await request.body()

        headers = {
            key: value
            for key, value
            in request.headers.items()
            if (
                key.lower()
                not in _HOP
            )
            and (
                key.lower()
                != "host"
            )
        }

        response = await http_client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
        )

        stats["total_bytes"] += len(
            response.content
        )

        stats["total_requests"] += 1

        hourly_traffic[
            now_ir().strftime(
                "%H:00"
            )
        ] += len(
            response.content
        )

        output_headers = {
            key: value
            for key, value
            in response.headers.items()
            if key.lower() not in _HOP
        }

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=output_headers,
        )

    except Exception as exc:

        stats["total_errors"] += 1

        error_logs.append(
            {
                "error":
                    str(exc),

                "url":
                    target_url,

                "time":
                    datetime.now().isoformat(),
            }
        )

        logger.exception(
            "Proxy error: %s",
            target_url,
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Proxy error: "
                f"{exc}"
            ),
        )


# ============================================================
# DASHBOARD
# ============================================================

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl" id="htmlRoot">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>AHBPanel 14.5.0</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&family=Inter:wght@400;500;600;700&family=Orbitron:wght@500;700;800&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#06060b;--bg2:#0b0b12;--bg3:#12121c;--card:rgba(18,18,28,.92);--card-b:rgba(255,255,255,.08);
  --accent:#3b82f6;--accent2:#60a5fa;--purple:#8b5cf6;--green:#22c55e;--red:#ef4444;--amber:#f59e0b;
  --t1:#f8fafc;--t2:rgba(248,250,252,.72);--t3:rgba(248,250,252,.42);
  --sb:252px;--sb-c:74px;--radius:18px;--shadow:0 12px 40px rgba(0,0,0,.45);
  --input-bg:rgba(0,0,0,.4);--hover:rgba(59,130,246,.12);
  --glow:0 0 40px rgba(59,130,246,.12);--glass:blur(16px);
}
html.light{
  --bg:#eef1f8;--bg2:#ffffff;--bg3:#f1f4fa;--card:#ffffff;--card-b:rgba(15,23,42,.09);
  --accent:#2563eb;--accent2:#3b82f6;--purple:#7c3aed;--green:#16a34a;--red:#dc2626;--amber:#d97706;
  --t1:#0f172a;--t2:#475569;--t3:#94a3b8;
  --shadow:0 10px 32px rgba(15,23,42,.08);
  --input-bg:#f8fafc;--hover:rgba(37,99,235,.08);
  --glow:0 0 32px rgba(37,99,235,.08);--glass:blur(12px);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{min-height:100%}
body{font-family:'Vazirmatn',sans-serif;background:var(--bg);color:var(--t1);display:flex;min-height:100vh;overflow-x:hidden;transition:background .3s,color .3s}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:
    radial-gradient(ellipse 80% 50% at 100% 0%, rgba(59,130,246,.14), transparent 50%),
    radial-gradient(ellipse 60% 40% at 0% 100%, rgba(139,92,246,.10), transparent 45%);
}
html.light body::before{
  background:
    radial-gradient(ellipse 80% 50% at 100% 0%, rgba(37,99,235,.08), transparent 50%),
    radial-gradient(ellipse 60% 40% at 0% 100%, rgba(124,58,237,.06), transparent 45%);
}
.sidebar,.main,.mob-bar,.modal-bg,.toast{position:relative;z-index:1}
.sidebar{z-index:300}.mob-bar{z-index:250}.modal-bg{z-index:500}.toast{z-index:999}
body.en{font-family:'Inter',system-ui,sans-serif}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-thumb{background:var(--t3);border-radius:99px}

.sidebar{position:fixed;right:0;top:0;bottom:0;width:var(--sb);background:var(--bg2);border-left:1px solid var(--card-b);display:flex;flex-direction:column;z-index:300;transition:width .28s cubic-bezier(.4,0,.2,1),transform .28s,background .3s;box-shadow:var(--shadow);backdrop-filter:var(--glass)}
.sidebar.collapsed{width:var(--sb-c)}
.sb-toggle{position:absolute;left:-15px;top:50%;transform:translateY(-50%);width:30px;height:30px;border-radius:8px;background:var(--accent);border:2px solid var(--bg);color:#fff;display:flex;align-items:center;justify-content:center;cursor:pointer;z-index:310;box-shadow:0 4px 14px rgba(37,99,235,.4);transition:.2s}
.sb-toggle:hover{filter:brightness(1.1);transform:translateY(-50%) scale(1.05)}
.sb-toggle svg{width:14px;height:14px;transition:transform .28s}
.sidebar.collapsed .sb-toggle svg{transform:rotate(180deg)}
.sb-logo{display:flex;align-items:center;gap:12px;padding:20px 16px;border-bottom:1px solid var(--card-b)}
.sb-logo-icon{width:40px;height:40px;border-radius:12px;background:linear-gradient(135deg,#3b82f6,#8b5cf6);display:flex;align-items:center;justify-content:center;font-weight:800;font-size:13px;color:#fff;flex-shrink:0;box-shadow:0 4px 14px rgba(59,130,246,.35)}
.sb-logo-text{overflow:hidden;white-space:nowrap}
.sb-logo-name{font-size:15px;font-weight:800;letter-spacing:-.02em}
.sb-logo-ver{font-size:10px;color:var(--t3);margin-top:2px}
.sidebar.collapsed .sb-logo-text,
.sidebar.collapsed .nav-label,
.sidebar.collapsed .nav-sec,
.sidebar.collapsed .sb-foot span{display:none!important}
.sidebar.collapsed .sb-logo{justify-content:center;padding:16px 8px}
.sidebar.collapsed .sb-logo-icon{margin:0 auto}
.nav{flex:1;overflow-y:auto;padding:10px 0}
.nav-sec{padding:14px 18px 6px;font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--t3);font-weight:700}
.nav-item{display:flex;align-items:center;gap:11px;padding:11px 16px;margin:2px 10px;border-radius:12px;color:var(--t3);cursor:pointer;transition:.15s;border:none;background:transparent;width:calc(100% - 20px);font-family:inherit;font-size:13px;font-weight:500}
.nav-item svg{width:18px;height:18px;min-width:18px;min-height:18px;flex-shrink:0;display:block}
.nav-item:hover{background:var(--hover);color:var(--t2)}
.nav-item.on{background:var(--hover);color:var(--accent2);font-weight:700;box-shadow:inset -3px 0 0 var(--accent)}
.sidebar.collapsed .nav-item{justify-content:center;align-items:center;padding:12px 0;margin:3px 10px;width:calc(100% - 20px);gap:0}
.sidebar.collapsed .nav-item svg{margin:0 auto}
.sidebar.collapsed .nav-item.on{box-shadow:none}
.sidebar.collapsed .sb-foot button,.sidebar.collapsed .sb-foot a.btn{padding:10px 0;gap:0}
.sidebar.collapsed .sb-foot button svg,.sidebar.collapsed .sb-foot a.btn svg{margin:0 auto;display:block}
.sb-foot{padding:12px;border-top:1px solid var(--card-b);display:flex;flex-direction:column;gap:7px}
.sb-foot button,.sb-foot a.btn{display:flex;align-items:center;justify-content:center;gap:8px;padding:10px;border-radius:11px;border:1px solid var(--card-b);background:var(--bg3);color:var(--t2);cursor:pointer;font-family:inherit;font-size:12px;width:100%;text-decoration:none;font-weight:600;transition:.15s}
.sb-foot button:hover,.sb-foot a.btn:hover{background:var(--hover);color:var(--t1)}
.sb-foot a.danger{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.2);color:var(--red)}

.main{margin-right:var(--sb);flex:1;min-width:0;padding:28px 24px 60px;transition:margin .28s}
.main.expanded{margin-right:var(--sb-c)}
.page{display:none;animation:fadeIn .25s ease}
.page.on{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.page-head{display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:14px;margin-bottom:22px}
.page-title{font-size:20px;font-weight:800;display:flex;align-items:center;gap:10px;letter-spacing:-.02em}
.page-title svg{width:22px;height:22px;color:var(--accent2)}
.page-sub{font-size:12px;color:var(--t3);margin-top:5px}

.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
.metric{background:var(--card);border:1px solid var(--card-b);border-radius:var(--radius);padding:18px;box-shadow:var(--shadow);transition:.25s;backdrop-filter:var(--glass)}
.metric:hover{border-color:rgba(59,130,246,.25)}
.metric-label{font-size:11px;color:var(--t3);margin-bottom:8px;display:flex;align-items:center;gap:6px;font-weight:600}
.metric-val{font-size:24px;font-weight:800;letter-spacing:-.03em}
.card{background:var(--card);border:1px solid var(--card-b);border-radius:var(--radius);padding:20px;margin-bottom:14px;box-shadow:var(--shadow);backdrop-filter:var(--glass);transition:border-color .2s,box-shadow .2s}
.card-title{font-size:13px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.card-title svg{width:16px;height:16px;color:var(--accent2)}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}
.action-card{cursor:pointer;transition:.2s;border:1px solid var(--card-b)}
.action-card:hover{border-color:rgba(59,130,246,.4);transform:translateY(-2px);box-shadow:0 12px 28px rgba(59,130,246,.12)}
.action-card.purple:hover{border-color:rgba(139,92,246,.45)}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;padding:10px 16px;border-radius:11px;border:1px solid var(--card-b);background:var(--bg3);color:var(--t2);cursor:pointer;font-family:inherit;font-size:12px;font-weight:600;transition:.15s}
.btn:hover{color:var(--t1);border-color:var(--accent)}
.btn-p{background:linear-gradient(135deg,#3b82f6,#6366f1);border:none;color:#fff;box-shadow:0 6px 20px rgba(59,130,246,.35)}
.btn-p:hover{filter:brightness(1.08);color:#fff}
.btn-d{background:rgba(239,68,68,.1);border-color:rgba(239,68,68,.25);color:var(--red)}
.btn-sm{padding:7px 11px;font-size:11px;border-radius:9px}
.btn svg{width:15px;height:15px}

.table-wrap{overflow-x:auto;border-radius:14px;border:1px solid var(--card-b)}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:right;padding:12px 14px;background:var(--bg3);color:var(--t3);font-weight:700;white-space:nowrap}
td{padding:12px 14px;border-top:1px solid var(--card-b);vertical-align:middle}
tr:hover td{background:var(--hover)}
.ops{display:flex;gap:5px;flex-wrap:wrap;align-items:center}

.range-tabs{display:flex;gap:4px;background:var(--bg3);padding:4px;border-radius:12px;border:1px solid var(--card-b)}
.range-tab{padding:7px 13px;border-radius:9px;font-size:11px;font-weight:700;color:var(--t3);cursor:pointer;border:none;background:transparent;font-family:inherit;transition:.15s}
.range-tab.on{background:var(--accent);color:#fff;box-shadow:0 2px 8px rgba(37,99,235,.35)}

.field{margin-bottom:14px}
.field label{display:block;font-size:11px;color:var(--t3);margin-bottom:6px;font-weight:700}
.field input,.field select,.field textarea{width:100%;padding:11px 13px;border-radius:11px;border:1px solid var(--card-b);background:var(--input-bg);color:var(--t1);font-family:inherit;font-size:13px;outline:none;transition:.15s}
.field input:focus,.field select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.15)}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}

.support-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}
.support-tile{display:flex;align-items:center;gap:14px;padding:20px;background:var(--card);border:1px solid var(--card-b);border-radius:var(--radius);text-decoration:none;color:inherit;transition:.2s;box-shadow:var(--shadow)}
.support-tile:hover{border-color:rgba(59,130,246,.35);transform:translateY(-3px)}
.support-icon{width:48px;height:48px;border-radius:14px;background:var(--hover);display:flex;align-items:center;justify-content:center;flex-shrink:0}
.support-icon svg{width:22px;height:22px;color:var(--accent2)}
.support-label{font-size:11px;color:var(--t3);font-weight:600}
.support-val{font-size:13px;font-weight:700;margin-top:3px}

.log-item{padding:12px 0;border-bottom:1px solid var(--card-b);font-size:12px;display:flex;gap:12px;align-items:flex-start}
.log-time{color:var(--t3);font-size:10px;white-space:nowrap;min-width:72px;font-weight:600}
.log-msg{color:var(--t2);flex:1;line-height:1.5}

.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.55);backdrop-filter:blur(6px);z-index:500;display:none;align-items:center;justify-content:center;padding:16px}
.modal-bg.open{display:flex}
.modal{background:var(--bg2);border:1px solid var(--card-b);border-radius:20px;width:min(520px,100%);max-height:90vh;overflow-y:auto;padding:24px;box-shadow:0 24px 64px rgba(0,0,0,.4)}
.modal-title{font-size:17px;font-weight:800;margin-bottom:16px}
.modal-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:18px;flex-wrap:wrap}
.link-box{background:var(--input-bg);border:1px solid var(--card-b);border-radius:12px;padding:12px;font-size:11px;word-break:break-all;color:var(--t2);margin:8px 0 12px;font-family:ui-monospace,monospace;line-height:1.6;max-height:90px;overflow:auto}

.toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%) translateY(90px);background:var(--bg2);border:1px solid var(--card-b);color:var(--t1);padding:13px 22px;border-radius:14px;font-size:13px;font-weight:600;z-index:999;opacity:0;transition:.3s;pointer-events:none;box-shadow:var(--shadow)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}

.switch{position:relative;display:inline-block;width:44px;height:26px;vertical-align:middle}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;inset:0;background:rgba(148,163,184,.35);border-radius:26px;transition:.2s}
.slider:before{position:absolute;content:"";height:20px;width:20px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.2s;box-shadow:0 2px 6px rgba(0,0,0,.2)}
.switch input:checked+.slider{background:var(--green)}
.switch input:checked+.slider:before{transform:translateX(18px)}

.mob-bar{display:none;position:fixed;top:0;left:0;right:0;height:56px;background:var(--bg2);border-bottom:1px solid var(--card-b);z-index:250;align-items:center;justify-content:space-between;padding:0 16px;box-shadow:var(--shadow)}
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:290;display:none}
.overlay.show{display:block}

@media(max-width:900px){
  .sidebar{transform:translateX(100%)}
  .sidebar.open{transform:translateX(0)}
  .sb-toggle{display:none!important}
  .main,.main.expanded{margin-right:0;padding-top:72px}
  .mob-bar{display:flex}
  .metrics{grid-template-columns:1fr 1fr}
  .g2,.form-row{grid-template-columns:1fr}
}
@media(max-width:480px){.metrics{grid-template-columns:1fr}}
.spin{width:36px;height:36px;border:3px solid var(--card-b);border-top-color:var(--accent);border-radius:50%;margin:0 auto;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

.conn-badge{display:inline-flex;align-items:center;justify-content:center;min-width:22px;height:20px;padding:0 7px;border-radius:8px;font-size:10px;font-weight:800}
.conn-badge.green{background:rgba(34,197,94,.18);color:#4ade80}
.conn-badge.gray{background:rgba(148,163,184,.15);color:#94a3b8}
.conn-badge.orange{background:rgba(245,158,11,.18);color:#fbbf24}
.conn-badge.red{background:rgba(239,68,68,.18);color:#f87171}
.spin{width:36px;height:36px;border:3px solid var(--card-b);border-top-color:var(--accent);border-radius:50%;margin:0 auto;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* ================= NEON GLASS · ACTION THEME ================= */
:root{
  --bg:#05030d;--bg2:rgba(16,10,38,.58);--bg3:rgba(255,255,255,.055);
  --card:rgba(255,255,255,.045);--card-b:rgba(255,255,255,.11);
  --accent:#00e5ff;--accent2:#6df3ff;--purple:#b26bff;--pink:#ff2bd6;
  --green:#2dff9a;--red:#ff4d6d;--amber:#ffc23d;
  --t1:#f4f7ff;--t2:rgba(232,238,255,.78);--t3:rgba(206,216,255,.5);
  --shadow:0 12px 40px rgba(0,0,0,.5),inset 0 1px 0 rgba(255,255,255,.12);
  --input-bg:rgba(5,3,20,.6);--hover:rgba(0,229,255,.1);
  --glow:0 0 40px rgba(0,229,255,.2);--glass:blur(20px) saturate(170%);
  --neon:linear-gradient(120deg,#00e5ff,#8a5cff 50%,#ff2bd6);
  --radius:20px;
}
html.light{
  --bg:#e8ebff;--bg2:rgba(255,255,255,.62);--bg3:rgba(255,255,255,.58);
  --card:rgba(255,255,255,.55);--card-b:rgba(80,70,180,.16);
  --accent:#0891b2;--accent2:#0e9fc0;--purple:#7c3aed;--pink:#db2777;
  --green:#059669;--red:#e11d48;--amber:#d97706;
  --t1:#14123a;--t2:#3d3a72;--t3:#7a77b0;
  --shadow:0 12px 32px rgba(80,70,180,.16),inset 0 1px 0 rgba(255,255,255,.9);
  --input-bg:rgba(255,255,255,.75);--hover:rgba(8,145,178,.1);
  --glow:0 0 32px rgba(8,145,178,.15);
}
::selection{background:rgba(0,229,255,.32);color:#fff}
:focus-visible{outline:2px solid var(--accent2);outline-offset:2px}

/* ---- background: moving aurora + neon grid ---- */
body::before,html.light body::before{
  inset:-25%;
  background:
    radial-gradient(38% 34% at 82% 12%, rgba(0,229,255,.30), transparent 70%),
    radial-gradient(34% 32% at 12% 86%, rgba(255,43,214,.24), transparent 70%),
    radial-gradient(40% 36% at 55% 50%, rgba(138,92,255,.20), transparent 72%);
  animation:auroraShift 26s ease-in-out infinite alternate;
  will-change:transform;
}
html.light body::before{opacity:.55}
@keyframes auroraShift{
  0%{transform:translate3d(0,0,0) scale(1)}
  50%{transform:translate3d(-4%,3%,0) scale(1.08)}
  100%{transform:translate3d(3%,-3%,0) scale(1.03)}
}
body::after{
  content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background-image:
    linear-gradient(rgba(0,229,255,.07) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,229,255,.07) 1px,transparent 1px);
  background-size:48px 48px;
  -webkit-mask-image:radial-gradient(ellipse 90% 70% at 50% 0%,#000 0%,transparent 78%);
  mask-image:radial-gradient(ellipse 90% 70% at 50% 0%,#000 0%,transparent 78%);
  animation:gridDrift 20s linear infinite;
}
html.light body::after{opacity:.5}
@keyframes gridDrift{to{background-position:0 48px,48px 0}}

/* ---- scrollbar ---- */
::-webkit-scrollbar-thumb{background:linear-gradient(180deg,var(--accent),var(--purple));border-radius:99px}
::-webkit-scrollbar-track{background:transparent}

/* ---- sidebar ---- */
.sidebar{
  background:linear-gradient(200deg,rgba(26,16,60,.62),rgba(8,5,22,.7));
  border-left:1px solid rgba(0,229,255,.22);
  box-shadow:-14px 0 60px rgba(0,229,255,.07),inset 1px 0 0 rgba(255,255,255,.08);
}
html.light .sidebar{background:linear-gradient(200deg,rgba(255,255,255,.7),rgba(235,238,255,.6))}
.sb-toggle{background:var(--neon);border:2px solid var(--bg);box-shadow:0 0 18px rgba(0,229,255,.55)}
.sb-logo{border-bottom-color:rgba(255,255,255,.09)}
.sb-logo-icon{
  background:var(--neon);color:#fff;text-shadow:0 1px 6px rgba(0,0,0,.4);
  box-shadow:0 0 22px rgba(0,229,255,.55),0 0 44px rgba(255,43,214,.25);
  animation:logoPulse 3.4s ease-in-out infinite;
}
@keyframes logoPulse{
  50%{box-shadow:0 0 30px rgba(0,229,255,.8),0 0 60px rgba(255,43,214,.4)}
}
.sb-logo-name{text-shadow:0 0 14px rgba(0,229,255,.45)}
.nav-sec{color:var(--accent2);opacity:.6}
.nav-item{border:1px solid transparent}
.nav-item:hover{
  background:rgba(0,229,255,.08);color:var(--t1);
  border-color:rgba(0,229,255,.18);transform:translateX(-3px);
}
.nav-item.on{
  background:linear-gradient(270deg,rgba(0,229,255,.2),rgba(138,92,255,.08) 60%,transparent);
  color:#fff;border-color:rgba(0,229,255,.3);
  box-shadow:inset -3px 0 0 var(--accent),0 0 26px rgba(0,229,255,.2);
  text-shadow:0 0 12px rgba(0,229,255,.7);
}
html.light .nav-item.on{color:var(--accent);text-shadow:none}
.nav-item.on svg{color:var(--accent2);filter:drop-shadow(0 0 6px rgba(0,229,255,.9))}
.sidebar.collapsed .nav-item.on{box-shadow:0 0 22px rgba(0,229,255,.25)}
.sb-foot{border-top-color:rgba(255,255,255,.09)}
.sb-foot button,.sb-foot a.btn{background:rgba(255,255,255,.05);border-color:rgba(255,255,255,.12)}
.sb-foot button:hover,.sb-foot a.btn:hover{border-color:var(--accent);box-shadow:0 0 18px rgba(0,229,255,.25)}
.sb-foot a.danger{background:rgba(255,77,109,.1);border-color:rgba(255,77,109,.35);color:#ff7a92}
.sb-foot a.danger:hover{box-shadow:0 0 20px rgba(255,77,109,.4);border-color:var(--red)}

/* ---- mobile bar ---- */
.mob-bar{background:rgba(10,6,28,.6);backdrop-filter:var(--glass);border-bottom:1px solid rgba(0,229,255,.22)}
html.light .mob-bar{background:rgba(255,255,255,.7)}
.overlay{background:rgba(3,1,12,.55);backdrop-filter:blur(4px)}

/* ---- page header ---- */
.page-title{font-weight:800;text-shadow:0 0 22px rgba(0,229,255,.35)}
.page-title svg{color:var(--accent2);filter:drop-shadow(0 0 8px rgba(0,229,255,.8))}
.page-sub{color:var(--t3)}

/* ---- metrics: glass tiles with a charged neon edge ---- */
.metric{
  position:relative;overflow:hidden;
  background:linear-gradient(160deg,rgba(255,255,255,.075),rgba(255,255,255,.025));
  border:1px solid rgba(255,255,255,.12);
}
.metric::before{
  content:'';position:absolute;top:0;right:0;left:0;height:2px;
  background:linear-gradient(90deg,transparent,var(--mc,var(--accent)),transparent);
  box-shadow:0 0 18px 1px var(--mc,var(--accent));
  transform-origin:100% 50%;
  animation:charge 1s cubic-bezier(.2,.8,.2,1) both;
}
.metric::after{
  content:'';position:absolute;top:-40%;right:-20%;width:70%;height:90%;pointer-events:none;
  background:radial-gradient(closest-side,var(--mc,var(--accent)),transparent);opacity:.12;
}
.metrics .metric:nth-child(1){--mc:#00e5ff}
.metrics .metric:nth-child(2){--mc:#b26bff}
.metrics .metric:nth-child(3){--mc:#ff2bd6}
.metrics .metric:nth-child(4){--mc:#2dff9a}
.metrics .metric:nth-child(2)::before{animation-delay:.1s}
.metrics .metric:nth-child(3)::before{animation-delay:.2s}
.metrics .metric:nth-child(4)::before{animation-delay:.3s}
@keyframes charge{from{transform:scaleX(0);opacity:0}to{transform:scaleX(1);opacity:1}}
.metric:hover{
  border-color:var(--mc,var(--accent));
  box-shadow:var(--shadow),0 0 30px -4px var(--mc,var(--accent));
}
.metric-label{color:var(--t3)}
.metric-val{
  font-family:'Orbitron','Vazirmatn',sans-serif;font-weight:700;letter-spacing:.01em;
  color:#fff;text-shadow:0 0 18px var(--mc,var(--accent));
}
html.light .metric-val{color:var(--t1);text-shadow:none}

/* ---- cards ---- */
.card,.support-tile{
  background:linear-gradient(160deg,rgba(255,255,255,.065),rgba(255,255,255,.025));
  border:1px solid rgba(255,255,255,.11);
  box-shadow:var(--shadow);
}
.card-title svg{color:var(--accent2);filter:drop-shadow(0 0 6px rgba(0,229,255,.7))}
.action-card:hover{
  border-color:var(--accent);
  box-shadow:var(--shadow),0 0 34px rgba(0,229,255,.28);
  transform:translateY(-3px);
}
.action-card.purple:hover{border-color:var(--purple);box-shadow:var(--shadow),0 0 34px rgba(178,107,255,.32)}
.support-tile:hover{border-color:var(--accent);box-shadow:var(--shadow),0 0 30px rgba(0,229,255,.25)}
.support-icon{background:rgba(0,229,255,.1);box-shadow:inset 0 0 0 1px rgba(0,229,255,.25),0 0 18px rgba(0,229,255,.15)}

/* ---- buttons ---- */
.btn{
  background:rgba(255,255,255,.055);border:1px solid rgba(255,255,255,.14);
  position:relative;overflow:hidden;
}
.btn:hover{border-color:var(--accent);color:#fff;box-shadow:0 0 18px rgba(0,229,255,.3);background:rgba(0,229,255,.09)}
html.light .btn:hover{color:var(--accent)}
.btn:active{transform:scale(.97)}
.btn-p{
  background:linear-gradient(120deg,#0086e8,#6a45ff 55%,#d11cb8);background-size:180% 100%;
  border:none;color:#fff;text-shadow:0 1px 4px rgba(0,0,0,.35);
  box-shadow:0 0 22px rgba(0,134,232,.5),0 8px 26px rgba(106,69,255,.38);
  transition:background-position .5s,box-shadow .2s,transform .1s;
}
.btn-p:hover{background-position:100% 0;color:#fff;background-color:transparent;
  box-shadow:0 0 30px rgba(0,229,255,.65),0 8px 30px rgba(209,28,184,.45)}
.btn-p::after{
  content:'';position:absolute;top:0;bottom:0;width:40%;left:-60%;
  background:linear-gradient(100deg,transparent,rgba(255,255,255,.4),transparent);
  transform:skewX(-20deg);transition:left .6s;pointer-events:none;
}
.btn-p:hover::after{left:130%}
.btn-d{background:rgba(255,77,109,.1);border-color:rgba(255,77,109,.38);color:#ff7a92}
.btn-d:hover{border-color:var(--red);box-shadow:0 0 20px rgba(255,77,109,.45);background:rgba(255,77,109,.16);color:#fff}

/* ---- table ---- */
.table-wrap{background:rgba(255,255,255,.025);border-color:rgba(255,255,255,.11)}
th{background:rgba(0,229,255,.06);color:var(--accent2);letter-spacing:.01em;border-bottom:1px solid rgba(0,229,255,.2)}
html.light th{color:var(--accent)}
td{border-top-color:rgba(255,255,255,.07)}
tr:hover td{background:rgba(0,229,255,.07)}
tr:hover td:first-child{box-shadow:inset -3px 0 0 var(--accent)}

/* ---- range tabs ---- */
.range-tabs{background:rgba(255,255,255,.05);border-color:rgba(255,255,255,.12)}
.range-tab:hover{color:var(--t1)}
.range-tab.on{
  background:linear-gradient(120deg,#0086e8,#6a45ff);color:#fff;
  box-shadow:0 0 18px rgba(0,229,255,.5);
}

/* ---- form fields ---- */
.field label{color:var(--t3)}
.field input,.field select,.field textarea{
  background:var(--input-bg);border-color:rgba(255,255,255,.14);
}
.field input:focus,.field select:focus,.field textarea:focus{
  border-color:var(--accent);
  box-shadow:0 0 0 3px rgba(0,229,255,.14),0 0 24px rgba(0,229,255,.22);
}

/* ---- modal: opens with a quick pop ---- */
.modal-bg{background:rgba(3,1,12,.62);backdrop-filter:blur(10px) saturate(130%)}
.modal{
  background:linear-gradient(160deg,rgba(34,22,74,.82),rgba(10,6,28,.88));
  backdrop-filter:blur(28px) saturate(160%);
  border:1px solid rgba(0,229,255,.28);
  box-shadow:0 0 0 1px rgba(255,255,255,.05),0 30px 80px rgba(0,0,0,.6),0 0 70px rgba(138,92,255,.2);
}
html.light .modal{background:rgba(255,255,255,.86);border-color:rgba(8,145,178,.3)}
.modal-bg.open .modal{animation:modalPop .26s cubic-bezier(.2,.9,.3,1.15)}
@keyframes modalPop{from{opacity:0;transform:translateY(14px) scale(.96)}to{opacity:1;transform:none}}
.modal-title{text-shadow:0 0 16px rgba(0,229,255,.4)}
.link-box{background:rgba(0,0,0,.35);border-color:rgba(0,229,255,.22);color:var(--accent2)}
html.light .link-box{background:rgba(255,255,255,.7)}

/* ---- toast ---- */
.toast{
  background:rgba(14,9,34,.78);backdrop-filter:var(--glass);
  border-color:rgba(0,229,255,.45);box-shadow:0 0 34px rgba(0,229,255,.28),var(--shadow);
}
html.light .toast{background:rgba(255,255,255,.88)}

/* ---- switch ---- */
.slider{background:rgba(255,255,255,.14)}
.switch input:checked+.slider{background:var(--green);box-shadow:0 0 16px rgba(45,255,154,.65)}

/* ---- badges ---- */
.conn-badge.green{background:rgba(45,255,154,.14);color:#5dffb0;box-shadow:0 0 12px rgba(45,255,154,.25)}
.conn-badge.orange{background:rgba(255,194,61,.14);color:#ffd36b;box-shadow:0 0 12px rgba(255,194,61,.22)}
.conn-badge.red{background:rgba(255,77,109,.16);color:#ff8aa0;box-shadow:0 0 12px rgba(255,77,109,.25)}
.conn-badge.gray{background:rgba(255,255,255,.08);color:var(--t3)}

/* ---- logs & spinner ---- */
.log-item{border-bottom-color:rgba(255,255,255,.07)}
.log-time{color:var(--accent2);opacity:.7}
.spin{border-color:rgba(255,255,255,.1);border-top-color:var(--accent);border-right-color:var(--pink);box-shadow:0 0 20px rgba(0,229,255,.35)}

@media(max-width:900px){
  /* lighter blur on phones for smooth scrolling */
  :root{--glass:blur(14px) saturate(150%)}
  body::after{display:none}
}
@media(prefers-reduced-motion:reduce){
  *,*::before,*::after{animation:none!important;transition-duration:.01ms!important}
}

/* ---- layout: sidebar left, like the reference ---- */
.sidebar{right:auto;left:0;border-left:0;border-right:1px solid rgba(0,229,255,.22);box-shadow:14px 0 60px rgba(0,229,255,.07),inset -1px 0 0 rgba(255,255,255,.08)}
.sb-toggle{left:auto;right:-15px}
.main{margin-right:0;margin-left:var(--sb)}.main.expanded{margin-right:0;margin-left:var(--sb-c)}
.nav-item:hover{transform:translateX(3px)}
@media(max-width:900px){.sidebar{transform:translateX(-100%)}.sidebar.open{transform:none}.main,.main.expanded{margin-left:0}.topbar{display:none}}
/* ---- top bar ---- */
.topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:18px}
.tb-pill,.tb-admin,.tb-btn{background:rgba(255,255,255,.05);border:1px solid rgba(0,229,255,.22);backdrop-filter:var(--glass);border-radius:14px;box-shadow:inset 0 1px 0 rgba(255,255,255,.1)}
.tb-pill{display:flex;align-items:center;gap:10px;padding:9px 16px;font-size:12px;font-weight:600;color:var(--green)}
.tb-clock{color:var(--t2);font-family:Orbitron,Vazirmatn,sans-serif;font-size:11px;direction:ltr}
.live{width:9px;height:9px;border-radius:50%;background:var(--green);box-shadow:0 0 10px var(--green);animation:livePulse 1.8s ease-in-out infinite}
@keyframes livePulse{50%{opacity:.35;transform:scale(.8)}}
.tb-right{display:flex;gap:10px;align-items:center}
.tb-btn{width:42px;height:42px;display:flex;align-items:center;justify-content:center;color:var(--accent2);cursor:pointer}
.tb-btn svg{width:18px;height:18px}.tb-btn:hover{box-shadow:0 0 18px rgba(0,229,255,.35)}
.tb-admin{display:flex;align-items:center;gap:10px;padding:5px 14px 5px 10px}
.tb-admin b{display:block;font-size:12px}.tb-admin small{color:var(--t3);font-size:10px}
.tb-av{width:32px;height:32px;border-radius:50%;background:var(--neon);display:flex;align-items:center;justify-content:center;box-shadow:0 0 14px rgba(0,229,255,.5)}
.tb-av svg{width:16px;height:16px;color:#fff}
/* ---- dashboard grid (side column first = far right in RTL) ---- */
.dash-grid{display:grid;grid-template-columns:300px minmax(0,1fr);gap:16px;align-items:start}
.dash-side .card,.dash-main .card{margin-bottom:16px}
@media(max-width:1180px){.dash-grid{grid-template-columns:1fr}.dash-side{order:2}}
.hero{position:relative;overflow:hidden;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:26px 28px;margin-bottom:16px;border-radius:22px;
  background:linear-gradient(120deg,rgba(0,134,232,.35),rgba(106,69,255,.3) 55%,rgba(209,28,184,.22));border:1px solid rgba(109,243,255,.5);
  box-shadow:0 0 40px rgba(0,229,255,.22),inset 0 0 40px rgba(0,229,255,.08),inset 0 1px 0 rgba(255,255,255,.2);backdrop-filter:var(--glass)}
.hero::after{content:'';position:absolute;top:0;bottom:0;width:30%;left:-40%;background:linear-gradient(100deg,transparent,rgba(255,255,255,.14),transparent);transform:skewX(-20deg);animation:heroSweep 6s ease-in-out infinite}
@keyframes heroSweep{60%,100%{left:130%}}
.hero h2{font-size:22px;font-weight:800;text-shadow:0 0 22px rgba(0,229,255,.6)}.hero p{color:var(--t2);margin-top:6px;font-size:13px}
.hero-s{display:flex;align-items:center;gap:12px;padding:12px 16px;border-radius:16px;background:rgba(5,3,20,.4);border:1px solid rgba(0,229,255,.3)}
.hero-s small{display:block;color:var(--t3);font-size:11px}.hero-s b{color:var(--green);text-shadow:0 0 12px var(--green);font-size:15px}
.metric{display:flex;align-items:center;gap:14px}.m-ico{width:50px;height:50px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;color:var(--mc);background:rgba(255,255,255,.05);box-shadow:inset 0 0 0 1px var(--mc),0 0 18px -2px var(--mc)}
.m-ico svg{width:22px;height:22px}.m-body{min-width:0}.metric-val{font-size:22px}
.g21{display:grid;grid-template-columns:minmax(0,1.7fr) minmax(0,1fr);gap:16px}@media(max-width:900px){.g21{grid-template-columns:1fr}}
.tchart{height:210px;direction:ltr}.tchart svg{width:100%;height:100%;overflow:visible}
.tchart text{fill:var(--t3);font-size:9px;font-family:Vazirmatn,sans-serif}
.donut-w{position:relative;width:150px;margin:6px auto 14px}.donut{width:150px;height:150px;transform:rotate(-90deg)}
.donut circle{fill:none;stroke-width:9}.d-bg{stroke:rgba(255,255,255,.1)}.d-fg{stroke:var(--green);stroke-linecap:round;filter:drop-shadow(0 0 7px var(--green));transition:stroke-dasharray .9s cubic-bezier(.2,.8,.2,1)}
.donut-c{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}.donut-c b{font:700 24px Orbitron,Vazirmatn,sans-serif;text-shadow:0 0 14px var(--green)}.donut-c small{color:var(--t3);font-size:10px}
.legend>div{display:flex;align-items:center;gap:8px;padding:6px 0;font-size:12px;color:var(--t2)}.legend i{width:9px;height:9px;border-radius:50%}.legend b{margin-right:auto;font-family:Orbitron,Vazirmatn;font-size:11px}
.qa-list{display:flex;flex-direction:column;gap:8px}
.qa{display:flex;align-items:center;gap:12px;padding:12px 14px;border-radius:12px;background:rgba(0,229,255,.05);border:1px solid rgba(0,229,255,.28);color:var(--t1);font-family:inherit;font-size:13px;cursor:pointer;transition:.15s}
.qa svg{width:17px;height:17px;color:var(--accent2)}.qa:hover{background:rgba(0,229,255,.12);box-shadow:0 0 20px rgba(0,229,255,.28);transform:translateX(3px)}
.st{display:flex;justify-content:space-between;align-items:center;padding:10px 12px;margin-bottom:6px;border-radius:10px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);font-size:12px}
.st em{font-style:normal;color:var(--green);font-weight:700;display:flex;align-items:center;gap:6px;font-size:11px}.st em::before{content:'';width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 8px currentColor}
.acts .log-item{padding:10px 12px;margin-bottom:6px;border:1px solid rgba(255,255,255,.08);border-radius:12px;background:rgba(255,255,255,.03)}
.bt-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}@media(max-width:900px){.bt-row{grid-template-columns:1fr 1fr}}
.bt{display:flex;align-items:center;gap:12px;padding:14px;border-radius:16px;font-family:inherit;color:var(--t1);text-align:right;cursor:pointer;background:linear-gradient(160deg,rgba(255,255,255,.06),rgba(255,255,255,.02));border:1px solid rgba(255,255,255,.12);transition:.2s}
.bt:hover{border-color:var(--accent);box-shadow:0 0 26px rgba(0,229,255,.25);transform:translateY(-2px)}
.bt-i{width:40px;height:40px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:rgba(138,92,255,.2);color:var(--accent2);flex-shrink:0}.bt-i svg{width:18px;height:18px}
.bt b{display:block;font-size:12px}.bt small{color:var(--t3);font-size:10px}
.pill-on{background:rgba(45,255,154,.14);color:#5dffb0;padding:3px 12px;border-radius:99px;font-size:11px;font-weight:700;box-shadow:0 0 12px rgba(45,255,154,.25)}
.pill-off{background:rgba(255,77,109,.16);color:#ff8aa0;padding:3px 12px;border-radius:99px;font-size:11px;font-weight:700}
/* ================= /NEON GLASS ================= */
</style>
</head>
<body>

<div class="mob-bar">
  <div style="font-weight:800;font-size:15px">AHBPanel</div>
  <button class="btn btn-sm" id="mobMenuBtn" aria-label="menu">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
  </button>
</div>
<div class="overlay" id="overlay"></div>

<aside class="sidebar" id="sidebar">
  <button class="sb-toggle" id="sbToggle" title="Toggle">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M15 18l-6-6 6-6"/></svg>
  </button>
  <div class="sb-logo">
    <div class="sb-logo-icon">AHB</div>
    <div class="sb-logo-text">
      <div class="sb-logo-name">AHBPanel</div>
      <div class="sb-logo-ver">v14.5.0</div>
    </div>
  </div>
  <nav class="nav">
    <div class="nav-sec" data-i18n="sec_panel">پنــــل</div>
    <button class="nav-item on" data-page="dash" data-perm="dash">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>
      <span class="nav-label" data-i18n="nav_dash">داشبـورد</span>
    </button>
    <button class="nav-item" data-page="configs" data-perm="configs">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
      <span class="nav-label" data-i18n="nav_configs">کانفیگ‌هـا</span>
    </button>
    <button class="nav-item" data-page="groups" data-perm="configs">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
      <span class="nav-label" data-i18n="nav_groups">گروه‌هـا</span>
    </button>
    <button class="nav-item" data-page="create" data-perm="create">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 5v14M5 12h14"/></svg>
      <span class="nav-label" data-i18n="nav_create">ساخت کانفیـگ</span>
    </button>
    <button class="nav-item" data-page="stats" data-perm="stats">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 3v18h18"/><path d="M7 16l4-8 4 4 5-6"/></svg>
      <span class="nav-label" data-i18n="nav_stats">امـار</span>
    </button>
    <button class="nav-item" data-page="logs" data-perm="logs">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/></svg>
      <span class="nav-label" data-i18n="nav_logs">لاگ فعالیـت</span>
    </button>
    <div class="nav-sec" data-i18n="sec_sys">سیستـم</div>
    <button class="nav-item" data-page="telegram" data-perm="telegram">
      <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18"><path d="M12 0C5.37 0 0 5.37 0 12s5.37 12 12 12 12-5.37 12-12S18.63 0 12 0zm5.56 8.2-1.86 8.77c-.14.62-.5.77-1.01.48l-2.8-2.06-1.35 1.3c-.15.15-.27.27-.55.27l.2-2.84 5.18-4.68c.22-.2-.05-.31-.35-.12l-6.4 4.03-2.76-.86c-.6-.19-.61-.6.12-.89l10.78-4.16c.5-.18.94.12.78.86z"/></svg>
      <span class="nav-label" data-i18n="nav_telegram">ای اچ بی بات</span>
    </button>
    <button class="nav-item" data-page="news" data-perm="news">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 22h16a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v16a2 2 0 0 1-2 2Zm0 0a2 2 0 0 1-2-2v-9c0-1.1.9-2 2-2h2"/><path d="M18 14h-8M15 18h-5M10 6h8v4h-8V6Z"/></svg>
      <span class="nav-label" data-i18n="nav_news">اخبـار</span>
    </button>
    <button class="nav-item" data-page="admins" data-perm="admins">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>
      <span class="nav-label" data-i18n="nav_admins">ادمین‌هـا</span>
    </button>
    <button class="nav-item" data-page="settings" data-perm="settings">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
      <span class="nav-label" data-i18n="nav_settings">تنظیمـات</span>
    </button>
    <button class="nav-item" data-page="support" data-perm="support">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 18v-6a9 9 0 0 1 18 0v6"/><path d="M21 19a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3zM3 19a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H3z"/></svg>
      <span class="nav-label" data-i18n="nav_support">پشتیبانـی</span>
    </button>
    <button class="nav-item" data-page="donate">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>
      <span class="nav-label" data-i18n="nav_donate">حمایت مالـی</span>
    </button>
  </nav>
  <div class="sb-foot">
    <button type="button" id="themeBtn" onclick="toggleTheme()">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="16" height="16"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>
      <span id="themeLabel" data-i18n="theme">تم روشـن</span>
    </button>
    <button type="button" onclick="refreshAll()" title="Stats">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="16" height="16"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.1-3.4L23 10M1 14l5.4 4.4A9 9 0 0 0 20.5 15"/></svg>
      <span data-i18n="refresh_stats">بروزرسانی امـار</span>
    </button>
    <button type="button" onclick="panelUpdate()" title="Panel" style="background:rgba(16,185,129,.12);border-color:rgba(16,185,129,.35);color:#34d399">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="16" height="16"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 16h5v5"/></svg>
      <span data-i18n="refresh_panel">بروزرسانی پنـل</span>
    </button>
    <a href="/logout" class="btn danger">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="16" height="16"><path d="M10 5H5v14h5"/><path d="m14 8 4 4-4 4"/><path d="M18 12H9"/></svg>
      <span data-i18n="logout">خروج</span>
    </a>
  </div>
</aside>

<main class="main" id="main">

<section class="page on" id="page-dash">
  <div class="topbar">
    <div class="tb-pill"><i class="live"></i><span id="tbStatus">سیستم فعال است</span><span class="tb-clock" id="tbClock">--:--:--</span></div>
    <div class="tb-right">
      <button class="tb-btn" onclick="refreshAll()" title="refresh"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg></button>
      <div class="tb-admin"><div class="tb-av"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1"/></svg></div><div><b id="tbUser">admin</b><small id="tbRole">مدیر</small></div></div>
    </div>
  </div>
  <div class="dash-grid">
    <aside class="dash-side">
      <div class="card"><div class="card-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg><span>عملیات سریع</span></div>
        <div class="qa-list"><button class="qa" onclick="goPage('configs')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg><span>مدیریت کانفیگ‌ها</span></button><button class="qa" onclick="goPage('create')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M5 12h14"/></svg><span>ایجاد کانفیگ جدید</span></button><button class="qa" onclick="goPage('groups')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg><span>گروه‌ها و ساب‌ها</span></button><button class="qa" onclick="goPage('telegram')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2 11 13M22 2l-7 20-4-9-9-4z"/></svg><span>تنظیمات ربات تلگرام</span></button><button class="qa" onclick="goPage('settings')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 1v3M12 20v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M1 12h3M20 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/></svg><span>تنظیمات پنل</span></button></div></div>
      <div class="card"><div class="card-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 1v3M12 20v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M1 12h3M20 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/></svg><span>وضعیت سیستم</span></div>
        <div class="st-list"><div class="st"><span>سرور اصلی</span><em id="stServer">فعال</em></div><div class="st"><span>آپتایم</span><em id="stUp">—</em></div><div class="st"><span>درخواست‌ها</span><em id="stReq">—</em></div><div class="st"><span>خطاها</span><em id="stErr">—</em></div></div></div>
      <div class="card"><div class="card-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg><span>آخرین فعالیت‌ها</span></div><div id="dashActs" class="acts"></div></div>
    </aside>
    <div class="dash-main">
      <div class="hero"><div class="hero-t"><h2>به پنل مدیریت AHB خوش آمدید</h2><p>مدیریت آسان، سریع و حرفه‌ای</p><div class="page-sub" id="lastUpd" data-i18n="loading">در حال بارگـذاری...</div></div>
        <div class="hero-s"><svg viewBox="0 0 64 64" width="64" height="64"><g fill="none" stroke="#6df3ff" stroke-width="2"><rect x="10" y="8" width="44" height="14" rx="4"/><rect x="10" y="25" width="44" height="14" rx="4"/><rect x="10" y="42" width="44" height="14" rx="4"/></g><g fill="#2dff9a"><circle cx="18" cy="15" r="2"/><circle cx="18" cy="32" r="2"/><circle cx="18" cy="49" r="2"/></g></svg><div><small>وضعیت سرور</small><b>آنلاین</b></div></div></div>
      <div class="metrics">
        <div class="metric"><div class="m-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg></div><div class="m-body"><div class="metric-label" data-i18n="m_conns">اتصالات فعـال</div><div class="metric-val" id="mConns">—</div></div></div><div class="metric"><div class="m-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12M7 11l5 5 5-5M4 21h16"/></svg></div><div class="m-body"><div class="metric-label" data-i18n="m_traffic">ترافیک کـل</div><div class="metric-val" id="mTraffic">—</div></div></div><div class="metric"><div class="m-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/></svg></div><div class="m-body"><div class="metric-label" data-i18n="m_links">کانفیگ‌هـا</div><div class="metric-val" id="mLinks">—</div></div></div><div class="metric"><div class="m-ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1"/></svg></div><div class="m-body"><div class="metric-label" data-i18n="m_uptime">آپتایـم سرور</div><div class="metric-val" id="mUptime" style="font-size:15px">—</div></div></div>
      </div>
      <div class="g21">
        <div class="card"><div class="card-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><path d="M7 16l4-8 4 4 5-6"/></svg><span>نمودار ترافیک مصرفی (ساعتی)</span></div><div id="trafficChart" class="tchart"></div></div>
        <div class="card"><div class="card-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg><span>کانفیگ‌های فعال</span></div>
          <div class="donut-w"><svg viewBox="0 0 120 120" class="donut"><circle cx="60" cy="60" r="48" class="d-bg"/><circle cx="60" cy="60" r="48" class="d-fg" id="donutFg" stroke-dasharray="0 302"/></svg><div class="donut-c"><b id="donutPct">0%</b><small>فعال</small></div></div>
          <div class="legend"><div><i style="background:#2dff9a"></i><span>فعال</span><b id="lgAct">0</b></div><div><i style="background:#ff4d6d"></i><span>غیرفعال</span><b id="lgOff">0</b></div><div><i style="background:#8a5cff"></i><span>کل</span><b id="lgAll">0</b></div></div></div>
      </div>
      <div class="card"><div class="card-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg><span>آخرین کانفیگ‌ها</span><button class="btn btn-sm" style="margin-right:auto" onclick="goPage('configs')">مشاهده همه</button></div>
        <div class="table-wrap"><table><thead><tr><th>نام</th><th>پروتکل</th><th>انقضا</th><th>مصرف</th><th>حجم مجاز</th><th>وضعیت</th></tr></thead><tbody id="dashLinks"></tbody></table></div></div>
      <div class="bt-row"><button class="bt" onclick="goPage('settings')"><div class="bt-i"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 1v3M12 20v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M1 12h3M20 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/></svg></div><div><b>تنظیمات کلی</b><small>پیکربندی پنل</small></div></button><button class="bt" onclick="goPage('groups')"><div class="bt-i"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg></div><div><b>مدیریت گروه‌ها</b><small>ساخت و ویرایش</small></div></button><button class="bt" onclick="goPage('stats')"><div class="bt-i"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><path d="M7 16l4-8 4 4 5-6"/></svg></div><div><b>گزارش ترافیک</b><small>آمار و گزارش‌ها</small></div></button><button class="bt" onclick="goPage('logs')"><div class="bt-i"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg></div><div><b>لاگ فعالیت</b><small>فعالیت‌های اخیر</small></div></button></div>
    </div>
  </div>
</section>

<section class="page" id="page-configs">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg><span data-i18n="nav_configs">کانفیگ‌ها</span></div>
      <div class="page-sub" data-i18n="configs_sub">مدیریـت لینک‌هــا · VLESS و سـاب</div>
    </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <input id="cfgSearch" placeholder="جستجو..." oninput="filterConfigs()" style="padding:8px 12px;border-radius:10px;border:1px solid var(--card-b);background:var(--input-bg);color:var(--t1);font-family:inherit;font-size:12px;min-width:140px">

      <button class="btn btn-p btn-sm" onclick="goPage('create')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M12 5v14M5 12h14"/></svg></button>
      <button class="btn btn-sm" onclick="refreshAll()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.1-3.4L23 10"/></svg></button>
    </div>
  </div>
  <div class="card" style="padding:0">
    <div class="table-wrap">
      <div id="bulkBar" style="display:none"></div>
      <table>
        <thead><tr>
          <th style="width:40px;text-align:center;padding:10px 8px">
            <input type="checkbox" id="chkAll" onchange="toggleSelectAll(this.checked);updateBulkBar()" title="انتخاب همه" style="width:16px;height:16px;margin:0;vertical-align:middle;cursor:pointer">
          </th>
          <th style="width:28px;padding:10px 4px"></th>
          <th data-i18n="th_name">نـام</th><th data-i18n="th_proto">پروتکـل</th><th data-i18n="th_status">وضعیت</th>
          <th data-i18n="th_usage">مصـرف</th><th data-i18n="th_ops">عملیـات</th>
        </tr></thead>
        <tbody id="linksTable"><tr><td colspan="7" style="text-align:center;color:var(--t3);padding:32px">...</td></tr></tbody>
      </table>
    </div>
  </div>
</section>

<section class="page" id="page-create">
  <div class="page-head">
    <div><div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 5v14M5 12h14"/></svg><span data-i18n="nav_create">ساخت کانفیگ</span></div></div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="card-title" data-i18n="manual_create">ساخت دستی</div>
      <div class="field"><label data-i18n="label_name">نام</label>
        <div style="display:flex;gap:8px;align-items:center">
          <input id="cName" placeholder="auto" style="flex:1">
          <button type="button" class="btn btn-sm" onclick="randomName()" title="Random" style="min-width:44px;height:42px">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M16 3h5v5M4 20L21 3M21 16v5h-5M15 15l6 6M4 4l5 5"/></svg>
          </button>
        </div>
      </div>
            <div class="field"><label data-i18n="label_proto">پروتکـل</label><select id="cProto"></select></div>
      <div class="field"><label>گروه</label><select id="cGroup"></select></div>
<div class="form-row">
        <div class="field"><label data-i18n="label_count">تعداد کانفیگ در ساب (۱–۴۰)</label><input id="cCount" type="number" value="1" min="1" max="40"></div>
        <div class="field"><label data-i18n="label_days">انقضـا (روز)</label><input id="cDays" type="number" value="0" min="0"></div>
      </div>
      <div class="form-row">
        <div class="field"><label data-i18n="label_limit">محدودیت حجم</label><input id="cLimit" type="number" value="0" min="0"></div>
        <div class="field"><label data-i18n="label_unit">واحد</label><select id="cUnit"><option>GB</option><option>MB</option><option>KB</option></select></div>
      </div>
      <div class="form-row">
        <div class="field"><label data-i18n="label_ip">محدودیت IP</label><input id="cIp" type="number" value="0" min="0"></div>
        <div class="field"><label data-i18n="label_speed">سرعـت (Mbps)</label><input id="cSpeed" type="number" value="0" min="0"></div>
      </div>
      <button class="btn btn-p" style="width:100%" onclick="doManualCreate()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 5v14M5 12h14"/></svg>
        <span data-i18n="btn_create">ساخت</span>
      </button>
    </div>
    <div class="card" style="border-color:rgba(139,92,246,.35)">
      <div class="card-title" data-i18n="auto_create">ساخت خودکـار (پیشنهــادی)</div>
      <p style="color:var(--t2);font-size:13px;line-height:1.75;margin-bottom:14px" data-i18n="auto_desc">با یک کلیک کانفیگ بهینه ساخته می‌شود. بعد از ساخت لینک VLESS و ساب در اختیار شماست.</p>
      <div class="field"><label data-i18n="label_proto">پروتکـل</label><select id="aProto"></select></div>
      <div class="field"><label data-i18n="label_count">تعداد کانفیگ در سـاب (1-40)</label><input id="aCount" type="number" value="1" min="1" max="40"></div>
      <button class="btn btn-p" style="width:100%;background:linear-gradient(135deg,#8b5cf6,#6366f1)" onclick="doAutoCreate()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="12" cy="12" r="3"/><path d="M12 2v2M12 20v2"/></svg>
        <span data-i18n="btn_auto">ساخـت خودکــار</span>
      </button>
    </div>
  </div>
</section>


<section class="page" id="page-groups">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg><span data-i18n="nav_groups">گروه‌ها</span></div>
      <div class="page-sub">ساخـت گـروه و اختصـاص کانفیـگ هـای دستـی و خودکـار</div>
    </div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="card-title">ساخت گروه جدیـد</div>
      <div class="field"><label>نام گروه</label><input id="grpName" placeholder="مثلا اختصاصـی"></div>
      <button class="btn btn-p" style="width:100%" onclick="createGroup()">ساخـت گروه</button>
    </div>
    <div class="card" style="padding:0">
      <div style="padding:16px 18px;border-bottom:1px solid var(--card-b);font-weight:700">لیست گروه‌ها</div>
      <div id="groupsList" style="padding:12px;max-height:480px;overflow:auto">...</div>
    </div>
  </div>
</section>
<section class="page" id="page-stats">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 3v18h18"/><path d="M7 16l4-8 4 4 5-6"/></svg><span data-i18n="nav_stats">آمار</span></div>
      <div class="page-sub" data-i18n="stats_sub">ترافیـک و اتصـالات · فیلتـر زمانـی</div>
    </div>
    <div class="range-tabs" id="rangeTabs">
      <button class="range-tab" data-r="day" onclick="setRange('day',this)" data-i18n="r_day">روز</button>
      <button class="range-tab" data-r="week" onclick="setRange('week',this)" data-i18n="r_week">هفتـه</button>
      <button class="range-tab on" data-r="month" onclick="setRange('month',this)" data-i18n="r_month">مـاه</button>
      <button class="range-tab" data-r="all" onclick="setRange('all',this)" data-i18n="r_all">کـل</button>
    </div>
  </div>
  <div class="metrics">
    <div class="metric"><div class="metric-label" data-i18n="m_traffic">ترافیـک</div><div class="metric-val" id="sTraffic">—</div></div>
    <div class="metric"><div class="metric-label" data-i18n="m_conns">اتصـالات</div><div class="metric-val" id="sConns">—</div></div>
    <div class="metric"><div class="metric-label" data-i18n="m_links">کانفیـگ فعـال</div><div class="metric-val" id="sActive">—</div></div>
    <div class="metric"><div class="metric-label" data-i18n="m_uptime">آپتایـم</div><div class="metric-val" id="sUptime" style="font-size:16px">—</div></div>
  </div>
  <div class="card"><div class="card-title" data-i18n="panel_info">اطلاعات کل پنل</div><div id="panelInfo" style="font-size:13px;color:var(--t2);line-height:2"></div></div>
</section>

<section class="page" id="page-logs">
  <div class="page-head">
    <div><div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg><span data-i18n="nav_logs">لاگ فعالیت</span></div></div>
    <button class="btn btn-sm" onclick="loadLogs()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.1-3.4L23 10"/></svg></button>
  </div>
  <div class="card" id="logsBox"><div style="text-align:center;color:var(--t3);padding:28px">...</div></div>
</section>

<section class="page" id="page-settings">
  <div class="page-head"><div><div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/></svg><span data-i18n="nav_settings">تنظیمات</span></div></div></div>
  <div class="card">
    <div class="card-title" data-i18n="theme">تــــم هـا</div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button class="btn btn-p" onclick="setTheme('dark')" data-i18n="theme_dark">تـم دارک</button>
      <button class="btn" onclick="setTheme('light')" data-i18n="theme_light">تـم روشـن</button>
    </div>
  </div>
  <div class="card">
    <div class="card-title" data-i18n="lang_label">زبـان / Language</div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button class="btn btn-p" onclick="setLang('fa')">فارسـی</button>
      <button class="btn" onclick="setLang('en')">English</button>
    </div>
  </div>
  <div class="card">
    <div class="card-title" data-i18n="change_pw">تغییر رمز عبـور</div>
    <div class="field"><label data-i18n="pw_cur">رمز فعلـی</label><input type="password" id="pwCur"></div>
    <div class="field"><label data-i18n="pw_new">رمـز جدیـد</label><input type="password" id="pwNew"></div>
    <div class="field"><label data-i18n="pw_cf">تکـرار رمـز</label><input type="password" id="pwCf"></div>
    <button class="btn btn-p" onclick="doChangePw()"><span data-i18n="btn_save">ذخیـره</span></button>
  </div>
  
  <div class="card">
    <div class="card-title">امنیت بیشتـر</div>
    <p style="font-size:12px;color:var(--t3);line-height:1.8;margin-bottom:12px">پـس از 5 تـلاش ناموفـق، ایپـی به مدت 30 دقیقه مسدود می‌شود.</p>
    <div id="secStatus" style="font-size:12px;color:var(--t2);margin-bottom:10px">—</div>
    <button class="btn btn-sm" onclick="loadSecurity()">بروزرسانی وضعیـت</button>
    <button class="btn btn-sm btn-d" onclick="unlockAllIps()">رفع مسدودی همـه ایپــی هــا</button>
  </div>
<div class="card">
    <div class="card-title">بــک آپ و بازیابــی</div>
    <p style="font-size:12px;color:var(--t3);line-height:1.8;margin-bottom:14px">در صورت خرابی پنل، بک‌آپ را دانلود کنید و در پنل جدید وارد کنید.</p>
    <div class="g2" style="margin-bottom:12px">
      <button class="btn btn-p" style="width:100%" onclick="downloadBackup('users')">دانلود بک‌آپ کاربران</button>
      <button class="btn btn-p" style="width:100%;background:linear-gradient(135deg,#8b5cf6,#6366f1)" onclick="downloadBackup('bot')">دانلود بک‌آپ ربات</button>
    </div>
    <div class="field">
      <label>وارد کردن بـک‌آپ کاربران</label>
      <input type="file" id="restoreUsersFile" accept="application/json,.json" style="padding:10px">
      <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
        <button class="btn btn-sm" onclick="restoreUsers('merge')">ادغام بــــا فعلـی</button>
        <button class="btn btn-sm btn-d" onclick="restoreUsers('replace')">جایگزینی کامـل</button>
      </div>
    </div>
    <div class="field" style="margin-top:12px">
      <label>وارد کردن بــک آپ ربـات</label>
      <input type="file" id="restoreBotFile" accept="application/json,.json" style="padding:10px">
      <button class="btn btn-sm" style="margin-top:8px" onclick="restoreBot()">بازیابـی ربـات</button>
    </div>
  </div>
</section>


<section class="page" id="page-news">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 22h16a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v16a2 2 0 0 1-2 2Zm0 0a2 2 0 0 1-2-2v-9c0-1.1.9-2 2-2h2"/></svg><span data-i18n="nav_news">اخبار</span></div>
      
    </div>
    <button class="btn btn-sm" onclick="loadNews(true)"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.1-3.4L23 10"/></svg> <span data-i18n="refresh_news">بروزرسانی اطلاعیه</span></button>
  </div>
  <div class="card" id="newsCard">
    <div class="card-title" id="newsTitle">—</div>
    <div id="newsBody" style="white-space:pre-wrap;line-height:1.9;color:var(--t2);font-size:13px">...</div>
    <div id="newsMeta" style="margin-top:14px;font-size:11px;color:var(--t3)"></div>
  </div>
</section>

<section class="page" id="page-admins">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg><span data-i18n="nav_admins">(نسخـه دمـو) ادمیـن هــا</span></div>
      <div class="page-sub" data-i18n="admins_sub">ساخت اکانت ادمین با دسترسی سفارشـی</div>
    </div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="card-title" data-i18n="admin_create">ساخـت اکانـت ادمیـن</div>
      <div class="field"><label data-i18n="admin_user">نام کاربـری</label><input id="adUser" placeholder="user1" style="direction:ltr;text-align:left"></div>
      <div class="form-row">
        <div class="field"><label data-i18n="admin_pw">رمز عبـور</label><input id="adPw" type="password"></div>
        <div class="field"><label data-i18n="admin_pw2">تکرار رمـز</label><input id="adPw2" type="password"></div>
      </div>
      <div class="form-row">
        <div class="field"><label data-i18n="label_limit">حجـم</label><input id="adLimit" type="number" value="0" min="0"></div>
        <div class="field"><label data-i18n="label_unit">واحـد</label><select id="adUnit"><option>GB</option><option>MB</option></select></div>
      </div>
      <div class="field"><label data-i18n="label_days">مدت اعتبـار (روز)</label><input id="adDays" type="number" value="0" min="0"></div>
      <div class="card-title" style="margin-top:8px" data-i18n="admin_perms">دسترسی‌ها</div>
      <div id="adPerms" style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px"></div>
      <button class="btn btn-p" style="width:100%;margin-top:14px" onclick="createAdmin()" data-i18n="admin_btn">ساخت اکانت</button>
    </div>
    <div class="card" style="padding:0">
      <div style="padding:16px 18px;border-bottom:1px solid var(--card-b);font-weight:700" data-i18n="admin_list">لیست ادمین‌ها</div>
      <div id="adminsList" style="padding:12px;max-height:480px;overflow:auto"><div style="color:var(--t3);text-align:center;padding:20px">...</div></div>
    </div>
  </div>
</section>


<section class="page" id="page-donate">
  <div class="page-head" style="justify-content:center">
    <div>
      <div class="page-title" style="justify-content:center">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>
        <span data-i18n="nav_donate">حمایـت مالــــی</span>
      </div>
    </div>
  </div>
  <div style="display:flex;justify-content:center;width:100%">
  <div class="card" style="max-width:560px;width:100%;line-height:2;font-size:14px;color:var(--t2);text-align:center">
    <div style="font-size:16px;font-weight:800;color:var(--t1);margin-bottom:12px">💖 حمایت از پروژه (اختیاری)</div>
    <p>اگه از پروژه خوشتون اومده یا براتون مفید بوده، می‌تونید با یه حمایت کوچیک مالی به ادامه‌ی توسعه و بهتر شدن پروژه کمک کنید. 🫶🏻✨</p>
    <p style="margin-top:10px">💰 هر مقدار حمایتی، حتی کم، برای ما ارزشمنده و باعث میشه با انگیزه‌ی بیشتری ادامه بدیم! 🚀❤️‍🔥</p>
    <p style="margin-top:10px">🔗 لینک حمایت مالی:</p>
    <div style="margin-top:12px;display:flex;justify-content:center"><a href="https://t.me/ahb_panel" target="_blank" rel="noopener" class="btn btn-p" style="display:inline-flex;text-decoration:none">🙂 reymit.ir/moditor</a></div>
    <p style="margin-top:16px;font-size:13px;color:var(--t3)">🙏🏻 ممنون از حمایت و همراهی‌تون عشقا! ❤️‍🔥🌹</p>
    <p style="margin-top:8px;font-size:12px;color:var(--t3)">کاملاً اختیاری است و هیچ اجباری وجود ندارد.</p>
  </div>
  </div>
</section>

<section class="page" id="page-support">
  <div class="page-head"><div><div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 18v-6a9 9 0 0 1 18 0v6"/></svg><span data-i18n="nav_support">پشتیبانی</span></div></div></div>
  <div class="support-grid">
    <a class="support-tile" href="https://github.com/ahb-panel/ahb_panel" target="_blank" rel="noopener">
      <div class="support-icon"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.44 9.8 8.2 11.4.6.1.82-.26.82-.58v-2.03c-3.34.73-4.03-1.61-4.03-1.61-.55-1.39-1.34-1.76-1.34-1.76-1.1-.75.08-.74.08-.74 1.21.09 1.85 1.24 1.85 1.24 1.07 1.84 2.81 1.31 3.5 1 .11-.78.42-1.31.76-1.61-2.66-.3-5.46-1.33-5.46-5.93 0-1.31.47-2.38 1.24-3.22-.12-.3-.54-1.52.12-3.18 0 0 1.01-.32 3.3 1.23a11.5 11.5 0 0 1 6 0c2.29-1.55 3.3-1.23 3.3-1.23.66 1.66.24 2.88.12 3.18.77.84 1.24 1.91 1.24 3.22 0 4.61-2.8 5.62-5.48 5.92.43.37.81 1.1.81 2.22v3.29c0 .32.22.69.83.57C20.56 21.8 24 17.3 24 12 24 5.37 18.63 0 12 0z"/></svg></div>
      <div><div class="support-label" data-i18n="github">گیت هـاب پروژه</div><div class="support-val">ahb-panel/ahb_panel</div></div>
    </a>
    <a class="support-tile" href="https://t.me/ahbpanel" target="_blank" rel="noopener">
      <div class="support-icon"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12s5.37 12 12 12 12-5.37 12-12S18.63 0 12 0zm5.56 8.2-1.86 8.77c-.14.62-.5.77-1.01.48l-2.8-2.06-1.35 1.3c-.15.15-.27.27-.55.27l.2-2.84 5.18-4.68c.22-.2-.05-.31-.35-.12l-6.4 4.03-2.76-.86c-.6-.19-.61-.6.12-.89l10.78-4.16c.5-.18.94.12.78.86z"/></svg></div>
      <div><div class="support-label" data-i18n="telegram">کانال تلگـرام</div><div class="support-val">@ahbpanel</div></div>
    </a>
    <a class="support-tile" href="https://t.me/logictop12" target="_blank" rel="noopener">
      <div class="support-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/></svg></div>
      <div><div class="support-label" data-i18n="channel">گروه تلگـرام (پشتیبانی)</div><div class="support-val">t.me/ahbpanelgap</div></div>
    </a>
  </div>
</section>

<section class="page" id="page-telegram">
  <div class="page-head">
    <div>
      <div class="page-title">
        <svg viewBox="0 0 24 24" fill="currentColor" width="22" height="22"><path d="M12 0C5.37 0 0 5.37 0 12s5.37 12 12 12 12-5.37 12-12S18.63 0 12 0zm5.56 8.2-1.86 8.77c-.14.62-.5.77-1.01.48l-2.8-2.06-1.35 1.3c-.15.15-.27.27-.55.27l.2-2.84 5.18-4.68c.22-.2-.05-.31-.35-.12l-6.4 4.03-2.76-.86c-.6-.19-.61-.6.12-.89l10.78-4.16c.5-.18.94.12.78.86z"/></svg>
        <span data-i18n="nav_telegram">ای اچ‌ بی بات</span>
      </div>
      <div class="page-sub" data-i18n="tg_sub">توکن ربات و آیدی عددی ادمین · فعال‌سازی خودکار و وب‌هوک</div>
    </div>
  </div>
  <div class="card">
    <div class="card-title" data-i18n="tg_config">پیکربندی ربات</div>
    <div class="field"><label data-i18n="tg_token">توکن ربات (BotFather)</label><input id="tgToken" placeholder="123456:ABC-DEF..." autocomplete="off"></div>
    <div class="field"><label data-i18n="tg_admin">آیدی عددی ادمین</label><input id="tgAdmin" placeholder="123456789" inputmode="numeric"></div>
    <div class="field" style="display:flex;align-items:center;gap:10px">
      <label class="switch"><input type="checkbox" id="tgWebhook" checked><span class="slider"></span></label>
      <span data-i18n="tg_webhook" style="font-size:13px;color:var(--t2)">فعال‌سازی Webhook (پیشنهادی روی Railway)</span>
    </div>
    <div id="tgStatus" style="font-size:12px;color:var(--t3);margin:10px 0"></div>
    <button class="btn btn-p" style="width:100%" onclick="saveTelegram()">
      <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></svg>
      <span data-i18n="tg_activate">ذخیره و فعال‌سازی ربات</span>
    </button>
  </div>
  <div class="card">
    <div class="card-title" data-i18n="tg_help">راهنما</div>
    <ol style="color:var(--t2);font-size:13px;line-height:2;padding-right:18px">
      <li data-i18n="tg_h1">از @BotFather یک ربات بساز و توکن را کپی کن</li>
      <li data-i18n="tg_h2">آیدی عددی خودت را از @userinfobot بگیر</li>
      <li data-i18n="tg_h3">ذخیره کن — وب‌هوک خودکار روی دامنه Railway ست می‌شود</li>
    </ol>
  </div>
</section>

</main>

<!-- Result modal after create -->
<div class="modal-bg" id="resultModal">
  <div class="modal">
    <div class="modal-title" data-i18n="created_title">کانفیگ ساخته شد</div>
    <div class="field"><label>VLESS</label><div class="link-box" id="resVless">—</div>
      <button class="btn btn-p btn-sm" style="width:100%" onclick="copyText(document.getElementById('resVless').textContent)">
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        <span data-i18n="copy_vless">کپی VLESS</span>
      </button>
    </div>
    <div class="field" style="margin-top:14px"><label data-i18n="sub_label">سابسکریپشن</label><div class="link-box" id="resSub">—</div>
      <button class="btn btn-sm" style="width:100%" onclick="copyText(document.getElementById('resSub').textContent)">
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 11a9 9 0 0 1 9 9M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg>
        <span data-i18n="copy_sub">کپی ساب</span>
      </button>
    </div>
    <div class="modal-actions">
      <button class="btn" onclick="closeResult()">OK</button>
    </div>
  </div>
</div>

<!-- Edit config modal -->
<div class="modal-bg" id="editModal">
  <div class="modal">
    <div class="modal-title">ویرایش کانفیگ</div>
    <input type="hidden" id="eUid">
    <div style="font-size:12px;color:var(--t3);margin-bottom:12px">فقط حجم، روز، محدودیت IP، محدودیت اتصال و سرعت قابل ویرایش هستند؛ بقیه فقط نمایشی‌اند.</div>
    <div class="field"><label>نام</label><input id="eName" maxlength="60"></div>
    <div class="field"><label>یادداشت</label><input id="eNote" maxlength="500"></div>
    <div class="form-row">
      <div class="field"><label>محدودیت حجم (۰ = نامحدود)</label><input id="eLimit" type="number" min="0" step="any"></div>
      <div class="field"><label>واحد</label><select id="eUnit"><option>GB</option><option>MB</option><option>KB</option></select></div>
    </div>
    <div class="field"><label>انقضا: چند روز از امروز (۰ = نامحدود، خالی = بدون تغییر)</label><input id="eDays" type="number" min="0" placeholder=""></div>
    <div id="eExpInfo" style="font-size:12px;color:var(--t3);margin:-4px 0 12px"></div>
    <div class="form-row">
      <div class="field"><label>محدودیت IP</label><input id="eIp" type="number" min="0"></div>
      <div class="field"><label>محدودیت اتصال</label><input id="eConn" type="number" min="0"></div>
    </div>
    <div class="form-row">
      <div class="field"><label>سرعت (Mbps، ۰ = نامحدود)</label><input id="eSpeed" type="number" min="0" step="any"></div>
      <div class="field"><label>پورت</label><input id="ePort" type="number" min="1" max="65535"></div>
    </div>
    <div class="modal-actions">
      <button class="btn" onclick="closeEdit()">انصراف</button>
      <button class="btn btn-p" id="eSaveBtn" onclick="saveEdit()">ذخیره</button>
    </div>
  </div>
</div>

<div class="modal-bg" id="panelModal">
  <div class="modal">
    <div class="modal-title" id="panelModalTitle">...</div>
    <div id="panelModalBody" style="color:var(--t2);font-size:13px;line-height:1.8"></div>
    <div class="modal-actions">
      <button class="btn" onclick="document.getElementById('panelModal').classList.remove('open')">OK</button>
    </div>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
const I18N={
fa:{sec_panel:'پنل',sec_sys:'سیستم',nav_dash:'داشبورد',nav_configs:'کانفیگ‌ها',nav_groups:'گروه‌ها',nav_create:'ساخت کانفیگ',nav_stats:'آمار',nav_logs:'لاگ فعالیت',nav_settings:'تنظیمات',nav_support:'پشتیبانی',nav_donate:'حمایت مالی',nav_news:'اخبار',nav_admins:'ادمین‌ها',refresh_news:'بروزرسانی اطلاعیه',admins_sub:'ساخت اکانت ادمین با دسترسی سفارشی',admin_create:'ساخت اکانت ادمین',admin_user:'نام کاربری',admin_pw:'رمز عبور',admin_pw2:'تکرار رمز',admin_perms:'دسترسی‌ها',admin_btn:'ساخت اکانت',admin_list:'لیست ادمین‌ها',refresh:'بروزرسانی',refresh_stats:'بروزرسانی آمار',refresh_panel:'بروزرسانی پنل',nav_telegram:'ربات تلگرام',tg_sub:'توکن ربات و آیدی عددی ادمین · فعال‌سازی خودکار و وب‌هوک',tg_config:'پیکربندی ربات',tg_token:'توکن ربات (BotFather)',tg_admin:'آیدی عددی ادمین',tg_webhook:'فعال‌سازی Webhook (پیشنهادی روی Railway)',tg_activate:'ذخیره و فعال‌سازی ربات',tg_help:'راهنما',tg_h1:'از @BotFather یک ربات بساز و توکن را کپی کن',tg_h2:'آیدی عددی خودت را از @userinfobot بگیر',tg_h3:'ذخیره کن — وب‌هوک خودکار روی دامنه Railway ست می‌شود',logout:'خروج',loading:'در حال بارگذاری...',m_conns:'اتصالات فعال',m_traffic:'ترافیک کل',m_links:'کانفیگ‌ها',m_uptime:'آپتایم سرور',quick_create:'ساخت کانفیگ',quick_create_desc:'ساخت دستی با محدودیت ترافیک، سرعت، تعداد و انقضا',auto_create:'ساخت خودکار (پیشنهادی)',auto_create_desc:'ساخت سریع با تنظیمات بهینه · لینک VLESS و ساب',configs_sub:'مدیریت لینک‌ها · VLESS و ساب',th_name:'نام',th_proto:'پروتکل',th_status:'وضعیت',th_usage:'مصرف',th_ops:'عملیات',manual_create:'ساخت دستی',label_name:'نام',label_proto:'پروتکل',label_count:'تعداد کانفیگ در ساب (۱–۴۰)',label_limit:'محدودیت حجم',label_unit:'واحد',label_days:'انقضا (روز)',label_ip:'محدودیت IP',label_speed:'سرعت (Mbps)',btn_create:'ساخت',btn_auto:'ساخت خودکار',auto_desc:'با یک کلیک کانفیگ بهینه ساخته می‌شود. بعد از ساخت لینک VLESS و ساب در اختیار شماست.',stats_sub:'ترافیک و اتصالات · فیلتر زمانی',r_day:'روز',r_week:'هفته',r_month:'ماه',r_all:'کل',panel_info:'اطلاعات کل پنل',lang_label:'زبان',change_pw:'تغییر رمز عبور',pw_cur:'رمز فعلی',pw_new:'رمز جدید',pw_cf:'تکرار رمز',btn_save:'ذخیره',github:'گیت‌هاب',telegram:'تلگرام',channel:'کانال پشتیبان',theme:'تم',theme_dark:'تم تیره',theme_light:'تم روشن',created_title:'کانفیگ ساخته شد',copy_vless:'کپی VLESS',copy_sub:'کپی ساب',sub_label:'سابسکریپشن'},
en:{sec_panel:'PANEL',sec_sys:'SYSTEM',nav_dash:'Dashboard',nav_configs:'Configs',nav_groups:'Groups',nav_create:'Create Config',nav_stats:'Statistics',nav_logs:'Activity Log',nav_settings:'Settings',nav_support:'Support',nav_donate:'Donate',nav_news:'News',nav_admins:'Admins',refresh_news:'Refresh news',admins_sub:'Create admin accounts with custom access',admin_create:'Create admin account',admin_user:'Username',admin_pw:'Password',admin_pw2:'Confirm password',admin_perms:'Permissions',admin_btn:'Create account',admin_list:'Admin list',refresh:'Refresh',refresh_stats:'Refresh stats',refresh_panel:'Update panel',nav_telegram:'Telegram bot',tg_sub:'Bot token and numeric admin ID · auto activate and webhook',tg_config:'Bot configuration',tg_token:'Bot token (BotFather)',tg_admin:'Admin numeric ID',tg_webhook:'Enable Webhook (recommended on Railway)',tg_activate:'Save and activate bot',tg_help:'Guide',tg_h1:'Create a bot with @BotFather and copy the token',tg_h2:'Get your numeric ID from @userinfobot',tg_h3:'Save — webhook is set automatically on Railway domain',logout:'Logout',loading:'Loading...',m_conns:'Active connections',m_traffic:'Total traffic',m_links:'Configs',m_uptime:'Server uptime',quick_create:'Create Config',quick_create_desc:'Manual create with traffic, speed, count and expiry',auto_create:'Auto Create (Suggested)',auto_create_desc:'Quick optimal create · VLESS and Sub links',configs_sub:'Manage links · VLESS and Sub',th_name:'Name',th_proto:'Protocol',th_status:'Status',th_usage:'Usage',th_ops:'Actions',manual_create:'Manual create',label_name:'Name',label_proto:'Protocol',label_count:'Configs in sub (1–40)',label_limit:'Traffic limit',label_unit:'Unit',label_days:'Expiry (days)',label_ip:'IP limit',label_speed:'Speed (Mbps)',btn_create:'Create',btn_auto:'Auto create',auto_desc:'One click creates an optimal config. VLESS and Sub links will be shown.',stats_sub:'Traffic and connections · time filter',r_day:'Day',r_week:'Week',r_month:'Month',r_all:'All',panel_info:'Panel overview',lang_label:'Language',change_pw:'Change password',pw_cur:'Current password',pw_new:'New password',pw_cf:'Confirm password',btn_save:'Save',github:'GitHub',telegram:'Telegram',channel:'Support channel',theme:'Theme',theme_dark:'Dark theme',theme_light:'Light theme',created_title:'Config created',copy_vless:'Copy VLESS',copy_sub:'Copy Sub',sub_label:'Subscription'}
};
let lang=localStorage.getItem('ahn_lang')||'fa';
let statRange='month';
function t(k){return (I18N[lang]||I18N.fa)[k]||k}
function applyLang(){
  document.getElementById('htmlRoot').lang=lang;
  document.getElementById('htmlRoot').dir=lang==='fa'?'rtl':'ltr';
  document.body.classList.toggle('en',lang==='en');
  document.querySelectorAll('[data-i18n]').forEach(el=>{const k=el.getAttribute('data-i18n');if(I18N[lang][k])el.textContent=I18N[lang][k]});
  const tl=document.getElementById('themeLabel');
  if(tl) tl.textContent=document.documentElement.classList.contains('light')?t('theme_dark'):t('theme_light');
}
function setLang(l){lang=l;localStorage.setItem('px_lang',l);applyLang();toast(l==='fa'?'زبان فارسی':'English')}

function setTheme(mode){
  if(mode==='light') document.documentElement.classList.add('light');
  else document.documentElement.classList.remove('light');
  localStorage.setItem('ahb_theme',mode);
  applyLang();
}
function toggleTheme(){
  const isLight=document.documentElement.classList.contains('light');
  setTheme(isLight?'dark':'light');
}
(function(){const th=localStorage.getItem('ahb_theme')||'dark';setTheme(th)})();

const sb=document.getElementById('sidebar'),main=document.getElementById('main');
document.getElementById('sbToggle').onclick=()=>{
  sb.classList.toggle('collapsed');
  main.classList.toggle('expanded',sb.classList.contains('collapsed'));
  localStorage.setItem('sb_c',sb.classList.contains('collapsed')?'1':'0');
};
if(localStorage.getItem('sb_c')==='1'){sb.classList.add('collapsed');main.classList.add('expanded')}
document.getElementById('mobMenuBtn').onclick=()=>{sb.classList.add('open');document.getElementById('overlay').classList.add('show')};
document.getElementById('overlay').onclick=()=>{sb.classList.remove('open');document.getElementById('overlay').classList.remove('show')};

function goPage(name){
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('on',n.dataset.page===name));
  document.querySelectorAll('.page').forEach(p=>p.classList.toggle('on',p.id==='page-'+name));
  sb.classList.remove('open');document.getElementById('overlay').classList.remove('show');
  window.scrollTo({top:0,behavior:'smooth'});
  if(name==='logs')loadLogs();
  if(name==='configs'||name==='dash'||name==='stats')refreshAll();
}
document.querySelectorAll('.nav-item').forEach(el=>el.addEventListener('click',()=>goPage(el.dataset.page)));

function toast(msg){
  const el=document.getElementById('toast');
  el.textContent=msg;el.classList.add('show');
  clearTimeout(window.__tt);window.__tt=setTimeout(()=>el.classList.remove('show'),2200);
}
async function api(url,opts={}){
  try{
    const r=await fetch(url,{cache:'no-store',credentials:'same-origin',...opts});
    if(r.status===401){location.href='/login';return null}
    let data=null;try{data=await r.json()}catch{data={ok:false}}
    if(!r.ok){toast(data.detail||data.error||'Error');return null}
    return data;
  }catch(e){toast(lang==='fa'?'ارتباط برقرار نشد':'Connection failed');return null}
}
function fmtB(b){b=Number(b)||0;if(b<1024)return b+' B';if(b<1024**2)return (b/1024).toFixed(1)+' KB';if(b<1024**3)return (b/1024**2).toFixed(2)+' MB';return (b/1024**3).toFixed(2)+' GB'}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}

async function refreshAll(){
  if(typeof loadGroups==='function') try{await loadGroups()}catch(e){}
  const links=await api('/api/links');
  if(!links)return;
  const arr=Array.isArray(links.links)?links.links:(Array.isArray(links)?links:[]);
  document.getElementById('mLinks').textContent=arr.length;
  let active=0,used=0;
  arr.forEach(l=>{if(l.active!==false)active++;used+=Number(l.used_bytes||0)});
  document.getElementById('mTraffic').textContent=fmtB(used);
  document.getElementById('sTraffic').textContent=fmtB(used);
  document.getElementById('sActive').textContent=active;
  document.getElementById('lastUpd').textContent=(lang==='fa'?'بروزرسانی: ':'Updated: ')+new Date().toLocaleTimeString(lang==='fa'?'fa-IR':'en-US');
  try{
    const c=await api('/api/connections');
    const cnt=(c&&c.connections)?c.connections.length:((c&&typeof c.count==='number')?c.count:0);
    document.getElementById('mConns').textContent=cnt;
    document.getElementById('sConns').textContent=cnt;
  }catch(e){}
  try{
    const h=await fetch('/health',{cache:'no-store'}).then(r=>r.json());
    if(h&&h.uptime){
      document.getElementById('mUptime').textContent=h.uptime;
      const su=document.getElementById('sUptime');if(su)su.textContent=h.uptime;
    }
  }catch(e){}
    __allLinks=arr;
  softUpdateLinks(arr);
  document.getElementById('panelInfo').innerHTML=lang==='fa'
    ?`کل کانفیگ: <b>${arr.length}</b> · فعال: <b>${active}</b> · مصرف: <b>${fmtB(used)}</b> · بازه: <b>${statRange}</b>`
    :`Total: <b>${arr.length}</b> · Active: <b>${active}</b> · Usage: <b>${fmtB(used)}</b> · Range: <b>${statRange}</b>`;
}


function linkBadgeClass(l){
  const conn=Number(l.connected_ips||0);
  const used=Number(l.used_bytes||0), lim=Number(l.limit_bytes||0);
  let usagePct=lim>0?(used/lim)*100:0;
  let expWarn=false, expDead=false;
  if(l.expires_at){try{const ms=new Date(l.expires_at)-Date.now();if(ms<=0)expDead=true;else if(ms<3*864e5)expWarn=true}catch(e){}}
  if(expDead||usagePct>=90) return 'conn-badge red';
  if(expWarn||usagePct>=70) return 'conn-badge orange';
  if(conn>0) return 'conn-badge green';
  return 'conn-badge gray';
}
function softUpdateLinks(arr){
  const tb=document.getElementById('linksTable');
  if(!tb) return;
  const rows=[...tb.querySelectorAll('tr[data-uid]')];
  const existing=rows.map(r=>r.getAttribute('data-uid'));
  const incoming=arr.map(l=>String(l.uuid||l.id||''));
  const same = existing.length===incoming.length && existing.every((id,i)=>id===incoming[i]);
  // اگر در حال درگ یا انتخاب هستیم، فقط سلول‌ها را آپدیت کن
  const selecting = document.querySelectorAll('.cfg-chk:checked').length>0;
  const dragging = !!__dragUid;
  if(!same || existing.length===0){
    if(dragging || selecting){
      // فقط آمار ردیف‌های موجود را آپدیت کن، ساختار را نشکن
      window.__linksMap = window.__linksMap || {};
      arr.forEach(l=>{
        const uid=String(l.uuid||l.id||'');
        window.__linksMap[uid]=l;
        const tr=tb.querySelector(`tr[data-uid="${uid}"]`);
        if(!tr) return;
        patchLinkRow(tr, l);
      });
      return;
    }
    renderLinks(arr);
    return;
  }
  window.__linksMap = window.__linksMap || {};
  arr.forEach(l=>{
    const uid=String(l.uuid||l.id||'');
    window.__linksMap[uid]=l;
    const tr=tb.querySelector(`tr[data-uid="${uid}"]`);
    if(tr) patchLinkRow(tr, l);
  });
}
function patchLinkRow(tr, l){
  const conn=Number(l.connected_ips||0);
  const badge=tr.querySelector('.conn-badge');
  if(badge){ badge.textContent=String(conn); badge.className=linkBadgeClass(l); }
  const usageCell=tr.querySelector('[data-usage]');
  if(usageCell){
    usageCell.textContent = fmtB(l.used_bytes) + (l.limit_bytes?(' / '+fmtB(l.limit_bytes)):'');
  }
  // وضعیت سوئیچ را اگر کاربر همین الان عوض نکرده دست نزن — فقط اگر API فرق دارد و فوکوس نیست
  const sw=tr.querySelector('.switch input[type=checkbox]');
  if(sw && document.activeElement!==sw){
    const on=l.active!==false&&!l.expired;
    if(sw.checked!==on) sw.checked=on;
  }
}
function renderLinks(arr){
  const tb=document.getElementById('linksTable');
  if(!arr.length){tb.innerHTML=`<tr><td colspan="7" style="text-align:center;color:var(--t3);padding:28px">${lang==='fa'?'کانفیگی نیست':'No configs'}</td></tr>`;updateBulkBar();return}
  window.__linksMap={};
  const catMap=window.__catMap||{};
  // preserve checked state
  const prevChecked=new Set([...document.querySelectorAll('.cfg-chk:checked')].map(c=>c.value));
  tb.innerHTML=arr.map(l=>{
    const uid=l.uuid||l.id||'';
    window.__linksMap[uid]=l;
    const name=l.label||l.name||String(uid).slice(0,8);
    const proto=l.protocol||'vless-ws';
    const on=l.active!==false&&!l.expired;
    const conn=Number(l.connected_ips||0);
    const gname=catMap[String(l.category_id||'')]||'';
    const chk=prevChecked.has(uid)?'checked':'';
    return `<tr draggable="true" data-uid="${esc(uid)}" ondragstart="cfgDragStart(event)" ondragover="cfgDragOver(event)" ondrop="cfgDrop(event)" ondragend="cfgDragEnd(event)">
      <td style="text-align:center;padding:10px 8px;vertical-align:middle"><input type="checkbox" class="cfg-chk" value="${esc(uid)}" ${chk} onchange="updateBulkBar()" style="width:16px;height:16px;margin:0;vertical-align:middle;cursor:pointer"></td>
      <td style="cursor:grab;color:var(--t3);user-select:none" title="کشیدن">⋮⋮</td>
      <td>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <b>${esc(name)}</b>
          <span class="${linkBadgeClass(l)}" title="${lang==='fa'?'متصل الان':'Online now'}">${conn}</span>
          ${gname?`<span style="font-size:10px;padding:2px 7px;border-radius:8px;background:var(--hover);color:var(--t3)">${esc(gname)}</span>`:''}
        </div>
      </td>
      <td style="color:var(--t3);font-size:11px">${esc(proto)}</td>
      <td><label class="switch"><input type="checkbox" ${on?'checked':''} onchange="toggleLink('${esc(uid)}',this.checked)"><span class="slider"></span></label></td>
      <td data-usage>${fmtB(l.used_bytes)}${l.limit_bytes?(' / '+fmtB(l.limit_bytes)):''}</td>
      <td class="ops">
        <button class="btn btn-sm" onclick="copyLinkById('${esc(uid)}')" title="VLESS"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
        <button class="btn btn-sm" onclick="copySubById('${esc(uid)}')" title="Sub"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 11a9 9 0 0 1 9 9M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg></button>
        <a class="btn btn-sm" href="/info/${esc(uid)}" target="_blank" title="INFO" style="text-decoration:none"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg></a>
        <button class="btn btn-sm" onclick="resetUsage('${esc(uid)}')" title="Reset"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg></button>
        <button class="btn btn-sm" onclick="openEdit('${esc(uid)}')" title="${lang==='fa'?'ویرایش':'Edit'}"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/></svg></button>
        <button class="btn btn-sm btn-d" onclick="deleteLink('${esc(uid)}')"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/></svg></button>
      </td>
    </tr>`;
  }).join('');
  updateBulkBar();
}
function getLinkUrl(l){if(!l)return '';return l.vless_full||l.vless||l.vless_link||l.link||''}
function getSubUrl(l){if(!l)return '';return l.sub||l.sub_url||l.info||''}
async function copyText(text){
  text=String(text||'').trim();
  if(!text||text==='—'){toast(lang==='fa'?'لینکی نیست':'Nothing to copy');return}
  try{
    if(navigator.clipboard&&window.isSecureContext) await navigator.clipboard.writeText(text);
    else{const ta=document.createElement('textarea');ta.value=text;ta.style.cssText='position:fixed;left:-9999px';document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta)}
    toast(lang==='fa'?'کپی شد':'Copied');
  }catch(e){toast(lang==='fa'?'کپی نشد':'Copy failed')}
}
async function copyLinkById(uid){await copyText(getLinkUrl((window.__linksMap||{})[uid]))}
async function copySubById(uid){await copyText(getSubUrl((window.__linksMap||{})[uid]))}
async function toggleLink(uid,state){
  // optimistic UI — رنگ بلافاصله عوض می‌شود
  if(window.__linksMap && window.__linksMap[uid]){
    window.__linksMap[uid].active = !!state;
    if(window.__linksMap[uid].expired && state) window.__linksMap[uid].expired = false;
  }
  if(typeof __allLinks !== 'undefined' && Array.isArray(__allLinks)){
    const item = __allLinks.find(x => (x.uuid||x.id)===uid);
    if(item) item.active = !!state;
  }
  const r=await api('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:!!state})});
  if(r===null){
    // rollback
    if(window.__linksMap && window.__linksMap[uid]) window.__linksMap[uid].active = !state;
    refreshAll();
    return;
  }
  toast(state?(lang==='fa'?'فعال شد':'Enabled'):(lang==='fa'?'غیرفعال شد':'Disabled'));
}
async function deleteLink(uid){
  if(!confirm(lang==='fa'?'حذف شود؟':'Delete?'))return;
  const r=await api('/api/links/'+uid,{method:'DELETE'});
  if(r!==null){toast(lang==='fa'?'حذف شد':'Deleted');refreshAll()}
}
function showResult(data){
  if(!data)return;
  document.getElementById('resVless').textContent=getLinkUrl(data)||'—';
  document.getElementById('resSub').textContent=getSubUrl(data)||'—';
  document.getElementById('resultModal').classList.add('open');
}
function closeResult(){document.getElementById('resultModal').classList.remove('open')}
document.getElementById('resultModal').addEventListener('click',e=>{if(e.target.id==='resultModal')closeResult()});

async function doAutoCreate(){
  toast(lang==='fa'?'در حال ساخت...':'Creating...');
  const count=Math.max(1,Math.min(40,Number(document.getElementById('aCount')?.value)||1));
  const protocol=document.getElementById('aProto')?.value||undefined;
  let r=await api('/api/links/auto',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({config_count:count,protocol})});
  if(!r){
    r=await api('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:'auto-'+Date.now().toString(36).slice(-5),limit_value:0,limit_unit:'GB',config_count:count})});
  }
  if(r){showResult(r);refreshAll()}
}
async function doManualCreate(){
  const body={
    label:document.getElementById('cName').value||undefined,
    protocol:document.getElementById('cProto')?.value||undefined,
    category_id:document.getElementById('cGroup')?.value||'0',
    config_count:Math.max(1,Math.min(40,Number(document.getElementById('cCount').value)||1)),
    limit_value:Number(document.getElementById('cLimit').value)||0,
    limit_unit:document.getElementById('cUnit').value||'GB',
    expires_days:Number(document.getElementById('cDays').value)||0,
    ip_limit:Number(document.getElementById('cIp').value)||0,
    speed_limit_value:Number(document.getElementById('cSpeed').value)||0,
    speed_limit_unit:'MBIT'
  };
  const r=await api('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r){showResult(r);refreshAll()}
}
async function doChangePw(){
  const cur=document.getElementById('pwCur').value,nw=document.getElementById('pwNew').value,cf=document.getElementById('pwCf').value;
  if(nw!==cf){toast(lang==='fa'?'رمزها یکی نیستند':'Passwords mismatch');return}
  const r=await api('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw,repeat_password:cf})});
  if(r){toast(lang==='fa'?'رمز تغییر کرد':'Password changed');document.getElementById('pwCur').value='';document.getElementById('pwNew').value='';document.getElementById('pwCf').value=''}
}
async function loadLogs(){
  const box=document.getElementById('logsBox');
  const data=await api('/api/activity');
  const logs=Array.isArray(data)?data:(data&&data.logs)||[];
  if(!logs.length){box.innerHTML=`<div style="text-align:center;color:var(--t3);padding:24px">${lang==='fa'?'لاگی نیست':'No logs'}</div>`;return}
  box.innerHTML=logs.slice().reverse().map(l=>{
    const tm=(l.time||l.ts||'').toString().slice(11,19)||'—';
    return `<div class="log-item"><div class="log-time">${esc(tm)}</div><div class="log-msg">${esc(l.message||l.msg||JSON.stringify(l))}</div></div>`;
  }).join('');
}
function setRange(r,el){
  statRange=r;
  document.querySelectorAll('#rangeTabs .range-tab').forEach(t=>t.classList.toggle('on',t.dataset.r===r));
  refreshAll();toast(t('r_'+r));
}
function randomName(){
  const chars='abcdefghijklmnopqrstuvwxyz0123456789';
  let s='';
  for(let i=0;i<10;i++) s+=chars[Math.floor(Math.random()*chars.length)];
  if(/^[0-9]/.test(s)) s='a'+s.slice(1);
  document.getElementById('cName').value=s;
}
async function panelUpdate(){
  const m=document.getElementById('panelModal');
  const t=document.getElementById('panelModalTitle');
  const b=document.getElementById('panelModalBody');
  t.textContent=lang==='fa'?'در حال بررسی آپدیت...':'Checking update...';
  b.innerHTML='<div style="text-align:center;padding:20px"><div class="spin"></div></div>';
  m.classList.add('open');
  await new Promise(r=>setTimeout(r,1400));
  t.textContent=lang==='fa'?'آپدیت پنل':'Panel update';
  b.innerHTML=(lang==='fa'
    ?'<p style="margin-bottom:12px">اپدیت با خطا مواجه شد. اپدیت را دستی انجام دهید.</p><a href="https://github.com/ahb-panel/ahb_panel" target="_blank" rel="noopener" style="color:var(--accent2);font-weight:700">github.com/ahb-panel/ahb_panel</a>'
    :'<p style="margin-bottom:12px">Update failed. Please update manually.</p><a href="https://github.com/ahb-panel/ahb_panel" target="_blank" rel="noopener" style="color:var(--accent2);font-weight:700">github.com/ahb-panell/ahb_panel</a>');
}
async function saveTelegram(){
  const token=document.getElementById('tgToken').value.trim();
  const admin=document.getElementById('tgAdmin').value.trim();
  const webhook=document.getElementById('tgWebhook').checked;
  if(!token||!admin){toast(lang==='fa'?'توکن و آیدی لازم است':'Token and admin ID required');return}
  toast(lang==='fa'?'در حال فعال‌سازی...':'Activating...');
  const r=await api('/api/telegram/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,admin_ids:admin,webhook})});
  if(r){
    document.getElementById('tgStatus').textContent=r.message||(lang==='fa'?'فعال شد':'Enabled');
    toast(r.message||'OK');
  }
}
async function loadTelegram(){
  const r=await api('/api/telegram/settings');
  if(!r)return;
  if(r.admin_ids) document.getElementById('tgAdmin').value=r.admin_ids;
  document.getElementById('tgWebhook').checked=r.webhook!==false;
  document.getElementById('tgStatus').textContent=r.has_token?(lang==='fa'?'توکن ذخیره شده: ':'Token saved: ')+(r.token_masked||''):'';
}
const _goPage=goPage;
goPage=function(name){
  _goPage(name);
  if(name==='telegram') loadTelegram();
  if(name==='news') loadNews();
  if(name==='admins') loadAdmins();
  if(name==='groups') loadGroups();
  if(name==='settings') loadSecurity();
};

const PERM_LABELS={
  fa:{dash:'داشبورد',configs:'کانفیگ‌ها',create:'ساخت',stats:'آمار',logs:'لاگ',settings:'تنظیمات',support:'پشتیبانی',telegram:'ربات',news:'اخبار',admins:'ادمین‌ها'},
  en:{dash:'Dashboard',configs:'Configs',create:'Create',stats:'Stats',logs:'Logs',settings:'Settings',support:'Support',telegram:'Bot',news:'News',admins:'Admins'}
};
let USER_PERMS=null;
let USER_ROLE='owner';
function buildPermChecks(containerId, selected){
  const box=document.getElementById(containerId);
  if(!box)return;
  const labels=PERM_LABELS[lang]||PERM_LABELS.fa;
  box.innerHTML=Object.keys(labels).map(k=>{
    const on=selected?!!selected[k]:(['dash','configs','create','stats','news'].includes(k));
    return `<div style="display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 12px;border-radius:12px;background:var(--bg3);border:1px solid var(--card-b)">
      <span style="font-size:12px;font-weight:600">${labels[k]}</span>
      <label class="switch"><input type="checkbox" data-perm="${k}" ${on?'checked':''}><span class="slider"></span></label>
    </div>`;
  }).join('');
}
function readPermChecks(containerId){
  const out={};
  document.querySelectorAll('#'+containerId+' input[data-perm]').forEach(inp=>{out[inp.getAttribute('data-perm')]=inp.checked});
  return out;
}
async function loadMe(){
  const r=await api('/api/me');
  if(!r)return;
  USER_ROLE=r.role||'owner';
  USER_PERMS=r.permissions||{};
  document.querySelectorAll('.nav-item[data-perm]').forEach(el=>{
    const p=el.getAttribute('data-perm');
    if(USER_ROLE==='owner'){el.style.display='';return}
    el.style.display=USER_PERMS[p]?'':'none';
  });
  // hide admins for non-owner always if no perm
  document.querySelectorAll('.nav-item[data-page="admins"]').forEach(el=>{
    if(USER_ROLE!=='owner') el.style.display='none';
  });
}
async function loadNews(toastOk){
  const r=await api('/api/news');
  if(!r)return;
  document.getElementById('newsTitle').textContent=r.title||(lang==='fa'?'بدون عنوان':'No title');
  document.getElementById('newsBody').textContent=r.message||'';
  document.getElementById('newsMeta').textContent=(lang==='fa'?'بروزرسانی: ':'Updated: ')+(r.updated_at||'—');
  if(toastOk) toast(lang==='fa'?'اطلاعیه بروزرسانی شد':'News refreshed');
}
async function loadAdmins(){
  buildPermChecks('adPerms');
  const r=await api('/api/admins');
  const box=document.getElementById('adminsList');
  if(!r||!r.admins){box.innerHTML='<div style="color:var(--t3);text-align:center;padding:20px">—</div>';return}
  if(!r.admins.length){box.innerHTML=`<div style="color:var(--t3);text-align:center;padding:20px">${lang==='fa'?'ادمینی نیست':'No admins'}</div>`;return}
  const labels=PERM_LABELS[lang]||PERM_LABELS.fa;
  box.innerHTML=r.admins.map(a=>{
    const st=a.blocked?'🔴 مسدود':(a.valid?'🟢 فعال':'🟠 نامعتبر');
    const perms=Object.entries(a.permissions||{}).filter(([,v])=>v).map(([k])=>labels[k]||k).join(' · ')||'—';
    return `<div style="border:1px solid var(--card-b);border-radius:12px;padding:12px;margin-bottom:10px;background:var(--bg3)">
      <div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:center">
        <div><b>${esc(a.username)}</b> <span style="font-size:11px;color:var(--t3)">${st}</span></div>
        <div class="ops" style="align-items:center">
          <label class="switch" title="مسدود">
            <input type="checkbox" ${a.blocked?'checked':''} onchange="toggleBlockAdmin('${esc(a.id)}',this.checked)">
            <span class="slider"></span>
          </label>
          <button class="btn btn-sm btn-d" onclick="deleteAdmin('${esc(a.id)}')">حذف</button>
        </div>
      </div>
      <div style="font-size:11px;color:var(--t3);margin-top:8px">حجم: ${fmtB(a.used_bytes)}${a.limit_bytes?(' / '+fmtB(a.limit_bytes)):' / ∞'} · انقضا: ${a.expires_at||'∞'}</div>
      <div style="font-size:11px;color:var(--t2);margin-top:6px">${perms}</div>
    </div>`;
  }).join('');
}
async function createAdmin(){
  const body={
    username:document.getElementById('adUser').value.trim(),
    password:document.getElementById('adPw').value,
    repeat_password:document.getElementById('adPw2').value,
    limit_value:Number(document.getElementById('adLimit').value)||0,
    limit_unit:document.getElementById('adUnit').value,
    expires_days:Number(document.getElementById('adDays').value)||0,
    permissions:readPermChecks('adPerms')
  };
  const r=await api('/api/admins',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r){toast(lang==='fa'?'اکانت ساخته شد':'Created');document.getElementById('adUser').value='';document.getElementById('adPw').value='';document.getElementById('adPw2').value='';loadAdmins()}
}
async function toggleBlockAdmin(id,blocked){
  const r=await api('/api/admins/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({blocked})});
  if(r){toast(blocked?'مسدود شد':'رفع شد');loadAdmins()}
}
async function deleteAdmin(id){
  if(!confirm(lang==='fa'?'حذف اکانت؟':'Delete?'))return;
  const r=await api('/api/admins/'+id,{method:'DELETE'});
  if(r){toast('OK');loadAdmins()}
}


async function loadProtocols(){
  const r=await api('/api/protocols');
  const list=(r&&r.protocols)||[];
  const def=(r&&r.default)||'vless-ws';
  ['cProto','aProto'].forEach(id=>{
    const el=document.getElementById(id);
    if(!el)return;
    el.innerHTML=list.map(p=>`<option value="${esc(p.id)}" ${p.id===def?'selected':''}>${esc(p.label||p.id)}</option>`).join('')
      ||'<option value="vless-ws">VLESS WebSocket</option>';
  });
}
let __allLinks=[];
function filterConfigs(){
  const q=(document.getElementById('cfgSearch')?.value||'').trim().toLowerCase();
  if(!q){renderLinks(__allLinks);return}
  renderLinks(__allLinks.filter(l=>{
    const name=(l.label||l.name||'').toLowerCase();
    const proto=(l.protocol||'').toLowerCase();
    const uid=String(l.uuid||l.id||'').toLowerCase();
    return name.includes(q)||proto.includes(q)||uid.includes(q);
  }));
}
function __bytesToLimit(b){
  b=Number(b)||0;
  if(b<=0)return {v:0,u:'GB'};
  if(b>=1024**3)return {v:+(b/1024**3).toFixed(2),u:'GB'};
  if(b>=1024**2)return {v:+(b/1024**2).toFixed(2),u:'MB'};
  return {v:+(b/1024).toFixed(2),u:'KB'};
}
function openEdit(uid){
  const l=(window.__linksMap||{})[uid];
  if(!l){toast(lang==='fa'?'کانفیگ پیدا نشد':'Not found');return}
  const lim=__bytesToLimit(l.limit_bytes);
  const spd=l.speed_limit_bytes?+(Number(l.speed_limit_bytes)*8/1048576).toFixed(2):0;
  const set=(id,v)=>{document.getElementById(id).value=v};
  set('eUid',uid);
  set('eName',l.label||l.name||'');
  set('eNote',l.note||'');
  set('eLimit',lim.v);
  set('eUnit',lim.u);
  set('eDays','');
  set('eIp',Number(l.ip_limit)||0);
  set('eConn',Number(l.connection_limit)||0);
  set('eSpeed',spd);
  set('ePort',l.port||'');
  let exp=lang==='fa'?'انقضا: ندارد':'No expiry';
  if(l.expires_at){try{exp=(lang==='fa'?'انقضای فعلی: ':'Current expiry: ')+new Date(l.expires_at).toLocaleDateString(lang==='fa'?'fa-IR':'en-US')}catch(e){}}
  document.getElementById('eExpInfo').textContent=exp;
  window.__editOrig={limit:String(lim.v),unit:lim.u,speed:String(spd),ip:String(Number(l.ip_limit)||0),conn:String(Number(l.connection_limit)||0),port:String(l.port||''),name:l.label||l.name||'',note:l.note||''};
  ['eName','eNote','ePort'].forEach(id=>{document.getElementById(id).disabled=true});
  document.getElementById('editModal').classList.add('open');
}
function closeEdit(){document.getElementById('editModal').classList.remove('open')}
document.getElementById('editModal').addEventListener('click',e=>{if(e.target.id==='editModal')closeEdit()});
async function saveEdit(){
  const uid=document.getElementById('eUid').value;
  const o=window.__editOrig||{};
  const g=id=>document.getElementById(id).value;
  const body={};
  if(g('eLimit')!==o.limit||g('eUnit')!==o.unit){body.limit_value=Number(g('eLimit'))||0;body.limit_unit=g('eUnit')}
  if(g('eDays').trim()!=='')body.expires_days=Math.max(0,parseInt(g('eDays'),10)||0);
  if(g('eIp')!==o.ip)body.ip_limit=Math.max(0,parseInt(g('eIp'),10)||0);
  if(g('eConn')!==o.conn)body.connection_limit=Math.max(0,parseInt(g('eConn'),10)||0);
  if(g('eSpeed')!==o.speed){body.speed_limit_value=Number(g('eSpeed'))||0;body.speed_limit_unit='MBIT'}
  if(!Object.keys(body).length){closeEdit();return}
  const btn=document.getElementById('eSaveBtn');btn.disabled=true;
  const r=await api('/api/links/'+encodeURIComponent(uid),{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  btn.disabled=false;
  if(r!==null){closeEdit();toast(lang==='fa'?'ذخیره شد':'Saved');refreshAll()}
}
async function resetUsage(uid){
  if(!confirm(lang==='fa'?'مصرف ریست شود؟':'Reset usage?'))return;
  const r=await api('/api/links/'+uid+'/reset-usage',{method:'POST'});
  if(r!==null){toast(lang==='fa'?'مصرف ریست شد':'Usage reset');refreshAll()}
}


let __dragUid=null;
function cfgDragStart(e){__dragUid=e.currentTarget.getAttribute('data-uid');e.currentTarget.style.opacity='.5';e.dataTransfer.effectAllowed='move';}
function cfgDragOver(e){e.preventDefault();e.dataTransfer.dropEffect='move';const tr=e.currentTarget;if(tr&&tr.tagName==='TR')tr.style.background='var(--hover)';}
function cfgDragEnd(e){e.currentTarget.style.opacity='1';document.querySelectorAll('#linksTable tr').forEach(tr=>tr.style.background='');}
async function cfgDrop(e){
  e.preventDefault();
  const target=e.currentTarget.getAttribute('data-uid');
  document.querySelectorAll('#linksTable tr').forEach(tr=>tr.style.background='');
  if(!__dragUid||!target||__dragUid===target)return;
  const rows=[...document.querySelectorAll('#linksTable tr[data-uid]')];
  const ids=rows.map(r=>r.getAttribute('data-uid'));
  const from=ids.indexOf(__dragUid), to=ids.indexOf(target);
  if(from<0||to<0)return;
  ids.splice(from,1);ids.splice(to,0,__dragUid);
  // reorder DOM optimistically
  const tb=document.getElementById('linksTable');
  ids.forEach(id=>{const el=tb.querySelector(`tr[data-uid="${id}"]`);if(el)tb.appendChild(el);});
  await api('/api/links/reorder',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({order:ids})});
  toast(lang==='fa'?'ترتیب ذخیره شد':'Order saved');
}

function updateBulkBar(){
  const n=document.querySelectorAll('.cfg-chk:checked').length;
  const bar=document.getElementById('bottomBulkBar');
  const cnt=document.getElementById('bulkCount');
  if(cnt) cnt.textContent = n + (lang==='fa'?' انتخاب‌شده':' selected');
  if(bar) bar.classList.toggle('show', n>0);
  const all=document.getElementById('chkAll');
  if(all && n===0) all.checked=false;
}
function clearSelection(){
  document.querySelectorAll('.cfg-chk').forEach(c=>c.checked=false);
  const all=document.getElementById('chkAll');
  if(all) all.checked=false;
  updateBulkBar();
}
function toggleSelectAll(on){
  document.querySelectorAll('.cfg-chk').forEach(c=>c.checked=!!on);
  updateBulkBar();
}

function selectedCfgIds(){return [...document.querySelectorAll('.cfg-chk:checked')].map(c=>c.value)}
async function bulkDelete(){
  const ids=selectedCfgIds();
  if(!ids.length){toast(lang==='fa'?'چیزی انتخاب نشده':'Nothing selected');return}
  if(!confirm(lang==='fa'?`حذف ${ids.length} کانفیگ؟`:`Delete ${ids.length}?`))return;
  const r=await api('/api/links/bulk-delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids})});
  if(r){toast(lang==='fa'?`حذف شد: ${r.deleted}`:`Deleted: ${r.deleted}`);refreshAll()}
}
async function bulkMoveGroup(){
  const ids=selectedCfgIds();
  const cid=document.getElementById('bulkGroup')?.value||'0';
  if(!ids.length){toast(lang==='fa'?'چیزی انتخاب نشده':'Nothing selected');return}
  const r=await api('/api/links/bulk-category',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids,category_id:cid})});
  if(r){toast(lang==='fa'?'به گروه منتقل شد':'Moved');refreshAll()}
}
async function loadGroups(){
  const r=await api('/api/categories');
  const list=(r&&r.categories)||[];
  window.__catMap={};
  list.forEach(g=>{window.__catMap[String(g.id)]=g.name||g.id});
  const bulk=document.getElementById('bulkGroup');
  const cGroup=document.getElementById('cGroup');
  const opts=list.map(g=>`<option value="${esc(g.id)}">${esc(g.name||g.id)}</option>`).join('');
  if(bulk) bulk.innerHTML=opts||'<option value="0">عمومی</option>';
  if(cGroup) cGroup.innerHTML=opts||'<option value="0">عمومی</option>';
  const box=document.getElementById('groupsList');
  if(box){
    if(!list.length){box.innerHTML='<div style="color:var(--t3);text-align:center;padding:16px">—</div>';}
    else{
      box.innerHTML=list.map(g=>{
        const cnt=(__allLinks||[]).filter(l=>String(l.category_id||'0')===String(g.id)).length;
        return `<div style="border:1px solid var(--card-b);border-radius:12px;padding:12px;margin-bottom:8px;background:var(--bg3);display:flex;justify-content:space-between;gap:8px;align-items:center;flex-wrap:wrap">
          <div><b>${esc(g.name)}</b> <span style="font-size:11px;color:var(--t3)">${cnt} کانفیگ</span></div>
          <button class="btn btn-sm btn-d" onclick="deleteGroup('${esc(g.id)}')">حذف</button>
        </div>`;
      }).join('');
    }
  }
}
async function createGroup(){
  const name=document.getElementById('grpName').value.trim();
  if(!name){toast('نام لازم است');return}
  const r=await api('/api/categories',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});
  if(r){toast('گروه ساخته شد');document.getElementById('grpName').value='';loadGroups()}
}
async function deleteGroup(id){
  if(!confirm('حذف گروه؟'))return;
  const r=await api('/api/categories/'+id,{method:'DELETE'});
  if(r){toast('حذف شد');loadGroups();refreshAll()}
}


async function loadSecurity(){
  const r=await api('/api/security/status');
  const el=document.getElementById('secStatus');
  if(!r||!el)return;
  const locked=(r.locked_ips||[]).map(x=>`${x.ip} (${Math.ceil(x.remaining_sec/60)}د)`).join(' · ')||'—';
  el.innerHTML=`حداکثر تلاش: <b>${r.max_attempts}</b> · قفل: <b>${Math.round(r.lockout_seconds/60)} دقیقه</b><br>IPهای مسدود: ${locked}`;
}
async function unlockAllIps(){
  if(!confirm('رفع مسدودی همه؟'))return;
  const r=await api('/api/security/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})});
  if(r){toast('انجام شد');loadSecurity()}
}


async function downloadBackup(kind){
  try{
    const url = kind==='bot' ? '/api/backup/bot' : '/api/backup/users';
    const r = await fetch(url, {credentials:'same-origin', cache:'no-store'});
    if(r.status===401){ location.href='/login'; return; }
    if(!r.ok){
      let msg='خطا';
      try{ const j=await r.json(); msg=j.detail||msg; }catch(e){}
      toast(String(msg)); return;
    }
    const text = await r.text();
    // validate json
    try{ JSON.parse(text); }catch(e){ toast('پاسخ نامعتبر'); return; }
    const blob = new Blob([text], {type:'application/json;charset=utf-8'});
    const a = document.createElement('a');
    const stamp = new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');
    a.href = URL.createObjectURL(blob);
    a.download = kind==='bot' ? ('pxpanel-bot-'+stamp+'.json') : ('pxpanel-users-'+stamp+'.json');
    document.body.appendChild(a);
    a.click();
    setTimeout(()=>{ URL.revokeObjectURL(a.href); a.remove(); }, 500);
    toast(lang==='fa'?'دانلود شد':'Downloaded');
  }catch(e){ toast(String(e.message||e)); }
}
function readJsonFile(inputId){
  return new Promise((resolve,reject)=>{
    const inp=document.getElementById(inputId);
    if(!inp||!inp.files||!inp.files[0]){ reject(new Error(lang==='fa'?'فایل انتخاب نشده':'No file')); return; }
    const fr=new FileReader();
    fr.onload=()=>{ try{ resolve(JSON.parse(fr.result)); }catch(e){ reject(new Error('JSON نامعتبر')); } };
    fr.onerror=()=>reject(new Error('خواندن فایل ناموفق'));
    fr.readAsText(inp.files[0],'utf-8');
  });
}
async function restoreUsers(mode){
  try{
    const data = await readJsonFile('restoreUsersFile');
    data.mode = mode||'merge';
    if(mode==='replace' && !confirm(lang==='fa'?'همه داده‌های فعلی پاک و جایگزین می‌شود. مطمئنی؟':'Replace all current data?')) return;
    const r = await api('/api/restore/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    if(r){ toast(lang==='fa'?('بازیابی شد: '+r.links+' کانفیگ'):('Restored: '+r.links)); refreshAll(); }
  }catch(e){ toast(e.message||String(e)); }
}
async function restoreBot(){
  try{
    const data = await readJsonFile('restoreBotFile');
    const r = await api('/api/restore/bot',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    if(r) toast(r.message||(lang==='fa'?'ربات بازیابی شد':'Bot restored'));
  }catch(e){ toast(e.message||String(e)); }
}

applyLang();loadMe();loadProtocols();loadGroups();refreshAll();setInterval(refreshAll,1000);


</script>

<script>
(function(){
  const E=id=>document.getElementById(id);
  setInterval(()=>{const c=E('tbClock');if(c)c.textContent=new Date().toLocaleTimeString('en-GB')},1000);
  async function me(){try{const r=await api('/api/me');if(r){E('tbUser').textContent=r.username||'admin';E('tbRole').textContent=r.role==='owner'||r.role==='superadmin'?'مدیر کل':(r.role||'مدیر')}}catch(e){}}
  function chart(h){
    const keys=Object.keys(h||{}).sort(), box=E('trafficChart');if(!box)return;
    if(!keys.length){box.innerHTML='<div style="text-align:center;color:var(--t3);padding:70px 0;font-size:12px">هنوز ترافیکی ثبت نشده است</div>';return}
    const v=keys.map(k=>h[k]),mx=Math.max(...v,1),W=560,H=190,pl=8,n=keys.length;
    const X=i=>pl+(n===1?W/2:i*(W-2*pl)/(n-1)),Y=x=>H-18-(x/mx)*(H-40);
    const pts=v.map((x,i)=>X(i)+','+Y(x)).join(' ');
    let g='';for(let i=0;i<4;i++){const y=22+i*(H-40)/3;g+=`<line x1="0" x2="${W}" y1="${y}" y2="${y}" stroke="rgba(0,229,255,.12)"/>`}
    const lab=keys.map((k,i)=>(n<=8||i%Math.ceil(n/8)===0)?`<text x="${X(i)}" y="${H}" text-anchor="middle">${k}</text>`:'').join('');
    box.innerHTML=`<svg viewBox="0 0 ${W} ${H+4}" preserveAspectRatio="none"><defs><linearGradient id="cg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#00e5ff" stop-opacity=".45"/><stop offset="1" stop-color="#8a5cff" stop-opacity="0"/></linearGradient></defs>${g}<polygon points="${X(0)},${H-18} ${pts} ${X(n-1)},${H-18}" fill="url(#cg)"/><polyline points="${pts}" fill="none" stroke="#6df3ff" stroke-width="2.5" stroke-linejoin="round" style="filter:drop-shadow(0 0 6px #00e5ff)"/>${v.map((x,i)=>`<circle cx="${X(i)}" cy="${Y(x)}" r="3.5" fill="#6df3ff"><title>${keys[i]} · ${fmtB(x)}</title></circle>`).join('')}${lab}</svg>`;
  }
  async function extras(){
    try{const st=await api('/stats');if(st){chart(st.hourly);E('stUp').textContent=st.uptime||'—';E('stReq').textContent=st.total_requests??'—';E('stErr').textContent=st.total_errors??'—'}}catch(e){}
    const arr=(typeof __allLinks!=='undefined'&&Array.isArray(__allLinks))?__allLinks:[];
    const act=arr.filter(l=>l.active!==false).length,tot=arr.length,pct=tot?Math.round(act/tot*100):0;
    E('donutFg').setAttribute('stroke-dasharray',(302*pct/100)+' 302');E('donutPct').textContent=pct+'%';
    E('lgAct').textContent=act;E('lgOff').textContent=tot-act;E('lgAll').textContent=tot;
    E('dashLinks').innerHTML=arr.slice(-5).reverse().map(l=>{
      const on=l.active!==false,lim=Number(l.limit_bytes||0),ex=l.expires_at?String(l.expires_at).slice(0,10):'—';
      return `<tr><td>${esc(l.name||l.label||'—')}</td><td>${esc(l.protocol||'—')}</td><td>${esc(ex)}</td><td>${fmtB(l.used_bytes)}</td><td>${lim?fmtB(lim):'∞'}</td><td><span class="${on?'pill-on':'pill-off'}">${on?'فعال':'غیرفعال'}</span></td></tr>`}).join('')||'<tr><td colspan="6" style="text-align:center;color:var(--t3)">کانفیگی وجود ندارد</td></tr>';
    try{const d=await api('/api/activity');const logs=(Array.isArray(d)?d:(d&&d.logs)||[]).slice(-4).reverse();
      E('dashActs').innerHTML=logs.map(l=>`<div class="log-item"><div class="log-time">${esc((l.time||l.ts||'').toString().slice(11,19)||'—')}</div><div class="log-msg">${esc(l.message||l.msg||'')}</div></div>`).join('')||'<div style="color:var(--t3);font-size:12px;text-align:center;padding:10px">فعالیتی ثبت نشده</div>'}catch(e){}
  }
  const _ra=refreshAll;
  refreshAll=async function(){await _ra.apply(this,arguments);try{await extras()}catch(e){}};
  me();setTimeout(()=>{try{extras()}catch(e){}},600);
})();
</script>
</body>
</html>
"""




@app.get(
    "/dashboard",
    response_class=HTMLResponse,
)
async def dashboard(
    request: Request,
):

    if not await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):
        return RedirectResponse(
            "/login"
        )

    await ensure_default_categories()
    await ensure_default_link()

    return HTMLResponse(
        DASHBOARD_HTML
    )


# ============================================================
# TEST
# ============================================================

@app.get(
    "/test-ws",
    response_class=HTMLResponse,
)
async def test_ws():

    return HTMLResponse(
        """
        <script>
        location.href='/dashboard'
        </script>
        """
    )


# ============================================================
# GLOBAL ERROR HANDLER
# ============================================================

@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception,
):

    stats[
        "total_errors"
    ] += 1

    error_logs.append(
        {
            "error":
                str(exc),

            "path":
                str(request.url),

            "method":
                request.method,

            "time":
                datetime.now().isoformat(),
        }
    )

    logger.exception(
        "Unhandled exception: %s %s",
        request.method,
        request.url,
    )

    # API requests
    if (
        request.url.path.startswith(
            "/api/"
        )
        or request.url.path == "/stats"
    ):

        return JSONResponse(
            {
                "ok": False,
                "error":
                    str(exc)
                or "internal server error",
            },
            status_code=500,
        )

    return HTMLResponse(
        """
        <html lang="fa" dir="rtl">
        <body style="
            background:#07070a;
            color:#fff;
            font-family:sans-serif;
            padding:40px;
        ">
            <h2>
            خطای داخلی AHB Panel
            </h2>

            <p>
            لطفاً لاگ Railway را بررسی کنید.
            </p>
        </body>
        </html>
        """,
        status_code=500,
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        workers=1,
    )
