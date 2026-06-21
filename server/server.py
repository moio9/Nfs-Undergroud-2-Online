"""
server.py - U2Online server core.
Exports the 3 functions mirrored from server.dll:
  StartServer()
  StopServer()
  IsServerRunning()

Plus the full GameServer class that orchestrates all subsystems.
"""

import ipaddress
import base64
import hashlib
import hmac
import json
import shlex
import socket
import select
import struct
import threading
import time
import logging
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from config       import Config, DEFAULTS
from user_manager import STAT_GAME, STAT_LOBBY, STAT_ROOM, User, UserManager
from room_manager import RoomManager, GameManager
from matchmaking  import PlayModule
from ranking      import RankingSystem, StatsSystem
from batch        import BatchReporter, ChallengeManager
from master       import MasterServer, SlaveClient
from client_handler import ClientHandler
from ea_messenger import EAMessengerServer
from protocol import encode_message
import persona_policy

# ------------------------------------------------------------------ #
# Logging setup                                                        #
# ------------------------------------------------------------------ #

_LOG_FORMAT = "%(asctime)s [%(name)-14s] %(levelname)s: %(message)s"
_LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"
_LOG_OFF_LEVEL = logging.CRITICAL + 10

logging.basicConfig(
    level=logging.WARNING,
    format=_LOG_FORMAT,
    datefmt=_LOG_DATEFMT,
)
for _handler in logging.getLogger().handlers:
    setattr(_handler, "_u2online_managed", True)
    setattr(_handler, "_u2online_kind", "console")

log = logging.getLogger("server")


class UDPRelayVerboseFilter(logging.Filter):
    def __init__(self) -> None:
        super().__init__()
        self.enabled = False

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno >= logging.WARNING:
            return True
        msg = str(record.msg or "")
        if msg.startswith(("UDP relay", "UDP room")):
            return self.enabled
        return True


_udp_relay_verbose_filter = UDPRelayVerboseFilter()
log.addFilter(_udp_relay_verbose_filter)


def _cfg_bool(value: object) -> bool:
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off", ""):
            return False
    try:
        return int(value or 0) != 0
    except (TypeError, ValueError):
        return False


def _log_level(value: object, default: int = logging.INFO) -> int:
    if isinstance(value, int):
        return value
    text = str(value or "").strip().upper()
    if not text:
        return default
    if text.isdigit():
        return int(text)
    levels = {
        "CRITICAL": logging.CRITICAL,
        "ERROR": logging.ERROR,
        "WARN": logging.WARNING,
        "WARNING": logging.WARNING,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG,
        "NOTSET": logging.NOTSET,
        "OFF": _LOG_OFF_LEVEL,
        "NONE": _LOG_OFF_LEVEL,
        "DISABLED": _LOG_OFF_LEVEL,
    }
    return levels.get(text, default)


def _log_file_path(config_path: str, raw_path: object) -> str:
    path = str(raw_path or "").strip()
    if not path:
        return ""
    if os.path.isabs(path):
        return path
    return os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(config_path)), path))


def _mark_log_handler(handler: logging.Handler, kind: str) -> logging.Handler:
    setattr(handler, "_u2online_managed", True)
    setattr(handler, "_u2online_kind", kind)
    return handler


def configure_logging_from_config(cfg: Config, config_path: str) -> None:
    debug_mode = _cfg_bool(cfg.get("DEBUG_MODE", 0))
    default_level = logging.DEBUG if debug_mode else _log_level(cfg.get("LOG_LEVEL", "INFO"), logging.INFO)
    console_level = _log_level(cfg.get("LOG_CONSOLE_LEVEL", ""), default_level)
    file_path = _log_file_path(config_path, cfg.get("LOG_FILE", ""))
    file_level = _log_level(cfg.get("LOG_FILE_LEVEL", ""), default_level)
    if debug_mode and file_path and file_level > logging.DEBUG:
        file_level = logging.DEBUG

    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, "_u2online_managed", False):
            root.removeHandler(handler)
            try:
                handler.close()
            except Exception:
                pass

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_LOG_DATEFMT)
    handler_levels = []

    if console_level < _LOG_OFF_LEVEL:
        console_handler = _mark_log_handler(logging.StreamHandler(), "console")
        console_handler.setLevel(console_level)
        console_handler.setFormatter(formatter)
        root.addHandler(console_handler)
        handler_levels.append(console_level)

    if file_path and file_level < _LOG_OFF_LEVEL:
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            file_handler = _mark_log_handler(logging.FileHandler(file_path, encoding="utf-8"), "file")
            file_handler.setLevel(file_level)
            file_handler.setFormatter(formatter)
            root.addHandler(file_handler)
            handler_levels.append(file_level)
        except OSError as exc:
            log.warning("Failed to open log file '%s': %s", file_path, exc)

    if not handler_levels:
        root.addHandler(_mark_log_handler(logging.NullHandler(), "null"))
        root.setLevel(_LOG_OFF_LEVEL)
    else:
        root.setLevel(min(handler_levels + [default_level]))
    for logger_name in ("server", "client", "rooms", "users", "ranking", "master", "config", "control", "batch", "matchmaking"):
        logging.getLogger(logger_name).setLevel(logging.NOTSET)

Addr = Tuple[str, int]


@dataclass
class UDPRelayRoomEndpoint:
    uid: int
    raw_ip: str
    match_ip: str
    presented_ip: str


@dataclass
class UDPRelayClientState:
    addr: Addr
    room: Optional[int] = None
    provisional_room: Optional[int] = None
    spoof_ip: str = ""
    sticky_peer: Optional[Addr] = None
    sticky_peer_at: float = 0.0
    last_peer: Optional[Addr] = None
    last_peer_at: float = 0.0
    control_sent_room: Optional[int] = None
    control_prime_count: int = 0
    control_prime_last: float = 0.0
    raw_ack_sent_room: Optional[int] = None
    room_role_room: Optional[int] = None
    room_role_cmd: int = 0
    last_room_cmd: int = 0
    last_room_id: Optional[int] = None
    last_room_cmd_at: float = 0.0
    last_seen: float = field(default_factory=time.time)
    packets_in: int = 0
    packets_out: int = 0
    uid: int = 0
    relay_listen_port: int = 0
    raw_sent_rooms: Set[int] = field(default_factory=set)
    raw_peer_kick_rooms: Set[int] = field(default_factory=set)
    raw_echo_counts: Dict[int, int] = field(default_factory=dict)
    raw_order_next: Dict[int, int] = field(default_factory=dict)
    raw_order_buffer: Dict[int, Dict[int, bytes]] = field(default_factory=dict)
    raw_real_65_rooms: Set[int] = field(default_factory=set)


def _udp_read_u32_le(buf: bytes, off: int = 0) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _udp_maybe_decode_wrapped(data: bytes) -> Optional[Tuple[Addr, bytes]]:
    if len(data) <= 10:
        return None

    b0 = data[0]
    version = b0 >> 4
    if version == 4 and len(data) >= 20:
        ihl = (b0 & 0x0F) * 4
        total_len = struct.unpack_from("!H", data, 2)[0]
        if ihl >= 20 and total_len >= ihl and total_len <= len(data):
            return None
    if version == 6 and len(data) >= 40:
        payload_len = struct.unpack_from("!H", data, 4)[0]
        total_len = 40 + payload_len
        if total_len <= len(data):
            return None

    outer_word = _udp_read_u32_le(data, 0)
    if outer_word <= 0x00001000:
        return None

    orig_port = struct.unpack_from("!H", data, 0)[0]
    orig_ip_raw = data[2:6]
    if orig_port == 0 or orig_ip_raw == b"\x00\x00\x00\x00":
        return None

    octet0 = orig_ip_raw[0]
    if octet0 == 0 or octet0 >= 224:
        return None
    if orig_ip_raw == b"\xFF\xFF\xFF\xFF":
        return None

    ip = ".".join(str(b) for b in orig_ip_raw)
    return (ip, orig_port), data[6:]


def _udp_make_wrapped(src: Addr, payload: bytes) -> bytes:
    ip_raw = bytes(int(part) & 0xFF for part in src[0].split("."))
    if len(ip_raw) != 4:
        raise ValueError(f"Invalid IPv4 address: {src[0]}")
    return struct.pack("!H", src[1]) + ip_raw + payload


def _udp_extract_room(payload: bytes) -> Optional[int]:
    if len(payload) < 8:
        return None
    cmd = _udp_read_u32_le(payload, 0)
    if cmd not in (1, 5):
        return None
    room = _udp_read_u32_le(payload, 4)
    if room in (0, 0xFFFFFFFF):
        return None
    return room


def _udp_is_local_or_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_loopback
        or addr.is_private
        or addr.is_unspecified
        or addr.is_link_local
    )


# ======================================================================= #
# GameServer - full U2Online server orchestrator                           #
# ======================================================================= #

class GameServer:
    def __init__(self, config_path: str = "server.cfg"):
        self._config_path = os.path.abspath(config_path)
        self.cfg = Config()
        self.cfg.load(config_path)
        configure_logging_from_config(self.cfg, self._config_path)

        # Subsystems
        self.users      = UserManager(self.cfg)
        self.rooms      = RoomManager(self.cfg)
        self.games      = GameManager(self.cfg)
        self.ranking    = RankingSystem(self.cfg)
        self.stats      = StatsSystem(self.cfg)
        self.play       = PlayModule(self.cfg, self.users, self.rooms,
                                     self.games, self.ranking)
        self.batch      = BatchReporter(self.cfg)
        self.challenges = ChallengeManager(self.users, self.rooms)

        # Master/Slave
        self.master: Optional[MasterServer] = None
        self.slave:  Optional[SlaveClient]  = None

        self.host = self._listen_host("lobby")
        self.udp_relay_port = 20000
        self.messenger = EAMessengerServer(self)

        # TCP listener
        self._sock:    Optional[socket.socket] = None
        self._legacy_lobby_sock: Optional[socket.socket] = None
        self._extra_lobby_socks: List[socket.socket] = []
        self._game_relay_sock: Optional[socket.socket] = None
        self._game_relay_socks: List[socket.socket] = []
        self._game_relay_sock_by_port: Dict[int, socket.socket] = {}
        self._thread:  Optional[threading.Thread] = None
        self._legacy_lobby_thread: Optional[threading.Thread] = None
        self._extra_lobby_threads: List[threading.Thread] = []
        self._game_relay_thread: Optional[threading.Thread] = None
        self._timer:   Optional[threading.Thread] = None
        self._admin_thread: Optional[threading.Thread] = None
        self._admin_stop = threading.Event()
        self.is_running = False

        # Global handle (mirrors g_serverHandle in DLL)
        self._handle: Optional[object] = None
        self._advertised_game_endpoints_path = ""
        self._advertised_game_endpoints_mtime = -1.0
        self._advertised_game_endpoints_cache: Dict[str, Dict[str, Tuple[str, int]]] = {
            "uid": {},
            "pers": {},
            "name": {},
        }
        self._auth_accounts_path = ""
        self._auth_accounts_mtime = -1.0
        self._auth_accounts_cache: List[dict] = []
        self._auth_accounts_lock = threading.RLock()
        self._auth_failures: Dict[str, List[float]] = {}
        self._auth_forced_rejects: List[dict] = []
        self._persona_forced_rejects: List[dict] = []
        self._auth_lock = threading.Lock()
        self._connection_rate_lock = threading.Lock()
        self._connection_rate_attempts: Dict[str, List[float]] = {}
        self._connection_rate_blocked_until: Dict[str, float] = {}
        self._lobby_connection_lock = threading.Lock()
        self._lobby_active_connections = 0
        self._lobby_dir_challenges: Dict[str, Tuple[str, str, float]] = {}
        self._lobby_dir_challenges_lock = threading.Lock()
        self._udp_relay_uid_addr_by_room: Dict[int, Dict[int, Addr]] = {}
        self._udp_relay_clients: Dict[Addr, UDPRelayClientState] = {}
        self._udp_relay_rooms: Dict[int, Set[Addr]] = {}
        self._udp_relay_pending_room_packets: Dict[int, List[Tuple[Addr, bytes]]] = {}
        self._udp_relay_pending_room_raw_packets: Dict[int, List[Tuple[Addr, bytes]]] = {}
        self._udp_relay_pending_room_seen: Dict[int, float] = {}
        self._udp_relay_pending_room_raw_seen: Dict[int, float] = {}
        self._udp_relay_raw_started_rooms: Set[int] = set()
        self._udp_relay_host_bootstrap_sent: Set[Tuple[int, Addr, Addr]] = set()
        self._udp_relay_missing_65_sent: Set[Tuple[int, Addr, Addr]] = set()
        self._udp_relay_host_continuation_sent: Set[Tuple[int, Addr, Addr]] = set()
        self._udp_relay_alias_send_logged: Set[Tuple[Addr, Addr]] = set()
        self._udp_relay_recv_log_count = 0
        self._udp_relay_limit_log_at = 0.0
        self._last_master_stat_payload = ""
        self._last_master_stat_log_time = 0.0
        self._master_stat_dirty = True
        self._resolved_ipv4_cache: Dict[str, str] = {}
        self._admin_banned_ips: Set[str] = set()
        self._admin_banned_names: Set[str] = set()
        self._admin_banned_personas: Set[str] = set()
        self._udp_relay_verbose = self._cfg_flag("UDP_RELAY_VERBOSE", "UDP_DEBUG")
        self._sync_udp_relay_verbose_filter()
        self._load_admin_bans()
        self.messenger.load_social_relations()

    @staticmethod
    def _cfg_host_value(value: object) -> str:
        text = str(value or "").strip()
        if text.count(":") == 1:
            host, port = text.rsplit(":", 1)
            if host.strip() and port.strip().isdigit():
                return host.strip()
        return text

    @staticmethod
    def _cfg_port_value(value: object) -> int:
        try:
            port = int(value or 0)
        except (TypeError, ValueError):
            text = str(value or "").strip()
            if text.count(":") != 1:
                return 0
            _, port_text = text.rsplit(":", 1)
            try:
                port = int(port_text.strip() or 0)
            except (TypeError, ValueError):
                return 0
        return port if port > 0 else 0

    def _first_host(self, *keys: str) -> str:
        for key in keys:
            host = self._cfg_host_value(self.cfg.get(key, ""))
            if host:
                return host
        return ""

    def _first_port(self, *keys: str) -> int:
        for key in keys:
            port = self._cfg_port_value(self.cfg.get(key, 0))
            if port > 0:
                return port
        return 0

    def _cfg_flag(self, *keys: str) -> bool:
        for key in keys:
            value = self.cfg.get(key, 0)
            if isinstance(value, str):
                text = value.strip().lower()
                if text in ("1", "true", "yes", "on"):
                    return True
                if text in ("0", "false", "no", "off", ""):
                    continue
            try:
                if int(value or 0) != 0:
                    return True
            except (TypeError, ValueError):
                continue
        return False

    def _cfg_int(self, key: str, default: int, *, min_value: Optional[int] = None, max_value: Optional[int] = None) -> int:
        try:
            value = int(self.cfg.get(key, default) or default)
        except (TypeError, ValueError):
            value = int(default)
        if min_value is not None:
            value = max(int(min_value), value)
        if max_value is not None:
            value = min(int(max_value), value)
        return value

    def _cfg_float(self, key: str, default: float, *, min_value: Optional[float] = None, max_value: Optional[float] = None) -> float:
        try:
            value = float(self.cfg.get(key, default) or default)
        except (TypeError, ValueError):
            value = float(default)
        if min_value is not None:
            value = max(float(min_value), value)
        if max_value is not None:
            value = min(float(max_value), value)
        return value

    def _connection_rate_settings(self) -> Tuple[int, float, float]:
        try:
            limit = int(self.cfg.get("SERVER_CONN_RATE_LIMIT", 20) or 0)
        except (TypeError, ValueError):
            limit = 20
        try:
            window = float(self.cfg.get("SERVER_CONN_RATE_WINDOW", 10.0) or 10.0)
        except (TypeError, ValueError):
            window = 10.0
        try:
            block = float(self.cfg.get("SERVER_CONN_RATE_BLOCK", 5.0) or 5.0)
        except (TypeError, ValueError):
            block = 5.0
        return max(0, limit), max(1.0, min(3600.0, window)), max(0.0, min(3600.0, block))

    def _accepts_new_connection(self, ip: str) -> bool:
        limit, window, block = self._connection_rate_settings()
        if limit <= 0:
            return True
        key = str(ip or "").strip() or "-"
        now = time.time()
        with self._connection_rate_lock:
            blocked_until = float(self._connection_rate_blocked_until.get(key, 0.0) or 0.0)
            if blocked_until > now:
                log.warning(
                    "Connection rate limited: ip=%s retry_after=%.1fs",
                    key,
                    max(0.0, blocked_until - now),
                )
                return False
            if blocked_until:
                self._connection_rate_blocked_until.pop(key, None)

            attempts = [
                ts for ts in self._connection_rate_attempts.get(key, [])
                if now - float(ts or 0.0) < window
            ]
            if len(attempts) >= limit:
                self._connection_rate_attempts[key] = attempts
                if block > 0:
                    self._connection_rate_blocked_until[key] = now + block
                log.warning(
                    "Connection rate limit tripped: ip=%s count=%d limit=%d window=%.1fs block=%.1fs",
                    key,
                    len(attempts) + 1,
                    limit,
                    window,
                    block,
                )
                return False

            attempts.append(now)
            self._connection_rate_attempts[key] = attempts
            if len(self._connection_rate_attempts) > 4096:
                stale = [
                    addr for addr, seen in self._connection_rate_attempts.items()
                    if not seen or now - float(seen[-1] or 0.0) >= window
                ]
                for addr in stale[:512]:
                    self._connection_rate_attempts.pop(addr, None)
                    self._connection_rate_blocked_until.pop(addr, None)
            return True

    def _lobby_max_connections(self) -> int:
        return self._cfg_int("SERVER_MAX_CONNECTIONS", 64, min_value=0, max_value=100000)

    def _open_lobby_connection_slot(self, ip: str) -> bool:
        max_connections = self._lobby_max_connections()
        if max_connections <= 0:
            return True
        with self._lobby_connection_lock:
            if self._lobby_active_connections >= max_connections:
                log.warning(
                    "Lobby connection limit reached: ip=%s active=%d max=%d",
                    ip or "-",
                    self._lobby_active_connections,
                    max_connections,
                )
                return False
            self._lobby_active_connections += 1
            return True

    def _close_lobby_connection_slot(self) -> None:
        with self._lobby_connection_lock:
            self._lobby_active_connections = max(0, self._lobby_active_connections - 1)

    def _sync_udp_relay_verbose_filter(self) -> None:
        _udp_relay_verbose_filter.enabled = bool(self._udp_relay_verbose)

    def auth_verify_enabled(self) -> bool:
        return self._cfg_flag("AUTH_VERIFY")

    def auth_capture_enabled(self) -> bool:
        return self._cfg_flag("AUTH_CAPTURE")

    def auth_auto_enroll_enabled(self) -> bool:
        return self._cfg_flag("AUTH_AUTO_ENROLL")

    def auth_allow_create_enabled(self) -> bool:
        return self._cfg_flag("AUTH_ALLOW_CREATE")

    def auth_mode(self) -> str:
        mode = str(self.cfg.get("AUTH_MODE", "password") or "password").strip().lower()
        if mode in ("account", "user", "whitelist", "name"):
            return "account"
        return "password"

    def auth_migrate_plaintext_enabled(self) -> bool:
        return self._cfg_flag("AUTH_MIGRATE_PLAINTEXT", "AUTH_SECURE_STORE") or str(
            self.cfg.get("AUTH_MIGRATE_PLAINTEXT", "1") or "1"
        ).strip().lower() not in ("0", "false", "no", "off", "")

    def _auth_config_path(self, key: str, default: str) -> str:
        path = str(self.cfg.get(key, default) or "").strip()
        if not path:
            path = default
        if os.path.isabs(path):
            return path
        return os.path.abspath(os.path.join(os.path.dirname(self._config_path), path))

    def _auth_accounts_file(self) -> str:
        return self._auth_config_path("AUTH_ACCOUNTS_FILE", "data/auth_accounts.json")

    def _auth_capture_file(self) -> str:
        return self._auth_config_path("AUTH_CAPTURE_FILE", "data/auth_captures.jsonl")

    def remember_lobby_dir_challenge(self, ip: str, sess: str, mask: str) -> None:
        key = str(ip or "").strip()
        if not key or not sess or not mask:
            return
        with self._lobby_dir_challenges_lock:
            self._lobby_dir_challenges[key] = (str(sess), str(mask), time.time())

    def recent_lobby_dir_challenge(self, ip: str, *, max_age: float = 30.0) -> tuple[str, str]:
        key = str(ip or "").strip()
        if not key:
            return "", ""
        now = time.time()
        with self._lobby_dir_challenges_lock:
            item = self._lobby_dir_challenges.get(key)
            if not item:
                return "", ""
            sess, mask, seen_at = item
            if (now - float(seen_at)) > max_age:
                self._lobby_dir_challenges.pop(key, None)
                return "", ""
            return sess, mask

    def sweep_lobby_dir_challenges(self, *, max_age: float = 60.0) -> None:
        now = time.time()
        with self._lobby_dir_challenges_lock:
            expired = [
                key for key, (_, _, seen_at) in self._lobby_dir_challenges.items()
                if (now - float(seen_at)) > max_age
            ]
            for key in expired:
                self._lobby_dir_challenges.pop(key, None)

    @staticmethod
    def _auth_norm(value) -> str:
        return str(value or "").strip().lower()

    @staticmethod
    def _auth_kv_value(kv: dict, *keys: str) -> str:
        if not kv:
            return ""
        upper = {str(k).strip().upper(): str(v).strip() for k, v in kv.items()}
        for key in keys:
            value = upper.get(str(key).strip().upper(), "")
            if value:
                return value
        return ""

    @staticmethod
    def _auth_list(value) -> List[str]:
        if value is None:
            return []
        if isinstance(value, list):
            raw_values = value
        else:
            raw_values = [value]
        out: List[str] = []
        for item in raw_values:
            if isinstance(item, (list, tuple)):
                out.extend(GameServer._auth_list(item))
                continue
            text = str(item or "").strip()
            if text:
                out.append(text)
        return out

    @staticmethod
    def _auth_bool(value, default: bool = False) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "on", "y", "accepted", "accept", "ok", "enabled", "active"):
            return True
        if text in ("0", "false", "no", "off", "n", "rejected", "deny", "denied", "disabled", "locked", "banned", ""):
            return False
        try:
            return int(text, 10) != 0
        except ValueError:
            return default

    @staticmethod
    def _auth_reason_alias(value) -> str:
        text = str(value or "").strip().lower()
        if not text:
            return ""
        if text.startswith("auth") and len(text) == 8:
            text = text[4:]
        text = text.replace("-", "_").replace(" ", "_")
        text = text.split(":", 1)[0]
        return {
            "imst": "invalid_auth",
            "invalid": "invalid_auth",
            "invalid_auth": "invalid_auth",
            "unknown_account": "invalid_auth",
            "logn": "account_in_use",
            "already_logged_in": "account_in_use",
            "already_online": "account_in_use",
            "account_in_use": "account_in_use",
            "lock": "account_locked",
            "locked": "account_locked",
            "account_locked": "account_locked",
            "disabled": "account_disabled",
            "account_disabled": "account_disabled",
            "banned": "admin_ban",
            "admin_ban": "admin_ban",
            "pass": "bad_password",
            "bad_password": "bad_password",
            "password_error": "bad_password",
            "ikey": "invalid_key",
            "invalid_key": "invalid_key",
            "bad_key": "invalid_key",
            "invalid_cdkey": "invalid_key",
            "invalid_cd_key": "invalid_key",
            "tosa": "tos_not_accepted",
            "tos": "tos_not_accepted",
            "tos_not_accepted": "tos_not_accepted",
            "terms_not_accepted": "tos_not_accepted",
            "dber": "database_error",
            "database_error": "database_error",
            "backend_error": "database_error",
            "blak": "blacklisted",
            "blacklist": "blacklisted",
            "blacklisted": "blacklisted",
            "blocked": "blacklisted",
            "shar": "share_not_accepted",
            "share": "share_not_accepted",
            "share_required": "share_not_accepted",
            "share_not_accepted": "share_not_accepted",
            "miss": "missing_fields",
            "missing_fields": "missing_fields",
            "missing_required_fields": "missing_fields",
            "filt": "filtered",
            "filter": "filtered",
            "filtered": "filtered",
            "filter_failed": "filtered",
            "profane": "filtered",
            "time": "auth_timeout",
            "timeout": "auth_timeout",
            "auth_timeout": "auth_timeout",
            "backend_timeout": "auth_timeout",
            "over": "invalid_state",
            "invalid_state": "invalid_state",
            "backend_over": "invalid_state",
        }.get(text, "")

    def _auth_required_fields(self) -> List[str]:
        raw = str(self.cfg.get("AUTH_REQUIRED_FIELDS", "") or "").strip()
        if not raw:
            return []
        fields: List[str] = []
        for item in raw.replace(";", ",").replace(" ", ",").split(","):
            field = item.strip().upper()
            if field and field not in fields:
                fields.append(field)
        return fields

    def _auth_missing_required_fields(self, kv: dict) -> List[str]:
        return [
            field for field in self._auth_required_fields()
            if not self._auth_kv_value(kv, field)
        ]

    def _auth_account_reject_reason(self, account: dict) -> str:
        for key in ("auth_reason", "auth_status", "auth_code", "login_reason", "login_status", "status"):
            reason = self._auth_reason_alias(account.get(key, ""))
            if reason:
                return reason
        if self._auth_bool(account.get("locked"), False) or self._auth_bool(account.get("account_locked"), False):
            return "account_locked"
        if self._auth_bool(account.get("disabled"), False) or not self._auth_bool(account.get("enabled"), True):
            return "account_disabled"
        if self._auth_bool(account.get("banned"), False):
            return "admin_ban"
        if self._auth_bool(account.get("blacklisted"), False) or self._auth_bool(account.get("blocked"), False):
            return "blacklisted"
        if "tos_accepted" in account and not self._auth_bool(account.get("tos_accepted"), False):
            return "tos_not_accepted"
        if "share_accepted" in account and not self._auth_bool(account.get("share_accepted"), False):
            return "share_not_accepted"
        return ""

    def _auth_account_key_reject_reason(self, account: dict, kv: dict) -> str:
        expected: List[str] = []
        for key in ("cdkey", "cd_key", "key", "lkey", "product_key", "serial"):
            expected.extend(self._auth_list(account.get(key)))
        for key in ("cdkeys", "cd_keys", "keys", "lkeys", "product_keys", "serials"):
            expected.extend(self._auth_list(account.get(key)))
        if not expected:
            return ""
        supplied = self._auth_kv_value(
            kv,
            "CDKEY",
            "CD_KEY",
            "KEY",
            "LKEY",
            "PRODUCT_KEY",
            "SERIAL",
            "REGKEY",
        )
        if not supplied:
            return "invalid_key"
        supplied_norm = self._auth_norm(supplied)
        for value in expected:
            if supplied_norm == self._auth_norm(value):
                return ""
        return "invalid_key"

    @staticmethod
    def _auth_reason_code(reason: str) -> str:
        key = GameServer._auth_reason_alias(reason) or str(reason or "").strip().lower()
        if key.startswith("auth") and len(key) == 8:
            key = key[4:]
        if len(key) == 4 and key in {
            "imst", "logn", "lock", "pass", "ikey", "tosa", "dber",
            "blak", "shar", "miss", "filt", "time", "over",
        }:
            return key
        return {
            "invalid_auth": "imst",
            "unknown_account": "imst",
            "missing_identifier": "imst",
            "account_in_use": "logn",
            "account_locked": "lock",
            "account_disabled": "lock",
            "admin_ban": "lock",
            "rate_limited": "lock",
            "bad_password": "pass",
            "missing_password": "pass",
            "invalid_key": "ikey",
            "tos_not_accepted": "tosa",
            "database_error": "dber",
            "no_accounts": "dber",
            "save_failed": "dber",
            "blacklisted": "blak",
            "share_not_accepted": "shar",
            "missing_fields": "miss",
            "filtered": "filt",
            "auth_timeout": "time",
            "invalid_state": "over",
        }.get(key, "")

    @staticmethod
    def _auth_supported_codes_text() -> str:
        return "imst logn lock pass ikey tosa dber blak shar miss filt time over"

    def _auth_force_reject_ttl(self) -> float:
        try:
            return max(1.0, float(self.cfg.get("AUTH_FORCE_REJECT_TTL", 300) or 300))
        except Exception:
            return 300.0

    def _auth_request_identities(self, kv: dict, identifier: str = "") -> Set[str]:
        identities: Set[str] = set()
        for value in (
            identifier,
            self._auth_kv_value(kv, "EMAIL", "MAIL", "PMAIL", "U2_OLX_MAIL"),
            self._auth_kv_value(kv, "USER", "USERNAME", "LOGIN"),
            self._auth_kv_value(kv, "NAME"),
            self._auth_kv_value(kv, "PERS", "PERSO", "PERSONA"),
        ):
            norm = self._auth_norm(value)
            if norm:
                identities.add(norm)
        return identities

    def _auth_clear_expired_forced_rejects_locked(self, now: float) -> None:
        self._auth_forced_rejects = [
            entry for entry in self._auth_forced_rejects
            if float(entry.get("expires_at", 0.0) or 0.0) > now
        ]

    def _auth_set_forced_reject(self, code_or_reason: str, identifier: str = "", uses: int = 1) -> str:
        reason = self._auth_reason_alias(code_or_reason)
        code = self._auth_reason_code(code_or_reason)
        if not reason or not code:
            return f"unknown auth code '{code_or_reason}'. known: {self._auth_supported_codes_text()}"
        try:
            uses = int(uses)
        except (TypeError, ValueError):
            uses = 1
        if uses <= 0:
            return "usage: authcode <code> [identifier|*] [uses]"
        identifier = str(identifier or "").strip()
        target = "" if identifier in ("", "*", "any", "ANY") else self._auth_norm(identifier)
        now = time.time()
        entry = {
            "reason": reason,
            "code": code,
            "identifier": identifier if target else "*",
            "target": target,
            "remaining": max(1, min(100, uses)),
            "created_at": now,
            "expires_at": now + self._auth_force_reject_ttl(),
        }
        with self._auth_lock:
            self._auth_clear_expired_forced_rejects_locked(now)
            self._auth_forced_rejects.append(entry)
        scope = f"matching '{identifier}'" if target else "any next login"
        return f"queued auth{code} ({reason}) for {scope}, uses={entry['remaining']}"

    def _auth_pop_forced_reject(self, kv: dict, identifier: str) -> str:
        now = time.time()
        request_ids = self._auth_request_identities(kv, identifier)
        matched_reason = ""
        with self._auth_lock:
            kept: List[dict] = []
            for entry in self._auth_forced_rejects:
                if float(entry.get("expires_at", 0.0) or 0.0) <= now:
                    continue
                target = str(entry.get("target", "") or "")
                matches = not target or target in request_ids
                if matches and not matched_reason:
                    matched_reason = str(entry.get("reason", "") or "")
                    remaining = int(entry.get("remaining", 1) or 1) - 1
                    if remaining > 0:
                        updated = dict(entry)
                        updated["remaining"] = remaining
                        kept.append(updated)
                    continue
                kept.append(entry)
            self._auth_forced_rejects = kept
        return matched_reason

    def _format_auth_forced_rejects(self) -> str:
        now = time.time()
        with self._auth_lock:
            self._auth_clear_expired_forced_rejects_locked(now)
            entries = [dict(entry) for entry in self._auth_forced_rejects]
        if not entries:
            return "no pending authcode overrides"
        lines = ["Code Reason               Target           Uses Expires"]
        for entry in entries:
            remaining_s = max(0, int(float(entry.get("expires_at", now) or now) - now))
            lines.append(
                f"{str(entry.get('code', '-')):<4} "
                f"{str(entry.get('reason', '-')):<20.20} "
                f"{str(entry.get('identifier', '*')):<15.15} "
                f"{int(entry.get('remaining', 0) or 0):<4} "
                f"{remaining_s}s"
            )
        return "\n".join(lines)

    def _clear_auth_forced_rejects(self) -> str:
        with self._auth_lock:
            count = len(self._auth_forced_rejects)
            self._auth_forced_rejects.clear()
        return f"cleared {count} authcode override(s)"

    @staticmethod
    def _persona_code_alias(value: str) -> tuple[str, str]:
        return persona_policy.parse_code(value)

    @staticmethod
    def _persona_supported_codes_text() -> str:
        return persona_policy.supported_codes_text()

    def _persona_set_forced_reject(self, code_or_reason: str, persona: str = "", uses: int = 1) -> str:
        cmd, reason = self._persona_code_alias(code_or_reason)
        if not cmd or not reason:
            return f"unknown persona code '{code_or_reason}'. known: {self._persona_supported_codes_text()}"
        try:
            uses = int(uses)
        except (TypeError, ValueError):
            uses = 1
        if uses <= 0:
            return "usage: personacode <code> [persona|*] [uses]"
        persona = str(persona or "").strip()
        target = "" if persona in ("", "*", "any", "ANY") else self._auth_norm(persona)
        now = time.time()
        entry = {
            "cmd": cmd,
            "reason": reason,
            "code": f"{cmd}{reason}",
            "persona": persona if target else "*",
            "target": target,
            "remaining": max(1, min(100, uses)),
            "created_at": now,
            "expires_at": now + self._auth_force_reject_ttl(),
        }
        with self._auth_lock:
            self._persona_clear_expired_forced_rejects_locked(now)
            self._persona_forced_rejects.append(entry)
        stage_label = "create-persona/cper" if cmd == "cper" else "select-persona/pers"
        scope = f"matching '{persona}' on {stage_label}" if target else f"any next {stage_label} request"
        return f"queued {entry['code']} ({reason}) for {scope}, uses={entry['remaining']}"

    def persona_blacklist_reject_reason(self, persona: str, stage: str) -> str:
        reason, match_type, match_value = persona_policy.blacklist_reject(
            self.cfg,
            self._config_path,
            persona,
            stage,
            warn=log.warning,
        )
        if not reason:
            return ""
        log.warning(
            "Persona blacklist matched stage=%s persona=%r type=%s value=%r reject=%s",
            stage,
            persona,
            match_type,
            match_value,
            reason,
        )
        return reason

    def _persona_clear_expired_forced_rejects_locked(self, now: float) -> None:
        self._persona_forced_rejects = [
            entry for entry in self._persona_forced_rejects
            if float(entry.get("expires_at", 0.0) or 0.0) > now
        ]

    def pop_forced_persona_reject(self, cmd: str, persona: str) -> str:
        now = time.time()
        cmd = str(cmd or "").strip().lower()
        persona_key = self._auth_norm(persona)
        matched_reason = ""
        with self._auth_lock:
            kept: List[dict] = []
            for entry in self._persona_forced_rejects:
                if float(entry.get("expires_at", 0.0) or 0.0) <= now:
                    continue
                matches_cmd = str(entry.get("cmd", "") or "") == cmd
                target = str(entry.get("target", "") or "")
                matches_persona = not target or target == persona_key
                if matches_cmd and matches_persona and not matched_reason:
                    matched_reason = str(entry.get("reason", "") or "")
                    remaining = int(entry.get("remaining", 1) or 1) - 1
                    if remaining > 0:
                        updated = dict(entry)
                        updated["remaining"] = remaining
                        kept.append(updated)
                    continue
                kept.append(entry)
            self._persona_forced_rejects = kept
        return matched_reason

    def _format_persona_forced_rejects(self) -> str:
        now = time.time()
        with self._auth_lock:
            self._persona_clear_expired_forced_rejects_locked(now)
            entries = [dict(entry) for entry in self._persona_forced_rejects]
        if not entries:
            return "no pending personacode overrides"
        lines = ["Code     Persona         Uses Expires"]
        for entry in entries:
            remaining_s = max(0, int(float(entry.get("expires_at", now) or now) - now))
            lines.append(
                f"{str(entry.get('code', '-')):<8} "
                f"{str(entry.get('persona', '*')):<15.15} "
                f"{int(entry.get('remaining', 0) or 0):<4} "
                f"{remaining_s}s"
            )
        return "\n".join(lines)

    def _clear_persona_forced_rejects(self) -> str:
        with self._auth_lock:
            count = len(self._persona_forced_rejects)
            self._persona_forced_rejects.clear()
        return f"cleared {count} personacode override(s)"

    def _format_auth_reject_timing(self) -> str:
        repeat = self.cfg.get("AUTH_REJECT_REPEAT", 4)
        interval = self.cfg.get("AUTH_REJECT_INTERVAL", 0.25)
        close_delay = self.cfg.get("AUTH_REJECT_CLOSE_DELAY", 1.10)
        return f"authreject repeat={repeat} interval={interval} close_delay={close_delay}"

    def _set_auth_reject_timing(self, repeat, interval, close_delay) -> str:
        try:
            repeat_i = int(repeat)
            interval_f = float(interval)
            close_delay_f = float(close_delay)
        except (TypeError, ValueError):
            return "usage: authreject <repeat> <interval_sec> <close_delay_sec>"
        if repeat_i < 1 or repeat_i > 8:
            return "authreject repeat must be 1..8"
        if interval_f < 0.0 or interval_f > 2.0:
            return "authreject interval_sec must be 0..2"
        if close_delay_f < 0.2 or close_delay_f > 10.0:
            return "authreject close_delay_sec must be 0.2..10"
        self.cfg["AUTH_REJECT_REPEAT"] = repeat_i
        self.cfg["AUTH_REJECT_INTERVAL"] = interval_f
        self.cfg["AUTH_REJECT_CLOSE_DELAY"] = close_delay_f
        return self._format_auth_reject_timing()

    @staticmethod
    def _auth_pbkdf2_iterations() -> int:
        return 210_000

    @staticmethod
    def _auth_pbkdf2_encode(secret: str, *, iterations: int = 210_000, salt: bytes | None = None) -> str:
        secret_bytes = str(secret or "").encode("utf-8", errors="ignore")
        salt = os.urandom(16) if salt is None else salt
        digest = hashlib.pbkdf2_hmac("sha256", secret_bytes, salt, int(iterations))
        return "pbkdf2_sha256$%d$%s$%s" % (
            int(iterations),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        )

    @staticmethod
    def _auth_pbkdf2_verify(secret: str, encoded: str) -> bool:
        try:
            alg, iter_text, salt_text, digest_text = str(encoded or "").split("$", 3)
            if alg != "pbkdf2_sha256":
                return False
            iterations = int(iter_text)
            salt = base64.b64decode(salt_text.encode("ascii"), validate=True)
            expected = base64.b64decode(digest_text.encode("ascii"), validate=True)
            actual = hashlib.pbkdf2_hmac(
                "sha256",
                str(secret or "").encode("utf-8", errors="ignore"),
                salt,
                iterations,
            )
            return len(actual) == len(expected) and hmac.compare_digest(actual, expected)
        except Exception:
            return False

    @staticmethod
    def _auth_rol8(value: int, count: int) -> int:
        value &= 0xFF
        count &= 7
        return ((value << count) | (value >> (8 - count))) & 0xFF

    @staticmethod
    def _auth_ror8(value: int, count: int) -> int:
        value &= 0xFF
        count &= 7
        return ((value >> count) | (value << (8 - count))) & 0xFF

    @staticmethod
    def _auth_make_pass_token(password: str, mask: str) -> str:
        mask_bytes = str(mask or "0").encode("ascii", errors="ignore") or b"0"
        state = 0
        out = ["$"]
        for index, ch in enumerate(str(password or "").encode("latin-1", errors="ignore")):
            state = GameServer._auth_rol8(ch ^ state, 3) ^ mask_bytes[index % len(mask_bytes)]
            out.append(f"{state & 0xFF:02x}")
        return "".join(out)

    @staticmethod
    def _auth_decode_pass_token(token: str, mask: str) -> Optional[str]:
        token = str(token or "").strip()
        if not token.startswith("$") or len(token) < 3 or (len(token) - 1) % 2:
            return None
        hex_part = token[1:]
        try:
            values = [int(hex_part[index:index + 2], 16) for index in range(0, len(hex_part), 2)]
        except ValueError:
            return None
        mask_bytes = str(mask or "0").encode("ascii", errors="ignore") or b"0"
        state = 0
        out = bytearray()
        for index, encoded in enumerate(values):
            mask_byte = mask_bytes[index % len(mask_bytes)]
            ch = GameServer._auth_ror8(encoded ^ mask_byte, 3) ^ state
            out.append(ch & 0xFF)
            state = encoded & 0xFF
        return out.decode("latin-1", errors="ignore")

    @staticmethod
    def _auth_add_mask_candidate(masks: List[str], value: str) -> None:
        text = str(value or "").strip()
        if not text:
            return

        def add(candidate: str) -> None:
            candidate = str(candidate or "").strip()
            if candidate and candidate not in masks:
                masks.append(candidate)

        add(text)

        # Some clients send SKEY as "$" + hex("Public Key").  The password
        # codec needs the real key bytes too, not only the visible hex text.
        hex_text = text[1:] if text.startswith("$") else text
        if len(hex_text) >= 2 and len(hex_text) % 2 == 0:
            try:
                raw = bytes.fromhex(hex_text)
            except ValueError:
                raw = b""
            if raw:
                add(hex_text)
                try:
                    add(raw.decode("latin-1", errors="ignore"))
                except Exception:
                    pass

    @staticmethod
    def _auth_mask_candidates(kv: dict) -> List[str]:
        masks: List[str] = []
        for key in ("MASK", "SKEY", "AUTH_SKEY", "PSES", "SESS", "CHAL", "CHALLENGE"):
            value = GameServer._auth_kv_value(kv, key)
            GameServer._auth_add_mask_candidate(masks, value)
        return masks

    @staticmethod
    def _auth_password_hashes(account: dict) -> List[str]:
        hashes: List[str] = []
        for key in ("password_pbkdf2", "pass_pbkdf2", "pass_wire_pbkdf2", "password_hash", "pass_hash"):
            value = str(account.get(key, "") or "").strip()
            if value:
                hashes.append(value)
        for key in ("password_hashes", "pass_hashes", "pass_wire_hashes"):
            hashes.extend(GameServer._auth_list(account.get(key)))
        return hashes

    @staticmethod
    def _auth_plain_password_keys() -> tuple[str, ...]:
        return (
            "password",
            "pass",
            "pass_wire",
            "password_wire",
            "wire_password",
            "password_raw",
            "pass_raw",
        )

    @staticmethod
    def _auth_plain_password_list_keys() -> tuple[str, ...]:
        return ("passwords", "passes", "pass_wires", "password_wires")

    @staticmethod
    def _auth_account_identities(account: dict) -> Set[str]:
        identities: Set[str] = set()
        for key in ("__key", "email", "mail", "name", "username", "user", "login", "id"):
            value = GameServer._auth_norm(account.get(key, ""))
            if value:
                identities.add(value)
        for key in ("aliases", "emails", "names", "usernames", "logins"):
            for value in GameServer._auth_list(account.get(key)):
                norm = GameServer._auth_norm(value)
                if norm:
                    identities.add(norm)
        return identities

    def _auth_password_candidates(self, kv: dict, supplied: str) -> List[str]:
        candidates: List[str] = []
        supplied = str(supplied or "")
        if supplied:
            candidates.append(supplied)
        masks = self._auth_mask_candidates(kv)
        fixed_mask = str(self.cfg.get("BOOTSTRAP_DIR_MASK", "") or "").strip()
        if fixed_mask and fixed_mask not in masks:
            masks.append(fixed_mask)
        legacy_masks: List[str] = []
        for item in str(self.cfg.get("AUTH_LEGACY_MASKS", "") or "").replace(";", ",").split(","):
            legacy_mask = item.strip()
            if legacy_mask and legacy_mask not in legacy_masks:
                legacy_masks.append(legacy_mask)
        for mask in masks:
            decoded = self._auth_decode_pass_token(supplied, mask)
            if decoded and decoded not in candidates:
                candidates.append(decoded)
            if decoded:
                for legacy_mask in legacy_masks:
                    legacy_token = self._auth_make_pass_token(decoded, legacy_mask)
                    if legacy_token and legacy_token not in candidates:
                        candidates.append(legacy_token)
        return candidates

    @staticmethod
    def _auth_password_matches_candidate(account: dict, supplied: str) -> bool:
        if supplied is None:
            supplied = ""
        supplied = str(supplied)

        supplied_sha256 = hashlib.sha256(supplied.encode("utf-8", errors="ignore")).hexdigest()
        has_fast_hash = False
        for key in ("password_sha256", "pass_sha256", "pass_wire_sha256"):
            expected = str(account.get(key, "") or "").strip().lower()
            if expected:
                has_fast_hash = True
                if expected == supplied_sha256:
                    return True
        for key in ("password_sha256s", "pass_sha256s", "pass_wire_sha256s"):
            values = GameServer._auth_list(account.get(key))
            if values:
                has_fast_hash = True
            for expected in values:
                if str(expected or "").strip().lower() == supplied_sha256:
                    return True

        for key in GameServer._auth_plain_password_keys():
            expected = account.get(key)
            if expected is not None and str(expected) == supplied:
                return True
        for key in GameServer._auth_plain_password_list_keys():
            for expected in GameServer._auth_list(account.get(key)):
                if expected == supplied:
                    return True

        supplied_md5 = hashlib.md5(supplied.encode("utf-8", errors="ignore")).hexdigest()
        for key in ("password_md5", "pass_md5", "pass_wire_md5"):
            expected = str(account.get(key, "") or "").strip().lower()
            if expected and expected == supplied_md5:
                return True

        # If a fast hash list exists, do not burn CPU on PBKDF2 for every wrong
        # candidate.  The caller will try the next candidate immediately.  This
        # fixes the 30-50 second reconnect delay on Termux accounts that contain
        # many pass_wire_hashes.
        if has_fast_hash:
            return False

        for encoded in GameServer._auth_password_hashes(account):
            if GameServer._auth_pbkdf2_verify(supplied, encoded):
                return True
        return False

    def _auth_password_matches(self, account: dict, kv: dict, supplied: str) -> bool:
        for candidate in self._auth_password_candidates(kv, supplied):
            if self._auth_password_matches_candidate(account, candidate):
                return True
        return False

    @staticmethod
    def _auth_password_fingerprints(account: dict, supplied: str) -> tuple[str, List[str]]:
        def fp(value: str) -> str:
            text = str(value or "")
            digest = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:12]
            return f"len={len(text)} sha256={digest}"

        supplied_fp = fp(supplied)
        expected: List[str] = []
        for encoded in GameServer._auth_password_hashes(account):
            parts = str(encoded).split("$", 3)
            if len(parts) >= 2 and parts[0] == "pbkdf2_sha256":
                expected.append(f"pbkdf2_sha256:iter={parts[1]}")
            else:
                expected.append("hash:unknown")
        for key in GameServer._auth_plain_password_keys():
            value = account.get(key)
            if value is not None:
                expected.append(f"{key}:{fp(str(value))}")
        for key in GameServer._auth_plain_password_list_keys():
            for value in GameServer._auth_list(account.get(key)):
                expected.append(f"{key}:{fp(value)}")
        for key in ("password_sha256", "pass_sha256", "pass_wire_sha256"):
            value = str(account.get(key, "") or "").strip().lower()
            if value:
                expected.append(f"{key}:sha256={value[:12]}")
        for key in ("password_md5", "pass_md5", "pass_wire_md5"):
            value = str(account.get(key, "") or "").strip().lower()
            if value:
                expected.append(f"{key}:md5={value[:12]}")
        return supplied_fp, expected

    @staticmethod
    def _auth_extract_accounts(data) -> List[dict]:
        if isinstance(data, list):
            return [dict(item) for item in data if isinstance(item, dict)]
        if not isinstance(data, dict):
            return []
        for key in ("users", "accounts"):
            value = data.get(key)
            if isinstance(value, list):
                return [dict(item) for item in value if isinstance(item, dict)]
            if isinstance(value, dict):
                out = []
                for account_key, account_value in value.items():
                    if isinstance(account_value, dict):
                        item = dict(account_value)
                    else:
                        item = {"password": str(account_value)}
                    item.setdefault("__key", str(account_key))
                    out.append(item)
                return out
        out = []
        for account_key, account_value in data.items():
            if isinstance(account_value, dict):
                item = dict(account_value)
                item.setdefault("__key", str(account_key))
                out.append(item)
        return out

    def _auth_secure_account(self, account: dict) -> tuple[dict, bool]:
        if not isinstance(account, dict):
            return {}, False
        secured = dict(account)
        changed = False
        hashes = list(self._auth_password_hashes(secured))

        for key in self._auth_plain_password_keys():
            value = secured.pop(key, None)
            if value is None:
                continue
            text = str(value)
            if text:
                hashes.append(self._auth_pbkdf2_encode(text, iterations=self._auth_pbkdf2_iterations()))
            changed = True

        for key in self._auth_plain_password_list_keys():
            values = self._auth_list(secured.pop(key, None))
            if values:
                for text in values:
                    hashes.append(self._auth_pbkdf2_encode(text, iterations=self._auth_pbkdf2_iterations()))
                changed = True

        if hashes:
            deduped: List[str] = []
            seen = set()
            for item in hashes:
                text = str(item or "").strip()
                if text and text not in seen:
                    seen.add(text)
                    deduped.append(text)
            if len(deduped) == 1:
                if secured.get("pass_wire_pbkdf2") != deduped[0]:
                    secured["pass_wire_pbkdf2"] = deduped[0]
                    changed = True
                secured.pop("pass_wire_hashes", None)
            else:
                if secured.get("pass_wire_hashes") != deduped:
                    secured["pass_wire_hashes"] = deduped
                    changed = True
                secured.pop("pass_wire_pbkdf2", None)
        return secured, changed

    def _auth_secure_accounts(self, accounts: List[dict]) -> tuple[List[dict], bool]:
        if not self.auth_migrate_plaintext_enabled():
            return accounts, False
        secured_accounts: List[dict] = []
        changed = False
        for account in accounts:
            secured, item_changed = self._auth_secure_account(account)
            secured_accounts.append(secured)
            changed = changed or item_changed
        return secured_accounts, changed

    def _load_auth_accounts(self) -> List[dict]:
        path = self._auth_accounts_file()
        with self._auth_accounts_lock:
            if not os.path.exists(path):
                self._auth_accounts_path = path
                self._auth_accounts_mtime = -1.0
                self._auth_accounts_cache = []
                return []
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                self._auth_accounts_cache = []
                return []
            if path == self._auth_accounts_path and mtime == self._auth_accounts_mtime:
                return self._auth_accounts_cache
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                accounts = self._auth_extract_accounts(data)
            except Exception as exc:
                log.warning("Failed to load auth accounts from '%s': %s", path, exc)
                accounts = []
            accounts, migrated = self._auth_secure_accounts(accounts)
            self._auth_accounts_path = path
            self._auth_accounts_mtime = mtime
            self._auth_accounts_cache = accounts
            log.info("Loaded auth accounts from '%s' (accounts=%d)", path, len(accounts))
            if migrated:
                log.info("Migrating auth accounts to hashed password storage.")
                self._save_auth_accounts(accounts)
            return self._auth_accounts_cache

    def _save_auth_accounts(self, accounts: List[dict]) -> bool:
        path = self._auth_accounts_file()
        tmp_path = path + ".tmp"
        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            payload = {"users": [dict(account) for account in accounts if isinstance(account, dict)]}
            with self._auth_accounts_lock:
                with open(tmp_path, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, indent=2, sort_keys=True)
                    fh.write("\n")
                os.replace(tmp_path, path)
                try:
                    self._auth_accounts_mtime = os.path.getmtime(path)
                except OSError:
                    self._auth_accounts_mtime = -1.0
                self._auth_accounts_path = path
                self._auth_accounts_cache = payload["users"]
            log.info("Saved auth accounts to '%s' (accounts=%d)", path, len(accounts))
            return True
        except Exception as exc:
            log.warning("Failed to save auth accounts to '%s': %s", path, exc)
            return False

    def _append_auth_capture(self, kv: dict, identifier: str, password: str) -> None:
        path = self._auth_capture_file()
        fields = {str(k).strip().upper(): str(v).strip() for k, v in (kv or {}).items()}
        for key in ("PASSWORD", "PASS", "PWORD", "PWD"):
            if key in fields:
                fields[key] = "<redacted>"
        pass_bytes = str(password or "").encode("utf-8", errors="ignore")
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "identifier": identifier,
            "pass_len": len(str(password or "")),
            "pass_sha256": hashlib.sha256(pass_bytes).hexdigest(),
            "pses": self._auth_kv_value(kv, "PSES"),
            "keys": sorted(fields.keys()),
            "fields": fields,
        }
        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True) + "\n")
        except Exception as exc:
            log.warning("Failed to append auth capture to '%s': %s", path, exc)

    def _auth_build_account(self, kv: dict, identifier: str, password: str) -> dict:
        name = self._auth_kv_value(kv, "NAME", "USER", "USERNAME", "LOGIN") or identifier
        email = self._auth_kv_value(kv, "EMAIL", "MAIL", "PMAIL", "U2_OLX_MAIL")
        persona = self._auth_kv_value(kv, "PERS", "PERSO", "PERSONA") or name
        aliases: Set[str] = set()
        for value in (
            identifier,
            email,
            name,
            self._auth_kv_value(kv, "USER", "USERNAME", "LOGIN"),
        ):
            value = str(value or "").strip()
            if value:
                aliases.add(value)

        account = {
            "name": name,
            "aliases": sorted(aliases, key=lambda item: item.lower()),
            "personas": [persona],
            "display_name": name,
            "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if password:
            # Store every plausible stable form we can derive from the create-account
            # packet.  U2 can send the password as a session/key encoded token; if we
            # pick the wrong decoded form here, the account works only in the creation
            # session and then fails with bad_password.  Verification already tries all
            # candidates, so saving all candidate hashes is safer for this protocol.
            candidates = []
            seen_candidates = set()
            for candidate in self._auth_password_candidates(kv, password):
                candidate = str(candidate or "")
                if candidate and candidate not in seen_candidates:
                    seen_candidates.add(candidate)
                    candidates.append(candidate)
            if candidates:
                # Store only fast wire hashes.  PBKDF2/large pass_wire_hashes made
                # auth_accounts.json huge and caused slow reconnects when many
                # wire-token candidates existed.
                sha256s = [
                    hashlib.sha256(candidate.encode("utf-8", errors="ignore")).hexdigest()
                    for candidate in candidates
                ]
                account["pass_wire_sha256s"] = sha256s
        if email:
            account["email"] = email
        return account

    def _auth_enroll_account(self, accounts: List[dict], kv: dict, identifier: str, password: str) -> Optional[dict]:
        account = self._auth_build_account(kv, identifier, password)
        if not self._save_auth_accounts([*accounts, account]):
            return None
        return account

    def create_account(self, kv: dict) -> Tuple[bool, str, dict, str]:
        identifier = self._auth_kv_value(
            kv,
            "NAME",
            "USER",
            "USERNAME",
            "LOGIN",
            "EMAIL",
            "MAIL",
            "PMAIL",
            "U2_OLX_MAIL",
        )
        password = self._auth_kv_value(kv, "PASSWORD", "PASS", "PWORD", "PWD")
        if not self.auth_allow_create_enabled():
            return False, "create_disabled", {}, identifier
        if not identifier:
            return False, "missing_identifier", {}, ""
        if not password:
            return False, "missing_password", {}, identifier

        accounts = self._load_auth_accounts()
        new_account = self._auth_build_account(kv, identifier, password)
        new_identities = self._auth_account_identities(new_account)
        for account in accounts:
            if new_identities.intersection(self._auth_account_identities(account)):
                return False, "account_exists", dict(account), identifier

        account = self._auth_enroll_account(accounts, kv, identifier, password)
        if not account:
            return False, "save_failed", {}, identifier
        return True, "created", dict(account), identifier

    def _auth_rate_window(self) -> float:
        try:
            return max(1.0, float(self.cfg.get("AUTH_FAIL_WINDOW", 60) or 60))
        except Exception:
            return 60.0

    def _auth_fail_limit(self) -> int:
        try:
            return max(1, int(self.cfg.get("AUTH_FAIL_LIMIT", 5) or 5))
        except Exception:
            return 5

    def _auth_lockout_seconds(self) -> float:
        try:
            return max(1.0, float(self.cfg.get("AUTH_LOCKOUT_SECONDS", 120) or 120))
        except Exception:
            return 120.0

    def _auth_rate_key(self, identifier: str) -> str:
        return self._auth_norm(identifier) or "-"

    def _auth_is_rate_limited(self, identifier: str) -> bool:
        key = self._auth_rate_key(identifier)
        now = time.time()
        window = max(self._auth_rate_window(), self._auth_lockout_seconds())
        with self._auth_lock:
            failures = [
                ts for ts in self._auth_failures.get(key, [])
                if (now - float(ts)) <= window
            ]
            self._auth_failures[key] = failures
            if len(failures) < self._auth_fail_limit():
                return False
            newest = max(failures) if failures else 0.0
            return (now - newest) <= self._auth_lockout_seconds()

    def _auth_note_failure(self, identifier: str) -> None:
        key = self._auth_rate_key(identifier)
        now = time.time()
        window = max(self._auth_rate_window(), self._auth_lockout_seconds())
        with self._auth_lock:
            failures = [
                ts for ts in self._auth_failures.get(key, [])
                if (now - float(ts)) <= window
            ]
            failures.append(now)
            self._auth_failures[key] = failures[-max(self._auth_fail_limit() * 2, 16):]

    def _auth_note_success(self, identifier: str) -> None:
        key = self._auth_rate_key(identifier)
        with self._auth_lock:
            self._auth_failures.pop(key, None)

    def authenticate_login(self, kv: dict) -> Tuple[bool, str, dict, str]:
        identifier = self._auth_kv_value(
            kv,
            "EMAIL",
            "MAIL",
            "PMAIL",
            "U2_OLX_MAIL",
            "USER",
            "USERNAME",
            "LOGIN",
            "NAME",
        )
        password = self._auth_kv_value(kv, "PASSWORD", "PASS", "PWORD", "PWD")
        mode = self.auth_mode()
        if self.auth_capture_enabled():
            safe_keys = ",".join(sorted(str(key).strip().upper() for key in kv.keys()))
            pses = self._auth_kv_value(kv, "PSES")
            pass_digest = hashlib.sha256(password.encode("utf-8", errors="ignore")).hexdigest()[:12]
            log.warning(
                "auth capture id=%r pass_len=%d pass_sha256=%s pses=%r keys=%s",
                identifier,
                len(password),
                pass_digest,
                pses,
                safe_keys or "-",
            )
            self._append_auth_capture(kv, identifier, password)

        forced_reason = self._auth_pop_forced_reject(kv, identifier)
        if forced_reason:
            log.warning("auth forced reject id=%r reason=%s", identifier, forced_reason)
            return False, forced_reason, {}, identifier

        if not self.auth_verify_enabled():
            return True, "disabled", {}, identifier

        missing_fields = self._auth_missing_required_fields(kv)
        if missing_fields:
            log.warning("auth missing required fields id=%r fields=%s", identifier, ",".join(missing_fields))
            return False, "missing_fields", {}, identifier
        if self._cfg_flag("AUTH_REQUIRE_TOS") and not self._auth_bool(
            self._auth_kv_value(kv, "TOS", "TERMS", "TERMS_ACCEPTED"),
            False,
        ):
            return False, "tos_not_accepted", {}, identifier
        if self._cfg_flag("AUTH_REQUIRE_SHARE") and not self._auth_bool(
            self._auth_kv_value(kv, "SHARE", "SHARE_ACCEPTED"),
            False,
        ):
            return False, "share_not_accepted", {}, identifier

        if not identifier:
            return False, "missing_identifier", {}, ""
        if self._auth_is_rate_limited(identifier):
            log.warning("auth rate limited id=%r", identifier)
            return False, "rate_limited", {}, identifier
        if mode != "account" and not password:
            return False, "missing_password", {}, identifier

        accounts = self._load_auth_accounts()
        if not accounts:
            if self.auth_auto_enroll_enabled():
                account = self._auth_enroll_account(accounts, kv, identifier, password)
                if account:
                    return True, "enrolled", dict(account), identifier
            return False, "no_accounts", {}, identifier

        ident_norm = self._auth_norm(identifier)
        for account in accounts:
            identities = self._auth_account_identities(account)
            if ident_norm not in identities:
                continue
            reject_reason = self._auth_account_reject_reason(account)
            if reject_reason:
                self._auth_note_failure(identifier)
                return False, reject_reason, {}, identifier
            reject_reason = self._auth_account_key_reject_reason(account, kv)
            if reject_reason:
                self._auth_note_failure(identifier)
                return False, reject_reason, {}, identifier
            if mode == "account":
                self._auth_note_success(identifier)
                return True, "ok", dict(account), identifier
            if self._auth_password_matches(account, kv, password):
                self._auth_note_success(identifier)
                return True, "ok", dict(account), identifier
            supplied_fp, expected_fps = self._auth_password_fingerprints(account, password)
            log.warning(
                "auth password mismatch id=%r supplied=%s expected=%s",
                identifier,
                supplied_fp,
                ";".join(expected_fps) or "-",
            )
            self._auth_note_failure(identifier)
            return False, "bad_password", {}, identifier
        if self.auth_auto_enroll_enabled():
            account = self._auth_enroll_account(accounts, kv, identifier, password)
            if account:
                self._auth_note_success(identifier)
                return True, "enrolled", dict(account), identifier
        self._auth_note_failure(identifier)
        return False, "unknown_account", {}, identifier

    def _csv_ports(self, *keys: str) -> List[int]:
        ports: List[int] = []
        seen: Set[int] = set()
        for key in keys:
            raw = str(self.cfg.get(key, "") or "").strip()
            if not raw:
                continue
            for part in raw.replace(";", ",").split(","):
                try:
                    port = int(part.strip() or "0", 10)
                except ValueError:
                    continue
                if port > 0 and port not in seen:
                    seen.add(port)
                    ports.append(port)
        return ports

    def _race_listen_ports(self) -> List[int]:
        primary = self._listen_port("race")
        ports: List[int] = []
        for port in [primary, *self._csv_ports("SAME_PC_RLYPORTS", "SAME_PC_RELAY_PORTS", "SAME_HOST_RLYPORTS")]:
            if port > 0 and port not in ports:
                ports.append(port)
        return ports

    def _extra_lobby_listen_ports(self, *exclude_ports: int) -> List[int]:
        excluded = {int(port) for port in exclude_ports if int(port or 0) > 0}
        ports: List[int] = []
        for port in self._csv_ports("LOBBY_EXTRA_LISTEN_PORTS"):
            if port > 0 and port not in excluded and port not in ports:
                ports.append(port)
        return ports

    @staticmethod
    def _peer_ip_for_conn(conn: Optional[socket.socket]) -> str:
        if conn is None:
            return ""
        try:
            return str(conn.getpeername()[0] or "").strip()
        except Exception:
            return ""

    def _peer_ip_for_uid(self, uid: int = 0, conn: Optional[socket.socket] = None) -> str:
        ip = self._peer_ip_for_conn(conn)
        if ip:
            return ip
        if uid > 0:
            user = self.users.get(int(uid))
            if user is not None:
                ip = self._peer_ip_for_conn(getattr(user, "conn", None))
                if not ip:
                    ip = str(getattr(user, "ip", "") or "").strip()
        return ip

    def _same_pc_endpoint_for(self, *, conn: Optional[socket.socket] = None, uid: int = 0) -> Optional[Tuple[str, int]]:
        ports = self._csv_ports("SAME_PC_RLYPORTS", "SAME_PC_RELAY_PORTS", "SAME_HOST_RLYPORTS")
        if len(ports) < 2:
            return None
        target_ip = self._peer_ip_for_uid(uid=uid, conn=conn)
        if not target_ip:
            return None
        peers = []
        for user in self.users.all_users():
            if not getattr(user, "connected", False):
                continue
            user_ip = self._peer_ip_for_uid(uid=int(getattr(user, "uid", 0) or 0))
            if user_ip == target_ip:
                peers.append(user)
        if len(peers) < 2:
            return None
        peers.sort(key=lambda user: int(getattr(user, "uid", 0) or 0))
        target_uid = int(uid or 0)
        if target_uid <= 0 and conn is not None:
            for user in peers:
                if getattr(user, "conn", None) is conn:
                    target_uid = int(getattr(user, "uid", 0) or 0)
                    break
        if target_uid <= 0:
            target_uid = int(getattr(peers[0], "uid", 0) or 0)
        index = 0
        for i, user in enumerate(peers):
            if int(getattr(user, "uid", 0) or 0) == target_uid:
                index = i
                break
        port = ports[min(index, len(ports) - 1)]
        host = self.advertised_game_host(conn=conn) or self.advertised_host(conn=conn)
        if host and port > 0:
            return host, int(port)
        return None

    def _udp_relay_sock_for_port(self, listen_port: int) -> Optional[socket.socket]:
        if listen_port > 0:
            sock = self._game_relay_sock_by_port.get(int(listen_port))
            if sock is not None:
                return sock
        return self._game_relay_sock

    def _udp_relay_sock_for_addr(self, addr: Addr) -> Optional[socket.socket]:
        state = self._udp_relay_clients.get(addr)
        listen_port = int(getattr(state, "relay_listen_port", 0) or 0) if state is not None else 0
        return self._udp_relay_sock_for_port(listen_port)

    def _runtime_local_host(self, conn: Optional[socket.socket] = None) -> str:
        host = self._cfg_host_value(self.cfg.get("HOST", "127.0.0.1"))
        if host in ("", "0.0.0.0", "::") and conn is not None:
            try:
                host = self._cfg_host_value(conn.getsockname()[0])
            except Exception:
                host = "127.0.0.1"
        if host in ("", "0.0.0.0", "::"):
            host = "127.0.0.1"
        return host

    def _listen_host(self, service: str, *, conn: Optional[socket.socket] = None) -> str:
        service = service.lower()
        if service == "lobby":
            host = self._first_host("LOBBY_LISTEN_HOST", "LOBBY_LISTEN", "LOBBY_PUBLIC_HOST", "LOBBY_ENDPOINT")
            if host:
                return host
            return self._cfg_host_value(self.cfg.get("HOST", "0.0.0.0")) or "0.0.0.0"
        if service == "control":
            host = self._first_host("CONTROL_LISTEN_HOST", "CONTROL_LISTEN", "CONTROL_PUBLIC_HOST", "CONTROL_ENDPOINT", "LOBBY_LISTEN_HOST", "LOBBY_LISTEN", "LOBBY_PUBLIC_HOST", "LOBBY_ENDPOINT")
            if host:
                return host
            return self._listen_host("lobby", conn=conn)
        if service == "control_alias":
            host = self._first_host("CONTROL_ALIAS_LISTEN_HOST", "CONTROL_ALIAS_LISTEN", "CONTROL_ALIAS_PUBLIC_HOST", "CONTROL_ALIAS_ENDPOINT", "CONTROL_LISTEN_HOST", "CONTROL_LISTEN", "CONTROL_PUBLIC_HOST", "CONTROL_ENDPOINT")
            if host:
                return host
            return self._listen_host("control", conn=conn)
        if service == "race":
            host = self._first_host("RACE_LISTEN_HOST", "RACE_LISTEN", "RACE_PUBLIC_HOST", "RACE_ENDPOINT")
            if host:
                return host
            return self._cfg_host_value(self.cfg.get("HOST", "0.0.0.0")) or "0.0.0.0"
        raise ValueError(f"Unknown listen service: {service}")

    def _public_host(self, service: str, *, conn: Optional[socket.socket] = None) -> str:
        service = service.lower()
        if service == "lobby":
            host = self._first_host("LOBBY_PUBLIC_HOST", "LOBBY_ENDPOINT", "LOBBY_LISTEN_HOST", "LOBBY_LISTEN", "LOBBY_TCP_HOST", "ADVERTISED_HOST")
            if host:
                return host
            return self._runtime_local_host(conn)
        if service == "control":
            host = self._first_host("CONTROL_PUBLIC_HOST", "CONTROL_ENDPOINT", "CONTROL_LISTEN_HOST", "CONTROL_LISTEN", "LOBBY_NEWS_HOST")
            if host:
                return host
            return self._public_host("lobby", conn=conn)
        if service == "control_alias":
            host = self._first_host("CONTROL_ALIAS_PUBLIC_HOST", "CONTROL_ALIAS_ENDPOINT", "CONTROL_ALIAS_LISTEN_HOST", "CONTROL_ALIAS_LISTEN")
            if host:
                return host
            return self._public_host("control", conn=conn)
        if service == "race":
            host = self._first_host("RACE_PUBLIC_HOST", "RACE_ENDPOINT", "RACE_LISTEN_HOST", "RACE_LISTEN", "RACE_UDP_HOST", "ADVERTISED_GAME_HOST")
            if host:
                return host
            return self._public_host("lobby", conn=conn)
        raise ValueError(f"Unknown public service: {service}")

    def _listen_port(self, service: str) -> int:
        service = service.lower()
        if service == "lobby":
            port = self._first_port("LOBBY_LISTEN_PORT", "LOBBY_LISTEN", "LOBBY_PUBLIC_PORT", "LOBBY_ENDPOINT", "PORT")
            return port if port > 0 else 9900
        if service == "control":
            port = self._first_port("CONTROL_LISTEN_PORT", "CONTROL_LISTEN", "CONTROL_PUBLIC_PORT", "CONTROL_ENDPOINT", "CONTROL_PORT")
            return port if port > 0 else 20923
        if service == "control_alias":
            port = self._first_port("CONTROL_ALIAS_LISTEN_PORT", "CONTROL_ALIAS_LISTEN", "CONTROL_ALIAS_PUBLIC_PORT", "CONTROL_ALIAS_ENDPOINT", "CONTROL_ALIAS_PORT")
            return port if port > 0 else 13505
        if service == "race":
            port = self._first_port(
                "RACE_LISTEN_PORT",
                "RACE_LISTEN",
                "RACE_PUBLIC_PORT",
                "RACE_ENDPOINT",
                "GAME_RELAY_PORT",
                "RACE_UDP_PORT",
                "ADVERTISED_GAME_PORT",
            )
            return port if port > 0 else 20000
        raise ValueError(f"Unknown listen service: {service}")

    def _public_port(self, service: str) -> int:
        service = service.lower()
        if service == "lobby":
            port = self._first_port("LOBBY_PUBLIC_PORT", "LOBBY_ENDPOINT", "LOBBY_LISTEN_PORT", "LOBBY_LISTEN", "LOBBY_TCP_PORT", "ADVERTISED_PORT", "PORT")
            return port if port > 0 else 9900
        if service == "control":
            port = self._first_port("CONTROL_PUBLIC_PORT", "CONTROL_ENDPOINT", "CONTROL_LISTEN_PORT", "CONTROL_LISTEN", "CONTROL_PORT")
            return port if port > 0 else 20923
        if service == "control_alias":
            port = self._first_port("CONTROL_ALIAS_PUBLIC_PORT", "CONTROL_ALIAS_ENDPOINT", "CONTROL_ALIAS_LISTEN_PORT", "CONTROL_ALIAS_LISTEN", "CONTROL_ALIAS_PORT")
            return port if port > 0 else 13505
        if service == "race":
            port = self._first_port("RACE_PUBLIC_PORT", "RACE_ENDPOINT", "RACE_LISTEN_PORT", "RACE_LISTEN", "RACE_UDP_PORT", "ADVERTISED_GAME_PORT", "GAME_RELAY_PORT")
            return port if port > 0 else 20000
        raise ValueError(f"Unknown public service: {service}")

    def configured_lobby_public_host(self) -> str:
        return self._first_host("LOBBY_PUBLIC_HOST", "LOBBY_TCP_HOST", "ADVERTISED_HOST")

    def has_explicit_lobby_public_host(self) -> bool:
        return bool(self.configured_lobby_public_host())

    # ------------------------------------------------------------------ #
    # StartServer equivalent                                               #
    # ------------------------------------------------------------------ #

    def start(self) -> bool:
        if self.is_running:
            log.warning("StartServer called while already running.")
            return False

        log.info("Master server startup")

        lobby_listen_host = self._listen_host("lobby")
        lobby_listen_port = self._listen_port("lobby")
        control_listen_host = self._listen_host("control")
        control_port = self._listen_port("control")
        control_alias_listen_host = self._listen_host("control_alias")
        control_alias_port = self._listen_port("control_alias")
        legacy_lobby_host = self._first_host("LOBBY_LEGACY_LISTEN_HOST", "BOOTSTRAP_LISTEN", "BOOTSTRAP_ENDPOINT", "LOBBY_LISTEN_HOST", "LOBBY_LISTEN", "LOBBY_PUBLIC_HOST", "LOBBY_ENDPOINT") or lobby_listen_host
        legacy_lobby_port = self._first_port("LOBBY_LEGACY_LISTEN_PORT", "BOOTSTRAP_LISTEN", "BOOTSTRAP_ENDPOINT")
        race_listen_host = self._listen_host("race")
        game_relay_port = self._listen_port("race")
        self.host = lobby_listen_host
        self.udp_relay_port = game_relay_port

        # Create listening socket
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((lobby_listen_host, lobby_listen_port))
            self._sock.listen(128)
            self._sock.settimeout(1.0)
            log.info("Master server is setup (listening on %s:%d, public %s:%d)", lobby_listen_host, lobby_listen_port, self.lobby_tcp_host(), self.lobby_tcp_port())
        except OSError as e:
            log.error("Lobby TCP listener (%s) or port (%d) incorrect: %s", lobby_listen_host, lobby_listen_port, e)
            return False

        # Set global handle (mirrors DLL g_serverHandle)
        self._handle  = self._sock
        self.is_running = True

        try:
            self.messenger.start(
                control_host=control_listen_host,
                control_port=control_port,
                alias_host=control_alias_listen_host,
                alias_port=control_alias_port,
            )
        except OSError as e:
            log.error("%s", e)
            self.is_running = False
            self._handle = None
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None
            return False

        if legacy_lobby_port > 0 and legacy_lobby_port != lobby_listen_port:
            try:
                self._legacy_lobby_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._legacy_lobby_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._legacy_lobby_sock.bind((legacy_lobby_host, legacy_lobby_port))
                self._legacy_lobby_sock.listen(128)
                self._legacy_lobby_sock.settimeout(1.0)
                log.info("Legacy lobby TCP is setup (listening on %s:%d)", legacy_lobby_host, legacy_lobby_port)
            except OSError as e:
                log.error("Legacy lobby port (%d) incorrect: %s", legacy_lobby_port, e)
                self.is_running = False
                self._handle = None
                self.messenger.stop()
                for sock_name in ("_sock", "_legacy_lobby_sock"):
                    sock = getattr(self, sock_name)
                    if sock:
                        try:
                            sock.close()
                        except Exception:
                            pass
                        setattr(self, sock_name, None)
                return False

        extra_lobby_ports = self._extra_lobby_listen_ports(lobby_listen_port, legacy_lobby_port)
        if extra_lobby_ports:
            self._extra_lobby_socks = []
            try:
                for extra_port in extra_lobby_ports:
                    extra_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    extra_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    extra_sock.bind((lobby_listen_host, extra_port))
                    extra_sock.listen(128)
                    extra_sock.settimeout(1.0)
                    self._extra_lobby_socks.append(extra_sock)
                    log.info("Extra lobby TCP is setup (listening on %s:%d)", lobby_listen_host, extra_port)
            except OSError as e:
                log.error("Extra lobby port (%d) incorrect: %s", extra_port, e)
                self.is_running = False
                self._handle = None
                self.messenger.stop()
                for sock in [self._sock, self._legacy_lobby_sock, *self._extra_lobby_socks]:
                    if sock:
                        try:
                            sock.close()
                        except Exception:
                            pass
                self._sock = None
                self._legacy_lobby_sock = None
                self._extra_lobby_socks = []
                return False

        relay_ports = self._race_listen_ports()
        if relay_ports:
            self._game_relay_socks = []
            self._game_relay_sock_by_port = {}
            try:
                for idx, relay_port in enumerate(relay_ports):
                    relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    relay_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    relay_sock.bind((race_listen_host, relay_port))
                    relay_sock.settimeout(1.0)
                    self._game_relay_socks.append(relay_sock)
                    self._game_relay_sock_by_port[int(relay_port)] = relay_sock
                    if idx == 0:
                        self._game_relay_sock = relay_sock
                    log.info(
                        "Game relay UDP is setup (listening on %s:%d, advertised as %s:%d)",
                        race_listen_host,
                        relay_port,
                        self.advertised_game_host() or self.advertised_host(),
                        relay_port if relay_port != relay_ports[0] else self.advertised_game_port(fallback=relay_ports[0]),
                    )
            except OSError as e:
                log.error("Game relay UDP port (%d) incorrect: %s", relay_port, e)
                self.is_running = False
                self._handle = None
                if self._sock:
                    try:
                        self._sock.close()
                    except Exception:
                        pass
                    self._sock = None
                self.messenger.stop()
                if self._legacy_lobby_sock:
                    try:
                        self._legacy_lobby_sock.close()
                    except Exception:
                        pass
                    self._legacy_lobby_sock = None
                for extra_sock in list(self._extra_lobby_socks):
                    try:
                        extra_sock.close()
                    except Exception:
                        pass
                self._extra_lobby_socks = []
                for relay_sock in list(self._game_relay_socks):
                    try:
                        relay_sock.close()
                    except Exception:
                        pass
                self._game_relay_socks = []
                self._game_relay_sock_by_port = {}
                self._game_relay_sock = None
                return False

        # Start subsystems
        self.play.create()
        self.batch.start()

        # Master server (if configured)
        if self.cfg.get("MASTER", ""):
            self.master = MasterServer(self.cfg, self._get_state)
            self.master.start()

        # Slave client (if MASTER_HOST configured)
        if self.cfg.get("MASTER_HOST", ""):
            self.slave = SlaveClient(self.cfg, self._on_master_update)
            self.slave.start()

        # Accept loop thread
        self._thread = threading.Thread(target=self._accept_loop,
                                        name="AcceptLoop", daemon=True)
        self._thread.start()

        self.messenger.start_threads()
        if self._legacy_lobby_sock:
            self._legacy_lobby_thread = threading.Thread(
                target=self._accept_loop_on_socket,
                args=(self._legacy_lobby_sock, "LegacyClient"),
                name="LegacyLobbyAcceptLoop",
                daemon=True,
            )
            self._legacy_lobby_thread.start()
        self._extra_lobby_threads = []
        for idx, extra_sock in enumerate(self._extra_lobby_socks):
            thread = threading.Thread(
                target=self._accept_loop_on_socket,
                args=(extra_sock, "ExtraLobbyClient"),
                name=f"ExtraLobbyAcceptLoop-{idx}",
                daemon=True,
            )
            thread.start()
            self._extra_lobby_threads.append(thread)
        if self._game_relay_sock:
            self._game_relay_thread = threading.Thread(
                target=self._game_relay_loop,
                name="GameRelayUDP",
                daemon=True,
            )
            self._game_relay_thread.start()
        # Periodic maintenance thread
        self._timer = threading.Thread(target=self._periodic,
                                       name="Periodic", daemon=True)
        self._timer.start()

        return True

    # ------------------------------------------------------------------ #
    # StopServer equivalent                                               #
    # ------------------------------------------------------------------ #

    def stop(self):
        if not self.is_running:
            return
        log.info("Master server shutdown")

        self.is_running = False
        self._handle    = None
        self._admin_stop.set()

        # Stop subsystems
        self.play.destroy()
        self.batch.stop()
        if self.master:
            self.master.stop()
        if self.slave:
            self.slave.stop()

        # Close listener
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self.messenger.stop()
        if self._legacy_lobby_sock:
            try:
                self._legacy_lobby_sock.close()
            except Exception:
                pass
            self._legacy_lobby_sock = None
        for extra_sock in list(self._extra_lobby_socks):
            try:
                extra_sock.close()
            except Exception:
                pass
        self._extra_lobby_socks = []
        for relay_sock in list(self._game_relay_socks or ([] if self._game_relay_sock is None else [self._game_relay_sock])):
            try:
                relay_sock.close()
            except Exception:
                pass
        self._game_relay_socks = []
        self._game_relay_sock_by_port = {}
        self._game_relay_sock = None
        # Wait for threads
        if self._thread:
            self._thread.join(timeout=3)
        self.messenger.join(timeout=3)
        if self._legacy_lobby_thread:
            self._legacy_lobby_thread.join(timeout=3)
        for thread in list(self._extra_lobby_threads):
            thread.join(timeout=3)
        self._extra_lobby_threads = []
        if self._game_relay_thread:
            self._game_relay_thread.join(timeout=3)
        if self._timer:
            self._timer.join(timeout=3)

        # Save state
        self.ranking.save(force=True)
        self.stats.save(force=True)
        self._save_admin_bans()
        self.messenger.save_social_relations()

        log.info("Master server shutdown complete.")

    # ------------------------------------------------------------------ #
    # Local admin shell                                                    #
    # ------------------------------------------------------------------ #

    def start_admin_shell(self) -> bool:
        if self._admin_thread and self._admin_thread.is_alive():
            return True
        if not sys.stdin or not hasattr(sys.stdin, "isatty") or not sys.stdin.isatty():
            return False
        self._admin_stop.clear()
        self._admin_thread = threading.Thread(
            target=self._admin_shell_loop,
            name="AdminShell",
            daemon=True,
        )
        self._admin_thread.start()
        return True

    @staticmethod
    def _admin_write(text: str = "") -> None:
        try:
            print(text, flush=True)
        except Exception:
            pass

    @staticmethod
    def _admin_prompt() -> None:
        try:
            sys.stdout.write("admin> ")
            sys.stdout.flush()
        except Exception:
            pass

    def _admin_shell_loop(self) -> None:
        self._admin_write("Admin shell ready. Type 'help' for commands.")
        while self.is_running and not self._admin_stop.is_set():
            self._admin_prompt()
            try:
                line = sys.stdin.readline()
            except Exception:
                break
            if line == "":
                break
            line = line.strip()
            if not line:
                continue
            try:
                response = self._run_admin_command(line)
            except Exception as exc:
                response = f"error: {exc}"
            if response:
                self._admin_write(response)

    def _admin_find_handler(self, uid: int) -> Optional[ClientHandler]:
        for handler in ClientHandler._snapshot_lobby_handlers():
            if int(getattr(handler.user, "uid", 0) or 0) == int(uid):
                return handler
        return None

    def _admin_any_handler(self) -> Optional[ClientHandler]:
        handlers = ClientHandler._snapshot_lobby_handlers()
        return handlers[0] if handlers else None

    def _admin_disconnect_socket(self, user: User, *, reason: str) -> None:
        handler = self._admin_find_handler(int(user.uid))
        if handler is not None:
            handler._disconnect_reason = reason
        user.connected = False
        try:
            user.send('+KICK TEXT="Disconnected by admin"\n')
        except Exception:
            pass

    def _admin_normalize_ban_token(self, value: str) -> str:
        return str(value or "").strip().lower()

    def _admin_ban_file_path(self) -> str:
        path = str(self.cfg.get("ADMIN_BANFILE", "data/admin_bans.json") or "data/admin_bans.json").strip()
        if os.path.isabs(path):
            return path
        return os.path.abspath(os.path.join(os.path.dirname(self._config_path), path))

    def _load_admin_bans(self) -> None:
        path = self._admin_ban_file_path()
        self._admin_banned_ips.clear()
        self._admin_banned_names.clear()
        self._admin_banned_personas.clear()
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self._admin_banned_ips.update(
                self._admin_normalize_ban_token(v) for v in data.get("ips", []) if str(v).strip()
            )
            self._admin_banned_names.update(
                self._admin_normalize_ban_token(v) for v in data.get("names", []) if str(v).strip()
            )
            self._admin_banned_personas.update(
                self._admin_normalize_ban_token(v) for v in data.get("personas", []) if str(v).strip()
            )
            log.info(
                "Loaded admin bans from '%s' (ips=%d names=%d personas=%d)",
                path,
                len(self._admin_banned_ips),
                len(self._admin_banned_names),
                len(self._admin_banned_personas),
            )
        except Exception as exc:
            log.warning("Failed to load admin bans from '%s': %s", path, exc)

    def _save_admin_bans(self) -> None:
        path = self._admin_ban_file_path()
        try:
            os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
            payload = {
                "ips": sorted(self._admin_banned_ips),
                "names": sorted(self._admin_banned_names),
                "personas": sorted(self._admin_banned_personas),
                "saved_at": time.time(),
            }
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
        except Exception as exc:
            log.warning("Failed to save admin bans to '%s': %s", path, exc)

    def _admin_is_ip_banned(self, ip: str) -> bool:
        return self._admin_normalize_ban_token(ip) in self._admin_banned_ips

    def is_user_banned(self, user: User) -> bool:
        if self._admin_is_ip_banned(str(getattr(user, "ip", "") or "")):
            return True
        if self._admin_normalize_ban_token(getattr(user, "name", "")) in self._admin_banned_names:
            return True
        if self._admin_normalize_ban_token(getattr(user, "pers", "")) in self._admin_banned_personas:
            return True
        return False

    def _admin_ban_user(self, uid: int) -> str:
        user = self.users.get(int(uid))
        if user is None:
            return f"user {uid} not found"
        ip = self._admin_normalize_ban_token(user.ip)
        name = self._admin_normalize_ban_token(user.name)
        pers = self._admin_normalize_ban_token(user.pers)
        if ip:
            self._admin_banned_ips.add(ip)
        if name:
            self._admin_banned_names.add(name)
        if pers:
            self._admin_banned_personas.add(pers)
        self._save_admin_bans()
        self._admin_disconnect_socket(user, reason="admin_ban")
        return f"banned user {uid} ({user.name}) ip={user.ip} pers={user.pers or '-'}"

    def _admin_unban(self, token: str) -> str:
        key = self._admin_normalize_ban_token(token)
        removed = []
        if key in self._admin_banned_ips:
            self._admin_banned_ips.discard(key)
            removed.append("ip")
        if key in self._admin_banned_names:
            self._admin_banned_names.discard(key)
            removed.append("name")
        if key in self._admin_banned_personas:
            self._admin_banned_personas.discard(key)
            removed.append("pers")
        if not removed:
            return f"ban token '{token}' not found"
        self._save_admin_bans()
        return f"unbanned {token} ({', '.join(removed)})"

    def _format_admin_bans(self) -> str:
        lines = []
        if self._admin_banned_ips:
            lines.append("ips: " + ", ".join(sorted(self._admin_banned_ips)))
        if self._admin_banned_names:
            lines.append("names: " + ", ".join(sorted(self._admin_banned_names)))
        if self._admin_banned_personas:
            lines.append("personas: " + ", ".join(sorted(self._admin_banned_personas)))
        return "\n".join(lines) if lines else "no bans"

    def _admin_debug_status(self) -> str:
        root = logging.getLogger()
        level = logging.getLevelName(root.getEffectiveLevel())
        handlers = []
        for handler in root.handlers:
            if not getattr(handler, "_u2online_managed", False):
                continue
            kind = str(getattr(handler, "_u2online_kind", "handler"))
            handler_level = logging.getLevelName(handler.level)
            if kind == "file":
                filename = getattr(handler, "baseFilename", "")
                handlers.append(f"file={handler_level}:{filename}")
            else:
                handlers.append(f"{kind}={handler_level}")
        handler_text = " ".join(handlers) if handlers else "handlers=external"
        return f"debug level={level} {handler_text} udpdebug={'on' if self._udp_relay_verbose else 'off'}"

    def _admin_set_debug(self, enabled: bool) -> str:
        if not enabled:
            configure_logging_from_config(self.cfg, self._config_path)
            return self._admin_debug_status()

        level = logging.DEBUG
        root = logging.getLogger()
        root.setLevel(level)
        for handler in root.handlers:
            if getattr(handler, "_u2online_managed", False):
                handler.setLevel(level)
        for logger_name in ("server", "client", "rooms", "users", "ranking", "master", "config", "control", "batch", "matchmaking"):
            logging.getLogger(logger_name).setLevel(level)
        return self._admin_debug_status()

    def _admin_set_udp_debug(self, enabled: bool) -> str:
        self._udp_relay_verbose = bool(enabled)
        self._sync_udp_relay_verbose_filter()
        return self._admin_debug_status()

    def _admin_kick_user(self, uid: int) -> str:
        user = self.users.get(int(uid))
        if user is None:
            return f"user {uid} not found"

        handler = self._admin_find_handler(int(uid))
        if handler is not None:
            self._admin_disconnect_socket(user, reason="admin_kick")
            return f"kicked user {uid} ({user.name})"

        game = self.games.get(int(user.game)) if int(user.game or 0) else None
        if game is not None:
            game_after, removed = self.games.leave(int(game.id), int(uid))
            helper = self._admin_any_handler()
            if helper is not None:
                helper._lobby_on_game_departure(game or game_after, departed_uid=int(uid), removed=removed)
        if int(user.room or 0):
            self.rooms.leave(int(user.room), int(uid))
        self.users.remove(int(uid))
        self.request_master_stat_refresh()
        return f"removed offline user {uid} ({user.name})"

    def _admin_kick_from_game(self, game_id: int, uid: int) -> str:
        game = self.games.get(int(game_id))
        if game is None:
            return f"game {game_id} not found"
        if int(uid) not in set(int(v) for v in game.participants) and int(uid) != int(game.host_uid):
            return f"user {uid} is not in game {game_id}"

        user = self.users.get(int(uid))
        handler = self._admin_find_handler(int(uid))
        game_after, removed = self.games.leave(int(game_id), int(uid))
        game_ref = game or game_after

        if user is not None:
            user.game = 0
            user.stat = STAT_ROOM if int(user.room or 0) else STAT_LOBBY

        if handler is not None and game_ref is not None:
            handler._lobby_emit_game_leave_reset(handler, game_ref, delay_s=0.01, self_leave=False)

        helper = handler or self._admin_any_handler()
        if helper is not None and game_ref is not None:
            helper._lobby_on_game_departure(game_ref, departed_uid=int(uid), removed=removed)

        self.request_master_stat_refresh()
        if removed:
            return f"removed user {uid} from game {game_id}; game closed"
        return f"removed user {uid} from game {game_id}"

    def _admin_close_game(self, game_id: int) -> str:
        game = self.games.get(int(game_id))
        if game is None:
            return f"game {game_id} not found"

        affected_uids = list(game.participants)
        host_uid = int(getattr(game, "host_uid", 0) or 0)
        if host_uid and host_uid not in affected_uids:
            affected_uids.insert(0, host_uid)

        removed_game = self.games.destroy(int(game_id), reason="admin_close")
        if removed_game is None:
            return f"game {game_id} not found"

        for uid in affected_uids:
            user = self.users.get(int(uid))
            if user is None:
                continue
            if int(user.game or 0) == int(game_id):
                user.game = 0
            if user.stat == STAT_GAME:
                user.stat = STAT_ROOM if int(user.room or 0) else STAT_LOBBY

        helper = self._admin_any_handler()
        if helper is not None:
            helper._lobby_on_game_departure(removed_game, departed_uid=0, removed=True)

        self.request_master_stat_refresh()
        return f"closed game {game_id}"

    def _admin_send_chat_to_user(self, user: User, text: str, *, private: bool = False) -> bool:
        if not bool(getattr(user, "connected", False)):
            return False
        handler = self._admin_find_handler(int(user.uid))
        if handler is not None:
            fields = handler._lobby_msg_fields(
                text,
                sender="Server",
                flag="P" if private else "",
            )
            burst = handler._make_20922_tab_message("+msg", fields)
            handler._send_bootstrap_bytes(burst)
            return True
        user.send(encode_message("MESG", NAME="Server", TEXT=text))
        return True

    def _admin_broadcast_chat(self, text: str) -> str:
        if not text.strip():
            return "usage: say <text>"
        delivered = 0
        for user in self.users.all_users():
            if self._admin_send_chat_to_user(user, text, private=False):
                delivered += 1
        return f"broadcast sent to {delivered} player(s)"

    def _admin_push_news(self) -> str:
        delivered = 0
        for handler in ClientHandler._snapshot_lobby_handlers():
            if not bool(getattr(handler.user, "connected", False)):
                continue
            try:
                handler._send_later_bytes(0.01, handler._lobby_news_burst(), label="admin-pushnews")
                delivered += 1
            except Exception as exc:
                log.warning(
                    "Admin pushnews failed for uid=%d: %s",
                    int(getattr(handler.user, "uid", 0) or 0),
                    exc,
                )
        return f"news pushed to {delivered} player(s)"

    def _admin_private_chat(self, uid: int, text: str) -> str:
        if not text.strip():
            return "usage: pm <uid> <text>"
        user = self.users.get(int(uid))
        if user is None:
            return f"user {uid} not found"
        if not self._admin_send_chat_to_user(user, text, private=True):
            return f"user {uid} is not connected"
        return f"private message sent to {uid} ({user.name})"

    def _admin_chat_to_room(self, room_id: int, text: str) -> str:
        if not text.strip():
            return "usage: sayroom <room_id> <text>"
        room = self.rooms.get(int(room_id))
        if room is None:
            return f"room {room_id} not found"
        delivered = 0
        for uid in sorted(room.members):
            user = self.users.get(int(uid))
            if user is not None and self._admin_send_chat_to_user(user, text, private=False):
                delivered += 1
        return f"room message sent to {delivered} player(s) in room {room_id}"

    def _admin_chat_to_game(self, game_id: int, text: str) -> str:
        if not text.strip():
            return "usage: saygame <game_id> <text>"
        game = self.games.get(int(game_id))
        if game is None:
            return f"game {game_id} not found"
        delivered = 0
        for uid in list(game.participants):
            user = self.users.get(int(uid))
            if user is not None and self._admin_send_chat_to_user(user, text, private=False):
                delivered += 1
        return f"game message sent to {delivered} player(s) in game {game_id}"

    def _admin_kick_name(self, name: str) -> str:
        if not str(name).strip():
            return "usage: kickname <name>"
        user = self.users.get_by_name(str(name))
        if user is None:
            return f"user '{name}' not found"
        return self._admin_kick_user(int(user.uid))

    def _admin_mute_user(self, uid: int, reason: str = "") -> str:
        user = self.users.get(int(uid))
        if user is None:
            return f"user {uid} not found"
        user.muted = True
        user.mute_reason = reason.strip()
        user.muted_at = time.time()
        notice = "You have been muted by admin"
        if user.mute_reason:
            notice += f": {user.mute_reason}"
        self._admin_send_chat_to_user(user, notice, private=True)
        return f"muted user {uid} ({user.name})" + (f": {user.mute_reason}" if user.mute_reason else "")

    def _admin_unmute_user(self, uid: int) -> str:
        user = self.users.get(int(uid))
        if user is None:
            return f"user {uid} not found"
        if not bool(getattr(user, "muted", False)):
            return f"user {uid} ({user.name}) is not muted"
        user.muted = False
        user.mute_reason = ""
        user.muted_at = 0.0
        self._admin_send_chat_to_user(user, "You have been unmuted by admin", private=True)
        return f"unmuted user {uid} ({user.name})"

    def _admin_mute_name(self, name: str, reason: str = "") -> str:
        if not str(name).strip():
            return "usage: mutename <name> [reason]"
        user = self.users.get_by_name(str(name))
        if user is None:
            return f"user '{name}' not found"
        return self._admin_mute_user(int(user.uid), reason)

    def _format_admin_mutes(self) -> str:
        users = sorted(
            [user for user in self.users.all_users() if bool(getattr(user, "muted", False))],
            key=lambda user: int(user.uid),
        )
        if not users:
            return "no muted players"
        now = time.time()
        lines = ["UID  Name           MutedFor Reason"]
        for user in users:
            muted_for = max(0, int(now - float(getattr(user, "muted_at", 0.0) or now)))
            reason = str(getattr(user, "mute_reason", "") or "-")
            lines.append(
                f"{int(user.uid):<4} "
                f"{str(user.name or '-'): <14.14} "
                f"{muted_for:<8} "
                f"{reason}"
            )
        return "\n".join(lines)

    def _admin_save_state(self) -> str:
        self.ranking.save(force=True)
        self.stats.save(force=True)
        self._save_admin_bans()
        self.messenger.save_social_relations()
        return "ranking/stats/bans/social saved"

    def _admin_reload_config(self) -> str:
        self.cfg._data = dict(DEFAULTS)
        if not self.cfg.load(self._config_path):
            return f"failed to reload config from {self._config_path}"
        configure_logging_from_config(self.cfg, self._config_path)

        # Apply safe runtime tunables only. Listener host/port changes still need restart.
        self.users.max_users = int(self.cfg.get("SERVER_MAX_PLAYERS", self.cfg.get("USERS", self.users.max_users)) or self.users.max_users)
        self.rooms.max_rooms = int(self.cfg.get("ROOMS", self.rooms.max_rooms))
        self.rooms.max_size = int(self.cfg.get("ROOMMAX", self.rooms.max_size))
        self.games.max_games = int(self.cfg.get("GAMES", self.games.max_games))
        self.games.expire_time = int(self.cfg.get("GAME_EXPIRE_TIME", self.games.expire_time))
        self.games.game_timeout = int(self.cfg.get("GAMETIMEOUT", self.games.game_timeout))
        self.ranking.rank_file = self.cfg.get("RANKFILE", self.ranking.rank_file)
        self.ranking.rank_lim = int(self.cfg.get("RANKLIM", self.ranking.rank_lim))
        self.ranking.save_interval = int(self.cfg.get("RANK_SAVE_TIME", self.ranking.save_interval))
        self.ranking.min_game_time = int(self.cfg.get("RANK_MINIMUM_TIME", self.ranking.min_game_time))
        self.ranking.do_evaluate = bool(self.cfg.get("RANK_EVALUATE_GAME", int(self.ranking.do_evaluate)))
        self.ranking.do_authent = bool(self.cfg.get("RANK_AUTHENT", int(self.ranking.do_authent)))
        self.ranking.output_raw = bool(self.cfg.get("RANK_OUTPUT_RAW", int(self.ranking.output_raw)))
        self.stats.stats_file = self.cfg.get("STATSFILE", self.stats.stats_file)
        self.stats.stats_lim = int(self.cfg.get("STATLIM", self.stats.stats_lim))
        self.stats.stat_refresh = int(self.cfg.get("SERVER_STAT_REFRESH", self.stats.stat_refresh))
        self._udp_relay_verbose = self._cfg_flag("UDP_RELAY_VERBOSE", "UDP_DEBUG")
        self._sync_udp_relay_verbose_filter()
        with self._auth_accounts_lock:
            self._auth_accounts_path = ""
            self._auth_accounts_mtime = -1.0
            self._auth_accounts_cache = []
        self.request_master_stat_refresh()
        self._load_admin_bans()
        self.messenger.load_social_relations()
        return (
            f"config reloaded from {self._config_path} "
            "(runtime tunables updated; listener host/port changes need restart)"
        )

    def _format_admin_players(self) -> str:
        users = sorted(self.users.all_users(), key=lambda user: int(user.uid))
        if not users:
            return "no players"
        lines = ["UID  Name           Persona         Stat   Room Game Conn Mute Addr"]
        for user in users:
            lines.append(
                f"{int(user.uid):<4} "
                f"{str(user.name or '-'): <14.14} "
                f"{str(user.pers or '-'): <14.14} "
                f"{str(user.stat or '-'): <6.6} "
                f"{int(user.room or 0):<4} "
                f"{int(user.game or 0):<4} "
                f"{('Y' if user.connected else 'N'):<4} "
                f"{('Y' if bool(getattr(user, 'muted', False)) else 'N'):<4} "
                f"{str(user.ip or '-')}:{int(user.port or 0)}"
            )
        return "\n".join(lines)

    def _format_admin_social(self, target: str = "") -> str:
        return self.messenger.format_admin_social(target)

    def _format_admin_games(self) -> str:
        games = sorted(self.games.list_games(), key=lambda game: int(game.id))
        if not games:
            return "no games"
        lines = ["ID   State    Host Players Ready Room Limit Name"]
        for game in games:
            lines.append(
                f"{int(game.id):<4} "
                f"{str(game.state or '-'): <8.8} "
                f"{int(game.host_uid or 0):<4} "
                f"{len(game.participants):<7} "
                f"{len(game.ready_participants):<5} "
                f"{int(game.room_id or 0):<4} "
                f"{int(game.limit or 0):<5} "
                f"{str(game.custom or '-').strip() or '-'}"
            )
        return "\n".join(lines)

    def _format_admin_rooms(self) -> str:
        rooms = sorted(self.rooms.list_rooms(), key=lambda room: int(room.id))
        if not rooms:
            return "no rooms"
        lines = ["ID   Host Count Max  Assistant Name"]
        for room in rooms:
            lines.append(
                f"{int(room.id):<4} "
                f"{int(room.host_uid or 0):<4} "
                f"{int(room.count):<5} "
                f"{int(room.maxsize or 0):<4} "
                f"{int(getattr(room, 'assistant_uid', 0) or 0):<9} "
                f"{str(room.name or '-').strip() or '-'}"
            )
        return "\n".join(lines)

    def _format_admin_user_detail(self, uid: int) -> str:
        user = self.users.get(int(uid))
        if user is None:
            return f"user {uid} not found"
        lines = [
            f"uid={int(user.uid)} name={user.name} pers={user.pers or '-'} stat={user.stat or '-'} connected={'yes' if user.connected else 'no'}",
            f"room={int(user.room or 0)} game={int(user.game or 0)} ip={user.ip}:{int(user.port or 0)}",
            f"laddr={user.laddr or '-'} serv={user.serv or '-'} sprt={int(user.sprt or 0)} maddr={user.maddr or '-'}",
            f"level={int(user.level or 0)} medals={int(user.medals or 0)} rep={int(user.rep or 0)} play={int(user.play or 0)} ping={int(user.ping or 0)}",
            f"lang={user.lang or '-'} from={user.from_ or '-'} rgb={int(user.rgb or 0)} seed={int(user.seed or 0)}",
        ]
        if bool(getattr(user, "muted", False)):
            muted_for = max(0, int(time.time() - float(getattr(user, "muted_at", 0.0) or time.time())))
            reason = str(getattr(user, "mute_reason", "") or "-")
            lines.append(f"muted=yes muted_for={muted_for}s reason={reason}")
        aux = str(getattr(user, "aux", "") or "").strip()
        if aux:
            aux = aux.replace("\n", "\\n")
            if len(aux) > 180:
                aux = aux[:177] + "..."
            lines.append(f"aux={aux}")
        return "\n".join(lines)

    def _format_admin_stats(self) -> str:
        counts = self.users.count()
        gstats = self.games.stats()
        lines = [
            f"users total={counts['total']} lobby={counts['lobby']} rooms={counts['rooms']} games={counts['games']}",
            f"games open={gstats['open']} active={gstats['active']} finished={gstats['finished']} created={gstats['created']} completed={gstats['completed']}",
            f"rooms total={self.rooms.count()}",
            self._master_stat_payload(),
        ]
        return "\n".join(lines)

    @staticmethod
    def _parse_admin_stat_category(raw: str = "all") -> tuple[int, str] | None:
        value = str(raw or "all").strip().lower()
        aliases = {
            "all": (0, "all"),
            "overall": (0, "all"),
            "circuit": (1, "circuit"),
            "circ": (1, "circuit"),
            "sprint": (2, "sprint"),
            "drag": (3, "drag"),
            "drift": (4, "drift"),
            "url": (4, "drift"),
        }
        if value in aliases:
            return aliases[value]
        if value.isdigit():
            idx = int(value)
            if 0 <= idx <= 4:
                names = ("all", "circuit", "sprint", "drag", "drift")
                return idx, names[idx]
        return None

    def _admin_stat_bump(self, persona: str, outcome: str, category: str = "all", count: int = 1) -> str:
        persona = str(persona or "").strip()
        if not persona:
            return "usage: statbump <persona> <win|loss|disconnect> [all|circuit|sprint|drag|drift|url] [count]"
        outcome_key = str(outcome or "").strip().lower()
        outcome_map = {
            "w": "WIN",
            "win": "WIN",
            "wins": "WIN",
            "l": "LOSS",
            "loss": "LOSS",
            "losses": "LOSS",
            "d": "DISCONNECT",
            "disc": "DISCONNECT",
            "disconnect": "DISCONNECT",
            "disconnects": "DISCONNECT",
        }
        mapped = outcome_map.get(outcome_key)
        parsed_category = self._parse_admin_stat_category(category)
        if mapped is None or parsed_category is None or count < 1:
            return "usage: statbump <persona> <win|loss|disconnect> [all|circuit|sprint|drag|drift|url] [count]"
        category_index, category_name = parsed_category
        for _ in range(min(1000, int(count))):
            self.stats.record_player_result(persona, mapped, category_index=category_index)
        self.stats.save(force=True)
        summary = self.stats.player_summary(persona)
        return (
            f"stats bumped persona={persona} outcome={mapped.lower()} category={category_name} count={count} "
            f"rank={int(summary.get('rank', 9999) or 9999)} "
            f"wins={int(summary.get('wins', 0) or 0)} "
            f"losses={int(summary.get('losses', 0) or 0)} "
            f"disconnects={int(summary.get('disconnects', 0) or 0)} "
            f"rep={int(summary.get('rep', 100) or 100)}"
        )

    def _admin_stat_show(self, persona: str) -> str:
        persona = str(persona or "").strip()
        if not persona:
            return "usage: statshow <persona>"
        summary = self.stats.player_summary(persona)
        csv = self.stats.player_stat_csv(persona)
        return (
            f"persona={persona} "
            f"rank={int(summary.get('rank', 9999) or 9999)} "
            f"wins={int(summary.get('wins', 0) or 0)} "
            f"losses={int(summary.get('losses', 0) or 0)} "
            f"disconnects={int(summary.get('disconnects', 0) or 0)} "
            f"rep={int(summary.get('rep', 100) or 100)}\n"
            f"S={csv}"
        )

    def _run_admin_command(self, line: str) -> str:
        try:
            argv = shlex.split(line)
        except ValueError as exc:
            return f"parse error: {exc}"
        if not argv:
            return ""

        cmd = argv[0].lower()
        if cmd in ("help", "?"):
            return "\n".join(
                [
                    "help",
                    "players",
                    "player <uid>",
                    "rooms",
                    "games",
                    "stats",
                    "statshow <persona>",
                    "statbump <persona> <win|loss|disconnect> [all|circuit|sprint|drag|drift|url] [count]",
                    "social [name]",
                    "kick <uid>",
                    "ban <uid>",
                    "unban <token>",
                    "listbans",
                    "authcode <code> [identifier|*] [uses]",
                    "authcode list|clear|codes",
                    "personacode <code> [persona|*] [uses]",
                    "personacode list|clear|codes",
                    "authreject [repeat interval close_delay]|slow|default",
                    "mute <uid> [reason]",
                    "unmute <uid>",
                    "mutename <name> [reason]",
                    "listmutes",
                    "kickname <name>",
                    "kickgame <game_id> <uid>",
                    "closegame <game_id>",
                    "save",
                    "reloadcfg",
                    "debug status|on|off",
                    "udpdebug status|on|off",
                    "pushnews",
                    "say <text>",
                    "pm <uid> <text>",
                    "sayroom <room_id> <text>",
                    "saygame <game_id> <text>",
                ]
            )
        if cmd == "players":
            return self._format_admin_players()
        if cmd == "player":
            if len(argv) != 2 or not argv[1].isdigit():
                return "usage: player <uid>"
            return self._format_admin_user_detail(int(argv[1]))
        if cmd == "rooms":
            return self._format_admin_rooms()
        if cmd == "games":
            return self._format_admin_games()
        if cmd == "stats":
            return self._format_admin_stats()
        if cmd == "statshow":
            if len(argv) != 2:
                return "usage: statshow <persona>"
            return self._admin_stat_show(argv[1])
        if cmd == "statbump":
            if len(argv) < 3 or len(argv) > 5:
                return "usage: statbump <persona> <win|loss|disconnect> [all|circuit|sprint|drag|drift|url] [count]"
            category = argv[3] if len(argv) >= 4 else "all"
            count = 1
            if len(argv) >= 5:
                if not argv[4].isdigit():
                    return "usage: statbump <persona> <win|loss|disconnect> [all|circuit|sprint|drag|drift|url] [count]"
                count = int(argv[4])
            return self._admin_stat_bump(argv[1], argv[2], category, count)
        if cmd == "social":
            if len(argv) > 2:
                return "usage: social [name]"
            return self._format_admin_social(argv[1] if len(argv) == 2 else "")
        if cmd == "kick":
            if len(argv) != 2 or not argv[1].isdigit():
                return "usage: kick <uid>"
            return self._admin_kick_user(int(argv[1]))
        if cmd == "ban":
            if len(argv) != 2 or not argv[1].isdigit():
                return "usage: ban <uid>"
            return self._admin_ban_user(int(argv[1]))
        if cmd == "unban":
            if len(argv) != 2:
                return "usage: unban <token>"
            return self._admin_unban(argv[1])
        if cmd == "listbans":
            return self._format_admin_bans()
        if cmd == "authcode":
            if len(argv) < 2:
                return "usage: authcode <code> [identifier|*] [uses] | authcode list|clear|codes"
            subcmd = argv[1].lower()
            if subcmd == "list":
                return self._format_auth_forced_rejects()
            if subcmd == "clear":
                return self._clear_auth_forced_rejects()
            if subcmd == "codes":
                return self._auth_supported_codes_text()
            identifier = argv[2] if len(argv) >= 3 else "*"
            uses = 1
            if len(argv) >= 4:
                if not argv[3].isdigit():
                    return "usage: authcode <code> [identifier|*] [uses]"
                uses = int(argv[3])
            if len(argv) > 4:
                return "usage: authcode <code> [identifier|*] [uses]"
            return self._auth_set_forced_reject(argv[1], identifier, uses)
        if cmd == "authreject":
            if len(argv) == 1 or (len(argv) == 2 and argv[1].lower() == "status"):
                return self._format_auth_reject_timing()
            if len(argv) == 2 and argv[1].lower() == "slow":
                return self._set_auth_reject_timing(1, 0.25, 8.0)
            if len(argv) == 2 and argv[1].lower() == "default":
                return self._set_auth_reject_timing(4, 0.25, 1.10)
            if len(argv) != 4:
                return "usage: authreject <repeat> <interval_sec> <close_delay_sec> | authreject slow|default|status"
            return self._set_auth_reject_timing(argv[1], argv[2], argv[3])
        if cmd == "personacode":
            if len(argv) < 2:
                return "usage: personacode <code> [persona|*] [uses] | personacode list|clear|codes"
            subcmd = argv[1].lower()
            if subcmd == "list":
                return self._format_persona_forced_rejects()
            if subcmd == "clear":
                return self._clear_persona_forced_rejects()
            if subcmd == "codes":
                return self._persona_supported_codes_text()
            persona = argv[2] if len(argv) >= 3 else "*"
            uses = 1
            if len(argv) >= 4:
                if not argv[3].isdigit():
                    return "usage: personacode <code> [persona|*] [uses]"
                uses = int(argv[3])
            if len(argv) > 4:
                return "usage: personacode <code> [persona|*] [uses]"
            return self._persona_set_forced_reject(argv[1], persona, uses)
        if cmd == "mute":
            if len(argv) < 2 or not argv[1].isdigit():
                return "usage: mute <uid> [reason]"
            return self._admin_mute_user(int(argv[1]), " ".join(argv[2:]))
        if cmd == "unmute":
            if len(argv) != 2 or not argv[1].isdigit():
                return "usage: unmute <uid>"
            return self._admin_unmute_user(int(argv[1]))
        if cmd == "mutename":
            if len(argv) < 2:
                return "usage: mutename <name> [reason]"
            return self._admin_mute_name(argv[1], " ".join(argv[2:]))
        if cmd == "listmutes":
            return self._format_admin_mutes()
        if cmd == "kickname":
            if len(argv) != 2:
                return "usage: kickname <name>"
            return self._admin_kick_name(argv[1])
        if cmd == "kickgame":
            if len(argv) != 3 or not argv[1].isdigit() or not argv[2].isdigit():
                return "usage: kickgame <game_id> <uid>"
            return self._admin_kick_from_game(int(argv[1]), int(argv[2]))
        if cmd == "closegame":
            if len(argv) != 2 or not argv[1].isdigit():
                return "usage: closegame <game_id>"
            return self._admin_close_game(int(argv[1]))
        if cmd == "save":
            return self._admin_save_state()
        if cmd == "reloadcfg":
            return self._admin_reload_config()
        if cmd == "debug":
            if len(argv) == 1 or argv[1].lower() == "status":
                return self._admin_debug_status()
            if argv[1].lower() == "on":
                return self._admin_set_debug(True)
            if argv[1].lower() == "off":
                return self._admin_set_debug(False)
            return "usage: debug status|on|off"
        if cmd in ("udpdebug", "racedebug"):
            if len(argv) == 1 or argv[1].lower() == "status":
                return self._admin_debug_status()
            if argv[1].lower() == "on":
                return self._admin_set_udp_debug(True)
            if argv[1].lower() == "off":
                return self._admin_set_udp_debug(False)
            return "usage: udpdebug status|on|off"
        if cmd == "pushnews":
            return self._admin_push_news()
        if cmd == "say":
            if len(argv) < 2:
                return "usage: say <text>"
            return self._admin_broadcast_chat(" ".join(argv[1:]))
        if cmd == "pm":
            if len(argv) < 3 or not argv[1].isdigit():
                return "usage: pm <uid> <text>"
            return self._admin_private_chat(int(argv[1]), " ".join(argv[2:]))
        if cmd == "sayroom":
            if len(argv) < 3 or not argv[1].isdigit():
                return "usage: sayroom <room_id> <text>"
            return self._admin_chat_to_room(int(argv[1]), " ".join(argv[2:]))
        if cmd == "saygame":
            if len(argv) < 3 or not argv[1].isdigit():
                return "usage: saygame <game_id> <text>"
            return self._admin_chat_to_game(int(argv[1]), " ".join(argv[2:]))
        return f"unknown command: {cmd}"

    # ------------------------------------------------------------------ #
    # IsServerRunning equivalent                                           #
    # ------------------------------------------------------------------ #

    def is_server_running(self) -> bool:
        return self._handle is not None and self.is_running

    # ------------------------------------------------------------------ #
    # Accept loop                                                          #
    # ------------------------------------------------------------------ #

    def _accept_loop(self):
        self._accept_loop_on_socket(self._sock, "Client")

    def _accept_loop_on_socket(self, listen_sock: socket.socket, thread_prefix: str):
        while self.is_running:
            try:
                conn, addr = listen_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            if not self._accepts_new_connection(addr[0]):
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    conn.close()
                except Exception:
                    pass
                continue

            if self._admin_is_ip_banned(addr[0]):
                log.info("Admin ban refused lobby connection from %s:%d", addr[0], addr[1])
                try:
                    conn.close()
                except Exception:
                    pass
                continue

            if not self._open_lobby_connection_slot(addr[0]):
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    conn.close()
                except Exception:
                    pass
                continue

            user    = User(conn, addr)
            handler = ClientHandler(self, user)

            def _run_handler() -> None:
                try:
                    handler.run()
                finally:
                    self._close_lobby_connection_slot()

            t = threading.Thread(target=_run_handler,
                                 name=f"{thread_prefix}-{addr[0]}",
                                 daemon=True)
            t.start()
            log.info("Connect status: max=%d, cur=%d",
                     self.users.max_users, len(self.users.all_users()) + 1)

    def _udp_relay_room_ordered_uids(self, room: Optional[int]) -> List[int]:
        room_id = int(room or 0)
        if room_id <= 0:
            return []
        game = self.games.get(room_id)
        if game is None:
            return []
        ordered: List[int] = []
        host_uid = int(getattr(game, "host_uid", 0) or 0)
        if host_uid > 0:
            ordered.append(host_uid)
        for uid in getattr(game, "participants", []) or []:
            uid_int = int(uid or 0)
            if uid_int > 0 and uid_int not in ordered:
                ordered.append(uid_int)
        return ordered

    def _udp_relay_bind_uid_to_client(
        self,
        client: UDPRelayClientState,
        room: Optional[int],
        *,
        prefer_uid: int = 0,
    ) -> int:
        room_id = int(room or 0)
        if room_id <= 0:
            return 0
        ordered = self._udp_relay_room_ordered_uids(room_id)
        if not ordered:
            return 0
        mapping = self._udp_relay_uid_addr_by_room.setdefault(room_id, {})
        try:
            stable_game_port = int(self.cfg.get("UDP_GAME_PORT", 3658) or 3658)
        except Exception:
            stable_game_port = 3658
        host_uid = int(ordered[0]) if ordered else 0
        if int(client.addr[1] or 0) == stable_game_port and host_uid > 0:
            previous_host_addr = mapping.get(host_uid)
            if previous_host_addr not in (None, client.addr):
                previous_state = self._udp_relay_clients.get(previous_host_addr)
                reassigned = 0
                used_after_host = {
                    int(uid)
                    for uid, addr in mapping.items()
                    if int(uid) != host_uid and addr != previous_host_addr
                }
                for uid in ordered[1:]:
                    if int(uid) not in used_after_host:
                        mapping[int(uid)] = previous_host_addr
                        reassigned = int(uid)
                        if previous_state is not None:
                            previous_state.uid = reassigned
                        break
                if reassigned <= 0:
                    for uid, addr in list(mapping.items()):
                        if addr == previous_host_addr:
                            mapping.pop(uid, None)
                    if previous_state is not None:
                        previous_state.uid = 0
                log.info(
                    "UDP relay host-port uid rebalance: room=0x%08X host_uid=%d host_addr=%s:%d previous=%s:%d reassigned_uid=%d",
                    room_id,
                    host_uid,
                    client.addr[0],
                    client.addr[1],
                    previous_host_addr[0],
                    previous_host_addr[1],
                    reassigned,
                )
            mapping[host_uid] = client.addr
            client.uid = host_uid
            return host_uid

        current_uid = int(getattr(client, "uid", 0) or 0)
        if current_uid > 0 and mapping.get(current_uid) == client.addr:
            return current_uid

        if prefer_uid > 0 and prefer_uid in ordered:
            existing = mapping.get(prefer_uid)
            if existing in (None, client.addr):
                mapping[prefer_uid] = client.addr
                client.uid = prefer_uid
                return prefer_uid

        for uid, addr in list(mapping.items()):
            if addr == client.addr and uid in ordered:
                client.uid = int(uid)
                return int(uid)

        used = {int(uid) for uid, addr in mapping.items() if addr != client.addr}
        for uid in ordered:
            if uid not in used:
                mapping[uid] = client.addr
                client.uid = uid
                return uid

        return 0

    def _udp_relay_guess_peer_by_uid_binding(self, src: Addr, room: Optional[int]) -> Optional[Addr]:
        room_id = int(room or 0)
        if room_id <= 0:
            return None
        sender_state = self._udp_relay_clients.get(src)
        if sender_state is None:
            return None
        sender_uid = int(getattr(sender_state, "uid", 0) or 0)
        if sender_uid <= 0:
            sender_uid = self._udp_relay_bind_uid_to_client(sender_state, room_id)
        ordered = self._udp_relay_room_ordered_uids(room_id)
        if len(ordered) < 2 or sender_uid <= 0:
            return None
        mapping = self._udp_relay_uid_addr_by_room.get(room_id, {})
        try:
            spoof_window = max(1.0, float(self.cfg.get("UDP_RELAY_SPOOF_PEER_WINDOW", 6.0) or 6.0))
        except Exception:
            spoof_window = 6.0
        idle_cutoff = time.time() - spoof_window
        for uid in ordered:
            if uid == sender_uid:
                continue
            addr = mapping.get(uid)
            if addr is None or addr == src:
                continue
            state = self._udp_relay_clients.get(addr)
            if state is None:
                continue
            if float(getattr(state, "last_seen", 0.0) or 0.0) < idle_cutoff:
                continue
            self._udp_relay_move_client_to_room(state, room_id, provisional=True)
            return addr
        return None

    def _udp_relay_drop_uid_binding(self, addr: Addr, room: Optional[int], uid: int = 0) -> None:
        room_id = int(room or 0)
        if room_id <= 0:
            return
        mapping = self._udp_relay_uid_addr_by_room.get(room_id)
        if not mapping:
            return
        target_uid = int(uid or 0)
        if target_uid > 0 and mapping.get(target_uid) == addr:
            mapping.pop(target_uid, None)
        else:
            for cand_uid, cand_addr in list(mapping.items()):
                if cand_addr == addr:
                    mapping.pop(cand_uid, None)
        if not mapping:
            self._udp_relay_uid_addr_by_room.pop(room_id, None)

    def _udp_relay_max_clients(self) -> int:
        return self._cfg_int("UDP_RELAY_MAX_CLIENTS", 128, min_value=0, max_value=100000)

    def _udp_relay_max_pending_rooms(self) -> int:
        return self._cfg_int("UDP_RELAY_MAX_PENDING_ROOMS", 128, min_value=0, max_value=100000)

    def _udp_relay_pending_room_ttl(self) -> float:
        return self._cfg_float("UDP_RELAY_PENDING_ROOM_TTL", 60.0, min_value=5.0, max_value=3600.0)

    def _udp_relay_touch_client(self, addr: Addr, relay_listen_port: int = 0) -> Optional[UDPRelayClientState]:
        state = self._udp_relay_clients.get(addr)
        if state is None:
            max_clients = self._udp_relay_max_clients()
            if max_clients > 0 and len(self._udp_relay_clients) >= max_clients:
                self._udp_relay_cleanup_idle()
            if max_clients > 0 and len(self._udp_relay_clients) >= max_clients:
                now = time.time()
                if now >= self._udp_relay_limit_log_at:
                    log.warning(
                        "UDP relay client limit reached: src=%s:%d active=%d max=%d",
                        addr[0],
                        addr[1],
                        len(self._udp_relay_clients),
                        max_clients,
                    )
                    self._udp_relay_limit_log_at = now + 5.0
                return None
            state = UDPRelayClientState(addr=addr)
            self._udp_relay_clients[addr] = state
        state.last_seen = time.time()
        state.packets_in += 1
        if int(relay_listen_port or 0) > 0:
            state.relay_listen_port = int(relay_listen_port)
        return state

    def _udp_relay_idle_timeout(self) -> float:
        return max(30.0, float(self.cfg.get("GAME_EXPIRE_TIME", 300) or 300))

    def _udp_relay_cleanup_pending_rooms(self) -> None:
        cutoff = time.time() - self._udp_relay_pending_room_ttl()
        for store, seen in (
            (self._udp_relay_pending_room_packets, self._udp_relay_pending_room_seen),
            (self._udp_relay_pending_room_raw_packets, self._udp_relay_pending_room_raw_seen),
        ):
            stale = [room for room, at in seen.items() if float(at or 0.0) < cutoff]
            for room in stale:
                store.pop(room, None)
                seen.pop(room, None)
            max_rooms = self._udp_relay_max_pending_rooms()
            if max_rooms > 0 and len(store) > max_rooms:
                overflow = sorted(store, key=lambda room: float(seen.get(room, 0.0) or 0.0))
                for room in overflow[: len(store) - max_rooms]:
                    store.pop(room, None)
                    seen.pop(room, None)

    def _udp_relay_pending_list(
        self,
        store: Dict[int, List[Tuple[Addr, bytes]]],
        seen: Dict[int, float],
        room: int,
    ) -> Optional[List[Tuple[Addr, bytes]]]:
        room_id = int(room or 0)
        if room_id <= 0 or room_id == 0xFFFFFFFF:
            return None
        if room_id not in store:
            self._udp_relay_cleanup_pending_rooms()
            max_rooms = self._udp_relay_max_pending_rooms()
            if max_rooms > 0 and len(store) >= max_rooms:
                now = time.time()
                if now >= self._udp_relay_limit_log_at:
                    log.warning(
                        "UDP relay pending-room limit reached: room=0x%08X active=%d max=%d",
                        room_id,
                        len(store),
                        max_rooms,
                    )
                    self._udp_relay_limit_log_at = now + 5.0
                return None
            store[room_id] = []
        seen[room_id] = time.time()
        return store[room_id]

    def _udp_relay_wrapped_target_is_plausible(self, target: Addr) -> bool:
        if target in self._udp_relay_clients:
            return True
        target_ip = str(target[0] or "")
        target_port = int(target[1] or 0)
        if target_port <= 0:
            return False
        if target_port == int(self.cfg.get("UDP_GAME_PORT", 3658) or 3658):
            return True
        if self._udp_relay_is_forced_same_host_endpoint(target):
            return True
        if _udp_is_local_or_private_ip(target_ip):
            return True
        advertised_host = self.advertised_game_host()
        if advertised_host:
            try:
                if target_ip == self._resolve_ipv4_host(advertised_host):
                    return True
            except Exception:
                pass
        return False

    def _udp_relay_same_host_pair_peer(self, src: Addr) -> Optional[Addr]:
        try:
            base = int(self.cfg.get("UDP_LOCAL_PORT", self.cfg.get("udp_local_port", 40001)) or 40001)
            span = int(self.cfg.get("UDP_LOCAL_PORT_SPAN", self.cfg.get("udp_local_port_span", 8)) or 8)
            port = int(src[1] or 0)
        except Exception:
            return None
        if span <= 1 or port < base or port >= base + span:
            return None
        offset = port - base
        peer_port = port + 1 if (offset % 2) == 0 else port - 1
        if peer_port < base or peer_port >= base + span:
            return None
        return (src[0], peer_port)

    def _udp_relay_is_forced_same_host_endpoint(self, addr: Addr) -> bool:
        try:
            base = int(self.cfg.get("UDP_LOCAL_PORT", self.cfg.get("udp_local_port", 40001)) or 40001)
            span = int(self.cfg.get("UDP_LOCAL_PORT_SPAN", self.cfg.get("udp_local_port_span", 8)) or 8)
            port = int(addr[1] or 0)
        except Exception:
            return False
        return span > 1 and port >= base and port < base + span

    def _udp_relay_same_room_activity(self, state: UDPRelayClientState, room: Optional[int]) -> bool:
        room_id = int(room or 0)
        if room_id <= 0:
            return False
        return (
            int(getattr(state, "room", 0) or 0) == room_id
            or int(getattr(state, "provisional_room", 0) or 0) == room_id
            or int(getattr(state, "last_room_id", 0) or 0) == room_id
            or int(getattr(state, "room_role_room", 0) or 0) == room_id
        )

    def _udp_relay_forced_peer_is_stale(
        self,
        src: Addr,
        peer: Addr,
        peer_state: Optional[UDPRelayClientState],
        room: Optional[int],
    ) -> bool:
        if peer_state is None:
            return False
        if src[0] != peer[0]:
            return False
        if not (
            self._udp_relay_is_forced_same_host_endpoint(src)
            and self._udp_relay_is_forced_same_host_endpoint(peer)
        ):
            return False
        return int(room or 0) > 0 and not self._udp_relay_same_room_activity(peer_state, room)

    def _udp_relay_note_peer(self, src: Addr, dst: Addr) -> None:
        now = time.time()
        src_state = self._udp_relay_clients.get(src)
        dst_state = self._udp_relay_clients.get(dst)
        if src_state is not None:
            src_state.last_peer = dst
            src_state.last_peer_at = now
        if dst_state is not None:
            dst_state.last_peer = src
            dst_state.last_peer_at = now

    def _udp_relay_pair_sticky_peers(self, a: Addr, b: Addr) -> None:
        now = time.time()
        a_state = self._udp_relay_clients.get(a)
        b_state = self._udp_relay_clients.get(b)
        if a_state is None or b_state is None:
            return
        a_state.sticky_peer = b
        a_state.sticky_peer_at = now
        b_state.sticky_peer = a
        b_state.sticky_peer_at = now
        log.info(
            "UDP relay sticky pair: %s:%d <-> %s:%d",
            a[0],
            a[1],
            b[0],
            b[1],
        )

    def _udp_relay_sticky_peer(
        self,
        sender: UDPRelayClientState,
        room: Optional[int],
        target: Optional[Addr],
    ) -> Optional[Addr]:
        peer = sender.sticky_peer or sender.last_peer
        if not peer or peer == sender.addr:
            return None
        peer_state = self._udp_relay_clients.get(peer)
        if peer_state is None:
            return None

        now = time.time()
        idle_cutoff = now - self._udp_relay_idle_timeout()
        sticky_peer_at = float(getattr(sender, "sticky_peer_at", 0.0) or 0.0)
        last_peer_at = float(getattr(sender, "last_peer_at", 0.0) or 0.0)
        peer_last_seen = float(getattr(peer_state, "last_seen", 0.0) or 0.0)
        if max(sticky_peer_at, last_peer_at, peer_last_seen) < idle_cutoff:
            return None

        room_id = int(room or 0)
        if self._udp_relay_forced_peer_is_stale(sender.addr, peer, peer_state, room):
            log.info(
                "UDP relay skipped stale forced sticky-peer: src=%s:%d room=%s peer=%s:%d target=%s:%s",
                sender.addr[0],
                sender.addr[1],
                f"0x{room_id:08X}" if room_id > 0 else "-",
                peer[0],
                peer[1],
                target[0] if target is not None else "-",
                target[1] if target is not None else "-",
            )
            return None
        if room_id > 0:
            self._udp_relay_move_client_to_room(peer_state, room_id, provisional=True)
        log.info(
            "UDP relay guessed peer by sticky-session: src=%s:%d room=%s guessed=%s:%d target=%s:%s age_ms=%d",
            sender.addr[0],
            sender.addr[1],
            f"0x{room_id:08X}" if room_id > 0 else "-",
            peer[0],
            peer[1],
            target[0] if target is not None else "-",
            target[1] if target is not None else "-",
            int(max(0.0, now - max(sticky_peer_at, last_peer_at, peer_last_seen)) * 1000.0),
        )
        return peer

    def _udp_relay_recent_last_peer(
        self,
        src: Addr,
        peer_hint: Optional[Addr],
        room: Optional[int],
        target: Optional[Addr],
    ) -> Optional[Addr]:
        if peer_hint is None or peer_hint == src:
            return None
        peer_state = self._udp_relay_clients.get(peer_hint)
        if peer_state is None:
            return None
        try:
            spoof_window = max(1.0, float(self.cfg.get("UDP_RELAY_SPOOF_PEER_WINDOW", 6.0) or 6.0))
        except Exception:
            spoof_window = 6.0
        idle_cutoff = time.time() - spoof_window
        sticky_peer_at = float(getattr(peer_state, "sticky_peer_at", 0.0) or 0.0)
        peer_last_seen = float(getattr(peer_state, "last_seen", 0.0) or 0.0)
        if max(sticky_peer_at, peer_last_seen) < idle_cutoff:
            return None

        room_id = int(room or 0)
        if room_id > 0:
            self._udp_relay_move_client_to_room(peer_state, room_id, provisional=True)
        log.info(
            "UDP relay preferred last-peer: src=%s:%d room=%s preferred=%s:%d target=%s:%s age_ms=%d",
            src[0],
            src[1],
            f"0x{room_id:08X}" if room_id > 0 else "-",
            peer_hint[0],
            peer_hint[1],
            target[0] if target is not None else "-",
            target[1] if target is not None else "-",
            int(max(0.0, time.time() - max(sticky_peer_at, peer_last_seen)) * 1000.0),
        )
        return peer_hint

    def _udp_relay_recent_spoof_peer(
        self,
        src: Addr,
        room: Optional[int],
        target: Optional[Addr],
        exclude: Optional[Set[Addr]] = None,
    ) -> Optional[Addr]:
        if target is None:
            return None
        target_ip = str(target[0] or "").strip()
        if not target_ip:
            return None

        try:
            spoof_window = max(1.0, float(self.cfg.get("UDP_RELAY_SPOOF_PEER_WINDOW", 6.0) or 6.0))
        except Exception:
            spoof_window = 6.0
        idle_cutoff = time.time() - spoof_window
        excluded = set(exclude or ())
        best: Optional[Tuple[float, Addr]] = None
        for addr, state in self._udp_relay_clients.items():
            if addr == src or addr in excluded:
                continue
            spoof_ip = str(getattr(state, "spoof_ip", "") or "").strip()
            if spoof_ip != target_ip:
                continue
            last_seen = float(getattr(state, "last_seen", 0.0) or 0.0)
            if last_seen < idle_cutoff:
                continue
            score = last_seen
            if best is None or score > best[0]:
                best = (score, addr)

        if best is None:
            return None

        chosen = best[1]
        chosen_state = self._udp_relay_clients.get(chosen)
        room_id = int(room or 0)
        if chosen_state is not None and room_id > 0:
            self._udp_relay_move_client_to_room(chosen_state, room_id, provisional=True)
        log.info(
            "UDP relay preferred spoof-peer: src=%s:%d room=%s preferred=%s:%d target=%s:%s age_ms=%d",
            src[0],
            src[1],
            f"0x{room_id:08X}" if room_id > 0 else "-",
            chosen[0],
            chosen[1],
            target[0] if target is not None else "-",
            target[1] if target is not None else "-",
            int(max(0.0, time.time() - best[0]) * 1000.0),
        )
        return chosen

    def _udp_relay_move_client_to_room(
        self,
        client: UDPRelayClientState,
        room: int,
        *,
        provisional: bool = False,
    ) -> None:
        if client.room == room:
            if not provisional and client.provisional_room == room:
                client.provisional_room = None
            return
        if client.room is not None:
            prev_members = self._udp_relay_rooms.get(client.room)
            if prev_members is not None:
                prev_members.discard(client.addr)
                if not prev_members:
                    self._udp_relay_rooms.pop(client.room, None)
                    self._udp_relay_raw_started_rooms.discard(client.room)
                    self._udp_relay_host_bootstrap_sent = {
                        item for item in self._udp_relay_host_bootstrap_sent if item[0] != client.room
                    }
                    self._udp_relay_missing_65_sent = {
                        item for item in self._udp_relay_missing_65_sent if item[0] != client.room
                    }
                    self._udp_relay_host_continuation_sent = {
                        item for item in self._udp_relay_host_continuation_sent if item[0] != client.room
                    }
        client.control_sent_room = None
        client.control_prime_count = 0
        client.control_prime_last = 0.0
        client.raw_ack_sent_room = None
        client.room = room
        client.provisional_room = room if provisional else None
        if client.room_role_room != room:
            client.room_role_room = room
            client.room_role_cmd = 0
        members = self._udp_relay_rooms.setdefault(room, set())
        members.add(client.addr)
        bound_uid = self._udp_relay_bind_uid_to_client(client, room)
        if bound_uid > 0:
            log.info("UDP relay room set: %s:%d -> 0x%08X uid=%d", client.addr[0], client.addr[1], room, bound_uid)
        else:
            log.info("UDP relay room set: %s:%d -> 0x%08X", client.addr[0], client.addr[1], room)
        if len(members) > 1:
            self._udp_relay_replay_pending_room_packets(room, client.addr)
            self._udp_relay_replay_pending_room_raw_packets(room, client.addr)
        self._udp_relay_prune_room_endpoints(room, prefer=client.addr)

    def _udp_relay_expected_endpoint_count(self, room: Optional[int]) -> int:
        room_id = int(room or 0)
        if room_id <= 0:
            return 0
        ordered = self._udp_relay_room_ordered_uids(room_id)
        if ordered:
            return max(2, len(ordered))
        game = self.games.get(room_id)
        if game is None:
            return 0
        return max(2, int(getattr(game, "count", 0) or 0))

    def _udp_relay_prune_room_endpoints(self, room: Optional[int], *, prefer: Optional[Addr] = None) -> None:
        room_id = int(room or 0)
        if room_id <= 0:
            return
        try:
            enabled = int(self.cfg.get("UDP_RELAY_PRUNE_ROOM_ENDPOINTS", 1) or 0) != 0
        except Exception:
            enabled = True
        if not enabled:
            return
        expected = self._udp_relay_expected_endpoint_count(room_id)
        if expected <= 0:
            return
        members = set(self._udp_relay_rooms.get(room_id, set()) or set())
        if len(members) <= expected:
            return

        ranked: List[Tuple[float, Addr]] = []
        for addr in members:
            state = self._udp_relay_clients.get(addr)
            last_seen = float(getattr(state, "last_seen", 0.0) or 0.0) if state is not None else 0.0
            score = last_seen
            if int(addr[1] or 0) == int(self.cfg.get("UDP_GAME_PORT", 3658) or 3658):
                score += 2.0
            if state is not None and room_id in (getattr(state, "raw_sent_rooms", set()) or set()):
                score += 1.5
            if state is not None and int(getattr(state, "last_room_id", 0) or 0) == room_id:
                score += 1.0
            if prefer is not None and addr == prefer and (time.time() - last_seen) <= 6.0:
                score = max(score, time.time() + 1.0)
            ranked.append((score, addr))
        ranked.sort(key=lambda item: item[0], reverse=True)
        keep = {addr for _last_seen, addr in ranked[:expected]}
        drop = sorted(members - keep, key=lambda addr: (addr[0], int(addr[1] or 0)))
        for addr in drop:
            state = self._udp_relay_clients.get(addr)
            if state is not None:
                self._udp_relay_drop_uid_binding(addr, room_id, int(getattr(state, "uid", 0) or 0))
                state.room = None
                state.provisional_room = None
                state.control_sent_room = None
                state.control_prime_count = 0
                state.control_prime_last = 0.0
                state.raw_ack_sent_room = None
            self._udp_relay_rooms.get(room_id, set()).discard(addr)
            log.info(
                "UDP relay pruned stale room endpoint: room=0x%08X addr=%s:%d expected=%d members_before=%d",
                room_id,
                addr[0],
                addr[1],
                expected,
                len(members),
            )
        if not self._udp_relay_rooms.get(room_id):
            self._udp_relay_rooms.pop(room_id, None)
        elif prefer is not None:
            prefer_state = self._udp_relay_clients.get(prefer)
            if (
                prefer_state is not None
                and int(getattr(prefer_state, "room", 0) or 0) == room_id
                and int(getattr(prefer_state, "uid", 0) or 0) <= 0
            ):
                rebound_uid = self._udp_relay_bind_uid_to_client(prefer_state, room_id)
                if rebound_uid > 0:
                    log.info(
                        "UDP relay room rebound uid: %s:%d -> 0x%08X uid=%d",
                        prefer[0],
                        prefer[1],
                        room_id,
                        rebound_uid,
                    )

    def _udp_relay_drop_client(self, addr: Addr) -> None:
        state = self._udp_relay_clients.pop(addr, None)
        if state is not None:
            self._udp_relay_drop_uid_binding(addr, state.room, int(getattr(state, "uid", 0) or 0))
        if state is not None and state.room is not None:
            state.control_sent_room = None
            state.control_prime_count = 0
            state.control_prime_last = 0.0
            state.raw_ack_sent_room = None
            members = self._udp_relay_rooms.get(state.room)
            if members is not None:
                members.discard(addr)
                if not members:
                    self._udp_relay_rooms.pop(state.room, None)
                    self._udp_relay_pending_room_packets.pop(state.room, None)
                    self._udp_relay_pending_room_raw_packets.pop(state.room, None)
                    self._udp_relay_pending_room_seen.pop(state.room, None)
                    self._udp_relay_pending_room_raw_seen.pop(state.room, None)
                    self._udp_relay_raw_started_rooms.discard(state.room)
                    self._udp_relay_host_bootstrap_sent = {
                        item for item in self._udp_relay_host_bootstrap_sent if item[0] != state.room
                    }
                    self._udp_relay_missing_65_sent = {
                        item for item in self._udp_relay_missing_65_sent if item[0] != state.room
                    }
                    self._udp_relay_host_continuation_sent = {
                        item for item in self._udp_relay_host_continuation_sent if item[0] != state.room
                    }

    def udp_relay_reset_room(self, room: int, *, preserve_recent: bool = True) -> None:
        room_id = int(room or 0)
        if room_id <= 0:
            return

        members = set(self._udp_relay_rooms.pop(room_id, set()))
        self._udp_relay_uid_addr_by_room.pop(room_id, None)
        preserved = 0
        dropped = 0
        now = time.time()
        preserve_cutoff = now - self._udp_relay_idle_timeout()
        preserved_addrs: List[Addr] = []
        for addr, state in list(self._udp_relay_clients.items()):
            matches_room = (
                state.room == room_id
                or (not preserve_recent and int(getattr(state, "last_room_id", 0) or 0) == room_id)
                or (not preserve_recent and int(getattr(state, "room_role_room", 0) or 0) == room_id)
            )
            if matches_room:
                members.add(addr)
                state.control_sent_room = None
                state.control_prime_count = 0
                state.control_prime_last = 0.0
                state.raw_ack_sent_room = None
                # Keep recent endpoints roomless so the next race can still
                # match the first arriving peer against the counterpart from
                # the previous race, even if one side sends a stale wrapped
                # target for a short time after reset.
                if preserve_recent and float(getattr(state, "last_seen", 0.0) or 0.0) >= preserve_cutoff:
                    state.room = None
                    state.provisional_room = None
                    preserved_addrs.append(addr)
                    preserved += 1
                else:
                    self._udp_relay_clients.pop(addr, None)
                    dropped += 1

        if len(preserved_addrs) == 2:
            self._udp_relay_pair_sticky_peers(preserved_addrs[0], preserved_addrs[1])

        self._udp_relay_pending_room_packets.pop(room_id, None)
        self._udp_relay_pending_room_raw_packets.pop(room_id, None)
        self._udp_relay_pending_room_seen.pop(room_id, None)
        self._udp_relay_pending_room_raw_seen.pop(room_id, None)
        self._udp_relay_raw_started_rooms.discard(room_id)
        self._udp_relay_host_bootstrap_sent = {
            item for item in self._udp_relay_host_bootstrap_sent if item[0] != room_id
        }
        self._udp_relay_missing_65_sent = {
            item for item in self._udp_relay_missing_65_sent if item[0] != room_id
        }
        self._udp_relay_host_continuation_sent = {
            item for item in self._udp_relay_host_continuation_sent if item[0] != room_id
        }

        if members:
            log.info(
                "UDP relay room reset: room=0x%08X cleared_clients=%d preserved_endpoints=%d dropped_endpoints=%d preserve_recent=%d",
                room_id,
                len(members),
                preserved,
                dropped,
                1 if preserve_recent else 0,
            )

    def _udp_relay_cleanup_idle(self) -> None:
        timeout = self._udp_relay_idle_timeout()
        cutoff = time.time() - timeout
        stale = [addr for addr, state in self._udp_relay_clients.items() if state.last_seen < cutoff]
        for addr in stale:
            self._udp_relay_drop_client(addr)
        self._udp_relay_cleanup_pending_rooms()

    def _udp_relay_room_last_seen(self, room: int) -> float:
        room_id = int(room or 0)
        if room_id <= 0:
            return 0.0
        latest = 0.0
        members = self._udp_relay_rooms.get(room_id, set())
        for addr in members:
            state = self._udp_relay_clients.get(addr)
            if state is not None:
                latest = max(latest, float(getattr(state, "last_seen", 0.0) or 0.0))
        return latest

    def _cleanup_detached_race_users(self) -> None:
        now = time.time()
        grace = max(5.0, float(self.cfg.get("RACE_DETACHED_GRACE", 8.0) or 8.0))
        detached_grace = max(grace, float(self.cfg.get("LOBBY_DETACHED_GRACE", 20.0) or 20.0))
        active_grace_default = max(grace, min(30.0, self._udp_relay_idle_timeout()))
        active_grace = max(
            grace,
            float(self.cfg.get("RACE_DETACHED_ACTIVE_GRACE", active_grace_default) or active_grace_default),
        )
        for user in self.users.all_users():
            detached_at = float(getattr(user, "race_detached_at", 0.0) or 0.0)
            if getattr(user, "connected", True) or detached_at <= 0.0:
                continue

            game_id = int(getattr(user, "game", 0) or 0)
            if game_id <= 0:
                if (now - detached_at) >= grace:
                    self.users.remove(int(user.uid))
                continue

            game = self.games.get(game_id)
            if game is None:
                self.users.remove(int(user.uid))
                continue
            if str(getattr(game, "state", "") or "") != "ACTIVE":
                if (now - detached_at) < detached_grace:
                    continue
                game_after, removed = self.games.leave(game_id, int(user.uid))
                user.game = 0
                self.users.remove(int(user.uid))
                self.request_master_stat_refresh()
                helper = self._admin_any_handler()
                if helper is not None:
                    helper._lobby_on_game_departure(game or game_after, departed_uid=int(user.uid), removed=removed)
                elif game_after is None:
                    self.udp_relay_reset_room(game_id)
                log.info(
                    "Detached lobby cleanup: uid=%d game=%d removed=%d grace=%d",
                    int(user.uid),
                    game_id,
                    int(removed),
                    int(detached_grace),
                )
                continue

            room_last_seen = self._udp_relay_room_last_seen(game_id)
            last_activity = max(detached_at, room_last_seen)
            if (now - last_activity) < active_grace:
                continue

            game_after, removed = self.games.leave(game_id, int(user.uid))
            user.game = 0
            self.users.remove(int(user.uid))
            self.request_master_stat_refresh()
            helper = self._admin_any_handler()
            if helper is not None:
                helper._lobby_on_game_departure(game or game_after, departed_uid=int(user.uid), removed=removed)
            else:
                self.udp_relay_reset_room(game_id)
            log.info(
                "Detached race cleanup: uid=%d game=%d removed=%d last_udp_age=%d active_grace=%d",
                int(user.uid),
                game_id,
                int(removed),
                int(now - room_last_seen) if room_last_seen > 0 else -1,
                int(active_grace),
            )

    def _udp_relay_send(self, data: bytes, addr: Addr) -> None:
        relay_sock = self._udp_relay_sock_for_addr(addr)
        if relay_sock is None:
            return
        try:
            relay_sock.sendto(data, addr)
        except OSError as exc:
            log.debug("UDP relay send failed to %s:%d: %s", addr[0], addr[1], exc)

        if not self._udp_relay_is_forced_same_host_endpoint(addr):
            return

        alias_addrs: List[Addr] = []
        if addr[0] != "127.0.0.1":
            alias_addrs.append(("127.0.0.1", int(addr[1])))

        advertised_host = self.advertised_game_host() or self.advertised_host()
        if advertised_host:
            try:
                advertised_ip = self._resolve_ipv4_host(advertised_host)
            except Exception:
                advertised_ip = ""
            if advertised_ip and advertised_ip != addr[0] and advertised_ip != "127.0.0.1":
                alias_addrs.append((advertised_ip, int(addr[1])))

        for alias in alias_addrs:
            if alias == addr:
                continue
            try:
                relay_sock.sendto(data, alias)
                if (addr, alias) not in self._udp_relay_alias_send_logged:
                    self._udp_relay_alias_send_logged.add((addr, alias))
                    log.info(
                        "UDP relay alias send enabled: dst=%s:%d alias=%s:%d",
                        addr[0],
                        addr[1],
                        alias[0],
                        alias[1],
                    )
            except OSError as exc:
                log.debug(
                    "UDP relay alias send failed to %s:%d via %s:%d: %s",
                    addr[0],
                    addr[1],
                    alias[0],
                    alias[1],
                    exc,
                )

    def _resolve_ipv4_host(self, host: str) -> str:
        raw = str(host or "").strip()
        if not raw:
            return ""
        try:
            ipaddress.IPv4Address(raw)
            return raw
        except ValueError:
            pass

        cached = self._resolved_ipv4_cache.get(raw)
        if cached:
            return cached

        try:
            infos = socket.getaddrinfo(raw, None, socket.AF_INET, socket.SOCK_DGRAM)
        except OSError as exc:
            log.warning("Failed to resolve IPv4 host '%s': %s", raw, exc)
            return raw

        for info in infos:
            sockaddr = info[4]
            if sockaddr and sockaddr[0]:
                resolved = str(sockaddr[0]).strip()
                if resolved:
                    self._resolved_ipv4_cache[raw] = resolved
                    return resolved
        return raw

    @staticmethod
    def _udp_relay_alias_ip(base_addr: str, used: Set[str]) -> str:
        try:
            ip = ipaddress.ip_address(base_addr)
        except ValueError:
            return base_addr
        if not isinstance(ip, ipaddress.IPv4Address):
            return base_addr
        if ip.is_loopback:
            for last in range(2, 255):
                candidate = f"127.0.0.{last}"
                if candidate not in used:
                    return candidate
            return base_addr
        if ip.is_private:
            network = ipaddress.ip_network(f"{base_addr}/24", strict=False)
            for host in network.hosts():
                candidate = str(host)
                if candidate == base_addr:
                    continue
                if candidate not in used:
                    return candidate
        return base_addr

    def _udp_relay_virtual_peer_mode(self) -> str:
        mode = str(self.cfg.get("RACE_VIRTUAL_PEER_MODE", "off") or "off").strip().lower()
        return mode if mode in ("off", "auto", "on") else "off"

    def _udp_relay_virtual_peer_network(self) -> Optional[ipaddress.IPv4Network]:
        raw = str(self.cfg.get("RACE_VIRTUAL_PEER_SUBNET", "100.64.0.0/24") or "100.64.0.0/24").strip()
        if not raw:
            return None
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            log.warning("Invalid RACE_VIRTUAL_PEER_SUBNET=%r; virtual peer spoof disabled", raw)
            return None
        if not isinstance(net, ipaddress.IPv4Network):
            log.warning("Non-IPv4 RACE_VIRTUAL_PEER_SUBNET=%r; virtual peer spoof disabled", raw)
            return None
        if net.prefixlen > 30:
            log.warning("Too-small RACE_VIRTUAL_PEER_SUBNET=%r; virtual peer spoof disabled", raw)
            return None
        return net

    def _udp_relay_should_virtualize_room_addrs(self, raw_addrs: List[str]) -> bool:
        mode = self._udp_relay_virtual_peer_mode()
        if mode == "off":
            return False
        if mode == "on":
            return True
        if not raw_addrs:
            return False
        unique_raw = {addr for addr in raw_addrs if addr}
        if len(unique_raw) < len(raw_addrs):
            return True
        return all(
            _udp_is_local_or_private_ip(addr) or addr.startswith("127.")
            for addr in raw_addrs
            if addr
        )

    def _udp_relay_virtual_addr_map(
        self,
        room: Optional[int],
        *,
        include: Optional[List[Addr]] = None,
    ) -> Dict[Addr, str]:
        room_id = int(room or 0)
        if room_id <= 0:
            return {}
        mode = self._udp_relay_virtual_peer_mode()
        if mode == "off":
            return {}
        net = self._udp_relay_virtual_peer_network()
        if net is None:
            return {}

        members: Set[Addr] = set(self._udp_relay_rooms.get(room_id, set()))
        for addr in include or []:
            if addr is not None:
                members.add(addr)
        if len(members) != 2:
            return {}

        sorted_members = sorted(members, key=lambda item: (item[0], int(item[1])))
        raw_ips = [addr[0] for addr in sorted_members]
        if not self._udp_relay_should_virtualize_room_addrs(raw_ips):
            return {}

        hosts = list(net.hosts())
        if len(hosts) < len(sorted_members):
            return {}
        return {addr: str(hosts[idx]) for idx, addr in enumerate(sorted_members)}

    def _udp_relay_room_lobby_endpoints(self, room: Optional[int]) -> List[UDPRelayRoomEndpoint]:
        room_id = int(room or 0)
        if room_id <= 0:
            return []
        game = self.games.get(room_id)
        if game is None:
            return []

        ordered_uids: List[int] = []
        host_uid = int(getattr(game, "host_uid", 0) or 0)
        if host_uid > 0:
            ordered_uids.append(host_uid)
        for uid in getattr(game, "participants", []) or []:
            uid_int = int(uid)
            if uid_int > 0 and uid_int not in ordered_uids:
                ordered_uids.append(uid_int)

        endpoints: List[UDPRelayRoomEndpoint] = []
        used_match: Set[str] = set()
        raw_addrs: List[str] = []
        for uid in ordered_uids:
            user = self.users.get(uid)
            if user is None:
                continue
            raw_addr = str(
                getattr(user, "laddr", "")
                or getattr(user, "addr", "")
                or getattr(user, "ip", "")
                or ""
            ).strip() or "127.0.0.1"
            match_addr = raw_addr
            alias_loopback = bool(int(self.cfg.get("RACE_LOOPBACK_ALIAS_PEERS", 0) or 0))
            # Same-host UDP is now separated by real local ports on the client
            # side. Only synthesize fake peer IPs when explicitly requested, or
            # when the virtual-peer mode is active.
            alias_duplicate = alias_loopback or self._udp_relay_virtual_peer_mode() != "off"
            if match_addr in used_match and alias_duplicate:
                match_addr = self._udp_relay_alias_ip(raw_addr, used_match)
            used_match.add(match_addr)
            raw_addrs.append(raw_addr)
            endpoints.append(
                UDPRelayRoomEndpoint(
                    uid=uid,
                    raw_ip=raw_addr,
                    match_ip=match_addr,
                    presented_ip=match_addr,
                )
            )

        if not endpoints or not self._udp_relay_should_virtualize_room_addrs(raw_addrs):
            return endpoints

        net = self._udp_relay_virtual_peer_network()
        if net is None:
            return endpoints
        hosts = list(net.hosts())
        if len(hosts) < len(endpoints):
            log.warning(
                "RACE_VIRTUAL_PEER_SUBNET=%s has only %d usable IPs for %d room endpoints; using real addresses",
                net,
                len(hosts),
                len(endpoints),
            )
            return endpoints

        for idx, endpoint in enumerate(endpoints):
            endpoint.presented_ip = str(hosts[idx])
        return endpoints

    def _udp_relay_update_spoof_ip(
        self,
        sender: UDPRelayClientState,
        room: Optional[int],
        target: Optional[Addr],
    ) -> None:
        if target is None:
            return
        if target == sender.addr:
            # During the first wrapped cmd=5 after race start, the client can
            # still point the wrapper back at itself. Do not derive/update the
            # presented peer identity from a self-target packet, otherwise the
            # stable 3658 endpoint can get overwritten with the peer's virtual
            # IP and both sides appear as the same host on wire.
            virtual_map = self._udp_relay_virtual_addr_map(room, include=[sender.addr])
            spoof_ip = virtual_map.get(sender.addr, "") if virtual_map else ""
            if spoof_ip and sender.spoof_ip != spoof_ip:
                sender.spoof_ip = spoof_ip
            return
        virtual_map = self._udp_relay_virtual_addr_map(room, include=[sender.addr, target])
        if virtual_map:
            spoof_ip = virtual_map.get(sender.addr, "")
            if spoof_ip:
                if sender.spoof_ip != spoof_ip:
                    sender.spoof_ip = spoof_ip
                    log.info(
                        "UDP relay spoof-ip set: src=%s:%d room=0x%08X ip=%s target=%s:%d",
                        sender.addr[0],
                        sender.addr[1],
                        int(room or 0),
                        spoof_ip,
                        target[0],
                        target[1],
                    )
                return
        room_endpoints = self._udp_relay_room_lobby_endpoints(room)
        if len(room_endpoints) != 2:
            return
        target_ip = str(target[0] or "").strip()
        target_idx = -1
        for idx, endpoint in enumerate(room_endpoints):
            if target_ip in (endpoint.raw_ip, endpoint.match_ip, endpoint.presented_ip):
                target_idx = idx
                break
        if target_idx < 0:
            return
        spoof_ip = room_endpoints[1 - target_idx].presented_ip
        if sender.spoof_ip != spoof_ip:
            sender.spoof_ip = spoof_ip
            log.info(
                "UDP relay spoof-ip set: src=%s:%d room=0x%08X ip=%s target=%s:%d",
                sender.addr[0],
                sender.addr[1],
                int(room or 0),
                spoof_ip,
                target[0],
                target[1],
            )

    def _udp_relay_wrapped_src(
        self,
        src: Addr,
        *,
        room: Optional[int] = None,
        target: Optional[Addr] = None,
        source_port: Optional[int] = None,
    ) -> Addr:
        state = self._udp_relay_clients.get(src)
        room_id = int(room or 0)
        virtualized_room = room_id > 0 and self._udp_relay_virtual_peer_mode() != "off"
        try:
            stable_game_port = int(self.cfg.get("UDP_GAME_PORT", 3658) or 3658)
        except Exception:
            stable_game_port = 3658
        if virtualized_room:
            out_port = stable_game_port
        elif source_port is not None and int(source_port or 0) > 0:
            out_port = int(source_port)
        else:
            same_host_pair = self._udp_relay_same_host_pair_peer(src)
            if same_host_pair is not None:
                out_port = int(src[1] or 0)
            else:
                virtual_map = self._udp_relay_virtual_addr_map(room_id, include=[src, target] if target is not None else [src])
                canonical_room_port = (
                    virtualized_room
                    and ((int(src[1] or 0) == stable_game_port) or (target is not None and int(target[1] or 0) == stable_game_port))
                )
                if (
                    target is not None
                    and str(src[0] or "") == str(target[0] or "")
                    and int(src[1] or 0) > 0
                    and int(target[1] or 0) > 0
                    and int(src[1] or 0) != int(target[1] or 0)
                ):
                    # For same-PC relay traffic the wrapped target is often the
                    # recipient endpoint. Using target's port as the presented
                    # source makes the recipient see its own port as the peer.
                    out_port = int(src[1])
                else:
                    out_port = int(target[1]) if target is not None and int(target[1] or 0) > 0 else src[1]
        if out_port is None or int(out_port or 0) <= 0:
            if target is not None and int(target[1] or 0) > 0:
                out_port = int(target[1])
            else:
                out_port = src[1]
        if state is not None and state.spoof_ip:
            if (
                not virtualized_room
                and
                target is not None
                and str(state.spoof_ip or "") == str(target[0] or "")
                and int(target[1] or 0) != stable_game_port
                and int(src[1] or 0) > 0
                and int(src[1] or 0) != int(target[1] or 0)
            ):
                out_port = int(src[1])
            return state.spoof_ip, out_port

        if not _udp_is_local_or_private_ip(src[0]):
            return src[0], out_port

        advertised_host = self.advertised_game_host()
        if not advertised_host:
            return src[0], out_port

        return self._resolve_ipv4_host(advertised_host), out_port

    def _udp_relay_send_wrapped_control(self, wrapped_src: Addr, dst: Addr, cmd: int, room: int) -> None:
        # The captured UDP bootstrap responds to cmd=1 with cmd=2,w1=0. Keep the
        # logical room for routing/logging, but mirror that payload shape.
        payload_room = 0 if cmd == 2 else room
        try:
            out = _udp_make_wrapped(wrapped_src, struct.pack("<II", cmd, payload_room))
        except ValueError as exc:
            log.warning(
                "UDP relay wrapped control failed for %s:%d -> %s:%d cmd=%d room=0x%08X: %s",
                wrapped_src[0],
                wrapped_src[1],
                dst[0],
                dst[1],
                cmd,
                room,
                exc,
            )
            return
        self._udp_relay_send(out, dst)
        log.info(
            "UDP room control(wrapped): src=%s:%d dst=%s:%d wrap=%s:%d cmd=%d room=0x%08X payload_room=0x%08X",
            wrapped_src[0],
            wrapped_src[1],
            dst[0],
            dst[1],
            wrapped_src[0],
            wrapped_src[1],
            cmd,
            room,
            payload_room,
        )

    @staticmethod
    def _lobby_aux_fields(aux_text: str) -> Dict[str, str]:
        text = str(aux_text or "").strip()
        if not text:
            return {}
        if "%" in text:
            try:
                from urllib.parse import unquote

                text = unquote(text)
            except Exception:
                pass
        out: Dict[str, str] = {}
        for line in text.replace("\r", "").split("\n"):
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip()
        return out

    @staticmethod
    def _udp_relay_lobby_aux_bootstrap_packets(aux_text: str) -> List[bytes]:
        fields = GameServer._lobby_aux_fields(aux_text)
        car_state = fields.get("C", "")
        if not car_state.startswith("281DC"):
            return []

        encoded = car_state[5:]
        try:
            car_data = base64.b64decode(encoded + ("=" * ((4 - len(encoded) % 4) % 4)))
        except Exception:
            return []
        if len(car_data) < 357:
            return []

        seq = 0x64
        packets = [
            struct.pack("<II", 0x65, seq)
            + bytes.fromhex(
                "00000000000000000000000002000fa0000100000001000000030000d38ec600d38ec60000000045"
            ),
            struct.pack("<III", 0x66, seq, 0x02040101)
            + b"\xf8\x00\x00\x00\x02\x01\x02"
            + car_data[0:89]
            + b"\x05",
            struct.pack("<III", 0x67, seq, 0x02040201)
            + b"\xf8"
            + car_data[89:184]
            + b"\x05",
            struct.pack("<III", 0x68, seq, 0x02040301)
            + b"\xf8"
            + car_data[184:279]
            + b"\x05",
            struct.pack("<III", 0x69, seq, 0x02040401)
            + b"\xac"
            + car_data[279:357]
            + bytes.fromhex("0064e414d453132005"),
        ]
        return packets

    def _udp_relay_host_aux_bootstrap_packets(self, room: int) -> List[bytes]:
        game = self.games.get(int(room or 0))
        if game is None:
            return []
        host_uid = int(getattr(game, "host_uid", 0) or 0)
        if host_uid <= 0:
            return []
        host_user = self.users.get(host_uid)
        if host_user is None:
            return []
        return self._udp_relay_lobby_aux_bootstrap_packets(str(getattr(host_user, "aux", "") or ""))

    def _udp_relay_user_aux_bootstrap_packets(self, uid: int) -> List[bytes]:
        user = self.users.get(int(uid or 0))
        if user is None:
            return []
        return self._udp_relay_lobby_aux_bootstrap_packets(str(getattr(user, "aux", "") or ""))

    def _udp_relay_inject_missing_65_from_sender(
        self,
        room: int,
        sender: UDPRelayClientState,
        wrapped_src: Addr,
        recipients: Set[Addr],
    ) -> None:
        room_id = int(room or 0)
        sender_uid = int(getattr(sender, "uid", 0) or 0)
        if room_id <= 0 or sender_uid <= 0 or not recipients:
            return
        packets = self._udp_relay_user_aux_bootstrap_packets(sender_uid)
        if not packets:
            log.info(
                "UDP relay missing-65 unavailable: room=0x%08X src=%s:%d uid=%d",
                room_id,
                sender.addr[0],
                sender.addr[1],
                sender_uid,
            )
            return
        payload65 = packets[0]
        sent = 0
        for dst in recipients:
            if dst == sender.addr:
                continue
            inject_key = (room_id, sender.addr, dst)
            if inject_key in self._udp_relay_missing_65_sent:
                continue
            try:
                out = _udp_make_wrapped(wrapped_src, payload65)
            except ValueError as exc:
                log.warning(
                    "UDP relay missing-65 wrap failed: room=0x%08X src=%s:%d dst=%s:%d uid=%d: %s",
                    room_id,
                    sender.addr[0],
                    sender.addr[1],
                    dst[0],
                    dst[1],
                    sender_uid,
                    exc,
                )
                return
            self._udp_relay_send(out, dst)
            self._udp_relay_missing_65_sent.add(inject_key)
            sent += 1
        if sent:
            first_word = _udp_read_u32_le(payload65, 0) if len(payload65) >= 4 else 0
            log.info(
                "UDP relay injected missing-65: room=0x%08X src=%s:%d wrap=%s:%d uid=%d recipients=%d first=0x%08X",
                room_id,
                sender.addr[0],
                sender.addr[1],
                wrapped_src[0],
                wrapped_src[1],
                sender_uid,
                sent,
                first_word,
            )

    def _udp_relay_inject_host_aux_bootstrap(self, room: int, host_addr: Addr, dst: Addr) -> None:
        room_id = int(room or 0)
        if room_id <= 0 or host_addr == dst:
            return
        inject_key = (room_id, host_addr, dst)
        if inject_key in self._udp_relay_host_bootstrap_sent:
            return

        packets = self._udp_relay_host_aux_bootstrap_packets(room_id)
        if not packets:
            log.info(
                "UDP relay host aux bootstrap unavailable: room=0x%08X host=%s:%d dst=%s:%d",
                room_id,
                host_addr[0],
                host_addr[1],
                dst[0],
                dst[1],
            )
            return

        wrapped_src = self._udp_relay_wrapped_src(
            host_addr,
            room=room_id,
            target=dst,
            source_port=host_addr[1],
        )
        sent = 0
        for payload in packets:
            try:
                out = _udp_make_wrapped(wrapped_src, payload)
            except ValueError as exc:
                log.warning(
                    "UDP relay host aux bootstrap wrap failed: room=0x%08X host=%s:%d dst=%s:%d: %s",
                    room_id,
                    host_addr[0],
                    host_addr[1],
                    dst[0],
                    dst[1],
                    exc,
                )
                return
            self._udp_relay_send(out, dst)
            sent += 1

        self._udp_relay_host_bootstrap_sent.add(inject_key)
        first_word = _udp_read_u32_le(packets[0], 0) if packets and len(packets[0]) >= 4 else 0
        log.info(
            "UDP relay injected host aux bootstrap: room=0x%08X host=%s:%d wrap=%s:%d dst=%s:%d packets=%d first=0x%08X",
            room_id,
            host_addr[0],
            host_addr[1],
            wrapped_src[0],
            wrapped_src[1],
            dst[0],
            dst[1],
            sent,
            first_word,
        )

    def _udp_relay_host_continuation_packets(self) -> List[bytes]:
        # Small host-side continuation observed in a working two-client local
        # capture. The same-PC forced-port path can miss the real host SendSocket
        # emission, so only inject this once after the peer reaches the 0x6A
        # bootstrap phase.
        hex_packets = [
            "6a0000006a0000000d0000000205",
            "6b0000006b000000",
            "6b0000006b0000000800d3900a00d390110017000045",
            "6c0000006c000000",
            "6c0000006d000000",
            "6c0000006d0000000d0000000300d391ff00d392030017000045",
            "6d0000006e000000",
            "060000006e0000000441b198943f8cc49c4843511ec1e006",
            "060000006e0000000441b220c53f95cac148435a24e02006",
            "060000006e0000000441b2b0213f9e4dd3484362a8006000d3930500d3930d0013000046",
        ]
        return [bytes.fromhex(item) for item in hex_packets]

    def _udp_relay_inject_host_continuation(self, room: int, host_addr: Addr, dst: Addr) -> None:
        room_id = int(room or 0)
        if room_id <= 0 or host_addr == dst:
            return
        inject_key = (room_id, host_addr, dst)
        if inject_key in self._udp_relay_host_continuation_sent:
            return

        packets = self._udp_relay_host_continuation_packets()
        wrapped_src = self._udp_relay_wrapped_src(
            host_addr,
            room=room_id,
            target=dst,
            source_port=host_addr[1],
        )
        sent = 0
        for payload in packets:
            try:
                out = _udp_make_wrapped(wrapped_src, payload)
            except ValueError as exc:
                log.warning(
                    "UDP relay host continuation wrap failed: room=0x%08X host=%s:%d dst=%s:%d: %s",
                    room_id,
                    host_addr[0],
                    host_addr[1],
                    dst[0],
                    dst[1],
                    exc,
                )
                return
            self._udp_relay_send(out, dst)
            sent += 1

        self._udp_relay_host_continuation_sent.add(inject_key)
        first_word = _udp_read_u32_le(packets[0], 0) if packets and len(packets[0]) >= 4 else 0
        log.info(
            "UDP relay injected host continuation: room=0x%08X host=%s:%d wrap=%s:%d dst=%s:%d packets=%d first=0x%08X",
            room_id,
            host_addr[0],
            host_addr[1],
            wrapped_src[0],
            wrapped_src[1],
            dst[0],
            dst[1],
            sent,
            first_word,
        )

    def _udp_relay_bootstrap_single_room_peer(
        self,
        sender: UDPRelayClientState,
        room: int,
        cmd: int,
    ) -> bool:
        if cmd not in (1, 5):
            return False
        if sender.control_sent_room != room:
            sender.control_prime_count = 0
            sender.control_prime_last = 0.0
        now = time.time()
        if sender.control_prime_count >= 3 and (now - sender.control_prime_last) < 0.75:
            return False

        endpoints = self._udp_relay_room_lobby_endpoints(room)
        if len(endpoints) < 2:
            return False

        src_ip = str(sender.addr[0] or "")
        peer_ip = ""
        for endpoint in endpoints:
            candidates = {
                str(endpoint.raw_ip or ""),
                str(endpoint.match_ip or ""),
                str(endpoint.presented_ip or ""),
            }
            if src_ip not in candidates:
                peer_ip = str(endpoint.presented_ip or endpoint.match_ip or endpoint.raw_ip or "")
                break
        if not peer_ip:
            peer_ip = str(endpoints[-1].presented_ip or endpoints[-1].match_ip or endpoints[-1].raw_ip or "")
        if not peer_ip:
            return False

        peer_addr: Optional[Addr] = None
        idle_cutoff = time.time() - self._udp_relay_idle_timeout()
        recent_room_peers = [
            (float(getattr(state, "last_seen", 0.0) or 0.0), addr)
            for addr, state in self._udp_relay_clients.items()
            if addr != sender.addr
            and int(getattr(state, "room", 0) or 0) == int(room or 0)
            and float(getattr(state, "last_seen", 0.0) or 0.0) >= idle_cutoff
        ]
        if recent_room_peers:
            recent_room_peers.sort(reverse=True)
            peer_addr = recent_room_peers[0][1]

        for candidate in self._udp_relay_recent_roomless_candidates(
            sender.addr,
            room,
            cmd,
        ):
            if peer_addr is not None:
                break
            if candidate == sender.addr:
                continue
            peer_addr = candidate
            break
        bound_peer = self._udp_relay_guess_peer_by_uid_binding(sender.addr, room)
        if bound_peer is not None and peer_addr is None:
            peer_addr = bound_peer
            log.info(
                "UDP relay guessed peer by uid-binding: src=%s:%d room=0x%08X guessed=%s:%d",
                sender.addr[0],
                sender.addr[1],
                room,
                bound_peer[0],
                bound_peer[1],
            )
        if peer_addr is None:
            paired = self._udp_relay_same_host_pair_peer(sender.addr)
            if paired is not None:
                paired_state = self._udp_relay_clients.get(paired)
                if self._udp_relay_forced_peer_is_stale(sender.addr, paired, paired_state, room):
                    log.info(
                        "UDP relay skipped stale same-host port-pair: src=%s:%d room=0x%08X guessed=%s:%d",
                        sender.addr[0],
                        sender.addr[1],
                        room,
                        paired[0],
                        paired[1],
                    )
                else:
                    peer_addr = paired
                    log.info(
                        "UDP relay guessed peer by same-host port-pair: src=%s:%d room=0x%08X guessed=%s:%d",
                        sender.addr[0],
                        sender.addr[1],
                        room,
                        paired[0],
                        paired[1],
                    )
        if peer_addr is None:
            recent = [
                (float(getattr(state, "last_seen", 0.0) or 0.0), addr)
                for addr, state in self._udp_relay_clients.items()
                if addr != sender.addr
                and float(getattr(state, "last_seen", 0.0) or 0.0) >= idle_cutoff
            ]
            if recent:
                recent.sort(reverse=True)
                peer_addr = recent[0][1]

        peer_port = 3658
        if peer_addr is not None:
            peer_state = self._udp_relay_clients.get(peer_addr)
            if peer_state is not None:
                self._udp_relay_move_client_to_room(peer_state, room, provisional=True)
                if peer_ip and peer_state.spoof_ip != peer_ip:
                    peer_state.spoof_ip = peer_ip
                self._udp_relay_note_peer(sender.addr, peer_addr)
            peer_port = int(peer_addr[1] or 0) or peer_port

        peer_src = (peer_ip, peer_port)
        if cmd == 1:
            self._udp_relay_send_wrapped_control(peer_src, sender.addr, 5, 0)
            self._udp_relay_send_wrapped_control(peer_src, sender.addr, 2, room)
            if peer_addr is not None:
                sender_src = self._udp_relay_wrapped_src(
                    sender.addr,
                    room=room,
                    target=peer_addr,
                    source_port=sender.addr[1],
                )
                self._udp_relay_send_wrapped_control(sender_src, peer_addr, 1, 0)
                self._udp_relay_send_wrapped_control(sender_src, peer_addr, 5, 0)
                self._udp_relay_send_wrapped_control(sender_src, peer_addr, 2, room)
        else:
            self._udp_relay_send_wrapped_control(peer_src, sender.addr, 2, room)
        sender.control_prime_count += 1
        sender.control_prime_last = now
        sender.control_sent_room = room
        sender.raw_ack_sent_room = room
        log.info(
            "UDP room bootstrap(single-peer): src=%s:%d peer=%s:%d real_peer=%s:%s cmd=%d room=0x%08X attempt=%d",
            sender.addr[0],
            sender.addr[1],
            peer_src[0],
            peer_src[1],
            peer_addr[0] if peer_addr is not None else "-",
            peer_addr[1] if peer_addr is not None else "-",
            cmd,
            room,
            sender.control_prime_count,
        )
        return True

    def _udp_relay_guess_recipient(self, src: Addr, room: Optional[int], target: Optional[Addr]) -> Optional[Addr]:
        now = time.time()
        recent_cutoff = now - 8.0
        candidates: list[Addr] = []
        if room not in (None, 0, 0xFFFFFFFF):
            bound_peer = self._udp_relay_guess_peer_by_uid_binding(src, room)
            if bound_peer is not None:
                log.info(
                    "UDP relay guessed peer by uid-binding: src=%s:%d room=0x%08X guessed=%s:%d target=%s:%s",
                    src[0],
                    src[1],
                    int(room),
                    bound_peer[0],
                    bound_peer[1],
                    target[0] if target is not None else '-',
                    target[1] if target is not None else '-',
                )
                return bound_peer
            for addr, state in self._udp_relay_clients.items():
                if addr == src:
                    continue
                if state.room == room:
                    candidates.append(addr)
            if len(candidates) == 1:
                return candidates[0]
            if not candidates:
                unknown = []
                unknown_recent = []
                for addr, state in self._udp_relay_clients.items():
                    if addr == src or state.room not in (None, 0, 0xFFFFFFFF):
                        continue
                    unknown.append(addr)
                    if float(getattr(state, "last_seen", 0.0) or 0.0) >= recent_cutoff:
                        unknown_recent.append(addr)
                if len(unknown_recent) == 1:
                    guessed = unknown_recent[0]
                    state = self._udp_relay_clients.get(guessed)
                    if state is not None:
                        self._udp_relay_move_client_to_room(state, int(room), provisional=True)
                    log.info(
                        "UDP relay guessed peer by recent-roomless: src=%s:%d room=0x%08X guessed=%s:%d target=%s:%s",
                        src[0],
                        src[1],
                        int(room),
                        guessed[0],
                        guessed[1],
                        target[0] if target is not None else '-',
                        target[1] if target is not None else '-',
                    )
                    return guessed
                if len(unknown) == 1:
                    guessed = unknown[0]
                    state = self._udp_relay_clients.get(guessed)
                    if state is not None:
                        self._udp_relay_move_client_to_room(state, int(room), provisional=True)
                    log.info(
                        "UDP relay guessed peer by room: src=%s:%d room=0x%08X guessed=%s:%d target=%s:%s",
                        src[0],
                        src[1],
                        int(room),
                        guessed[0],
                        guessed[1],
                        target[0] if target is not None else '-',
                        target[1] if target is not None else '-',
                    )
                    return guessed
        paired = self._udp_relay_same_host_pair_peer(src)
        if paired is not None:
            paired_state = self._udp_relay_clients.get(paired)
            if self._udp_relay_forced_peer_is_stale(src, paired, paired_state, room):
                log.info(
                    "UDP relay skipped stale same-host port-pair: src=%s:%d room=%s guessed=%s:%d target=%s:%s",
                    src[0],
                    src[1],
                    f"0x{int(room):08X}" if room not in (None, 0, 0xFFFFFFFF) else '-',
                    paired[0],
                    paired[1],
                    target[0] if target is not None else '-',
                    target[1] if target is not None else '-',
                )
                return None
            log.info(
                "UDP relay guessed peer by same-host port-pair: src=%s:%d room=%s guessed=%s:%d target=%s:%s",
                src[0],
                src[1],
                f"0x{int(room):08X}" if room not in (None, 0, 0xFFFFFFFF) else '-',
                paired[0],
                paired[1],
                target[0] if target is not None else '-',
                target[1] if target is not None else '-',
            )
            return paired
        others_recent = [
            addr
            for addr, state in self._udp_relay_clients.items()
            if addr != src and float(getattr(state, "last_seen", 0.0) or 0.0) >= recent_cutoff
        ]
        if len(others_recent) == 1:
            guessed = others_recent[0]
            log.info(
                "UDP relay guessed peer globally-recent: src=%s:%d room=%s guessed=%s:%d target=%s:%s",
                src[0],
                src[1],
                f"0x{int(room):08X}" if room not in (None, 0, 0xFFFFFFFF) else '-',
                guessed[0],
                guessed[1],
                target[0] if target is not None else '-',
                target[1] if target is not None else '-',
            )
            return guessed
        others = [addr for addr in self._udp_relay_clients if addr != src]
        if len(others) == 1:
            guessed = others[0]
            log.info(
                "UDP relay guessed peer globally: src=%s:%d room=%s guessed=%s:%d target=%s:%s",
                src[0],
                src[1],
                f"0x{int(room):08X}" if room not in (None, 0, 0xFFFFFFFF) else '-',
                guessed[0],
                guessed[1],
                target[0] if target is not None else '-',
                target[1] if target is not None else '-',
            )
            return guessed
        return None

    def _udp_relay_recent_roomless_candidates(
        self,
        src: Addr,
        room: Optional[int],
        cmd: int = 0,
        exclude: Optional[Set[Addr]] = None,
    ) -> List[Addr]:
        room_id = int(room or 0)
        if room_id <= 0:
            return []

        cutoff = time.time() - 20.0
        excluded = set(exclude or ())
        ranked: List[Tuple[float, Addr]] = []
        role_preferred: List[Tuple[float, Addr]] = []
        preferred: List[Tuple[float, Addr]] = []
        room_matched: List[Tuple[float, Addr]] = []
        for addr, state in self._udp_relay_clients.items():
            if addr == src or addr in excluded:
                continue
            if state.room not in (None, 0, 0xFFFFFFFF):
                continue
            last_seen = float(getattr(state, "last_seen", 0.0) or 0.0)
            if last_seen < cutoff:
                continue
            ranked.append((last_seen, addr))
            if (
                int(getattr(state, "room_role_room", 0) or 0) == room_id
                or int(getattr(state, "last_room_id", 0) or 0) == room_id
            ):
                room_matched.append((
                    float(
                        max(
                            getattr(state, "last_room_cmd_at", 0.0) or 0.0,
                            last_seen,
                        )
                    ),
                    addr,
                ))
            if (
                cmd in (1, 5)
                and int(getattr(state, "room_role_room", 0) or 0) == room_id
                and int(getattr(state, "room_role_cmd", 0) or 0) in (1, 5)
                and int(getattr(state, "room_role_cmd", 0) or 0) != cmd
            ):
                role_preferred.append((
                    float(getattr(state, "last_room_cmd_at", 0.0) or last_seen),
                    addr,
                ))
            if (
                cmd in (1, 5)
                and int(getattr(state, "last_room_id", 0) or 0) == room_id
                and int(getattr(state, "last_room_cmd", 0) or 0) in (1, 5)
                and int(getattr(state, "last_room_cmd", 0) or 0) != cmd
            ):
                preferred.append((
                    float(getattr(state, "last_room_cmd_at", 0.0) or last_seen),
                    addr,
                ))

        if role_preferred:
            role_preferred.sort(key=lambda item: item[0], reverse=True)
            return [role_preferred[0][1]]

        if preferred:
            preferred.sort(key=lambda item: item[0], reverse=True)
            return [preferred[0][1]]

        if room_matched:
            room_matched.sort(key=lambda item: item[0], reverse=True)
            return [room_matched[0][1]]

        ranked.sort(key=lambda item: item[0], reverse=True)
        return [addr for _, addr in ranked[:1]]

    def _udp_relay_extra_prime_roomless_candidates(
        self,
        src: Addr,
        room: Optional[int],
        target: Optional[Addr],
        cmd: int,
    ) -> List[Addr]:
        room_id = int(room or 0)
        if room_id <= 0 or cmd not in (1, 5):
            return []
        if target is None:
            return []

        target_state = self._udp_relay_clients.get(target)
        if target_state is None:
            return []
        if target_state.room not in (None, 0, 0xFFFFFFFF):
            return []

        cutoff = time.time() - 20.0
        ranked: List[Tuple[float, Addr]] = []
        for addr, state in self._udp_relay_clients.items():
            if addr in (src, target):
                continue
            if state.room not in (None, 0, 0xFFFFFFFF):
                continue
            last_seen = float(getattr(state, "last_seen", 0.0) or 0.0)
            if last_seen < cutoff:
                continue
            if int(getattr(state, "room_role_room", 0) or 0) != room_id and int(getattr(state, "last_room_id", 0) or 0) != room_id:
                continue
            ranked.append((last_seen, addr))

        ranked.sort(key=lambda item: item[0], reverse=True)
        return [addr for _, addr in ranked[:1]]

    def _udp_relay_replay_pending_room_packets(self, room: int, dst: Addr) -> None:
        pending = self._udp_relay_pending_room_packets.pop(room, [])
        self._udp_relay_pending_room_seen.pop(room, None)
        for src, payload in pending:
            cmd = _udp_read_u32_le(payload, 0) if len(payload) >= 4 else 0
            wrapped_src = self._udp_relay_wrapped_src(
                src,
                room=room,
                target=dst,
                source_port=src[1],
            )
            try:
                out = _udp_make_wrapped(wrapped_src, payload)
            except ValueError as exc:
                log.warning(
                    "UDP room replay wrap failed for %s:%d -> %s:%d room=0x%08X: %s",
                    src[0],
                    src[1],
                    dst[0],
                    dst[1],
                    room,
                    exc,
                )
                continue
            self._udp_relay_send(out, dst)
            if cmd == 1:
                dst_state = self._udp_relay_clients.get(dst)
                if dst_state is not None:
                    self._udp_relay_update_spoof_ip(dst_state, room, src)
                peer_control_src = self._udp_relay_wrapped_src(
                    dst,
                    room=room,
                    target=src,
                    source_port=dst[1],
                )
                self._udp_relay_send_wrapped_control(peer_control_src, src, 2, room)
                src_state = self._udp_relay_clients.get(src)
                if src_state is not None:
                    src_state.control_prime_count = max(1, int(getattr(src_state, "control_prime_count", 0) or 0))
                    src_state.control_prime_last = time.time()
                    src_state.control_sent_room = room
                    src_state.raw_ack_sent_room = room
            log.info(
                "UDP room replayed(pending): src=%s:%d wrap=%s:%d cmd=%d room=0x%08X dst=%s:%d",
                src[0],
                src[1],
                wrapped_src[0],
                wrapped_src[1],
                cmd,
                room,
                dst[0],
                dst[1],
            )

    def _udp_relay_replay_pending_room_raw_packets(self, room: int, dst: Addr) -> None:
        pending = self._udp_relay_pending_room_raw_packets.get(room, [])
        if not pending:
            return
        keep: List[Tuple[Addr, bytes]] = []
        replayed = 0
        for src, payload in pending:
            if src == dst or src not in self._udp_relay_clients:
                keep.append((src, payload))
                continue
            wrapped_src = self._udp_relay_wrapped_src(
                src,
                room=room,
                target=dst,
                source_port=src[1],
            )
            try:
                out = _udp_make_wrapped(wrapped_src, payload)
            except ValueError as exc:
                log.warning(
                    "UDP relay raw pending wrap failed for %s:%d -> %s:%d room=0x%08X: %s",
                    src[0],
                    src[1],
                    dst[0],
                    dst[1],
                    room,
                    exc,
                )
                keep.append((src, payload))
                continue
            self._udp_relay_send(out, dst)
            state = self._udp_relay_clients.get(src)
            if state is not None:
                state.packets_out += 1
            first_word = _udp_read_u32_le(payload, 0) if len(payload) >= 4 else 0
            log.info(
                "UDP relay replayed(raw pending): src=%s:%d wrap=%s:%d len=%d w0=0x%08X room=0x%08X dst=%s:%d",
                src[0],
                src[1],
                wrapped_src[0],
                wrapped_src[1],
                len(payload),
                first_word,
                room,
                dst[0],
                dst[1],
            )
            replayed += 1
        if keep:
            self._udp_relay_pending_room_raw_packets[room] = keep
            self._udp_relay_pending_room_raw_seen[room] = time.time()
        else:
            self._udp_relay_pending_room_raw_packets.pop(room, None)
            self._udp_relay_pending_room_raw_seen.pop(room, None)
        if replayed:
            log.info(
                "UDP relay replayed(raw pending batch): room=0x%08X dst=%s:%d count=%d",
                room,
                dst[0],
                dst[1],
                replayed,
            )

    def _udp_relay_infer_room(self, sender: UDPRelayClientState, payload: bytes) -> Optional[int]:
        if len(payload) < 8:
            return None
        cmd = _udp_read_u32_le(payload, 0)
        raw_opcode = cmd & 0xFF
        rawish = cmd == 0x00010108 or 0x65 <= raw_opcode <= 0x7F
        if cmd in (1, 5):
            room = _udp_read_u32_le(payload, 4)
            if room not in (0, 0xFFFFFFFF):
                return room
        elif not rawish:
            if sender.room not in (None, 0, 0xFFFFFFFF):
                return sender.room
            return None
        active = self.games.active_games()
        if len(active) == 1:
            active_room = int(active[0].id)
            if sender.room not in (None, 0, 0xFFFFFFFF) and int(sender.room) != active_room:
                log.info(
                    "UDP room inference overriding stale sender room: src=%s:%d stale=0x%08X active=0x%08X",
                    sender.addr[0],
                    sender.addr[1],
                    int(sender.room),
                    active_room,
                )
            return active_room
        candidates = [g for g in self.games.list_games() if g.state in ("OPEN", "ACTIVE") and g.count >= 2]
        if len(candidates) == 1:
            candidate_room = int(candidates[0].id)
            if sender.room not in (None, 0, 0xFFFFFFFF) and int(sender.room) != candidate_room:
                log.info(
                    "UDP room inference overriding stale sender room: src=%s:%d stale=0x%08X candidate=0x%08X",
                    sender.addr[0],
                    sender.addr[1],
                    int(sender.room),
                    candidate_room,
                )
            return candidate_room
        if sender.room not in (None, 0, 0xFFFFFFFF):
            return sender.room
        if len(self._udp_relay_pending_room_packets) == 1:
            inferred = next(iter(self._udp_relay_pending_room_packets))
            if inferred not in (0, 0xFFFFFFFF):
                return inferred
        if len(self._udp_relay_pending_room_raw_packets) == 1:
            inferred = next(iter(self._udp_relay_pending_room_raw_packets))
            if inferred not in (0, 0xFFFFFFFF):
                return inferred
        if len(self._udp_relay_rooms) == 1:
            inferred = next(iter(self._udp_relay_rooms))
            if inferred not in (0, 0xFFFFFFFF):
                return inferred
        return None

    def _udp_relay_handle_datagram(self, data: bytes, src: Addr, relay_listen_port: int = 0) -> None:
        sender = self._udp_relay_touch_client(src, relay_listen_port)
        if sender is None:
            return
        decoded = _udp_maybe_decode_wrapped(data)
        payload = data
        target: Optional[Addr] = None
        if decoded is not None:
            decoded_target, decoded_payload = decoded
            if self._udp_relay_wrapped_target_is_plausible(decoded_target):
                target = decoded_target
                payload = decoded_payload
                stripped = 0
                while True:
                    nested = _udp_maybe_decode_wrapped(payload)
                    if nested is None:
                        break
                    nested_target, nested_payload = nested
                    if nested_target != target:
                        break
                    if len(nested_payload) < 4:
                        break
                    nested_cmd = _udp_read_u32_le(nested_payload, 0)
                    nested_opcode = nested_cmd & 0xFF
                    if nested_cmd not in (1, 2, 3, 4, 5) and not (0x65 <= nested_opcode <= 0x7F):
                        break
                    payload = nested_payload
                    stripped += 1
                if stripped:
                    first_word = _udp_read_u32_le(payload, 0) if len(payload) >= 4 else 0
                    log.info(
                        "UDP relay stripped nested wrapper: src=%s:%d target=%s:%d stripped=%d len=%d w0=0x%08X",
                        src[0],
                        src[1],
                        target[0],
                        target[1],
                        stripped,
                        len(payload),
                        first_word,
                    )
            else:
                first_word = _udp_read_u32_le(data, 0) if len(data) >= 4 else 0
                log.info(
                    "UDP relay ignore false wrapped decode: src=%s:%d target=%s:%d len=%d w0=0x%08X",
                    src[0],
                    src[1],
                    decoded_target[0],
                    decoded_target[1],
                    len(data),
                    first_word,
                )
                decoded = None
        wrapped_in = decoded is not None

        cmd = _udp_read_u32_le(payload, 0) if len(payload) >= 4 else 0
        first_opcode = cmd & 0xFF if len(payload) >= 4 else 0
        word1 = _udp_read_u32_le(payload, 4) if len(payload) >= 8 else 0
        if self._udp_relay_verbose:
            self._udp_relay_recv_log_count += 1
            if self._udp_relay_recv_log_count <= 20 or self._udp_relay_recv_log_count % 100 == 0:
                log.info(
                    "UDP relay recv: listen=%d src=%s:%d len=%d wrapped=%s target=%s:%s w0=0x%08X w1=0x%08X count=%d",
                    int(relay_listen_port or 0),
                    src[0],
                    src[1],
                    len(data),
                    wrapped_in,
                    target[0] if target is not None else "-",
                    target[1] if target is not None else "-",
                    cmd,
                    word1,
                    self._udp_relay_recv_log_count,
                )
        rawish_packet = cmd == 0x00010108 or 0x65 <= first_opcode <= 0x7F
        room = _udp_extract_room(payload)
        if room is None:
            inferred_room = self._udp_relay_infer_room(sender, payload)
            if inferred_room is not None:
                room = inferred_room
                log.info(
                    "UDP room inferred: src=%s:%d cmd=%d inferred=0x%08X explicit=0x%08X",
                    src[0],
                    src[1],
                    cmd,
                    room,
                    _udp_read_u32_le(payload, 4) if len(payload) >= 8 else 0,
                )
        if room is not None:
            if cmd in (1, 5):
                self._udp_relay_update_spoof_ip(sender, room, target)
                if sender.room_role_room != room:
                    sender.room_role_room = room
                    sender.room_role_cmd = cmd
                elif sender.room_role_cmd not in (1, 5):
                    sender.room_role_cmd = cmd
                sender.last_room_cmd = cmd
                sender.last_room_id = room
                sender.last_room_cmd_at = time.time()
            self._udp_relay_move_client_to_room(sender, room, provisional=False)
            log.info(
                "UDP room pkt: src=%s:%d cmd=%d room=0x%08X wrapped=%s target=%s:%s",
                src[0],
                src[1],
                cmd,
                room,
                wrapped_in,
                target[0] if target is not None else "-",
                target[1] if target is not None else "-",
            )
            if rawish_packet:
                if first_opcode == 0x65 and len(payload) < 48 and room not in self._udp_relay_raw_started_rooms:
                    log.info(
                        "UDP room raw short-prestart ignored: src=%s:%d room=0x%08X len=%d wrapped=%s w0=0x%08X w1=0x%08X",
                        src[0],
                        src[1],
                        int(room),
                        len(payload),
                        wrapped_in,
                        cmd,
                        word1,
                    )
                    return
                if first_opcode == 0x65 and len(payload) >= 48:
                    sender.raw_real_65_rooms.add(int(room))
                sender.raw_sent_rooms.add(int(room))
                prestart_allowed = first_opcode in (1, 2, 3, 4, 5, 0x65, 0x66, 0x67)
                if room not in self._udp_relay_raw_started_rooms:
                    raw_head_hex = payload[: min(len(payload), 64)].hex()
                    if not prestart_allowed:
                        log.info(
                            "UDP room raw-started(late): room=0x%08X src=%s:%d len=%d wrapped=%s w0=0x%08X w1=0x%08X hex=%s",
                            room,
                            src[0],
                            src[1],
                            len(payload),
                            wrapped_in,
                            cmd,
                            word1,
                            raw_head_hex,
                        )
                    else:
                        log.info(
                            "UDP room raw-started: room=0x%08X src=%s:%d len=%d wrapped=%s w0=0x%08X w1=0x%08X hex=%s",
                            room,
                            src[0],
                            src[1],
                            len(payload),
                            wrapped_in,
                            cmd,
                            word1,
                            raw_head_hex,
                        )
                    self._udp_relay_raw_started_rooms.add(int(room))
                    if 0x65 < first_opcode <= 0x69:
                        # Some tunnel runs never deliver a full 0x65 start
                        # packet; after the short prestart 0x65 probes, the
                        # first usable raw packet can be 0x66. Start ordering
                        # from the first usable opcode instead of waiting
                        # forever for 0x65.
                        sender.raw_order_next.setdefault(int(room), first_opcode)
                    self._udp_relay_replay_pending_room_raw_packets(int(room), src)
                # Once raw race traffic starts, do not inject additional cmd5/cmd2
                # control packets. They were useful for early bootstrap probing, but
                # can look like a kick/reset to the game during the race transition.
            room_members = self._udp_relay_rooms.get(room, set())
            if len(room_members) > 1 and room in self._udp_relay_pending_room_packets:
                pending = self._udp_relay_pending_room_packets.pop(room, [])
                self._udp_relay_pending_room_seen.pop(room, None)
                for pending_src, pending_payload in pending:
                    if pending_src not in self._udp_relay_clients:
                        continue
                    pending_cmd = _udp_read_u32_le(pending_payload, 0) if len(pending_payload) >= 4 else 0
                    if pending_cmd not in (1, 5):
                        continue
                    replayed = 0
                    for dst in room_members:
                        if dst == pending_src:
                            continue
                        wrapped_src = self._udp_relay_wrapped_src(
                            pending_src,
                            room=room,
                            target=dst,
                            source_port=pending_src[1],
                        )
                        try:
                            out = _udp_make_wrapped(wrapped_src, pending_payload)
                        except ValueError as exc:
                            log.warning(
                                "UDP room pending wrap failed for %s:%d via %s:%d room=0x%08X: %s",
                                pending_src[0],
                                pending_src[1],
                                wrapped_src[0],
                                wrapped_src[1],
                                room,
                                exc,
                            )
                            continue
                        self._udp_relay_send(out, dst)
                        replayed += 1
                        if pending_cmd == 1:
                            dst_state = self._udp_relay_clients.get(dst)
                            if dst_state is not None:
                                self._udp_relay_update_spoof_ip(dst_state, room, pending_src)
                            peer_control_src = self._udp_relay_wrapped_src(
                                dst,
                                room=room,
                                target=pending_src,
                                source_port=dst[1],
                            )
                            self._udp_relay_send_wrapped_control(
                                peer_control_src,
                                pending_src,
                                5,
                                0,
                            )
                            self._udp_relay_send_wrapped_control(
                                peer_control_src,
                                pending_src,
                                2,
                                room,
                            )
                            self._udp_relay_send_wrapped_control(
                                wrapped_src,
                                dst,
                                2,
                                room,
                            )
                    state = self._udp_relay_clients.get(pending_src)
                    if state is not None:
                        state.packets_out += replayed
                        if pending_cmd == 1 and replayed:
                            state.control_prime_count = max(1, int(getattr(state, "control_prime_count", 0) or 0))
                            state.control_prime_last = time.time()
                            state.control_sent_room = room
                            state.raw_ack_sent_room = room
                    if replayed:
                        log.info(
                            "UDP room pending(replayed): src=%s:%d wrap=%s:%d cmd=%d room=0x%08X peers=%d",
                            pending_src[0],
                            pending_src[1],
                            wrapped_src[0],
                            wrapped_src[1],
                            pending_cmd,
                            room,
                            replayed,
                        )
        recipients: Set[Addr] = set()
        roomless_fallback_used = False
        preferred_roomless_peer: Optional[Addr] = None
        bootstrap_target_exclude: Set[Addr] = set()
        strict_same_host_target = False
        defer_self_target_bootstrap = (
            wrapped_in
            and room is not None
            and cmd == 5
            and target is not None
            and target == src
        )
        if defer_self_target_bootstrap:
            log.info(
                "UDP relay defer self-target bootstrap: src=%s:%d cmd=%d room=0x%08X target=%s:%d",
                src[0],
                src[1],
                cmd,
                int(room or 0),
                target[0] if target is not None else "-",
                target[1] if target is not None else -1,
            )

        if wrapped_in and room is not None and cmd in (1, 5):
            if target is not None:
                if defer_self_target_bootstrap:
                    bootstrap_target_exclude.add(target)
                else:
                    same_host_pair = self._udp_relay_same_host_pair_peer(src)
                    target_state = self._udp_relay_clients.get(target)
                    target_last_seen = float(getattr(target_state, "last_seen", 0.0) or 0.0) if target_state is not None else 0.0
                    target_room_match = target_state is not None and int(getattr(target_state, "room", 0) or 0) == int(room or 0)
                    target_port = int(target[1] or 0)
                    forced_same_host_direct_target = (
                        same_host_pair is not None
                        and target == same_host_pair
                    )
                    stable_direct_target = (
                        (target_state is not None or forced_same_host_direct_target)
                        and target != src
                        and (
                            forced_same_host_direct_target
                            or (
                                target_last_seen >= (time.time() - self._udp_relay_idle_timeout())
                                and (target_room_match or target_port == 3658)
                            )
                        )
                    )
                    if stable_direct_target:
                        # After a room reset we can keep a stale ephemeral peer as the
                        # target's sticky/last-peer. If the wrapped target already
                        # points at the stable relay-side endpoint, trust it directly.
                        preferred_roomless_peer = target
                        strict_same_host_target = forced_same_host_direct_target
                        if target_state is not None and not target_room_match:
                            self._udp_relay_move_client_to_room(target_state, int(room), provisional=True)
                        self._udp_relay_note_peer(src, target)
                        recipients.add(target)
                        log.info(
                            "UDP relay preferred direct target: src=%s:%d cmd=%d room=0x%08X target=%s:%d room_match=%s forced_same_host=%s",
                            src[0],
                            src[1],
                            cmd,
                            int(room),
                            target[0],
                            target[1],
                            target_room_match,
                            forced_same_host_direct_target,
                        )
                    else:
                        bootstrap_target_exclude.add(target)
                        target_spoof_peer = self._udp_relay_recent_spoof_peer(
                            src,
                            room,
                            target,
                            exclude=bootstrap_target_exclude,
                        )
                        if target_spoof_peer is not None:
                            preferred_roomless_peer = target_spoof_peer
                            self._udp_relay_note_peer(src, target_spoof_peer)
                            recipients.add(target_spoof_peer)
                        target_last_peer = None
                        if target_state is not None and preferred_roomless_peer is None:
                            target_last_peer = self._udp_relay_recent_last_peer(
                                src,
                                getattr(target_state, "sticky_peer", None),
                                room,
                                target,
                            )
                        if target_state is not None and preferred_roomless_peer is None and target_last_peer is None:
                            target_last_peer = self._udp_relay_recent_last_peer(
                                src,
                                getattr(target_state, "last_peer", None),
                                room,
                                target,
                            )
                        if target_last_peer is not None:
                            preferred_roomless_peer = target_last_peer
                            self._udp_relay_note_peer(src, target_last_peer)
                            recipients.add(target_last_peer)
            preferred_candidates = self._udp_relay_recent_roomless_candidates(
                src,
                room,
                cmd,
                exclude=bootstrap_target_exclude,
            )
            if not defer_self_target_bootstrap and preferred_roomless_peer is None and preferred_candidates:
                candidate = preferred_candidates[0]
                if candidate != src:
                    preferred_roomless_peer = candidate
                    candidate_state = self._udp_relay_clients.get(candidate)
                    if candidate_state is not None:
                        self._udp_relay_move_client_to_room(
                            candidate_state,
                            int(room),
                            provisional=True,
                        )
                    self._udp_relay_note_peer(src, candidate)
                    recipients.add(candidate)
                    log.info(
                        "UDP relay preferred roomless peer: src=%s:%d cmd=%d room=0x%08X preferred=%s:%d target=%s:%s",
                        src[0],
                        src[1],
                        cmd,
                        int(room),
                        candidate[0],
                        candidate[1],
                        target[0] if target is not None else "-",
                        target[1] if target is not None else "-",
                    )
        bootstrap_wrapped_cmd = wrapped_in and room is not None and cmd in (1, 5)
        if (
            preferred_roomless_peer is None
            and not bootstrap_wrapped_cmd
            and target is not None
            and target in self._udp_relay_clients
            and target != src
        ):
            recipients.add(target)
        if sender.room is not None and not strict_same_host_target:
            for peer in self._udp_relay_rooms.get(sender.room, set()):
                if peer != src:
                    recipients.add(peer)
        if not recipients and not defer_self_target_bootstrap and not strict_same_host_target:
            sticky = self._udp_relay_sticky_peer(sender, room, target)
            if sticky is not None and sticky != src:
                recipients.add(sticky)
        if not recipients and not defer_self_target_bootstrap and not strict_same_host_target:
            guessed = self._udp_relay_guess_recipient(src, sender.room, target)
            if guessed is not None and guessed != src:
                recipients.add(guessed)
        if not recipients and not defer_self_target_bootstrap and not strict_same_host_target and room is not None and cmd in (1, 5):
            fallback_peers = self._udp_relay_recent_roomless_candidates(
                src,
                room,
                cmd,
                exclude=bootstrap_target_exclude,
            )
            if fallback_peers:
                roomless_fallback_used = True
                if len(fallback_peers) == 1:
                    chosen_state = self._udp_relay_clients.get(fallback_peers[0])
                    if chosen_state is not None:
                        self._udp_relay_move_client_to_room(
                            chosen_state,
                            int(room),
                            provisional=True,
                        )
                recipients.update(fallback_peers)
                peer_text = ", ".join(f"{addr[0]}:{addr[1]}" for addr in fallback_peers)
                log.info(
                    "UDP room fallback(roomless-fanout): src=%s:%d cmd=%d room=0x%08X peers=%d targets=%s target=%s:%s",
                    src[0],
                    src[1],
                    cmd,
                    room,
                    len(fallback_peers),
                    peer_text,
                    target[0] if target is not None else "-",
                    target[1] if target is not None else "-",
                )

        if room is not None and cmd in (1, 5) and len(recipients) == 1:
            hinted_peer = next(iter(recipients))
            hinted_state = self._udp_relay_clients.get(hinted_peer)
            if hinted_state is not None and hinted_state.room in (None, 0, 0xFFFFFFFF):
                self._udp_relay_move_client_to_room(hinted_state, int(room), provisional=True)
                log.info(
                    "UDP relay room hinted-peer: src=%s:%d cmd=%d room=0x%08X peer=%s:%d target=%s:%s",
                    src[0],
                    src[1],
                    cmd,
                    room,
                    hinted_peer[0],
                    hinted_peer[1],
                    target[0] if target is not None else "-",
                    target[1] if target is not None else "-",
                )

        if room is None and sender.room not in (None, 0, 0xFFFFFFFF):
            first_word = _udp_read_u32_le(payload, 0) if len(payload) >= 4 else 0
            first_opcode = first_word & 0xFF if len(payload) >= 4 else 0
            if first_opcode >= 0x65:
                sender.raw_sent_rooms.add(int(sender.room))
            prestart_allowed = first_opcode in (1, 2, 3, 4, 5, 0x65, 0x66, 0x67)
            # Keep raw control packets flowing once the room is established.
            # On some runs the passive side still needs a later wrapped/raw
            # cmd=2 transition even after gameplay packets have started, and
            # suppressing it can leave the race stuck in the loading branch.
            if sender.room not in self._udp_relay_raw_started_rooms:
                if not prestart_allowed:
                    log.info(
                        "UDP room raw-started(late): room=0x%08X src=%s:%d len=%d wrapped=%s w0=0x%08X",
                        sender.room,
                        src[0],
                        src[1],
                        len(payload),
                        wrapped_in,
                        first_word,
                    )
                else:
                    log.info(
                        "UDP room raw-started: room=0x%08X src=%s:%d len=%d wrapped=%s w0=0x%08X",
                        sender.room,
                        src[0],
                        src[1],
                        len(payload),
                        wrapped_in,
                        first_word,
                    )
                self._udp_relay_raw_started_rooms.add(sender.room)
                if 0x65 < first_opcode <= 0x69:
                    sender.raw_order_next.setdefault(int(sender.room), first_opcode)
                # Replay any previously queued late raw packets from the other
                # side to the endpoint that has just entered raw mode. This is
                # the side that was missing those packets while still in the
                # pre-start control branch.
                self._udp_relay_replay_pending_room_raw_packets(sender.room, src)
                if self._udp_relay_is_forced_same_host_endpoint(src):
                    for dst in recipients:
                        if not self._udp_relay_is_forced_same_host_endpoint(dst):
                            continue
                        if dst[0] != src[0] or int(dst[1] or 0) >= int(src[1] or 0):
                            continue
                        # In the same-PC two-client path the host instance is
                        # pinned to the lower forced port. If it never emits
                        # the large 0x65..0x69 race init block, inject it from
                        # the host's aux/car-state payload so the peer can
                        # leave the pre-race bootstrap loop.
                        self._udp_relay_inject_host_aux_bootstrap(int(sender.room), dst, src)
            elif wrapped_in and len(payload) == 8 and first_word == 2:
                log.info(
                    "UDP room raw-control-pass: room=0x%08X src=%s:%d len=%d w0=0x%08X started=%s",
                    sender.room,
                    src[0],
                    src[1],
                    len(payload),
                    first_word,
                    sender.room in self._udp_relay_raw_started_rooms,
                )

            if (
                self._udp_relay_is_forced_same_host_endpoint(src)
                and first_opcode in (0x6A, 0x6B, 0x6C)
            ):
                for dst in recipients:
                    if not self._udp_relay_is_forced_same_host_endpoint(dst):
                        continue
                    if dst[0] != src[0] or int(dst[1] or 0) >= int(src[1] or 0):
                        continue
                    self._udp_relay_inject_host_continuation(int(sender.room), dst, src)
                    break

        suppress_room_relay = False
        if room is not None:
            if cmd == 1 and recipients:
                wrapped_src = self._udp_relay_wrapped_src(src, room=room, target=target)
                prime_recipients: Set[Addr] = set(recipients)
                extra_prime_recipients = self._udp_relay_extra_prime_roomless_candidates(
                    src,
                    room,
                    target,
                    cmd,
                )
                for extra_dst in extra_prime_recipients:
                    prime_recipients.add(extra_dst)
                if extra_prime_recipients:
                    extra_text = ", ".join(f"{addr[0]}:{addr[1]}" for addr in extra_prime_recipients)
                    log.info(
                        "UDP room prime-extra(roomless): src=%s:%d cmd=%d room=0x%08X extras=%s target=%s:%s",
                        src[0],
                        src[1],
                        cmd,
                        room,
                        extra_text,
                        target[0] if target is not None else "-",
                        target[1] if target is not None else "-",
                    )
                suppress_room_relay = True
                if sender.control_sent_room != room:
                    sender.control_prime_count = 0
                    sender.control_prime_last = 0.0
                raw_started = room in self._udp_relay_raw_started_rooms
                now = time.time()
                should_prime = (
                    not raw_started
                    and sender.control_prime_count < 3
                    and (
                        sender.control_sent_room != room
                        or (now - sender.control_prime_last) >= 0.75
                    )
                )
                if should_prime:
                    # Re-prime a small number of times until the first raw packet
                    # shows up. Some runs miss the initial wrapped cmd=1.
                    ambiguous_fallback = len(recipients) > 1
                    initial_prime = sender.control_sent_room != room and sender.control_prime_count == 0
                    preprime_controls_sent = False
                    prime_payload = payload
                    try:
                        out = _udp_make_wrapped(wrapped_src, prime_payload)
                    except ValueError as exc:
                        log.warning(
                            "UDP room prime wrap failed for %s:%d via %s:%d room=0x%08X: %s",
                            src[0],
                            src[1],
                            wrapped_src[0],
                            wrapped_src[1],
                            room,
                            exc,
                        )
                    else:
                        if initial_prime:
                            for dst in recipients:
                                dst_state = self._udp_relay_clients.get(dst)
                                if dst_state is not None:
                                    self._udp_relay_update_spoof_ip(dst_state, room, src)
                        send_prime_recipients = set(prime_recipients)
                        for dst in send_prime_recipients:
                            self._udp_relay_send(out, dst)
                        sender.packets_out += len(send_prime_recipients)
                        log.info(
                            "UDP room %s: src=%s:%d wrap=%s:%d cmd=%d room=0x%08X peers=%d primed=%d attempt=%d",
                            "re-primed" if sender.control_prime_count > 0 else "primed",
                            src[0],
                            src[1],
                            wrapped_src[0],
                            wrapped_src[1],
                            cmd,
                            room,
                            len(recipients),
                            len(send_prime_recipients),
                            sender.control_prime_count + 1,
                        )
                    for dst in recipients:
                        dst_state = self._udp_relay_clients.get(dst)
                        if dst_state is not None:
                            self._udp_relay_update_spoof_ip(dst_state, room, src)
                        # For local multi-instance testing, wrapped control sent
                        # back to the cmd=1 sender must present the peer with the
                        # same virtualized identity as normal room traffic. Using
                        # the incoming wrapped target here leaks the real peer IP
                        # back into the control branch and desynchronizes the race
                        # bootstrap state machine.
                        peer_control_src = self._udp_relay_wrapped_src(
                            dst,
                            room=room,
                            target=src,
                            source_port=dst[1],
                        )
                        if (
                            not ambiguous_fallback
                            and initial_prime
                            and not preprime_controls_sent
                            and sender.raw_ack_sent_room != room
                        ):
                            # This client starts sending race-state (0x65) only
                            # after seeing the peer's cmd=5 followed by cmd=2.
                            self._udp_relay_send_wrapped_control(
                                peer_control_src,
                                src,
                                5,
                                0,
                            )
                            self._udp_relay_send_wrapped_control(
                                peer_control_src,
                                src,
                                2,
                                room,
                            )
                            self._udp_relay_send_wrapped_control(
                                wrapped_src,
                                dst,
                                5,
                                0,
                            )
                            self._udp_relay_send_wrapped_control(
                                wrapped_src,
                                dst,
                                2,
                                room,
                            )
                    sender.control_prime_count += 1
                    sender.control_prime_last = now
                    sender.control_sent_room = room
                    if not ambiguous_fallback:
                        sender.raw_ack_sent_room = room
                else:
                    # After the initial priming burst, keep forwarding the
                    # periodic cmd=1 probe as wrapped room traffic. The cmd=5
                    # side can still be waiting on a later peer cmd=1 even
                    # after raw has already started, but re-sending cmd=2 here
                    # tends to pin both clients in the pre-race control loop.
                    suppress_room_relay = False
            elif cmd == 5:
                # The cmd=5 side may keep retransmitting until the peer fully
                # leaves the pre-race control branch. Once a peer exists, relay
                # those cmd=5 probes as wrapped room traffic. If this endpoint
                # has not emitted raw race packets yet, also send one peer cmd=2
                # ack; a headless bot can start raw first, leaving the stock
                # host stuck waiting for the peer-side control transition.
                try:
                    ack_cmd5_unraw = int(self.cfg.get("UDP_RELAY_ACK_CMD5_UNRAW", 1) or 0) != 0
                except Exception:
                    ack_cmd5_unraw = True
                now = time.time()
                should_ack_cmd5 = (
                    ack_cmd5_unraw
                    and recipients
                    and int(room or 0) > 0
                    and int(room) not in sender.raw_sent_rooms
                    and (
                        sender.raw_ack_sent_room != room
                        or (
                            sender.control_prime_count < 4
                            and (now - float(sender.control_prime_last or 0.0)) >= 0.5
                        )
                    )
                )
                if should_ack_cmd5:
                    peer = next(iter(recipients))
                    peer_control_src = self._udp_relay_wrapped_src(
                        peer,
                        room=room,
                        target=src,
                        source_port=peer[1],
                    )
                    self._udp_relay_send_wrapped_control(peer_control_src, src, 5, 0)
                    self._udp_relay_send_wrapped_control(peer_control_src, src, 2, room)
                    sender.raw_ack_sent_room = room
                    sender.control_prime_count += 1
                    sender.control_prime_last = now
                    log.info(
                        "UDP room cmd5 raw-ack: src=%s:%d peer=%s:%d room=0x%08X raw_started=%d attempt=%d",
                        src[0],
                        src[1],
                        peer[0],
                        peer[1],
                        int(room),
                        int(room in self._udp_relay_raw_started_rooms),
                        sender.control_prime_count,
                    )
                suppress_room_relay = not recipients

        if not recipients:
            if room is not None:
                log.info(
                    "UDP room drop(no-recipient): src=%s:%d cmd=%d room=0x%08X wrapped=%s",
                    src[0],
                    src[1],
                    cmd,
                    room,
                    wrapped_in,
                )
                if cmd in (1, 5):
                    self._udp_relay_bootstrap_single_room_peer(sender, int(room), cmd)
                    # Keep the first room-control probe around until a second
                    # peer reaches the room. Public-path races can enter the
                    # room one side at a time after post-race reset, and if we
                    # drop the early cmd=1/cmd=5 packets there is nothing left
                    # to replay once the peer finally appears.
                    room_pending = self._udp_relay_pending_list(
                        self._udp_relay_pending_room_packets,
                        self._udp_relay_pending_room_seen,
                        int(room),
                    )
                    already_saved = bool(room_pending) and any(
                        pending_src == src and pending_payload == payload for pending_src, pending_payload in room_pending
                    )
                    if room_pending is not None and not already_saved and len(room_pending) < 8:
                        room_pending.append((src, payload))
                        log.info(
                            "UDP room pending(saved): src=%s:%d cmd=%d room=0x%08X count=%d",
                            src[0],
                            src[1],
                            cmd,
                            room,
                            len(room_pending),
                        )
                    else:
                        log.info(
                            "UDP room pending(ignored): src=%s:%d cmd=%d room=0x%08X",
                            src[0],
                            src[1],
                            cmd,
                            room,
                        )
                elif rawish_packet:
                    room_raw = self._udp_relay_pending_list(
                        self._udp_relay_pending_room_raw_packets,
                        self._udp_relay_pending_room_raw_seen,
                        int(room),
                    )
                    already_saved = bool(room_raw) and any(
                        pending_src == src and pending_payload == payload for pending_src, pending_payload in room_raw
                    )
                    if room_raw is not None and not already_saved and len(room_raw) < 64:
                        room_raw.append((src, payload))
                        log.info(
                            "UDP room pending(raw saved): src=%s:%d len=%d w0=0x%08X room=0x%08X wrapped=%s target=%s:%s count=%d",
                            src[0],
                            src[1],
                            len(payload),
                            cmd,
                            int(room),
                            wrapped_in,
                            target[0] if target is not None else "-",
                            target[1] if target is not None else "-",
                            len(room_raw or []),
                        )
                    else:
                        log.info(
                            "UDP room pending(raw ignored): src=%s:%d len=%d w0=0x%08X room=0x%08X wrapped=%s target=%s:%s count=%d",
                            src[0],
                            src[1],
                            len(payload),
                            cmd,
                            int(room),
                            wrapped_in,
                            target[0] if target is not None else "-",
                            target[1] if target is not None else "-",
                            len(room_raw or []),
                        )
                else:
                    log.info(
                        "UDP room pending(ignored): src=%s:%d cmd=%d room=0x%08X",
                        src[0],
                        src[1],
                        cmd,
                        room,
                    )
            elif sender.room is not None:
                first_word = _udp_read_u32_le(payload, 0) if len(payload) >= 4 else 0
                room_raw = self._udp_relay_pending_list(
                    self._udp_relay_pending_room_raw_packets,
                    self._udp_relay_pending_room_raw_seen,
                    int(sender.room),
                )
                if room_raw is not None and len(room_raw) < 64:
                    room_raw.append((src, payload))
                    log.info(
                        "UDP relay pending(raw saved): src=%s:%d len=%d w0=0x%08X sender_room=0x%08X wrapped=%s target=%s:%s count=%d",
                        src[0],
                        src[1],
                        len(payload),
                        first_word,
                        sender.room,
                        wrapped_in,
                        target[0] if target is not None else "-",
                        target[1] if target is not None else "-",
                        len(room_raw or []),
                    )
                else:
                    log.info(
                        "UDP relay pending(raw ignored): src=%s:%d len=%d w0=0x%08X sender_room=0x%08X wrapped=%s target=%s:%s count=%d",
                        src[0],
                        src[1],
                        len(payload),
                        first_word,
                        sender.room,
                        wrapped_in,
                        target[0] if target is not None else "-",
                        target[1] if target is not None else "-",
                        len(room_raw or []),
                    )
                log.info(
                    "UDP relay drop(raw no-recipient): src=%s:%d len=%d w0=0x%08X sender_room=0x%08X wrapped=%s target=%s:%s",
                    src[0],
                    src[1],
                    len(payload),
                    first_word,
                    sender.room,
                    wrapped_in,
                    target[0] if target is not None else "-",
                    target[1] if target is not None else "-",
                )
            return

        if room is not None and suppress_room_relay:
            return

        if len(recipients) == 1:
            self._udp_relay_note_peer(src, next(iter(recipients)))

        delayed_raw_opcode = 0
        if (
            room is not None
            and rawish_packet
            and 0x65 <= first_opcode <= 0x69
        ):
            room_id = int(room)
            expected_opcode = int(sender.raw_order_next.get(room_id, 0x65) or 0x65)
            if first_opcode > expected_opcode:
                room_buffer = sender.raw_order_buffer.setdefault(room_id, {})
                if first_opcode not in room_buffer:
                    room_buffer[first_opcode] = bytes(payload)
                log.info(
                    "UDP room raw delayed(order): src=%s:%d room=0x%08X opcode=0x%02X expected=0x%02X buffered=%d",
                    src[0],
                    src[1],
                    room_id,
                    first_opcode,
                    expected_opcode,
                    len(room_buffer),
                )
                return
            if first_opcode == expected_opcode:
                delayed_raw_opcode = first_opcode

        wrap_target = next(iter(recipients)) if len(recipients) == 1 else target
        wrapped_src = self._udp_relay_wrapped_src(
            src,
            room=sender.room if sender.room not in (None, 0, 0xFFFFFFFF) else room,
            target=wrap_target,
        )
        try:
            out = _udp_make_wrapped(wrapped_src, payload)
        except ValueError as exc:
            log.warning(
                "UDP relay wrap failed for %s:%d via %s:%d: %s",
                src[0],
                src[1],
                wrapped_src[0],
                wrapped_src[1],
                exc,
            )
            return

        if room is not None and delayed_raw_opcode and delayed_raw_opcode > 0x65:
            if int(room) not in sender.raw_real_65_rooms:
                self._udp_relay_inject_missing_65_from_sender(
                    int(room),
                    sender,
                    wrapped_src,
                    recipients,
                )

        for dst in recipients:
            self._udp_relay_send(out, dst)
        sender.packets_out += len(recipients)

        if room is not None:
            log.info(
                "UDP room relayed: src=%s:%d wrap=%s:%d cmd=%d room=0x%08X peers=%d wrapped=%s",
                src[0],
                src[1],
                wrapped_src[0],
                wrapped_src[1],
                cmd,
                room,
                len(recipients),
                wrapped_in,
            )
            if delayed_raw_opcode:
                room_id = int(room)
                next_opcode = delayed_raw_opcode + 1
                sender.raw_order_next[room_id] = next_opcode
                room_buffer = sender.raw_order_buffer.get(room_id, {})
                while next_opcode <= 0x69 and next_opcode in room_buffer:
                    queued_payload = room_buffer.pop(next_opcode)
                    queued_cmd = _udp_read_u32_le(queued_payload, 0) if len(queued_payload) >= 4 else 0
                    try:
                        queued_out = _udp_make_wrapped(wrapped_src, queued_payload)
                    except ValueError as exc:
                        log.warning(
                            "UDP room delayed raw wrap failed for %s:%d via %s:%d room=0x%08X opcode=0x%02X: %s",
                            src[0],
                            src[1],
                            wrapped_src[0],
                            wrapped_src[1],
                            room_id,
                            next_opcode,
                            exc,
                        )
                        break
                    for dst in recipients:
                        self._udp_relay_send(queued_out, dst)
                    sender.packets_out += len(recipients)
                    log.info(
                        "UDP room relayed(delayed-order): src=%s:%d wrap=%s:%d cmd=%d room=0x%08X opcode=0x%02X peers=%d",
                        src[0],
                        src[1],
                        wrapped_src[0],
                        wrapped_src[1],
                        queued_cmd,
                        room_id,
                        next_opcode,
                        len(recipients),
                    )
                    next_opcode += 1
                    sender.raw_order_next[room_id] = next_opcode
                if not room_buffer:
                    sender.raw_order_buffer.pop(room_id, None)
        else:
            first_word = _udp_read_u32_le(payload, 0) if len(payload) >= 4 else 0
            first_opcode = first_word & 0xFF if len(payload) >= 4 else 0
            sender_room = int(sender.room or 0)
            if (
                sender_room not in (0, 0xFFFFFFFF)
                and first_opcode >= 0x65
                and self._udp_relay_is_forced_same_host_endpoint(src)
            ):
                try:
                    same_host_raw_echo_limit = int(
                        self.cfg.get("UDP_SAME_HOST_RAW_ECHO_LIMIT", 0) or 0
                    )
                except Exception:
                    same_host_raw_echo_limit = 0
                echo_count = int(sender.raw_echo_counts.get(sender_room, 0) or 0)
                if same_host_raw_echo_limit > 0:
                    for dst in recipients:
                        dst_state = self._udp_relay_clients.get(dst)
                        if not self._udp_relay_is_forced_same_host_endpoint(dst):
                            continue
                        if dst_state is not None and sender_room in dst_state.raw_sent_rooms:
                            continue
                        if echo_count >= same_host_raw_echo_limit:
                            break
                        echo_src = self._udp_relay_wrapped_src(
                            dst,
                            room=sender_room,
                            target=src,
                            source_port=dst[1],
                        )
                        try:
                            echo = _udp_make_wrapped(echo_src, payload)
                        except ValueError as exc:
                            log.warning(
                                "UDP relay same-host raw echo wrap failed: src=%s:%d peer=%s:%d room=0x%08X: %s",
                                src[0],
                                src[1],
                                dst[0],
                                dst[1],
                                sender_room,
                                exc,
                            )
                            continue
                        self._udp_relay_send(echo, src)
                        echo_count += 1
                        sender.raw_echo_counts[sender_room] = echo_count
                        if echo_count <= 32 or (echo_count % 32) == 0:
                            log.info(
                                "UDP relay same-host raw echo: src=%s:%d peer=%s:%d wrap=%s:%d len=%d w0=0x%08X room=0x%08X count=%d limit=%d",
                                src[0],
                                src[1],
                                dst[0],
                                dst[1],
                                echo_src[0],
                                echo_src[1],
                                len(payload),
                                first_word,
                                sender_room,
                                echo_count,
                                same_host_raw_echo_limit,
                            )
            log.info(
                "UDP relay relayed(raw): src=%s:%d wrap=%s:%d len=%d w0=0x%08X sender_room=0x%08X peers=%d wrapped=%s target=%s:%s",
                src[0],
                src[1],
                wrapped_src[0],
                wrapped_src[1],
                len(payload),
                first_word,
                sender.room if sender.room is not None else 0,
                len(recipients),
                wrapped_in,
                target[0] if target is not None else "-",
                target[1] if target is not None else "-",
            )

    def _game_relay_loop(self) -> None:
        while self.is_running:
            relay_socks = list(self._game_relay_socks or ([] if self._game_relay_sock is None else [self._game_relay_sock]))
            if not relay_socks:
                time.sleep(0.1)
                continue
            try:
                ready, _, _ = select.select(relay_socks, [], [], 1.0)
            except (OSError, ValueError):
                break
            if not ready:
                self._udp_relay_cleanup_idle()
                continue
            for relay_sock in ready:
                try:
                    data, addr = relay_sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    continue
                try:
                    local_port = int(relay_sock.getsockname()[1] or 0)
                except Exception:
                    local_port = 0
                self._udp_relay_handle_datagram(data, addr, local_port)

    def advertised_host(self, conn: Optional[socket.socket] = None) -> str:
        return self._public_host("lobby", conn=conn)

    def advertised_port(self) -> int:
        return self._public_port("lobby")

    def advertised_game_host(self, conn: Optional[socket.socket] = None) -> str:
        return self._public_host("race", conn=conn)

    def advertised_game_port(self, fallback: int = 0) -> int:
        port = self._public_port("race")
        if port > 0:
            return port
        return int(fallback or 0)

    def advertised_game_tcp_port(self, fallback: int = 0) -> int:
        port = self._first_port("ADVERTISED_GAME_TCP_PORT")
        if port > 0:
            return port
        port = self._public_port("lobby")
        if port > 0:
            return port
        return int(fallback or 0)

    def _advertised_game_endpoints_file(self) -> str:
        path = str(self.cfg.get("ADVERTISED_GAME_ENDPOINTS_FILE", "") or "").strip()
        if not path:
            return ""
        if not os.path.isabs(path):
            path = os.path.join(os.path.dirname(self._config_path), path)
        return path

    @staticmethod
    def _parse_advertised_game_endpoint(value: str) -> Optional[Tuple[str, int]]:
        raw = str(value or "").strip()
        if not raw or ":" not in raw:
            return None
        host, _, port_text = raw.rpartition(":")
        host = host.strip()
        try:
            port = int(port_text.strip() or "0", 10)
        except ValueError:
            return None
        if not host or port <= 0:
            return None
        return host, port

    def _load_advertised_game_endpoints(self) -> Dict[str, Dict[str, Tuple[str, int]]]:
        path = self._advertised_game_endpoints_file()
        empty: Dict[str, Dict[str, Tuple[str, int]]] = {"uid": {}, "pers": {}, "name": {}}
        if not path or not os.path.exists(path):
            self._advertised_game_endpoints_path = path
            self._advertised_game_endpoints_mtime = -1.0
            self._advertised_game_endpoints_cache = empty
            return self._advertised_game_endpoints_cache
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            self._advertised_game_endpoints_cache = empty
            return self._advertised_game_endpoints_cache
        if (
            path == self._advertised_game_endpoints_path
            and mtime == self._advertised_game_endpoints_mtime
        ):
            return self._advertised_game_endpoints_cache

        mapping: Dict[str, Dict[str, Tuple[str, int]]] = {"uid": {}, "pers": {}, "name": {}}
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for lineno, line in enumerate(fh, 1):
                    raw = line.strip()
                    if not raw or raw.startswith("#"):
                        continue
                    if "=" not in raw:
                        log.warning("%s:%d invalid endpoint mapping line", path, lineno)
                        continue
                    key, _, value = raw.partition("=")
                    key = key.strip()
                    endpoint = self._parse_advertised_game_endpoint(value)
                    if endpoint is None:
                        log.warning("%s:%d invalid endpoint '%s'", path, lineno, value.strip())
                        continue
                    kind = "pers"
                    map_key = key
                    if ":" in key:
                        prefix, _, tail = key.partition(":")
                        prefix_norm = prefix.strip().lower()
                        if prefix_norm in mapping:
                            kind = prefix_norm
                            map_key = tail
                    map_key = map_key.strip().lower()
                    if not map_key:
                        log.warning("%s:%d empty mapping key", path, lineno)
                        continue
                    mapping[kind][map_key] = endpoint
        except OSError as exc:
            log.warning("Failed to load advertised game endpoints from '%s': %s", path, exc)
            mapping = empty

        self._advertised_game_endpoints_path = path
        self._advertised_game_endpoints_mtime = mtime
        self._advertised_game_endpoints_cache = mapping
        return self._advertised_game_endpoints_cache

    def advertised_game_endpoint_for(
        self,
        *,
        conn: Optional[socket.socket] = None,
        uid: int = 0,
        name: str = "",
        persona: str = "",
    ) -> Tuple[str, int]:
        mapping = self._load_advertised_game_endpoints()
        if uid > 0:
            endpoint = mapping["uid"].get(str(int(uid)))
            if endpoint is not None:
                return endpoint
        persona_key = str(persona or "").strip().lower()
        if persona_key:
            endpoint = mapping["pers"].get(persona_key)
            if endpoint is not None:
                return endpoint
        name_key = str(name or "").strip().lower()
        if name_key:
            endpoint = mapping["name"].get(name_key)
            if endpoint is not None:
                return endpoint
        same_pc_endpoint = self._same_pc_endpoint_for(conn=conn, uid=uid)
        if same_pc_endpoint is not None:
            return same_pc_endpoint
        host = self.advertised_game_host(conn=conn)
        if host:
            return host, self.advertised_game_port()
        return "", 0

    def control_host(self, conn: Optional[socket.socket] = None) -> str:
        return self._public_host("control", conn=conn)

    def control_port(self) -> int:
        return self._public_port("control")

    def control_alias_host(self, conn: Optional[socket.socket] = None) -> str:
        return self._public_host("control_alias", conn=conn)

    def control_alias_port(self) -> int:
        return self._public_port("control_alias")

    def lobby_tcp_host(self, conn: Optional[socket.socket] = None) -> str:
        return self._public_host("lobby", conn=conn)

    def lobby_tcp_port(self) -> int:
        return self._public_port("lobby")

    def race_udp_endpoint_for(
        self,
        *,
        conn: Optional[socket.socket] = None,
        name: str = "",
        persona: str = "",
    ) -> Tuple[str, int]:
        dyn_host, dyn_port = self.advertised_game_endpoint_for(conn=conn, name=name, persona=persona)
        host = dyn_host or self.advertised_game_host(conn=conn) or self.advertised_host(conn)
        port = dyn_port or self.advertised_game_port(self.udp_relay_port or 20000)
        return host, port

    def __getattr__(self, name: str):
        messenger = self.__dict__.get("messenger")
        if messenger is not None and (
            name in {"remember_control_profile", "get_control_profile", "_social_key", "_social_reports"}
            or name.startswith("control_profile_")
            or name.startswith("control_social_")
        ):
            return getattr(messenger, name)
        raise AttributeError(f"{type(self).__name__!s} object has no attribute {name!r}")

    # ------------------------------------------------------------------ #
    # Periodic maintenance                                                 #
    # ------------------------------------------------------------------ #

    def _periodic(self):
        last_stat_refresh = time.time()
        stat_interval     = float(self.cfg.get("SERVER_STAT_REFRESH", 60))

        while self.is_running:
            try:
                now = time.time()

                # Sweep inactive users
                kicked = self.users.kick_inactive()
                for u in kicked:
                    self.users.remove(u.uid)

                # Clean up users detached from active race TCP once UDP has
                # gone quiet for a short grace window.
                self._cleanup_detached_race_users()
                self.sweep_lobby_dir_challenges()

                # Sweep expired games
                self.games.sweep_expired()

                # Sweep expired challenges
                self.challenges.sweep_expired()

                # Periodic matchmaking
                self.play.periodic()

                # Save ranking/stats periodically
                self.ranking.save()
                self.stats.save()

                self._maybe_log_master_stat(now=now)

                # Master stat refresh
                if (now - last_stat_refresh) >= stat_interval:
                    self._log_master_stat(force=True, now=now)
                    last_stat_refresh = now

                # Master slave health check
                if self.master:
                    self.master.check_slaves()

            except Exception as e:
                log.error("MasterPeriodic: failed to get time info: %s", e)

            time.sleep(1.0)

    def _master_stat_payload(self) -> str:
        counts = self.users.count()
        gstats = self.games.stats()
        users_lobby_display = counts["lobby"] + counts["rooms"]
        return (
            "<master usersInLobby=%d usersInRooms=%d usersInGames=%d "
            "gamesInProgress=%d gamesCreated=%d gamesCompleted=%d "
            "rooms=%d sync=0 />"
        ) % (
            users_lobby_display, counts["rooms"], counts["games"],
            gstats["active"], gstats["created"], gstats["completed"],
            self.rooms.count(),
        )

    def request_master_stat_refresh(self) -> None:
        self._master_stat_dirty = True

    def _maybe_log_master_stat(self, *, now: Optional[float] = None, min_interval: float = 1.0) -> bool:
        if not self._master_stat_dirty:
            return False
        now = time.time() if now is None else now
        if (now - self._last_master_stat_log_time) < float(min_interval):
            return False
        return self._log_master_stat(force=False, now=now)

    def _log_master_stat(self, *, force: bool = False, now: Optional[float] = None) -> bool:
        payload = self._master_stat_payload()
        if not force and payload == self._last_master_stat_payload:
            self._master_stat_dirty = False
            return False
        log.info(payload)
        self._last_master_stat_payload = payload
        self._last_master_stat_log_time = time.time() if now is None else now
        self._master_stat_dirty = False
        return True

    # ------------------------------------------------------------------ #
    # Master/Slave integration                                             #
    # ------------------------------------------------------------------ #

    def _get_state(self) -> dict:
        """Snapshot of current server state for replication."""
        counts = self.users.count()
        gstats = self.games.stats()
        return {
            "users":           counts,
            "games":           gstats,
            "rooms":           self.rooms.count(),
        }

    def _on_master_update(self, data: dict):
        """Receive config update from master. Triggers reconfig."""
        log.info("Master server reconfig (from master)")


# ======================================================================= #
# Module-level API (mirrors DLL exported functions)                        #
# ======================================================================= #

_server: Optional[GameServer] = None
_server_lock = threading.Lock()


def StartServer(config_path: str = "server.cfg") -> bool:
    """
    Equivalent to server.dll::StartServer().
    Returns True on success.
    """
    global _server
    with _server_lock:
        if _server and _server.is_server_running():
            return True
        _server = GameServer(config_path)
        return _server.start()


def StopServer():
    """Equivalent to server.dll::StopServer()."""
    global _server
    with _server_lock:
        if _server:
            _server.stop()
            _server = None


def IsServerRunning() -> bool:
    """Equivalent to server.dll::IsServerRunning()."""
    with _server_lock:
        return _server is not None and _server.is_server_running()


# ======================================================================= #
# Entry point                                                              #
# ======================================================================= #

if __name__ == "__main__":
    import signal

    cfg_path = sys.argv[1] if len(sys.argv) > 1 else "server.cfg"

    print("Starting U2Online server...")
    print(f"Config: {cfg_path}")

    ok = StartServer(cfg_path)
    if not ok:
        print("Failed to start server. Check logs.")
        sys.exit(1)

    print(f"Server running. IsServerRunning() = {IsServerRunning()}")
    if _server is not None and _server.start_admin_shell():
        print("Admin shell enabled. Type 'help' for commands.")
    print("Press Ctrl+C to stop.\n")

    def _shutdown(sig, frame):
        print("\nShutting down...")
        StopServer()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Keep main thread alive
    while IsServerRunning():
        time.sleep(1)
