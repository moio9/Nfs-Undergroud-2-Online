"""
user_manager.py — User session management.
Manages all connected users, their state, and associated data.
"""

import time
import threading
import logging
from typing import Optional, Dict, List

log = logging.getLogger("users")

# User status values (STAT= field in protocol)
STAT_IDLE   = "IDLE"
STAT_LOBBY  = "LOBBY"
STAT_ROOM   = "ROOM"
STAT_GAME   = "GAME"
STAT_AWAY   = "AWAY"


class User:
    _uid_counter = 1
    _lock = threading.Lock()

    def __init__(self, conn, addr: tuple, name: str = ""):
        with User._lock:
            self.uid = User._uid_counter
            User._uid_counter += 1

        self.conn = conn
        self.ip   = addr[0]
        self.port = addr[1]

        # Identity
        self.name     = name or f"Player{self.uid}"
        self.pers     = ""          # persona name
        self.uid      = self.uid
        self.lang     = "en"
        self.from_    = ""

        # Location
        self.room     = 0           # current room id
        self.game     = 0           # current game id
        self.stat     = STAT_LOBBY
        self.aux      = ""

        # Display
        self.rgb      = 0xFFFFFF
        self.ping     = 0
        self.play     = 0           # games played
        self.seed     = int(time.time()) & 0xFFFF
        self.flags    = 0.0
        self.sync     = 0

        # Network
        self.addr     = self.ip
        self.laddr    = self.ip
        self.serv     = "0.0.0.0"
        self.sprt     = 0
        self.maddr    = ""

        # Ranking / progression
        self.level    = 1
        self.medals   = 0
        self.rep      = 0
        self.hw_flag  = 0
        self.hw_mask  = 0
        self.hw_mid   = ""          # hardware machine ID (anti-cheat)
        self.mac      = ""          # MAC address (anti-cheat)

        # Timing
        self.login_time   = time.time()
        self.last_active  = time.time()
        self.connected    = True
        self.race_detached_at = 0.0
        self.muted        = False
        self.mute_reason  = ""
        self.muted_at     = 0.0

        # Stock lobby-style per-client filter/subscription state.
        self.rooms_filter = {
            "USERS": 0,
            "USERSETS": 0,
            "GAMES": 0,
            "MYGAME": 0,
            "ROOMS": 0,
            "RANKS": 0,
            "MESGS": 0,
            "ASYNC": 0,
            "STATS": 0,
            "USERSET0": "",
            "USERSET1": "",
            "USERSET2": "",
            "USERSET3": "",
        }
        self.room_privacy = "OFF"

        # Send buffer lock
        self._send_lock = threading.Lock()

    def send(self, msg: str):
        """Thread-safe UTF-8 text send."""
        if not self.connected:
            return
        try:
            with self._send_lock:
                self.conn.sendall(msg.encode("utf-8"))
        except Exception as e:
            log.warning("Send failed to user %d (%s): %s", self.uid, self.name, e)
            self.connected = False

    def send_bytes(self, data: bytes):
        """Thread-safe raw byte send for pre-login framed bootstrap."""
        if not self.connected:
            return
        try:
            with self._send_lock:
                self.conn.sendall(data)
        except Exception as e:
            log.warning("Raw send failed to user %d (%s): %s", self.uid, self.name, e)
            self.connected = False

    def touch(self):
        self.last_active = time.time()

    def idle_seconds(self) -> float:
        return time.time() - self.last_active

    def to_dict(self) -> dict:
        return {
            "name":    self.name,
            "pers":    self.pers,
            "uid":     self.uid,
            "room":    self.room,
            "game":    self.game,
            "stat":    self.stat,
            "aux":     self.aux,
            "rgb":     self.rgb,
            "ping":    self.ping,
            "play":    self.play,
            "seed":    self.seed,
            "flags":   self.flags,
            "sync":    self.sync,
            "addr":    self.addr,
            "laddr":   self.laddr,
            "serv":    self.serv,
            "sprt":    self.sprt,
            "level":   self.level,
            "medals":  self.medals,
            "lang":    self.lang,
            "rep":     self.rep,
            "muted":   self.muted,
        }

    def __repr__(self):
        return f"<User uid={self.uid} name={self.name!r} stat={self.stat} room={self.room} game={self.game}>"


class UserManager:
    def __init__(self, cfg):
        self.cfg   = cfg
        self._lock = threading.Lock()
        self._users: Dict[int, User] = {}          # uid -> User
        self._by_name: Dict[str, User] = {}        # name -> User
        self._hw_ids: Dict[str, int] = {}          # hw_mid -> uid (anti-cheat)
        self._cheat_log: List[dict] = []

        self.max_users = int(cfg.get("SERVER_MAX_PLAYERS", cfg.get("USERS", 256)) or 256)
        self.inactivity_timeout = 300              # seconds

    # ------------------------------------------------------------------ #
    # Registration / removal                                               #
    # ------------------------------------------------------------------ #

    def add(self, user: User) -> bool:
        with self._lock:
            if len(self._users) >= self.max_users:
                log.warning("Connect status: max=%d, cur=%d", self.max_users, len(self._users))
                return False
            self._users[user.uid] = user
            self._by_name[user.name.lower()] = user
            log.info("LOGIN: PERS=%s GAMEREPT=%d", user.pers, user.play)
            return True

    def remove(self, uid: int):
        with self._lock:
            user = self._users.pop(uid, None)
            if user:
                for key, mapped in list(self._by_name.items()):
                    if mapped is user or getattr(mapped, "uid", 0) == uid:
                        self._by_name.pop(key, None)
                log.info("LOGOUT[users.remove]: uid=%d PERS=%s GAMEREPT=%d EXPIRE=%d",
                         user.uid,
                         user.pers, user.play,
                         int(time.time() - user.login_time))
                return user
        return None

    # ------------------------------------------------------------------ #
    # Lookup                                                               #
    # ------------------------------------------------------------------ #

    def get(self, uid: int) -> Optional[User]:
        return self._users.get(uid)

    def get_by_name(self, name: str) -> Optional[User]:
        return self._by_name.get(name.lower())

    def all_users(self) -> List[User]:
        with self._lock:
            return list(self._users.values())

    def users_in_lobby(self) -> List[User]:
        return [u for u in self.all_users() if u.stat == STAT_LOBBY]

    def users_in_rooms(self) -> List[User]:
        return [u for u in self.all_users() if u.stat == STAT_ROOM]

    def users_in_games(self) -> List[User]:
        return [u for u in self.all_users() if u.stat == STAT_GAME]

    # ------------------------------------------------------------------ #
    # Anti-cheat hardware tracking                                         #
    # ------------------------------------------------------------------ #

    def register_hw(self, user: User, hw_mid: str, mac: str):
        """
        Track hardware ID → user mapping.
        Matches DLL: HW MID=%s MAC=%s IP=%a FLAG=%d MASK=%d
        """
        user.hw_mid = hw_mid
        user.mac    = mac
        with self._lock:
            existing_uid = self._hw_ids.get(hw_mid)
            if existing_uid and existing_uid != user.uid:
                log.warning("Cheat Device: HW_MID=%s already registered to uid=%d, new uid=%d",
                            hw_mid, existing_uid, user.uid)
                self._cheat_log.append({
                    "time":    time.time(),
                    "hw_mid":  hw_mid,
                    "mac":     mac,
                    "uid_old": existing_uid,
                    "uid_new": user.uid,
                    "ip":      user.ip,
                })
            self._hw_ids[hw_mid] = user.uid

    def cheat_stats(self) -> dict:
        """Matches: Cheat Device Statistics / Cheat Response Log"""
        return {
            "total_hw_ids":    len(self._hw_ids),
            "flagged_devices": len(self._cheat_log),
            "log":             list(self._cheat_log[-100:]),  # max entries
        }

    # ------------------------------------------------------------------ #
    # Inactivity sweep                                                     #
    # ------------------------------------------------------------------ #

    def kick_inactive(self, timeout: float = None) -> List[User]:
        """
        Disconnect idle users.
        Matches: 'Disconnected due to inactivity' / 'Maximum connection time exceeded'
        """
        if timeout is None:
            timeout = self.inactivity_timeout
        now = time.time()
        kicked = []
        for user in self.all_users():
            if user.idle_seconds() > timeout:
                user.send("+KICK TEXT=\"Disconnected due to inactivity\"\n")
                user.connected = False
                kicked.append(user)
                log.info("Kicked uid=%d (%s): inactivity", user.uid, user.name)
        return kicked

    # ------------------------------------------------------------------ #
    # Stats                                                                #
    # ------------------------------------------------------------------ #

    def count(self) -> dict:
        users = self.all_users()
        return {
            "total":    len(users),
            "lobby":    sum(1 for u in users if u.stat == STAT_LOBBY),
            "rooms":    sum(1 for u in users if u.stat == STAT_ROOM),
            "games":    sum(1 for u in users if u.stat == STAT_GAME),
        }
