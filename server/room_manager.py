"""
room_manager.py — Room and Game management.
Implements the full lobby/room/game lifecycle from server.dll.
"""

import time
import threading
import logging
from typing import Optional, Dict, List, Set

log = logging.getLogger("rooms")


# ======================================================================= #
# Room                                                                     #
# ======================================================================= #

class Room:
    _counter = 1
    _lock    = threading.Lock()

    def __init__(self, name: str, host_uid: int, maxsize: int = 8,
                 minsize: int = 2, custflags: int = 0, sysflags: int = 0):
        with Room._lock:
            self.id = Room._counter
            Room._counter += 1

        self.name       = name
        self.host_uid   = host_uid
        self.maxsize    = maxsize
        self.minsize    = minsize
        self.custflags  = custflags
        self.sysflags   = sysflags
        self.created_at = time.time()
        self.members: Set[int] = set()   # uid set
        self.door_msg   = ""             # ROOM_DOOR_MESG
        self.assistant_uid = 0
        self.persist    = False

    @property
    def count(self) -> int:
        return len(self.members)

    @property
    def full(self) -> bool:
        return self.count >= self.maxsize

    @property
    def host(self) -> str:
        return f"uid:{self.host_uid}"

    def to_dict(self) -> dict:
        return {
            "id":        self.id,
            "name":      self.name,
            "host":      self.host,
            "maxsize":   self.maxsize,
            "minsize":   self.minsize,
            "count":     self.count,
            "custflags": self.custflags,
            "sysflags":  self.sysflags,
            "assistant_uid": self.assistant_uid,
            "persist":   self.persist,
        }

    def __repr__(self):
        return f"<Room id={self.id} name={self.name!r} {self.count}/{self.maxsize}>"


# ======================================================================= #
# Game                                                                     #
# ======================================================================= #

GAME_STATE_OPEN      = "OPEN"
GAME_STATE_ACTIVE    = "ACTIVE"
GAME_STATE_FINISHED  = "FINISHED"
GAME_STATE_EXPIRED   = "EXPIRED"


class Game:
    _counter = 1
    _lock    = threading.Lock()

    def __init__(self, room_id: int, host_uid: int, limit: int = 8,
                 game_type: str = "PUBLIC", flags: float = 0.0,
                 secret: str = "", custom: str = "", fmt: str = "",
                 addr: str = "0.0.0.0", port: int = 0):
        with Game._lock:
            self.id = Game._counter
            Game._counter += 1

        self.room_id    = room_id
        self.host_uid   = host_uid
        self.limit      = limit
        self.type       = game_type
        self.flags      = flags
        self.secret     = secret
        self.custom     = custom
        self.format     = fmt
        self.state      = GAME_STATE_OPEN
        self._addr      = addr
        self._port      = port

        self.participants: List[int] = []   # ordered list of uid
        self.ready_participants: Set[int] = set()
        self.kicked_uids: Set[int] = set()
        self.results: Dict[int, dict] = {}  # uid -> result dict

        self.created_at  = time.time()
        self.started_at  = None
        self.finished_at = None

        # Stats tracking
        self.evid   = self.id
        self.evgid  = 0

    @property
    def count(self) -> int:
        return len(self.participants)

    @property
    def addr(self) -> str:
        return self._addr

    @addr.setter
    def addr(self, value: str):
        self._addr = value

    @property
    def port(self) -> int:
        return self._port

    @port.setter
    def port(self, value: int):
        self._port = value

    def add_player(self, uid: int) -> bool:
        if uid in self.participants:
            return False
        if uid in self.kicked_uids:
            return False
        if self.count >= self.limit:
            return False
        if self.state != GAME_STATE_OPEN:
            return False
        self.participants.append(uid)
        return True

    def remove_player(self, uid: int):
        if uid in self.participants:
            self.participants.remove(uid)
        self.ready_participants.discard(uid)

    def mark_kicked(self, uid: int):
        self.kicked_uids.add(int(uid))

    def set_ready(self, uid: int, ready: bool = True):
        if uid not in self.participants:
            return
        if ready:
            self.ready_participants.add(uid)
        else:
            self.ready_participants.discard(uid)

    def start(self):
        self.state      = GAME_STATE_ACTIVE
        self.started_at = time.time()
        log.info("GAME: IDENT=%d AUTO=0 START", self.id)

    def finish(self, results: Dict[int, dict] = None):
        self.state       = GAME_STATE_FINISHED
        self.finished_at = time.time()
        if results:
            self.results = results
        log.info("BATCH: completed processing of game %d", self.id)

    def is_expired(self, timeout: float) -> bool:
        if self.state == GAME_STATE_FINISHED:
            return (time.time() - self.finished_at) > timeout
        if self.state == GAME_STATE_OPEN and not self.participants:
            return (time.time() - self.created_at) > timeout
        return False

    def to_dict(self) -> dict:
        return {
            "id":      self.id,
            "type":    self.type,
            "count":   self.count,
            "limit":   self.limit,
            "addr":    self.addr,
            "port":    self.port,
            "flags":   self.flags,
            "secret":  self.secret,
            "custom":  self.custom,
            "format":  self.format,
            "state":   self.state,
        }

    def __repr__(self):
        return f"<Game id={self.id} state={self.state} {self.count}/{self.limit}>"


# ======================================================================= #
# Room Manager                                                             #
# ======================================================================= #

class RoomManager:
    def __init__(self, cfg):
        self.cfg        = cfg
        self._lock      = threading.Lock()
        self._rooms: Dict[int, Room] = {}
        self.max_rooms  = cfg.get("ROOMS", 32)
        self.max_size   = cfg.get("ROOMMAX", 64)

        # Auto-create lobby room
        if cfg.get("AUTOROOM", 0):
            self._auto_create_rooms()

    def _auto_create_rooms(self):
        lobby = Room("Lobby", host_uid=0, maxsize=self.max_size)
        self._rooms[lobby.id] = lobby
        log.info("AUTOROOM: created default lobby room id=%d", lobby.id)

    # ------------------------------------------------------------------ #

    def create(self, name: str, host_uid: int, maxsize: int = 8,
               minsize: int = 2, custflags: int = 0, sysflags: int = 0) -> Optional[Room]:
        with self._lock:
            if len(self._rooms) >= self.max_rooms:
                log.warning("LoadBalUpdate: No room in load balancing table. Ignoring.")
                return None
            room = Room(name, host_uid, min(maxsize, self.max_size),
                        minsize, custflags, sysflags)
            self._rooms[room.id] = room
            log.info("Room created: id=%d name=%r by uid=%d", room.id, name, host_uid)
            return room

    def get(self, room_id: int) -> Optional[Room]:
        return self._rooms.get(room_id)

    def destroy(self, room_id: int):
        with self._lock:
            room = self._rooms.pop(room_id, None)
            if room:
                log.info("Room destroyed: id=%d name=%r", room.id, room.name)
            return room

    def join(self, room_id: int, uid: int) -> bool:
        room = self.get(room_id)
        if not room or room.full:
            return False
        room.members.add(uid)
        return True

    def leave(self, room_id: int, uid: int):
        room = self.get(room_id)
        if room:
            room.members.discard(uid)
            if room.count == 0 and room.host_uid != 0:
                self.destroy(room_id)

    def list_rooms(self) -> List[Room]:
        with self._lock:
            return list(self._rooms.values())

    def count(self) -> int:
        return len(self._rooms)


# ======================================================================= #
# Game Manager                                                             #
# ======================================================================= #

class GameManager:
    def __init__(self, cfg):
        self.cfg         = cfg
        self._lock       = threading.Lock()
        self._games: Dict[int, Game] = {}
        self.max_games   = cfg.get("GAMES", 128)
        self.expire_time = cfg.get("GAME_EXPIRE_TIME", 300)
        self.game_timeout= cfg.get("GAMETIMEOUT", 3600)

        # Global counters (matches DLL master stat)
        self.games_created   = 0
        self.games_completed = 0

    def create(self, room_id: int, host_uid: int, limit: int = 8,
               game_type: str = "PUBLIC", flags: float = 0.0,
               secret: str = "", custom: str = "", fmt: str = "",
               addr: str = "0.0.0.0", port: int = 0) -> Optional[Game]:
        with self._lock:
            if len(self._games) >= self.max_games:
                return None
            game = Game(room_id, host_uid, limit, game_type,
                        flags, secret, custom, fmt, addr, port)
            self._games[game.id] = game
            self.games_created += 1
            log.info("GAME: IDENT=%d AUTO=0 CREATED at %s:%d", game.id, addr, port)
            return game

    def get(self, game_id: int) -> Optional[Game]:
        return self._games.get(game_id)

    def destroy(self, game_id: int, *, reason: str = "") -> Optional[Game]:
        with self._lock:
            game = self._games.pop(game_id, None)
        if game is not None:
            if reason:
                log.info("GAME: IDENT=%d REMOVED reason=%s", game.id, reason)
            else:
                log.info("GAME: IDENT=%d REMOVED", game.id)
        return game

    def join(self, game_id: int, uid: int) -> bool:
        game = self.get(game_id)
        if not game:
            return False
        ok = game.add_player(uid)
        if not ok:
            log.warning("NOTINGAME: uid %d could not join game %d", uid, game_id)
        return ok

    def leave(self, game_id: int, uid: int) -> tuple[Optional[Game], bool]:
        game = self.get(game_id)
        if not game:
            return None, False

        was_host = int(uid) == int(game.host_uid)
        game.remove_player(uid)
        if was_host:
            return self.destroy(game_id, reason=f"host_left:{uid}"), True
        if not game.participants:
            return self.destroy(game_id, reason=f"empty_after_leave:{uid}"), True
        return game, False

    def finish_game(self, game_id: int, results: Dict[int, dict] = None):
        game = self.get(game_id)
        if game:
            game.finish(results)
            self.games_completed += 1

    def list_games(self, room_id: int = None) -> List[Game]:
        with self._lock:
            games = list(self._games.values())
        if room_id is not None:
            games = [g for g in games if g.room_id == room_id]
        return games

    def active_games(self) -> List[Game]:
        return [g for g in self.list_games() if g.state == GAME_STATE_ACTIVE]

    def sweep_expired(self) -> List[Game]:
        """Remove expired games. Matches GAME_EXPIRE_TIME config."""
        expired = []
        with self._lock:
            for gid in list(self._games.keys()):
                game = self._games[gid]
                if game.is_expired(self.expire_time):
                    del self._games[gid]
                    expired.append(game)
                    log.info("Game %d expired and removed.", gid)
        return expired

    def stats(self) -> dict:
        games = self.list_games()
        return {
            "open":       sum(1 for g in games if g.state == GAME_STATE_OPEN),
            "active":     sum(1 for g in games if g.state == GAME_STATE_ACTIVE),
            "finished":   sum(1 for g in games if g.state == GAME_STATE_FINISHED),
            "created":    self.games_created,
            "completed":  self.games_completed,
        }
