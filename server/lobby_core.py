"""
lobby_core.py - Shared stateful lobby core for post-bootstrap semantics.

The relay keeps the online bootstrap/protocol adaptation locally, but delegates
the actual lobby/user/room state model to this module so it does not maintain a
second copy inline.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class TCP20922LobbyFilterState:
    users: int = 0
    usersets: int = 0
    games: int = 0
    mygame: int = 0
    rooms: int = 0
    ranks: int = 0
    mesgs: int = 0
    async_flag: int = 0
    stats: int = 0
    slots: int = 32
    usersets_selected: List[str] = field(default_factory=lambda: ["", "", "", ""])
    refresh_count: int = 0


@dataclass
class TCP20922LobbyUser:
    ident: int
    client_key: str
    persona: str
    display_name: str
    room_ident: int = 0
    ping: int = 100
    flags: int = 0
    privacy_enabled: bool = False
    created_at: float = field(default_factory=time.time)


@dataclass
class TCP20922LobbyRoom:
    ident: int
    name: str
    host_persona: str
    host_user_ident: int
    assistant_user_ident: int = 0
    assistant_persona: str = ""
    game_name: str = ""
    params: str = ""
    limit: int = 4
    flags: int = 8
    min_size: int = 1
    system_flags: int = 0
    event_id: int = 0
    event_group_id: int = 0
    num_partitions: int = 0
    sync_id: int = 0
    persist: bool = False
    occupants: Set[int] = field(default_factory=set)
    created_at: float = field(default_factory=time.time)


@dataclass
class TCP20922LobbyMessage:
    priv: int = 0
    set_id: int = 0
    room_ident: int = 0
    game: int = 0
    flags: int = 0
    name: str = ""
    text: str = ""
    created_at: float = field(default_factory=time.time)


class TCP20922LobbyCore:
    def __init__(self) -> None:
        self.filters: Dict[str, TCP20922LobbyFilterState] = {}
        self.users: Dict[str, TCP20922LobbyUser] = {}
        self.rooms_by_id: Dict[int, TCP20922LobbyRoom] = {}
        self.rooms_by_name: Dict[str, int] = {}
        self.messages: List[TCP20922LobbyMessage] = []
        self.next_user_ident = 50000
        self.next_room_ident = 1

    def get_filter_state(self, client_key: str) -> TCP20922LobbyFilterState:
        state = self.filters.get(client_key)
        if state is None:
            state = TCP20922LobbyFilterState()
            self.filters[client_key] = state
        return state

    def apply_rooms_filters(
        self, client_key: str, kv: Dict[str, str]
    ) -> TCP20922LobbyFilterState:
        state = self.get_filter_state(client_key)

        def _parse_int(name: str, default: int = 0) -> int:
            raw = kv.get(name)
            if raw is None or raw == "":
                return default
            try:
                return int(raw, 0)
            except Exception:
                return default

        for attr, key in (
            ("users", "USERS"),
            ("usersets", "USERSETS"),
            ("games", "GAMES"),
            ("mygame", "MYGAME"),
            ("ranks", "RANKS"),
            ("mesgs", "MESGS"),
            ("async_flag", "ASYNC"),
            ("stats", "STATS"),
        ):
            if key in kv:
                setattr(state, attr, 1 if _parse_int(key, 0) > 0 else 0)

        if "ROOMS" in kv:
            room_val = _parse_int("ROOMS", 0)
            if room_val == 0:
                state.rooms = 0
            else:
                state.rooms = 1
                state.refresh_count += 1

        if "SLOTS" in kv:
            state.slots = max(1, min(1000, _parse_int("SLOTS", state.slots)))

        for i in range(4):
            key = f"USERSET{i}"
            if key in kv:
                state.usersets_selected[i] = kv.get(key, "").strip()

        return state

    @staticmethod
    def room_name_key(name: str) -> str:
        return name.strip().lower()

    def ensure_user(
        self, client_key: str, persona: str, display_name: str
    ) -> TCP20922LobbyUser:
        user = self.users.get(client_key)
        if user is None:
            user = TCP20922LobbyUser(
                ident=self.next_user_ident,
                client_key=client_key,
                persona=persona.strip() or display_name.strip() or "Player",
                display_name=display_name.strip() or persona.strip() or "Player",
            )
            self.next_user_ident += 1
            self.users[client_key] = user
        else:
            if persona.strip():
                user.persona = persona.strip()
            if display_name.strip():
                user.display_name = display_name.strip()
        return user

    def get_user(self, client_key: str) -> Optional[TCP20922LobbyUser]:
        return self.users.get(client_key)

    def get_room(self, room_ident: int) -> Optional[TCP20922LobbyRoom]:
        if room_ident <= 0:
            return None
        return self.rooms_by_id.get(room_ident)

    def find_room_by_name(self, name: str) -> Optional[TCP20922LobbyRoom]:
        room_ident = self.rooms_by_name.get(self.room_name_key(name))
        if room_ident is None:
            return None
        return self.rooms_by_id.get(room_ident)

    def find_room(self, *, room_ident: int = 0, room_name: str = "") -> Optional[TCP20922LobbyRoom]:
        if room_ident > 0:
            room = self.get_room(room_ident)
            if room is not None:
                return room
        if room_name.strip():
            return self.find_room_by_name(room_name)
        return None

    def detach_user_from_room(self, user: TCP20922LobbyUser) -> None:
        room = self.get_room(user.room_ident)
        if room is None:
            user.room_ident = 0
            return
        room.occupants.discard(user.ident)
        user.room_ident = 0
        if not room.occupants:
            self.rooms_by_id.pop(room.ident, None)
            self.rooms_by_name.pop(self.room_name_key(room.name), None)
            return
        if room.host_user_ident not in room.occupants:
            next_ident = next(iter(room.occupants))
            room.host_user_ident = next_ident
            for cand in self.users.values():
                if cand.ident == next_ident:
                    room.host_persona = cand.persona
                    break

    def attach_user_to_room(self, user: TCP20922LobbyUser, room: TCP20922LobbyRoom) -> None:
        if user.room_ident == room.ident:
            return
        self.detach_user_from_room(user)
        room.occupants.add(user.ident)
        user.room_ident = room.ident

    def find_user_by_ident(self, user_ident: int) -> Optional[TCP20922LobbyUser]:
        if user_ident <= 0:
            return None
        for user in self.users.values():
            if user.ident == user_ident:
                return user
        return None

    def find_user_by_name(self, name: str) -> Optional[TCP20922LobbyUser]:
        val = name.strip()
        if not val:
            return None
        lower = val.lower()
        for user in self.users.values():
            if (user.persona.lower() == lower) or (user.display_name.lower() == lower):
                return user
        return None

    def join_or_create_room(
        self,
        client_key: str,
        persona: str,
        display_name: str,
        room_name: str,
        limit: int = 4,
        flags: int = 8,
        params: str = "",
        min_size: int = 1,
        system_flags: int = 0,
    ) -> Tuple[TCP20922LobbyUser, TCP20922LobbyRoom, bool]:
        user = self.ensure_user(client_key, persona, display_name)
        room = self.find_room_by_name(room_name)
        created = False
        if room is None:
            room = TCP20922LobbyRoom(
                ident=self.next_room_ident,
                name=room_name.strip() or f"Room{self.next_room_ident}",
                host_persona=user.persona,
                host_user_ident=user.ident,
                game_name=room_name.strip(),
                params=params,
                limit=max(1, min(1000, limit)),
                flags=flags,
                min_size=max(1, min(1000, min_size)),
                system_flags=system_flags,
                sync_id=self.next_room_ident,
                num_partitions=1,
            )
            self.next_room_ident += 1
            self.rooms_by_id[room.ident] = room
            self.rooms_by_name[self.room_name_key(room.name)] = room.ident
            created = True
        else:
            if params:
                room.params = params
            room.flags = flags
            room.limit = max(1, min(1000, limit))
            room.min_size = max(1, min(1000, min_size))
            room.system_flags = system_flags
            room.num_partitions = max(1, room.num_partitions)
        self.attach_user_to_room(user, room)
        return user, room, created

    def move_user_to_room(
        self, client_key: str, room_ident: int
    ) -> Tuple[Optional[TCP20922LobbyUser], Optional[TCP20922LobbyRoom]]:
        user = self.users.get(client_key)
        room = self.get_room(room_ident)
        if user is None or room is None:
            return user, room
        self.attach_user_to_room(user, room)
        return user, room

    def leave_room(self, client_key: str) -> Optional[TCP20922LobbyUser]:
        user = self.users.get(client_key)
        if user is None:
            return None
        self.detach_user_from_room(user)
        return user

    def record_message(
        self,
        name: str,
        text: str,
        priv: int = 0,
        set_id: int = 0,
        room_ident: int = 0,
        game: int = 0,
        flags: int = 0,
    ) -> None:
        self.messages.append(
            TCP20922LobbyMessage(
                priv=priv,
                set_id=set_id,
                room_ident=room_ident,
                game=game,
                flags=flags,
                name=name,
                text=text,
            )
        )
        del self.messages[:-64]

    def emit_room_event(
        self,
        room: Optional[TCP20922LobbyRoom],
        persona: str,
        text: str,
        flags: int = 8,
    ) -> None:
        self.record_message(
            name=persona,
            text=text,
            room_ident=room.ident if room is not None else 0,
            flags=flags,
        )

    def user_reply_lines(
        self,
        user: TCP20922LobbyUser,
        *,
        addr: str = "127.0.0.1",
        server_addr: str = "127.0.0.1",
        maddr: str = "127.0.0.1",
        sprt: int = 13505,
    ) -> List[str]:
        room = self.get_room(user.room_ident)
        room_ident = room.ident if room is not None else 0
        game_ident = room.ident if room is not None else 0
        return [
            f"NAME={user.display_name}",
            f"PERS={user.persona}",
            f"UID={user.ident}",
            f"ROOM={room_ident}",
            f"GAME={game_ident}",
            "STAT=online",
            "AUX=",
            "RGB=0",
            f"PING={user.ping}",
            "PLAY=0",
            "SEED=0",
            f"FLAGS={user.flags}",
            f"SYNC={int(user.created_at)}",
            f"ADDR={addr}",
            f"LADDR={addr}",
            f"SERV={server_addr}",
            f"SPRT={sprt}",
            f"MADDR={maddr}",
            "GFIDS=0",
            "ATTR=0",
            "HWFLAG=0",
            "HWMASK=0",
            "LEVEL=0",
            "MEDALS=0",
            "LANG=en",
            f"FROM={user.display_name}",
            "REP=0",
        ]

    def room_reply_lines(self, room: TCP20922LobbyRoom) -> List[str]:
        host = self.find_user_by_ident(room.host_user_ident)
        host_name = host.persona if host is not None else room.host_persona
        return [
            f"IDENT={room.ident}",
            f"WHEN={room.created_at:.6e}",
            f"NAME={room.name}",
            f"HOST={host_name}",
            f"ROOM={room.ident}",
            f"MAXSIZE={room.limit}",
            f"MINSIZE={room.min_size}",
            f"COUNT={len(room.occupants)}",
            f"CUSTFLAGS={room.flags}",
            f"SYSFLAGS={room.system_flags}",
            f"EVID={room.event_id}",
            f"EVGID={room.event_group_id}",
            f"NUMPART={room.num_partitions}",
            f"LIMIT={room.limit}",
            f"FLAGS={room.flags}",
            f"PARAMS={room.params}",
        ]

    def room_feed_lines(
        self,
        room: TCP20922LobbyRoom,
        viewer: Optional[TCP20922LobbyUser] = None,
        *,
        addr: str = "127.0.0.1",
        laddr: str = "127.0.0.1",
        maddr: str = "127.0.0.1",
    ) -> List[str]:
        lines = self.room_reply_lines(room)
        occupants: List[TCP20922LobbyUser] = []
        for user_ident in sorted(room.occupants):
            user = self.find_user_by_ident(user_ident)
            if user is not None:
                occupants.append(user)

        if viewer is not None and viewer.ident not in room.occupants:
            occupants.insert(0, viewer)

        if not occupants:
            host = self.find_user_by_ident(room.host_user_ident)
            if host is not None:
                occupants.append(host)

        if not occupants:
            return lines

        lines.append(f"NUMPART={max(1, room.num_partitions)}")
        room_params = room.params or ""
        for idx, user in enumerate(occupants[:8]):
            lines.extend(
                [
                    f"OPID{idx}={user.ident}",
                    f"OPPO{idx}={user.persona}",
                    f"ADDR{idx}={addr}",
                    f"LADDR{idx}={laddr}",
                    f"MADDR{idx}={maddr}",
                    "OPPART{idx}=0".format(idx=idx),
                    f"OPFLAG{idx}={0x10000 if user.ident == room.host_user_ident else 0}",
                    f"OPPARAM{idx}={room_params}",
                ]
            )

        part_count = max(1, room.num_partitions)
        for idx in range(part_count):
            lines.extend(
                [
                    f"PARTSIZE{idx}={room.limit}",
                    f"PARTPARAMS{idx}={room_params}",
                ]
            )
        return lines

    def rooms_reply_lines(self, client_key: str) -> List[str]:
        state = self.get_filter_state(client_key)
        users_in_rooms = sum(1 for user in self.users.values() if user.room_ident > 0)
        users_in_lobby = max(0, len(self.users) - users_in_rooms)
        lines = [
            f"GAMES={1 if self.rooms_by_id else 0}",
            "MYGAME=1",
            f"ROOMS={state.rooms}",
            f"USERS={state.users}",
            f"USERSETS={state.usersets}",
            f"ROOMCOUNT={len(self.rooms_by_id)}",
            f"USERSINLOBBY={users_in_lobby}",
            f"USERSINROOMS={users_in_rooms}",
        ]
        for i, val in enumerate(state.usersets_selected):
            if val:
                lines.append(f"USERSET{i}={val}")
        if state.rooms:
            for idx, room in enumerate(sorted(self.rooms_by_id.values(), key=lambda r: r.ident)):
                if idx >= state.slots:
                    break
                lines.extend(
                    [
                        f"ROOMIDENT{idx}={room.ident}",
                        f"ROOMNAME{idx}={room.name}",
                        f"ROOMHOST{idx}={room.host_persona}",
                        f"ROOMCOUNT{idx}={len(room.occupants)}",
                        f"ROOMLIMIT{idx}={room.limit}",
                        f"ROOMFLAGS{idx}={room.flags}",
                    ]
                )
        lines.extend(
            [
                f"MESGS={state.mesgs}",
                f"ASYNC={state.async_flag}",
                f"RANKS={state.ranks}",
                f"STATS={state.stats}",
                f"SLOTS={state.slots}",
            ]
        )
        if state.mesgs:
            recent = self.messages[-min(8, len(self.messages)) :]
            lines.append(f"MSGCOUNT={len(recent)}")
            for idx, msg in enumerate(recent):
                lines.extend(
                    [
                        f"MSGNAME{idx}={msg.name}",
                        f"MSGTEXT{idx}={msg.text}",
                        f"MSGROOM{idx}={msg.room_ident}",
                        f"MSGFLAGS{idx}={msg.flags}",
                    ]
                )
        return lines
