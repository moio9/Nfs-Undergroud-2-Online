"""
protocol.py — EA-style key=value text protocol parser/formatter
Matches the wire format found in server.dll strings.
"""

import re
import time
import socket


def format_addr(ip: str) -> str:
    """Format IP as packed 32-bit hex (EA %a format)."""
    try:
        packed = socket.inet_aton(ip)
        return "0x" + packed.hex().upper()
    except Exception:
        return "0x00000000"


def parse_addr(val: str) -> str:
    """Parse packed hex IP back to dotted notation."""
    try:
        val = val.replace("0x", "").replace("0X", "")
        packed = bytes.fromhex(val.zfill(8))
        return socket.inet_ntoa(packed)
    except Exception:
        return "0.0.0.0"


def encode_message(tag: str, **fields) -> str:
    """
    Build a protocol message string.
    e.g. encode_message("USER", NAME="Player1", ROOM=1, FLAGS=0.0)
    -> '+USER NAME=Player1 ROOM=1 FLAGS=0.000000\n'
    """
    parts = []
    for k, v in fields.items():
        if isinstance(v, float):
            parts.append(f"{k}={v:.6f}")
        elif isinstance(v, str) and " " in v:
            parts.append(f'{k}="{v}"')
        else:
            parts.append(f"{k}={v}")
    body = " ".join(parts)
    return f"+{tag} {body}\n" if body else f"+{tag}\n"


def encode_error(tag: str, code: int, msg: str) -> str:
    return f"-{tag} ERROR={code} TEXT={msg!r}\n"


def encode_stat_line(tag: str, **fields) -> str:
    """XML-style stat record as seen in DLL."""
    attrs = " ".join(f'{k}="{v}"' for k, v in fields.items())
    return f"<{tag} {attrs} />"


def parse_message(raw: str):
    """
    Parse a raw message line into (sign, tag, fields_dict).
    Lines starting with '+' are success, '-' are errors, others are commands.
    """
    raw = raw.strip()
    if not raw:
        return None, None, {}

    sign = ""
    if raw[0] in ("+", "-"):
        sign = raw[0]
        raw = raw[1:]

    parts = raw.split(None, 1)
    tag = parts[0].upper() if parts else ""
    fields_str = parts[1] if len(parts) > 1 else ""

    fields = {}
    # Parse key=value pairs, respecting quoted strings
    pattern = r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)'
    for m in re.finditer(pattern, fields_str):
        k = m.group(1).upper()
        v = m.group(2).strip('"')
        # Try numeric conversion
        try:
            fields[k] = int(v)
        except ValueError:
            try:
                fields[k] = float(v)
            except ValueError:
                fields[k] = v

    return sign, tag, fields


def encode_master_stat(users_lobby: int, users_rooms: int,
                       users_games: int, games_progress: int,
                       games_created: int, games_completed: int,
                       rooms: int, sync: int) -> str:
    """Matches: <master usersInLobby=%d usersInRooms=%d ... />"""
    return (f"<master usersInLobby={users_lobby} usersInRooms={users_rooms} "
            f"usersInGames={users_games} gamesInProgress={games_progress} "
            f"gamesCreated={games_created} gamesCompleted={games_completed} "
            f"rooms={rooms} sync={sync} />\n")


def encode_user_record(user: dict) -> str:
    """
    Full user record matching DLL format:
    NAME=%s PERS=%s UID=%s ROOM=%d GAME=%d STAT=%s AUX=%s RGB=%d
    PING=%d PLAY=%d SEED=%d FLAGS=%f SYNC=%d ADDR=%a LADDR=%a ...
    """
    return encode_message(
        "USER",
        NAME=user.get("name", ""),
        PERS=user.get("pers", ""),
        UID=user.get("uid", 0),
        ROOM=user.get("room", 0),
        GAME=user.get("game", 0),
        STAT=user.get("stat", "IDLE"),
        AUX=user.get("aux", ""),
        RGB=user.get("rgb", 0),
        PING=user.get("ping", 0),
        PLAY=user.get("play", 0),
        SEED=user.get("seed", 0),
        FLAGS=float(user.get("flags", 0)),
        SYNC=user.get("sync", 0),
        ADDR=user.get("addr", "0.0.0.0"),
        LADDR=user.get("laddr", "0.0.0.0"),
        SERV=user.get("serv", "0.0.0.0"),
        SPRT=user.get("sprt", 0),
        LEVEL=user.get("level", 1),
        MEDALS=user.get("medals", 0),
        LANG=user.get("lang", "en"),
        REP=user.get("rep", 0),
    )


def encode_room_record(room: dict) -> str:
    """IDENT=%d WHEN=%e NAME=%s HOST=%s ROOM=%d MAXSIZE=%d ..."""
    return encode_message(
        "ROOM",
        IDENT=room["id"],
        WHEN=time.time(),
        NAME=room.get("name", ""),
        HOST=room.get("host", ""),
        TYPE=room.get("type", "PUBLIC"),
        MAXSIZE=room.get("maxsize", 8),
        MINSIZE=room.get("minsize", 2),
        COUNT=room.get("count", 0),
        CUSTFLAGS=room.get("custflags", 0),
        SYSFLAGS=room.get("sysflags", 0),
        PRIV=room.get("private", 0),
        MATCHED=room.get("matched", 0),
        HASPASS=room.get("haspass", 0),
    )


def encode_game_record(game: dict) -> str:
    """IDENT=%d TYPE=%s COUNT=%d LIMIT=%d ADDR=%a PORT=%d FLAGS=%f ..."""
    return encode_message(
        "GAME",
        IDENT=game["id"],
        TYPE=game.get("type", "PUBLIC"),
        COUNT=game.get("count", 0),
        LIMIT=game.get("limit", 8),
        MINSIZE=game.get("minsize", 2),
        ADDR=game.get("addr", "0.0.0.0"),
        PORT=game.get("port", 0),
        FLAGS=float(game.get("flags", 0)),
        SECRET=game.get("secret", ""),
        CUSTOM=game.get("custom", ""),
        FORMAT=game.get("format", ""),
        PRIV=game.get("private", 0),
        MATCHED=game.get("matched", 0),
        RLYHOST=game.get("rlyhost", game.get("addr", "0.0.0.0")),
        RLYPORT=game.get("rlyport", game.get("port", 0)),
    )
