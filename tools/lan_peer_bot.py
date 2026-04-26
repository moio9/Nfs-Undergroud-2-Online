"""
lan_peer_bot.py — Minimal second LAN client for the NFSU2 plaintext 9900 path.

Use it to connect a fake second player to the Python LAN server so the real
client can test 2-player lobby/game flow without another PC.
"""

from __future__ import annotations

import argparse
import base64
import os
import socket
import struct
import threading
import time
from urllib.parse import unquote


_SHORT_TAGS = {b"newsbadc", b"userbadc"}
_DEFAULT_SKEY = "$5075626c6963204b6579"
_DEFAULT_PARAMS = "TRACK%3d4000%0aDIR%3d0%0aLAPS%3d3"
_DEFAULT_AUX = (
    "C%3d281DCV74j/4AAAAAAAAAAAAAAAClkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZ"
    "KoZXGWBnf6A+gBpYaXJmxpwadG1htcb2G9xvscKHGRxocfHJBykcuHM/oD6AHOBz4c/HPx0AdA+gB0GH+HXDCE"
    "whMMjDIxIMSDCEwhMITCEwyMMvoD6A+gPoD6AHQh0QdFHRh0cdIHSh0wdQHVB1hJg+gPoD6A+gPoD6A+gPoD6A"
    "+gPoD6A+gE3JNrTfk2pNyTa035NqTck2tN+Tak3JNrTfk2q5xucbnG5x+gPoD6A+gPoD6A+gPoD6A+gPoD6A+"
    "gPoD6A+gPoD6A+gPoD6A+gPoD6A+gPoD6A+gPoD6A+gPoD6A+gPoD6A+gPoD6A+gPoD6A+gPoD6A+gPoD6A+"
    "gPoD6A+gPoD6A+gPoBqPJhCYQmEJhHWCpJudmv50et134N+Dfg/oD6AHYA%0aR%3dAA%253d%253d%0a"
)
_BOT_BUILD = "real-init-w1-zero-bind4602-20260418"
_READY_USERFLAGS = 134217728
_RACE_CONTROL_HOST = 1
_RACE_CONTROL_GUEST = 5
_RACE_REAL_INIT_WORD = 0x00010108
_RACE_CONTINUATION_HEX = [
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


def _is_cmd4(raw: bytes) -> bool:
    return len(raw) == 4 and all(32 <= b <= 126 for b in raw)


def _frame(cmd: str, fields: list[str] | None = None) -> bytes:
    body = (("\t".join(fields or [])) if fields else "").encode("utf-8") + b"\x00"
    total = 12 + len(body)
    return cmd.encode("latin1") + b"\x00\x00\x00\x00" + struct.pack(">I", total) + body


def _iter_frames(buf: bytearray) -> list[bytes]:
    out: list[bytes] = []
    off = 0
    while off + 12 <= len(buf):
        tag8 = bytes(buf[off : off + 8])
        if tag8 in _SHORT_TAGS and struct.unpack(">I", bytes(buf[off + 8 : off + 12]))[0] == 12:
            out.append(bytes(buf[off : off + 12]))
            off += 12
            continue
        cmd4 = bytes(buf[off : off + 4])
        if not (_is_cmd4(cmd4) and buf[off + 4 : off + 8] == b"\x00\x00\x00\x00"):
            off += 1
            continue
        total = struct.unpack(">I", bytes(buf[off + 8 : off + 12]))[0]
        if total < 12:
            off += 1
            continue
        if off + total > len(buf):
            break
        out.append(bytes(buf[off : off + total]))
        off += total
    if off:
        del buf[:off]
    return out


def _decode_frame(frame: bytes) -> tuple[str, str]:
    tag8 = frame[:8]
    if tag8 in _SHORT_TAGS:
        return tag8.decode("latin1"), ""
    cmd = frame[:4].decode("latin1", errors="replace")
    body = frame[12:].rstrip(b"\x00").decode("utf-8", errors="replace").replace("\t", " | ")
    return cmd, body


def _field_from_body(body: str, key: str) -> str:
    prefix = f"{key}="
    for part in body.split(" | "):
        part = part.strip()
        if part.startswith(prefix):
            return part[len(prefix) :]
    return ""


def _load_simple_cfg(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path:
        return out
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                text = line.strip()
                if not text or text.startswith("#") or "=" not in text:
                    continue
                key, value = text.split("=", 1)
                value = value.split("#", 1)[0].strip()
                out[key.strip().upper()] = value
    except OSError:
        return {}
    return out


def _cfg_int(fields: dict[str, str], *keys: str, default: int = 0) -> int:
    for key in keys:
        value = fields.get(key.upper(), "").strip()
        if not value:
            continue
        try:
            return int(value, 0)
        except ValueError:
            continue
    return default


def _fields_from_body(body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in body.split(" | "):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, value = part.split("=", 1)
        fields[key.strip().upper()] = value.strip()
    return fields


def _merged_fields(responses: list[tuple[str, str]]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for _cmd, body in responses:
        merged.update(_fields_from_body(body))
    return merged


def _int_from_fields(fields: dict[str, str], *keys: str, default: int = 0) -> int:
    for key in keys:
        value = fields.get(key.upper(), "").strip()
        if not value:
            continue
        try:
            parsed = int(value, 0)
        except ValueError:
            continue
        if parsed > 0:
            return parsed
    return default


def _host_from_fields(fields: dict[str, str], *keys: str) -> str:
    for key in keys:
        value = fields.get(key.upper(), "").strip()
        if value and value not in ("0.0.0.0", "::"):
            return value
    return ""


def _drain(sock: socket.socket, *, wait_s: float = 0.35, quiet: bool = False) -> list[tuple[str, str]]:
    end = time.time() + wait_s
    buf = bytearray()
    out: list[tuple[str, str]] = []
    while time.time() < end:
        remaining = max(0.01, end - time.time())
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        for frame in _iter_frames(buf):
            decoded = _decode_frame(frame)
            out.append(decoded)
            if not quiet:
                cmd, body = decoded
                print(f"RX {cmd}: {body}")
    return out


def _send(sock: socket.socket, cmd: str, fields: list[str] | None = None, *, quiet: bool = False):
    payload = _frame(cmd, fields)
    sock.sendall(payload)
    if not quiet:
        pretty = " | ".join(fields or [])
        print(f"TX {cmd}: {pretty}")


def _bootstrap(sock: socket.socket, *, name: str, persona: str, password: str, aux: str, quiet: bool = False) -> list[tuple[str, str]]:
    responses: list[tuple[str, str]] = []
    local_host, local_port = sock.getsockname()
    burst = b"".join(
        (
            _frame("addr", [f"ADDR={local_host}", f"PORT={local_port}"]),
            _frame("skey", [f"SKEY={_DEFAULT_SKEY}"]),
            _frame("news", ["NAME=7"]),
        )
    )
    sock.sendall(burst)
    if not quiet:
        print(f"TX burst: addr+skey+news ({local_host}:{local_port})")
    responses.extend(_drain(sock, wait_s=0.4, quiet=quiet))
    _send(sock, "~png", [f"REF={time.strftime('%Y.%-m.%-d %H:%M:%S')}"], quiet=quiet)
    responses.extend(_drain(sock, wait_s=0.15, quiet=quiet))
    _send(sock, "sele", ["SLOTS=1"], quiet=quiet)
    responses.extend(_drain(sock, wait_s=0.15, quiet=quiet))
    auth_fields = [f"NAME={name}"]
    if password:
        auth_fields.append(f"PASS={password}")
    _send(sock, "auth", auth_fields, quiet=quiet)
    responses.extend(_drain(sock, wait_s=0.15, quiet=quiet))
    _send(sock, "pers", [f"PERS={persona}"], quiet=quiet)
    responses.extend(_drain(sock, wait_s=0.15, quiet=quiet))
    _send(sock, "user", quiet=quiet)
    responses.extend(_drain(sock, wait_s=0.25, quiet=quiet))
    _send(sock, "auxi", [f"TEXT={aux}"], quiet=quiet)
    responses.extend(_drain(sock, wait_s=0.25, quiet=quiet))
    _send(sock, "gsea", ["START=0", "COUNT=20"], quiet=quiet)
    responses.extend(_drain(sock, wait_s=0.2, quiet=quiet))
    _send(sock, "gsea", ["START=0", "COUNT=20"], quiet=quiet)
    responses.extend(_drain(sock, wait_s=0.25, quiet=quiet))
    return responses


def _game_candidates(responses: list[tuple[str, str]]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for cmd, body in responses:
        if cmd not in ("+gam", "+mgm", "+ses", "gcre", "gjoi", "gset", "gsta"):
            continue
        fields = _fields_from_body(body)
        if _int_from_fields(fields, "IDENT", default=0) <= 0:
            continue
        out.append(fields)
    return out


def _discover_join_target(responses: list[tuple[str, str]], *, join_name: str = "") -> tuple[int, str]:
    candidates = _game_candidates(responses)
    if join_name:
        want = join_name.strip().casefold()
        for fields in reversed(candidates):
            if fields.get("NAME", "").strip().casefold() == want:
                return _int_from_fields(fields, "IDENT", default=0), fields.get("NAME", "")
    for fields in reversed(candidates):
        ident = _int_from_fields(fields, "IDENT", default=0)
        if ident > 0:
            return ident, fields.get("NAME", "")
    return 0, ""


def _join_succeeded(responses: list[tuple[str, str]]) -> bool:
    for cmd, body in responses:
        fields = _fields_from_body(body)
        if cmd in ("gjoi", "+mgm", "+gam", "+ses", "gset", "gsta") and _int_from_fields(fields, "IDENT", default=0) > 0:
            return True
    return False


def _join_or_create(
    sock: socket.socket,
    *,
    mode: str,
    join_ident: int,
    join_name: str,
    discovered_responses: list[tuple[str, str]],
    game_name: str,
    limit: int,
    params: str,
    quiet: bool = False,
) -> list[tuple[str, str]]:
    if mode == "create":
        _send(
            sock,
            "gcre",
            [
                f"NAME={game_name}",
                f"MAXSIZE={limit}",
                f"PARAMS={params}",
                "CUSTFLAGS=67109107",
                "SYSFLAGS=0",
            ],
            quiet=quiet,
        )
        return _drain(sock, wait_s=0.7, quiet=quiet)

    if join_name:
        attempts: list[tuple[str, str | int]] = [("NAME", join_name)]
    else:
        attempts = []
        if join_ident > 0:
            attempts.append(("IDENT", int(join_ident)))
        discovered_ident, _discovered_name = _discover_join_target(discovered_responses)
        if discovered_ident > 0 and all(value != discovered_ident for key, value in attempts if key == "IDENT"):
            attempts.append(("IDENT", discovered_ident))
        if not attempts:
            attempts.append(("IDENT", 1))

    last_responses: list[tuple[str, str]] = []
    for idx, (key, value) in enumerate(attempts):
        fields = [f"{key}={value}"]
        if idx > 0 and not quiet:
            print(f"Retry join with {key}={value}")
        _send(sock, "gjoi", fields, quiet=quiet)
        last_responses = _drain(sock, wait_s=0.8, quiet=quiet)
        if _join_succeeded(last_responses):
            return last_responses
    return last_responses


def _resolve_game_name(responses: list[tuple[str, str]], *, fallback: str) -> str:
    for cmd, body in responses:
        if cmd in ("gjoi", "gcre", "+mgm", "+ses"):
            name = _field_from_body(body, "NAME")
            if name:
                return name
    return fallback


def _responses_indicate_race_start(responses: list[tuple[str, str]]) -> bool:
    for cmd, _body in responses:
        if cmd in ("gsta", "+ses"):
            return True
    return False


def _udp_make_wrapped(src: tuple[str, int], payload: bytes) -> bytes:
    return struct.pack("!H", src[1]) + socket.inet_aton(src[0]) + payload


def _udp_wrap_payload(payload: bytes, *, wrapped: bool, wrap_target: tuple[str, int]) -> bytes:
    if not wrapped:
        return payload
    return _udp_make_wrapped(wrap_target, payload)


def _parse_host_port(value: str, *, default_host: str, default_port: int) -> tuple[str, int]:
    text = str(value or "").strip()
    if not text:
        return default_host, int(default_port)
    if ":" in text:
        host, port_text = text.rsplit(":", 1)
        try:
            port = int(port_text, 0)
        except ValueError:
            port = int(default_port)
        return host.strip() or default_host, port
    try:
        return default_host, int(text, 0)
    except ValueError:
        return text, int(default_port)


def _udp_packet_summary(data: bytes) -> str:
    payload = data
    wrapped = ""
    if len(data) > 10:
        try:
            src_port = struct.unpack_from("!H", data, 0)[0]
            src_ip = socket.inet_ntoa(data[2:6])
        except OSError:
            src_port = 0
            src_ip = ""
        if src_port and src_ip and src_ip != "0.0.0.0":
            wrapped = f" wrapped={src_ip}:{src_port}"
            payload = data[6:]
    word0 = struct.unpack_from("<I", payload, 0)[0] if len(payload) >= 4 else 0
    word1 = struct.unpack_from("<I", payload, 4)[0] if len(payload) >= 8 else 0
    return f"len={len(payload)} w0=0x{word0:08X} w1=0x{word1:08X}{wrapped}"


def _drain_udp(sock: socket.socket, *, quiet: bool = False) -> None:
    while True:
        try:
            data = sock.recv(4096)
        except BlockingIOError:
            break
        except OSError:
            break
        if not data:
            break
        if not quiet:
            print(f"RX UDP: {_udp_packet_summary(data)}")


def _aux_fields(aux_text: str) -> dict[str, str]:
    text = str(aux_text or "").strip()
    if not text:
        return {}
    if "%" in text:
        try:
            text = unquote(text)
        except Exception:
            pass
    out: dict[str, str] = {}
    for line in text.replace("\r", "").split("\n"):
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip().upper()] = value.strip()
    return out


def _car_data_from_aux(aux_text: str) -> bytes:
    car_state = _aux_fields(aux_text).get("C", "")
    if not car_state.startswith("281DC"):
        return bytes(357)
    encoded = car_state[5:]
    try:
        decoded = base64.b64decode(encoded + ("=" * ((4 - len(encoded) % 4) % 4)))
    except Exception:
        return bytes(357)
    if len(decoded) < 357:
        return decoded.ljust(357, b"\x00")
    return decoded[:357]


def _race_bootstrap_packets(aux_text: str, seq: int) -> list[bytes]:
    car_data = _car_data_from_aux(aux_text)
    return [
        struct.pack("<II", 0x65, seq)
        + bytes.fromhex(
            "00000000000000000000000002000fa0000100000001000000030000d38ec600d38ec60000000045"
        ),
        struct.pack("<III", 0x66, seq, 0x02040101) + b"\xf8\x00\x00\x00\x02\x01\x02" + car_data[0:89] + b"\x05",
        struct.pack("<III", 0x67, seq, 0x02040201) + b"\xf8" + car_data[89:184] + b"\x05",
        struct.pack("<III", 0x68, seq, 0x02040301) + b"\xf8" + car_data[184:279] + b"\x05",
        struct.pack("<III", 0x69, seq, 0x02040401) + b"\xac" + car_data[279:357] + bytes.fromhex("0064e414d453132005"),
    ]


def _bytes_from_hex(text: str, *, size: int = 0) -> bytes:
    cleaned = "".join(ch for ch in str(text or "") if ch in "0123456789abcdefABCDEF")
    if len(cleaned) % 2:
        cleaned = cleaned[:-1]
    if not cleaned:
        return b""
    try:
        data = bytes.fromhex(cleaned)
    except ValueError:
        return b""
    if size > 0:
        if len(data) < size:
            return data.ljust(size, b"\x00")
        return data[:size]
    return data


def _race_real_init_packet(room: int, template_hex: str = "") -> bytes:
    template = _bytes_from_hex(template_hex, size=64)
    if template:
        return template
    # Real clients emit a 64-byte zero-filled packet with w0=0x00010108 before
    # the normal 0x65..0x69 raw bootstrap. The room is inferred by the relay,
    # not carried in w1.
    return struct.pack("<II", _RACE_REAL_INIT_WORD, 0) + bytes(56)


def _race_continuation_packets() -> list[bytes]:
    return [bytes.fromhex(item) for item in _RACE_CONTINUATION_HEX]


def _race_control_cmds(role: str, mode: str) -> list[int]:
    if role == "host":
        return [_RACE_CONTROL_HOST]
    if role == "guest":
        return [_RACE_CONTROL_GUEST]
    if role == "both":
        return [_RACE_CONTROL_GUEST, _RACE_CONTROL_HOST]
    # The stock peer paths are asymmetric, but the headless bot is not a real
    # game instance. Sending both probes in join mode gives the relay enough
    # traffic to prime either branch of the race bootstrap.
    return [_RACE_CONTROL_HOST] if mode == "create" else [_RACE_CONTROL_GUEST, _RACE_CONTROL_HOST]


def _resolve_race_room(responses: list[tuple[str, str]], *, fallback: int) -> int:
    game_cmds = {"gjoi", "gcre", "gset", "gsta", "+mgm", "+ses", "+gam"}
    for cmd, body in reversed(responses):
        fields = _fields_from_body(body)
        if cmd == "+usr":
            game_id = _int_from_fields(fields, "GAME", default=0)
            if game_id > 0:
                return game_id
            continue
        if cmd in game_cmds:
            game_id = _int_from_fields(fields, "IDENT", default=0)
            if game_id > 0:
                return game_id
    fields = _merged_fields(responses)
    return _int_from_fields(fields, "GAME", "IDENT", "ROOM", default=max(1, int(fallback or 1)))


def _resolve_race_endpoint(
    responses: list[tuple[str, str]],
    *,
    default_host: str,
    default_port: int,
) -> tuple[str, int]:
    fields = _merged_fields(responses)
    host = _host_from_fields(fields, "RLYHOST", "RELAYHOST", "UDPHOST", "RACEHOST")
    port = _int_from_fields(fields, "RLYPORT", "RELAYPORT", "UDPPORT", "RACEPORT", default=0)
    if not host:
        host = default_host
    if host in ("0.0.0.0", "::"):
        host = "127.0.0.1"
    if port <= 0:
        port = default_port
    return host, port


def _race_afk_loop(
    *,
    stop_event: threading.Event,
    race_start_event: threading.Event,
    relay_host: str,
    relay_port: int,
    bind_host: str,
    bind_port: int,
    wrap_target: tuple[str, int],
    room: int,
    control_cmds: list[int],
    control_interval: float,
    raw_enabled: bool,
    raw_immediate: bool,
    raw_delay: float,
    raw_interval: float,
    bootstrap_repeats: int,
    wrapped: bool,
    real_init: bool,
    real_init_hex: str,
    aux: str,
    quiet: bool,
) -> None:
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        bind_candidates = [int(bind_port or 0)]
        if int(bind_port or 0) > 0:
            bind_candidates.append(0)
        last_bind_error: OSError | None = None
        for candidate_port in bind_candidates:
            try:
                udp.bind((bind_host, candidate_port))
                if candidate_port != int(bind_port or 0) and not quiet:
                    print(f"UDP AFK bind fallback: requested={bind_port} actual={udp.getsockname()[1]}")
                break
            except OSError as exc:
                last_bind_error = exc
        else:
            raise last_bind_error or OSError("UDP bind failed")
        udp.connect((relay_host, relay_port))
        udp.setblocking(False)
        local_addr = udp.getsockname()
        if not quiet:
            cmds = ",".join(str(cmd) for cmd in control_cmds)
            print(
                "UDP AFK: "
                f"relay={relay_host}:{relay_port} local={local_addr[0]}:{local_addr[1]} "
                f"wrap_target={wrap_target[0]}:{wrap_target[1]} "
                f"room=0x{room:08X} cmds={cmds} wrapped={int(wrapped)} "
                f"raw={int(raw_enabled)} real_init={int(real_init)} bootstrap_repeats={bootstrap_repeats}"
            )
        control_interval = max(0.1, float(control_interval or 0.75))
        raw_interval = max(0.05, float(raw_interval or 0.25))
        next_control = 0.0
        next_raw = 0.0
        raw_ready_at: float | None = None
        raw_started = False
        bootstrap_sent_count = 0
        real_init_sent = False
        raw_seq = 0x64
        continuation = _race_continuation_packets()
        continuation_idx = 0
        control_idx = 0

        while not stop_event.is_set():
            now = time.time()
            if now >= next_control:
                cmd = control_cmds[control_idx % len(control_cmds)]
                control_idx += 1
                payload = struct.pack("<II", cmd, int(room))
                payload = _udp_wrap_payload(payload, wrapped=wrapped, wrap_target=wrap_target)
                udp.send(payload)
                if not quiet:
                    print(f"TX UDP control: cmd={cmd} room=0x{room:08X}")
                _drain_udp(udp, quiet=quiet)
                next_control = now + control_interval

            raw_allowed = raw_enabled and (raw_immediate or race_start_event.is_set())
            if raw_allowed and raw_ready_at is None:
                raw_ready_at = now + max(0.0, float(raw_delay or 0.0))
                if not quiet:
                    print(f"UDP AFK raw armed: delay={max(0.0, float(raw_delay or 0.0)):.2f}s")

            if raw_allowed and raw_ready_at is not None and now >= raw_ready_at and now >= next_raw:
                if not raw_started or bootstrap_sent_count < bootstrap_repeats:
                    if real_init:
                        cmd5 = struct.pack("<II", _RACE_CONTROL_GUEST, int(room))
                        out = _udp_wrap_payload(cmd5, wrapped=wrapped, wrap_target=wrap_target)
                        udp.send(out)
                        if not quiet:
                            print(f"TX UDP control: cmd={_RACE_CONTROL_GUEST} room=0x{room:08X} phase=real-init")
                        init_packet = _race_real_init_packet(room, real_init_hex)
                        out = _udp_wrap_payload(init_packet, wrapped=wrapped, wrap_target=wrap_target)
                        udp.send(out)
                        real_init_sent = True
                        if not quiet:
                            print(
                                "TX UDP raw real-init: "
                                f"len={len(init_packet)} w0=0x{_RACE_REAL_INIT_WORD:08X} room=0x{room:08X}"
                            )
                        cmd1 = struct.pack("<II", _RACE_CONTROL_HOST, int(room))
                        out = _udp_wrap_payload(cmd1, wrapped=wrapped, wrap_target=wrap_target)
                        udp.send(out)
                        if not quiet:
                            print(f"TX UDP control: cmd={_RACE_CONTROL_HOST} room=0x{room:08X} phase=real-init")
                    packets = _race_bootstrap_packets(aux, raw_seq)
                    raw_started = True
                    bootstrap_sent_count += 1
                    if not quiet:
                        print(
                            "TX UDP raw bootstrap: "
                            f"packets={len(packets)} seq=0x{raw_seq:08X} "
                            f"repeat={bootstrap_sent_count}/{bootstrap_repeats}"
                        )
                else:
                    packets = [continuation[continuation_idx % len(continuation)]]
                    continuation_idx += 1
                    if not quiet:
                        word0 = struct.unpack_from("<I", packets[0], 0)[0] if len(packets[0]) >= 4 else 0
                        print(f"TX UDP raw idle: w0=0x{word0:08X} idx={continuation_idx}")
                for packet in packets:
                    out = _udp_wrap_payload(packet, wrapped=wrapped, wrap_target=wrap_target)
                    udp.send(out)
                _drain_udp(udp, quiet=quiet)
                next_raw = now + raw_interval

            stop_event.wait(0.05)
    except OSError as exc:
        if not quiet:
            print(f"UDP AFK stopped: {exc}")
    finally:
        udp.close()


def main():
    default_cfg = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server.cfg")
    ap = argparse.ArgumentParser(description="Minimal LAN 9900 peer bot")
    ap.add_argument("--cfg", default=default_cfg)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--name", default="BOT2")
    ap.add_argument("--persona", default="BOT2")
    ap.add_argument("--password", default="bot")
    ap.add_argument("--aux", default=_DEFAULT_AUX)
    ap.add_argument("--mode", choices=("join", "create"), default="join")
    ap.add_argument("--join-ident", type=int, default=0)
    ap.add_argument("--join-name", default="")
    ap.add_argument("--game-name", default="007.BOT2")
    ap.add_argument("--limit", type=int, default=4)
    ap.add_argument("--params", default=_DEFAULT_PARAMS)
    ap.add_argument("--chat", default="")
    ap.add_argument("--ready", dest="ready", action="store_true", default=None)
    ap.add_argument("--no-ready", dest="ready", action="store_false")
    # Give the host UI time to settle after gjoi before toggling ready.
    ap.add_argument("--ready-delay", type=float, default=2.0)
    ap.add_argument("--stay", type=float, default=90.0)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--race-afk", dest="race_afk", action="store_true", default=True)
    ap.add_argument("--no-race-afk", dest="race_afk", action="store_false")
    ap.add_argument("--race-host", default="")
    ap.add_argument("--race-port", type=int, default=0)
    ap.add_argument("--race-room", type=lambda v: int(v, 0), default=0)
    ap.add_argument("--race-role", choices=("auto", "host", "guest", "both"), default="auto")
    ap.add_argument("--race-bind", default="0.0.0.0")
    ap.add_argument("--race-bind-port", type=int, default=0)
    ap.add_argument("--race-wrapped", action="store_true")
    ap.add_argument("--race-wrap-target", default="")
    ap.add_argument("--race-wrap-target-port", type=int, default=0)
    ap.add_argument("--race-afk-interval", type=float, default=0.75)
    ap.add_argument("--race-afk-raw", dest="race_afk_raw", action="store_true", default=True)
    ap.add_argument("--no-race-afk-raw", dest="race_afk_raw", action="store_false")
    ap.add_argument("--race-afk-raw-immediate", action="store_true")
    ap.add_argument("--race-afk-raw-delay", type=float, default=0.5)
    ap.add_argument("--race-afk-raw-interval", type=float, default=0.25)
    ap.add_argument("--race-bootstrap-repeats", type=int, default=3)
    ap.add_argument("--race-real-init", dest="race_real_init", action="store_true", default=None)
    ap.add_argument("--no-race-real-init", dest="race_real_init", action="store_false")
    ap.add_argument("--race-real-init-hex", default="")
    args = ap.parse_args()
    cfg_fields = _load_simple_cfg(args.cfg)
    if args.port <= 0:
        args.port = _cfg_int(
            cfg_fields,
            "LOBBY_LISTEN_PORT",
            "LOBBY_PUBLIC_PORT",
            "PORT",
            default=9900,
        )
    if args.ready is None:
        args.ready = args.mode == "join"
    if args.race_real_init is None:
        args.race_real_init = args.mode == "join" or args.race_role in ("guest", "both")
    if args.race_bind_port <= 0 and args.mode == "join" and args.race_wrapped:
        args.race_bind_port = 4602
    if not args.quiet:
        print(f"lan_peer_bot build={_BOT_BUILD} file={os.path.abspath(__file__)}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((args.host, args.port))
    except ConnectionRefusedError as exc:
        cfg_hint = f" cfg={args.cfg}" if args.cfg else ""
        raise SystemExit(
            f"Cannot connect to LAN lobby at {args.host}:{args.port}.{cfg_hint} "
            "Start server.py first or pass the correct --port."
        ) from exc
    race_stop_event: threading.Event | None = None
    race_start_event: threading.Event | None = None
    race_thread: threading.Thread | None = None
    try:
        bootstrap_responses = _bootstrap(
            sock,
            name=args.name,
            persona=args.persona,
            password=args.password,
            aux=args.aux,
            quiet=args.quiet,
        )
        responses = _join_or_create(
            sock,
            mode=args.mode,
            join_ident=args.join_ident,
            join_name=args.join_name,
            discovered_responses=bootstrap_responses,
            game_name=args.game_name,
            limit=args.limit,
            params=args.params,
            quiet=args.quiet,
        )
        discovered_ident, discovered_name = _discover_join_target(bootstrap_responses, join_name=args.join_name)
        joined_game_name = _resolve_game_name(
            responses,
            fallback=args.join_name or discovered_name or args.game_name,
        )
        if args.ready:
            if args.ready_delay > 0:
                time.sleep(args.ready_delay)
            if joined_game_name:
                _send(
                    sock,
                    "gset",
                    [f"NAME={joined_game_name}", f"USERFLAGS={_READY_USERFLAGS}"],
                    quiet=args.quiet,
                )
                responses.extend(_drain(sock, wait_s=0.5, quiet=args.quiet))
        if args.chat:
            _send(sock, "mesg", [f"TEXT={args.chat}", "ATTR=G"], quiet=args.quiet)
            responses.extend(_drain(sock, wait_s=0.4, quiet=args.quiet))
        if args.race_afk:
            relay_default_host = args.race_host or args.host or "127.0.0.1"
            relay_default_port = int(args.race_port or 2000)
            relay_host, relay_port = _resolve_race_endpoint(
                responses,
                default_host=relay_default_host,
                default_port=relay_default_port,
            )
            if args.race_host:
                relay_host = args.race_host
            if args.race_port > 0:
                relay_port = args.race_port
            room_id = int(args.race_room or 0) or _resolve_race_room(
                responses,
                fallback=args.join_ident or discovered_ident or 1,
            )
            if relay_port > 0 and room_id > 0:
                wrap_target_host = args.host or "127.0.0.1"
                wrap_target_port = int(args.race_wrap_target_port or 0)
                if wrap_target_port <= 0:
                    wrap_target_port = _cfg_int(cfg_fields, "UDP_GAME_PORT", default=3658)
                if args.race_wrap_target:
                    wrap_target = _parse_host_port(
                        args.race_wrap_target,
                        default_host=wrap_target_host,
                        default_port=wrap_target_port,
                    )
                elif args.mode == "join":
                    wrap_target = (wrap_target_host, wrap_target_port)
                else:
                    wrap_target = (relay_host, relay_port)
                race_stop_event = threading.Event()
                race_start_event = threading.Event()
                if args.race_afk_raw_immediate or _responses_indicate_race_start(responses):
                    race_start_event.set()
                race_thread = threading.Thread(
                    target=_race_afk_loop,
                    kwargs={
                        "stop_event": race_stop_event,
                        "race_start_event": race_start_event,
                        "relay_host": relay_host,
                        "relay_port": relay_port,
                        "bind_host": args.race_bind,
                        "bind_port": args.race_bind_port,
                        "wrap_target": wrap_target,
                        "room": room_id,
                        "control_cmds": _race_control_cmds(args.race_role, args.mode),
                        "control_interval": args.race_afk_interval,
                        "raw_enabled": args.race_afk_raw,
                        "raw_immediate": args.race_afk_raw_immediate,
                        "raw_delay": args.race_afk_raw_delay,
                        "raw_interval": args.race_afk_raw_interval,
                        "bootstrap_repeats": max(1, int(args.race_bootstrap_repeats or 1)),
                        "wrapped": args.race_wrapped,
                        "real_init": args.race_real_init,
                        "real_init_hex": args.race_real_init_hex,
                        "aux": args.aux,
                        "quiet": args.quiet,
                    },
                    daemon=True,
                )
                race_thread.start()
            elif not args.quiet:
                print(f"UDP AFK disabled: missing relay/room relay={relay_host}:{relay_port} room={room_id}")
        if not args.quiet:
            print(f"JOIN/CREATE responses: {len(responses)} frames")
            print(f"Holding connection for {args.stay:.1f}s")
        deadline = time.time() + max(0.0, args.stay)
        race_start_reported = False
        while time.time() < deadline:
            drained = _drain(sock, wait_s=1.0, quiet=args.quiet)
            if race_start_event is not None and _responses_indicate_race_start(drained):
                race_start_event.set()
                if not args.quiet and not race_start_reported:
                    print("TCP race start seen; raw UDP AFK traffic enabled")
                    race_start_reported = True
    finally:
        if race_stop_event is not None:
            race_stop_event.set()
        if race_thread is not None:
            race_thread.join(timeout=1.0)
        try:
            _send(sock, "TERM", quiet=args.quiet)
            _drain(sock, wait_s=0.2, quiet=True)
        except Exception:
            pass
        sock.close()


if __name__ == "__main__":
    main()
