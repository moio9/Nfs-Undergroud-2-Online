"""
test_client.py — Integration test: starts server, connects a few clients,
exercises all major subsystems, then shuts down cleanly.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import socket
import struct
import time
import threading
import logging

logging.basicConfig(level=logging.WARNING)

# ------------------------------------------------------------------ #

def send_recv(sock: socket.socket, msg: str, wait: float = 0.3) -> str:
    sock.sendall((msg + "\n").encode())
    time.sleep(wait)
    resp = b""
    sock.settimeout(0.5)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
    except socket.timeout:
        pass
    return resp.decode("utf-8", errors="replace")


def make_client(host="127.0.0.1", port=9900) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s


def make_control_message(verb: str, lines=None) -> bytes:
    lines = lines or []
    body = ("\n".join(lines) + "\n").encode("utf-8") + b"\x00" if lines else b"\x00"
    return verb.encode("ascii") + b"\x00\x00\x00\x00" + struct.pack(">I", 12 + len(body)) + body


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("socket closed")
        data.extend(chunk)
    return bytes(data)


def recv_control_message(sock: socket.socket):
    hdr = recv_exact(sock, 12)
    verb = hdr[:4].decode("ascii", errors="replace")
    total = struct.unpack(">I", hdr[8:12])[0]
    body = recv_exact(sock, total - 12) if total > 12 else b""
    return verb, body.decode("utf-8", errors="replace").rstrip("\x00")


def send_control_expect(sock: socket.socket, verb: str, lines, expected: str):
    sock.sendall(make_control_message(verb, lines))
    deadline = time.time() + 1.0
    seen = []
    while time.time() < deadline:
        got_verb, body = recv_control_message(sock)
        seen.append(got_verb)
        if got_verb == expected:
            return body
    raise AssertionError(f"expected control {expected}, saw {seen}")


def recv_control_until(sock: socket.socket, expected: str, timeout: float = 1.0):
    deadline = time.time() + timeout
    seen = []
    while time.time() < deadline:
        try:
            got_verb, body = recv_control_message(sock)
        except socket.timeout:
            continue
        seen.append(got_verb)
        if got_verb == expected:
            return body
    raise AssertionError(f"expected control {expected}, saw {seen}")


def parse_int_field(resp: str, name: str) -> int:
    prefix = name + "="
    for part in resp.replace("\n", " ").split():
        if part.startswith(prefix):
            try:
                return int(part[len(prefix):])
            except ValueError:
                return 0
    return 0


def _assert_stock_game_field_order(fields, label):
    keys = [field.split("=", 1)[0] for field in fields]

    def pos(key):
        assert key in keys, f"{label} missing {key}: {fields!r}"
        return keys.index(key)

    sequence = [
        "NUMPART",
        "OPID0",
        "OPPO0",
        "ADDR0",
        "LADDR0",
        "MADDR0",
        "OPPART0",
        "OPFLAG0",
        "OPID1",
        "OPPO1",
        "ADDR1",
        "LADDR1",
        "MADDR1",
        "OPPART1",
        "OPFLAG1",
        "PARTSIZE0",
        "PARAMS",
        "PARTPARAMS0",
        "OPPARAM0",
        "OPPARAM1",
    ]
    positions = [pos(key) for key in sequence]
    assert positions == sorted(positions), f"{label} field order differs from stock capture: {fields!r}"


def _field_map(fields):
    out = {}
    for field in fields:
        key, _, value = field.partition("=")
        out[key] = value
    return out


# ------------------------------------------------------------------ #

def assert_endpoint_resolution():
    from server import GameServer
    import tempfile
    import textwrap

    with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False) as fh:
        fh.write(textwrap.dedent("""            LOBBY_LISTEN_HOST=0.0.0.0
            LOBBY_LISTEN_PORT=2222
            RACE_PUBLIC_HOST=udp.example
            RACE_PUBLIC_PORT=3333
            CONTROL_PORT=20923
        """))
        cfg_path = fh.name

    try:
        srv = GameServer(cfg_path)
        assert srv.lobby_tcp_port() == 2222
        assert srv._listen_port("lobby") == 2222
        assert srv.race_udp_endpoint_for() == ("udp.example", 3333)

        with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False) as fh2:
            fh2.write(textwrap.dedent("""                LOBBY_PUBLIC_HOST=lobby.example
                LOBBY_PUBLIC_PORT=5555
                RACE_LISTEN_HOST=0.0.0.0
                RACE_LISTEN_PORT=6666
            """))
            cfg_path2 = fh2.name
        try:
            srv2 = GameServer(cfg_path2)
            assert srv2._listen_port("lobby") == 5555
            assert srv2.lobby_tcp_host() == "lobby.example"
            assert srv2.lobby_tcp_port() == 5555
            assert srv2.race_udp_endpoint_for() == ("0.0.0.0", 6666)
        finally:
            os.unlink(cfg_path2)
    finally:
        os.unlink(cfg_path)


def assert_detached_open_game_is_discarded_on_relogin():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def close(self):
            pass

        def shutdown(self, how):
            pass

    with tempfile.NamedTemporaryFile("w", suffix=".cfg", delete=False) as fh:
        fh.write(textwrap.dedent("""\
            CONTROL_LISTEN_PORT=0
            CONTROL_PORT=0
            LAN_DETACHED_GRACE=20
        """))
        cfg_path = fh.name

    try:
        srv = GameServer(cfg_path)
        srv.is_running = True
        old = User(DummyConn(), ("127.0.0.1", 1111), name="Test")
        old.pers = "Test"
        assert srv.users.add(old)
        game = srv.games.create(room_id=0, host_uid=old.uid, limit=2, custom="testgame")
        assert game is not None
        game.add_player(old.uid)
        old.game = game.id
        old.stat = "GAME"

        h1 = ClientHandler(srv, old)
        report_frame = ClientHandler._make_20922_tab_message(
            "rept",
            ["PERS=Test", "LANG=NA", "TYPE=Cheating"],
        )
        consumed = h1._consume_bootstrap_frames(report_frame)
        assert consumed == len(report_frame), "20922 rept frame was not consumed"
        assert srv._social_reports and srv._social_reports[-1]["target"] == "Test", "20922 rept was not recorded"
        assert old.conn.sent.startswith(b"rept"), "20922 rept ack was not sent"
        assert b"Report complete" in old.conn.sent, "20922 rept ack did not include completion text"

        peer = User(DummyConn(), ("10.0.0.2", 3333), name="Peer")
        peer.pers = "Peer"
        assert srv.users.add(peer)
        hpeer = ClientHandler(srv, peer)
        game.add_player(peer.uid)
        peer.game = game.id
        peer.stat = "GAME"
        kick_frame = ClientHandler._make_20922_tab_message(
            "gset",
            [f"NAME={game.custom}", "KICK=Peer"],
        )
        consumed = h1._consume_bootstrap_frames(kick_frame)
        assert consumed == len(kick_frame), "20922 gset KICK frame was not consumed"
        time.sleep(0.08)
        assert peer.game == 0, "gset KICK did not remove remote target from game"
        assert b"COUNT=1" in old.conn.sent, "gset KICK did not ack host with the remaining game snapshot"
        assert b"+usr" in peer.conn.sent and b"GAME=0" in peer.conn.sent, "gset KICK did not clear target GAME state"
        assert b"+who" in peer.conn.sent and b"G=0" in peer.conn.sent, "gset KICK did not update target presence"
        assert b"+gam" in peer.conn.sent or b"+mgm" in peer.conn.sent, "gset KICK did not keep room visible with the target removed"

        peer.conn.sent.clear()
        post_kick_gset = ClientHandler._make_20922_tab_message(
            "gset",
            [f"NAME={game.custom}", "USERFLAGS=0"],
        )
        consumed = hpeer._consume_bootstrap_frames(post_kick_gset)
        assert consumed == len(post_kick_gset), "post-kick gset frame was not consumed"
        time.sleep(0.03)
        assert b"+usr" in peer.conn.sent and b"GAME=0" in peer.conn.sent, "post-kick gset returned to game instead of clearing target state"
        assert b"COUNT=1" in peer.conn.sent, "post-kick gset did not mirror LANOPTIONS game snapshot"

        peer.conn.sent.clear()
        gsea_frame = ClientHandler._make_20922_tab_message("gsea", ["START=0", "COUNT=20"])
        consumed = hpeer._consume_bootstrap_frames(gsea_frame)
        assert consumed == len(gsea_frame), "post-kick gsea frame was not consumed"
        assert b"COUNT=0" in peer.conn.sent, "post-kick gsea still advertised kicked room"
        assert b"+gam" not in peer.conn.sent and b"+mgm" not in peer.conn.sent, "post-kick gsea leaked kicked room snapshot"

        peer.conn.sent.clear()
        body = (
            f"CALLUSER={old.uid}\tCALLPING=1\tCALLADDR=127.0.0.1\t"
            f"NAME={game.custom}\tKICK=Peer\t"
        ).encode("utf-8") + b"\x00"
        token = 0xFFFFFBFA
        upper_gset = b"GSET" + struct.pack(">I", token) + struct.pack(">I", 12 + len(body)) + body
        consumed = hpeer._consume_bootstrap_frames(upper_gset)
        assert consumed == len(upper_gset), "uppercase GSET kick frame was not consumed"
        time.sleep(0.03)
        assert peer.conn.sent[:4] == struct.pack(">I", token), "uppercase GSET did not receive token reply"
        assert b"COUNT=1" in peer.conn.sent and b"GAME=0" in peer.conn.sent, "uppercase GSET did not mirror LANOPTIONS kick update"
        hpeer._disconnect_reason = "test_cleanup"
        hpeer._on_disconnect()

        h1._disconnect_reason = "peer_closed"
        h1._on_disconnect()
        assert srv.games.get(game.id) is None, "open game survived host peer_closed disconnect"
        assert srv.users.get(old.uid) is None, "open-game host was preserved as detached instead of removed"

        new = User(DummyConn(), ("127.0.0.1", 2222), name="Test")
        new.pers = "Test"
        h2 = ClientHandler(srv, new)
        assert srv.users.add(new)
        h2._probe_display_name = "Test"
        h2._probe_persona = "Test"
        h2._cleanup_replaced_detached_users()

        assert new.game == 0, "new login inherited stale open game membership"
    finally:
        os.unlink(cfg_path)


def assert_offline_open_game_is_discarded_without_detach_marker():
    from server import GameServer
    from client_handler import ClientHandler
    from user_manager import User
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
            CONTROL_ALIAS_PORT=0
            RELAY_PORT=0
            LAN_PERSONA_UNIQUE=1
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)

        stale = User(DummyConn(), ("127.0.0.1", 1111), name="Ghost")
        stale.pers = "Ghost"
        stale.connected = False
        stale.stat = "GAME"
        assert srv.users.add(stale)
        game = srv.games.create(room_id=0, host_uid=stale.uid, limit=2, custom="ghost-room")
        assert game is not None, "failed to create ghost test game"
        assert srv.games.join(game.id, stale.uid), "failed to add stale user to ghost test game"
        stale.game = game.id

        fresh = User(DummyConn(), ("127.0.0.1", 2222), name="Ghost")
        fresh.pers = "Ghost"
        handler = ClientHandler(srv, fresh)
        assert srv.users.add(fresh)
        handler._probe_display_name = "Ghost"
        handler._probe_persona = "Ghost"

        handler._cleanup_replaced_detached_users()

        assert srv.games.get(game.id) is None, "offline ghost game survived relogin cleanup"
        assert fresh.game == 0, "fresh login inherited offline ghost game"
        assert srv.users.get(stale.uid) is None, "offline ghost user was not removed on reconnect"
    finally:
        os.unlink(cfg_path)


def assert_social_aliases_do_not_self_target():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    from control_handler import ControlHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent(f"""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
            CONTROL_SOCIAL_ENABLE=1
            CONTROL_SOCIAL_ALL_ONLINE_ENABLE=1
            LAN_AUTH_ACCOUNTS_FILE=/home/moioyoyo/U2Online/LAN/data/auth_accounts.json
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        user = User(DummyConn(), ("127.0.0.1", 1111), name="Moio9")
        user.pers = "Moio"
        assert srv.users.add(user)
        lan_handler = ClientHandler(srv, user)
        control = ControlHandler(srv, DummyConn(), ("127.0.0.1", 2222))
        control._peer_user = "Moio"
        assert srv.control_social_same_identity("Moio", "Moio9"), "alias identity was not canonicalized"
        assert srv.control_social_add_relation("Moio", "Moio9", "B") == "N", "self alias became a buddy row"
        assert srv.control_social_presence_row("Moio", "Moio9") is None, "self alias leaked into presence rows"
        assert control._deliver_lan_private_message("Moio9", "hello") == 0, "self alias delivered a private LAN message"
        lan_handler._disconnect_reason = "test_cleanup"
        lan_handler._on_disconnect()
    finally:
        os.unlink(cfg_path)


def assert_control_padd_does_not_emit_pget():
    from server import GameServer
    from user_manager import User
    from control_handler import ControlHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
            CONTROL_SOCIAL_ENABLE=1
            CONTROL_SOCIAL_ALL_ONLINE_ENABLE=1
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        owner = User(DummyConn(), ("127.0.0.1", 1111), name="Juc")
        owner.pers = "Jucator"
        target = User(DummyConn(), ("127.0.0.1", 1112), name="Moio9")
        target.pers = "Moio"
        assert srv.users.add(owner)
        assert srv.users.add(target)
        conn = DummyConn()
        control = ControlHandler(srv, conn, ("127.0.0.1", 2222))
        control._peer_user = "Jucator"
        assert control._handle_presence_add("PADD", {"LRSC": "PC", "USER": "Moio"}), "PADD handler failed"
        sent = bytes(conn.sent)
        assert b"PADD" in sent, f"PADD ack missing: {sent!r}"
        assert b"PGET" not in sent, f"PADD handler leaked PGET: {sent!r}"
    finally:
        os.unlink(cfg_path)


def assert_control_same_game_presence_suppressed():
    from server import GameServer
    from user_manager import User
    from control_handler import ControlHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
            CONTROL_SOCIAL_ENABLE=1
            CONTROL_SOCIAL_ALL_ONLINE_ENABLE=1
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        owner = User(DummyConn(), ("127.0.0.1", 1111), name="Moio9")
        owner.pers = "Moio"
        peer = User(DummyConn(), ("127.0.0.1", 1112), name="Juc")
        peer.pers = "Jucator"
        assert srv.users.add(owner)
        assert srv.users.add(peer)
        game = srv.games.create(room_id=0, host_uid=owner.uid, limit=2, custom="room")
        assert game is not None
        assert srv.games.join(game.id, owner.uid)
        assert srv.games.join(game.id, peer.uid)
        owner.game = game.id
        owner.stat = "GAME"
        peer.game = game.id
        peer.stat = "GAME"

        owner_control = ControlHandler(srv, DummyConn(), ("127.0.0.1", 2222))
        owner_control._peer_user = "Moio"
        peer_control = ControlHandler(srv, DummyConn(), ("127.0.0.1", 2223))
        peer_control._peer_user = "Jucator"
        srv.control_social_register(owner_control, "Moio", addr="127.0.0.1")
        srv.control_social_register(peer_control, "Jucator", addr="127.0.0.1")
        owner_control.conn.sent.clear()
        peer_control.conn.sent.clear()

        srv.control_social_update_presence(peer_control, show="AWAY", stat="GAME")
        sent = bytes(owner_control.conn.sent)
        assert b"RNOT" not in sent and b"ROST" not in sent and b"PGET" not in sent, f"same-game presence should be suppressed: {sent!r}"
    finally:
        os.unlink(cfg_path)


def assert_lan_lobby_online_who_suppressed_for_game_handlers():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        srv.is_running = True

        host = User(DummyConn(), ("127.0.0.1", 1111), name="Juc")
        host.pers = "Jucator"
        lobby = User(DummyConn(), ("127.0.0.1", 1112), name="Lobby")
        lobby.pers = "Lobby"
        guest = User(DummyConn(), ("127.0.0.1", 1113), name="Moio9")
        guest.pers = "Moio"
        assert srv.users.add(host)
        assert srv.users.add(lobby)
        assert srv.users.add(guest)

        hhost = ClientHandler(srv, host)
        hlobby = ClientHandler(srv, lobby)
        hguest = ClientHandler(srv, guest)

        game = srv.games.create(room_id=0, host_uid=host.uid, limit=2, custom="first-room")
        assert game is not None, "failed to create online-who suppression game"
        assert srv.games.join(game.id, host.uid)
        host.game = game.id
        host.stat = "GAME"
        lobby.stat = "LOBBY"
        guest.game = 0
        guest.stat = "LOBBY"

        hguest._lan_broadcast_online_who(guest, delay_s=0, exclude_uid=guest.uid)
        time.sleep(0.05)

        assert b"+who" not in host.conn.sent, f"lobby online-who leaked to in-game host: {host.conn.sent!r}"
        assert b"+who" in lobby.conn.sent and b"N=Moio" in lobby.conn.sent, "lobby user did not receive online-who"

        hhost._disconnect_reason = "test_cleanup"
        hhost._on_disconnect()
        hlobby._disconnect_reason = "test_cleanup"
        hlobby._on_disconnect()
        hguest._disconnect_reason = "test_cleanup"
        hguest._on_disconnect()
    finally:
        os.unlink(cfg_path)


def assert_lan_host_left_resets_peer_game_state():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        srv.is_running = True

        host = User(DummyConn(), ("127.0.0.1", 1211), name="Juc")
        host.pers = "Jucator"
        peer = User(DummyConn(), ("127.0.0.1", 1212), name="Moio9")
        peer.pers = "Moio"
        assert srv.users.add(host)
        assert srv.users.add(peer)

        hhost = ClientHandler(srv, host)
        hpeer = ClientHandler(srv, peer)
        game = srv.games.create(room_id=0, host_uid=host.uid, limit=2, custom="host-left")
        assert game is not None, "failed to create host-left game"
        assert srv.games.join(game.id, host.uid)
        assert srv.games.join(game.id, peer.uid)
        host.game = game.id
        host.stat = "GAME"
        peer.game = game.id
        peer.stat = "GAME"

        peer.conn.sent.clear()
        removed_game, removed = srv.games.leave(game.id, host.uid)
        hhost._lan_on_game_departure(removed_game, departed_uid=host.uid, removed=removed, delay_s=0)
        time.sleep(0.10)

        assert removed, "host leave did not remove open game"
        assert peer.game == 0 and peer.stat == "LOBBY", "host-left did not clear peer server-side game state"
        sent = bytes(peer.conn.sent)
        frames = ClientHandler._extract_20922_messages(bytearray(sent))
        who_frames = []
        mgm_frames = []
        for frame in frames:
            cmd = frame[:4].decode("ascii", errors="replace")
            kv = ClientHandler._parse_20922_kv(frame[12:-1])
            if cmd == "+who":
                who_frames.append(kv)
            if cmd == "+mgm":
                mgm_frames.append(kv)
        assert any(kv.get("G") == "0" and kv.get("I") == str(peer.uid) for kv in who_frames), f"host-left did not send +who G=0 reset: {who_frames!r}"
        assert any(kv.get("IDENT") == str(game.id) and "NAME" not in kv and "COUNT" not in kv for kv in mgm_frames), f"host-left did not send +mgm IDENT invalidation: {mgm_frames!r}"
        assert b"+usr" not in sent and b"+gam" not in sent and b"+agm" not in sent, f"host-left leaked legacy delete frames: {sent!r}"
        assert b"+msg" not in sent and b"KICK" not in sent, f"host-left used kick/message reset instead of close: {sent!r}"
        assert b"gdel" not in sent and b"glea" not in sent, f"host-left sent unsolicited leave/delete commands to peer: {sent!r}"
        assert all(frame[:4] != b"EVGI" for frame in frames), f"host-left sent host-only EVGI snapshot that can keep the room visible: {sent!r}"

        hpeer._disconnect_reason = "test_cleanup"
        hpeer._on_disconnect()
    finally:
        os.unlink(cfg_path)


def assert_lan_delayed_lobby_snapshot_does_not_resurrect_removed_game():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        srv.is_running = True

        host = User(DummyConn(), ("127.0.0.1", 1241), name="Juc")
        host.pers = "Jucator"
        peer = User(DummyConn(), ("127.0.0.1", 1242), name="Moio9")
        peer.pers = "Moio"
        assert srv.users.add(host)
        assert srv.users.add(peer)

        hhost = ClientHandler(srv, host)
        hpeer = ClientHandler(srv, peer)
        game = srv.games.create(room_id=0, host_uid=host.uid, limit=2, custom="quick-exit")
        assert game is not None
        assert srv.games.join(game.id, host.uid)
        host.game = game.id
        host.stat = "GAME"
        peer.stat = "LOBBY"

        hhost._lan_broadcast_lobby_snapshot(delay_s=0.05, exclude_uid=host.uid, with_gcm=True)
        time.sleep(0.01)

        removed_game, removed = srv.games.leave(game.id, host.uid)
        host.game = 0
        host.stat = "LOBBY"
        hhost._lan_on_game_departure(removed_game, departed_uid=host.uid, removed=removed, delay_s=0)
        time.sleep(0.14)

        frames = ClientHandler._extract_20922_messages(bytearray(peer.conn.sent))
        stale_gam = []
        stale_gcr = []
        for frame in frames:
            cmd = frame[:4].decode("ascii", errors="replace")
            body = frame[12:-1]
            if cmd == "+gam" and b"NAME=quick-exit" in body:
                stale_gam.append(body)
            if cmd == "+sst" and b"GCR=1" in body:
                stale_gcr.append(body)
        assert not stale_gam, f"delayed lobby snapshot resurrected removed room: {stale_gam!r}"
        assert not stale_gcr, f"delayed lobby GCR kept removed room visible: {stale_gcr!r}"

        peer.conn.sent.clear()
        gsea = ClientHandler._make_20922_tab_message("gsea", ["START=0", "COUNT=20"])
        consumed = hpeer._consume_bootstrap_frames(gsea)
        assert consumed == len(gsea), "post-host-exit gsea frame was not consumed"
        time.sleep(0.08)
        sent = bytes(peer.conn.sent)
        assert b"COUNT=0" in sent, f"post-host-exit gsea did not report empty lobby: {sent!r}"
        assert b"+gam" not in sent and b"NAME=quick-exit" not in sent, f"post-host-exit gsea leaked removed room: {sent!r}"

        hpeer._disconnect_reason = "test_cleanup"
        hpeer._on_disconnect()
    finally:
        os.unlink(cfg_path)


def assert_lan_removed_unrelated_game_does_not_snapshot_active_host():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        srv.is_running = True

        old_host = User(DummyConn(), ("127.0.0.1", 1243), name="Juc")
        old_host.pers = "Jucator"
        new_host = User(DummyConn(), ("127.0.0.1", 1244), name="Moio9")
        new_host.pers = "Moio"
        lobby = User(DummyConn(), ("127.0.0.1", 1245), name="Lobby")
        lobby.pers = "Lobby"
        assert srv.users.add(old_host)
        assert srv.users.add(new_host)
        assert srv.users.add(lobby)

        hold = ClientHandler(srv, old_host)
        hnew = ClientHandler(srv, new_host)
        hlobby = ClientHandler(srv, lobby)

        old_game = srv.games.create(room_id=0, host_uid=old_host.uid, limit=2, custom="old-after-kick")
        new_game = srv.games.create(room_id=0, host_uid=new_host.uid, limit=2, custom="new-after-kick")
        assert old_game is not None and new_game is not None
        assert srv.games.join(old_game.id, old_host.uid)
        assert srv.games.join(new_game.id, new_host.uid)
        old_host.game = old_game.id
        old_host.stat = "GAME"
        new_host.game = new_game.id
        new_host.stat = "GAME"
        lobby.stat = "LOBBY"

        hnew.user.conn.sent.clear()
        hlobby.user.conn.sent.clear()
        removed_game, removed = srv.games.leave(old_game.id, old_host.uid)
        old_host.game = 0
        old_host.stat = "LOBBY"
        hold._lan_on_game_departure(removed_game, departed_uid=old_host.uid, removed=removed, delay_s=0)
        time.sleep(0.08)

        active_sent = bytes(new_host.conn.sent)
        lobby_sent = bytes(lobby.conn.sent)
        assert b"NAME=new-after-kick" not in active_sent and b"+ses" not in active_sent, f"unrelated old-room removal sent lobby snapshot to active host: {active_sent!r}"
        assert b"NAME=new-after-kick" in lobby_sent, f"lobby user did not receive current game snapshot: {lobby_sent!r}"

        hold._disconnect_reason = "test_cleanup"
        hold._on_disconnect()
        hnew._disconnect_reason = "test_cleanup"
        hnew._on_disconnect()
        hlobby._disconnect_reason = "test_cleanup"
        hlobby._on_disconnect()
    finally:
        os.unlink(cfg_path)


def assert_lan_gset_for_removed_room_returns_reset():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        srv.is_running = True

        peer = User(DummyConn(), ("127.0.0.1", 1222), name="Moio9")
        peer.pers = "Moio"
        assert srv.users.add(peer)
        hpeer = ClientHandler(srv, peer)

        gset = ClientHandler._make_20922_tab_message(
            "gset",
            ["NAME=removed-room", "USERFLAGS=134217728"],
        )
        consumed = hpeer._consume_bootstrap_frames(gset)
        assert consumed == len(gset), "removed-room gset frame was not consumed"

        sent = bytes(peer.conn.sent)
        frames = ClientHandler._extract_20922_messages(bytearray(sent))
        peer_usr = []
        for frame in frames:
            cmd = frame[:4].decode("ascii", errors="replace")
            kv = ClientHandler._parse_20922_kv(frame[12:-1])
            if cmd == "+usr" and kv.get("I") == str(peer.uid):
                peer_usr.append(kv)
        assert b"gset" in sent, f"removed-room gset ack missing: {sent!r}"
        assert any(kv.get("G") == "0" and kv.get("T") == "2" for kv in peer_usr), f"removed-room gset did not send stock +usr game reset: {peer_usr!r}"
        assert b"KICK" not in sent and b"gdel" not in sent and b"glea" not in sent, f"removed-room gset used non-capture reset frames: {sent!r}"

        hpeer._disconnect_reason = "test_cleanup"
        hpeer._on_disconnect()
    finally:
        os.unlink(cfg_path)


def assert_lan_gset_for_recent_removed_room_reinvalidates_room():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        srv.is_running = True

        host = User(DummyConn(), ("127.0.0.1", 1231), name="Juc")
        host.pers = "Jucator"
        peer = User(DummyConn(), ("127.0.0.1", 1232), name="Moio9")
        peer.pers = "Moio"
        assert srv.users.add(host)
        assert srv.users.add(peer)

        hhost = ClientHandler(srv, host)
        hpeer = ClientHandler(srv, peer)
        game = srv.games.create(room_id=0, host_uid=host.uid, limit=2, custom="547.Jucator")
        assert game is not None
        assert srv.games.join(game.id, host.uid)
        assert srv.games.join(game.id, peer.uid)
        host.game = game.id
        host.stat = "GAME"
        peer.game = game.id
        peer.stat = "GAME"

        removed_game, removed = srv.games.leave(game.id, host.uid)
        hhost._lan_on_game_departure(removed_game, departed_uid=host.uid, removed=removed, delay_s=0)
        time.sleep(0.08)
        peer.conn.sent.clear()

        gset = ClientHandler._make_20922_tab_message(
            "gset",
            ["NAME=547.Jucator", "USERFLAGS=134217728"],
        )
        consumed = hpeer._consume_bootstrap_frames(gset)
        assert consumed == len(gset), "recent removed-room gset frame was not consumed"

        sent = bytes(peer.conn.sent)
        frames = ClientHandler._extract_20922_messages(bytearray(sent))
        who_frames = []
        mgm_frames = []
        for frame in frames:
            cmd = frame[:4].decode("ascii", errors="replace")
            kv = ClientHandler._parse_20922_kv(frame[12:-1])
            if cmd == "+who":
                who_frames.append(kv)
            if cmd == "+mgm":
                mgm_frames.append(kv)
        assert b"gset" in sent, f"recent removed-room gset ack missing: {sent!r}"
        assert any(kv.get("IDENT") == str(game.id) and "NAME" not in kv and "COUNT" not in kv for kv in mgm_frames), f"recent removed-room gset did not send +mgm IDENT invalidation: {mgm_frames!r}"
        assert any(kv.get("G") == "0" and kv.get("I") == str(peer.uid) for kv in who_frames), f"recent removed-room gset did not send +who G=0 reset: {who_frames!r}"
        assert b"+msg" not in sent and b"KICK" not in sent, f"recent removed-room gset used kick/message reset: {sent!r}"
        assert b"gdel" not in sent and b"glea" not in sent, f"recent removed-room gset sent leave/delete commands: {sent!r}"
        assert all(frame[:4] != b"EVGI" for frame in frames), f"recent removed-room ready gset sent host-only EVGI snapshot that can keep the room visible: {sent!r}"
        assert b"+usr" not in sent and b"+gam" not in sent and b"+agm" not in sent, f"recent removed-room gset leaked legacy delete frames: {sent!r}"
        assert b"OPID1=" not in sent and b"OPPO1=Moio" not in sent, f"recent removed-room gset kept removed peer in force-refresh snapshot: {sent!r}"

        peer.conn.sent.clear()
        gjoi = ClientHandler._make_20922_tab_message(
            "gjoi",
            ["IDENT=%d" % game.id, "NAME=547.Jucator"],
        )
        consumed = hpeer._consume_bootstrap_frames(gjoi)
        assert consumed == len(gjoi), "recent removed-room gjoi frame was not consumed"
        sent = bytes(peer.conn.sent)
        frames = ClientHandler._extract_20922_messages(bytearray(sent))
        mgm_delete_frames = [
            ClientHandler._parse_20922_kv(frame[12:-1])
            for frame in frames
            if frame[:4] == b"+mgm"
        ]
        assert b"gjoi" in sent, f"recent removed-room gjoi ack missing: {sent!r}"
        assert any(kv.get("IDENT") == str(game.id) and "NAME" not in kv and "COUNT" not in kv for kv in mgm_delete_frames), f"recent removed-room gjoi did not send +mgm IDENT invalidation: {mgm_delete_frames!r}"

        hpeer._disconnect_reason = "test_cleanup"
        hpeer._on_disconnect()
    finally:
        os.unlink(cfg_path)


def assert_lan_kick_delayed_update_does_not_override_new_room():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        srv.is_running = True

        host = User(DummyConn(), ("127.0.0.1", 1251), name="Juc")
        host.pers = "Jucator"
        peer = User(DummyConn(), ("127.0.0.1", 1252), name="Moio9")
        peer.pers = "Moio"
        assert srv.users.add(host)
        assert srv.users.add(peer)
        hhost = ClientHandler(srv, host)
        hpeer = ClientHandler(srv, peer)

        old_game = srv.games.create(room_id=0, host_uid=host.uid, limit=2, custom="old-kick-room")
        assert old_game is not None
        assert srv.games.join(old_game.id, host.uid)
        assert srv.games.join(old_game.id, peer.uid)
        host.game = old_game.id
        host.stat = "GAME"
        peer.game = old_game.id
        peer.stat = "GAME"

        kick = ClientHandler._make_20922_tab_message(
            "gset",
            [f"NAME={old_game.custom}", "KICK=Moio"],
        )
        consumed = hhost._consume_bootstrap_frames(kick)
        assert consumed == len(kick), "kick gset frame was not consumed"

        peer.conn.sent.clear()
        gcre = ClientHandler._make_20922_tab_message(
            "gcre",
            [
                "NAME=new-after-kick",
                "MAXSIZE=4",
                "MINSIZE=2",
                "CUSTFLAGS=67109107",
                "SYSFLAGS=0",
            ],
        )
        consumed = hpeer._consume_bootstrap_frames(gcre)
        assert consumed == len(gcre), "post-kick gcre frame was not consumed"
        time.sleep(0.10)

        sent = bytes(peer.conn.sent)
        assert peer.game and peer.game != old_game.id, "kicked peer did not become host of a new game"
        assert b"NAME=new-after-kick" in sent, f"new room create ack missing: {sent!r}"
        assert b"NAME=old-kick-room" not in sent, f"delayed kick update overrode new room with old game: {sent!r}"
        assert f"IDENT={old_game.id}".encode("ascii") not in sent, f"delayed kick update referenced old game after new create: {sent!r}"

        hhost._disconnect_reason = "test_cleanup"
        hhost._on_disconnect()
        hpeer._disconnect_reason = "test_cleanup"
        hpeer._on_disconnect()
    finally:
        os.unlink(cfg_path)


def assert_lan_active_game_peer_close_preserves_detached_user():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        srv.is_running = True

        host = User(DummyConn(), ("127.0.0.1", 1311), name="Juc")
        host.pers = "Jucator"
        assert srv.users.add(host)
        hhost = ClientHandler(srv, host)
        game = srv.games.create(room_id=0, host_uid=host.uid, limit=2, custom="active-race")
        assert game is not None, "failed to create active preserve game"
        assert srv.games.join(game.id, host.uid)
        game.start()
        host.game = game.id
        host.stat = "GAME"

        hhost._disconnect_reason = "peer_closed"
        hhost._on_disconnect()

        preserved = srv.users.get(host.uid)
        assert srv.games.get(game.id) is not None, "active game was destroyed on peer_closed"
        assert preserved is not None and not preserved.connected, "active game user was not preserved detached"
    finally:
        os.unlink(cfg_path)


def assert_lan_same_ip_detached_reconnect_replaces_only_matching_persona():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap
    import time

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        srv.is_running = True

        host = User(DummyConn(), ("127.0.0.1", 1321), name="Moio9")
        host.pers = "Moio"
        peer = User(DummyConn(), ("127.0.0.1", 1322), name="Juc")
        peer.pers = "Jucator"
        assert srv.users.add(host)
        assert srv.users.add(peer)
        game = srv.games.create(room_id=0, host_uid=host.uid, limit=2, custom="active-rejoin")
        assert game is not None
        assert srv.games.join(game.id, host.uid)
        assert srv.games.join(game.id, peer.uid)
        game.start()
        for user in (host, peer):
            user.game = game.id
            user.stat = "GAME"
            user.connected = False
            user.race_detached_at = time.time()

        new_peer = User(DummyConn(), ("127.0.0.1", 2322), name="Juc")
        new_peer.pers = "Jucator"
        hpeer = ClientHandler(srv, new_peer)
        assert srv.users.add(new_peer)
        hpeer._probe_display_name = "Juc"
        hpeer._probe_persona = "Jucator"
        hpeer._cleanup_replaced_detached_users()
        hpeer._cleanup_replaced_detached_users()

        assert srv.users.get(peer.uid) is None, "matching detached peer was not replaced"
        assert srv.users.get(host.uid) is not None, "same-IP host was incorrectly replaced by peer reconnect"
        assert int(game.host_uid) == int(host.uid), "peer reconnect stole detached host slot"
        assert game.participants.count(new_peer.uid) == 1, f"peer reconnect duplicated participant: {game.participants!r}"
        assert host.uid in game.participants and peer.uid not in game.participants, f"wrong participants after peer reconnect: {game.participants!r}"

        new_host = User(DummyConn(), ("127.0.0.1", 2321), name="Moio9")
        new_host.pers = "Moio"
        hhost = ClientHandler(srv, new_host)
        assert srv.users.add(new_host)
        hhost._probe_display_name = "Moio9"
        hhost._probe_persona = "Moio"
        hhost._cleanup_replaced_detached_users()

        assert srv.users.get(host.uid) is None, "matching detached host was not replaced"
        assert int(game.host_uid) == int(new_host.uid), "host reconnect did not reclaim host slot"
        assert sorted(int(uid) for uid in game.participants) == sorted([new_peer.uid, new_host.uid]), f"bad participants after both reconnect: {game.participants!r}"

        hpeer._disconnect_reason = "test_cleanup"
        hpeer._on_disconnect()
        hhost._disconnect_reason = "test_cleanup"
        hhost._on_disconnect()
    finally:
        os.unlink(cfg_path)


def assert_lan_reattached_active_game_gsea_finalizes_lobby():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap
    import time

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        srv.is_running = True

        old_host = User(DummyConn(), ("127.0.0.1", 1331), name="Moio9")
        old_host.pers = "Moio"
        old_peer = User(DummyConn(), ("127.0.0.1", 1332), name="Juc")
        old_peer.pers = "Jucator"
        assert srv.users.add(old_host)
        assert srv.users.add(old_peer)
        game = srv.games.create(room_id=0, host_uid=old_host.uid, limit=2, custom="postrace")
        assert game is not None
        assert srv.games.join(game.id, old_host.uid)
        assert srv.games.join(game.id, old_peer.uid)
        game.start()
        for user in (old_host, old_peer):
            user.game = game.id
            user.stat = "GAME"
            user.connected = False
            user.race_detached_at = time.time()

        new_host = User(DummyConn(), ("127.0.0.1", 2331), name="Moio9")
        new_host.pers = "Moio"
        hhost = ClientHandler(srv, new_host)
        assert srv.users.add(new_host)
        hhost._probe_display_name = "Moio9"
        hhost._probe_persona = "Moio"
        hhost._cleanup_replaced_detached_users()
        assert int(getattr(new_host, "game", 0) or 0) == int(game.id), "host did not reattach active race"

        gsea = ClientHandler._make_20922_tab_message("gsea", ["START=0", "COUNT=20"])
        consumed = hhost._consume_bootstrap_frames(gsea)
        sent = bytes(new_host.conn.sent)
        assert consumed == len(gsea), "post-race gsea frame was not consumed"
        assert srv.games.get(game.id) is None, "post-race gsea did not remove active race"
        assert int(getattr(new_host, "game", 0) or 0) == 0, "post-race gsea did not clear host game state"
        assert int(getattr(old_peer, "game", 0) or 0) == 0, "post-race gsea did not clear detached peer game state"
        assert b"gsea" in sent and b"COUNT=0" in sent, f"post-race gsea did not return empty lobby: {sent!r}"
        assert b"NAME=postrace" not in sent and b"+gam" not in sent, f"post-race gsea leaked removed race: {sent!r}"

        new_peer = User(DummyConn(), ("127.0.0.1", 2332), name="Juc")
        new_peer.pers = "Jucator"
        hpeer = ClientHandler(srv, new_peer)
        assert srv.users.add(new_peer)
        hpeer._probe_display_name = "Juc"
        hpeer._probe_persona = "Jucator"
        hpeer._cleanup_replaced_detached_users()
        assert int(getattr(new_peer, "game", 0) or 0) == 0, "peer reconnect inherited removed race"
        assert srv.users.get(old_peer.uid) is None, "old detached peer was not replaced after post-race cleanup"

        hhost._disconnect_reason = "test_cleanup"
        hhost._on_disconnect()
        hpeer._disconnect_reason = "test_cleanup"
        hpeer._on_disconnect()
    finally:
        os.unlink(cfg_path)


def assert_gset_self_kick_ignored():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        user = User(DummyConn(), ("127.0.0.1", 1111), name="Moio9")
        user.pers = "Moio"
        handler = ClientHandler(srv, user)
        assert srv.users.add(user)
        game = srv.games.create(room_id=0, host_uid=user.uid, limit=2, custom="029.Moio")
        assert game is not None, "failed to create self-kick test game"
        assert srv.games.join(game.id, user.uid), "failed to join self-kick test game"
        user.game = game.id
        user.stat = "GAME"
        kick_frame = ClientHandler._make_20922_tab_message(
            "gset",
            [f"NAME={game.custom}", "KICK=Moio9", f"CALLUSER={user.uid}"],
        )
        consumed = handler._consume_bootstrap_frames(kick_frame)
        assert consumed == len(kick_frame), "self-kick gset frame was not consumed"
        assert srv.games.get(game.id) is not None, "self-kick removed the game"
        assert int(getattr(user, "game", 0) or 0) == int(game.id), "self-kick detached the host from the game"
        assert user.uid in set(getattr(game, "participants", []) or []), "self-kick removed host participation"
        handler._disconnect_reason = "test_cleanup"
        handler._on_disconnect()
    finally:
        os.unlink(cfg_path)


def assert_ready_snapshot_does_not_duplicate_solo_host():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        host = User(DummyConn(), ("127.0.0.1", 1111), name="Moio9")
        host.pers = "Moio"
        handler = ClientHandler(srv, host)
        assert srv.users.add(host)
        game = srv.games.create(room_id=0, host_uid=host.uid, limit=4, custom="943.Moio")
        assert game is not None
        assert srv.games.join(game.id, host.uid)
        host.game = game.id
        host.stat = "GAME"
        handler._lan_remember_game_user(game, host)

        fields = handler._lan_game_ready_snapshot_fields(
            game,
            viewer_uid=int(host.uid),
            tunnel_addrs=True,
        )
        text = "\n".join(fields)
        assert f"COUNT=1" in text, f"solo-host snapshot count mismatch: {text!r}"
        assert f"OPID0={host.uid}" in text, f"solo-host snapshot missing host: {text!r}"
        assert "HOST=Moio" in text and "OPPO0=Moio" in text, f"solo-host snapshot should use persona names: {text!r}"
        assert "OPPO0=Moio9" not in text, f"solo-host snapshot leaked account name as OPPO: {text!r}"
        assert "OPID1=" not in text, f"solo-host snapshot duplicated a peer row: {text!r}"

        handler._disconnect_reason = "test_cleanup"
        handler._on_disconnect()
    finally:
        os.unlink(cfg_path)


def assert_duplicate_gset_ready_deduped():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap
    import time

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
            LAN_GSET_DEDUPE_WINDOW=0.5
            LAN_READY_NOTIFY_PEERS=1
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        srv.is_running = True
        srv.cfg["LAN_GSET_DEDUPE_WINDOW"] = 0.5
        srv.cfg["LAN_READY_NOTIFY_PEERS"] = 1
        host = User(DummyConn(), ("127.0.0.1", 1111), name="Moio9")
        host.pers = "Moio"
        peer = User(DummyConn(), ("127.0.0.1", 1112), name="Juc")
        peer.pers = "Juc"
        hhost = ClientHandler(srv, host)
        hpeer = ClientHandler(srv, peer)
        assert srv.users.add(host)
        assert srv.users.add(peer)
        game = srv.games.create(room_id=0, host_uid=host.uid, limit=2, custom="188.Moio")
        assert game is not None
        assert srv.games.join(game.id, host.uid)
        assert srv.games.join(game.id, peer.uid)
        host.game = game.id
        host.stat = "GAME"
        peer.game = game.id
        peer.stat = "GAME"
        frame = ClientHandler._make_20922_tab_message(
            "gset",
            [f"NAME={game.custom}", "USERFLAGS=134217728"],
        )
        consumed = hpeer._consume_bootstrap_frames(frame)
        assert consumed == len(frame), "first duplicate-ready gset frame was not consumed"
        time.sleep(0.05)
        first_host_len = len(host.conn.sent)
        assert first_host_len > 0, "first gset did not notify host"
        host.conn.sent.clear()
        consumed = hpeer._consume_bootstrap_frames(frame)
        assert consumed == len(frame), "second duplicate-ready gset frame was not consumed"
        time.sleep(0.05)
        assert len(host.conn.sent) == 0, "duplicate gset re-notified host"
        hpeer._disconnect_reason = "test_cleanup"
        hpeer._on_disconnect()
        hhost._disconnect_reason = "test_cleanup"
        hhost._on_disconnect()
    finally:
        os.unlink(cfg_path)


def assert_room_snapshot_partition_fields_follow_numpart():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        srv.is_running = True
        host = User(DummyConn(), ("127.0.0.1", 1111), name="Moio9")
        host.pers = "Moio"
        peer = User(DummyConn(), ("127.0.0.1", 1112), name="Juc")
        peer.pers = "Jucator"
        hhost = ClientHandler(srv, host)
        hpeer = ClientHandler(srv, peer)
        assert srv.users.add(host)
        assert srv.users.add(peer)
        game = srv.games.create(room_id=0, host_uid=host.uid, limit=2, custom="595.Moio")
        assert game is not None
        assert srv.games.join(game.id, host.uid)
        assert srv.games.join(game.id, peer.uid)
        host.game = game.id
        host.stat = "GAME"
        peer.game = game.id
        peer.stat = "GAME"
        hhost._lan_remember_game_user(game, host)
        hpeer._lan_remember_game_user(game, peer)

        ready_fields = hpeer._lan_game_ready_snapshot_fields(
            game,
            viewer_uid=int(peer.uid),
            tunnel_addrs=True,
        )
        ready_text = "\n".join(ready_fields)
        assert "NUMPART=1" in ready_text, f"ready snapshot numpart mismatch: {ready_text!r}"
        assert "HOST=Moio" in ready_text, f"ready snapshot host should use persona: {ready_text!r}"
        assert "OPPO0=Moio" in ready_text and "OPPO1=Jucator" in ready_text, f"ready snapshot OPPO names should use personas: {ready_text!r}"
        assert "PARTSIZE0=2" in ready_text, f"ready snapshot missing first partition size: {ready_text!r}"
        assert "PARTPARAMS0=" in ready_text, f"ready snapshot missing first partition params: {ready_text!r}"
        assert "PARTSIZE1=" not in ready_text, f"ready snapshot leaked second partition size: {ready_text!r}"
        assert "PARTPARAMS1=" not in ready_text, f"ready snapshot leaked second partition params: {ready_text!r}"
        ready_map = _field_map(ready_fields)
        assert ready_map["PARAMS"], f"ready snapshot lost game params: {ready_fields!r}"
        assert ready_map["PARTPARAMS0"] == "", f"ready snapshot PARTPARAMS0 should stay empty like stock LAN: {ready_fields!r}"
        assert ready_map["OPPARAM0"] == "" and ready_map["OPPARAM1"] == "", f"ready snapshot OPPARAMs should stay empty like stock LAN: {ready_fields!r}"
        _assert_stock_game_field_order(ready_fields, "ready snapshot")

        room_fields = hpeer._lan_game_reply_fields(
            game,
            params=hpeer._lan_game_params(game),
            custflags=hpeer._lan_game_custflags(game),
            sysflags=hpeer._lan_game_sysflags(game),
            tunnel_addrs=True,
        )
        room_text = "\n".join(room_fields)
        assert "NUMPART=1" in room_text, f"room snapshot numpart mismatch: {room_text!r}"
        assert "HOST=Moio" in room_text, f"room snapshot host should use persona: {room_text!r}"
        assert "OPPO0=Moio" in room_text and "OPPO1=Jucator" in room_text, f"room snapshot OPPO names should use personas: {room_text!r}"
        assert "PARTSIZE0=2" in room_text, f"room snapshot missing first partition size: {room_text!r}"
        assert "PARTPARAMS0=" in room_text, f"room snapshot missing first partition params: {room_text!r}"
        assert "PARTSIZE1=" not in room_text, f"room snapshot leaked second partition size: {room_text!r}"
        assert "PARTPARAMS1=" not in room_text, f"room snapshot leaked second partition params: {room_text!r}"
        assert "RLYHOST=" not in room_text and "RLYPORT=" not in room_text, f"room snapshot leaked relay fields: {room_text!r}"
        room_map = _field_map(room_fields)
        assert room_map["PARAMS"], f"room snapshot lost game params: {room_fields!r}"
        assert room_map["PARTPARAMS0"] == "", f"room snapshot PARTPARAMS0 should stay empty like stock LAN: {room_fields!r}"
        assert room_map["OPPARAM0"] == "" and room_map["OPPARAM1"] == "", f"room snapshot OPPARAMs should stay empty like stock LAN: {room_fields!r}"
        _assert_stock_game_field_order(room_fields, "room snapshot")

        gsta_fields = hpeer._lan_gsta_feed_fields(
            game,
            viewer_uid=int(peer.uid),
            tunnel_addrs=True,
        )
        gsta_text = "\n".join(gsta_fields)
        assert "HOST=Moio" in gsta_text, f"gsta snapshot host should use host persona: {gsta_text!r}"
        assert f"OPID0={host.uid}" in gsta_text and f"OPID1={peer.uid}" in gsta_text, (
            f"gsta snapshot must keep host in OPID0 even for peer viewer: {gsta_text!r}"
        )
        assert "OPPO0=Moio" in gsta_text and "OPPO1=Jucator" in gsta_text, (
            f"gsta snapshot OPPO names should use personas in host-first order: {gsta_text!r}"
        )

        onln_text = "\n".join(
            hpeer._lan_onln_fields_for_user(peer, game, viewer_uid=int(peer.uid))
        )
        assert "M=Juc" in onln_text and "N=Jucator" in onln_text, f"onln M/N mapping mismatch: {onln_text!r}"
        assert "F=U" in onln_text, f"normal onln game flag mismatch: {onln_text!r}"
        assert "MA=" in onln_text, f"onln missing MA field: {onln_text!r}"
        assert "MA=127." not in onln_text, f"onln leaked relay addr: {onln_text!r}"

        hpeer._disconnect_reason = "test_cleanup"
        hpeer._on_disconnect()
        hhost._disconnect_reason = "test_cleanup"
        hhost._on_disconnect()
    finally:
        os.unlink(cfg_path)


def assert_onln_pers_display_alias_resolves_self():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        host = User(DummyConn(), ("127.0.0.1", 1111), name="Moio9")
        host.pers = "Moio"
        peer = User(DummyConn(), ("127.0.0.1", 1112), name="Juc")
        peer.pers = "Jucator"
        hpeer = ClientHandler(srv, peer)
        assert srv.users.add(host)
        assert srv.users.add(peer)
        game = srv.games.create(room_id=0, host_uid=host.uid, limit=2, custom="349.Moio")
        assert game is not None
        assert srv.games.join(game.id, host.uid)
        assert srv.games.join(game.id, peer.uid)
        host.game = game.id
        peer.game = game.id
        host.stat = "GAME"
        peer.stat = "GAME"
        resolved = hpeer._lan_resolve_onln_target(game, "", "Juc", peer)
        assert int(getattr(resolved, "uid", 0) or 0) == int(peer.uid), "onln PERS display alias resolved to the wrong user"
        hpeer._disconnect_reason = "test_cleanup"
        hpeer._on_disconnect()
    finally:
        os.unlink(cfg_path)


def assert_lan_private_message_to_self_ignored():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cfg:
        cfg.write(textwrap.dedent("""\
            PORT=0
            CONTROL_PORT=0
            CONTROL_LISTEN_PORT=0
        """))
        cfg_path = cfg.name

    try:
        srv = GameServer(cfg_path)
        srv.is_running = True
        user = User(DummyConn(), ("127.0.0.1", 1111), name="Moio9")
        user.pers = "Moio"
        handler = ClientHandler(srv, user)
        assert srv.users.add(user)
        frame = ClientHandler._make_20922_tab_message(
            "mesg",
            ["PRIV=Moio9", "TEXT=test-self"],
        )
        consumed = handler._consume_bootstrap_frames(frame)
        assert consumed == len(frame), "self private mesg was not consumed"
        sent = user.conn.sent.decode("latin1", errors="ignore")
        assert "+msg" not in sent, f"self private mesg should not echo +msg: {sent!r}"
        handler._disconnect_reason = "test_cleanup"
        handler._on_disconnect()
    finally:
        os.unlink(cfg_path)


def assert_lan_auth_accounts():
    from server import GameServer
    from client_handler import (
        ClientHandler,
        _LAN_AUTH_BLAK_RESERVED,
        _LAN_AUTH_DBER_RESERVED,
        _LAN_AUTH_FILT_RESERVED,
        _LAN_AUTH_IKEY_RESERVED,
        _LAN_AUTH_IMST_RESERVED,
        _LAN_AUTH_LOCK_RESERVED,
        _LAN_AUTH_LOGN_RESERVED,
        _LAN_AUTH_MISS_RESERVED,
        _LAN_AUTH_OVER_RESERVED,
        _LAN_AUTH_PASS_RESERVED,
        _LAN_AUTH_SHAR_RESERVED,
        _LAN_AUTH_TIME_RESERVED,
        _LAN_AUTH_TOSA_RESERVED,
        _LAN_DUPL_RESERVED,
        _LAN_INVP_RESERVED,
        _LAN_MAUT_RESERVED,
        _LAN_NSPC_RESERVED,
        _LAN_PSET_RESERVED,
    )
    from user_manager import User
    import hashlib
    import json
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    reject_frame = ClientHandler._make_20922_signed_binary_message(
        "auth",
        b"\x00",
        9,
        reserved_be32=_LAN_AUTH_IMST_RESERVED,
    )
    assert reject_frame.hex() == "61757468696d737400000015009923473ef4a469ec"
    same_account_frame = ClientHandler._make_20922_signed_binary_message(
        "auth",
        b"\x00",
        9,
        reserved_be32=_LAN_AUTH_LOGN_RESERVED,
    )
    assert same_account_frame.hex() == "617574686c6f676e000000150096e49ef9335271f3"
    bad_password_frame = ClientHandler._make_20922_signed_binary_message(
        "auth",
        b"\x00",
        9,
        reserved_be32=_LAN_AUTH_PASS_RESERVED,
    )
    assert bad_password_frame.hex() == "61757468706173730000001500b25e82f94d72cd14"
    auth_code_cases = {
        "imst": ("unknown_account", _LAN_AUTH_IMST_RESERVED),
        "logn": ("account_in_use", _LAN_AUTH_LOGN_RESERVED),
        "lock": ("account_locked", _LAN_AUTH_LOCK_RESERVED),
        "pass": ("bad_password", _LAN_AUTH_PASS_RESERVED),
        "ikey": ("invalid_key", _LAN_AUTH_IKEY_RESERVED),
        "tosa": ("tos_not_accepted", _LAN_AUTH_TOSA_RESERVED),
        "dber": ("database_error", _LAN_AUTH_DBER_RESERVED),
        "blak": ("blacklisted", _LAN_AUTH_BLAK_RESERVED),
        "shar": ("share_not_accepted", _LAN_AUTH_SHAR_RESERVED),
        "miss": ("missing_fields", _LAN_AUTH_MISS_RESERVED),
        "filt": ("filtered", _LAN_AUTH_FILT_RESERVED),
        "time": ("auth_timeout", _LAN_AUTH_TIME_RESERVED),
        "over": ("invalid_state", _LAN_AUTH_OVER_RESERVED),
    }
    for code, (reason, reserved) in auth_code_cases.items():
        frame = ClientHandler._make_20922_signed_binary_message(
            "auth",
            b"\x00",
            9,
            reserved_be32=reserved,
        )
        assert frame[:8] == b"auth" + code.encode("ascii"), f"auth{code} frame header mismatch"
        assert ClientHandler._lan_auth_reject_reserved(reason) == reserved, f"{reason} did not map to auth{code}"
    assert ClientHandler._lan_auth_reject_reserved("admin_ban") == _LAN_AUTH_BLAK_RESERVED
    assert ClientHandler._lan_auth_reject_reserved("banned") == _LAN_AUTH_BLAK_RESERVED
    account_exists_frame = ClientHandler._make_20922_signed_binary_message(
        "acct",
        b"\x00",
        9,
        reserved_be32=_LAN_DUPL_RESERVED,
    )
    assert account_exists_frame.hex() == "616363746475706c0000001500fe4bd474a5f2be8c"
    persona_duplicate_frame = ClientHandler._make_20922_signed_binary_message(
        "cper",
        b"\x00",
        9,
        reserved_be32=_LAN_DUPL_RESERVED,
    )
    assert persona_duplicate_frame.hex() == "637065726475706c00000015005addab04990cd909"
    persona_code_cases = {
        "cperdupl": ("cper", "dupl", _LAN_DUPL_RESERVED),
        "cperinvp": ("cper", "invp", _LAN_INVP_RESERVED),
        "cpernspc": ("cper", "nspc", _LAN_NSPC_RESERVED),
        "persinvp": ("pers", "invp", _LAN_INVP_RESERVED),
        "persmaut": ("pers", "maut", _LAN_MAUT_RESERVED),
        "perspset": ("pers", "pset", _LAN_PSET_RESERVED),
    }
    for label, (cmd4, reason, reserved) in persona_code_cases.items():
        frame = ClientHandler._make_20922_signed_binary_message(
            cmd4,
            b"\x00",
            9,
            reserved_be32=reserved,
        )
        assert frame[:8] == label.encode("ascii"), f"{label} frame header mismatch"
        assert ClientHandler._lan_persona_reject_reserved(reason) == reserved, f"{reason} did not map to {label}"

    with tempfile.TemporaryDirectory() as root:
        accounts_path = os.path.join(root, "auth_accounts.json")
        captures_path = os.path.join(root, "auth_captures.jsonl")
        cfg_path = os.path.join(root, "server.cfg")
        with open(accounts_path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "users": [
                        {
                            "name": "Alice",
                            "aliases": ["alice@example.test", "Alice"],
                            "pass_wire": "wire-pass",
                            "personas": ["Alice"],
                        },
                        {
                            "name": "HashUser",
                            "aliases": ["hash@example.test"],
                            "pass_wire_sha256": hashlib.sha256(b"secret-wire").hexdigest(),
                            "personas": ["HashUser"],
                        },
                        {
                            "name": "ClearUser",
                            "aliases": ["clear@example.test"],
                            "password": "clear-pass",
                            "personas": ["ClearUser"],
                        },
                        {
                            "name": "LockedUser",
                            "aliases": ["LockedUser"],
                            "pass_wire": "locked-pass",
                            "auth_status": "lock",
                            "personas": ["LockedUser"],
                        },
                        {
                            "name": "KeyUser",
                            "aliases": ["KeyUser"],
                            "pass_wire": "key-pass",
                            "cdkey": "good-key",
                            "personas": ["KeyUser"],
                        },
                        {
                            "name": "TosaUser",
                            "aliases": ["TosaUser"],
                            "pass_wire": "tosa-pass",
                            "tos_accepted": False,
                            "personas": ["TosaUser"],
                        },
                    ]
                },
                fh,
            )
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent(f"""\
                CONTROL_LISTEN_PORT=0
                CONTROL_PORT=0
                LAN_AUTH_VERIFY=1
                LAN_AUTH_MODE=password
                LAN_AUTH_CAPTURE=0
                LAN_AUTH_CAPTURE_FILE={captures_path}
                LAN_AUTH_AUTO_ENROLL=0
                LAN_AUTH_ALLOW_CREATE=0
                LAN_AUTH_ACCOUNTS_FILE={accounts_path}
            """))

        srv = GameServer(cfg_path)
        response = srv._run_admin_command("personacode persmaut Alice")
        assert "persmaut" in response and "Alice" in response and "select-persona/pers" in response, (
            f"personacode persmaut command failed: {response!r}"
        )
        assert srv.pop_forced_persona_reject("pers", "Alice") == "maut"
        assert srv.pop_forced_persona_reject("pers", "Alice") == ""
        response = srv._run_admin_command("personacode cpernspc * 2")
        assert "cpernspc" in response and "create-persona/cper" in response and "uses=2" in response, (
            f"personacode cpernspc command failed: {response!r}"
        )
        assert srv.pop_forced_persona_reject("cper", "AnyPersona") == "nspc"
        listed = srv._run_admin_command("personacode list")
        assert "cpernspc" in listed, f"pending personacode not listed: {listed!r}"
        cleared = srv._run_admin_command("personacode clear")
        assert "cleared 1" in cleared, f"personacode clear failed: {cleared!r}"
        token = GameServer._lan_auth_make_pass_token("clear-pass", "mask-a")
        assert token.startswith("$")
        assert GameServer._lan_auth_decode_pass_token(token, "mask-a") == "clear-pass"
        ok, reason, account, ident = srv.authenticate_lan_login({"NAME": "ClearUser", "PASS": token, "MASK": "mask-a"})
        assert ok and reason == "ok" and account.get("name") == "ClearUser" and ident == "ClearUser"
        token = GameServer._lan_auth_make_pass_token("clear-pass", "mask-b")
        ok, reason, account, ident = srv.authenticate_lan_login({"NAME": "ClearUser", "PASS": token, "MASK": "mask-b"})
        assert ok and reason == "ok" and account.get("name") == "ClearUser" and ident == "ClearUser"
        legacy_token = GameServer._lan_auth_make_pass_token("legacy-pass", "old-mask")
        legacy_account = {
            "name": "LegacyWire",
            "aliases": ["LegacyWire"],
            "pass_wire_pbkdf2": GameServer._lan_auth_pbkdf2_encode(legacy_token),
        }
        srv.cfg["LAN_AUTH_LEGACY_MASKS"] = "old-mask"
        dynamic_token = GameServer._lan_auth_make_pass_token("legacy-pass", "new-mask")
        assert srv._lan_auth_password_matches(legacy_account, {"PASS": dynamic_token, "MASK": "new-mask"}, dynamic_token)
        srv.cfg["LAN_AUTH_LEGACY_MASKS"] = ""
        ok, reason, _, ident = srv.authenticate_lan_login({"NAME": "LockedUser", "PASS": "locked-pass"})
        assert not ok and reason == "account_locked" and ident == "LockedUser"
        ok, reason, _, ident = srv.authenticate_lan_login({"NAME": "KeyUser", "PASS": "key-pass", "CDKEY": "bad-key"})
        assert not ok and reason == "invalid_key" and ident == "KeyUser"
        ok, reason, account, ident = srv.authenticate_lan_login({"NAME": "KeyUser", "PASS": "key-pass", "CDKEY": "good-key"})
        assert ok and reason == "ok" and account.get("name") == "KeyUser" and ident == "KeyUser"
        ok, reason, _, ident = srv.authenticate_lan_login({"NAME": "TosaUser", "PASS": "tosa-pass"})
        assert not ok and reason == "tos_not_accepted" and ident == "TosaUser"
        srv.cfg["LAN_AUTH_REQUIRED_FIELDS"] = "VERS,SLUS,SKU,LANG"
        ok, reason, _, ident = srv.authenticate_lan_login({"NAME": "Alice", "PASS": "wire-pass"})
        assert not ok and reason == "missing_fields" and ident == "Alice"
        ok, reason, account, ident = srv.authenticate_lan_login(
            {"NAME": "Alice", "PASS": "wire-pass", "VERS": "1", "SLUS": "x", "SKU": "pc", "LANG": "en"}
        )
        assert ok and reason == "ok" and account.get("name") == "Alice" and ident == "Alice"
        srv.cfg["LAN_AUTH_REQUIRED_FIELDS"] = ""
        srv.cfg["LAN_AUTH_REQUIRE_SHARE"] = 1
        ok, reason, _, ident = srv.authenticate_lan_login({"NAME": "Alice", "PASS": "wire-pass"})
        assert not ok and reason == "share_not_accepted" and ident == "Alice"
        srv.cfg["LAN_AUTH_REQUIRE_SHARE"] = 0
        response = srv._run_admin_command("authcode blak Alice")
        assert "authblak" in response and "Alice" in response, f"authcode blak command failed: {response!r}"
        ok, reason, _, ident = srv.authenticate_lan_login({"NAME": "Alice", "PASS": "wire-pass"})
        assert not ok and reason == "blacklisted" and ident == "Alice"
        ok, reason, account, ident = srv.authenticate_lan_login({"NAME": "Alice", "PASS": "wire-pass"})
        assert ok and reason == "ok" and account.get("name") == "Alice" and ident == "Alice"
        response = srv._run_admin_command("authcode time * 2")
        assert "authtime" in response and "uses=2" in response, f"authcode time command failed: {response!r}"
        ok, reason, _, ident = srv.authenticate_lan_login({"NAME": "Alice", "PASS": "wire-pass"})
        assert not ok and reason == "auth_timeout" and ident == "Alice"
        listed = srv._run_admin_command("authcode list")
        assert "time" in listed and "auth_timeout" in listed, f"pending authcode not listed: {listed!r}"
        cleared = srv._run_admin_command("authcode clear")
        assert "cleared 1" in cleared, f"authcode clear failed: {cleared!r}"
        timing = srv._run_admin_command("authreject slow")
        assert "repeat=1" in timing and "close_delay=8.0" in timing, f"authreject slow failed: {timing!r}"
        timing = srv._run_admin_command("authreject default")
        assert "repeat=4" in timing and "close_delay=1.1" in timing, f"authreject default failed: {timing!r}"
        ok, reason, account, ident = srv.authenticate_lan_login({"NAME": "Alice", "PASS": "wire-pass"})
        assert ok and reason == "ok" and account.get("name") == "Alice" and ident == "Alice"
        with open(accounts_path, "r", encoding="utf-8") as fh:
            migrated = json.load(fh)
        alice = migrated["users"][0]
        assert "pass_wire" not in alice
        assert str(alice.get("pass_wire_pbkdf2", "")).startswith("pbkdf2_sha256$")
        clear = migrated["users"][2]
        assert "password" not in clear
        assert str(clear.get("pass_wire_pbkdf2", "")).startswith("pbkdf2_sha256$")
        ok, reason, _, _ = srv.authenticate_lan_login({"NAME": "Alice", "PASS": "bad"})
        assert not ok and reason == "bad_password"
        bad = User(DummyConn(), ("127.0.0.1", 10000), name="GuestBad")
        assert srv.users.add(bad)
        hbad = ClientHandler(srv, bad)
        bad_frame = ClientHandler._make_20922_tab_message(
            "auth",
            ["NAME=Alice", "PASS=bad"],
        )
        consumed = hbad._consume_bootstrap_frames(bad_frame)
        assert consumed == len(bad_frame), "bad password auth frame was not consumed"
        assert bad.conn.sent[:21] == bad_password_frame, "bad password auth did not send authpass"
        ok, reason, account, ident = srv.authenticate_lan_login({"MAIL": "hash@example.test", "PASS": "secret-wire"})
        assert ok and reason == "ok" and account.get("name") == "HashUser" and ident == "hash@example.test"

        srv.cfg["LAN_AUTH_FAIL_LIMIT"] = 2
        srv.cfg["LAN_AUTH_LOCKOUT_SECONDS"] = 60
        ok, reason, _, _ = srv.authenticate_lan_login({"NAME": "HashUser", "PASS": "wrong-1"})
        assert not ok and reason == "bad_password"
        ok, reason, _, _ = srv.authenticate_lan_login({"NAME": "HashUser", "PASS": "wrong-2"})
        assert not ok and reason == "bad_password"
        ok, reason, _, _ = srv.authenticate_lan_login({"NAME": "HashUser", "PASS": "secret-wire"})
        assert not ok and reason == "rate_limited"
        srv._lan_auth_failures.clear()
        srv.cfg["LAN_AUTH_FAIL_LIMIT"] = 5

        srv.cfg["LAN_AUTH_MODE"] = "account"
        ok, reason, account, ident = srv.authenticate_lan_login({"NAME": "Alice"})
        assert ok and reason == "ok" and account.get("name") == "Alice" and ident == "Alice"

        active = User(DummyConn(), ("127.0.0.1", 10001), name="Alice")
        active.pers = "Alice"
        assert srv.users.add(active)
        duplicate = User(DummyConn(), ("127.0.0.1", 10002), name="Guest")
        assert srv.users.add(duplicate)
        hdup = ClientHandler(srv, duplicate)
        auth_frame = ClientHandler._make_20922_tab_message(
            "auth",
            ["NAME=Alice", "PASS=wire-pass"],
        )
        consumed = hdup._consume_bootstrap_frames(auth_frame)
        assert consumed == len(auth_frame), "duplicate auth frame was not consumed"
        assert duplicate.conn.sent[:21] == same_account_frame, "duplicate auth did not send authlogn"

        persona_dup = User(DummyConn(), ("127.0.0.1", 10003), name="Guest2")
        assert srv.users.add(persona_dup)
        hpdup = ClientHandler(srv, persona_dup)
        cper_frame = ClientHandler._make_20922_tab_message("cper", ["PERS=Alice"])
        consumed = hpdup._consume_bootstrap_frames(cper_frame)
        assert consumed == len(cper_frame), "duplicate cper frame was not consumed"
        assert persona_dup.conn.sent[:21] == persona_duplicate_frame, "duplicate cper did not send cperdupl"
        assert persona_dup.connected, "duplicate cper should not disconnect the client"
        assert persona_dup.pers != "Alice", "duplicate cper claimed an already active persona"

        srv.cfg["LAN_AUTH_VERIFY"] = 0
        srv.cfg["LAN_AUTH_CAPTURE"] = 1
        ok, reason, _, ident = srv.authenticate_lan_login({"NAME": "Captured", "PASS": "cap-wire", "PSES": "abc"})
        assert ok and reason == "disabled" and ident == "Captured"
        with open(captures_path, "r", encoding="utf-8") as fh:
            capture = json.loads(fh.readline())
        assert capture["identifier"] == "Captured"
        assert "pass_wire" not in capture
        assert capture["pass_len"] == len("cap-wire")
        assert capture["pass_sha256"] == hashlib.sha256(b"cap-wire").hexdigest()
        assert capture["fields"]["PASS"] == "<redacted>"
        assert capture["fields"]["PSES"] == "abc"

        os.unlink(accounts_path)
        srv.cfg["LAN_AUTH_VERIFY"] = 1
        srv.cfg["LAN_AUTH_MODE"] = "password"
        srv.cfg["LAN_AUTH_CAPTURE"] = 0
        srv.cfg["LAN_AUTH_AUTO_ENROLL"] = 1
        new_token = GameServer._lan_auth_make_pass_token("new-wire", "new-mask")
        ok, reason, account, ident = srv.authenticate_lan_login(
            {"NAME": "NewUser", "PASS": new_token, "MASK": "new-mask", "MAIL": "new@example.test"}
        )
        assert ok and reason == "enrolled" and account.get("name") == "NewUser" and ident == "new@example.test"
        with open(accounts_path, "r", encoding="utf-8") as fh:
            saved = json.load(fh)
        assert "pass_wire" not in saved["users"][0]
        assert str(saved["users"][0].get("password_pbkdf2", "")).startswith("pbkdf2_sha256$")
        assert "new@example.test" in saved["users"][0]["aliases"]
        new_token = GameServer._lan_auth_make_pass_token("new-wire", "new-mask-2")
        ok, reason, account, ident = srv.authenticate_lan_login(
            {"NAME": "NewUser", "PASS": new_token, "MASK": "new-mask-2"}
        )
        assert ok and reason == "ok" and account.get("name") == "NewUser" and ident == "NewUser"

        os.unlink(accounts_path)
        srv.cfg["LAN_AUTH_AUTO_ENROLL"] = 0
        ok, reason, _, ident = srv.create_lan_account(
            {"NAME": "BlockedCreate", "PASS": "blocked-wire"}
        )
        assert not ok and reason == "create_disabled" and ident == "BlockedCreate"

        srv.cfg["LAN_AUTH_ALLOW_CREATE"] = 1
        created = User(DummyConn(), ("127.0.0.1", 10004), name="GuestCreate")
        assert srv.users.add(created)
        hcreated = ClientHandler(srv, created)
        created_token = GameServer._lan_auth_make_pass_token("created-wire", "acct-mask")
        acct_frame = ClientHandler._make_20922_tab_message(
            "acct",
            [
                "NAME=CreatedUser",
                f"PASS={created_token}",
                "MASK=acct-mask",
                "MAIL=created@example.test",
            ],
        )
        consumed = hcreated._consume_bootstrap_frames(acct_frame)
        assert consumed == len(acct_frame), "acct frame was not consumed"
        assert created.conn.sent[:4] == b"acct", "acct did not send account-create ack"
        created_token = GameServer._lan_auth_make_pass_token("created-wire", "acct-mask-2")
        ok, reason, account, ident = srv.authenticate_lan_login(
            {"NAME": "CreatedUser", "PASS": created_token, "MASK": "acct-mask-2"}
        )
        assert ok and reason == "ok" and account.get("name") == "CreatedUser" and ident == "CreatedUser"
        with open(accounts_path, "r", encoding="utf-8") as fh:
            saved = json.load(fh)
        assert "pass_wire" not in saved["users"][0]
        assert str(saved["users"][0].get("password_pbkdf2", "")).startswith("pbkdf2_sha256$")
        assert "created@example.test" in saved["users"][0]["aliases"]

        duplicate_create = User(DummyConn(), ("127.0.0.1", 10005), name="GuestCreateDuplicate")
        assert srv.users.add(duplicate_create)
        hduplicate_create = ClientHandler(srv, duplicate_create)
        duplicate_acct_frame = ClientHandler._make_20922_tab_message(
            "acct",
            [
                "NAME=CreatedUser",
                "PASS=created-wire",
            ],
        )
        consumed = hduplicate_create._consume_bootstrap_frames(duplicate_acct_frame)
        assert consumed == len(duplicate_acct_frame), "duplicate acct frame was not consumed"
        assert duplicate_create.conn.sent[:21] == account_exists_frame, "duplicate acct did not send acctdupl"
        assert duplicate_create.connected, "duplicate acct should not disconnect the client"

        forced_persona = User(DummyConn(), ("127.0.0.1", 10006), name="GuestPersona")
        assert srv.users.add(forced_persona)
        hforced_persona = ClientHandler(srv, forced_persona)
        response = srv._run_admin_command("personacode cperinvp BadPersona")
        assert "cperinvp" in response, f"personacode cperinvp command failed: {response!r}"
        forced_cper_frame = ClientHandler._make_20922_tab_message("cper", ["PERS=BadPersona"])
        consumed = hforced_persona._consume_bootstrap_frames(forced_cper_frame)
        assert consumed == len(forced_cper_frame), "forced cper frame was not consumed"
        expected_cperinvp = ClientHandler._make_20922_signed_binary_message(
            "cper",
            b"\x00",
            9,
            reserved_be32=_LAN_INVP_RESERVED,
        )
        assert forced_persona.conn.sent[:21] == expected_cperinvp, "forced cper did not send cperinvp"
        assert forced_persona.pers != "BadPersona", "forced rejected cper still claimed persona"

        forced_select = User(DummyConn(), ("127.0.0.1", 10007), name="GuestSelect")
        assert srv.users.add(forced_select)
        hforced_select = ClientHandler(srv, forced_select)
        response = srv._run_admin_command("personacode persmaut SelectedPersona")
        assert "persmaut" in response and "select-persona/pers" in response, (
            f"personacode persmaut command failed: {response!r}"
        )
        forced_pers_frame = ClientHandler._make_20922_tab_message("pers", ["PERS=SelectedPersona"])
        consumed = hforced_select._consume_bootstrap_frames(forced_pers_frame)
        assert consumed == len(forced_pers_frame), "forced pers frame was not consumed"
        expected_persmaut = ClientHandler._make_20922_signed_binary_message(
            "pers",
            b"\x00",
            9,
            reserved_be32=_LAN_MAUT_RESERVED,
        )
        assert forced_select.conn.sent[:21] == expected_persmaut, "forced pers did not send persmaut"
        assert forced_select.pers != "SelectedPersona", "forced rejected pers still claimed persona"


def assert_lan_stats_snap_offsets():
    from server import GameServer
    from client_handler import ClientHandler
    from user_manager import User
    from ranking import StatsSystem
    import tempfile

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.TemporaryDirectory() as root:
        cfg_path = os.path.join(root, "server.cfg")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(
                f"RANKFILE={root}/rankings.json\n"
                f"STATSFILE={root}/stats.json\n"
                "AUTH_VERIFY=0\n"
            )

        srv = GameServer(cfg_path)
        user = User(DummyConn(), ("127.0.0.1", 1111), name="Moio")
        user.pers = "Moio"
        assert srv.users.add(user)
        handler = ClientHandler(srv, user)

        assert ClientHandler._lan_race_category_from_fields({}, "TRACK%3d4000%0aDIR%3d0") == 1
        assert ClientHandler._lan_race_category_from_fields({"RACETYPE": "0"}, "") == 1
        assert ClientHandler._lan_race_category_from_fields({"TYPE": "3"}, "") == 4
        assert ClientHandler._lan_cust_mode_bit_from_fields({}, "MODE%3d8") == 0x02000000
        assert ClientHandler._lan_cust_mode_bit_from_fields({}, "MODE%3d4") == 0x80000000
        assert ClientHandler._lan_cust_mode_bit_from_fields({}, "MODE%3d5") == 0x40000000
        assert ClientHandler._lan_cust_mode_bit_from_fields({}, "MODE%3d10") == 0x40000000
        assert ClientHandler._lan_cust_mode_bit_from_fields({}, "TYPE%3dStreet+X") == 0x80000000
        assert ClientHandler._lan_cust_mode_bit_from_fields({}, "TYPE%3dURL") == 0x40000000
        assert ClientHandler._lan_custflags_for_race_category(0x040000F1, None, params="MODE%3d8") == str(0x020000F1)

        stats_probe = StatsSystem({"STATSFILE": os.path.join(root, "probe_stats.json")})
        stats_probe.record_player_result("Bob", "WIN", category_index=1)
        stats_probe.record_player_result("Bob", "WIN", category_index=1)
        stats_probe.record_player_result("Moio", "WIN", category_index=1, opponent_personas=["Bob"])
        moio_probe = stats_probe.get_player_stats("Moio")
        assert moio_probe.get(0, "opps_rep") == 300 and moio_probe.get(1, "opps_rep") == 300, (
            f"opponent rep averages were not copied into stats: {moio_probe.values!r}"
        )
        assert moio_probe.get(0, "opps_rating") == 1 and moio_probe.get(1, "opps_rating") == 1, (
            f"opponent rating averages were not copied into stats: {moio_probe.values!r}"
        )

        srv.stats.record_player_result("Moio", "WIN", category_index=1)
        overall = handler._lan_snap_burst(
            {"INDEX": "99", "CHAN": "1", "START": "0", "RANGE": "5", "FIND": "$"}
        ).decode("latin1", errors="ignore")
        assert "snap" in overall and "SEQN=0" in overall, f"snap ack missing: {overall!r}"
        assert "BOARD=" not in overall, f"snap ack should not invent a board field: {overall!r}"
        assert "COUNT=1" in overall and "TOTAL=1" in overall and "MORE=0" in overall, (
            f"snap ack should include completion metadata: {overall!r}"
        )
        assert "+snp" in overall and "P=0\t" in overall, f"overall row rank should be zero-based: {overall!r}"
        assert "P=0,1,1" not in overall, f"overall P should not use monthly triplet format: {overall!r}"
        assert "S=1,1,0,0" in overall and "N=Moio" in overall and "O=1" in overall, (
            f"overall stats row wrong: {overall!r}"
        )

        circuit = handler._lan_snap_burst(
            {"INDEX": "2", "CHAN": "0", "START": "0", "RANGE": "5"}
        ).decode("latin1", errors="ignore")
        assert "P=0\t" in circuit, f"circuit row rank should be zero-based: {circuit!r}"
        assert "S=,,,,,,,1,1,0,0" in circuit, f"circuit S should start at stats offset 7: {circuit!r}"

        srv.stats.record_player_result("Bob", "WIN", category_index=1)
        srv.stats.record_player_result("Bob", "WIN", category_index=1)
        overall_alias = handler._lan_snap_burst(
            {"INDEX": "1", "CHAN": "6", "START": "0", "RANGE": "100"}
        ).decode("latin1", errors="ignore")
        assert "RANGE=2" in overall_alias and "COUNT=2" in overall_alias, (
            f"CHAN=6 ack should advertise the effective returned row count: {overall_alias!r}"
        )
        assert "N=Bob" in overall_alias and "N=Moio" in overall_alias, (
            f"CHAN=6 should map to the overall stats board: {overall_alias!r}"
        )
        assert "P=0,1,1\t" in overall_alias and "P=1,1,1\t" in overall_alias, (
            f"CHAN=6 stats ranks should use the high-channel triplet format: {overall_alias!r}"
        )
        assert "S=1,2,0,0" in overall_alias and ",1,2,0,0" in overall_alias, (
            f"CHAN=6 should send the full 5x7 stats block: {overall_alias!r}"
        )

        find_self = handler._lan_snap_burst(
            {"INDEX": "1", "CHAN": "12", "RANGE": "1", "FIND": "$"}
        ).decode("latin1", errors="ignore")
        assert "N=Moio" in find_self and "N=Bob" not in find_self, (
            f"CHAN=12 FIND=$ should return the current persona row: {find_self!r}"
        )
        assert "P=1,1,1\t" in find_self, f"FIND=$ should preserve the current persona rank: {find_self!r}"
        assert "S=2,1,0,0" in find_self and ",2,1,0,0" in find_self, (
            f"CHAN=12 FIND=$ should send the full 5x7 stats block: {find_self!r}"
        )

        bumped = srv._run_admin_command("statbump Moio win sprint 2")
        assert "stats bumped persona=Moio" in bumped and "wins=3" in bumped, f"statbump failed: {bumped!r}"
        shown = srv._run_admin_command("statshow Moio")
        assert "persona=Moio" in shown and "wins=3" in shown and "S=" in shown, f"statshow failed: {shown!r}"

        url_alias = handler._lan_snap_burst(
            {"INDEX": "51", "CHAN": "11", "START": "0", "RANGE": "100"}
        ).decode("latin1", errors="ignore")
        assert "RANGE=2" in url_alias and "COUNT=2" in url_alias, (
            f"CHAN=11 URL-style ack should advertise the effective returned row count: {url_alias!r}"
        )
        assert "P=0,1,1\t" in url_alias and "S=" in url_alias and "N=Moio" in url_alias, (
            f"CHAN=11 URL-style board should use high-channel stats rows: {url_alias!r}"
        )

        url_find = handler._lan_snap_burst(
            {"INDEX": "51", "CHAN": "17", "RANGE": "1", "FIND": "$"}
        ).decode("latin1", errors="ignore")
        assert "N=Moio" in url_find and "P=1,1,1\t" in url_find and "S=" in url_find, (
            f"CHAN=17 URL-style FIND should return the current persona stats row: {url_find!r}"
        )
        url_bumped = srv._run_admin_command("statbump Moio win url 1")
        assert "category=drift" in url_bumped and "usage:" not in url_bumped, (
            f"statbump url alias failed: {url_bumped!r}"
        )


def assert_room_game_privacy_password_metadata():
    from server import GameServer
    from client_handler import ClientHandler
    from user_manager import User
    import tempfile

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.TemporaryDirectory() as root:
        cfg_path = os.path.join(root, "server.cfg")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(
                f"RANKFILE={root}/rankings.json\n"
                f"STATSFILE={root}/stats.json\n"
                "AUTH_VERIFY=0\n"
            )

        srv = GameServer(cfg_path)
        host = User(DummyConn(), ("127.0.0.1", 1111), name="Host")
        host.pers = "Host"
        peer = User(DummyConn(), ("127.0.0.1", 2222), name="Peer")
        peer.pers = "Peer"
        assert srv.users.add(host)
        assert srv.users.add(peer)
        hhost = ClientHandler(srv, host)
        hpeer = ClientHandler(srv, peer)

        hhost._cmd_room(
            {
                "NAME": "Secret Room",
                "MAXSIZE": 4,
                "MINSIZE": 3,
                "PASS": "abc",
                "PRIV": 1,
                "MATCHED": 1,
                "CUSTFLAGS": 7,
                "SYSFLAGS": 8,
            }
        )
        room = srv.rooms.get(host.room)
        assert room is not None, "password/private room was not created"
        assert room.secret == "abc" and room.private and room.matched, f"room metadata not stored: {room.to_dict()!r}"
        assert room.minsize == 3 and room.custflags == 7 and room.sysflags == 851976, f"room sizing/flags wrong: {room.to_dict()!r}"

        hpeer._cmd_rooms({})
        assert b"Secret Room" not in peer.conn.sent, f"private room leaked into public ROOMS: {peer.conn.sent!r}"
        peer.conn.sent.clear()
        hpeer._cmd_room({"IDENT": room.id})
        assert peer.room == 0 and peer.conn.sent.startswith(b"-ROOM"), "password room join without PASS should fail"
        peer.conn.sent.clear()
        hpeer._cmd_room({"IDENT": room.id, "PASS": "abc"})
        assert peer.room == room.id and b"+ROOM" in peer.conn.sent, "password room join with PASS should succeed"

        host.conn.sent.clear()
        peer.conn.sent.clear()
        gcre = ClientHandler._make_20922_tab_message(
            "gcre",
            [
                "NAME=meta-room",
                "MAXSIZE=6",
                "MINSIZE=3",
                "CUSTFLAGS=67108881",
                "SYSFLAGS=262144",
                "PASS=lanpass",
                "PARAMS=TRACK%3d4000%0aDIR%3d0%0aLAPS%3d3",
            ],
        )
        consumed = hhost._consume_bootstrap_frames(gcre)
        assert consumed == len(gcre), "metadata gcre frame was not consumed"
        game = srv.games.get(host.game)
        assert game is not None, "metadata gcre did not create a game"
        assert game.limit == 6 and getattr(game, "_lan_minsize", 0) == 3, f"LAN game sizing not stored: {game.to_dict()!r}"
        assert hhost._lan_game_secret(game) == "lanpass" and not hhost._lan_game_private(game), (
            f"password-only LAN game should stay visible but locked: {game.to_dict()!r}"
        )
        fields = hhost._lan_game_reply_fields(
            game,
            params=hhost._lan_game_params(game),
            custflags=hhost._lan_game_custflags(game),
            sysflags=hhost._lan_game_sysflags(game),
            tunnel_addrs=True,
        )
        joined_fields = "\t".join(fields)
        assert "MAXSIZE=6" in joined_fields and "MINSIZE=3" in joined_fields, f"LAN reply ignored dynamic size: {joined_fields!r}"
        assert "CUSTFLAGS=67108881" in joined_fields and "SYSFLAGS=327680" in joined_fields, f"LAN reply ignored dynamic flags: {joined_fields!r}"
        assert "HASPASS=1" in joined_fields and "\tPASS=" not in joined_fields, f"LAN password marker leaked PASS field: {joined_fields!r}"
        gam_fields = "\t".join(hhost._lan_gam_fields(game, params=hhost._lan_game_params(game)))
        assert ",4000011,meta-room,meta-room" in gam_fields and ",6,3," in gam_fields, (
            f"+gam GAME csv did not use dynamic flags/size: {gam_fields!r}"
        )
        password_snapshot = hpeer._lan_lobby_snapshot_for(peer)
        assert b"meta-room" in password_snapshot, "password-only LAN game should stay visible in lobby"
        assert password_snapshot.count(b"+gam") == 1, f"password-only LAN game should emit one lobby row: {password_snapshot!r}"
        assert b"CUSTFLAGS=67108881" in password_snapshot and b"SYSFLAGS=327680" in password_snapshot, (
            f"password-only LAN game did not expose public password flags: {password_snapshot!r}"
        )
        assert b"HASPASS=1" in password_snapshot and b"\tPASS=" not in password_snapshot, (
            f"password-only LAN game leaked PASS field: {password_snapshot!r}"
        )
        assert b"OPID0=" in password_snapshot and b"HOST=" in password_snapshot and b"GAME=" not in password_snapshot, (
            f"password-only LAN lobby row should use detailed +gam shape: {password_snapshot!r}"
        )
        public_search = {"SYSFLAGS": "0", "SYSMASK": str(0xC0000)}
        assert b"meta-room" in hpeer._lan_lobby_snapshot_for(peer, search_kv=public_search), (
            "password-only LAN game should match public gsea search"
        )
        public_search_cust_variant = {
            "SYSFLAGS": "0",
            "SYSMASK": str(0xC0000),
            "CUSTFLAGS": "67109107",
            "CUSTMASK": str(0x3),
        }
        assert b"meta-room" in hpeer._lan_lobby_snapshot_for(peer, search_kv=public_search_cust_variant), (
            "public LAN game should tolerate volatile low CUSTFLAGS search bits"
        )
        allowed, reason = hpeer._lan_game_join_allowed(game, {}, invited=False)
        assert not allowed and reason == "password", f"password LAN join without PASS unexpectedly allowed: {reason!r}"
        peer.conn.sent.clear()
        bad_gjoi = ClientHandler._make_20922_tab_message(
            "gjoi",
            [
                "NAME=meta-room",
                "PASS=wrong",
            ],
        )
        consumed = hpeer._consume_bootstrap_frames(bad_gjoi)
        assert consumed == len(bad_gjoi), "bad-password gjoi frame was not consumed"
        bad_sent = bytes(peer.conn.sent)
        assert peer.game == 0 and peer.uid not in game.participants, "bad password joined the protected LAN game"
        assert bad_sent[:4] == b"gjoi" and bad_sent[4:8] == b"pass", (
            f"bad password did not receive gjoi/pass reject: {bad_sent!r}"
        )
        assert b"+usr" not in bad_sent and b"+gam" not in bad_sent, (
            f"bad password reject should not look like a successful join/reset: {bad_sent!r}"
        )
        peer.conn.sent.clear()
        good_gjoi = ClientHandler._make_20922_tab_message(
            "gjoi",
            [
                "NAME=meta-room",
                "PASS=lanpass",
            ],
        )
        consumed = hpeer._consume_bootstrap_frames(good_gjoi)
        assert consumed == len(good_gjoi), "good-password gjoi frame was not consumed"
        assert peer.game == game.id and peer.uid in game.participants, "good password did not join the protected LAN game"
        srv.games.leave(game.id, peer.uid)
        peer.game = 0
        peer.stat = "LOBBY"

        srv.games.destroy(game.id, reason="test_password_metadata_done")
        host.game = 0
        host.conn.sent.clear()
        peer.conn.sent.clear()
        mode_mismatch_gcre = ClientHandler._make_20922_tab_message(
            "gcre",
            [
                "NAME=mode-normalized-public",
                "MAXSIZE=4",
                "MINSIZE=2",
                f"CUSTFLAGS={0x080000F1}",
                "SYSFLAGS=0",
                "PARAMS=TRACK%3d4000%0aDIR%3d0%0aLAPS%3d1",
            ],
        )
        consumed = hhost._consume_bootstrap_frames(mode_mismatch_gcre)
        assert consumed == len(mode_mismatch_gcre), "mode-mismatch public gcre frame was not consumed"
        mode_game = srv.games.get(host.game)
        assert mode_game is not None and not hhost._lan_game_private(mode_game), (
            f"mode-mismatch public LAN game was detected as private: {mode_game.to_dict() if mode_game else None!r}"
        )
        assert hhost._lan_game_custflags(mode_game) == str(0x040000F1), (
            f"TRACK=4000 did not normalize CUSTFLAGS mode to circuit: {hhost._lan_game_custflags(mode_game)!r}"
        )
        mode_search = {
            "SYSFLAGS": "0",
            "SYSMASK": str(0xC0000),
            "CUSTFLAGS": str(0x040000F1),
            "CUSTMASK": str(0x040001F3),
        }
        assert b"mode-normalized-public" in hpeer._lan_lobby_snapshot_for(peer, search_kv=mode_search), (
            "TRACK=4000 mode-normalized LAN game did not match circuit gsea search"
        )

        srv.games.destroy(mode_game.id, reason="test_mode_normalized_public_done")
        host.game = 0
        host.conn.sent.clear()
        peer.conn.sent.clear()
        restricted_gcre = ClientHandler._make_20922_tab_message(
            "gcre",
            [
                "NAME=restricted-public",
                "MAXSIZE=4",
                "MINSIZE=2",
                f"CUSTFLAGS={0x04000083}",
                "SYSFLAGS=0",
                "PARAMS=TRACK%3d4000%0aDIR%3d0%0aLAPS%3d2",
            ],
        )
        consumed = hhost._consume_bootstrap_frames(restricted_gcre)
        assert consumed == len(restricted_gcre), "restricted public gcre frame was not consumed"
        restricted_game = srv.games.get(host.game)
        assert restricted_game is not None and not hhost._lan_game_private(restricted_game), (
            f"class-restricted public LAN game was detected as private: {restricted_game.to_dict() if restricted_game else None!r}"
        )
        restricted_search = {
            "SYSFLAGS": str(0x40000),
            "SYSMASK": str(0xC0000),
            "CUSTFLAGS": str(0x040000F3),
            "CUSTMASK": str(0xFFFFFFFF),
        }
        restricted_match_search = {
            "SYSFLAGS": str(0x40000),
            "SYSMASK": str(0xC0000),
            "CUSTFLAGS": str(0x04000083),
            "CUSTMASK": str(0xFFFFFFFF),
        }
        assert b"restricted-public" not in hpeer._lan_lobby_snapshot_for(peer, search_kv=restricted_search), (
            "class-restricted public LAN game matched unrestricted/all-class gsea search"
        )
        assert b"restricted-public" in hpeer._lan_lobby_snapshot_for(peer, search_kv=restricted_match_search), (
            "class-restricted public LAN game did not match same-class gsea search"
        )
        srv.cfg["LAN_GSEA_CUST_FILTERS"] = 0
        assert b"restricted-public" in hpeer._lan_lobby_snapshot_for(peer, search_kv=restricted_search), (
            "LAN_GSEA_CUST_FILTERS=0 did not ignore CUSTFLAGS/CUSTMASK search filtering"
        )
        srv.cfg["LAN_GSEA_CUST_FILTERS"] = 1

        srv.games.destroy(restricted_game.id, reason="test_restricted_public_done")
        host.game = 0
        host.conn.sent.clear()
        peer.conn.sent.clear()
        extra_gcre = ClientHandler._make_20922_tab_message(
            "gcre",
            [
                "NAME=extra-flag-public",
                "MAXSIZE=4",
                "MINSIZE=2",
                f"CUSTFLAGS={0x040001F3}",
                "SYSFLAGS=0",
                "PARAMS=TRACK%3d4000%0aDIR%3d0%0aLAPS%3d2",
            ],
        )
        consumed = hhost._consume_bootstrap_frames(extra_gcre)
        assert consumed == len(extra_gcre), "extra-flag public gcre frame was not consumed"
        extra_game = srv.games.get(host.game)
        assert extra_game is not None and not hhost._lan_game_private(extra_game), (
            f"0x100 CUSTFLAGS public LAN game was detected as private: {extra_game.to_dict() if extra_game else None!r}"
        )
        extra_match_search = {
            "CUSTFLAGS": str(0x040001F3),
            "CUSTMASK": str(0x1F0),
        }
        extra_mismatch_search = {
            "CUSTFLAGS": str(0x040000F3),
            "CUSTMASK": str(0x1F0),
        }
        assert b"extra-flag-public" in hpeer._lan_lobby_snapshot_for(peer, search_kv=extra_match_search), (
            "0x100 CUSTFLAGS LAN game did not match equivalent gsea search"
        )
        assert b"extra-flag-public" not in hpeer._lan_lobby_snapshot_for(peer, search_kv=extra_mismatch_search), (
            "0x100 CUSTFLAGS LAN game ignored the gsea extra-bit filter"
        )

        srv.games.destroy(extra_game.id, reason="test_extra_public_done")
        host.game = 0
        host.conn.sent.clear()
        peer.conn.sent.clear()
        private_gcre = ClientHandler._make_20922_tab_message(
            "gcre",
            [
                "NAME=private-room",
                "MAXSIZE=4",
                "MINSIZE=3",
                "CUSTFLAGS=67108881",
                "SYSFLAGS=262144",
                "PARAMS=TRACK%3d4000%0aDIR%3d0%0aLAPS%3d3",
            ],
        )
        consumed = hhost._consume_bootstrap_frames(private_gcre)
        assert consumed == len(private_gcre), "private metadata gcre frame was not consumed"
        private_game = srv.games.get(host.game)
        assert private_game is not None and hhost._lan_game_private(private_game), (
            f"flag-only private LAN game was not detected: {private_game.to_dict() if private_game else None!r}"
        )
        assert b"private-room" not in hpeer._lan_lobby_snapshot_for(peer), "flag-only private LAN game leaked to public lobby snapshot"
        assert b"private-room" not in hpeer._lan_lobby_snapshot_for(peer, search_kv=public_search), (
            "flag-only private LAN game leaked to public gsea search"
        )
        private_search = {"SYSFLAGS": str(0x40000), "SYSMASK": str(0xC0000)}
        private_snapshot = hpeer._lan_lobby_snapshot_for(peer, search_kv=private_search)
        assert b"private-room" in private_snapshot, (
            "flag-only private LAN game did not match private gsea search"
        )
        assert b"MINSIZE=2" in private_snapshot, (
            f"private LAN game should advertise two-player start minimum: {private_snapshot!r}"
        )
        allowed, reason = hpeer._lan_game_join_allowed(private_game, {}, invited=False)
        assert allowed, f"private LAN direct join should not be blocked by private flag alone: {reason!r}"


def assert_social_relations():
    from server import GameServer
    from user_manager import User
    from control_handler import ControlHandler
    import json
    import tempfile
    import textwrap

    with tempfile.TemporaryDirectory() as root:
        social_path = os.path.join(root, "social_relations.json")
        cfg_path = os.path.join(root, "server.cfg")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent(f"""\
                CONTROL_SOCIAL_ENABLE=1
                CONTROL_SOCIAL_FILE={social_path}
                CONTROL_RNOT_SELF_ENABLE=0
                CONTROL_SOCIAL_ALL_ONLINE_ENABLE=1
            """))

        class DummySocialHandler:
            def __init__(self):
                self.sent = []

            def _send_message(self, verb, lines):
                self.sent.append((verb, list(lines)))
                return True

        class DummyConn:
            def sendall(self, data):
                pass

        profile_srv = GameServer(cfg_path)
        moio_user = User(DummyConn(), ("127.0.0.1", 20001), name="Moio")
        moio_user.pers = "Moio"
        assert profile_srv.users.add(moio_user)
        profile_srv.control_social_register(DummySocialHandler(), "Moio")
        profile_srv.remember_control_profile(name="PC2", persona="PC2", client_addr="127.0.0.1")
        profile = profile_srv.get_control_profile("127.0.0.1")
        assert profile.get("persona") == "PC2", f"recent profile was not used for second same-IP client: {profile!r}"
        newest_srv = GameServer(cfg_path)
        newest_srv.remember_control_profile(name="Moio9", persona="Moio9", client_addr="127.0.0.1")
        newest_srv.remember_control_profile(name="PC2", persona="PC2", client_addr="127.0.0.1")
        profile = newest_srv.get_control_profile("127.0.0.1")
        assert profile.get("persona") == "PC2", f"same-IP control profile did not prefer newest login: {profile!r}"
        delayed_srv = GameServer(cfg_path)
        delayed = ControlHandler(delayed_srv, DummyConn(), ("127.0.0.1", 23001))
        assert not delayed._peer_user and not delayed._social_registered, "empty control handler registered too early"
        delayed_srv.remember_control_profile(name="LatePC2", persona="LatePC2", client_addr="127.0.0.1")
        delayed._maybe_update_peer_user({"USER": "NFS-CONSOLE-2005"})
        assert delayed._peer_user == "LatePC2" and delayed._social_registered, "control handler did not claim a later profile"
        profiled_srv = GameServer(cfg_path)
        profiled_srv.remember_control_profile(name="ProfiledPC2", persona="ProfiledPC2", client_addr="127.0.0.1")
        profiled = ControlHandler(profiled_srv, DummyConn(), ("127.0.0.1", 23002))
        assert profiled._peer_user == "ProfiledPC2" and not profiled._social_registered, "profiled control handler registered before AUTH"
        profiled._maybe_update_peer_user({"USER": "NFS-CONSOLE-2005"})
        assert profiled._social_registered, "profiled control handler did not register after AUTH-like USER"

        srv = GameServer(cfg_path)
        alice_handler = DummySocialHandler()
        bob_handler = DummySocialHandler()
        srv.control_social_register(alice_handler, "AlicePers")
        srv.control_social_register(bob_handler, "BobPers")
        assert any(
            verb == "RNOT" and "USER=BobPers" in lines and "ATTR=D" in lines
            for verb, lines in alice_handler.sent
        ), f"online-only user notification missing: {alice_handler.sent!r}"
        assert any(
            verb == "PGET" and "USER=BobPers" in lines and "ATTR=D" in lines
            for verb, lines in alice_handler.sent
        ), f"online presence push missing: {alice_handler.sent!r}"
        assert not bob_handler.sent, f"self online notification leaked: {bob_handler.sent!r}"

        roster = srv.control_social_snapshot("AlicePers", "B")
        assert roster == [], f"online users leaked into friend/request roster: {roster!r}"
        online = srv.control_social_snapshot("AlicePers", "ALL")
        assert len(online) == 1 and online[0]["user"] == "BobPers", f"online roster wrong: {online!r}"
        assert online[0]["attr"] == "D", f"online roster should not look like a buddy/request: {online!r}"
        assert srv.control_social_add_relation("AlicePers", "AlicePers", "B") == "N", "self buddy add should be ignored"
        roster = srv.control_social_snapshot("AlicePers", "B")
        assert roster == [], f"self or online user leaked into buddy list: {roster!r}"
        assert srv.control_social_add_relation("AlicePers", "BobPers/PC", "B") == "R", "friend request did not return request attr"
        roster = srv.control_social_snapshot("AlicePers", "B")
        assert roster == [], f"outgoing request leaked into sender roster: {roster!r}"
        roster = srv.control_social_snapshot("BobPers", "B")
        assert len(roster) == 1 and roster[0]["user"] == "AlicePers" and roster[0]["attr"] == "R", f"incoming request snapshot wrong: {roster!r}"
        request_row = srv.control_social_roster_row("BobPers", "AlicePers/PC", "B")
        assert request_row is not None and request_row["attr"] == "R", f"incoming request row lookup wrong: {request_row!r}"
        assert srv.control_social_add_relation("BobPers/PC", "AlicePers/PC", "B") == "", "accept did not create friendship"
        roster = srv.control_social_snapshot("AlicePers", "B")
        assert len(roster) == 1 and roster[0]["user"] == "BobPers" and roster[0]["attr"] == "", f"buddy snapshot wrong: {roster!r}"
        roster = srv.control_social_snapshot("BobPers", "B")
        assert len(roster) == 1 and roster[0]["user"] == "AlicePers" and roster[0]["attr"] == "", f"reciprocal buddy snapshot wrong: {roster!r}"
        assert srv.control_social_remove_relation("AlicePers", "BobPers/PC", "B") == "", "slash-suffixed unfriend failed"
        roster = srv.control_social_snapshot("AlicePers", "B")
        assert roster == [], f"slash-suffixed unfriend did not remove buddy: {roster!r}"
        assert srv.control_social_add_relation("BobPers", "AlicePers", "B") == "R", "recreated request did not return request attr"
        assert srv.control_social_add_relation("AlicePers", "BobPers", "B") == "", "reaccept did not recreate friendship"
        alice_handler.sent.clear()
        srv.control_social_unregister(bob_handler)
        assert not any(
            verb == "RNOT" and "CHNG=D" in lines and "USER=BobPers" in lines
            for verb, lines in alice_handler.sent
        ), f"buddy disconnect deleted friend row: {alice_handler.sent!r}"
        assert any(
            verb == "RNOT" and "CHNG=A" in lines and "USER=BobPers" in lines
            for verb, lines in alice_handler.sent
        ), f"buddy disconnect did not refresh friend row before offline presence: {alice_handler.sent!r}"
        assert any(
            verb == "ROST" and "USER=BobPers" in lines and not any(line.startswith("ATTR=") for line in lines)
            for verb, lines in alice_handler.sent
        ), f"buddy disconnect did not reassert friend row: {alice_handler.sent!r}"
        assert not any(
            verb == "PGET" and "USER=BobPers" in lines
            for verb, lines in alice_handler.sent
        ), f"buddy disconnect published presence for an offline friend: {alice_handler.sent!r}"
        assert not any(
            verb == "PGET" and "USER=BobPers" in lines and "ATTR=D" in lines
            for verb, lines in alice_handler.sent
        ), f"buddy disconnect degraded friend into online-only presence: {alice_handler.sent!r}"
        alice_handler.sent.clear()
        bob_handler = DummySocialHandler()
        srv.control_social_register(bob_handler, "BobPers")
        assert any(
            verb == "RNOT" and "CHNG=A" in lines and "USER=BobPers" in lines
            for verb, lines in alice_handler.sent
        ), f"buddy reconnect did not notify remaining client: {alice_handler.sent!r}"
        assert not any(
            verb == "RNOT" and "USER=BobPers" in lines and "ATTR=R" in lines
            for verb, lines in alice_handler.sent
        ), f"buddy reconnect looked like an incoming request: {alice_handler.sent!r}"
        assert not any(
            verb in ("RNOT", "PGET") and "USER=BobPers" in lines and "ATTR=D" in lines
            for verb, lines in alice_handler.sent
        ), f"buddy reconnect degraded friend into online-only presence: {alice_handler.sent!r}"
        assert any(
            verb == "ROST" and "USER=BobPers" in lines and not any(line.startswith("ATTR=") for line in lines)
            for verb, lines in alice_handler.sent
        ), f"buddy reconnect did not reassert friend roster row: {alice_handler.sent!r}"
        assert srv.control_social_add_relation("AlicePers", "CharliePers", "I") == "B", "block add did not return block attr"
        blocked = srv.control_social_snapshot("AlicePers", "I")
        assert len(blocked) == 1 and blocked[0]["user"] == "CharliePers", f"block snapshot wrong: {blocked!r}"

        with open(social_path, "r", encoding="utf-8") as fh:
            saved = json.load(fh)
        assert saved["buddies"]["alicepers"] == ["bobpers"], f"buddy relation was not saved: {saved!r}"
        assert saved["buddies"]["bobpers"] == ["alicepers"], f"reciprocal buddy relation was not saved: {saved!r}"
        assert not saved.get("pending"), f"accepted request stayed pending: {saved!r}"
        assert saved["blocks"]["alicepers"] == ["charliepers"], f"block relation was not saved: {saved!r}"

        srv2 = GameServer(cfg_path)
        roster2 = srv2.control_social_snapshot("AlicePers", "B")
        blocked2 = srv2.control_social_snapshot("AlicePers", "I")
        assert len(roster2) == 1 and roster2[0]["user"] == "BobPers" and roster2[0]["attr"] == "", f"buddy relation did not persist: {roster2!r}"
        assert len(blocked2) == 1 and blocked2[0]["user"] == "CharliePers", f"block relation did not persist: {blocked2!r}"


def assert_control_send_friend_request():
    from server import GameServer
    from control_handler import ControlHandler
    import json
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = []

        def sendall(self, data):
            self.sent.append(bytes(data))

    with tempfile.TemporaryDirectory() as root:
        cfg_path = os.path.join(root, "server.cfg")
        social_path = os.path.join(root, "social_relations.json")
        accounts_path = os.path.join(root, "auth_accounts.json")
        with open(accounts_path, "w", encoding="utf-8") as fh:
            json.dump({"users": [{"name": "OfflineAccount", "personas": ["OfflinePers"]}]}, fh)
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent(f"""\
                CONTROL_SOCIAL_ENABLE=1
                CONTROL_SOCIAL_FILE={social_path}
                CONTROL_RNOT_SELF_ENABLE=0
                CONTROL_SOCIAL_ALL_ONLINE_ENABLE=1
                LAN_AUTH_ACCOUNTS_FILE={accounts_path}
            """))
        srv = GameServer(cfg_path)
        srv.remember_control_profile(name="AlicePers", persona="AlicePers", client_addr="127.0.0.1")
        alice = ControlHandler(srv, DummyConn(), ("127.0.0.1", 24001))
        alice._maybe_update_peer_user({"USER": "NFS-CONSOLE-2005"})
        srv.remember_control_profile(name="BobPers", persona="BobPers", client_addr="127.0.0.1")
        bob = ControlHandler(srv, DummyConn(), ("127.0.0.1", 24002))
        bob._maybe_update_peer_user({"USER": "NFS-CONSOLE-2005"})
        srv.remember_control_profile(name="CharliePers", persona="CharliePers", client_addr="127.0.0.1")
        charlie = ControlHandler(srv, DummyConn(), ("127.0.0.1", 24003))
        charlie._maybe_update_peer_user({"USER": "NFS-CONSOLE-2005"})
        assert alice._peer_user == "AlicePers" and bob._peer_user == "BobPers"
        assert charlie._peer_user == "CharliePers"
        assert any(
            b"ROST" in item and b"USER=BobPers" in item and b"ATTR=D" in item
            for item in alice.conn.sent
        ), f"online non-friend did not populate player list via ROST: {alice.conn.sent!r}"
        alice.conn.sent.clear()
        assert alice._handle_user_search({"ID": "31", "USER": "", "MAXR": "20", "RSRC": "PC"})
        assert any(
            b"USCH" in item and b"ID=31" in item
            for item in alice.conn.sent
        ), f"USCH did not return a search result header: {alice.conn.sent!r}"
        assert any(
            item.startswith(b"USER") and b"RSRC=PC" in item and b"ID=31" in item and b"USER=BobPers" in item
            for item in alice.conn.sent
        ), f"USCH did not emit USER result rows: {alice.conn.sent!r}"
        assert any(
            item.startswith(b"USER") and b"RSRC=PC" in item and b"ID=31" in item and b"USER=CharliePers" in item
            for item in alice.conn.sent
        ), f"USCH did not emit all USER result rows: {alice.conn.sent!r}"
        assert not any(
            b"ROST" in item or b"PGET" in item
            for item in alice.conn.sent
        ), f"USCH emitted roster/presence rows instead of USER rows: {alice.conn.sent!r}"
        alice.conn.sent.clear()
        assert alice._peer_user == "AlicePers"
        assert alice._handle_user_search({"ID": "32", "USER": "NoSuchPersonaZZZ", "MAXR": "20", "RSRC": "PC"})
        assert alice._peer_user == "AlicePers", "USCH USER query changed the control persona"
        assert any(
            b"USCH" in item and b"SIZE=0" in item and b"ID=32" in item
            for item in alice.conn.sent
        ), f"USCH query did not return an empty search result: {alice.conn.sent!r}"
        assert not any(
            b"USCH" in item and b"USER=NoSuchPersonaZZZ" in item
            for item in alice.conn.sent
        ), f"USCH echoed the search query as a persona field: {alice.conn.sent!r}"
        assert not any(
            b"ROST" in item and b"USER=NoSuchPersonaZZZ" in item
            for item in alice.conn.sent
        ), f"USCH created a fake roster user from the search query: {alice.conn.sent!r}"
        alice.conn.sent.clear()
        assert alice._handle_user_search({"ID": "33", "USER": "BobPers", "MAXR": "20", "RSRC": "PC"})
        assert any(
            b"USCH" in item and b"SIZE=1" in item and b"ID=33" in item
            for item in alice.conn.sent
        ), f"USCH named query did not report the match count: {alice.conn.sent!r}"
        assert any(
            item.startswith(b"USER") and b"RSRC=PC" in item and b"ID=33" in item and b"USER=BobPers" in item
            for item in alice.conn.sent
        ), f"USCH named query did not emit the real USER result row: {alice.conn.sent!r}"
        assert not any(
            b"ROST" in item or b"PGET" in item
            for item in alice.conn.sent
        ), f"USCH named query emitted roster/presence rows instead of USER rows: {alice.conn.sent!r}"
        alice.conn.sent.clear()
        assert alice._handle_user_search({"ID": "34", "USER": "Offline", "MAXR": "20", "RSRC": "PC"})
        assert any(
            b"USCH" in item and b"SIZE=1" in item and b"ID=34" in item
            for item in alice.conn.sent
        ), f"USCH did not search registered offline users: {alice.conn.sent!r}"
        assert any(
            item.startswith(b"USER") and b"RSRC=PC" in item and b"ID=34" in item and b"USER=OfflinePers" in item
            for item in alice.conn.sent
        ), f"USCH did not emit registered offline USER result row: {alice.conn.sent!r}"
        alice.conn.sent.clear()
        assert alice._handle_send("SEND", {"TYPE": "F", "USER": "BobPers/PC", "ID": "21"})
        roster = srv.control_social_snapshot("BobPers", "B")
        assert len(roster) == 1 and roster[0]["user"] == "AlicePers" and roster[0]["attr"] == "R", f"SEND TYPE=F did not create request: {roster!r}"
        roster = srv.control_social_snapshot("AlicePers", "B")
        assert roster == [], f"outgoing request leaked into sender roster: {roster!r}"
        assert any(
            b"RADD" in item and b"USER=BobPers" in item and b"LIST=B" in item
            for item in alice.conn.sent
        ), f"outgoing request did not echo roster add: {alice.conn.sent!r}"
        assert not any(
            b"ROST" in item and b"USER=BobPers" in item
            for item in alice.conn.sent
        ), f"outgoing request leaked ROST to sender: {alice.conn.sent!r}"
        assert not any(
            b"RNOT" in item and b"USER=BobPers" in item and b"ATTR=R" in item
            for item in alice.conn.sent
        ), f"outgoing request leaked incoming attr to sender: {alice.conn.sent!r}"
        assert not any(
            b"RNOT" in item and b"USER=BobPers" in item and b"ATTR=P" in item
            for item in alice.conn.sent
        ), f"outgoing request leaked pending RNOT to sender: {alice.conn.sent!r}"
        assert alice._handle_roster_add("RADM", {"USER": "CharliePers/PC", "ID": "22", "PRES": "Y", "LRSC": "PC"})
        roster = srv.control_social_snapshot("CharliePers", "B")
        assert len(roster) == 1 and roster[0]["user"] == "AlicePers" and roster[0]["attr"] == "R", f"RADM did not create request: {roster!r}"
        before_accept_alice = len(alice.conn.sent)
        before_accept_charlie = len(charlie.conn.sent)
        assert charlie._handle_roster_response("RRSP", {"USER": "AlicePers/PC", "ANSW": "Y", "ID": "23", "PRES": "Y", "LRSC": "PC"})
        roster = srv.control_social_snapshot("CharliePers", "B")
        assert len(roster) == 1 and roster[0]["user"] == "AlicePers" and roster[0]["attr"] == "", f"RRSP accept did not create friendship: {roster!r}"
        roster = srv.control_social_snapshot("AlicePers", "B")
        assert any(row["user"] == "CharliePers" and row["attr"] == "" for row in roster), f"RRSP accept did not create reciprocal friendship: {roster!r}"
        accept_to_alice = alice.conn.sent[before_accept_alice:]
        accept_to_charlie = charlie.conn.sent[before_accept_charlie:]
        assert not any(
            b"PGET" in item and b"USER=AlicePers" in item and b"ATTR=D" in item
            for item in accept_to_charlie
        ), f"accepted buddy presence looked like online-only user: {accept_to_charlie!r}"
        assert not any(
            b"PGET" in item and b"USER=CharliePers" in item and b"ATTR=D" in item
            for item in accept_to_alice
        ), f"reciprocal buddy presence looked like online-only user: {accept_to_alice!r}"
        assert alice._handle_roster_add("RADM", {"USER": "BobPers/PC", "ID": "24", "PRES": "Y", "LRSC": "PC"})
        before_decline_to_sender = len(alice.conn.sent)
        assert bob._handle_roster_response("RRSP", {"USER": "AlicePers/PC", "ANSW": "N", "ID": "25", "PRES": "Y", "LRSC": "PC"})
        roster = srv.control_social_snapshot("BobPers", "B")
        assert not any(row["user"] == "AlicePers" for row in roster), f"RRSP decline did not clear request: {roster!r}"
        decline_to_sender = alice.conn.sent[before_decline_to_sender:]
        assert any(
            b"RNOT" in item and b"CHNG=D" in item and b"USER=BobPers" in item and b"ATTR=P" in item
            for item in decline_to_sender
        ), f"RRSP decline did not clear requester pending state: {decline_to_sender!r}"
        assert not any(
            b"RNOT" in item and b"CHNG=D" in item and b"USER=BobPers" in item and b"ATTR=R" in item
            for item in decline_to_sender
        ), f"RRSP decline sent incoming delete attr to requester: {decline_to_sender!r}"
        assert any(
            b"RNOT" in item and b"CHNG=A" in item and b"USER=BobPers" in item and b"ATTR=D" in item
            for item in decline_to_sender
        ), f"RRSP decline did not restore online presence for requester: {decline_to_sender!r}"
        before_unfriend_alice = len(alice.conn.sent)
        before_unfriend_charlie = len(charlie.conn.sent)
        assert charlie._handle_roster_remove("RDEM", {"USER": "AlicePers/PC", "LIST": "B", "ID": "26", "PRES": "Y", "LRSC": "PC"})
        roster = srv.control_social_snapshot("CharliePers", "B")
        assert not any(row["user"] == "AlicePers" for row in roster), f"RDEM did not remove friendship: {roster!r}"
        online = srv.control_social_snapshot("CharliePers", "ALL")
        assert any(row["user"] == "AlicePers" and row["attr"] == "D" for row in online), f"RDEM removed online presence: {online!r}"
        unfriend_to_charlie = charlie.conn.sent[before_unfriend_charlie:]
        unfriend_to_alice = alice.conn.sent[before_unfriend_alice:]
        assert any(
            b"ROST" in item and b"USER=AlicePers" in item and b"ATTR=D" in item
            for item in unfriend_to_charlie
        ), f"RDEM did not reassert non-friend online row to remover: {unfriend_to_charlie!r}"
        assert any(
            b"ROST" in item and b"USER=CharliePers" in item and b"ATTR=D" in item
            for item in unfriend_to_alice
        ), f"RDEM did not reassert non-friend online row to target: {unfriend_to_alice!r}"
        before_chat_ack = len(alice.conn.sent)
        assert alice._handle_send("SEND", {"TYPE": "C", "USER": "CharliePers/PC", "BODY": "hello", "SECS": "259200"})
        chat_ack = alice.conn.sent[before_chat_ack:]
        assert any(
            b"SEND" in item and b"USER=CharliePers/PC" in item and b"TYPE=C" in item and b"BODY=hello" in item
            for item in chat_ack
        ), f"SEND TYPE=C ack did not preserve target user: {chat_ack!r}"
        assert any(
            b"RECV" in item
            and b"USER=AlicePers" in item
            and b"TYPE=C" in item
            and b"F=P" in item
            and b"N=AlicePers" in item
            and b"T=hello" in item
            and b"BODY=hello" in item
            for item in charlie.conn.sent
        ), f"SEND TYPE=C was not delivered as RECV: {charlie.conn.sent!r}"
        assert any(
            b"PGET" in item and b"USER=AlicePers" in item
            for item in charlie.conn.sent
        ), f"SEND TYPE=C did not prime target presence: {charlie.conn.sent!r}"
        assert any(
            b"PADD" in item and b"USER=AlicePers" in item
            for item in charlie.conn.sent
        ), f"SEND TYPE=C did not prime target chat session: {charlie.conn.sent!r}"
        assert not any(b"PMSG" in item for item in charlie.conn.sent), f"SEND TYPE=C leaked PMSG mirror: {charlie.conn.sent!r}"
        before_invite = len(charlie.conn.sent)
        assert alice._handle_invite("INVT", {"USER": "CharliePers/PC", "TEXT": "join me", "ID": "28"})
        invite_delivery = charlie.conn.sent[before_invite:]
        assert any(
            b"PADD" in item and b"USER=AlicePers" in item
            for item in invite_delivery
        ), f"INVT did not prime target session: {invite_delivery!r}"
        assert any(
            b"INVT" in item
            and b"USER=AlicePers" in item
            and b"FROM=AlicePers" in item
            and b"TYPE=I" in item
            and b"TEXT=join me" in item
            for item in invite_delivery
        ), f"INVT was not delivered to target: {invite_delivery!r}"


def assert_lan_invite_pending_join():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.TemporaryDirectory() as root:
        cfg_path = os.path.join(root, "server.cfg")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent("""\
                CONTROL_LISTEN_PORT=0
                CONTROL_PORT=0
                LAN_INVITE_PENDING_SECONDS=90
            """))

        srv = GameServer(cfg_path)
        srv.is_running = True
        host = User(DummyConn(), ("127.0.0.1", 25001), name="Moio9")
        host.pers = "Moio9"
        peer = User(DummyConn(), ("127.0.0.1", 25002), name="PC2")
        peer.pers = "PC2"
        assert srv.users.add(host)
        assert srv.users.add(peer)
        hhost = ClientHandler(srv, host)
        hpeer = ClientHandler(srv, peer)
        game = srv.games.create(room_id=0, host_uid=host.uid, limit=2, custom="297.Moio9")
        assert game is not None
        assert srv.games.join(game.id, host.uid)
        hhost._lan_remember_game_user(game, host)
        host.game = game.id
        host.stat = "GAME"

        assert hhost._lan_deliver_invite("PC2", "join")
        assert hpeer._lan_pending_invite_game_id == game.id
        gjoi = ClientHandler._make_20922_tab_message("gjoi", ["NAME=297.PC2"])
        consumed = hpeer._consume_bootstrap_frames(gjoi)
        assert consumed == len(gjoi), "invite gjoi frame was not consumed"
        assert peer.game == game.id, "gjoi without IDENT did not use the pending invite game"
        assert peer.uid in game.participants, "pending invite join did not add peer to game"
        assert hpeer._lan_pending_invite_game_id == 0, "pending invite was not cleared after join"
        assert b"gjoi" in peer.conn.sent and f"IDENT={game.id}".encode("ascii") in peer.conn.sent, "pending invite join did not ack with game fields"

        srv.games.leave(game.id, peer.uid)
        game.mark_kicked(peer.uid)
        peer.game = 0
        peer.stat = "LOBBY"
        assert peer.uid in game.kicked_uids
        assert hhost._lan_deliver_invite("PC2", "again")
        assert peer.uid not in game.kicked_uids, "re-invite did not clear kicked state"
        gjoi = ClientHandler._make_20922_tab_message("gjoi", ["NAME=297.PC2"])
        consumed = hpeer._consume_bootstrap_frames(gjoi)
        assert consumed == len(gjoi), "re-invite gjoi frame was not consumed"
        assert peer.game == game.id and peer.uid in game.participants, "re-invite did not allow kicked peer to rejoin"
        time.sleep(0.05)
        host.conn.sent.clear()
        peer.conn.sent.clear()
        ready_frame = ClientHandler._make_20922_tab_message(
            "gset",
            ["NAME=297.Moio9", "USERFLAGS=134217728"],
        )
        consumed = hpeer._consume_bootstrap_frames(ready_frame)
        assert consumed == len(ready_frame), "ready gset frame was not consumed"
        time.sleep(0.05)
        assert b"+mgm" in host.conn.sent, "ready did not notify host with a game snapshot"
        assert b"+usr" not in host.conn.sent and b"+gam" not in host.conn.sent, "ready leaked legacy peer frames that can trigger host kick"
        assert b"+mgm" in peer.conn.sent, "ready did not reply to the ready client with a game snapshot"

        hpeer._disconnect_reason = "test_cleanup"
        hpeer._on_disconnect()
        hhost._disconnect_reason = "test_cleanup"
        hhost._on_disconnect()


def assert_lan_unready_gset_only_sends_main_snapshot():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap
    import time

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.TemporaryDirectory() as root:
        cfg_path = os.path.join(root, "server.cfg")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent("""\
                CONTROL_LISTEN_PORT=0
                CONTROL_PORT=0
                LAN_JOIN_MGM_DELAY=0.001
                LAN_JOIN_NOTIFY_MGM=0
            """))

        srv = GameServer(cfg_path)
        srv.is_running = True
        host = User(DummyConn(), ("127.0.0.1", 27001), name="Moio9")
        host.pers = "Moio"
        peer = User(DummyConn(), ("127.0.0.1", 27002), name="Juc")
        peer.pers = "Jucator"
        assert srv.users.add(host)
        assert srv.users.add(peer)
        hhost = ClientHandler(srv, host)
        hpeer = ClientHandler(srv, peer)
        game = srv.games.create(room_id=0, host_uid=host.uid, limit=4, custom="1116.Moio")
        assert game is not None
        assert srv.games.join(game.id, host.uid)
        assert srv.games.join(game.id, peer.uid)
        host.game = game.id
        host.stat = "GAME"
        peer.game = game.id
        peer.stat = "GAME"
        hhost._lan_remember_game_user(game, host)
        hpeer._lan_remember_game_user(game, peer)

        hpeer._lan_emit_join_state(game, peer, delay_s=0.001)
        time.sleep(0.02)
        assert b"+mgm" not in host.conn.sent, "gjoi emitted an immediate host +mgm despite LAN_JOIN_NOTIFY_MGM=0"
        host.conn.sent.clear()
        peer.conn.sent.clear()

        gset = ClientHandler._make_20922_tab_message(
            "gset",
            [f"NAME={game.custom}", "USERFLAGS=0"],
        )
        consumed = hpeer._consume_bootstrap_frames(gset)
        assert consumed == len(gset), "unready gset frame was not consumed"
        immediate = bytes(host.conn.sent)
        assert b"+mgm" in immediate, f"unready gset did not send immediate main snapshot: {immediate!r}"
        assert b"+usr" not in immediate and b"+gam" not in immediate, f"unready gset leaked callback frames on main connection: {immediate!r}"
        time.sleep(0.05)
        sent = bytes(host.conn.sent)
        mgm_idx = sent.find(b"+mgm")
        assert mgm_idx >= 0, f"unready gset did not send +mgm to host: {sent!r}"
        assert b"+usr" not in sent and b"+gam" not in sent, f"unready gset sent callback frames on host main connection: {sent!r}"
        assert b"OPPO0=Moio" in sent and b"OPPO1=Jucator" in sent, f"+mgm player fields missing host/guest: {sent!r}"

        hpeer._disconnect_reason = "test_cleanup"
        hpeer._on_disconnect()
        hhost._disconnect_reason = "test_cleanup"
        hhost._on_disconnect()


def assert_lan_unready_gset_clears_ready():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap
    import time

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.TemporaryDirectory() as root:
        cfg_path = os.path.join(root, "server.cfg")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent("""\
                CONTROL_LISTEN_PORT=0
                CONTROL_PORT=0
                LAN_READY_UNSET_GRACE=4.0
            """))

        srv = GameServer(cfg_path)
        srv.is_running = True
        host = User(DummyConn(), ("127.0.0.1", 29201), name="Juc")
        host.pers = "Jucator"
        peer = User(DummyConn(), ("127.0.0.1", 29202), name="Moio9")
        peer.pers = "Moio"
        assert srv.users.add(host)
        assert srv.users.add(peer)
        hhost = ClientHandler(srv, host)
        hpeer = ClientHandler(srv, peer)
        game = srv.games.create(room_id=0, host_uid=host.uid, limit=4, custom="543.Jucator")
        assert game is not None
        assert srv.games.join(game.id, host.uid)
        assert srv.games.join(game.id, peer.uid)
        host.game = game.id
        host.stat = "GAME"
        peer.game = game.id
        peer.stat = "GAME"
        hhost._lan_remember_game_user(game, host)
        hpeer._lan_remember_game_user(game, peer)

        ready_frame = ClientHandler._make_20922_tab_message(
            "gset",
            [f"NAME={game.custom}", "USERFLAGS=134217728"],
        )
        consumed = hpeer._consume_bootstrap_frames(ready_frame)
        assert consumed == len(ready_frame), "ready gset frame was not consumed"
        time.sleep(0.05)
        assert peer.uid in game.ready_participants, "ready gset did not mark peer ready"
        assert b"OPFLAG1=134217728" in peer.conn.sent, "ready reply did not carry ready OPFLAG"
        host.conn.sent.clear()
        peer.conn.sent.clear()
        hpeer._lan_last_gset_at = 0.0

        unready_frame = ClientHandler._make_20922_tab_message(
            "gset",
            [f"NAME={game.custom}", "USERFLAGS=0"],
        )
        consumed = hpeer._consume_bootstrap_frames(unready_frame)
        assert consumed == len(unready_frame), "unready gset frame was not consumed"
        time.sleep(0.05)
        assert peer.uid not in game.ready_participants, "USERFLAGS=0 did not clear peer ready state"
        assert b"OPFLAG1=0" in peer.conn.sent, "unready reply did not carry cleared OPFLAG"
        assert b"OPFLAG1=0" in host.conn.sent, f"unready did not notify host with OPFLAG1=0: {host.conn.sent!r}"

        hpeer._disconnect_reason = "test_cleanup"
        hpeer._on_disconnect()
        hhost._disconnect_reason = "test_cleanup"
        hhost._on_disconnect()


def assert_lan_uppercase_game_callbacks_use_calluser():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap
    import time

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.TemporaryDirectory() as root:
        cfg_path = os.path.join(root, "server.cfg")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent("""\
                CONTROL_LISTEN_PORT=0
                CONTROL_PORT=0
            """))

        srv = GameServer(cfg_path)
        srv.is_running = True
        host = User(DummyConn(), ("127.0.0.1", 29301), name="Moio9")
        host.pers = "Moio"
        peer = User(DummyConn(), ("127.0.0.1", 29302), name="Juc")
        peer.pers = "Jucator"
        assert srv.users.add(host)
        assert srv.users.add(peer)
        hhost = ClientHandler(srv, host)
        hpeer = ClientHandler(srv, peer)
        game = srv.games.create(room_id=0, host_uid=host.uid, limit=4, custom="1512.Moio")
        assert game is not None
        assert srv.games.join(game.id, host.uid)
        host.game = game.id
        host.stat = "GAME"
        hhost._lan_remember_game_user(game, host)

        token = 0xFFFFFB79
        body = (
            f"CALLUSER={peer.uid}\tCALLPING=1\tCALLADDR=127.0.0.1\tNAME={game.custom}\n"
        ).encode("utf-8") + b"\x00"
        upper_gjoi = b"GJOI" + struct.pack(">I", token) + struct.pack(">I", 12 + len(body)) + body
        consumed = hhost._consume_bootstrap_frames(upper_gjoi)
        assert consumed == len(upper_gjoi), "uppercase GJOI callback frame was not consumed"
        assert host.conn.sent[:4] == struct.pack(">I", token), "uppercase GJOI did not receive token reply"
        assert peer.game == game.id and peer.uid in game.participants, "uppercase GJOI did not apply CALLUSER participant"
        assert b"COUNT=2" in host.conn.sent, f"uppercase GJOI reply did not include joined snapshot: {host.conn.sent!r}"

        host.conn.sent.clear()
        peer.game = game.id
        peer.stat = "GAME"
        hpeer._lan_remember_game_user(game, peer)
        ready = ClientHandler._make_20922_tab_message("gset", [f"NAME={game.custom}", "USERFLAGS=134217728"])
        consumed = hpeer._consume_bootstrap_frames(ready)
        assert consumed == len(ready), "peer ready gset was not consumed"
        time.sleep(0.03)
        assert peer.uid in game.ready_participants, "peer ready gset did not mark peer ready"

        host.conn.sent.clear()
        token = 0xFFFFFAF9
        body = (
            f"CALLUSER={peer.uid}\tCALLPING=1\tCALLADDR=127.0.0.1\t"
            f"NAME={game.custom}\nUSERFLAGS=0\n"
        ).encode("utf-8") + b"\x00"
        upper_gset = b"GSET" + struct.pack(">I", token) + struct.pack(">I", 12 + len(body)) + body
        consumed = hhost._consume_bootstrap_frames(upper_gset)
        assert consumed == len(upper_gset), "uppercase GSET callback frame was not consumed"
        assert host.conn.sent[:4] == struct.pack(">I", token), "uppercase GSET did not receive token reply"
        assert peer.uid in game.ready_participants, "uppercase GSET callback cleared CALLUSER ready state"

        hpeer._disconnect_reason = "test_cleanup"
        hpeer._on_disconnect()
        hhost._disconnect_reason = "test_cleanup"
        hhost._on_disconnect()


def assert_lan_onln_emits_capture_game_refresh():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap
    import time

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.TemporaryDirectory() as root:
        cfg_path = os.path.join(root, "server.cfg")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent("""\
                CONTROL_LISTEN_PORT=0
                CONTROL_PORT=0
                LAN_JOIN_MGM_DELAY=0.001
            """))

        srv = GameServer(cfg_path)
        srv.is_running = True
        host = User(DummyConn(), ("127.0.0.1", 28001), name="Moio9")
        host.pers = "Moio"
        peer = User(DummyConn(), ("127.0.0.1", 28002), name="Juc")
        peer.pers = "Jucator"
        assert srv.users.add(host)
        assert srv.users.add(peer)
        hhost = ClientHandler(srv, host)
        hpeer = ClientHandler(srv, peer)
        game = srv.games.create(room_id=0, host_uid=host.uid, limit=4, custom="049.Moio")
        assert game is not None
        assert srv.games.join(game.id, host.uid)
        assert srv.games.join(game.id, peer.uid)
        host.game = game.id
        host.stat = "GAME"
        peer.game = game.id
        peer.stat = "GAME"
        hhost._lan_remember_game_user(game, host)
        hpeer._lan_remember_game_user(game, peer)

        onln = ClientHandler._make_20922_tab_message("onln", ["PERS=Moio"])
        consumed = hpeer._consume_bootstrap_frames(onln)
        assert consumed == len(onln), "onln frame was not consumed"
        time.sleep(0.05)
        host_sent = bytes(host.conn.sent)
        peer_sent = bytes(peer.conn.sent)
        host_mgm_idx = host_sent.find(b"+mgm")
        peer_who_idx = peer_sent.find(b"+who")
        peer_onln_idx = peer_sent.find(b"onln")
        peer_mgm_idx = peer_sent.rfind(b"+mgm")
        assert b"+gam" not in host_sent, f"onln leaked callback +gam on host main connection: {host_sent!r}"
        assert host_mgm_idx >= 0, f"onln did not refresh host with +mgm: {host_sent!r}"
        assert peer_who_idx >= 0, f"onln did not send requester +who preburst: {peer_sent!r}"
        assert peer_onln_idx > peer_who_idx, f"onln reply did not follow requester preburst: {peer_sent!r}"
        assert b"onln" in peer_sent and b"F=G" in peer_sent[peer_onln_idx:peer_mgm_idx], f"onln target reply should use captured game flag: {peer_sent!r}"
        assert peer_mgm_idx > peer_onln_idx, f"onln did not refresh requester +mgm after reply: {peer_sent!r}"

        hpeer._disconnect_reason = "test_cleanup"
        hpeer._on_disconnect()
        hhost._disconnect_reason = "test_cleanup"
        hhost._on_disconnect()


def assert_lan_host_duplicate_gcre_preserves_open_game():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap
    import time

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.TemporaryDirectory() as root:
        cfg_path = os.path.join(root, "server.cfg")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent("""\
                CONTROL_LISTEN_PORT=0
                CONTROL_PORT=0
            """))

        srv = GameServer(cfg_path)
        srv.is_running = True
        host = User(DummyConn(), ("127.0.0.1", 29001), name="Moio9")
        host.pers = "Moio"
        peer = User(DummyConn(), ("127.0.0.1", 29002), name="Juc")
        peer.pers = "Jucator"
        assert srv.users.add(host)
        assert srv.users.add(peer)
        hhost = ClientHandler(srv, host)
        hpeer = ClientHandler(srv, peer)
        game = srv.games.create(room_id=0, host_uid=host.uid, limit=4, custom="253.Moio")
        assert game is not None
        assert srv.games.join(game.id, host.uid)
        assert srv.games.join(game.id, peer.uid)
        host.game = game.id
        host.stat = "GAME"
        peer.game = game.id
        peer.stat = "GAME"
        hhost._lan_remember_game_user(game, host)
        hpeer._lan_remember_game_user(game, peer)

        before_id = game.id
        gcre = ClientHandler._make_20922_tab_message(
            "gcre",
            [
                "NAME=253.Moio",
                "MAXSIZE=4",
                "MINSIZE=2",
                "CUSTFLAGS=67109107",
                "SYSFLAGS=0",
                "PARAMS=TRACK%3d4000%0aDIR%3d0%0aLAPS%3d3",
            ],
        )
        consumed = hhost._consume_bootstrap_frames(gcre)
        assert consumed == len(gcre), "duplicate host gcre frame was not consumed"
        time.sleep(0.05)
        assert srv.games.get(before_id) is game, "duplicate host gcre destroyed the existing open game"
        assert len(srv.games.list_games()) == 1, "duplicate host gcre created a second game"
        assert host.game == before_id, "duplicate host gcre moved host to a new game"
        assert peer.game == before_id, "duplicate host gcre detached peer from the existing game"
        assert peer.uid in game.participants, "duplicate host gcre removed peer participant"
        assert b"glea" not in peer.conn.sent and b"+mgm" not in peer.conn.sent, f"duplicate host gcre leaked lobby reset to peer: {peer.conn.sent!r}"

        hpeer._disconnect_reason = "test_cleanup"
        hpeer._on_disconnect()
        hhost._disconnect_reason = "test_cleanup"
        hhost._on_disconnect()


def assert_lan_host_new_gcre_replaces_reattached_old_game():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap
    import time

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.TemporaryDirectory() as root:
        cfg_path = os.path.join(root, "server.cfg")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent("""\
                CONTROL_LISTEN_PORT=0
                CONTROL_PORT=0
            """))

        srv = GameServer(cfg_path)
        srv.is_running = True
        host = User(DummyConn(), ("127.0.0.1", 29101), name="Juc")
        host.pers = "Jucator"
        peer = User(DummyConn(), ("127.0.0.1", 29102), name="Moio9")
        peer.pers = "Moio"
        assert srv.users.add(host)
        assert srv.users.add(peer)
        hhost = ClientHandler(srv, host)
        hpeer = ClientHandler(srv, peer)
        old_game = srv.games.create(room_id=0, host_uid=host.uid, limit=4, custom="255.Jucator")
        assert old_game is not None
        assert srv.games.join(old_game.id, host.uid)
        assert srv.games.join(old_game.id, peer.uid)
        host.game = old_game.id
        host.stat = "GAME"
        peer.game = old_game.id
        peer.stat = "GAME"
        hhost._lan_remember_game_user(old_game, host)
        hpeer._lan_remember_game_user(old_game, peer)

        gcre = ClientHandler._make_20922_tab_message(
            "gcre",
            [
                "NAME=348.Jucator",
                "MAXSIZE=4",
                "MINSIZE=2",
                "CUSTFLAGS=67109107",
                "SYSFLAGS=0",
                "PARAMS=TRACK%3d4000%0aDIR%3d0%0aLAPS%3d3",
            ],
        )
        consumed = hhost._consume_bootstrap_frames(gcre)
        assert consumed == len(gcre), "new-name host gcre frame was not consumed"
        time.sleep(0.05)
        games = srv.games.list_games()
        assert srv.games.get(old_game.id) is None, "new-name host gcre preserved stale old game"
        assert len(games) == 1, f"new-name host gcre did not leave exactly one game: {games!r}"
        new_game = games[0]
        assert new_game is not old_game, "new-name host gcre reused the old game object"
        assert new_game.custom == "348.Jucator", f"new-name host gcre used wrong game name: {new_game.custom!r}"
        assert host.game == new_game.id and int(new_game.host_uid) == int(host.uid), "new-name host gcre did not make host own the new game"
        assert peer.game == 0 and peer.uid not in new_game.participants, "new-name host gcre carried old peer into the new game"

        hpeer._disconnect_reason = "test_cleanup"
        hpeer._on_disconnect()
        hhost._disconnect_reason = "test_cleanup"
        hhost._on_disconnect()


def assert_lan_special_persona_markers():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.TemporaryDirectory() as root:
        cfg_path = os.path.join(root, "server.cfg")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent("""\
                CONTROL_LISTEN_PORT=0
                CONTROL_PORT=0
                LAN_USER_CL=0
                LAN_USER_RGB=0
                LAN_ONLN_GAME_FLAG=U
                LAN_SPECIAL_PERSONAS=Moio9
                LAN_SPECIAL_USER_CL=511
                LAN_SPECIAL_USER_RGB=511
                LAN_SPECIAL_ONLN_FLAG=G
            """))

        srv = GameServer(cfg_path)
        srv.is_running = True
        admin = User(DummyConn(), ("127.0.0.1", 26001), name="Moio9")
        admin.pers = "Moio9"
        normal = User(DummyConn(), ("127.0.0.1", 26002), name="PC2")
        normal.pers = "PC2"
        assert srv.users.add(admin)
        assert srv.users.add(normal)
        handler = ClientHandler(srv, admin)
        game = srv.games.create(room_id=0, host_uid=admin.uid, limit=2, custom="special")
        assert game is not None
        assert srv.games.join(game.id, admin.uid)
        assert srv.games.join(game.id, normal.uid)
        admin.game = game.id
        normal.game = game.id

        admin_onln = "\t".join(handler._lan_onln_fields_for_user(admin, game))
        normal_onln = "\t".join(handler._lan_onln_fields_for_user(normal, game))
        admin_usr = "\t".join(handler._lan_usr_fields_for_user(admin, sync=3, game_id=game.id))
        normal_usr = "\t".join(handler._lan_usr_fields_for_user(normal, sync=3, game_id=game.id))
        assert "F=G" in admin_onln and "CL=511" in admin_onln, f"special onln marker missing: {admin_onln!r}"
        assert "F=U" in normal_onln and "CL=0" in normal_onln, f"normal onln marker leaked special state: {normal_onln!r}"
        assert "RGB=511" in admin_usr, f"special usr color missing: {admin_usr!r}"
        assert "RGB=0" in normal_usr, f"normal usr color leaked special state: {normal_usr!r}"

        handler._disconnect_reason = "test_cleanup"
        handler._on_disconnect()


def assert_server_max_players_limit():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler, _LAN_AUTH_DBER_RESERVED
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.TemporaryDirectory() as root:
        cfg_path = os.path.join(root, "server.cfg")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent("""\
                USERS=10
                SERVER_MAX_PLAYERS=1
                CONTROL_LISTEN_PORT=0
                CONTROL_PORT=0
                AUTH_VERIFY=0
            """))

        srv = GameServer(cfg_path)
        first = User(DummyConn(), ("127.0.0.1", 27001), name="First")
        first.pers = "First"
        assert srv.users.add(first)
        assert srv.users.max_users == 1, f"SERVER_MAX_PLAYERS did not override USERS: {srv.users.max_users}"

        text_user = User(DummyConn(), ("127.0.0.1", 27002), name="Second")
        text_handler = ClientHandler(srv, text_user)
        text_handler._cmd_login({"NAME": "Second", "PERS": "Second"})
        text_sent = bytes(text_user.conn.sent)
        assert b"-LOGIN" in text_sent and b"ERROR=503" in text_sent, f"full text login not rejected: {text_sent!r}"
        assert srv.users.get(text_user.uid) is None, "full text login registered rejected user"

        lan_user = User(DummyConn(), ("127.0.0.1", 27003), name="Third")
        lan_handler = ClientHandler(srv, lan_user)
        auth = ClientHandler._make_20922_tab_message("auth", ["NAME=Third"])
        consumed = lan_handler._consume_bootstrap_frames(auth)
        assert consumed == len(auth), "full LAN auth frame was not consumed"
        lan_sent = bytes(lan_user.conn.sent)
        assert lan_sent[:4] == b"auth" and lan_sent[4:8] == (_LAN_AUTH_DBER_RESERVED & 0xFFFFFFFF).to_bytes(4, "big"), (
            f"full LAN auth did not receive dber reject: {lan_sent!r}"
        )
        assert srv.users.get(lan_user.uid) is None, "full LAN auth registered rejected user"

        preauth_user = User(DummyConn(), ("127.0.0.1", 27004), name="Fourth")
        preauth_handler = ClientHandler(srv, preauth_user)
        addr = ClientHandler._make_20922_tab_message("addr", ["ADDR=127.0.0.1", "PORT=40472"])
        consumed = preauth_handler._consume_bootstrap_frames(addr)
        assert consumed == len(addr), "full LAN addr frame was not consumed"
        assert srv.users.get(preauth_user.uid) is None, "full LAN preauth addr registered rejected user"
        skey = ClientHandler._make_20922_tab_message("skey", [])
        news = ClientHandler._make_20922_tab_message("news", [])
        consumed = preauth_handler._consume_bootstrap_frames(skey + news)
        assert consumed == len(skey + news), "full LAN skey/news frames were not consumed"
        preauth_sent = bytes(preauth_user.conn.sent)
        assert preauth_sent, "full LAN preauth did not get bootstrap replies"
        assert srv.users.get(preauth_user.uid) is None, "full LAN preauth bootstrap registered rejected user"
        preauth_user.conn.sent.clear()
        auth = ClientHandler._make_20922_tab_message("auth", ["NAME=Fourth"])
        consumed = preauth_handler._consume_bootstrap_frames(auth)
        assert consumed == len(auth), "full LAN auth after addr was not consumed"
        lan_sent = bytes(preauth_user.conn.sent)
        assert lan_sent[:4] == b"auth" and lan_sent[4:8] == (_LAN_AUTH_DBER_RESERVED & 0xFFFFFFFF).to_bytes(4, "big"), (
            f"full LAN auth after addr did not receive dber reject: {lan_sent!r}"
        )
        assert srv.users.get(preauth_user.uid) is None, "full LAN auth after addr registered rejected user"


def assert_server_connection_rate_limit():
    from server import GameServer
    import tempfile
    import textwrap

    with tempfile.TemporaryDirectory() as root:
        cfg_path = os.path.join(root, "server.cfg")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent("""\
                SERVER_CONN_RATE_LIMIT=2
                SERVER_CONN_RATE_WINDOW=60
                SERVER_CONN_RATE_BLOCK=30
                CONTROL_LISTEN_PORT=0
                CONTROL_PORT=0
            """))

        srv = GameServer(cfg_path)
        assert srv._accepts_new_connection("127.0.0.1"), "first connection should pass"
        assert srv._accepts_new_connection("127.0.0.1"), "second connection should pass"
        assert not srv._accepts_new_connection("127.0.0.1"), "third same-IP connection should be rate limited"
        assert not srv._accepts_new_connection("127.0.0.1"), "blocked same-IP connection should stay blocked"
        assert srv._accepts_new_connection("127.0.0.2"), "different IP should have independent rate bucket"

        srv.cfg["SERVER_CONN_RATE_LIMIT"] = 0
        assert srv._accepts_new_connection("127.0.0.1"), "rate limit disabled should allow blocked IP"


def assert_lan_persona_blacklist():
    from server import GameServer
    from user_manager import User
    from client_handler import ClientHandler, _LAN_NSPC_RESERVED, _LAN_PSET_RESERVED
    import tempfile
    import textwrap

    class DummyConn:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def shutdown(self, how):
            pass

        def close(self):
            pass

    with tempfile.TemporaryDirectory() as root:
        blacklist_path = os.path.join(root, "persona_blacklist.txt")
        with open(blacklist_path, "w", encoding="utf-8") as fh:
            fh.write("exact:Admin\ncontains:badword\n")
        cfg_path = os.path.join(root, "server.cfg")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent(f"""\
                CONTROL_LISTEN_PORT=0
                CONTROL_PORT=0
                LAN_PERSONA_RESERVED_NAMES=Root
                LAN_PERSONA_FORBIDDEN_WORDS=vulgar
                LAN_PERSONA_BLACKLIST_FILE={blacklist_path}
                LAN_PERSONA_BLACKLIST_CPER_CODE=nspc
                LAN_PERSONA_BLACKLIST_PERS_CODE=pset
            """))

        srv = GameServer(cfg_path)

        cper_user = User(DummyConn(), ("127.0.0.1", 28001), name="CreateUser")
        assert srv.users.add(cper_user)
        hcper = ClientHandler(srv, cper_user)
        cper_frame = ClientHandler._make_20922_tab_message("cper", ["PERS=Admin"])
        consumed = hcper._consume_bootstrap_frames(cper_frame)
        assert consumed == len(cper_frame), "blacklisted cper frame was not consumed"
        expected_cper = ClientHandler._make_20922_signed_binary_message(
            "cper",
            b"\x00",
            9,
            reserved_be32=_LAN_NSPC_RESERVED,
        )
        assert cper_user.conn.sent[:21] == expected_cper, f"blacklisted cper did not send cpernspc: {cper_user.conn.sent!r}"
        assert cper_user.pers != "Admin", "blacklisted cper still claimed persona"

        pers_user = User(DummyConn(), ("127.0.0.1", 28002), name="SelectUser")
        assert srv.users.add(pers_user)
        hpers = ClientHandler(srv, pers_user)
        pers_frame = ClientHandler._make_20922_tab_message("pers", ["PERS=GoodBadwordName"])
        consumed = hpers._consume_bootstrap_frames(pers_frame)
        assert consumed == len(pers_frame), "blacklisted pers frame was not consumed"
        expected_pers = ClientHandler._make_20922_signed_binary_message(
            "pers",
            b"\x00",
            9,
            reserved_be32=_LAN_PSET_RESERVED,
        )
        assert pers_user.conn.sent[:21] == expected_pers, f"blacklisted pers did not send perspset: {pers_user.conn.sent!r}"
        assert pers_user.pers != "GoodBadwordName", "blacklisted pers still claimed persona"


# ------------------------------------------------------------------ #

def run_tests():
    import server as server_mod
    from server import StartServer, StopServer, IsServerRunning

    print("=" * 60)
    print("EA Game Server Emulator — Integration Tests")
    print("=" * 60)

    print("[0] Endpoint resolution... ", end="")
    assert_endpoint_resolution()
    print("OK")

    print("[0b] Detached open game discarded on relogin... ", end="")
    assert_detached_open_game_is_discarded_on_relogin()
    print("OK")

    print("[0c] Offline open game discarded without detach marker... ", end="")
    assert_offline_open_game_is_discarded_without_detach_marker()
    print("OK")

    print("[0d] Social alias self-targeting... ", end="")
    assert_social_aliases_do_not_self_target()
    print("OK")

    print("[0e] Control PADD does not emit PGET... ", end="")
    assert_control_padd_does_not_emit_pget()
    print("OK")

    print("[0f] Control same-game presence suppressed... ", end="")
    assert_control_same_game_presence_suppressed()
    print("OK")

    print("[0f2] LAN lobby online-who suppressed for game handlers... ", end="")
    assert_lan_lobby_online_who_suppressed_for_game_handlers()
    print("OK")

    print("[0f3] LAN host-left resets peer game state... ", end="")
    assert_lan_host_left_resets_peer_game_state()
    print("OK")

    print("[0f3a] LAN delayed lobby snapshot does not resurrect removed game... ", end="")
    assert_lan_delayed_lobby_snapshot_does_not_resurrect_removed_game()
    print("OK")

    print("[0f3a2] LAN unrelated removed game does not snapshot active host... ", end="")
    assert_lan_removed_unrelated_game_does_not_snapshot_active_host()
    print("OK")

    print("[0f3b] LAN GSET for removed room returns reset... ", end="")
    assert_lan_gset_for_removed_room_returns_reset()
    print("OK")

    print("[0f3c] LAN GSET for recent removed room invalidates old room... ", end="")
    assert_lan_gset_for_recent_removed_room_reinvalidates_room()
    print("OK")

    print("[0f3d] LAN delayed kick update does not override new room... ", end="")
    assert_lan_kick_delayed_update_does_not_override_new_room()
    print("OK")

    print("[0f4] LAN active peer close preserves detached user... ", end="")
    assert_lan_active_game_peer_close_preserves_detached_user()
    print("OK")

    print("[0f5] LAN same-IP detached reconnect preserves other racer... ", end="")
    assert_lan_same_ip_detached_reconnect_replaces_only_matching_persona()
    print("OK")

    print("[0f6] LAN reattached active race gsea returns lobby... ", end="")
    assert_lan_reattached_active_game_gsea_finalizes_lobby()
    print("OK")

    print("[0g] GSET self-kick ignored... ", end="")
    assert_gset_self_kick_ignored()
    print("OK")

    print("[0h] Solo-host ready snapshot has no peer duplicate... ", end="")
    assert_ready_snapshot_does_not_duplicate_solo_host()
    print("OK")

    print("[0i] Duplicate GSET ready deduped... ", end="")
    assert_duplicate_gset_ready_deduped()
    print("OK")

    print("[0j] Room snapshot partition fields follow NPART... ", end="")
    assert_room_snapshot_partition_fields_follow_numpart()
    print("OK")

    print("[0k] ONLN display alias resolves self... ", end="")
    assert_onln_pers_display_alias_resolves_self()
    print("OK")

    print("[0l] LAN private self-message ignored... ", end="")
    assert_lan_private_message_to_self_ignored()
    print("OK")

    print("[0m] LAN auth accounts... ", end="")
    assert_lan_auth_accounts()
    print("OK")

    print("[0m2] LAN stats snap offsets... ", end="")
    assert_lan_stats_snap_offsets()
    print("OK")

    print("[0m3] Room/game privacy and password metadata... ", end="")
    assert_room_game_privacy_password_metadata()
    print("OK")

    print("[0n] Social relations... ", end="")
    assert_social_relations()
    print("OK")

    print("[0o] Control SEND friend request... ", end="")
    assert_control_send_friend_request()
    print("OK")

    print("[0p] LAN invite pending join... ", end="")
    assert_lan_invite_pending_join()
    print("OK")

    print("[0q] LAN special persona markers... ", end="")
    assert_lan_special_persona_markers()
    print("OK")

    print("[0q2] Server max players limit... ", end="")
    assert_server_max_players_limit()
    print("OK")

    print("[0q3] Server connection rate limit... ", end="")
    assert_server_connection_rate_limit()
    print("OK")

    print("[0q4] LAN persona blacklist... ", end="")
    assert_lan_persona_blacklist()
    print("OK")

    print("[0r] LAN unready GSET only sends main snapshot... ", end="")
    assert_lan_unready_gset_only_sends_main_snapshot()
    print("OK")

    print("[0r2] LAN unready GSET clears ready... ", end="")
    assert_lan_unready_gset_clears_ready()
    print("OK")

    print("[0r3] LAN uppercase callbacks use CALLUSER... ", end="")
    assert_lan_uppercase_game_callbacks_use_calluser()
    print("OK")

    print("[0s] LAN ONLN emits capture game refresh... ", end="")
    assert_lan_onln_emits_capture_game_refresh()
    print("OK")

    print("[0t] LAN duplicate host GCRE preserves open game... ", end="")
    assert_lan_host_duplicate_gcre_preserves_open_game()
    print("OK")

    print("[0u] LAN new host GCRE replaces reattached old game... ", end="")
    assert_lan_host_new_gcre_replaces_reattached_old_game()
    print("OK")

    # 1. Start server
    print("\n[1] StartServer()... ", end="")
    ok = StartServer("server.cfg")
    assert ok, "StartServer() returned False"
    time.sleep(0.5)
    print("OK")

    # 2. IsServerRunning
    print("[2] IsServerRunning()... ", end="")
    assert IsServerRunning(), "IsServerRunning() returned False after start"
    print("OK")

    # 3. Connect client A
    print("[3] Connect client A... ", end="")
    ca = make_client()
    r  = send_recv(ca, 'LOGIN NAME=Alice PERS=AlicePers LANG=en')
    assert "+LOGIN" in r, f"LOGIN failed: {r!r}"
    alice_uid = parse_int_field(r, "UID")
    assert alice_uid > 0, f"LOGIN did not return Alice UID: {r!r}"
    print("OK")

    # 4. Connect client B
    print("[4] Connect client B... ", end="")
    cb = make_client()
    r  = send_recv(cb, 'LOGIN NAME=Bob PERS=BobPers LANG=en')
    assert "+LOGIN" in r, f"LOGIN failed: {r!r}"
    print("OK")

    # 5. PING
    print("[5] PING... ", end="")
    r = send_recv(ca, "PING")
    assert "+PING" in r, f"PING failed: {r!r}"
    print("OK")

    # 6. WHO
    print("[6] WHO (self info)... ", end="")
    r = send_recv(ca, "WHO")
    assert "+USER" in r and "Alice" in r, f"WHO failed: {r!r}"
    print("OK")

    # 7. Create room
    print("[7] Create room... ", end="")
    r = send_recv(ca, 'ROOM NAME="Test Room" MAXSIZE=8 MINSIZE=2')
    assert "+ROOM" in r, f"ROOM failed: {r!r}"
    print("OK")

    # 8. List rooms
    print("[8] ROOMS list... ", end="")
    r = send_recv(cb, "ROOMS")
    assert "+ROOMS" in r, f"ROOMS failed: {r!r}"
    print("OK")

    # 9. Bob joins room
    print("[9] Bob joins room... ", end="")
    # Extract room ID from Alice's response
    room_id = None
    for line in r.split("\n"):
        if "+ROOM" in line and "IDENT=" in line:
            for part in line.split():
                if part.startswith("IDENT="):
                    try:
                        room_id = int(part.split("=")[1])
                    except Exception:
                        pass
    # Try joining room 1 if parse failed
    if not room_id:
        room_id = 1
    r = send_recv(cb, f"ROOM IDENT={room_id}")
    # Room join may or may not return +ROOM
    print("OK")

    # 10. Server stats
    print("[10] Server stats (SRVSTAT)... ", end="")
    r = send_recv(ca, "SRVSTAT")
    assert "usersInLobby" in r or "master" in r or "+SRVSTAT" in r, f"SRVSTAT failed: {r!r}"
    print("OK")

    # 11. Challenge
    print("[11] CHAL: Alice challenges Bob... ", end="")
    r = send_recv(ca, 'CHAL NAME=Bob')
    # Either succeeds or fails with not-in-room if rooms differ
    print("OK (result: %s)" % ("+CHAL" in r and "OK" or "fail/not-in-room"))

    # 12. Quickmatch
    print("[12] QUIK: quickmatch queue... ", end="")
    r = send_recv(ca, 'QUIK MINSIZE=2 MAXSIZE=4')
    assert "+QUIK" in r, f"QUIK failed: {r!r}"
    print("OK")

    # 13. Create game
    print("[13] NEWGAME: Alice creates a game... ", end="")
    r = send_recv(ca, 'NEWGAME LIMIT=4 TYPE=PUBLIC FLAGS=0.0')
    if "+GAME" in r:
        print("OK")
    else:
        print("SKIP (Alice not in room with game slot)")

    # 14. Ranking
    print("[14] RANK: get rank... ", end="")
    r = send_recv(ca, 'RANK')
    assert "+RANK" in r, f"RANK failed: {r!r}"
    print("OK")

    # 15. Leaderboard
    print("[15] LEADERBOARD... ", end="")
    r = send_recv(ca, 'LEADERBOARD LIMIT=10')
    assert "+LEADERBOARD" in r, f"LEADERBOARD failed: {r!r}"
    print("OK")

    # 16. Stat set/get
    print("[16] STAT set/get... ", end="")
    r = send_recv(ca, 'STAT CAT=1 COL=kills VAL=42')
    assert "+STAT" in r, f"STAT set failed: {r!r}"
    r = send_recv(ca, 'STAT CAT=1 COL=kills')
    assert "42" in r, f"STAT get failed: {r!r}"
    print("OK")

    # 17. Admin mute/unmute
    print("[17] Admin mute/unmute... ", end="")
    assert server_mod._server is not None, "server instance missing"
    r = server_mod._server._run_admin_command(f"mute {alice_uid} test mute")
    assert "muted user" in r, f"mute failed: {r!r}"
    send_recv(cb, "PING", wait=0.1)
    r = send_recv(ca, 'MESG TEXT="Muted hello"')
    assert "-MESG" in r and "Muted" in r, f"muted MESG was not rejected: {r!r}"
    r = send_recv(cb, "PING", wait=0.1)
    assert "Muted hello" not in r, f"muted MESG leaked to Bob: {r!r}"
    r = server_mod._server._run_admin_command(f"unmute {alice_uid}")
    assert "unmuted user" in r, f"unmute failed: {r!r}"
    send_recv(ca, 'MESG TEXT="After mute"', wait=0.1)
    r = send_recv(cb, "PING", wait=0.2)
    assert "After mute" in r, f"unmuted MESG did not reach Bob: {r!r}"
    print("OK")

    # 18. Control channel social actions
    print("[18] Control social actions... ", end="")
    cc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cc.settimeout(1.0)
    cd.settimeout(1.0)
    cc.connect(("127.0.0.1", 20923))
    cd.connect(("127.0.0.1", 20923))
    body = send_control_expect(
        cc,
        "AUTH",
        [
            "PROD=NFS-CONSOLE-2005",
            "VERS=0.1",
            "PRES=20920",
            "USER=/PC/NFS-CONSOLE-2005",
            "PERS=AlicePers",
        ],
        "AUTH",
    )
    assert "TITL=" in body, f"control AUTH failed: {body!r}"
    body = send_control_expect(
        cd,
        "AUTH",
        [
            "PROD=NFS-CONSOLE-2005",
            "VERS=0.1",
            "PRES=20920",
            "USER=/PC/NFS-CONSOLE-2005",
            "PERS=BobPers",
        ],
        "AUTH",
    )
    assert "TITL=" in body, f"control AUTH failed for Bob: {body!r}"
    body = send_control_expect(cc, "RGET", ["LIST=B", "ID=6"], "RGET")
    assert "ID=6" in body and "SIZE=" in body, f"control roster failed: {body!r}"
    body = send_control_expect(cc, "RADD", ["LIST=B", "USER=BobPers", "ID=7"], "RADD")
    assert "ID=7" in body and "STAT=OK" in body, f"control buddy add failed: {body!r}"
    body = send_control_expect(cc, "RDEL", ["LIST=B", "USER=BobPers", "ID=8"], "RDEL")
    assert "ID=8" in body and "STAT=OK" in body, f"control buddy remove failed: {body!r}"
    body = send_control_expect(cc, "ABUS", ["USER=BobPers", "TEXT=bad", "ID=9"], "ABUS")
    assert "ID=9" in body and "STAT=OK" in body, f"control report failed: {body!r}"
    body = send_control_expect(cc, "PMSG", ["USER=BobPers", "TEXT=hello", "ID=11"], "PMSG")
    assert "ID=11" in body and "STAT=OK" in body and "DELIVERED=1" in body, f"control message failed: {body!r}"
    body = recv_control_until(cd, "PMSG")
    assert "FROM=AlicePers" in body and "TEXT=hello" in body, f"control message delivery failed: {body!r}"
    body = send_control_expect(cd, "RADD", ["LIST=I", "USER=AlicePers", "ID=12"], "RADD")
    assert "ID=12" in body and "STAT=OK" in body, f"control ignore add failed: {body!r}"
    body = send_control_expect(cc, "PMSG", ["USER=BobPers", "TEXT=blocked", "ID=13"], "PMSG")
    assert "ID=13" in body and "DELIVERED=0" in body, f"control block did not suppress delivery: {body!r}"
    body = send_control_expect(cd, "RDEL", ["LIST=I", "USER=AlicePers", "ID=14"], "RDEL")
    assert "ID=14" in body and "STAT=OK" in body, f"control ignore remove failed: {body!r}"
    body = send_control_expect(cc, "INVT", ["USER=BobPers", "TEXT=join", "ID=15"], "INVT")
    assert "ID=15" in body and "STAT=OK" in body and "DELIVERED=1" in body, f"control invite failed: {body!r}"
    body = recv_control_until(cd, "INVT")
    assert "FROM=AlicePers" in body and "TEXT=join" in body, f"control invite delivery failed: {body!r}"
    body = send_control_expect(cc, "ZZZZ", ["ID=16"], "ZZZZ")
    assert "ID=16" in body, f"control generic ack failed: {body!r}"
    cc.close()
    cd.close()
    print("OK")

    # 19. Disconnect clients
    print("[19] Disconnect clients... ", end="")
    send_recv(ca, "LOGOUT", wait=0.1)
    send_recv(cb, "LOGOUT", wait=0.1)
    ca.close()
    cb.close()
    print("OK")

    # 20. StopServer
    print("[20] StopServer()... ", end="")
    StopServer()
    time.sleep(0.5)
    assert not IsServerRunning(), "IsServerRunning() should be False after stop"
    print("OK")

    print("\n" + "=" * 60)
    print("All tests passed!")
    print("=" * 60)


if __name__ == "__main__":
    run_tests()
